#!/usr/bin/env python3
"""Offline allocation/attestation regressions; never invokes Docker or host ip."""
import contextlib
import importlib.util
import io
import ipaddress
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch


SPEC = importlib.util.spec_from_file_location('review_network',
    Path(__file__).resolve().parents[1] / 'scripts/nosh-review-network.py')
NETWORK = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(NETWORK)
ID = 'a' * 64
OTHER_ID = 'b' * 64


def config(pool='10.225.0.0/24', excluded=None):
    return NETWORK.validate_configuration({'schemaVersion': 1, 'pool': pool,
                                           'excludedCidrs': excluded or []})


def docker_network(network_id=ID, subnet='10.225.0.0/29', gateway='10.225.0.1'):
    return {'Id': network_id, 'Driver': 'bridge', 'EnableIPv6': False, 'Options': {},
            'IPAM': {'Config': [{'Subnet': subnet, 'Gateway': gateway}]}}


def interface(name='eth0', address='192.168.1.68', prefix=24):
    return {'ifname': name, 'addr_info': [{'family': 'inet', 'local': address, 'prefixlen': prefix}]}


class ConfigurationTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.path = Path(self.directory.name) / 'config/review-network.json'

    def test_missing_is_not_an_automatic_pool(self):
        self.assertIsNone(NETWORK.read_configuration(self.path))
        self.assertEqual(NETWORK.status(None)['status'], 'missing')

    def test_exclusive_private_configuration_roundtrip(self):
        expected = NETWORK.configure(self.path, '10.225.0.0/16', ['192.168.0.0/16'])
        self.assertEqual(self.path.stat().st_mode & 0o777, 0o600)
        self.assertEqual(NETWORK.read_configuration(self.path), expected)
        with self.assertRaises(FileExistsError):
            NETWORK.configure(self.path, '172.20.0.0/16', [])
        self.assertEqual(NETWORK.read_configuration(self.path), expected)

    def test_invalid_pools_and_noncanonical_prefixes(self):
        for pool in ('8.8.0.0/16', '127.0.0.0/16', '169.254.0.0/16', '100.64.0.0/16',
                     '172.15.0.0/16', '172.32.0.0/16', '10.0.0.0/8', '10.225.0.0/30',
                     '10.225.0.1/24', '10.225.0.0/255.255.255.0', '192.168.016.0/24', 'fd42::/64'):
            with self.subTest(pool=pool), self.assertRaises(ValueError):
                config(pool)
        for pool in ('10.225.0.0/16', '172.16.0.0/16', '172.31.255.248/29', '192.168.0.0/16'):
            self.assertEqual(config(pool)['pool'], pool)

    def test_digest_is_canonical_and_binds_exclusions(self):
        one = config(excluded=['192.168.0.0/16', '10.226.0.0/16'])
        two = config(excluded=['10.226.0.0/16', '192.168.0.0/16'])
        self.assertEqual(NETWORK.configuration_digest(one), NETWORK.configuration_digest(two))
        self.assertNotEqual(NETWORK.configuration_digest(one), NETWORK.configuration_digest(config()))

    def test_unsafe_config_files_and_parents_are_rejected(self):
        NETWORK.configure(self.path, '10.225.0.0/16', [])
        self.path.chmod(0o644)
        with self.assertRaises(ValueError):
            NETWORK.read_configuration(self.path)
        self.path.chmod(0o600)
        self.path.parent.chmod(0o777)
        with self.assertRaises(ValueError):
            NETWORK.read_configuration(self.path)
        self.path.parent.chmod(0o700)
        link = self.path.parent / 'link.json'
        link.symlink_to(self.path)
        with self.assertRaises(ValueError):
            NETWORK.read_configuration(link)
        hardlink = self.path.parent / 'hardlink.json'
        os.link(self.path, hardlink)
        with self.assertRaises(ValueError):
            NETWORK.read_configuration(self.path)

    def test_duplicate_and_extra_fields_are_rejected(self):
        NETWORK.configure(self.path, '10.225.0.0/16', [])
        self.path.write_text('{"schemaVersion":1,"schemaVersion":1,"pool":"10.225.0.0/16","excludedCidrs":[]}')
        with self.assertRaises(ValueError):
            NETWORK.read_configuration(self.path)
        with self.assertRaises(ValueError):
            NETWORK.validate_configuration({**config(), 'fallback': '192.168.0.0/16'})
        with self.assertRaises(ValueError):
            NETWORK.validate_configuration({**config(), 'schemaVersion': True})

    def test_status_command_digest_and_missing_contract(self):
        with patch.dict(os.environ, {'NOSH_REVIEW_NETWORK_CONFIG': str(self.path)}):
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                self.assertEqual(NETWORK.main(['status']), 3)
            self.assertEqual(json.loads(output.getvalue())['status'], 'missing')
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(NETWORK.main(['configure', '--pool', '10.225.0.0/16']), 0)
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                self.assertEqual(NETWORK.main(['status', '--digest']), 0)
            self.assertEqual(output.getvalue().strip(), NETWORK.configuration_digest(config('10.225.0.0/16')))


class AllocationTests(unittest.TestCase):
    def test_stable_small_allocation(self):
        first = NETWORK.select_subnet(config(), 'session-key', [])
        self.assertEqual(first, NETWORK.select_subnet(config(), 'session-key', []))
        subnet = ipaddress.ip_network(first[0])
        self.assertEqual(subnet.prefixlen, 29)
        self.assertTrue(subnet.subnet_of(ipaddress.ip_network('10.225.0.0/24')))
        self.assertEqual(first[1], str(subnet.network_address + 1))

    def test_docker_routes_addresses_and_exclusions_each_prevent_overlap(self):
        reserved = config('10.225.0.0/29')
        datasets = [
            ([docker_network()], [], []),
            ([], [{'dst': '10.0.0.0/8', 'dev': 'tun0', 'table': 200}], []),
            ([], [{'dst': '10.225.0.4', 'type': 'blackhole'}], []),
            ([], [], [interface(address='10.225.0.1', prefix=24)]),
        ]
        for networks, routes, addresses in datasets:
            with self.subTest(data=(networks, routes, addresses)), self.assertRaises(ValueError):
                NETWORK.select_subnet(reserved, 'session', NETWORK.occupied_networks(networks, routes, addresses))
        with self.assertRaises(ValueError):
            NETWORK.select_subnet(config('10.225.0.0/29', ['10.225.0.0/29']), 'session', [])

    def test_default_route_does_not_block_allocation_but_lan_route_does(self):
        occupied = NETWORK.occupied_networks([], [{'dst': 'default', 'dev': 'wlo1'},
                                                  {'dst': '0.0.0.0/0'},
                                                  {'dst': '192.168.1.0/24'}],
                                             [interface()])
        self.assertEqual(NETWORK.select_subnet(config('192.168.16.0/29'), 'session', occupied),
                         ('192.168.16.0/29', '192.168.16.1'))
        with self.assertRaises(ValueError):
            NETWORK.select_subnet(config('192.168.1.0/29'), 'session', occupied)

    def test_used_candidate_advances_within_reserved_pool_then_exhausts(self):
        reserved = config('10.225.0.0/28')
        first = NETWORK.select_subnet(reserved, 'session', [])
        second = NETWORK.select_subnet(reserved, 'session', [ipaddress.ip_network(first[0])])
        self.assertNotEqual(first, second)
        with self.assertRaises(ValueError):
            NETWORK.select_subnet(reserved, 'session', [ipaddress.ip_network(first[0]), ipaddress.ip_network(second[0])])

    def test_malformed_inspection_fails_closed(self):
        cases = [([], [{}], []), ([{'Id': ID, 'IPAM': None}], [], []),
                 ([], [], [{'ifname': 'eth0', 'addr_info': [{'family': 'inet', 'local': '1.2.3.4'}]}])]
        for data in cases:
            with self.subTest(data=data), self.assertRaises(ValueError):
                NETWORK.occupied_networks(*data)

    def test_builtin_null_ipam_allows_checked_allocation(self):
        networks = [docker_network(subnet='172.17.0.0/16', gateway='172.17.0.1'),
                    {'Name': 'host', 'Driver': 'host', 'IPAM': {'Config': None}},
                    {'Name': 'none', 'Driver': 'null', 'IPAM': {'Config': None}}]
        occupied = NETWORK.occupied_networks(networks, [{'dst': '192.168.1.0/24'}], [])
        self.assertIn(ipaddress.ip_network('172.17.0.0/16'), occupied)
        subnet, gateway = NETWORK.select_subnet(config('10.0.0.0/26'), 'review', occupied)
        self.assertTrue(ipaddress.ip_network(subnet).subnet_of(ipaddress.ip_network('10.0.0.0/26')))
        self.assertEqual(ipaddress.ip_network(subnet).prefixlen, 29)

    def test_null_ipam_is_not_accepted_for_bridge_or_plugin(self):
        for name, driver in [('bridge', 'bridge'), ('host', 'bridge'), ('none', 'plugin'), ('custom', 'host')]:
            with self.subTest(name=name, driver=driver), self.assertRaisesRegex(ValueError, 'malformed IPAM'):
                NETWORK.occupied_networks([{'Name': name, 'Driver': driver, 'IPAM': {'Config': None}}], [], [])

    def test_builtin_nonempty_ipam_is_still_checked(self):
        network = {'Name': 'host', 'Driver': 'host', 'IPAM': {'Config': [{'Subnet': '10.0.0.0/26'}]}}
        occupied = NETWORK.occupied_networks([network], [], [])
        with self.assertRaisesRegex(ValueError, 'no free /29'):
            NETWORK.select_subnet(config('10.0.0.0/26'), 'review', occupied)


class HostInspectionTests(unittest.TestCase):
    def test_remote_endpoints_and_container_context_are_rejected(self):
        for endpoint in ('tcp://127.0.0.1:2375', 'ssh://server', 'npipe:////./pipe/docker_engine',
                         'unix://relative', 'unix:///', 'unix:///socket path', 'unix:///sock\x00', 'unix:///sock?arg'):
            with self.subTest(endpoint=endpoint), self.assertRaises(ValueError):
                NETWORK.local_endpoint('docker', environment={'DOCKER_HOST': endpoint})
        calls = []
        with self.assertRaisesRegex(ValueError, 'outside containers'):
            NETWORK.host_snapshot('docker', run=lambda args: calls.append(args), is_container=lambda: True)
        self.assertEqual(calls, [])

    def test_explicit_context_overrides_host_environment(self):
        calls = []
        def run(args):
            calls.append(args)
            return json.dumps('ssh://remote')
        with self.assertRaises(ValueError):
            NETWORK.local_endpoint('docker', run, {'DOCKER_HOST': 'unix:///var/run/docker.sock',
                                                   'DOCKER_CONTEXT': 'remote-context'})
        self.assertEqual(calls[0][3], 'remote-context')

    def test_snapshot_inspects_all_tables_interfaces_and_exact_network_ids(self):
        calls = []
        def run(args):
            calls.append(args)
            if args[1:3] == ['context', 'inspect']:
                return json.dumps('unix:///var/run/docker.sock')
            if args[3:5] == ['network', 'ls']:
                return ID + '\n'
            if args[3:5] == ['network', 'inspect']:
                return json.dumps([docker_network()])
            return '[]'
        result = NETWORK.host_snapshot('docker', run, lambda: False, {'NOSH_REVIEW_IP_BIN': '/usr/sbin/ip'})
        self.assertEqual(result[0][0]['Id'], ID)
        self.assertIn(['/usr/sbin/ip', '-j', '-4', 'route', 'show', 'table', 'all'], calls)
        self.assertIn(['/usr/sbin/ip', '-j', '-4', 'address', 'show'], calls)
        self.assertIn(['docker', '--host', 'unix:///var/run/docker.sock', 'network', 'inspect', ID], calls)

    def test_selected_context_endpoint_is_pinned_on_every_docker_network_call(self):
        calls = []
        def run(args):
            calls.append(args)
            if args[1:3] == ['context', 'inspect']:
                return json.dumps('unix:///run/selected-docker.sock')
            return '' if args[3:5] == ['network', 'ls'] else '[]'
        NETWORK.host_snapshot('docker', run, lambda: False,
                              {'DOCKER_CONTEXT': 'selected', 'DOCKER_HOST': 'ssh://ignored'})
        self.assertEqual(calls[0][1:4], ['context', 'inspect', 'selected'])
        self.assertEqual(calls[1][:5], ['docker', '--host', 'unix:///run/selected-docker.sock', 'network', 'ls'])

    def test_endpoint_command_does_not_need_configuration(self):
        output = io.StringIO()
        with patch.object(NETWORK, 'host_endpoint', return_value='unix:///var/run/docker.sock') as endpoint:
            with patch.object(NETWORK, 'read_configuration', side_effect=AssertionError('unexpected config read')):
                with contextlib.redirect_stdout(output):
                    self.assertEqual(NETWORK.main(['endpoint', '--docker-bin', '/usr/bin/docker']), 0)
        endpoint.assert_called_once_with('/usr/bin/docker')
        self.assertEqual(output.getvalue(), 'unix:///var/run/docker.sock\n')

    def test_command_removes_context_environment_before_pinned_inspection(self):
        result = type('Result', (), {'returncode': 0, 'stdout': '[]'})()
        with patch.dict(os.environ, {'DOCKER_CONTEXT': 'remote'}):
            with patch.object(NETWORK.subprocess, 'run', return_value=result) as run:
                NETWORK.command(['docker', '--host', 'unix:///var/run/docker.sock', 'network', 'inspect', ID])
        self.assertNotIn('DOCKER_CONTEXT', run.call_args.kwargs['env'])


class VerificationTests(unittest.TestCase):
    def setUp(self):
        self.networks = [docker_network()]
        self.bridge = 'br-' + ID[:12]
        self.routes = [{'dst': '10.225.0.0/29', 'dev': self.bridge},
                       {'dst': '10.225.0.1', 'dev': self.bridge, 'type': 'local', 'table': 'local'},
                       {'dst': 'default', 'dev': 'eth0'}]
        self.addresses = [interface(self.bridge, '10.225.0.1', 29), interface()]

    def verify(self, **changes):
        data = {'config': config(), 'network_id': ID, 'subnet': '10.225.0.0/29', 'gateway': '10.225.0.1',
                'networks': self.networks, 'routes': self.routes, 'addresses': self.addresses}
        data.update(changes)
        return NETWORK.verify_network(**data)

    def test_own_bridge_routes_are_ignored_and_configuration_is_bound(self):
        self.assertEqual(self.verify(), NETWORK.configuration_digest(config()))

    def test_other_route_or_network_overlap_is_rejected(self):
        self.routes.append({'dst': '10.0.0.0/8', 'dev': 'tun0', 'table': 200})
        with self.assertRaises(ValueError):
            self.verify()
        self.routes.pop()
        self.networks.append(docker_network(OTHER_ID, '10.225.0.0/24', '10.225.0.1'))
        with self.assertRaises(ValueError):
            self.verify()

    def test_exact_id_ipam_and_current_configuration_are_required(self):
        for change in ({'network_id': OTHER_ID}, {'gateway': '10.225.0.2'},
                       {'subnet': '192.168.16.0/29'},
                       {'config': config(excluded=['10.225.0.0/24'])}, {'addresses': [interface()]}):
            with self.subTest(change=change), self.assertRaises(ValueError):
                self.verify(**change)
        self.networks[0]['IPAM']['Config'][0]['Subnet'] = '10.225.0.0/24'
        with self.assertRaises(ValueError):
            self.verify()

    def test_ipv6_or_extra_ipam_is_rejected(self):
        self.networks[0]['EnableIPv6'] = True
        with self.assertRaises(ValueError):
            self.verify()
        self.networks[0]['EnableIPv6'] = False
        self.networks[0]['IPAM']['Config'].append({'Subnet': 'fd42::/64', 'Gateway': 'fd42::1'})
        with self.assertRaises(ValueError):
            self.verify()

    def test_explicit_bridge_name_is_bound_to_present_host_interface(self):
        self.networks[0]['Options']['com.docker.network.bridge.name'] = 'review-bridge'
        with self.assertRaises(ValueError):
            self.verify()
        for route in self.routes:
            if route.get('dev') == self.bridge:
                route['dev'] = 'review-bridge'
        self.addresses[0]['ifname'] = 'review-bridge'
        self.assertEqual(self.verify(), NETWORK.configuration_digest(config()))


class Suggestions(unittest.TestCase):
    def report(self):
        return {'docker': {'endpoint': 'unix:///var/run/docker.sock', 'DefaultAddressPools': None},
                'daemon': {}, 'networks': [], 'routes': [], 'interfaces': [], 'findings': []}

    def pools(self, report, exclusions=()):
        return [item['pool'] for item in NETWORK.suggest_pools(report, list(exclusions))['suggestions']]

    def test_default_capacity_and_determinism(self):
        report = self.report()
        self.assertEqual(self.pools(report), ['10.0.0.0/26', '172.16.0.0/26', '192.168.0.0/26'])
        self.assertEqual(self.pools(report), self.pools(report))
        self.assertEqual(len(list(ipaddress.ip_network(self.pools(report)[0]).subnets(new_prefix=29))), 8)

    def test_large_docker_subnet_excludes_children_even_if_unused(self):
        report = self.report()
        report['networks'] = [{'Name': 'bridge', 'IPAM': {'Config': [{'Subnet': '172.17.0.0/16'}]}}]
        blockers = NETWORK.suggestion_blockers(report, [])
        self.assertTrue(NETWORK.pool_conflicts(ipaddress.ip_network('172.17.0.0/26'), blockers))

    def test_routes_interfaces_and_exclusions(self):
        report = self.report()
        report['routes'] = [{'dst': 'default'}, {'dst': '10.0.0.0/8'}, {'dst': '::/0'}]
        report['interfaces'] = [{'ifname': 'lan', 'addr_info': [{'family': 'inet', 'local': '192.168.0.4', 'prefixlen': 24}]}]
        pools = self.pools(report, ['172.16.0.0/12'])
        self.assertEqual(pools, ['192.168.1.0/26', '192.168.2.0/26', '192.168.3.0/26'])

    def test_known_guard_reservation_is_always_excluded(self):
        with self.assertRaisesRegex(ValueError, 'Guard runtime reservation'):
            NETWORK.check_configuration_host('10.240.0.0/26', [], self.report())

    def test_declared_and_reported_docker_pools(self):
        report = self.report()
        report['docker']['DefaultAddressPools'] = [{'Base': '10.0.0.0/8', 'Size': 24}]
        report['daemon']['diskNetworkSettings'] = {'default-address-pools': [{'base': '192.168.0.0/16', 'size': 24}]}
        report['daemon']['runningNetworkFlags'] = {'default-address-pool': ['base=172.16.0.0/12,size=24']}
        self.assertEqual(self.pools(report), [])

    def test_pending_bridge_config_excluded(self):
        report = self.report()
        report['daemon']['diskNetworkSettings'] = {'bip': '10.0.0.1/24'}
        self.assertEqual(self.pools(report)[0], '10.1.0.0/26')

    def test_custom_pool_rechecked_before_any_write(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'new' / 'review-network.json'
            report = self.report()
            self.assertIn('10.0.0.0/26', self.pools(report))
            report['routes'] = [{'dst': '10.0.0.0/24'}]
            with patch.object(NETWORK, 'configuration_path', return_value=path), patch.object(NETWORK, 'checked_host_report', return_value=report), contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(NETWORK.main(['configure', '--check-host', '--pool', '10.0.0.0/26']), 1)
            self.assertFalse(path.parent.exists())

    def test_incomplete_inspection_never_saves(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'review-network.json'
            with patch.object(NETWORK, 'configuration_path', return_value=path), patch.object(NETWORK, 'checked_host_report', side_effect=ValueError('namespace unknown')), contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(NETWORK.main(['configure', '--check-host', '--pool', '10.0.0.0/26']), 1)
            self.assertFalse(path.exists())

    def test_checked_configuration_preserves_existing_file(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'review-network.json'
            NETWORK.configure(path, '10.3.0.0/26', [])
            original = path.read_bytes()
            with patch.object(NETWORK, 'configuration_path', return_value=path), patch.object(NETWORK, 'checked_host_report', return_value=self.report()), contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(NETWORK.main(['configure', '--check-host', '--pool', '10.0.0.0/26']), 1)
            self.assertEqual(path.read_bytes(), original)

    def test_suggestion_has_no_network_or_filesystem_mutations(self):
        with patch.object(NETWORK.subprocess, 'run', side_effect=AssertionError('no commands')), patch.object(NETWORK, 'configure', side_effect=AssertionError('no writes')):
            self.assertEqual(len(self.pools(self.report())), 3)


if __name__ == '__main__':
    unittest.main()
