import contextlib
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import unittest
from unittest.mock import patch

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('preflight', ROOT / 'scripts/nosh-network-preflight.py')
p = importlib.util.module_from_spec(spec)
spec.loader.exec_module(p)


def network(cidr='172.20.0.0/24', identity='a', name='test'):
    return {'Id': identity * 64, 'Name': name, 'Driver': 'bridge', 'Options': {},
            'IPAM': {'Config': [{'Subnet': cidr}]}}


def address(cidr, device):
    interface = p.ipaddress.ip_interface(cidr)
    return {'ifname': device, 'addr_info': [{'family': 'inet' if interface.version == 4 else 'inet6',
            'local': str(interface.ip), 'prefixlen': interface.network.prefixlen}]}


class Fixture(p.Inspector):
    def __init__(self, config=None, arguments=None):
        super().__init__()
        self.calls = []
        self.config = config if config is not None else {}
        self.arguments = arguments or ['/usr/bin/dockerd', '-H', 'fd://']
        self.proc_stat = '100 (dockerd) ' + ' '.join(['0'] * 19 + ['12345'])

    def run(self, args):
        self.calls.append(args)
        if args[:3] == ['systemctl', 'show', 'docker.service']:
            return 'MainPID=100\nFragmentPath=/usr/lib/systemd/system/docker.service\nDropInPaths=/etc/systemd/system/docker.service.d/override.conf\nEnvironmentFiles=/etc/default/docker\n'
        if args[:3] == ['systemctl', 'show', 'docker.socket']:
            return '/run/docker.sock (Stream)\n'
        raise AssertionError(args)

    def read(self, path):
        if path.endswith('/stat'):
            return self.proc_stat
        if path.endswith('/cmdline'):
            return '\0'.join(self.arguments) + '\0'
        self.config_read = path
        return json.dumps(self.config)

    def readlink(self, path):
        return 'net:[100]'


class Tests(unittest.TestCase):
    def report(self, networks=(), interfaces=(), routes=()):
        report = p.Inspector().report
        report.update(networks=list(networks), interfaces=list(interfaces), routes=list(routes))
        return report

    def test_expected_bridge_is_not_collision(self):
        report = self.report([network()], [address('172.20.0.1/24', 'br-' + 'a' * 12)],
                             [{'dst': '172.20.0.0/24', 'dev': 'br-' + 'a' * 12}, {'dst': 'default'}])
        p.analyze(report)
        self.assertEqual(p.finish(report), 0)

    def test_lan_overlap(self):
        report = self.report([network()], [address('172.20.0.2/24', 'eth0')])
        p.analyze(report)
        self.assertEqual(p.finish(report), 2)

    def test_ipv6_overlap(self):
        report = self.report([network('fd00:1::/64')], [address('fd00:1::2/64', 'vpn0')])
        p.analyze(report)
        self.assertEqual(p.finish(report), 2)

    def test_unrelated_families(self):
        report = self.report([network()], [address('fd00::2/64', 'eth0')])
        p.analyze(report)
        self.assertEqual(p.finish(report), 0)

    def test_unused_network_is_still_allocated(self):
        report = self.report([network(), network('172.20.0.0/25', 'b')])
        p.analyze(report)
        self.assertEqual(p.finish(report), 2)

    def test_disconnected_exclusion(self):
        report = self.report([network()])
        p.analyze(report, exclusions=[p.prefix('172.20.0.0/16')])
        self.assertEqual(p.finish(report), 2)

    def test_pool_reports_used_slices(self):
        report = self.report([network()], [address('172.20.0.1/24', 'br-' + 'a' * 12)])
        p.analyze(report, p.prefix('172.20.0.0/16'))
        self.assertEqual(p.finish(report), 0)
        self.assertEqual(len(report['pool']['occupiedDockerSubnets']), 1)

    def test_proposed_pool_overlaps_lan(self):
        report = self.report(interfaces=[address('10.1.0.1/24', 'vpn0')])
        p.analyze(report, p.prefix('10.0.0.0/8'))
        self.assertEqual(p.finish(report), 2)

    def test_link_local_and_loopback_are_scoped(self):
        self.assertEqual(p.host_ranges([address('fe80::1/64', 'eth0'), address('127.0.0.1/8', 'lo')], []), set())

    def test_default_pool_lan_intersection_warns(self):
        report = self.report(interfaces=[address('192.168.1.1/24', 'eth0')])
        report['docker']['DefaultAddressPools'] = [{'Base': '192.168.0.0/16', 'Size': 24}]
        p.analyze(report)
        self.assertEqual(report['findings'][0]['code'], 'default-pool-host-intersection')

    def test_custom_config_and_unit_discovery(self):
        fixture = Fixture({'bip': '10.9.0.1/24', 'secret': 'never print'},
                          ['/usr/bin/dockerd', '--config-file=/etc/docker/custom.json', '--host=unix:///run/custom.sock'])
        fixture.inspect_daemon('unix:///run/custom.sock')
        self.assertEqual(fixture.config_read, '/etc/docker/custom.json')
        self.assertTrue(fixture.report['daemon']['endpointAssociated'])
        self.assertIn('override.conf', fixture.report['daemon']['unit']['DropInPaths'])
        self.assertNotIn('never print', json.dumps(fixture.report))

    def test_socket_activation(self):
        fixture = Fixture()
        fixture.inspect_daemon('unix:///run/docker.sock')
        self.assertTrue(fixture.report['daemon']['endpointAssociated'])
        self.assertEqual(fixture.report['daemon']['networkNamespace'], 'net:[100]')
        self.assertEqual(fixture.report['daemon']['inspectorNetworkNamespace'], 'net:[100]')
        self.assertTrue(fixture.report['daemon']['networkNamespaceMatches'])
        self.assertTrue(all(call[:2] == ['systemctl', 'show'] for call in fixture.calls))

    def test_conflicting_declarations(self):
        fixture = Fixture({'bip': '10.1.0.1/24'}, ['/usr/bin/dockerd', '--bip=10.2.0.1/24'])
        fixture.inspect_daemon('unix:///var/run/docker.sock')
        self.assertEqual(p.finish(fixture.report), 2)

    def test_invalid_configuration(self):
        fixture = Fixture({'default-address-pools': [{'base': '10.0.0.0/8', 'size': 33}]})
        fixture.inspect_daemon('unix:///run/docker.sock')
        self.assertEqual(p.finish(fixture.report), 2)

    def test_duplicate_json_keys(self):
        with self.assertRaises(ValueError):
            p.decode('{"bip":"10.1.0.1/24","bip":"10.2.0.1/24"}')

    def test_endpoint_not_assumed(self):
        fixture = Fixture()
        fixture.inspect_daemon('unix:///run/unrelated.sock')
        self.assertEqual(p.finish(fixture.report), 3)

    def test_namespace_mismatch(self):
        fixture = Fixture()
        fixture.readlink = lambda path: 'net:[1]' if path == f'/proc/{os.getpid()}/ns/net' else 'net:[2]'
        fixture.inspect_daemon('unix:///run/docker.sock')
        self.assertEqual(p.finish(fixture.report), 3)
        finding = next(item for item in fixture.report['findings'] if item['code'] == 'daemon-namespace')
        self.assertIn('net:[1]', finding['detail'])
        self.assertIn('net:[2]', finding['detail'])

    def test_unreadable_namespace_is_not_reported_as_mismatch(self):
        fixture = Fixture()
        fixture.readlink = lambda path: ''
        fixture.optional('daemon-inspection', lambda: fixture.inspect_daemon('unix:///run/docker.sock'))
        self.assertEqual(p.finish(fixture.report), 3)
        self.assertNotIn('daemon-namespace', [item['code'] for item in fixture.report['findings']])

    def test_namespace_permission_failure_is_not_a_mismatch(self):
        fixture = Fixture()
        fixture.readlink = lambda path: (_ for _ in ()).throw(PermissionError('access denied'))
        fixture.optional('daemon-inspection', lambda: fixture.inspect_daemon('unix:///run/docker.sock'))
        self.assertEqual(p.finish(fixture.report), 3)
        self.assertNotIn('daemon-namespace', [item['code'] for item in fixture.report['findings']])

    def test_elevated_namespace_read_uses_explicit_inspector_pid(self):
        inspector = p.Inspector(sudo=True)
        with patch.object(p.os, 'readlink', side_effect=PermissionError), patch.object(inspector, 'run', return_value='net:[4026531833]\n') as run:
            self.assertEqual(inspector.network_namespace(os.getpid()), 'net:[4026531833]')
            self.assertEqual(run.call_args.args[0][-1], f'/proc/{os.getpid()}/ns/net')

    def test_empty_unprivileged_namespace_retries_with_authorized_sudo(self):
        inspector = p.Inspector(sudo=True)
        with patch.object(p.os, 'geteuid', return_value=1000), patch.object(p.os, 'readlink', return_value=''), patch.object(inspector, 'run', return_value='net:[4026531833]\n') as run:
            self.assertEqual(inspector.network_namespace(2122), 'net:[4026531833]')
            self.assertEqual(run.call_args.args[0], ['sudo', '-n', '--', 'readlink', '-v', '--', '/proc/2122/ns/net'])

    def test_invalid_namespace_retry_requires_permission(self):
        inspector = p.Inspector()
        with patch.object(p.os, 'geteuid', return_value=1000), patch.object(p.os, 'readlink', return_value='unavailable'), patch.object(inspector, 'run') as run:
            with self.assertRaises(ValueError):
                inspector.network_namespace(2122)
            run.assert_not_called()

    def test_invalid_elevated_namespace_stays_incomplete(self):
        inspector = p.Inspector(sudo=True)
        with patch.object(p.os, 'geteuid', return_value=1000), patch.object(p.os, 'readlink', return_value=''), patch.object(inspector, 'run', return_value='') as run:
            with self.assertRaises(ValueError):
                inspector.network_namespace(2122)
            self.assertEqual(run.call_count, 1)

    def test_json_never_prompts(self):
        inspector = p.Inspector(interactive=False)
        with patch.object(p.os, 'geteuid', return_value=1000), patch('sys.stdin', io.StringIO('y\n')):
            self.assertFalse(inspector.authorize_read())
            self.assertFalse(inspector.asked)
        self.assertIn('-n', inspector.sudo_args())

    def test_unreadable_file_does_not_elevate_without_permission(self):
        inspector = p.Inspector()
        with patch.object(p.os, 'geteuid', return_value=1000), patch.object(Path, 'stat', side_effect=PermissionError), patch.object(inspector, 'run') as run:
            with self.assertRaises(PermissionError):
                inspector.read('/etc/docker/daemon.json')
            run.assert_not_called()

    def test_authorized_read_is_bounded_and_only_reads(self):
        inspector = p.Inspector(sudo=True)
        with patch.object(Path, 'stat', side_effect=PermissionError), patch.object(inspector, 'run', side_effect=['81a4 2', '{}']) as run:
            self.assertEqual(inspector.read('/etc/docker/daemon.json'), '{}')
            self.assertEqual(run.call_args_list[0].args[0], ['sudo', '-n', '--', 'stat', '-Lc', '%f %s', '--', '/etc/docker/daemon.json'])
            self.assertEqual(run.call_args_list[1].args[0], ['sudo', '-n', '--', 'head', '-c', str(p.LIMIT + 1), '--', '/etc/docker/daemon.json'])

    def test_privileged_special_file_is_rejected(self):
        inspector = p.Inspector(sudo=True)
        with patch.object(Path, 'stat', side_effect=PermissionError), patch.object(inspector, 'run', return_value='21b6 0') as run:
            with self.assertRaises(ValueError):
                inspector.read('/etc/docker/daemon.json')
            self.assertEqual(run.call_count, 1)

    def test_absent_default_config_is_reported_without_invented_defaults(self):
        fixture = Fixture()
        read = fixture.read
        def missing(path):
            if path == '/etc/docker/daemon.json':
                raise FileNotFoundError(path)
            return read(path)
        fixture.read = missing
        fixture.inspect_daemon('unix:///run/docker.sock')
        self.assertFalse(fixture.report['daemon']['configFilePresent'])
        self.assertEqual(fixture.report['daemon']['diskNetworkSettings'], {})
        self.assertEqual(p.finish(fixture.report), 0)

    def test_missing_explicit_configuration_is_incomplete(self):
        fixture = Fixture(arguments=['dockerd', '--config-file=/etc/docker/missing.json'])
        read = fixture.read
        def missing(path):
            if path.endswith('missing.json'):
                raise FileNotFoundError(path)
            return read(path)
        fixture.read = missing
        fixture.inspect_daemon('unix:///var/run/docker.sock')
        self.assertEqual(p.finish(fixture.report), 3)

    def test_malformed_route_json_is_rejected(self):
        for value in ('{}', '["not a route"]', 'null'):
            with self.assertRaises(ValueError):
                p.object_list(value)

    def test_declined_sudo_asked_once(self):
        inspector = p.Inspector(interactive=True)
        with patch.object(p.os, 'geteuid', return_value=1000), patch('sys.stdin', io.StringIO('n\ny\n')), contextlib.redirect_stderr(io.StringIO()):
            self.assertFalse(inspector.authorize_read())
            self.assertFalse(inspector.authorize_read())

    def test_privileged_docker_keeps_endpoint(self):
        inspector = p.Inspector(sudo=True)
        command = ['docker', '--host', 'unix:///run/custom.sock', 'info', '--format', '{{json .}}']
        outputs = [subprocess.CompletedProcess(command, 1, '', 'permission denied'), subprocess.CompletedProcess(command, 0, '{}', '')]
        with patch.object(p.subprocess, 'run', side_effect=outputs) as run:
            self.assertEqual(inspector.run(command), '{}')
            self.assertEqual(run.call_args_list[1].args[0], ['sudo', '-n', '--', *command])

    def test_container_refused_before_commands(self):
        class Helper:
            container_context = staticmethod(lambda: True)
        fixture = Fixture()
        p.collect(fixture, Helper())
        self.assertEqual(p.finish(fixture.report), 3)
        self.assertEqual(fixture.calls, [])

    def test_remote_endpoint_stops_inspection(self):
        class Helper:
            container_context = staticmethod(lambda: False)
            @staticmethod
            def local_endpoint(*args, **kwargs):
                raise ValueError('requires a local Unix Docker endpoint')
        fixture = Fixture()
        p.collect(fixture, Helper())
        self.assertEqual(p.finish(fixture.report), 3)
        self.assertEqual(fixture.calls, [])

    def test_null_pools_and_rootless_are_explicit(self):
        class Helper:
            container_context = staticmethod(lambda: False)
            local_endpoint = staticmethod(lambda *args, **kwargs: 'unix:///run/user/1000/docker.sock')
            inspect_networks = staticmethod(lambda *args, **kwargs: [])
            configuration_path = staticmethod(lambda: Path('/unused'))
            read_configuration = staticmethod(lambda path: None)
        fixture = p.Inspector()
        commands = []
        def run(args):
            commands.append(args)
            if args[0] == 'docker':
                return '{"DefaultAddressPools":null,"SecurityOptions":["name=rootless"]}'
            return '[]'
        fixture.run = run
        p.collect(fixture, Helper())
        self.assertEqual(p.finish(fixture.report), 3)
        self.assertIn('pools-unreported', [item['code'] for item in fixture.report['findings']])
        self.assertTrue(all(command[0] in ('docker', 'ip') for command in commands))


if __name__ == '__main__':
    unittest.main()
