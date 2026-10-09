#!/usr/bin/env python3
"""Read-only host Docker address inspection. Never allocates or changes networks."""
import argparse
import importlib.util
import ipaddress
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys


LIMIT = 16 * 1024 * 1024
NETWORK_KEYS = ('bip', 'bip6', 'fixed-cidr', 'fixed-cidr-v6', 'default-address-pools', 'ipv6', 'bridge')


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('duplicate JSON key: ' + key)
        result[key] = value
    return result


def decode(value):
    return json.loads(value, object_pairs_hook=unique_object)


def load_network_helper():
    spec = importlib.util.spec_from_file_location('review_network', Path(__file__).with_name('nosh-review-network.py'))
    module = importlib.util.module_from_spec(spec)
    previous = sys.dont_write_bytecode
    try:
        sys.dont_write_bytecode = True
        spec.loader.exec_module(module)
    finally:
        sys.dont_write_bytecode = previous
    return module


class Inspector:
    def __init__(self, sudo=False, interactive=False):
        self.sudo = sudo
        self.interactive = interactive
        self.asked = False
        self.report = {
            'schemaVersion': 1, 'readOnly': True, 'docker': {}, 'daemon': {},
            'networks': [], 'interfaces': [], 'routes': [], 'findings': [],
            'limitations': [
                'Disconnected LAN/VPN and remote routed networks require operator-supplied exclusions.',
                'On-disk settings may differ from those loaded by the running daemon.',
                'No policy, service, network, or Docker configuration is changed.',
            ],
        }

    def finding(self, severity, code, detail):
        self.report['findings'].append({'severity': severity, 'code': code, 'detail': detail})

    def run(self, args):
        environment = os.environ.copy()
        environment.pop('DOCKER_CONTEXT', None)
        result = subprocess.run(args, capture_output=True, text=True, timeout=30, env=environment)
        if (result.returncode and args[0] == 'docker' and '--host' in args
                and 'permission denied' in result.stderr.lower() and self.authorize_read()):
            return self.run(self.sudo_args() + args)
        if result.returncode:
            # Do not echo raw daemon/config errors, which can contain secrets.
            raise OSError(f'{Path(args[0]).name} inspection exited {result.returncode}')
        if len(result.stdout) > LIMIT:
            raise ValueError('inspection output exceeds size limit')
        return result.stdout

    def sudo_args(self):
        # JSON/noninteractive runs must not acquire credentials interactively.
        return ['sudo', *([] if self.interactive else ['-n']), '--']

    def readlink(self, path):
        try:
            return os.readlink(path)
        except PermissionError:
            if not self.authorize_read():
                raise PermissionError('privileged namespace inspection was not authorized')
            return self.run(self.sudo_args() + ['readlink', '--', str(path)]).strip()

    def network_namespace(self, pid):
        path = f'/proc/{pid}/ns/net'
        value = self.readlink(path).strip()
        # Some restricted procfs views return an unusable link target instead
        # of raising EACCES. Treat that as unavailable evidence, not a different
        # namespace, and offer the same authorized privileged read.
        if (not re.fullmatch(r'net:\[[0-9]+\]', value)
                and os.geteuid() != 0 and self.authorize_read()):
            value = self.run(self.sudo_args() + ['readlink', '-v', '--', path]).strip()
        if not re.fullmatch(r'net:\[[0-9]+\]', value):
            raise ValueError(f'No valid network namespace ID could be read for PID {pid}')
        return value

    def authorize_read(self):
        if self.sudo or os.geteuid() == 0:
            return True
        if self.interactive and not self.asked:
            self.asked = True
            print('Some daemon metadata needs root access. Allow sudo for read-only inspection? [y/N] ',
                  end='', file=sys.stderr, flush=True)
            self.sudo = sys.stdin.readline().strip().lower() == 'y'
        return self.sudo

    def read(self, path):
        path = Path(path)
        try:
            info = path.stat()
            if not stat.S_ISREG(info.st_mode) or info.st_size > LIMIT:
                raise ValueError('inspection input is not a bounded regular file')
            with path.open() as stream:
                contents = stream.read(LIMIT + 1)
        except PermissionError:
            if not self.authorize_read():
                raise PermissionError('privileged inspection was not authorized')
            metadata = self.run(self.sudo_args() + ['stat', '-Lc', '%f %s', '--', str(path)]).split()
            if len(metadata) != 2 or not stat.S_ISREG(int(metadata[0], 16)) or int(metadata[1]) > LIMIT:
                raise ValueError('privileged input is not a bounded regular file')
            contents = self.run(self.sudo_args() + ['head', '-c', str(LIMIT + 1), '--', str(path)])
        if len(contents) > LIMIT:
            raise ValueError('inspection input exceeds size limit')
        return contents

    def optional(self, label, operation):
        try:
            return operation()
        except (OSError, ValueError, TypeError, KeyError, IndexError, subprocess.SubprocessError) as error:
            self.finding('incomplete', label, str(error))
            return None

    def inspect_daemon(self, endpoint):
        daemon = self.report['daemon']
        properties = self.optional('systemd-inspection', lambda: self.run([
            'systemctl', 'show', 'docker.service', '--no-pager',
            '--property=MainPID,FragmentPath,DropInPaths,EnvironmentFiles']))
        if properties is None:
            return
        fields = dict(line.split('=', 1) for line in properties.splitlines() if '=' in line)
        daemon['unit'] = {key: fields.get(key, '') for key in ('FragmentPath', 'DropInPaths', 'EnvironmentFiles')}
        pid = fields.get('MainPID', '')
        if not pid.isdigit() or int(pid) <= 0:
            self.finding('incomplete', 'daemon-identity', 'No running system Docker service PID; rootless/custom services need separate inspection.')
            return
        daemon['pid'] = int(pid)
        before = self.read(f'/proc/{pid}/stat')
        arguments = self.read(f'/proc/{pid}/cmdline').rstrip('\0').split('\0')
        if not arguments or Path(arguments[0]).name != 'dockerd':
            raise ValueError('system Docker MainPID is not dockerd')
        # Pin the inspector PID explicitly: /proc/self would refer to the
        # readlink child if reading ever needed an elevated subprocess.
        inspector_pid = os.getpid()
        daemon['inspectorPid'] = inspector_pid
        inspector_namespace = self.network_namespace(inspector_pid)
        daemon['inspectorNetworkNamespace'] = inspector_namespace
        daemon_namespace = self.network_namespace(pid)
        daemon['networkNamespace'] = daemon_namespace
        daemon['networkNamespaceMatches'] = daemon_namespace == inspector_namespace
        if not daemon['networkNamespaceMatches']:
            self.finding('incomplete', 'daemon-namespace',
                         f'Docker PID {pid} uses {daemon_namespace}; preflight PID {inspector_pid} uses {inspector_namespace}.')
        flags = daemon_flags(arguments[1:])
        config_path = flags.get('config-file', ['/etc/docker/daemon.json'])[-1]
        if not Path(config_path).is_absolute() or any(ord(char) < 32 for char in config_path):
            raise ValueError('daemon configuration path must be absolute and contain no control characters')
        daemon['configPath'] = config_path
        try:
            configuration = decode(self.read(config_path))
            if not isinstance(configuration, dict):
                raise ValueError('daemon configuration must be a JSON object')
        except (ValueError, TypeError) as error:
            self.finding('conflict', 'invalid-daemon-config', str(error))
            return
        except FileNotFoundError:
            configuration = {}
            daemon['configFilePresent'] = False
            if 'config-file' in flags:
                self.finding('incomplete', 'config-missing', 'Explicit daemon configuration file is absent.')
        else:
            daemon['configFilePresent'] = True
        try:
            validate_settings(configuration, flags)
        except (ValueError, TypeError) as error:
            self.finding('conflict', 'invalid-daemon-config', str(error))
            return
        daemon['diskNetworkSettings'] = {key: configuration[key] for key in NETWORK_KEYS if key in configuration}
        daemon['runningNetworkFlags'] = {key: value for key, value in flags.items() if key in (*NETWORK_KEYS, 'default-address-pool')}
        for key in daemon['runningNetworkFlags']:
            config_key = 'default-address-pools' if key == 'default-address-pool' else key
            if config_key in configuration:
                self.finding('conflict', 'duplicate-declaration', f'{config_key} is declared in both disk configuration and running arguments; no precedence is assumed.')
        hosts = flags.get('host', configuration.get('hosts', ['unix:///var/run/docker.sock']))
        if not isinstance(hosts, list) or any(not isinstance(host, str) for host in hosts):
            raise ValueError('invalid daemon hosts setting')
        sockets = [host[7:] for host in hosts if host.startswith('unix://')]
        if 'fd://' in hosts:
            listen = self.optional('socket-unit-inspection', lambda: self.run([
                'systemctl', 'show', 'docker.socket', '--property=Listen', '--value', '--no-pager']))
            sockets.extend(re.findall(r'(/[^\s]+) \(Stream\)', listen or ''))
        if not any(os.path.realpath(path) == os.path.realpath(endpoint[7:]) for path in sockets):
            self.finding('incomplete', 'endpoint-daemon-association', 'Selected socket could not be associated with the inspected system Docker service.')
        else:
            daemon['endpointAssociated'] = True
        after = self.read(f'/proc/{pid}/stat')
        # Ignore changing CPU counters; field 22 is process start time.
        if before.rsplit(')', 1)[1].split()[19] != after.rsplit(')', 1)[1].split()[19]:
            raise ValueError('daemon process changed during inspection')


def daemon_flags(arguments):
    recognized = set(NETWORK_KEYS) | {'config-file', 'default-address-pool', 'host'}
    result = {}
    index = 0
    while index < len(arguments):
        argument = arguments[index]
        if argument == '-H':
            argument = '--host'
        elif argument.startswith('-H') and len(argument) > 2:
            argument = '--host=' + argument[2:].removeprefix('=')
        name, separator, value = argument.removeprefix('--').partition('=')
        if argument.startswith('--') and name in recognized:
            if not separator:
                if name == 'ipv6':
                    value = 'true'
                else:
                    index += 1
                    if index >= len(arguments) or arguments[index].startswith('-'):
                        raise ValueError('missing daemon flag value: ' + name)
                    value = arguments[index]
            result.setdefault(name, []).append(value)
        index += 1
    return result


def prefix(value):
    return ipaddress.ip_network(value, strict=False)


def validate_settings(configuration, flags):
    for key in ('bip', 'bip6', 'fixed-cidr', 'fixed-cidr-v6'):
        values = ([configuration[key]] if key in configuration else []) + flags.get(key, [])
        for value in values:
            network = prefix(value)
            if network.version != (6 if key in ('bip6', 'fixed-cidr-v6') else 4):
                raise ValueError('wrong address family in ' + key)
    pools = configuration.get('default-address-pools', [])
    if not isinstance(pools, list):
        raise ValueError('default-address-pools must be an array')
    pools = list(pools)
    for value in flags.get('default-address-pool', []):
        pools.append(dict(part.split('=', 1) for part in value.split(',')))
    for pool in pools:
        if not isinstance(pool, dict) or set(pool) != {'base', 'size'}:
            raise ValueError('address pool requires base and size')
        base = ipaddress.ip_network(pool['base'], strict=True)
        size = int(pool['size'])
        if isinstance(pool['size'], bool) or not base.prefixlen <= size <= base.max_prefixlen:
            raise ValueError('invalid address pool allocation size')


def host_ranges(interfaces, routes):
    result = set()
    for interface in interfaces:
        for address in interface.get('addr_info', []):
            if address.get('family') not in ('inet', 'inet6'):
                continue
            network = prefix(f"{address['local']}/{address['prefixlen']}")
            if not network.is_link_local and not network.is_loopback:
                result.add((network, interface['ifname']))
    for route in routes:
        destination = route.get('dst', 'default')
        if destination == 'default' or route.get('type') in ('local', 'broadcast', 'multicast'):
            continue
        network = prefix(destination)
        if network.prefixlen and not network.is_link_local and not network.is_loopback:
            result.add((network, route.get('dev', '<routed>')))
    return result


def network_ranges(networks):
    result = []
    for network in networks:
        if not re.fullmatch(r'[a-f0-9]{64}', network['Id']):
            raise ValueError('invalid Docker network ID')
        bridge = None
        if network.get('Driver') == 'bridge':
            bridge = (network.get('Options') or {}).get('com.docker.network.bridge.name')
            bridge = bridge or ('docker0' if network['Name'] == 'bridge' else 'br-' + network['Id'][:12])
        for allocation in (network.get('IPAM') or {}).get('Config') or []:
            if allocation.get('Subnet'):
                result.append((prefix(allocation['Subnet']), network['Id'], network['Name'], bridge))
    return result


def analyze(report, pool=None, exclusions=()):
    occupied = network_ranges(report['networks'])
    host = host_ranges(report['interfaces'], report['routes'])
    def conflict(code, detail):
        report['findings'].append({'severity': 'conflict', 'code': code, 'detail': detail})
    for index, (network, identity, name, bridge) in enumerate(occupied):
        for other, other_id, other_name, _ in occupied[index + 1:]:
            if identity != other_id and network.overlaps(other):
                conflict('docker-overlap', f'{name} {network} overlaps {other_name} {other}')
        for other, device in sorted(host, key=lambda item: (str(item[0]), item[1])):
            if bridge == device and other.version == network.version and other.subnet_of(network):
                continue
            if network.overlaps(other):
                conflict('host-overlap', f'{name} {network} overlaps host {other} on {device}')
        for other in exclusions:
            if network.overlaps(other):
                conflict('excluded-overlap', f'{name} {network} overlaps operator exclusion {other}')
    if pool is not None:
        # A reserved pool can contain allocations; report occupied slices instead
        # of treating expected children as a conflict or promising it is empty.
        report['pool'] = {'cidr': str(pool), 'occupiedDockerSubnets': [], 'excludedCidrs': [str(item) for item in exclusions]}
        own_bridges = {bridge for network, _, _, bridge in occupied if bridge and network.version == pool.version and network.subnet_of(pool)}
        for network, _, name, _ in occupied:
            if pool.overlaps(network):
                report['pool']['occupiedDockerSubnets'].append({'network': name, 'cidr': str(network)})
        for network, device in host:
            if device in own_bridges and any(device == bridge and network.version == item.version and network.subnet_of(item) for item, _, _, bridge in occupied):
                continue
            if pool.overlaps(network):
                conflict('pool-host-overlap', f'Pool {pool} overlaps host {network} on {device}')
        for network in exclusions:
            if pool.overlaps(network):
                report['findings'].append({'severity': 'warning', 'code': 'pool-exclusion', 'detail': f'Exclude {network} when allocating within {pool}.'})
    declarations = []
    effective_pools = report['docker'].get('DefaultAddressPools')
    if effective_pools is not None and (not isinstance(effective_pools, list) or any(not isinstance(item, dict) for item in effective_pools)):
        raise ValueError('invalid daemon-reported address pools')
    for item in effective_pools or []:
        declarations.append(('daemon-reported', prefix(item.get('Base', item.get('base')))))
    for item in report['daemon'].get('diskNetworkSettings', {}).get('default-address-pools', []):
        declarations.append(('on-disk', prefix(item['base'])))
    for item in report['daemon'].get('runningNetworkFlags', {}).get('default-address-pool', []):
        declarations.append(('running-argument', prefix(dict(part.split('=', 1) for part in item.split(','))['base'])))
    docker_bridges = {bridge for _, _, _, bridge in occupied if bridge}
    for source, base in declarations:
        for network, device in sorted(host, key=lambda item: (str(item[0]), item[1])):
            if device not in docker_bridges and base.overlaps(network):
                report['findings'].append({'severity': 'warning', 'code': 'default-pool-host-intersection',
                    'detail': f'{source} pool {base} intersects host {network} on {device}; allocation must exclude this range.'})


def collect(inspector, helper, pool=None):
    report = inspector.report
    if helper.container_context():
        inspector.finding('incomplete', 'container-context', 'Run this script outside the container, on the Docker host.')
        return report
    endpoint = inspector.optional('docker-endpoint', lambda: helper.local_endpoint('docker', run=inspector.run))
    if endpoint is None:
        return report
    report['docker']['endpoint'] = endpoint
    info = inspector.optional('docker-info', lambda: decode(inspector.run(['docker', '--host', endpoint, 'info', '--format', '{{json .}}'])))
    if isinstance(info, dict):
        report['docker'].update({key: info.get(key) for key in ('ID', 'ServerVersion', 'DefaultAddressPools')})
        if info.get('DefaultAddressPools') is None:
            inspector.finding('warning', 'pools-unreported', 'Docker did not report effective default address pools; no defaults are inferred.')
        if any('rootless' in str(option) for option in info.get('SecurityOptions', [])):
            inspector.finding('incomplete', 'rootless-daemon', 'Rootless Docker requires namespace-specific inspection.')
        else:
            inspector.optional('daemon-inspection', lambda: inspector.inspect_daemon(endpoint))
    elif info is not None:
        inspector.finding('incomplete', 'docker-info', 'Docker info did not return an object.')
    networks = inspector.optional('docker-networks', lambda: helper.inspect_networks('docker', endpoint, run=inspector.run))
    if networks is not None:
        for item in networks:
            entry = {key: item.get(key) for key in ('Id', 'Name', 'Driver', 'Internal', 'EnableIPv6')}
            entry['IPAM'] = {'Config': (item.get('IPAM') or {}).get('Config') or []}
            entry['Options'] = {key: value for key, value in (item.get('Options') or {}).items()
                                if key == 'com.docker.network.bridge.name'}
            report['networks'].append(entry)
    for family in ('-4', '-6'):
        routes = inspector.optional('host-routes-' + family, lambda: object_list(inspector.run(['ip', '-j', family, 'route', 'show', 'table', 'all'])))
        if routes is not None:
            report['routes'].extend(routes)
    addresses = inspector.optional('host-interfaces', lambda: object_list(inspector.run(['ip', '-j', 'address', 'show'])))
    if addresses is not None:
        report['interfaces'] = [{'ifname': item['ifname'], 'addr_info': item.get('addr_info', [])} for item in addresses]
    config = inspector.optional('review-pool-config', lambda: helper.read_configuration(helper.configuration_path()))
    exclusions = [prefix(item) for item in config['excludedCidrs']] if config else []
    if pool is None and config:
        pool = prefix(config['pool'])
    inspector.optional('range-analysis', lambda: analyze(report, pool, exclusions))
    if pool is None:
        inspector.finding('warning', 'pool-not-selected', 'No review pool configured or proposed; existing allocations were inspected only.')
    return report


def object_list(contents):
    value = decode(contents)
    if not isinstance(value, list) or any(not isinstance(item, dict) for item in value):
        raise ValueError('inspection requires an array of objects')
    return value


def finish(report):
    severities = {item['severity'] for item in report['findings']}
    code = 2 if 'conflict' in severities else 3 if 'incomplete' in severities else 0
    report['status'] = {0: 'checked', 2: 'conflict', 3: 'incomplete'}[code]
    return code


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--json', action='store_true', help='JSON output; never prompts')
    parser.add_argument('--sudo', action='store_true', help='explicitly authorize sudo for otherwise unreadable metadata')
    parser.add_argument('--pool', type=lambda value: ipaddress.ip_network(value, strict=True), help='inspect a proposed pool without saving it')
    args = parser.parse_args()
    inspector = Inspector(args.sudo, not args.json and sys.stdin.isatty() and sys.stderr.isatty())
    try:
        report = collect(inspector, load_network_helper(), args.pool)
    except (OSError, ValueError, TypeError, KeyError, subprocess.SubprocessError) as error:
        inspector.finding('incomplete', 'inspection-failed', str(error))
        report = inspector.report
    code = finish(report)
    if args.json:
        print(json.dumps(report, indent=2))
    else:
        print('Docker network preflight (read-only): ' + report['status'])
        for label in ('docker', 'daemon', 'pool'):
            if report.get(label):
                print(label + ': ' + json.dumps(report[label], sort_keys=True))
        for network in report['networks']:
            print('network: ' + json.dumps(network, sort_keys=True))
        for finding in report['findings']:
            print(f"[{finding['severity'].upper()}] {finding['code']}: {finding['detail']}")
        for limitation in report['limitations']:
            print(limitation)
    return code


if __name__ == '__main__':
    sys.exit(main())
