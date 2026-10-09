#!/usr/bin/env python3
"""Allocate review bridges only inside an explicitly reserved private pool."""
import argparse
import hashlib
import importlib.util
import ipaddress
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys


PRIVATE_RANGES = tuple(ipaddress.IPv4Network(value) for value in
                       ('10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16'))
NETWORK_ID = re.compile(r'[a-f0-9]{64}')
BRIDGE_NAME = re.compile(r'[A-Za-z0-9_.-]{1,15}')
MAX_OUTPUT = 16 * 1024 * 1024


def configuration_path():
    return Path(os.environ.get('NOSH_REVIEW_NETWORK_CONFIG', str(
        Path(os.environ.get('XDG_CONFIG_HOME', str(Path.home() / '.config')))
        / 'nosh/review-network.json')))


def canonical_network(value):
    if not isinstance(value, str):
        raise ValueError('network prefixes must be canonical IPv4 CIDRs')
    network = ipaddress.IPv4Network(value, strict=True)
    if str(network) != value:
        raise ValueError('network prefixes must be canonical IPv4 CIDRs')
    return network


def validate_configuration(value):
    if not isinstance(value, dict) or set(value) != {'schemaVersion', 'pool', 'excludedCidrs'}:
        raise ValueError('review network configuration must contain schemaVersion, pool and excludedCidrs')
    if type(value['schemaVersion']) is not int or value['schemaVersion'] != 1:
        raise ValueError('unsupported review network configuration schema')
    pool = canonical_network(value['pool'])
    if not 16 <= pool.prefixlen <= 29 or not any(pool.subnet_of(item) for item in PRIVATE_RANGES):
        raise ValueError('reserved pool must be an RFC1918 IPv4 CIDR with prefix /16 through /29')
    excluded = value['excludedCidrs']
    if not isinstance(excluded, list) or len(excluded) > 1024:
        raise ValueError('excludedCidrs must be a list of at most 1024 IPv4 CIDRs')
    for item in excluded:
        canonical_network(item)
    if len(set(excluded)) != len(excluded):
        raise ValueError('excludedCidrs contains duplicate prefixes')
    return {'schemaVersion': 1, 'pool': str(pool), 'excludedCidrs': sorted(excluded)}


def configuration_digest(config):
    encoded = json.dumps(config, sort_keys=True, separators=(',', ':')).encode()
    return 'sha256:' + hashlib.sha256(encoded).hexdigest()


def validate_path(path, create=False):
    path = Path(path)
    if not path.is_absolute() or path.resolve() != path or path.is_symlink():
        raise ValueError('review network configuration must use an absolute path without symlinks')
    if create:
        path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    if path.parent.exists():
        parent = path.parent.stat()
        if not stat.S_ISDIR(parent.st_mode) or parent.st_uid != os.getuid() or parent.st_mode & 0o022:
            raise ValueError('review network configuration directory must be caller-owned and not writable by others')
    return path


def unique_object(items):
    result = {}
    for key, value in items:
        if key in result:
            raise ValueError('duplicate configuration field: ' + key)
        result[key] = value
    return result


def read_configuration(path):
    path = validate_path(path)
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except FileNotFoundError:
        return None
    with os.fdopen(descriptor, encoding='utf-8') as stream:
        info = os.fstat(stream.fileno())
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
                or stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 1
                or info.st_size > 65536):
            raise ValueError('review network configuration must be a private caller-owned 0600 regular file')
        contents = stream.read(65537)
        after = os.fstat(stream.fileno())
        identity = lambda item: (item.st_dev, item.st_ino, item.st_size, item.st_mode,
                                 item.st_uid, item.st_nlink, item.st_mtime_ns, item.st_ctime_ns)
        if len(contents) > 65536 or identity(after) != identity(info):
            raise ValueError('review network configuration changed while reading')
    return validate_configuration(json.loads(contents, object_pairs_hook=unique_object))


def configure(path, pool, exclusions):
    config = validate_configuration({'schemaVersion': 1, 'pool': pool, 'excludedCidrs': exclusions})
    path = validate_path(path, create=True)
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, 'w', encoding='utf-8') as stream:
        json.dump(config, stream, indent=2)
        stream.write('\n')
        stream.flush()
        os.fsync(stream.fileno())
    return config


def command(arguments):
    environment = os.environ.copy()
    # Context discovery supplies an explicit name when this variable is set.
    # Network inspection uses --host to pin the endpoint selected by discovery.
    environment.pop('DOCKER_CONTEXT', None)
    result = subprocess.run(arguments, text=True, stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, timeout=30, check=False, env=environment)
    if result.returncode != 0:
        raise ValueError(f'{Path(arguments[0]).name} inspection failed (exit {result.returncode})')
    if len(result.stdout) > MAX_OUTPUT:
        raise ValueError('network inspection output exceeds the size limit')
    return result.stdout


def container_context():
    if Path('/.dockerenv').exists() or Path('/run/.containerenv').exists() or os.environ.get('container'):
        return True
    try:
        return bool(re.search(r'docker|kubepods|containerd|(?:^|/)lxc(?:/|\.)',
                              Path('/proc/1/cgroup').read_text()))
    except OSError:
        # A missing host process view cannot establish the host route context.
        return True


def local_endpoint(docker, run=command, environment=None):
    environment = os.environ if environment is None else environment
    context = environment.get('DOCKER_CONTEXT')
    if context:
        endpoint = json.loads(run([docker, 'context', 'inspect', context,
                                   '--format', '{{json .Endpoints.docker.Host}}']))
    elif environment.get('DOCKER_HOST'):
        endpoint = environment['DOCKER_HOST']
    else:
        endpoint = json.loads(run([docker, 'context', 'inspect',
                                   '--format', '{{json .Endpoints.docker.Host}}']))
    if (not isinstance(endpoint, str) or not re.fullmatch(r'unix:///[^\x00-\x20\x7f?#]+', endpoint)):
        raise ValueError('review network allocation requires a local Unix Docker endpoint')
    return endpoint


def inspect_networks(docker, endpoint, run=command):
    prefix = [docker, '--host', endpoint]
    ids = run([*prefix, 'network', 'ls', '--no-trunc', '--quiet']).split()
    if len(ids) > 8192 or len(set(ids)) != len(ids) or any(not NETWORK_ID.fullmatch(item) for item in ids):
        raise ValueError('Docker returned invalid network identities')
    if not ids:
        return []
    networks = json.loads(run([*prefix, 'network', 'inspect', *ids]))
    if (not isinstance(networks, list) or len(networks) != len(ids)
            or any(not isinstance(item, dict) for item in networks)
            or {item.get('Id') for item in networks} != set(ids)):
        raise ValueError('Docker network inspection did not match the requested identities')
    return networks


def route_network(value):
    if not isinstance(value, str):
        raise ValueError('host route inspection returned a missing or invalid destination')
    if value == 'default':
        return None
    network = ipaddress.IPv4Network(value, strict=False)
    return None if network.prefixlen == 0 else network


def occupied_networks(networks, routes, addresses, exclude_id=None, exclude_bridge=None):
    result = []
    for network in networks:
        if exclude_id is not None and network.get('Id') == exclude_id:
            continue
        ipam = network.get('IPAM')
        # Docker's built-in host/none networks allocate no subnet and may
        # serialize Config as null. Do not extend this exception to bridges
        # or plugins, whose allocation must be available for overlap checks.
        builtin_without_subnet = (network.get('Name'), network.get('Driver')) in {
            ('host', 'host'), ('none', 'null'),
        }
        if isinstance(ipam, dict) and ipam.get('Config') is None and builtin_without_subnet:
            continue
        if not isinstance(ipam, dict) or not isinstance(ipam.get('Config'), list):
            raise ValueError(f"Docker returned malformed IPAM configuration for network {network.get('Name', network.get('Id'))!r}")
        for entry in ipam['Config']:
            if not isinstance(entry, dict) or not isinstance(entry.get('Subnet'), str):
                raise ValueError('Docker returned a missing IPAM subnet')
            parsed = ipaddress.ip_network(entry['Subnet'], strict=False)
            if parsed.version == 4:
                result.append(parsed)
    if not isinstance(routes, list) or not isinstance(addresses, list):
        raise ValueError('host route or interface inspection returned invalid data')
    for route in routes:
        if not isinstance(route, dict):
            raise ValueError('host route inspection returned an invalid record')
        if exclude_bridge and route.get('dev') == exclude_bridge:
            continue
        parsed = route_network(route.get('dst'))
        if parsed is not None:
            result.append(parsed)
    for interface in addresses:
        if (not isinstance(interface, dict) or not isinstance(interface.get('ifname'), str)
                or not isinstance(interface.get('addr_info'), list)):
            raise ValueError('host interface inspection returned an invalid record')
        if exclude_bridge and interface['ifname'] == exclude_bridge:
            continue
        for address in interface['addr_info']:
            if not isinstance(address, dict):
                raise ValueError('host interface inspection returned an invalid address')
            if address.get('family') != 'inet':
                raise ValueError('IPv4 interface inspection returned an unexpected address family')
            prefix = address.get('prefixlen')
            if type(prefix) is not int or not 0 <= prefix <= 32:
                raise ValueError('host interface inspection returned an invalid prefix')
            result.append(ipaddress.IPv4Network(f"{address.get('local')}/{prefix}", strict=False))
    return result


def host_endpoint(docker, run=command, is_container=container_context, environment=None):
    if is_container():
        raise ValueError('run review network allocation on the Docker host, outside containers')
    return local_endpoint(docker, run, environment)


def host_snapshot(docker, run=command, is_container=container_context, environment=None):
    environment = os.environ if environment is None else environment
    endpoint = host_endpoint(docker, run, is_container, environment)
    ip = environment.get('NOSH_REVIEW_IP_BIN', 'ip')
    return (inspect_networks(docker, endpoint, run),
            json.loads(run([ip, '-j', '-4', 'route', 'show', 'table', 'all'])),
            json.loads(run([ip, '-j', '-4', 'address', 'show'])))


def select_subnet(config, key, occupied):
    if not isinstance(key, str) or not key or len(key) > 4096:
        raise ValueError('review network allocation requires a bounded nonempty service key')
    pool = canonical_network(config['pool'])
    excluded = [canonical_network(value) for value in config['excludedCidrs']]
    total = pool.num_addresses // 8
    offset = int.from_bytes(hashlib.sha256(key.encode()).digest(), 'big') % total
    for attempt in range(total):
        base = int(pool.network_address) + ((offset + attempt) % total) * 8
        candidate = ipaddress.IPv4Network((base, 29))
        if not any(candidate.overlaps(item) for item in occupied + excluded):
            return str(candidate), str(candidate.network_address + 1)
    raise ValueError('reserved review network pool has no free /29 subnet; no network was created')


def verify_network(config, network_id, subnet, gateway, networks, routes, addresses):
    if not NETWORK_ID.fullmatch(network_id):
        raise ValueError('verification requires an exact Docker network ID')
    candidate = canonical_network(subnet)
    if candidate.prefixlen != 29 or not candidate.subnet_of(canonical_network(config['pool'])):
        raise ValueError('review network subnet is outside the configured reserved pool')
    if gateway != str(candidate.network_address + 1):
        raise ValueError('review network gateway differs from the expected allocation')
    if any(candidate.overlaps(canonical_network(value)) for value in config['excludedCidrs']):
        raise ValueError('review network overlaps a configured excluded prefix')
    matching = [item for item in networks if item.get('Id') == network_id]
    if len(matching) != 1:
        raise ValueError('review network identity was not found exactly once')
    target = matching[0]
    entries = target.get('IPAM', {}).get('Config')
    if (target.get('Driver') != 'bridge' or target.get('EnableIPv6') is not False
            or not isinstance(entries, list) or len(entries) != 1
            or not isinstance(entries[0], dict) or entries[0].get('Subnet') != subnet
            or entries[0].get('Gateway') != gateway or entries[0].get('IPRange')
            or entries[0].get('AuxiliaryAddresses') or entries[0].get('AuxAddress')):
        raise ValueError('review network IPAM or bridge configuration differs from the allocation')
    options = target.get('Options')
    if not isinstance(options, dict):
        raise ValueError('review network bridge options are malformed')
    bridge = options.get('com.docker.network.bridge.name') or 'br-' + network_id[:12]
    if not isinstance(bridge, str) or not BRIDGE_NAME.fullmatch(bridge):
        raise ValueError('review network bridge interface name is invalid')
    if len([item for item in addresses if isinstance(item, dict) and item.get('ifname') == bridge]) != 1:
        raise ValueError('review network bridge interface is not present on this host')
    occupied = occupied_networks(networks, routes, addresses, network_id, bridge)
    if any(candidate.overlaps(item) for item in occupied):
        raise ValueError('review network overlaps another host route, interface or Docker network')
    return configuration_digest(config)


def status(config, path=None):
    result = {'schemaVersion': 1, 'status': 'configured' if config else 'missing',
              'pool': config['pool'] if config else None,
              'excludedCidrs': config['excludedCidrs'] if config else [],
              'configDigest': configuration_digest(config) if config else None}
    if path is not None:
        result['path'] = str(path)
    return result


def checked_host_report():
    spec = importlib.util.spec_from_file_location('network_preflight', Path(__file__).with_name('nosh-network-preflight.py'))
    module = importlib.util.module_from_spec(spec)
    previous = sys.dont_write_bytecode
    try:
        sys.dont_write_bytecode = True
        spec.loader.exec_module(module)
        inspector = module.Inspector(interactive=sys.stdin.isatty() and sys.stderr.isatty())
        report = module.collect(inspector, module.load_network_helper())
    finally:
        sys.dont_write_bytecode = previous
    incomplete = [item['detail'] for item in report['findings'] if item['severity'] == 'incomplete']
    incomplete += [item['detail'] for item in report['findings']
                   if item['severity'] == 'conflict' and item['code'] in ('invalid-daemon-config', 'duplicate-declaration')]
    if incomplete:
        raise ValueError('host inspection incomplete: ' + '; '.join(incomplete))
    if report['daemon'].get('endpointAssociated') is not True or report['daemon'].get('networkNamespaceMatches') is not True:
        raise ValueError('host inspection did not establish the selected daemon and network namespace')
    return report


def suggestion_blockers(report, exclusions):
    blockers = [(ipaddress.IPv4Network('10.240.0.0/16'), 'Guard runtime reservation')]
    def add(value, reason):
        network = ipaddress.ip_network(value, strict=False)
        if network.version == 4 and network.prefixlen:
            blockers.append((network, reason))
    for network in report['networks']:
        for item in network['IPAM']['Config']:
            if item.get('Subnet'):
                add(item['Subnet'], 'Docker network ' + network['Name'])
    for route in report['routes']:
        if route.get('dst', 'default') != 'default':
            add(route['dst'], 'host route')
    for interface in report['interfaces']:
        for address in interface['addr_info']:
            if address['family'] == 'inet':
                add(f"{address['local']}/{address['prefixlen']}", 'interface ' + interface['ifname'])
    for item in report['docker'].get('DefaultAddressPools') or []:
        add(item.get('Base', item.get('base')), 'daemon-reported default pool')
    daemon = report['daemon']
    for item in daemon.get('diskNetworkSettings', {}).get('default-address-pools', []):
        add(item['base'], 'configured Docker default pool')
    for item in daemon.get('runningNetworkFlags', {}).get('default-address-pool', []):
        add(dict(part.split('=', 1) for part in item.split(','))['base'], 'running Docker default pool')
    for key in ('bip', 'fixed-cidr'):
        for value in daemon.get('runningNetworkFlags', {}).get(key, []):
            add(value, 'running Docker ' + key)
        if key in daemon.get('diskNetworkSettings', {}):
            add(daemon['diskNetworkSettings'][key], 'configured Docker ' + key)
    for value in exclusions:
        blockers.append((canonical_network(value), 'operator exclusion'))
    return blockers


def pool_conflicts(pool, blockers):
    return [{'cidr': str(network), 'reason': reason} for network, reason in blockers if pool.overlaps(network)]


def suggest_pools(report, exclusions):
    blockers = suggestion_blockers(report, exclusions)
    families = [
        [f'10.{index}.0.0/26' for index in range(256)],
        [f'172.{index}.0.0/26' for index in range(16, 32)],
        [f'192.168.{index}.0/26' for index in range(256)],
    ]
    groups = []
    rejected = []
    for family in families:
        clear = []
        for value in family:
            conflicts = pool_conflicts(canonical_network(value), blockers)
            if conflicts:
                if len(rejected) < 6:
                    rejected.append({'pool': value, 'conflict': conflicts[0]})
            elif len(clear) < 3:
                clear.append(value)
        groups.append(clear)
    choices = [group[0] for group in groups if group]
    for group in groups:
        for value in group[1:]:
            if len(choices) < 3:
                choices.append(value)
    return {'schemaVersion': 1, 'status': 'checked', 'prefixLength': 26,
            'endpoint': report['docker']['endpoint'],
            'suggestions': [{'pool': value, 'reviewNetworks': 8} for value in choices],
            'rejectedExamples': rejected,
            'warnings': [item['detail'] for item in report['findings'] if item['severity'] == 'warning']}


def check_configuration_host(pool, exclusions, report):
    conflicts = pool_conflicts(canonical_network(pool), suggestion_blockers(report, exclusions))
    if conflicts:
        first = conflicts[0]
        raise ValueError(f"selected pool {pool} overlaps {first['cidr']} ({first['reason']}); configuration was not saved")


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='action', required=True)
    state = commands.add_parser('status')
    state.add_argument('--digest', action='store_true')
    endpoint = commands.add_parser('endpoint')
    endpoint.add_argument('--docker-bin', required=True)
    setup = commands.add_parser('configure')
    setup.add_argument('--pool', required=True)
    setup.add_argument('--exclude', action='append', default=[])
    setup.add_argument('--check-host', action='store_true')
    suggest = commands.add_parser('suggest')
    suggest.add_argument('--exclude', action='append', default=[])
    choose = commands.add_parser('select')
    choose.add_argument('--docker-bin', required=True)
    choose.add_argument('--key', required=True)
    verify = commands.add_parser('verify')
    verify.add_argument('--docker-bin', required=True)
    verify.add_argument('--network-id', required=True)
    verify.add_argument('--subnet', required=True)
    verify.add_argument('--gateway', required=True)
    args = parser.parse_args(argv)
    try:
        if args.action == 'endpoint':
            print(host_endpoint(args.docker_bin))
            return 0
        path = configuration_path()
        if args.action == 'configure':
            validate_configuration({'schemaVersion': 1, 'pool': args.pool, 'excludedCidrs': args.exclude})
            if args.check_host:
                check_configuration_host(args.pool, args.exclude, checked_host_report())
            config = configure(path, args.pool, args.exclude)
            print(json.dumps(status(config, path)))
            return 0
        config = read_configuration(path)
        if args.action == 'suggest':
            exclusions = sorted(set(args.exclude + (config['excludedCidrs'] if config else [])))
            for value in exclusions:
                canonical_network(value)
            print(json.dumps(suggest_pools(checked_host_report(), exclusions)))
            return 0
        if args.action == 'status':
            if args.digest:
                if config:
                    print(configuration_digest(config))
            else:
                print(json.dumps(status(config)))
            return 0 if config else 3
        if config is None:
            raise ValueError('no reserved review network pool is configured; run nosh init to configure one')
        networks, routes, addresses = host_snapshot(args.docker_bin)
        if args.action == 'select':
            subnet, gateway = select_subnet(config, args.key, occupied_networks(networks, routes, addresses))
            print('\t'.join((subnet, gateway, configuration_digest(config))))
        else:
            print(verify_network(config, args.network_id, args.subnet, args.gateway,
                                 networks, routes, addresses))
        return 0
    except (OSError, ValueError, TypeError, subprocess.SubprocessError) as error:
        print('nosh review network: ' + str(error), file=sys.stderr)
        return 1


if __name__ == '__main__':
    sys.exit(main())
