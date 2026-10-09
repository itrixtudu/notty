#!/usr/bin/env python3
"""Wizard discovery hints and explicit local receipts; never policy authority."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
from nosh_policy_manager import discover_reports

DIGEST = re.compile(r"sha256:[a-f0-9]{64}\Z")


def object_value(value):
    return value if isinstance(value, dict) else {}


def private_json(path):
    """Only read bounded caller-owned JSON; do not follow file symlinks."""
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(fd) as stream:
            info = os.fstat(stream.fileno())
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
                    or stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 1
                    or info.st_size > 8 * 1024 * 1024):
                return {}
            encoded = stream.read(8 * 1024 * 1024 + 1)
            if len(encoded) > 8 * 1024 * 1024:
                return {}
            value = json.loads(encoded)
            return value if isinstance(value, dict) else {}
    except (OSError, ValueError):
        return {}


def command(args):
    try:
        result = subprocess.run(args, capture_output=True, text=True, timeout=3)
        return result.stdout.strip() if result.returncode == 0 else None
    except (OSError, subprocess.SubprocessError):
        return None


def read_sysctl(name):
    try:
        return (Path('/proc/sys') / name.replace('.', '/')).read_text().strip()
    except OSError:
        return None


def ipv6_routing_status():
    """Describe the live, read-only host prerequisites for dual-stack runs."""
    disabled = read_sysctl('net.ipv6.conf.all.disable_ipv6')
    forwarding = read_sysctl('net.ipv6.conf.all.forwarding')
    route_output = command(['ip', '-6', 'route', 'show', 'default'])
    route_lines = [] if route_output is None else [
        line.strip() for line in route_output.splitlines()
        if line.strip() and not re.search(r'(?:^|\s)dev\s+lo(?:\s|$)', line)
    ]
    route_interface = ''
    route_uses_ra = False
    if route_lines:
        fields = route_lines[0].split()
        if 'dev' in fields and fields.index('dev') + 1 < len(fields):
            candidate = fields[fields.index('dev') + 1]
            if re.fullmatch(r'[A-Za-z0-9_.:-]{1,15}', candidate):
                route_interface = candidate
        route_uses_ra = ('proto' in fields and fields.index('proto') + 1 < len(fields)
                         and fields[fields.index('proto') + 1] == 'ra')
    elif route_output is None:
        try:
            for line in Path('/proc/net/ipv6_route').read_text().splitlines():
                fields = line.split()
                if (len(fields) >= 10
                        and fields[0] == '0' * 32 and fields[1] == '00'
                        and fields[-1] != 'lo' and fields[5] != 'ffffffff'):
                    route_lines.append('default dev ' + fields[-1])
                    route_interface = fields[-1]
                    break
        except OSError:
            pass

    ipv6_enabled = disabled == '0'
    forwarding_enabled = forwarding == '1'
    default_route = bool(route_lines and route_interface)
    interface_accept_ra = read_sysctl(
        f'net.ipv6.conf.{route_interface}.accept_ra') if route_interface else None
    checks = [
        {
            'key': 'ipv6-enabled',
            'label': 'IPv6 enabled',
            'status': 'pass' if ipv6_enabled else 'fail',
            'detail': ('net.ipv6.conf.all.disable_ipv6=0' if ipv6_enabled else
                       f'expected 0, found {disabled if disabled is not None else "unavailable"}'),
        },
        {
            'key': 'ipv6-forwarding',
            'label': 'IPv6 forwarding',
            'status': 'pass' if forwarding_enabled else 'fail',
            'detail': ('net.ipv6.conf.all.forwarding=1' if forwarding_enabled else
                       f'expected 1, found {forwarding if forwarding is not None else "unavailable"}'),
            'remediation': 'sudo sysctl -w net.ipv6.conf.all.forwarding=1',
        },
        {
            'key': 'ipv6-default-route',
            'label': 'IPv6 default route',
            'status': 'pass' if default_route else 'fail',
            'detail': (route_lines[0] if default_route else
                       'no non-loopback IPv6 default route was found'),
        },
    ]
    if route_interface:
        ra_ok = interface_accept_ra == '2'
        checks.append({
            'key': 'ipv6-router-advertisements',
            'label': f'Router advertisements ({route_interface})',
            'status': 'pass' if ra_ok else ('warning' if route_uses_ra else 'info'),
            'detail': (
                'accept_ra=2; router advertisements remain accepted while forwarding' if ra_ok
                else f'accept_ra={interface_accept_ra if interface_accept_ra is not None else "unavailable"}'
                     + ('; this RA-learned route may disappear while forwarding' if route_uses_ra else
                        '; set 2 only if this interface relies on router advertisements')
            ),
            'remediation': f'sudo sysctl -w net.ipv6.conf.{route_interface}.accept_ra=2',
        })
    ready = ipv6_enabled and forwarding_enabled and default_route
    return {
        'status': 'ready' if ready else 'blocked',
        'detail': ('dual-stack host routing prerequisites are present' if ready else
                   'scoped runtime policy requires IPv6 forwarding and a non-loopback default route'),
        'routeInterface': route_interface or None,
        'routeUsesRouterAdvertisements': route_uses_ra,
        'checks': checks,
    }


def inspect_image(reference):
    if not isinstance(reference, str) or not reference or reference.startswith('-'):
        return None
    # Never contact a remote Docker endpoint as part of automatic discovery.
    endpoint = os.environ.get('DOCKER_HOST')
    if not endpoint:
        endpoint = command(['docker', 'context', 'inspect', '--format', '{{.Endpoints.docker.Host}}'])
    if not endpoint or not endpoint.startswith('unix://'):
        return None
    value = command(['docker', '--host', endpoint, 'image', 'inspect', '--format',
                     '{{.Id}}|{{index .Config.Labels "io.notty.guard.runner-abi"}}', reference])
    if not value:
        return None
    image, _, abi = value.partition('|')
    return (image, abi) if DIGEST.fullmatch(image) else None


def policy_tooling_status(path):
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except FileNotFoundError:
        return {'status': 'missing', 'detail': 'no saved policy tooling image'}
    except OSError:
        return {'status': 'invalid', 'detail': 'policy tooling configuration is unreadable'}
    try:
        with os.fdopen(descriptor, encoding='utf-8') as stream:
            info = os.fstat(stream.fileno())
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
                    or stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 1
                    or info.st_size > 65536):
                return {'status': 'invalid', 'detail': 'policy tooling configuration is unsafe'}
            encoded = stream.read(65537)
            if len(encoded) > 65536:
                return {'status': 'invalid', 'detail': 'policy tooling configuration is too large'}
        values = {}
        known = {'SCHEMA_VERSION', 'NOSH_POLICY_TOOLING_IMAGE', 'NOSH_POLICY_REVIEW_UI_IMAGE'}
        for line in encoded.splitlines():
            if not line or line.startswith('#'):
                continue
            key, separator, value = line.partition('=')
            if not separator or key not in known or key in values:
                return {'status': 'invalid', 'detail': 'policy tooling configuration is malformed'}
            values[key] = value
    except (OSError, UnicodeError):
        return {'status': 'invalid', 'detail': 'policy tooling configuration is unreadable'}
    image = values.get('NOSH_POLICY_TOOLING_IMAGE', '')
    review_image = values.get('NOSH_POLICY_REVIEW_UI_IMAGE', '')
    if (set(values) != known or values.get('SCHEMA_VERSION') != '1'
            or not DIGEST.fullmatch(image)
            or (review_image and not DIGEST.fullmatch(review_image))):
        return {'status': 'invalid', 'detail': 'saved policy tooling identity is invalid'}
    endpoint = os.environ.get('DOCKER_HOST')
    if not endpoint:
        endpoint = command(['docker', 'context', 'inspect', '--format', '{{.Endpoints.docker.Host}}'])
    if not endpoint or not endpoint.startswith('unix://'):
        return {'status': 'unchecked', 'detail': 'local Docker tooling identity was not inspected'}
    value = command(['docker', '--host', endpoint, 'image', 'inspect', '--format',
                     '{{.Id}}|{{index .Config.Labels "io.notty.guard.policy-tooling-abi"}}', image])
    if value == f'{image}|1':
        return {'status': 'ready', 'detail': 'saved exact local policy tooling image has ABI 1',
                'imageId': image}
    return {'status': 'missing', 'detail': 'saved policy tooling image is missing or incompatible'}


def detect(workspace, prefix, image_ref, repo, authoritative=None, workload='dev'):
    home = Path.home()
    config = Path(os.environ.get('XDG_CONFIG_HOME', home / '.config')) / 'nosh'
    state = Path(os.environ.get('NOSH_PROFILE_REVIEW_STATE_ROOT',
                               Path(os.environ.get('XDG_STATE_HOME', home / '.local/state')) / 'nosh/policy-review'))
    rows = {
        1: ('missing', 'Guard executable not found'),
        2: ('missing', 'launcher configuration not found'),
        3: ('unknown', 'no matching local image confirmed'),
        4: ('missing', 'no matching saved learning export'),
        5: ('missing', 'no completed matching review found'),
        6: ('missing', 'signing configuration absent or incomplete'),
        7: ('unknown', 'active policy requires step 8'),
        8: ('unchecked', 'explicit sudo status check; never automatic'),
        9: ('missing', 'matching source and image inventories not found'),
        10: ('missing', 'matching evidence has not been prepared for review'),
    }
    if os.access(Path(prefix) / 'bin/nosh-guard', os.X_OK):
        rows[1] = ('present', 'Guard executable found; version/daemon health not verified')
    try:
        config_path = config / 'paths.conf'
        info = config_path.lstat()
        if (stat.S_ISREG(info.st_mode) and info.st_uid == os.getuid()
                and stat.S_IMODE(info.st_mode) == 0o600 and info.st_size <= 65536):
            fields = dict(line.split('=', 1) for line in config_path.read_text().splitlines() if '=' in line)
            if (fields.get('NOSH_GUARD_PREFIX') == prefix
                    and Path(fields.get('NOSH_BIN', '/nonexistent')).resolve() == Path(repo) / 'scripts/nosh.sh'
                    and os.access(fields.get('NOSH_BIN', ''), os.X_OK)):
                rows[2] = ('configured', 'launcher points to this checkout and Guard prefix')
    except (OSError, ValueError):
        pass

    key = hashlib.sha256(workspace.encode()).hexdigest()
    mirrors = list((home / '.nosh/net-profiles').glob('*-' + key + ('-' + workload)))
    receipt = private_json(mirrors[0] / 'current.json') if len(mirrors) == 1 else {}
    if object_value(receipt.get('workspace')).get('path') != workspace:
        receipt = {}
    candidate = object_value(receipt.get('latestCandidate'))
    revision = candidate.get('revision', '')
    learned_image = candidate.get('imageDigest', '')
    inspected = inspect_image(image_ref or learned_image or ('nosh' if workspace == repo else ''))
    if (not image_ref and learned_image and workspace == repo
            and (not inspected or inspected[1] != '1')):
        inspected = inspect_image('nosh')
    image = inspected[0] if inspected else None
    if inspected:
        rows[3] = ('available', 'local image found; build-profile completion not verified')
        if inspected[1] != '1':
            rows[3] = ('incompatible', 'local image lacks Guard runner ABI 1')
    matching = bool(inspected and inspected[1] == '1' and image == learned_image
                    and isinstance(revision, str) and re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,127}', revision))
    if matching:
        exported = mirrors[0] / 'review-candidates' / key / revision
        names = ['egress-profile.json', 'egress-policy.json', 'guard-ebpf-target-context.json']
        if all(private_json(exported / name) for name in names):
            rows[4] = ('saved', 'matching runtime export found; authoritative validation occurs on use')
            learning = private_json(mirrors[0] / 'wizard-learning.json')
            if (learning.get('revision') == revision and learning.get('imageDigest') == image
                    and isinstance(learning.get('exitCode'), int) and learning['exitCode'] != 0):
                rows[4] = ('interrupted', 'learning exited with an error; saved evidence is available but learning must be repeated')
            rows['revision'] = (revision, image)
        else:
            matching = False
    elif candidate:
        rows[4] = ('stale', 'saved learning does not match a confirmed local runner image')

    # Current collection hints distinguish an old completed review from a fresh
    # draft for the same image/learning revision. Apply still validates content.
    current_inventory_digest = None
    current_inventory_tooling = None
    inventory = private_json(state / ('inventory-' + key + '.json'))
    if inventory.get('image') == image and isinstance(inventory.get('directory'), str):
        directory = Path(inventory['directory'])
        if (directory.is_absolute() and directory.resolve() == directory
                and os.path.commonpath([str(directory), str(state.resolve())]) == str(state.resolve())):
            if DIGEST.fullmatch(str(inventory.get('tooling', ''))):
                current_inventory_tooling = inventory['tooling']
            collection = private_json(directory / 'source.collection.json')
            image_collection = private_json(directory / 'image.collection.json')
            digest = object_value(collection.get('input')).get('metadataDigest')
            if (collection.get('role') == 'source' and collection.get('status') == 'complete'
                    and DIGEST.fullmatch(str(digest))
                    and DIGEST.fullmatch(str(collection.get('sbomDigest', '')))):
                current_inventory_digest = digest
            if (current_inventory_digest and current_inventory_tooling
                    and image_collection.get('role') == 'image'
                    and image_collection.get('status') == 'complete'
                    and object_value(image_collection.get('input')).get('imageDigest') == image
                    and DIGEST.fullmatch(str(image_collection.get('sbomDigest', '')))):
                rows[9] = ('saved', 'matching complete source and image inventories found')

    reviews = []
    if matching:
        for metadata in list(state.glob('*/runtime/review-session.json'))[:256]:
            session = private_json(metadata)
            if (session.get('kind') != 'NoshPolicyReviewSession'
                    or session.get('workdir') != workspace or session.get('revision') != revision
                    or session.get('imageDigest') != image):
                continue
            directory = metadata.parent.parent
            if (not directory.is_absolute() or directory.resolve() != directory
                    or session.get('directory') != str(directory)
                    or any(ord(char) < 32 or ord(char) == 127 for char in str(directory))):
                continue
            if current_inventory_tooling and session.get('toolingImage') != current_inventory_tooling:
                if not reviews and rows[5][0] != 'draft':
                    rows[5] = ('stale', 'saved selections use previous policy tooling; review the restored draft')
                continue
            decisions = private_json(directory / 'decisions/decisions.json')
            graph = private_json(metadata.parent / 'review.graph.json')
            readiness = object_value(session.get('readiness'))
            if current_inventory_digest:
                nodes = graph.get('nodes', [])
                sources = [node for node in nodes if isinstance(node, dict)
                           and node.get('nodeType') == 'evidenceSource'
                           and object_value(node.get('identity')).get('role') == 'source'] if isinstance(nodes, list) else []
                source_collection = object_value(object_value(sources[0].get('properties')).get('collection')) if len(sources) == 1 else {}
                if object_value(source_collection.get('input')).get('metadataDigest') != current_inventory_digest:
                    if not reviews and rows[5][0] != 'draft':
                        rows[5] = ('stale', 'saved selections use an older source inventory; review the refreshed draft')
                    continue
            if (graph.get('contentDigest') == session.get('graphContentDigest')
                    and session.get('graphContentDigest')):
                blockers = readiness.get('blockers')
                if readiness.get('readyForReview') is True or blockers == []:
                    rows[10] = ('ready', 'matching evidence and inventories are prepared for review')
                elif isinstance(blockers, list) and blockers:
                    rows[10] = ('blocked', 'prepared evidence has unresolved readiness blockers')
            entries = decisions.get('decisions')
            proposals = graph.get('proposals')
            if (DIGEST.fullmatch(str(decisions.get('contentDigest', '')))
                    and decisions.get('graphContentDigest') == session.get('graphContentDigest')
                    and session.get('graphContentDigest')
                    and graph.get('contentDigest') == session.get('graphContentDigest')
                    and decisions.get('graphDigest') == graph.get('graphDigest')
                    and graph.get('graphDigest')
                    and isinstance(entries, list)
                    and isinstance(proposals, list)
                    and all(isinstance(entry, dict) and isinstance(entry.get('proposalId'), str)
                            and entry.get('disposition') in ('accept', 'reject') for entry in entries)
                    and all(isinstance(proposal, dict) and isinstance(proposal.get('id'), str) for proposal in proposals)
                    and len(entries) == len(proposals)
                    and {entry.get('proposalId') for entry in entries} == {proposal['id'] for proposal in proposals}):
                coverage = graph.get('coverage', [])
                coverage = coverage if isinstance(coverage, list) else []
                missing_sboms = [domain for domain in ('sbom-source', 'sbom-image')
                                 if [entry.get('status') for entry in coverage
                                     if isinstance(entry, dict) and entry.get('domain') == domain] != ['complete']]
                if missing_sboms:
                    if not reviews:
                        rows[5] = ('needs-sbom', 'saved decisions need ' + ', '.join(missing_sboms)
                                   + '; reopen review to generate inventories before Apply')
                else:
                    blockers = readiness.get('blockers')
                    if isinstance(blockers, list) and blockers:
                        if not reviews:
                            rows[5] = ('blocked', 'saved selections have unresolved readiness blockers; prepare the review before Apply')
                    else:
                        rows[5] = ('saved', 'completed selection and SBOM coverage found; Apply verifies integrity and bindings')
                        reviews.append((str(directory), decisions['contentDigest']))
            elif not reviews and rows[5][0] != 'needs-sbom':
                rows[5] = ('draft', 'matching review exists; completed selection not found')
    for index, (directory, digest) in enumerate(sorted(reviews)):
        rows[f'review:{index}'] = (directory, digest)

    signing = private_json(Path(os.environ.get('NOSH_POLICY_APPLY_CONFIG', config / 'policy-apply.json')))
    fields = ['reviewPrivateKey', 'reviewPublicKey', 'deploymentPrivateKey', 'reviewAudience', 'deploymentAudience']
    if all(isinstance(signing.get(field), str) and signing[field] for field in fields):
        keys = [Path(signing[field]) for field in fields[:3]]
        def private_key(key):
            try:
                info = key.lstat()
                return (stat.S_ISREG(info.st_mode) and info.st_uid == os.getuid()
                        and stat.S_IMODE(info.st_mode) == 0o600 and info.st_nlink == 1
                        and os.path.commonpath([str(key.resolve()), workspace]) != workspace)
            except OSError:
                return False
        if (all(key.is_absolute() and key.is_file() for key in keys)
                and keys[0].resolve() != keys[2].resolve()
                and private_key(keys[0]) and private_key(keys[2])):
            rows[6] = ('configured', 'key paths present; host trust/key validity checked by Apply')

    if (isinstance(authoritative, dict) and object_value(authoritative.get('workspace')).get('path') == workspace
            and authoritative.get('workload') == workload):
        activation = authoritative.get('activation')
        rows[8] = ('checked', 'privileged workspace status read this session; refresh after external changes')
        if object_value(authoritative.get('integrity')).get('ok') is not True:
            rows[7] = ('unknown', 'authoritative integrity check did not pass')
        elif not activation:
            rows[7] = ('inactive', 'no active deployment for this workspace')
        elif (isinstance(activation, dict) and activation.get('imageDigest') == image and activation.get('learnRevision') == revision
              and DIGEST.fullmatch(str(activation.get('leafBundleDigest', '')))):
            rows[7] = ('active', 'deployment matches selected image and learning revision; not a running-container check')
        else:
            rows[7] = ('different', 'active deployment belongs to another image/revision')

    ready = {1: 'present', 2: 'configured', 3: 'available', 4: 'saved', 5: 'saved', 6: 'configured', 7: 'active'}
    next_step = next((step for step, value in ready.items() if rows[step][0] != value), 8)
    # Pass the verified local runner ID to the wizard, not just a display hint.
    if inspected and inspected[1] == '1':
        rows['image'] = (image, '1')
    return rows, next_step


def discover_workload_images(workspace):
    """Return base/derived workload Dockerfiles, excluding Guard infrastructure."""
    root = Path(workspace)
    found = []
    base = root / 'Dockerfile.nosh'
    if base.is_file() and not base.is_symlink():
        found.append(('nosh', str(base), True))
    pattern = re.compile(r'(?ms)^\s*ARG\s+NOSH_IMAGE(?:\s*=.*)?$.*?^\s*FROM\s+\$\{NOSH_IMAGE\}(?:\s|$)')
    for dockerfile in sorted(root.glob('Dockerfile.nosh-*')):
        if not dockerfile.is_file() or dockerfile.is_symlink():
            continue
        try:
            text = dockerfile.read_text(encoding='utf-8')
        except (OSError, UnicodeError):
            continue
        name = dockerfile.name.removeprefix('Dockerfile.')
        if re.fullmatch(r'nosh(?:-[a-z0-9][a-z0-9_.-]*)?', name) and pattern.search(text):
            found.append((name, str(dockerfile), False))
    return found


def status_entry(rows, key):
    status, detail = rows.get(key, ('unknown', 'state unavailable'))
    return {'status': status, 'detail': detail}


def build_profile_status(workspace, image_id):
    """Find a private capture for this exact local image; never policy authority."""
    missing = {'status': 'missing', 'detail': 'no saved build capture matches this image'}
    if not DIGEST.fullmatch(image_id or ''):
        return missing
    canonical = str(Path(workspace).resolve())
    key = hashlib.sha256(canonical.encode()).hexdigest()
    matches = []
    for root_name, mode in (('build-net-profiles', 'build-net-learn'),
                            ('build-profiles', 'build-profile')):
        store = Path.home() / '.nosh' / root_name / key
        # These are discovery hints. The review launcher validates the full
        # manifest and evidence again before opening or applying anything.
        try:
            for parent in (store, store.parent, store.parent.parent):
                info = parent.lstat()
                if (not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid()
                        or stat.S_IMODE(info.st_mode) != 0o700):
                    raise ValueError('unsafe build profile directory')
            directories = list(store.iterdir())
        except (OSError, ValueError):
            continue
        for directory in directories:
            if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,127}', directory.name):
                continue
            try:
                info = directory.lstat()
                if (not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid()
                        or stat.S_IMODE(info.st_mode) != 0o700):
                    continue
            except OSError:
                continue
            manifest = private_json(directory / 'evidence-manifest.json')
            project = object_value(manifest.get('project'))
            build = object_value(manifest.get('build'))
            if (manifest.get('schemaVersion') != 1
                    or manifest.get('kind') != 'NoshBuildEvidenceManifest'
                    or manifest.get('mode') != mode
                    or manifest.get('runId') != directory.name
                    or project.get('canonicalPath') != canonical or project.get('key') != key
                    or build.get('configDigest') != image_id):
                continue
            complete = (manifest.get('complete') is True and build.get('success') is True
                        and type(build.get('exitCode')) is int and build['exitCode'] == 0)
            profile = {'status': 'saved' if complete else 'incomplete',
                       'detail': 'saved build capture matches this exact image' if complete else
                       'matching build evidence is incomplete; record again before review',
                       'path': str(directory), 'imageDigest': image_id,
                       'runId': directory.name, 'mode': mode}
            generated = manifest.get('generatedAt')
            matches.append((generated if isinstance(generated, str) else '', directory.name, profile))
    return max(matches, key=lambda item: (item[0], item[1]))[2] if matches else missing


def json_status(args):
    discovered = discover_workload_images(args.workdir)
    if args.image and not any(name == args.image for name, _, _ in discovered):
        discovered.append((args.image, '', False))
    images = []
    workloads = {}
    first_rows = None
    for name, dockerfile, base in discovered:
        inspected = inspect_image(name)
        image_id, abi = inspected if inspected else ('', '')
        images.append({'name': name, 'dockerfile': dockerfile, 'base': base,
                       'status': 'available' if inspected and abi == '1' else (
                           'incompatible' if inspected else 'missing'),
                       'imageId': image_id, 'runnerAbi': abi,
                       'buildProfile': build_profile_status(args.workdir, image_id)})
        workloads[name] = {}
        selected_workloads = ('dev', 'run') if args.all_workloads else (args.workload,)
        for workload in selected_workloads:
            rows, next_step = detect(args.workdir, args.guard_prefix, image_id or name,
                                     args.repo, None, workload)
            first_rows = first_rows or rows
            workloads[name][workload] = {
                'steps': {
                    'image': status_entry(rows, 3),
                    'inventory': status_entry(rows, 9),
                    'learn': status_entry(rows, 4),
                    'prepare': status_entry(rows, 10),
                    'review': status_entry(rows, 5),
                    'signing': status_entry(rows, 6),
                    'activation': status_entry(rows, 7),
                    'authority': status_entry(rows, 8),
                },
                'nextStep': next_step,
                'revision': rows.get('revision', ('', ''))[0],
                'reviews': [
                    {'path': value[0], 'decisionDigest': value[1]}
                    for key, value in rows.items() if isinstance(key, str) and key.startswith('review:')
                ],
            }
    if first_rows is None:
        first_rows, _ = detect(args.workdir, args.guard_prefix, args.image,
                               args.repo, None, args.workload)
    network = {'status': 'unchecked', 'detail': 'review network status was not checked'}
    network_script = Path(args.repo) / 'scripts/nosh-review-network.py'
    if network_script.is_file():
        try:
            probe = subprocess.run(['python3', '-I', '-S', str(network_script), 'status'],
                                   capture_output=True, text=True, timeout=3)
        except (OSError, subprocess.SubprocessError):
            probe = None
        if probe and probe.returncode in (0, 3) and probe.stdout.strip():
            try:
                value = json.loads(probe.stdout)
                if value.get('schemaVersion') == 1:
                    network = {'status': value.get('status', 'unknown'),
                               'detail': value.get('pool') or 'review pool is not configured'}
            except ValueError:
                pass
    tools = {'status': 'unchecked', 'detail': 'tool environment policy status was not checked'}
    tool_script = Path(args.repo) / 'scripts/nosh-tool-policy.py'
    if tool_script.is_file():
        result = command(['python3', '-I', '-S', str(tool_script), 'status',
                          '--workdir', args.workdir])
        if result:
            try:
                value = json.loads(result)
                tools = {'status': 'active' if value.get('enabled') is True else 'inactive',
                         'detail': 'applied environment policy found' if value.get('enabled') is True
                         else 'no applied tool environment policy'}
                digest = value.get('policyDigest') or value.get('revision')
                if DIGEST.fullmatch(str(digest or '')):
                    tools['policyDigest'] = digest
            except ValueError:
                pass
    tools['reports'] = [{'path': path} for path in discover_reports(args.workdir, getattr(args, 'review', ''))]
    config_home = Path(os.environ.get('XDG_CONFIG_HOME') or Path.home() / '.config')
    tooling_config = Path(os.environ.get('NOSH_PROFILE_REVIEW_IMAGE_CONFIG')
                          or config_home / 'nosh/policy-review-images.conf')
    return {
        'schemaVersion': 1,
        'workspace': args.workdir,
        'guardPrefix': args.guard_prefix,
        'host': {
            'guard': status_entry(first_rows, 1),
            'launchers': status_entry(first_rows, 2),
            'signing': status_entry(first_rows, 6),
            'reviewNetwork': network,
            'runtimeNetwork': ipv6_routing_status(),
            'policyTooling': policy_tooling_status(tooling_config),
        },
        'images': images,
        'workloads': workloads,
        'tools': tools,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--workload', choices=['dev', 'run'], default='dev')
    parser.add_argument('--workdir', required=True)
    parser.add_argument('--guard-prefix', required=True)
    parser.add_argument('--repo', required=True)
    parser.add_argument('--image', default='')
    parser.add_argument('--review', default='', help='Explicit scoped tool report to include in discovery')
    parser.add_argument('--authoritative-stdin', action='store_true')
    parser.add_argument('--json', action='store_true')
    parser.add_argument('--all-workloads', action='store_true')
    parser.add_argument('--record-learning-exit', type=int)
    parser.add_argument('--previous-revision', default='')
    args = parser.parse_args()
    if args.record_learning_exit is not None:
        key = hashlib.sha256(args.workdir.encode()).hexdigest()
        mirrors = list((Path.home() / '.nosh/net-profiles').glob('*-' + key + ('-' + args.workload)))
        if len(mirrors) == 1:
            info = mirrors[0].lstat()
            if (not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid()
                    or stat.S_IMODE(info.st_mode) != 0o700 or mirrors[0].resolve() != mirrors[0]):
                raise SystemExit('Learning receipt directory is not private and caller-owned')
            receipt = private_json(mirrors[0] / 'current.json')
            candidate = object_value(receipt.get('latestCandidate'))
            if (object_value(receipt.get('workspace')).get('path') == args.workdir
                    and candidate.get('revision') != args.previous_revision
                    and candidate.get('imageDigest') == args.image):
                import tempfile
                fd, temporary = tempfile.mkstemp(prefix='.wizard-learning.', dir=mirrors[0])
                try:
                    with os.fdopen(fd, 'w') as stream:
                        json.dump({'revision': candidate.get('revision'), 'imageDigest': args.image,
                                   'exitCode': args.record_learning_exit}, stream)
                    os.replace(temporary, mirrors[0] / 'wizard-learning.json')
                finally:
                    if os.path.exists(temporary):
                        os.unlink(temporary)
        return
    if args.json:
        print(json.dumps(json_status(args), sort_keys=True))
        return
    authoritative = None
    if args.authoritative_stdin:
        try:
            authoritative = json.loads(sys.stdin.read(1024 * 1024))
        except ValueError:
            pass
    rows, next_step = detect(args.workdir, args.guard_prefix, args.image, args.repo, authoritative, args.workload)
    for step, (status, detail) in rows.items():
        print(f'{step}\t{status}\t{detail}')
    print(f'next\t{next_step}\t')


if __name__ == '__main__':
    main()
