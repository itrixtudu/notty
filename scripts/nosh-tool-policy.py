#!/usr/bin/env python3
"""Nosh environment-policy authority and Docker adapter. Never modifies Codex."""
import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import shlex
import subprocess
import sqlite3
import sys
import tempfile

STATE_ROOT = Path('/var/lib/nosh-tool-policies')
DESTINATION = '/etc/nosh/policy'
RUNTIME = '/var/lib/nosh-agent-state'
LABEL = 'io.notty.tool-policy.'
PROTECTED_TARGETS = (DESTINATION, RUNTIME, '/bin', '/sbin', '/lib', '/lib64', '/usr', '/proc', '/sys', '/dev',
                     '/etc/ld.so.preload', '/etc/ld.so.cache', '/etc/ld.so.conf', '/etc/passwd', '/etc/group',
                     '/run/nosh-tool-policy-ready', '/run/nosh-guard/release')
INPUT_FILES = ('allow.json', 'not-yet.json', 'rules-review.json', 'planning.config.toml', 'implementation.config.toml')
MAX_BYTES = 25 * 1024 * 1024
LIMITATIONS = ('individual-tools-not-enforced', 'unknown-commands-not-universally-blocked',
               'workspace-writes-not-tool-specific', 'network-policy-independent', 'remote-effects-not-filesystem-controlled')
LEGACY_TOOL_CHOICES = {'needs-review': 'unreviewed', 'read-only': 'expected',
                       'implementation': 'investigate', 'exclude': 'investigate'}
TOOL_ACTIVITY_CHOICES = {'unreviewed', 'expected', 'investigate'}


def encoded(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(',', ':')).encode()


def digest(data):
    return 'sha256:' + hashlib.sha256(data).hexdigest()


def canonical(value):
    path = Path(value).absolute()
    if path.resolve() != path or any(c in str(path) for c in ':,\n\r\0'):
        raise ValueError('Expected a canonical path without symlinks or mount separators')
    return path


def within(child, parent):
    return child == parent or parent in child.parents


def read_file(path, owner=None, private=False, maximum=MAX_BYTES):
    path = canonical(path)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_size > maximum:
            raise ValueError('Expected a bounded, singly linked regular policy file')
        if owner is not None and info.st_uid != owner:
            raise ValueError('Unexpected policy file owner')
        if info.st_mode & (0o077 if private else 0o022):
            raise ValueError('Policy file permissions are too broad')
        value = stream.read(maximum + 1)
        if len(value) > maximum:
            raise ValueError('Policy input exceeds its size limit')
        return value


def write_atomic(path, data, mode=0o444):
    fd, temporary = tempfile.mkstemp(prefix='.policy-', dir=path.parent)
    try:
        with os.fdopen(fd, 'wb') as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
            os.fchmod(stream.fileno(), mode)
        os.replace(temporary, path)
        directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def validate_environment(value):
    required = {'kind', 'schemaVersion', 'snapshotDigest', 'proposalDigest', 'workspace', 'workload',
                'allowImplementation', 'defaultMode', 'policyReadOnly', 'toolSelectionsInformational',
                'limitations', 'reviewer', 'acknowledged', 'approvedAt'}
    if not isinstance(value, dict) or set(value) != required:
        raise ValueError('Invalid environment-policy fields')
    if (value['kind'] != 'NoshEnvironmentPolicy' or value['schemaVersion'] != 1
            or value['workload'] != 'dev' or value['defaultMode'] != 'read-only'
            or value['policyReadOnly'] is not True or value['toolSelectionsInformational'] is not True
            or value['acknowledged'] is not True or type(value['allowImplementation']) is not bool
            or value['limitations'] != list(LIMITATIONS)
            or not isinstance(value['reviewer'], str) or not value['reviewer'].strip() or len(value['reviewer']) > 200
            or not isinstance(value['approvedAt'], str) or not re.fullmatch(r'\d{4}-\d\d-\d\dT[0-9:.]+Z', value['approvedAt'])):
        raise ValueError('Approve the environment permissions and all stated limitations first')
    for key in ('snapshotDigest', 'proposalDigest'):
        if not isinstance(value[key], str) or not re.fullmatch(r'sha256:[a-f0-9]{64}', value[key]):
            raise ValueError('Invalid policy evidence digest')
    canonical(value['workspace'])
    return value


def validate_request_evidence(directory, inputs, owner):
    descriptor = inputs['allow.json'].get('request_evidence')
    if descriptor != inputs['not-yet.json'].get('request_evidence'):
        raise ValueError('Request evidence descriptors disagree')
    versions = [inputs[name].get('schema_version') for name in ('allow.json', 'not-yet.json')]
    if versions[0] != versions[1] or versions[0] not in (1, 2) or (versions[0] == 2 and not descriptor):
        raise ValueError('Unsupported audit evidence version')
    if descriptor is None:
        return None
    if (not isinstance(descriptor, dict) or descriptor.get('schemaVersion') != 1
            or descriptor.get('file') != 'requests.sqlite3' or descriptor.get('originalInputs') is not True
            or not re.fullmatch(r'sha256:[a-f0-9]{64}', str(descriptor.get('digest', '')))
            or type(descriptor.get('bytes')) is not int or not 0 < descriptor['bytes'] <= 2 * 1024 ** 3
            or type(descriptor.get('uniqueRequests')) is not int or descriptor['uniqueRequests'] < 0
            or type(descriptor.get('recordedRequests')) is not int
            or descriptor['recordedRequests'] < descriptor['uniqueRequests']):
        raise ValueError('Invalid request evidence descriptor')
    filename = canonical(Path(directory) / 'requests.sqlite3')
    fd = os.open(filename, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as stream:
        info = os.fstat(stream.fileno())
        if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_uid != owner
                or info.st_mode & 0o077 or info.st_size != descriptor['bytes']):
            raise ValueError('Request evidence must be a private, singly linked owned file')
        if 'sha256:' + hashlib.file_digest(stream, 'sha256').hexdigest() != descriptor['digest']:
            raise ValueError('Request evidence changed since the audit')
        db = sqlite3.connect(f'file:/proc/self/fd/{stream.fileno()}?mode=ro', uri=True)
        try:
            db.execute('PRAGMA trusted_schema=OFF')
            db.execute('PRAGMA query_only=ON')
            if db.execute('PRAGMA user_version').fetchone()[0] != 1:
                raise ValueError('Unsupported request evidence database')
            counts = db.execute('SELECT count(*), coalesce(sum(occurrences),0) FROM requests').fetchone()
            if counts != (descriptor['uniqueRequests'], descriptor['recordedRequests']):
                raise ValueError('Request evidence counts disagree')
            expected = {}
            for category in ('allow', 'not-yet'):
                for group in inputs[category + '.json']['entries']:
                    key = hashlib.sha256(json.dumps([category, group['tool'], group['form'], group['reason']],
                                         ensure_ascii=False, separators=(',', ':')).encode()).hexdigest()
                    expected[key] = group['count']
            actual = dict(db.execute('SELECT group_id, sum(occurrences) FROM requests GROUP BY group_id'))
            if actual != {key: value for key, value in expected.items() if value}:
                raise ValueError('Request evidence group counts disagree')
        finally:
            db.close()
        after = os.fstat(stream.fileno())
        if (info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns) != (after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns):
            raise ValueError('Request evidence changed during verification')
    return descriptor


def normalize_tool_proposal(proposal):
    if not isinstance(proposal, dict) or proposal.get('schemaVersion') not in (1, 2):
        raise ValueError('Unsupported tool review proposal version')
    decisions = proposal.get('decisions')
    if not isinstance(decisions, dict):
        raise ValueError('Invalid tool activity decisions')
    normalized = {}
    for group_id, decision in decisions.items():
        if (not isinstance(group_id, str) or not isinstance(decision, dict)
                or not isinstance(decision.get('note'), str) or len(decision['note']) > 4096):
            raise ValueError('Invalid tool activity decision')
        if proposal['schemaVersion'] == 1:
            legacy = decision.get('choice')
            choice = LEGACY_TOOL_CHOICES.get(legacy)
        else:
            legacy = decision.get('legacyChoice')
            choice = decision.get('choice')
        if (choice not in TOOL_ACTIVITY_CHOICES
                or (legacy is not None and LEGACY_TOOL_CHOICES.get(legacy) != choice)):
            raise ValueError('Invalid tool activity classification')
        normalized[group_id] = {'choice': choice, 'note': decision['note']}
        if legacy is not None:
            normalized[group_id]['legacyChoice'] = legacy
    return {
        'kind': 'NoshToolReviewProposal',
        'schemaVersion': 2,
        'enforcing': False,
        'snapshotDigest': proposal.get('snapshotDigest'),
        'reviewer': proposal.get('reviewer'),
        'acknowledged': proposal.get('acknowledged'),
        'decisions': normalized,
        'completedAt': proposal.get('completedAt'),
    }


def check_review(directory, workspace, workload='dev', expected=None):
    directory, workspace = canonical(directory), canonical(workspace)
    info = workspace.stat()
    if not workspace.is_dir() or workload != 'dev':
        raise ValueError('Tool environment policies require a dev workspace')
    owner = info.st_uid
    if os.geteuid() != 0 and owner != os.getuid():
        raise ValueError('Workspace must belong to the invoking user')
    command_draft = directory / 'review/command-policy-draft.json'
    if command_draft.exists() or command_draft.is_symlink():
        command_rules = json.loads(read_file(command_draft, owner, True, 8 * 1024 * 1024))
        if command_rules.get('rules'):
            raise ValueError('Command policy cannot be activated: strict runner host enforcement has not passed live Docker/AppArmor bypass tests. No environment-only fallback is allowed.')
    inputs, hashes, total = {}, [], 0
    for name in INPUT_FILES:
        data = read_file(directory / name, owner, True)
        total += len(data)
        if total > MAX_BYTES:
            raise ValueError('Audit exceeds the input limit')
        hashes.append(name + '\0' + hashlib.sha256(data).hexdigest() + '\n')
        if name.endswith('.json'):
            inputs[name] = json.loads(data)
    snapshot = digest(''.join(hashes).encode())
    validate_request_evidence(directory, inputs, owner)
    proposal = json.loads(read_file(directory / 'review/proposal.json', owner, True, 8 * 1024 * 1024))
    if (proposal.get('kind') != 'NoshToolReviewProposal' or proposal.get('schemaVersion') not in (1, 2)
            or proposal.get('snapshotDigest') != snapshot or proposal.get('enforcing') is not False
            or proposal.get('acknowledged') is not True or not str(proposal.get('reviewer', '')).strip()):
        raise ValueError('A completed proposal bound to this audit is required')
    ids = set()
    for category in ('allow', 'not-yet'):
        report = inputs[category + '.json']
        if report.get('schema_version') not in (1, 2) or report.get('category') != category or report.get('complete') is not True or report.get('errors'):
            raise ValueError('A complete supported audit is required')
        count = 0
        for group in report['entries']:
            identity = [category, group['tool'], group['form'], group['reason']]
            group_id = hashlib.sha256(json.dumps(identity, ensure_ascii=False, separators=(',', ':')).encode()).hexdigest()
            if group_id in ids or type(group['count']) is not int or group['count'] < 0:
                raise ValueError('Duplicate or invalid audit group')
            ids.add(group_id)
            count += group['count']
        if count != report['totals'][category + '_requests']:
            raise ValueError('Audit counts do not reconcile')
    if inputs['rules-review.json'].get('errors'):
        raise ValueError('Resolve audit rule input errors first')
    history_scope = inputs['allow.json'].get('history_scope')
    if history_scope != inputs['not-yet.json'].get('history_scope'):
        raise ValueError('Audit history scopes disagree')
    if history_scope is not None:
        if (not isinstance(history_scope, dict) or history_scope.get('kind') not in ('repo', 'directory', 'all')
                or history_scope.get('dates') != 'all'
                or not isinstance(history_scope.get('excluded_roots'), list)
                or any(not isinstance(root, str) or not root.startswith('/') for root in history_scope['excluded_roots'])
                or (history_scope['kind'] == 'all' and history_scope.get('root') is not None)
                or (history_scope['kind'] != 'all' and (not isinstance(history_scope.get('root'), str)
                                                       or not history_scope['root'].startswith('/')))
                or type(history_scope.get('excluded_requests')) is not int or history_scope['excluded_requests'] < 0
                or type(history_scope.get('unattributed_requests')) is not int or history_scope['unattributed_requests'] < 0
                or (history_scope['kind'] != 'all' and history_scope['unattributed_requests'] != 0)):
            raise ValueError('A valid history scope with complete attribution is required')
    totals = inputs['allow.json']['totals']
    if (totals != inputs['not-yet.json']['totals']
            or totals['unique_requests'] != totals['allow_requests'] + totals['not-yet_requests']
            or totals['raw_requests'] != totals['unique_requests'] + totals['duplicate_requests']):
        raise ValueError('Audit totals disagree')
    normalized_proposal = normalize_tool_proposal(proposal)
    decisions = normalized_proposal['decisions']
    if set(decisions) != ids or any(v['choice'] == 'unreviewed' for v in decisions.values()):
        raise ValueError('Finish every tool activity classification before approving an environment')
    data = read_file(directory / 'review/environment-policy.json', owner, True, 8 * 1024 * 1024)
    environment = validate_environment(json.loads(data))
    proposal_digests = {digest(encoded(normalized_proposal))}
    if proposal['schemaVersion'] == 1:
        # Existing v1 environment policies remain valid, while a newly saved
        # policy may bind the in-memory v2 migration without rewriting v1.
        proposal_digests.add(digest(encoded(proposal)))
    if (environment['workspace'] != str(workspace) or environment['workload'] != workload
            or environment['snapshotDigest'] != snapshot or environment['proposalDigest'] not in proposal_digests):
        raise ValueError('Environment approval belongs to different evidence or workspace')
    revision = digest(data)
    if expected and revision != expected:
        raise ValueError('Environment policy digest changed; review the exact saved policy again')
    return environment, data, revision


class Store:
    def __init__(self, root=STATE_ROOT, owner=0):
        self.root, self.owner = Path(root), owner

    def secure(self, directory, create=False):
        directory = canonical(directory)
        if create:
            directory.mkdir(mode=0o755, parents=True, exist_ok=True)
        for current in (directory, *directory.parents):
            info = current.stat()
            if not current.is_dir() or info.st_uid != self.owner or info.st_mode & 0o022:
                # Test stores can live below the system temporary directory.
                if self.owner != 0 and current not in (self.root, directory) and not within(current, self.root):
                    break
                raise ValueError('Policy storage must be authority-owned and not writable by other users')
            if current == self.root.parent:
                break
        return directory

    def location(self, workspace, workload='dev'):
        workspace = canonical(workspace)
        if within(workspace, self.root) or within(self.root, workspace):
            raise ValueError('Workspace overlaps authority storage')
        key = hashlib.sha256((str(workspace) + '\0' + workload).encode()).hexdigest()
        return self.root / key

    def load(self, workspace, workload='dev', revision=None):
        location = self.location(workspace, workload)
        if not self.root.exists():
            return None
        self.secure(self.root)
        if not location.exists():
            return None
        self.secure(location)
        if revision is None:
            active = json.loads(read_file(location / 'active.json', self.owner))
            revision = active['revision']
        if not re.fullmatch(r'sha256:[a-f0-9]{64}', revision or ''):
            raise ValueError('Invalid applied policy revision')
        directory = self.secure(location / 'revisions' / revision[7:])
        data = read_file(directory / 'environment-policy.json', self.owner)
        if digest(data) != revision:
            raise ValueError('Applied policy digest mismatch')
        environment = validate_environment(json.loads(data))
        binding = json.loads(read_file(directory / 'binding.json', self.owner))
        current = canonical(workspace).stat()
        if (environment['workspace'] != str(canonical(workspace)) or environment['workload'] != workload
                or binding != {'uid': current.st_uid, 'gid': current.st_gid, 'dev': current.st_dev, 'ino': current.st_ino}):
            raise ValueError('Applied policy workspace identity changed')
        return {'enabled': True, 'revision': revision, 'directory': str(directory), 'environment': environment,
                'binding': binding, 'runtime': str(location / 'runtime'), 'enforcementScope': 'container-filesystem',
                'limitations': list(LIMITATIONS)}

    def activate(self, workspace, environment, data, revision):
        if os.geteuid() != self.owner:
            raise ValueError('Apply requires the installed privileged Nosh Guard authority')
        validate_environment(environment)
        if digest(data) != revision or json.loads(data) != environment or environment['workspace'] != str(canonical(workspace)):
            raise ValueError('Invalid activation binding')
        location = self.location(workspace, environment['workload'])
        self.secure(self.root, True)
        self.secure(location, True)
        lock = os.open(location / '.lock', os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
        try:
            fcntl.flock(lock, fcntl.LOCK_EX)
            info = canonical(workspace).stat()
            binding = {'uid': info.st_uid, 'gid': info.st_gid, 'dev': info.st_dev, 'ino': info.st_ino}
            revisions = self.secure(location / 'revisions', True)
            directory = revisions / revision[7:]
            if directory.exists():
                self.load(workspace, environment['workload'], revision)
            else:
                temporary = Path(tempfile.mkdtemp(prefix='.revision-', dir=revisions))
                try:
                    write_atomic(temporary / 'environment-policy.json', data)
                    write_atomic(temporary / 'binding.json', encoded(binding) + b'\n')
                    write_atomic(temporary / 'empty-config.toml', b'')
                    write_atomic(temporary / 'empty-auth.json', b'{}\n')
                    temporary.chmod(0o755)
                    temporary.rename(directory)
                except BaseException:
                    import shutil
                    shutil.rmtree(temporary, ignore_errors=True)
                    raise
            runtime = location / 'runtime'
            self.secure(runtime, True)
            for name in ('codex', 'auth'):
                child = runtime / name
                if not child.exists():
                    child.mkdir(mode=0o700)
                    if os.geteuid() == 0:
                        os.chown(child, info.st_uid, info.st_gid)
                if child.is_symlink() or not child.is_dir() or child.stat().st_uid != info.st_uid:
                    raise ValueError('Invalid isolated runtime state')
            write_atomic(location / 'active.json', encoded({'revision': revision}) + b'\n')
        finally:
            os.close(lock)
        return self.load(workspace, environment['workload'])


def assert_no_submounts(source):
    source = str(canonical(source))
    for line in Path('/proc/self/mountinfo').read_text().splitlines():
        mount = line.split()[4]
        mount = re.sub(r'\\([0-7]{3})', lambda m: chr(int(m[1], 8)), mount)
        if mount.startswith(source.rstrip('/') + '/'):
            raise ValueError('Nested host mounts must be removed before a policy-enabled launch')


def check_auth_state(source, workspace, applied):
    info = source.stat()
    if (not source.is_dir() or info.st_uid != applied['binding']['uid'] or info.st_mode & 0o077
            or within(source, workspace) or within(workspace, source)
            or within(source, STATE_ROOT) or within(STATE_ROOT, source)):
        raise ValueError('Application auth state must be a private directory outside the workspace and policy authority')


def check_no_host_ipc(source):
    candidates = [source]
    if source.is_dir():
        candidates.extend(Path(root) / name for root, dirs, files in os.walk(source, followlinks=False)
                          for name in files)
    for candidate in candidates:
        info = candidate.lstat()
        if stat.S_ISSOCK(info.st_mode) or stat.S_ISBLK(info.st_mode) or stat.S_ISCHR(info.st_mode):
            raise ValueError('Host sockets and devices cannot be exposed through directory mounts')


def check_protected_tree(source):
    # Reject hard-link write aliases of protected configuration, and host IPC.
    candidates = [source]
    if source.is_dir():
        candidates.extend(Path(root) / name for root, dirs, files in os.walk(source, followlinks=False)
                          for name in [*dirs, *files])
    for candidate in candidates:
        info = candidate.lstat()
        if stat.S_ISSOCK(info.st_mode) or stat.S_ISBLK(info.st_mode) or stat.S_ISCHR(info.st_mode):
            raise ValueError('Host sockets and devices cannot be exposed through policy mounts')
        if stat.S_ISREG(info.st_mode) and info.st_nlink != 1:
            raise ValueError('Protected configuration has a hard-linked writable alias')
        if stat.S_ISLNK(info.st_mode):
            raise ValueError('Protected configuration must not contain symbolic links')


def adapt_spec(spec, workspace, mode=None, store=None):
    store = store or Store()
    workload = spec.get('Labels', {}).get('io.notty.guard.workload', 'dev')
    applied = store.load(workspace, workload)
    if not applied:
        if mode:
            raise ValueError('No applied environment policy; use nosh tools apply first')
        return spec
    mode = mode or 'read-only'
    if mode not in ('read-only', 'implementation') or (mode == 'implementation' and not applied['environment']['allowImplementation']):
        raise ValueError('Requested mode is not approved; review and apply an updated environment policy')
    workspace = canonical(workspace)
    host = spec.setdefault('HostConfig', {})
    if (host.get('Privileged') or host.get('CapAdd') or host.get('Devices') or host.get('DeviceRequests')
            or host.get('Mounts') or host.get('VolumesFrom') or spec.get('Volumes')
            or host.get('NetworkMode') == 'host' or str(host.get('NetworkMode', '')).startswith('container:')
            or host.get('PidMode') == 'host' or host.get('IpcMode') == 'host'):
        raise ValueError('Conflicting Docker privileges, image volumes, or extra mount configuration')
    if any(x in ('seccomp=unconfined', 'apparmor=unconfined') for x in host.get('SecurityOpt', [])):
        raise ValueError('Unconfined container security options are incompatible with tool policy')
    state = canonical(applied['runtime'])
    revision = canonical(applied['directory'])
    env = dict(entry.split('=', 1) for entry in spec.get('Env', []) if '=' in entry)
    if any(value for key, value in env.items() if key.startswith('LD_') or key in ('BASH_ENV', 'ENV')):
        raise ValueError('Loader and shell startup injection variables are incompatible with the release gate')
    old_codex = env.get('CODEX_HOME')
    binds, codex_source = [], None
    for value in host.get('Binds', []):
        fields = value.split(':')
        if len(fields) != 3 or fields[2] not in ('ro', 'rw'):
            raise ValueError('Unsupported bind syntax in policy-enabled container')
        source, target = canonical(fields[0]), Path(fields[1])
        if not target.is_absolute() or '..' in target.parts:
            raise ValueError('Invalid container mount destination')
        if (within(source, store.root) or within(store.root, source)
                or any(within(target, Path(protected)) or within(Path(protected), target)
                       for protected in PROTECTED_TARGETS)):
            raise ValueError('A mount overlaps protected policy, runtime, gate, or system paths')
        if not source.exists() or source.is_socket() or source.is_char_device() or source.is_block_device():
            raise ValueError('Host control sockets and devices cannot be mounted')
        assert_no_submounts(source)
        check_no_host_ipc(source)
        if str(target) == old_codex:
            codex_source = source
        access = 'rw' if source == workspace and target == workspace and mode == 'implementation' else 'ro'
        if str(target) == env.get('NOTTY_AUTH_STATE_DIR'):
            check_auth_state(source, workspace, applied)
            access = 'rw'
        binds.append(f'{source}:{target}:{access}')
    if not any(value.split(':')[:2] == [str(workspace), str(workspace)] for value in binds):
        raise ValueError('Workspace bind is missing')
    binds.extend([f'{revision}:{DESTINATION}:ro', f'{state / "codex"}:{RUNTIME}/codex:rw'])
    # Isolated Codex state, with existing credentials/settings mounted read-only.
    protected_names = set()
    if codex_source:
        names = ['auth.json', 'config.toml', 'AGENTS.md', 'AGENTS.override.md', 'rules', 'skills', 'plugins', 'prompts', 'hooks.json']
        names += [p.name for p in codex_source.glob('*.config.toml')]
        for name in dict.fromkeys(names):
            source = codex_source / name
            if source.exists():
                canonical(source)
                check_protected_tree(source)
                assert_no_submounts(source)
                binds.append(f'{source}:{RUNTIME}/codex/{name}:ro')
                protected_names.add(name)
    for name in ('auth.json', 'config.toml'):
        if name not in protected_names:
            binds.append(f'{revision / ("empty-" + name)}:{RUNTIME}/codex/{name}:ro')
    # Protect existing project agent configuration from implementation writes.
    for name in ('.codex', '.agents', 'AGENTS.md', 'AGENTS.override.md'):
        source = workspace / name
        if source.exists():
            canonical(source)
            check_protected_tree(source)
            assert_no_submounts(source)
            target = str(source)
            binds = [value for value in binds if value.split(':')[1] != target]
            binds.append(f'{source}:{target}:ro')
    uid, gid = applied['binding']['uid'], applied['binding']['gid']
    if uid == 0:
        raise ValueError('Policy-enabled agents must run as a non-root workspace owner')
    spec['User'] = f'{uid}:{gid}'
    spec['Healthcheck'] = {'Test': ['NONE']}
    host.update({'Binds': binds, 'ReadonlyRootfs': True, 'CapDrop': ['ALL'], 'CapAdd': [],
                 'Privileged': False, 'Devices': [], 'PidsLimit': min(host.get('PidsLimit') or 512, 512)})
    host['SecurityOpt'] = list(dict.fromkeys([*host.get('SecurityOpt', []), 'no-new-privileges:true']))
    # Scratch is never a writable alias of host files.
    host['Tmpfs'] = {'/tmp': 'rw,nosuid,nodev,noexec,size=268435456,mode=1777',
                     '/run': 'rw,nosuid,nodev,noexec,size=67108864,mode=0755'}
    home = env.get('HOME')
    if home and re.fullmatch(r'/home/[^/]+', home) and not any(within(Path(home), Path(value.split(':')[1])) for value in binds):
        host['Tmpfs'][home] = f'rw,nosuid,nodev,noexec,size=67108864,mode=0700,uid={uid},gid={gid}'
    env.update({'CODEX_HOME': RUNTIME + '/codex', 'NOSH_TOOL_MODE': mode,
                'NOSH_TOOL_POLICY': DESTINATION + '/environment-policy.json',
                'NOSH_TOOL_POLICY_REVISION': applied['revision']})
    spec['Env'] = [f'{key}={value}' for key, value in env.items()]
    spec.setdefault('Labels', {}).update({LABEL + 'revision': applied['revision'], LABEL + 'mode': mode,
                                         LABEL + 'scope': 'container-filesystem'})
    spec['Labels'][LABEL + 'mount-digest'] = digest(encoded(sorted(binds)))
    return spec


def verify_live_mounts(inspected):
    state = inspected.get('State')
    if not isinstance(state, dict):
        raise ValueError('Docker did not provide container state')
    if not state.get('Running'):
        return
    pid = state.get('Pid')
    if type(pid) is not int or pid <= 0:
        raise ValueError('Live mount verification requires the local container PID')
    for mount in inspected.get('Mounts', []):
        if mount['Type'] != 'bind':
            continue
        host = canonical(mount['Source']).stat()
        try:
            live = os.stat(f"/proc/{pid}/root{mount['Destination']}")
        except OSError as error:
            raise ValueError('Cannot inspect live mounts; use a local Linux Docker daemon with accessible runner PIDs') from error
        if (host.st_dev, host.st_ino) != (live.st_dev, live.st_ino):
            raise ValueError('Live bind identity differs from the approved host source')


def verify_container(inspected, workspace, mode=None, store=None):
    store = store or Store()
    labels = inspected.get('Config', {}).get('Labels') or {}
    active = store.load(workspace, labels.get('io.notty.guard.workload', 'dev'))
    revision = labels.get(LABEL + 'revision')
    if not active and not revision:
        if mode:
            raise ValueError('Container has no applied environment policy')
        return {'verified': False, 'enabled': False}
    if not revision:
        raise ValueError('Existing container predates the applied policy; recreate it')
    applied = store.load(workspace, 'dev', revision)
    actual_mode = labels.get(LABEL + 'mode')
    if mode and mode != actual_mode:
        raise ValueError('Container mode differs; recreate explicitly to change modes')
    if actual_mode not in ('read-only', 'implementation') or (actual_mode == 'implementation' and not applied['environment']['allowImplementation']):
        raise ValueError('Container mode is not approved')
    host = inspected['HostConfig']
    if (not host.get('ReadonlyRootfs') or host.get('Privileged') or host.get('CapAdd') or host.get('Devices')
            or host.get('DeviceRequests') or host.get('VolumesFrom')
            or host.get('NetworkMode') == 'host' or str(host.get('NetworkMode', '')).startswith('container:')
            or host.get('PidMode') == 'host' or host.get('IpcMode') == 'host'
            or any(x in ('seccomp=unconfined', 'apparmor=unconfined') for x in host.get('SecurityOpt', []))
            or 'ALL' not in host.get('CapDrop', []) or 'no-new-privileges:true' not in host.get('SecurityOpt', [])
            or inspected['Config'].get('User') != f"{applied['binding']['uid']}:{applied['binding']['gid']}"):
        raise ValueError('Container privileges do not match the approved environment')
    mounts = inspected.get('Mounts', [])
    live = sorted(f"{m['Source']}:{m['Destination']}:{'rw' if m['RW'] else 'ro'}" for m in mounts if m['Type'] == 'bind')
    if digest(encoded(live)) != labels.get(LABEL + 'mount-digest'):
        raise ValueError('Container mounts differ from the verified launch plan')
    policy = next((m for m in mounts if m['Destination'] == DESTINATION), None)
    work = next((m for m in mounts if m['Destination'] == str(canonical(workspace))), None)
    if not policy or policy['RW'] or policy['Source'] != applied['directory']:
        raise ValueError('Applied policy must be the exact read-only revision mount')
    if not work or work['Source'] != str(canonical(workspace)) or work['RW'] != (actual_mode == 'implementation'):
        raise ValueError('Workspace mount does not match the approved mode')
    allowed_tmpfs = set(host.get('Tmpfs', {}))
    for target in allowed_tmpfs:
        if target not in ('/tmp', '/run') and not (target.startswith('/home/') and target.count('/') == 2):
            raise ValueError('Unexpected scratch mount')
        if any(within(Path(target), Path(m['Destination']))
               for m in mounts if m['Type'] == 'bind'):
            raise ValueError('Scratch overlaps protected bind mounts')
    env = dict(entry.split('=', 1) for entry in inspected['Config'].get('Env', []) if '=' in entry)
    for m in mounts:
        if m['Type'] == 'tmpfs' and m['Destination'] not in allowed_tmpfs:
            raise ValueError('Unexpected scratch mount')
        if m['Type'] not in ('bind', 'tmpfs'):
            raise ValueError('Unexpected anonymous or named writable volume')
        if m['Type'] == 'bind':
            assert_no_submounts(m['Source'])
            source = canonical(m['Source'])
            if m['RW'] and m['Destination'] == env.get('NOTTY_AUTH_STATE_DIR'):
                check_auth_state(source, canonical(workspace), applied)
                continue
            if m['RW'] and source not in (canonical(workspace) if actual_mode == 'implementation' else None,
                                         Path(applied['runtime']) / 'codex', Path(applied['runtime']) / 'auth'):
                raise ValueError('Unexpected writable host mount')
    verify_live_mounts(inspected)
    return {'verified': True, 'enabled': True, 'revision': revision, 'mode': actual_mode,
            'activeRevision': active['revision'] if active else None, 'enforcementScope': 'container-filesystem'}


def docker(*args, input_data=None):
    result = subprocess.run(['docker', *args], input=input_data, text=True, capture_output=True, timeout=60)
    if result.returncode:
        raise ValueError('Docker operation failed: ' + result.stderr.strip())
    return result.stdout.strip()


def release_gate(container):
    # /run is root-owned; only the trusted host can release the initial workload.
    docker('exec', '--user', '0:0', container, '/bin/sh', '-c',
           'umask 022; : > /run/nosh-tool-policy-ready')


def launch_container(arguments, workspace, mode=None, store=None):
    store = store or Store()
    workload = next((value.split('=', 1)[1] for value in arguments if value.startswith('io.notty.guard.workload=')), 'dev')
    if not store.load(workspace, workload):
        if mode:
            raise ValueError('No approved environment policy; run nosh tools apply first')
        return docker(*arguments)
    if not arguments or arguments[0] != 'run':
        raise ValueError('Expected Docker run arguments')
    spec = {'Env': [], 'Labels': {}, 'HostConfig': {'Binds': []}}
    options, name, index = [], None, 1
    while index < len(arguments) and arguments[index].startswith('-'):
        flag = arguments[index]
        if flag in ('-d', '--detach', '--init'):
            if flag == '--init': options.append(flag)
            index += 1
            continue
        if flag not in ('--name', '--hostname', '--workdir', '-v', '--volume', '-e', '--env', '--label', '--network', '-p', '--publish'):
            raise ValueError('Unsupported Docker option with environment policy: ' + flag)
        value = arguments[index + 1]
        index += 2
        if flag in ('-v', '--volume'):
            spec['HostConfig']['Binds'].append(value + ':rw' if value.count(':') == 1 else value)
        elif flag in ('-e', '--env'):
            if '=' not in value: raise ValueError('Explicit environment values are required')
            spec['Env'].append(value)
        elif flag == '--label':
            key, val = value.split('=', 1)
            spec['Labels'][key] = val
        else:
            options.extend((flag, value))
            if flag == '--name': name = value
            if flag == '--network': spec['HostConfig']['NetworkMode'] = value
    if not name or index >= len(arguments):
        raise ValueError('Missing container name or image')
    image, command = arguments[index], arguments[index + 1:]
    config = json.loads(docker('image', 'inspect', image))[0]['Config']
    if config.get('Volumes') or config.get('Entrypoint'):
        raise ValueError('Policy-enabled ordinary startup requires an image without implicit volumes or an entrypoint')
    spec['Env'] = [*(config.get('Env') or []), *spec['Env']]
    spec = adapt_spec(spec, workspace, mode, store)
    host = spec['HostConfig']
    create = ['create', *options, '--no-healthcheck', '--read-only', '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges:true',
              '--user', spec['User'], '--pids-limit', str(host['PidsLimit']), '--entrypoint', '/bin/sh']
    for value in host['Binds']: create.extend(('--volume', value))
    for value in spec['Env']: create.extend(('--env', value))
    for key, value in spec['Labels'].items(): create.extend(('--label', key + '=' + value))
    for key, value in host['Tmpfs'].items(): create.extend(('--tmpfs', key + ':' + value))
    gate = 'while [ ! -f /run/nosh-tool-policy-ready ]; do /bin/sleep 0.1; done; exec "$@"'
    create.extend((image, '-c', gate, 'nosh-policy-gate', *(command or config.get('Cmd') or ['/bin/sh'])))
    container = docker(*create)
    try:
        docker('start', container)
        verify_container(json.loads(docker('inspect', container))[0], workspace, mode, store)
        release_gate(container)
    except BaseException:
        docker('rm', '--force', container)
        raise
    return container


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('command', choices=('check', 'apply', 'status', 'rollback', 'spec', 'verify', 'verify-spec', 'launch'))
    parser.add_argument('--review', type=Path)
    parser.add_argument('--workdir', required=True, type=Path)
    parser.add_argument('--workload', default='dev', choices=('dev', 'run'))
    parser.add_argument('--policy-digest')
    parser.add_argument('--revision')
    parser.add_argument('--tool-mode', choices=('read-only', 'implementation'))
    parser.add_argument('--container')
    parser.add_argument('--yes', action='store_true')
    parser.add_argument('--json', action='store_true')
    parser.add_argument('--release', action='store_true')
    raw = list(sys.argv[1:] if argv is None else argv)
    launch_args = raw[raw.index('--') + 1:] if '--' in raw else []
    args = parser.parse_args(raw[:raw.index('--')] if '--' in raw else raw)
    try:
        store = Store()
        if args.command in ('check', 'apply'):
            if not args.review:
                raise ValueError('--review is required')
            environment, data, revision = check_review(args.review, args.workdir, args.workload, args.policy_digest)
            result = {'ready': True, 'policyDigest': revision, 'environment': environment}
            if args.command == 'apply':
                if not args.policy_digest:
                    raise ValueError('--policy-digest is required for Apply')
                print(json.dumps(result, indent=2), file=sys.stderr)
                if not args.yes and input('Apply these environment permissions for future containers? [y/N] ').lower() != 'y':
                    return 0
                result = store.activate(args.workdir, environment, data, revision)
        elif args.command == 'rollback':
            if not args.revision:
                raise ValueError('--revision is required')
            old = store.load(args.workdir, args.workload, args.revision)
            if not old:
                raise ValueError('No saved policy revision')
            print(json.dumps(old, indent=2), file=sys.stderr)
            if not args.yes and input('Activate this previous revision for future containers? [y/N] ').lower() != 'y':
                return 0
            data = read_file(Path(old['directory']) / 'environment-policy.json', 0)
            result = store.activate(args.workdir, old['environment'], data, old['revision'])
        elif args.command == 'launch':
            print(launch_container(launch_args, args.workdir, args.tool_mode, store))
            return 0
        elif args.command == 'verify-spec':
            result = verify_container(json.load(sys.stdin), args.workdir, args.tool_mode, store)
        elif args.command == 'spec':
            result = adapt_spec(json.load(sys.stdin), args.workdir, args.tool_mode, store)
        elif args.command == 'verify':
            if not args.container:
                raise ValueError('--container is required')
            result = verify_container(json.loads(docker('inspect', args.container))[0], args.workdir, args.tool_mode, store)
            if result['enabled'] and args.release:
                release_gate(args.container)
        else:
            result = store.load(args.workdir, args.workload) or {'enabled': False}
            if result.get('enabled'):
                result['revisions'] = sorted('sha256:' + p.name for p in (store.location(args.workdir, args.workload) / 'revisions').iterdir()
                                             if re.fullmatch('[a-f0-9]{64}', p.name))
            if args.container:
                result['container'] = verify_container(json.loads(docker('inspect', args.container))[0], args.workdir, args.tool_mode, store)
        print(json.dumps(result, separators=(',', ':')))
        return 0
    except (OSError, ValueError, KeyError, TypeError, sqlite3.Error, subprocess.SubprocessError, EOFError) as error:
        print('nosh tools: ' + str(error), file=sys.stderr)
        return 1


if __name__ == '__main__':
    sys.exit(main())
