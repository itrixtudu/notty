#!/usr/bin/env python3
"""Private repository configuration, managed browser sessions and CI capture."""
import argparse
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import secrets
import shlex
import shutil
import stat
import subprocess
import sys
import tempfile
import time
import webbrowser
from contextlib import contextmanager
from datetime import datetime, timezone

REPO = Path(__file__).resolve().parent.parent
MAX_BYTES = 1024 * 1024
SCHEMA = json.loads((REPO / 'policy-review/modules/setup/profile-schema.json').read_text())


def now():
    return datetime.now(timezone.utc).isoformat()


def digest(value):
    return 'sha256:' + hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode()).hexdigest()


def defaults(schema=SCHEMA):
    if schema['type'] == 'object':
        return {key: defaults(value) for key, value in schema['properties'].items()}
    return copy.deepcopy(schema['default'])


def validate(value, schema=SCHEMA, label='profile'):
    kind = schema['type']
    invalid = False
    if kind == 'object':
        if not isinstance(value, dict) or set(value) != set(schema['properties']):
            raise ValueError(label + ': missing or unknown fields')
        for key, item in value.items():
            validate(item, schema['properties'][key], label + '.' + key)
    elif kind == 'array':
        if not isinstance(value, list) or len(value) > schema['maxItems']:
            raise ValueError(label + ': invalid list')
        for item in value:
            validate(item, schema['items'], label)
    elif kind == 'string':
        invalid = (not isinstance(value, str) or len(value) > schema['maxLength']
                   or len(value) < schema.get('minLength', 0)
                   or re.search(r'[\x00-\x1f\x7f]', value)
                   or ('pattern' in schema and not re.search(schema['pattern'], value)))
    elif kind == 'boolean':
        invalid = type(value) is not bool
    elif kind == 'integer':
        invalid = type(value) is not int or not schema['minimum'] <= value <= schema['maximum']
    if invalid or ('enum' in schema and value not in schema['enum']):
        raise ValueError(label + ': invalid value')
    return value


def validate_profile(value):
    validate(value)
    if any(part in ('.', '..') for part in value['host']['guardPrefix'].split('/')):
        raise ValueError('Use a normalized Guard prefix')
    build, run = value['settings']['build'], value['settings']['runtime']['run']
    if run['agents'] != 'none' or run['presets'] or run['baselines']:
        raise ValueError('Run cannot use development agents, presets or baselines')
    if any(re.search(r'secret|token|password|credential|private.?key', arg.split('=')[0], re.I) for arg in build['buildArgs']):
        raise ValueError('Build arguments must be non-secret; use external secret delivery')
    if any(not tag for tag in build['tags']) or (build['outputMode'] == 'push' and not build['tags']):
        raise ValueError('Push requires a nonempty image tag')
    return value


def private_path(path, directory=False):
    path = Path(path)
    if path.is_symlink() or path.resolve() != path.absolute():
        raise ValueError('Configuration paths must not traverse symlinks')
    info = path.stat()
    valid = stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode)
    if not valid or info.st_uid != os.getuid() or info.st_mode & 0o077 or (not directory and info.st_nlink != 1):
        raise ValueError('Configuration must be private and owned by the current user')
    return path


def private_dir(path):
    path = Path(path).absolute()
    if path.resolve() != path:
        raise ValueError('Configuration paths must not traverse symlinks')
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    return private_path(path, True)


def read_json(path, private=True, maximum=MAX_BYTES):
    path = Path(path)
    if private:
        private_path(path)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd) as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_size > maximum:
            raise ValueError('Expected bounded JSON file')
        data = stream.read(maximum + 1)
        if len(data.encode()) > maximum:
            raise ValueError('JSON exceeds size limit')
        return json.loads(data)


def write_json(path, value):
    path = Path(path)
    private_path(path.parent, True)
    if path.exists() or path.is_symlink():
        private_path(path)
    encoded = json.dumps(value, indent=2, ensure_ascii=False) + '\n'
    if len(encoded.encode()) > MAX_BYTES:
        raise ValueError('JSON exceeds size limit')
    fd, temporary = tempfile.mkstemp(prefix='.save-', dir=path.parent)
    try:
        with os.fdopen(fd, 'w') as stream:
            stream.write(encoded)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        Path(temporary).unlink(missing_ok=True)


@contextmanager
def profile_lock(directory):
    lock = directory / '.write-lock'
    try:
        lock.mkdir(mode=0o700)
    except FileExistsError:
        raise ValueError('Profile is being saved; retry (after a crash, inspect the private .write-lock directory)') from None
    try:
        yield
    finally:
        lock.rmdir()


def workspace_identity(workdir):
    directory = Path(workdir).expanduser().resolve(strict=True)
    if not directory.is_dir():
        raise ValueError('Workspace must be a directory')
    if any(character in str(directory) for character in ('\n', '\r', ',', '\0')):
        raise ValueError('Workspace path cannot contain control characters or commas')
    info = directory.stat()
    return {'path': str(directory), 'dev': str(info.st_dev), 'ino': str(info.st_ino)}


def locations(identity):
    key = hashlib.sha256(identity['path'].encode()).hexdigest()
    config = Path(os.environ.get('XDG_CONFIG_HOME', Path.home() / '.config')) / 'nosh/repositories' / key
    state = Path(os.environ.get('XDG_STATE_HOME', Path.home() / '.local/state')) / 'nosh/repositories' / key
    for root in (config, state):
        if not root.is_absolute() or root.is_relative_to(Path(identity['path'])):
            raise ValueError('Repository configuration and state must be absolute and outside the workspace')
    if config.is_relative_to(state) or state.is_relative_to(config):
        raise ValueError('Configuration and host state directories must not overlap')
    return config, state


def load_profile(config):
    document = read_json(config / 'profile.json')
    if not isinstance(document, dict) or set(document) != {'kind','schemaVersion','revision','profile'} or document.get('kind') != 'NoshRepositoryProfile' or document.get('schemaVersion') != 1 or type(document.get('revision')) is not int or document['revision'] < 1:
        raise ValueError('Unsupported repository profile')
    validate_profile(document['profile'])
    return document


def initial_profile(identity):
    profile = defaults()
    profile['settings']['label'] = Path(identity['path']).name
    root = Path(os.environ.get('XDG_CONFIG_HOME', Path.home() / '.config')) / 'nosh'
    for filename, fields in [('paths.conf', {'NOSH_GUARD_PREFIX':'guardPrefix'}),
                             ('policy-review-images.conf', {'NOSH_POLICY_TOOLING_IMAGE':'toolingImage', 'NOSH_POLICY_REVIEW_UI_IMAGE':'reviewImage'})]:
        source = root / filename
        if source.exists() or source.is_symlink():
            private_path(source)
            if source.stat().st_size > 65536:
                raise ValueError('Host configuration exceeds size limit')
            for line in source.read_text().splitlines():
                key, separator, value = line.partition('=')
                if separator and key in fields:
                    profile['host'][fields[key]] = value
    pool = Path(os.environ.get('NOSH_REVIEW_NETWORK_CONFIG', root / 'review-network.json'))
    if pool.exists() or pool.is_symlink():
        value = helper('nosh-review-network').validate_configuration(read_json(pool))
        profile['host']['reviewPool'] = value['pool']
        profile['host']['excludedCidrs'] = value['excludedCidrs']
    if Path(identity['path']) == REPO:
        profile['settings']['build']['dockerfile'] = 'Dockerfile.nosh'
        profile['settings']['build']['target'] = 'local'
        profile['settings']['build']['tags'] = ['nosh']
    return validate_profile(profile)


def open_profile(workdir, create=False, rebind=False):
    identity = workspace_identity(workdir)
    config, state = locations(identity)
    if create:
        private_dir(config)
        private_dir(state)
    else:
        private_path(config, True)
        private_path(state, True)
    binding_file = state / 'binding.json'
    if binding_file.exists():
        binding = read_json(binding_file)
        if binding.get('workspace') != identity and not rebind:
            raise ValueError('Workspace identity changed. Export settings and explicitly import into the new checkout; old policy cannot be reused.')
        if binding.get('launcher') != str(REPO / 'scripts/nosh.sh') and not rebind:
            raise ValueError('Profile belongs to a different Nosh installation; export/import explicitly')
    elif create and not (config / 'profile.json').exists():
        binding = {'workspace': identity, 'launcher': str(REPO / 'scripts/nosh.sh'), 'scripts': str(REPO / 'scripts')}
        write_json(binding_file, binding)
    else:
        raise ValueError('Missing workspace binding; refusing to adopt existing profile')
    if create and not (config / 'profile.json').exists():
        with profile_lock(config):
            if not (config / 'profile.json').exists():
                profile = initial_profile(identity)
                write_json(config / 'profile.json', {'kind':'NoshRepositoryProfile', 'schemaVersion':1, 'revision':1, 'profile':profile})
    return config, state, binding, load_profile(config)


def helper(name):
    spec = importlib.util.spec_from_file_location(name.replace('-', '_'), REPO / 'scripts' / (name + '.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def checked_guard(prefix):
    guard = (Path(prefix) / 'bin/nosh-guard').resolve(strict=True)
    for node in (guard, *guard.parents):
        info = node.stat()
        if info.st_uid != 0 or info.st_mode & 0o022:
            raise ValueError('Install the root-owned Guard host bundle before privileged checks')
    if not guard.is_file() or guard.stat().st_nlink != 1 or not os.access(guard, os.X_OK):
        raise ValueError('Invalid installed Guard helper')
    return str(guard)


def refresh(config, state, binding, document, privileged=False):
    detector = helper('nosh-init-status')
    profile = document['profile']
    host = profile['host']
    snapshot = {'kind':'NoshRepositoryStatus', 'schemaVersion':1, 'checkedAt':now(), 'profileDigest':digest(profile),
                'revision':document['revision'], 'authoritative':False, 'workloads':{}, 'tools':None,
                'build':build_snapshot(profile['settings']['build'], binding['workspace']['path'])}
    for workload in ('dev', 'run'):
        authority = None
        if privileged:
            guard = checked_guard(host['guardPrefix'])
            result = subprocess.run(['sudo', '--', guard, 'net', 'status', '--workdir', binding['workspace']['path'], '--workload', workload, '--json'], capture_output=True, text=True, timeout=120)
            if result.returncode == 0:
                authority = json.loads(result.stdout)
            else:
                snapshot.setdefault('errors', []).append(workload + ': privileged status failed; no activation verified')
        rows, next_step = detector.detect(binding['workspace']['path'], host['guardPrefix'], profile['settings']['runtime'][workload]['image'], str(REPO), authority, workload)
        snapshot['workloads'][workload] = {'steps': {str(key): {'state':value[0], 'detail':value[1]} for key, value in rows.items()}, 'nextStep':next_step}
    # Existing local tool status is an informational mirror. No elevation here.
    try:
        result = subprocess.run(['python3', '-I', '-S', str(REPO / 'scripts/nosh-tool-policy.py'), 'status', '--workdir', binding['workspace']['path']], capture_output=True, text=True, timeout=12)
        if result.returncode == 0:
            snapshot['tools'] = json.loads(result.stdout)
    except (OSError, ValueError, subprocess.TimeoutExpired):
        snapshot['tools'] = {'state':'unknown'}
    write_json(state / 'snapshot.json', snapshot)
    print('Saved host status. Reload status in the browser. Checks are hints, never policy authority.')
    return snapshot


def build_snapshot(build, workspace):
    """Read a saved candidate reference, without implying it matches today's source."""
    try:
        context = repo_path(workspace, build['context'], True)
        identity = workspace_identity(context)
        key = hashlib.sha256(context.encode()).hexdigest()
        directory = Path.home() / '.nosh' / ('build-net-profiles' if build['mode'] == 'network' else 'build-profiles') / key
        reference = read_json(directory / 'latest-candidate.json')
        if reference.get('projectKey') != key or not re.fullmatch(r'[A-Za-z0-9_.-]+', str(reference.get('runId', ''))) or reference['runId'] in ('.', '..'):
            raise ValueError('Invalid saved build reference')
        bundle = private_path(directory / reference['runId'], True)
        manifest = read_json(bundle / 'evidence-manifest.json', maximum=64 * MAX_BYTES)
        project = manifest.get('project') or {}
        if any(project.get(field) != identity[source] for field, source in [('canonicalPath','path'), ('dev','dev'), ('ino','ino')]):
            return {'state':'stale', 'detail':'Saved build belongs to a different directory identity.'}
        return {'state':'saved-unverified', 'directory':str(bundle), 'runId':reference['runId'],
                'candidateDigest':reference.get('candidateHash'), 'imageDigest':manifest.get('build', {}).get('configDigest'),
                'detail':'Saved candidate found. Re-capture after source or build settings change; this is not approval or a verified current build.'}
    except FileNotFoundError:
        return {'state':'missing', 'detail':'No saved build candidate for this context.'}
    except (OSError, ValueError, KeyError, TypeError):
        return {'state':'unknown', 'detail':'Saved build evidence could not be read safely.'}


def runtime_arguments(profile, binding, workload, operation):
    runtime = profile['settings']['runtime'][workload]
    host = profile['host']
    args = ['net', operation, '--workdir', binding['workspace']['path'], '--workload', workload,
            '--image', runtime['image'], '--start-app' if runtime['startApp'] else '--no-start-app', '--no-collab']
    if not runtime['image']:
        raise ValueError('Select a runtime image first')
    if workload == 'dev':
        args += ['--agents', runtime['agents']]
        if host['codexHome']:
            args += ['--codex-home', host['codexHome']]
        if runtime['presets']:
            args += ['--profile', ','.join(runtime['presets'])]
        if operation == 'enforce':
            args += ['--tool-mode', profile['settings']['tools']['mode']]
    if operation == 'learn':
        args += ['--review-output']
        if runtime['duration']:
            args += ['--duration', str(runtime['duration'])]
        for baseline in runtime['baselines']:
            filename, hash_value = baseline.rsplit('@', 1)
            args += ['--agent-baseline', repo_path(binding['workspace']['path'], filename, True) + '@' + hash_value]
    return args


def run_runtime(workdir, workload, operation, revision):
    _, _, binding, document = open_profile(workdir)
    if revision != document['revision']:
        raise ValueError('Profile changed since this command was copied; reload setup and copy the new command')
    guard = checked_guard(document['profile']['host']['guardPrefix'])
    args = runtime_arguments(document['profile'], binding, workload, operation)
    command = ['sudo', '--', guard, *args]
    print('Using saved profile revision ' + str(revision) + ':\n' + shlex.join(command), flush=True)
    return subprocess.run(command, cwd=binding['workspace']['path']).returncode


def launch(config, state, binding, profile, browser=True):
    launcher = helper('review-codex-tools')
    image = profile['profile']['host']['reviewImage'] or launcher.configured_image()
    # Automatic discovery must never contact a remote daemon.
    endpoint = os.environ.get('DOCKER_HOST') or launcher.docker('context', 'inspect', '--format', '{{.Endpoints.docker.Host}}')
    if not endpoint.startswith('unix://'):
        raise ValueError('Setup requires a local Unix-socket Docker daemon')
    found = launcher.docker('image', 'inspect', '--format', '{{.Id}}|{{index .Config.Labels "io.notty.setup.ui-abi"}}', image)
    if found != image + '|1':
        raise ValueError('Build the updated policy-review image and configure its exact image ID (setup ABI 1)')
    session_dir = private_dir(state / ('session-' + secrets.token_hex(8)))
    session = {'kind':'NoshSetupSession', 'schemaVersion':1, 'token':secrets.token_hex(32), 'origin':''}
    write_json(session_dir / 'session.json', session)
    name = 'nosh-setup-' + secrets.token_hex(8)
    args = ['run', '--detach', '--rm', '--pull', 'never', '--name', name, '--user', f'{os.getuid()}:{os.getgid()}',
            '--read-only', '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges:true', '--pids-limit', '128', '--memory', '1g',
            '--tmpfs', '/tmp:rw,nosuid,nodev,noexec,size=67108864', '--publish', '127.0.0.1::3000',
            '--env', 'NOTTY_SETUP_SESSION_FILE=/session/session.json', '--env', 'NOTTY_SETUP_PROFILE_DIR=/profile',
            '--env', 'NOTTY_SETUP_STATE_DIR=/state']
    for source, target, readonly in [(config, '/profile', False), (state, '/state', True), (session_dir, '/session', True)]:
        if ',' in str(source):
            raise ValueError('Docker mount paths cannot contain commas')
        args += ['--mount', f'type=bind,src={source},dst={target}' + (',readonly' if readonly else '')]
    args.append(image)
    try:
        launcher.docker(*args)
        address = launcher.docker('port', name, '3000/tcp')
        if not re.fullmatch(r'127\.0\.0\.1:\d+', address):
            raise ValueError('Setup listener must be loopback-only')
        session['origin'] = 'http://' + address
        write_json(session_dir / 'session.json', session)
        for _ in range(60):
            health = launcher.docker('inspect', '--format', '{{.State.Health.Status}}', name)
            if health == 'healthy':
                break
            if health == 'unhealthy':
                raise ValueError('Setup UI health check failed')
            time.sleep(0.5)
        else:
            raise ValueError('Setup UI startup timed out')
        url = session['origin'] + '/setup#token=' + session['token']
        print('Repository setup: ' + url)
        print('Stop: docker stop ' + name)
        if browser:
            try:
                webbrowser.open(url)
            except webbrowser.Error:
                pass
    except BaseException:
        try:
            launcher.docker('rm', '-f', name)
        finally:
            (session_dir / 'session.json').unlink(missing_ok=True)
        raise


def portable(document):
    return {'kind':'NoshRepositoryConfiguration', 'schemaVersion':1, 'settings':copy.deepcopy(document['profile']['settings'])}


def import_profile(filename, workdir):
    value = read_json(filename, private=False)
    if not isinstance(value, dict) or set(value) != {'kind', 'schemaVersion', 'settings'} or value['kind'] != 'NoshRepositoryConfiguration' or value['schemaVersion'] != 1:
        raise ValueError('Expected portable repository configuration v1')
    profile = initial_profile(workspace_identity(workdir))
    profile['settings'] = value['settings']
    validate_profile(profile)
    config, state, binding, old = open_profile(workdir, create=True, rebind=True)
    with profile_lock(config):
        old = load_profile(config)
        # Import resets host references. It cannot carry approval across machines.
        document = {'kind':'NoshRepositoryProfile', 'schemaVersion':1, 'revision':old['revision'] + 1, 'profile':profile}
        write_json(config / 'profile.json', document)
        binding = {'workspace':workspace_identity(workdir), 'launcher':str(REPO / 'scripts/nosh.sh'), 'scripts':str(REPO / 'scripts')}
        write_json(state / 'binding.json', binding)
    refresh(config, state, binding, document)


def repo_path(workspace, relative, existing=False):
    root = Path(workspace).resolve(strict=True)
    selected = root / relative
    resolved = selected.resolve(strict=existing)
    if not resolved.is_relative_to(root):
        raise ValueError('Build paths must remain inside the selected repository')
    return str(resolved)


def build_arguments(build, workspace):
    args = ['build']
    if build['mode'] == 'network':
        args += ['net', 'learn', '--http-capture', build['httpCapture']]
    else:
        args += ['profile', '--cache-mode', build['cacheMode'], '--depth', build['depth']]
    args += ['--file', repo_path(workspace, build['dockerfile'], True)]
    for key in ('target', 'platform'):
        if build[key]:
            args += ['--' + key, build[key]]
    for tag in build['tags']:
        args += ['--tag', tag]
    for argument in build['buildArgs']:
        args += ['--build-arg', argument]
    if build['outputMode'] == 'push':
        args += ['--push']
    elif build['outputMode'] == 'cache':
        args += ['--no-load']
    elif build['outputMode'] == 'local':
        args += ['--output', 'type=local,dest=' + repo_path(workspace, build['outputDirectory'])]
    args += ['--private-json', repo_path(workspace, build['context'], True)]
    return args


def ci_capture(filename, workdir, output_dir):
    value = read_json(filename, private=False)
    if not isinstance(value, dict) or set(value) != {'kind','schemaVersion','settings'} or value['kind'] != 'NoshRepositoryConfiguration' or value['schemaVersion'] != 1:
        raise ValueError('Expected portable repository configuration v1')
    profile = defaults()
    profile['settings'] = value['settings']
    validate_profile(profile)
    identity = workspace_identity(workdir)
    output = Path(output_dir).absolute()
    if output.exists():
        raise ValueError('CI output directory must be new')
    output = private_dir(output)
    private_root = private_dir(Path(os.environ.get('XDG_STATE_HOME', Path.home() / '.local/state')) / 'nosh/config-ci')
    if private_root.is_relative_to(output) or private_root.is_relative_to(Path(identity['path'])):
        raise ValueError('Private CI state must be outside workspace and artifact output')
    run_dir = private_dir(private_root / secrets.token_hex(12))
    result = {'kind':'NoshRepositoryCIResult', 'schemaVersion':1, 'configurationDigest':digest(value), 'startedAt':now(),
              'status':'failed', 'exitCode':1, 'portableDirectory':None, 'imageDigest':None, 'evidenceDigest':None,
              'approved':False}
    try:
        if os.geteuid() == 0:
            raise ValueError('Run CI builds as the normal Docker-authorized user, without sudo')
        command = ['bash', str(REPO / 'scripts/nosh.sh'), *build_arguments(profile['settings']['build'], identity['path'])]
        environment = {**os.environ, 'NOSH_BUILD_NONINTERACTIVE':'1'}
        # Keep the full result and build output private; only portable/ is published.
        with (run_dir / 'result.json').open('x') as stdout, (run_dir / 'stderr.log').open('x') as stderr:
            process = subprocess.run(command, stdin=subprocess.DEVNULL, stdout=stdout, stderr=stderr, env=environment, cwd=identity['path'])
        result['exitCode'] = process.returncode if process.returncode >= 0 else 128 - process.returncode
        try:
            captured = read_json(run_dir / 'result.json', maximum=64 * MAX_BYTES)
        except (OSError, ValueError):
            captured = {}
        if not isinstance(captured, dict):
            captured = {}
        manifest = captured.get('manifest') or {}
        if captured.get('kind') == 'NoshBuildCaptureFailure':
            try:
                bundle = private_path(Path(captured['bundleDir']), True)
                manifest = read_json(bundle / 'evidence-manifest.json', maximum=64 * MAX_BYTES)
            except (OSError, ValueError):
                manifest = {}
        if not isinstance(manifest, dict):
            raise ValueError('Invalid build result manifest')
        build = manifest.get('build') or {}
        if not isinstance(build, dict):
            raise ValueError('Invalid build result')
        for target, source in [('imageDigest', build.get('configDigest')), ('evidenceDigest', manifest.get('contentHash'))]:
            if isinstance(source, str) and re.fullmatch(r'sha256:[a-f0-9]{64}', source):
                result[target] = source
        source = captured.get('portableBundleDir')
        if source:
            bundle = private_path(Path(captured['bundleDir']), True)
            candidate = private_path(Path(source), True)
            if candidate != bundle / 'portable':
                raise ValueError('Unexpected portable artifact location')
            # Refuse links/special files rather than copying them into CI artifacts.
            for file in candidate.rglob('*'):
                if file.is_symlink() or not (file.is_dir() or file.is_file()):
                    raise ValueError('Unsafe portable artifact')
            shutil.copytree(candidate, output / 'portable')
            result['portableDirectory'] = 'portable'
        complete = manifest.get('complete') is True and manifest.get('candidateEligible') is True and build.get('success') is True and result['portableDirectory']
        if process.returncode == 0 and complete:
            result['status'] = 'captured'
        elif process.returncode == 0:
            result['exitCode'] = 1
            result['status'] = 'incomplete'
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        result['error'] = str(error) if isinstance(error, ValueError) else type(error).__name__
        result['exitCode'] = result['exitCode'] or 1
    except KeyboardInterrupt:
        result['status'] = 'interrupted'
        result['exitCode'] = 130
    result['finishedAt'] = now()
    write_json(output / 'result.json', result)
    print(json.dumps(result))
    print('Private diagnostics: ' + str(run_dir), file=sys.stderr)
    return result['exitCode']


def main(argv=None):
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', nargs='?', choices=['open','refresh','export','import','ci','runtime'], default='open')
    parser.add_argument('--workdir', default=os.getcwd())
    parser.add_argument('--profile', type=Path, help='Portable JSON file for import or CI')
    parser.add_argument('--output-dir', type=Path, help='New artifact directory for CI')
    parser.add_argument('--no-browser', action='store_true')
    parser.add_argument('--privileged', action='store_true', help='Explicit sudo status checks during refresh')
    parser.add_argument('--operation', choices=['learn','enforce'], help='Explicit host runtime action')
    parser.add_argument('--workload', choices=['dev','run'], default='dev')
    parser.add_argument('--revision', type=int, help='Exact saved revision for a copied runtime command')
    args = parser.parse_args(argv)
    try:
        if args.privileged and args.action != 'refresh':
            raise ValueError('--privileged is only valid for refresh')
        if args.action == 'runtime':
            if not args.operation or args.revision is None:
                raise ValueError('Runtime actions require --operation and --revision')
            return run_runtime(args.workdir, args.workload, args.operation, args.revision)
        if args.action in ('ci','import') and not args.profile:
            raise ValueError('--profile is required')
        if args.action == 'ci':
            if not args.output_dir:
                raise ValueError('--output-dir is required')
            return ci_capture(args.profile, args.workdir, args.output_dir)
        if args.action == 'import':
            import_profile(args.profile, args.workdir)
            return 0
        config, state, binding, document = open_profile(args.workdir, create=args.action == 'open')
        if args.action == 'export':
            print(json.dumps(portable(document), indent=2))
            return 0
        refresh(config, state, binding, document, args.privileged)
        if args.action == 'open':
            launch(config, state, binding, document, not args.no_browser)
        return 0
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        print('nosh config: ' + str(error), file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        return 130


if __name__ == '__main__':
    sys.exit(main())
