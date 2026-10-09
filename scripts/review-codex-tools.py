#!/usr/bin/env python3
"""Launch the containerized, proposal-only UI for a saved Codex tool audit."""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import stat
import subprocess
import sys
import tempfile
import time
import webbrowser

INPUT_FILES = ('allow.json', 'not-yet.json', 'rules-review.json',
               'planning.config.toml', 'implementation.config.toml')
MAX_INPUT_BYTES = 25 * 1024 * 1024
MANAGED_IMAGE = 'nosh-policy-review:managed'


def private_path(path, directory=False):
    if path.is_symlink() or path.resolve() != path.absolute():
        raise ValueError('Review paths must not traverse symlinks')
    info = path.stat()
    valid_type = stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode)
    if not valid_type or info.st_uid != os.getuid() or info.st_mode & 0o077:
        raise ValueError('Review inputs and directories must be private and owned by the current user')
    if not directory and info.st_nlink != 1:
        raise ValueError('Review inputs must not be hard linked')
    if any(character in str(path) for character in (',', '\n', '\r')):
        raise ValueError('Unsupported character in Docker mount path')
    return path


def snapshot_digest(directory):
    hashes, size = [], 0
    for name in INPUT_FILES:
        file = private_path(directory / name)
        size += file.stat().st_size
        if size > MAX_INPUT_BYTES:
            raise ValueError('Audit inputs exceed the 25 MiB review limit')
        with file.open('rb') as stream:
            data = stream.read(MAX_INPUT_BYTES + 1)
        if len(data) > MAX_INPUT_BYTES:
            raise ValueError('Audit input exceeds the review limit')
        hashes.append(name + '\0' + hashlib.sha256(data).hexdigest() + '\n')
    return 'sha256:' + hashlib.sha256(''.join(hashes).encode()).hexdigest()


def image_configuration():
    config_home = Path(os.environ.get('XDG_CONFIG_HOME', str(Path.home() / '.config')))
    return Path(os.environ.get('NOSH_PROFILE_REVIEW_IMAGE_CONFIG', str(config_home / 'nosh/policy-review-images.conf')))


def configured_image(allow_missing=False):
    image = os.environ.get('NOSH_POLICY_REVIEW_UI_IMAGE', '')
    config = image_configuration()
    if not image and config.exists():
        for line in private_path(config).read_text().splitlines():
            if line.startswith('NOSH_POLICY_REVIEW_UI_IMAGE='):
                image = line.split('=', 1)[1]
    if image and not re.fullmatch(r'sha256:[a-f0-9]{64}', image):
        raise ValueError('Configured NOSH_POLICY_REVIEW_UI_IMAGE must be an exact local sha256 image ID')
    if not image and not allow_missing:
        raise ValueError('Set NOSH_POLICY_REVIEW_UI_IMAGE to an exact local image ID from the rebuilt policy-review image')
    return image


def docker(*args):
    result = subprocess.run(['docker', *args], capture_output=True, text=True, timeout=45)
    if result.returncode:
        raise ValueError('Docker operation failed; check daemon access and the configured local review image')
    return result.stdout.strip()


def inspect_image(reference):
    identity = docker('image', 'inspect', '--format', '{{.Id}}|{{index .Config.Labels "io.notty.tool-review.ui-abi"}}', reference)
    match = re.fullmatch(r'(sha256:[a-f0-9]{64})\|2', identity)
    if not match or (reference.startswith('sha256:') and match[1] != reference):
        raise ValueError('Review image lacks tool-review ABI 2; rebuild the review UI image')
    return match[1]


def remember_image(image, previous):
    helper = Path(__file__).with_name('nosh-save-tooling.py')
    spec = importlib.util.spec_from_file_location('nosh_save_tooling', helper)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    module.save_tooling(image_configuration(), image, setting='NOSH_POLICY_REVIEW_UI_IMAGE', expected_image=previous)
    print('Remembered review UI image in ' + str(image_configuration()))


def build_image():
    context = Path(__file__).resolve().parents[1] / 'policy-review'
    if not (context / 'Dockerfile').is_file():
        raise ValueError('Review UI build sources are missing; use a complete Nosh checkout')
    with tempfile.TemporaryDirectory(prefix='nosh-review-ui-build-') as temporary:
        identity_file = Path(temporary) / 'image.id'
        result = subprocess.run(['docker', 'build', '--pull=false', '--iidfile', str(identity_file),
                                 '--file', str(context / 'Dockerfile'), '--tag', MANAGED_IMAGE, str(context)],
                                env={**os.environ, 'DOCKER_BUILDKIT': '1'})
        if result.returncode:
            raise ValueError('Review UI build failed; image configuration and saved audit are unchanged')
        image = identity_file.read_text().strip()
        if not re.fullmatch(r'sha256:[a-f0-9]{64}', image):
            raise ValueError('Review UI build did not produce an exact local image ID')
        return inspect_image(image)


def prepare_image(allow_build=False):
    previous = configured_image(allow_missing=True)
    try:
        image = inspect_image(previous or MANAGED_IMAGE)
    except (ValueError, subprocess.TimeoutExpired):
        # Do not propose a build to repair daemon connectivity or authorization.
        docker('info', '--format', '{{.ID}}')
        if os.environ.get('NOSH_POLICY_REVIEW_UI_IMAGE'):
            raise ValueError('The explicit NOSH_POLICY_REVIEW_UI_IMAGE is missing or incompatible; '
                             'unset it to use automatic setup, or rebuild and set a compatible exact image ID')
        print('The review UI image is missing or needs an update.')
        if not allow_build:
            if not (sys.stdin.isatty() and sys.stdout.isatty()):
                raise ValueError('Run nosh tools review --review REPORT --build-ui to build and remember the UI image, '
                                 'or reopen review in an interactive host terminal')
            print('Build the review UI from this Nosh checkout in Docker? This may download build dependencies.')
            if input('Build and continue? [Y/n] ').strip().lower() not in ('', 'y', 'yes'):
                raise ValueError('UI setup skipped; your saved audit is unchanged')
        image = build_image()
        remember_image(image, previous)
        return image
    if not previous:
        remember_image(image, '')
    return image


def launch(directory, open_browser=True, build_ui=False):
    directory = private_path(directory.expanduser().absolute(), directory=True)
    digest = snapshot_digest(directory)
    inputs = {name: json.loads((directory / name).read_text()) for name in ('allow.json', 'not-yet.json')}
    evidence = inputs['allow.json'].get('request_evidence')
    if evidence is not None or inputs['allow.json'].get('schema_version') == 2:
        spec = importlib.util.spec_from_file_location('tool_policy', Path(__file__).with_name('nosh-tool-policy.py'))
        policy = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(policy)
        try:
            evidence = policy.validate_request_evidence(directory, inputs, os.getuid())
        except policy.sqlite3.Error:
            raise ValueError('Invalid request evidence database') from None
    if not shutil.which('docker'):
        raise ValueError('Docker is required to open the review UI; the terminal review remains available')
    image = prepare_image(allow_build=build_ui)
    output = directory / 'review'
    output.mkdir(mode=0o700, exist_ok=True)
    private_path(output, directory=True)
    binding = output / 'snapshot.json'
    if binding.exists():
        if json.loads(private_path(binding).read_text()).get('snapshotDigest') != digest:
            raise ValueError('Audit changed since its saved review; create a fresh audit directory')
    else:
        with binding.open('x') as stream:
            json.dump({'snapshotDigest': digest}, stream)
        binding.chmod(0o600)
    runtime = output / ('runtime-' + secrets.token_hex(8))
    runtime.mkdir(mode=0o700)
    session_file = runtime / 'session.json'
    session = {'kind': 'NoshToolReviewSession', 'schemaVersion': 1,
               'snapshotDigest': digest, 'token': secrets.token_hex(32), 'origin': ''}

    def write_session():
        temporary = runtime / 'session.tmp'
        with temporary.open('x') as stream:
            json.dump(session, stream)
        temporary.chmod(0o600)
        temporary.replace(session_file)

    write_session()
    name = 'nosh-tool-review-' + secrets.token_hex(8)
    command = ['run', '--detach', '--rm', '--pull', 'never', '--name', name,
               '--user', f'{os.getuid()}:{os.getgid()}', '--read-only', '--cap-drop', 'ALL',
               '--security-opt', 'no-new-privileges:true', '--pids-limit', '128', '--memory', '1g',
               '--tmpfs', '/tmp:rw,nosuid,nodev,noexec,size=67108864',
               '--publish', '127.0.0.1::3000',
               '--env', 'NOTTY_TOOL_REVIEW_SESSION_FILE=/session/session.json',
               '--env', 'NOTTY_TOOL_REVIEW_INPUT_DIR=/audit',
               '--env', 'NOTTY_TOOL_REVIEW_OUTPUT_DIR=/review',
               '--mount', f'type=bind,src={runtime},dst=/session,readonly',
               '--mount', f'type=bind,src={output},dst=/review']
    for filename in INPUT_FILES:
        command += ['--mount', f'type=bind,src={directory / filename},dst=/audit/{filename},readonly']
    if evidence:
        command += ['--mount', f'type=bind,src={directory / "requests.sqlite3"},dst=/audit/requests.sqlite3,readonly']
    command.append(image)
    started = False
    try:
        # Cleanup also covers a Docker client timeout after the daemon started it.
        started = True
        docker(*command)
        address = docker('port', name, '3000/tcp')
        if not re.fullmatch(r'127\.0\.0\.1:\d+', address):
            raise ValueError('Review listener is not bound exclusively to loopback')
        session['origin'] = 'http://' + address
        write_session()
        for _ in range(60):
            health = docker('inspect', '--format', '{{.State.Health.Status}}', name)
            if health == 'healthy':
                break
            if health == 'unhealthy':
                raise ValueError('Review UI health check failed')
            time.sleep(0.5)
        else:
            raise ValueError('Review UI startup timed out')
        url = session['origin'] + '/tool-review#token=' + session['token']
        print('Tool review: ' + url)
        print('Draft and proposal: ' + str(output))
        print('Stop: docker stop ' + name)
        print('Saving a proposal does not change active permissions.')
        if open_browser:
            try:
                if not webbrowser.open(url):
                    print('Browser did not open; use the URL above.')
            except webbrowser.Error:
                print('Browser did not open; use the URL above.')
        return 0
    except BaseException:
        if started:
            try:
                docker('rm', '-f', name)
            except (ValueError, subprocess.TimeoutExpired):
                print('Check cleanup with: docker rm -f ' + name, file=sys.stderr)
        raise
    finally:
        # Successful sessions keep their token until their container is stopped.
        # Failed launches leave no usable session token behind.
        if sys.exc_info()[0] is not None:
            session_file.unlink(missing_ok=True)
            (runtime / 'session.tmp').unlink(missing_ok=True)
            runtime.rmdir()


def main(argv=None):
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('report_dir', type=Path)
    parser.add_argument('--no-browser', action='store_true')
    parser.add_argument('--build-ui', action='store_true', help='allow a Docker UI build when no compatible image is available')
    args = parser.parse_args(argv)
    try:
        return launch(args.report_dir, not args.no_browser, args.build_ui)
    except (OSError, ValueError, subprocess.TimeoutExpired) as error:
        message = str(error) if isinstance(error, ValueError) and not isinstance(error, json.JSONDecodeError) else type(error).__name__
        print('Tool review: ' + message, file=sys.stderr)
        return 1
    except (EOFError, KeyboardInterrupt):
        return 130


if __name__ == '__main__':
    sys.exit(main())
