#!/usr/bin/env python3
"""Explicit first-time signing setup; key generation stays in offline containers."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import shlex
import stat
import subprocess
import sys
import tempfile
import uuid

# This fixed administrative operation copies only the reviewed public material.
# The final hard link is exclusive: it cannot overwrite installed trust.
INSTALL_PUBLIC_TRUST = r'''
set -euo pipefail
source_dir=$1
keys_dir=$2
review_hash=$3
deployment_hash=$4
trust_hash=$5
trust_file=/etc/nosh-guard/ebpf-deployment-trust.json
[[ $keys_dir =~ ^/etc/nosh-guard/ebpf-trust-[a-f0-9]{32}$ ]]
[[ -d /etc/nosh-guard && ! -L /etc/nosh-guard ]]
[[ $(stat -c '%u' /etc/nosh-guard) == 0 ]]
[[ $(stat -c '%a' /etc/nosh-guard) =~ ^(700|750|755)$ ]]
check_file() {
  [[ -f $1 && ! -L $1 && $(stat -c '%u:%a:%h' "$1") == '0:600:1' ]]
  [[ $(sha256sum "$1" | cut -d' ' -f1) == "$2" ]]
}
if [[ -e $trust_file || -L $trust_file ]]; then
  check_file "$trust_file" "$trust_hash"
  check_file "$keys_dir/review-public.pem" "$review_hash"
  check_file "$keys_dir/deployment-public.pem" "$deployment_hash"
  exit 0
fi
stage=$(mktemp -d /etc/nosh-guard/.signing-public.XXXXXX)
trap 'rm -rf -- "$stage"' EXIT
install -o root -g root -m 0600 -- "$source_dir/review-public.pem" "$stage/review-public.pem"
install -o root -g root -m 0600 -- "$source_dir/deployment-public.pem" "$stage/deployment-public.pem"
install -o root -g root -m 0600 -- "$source_dir/trust.json" "$stage/trust.json"
check_file "$stage/review-public.pem" "$review_hash"
check_file "$stage/deployment-public.pem" "$deployment_hash"
check_file "$stage/trust.json" "$trust_hash"
if [[ -e $keys_dir || -L $keys_dir ]]; then
  [[ -d $keys_dir && ! -L $keys_dir && $(stat -c '%u:%a' "$keys_dir") == '0:700' ]]
  check_file "$keys_dir/review-public.pem" "$review_hash"
  check_file "$keys_dir/deployment-public.pem" "$deployment_hash"
else
  mkdir -m 0700 -- "$stage/keys"
  mv -- "$stage/review-public.pem" "$stage/deployment-public.pem" "$stage/keys/"
  mv -T -- "$stage/keys" "$keys_dir"
fi
ln -T -- "$stage/trust.json" "$trust_file"
rm -- "$stage/trust.json"
printf 'Installed public signing trust. No private keys copied to root state.\n'
'''


def private_file(path):
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 1:
        raise ValueError(f'Expected a caller-owned mode-0600 regular file: {path}')
    return path


def safe_directory(path, workspace):
    if not path.is_absolute() or any(c in str(path) for c in '\r\n,'):
        raise ValueError(f'Unsafe container mount path: {path}')
    if path.resolve() != path or path == workspace or workspace in path.parents:
        raise ValueError('Signing files must be outside the workspace and use canonical paths')
    info = path.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o700:
        raise ValueError(f'Expected a caller-owned mode-0700 directory: {path}')


def write_json(path, value):
    with path.open('x', encoding='utf8') as output:
        json.dump(value, output, indent=2)
        output.write('\n')


def capture(command):
    return subprocess.check_output(command, text=True).strip()


def confirm(message):
    if input(f'{message} y/N: ').strip().lower() != 'y':
        raise ValueError('Not confirmed. Existing setup files are retained; no trust was replaced.')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--workdir', default=os.getcwd())
    parser.add_argument('--resume', type=Path, help='Resume a previously printed private setup directory')
    parser.add_argument('--image', help='Exact local policy-tooling image ID')
    args = parser.parse_args()
    if os.getuid() == 0 or not sys.stdin.isatty():
        raise ValueError('Run interactively as your normal host user; only public trust installation uses sudo')
    os.umask(0o077)
    workspace = Path(args.workdir).resolve(strict=True)
    config_home = Path(os.environ.get('XDG_CONFIG_HOME', str(Path.home() / '.config')))
    config = Path(os.environ.get('NOSH_POLICY_APPLY_CONFIG', str(config_home / 'nosh/policy-apply.json')))
    if not config.is_absolute() or config.resolve() != config or config == workspace or workspace in config.parents:
        raise ValueError('Signing configuration must use a canonical absolute path outside the workspace')
    if config.exists() or config.is_symlink():
        raise ValueError(f'Signing configuration already exists; refusing to replace it: {config}')
    config.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    safe_directory(config.parent, workspace)
    for executable in ('docker', 'sudo'):
        if not shutil.which(executable):
            raise ValueError(f'Missing command: {executable}')
    endpoint = os.environ.get('DOCKER_HOST') or capture(['docker', 'context', 'inspect', '--format', '{{.Endpoints.docker.Host}}'])
    if not endpoint.startswith('unix://'):
        raise ValueError('Signing setup requires a local Unix Docker socket')
    docker = ['docker', '--host', endpoint]
    image = args.image or os.environ.get('NOSH_POLICY_TOOLING_IMAGE')
    image_config = Path(os.environ.get('NOSH_PROFILE_REVIEW_IMAGE_CONFIG', str(config_home / 'nosh/policy-review-images.conf')))
    if not image and image_config.exists():
        for line in private_file(image_config).read_text().splitlines():
            if line.startswith('NOSH_POLICY_TOOLING_IMAGE='):
                image = line.split('=', 1)[1]
    if image and not re.fullmatch(r'sha256:[a-f0-9]{64}', image):
        raise ValueError('Configured tooling image must be an exact sha256 ID')
    identity = capture(docker + ['image', 'inspect', '--format', '{{.Id}}|{{index .Config.Labels "io.notty.guard.policy-tooling-abi"}}', image or 'nosh'])
    if not re.fullmatch(r'sha256:[a-f0-9]{64}\|1', identity):
        raise ValueError('Local image is not compatible policy tooling')
    selected = identity.split('|')[0]
    if image and selected != image:
        raise ValueError('Policy tooling image identity mismatch')
    image = selected

    if args.resume:
        stage = args.resume
        safe_directory(stage, workspace)
        setup = json.loads(private_file(stage / 'setup.json').read_text())
        if setup['image'] != image or setup['config'] != str(config):
            raise ValueError('Resume configuration or tooling image differs from the prepared setup')
        instance = setup['instance']
        if not re.fullmatch('[a-f0-9]{32}', instance):
            raise ValueError('Invalid setup instance identity')
    else:
        confirm(f'Generate two separate signing keys using local image {image}, with no container network?')
        base = Path(os.environ.get('XDG_DATA_HOME', str(Path.home() / '.local/share'))) / 'nosh'
        if not base.is_absolute() or base.resolve() != base or base == workspace or workspace in base.parents:
            raise ValueError('Signing data directory must be outside the workspace and canonical')
        base.mkdir(mode=0o700, parents=True, exist_ok=True)
        stage = Path(tempfile.mkdtemp(prefix='signing-', dir=base))
        safe_directory(stage, workspace)
        instance = uuid.uuid4().hex
        write_json(stage / 'setup.json', {'image': image, 'config': str(config), 'instance': instance})
    print(f'Setup retained: {stage}', flush=True)
    print('To resume: ' + shlex.join(['python3', str(Path(__file__).resolve()), '--workdir', str(workspace), '--resume', str(stage), '--image', image]), flush=True)
    for role in ('review', 'deployment'):
        directory = stage / role
        directory.mkdir(mode=0o700, exist_ok=True)
        safe_directory(directory, workspace)
        command = docker + ['run', '--rm', '--pull', 'never', '--network', 'none',
            '--user', f'{os.getuid()}:{os.getgid()}', '--read-only', '--cap-drop', 'ALL',
            '--security-opt', 'no-new-privileges:true', '--pids-limit', '128', '--memory', '256m',
            '--tmpfs', '/tmp:rw,nosuid,nodev,noexec,size=67108864',
            '--mount', f'type=bind,src={directory},dst=/role', '--entrypoint', '/usr/local/bin/node', image]
        if not (directory / 'key').exists():
            subprocess.run(command + ['/app/scripts/nosh-guard.mjs', 'review', 'keygen', '--output', '/role/key'], check=True)
        safe_directory(directory / 'key', workspace)
        private_file(directory / 'key/private.pem')
        private_file(directory / 'key/public.pem')
        # Verify pairing inside this role's isolated container; never load private
        # key contents into this host process or the other role's container.
        subprocess.run(command + ['-e', "const fs=require('fs'),c=require('crypto');const k=c.createPrivateKey(fs.readFileSync('/role/key/private.pem'));if(k.asymmetricKeyType!=='ed25519')throw Error('Expected Ed25519');const a=c.createPublicKey(k).export({type:'spki',format:'pem'});const b=c.createPublicKey(fs.readFileSync('/role/key/public.pem')).export({type:'spki',format:'pem'});if(a!==b)throw Error('Key pair mismatch');"], check=True)
    public = stage / 'public'
    public.mkdir(mode=0o700, exist_ok=True)
    safe_directory(public, workspace)
    keys_dir = f'/etc/nosh-guard/ebpf-trust-{instance}'
    trust = {'schemaVersion': 1, 'kind': 'NoshGuardEbpfDeploymentTrust', 'backendAbi': 'nosh-egress-v2',
        'reviewPublicKey': f'{keys_dir}/review-public.pem', 'deploymentPublicKey': f'{keys_dir}/deployment-public.pem',
        'reviewAudience': f'notty-review-{instance}', 'deploymentAudience': f'notty-guard-ebpf-{instance}'}
    config_document = {'schemaVersion': 1,
        'reviewPrivateKey': str(stage / 'review/key/private.pem'), 'reviewPublicKey': str(stage / 'review/key/public.pem'),
        'deploymentPrivateKey': str(stage / 'deployment/key/private.pem'),
        'reviewAudience': trust['reviewAudience'], 'deploymentAudience': trust['deploymentAudience']}
    for role in ('review', 'deployment'):
        destination = public / f'{role}-public.pem'
        content = (stage / role / 'key/public.pem').read_bytes()
        if destination.exists() or destination.is_symlink():
            if private_file(destination).read_bytes() != content:
                raise ValueError('Prepared public key changed; refusing to continue')
        else:
            with destination.open('xb') as output:
                output.write(content)
    for path, document in ((public / 'trust.json', trust), (stage / 'policy-apply.json', config_document)):
        if path.exists() or path.is_symlink():
            if json.loads(private_file(path).read_text()) != document:
                raise ValueError(f'Prepared setup changed: {path}')
        else:
            write_json(path, document)
    digest = lambda path: hashlib.sha256(private_file(path).read_bytes()).hexdigest()
    hashes = [digest(public / name) for name in ('review-public.pem', 'deployment-public.pem', 'trust.json')]
    if hashes[0] == hashes[1]:
        raise ValueError('Review and deployment keys must be independent')
    print('Public trust to install at /etc/nosh-guard/ebpf-deployment-trust.json:')
    print(json.dumps(trust, indent=2))
    print(f'Review public key SHA-256: {hashes[0]}\nDeployment public key SHA-256: {hashes[1]}')
    print(f'User signing configuration: {config}\nPrivate keys remain in the two separate role directories under {stage}.')
    print('This establishes signing authority for this Guard instance. It does not activate a network policy.')
    confirm('Install this public trust with sudo and save the user signing configuration?')
    subprocess.run(['sudo', '/bin/bash', '-c', INSTALL_PUBLIC_TRUST, 'nosh-signing-setup', str(public), keys_dir, *hashes], check=True)
    config.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    safe_directory(config.parent, workspace)
    # Atomic exclusive creation, including a different filesystem for XDG config.
    fd, temporary = tempfile.mkstemp(prefix='.policy-apply-', dir=config.parent)
    try:
        with os.fdopen(fd, 'w') as output:
            json.dump(config_document, output, indent=2)
            output.write('\n')
        os.link(temporary, config)
    finally:
        os.unlink(temporary)
    print('Signing setup complete. Retry the same saved apply command (or wizard step 7).')


if __name__ == '__main__':
    try:
        main()
    except (ValueError, OSError, subprocess.CalledProcessError, EOFError, KeyError) as error:
        print(f'Signing setup stopped: {error}', file=sys.stderr)
        sys.exit(1)
