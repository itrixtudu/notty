#!/usr/bin/env python3
"""Run mount-enforcement probes against a local Nosh image; no installed policy changes."""
import argparse
import importlib.util
import os
from pathlib import Path
import subprocess
import tempfile

module = importlib.util.spec_from_file_location('policy', Path(__file__).with_name('nosh-tool-policy.py'))
policy = importlib.util.module_from_spec(module)
module.loader.exec_module(policy)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--image', required=True, help='Already-built local Nosh image; never builds or pulls')
    args = parser.parse_args()
    if os.getuid() == 0:
        parser.error('Run as the normal Docker-authorized workspace owner')
    image = policy.docker('image', 'inspect', '--format', '{{.Id}}', args.image)
    with tempfile.TemporaryDirectory(prefix='nosh-policy-smoke-') as temporary:
        root = Path(temporary)
        workspace = root / 'workspace'
        workspace.mkdir()
        (workspace / '.codex').mkdir()
        (workspace / '.codex/config.toml').write_text('# protected\n')
        store = policy.Store(root / 'test-authority', os.getuid())
        environment = dict(kind='NoshEnvironmentPolicy', schemaVersion=1, snapshotDigest='sha256:' + 'a' * 64,
            proposalDigest='sha256:' + 'b' * 64, workspace=str(workspace), workload='dev', allowImplementation=True,
            defaultMode='read-only', policyReadOnly=True, toolSelectionsInformational=True,
            limitations=list(policy.LIMITATIONS), reviewer='Docker smoke', acknowledged=True, approvedAt='2026-10-04T00:00:00Z')
        data = policy.encoded(environment)
        store.activate(workspace, environment, data, policy.digest(data))
        for mode in ('read-only', 'implementation'):
            container = policy.launch_container(['run', '-d', '--name', f'nosh-policy-smoke-{os.getpid()}-{mode}',
                '--network', 'none', '-v', f'{workspace}:{workspace}', image, '/bin/sh', '-c', 'while sleep 3600; do :; done'],
                workspace, mode, store)
            try:
                def probe(command, success):
                    result = subprocess.run(['docker', 'exec', container, '/bin/sh', '-c', command], capture_output=True, text=True)
                    if (result.returncode == 0) != success:
                        raise RuntimeError(f'{mode}: unexpected result for {command}: {result.stderr}')
                probe(f'touch {workspace}/workspace-write', mode == 'implementation')
                probe('touch /tmp/scratch-write', True)
                probe(f'touch {policy.RUNTIME}/codex/state-write', True)
                probe(f'printf changed >> {policy.DESTINATION}/environment-policy.json', False)
                probe(f'rm {policy.DESTINATION}/environment-policy.json', False)
                probe(f'touch {policy.DESTINATION}/new-policy', False)
                probe(f'printf changed >> {workspace}/.codex/config.toml', False)
                probe('touch /etc/rootfs-write', False)
                probe('test ! -S /var/run/docker.sock', True)
                print(f'{mode}: workspace, policy, settings, root filesystem, scratch, and isolated state verified')
            finally:
                policy.docker('rm', '--force', container)


if __name__ == '__main__':
    main()
