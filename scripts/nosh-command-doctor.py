#!/usr/bin/env python3
"""Read-only diagnosis of prerequisites; never grants command-policy activation."""
import json
from pathlib import Path
import shutil
import subprocess


def inspect_host():
    checks = {'dockerClient': bool(shutil.which('docker')),
              'apparmorParser': bool(shutil.which('apparmor_parser')),
              'hostSecurityInterface': Path('/sys/kernel/security/apparmor').is_dir(),
              'localDaemon': False, 'dockerAppArmor': False}
    if checks['dockerClient']:
        try:
            result = subprocess.run(['docker', 'info', '--format', '{{json .SecurityOptions}}'],
                                    capture_output=True, text=True, timeout=10)
            checks['dockerAppArmor'] = result.returncode == 0 and any('apparmor' in value for value in json.loads(result.stdout))
            import os
            endpoint = os.environ.get('DOCKER_HOST')
            if not endpoint:
                result = subprocess.run(['docker', 'context', 'inspect', '--format', '{{.Endpoints.docker.Host}}'],
                                        capture_output=True, text=True, timeout=10)
                endpoint = result.stdout.strip() if result.returncode == 0 else ''
            checks['localDaemon'] = endpoint.startswith('unix://')
        except (OSError, ValueError, TypeError, subprocess.SubprocessError):
            pass
    return {'kind': 'NoshCommandPolicyReadiness', 'schemaVersion': 1, 'ready': False, 'checks': checks,
            'blocking': ['Live strict-agent and worker bypass tests have not been completed.',
                         'The MCP broker and strict agent startup integration are not available for activation.'],
            'nextStep': 'Run the worker probe on the Docker/AppArmor host; a passing worker probe alone does not authorize activation.'}


if __name__ == '__main__':
    print(json.dumps(inspect_host(), indent=2))
    raise SystemExit(2)
