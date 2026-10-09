"""Exercise the real Bash launcher through a PTY, with local Guard/Docker fakes."""
import hashlib
import json
import os
from pathlib import Path
import pty
import select
import shutil
import subprocess
import tempfile
import time
import unittest

REPO = Path(__file__).resolve().parents[1]


class LaunchMenuTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.home = self.root / 'home'
        self.work = self.root / 'workspace'
        self.checkout = self.root / 'checkout'
        for path in [self.home, self.work, self.checkout / 'scripts', self.root / 'bin']:
            path.mkdir(parents=True)
        shutil.copy(REPO / 'scripts/nosh.sh', self.checkout / 'scripts/nosh.sh')
        shutil.copy(REPO / 'scripts/nosh-launch-policy.py', self.checkout / 'scripts')
        self.write(self.checkout / 'scripts/nosh-init.sh', '#!/bin/bash\nprintf "PROFILE %s\\n" "$@"\n')
        key = hashlib.sha256(str(self.work).encode()).hexdigest()
        directory = self.home / '.nosh/net-profiles' / ('workspace-' + key + '-dev')
        directory.mkdir(parents=True)
        self.receipt = directory / 'current.json'
        self.receipt.write_text(json.dumps({'kind': 'NoshEgressProfileReceipt',
            'authoritative': False, 'workload': 'dev', 'workspace': {'path': str(self.work)},
            'latestCandidate': {'revision': 'new-draft', 'imageDigest': 'sha256:' + 'b' * 64}}))
        self.status = self.root / 'status.json'
        self.status.write_text(json.dumps({'workload': 'dev', 'workspace': {'path': str(self.work)},
            'integrity': {'ok': True}, 'activation': {'learnRevision': 'applied-run',
                'leafBundleDigest': 'sha256:' + 'a' * 64, 'imageDigest': 'sha256:' + 'b' * 64}}))
        self.write(self.root / 'bin/guard', '#!/bin/bash\n'
            'if [[ "$2" == status ]]; then cat "$TEST_STATUS"; else printf "ENFORCE %s\\n" "$@"; exit 17; fi\n')
        self.write(self.root / 'bin/sudo', '#!/bin/bash\n[[ "$1" != -- ]] || shift\nexec "$@"\n')
        self.write(self.root / 'bin/docker', '#!/bin/bash\necho LEGACY_DOCKER\nexit 41\n')
        self.env = {**os.environ, 'HOME': str(self.home),
            'XDG_CONFIG_HOME': str(self.home / '.config'),
            'NOSH_GUARD_BIN': str(self.root / 'bin/guard'), 'TEST_STATUS': str(self.status),
            'PATH': str(self.root / 'bin') + ':' + os.environ['PATH']}

    def write(self, path, text):
        path.write_text(text)
        path.chmod(0o755)

    def run_menu(self, choice, args=(), confirm=True):
        master, slave = pty.openpty()
        process = subprocess.Popen(['bash', str(self.checkout / 'scripts/nosh.sh'), *args],
            cwd=self.work, env=self.env, stdin=slave, stdout=slave, stderr=slave)
        os.close(slave)
        output = b''
        answers = {'': ('', '', ''), '1': ('y', '', ''),
                   '2': ('n', 'n', ''), '3': ('n', '', ''), '0': ('n', 'n', 'n')}[choice]
        replies = [(b'Run with existing policy [Y/n]:', answers[0] + '\n'),
                   (b'Profile new run [Y/n]:', answers[1] + '\n'),
                   (b'Run without policy [Y/n]:', answers[2] + '\n'),
                   (b'Allow sudo', 'y\n' if confirm else 'n\n'),
                   (b'Start bundled /app service?', 'n\n')]
        deadline = time.monotonic() + 8
        try:
            while time.monotonic() < deadline:
                if select.select([master], [], [], .05)[0]:
                    try:
                        data = os.read(master, 65536)
                    except OSError:
                        break
                    if not data:
                        break
                    output += data
                    for prompt, reply in list(replies):
                        if prompt in output:
                            os.write(master, reply.encode())
                            replies.remove((prompt, reply))
                elif process.poll() is not None:
                    break
            if process.poll() is None:
                process.wait(timeout=1)
        finally:
            if process.poll() is None:
                process.kill()
            process.wait()
            os.close(master)
        return process.returncode, output.decode()

    def test_enforcement_uses_applied_revision_and_preserves_image_override(self):
        code, output = self.run_menu('', ['--image', 'custom:image'])
        self.assertEqual(code, 17, output)
        self.assertIn('ENFORCE applied-run', output)
        self.assertIn('ENFORCE --expected-deployment', output)
        self.assertIn('ENFORCE sha256:' + 'a' * 64, output)
        self.assertIn('ENFORCE custom:image', output)
        self.assertNotIn('LEGACY_DOCKER', output)
        self.assertNotIn('Run without policy [Y/n]', output)
        self.assertNotIn('Profile new run [Y/n]', output)

    def test_running_container_attaches_without_launch_questions(self):
        self.write(self.root / 'bin/docker', '#!/bin/bash\n'
            'case "$1 $2" in\n'
            '  "inspect -f") case "$3" in *WorkingDir*) printf "%s\\n" "$PWD" ;; *workload*) printf "dev\\n" ;; *) printf "true\\n" ;; esac ;;\n'
            '  "container inspect") exit 0 ;;\n'
            '  "exec -it") printf "ATTACH %s\\n" "$@"; exit 23 ;;\n'
            '  *) printf "UNEXPECTED_DOCKER %s\\n" "$@"; exit 41 ;;\n'
            'esac\n')
        for args, name in [([], 'nosh-workspace-dev'),
                           (['start', '--name', 'custom-run'], 'custom-run')]:
            with self.subTest(args=args):
                code, output = self.run_menu('', args)
                self.assertEqual(code, 23, output)
                self.assertIn('ATTACH ' + name, output)
                self.assertIn('ATTACH ' + str(self.work), output)
                self.assertNotIn('Run with existing policy', output)
                self.assertNotIn('Profile new run', output)
                self.assertNotIn('Start bundled /app service?', output)
                self.assertNotIn('ENFORCE ', output)
                self.assertNotIn('UNEXPECTED_DOCKER', output)

    def test_cancel_and_declined_authority_never_launch(self):
        for choice, confirm in [('0', True), ('1', False)]:
            code, output = self.run_menu(choice, confirm=confirm)
            self.assertEqual(code, 0, output)
            self.assertNotIn('ENFORCE ', output)
            self.assertNotIn('LEGACY_DOCKER', output)

    def test_profile_delegates_to_wizard(self):
        code, output = self.run_menu('3', ['--image', 'custom:image'])
        self.assertEqual(code, 0, output)
        self.assertIn('PROFILE learn', output)
        self.assertIn('PROFILE custom:image', output)
        self.assertNotIn('ENFORCE ', output)
        self.assertNotIn('Run without policy [Y/n]', output)

    def test_missing_activation_stops_without_fallback(self):
        value = json.loads(self.status.read_text())
        value['activation'] = None
        self.status.write_text(json.dumps(value))
        code, output = self.run_menu('1')
        self.assertNotEqual(code, 0, output)
        self.assertIn('resume nosh init', output)
        self.assertNotIn('ENFORCE ', output)
        self.assertNotIn('LEGACY_DOCKER', output)

    def test_unguarded_and_explicit_legacy_skip_enforcement(self):
        for args in [[], ['--security-mode', 'legacy']]:
            _, output = self.run_menu('2', [*args, '--no-start-app', '--no-collab'])
            self.assertNotIn('ENFORCE ', output)
            if args:
                self.assertNotIn('Run with existing policy [Y/n]', output)
            else:
                self.assertIn('no Guard network policy enforcement', output)
                self.assertLess(output.index('Profile new run [Y/n]'),
                                output.index('Run without policy [Y/n]'))

    def test_status_workspace_mismatch_and_legacy_options_fail_closed(self):
        value = json.loads(self.status.read_text())
        value['workspace']['path'] = '/different'
        self.status.write_text(json.dumps(value))
        code, output = self.run_menu('1')
        self.assertNotEqual(code, 0, output)
        self.assertIn('another workspace', output)
        self.assertNotIn('ENFORCE ', output)
        code, output = self.run_menu('1', ['-P', '3000'])
        self.assertNotEqual(code, 0, output)
        self.assertIn('not supported with a network policy', output)

    def test_absent_receipt_keeps_normal_launcher(self):
        self.receipt.unlink()
        _, output = self.run_menu('0', ['--no-start-app', '--no-collab'])
        self.assertNotIn('Run with existing policy [Y/n]', output)
        self.assertNotIn('ENFORCE ', output)

    def test_noninteractive_and_dry_run_do_not_offer_menu(self):
        result = subprocess.run(['bash', str(self.checkout / 'scripts/nosh.sh'), '--dry-run',
            '--no-start-app', '--no-collab'], cwd=self.work, env=self.env,
            capture_output=True, text=True)
        self.assertNotIn('Run with existing policy [Y/n]', result.stdout + result.stderr)
        self.assertNotIn('ENFORCE ', result.stdout + result.stderr)


if __name__ == '__main__':
    unittest.main()
