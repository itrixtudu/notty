import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts/qemu'))
import session
codex = session.codex


class CodexStateTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='nosh-codex-test-')
        self.addCleanup(self.temp.cleanup)
        self.home = Path(self.temp.name)
        self.profile = self.home / '.codex'
        self.work = self.home / 'project'
        self.profile.mkdir(mode=0o700)
        self.work.mkdir(mode=0o700)
        (self.profile / 'history.jsonl').write_text('{"fixture":true}\n')
        (self.profile / 'auth.json').write_text('{"fixture":"not-a-real-token"}\n')

    def policy(self, modes=None, prepare=True):
        return codex.policy(self.home, self.profile, self.work, modes or {}, prepare=prepare)

    def test_default_ro_preserves_history_and_auth(self):
        before = (self.profile / 'history.jsonl').read_bytes()
        result = self.policy()
        self.assertTrue(all(r['mode'] == 'ro' for r in result['resources']))
        self.assertNotIn('not-a-real-token', json.dumps(result))
        self.assertEqual(before, (self.profile / 'history.jsonl').read_bytes())
        self.assertFalse(any('history' in r['source'] for r in result['resources']))
        self.assertFalse((self.work / 'AGENTS.override.md').exists())

    def test_rw_files_allow_atomic_replacement_credentials_stay_ro(self):
        result = self.policy(dict(skills='rw', settings='rw', plugins='rw'))
        self.assertEqual([r['category'] for r in result['resources'] if r['mode'] == 'ro'], ['credentials'])
        self.assertFalse(any(r['source'].endswith('config.toml') for r in result['resources']))
        temporary = self.profile / 'config.new'
        temporary.write_text('model="fixture"\n')
        temporary.replace(self.profile / 'config.toml')
        self.assertEqual((self.profile / 'config.toml').read_text(), 'model="fixture"\n')

    def test_dry_policy_has_no_filesystem_side_effects(self):
        before = sorted(str(p) for p in self.home.rglob('*'))
        self.policy(prepare=False)
        self.assertEqual(before, sorted(str(p) for p in self.home.rglob('*')))

    def test_symlink_hardlink_and_overlap_rejected(self):
        (self.profile / 'skills').symlink_to(self.work)
        with self.assertRaisesRegex(ValueError, 'canonical'):
            self.policy()
        (self.profile / 'skills').unlink()
        os.link(self.profile / 'auth.json', self.work / 'alias')
        with self.assertRaisesRegex(ValueError, 'hard-linked'):
            self.policy()
        with self.assertRaisesRegex(ValueError, 'overlap'):
            codex.policy(self.home, self.profile, self.home, {})

    def test_alias_bind_cannot_bypass_protection(self):
        result = self.policy()
        codex.validate_binds(result, [f'{self.profile}:{self.home}/.codex:rw', f'{self.work}:{self.work}:rw'])
        with self.assertRaisesRegex(ValueError, 'exposes'):
            codex.validate_binds(result, [f'{self.profile}:/alternate:rw'])
        with self.assertRaisesRegex(ValueError, 'overlaps'):
            codex.validate_binds(result, [f'{self.work}/.codex:/config-alias:rw'])

    def test_lock_exclusion_across_processes_and_release(self):
        lock = codex.ProfileLock(self.profile, 'test')
        command = [sys.executable, str(ROOT / 'scripts/codex-state.py'), 'lease', '--codex-home', str(self.profile)]
        result = subprocess.run(command, input='', text=True, capture_output=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('already in use', result.stderr)
        lock.close()
        result = subprocess.run(command, input='', text=True, capture_output=True)
        self.assertEqual(result.stdout.strip(), 'locked')

    def test_detached_container_lease_survives_launcher_exit(self):
        binary = self.home / 'bin'
        binary.mkdir()
        marker = self.home / 'running'
        self.addCleanup(lambda: marker.unlink(missing_ok=True))
        docker = binary / 'docker'
        docker.write_text('#!' + sys.executable + '\n' + """
import os, pathlib, sys, time
marker = pathlib.Path(os.environ['FIXTURE_RUNNING'])
args = sys.argv[1:]
if args[0] == 'ps':
    pass
elif args[0] == 'run':
    marker.touch()
    print('a' * 64)
elif args[0] == 'inspect':
    print('a' * 64 if args[2] == '{{.Id}}' else ('true' if marker.exists() else 'false'))
elif args[0] == 'wait':
    while marker.exists():
        time.sleep(.02)
""")
        docker.chmod(0o700)
        environment = {**os.environ, 'PATH': str(binary) + ':' + os.environ['PATH'], 'FIXTURE_RUNNING': str(marker)}
        result = subprocess.run([sys.executable, str(ROOT / 'scripts/codex-state.py'), 'launch',
                                 '--codex-home', str(self.profile), '--', 'docker', 'run', 'fixture'],
                                env=environment, capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr)
        with self.assertRaisesRegex(ValueError, 'already in use'):
            codex.ProfileLock(self.profile, 'competitor')
        marker.unlink()
        deadline = time.monotonic() + 5
        while True:
            try:
                lock = codex.ProfileLock(self.profile, 'after-exit')
                lock.close()
                break
            except ValueError:
                if time.monotonic() > deadline:
                    raise
                time.sleep(.02)

    def test_exports_keep_workdir_and_do_not_export_home(self):
        config = dict(self.policy(), repository=str(ROOT))
        exports, repo = session.exports_for(config)
        self.assertEqual(exports[0]['source'], exports[0]['target'])
        self.assertFalse(any(e['source'] == str(self.home) for e in exports))
        self.assertEqual(exports[1]['target'], '/home/noshqemu/.codex')
        self.assertTrue(exports[-1]['readonly'])

    def test_qemu_uses_shared_memory_and_scoped_exports(self):
        config = dict(self.policy(), repository=str(ROOT), uid=os.getuid(), gid=os.getgid())
        args = session.parse_args(['start', '--accel', 'tcg'])
        guest = session.SessionGuest(args, {}, self.home, self.work, config)
        guest.port = 2222
        command = guest.qemu_command()
        self.assertIn('q35,memory-backend=sharedmem', command)
        self.assertTrue(any('memory-backend-memfd' in arg and 'share=on' in arg for arg in command))
        self.assertEqual(sum('vhost-user-fs-pci' in arg for arg in command), 4)
        self.assertEqual(guest.paths['disk'], self.home / 'guest.qcow2')

    def test_session_defaults_to_start(self):
        self.assertEqual(session.parse_args([]).command, 'start')
        self.assertEqual(session.parse_args(['--detach']).command, 'start')
        self.assertEqual(session.parse_args(['status']).command, 'status')

    def test_start_reuses_running_session(self):
        state = self.home / 'state' / 'project-qemu'
        state.mkdir(parents=True, mode=0o700)
        config = dict(self.policy(), repository=str(ROOT))
        session.write_json(state / 'session.json', config)
        args = ['--state-dir', str(state.parent), '--workdir', str(self.work)]
        current = dict(status='running', runtime=str(self.home / 'runtime'), port=2222)
        with mock.patch.object(session, 'live_status', return_value=current), \
                mock.patch.object(session, 'preflight') as preflight, \
                mock.patch.object(session, 'state_lock') as lock, \
                mock.patch.object(session.subprocess, 'call', return_value=0) as attach:
            self.assertEqual(session.main(args), 0)
            self.assertIn('-tt', attach.call_args.args[0])
            self.assertIn('nosh-qemu-codex /bin/bash', attach.call_args.args[0][-1])
            attach.reset_mock()
            self.assertEqual(session.main(args + ['--detach']), 0)
            attach.assert_not_called()
            preflight.assert_not_called()
            lock.assert_not_called()

    def test_reset_preserves_history_and_refuses_unknown_content(self):
        state = self.home / 'state' / 'fixture'
        state.mkdir(parents=True, mode=0o700)
        (state / 'session.json').write_text('{}')
        (state / 'guest.qcow2').write_text('fixture')
        (state / 'unexpected').write_text('preserve')
        args = ['reset', '--state-dir', str(state.parent), '--name', 'fixture']
        with self.assertRaisesRegex(ValueError, 'unmanaged'):
            session.main(args)
        (state / 'unexpected').unlink()
        session.main(args)
        self.assertTrue((self.profile / 'history.jsonl').exists())
        self.assertEqual([p.name for p in state.iterdir()], ['session.lock'])


if __name__ == '__main__':
    unittest.main()
