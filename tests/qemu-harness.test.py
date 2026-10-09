#!/usr/bin/env python3
"""Offline QEMU harness tests, run by the Docker-only package test suite."""

import contextlib
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import signal
import socket
import subprocess
import sys
import tempfile
import threading
import time
from types import SimpleNamespace
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('qemu_harness',
                                            ROOT / 'scripts/qemu/harness.py')
HARNESS = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = HARNESS
SPEC.loader.exec_module(HARNESS)


class TemporaryDirectoryTest(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix='notty-qemu-test-')
        self.addCleanup(temporary.cleanup)
        self.directory = Path(temporary.name)


class ChecksumTests(TemporaryDirectoryTest):
    def test_image_checksum_covers_complete_binary_file(self):
        contents = bytes(range(256)) * 4097 + b'final block\0\xff'
        image = self.directory / 'disk.img'
        image.write_bytes(contents)
        self.assertEqual(HARNESS.sha256_file(image), hashlib.sha256(contents).hexdigest())
        with image.open('ab') as output:
            output.write(b'corrupt')
        self.assertNotEqual(HARNESS.sha256_file(image), hashlib.sha256(contents).hexdigest())


class DownloadTests(TemporaryDirectoryTest):
    def setUp(self):
        super().setUp()
        self.contents = b'fixture-image\0' * 2048
        self.image = json.loads((ROOT / 'config/qemu-test.json').read_text())['image']
        self.image['sha256'] = hashlib.sha256(self.contents).hexdigest()
        self.cache = self.directory / 'cache'

    def response(self, contents, url=None):
        response = io.BytesIO(contents)
        response.geturl = lambda: url or self.image['url']
        return response

    def test_verified_image_is_reused_without_network(self):
        with patch('urllib.request.urlopen', return_value=self.response(self.contents)) as request:
            downloaded = HARNESS.download_image(self.image, self.cache)
        request.assert_called_once()
        self.assertEqual(downloaded.read_bytes(), self.contents)
        with patch('urllib.request.urlopen', side_effect=AssertionError('cache should be offline')):
            self.assertEqual(HARNESS.download_image(self.image, self.cache), downloaded)

    def test_corrupt_download_fails_without_retaining_unverified_image(self):
        with patch('urllib.request.urlopen', return_value=self.response(b'corrupt download')), \
                self.assertRaises(HARNESS.HarnessError):
            HARNESS.download_image(self.image, self.cache)
        self.assertEqual(list(self.cache.iterdir()), [])

    def test_corrupt_cached_image_is_rejected(self):
        with patch('urllib.request.urlopen', return_value=self.response(self.contents)):
            downloaded = HARNESS.download_image(self.image, self.cache)
        downloaded.chmod(0o600)
        downloaded.write_bytes(b'corrupt cached image')
        with patch('urllib.request.urlopen', side_effect=AssertionError('corrupt cache must fail')), \
                self.assertRaises(HARNESS.HarnessError):
            HARNESS.download_image(self.image, self.cache)

    def test_redirect_to_plain_http_is_rejected(self):
        response = self.response(self.contents, 'http://example.invalid/image')
        with patch('urllib.request.urlopen', return_value=response), \
                self.assertRaises(HARNESS.HarnessError):
            HARNESS.download_image(self.image, self.cache)
        self.assertEqual(list(self.cache.iterdir()), [])


class ManifestTests(unittest.TestCase):
    def manifest(self):
        return json.loads((ROOT / 'config/qemu-test.json').read_text())

    def test_committed_manifest_is_valid(self):
        manifest = self.manifest()
        self.assertIs(HARNESS.validate_manifest(manifest), manifest)

    def test_invalid_image_and_package_pins_are_rejected(self):
        cases = [('version', None, 2),
                 ('image', 'sha256', 'not-a-sha256'),
                 ('image', 'url', 'http://cloud-images.ubuntu.com/noble/image.img'),
                 ('image', 'architecture', 'arm64'),
                 ('image', 'format', 'raw'),
                 ('guest', 'aptSnapshot', 'latest'),
                 ('guest', 'packages', {}),
                 ('packages', 'docker.io', '*'),
                 ('packages', 'docker-buildx', '')]
        for section, name, value in cases:
            with self.subTest(section=section, name=name):
                manifest = self.manifest()
                if name is None:
                    manifest[section] = value
                elif section == 'packages':
                    manifest['guest']['packages'][name] = value
                else:
                    manifest[section][name] = value
                with self.assertRaises(HARNESS.HarnessError):
                    HARNESS.validate_manifest(manifest)


class CommandTests(TemporaryDirectoryTest):
    @staticmethod
    def process_is_running(pid):
        try:
            state = Path(f'/proc/{pid}/stat').read_text().split(')', 1)[1].split()[0]
        except FileNotFoundError:
            return False
        return state != 'Z'

    def stop_child_if_needed(self, pid_path):
        if pid_path.exists():
            pid = int(pid_path.read_text())
            if self.process_is_running(pid):
                os.kill(pid, signal.SIGKILL)

    def test_command_timeout_stops_descendant_processes(self):
        pid_path = self.directory / 'child.pid'
        self.addCleanup(self.stop_child_if_needed, pid_path)
        code = (
            'import pathlib, subprocess, sys, time; '
            'child = subprocess.Popen([sys.executable, "-c", '
            '"import signal, time; signal.signal(signal.SIGTERM, signal.SIG_IGN); time.sleep(60)"]); '
            'pathlib.Path(sys.argv[1]).write_text(str(child.pid)); '
            'time.sleep(60)'
        )
        started_processes = []
        start_process = HARNESS.start_process

        def capture_process(*args, **kwargs):
            process = start_process(*args, **kwargs)
            started_processes.append(process)
            return process

        started = time.monotonic()
        with patch.object(HARNESS, 'start_process', side_effect=capture_process), \
                self.assertRaises(HARNESS.HarnessError):
            HARNESS.run_command([sys.executable, '-c', code, str(pid_path)], timeout=1)
        self.assertLess(time.monotonic() - started, 10)
        self.assertTrue(pid_path.exists(), 'command must start its child before timing out')
        child_pid = int(pid_path.read_text())
        deadline = time.monotonic() + 2
        while self.process_is_running(child_pid) and time.monotonic() < deadline:
            time.sleep(0.02)
        self.assertFalse(self.process_is_running(child_pid), 'timeout left a live descendant')
        self.assertTrue(started_processes[0].stdout.closed, 'timeout left its output pipe open')

    def test_command_arguments_are_literal_and_capture_binary_output(self):
        sentinel = self.directory / 'should-not-exist'
        argument = f"a path with spaces; $(touch '{sentinel}') `touch '{sentinel}'`"
        result = HARNESS.run_command(
            [sys.executable, '-c', 'import json, sys; print(json.dumps(sys.argv[1:]))', argument],
            timeout=5)
        self.assertIsInstance(result.stdout, bytes)
        self.assertEqual(json.loads(result.stdout), [argument])
        self.assertFalse(sentinel.exists())

    def test_command_failure_is_reported(self):
        with self.assertRaises(HARNESS.HarnessError):
            HARNESS.run_command([sys.executable, '-c', 'raise SystemExit(17)'], timeout=5)

    def test_logged_failure_points_to_absolute_log_without_disclosing_output(self):
        log_path = self.directory / 'stage output.log'
        code = ('import sys; print("private stdout"); '
                'print("private stderr", file=sys.stderr); raise SystemExit(int(sys.argv[1]))')
        for returncode, status in ((1, 1), (2, 2), (17, 1)):
            with self.subTest(returncode=returncode), self.assertRaises(HARNESS.HarnessError) as raised:
                HARNESS.run_command([sys.executable, '-c', code, str(returncode)], timeout=5,
                                    log_path=os.path.relpath(log_path))
            self.assertEqual(raised.exception.status, status)
            self.assertEqual(str(raised.exception),
                             f'{Path(sys.executable).name} exited {returncode}: see {log_path}')
        output = log_path.read_text()
        self.assertEqual(output.count('private stdout'), 3)
        self.assertEqual(output.count('private stderr'), 3)

    def test_logged_timeout_points_to_log_and_stops_process(self):
        log_path = self.directory / 'timed out.log'
        code = 'import time; print("private progress", flush=True); time.sleep(60)'
        started_processes = []
        start_process = HARNESS.start_process

        def capture_process(*args, **kwargs):
            process = start_process(*args, **kwargs)
            started_processes.append(process)
            return process

        with patch.object(HARNESS, 'start_process', side_effect=capture_process), \
                self.assertRaises(HARNESS.HarnessError) as raised:
            HARNESS.run_command([sys.executable, '-c', code], timeout=0.5,
                                log_path=os.path.relpath(log_path))
        self.assertEqual(raised.exception.status, 1)
        self.assertEqual(str(raised.exception),
                         f'command timed out after 0.5s: {Path(sys.executable).name}; see {log_path}')
        self.assertEqual(log_path.read_text(), 'private progress\n')
        self.assertIsNotNone(started_processes[0].poll(), 'timeout left the command running')
        self.assertTrue(started_processes[0]._nosh_qemu_closed)

    def test_termination_does_not_touch_an_unrelated_process_group(self):
        owned = HARNESS.start_process([sys.executable, '-c', 'import time; time.sleep(60)'])
        unrelated = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(60)'],
                                     start_new_session=True)
        for process in (owned, unrelated):
            self.addCleanup(self.ensure_stopped, process)
        HARNESS.terminate_process(owned)
        self.assertIsNotNone(owned.poll(), 'owned process was not reaped')
        self.assertIsNone(unrelated.poll(), 'cleanup killed another process group')
        HARNESS.terminate_process(owned)
        self.assertIsNone(unrelated.poll(), 'repeated cleanup killed another process group')

    def test_process_in_callers_group_never_causes_group_wide_termination(self):
        code = '''
import importlib.util, subprocess, sys
spec = importlib.util.spec_from_file_location('qemu_harness_child', sys.argv[1])
harness = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = harness
spec.loader.exec_module(harness)
child = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(60)'])
try:
    try:
        harness.terminate_process(child)
    except harness.HarnessError:
        pass
finally:
    if child.poll() is None:
        child.kill()
    child.wait(timeout=5)
print('caller survived')
'''
        helper = subprocess.Popen([sys.executable, '-B', '-c', code, str(SPEC.origin)],
                                  start_new_session=True, stdout=subprocess.PIPE,
                                  stderr=subprocess.PIPE)
        self.addCleanup(self.ensure_stopped, helper)
        stdout, stderr = helper.communicate(timeout=10)
        self.assertEqual(helper.returncode, 0, stderr.decode())
        self.assertEqual(stdout.strip(), b'caller survived')

    @staticmethod
    def ensure_stopped(process):
        if process.poll() is None:
            process.kill()
        process.wait(timeout=5)


class ArgumentTests(TemporaryDirectoryTest):
    def test_kvm_is_default_and_tcg_requires_explicit_selection(self):
        default = HARNESS.parse_args(['run'])
        self.assertEqual(default.accel, 'kvm')
        self.assertEqual(default.suite, 'smoke')
        self.assertEqual(default.ref, 'HEAD')
        self.assertEqual(HARNESS.parse_args(['run', '--accel', 'tcg']).accel, 'tcg')
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as raised:
            HARNESS.parse_args(['run', '--accel', 'auto'])
        self.assertEqual(raised.exception.code, 2)

    def test_full_suite_requires_explicit_upgrade_baseline(self):
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as raised:
            HARNESS.parse_args(['run', '--suite', 'full'])
        self.assertEqual(raised.exception.code, 2)
        parsed = HARNESS.parse_args(['run', '--suite', 'full', '--baseline-ref', 'v0.1.0'])
        self.assertEqual(parsed.baseline_ref, 'v0.1.0')

    def test_qemu_argv_keeps_paths_literal_and_network_forwarding_on_loopback(self):
        paths = {name: self.directory / f"vm, 'quoted $({name})'.{name}"
                 for name in ('disk', 'seed', 'qmp', 'serial')}
        for accelerator in ('kvm', 'tcg'):
            with self.subTest(accelerator=accelerator):
                arguments = SimpleNamespace(accel=accelerator, cpus=4, memory_mib=8192)
                command = HARNESS.build_qemu_command(arguments, paths, 22222)
                self.assertIsInstance(command, list)
                self.assertTrue(all(isinstance(item, str) for item in command))
                self.assertEqual(command[command.index('-accel') + 1], accelerator)
                self.assertIn('hostfwd=tcp:127.0.0.1:22222-:22', ' '.join(command))
                network = command[command.index('-netdev') + 1].split(',')
                # IPv6-only QEMU networking leaves DHCPv4 and SSH unreachable.
                self.assertIn('ipv4=on', network)
                self.assertIn('ipv6=on', network)
                for path in paths.values():
                    escaped_path = str(path).replace(',', ',,')
                    self.assertTrue(any(escaped_path in item for item in command), str(path))


class DirectoryTests(TemporaryDirectoryTest):
    def test_new_directory_is_private_and_reusable(self):
        path = self.directory / 'new' / 'cache'
        HARNESS.secure_directory(path)
        self.assertTrue(path.is_dir())
        self.assertEqual(path.stat().st_mode & 0o777, 0o700)
        HARNESS.secure_directory(path)

    def test_writable_directory_is_rejected_without_changing_its_mode(self):
        for mode in (0o770, 0o777):
            with self.subTest(mode=oct(mode)):
                path = self.directory / str(mode)
                path.mkdir(mode=0o700)
                path.chmod(mode)
                with self.assertRaises(HARNESS.HarnessError):
                    HARNESS.secure_directory(path)
                self.assertEqual(path.stat().st_mode & 0o777, mode)

    def test_symlink_endpoint_and_parent_are_rejected(self):
        target = self.directory / 'target'
        target.mkdir(mode=0o700)
        link = self.directory / 'link'
        link.symlink_to(target, target_is_directory=True)
        for path in (link, link / 'child'):
            with self.subTest(path=path), self.assertRaises(HARNESS.HarnessError):
                HARNESS.secure_directory(path)
        self.assertFalse((target / 'child').exists())

    def test_existing_directory_owned_by_another_user_is_rejected(self):
        path = self.directory / 'cache'
        path.mkdir(mode=0o700)
        other_uid = os.getuid() + 1
        with patch('os.getuid', return_value=other_uid), \
                patch('os.geteuid', return_value=other_uid), \
                self.assertRaises(HARNESS.HarnessError):
            HARNESS.secure_directory(path)


class QmpTests(TemporaryDirectoryTest):
    def exchange(self, responses, expected_commands):
        guest = HARNESS.Guest(SimpleNamespace(), {}, self.directory, self.directory)
        socket_path = guest.paths['qmp']
        socket_path.unlink(missing_ok=True)
        commands, failures = [], []
        with socket.socket(socket.AF_UNIX) as listener:
            listener.settimeout(5)
            listener.bind(str(socket_path))
            listener.listen(1)

            def serve():
                try:
                    connection, _ = listener.accept()
                    with connection:
                        connection.settimeout(5)
                        with connection.makefile('rwb') as stream:
                            greeting = {'QMP': {'version': {'qemu': {'major': 9, 'minor': 0,
                                                                   'micro': 0}}, 'capabilities': []}}
                            stream.write((json.dumps(greeting) + '\r\n').encode())
                            stream.flush()
                            for response_group in responses:
                                commands.append(json.loads(stream.readline())['execute'])
                                for response in response_group:
                                    stream.write((json.dumps(response) + '\r\n').encode())
                                stream.flush()
                except BaseException as error:
                    failures.append(error)

            server = threading.Thread(target=serve, daemon=True)
            server.start()
            try:
                return guest.qmp('query-kvm')
            finally:
                server.join(timeout=6)
                self.assertFalse(server.is_alive(), 'QMP client left server waiting for a command')
                self.assertEqual(failures, [])
                self.assertEqual(commands, expected_commands)

    def test_qmp_negotiates_capabilities_and_returns_actual_kvm_state_amid_events(self):
        for enabled in (True, False):
            with self.subTest(enabled=enabled):
                actual = {'enabled': enabled, 'present': True}
                result = self.exchange([
                    [{'event': 'RESUME', 'data': {}}, {'return': {}}],
                    [{'event': 'RTC_CHANGE', 'data': {'offset': 0}}, {'return': actual}],
                ], ['qmp_capabilities', 'query-kvm'])
                self.assertEqual(result, actual)

    def test_qmp_refuses_command_error(self):
        with self.assertRaises(HARNESS.HarnessError):
            self.exchange([
                [{'return': {}}],
                [{'error': {'class': 'CommandNotFound', 'desc': 'unavailable'}}],
            ], ['qmp_capabilities', 'query-kvm'])

    def test_qmp_refuses_capability_failure_without_issuing_query(self):
        with self.assertRaises(HARNESS.HarnessError):
            self.exchange([
                [{'error': {'class': 'GenericError', 'desc': 'capabilities rejected'}}],
            ], ['qmp_capabilities'])


class GitBundleTests(TemporaryDirectoryTest):
    def git(self, *arguments, directory=None):
        result = subprocess.run(['git', '-C', str(directory or self.repo), *arguments],
                                check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        return result.stdout.decode().strip()

    def setUp(self):
        super().setUp()
        self.repo = self.directory / 'source'
        self.repo.mkdir()
        self.git('init', '-q')
        self.git('config', 'user.name', 'QEMU Test')
        self.git('config', 'user.email', 'qemu-test@example.invalid')
        self.git('config', 'commit.gpgsign', 'false')
        self.git('config', 'tag.gpgsign', 'false')
        (self.repo / 'tracked.txt').write_text('baseline\n')
        self.git('add', 'tracked.txt')
        self.git('commit', '-qm', 'baseline')
        self.baseline = self.git('rev-parse', 'HEAD')
        self.git('tag', '-a', 'v0.1.0', '-m', 'baseline release')
        (self.repo / 'tracked.txt').write_text('candidate\n')
        self.git('commit', '-qam', 'candidate')
        self.candidate = self.git('rev-parse', 'HEAD')
        self.git('tag', 'v0.2.0')
        (self.repo / 'tracked.txt').write_text('local uncommitted change\n')
        (self.repo / 'private-untracked.txt').write_text('not part of a commit\n')

    def test_bundle_preserves_commits_and_release_tags_without_dirty_files(self):
        bundle = self.directory / 'source.bundle'
        result = HARNESS.prepare_git_bundle(self.repo, 'HEAD', 'v0.1.0', bundle)
        self.assertEqual(result['candidate'], self.candidate)
        self.assertEqual(result['baseline'], self.baseline)
        self.assertIn('refs/tags/v0.1.0', result['tags'])
        self.assertIn('refs/tags/v0.2.0', result['tags'])
        checkout = self.directory / 'checkout'
        self.git('clone', '-q', '--bare', str(bundle), str(checkout))
        self.assertEqual(self.git('show', f'{self.candidate}:tracked.txt', directory=checkout),
                         'candidate')
        self.assertEqual(self.git('show', f'{self.baseline}:tracked.txt', directory=checkout),
                         'baseline')
        self.assertEqual(self.git('rev-parse', 'v0.1.0^{}', directory=checkout), self.baseline)
        self.assertEqual(self.git('rev-parse', 'v0.2.0^{}', directory=checkout), self.candidate)
        self.assertNotIn('private-untracked.txt',
                         self.git('ls-tree', '-r', '--name-only', self.candidate, directory=checkout))
        self.assertEqual((self.repo / 'tracked.txt').read_text(), 'local uncommitted change\n')
        self.assertEqual(self.git('rev-parse', 'HEAD'), self.candidate)

    def test_smoke_bundle_records_no_baseline(self):
        result = HARNESS.prepare_git_bundle(self.repo, 'HEAD', None,
                                            self.directory / 'smoke.bundle')
        self.assertEqual(result['candidate'], self.candidate)
        self.assertIsNone(result['baseline'])

    def test_missing_revision_fails_without_creating_bundle(self):
        bundle = self.directory / 'missing.bundle'
        with self.assertRaises(HARNESS.HarnessError):
            HARNESS.prepare_git_bundle(self.repo, 'not-a-valid-revision', None, bundle)
        self.assertFalse(bundle.exists())

    def test_upgrade_cannot_use_two_refs_for_the_same_commit(self):
        bundle = self.directory / 'same-commit.bundle'
        with self.assertRaises(HARNESS.HarnessError) as raised:
            HARNESS.prepare_git_bundle(self.repo, 'HEAD', 'v0.2.0', bundle)
        self.assertEqual(raised.exception.status, 2)
        self.assertFalse(bundle.exists())


if __name__ == '__main__':
    unittest.main()
