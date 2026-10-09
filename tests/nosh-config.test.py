#!/usr/bin/env python3
import contextlib
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('nosh_config', Path(__file__).resolve().parents[1] / 'scripts/nosh-config.py')
c = importlib.util.module_from_spec(spec)
spec.loader.exec_module(c)

class ConfigTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.repo = self.root / "repo ' $(touch injected)"
        self.repo.mkdir()
        (self.repo / 'Dockerfile').write_text('FROM scratch\n')
        self.environment = patch.dict(os.environ, {'XDG_CONFIG_HOME':str(self.root / 'config'), 'XDG_STATE_HOME':str(self.root / 'state')})
        self.environment.start()
        self.mask = os.umask(0o077)
    def tearDown(self):
        os.umask(self.mask)
        self.environment.stop()
        self.temp.cleanup()
    def opened(self):
        return c.open_profile(self.repo, create=True)
    def export(self, settings=None):
        path = self.root / 'export.json'
        path.write_text(json.dumps({'kind':'NoshRepositoryConfiguration','schemaVersion':1,'settings':settings or c.defaults()['settings']}))
        return path

    def test_save_reopen_and_portable_boundaries(self):
        config, state, binding, doc = self.opened()
        self.assertEqual(c.open_profile(self.repo)[3], doc)
        self.assertEqual((config / 'profile.json').stat().st_mode & 0o777, 0o600)
        self.assertEqual(config.stat().st_mode & 0o777, 0o700)
        exported = c.portable(doc)
        self.assertNotIn('host', exported)
        self.assertNotIn(str(self.repo), json.dumps(exported))
        self.assertEqual(doc['profile']['settings']['tools']['mode'], 'read-only')
        self.assertEqual(doc['profile']['settings']['runtime']['dev']['launchMode'], 'enforce')

    def test_replaced_workspace_requires_explicit_import(self):
        self.opened()
        moved = self.root / 'moved'
        self.repo.rename(moved)
        self.repo.mkdir()
        with self.assertRaisesRegex(ValueError, 'identity changed'):
            c.open_profile(self.repo)
        with patch.object(c, 'refresh'):
            c.import_profile(self.export(), self.repo)
        self.assertEqual(c.open_profile(self.repo)[2]['workspace'], c.workspace_identity(self.repo))

    def test_import_resets_host_references_and_increments_revision(self):
        config, _, _, doc = self.opened()
        doc['profile']['host']['toolPolicyDigest'] = 'sha256:' + 'a' * 64
        c.write_json(config / 'profile.json', doc)
        with patch.object(c, 'refresh'):
            c.import_profile(self.export(), self.repo)
        imported = c.load_profile(config)
        self.assertEqual(imported['revision'], 2)
        self.assertEqual(imported['profile']['host']['toolPolicyDigest'], '')

    def test_unsafe_storage_and_workspace_local_state_rejected(self):
        config, state, _, _ = self.opened()
        filename = config / 'profile.json'
        original = filename.read_text()
        filename.unlink()
        target = self.root / 'elsewhere'
        target.write_text(original)
        filename.symlink_to(target)
        with self.assertRaises(ValueError): c.load_profile(config)
        with patch.dict(os.environ, {'XDG_STATE_HOME':str(self.repo / '.state')}):
            with self.assertRaisesRegex(ValueError, 'outside'): c.open_profile(self.repo, True)

    def test_validation_rejects_hooks_secrets_traversal_and_run_agents(self):
        for mutate in [
            lambda p: p.update(hook='curl bad'),
            lambda p: p['settings']['build'].update(dockerfile='../secret'),
            lambda p: p['settings']['build'].update(context='/etc'),
            lambda p: p['settings']['build'].update(buildArgs=['ACCESS_TOKEN=secret']),
            lambda p: p['settings']['runtime']['run'].update(agents='codex'),
            lambda p: p['host'].update(guardPrefix='/opt/../etc'),
            lambda p: p['settings']['build'].update(outputMode='push'),
        ]:
            profile = c.defaults()
            mutate(profile)
            with self.assertRaises(ValueError): c.validate_profile(profile)

    def test_build_arguments_remain_structured_and_paths_cannot_escape(self):
        build = c.defaults()['settings']['build']
        build['buildArgs'] = ['DISPLAY=$(touch injected); `id`']
        args = c.build_arguments(build, self.repo)
        self.assertIn('DISPLAY=$(touch injected); `id`', args)
        self.assertNotIn('--depth', args)
        self.assertNotIn('--cache-mode', args)
        (self.repo / 'outside').symlink_to(self.root)
        build['context'] = 'outside'
        with self.assertRaisesRegex(ValueError, 'inside'): c.build_arguments(build, self.repo)

    def test_write_lock_rejects_concurrent_import(self):
        config, _, _, _ = self.opened()
        with c.profile_lock(config):
            with self.assertRaisesRegex(ValueError, 'being saved'):
                with c.profile_lock(config): pass
        self.assertFalse((config / '.write-lock').exists())

    def captured(self, complete=True):
        bundle = c.private_dir(self.root / 'bundle')
        portable = c.private_dir(bundle / 'portable')
        c.write_json(portable / 'report.json', {'redacted':True})
        return {'bundleDir':str(bundle),'portableBundleDir':str(portable),'manifest':{'complete':complete, 'candidateEligible':complete, 'contentHash':'sha256:'+'c'*64, 'build':{'success':complete,'configDigest':'sha256:'+'b'*64}}}

    def run_ci(self, captured=None, status=0, exception=None):
        def run(command, **kw):
            self.assertEqual(kw['env']['NOSH_BUILD_NONINTERACTIVE'], '1')
            self.assertEqual(kw['stdin'], subprocess.DEVNULL)
            self.assertNotIn('sudo', command)
            self.assertIn('--private-json', command)
            if exception: raise exception
            if captured: kw['stdout'].write(json.dumps(captured))
            kw['stderr'].write('private diagnostic secret')
            return subprocess.CompletedProcess(command, status)
        output = self.root / 'artifacts'
        with patch.object(c.os, 'geteuid', return_value=1000), patch.object(c.subprocess, 'run', side_effect=run), contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            code = c.ci_capture(self.export(), self.repo, output)
        return code, c.read_json(output / 'result.json'), output

    def test_ci_success_publishes_only_portable_evidence(self):
        code, result, output = self.run_ci(self.captured())
        self.assertEqual(code, 0)
        self.assertEqual(result['status'], 'captured')
        self.assertFalse(result['approved'])
        self.assertEqual(result['imageDigest'], 'sha256:'+'b'*64)
        self.assertEqual(sorted(p.name for p in output.iterdir()), ['portable','result.json'])
        self.assertNotIn('secret', (output / 'result.json').read_text())
        self.assertEqual(result['portableDirectory'], 'portable')

    def test_ci_build_failure_preserves_exit_and_partial_artifacts(self):
        code, result, output = self.run_ci(self.captured(False), 23)
        self.assertEqual(code, 23)
        self.assertTrue((output / 'portable/report.json').exists())

    def test_ci_incomplete_zero_exit_still_fails(self):
        code, result, _ = self.run_ci(self.captured(False))
        self.assertEqual(code, 1)
        self.assertEqual(result['status'], 'incomplete')

    def test_ci_missing_guard_retains_failure_without_unprofiled_fallback(self):
        code, result, output = self.run_ci(status=1)
        self.assertEqual(code, 1)
        self.assertIsNone(result['portableDirectory'])
        self.assertEqual(list(output.iterdir()), [output / 'result.json'])

    def test_ci_interrupt_records_result(self):
        code, result, _ = self.run_ci(exception=KeyboardInterrupt())
        self.assertEqual(code, 130)
        self.assertEqual(result['status'], 'interrupted')

    def test_ci_artifact_symlink_is_rejected(self):
        captured = self.captured()
        (Path(captured['portableBundleDir']) / 'secret').symlink_to(self.root / 'export.json')
        code, result, _ = self.run_ci(captured)
        self.assertNotEqual(code, 0)
        self.assertIn('Unsafe', result['error'])

    def test_refresh_is_unprivileged_and_marks_revision(self):
        config, state, binding, doc = self.opened()
        class Detector:
            def detect(self, *args): return {7:('unknown','requires explicit status')}, 1
        with patch.object(c, 'helper', return_value=Detector()), patch.object(c.subprocess, 'run', return_value=subprocess.CompletedProcess([], 0, '{}', '')) as run, contextlib.redirect_stdout(io.StringIO()):
            snapshot = c.refresh(config, state, binding, doc)
        self.assertFalse(snapshot['authoritative'])
        self.assertEqual(snapshot['revision'], doc['revision'])
        self.assertTrue(all('sudo' not in call.args[0] for call in run.call_args_list))

    def test_runtime_uses_saved_revision_and_validated_installed_authority(self):
        config, _, binding, doc = self.opened()
        doc['profile']['settings']['runtime']['dev']['duration'] = 180
        doc['profile']['settings']['tools']['mode'] = 'implementation'
        c.write_json(config / 'profile.json', doc)
        with patch.object(c, 'checked_guard', return_value='/trusted/bin/nosh-guard'), patch.object(c.subprocess, 'run', return_value=subprocess.CompletedProcess([], 0)) as run, contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(c.run_runtime(self.repo, 'dev', 'learn', 1), 0)
            args = run.call_args.args[0]
            self.assertEqual(args[:5], ['sudo','--','/trusted/bin/nosh-guard','net','learn'])
            self.assertIn('180', args)
            self.assertNotIn('--tool-mode', args)
            c.run_runtime(self.repo, 'dev', 'enforce', 1)
            self.assertIn('implementation', run.call_args.args[0])
            run.reset_mock()
            with self.assertRaisesRegex(ValueError, 'changed'):
                c.run_runtime(self.repo, 'dev', 'enforce', 2)
            run.assert_not_called()
        with patch.object(c, 'checked_guard', side_effect=ValueError('untrusted')), patch.object(c.subprocess, 'run') as run:
            with self.assertRaisesRegex(ValueError, 'untrusted'): c.run_runtime(self.repo, 'dev', 'enforce', 1)
            run.assert_not_called()

    def test_build_snapshot_checks_physical_directory_identity(self):
        identity = c.workspace_identity(self.repo)
        key = c.hashlib.sha256(identity['path'].encode()).hexdigest()
        directory = c.private_dir(self.root / '.nosh/build-net-profiles' / key)
        bundle = c.private_dir(directory / 'run-1')
        c.write_json(directory / 'latest-candidate.json', {'projectKey':key,'runId':'run-1'})
        manifest = {'project':{'canonicalPath':identity['path'],'dev':identity['dev'],'ino':identity['ino']}, 'build':{}}
        c.write_json(bundle / 'evidence-manifest.json', manifest)
        with patch.object(c.Path, 'home', return_value=self.root):
            self.assertEqual(c.build_snapshot(c.defaults()['settings']['build'], self.repo)['state'], 'saved-unverified')
            manifest['project']['ino'] = '0'
            c.write_json(bundle / 'evidence-manifest.json', manifest)
            self.assertEqual(c.build_snapshot(c.defaults()['settings']['build'], self.repo)['state'], 'stale')

    def test_failed_capture_can_publish_preserved_diagnostics(self):
        captured = self.captured(False)
        c.write_json(Path(captured['bundleDir']) / 'evidence-manifest.json', captured.pop('manifest'))
        captured['kind'] = 'NoshBuildCaptureFailure'
        code, result, output = self.run_ci(captured, 1)
        self.assertEqual(code, 1)
        self.assertTrue((output / 'portable/report.json').exists())

    def test_config_and_readonly_state_cannot_share_directory(self):
        with patch.dict(os.environ, {'XDG_STATE_HOME':str(self.root / 'config')}):
            with self.assertRaisesRegex(ValueError, 'overlap'): self.opened()

    def test_launcher_pins_image_and_mounts_no_workspace_or_control_socket(self):
        config, state, binding, doc = self.opened()
        image = 'sha256:' + 'a' * 64
        calls = []
        class Launcher:
            def configured_image(self): return image
            def docker(self, *args):
                calls.append(args)
                if args[:2] == ('context','inspect'): return 'unix:///var/run/docker.sock'
                if args[:2] == ('image','inspect'): return image + '|1'
                if args[0] == 'port': return '127.0.0.1:43123'
                if args[0] == 'inspect': return 'healthy'
                return 'container-id'
        with patch.object(c, 'helper', return_value=Launcher()), patch.dict(os.environ, {'DOCKER_HOST':''}), contextlib.redirect_stdout(io.StringIO()):
            c.launch(config, state, binding, doc, browser=False)
        run = next(args for args in calls if args[0] == 'run')
        self.assertEqual(run[-1], image)
        self.assertEqual(run[run.index('--pull') + 1], 'never')
        mounts = [run[index+1] for index, arg in enumerate(run) if arg == '--mount']
        self.assertEqual(len(mounts), 3)
        self.assertTrue(any(str(config) in item and not item.endswith(',readonly') for item in mounts))
        self.assertTrue(any(str(state) in item and item.endswith(',readonly') for item in mounts))
        self.assertTrue(all(str(self.repo) not in item and 'docker.sock' not in item for item in mounts))
        self.assertIn('--read-only', run)
        self.assertIn('no-new-privileges:true', run)

    def test_launcher_rejects_remote_daemon_before_starting_containers(self):
        config, state, binding, doc = self.opened()
        class Launcher:
            def configured_image(self): return 'sha256:' + 'a' * 64
            def docker(self, *args): raise AssertionError('No Docker contact expected')
        with patch.object(c, 'helper', return_value=Launcher()), patch.dict(os.environ, {'DOCKER_HOST':'ssh://remote'}):
            with self.assertRaisesRegex(ValueError, 'local'): c.launch(config, state, binding, doc, False)

    def test_new_profile_seeds_existing_private_host_configuration(self):
        root = c.private_dir(self.root / 'config/nosh')
        (root / 'paths.conf').write_text('SCHEMA_VERSION=1\nNOSH_GUARD_PREFIX=/usr/local\n')
        _, _, _, doc = self.opened()
        self.assertEqual(doc['profile']['host']['guardPrefix'], '/usr/local')

if __name__ == '__main__': unittest.main()
