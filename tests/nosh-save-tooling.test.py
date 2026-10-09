"""Private tooling configuration publication and preservation checks."""
import importlib.util
import os
from pathlib import Path
import stat
import subprocess
import tempfile
import unittest
from unittest import mock


SCRIPT = Path(__file__).resolve().parents[1] / 'scripts/nosh-save-tooling.py'
SPEC = importlib.util.spec_from_file_location('nosh_save_tooling', SCRIPT)
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)
IMAGE = 'sha256:' + 'a' * 64
OLD = 'sha256:' + 'b' * 64
UI = 'sha256:' + 'c' * 64
SAVED = f'SCHEMA_VERSION=1\nNOSH_POLICY_TOOLING_IMAGE={IMAGE}\nNOSH_POLICY_REVIEW_UI_IMAGE=\n'
ORIGINAL = f'SCHEMA_VERSION=1\nNOSH_POLICY_TOOLING_IMAGE={OLD}\nNOSH_POLICY_REVIEW_UI_IMAGE=\n'


class SaveToolingTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='nosh-save-tooling-')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.config = self.root / 'config' / 'policy-review-images.conf'

    def write_config(self, text, mode=0o600):
        self.config.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        if self.config.exists():
            self.config.chmod(0o600)
        self.config.write_text(text, encoding='utf-8')
        self.config.chmod(mode)

    def assert_no_temporary_files(self):
        self.assertEqual(list(self.root.rglob('.wizard-tooling.*')), [])

    def test_new_config_is_private_and_complete(self):
        result = MODULE.save_tooling(self.config, IMAGE)
        self.assertEqual(result, str(self.config))
        self.assertEqual(self.config.read_text(), SAVED)
        self.assertEqual(stat.S_IMODE(self.config.stat().st_mode), 0o600)
        self.assertEqual(stat.S_IMODE(self.config.parent.stat().st_mode), 0o700)
        self.assertEqual(self.config.stat().st_nlink, 1)
        self.assert_no_temporary_files()

    def test_existing_config_replaces_only_tooling_selection(self):
        self.write_config(f'# locally reviewed UI\nSCHEMA_VERSION=1\nNOSH_POLICY_REVIEW_UI_IMAGE={UI}\n\n'
                          f'NOSH_POLICY_TOOLING_IMAGE={OLD}\n# keep this comment\n')
        previous_inode = self.config.stat().st_ino
        MODULE.save_tooling(self.config, IMAGE)
        self.assertEqual(self.config.read_text(), f'# locally reviewed UI\nSCHEMA_VERSION=1\nNOSH_POLICY_REVIEW_UI_IMAGE={UI}\n\n'
                         f'NOSH_POLICY_TOOLING_IMAGE={IMAGE}\n# keep this comment\n')
        self.assertNotEqual(self.config.stat().st_ino, previous_inode)
        self.assertEqual(stat.S_IMODE(self.config.stat().st_mode), 0o600)
        self.assertEqual(self.config.stat().st_nlink, 1)
        self.assert_no_temporary_files()

    def test_ui_selection_preserves_tooling_and_comments(self):
        original = f'# locally verified tooling\nSCHEMA_VERSION=1\nNOSH_POLICY_TOOLING_IMAGE={OLD}\nNOSH_POLICY_REVIEW_UI_IMAGE={UI}\n'
        self.write_config(original)
        MODULE.save_tooling(self.config, IMAGE, setting='NOSH_POLICY_REVIEW_UI_IMAGE', expected_image=UI)
        self.assertEqual(self.config.read_text(), original.replace(UI, IMAGE))
        self.assertEqual(stat.S_IMODE(self.config.stat().st_mode), 0o600)
        self.assert_no_temporary_files()

    def test_ui_selection_creates_complete_private_configuration(self):
        MODULE.save_tooling(self.config, UI, setting='NOSH_POLICY_REVIEW_UI_IMAGE', expected_image='')
        self.assertEqual(self.config.read_text(), f'SCHEMA_VERSION=1\nNOSH_POLICY_TOOLING_IMAGE=\nNOSH_POLICY_REVIEW_UI_IMAGE={UI}\n')
        self.assertEqual(stat.S_IMODE(self.config.stat().st_mode), 0o600)

    def test_changed_ui_selection_during_build_is_preserved(self):
        self.write_config(f'SCHEMA_VERSION=1\nNOSH_POLICY_REVIEW_UI_IMAGE={UI}\n')
        original = self.config.read_bytes()
        for previous in ['', OLD]:
            with self.subTest(previous=previous), self.assertRaisesRegex(ValueError, 'changed during preparation'):
                MODULE.save_tooling(self.config, IMAGE, setting='NOSH_POLICY_REVIEW_UI_IMAGE', expected_image=previous)
            self.assertEqual(self.config.read_bytes(), original)
        self.assert_no_temporary_files()

    def test_unrelated_tooling_change_during_ui_build_is_preserved(self):
        MODULE.save_tooling(self.config, OLD)
        MODULE.save_tooling(self.config, IMAGE)
        MODULE.save_tooling(self.config, UI, setting='NOSH_POLICY_REVIEW_UI_IMAGE', expected_image='')
        self.assertEqual(self.config.read_text(), SAVED.replace('NOSH_POLICY_REVIEW_UI_IMAGE=\n', f'NOSH_POLICY_REVIEW_UI_IMAGE={UI}\n'))

    def test_unknown_image_setting_is_rejected_before_creating_configuration(self):
        with self.assertRaisesRegex(ValueError, 'unknown image configuration setting'):
            MODULE.save_tooling(self.config, IMAGE, setting='SCHEMA_VERSION')
        self.assertFalse(self.config.parent.exists())

    def test_missing_tooling_setting_is_appended_preserving_ui_and_comments(self):
        self.write_config(f'# selection is optional\nNOSH_POLICY_REVIEW_UI_IMAGE={UI}\n')
        MODULE.save_tooling(self.config, IMAGE)
        self.assertEqual(self.config.read_text(), f'SCHEMA_VERSION=1\n# selection is optional\nNOSH_POLICY_REVIEW_UI_IMAGE={UI}\n'
                         f'NOSH_POLICY_TOOLING_IMAGE={IMAGE}\n')

    def test_legacy_tooling_only_config_gains_schema_and_managed_ui_default(self):
        self.write_config(f'NOSH_POLICY_TOOLING_IMAGE={OLD}\n')
        MODULE.save_tooling(self.config, IMAGE)
        self.assertEqual(self.config.read_text(), SAVED)

    def test_unsupported_schema_and_unknown_or_malformed_lines_are_rejected(self):
        for original in ['SCHEMA_VERSION=2\n', 'SCHEMA_VERSION=\n', 'export NOSH_POLICY_TOOLING_IMAGE=x\n',
                         'UNRECOGNIZED=1\n', 'malformed\n', ' SCHEMA_VERSION=1\n',
                         'NOSH_POLICY_REVIEW_UI_IMAGE=nosh-ui\n', 'NOSH_POLICY_TOOLING_IMAGE=nosh\n']:
            with self.subTest(original=original):
                self.write_config(original)
                with self.assertRaises(ValueError):
                    MODULE.save_tooling(self.config, IMAGE)
                self.assertEqual(self.config.read_text(), original)
                self.assert_no_temporary_files()

    def test_invalid_image_id_rejected_before_creating_configuration(self):
        for image in ['nosh', OLD.upper(), 'sha256:' + 'a' * 63, IMAGE + '\n',
                      'sha256:' + 'g' * 64, '', IMAGE + '\nOTHER=1']:
            with self.subTest(image=image), self.assertRaisesRegex(ValueError, 'exact local image ID'):
                MODULE.save_tooling(self.config, image)
            self.assertFalse(self.config.parent.exists())

    def test_relative_config_path_is_rejected_like_the_review_wrapper(self):
        with self.assertRaisesRegex(ValueError, 'absolute path'):
            MODULE.save_tooling('policy-review-images.conf', IMAGE)

    def test_existing_config_must_have_private_permissions(self):
        for mode in [0o644, 0o660, 0o400, 0o700]:
            with self.subTest(mode=oct(mode)):
                self.write_config('original\n', mode)
                with self.assertRaisesRegex(ValueError, 'private caller-owned regular file'):
                    MODULE.save_tooling(self.config, IMAGE)
                self.assertEqual(self.config.read_text(), 'original\n')
        self.assert_no_temporary_files()

    def test_group_or_world_writable_parent_is_rejected(self):
        self.config.parent.mkdir(mode=0o700)
        for mode in [0o770, 0o707, 0o777]:
            with self.subTest(mode=oct(mode)):
                self.config.parent.chmod(mode)
                with self.assertRaisesRegex(ValueError, 'not writable by others'):
                    MODULE.save_tooling(self.config, IMAGE)
                self.assertFalse(self.config.exists())
        self.config.parent.chmod(0o700)

    def test_symlink_file_or_parent_is_rejected(self):
        self.write_config('original\n')
        target = self.root / 'original.conf'
        self.config.rename(target)
        self.config.symlink_to(target)
        with self.assertRaisesRegex(ValueError, 'symlinks'):
            MODULE.save_tooling(self.config, IMAGE)
        self.assertEqual(target.read_text(), 'original\n')
        self.config.unlink()
        linked_parent = self.root / 'linked'
        linked_parent.symlink_to(self.config.parent, target_is_directory=True)
        with self.assertRaisesRegex(ValueError, 'symlinks'):
            MODULE.save_tooling(linked_parent / 'new.conf', IMAGE)
        self.assertFalse((self.config.parent / 'new.conf').exists())

    def test_hardlinked_config_is_rejected_without_changing_either_link(self):
        self.write_config('original\n')
        alias = self.root / 'alias.conf'
        os.link(self.config, alias)
        with self.assertRaisesRegex(ValueError, 'private caller-owned regular file'):
            MODULE.save_tooling(self.config, IMAGE)
        self.assertEqual(self.config.read_text(), 'original\n')
        self.assertEqual(alias.read_text(), 'original\n')
        self.assert_no_temporary_files()

    def test_duplicate_tooling_selection_is_rejected(self):
        original = f'NOSH_POLICY_TOOLING_IMAGE={OLD}\n# duplicate\nNOSH_POLICY_TOOLING_IMAGE={IMAGE}\n'
        self.write_config(original)
        with self.assertRaisesRegex(ValueError, 'duplicate settings'):
            MODULE.save_tooling(self.config, IMAGE)
        self.assertEqual(self.config.read_text(), original)
        self.assert_no_temporary_files()

    def test_duplicate_schema_or_ui_settings_are_rejected(self):
        for key, value in [('SCHEMA_VERSION', '1'), ('NOSH_POLICY_REVIEW_UI_IMAGE', UI)]:
            original = f'{key}={value}\n# duplicate\n{key}={value}\n'
            with self.subTest(key=key):
                self.write_config(original)
                with self.assertRaisesRegex(ValueError, 'duplicate settings'):
                    MODULE.save_tooling(self.config, IMAGE)
                self.assertEqual(self.config.read_text(), original)
                self.assert_no_temporary_files()

    def test_oversized_configuration_is_rejected(self):
        original = '#' * 65537
        self.write_config(original)
        with self.assertRaisesRegex(ValueError, 'private caller-owned regular file'):
            MODULE.save_tooling(self.config, IMAGE)
        self.assertEqual(self.config.read_text(), original)

    def test_fifo_is_rejected_without_blocking(self):
        self.config.parent.mkdir(mode=0o700)
        os.mkfifo(self.config, 0o600)
        result = subprocess.run(['python3', str(SCRIPT), '--image', IMAGE], capture_output=True,
                                text=True, timeout=5,
                                env={**os.environ, 'NOSH_PROFILE_REVIEW_IMAGE_CONFIG': str(self.config)})
        self.assertEqual(result.returncode, 1)
        self.assertIn('private caller-owned regular file', result.stderr)

    def test_new_config_does_not_replace_a_concurrently_created_file(self):
        original_link = os.link

        def competing_link(source, destination, **kwargs):
            Path(destination).write_text('concurrent selection\n')
            return original_link(source, destination, **kwargs)

        with mock.patch.object(MODULE.os, 'link', side_effect=competing_link):
            with self.assertRaises(FileExistsError):
                MODULE.save_tooling(self.config, IMAGE)
        self.assertEqual(self.config.read_text(), 'concurrent selection\n')
        self.assert_no_temporary_files()

    def test_existing_config_detects_concurrent_replacement(self):
        self.write_config(ORIGINAL)
        original_fsync = os.fsync

        def competing_write(descriptor):
            competing = self.root / 'concurrent.conf'
            competing.write_text('concurrent selection\n')
            os.replace(competing, self.config)
            original_fsync(descriptor)

        with mock.patch.object(MODULE.os, 'fsync', side_effect=competing_write):
            with self.assertRaisesRegex(ValueError, 'changed; refusing to replace'):
                MODULE.save_tooling(self.config, IMAGE)
        self.assertEqual(self.config.read_text(), 'concurrent selection\n')
        self.assert_no_temporary_files()

    def test_existing_config_detects_concurrent_permission_or_hardlink_changes(self):
        for operation in ['chmod', 'hardlink', 'chmod_restore']:
            with self.subTest(operation=operation):
                self.write_config(ORIGINAL)
                original_fsync = os.fsync

                def competing_change(descriptor):
                    if operation == 'hardlink':
                        os.link(self.config, self.root / 'concurrent-link')
                    else:
                        self.config.chmod(0o644)
                        if operation == 'chmod_restore':
                            self.config.chmod(0o600)
                    original_fsync(descriptor)

                with mock.patch.object(MODULE.os, 'fsync', side_effect=competing_change):
                    with self.assertRaisesRegex(ValueError, 'changed; refusing to replace'):
                        MODULE.save_tooling(self.config, IMAGE)
                self.assertEqual(self.config.read_text(), ORIGINAL)
                self.assert_no_temporary_files()
                (self.root / 'concurrent-link').unlink(missing_ok=True)

    def test_cli_uses_explicit_config_without_touching_default(self):
        result = subprocess.run(['python3', str(SCRIPT), '--image', IMAGE], capture_output=True,
                                text=True, timeout=5, env={**os.environ,
                                'NOSH_PROFILE_REVIEW_IMAGE_CONFIG': str(self.config),
                                'XDG_CONFIG_HOME': str(self.root / 'default')})
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(self.config.exists())
        self.assertFalse((self.root / 'default').exists())

    def test_cli_uses_xdg_config_when_no_override_is_present(self):
        env = {**os.environ, 'XDG_CONFIG_HOME': str(self.root / 'xdg')}
        env.pop('NOSH_PROFILE_REVIEW_IMAGE_CONFIG', None)
        result = subprocess.run(['python3', str(SCRIPT), '--image', IMAGE], capture_output=True,
                                text=True, timeout=5, env=env)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual((self.root / 'xdg/nosh/policy-review-images.conf').read_text(),
                         SAVED)


if __name__ == '__main__':
    unittest.main()
