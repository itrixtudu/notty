"""Private report selection and exact network-review scope, without Docker."""
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).parents[1] / 'scripts'))
from nosh_policy_manager import discover_reports, private_json, validate_report, validate_session


class PolicyManagerTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.workspace = self.root / 'project'
        self.workspace.mkdir()

    def write(self, path, value):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(value))
        path.chmod(0o600)

    def report(self, name, scope=None):
        report = self.root / 'nosh/codex-tool-audit' / name
        value = {'history_scope': scope or {'kind': 'directory', 'root': str(self.workspace)}}
        for name in ('allow.json', 'not-yet.json'):
            self.write(report / name, value)
        return report

    def test_discovery_excludes_other_workspaces_and_all_history(self):
        good = self.report('good')
        self.report('other', {'kind': 'directory', 'root': str(self.root)})
        self.report('all', {'kind': 'all', 'root': None})
        with patch.dict(os.environ, {'XDG_STATE_HOME': str(self.root)}):
            self.assertEqual(discover_reports(self.workspace), [str(good)])

    def test_multiple_and_explicit_reports_remain_distinct(self):
        first, second = self.report('first'), self.report('second')
        with patch.dict(os.environ, {'XDG_STATE_HOME': str(self.root)}):
            self.assertEqual(set(discover_reports(self.workspace, str(first))), {str(first), str(second)})

    def test_unsafe_metadata_and_symlink_rejected(self):
        report = self.report('bad')
        path = report / 'allow.json'
        path.chmod(0o644)
        with self.assertRaises(ValueError):
            validate_report(report, self.workspace)
        link = self.root / 'link'
        link.symlink_to(path)
        with self.assertRaises(OSError):
            private_json(link)

    def test_network_scope_must_match_all_dimensions(self):
        session = self.root / 'session'
        candidate = self.root / 'candidate'
        self.write(candidate / 'egress-profile.json', {'spec': {'launch': {'config': {'workload': 'dev'}}}})
        self.write(session / 'runtime/review-session.json', {'workdir': str(self.workspace),
            'imageDigest': 'sha256:a', 'revision': 'rev1', 'runtimeCandidate': str(candidate)})
        validate_session(session, self.workspace, 'sha256:a', 'rev1', 'dev')
        for workspace, image, revision, workload in [(self.root, 'sha256:a', 'rev1', 'dev'),
                (self.workspace, 'sha256:b', 'rev1', 'dev'), (self.workspace, 'sha256:a', 'rev2', 'dev'),
                (self.workspace, 'sha256:a', 'rev1', 'run')]:
            with self.assertRaises(ValueError):
                validate_session(session, workspace, image, revision, workload)


if __name__ == '__main__':
    unittest.main()
