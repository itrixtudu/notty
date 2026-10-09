import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import sys
sys.dont_write_bytecode = True
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('policy', Path(__file__).parents[1] / 'scripts/nosh-tool-policy.py')
policy = importlib.util.module_from_spec(spec)
spec.loader.exec_module(policy)


class PolicyTests(unittest.TestCase):
    def setUp(self):
        self.live_mock = patch.object(policy, 'verify_live_mounts')
        self.live_mock.start()
        self.addCleanup(self.live_mock.stop)
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.workspace = self.root / 'work'
        self.workspace.mkdir()
        self.store = policy.Store(self.root / 'authority', os.getuid())
        self.environment = dict(kind='NoshEnvironmentPolicy', schemaVersion=1, snapshotDigest='sha256:' + 'a' * 64,
            proposalDigest='sha256:' + 'b' * 64, workspace=str(self.workspace), workload='dev', allowImplementation=True,
            defaultMode='read-only', policyReadOnly=True, toolSelectionsInformational=True,
            limitations=list(policy.LIMITATIONS), reviewer='Reviewer', acknowledged=True, approvedAt='2026-10-04T00:00:00Z')
        self.data = policy.encoded(self.environment)
        self.revision = policy.digest(self.data)
        self.store.activate(self.workspace, self.environment, self.data, self.revision)

    def tearDown(self):
        self.temporary.cleanup()

    def base(self):
        return {'Env': ['HOME=/home/agent'], 'HostConfig': {'Binds': [f'{self.workspace}:{self.workspace}:rw']}}

    def test_tool_activity_proposal_migration_preserves_legacy_provenance(self):
        legacy = {'kind': 'NoshToolReviewProposal', 'schemaVersion': 1, 'enforcing': False,
                  'snapshotDigest': 'sha256:' + 'a' * 64, 'reviewer': 'Reviewer', 'acknowledged': True,
                  'completedAt': '2026-10-07T00:00:00.000Z',
                  'decisions': {'one': {'choice': 'read-only', 'note': ''},
                                'two': {'choice': 'exclude', 'note': 'inspect'}}}
        migrated = policy.normalize_tool_proposal(legacy)
        self.assertEqual(migrated['schemaVersion'], 2)
        self.assertEqual(migrated['decisions']['one'],
                         {'choice': 'expected', 'note': '', 'legacyChoice': 'read-only'})
        self.assertEqual(migrated['decisions']['two'],
                         {'choice': 'investigate', 'note': 'inspect', 'legacyChoice': 'exclude'})
        with self.assertRaises(ValueError):
            policy.normalize_tool_proposal({**legacy, 'schemaVersion': 2,
                                            'decisions': {'one': {'choice': 'exclude', 'note': ''}}})
        with self.assertRaises(ValueError):
            policy.normalize_tool_proposal({**legacy, 'schemaVersion': 2,
                                            'decisions': {'one': {'choice': 'expected',
                                                                  'legacyChoice': 'exclude',
                                                                  'note': ''}}})

    def adapted(self, mode=None):
        return policy.adapt_spec(self.base(), self.workspace, mode, self.store)

    def inspected(self, spec):
        return {'Config': {key: spec[key] for key in ('Env', 'Labels', 'User')}, 'HostConfig': spec['HostConfig'],
            'Mounts': [dict(Type='bind', Source=s, Destination=t, RW=m == 'rw') for s, t, m in
                       (value.split(':') for value in spec['HostConfig']['Binds'])]}

    def test_modes_keep_policy_readonly_and_isolate_agent_state(self):
        for mode in ('read-only', 'implementation'):
            spec = self.adapted(mode)
            inspected = self.inspected(spec)
            self.assertTrue(policy.verify_container(inspected, self.workspace, mode, self.store)['verified'])
            self.assertIn(f'{self.workspace}:{self.workspace}:' + ('ro' if mode == 'read-only' else 'rw'), spec['HostConfig']['Binds'])
            mount = next(m for m in inspected['Mounts'] if m['Destination'] == policy.DESTINATION)
            self.assertFalse(mount['RW'])
            self.assertTrue(spec['HostConfig']['ReadonlyRootfs'])
            self.assertEqual(spec['Healthcheck'], {'Test': ['NONE']})
            self.assertEqual(spec['HostConfig']['CapDrop'], ['ALL'])
            self.assertIn('CODEX_HOME=' + policy.RUNTIME + '/codex', spec['Env'])

    def test_tampered_live_mount_and_privileges_rejected(self):
        for mutation in ('policy-write', 'workspace-write', 'privileged', 'extra-volume', 'extra-tmpfs'):
            inspected = self.inspected(self.adapted())
            if mutation == 'policy-write':
                next(m for m in inspected['Mounts'] if m['Destination'] == policy.DESTINATION)['RW'] = True
            elif mutation == 'workspace-write': inspected['Mounts'][0]['RW'] = True
            elif mutation == 'privileged': inspected['HostConfig']['Privileged'] = True
            elif mutation == 'extra-volume': inspected['Mounts'].append(dict(Type='volume', Destination='/escape', RW=True))
            else: inspected['Mounts'].append(dict(Type='tmpfs', Destination=policy.DESTINATION, RW=True))
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                policy.verify_container(inspected, self.workspace, store=self.store)

    def test_unsupported_privileges_and_aliases_rejected(self):
        for key, value in [('Privileged', True), ('CapAdd', ['SYS_ADMIN']), ('NetworkMode', 'host'),
                           ('Devices', [{}]), ('DeviceRequests', [{}]), ('VolumesFrom', ['other']),
                           ('SecurityOpt', ['seccomp=unconfined'])]:
            spec = self.base()
            spec['HostConfig'][key] = value
            with self.subTest(key=key), self.assertRaises(ValueError):
                policy.adapt_spec(spec, self.workspace, store=self.store)
        for source, target in [(self.store.root, '/alias'), (self.workspace, '/etc/nosh'),
                               (self.workspace, policy.RUNTIME), (self.workspace, '/bin'),
                               (self.workspace, '/run/nosh-tool-policy-ready'), (self.workspace, '/run/nosh-guard')]:
            spec = self.base()
            spec['HostConfig']['Binds'].append(f'{source}:{target}:rw')
            with self.assertRaises(ValueError): policy.adapt_spec(spec, self.workspace, store=self.store)

    def test_old_container_remains_pinned_and_explicit_mode_change_fails(self):
        old = self.inspected(self.adapted('implementation'))
        changed = {**self.environment, 'allowImplementation': False}
        data = policy.encoded(changed)
        self.store.activate(self.workspace, changed, data, policy.digest(data))
        verified = policy.verify_container(old, self.workspace, store=self.store)
        self.assertEqual(verified['revision'], self.revision)
        self.assertEqual(verified['activeRevision'], policy.digest(data))
        with self.assertRaises(ValueError): policy.verify_container(old, self.workspace, 'read-only', self.store)
        with self.assertRaises(ValueError): self.adapted('implementation')
        self.store.activate(self.workspace, self.environment, self.data, self.revision)
        self.assertEqual(self.store.load(self.workspace)['revision'], self.revision)

    def test_modified_authority_or_workspace_identity_fails(self):
        applied = self.store.load(self.workspace)
        target = Path(applied['directory']) / 'environment-policy.json'
        target.chmod(0o644)
        target.write_bytes(self.data + b' ')
        with self.assertRaises(ValueError): self.store.load(self.workspace)
        target.write_bytes(self.data)
        self.workspace.rename(self.root / 'old-work')
        self.workspace.mkdir()
        with self.assertRaises(ValueError): self.store.load(self.workspace)

    def test_protected_configuration_aliases_rejected(self):
        config = self.workspace / '.codex'
        config.mkdir()
        original = config / 'config.toml'
        original.write_text('')
        os.link(original, self.workspace / 'alias')
        with self.assertRaises(ValueError): self.adapted('implementation')
        (self.workspace / 'alias').unlink()
        original.unlink()
        original.symlink_to(self.workspace / 'elsewhere')
        with self.assertRaises(ValueError): self.adapted('implementation')

    def test_new_policy_requires_recreate_and_missing_policy_rejects_mode(self):
        with self.assertRaisesRegex(ValueError, 'recreate'):
            policy.verify_container({'Config': {}, 'HostConfig': {}}, self.workspace, store=self.store)
        empty = policy.Store(self.root / 'empty', os.getuid())
        with self.assertRaises(ValueError): policy.adapt_spec(self.base(), self.workspace, 'read-only', empty)
        base = self.base()
        self.assertEqual(base, policy.adapt_spec(copy.deepcopy(base), self.workspace, store=empty))

    def test_live_mount_identity_rejects_a_different_inode(self):
        self.live_mock.stop()
        inspected = self.inspected(self.adapted())
        inspected['State'] = {'Running': True, 'Pid': os.getpid()}
        # This process has no policy bind mounts at the declared targets.
        with self.assertRaises(ValueError): policy.verify_live_mounts(inspected)

    def test_launch_verifies_before_release_and_removes_failed_container(self):
        called = []
        def docker(*args):
            called.append(args)
            if args[:2] == ('image', 'inspect'): return json.dumps([{'Config': {}}])
            if args[0] == 'create': return 'container-id'
            if args[0] == 'inspect': return '[{}]'
            return ''
        with patch.object(policy, 'docker', docker), patch.object(policy, 'verify_container', side_effect=ValueError('drift')):
            with self.assertRaisesRegex(ValueError, 'drift'):
                policy.launch_container(['run', '-d', '--name', 'test', '-v', f'{self.workspace}:{self.workspace}', 'image', 'sleep', '10'],
                                        self.workspace, store=self.store)
        self.assertEqual(called[-1], ('rm', '--force', 'container-id'))
        self.assertFalse(any(call[0] == 'exec' for call in called))


if __name__ == '__main__':
    unittest.main()
