"""Exercise real on-disk discovery with Docker inspection mocked offline."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest
import sys
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).parents[1] / 'scripts'))
spec = importlib.util.spec_from_file_location('wizard_status', Path(__file__).parents[1] / 'scripts/nosh-init-status.py')
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
real_inspect_image = module.inspect_image


class DiscoveryTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.home = self.root / 'home'
        self.workspace = self.root / 'repo'
        self.workspace.mkdir()
        self.prefix = self.root / 'guard'
        self.image = 'sha256:' + 'a' * 64
        self.env = patch.dict(os.environ, {
            'HOME': str(self.home), 'XDG_CONFIG_HOME': str(self.home / '.config'),
            'XDG_STATE_HOME': str(self.home / '.local/state'),
            'NOSH_PROFILE_REVIEW_STATE_ROOT': str(self.root / 'reviews'),
            'NOSH_POLICY_APPLY_CONFIG': str(self.home / '.config/nosh/policy-apply.json'),
        })
        self.env.start()
        self.addCleanup(self.env.stop)
        self.inspect = patch.object(module, 'inspect_image', return_value=(self.image, '1')).start()
        self.addCleanup(patch.stopall)
        self.key = hashlib.sha256(str(self.workspace).encode()).hexdigest()
        self.mirror = self.home / '.nosh/net-profiles' / ('repo-' + self.key + '-dev')
        self.receipt = {'workspace': {'path': str(self.workspace)},
                        'latestCandidate': {'revision': 'learn-1', 'imageDigest': self.image}}

    def write(self, path, value):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(value))
        path.chmod(0o600)

    def detect(self, authority=None):
        return module.detect(str(self.workspace), str(self.prefix), '', str(self.workspace), authority)

    def learned(self):
        self.write(self.mirror / 'current.json', self.receipt)
        for name in ['egress-profile.json', 'egress-policy.json', 'guard-ebpf-target-context.json']:
            self.write(self.mirror / 'review-candidates' / self.key / 'learn-1' / name, {'schemaVersion': 1})

    def reviewed(self):
        self.learned()
        session = self.root / 'reviews/session'
        self.write(session / 'runtime/review-session.json', {
            'kind': 'NoshPolicyReviewSession', 'directory': str(session), 'workdir': str(self.workspace),
            'revision': 'learn-1', 'imageDigest': self.image, 'graphContentDigest': 'graph-content',
            'readiness': {'readyForReview': True, 'blockers': []},
        })
        self.write(session / 'runtime/review.graph.json', {
            'contentDigest': 'graph-content', 'graphDigest': 'graph', 'proposals': [{'id': 'one'}],
            'coverage': [{'domain': domain, 'status': 'complete'} for domain in ['sbom-source', 'sbom-image']],
        })
        self.decision_file = session / 'decisions/decisions.json'
        self.decisions = {'contentDigest': 'sha256:' + 'b' * 64,
                          'graphContentDigest': 'graph-content', 'graphDigest': 'graph',
                          'decisions': [{'proposalId': 'one', 'disposition': 'accept'}]}
        self.write(self.decision_file, self.decisions)

    def test_missing_install_is_first(self):
        rows, suggested = self.detect()
        self.assertEqual(suggested, 1)
        self.assertEqual(rows[7][0], 'unknown')

    def test_installed_setup_and_existing_image_skip_to_learning(self):
        binary = self.prefix / 'bin/nosh-guard'
        binary.parent.mkdir(parents=True)
        binary.write_text('')
        binary.chmod(0o755)
        launcher = self.workspace / 'scripts/nosh.sh'
        launcher.parent.mkdir(exist_ok=True)
        launcher.write_text('')
        launcher.chmod(0o755)
        conf = self.home / '.config/nosh/paths.conf'
        conf.parent.mkdir(parents=True)
        conf.write_text(f'NOSH_GUARD_PREFIX={self.prefix}\nNOSH_BIN={launcher}\n')
        conf.chmod(0o600)
        rows, suggested = self.detect()
        self.assertEqual(suggested, 4)
        self.assertEqual(rows[3][0], 'available')
        self.assertEqual(rows['image'], (self.image, '1'))

    def test_learning_requires_export_and_exact_local_image(self):
        self.write(self.mirror / 'current.json', self.receipt)
        self.assertNotEqual(self.detect()[0][4][0], 'saved')
        self.learned()
        self.assertEqual(self.detect()[0][4][0], 'saved')
        self.inspect.return_value = ('sha256:' + 'c' * 64, '1')
        self.assertEqual(self.detect()[0][4][0], 'stale')
        self.inspect.return_value = (self.image, '0')
        self.assertEqual(self.detect()[0][3][0], 'incompatible')
        self.assertNotIn('image', self.detect()[0])

    def build_capture(self, run_id='build-one', image=None, complete=True):
        directory = self.home / '.nosh/build-net-profiles' / self.key / run_id
        self.write(directory / 'evidence-manifest.json', {
            'schemaVersion': 1, 'kind': 'NoshBuildEvidenceManifest',
            'mode': 'build-net-learn', 'runId': run_id,
            'generatedAt': '2026-10-08T03:00:00.000Z', 'complete': complete,
            'project': {'canonicalPath': str(self.workspace), 'key': self.key},
            'build': {'configDigest': image or self.image, 'success': True, 'exitCode': 0},
        })
        for path in (directory, directory.parent, directory.parent.parent, self.home / '.nosh'):
            path.chmod(0o700)
        return directory

    def test_build_capture_discovery_requires_exact_image_and_private_evidence(self):
        directory = self.build_capture()
        saved = module.build_profile_status(str(self.workspace), self.image)
        self.assertEqual(saved['status'], 'saved')
        self.assertEqual(saved['path'], str(directory))
        self.assertEqual(saved['imageDigest'], self.image)
        self.assertEqual(module.build_profile_status(str(self.workspace), 'sha256:' + 'b' * 64)['status'], 'missing')
        manifest = directory / 'evidence-manifest.json'
        manifest.chmod(0o644)
        self.assertEqual(module.build_profile_status(str(self.workspace), self.image)['status'], 'missing')
        manifest.chmod(0o600)
        directory.chmod(0o755)
        self.assertEqual(module.build_profile_status(str(self.workspace), self.image)['status'], 'missing')

    def test_build_capture_discovery_preserves_incomplete_state_and_rejects_foreign_workspace(self):
        directory = self.build_capture(complete=False)
        profile = module.build_profile_status(str(self.workspace), self.image)
        self.assertEqual(profile['status'], 'incomplete')
        self.assertEqual(profile['path'], str(directory))
        manifest = json.loads((directory / 'evidence-manifest.json').read_text())
        manifest['complete'] = True
        manifest['project']['canonicalPath'] = str(self.root / 'another-workspace')
        self.write(directory / 'evidence-manifest.json', manifest)
        self.assertEqual(module.build_profile_status(str(self.workspace), self.image)['status'], 'missing')

    def test_build_capture_discovery_does_not_follow_directory_symlinks(self):
        directory = self.build_capture()
        foreign = self.root / directory.name
        directory.rename(foreign)
        directory.symlink_to(foreign, target_is_directory=True)
        self.assertEqual(module.build_profile_status(str(self.workspace), self.image)['status'], 'missing')

    def test_review_must_match_current_learning_and_resolve_every_proposal(self):
        self.reviewed()
        self.assertEqual(self.detect()[0][5][0], 'saved')
        self.assertEqual(self.detect()[0][10][0], 'ready')
        self.assertEqual(self.detect()[0]['review:0'], (str(self.decision_file.parent.parent), self.decisions['contentDigest']))
        for entries in [[], [{'proposalId': 'one', 'disposition': 'needs-review'}],
                        [{'proposalId': 'other', 'disposition': 'accept'}]]:
            self.decisions['decisions'] = entries
            self.write(self.decision_file, self.decisions)
            self.assertEqual(self.detect()[0][5][0], 'draft')
            self.assertNotIn('review:0', self.detect()[0])

    def test_multiple_reviews_are_reported_and_foreign_session_paths_are_excluded(self):
        self.reviewed()
        import shutil
        first = self.decision_file.parent.parent
        second = first.parent / 'second'
        shutil.copytree(first, second)
        metadata = second / 'runtime/review-session.json'
        session = json.loads(metadata.read_text())
        # A copied receipt that still identifies another directory is not eligible.
        self.assertNotIn('review:1', self.detect()[0])
        session['directory'] = str(second)
        self.write(metadata, session)
        rows, _ = self.detect()
        self.assertEqual({rows['review:0'][0], rows['review:1'][0]}, {str(first), str(second)})
        session['revision'] = 'old-revision'
        self.write(metadata, session)
        self.assertNotIn('review:1', self.detect()[0])

    def test_missing_sboms_do_not_offer_saved_review_for_apply(self):
        self.reviewed()
        graph_file = self.decision_file.parent.parent / 'runtime/review.graph.json'
        graph = json.loads(graph_file.read_text())
        for coverage in ([], [{'domain': 'sbom-source', 'status': 'complete'}],
                         [{'domain': 'sbom-source', 'status': 'unavailable'},
                          {'domain': 'sbom-image', 'status': 'complete'}]):
            graph['coverage'] = coverage
            self.write(graph_file, graph)
            rows, _ = self.detect()
            self.assertEqual(rows[5][0], 'needs-sbom')
            self.assertNotIn('review:0', rows)

    def test_missing_saved_image_falls_back_to_local_nosh(self):
        self.learned()
        replacement = 'sha256:' + 'e' * 64
        self.inspect.side_effect = [None, (replacement, '1')]
        rows, _ = self.detect()
        self.assertEqual(rows['image'], (replacement, '1'))
        self.assertEqual(rows[4][0], 'stale')
        self.assertEqual(self.inspect.call_args_list[-1].args, ('nosh',))

    def test_corrupt_unsafe_or_symlinked_receipts_are_not_completed(self):
        self.learned()
        current = self.mirror / 'current.json'
        current.write_text('{broken')
        self.assertNotEqual(self.detect()[0][4][0], 'saved')
        self.write(current, self.receipt)
        current.chmod(0o644)
        self.assertNotEqual(self.detect()[0][4][0], 'saved')
        target = self.root / 'receipt'
        self.write(target, self.receipt)
        current.unlink()
        current.symlink_to(target)
        self.assertNotEqual(self.detect()[0][4][0], 'saved')

    def test_historical_applied_receipt_does_not_prove_activation(self):
        self.reviewed()
        self.write(self.decision_file.parent / 'applied.json', {'status': 'active'})
        self.assertEqual(self.detect()[0][7][0], 'unknown')

    def test_interrupted_learning_receipt_is_scoped_to_exact_revision_and_image(self):
        self.learned()
        record = {'revision': 'learn-1', 'imageDigest': self.image, 'exitCode': 137}
        self.write(self.mirror / 'wizard-learning.json', record)
        self.assertEqual(self.detect()[0][4][0], 'interrupted')
        record['revision'] = 'earlier'
        self.write(self.mirror / 'wizard-learning.json', record)
        self.assertEqual(self.detect()[0][4][0], 'saved')

    def test_verified_session_blockers_prevent_apply_suggestion(self):
        self.reviewed()
        metadata = self.decision_file.parent.parent / 'runtime/review-session.json'
        session = json.loads(metadata.read_text())
        session['readiness'] = {'readyForReview': False, 'blockers': [{'code': 'coverage'}]}
        self.write(metadata, session)
        rows, _ = self.detect()
        self.assertEqual(rows[5][0], 'blocked')
        self.assertEqual(rows[10][0], 'blocked')
        self.assertNotIn('review:0', rows)

    def test_fresh_inventory_prevents_old_completed_review_from_skipping_new_draft(self):
        self.reviewed()
        state = self.root / 'reviews'
        inventory = state / 'inventory-operation/data'
        digest = 'sha256:' + 'c' * 64
        self.write(state / ('inventory-' + self.key + '.json'), {'image': self.image, 'directory': str(inventory)})
        self.write(inventory / 'source.collection.json', {'role': 'source', 'status': 'complete',
                    'sbomDigest': 'sha256:' + 'f' * 64, 'input': {'metadataDigest': digest}})
        rows, _ = self.detect()
        self.assertEqual(rows[5][0], 'stale')
        self.assertNotIn('review:0', rows)
        graph_file = self.decision_file.parent.parent / 'runtime/review.graph.json'
        graph = json.loads(graph_file.read_text())
        graph['nodes'] = [{'nodeType': 'evidenceSource', 'identity': {'role': 'source'},
                          'properties': {'collection': {'input': {'metadataDigest': digest}}}}]
        self.write(graph_file, graph)
        self.assertEqual(self.detect()[0][5][0], 'saved')
        self.decision_file.unlink()
        self.assertEqual(self.detect()[0][5][0], 'draft')

    def test_inventory_completion_requires_matching_source_and_image_collections(self):
        state = self.root / 'reviews'
        inventory = state / 'inventory-operation/data'
        tooling = 'sha256:' + 'd' * 64
        self.write(state / ('inventory-' + self.key + '.json'), {
            'image': self.image, 'tooling': tooling, 'directory': str(inventory),
        })
        self.write(inventory / 'source.collection.json', {
            'role': 'source', 'status': 'complete', 'sbomDigest': 'sha256:' + 'e' * 64,
            'input': {'metadataDigest': 'sha256:' + 'f' * 64},
        })
        self.assertEqual(self.detect()[0][9][0], 'missing')
        self.write(inventory / 'image.collection.json', {
            'role': 'image', 'status': 'complete', 'sbomDigest': 'sha256:' + '1' * 64,
            'input': {'imageDigest': self.image},
        })
        self.assertEqual(self.detect()[0][9][0], 'saved')

    def test_updated_tooling_does_not_reuse_old_completed_review_with_identical_inventory(self):
        self.reviewed()
        state = self.root / 'reviews'
        inventory = state / 'inventory-operation/data'
        digest = 'sha256:' + 'c' * 64
        tooling = 'sha256:' + 'd' * 64
        self.write(state / ('inventory-' + self.key + '.json'),
                   {'image': self.image, 'tooling': tooling, 'directory': str(inventory)})
        self.write(inventory / 'source.collection.json', {'role': 'source', 'status': 'complete',
                   'sbomDigest': 'sha256:' + 'f' * 64, 'input': {'metadataDigest': digest}})
        graph_file = self.decision_file.parent.parent / 'runtime/review.graph.json'
        graph = json.loads(graph_file.read_text())
        graph['nodes'] = [{'nodeType': 'evidenceSource', 'identity': {'role': 'source'},
                          'properties': {'collection': {'input': {'metadataDigest': digest}}}}]
        self.write(graph_file, graph)
        metadata = graph_file.parent / 'review-session.json'
        session = json.loads(metadata.read_text())
        session['toolingImage'] = 'sha256:' + 'e' * 64
        self.write(metadata, session)
        rows, _ = self.detect()
        self.assertEqual(rows[5][0], 'stale')
        self.assertNotIn('review:0', rows)
        session['toolingImage'] = tooling
        self.write(metadata, session)
        self.assertEqual(self.detect()[0][5][0], 'saved')

    def test_signing_configuration_is_a_hint_not_host_trust_validation(self):
        keys = [self.root / name for name in ['review.pem', 'public.pem', 'deploy.pem']]
        for key in keys:
            key.write_text('contents are deliberately not parsed')
            key.chmod(0o600)
        config = dict(zip(['reviewPrivateKey', 'reviewPublicKey', 'deploymentPrivateKey'], map(str, keys)))
        config.update(reviewAudience='review', deploymentAudience='guard')
        self.write(Path(os.environ['NOSH_POLICY_APPLY_CONFIG']), config)
        rows, _ = self.detect()
        self.assertEqual(rows[6][0], 'configured')
        self.assertEqual(rows[7][0], 'unknown')
        keys[0].chmod(0o644)
        self.assertEqual(self.detect()[0][6][0], 'missing')

    def test_authoritative_status_must_match_workspace_image_revision(self):
        self.reviewed()
        authority = {'workload': 'dev', 'workspace': {'path': str(self.workspace)}, 'integrity': {'ok': True},
                     'activation': {'imageDigest': self.image, 'learnRevision': 'learn-1',
                                    'leafBundleDigest': 'sha256:' + 'd' * 64}}
        self.assertEqual(self.detect(authority)[0][7][0], 'active')
        authority['activation']['learnRevision'] = 'old'
        self.assertEqual(self.detect(authority)[0][7][0], 'different')
        authority['activation'] = None
        self.assertEqual(self.detect(authority)[0][7][0], 'inactive')
        authority['workspace']['path'] = '/another/workspace'
        self.assertEqual(self.detect(authority)[0][7][0], 'unknown')

    def test_ready_setup_suggests_apply_without_requiring_status_first(self):
        self.reviewed()
        binary = self.prefix / 'bin/nosh-guard'
        binary.parent.mkdir(parents=True)
        binary.write_text('')
        binary.chmod(0o755)
        launcher = self.workspace / 'scripts/nosh.sh'
        launcher.parent.mkdir(exist_ok=True)
        launcher.write_text('')
        launcher.chmod(0o755)
        config = self.home / '.config/nosh'
        config.mkdir(parents=True, exist_ok=True)
        paths = config / 'paths.conf'
        paths.write_text(f'NOSH_GUARD_PREFIX={self.prefix}\nNOSH_BIN={launcher}\n')
        paths.chmod(0o600)
        keys = [self.root / name for name in ['review.pem', 'public.pem', 'deploy.pem']]
        for key in keys:
            key.write_text('fixture')
            key.chmod(0o600)
        signing = dict(zip(['reviewPrivateKey', 'reviewPublicKey', 'deploymentPrivateKey'], map(str, keys)))
        signing.update(reviewAudience='review', deploymentAudience='guard')
        self.write(Path(os.environ['NOSH_POLICY_APPLY_CONFIG']), signing)
        rows, suggested = self.detect()
        self.assertEqual(rows[8][0], 'unchecked')
        self.assertEqual(suggested, 7)
        authority = {'workload': 'dev', 'workspace': {'path': str(self.workspace)}, 'integrity': {'ok': True},
                     'activation': {'imageDigest': self.image, 'learnRevision': 'learn-1',
                                    'leafBundleDigest': 'sha256:' + 'd' * 64}}
        self.assertEqual(self.detect(authority)[1], 8)

    def test_remote_docker_is_not_contacted(self):
        with patch.dict(os.environ, {'DOCKER_HOST': 'tcp://remote:2375'}), patch.object(module, 'command') as command:
            self.assertIsNone(real_inspect_image('nosh'))
            command.assert_not_called()

    def test_ipv6_readiness_reports_failures_and_ra_remediation(self):
        values = {
            'net.ipv6.conf.all.disable_ipv6': '0',
            'net.ipv6.conf.all.forwarding': '0',
            'net.ipv6.conf.eth0.accept_ra': '1',
        }
        with patch.object(module, 'read_sysctl', side_effect=lambda name: values.get(name)), \
                patch.object(module, 'command', return_value='default via fe80::1 dev eth0 proto ra metric 100'):
            status = module.ipv6_routing_status()
        self.assertEqual(status['status'], 'blocked')
        self.assertEqual(status['routeInterface'], 'eth0')
        self.assertTrue(status['routeUsesRouterAdvertisements'])
        checks = {item['key']: item for item in status['checks']}
        self.assertEqual(checks['ipv6-forwarding']['status'], 'fail')
        self.assertIn('forwarding=1', checks['ipv6-forwarding']['remediation'])
        self.assertEqual(checks['ipv6-router-advertisements']['status'], 'warning')
        self.assertIn('eth0.accept_ra=2', checks['ipv6-router-advertisements']['remediation'])

    def test_ipv6_readiness_accepts_forwarding_and_non_loopback_default(self):
        values = {
            'net.ipv6.conf.all.disable_ipv6': '0',
            'net.ipv6.conf.all.forwarding': '1',
            'net.ipv6.conf.enp1s0.accept_ra': '2',
        }
        with patch.object(module, 'read_sysctl', side_effect=lambda name: values.get(name)), \
                patch.object(module, 'command', return_value='default via fe80::1 dev enp1s0 proto ra'):
            status = module.ipv6_routing_status()
        self.assertEqual(status['status'], 'ready')
        self.assertTrue(all(item['status'] == 'pass' for item in status['checks']))

    def test_ipv6_readiness_rejects_an_unsafe_route_interface(self):
        values = {
            'net.ipv6.conf.all.disable_ipv6': '0',
            'net.ipv6.conf.all.forwarding': '1',
        }
        with patch.object(module, 'read_sysctl', side_effect=lambda name: values.get(name)), \
                patch.object(module, 'command', return_value='default dev ../../status proto ra'):
            status = module.ipv6_routing_status()
        self.assertEqual(status['status'], 'blocked')
        self.assertIsNone(status['routeInterface'])
        self.assertNotIn('ipv6-router-advertisements',
                         {item['key'] for item in status['checks']})

    def test_policy_tooling_status_reads_a_private_exact_local_identity(self):
        image = 'sha256:' + '9' * 64
        path = self.root / 'images.conf'
        path.write_text(
            f'SCHEMA_VERSION=1\nNOSH_POLICY_TOOLING_IMAGE={image}\n'
            'NOSH_POLICY_REVIEW_UI_IMAGE=\n')
        path.chmod(0o600)
        with patch.dict(os.environ, {'DOCKER_HOST': 'unix:///run/docker.sock'}), \
                patch.object(module, 'command', return_value=f'{image}|1'):
            status = module.policy_tooling_status(path)
        self.assertEqual(status['status'], 'ready')
        self.assertEqual(status['imageId'], image)
        path.write_text(f'SCHEMA_VERSION=1\nNOSH_POLICY_TOOLING_IMAGE={image}\n')
        self.assertEqual(module.policy_tooling_status(path)['status'], 'invalid')


if __name__ == '__main__':
    unittest.main()
