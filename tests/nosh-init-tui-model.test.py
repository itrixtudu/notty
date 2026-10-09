#!/usr/bin/env python3
import importlib.util
import json
from pathlib import Path
import tempfile
import sys
import unittest


ROOT = Path(__file__).parents[1]
SPEC = importlib.util.spec_from_file_location('nosh_init_model', ROOT / 'scripts/nosh_init_model.py')
MODEL = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODEL
SPEC.loader.exec_module(MODEL)


class InitTuiModelTest(unittest.TestCase):
    def test_discovers_only_runner_dockerfiles(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'Dockerfile.nosh').write_text('FROM example\n')
            (root / 'Dockerfile.nosh-zig').write_text(
                'ARG NOSH_IMAGE=nosh:latest\nFROM ${NOSH_IMAGE}\n')
            (root / 'Dockerfile.nosh-egress').write_text('FROM node\n')
            (root / 'Dockerfile.nosh-bad').symlink_to(root / 'Dockerfile.nosh-zig')
            self.assertEqual([item.name for item in MODEL.discover_images(root)], ['nosh', 'nosh-zig'])

    def test_queue_orders_base_before_derived_and_policy_lanes(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            base = MODEL.ImageChoice('nosh', root / 'Dockerfile.nosh', True)
            zig = MODEL.ImageChoice('nosh-zig', root / 'Dockerfile.nosh-zig', False)
            state = {
                'host': {
                    'guard': {'status': 'present'},
                    'launchers': {'status': 'configured'},
                    'reviewNetwork': {'status': 'configured'},
                    'signing': {'status': 'configured'},
                },
                'workloads': {},
            }
            queue = MODEL.build_queue(
                repo=root, workspace=root, guard_prefix=Path('/opt/notty'),
                images=[base, zig], selected={'nosh-zig'}, build_profiles={'nosh-zig'},
                dev_profiles={'nosh-zig'}, run_profiles=set(), tools=True, state=state,
                dev_options=('--agents', 'codex'), tool_report='/tmp/report',
                tool_digest='sha256:' + 'a' * 64,
            )
            keys = [item.key for item in queue]
            self.assertEqual(keys[:3], ['host:tooling', 'image:nosh', 'build-profile:nosh-zig'])
            self.assertLess(keys.index('dev:learn:nosh-zig'), keys.index('dev:review:nosh-zig'))
            self.assertLess(keys.index('dev:review:nosh-zig'), keys.index('dev:apply:nosh-zig'))
            learn = next(item for item in queue if item.key == 'dev:learn:nosh-zig')
            self.assertEqual(learn.argv[-2:], ('--agents', 'codex'))
            apply_tools = next(item for item in queue if item.key == 'tools:tools-apply')
            self.assertIn('/tmp/report', apply_tools.argv)
            self.assertIn('sha256:' + 'a' * 64, apply_tools.argv)
            self.assertEqual(keys[-5:], [
                'tools:tools-init', 'tools:tools-review', 'tools:tools-check',
                'tools:tools-apply', 'tools:tools-status',
            ])
            for action in queue:
                self.assertIsInstance(action.argv, tuple)

    def test_build_review_is_never_an_apply_action(self):
        image = MODEL.ImageChoice('nosh', ROOT / 'Dockerfile.nosh', True, 'available', 'sha256:x', '1')
        queue = MODEL.build_queue(
            repo=ROOT, workspace=ROOT, guard_prefix=Path('/opt/notty'), images=[image],
            selected={'nosh'}, build_profiles={'nosh'}, dev_profiles=set(), run_profiles=set(),
            tools=False, state={'host': {'guard': {'status': 'present'},
                                          'launchers': {'status': 'configured'},
                                          'reviewNetwork': {'status': 'configured'},
                                          'signing': {'status': 'configured'}}},
        )
        self.assertEqual([action.key for action in queue], ['host:tooling', 'build-profile:nosh'])
        self.assertIn('not a runtime activation', queue[1].detail)

    def test_wizard_keeps_completed_pending_blocked_and_skipped_steps_visible(self):
        image = MODEL.ImageChoice('nosh', ROOT / 'Dockerfile.nosh', True,
                                  'available', 'sha256:' + 'a' * 64, '1')
        state = {
            'host': {
                'guard': {'status': 'present', 'detail': 'installed'},
                'launchers': {'status': 'configured', 'detail': 'configured'},
                'reviewNetwork': {'status': 'configured', 'detail': '10.0.0.0/26'},
                'signing': {'status': 'missing', 'detail': 'not configured'},
                'policyTooling': {'status': 'ready', 'detail': 'exact image ready'},
                'runtimeNetwork': {'status': 'blocked', 'detail': 'IPv6 forwarding is disabled'},
            },
            'workloads': {'nosh': {'dev': {'steps': {
                'inventory': {'status': 'missing', 'detail': 'missing'},
                'learn': {'status': 'missing', 'detail': 'missing'},
                'prepare': {'status': 'blocked', 'detail': 'unresolved evidence blockers'},
                'review': {'status': 'missing', 'detail': 'missing'},
                'activation': {'status': 'unknown', 'detail': 'unchecked'},
                'authority': {'status': 'unchecked', 'detail': 'unchecked'},
            }}}},
        }
        steps = MODEL.build_steps(
            repo=ROOT, workspace=ROOT, guard_prefix=Path('/opt/notty'), images=[image],
            selected={'nosh'}, build_profiles=set(), dev_profiles={'nosh'}, run_profiles=set(),
            tools=False, state=state, choices_confirmed=True,
        )
        by_key = {step.key: step for step in steps}
        self.assertEqual(by_key['project:choices'].status, 'complete')
        self.assertEqual(by_key['host:guard'].status, 'complete')
        self.assertEqual(by_key['host:signing'].status, 'pending')
        self.assertEqual(by_key[f'readiness:nosh:{image.image_id}'].status, 'blocked')
        self.assertEqual(by_key['dev:prepare:nosh'].status, 'blocked')
        self.assertEqual(by_key['run:disabled'].status, 'skipped')
        self.assertEqual(by_key['tools:disabled'].status, 'skipped')
        self.assertEqual(by_key['finish'].status, 'pending')

    def test_session_verified_steps_complete_without_claiming_durable_receipts(self):
        image = MODEL.ImageChoice('nosh', ROOT / 'Dockerfile.nosh', True,
                                  'available', 'sha256:' + 'a' * 64, '1')
        state = {
            'host': {
                'guard': {'status': 'present'}, 'launchers': {'status': 'configured'},
                'reviewNetwork': {'status': 'configured'}, 'signing': {'status': 'configured'},
                'policyTooling': {'status': 'ready'},
                'runtimeNetwork': {'status': 'ready', 'detail': 'ready'},
            },
            'workloads': {'nosh': {'dev': {'steps': {}}}},
        }
        readiness = f'readiness:nosh:{image.image_id}'
        steps = MODEL.build_steps(
            repo=ROOT, workspace=ROOT, guard_prefix=Path('/opt/notty'), images=[image],
            selected={'nosh'}, build_profiles=set(), dev_profiles={'nosh'}, run_profiles=set(),
            tools=False, state=state, choices_confirmed=True,
            session_results={readiness: 'complete', 'dev:status:nosh': 'complete'},
        )
        by_key = {step.key: step for step in steps}
        self.assertEqual(by_key[readiness].status, 'complete')
        self.assertEqual(by_key['dev:status:nosh'].status, 'complete')
        self.assertEqual(by_key['dev:learn:nosh'].status, 'pending')

    def test_finish_and_tool_verification_require_current_verified_state(self):
        qemu_arguments = {
            'repo': ROOT, 'workspace': ROOT, 'guard_prefix': Path('/opt/notty'),
            'images': [], 'selected': set(), 'build_profiles': set(),
            'dev_profiles': set(), 'run_profiles': set(), 'tools': False,
            'state': {'host': {'launchers': {'status': 'configured'}}},
            'environments': {'qemu'}, 'choices_confirmed': True,
        }
        complete = MODEL.build_steps(
            **qemu_arguments,
            session_results={'qemu:start': 'complete', 'qemu:status': 'complete',
                             'finish': 'complete'},
        )
        self.assertEqual(complete[-1].status, 'complete')
        regressed = MODEL.build_steps(
            **qemu_arguments,
            session_results={'qemu:start': 'complete', 'qemu:status': 'failed',
                             'finish': 'complete'},
        )
        self.assertEqual(regressed[-1].status, 'pending')

        tool_state = {
            'host': {
                'guard': {'status': 'present'}, 'launchers': {'status': 'configured'},
                'reviewNetwork': {'status': 'configured'}, 'policyTooling': {'status': 'ready'},
            },
            'tools': {'status': 'active', 'detail': 'active'},
        }
        tool_arguments = {
            'repo': ROOT, 'workspace': ROOT, 'guard_prefix': Path('/opt/notty'),
            'images': [], 'selected': set(), 'build_profiles': set(),
            'dev_profiles': set(), 'run_profiles': set(), 'tools': True,
            'state': tool_state, 'choices_confirmed': True,
        }
        steps = {step.key: step for step in MODEL.build_steps(**tool_arguments)}
        self.assertEqual(steps['tools:tools-apply'].status, 'complete')
        self.assertEqual(steps['tools:tools-status'].status, 'pending')
        verified = {step.key: step for step in MODEL.build_steps(
            **tool_arguments, session_results={'tools:tools-status': 'complete'})}
        self.assertEqual(verified['tools:tools-status'].status, 'complete')

    def test_environments_can_select_qemu_alone_or_with_docker(self):
        image = MODEL.ImageChoice('nosh', ROOT / 'Dockerfile.nosh', True, 'available', 'sha256:x', '1')
        state = {'host': {'guard': {'status': 'present'}, 'launchers': {'status': 'configured'},
                          'reviewNetwork': {'status': 'configured'}, 'signing': {'status': 'configured'}},
                 'workloads': {}}
        qemu = MODEL.build_queue(
            repo=ROOT, workspace=ROOT, guard_prefix=Path('/opt/notty'), images=[image],
            selected={'nosh'}, build_profiles=set(), dev_profiles={'nosh'}, run_profiles=set(),
            tools=True, state=state, environments={'qemu'},
        )
        self.assertEqual([action.key for action in qemu], ['qemu:start', 'qemu:status'])
        both = MODEL.build_queue(
            repo=ROOT, workspace=ROOT, guard_prefix=Path('/opt/notty'), images=[image],
            selected={'nosh'}, build_profiles=set(), dev_profiles={'nosh'}, run_profiles=set(),
            tools=False, state=state, environments={'docker', 'qemu'},
        )
        keys = [action.key for action in both]
        self.assertIn('dev:learn:nosh', keys)
        self.assertEqual(keys[-2:], ['qemu:start', 'qemu:status'])

    def test_project_manifest_round_trips_portable_policy_references(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            dockerfile = root / 'Dockerfile.nosh-zig'
            dockerfile.write_text('ARG NOSH_IMAGE=nosh:latest\nFROM ${NOSH_IMAGE}\n')
            image_digest = 'sha256:' + '1' * 64
            decision_digest = 'sha256:' + '2' * 64
            tool_digest = 'sha256:' + '3' * 64
            image = MODEL.ImageChoice('nosh-zig', dockerfile, False, 'available', image_digest, '1')
            state = {
                'workloads': {'nosh-zig': {'dev': {
                    'revision': 'learn-17',
                    'reviews': [{'path': '/private/host/review',
                                 'decisionDigest': decision_digest}],
                }}},
                'tools': {'policyDigest': tool_digest, 'detail': '/private/tool/report'},
            }
            document = MODEL.project_manifest(
                workspace=root, environments={'docker', 'qemu'}, images=[image],
                selected={'nosh-zig'}, build_profiles={'nosh-zig'},
                dev_profiles={'nosh-zig'}, run_profiles=set(), tools=True,
                preflight=True, state=state,
            )
            path = MODEL.save_project_manifest(root, document)
            loaded = MODEL.load_project_manifest(root)
            self.assertEqual(loaded, document)
            self.assertEqual(loaded['images'][0]['dockerfile'], 'Dockerfile.nosh-zig')
            reference = loaded['policyReferences']['runtime'][0]
            self.assertEqual(reference['imageDigest'], image_digest)
            self.assertEqual(reference['learnRevision'], 'learn-17')
            self.assertEqual(reference['decisionDigests'], [decision_digest])
            self.assertEqual(loaded['policyReferences']['toolPolicyDigest'], tool_digest)
            encoded = path.read_text()
            self.assertNotIn('/private/', encoded)
            self.assertNotIn(str(root), encoded)

    def test_project_manifest_rejects_unsafe_or_unknown_content(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / '.nosh/project.json'
            target.parent.mkdir()
            invalid = {
                'schemaVersion': 1, 'kind': 'NoshProject',
                'environments': ['docker'],
                'images': [{'name': 'nosh', 'dockerfile': '/tmp/Dockerfile',
                            'buildNetwork': False, 'dev': True, 'run': False}],
                'toolProfiling': False, 'preflight': False,
                'policyReferences': {'runtime': []},
            }
            target.write_text(json.dumps(invalid))
            with self.assertRaisesRegex(ValueError, 'relative paths'):
                MODEL.load_project_manifest(root)
            invalid['images'][0]['dockerfile'] = 'Dockerfile.nosh'
            invalid['secret'] = 'must not be accepted'
            target.write_text(json.dumps(invalid))
            with self.assertRaisesRegex(ValueError, 'unknown'):
                MODEL.load_project_manifest(root)

    def test_project_manifest_does_not_follow_manifest_symlink(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            nosh = root / '.nosh'
            nosh.mkdir()
            outside = root / 'outside.json'
            outside.write_text('{}')
            (nosh / 'project.json').symlink_to(outside)
            with self.assertRaisesRegex(ValueError, 'unsafe'):
                MODEL.save_project_manifest(root, {})


class SingleImageGuidedModelTest(unittest.TestCase):
    def setUp(self):
        self.image = MODEL.ImageChoice('nosh', ROOT / 'Dockerfile.nosh', True,
                                       'available', 'sha256:' + 'a' * 64, '1')
        self.state = {
            'host': {
                'guard': {'status': 'present'}, 'launchers': {'status': 'configured'},
                'policyTooling': {'status': 'ready'}, 'reviewNetwork': {'status': 'configured'},
                'signing': {'status': 'configured'}, 'runtimeNetwork': {'status': 'ready'},
            },
            'workloads': {'nosh': {'dev': {'revision': 'learn-one', 'steps': {}},
                                    'run': {'revision': 'run-one', 'steps': {}}}},
            'images': [],
        }

    def pages(self, **kwargs):
        arguments = dict(repo=ROOT, workspace=ROOT, guard_prefix=Path('/opt/notty'),
                         image=self.image, images=[self.image], state=self.state,
                         build_mode='reuse', stage_choices={'dev': True, 'run': False})
        arguments.update(kwargs)
        return {page.key: page for page in MODEL.build_guided_pages(**arguments)}

    def ready(self):
        page = self.pages()['readiness:nosh']
        return {'readiness:nosh': MODEL.guided_result(page, 'complete')}

    def test_single_image_starts_with_selection_and_unrequested_stages(self):
        self.assertEqual(list(self.pages(image=None)), ['image:choose'])
        pages = self.pages(stage_choices={}, build_mode=None)
        self.assertEqual(list(pages), ['image:choose', 'build:choice', 'dev:learn:nosh',
                                      'run:learn:nosh', 'finish'])
        self.assertEqual(pages['dev:learn:nosh'].kind, 'recording')
        self.assertNotIn('host:guard', pages)
        self.assertNotIn('dev:results:nosh', pages)
        requested = self.pages()
        self.assertLess(list(requested).index('dev:learn:nosh'), list(requested).index('host:guard'))

    def test_capture_builds_selected_image_once_and_only_base_as_dependency(self):
        derived = MODEL.ImageChoice('nosh-zig', ROOT / 'Dockerfile.nosh-zig', False)
        pages = self.pages(image=derived, images=[self.image, derived], build_mode='capture',
                           stage_choices={})
        builds = [page for page in pages.values() if page.key.startswith('build:execute:')]
        self.assertEqual(len(builds), 1)
        self.assertIn('learn', builds[0].argv)
        self.assertIn('nosh-zig', builds[0].argv)
        self.assertEqual(pages['build:base:nosh'].status, 'complete')
        self.assertNotIn('dev:results:nosh', pages)
        self.assertNotIn('run:results:nosh', pages)
        base_capture = self.pages(build_mode='capture')['build:execute:nosh']
        self.assertEqual(base_capture.argv[-3:], ('net', 'learn', '--no-review'))
        self.assertNotIn('host:tooling', base_capture.dependencies)
        self.assertIn('Shai-Hulud', base_capture.detail)
        self.assertIn('does not automatically detect or block malware', base_capture.detail)

    def test_skipping_recording_skips_its_dependents_but_run_remains_independent(self):
        pages = self.pages(stage_choices={'dev': True, 'run': True},
                           session_results=self.ready(), skipped={'dev:learn:nosh'})
        self.assertEqual(pages['dev:learn:nosh'].status, 'skipped')
        for action in ('results', 'prepare', 'review', 'apply', 'status'):
            self.assertNotIn(f'dev:{action}:nosh', pages)
        self.assertEqual(pages['run:learn:nosh'].status, 'pending')
        self.assertTrue(pages['run:learn:nosh'].can_execute)
        self.assertIn('Development requested but unfinished', pages['finish'].evidence)

    def test_skipped_recording_defers_shared_setup_until_requested_run(self):
        pages = self.pages(session_results=self.ready(), skipped={'dev:learn:nosh'})
        prerequisites = ('host:tooling', 'host:network', 'inventory:nosh', 'host:signing')
        for key in prerequisites:
            self.assertNotIn(key, pages)
        pages = self.pages(stage_choices={'dev': True, 'run': True},
                           session_results=self.ready(), skipped={'dev:learn:nosh'})
        keys = list(pages)
        for key in prerequisites:
            self.assertGreater(keys.index(key), keys.index('run:learn:nosh'))
            self.assertEqual(pages[key].phase, 'Application runtime (Run)')
        self.assertIn('run', pages['inventory:nosh'].argv)

    def test_skipped_rebuild_keeps_compatible_existing_image_usable(self):
        pages = self.pages(build_mode='build', session_results=self.ready(),
                           skipped={'build:execute:nosh'})
        self.assertEqual(pages['build:execute:nosh'].status, 'skipped')
        self.assertEqual(pages['readiness:nosh'].status, 'complete')
        self.assertTrue(pages['dev:learn:nosh'].can_execute)
        self.assertIn('Build skipped; requested build unfinished', pages['finish'].evidence)

    def test_skipping_build_without_a_local_image_skips_runtime_dependencies(self):
        missing = MODEL.ImageChoice('nosh', self.image.dockerfile, True)
        pages = self.pages(image=missing, build_mode='skip')
        self.assertEqual(pages['build:choice'].status, 'complete')
        self.assertEqual(pages['readiness:nosh'].status, 'skipped')
        self.assertEqual(pages['dev:learn:nosh'].status, 'skipped')
        self.assertFalse(pages['dev:learn:nosh'].can_execute)

    def test_missing_external_dockerfile_cannot_schedule_a_build(self):
        external = MODEL.ImageChoice('nosh-external', Path('.'), False)
        pages = self.pages(image=external, build_mode='capture')
        self.assertEqual(pages['build:execute:nosh-external'].status, 'blocked')
        self.assertFalse(pages['build:execute:nosh-external'].can_execute)
        self.assertEqual(pages['build:execute:nosh-external'].argv, ())

    def test_saved_recording_is_retained_but_skipping_omits_remaining_workload_actions(self):
        self.state['workloads']['nosh']['dev']['steps'] = {
            'learn': {'status': 'saved'}, 'inventory': {'status': 'saved'}}
        pages = self.pages(skipped={'dev:learn:nosh'})
        self.assertEqual(pages['dev:learn:nosh'].status, 'complete')
        for action in ('results', 'prepare', 'review', 'apply', 'status'):
            self.assertNotIn(f'dev:{action}:nosh', pages)
        self.assertIn('Development recording skipped', pages['finish'].evidence)
        pages = self.pages()
        self.assertEqual(pages['dev:prepare:nosh'].status, 'pending')
        self.assertTrue(pages['dev:prepare:nosh'].can_execute)
        self.assertEqual(pages['run:learn:nosh'].kind, 'recording')
        self.assertNotIn('run:results:nosh', pages)

    def test_transient_success_is_bound_to_image_workload_and_revision(self):
        pages = self.pages()
        results = self.ready()
        results['dev:status:nosh'] = MODEL.guided_result(pages['dev:status:nosh'], 'complete')
        results['dev:apply:nosh'] = MODEL.guided_result(pages['dev:apply:nosh'], 'complete')
        self.assertEqual(self.pages(session_results=results)['dev:status:nosh'].status, 'complete')
        self.state['workloads']['nosh']['dev']['reviews'] = [{'decisionDigest': 'sha256:' + 'c' * 64}]
        self.assertNotEqual(self.pages(session_results=results)['dev:status:nosh'].status, 'complete')
        self.state['workloads']['nosh']['dev']['reviews'] = []
        self.state['workloads']['nosh']['dev']['revision'] = 'learn-two'
        changed = self.pages(session_results=results)
        self.assertNotEqual(changed['dev:status:nosh'].status, 'complete')
        self.assertEqual(changed['readiness:nosh'].status, 'complete')
        rebuilt = MODEL.ImageChoice('nosh', self.image.dockerfile, True,
                                     'available', 'sha256:' + 'b' * 64, '1')
        changed = self.pages(image=rebuilt, session_results=results)
        self.assertNotEqual(changed['readiness:nosh'].status, 'complete')
        self.assertNotEqual(changed['dev:status:nosh'].status, 'complete')

    def test_live_network_regression_overrides_earlier_readiness_success(self):
        results = self.ready()
        self.state['host']['runtimeNetwork'] = {'status': 'blocked', 'detail': 'forwarding disabled'}
        pages = self.pages(session_results=results)
        self.assertEqual(pages['readiness:nosh'].status, 'blocked')
        self.assertTrue(pages['readiness:nosh'].can_execute)
        self.assertFalse(pages['dev:learn:nosh'].can_execute)

    def test_recheck_prefers_current_durable_success_over_a_previous_failure(self):
        self.state['host']['signing'] = {'status': 'missing'}
        failed = {'host:signing': MODEL.guided_result(self.pages()['host:signing'], 'failed')}
        self.assertEqual(self.pages(session_results=failed)['host:signing'].status, 'blocked')
        self.state['host']['signing'] = {'status': 'configured'}
        self.assertEqual(self.pages(session_results=failed)['host:signing'].status, 'complete')

    def test_review_and_recording_must_be_verified_not_just_successful_exit(self):
        pages = self.pages()
        results = {key: MODEL.guided_result(pages[key], 'complete')
                   for key in ('dev:learn:nosh', 'dev:review:nosh')}
        pages = self.pages(session_results=results)
        self.assertNotEqual(pages['dev:learn:nosh'].status, 'complete')
        self.assertNotEqual(pages['dev:review:nosh'].status, 'complete')
        self.assertFalse(pages['dev:apply:nosh'].can_execute)

    def test_capture_results_and_review_require_a_verified_matching_bundle(self):
        pages = self.pages(build_mode='capture', stage_choices={})
        completed = {'build:execute:nosh': MODEL.guided_result(pages['build:execute:nosh'], 'complete')}
        self.assertNotEqual(self.pages(build_mode='capture', session_results=completed)
                            ['build:execute:nosh'].status, 'complete')
        self.assertFalse(self.pages(build_mode='capture', session_results=completed)
                         ['build:review:nosh'].can_execute)
        self.state['images'] = [{'name': 'nosh', 'buildProfile': {
            'status': 'saved', 'path': '/private/build', 'runId': 'capture-one',
            'imageDigest': self.image.image_id}}]
        pages = self.pages(build_mode='capture', session_results=completed)
        self.assertEqual(pages['build:results:nosh'].status, 'complete')
        self.assertTrue(pages['build:review:nosh'].can_execute)
        self.assertIn('/private/build', pages['build:review:nosh'].argv)
        self.assertIn(f'NOSH_PROFILE_REVIEW_WORKDIR={ROOT}', pages['build:review:nosh'].argv)
        self.assertIn('Build complete with network recording', pages['finish'].evidence)

    def test_external_workspace_base_build_uses_its_dockerfile_and_context(self):
        with tempfile.TemporaryDirectory() as directory:
            workspace = Path(directory)
            dockerfile = workspace / 'Dockerfile.nosh'
            dockerfile.write_text('FROM scratch AS local\n')
            image = MODEL.ImageChoice('nosh', dockerfile, True)
            for mode in ('build', 'capture'):
                pages = self.pages(workspace=workspace, image=image, images=[image], build_mode=mode)
                argv = pages['build:execute:nosh'].argv
                self.assertIn(str(dockerfile), argv)
                self.assertEqual(argv[-1], str(workspace))
                self.assertNotIn(str(ROOT / 'scripts/build-nosh.sh'), argv)
                self.assertEqual(argv[argv.index('--target') + 1], 'local')
                self.assertTrue(any(value.startswith('USER_UID=') for value in argv))
                self.assertTrue(any(value.startswith('USER_GID=') for value in argv))

    def test_runtime_defaults_are_visible_in_delegated_command(self):
        pages = self.pages(stage_choices={'dev': True, 'run': True})
        self.assertIn('--no-start-app', pages['dev:learn:nosh'].argv)
        self.assertIn('--start-app', pages['run:learn:nosh'].argv)
        pages = self.pages(dev_options=('--agents', 'codex', '--start-app'),
                           network_options=('--review-pool', '10.20.0.0/24'))
        self.assertNotIn('--no-start-app', pages['dev:learn:nosh'].argv)
        self.assertEqual(pages['host:network'].argv[-2:], ('--review-pool', '10.20.0.0/24'))

    def test_manifest_merge_preserves_other_images_and_skipped_policy_references(self):
        derived = MODEL.ImageChoice('nosh-zig', ROOT / 'Dockerfile.nosh-zig', False)
        prior = MODEL.project_manifest(
            workspace=ROOT, environments={'qemu'}, images=[self.image, derived],
            selected={'nosh', 'nosh-zig'}, build_profiles=set(), dev_profiles={'nosh', 'nosh-zig'},
            run_profiles=set(), tools=True, preflight=True, state=self.state)
        merged = MODEL.guided_project_manifest(
            workspace=ROOT, image=self.image, build_mode='capture',
            stage_choices={'dev': False, 'run': False}, state=self.state, existing=prior)
        self.assertEqual(merged['environments'], ['docker', 'qemu'])
        self.assertTrue(merged['toolProfiling'])
        self.assertTrue(merged['preflight'])
        images = {entry['name']: entry for entry in merged['images']}
        self.assertTrue(images['nosh-zig']['dev'])
        self.assertFalse(images['nosh']['dev'])
        self.assertTrue(images['nosh']['buildNetwork'])
        self.assertEqual(merged['policyReferences'], prior['policyReferences'])
        self.assertTrue(prior['images'][0]['dev'], 'merge must not mutate the previous document')


if __name__ == '__main__':
    unittest.main()
