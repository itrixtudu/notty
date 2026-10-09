#!/usr/bin/env python3
"""Headless installer journeys; no Docker commands or workspace writes."""

import copy
import importlib.util
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

try:
    import textual
except ImportError:
    textual = None


ROOT = Path(__file__).parents[1]


@unittest.skipIf(textual is None or getattr(textual, '__version__', '') != '8.2.8',
                 'Textual 8.2.8 is installed only in the isolated host TUI venv')
class InitTuiTest(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        sys.path.insert(0, str(ROOT / 'scripts'))
        self.addCleanup(lambda: sys.path.remove(str(ROOT / 'scripts')))
        spec = importlib.util.spec_from_file_location('nosh_init_tui', ROOT / 'scripts/nosh-init-tui.py')
        self.module = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = self.module
        spec.loader.exec_module(self.module)
        choices = [self.module.ImageChoice('nosh', ROOT / 'Dockerfile.nosh', True),
                   self.module.ImageChoice('nosh-zig', ROOT / 'Dockerfile.nosh-zig', False)]
        for name, value in (('discover_images', choices), ('load_project_manifest', None)):
            mocked = patch.object(self.module, name, return_value=value)
            mocked.start()
            self.addCleanup(mocked.stop)

    def make_app(self, *, network_ready=True, saved_recording=False):
        fixture = {
            'schemaVersion': 1,
            'host': {
                'guard': {'status': 'present', 'detail': 'Installed'},
                'launchers': {'status': 'configured', 'detail': 'Configured'},
                'reviewNetwork': {'status': 'configured' if network_ready else 'missing', 'detail': ''},
                'signing': {'status': 'configured', 'detail': 'Configured'},
                'policyTooling': {'status': 'ready', 'detail': 'Ready'},
                'runtimeNetwork': {
                    'status': 'ready', 'detail': 'Dual-stack routing ready',
                    'checks': [{'key': 'ipv6-forwarding', 'label': 'IPv6 forwarding',
                                'status': 'pass', 'detail': 'forwarding=1'}],
                },
            },
            'images': [
                {'name': 'nosh', 'status': 'available', 'imageId': 'sha256:' + 'a' * 64, 'runnerAbi': '1'},
                {'name': 'nosh-zig', 'status': 'missing', 'imageId': '', 'runnerAbi': ''},
            ],
            'workloads': {
                name: {workload: {'steps': {}} for workload in ('dev', 'run')}
                for name in ('nosh', 'nosh-zig')
            },
        }
        if saved_recording:
            lane = fixture['workloads']['nosh']['dev']
            lane['revision'] = 'dev-saved'
            lane['steps'] = {key: {'status': status} for key, status in
                             (('learn', 'saved'), ('inventory', 'saved'), ('prepare', 'ready'))}

        class FixtureApp(self.module.NoshInitApp):
            def __init__(self):
                self.detected = copy.deepcopy(fixture)
                self.commands = []
                self.fail_codes = {}
                self.complete_reviews = True
                self.saved_count = 0
                super().__init__(repo=ROOT, workspace=ROOT, guard_prefix=Path('/opt/notty'))

            def load_state(self):
                return copy.deepcopy(self.detected)

            async def save_project(self):
                self.saved_count += 1
                return True

            async def execute_command(self, argv):
                key = self.page_key
                self.commands.append((key, argv))
                if key in self.fail_codes:
                    return self.fail_codes[key]
                name = self.guided_image_name
                if key.startswith('build:execute:'):
                    image = next(item for item in self.detected['images'] if item['name'] == name)
                    image.update(status='available', imageId='sha256:' + 'b' * 64, runnerAbi='1')
                    image['buildProfile'] = {'status': 'saved', 'path': '/tmp/build-evidence',
                                             'imageDigest': image['imageId'],
                                             'runId': 'build-1', 'detail': 'Recorded build connections'}
                elif key == 'host:network':
                    self.detected['host']['reviewNetwork']['status'] = 'configured'
                elif key in ('host:guard', 'host:setup'):
                    section, status = ('guard', 'present') if key == 'host:guard' else ('launchers', 'configured')
                    self.detected['host'][section]['status'] = status
                elif key.startswith(('dev:', 'run:')):
                    workload, step, _ = key.split(':')
                    lane = self.detected['workloads'][name][workload]
                    if step == 'learn':
                        lane['revision'] = workload + '-recorded'
                        lane['steps']['learn'] = {'status': 'saved'}
                    elif step == 'prepare':
                        lane['steps']['prepare'] = {'status': 'ready'}
                    elif step == 'review' and self.complete_reviews:
                        lane['steps']['review'] = {'status': 'saved'}
                    elif step in ('apply', 'status'):
                        lane['steps']['activation'] = {'status': 'active'}
                        if step == 'status':
                            lane['steps']['authority'] = {'status': 'checked'}
                elif key.startswith('inventory:'):
                    for lane in self.detected['workloads'][name].values():
                        lane['steps']['inventory'] = {'status': 'saved'}
                return 0

        return FixtureApp()

    async def click(self, pilot, selector):
        self.assertTrue(await pilot.click(selector), f'{selector} must be visible and clickable')
        await pilot.pause(0.35)

    async def next_until(self, app, pilot, target):
        for _ in range(30):
            if app.page_key == target:
                return
            self.assertFalse(app.query_one('#next').disabled,
                             f'Next unexpectedly disabled on {app.page_key}: {app.current_page.evidence}')
            before = app.page_key
            await self.click(pilot, '#next')
            self.assertNotEqual(app.page_key, before, f'Next did not leave {before}')
        self.fail(f'Never reached {target}; stopped at {app.page_key}')

    def assert_navigation_visible(self, app, *, height=30):
        for identifier in ('summary', 'next-effect', 'back', 'skip', 'next'):
            region = app.query_one('#' + identifier).region
            self.assertGreater(region.height, 0, identifier)
            self.assertGreaterEqual(region.y, 0, identifier)
            self.assertLessEqual(region.bottom, height, identifier)

    async def test_image_selection_and_existing_image_flow(self):
        app = self.make_app()
        async with app.run_test(size=(100, 30)) as pilot:
            await pilot.pause()
            self.assertFalse(app.advanced_mode)
            self.assertEqual(app.page_key, 'image:choose')
            self.assertEqual(len(app.query('#progress')), 0)
            self.assertFalse(app.query_one('#step-state').display)
            self.assertFalse(app.query_one('#step-evidence').display)
            self.assertEqual(len(app.query('#image-choice Label')), 0)
            self.assertIn('show build options', str(app.query_one('#next-effect').render()))
            self.assert_navigation_visible(app)
            context = app.query_one('#summary').render()
            self.assertIn('Workspace:', str(context))
            self.assertIn('Image:', str(context))
            self.assertIn('Policy:', str(context))
            self.assertTrue(any('cyan' in str(span.style) and 'bold' in str(span.style)
                                for span in context.spans))
            self.assertTrue(any('magenta' in str(span.style) and 'bold' in str(span.style)
                                for span in context.spans))

            app.set_focus(None)
            await pilot.press('space', 'b', 'd', 'r')
            await pilot.pause()
            self.assertEqual(app.page_key, 'image:choose')
            self.assertEqual(app.selected, set())
            self.assertEqual(app.stage_choices, {'dev': None, 'run': None})
            app.query_one('#image-select').focus()
            await pilot.press('space')
            await pilot.pause()
            self.assertTrue(app.query_one('#image-select').expanded)
            await pilot.press('escape')
            await self.next_until(app, pilot, 'build:choice')
            self.assertEqual(app.guided_image_name, 'nosh')
            self.assertTrue(app.query_one('#step-state').display)
            self.assertTrue(app.query_one('#build-reuse').value)
            description = str(app.query_one('#build-capture-help').render())
            self.assertIn('Shai-Hulud', description)
            self.assertIn('CI/CD', description)
            self.assertIn('does not automatically detect or block malware', description)
            self.assertIn('does not prove the image is safe', description)
            self.assert_navigation_visible(app)
            self.assertLess(app.query_one('#build-options').region.bottom,
                            app.query_one('#navigation').region.y)
            app.query_one('#build-options').focus()
            await pilot.press('down', 'space')
            await pilot.pause()
            self.assertTrue(app.query_one('#build-plain').value)
            await pilot.press('up', 'space')
            await pilot.pause()
            self.assertTrue(app.query_one('#build-reuse').value)
            await self.next_until(app, pilot, 'dev:learn:nosh')
            self.assertEqual(app.commands, [])
            await self.click(pilot, '#skip')
            self.assertEqual(app.page_key, 'run:learn:nosh')
            self.assertFalse(app.stage_choices['dev'])
            await self.click(pilot, '#skip')
            self.assertEqual(app.page_key, 'finish')
            self.assertIn('Development not requested', app.current_page.evidence)
            self.assertIn('Run not requested', app.current_page.evidence)
            self.assertEqual(app.current_page.label, 'Setup ready')
            self.assert_navigation_visible(app)
            await self.click(pilot, '#next')
            self.assertTrue(app.saved_finish)
            await self.click(pilot, '#back')
            self.assertEqual(app.page_key, 'run:learn:nosh')
            self.assertEqual(app.commands, [])
            await self.click(pilot, '#next')
            self.assertFalse(app.saved_finish)

    async def test_guided_navigation_hotkeys_and_advanced_shortcuts(self):
        app = self.make_app()
        async with app.run_test(size=(100, 30)) as pilot:
            await pilot.pause()
            for key, action in (('n', 'next_step'), ('p', 'previous_step'), ('s', 'skip_step')):
                self.assertEqual(app.screen.active_bindings[key].binding.action, action)
            await pilot.press('n')
            await pilot.pause()
            self.assertEqual(app.page_key, 'build:choice')
            await pilot.press('p')
            await pilot.pause()
            self.assertEqual(app.page_key, 'image:choose')
            await pilot.press('N')
            await pilot.pause()
            self.assertEqual(app.page_key, 'build:choice')
            await pilot.press('P')
            await pilot.pause()
            self.assertEqual(app.page_key, 'image:choose')
            await pilot.press('n')
            await pilot.pause()
            await pilot.press('n')
            await pilot.pause()
            self.assertEqual(app.page_key, 'dev:learn:nosh')
            await pilot.press('s')
            await pilot.pause()
            self.assertEqual(app.page_key, 'run:learn:nosh')
            await pilot.press('S')
            await pilot.pause()
            self.assertEqual(app.page_key, 'finish')
            self.assertEqual(app.saved_count, 0)
            self.assertEqual(app.commands, [])
            await pilot.press('a')
            await pilot.pause()
            self.assertTrue(app.advanced_mode)
            self.assertEqual(app.screen.active_bindings['p'].binding.action, 'toggle_preflight')
            self.assertEqual(app.screen.active_bindings['s'].binding.action, 'save_project')
            await pilot.press('p', 's')
            await pilot.pause()
            self.assertTrue(app.preflight)
            self.assertEqual(app.saved_count, 1)
            await pilot.press('escape')
            await pilot.pause()
            self.assertFalse(app.advanced_mode)
            self.assertEqual(app.screen.active_bindings['p'].binding.action, 'previous_step')

    async def test_build_capture_risk_phrases_are_red_on_both_pages(self):
        app = self.make_app()
        async with app.run_test(size=(100, 30)) as pilot:
            await pilot.pause()
            await self.next_until(app, pilot, 'build:choice')
            app.build_mode = 'capture'
            app.render_state()
            for selector in ('#build-capture-help', '#step-detail'):
                if selector == '#step-detail':
                    app.set_page('build:execute:nosh')
                    await pilot.pause()
                description = app.query_one(selector).render()
                red_phrases = [description.plain[span.start:span.end]
                               for span in description.spans
                               if span.style.bold and span.style.foreground.ansi == 1]
                self.assertEqual(red_phrases, [
                    'supply-chain attacks', 'secret-stealing code', 'malware detection',
                    '!!!Malicious traffic can still succeed!!!',
                ])
                self.assertNotIn('[red]', description.plain)
                self.assert_navigation_visible(app)
            self.assertEqual(app.commands, [])

    async def test_run_is_independent_and_previous_does_not_repeat_actions(self):
        app = self.make_app()
        async with app.run_test(size=(100, 30)) as pilot:
            await pilot.pause()
            await self.next_until(app, pilot, 'dev:learn:nosh')
            await self.click(pilot, '#skip')
            self.assertEqual(app.page_key, 'run:learn:nosh')
            self.assertTrue(app.query_one('#start-app').value)
            self.assertIn('--start-app', app.command_for(app.current_page))
            app.query_one('#start-app').focus()
            await pilot.press('space')
            await pilot.pause()
            self.assertFalse(app.query_one('#start-app').value)
            self.assertIn('--no-start-app', app.command_for(app.current_page))
            await self.click(pilot, '#next')
            self.assertEqual(app.page_key, 'readiness:nosh')
            self.assertTrue(app.stage_choices['run'])
            self.assertFalse(app.stage_choices['dev'])
            self.assertIn('forwarding=1', app.page_evidence(app.current_page))
            self.assert_navigation_visible(app)
            await self.click(pilot, '#next')
            self.assertEqual(app.page_key, 'run:results:nosh')
            self.assertEqual([key for key, _ in app.commands], ['readiness:nosh', 'run:learn:nosh'])
            await self.click(pilot, '#back')
            self.assertEqual(app.page_key, 'run:learn:nosh')
            await self.click(pilot, '#next')
            self.assertEqual(len(app.commands), 2)
            await self.next_until(app, pilot, 'finish')
            self.assertIn('Run ready', app.current_page.evidence)
            self.assertIn('Development not requested', app.current_page.evidence)
            self.assertFalse(any(key.startswith('dev:') for key, _ in app.commands))
            await self.click(pilot, '#next')
            self.assertEqual(app.saved_count, 1)
            self.assertEqual(str(app.query_one('#next').label), 'Close')

    async def test_new_image_capture_builds_once_and_another_image_resets_state(self):
        app = self.make_app()
        async with app.run_test(size=(100, 30)) as pilot:
            await pilot.pause()
            app.query_one('#image-select').focus()
            await pilot.press('space', 'end', 'enter')
            await pilot.pause()
            self.assertEqual(app.candidate_image_name, 'nosh-zig')
            await self.next_until(app, pilot, 'build:choice')
            self.assertTrue(app.query_one('#build-reuse').disabled)
            self.assertTrue(app.query_one('#build-capture').value)
            await self.next_until(app, pilot, 'build:results:nosh-zig')
            builds = [(key, argv) for key, argv in app.commands if key.startswith('build:execute:')]
            self.assertEqual(len(builds), 1)
            self.assertEqual(builds[0][1][1:4], ('build', 'net', 'learn'))
            self.assertIn('nosh-zig', str(app.query_one('#summary').render()))
            await self.click(pilot, '#back')
            self.assertEqual(app.page_key, 'build:execute:nosh-zig')
            await self.click(pilot, '#next')
            self.assertEqual(len(app.commands), 1)
            await self.next_until(app, pilot, 'dev:learn:nosh-zig')
            await self.click(pilot, '#skip')
            await self.click(pilot, '#skip')
            self.assertEqual(app.page_key, 'finish')
            self.assertTrue(app.guided_results)
            await self.click(pilot, '#another-image')
            self.assertEqual(app.page_key, 'image:choose')
            self.assertEqual(app.guided_results, {})
            self.assertEqual(app.guided_skipped, set())
            self.assertEqual(app.stage_choices, {'dev': None, 'run': None})
            app.query_one('#image-select').focus()
            await pilot.press('space', 'home', 'down', 'enter')
            await pilot.pause()
            self.assertEqual(app.candidate_image_name, 'nosh')
            await self.next_until(app, pilot, 'build:choice')
            self.assertEqual(app.guided_image_name, 'nosh')
            self.assertTrue(app.query_one('#build-reuse').value)

    async def test_review_requires_saved_evidence_and_saved_recording_is_reused(self):
        app = self.make_app(saved_recording=True)
        app.complete_reviews = False
        async with app.run_test(size=(100, 30)) as pilot:
            await pilot.pause()
            await self.next_until(app, pilot, 'dev:learn:nosh')
            self.assertTrue(app.query_one('#rerun').display)
            app.detected['host']['runtimeNetwork']['status'] = 'blocked'
            app.refresh_state()
            await pilot.pause()
            self.assertFalse(app.query_one('#rerun').disabled)
            count = len(app.commands)
            await app.action_rerun_step().wait()
            self.assertEqual(len(app.commands), count)
            self.assertEqual(app.page_key, 'readiness:nosh')
            self.assertTrue(app.query_one('#next').disabled)
            await self.click(pilot, '#back')
            self.assertIsNone(app.pending_capture)
            app.detected['host']['runtimeNetwork']['status'] = 'ready'
            app.refresh_state()
            await self.next_until(app, pilot, 'dev:review:nosh')
            self.assertFalse(any(':learn:' in key for key, _ in app.commands))
            await self.click(pilot, '#next')
            self.assertEqual(app.page_key, 'dev:review:nosh')
            self.assertNotEqual(app.current_page.status, 'complete')
            self.assertIn('Completion is not yet verified', app.last_result)
            app.complete_reviews = True
            await self.click(pilot, '#next')
            self.assertNotEqual(app.page_key, 'dev:review:nosh')
            self.assertEqual(sum(key == 'dev:review:nosh' for key, _ in app.commands), 2)

    async def test_network_options_and_dev_application_checkbox_reach_commands(self):
        app = self.make_app(network_ready=False)
        async with app.run_test(size=(100, 30)) as pilot:
            await pilot.pause()
            await self.next_until(app, pilot, 'dev:learn:nosh')
            self.assertFalse(app.query_one('#start-app').value)
            self.assertIn('type exit', app.current_page.detail)
            await self.click(pilot, '#start-app')
            self.assertTrue(app.query_one('#start-app').value)
            await self.next_until(app, pilot, 'host:network')
            learn = next(argv for key, argv in app.commands if key == 'dev:learn:nosh')
            self.assertIn('--start-app', learn)
            self.assertTrue(app.query_one('#network-choice').display)
            self.assertTrue(app.query_one('#next').disabled)
            app.query_one('#network-pool').focus()
            await pilot.press(*'172.28.0.0/26')
            app.query_one('#network-exclusions').focus()
            await pilot.press(*'10.80.0.0/16,192.168.10.0/24')
            await pilot.pause()
            self.assertFalse(app.query_one('#next').disabled)
            self.assert_navigation_visible(app)
            await self.click(pilot, '#next')
            network = next(argv for key, argv in app.commands if key == 'host:network')
            self.assertEqual(network[-6:], ('--review-pool', '172.28.0.0/26', '--exclude',
                                           '10.80.0.0/16', '--exclude', '192.168.10.0/24'))

    async def test_skip_dev_recording_goes_directly_to_run_without_extra_setup(self):
        app = self.make_app()
        async with app.run_test(size=(100, 30)) as pilot:
            await pilot.pause()
            await self.next_until(app, pilot, 'dev:learn:nosh')
            self.assertEqual(str(app.query_one('#skip').label), 'Skip recording')
            self.assertFalse(app.query_one('#skip').disabled)
            self.assert_navigation_visible(app)
            commands_before_skip = list(app.commands)
            await self.click(pilot, '#skip')
            self.assertEqual(app.page_key, 'run:learn:nosh')
            self.assertEqual(app.commands, commands_before_skip)
            self.assertNotIn('inventory:nosh', {page.key for page in app.guided_pages})
            await self.click(pilot, '#next')
            self.assertEqual(app.page_key, 'readiness:nosh')
            await self.next_until(app, pilot, 'finish')
            self.assertIn('Run ready', app.current_page.evidence)
            self.assertFalse(any(key.startswith('dev:') for key, _ in app.commands))

    async def test_saved_dev_recording_can_be_skipped_by_key_or_button(self):
        app = self.make_app(saved_recording=True)
        async with app.run_test(size=(100, 30)) as pilot:
            await pilot.pause()
            await self.next_until(app, pilot, 'dev:learn:nosh')
            self.assertEqual(app.current_page.status, 'complete')
            self.assertFalse(app.query_one('#skip').disabled)
            before = copy.deepcopy(app.detected)
            commands_before = list(app.commands)
            for key in ('s', 'S', None):
                app.query_one('#start-app').focus()
                if key:
                    await pilot.press(key)
                    await pilot.pause()
                else:
                    await self.click(pilot, '#skip')
                self.assertEqual(app.page_key, 'run:learn:nosh')
                self.assertEqual(app.commands, commands_before)
                self.assertEqual(app.detected, before)
                self.assertNotIn('dev:review:nosh', {page.key for page in app.guided_pages})
                await pilot.press('p')
                await pilot.pause()
                self.assertEqual(app.page_key, 'dev:learn:nosh')
            await pilot.press('n')
            await pilot.pause()
            self.assertEqual(app.page_key, 'dev:results:nosh')
            self.assertNotIn('dev:learn:nosh', app.guided_skipped)
            self.assertEqual(app.commands, commands_before)
            self.assertIn('dev:review:nosh', {page.key for page in app.guided_pages})

    async def test_skipped_recording_can_be_revisited_and_started(self):
        app = self.make_app()
        async with app.run_test(size=(100, 30)) as pilot:
            await pilot.pause()
            await self.next_until(app, pilot, 'dev:learn:nosh')
            await self.click(pilot, '#skip')
            self.assertEqual(app.page_key, 'run:learn:nosh')
            await self.click(pilot, '#back')
            self.assertEqual(app.page_key, 'dev:learn:nosh')
            self.assertFalse(app.query_one('#next').disabled)
            await self.next_until(app, pilot, 'dev:results:nosh')
            self.assertEqual(app.page_key, 'dev:results:nosh')
            self.assertEqual(sum(key == 'dev:learn:nosh' for key, _ in app.commands), 1)
            self.assertIn('inventory:nosh', {page.key for page in app.guided_pages})

    async def test_interrupted_recording_can_be_skipped_without_applying_dependents(self):
        app = self.make_app()
        app.fail_codes['dev:learn:nosh'] = 130
        async with app.run_test(size=(100, 30)) as pilot:
            await pilot.pause()
            await self.next_until(app, pilot, 'dev:learn:nosh')
            await self.click(pilot, '#next')
            self.assertEqual(app.page_key, 'readiness:nosh')
            await self.click(pilot, '#next')
            self.assertEqual(app.page_key, 'dev:learn:nosh')
            self.assertEqual(app.current_page.status, 'blocked')
            self.assertIn('130', app.last_result)
            await self.click(pilot, '#skip')
            self.assertEqual(app.page_key, 'run:learn:nosh')
            await self.click(pilot, '#skip')
            self.assertEqual(app.page_key, 'finish')
            self.assertEqual(app.current_page.label, 'Setup ready')
            self.assertIn('Development not requested', app.current_page.evidence)
            self.assertIn('Run not requested', app.current_page.evidence)
            self.assertFalse(any(key.startswith(('dev:prepare:', 'dev:review:', 'dev:apply:', 'dev:status:'))
                                 for key, _ in app.commands))

    async def test_recording_requests_missing_setup_then_captures_exactly_once(self):
        app = self.make_app()
        app.detected['host']['guard']['status'] = 'missing'
        app.detected['host']['launchers']['status'] = 'missing'
        async with app.run_test(size=(100, 30)) as pilot:
            await pilot.pause()
            await self.next_until(app, pilot, 'dev:learn:nosh')
            self.assertFalse(any(':intro:' in page.key for page in app.guided_pages))
            self.assertEqual(app.commands, [])
            self.assertIn('automatically start capture', str(app.query_one('#next-effect').render()))
            await self.click(pilot, '#next')
            self.assertEqual(app.page_key, 'host:guard')
            self.assertIsNotNone(app.pending_capture)
            await self.click(pilot, '#next')
            self.assertEqual(app.page_key, 'host:setup')
            await self.click(pilot, '#next')
            self.assertEqual(app.page_key, 'readiness:nosh')
            await self.click(pilot, '#next')
            self.assertEqual(app.page_key, 'dev:results:nosh')
            self.assertEqual([key for key, _ in app.commands],
                             ['host:guard', 'host:setup', 'readiness:nosh', 'dev:learn:nosh'])
            self.assertIsNone(app.pending_capture)
            app.action_refresh()
            await self.click(pilot, '#back')
            self.assertEqual(app.page_key, 'dev:learn:nosh')
            await self.click(pilot, '#next')
            self.assertEqual(len(app.commands), 4)

    async def test_previous_on_completed_prerequisite_requires_a_new_capture_request(self):
        app = self.make_app()
        app.detected['host']['launchers']['status'] = 'missing'
        async with app.run_test(size=(100, 30)) as pilot:
            await pilot.pause()
            await self.next_until(app, pilot, 'dev:learn:nosh')
            await self.click(pilot, '#next')
            self.assertEqual(app.page_key, 'host:setup')
            await self.click(pilot, '#next')
            self.assertEqual(app.page_key, 'readiness:nosh')
            await self.click(pilot, '#back')
            self.assertEqual(app.page_key, 'host:setup')
            self.assertIsNone(app.pending_capture)
            await self.click(pilot, '#next')
            self.assertEqual(app.page_key, 'dev:learn:nosh')
            self.assertEqual([key for key, _ in app.commands], ['host:setup'])
            await self.click(pilot, '#next')
            self.assertEqual(app.page_key, 'readiness:nosh')
            await self.click(pilot, '#next')
            self.assertEqual(app.page_key, 'dev:results:nosh')

    async def test_ready_capture_starts_directly_and_record_again_is_explicit(self):
        app = self.make_app()
        async with app.run_test(size=(100, 30)) as pilot:
            await pilot.pause()
            await self.next_until(app, pilot, 'dev:learn:nosh')
            app.stage_choices['dev'] = True
            app.render_state()
            readiness = next(page for page in app.guided_pages if page.key == 'readiness:nosh')
            app.guided_results[readiness.key] = self.module.guided_result(readiness, 'complete')
            app.render_state()
            self.assertIn('Next: start capture.', str(app.query_one('#next-effect').render()))
            await self.click(pilot, '#next')
            self.assertEqual(app.page_key, 'dev:results:nosh')
            self.assertEqual([key for key, _ in app.commands], ['dev:learn:nosh'])
            await self.click(pilot, '#back')
            await self.click(pilot, '#rerun')
            self.assertEqual(app.page_key, 'dev:results:nosh')
            self.assertEqual([key for key, _ in app.commands], ['dev:learn:nosh', 'dev:learn:nosh'])

    async def test_pending_capture_is_cancelled_by_navigation_failure_or_image_change(self):
        for outcome in ('previous', 'skip', 'completed-skip', 'failure', 'image', 'status-error'):
            with self.subTest(outcome=outcome):
                app = self.make_app()
                async with app.run_test(size=(100, 30)) as pilot:
                    await pilot.pause()
                    await self.next_until(app, pilot, 'dev:learn:nosh')
                    await self.click(pilot, '#next')
                    self.assertEqual(app.page_key, 'readiness:nosh')
                    self.assertIsNotNone(app.pending_capture)
                    if outcome == 'previous':
                        await self.click(pilot, '#back')
                        self.assertEqual(app.page_key, 'dev:learn:nosh')
                        app.action_refresh()
                    elif outcome in ('skip', 'completed-skip'):
                        if outcome == 'completed-skip':
                            page = app.current_page
                            app.guided_results[page.key] = self.module.guided_result(page, 'complete')
                            app.render_state()
                            self.assertFalse(app.query_one('#skip').disabled)
                        await self.click(pilot, '#skip')
                        self.assertEqual(app.page_key, 'run:learn:nosh')
                        self.assertFalse(app.stage_choices['dev'])
                    elif outcome == 'failure':
                        app.fail_codes['readiness:nosh'] = 130
                        await self.click(pilot, '#next')
                        self.assertIsNone(app.pending_capture)
                        app.fail_codes.clear()
                        await self.click(pilot, '#next')
                        self.assertEqual(app.page_key, 'dev:learn:nosh')
                    elif outcome == 'image':
                        app.detected['images'][0]['imageId'] = 'sha256:' + 'c' * 64
                        app.action_refresh()
                        self.assertIsNone(app.pending_capture)
                        await self.click(pilot, '#next')
                        self.assertEqual(app.page_key, 'dev:learn:nosh')
                    else:
                        with patch.object(app, 'load_state', side_effect=RuntimeError('Unavailable')):
                            app.action_refresh()
                        self.assertTrue(app.query_one('#next').disabled)
                    self.assertIsNone(app.pending_capture)
                    self.assertFalse(any(':learn:' in key for key, _ in app.commands))

    async def test_policy_hub_cancels_capture_and_returns_without_execution(self):
        app = self.make_app()
        async with app.run_test(size=(100, 30)) as pilot:
            await pilot.pause()
            await self.next_until(app, pilot, 'dev:learn:nosh')
            original = app.page_key
            app.pending_capture = (original, 'sha256:' + 'a' * 64, ('false',))
            app.capture_context = original
            before = list(app.commands)
            await self.click(pilot, '#more')
            await self.click(pilot, '#policies')
            self.assertIsNone(app.pending_capture)
            self.assertIsNone(app.capture_context)
            self.assertEqual(app.screen.kind, 'dev')
            self.assertTrue(app.screen.query_one('#policy-apply').disabled)
            await pilot.press('n', 'p', 's')
            await pilot.pause()
            self.assertEqual(app.page_key, original)
            # Refresh is discovery only; fake the explicit terminal status command.
            from unittest.mock import AsyncMock
            with patch.object(app, 'execute_command', new=AsyncMock(return_value=0)):
                app.screen.perform('policy-verify')
                await app.workers.wait_for_complete()
                await pilot.pause()
            self.assertEqual(app.commands, before)
            await pilot.press('escape')
            await pilot.pause()
            self.assertEqual(app.page_key, original)
            self.assertEqual(app.commands, before)
            self.assert_navigation_visible(app)

    async def test_policy_colors_and_more_escape(self):
        app = self.make_app()
        async with app.run_test(size=(140, 45)) as pilot:
            await pilot.pause()
            await self.next_until(app, pilot, 'dev:learn:nosh')
            self.assertIn('for Dev Policy', str(app.query_one('#step-title').render()))
            self.assertTrue(any('bright_blue' in str(span.style) for span in app.query_one('#summary').render().spans))
            page = app.page_key
            await self.click(pilot, '#more')
            await pilot.press('escape')
            await pilot.pause()
            self.assertEqual(app.page_key, page)
            self.assertEqual(app.policy_color('Build'), 'bold bright_yellow')
            self.assertEqual(app.policy_color('Run'), 'bold bright_red')

    async def test_policy_radio_choices_are_colored_and_switch_scope(self):
        app = self.make_app()
        async with app.run_test(size=(100, 30)) as pilot:
            await pilot.pause()
            app.action_manage_policies()
            await pilot.pause()
            hub = app.screen
            for policy, color in (('build', 'bright_yellow'), ('run', 'bright_red'),
                                  ('tools', 'bright_blue'), ('dev', 'bright_blue')):
                hub.validated = ('old', 'review', 'digest')
                await self.click(pilot, '#policy-kind-' + policy)
                self.assertEqual(hub.kind, policy)
                self.assertIsNone(hub.validated)
                self.assertTrue(hub.query_one('#policy-apply').disabled)
                self.assertEqual(hub.query_one('#policy-image').display, policy != 'tools')
                self.assertEqual(hub.query_one('#policy-validate').disabled, policy == 'build')
                button = hub.query_one('#policy-kind-' + policy)
                self.assertTrue(any(color in str(span.style) for span in button.label.spans))
                self.assertEqual(sum(button.value for button in hub.query('#policy-kind RadioButton')), 1)
            hub.query_one('#policy-kind').focus()
            await pilot.press('down', 'space')
            await pilot.pause()
            self.assertEqual(hub.kind, 'run')
            self.assertEqual(app.commands, [])

    async def test_policy_apply_cancellation_changed_decisions_and_failure(self):
        from unittest.mock import AsyncMock
        app = self.make_app()
        async with app.run_test(size=(100, 30)) as pilot:
            await pilot.pause()
            app.action_manage_policies()
            await pilot.pause()
            hub = app.screen
            hub.query_one('#policy-kind-tools').value = True
            await pilot.pause()
            digest = 'sha256:' + 'a' * 64
            with patch.object(hub, 'selected_review', return_value='/private/report'), \
                    patch.object(hub, 'check', new=AsyncMock(return_value=digest)) as check, \
                    patch.object(hub, 'confirm', new=AsyncMock(return_value=False)) as confirm, \
                    patch.object(app, 'execute_command', new=AsyncMock(return_value=1)) as execute:
                async def run(operation):
                    hub.perform(operation)
                    await app.workers.wait_for_complete()
                    await pilot.pause()
                await run('policy-validate')
                self.assertFalse(hub.query_one('#policy-apply').disabled)
                await run('policy-apply')
                execute.assert_not_awaited()
                self.assertIn('canceled', str(hub.query_one('#policy-info').render()))
                await run('policy-validate')
                check.return_value = 'sha256:' + 'b' * 64
                await run('policy-apply')
                execute.assert_not_awaited()
                self.assertIn('changed', str(hub.query_one('#policy-info').render()))
                await run('policy-validate')
                confirm.return_value = True
                await run('policy-apply')
                execute.assert_awaited_once()
                self.assertIn('Apply failed', str(hub.query_one('#policy-info').render()))
                self.assertTrue(hub.query_one('#policy-apply').disabled)

    async def test_browser_launch_is_exact_scope_and_not_completion(self):
        from unittest.mock import AsyncMock
        app = self.make_app(saved_recording=True)
        async with app.run_test(size=(100, 30)) as pilot:
            await pilot.pause()
            await self.next_until(app, pilot, 'dev:learn:nosh')
            original = app.page_key
            app.action_manage_policies()
            await pilot.pause()
            hub = app.screen
            with patch.object(hub, 'confirm', new=AsyncMock(return_value=True)), \
                    patch.object(app, 'execute_command', new=AsyncMock(return_value=0)) as execute:
                hub.perform('policy-open')
                await app.workers.wait_for_complete()
                await pilot.pause()
                argv = execute.call_args.args[0]
                self.assertEqual(argv[argv.index('--revision') + 1], 'dev-saved')
                self.assertEqual(argv[argv.index('--expected-image') + 1], 'sha256:' + 'a' * 64)
                self.assertIn('not marked reviewed or applied', str(hub.query_one('#policy-info').render()))
                self.assertTrue(hub.query_one('#policy-apply').disabled)
                self.assertEqual(app.page_key, original)
                execute.return_value = 1
                hub.perform('policy-open')
                await app.workers.wait_for_complete()
                await pilot.pause()
                self.assertIn('launch failed', str(hub.query_one('#policy-info').render()))

    async def test_large_terminal_keeps_single_image_controls_visible(self):
        app = self.make_app()
        async with app.run_test(size=(140, 45)) as pilot:
            await pilot.pause()
            self.assert_navigation_visible(app, height=45)
            self.assertEqual(len(app.query('#progress')), 0)
            await self.next_until(app, pilot, 'build:choice')
            self.assert_navigation_visible(app, height=45)
            self.assertTrue(app.query_one('#build-choice').display)
            self.assertLess(app.query_one('#build-options').region.bottom,
                            app.query_one('#navigation').region.y)


if __name__ == '__main__':
    unittest.main()
