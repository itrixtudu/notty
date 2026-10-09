"""Wizard hand-off to the existing local React policy editors."""
import asyncio
import json
from pathlib import Path
import re
import subprocess
import tempfile
from rich.text import Text

from textual import work
from textual.app import ComposeResult
from textual.containers import Horizontal, Vertical, VerticalScroll
from textual.screen import ModalScreen
from textual.widgets import Button, Input, RadioButton, RadioSet, Select, Static

from nosh_init_model import Action
from nosh_policy_manager import discover_reports, private_json, validate_report, validate_session


class MoreMenu(ModalScreen[str]):
    CSS = """
    MoreMenu { align: center middle; }
    #more-dialog { width: 30; height: auto; padding: 1; background: $surface; border: round $accent; }
    #more-dialog Button { width: 100%; }
    """
    BINDINGS = [('escape', 'close', 'Close'), ('down', 'focus_next', 'Next'),
                ('up', 'focus_previous', 'Previous')]

    def compose(self):
        with Vertical(id='more-dialog'):
            for label, key in [('Manage Policies', 'policies'), ('Details', 'details'),
                               ('Recheck', 'refresh'), ('Advanced', 'advanced')]:
                yield Button(label, id=key, disabled=key == 'details' and not self.app.current_page.argv)

    def action_close(self):
        self.dismiss('')

    def on_button_pressed(self, event):
        event.stop()
        self.dismiss(event.button.id)


class PolicyManager(ModalScreen[str]):
    CSS = """
    PolicyManager { align: center middle; }
    #policy-dialog { width: 94%; height: 92%; background: $surface; border: heavy $accent; padding: 1 2; }
    #policy-content { height: 1fr; }
    #policy-content Static { height: auto; margin: 1 0; }
    #policy-kind { height: auto; }
    .policy-buttons { height: auto; min-height: 3; }
    .policy-buttons Button { margin-right: 1; min-width: 10; }
    """
    BINDINGS = [('escape', 'close', 'Return to setup')]

    def __init__(self, confirm_screen, policy='dev'):
        super().__init__()
        self.confirm_screen = confirm_screen
        self.initial_policy = policy
        self.validated = None
        self.busy = False

    def compose(self) -> ComposeResult:
        with Vertical(id='policy-dialog'):
            yield Static('Manage Policies — saving a review does not activate it', markup=False)
            with VerticalScroll(id='policy-content'):
                yield Static(str(self.app.workspace), markup=False)
                with RadioSet(id='policy-kind'):
                    for label, policy, color in (
                            ('Build Network (evidence only)', 'build', 'bright_yellow'),
                            ('Dev Network', 'dev', 'bright_blue'),
                            ('Run Network', 'run', 'bright_red'),
                            ('Dev Tools (filesystem permissions)', 'tools', 'bright_blue')):
                        yield RadioButton(Text(label, style='bold ' + color),
                                          value=policy == self.initial_policy,
                                          id='policy-kind-' + policy)
                names = [(Text(item.name), item.name) for item in self.app.images]
                selected = self.app.guided_image_name or self.app.candidate_image_name
                yield Select(names, value=selected if selected else Select.NULL, id='policy-image')
                yield Select([], prompt='Select saved review / tool report', id='policy-review')
                yield Input(placeholder='Other tool report directory (then Load report)', id='policy-path')
                yield Button('Load report', id='policy-load')
                yield Static(id='policy-info', markup=False)
                with Horizontal(classes='policy-buttons'):
                    yield Button('Open in browser', id='policy-open', variant='primary')
                    yield Button('Validate', id='policy-validate')
                    yield Button('Apply', id='policy-apply', disabled=True)
                with Horizontal(classes='policy-buttons'):
                    yield Button('Verify status', id='policy-verify')
                    yield Button('Go to recording', id='policy-record')
                    yield Button('Initialize history', id='policy-init')
                yield Button('Review setup prerequisites', id='policy-setup')
                yield Select([('Guard installation', 'install'), ('Launch commands', 'setup'),
                              ('Review network pool', 'network'), ('Policy tooling', 'tooling'),
                              ('Policy signing', 'signing')], prompt='Choose a prerequisite to configure',
                             id='policy-prerequisite')
                yield Button('Configure selected prerequisite', id='policy-configure')
            yield Button('Return to setup', id='policy-close')

    @property
    def kind(self):
        selected = self.query_one('#policy-kind', RadioSet).pressed_button
        return selected.id.removeprefix('policy-kind-') if selected else self.initial_policy

    def context(self):
        name = self.query_one('#policy-image', Select).value
        image = next((i for i in self.app.state.get('images', []) if i['name'] == name), {})
        lane = self.app.state.get('workloads', {}).get(name, {}).get(self.kind, {})
        return image, lane

    def on_mount(self):
        self.query_one('#policy-prerequisite').display = False
        self.query_one('#policy-configure').display = False
        self.refresh_choices()

    def invalidate(self):
        self.validated = None
        self.query_one('#policy-apply', Button).disabled = True

    def refresh_choices(self):
        self.invalidate()
        image, lane = self.context()
        tools = self.kind == 'tools'
        self.query_one('#policy-image').display = not tools
        for key in ('policy-path', 'policy-load', 'policy-init'):
            self.query_one('#' + key).display = tools
        self.query_one('#policy-record').display = not tools
        reports = discover_reports(self.app.workspace, self.app.tool_report) if tools else [r['path'] for r in lane.get('reviews', [])]
        selector = self.query_one('#policy-review', Select)
        with selector.prevent(Select.Changed):
            selector.set_options([(Text(p), p) for p in reports])
            selector.value = reports[0] if len(reports) == 1 else Select.NULL
        selector.display = self.kind != 'build'
        self.query_one('#policy-validate', Button).disabled = self.kind == 'build'
        detail = ('Dev-only, workspace-wide container filesystem permissions; not an executable allowlist. '
                  'Applied changes affect future containers; existing containers are not recreated.\n'
                  + json.dumps(self.app.state.get('tools', {}), indent=2) if tools else
                  f"Image: {image.get('imageId', 'not selected')}\nRecording revision: {lane.get('revision', 'none')}\n"
                  + ('Build capture is investigation evidence, not active runtime enforcement.' if self.kind == 'build'
                     else json.dumps(lane.get('steps', {}), indent=2)))
        self.message(detail + '\nChoose a saved review, or open the browser to create one. Return here and Verify status after saving. Missing tooling, review networking, or signing must be configured in setup first.')

    def message(self, value):
        self.query_one('#policy-info', Static).update(value)

    def on_select_changed(self, event):
        event.stop()
        if not self.is_mounted:
            return
        if event.select.id == 'policy-image':
            self.refresh_choices()
        else:
            self.invalidate()

    def on_radio_set_changed(self, event: RadioSet.Changed):
        event.stop()
        if self.is_mounted and event.radio_set.id == 'policy-kind':
            self.refresh_choices()

    def selected_review(self):
        value = self.query_one('#policy-review', Select).value
        if value is Select.NULL:
            raise ValueError('Select a saved review first. Open the browser, save your decisions, then Verify status.')
        path = str(value)
        image, lane = self.context()
        if self.kind == 'tools':
            validate_report(path, self.app.workspace)
        else:
            validate_session(path, self.app.workspace, image.get('imageId'), lane.get('revision'), self.kind)
        return path

    def command(self, operation, path=''):
        script = 'nosh-tools.sh' if self.kind == 'tools' else 'nosh-net-review.sh'
        argv = ('bash', str(self.app.repo / 'scripts' / script), operation,
                '--workdir', str(self.app.workspace))
        if self.kind == 'tools':
            argv += ('--guard-prefix', str(self.app.guard_prefix))
        else:
            argv += ('--workload', self.kind)
        return argv + (('--review', path) if path else ())

    async def confirm(self, title, argv, detail):
        return await self.app.push_screen_wait(self.confirm_screen(Action('policy-manager', title, argv, detail)))

    async def check(self, path):
        argv = self.command('check', path)
        expected = ''
        if self.kind != 'tools':
            expected = next((r['decisionDigest'] for r in self.context()[1].get('reviews', []) if r['path'] == path), '')
            if not re.fullmatch(r'sha256:[a-f0-9]{64}', expected):
                raise ValueError('No complete saved decisions; save in the browser and Verify status')
            argv += ('--decision-digest', expected)
        result = await asyncio.to_thread(subprocess.run, argv,
                                         cwd=self.app.repo, text=True, capture_output=True, timeout=180)
        if result.returncode:
            raise ValueError(result.stderr[-3000:] or 'Validation failed; review prerequisites and saved decisions.')
        value = json.loads(result.stdout)
        if not value.get('ready' if self.kind == 'tools' else 'readyForApply'):
            raise ValueError('Saved review is not ready to apply')
        digest = value.get('policyDigest') if self.kind == 'tools' else expected
        if not isinstance(digest, str) or not re.fullmatch(r'sha256:[a-f0-9]{64}', digest):
            raise ValueError('Validation did not identify an exact saved policy digest')
        return digest

    def action_close(self):
        if not self.busy:
            self.dismiss('')

    def on_button_pressed(self, event):
        event.stop()
        if event.button.id == 'policy-close':
            self.action_close()
        elif not self.busy:
            self.perform(event.button.id)

    @work(exclusive=True)
    async def perform(self, operation):
        self.busy = True
        self.query_one('#policy-kind', RadioSet).disabled = True
        for select in self.query(Select):
            select.disabled = True
        try:
            image, lane = self.context()
            if operation == 'policy-load':
                self.app.tool_report = validate_report(self.query_one('#policy-path', Input).value, self.app.workspace)
                self.refresh_choices()
            elif operation == 'policy-record':
                if not image:
                    raise ValueError('Select an image first')
                self.app.guided_image_name = image['name']
                self.dismiss(self.kind)
            elif operation == 'policy-setup':
                self.query_one('#policy-prerequisite').display = True
                self.query_one('#policy-configure').display = True
                self.message('Choose the prerequisite you want to configure. No recording starts.\n'
                             + json.dumps(self.app.state.get('host', {}), indent=2))
            elif operation == 'policy-configure':
                step = self.query_one('#policy-prerequisite', Select).value
                if step is Select.NULL:
                    raise ValueError('Select a prerequisite first')
                argv = ('bash', str(self.app.repo / 'scripts/nosh-init.sh'), '--classic',
                        '--step', str(step), '--workdir', str(self.app.workspace),
                        '--guard-prefix', str(self.app.guard_prefix))
                if image.get('name') and self.kind != 'tools':
                    argv += ('--image', image['name'], '--workload', 'run' if self.kind == 'run' else 'dev')
                if await self.confirm('Configure ' + str(step), argv,
                                      'Run only this setup step. Existing prompts and privileged confirmations remain in effect. No recording starts.'):
                    result = await self.app.execute_command(argv)
                    self.app.refresh_state()
                    self.refresh_choices()
                    if result:
                        self.message('Prerequisite setup did not complete. Review terminal output and Verify status.')
            elif operation == 'policy-verify':
                self.app.refresh_state()
                self.refresh_choices()
                if self.kind == 'tools':
                    await self.app.execute_command(self.command('status'))
                elif self.kind != 'build':
                    argv = ('bash', str(self.app.repo / 'scripts/nosh-init.sh'), '--classic', '--tui-confirmed',
                            '--step', 'status', '--workdir', str(self.app.workspace), '--guard-prefix',
                            str(self.app.guard_prefix), '--image', image.get('name', ''), '--workload', self.kind)
                    await self.app.execute_command(argv)
            elif operation == 'policy-init':
                git = subprocess.run(['git', '-C', str(self.app.workspace), 'rev-parse', '--show-toplevel'], capture_output=True)
                scope = 'repo' if git.returncode == 0 else 'directory'
                argv = self.command('init') + ('--scope', scope, '--no-prompt')
                if '--codex-home' in self.app.dev_options:
                    index = self.app.dev_options.index('--codex-home')
                    argv += ('--codex-home', self.app.dev_options[index + 1])
                if await self.confirm('Initialize Dev tool history', argv, f'Read {scope}-scoped history for {self.app.workspace}. Never all history.'):
                    await self.app.execute_command(argv)
                    self.refresh_choices()
            elif operation == 'policy-open':
                self.invalidate()
                if self.kind == 'tools':
                    argv = self.command('review', self.selected_review())
                elif self.kind == 'build':
                    profile = image.get('buildProfile', {})
                    if profile.get('status') != 'saved':
                        raise ValueError('No saved build capture for this image. Go to recording first.')
                    argv = ('env', f'NOSH_PROFILE_REVIEW_WORKDIR={self.app.workspace}',
                            str(self.app.repo / 'scripts/profile-build-and-review.sh'), '--build-profile', profile['path'], '--allow-missing-sbom')
                else:
                    if not lane.get('revision') or not image.get('imageId'):
                        raise ValueError('No matching recording. Go to recording; capture will not start automatically.')
                    argv = self.command('review') + ('--revision', lane['revision'], '--expected-image', image['imageId'])
                if await self.confirm('Open policy editor', argv, 'Launch the existing Docker-backed React editor. Its launcher may build the review UI. The terminal prints a copyable local URL if no browser opens. Saving does not Apply.'):
                    result = await self.app.execute_command(argv)
                    self.app.refresh_state()
                    self.refresh_choices()
                    self.message('Editor launch failed.' if result else 'Editor launched, not marked reviewed or applied. Save in the browser, then Verify status. The local URL remains in the launcher terminal output.')
            elif operation == 'policy-validate':
                self.invalidate()
                path = self.selected_review()
                digest = await self.check(path)
                self.validated = (self.kind, path, digest)
                self.query_one('#policy-apply', Button).disabled = False
                self.message(f'Validated saved decisions: {digest}\nReview: {path}\nNot activated. Apply requires confirmation and checks the saved decisions again.')
            elif operation == 'policy-apply':
                previous = self.validated
                self.invalidate()
                path = self.selected_review()
                digest = await self.check(path)
                if previous != (self.kind, path, digest):
                    raise ValueError('Saved decisions changed or were not validated. Validate again before Apply.')
                flag = '--policy-digest' if self.kind == 'tools' else '--decision-digest'
                argv = self.command('apply', path) + (flag, digest)
                scope = ('Dev Tools — workspace-wide, not image-specific' if self.kind == 'tools' else
                         f'{self.kind.capitalize()} Network\nImage: {image.get("imageId")}\nRecording revision: {lane.get("revision")}')
                detail = f'Workspace: {self.app.workspace}\nPolicy: {scope}\nReview: {path}\nDigest: {digest}\nExisting authority and privileged confirmation checks remain in effect.'
                if await self.confirm('Apply exact saved policy', argv, detail):
                    # Recheck after confirmation too: browser decisions may have changed.
                    self.selected_review()
                    if await self.check(path) != digest:
                        raise ValueError('Decisions changed during confirmation; Validate again')
                    with tempfile.TemporaryDirectory(prefix='nosh-wizard-apply-') as temporary:
                        output = Path(temporary) / 'result.json'
                        if self.kind != 'tools':
                            argv += ('--result-json', str(output))
                        result = await self.app.execute_command(argv)
                        if result:
                            raise ValueError('Apply failed; no activation is assumed')
                        if self.kind == 'tools':
                            status = await asyncio.to_thread(subprocess.run, self.command('status'),
                                cwd=self.app.repo, capture_output=True, text=True, timeout=30)
                            actual = json.loads(status.stdout) if status.returncode == 0 else {}
                            verified = (actual.get('enabled') is True and actual.get('revision') == digest
                                and actual.get('environment', {}).get('workspace') == str(self.app.workspace))
                        else:
                            actual = private_json(output) if output.exists() else {}
                            activation = actual.get('activation', {})
                            verified = (actual.get('workspace') == str(self.app.workspace)
                                and actual.get('session') == path and actual.get('decisionDigest') == digest
                                and activation.get('imageDigest') == image.get('imageId')
                                and activation.get('learnRevision') == lane.get('revision'))
                    self.app.refresh_state()
                    self.refresh_choices()
                    self.message('Exact saved policy verified active for future containers. Existing containers were not recreated.' if verified else
                                 'Activation was not verified. Apply may have been canceled. Use Verify status; no success is assumed.')
                else:
                    self.message('Apply canceled. No policy was changed. Validate again before applying.')
        except (OSError, ValueError, KeyError, TypeError, subprocess.TimeoutExpired) as error:
            self.invalidate()
            self.message(str(error))
        finally:
            self.busy = False
            self.query_one('#policy-kind', RadioSet).disabled = False
            for select in self.query(Select):
                select.disabled = False
