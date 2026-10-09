import contextlib
import importlib.util
import io
import json
import os
from pathlib import Path
import stat
import sqlite3
import subprocess
import tempfile
import tomllib
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('audit', ROOT / 'scripts/audit-codex-tools.py')
audit = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(audit)


def meta(session='session-one'):
    return {'type': 'session_meta', 'payload': {'id': session, 'cwd': '/private/workspace'}}


def call(command, call_id='call-one', tool='exec_command', **kwargs):
    return {'type': 'response_item', 'payload': {
        'type': 'function_call', 'call_id': call_id, 'name': tool,
        'arguments': json.dumps({'cmd': command, **kwargs}),
    }}


class ClassificationTests(unittest.TestCase):
    def test_reviewed_literal_forms(self):
        commands = [
            "rg --files --hidden -g '*.py' .", "rg -n 'literal $HOME; x|y' 'space directory'",
            'grep -n -e needle -- -file', 'find . -maxdepth 2 -type f -name "*.py" -print',
            'find -L . -name "-delete" -print', 'diff -u before after', 'cmp -s one two',
            'cat -- -odd-name', 'head -n 40 README.md', 'tail -n +20 README.md',
            'wc -l README.md', 'ls -la', 'pwd -P', 'stat -c %s README.md',
            'file --mime README.md', 'readlink -f README.md', 'realpath --relative-to . README.md',
            'du -sh .', 'git --no-optional-locks status --short',
            'git -C "space directory" --no-pager diff --no-ext-diff --no-textconv --stat',
            'git log --no-ext-diff --no-textconv --oneline -n 5',
            'git show --no-ext-diff --no-textconv HEAD:README.md', 'git ls-files',
            'git ls-tree -r HEAD', 'git rev-parse --show-toplevel',
            'git describe --tags --always', 'git branch --list feature',
            'git worktree list --porcelain', ['/usr/bin/rg', '-n', 'a; touch BAD', 'file'],
        ]
        for command in commands:
            with self.subTest(command=command):
                self.assertEqual(audit.classify_command(command)[0], 'allow')

    def test_modifying_ambiguous_and_network_forms_remain_pending(self):
        commands = [
            'find . -delete', 'find . -exec touch BAD \\;', 'find . -fprint BAD',
            'rg --pre=touch needle .', 'rg --hostname-bin touch needle .',
            'sed -i s/old/new/ file', 'sed -n 1,5p file', 'sort -o BAD file',
            'git diff --output=BAD', 'git diff', 'git show HEAD', 'git log -p',
            'git branch new-branch', 'git branch -D branch', 'git worktree add branch',
            'git -c alias.test=whatever status', 'git --config-env=a=b status',
            'git fetch', 'git add .', 'git commit -m change', 'rg x > BAD',
            'rg x | tee BAD', 'rg x && touch BAD', 'rg x; touch BAD',
            'rg x\ntouch BAD', 'rg "$(touch BAD)" .', 'rg `touch BAD` .',
            'rg "$PATTERN" .', 'rg x *.py', 'RG_CONFIG_PATH=secret rg x',
            'bash -c "cat README.md"', 'python3 -c "print(1)"', 'node -e "1"',
            'curl https://example.invalid', 'ssh host cat file', 'npm test',
            'docker inspect image', 'unknown-program file', '/tmp/rg x',
            'rg --unknown=value x', "rg 'unterminated", 'head -n', 'find . -name',
            'file --preserve-date README.md', 'file -z README.md',
        ]
        for command in commands:
            with self.subTest(command=command):
                self.assertEqual(audit.classify_command(command)[0], 'not-yet')

    def test_non_shell_tools_and_escalations(self):
        for name in ['apply_patch', 'exec', 'write_stdin', 'spawn_agent',
                     'mcp__notty__read_terminal', 'mcp__notty__write_terminal', 'unknown']:
            self.assertEqual(audit.classify_call({'name': name})[1][0], 'not-yet')
        for name in ['view_image', 'functions.list_agents']:
            self.assertEqual(audit.classify_call({'name': name})[1][0], 'allow')
        for args in [dict(cmd='rg --files', sandbox_permissions='require_escalated'),
                     dict(cmd='rg --files', env={'LD_PRELOAD': 'library'}),
                     dict(cmd='rg --files', prefix_rule=['rg']),
                     dict(cmd='rg --files', command='touch file')]:
            self.assertEqual(audit.classify_call({'name': 'exec_command', 'arguments': args})[1][0], 'not-yet')


class HistoryTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.home = self.root / 'codex'
        for name in ('sessions', 'archived_sessions', 'rules'):
            (self.home / name).mkdir(parents=True)
        patcher = mock.patch.object(audit, 'SYSTEM_RULES', self.root / 'system/rules')
        patcher.start()
        self.addCleanup(patcher.stop)

    def write(self, relative, rows):
        path = self.home / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(''.join(json.dumps(row) + '\n' for row in rows))
        return path

    def scan(self):
        return audit.scan_history(self.home)

    def test_original_evidence_deduplicates_inputs_without_executing_or_collecting_outputs(self):
        marker = self.root / 'never-execute'
        command = 'touch ' + str(marker)
        rows = [meta(), call(command, 'one'), call(command, 'two'),
                call(command, 'three', workdir='/another/workspace'),
                {'type': 'response_item', 'payload': {'type': 'function_call_output',
                 'output': 'OUTPUT_MUST_NOT_BE_COLLECTED'}}]
        self.write('sessions/one.jsonl', rows)
        self.write('archived_sessions/copy.jsonl', rows)
        output = self.root / 'report'
        audit.run(self.home, output, self.root, request_details=True)
        descriptor = json.loads((output / 'allow.json').read_text())['request_evidence']
        self.assertEqual(descriptor['uniqueRequests'], 2)
        self.assertEqual(descriptor['recordedRequests'], 3)
        evidence = output / descriptor['file']
        self.assertEqual(stat.S_IMODE(evidence.stat().st_mode), 0o600)
        with sqlite3.connect(evidence) as connection:
            stored = connection.execute('SELECT input_json,cwd,occurrences FROM requests').fetchall()
        self.assertEqual(sorted(row[2] for row in stored), [1, 2])
        self.assertEqual({row[1] for row in stored}, {'/private/workspace', '/another/workspace'})
        self.assertTrue(all(json.loads(row[0])['cmd'] == command for row in stored))
        self.assertNotIn(b'OUTPUT_MUST_NOT_BE_COLLECTED', evidence.read_bytes())
        self.assertFalse(marker.exists())

    def test_deduplication_conflicts_and_all_request_formats(self):
        first = call('rg --files')
        conflict = call('touch BAD')
        no_id = call('pwd')
        del no_id['payload']['call_id']
        custom = {'type': 'response_item', 'payload': {'type': 'custom_tool_call',
                  'name': 'functions.exec_command', 'call_id': 'custom',
                  'input': json.dumps({'cmd': 'wc -l README.md'})}}
        legacy = {'type': 'function_call', 'name': 'shell', 'call_id': 'legacy',
                  'arguments': {'command': ['ls', '-l']}}
        tool_use = {'type': 'tool_use', 'name': 'shell_command', 'id': 'tool-use',
                    'input': {'command': 'pwd'}}
        native = {'type': 'response_item', 'payload': {'type': 'web_search_call', 'id': 'native'}}
        output = {'type': 'response_item', 'payload': {'type': 'function_call_output', 'output': 'not a request'}}
        self.write('sessions/one.jsonl', [meta(), first, conflict, no_id, no_id,
                                         custom, legacy, tool_use, native, output])
        self.write('archived_sessions/copy.jsonl', [meta(), first, custom, conflict])
        self.write('sessions/two.jsonl', [meta('different-session'), first])
        stats, errors, groups, _ = self.scan()
        self.assertFalse(errors)
        self.assertEqual(stats['raw_requests'], 12)
        self.assertEqual(stats['duplicate_requests'], 3)
        self.assertEqual(stats['unique_requests'], 9)
        self.assertEqual(stats['requests_without_dedup_identity'], 2)
        self.assertEqual(stats['native_tool_requests'], 1)
        self.assertEqual(stats['conflicting_call_versions'], 1)
        self.assertEqual(sum(g['count'] for cat in groups.values() for g in cat.values()), 9)

    def test_malformed_oversized_and_symlink_inputs_are_accounted_for(self):
        path = self.write('sessions/one.jsonl', [meta(), call('pwd')])
        with path.open('a') as stream:
            stream.write('{"truncated":\n')
        (self.home / 'sessions/link.jsonl').symlink_to(path)
        (self.home / 'sessions/link-dir').symlink_to(self.root, target_is_directory=True)
        (self.home / 'sessions/pipe.jsonl').touch()
        (self.home / 'sessions/pipe.jsonl').unlink()
        os.mkfifo(self.home / 'sessions/pipe.jsonl')
        stats, errors, _, _ = self.scan()
        self.assertEqual(stats['unique_requests'], 1)
        self.assertEqual(errors['malformed-records'], 1)
        self.assertEqual(errors['unreadable-or-nonregular-files'], 2)
        self.assertEqual(errors['symlink-directories'], 1)
        with mock.patch.object(audit, 'MAX_LINE', 8):
            _, errors, _, _ = self.scan()
        self.assertGreater(errors['oversized-records'], 0)

    def test_native_request_content_participates_in_deduplication(self):
        first = {'type': 'local_shell_call', 'id': 'native',
                 'action': {'command': ['cat', 'file']}}
        second = dict(first, action={'command': ['touch', 'file']})
        self.write('sessions/one.jsonl', [meta(), first, second, dict(first, status='completed')])
        stats, _, groups, _ = self.scan()
        self.assertEqual(stats['unique_requests'], 2)
        self.assertEqual(stats['duplicate_requests'], 1)
        self.assertEqual({g['tool'] for g in groups['not-yet'].values()}, {'local_shell_call'})

    def test_optional_archive_and_incomplete_exit_status(self):
        (self.home / 'archived_sessions').rmdir()
        path = self.write('sessions/one.jsonl', [meta(), call('pwd')])
        self.assertFalse(self.scan()[1])
        with path.open('a') as stream:
            stream.write('{')
        output = self.root / 'partial'
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(audit.run(self.home, output, self.root), 2)
        report = json.loads((output / 'allow.json').read_text())
        self.assertFalse(report['complete'])
        self.assertEqual(report['errors']['malformed-records'], 1)

    def test_file_growth_marks_snapshot_incomplete(self):
        path = self.write('sessions/one.jsonl', [meta(), call('pwd')])
        original = audit.classify_call
        def grow(payload):
            with path.open('a') as stream:
                stream.write(json.dumps(call('touch BAD', 'new')) + '\n')
            return original(payload)
        with mock.patch.object(audit, 'classify_call', side_effect=grow):
            stats, errors, _, _ = self.scan()
        self.assertEqual(stats['unique_requests'], 1)
        self.assertEqual(errors['file-size-changed'], 1)

    def test_unrecognized_response_formats_are_not_silently_dropped(self):
        self.write('sessions/one.jsonl', [meta(), call('pwd'),
            {'type': 'response_item', 'payload': {'type': 'future_request_format'}},
            {'type': 'response_item', 'payload': {'type': 'ghost_snapshot', 'ghost_commit': {}}},
            {'type': 'response_item', 'payload': {'type': 'agent_message', 'content': []}},
            {'type': 'response_item', 'payload': []}])
        stats, errors, _, _ = self.scan()
        self.assertEqual(stats['unique_requests'], 1)
        self.assertEqual(errors['unsupported-response-items'], 2)
        self.assertEqual(stats['non_request_response_items'], 2)

    def test_reports_are_private_redacted_and_never_replay_requests(self):
        secret = 'DO_NOT_EXPORT_PRIVATE_VALUE'
        marker = self.root / 'executed'
        self.write('sessions/' + secret + '.jsonl', [
            meta(), call(f"rg -e '{secret}' '{secret}'"),
            call(f'touch {marker}', 'write'),
            call(f'curl https://example.invalid/{secret}', 'network'),
            {'type': 'response_item', 'payload': {'type': 'custom_tool_call', 'name': 'exec',
             'call_id': 'code', 'input': f'process.env.TOKEN="{secret}"'}},
            {'type': 'response_item', 'payload': {'type': 'function_call_output', 'output': secret}},
        ])
        (self.home / 'rules/default.rules').write_text(
            f'prefix_rule(pattern=["sed"], decision="allow")\n'
            f'prefix_rule(pattern=["rm", "{secret}"], decision="allow")\n')
        (self.home / 'config.toml').write_text(f'model="{secret}"\n')
        before = {p: p.read_bytes() for p in self.home.rglob('*') if p.is_file()}
        output = self.root / 'state/nosh/audit/report'
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(audit.run(self.home, output, self.root), 0)
        self.assertFalse(marker.exists())
        self.assertEqual(before, {p: p.read_bytes() for p in before})
        self.assertEqual(stat.S_IMODE(output.stat().st_mode), 0o700)
        for parent in [self.root / 'state', self.root / 'state/nosh', output.parent]:
            self.assertEqual(stat.S_IMODE(parent.stat().st_mode), 0o700)
        for path in output.iterdir():
            self.assertNotIn(secret, path.read_text())
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
        allowed = json.loads((output / 'allow.json').read_text())
        pending = json.loads((output / 'not-yet.json').read_text())
        self.assertEqual(allowed['totals']['unique_requests'], 4)
        self.assertEqual(sum(g['count'] for g in allowed['entries']), 1)
        self.assertEqual(sum(g['count'] for g in pending['entries']), 3)
        rules = json.loads((output / 'rules-review.json').read_text())
        self.assertEqual(len(rules['entries']), 2)
        self.assertTrue(all(entry['needs_review'] for entry in rules['entries']))
        planning = tomllib.loads((output / 'planning.config.toml').read_text())
        implementation = tomllib.loads((output / 'implementation.config.toml').read_text())
        self.assertEqual(planning['sandbox_mode'], 'read-only')
        self.assertEqual(planning['approval_policy'], 'never')
        self.assertEqual(implementation['sandbox_mode'], 'workspace-write')
        self.assertFalse(implementation['sandbox_workspace_write']['network_access'])
        with self.assertRaises(FileExistsError):
            audit.run(self.home, output, self.root)

    def test_rule_code_is_parsed_not_executed(self):
        marker = self.root / 'executed'
        (self.home / 'rules/dynamic.rules').write_text(
            f'open("{marker}", "w")\nprefix_rule(pattern=calculate(), decision="allow")\n')
        rules = audit.audit_rules(self.home, self.root)
        self.assertFalse(marker.exists())
        self.assertGreater(rules['errors']['unsupported-rule-code'], 0)

    def test_no_output_in_codex_home_or_repository(self):
        for output in [self.home / 'report', ROOT / 'report']:
            with self.assertRaises(ValueError):
                audit.run(self.home, output, self.root)
        link = self.root / 'link'
        link.symlink_to(self.home, target_is_directory=True)
        with self.assertRaises(ValueError):
            audit.run(self.home, link / 'report', self.root)


class ReviewMenuTests(unittest.TestCase):
    def test_browse_reports_and_profiles_without_mutations(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory)
            for name in ('rules-review.json', 'not-yet.json', 'allow.json'):
                (output / name).write_text(json.dumps({'entries': [{'form': str(i)} for i in range(26)]}))
            (output / 'planning.config.toml').write_text(audit.PLANNING_CONFIG)
            (output / 'implementation.config.toml').write_text(audit.IMPLEMENTATION_CONFIG)
            before = {p: p.read_bytes() for p in output.iterdir()}
            capture = io.StringIO()
            with mock.patch('builtins.input', side_effect=['invalid', '1', '', '2', 'm', '3', 'm', '4', 'q']), contextlib.redirect_stdout(capture):
                audit.review_reports(output)
            self.assertIn('Choose 1, 2, 3, 4, 5, or q.', capture.getvalue())
            self.assertIn('"form": "25"', capture.getvalue())
            self.assertIn('sandbox_mode = "read-only"', capture.getvalue())
            self.assertIn('sandbox_mode = "workspace-write"', capture.getvalue())
            self.assertEqual(before, {p: p.read_bytes() for p in output.iterdir()})

    def test_eof_and_interrupt_close_menu(self):
        for error in (EOFError, KeyboardInterrupt):
            with mock.patch('builtins.input', side_effect=error), contextlib.redirect_stdout(io.StringIO()):
                audit.review_reports(Path('/unused'))

    def test_reopen_ui_skips_scanning_and_menu_failure_preserves_review(self):
        with mock.patch.object(audit, 'run') as scan, mock.patch.object(audit, 'open_review_ui', return_value=1) as launch:
            self.assertEqual(audit.main(['--review-ui', '/saved/report']), 1)
            scan.assert_not_called()
            launch.assert_called_once_with(Path('/saved/report'))
        with mock.patch.object(audit, 'open_review_ui', return_value=1) as launch, \
                mock.patch('builtins.input', side_effect=['5', 'q']), contextlib.redirect_stdout(io.StringIO()):
            audit.review_reports(Path('/saved/report'))
            launch.assert_called_once()

    def test_prompt_gating_and_exit_status(self):
        for flags, stdin_tty, stdout_tty, status, expected in [
            ([], True, True, 0, True),
            ([], True, True, 2, True),
            (['--no-prompt'], True, True, 0, False),
            ([], False, True, 0, False),
            ([], True, False, 0, False),
        ]:
            with mock.patch.object(audit, 'run', return_value=status), \
                    mock.patch.object(audit, 'review_reports') as review, \
                    mock.patch('sys.stdin.isatty', return_value=stdin_tty), \
                    mock.patch('sys.stdout.isatty', return_value=stdout_tty), \
                    contextlib.redirect_stdout(io.StringIO()) as capture:
                # redirect_stdout replaces stdout, so set its TTY behavior too.
                capture.isatty = lambda: stdout_tty
                self.assertEqual(audit.main(flags), status)
                self.assertEqual(review.called, expected)


class ScopedHistoryTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.home = self.root / 'codex'
        for folder in ('sessions', 'archived_sessions'):
            (self.home / folder).mkdir(parents=True)
        self.work = self.root / 'work'
        self.work.mkdir()

    def write(self, folder, name, rows):
        (self.home / folder / name).write_text(''.join(json.dumps(row) + '\n' for row in rows))

    def metadata(self, cwd):
        return {'type': 'session_meta', 'payload': {'id': 'scoped-session', 'cwd': str(cwd)}}

    def selection(self):
        return audit.history_scope('directory', self.work)

    def test_directory_boundaries_archives_and_dedup_after_filtering(self):
        request = call('rg --files')
        self.write('sessions', 'outside.jsonl', [self.metadata(str(self.work) + '-other'), request])
        self.write('sessions', 'inside.jsonl', [self.metadata(self.work / 'child'), request])
        self.write('archived_sessions', 'copy.jsonl', [self.metadata(self.work), request])
        stats, errors, groups, _ = audit.scan_history(self.home, self.selection())
        self.assertFalse(errors)
        self.assertEqual(stats['raw_requests'], 2)
        self.assertEqual(stats['duplicate_requests'], 1)
        self.assertEqual(stats['unique_requests'], 1)
        self.assertEqual(stats['out_of_scope_requests'], 1)

    def test_turn_changes_and_missing_context_are_not_guessed_from_commands(self):
        self.write('sessions', 'turns.jsonl', [call('pwd'), self.metadata(self.work), call('ls'),
            {'type': 'turn_context', 'payload': {'cwd': str(self.root / 'elsewhere')}}, call('pwd'),
            {'type': 'turn_context', 'payload': {'cwd': 'relative'}}, call('pwd'),
            {'type': 'turn_context', 'payload': {'cwd': str(self.work / 'nested')}}, call('wc file')])
        stats, errors, _, _ = audit.scan_history(self.home, self.selection())
        self.assertEqual(stats['raw_requests'], 2)
        self.assertEqual(stats['out_of_scope_requests'], 1)
        self.assertEqual(stats['unattributed_requests'], 2)
        self.assertEqual(errors['requests-without-working-directory'], 2)
        all_stats, all_errors, _, _ = audit.scan_history(self.home)
        self.assertFalse(all_errors)
        self.assertEqual(all_stats['raw_requests'], 5)
        self.assertEqual(all_stats['unattributed_requests'], 2)

    def test_repo_root_and_nested_linked_worktree_exclusion(self):
        import subprocess
        def git(*args):
            subprocess.run(['git', '-C', str(self.work), *args], check=True, capture_output=True)
        git('init')
        git('-c', 'user.name=Test', '-c', 'user.email=test@example.invalid', 'commit', '--allow-empty', '-m', 'fixture')
        nested = self.work / 'linked'
        git('worktree', 'add', '-b', 'fixture-worktree', str(nested))
        child = self.work / 'child'
        child.mkdir()
        selected = audit.history_scope('repo', child)
        self.assertEqual(selected['root'], str(self.work))
        self.assertEqual(selected['excluded_roots'], [str(nested)])
        self.write('sessions', 'repo.jsonl', [self.metadata(nested), call('pwd'),
            {'type': 'turn_context', 'payload': {'cwd': str(child)}}, call('ls')])
        stats, _, _, _ = audit.scan_history(self.home, selected)
        self.assertEqual(stats['raw_requests'], 1)
        self.assertEqual(stats['out_of_scope_requests'], 1)

    def test_scoped_unknowns_are_incomplete_but_all_history_retains_them(self):
        marker = self.root / 'HISTORY-MUST-NOT-RUN'
        self.write('sessions', 'unknown.jsonl', [call('touch ' + str(marker))])
        with mock.patch.object(audit, 'SYSTEM_RULES', self.root / 'system'), contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(audit.run(self.home, self.root / 'scoped-report', self.work, self.selection()), 2)
            self.assertEqual(audit.run(self.home, self.root / 'all-report', self.work), 0)
        scoped = json.loads((self.root / 'scoped-report/allow.json').read_text())
        all_history = json.loads((self.root / 'all-report/not-yet.json').read_text())
        self.assertFalse(scoped['complete'])
        self.assertEqual(scoped['history_scope']['unattributed_requests'], 1)
        self.assertTrue(all_history['complete'])
        self.assertEqual(all_history['totals']['unique_requests'], 1)
        self.assertFalse(marker.exists())

    def test_interactive_cli_defaults_to_directory_and_returns_to_review_menu(self):
        import shutil
        import shlex
        import subprocess
        if not shutil.which('script'):
            self.skipTest('script is required for terminal integration')
        command = ['bash', str(ROOT / 'scripts/nosh.sh'), 'tools', 'init', '--codex-home', str(self.home),
                   '--workdir', str(self.work), '--output-dir', str(self.root / 'interactive-report')]
        result = subprocess.run(['script', '-q', '-e', '-c', shlex.join(command), '/dev/null'],
                                input='\nq\n', capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn('Scope [1]', result.stdout)
        self.assertIn('History scope: directory', result.stdout)
        saved = json.loads((self.root / 'interactive-report/allow.json').read_text())
        self.assertEqual(saved['history_scope']['kind'], 'directory')

    def test_scope_menu_defaults_and_cancel(self):
        with mock.patch.object(audit, 'history_scope', side_effect=[{'kind': 'repo', 'root': '/repo', 'dates': 'all'}, self.selection()]), \
                mock.patch('builtins.input', return_value=''), contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(audit.choose_history_scope(self.work)['kind'], 'directory')
        with mock.patch.object(audit, 'history_scope', side_effect=[audit.ScopeError('no repo'), self.selection()]), \
                mock.patch('builtins.input', return_value=''), contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(audit.choose_history_scope(self.work)['kind'], 'directory')
        with mock.patch('builtins.input', return_value='q'), contextlib.redirect_stdout(io.StringIO()):
            self.assertIsNone(audit.choose_history_scope(self.work))

    def test_cli_requires_scope_and_writes_bound_empty_scope_report(self):
        import subprocess
        command = ['bash', str(ROOT / 'scripts/nosh.sh'), 'tools', 'init', '--no-prompt',
                   '--codex-home', str(self.home), '--workdir', str(self.work)]
        missing = subprocess.run(command, capture_output=True, text=True)
        self.assertEqual(missing.returncode, 2)
        self.assertIn('requires --scope', missing.stderr)
        report = self.root / 'report'
        result = subprocess.run(command + ['--scope', 'directory', '--output-dir', str(report)], capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        allowed = json.loads((report / 'allow.json').read_text())
        pending = json.loads((report / 'not-yet.json').read_text())
        self.assertEqual(allowed['history_scope'], pending['history_scope'])
        self.assertEqual(allowed['history_scope']['root'], str(self.work))
        self.assertEqual(allowed['totals']['unique_requests'], 0)
        self.assertIn('History scope: directory', result.stdout)
        invalid = subprocess.run(command + ['--scope', 'repo'], capture_output=True, text=True)
        self.assertEqual(invalid.returncode, 1)
        self.assertIn('requires a Git checkout', invalid.stderr)


class ToolReviewLauncherTests(unittest.TestCase):
    image = 'sha256:' + 'a' * 64

    def setUp(self):
        spec = importlib.util.spec_from_file_location('review_launcher', ROOT / 'scripts/review-codex-tools.py')
        self.launcher = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.launcher)
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.config = self.root / 'config' / 'images.conf'
        environment = mock.patch.dict(os.environ, {
            'NOSH_POLICY_REVIEW_UI_IMAGE': '',
            'NOSH_PROFILE_REVIEW_IMAGE_CONFIG': str(self.config),
        })
        environment.start()
        self.addCleanup(environment.stop)
        for name in self.launcher.INPUT_FILES:
            path = self.root / name
            path.write_text('{}' if name.endswith('.json') else 'sandbox_mode="read-only"')
            path.chmod(0o600)

    def test_digest_is_stable_and_changes_with_input(self):
        first = self.launcher.snapshot_digest(self.root)
        self.assertEqual(first, self.launcher.snapshot_digest(self.root))
        (self.root / 'allow.json').write_text('{"changed": true}')
        self.assertNotEqual(first, self.launcher.snapshot_digest(self.root))

    def test_rejects_nonprivate_and_linked_inputs(self):
        path = self.root / 'allow.json'
        path.chmod(0o644)
        with self.assertRaises(ValueError):
            self.launcher.snapshot_digest(self.root)
        path.chmod(0o600)
        path.rename(self.root / 'original.json')
        path.symlink_to(self.root / 'original.json')
        with self.assertRaises(ValueError):
            self.launcher.snapshot_digest(self.root)

    def test_launcher_uses_private_mounts_loopback_and_local_pinned_image(self):
        image = 'sha256:' + 'a' * 64
        calls = []
        def docker(*args):
            calls.append(args)
            if args[:2] == ('image', 'inspect'):
                return image + '|2'
            if args[0] == 'port':
                return '127.0.0.1:43123'
            if args[0] == 'inspect':
                return 'healthy'
            return 'container-id'
        with mock.patch.object(self.launcher.shutil, 'which', return_value='/usr/bin/docker'), \
                mock.patch.object(self.launcher, 'configured_image', return_value=image), \
                mock.patch.object(self.launcher, 'docker', side_effect=docker), \
                contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(self.launcher.launch(self.root, False), 0)
        run = next(args for args in calls if args[0] == 'run')
        self.assertIn('127.0.0.1::3000', run)
        self.assertEqual(run[run.index('--pull') + 1], 'never')
        self.assertEqual(run[-1], image)
        self.assertFalse(any('docker.sock' in arg or '.codex' in arg for arg in run))
        self.assertEqual(len([arg for arg in run if 'dst=/audit/' in arg and arg.endswith(',readonly')]), 5)
        session = json.loads(next((self.root / 'review').glob('runtime-*/session.json')).read_text())
        self.assertEqual(session['origin'], 'http://127.0.0.1:43123')
        self.assertEqual(session['snapshotDigest'], self.launcher.snapshot_digest(self.root))
        (self.root / 'allow.json').write_text('{"changed": true}')
        with mock.patch.object(self.launcher.shutil, 'which', return_value='/usr/bin/docker'), \
                mock.patch.object(self.launcher, 'configured_image', return_value=image), \
                mock.patch.object(self.launcher, 'docker', side_effect=docker):
            with self.assertRaisesRegex(ValueError, 'Audit changed'):
                self.launcher.launch(self.root, False)

    def test_failed_launch_cleans_container_and_token(self):
        image = 'sha256:' + 'a' * 64
        calls = []
        def docker(*args):
            calls.append(args)
            if args[:2] == ('image', 'inspect'):
                return image + '|2'
            if args[0] == 'port':
                return '0.0.0.0:43123'
            return ''
        with mock.patch.object(self.launcher.shutil, 'which', return_value='/usr/bin/docker'), \
                mock.patch.object(self.launcher, 'configured_image', return_value=image), \
                mock.patch.object(self.launcher, 'docker', side_effect=docker):
            with self.assertRaisesRegex(ValueError, 'loopback'):
                self.launcher.launch(self.root, False)
        self.assertTrue(any(args[0] == 'rm' for args in calls))
        self.assertFalse(list((self.root / 'review').glob('runtime-*')))

    def test_missing_docker_and_old_image_leave_reports_untouched(self):
        before = {p.name: p.read_bytes() for p in self.root.iterdir()}
        with mock.patch.object(self.launcher.shutil, 'which', return_value=None):
            with self.assertRaisesRegex(ValueError, 'Docker is required'):
                self.launcher.launch(self.root, False)
        with mock.patch.object(self.launcher.shutil, 'which', return_value='/usr/bin/docker'), \
                mock.patch.dict(os.environ, {'NOSH_POLICY_REVIEW_UI_IMAGE': self.image}), \
                mock.patch.object(self.launcher, 'configured_image', return_value='sha256:' + 'a' * 64), \
                mock.patch.object(self.launcher, 'docker', return_value='old-image|<no value>'):
            with self.assertRaisesRegex(ValueError, 'rebuild'):
                self.launcher.launch(self.root, False)
        self.assertEqual(before, {p.name: p.read_bytes() for p in self.root.iterdir()})

    def test_managed_image_is_resolved_and_remembered_without_a_build(self):
        with mock.patch.object(self.launcher, 'docker', return_value=self.image + '|2') as docker, \
                mock.patch.object(self.launcher, 'build_image') as build, \
                mock.patch('builtins.input') as prompt, contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(self.launcher.prepare_image(), self.image)
        self.assertEqual(docker.call_args.args[-1], self.launcher.MANAGED_IMAGE)
        self.assertEqual(self.launcher.configured_image(), self.image)
        self.assertEqual(stat.S_IMODE(self.config.stat().st_mode), 0o600)
        build.assert_not_called()
        prompt.assert_not_called()

    def test_other_launchers_still_require_configured_image_unless_opted_in(self):
        with self.assertRaisesRegex(ValueError, 'Set NOSH_POLICY_REVIEW_UI_IMAGE'):
            self.launcher.configured_image()
        self.assertEqual(self.launcher.configured_image(allow_missing=True), '')

    def test_explicit_pin_is_used_without_rewriting_configuration(self):
        with mock.patch.dict(os.environ, {'NOSH_POLICY_REVIEW_UI_IMAGE': self.image}), \
                mock.patch.object(self.launcher, 'docker', return_value=self.image + '|2') as docker, \
                mock.patch.object(self.launcher, 'build_image') as build:
            self.assertEqual(self.launcher.prepare_image(allow_build=True), self.image)
        self.assertEqual(docker.call_args.args[-1], self.image)
        self.assertFalse(self.config.exists())
        build.assert_not_called()

    def test_invalid_explicit_image_is_never_replaced_automatically(self):
        for image in ['mutable:tag', self.image]:
            with self.subTest(image=image), mock.patch.dict(os.environ, {'NOSH_POLICY_REVIEW_UI_IMAGE': image}), \
                    mock.patch.object(self.launcher, 'docker', return_value='old-image|<no value>'), \
                    mock.patch.object(self.launcher, 'build_image') as build:
                with self.assertRaisesRegex(ValueError, 'exact.*image ID'):
                    self.launcher.prepare_image(allow_build=True)
                build.assert_not_called()
                self.assertFalse(self.config.exists())

    def test_interactive_setup_builds_and_remembers_missing_or_outdated_ui(self):
        for previous in ['', 'sha256:' + 'b' * 64]:
            with self.subTest(previous=previous):
                self.config.parent.mkdir(mode=0o700, exist_ok=True)
                original = f'# retain tooling\nSCHEMA_VERSION=1\nNOSH_POLICY_TOOLING_IMAGE={self.image}\nNOSH_POLICY_REVIEW_UI_IMAGE={previous}\n'
                self.config.write_text(original)
                self.config.chmod(0o600)
                with mock.patch.object(self.launcher, 'docker', return_value='old-image|<no value>') as docker, \
                        mock.patch.object(self.launcher, 'build_image', return_value=self.image) as build, \
                        contextlib.redirect_stdout(io.StringIO()), \
                        mock.patch.object(self.launcher.sys.stdin, 'isatty', return_value=True), \
                        mock.patch.object(self.launcher.sys.stdout, 'isatty', return_value=True), \
                        mock.patch('builtins.input', return_value='') as prompt:
                    self.assertEqual(self.launcher.prepare_image(), self.image)
                build.assert_called_once_with()
                prompt.assert_called_once()
                self.assertEqual(docker.call_args_list[0].args[-1], previous or self.launcher.MANAGED_IMAGE)
                self.assertEqual(self.config.read_text(), original.replace(f'NOSH_POLICY_REVIEW_UI_IMAGE={previous}\n',
                                                                         f'NOSH_POLICY_REVIEW_UI_IMAGE={self.image}\n'))

    def test_declined_and_noninteractive_setup_leave_audit_untouched(self):
        before = {p.name: p.read_bytes() for p in self.root.iterdir()}
        for interactive, message in [(True, 'setup skipped'), (False, '--build-ui')]:
            with self.subTest(interactive=interactive), \
                    mock.patch.object(self.launcher.shutil, 'which', return_value='/usr/bin/docker'), \
                    mock.patch.object(self.launcher, 'docker', return_value='old-image|<no value>'), \
                    mock.patch.object(self.launcher, 'build_image') as build, \
                    contextlib.redirect_stdout(io.StringIO()), \
                    mock.patch.object(self.launcher.sys.stdin, 'isatty', return_value=interactive), \
                    mock.patch.object(self.launcher.sys.stdout, 'isatty', return_value=interactive), \
                    mock.patch('builtins.input', return_value='n') as prompt:
                with self.assertRaisesRegex(ValueError, message):
                    self.launcher.launch(self.root, False)
                build.assert_not_called()
                self.assertEqual(prompt.call_count, int(interactive))
            self.assertEqual(before, {p.name: p.read_bytes() for p in self.root.iterdir()})

    def test_daemon_failure_does_not_offer_a_build(self):
        with mock.patch.object(self.launcher, 'docker', side_effect=ValueError('Docker unavailable')), \
                mock.patch.object(self.launcher, 'build_image') as build, mock.patch('builtins.input') as prompt:
            with self.assertRaisesRegex(ValueError, 'Docker unavailable'):
                self.launcher.prepare_image(allow_build=True)
        build.assert_not_called()
        prompt.assert_not_called()
        self.assertFalse(self.config.exists())

    def test_build_option_continues_to_launch_same_saved_audit(self):
        before = self.launcher.snapshot_digest(self.root)
        def docker(*args):
            if args[:2] == ('image', 'inspect'):
                raise ValueError('missing image')
            if args[0] == 'port':
                return '127.0.0.1:43123'
            return 'healthy'
        with mock.patch.object(self.launcher.shutil, 'which', return_value='/usr/bin/docker'), \
                mock.patch.object(self.launcher, 'docker', side_effect=docker) as calls, \
                mock.patch.object(self.launcher, 'build_image', return_value=self.image) as build, \
                mock.patch('builtins.input') as prompt, contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(self.launcher.launch(self.root, False, build_ui=True), 0)
        build.assert_called_once_with()
        prompt.assert_not_called()
        run = next(call.args for call in calls.call_args_list if call.args[0] == 'run')
        self.assertEqual(run[-1], self.image)
        self.assertEqual(self.launcher.snapshot_digest(self.root), before)
        self.assertEqual(self.launcher.configured_image(), self.image)

    def test_failed_build_preserves_selection_and_audit(self):
        previous = 'sha256:' + 'b' * 64
        self.config.parent.mkdir(mode=0o700)
        self.config.write_text(f'SCHEMA_VERSION=1\nNOSH_POLICY_REVIEW_UI_IMAGE={previous}\n')
        self.config.chmod(0o600)
        before = self.launcher.snapshot_digest(self.root)
        with mock.patch.object(self.launcher.shutil, 'which', return_value='/usr/bin/docker'), \
                mock.patch.object(self.launcher, 'docker', return_value='old-image|<no value>'), \
                mock.patch.object(self.launcher.subprocess, 'run', return_value=subprocess.CompletedProcess([], 1)), \
                contextlib.redirect_stdout(io.StringIO()):
            with self.assertRaisesRegex(ValueError, 'build failed'):
                self.launcher.launch(self.root, False, build_ui=True)
        self.assertEqual(self.launcher.configured_image(), previous)
        self.assertEqual(self.launcher.snapshot_digest(self.root), before)
        self.assertFalse((self.root / 'review').exists())

    def test_build_uses_iidfile_and_checks_abi_before_remembering_image(self):
        for identity, inspected, succeeds in [(self.image, self.image + '|2', True),
                                              ('mutable:tag', self.image + '|2', False),
                                              (self.image, self.image + '|<no value>', False),
                                              (self.image, 'sha256:' + 'b' * 64 + '|2', False)]:
            with self.subTest(identity=identity, inspected=inspected):
                def run(args, **kwargs):
                    self.assertEqual(args[:3], ['docker', 'build', '--pull=false'])
                    self.assertEqual(args[-1], str(ROOT / 'policy-review'))
                    self.assertEqual(kwargs['env']['DOCKER_BUILDKIT'], '1')
                    Path(args[args.index('--iidfile') + 1]).write_text(identity + '\n')
                    return subprocess.CompletedProcess(args, 0)
                with mock.patch.object(self.launcher.subprocess, 'run', side_effect=run), \
                        mock.patch.object(self.launcher, 'docker', return_value=inspected) as docker:
                    if succeeds:
                        self.assertEqual(self.launcher.build_image(), self.image)
                        self.assertEqual(docker.call_args.args[-1], self.image)
                    else:
                        with self.assertRaises(ValueError):
                            self.launcher.build_image()
                self.assertFalse(self.config.exists())

    def test_tools_review_forwards_build_and_browser_options(self):
        binary = self.root / 'bin'
        binary.mkdir()
        python = binary / 'python3'
        python.write_text('#!/bin/bash\nprintf "%s\\0" "$@"\n')
        python.chmod(0o700)
        result = subprocess.run(['bash', str(ROOT / 'scripts/nosh-tools.sh'), 'review', '--review', str(self.root),
                                 '--build-ui', '--no-browser'], capture_output=True,
                                env={**os.environ, 'PATH': str(binary) + os.pathsep + os.environ['PATH']})
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.decode().split('\0')[:-1],
                         ['-B', str(ROOT / 'scripts/review-codex-tools.py'), str(self.root), '--build-ui', '--no-browser'])


if __name__ == '__main__':
    unittest.main()
