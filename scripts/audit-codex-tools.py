#!/usr/bin/env python3
"""Offline inventory of Codex tool requests; never replay or approve a request."""

import argparse
import ast
import collections
from datetime import datetime, timezone
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import shlex
import stat
import subprocess
import sys

SCHEMA_VERSION = 1
MAX_LINE = 64 * 1024 * 1024
SAMPLES = 3
SHELL_TOOLS = {'exec_command', 'shell_command', 'shell'}
READ_TOOLS = {'view_image', 'list_agents'}
WRITE_TOOLS = {'apply_patch', 'create_goal', 'update_goal', 'update_plan'}
PROCESS_TOOLS = {'write_stdin', 'send_input', 'wait', 'spawn_agent', 'send_message',
                 'followup_task', 'interrupt_agent', 'close_agent', 'wait_agent'}
NETWORK_COMMANDS = {'curl', 'wget', 'ssh', 'scp', 'sftp', 'rsync', 'gh', 'glab', 'nc', 'ncat'}
PROGRAM_COMMANDS = {'bash', 'sh', 'zsh', 'fish', 'dash', 'python', 'python3', 'node',
                    'perl', 'ruby', 'awk', 'gawk', 'xargs', 'eval', 'source'}
WRITE_COMMANDS = {'rm', 'mv', 'cp', 'mkdir', 'rmdir', 'touch', 'chmod', 'chown', 'ln',
                  'tee', 'install', 'truncate', 'dd', 'patch', 'sed'}
RUNTIME_COMMANDS = {'npm', 'npx', 'docker', 'podman', 'make', 'cmake', 'cargo', 'go',
                    'pytest', 'pip', 'pip3', 'sudo', 'systemctl', 'service', 'kill',
                    'pkill', 'tmux', 'codex', 'nosh', 'timeout', 'env', 'command'}


def options(short='', values='', long='', long_values=''):
    return set(short), set(values), set(long.split()), set(long_values.split())


# A positive catalogue of options, not a claim that executable names are safe.
# The filesystem/network sandbox remains mandatory, including for these forms.
OPTIONS = {
    'rg': options('nHiIlLovscwFxqSUuazP', 'e f g t T m A B C',
                  'files hidden no-ignore no-ignore-vcs no-ignore-parent no-config '
                  'line-number with-filename no-filename ignore-case smart-case '
                  'fixed-strings word-regexp line-regexp invert-match only-matching '
                  'count count-matches files-with-matches files-without-match '
                  'no-messages quiet null null-data text multiline multiline-dotall '
                  'pcre2 no-unicode stats json heading no-heading help version',
                  'glob iglob type type-not max-count after-context before-context '
                  'context max-depth max-filesize color colors sort sortr path-separator '
                  'regexp file encoding'),
    'grep': options('nHiIlLovscwFxqEzZarRbh', 'e f m A B C',
                    'line-number with-filename no-filename ignore-case fixed-strings '
                    'word-regexp line-regexp invert-match only-matching count '
                    'files-with-matches files-without-match no-messages quiet null '
                    'null-data text recursive dereference-recursive extended-regexp '
                    'help version',
                    'regexp file max-count after-context before-context context '
                    'include exclude exclude-dir color binary-files'),
    'diff': options('uUcrqsywiBEbtaTN', 'U C I L F W',
                    'brief report-identical-files recursive text ignore-case '
                    'ignore-all-space ignore-space-change ignore-blank-lines '
                    'strip-trailing-cr new-file help version',
                    'unified context ignore-matching-lines label width tabsize '
                    'exclude exclude-from'),
    'cmp': options('bls', 'i n', 'silent quiet verbose print-bytes help version',
                   'ignore-initial bytes'),
    'cat': options('AbEnstTuv', '', 'show-all number-nonblank show-ends number '
                   'squeeze-blank show-tabs show-nonprinting help version'),
    'head': options('qvz', 'c n', 'quiet silent verbose zero-terminated help version',
                    'bytes lines'),
    'tail': options('qvz', 'c n', 'quiet silent verbose zero-terminated help version',
                    'bytes lines'),
    'wc': options('cmlLw', '', 'bytes chars lines max-line-length words help version'),
    'ls': options('aAbBcCdDfFgGhHiIklLmNnoprRsStTuUvwxX1Q', 'I T w',
                  'all almost-all author directory human-readable inode literal '
                  'numeric-uid-gid recursive reverse size help version',
                  'color format sort time time-style quoting-style ignore hide '
                  'width tabsize block-size'),
    'pwd': options('LP', '', 'logical physical help version'),
    'stat': options('Lf t', 'c', 'dereference file-system terse help version', 'format printf'),
    'file': options('bhiLNr', '', 'brief mime mime-type mime-encoding dereference '
                    'no-dereference no-pad raw help version'),
    'readlink': options('efmnqsvz', '', 'canonicalize canonicalize-existing '
                        'canonicalize-missing no-newline quiet silent verbose zero help version'),
    'realpath': options('eLmPqsz', '', 'canonicalize-existing canonicalize-missing '
                        'logical physical quiet strip no-symlinks zero help version',
                        'relative-to relative-base'),
    'du': options('aBcdhHklLmPsSx', 'B d', 'all apparent-size bytes total '
                  'human-readable count-links summarize separate-dirs one-file-system '
                  'null help version', 'block-size max-depth exclude exclude-from'),
}
# Whitespace makes value-option catalogues readable above; it is not an option.
OPTIONS = {name: tuple({x for x in group if not x.isspace()} for group in groups)
           for name, groups in OPTIONS.items()}
GIT_OPTIONS = {
    'status': options('sbzu', '', 'short branch porcelain ignored untracked-files '
                      'ignore-submodules show-stash'),
    'log': options('puz', 'n', 'oneline all decorate no-decorate graph stat numstat '
                   'shortstat name-only name-status reverse no-merges merges '
                   'first-parent date-order author-date-order topo-order no-walk '
                   'no-ext-diff no-textconv',
                   'max-count skip since until after before author committer grep '
                   'format pretty date'),
    'show': options('puz', '', 'stat numstat shortstat name-only name-status '
                    'no-patch no-ext-diff no-textconv', 'format pretty'),
    'diff': options('pUuwbz', 'U', 'stat numstat shortstat name-only name-status '
                    'check cached staged quiet exit-code raw no-renames '
                    'ignore-all-space ignore-space-change ignore-blank-lines '
                    'no-ext-diff no-textconv'),
    'ls-files': options('zcsdmouikv', '', 'cached deleted modified others ignored '
                        'stage unmerged killed exclude-standard full-name error-unmatch',
                        'exclude exclude-from exclude-per-directory'),
    'ls-tree': options('drtzl', '', 'name-only name-status full-name full-tree'),
    'rev-parse': options('', '', 'show-toplevel show-prefix show-cdup git-dir '
                         'absolute-git-dir is-inside-work-tree is-bare-repository '
                         'verify quiet short abbrev-ref symbolic symbolic-full-name '
                         'show-object-format'),
    'describe': options('', '', 'all tags contains always long exact-match',
                        'abbrev candidates match exclude'),
    'branch': options('arv', '', 'all remotes verbose list show-current', 'contains merged no-merged'),
    'worktree list': options('vz', '', 'porcelain verbose expire'),
}
# These optional-value spellings accept the attached form only.
GIT_OPTIONAL_VALUES = {'status': {'porcelain', 'untracked-files', 'ignore-submodules', 'ignored'},
                       'rev-parse': {'short', 'abbrev-ref'}}
KNOWN_COMMANDS = (set(OPTIONS) | {'find', 'git'} | NETWORK_COMMANDS | PROGRAM_COMMANDS
                  | WRITE_COMMANDS | RUNTIME_COMMANDS)
KNOWN_TOOLS = SHELL_TOOLS | READ_TOOLS | WRITE_TOOLS | PROCESS_TOOLS | {
    'exec', 'run', 'request_user_input', 'request_user_input_async', 'get_goal',
    'list_mcp_resources', 'list_mcp_resource_templates', 'read_mcp_resource',
    'web_search_call', 'file_search_call', 'image_generation_call', 'computer_call',
    'local_shell_call', 'code_interpreter_call', 'mcp_call'}
SYSTEM_RULES = Path('/etc/codex/rules')
NON_REQUEST_ITEMS = {'message', 'reasoning', 'compaction', 'compaction_summary',
                     'tool_result', 'mcp_approval_response', 'ghost_snapshot', 'agent_message'}


def digest(value):
    return hashlib.sha256(value.encode('utf-8', errors='surrogatepass')).hexdigest()


def tool_label(name):
    if not isinstance(name, str):
        return 'unknown-tool'
    local = name.removeprefix('functions.')
    if local in KNOWN_TOOLS:
        return local
    if re.fullmatch(r'mcp__[a-zA-Z0-9_]{1,80}__[a-zA-Z0-9_]{1,80}', local):
        return local
    return 'unknown-tool-' + digest(name)[:12]


def result(category, form, reason):
    return category, form, reason


def literal_argv(command):
    """Accept a deliberately small literal shell grammar. No shell is invoked."""
    if isinstance(command, list):
        if command and all(isinstance(arg, str) and '\0' not in arg for arg in command):
            return command, None
        return None, 'invalid-argv'
    if not isinstance(command, str) or '\0' in command:
        return None, 'invalid-command'
    quote = None
    escaped = False
    for char in command.strip():
        if escaped:
            if char in '\r\n':
                return None, 'shell-continuation'
            escaped = False
            continue
        if quote == "'":
            if char == "'":
                quote = None
            continue
        if char == '\\':
            escaped = True
        elif char == quote:
            quote = None
        elif char in "'\"" and quote is None:
            quote = char
        elif char in '$`':
            return None, 'shell-expansion'
        elif quote is None and char in '<>':
            return None, 'shell-redirection'
        elif quote is None and char in ';|&()\r\n':
            return None, 'compound-shell'
        elif quote is None and char in '*?[{}~!#':
            return None, 'unreviewed-shell-syntax'
    if quote or escaped:
        return None, 'malformed-shell'
    try:
        args = shlex.split(command, comments=False, posix=True)
    except ValueError:
        return None, 'malformed-shell'
    return (args, None) if args else (None, 'empty-command')


def parse_options(args, spec, optional_values=()):
    switches, values, long_switches, long_values = spec
    flags, operands = set(), []
    i = 0
    while i < len(args):
        arg = args[i]
        if arg == '--':
            operands.extend(args[i + 1:])
            break
        if arg.startswith('--'):
            name, equals, value = arg[2:].partition('=')
            if name in long_values:
                if not equals:
                    i += 1
                    if i == len(args):
                        return None, None
                flags.add('--' + name)
            elif name in long_switches and (not equals or name in optional_values):
                flags.add('--' + name)
            else:
                return None, None
        elif arg.startswith('-') and arg != '-':
            for offset, flag in enumerate(arg[1:], 1):
                if flag in values:
                    if offset == len(arg) - 1:
                        i += 1
                        if i == len(args):
                            return None, None
                    flags.add('-' + flag)
                    break
                if flag not in switches:
                    return None, None
                flags.add('-' + flag)
        else:
            operands.append(arg)
        i += 1
    return flags, operands


def classify_find(args):
    no_value = {'-H', '-L', '-P', '-print', '-print0', '-ls', '-empty', '-true',
                '-false', '-readable', '-writable', '-executable', '-prune', '-quit',
                '-a', '-and', '-o', '-or', '!', '-not', '(', ')'}
    values = {'-name', '-iname', '-path', '-ipath', '-regex', '-iregex', '-type',
              '-maxdepth', '-mindepth', '-size', '-mtime', '-mmin', '-perm', '-user', '-group'}
    flags = set()
    expression = False
    i = 0
    while i < len(args):
        arg = args[i]
        if arg in {'-H', '-L', '-P'} and not expression:
            flags.add(arg)
        elif arg in no_value:
            flags.add(arg)
            expression = True
        elif arg in values:
            flags.add(arg)
            expression = True
            i += 1
            if i == len(args):
                return result('not-yet', 'find', 'incomplete-find-expression')
        elif arg.startswith('-') or expression:
            return result('not-yet', 'find', 'unreviewed-find-expression')
        i += 1
    return result('allow', 'find ' + ' '.join(sorted(flags)), 'local-inspection-in-sandbox')


def classify_git(args):
    flags = set()
    while args and args[0] in ('--no-pager', '--no-optional-locks', '-C'):
        flag, args = args[0], args[1:]
        flags.add(flag)
        if flag == '-C':
            if not args:
                return result('not-yet', 'git', 'incomplete-git-command')
            args = args[1:]
    if not args or args[0] not in GIT_OPTIONS and args[0] != 'worktree':
        return result('not-yet', 'git', 'unreviewed-git-command-or-global-option')
    subcommand, args = args[0], args[1:]
    if subcommand == 'worktree':
        if not args or args[0] != 'list':
            return result('not-yet', 'git worktree', 'worktree-mutation-or-unknown')
        subcommand, args = 'worktree list', args[1:]
    parsed, operands = parse_options(args, GIT_OPTIONS[subcommand],
                                    GIT_OPTIONAL_VALUES.get(subcommand, ()))
    if parsed is None:
        return result('not-yet', 'git ' + subcommand, 'unreviewed-git-option')
    if subcommand == 'branch' and operands and '--list' not in parsed:
        return result('not-yet', 'git branch', 'branch-creation-or-unknown')
    if subcommand == 'worktree list' and operands:
        return result('not-yet', 'git worktree list', 'unreviewed-git-operands')
    if subcommand in ('diff', 'log', 'show') and not {'--no-ext-diff', '--no-textconv'} <= parsed:
        return result('not-yet', 'git ' + subcommand, 'git-diff-helpers-not-disabled')
    return result('allow', 'git ' + subcommand + ' ' + ' '.join(sorted(flags | parsed)),
                  'local-inspection-in-sandbox')


def classify_command(command):
    args, error = literal_argv(command)
    if error:
        return result('not-yet', 'shell', error)
    executable = args[0]
    if re.match(r'^[A-Za-z_][A-Za-z0-9_]*=', executable):
        return result('not-yet', 'shell', 'environment-override')
    name = Path(executable).name
    if name not in KNOWN_COMMANDS:
        return result('not-yet', 'executable-' + digest(executable)[:12], 'unreviewed-executable')
    if executable not in (name, '/bin/' + name, '/usr/bin/' + name):
        return result('not-yet', name, 'custom-executable-path')
    if name in NETWORK_COMMANDS:
        return result('not-yet', name, 'network-access')
    if name in PROGRAM_COMMANDS:
        return result('not-yet', name, 'embedded-program-or-interpreter')
    if name in WRITE_COMMANDS:
        return result('not-yet', name, 'write-capable-command')
    if name in RUNTIME_COMMANDS:
        return result('not-yet', name, 'runtime-or-wrapper-needs-review')
    if name == 'git':
        return classify_git(args[1:])
    if name == 'find':
        return classify_find(args[1:])
    flags, operands = parse_options(args[1:], OPTIONS[name])
    if flags is None:
        return result('not-yet', name, 'unreviewed-option')
    return result('allow', name + ' ' + ' '.join(sorted(flags)), 'local-inspection-in-sandbox')


def classify_call(payload):
    tool = tool_label(payload.get('name'))
    if tool in SHELL_TOOLS:
        arguments = payload.get('arguments', payload.get('input'))
        if isinstance(arguments, str):
            try:
                arguments = json.loads(arguments)
            except ValueError:
                return tool, result('not-yet', 'shell', 'unparseable-tool-arguments')
        if not isinstance(arguments, dict):
            return tool, result('not-yet', 'shell', 'unsupported-tool-arguments')
        # Extra environment or explicit escalation requests need independent review.
        if set(arguments) - {'cmd', 'command', 'workdir', 'cwd', 'max_output_tokens',
                             'yield_time_ms', 'timeout_ms', 'login', 'tty',
                             'sandbox_permissions', 'prefix_rule', 'justification'}:
            return tool, result('not-yet', 'shell', 'unreviewed-tool-option')
        if arguments.get('sandbox_permissions') not in (None, 'use_default'):
            return tool, result('not-yet', 'shell', 'sandbox-escalation')
        if arguments.get('prefix_rule'):
            return tool, result('not-yet', 'shell', 'sandbox-rule-request')
        if ('cmd' in arguments) == ('command' in arguments):
            return tool, result('not-yet', 'shell', 'ambiguous-or-missing-command')
        return tool, classify_command(arguments.get('cmd', arguments.get('command')))
    if tool in READ_TOOLS:
        return tool, result('allow', tool, 'reviewed-inspection-tool')
    if tool == 'exec':
        reason = 'opaque-orchestration-code'
    elif tool in WRITE_TOOLS:
        reason = 'state-mutation'
    elif tool in PROCESS_TOOLS:
        reason = 'process-or-agent-control'
    elif tool.startswith('mcp__'):
        reason = 'mcp-semantics-not-reviewed'
    else:
        reason = 'tool-semantics-not-reviewed'
    return tool, result('not-yet', tool, reason)


def source_label(relative):
    text = str(relative)
    if re.fullmatch(r'(?:sessions|archived_sessions)/(?:\d{4}/\d{2}/\d{2}/)?'
                    r'rollout-[0-9TZ:.-]+-[0-9a-f-]{36}\.jsonl', text):
        return text
    return 'source-' + digest(text)[:16]


def regular_files(directory, suffix, errors):
    if directory.is_symlink():
        errors['symlink-directories'] += 1
        return
    if not directory.is_dir():
        return
    def onerror(_):
        errors['unreadable-directories'] += 1
    for base, dirs, files in os.walk(directory, followlinks=False, onerror=onerror):
        for name in list(dirs):
            if (Path(base) / name).is_symlink():
                dirs.remove(name)
                errors['symlink-directories'] += 1
        dirs.sort()
        for name in sorted(files):
            if name.endswith(suffix):
                yield Path(base) / name


def open_regular(path):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    if not stat.S_ISREG(os.fstat(fd).st_mode):
        os.close(fd)
        raise OSError('not a regular file')
    return os.fdopen(fd, 'rb')


def request_digest(payload):
    transport = {'id', 'call_id', 'status', 'internal_chat_message_metadata_passthrough'}
    return digest(json.dumps({key: value for key, value in payload.items() if key not in transport},
                             sort_keys=True, ensure_ascii=True))


def is_request(payload):
    if not isinstance(payload, dict):
        return False
    kind = payload.get('type')
    return isinstance(kind, str) and (kind.endswith('_call') or kind == 'tool_use')


class ScopeError(ValueError):
    pass


def history_scope(kind, cwd):
    root = cwd.expanduser().resolve()
    if not root.is_dir():
        raise ScopeError('Working directory does not exist')
    excluded_roots = []
    if kind == 'repo':
        result = subprocess.run(['git', '-C', str(root), 'rev-parse', '--show-toplevel'],
                                capture_output=True, text=True, timeout=10)
        if result.returncode:
            raise ScopeError('Repository scope requires a Git checkout; choose directory or all')
        root = Path(result.stdout.strip()).resolve()
        worktrees = subprocess.run(['git', '-C', str(root), 'worktree', 'list', '--porcelain', '-z'],
                                   capture_output=True, text=True, timeout=10)
        if worktrees.returncode:
            raise ScopeError('Cannot inspect Git worktrees; choose directory scope instead')
        for field in worktrees.stdout.split('\0'):
            if field.startswith('worktree '):
                other = Path(field[9:]).resolve()
                if other != root and other.is_relative_to(root):
                    excluded_roots.append(str(other))
    return {'kind': kind, 'root': None if kind == 'all' else str(root), 'dates': 'all',
            'excluded_roots': sorted(excluded_roots)}


def choose_history_scope(cwd):
    try:
        repo = history_scope('repo', cwd)
    except (OSError, ValueError, subprocess.SubprocessError):
        repo = None
    print('Tool history scope (all recorded dates):')
    print('  1 This directory and subdirectories: ' + str(cwd.resolve()))
    print('  2 This Git checkout' + (': ' + repo['root'] if repo else ' (unavailable)'))
    print('  3 All recorded history (active and archived sessions)')
    default = '1'
    while True:
        answer = input(f'Scope [{default}] (q to cancel): ').strip() or default
        if answer.lower() == 'q':
            return None
        if answer == '2' and repo:
            return repo
        if answer in ('1', '3'):
            return history_scope('directory' if answer == '1' else 'all', cwd)
        print('Choose an available scope or q.')


def recorded_directory(value):
    if not isinstance(value, str) or not value.startswith('/') or '\0' in value:
        return None
    # Historical paths may no longer exist. Normalize lexically, without
    # consulting today's symlinks or reconstructing commands from their text.
    return Path(os.path.normpath(value))


def scan_history(home, selection=None, evidence=None):
    stats = collections.Counter()
    errors = collections.Counter()
    groups = {'allow': {}, 'not-yet': {}}
    sources = []
    seen = set()
    identities = {}
    sessions, workspaces = set(), set()
    for folder in ('sessions', 'archived_sessions'):
        directory = home / folder
        if folder == 'sessions' and not directory.exists():
            errors['missing-' + folder] += 1
        for path in regular_files(directory, '.jsonl', errors):
            label = source_label(path.relative_to(home))
            source = {'source': label, 'requests': 0, 'errors': {}}
            source_errors = collections.Counter()
            sources.append(source)
            stats['source_files'] += 1
            session = None
            recorded_cwd = None
            try:
                with open_regular(path) as stream:
                    remaining = os.fstat(stream.fileno()).st_size
                    source['snapshot_bytes'] = remaining
                    line_number = 0
                    while remaining:
                        raw = stream.readline(min(remaining, MAX_LINE + 1))
                        if not raw:
                            source_errors['file-shortened'] += 1
                            break
                        remaining -= len(raw)
                        line_number += 1
                        if len(raw) > MAX_LINE:
                            while raw and not raw.endswith(b'\n') and remaining:
                                raw = stream.readline(min(remaining, MAX_LINE))
                                remaining -= len(raw)
                            source_errors['oversized-records'] += 1
                            continue
                        try:
                            row = json.loads(raw)
                        except (ValueError, UnicodeError, RecursionError):
                            source_errors['malformed-records'] += 1
                            continue
                        if not isinstance(row, dict):
                            source_errors['non-object-records'] += 1
                            continue
                        stats['records'] += 1
                        if row.get('type') == 'session_meta':
                            meta = row.get('payload')
                            recorded_cwd = None
                            if isinstance(meta, dict):
                                if isinstance(meta.get('id'), str):
                                    session = digest(meta['id'])
                                    sessions.add(session)
                                recorded_cwd = recorded_directory(meta.get('cwd'))
                                if isinstance(meta.get('cwd'), str):
                                    workspaces.add(digest(meta['cwd']))
                            continue
                        if row.get('type') == 'turn_context':
                            context = row.get('payload')
                            recorded_cwd = recorded_directory(context.get('cwd')) if isinstance(context, dict) else None
                            continue
                        if row.get('type') == 'response_item':
                            payload = row.get('payload')
                        else:
                            payload = row
                        if not is_request(payload):
                            if row.get('type') == 'response_item':
                                kind = payload.get('type') if isinstance(payload, dict) else None
                                if not isinstance(kind, str) or (kind not in NON_REQUEST_ITEMS and not kind.endswith('_output')):
                                    source_errors['unsupported-response-items'] += 1
                                else:
                                    stats['non_request_response_items'] += 1
                            continue
                        stats['observed_requests'] += 1
                        if recorded_cwd is None:
                            stats['unattributed_requests'] += 1
                        if selection and selection['kind'] != 'all':
                            if recorded_cwd is None:
                                source_errors['requests-without-working-directory'] += 1
                                continue
                            if (not recorded_cwd.is_relative_to(Path(selection['root']))
                                    or any(recorded_cwd.is_relative_to(Path(root)) for root in selection.get('excluded_roots', []))):
                                stats['out_of_scope_requests'] += 1
                                continue
                        stats['raw_requests'] += 1
                        source['requests'] += 1
                        call_id = payload.get('call_id') or payload.get('id')
                        if isinstance(call_id, str) and session:
                            identity = digest(session + '\0' + call_id)
                            fingerprint = request_digest(payload)
                            key = bytes.fromhex(digest(identity + fingerprint))
                            if key in seen:
                                stats['duplicate_requests'] += 1
                                continue
                            seen.add(key)
                            if identity in identities and identities[identity] != fingerprint:
                                stats['conflicting_call_versions'] += 1
                            identities[identity] = fingerprint
                        else:
                            stats['requests_without_dedup_identity'] += 1
                        stats['unique_requests'] += 1
                        if payload.get('type') not in ('function_call', 'custom_tool_call', 'tool_use'):
                            stats['native_tool_requests'] += 1
                            tool = tool_label(payload.get('type'))
                            category, form, reason = 'not-yet', tool, 'native-tool-semantics-not-reviewed'
                        else:
                            tool, (category, form, reason) = classify_call(payload)
                        form = form.strip()
                        stats[category + '_requests'] += 1
                        key = (tool, form, reason)
                        group = groups[category].setdefault(key, dict(tool=tool, form=form,
                                    reason=reason, count=0, examples=[]))
                        group['count'] += 1
                        if evidence is not None:
                            evidence.add(payload, tool, category, form, reason, recorded_cwd, label, line_number)
                        if len(group['examples']) < SAMPLES:
                            group['examples'].append({'source': label, 'line': line_number})
                    if os.fstat(stream.fileno()).st_size != source['snapshot_bytes']:
                        source_errors['file-size-changed'] += 1
            except OSError:
                source_errors['unreadable-or-nonregular-files'] += 1
            source['errors'] = dict(source_errors)
            errors.update(source_errors)
    for key in ('raw_requests', 'unique_requests', 'duplicate_requests', 'allow_requests', 'not-yet_requests'):
        stats.setdefault(key, 0)
    assert stats['raw_requests'] == stats['unique_requests'] + stats['duplicate_requests']
    assert stats['unique_requests'] == stats['allow_requests'] + stats['not-yet_requests']
    stats['sessions'] = len(sessions)
    stats['workspaces'] = len(workspaces)
    return stats, errors, groups, sources


def audit_rules(home, cwd):
    directories = [home / 'rules', SYSTEM_RULES]
    directories += [p / '.codex/rules' for p in (cwd, *cwd.parents)]
    entries, seen, errors = [], set(), collections.Counter()
    for directory in directories:
        for path in regular_files(directory, '.rules', errors):
            if path in seen:
                continue
            seen.add(path)
            source = ('user/rules/default.rules' if path == home / 'rules/default.rules'
                      else 'rules-' + digest(str(path))[:16])
            try:
                with open_regular(path) as stream:
                    data = stream.read(1024 * 1024 + 1)
                if len(data) > 1024 * 1024:
                    raise ValueError('oversized')
                tree = ast.parse(data)
            except (OSError, ValueError, SyntaxError, RecursionError):
                errors['unreadable-or-unparseable-rules'] += 1
                continue
            for node in ast.walk(tree):
                if not isinstance(node, ast.Call):
                    continue
                if not isinstance(node.func, ast.Name) or node.func.id != 'prefix_rule':
                    errors['unsupported-rule-code'] += 1
                    continue
                fields = {kw.arg: kw.value for kw in node.keywords}
                try:
                    pattern = ast.literal_eval(fields['pattern'])
                    decision = ast.literal_eval(fields['decision']) if 'decision' in fields else 'allow'
                    if not isinstance(pattern, list) or not pattern or decision not in ('allow', 'prompt', 'forbidden'):
                        raise ValueError('invalid rule')
                except (KeyError, ValueError, TypeError, RecursionError):
                    errors['unsupported-rule-code'] += 1
                    continue
                name = pattern[0] if isinstance(pattern[0], str) else '<alternatives>'
                if name not in KNOWN_COMMANDS:
                    name = 'executable-' + digest(json.dumps(name))[:12]
                entries.append({'source': source, 'line': node.lineno, 'executable': name,
                                'prefix_tokens': len(pattern), 'decision': decision,
                                'needs_review': decision == 'allow',
                                'reason': 'sandbox-escape-allow' if decision == 'allow' else 'restrictive-rule'})
    return {'entries': entries, 'errors': dict(errors),
            'scope': 'User, system, and current-directory ancestor rule files; trust and managed remote policy are not resolved.'}


PLANNING_CONFIG = '''# Proposed profile only. Review inherited allow rules before using it.
# ~/.codex/planning.config.toml; select with: codex --profile planning
sandbox_mode = "read-only"
approval_policy = "never"
'''
IMPLEMENTATION_CONFIG = '''# Proposed profile only. Review inherited allow rules before using it.
# ~/.codex/implementation.config.toml; select with: codex --profile implementation
sandbox_mode = "workspace-write"
approval_policy = "on-request"

[sandbox_workspace_write]
network_access = false
'''


def write_private(path, content):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'w', encoding='utf-8') as stream:
        stream.write(content)


def make_private_parents(path):
    # Path.mkdir(parents=True) applies mode only to the final component. Nosh
    # also expects a newly created XDG state directory to be private.
    missing = []
    cursor = path
    while not cursor.exists():
        missing.append(cursor)
        cursor = cursor.parent
    for directory in reversed(missing):
        try:
            directory.mkdir(mode=0o700)
        except FileExistsError:
            if directory.is_symlink() or not directory.is_dir():
                raise


def run(home, output, cwd, selection=None, request_details=False):
    home, cwd = home.resolve(), cwd.resolve()
    if not home.is_dir() or not (home / 'sessions').is_dir():
        raise ValueError('Codex home must contain a sessions directory')
    output = output.absolute()
    if output.resolve() != output:
        raise ValueError('output path must not traverse symlinks')
    repository = Path(__file__).resolve().parents[1]
    if output.is_relative_to(repository) or output.is_relative_to(home):
        raise ValueError('reports must be outside the repository and Codex home')
    make_private_parents(output.parent)
    output.mkdir(mode=0o700)  # Refuse to overwrite an earlier report.
    print('Scanning session files; no historical requests will be executed.', file=sys.stderr, flush=True)
    selection = selection or history_scope('all', cwd)
    print(f"History scope: {selection['kind']} — {selection['root'] or 'all available sessions'}; all recorded dates", flush=True)
    evidence = None
    if request_details:
        spec = importlib.util.spec_from_file_location('tool_request_evidence', Path(__file__).with_name('tool-request-evidence.py'))
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        evidence = module.Evidence(output)
    try:
        stats, errors, groups, sources = scan_history(home, selection, evidence)
        descriptor = evidence.finish() if evidence is not None else None
    except BaseException:
        if evidence is not None:
            evidence.abort()
        raise
    rules = audit_rules(home, cwd)
    complete = not errors and not rules['errors']
    common = {'schema_version': SCHEMA_VERSION, 'complete': complete, 'totals': dict(stats),
              'errors': dict(errors), 'sources': sources,
              'history_scope': {**selection, 'excluded_requests': stats['out_of_scope_requests'],
                                'unattributed_requests': stats['unattributed_requests']},
              'scope': 'Reviewed inspection candidates inside a sandbox, not executable permission rules. '
                       'Opaque orchestration and unsupported syntax stay not-yet. Examples contain no arguments.'}
    if descriptor:
        common['schema_version'] = 2
        common['request_evidence'] = descriptor
    for category in groups:
        entries = sorted(groups[category].values(), key=lambda g: (-g['count'], g['tool'], g['form'], g['reason']))
        write_private(output / (category + '.json'), json.dumps(dict(common, category=category, entries=entries), indent=2) + '\n')
    write_private(output / 'rules-review.json', json.dumps(rules, indent=2) + '\n')
    write_private(output / 'planning.config.toml', PLANNING_CONFIG)
    write_private(output / 'implementation.config.toml', IMPLEMENTATION_CONFIG)
    lines = ['Codex tool history audit', '', f'Complete snapshot: {complete}',
             f'Session files scanned: {stats["source_files"]}', f'Raw requests: {stats["raw_requests"]}',
             f'Duplicates: {stats["duplicate_requests"]}', f'Unique requests: {stats["unique_requests"]}',
             f'Allow (sandboxed inspection): {stats["allow_requests"]}',
             f'Not yet (review required): {stats["not-yet_requests"]}',
             f'Existing sandbox-escape allows to review: {sum(e["needs_review"] for e in rules["entries"])}', '',
             f"History scope: {selection['kind']} ({selection['root'] or 'all available sessions'}); all recorded dates",
             f"Out-of-scope requests: {stats['out_of_scope_requests']}; unattributed requests: {stats['unattributed_requests']}",
             'Scope uses recorded working directories, not files touched by commands.',
             'Counts describe recorded requests, not successful executions or approvals.',
             'No historical requests were executed. No active config or rules were changed.',
             'The allow inventory is NOT a set of prefix_rule(decision="allow") entries.',
             'Inherited allow rules may bypass the sandbox, even with a planning profile.',
             'Review rules-review.json before installing either proposed profile.',
             'Plan mode and permission-profile selection are separate: select the profile explicitly.',
             'No live sandbox enforcement has been verified by this offline audit.',
             'MCP/remote tools are not confined by local shell filesystem settings.',
             'No network shell commands are automatically approved.',
             'References use relative rollout filenames and 1-based lines; other filenames are hashed.',
             'Deduplication requires a session ID and call ID; unkeyed calls are retained.',
             'Parsing errors, changed files, and unreadable input make the snapshot incomplete.', '',
             'Top allow forms:']
    for group in sorted(groups['allow'].values(), key=lambda g: -g['count'])[:25]:
        lines.append(f'  {group["count"]:8d}  {group["form"]} ({group["tool"]})')
    lines += ['', 'Not-yet reasons:']
    reasons = collections.Counter()
    for group in groups['not-yet'].values():
        reasons[group['reason']] += group['count']
    lines += [f'  {count:8d}  {reason}' for reason, count in reasons.most_common()]
    if errors or rules['errors']:
        lines += ['', 'Input issues:', json.dumps(dict(errors), sort_keys=True),
                  'Rule issues: ' + json.dumps(rules['errors'], sort_keys=True)]
    write_private(output / 'summary.txt', '\n'.join(lines) + '\n')
    print('\n'.join(lines[:10]))
    print(f"Out-of-scope requests: {stats['out_of_scope_requests']}; unattributed requests: {stats['unattributed_requests']}")
    if stats['unique_requests'] == 0:
        print('No matching tool requests were found in the selected history scope.')
    print(f'Reports: {output}')
    if descriptor:
        print(f"Distinct requests: {descriptor['uniqueRequests']}; original inputs saved privately in {output / descriptor['file']}")
    return 0 if complete else 2


def open_review_ui(output):
    launcher = Path(__file__).resolve().with_name('review-codex-tools.py')
    result = subprocess.run([sys.executable, '-B', str(launcher), str(output)])
    if result.returncode:
        print('UI launch did not complete. Saved reports and terminal review remain available.')
    return result.returncode


def review_reports(output):
    """Browse the saved, redacted inventory without changing active policy."""
    reports = {
        '1': ('rules-review.json', 'Review original rules at these source/line references; '
              'decide whether to keep, narrow, remove, prompt, or forbid each rule.'),
        '2': ('not-yet.json', 'Classify forms as inspection, workspace writes, network/external '
              'effects, or unknown. Use example references to inspect payloads locally.'),
        '3': ('allow.json', 'These forms are inspection candidates INSIDE a sandbox. '
              'Do not turn this inventory into sandbox-escape allow rules.'),
    }
    print('\nReview only: no historical commands will run and no active policy will change.')
    try:
        while True:
            print('\nNext action:\n'
                  '  1  Review existing sandbox-escape rules (start here)\n'
                  '  2  Review pending command/tool groups\n'
                  '  3  Review sandboxed inspection groups\n'
                  '  4  Compare read-only and workspace-write profiles\n'
                  '  5  Open review UI (select proposed read/write permissions)\n'
                  '  q  Finish (default)')
            choice = input('Choose [1-5/q]: ').strip().lower()
            if choice in ('', 'q'):
                return
            if choice == '5':
                open_review_ui(output)
            elif choice == '4':
                for name in ('planning.config.toml', 'implementation.config.toml'):
                    print('\n' + name + '\n' + (output / name).read_text())
                print('Before installing: review inherited rules, then validate each profile '
                      'in a fresh session using disposable files. Test workspace writes, '
                      'outside-workspace writes, and network access. Review MCP permissions '
                      'separately; local shell sandbox settings do not constrain remote tools.')
            elif choice in reports:
                filename, guidance = reports[choice]
                report = json.loads((output / filename).read_text())
                print('\n' + guidance)
                print('Report: ' + str(output / filename))
                entries = report['entries']
                if not entries:
                    print('No entries.')
                for start in range(0, len(entries), 25):
                    # JSON escaping keeps history-derived control characters inert.
                    print(json.dumps(entries[start:start + 25], indent=2, ensure_ascii=True))
                    if start + 25 < len(entries):
                        if input('Enter for next 25; m for menu: ').strip().lower() != '':
                            break
            else:
                print('Choose 1, 2, 3, 4, 5, or q.')
    except (EOFError, KeyboardInterrupt):
        print('\nReview closed; saved reports are unchanged.')


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__,
        prog='nosh tools init' if '--init' in (sys.argv[1:] if argv is None else argv) else None)
    parser.add_argument('--init', action='store_true', help=argparse.SUPPRESS)
    parser.add_argument('--scope', choices=('repo', 'directory', 'all'))
    parser.add_argument('--workdir', type=Path, default=Path.cwd())
    parser.add_argument('--codex-home', type=Path,
                        default=Path(os.environ.get('CODEX_HOME', str(Path.home() / '.codex'))))
    state = Path(os.environ.get('XDG_STATE_HOME', str(Path.home() / '.local/state')))
    stamp = datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ') + '-' + str(os.getpid())
    parser.add_argument('--output-dir', type=Path, default=state / 'nosh/codex-tool-audit' / stamp)
    parser.add_argument('--no-prompt', action='store_true',
                        help='write reports and exit without the interactive review menu')
    parser.add_argument('--request-details', choices=('original', 'none'), default=None,
                        help='capture original unique inputs (default: original for nosh tools init, none for legacy script)')
    parser.add_argument('--review-ui', type=Path, metavar='REPORT_DIR',
                        help='open the review UI for an existing report without rescanning')
    args = parser.parse_args(argv)
    try:
        if args.review_ui:
            return open_review_ui(args.review_ui.expanduser())
        output = args.output_dir.expanduser()
        cwd = args.workdir.expanduser().resolve()
        interactive = sys.stdin.isatty() and sys.stdout.isatty() and not args.no_prompt
        if args.scope:
            selection = history_scope(args.scope, cwd)
        elif args.init:
            if not interactive:
                parser.error('nosh tools init requires --scope repo|directory|all when prompts are disabled')
            selection = choose_history_scope(cwd)
            if selection is None:
                return 0
        else:
            selection = history_scope('all', cwd)
        status = run(args.codex_home.expanduser(), output, cwd, selection,
                     request_details=args.request_details == 'original' or (args.request_details is None and args.init))
        if not args.no_prompt and sys.stdin.isatty() and sys.stdout.isatty():
            if status == 2:
                print('Snapshot incomplete: resolve input issues in summary.txt before relying on it.')
            review_reports(output)
        return status
    except (EOFError, KeyboardInterrupt):
        print('Audit initialization cancelled.')
        return 130
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        # Paths and parse exceptions can contain private history/config values.
        print('codex tool audit: ' + (str(error) if isinstance(error, ScopeError) else type(error).__name__) + '; check input paths and use a new private output directory', file=sys.stderr)
        return 1


if __name__ == '__main__':
    sys.exit(main())
