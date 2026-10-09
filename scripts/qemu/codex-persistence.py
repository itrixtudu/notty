#!/usr/bin/env python3
"""Opt-in real VM test. Uses synthetic Codex state, never the operator's profile."""
import argparse
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

import session

PROBE = r'''
import errno, fcntl, json, os, pathlib, sqlite3
home = pathlib.Path(os.environ['CODEX_HOME'])
mode, phase = __import__('sys').argv[1:]
history = home / 'history.jsonl'
if phase == 'write':
    with history.open('a') as stream:
        stream.write('{"fixture":"qemu-codex-persistence"}\n')
        stream.flush()
        os.fsync(stream.fileno())
    for directory in ('sessions', 'archived_sessions'):
        (home / directory).mkdir(exist_ok=True)
        temporary = home / directory / 'new'
        temporary.write_text('fixture')
        temporary.replace(home / directory / 'fixture.jsonl')
        (home / directory / 'symlink').symlink_to('fixture.jsonl')
else:
    assert 'qemu-codex-persistence' in history.read_text()
    for directory in ('sessions', 'archived_sessions'):
        assert (home / directory / 'symlink').read_text() == 'fixture'
with (home / 'fixture.lock').open('a') as stream:
    fcntl.flock(stream, fcntl.LOCK_EX | fcntl.LOCK_NB)
    with sqlite3.connect(home / 'fixture.sqlite') as database:
        assert database.execute('pragma journal_mode=WAL').fetchone()[0] == 'wal'
        database.execute('pragma mmap_size=1048576')
        database.execute('create table if not exists fixture(value text)')
        if phase == 'write':
            database.execute('insert into fixture values (?)', ('persistent',))
        else:
            assert database.execute('select value from fixture').fetchone()[0] == 'persistent'
paths = [(home / 'auth.json', False)]
for root in (home / 'skills', home / 'plugins', pathlib.Path.home() / '.agents/skills',
             pathlib.Path.cwd() / '.agents/skills', pathlib.Path.cwd() / '.codex/skills'):
    paths.append((root / 'fixture-write', mode == 'rw'))
paths += [(home / 'config.toml', mode == 'rw'), (pathlib.Path.cwd() / 'AGENTS.md', mode == 'rw')]
for path, writable in paths:
    try:
        with path.open('a') as stream:
            stream.write('fixture\n')
        assert writable, f'unexpected write permitted: {path}'
    except OSError as error:
        assert not writable and error.errno in (errno.EROFS, errno.EACCES, errno.EPERM), (path, error)
if mode == 'rw':
    temporary = home / 'config.pending'
    temporary.write_text('model=\"fixture\"\n')
    temporary.replace(home / 'config.toml')
print(json.dumps({'history': 'persistent', 'sqlite': 'wal+mmap', 'resources': mode, 'credentials': 'ro'}))
'''


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--accel', choices=('kvm', 'tcg'), default='kvm')
    args = parser.parse_args()
    # Prerequisites before creating any fixture state.
    session.preflight(session.parse_args(['start', '--accel', args.accel]))
    root = Path(tempfile.mkdtemp(prefix='nosh-qemu-codex-test-'))
    success = False
    try:
        home, workspace = root / 'home', root / 'project'
        profile = home / '.codex'
        profile.mkdir(parents=True, mode=0o700)
        workspace.mkdir(mode=0o700)
        (profile / 'auth.json').write_text('{}\n')
        (profile / 'history.jsonl').write_text('{"fixture":"host-existing"}\n')
        state_root = root / 'state'
        state = state_root / 'fixture'
        environment = {**os.environ, 'HOME': str(home), 'CODEX_HOME': str(profile)}
        base = [sys.executable, str(Path(session.__file__)), '--name', 'fixture', '--state-dir', str(state_root)]

        def command(action, *extra):
            subprocess.run([*base, action, *extra], env=environment, check=True)

        def start(mode):
            command('start', '--detach', '--workdir', str(workspace), '--codex-home', str(profile), '--accel', args.accel,
                    '--agent-skills', mode, '--agent-settings', mode, '--agent-plugins', mode)

        def probe(mode, phase):
            status = session.live_status(state)
            guest = session.SessionGuest(session.parse_args(['attach']), {}, state, Path(status['runtime']),
                                         json.loads((state / 'session.json').read_text()))
            guest.port = status['port']
            result = guest.ssh(['docker', 'exec', '--workdir', str(workspace), 'nosh-qemu-codex',
                                'python3', '-c', PROBE, mode, phase])
            print(result.stdout.decode(), end='', flush=True)

        try:
            start('ro')
            probe('ro', 'write')
            try:
                session.codex.ProfileLock(profile, 'must-conflict')
            except ValueError as error:
                assert 'already in use' in str(error)
            else:
                raise AssertionError('VM did not retain the host profile lease')
            command('stop')
            assert 'qemu-codex-persistence' in (profile / 'history.jsonl').read_text()
            start('ro')
            probe('ro', 'read')
            command('stop')
            command('reset')
            start('rw')
            probe('rw', 'read')
            command('stop')
            assert (profile / 'auth.json').read_text() == '{}\n'
            print(f'PASS: {args.accel}; host → QEMU → Docker persistence, restart/reset, permissions, SQLite and locking')
            success = True
        finally:
            current = session.live_status(state)
            if current['status'] in ('running', 'starting', 'stopping'):
                command('stop')
            if session.live_status(state)['status'] == 'unreachable':
                # Do not delete files that an unreachable VM may still hold.
                raise RuntimeError(f'supervisor unreachable; retain fixture for recovery: {root}')

    finally:
        if success:
            shutil.rmtree(root)
        else:
            print(f'codex-persistence: retained fixture and logs: {root}', file=sys.stderr)


if __name__ == '__main__':
    try:
        main()
    except (ValueError, OSError, session.vm.HarnessError) as error:
        print(f'codex-persistence: {error}', file=sys.stderr)
        sys.exit(2)
