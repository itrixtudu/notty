#!/usr/bin/env python3
"""Codex resource policy and lifetime locks. No package manager or Node on host."""
import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import time
import signal
import shutil

ROOT = Path(__file__).resolve().parents[1]
RESOURCES = json.loads((ROOT / 'config/codex-resources.json').read_text())['resources']


def canonical(value, uid=None):
    path = Path(os.path.abspath(value))
    if path.resolve() != path or any(c in str(path) for c in ':,\n\r\0\t'):
        raise ValueError(f'expected a canonical mount-safe path: {path}')
    if path.exists():
        info = path.stat()
        if uid is not None and info.st_uid != uid:
            raise ValueError(f'path must belong to the invoking user: {path}')
        if info.st_mode & 0o002:
            raise ValueError(f'world-writable resource refused: {path}')
    return path


def policy(home, codex, workspace, modes, prepare=False, uid=None, target_home=None):
    uid = os.getuid() if uid is None else uid
    roots = {key: canonical(value, uid) for key, value in
             [('home', home), ('codex', codex), ('workspace', workspace)]}
    if not roots['codex'].is_dir():
        raise ValueError('initialize the Codex profile on the host first')
    if any(roots['workspace'] == p or roots['workspace'] in p.parents
           or p in roots['workspace'].parents for p in [roots['codex'], roots['home'] / '.agents']):
        raise ValueError('workspace must not overlap Codex state or shared skills')
    if roots['workspace'] == roots['home'] or roots['workspace'] in roots['home'].parents:
        raise ValueError('sharing the home directory or its ancestors as a workspace is refused')
    modes = {key: modes.get(key, 'ro') for key in ('skills', 'settings', 'plugins')}
    if any(value not in ('ro', 'rw') for value in modes.values()):
        raise ValueError('agent resource modes must be ro or rw')
    target_home = Path(target_home or home)
    targets = {'home': target_home, 'codex': target_home / '.codex', 'workspace': roots['workspace']}
    mounts = []
    for entry in RESOURCES:
        source = canonical(roots[entry['root']] / entry['path'], uid)
        if entry.get('optional') and not source.exists():
            continue
        if prepare and not source.exists():
            source.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            if entry['kind'] == 'directory':
                source.mkdir(mode=0o700)
            else:
                fd = os.open(source, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
                with os.fdopen(fd, 'w') as stream:
                    stream.write(entry.get('initial', ''))
        if source.exists() and source.is_file() and source.stat().st_nlink != 1:
            raise ValueError(f'hard-linked protected file refused: {source}')
        if source.exists() and (source.is_dir() != (entry['kind'] == 'directory')
                                or not (source.is_dir() or source.is_file())):
            raise ValueError(f'invalid resource type: {source}')
        mode = 'ro' if entry['category'] == 'credentials' else modes[entry['category']]
        # Files that are writable stay on the parent bind, allowing atomic rename.
        if mode == 'rw' and entry['kind'] == 'file':
            continue
        mounts.append(dict(source=str(source), target=str(targets[entry['root']] / entry['path']),
                           mode=mode, category=entry['category'], kind=entry['kind']))
    return dict(version=1, home=str(roots['home']), codex=str(roots['codex']),
                workspace=str(roots['workspace']), modes=modes, resources=mounts)


def validate_binds(result, binds):
    """Reject alternate writable aliases and mounts that hide a protection."""
    protected = [Path(result['codex']), Path(result['home']) / '.agents']
    allowed = {(result['codex'], str(Path(result['home']) / '.codex')),
               (result['workspace'], result['workspace'])}
    resources = result['resources']
    allowed.update((r['source'], r['target']) for r in resources)
    for bind in binds:
        fields = bind.split(':')
        if len(fields) not in (2, 3):
            raise ValueError('invalid bind mount')
        source, target = fields[:2]
        if (source, target) in allowed:
            continue
        src, dst = canonical(source), Path(target)
        if any(src == p or src in p.parents or p in src.parents for p in protected):
            raise ValueError(f'additional mount exposes Codex state: {source}')
        for entry in resources:
            p, q = Path(entry['source']), Path(entry['target'])
            if src == p or src in p.parents or p in src.parents or dst == q or dst in q.parents or q in dst.parents:
                raise ValueError(f'additional mount overlaps a protected resource: {source}')


def wait_container(container):
    while True:
        result = subprocess.run(['docker', 'inspect', '--format', '{{.State.Running}}', container],
                                capture_output=True, text=True)
        if result.returncode == 0 and result.stdout.strip() == 'false':
            return
        if result.returncode and 'No such' in result.stderr:
            return
        if result.returncode == 0:
            subprocess.run(['docker', 'wait', container], stdout=subprocess.DEVNULL,
                           stderr=subprocess.DEVNULL)
        else:
            time.sleep(5)


def launch(args):
    """Detached worker owns both launch reservation and container lifetime."""
    if not args.worker:
        command = [sys.executable, __file__, 'launch', '--worker', '--codex-home', args.codex_home,
                   '--uid', str(args.uid), '--', *args.argv]
        worker = subprocess.Popen(command, start_new_session=True, stdin=subprocess.DEVNULL,
                                  stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
        line = worker.stdout.readline()
        worker.stdout.close()
        if not line:
            raise ValueError('Codex lease worker exited before launch')
        result = json.loads(line)
        if result['error']:
            print(result['error'], file=sys.stderr)
        return result['status']
    lock = None
    try:
        signal.signal(signal.SIGHUP, signal.SIG_IGN)
        lock = ProfileLock(args.codex_home, 'docker', args.uid)
        result = subprocess.run(args.argv, capture_output=True, text=True)
        if result.returncode:
            raise ValueError(result.stderr.strip() or 'container launch failed')
        container = result.stdout.strip()
        # docker start returns a name; resolve an immutable ID before monitoring.
        while len(container) != 64 or any(c not in '0123456789abcdef' for c in container):
            inspected = subprocess.run(['docker', 'inspect', '--format', '{{.Id}}', container],
                                       capture_output=True, text=True)
            if inspected.returncode == 0:
                container = inspected.stdout.strip()
                if len(container) != 64 or any(c not in '0123456789abcdef' for c in container):
                    raise ValueError('Docker did not return an immutable container ID')
            elif 'No such' in inspected.stderr:
                raise ValueError('launched container no longer exists')
            else:
                # The command succeeded; retain its reservation through outages.
                time.sleep(5)
        try:
            print(json.dumps({'status': 0, 'error': ''}), flush=True)
        except BrokenPipeError:
            pass
        os.dup2(os.open(os.devnull, os.O_WRONLY), 1)
        wait_container(container)
        return 0
    except (ValueError, OSError, subprocess.SubprocessError) as error:
        print(json.dumps({'status': 2, 'error': str(error)}), flush=True)
        return 2
    finally:
        if lock:
            lock.close()


class ProfileLock:
    def __init__(self, profile, owner, uid=None):
        uid = os.getuid() if uid is None else uid
        profile = canonical(profile, uid)
        if not profile.is_dir():
            raise ValueError('Codex profile is not a directory')
        # Use the same location from ordinary Nosh, Guard and QEMU, independent
        # of XDG overrides. Never unlink a lock inode while a peer may hold it.
        root = Path(f'/tmp/nosh-codex-locks-{uid}')
        try:
            root.mkdir(mode=0o700)
            if os.getuid() == 0 and uid != 0:
                os.chown(root, uid, -1)
        except FileExistsError:
            pass
        info = root.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != uid or stat.S_IMODE(info.st_mode) != 0o700:
            raise ValueError('unsafe Codex lock directory')
        key = hashlib.sha256(str(profile).encode()).hexdigest()
        directory_fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            opened = os.fstat(directory_fd)
            if (opened.st_dev, opened.st_ino) != (info.st_dev, info.st_ino):
                raise ValueError('Codex lock directory changed')
            try:
                self.fd = os.open(key, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                                  0o600, dir_fd=directory_fd)
                if os.getuid() == 0:
                    os.fchown(self.fd, uid, -1)
            except FileExistsError:
                self.fd = os.open(key, os.O_RDWR | os.O_NOFOLLOW, dir_fd=directory_fd)
        finally:
            os.close(directory_fd)
        info = os.fstat(self.fd)
        if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_uid != uid
                or stat.S_IMODE(info.st_mode) != 0o600):
            os.close(self.fd)
            raise ValueError('unsafe Codex lock file')
        try:
            fcntl.flock(self.fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            os.close(self.fd)
            raise ValueError(f'Codex profile already in use: {profile}') from None
        os.ftruncate(self.fd, 0)
        os.write(self.fd, json.dumps({'pid': os.getpid(), 'owner': owner}).encode())
        try:
            reject_active_writers(profile, uid)
        except BaseException:
            os.close(self.fd)
            raise

    def close(self):
        os.close(self.fd)


def reject_active_writers(profile, uid):
    """Best effort for native CLIs; managed launches also share the flock."""
    for entry in Path('/proc').iterdir():
        if not entry.name.isdigit():
            continue
        try:
            if entry.stat().st_uid != uid or Path(os.readlink(entry / 'exe')).name != 'codex':
                continue
            values = dict(item.split(b'=', 1) for item in (entry / 'environ').read_bytes().split(b'\0') if b'=' in item)
            home = values.get(b'CODEX_HOME') or values.get(b'HOME', b'') + b'/.codex'
            if Path(os.fsdecode(home)).resolve() == profile:
                raise ValueError('stop the native Codex CLI using this profile before launching Nosh')
        except (OSError, PermissionError):
            continue
    if shutil.which('docker'):
        running = subprocess.run(['docker', 'ps', '-q', '--no-trunc'], capture_output=True, text=True, timeout=15)
        if running.returncode:
            # QEMU does not need a host Docker daemon. Managed peers are still
            # excluded by flock even while the daemon is unavailable.
            return
        for container in running.stdout.split():
            result = subprocess.run(['docker', 'inspect', container], capture_output=True, text=True, timeout=15)
            if result.returncode == 0:
                for mount in json.loads(result.stdout)[0].get('Mounts', []):
                    if mount.get('RW') and Path(mount.get('Source', '/')).resolve() == profile:
                        raise ValueError('a running Docker container already mounts this Codex profile')


def lease(args):
    lock = ProfileLock(args.codex_home, args.container, args.uid)
    print('locked', flush=True)
    # Parent sends the immutable container ID after successful creation. EOF
    # before that releases the reservation without touching any container.
    container = sys.stdin.readline().strip()
    if len(container) != 64 or any(c not in '0123456789abcdef' for c in container):
        lock.close()
        return 1
    try:
        wait_container(container)
    finally:
        lock.close()
    return 0


def main():
    parser = argparse.ArgumentParser()
    # Keep Docker's arguments outside this parser (they may contain our flags).
    argv = sys.argv[1:]
    command_argv = []
    if '--' in argv:
        split = argv.index('--')
        argv, command_argv = argv[:split], argv[split + 1:]
    parser.add_argument('command', choices=('policy', 'lease', 'launch'))
    parser.add_argument('--worker', action='store_true')
    parser.add_argument('--bind', action='append', default=[])
    parser.add_argument('--home', default=str(Path.home()))
    parser.add_argument('--codex-home', required=True)
    parser.add_argument('--workspace')
    parser.add_argument('--target-home')
    parser.add_argument('--skills', default='ro', choices=('ro', 'rw'))
    parser.add_argument('--settings', default='ro', choices=('ro', 'rw'))
    parser.add_argument('--plugins', default='ro', choices=('ro', 'rw'))
    parser.add_argument('--prepare', action='store_true')
    parser.add_argument('--tsv', action='store_true')
    parser.add_argument('--container', default='nosh')
    parser.add_argument('--uid', type=int, default=os.getuid())
    args = parser.parse_args(argv)
    args.argv = command_argv
    try:
        if args.command == 'lease':
            return lease(args)
        if args.command == 'launch':
            return launch(args)
        if not args.workspace:
            raise ValueError('--workspace is required')
        result = policy(args.home, args.codex_home, args.workspace, vars(args), False,
                        args.uid, args.target_home)
        validate_binds(result, args.bind)
        if args.prepare:
            reservation = ProfileLock(args.codex_home, 'prepare', args.uid)
            try:
                result = policy(args.home, args.codex_home, args.workspace, vars(args), True,
                                args.uid, args.target_home)
            finally:
                reservation.close()
        if args.tsv:
            for entry in result['resources']:
                print('\t'.join(entry[key] for key in ('source', 'target', 'mode')))
        else:
            print(json.dumps(result))
        return 0
    except (ValueError, OSError) as error:
        print(f'codex-state: {error}', file=sys.stderr)
        return 2


if __name__ == '__main__':
    sys.exit(main())
