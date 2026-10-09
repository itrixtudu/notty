#!/usr/bin/env python3
"""Persistent, user-owned QEMU sessions. Host state is never copied into a disk."""
import argparse
import fcntl
import importlib.util
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import socket
import stat
import subprocess
import sys
import tempfile
import threading
import time

import harness as vm

spec = importlib.util.spec_from_file_location('codex_state', vm.REPOSITORY / 'scripts/codex-state.py')
codex = importlib.util.module_from_spec(spec)
spec.loader.exec_module(codex)
GUEST_HOME = Path('/home/noshqemu')


def write_json(path, value):
    fd, name = tempfile.mkstemp(prefix=path.name + '-', dir=path.parent)
    temporary = Path(name)
    try:
        with os.fdopen(fd, 'w') as stream:
            stream.write(json.dumps(value, indent=2) + '\n')
        temporary.replace(path)
    finally:
        temporary.unlink(missing_ok=True)


def validate_state_files(state):
    for entry in state.iterdir():
        try:
            info = entry.lstat()
        except FileNotFoundError:
            continue
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
                or info.st_nlink != 1 or info.st_mode & 0o022):
            raise ValueError(f'unsafe persistent session file: {entry}')


def virtiofs_binary():
    for name in ('virtiofsd', '/usr/libexec/virtiofsd', '/usr/lib/qemu/virtiofsd'):
        found = shutil.which(name)
        if found:
            return found
    raise ValueError('install the Rust virtiofsd package (rootless --uid-map support is required)')


def preflight(args):
    result = vm.doctor(args)
    if result['status'] != 'ready':
        raise ValueError(result['hint'])
    binary = virtiofs_binary()
    help_text = subprocess.check_output([binary, '--help'], text=True)
    for flag in ('--uid-map', '--gid-map', '--translate-uid', '--translate-gid',
                 '--sandbox', '--readonly', '--cache'):
        if flag not in help_text:
            raise ValueError(f'virtiofsd lacks {flag}; install a current Rust virtiofsd')
    return binary


def exports_for(config):
    exports = [dict(source=config['workspace'], target=config['workspace'], tag='workspace'),
               dict(source=config['codex'], target=str(GUEST_HOME / '.codex'), tag='codex'),
               dict(source=str(Path(config['home']) / '.agents/skills'),
                    target=str(GUEST_HOME / '.agents/skills'), tag='skills')]
    repo, work = Path(config['repository']), Path(config['workspace'])
    if repo == work or work in repo.parents:
        repository = str(repo)
    else:
        repository = '/opt/nosh-source'
        exports.append(dict(source=str(repo), target=repository, tag='source', readonly=True))
    return exports, repository


class SessionGuest(vm.Guest):
    def __init__(self, args, manifest, state, runtime, config):
        super().__init__(args, manifest, state, runtime)
        self.config = config
        self.exports, self.repository = exports_for(config)
        self.paths['disk'] = state / 'guest.qcow2'
        self.paths['seed'] = state / 'seed.img'
        self.paths['serial'] = state / 'serial.log'

    def cloud_config(self, public_key, private_key, host_key):
        data = json.loads(vm.cloud_config(self.manifest, public_key, private_key, host_key).split('\n', 1)[1])
        data['groups'] = [{'noshqemu': []}]
        data['users'][0]['uid'] = self.config['uid']
        # Explicit group ID avoids assuming all host primary groups equal UIDs.
        data['bootcmd'].insert(0, ['groupadd', '-g', str(self.config['gid']), 'noshqemu'])
        data['users'][0]['primary_group'] = 'noshqemu'
        return '#cloud-config\n' + json.dumps(data) + '\n'

    def qemu_command(self):
        command = super().qemu_command()
        command[command.index('-machine') + 1] = 'q35,memory-backend=sharedmem'
        command += ['-object', f'memory-backend-memfd,id=sharedmem,size={self.args.memory_mib}M,share=on']
        for entry in self.exports:
            tag = entry['tag']
            command += ['-chardev', f'socket,id=fs-{tag},path={vm.qemu_path(self.runtime / (tag + ".sock"))}',
                        '-device', f'vhost-user-fs-pci,chardev=fs-{tag},tag={tag}']
        return command

    def initialize_persistent(self, image):
        if self.paths['disk'].exists():
            for name in ('identity', 'identity.pub', 'guest-host', 'guest-host.pub'):
                shutil.copyfile(self.run_dir / name, self.runtime / name)
                (self.runtime / name).chmod(0o600)
            return
        super().initialize(image)
        for name in ('identity', 'identity.pub', 'guest-host', 'guest-host.pub'):
            shutil.copyfile(self.runtime / name, self.run_dir / name)
            (self.run_dir / name).chmod(0o600)

    def mount_exports(self):
        for entry in self.exports:
            self.ssh(['sudo', '-n', 'mkdir', '-p', '--', entry['target']])
            self.ssh(['sudo', '-n', 'mount', '-t', 'virtiofs', '-o',
                      'ro' if entry.get('readonly') else 'rw', entry['tag'], entry['target']])
        # Check actual guest-side ownership before passing files to Docker.
        self.ssh(['test', '-w', str(GUEST_HOME / '.codex')])

    def start_nosh(self):
        log = self.run_dir / 'install.log'
        vm.print_log_hint('image build and container launch', log)
        image = 'nosh-qemu-codex'
        exists = self.ssh(['bash', '-c', f'docker image inspect {image} >/dev/null 2>&1 && echo yes || echo no'])
        if exists.stdout.strip() != b'yes':
            self.ssh(['env', 'USERNAME=noshqemu', f'USER_UID={self.config["uid"]}',
                      f'USER_GID={self.config["gid"]}', f'IMAGE_NAME={image}',
                      'bash', self.repository + '/scripts/build-nosh.sh'], log_path=log)
        command = ['bash', self.repository + '/scripts/nosh.sh', 'start', '--security-mode', 'legacy',
                   '--workdir', self.config['workspace'], '--agents', 'codex', '--codex-home',
                   str(GUEST_HOME / '.codex'), '--name', 'nosh-qemu-codex', '--image', image,
                   '--detach', '--no-start-app', '--no-collab']
        for category, mode in self.config['modes'].items():
            command += ['--agent-' + category, mode]
        self.ssh(command, log_path=log)


def state_lock(state):
    fd = os.open(state / 'session.lock', os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    info = os.fstat(fd)
    if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_nlink != 1 or info.st_mode & 0o022:
        os.close(fd)
        raise ValueError('unsafe persistent session lock')
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        os.close(fd)
        raise ValueError('session is already active; use attach, status, or stop') from None
    return fd


def serve(args, state):
    session_fd = args.lock_fd if args.lock_fd is not None else state_lock(state)
    opened, expected = os.fstat(session_fd), (state / 'session.lock').stat()
    if (opened.st_dev, opened.st_ino) != (expected.st_dev, expected.st_ino):
        raise ValueError('invalid inherited session lock')
    config = json.loads((state / 'session.json').read_text())
    lock, guest, daemons = None, None, []
    stop = threading.Event()
    runtime = Path(tempfile.mkdtemp(prefix='nosh-qemu-'))
    status = dict(status='starting', name=args.name, stage='profile-lock', runtime=str(runtime))
    control = socket.socket(socket.AF_UNIX)
    control.bind(str(runtime / 'control.sock'))
    control.listen(4)
    control.settimeout(1)

    def publish(stage):
        status['stage'] = stage
        write_json(state / 'status.json', status)
        print(f'nosh-qemu: {stage}', flush=True)
        if stop.is_set():
            raise ValueError('session stopped during startup')

    def respond():
        while not stop.is_set():
            try:
                connection, _ = control.accept()
            except socket.timeout:
                continue
            except OSError:
                return
            with connection:
                connection.settimeout(5)
                try:
                    command = connection.recv(32).decode().strip()
                    if command == 'stop':
                        stop.set()
                    connection.sendall(json.dumps(status).encode() + b'\n')
                except (OSError, UnicodeError):
                    pass

    thread = threading.Thread(target=respond, daemon=True)
    thread.start()
    try:
        publish('profile-lock')
        lock = codex.ProfileLock(config['codex'], 'qemu:' + args.name)
        # Prepare only after reserving the profile; no auth/history is copied.
        codex.policy(config['home'], config['codex'], config['workspace'], config['modes'], prepare=True)
        publish('download-image')
        manifest = vm.validate_manifest(json.loads(vm.MANIFEST.read_text()))
        image = vm.download_image(manifest['image'], state.parent / 'cache')
        guest = SessionGuest(args, manifest, state, runtime, config)
        # QEMU retains both locks if the supervisor dies unexpectedly. Never
        # admit another writer or reset its disk while that VM remains alive.
        guest.inherited_fds = (lock.fd, session_fd)
        guest.cancel_requested = stop.is_set
        guest.initialize_persistent(image)
        publish('exports')
        for entry in guest.exports:
            path = runtime / (entry['tag'] + '.sock')
            command = [config['virtiofsd'], '--socket-path', str(path), '--shared-dir', entry['source'],
                       '--sandbox', 'namespace', '--cache', 'auto',
                       f'--uid-map=:{config["uid"]}:{config["uid"]}:1:',
                       f'--gid-map=:{config["gid"]}:{config["gid"]}:1:',
                       # Guest Docker runs as root. Translate only its requests
                       # to the host caller; reported ownership remains UID/GID
                       # of the caller for the unprivileged agent container.
                       f'--translate-uid=guest:0:{config["uid"]}:1',
                       f'--translate-gid=guest:0:{config["gid"]}:1']
            if entry.get('readonly'):
                command += ['--readonly']
            with open(state / 'virtiofs.log', 'ab') as output:
                proc = vm.start_process(command, stdin=subprocess.DEVNULL, stdout=output, stderr=subprocess.STDOUT)
            daemons.append(proc)
            deadline = time.monotonic() + 20
            while not path.exists():
                if proc.poll() is not None or time.monotonic() > deadline:
                    raise ValueError('rootless virtiofsd failed; see virtiofs.log (user namespaces must be enabled)')
                time.sleep(0.1)
        publish('boot')
        guest.boot()
        status['port'] = guest.port
        publish('mounts')
        guest.mount_exports()
        publish('container')
        guest.start_nosh()
        status['status'] = 'running'
        publish('ready')
        while not stop.wait(1):
            if guest.proc.poll() is not None or any(proc.poll() is not None for proc in daemons):
                raise ValueError('QEMU or virtiofsd exited; inspect serial.log and virtiofs.log')
        status['status'] = 'stopping'
        write_json(state / 'status.json', status)
        guest.ssh(['docker', 'stop', '--time', '30', 'nosh-qemu-codex'], timeout=45)
        guest.shutdown()
        status['status'] = 'stopped'
    except BaseException as error:
        status.update(status='failed', error=str(error))
        print(f'nosh-qemu: {error}', flush=True)
    finally:
        stop.set()
        control.close()
        if guest:
            guest.close()
        if (runtime / 'qemu.log').exists():
            shutil.copyfile(runtime / 'qemu.log', state / 'qemu.log')
        for proc in daemons:
            vm.terminate_process(proc)
        if lock:
            lock.close()
        shutil.rmtree(runtime)
        status.pop('runtime', None)
        write_json(state / 'status.json', status)
        os.close(session_fd)


def live_status(state, command='status'):
    saved = json.loads((state / 'status.json').read_text()) if (state / 'status.json').exists() else {'status': 'stopped'}
    if 'runtime' not in saved:
        return saved
    try:
        with socket.socket(socket.AF_UNIX) as connection:
            connection.settimeout(5)
            connection.connect(str(Path(saved['runtime']) / 'control.sock'))
            connection.sendall(command.encode())
            return json.loads(connection.recv(65536))
    except (OSError, ValueError):
        return dict(saved, status='unreachable')


def parse_args(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('command', nargs='?', default='start',
                        choices=('start', 'attach', 'stop', 'status', 'reset', '_serve'),
                        help='start or attach to the session (default: start)')
    parser.add_argument('--name', help='session name (default: <workspace-directory>-qemu)')
    parser.add_argument('--detach', action='store_true', help='start without attaching a shell')
    parser.add_argument('--workdir', default=os.getcwd(), help='workspace directory (default: current directory)')
    parser.add_argument('--codex-home', default=os.environ.get('CODEX_HOME', str(Path.home() / '.codex')))
    parser.add_argument('--agents', choices=('codex',), default='codex')
    for category in ('skills', 'settings', 'plugins'):
        parser.add_argument('--agent-' + category, choices=('ro', 'rw'), default='ro')
    parser.add_argument('--accel', choices=('kvm', 'tcg'), default='kvm')
    parser.add_argument('--cpus', type=int, default=4)
    parser.add_argument('--memory-mib', type=int, default=8192)
    parser.add_argument('--disk-gib', type=int, default=64)
    parser.add_argument('--boot-timeout', type=int)
    parser.add_argument('--timeout', type=int, default=7200)
    parser.add_argument('--state-dir', type=Path, default=Path(os.environ.get('XDG_STATE_HOME', str(Path.home() / '.local/state'))) / 'nosh/qemu')
    parser.add_argument('--lock-fd', type=int, help=argparse.SUPPRESS)
    args = parser.parse_args(argv)
    if args.name is None:
        directory = Path(os.path.abspath(args.workdir)).name.lower()
        slug = re.sub(r'[^a-z0-9_-]+', '-', directory).strip('-_') or 'workspace'
        args.name = slug[:43] + '-qemu'
    if not re.fullmatch('[a-zA-Z0-9][a-zA-Z0-9_-]{0,47}', args.name) or args.name == 'cache':
        parser.error('invalid session name')
    args.boot_timeout = args.boot_timeout or (600 if args.accel == 'kvm' else 1800)
    if min(args.cpus, args.memory_mib, args.disk_gib, args.boot_timeout, args.timeout) < 1:
        parser.error('resource sizes and deadlines must be positive')
    return args


def main(argv=None):
    args = parse_args(argv)
    os.umask(0o077)
    state = vm.secure_directory(vm.secure_directory(args.state_dir) / args.name)
    validate_state_files(state)
    if args.command == '_serve':
        serve(args, state)
        return 0
    if args.command == 'status':
        print(json.dumps(live_status(state), indent=2))
        return 0
    if args.command == 'stop':
        current = live_status(state, 'stop')
        deadline = time.monotonic() + 180
        while current['status'] in ('running', 'starting', 'stopping'):
            if time.monotonic() > deadline:
                raise ValueError('stop still pending; inspect status and session.log')
            time.sleep(1)
            current = live_status(state)
        print(json.dumps(current, indent=2))
        return 0 if current['status'] == 'stopped' else 1
    if args.command == 'reset':
        fd = state_lock(state)
        try:
            # Never remove a lock inode; another process may already have opened it.
            known = {'session.lock', 'session.json', 'status.json', 'guest.qcow2', 'seed.img',
                     'identity', 'identity.pub', 'guest-host', 'guest-host.pub',
                     'serial.log', 'virtiofs.log', 'session.log', 'install.log', 'qemu.log'}
            if any(entry.name not in known or entry.is_dir() for entry in state.iterdir()):
                raise ValueError('reset refused: session directory contains unmanaged files')
            if not (state / 'session.json').exists():
                raise ValueError('reset refused: no managed session configuration')
            for entry in state.iterdir():
                if entry.name == 'session.lock':
                    continue
                entry.unlink()
        finally:
            os.close(fd)
        print('nosh-qemu: VM reset; shared host workspace and Codex history retained')
        return 0
    if args.command == 'start' and live_status(state)['status'] != 'running':
        binary = preflight(args)
        fd = state_lock(state)
        try:
            modes = {key: getattr(args, 'agent_' + key) for key in ('skills', 'settings', 'plugins')}
            policy = codex.policy(str(Path.home()), args.codex_home, args.workdir, modes)
            config = {key: policy[key] for key in ('home', 'codex', 'workspace', 'modes')}
            config.update(uid=os.getuid(), gid=os.getgid(), repository=str(vm.REPOSITORY), virtiofsd=binary)
            existing = state / 'session.json'
            if existing.exists() and json.loads(existing.read_text()) != config:
                raise ValueError('session workspace/profile/access changed; reset this stopped VM or use a new --name')
            write_json(existing, config)
        except BaseException:
            os.close(fd)
            raise
        command = [sys.executable, __file__, '_serve', '--name', args.name, '--state-dir', str(args.state_dir)]
        command += ['--lock-fd', str(fd)]
        for key in ('accel', 'cpus', 'memory_mib', 'disk_gib', 'boot_timeout', 'timeout'):
            command += ['--' + key.replace('_', '-'), str(getattr(args, key))]
        with open(state / 'session.log', 'ab') as output:
            child = subprocess.Popen(command, start_new_session=True, stdin=subprocess.DEVNULL,
                                     stdout=output, stderr=subprocess.STDOUT, pass_fds=(fd,))
        os.close(fd)
        print(f'nosh-qemu: watch startup: {shlex.join(["tail", "-n", "80", "-F", "--", str(state / "session.log")])}', flush=True)
        deadline = time.monotonic() + args.boot_timeout + args.timeout + 300
        while time.monotonic() < deadline:
            current = live_status(state)
            if current['status'] == 'running':
                break
            if child.poll() is not None:
                raise ValueError(f'session startup failed; see {state / "session.log"}')
            time.sleep(1)
        else:
            raise ValueError('startup deadline exceeded; inspect status or stop the session')
    if args.command == 'start' and args.detach:
        print(f'nosh-qemu: ready; attach with nosh --qemu attach --name {args.name}')
        return 0
    current = live_status(state)
    if current['status'] != 'running':
        raise ValueError('session is not ready; use start or inspect status')
    runtime = Path(current['runtime'])
    guest = SessionGuest(args, {}, state, runtime, json.loads((state / 'session.json').read_text()))
    guest.port = current['port']
    print('nosh-qemu: exit detaches; stop ends the VM. Host Codex history remains persistent.', flush=True)
    return subprocess.call(['ssh', *guest.ssh_options(), '-tt', '-p', str(guest.port), 'noshqemu@127.0.0.1',
                            shlex.join(['docker', 'exec', '-it', '--user', f'{os.getuid()}:{os.getgid()}',
                                        '--workdir', guest.config['workspace'], 'nosh-qemu-codex', '/bin/bash'])])


if __name__ == '__main__':
    try:
        sys.exit(main())
    except (ValueError, OSError, vm.HarnessError) as error:
        print(f'nosh-qemu: {error}', file=sys.stderr)
        sys.exit(2)
