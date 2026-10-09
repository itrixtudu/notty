#!/usr/bin/env python3
"""Disposable, opt-in QEMU integration environment. Python standard library only."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import shlex
import shutil
import signal
import socket
import stat
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone


REPOSITORY = Path(__file__).resolve().parents[2]
MANIFEST = REPOSITORY / "config/qemu-test.json"
GUEST_HOME = "/home/noshqemu"
REQUIRED_TOOLS = ("qemu-system-x86_64", "qemu-img", "cloud-localds", "ssh",
                  "scp", "ssh-keygen", "git")
TOOL_PACKAGES = {"qemu-system-x86_64": "qemu-system-x86", "qemu-img": "qemu-utils",
                 "cloud-localds": "cloud-image-utils", "ssh": "openssh-client",
                 "scp": "openssh-client", "ssh-keygen": "openssh-client", "git": "git"}
GUEST_FILES = ("guest.sh", "terminal-smoke.mjs", "guard-scenarios.mjs", "guest-fixture.py")
GUEST_MAC = "52:54:00:12:34:56"


class HarnessError(Exception):
    def __init__(self, message, status=1):
        super().__init__(message)
        self.status = status


def sha256_file(path):
    digest = hashlib.sha256()
    with open(path, "rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def secure_directory(path):
    path = Path(os.path.abspath(path))
    for component in [*reversed(path.parents), path]:
        if component.is_symlink():
            raise HarnessError(f"refusing symlink directory: {component}")
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    metadata = path.stat()
    if (not stat.S_ISDIR(metadata.st_mode) or metadata.st_uid != os.getuid()
            or metadata.st_mode & 0o022):
        raise HarnessError(f"directory must be caller-owned and private: {path}")
    return path


def validate_manifest(data):
    if not isinstance(data, dict) or data.get("version") != 1:
        raise HarnessError("unsupported QEMU manifest version", 2)
    image = data.get("image", {})
    if not isinstance(image, dict):
        raise HarnessError("invalid image manifest", 2)
    if (image.get("architecture") != "amd64" or image.get("format") != "qcow2"
            or not re.fullmatch(r"[a-f0-9]{64}", str(image.get("sha256", "")))
            or not str(image.get("url", "")).startswith("https://cloud-images.ubuntu.com/")
            or not image.get("release")):
        raise HarnessError("image must pin an Ubuntu amd64 qcow2 HTTPS URL and SHA-256", 2)
    guest = data.get("guest", {})
    if not isinstance(guest, dict) or not re.fullmatch(
            r"\d{8}T\d{6}Z", str(guest.get("aptSnapshot", ""))):
        raise HarnessError("guest requires an immutable Ubuntu apt snapshot", 2)
    packages = guest.get("packages", {})
    if not isinstance(packages, dict) or not {"docker.io", "docker-buildx", "git",
                                             "python3", "curl", "ca-certificates"} <= packages.keys():
        raise HarnessError("guest package pins are incomplete", 2)
    for name, version in packages.items():
        if (not re.fullmatch(r"[a-z0-9][a-z0-9+.-]*", name)
                or not re.fullmatch(r"[A-Za-z0-9.+:~_-]+", str(version))):
            raise HarnessError("invalid guest package pin", 2)
    return data


def terminate_process(proc):
    """Only signal a session created and retained by this harness."""
    if getattr(proc, "_nosh_qemu_closed", False):
        return
    if not getattr(proc, "_nosh_qemu_owned", False):
        raise HarnessError("refusing to terminate an unowned process")
    try:
        os.killpg(proc.pid, signal.SIGTERM)
    except ProcessLookupError:
        pass
    try:
        proc.wait(timeout=3)
    except subprocess.TimeoutExpired:
        pass
    # The session leader can exit while descendants still hold pipes open.
    try:
        os.killpg(proc.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    proc.wait(timeout=5)
    proc._nosh_qemu_closed = True


def start_process(argv, **kwargs):
    proc = subprocess.Popen([str(value) for value in argv], start_new_session=True, **kwargs)
    proc._nosh_qemu_owned = True
    return proc


def run_command(argv, timeout, cwd=None, log_path=None):
    log_path = Path(os.path.abspath(log_path)) if log_path else None
    log = open(log_path, "ab") if log_path else None
    proc = None
    try:
        proc = start_process(argv, cwd=cwd, stdin=subprocess.DEVNULL,
                             stdout=log or subprocess.PIPE, stderr=subprocess.STDOUT)
        output, _ = proc.communicate(timeout=timeout)
        if proc.returncode:
            detail = (f"see {log_path}" if log_path else
                      (output or b"").decode("utf-8", errors="replace")[-2000:])
            raise HarnessError(f"{Path(str(argv[0])).name} exited {proc.returncode}: {detail}",
                               2 if proc.returncode == 2 else 1)
        return subprocess.CompletedProcess(argv, proc.returncode, output or b"", b"")
    except subprocess.TimeoutExpired as error:
        if proc:
            terminate_process(proc)
        detail = f"; see {log_path}" if log_path else ""
        raise HarnessError(f"command timed out after {timeout}s: {Path(str(argv[0])).name}{detail}") from error
    except BaseException:
        if proc:
            terminate_process(proc)
        raise
    finally:
        if proc:
            for pipe in (proc.stdout, proc.stderr):
                if pipe:
                    pipe.close()
        if log:
            log.close()


def download_image(image, cache_dir):
    cache = secure_directory(cache_dir)
    target = cache / (image["sha256"] + ".qcow2")
    if target.is_symlink():
        raise HarnessError("refusing symlink image cache")
    if target.exists():
        if not target.is_file() or sha256_file(target) != image["sha256"]:
            raise HarnessError("cached guest image checksum mismatch; remove the corrupt cache entry")
        return target
    fd, name = tempfile.mkstemp(prefix="download-", suffix=".partial", dir=cache)
    partial = Path(name)
    try:
        with os.fdopen(fd, "wb") as output, urllib.request.urlopen(image["url"], timeout=60) as response:
            if not response.geturl().startswith("https://"):
                raise HarnessError("guest image download redirected away from HTTPS")
            shutil.copyfileobj(response, output, length=1024 * 1024)
        if sha256_file(partial) != image["sha256"]:
            raise HarnessError("downloaded guest image checksum mismatch")
        partial.chmod(0o400)
        partial.replace(target)
        return target
    finally:
        partial.unlink(missing_ok=True)


def git(repo, *args):
    return run_command(["git", "-c", "core.hooksPath=/dev/null", "-C", repo, *args],
                       timeout=300).stdout.decode().strip()


def prepare_git_bundle(repo, candidate, baseline, destination):
    """Bundle selected commits and their reachable tags, never the worktree."""
    repo, destination = Path(repo).resolve(), Path(destination)
    refs = {}
    for label, ref in (("candidate", candidate), ("baseline", baseline)):
        refs[label] = (git(repo, "rev-parse", "--verify", "--end-of-options", ref + "^{commit}")
                       if ref else None)
    if refs["baseline"] and refs["baseline"] == refs["candidate"]:
        raise HarnessError("upgrade baseline and candidate must be different commits", 2)
    tags = []
    for tag in git(repo, "for-each-ref", "--format=%(refname)", "refs/tags/").splitlines():
        try:
            commit = git(repo, "rev-parse", "--verify", tag + "^{commit}")
        except HarnessError:
            continue
        for selected in (refs["candidate"], refs["baseline"]):
            if not selected:
                continue
            try:
                git(repo, "merge-base", "--is-ancestor", commit, selected)
                tags.append(tag)
                break
            except HarnessError:
                continue
    with tempfile.TemporaryDirectory(prefix="bundle-", dir=destination.parent) as temp:
        bare = Path(temp) / "source.git"
        run_command(["git", "init", "--bare", bare], timeout=30)
        refspecs = [f"{value}:refs/heads/{key}" for key, value in refs.items() if value]
        refspecs.extend(f"{tag}:{tag}" for tag in tags)
        git(bare, "fetch", "--no-tags", "--no-recurse-submodules", str(repo), *refspecs)
        git(bare, "bundle", "create", str(destination.resolve()), "--all")
    return {**refs, "tags": tags}


def qemu_path(path):
    # QEMU parses commas itself even when subprocess receives a single argument.
    return str(path).replace(",", ",,")


def build_qemu_command(args, paths, ssh_port):
    if args.accel not in ("kvm", "tcg"):
        raise HarnessError("acceleration must explicitly be kvm or tcg", 2)
    # QEMU's ipv6=on alone disables IPv4, including guest DHCP and SSH access.
    return ["qemu-system-x86_64", "-machine", "q35", "-accel", args.accel,
            "-cpu", "host" if args.accel == "kvm" else "max",
            "-smp", str(args.cpus), "-m", str(args.memory_mib),
            "-display", "none", "-monitor", "none",
            "-qmp", f"unix:{qemu_path(paths['qmp'])},server=on,wait=off",
            "-serial", f"file:{qemu_path(paths['serial'])}",
            "-drive", f"file={qemu_path(paths['disk'])},format=qcow2,if=virtio",
            "-drive", f"file={qemu_path(paths['seed'])},format=raw,if=virtio,readonly=on",
            "-netdev", f"user,id=net0,ipv4=on,ipv6=on,hostfwd=tcp:127.0.0.1:{ssh_port}-:22",
            "-device", f"virtio-net-pci,netdev=net0,mac={GUEST_MAC}",
            "-device", "virtio-rng-pci", "-no-reboot"]


def parse_args(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    parser = argparse.ArgumentParser(
        prog="./scripts/qemu-test.sh",
        description="Test Notty and Nosh Guard in a disposable Linux VM.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""With no arguments, show a quick start and check host prerequisites.

Examples:
  ./scripts/qemu-test.sh doctor
  ./scripts/qemu-test.sh run --suite smoke
  ./scripts/qemu-test.sh run --suite smoke --accel tcg
  ./scripts/qemu-test.sh run --suite full --baseline-ref <previous-commit>
""")
    parser.add_argument("command", choices=("doctor", "run"))
    parser.add_argument("--suite", choices=("smoke", "full"), default="smoke")
    parser.add_argument("--ref", default="HEAD")
    parser.add_argument("--baseline-ref")
    parser.add_argument("--accel", choices=("kvm", "tcg"), default="kvm")
    parser.add_argument("--cpus", type=int, default=4)
    parser.add_argument("--memory-mib", type=int, default=8192)
    parser.add_argument("--disk-gib", type=int, default=64)
    parser.add_argument("--boot-timeout", type=int)
    parser.add_argument("--timeout", type=int, default=7200, help="per-stage deadline in seconds")
    parser.add_argument("--output-dir", type=Path, default=REPOSITORY / ".release-audit/qemu")
    args = parser.parse_args(argv or ["doctor"])
    args.quickstart = not argv
    if args.command == "run" and args.suite == "full" and not args.baseline_ref:
        parser.error("--suite full requires --baseline-ref")
    for name in ("cpus", "memory_mib", "disk_gib", "timeout"):
        if getattr(args, name) < 1:
            parser.error(f"--{name.replace('_', '-')} must be positive")
    if args.boot_timeout is None:
        args.boot_timeout = 600 if args.accel == "kvm" else 1800
    if args.boot_timeout < 1:
        parser.error("--boot-timeout must be positive")
    return args


def doctor(args):
    checks = [{"name": "linux-x86_64", "ok": platform.system() == "Linux"
               and platform.machine() in ("x86_64", "amd64")},
              {"name": "unprivileged-owner", "ok": os.getuid() != 0}]
    checks.extend({"name": tool, "ok": shutil.which(tool) is not None} for tool in REQUIRED_TOOLS)
    if args.accel == "kvm":
        checks.append({"name": "kvm-access", "ok": os.access("/dev/kvm", os.R_OK | os.W_OK)})
    missing = {item["name"] for item in checks if not item["ok"]}
    hints = []
    packages = sorted({TOOL_PACKAGES[name] for name in missing if name in TOOL_PACKAGES})
    if packages:
        hints.append("On Debian/Ubuntu, install missing tools: sudo apt-get install " + " ".join(packages))
    if "kvm-access" in missing:
        hints.append("KVM requires /dev/kvm access; use --accel tcg explicitly for software emulation.")
    if "unprivileged-owner" in missing:
        hints.append("Run the harness as a regular user, without sudo.")
    if "linux-x86_64" in missing:
        hints.append("This harness requires a Linux x86-64 host.")
    return {"status": "blocked" if missing else "ready",
            "acceleration": args.accel, "checks": checks,
            "hint": " ".join(hints) if hints else "All host prerequisites passed."}


def cloud_config(manifest, public_key, guest_private_key, guest_public_key):
    snapshot = manifest["guest"]["aptSnapshot"]
    sources = (f"deb [check-valid-until=no] https://snapshot.ubuntu.com/ubuntu/{snapshot}/ "
               "noble main universe\n"
               f"deb [check-valid-until=no] https://snapshot.ubuntu.com/ubuntu/{snapshot}/ "
               "noble-updates main universe\n"
               f"deb [check-valid-until=no] https://snapshot.ubuntu.com/ubuntu/{snapshot}/ "
               "noble-security main universe\n")
    packages = [f"{name}={version}" for name, version in manifest["guest"]["packages"].items()]
    apt_options = "-o Dir::Etc::sourcelist=/etc/apt/nosh-qemu.list -o Dir::Etc::sourceparts=-"
    bootstrap = ("#!/bin/bash\nset -euo pipefail\nexport DEBIAN_FRONTEND=noninteractive\n"
                 f"apt-get {apt_options} update\n"
                 f"apt-get {apt_options} install -y --no-install-recommends "
                 + shlex.join(packages) + "\n"
                 "sysctl -p /etc/sysctl.d/90-nosh-qemu.conf\n"
                 "usermod -aG docker noshqemu\n"
                 "systemctl enable --now docker\n"
                 "install -d -o noshqemu -g noshqemu -m 0700 /home/noshqemu/results\n"
                 "touch /var/lib/nosh-qemu-ready\n")
    data = {
        "users": [{"name": "noshqemu", "shell": "/bin/bash", "lock_passwd": True,
                   "sudo": "ALL=(ALL) NOPASSWD:ALL", "ssh_authorized_keys": [public_key]}],
        "ssh_pwauth": False, "disable_root": True,
        "ssh_keys": {"ed25519_private": guest_private_key, "ed25519_public": guest_public_key},
        "ssh": {"emit_keys_to_console": False},
        "ssh_publish_hostkeys": {"enabled": False},
        "package_update": False, "package_upgrade": False,
        "bootcmd": [["systemctl", "mask", "--now", "apt-daily.timer", "apt-daily-upgrade.timer",
                     "apt-daily.service", "apt-daily-upgrade.service", "unattended-upgrades.service"]],
        "write_files": [{"path": "/etc/apt/nosh-qemu.list", "content": sources},
                        {"path": "/etc/sysctl.d/90-nosh-qemu.conf", "content":
                         "net.ipv6.conf.all.forwarding=1\nnet.ipv6.conf.default.forwarding=1\n"
                         "net.ipv6.conf.all.accept_ra=2\nnet.ipv6.conf.default.accept_ra=2\n"
                         "net.ipv6.conf.eth0.accept_ra=2\n"},
                        {"path": "/usr/local/sbin/nosh-qemu-bootstrap", "permissions": "0700",
                         "content": bootstrap}],
        "runcmd": [["bash", "/usr/local/sbin/nosh-qemu-bootstrap"]],
        "final_message": "nosh-qemu cloud-init finished"
    }
    # JSON is a YAML subset; using the serializer avoids shell/YAML injection.
    return "#cloud-config\n" + json.dumps(data, indent=2) + "\n"


def print_log_hint(label, path):
    command = shlex.join(["tail", "-n", "80", "-F", "--", str(path)])
    print(f"qemu-test: watch {label} in another terminal:\n  {command}", flush=True)


class Guest:
    def __init__(self, args, manifest, run_dir, runtime):
        self.args, self.manifest, self.run_dir, self.runtime = args, manifest, run_dir, runtime
        self.paths = {name: runtime / filename for name, filename in
                      (("disk", "guest.qcow2"), ("seed", "seed.img"), ("qmp", "qmp.sock"),
                       ("serial", "serial.log"))}
        self.proc = None
        self.qemu_log = None
        self.port = None
        self.acceleration = None

    def cloud_config(self, public_key, private_key, host_key):
        return cloud_config(self.manifest, public_key, private_key, host_key)

    def qemu_command(self):
        return build_qemu_command(self.args, self.paths, self.port)

    def initialize(self, image):
        run_command(["qemu-img", "create", "-f", "qcow2", "-F", "qcow2", "-b", image,
                     self.paths["disk"], f"{self.args.disk_gib}G"], 60)
        for key in ("identity", "guest-host"):
            run_command(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", self.runtime / key], 30)
        config = self.cloud_config((self.runtime / "identity.pub").read_text().strip(),
                              (self.runtime / "guest-host").read_text(),
                              (self.runtime / "guest-host.pub").read_text().strip())
        (self.runtime / "user-data").write_text(config)
        (self.runtime / "meta-data").write_text(json.dumps({
            "instance-id": self.run_dir.name, "local-hostname": "nosh-qemu"}))
        (self.runtime / "network-config").write_text(json.dumps({"version": 2, "ethernets": {
            "eth0": {"match": {"macaddress": GUEST_MAC}, "set-name": "eth0",
                     "dhcp4": True, "dhcp6": False, "accept-ra": True}}}))
        run_command(["cloud-localds", "--network-config", self.runtime / "network-config",
                     self.paths["seed"], self.runtime / "user-data",
                     self.runtime / "meta-data"], 60)

    def ssh_options(self):
        return ["-F", "/dev/null", "-i", str(self.runtime / "identity"),
                "-o", "BatchMode=yes", "-o", "IdentitiesOnly=yes", "-o", "IdentityAgent=none",
                "-o", "ForwardAgent=no", "-o", "StrictHostKeyChecking=yes",
                "-o", f"UserKnownHostsFile={self.runtime / 'known_hosts'}",
                "-o", "GlobalKnownHostsFile=/dev/null", "-o", "ConnectTimeout=5",
                "-o", "ServerAliveInterval=10", "-o", "ServerAliveCountMax=3"]

    def ssh(self, argv, timeout=None, log_path=None):
        return run_command(["ssh", *self.ssh_options(), "-p", str(self.port),
                            "noshqemu@127.0.0.1", shlex.join([str(item) for item in argv])],
                           timeout or self.args.timeout, log_path=log_path)

    def copy(self, source, target, download=False, timeout=None):
        remote = f"noshqemu@127.0.0.1:{target}"
        argv = ["scp", *self.ssh_options(), "-P", str(self.port), "-r"]
        argv.extend([remote, str(source)] if download else [str(source), remote])
        run_command(argv, timeout=timeout or self.args.timeout)

    def boot(self):
        with socket.socket() as reservation:
            reservation.bind(("127.0.0.1", 0))
            self.port = reservation.getsockname()[1]
        # A race for the selected port causes QEMU to fail, never a connection
        # to a different guest: its SSH host key is pinned independently.
        key = (self.runtime / "guest-host.pub").read_text().split()
        (self.runtime / "known_hosts").write_text(f"[127.0.0.1]:{self.port} {' '.join(key[:2])}\n")
        self.paths["qmp"].unlink(missing_ok=True)
        print_log_hint("boot and provisioning", self.paths["serial"])
        self.qemu_log = open(self.runtime / "qemu.log", "ab")
        self.proc = start_process(self.qemu_command(),
                                  stdin=subprocess.DEVNULL, stdout=self.qemu_log,
                                  stderr=subprocess.STDOUT,
                                  pass_fds=getattr(self, 'inherited_fds', ()))
        deadline = time.monotonic() + self.args.boot_timeout
        while time.monotonic() < deadline:
            if getattr(self, 'cancel_requested', lambda: False)():
                raise HarnessError('guest boot cancelled')
            if self.proc.poll() is not None:
                raise HarnessError("QEMU exited before guest readiness; see qemu.log", 2)
            try:
                self.ssh(["test", "-f", "/var/lib/nosh-qemu-ready"], timeout=10)
                kvm = self.qmp("query-kvm")
                self.acceleration = "kvm" if kvm.get("enabled") else "tcg"
                if self.acceleration != self.args.accel:
                    raise HarnessError("QEMU accelerator differs from the requested accelerator")
                return
            except HarnessError:
                time.sleep(2)
        raise HarnessError("guest boot/provisioning timed out; see serial.log", 2)

    def qmp(self, command):
        with socket.socket(socket.AF_UNIX) as connection:
            connection.settimeout(5)
            connection.connect(str(self.paths["qmp"]))
            with connection.makefile("rwb") as stream:
                json.loads(stream.readline())
                for execute in ("qmp_capabilities", command):
                    stream.write((json.dumps({"execute": execute}) + "\r\n").encode())
                    stream.flush()
                    while True:
                        result = json.loads(stream.readline())
                        if "error" in result:
                            raise HarnessError(f"QMP {execute} failed")
                        if "return" in result:
                            break
                return result["return"]

    def shutdown(self):
        if self.proc and self.proc.poll() is None:
            self.qmp("system_powerdown")
            try:
                self.proc.wait(timeout=120)
            except subprocess.TimeoutExpired as error:
                raise HarnessError("guest did not shut down cleanly; checkpoint refused") from error
            if self.proc.returncode:
                raise HarnessError("QEMU failed during shutdown; checkpoint refused")
        if self.qemu_log:
            self.qemu_log.close()
            self.qemu_log = None

    def action(self, action, repo="candidate"):
        log_path = self.run_dir / (action + "-" + repo + ".log")
        print_log_hint(f"{action} ({repo})", log_path)
        self.ssh(["bash", GUEST_HOME + "/harness/guest.sh", action,
                  GUEST_HOME + "/" + repo, GUEST_HOME + "/results"],
                 log_path=log_path)

    def close(self):
        if self.proc:
            terminate_process(self.proc)
            self.proc = None
        if self.qemu_log:
            self.qemu_log.close()
            self.qemu_log = None


def execute(args, manifest):
    output = secure_directory(args.output_dir)
    run_id = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ") + f"-{os.getpid()}"
    run_dir = secure_directory(output / run_id)
    report = {"version": 1, "runId": run_id, "suite": args.suite, "status": "running",
              "manifest": manifest, "acceleration": args.accel, "stages": [],
              "resources": {"cpus": args.cpus, "memoryMiB": args.memory_mib, "diskGiB": args.disk_gib},
              "releaseCertification": False}
    runtime = None
    guest = None
    result = 1

    def save():
        (run_dir / "report.json").write_text(json.dumps(report, indent=2) + "\n")

    def stage(name, callback):
        print(f"qemu-test: {name}", flush=True)
        entry = {"name": name, "status": "running"}
        report["stages"].append(entry)
        started = time.monotonic()
        save()
        try:
            value = callback()
            entry["status"] = "passed"
            return value
        except HarnessError as error:
            entry.update(status="blocked" if error.status == 2 else "failed", error=str(error))
            raise
        finally:
            entry["seconds"] = round(time.monotonic() - started, 3)
            save()

    try:
        readiness = doctor(args)
        report["host"] = readiness
        if readiness["status"] != "ready":
            raise HarnessError("host prerequisites missing: " + ", ".join(
                item["name"] for item in readiness["checks"] if not item["ok"]), 2)
        report["qemuVersion"] = run_command(["qemu-system-x86_64", "--version"], 15).stdout.decode().strip()
        runtime = Path(tempfile.mkdtemp(prefix="notty-qemu-"))
        guest = Guest(args, manifest, run_dir, runtime)
        save()
        print(f"qemu-test: report: {run_dir / 'report.json'}", flush=True)
        print("qemu-test: live log commands appear as stages start; "
              "Ctrl+C in the viewing terminal stops only the viewer.", flush=True)
        refs = stage("export-source", lambda: prepare_git_bundle(
            REPOSITORY, args.ref, args.baseline_ref, runtime / "source.bundle"))
        report["source"] = refs
        report["source"]["bundleSha256"] = sha256_file(runtime / "source.bundle")
        staged_harness = secure_directory(runtime / "harness")
        report["harnessFiles"] = {}
        for name in GUEST_FILES:
            source = REPOSITORY / "scripts/qemu" / name
            if source.is_symlink() or not source.is_file():
                raise HarnessError(f"missing or unsafe guest harness source: {name}", 2)
            shutil.copyfile(source, staged_harness / name)
            report["harnessFiles"][f"scripts/qemu/{name}"] = sha256_file(staged_harness / name)
        report["harnessFiles"]["scripts/qemu/harness.py"] = sha256_file(Path(__file__))
        report["harnessFiles"]["scripts/qemu-test.sh"] = sha256_file(REPOSITORY / "scripts/qemu-test.sh")
        image = stage("download-image", lambda: download_image(manifest["image"], output / "cache"))
        info = json.loads(run_command(["qemu-img", "info", "--output=json", image], 60).stdout)
        if info.get("format") != "qcow2" or info.get("backing-filename"):
            raise HarnessError("base image must be a standalone qcow2 disk")
        if info.get("virtual-size", 0) > args.disk_gib * 1024 ** 3:
            raise HarnessError("--disk-gib must not shrink the pinned image", 2)
        stage("initialize", lambda: guest.initialize(image))
        stage("boot", guest.boot)
        report["actualAcceleration"] = guest.acceleration
        stage("transfer-source", lambda: guest.copy(runtime / "source.bundle", GUEST_HOME + "/source.bundle"))
        stage("transfer-harness", lambda: guest.copy(staged_harness, GUEST_HOME + "/harness"))
        for label in ("candidate", "baseline"):
            if refs[label]:
                guest.ssh(["git", "clone", "--branch", label, GUEST_HOME + "/source.bundle",
                           GUEST_HOME + "/" + label])
                actual = guest.ssh(["git", "-C", GUEST_HOME + "/" + label,
                                    "rev-parse", "HEAD"]).stdout.decode().strip()
                if actual != refs[label]:
                    raise HarnessError("guest source identity mismatch")
        guest.ssh(["rm", "--", GUEST_HOME + "/source.bundle"])
        if args.suite == "full":
            stage("baseline-install", lambda: guest.action("install", "baseline"))
            stage("baseline-verify", lambda: guest.action("verify", "baseline"))
            stage("baseline-smoke", lambda: guest.action("smoke", "baseline"))
            stage("checkpoint-shutdown", guest.shutdown)
            checkpoint = runtime / "baseline.qcow2"
            stage("checkpoint", lambda: run_command(["qemu-img", "convert", "-f", "qcow2",
                  "-O", "qcow2", guest.paths["disk"], checkpoint], args.timeout))
            stage("boot-for-upgrade", guest.boot)
        stage("candidate-install", lambda: guest.action("install"))
        stage("smoke", lambda: guest.action("smoke"))
        if args.suite == "full":
            stage("full", lambda: guest.action("full"))
            stage("daemon-restart", lambda: guest.ssh(["sudo", "systemctl", "restart", "nosh-guardd.service"]))
            stage("verify-after-restart", lambda: guest.action("verify"))
            stage("reboot-shutdown", guest.shutdown)
            stage("reboot-boot", guest.boot)
            stage("verify-after-reboot", lambda: guest.action("verify"))
        stage("export-results", lambda: guest.copy(run_dir / "guest", GUEST_HOME + "/results", download=True))
        stage("candidate-cleanup", lambda: guest.action("cleanup"))
        stage("export-cleanup-results", lambda: guest.copy(
            run_dir / "guest-cleanup", GUEST_HOME + "/results", download=True))
        if args.suite == "full":
            stage("rollback-shutdown", guest.shutdown)
            stage("restore-checkpoint", lambda: shutil.copyfile(checkpoint, guest.paths["disk"]))
            stage("rollback-boot", guest.boot)
            stage("rollback-verify", lambda: guest.action("verify", "baseline"))
            stage("rollback-smoke", lambda: guest.action("smoke", "baseline"))
            stage("rollback-cleanup", lambda: guest.action("cleanup", "baseline"))
            stage("export-rollback-results", lambda: guest.copy(
                run_dir / "guest-rollback", GUEST_HOME + "/results", download=True))
        stage("shutdown", guest.shutdown)
        report["status"] = "passed"
        result = 0
    except HarnessError as error:
        result = error.status
        report.update(status="blocked" if result == 2 else "failed", error=str(error))
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        report.update(status="failed", error=str(error))
    finally:
        if guest:
            if report["status"] != "passed" and guest.proc and guest.proc.poll() is None:
                try:
                    guest.copy(run_dir / "guest-failure", GUEST_HOME + "/results", download=True, timeout=60)
                except (HarnessError, OSError):
                    pass
            try:
                guest.close()
            except (HarnessError, OSError, subprocess.SubprocessError) as error:
                report["cleanupError"] = str(error)
                report["status"], result = "failed", 1
        if runtime:
            # Never export seed disks, keys, source bundles, or VM disks.
            secrets = []
            for name in ("identity", "guest-host"):
                key = runtime / name
                if key.is_file():
                    secrets.extend(key.read_text().splitlines()[1:-1])
            for name in ("serial.log", "qemu.log"):
                source = runtime / name
                if source.is_file():
                    text = source.read_text(errors="replace")
                    for secret in secrets:
                        text = text.replace(secret, "[redacted]")
                    (run_dir / name).write_text(text)
            shutil.rmtree(runtime)
        save()
        if report.get("error"):
            print(f"qemu-test: {report['error']}", file=sys.stderr, flush=True)
        if report.get("host", {}).get("status") == "blocked":
            print(f"qemu-test: {report['host']['hint']}", file=sys.stderr, flush=True)
        if report.get("cleanupError"):
            print(f"qemu-test: cleanup failed: {report['cleanupError']}", file=sys.stderr, flush=True)
        print(f"qemu-test: {report['status']}; report: {run_dir / 'report.json'}", flush=True)
    return result


def main(argv=None):
    os.umask(0o077)
    args = parse_args(argv)
    if args.quickstart:
        print("QEMU test environment\n"
              "Checking host prerequisites.\n\n"
              "Start a smoke run: ./scripts/qemu-test.sh run --suite smoke\n"
              "Software emulation: ./scripts/qemu-test.sh run --suite smoke --accel tcg\n"
              "All options: ./scripts/qemu-test.sh --help\n",
              file=sys.stderr, flush=True)
    if args.command == "doctor":
        report = doctor(args)
        print(json.dumps(report, indent=2))
        return 0 if report["status"] == "ready" else 2
    try:
        manifest = validate_manifest(json.loads(MANIFEST.read_text()))
        def interrupted(signum, _frame):
            raise HarnessError(f"interrupted by signal {signum}", 130)
        for signum in (signal.SIGINT, signal.SIGTERM):
            signal.signal(signum, interrupted)
        return execute(args, manifest)
    except (HarnessError, OSError, ValueError) as error:
        print(f"qemu-test: {error}", file=sys.stderr)
        return error.status if isinstance(error, HarnessError) else 2


if __name__ == "__main__":
    sys.exit(main())
