# Disposable QEMU tests

The optional QEMU harness exercises Notty and Nosh Guard in a fresh Ubuntu
24.04 LTS amd64 guest. It uses the existing container builds and installer;
it does not change daily Nosh startup, enable bubblewrap, or replace release
approval checks.

Run the harness from a Linux x86-64 host as a regular user. Install Python 3,
Git, OpenSSH client tools (`ssh`, `scp`, `ssh-keygen`), `qemu-img`,
`qemu-system-x86_64`, and `cloud-localds`. On Ubuntu, the QEMU and cloud-init
tools are supplied by `qemu-system-x86`, `qemu-utils`, and `cloud-image-utils`.
KVM requires hardware virtualization and access to `/dev/kvm`; the harness
does not change device permissions or elevate QEMU. The host does not need
Node.js, npm, or Docker. Docker and Buildx run inside the guest, and all
package-manager commands for the project run inside guest containers.

The host downloads the pinned Ubuntu image; the guest needs outbound access
to download packages and the dependencies used by the existing container
builds. This is an integration test environment, not an offline build.

## Run a suite

Run `./scripts/qemu-test.sh` without arguments for a quick start and host
prerequisite check. This performs the same checks as `doctor`; starting a VM
requires the explicit `run` command. Use `--help` for all options and examples.

```bash
# Check host dependencies and KVM availability.
./scripts/qemu-test.sh doctor

# Clean install and terminal smoke checks.
./scripts/qemu-test.sh run --suite smoke --ref HEAD --accel kvm

# Include enforcement and lifecycle checks against a chosen prior revision.
./scripts/qemu-test.sh run --suite full --ref HEAD \
  --baseline-ref <previous-commit> --accel kvm

# Explicit software emulation for hosts without KVM.
./scripts/qemu-test.sh run --suite smoke --ref HEAD --accel tcg
```

Each run prints its report path at startup and a copyable `tail -n 80 -F`
command as boot or a guest test stage starts. Run the printed command in
another terminal to watch live output. The commands use that run's exact
paths, including custom temporary and output directories. If the log has not
appeared yet, `tail -F` waits for it. Ctrl+C in the viewing terminal stops only
the viewer. Boot logs live in the temporary runtime directory during the run
and are copied into the report directory when it finishes.
Failed or timed-out commands that write to a stage log include its path in
the error message and report.

`--ref` and `--baseline-ref` select committed Git revisions. Local edits and
untracked files are not part of either guest checkout: commit the changes you
intend to test first. The selected commits and reachable Git tags travel to
the guest in a Git bundle, without copying the host home directory or Git
credentials. The harness scripts themselves are transferred from the current
workspace separately, and their hashes are recorded with the source commits.
The full suite requires an explicit, compatible baseline revision at a
different commit, containing the Guard build and installation interfaces
exercised by the harness.

| Option | Default | Meaning |
| --- | --- | --- |
| `--suite` | `smoke` | `smoke` or `full` |
| `--ref` | `HEAD` | Candidate Git revision |
| `--baseline-ref` | none | Prior Git revision; required by `full` |
| `--accel` | `kvm` | `kvm` or explicit `tcg`; no automatic fallback |
| `--cpus` | `4` | Guest virtual CPUs |
| `--memory-mib` | `8192` | Guest RAM in MiB |
| `--disk-gib` | `64` | Sparse guest disk capacity in GiB |
| `--boot-timeout` | `600` for KVM, `1800` for TCG | Boot/provisioning deadline in seconds |
| `--timeout` | `7200` | Per-stage command deadline in seconds |
| `--output-dir` | `.release-audit/qemu` | Reports and run artifacts |

TCG can be substantially slower than KVM. Increase the explicit timeouts when
needed; an expired deadline is a failed or blocked run, never a passing skip.
Missing host tools, unavailable acceleration, failed provisioning, or missing
guest kernel/eBPF prerequisites must be resolved before treating a VM run as
validation.

## What the suites exercise

The smoke suite boots the guest, records its prerequisites, builds a Guard
host bundle inside Docker against the guest's BTF, and installs it with deep
verification. It starts Nosh and checks terminal creation, input, output,
resize, and close over both HTTP and SSE. After requesting terminal
termination, it waits up to 15 seconds for the terminal to disappear from the
session list. A terminal that remains listed fails the check. The harness
collects evidence, including the server log when smoke checks fail, and
disposes of the guest after the run.

The full suite adds profile building and the scoped network learn, audit,
and enforce lifecycle. Two guest-local literal-IP endpoints provide a
controlled test: both are reachable while learning, audit records the
disallowed endpoint while allowing traffic, and enforcement permits the
approved endpoint while denying the other with matching Guard evidence.
Temporary test keys exercise approval and activation. Full standalone
`enforce` is separately expected to reject admission with
`GUARD_STANDALONE_INGRESS_UNAVAILABLE`, as documented in
[Nosh Guard](nosh-guard.md); a scoped egress test must not be presented as
proof of full standalone ingress enforcement.

Lifecycle checks cover daemon restart, guest reboot, installation of the
baseline, upgrade to the candidate, rollback to a powered-off VM checkpoint,
uninstall, and explicit purge. The checkpoint is taken before introducing
test signing keys. Restoring it validates guest recovery; it does not claim
that the product provides an installer downgrade command.

Project checks reuse the existing container audit path. Results from
development commits remain development evidence and do not become release
certification. Live KVM full and TCG smoke runs are required before declaring
the VM feature validated; offline harness tests alone cannot establish
kernel, Docker, eBPF, or terminal integration behavior.

## Isolation and evidence

The manifest selects a dated, checksum-verified cloud image. Each run writes
to its own qcow2 overlay; the reusable base image is not booted with writable
storage. QEMU uses user-mode networking with both IPv4 and IPv6 explicitly
enabled and loopback-only SSH forwarding. IPv4 supplies guest DHCP, DNS, and
SSH access; specifying only `ipv6=on` disables IPv4 in QEMU.
The host does not share directories, Docker sockets, SSH agents, provider
credentials, or release-signing keys with the guest. User-mode networking
still provides the outbound connectivity needed by provisioning and builds.

SSH keys are generated for the run. The client private key remains in the
host's private runtime directory; the guest host key is pinned independently
so a forwarded-port collision cannot connect the harness to another guest.
The per-run rollback checkpoint includes the guest's SSH host identity but
predates test signing keys. Those signing keys are created only for the
relevant guest checks. No private keys belong in the reusable base image,
exported reports, or console logs. Interruptions and timeouts must clean up
only processes and files owned by the current run. The harness exports
diagnostic evidence before removing writable disks, temporary keys, and
runtime sockets.

Each run writes `report.json` in
`.release-audit/qemu/<UTCtimestamp>-<pid>/` (or the chosen output directory).
Keep it with the stage logs, exported `guest/` and `guest-cleanup/` results,
`serial.log`, and `qemu.log` when reviewing a result. Together they record
candidate and baseline commits, image and artifact hashes, the guest kernel and
architecture, cgroup/BTF capabilities, Docker/QEMU versions, actual
acceleration, and individual outcomes. Interrupted or failed runs attempt
to export available guest results to `guest-failure/` before disposal.

`doctor` reports `ready` or `blocked`. Run reports use `passed`, `failed`, or
`blocked`; the corresponding exit codes are `0`, `1`, and `2` (`130` for
interruption). A missing prerequisite is not evidence of passing the
remaining checks. Reports and diagnostic logs remain after the private
runtime directory, overlays, checkpoints, and keys are removed. The verified
base image is retained read-only at `<output-dir>/cache/<sha256>.qcow2`.

A live KVM smoke run passed on 2026-09-30 for candidate commit
`80686a3ad7b2ac69b763a42875e1b524166a378b`, using the workspace harness recorded
in run `20260930T174037Z-518273`. All 12 stages passed, including guest
provisioning, installation, HTTP/SSE terminal checks, uninstall preservation,
explicit purge, evidence export, and shutdown. The saved evidence is under
`.release-audit/qemu/20260930T174037Z-518273/` on the test host.
KVM full and TCG smoke validation remain outstanding.

Blocked runs print the reason and, for missing host tools, the relevant
Debian/Ubuntu package command. For example, missing `cloud-localds` requires
`sudo apt-get install cloud-image-utils`. After installing it, rerun the same
suite command; QEMU itself still runs as your regular user.

The deterministic harness tests are included in the repository's container
test suite. Run the normal Docker-backed `./scripts/release-audit.sh` baseline; never
run `npm`, `npx`, or `npm exec` on the host. The QEMU suites remain opt-in and
are not added to the regular release gate.

## Refresh the pinned guest

[The manifest](../config/qemu-test.json) pins the 20260926 Noble amd64 cloud
image by SHA-256 and the `20260928T000000Z` Ubuntu package snapshot. The image
hash comes from the dated official
[SHA256SUMS](https://cloud-images.ubuntu.com/noble/20260926/SHA256SUMS).
Docker and Buildx versions come from that snapshot's
[noble-updates/universe package index](https://snapshot.ubuntu.com/ubuntu/20260928T000000Z/dists/noble-updates/universe/binary-amd64/Packages.xz);
`libbpf1` comes from
[noble/main](https://snapshot.ubuntu.com/ubuntu/20260928T000000Z/dists/noble/main/binary-amd64/Packages.xz),
and the remaining direct package versions come from
[noble-updates/main](https://snapshot.ubuntu.com/ubuntu/20260928T000000Z/dists/noble-updates/main/binary-amd64/Packages.xz).
Dependencies resolve within the same fixed archive snapshot. Ubuntu describes
the timestamp and retention behavior in its
[snapshot service documentation](https://snapshot.ubuntu.com/).

To refresh the guest, select a dated official image, verify its published
SHA-256, and choose an archive snapshot at least as recent as the image.
Resolve every direct package's exact version from that snapshot, retaining
the distribution's archive signature verification. Commit the image and
package pins together, then run KVM full and TCG smoke suites and review the
changed kernel/BTF and Docker evidence. Do not substitute a moving `current`
URL, remove checksum verification, or fall back to the latest archive after
a failed download. Dated images can be removed upstream; retain a verified
cache or explicitly refresh the manifest when that happens.

## Persistent Codex sessions

The disposable `qemu-test.sh` harness still uses isolated guest state. For daily
Codex work, select the persistent QEMU backend with `nosh --qemu` (or invoke
`./scripts/nosh.sh --qemu` before installing the `nosh` command):

```sh
nosh --qemu
nosh --qemu attach
nosh --qemu status
nosh --qemu stop
nosh --qemu reset
```

The session name defaults to `<workspace-directory>-qemu`, for example
`notty-qemu` from `~/notty`. Run lifecycle commands from the same directory, or
select the workspace with `--workdir PATH`. Use `--name NAME` to override the
default or access an existing named session, including the former `codex` default.

`scripts/nosh-qemu.sh` remains the direct backend entrypoint.
With no command, the launcher defaults to `start`, like `nosh`. `start` attaches
to an already-running session; otherwise it provisions the pinned guest and
builds its Nosh Docker image once. It opens `/bin/bash` in the container.
Run `codex resume` there. Exiting that shell
leaves the VM running; `stop` stops the container and shuts down the VM. Use
`start --detach` to start without entering the shell. Startup prints a live log
command; `serial.log`, `install.log`, and `virtiofs.log` are beside `session.log`.
The default storage is `${XDG_STATE_HOME:-$HOME/.local/state}/nosh/qemu/NAME`.
`--accel tcg` explicitly selects software emulation; KVM is the default.

The workspace defaults to the current directory; use `--workdir PATH` to override
it. The host workspace retains its absolute path in both the guest and container.
The existing `${CODEX_HOME:-$HOME/.codex}` is exported into the guest and bound
read-write into Docker at `/home/noshqemu/.codex`. This includes history,
sessions, archives, databases, logs and caches without maintaining a list of
Codex's internal database names. `--codex-home PATH` selects another existing
profile. User `.agents/skills` is shared separately. The entire host home is
never exported. The guest user and Docker user have the host caller's UID/GID.
Only Codex is supported by this session launcher; Claude/Gemini are deferred.

Known credential files are read-only inside Docker. Skills, settings and plugins
are independently read-only by default:

```sh
nosh --qemu start --name editable-skills \
  --agent-skills rw --agent-settings ro --agent-plugins ro
```

The shared resource list is `config/codex-resources.json`. It includes Codex
configuration, instruction files, rules, prompts, skills and plugins, user
`.agents/skills`, and workspace `.agents/skills`, `.codex/skills`, configuration
and instruction files. Missing standard resources are initialized on the host;
optional `AGENTS.override.md` files are protected when present and are never
created automatically. Writable configuration files stay on their parent bind
so atomic replacement works. Read-only credential/configuration file mounts
retain their inode until container restart: refresh credentials on the host,
then stop and start the VM to pick up replacement files. Login/token refresh
inside a protected container may fail by design.

These controls protect the listed paths from writes through the agent container.
They do not make a writable workspace immutable, prevent new project instruction
files from being created, or restrict a trusted VM administrator. Custom
instruction/resource paths require corresponding protections before use. Stop
native Codex processes first: Nosh launches with explicit agent-resource controls
and managed Guard/QEMU launches share an exclusive
profile lock, but native CLIs do not participate. The launcher rejects detectable
native processes and existing Docker users of the same profile. The lock remains
held while a detached managed container or VM is running. Different profiles can
run concurrently. Symlinked state/resource paths, hard-linked protected files,
and overlapping workspace/state mounts are rejected.

Ordinary `nosh` shells share host agent profiles without taking an exclusive
profile lock, so a running native Codex CLI does not block shell startup.

The VM disk retains Docker installations/images and can be restarted. `reset`
requires a stopped session and deletes only its managed VM files; it never
rolls back host history or the workspace. A named session records its workspace,
profile and access modes. To change those, stop and reset that VM or choose a
new name. Reset requires rebuilding the guest image. Do not copy session disks
as a way to snapshot Codex history: history lives on the host.

Host prerequisites add a current Rust `virtiofsd` with `--uid-map`, `--gid-map`,
`--translate-uid`, `--translate-gid`, `--readonly`, namespace sandboxing and cache
controls. Guest Docker root requests map to the host caller; file ownership
remains the caller’s UID/GID. Rootless user namespaces
must work on the host. Each export has its own daemon, with matching host/guest
UID/GID mapping and QEMU shared memory. See the
[virtiofsd documentation](https://gitlab.com/virtio-fs/virtiofsd/-/blob/main/README.md)
for host packaging and rootless configuration. The launcher does not fall back
to privileged daemons or disable the namespace sandbox.

Ordinary Nosh keeps its existing access defaults. Explicit `--agent-skills`,
`--agent-settings` or `--agent-plugins` enables this policy with omitted modes
set to `ro`; the same options pass through to Guard and become part of learned
launch identity. Relearn a Guard profile after changing resource modes or
replacing protected resource directories. Guard host bundles include the shared
policy helper and require Python 3 for controlled Codex launches/profile locks.

### Persistence validation

Deterministic policy, identity, lifecycle and layout tests run with the normal
container test suite. The real opt-in VM test uses a synthetic profile and
workspace, never personal Codex history:

```sh
python3 -B scripts/qemu/codex-persistence.py --accel kvm
python3 -B scripts/qemu/codex-persistence.py --accel tcg
```

It checks host → guest → Docker writes, session/archive files, symlinks, atomic
renames, fsync, file locking, SQLite WAL/mmap, read-only credentials/resources,
writable opt-ins, exclusive host leases, VM restart and reset persistence.
Failed fixtures/logs are retained for inspection. These live KVM/TCG checks must
run on a provisioned host; they were not executed in the implementation
container, which lacks QEMU, virtiofsd, SSH and Docker.
