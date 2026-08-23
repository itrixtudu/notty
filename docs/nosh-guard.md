# Nosh Guard operations and profile lifecycle

Nosh Guard isolates each coding-agent run, records kernel and network evidence,
and turns reviewed evidence into an image-bound `NoshSecurityProfile`. It does
not infer that a process is a trusted coding agent. Authentication and
authorization remain responsibilities of the Notty API and launcher; the guard
constrains a runner after that identity has been established.

Ownership is intentionally narrow:

- Tetragon provides runtime evidence and enforces only an explicitly approved
  Tetragon artifact.
- The Nosh profile compiler owns normalization, candidate generation,
  validation, reporting, and promotion provenance.
- `tetragon.yaml`, `seccomp.json`, `apparmor.profile`, `docker.json`, and
  `network-policy.yaml` are independent outputs. Passing or applying one never
  implies that another output was evaluated or installed.
- Docker build candidates are a separate observational product. Their state,
  candidate lifecycle, and informational output image digest are never shared
  with or consumed by runtime Guard profiles.

The Docker build-specific workflow, limitations, and private/portable artifact
split are documented in
[Nosh Docker build profiling](nosh-build-profiling.md).
The frozen semantic graph, visual proposal review, target compilers, and
separate-gateway grants are documented in
[Nosh semantic policy review](nosh-policy-review.md).

This document covers two separate network paths. The full-profile standalone
design retains the historical managed DNS/nftables gateway material described
in its explicitly labeled sections. The scoped `nosh net` workflow uses only
the `nosh-egress` cgroup eBPF backend for allow/deny and never treats that
gateway, dnsmasq, `nosh-dns`, or nftables as policy authority. Do not combine
the trust or approval claims of those paths.

## Network authority lifecycle

Learning acquires evidence; it does not exercise a candidate allowlist. The
intended build-to-runtime sequence is:

| Stage | Network effect | Artifact or decision boundary |
| --- | --- | --- |
| Build learn | Observe the build's natural DNS and L3/L4 activity. Do not apply a candidate network policy. | Preserve immutable private evidence and an unapproved, separately editable review draft. |
| Build review | Accept, deny, or narrow observed build authority. | A human decision is required; build observations never authorize runtime traffic. |
| Reviewed build | Apply only the reviewed build authority and bind the result to an exact output image digest. | Changing the build inputs or resulting digest starts a new review lineage. |
| Runtime learn (`egress-learn`) | Observe and allow ordinary destinations, including RFC1918 addresses, direct DNS, and DNS-over-TLS. Do not apply the candidate policy. | Produce an immutable runtime candidate bound to the workspace and exact image digest. |
| Policy Review | Decide which observed runtime authority should be accepted, denied, or narrowed. | Only a complete DecisionSet and the signed projection/grant workflow can activate authority. |
| Runtime audit (`egress-audit`) | Evaluate the reviewed policy, emit `would-deny` for traffic outside it, and otherwise allow the traffic. | Audit evidence is diagnostic and cannot train a wider replacement policy. |
| Runtime enforce (`egress-enforce`) | Default deny and allow only the activated, reviewed policy. | The pinned eBPF dataplane remains the enforcement boundary. |

The exception is exact platform containment, not a broad address class. For
each scoped runtime run, Guard derives the Docker bridge gateway endpoints and
binds their exact IPv4 `/32` and IPv6 `/128` identities into the run manifest
and target context. Those endpoints remain denied in learn, audit, and
enforce, and Policy Review cannot turn them into application authority. An
arbitrary address is not containment merely because it is loopback, link-local,
RFC1918, or otherwise private. The historical full-profile gateway has a
different, explicitly labeled legacy invariant contract later in this
document; do not transfer those broad invariants into scoped learning.
Strictly validated IPv6 Neighbor Discovery and quoted ICMPv6 error delivery
remain infrastructure plumbing even when the peer is the contained bridge
gateway; that does not authorize application traffic to the gateway.

Known decoder or protocol coverage gaps are also distinct from policy denies.
Scoped learn permits an ordinary attempted flow while recording the gap and
preventing candidate promotion; audit records the corresponding would-deny;
enforce denies it. Missing configuration, backend identity drift, evidence
loss, and other failures of the containment boundary still fail closed.

The checked-in assets are deliberately split into:

- a privileged Tetragon host sensor pinned to `v1.7.0`;
- Inspektor Gadget evidence collectors pinned to `v0.54.1`;
- a canonical evidence and fixture contract;
- a managed DNS/egress contract;
- mode and failure semantics; and
- a read-only host doctor.

The standalone design requires a privileged external container manager; a
process inside the runner cannot safely attach host eBPF programs or establish
its own security boundary. This repository's `nosh-guardd` and
`nosh-guard-egress:0.1` are the initial Docker manager and managed DNS/egress
implementation. A Kubernetes deployment can replace them with CRI lifecycle
hooks, Tetragon, Cilium NetworkPolicy, and Security Profiles Operator. Starting
an `enforce` runner without one complete manager stack would provide only a
subset of the promised boundary and must fail admission.

That fail-closed condition is active in the shipped standalone daemon, not
merely a deployment recommendation. Every standalone `enforce` request is
rejected before host or profile setup with
`GUARD_STANDALONE_INGRESS_UNAVAILABLE`: the checked-in gateway consumes the
compiled egress rules, but there is no backend that consumes and enforces the
compiled ingress rules. There is no configuration bypass. Enforce mode
requires an external container/network manager integration that applies and
attests both directions, plus a corresponding admission integration; the
current standalone daemon must be extended or replaced for that deployment.

## Implementation gates

Treat this as a staged security project, not as a one-shot learned allowlist.
The contracts, compiler, standalone supervisor, gateway, sensor source, and
test fixtures can be reviewed independently, but production enforcement is
ready only when all of these gates are closed:

1. A privileged userspace loader attaches `bpf/nosh_l4` to the exact runner
   cgroup and publishes its events, map snapshots, build identity, and loss
   counters.
2. The manager normalizes Tetragon, Inspektor Gadget, `nosh_l4`, DNS, and
   gateway records into one per-run manifest and rejects missing, lossy, stale,
   or identity-mismatched inputs.
3. Tetragon policy load is attested after the operation: the exact runtime
   policy name must exist and report enforcement rather than `monitor_only`.
4. The gateway acknowledges the new DNS/nftables revision before the process
   gate is released. An out-of-process watchdog must quarantine runners if the
   daemon, resolver, or gateway hangs; the current implementation has an
   in-process poller plus a systemd exit helper, not an independent hang
   detector.
5. Every approved artifact is actually consumed: seccomp, AppArmor, Docker
   hardening, Tetragon, and network policy must match the live container and
   host state, not merely pass file validation.
6. Audit evaluators bind their results to the SHA-256 of all five candidate
   artifacts and completely report Tetragon shadow matches, seccomp log
   decisions, AppArmor complain decisions, Docker runtime conformance, and
   both network directions.
7. Negative tests prove container and namespace targeting, default-deny
   egress, direct-DNS denial, cleanup, restart recovery, event-loss handling,
   and fail-closed behavior on every supported kernel/runtime family.

Until those checks are automated, use `learn` and `audit` only in a disposable
environment and do not describe the output as an enforced Cilium-equivalent
profile. The checked-in implementation now automates substantial parts of the
first five gates for learn and audit. Gate 5 is not complete for enforce:
standalone admission rejects the run because no compiled ingress evaluator is
installed. The implementation also deliberately leaves gate 6 unsatisfied:
current audit manifests record the candidate hashes and the missing evaluator
coverage, so they cannot be counted as clean promotion runs. Production
readiness depends on closing those gaps and exercising every gate on the
supported hosts. The current `nosh_l4` tree provides the sensor ABI, reference
libbpf loader, build/install path, control schemas, and loss accounting.

The intended evidence-to-control mapping is:

| Layer | Learn/audit evidence | Enforce with |
| --- | --- | --- |
| Admission identity | authenticated launcher principal, requested agent/role, image digest | daemon authorization, image digest and approved profile binding |
| Process and syscall | Tetragon lifecycle/tracing events; reviewed IG seccomp advice | Docker seccomp, capability drop, no-new-privileges, narrow Tetragon actions |
| Files, mounts, namespaces | Tetragon file/LSM and high-risk syscall events | read-only root, bounded mounts, AppArmor, private namespaces |
| Network and DNS | `nosh_l4`, managed resolver logs, gateway decisions | per-run internal network plus DNS-aware nftables gateway, or Cilium |
| Resources and devices | Docker/cgroup state and runtime measurements | PID, CPU, memory, tmpfs, device, publish, and namespace limits |

“Coding agent” is an admission identity, not a trustworthy process label. An
agent can launch compilers, shells, package managers, tests, and arbitrary
project code; all descendants inherit the container/cgroup policy. If two
agents need different authority, give them distinct runner cgroups, image-bound
profiles, network identities, and authenticated management principals. Do not
attempt to authorize a process solely because its executable is named
`codex`, `claude`, or similar.

## Container-manager decision

An external manager is required. Tetragon observes and can enforce selected
kernel hooks, but it does not own Docker admission, image approval, seccomp,
AppArmor, volumes, credentials, per-run networking, or cleanup.

| Option | Best fit | Main tradeoff |
| --- | --- | --- |
| Docker plus `nosh-guardd` | local development and an incremental prototype | simplest deployment, but the gate process starts before sensors attach and all lifecycle/egress identity must be implemented here |
| containerd/CRI plus an OCI/runtime hook | hosts that need a pre-exec attachment point without Kubernetes | stronger lifecycle timing, with more runtime-specific integration and recovery work |
| Kubernetes plus Tetragon, Cilium, and Security Profiles Operator | multi-user or production agent pools | strongest workload identity and policy machinery, with the largest operational footprint |

Start with the standalone manager to learn the behavior and artifact model. If
the threat model includes mutually untrusted users, zero execution before
sensor attachment, frequent concurrent runners, or cluster-wide policy,
promote the design to Kubernetes/Cilium rather than growing a bespoke Docker
control plane indefinitely.

## Trust boundaries

Tetragon and Inspektor Gadget attach eBPF programs to the host kernel. They are
trusted host services and must never run inside the untrusted Nosh runner. Do
not mount the Tetragon socket, Docker socket, guard socket, eBPF filesystem, or
host `/proc` into a runner.

The guard API socket is deliberately an administrator endpoint. The daemon
runs as root and creates `/run/nosh-guardd.sock` under a restrictive umask so
the socket is `0600` from the instant it is bound; there is no post-bind
`chmod` window. It then verifies the socket type, owner, and exact mode. Before
using either the state root or socket parent it walks the full path and
requires real, non-symlink directories owned by root or the daemon UID and not
group- or other-writable; the state root itself must be mode `0700`.

The daemon also holds an exclusive `flock(2)` on the persistent
`/var/lib/nosh-guard/guardd.lock` anchor, which is a singly linked regular file
owned by the daemon UID at mode `0600`. The anchor is not deleted on shutdown;
closing the held descriptor releases the lock without creating a stale-lock
unlink race. This permits only one live daemon per state root even if two
instances request different socket paths.

Node's HTTP-over-Unix-socket API does not expose peer credentials here, so
making the socket group- or world-writable would grant lifecycle authority to
every caller. When running outside the supplied unit, preserve the same safe
ancestry and modes, and never bind-mount the socket into an agent container.

The expected flow is:

```text
nosh.sh
  -> nosh-guard CLI
    -> /run/nosh-guardd.sock
      -> Docker API: create a gated, hardened runner
      -> Tetragon / Inspektor Gadget: attach evidence collectors
      -> nosh-guard-egress: attach a private per-run network and DNS identity
      -> release the runner gate
      -> /var/lib/nosh-guard/evidence/<run-id>
      -> compiler: unapproved candidate artifacts
      -> explicit approval: image digest + artifact hashes
      -> external-manager enforce: apply both network directions,
         re-verify hashes, then launch
```

The final arrow is a required integration point, not a capability of the
shipped standalone daemon.

The process gate narrows the startup race but is not equivalent to an OCI
pre-start runtime hook: Docker has already launched the small gate process
before per-run collectors attach. Do not include that gate process in the
learned application baseline. Kubernetes with Tetragon runtime hooks is the
stronger design when zero pre-attachment execution is required.

## Fixed locations and versions

The daemon and CLI use:

| Purpose | Location |
| --- | --- |
| Configuration | `/etc/nosh-guard` |
| Durable state | `/var/lib/nosh-guard` |
| Daemon exclusion lock | `/var/lib/nosh-guard/guardd.lock` |
| Guard socket | `/run/nosh-guardd.sock` |
| Tetragon socket | `/run/nosh-guard/tetragon/tetragon.sock` |
| Build adapter configuration | `/etc/nosh-guard/build-adapters.json` |
| Root build-session state | `/var/lib/nosh-guard/build-runs` |
| Root build-session evidence | `/var/lib/nosh-guard/build-evidence` |

Override paths only with the corresponding `NOSH_GUARD_*` environment
variables. An overridden guard socket must remain under a root-owned runtime
directory and mode `0600`. Do not put credentials in adapter arguments or
committed configuration.

Profile selection and trust anchoring use different variables.
`NOSH_GUARD_PROFILE_DIR` is only the default candidate/approved directory
selected for a `run` when `--profile-dir` is omitted.
`NOSH_GUARD_TRUSTED_PROFILE_ROOT` is the root below which
`profile approve` accepts root-owned candidates; it defaults to the guard
state directory's `profiles/` location (`/var/lib/nosh-guard/profiles` with
the default state directory). Enforce admission independently requires the
approved directory below the running daemon's own state `profiles/` directory,
so custom deployments must keep the approval trust root and daemon state root
aligned. Neither variable approves a candidate by itself.

`NOSH_GUARD_TETRAGON_SOCKET` changes the doctor probe only. Runtime sensor
commands use the socket configured in the root-owned `adapters.json`; moving
that socket requires a reviewed adapter configuration and a matching Tetragon
mount.

`NOSH_GUARD_BUILD_ADAPTER_CONFIG` changes the daemon's build-collector
configuration from `/etc/nosh-guard/build-adapters.json`. Keep any override in
a root-owned, non-symlink directory and install it mode `0640` or stricter.
`NOSH_BUILDKIT_IMAGE` selects the dedicated builder image used by the
unprivileged build orchestrator; live deployments must use the reviewed
digest-qualified reference, not a mutable tag.

[versions.json](../config/nosh-guard/versions.json) pins:

- `quay.io/cilium/tetragon:v1.7.0` and a matching `tetra` CLI;
- `ig v0.54.1`;
- `trace_dns:v0.54.1`; and
- `advise_seccomp:v0.54.1`; and
- `nosh-l4-loader` version 1 with evidence schema 1.

[build versions](../config/nosh-build/versions.json) separately pin the build
collector ABI and BuildKit `v0.30.0` to an exact multi-platform index digest.
Live build profiling rejects mutable BuildKit references; any deployment
override must likewise use a reviewed `@sha256` identity rather than `latest`.

Version tags make review understandable but are not immutable supply-chain
identities. Production installation should resolve each image to a digest,
record that digest in deployment inventory, and keep Inspektor Gadget image
signature verification enabled. Never substitute a `latest` tag.

## Host requirements

The official Tetragon minimum kernel is 4.19, `advise_seccomp` needs 5.6, and
`trace_dns` needs 5.4. Nosh Guard's overall minimum is nevertheless Linux 5.8
because the required `nosh_l4` sensor uses a BPF ring buffer. A current 6.x LTS
kernel is the recommended baseline. The host needs:

- kernel BTF, normally `/sys/kernel/btf/vmlinux`;
- cgroup v2 and bpffs;
- `CONFIG_BPF`, `CONFIG_BPF_SYSCALL`, `CONFIG_BPF_JIT`,
  `CONFIG_BPF_EVENTS`, `CONFIG_CGROUP_BPF`, and syscall tracing;
- `CONFIG_BPF_KPROBE_OVERRIDE` for Tetragon `Override` actions;
- `CONFIG_BPF_LSM=y` and `bpf` in `/sys/kernel/security/lsm` for BPF LSM
  policies;
- AppArmor active in `/sys/kernel/security/lsm`, securityfs mounted at
  `/sys/kernel/security`, and `apparmor_parser` able to replace and remove
  profiles through `/sys/kernel/security/apparmor`;
- Docker and access to its Unix socket from the root guard daemon;
- Docker Engine API `v1.44` or newer; the current client pins `v1.44` and does
  not negotiate down;
- util-linux `flock` installed at exactly `/usr/bin/flock` or `/bin/flock`;
- a runner image labeled `io.notty.guard.runner-abi=1`;
- the version-2 `nosh-egress-loader` and its exact digest-bound BPF object
  installed under `PREFIX/libexec/nosh-guard/`, with bpffs mounted at
  `/sys/fs/bpf`, for scoped egress modes;
- the version-1 `nosh-l4-loader` installed under
  `PREFIX/libexec/nosh-guard/` (default prefix `/usr/local`);
- the version-4 `nosh-build-loader` installed under
  `PREFIX/libexec/nosh-build/` and the root-owned build adapter file at
  `/etc/nosh-guard/build-adapters.json` when Docker builds will be profiled;
- the version-1 `nosh-url-loader` retained under
  `PREFIX/libexec/nosh-build/` as a disabled legacy observation-only collector;
- the exact digest-pinned managed mitmproxy image when full HTTP capture is
  explicitly selected for build network learning;
- the Docker Buildx plugin and its `docker-container` driver for build
  profiling;
- Python 3 for the checkout doctor's read-only JSON syntax checks; the doctor
  never invokes host Node, npm, npx, or npm exec;
- the exact `tetra` and `ig` CLI versions for full-profile modes; and
- for legacy full-profile modes only, host `nsenter` and `ip` plus the trusted
  `nosh-guard-egress:0.1` image labeled `io.notty.guard.egress-abi=1`.

Scoped `egress-learn`, `egress-audit`, and `egress-enforce` do not require the
legacy gateway image, dnsmasq, nftables, `nsenter`, `ip`, Tetragon, BPF LSM, or
AppArmor policy loading. They require cgroup v2, bpffs, BTF, the first-party
`nosh-egress` loader/object, Docker, and an exact runner image.

Run the non-mutating preflight before installing or upgrading:

```bash
bash scripts/nosh-guard-doctor.sh --mode egress-learn
bash scripts/nosh-guard-doctor.sh --mode learn
bash scripts/nosh-guard-doctor.sh --mode enforce
```

The enforce invocation deliberately includes a failed
`standalone ingress evaluator` check and therefore exits `1` in the shipped
deployment. It is useful for seeing the complete remaining readiness report,
not as an admission-ready result.

`--deep` additionally runs Tetragon's transient feature probe and asks
Inspektor Gadget to enumerate Docker containers. It never installs or starts a
service, but the Tetragon probe can briefly load and detach eBPF programs, so
the flag is an explicit operator choice:

```bash
sudo bash scripts/nosh-guard-doctor.sh --mode learn --deep
```

Exit status `0` means there were no failed checks, `1` means the host is not
ready, and `2` means the command line was invalid. Warnings do not change the
exit status.

The shared doctor does not create a BuildKit container. Build profiling also
performs its own live preflight for a local Unix Docker endpoint, Linux,
cgroup v2, non-rootless Docker, Buildx, the exact builder identity, and both
required build collectors. Managed HTTP capture, when selected, is a distinct
digest-bound userspace proxy source; the legacy URL uprobe is disabled. The
doctor's `--deep` host probe is unrelated to
`nosh build profile --depth deep`; the latter remains unavailable until the
off-CPU and block-latency collectors are installed. Metadata-only file-open
collection is available separately as `nosh build profile --depth policy`.

Build network learning uses the version-2 `nosh-build` DNS evidence contract.
For bounded IPv4 and IPv6 UDP DNS on port 53, it records queries and responses,
transaction correlation IDs, resolver and client endpoints, A/AAAA addresses,
CNAME chains, and answer TTLs. The build summarizer can correlate a query to a
process/socket and an answer address to a same-pass L3/L4 destination only
when a unique exact query tuple was observed before the response, the response
is untruncated and fully parsed, and the destination attempt follows that
response within a TTL capped at five minutes. Query-to-process attribution is
an explicitly heuristic same-socket/resolver, nearest-preceding join bounded to
30 seconds because the L4 sendmsg hook cannot report the local UDP port. CNAME
chains use the minimum TTL across every traversed alias edge and the terminal
address record. These links are observational evidence for review, not proof
that every request used that answer and not an automatic FQDN allow rule. DNS
over TCP, encrypted DNS, UDP behind unsupported IPv6 extension headers, parse
failures, and responses beyond the fixed answer budget remain explicit coverage
gaps. Their L3/L4 destinations, including direct DNS and DNS-over-TLS, remain
observable and are not denied by build learning.

`nosh-url` is retained only to parse older private evidence and is not active in
any default build mode. Full HTTP observation uses
`nosh build net learn --http-capture mitmproxy`: the builder remains scoped by
the required eBPF collectors, while a digest-pinned managed proxy records exact
request/redirect/response identities and immutable response objects. These
streams remain independent. The current eBPF attachment proves the
workload-to-proxy leg; provider-reported upstream addresses are not promoted to
origin reachability. Until a separate proxy-cgroup L4 source exists, the origin
leg is a blocking Policy Review gap and creates no origin authority proposal.

## Guarded runner ABI

Admission requires the exact image label:

```text
io.notty.guard.runner-abi=1
```

The check happens before network allocation or container creation, and the
doctor checks the same label with `--runner-image`. The label declares
compatibility; it is not a signature, image provenance, or supply-chain
attestation. ABI version 1 assumes `/bin/sh`, `/bin/bash`, `node`, `sleep`,
`mkdir`, and `chmod`. `--start-app` additionally assumes `/app`, npm, and the
`start:next:sse` package script.

The runner uses the non-root UID/GID that owns the workspace. Build the
supported image/workspace pairing with compatible ownership; the guard does
not currently prove that the image has a matching passwd entry. It forces
`HOME=/home/nosh-guard` and every XDG directory beneath an empty, UID/GID-owned
`0700` tmpfs. That home and `/tmp` are `noexec`, `nosuid`, and `nodev`, and
disappear with the container. Install executable toolchains in a reviewed
image or workspace rather than under the ephemeral home.

The root filesystem is read-only and the workspace is the only persistent
writable bind. No Codex, Claude, Gemini, launcher OTP, Basic-auth, or arbitrary
host credentials are projected. Secure profile names are role metadata only;
legacy profile mounts and devices are not applied. A hosted coding agent still
needs the separately designed credential broker described under limitations.
Do not place durable provider credentials in the workspace as a workaround.

The normal `nosh.sh`/`nosh-guard run` path constructs the runner environment;
it does not copy the launcher's host environment wholesale. It supplies the
mode, exact run and agent IDs, work directories, Collab switch and role names,
forces `NOTTY_COLLAB_UNSANDBOXED=false` and
`NOTTY_BASIC_AUTH_ENABLED=false`, and adds `NOTTY_CONFIG` only when the
selected file resolves inside the workspace. `HOME` and the five `XDG_*`
locations are then overwritten with the fixed ephemeral paths above. When the
mTLS gateway is enabled, the daemon also overwrites `ALLOWED_ORIGIN`,
`NOTTY_PUBLIC_HOST`, `NOTTY_PUBLIC_WS_URL`, and `NOTTY_TRUSTED_HOSTS` from its
configured public origin. A direct caller of the root-only guard API is an
administrator and can request additional non-secret environment entries;
the daemon still strips launcher OTP and Basic-auth username/password fields
and retains control of the fixed home and gateway-origin values.

## Installing the sensor assets

The supported installer creates the root-owned configuration, state, runtime,
binary, documentation, and service paths. The network contract it seeds on a
new host is an example, not an approved production allowlist. Replace its
domains and revision with the result of reviewed learning runs. It documents
and validates manager behavior; per-run enforcement consumes the approved
`network-policy.yaml` artifact, not this example file directly.

First run `./setup-nosh.sh` as the account that will use Nosh. It creates the
user `nosh` and development `nosh-guard` links plus a strict mode-`0600` path
record; it never invokes sudo. If the privileged Guard is absent, setup prints
the reviewed bundle recipe below. `--guard-prefix /opt/notty` records a custom
software prefix, `--require-guard` makes incomplete host readiness fatal, and
`--check` performs a non-mutating readiness check.

Never run npm on the host. Use this fail-closed flow to build the supported,
checksummed host archive, verify and extract it without root authority, and
run only its installer through `sudo`:

```bash
(
  set -euo pipefail
  work_dir="$(mktemp -d)"
  trap 'rm -rf -- "$work_dir"' EXIT
  artifact_dir="$work_dir/artifacts"
  extract_dir="$work_dir/extracted"
  install -d -m 0700 "$artifact_dir" "$extract_dir"
  ./scripts/build-nosh-guard-host-bundle.sh --output-dir "$artifact_dir"
  shopt -s nullglob
  archives=("$artifact_dir"/*.tar.gz)
  checksums=("$artifact_dir"/*.tar.gz.sha256)
  if (( ${#archives[@]} != 1 || ${#checksums[@]} != 1 )); then
    printf 'expected exactly one Nosh Guard archive and checksum\n' >&2
    exit 1
  fi
  archive="${archives[0]}"
  checksum="${checksums[0]}"
  if [[ ! -f "$archive" || -L "$archive" || ! -f "$checksum" || -L "$checksum"
    || "$checksum" != "$archive.sha256" ]]; then
    printf 'Nosh Guard archive or checksum is unsafe or mismatched\n' >&2
    exit 1
  fi
  (cd "$artifact_dir" && sha256sum --check --strict -- "$(basename "$checksum")")
  tar -xzf "$archive" -C "$extract_dir"
  installers=("$extract_dir"/*/install.sh)
  if (( ${#installers[@]} != 1 )) || [[ ! -f "${installers[0]}"
    || -L "${installers[0]}" || ! -x "${installers[0]}" ]]; then
    printf 'expected exactly one safe Nosh Guard installer\n' >&2
    exit 1
  fi
  sudo "${installers[0]}" install --prefix /usr/local --enable-now --deep-verify
)
```

If Docker panics under `/usr/lib/msft-golang` at
`OSSL_PARAM_BLD_push_octet_string`, this is a host Moby/Buildx runtime issue.
The affected host Moby components must be upgraded before rerunning this
unchanged flow; do not run npm on the host or weaken checksum or deep
verification.

Docker is mandatory for this command; host Node.js, npm, npx, clang, bpftool,
and the loader development packages are not used. The wrapper builds a
dedicated image from the exact pinned base
`node:24.18.0-bookworm-slim@sha256:cb4e8f7c443347358b7875e717c29e27bf9befc8f5a26cf18af3c3dec80e58c5`.
Debian compiler and CO-RE packages resolve only while that image is built. The
packaging container then runs with no network as the invoking user's UID/GID,
with all capabilities dropped, a read-only root filesystem, the checkout
mounted read-only, executable scratch tmpfs, `/sys/kernel/btf/vmlinux` mounted
read-only, and only the selected artifact directory exposed as a writable host
path.

The daemon must be local, rootful, non-userns-remapped, and Linux. Rootless or
userns-remapped Docker is rejected because its ID mapping cannot preserve both
the non-root container UID and the caller-owned private output-directory
contract.

Inside that boundary, the builder packages the Guard's checked-in local
JavaScript module closure, which imports no third-party JavaScript packages,
and clean-builds all four CO-RE loaders against the mounted host BTF. It copies the
pinned image's Node `v24.18.0` runtime and corresponding license into the
archive. The manifest, installer, and systemd preflight bind and recheck the
runtime digest and version. There is no public host-runtime override: changing
the runtime or toolchain means reviewing and changing the builder image pin.
The compatibility option `--use-existing-loaders` skips compilation and reads
the four already-built loader binaries plus the exact egress BPF object from
the read-only checkout; use it only for separately built, reviewed artifacts.
It still packages inside the
same offline container and never selects a host Node.js runtime.

The normal runner can still be built as the invoking, non-root workspace user
so its UID/GID matches that user's projects:

```bash
./build-nosh.sh
test "$(
  docker image inspect \
    --format '{{ index .Config.Labels "io.notty.guard.runner-abi" }}' \
    nosh
)" = 1

test -x /usr/bin/flock || test -x /bin/flock
```

By default all four loader builds consume `/sys/kernel/btf/vmlinux` and start from
clean collector trees, preventing a stale object, skeleton, or loader from
entering the archive. The grouped flow uses fresh private artifact and
extraction directories, requires exactly one matching archive, checksum, and
installer, and removes its unprivileged work directory on exit.

The root installer verifies a complete internal manifest before mutation,
installs a versioned release below
`PREFIX/lib/notty/nosh-guard/releases` (default prefix `/usr/local`),
atomically selects `current`, and deploys the rendered launchers, daemon
payload, loaders, adapter configuration, licenses, documentation, and systemd
unit.
It binds the release name to the initially verified manifest digest and repeats
the complete inventory, hash, object-type, and hard-link checks after copying
the payload into root-owned staging.
Existing authoritative adapter configuration must match; after review, use
`--replace-config` to replace a drifted copy. The network contract is seeded
only when absent and is not overwritten on upgrade; an existing copy must be a
singly linked, root-owned mode-`0640` regular file.

For unattended build profiling, `--sudoers-group GROUP` installs a
`visudo`-validated rule limited to exact `build-session begin`, `finish`,
`abort`, and `exported` commands. The final command acknowledges retention only
after the unprivileged private and portable bundle has been durably adopted.
The named group must already have Docker access. No sudoers policy is installed
by default.

Pass `--prefix /opt/notty` to install the software below another reviewed,
root-owned prefix. The manifest-covered renderer adjusts only software paths:
`PREFIX/bin`, `PREFIX/lib/notty/nosh-guard`, `PREFIX/libexec`, and
`PREFIX/share/doc/notty`. Configuration and state remain under
`/etc/nosh-guard` and `/var/lib/nosh-guard`; the runtime socket, systemd unit
destination, and sudoers destination also remain fixed. The installer records
the selected prefix in the root-owned mode-`0644`
`/etc/nosh-guard-install-layout.conf` receipt and refuses an implicit
cross-prefix upgrade.

An existing Nosh sudoers file must be a singly linked, root-owned mode-`0440`
regular file and exactly match the requested rule. Drift is refused; after
review, `--replace-sudoers` explicitly authorizes replacement. An installer
that finds this file requires `--sudoers-group` even when no policy change is
requested, preventing silent adoption of host authority.

The daemon runs the applicable loader health commands before attachment,
resolves the exact container cgroup path and kernel ID, then waits for JSON
`ready` records before releasing the relevant runner/build gate. A clean stop
must yield final stats records; missing final stats or any reported loss
invalidates the evidence. Runtime and build sessions use separate state and
candidate stores even though both require `nosh-l4-loader`.

Both loader `run` processes arm Linux `PR_SET_PDEATHSIG` with SIGTERM and check
for a parent-exit race before loading BPF, so a daemon crash requests link
teardown rather than leaving an orphaned collector.
They also lower `RLIMIT_FSIZE` to at most 128 MiB per regular output file and
treat `SIGXFSZ` as fatal; the daemon's live byte quota independently bounds
each pipe-backed evidence stream. Build-profile finalization separately bounds
combined sources by their validated cold/warm pass count (at most two), while
retaining the 128 MiB per-pass ceiling.

### Legacy/full-profile gateway image

The scoped `nosh net` eBPF workflow does not build or use this image. The
following instructions are retained only for deployments of the historical
full-profile managed gateway.

Build the checked-in standalone gateway image before running the daemon:

```bash
docker build \
  -f Dockerfile.nosh-egress \
  -t nosh-guard-egress:0.1 \
  .
```

This creates `nosh-guard-egress:0.1` locally. The build fetches the
digest-pinned base image only when it is absent from the local image store; it
does not pull the output tag from a registry.

The daemon never builds or pulls this trusted image automatically. Runtime
egress admission fails with `GUARD_EGRESS_IMAGE_MISSING` before creating a
gateway container or per-run network when the configured image is absent;
install it from a reviewed checkout or configure `NOSH_GUARD_EGRESS_IMAGE` to
a reviewed local immutable image ID or digest-pinned reference.

The gateway image must also carry `io.notty.guard.egress-abi=1`. The daemon
and doctor reject a missing or different label before gateway or per-run
network mutation with `GUARD_EGRESS_IMAGE_ABI_MISMATCH`. This ABI covers the
host/gateway policy-acknowledgement contract: a syntactically valid stale
acknowledgement fails immediately with
`GUARD_EGRESS_POLICY_ACK_MISMATCH` and names the incompatible fields instead
of waiting for the generic attestation timeout.

Rebuilding a mutable tag does not replace an already-created singleton, and a
host-bundle reset preserves the managed gateway. If the tag or singleton has
the wrong ABI, first confirm there are no active or quarantined Guard runs,
stop `nosh-guardd`, then stop and remove only the `nosh-guard-egress`
container. Restart the daemon and retry so it creates the singleton from the
reviewed compatible image. The daemon deliberately does not auto-delete or
replace a gateway that might still carry live isolated networks.

Production deployment should pin the resulting image digest in deployment
inventory. The host bundle installs the complete local module closure instead
of copying a `bin/` launcher without its imports. The bpffs unit mounts and
attests `/sys/fs/bpf` before `deploy/systemd/nosh-guardd.service`; the Guard
unit runs the daemon as root and invokes the
separate fail-closed cleanup helper after exit. It makes configuration and
state directories root-owned, uses a private device view, protects the clock,
hostname, cgroup filesystem, kernel logs, modules, and most kernel tunables,
and stops the unit if one of its processes is OOM-killed. Adapt its AppArmor
and Tetragon service dependencies to the actual host deployment, then test
daemon-kill recovery before enabling runners.

The host bundle does not install Docker, `tetra`, `ig`, nftables,
AppArmor tools, `flock`, `nsenter`, or `ip`. Install and pin those runtime host
dependencies separately. Compiler, bpftool, and development packages remain
in the disposable builder image and are not installed on the host. The
daemon accepts only the two absolute `flock` paths above; a copy elsewhere on
`PATH` does not satisfy exclusion. The supported bundle uses `/usr/local` by
default and renders its complete manifest-covered unit, wrapper, verifier,
adapter, and sudoers set when `--prefix` selects another trusted software
root. `/bin/bash` and the fixed host-integration paths above do not relocate.

The bundled Node executable comes from the pinned Bookworm image rather than
host `PATH`. Deploy it only to the same architecture and a compatible
libc/libstdc++ ABI, or rebuild the archive on the destination host. The fixed
launchers execute the manifest-covered runtime below the selected versioned
release; they do not resolve a mutable host `node` from `PATH` or append
caller-controlled search paths. Docker and adapter tools must be installed below the selected
`PREFIX/sbin` or `PREFIX/bin`, or below `/usr/local/sbin`, `/usr/local/bin`,
`/usr/sbin`, `/usr/bin`, `/sbin`, or `/bin`.
The compiled loaders retain the Bookworm builder's userspace runtime
dependencies, normally libbpf, libelf, zlib, and libc. These shared objects
are not vendored. A matching kernel BTF layout is not proof of userspace ABI
compatibility; use `--deep-verify` on every target before enabling the service.

`apparmor_parser --replace` and `--remove` are privileged profile operations
through the AppArmor security filesystem. Consequently, the unit cannot make
all of `/sys` read-only: with `ProtectKernelTunables=true`, it explicitly
carves back write access to `/sys/kernel/security/apparmor`. It also permits
`/sys/fs/bpf` for the configured eBPF collectors. These exceptions are for the
trusted root manager only and must not be exposed to a runner. The unit retains
a writable `/run` because the current server creates the top-level
`/run/nosh-guardd.sock`; moving that socket under a dedicated runtime
directory or adding systemd socket activation would allow a narrower mount
exception.

`TimeoutStopSec=90` gives supervised collectors time to handle `SIGTERM`,
detach, and flush final records. Size that timeout for the maximum supported
runner concurrency and test it under load. If systemd reaches the timeout and
uses `SIGKILL`, treat every affected evidence set as incomplete.

The Compose template is the official privileged-container deployment adapted
to a host Unix socket:

```bash
docker compose \
  -f config/nosh-guard/tetragon/compose.example.yaml \
  up -d
```

Its important properties are `pid: host`, host cgroup namespace, privileged
execution, the host BTF mount, no network, and a host-mounted Unix socket.
Protect the socket as a policy-administration endpoint. The host `tetra` CLI
connects with:

```bash
tetra \
  --server-address unix:///run/nosh-guard/tetragon/tetragon.sock \
  version --server
```

If Compose's `cgroup: host` field is unsupported by the installed Compose
version, use the official Docker form with `--pid=host --cgroupns=host
--privileged` rather than silently dropping host cgroup visibility.

After the host bundle, Tetragon, both images, and external host dependencies
are present, verify the installed manifest, enable the daemon if installation
did not use `--enable-now`, run the learn-mode doctor, and inspect the
intentionally failing enforce-mode report:

```bash
sudo /usr/local/libexec/nosh-guard/nosh-guard-host-verify --deep
sudo systemctl daemon-reload
sudo systemctl enable --now nosh-guardd.service
sudo nosh-guard doctor --mode learn
sudo nosh-guard doctor --mode enforce
```

Do not enable guarded runners merely because systemd reports the daemon
running. The doctor must also find the selected runner image, gateway image,
Docker daemon, Tetragon socket/CLI, IG CLI, nftables, AppArmor, and
`nosh-l4-loader` requirements for the requested mode. The shipped
`doctor --mode enforce` always fails its explicit missing-ingress check; that
failure cannot be bypassed by satisfying the other probes.

The daemon creates `/run/nosh-guardd.sock` itself with mode `0600`; the bundle
does not install a socket unit because this server does not implement systemd
socket activation. `ExecStartPre` verifies the selected release manifest and
all authoritative deployed copies before every service start.

To rebuild from the reviewed checkout and refresh the existing installation
in place, run the reset wrapper as the Docker-authorized user:

```bash
./reset-nosh-guard.sh
```

It selects the installed prefix from the protected layout receipt (or accepts
`--prefix ABS`), performs the checksummed bundle build and extraction without
root, then invokes only `install.sh install` through `sudo`. The refresh
enables and starts the daemon, performs deep verification, and preserves all
configuration and evidence by default. It preserves the separately built
managed egress image and its gateway container; use the reviewed replacement
procedure above when that host/gateway contract changes. It fails closed if a
bundle-authoritative adapter or version file differs. After reviewing an
intentional collector-contract upgrade, use
`./reset-nosh-guard.sh --replace-config`; that option replaces only the
bundle-authoritative adapter/version files, never the operator-managed network
contract, state, or evidence. The wrapper never uninstalls or passes
purge/force options.

To uninstall while preserving policy and evidence, run:

```bash
sudo /usr/local/lib/notty/nosh-guard/current/install.sh uninstall
```

For a custom installation, replace `/usr/local` with its prefix and pass the
same `--prefix PREFIX` to `verify` or `uninstall`.

Add `--purge-config` to remove only known bundle-managed configuration files.
Add `--purge-state` only when permanent deletion of all Guard evidence and
state below `/var/lib/nosh-guard` is intended. The default preserves both.

## Authenticated runner gateway

The optional TLS gateway exposes one selected runner's Notty HTTP, SSE, and
WebSocket routes to an mTLS-authenticated principal. It is not a remote guard
administration API: `/v1/runs` and all lifecycle operations remain available
only through the root-owned Unix socket.

Install an operator-issued server certificate, server key, and client CA
under a root-only directory. The server certificate SAN must match the
browser-visible hostname. Then create `/etc/nosh-guard/nosh-guard.env` with
mode `0600`:

```ini
NOSH_GUARD_GATEWAY_CERT=/etc/nosh-guard/pki/server.crt
NOSH_GUARD_GATEWAY_KEY=/etc/nosh-guard/pki/server.key
NOSH_GUARD_GATEWAY_CA=/etc/nosh-guard/pki/client-ca.crt
NOSH_GUARD_GATEWAY_PUBLIC_ORIGIN=https://guard.example:3443
NOSH_GUARD_GATEWAY_HOST=0.0.0.0
NOSH_GUARD_GATEWAY_PORT=3443
```

The three TLS paths and public origin are an all-or-none contract; incomplete
configuration stops daemon startup. The public origin must be one exact HTTPS
origin without credentials, path, query, or fragment, and must include a
non-default external port. With no explicit bind settings the gateway listens
on `127.0.0.1:3443`. Configure this before creating runners. The daemon binds
the origin into both runner environment and the root-owned per-run proxy
policy, so an origin change requires a daemon restart and fresh runners.

Create a short-lived principal from the SHA-256 fingerprint of a client
certificate. Prefer an exact run binding:

```bash
fingerprint="$(
  openssl x509 -in client.crt -noout -fingerprint -sha256 |
    sed 's/^[^=]*=//'
)"

sudo nosh-guard principal add \
  --id agent-run-1 \
  --fingerprint "$fingerprint" \
  --run '<run-id>' \
  --ttl-seconds 3600
```

`--agent-id` is an alternative only when it resolves to exactly one running
run. TTL is limited to 1–86,400 seconds. Principal files are read on every new
request, so add/revoke does not require a gateway restart. Active HTTP, SSE,
and WebSocket sessions are also revalidated at a bounded interval of no more
than five seconds and have a separate exact-expiry timer. The gateway closes
them when the principal is revoked or mutated, its route authorization
changes, the selected run stops or is replaced, or the bound
run/container/agent identity no longer matches. Omitting `--prefix` grants the
fixed route ceiling below; repeat `--prefix` to narrow it, for example
`--prefix /mcp --prefix /health`. A prefix permits its exact path and
descendants, except `/`, which permits only the root page.

```text
/
/collab
/mcp
/_next
/credentialless-bootstrap.js
/api/features
/api/lockdown
/api/ws
/api/agents
/api/collab
/api/copilots
/sse
/message
/api/mcp
/api/spawn-otps
/api/terminals
/ws/terminals
/oauth/token
/health
```

No stored prefix can widen that ceiling. Requests must use the configured
Host authority; a browser Origin, when present, must equal the configured
origin. The gateway strips caller-controlled forwarding, guard, common proxy,
and Next.js control headers, then injects its own origin, forwarding metadata,
principal, agent, and exact run ID through both proxy hops.

mTLS terminates at Nosh Guard. Putting a front proxy in front of it with one
shared backend client certificate collapses every end-user identity into that
single principal unless a new authenticated identity-propagation design is
implemented and reviewed.

## Security modes

[mode-contract.json](../config/nosh-guard/mode-contract.json) is the normative
mode contract.

The first three rows are the legacy/full-profile manager contract. The scoped
rows are the runtime learn/review/audit/enforce path described above; broad
legacy private-network invariants do not apply to them.

| Mode | Candidate behavior | Network behavior | Failure result |
| --- | --- | --- | --- |
| `learn` | Baseline hardening remains on; collect representative full-profile evidence; write only an unapproved candidate. | Legacy managed-gateway behavior records and allows except for that path's explicitly documented invariants. | Reject admission, or stop and mark the run incomplete. |
| `audit` | Snapshot one exact full-profile candidate and run non-blocking controls where implemented. Missing backend evaluators make the run non-promotable. | Legacy managed-gateway behavior records egress would-deny decisions while its explicit invariants remain active; ingress is not yet evaluated. | Quarantine, stop, and mark the audit incomplete on collection failure. |
| `enforce` | Required design: verify image identity, approval record, and every artifact hash before applying approved controls. The shipped standalone daemon rejects admission first. | Required design: default deny in both directions. The checked-in gateway implements egress only. | `GUARD_STANDALONE_INGRESS_UNAVAILABLE` until an external manager integration supplies compiled ingress enforcement. |
| `egress-learn` | Collect a workspace- and image-bound outbound candidate; candidate policy never blocks. | Record and allow ordinary destinations, including private addresses and direct DNS/DoT; deny only exact per-run platform containment endpoints. | Reject admission, or stop and mark the run incomplete; coverage gaps cannot advance a candidate. |
| `egress-audit` | Snapshot one exact reviewed scoped policy; evidence is diagnostic-only. | Emit would-deny for traffic outside reviewed authority and allow it; exact platform containment remains denied. | Quarantine, stop, and mark the audit incomplete on collection or backend failure. |
| `egress-enforce` | Load only the active, signed, workspace/image/backend-bound eBPF leaf. | Default deny; allow only reviewed rules. Exact platform containment cannot be authorized. | Reject admission or quarantine and stop on policy/backend drift. |

Secure launch must never fall back to legacy Docker behavior. A missing daemon,
sensor, profile, approval, DNS proxy, network gateway, or firewall is an
admission failure.

The ingress rejection occurs for every standalone enforce request, even when
the candidate and approval are otherwise valid. A profile hash, approval
override, dependency grant, or `--allow-incomplete` cannot enable it.

The baseline is not relaxed in learn mode. Learning does not mean privileged,
unconfined, writable-root, host-networked, or Docker-socket access.

## Tetragon policy semantics

Tetragon emits process lifecycle events without a custom tracing policy. The
default `tetragon-events` adapter streams those events and filters the output by
container name. That filter is a client/export filter; it is not a kernel
enforcement selector.

The name filter is also not accepted as evidence attribution. Before
projection, manifest-backed ingestion requires every canonical Tetragon record
to carry a container ID and every recognized native Tetragon envelope to carry
an attributable container ID in its event payload. Every observed ID must
exactly equal the manifest's container ID; missing or mismatched identity
rejects the source.

Standalone Docker cannot use Tetragon's Kubernetes `podSelector`,
`containerSelector`, or `matchWorkloads` identity. Docker container IDs are
event metadata, not a supported tracing-policy enforcement selector. The
operator-authored templates therefore use a rendered `Cgroup` namespace inode:

- [observe-high-risk.yaml.tmpl](../config/nosh-guard/tetragon/observe-high-risk.yaml.tmpl)
  records namespace, mount, ptrace, BPF, perf, and connect activity.
- [candidate-deny-dangerous-syscalls.yaml.tmpl](../config/nosh-guard/tetragon/candidate-deny-dangerous-syscalls.yaml.tmpl)
  contains narrow `Override` actions but embeds monitor mode.
- [candidate-enforcement-rules.example.json](../config/nosh-guard/tetragon/candidate-enforcement-rules.example.json)
  is the equivalent compiler input shape for `--tetragon-rules`. It is a
  review example, not a pre-approved policy.

A cgroup namespace inode is not a cgroup path or stable workload identity. It
changes when a container is recreated. Before rendering either template:

1. inspect the exact target container;
2. resolve its init PID;
3. verify its cgroup namespace differs from the host and other runners;
4. obtain the inode from `/proc/<pid>/ns/cgroup`;
5. replace both template markers;
6. reject any marker left in the rendered file; and
7. load it in monitor mode on the exact target host.

Never load an unrendered template. Never reuse a rendered policy after a
container restart.

Tetragon has three effective policy states:

- `monitor_only`: the policy has no enforcement action and cannot be changed
  into enforcement;
- monitoring: enforcement actions exist but are elided; and
- enforcement: actions are active.

The CLI spellings are `--mode monitor` and `--mode enforce`. Load-time CLI mode
overrides the embedded `spec.options` mode. Critically, asking Tetragon to load
a `monitor_only` policy with `--mode enforce` succeeds with a warning; it does
not turn `Post` events into denies.

For that reason:

- learn and audit never auto-load compiler-produced Tetragon candidates;
- the separately authored observation template may be loaded only in monitor
  mode;
- the downstream enforce path activates `tetragon-enforce-policy` only in
  `enforce` (that path is currently unreachable in the standalone daemon);
- `{tetragonPolicy}` must point inside the approved profile directory;
- any manager that enables the downstream path must verify approval and
  artifact hashes before running the adapter; and
- admission must fail unless the post-load policy list reports enforcement,
  not `monitor_only` or monitoring.

That first rule means the current Tetragon stream is observation evidence, not
a shadow evaluation of the candidate's blocking selectors. The audit manifest
therefore marks the Tetragon backend incomplete. It must stay non-promotable
until a cgroup-scoped companion evaluator reports candidate matches without
activating the deny action.

The `tetragon-enforce-policy` adapter performs that post-load check with
`nosh-guard-tetragon-verify`. The helper requests JSON from the pinned `tetra`
CLI, selects one exact runtime name, and requires both
`TP_STATE_ENABLED` and `TP_MODE_ENFORCE`. It is read-only and emits a compact
JSON attestation; a missing, duplicate, loading, disabled, errored,
monitoring, or monitor-only result fails admission. This control adapter is
recorded in run state but has `evidence: false`, so its command log is not
mistaken for workload evidence by the compiler.

The runtime renderer gives each loaded policy a collision-resistant name and
records that exact name in the run state. Detach must delete
`{tetragonPolicyName}` from that state; reconstructing a name from the run ID
or approved template risks leaving an enforcement policy attached to the host.
A failed delete keeps the run quarantined and blocks run-ID reuse.

`Override` requires a compatible error-injectable hook and
`CONFIG_BPF_KPROBE_OVERRIDE`. A signal can arrive after an operation has
partially happened, so `Sigkill` alone is not a prevention guarantee. Prefer
BPF LSM hooks for file enforcement and `Override` for explicitly supported
syscalls. Every hook must be validated against the production kernel; YAML
shape validation cannot establish hook availability.

## Inspektor Gadget evidence

[adapters.json](../config/nosh-guard/adapters.json) uses argument arrays, never
shell command strings. `requiredModes` is the activation set: an adapter must
not start in a mode absent from that array.

The two v0.54.1 collectors are:

```text
ig run ghcr.io/inspektor-gadget/gadget/trace_dns:v0.54.1
  --runtimes docker --containername <name> --output json

ig run ghcr.io/inspektor-gadget/gadget/advise_seccomp:v0.54.1
  --runtimes docker --containername <name>
```

These commands are compatibility-sensitive. Do not upgrade the CLI or gadgets
independently. `trace_dns` produces newline-delimited JSON. Its DNS-over-TCP
support cannot reconstruct a DNS message split across TCP packets.

`advise_seccomp` emits its aggregate when stopped. The adapter supervisor must
terminate it cleanly and wait for output to flush. A crash, forced kill, empty
output, or dropped-event signal makes the learn/audit run incomplete. Its
result is an `ig` recommendation with provenance; it is never merged directly
into observations and never installed as `seccomp.json`.

Both collectors may expose sensitive paths, arguments, endpoints, and domain
names. Evidence directories use mode `0700`, files use `0600`, and reports must
redact before presentation.

## Evidence and fixtures

[evidence-inputs.json](../config/nosh-guard/evidence-inputs.json) declares six
independent inputs:

- `tetragon-events`;
- `ig-dns`;
- `ig-syscalls`;
- `nosh-l4`;
- `managed_dns`; and
- `managed_gateway`.

The hyphenated identifiers name adapters and per-run files. After parsing,
events use the stable producer kinds in the event schema (`tetragon`, `ig`,
`nosh_l4`, `managed_dns`, and `managed_gateway`); do not infer policy authority
from a filename alone.

Every normalized event follows
[evidence-event.schema.json](../config/nosh-guard/schemas/evidence-event.schema.json):

```json
{
  "schemaVersion": 1,
  "source": {
    "kind": "tetragon",
    "name": "process_exec",
    "version": "v1.7.0"
  },
  "runId": "run-id",
  "observedAt": "2026-07-25T12:00:01.000Z",
  "container": {
    "id": "container-id",
    "name": "nosh-project",
    "image": "nosh:version",
    "imageDigest": "sha256:..."
  },
  "event": {
    "type": "process.exec",
    "executable": "/usr/bin/node"
  }
}
```

Raw Tetragon envelopes are also accepted as compiler inputs. Source fixtures
under `config/nosh-guard/fixtures/` contain a raw producer record and its
expected normalized event. They cover all six sources and an evidence
manifest. The fixtures use synthetic IDs, addresses, and timestamps; they are
schemas and regression inputs, not a learned profile.

The `nosh_l4` fixture's raw record conforms to
`bpf/nosh_l4/schema/nosh-l4-event.schema.json`. Its privileged host collector
must attach all six programs to the exact target cgroup, initialize the target
cgroup ID, keep every BPF link alive for the run, and enrich normalized output
with the manifest's run/container/image identity. On supervised shutdown, the
reference loader detaches its links, drains the ring buffer, and emits a final
aggregate loss-statistics record; the finalizer requires that record and zero
reported loss. A dropped ring-buffer event, full flow map, missing session
configuration, unknown schema version, container cgroup replacement, or
missing final stats makes the evidence incomplete.

Runtime event mode currently sums each per-CPU loss map and retains live packet
records rather than dumping `flow_totals`. Build profiling instead selects the
bounded `flow-summary` mode: after all links detach it emits one final map
summary per key and binds the emitted count into final statistics. Individual
per-CPU values are not retained in either mode. The sensor is observe-only:
every hook returns allow and neither connection attempts nor byte counters
prove a successful connection.

Promotion requires all sources required by the selected mode, exact run and
container identity, an immutable image digest, no event-loss indication, and
no unexplained collection gaps. DNS and connection evidence are joined by run,
container, destination address, and time window. A DNS answer alone never
authorizes a connection.

An audit manifest also carries `auditEvaluation`. It binds the run to the exact
SHA-256 of all five candidate artifacts and contains one result for each
Tetragon, seccomp, AppArmor, Docker, and network backend. “Complete evidence”
and “complete candidate evaluation” are different claims: a run can collect
all required telemetry while still lacking one or more shadow evaluators. The
compiler preserves that run for analysis but sets `promotionEligible: false`
and `cleanAudit: false`.

The current finalizer is intentionally explicit about those gaps. It records
the runtime snapshot hashes, the managed egress would-deny count, and
incomplete results for candidate Tetragon matching, attributed seccomp logs,
attributed AppArmor complain logs, final Docker conformance, and network
ingress. It never converts absence of an evaluator into a zero-deny result.

## Legacy/full-profile managed DNS and network contract

This section describes the historical full-profile gateway design. It does
not apply to the scoped `egress-learn`, `egress-audit`, or `egress-enforce`
workflow documented below.

[network-contract.example.json](../config/nosh-guard/network-contract.example.json)
and its JSON Schema define the boundary an external network manager must
provide:

- a distinct internal `/29` Docker network for every run;
- the runner's only resolver at the contract's managed DNS address;
- UDP and TCP DNS support;
- denial of direct external DNS, DNS-over-TLS, and unauthorized encrypted DNS
  bypasses;
- a bounded TTL cache tying allowed names to current addresses;
- invariant denial of loopback, link-local, multicast, carrier-grade NAT, and
  private host networks;
- default-deny egress in enforce mode; and
- allowed and denied decision logs tied to run and container identity.

Wildcard names use suffix semantics: `*.example.com` matches subdomains but not
the apex `example.com`. Add the apex separately when required. An address
learned for an allowed name expires with the bounded DNS TTL; it must not
become a permanent IP allow entry. Literal-IP egress needs an explicit reviewed
rule rather than a fabricated DNS association.

Each network is named `nosh-guard-<run-hash>` and allocated from
`10.240.0.0/16` as a `/29`. IPAM reserves `.1` as the Docker gateway, but the
manager requires `com.docker.network.bridge.inhibit_ipv4=true` so the host
bridge is not assigned that address. The trusted two-homed egress/DNS
container owns `.2`, the runner owns `.3`, and the runner's default route is
replaced with `.2`. The example uses `nosh-guard-a1b2c3d4e5f6` and
`10.240.8.0/29` only to make the schema concrete; the manager derives the real
values from the run ID.

The per-run subnet is itself covered by the invariant private-CIDR deny. The
gateway INPUT chain makes exactly one runner-facing exception before that
deny: TCP/UDP port 53 to the trusted `.2` address. That address is otherwise a
router, not a general service allow. Forwarded private CIDRs remain denied. No
other runner-to-runner, runner-to-host, or runner-to-private-subnet traffic is
permitted, and separate bridges prevent runner-to-runner L2 access.

The runner must not be able to route around the gateway through another Docker
bridge, host networking, IPv6, a published port, an attached VPN, or a host
proxy. The manager must apply firewall state before releasing the process gate.
On manager, resolver, or gateway failure it quarantines the runner before
stopping it.

Runner HTTP and WebSocket traffic returns through a separate Unix control
path. The egress container creates
`/var/lib/nosh-guard/egress/control/runner-proxy.sock` on the host bind mount,
with its parent directory at `0700` and the socket at `0600`. It accepts only a
run ID that matches an active gateway policy, then forwards to that runner's
fixed internal address and port. The root daemon's optional mTLS gateway
authenticates a principal, verifies its run binding, strips caller-supplied
forwarding and `x-nosh-guard-*` headers, injects the canonical public origin
and selected run ID, and talks to this Unix socket. The runner publishes no
Docker port.

The Unix proxy is an internal trust boundary, not a user-facing authentication
mechanism: possession of the socket is sufficient to submit its trusted run-ID
header. Keep its host directory root-only, never mount it into a runner, and
use the mTLS gateway or another credential-aware broker for non-root clients.

The gateway records nftables counters every ten seconds and implements a
synchronous final snapshot before evidence finalization and policy removal.
The manager writes a fresh request containing the run ID, policy hash, and a
random nonce, signals the gateway, and accepts only a complete response bound
to those exact values. Before publishing that response, the gateway stops and
drains managed DNS logging, records the per-run byte endpoint and any durable
overflow marker, and restarts DNS without replacing the nftables rules. The
gateway requires the mode's terminal nftables counter, appends the counter
record, and returns an attestation containing its content hash and the DNS
evidence boundary. The evidence finalizer reads only to that attested boundary
and requires the original policy
acknowledgement, the nonce-bound attestation, and the exact complete counter
record; a timeout, stale nonce, missing terminal counter, nftables error, or
hash mismatch makes the run incomplete. Managed DNS capture is capped at 8 MiB
per run; exceeding it persists an overflow marker, stops further writes for
that run, and records explicit loss/incomplete evidence. Collector write
failure, drain timeout, or forced resolver termination persists the same
run-scoped loss marker with a distinct reason and can never produce a complete
snapshot.

The shared `managed-gateway-counters.ndjson` diagnostic log has a 256 MiB hard
ceiling. The gateway never appends beyond it. Exhaustion creates
`managed-gateway-counters.overflow.json`, installs fail-closed rules, removes
gateway health, and exits with `GUARD_GATEWAY_EVIDENCE_EXHAUSTED`. Operational
recovery is to retain or archive the counter log, mark affected active runs
incomplete, clear the log, and only then remove the overflow marker before
restarting the managed gateway. Rotation is intentionally not automatic
because replacing or truncating the file would invalidate active run cursors.

This handshake covers supervised stop, removal, and in-process quarantine. A
hard daemon exit handled only by systemd's `ExecStopPost`, a host crash, or
`SIGKILL` can still prevent the request and final evidence assembly. Those runs
must remain incomplete even if an earlier periodic counter record exists.

The example domain list is intentionally incomplete. Coding agents invoke
package managers, source hosts, model APIs, artifact CDNs, certificate
services, and subprocesses. Learn each agent/toolchain/task class separately;
one universal coding-agent profile will either be fragile or overly broad.

Short dependency-fetch exceptions are separate from profile artifacts and
approvals. A grant is bound to one exact run ID, never to a profile revision or
all runners, and expires after at most 3,600 seconds. Active grants are folded
into that run's egress rules when the gateway reloads its inputs; invariant
private-network and DNS-bypass denies are evaluated first and remain in force.
Grants do not add ingress handling and cannot make standalone enforce mode
available.

Create grants only from the root administration boundary and include an actor
and review reason:

```bash
sudo nosh-guard grant create \
  --run '<active-run-id>' \
  --destination registry.npmjs.org \
  --protocol tcp \
  --ports 443 \
  --ttl-seconds 300 \
  --actor '<operator-id>' \
  --reason 'fetch reviewed dependency'

sudo nosh-guard grant list

sudo nosh-guard grant revoke \
  --id '<grant-id>' \
  --actor '<operator-id>' \
  --reason 'dependency fetch complete'
```

TCP and UDP grants require one or more ports. ICMP grants use
`--icmp-type` and optional `--icmp-code` instead. Destinations are an FQDN,
FQDN wildcard, or CIDR. `grant list` shows active entries; `grant list --all`
also shows expired and revoked entries. Creates and revocations are appended
to `/var/lib/nosh-guard/grant-audit.ndjson`, while the current state lives in
the root-controlled `grants/current.json`. The dedicated grants directory is
mounted read-only into the gateway so atomic updates remain visible. The store requires a run ID but does not
prove that the run is currently active when the record is created, so select
the ID from `nosh-guard runs` and revoke the grant as soon as the operation
finishes.

For Kubernetes, use Cilium NetworkPolicy instead of translating this contract
into Tetragon socket rules. Cilium supplies the workload identity and stateful,
DNS-aware network layer that standalone Tetragon does not.

## Per-workspace egress workflow

The `nosh net` command family is the short path for learning and applying one
outbound allowlist per canonical workspace:

```bash
./setup-nosh.sh \
  --policy-tooling-image sha256:<approved-64-hex-tooling-image-id> \
  --policy-review-ui-image sha256:<approved-64-hex-review-ui-image-id>
./profile-build-and-review.sh --cache-mode cold
```

The wrapper builds and learns, exports an immutable runtime candidate plus
exact `NoshGuardEbpfTargetContext`, starts the tokenized graph server and exact
reviewed Policy Review UI image on a dedicated internal Docker bridge,
discovers their current `172.*` addresses, applies exact-origin CORS,
health-checks the UI, and opens that UI with `xdg-open`. It never trusts the new candidate or an existing
web server as review tooling. Review every proposal and export one complete
`NoshPolicyDecisionSet`. It never approves, activates, or enforces
automatically.

Scoped egress uses the first-party `nosh-egress` CO-RE cgroup programs as its
sole allow/deny dataplane. Docker supplies an isolated dual-stack bridge and
ordinary routing/NAT only. dnsmasq, `nosh-dns`, the managed gateway, and
nftables are not policy authorities for `egress-learn`, `egress-audit`, or
`egress-enforce`. The backend observes IPv4/IPv6 connects and sends plus DNS
responses, and evaluates explicit CIDRs and DNS-derived TTL grants per packet.
The default resolver set is exactly `1.1.1.1` and `8.8.8.8`; alternate
Cloudflare/Google addresses are not implicit.
The resolved per-run resolver set is recorded and replayed with the learned
launch settings; an explicit resolver changes those settings and requires a
new learning lineage.

During `egress-learn`, RFC1918 and other private destinations, direct DNS, and
DNS-over-TLS are ordinary evidence. The eBPF backend records their destination,
protocol, port, and decision context and permits the attempt; it does not apply
candidate rules. Known parser, fragment, unsupported-protocol, and bounded DNS
correlation gaps are recorded as coverage gaps and prevent candidate
promotion, but are not silently converted into learn-time destination denies.
`egress-audit` applies the reviewed policy logically, emits would-deny for
unmatched or coverage-gap traffic, and permits it. `egress-enforce` denies
unmatched or ambiguous traffic by default. Exact per-run Docker bridge gateway
endpoints remain non-reviewable containment in all three modes. Map or
ring-buffer loss, configuration failure, adapter failure, and policy/backend
identity drift remain fail-closed evidence or containment failures.

A complete learn run produces write-once `NoshEgressProfile` and
`NoshEgressPolicy` artifacts, then mirrors an immutable user-owned review
candidate containing those files, the manifest, and the exact target context.
The run record is removed only after compilation, authoritative registration,
and review export succeed. Incomplete evidence leaves the stopped run in place
and cannot advance the candidate.

Provision two independent Ed25519 trust roles before the first activation.
Generate each pair in a separate network-none invocation of the exact reviewed
policy-tooling image. Mount only that role's private directory; never expose
both private roles to one container:

```bash
install -d -m 0700 "$HOME/.local/share/nosh/review-role" \
  "$HOME/.local/share/nosh/deployment-role"
docker run --rm --pull never --network none \
  --user "$(id -u):$(id -g)" --read-only --cap-drop ALL \
  --security-opt no-new-privileges:true --tmpfs /tmp:rw,nosuid,nodev,noexec \
  --mount "type=bind,src=$HOME/.local/share/nosh/review-role,dst=/role" \
  --entrypoint /usr/local/bin/node "$NOSH_POLICY_TOOLING_IMAGE" \
  /app/scripts/nosh-guard.mjs review keygen --output /role/key
docker run --rm --pull never --network none \
  --user "$(id -u):$(id -g)" --read-only --cap-drop ALL \
  --security-opt no-new-privileges:true --tmpfs /tmp:rw,nosuid,nodev,noexec \
  --mount "type=bind,src=$HOME/.local/share/nosh/deployment-role,dst=/role" \
  --entrypoint /usr/local/bin/node "$NOSH_POLICY_TOOLING_IMAGE" \
  /app/scripts/nosh-guard.mjs review keygen --output /role/key
```

Keep both `private.pem` files outside root Guard state. On the host, install
only the public halves and an explicit trust document (choose stable audiences
for this Guard deployment):

```bash
umask 077
REVIEW_AUDIENCE='notty-review-prod'
# Provision a stable value unique to this Guard instance; never clone it.
GUARD_AUDIENCE='notty-guard-ebpf-<unique-instance-id>'
sudo install -d -o root -g root -m 0700 /etc/nosh-guard/ebpf-trust
sudo install -o root -g root -m 0600 \
  "$HOME/.local/share/nosh/review-role/key/public.pem" \
  /etc/nosh-guard/ebpf-trust/review-public.pem
sudo install -o root -g root -m 0600 \
  "$HOME/.local/share/nosh/deployment-role/key/public.pem" \
  /etc/nosh-guard/ebpf-trust/deployment-public.pem

trust_tmp="$(mktemp)"
printf '%s\n' \
  '{' \
  '  "schemaVersion": 1,' \
  '  "kind": "NoshGuardEbpfDeploymentTrust",' \
  '  "backendAbi": "nosh-egress-v2",' \
  '  "reviewPublicKey": "/etc/nosh-guard/ebpf-trust/review-public.pem",' \
  '  "deploymentPublicKey": "/etc/nosh-guard/ebpf-trust/deployment-public.pem",' \
  "  \"reviewAudience\": \"$REVIEW_AUDIENCE\"," \
  "  \"deploymentAudience\": \"$GUARD_AUDIENCE\"" \
  '}' >"$trust_tmp"
sudo install -o root -g root -m 0600 "$trust_tmp" \
  /etc/nosh-guard/ebpf-deployment-trust.json
rm -f -- "$trust_tmp"
```

Review that JSON against
`config/nosh-guard/schemas/ebpf-deployment-trust.schema.json`. Guard never
generates either key, never copies a private key into root state, and has no
trust-on-first-use fallback. A missing, mutable, wrongly owned, or mismatched
trust file/key/audience makes activation fail closed.
`deploymentAudience` is part of the grant replay scope and must be unique per
Guard instance. A cloned pre-grant state with the same audience is not an
independent deployment authority; reprovision the clone before granting.

For unattended sampling, `net learn --duration SECONDS` (1 through 86400)
runs without executing an attached shell, observes the configured app for the
requested interval, and periodically calls the attach revalidation for the
exact run ID. Each check verifies the live container identity, namespaces,
cgroup, pinned eBPF policy identity, and required adapters; checks are
serialized so stop cannot race one in flight. A full window then uses the same
stop, evidence-flush, candidate-registration, and removal path. `--start-app` is
recommended for a representative application window. SIGINT and SIGTERM are
owned until stop/finalization completes. A shortened or unhealthy observation
creates no candidate and leaves the stopped run in place for diagnostics.
After a full window has stopped, the learner synchronously checks for a latched
signal and then arms an irreversible commit barrier before writing the
candidate. Signals received before that barrier cancel promotion with status
130/143; signals after it remain intercepted until the already-authorized
candidate registration and run removal finish. Guard management requests have
a bounded 120-second default timeout and destroy a wedged socket request. A
second SIGINT/SIGTERM is the explicit emergency escape from best-effort cleanup.

`net learn --duration SECONDS --json` emits one `NoshEgressLearnResult` only
after a full window and successful candidate/mirror finalization. It includes
the exact `runId`, `revision`, root-owned `profileDirectory`, explicit
`authoritativePolicy` and `mirrorPolicy` paths, `evidenceManifest`, requested
and observed durations, completion flag, exact image digest/reference, and
policy/profile/manifest hashes. It also includes `reviewCandidateDirectory`
and `reviewTargetContext`, which are the only runtime inputs the combined
build/review wrapper accepts.
The `candidatePolicy` compatibility field is an alias of `mirrorPolicy`.
`--json` requires `--duration`, preventing interactive terminal output from
being mixed with the JSON document.

`net audit` resolves the current workspace candidate and uses
`egress-audit`: reviewed matching rules are evaluated, unmatched traffic is
logged as would-deny and otherwise allowed, and only exact platform
containment endpoints remain denied. Audits are useful before signed review
but are not a promotion prerequisite. `net approve` is retained only as a
legacy local acknowledgement. It does not create a signed target leaf, does
not advance root activation state, and cannot authorize `egress-enforce`.

The actual activation sequence is:

1. `profile-build-and-review.sh` creates and opens the frozen graph;
2. the reviewer exports the complete DecisionSet;
3. `policy project --target guard-ebpf --context TARGET_CONTEXT` creates the
   canonical eBPF leaf;
4. `review approve` signs the exact target-review-set digest and configured
   review audience;
5. `deployment grant` signs a short-lived, single-use transition from the
   current root-owned active-grant-set digest;
6. `ebpf activate` verifies both signatures, subject/backend bindings, nonce,
   expiry, and exact workspace/image context, then atomically advances root
   state; and
7. `net enforce` replays only the verified learned image/settings while Guard
   supplies the active signed leaf.

Run steps 3 through 5 in separate network-none invocations of the reviewed
tooling image. Projection mounts no private key, approval mounts only the
review private key file, and the deployment grant mounts only the deployment
private key file. Follow the exact commands in
[Guard eBPF review and activation](nosh-policy-review.md#guard-ebpf-review-and-activation),
which also derives `GUARD_BIN` from the user/install layout instead of assuming
`/usr/local`.

The approval's signed review audience, deployment grant audience, and both
public keys must already match the root-owned
`/etc/nosh-guard/ebpf-deployment-trust.json`. Assemble the activation
directory exactly as follows:

```text
activation-001/
├── policy/                         # complete projected-ebpf directory
├── approval-envelope.dsse.json
└── deployment-grant.dsse.json
```

Then use the install-layout-derived `GUARD_BIN` for activation and enforcement,
as shown in the linked workflow.

The current backend advertises `tcpDns:false`. It handles UDP and bounded
single-segment, single-message TCP DNS, but not arbitrary segmented or
coalesced TCP DNS streams. The `guard-ebpf` compiler therefore marks accepted
FQDN rules unsupported, emits an activation-ineligible projection, and exits
status 2. Do not proceed to approval, grant, activation, or enforce for such a
projection. Literal IPv4/IPv6 CIDR rules do not depend on DNS and may project
exactly while `tcpDns:false`; their projection is still fail-closed on every
other backend capability and review condition.

The scoped policy is dual-stack. Reviewed IPv4/IPv6 CIDRs—including private
CIDRs—and exact or wildcard FQDN transport rules may project when the backend
can represent them exactly. Direct DNS and DNS-over-TLS can likewise become
authority only through an explicit reviewed endpoint rule. Exact per-run
platform containment endpoints cannot project, even if they overlap a broader
accepted CIDR. Unsupported or ambiguous observations stay review-visible and
block activation rather than becoming allow rules.

This scope is deliberately separate from `--security-mode enforce`:

- `egress-learn`, `egress-audit`, and `egress-enforce` do not load candidate
  Tetragon, seccomp, AppArmor, Docker, or ingress artifacts;
- the usual non-root user, dropped capabilities, read-only root filesystem,
  private namespaces, resource limits, one workspace mount, isolated network,
  and no published ports remain active;
- inbound traffic has baseline isolation only, not compiled ingress-policy
  enforcement; and
- full standalone `enforce` continues to reject admission with
  `GUARD_STANDALONE_INGRESS_UNAVAILABLE`.

Authoritative state is stored below
`/var/lib/nosh-guard/profiles/net/<workspace-hash>/`. Workspace identity is the
SHA-256 of the physical absolute workdir, so same-named projects do not share
profiles and moving a checkout requires relearning. Scoped runs also capture
the workspace directory device/inode before container creation, verify the
live bind mount against that identity before release, and record the identity
in finalized evidence. Each learning run creates
an immutable revision. The registry's legacy approved pointer is historical
and is never consulted as policy authority by `net enforce`. An optional
`--revision` selects only the exact current learned launch-settings revision;
it cannot select or activate a policy. Without a TTY, enforce leaves the
verified run active and prints its Guard run record instead of attaching a
shell; use the lower Guard lifecycle commands to stop and remove that
long-running run.

The invoking user's mirror is stored under:

```text
~/.nosh/net-profiles/<project>-<path-hash>/
  current.json
  candidate-egress-policy.json
  review-candidates/<workspace-key>/<revision>/
    egress-profile.json
    egress-policy.json
    manifest.json
    guard-ebpf-target-context.json
    review-export.json
```

The launcher resolves the invoking identity from numeric sudo UID/GID data and
writes this mirror after dropping privileges. It is for inspection only and is
never read as enforcement authority. Run `nosh net status [--json]` to inspect
it without root, or use `sudo -- "$GUARD_BIN" net status --workdir "$PWD"
--repair` after deriving `GUARD_BIN` from the setup/install layout to reconstruct it from the
root registry.

Learning records the resolved image, any explicit mounted configuration path
and content hash, launcher role metadata, effective Collab selection, and
app-start choice. These values are replay/detection metadata, not egress
authorization authority. Audit/enforce replay them. Explicit incompatible
overrides are listed and may be discarded in favor of the learned values; an
image digest or explicit configuration-content change requires a new learning
run. `--persist`, `--security-mode`,
`--security-profile-dir`, `--network`, and `--publish` are intentionally not
accepted by `nosh net`; use the lower-level lifecycle commands for diagnostics.

The readable policy and user mirror are review inputs only. The root activation
store verifies the signed canonical `guard-ebpf` leaf, and the pinned
`nosh-egress` cgroup programs are the sole scoped allow/deny backend.

## Learn, compile, and audit workflow

The local guard socket is an administrator boundary, so the secure launcher
and lifecycle CLI must be run explicitly as root. Do not make the socket
world-writable and do not put an automatic `sudo` inside the launcher.

The lifecycle examples intentionally omit `--name`. Nosh derives the runner
name from the sanitized basename of the resolved `--workdir`, matching the
ordinary `nosh-$(basename "$PWD")` project workflow when no workdir override is
used.

Start a representative learning run. For an interactive `start` or `recreate`,
`--persist` leaves the run in `running` state after the initial shell exits so
the operator can stop it deliberately. Without `--persist`, that initial shell
exit triggers `stop` followed by `rm`: stop flushes collectors and finalizes
evidence, then removal releases the run name. A non-interactive start prints
the run JSON and leaves it active regardless of `--persist`.

```bash
sudo ./nosh.sh start \
  --security-mode learn \
  --image nosh \
  --workdir /absolute/path/to/project \
  --persist

sudo ./nosh.sh stop \
  --security-mode learn \
  --image nosh \
  --workdir /absolute/path/to/project

sudo nosh-guard runs

# After recording the evidenceManifest path:
sudo ./nosh.sh rm \
  --security-mode learn \
  --image nosh \
  --workdir /absolute/path/to/project
```

`stop` leaves a stopped run record and its name reserved; a stopped run cannot
be attached or restarted. Read `evidenceManifest` from that record, then use
`rm` when the name may be released. The evidence directory remains in the
state tree after successful removal. The user-facing container name may then
be used for a new run, but its UUID run ID is permanently tombstoned by that
directory; an explicit attempt to reuse it fails with `GUARD_RUN_ID_REUSED`.

Compile an unapproved audit-input candidate into a unique directory in the
root-owned profile store. Compiler output is write-once by default:
`profile compile` has no overwrite flag and refuses to replace any existing
artifact. Use a new output directory for every compilation rather than
deleting or editing an earlier candidate. The example Tetragon fragments still
require a human/kernel review; the flag records that this review occurred, it
does not perform it:

```bash
sudo nosh-guard profile compile \
  --evidence /var/lib/nosh-guard/evidence/<learn-run-id>/evidence-manifest.json \
  --name node-agent-v1 \
  --tetragon-rules \
    config/nosh-guard/tetragon/candidate-enforcement-rules.example.json \
  --reviewed-tetragon-enforcement \
  --output /var/lib/nosh-guard/profiles/node-agent-v1-audit-input
```

Exercise that exact, unchanged candidate in audit mode. Audit admission
independently validates the candidate artifact set and snapshots it beneath
the run's evidence directory before releasing the gate:

```bash
sudo ./nosh.sh start \
  --security-mode audit \
  --security-profile-dir \
    /var/lib/nosh-guard/profiles/node-agent-v1-audit-input \
  --image nosh \
  --workdir /absolute/path/to/project \
  --persist

sudo ./nosh.sh stop \
  --security-mode audit \
  --image nosh \
  --workdir /absolute/path/to/project

sudo nosh-guard runs

# After recording the evidenceManifest path:
sudo ./nosh.sh rm \
  --security-mode audit \
  --image nosh \
  --workdir /absolute/path/to/project
```

With the collectors currently implemented, this audit is expected to be
non-promotable: its manifest preserves the candidate hashes and explicitly
lists the missing backend evaluators. Any candidate compiled with that audit
manifest must be rejected by `profile approve`, even with an override reason.
That is the safe stopping point for this prototype.

After the evaluator gate is implemented, repeat at least three independent
audit runs against the same audit-input candidate. Recompile from the learning
manifest and those audit manifests, with the same profile name and compiler
options, into another new directory. The five policy artifact hashes must equal
the hashes bound into every audit. The compiler checks that condition while
counting clean audits, and approval checks it again. Any newly observed
behavior that changes one of those artifacts starts another audit cycle.

```bash
sudo nosh-guard profile compile \
  --evidence /var/lib/nosh-guard/evidence/<learn-run-id>/evidence-manifest.json \
  --evidence /var/lib/nosh-guard/evidence/<audit-run-1>/evidence-manifest.json \
  --evidence /var/lib/nosh-guard/evidence/<audit-run-2>/evidence-manifest.json \
  --evidence /var/lib/nosh-guard/evidence/<audit-run-3>/evidence-manifest.json \
  --name node-agent-v1 \
  --tetragon-rules \
    config/nosh-guard/tetragon/candidate-enforcement-rules.example.json \
  --reviewed-tetragon-enforcement \
  --output /var/lib/nosh-guard/profiles/node-agent-v1-reviewed
```

Approve the new candidate and then verify the approved bundle. The
`profile verify` CLI expects `approval.json`; it is a post-approval integrity
check, not the candidate check used by audit admission:

```bash
sudo nosh-guard profile approve \
  --candidate /var/lib/nosh-guard/profiles/node-agent-v1-reviewed \
  --revision node-agent-v1 \
  --reviewer <reviewer-id>

sudo nosh-guard profile verify \
  --candidate /var/lib/nosh-guard/profiles/node-agent-v1-reviewed
```

The following standalone launch is intentionally unavailable today:

```bash
sudo ./nosh.sh start \
  --security-mode enforce \
  --security-profile-dir /var/lib/nosh-guard/profiles/node-agent-v1-reviewed \
  --image nosh \
  --workdir /absolute/path/to/project \
  --persist
```

It fails with `GUARD_STANDALONE_INGRESS_UNAVAILABLE`, before profile
application. An external manager/admission integration must consume and attest
the compiled ingress and egress policy independently before this final launch
step can be enabled.

## Artifacts, approval, and failure handling

A profile directory contains:

```text
tetragon.yaml
seccomp.json
apparmor.profile
docker.json
network-policy.yaml
profile.yaml
report.json
report.html
manifest.json
approval.json              # present only after explicit approval
```

`profile.yaml` uses `apiVersion: notty.dev/v1alpha1` and
`kind: NoshSecurityProfile`. Candidate output is never an approval. Approval
binds the exact image digest through `profile.yaml`, the requested revision,
the profile's normalized evidence hash and provenance, the bundle-manifest
hash, and the SHA-256 of every candidate file. `approval.json` does not record
or attest a compiler binary/version identity; reproducible output and the
checked-in implementation version must be tracked separately by packaging or
signed build provenance.

The promotion floor is three distinct clean `audit` runs. Each counted run
must have a distinct run ID and manifest hash, match the profile's immutable
image digest, be complete and promotion-eligible, report zero lost events and
zero would-deny decisions, have no collection gaps, bind all five exact
candidate artifact hashes, and contain complete evaluations from all five
backends. After compiling, the compiler compares every run's bound hashes with
the artifacts it just generated. Approval independently repeats that
comparison. An audit of candidate A can never promote candidate B. Compiler
inputs must normally be completed, integrity-verified manifests rather than
direct raw records. A candidate cannot lower the threshold below three.

Promotion is never automatic. A root operator may approve below the clean-run
or manifest-completeness gate only by supplying both an explicit reviewer and
a non-empty `--promotion-override-reason`. The approval records that exception
and the downstream enforce verification recomputes it once an external ingress
integration makes that path reachable. The shipped standalone daemon rejects
before this check. An override cannot repair hard provenance errors such as an
invalid image digest, duplicate run or manifest identity, image mismatch, a
threshold below three, a promotion summary inconsistent with its evidence, a
missing audit evaluator, an incomplete backend, or an artifact hash mismatch.
The current runtime produces incomplete backend evaluations, so including one
of its audit manifests makes approval fail even when an override reason is
supplied.

The distinction matters for break glass: a candidate compiled without those
audit manifests, including a learn-only candidate or a direct-fixture
candidate that otherwise passes all hard checks, can remain override-eligible
because the missing clean-run or manifested-input floor is a soft promotion
gate. Omitting a failed audit does not mean it passed. Any such approval is an
explicit risk acceptance, not evidence-backed promotion, and the approval
records the reviewer and reason.

```bash
sudo nosh-guard profile approve \
  --candidate /var/lib/nosh-guard/profiles/<revision> \
  --reviewer <reviewer-id>

# Exceptional, reviewed break-glass promotion:
sudo nosh-guard profile approve \
  --candidate /var/lib/nosh-guard/profiles/<revision> \
  --reviewer <reviewer-id> \
  --promotion-override-reason '<change record and risk acceptance>'
```

The bundle's `manifest.json` hashes compiler outputs; it is distinct from the
per-run evidence manifest that records source completeness and loss counters.
`approval.json` records the reviewer, revision, decision, profile/evidence
references, candidate-file hashes, and its own unkeyed content hash, but is not
itself a candidate artifact. Approval is also write-once by default: a second
approval refuses to replace the file unless the operator explicitly supplies
`--replace`. Prefer a fresh candidate directory and a new revision; use
`--replace` only for a deliberate re-review with an external audit trail.
Protect approvals with root-owned storage or add an external
signature/attestation service; an unkeyed content hash alone is not a trust
anchor against a writer who can replace the whole directory.

The same distinction applies to evidence manifests. Their hashes detect
changes after ingestion, but do not authenticate who created the original
manifest. Compile production candidates only from the guard's root-owned state
tree, preserve its ownership chain, and add signed provenance when evidence
must cross a host or administrative boundary.

The approval command itself must run as root. Before writing `approval.json`,
it requires the candidate directory and every candidate artifact to be
root-owned and not group- or other-writable, beneath
`NOSH_GUARD_TRUSTED_PROFILE_ROOT`. The downstream enforce path applies the same
check to `approval.json` and additionally requires the bundle beneath the
daemon state directory's `profiles/` tree. Compile directly into a unique
root-owned directory there, or install the reviewed output there without
changing its contents; use directory mode `0700` and file mode `0600`. Do not
point enforcement at a user-writable workspace or a root-owned directory
inside a user-renamable parent.

After an external ingress integration permits the downstream enforce path, the
daemon re-hashes all artifacts, re-inspects the image digest, validates the
host feature set, takes a fresh `0600` hash-checked runtime snapshot beneath
the run's `0700` evidence directory, attaches the network identity, applies
controls, and only then releases the process gate. The shipped daemon rejects
earlier with `GUARD_STANDALONE_INGRESS_UNAVAILABLE`.

Failure behavior is intentionally conservative:

The enforce column after its admission row describes the implemented
downstream cleanup and failure policy that becomes reachable only after the
missing external ingress integration is added.

| Failure | Learn | Audit | Enforce |
| --- | --- | --- | --- |
| Compiled ingress evaluator unavailable in standalone manager | Not applicable | Recorded as missing audit coverage | Reject admission with `GUARD_STANDALONE_INGRESS_UNAVAILABLE` |
| Required adapter unavailable before start | Reject start | Reject start | Reject start |
| Evidence loss or collector exit | Stop; mark incomplete | Quarantine and stop; mark incomplete | Quarantine and stop |
| DNS/gateway/firewall unavailable | Reject or quarantine and stop | Quarantine and stop | Quarantine and stop |
| Artifact/hash/image mismatch | Not promotable | Reject audit | Reject start |
| Tetragon policy reports `monitor_only` after enforce load | Not applicable | Not applicable | Remove policy and reject start |
| Cleanup cannot remove controls or identity | Block run-ID reuse | Block run-ID reuse | Keep quarantined; require operator recovery |
| Required adapter or gateway fails while daemon is responsive | In-process poller quarantines and removes | In-process poller quarantines and removes | In-process poller quarantines and removes |
| Guard daemon exits or is OOM-stopped by systemd | `ExecStopPost` pauses, then stops on pause failure | `ExecStopPost` pauses, then stops on pause failure | `ExecStopPost` pauses, then stops on pause failure |
| Guard daemon hangs | No independent detector yet | No independent detector yet | No independent detector yet |

Native seccomp and AppArmor controls can remain active if Tetragon exits, but
that does not satisfy the whole profile. Do not silently continue because one
layer happened to persist.

The daemon's five-second poller re-inspects the container, image, network,
namespace, cgroup, and gateway identities and checks the managed gateway and
required adapter processes. On a detected failure it first tries to pause the
runner, marks the run quarantined and evidence incomplete, detaches collectors,
requests the final gateway counter snapshot, finalizes incomplete evidence,
and force-removes the container. Failed critical cleanup remains in run state
and blocks reuse. Graceful daemon shutdown takes the same path for every
running container.

This poller shares the daemon's event loop and cannot detect or recover from a
stuck process. The systemd `ExecStopPost` helper is a separate process and
catches service exit, startup failure, OOM stop, and systemd-initiated stop,
but it only pauses or stops labeled runner containers; it does not finalize
evidence or prove adapter, AppArmor, Tetragon, and network cleanup. Production
enforcement therefore still needs an external liveness monitor or systemd
watchdog integration with real `sd_notify` heartbeats and complete recovery
tests.

## Current standalone limitations

- The shipped standalone daemon cannot admit `enforce` runs. Its managed
  gateway consumes egress rules but no backend consumes the compiled ingress
  policy, so admission fails with
  `GUARD_STANDALONE_INGRESS_UNAVAILABLE`. An external manager and corresponding
  admission integration must apply and attest both directions.
- Current audit runs are not promotable. They bind the candidate but lack
  complete Tetragon, seccomp, AppArmor, Docker, and ingress evaluators. This is
  a deliberate fail-closed state, not a temporary zero-deny shortcut.
- The root daemon has Docker control and the privileges needed for AppArmor,
  eBPF loading, cgroup inspection, and network namespace entry. The unit
  narrows filesystems and several kernel interfaces, but it intentionally does
  not yet use a tight capability or syscall allowlist because supported kernel
  and Inspektor Gadget combinations have not been characterized.
- The guard API relies on a root-only `0600` Unix socket instead of Unix peer
  credentials. Remote or non-root clients require the separate authenticated
  gateway.
- The startup gate is a process inside an already-created Docker container,
  not an OCI pre-start hook. A runtime hook or Kubernetes is required for zero
  workload execution before sensor attachment.
- Secure Nosh role names are admission metadata only. The guarded runner mounts
  exactly one writable workspace and does not project the legacy
  `codex`/`claude`/`gemini` credential directories or launcher OTP/basic-auth
  secrets. Hosted coding agents need a separately designed, operator-reviewed
  credential broker or capability grant; that broker is not implemented.
- The in-process poller is not an independent watchdog, and the exit helper is
  cleanup fallback rather than complete recovery orchestration.
- Runtime `nosh_l4` event mode lacks a shutdown dump of `flow_totals`, and no
  mode retains individual per-CPU counter values. Build `flow-summary` mode
  does dump the bounded aggregate map. The gateway has a nonce-bound
  synchronous final nftables snapshot, but daemon or host failure can prevent
  that handshake and final manifest assembly.
- Tetragon's standalone Docker scoping uses ephemeral namespace identity, and
  Inspektor Gadget/Tetragon behavior remains kernel- and version-sensitive.
  Revalidate the unit's securityfs/bpffs exceptions, BPF coexistence, and
  shutdown timing on every supported host family.
- Shared DNS and gateway evidence logs are append-only and do not yet have
  coordinated rotation. Put `/var/lib/nosh-guard` on a quota-limited
  filesystem, monitor capacity, and treat truncation or inode replacement
  during a run as incomplete evidence.
- Docker user-namespace remapping is not configured by the standalone manager.
  The runner is non-root with all capabilities dropped and private cgroup,
  PID, network, mount, IPC, and UTS namespaces, but host UID/GID mapping still
  follows the Docker daemon configuration.

## Launcher contract

For `learn`, `audit`, and `enforce`, `nosh.sh` delegates each lifecycle action:

```text
nosh-guard run
  --mode <learn|audit|enforce>
  --image <image>
  --name <container-name>
  --workdir <absolute-path>
  --action <start|attach|stop|rm|recreate>
  [Nosh-compatible options]
```

Resolution order is `NOSH_GUARD_BIN`, repository `bin/nosh-guard`, then
`PATH`. Host variables used to configure the trusted guard process remain in
its process environment rather than argv; launcher OTP and Basic-auth values
are explicitly unset before delegation, and the runner receives only the
constructed environment described above. `--dry-run` prints the command
without resolving or requiring the guard executable.

Lifecycle behavior is intentionally different from legacy container reuse:

- An interactive `start` or `recreate` first creates a new run, revalidates it,
  and opens `/bin/bash` with `docker exec`. Without `--persist`, shell exit
  invokes `stop` and then `rm`. With `--persist`, shell exit leaves the run
  active.
- A non-interactive `start` or `recreate` prints JSON and leaves the run active;
  `--persist` does not change that behavior.
- `attach` succeeds only for a run whose stored status is `running`. Before an
  interactive shell is opened it revalidates the exact container/image,
  namespaces, cgroup, network/gateway identity, and required adapter health.
  A failed check quarantines the run. Exiting an attached shell never stops or
  removes the run.
- `stop` stops the container, detaches collectors, takes the final gateway
  snapshot, and finalizes evidence. It retains the stopped run record and
  reserves the run ID and container name; stopped runs are not attachable.
- `rm` contains a running runner if necessary, finalizes its evidence, removes
  critical controls and network identity, and deletes the run record only
  after critical cleanup succeeds. It refuses removal when cleanup remains
  unsafe. Successful removal releases the name but retains the evidence
  directory and permanently tombstones the immutable run ID.
- `recreate` performs `rm` by name before starting a fresh run. A failed or
  quarantined cleanup prevents the replacement from starting; there is no
  fallback to an unguarded container.

`NOSH_GUARD_PROFILE_DIR` supplies only the default `--profile-dir` selection
for new audit/enforce requests. Approval trust uses
`NOSH_GUARD_TRUSTED_PROFILE_ROOT`, and the daemon's enforce path uses its own
state `profiles/` directory as the trusted ancestor.

## Validation and rollout

The checked-in artifact validators prove deterministic shape, internal hashes,
and conservative policy properties. `profile verify` rechecks an approved
bundle and its promotion decision, but it does not contact Docker, Tetragon,
AppArmor, nftables, or the kernel and cannot prove that a hook or policy is
installed. The doctor checks host prerequisites and versions; it is not an
end-to-end enforcement test.

Repository tests use fake Docker/runtime clients, fixture records, and static
command or policy assertions. They do not run a real Tetragon/Inspektor Gadget
sensor, load AppArmor/seccomp on a live runner, attach the CO-RE programs, or
exercise real nftables and network namespaces. Until a privileged,
host-versioned integration suite closes that gap, passing tests and the doctor
must not be reported as production enforcement validation.

After an external manager integration updates admission and the doctor to
attest the missing ingress backend, and before any future production
promotion:

1. run the doctor in the target mode;
2. validate every JSON document against its checked-in schema;
3. render Tetragon placeholders and reject leftovers;
4. load Tetragon policies in monitor mode on a disposable target;
5. confirm events belong only to that container;
6. exercise startup, idle, shell, Git, builds, tests, package installs,
   cancellation, failure, restart, DNS TCP fallback, and agent subprocesses;
7. test event loss and collector termination;
8. inject forbidden namespace, mount, ptrace, BPF, and host-network attempts;
9. exercise RFC1918, direct-DNS, DoT, exact platform-containment, parser-gap,
   and unapproved-domain traffic, proving learn evidence, audit would-deny,
   and enforce/default-deny behavior separately; and
10. enforce on a canary with automatic health rollback and a documented
    break-glass procedure.

An image, base image, architecture, kernel/runtime family, agent, or toolchain
change starts a new learning cycle. Never let an enforced workload train and
approve its own replacement profile.

## Primary references

- [Tetragon container installation](https://tetragon.io/docs/installation/container/)
- [Tetragon kernel and BTF requirements](https://tetragon.io/docs/installation/faq/)
- [Tetragon tracing policies](https://tetragon.io/docs/concepts/tracing-policy/)
- [Tetragon selectors](https://tetragon.io/docs/concepts/tracing-policy/selectors/)
- [Tetragon enforcement modes](https://tetragon.io/docs/concepts/tracing-policy/mode/)
- [Tetragon enforcement](https://tetragon.io/docs/concepts/enforcement/)
- [Tetragon events and export filters](https://tetragon.io/docs/concepts/events/)
- [Tetragon runtime hooks](https://tetragon.io/docs/concepts/runtime-hooks/)
- [Tetragon threat model](https://tetragon.io/docs/threat-model/)
- [Inspektor Gadget v0.54.1 `ig` reference](https://inspektor-gadget.io/docs/v0.54.1/reference/ig/)
- [Inspektor Gadget image verification](https://inspektor-gadget.io/docs/v0.54.1/reference/verify-gadgets/)
- [Docker seccomp](https://docs.docker.com/engine/security/seccomp/)
- [Security Profiles Operator](https://github.com/kubernetes-sigs/security-profiles-operator)
- [systemd execution sandboxing](https://www.freedesktop.org/software/systemd/man/latest/systemd.exec.html)
- [Linux kernel AppArmor documentation](https://docs.kernel.org/admin-guide/LSM/apparmor.html)
- [AppArmor parser](https://gitlab.com/apparmor/apparmor/-/tree/master/parser)
