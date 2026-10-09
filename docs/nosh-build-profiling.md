# Nosh Docker build profiling

`nosh build` records build-time performance, process, syscall, network, DNS,
and cgroup evidence around a dedicated BuildKit container. It is intended for
repeatable local or CI builds of any project with a Dockerfile. It does not
replace the runtime `nosh net` or Nosh Guard profile lifecycle.

Verified build evidence can be projected into the strict visual model in
[Nosh semantic policy review](nosh-policy-review.md). That graph is a
non-executable review layer; activation still requires a complete DecisionSet,
target projection, review signature, and a short-lived deployment grant for
either the scoped `guard-ebpf` backend or an external gateway.

Build profiles and runtime profiles are deliberately independent:

- build evidence is stored below the invoking user's home, while guarded
  runtime evidence and policy state remain below `/var/lib/nosh-guard`;
- a build output digest is informational and is never treated as a runtime
  profile binding or approval;
- build candidates have no direct audit, approve, or enforce command; the
  separate semantic-review pipeline requires new digest-bound artifacts;
  and
- changing either profile family never advances or invalidates the other.

## Commands

Profile the Dockerfile in the current directory:

```bash
nosh build profile .
nosh build status .
```

The default `compare` cache mode runs a cold pass followed by a warm pass in
one dedicated builder, retaining evidence for both. The cold pass uses a
cache-only output; the warm pass produces the requested output. Select a
single cache condition when a comparison is not useful:

```bash
nosh build profile --cache-mode cold .
nosh build profile --cache-mode warm .
```

Learn the external services needed by a build with a forced clean pass:

```bash
nosh build net learn .
nosh build net status .
```

There are two explicit collection levels:

```bash
# Kernel-scoped IP, protocol, port, process/socket, and userspace-decoded DNS.
./scripts/build-nosh.sh net learn --http-capture none

# The same eBPF evidence plus managed HTTP(S) request/response capture and CAS.
./scripts/build-nosh.sh net learn --http-capture mitmproxy
```

`none` is the default and is the shortest verifier/load smoke. `mitmproxy`
starts the digest-pinned managed proxy, attaches the dedicated BuildKit builder
to its bridge, injects the proxy variables and public per-run CA into opted-in
Dockerfile stages, and records private exact-request digests, redirects,
response identities, and content-addressed response objects. The CA private key
never enters the build, and `Dockerfile.nosh` removes the public CA before the
final image is emitted. A Dockerfile must contain the exact
`# nosh-http-capture-ca-secret=v1` marker before managed capture is allowed.

Managed capture does not replace eBPF. The current build sensor independently
proves the workload-to-proxy socket flow. The proxy-to-origin leg is a separate
cgroup and is retained as provider evidence with a blocking provenance gap
until a separately scoped proxy-leg L4 collector is available; the review
adapter must not turn that gap into origin network authority. Direct web/QUIC
bypass, opaque CONNECT, certificate pinning, incomplete/oversize bodies, and
unmatched evidence also remain explicit gaps. Burp HAR import is review context
only and cannot attest capture completeness.

Consequently, the current `mitmproxy` mode intentionally finishes as
diagnostic-only (status 1) after preserving its private evidence; it does not
advance a candidate. Use `--http-capture none` for the present successful basic
eBPF/DNS learner acceptance test. Managed capture becomes candidate-eligible
only after the independent proxy-origin provenance gap is closed.

Network learning always uses `--pull --no-cache`, rejects cache imports, and
produces immutable observational evidence, an unapproved network candidate,
and a separate editable policy draft. It does not apply that draft or deny an
ordinary destination merely because it is private, local, direct DNS, or DoT.
Selection of build authority happens later in Policy Review; reviewed audit
allows traffic while recording would-deny decisions, and enforcement is the
default-deny stage. Re-run learning for each CI environment,
platform, Dockerfile, target, dependency-lock change, registry/proxy setup,
and credential-delivery mechanism that materially changes build behavior.

Common structured options are:

```text
--file PATH                 select a Dockerfile
--variant NAME              select <context>/Dockerfile.NAME
--tag IMAGE                 tag the result
--target STAGE              select one Dockerfile target
--platform linux/ARCH       profile exactly one platform
--build-arg KEY=VALUE       pass a build argument
--push                      push instead of loading locally
--output DESTINATION        select an explicit Buildx output
--no-load                   retain only cache/explicit outputs
--http-capture MODE         with net learn: none (default) or mitmproxy
--json                      with net learn: print the redacted portable result
--private-json              print the sensitive full result instead of summary
```

`--file` and `--variant`, and `--push` and `--output`, are mutually exclusive.
The context defaults to the
current directory and must be a local directory. Options owned by the
profiler, insecure BuildKit entitlements, and host networking are rejected
when repeated as advanced Buildx arguments after `--`.

The project convenience wrapper preserves its ordinary build behavior and
adds equivalent profiled forms. `net learn` also launches the managed Policy
Review handoff automatically; use `--no-review` to suppress it:


```bash
./scripts/build-nosh.sh
./scripts/build-nosh.sh profile
./scripts/build-nosh.sh net learn
```

`IMAGE_NAME`, `TARGET`, `USERNAME`, `USER_UID`, and `USER_GID` are passed to
the profiled wrapper in the same way as an ordinary `build-nosh.sh` build.
For `./scripts/build-nosh.sh net learn`, Nosh automatically opens the persisted build
profile in the managed Policy Review UI after learning. The terminal prints a
clickable `http://172.*:3000/policy-review?graph=...` link; use
`--no-review` for machine-only or CI runs. Public JSON, private JSON, dry-run,
and help output suppress the handoff automatically. The wrapper prints both an
OSC-8 hyperlink and a plain `Policy Review: http://172...` fallback and tries
`xdg-open`; a missing or failing browser opener does not change the learn
status. Incomplete evidence still opens for diagnosis but remains
activation-ineligible.

The default `local` target and the existing `base`, `agent`, `hardware`,
`cdev`, and `full` targets omit Ollama. Select the explicit target and a
distinct image tag when profiling its pinned CLI and runtime libraries:

```bash
IMAGE_NAME=nosh:ollama TARGET=ollama ./scripts/build-nosh.sh profile
```

This opt-in cold profile includes the large Ollama distribution download and
the correspondingly larger image export. The target does not embed models or
Ollama daemon state.

## Combined build and three-minute runtime profile

The repository includes a non-destructive demonstration workflow:

```bash
./scripts/profile-build-and-run.sh
```

Run it as the Docker-authorized user, not through `sudo`. It performs these
steps in order:

Live mode uses the installed `nosh-egress` eBPF backend for runtime network
observation. It has no separate dnsmasq/nftables gateway-image prerequisite;
the Guard host-bundle verification checks the packaged loader and its kernel
requirements before a run is released.

1. captures the canonical `Dockerfile.nosh` build profile and displays its
   verified report;
2. runs the locally loaded image with
   `nosh net learn --duration 180 --start-app`, elevating only that
   Guard-managed runtime session;
3. verifies and displays the runtime egress result;
4. prints the redacted build candidate from the complete portable bundle and
   the non-authoritative readable mirror of the runtime egress policy; and
5. prints the immutable runtime review-candidate directory and exact
   `guard-ebpf-target-context.json` needed for signed review and activation.

Select a different window, image, target, cache condition, or mounted runtime
workspace with:

```bash
./scripts/profile-build-and-run.sh \
  --duration 180 \
  --image nosh \
  --target local \
  --cache-mode compare \
  --workdir "$PWD"
```

Use `--image nosh:ollama --target ollama` together only when the timed runtime
profile exercises the `ollama` command itself. Managed Copilot and Collab
backends connect from Codex to an external daemon and work with the lean
targets.

For the shortest build-to-review handoff, use `./scripts/build-nosh.sh net learn`.
It derives the just-built image digest, builds or reuses the managed Policy
Review UI image, and opens the review automatically. For separately pinned
review images, configure them once:

```bash
./scripts/setup-nosh.sh \
  --policy-tooling-image sha256:<approved-64-hex-tooling-image-id> \
  --policy-review-ui-image sha256:<approved-64-hex-review-ui-image-id>
./scripts/profile-build-and-review.sh --cache-mode cold
```

Warm-only evidence cannot advance a behavioral candidate, so use `cold` or the
default `compare`. The wrapper validates that exact independently reviewed
tooling image, uses it for network-none bundle generation, starts the frozen
graph and exact reviewed UI image on a dedicated internal Docker bridge,
inspects each current `172.*` address, configures exact-origin CORS,
health-checks the UI, and opens that instance with `xdg-open`; the host does not
execute Node or a package manager. It leaves decisions, approval, and
enforcement to the operator. The UI selection is the policy decision; signed
approval and activation remain explicit. The new build candidate is never trusted as
validation, projection, review, or signing tooling.
Both wrapper shells re-exec an unlinked, read-only control snapshot before the
candidate is launched; post-runtime validation and review startup therefore do
not execute checkout text that the candidate could have rewritten.

Use `--sbom-source /absolute/source.spdx.json --sbom-image
/absolute/image.spdx.json` to provide reviewed SBOMs bound to the exact build;
the wrapper snapshots them before candidate execution. Without them, missing
coverage blocks. `--allow-missing-sbom` is an explicit review-only downgrade,
not an activation override.

Provision the review and deployment roles in separate network-none tooling
containers and never mount both private keys together. Projection mounts
neither key, approval mounts only the review private key file, and the grant
container mounts only the deployment private key file. Install only the public
halves in root trust. Use distinct audiences, with `deploymentAudience` unique
to each Guard instance. The complete commands (including install-layout-derived
`GUARD_BIN` resolution instead of a `/usr/local` assumption) are in
[Guard eBPF review and activation](nosh-policy-review.md#guard-ebpf-review-and-activation).

The current target context reports `tcpDns:false`: UDP and bounded
single-segment TCP DNS are parsed, but arbitrary segmented/coalesced TCP DNS
is not yet supported. Consequently any projection containing accepted FQDN
authority is activation-ineligible and returns status 2; stop there. Literal
IPv4/IPv6 CIDR-only authority does not depend on DNS and may project exactly
when all other target and review preconditions pass.

The backend resolver default is exactly `1.1.1.1` and `8.8.8.8`; the target
context must bind that reviewed set explicitly.

The build phase must leave the image in local Docker, so this combined script
rejects `--push`, `--output`, `--no-load`, and `--load`. A failed or incomplete
build never starts runtime learning. Before launch, the script reads the exact
selected build manifest and uses its `configDigest` as the Docker image ID;
the requested tag is not trusted across the build/run boundary. It then checks
that same digest in the exact learn result and authoritative runtime receipt.
This is a local correlation check, not an approval or a merger of the otherwise
independent build and runtime evidence lifecycles. An interrupted timed window
is stopped and retained for diagnostics but never advances the runtime
candidate.

The two outputs deliberately have different application semantics:

- the build candidate is observational only. Preserve the entire `portable/`
  directory as CI evidence; the current build workflow has no direct approve
  or enforce command;
- the runtime output is an egress-only candidate. Review its exported graph,
  project `guard-ebpf`, sign the complete DecisionSet review, issue a
  short-lived deployment grant, and import it with `ebpf activate` before
  `net enforce`. The readable policy is a mirror and the learned candidate is
  launch metadata, not policy authority. These runtime operations need normal
  root authorization; the optional narrow build-session sudoers rule does not
  grant any `net` or `ebpf` command.

The timed mode starts its clock only after admission and an initial attach
action has revalidated the exact live runner and required adapters. Further
serialized attach revalidations run throughout the window. It does not wrap
the interactive learner in `timeout`, so normal collector flushing, diagnostic
retention, and cleanup are preserved. The workflow consumes the hash-bound
`net learn --duration ... --json` result rather than guessing mirror paths.

## Reviewed-policy enforcement smoke

The supported one-click entrypoint is `./scripts/build-nosh.sh net learn`: it profiles
the build, opens Policy Review, and persists the DecisionSet selected in the
UI. Use the signed projection/activation workflow above to enforce that exact
JSON. The deterministic enforcement regression is
`tests/reviewed-policy-enforcement.test.cjs`; the Docker isolation regression
is `tests/build-network-deny.test.cjs` and is not a substitute for signed
policy enforcement.

For a small Docker-backed network-deny regression, run:

```console
node --test tests/build-network-deny.test.cjs
node --test tests/reviewed-policy-enforcement.test.cjs
```

The fixture performs build-time requests to `example.org` and `1.1.1.1` with
`docker build --network=none`; it passes only when both attempts are blocked.
It skips when Docker or the local `busybox:1.36` fixture image is unavailable and never pulls
an image. The reviewed-policy test separately verifies the generated
`egress-enforce` rules and that editing the same JSON contract used by the UI
changes the selected allowlist without changing the source binding.

## Collection boundary

Buildx and the Docker CLI run as the invoking Docker-authorized user. For each
measured pass, the CLI asks for narrowly scoped root authority to create one
sensor session. The root daemon then:

1. validates the exact 64-character BuildKit container ID, expected
   `docker-container` builder name, image, PID, private cgroup namespace, and
   cgroup-v2 identity;
2. binds the session to the canonical context device and inode;
3. runs both collector health checks against that exact cgroup path and ID;
4. attaches the required `nosh-build` and `nosh-l4` loaders to that builder
   cgroup; managed HTTP capture, when selected, is a distinct userspace source;
5. waits for both required collectors to report ready before the build starts;
6. supervises final collector statistics and cgroup snapshots; and
7. treats missing final records, loss counters, identity drift, or incomplete
   cleanup as incomplete evidence.

If a required collector exits during startup, the daemon drains its bounded
structured diagnostics and returns the final status error before discarding a
cleanly contained admission failure. The caller therefore receives the loader's
cgroup, verifier, map, or attachment reason instead of only its exit status.

Do not prefix the overall build command with `sudo`; live profiling refuses
that form when it detects a sudo invocation. Run Buildx as the
Docker-authorized user so credential helpers, SSH/secret sessions, local
outputs, and generated files keep the caller's identity. Only the fixed
`build-session` helper calls elevate.

The profiled build never receives the guard socket, Docker socket from another
context, bpffs, host `/proc`, BPF capabilities, or collector binaries. A user
with Docker authority can still influence the builder and its observations;
the resulting hashes provide integrity checks, not trusted attestation.
The cooperative Nosh lease excludes other Nosh profiling sessions, but a
Docker-authorized user can still run Buildx against the builder out of band and
contaminate the observation window. The balanced kernel evidence targets the
exact Docker container cgroup root, not only the internal `init` leaf occupied
by the BuildKit daemon, so it covers both that leaf and sibling executor
cgroups. Docker CLI context preparation and Docker-daemon work outside that
subtree are represented only by BuildKit's native progress/history where
available.
Run the command on the Docker host. Do not make it work from a Nosh runner by
mounting the Docker/guard sockets or host kernel files into that container.

Each invocation uses a dedicated Buildx `docker-container` builder. Compare
and cold builders are removed when the invocation finishes. Warm-only mode
uses a stable builder identity and asks Buildx to preserve its state so a
later warm measurement can reuse cache. Interruptions still run collector and
builder cleanup; an unsafe cleanup failure leaves the evidence ineligible.

The current build-session envelope supports Linux, cgroup v2, a local
Unix-socket Docker context, and a non-rootless Docker daemon. It profiles
exactly one platform per invocation. Build network evidence contract v2
observes exec/exit, syscall latency summaries, bounded UDP DNS queries and
responses on port 53, A/AAAA/CNAME answers with TTLs, L3/L4 flows, BuildKit
progress/history, and cgroup CPU/memory/I/O/pressure state. The kernel DNS
hooks only scope and copy a bounded 1232-byte private wire record; the trusted
loader performs DNS decoding and immediately discards those bytes. DNS over
TCP, encrypted DNS names, and messages beyond the handoff budget remain
explicit coverage gaps. DNS-to-destination edges require a complete,
untruncated response that precedes the destination attempt, and expire after
the lesser of the observed TTL or five minutes. `--depth policy` adds
metadata-only file-open summaries on hosts
with Linux 5.10+ and BPF LSM enabled. The current path key is limited to 255
bytes and fails completion on truncation rather than authorizing a shortened
path. `--depth deep` is reserved for off-CPU and block-latency sources and
currently fails preflight because those collectors are not installed.

The former `nosh-url` libcurl uprobe remains packaged only as a disabled legacy
observer. It is not activated by any default build mode: apt, npm, Node TLS,
static libcurl, and other clients could bypass it, so it cannot provide the
complete URL boundary required for review. Use `--http-capture mitmproxy` for
managed HTTP evidence. Existing legacy records remain parseable and
non-authoritative for compatibility.

## BuildKit and host prerequisites

The reference BuildKit release is `v0.30.0`; see
[`config/nosh-build/versions.json`](../config/nosh-build/versions.json).
The shipped default is the reviewed multi-platform index reference pinned with
an exact `@sha256` digest. `NOSH_BUILDKIT_IMAGE` may override it only with
another immutable `@sha256` reference; mutable tags and `latest` are refused
for live profiles.

The host requires:

- Docker Engine on Linux, a local Unix Docker endpoint, cgroup v2, the default
  private container cgroup namespace mode, and the Buildx plugin with the
  `docker-container` driver;
- kernel BTF, cgroup BPF, bpffs, and BPF ring-buffer support;
- the running root `nosh-guardd` manager and its mode-`0600` Unix socket;
- a root-owned, non-group/world-writable `nosh-guard` helper at
  `$NOSH_GUARD_PREFIX/bin/nosh-guard` (default
  `/usr/local/bin/nosh-guard`, with `NOSH_GUARD_PRIVILEGED_BIN` as an exact
  helper override) for the narrow `build-session
  begin|finish|abort|exported` elevation calls;
- `$NOSH_GUARD_PREFIX/libexec/nosh-build/nosh-build-loader` version 4;
- `$NOSH_GUARD_PREFIX/libexec/nosh-guard/nosh-l4-loader` version 1;
- the digest-pinned managed mitmproxy image when `--http-capture mitmproxy` is
  selected; and
- the root-owned build adapter configuration at
  `/etc/nosh-guard/build-adapters.json`.

`./scripts/reset-nosh-guard.sh --replace-config` rebuilds the four collector binaries,
installs the current adapter/version contract, and now performs a real
non-attaching kernel verifier load of `nosh-build` in balanced mode. A reset
that succeeds has therefore already passed compilation and verifier admission;
the subsequent basic learn proves real cgroup attachment and inspectable
evidence:

```bash
./scripts/reset-nosh-guard.sh --replace-config
./scripts/build-nosh.sh net learn --http-capture none
./scripts/build-nosh.sh net status
```

Version 1 deliberately fixes the privileged build-session boundary to
`/run/nosh-guardd.sock` and `/var/lib/nosh-guard/build-evidence`; it does not
honor a user-selected management socket or state root. The software prefix is
relocatable, but `/etc/nosh-guard`, `/var/lib/nosh-guard`, the runtime socket,
systemd unit destination, and sudoers destination remain fixed host-integration
paths.

Run `./scripts/setup-nosh.sh` to create the user launchers and path record. This
unprivileged command never invokes sudo. If the root Guard is absent, it prints
the checksum verification, private extraction, and host-bundle installer
commands to review and run. `./scripts/setup-nosh.sh --check` verifies both launcher
and host readiness; `--guard-prefix /opt/notty` selects a custom root-owned
software prefix.

The ordinary launcher resolves Guard as `NOSH_GUARD_BIN`, the strict user path
record, the checkout's `bin/nosh-guard`, then `PATH`. Privileged build-session
resolution is separate: an explicit caller path, then
`NOSH_GUARD_PRIVILEGED_BIN`, `NOSH_GUARD_PREFIX`, the user path record, the
root install receipt, and finally `/usr/local/bin/nosh-guard`. Every selected
privileged helper is canonicalized and revalidated inside a root-owned,
non-writable path before each elevation call.

Run the existing non-mutating host doctor for the shared Docker, kernel,
cgroup, BTF, bpffs, daemon, and `nosh-l4` prerequisites:

```bash
bash scripts/nosh-guard-doctor.sh --mode learn
sudo bash scripts/nosh-guard-doctor.sh --mode learn --deep
```

The command's `--deep` flag means deeper host feature probes; it is unrelated
to the currently unavailable `nosh build profile --depth deep` collector set.
Before a real build profile, also verify the build-specific pieces without
attaching a sensor:

```bash
guard_prefix="${NOSH_GUARD_PREFIX:-/usr/local}"
docker context inspect --format '{{json .Endpoints.docker.Host}}'
docker info --format '{{json .}}'
docker buildx version
sudo "$guard_prefix/libexec/nosh-build/nosh-build-loader" health --depth balanced
sudo "$guard_prefix/libexec/nosh-build/nosh-build-loader" verify --depth balanced
sudo "$guard_prefix/libexec/nosh-guard/nosh-l4-loader" health
```

The `verify` command creates and immediately destroys the collector maps and
programs without attaching them. Unlike `health`, it invokes the target
kernel's real BPF verifier and catches complexity or compatibility rejection
before a build session begins. Bundle installation with `--deep-verify` runs
both checks automatically.

The live command repeats the relevant checks and refuses unsupported remote,
rootless, non-Linux, cgroup-v1, or host-cgroup-namespace Docker setups. Docker
must advertise private cgroup namespaces as its default before Nosh starts the
privileged BuildKit builder; the started builder and root Guard independently
revalidate that boundary.

`./scripts/release-audit.sh` installs the Debian CO-RE toolchain in its digest-pinned
audit image and compiles all four objects, skeletons, and loaders in the offline
verification phase. The unprivileged audit intentionally does not
verifier-load or attach BPF; retain that check in the privileged host smoke
matrix for every supported kernel family.

## Installing the host assets

Build the supported host archive on the Docker host. Docker is the only host
build tool used by this command: it never invokes host Node.js, npm, npx,
clang, bpftool, or a compiler. The wrapper builds a dedicated image from the
exact pinned base
`node:24.18.0-bookworm-slim@sha256:cb4e8f7c443347358b7875e717c29e27bf9befc8f5a26cf18af3c3dec80e58c5`;
its Debian compiler and CO-RE packages resolve at image-build time. The Guard
host payload has no third-party JavaScript imports: it packages the checked-in
CLI/daemon module closure, the pinned image's Node `v24.18.0` runtime and
license, and freshly compiled loaders. Their bytes, version, and licenses are
covered by the release manifest.

Use this fail-closed flow so the build, checksum verification, and extraction
remain unprivileged and only the validated installer runs through `sudo`:

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

The packaging container runs offline as the invoking user's UID/GID with all
capabilities dropped and a read-only root filesystem. It receives the checkout
and `/sys/kernel/btf/vmlinux` read-only, uses executable scratch tmpfs for clean
collector builds, and exposes only the selected output directory as a writable
host path. Without `--output-dir`, it emits a `.tar.gz` plus a same-directory
`.sha256` below `.nosh-guard-host-bundles/`; the grouped flow instead selects a
fresh private artifact directory. Readable host BTF and a working Docker daemon
are therefore the host prerequisites; the compiler toolchain stays in the
image.
The daemon must be local, rootful, non-userns-remapped, and Linux. Rootless or
userns-remapped Docker is rejected because its ID mapping cannot satisfy the
private caller-owned output mount.
The default path cleans and rebuilds all four first-party BPF loaders so stale objects,
skeletons, or loaders cannot enter a new archive. The compatibility option
`--use-existing-loaders` instead packages the four reviewed loader binaries
and exact `nosh_egress.bpf.o` already present in the read-only checkout;
packaging remains containerized and
the pinned Node.js runtime cannot be overridden.

The grouped flow requires exactly one matching archive, checksum, and safe
installer, and removes its unprivileged work directory on exit.

The default software prefix is `/usr/local`. To use a reviewed root-owned
prefix such as `/opt/notty`, pass `--prefix /opt/notty` to `install`,
`verify`, and `uninstall`, and record the same choice with
`./scripts/setup-nosh.sh --guard-prefix /opt/notty`. The installer renders the
manifest-covered wrappers, adapter paths, service units, verifier, and sudoers
commands for that prefix. Fixed configuration, state, socket, unit, and
sudoers locations do not move.

Installation creates a versioned, manifest-verified release below
`PREFIX/lib/notty/nosh-guard/releases/`, atomically selects `current`, and
installs root-owned launchers, all four loaders, the exact egress BPF object
and digest receipt, authoritative adapter files, documentation/licenses, and
the bpffs/Guard service units. The Guard service runs a manifest
and deployment-integrity check before every start. Before selecting a release,
the installer rechecks the original manifest digest, complete file inventory,
hashes, object types, and hard-link counts from a root-owned staging copy. The
daemon itself creates
the fixed mode-`0600` management socket, so no systemd socket unit is installed
and socket activation is not implied.
It also writes the non-secret, root-owned mode-`0644` layout receipt
`/etc/nosh-guard-install-layout.conf`. User launchers use that receipt when no
environment or user path selection is present. An existing receipt prevents a
cross-prefix upgrade; uninstall the old prefix while preserving configuration
and state, then install the reviewed bundle at the new prefix.

Existing adapter files that differ are never overwritten implicitly. Review
the difference and add `--replace-config` to make the bundled versions
authoritative. The managed network contract is seeded only when absent and is
then left for the operator to replace with reviewed policy. A preserved
network contract must remain a singly linked, root-owned mode-`0640` regular
file.

For unattended CI, replace the final `sudo` command inside the grouped flow
with the following installer invocation to create a narrowly scoped sudoers
rule for an existing Docker-authorized group:

```bash
sudo "${installers[0]}" install --prefix /usr/local \
  --replace-config \
  --sudoers-group docker \
  --enable-now \
  --deep-verify
```

That rule permits only the exact `nosh-guard build-session begin`, `finish`,
`abort`, and `exported` helper commands. `exported` is the retention handshake
sent only after the private and portable bundle has been durably adopted. The
rule does not grant the general Guard lifecycle API. Docker authority is
already host-root-equivalent on a conventional daemon; use a dedicated CI
group if the local authorization model differs. Without this option, normal
sudo authentication remains required.

An existing `/etc/sudoers.d/nosh-build-profile` must be a singly linked,
root-owned mode-`0440` regular file and exactly match the requested group. The
installer refuses drift; after review, add `--replace-sudoers` together with
`--sudoers-group` to authorize replacement. A receipted same-prefix refresh
derives the group from the exact existing policy and revalidates it. Other
installations must name the group explicitly rather than silently inheriting
the file.

After changing Guard or collector sources, refresh the existing host
installation from the reviewed checkout with:

```bash
./scripts/reset-nosh-guard.sh
```

Run the wrapper as the Docker-authorized user, not with `sudo`. It discovers
the existing prefix from the protected installation receipt (or accepts
`--prefix ABS`), rebuilds and checks the bundle in a private temporary
directory, and elevates only the extracted `install.sh install` step. This is
an in-place versioned refresh: it enables/starts and deep-verifies the daemon
without deleting `/etc/nosh-guard` or `/var/lib/nosh-guard`. The default
fails closed if a bundle-authoritative adapter or version file differs. After
reviewing an intentional collector-contract upgrade, run
`./scripts/reset-nosh-guard.sh --replace-config` to replace only those
bundle-authoritative files. That option never replaces the operator-managed
network contract and never deletes Guard state or evidence.

Verify or remove a deployed bundle with its installed scripts:

```bash
sudo /usr/local/libexec/nosh-guard/nosh-guard-host-verify --deep
sudo /usr/local/lib/notty/nosh-guard/current/install.sh verify --deep
sudo /usr/local/lib/notty/nosh-guard/current/install.sh uninstall
```

For a custom prefix, replace `/usr/local` in all three commands and pass the
same `--prefix PREFIX` to the installed `install.sh` verify or uninstall
operation.

Uninstall disables the service and removes only managed binaries, docs,
sudoers policy, and release payload by default. It preserves
`/etc/nosh-guard` and `/var/lib/nosh-guard`. `--purge-config` removes only the
known bundle-managed configuration files; `--purge-state` irreversibly
removes all Guard evidence and state. Use `--force` only when recovering an
already damaged installation.

The bundle intentionally does not install Docker, Buildx, sudo, systemd,
Tetragon, Inspektor Gadget, nftables, AppArmor tools, or a compiler toolchain.
It also does not add BPF privileges or host sockets to `Dockerfile.nosh`; all
collector authority remains in the root host daemon and loader binaries.
The bundled Node executable comes from the pinned Bookworm builder image and
still uses the target's dynamic loader, libc, libstdc++, and related system
libraries. Move the archive only to a reviewed host with the same architecture
and compatible ABI, or rebuild it on the destination host. Installed launchers
use only the bundled runtime plus `/usr/local/sbin`, `/usr/local/bin`,
`/usr/sbin`, `/usr/bin`, `/sbin`, and `/bin`; install Docker and adapter tools
in one of those root-controlled paths.
The loader binaries likewise retain the Bookworm builder's userspace runtime
dependencies (normally libbpf, libelf, zlib, and libc). The installer does not
vendor those shared objects, and host BTF compatibility does not guarantee the
userspace ABI. `--deep-verify` must expose missing or incompatible loader
dependencies before the service is enabled.

Both loaders arm Linux's parent-death signal for supervised `run` processes
and verify that their parent remained stable while arming it. A guard daemon
crash therefore requests collector shutdown and link teardown; because a
missing supervisor may also remove the evidence pipes, such a run remains
incomplete unless its normal final records were already persisted.

As defense in depth, each loader also lowers `RLIMIT_FSIZE` to at most 128 MiB
per regular output file before BPF setup and treats `SIGXFSZ` as a fatal
collector error. This complements the daemon's live per-source byte quota:
the process limit protects direct regular-file descriptors, while the daemon
quota independently bounds each pipe-backed collector stream. Finalized
user-owned sources use a separate limit derived from the validated cold/warm
pass count (at most two), so a compare profile can retain both bounded streams
without relaxing the 128 MiB per-pass limit.
The unprivileged orchestrator independently caps raw BuildKit progress at
128 MiB and the optional Docker Desktop build-record export at 64 MiB. An
over-limit required progress stream stops the build and preserves an
incomplete bundle; an over-limit optional build-record archive is omitted and
reported without weakening the required BuildKit history summary.

## Evidence and CI artifacts

Private bundles are mode-`0700` directories with mode-`0600` files:

```text
~/.nosh/build-profiles/<project-key>/<run-id>/
~/.nosh/build-net-profiles/<project-key>/<run-id>/
```

They can contain sanitized invocation metadata, raw Buildx progress and
history, root-exported kernel evidence, cgroup snapshots, reports, and the
unapproved candidate. A build-network bundle also contains
`build-network-policy-draft.json`, which is editable and hash-bound to the
immutable evidence/candidate but is not itself approval or authority. Treat
the entire private bundle as sensitive: source
paths, command arguments, registry names, DNS lookups, and process behavior
can reveal project or infrastructure details. Build secrets and SSH material
are not copied intentionally, but a tool can still expose sensitive values in
its own output.

The root helper never writes into these user-owned directories. It first
copies the fixed, root-owned evidence files into a root-protected directory
under the sticky `/tmp` boundary, changes ownership only after the copy is
complete, and returns that directory to the unprivileged orchestrator for
adoption into the private bundle.

Profile commands print safe preflight, builder, pass, cleanup, and evidence
stage updates to standard error while they run. Successful commands reserve
standard output for the redacted text summary and the private/portable bundle
paths. `--private-json` is an explicit diagnostic escape hatch for the full
result object; do not enable it in shared CI logs.

The `portable/` directory is the artifact intended for CI upload. It excludes
raw events, raw logs, commands, and source paths, redacts user/project values,
and carries content hashes plus a non-authoritative summary. Its
`candidate.json` is a separately hashed `NoshBuildPortableCandidateProjection`;
the labeled private hashes are correlation values, not a claim that the
redacted projection validates as the private candidate. It remains
unattested and must not be interpreted as an approval. Keep the private bundle
on a protected runner and publish only the redacted portable directory, for
example with the CI system's normal artifact uploader after the profiling
command succeeds.

A useful CI job preserves the command's exit status, uploads `portable/` even
when evidence is incomplete, and marks an incomplete candidate as a profiling
failure rather than silently falling back to an ordinary unmeasured build.
Self-hosted runners need the same reviewed kernel, Docker, daemon, loader, and
sudo policy on every worker; hosted Docker runners generally cannot attach the
required host eBPF programs.
