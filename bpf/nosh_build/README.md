# Nosh build evidence sensor

`nosh_build` is a first-party, observe-only CO-RE eBPF collector for a
dedicated BuildKit builder cgroup. It supplies the balanced behavioral half of
`nosh build profile` and `nosh build net learn`:

- process exec and exit events;
- syscall counts, error counts, and elapsed-time summaries; and
- direct IPv4/IPv6 UDP DNS queries and bounded matching responses on port 53.

`nosh build profile --depth policy` adds metadata-only `file_open` summaries:
resolved path, first/last observation time, and read/write/execute/create open
counts. It never captures file contents. The policy hook requires Linux 5.10+
with BPF LSM enabled; path/map loss is fatal rather than silently omitted.

The existing `nosh_l4` loader is a separate required build adapter. It records
L3/L4 attempts and flow totals for the same builder cgroup. Neither collector
enforces policy or turns observations into an approved runtime profile.

The C sources use `0BSD OR GPL-2.0-only`, with the license texts shared from
[`../nosh_l4/LICENSES`](../nosh_l4/LICENSES/). The kernel license string is the
kernel-recognized `Dual BSD/GPL` designation.

## Scope and cgroup identity

The four process/syscall tracepoints are necessarily system-wide attachment
points. Before recording anything, the BPF program uses a cgroup-array target
and the kernel's descendant-membership helper. This avoids doing map or event
work for unrelated host syscalls. Helper errors fail closed and increment
`cgroupFilterErrors` rather than attributing the event.

The UDP DNS programs attach directly to `cgroup_skb/egress` and
`cgroup_skb/ingress` on the selected builder cgroup, so the kernel applies
them to descendant executors. Both always return `1` (`NOSH_BUILD_ALLOW`).
The parser reads only IP, UDP, DNS headers, one question, and a bounded set of
answer metadata. It never stores packet payloads. Because cgroup packet hooks
are not reliable current-task attribution points, DNS events deliberately use
`process: null`; the selected cgroup and companion L4 flow remain
authoritative.

Every query and response records the kernel socket cookie, transaction ID,
client port, server address, and server port in correlation-key version 1.
Consumers may join records only when `correlation.complete` is true and all
tuple fields match. A zero socket cookie remains visible but increments the
`dnsCorrelationMissing` coverage counter, preventing an ambiguous join.

The loader independently opens an absolute cgroup-v2 path with `O_NOFOLLOW`,
rejects the cgroup root, resolves its kernel ID with `name_to_handle_at()`, and
checks `--cgroup-id` before loading the session configuration. Selecting a
builder by name alone is not supported.

## Balanced and policy evidence contract

Stdout is JSONL containing:

- a `capabilities` record declaring available and unavailable sources;
- `event` records matching
  [`schema/nosh-build-event.schema.json`](schema/nosh-build-event.schema.json);
- one final `syscall-summary` record per observed syscall number; and
- initial/periodic `stats` records, ending with exactly one `final: true`
  record after programs detach and the ring buffer drains.

Status, readiness, and libbpf diagnostics are JSONL on stderr unless the
supervisor supplies `--status-fd`. A run is complete only when the loader exits
zero after SIGTERM/SIGINT, emits final stats, and all fatal counters are zero:

- `decoderErrors`;
- `ringbufDrops`;
- `syscallMapFull`;
- `inflightMapFull`;
- `configMissing`;
- `cgroupFilterErrors`;
- `dnsAnswerLimitReached`;
- `dnsCorrelationMissing`.

Policy depth additionally requires `fileMapFull` and `filePathErrors` to be
zero, emits one final `file-summary` per bounded map key, and binds the actual
summary count and total opens to final statistics. Resolved paths are limited
to 255 bytes in this prerelease ABI; a longer path makes the run incomplete.

DNS parsing counters are explicit coverage gaps rather than silent loss. They
must be retained in the candidate and portable report. Missing correlation and
answer-limit exhaustion make the session incomplete. A truncated response has
`parseComplete: false`; a malformed response is discarded and counted. Neither
can contribute a name-to-address relation. Unsupported answer counts and
compression-pointer counts are also diagnostic. `inflightSyscalls` is a
diagnostic: a nonzero final value means some syscalls were still active when
collection stopped, so duration totals are not complete.

The raw ABI changes only with `NOSH_BUILD_SCHEMA_VERSION` (currently v2).
Unsigned 64-bit
values are decimal JSON strings to avoid JavaScript precision loss. Kernel
monotonic event timestamps are converted to Unix epoch nanoseconds by the
loader. The raw syscall tracepoint exposes its syscall identifier as a signed
machine word, so the map key and emitted `syscallNumber` retain a signed 64-bit
contract on the supported 64-bit architectures.

Syscall totals use a bounded per-CPU hash. Each BPF invocation therefore
updates a CPU-local value, making `max_duration_ns` a race-free compare/store
without a verifier-hostile retry loop. After all syscall programs detach, the
loader saturating-sums counts and durations across possible CPUs and selects
the greatest per-CPU maximum.

## DNS coverage and explicit gaps

The v2 balanced sensor keeps its kernel role deliberately small. Each exact
cgroup-scoped UDP/53 hook records socket, address, port, direction, and timing
metadata and copies at most 1232 bytes beginning at the DNS header into one
private ring-buffer record. The trusted loader immediately decodes that record
in userspace, emits only normalized metadata, and never writes the raw DNS wire
bytes to evidence or diagnostics.

The userspace decoder emits one dotted, root-terminated QNAME and reports the
valid root QNAME as `.`. Response names may use bounded backward DNS
compression pointers. Up to sixteen relevant IN-class A, AAAA, or CNAME answers
are retained after visiting at most sixteen declared answers. This is
sufficient to materialize a conservative QNAME -> CNAME -> A/AAAA chain
without putting branch-heavy protocol normalization in the kernel verifier.

The following conditions are explicit rather than silently omitted:

- missing socket cookies increment `dnsCorrelationMissing`;
- DNS messages larger than the private 1232-byte handoff and UDP responses
  with the DNS truncated bit increment
  `dnsTruncatedResponses` and set `parseComplete: false`;
- declared or relevant answers beyond the fixed bounds increment
  `dnsAnswerLimitReached` and set `answerLimitReached: true`; and
- malformed, overlong, cyclic, or over-deep compressed names increment the
  parsing/loss counters.

Unsupported answer types are counted and omitted because they cannot directly
establish the requested CNAME/A/AAAA-to-IP relation. The collector deliberately
does not claim coverage for:

- DNS over TCP;
- DoH, DoT, or application-specific encrypted name resolution; or
- fragmented IPv4 UDP DNS or UDP DNS behind IPv6 extension headers.

`nosh_l4` still records the corresponding IP/protocol/port flows. BuildKit
source/provenance hosts and the build-network logging forwarder should be
joined by the higher-level build profiler; they are not inferred in this
sensor.

## Deep collection

Deep mode is not implemented in this component. `health --depth deep` returns
unhealthy and `run --depth deep` exits before loading BPF. Off-CPU stacks,
block-latency evidence, and cgroup CPU stack samples are listed as unavailable
in the capabilities record. File-open evidence belongs to the separate
`policy` depth. This keeps balanced evidence usable without presenting
diagnostic substitutes as complete deep profiling.

## Build, install, and supervise

Build on a supported Linux host or in the project’s privileged build tooling:

```sh
cd bpf/nosh_build
make loader
sudo make install
```

The normal repository rule still applies: do not run npm, npx, package tests,
or production builds directly on the host. The Makefile only invokes the C/BPF
toolchain and its static Node test target is intended for the repository’s
Docker-backed audit environment.

The command contract is:

```text
nosh-build-loader health [--cgroup ABSOLUTE_PATH] [--cgroup-id UINT64]
  [--depth balanced|policy|deep]

nosh-build-loader verify [--depth balanced|policy|deep]

nosh-build-loader run --cgroup ABSOLUTE_PATH [--cgroup-id UINT64]
  [--depth balanced|policy|deep]
  [--stats-interval-ms 0|100..3600000] [--status-fd FD]
```

`health` checks prerequisites without creating BPF maps or invoking the kernel
verifier. Root may run `verify` to open and load the selected CO-RE programs,
then immediately destroy them without attaching to a tracepoint or cgroup. This
is the definitive preflight for verifier complexity and kernel compatibility.

The default install path is
`/usr/local/libexec/nosh-build/nosh-build-loader`. The source adapter set is
[`../../config/nosh-build/adapters.json`](../../config/nosh-build/adapters.json);
`make install` places that reviewed file and `versions.json` at the build
service's configured root-owned paths, with mode `0640`. Both `nosh-build` and
`nosh-l4` must reach `ready` before the Buildx invocation begins.

Send SIGTERM or SIGINT only after the build pass and its nested executors have
finished. SIGKILL, a nonzero loader exit, missing final stats, identity drift,
or a fatal loss counter makes the evidence incomplete.

The supervised `run` process also arms Linux `PR_SET_PDEATHSIG` with SIGTERM
and verifies its parent did not exit during setup, so loss of the guard daemon
triggers link teardown instead of orphaning the collector.

Before loading BPF, `run` lowers `RLIMIT_FSIZE` to 128 MiB per regular output
file, or preserves a smaller inherited limit, and handles `SIGXFSZ` as a fatal
collector error that detaches links. The supervisor's live byte quota remains
authoritative for pipe-backed output and for aggregate session storage.

## BuildKit version pin

[`../../config/nosh-build/versions.json`](../../config/nosh-build/versions.json)
records the reviewed BuildKit `v0.30.0` reference and its multi-platform index
digest. Live profiling must retain and validate that immutable digest. A bare
mutable tag is permitted only to describe or dry-run the command.

## Verification

Static tests validate the ABI, bounded attribution, observe-only DNS hook,
loss accounting, schemas, adapter composition, deep-mode rejection, and clean
finalization contract. The Docker-backed release audit also performs an
offline CO-RE object, skeleton, and userspace-loader compile for both BPF
collectors, then removes the generated files before package inspection. It
does not verifier-load or attach programs. A live privileged smoke test must
still prove that nested BuildKit `RUN` processes and UDP DNS traffic appear
beneath the selected builder cgroup on every supported kernel family.
