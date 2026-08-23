# Nosh L3/L4 evidence sensor

`nosh_l4` is an observe-only CO-RE eBPF sensor for building a network
allowlist from a training run of a Nosh container. It records connection and
datagram attempts plus per-flow packet/byte accounting. It does not enforce a
policy, copy application data, or keep packet payload.

This directory is deliberately standalone. The included
`nosh-l4-loader` is the privileged host-side manager: it resolves one exact
container cgroup, loads the object, attaches the programs, and consumes the
evidence. The BPF object can also be compiled and packaged as an Inspektor
Gadget OCI image.

## License

This first-party Notty component is available under the recipient's choice of
`0BSD OR GPL-2.0-only`. The C and header sources carry that SPDX expression,
and the complete license texts are in [`LICENSES/`](LICENSES/).

The BPF object's `Dual BSD/GPL` loader string is the kernel's recognized
GPL-compatible designation. It describes kernel loading compatibility; it
does not replace or narrow the exact source-license choice above.

## Evidence and hook coverage

| Section | Evidence | Protocols | Process attribution |
| --- | --- | --- | --- |
| `cgroup/connect4` | IPv4 connect attempt and requested peer | TCP, UDP | Current task and socket cookie |
| `cgroup/connect6` | IPv6 connect attempt and requested peer | TCP, UDP | Current task and socket cookie |
| `cgroup/sendmsg4` | IPv4 UDP sendmsg attempt and requested peer | UDP | Current task and socket cookie |
| `cgroup/sendmsg6` | IPv6 UDP sendmsg attempt and requested peer | UDP | Current task and socket cookie |
| `cgroup_skb/ingress` | Running flow packet/byte totals | TCP, UDP, ICMPv4, ICMPv6 | Socket-cookie cache when available |
| `cgroup_skb/egress` | Running flow packet/byte totals | TCP, UDP, ICMPv4, ICMPv6 | Socket-cookie cache when available |

The sendmsg cgroup hooks are the kernel's UDP sendmsg attach points. TCP
connection intent comes from the connect hooks and TCP traffic volume comes
from the packet hooks.

Every cgroup program returns `1` (`NOSH_L4_ALLOW`). `verdict=allow`,
`observed-only`, and the hook return are evidence about this sensor's decision,
not proof that the syscall or packet ultimately succeeded. Connect and sendmsg
events therefore carry `completion-unknown`.

The packet parser reads only the IPv4/IPv6 and first transport-control bytes
needed for addresses, ports, protocol, and ICMP type/code. IPv6 extension
walking is bounded to six headers. Non-initial fragments are counted without
inventing transport fields and are marked `l4-unavailable`.

## Maps and ABI

- `events` is a ring buffer of `struct nosh_l4_event`. Attempt and packet
  events share a versioned fixed-size ABI.
- `socket_owners` is a bounded LRU cache keyed by the kernel socket cookie.
  Connect/sendmsg hooks populate it with PID/TID, UID/GID, and `comm`.
- `flow_totals` is a bounded hash keyed by cgroup, cookie, direction,
  addresses, transport fields, ICMP fields, and interface. Its value holds
  first/last timestamps and cumulative packets/bytes.
- `stats` is a per-CPU array for ring-buffer loss, parse errors, unsupported
  protocols, missing session configuration, and flow-map capacity failures.
- `session_config[0].target_cgroup_id` binds packet observations to the exact
  runtime cgroup selected by the host manager.

The normalized userspace contract is
[`schema/nosh-l4-event.schema.json`](schema/nosh-l4-event.schema.json).
Unsigned 64-bit values are decimal strings in JSON so JavaScript consumers do
not lose precision. A collector should map zero/unknown transport fields to
`null`, translate the fixed 16-byte address slots to text, and set
`metadataOnly: true`. `sensorDecision` preserves the allow-only hook verdict
for both attempt and packet events. The raw ABI timestamp is kernel monotonic
time; the reference loader samples the realtime/monotonic offset and emits
`timestampNs` as Unix epoch nanoseconds for evidence correlation.

The loader also writes cumulative loss records described by
[`schema/nosh-l4-stats.schema.json`](schema/nosh-l4-stats.schema.json).
Health, readiness, shutdown, and libbpf diagnostic records follow
[`schema/nosh-l4-control.schema.json`](schema/nosh-l4-control.schema.json).

The raw ABI changes only with `NOSH_L4_SCHEMA_VERSION`. Consumers must reject
an unknown version or an unexpected `event_size`.

## Host prerequisites

- Linux cgroup v2 with cgroup BPF enabled.
- Kernel BTF at `/sys/kernel/btf/vmlinux` for the normal CO-RE build.
- Ring-buffer support (Linux 5.8 or newer).
- A host process with the privileges needed to load BPF and attach to the
  target cgroup. Exact capabilities depend on the kernel; a root host service
  is the simplest initial deployment.
- `clang`, `bpftool`, libbpf headers/libraries, and a C compiler for the
  libbpf path, or Docker plus `ig` for the default Gadget builder.

Run the loader on the host, not inside the Nosh container. Giving the profiled
container BPF or host-cgroup access would defeat the isolation the resulting
profile is intended to provide.

## Host loader build and contract

Build the CO-RE object, skeleton, and standalone loader:

```sh
cd bpf/nosh_l4
make loader
```

`make object` creates `vmlinux.h` from the running host's BTF and compiles
`build/nosh_l4.bpf.o`. `make skeleton` additionally creates
`build/nosh_l4.skel.h` with `bpftool gen skeleton`. `make loader` embeds that
skeleton in `build/nosh-l4-loader`, so no `.bpf.o` file is needed at runtime.
`make install-loader` installs it under
`/usr/local/libexec/nosh-guard/` by default; `PREFIX`, `DESTDIR`, and
`LOADER_INSTALL_DIR` are overridable.

The command contract is:

```text
nosh-l4-loader health [--cgroup ABSOLUTE_PATH] [--cgroup-id UINT64]
  [--output-mode events|flow-summary]

nosh-l4-loader run --cgroup ABSOLUTE_PATH [--cgroup-id UINT64]
  [--output-mode events|flow-summary]
  [--stats-interval-ms 0|100..3600000] [--status-fd FD]
```

`health` emits one status JSON object on stdout and exits zero only when the
reference root-host prerequisites pass. With `--cgroup`, it also opens and
resolves that target without attaching anything.

`run` requires an absolute cgroup-v2 directory and refuses the cgroup mount
root. It opens the final path with `O_NOFOLLOW`, resolves the kernel cgroup ID
from that directory FD with `name_to_handle_at()`, and validates
`--cgroup-id` when supplied. Supplying both values is recommended because it
detects runtime/path races before BPF attachment.

After loading, the loader writes `session_config`, opens the ring consumer,
and attaches all six programs. A `ready` control record is emitted only after
all links exist. Each invocation loads a fresh object and map set for exactly
one target cgroup.

Stdout is newline-delimited evidence. The default `events` mode retains live
attempt and packet records for runtime Guard. Build profiling selects
`flow-summary`: attempts remain live, packet records are suppressed after
updating the bounded map, and shutdown emits one metadata-only
`flow-summary` record per map key.

The stream contains:

- normalized attempt/packet records matching `nosh-l4-event.schema.json`;
- an initial and periodic cumulative `stats` record; and
- a final `stats` record with `final: true` after links are detached and the
  ring buffer is drained.

In `flow-summary` mode the final statistics declare the number of emitted
summaries; the daemon verifies that count. A link-detach failure prevents the
map snapshot and fails the run.

Readiness and diagnostics use stderr by default. `--status-fd` accepts an
already-open descriptor of 2 or greater when a supervisor wants a dedicated
control stream. Every control line is JSON. `--stats-interval-ms 0` disables
periodic snapshots but retains initial/final statistics.

Send `SIGTERM` or `SIGINT` for a valid shutdown. The loader detaches all links,
drains pending events, emits final loss statistics, and exits zero. `SIGKILL`,
a nonzero exit, missing final stats, any `ringbufDrops`, `flowMapFull`,
`configMissing`, or `decoderErrors` must make the evidence run incomplete.
For supervised `run` processes, Linux `PR_SET_PDEATHSIG` is armed with SIGTERM
and followed by a parent-race check; if the supervisor exits, the loader tears
down its links rather than remaining orphaned.

Before BPF setup, `run` lowers `RLIMIT_FSIZE` to 128 MiB per regular output
file, preserving any smaller inherited limit. `SIGXFSZ` becomes a fatal
collector error and triggers link teardown. The supervisor separately caps
pipe-backed output and aggregate session storage.

Exit status `2` means invalid CLI usage. Status `1` means unhealthy or a
runtime/collector failure. Status `0` means a healthy check or a clean
supervised run.

For `adapters.json`, the intended mapping is also available as
[`adapter.example.json`](adapter.example.json):

```json
{
  "name": "nosh-l4",
  "requiredModes": ["learn", "audit", "enforce"],
  "health": {
    "command": "/usr/local/libexec/nosh-guard/nosh-l4-loader",
    "args": ["health"]
  },
  "attach": {
    "command": "/usr/local/libexec/nosh-guard/nosh-l4-loader",
    "args": [
      "run",
      "--cgroup",
      "{cgroupPath}",
      "--cgroup-id",
      "{cgroupId}"
    ]
  },
  "detach": {
    "command": "true",
    "args": []
  },
  "readiness": {
    "stream": "stderr",
    "match": {
      "recordKind": "status",
      "status": "ready"
    },
    "timeoutMs": 10000
  },
  "outputFile": "nosh-l4.jsonl",
  "stderrFile": "nosh-l4.status.jsonl",
  "detachTimeoutMs": 10000,
  "longRunning": true
}
```

The adapter supervisor must derive `cgroupPath` and `cgroupId` from the
container runtime, route the combined JSONL to `nosh-l4.jsonl`, wait for the
`ready` record before releasing a gated container, send `SIGTERM` at detach,
and wait for the final stats record. Do not select a cgroup from a container
name alone.

Record container image digest, cgroup ID, training start/end times,
dropped-event counters, and the sensor build hash beside the evidence. Those
fields are required to judge whether a generated allowlist is complete. If
another cgroup BPF product is installed, validate multi-attach coexistence on
the target kernel before training.

## Inspektor Gadget image build

`build.yaml` enables the Gadget metadata macros while preserving the same map
and struct names:

```sh
cd bpf/nosh_l4
sudo ig image build . -f build.yaml \
  --update-metadata \
  -t ghcr.io/your-org/nosh-l4-evidence:dev
sudo ig image inspect ghcr.io/your-org/nosh-l4-evidence:dev \
  --extra-info=ebpf.programs
```

The equivalent convenience target is:

```sh
make gadget GADGET_TAG=ghcr.io/your-org/nosh-l4-evidence:dev
```

Inspektor Gadget's builder supplies its BPF headers and packages the object and
`gadget.yaml` as an OCI artifact. At the time this component was written,
standard Gadget runners did not document automatic attachment for arbitrary
`cgroup/connect*`, `cgroup/sendmsg*`, or `cgroup_skb/*` sections. Treat the OCI
image as a reproducible build/distribution path unless the selected Gadget
runtime explicitly supports a target-cgroup attachment lifecycle. The bundled
libbpf loader remains the reference runtime.

## Profiling workflow and policy boundary

Use this sensor during a deliberately broad and repeatable training suite:
startup, idle periods, package installation, source fetches, builds, tests,
interactive agent work, expected DNS/NTP/proxy paths, failures, and shutdown.
Train each supported image digest and operating mode separately. Merge flows
only after reviewing destination ownership and whether an address should
become a DNS name, service identity, CIDR, proxy, or fixed endpoint.

The output is evidence for a later policy compiler. Do not convert every
observed address directly into a permanent allow rule. Separate at least:

- control-plane destinations required to start and supervise the agent;
- user/project destinations permitted for a particular coding session;
- infrastructure such as DNS, registries, proxies, and time synchronization;
- unexplained or one-off traffic that needs review.

Tetragon can run alongside this sensor for process, file, capability, and
syscall evidence and enforcement. A Cilium-style network policy still needs an
enforcement layer such as Cilium, nftables, or another host datapath. This
sensor intentionally cannot block traffic.

## Known limits

- Attempt hooks run before the final syscall result, so they cannot prove a
  successful connection or send.
- Socket-cookie attribution is best effort. Inbound accepted sockets, traffic
  first seen before connect/sendmsg, and zero-cookie packets can have a `null`
  process. If the manager fails to initialize `session_config`, packet events
  carry cgroup ID `0` and increment `CONFIG_MISSING`; attempt events can still
  fall back to the current task's cgroup.
- A full `flow_totals` map stops adding unseen flows and increments
  `FLOW_MAP_FULL`; it never silently evicts policy evidence. The reference
  loader treats that counter as incomplete evidence. A longer-running manager
  can additionally snapshot/delete entries or enlarge the map.
- IPv6 ESP, no-next-header packets, unsupported protocols, malformed headers,
  and extension chains longer than six are not added as profile flows; the
  corresponding counters expose the gap.
- Packet and byte counts are observations at cgroup ingress/egress and may
  include retransmission, fragmentation, or encapsulation effects.
- This component has no DNS-to-IP correlation, L7 parsing, or executable/file
  provenance. Join it with separately collected runtime evidence before
  producing an enforceable profile.

## Tests

The self-contained checks require only Node.js and never load BPF:

```sh
make test
```

They validate the schema, hook/protocol coverage, allow-only returns, map
accounting, process correlation, bounded header parsing, and the absence of
payload-read or packet-write helpers. The Docker-backed release audit compiles
the CO-RE object, generated skeleton, and userspace loader offline, but does
not have privileges to verifier-load or attach it. A production build must
still verifier-load the object on every supported kernel family as a live host
smoke test.
