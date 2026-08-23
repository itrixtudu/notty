# Optional build URL observation collector

`nosh-url` is a cgroup-scoped, observation-only enrichment collector for
`build-net-learn`. Its first provider observes calls to the exported libcurl
function `curl_easy_setopt` when the option is `CURLOPT_URL`. It supplies
recognizable resource evidence to Policy Review; it does not grant authority,
evaluate policy, allow traffic, or deny traffic. L3/L4 evidence remains the
network truth and the egress dataplane remains the enforcement boundary.

## Data boundary

The BPF program reads at most 2047 URL bytes plus a terminating NUL into a
bounded ring-buffer record. This raw field is only an internal kernel-to-loader
transport. The loader never writes it to JSON, diagnostics, status output, or
statistics. Failed and truncated reads increment `readErrors` and produce no
observation.

Before writing JSON, the loader:

- removes URL userinfo, query, and fragment components;
- lowercases and validates the scheme and host;
- calculates an explicit or known default effective port;
- retains only a visible-ASCII path beginning with `/`;
- limits the retained path to 512 bytes and marks truncation; and
- records only process name, PID/TID, target and observed cgroup IDs,
  monotonic/Unix timestamps, provider, source, scheme, host, port, and path.

Headers, request or response payloads, query parameters, fragments, passwords,
tokens in URL userinfo, and the raw URL are never evidence fields. Paths can
still contain application-selected identifiers, so URL evidence remains
private review material and must receive the same redaction and retention
treatment as other build evidence.

## Attachment and coverage

The loader opens the exact cgroup-v2 directory and puts its descriptor in a
`BPF_MAP_TYPE_CGROUP_ARRAY`. The global uprobe calls
`bpf_current_task_under_cgroup()` before reading userspace memory, so only the
selected cgroup and descendants can produce events.

An explicit repeatable `--library` path is opened, verified as a bounded regular
file, and attached before readiness. Dynamic discovery recursively reads the
selected cgroup's `cgroup.procs`, inspects executable `libcurl*.so*` mappings,
reopens them through the process root, verifies the mapped device and inode,
then attaches through `/proc/self/fd/<fd>`. The link is therefore bound to the
already-verified object even if a pathname changes. No discovered library path
is emitted.

Dynamic discovery cannot be exhaustive. A short-lived process can call libcurl
before the next scan, a new object can execute before its uprobe is attached,
static libcurl does not expose a shared-object mapping, and clients such as Git
or apt may use another HTTP implementation. Every object first discovered
after readiness increments `discoveryMisses` for its uncertain pre-attachment
window. Map/open/identity/attachment failures increment it as well. The final
record always states `coverageComplete: false`; zero misses must not be treated
as proof that every URL-producing call was seen.

This makes the collector safe supplemental evidence rather than a false
coverage oracle. A consumer may correlate a sanitized resource with process,
DNS, and L4 observations, but must never create an enforcement rule from the
URL observation alone.

## Records and lifecycle

Evidence stdout contains only `url-observation` and `stats` records. Status JSON
uses the separately inherited status descriptor. SIGINT or SIGTERM stops new
discovery, detaches every uprobe, drains the ring buffer with checked consume
results, and only then emits one `final: true` statistics record. A detach or
drain error produces a nonzero exit and no clean final record.

Final counters include:

- `discoveryMisses` and `readErrors` as required explicit coverage gaps;
- ring-buffer, configuration, and cgroup-filter failures;
- scans, inspected processes, mappings, and successful attachments;
- captured-call (`rawObservations` is a count, never raw URL content), rejected,
  truncated-path, and emitted observation counts; and
- decoder and output-limit failures.

The evidence stream is capped at 64 MiB with reserved space for final
statistics. Hitting the cap stops collection and is explicit in
`outputLimitReached`.

## Build and usage

Build and test this directory only inside the project audit/Nosh container:

```text
make -C bpf/nosh_url
make -C bpf/nosh_url test
```

The host-side integration should launch it as an optional adapter only for
`build-net-learn`:

```text
nosh-url-loader run \
  --cgroup /sys/fs/cgroup/... \
  --cgroup-id 1234 \
  --status-fd 3
```

Known, immutable provider objects may be preattached with repeatable
`--library /absolute/path/to/libcurl.so...`. The default 100 ms discovery poll
can be changed from 50 ms through 10 seconds. Reducing it narrows but cannot
eliminate the late-attachment coverage window.
