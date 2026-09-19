# Live eBPF allow/deny proof

`scripts/nosh-egress-poc.sh` tests actual socket enforcement on a disposable
container cgroup using the installed `nosh-egress-loader`. It uses cached images
by immutable image ID and a new internal Docker bridge. The two HTTP endpoints
are local containers; the test makes no Internet requests or image pulls.

The Alpine-based client image already contains curl. Its normal Nginx
entrypoint is overridden with an idle process, and each probe runs through
`docker exec`. Two small Node HTTP servers respond with `A` or `B` on port 8080.
The workload containers run as UID/GID 1000, with read-only roots, all
capabilities dropped, no published ports, and no host mounts or Docker socket.

## Commands and context

Run the Docker-backed baseline from the **host**, as your normal user:

```sh
bash /home/kross/notty/scripts/nosh-egress-poc.sh --baseline
```

It checks the client image, both HTTP endpoints, JSON policy generation, and
cleanup. It never loads or attaches BPF. All JavaScript tooling runs inside an
offline container; no host npm installation or execution is needed.

After reviewing the helper, the live proof requires an explicitly authorized
root invocation from the **host**, not from inside the client container:

```sh
sudo bash /home/kross/notty/scripts/nosh-egress-poc.sh --run
```

If already in a root host shell, omit `sudo`. The helper never invokes sudo
itself. It creates a private mount namespace and mounts a fresh bpffs there.
All BPF attachment, inspection, and detachment happen in that namespace. It
does not contact `nosh-guardd`, activate a deployment, or change signing trust.
The operator controls this diagnostic attachment directly; it is not evidence
that the signed production deployment workflow has passed.

## Try the policy interactively

To keep the disposable client running with the allow-A policy attached, run
this command in the first **host terminal**:

```sh
sudo bash /home/kross/notty/scripts/nosh-egress-poc.sh --hold allowA
```

Use `--hold allowB` to reverse which endpoint is allowed. Leave this terminal
open: the helper supervises the native policy attachment for the held session.
Once ready, it prints a complete `docker exec -it` command containing the
client's full container ID and the `ALLOW_URL` and `DENY_URL` environment
variables. Copy that printed command into a **second host terminal** to enter
the client container.

Run these commands **inside that container shell**:

```sh
curl --noproxy '*' --max-time 3 "$ALLOW_URL"
curl --noproxy '*' --max-time 3 "$DENY_URL"
```

The allowed URL returns `A` for `allowA`, or `B` for `allowB`. The denied URL
fails to connect. Exiting this shell only disconnects the interactive session;
the first terminal continues supervising enforcement. Press **Ctrl-C in the
first host terminal** to stop the holder and clean up its containers, network,
and BPF pins.

Hold mode writes a separate `held-session.json` receipt. It does not produce
an acceptance-test result; use `--run` for the complete six-probe proof below.
Its `closed` status reports successful teardown, not complete capture of every
manual request. A terminal signal can stop collection before the client is
paused; the policy remains attached until explicit detachment during cleanup.
The held policy applies only to the disposable client identified by the
printed command. It is not automatically applied to other containers or
`3jsui`.

## Required results

| Phase | Endpoint A | Endpoint B |
| --- | --- | --- |
| Baseline | HTTP 200, body `A` | HTTP 200, body `B` |
| Allow A only | HTTP 200, body `A` | Connection denied |
| Allow B only | Connection denied | HTTP 200, body `B` |

Each request uses a numeric IPv4 address, a fresh curl process, a phase-specific
URL path, no proxy or curl configuration file, and a short timeout. IPv6 is
disabled only in these disposable containers' network namespaces.

The helper requires matching `connect4` kernel decisions for the allowed and
denied destination in each phase. Denials must report `policy-deny`,
`default-deny`, and `enforcementApplied: true` for the exact client cgroup and
policy generation. Server logs must show the four successful requests and no
request for either denied path. A curl timeout alone cannot pass the proof.

Readiness binds all six attached programs, twelve maps, the object digest,
policy digest, client image, and cgroup identity. Collector final counters
must match the events and final pinned snapshot, with no lost events,
decoding errors, or backend failures. Synthetic packet tests and mocked
evidence fixtures do not count as this live result.

The recorded live acceptance run
`cache/policy-cli-test/enforce-poc/live-oylBiZ` passed all six probes, with
kernel denials bound to the client cgroup and each policy generation. Each
enforcement phase recorded twelve kernel events: eleven allowed and one
denied. These are socket/packet decision counts; each enforcement phase made
two HTTP connection attempts. The run reported zero loss, decoding errors,
or backend failures, and verified removal of the containers, network, and
BPF pins.

## Policies, evidence, and cleanup

A full `--run` retains `endpoints.json`, `probes.jsonl`, both server logs, and
`allowA/` and `allowB/` directories containing readable `policy.json`, the
native `policy.manifest`, readiness, decisions, final counters, and detach
receipts. These JSON policies are diagnostic fixtures passed through the
existing manifest renderer; they are not signed deployment artifacts.

The policy contains one exact `/32` TCP/8080 allow. The loader also requires a
resolver entry and exact bridge-gateway containment; the configured resolver
is a local fixture address and is not used by these numeric-IP requests.
The helper prints the JSON policy path. Editing that file does not update an
already attached policy; hold mode currently selects either generated fixture
with `--hold allowA` or `--hold allowB`.

The client stays paused between detachment and the next verified attachment.
The collector is stopped and waited on before explicit detach. `SIGTERM`
alone does not remove enforcement. Normal completion requires pin removal,
container removal, and network removal; cleanup recovers resources by a fresh
session UUID if Docker creation loses its reply. A cleanup failure fails the
test. On failure, the helper removes its client even if native detach failed,
so it does not leave a running, unguarded test workload.

Root evidence remains under `/root/nosh-egress-poc.*`. The helper exports a
user-readable copy under `cache/policy-cli-test/enforce-poc/live-*`. Baseline
results remain under the corresponding `baseline.*` directory. The final
`result.json` exists only for live verification; check the helper's exit status
and `cleanup.json` as well. Evidence consistency checks cannot authenticate an
entirely fabricated directory.

This proof covers container-scoped IPv4/TCP enforcement. DNS policy, IPv6,
per-binary distinctions, and signed end-to-end activation need their own
tests. Syft tooling remains a separate follow-up after this proof passes.
