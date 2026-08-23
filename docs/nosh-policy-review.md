# Nosh semantic policy review

Nosh policy review turns verified build and runtime captures into a frozen,
UML-like semantic graph. The graph is a review projection of evidence, not the
evidence itself and not an executable policy. Only explicit decisions over a
frozen graph can become `NoshPolicyIR`; target compilers then produce
reviewable Guard eBPF, Cilium, nftables, or iptables artifacts.

This feature is prerelease. A blocking coverage gap, blocking finding,
unresolved decision, unsupported target mapping, digest mismatch, or expired
deployment grant prevents activation.

## Authority lifecycle

Policy Review sits between observation and authority. Build and runtime learn
runs do not apply candidate network policy:

1. **Build learn** observes the build's natural DNS, resource, process, and
   L3/L4 activity. Ordinary destinations—including RFC1918 addresses, direct
   DNS, and DNS-over-TLS—remain observations rather than expected denies.
2. **Build review** lets the operator accept, deny, or narrow that observed
   build authority. Build evidence does not become runtime authority, and a
   reviewed build result is bound to its exact output image digest.
3. **Runtime learn** observes the exact image/workspace pair without applying
   the candidate. Its immutable capture is a review input, not an allowlist.
4. **Runtime review** produces explicit decisions and a target projection.
5. **Audit** evaluates the reviewed policy, emits would-deny evidence for
   traffic outside it, and otherwise allows the traffic.
6. **Enforce** defaults to deny and allows only the activated reviewed policy.

The scoped runtime exception is exact platform containment. Guard derives the
per-run Docker bridge gateway endpoints and binds their exact IPv4 `/32` and
IPv6 `/128` identities into the authenticated target context. Those endpoints
remain denied in learn, audit, and enforce and cannot be accepted by a review
decision. RFC1918, loopback, link-local, direct-DNS, and DoT address classes are
not non-reviewable invariants as a class. A known parser or protocol gap remains
visible as blocking coverage; it is allowed during learn, represented as
would-deny during audit, and denied during enforce.

## Worked profile → review → enforcement example

Run the one-click profile from the repository root on the Docker host:

```console
./build-nosh.sh net learn
```

The command opens the managed Policy Review UI and prints exact paths such as:

```text
Frozen review bundle: /absolute/path/to/bundle
Guard eBPF target context: /absolute/path/to/context.json
DecisionSet output: /absolute/path/to/decisions/decisions.json
```

In the UI, accept the interactions you want to keep and reject the unwanted
timeline interaction. Export the DecisionSet; the managed copy is written at
the printed `DecisionSet output` path.

The JSON is also editable. To reject a proposal manually without changing its
graph binding:

```console
jq '(.decisions[] | select(.proposalId == "PROPOSAL_ID")).disposition = "reject"' \
  /absolute/path/to/decisions/decisions.json > /tmp/decisions.json
install -m 0600 /tmp/decisions.json /absolute/path/to/decisions/decisions.json
```

Project that exact reviewed JSON:

```console
nosh-guard policy project \
  --bundle /absolute/path/to/bundle \
  --decisions /absolute/path/to/decisions/decisions.json \
  --target guard-ebpf \
  --context /absolute/path/to/context.json \
  --output /absolute/path/to/projected-policy
```

Continue only when the result reports `activationEligible: true`. Complete the
signed approval, deployment grant, and activation commands in the **Guard eBPF
review and activation** section, then run:

```console
sudo nosh-guard net enforce --workdir "$PWD"
```

Verify both outcomes from the profiled workload: the selected positive-control
destination succeeds, while the rejected literal IP receives no response and
the Guard deny counter increases. A timeout alone is not proof; inspect the
counter and evidence:

```console
sudo nosh-gateway status
sudo journalctl -k --since "5 minutes ago" | rg 'nosh.*deny'
```

The current target context advertises `tcpDns:false`, so literal IPv4/CIDR
rules are the activation-eligible example. An `example.org` FQDN remains
reviewable but must stay activation-ineligible until complete managed TCP-DNS
support is available; test its resolved literal IP as the enforcement canary.

## Capture and review workflow

Use the `policy` collection depth when file-open metadata is required:

```console
nosh build profile --depth policy
```

`policy` includes the balanced BuildKit, process, syscall, DNS, and L3/L4
sources plus metadata-only file-open summaries. File contents are never
captured. The build-specific L4 collector emits live connect/sendmsg attempts
and a bounded final summary per flow instead of one JSON record per packet.
Runtime Guard collection keeps its existing event mode.

The version-2 build DNS contract captures bounded IPv4/IPv6 UDP port-53 queries
and responses. It retains transaction correlation IDs, resolver/client
endpoints, A/AAAA addresses, CNAME chains, and TTLs. The summarizer can join a
query to a process/socket and an answer address to a same-pass L3/L4
destination and application service port only after a unique exact query tuple
was observed before a correlation-complete, untruncated, fully parsed response
and only while its bounded TTL remains valid. The process edge is explicitly a
nearest-preceding same-socket/resolver heuristic bounded to 30 seconds; the L4
sendmsg hook does not expose the local UDP port. CNAME attribution expires at
the minimum TTL across the traversed alias chain and terminal A/AAAA record.
Every such edge records its correlation algorithm and provenance.

That richer correlation is still observational, not automatic FQDN authority.
A client can bypass the observed resolver, reuse cached data, race a changed
answer, or connect for an unrelated reason. DNS over TCP, encrypted DNS, UDP
behind unsupported IPv6 extension headers, parse failures, and responses past
the bounded answer budget remain explicit gaps. Direct DNS and DoT attempts
remain visible in L3/L4 evidence and are allowed during build/runtime learning;
their port numbers do not make them implicit allows or invariant denies.

Build network learning has an explicit managed HTTP option:

```bash
./build-nosh.sh net learn --http-capture mitmproxy
```

The digest-pinned mitmproxy adapter records a provider-neutral private stream:
HTTP method, sanitized origin display, digests of the exact request target,
representation headers and optional request body, redirect status and exact
raw `Location` digest, response status/length/type/encoding, and raw and decoded
response digests when the provider exposes both representations. The managed
mitmproxy collector currently binds the raw transferred entity. Complete
non-credentialed responses are stored in an
immutable content-addressed store. Headers, cookies, credentials, query values,
and bodies do not enter portable review data. The old libcurl uprobe remains a
disabled legacy parser input and is not used as the managed URL boundary.

The independent evidence streams are not interchangeable. Build eBPF proves
the exact cgroup/socket/IP/protocol/port tuple; managed HTTP proves the request
and response identity; userspace DNS supplies bounded name/address history.
An unmatched record is retained with a coverage finding. In particular, the
current collector proves builder-to-proxy reachability but not the separate
proxy-container-to-origin leg. That absence is blocking and cannot produce an
origin authority proposal until a separately scoped proxy-leg L4 observation
exists. `upstreamDestination` reported by mitmproxy remains provider metadata,
not eBPF provenance. Manual Burp HAR import is always review-only and cannot
claim capture completeness or create authority.

When all required provenance exists, Policy Review presents one frozen
assurance group per observed web fetch:

- **Endpoint only** — IP/FQDN, protocol, and port; path and future bytes remain
  mutable.
- **URL restricted** — exact method/request identity through a forced proxy;
  the same URL may still return different bytes.
- **Native integrity** — package-manager/signature evidence binds the content.
- **Reviewed replay / CAS** — serve only the reviewed captured bytes, with
  upstream networking disabled.
- **Live digest gate** — buffer the complete response and release it only after
  its reviewed identity matches.

The UI makes these mutually exclusive decisions over frozen proposals. It
cannot invent a URL or digest. A digest means “identical to the reviewed
observation,” not “known safe”; provenance, signature, SBOM, and advisory
review remain separate decisions.

The build-network evidence manifest and candidate are immutable and hash-bound.
The adjacent `build-network-policy-draft.json` is deliberately separate and
editable: operator decisions and notes may change, but its `candidateHash` and
`evidenceManifestHash` must continue to identify the exact captured inputs.
Portable review material never replaces the private evidence as authority.

Create offline SPDX SBOMs with the digest-pinned scanner. Existing
SPDX/CycloneDX JSON can be used instead. For an authoritative build/runtime
review, select exact independently reviewed tooling and UI image IDs, then let
the combined wrapper validate, compose, health-check, and open the review:

```bash
nosh review sbom --context . --image local/image:tag --output sbom-001

./setup-nosh.sh \
  --policy-tooling-image sha256:<approved-64-hex-tooling-image-id> \
  --policy-review-ui-image sha256:<approved-64-hex-review-ui-image-id>
./profile-build-and-review.sh --cache-mode cold \
  --sbom-source "$PWD/sbom-001/source.spdx.json" \
  --sbom-image "$PWD/sbom-001/image.spdx.json"
```

The wrapper rejects mutable tags and ABI mismatch, never pulls either image,
runs bundle projection with networking disabled, starts the reviewed UI and
graph server on a dedicated internal Docker bridge, inspects both current
container addresses, configures exact-origin CORS, waits for the image health
check, and opens that exact UI. It
does not trust candidate code or an arbitrary pre-existing server. Supplying no
SBOM leaves blocking coverage; `--allow-missing-sbom` is an explicit
review-only downgrade and does not permit activation.

`--runtime-candidate` points to a verified, private exported candidate laid out
as `<export-root>/<workspace-key>/<revision>/`. Its manifest, profile, policy,
image digest, workspace key, and workspace device/inode identity are verified
before composition. Build proposals remain `scopeClass: build`; composing the
two sources does not make build-time downloads runtime egress authority. Only
verified candidate rules are `scopeClass: runtime` and eligible for the
`guard-ebpf` projection.

For a later revision, select the prior frozen review with `--baseline` and
bind the verified policy leaf actually approved from that review with
`--base-policy`. Nosh verifies that the leaf descends from the selected graph;
without `--base-policy`, `basePolicyDigest` is explicitly the null-policy
digest and no deployed-policy lineage is claimed.

The following development flow is for UI development and diagnostics only; it
is not the authoritative reviewer used by `profile-build-and-review.sh`. From
the repository root on the host, recreate the development container with the
reviewer's port published only on loopback:

```console
./nosh.sh recreate --no-start-app --publish 127.0.0.1:3001
```

Then start the standalone application from `policy-review/` inside the attached
Nosh shell:

```console
cd policy-review
npm run dev
```

Stop and restart any existing development server first because its lifecycle
mode is fixed when the server process starts.

Open `http://localhost:3001/policy-review` only for development diagnostics.
Authoritative review uses the exact, health-checked UI image started by the
wrapper at the detected Docker bridge address (for example
`http://172.17.0.2:3000/policy-review`). It loads the unguessable, no-store
tokenized graph URL printed by `review serve` (or a materialized graph
JSON file). A launcher may safely deep-link the frozen graph as
`/policy-review?graph=<percent-encoded-graph-url>`. Auto-load accepts a
tokenized loopback diagnostics URL or the exact Docker `172.16/12` graph
origin attested by the managed launcher; another private or public origin is
rejected. It removes the token from browser history before fetching. Install dependencies and run other
package-manager commands only inside the development container.

The URL remains valid only while that foreground server is running. The
reviewer records `accept`, `reject`, or `needs-review` for every proposal,
supplies rationale, and acknowledges restrictive or conditional target
mappings. File and managed local URL imports are SHA-256 verified before review,
and the exact materialized graph is verified again at export. Export is a
complete `NoshPolicyDecisionSet` whose `graphContentDigest` binds every
reviewed node, observation, finding, proposal, and source field; browser layout
and view state are not part of it.

The graph and proposal list support multi-selection. Ctrl/Cmd-click toggles
nodes, observation edges, and proposals; Shift-click selects a proposal range.
Bulk dispositions require a shared rationale but still produce one decision
per proposal. **Allow selected telemetry** follows exact proposal
`observationRefs` or an unambiguous typed peer-node identity and accepts only
existing `allow` intents. It reports unlinked, ambiguous, and monitor-only
records rather than guessing a rule. This selection state is view-only and
never changes the frozen graph or its digests; restrictive and conditional
target projections retain their individual acknowledgement gates.

For a legacy operator-readable syntax aid, select accepted network proposals
and choose **Unsigned selected-rule iptables sketch**. The browser renders only
exact, static IPv4/IPv4-CIDR egress mappings whose accepted decisions include a
rationale, followed by default deny. It does not silently classify RFC1918,
DNS/DoT/QUIC ports, or any other destination as a non-reviewable invariant.
Ingress, non-network, FQDN, conditional, and unsupported mappings remain
visible but are not included. A selection spanning multiple policy subjects,
or one with missing/incomplete network coverage, produces no script.

The embedded selection manifest is machine-marked `signed: false`,
`renderOnly: true`, and `activationEligible: false`. The generated shell only
prints an `iptables-restore --noflush` payload; it never invokes a firewall or
`sudo`. This browser sketch is not a complete `NoshPolicyDecisionSet`,
`NoshPolicyIR`, target projection, approval, gateway grant, managed-DNS
configuration, or apply/verification plan. Create canonical gateway artifacts
from the complete DecisionSet with `nosh policy project`; only that server-side
target context may introduce deliberately chosen containment invariants.
`gateway-pf`, `gateway-ipfw`, and `gateway-ipfilter` projections remain
render-only themselves, but unlike the browser sketch they bind the complete
DecisionSet and PolicyIR and include gateway, DNS-table, apply, and verify
contracts.

The managed launcher uses the exact reviewed UI image, an exact CORS origin, and
the local Docker bridge address. Digest verification uses Web Crypto when the
browser exposes it and the tested in-bundle SHA-256 implementation otherwise.
The generated link is intended only for the host that owns that Docker bridge;
arbitrary container or LAN origins are rejected. For HMR or diagnostics only, an intentionally accessed
development page can allow one additional exact host before Next.js starts
inside the container:

```console
NOTTY_ALLOWED_DEV_ORIGINS=172.17.0.3 npm run dev
```

The value is a comma-separated list of exact hostnames or IP addresses; do not
include a scheme, port, path, or wildcard. Loopback hosts are allowed by
default. This escape hatch permits Next.js development resources such as HMR; it does not
make the mutable development server authoritative. Use the managed launcher for
policy review and DecisionSet export.

Bundle creation fails before writing if the materialized review would exceed
the browser contract: 25 MiB, 5,000 nodes/proposals/coverage/findings/diff
records, or 20,000 observations. Nosh does not silently truncate an
authoritative graph. Larger captures need a future, explicitly coverage-bound
aggregation/paging format before they can be approved.

Project one target at a time:

```console
nosh policy project \
  --bundle review-001 \
  --decisions decisions.json \
  --target gateway-iptables \
  --context gateway-context.json \
  --output projected-iptables
```

## Guard eBPF review and activation

The complete Guard eBPF flow is intentionally split across review,
projection, durable approval, and a short-lived single-use activation grant:

1. For the one-click workflow, `./build-nosh.sh net learn` derives the tooling
   image ID from the learned build output and builds/reuses the managed UI
   image automatically. No SHA export is required. Deployments that require
   independently pinned images can instead run `./setup-nosh.sh` with exact
   local IDs; the tooling image must carry
   `io.notty.guard.policy-tooling-abi=1`:

   ```bash
   ./setup-nosh.sh \
     --policy-tooling-image sha256:<approved-64-hex-tooling-image-id> \
     --policy-review-ui-image sha256:<approved-64-hex-review-ui-image-id>

   # Per-run overrides remain available through NOSH_POLICY_TOOLING_IMAGE and
   # NOSH_POLICY_REVIEW_UI_IMAGE; both values must still be exact local IDs.
   docker image inspect --format \
     '{{.Id}} {{index .Config.Labels "io.notty.guard.policy-tooling-abi"}}' \
     "$NOSH_POLICY_TOOLING_IMAGE"
   ```

2. Run `./profile-build-and-review.sh --cache-mode cold`. It validates both
   exact local images, snapshots any supplied SBOM files before candidate code
   runs, executes bundle projection with `--pull never` and `--network none`,
   starts the trusted tokenized graph server and a health-checked UI container
   on one dedicated internal Docker bridge, discovers their exact addresses,
   and opens the resulting `172.*` UI link. Review every proposal and export the complete
   `NoshPolicyDecisionSet` as `decisions.json`. Missing SBOM coverage blocks by
   default; `--allow-missing-sbom` is an explicit review-only downgrade and
   never makes a graph activation-eligible.

3. Put only non-secret review inputs and generated outputs below one private
   directory. Keep the two private signing keys outside that directory and
   outside each other's directories. Configure a common network-none Docker
   command; every invocation uses the reviewed tooling image, not the runtime
   candidate:

   ```bash
   # Set these three paths from the wrapper output and browser export.
   FROZEN_REVIEW_BUNDLE='/absolute/path/printed-as-Frozen-review-bundle'
   RUNTIME_TARGET_CONTEXT='/absolute/path/printed-as-Guard-eBPF-target-context'
   EXPORTED_DECISIONS='/absolute/path/to/exported-decisions.json'
   # Set these from the separately provisioned trust roles. The audiences must
   # exactly match /etc/nosh-guard/ebpf-deployment-trust.json.
   REVIEWER='<operator-reviewer-id>'
   REVIEW_AUDIENCE='notty-review-prod'
   GUARD_AUDIENCE='notty-guard-ebpf-<unique-instance-id>'
   REVIEW_PRIVATE_KEY="$HOME/.local/share/nosh/review-role/key/private.pem"
   REVIEW_PUBLIC_KEY="$HOME/.local/share/nosh/review-role/key/public.pem"
   DEPLOYMENT_PRIVATE_KEY="$HOME/.local/share/nosh/deployment-role/key/private.pem"
   POLICY_IO="$HOME/.local/share/nosh/policy-io"

   FROZEN_REVIEW_BUNDLE="$(realpath -e "$FROZEN_REVIEW_BUNDLE")"
   RUNTIME_TARGET_CONTEXT="$(realpath -e "$RUNTIME_TARGET_CONTEXT")"
   EXPORTED_DECISIONS="$(realpath -e "$EXPORTED_DECISIONS")"
   REVIEW_PRIVATE_KEY="$(realpath -e "$REVIEW_PRIVATE_KEY")"
   REVIEW_PUBLIC_KEY="$(realpath -e "$REVIEW_PUBLIC_KEY")"
   DEPLOYMENT_PRIVATE_KEY="$(realpath -e "$DEPLOYMENT_PRIVATE_KEY")"

   install -d -m 0700 "$POLICY_IO"
   cp -a -- "$FROZEN_REVIEW_BUNDLE" "$POLICY_IO/review-001"
   install -m 0600 -- "$RUNTIME_TARGET_CONTEXT" \
     "$POLICY_IO/guard-ebpf-target-context.json"
   install -m 0600 -- "$EXPORTED_DECISIONS" "$POLICY_IO/decisions.json"
   install -m 0400 -- "$REVIEW_PUBLIC_KEY" "$POLICY_IO/review-public.pem"

   POLICY_IO="$(realpath -e "$POLICY_IO")"
   case "$REVIEW_PRIVATE_KEY:$DEPLOYMENT_PRIVATE_KEY" in
     "$POLICY_IO"/*|*:"$POLICY_IO"/*) echo 'private keys must be outside POLICY_IO' >&2; exit 1 ;;
   esac

   policy_docker=(
     docker run --rm --pull never --network none
     --user "$(id -u):$(id -g)"
     --read-only --cap-drop ALL --security-opt no-new-privileges:true
     --pids-limit 64 --memory 512m --memory-swap 512m
     --tmpfs /tmp:rw,nosuid,nodev,noexec,size=67108864
     --env HOME=/tmp/nosh-policy-home
     --mount "type=bind,src=$POLICY_IO,dst=/policy-io"
   )

   paths="${XDG_CONFIG_HOME:-$HOME/.config}/nosh/paths.conf"
   GUARD_BIN="$(sed -n 's/^NOSH_GUARD_PRIVILEGED_BIN=//p' "$paths" 2>/dev/null)"
   if [[ ! -x "$GUARD_BIN" ]]; then
     prefix="$(sed -n 's/^NOSH_GUARD_PREFIX=//p' \
       /etc/nosh-guard-install-layout.conf)"
     GUARD_BIN="$prefix/bin/nosh-guard"
   fi
   test -x "$GUARD_BIN" || { echo 'installed Guard not found' >&2; exit 1; }
   ```

4. Project the accepted runtime rules using the exact target context emitted by
   the eBPF learn run:

   ```bash
   "${policy_docker[@]}" \
     --entrypoint /usr/local/bin/node \
     "$NOSH_POLICY_TOOLING_IMAGE" \
     /app/scripts/nosh-guard.mjs policy project \
     --bundle /policy-io/review-001 \
     --decisions /policy-io/decisions.json \
     --target guard-ebpf \
     --context /policy-io/guard-ebpf-target-context.json \
     --output /policy-io/projected-ebpf |
     tee "$POLICY_IO/project-result.json"
   ```

   The compiler verifies the `NoshGuardEbpfTargetContext` content hash and
   exact image/workspace/backend-object binding. It writes canonical
   `projected-ebpf/rendered/ebpf-policy.json` and prints the target-review,
   subject, and backend/subject binding digests needed below. The current
   target reports `tcpDns:false`. A projection containing an accepted FQDN
   rule therefore exits 2 and is activation-ineligible because arbitrary
   segmented/coalesced TCP DNS is not observable. **Stop here for that
   projection:** do not invoke either signing role, activation, or enforcement.
   A projection containing only literal IPv4/IPv6 CIDR rules does not depend
   on TCP DNS and may be activation-eligible when every other rule and target
   precondition is exact.

   Once the projection reports `activationEligible: true`, bind the two values
   used by the following signing steps directly from that receipt:

   ```bash
   TARGET_REVIEW_SET_DIGEST="$(
     jq -er '.targetReviewSetDigest' "$POLICY_IO/project-result.json"
   )"
   TARGET_BINDING_DIGEST="$(
     jq -er '.targetBindingDigest' "$POLICY_IO/project-result.json"
   )"
   ```

5. Only after an eligible projection, sign the durable review approval after
   inspecting that rendered leaf. This container sees the review private key
   file, but not the deployment private key:

   ```bash
   "${policy_docker[@]}" \
     --mount "type=bind,src=$REVIEW_PRIVATE_KEY,dst=/run/nosh-review-private.pem,readonly" \
     --entrypoint /usr/local/bin/node \
     "$NOSH_POLICY_TOOLING_IMAGE" \
     /app/scripts/nosh-guard.mjs review approve \
     --bundle /policy-io/review-001 \
     --decisions /policy-io/decisions.json \
     --policy /policy-io/projected-ebpf \
     --reviewer "$REVIEWER" \
     --audience "$REVIEW_AUDIENCE" \
     --key /run/nosh-review-private.pem \
     --confirmation "$TARGET_REVIEW_SET_DIGEST" \
     --output /policy-io/approval-001
   ```

6. Read the current root-owned replay state and issue a short-lived deployment
   grant. The approval's signed review audience, public review key, and grant
   audience must match Guard's reviewed root configuration. The configured
   deployment audience must be unique to this Guard instance; cloned stores
   must be reprovisioned with a new audience before any grant is issued. This second
   network-none container sees the deployment private key file, but never the
   review private key:

   ```bash
   sudo -- "$GUARD_BIN" ebpf status --json
   ACTIVE_GRANT_SET_DIGEST="$(
     sudo -- "$GUARD_BIN" ebpf status --json |
       jq -er '.activeGrantSetDigest'
   )"

   "${policy_docker[@]}" \
     --mount "type=bind,src=$DEPLOYMENT_PRIVATE_KEY,dst=/run/nosh-deployment-private.pem,readonly" \
     --entrypoint /usr/local/bin/node \
     "$NOSH_POLICY_TOOLING_IMAGE" \
     /app/scripts/nosh-guard.mjs deployment grant \
     --policy /policy-io/projected-ebpf \
     --approval /policy-io/approval-001/approval-envelope.dsse.json \
     --review-key /policy-io/review-public.pem \
     --review-audience "$REVIEW_AUDIENCE" \
     --deployment-key /run/nosh-deployment-private.pem \
     --audience "$GUARD_AUDIENCE" \
     --target-binding-digest "$TARGET_BINDING_DIGEST" \
     --active-grant-set-digest "$ACTIVE_GRANT_SET_DIGEST" \
     --ttl-seconds 3600 \
     --output /policy-io/deployment-001
   ```

7. Assemble a private import directory with this fixed layout:

   ```text
   activation-001/
   ├── policy/                         # complete projected-ebpf directory
   ├── approval-envelope.dsse.json
   └── deployment-grant.dsse.json
   ```

   ```bash
   install -d -m 0700 "$POLICY_IO/activation-001"
   cp -a -- "$POLICY_IO/projected-ebpf" \
     "$POLICY_IO/activation-001/policy"
   install -m 0600 \
     "$POLICY_IO/approval-001/approval-envelope.dsse.json" \
     "$POLICY_IO/activation-001/approval-envelope.dsse.json"
   install -m 0600 \
     "$POLICY_IO/deployment-001/deployment-grant.dsse.json" \
     "$POLICY_IO/activation-001/deployment-grant.dsse.json"
   ```

8. Import and atomically activate it through Guard's root-owned control plane:

   ```bash
   sudo -- "$GUARD_BIN" ebpf activate \
     --bundle "$POLICY_IO/activation-001" \
     --target-context "$POLICY_IO/guard-ebpf-target-context.json"
   sudo -- "$GUARD_BIN" net enforce --workdir "$PWD"
   ```

The grant is consumed once to authorize that activation transition. Guard
advances the root-owned active-grant-set digest and rejects a stale digest or
reused nonce. Grant expiry limits when activation may occur; it does not tear
down an already activated policy. Later `egress-enforce` runs consume only the
root-owned active eBPF leaf. Legacy `net approve` artifacts remain historical
and cannot authorize this backend.

The eBPF compiler emits only runtime-scoped rules. Port 53 and port 853
observations are ordinary reviewable endpoints: neither the port nor a private
address automatically makes a rule an allow or an invariant deny. Accepted
endpoint rules render only when the target can represent them exactly, while
accepted FQDN rules remain DNS-mediated through the target context's recorded
resolver set. The exact per-run platform containment endpoints cannot be
rendered as application authority. Selector-free ICMP/ICMPv6 rules preserve
empty port lists; ICMP
type/code proposals remain visible but are blocking/unsupported until the
loader ABI can enforce those selectors exactly. Multi-port FQDN transport
arrays remain intact. A target acknowledgement can document a safe restrictive
mapping, but it can never turn an omitted bypass rule into an allow.

The target context is also canonical JSON and is covered by
`targetContextDigest`. For Cilium v1, bind the exact namespace and subject
selector and assert exclusive ownership only when the operator has actually
established it:

```json
{
  "namespace": "builds",
  "name": "nosh-reviewed-policy",
  "endpointSelector": { "app.kubernetes.io/name": "builder" },
  "exclusiveOwnership": true
}
```

A caller-supplied selecting-policy inventory digest is recorded for review but
is not treated as composition proof. Until Nosh verifies the inventory
artifact and selector coverage, a non-exclusive Cilium projection remains
conditional and needs an explicit target acknowledgement. That acknowledgement
records review understanding; it does not satisfy the runtime composition
precondition, so the leaf remains activation-ineligible.

For an iptables gateway, bind the routed source, gateway/uplink topology,
backend variant, DNS upstreams, and every capability the operator has
independently verified:

```json
{
  "networkName": "build-egress",
  "sourceIpv4": "10.240.8.3",
  "gatewayIpv4": "10.240.8.2",
  "uplinkInterface": "eth0",
  "internalInterfaces": ["build0"],
  "upstreamServers": ["1.1.1.1", "9.9.9.9"],
  "iptablesVariant": "nft",
  "capabilities": {
    "connmarkAllowlist": true,
    "conntrack": true,
    "dnsmasqIpSet": true,
    "exclusiveFirewallOwnership": true,
    "ipset": true,
    "iptablesRestore": true,
    "managedDnsExclusive": true,
    "strictSourceMarking": true
  }
}
```

`guard-nftables` uses the same topology fields, omits `iptablesVariant`, and
requires `connmarkAllowlist`, `exclusiveFirewallOwnership`,
`managedDnsExclusive`, `nftAtomic`, `nftset`, and `strictSourceMarking`.
Unknown or false capabilities do not become optimistic assumptions; the
projection remains ineligible.

Generate an Ed25519 review key and sign only after reviewing the rendered leaf:

```console
nosh review keygen --output review-key
nosh review approve \
  --bundle review-001 \
  --decisions decisions.json \
  --policy projected-iptables \
  --reviewer kross \
  --audience gateway-west \
  --key review-key/private.pem \
  --confirmation sha256:TARGET_REVIEW_SET_DIGEST \
  --output approval-001
```

Review approval is durable and binds the review bundle, semantic graph,
proposal set, decisions, baseline, PolicyIR, target review, scope, review
audience, and the operator's exact confirmation. It does not itself authorize
a gateway change.
A separate deployment key issues a short-lived, audience-bound grant (maximum
24 hours):

```console
nosh gateway grant \
  --policy projected-iptables \
  --approval approval-001/approval-envelope.dsse.json \
  --review-key review-key/public.pem \
  --deployment-key deployment-key/private.pem \
  --audience gateway-west \
  --target-binding-digest sha256:... \
  --active-grant-set-digest sha256:... \
  --ttl-seconds 3600 \
  --output grant-001
```

The independent `nosh-gateway` verifier checks the policy leaf, both signature
roles, audience, expiry, gateway identity/topology, capabilities, rendered
artifact hashes, and the current active-grant-set digest before diff or apply.
Replay against a different gateway or later grant-set state fails closed.

## Canonical JSON model

The canonical bundle is `NoshReviewBundle` plus six sorted, hash-addressed JCS
NDJSON streams:

```text
review-001/
├── review-bundle.json
└── streams/
    ├── nodes.<sha256>.ndjson
    ├── observations.<sha256>.ndjson
    ├── coverage.<sha256>.ndjson
    ├── findings.<sha256>.ndjson
    ├── proposals.<sha256>.ndjson
    └── diff.<sha256>.ndjson
```

The materialized UI envelope is:

```json
{
  "apiVersion": "notty.dev/v1alpha1",
  "kind": "NoshSemanticGraph",
  "schemaVersion": 1,
  "graphId": "graph:<sha256>",
  "revision": "sha256:<bundle>",
  "graphDigest": "sha256:<semantic-graph>",
  "proposalSetDigest": "sha256:<proposal-set>",
  "basePolicyDigest": "sha256:<base-policy-or-null>",
  "scope": { "class": "build", "subjectId": "subject:<sha256>", "scopeDigest": "sha256:<scope>" },
  "sources": [],
  "nodes": [],
  "observations": [],
  "coverage": [],
  "findings": [],
  "proposals": [],
  "diff": [],
  "frozen": true,
  "contentDigest": "sha256:<exact-materialized-envelope>"
}
```

Every observation states whether its basis is `observed`, `correlated`, or
`inferred`, includes confidence and evidence references, and stays inside one
build or runtime scope. Coverage is first-class; missing or lossy telemetry is
never represented as a clean empty graph. Stable IDs are derived from semantic
keys. A proposal may carry sorted `observationRefs` that bind it to the exact
observations from which it was derived; materialization rejects dangling
references. `graphDigest` and `proposalSetDigest` authenticate the corresponding
hash-addressed streams, while `contentDigest` authenticates the complete
materialized JSON envelope. `NoshPolicyDecisionSet.graphContentDigest` and
`NoshPolicyIR.graphContentDigest` carry that exact snapshot identity through
projection, preventing a graph or proposal body from being substituted while
retaining stale semantic IDs. Decision, IR, target, and bundle digests bind
the remaining successive review layers.

The normative schemas are under
`config/nosh-guard/schemas/review/`. Important kinds are:

| Kind | Purpose | Authority |
| --- | --- | --- |
| `NoshReviewBundle` | Source and stream manifest | Frozen evidence projection |
| `NoshSemanticGraph` | Materialized reviewer/API view | Non-executable |
| `NoshPolicyDecisionSet` | Complete proposal dispositions and rationale | Review input |
| `NoshPolicyIR` | Accepted typed intents with default deny | Compiler input |
| `NoshTargetReviewSet` | Per-rule parity and rendered artifact hashes | Target review |
| `NoshReviewApprovalStatement` | Durable DSSE review signature payload | Approval |
| `NoshPolicyLeafBundle` | Independently transferable target artifact set | Deployment input |
| `NoshGatewayGrantStatement` | Short-lived DSSE deployment authorization | Activation grant |

Renderer/ReactFlow coordinates, lane collapse, viewport, focus, and animation
belong to `NoshGraphViewState`, keyed by graph digest and renderer version.
They never change graph or policy digests. Generic graph mutations are not
policy edits; multi-selection only resolves and decides typed proposals already
present in the authenticated proposal stream.

### Temporal review

The standalone reviewer derives a view-only timeline from strict observation
and source time bounds. Play, pause, rewind, playback speed, cumulative/window
mode, and domain selection affect only the graph projection; they never alter
the frozen graph, proposal set, DecisionSet, or approval digests. Untimed
records remain explicit context instead of being assigned an invented time.

Build evidence has mixed temporal precision. Process execution can be an exact
point, while DNS, network, and filesystem records are commonly aggregate
first/last windows. Syscall summaries and some structural relationships have
no occurrence time. The UI therefore labels point, interval, and untimed data
and does not claim call-by-call replay. Exact replay requires a separate
bounded, hash-addressed occurrence stream in a future review schema.

## Live Hubble and other telemetry

Live Hubble JSONL may be adapted into the same visual language for exploration,
but remains unfrozen and non-authoritative. It cannot be approved directly.
Guard must ingest it as a bounded source, record loss/filters/time bounds,
freeze hash-addressed records, and materialize a new graph revision first.
Browser-applied live deltas are still integrity checked: JCS SHA-256 binds each
upsert and the complete delta, removals bind the current record, sequence and
previous-delta links reject replay, and per-source watermarks must advance.
These checks make the visualization trustworthy without promoting live input
to approvable evidence.

Build and runtime scopes are never silently merged. Current build profiles use
Nosh Build/Nosh L4 plus BuildKit/Buildx/cgroup evidence. Tetragon and Hubble are
runtime sources unless a future build adapter explicitly captures and binds
them. Build DNS v2 and optional libcurl resource edges must say which algorithm
and source produced them. A bounded same-process/host/port/time correlation is
useful review evidence, but is not proof that a later IP connection used that
answer or resource and never authorizes a rule by itself.

## Target behavior

- Cilium emits a namespaced `CiliumNetworkPolicy`. Exact parity in v1 requires
  exclusive selector ownership. A caller-supplied inventory digest is retained
  for review but is not verified as complete composition evidence; without
  exclusive ownership the union of Kubernetes/Cilium policies remains
  conditional and activation-ineligible.
- Guard nftables emits nftables plus strict managed-dns configuration. FQDN
  activation requires connmark allowlisting, strict source marking, managed DNS
  exclusivity, nftset support, and atomic nft transactions.
- Gateway iptables emits versioned ipsets, `iptables-restore` input, strict
  managed-dns configuration, an apply plan, and a verification plan. It requires
  ipset, conntrack, dnsmasq ipset/connmark support, and a bound legacy-or-nft
  iptables variant.
- `gateway-pf`, `gateway-ipfw`, and `gateway-ipfilter` emit deterministic,
  backend-native NAT/gateway previews from the same reviewed PolicyIR. Their
  target contexts bind the platform (`openbsd`, `freebsd`, or
  `illumos`/`netbsd`), routed source, gateway address, and uplink. Every bundle
  includes a canonical `gateway-policy.json`, a fail-closed DNS-table contract,
  and an apply plan. These v1 projections are deliberately render-only and
  always activation-ineligible until a native syntax validator, quarantine
  installer, transactional loader, and live-state verifier exist on that OS.
  Literal IPv4 TCP/UDP mappings have exact projection parity. FQDN mappings are
  conditional on a TTL-aware managed table updater whose failure leaves the
  table empty; unsupported directions, address families, or protocols remain
  explicit and are never omitted as if they had been enforced.
  The PF leaf contains `pf.anchor.conf`; IPFW contains `ipfw.rules` and
  `ipfw-nat.conf`; IPFilter contains `ipf.conf`, `ipnat.conf`, and
  `ippool.conf`. All three also contain `gateway-policy.json`,
  `dns-tables.json`, `apply-plan.json`, and `verify-plan.json`.
- `gateway-l7-proxy` emits one composite, digest-bound preview: a workload
  network leaf that permits only the fixed proxy endpoint, a distinct
  proxy-source leaf for reviewed origins, an exact HTTP proxy policy, optional
  selected CAS manifest, topology, and composite apply/verify plans. Direct
  workload TCP on every reviewed HTTP origin port, direct TCP 80/443, and UDP
  on the corresponding web/QUIC ports are classified as bypass conflicts.
  The compiler supports the managed mitmproxy provider; Burp remains import
  context. This v1 target is deliberately render-only and activation-ineligible
  until a host actuator can atomically quarantine, apply, and verify both
  network identities and the content gate.

A render-only target context is deliberately small and target-bound:

```json
{
  "target": "gateway-pf",
  "platform": "openbsd",
  "networkName": "review-net",
  "sourceIpv4": "10.240.8.3",
  "gatewayIpv4": "10.240.8.2",
  "uplinkInterface": "em0",
  "capabilities": {}
}
```

Use it with `nosh policy project --target gateway-pf`. Substitute the matching
target/platform pair for `gateway-ipfw`/`freebsd` or
`gateway-ipfilter`/`illumos` (`netbsd` is also accepted). A successful export
returns zero and reports `renderOnly: true` with `activationEligible: false`;
the new private output directory contains the immutable export for review but
cannot be used to request a deployment grant.

After an HTTP assurance proposal has complete independent network provenance,
project the composite target with two distinct routed identities. This
iptables example is intentionally verbose: every `true` is an operator-bound
deployment capability, not a compiler assumption.

```json
{
  "target": "gateway-l7-proxy",
  "networkBackend": "gateway-iptables",
  "provider": "mitmproxy",
  "proxyEndpoint": { "ipv4": "10.240.8.9", "port": 8080 },
  "workloadNetwork": {
    "target": "gateway-iptables",
    "networkName": "review-workload",
    "sourceIpv4": "10.240.8.3",
    "gatewayIpv4": "10.240.8.2",
    "uplinkInterface": "eth0",
    "iptablesVariant": "nft",
    "internalInterfaces": ["review0"],
    "upstreamServers": ["1.1.1.1"],
    "capabilities": {
      "connmarkAllowlist": true,
      "conntrack": true,
      "dnsmasqIpSet": true,
      "exclusiveFirewallOwnership": true,
      "ipset": true,
      "iptablesRestore": true,
      "managedDnsExclusive": true,
      "strictSourceMarking": true
    }
  },
  "proxyNetwork": {
    "target": "gateway-iptables",
    "networkName": "review-proxy",
    "sourceIpv4": "10.240.8.9",
    "gatewayIpv4": "10.240.8.2",
    "uplinkInterface": "eth0",
    "iptablesVariant": "nft",
    "internalInterfaces": ["review0"],
    "upstreamServers": ["1.1.1.1"],
    "capabilities": {
      "connmarkAllowlist": true,
      "conntrack": true,
      "dnsmasqIpSet": true,
      "exclusiveFirewallOwnership": true,
      "ipset": true,
      "iptablesRestore": true,
      "managedDnsExclusive": true,
      "strictSourceMarking": true
    }
  },
  "capabilities": {
    "completeCapture": true,
    "directWebDeny": true,
    "forcedRouting": true,
    "proxyPolicyAtomic": true,
    "quicDeny": true,
    "tlsInterception": true
  }
}
```

```bash
nosh policy project \
  --bundle review-001 \
  --decisions decisions.json \
  --target gateway-l7-proxy \
  --context gateway-l7-proxy-context.json \
  --output projected-l7
```

For a selected CAS-replay variant, the target context additionally includes
the exact private `contentManifest` document and its `contentManifestDigest`.
The compiler verifies membership for the selected request and response before
including `http-content-manifest.json`. It never accepts a digest without the
corresponding normalized manifest.

The portable intent contains exact FQDNs or IPv4/CIDRs, protocols, numeric
ports, and ICMPv4 type/code. It never promotes a transient address into an
FQDN identity: an accepted observed `/32` remains that exact, capture-specific
IP rule. Wildcard FQDNs and IPv6 activation are unsupported in v1. File,
process, and syscall proposals are review previews in build v1 and have no
silent network-backend translation.

iptables/ipset/dnsmasq do not share one transaction. The external gateway
therefore installs a source quarantine first and retains it on any failed
validation or apply phase. Only a fully verified live state removes the
quarantine. This makes a separate bare-metal gateway possible without treating
the build host's generated rules as self-authorizing.

The gateway topology must make bypass impossible: the reviewed workload uses
the managed gateway as its only default route, forwarding is enabled only on
that gateway, the dedicated ruleset defaults to deny for the bound source, and
NAT occurs only after the reviewed forwarding decision. Exact HTTP/HTTPS URL
paths are outside every L3/L4 firewall projection. Enforcing them requires a
separately reviewed forced-proxy policy plus firewall rules that deny direct
web egress. Nosh's managed reference provider is mitmproxy. Burp can be
imported for human review but is not launched, bundled, or accepted as a
managed completeness source. Proxy observations alone never prove network
reachability.

## SBOM generation

`config/nosh-review/tools.json` pins Syft by OCI digest. Generation runs in an
offline, unprivileged container: source is mounted read-only and final-image
scanning uses a local `docker image save` archive, not the Docker socket inside
the scanner. Checksums prove integrity, not provenance; use a reviewed checkout
and reviewed pinned image update. Imported SPDX JSON and CycloneDX JSON remain
supported for systems that already produce SBOMs.
