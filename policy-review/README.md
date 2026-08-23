# Nosh Policy Review

This standalone Next.js application renders frozen Nosh semantic graphs as an
eight-lane UML-style policy review. It imports the exact URL printed by
`nosh review serve`, local `NoshSemanticGraph` JSON, preview-only Hubble JSONL,
and integrity-chained live deltas. It exports a digest-bound
`NoshPolicyDecisionSet`; signing and policy compilation remain outside the
browser.

## Authoritative use

Do not use an arbitrary development server for a policy decision. The
repository's authoritative handoff requires
`NOSH_POLICY_REVIEW_UI_IMAGE=sha256:<approved-image-id>`, verifies
`io.notty.policy-review.ui-abi=1`, starts that exact image with `--pull never`,
places it and the trusted graph server on one dedicated internal Docker
bridge, inspects both current addresses, waits for the container health check,
and opens the dynamically attested `172.*` link:

```console
./profile-build-and-review.sh --cache-mode cold
```

The wrapper prints separate stop commands for the reviewed UI and graph
containers.

## Development

From the repository root on the host, recreate the Nosh development container
with the reviewer's port published only on loopback:

```console
./nosh.sh recreate --no-start-app --publish 127.0.0.1:3001
```

Then, inside the attached Nosh shell, start the standalone application:

```console
cd policy-review
npm run dev
```

Development defaults to loopback origins. Set `NOTTY_ALLOWED_DEV_ORIGINS` to
the exact additional development hostname or IP when diagnostics require one;
the managed production launcher does not use this development escape hatch.

Stop and restart any existing development server before using this command;
the lifecycle mode is fixed when the server process starts.

Open `http://localhost:3001/policy-review`. This mutable development server is not an
authoritative policy reviewer, regardless of which address opens it. The managed
launcher uses the exact reviewed UI image and verifies graph and decision digests
with Web Crypto when available or the tested in-bundle SHA-256 fallback on its
local Docker bridge origin.

Run all other package-manager commands inside a Nosh or other development
container as well:

```console
npm ci --include=dev
npm run test:run
```

For HMR or diagnostics only, Next.js development resources can accept another
exact host. Set only the host or IP before startup:

```console
NOTTY_ALLOWED_DEV_ORIGINS=172.17.0.3 npm run dev
```

This escape hatch only enables development resources; it does not make the mutable
development server authoritative. Use the managed launcher for policy review and
DecisionSet export.

For an isolated development build:

```console
docker build -t nosh-policy-review .
docker run --rm -p 127.0.0.1:3000:3000 nosh-policy-review
```

The container build runs the standalone test suite and production build before
copying only production dependencies and `.next` output into the runtime stage.
Review and record its exact image ID before configuring it as the authoritative
UI; never configure the mutable tag shown in this development example.

## Temporal review

The timeline is a non-authoritative view over the frozen semantic graph. Use
its playhead, playback rate, cumulative/window mode, and domain filters to see
when captured relationships became relevant without changing the graph or any
policy decision digest. Process events may be exact points; DNS, network, and
filesystem evidence is commonly represented as an aggregated first/last
observation window. Untimed evidence remains visible and is labeled as such.

The timeline does not claim call-by-call replay. Exact occurrence playback
requires a future bounded, digest-bound temporal evidence stream rather than
reconstructing events from aggregate counts.

## Selecting policy

Ctrl/Cmd-click graph nodes, observation edges, or proposal nodes to build a
multi-selection. Shift-click proposals in the proposal list to select a range,
or use **Select all**. A required shared rationale can then apply Accept,
Reject, or Needs review to the selected proposals.

**Allow selected telemetry** resolves selected observation edges through their
exact `observationRefs`, and selected endpoint nodes through an unambiguous
typed peer identity. It accepts only existing digest-bound proposals whose
effect is `allow`. Unlinked, ambiguous, or monitor-only telemetry is reported
and left unchanged; the browser never manufactures a broader rule or mutates
the frozen graph. Restrictive or conditional target mappings still require
their individual projection acknowledgement.

**Unsigned selected-rule iptables sketch** is a legacy, operator-readable
syntax aid for accepted, exact, static IPv4/IPv4-CIDR egress proposals in the
current selection. It renders only those selected rules followed by default
deny; it does not invent RFC1918, DNS-port, or other containment invariants.
Unsupported, FQDN, ingress, restrictive, and unaccepted proposals remain
visible instead of being silently omitted. The downloaded shell script only
prints deterministic `iptables-restore --noflush` input and never calls a
firewall, privilege, or Nosh activation command.

The embedded manifest marks the artifact as an unsigned, render-only,
activation-ineligible browser sketch. It is not a DecisionSet, PolicyIR, or
target projection. Use the complete canonical DecisionSet and server-side
gateway compiler for `gateway-iptables`, `gateway-pf`, `gateway-ipfw`, or
`gateway-ipfilter`; only explicit target context may define non-reviewable
containment invariants or managed-DNS behavior. Approval, grant, and live
verification remain separate enforcement steps.

## Load a Nosh review

The application uploads a materialized `NoshSemanticGraph`, not a raw build
profile directory. Convert a verified private profile into a review bundle,
then either upload its materialized JSON or serve the graph on loopback:

```console
nosh review bundle \
  --profile "$PROFILE" \
  --sbom-source sbom-001/source.spdx.json \
  --sbom-image sbom-001/image.spdx.json \
  --output review-001

nosh review inspect \
  --bundle review-001 \
  --json > review-001.graph.json
```

Choose **Open graph** and select `review-001.graph.json`. For visualization
only, `nosh review bundle --allow-missing-sbom` preserves explicit missing-SBOM
coverage; it does not make that degraded review eligible for approval.

The URL alternative is:

```console
nosh review serve --bundle review-001 --origin http://localhost:3001
```

Choose **Open URL** in the application and paste the unguessable loopback URL
printed by the command. Live Hubble imports remain non-authoritative and cannot
be exported as an approvable DecisionSet until Guard freezes them into a new
review bundle.

To compare a package change, create the second bundle with
`--baseline review-001`. Only activity that executes during the new capture can
appear in the graph; a build profile does not continue watching the project
after it finishes. The root README's
[package-request walkthrough](../README.md#prove-that-a-newly-added-package-request-is-observed-and-denied)
shows the complete baseline, recapture, selection, and enforcement boundary.

The canonical formats and end-to-end approval/gateway workflow are documented
in `../docs/nosh-policy-review.md`.
