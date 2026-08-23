# Nosh managed HTTP capture contract

The managed HTTP collector is an independent observational/content-assurance
stream. It does not replace cgroup-scoped eBPF network evidence and must not be
used to invent DNS or socket correlations.

## Managed runtime

Run the wrapper inside exactly this pinned image:

```text
mitmproxy/mitmproxy:12.2.3@sha256:00b77b5d8804c8ad18cb6caefbf9d5849e895e8986c5ce011f4ae30f4385962f
```

The wrapper interface is:

```text
scripts/nosh-mitmproxy-capture.sh \
  --run-id RUN_ID \
  --run-root /private \
  --evidence /private/evidence/http.ndjson \
  --cas-root /private/http-cas \
  --mode observe|offline-replay|live-buffer-verify \
  --image-digest sha256:00b77b5d8804c8ad18cb6caefbf9d5849e895e8986c5ce011f4ae30f4385962f \
  --addon-digest sha256:ADDON_FILE_DIGEST \
  --wrapper-digest sha256:WRAPPER_FILE_DIGEST \
  [--content-manifest /private/review/http-content-manifest.json] \
  [--listen-host 127.0.0.1] [--listen-port 8080] \
  [--confdir /private/mitmproxy-conf] \
  [--max-body-bytes 536870912] \
  [--max-cas-bytes 8589934592] [--max-cas-objects 10000]
```

`--content-manifest` is forbidden in `observe` and required in both enforcement
modes. Response buffering has a 512 MiB hard ceiling; a smaller per-run ceiling
may be selected with `--max-body-bytes`. The wrapper passes only these private
environment values to the addon:

- `NOSH_HTTP_RUN_ID`
- `NOSH_HTTP_RUN_ROOT`
- `NOSH_HTTP_EVIDENCE_PATH`
- `NOSH_HTTP_CAS_ROOT`
- `NOSH_HTTP_CAPTURE_MODE`
- `NOSH_HTTP_CONTENT_MANIFEST` in a reviewed enforcement mode
- `NOSH_HTTP_MAX_BODY_BYTES`
- `NOSH_HTTP_MAX_CAS_BYTES`
- `NOSH_HTTP_MAX_CAS_OBJECTS`
- `NOSH_HTTP_COLLECTOR_IMAGE_DIGEST`
- `NOSH_HTTP_COLLECTOR_ADDON_DIGEST`
- `NOSH_HTTP_COLLECTOR_WRAPPER_DIGEST`

`--run-root` is an explicit mode-0700, owner-controlled containment boundary.
The evidence file, CAS root, confdir, and reviewed manifest must be strict
children of that boundary. Filesystem root, symlinked ancestors, and broad
system directories are rejected before any mkdir or chmod.

The three collector digests are mandatory. The image digest must equal the pin
above, and the wrapper verifies the mounted addon and itself before starting
mitmdump. Terminal stats repeat all three values; managed source validation
requires the orchestrator's independently computed expected identity.
Before creating the capture network, the manager verifies that this exact image
reference already exists in the local Docker image store. The managed run uses
`--pull=never`; image acquisition is never part of a measured build.

The wrapper creates a mode-0700 mitmproxy confdir (by default
`CAS_ROOT/mitmproxy-conf`). The orchestrator must wait for the public CA at
`CONFDIR/mitmproxy-ca-cert.pem` before starting BuildKit, and may mount only
that public certificate into the workload. The CA private key remains inside
the private confdir.

The process exits nonzero on addon initialization or normalization failures.
The orchestrator must treat unexpected process exit, absent terminal stats, or
an incomplete terminal stats record as incomplete evidence.

## Output and completion

The addon creates private mode-0600 NDJSON with exclusive-create semantics,
matching
`config/nosh-guard/schemas/http-exchange-evidence.schema.json`. It writes
mode-0400 response objects below `CAS_ROOT/objects/sha256/`. In observe mode it
also atomically publishes a mode-0400 immutable full capture manifest below
`CAS_ROOT/manifests/` when at least one response is safely replayable. Query
values, credentials, cookies, exact redirect locations, and raw provider
identifiers never enter normalized NDJSON; exact request targets and exact raw
Location header values are bound by digest. A redirect's resolved/sanitized URL
is display-only.

Each managed request record includes the private downstream tuple
`clientAddress:clientPort -> proxyAddress:proxyPort`. Correlate that exact tuple,
pass, and timestamp with independently collected eBPF L4 evidence to prove that
the build used the managed proxy. This downstream tuple does not attest the
proxy-to-origin route: it is published only as `destinationRole:
workload-to-proxy`, which Review treats as a non-authoritative correlation and
never as origin authority. Until a separately scoped proxy-leg eBPF collector
attests that route, capture reports `managed HTTP origin route lacks independent
proxy-leg L4 provenance` and remains incomplete. Provider-observed
`upstreamDestination` also remains non-authoritative. Private source tuples are
omitted from portable review data.

Exactly one `http-capture-stats` record must be the final NDJSON record.
Capture is complete only when all of these hold:

- `complete` is true;
- `captureAuthority` is `managed`;
- `captureMode` is `managed-proxy`;
- `coverageGaps` is empty;
- `errors`, `incompleteBodies`, and `droppedRecords` are zero;
- the mitmdump process exits successfully.

After reading and validating the private file, the orchestrator creates the
ordinary build source descriptor with:

```js
createHttpEvidenceSourceDescriptor({
  file: 'raw/http.ndjson',
  content: privateNdjsonBuffer,
  required: true,
  expectedCollectorIdentity: {
    collectorImageDigest,
    collectorAddonDigest,
    collectorWrapperDigest,
  },
})
```

The returned descriptor retains the private `content` buffer so it can be
passed directly in `BuildProfileStore.finalizeRun({ sources })`. It is named
`http`, uses `format: 'ndjson'`, binds byte and record counts plus SHA-256, and reports either
`nosh-http-capture-complete` or `nosh-http-capture-incomplete`. When managed
HTTP capture is requested, `http` must be added to the build run's required
sources; it must remain absent when basic learn is selected.

The managed orchestration interface is:

```js
const session = await startManagedHttpCapture({
  runId, bundleDir, dockerfile, scriptsDirectory,
});
const buildInputs = managedHttpBuildOptions(session);
const { records, source, contentManifest, contentManifestPath } =
  await stopManagedHttpCapture(session);
const http = correlateManagedHttpEvidence(records, {
  networkAttempts,
  proxyIpv4: session.proxyIpv4,
  proxyPort: session.proxyPort,
  contentManifest,
});
cleanupManagedHttpCaptureNetwork(session);
```

`source` already retains its private NDJSON `content` for source
materialization. `contentManifest` is the verified full private capture index;
`contentManifestPath` names its immutable store object. Correlation adds CAS
membership only after the manifest entry, normalized response (including exact
raw Location digest), and stored object all verify. Cleanup errors retain exact
container/network identifiers on `error.managedHttpResources` for bounded
operator recovery.

## Content modes and imports

- `observe` never accepts or applies a policy. It records exchanges and stores
  fully observed, bounded, non-range response bytes by content digest only when
  the request is not credentialed and its request identity is unambiguous.
  HEAD, interim 1xx, partial 206, and 304 responses are not replay candidates
  because they do not bind one complete terminal representation and its length.
  A generic 1xx/upgrade is also a blocking capture gap and cannot create HTTP
  authority; it is not treated as an ordinary URL-restricted exchange.
  Per-run CAS persistence is
  capped at 8 GiB and 10,000 objects (and can be lowered); exceeding either
  quota records `cas-quota-exceeded` without failing the observational stream.
- `offline-replay` refuses upstream response bodies and returns only a verified
  object named by the reviewed manifest.
- `live-buffer-verify` buffers the complete upstream body and releases it only
  after its status, size, and digest match the reviewed manifest.

`coverageGaps` describes capture/routing loss and alone controls HTTP capture
`complete`. `contentAssuranceGaps` separately describes responses that cannot
enter CAS/native-integrity assurance (credentials, interim/partial responses, ambiguity,
oversize, or incomplete bodies). Those content gaps remain visible without
erasing an otherwise exact URL observation.

Managed NDJSON is capped at 128 MiB and 1,000,000 records. The producer keeps
64 KiB and one record in reserve for terminal stats; reaching either bound
fails the proxy closed and records `dropped-records`/`provider-loss` instead of
writing an artifact that the manager cannot safely ingest.

`normalizeBurpHarImport()` accepts a private in-memory HAR document and emits
the same normalized record types, but permanently marks every record and its
terminal stats as `review-only` / `manual-import`. Manual Burp exports can aid
review but can never satisfy managed-capture completeness. Imports are capped
at 100,000 exchanges and 64 MiB for each decoded request or response body.
