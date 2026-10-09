# Notty Workflows

## Split-auth local MCP testing

### Goal

Run Notty on host loopback with these independent boundaries:

| Surface | Required authorization |
| --- | --- |
| Browser UI, REST APIs, and terminal WebSocket | HTTP Basic Auth |
| MCP Streamable HTTP and SSE transports | No Authorization header |
| Terminal creation through MCP | One-time spawn OTP |
| Browser OTP management | HTTP Basic Auth |

This is a trusted-workstation test mode. An unauthenticated MCP client can use
every MCP tool that does not require a spawn OTP, including tools that inspect
or control existing terminals. The OTP protects terminal creation; it is not a
general MCP authorization mechanism. This mode must therefore remain restricted
to an explicitly published host-loopback listener and must not be available in
Guard mode.

### Current status

The launcher cannot express this matrix yet:

- the default mode uses OAuth Bearer for MCP, Basic Auth for the browser, and a
  spawn OTP;
- `--no-oauth` disables OAuth but makes MCP fall back to Basic Auth;
- `--no-otp-auth` makes MCP credentialless and retains spawn OTP enforcement,
  but also disables Basic Auth for the browser.

Do not use either existing flag as if it implemented the target workflow.

### Proposed launcher contract

Add an explicit `--no-mcp-auth` mode rather than changing the established
meaning of `--no-oauth`:

```sh
cd /path/to/project
nosh recreate \
  -p codex \
  --start-app \
  --persist \
  --publish 127.0.0.1:3000 \
  --no-mcp-auth
```

Expected launcher state:

```text
Basic browser authentication: enabled
MCP OAuth/Bearer/Basic authentication: disabled
Terminal spawn OTP: enabled
Exposure: host loopback only
```

The launcher should generate and reveal the Basic credential and initial spawn
OTP once, as it does in the default mode. Neither secret may appear in Docker
arguments, logs, child environments, URLs, or MCP configuration.

### Implementation checklist

- [ ] Add `--no-mcp-auth` to Nosh argument parsing, help, completion, and dry-run
      output.
- [ ] Represent MCP transport authentication independently from
      `basicEnabled` and `oauthEnabled`; use an explicit transport mode such as
      `oauth`, `basic`, or `none`.
- [ ] In `none` mode, mount `/mcp`, `/api/mcp`, `/sse`, and MCP message routes
      without Bearer or Basic middleware.
- [ ] Keep the ordinary browser `GET /mcp`, UI pages, REST routes, and terminal
      WebSocket upgrades behind Basic Auth.
- [ ] Keep `NOTTY_MCP_SPAWN_OTP_ENABLED=true` and reject any combination of
      `--no-mcp-auth` with `--no-otp`.
- [ ] Keep browser OTP status and minting behind Basic Auth. Continue to support
      local one-time minting with `nosh auth otp`.
- [ ] Require an explicit loopback publication such as
      `--publish 127.0.0.1:3000`; reject host networking, wildcard publication,
      non-loopback public origins, and Guard mode.
- [ ] Ensure child agent, Copilot, Collab, and terminal environments receive no
      Basic credential, MCP Authorization value, or plaintext spawn OTP.
- [ ] Log only the resolved mode and OTP lifecycle metadata, never reusable
      credential values.

### Deterministic acceptance tests

- [ ] The launcher auth matrix resolves to Basic enabled, OAuth disabled, MCP
      transport auth `none`, and spawn OTP enabled.
- [ ] An MCP request without an Authorization header reaches `/mcp` and
      `/api/mcp` on loopback.
- [ ] Supplying an unnecessary or malformed Authorization header cannot widen
      MCP authority.
- [ ] An ordinary browser request to `/`, `/mcp`, or a REST API receives a Basic
      challenge without valid credentials and succeeds with valid credentials.
- [ ] A terminal WebSocket upgrade fails without valid Basic credentials.
- [ ] An unauthenticated MCP spawn without an OTP fails closed.
- [ ] A valid OTP authorizes exactly one spawn, and replay or mutation fails.
- [ ] Non-spawn MCP tools are explicitly tested as unauthenticated so the risk
      is visible rather than accidental.
- [ ] Non-loopback publication and `--network host` fail before Docker starts.
- [ ] `--no-mcp-auth --no-otp` and Guard combinations fail during argument
      validation.
- [ ] Logs, dry-run output, child environments, and dashboard responses contain
      no plaintext Basic password or spawn OTP.

### Manual test workflow after implementation

1. Launch with the proposed command and confirm the printed endpoint is
   `http://127.0.0.1:3000`.
2. Open the web UI and confirm the browser requires the generated Basic
   credential.
3. Register MCP without a login or Authorization header:

   ```sh
   codex mcp add notty --url http://127.0.0.1:3000/mcp
   codex mcp get notty
   ```

4. Confirm a non-spawn MCP tool works without `codex mcp login`.
5. Confirm terminal spawn fails when `otp` is omitted or incorrect.
6. Supply the launcher's OTP only as the spawn tool's `otp` argument and confirm
   one terminal is created.
7. Replay the same OTP and confirm it is rejected.
8. Mint a replacement locally, then repeat the one-use and replay checks:

   ```sh
   cd /path/to/project
   nosh auth otp
   ```

9. Confirm the browser remains Basic-protected while MCP remains connected
   without login.
10. Stop and recreate the service, then verify consumed OTPs remain unusable and
    no credential values appear in logs or retained container configuration.

## Connect a Terminal Copilot

### Goal

Bind one visible Copilot agent to one running terminal so it can inspect that
terminal's bounded context, answer questions about selected output, and offer
only the level of terminal control chosen by the operator.

The Copilot connection is separate from the public MCP authentication mode.
Notty creates a private, binding-specific MCP broker and a time-limited access
lease for the agent. The agent is permanently associated with the selected
source terminal's UUID; it does not receive the browser Basic credential, a
public MCP credential, or a spawn OTP.

### Runtime prerequisites

Choose and prepare one supported agent runtime before launching Notty:

| Agent | Prerequisite | Default lease |
| --- | --- | --- |
| Codex | Launch Nosh with the `codex` profile and working Codex credentials | 1 hour |
| Agy | Launch Nosh with the appropriate Gemini/Antigravity state available | 1 hour |
| Ollama | Reachable Ollama host, installed tool-capable model, and the Codex executable | 8 hours |

For a Codex-backed Copilot, the ordinary local launch shape is:

```sh
cd /path/to/project
nosh recreate \
  -p codex \
  --start-app \
  --persist \
  --publish 127.0.0.1:3000
```

When the split-auth workflow above is implemented, `--no-mcp-auth` may be added
to this command. It is not required for Terminal Copilot: the Copilot uses its
own private broker capability rather than the public `/mcp` authorization.

### Connect the Copilot

1. Open the Notty web interface and authenticate with the browser Basic
   credential.
2. Create a terminal or select an existing live terminal tab. The selected
   terminal becomes the Copilot's source terminal.
3. Select **Copilot** in the top toolbar. If the pane was previously collapsed,
   expand the **Copilot** rail on the right.
4. In **Copilot configuration**, select the agent and model. An unavailable
   runtime is shown as unavailable and cannot be launched.
5. Start with **Observe: Passive** and **Terminal control: Off**. These are the
   safest settings for verifying the connection.
6. Select **Launch copilot**. Wait for the pane header to show the runtime,
   `running`, and the correct terminal number.
7. Confirm that the embedded **Agent terminal** starts and that the access lease
   is active.
8. Highlight a short region of output in the source terminal. Enter a question
   under **Ask about this terminal**, then press Ctrl+Enter or select **Ask**.
9. Verify the response refers to the selected source terminal and does not type
   into it while terminal control is **Off**.

Only one Copilot can be bound to a source terminal at a time. Selecting another
terminal changes the pane context; it does not silently move an existing
binding to the new terminal.

### Observation and terminal-control modes

| Setting | Behavior |
| --- | --- |
| Observe: Passive | Responds to explicit questions without automatic terminal analysis |
| Observe: Active | Watches terminal activity for failures and optional idle tips |
| Control: Off | Cannot submit commands to the source terminal |
| Control: Insert | May place command text at a ready prompt but cannot press Enter |
| Control: Approve | Creates a proposal that runs only after **Approve & run** |
| Control: Autonomous | May type commands and press Enter until its visible lease expires |

Use **Insert** or **Approve** before considering **Autonomous**. Notty requires a
separate confirmation when Autonomous mode is enabled. A command is held rather
than inserted or executed when the source terminal is not at a known-ready
prompt or is using an alternate screen.

Active observation can generate failure analysis and periodic tips. Set
**Tips** to **Off** initially, then choose an interval only after confirming the
agent is observing the intended terminal.

### Lease, pop-out, and shutdown behavior

- Remote-agent leases for Codex and Agy last one hour; the local Ollama lease
  lasts eight hours. Use **Renew** deliberately when continued access is needed.
- Renewing an Autonomous visible lease requires the operator to confirm
  Autonomous control again.
- **Pop out** moves the Copilot pane to a separate browser window while keeping
  the same exact source-terminal UUID. **Dock** returns it to the main UI.
- **Stop copilot** stops its managed agent terminal and revokes its access while
  leaving the source terminal open.
- Exiting the source terminal stops only the Copilot bound to that source.

### Manual connection smoke test

- [ ] The pane reports the expected source terminal number and runtime.
- [ ] A highlighted-output question produces a relevant response.
- [ ] Control **Off** prevents command submission.
- [ ] **Insert** stages text without a carriage return at a ready shell prompt.
- [ ] **Approve** displays a pending proposal and runs it only after explicit
      approval.
- [ ] Autonomous mode presents a confirmation and stops working after lease
      expiry or revocation.
- [ ] Switching tabs does not rebind the original Copilot.
- [ ] Pop-out and dock preserve the exact source terminal.
- [ ] Stopping the Copilot leaves the source terminal running.
- [ ] No Basic password, public MCP authorization value, or spawn OTP appears in
      the agent terminal or its environment.

## Test Collab and each agent's OTP boundary

### Goal

Launch a browser-managed Collab roster, verify every configured agent and its
terminal independently, and confirm that no managed agent inherits or consumes
the operator's terminal-spawn OTP.

Managed Collab agents do **not** have individual spawn OTPs. Their detached tmux
sessions are created by the trusted Collab supervisor rather than through the
public terminal-spawn API. Delivering a launcher OTP to an agent is explicitly
unsupported. If a future workflow lets an agent call the public spawn tool, the
operator must mint a fresh OTP for that one request and supply it only in the
tool's `otp` argument.

### Launch Collab

Use this only with trusted agents and trusted workspace contents. The legacy
`agents` profile projects several provider credential directories into one
container, and the agents currently share one Unix identity.

```sh
cd /path/to/project
nosh recreate \
  --collab \
  -p agents \
  --start-app \
  --persist \
  --publish 127.0.0.1:3000
```

Record the launcher OTP privately for the lifecycle check below. Do not paste
it into a prompt, Collab channel, agent terminal, URL, environment variable, or
configuration file.

1. Open `http://127.0.0.1:3000/collab` and authenticate with the browser Basic
   credential.
2. Confirm the Collab service reports `ready`.
3. Refresh the launch catalog and confirm every runtime required by the chosen
   profile is available.
4. Select **Full Roster** when testing every supported agent/backend combination,
   or select a smaller profile for a focused smoke test.
5. Use **Agent** coordinator mode to verify one coordinator, or repeat with
   **Human** mode to verify that coordinator-capable roles are omitted.
6. Enter a harmless kickoff task that requires each agent to announce its
   identity, role, runtime/backend, and readiness in the shared channel.
7. Select **Launch profile** and wait for the roster and terminal grid to
   appear.

### Verify every agent

Work through the roster one row at a time; do not treat one healthy agent as
evidence for the others.

For each agent:

1. Match its visible identity, role, agent harness, backend, model, and Think
   setting to the launch preview.
2. Confirm its status becomes ready/running, its owned tmux terminal is alive,
   and its embedded terminal viewer connects to that exact agent.
3. Confirm it joins the expected Collab channel and posts under its own
   identity rather than another agent's identity.
4. Ask it for a harmless, identity-specific response and confirm exactly that
   agent responds once.
5. Ask it to inspect only the **names** of environment variables matching
   `OTP`, `TOKEN`, `PASSWORD`, `SECRET`, or `AUTH`; never ask it to print
   values. Confirm none of the following OTP variables exists in its process
   environment:

   ```text
   MCP_SPAWN_OTP
   SPAWN_OTP
   COLLAB_AGENT_SPAWN_OTP
   NOTTY_MCP_SPAWN_OTP
   NOTTY_MCP_SPAWN_OTP_ENABLED
   NOTTY_MCP_SPAWN_OTP_TTL_SECONDS
   NOTTY_GUARD_OTP_MINT_TOKEN
   ```

6. Confirm no spawn OTP, OTP UUID, or `spawn_otp_configured` field appears in
   the agent prompt, terminal output, managed-agent metadata, or Collab channel.
7. Record pass/fail for that exact agent before moving to the next roster row.

The environment-name check is useful manual evidence, but it is not sufficient
by itself because the agent is part of the system under test. Pair it with the
server-side OTP lifecycle check and the deterministic secret-scrubbing tests.

### Verify the operator OTP was not consumed by Collab

1. Open **Settings & Sessions** on the Terminals page, then inspect **Spawn OTP
   Management**.
2. Confirm the launcher OTP record is still **Available** after the complete
   Collab roster launches. Agent creation must not consume a terminal-spawn OTP.
3. Confirm the available count does not decrease as agents start, retry, change
   permission mode, reconnect viewers, or stop.
4. Use the launcher OTP once in a deliberate public MCP `spawn_terminal` call.
   Confirm that operation alone moves the record to **Used**.
5. Replay the same value and confirm the public spawn fails closed.
6. Mint a replacement from the host only when another public spawn test is
   required:

   ```sh
   cd /path/to/project
   nosh auth otp
   ```

7. Confirm the newly minted OTP is not projected into any already-running or
   subsequently retried Collab agent.

### Collab workflow acceptance checklist

- [ ] The Collab page is unavailable when Collab is disabled and ready when
      launched with `--collab`.
- [ ] The launched roster exactly matches the chosen coordinator mode and
      profile preview.
- [ ] Every agent has a distinct identity, owned tmux session, connected viewer,
      and correct runtime/backend/model.
- [ ] Every agent joins the expected channel and can send and receive a bounded
      test message.
- [ ] Each agent independently reports no spawn-OTP environment variable names.
- [ ] No agent output, prompt, channel record, API response, or managed metadata
      contains OTP plaintext or an OTP-delivery field.
- [ ] Launch, retry, viewer reconnect, permission relaunch, and stop do not
      consume the operator's available OTP.
- [ ] Only an explicit public terminal-spawn request consumes an OTP, exactly
      once; replay fails.
- [ ] Stopping the Collab session closes its managed viewers and owned tmux
      agents without stopping unrelated terminals.

## Install Nosh Guard, profile a build, and profile a run

### Goal

Install the reviewed root-owned Nosh Guard host bundle, prove that its daemon
and eBPF collectors are ready, capture a Docker build profile, and then capture
a timed guarded-runtime profile of the exact image produced by that build.

This workflow changes privileged host state and attaches eBPF collectors. Run
it only on a supported local Linux Docker host, review every `sudo` boundary,
and preserve the generated evidence. Never run npm, npx, Node, clang, or
bpftool directly on the host; the supported bundle builder uses Docker.

Build evidence and runtime evidence remain independent records. Neither a
successful profile nor a generated candidate is an approval or enforcement
decision.

### Phase 1: unprivileged user setup

- [ ] Run setup as the account that will use Nosh, never through `sudo`:

  ```sh
  cd /path/to/notty
  ./scripts/setup-nosh.sh
  ```

- [ ] Confirm the user-facing `nosh` and development `nosh-guard` launchers
      and the mode-`0600` path record were created.
- [ ] Ensure the configured launcher directory, normally `~/.local/bin`, is on
      `PATH`, or use the checkout scripts by explicit path.
- [ ] Review the Guard installation recipe printed by setup when the privileged
      installation is absent.

For a custom reviewed prefix, use the same prefix at setup, install, verify,
and uninstall time:

```sh
./scripts/setup-nosh.sh --guard-prefix /opt/notty
```

### Phase 2: build and install the Guard host bundle

Use a fresh private directory, verify the detached checksum, extract without
root, and elevate only the validated installer:

```bash
(
  set -euo pipefail
  guard_work_dir="$(mktemp -d)"
  trap 'rm -rf -- "$guard_work_dir"' EXIT
  guard_artifact_dir="$guard_work_dir/artifacts"
  guard_extract_dir="$guard_work_dir/extracted"
  install -d -m 0700 "$guard_artifact_dir" "$guard_extract_dir"

  ./scripts/build-nosh-guard-host-bundle.sh \
    --output-dir "$guard_artifact_dir"

  shopt -s nullglob
  guard_archives=("$guard_artifact_dir"/*.tar.gz)
  guard_checksums=("$guard_artifact_dir"/*.tar.gz.sha256)
  if (( ${#guard_archives[@]} != 1 || ${#guard_checksums[@]} != 1 )); then
    printf 'expected exactly one Guard archive and checksum\n' >&2
    exit 1
  fi

  guard_archive="${guard_archives[0]}"
  guard_checksum="${guard_checksums[0]}"
  if [[ ! -f "$guard_archive" || -L "$guard_archive" \
    || ! -f "$guard_checksum" || -L "$guard_checksum" \
    || "$guard_checksum" != "$guard_archive.sha256" ]]; then
    printf 'Guard archive or checksum is unsafe or mismatched\n' >&2
    exit 1
  fi

  (
    cd "$guard_artifact_dir"
    sha256sum --check --strict -- "$(basename "$guard_checksum")"
  )
  tar -xzf "$guard_archive" -C "$guard_extract_dir"

  guard_installers=("$guard_extract_dir"/*/install.sh)
  if (( ${#guard_installers[@]} != 1 )) \
    || [[ ! -f "${guard_installers[0]}" \
      || -L "${guard_installers[0]}" \
      || ! -x "${guard_installers[0]}" ]]; then
    printf 'expected exactly one safe Guard installer\n' >&2
    exit 1
  fi

  sudo "${guard_installers[0]}" install \
    --prefix /usr/local \
    --enable-now \
    --deep-verify
)
```

- [ ] Confirm checksum verification succeeds before the `sudo` step.
- [ ] Confirm the install creates a versioned release, selects `current`,
      installs the four collector loaders, records the prefix receipt, and
      enables `nosh-guardd.service`.
- [ ] Do not add `--replace-config`, `--replace-sudoers`, or purge options
      unless the corresponding drift or deletion has been separately reviewed.
- [ ] Build the ordinary runner image as the non-root Docker-authorized user:

  ```sh
  ./scripts/build-nosh.sh
  ```

### Phase 3: verify host readiness

```sh
sudo /usr/local/libexec/nosh-guard/nosh-guard-host-verify --deep
./scripts/setup-nosh.sh --check
bash scripts/nosh-guard-doctor.sh --mode learn
sudo bash scripts/nosh-guard-doctor.sh --mode learn --deep
```

- [ ] Confirm the installed release manifest, deployment copies, bundled
      runtime, loader ABI, and host dependencies pass deep verification.
- [ ] Confirm Docker is local, rootful, non-userns-remapped, Linux, cgroup v2,
      and configured with private cgroup namespaces.
- [ ] Confirm the Guard daemon is active and its mode-`0600` management socket
      exists at `/run/nosh-guardd.sock`.
- [ ] Confirm the balanced build collector passes both `health` and the real
      kernel-verifier `verify` probe.
- [ ] Treat `doctor --mode enforce` separately: the shipped standalone
      implementation intentionally reports its missing-ingress limitation and
      must not be used as the learn-mode installation gate.

### Phase 4: capture and inspect the build profile

For the repository's canonical `Dockerfile.nosh` build:

```sh
./scripts/build-nosh.sh profile
```

For an arbitrary Docker context with its ordinary `Dockerfile`:

```sh
nosh build profile --cache-mode compare .
nosh build status .
```

- [ ] Run as the Docker-authorized user, not by wrapping the entire command in
      `sudo`; allow only the Guard build-session operations to elevate.
- [ ] Confirm the default compare profile records one cold and one warm pass.
- [ ] Confirm required collectors start, stop, drain final statistics, and
      report no loss or truncation.
- [ ] Confirm the requested image remains in local Docker for the runtime phase.
- [ ] Record the run ID, image/config digest, private bundle path, portable
      bundle path, and final profile status.
- [ ] Stop if the build fails, evidence is incomplete, the image digest cannot
      be verified, or only warm evidence is available.

### Phase 5: capture the guarded runtime profile

The preferred release smoke is the correlated wrapper, which repeats the
canonical build profile and then observes the exact resulting image digest for
three minutes:

```sh
./scripts/profile-build-and-run.sh \
  --duration 180 \
  --image nosh \
  --target local \
  --cache-mode compare \
  --workdir "$PWD"
```

The wrapper runs as the Docker-authorized user, elevates only authoritative
runtime verification, and internally performs a timed
`nosh net learn --duration 180 --start-app`. Do not run the wrapper through
`sudo`.

- [ ] Confirm runtime admission binds the exact build `configDigest`, runner
      identity, workspace identity, cgroup namespace, and installed collector
      ABI before releasing the runner.
- [ ] Confirm the timer starts only after admission and the initial attachment
      health check succeeds.
- [ ] Exercise a small, deterministic Notty runtime flow during the observation
      window, or document that the timed run intentionally observed an idle
      service.
- [ ] Confirm orderly stop drains final eBPF and DNS evidence, removes the
      managed runner, and reports no lost events.
- [ ] Record the runtime run ID, exact image digest, immutable review-candidate
      directory, readable policy mirror, target-context path, hashes, and final
      status.
- [ ] Confirm an interrupted or incomplete timed window retains diagnostics but
      does not advance the runtime candidate.
- [ ] Do not treat the readable policy mirror, build candidate, runtime
      candidate, or opened Policy Review graph as approved authority.

### End-to-end acceptance checklist

- [ ] User setup and privileged installation use their intended separate trust
      boundaries.
- [ ] Deep install verification and learn-mode doctor pass before profiling.
- [ ] The build profile contains complete cold/warm evidence and a verified
      locally loaded image digest.
- [ ] The runtime profile is bound to that exact digest and canonical workspace.
- [ ] Both profile families preserve their private and portable/reviewable
      artifacts without silently merging authority.
- [ ] No profile step runs npm or npx, resolves a mutable host-PATH Node
      runtime, or uses a host compiler toolchain; Guard executes only its
      manifest-covered installed runtime and loaders.
- [ ] No failed, interrupted, lossy, or identity-drifted run advances a
      candidate.
- [ ] All generated reports and artifact paths are recorded for later manual
      review, while approval, signing, activation, audit, and enforcement remain
      explicit later workflows.

## Test reviewed build policy and runtime profile enforcement

This workflow follows profiling. Keep the two meanings separate: a build
candidate is observational evidence and has no direct `audit`, `approve`, or
`enforce` command. Runtime egress enforcement is authorized only by a complete
DecisionSet, exact `guard-ebpf` projection, review signature, short-lived
deployment grant, and successful root-owned activation.

### Phase 1: prove the build candidate is not authority

- [ ] Preserve the complete build candidate and its hashes as review evidence.
- [ ] Confirm attempts to use a direct build `audit`, `approve`, or `enforce`
      command are rejected without changing Guard, Docker, or policy state.
- [ ] Open the frozen graph with the supported Policy Review workflow and
      disposition every proposal; do not silently convert observations into
      allow rules.
- [ ] Confirm missing SBOM coverage, unresolved decisions, blocking findings,
      digest drift, or unsupported target mappings make the result
      activation-ineligible.
- [ ] Treat browser sketches and gateway renderings marked `renderOnly` as
      inspection artifacts, never executable policy.
- [ ] Where a reviewed build restriction has a supported target projection,
      test that projection in a disposable environment and bind the result to
      the exact build inputs and output image digest. Do not reuse it as
      runtime-profile approval.

Run the two container-backed regression tests from inside a Nosh container:

```console
node --test tests/build-network-deny.test.cjs
node --test tests/reviewed-policy-enforcement.test.cjs
```

- [ ] Record a skip as untested, not passed. The network-none regression is not
      a substitute for signed policy activation.

### Phase 2: audit the learned runtime candidate

Before activation, run the scoped audit against the current workspace:

```console
sudo -- "$GUARD_BIN" net audit --workdir "$PWD"
```

- [ ] Exercise each intended destination and at least one unreviewed domain,
      direct IP, port, and transport.
- [ ] Confirm matching traffic is allowed and unmatched traffic is allowed but
      recorded as `would-deny`; audit evidence must not train or widen policy.
- [ ] Confirm platform containment endpoints remain denied during audit.
- [ ] Stop and finalize the audit run, then record its run ID, image digest,
      policy identity, counters, loss status, and evidence manifest.
- [ ] Confirm `nosh net approve` is only a legacy acknowledgement and cannot
      authorize enforcement.

### Phase 3: review, sign, grant, and activate

- [ ] Export one complete `NoshPolicyDecisionSet` from the immutable runtime
      review candidate.
- [ ] Follow `docs/nosh-policy-review.md`, section **Guard eBPF review and
      activation**, using separate `--network none` tooling invocations for
      projection, review approval, and deployment grant.
- [ ] Project the exact `guard-ebpf` leaf with the captured target-context file.
      Continue only when it reports `activationEligible: true`.
- [ ] Stop if an accepted FQDN rule is unsupported by the current
      `tcpDns:false` backend. Do not weaken it to a literal address or bypass
      the projection failure merely to complete the test.
- [ ] Use distinct review and deployment signing keys whose public keys and
      audiences already match the root-owned deployment trust configuration.
- [ ] Keep both private keys out of the workspace, containers other than their
      one signing step, reports, command output, and Git.
- [ ] Issue a short-lived, single-use deployment grant bound to the current
      active-grant-set digest, exact subject, backend ABI, workspace, image,
      projection, and approval.
- [ ] Assemble the activation bundle exactly as documented, then activate it:

```console
# Set LEARN_REVISION to the exact learned revision used for this review.
sudo -- "$GUARD_BIN" ebpf activate \
  --workload dev --workdir "$PWD" --learn-revision "$LEARN_REVISION" \
  --bundle "$POLICY_IO/activation-001" \
  --target-context "$POLICY_IO/guard-ebpf-target-context.json"
```

- [ ] Confirm tampered hashes, a stale or replayed grant, expired authority,
      audience/key mismatch, target-context drift, missing backend health, or
      changed image/workspace identity fails before policy mutation.

### Phase 4: enforce the activated runtime profile

```console
sudo -- "$GUARD_BIN" net enforce --workdir "$PWD"
```

Add `--revision REVISION` only to select the exact current learned launch
settings. A revision never selects or activates policy.

- [ ] Confirm the selected positive-control destination succeeds only on its
      reviewed address, port, and transport.
- [ ] Confirm unreviewed domains, direct IPs, ports, transports, DNS endpoints,
      DNS-over-TLS, and QUIC are denied unless each is explicitly represented
      by the activated policy.
- [ ] Confirm broader reviewed CIDRs cannot override exact platform-containment
      denies.
- [ ] Confirm the runner remains unprivileged, has no published ports, retains
      its read-only/root filesystem and namespace controls, and receives only
      the active signed egress leaf.
- [ ] Confirm enforcement does not imply compiled ingress policy; this scoped
      workflow is distinct from full standalone `--security-mode enforce`.
- [ ] Stop the run through Guard, drain final DNS/eBPF evidence, and verify the
      final counters are hash-bound with no loss or incomplete sources.
- [ ] Confirm a failed or interrupted enforce run preserves diagnostics and
      containment state until cleanup is proven; it must not detach controls
      merely to make removal succeed.

### Acceptance

- [ ] Build observations never become authority directly.
- [ ] Audit shows the expected would-deny set without widening policy.
- [ ] Activation consumes one valid grant and advances only the intended
      signed policy transition.
- [ ] Enforce permits every reviewed positive control and blocks every selected
      negative control.
- [ ] Evidence records the exact build, image, workspace, revision, projection,
      signatures, grant, active policy, run, counters, and cleanup result.

## Test the HTTP network kill switch and per-agent profiling

### Phase 1: establish identities and initial state

- [ ] Start a Guard-managed Notty container with the general container policy
      and every agent policy shown separately in the HTTP interface.
- [ ] Confirm the UI obtains authoritative state from Guard and displays the
      exact container/run identity, backend health, and last transition.
- [ ] Launch one agent at a time with a known harness, provider/model, version,
      image digest, and exact cgroup/process identity.
- [ ] Confirm a new agent receives the configured default network state and
      cannot inherit another agent's policy or the browser's stale state.

### Phase 2: exercise the emergency OFF path

- [ ] Begin a bounded connection from the selected agent, then select its
      **Network OFF** control.
- [ ] Confirm Guard atomically installs and verifies the deny boundary before
      the UI reports OFF.
- [ ] Confirm new TCP, UDP, IPv4, IPv6, DNS, direct-IP, QUIC, and DNS-over-TLS
      attempts from that agent fail while unrelated allowed agents and general
      container traffic retain their own policy state.
- [ ] Confirm existing connections are purged, terminated, or explicitly shown
      as a backend limitation; OFF must not misleadingly claim containment.
- [ ] Repeat with the container-wide OFF control and confirm all container
      egress is denied.
- [ ] Inject backend installation and verification failures. Confirm Guard
      pauses/stops the exact container and kills it when lesser containment
      cannot be proven.
- [ ] Confirm forced containment preserves evidence and reports a degraded or
      contained state rather than resetting the UI to ON.

### Phase 3: exercise the authorized ON path

- [ ] Select a time-bounded LEARN window or a reviewed ENFORCE profile; show
      its identity, expiry, and affected agent/container scope in confirmation.
- [ ] Confirm LEARN permits observation only for the selected scope, expires
      back to OFF, and cannot itself authorize later enforcement.
- [ ] Confirm ENFORCE activates only that reviewed policy and a generic ON
      action cannot become an unrestricted-network shortcut.
- [ ] Confirm the selected agent can reach reviewed positive controls and
      cannot reach unreviewed negative controls.
- [ ] Confirm one agent's ON transition cannot change a peer agent or general
      container policy.
- [ ] Refresh/reconnect the browser and restart the Notty service. Confirm the
      UI reconciles to Guard state without changing enforcement.

### Phase 4: learn one profile per agent

Repeat this phase independently for Codex, Gemini, and Claude:

- [ ] Start a fresh learn session bound to the exact agent and descendants, not
      the whole container.
- [ ] Connect and complete the provider login flow manually without recording
      credentials, authorization codes, tokens, URL query values, or content.
- [ ] Exercise representative model calls, streaming, tool use, retries,
      refresh, and clean logout/stop behavior.
- [ ] Verify general Notty traffic and peer-agent traffic are excluded from the
      agent evidence.
- [ ] Stop cleanly and confirm final eBPF/DNS evidence is complete, loss-free,
      hash-bound, and attached to the exact agent/tool/image identities.
- [ ] Review every destination and unresolved observation. Project, sign, grant,
      and activate only an exact supported policy; never enforce the raw learned
      candidate.
- [ ] Re-run the agent under audit, inspect would-deny results, then enforce and
      repeat the positive and negative controls.
- [ ] Change the agent binary/version, backend/model, image digest, and process
      identity in separate negative tests; confirm stale profiles fail closed.

### Phase 5: optional preprofiles and domain view

- [ ] Run preprofiling as an explicit release job, outside the ordinary Docker
      build, with ephemeral manual credentials and no secrets in layers/cache.
- [ ] Confirm every shipped preprofile records provenance and is bound to exact
      supported agent and image versions.
- [ ] Compare a manually learned profile with its preprofile without silently
      unioning their permissions.
- [ ] If the domain inventory is implemented, verify per-agent and general
      views remain separate, deduplicate safely, expose uncertainty/loss, and
      reveal no credentials or sensitive URL data.

### Acceptance

- [ ] Agent OFF contains only the selected agent; container OFF contains all
      egress; failure to verify either path stops or kills the exact container.
- [ ] LEARN is temporary observation; ENFORCE is one selected reviewed policy.
- [ ] Codex, Gemini, and Claude profiles remain independently attributable and
      independently reviewable.
- [ ] Every transition and profiling run leaves complete operator-visible audit
      evidence.
