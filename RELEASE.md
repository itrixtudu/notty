# Notty Public Release Plan

**Status:** No-go until the applicable release gates and Definition of Done are
complete.

**Proposed first public version:** `1.0.0`

**Release candidate:** `1.0.0`

**Last reviewed:** 2026-09-01

This document is the sole release authority for Notty. It turns the current
security, product, packaging, and documentation findings into an ordered path to
the first public release. It also consolidates the still-current material from
the former `release-plan.md` and `nice-to-have.md`. Those files are compatibility
pointers, not independent plans. Where historical guidance conflicts with this
document, this document wins.

## Previous Repository Snapshot (2026-07-31)

This snapshot is retained as the finding set for commit `15d560e`; it is not a
claim about the current checkout. Run `./scripts/release-audit.sh` for current automated
results. Docker is mandatory and the audit never falls back to host npm.

- The reviewed checkout is branch `v0.4` at commit `15d560e`, tracking
  `origin/v0.4`; no semantic release tag exists. Release status remains
  **no-go**. Before this documentation update, its only unrelated worktree
  state was an untracked `logs/` directory containing local audit and MCP
  logs.
- The automated baseline passes all 310 tests and the production Next.js build.
  Docker is unavailable in the review environment, so no live container,
  eBPF, or Nosh Guard run has been verified.
- `npm audit --omit=dev` reports six production findings: four high and two
  moderate. The reviewed `npm pack --dry-run --json` baseline emits 460 files
  and includes tracked `agents/runs/**` and `agents/msgs/**` runtime state, so
  the package is not release-safe.
- At that snapshot, root release materials and automation were missing:
  `LICENSE`, `THIRD_PARTY_NOTICES.md`, `SECURITY.md`, `CONTRIBUTING.md`,
  `CHANGELOG.md`, and a checked-in CI workflow.
- Version identity conflicts remain unresolved: the branch is named `v0.4`,
  package and lock metadata report `1.0.0`, no semantic release tag exists,
  and the plan at that snapshot proposed `0.1.0`.
- Authentication coverage, scoped principals, fail-closed human-approved spawn
  grants, terminal ownership/delegation, and child credential isolation do not
  yet satisfy the release gates. Legacy agent profiles can project shared
  provider credentials; the guarded runner omits them but has no reviewed
  hosted-agent credential broker.
- Nosh Guard `learn` records and permits traffic except invariant host/private
  network denies. `audit` binds one candidate and records would-deny egress
  decisions, but incomplete backend evaluation makes current runs
  non-promotable. The standalone `enforce` path rejects admission because no
  integrated backend applies and attests the compiled ingress policy.

## Documentation and Provenance Update (2026-08-03)

- The root 0BSD license, third-party notices, security policy, contribution
  guide, forward-only changelog, and Docker-backed CI workflow are now present.
  Artifact-specific SBOM/license inventories and final manual legal review
  remain open.
- Durdraw remains pinned at 0.29.0 with its BSD-3-Clause license and upstream
  attribution. The Nosh L4 eBPF source is explicitly available under
  `0BSD OR GPL-2.0-only` with the kernel loader designation `Dual BSD/GPL`.
- Provenance-unresolved Acid/Kross and Ghosts/Iniquity material is retained
  only in the private local checkout: it is untracked and excluded from Git,
  npm, and Docker release contexts. The unused copied ASCII effect and
  off-version Durdraw installer were removed.
- Known generated agent runs, messages, locks, Collab channel/swap state,
  logs, cache state, and the credential-bearing OAuth helper are likewise
  untracked while retained only in the ignored local checkout. Their prior
  presence in history still requires the history scan and any indicated
  credential rotation before publication.
- Nosh provides `vlock` as an opt-in single-PTY convenience with interactive
  container password setup. It is not an application, agent, tmux, container,
  or host security boundary. The existing lockdown view uses a separate
  read-only first-party status process, but its current guards do not disable
  MCP or terminal WebSocket input and remain an incomplete security boundary.
- At that update, package and root lockfile metadata matched the then-declared
  pre-1.0 candidate. The current release identity is declared at the top of
  this document.
- Release status remains **no-go** until the remaining security, dependency,
  artifact, CI, and clean-machine gates pass.

## Release Gates

Priority labels describe implementation order; they do not waive lower-priority
work from the public release.

- **Repository visibility gate:** complete the history secret scan, legal and
  artwork provenance review, and runtime-artifact purge before changing a
  private repository to public.
- **Release-candidate gate:** complete every P0 item, establish minimal CI, add
  the root license and notices, and prove that candidate source/image/package
  contents contain no runtime or private data.
- **Public `v1.0.0` gate:** satisfy the complete Definition of Done, including
  the required P1, P2, documentation, dependency, and clean-machine checks.

Only the owner can explicitly defer an item, and a deferred item must move to a
documented non-goal without weakening a security, privacy, legal, or artifact
hygiene guarantee.

## Release Intent

Notty should ship as a local-first terminal workspace where a human, a
per-terminal copilot, and optional coordinated agent teams can safely share
terminal context and control.

The first release should demonstrate a narrow, dependable path:

- create, attach, split, read, and control terminal sessions;
- run one copilot per source terminal;
- ask about highlighted terminal text;
- use Passive observation and Off, Insert, or Approve control;
- launch Codex with hosted models through its default runtime or Ollama;
- launch Agy when its real-runtime smoke is reliable;
- enable Collab explicitly as a preview;
- expose terminal MCP only through a strict, user-controlled authorization
  boundary.

Notty is not ready to claim that an Internet-facing deployment is supported.
The supported release posture is local or loopback-first. A non-loopback
deployment must use TLS, explicit authentication, and the same authorization
rules as a local deployment.

## Release Scope

### Supported

- Browser terminal workspace
- Terminal lifecycle and split layouts
- One Copilot per terminal
- Highlight-and-Ask
- Passive observation
- Off, Insert, and Approve terminal control
- Codex with hosted models through its default runtime
- Codex with local models through the Ollama runtime
- MCP terminal access behind Basic Auth and one-time spawn grants
- Nosh as the recommended isolated launcher

### Preview

- Agy
- Collab profiles and Human/Agent coordinator modes
- Active Copilot feedback
- Local feedback statistics

### Labs

- Autonomous Copilot control
- Timed intent inference
- Claude in Collab
- XR, WebGL, and BasicGL pages
- Durdraw multi-agent art orchestration
- Legacy swarm and standalone Collab workflows
- Hardware and C-development container targets

Labs may remain in the repository, but they must not obscure the supported
quick start or be presented as release-stable. Labs must be off by default
behind an explicit switch. Any reachable Labs code remains subject to every P0
authentication, authorization, isolation, and resource boundary.

Agy remains Preview only if preflight, launch, one prompt/response, and clean
shutdown pass three consecutive real-runtime smokes on each supported host
class before the release candidate. Otherwise it moves to Labs. Collab is part
of the Preview scope for `v1.0.0` and is not an optional release-candidate test.

## Security Model

The supported HTTP service separates three kinds of authority:

- **OAuth 2.1 Bearer authenticates MCP clients.** Public clients register with
  DCR and use authorization code plus PKCE S256. Access and rotating refresh
  tokens are scoped to `mcp:tools` and one exact RFC 8707 resource.
- **Basic Auth protects human consent and browser/admin routes.** It is never
  stacked with Bearer on an MCP request's `Authorization` header.
- **A spawn OTP authorizes one terminal creation.** Validation happens first;
  the accepted OTP is then atomically consumed immediately before PTY spawn.
  A subsequent spawn failure does not restore it.
- **Guard mTLS authenticates Guard operators.** Guard does not embed the OAuth
  service; its runners remain OTP-locked behind the mTLS gateway.
- **Process isolation limits impact.** Spawned PTYs and agents do not inherit
  Basic credentials, OAuth headers/tokens, launcher OTPs, or registry state.

OAuth clients, grants, hashed tokens, refresh families, OTP hashes, consumed
tombstones, and revocations persist in a private per-workspace SQLite database.
MCP HTTP and SSE sessions are bound to OAuth client, subject, scope, and
resource. OAuth tokens and spawn OTPs never appear in URLs or dashboard history.

The explicit loopback-only `--no-otp-auth` mode removes Bearer and Basic
authentication while retaining fail-closed OTP checks for every external
spawn. Non-spawn MCP tools are intentionally anonymous in that mode. Only
`--no-otp` disables spawn enforcement.

## P0: Public Release Blockers

Every item in this section must be complete before cutting a release candidate.
Completing P0 alone does not authorize a public release; the Release Gates and
Definition of Done still apply.

### 1. Safe Binding and Authentication

- [ ] Bind HTTP, MCP, and WebSocket listeners to `127.0.0.1` by default.
- [ ] In Nosh, publish the container port on host `127.0.0.1` by default even
      when the process must listen on the container interface.
- [ ] Do not support a directly exposed non-loopback Notty listener in
      `v1.0.0`. Refuse it unless an explicit Labs-only unsafe override is used.
- [ ] Document one supported remote topology: TLS terminates at a configured
      reverse proxy and its Notty upstream is loopback, a Unix socket, or a
      private container network inaccessible to clients.
- [ ] Trust forwarded scheme/client headers only from the exact configured
      proxy address or local socket; never infer TLS safety from untrusted
      forwarded headers.
- [ ] Protect every privileged route consistently:
  - `/mcp` and all transport aliases;
  - `/api/mcp/**`;
  - `/api/terminals/**`;
  - `/api/copilots/**` and the separate Copilot MCP broker;
  - `/api/agents/**`;
  - `/api/spawn-otps` or its replacement;
  - `/api/collab/**`;
  - any legacy `/oauth/**` or bearer-token endpoint until it is removed from
    the supported build;
  - terminal WebSocket upgrades.
- [ ] Inventory every listener and launch mode, including the integrated
      server, standalone SSE, standalone Collab, Copilot broker, proxy, and
      helper entrypoints. Give each one an explicit authentication,
      authorization, Origin/CSRF, body-size, and rate-limit policy, or exclude
      it from the supported artifact.
- [ ] Leave only a minimal health/version endpoint unauthenticated.
- [ ] Provision Basic consent/admin access and persistent, revocable per-client
      OAuth DCR registrations scoped to exact MCP resources.
- [ ] Ensure MCP-client credentials cannot call administrator REST routes.
- [ ] Start in a locked state until credentials are initialized from a local
      controlling TTY or a pre-created `0600` secret file.
- [ ] Store password verifiers using a reviewed password KDF; never store or
      log reusable plaintext passwords.
- [ ] Show generated bootstrap credentials once, support rotate/revoke/recover,
      and never place them in child environments or command output.
- [ ] Require same-origin and CSRF protection on every state-changing browser
      or administrator route, not only OTP routes.
- [ ] Validate WebSocket Origin before upgrade to prevent cross-site WebSocket
      hijacking.
- [ ] Enforce the documented loopback-only policy for `--noauth`,
      `--no-oauth`, `--no-otp-auth`, and `--no-otp`; disable HTTP OTP minting
      specifically in OTP-only mode.
- [ ] Rate-limit failed authentication attempts.
- [ ] Support MCP OAuth 2.1 authorization code, DCR, PKCE S256, exact resource
      audiences, refresh rotation/replay revocation, and Bearer-only MCP
      requests. Keep legacy `/oauth/token` as unauthenticated `410 Gone` for
      one release and reject all query-string tokens.

Acceptance criteria:

- Outside explicit loopback OTP-only mode, an unauthenticated caller cannot
  create, enumerate, attach to, read, write,
  resize, kill, launch an agent/Copilot, approve a command, or manage Collab
  through any HTTP, MCP, SSE, broker, or WebSocket alias.
- A fresh install refuses privileged service until the administrator and at
  least one unique MCP principal have been deliberately provisioned.
- A direct remote bind fails clearly. The documented proxy topology rejects
  plain HTTP at its public edge and ignores spoofed forwarded headers.
- An OAuth MCP identity cannot access Basic-protected OTP administration or
  bypass the same spawn gateway through REST terminal creation.

### 2. Strict User-Controlled Spawn Grants

- [ ] Change the OTP registry from fail-open to fail-closed whenever terminal
      MCP is enabled.
- [ ] Route every MCP, REST, browser, WebGL, XR, and other external creation
      path through one fail-closed spawn gateway.
- [ ] Accept OTPs only in MCP arguments or JSON bodies; never accept them in
      authentication headers, URLs, cookies, browser storage, or logs.
- [ ] Return plaintext only on initial generation; dashboard reads expose only
      status, UUID, source, and timestamps.
- [ ] Support an operator-configured finite TTL and record expiry tombstones.
- [ ] Generate high-entropy values at launch or through an authenticated local
      operator action; allow an explicit launcher `--otp VALUE` override.
- [ ] Add `Cache-Control: no-store` and prevent browser/proxy caching.
- [ ] Persist only a verifier or hash, never the raw OTP.
- [ ] List only UUID, source, status, and timestamps.
- [ ] Require an authenticated, same-origin, CSRF-protected user action to
      issue an OTP through HTTP. Disable this mutation entirely in OTP-only
      mode; Guard requires an mTLS-authenticated operator.
- [ ] Accept only the documented JSON content type on mutation routes.
- [ ] Consume the grant atomically before attempting the spawn.
- [ ] Keep a consumed grant consumed if process creation fails.
- [ ] Rate-limit invalid OTP guesses independently from Basic Auth failures.
- [ ] Preserve OTPs and consumption tombstones across service/container
      restarts; only `nosh auth reset` invalidates the workspace registry.
- [ ] Record issue, consume, expire, revoke, and failure events without logging
      the OTP.
- [ ] Store auth state in owned, non-symlink 0700 directories and a 0600
      integrity-checked SQLite database.
- [ ] Garbage-collect expired secret material and bound audit history.
- [ ] Do not add an automatic refresh or renewal endpoint.

Acceptance criteria:

- No active grant means `spawn_terminal` is denied.
- A concurrent replay race produces exactly one authorized attempt.
- An invalid, expired, consumed, or revoked value is rejected.
- A dashboard reload cannot recover an issued token value.
- A restart cannot make a consumed launcher OTP usable again.

The required `v1.0.0` handshake is:

```text
Launcher or authenticated operator --> generate OTP --> reveal once
MCP/REST/browser caller --> validate spawn request + submit OTP in body/argument
Server --> atomic consume --> PTY spawn attempt
Server --> retain consumed tombstone whether spawn succeeds or fails
```

### 3. Terminal Ownership and Delegation

- [ ] Record the unique authenticated owner principal and originating MCP
      session on every terminal.
- [ ] Treat a terminal UUID as a locator, not authorization by itself.
- [ ] Enforce ownership or explicit delegation for read, write, resize, type
      changes, attach, context capture, and kill.
- [ ] Restrict terminal listing to the administrator or the caller's owned
      terminals.
- [ ] Namespace reader handles and persistent read pointers by principal and
      MCP session.
- [ ] Prevent one MCP session from reading or closing another session's reader.
- [ ] Apply the same ownership rules to REST, MCP, SSE, and WebSocket paths.
- [ ] Implement user-visible, server-side delegation with separate `read`,
      `write`, `resize`, `attach`, and `kill` scopes, a finite TTL, and explicit
      revocation.
- [ ] Create a scoped internal delegation when the terminal owner explicitly
      launches a Copilot. Passive and Off modes receive read access only;
      Insert and Approve receive only the write behavior their mode requires;
      autonomous Enter remains Labs-only.
- [ ] Give each Collab agent only the terminal scopes required by its role and
      revoke them when the Collab session stops.
- [ ] Make every Copilot/Collab delegation visible to the administrator and
      tie it to the source terminal, internal service identity, and lease.
- [ ] Revoke all ACL state when the terminal exits. On transport disconnect,
      expire session readers and session-scoped delegations, but allow the same
      authenticated owner principal to reconnect to its live terminal.

Acceptance criteria:

- Two authenticated MCP clients cannot observe or control one another's
  terminals without an explicit administrator delegation.
- A Copilot or Collab agent cannot exceed its displayed mode/role scopes, and
  lease expiry or revocation takes effect before its next operation.
- Closing a transport invalidates that session's readers without destroying
  the owner's terminal; revoked credentials prevent the principal from
  reconnecting.

### 4. Secret and Process Isolation

- [ ] Replace `process.env` inheritance with a strict child-environment
      allowlist.
- [ ] Strip Basic Auth passwords, OAuth credentials, OTPs, broker tokens,
      Notty control-plane values, and unrelated provider/API secrets.
- [ ] Pass agent-specific capability values only to the intended process.
- [ ] Ensure terminal output, process listings, `/proc`, logs, and error
      reports cannot reveal control-plane credentials.
- [ ] Do not print secret-valued Docker arguments in Nosh normal or dry-run
      output.
- [ ] Load service credentials through a protected mechanism rather than
      placing reusable secrets in child-visible container environment state.
- [ ] Ensure one agent cannot read or use another agent's provider credentials.
      Separate Unix users and homes are one possible future implementation, not
      a required architecture; an equivalently reviewed capability or
      credential-broker boundary is acceptable.
- [ ] Separate the Notty control-plane process from untrusted PTYs by OS user,
      container boundary, or an equivalently reviewed isolation mechanism.
- [ ] Make Codex, Agy, Claude, Arduino, node-module, and serial-device mounts
      opt-in profiles rather than default mounts.
- [ ] Mount only the minimum credential files and prefer read-only access.
- [ ] Default managed agents to the safe sandbox mode.
- [ ] Before the first hosted-agent launch, obtain explicit user consent and
      disclose which selection, terminal tail, cwd/workspace metadata, files,
      and feedback may leave the machine.
- [ ] Default hosted requests to the smallest required context, redact common
      secret forms, and require another explicit action before sending files
      or a larger terminal history.
- [ ] Label Ollama as a local runtime while documenting that its configured
      host still receives prompts and terminal context.

Acceptance criteria:

- Running `env`, inspecting process metadata, or causing a spawn error inside
  an agent terminal reveals no Basic password, OTP, OAuth secret, or Notty
  capability.
- A Nosh dry run contains placeholders or redactions for every secret.
- Starting Nosh without a profile mounts no provider credentials or hardware.
- The hosted-agent request preview and captured test transport contain only the
  context classes the user approved.

### 5. Resource and Abuse Limits

- [ ] Set global and per-principal terminal quotas.
- [ ] Set hard minimum and maximum terminal dimensions.
- [ ] Bound terminal buffer memory and total retained output.
- [ ] Bound MCP session count and add idle-session cleanup.
- [ ] Bound closed-session and reader-handle bookkeeping.
- [ ] Set WebSocket connection, payload, and message-rate limits.
- [ ] Set HTTP body limits consistently on every route.
- [ ] Add container CPU, memory, PID, and file-descriptor guidance or defaults.
- [ ] Ensure cleanup runs on disconnect, timeout, process exit, and server
      shutdown.

Proposed starting limits, to confirm with load tests before the release
candidate:

| Resource | Default limit | Enforced ceiling |
| --- | ---: | ---: |
| Terminals | 8 per principal / 32 global | 16 / 64 |
| Terminal dimensions | 300 x 120 | 500 x 200 |
| Retained output | 4 MiB per terminal / 64 MiB global | 16 MiB / 256 MiB |
| MCP sessions | 4 per principal / 16 global | 8 / 32 |
| Reader handles | 8 per session | 32 per session |
| MCP idle timeout | 15 minutes | 60 minutes |
| Closed-session records | 1,024 for 15 minutes | 4,096 for 60 minutes |
| HTTP request body | 256 KiB | 1 MiB |
| WebSocket payload | 256 KiB | 1 MiB |
| WebSockets | 4 per principal / 32 global | 8 / 64 |
| WebSocket messages | 20/second, burst 40 | 50/second, burst 100 |

Acceptance criteria:

- Oversized payloads return `413`, invalid dimensions return `422`, and
  exhausted quotas or rate limits return `429` without spawning work.
- Process exits and disconnects release terminal/connection quota within five
  seconds; idle MCP state and reader handles are reclaimed within 30 seconds
  of their configured expiry.
- Every limit can be lowered by configuration. Raising an enforced ceiling
  requires an explicit unsafe override and produces a startup warning.

### 6. Security Regression Suite

Add deterministic tests for at least the following:

- [ ] every privileged route, broker, and standalone mode rejects missing or
      invalid Basic Auth;
- [ ] bootstrap lock, unique principal scopes, credential rotation, and
      revocation;
- [ ] direct remote binding refusal, trusted-proxy behavior, CSRF, Origin, and
      WebSocket upgrade defenses;
- [ ] terminal MCP is fail-closed without a grant;
- [ ] pending request, explicit approval, and one-time reveal behavior;
- [ ] finite TTL boundary behavior;
- [ ] concurrent single-use consumption;
- [ ] revoke and replace behavior;
- [ ] principal, session, purpose, and workspace binding;
- [ ] canonical request mismatch and realpath/symlink escape rejection;
- [ ] raw tokens never appear in list responses, logs, child environments, or
      retained state;
- [ ] REST cannot bypass MCP spawn authorization for an MCP principal;
- [ ] terminal ownership across REST, MCP, SSE, and WebSocket;
- [ ] reader-handle isolation;
- [ ] Copilot and Collab scope, lease, and revocation enforcement;
- [ ] child-environment secret scrubbing;
- [ ] hosted-agent context consent and bounded payload;
- [ ] Nosh command-output redaction;
- [ ] terminal and session quotas;
- [ ] restart invalidates outstanding grants.

Suggested focused test modules:

```text
tests/auth-boundaries.test.cjs
tests/auth-bootstrap.test.cjs
tests/spawn-grants.test.cjs
tests/terminal-ownership.test.cjs
tests/agent-delegation.test.cjs
tests/terminal-env-isolation.test.cjs
tests/nosh-secret-handling.test.cjs
```

## P1: Required Repository and Distribution Readiness

### Legal and Provenance

- [x] Choose the 0BSD Notty license and add a root `LICENSE` file.
- [x] Make `package.json` and the root lockfile metadata match 0BSD.
- [x] Add `THIRD_PARTY_NOTICES.md`.
- [x] Preserve the vendored Durdraw BSD-3-Clause license and attribution.
- [x] Exclude the currently identified provenance-unresolved Acid/Kross and
      Ghosts/Iniquity material from tracked Git and npm/Docker release
      contexts.
- [x] Remove precompiled architecture-specific Acid binaries from tracked
      source and release contexts while retaining the private local copies.
- [ ] Generate SBOM and license inventories for each exact release artifact
      and complete the final manual legal/provenance review.

### Repository Hygiene

- [x] Remove tracked runtime artifacts from the current release tree:
  - `.notty-art-runs/**`;
  - `agents/runs/**`;
  - `agents/msgs/**`;
  - Collab channel and feedback JSONL;
  - editor swap files;
  - runtime logs and caches;
  - machine-specific manifests and absolute paths.
- [x] Expand `.gitignore`, `.npmignore`, and `.dockerignore` for known runtime,
      credential, report, and private-art paths.
- [ ] Use a `package.json` `files` allowlist if npm packaging remains enabled.
- [ ] Run a secret scanner across the complete Git history before making a
      private repository public.
- [ ] If the development repository is still private, decide whether to expose
      its experimental history or publish a clean release repository/history.
- [ ] Remove or rewrite stale internal notes, including outdated Collab and
      terminal documents.

### Package and Artifact Identity

- [x] Prevent publication of the unrelated public npm name `notty` with the
      package-private metadata gate.
- [ ] Prefer GitHub source releases and GHCR images for the first release.
- [ ] If npm publishing is required, use a scope such as `@xpatchdev/notty`.
- [x] Set `"private": true` to prevent accidental publication of the unrelated
      unscoped npm name while npm distribution remains deferred.
- [ ] Select one version source and remove hard-coded divergent versions.
- [ ] Align package, lockfile, CLI, MCP server metadata, tag, and release name.
- [ ] Add package repository, homepage, bugs, supported Node, and platform
      metadata.
- [ ] Publish immutable version and commit-SHA container tags.
- [ ] Generate checksums, an SBOM, and build provenance for release artifacts.

### Dependency and Container Hygiene

- [ ] Resolve or document reachability for every high/moderate production
      dependency advisory.
- [ ] Do not apply `npm audit fix` downgrades without review.
- [ ] Pin and verify the Antigravity installer instead of executing an
      unversioned remote `curl | bash` script.
- [ ] Use a non-root, minimal, multi-stage production image.
- [ ] Remove compilers and build-only dependencies from the runtime image.
- [ ] Ensure Docker contexts cannot include local runtime data.
- [ ] Scan the final image and inspect its full file list before release.

### Container and Launcher Contract

These requirements preserve the useful container and launcher scope from the
former cleanup plan without carrying forward its obsolete authentication
defaults.

- [ ] Refactor `Dockerfile.nosh` into meaningful named `base`, `local`, `agent`,
      `hardware`, `cdev`, and `full` targets. `base` must become the generic
      application sidecar; local shell, agent, hardware, and C-development
      tooling must remain opt-in. Labs targets do not become Supported merely
      because they build.
- [ ] Keep `./scripts/build-nosh.sh` as the canonical image build entrypoint, defaulting
      to the `local` development target. Local targets may map `USERNAME`,
      `USER_UID`, and `USER_GID`, but release artifacts must not embed a
      maintainer username, home path, credential directory, or private tool
      path.
- [ ] Keep personal mounts, provider credentials, device access, and private
      tooling out of image defaults. Expose them only through explicit profiles
      with the minimum required access.
- [ ] Keep `./scripts/nosh.sh` as the canonical launcher. Any retained legacy launcher
      names must be thin compatibility shims rather than divergent
      implementations.
- [ ] Retain explicit `--image` and `--name` overrides for local and test
      workflows without allowing either option to bypass release admission,
      image verification, or project-scoping rules.
- [ ] Preserve the legacy container lifecycle contract while legacy mode
      remains available: create an ephemeral project-scoped container, attach
      to a matching existing container, and retain it after the primary shell
      exits only when `--persist` is explicit. Guarded lifecycle semantics stay
      separate and follow the Nosh Guard state machine.
- [ ] Load launcher profiles from built-ins, optional repo-local
      `nosh.mounts.json`, and optional user configuration under
      `~/.config/nosh/`, with deterministic precedence and clear failures for
      missing required mounts. Optional missing mounts may warn and continue.
- [ ] Retire or explicitly Labs-gate launcher behavior that generates, injects,
      or prints reusable Basic Auth or spawn-OTP credentials. The supported
      release path starts locked and follows the human-approved, one-time
      reveal flow in P0; `--otp`, `--noauth`, `--publish`, and direct network
      overrides cannot weaken that path.
- [ ] Add deterministic launcher coverage for no profile, multiple profiles,
      missing optional and required mounts, `--persist`, attach, stop, remove,
      recreate, dry-run secret redaction, and invocation outside the Notty
      checkout.
- [ ] Build every documented Docker target retained in the release source and
      verify that no launcher or image target depends on a
      maintainer-specific path or an optional local helper.

## P2: Required Product and Documentation Polish

### Product Contract

- [ ] Use one shared agent/runtime/model catalog across Copilot and Collab.
- [ ] Present Codex, Agy, and Claude as agents.
- [ ] Present Ollama as a runtime, never as an agent or model.
- [ ] Support Ollama only with Codex unless a reviewed implementation changes
      that constraint.
- [ ] Always display `Agent + model`; append `via Ollama` when applicable.
- [ ] Do not infer the agent from a model family such as Opus or Sonnet.
- [ ] Remove only Agy's provider prefix from its displayed model name; preserve
      the full launch identifier internally.
- [ ] Preserve raw launch model IDs separately from display aliases.
- [ ] Keep Human coordinator mode worker-only and Agent mode exactly-one-
      coordinator.
- [ ] Mark Claude deprecated or Labs wherever it is not actively supported.

### First-Run Experience

- [ ] Replace the README opening with a product-level description.
- [ ] Put a safe five-minute quick start before internal architecture details.
- [ ] Document supported operating systems and exact prerequisites.
- [ ] Provide one recommended installation path.
- [ ] Show the expected URL and first successful screen.
- [ ] Document `notty auth init` (or its equivalent), one-time credential
      display, protected verifier storage, adding a unique MCP client,
      rotation/revocation, and local recovery.
- [ ] Guide the user through:
    1. initializing administrator and MCP-client Basic Auth;
    2. creating a terminal;
    3. highlighting terminal output;
    4. asking the Copilot;
    5. approving an optional command;
    6. reviewing a pending MCP request and explicitly issuing its one-time
       spawn grant.
- [ ] Add actionable dependency/preflight messages for Docker, tmux, agent
      login, Ollama connectivity, installed models, ports, and authentication.
- [ ] Add a `notty doctor` or equivalent diagnostic command.
- [ ] Normalize structured errors and provide retry/recovery actions.

### Public Documentation

- [x] Add `SECURITY.md` with the no-guaranteed-support policy and GitHub Private
      Vulnerability Reporting instructions.
- [ ] Add a threat model describing principals, trust boundaries, OTPs,
      terminal ownership, mounts, Ollama, and remote deployment.
- [x] Add `CONTRIBUTING.md` with test commands and scope expectations.
- [x] Add concise conduct expectations to `CONTRIBUTING.md`.
- [x] Add `CHANGELOG.md`.
- [ ] Add and validate a root `EXAMPLES.md` covering host-side MCP setup and
      agent updates, direct and Collab launches, browser and Tilix/tmux
      observation, legacy no-network work, and Nosh Guard learn/audit
      profiling. It must distinguish observation from enforcement and show
      that Guard evidence is host-owned, root-only, and absent from runner
      mounts; append-only writers and truncation detection are not WORM
      storage or protection from host root.
- [ ] Document what data hosted agents receive versus local Ollama.
- [ ] Document terminal, Collab message, feedback, and log retention.
- [ ] Provide purge/export commands for retained local data.
- [ ] Move deep testing, Durdraw, and configuration material out of the README
      into focused documents.
- [ ] Remove stale file-line citations and claims that no longer match code.
- [ ] Add page titles, descriptions, a social preview, screenshots, and a short
      scrubbed demo.

## CI and Release Automation

- [x] Add pull-request, branch, tag, and manual CI using the release audit's
      digest-pinned Node 24 toolchain; expand the matrix only after the final
      support decision.
- [x] In dedicated audit containers with a digest-pinned Node base, run the
      clean install, deterministic tests, and production build; never invoke
      npm on the host.
- [x] Run focused shell/Nosh tests as part of the deterministic container suite.
- [x] Run committed-range `git diff --check` in CI.
- [ ] Add and review a complete-history secret scan.
- [x] Inspect `npm pack --dry-run --json` even though npm publishing is deferred.
- [ ] Produce a reviewed, checksummed, container-built host installation
      bundle for `nosh-guardd`; do not use host `npm install --global`.
- [ ] Build and scan the supported production container target.
- [ ] Keep real provider tests manual or explicitly dispatched; never expose
      provider credentials to pull requests from forks.
- [ ] Require every security-control change to land with its focused
      regression tests instead of deferring tests to a final hardening pass.
- [ ] Add dependency update automation with reviewed grouping.
- [ ] Enable repository secret scanning and push protection.
- [ ] Require CI before merging the release branch.

Dependency maintenance and the baseline release audit:

```sh
# After reviewing package.json changes; then review and commit the new lock.
./scripts/regenerate-package-lock.sh

# Run only from the resulting clean, committed checkout.
./scripts/release-audit.sh
```

The lockfile command is a mutating maintenance tool, not release evidence. It
passes only `package.json` to a locked-down networked container, builds a fresh
lock without the old lockfile or `node_modules`, rejects non-registry sources
and production advisories, validates again with `--network none`, and replaces
the lock atomically. It never invokes a host package manager. Review and commit
its output before auditing; use `--replace-dirty-lock` only after reviewing
uncommitted lock output that should be discarded.

`release-audit.sh` remains the only host-side release validation command. It
requires Docker, Git, Python 3, and standard GNU tools, and it never falls back
to host `npm`, `npx`, or `node`. Dependency acquisition and advisory lookup
receive only the package manifests in networked containers. Native
rebuilds, tests, the production build, and package inspection run in a
separate no-network container; a no-network, no-script inventory also checks
an ephemeral copy of the full checkout for package leaks. Each valid run writes
`.release-audit/latest.md` (or the path selected with `--report`) with automated
evidence and the still-manual gates; it never edits this checklist. A custom
report must be outside the checkout or below its ignored `.release-audit/`
directory. The release-identity gate requires the captured `package.json`
version to equal this plan's release candidate and accepts only that exact tag
or the same tag prefixed with `v`.

Use a two-pass candidate workflow. First run the audit on the reviewed, clean,
committed dependency update while the candidate tag is absent. Resolve every
other automated failure and complete the applicable manual gates. Only when
the missing tag is the sole automated failure should the owner create the
immutable `v1.0.0` tag on that exact commit. Rerun the audit without
moving or reusing the tag.

Manual release validation:

- [ ] Start from a fresh supported Linux or WSL environment.
- [ ] Follow only the public quick start with no unpublished knowledge.
- [ ] Initialize unique administrator and MCP-client credentials and confirm
      loopback binding before creating a terminal.
- [ ] Confirm no OTP is active until the user explicitly approves one.
- [ ] Submit and review a pending request, complete one exact MCP spawn, then
      verify replay and modified-request rejection.
- [ ] Revoke an unused grant and verify rejection.
- [ ] Verify the agent cannot access another client's terminal.
- [ ] Verify terminal shells cannot read server credentials.
- [ ] Exercise Copilot highlight-and-Ask and Approve mode.
- [ ] Exercise Codex with hosted models through its default runtime.
- [ ] Exercise Codex via Ollama using an already-installed local model.
- [ ] Complete the required Agy real-runtime smoke or move Agy to Labs.
- [ ] Exercise Collab Human and Agent coordinator modes.
- [ ] Exercise the documented `--network none` example and confirm offline
      local work succeeds while external DNS/HTTPS access is denied.
- [ ] On a provisioned disposable Guard host, run separate positive and
      negative-control learn/audit profiles, inspect the root-owned evidence,
      and confirm standalone `enforce` fails closed rather than claiming
      allowlist confinement.
- [ ] Stop Notty and verify terminal, tmux, broker, and temporary-file cleanup.
- [ ] Inspect the final source archive and image contents manually.
- [ ] Record the tested commit, source checksum, and image digest and promote
      those exact artifacts without rebuilding them.

## Release Sequence

Recommended implementation order:

1. **Phase 0 — owner decisions and visibility freeze**
   - decide license, distribution, supported hosts/features, Basic Auth
     principals, ACL semantics, OTP TTLs, and resource-limit baselines;
   - keep the repository private until the visibility gate passes.
2. **Minimal CI and confidentiality hygiene**
   - run clean install, tests, build, whitespace, package-content, and secret
     checks on every change;
   - scan history, resolve provenance, purge runtime artifacts, and add the
     root license before public visibility.
3. **Threat model and complete surface matrix**
   - enumerate every HTTP, MCP, SSE, REST, broker, proxy, standalone, and
     WebSocket entrypoint;
   - assign each surface a principal, scope, Origin/CSRF, size, and rate policy.
4. **Authentication and binding, with tests**
   - implement locked bootstrap, loopback/container binding, supported proxy
     topology, scoped Basic Auth, and consistent route enforcement.
5. **Spawn grants and ownership, with tests**
   - implement pending review, fail-closed OTP state, atomic consumption,
     server-side terminal ACLs, reader isolation, and revocation.
6. **Delegation, isolation, and limits, with tests**
   - enforce Copilot/Collab leases, scrub child environments, isolate PTYs,
     remove default credential mounts, and add measured quotas.
7. **Repository and distribution completion**
   - finish package allowlists, dependency triage, container hardening,
     versioning, SBOM, and provenance.
8. **Product consistency**
   - finish the shared Agent/Runtime/Model contract, first-run recovery,
     provider consent, and Preview/Labs boundaries.
9. **Documentation and full release CI**
   - finish the public quick start, security/contribution/retention documents,
     supported container build, scans, and release automation.
10. **Release validation**
    - while `v1.0.0` remains absent, build immutable draft artifacts once,
      record their commit/checksums/digests, clean-room test those exact
      artifacts, and dogfood them.
11. **First public release**
    - close the Definition of Done, tag the exact tested commit as `v1.0.0`,
      rerun the audit, promote the tested artifacts without a rebuild, and
      publish notes, checksums, image digests, and known limitations.

## Decisions Requiring Owner Review

These choices should be explicit before implementation begins:

| Decision | Recommended starting point |
| --- | --- |
| Project license | 0BSD for Notty; preserve all third-party licenses |
| eBPF license | `0BSD OR GPL-2.0-only`; `Dual BSD/GPL` kernel loader designation |
| First version | `1.0.0` |
| Supported hosts | Linux and WSL first |
| Default bind | `127.0.0.1` |
| Remote access | TLS reverse proxy to a local/private upstream; no direct remote listener |
| Administrator authentication | Dedicated Basic Auth principal, initialized locally |
| MCP authentication | OAuth 2.1 authorization code + DCR + PKCE S256; OTP-only is loopback-only |
| Legacy OAuth/bearer auth | Singleton/client-credentials flow removed; `/oauth/token` returns 410 for one release |
| Credential storage | Hashed tokens/OTPs and grants in per-workspace `auth.sqlite3` mode 0600 |
| Terminal authorization | Server-side ACL keyed to principal; UUID is only a locator |
| Reconnect behavior | Owner survives reconnect; readers and temporary leases do not |
| OTP default TTL | Launcher-configured; currently 3600 seconds |
| OTP maximum TTL | Operator policy; positive finite values only when configured |
| Active OTPs | Persistent registry; each value remains single-use |
| OTP renewal | Never automatic; explicit user replacement only |
| Terminal sharing | Denied by default; explicit delegation only |
| Public distribution | GitHub release plus GHCR image |
| npm distribution | Deferred or scoped as `@xpatchdev/notty` |
| Security maintenance | No guaranteed supported version or SLA; latest stable is best effort |
| Private vulnerability reports | GitHub Private Vulnerability Reporting only |
| Contributions | Issue first; maintainer assigns branch; 0BSD; no CLA or DCO |
| Per-terminal locking | Opt-in `vlock`; never an application or isolation boundary |
| Collab status | Opt-in preview |
| Autonomous mode | Labs |
| Claude | Labs/deprecated in the supported context |

## Definition of Done

Notty is ready for `v1.0.0` only when all of the following are true:

- [ ] Every required P0, P1, P2, and release-automation item is complete.
- [ ] Every P0 security property is covered by deterministic tests.
- [ ] The service is loopback-only and fail-closed by default.
- [ ] The supported TLS proxy topology is tested and direct remote exposure is
      rejected.
- [ ] Basic Auth bootstrap, unique principals, scopes, rotation, and revocation
      are documented and tested.
- [ ] OTP authority is short-lived, single-use, user-issued, revocable, and
      never automatically refreshed.
- [ ] Every terminal has an enforced owner or delegation.
- [ ] Spawned processes cannot recover control-plane secrets.
- [ ] No runtime state or private machine data appears in source, package, or
      image artifacts.
- [x] A root license and third-party notices are present.
- [x] Regenerate the lockfile with the reviewed `hono@4.12.34` floor and prove
      that the queried advisory service reports no known production advisories.
- [ ] CI passes tests, build, package inspection, secret scan, and supported
      container build.
- [ ] The README gives a new user one safe, reproducible path to success.
- [ ] Security, contribution, retention, and known-limitations documents are
      published.
- [ ] A clean-machine release-candidate test succeeds without maintainer-only
      knowledge.
- [ ] The exact tested source checksum and image digest are promoted without a
      rebuild.
- [ ] Agy meets its Preview smoke threshold or is moved to Labs; both Collab
      coordinator modes pass their Preview smoke.
- [ ] The release notes distinguish Supported, Preview, and Labs features.

## Post-Release Defense-in-Depth Roadmap

These are concrete follow-up designs, not current command-line options and not
substitutes for the P0 controls. In particular, `v1.0.0` must already prevent
one agent from reading or using another agent's credentials. The first item
describes a preferred additional OS boundary, not permission to defer that
security outcome.

### Per-Agent Unix Identities

Run each managed agent under its own Unix user and private home while granting
only a shared collaboration group access to the project workspace. Derive the
final account list from the shared Agent/Runtime/Model catalog; an illustrative
layout is:

| Agent account | UID | Collaboration group |
| --- | ---: | --- |
| `codex` | 1001 | `agents` (GID 2000) |
| `agy` | 1002 | `agents` (GID 2000) |
| `claude` | 1003 | `agents` (GID 2000) |

| Path | Ownership and mode | Purpose |
| --- | --- | --- |
| `/app` | `root:root`, read-only | Immutable platform and application files |
| `/src` | `root:agents`, shared read/write | Intentional collaboration workspace |
| `/home/codex` | `codex:codex`, `0700` | Codex config, cache, history, and credentials |
| `/home/agy` | `agy:agy`, `0700` | Agy config, cache, history, and credentials |
| `/home/claude` | `claude:claude`, `0700` | Claude config, cache, history, and credentials |

The design should:

- keep provider credentials out of shared environment variables and writable
  project paths;
- use normal Unix permissions as the primary isolation boundary, with narrower
  modes for credential files;
- preserve intentional collaboration through `/src` without granting access to
  peer homes;
- treat `/src` as an intentional shared integrity boundary: an agent that can
  modify source, hooks, or package metadata may influence what another agent
  later executes;
- avoid executing peer-writable code with reusable provider credentials; use
  isolated workspaces and short-lived, scoped broker capabilities when agents
  are mutually untrusted;
- add an explicit observation broker for tmux output instead of sharing a tmux
  socket across users;
- keep platform files immutable to agent accounts; and
- optionally use eBPF/Tetragon to report attempted cross-agent or immutable-path
  access, not as a replacement for filesystem isolation.

Acceptance tests should prove that each agent can collaborate in `/src`, cannot
read or modify another agent's private state, cannot modify `/app`, and cannot
use a temporary broker capability after its lease ends.

Separate UIDs block direct filesystem access but do not, by themselves, satisfy
the P0 requirement that one agent cannot *use* another agent's authority. The
credential broker, execution policy, and shared-workspace model must close
indirect paths such as peer-written hooks or launch configuration.

### Clean-Room Network Observation

Add a `clean-room-network` mode for workloads assumed to need no network. Deny
all ingress and egress while host-side sensors record attempted DNS names,
literal-IP connections, protocols, ports, process attribution, loss counters,
and timestamps. Retain evidence across long idle windows so a dependency that
tries to phone home six hours after launch remains visible.

The recorder must not resolve or forward DNS, allow the attempted connection,
auto-allow observed destinations, or silently convert observations into policy.
Its evidence must remain host-owned and absent from runner mounts. This differs
from legacy `--network none`, which blocks traffic but cannot by itself preserve
an attempted-network audit trail.

### Stronger Audit-Evidence Integrity

Extend the current root-owned Guard evidence and append-opened shared
DNS/gateway logs with signed or keyed manifests, hash-chained records, periodic
external checkpoints, and immutable or remote retention when the threat model
includes a privileged host writer. Until then, documentation must continue to
state that append-only file descriptors and truncation detection are not WORM
storage and do not protect against host root.

## Deliberate Non-Goals Before `v1.0.0`

Do not delay the release for:

- a TypeScript rewrite;
- a wholesale split of every large module;
- support for every operating system or model provider;
- a hosted Notty service;
- stabilization of every XR, ANSI, Durdraw, hardware, or legacy swarm feature;
- delivery of the dedicated clean-room network observation mode described in
  the post-release roadmap;
- separate Unix users and homes for every agent, provided the release still
  enforces equivalent per-agent credential isolation before `v1.0.0`;
- WORM, externally checkpointed, or cryptographically authenticated Guard
  evidence beyond the accurate append-only and tamper-detection claims required
  for `v1.0.0`;
- automatic OTP refresh for convenience.

The release should earn trust through a small supported surface, strict user
control, and reproducible behavior—not through a larger feature count.
