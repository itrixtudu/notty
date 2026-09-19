# Security Review

> Review date: 2026-09-01
> Reviewed application revision: 402aebf9934f2293ca5aa76d122d0f1f18d05fbb
> Release tag inspected: v1.0.0
> Method: static review plus inspection of the release-audit report and console transcript
> Decision: **No-go for public, multi-user, or mutually untrusted-agent deployment**

## Executive summary

Notty is a shell-control plane. A successful authorization decision can create
processes, disclose terminal output, submit commands, change agent permission
modes, and affect network enforcement. Authentication, object ownership,
controller/worker privilege separation, and bounded resource use are therefore
primary security boundaries.

The two Critical blockers in the 2026-08-11 review are materially fixed.
Authentication now defaults on, weakened modes are restricted to loopback,
origin handling is exact, the integrated server applies one gate across the
HTTP, WebSocket, MCP, and Next.js paths, and raw Next.js API startup fails
closed. OAuth and spawn-OTP handling have also been substantially redesigned.
No current Critical finding was identified in the reviewed configuration.

The release candidate is not yet ready for hostile multi-user or mutually
untrusted-agent use. The largest remaining issue is that trusted controller
state and untrusted terminal/agent workloads still share operating-system
identities and writable state. Terminal objects and Collab operations are also
process-global rather than principal-owned. Consequently, a valid client or a
compromised agent can cross boundaries that the external authentication layer
appears to establish.

Availability boundaries are incomplete. Persistent readers can defeat the
nominal terminal-buffer ceiling, terminal and reader creation lack useful
quotas, and invalid WebSocket operations can escape the per-message handler.
Autonomous Copilot also deliberately turns model output influenced by
untrusted terminal text into commands without an independent per-command
authority. That mode remains a High accepted risk unless it is constrained to
a disposable, secret-free environment.

Guard mode has strong fail-closed design elements: exact runner identities,
gated startup, mTLS-bound principals, signed enforcement-activation artifacts, hardened
containers, scoped cleanup, and explicit refusal of unsupported full
enforcement. Its eBPF FQDN rules are nevertheless DNS-derived L3/L4 grants,
not hostname enforcement, and several live assurance and independent-watchdog
gates remain open. The production Docker path also sends a broad checkout
context, executes an unverified remote installer, and retains a root runtime
in the primary image.

The generated release audit and accompanying console transcript for the
reviewed commit passed the automated checks: 35 passes, zero failures, 828
tests with 827 passing and one skipped, a successful offline production
build/package inspection, and zero known root-production npm vulnerabilities
at audit time. That is useful evidence, but it does not close the audit's four
manual gates: history/secrets, legal/art provenance, production-image review,
and live security smokes.

This review records:

- 9 High findings
- 7 Medium findings
- 0 Low or Critical findings

The appropriate status is controlled pre-release testing, not a stable public
release. A loopback, single-operator test environment is reasonable when
autonomous execution is off and provider mounts are minimized. Guard-protected
tests are also reasonable when their live prerequisites and containment
behavior are verified.

## Scope and threat model

### Reviewed areas

- Authentication modes, Basic authentication, OAuth, origins, and spawn OTPs
- MCP HTTP/SSE sessions and tool dispatch
- Terminal HTTP, WebSocket, PTY, buffering, and reader management
- Collab, agent launch, tmux ownership, permission changes, and coordination
- Copilot leases, analyzer isolation, MCP broker, and autonomous execution
- Nosh legacy launch behavior and provider-state mounts
- Nosh Guard admission, runner specifications, gateways, policy grants,
  watchdogs, cleanup, build profiling, and eBPF enforcement
- Next.js headers, proxy entrypoints, Docker contexts/images, install scripts,
  package/release scripts, and host-bundle generation
- The generated .release-audit/latest.md report and accompanying console
  transcript for the captured revision

### Assumed adversaries

- An unauthenticated client that can reach any listener
- An authenticated client that must not control another client's resources
- A compromised or malicious agent that can execute as its assigned worker
- A repository, startup file, command output, or terminal program that controls
  text seen by an agent or Copilot analyzer
- A same-container process that can reach loopback services
- A malicious DNS answer, shared hosting destination, dependency source,
  build-time download, or Docker daemon
- An operational failure that wedges the Node event loop, Docker, a collector,
  an enforcement helper, or cleanup

### Trust-boundary rule

External authentication is not sufficient if the authenticated controller,
terminal workload, and multiple agents all become the same Unix principal.
Shared source-tree group access may be appropriate, but it must not imply
access to auth databases, service environments, agent credentials, terminal
objects, runtime sockets, Docker, Guard management, or signing material.

### Review limitations

The application review was static. Source was read and traced, but exploit
proofs, browser tests, kernel program loading, live provider logins, firewall
mutation, and Guard failover were not performed. The release-audit report and
console transcript below were inspected rather than rerun. Runtime-dependent
impacts are labeled accordingly.

The reviewed application revision was clean when the cited audit ran. This
document and the separate workflow/TODO documents are later documentation
changes and must receive their own final clean-tree audit before release.

## Findings summary

| ID | Severity | Confidence | Finding |
| --- | --- | --- | --- |
| SR-01 | High | Confirmed | Trusted auth state and untrusted workers share an identity and writable database |
| SR-02 | High | Confirmed | Terminal and reader objects have no principal ownership authorization |
| SR-03 | High | Confirmed | Collab trusts loopback peers and caller-selected identities and targets |
| SR-04 | High | Confirmed / runtime impact likely | Reader retention and WebSocket handling expose denial-of-service paths |
| SR-05 | High | Confirmed accepted risk | Autonomous Copilot can execute model output derived from untrusted terminal text |
| SR-06 | High | Confirmed | Legacy Nosh mounts broad provider state read/write and often grants full agent access |
| SR-07 | High | Confirmed | FQDN eBPF rules are DNS-derived address grants rather than hostname enforcement |
| SR-08 | High | Confirmed | Docker build context can include ignored provider and local secret state |
| SR-09 | High | Confirmed | Production image construction executes unverified installers and retains root |
| SR-10 | Medium | Confirmed | OAuth registration and spawn-OTP lifecycle controls permit state exhaustion or weak grants |
| SR-11 | Medium | Confirmed | Copilot broker follow-up messages are not bound to the initial capability |
| SR-12 | Medium | Confirmed design gap | Guard needs independent liveness, revocation, and recurring live-state assurance |
| SR-13 | Medium | Confirmed | Guard host-bundle provenance does not bind copied bytes to the recorded Git commit |
| SR-14 | Medium | Confirmed | Browser policy retains unsafe script capabilities and broad outbound reach |
| SR-15 | Medium | Confirmed | The stdio HTTP proxy permits unsafe plaintext targets and secret-bearing debug logs |
| SR-16 | Medium | Confirmed | The bpr helper can continue after a failed build and launch a stale insecure image |

## Detailed findings

### SR-01 — Trusted auth state and untrusted workers share an identity and writable database

**Severity:** High

**Confidence:** Confirmed

**Evidence**

- nosh.sh:516-560 creates the host auth-state location and prepares the
  container path; nosh.sh:2846-2862 mounts that state read/write and supplies
  Basic/spawn secrets to the container environment.
- Dockerfile.nosh:208-225 runs the server and agent-capable targets as the same
  notty user.
- lib/terminalManager.js:246-250 and lib/childEnvironment.cjs:3-61 remove known
  Notty variables with a denylist but otherwise inherit the service
  environment.
- lib/guardd/runner-spec.js:87-114 and 324-355 repeat the central problem: auth
  state is owned by the runner identity, mounted read/write, and the runner
  process uses that identity.
- lib/authState.js:245-353, 406-463, and 479-524 rejects wrong ownership, weak
  modes, symlinks, hard links, and schema drift. Those checks protect against
  other identities; they cannot protect the file from the identity that is
  intentionally authorized to write it.

**Impact**

A terminal or agent running as the service user can read, corrupt, revoke, or
construct structurally valid SQLite authentication state. It can cause a
denial of service and, with knowledge of the schema, create hashes for
attacker-chosen capability values. Same-UID process inspection may also expose
service environment secrets depending on procfs policy. This defeats the
intended controller/worker distinction even when external authentication is
correct.

**Recommendation**

- Run the authentication terminator and state owner as a distinct service UID
  or isolated controller container.
- Make the auth database inaccessible to terminal and agent identities.
- Expose only a narrow authenticated Unix-socket operation broker; authorize
  it with peer credentials and short-lived, purpose-bound capabilities.
- Give agents distinct UIDs and private homes. Use a positive allowlist for
  child environment construction instead of copying then denying names.
- Treat a shared source group as filesystem collaboration only.

**Required regression evidence**

An agent must fail to read or write the database, inspect the controller
environment, insert a known OTP hash, revoke OAuth families, or contact the
broker outside its own allowed operations.

### SR-02 — Terminal and reader objects have no principal ownership authorization

**Severity:** High

**Confidence:** Confirmed

**Evidence**

- lib/terminalManager.js:21-33 stores terminal sessions in one process-global
  collection without an owning principal.
- lib/createMcpServer.js:20-60 dispatches a tool name and arguments without
  carrying the authenticated principal into object operations.
- lib/terminalHttpApi.js:90-164 exposes global list, read, write, resize, and
  kill operations.
- lib/mcpTools.js:19-24 and 329-610 expose the same global controls; the
  persistent MCP reader identity is shared rather than principal-bound.
- lib/terminalWsHandlers.js:88-138 attaches to a caller-selected terminal ID
  and then permits control without an ownership check.
- lib/mcpHttpServer.js does bind transport sessions to exact authorization
  identities. That binding currently stops at tool dispatch and does not
  protect the resource selected by a tool call.

**Impact**

Any authenticated client able to enumerate or learn a terminal identifier can
read another client's transcript, inject commands, resize it, or terminate it.
Reader handles can similarly cross callers. This is a horizontal
authorization failure and makes multi-user operation unsafe.

**Recommendation**

- Add an immutable owner principal and optional explicit delegates to every
  terminal, reader, Copilot binding, and agent object.
- Pass a normalized authorization context through HTTP, WebSocket, MCP, and
  local operations; enforce it inside the manager rather than at route edges.
- Filter inventory by principal and replace raw global identifiers with
  opaque, principal-bound handles.
- Reserve cross-principal attach/control for an explicit audited administrator
  operation with a separate capability.

**Required regression evidence**

Create objects as principals A and B across every transport. B must be unable
to list, infer, read, write, resize, kill, subscribe to, or reuse A's objects,
including after reconnect and server restart.

### SR-03 — Collab trusts loopback peers and caller-selected identities and targets

**Severity:** High

**Confidence:** Confirmed

**Evidence**

- lib/collabSupervisor.js:25-36 and 126-135 use a loopback HTTP service without
  a per-request capability.
- lib/collabSupervisor.js:225-316 validates a marker, version, and workspace,
  but not a caller authority tied to an agent identity.
- collab.cjs:3427-3471 treats loopback peer/Host/Origin properties as the
  administrative trust boundary.
- collab.cjs:3488-3500 accepts a caller-supplied operator header.
- collab.cjs:3503-3642 permits creation, stop, relaunch, permission changes,
  commands, health changes, and configuration mutations.
- collab.cjs:3007-3157 and 3733-3901 allow MCP clients to supply agent identity
  and coordination data; tmux targets are accepted as caller-selected values
  and used by the control path around collab.cjs:1090-1097 and 2019-2049.

**Impact**

A process inside the container can impersonate an operator or peer, read or
control another agent's tmux pane, claim coordination work, stop or relaunch
agents, and request permission changes. Basic authentication on the outer
/api/collab route does not protect a direct call to the loopback daemon.

**Recommendation**

- Split operator administration from agent coordination.
- Put administration on a mode-0600 Unix socket and verify peer credentials
  plus a purpose-bound capability.
- Assign identity and tmux target server-side; an agent capability should
  permit only its own channel, pane, health, and work claims.
- Bind each capability to workspace, session, role, expiry, and operation set;
  revoke it immediately on stop, halt, or relaunch.
- Make OTP/capability timers, renewal, interrupt, and halt visible control-plane
  operations rather than trusting a caller label.

**Required regression evidence**

From agent A, attempt every operator method, impersonate B, select B's pane,
change B's permission mode, and reuse an expired/revoked token. Every attempt
must fail without disclosing whether an unauthorized target exists.

### SR-04 — Reader retention and WebSocket handling expose denial-of-service paths

**Severity:** High

**Confidence:** Defect confirmed; final process impact not dynamically exercised

**Evidence**

- lib/terminalManager.js:16-18 defines a nominal 10 MiB buffer limit.
- lib/terminalManager.js:448-475 trims according to the oldest reader pointer.
  A persistent abandoned pointer can remain at zero and prevent trimming.
- lib/mcpTools.js:390-450 opens and retains readers without meaningful
  per-principal quotas, TTLs, or a global hard ceiling.
- No effective global/per-principal terminal, reader, or MCP-session quota was
  identified.
- lib/terminalWsHandlers.js:112-138 catches JSON parsing but does not contain
  exceptions from each requested operation.
- lib/terminalManager.js:199-206 accepts any positive integer dimensions
  without a practical maximum; invalid values throw.
- server.js:738-805 creates the WebSocket service but does not set an explicit
  payload ceiling, per-client message rate, or backpressure policy.

**Impact**

An authenticated client can retain output indefinitely, create many objects,
or send abusive dimensions/payloads. Invalid resize or other operation errors
can escape the callback and may terminate or destabilize the Node process.
The result is cross-user denial of service and potentially unbounded memory
growth.

**Recommendation**

- Enforce a hard ring-buffer cap independent of reader position; report
  explicit loss/gap state to lagging readers.
- Add per-principal and global terminal, reader, subscription, and session
  quotas with idle TTLs.
- Bound columns, rows, input size, history size, and output rate.
- Configure WebSocket maxPayload, rate limits, bounded send queues, and
  backpressure/slow-client eviction.
- Strictly validate every frame and contain all operation errors inside the
  message handler with a safe close/error response.

**Required regression evidence**

Exercise abandoned readers, slow WebSockets, oversized frames, invalid and
huge dimensions, subscription floods, and rapid terminal creation under an
external process supervisor. Memory must remain bounded and the server must
remain alive.

### SR-05 — Autonomous Copilot can execute model output derived from untrusted terminal text

**Severity:** High

**Confidence:** Confirmed accepted risk

**Evidence**

- lib/copilotMcpBroker.js:120-170 correctly prevents the analyzer role from
  directly submitting terminal input.
- lib/copilotManager.js:342-363 labels automatic-analyzer terminal context as
  untrusted; 908-935 bounds and JSON-frames those automatic prompts.
- lib/copilotManager.js:1241-1252, 1522-1544, and 1630-1658 make autonomous
  mode explicit, time-bound, and subject to confirmation/renewal.
- lib/copilotManager.js:252-268 constrains proposed commands to one bounded
  line, and shell-readiness checks reduce accidental injection.
- lib/copilotManager.js:1703-1770 nevertheless executes a visible role's model
  command without an independent per-command decision once the autonomous
  lease is active and confirmed, promptReady is true, and no alternate screen
  is active.

**Impact**

Terminal output controlled by an untrusted repository, build, service, escape
sequence, or remote peer can influence the model that chooses the next command.
Prompt text and readiness markers reduce mistakes but are not independent
authorization. During a valid lease, indirect prompt injection can become
shell command execution with the Copilot runtime's filesystem and network
authority.

**Recommendation**

- Require a non-model, per-command human capability for commands affecting the
  host, credentials, network, policy, or persistent source.
- If true autonomy is retained, constrain it to a disposable Guard runner with
  a distinct UID, no provider/auth secrets, an immutable or throwaway
  workspace, default-deny egress, and strict command/resource ceilings.
- Make the accepted risk explicit in UI text and audit records. Do not describe
  promptReady or terminal markers as authorization.

**Required regression evidence**

Maintain a prompt-injection corpus covering terminal output, filenames, ANSI
sequences, shell prompts, build logs, and agent messages. Verify that no case
can cross the independent authority boundary.

### SR-06 — Legacy Nosh mounts broad provider state read/write and often grants full agent access

**Severity:** High

**Confidence:** Confirmed

**Evidence**

- nosh.sh:1296-1317 mounts the host $HOME/.codex directory read/write, while
  auth.json, config.toml, and present *.config.toml files are overmounted
  read-only.
- nosh.sh:1707-1713 mounts $HOME/.gemini and $HOME/.claude read/write.
- config/nosh-profiles.json:3-160 repeats broad provider-directory mounts for
  Codex, Gemini, Claude, and agent profiles.
- agents/bin/swarm.lib.sh:816-839 and lib/collab/session.cjs:71-79 and 665-671
  default Codex/Ollama to full access in Nosh/container environments.
- The legacy workspace mount is writable and legacy is the default security
  mode in nosh.sh:2787-2808 and 3015-3029.
- README.md warns about provider-state mounts, confirming that the exposure is
  intentional rather than accidental; the warning does not contain a
  compromised worker.

**Impact**

A compromised terminal or agent can read, alter, or destroy durable host
provider configuration, credentials, conversation/session state, hooks, and
trusted instructions. Writable shared state also enables persistence and
cross-agent compromise.

**Recommendation**

- Replace whole-directory mounts with file-level, role-specific, read-only
  inputs or a credential broker issuing short-lived scoped tokens.
- Give each agent a private home and writable cache that is not mounted from
  the host or shared with peers.
- Make sandboxed/read-only the default for every agent family. Require a
  visible, expiring opt-in for broader workspace access.
- Prefer Guard mode for any untrusted repository or agent.

**Required regression evidence**

Run each agent family and prove it cannot enumerate, modify, rename, or delete
another provider's state, the host provider root, auth material, or a peer's
private home while still supporting the intended login flow.

### SR-07 — FQDN eBPF rules are DNS-derived address grants rather than hostname enforcement

**Severity:** High when relied on as hostname isolation

**Confidence:** Confirmed

**Evidence**

- bpf/nosh_egress/README.md:62-74 explicitly describes FQDN policy as bounded
  DNS-derived L3/L4 grants with a maximum lifetime, not TLS hostname control.
- bpf/nosh_egress/nosh_egress.bpf.c:639-675 keys grants by generation, address
  family, protocol, port, and destination address.
- bpf/nosh_egress/nosh_egress.bpf.c:1381-1460 creates tuple grants for matched
  domain rules after validated DNS answers; 1648-1707 processes A/AAAA
  answers; 1800-1833 enforces at connect time.
- bpf/nosh_egress/README.md:62-84 and the BPF path at 1620-1731 and 1780-1797
  require a previously matched question and a complete bounded,
  positive-TTL-correlated A/AAAA response. One CNAME hop is supported, TTL is
  capped at 300 seconds, malformed or ambiguous coverage is mode-aware, and
  exact configured platform-containment endpoints remain denied.
- bpf/nosh_egress/README.md:34-40 states that private, link-local, and related
  ranges are not universal hardcoded containment.

**Impact**

Once a tuple grant exists, a workload may contact another virtual host or
application protocol on the same IP and permitted transport/port. It cannot
cross an unapproved port or transport, but the kernel key cannot distinguish
TLS SNI, certificate name, HTTP Host, or application protocol within that
tuple. Shared CDNs are the common case. A malicious or compromised
authoritative zone or configured resolver can also resolve a reviewed name to
an unintended special-use or private destination. A UI list of domains would
therefore overstate what the kernel rule actually enforces.

**Recommendation**

- Label this feature everywhere as DNS-derived IP/protocol/port policy.
- Reject private, loopback, link-local, multicast, and other special-use DNS
  answers unless the exact range is separately reviewed and signed.
- For genuine domain enforcement, force web traffic through an L7 proxy that
  binds DNS, destination, TLS SNI/certificate, and HTTP Host, while blocking
  direct TCP and QUIC bypasses.
- Keep per-agent learned profiles separate and bind them to exact agent,
  workspace, image, tool version, and policy revision.

**Required regression evidence**

Test shared-CDN alternate hosts, DNS rebinding, CNAME chains, TTL expiry,
private/special-use answers, direct IP access, TLS SNI mismatch, HTTP Host
mismatch, and QUIC bypass in audit and enforce modes.

### SR-08 — Docker build context can include ignored provider and local secret state

**Severity:** High

**Confidence:** Confirmed

**Evidence**

- .gitignore:4 excludes the repository-root .gemini directory.
- .dockerignore:1-34 does not exclude .gemini, .codex, .claude, .ssh, .npmrc,
  or comparable local secret/configuration paths.
- A repository-local ignored .gemini/settings.json exists in the reviewed
  checkout. Its contents were not inspected.
- Dockerfile:26-27 uses COPY . ., and build-nosh.sh:174-182 sends the current
  checkout as the build context.

**Impact**

Ignored local credentials or configuration can be sent to the Docker daemon,
including a remote or compromised daemon, and can be embedded in intermediate
layers or the final image. Git cleanliness and npm package inventory do not
prove Docker-context cleanliness.

**Recommendation**

- Add anchored deny rules for all credential, provider, state, report, VCS,
  editor, socket, and local override paths, then allowlist only required
  context roots.
- Build release images from a clean Git archive or a generated minimal context
  outside the checkout.
- Record and review the context digest and final image filesystem inventory.
- Treat a remote Docker daemon as a separate trust boundary.

**Required regression evidence**

Seed canary secret files in every ignored provider/location and prove they are
absent from the transmitted context, all image layers, exported filesystem,
SBOM, and build logs.

### SR-09 — Production image construction executes unverified installers and retains root

**Severity:** High

**Confidence:** Confirmed

**Evidence**

- Dockerfile:9-17 downloads an installer and pipes it to a privileged shell
  without a pinned content digest or signature.
- Dockerfile:21-30 combines dependency installation, compilation, source, and
  runtime content in one image.
- The primary Dockerfile has no final USER instruction, so the application
  runtime remains root.
- Dockerfile.nosh:101-109 also installs global CLI tooling outside the
  application's reviewed lockfile and uses a remote installer.
- Dockerfile.nosh does have a non-root base runtime at 208-211, uses it for
  local/agent targets at 217-225, and verifies the Ollama artifact hash at
  253-292. These are positive controls but do not close the other image paths.
- .release-audit/latest.md:95-97 warns that Debian audit-tool packages are
  resolved at build time rather than snapshot-pinned.

**Impact**

A compromised mutable installer or package source receives build-time code
execution and can persist in the image. A root application runtime turns a
server-side or dependency compromise into root inside the container and
increases the impact of dangerous mounts/capabilities.

**Recommendation**

- Replace remote shell installers with versioned artifacts verified by digest
  and, where available, independent signatures/provenance.
- Use a minimal multi-stage production image that copies only the verified
  runtime output and runs as a dedicated non-root UID.
- Lock global CLI and Python transitive dependencies, or isolate them from the
  production server image.
- Produce an SBOM, image filesystem inventory, vulnerability scan, base-image
  digest, build-context digest, and signed provenance for the released image.

**Required regression evidence**

The production-image manual gate must inspect every layer, user, entrypoint,
capability, mount expectation, package origin, executable, and secret canary.

### SR-10 — OAuth registration and spawn-OTP lifecycle controls permit state exhaustion or weak grants

**Severity:** Medium

**Confidence:** Confirmed

**Evidence**

- server.js:452-454 exposes the standards-compatible dynamic registration path
  from lib/oauthService.js:507-548 before user authentication.
- lib/oauthService.js:633-698 persists a client row per accepted registration;
  no practical per-origin/IP quota, database budget, expiry, or pruning path
  was identified.
- lib/mcpSpawnOtp.js:19-25 and 228-251 accept a caller-supplied OTP as an
  arbitrary nonempty trimmed string without a length floor.
- lib/mcpSpawnOtp.js:38-47 permits no expiry when used outside Nosh defaults.
- lib/mcpSpawnOtp.js:83-104 and 197-216 return retained grant metadata without
  pagination/pruning or a practical global cap.
- Generated OTPs are strong, values are hash-only, and consumption is atomic.
  Nosh defaults expiry to one hour. Those are important positive controls.

**Impact**

An unauthenticated remote party can grow the OAuth database through valid
registrations. Any Basic-authenticated UI caller, or an authorized Guard
operator, can accidentally issue a guessable or non-expiring spawn capability.
Retained grant history can create slow queries or unbounded state over a
long-lived service.

**Recommendation**

- Rate-limit registration, authorization, token, Basic, OTP, and recovery
  paths; cap total clients and state bytes per deployment.
- Expire/prune unused dynamic registrations and old OTP metadata.
- Generate OTPs server-side with at least 128 bits of entropy and remove
  caller-supplied values.
- Make one hour the global default maximum unless a shorter policy applies;
  cap active grants and paginate/aggregate dashboard history.

**Operational note**

An OTP gates terminal spawning; it is not general MCP authentication. Testing
an OAuth-disabled MCP workflow must remain loopback/single-operator or use a
strong outer boundary, because non-spawn tools may still disclose or control
existing resources.

### SR-11 — Copilot broker follow-up messages are not bound to the initial capability

**Severity:** Medium

**Confidence:** Confirmed

**Evidence**

- lib/copilotMcpBroker.js:216-239 and 270-293 validate the initial binding
  token during connection setup.
- lib/copilotMcpBroker.js:295-315 accepts later /message requests using session
  ID, binding, and role without revalidating that capability.
- lib/copilotMcpBroker.js:194-204 and 334-341 place the Agy capability in a
  query URL.
- Individual tools recheck binding roles and active leases around
  lib/copilotMcpBroker.js:102-171, limiting but not eliminating the session
  takeover consequence.

**Impact**

A process that learns the binding ID, asserted role, and live session
identifier can inject messages without the connection capability. URL
credentials are also more likely to appear in logs, history, diagnostics, and
intermediary metadata.

**Recommendation**

- Require a bearer/capability on every POST and bind it to transport, role,
  binding, session, expiry, and operation.
- Use a one-use short-lived ticket for the initial SSE handshake and rotate to
  an in-memory channel capability.
- Never place bearer material in URLs. Add session quotas, idle TTLs, and
  replay detection.

### SR-12 — Guard needs independent liveness, revocation, and recurring live-state assurance

**Severity:** Medium

**Confidence:** Confirmed design gap; mode-dependent impact

**Evidence**

- lib/guardd/server.js:508-518 runs the watchdog in the same Node event loop as
  the controller it watches.
- lib/guardd/service.js:2659-2801 performs meaningful drift checks while the
  service remains responsive.
- deploy/systemd/nosh-guardd.service:8-18 restarts the daemon and invokes
  fail-closed cleanup after exit, but has no external readiness/watchdog
  heartbeat contract.
- scripts/nosh-guard-fail-closed.mjs:5-38 acts after failure/termination;
  docs/nosh-guard.md:1815-1848 acknowledges the residual liveness boundary.
- lib/guardd/ebpf-activation-store.js:559-690 verifies activation transitions,
  but grant expiry does not invalidate current root-owned activation state or
  stop it authorizing a later matching egress-enforce run. Existing per-run
  attachments end through run containment and cleanup, not activation expiry.
- The public Guard CLI exposes activate/status but no equally clear
  deactivate/revoke/renew lifecycle for root-owned activation state.
- lib/guard/review/gateway-host.js performs strong exact verification at
  activation and requested status. No independent recurring host-gateway
  attestor and negative functional probe were identified. Per-run Guard does
  perform recurring checks, but only in the daemon event loop cited above.
- The unit at deploy/systemd/nosh-guardd.service:9-10 and 28-50 runs the daemon as root
  with strong filesystem/process hardening but no CapabilityBoundingSet or
  SystemCallFilter. docs/nosh-guard.md:1850-1864 explicitly acknowledges its
  broad Docker, eBPF, AppArmor, cgroup, and network-namespace authority.

**Impact**

If the event loop wedges, the in-process watchdog also stops. Pinned
scoped-eBPF links/maps are expected to keep enforcing while the kernel remains
healthy, but in-process drift detection and lifecycle/cleanup stop. Learn and
audit modes intentionally allow ordinary traffic, so a hang can prolong an
observation and invalidate evidence rather than bypass promised denial. Full
enforce mode is rejected entirely. Systemd cleanup does not act on a
spontaneous hang until an administrator or supervisor terminates the process.
Operators may also confuse authorization-grant expiry with the lifetime of
root-owned activation state. Root Node control concentrates a large trusted
computing base.

**Recommendation**

- Add an independent supervisor heartbeat that quarantines runners on missed
  deadlines and proves the containment action externally.
- Run recurring exact-state attestations plus negative/positive network probes.
- Define explicit activate, renew, revoke, deactivate, status, and emergency
  containment semantics; display grant expiry separately from policy lifetime.
- Reduce the privileged TCB to a small broker and run policy orchestration
  unprivileged with capability/syscall restrictions.

### SR-13 — Guard host-bundle provenance does not bind copied bytes to the recorded Git commit

**Severity:** Medium

**Confidence:** Confirmed

**Evidence**

- scripts/build-nosh-guard-host-bundle.sh:228-251 mounts the live checkout into
  the isolated builder.
- scripts/build-nosh-guard-host-bundle-container.sh:222-252 and 307-410
  recursively copies selected BPF and source roots from that live mount.
- The same script at 432-456 records the current Git commit.
- The generated internal manifest protects the resulting bundle from later
  modification, but it does not prove the copied inputs were the bytes in the
  recorded Git tree.

**Impact**

Modified tracked bytes and ignored or untracked additions beneath recursively
copied source roots can be packaged and attributed to a clean HEAD. The result
can be internally consistent while its source provenance claim is false.

**Recommendation**

- Export inputs with git archive from the captured commit, or independently
  compare every copied byte and mode to that tree.
- Reject dirty or untracked files in any bundle input namespace.
- Record the commit, tree, source-archive digest, builder image digest, bundle
  manifest digest, and reproducibility result.
- Sign release provenance when bundles leave the local host.

### SR-14 — Browser policy retains unsafe script capabilities and broad outbound reach

**Severity:** Medium

**Confidence:** Confirmed

**Evidence**

- next.config.mjs:6-16 permits unsafe-eval, blob script sources, inline styles,
  and broad HTTPS/WSS connection destinations.
- next.config.mjs:34-47 installs CSP and permissions policy headers but omits
  several common production headers/directives, including a narrow base/form
  policy, nosniff, Referrer-Policy, and COOP.
- The production build warns that dynamic filesystem access in
  lib/authState.js:356-401 causes Turbopack to trace the whole project into
  server output.
- No exploitable React HTML sink was identified in this review. The issue is
  blast-radius reduction and output inventory, not a demonstrated XSS.

**Impact**

If any script injection is later found, unsafe evaluation and broad connect
destinations make capability theft and exfiltration easier. The browser can
hold terminal content and live one-time control capabilities, so its policy
deserves a narrow production profile. Broad server tracing can also package
unintended source/assets.

**Recommendation**

- Use production nonce/hash-based scripts and remove unsafe-eval/blob where
  framework requirements permit.
- Restrict connect-src to the exact configured HTTP/SSE/WebSocket endpoints.
- Add base-uri none, an appropriate form-action, nosniff, Referrer-Policy, and
  COOP. Tighten the existing frame-ancestors from self to none if embedding is
  not required; enable HSTS only at the confirmed TLS edge.
- Resolve or explicitly suppress the Turbopack dynamic-tracing warnings and
  inventory standalone output before publishing.

### SR-15 — The stdio HTTP proxy permits unsafe plaintext targets and secret-bearing debug logs

**Severity:** Medium

**Confidence:** Confirmed

**Evidence**

- stdio-http-proxy.js:63-75 accepts HTTP endpoints without requiring loopback.
- With debug enabled, stdio-http-proxy.js:88-104 logs the complete target URL.
- stdio-http-proxy.js:135-155 can log complete MCP request/response messages
  when debug logging is enabled.
- Target URLs are not required to reject embedded user information or
  secret-bearing query parameters.

**Impact**

Remote plaintext transport permits interception or modification. URL
credentials and debug payloads can leak OAuth tokens, OTPs, prompts, terminal
content, tool arguments, and results into process logs.

**Recommendation**

- Permit HTTP only for exact loopback targets unless a visibly named insecure
  development override is used; require verified HTTPS remotely.
- Reject URL userinfo and query credentials. Supply Authorization from a
  protected secret source.
- Make debug logs metadata-only with bounded, structured redaction.

### SR-16 — The bpr helper can continue after a failed build and launch a stale insecure image

**Severity:** Medium

**Confidence:** Confirmed developer/release hazard

**Evidence**

- bpr.sh:1-5 references Dockerfile.prod, which is absent in the reviewed tree,
  and lacks fail-fast shell options, so a failed build can be followed by later
  run commands.
- bpr.sh:7-9 launches the mutable ntty tag, publishes a host port on all
  interfaces by default, and supplies the fixed spawn value otptest.
- Current code rejects HTTP requests when Basic is enabled but unconfigured
  (lib/httpBasicAuth.js:87-89 and 141-143) and rejects WebSockets likewise
  (server.js:786-795). A stale mutable image is not guaranteed to have that
  behavior.

**Impact**

Developers can believe they launched newly reviewed code while actually
running an older mutable image with a known control value on a public bind.
This is not a default product path, but it is unsafe release and smoke-test
tooling.

**Recommendation**

Delete the helper or rewrite it with fail-fast options, the real reviewed
Dockerfile, an immutable captured image ID, loopback publication, normal
authentication, a generated one-time capability, cleanup traps, and explicit
output identifying the image and revision under test.

## Positive controls verified by source

The following controls are material improvements and should be preserved:

- lib/authMode.js:17-79 defaults Basic, OAuth, and spawn OTP protection on and
  restricts weakened configurations to loopback; Guard maintains its mTLS
  boundary.
- lib/publicOrigin.js:22-52 and 82-90 accepts exact HTTP/HTTPS origins and
  permits HTTP only for loopback.
- server.js:219-269, 452-641, and 751-805 centralizes transport authentication,
  rejects bearer query credentials, protects the UI/REST surface, and applies
  Guard/origin checks to WebSockets.
- proxy.js:21-39 rejects raw Next.js API/MCP use without the integrated server.
- OAuth uses PKCE S256, exact issuer/resource/scope checks, bounded token
  lifetimes, hashed tokens, one-time consent challenges, refresh rotation, and
  replay-family revocation.
- Spawn OTPs are generated with strong randomness, returned once when minted,
  stored only as hashes, consumed atomically, and thereafter represented by
  metadata.
- Auth-state creation verifies private modes, ownership, regular files,
  symlinks, hard links, exact schema constraints, and integrity.
- MCP transport sessions bind the complete principal/client/agent/subject,
  scope, resource, and transport identity.
- Guard runners use gated release, exact container/network identity,
  no-new-privileges, capability removal, read-only roots, private cgroups,
  resource limits, run-bound proxy capabilities, and containment-first cleanup.
- Full Guard enforce mode refuses admission while its required ingress
  enforcement contract remains intentionally incomplete. Scoped
  egress-enforce is enabled only for egress and deliberately claims no ingress
  enforcement.
- eBPF and gateway artifacts use strict schemas and hashes; enforcement
  activation uses signed role-separated policy/grant material and exact
  deployment bindings. Evidence loss is explicit, and drift checks fail
  closed at admission/activation and during responsive-daemon watchdog or
  requested status checks.
- Package-manager commands in the release audit stay inside Docker and its
  offline build/test/package stages use a clean Git snapshot.

## Prior review disposition

This table maps the 2026-08-11 findings to the current review.

| Prior ID | Disposition | Current status |
| --- | --- | --- |
| SR-01 | Closed | Authentication defaults on and weakened modes require loopback |
| SR-02 | Closed | Integrated auth covers transports; raw Next.js API paths fail closed |
| SR-03 | Partially closed | MCP transport sessions are bound, but terminal/readers remain global; see current SR-02 |
| SR-04 | Partially closed | Known Notty secrets are scrubbed, but controller/worker identity and provider-state separation remain open; see SR-01/SR-06 |
| SR-05 | Open | Buffer retention, quotas, and reader lifecycle remain in current SR-04 |
| SR-06 | Open | WebSocket operation containment remains in current SR-04 |
| SR-07 | Open / accepted risk | Autonomous execution remains current SR-05 |
| SR-08 | Open | Broad legacy provider mounts remain current SR-06 |
| SR-09 | Closed | OAuth URL/log/lifetime/replay design was materially replaced |
| SR-10 | Partially closed | Values are hash-only/atomic; expiry, entropy, quotas, and pruning remain current SR-10 |
| SR-11 | Open and raised | Collab authority remains current SR-03 |
| SR-12 | Open / split | Current SR-08, SR-09, and SR-13 cover context, image, and provenance |
| SR-13 | Open | Browser hardening remains current SR-14 |
| SR-14 | Open | stdio proxy hardening remains current SR-15 |
| SR-15 | Closed for integrated startup | Validated public-origin logic and integrated WebSocket handling replaced forwarding-header trust |
| SR-16 | Open / reframed | The stale bpr helper remains current SR-16 |

## Release-audit evidence and remaining gates

The inspected .release-audit/latest.md report is bound to
402aebf9934f2293ca5aa76d122d0f1f18d05fbb and tag v1.0.0. It records the
aggregate result and gates. The accompanying audit console transcript supplies
the detailed test counts, component compilation results, build warnings, and
artifact digest:

- automated result PASS, exit status 0
- 35 passes, zero failures, and one warning
- 828 deterministic tests: 827 passed, zero failed, one skipped
- successful offline TypeScript/Next.js production build
- successful static contracts and CO-RE compilation for four eBPF components
- clean-snapshot and full-checkout package inventories with no forbidden paths
- package artifact notty-1.0.0.tgz with SHA-256
  f75a4d8fa43c78c742ec9a0061d878c52418c38458c6370fbdad1305461dc57c
- zero known root-production npm vulnerabilities at audit time
- one reproducibility warning: Debian audit-tool packages are selected at
  image-build time rather than from a snapshot-pinned repository

The npm result covers only the root package's production dependency graph via
npm audit --omit=dev at audit time. It does not cover globally installed CLIs,
OS/Python packages, Ollama, separate applications, or final-image reachability.

The automated audit does not claim completion of:

- history and secret scanning
- license, third-party notice, ANSI/art, font, and asset provenance
- production image/context/layer/SBOM review
- live provider, OAuth, OTP, WebSocket, Collab, Copilot, Guard, eBPF, gateway,
  enforcement, cleanup, reboot, and failure-injection smokes

The skipped Docker-daemon-dependent isolation test also needs a live
environment result before it can support a release claim.

## Prioritized remediation plan

### P0 — Required before public or mutually untrusted use

1. Separate the controller/auth UID and database from every terminal and agent.
2. Introduce principal ownership/delegation for terminals, readers, agents,
   Copilot bindings, and Collab operations across every transport.
3. Authenticate the Collab admin/agent planes with separate, expiring,
   operation-bound capabilities and server-owned identity/target mapping.
4. Add hard memory/object/message limits and make every WebSocket operation
   exception-safe.
5. Remove broad provider mounts and default full-access agent launches from
   the release posture.
6. Build a minimal non-root production image from a clean allowlisted context;
   verify every installer and close the production-image manual gate.
7. Accurately represent DNS-derived eBPF grants, block special-use rebinding,
   and complete live audit/enforce tests for each supported network mode.

### P1 — Required for a defensible stable release

1. Add OAuth/OTP/client state budgets, rate limits, finite expiry, pagination,
   pruning, and recovery abuse tests.
2. Bind every Copilot broker message to a non-URL capability and constrain
   autonomous mode to an independently authorized disposable environment.
3. Add an external Guard watchdog, recurring live-state attestation, negative
   probes, and explicit activate/renew/revoke/deactivate semantics.
4. Build Guard host bundles from the exact captured Git tree and emit signed,
   reproducible provenance.
5. Complete the four manual release-audit gates and archive their immutable
   evidence against the final commit, tag, context, image, and package hashes.

### P2 — Hardening and operational clarity

1. Narrow the production CSP and add missing browser security headers.
2. Harden or retire the stdio proxy and bpr helper.
3. Resolve Turbopack broad-tracing warnings and inventory standalone output.
4. Add QEMU/KVM clean-guest install/upgrade/rollback testing.
5. Evaluate bubblewrap only as defense in depth, with explicit fail-closed
   behavior when user namespaces or bwrap are unavailable.
6. Document that shared agent group membership grants source collaboration,
   not controller, credential, terminal, network, Docker, or Guard authority.

## Required workflow/security test matrix

Before changing the release decision, exercise at least:

- Basic-protected web UI with OAuth-disabled MCP, one-time spawn OTPs, multiple
  independent countdowns, replacement minting, expiry, replay, and auth-reset
  revocation; per-token renewal/revocation remains a feature gate
- terminal create/read/write/resize/close through HTTP, WebSocket, SSE, and MCP
  as two mutually distrustful principals
- terminal-tab close behavior and cleanup after browser disconnect/reconnect
- Copilot connect, insert, approval, autonomous lease, interrupt, halt, timeout,
  source exit, and analyzer failure
- each agent's own Collab capability plus an operator-held one-use OTP for
  creating that agent's terminal; verify timeout display, replacement
  minting, interrupt, halt, permission change, prohibited peer/operator
  operations, and that the spawn OTP is never delivered to the agent
- proof that agents cannot obtain HTTP Basic, OAuth, spawn, signing, Guard, or
  provider credentials from environment, procfs, filesystem, sockets, logs,
  inherited descriptors, or peer processes
- Nosh Guard setup/install; nosh build profile; lower-level full-profile
  learn/audit; nosh net learn; nosh net audit; signed eBPF activation; and
  nosh net enforce, plus a negative test that full enforce remains rejected
  until ingress enforcement exists
- grant expiry before activation, consumed-grant replay, chosen
  after-activation expiry semantics, activation-state revoke/deactivate,
  daemon SIGSTOP/event-loop wedge, nft/iptables replacement, dnsmasq death,
  exact cgroup hook/map attachment, and functional IPv4/IPv6 deny tests
- policy drift, reboot, daemon crash, Docker hang, collector loss, containment
  failure, cleanup retry, and rollback in every applicable Guard mode
- per-agent network learn/audit/enforce with DNS/CNAME/TTL/shared-CDN/rebinding,
  direct-IP, SNI/Host mismatch, QUIC, special-use ranges, kill switch, and
  container termination fallback
- production build context canaries, layer/image inventory, SBOM, CVE scan,
  provenance, package comparison, and clean-machine installation

The repository's todo.md and workflows.md can track the human sequence, but
passing documentation checkboxes is not evidence by itself. Each release gate
should retain machine-readable results bound to immutable artifact identities.

## Final decision

**No-go for public, multi-user, or mutually untrusted-agent deployment at
402aebf9934f2293ca5aa76d122d0f1f18d05fbb.**

The former unauthenticated remote-shell and alternate-entrypoint Critical
findings are fixed, so controlled testing can continue. The release should not
be represented as security-complete or stable until the P0 boundaries and
manual audit gates are closed with live evidence. In particular, external
authentication does not compensate for sharing the auth database, Unix
identity, terminal namespace, Collab authority, provider state, or learned
network grants among mutually untrusted agents.
