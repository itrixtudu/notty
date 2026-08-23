# Security Review

> Review date: 2026-08-11  
> Reviewed revision: 189ff32de5e05e2630d1f05ed50ca340ddcb1bd4  
> Method: read-only static source and configuration review  
> Decision: **No-go for exposure to an untrusted or multi-user network until SR-01 and SR-02 are fixed**

## Executive summary

The service is a deliberate shell-control plane: authenticated users can start processes, read terminal output, and write commands. That makes authentication, authorization, secret separation, and process isolation part of the primary security boundary rather than optional deployment hardening.

The direct server defaults do not currently provide that boundary. With no explicit bind address, the server can listen on all interfaces, while Basic authentication is disabled unless enabled by configuration. The resulting HTTP API accepts a caller-selected executable, arguments, command, and working directory and passes them to a PTY. A network-reachable default deployment therefore exposes unauthenticated command execution as the server account. This is release-blocking for hostile-network use.

Authentication coverage is also inconsistent. OAuth protects the custom /mcp router only; it does not protect the terminal HTTP API, terminal WebSocket, or the Next.js /api/mcp handler. The pages/api handlers contain no local authentication and rely on the custom Express wrapper. Starting Next.js directly can bypass that wrapper. These alternate paths must either share one fail-closed authentication layer or be rejected at startup.

After authentication, all terminal sessions, MCP sessions, and MCP reader handles are process-global and have no owner checks. A shared deployment therefore permits horizontal terminal takeover and transcript disclosure. Child terminals also inherit the server's full environment, including service credentials supplied through environment variables.

The highest prompt-injection risk is the copilot autonomous mode. The implementation has useful prompt-level defenses and launches the analyzer in a read-only mode, but attacker-controlled terminal text still influences a model whose submitted command can be executed without a per-command human decision. The shell-readiness marker is not a safe authorization boundary because code running in the shell can access and replay its nonce.

The Nosh launcher's normal defaults reduce immediate exposure by enabling Basic authentication and not publishing a host port by default. Guard mode is materially stronger: it uses mTLS-bound principals, strict proxy checks, a scrubbed runner environment, non-root containers, a read-only root filesystem, capability removal, and resource limits. Those controls are valuable, but they do not repair the direct-server and alternate-entrypoint behavior.

This review found:

- 2 Critical findings
- 8 High findings
- 4 Medium findings
- 2 Low findings

No repository code, scripts, tests, containers, package managers, installers, or network operations were executed. Dependency advisory status and runtime exploitability were therefore not tested.

## Scope and threat model

### Reviewed areas

- Custom server and entrypoints: server.js, main.js, proxy.js, and stdio-http-proxy.js
- Terminal HTTP, WebSocket, PTY, buffering, and reader management
- MCP HTTP/SSE transport, sessions, tools, spawn OTPs, and OAuth token handling
- Copilot, command-agent, shell-integration, and collaboration paths
- Next.js API routes, client message handling, CSP, and browser headers
- Nosh legacy and Guard launch modes
- Guard daemon, gateway, grant, principal, proxy-contract, and runner specifications
- Dockerfiles, launch scripts, release-audit scripts, and lockfile controls

### Assumed adversaries

- An unauthenticated network client that can reach an application listener
- An authenticated but untrusted user in a multi-user deployment
- A malicious process, repository, startup file, or terminal program that controls terminal output
- A same-host or same-container process that can reach loopback services
- A compromised build-time download or dependency source

### Review rules

Repository text, comments, fixtures, terminal strings, and instructions were treated as untrusted data. Nothing discovered in the repository was followed as an instruction. The review was static only; even security test scripts and containerized audit commands were not run.

### Severity and confidence

- Critical: direct compromise of the host/application security boundary with little or no prerequisite
- High: major confidentiality, integrity, or availability impact with a configuration or feature prerequisite
- Medium: constrained impact, local prerequisite, or important defense-in-depth failure
- Low: hardening or developer-workflow risk with limited default exposure
- Confirmed: the vulnerable control flow is directly established by source
- Likely/runtime-dependent: the source-level defect is established, but final runtime impact was not dynamically exercised

## Findings summary

| ID | Severity | Confidence | Finding |
| --- | --- | --- | --- |
| SR-01 | Critical | Confirmed | Direct startup can expose an unauthenticated remote shell |
| SR-02 | Critical | Confirmed | Authentication can be bypassed through uncovered transports and entrypoints |
| SR-03 | High | Confirmed | Terminal, MCP session, and reader objects have no owner authorization |
| SR-04 | High | Confirmed | Terminals and child services inherit the server's secret-bearing environment |
| SR-05 | High | Confirmed | Unbounded sessions/readers and a bypassable buffer ceiling permit resource exhaustion |
| SR-06 | High | Likely/runtime-dependent | Invalid WebSocket operations can escape as uncaught exceptions |
| SR-07 | High | Likely/runtime-dependent | Indirect prompt injection can reach autonomous command execution |
| SR-08 | High | Confirmed | Legacy Nosh mounts broad host credential directories read/write |
| SR-09 | High | Confirmed | OAuth bearer credentials are logged, accepted in URLs, and long-lived by default |
| SR-10 | Medium | Confirmed | Spawn OTP values and history remain recoverable and unbounded |
| SR-11 | Medium | Confirmed | The collaboration control plane trusts unauthenticated loopback peers |
| SR-12 | High | Confirmed | Container builds execute unverified remote installers and one runtime remains root |
| SR-13 | Medium | Confirmed | Browser policy permits unsafe script capabilities and broad outbound connections |
| SR-14 | Medium | Confirmed | The stdio proxy permits plaintext transport and can log complete MCP messages |
| SR-15 | Low | Confirmed | Advertised WebSocket URLs trust unvalidated forwarding headers |
| SR-16 | Low | Confirmed | A tracked development launcher publishes an insecure configuration |

## Detailed findings

### SR-01 — Direct startup can expose an unauthenticated remote shell

**Severity:** Critical  
**Confidence:** Confirmed  
**CWE:** CWE-306, Missing Authentication for Critical Function  
**Affected deployment:** Direct custom-server startup when network reachable and Basic authentication is not explicitly enabled

#### Evidence

- lib/httpBasicAuth.js:3 makes Basic authentication opt-in.
- lib/httpBasicAuth.js:67-70 and 104-108 explicitly allow requests when the feature is disabled.
- lib/serverAddress.js:111-125 can return a null bind host when no bind address is configured.
- server.js:771-773 then calls listen with only the port, which normally binds all available interfaces.
- server.js:394-418 registers terminal and related control routes behind only the optional global Basic middleware.
- lib/terminalHttpApi.js:86-95 accepts the POST body and passes it directly to spawnTerminal.
- lib/terminalManager.js:844-890 accepts caller-controlled shell, args, command, cwd, dimensions, UUID, and metadata, then invokes pty.spawn. A command is converted to shell -c form.
- lib/corsPolicy.js:108-121 permits requests with no Origin unless browser fetch metadata indicates a cross-site request. This is appropriate for non-browser clients, but demonstrates that CORS is not authentication.

#### Impact

A remote client that can reach the listener can start arbitrary commands as the server account, read their output, send more input, and terminate sessions. Because the default terminal environment is inherited from the server, compromise also exposes service credentials and any filesystem access available to that account.

This behavior may be acceptable for an explicitly loopback-only, single-user development tool. It is not a safe network default.

#### Existing mitigating controls

- README.md:506-514 warns that direct startup is unauthenticated unless Basic authentication is enabled.
- SECURITY.md:5-7 warns against exposing the prerelease to untrusted users or the public Internet.
- The normal Nosh legacy flow enables Basic authentication and does not publish a host port by default.
- Guard mode adds a separate authenticated gateway and container isolation.

Documentation does not replace an enforcement boundary when a shell-capable service can bind beyond loopback.

#### Required remediation

1. Bind to 127.0.0.1 and ::1 by default.
2. Fail startup if a non-loopback bind is requested without an enabled, valid authentication configuration.
3. Apply the invariant centrally to every HTTP, SSE, WebSocket, MCP, Next API, copilot, agent, collaboration, and OTP route.
4. Treat CORS, Host checks, terminal UUIDs, and spawn OTPs as supplementary controls, never authentication.
5. Emit a bounded startup summary that states bind scope and authentication mode without printing secrets.

#### Regression criteria

- An unauthenticated request cannot list, spawn, read, write, resize, or kill a terminal.
- An unauthenticated WebSocket upgrade is rejected before a terminal is resolved.
- Startup refuses wildcard or non-loopback binding with authentication disabled or incomplete.
- Loopback-only development requires an explicit configuration choice before relaxing authentication.

### SR-02 — Authentication can be bypassed through uncovered transports and entrypoints

**Severity:** Critical  
**Confidence:** Confirmed  
**CWE:** CWE-288, Authentication Bypass Using an Alternate Path or Channel  
**Affected deployment:** OAuth-only custom-server deployments; direct Next.js development or standalone deployments; any future route not covered by the custom wrapper

#### Evidence

- server.js:367-382 installs optional Basic authentication as global Express middleware.
- server.js:441-454 installs OAuth only on the custom /mcp router.
- server.js:673-710 checks only Basic authentication for terminal WebSocket upgrades.
- server.js:714-715 hands other upgrade paths to Next.js.
- pages/api/terminals/index.js:27-49 lists and spawns terminals without a route-local authentication check.
- pages/api/mcp/index.js:10-34 exposes MCP handling without a route-local authentication check.
- proxy.js:21-61 applies origin/fetch-metadata policy but no Basic or OAuth authentication.

Consequently, enabling OAuth alone does not protect /api/mcp, the terminal HTTP API, or terminal WebSockets. When the custom Express server is used, optional Basic middleware may cover the Next API routes, but OAuth still does not. When Next.js is started directly, that global Basic middleware is absent.

#### Impact

An operator can reasonably believe OAuth protects the MCP service while a second MCP endpoint remains unauthenticated. A raw Next.js deployment can expose all shell-capable pages/api handlers without the custom-server authentication layer. Either path reaches the same terminal primitives described in SR-01.

#### Required remediation

1. Define one supported authentication policy and enforce it in code shared by all entrypoints.
2. Require explicit scopes for terminal read, terminal write, terminal spawn, process termination, copilot control, OTP administration, and collaboration administration.
3. Make WebSocket authentication use the same principal and policy as HTTP.
4. Remove duplicate MCP paths, or prove with route-inventory tests that every path has equivalent policy.
5. If raw Next.js startup is unsupported, make it fail closed and document the only supported production entrypoint.
6. Define whether Basic and OAuth compose, are alternatives, or serve different trusted zones. Reject ambiguous or partial configurations.

#### Regression criteria

Create a route-inventory test covering every shell-capable HTTP, SSE, and WebSocket path in custom-server, raw Next development, and standalone modes. For each mode, test Basic off/on/misconfigured, OAuth off/on/misconfigured/expired, missing and malicious Origin/Host headers, and authenticated principals with insufficient scopes.

### SR-03 — Terminal, MCP session, and reader objects have no owner authorization

**Severity:** High  
**Confidence:** Confirmed  
**CWE:** CWE-639, Authorization Bypass Through User-Controlled Key; CWE-862, Missing Authorization  
**Affected deployment:** Any deployment with more than one mutually untrusted authenticated user or client

#### Evidence

- lib/terminalHttpApi.js:86-151 lets any admitted caller list all sessions and read, write, resize, inspect, or kill a session using its numeric ID or UUID.
- lib/terminalManager.js maintains process-global terminal and UUID maps and exposes all sessions through listTerminals at 1100-1107.
- lib/mcpTools.js:19-24 maintains a process-global reader map with sequential handles.
- lib/mcpTools.js:414-495 opens, reads, and closes reader handles without binding them to an MCP transport session or authenticated principal.
- lib/mcpHttpServer.js:6-25 maintains global active and closed session maps and accepts caller-supplied session identifiers.
- lib/mcpHttpServer.js:28-64 creates sessions without a principal owner or per-owner quota.
- server.js:486-503 exposes MCP session inventory and cleanup operations.

Basic authentication supplies one shared credential, and the OAuth implementation supplies a singleton bearer rather than a user identity with scopes. Neither creates an object-ownership boundary.

#### Impact

One authenticated client can discover and take over another client's shell, retrieve full terminal history, inject commands, resize or terminate the session, and guess or reuse globally sequential reader handles. Terminal output commonly contains source code, tokens, command history, paths, and other sensitive data.

#### Required remediation

1. Introduce a stable authenticated principal for every HTTP, SSE, and WebSocket connection.
2. Store owner ID and allowed delegates on every terminal, MCP session, reader, copilot, proposal, and OTP administrative object.
3. Authorize every object access against that owner before returning whether the object exists.
4. Use opaque external identifiers only; do not expose sequential numeric IDs.
5. Bind MCP reader handles to both the owning principal and transport session.
6. Add per-principal quotas, TTLs, and cleanup on disconnect.

#### Regression criteria

Two-principal tests must prove that principal B cannot enumerate, read, write, resize, kill, or infer the existence of principal A's terminal; cannot use A's MCP session ID; and cannot read or close A's reader handle.

### SR-04 — Terminals and child services inherit the server's secret-bearing environment

**Severity:** High  
**Confidence:** Confirmed  
**CWE:** CWE-200, Exposure of Sensitive Information to an Unauthorized Actor  
**Affected deployment:** All terminal modes that place credentials or service secrets in the server environment

#### Evidence

- lib/terminalManager.js:225-240 starts from the complete process.env, including when applying caller-independent overrides.
- lib/terminalManager.js:858-889 passes that environment to pty.spawn.
- lib/agentManager.js:493-509 spreads process.env into command-agent children.
- lib/collabSupervisor.js:316-344 spreads process.env into the collaboration daemon.
- nosh.sh:2143-2154 supplies the spawn OTP and Basic username/password to the container through environment variables.
- By contrast, lib/guardd/runner-spec.js:73-92 deliberately strips Basic and spawn-OTP variables from the guarded runner environment.

#### Impact

Any user who obtains a terminal can read the server's environment and recover authentication secrets, OAuth/client credentials, provider API keys, or infrastructure configuration. A shared Basic password or spawn OTP recovered this way can be replayed against the service. A malicious command-agent or compromised collaboration daemon receives the same secret set.

#### Required remediation

1. Construct child environments from a small allowlist such as PATH, locale, terminal type, HOME, and explicitly approved workspace variables.
2. Always remove NOTTY authentication values, OAuth client secrets, spawn OTPs, proxy credentials, cloud/provider tokens, and unrelated host secrets.
3. Where a shell genuinely needs provider access, broker narrowly scoped, short-lived credentials to that specific principal and session.
4. Apply the Guard runner's scrubbing approach consistently to legacy terminals, agents, copilots, and collaboration children.
5. Prefer file descriptors or permissioned secret files over long-lived environment variables for service-only credentials.

#### Regression criteria

Spawned shells and child services must be tested against a canary secret set in the parent environment. The canary must not appear in /proc-derived environment data, child output, error messages, logs, or generated launch specifications.

### SR-05 — Unbounded sessions/readers and a bypassable buffer ceiling permit resource exhaustion

**Severity:** High  
**Confidence:** Confirmed  
**CWE:** CWE-770, Allocation of Resources Without Limits or Throttling; CWE-400, Uncontrolled Resource Consumption  
**Affected deployment:** All network-reachable modes, especially MCP and long-lived WebSocket use

#### Evidence

- Terminal creation paths contain no global or per-principal maximum, spawn-rate limit, idle timeout, or process-runtime limit.
- lib/terminalManager.js defines a nominal 10 MiB buffer per terminal.
- lib/terminalManager.js:435-463 trims only up to the minimum reader pointer. A persistent reader pinned at position zero prevents trimming even when the nominal ceiling is exceeded.
- lib/mcpTools.js:390-405 creates persistent MCP readers that can include full history.
- lib/terminalManager.js:1121-1180 retains persistent readers until explicit disposal and provides no reader TTL.
- lib/mcpHttpServer.js:6-64 maintains active session state without count or per-caller limits.
- lib/mcpHttpServer.js:77-80 and 112-124 retain closed session identifiers without pruning.
- HTTP reads and WebSocket connections can return full retained history, and the WebSocket send path has no application-level bufferedAmount/backpressure policy.
- server.js:664 creates the WebSocket server without an explicit project payload policy.

#### Impact

An attacker can create PTYs, child processes, MCP sessions, readers, and output faster than the service releases them. A dormant history reader can turn the nominal buffer limit into unbounded memory growth. Repeated full-history reads and slow WebSocket consumers amplify CPU and memory pressure. This can exhaust the Node process or host and disrupt all users.

#### Required remediation

1. Replace reader-dependent trimming with a hard ring-buffer ceiling. Advance or invalidate lagging readers and report a bounded data-loss marker.
2. Add global and per-principal limits for terminals, processes, MCP sessions, readers, SSE connections, WebSockets, copilots, and agents.
3. Add spawn and request rate limits, idle and absolute TTLs, output-rate limits, and deterministic disconnect cleanup.
4. Bound history reads by bytes and pagination; never serialize an unbounded transcript in one response.
5. Apply WebSocket payload limits and backpressure thresholds, closing slow consumers safely.
6. Bound metadata, UUID, session-ID, and error-string lengths.

#### Regression criteria

Tests should cover fork/CPU/output bombs, dormant include-history readers, a slow WebSocket client, repeated reconnects, attacker-selected session IDs, disconnect races, and quota recovery after failed spawns.

### SR-06 — Invalid WebSocket operations can escape as uncaught exceptions

**Severity:** High  
**Confidence:** Likely/runtime-dependent  
**CWE:** CWE-248, Uncaught Exception  
**Affected deployment:** Terminal WebSocket endpoint

#### Evidence

- lib/terminalWsHandlers.js:112-138 validates JSON syntax but does not schema-validate message fields and does not wrap write or resize operations in a local try/catch.
- lib/terminalManager.js:178-185 accepts positive integer dimensions but applies no maximum.
- lib/terminalManager.js:1065-1068 throws for invalid resize values.
- lib/terminalManager.js:974-1001 assumes an appropriate input data type before passing it to the PTY.
- No process-level exception handler was found that would safely isolate an exception from this message listener.

A syntactically valid JSON resize frame with zero, negative, non-integer, or missing dimensions reaches a throwing operation from the event callback. A non-string input frame can also reach the PTY write path.

#### Impact

In normal Node EventEmitter behavior, an exception escaping a message listener can terminate the process. Dynamic execution was prohibited for this review, so process termination is labeled likely rather than confirmed. Even if a particular runtime contains the exception, oversized dimensions and malformed high-rate messages remain a denial-of-service surface.

#### Required remediation

1. Define a strict discriminated schema for every WebSocket message.
2. Require input data to be a bounded string.
3. Constrain rows and columns to operationally safe maxima.
4. Catch every operation error inside the message handler and return a bounded generic error frame.
5. Add connection/message rate limits and an explicit maxPayload.
6. Never include raw native or filesystem error strings in client-visible responses.

#### Regression criteria

Run the service in an isolated container and send malformed JSON, valid JSON with wrong types, invalid dimensions, oversized frames, and high-rate messages. The connection may be rejected, but the process must remain healthy and other sessions must remain usable.

### SR-07 — Indirect prompt injection can reach autonomous command execution

**Severity:** High  
**Confidence:** Likely/runtime-dependent  
**CWE:** CWE-1427, Improper Neutralization of Input Used for LLM Prompting; OWASP LLM01 Prompt Injection  
**Affected deployment:** Copilot autonomous mode, particularly when terminal output or startup files are attacker-controlled

#### Evidence

- lib/copilotManager.js:323-344 includes explicit instructions to treat selected terminal text as untrusted and not to submit commands from the analyzer.
- lib/copilotManager.js:359-372 launches the analyzer with read-only sandboxing and approval disabled, which is a useful containment layer.
- lib/copilotManager.js:809-836 wraps terminal material in a structured untrusted-data envelope.
- lib/copilotManager.js:1108-1129 defaults control mode to off and requires an autonomousConfirmed request boolean to enable autonomous mode.
- lib/copilotManager.js:1350-1376 applies the same request-level confirmation during updates.
- lib/copilotManager.js:1536-1547 gates writes on promptReady and alternate-screen state.
- lib/copilotManager.js:1549-1602 executes a model-submitted command immediately in autonomous mode by appending a carriage return.
- scripts/shell-integration/bashrc:5-11 captures the marker nonce in a shell variable before sourcing user startup configuration.
- scripts/shell-integration/bashrc:46-58 leaves a shell function able to emit markers with that nonce. Equivalent trust concerns apply to other supported shell integrations.
- lib/terminalCommandProtocol.js:62-118 and 142-220 validates the nonce, but the nonce authenticates only an in-band shell marker; it does not distinguish trusted integration code from malicious code already executing in the same shell.
- The legacy agent prompt in lib/agentManager.js:422-447 labels terminal output but relies on fencing and regex redaction rather than a structural trust boundary. That path proposes commands but was not found to execute them automatically.

#### Impact

A malicious repository, command output, startup file, log, test failure, or terminal program can present instructions designed to override the copilot's policy. Prompt text and JSON framing reduce model error probability but cannot guarantee non-compliance. In autonomous mode, a successful indirect prompt injection can become shell execution without a fresh per-command human decision. Malicious shell code can also forge readiness/completion markers, so promptReady must not be treated as authorization.

#### Required remediation

1. Make untrusted-output analyzers structurally unable to invoke a command-submission capability.
2. Require a separate, authenticated, short-lived, single-command approval capability before execution.
3. If autonomous execution remains a feature, confine it to a strongly isolated disposable runner with explicit filesystem, network, process, and secret policies.
4. Apply deterministic policy outside the model: executable allowlists where practical, working-directory containment, environment scrubbing, argument/length limits, and prohibited secret/privilege operations.
5. Treat shell markers as lifecycle hints only, never authorization or proof that a trusted prompt is active.
6. Redact secrets before model submission with structured provenance and allowlists; do not rely on regex-only filtering.

#### Regression criteria

Add malicious terminal-output, selected-text, repository-file, startup-file, ANSI/OSC, password-prompt, and agent-message fixtures. Verify behavior in off, insert, approve, and autonomous modes. No untrusted text may independently authorize a write or execution, and forged markers must not change authorization state.

### SR-08 — Legacy Nosh mounts broad host credential directories read/write

**Severity:** High  
**Confidence:** Confirmed  
**CWE:** CWE-732, Incorrect Permission Assignment for Critical Resource; CWE-200  
**Affected deployment:** Legacy Nosh mode with local Codex, Gemini, or Claude configuration present

#### Evidence

- nosh.sh:868-884 bind-mounts the entire host Codex directory read/write, then adds narrower read-only mounts for selected files. The parent mount still exposes other state.
- nosh.sh:1265-1272 bind-mounts the entire Gemini and Claude directories read/write.
- nosh.sh:2133-2147 bind-mounts the workspace read/write and injects service configuration into the container.
- nosh.sh:2252 selects legacy as the default security mode.

#### Impact

A terminal or application compromise can read provider credentials and conversation/configuration state, modify host agent configuration, poison persistent instructions, or establish persistence that affects later trusted host sessions. Read-only nested mounts for selected files do not remove the broader readable/writable parent-directory exposure.

#### Required remediation

1. Make Guard mode, or an equivalently isolated rootless mode, the default.
2. Mount only explicitly selected credential files, read-only, and avoid mounting their parent directories.
3. Place caches, history, and mutable session state in isolated ephemeral directories.
4. Prefer a host credential broker that returns scoped, short-lived tokens to mounting long-lived provider state.
5. Require an explicit warning and opt-in for any read/write host credential mount.

#### Regression criteria

A compromised test container must be unable to read or alter unrelated files under the host provider directories. Symlink and nested-mount tests must prove that an allowed path cannot be used to reach sibling secrets.

### SR-09 — OAuth bearer credentials are logged, accepted in URLs, and long-lived by default

**Severity:** High  
**Confidence:** Confirmed  
**CWE:** CWE-532, Insertion of Sensitive Information into Log File; CWE-598, Use of GET Request Method With Sensitive Query Strings  
**Affected deployment:** OAuth-enabled MCP/SSE and copilot-broker configurations

#### Evidence

- lib/authToken.js:11-12 defaults token TTL to zero, meaning no expiry.
- lib/authToken.js:25-35 writes a token file without an explicit no-follow/exclusive replacement strategy; an existing permissive file is not necessarily repaired.
- lib/authToken.js:38-48 logs the complete bearer token.
- lib/authToken.js:133-146 accepts access_token from the query string when enabled.
- server.js:442 enables query-token support.
- lib/authToken.js:260 compares client credentials using ordinary string equality.
- lib/copilotMcpBroker.js:194-204 also accepts a capability token from a query parameter.
- lib/copilotMcpBroker.js:334-341 constructs a broker URL carrying that token in the query.

#### Impact

Anyone with access to application, proxy, shell-history, browser-history, telemetry, or copied-URL logs can recover a bearer credential. The default non-expiring singleton token has no user scope and grants access until the service state changes. A token-file symlink or pre-existing mode can redirect or expose persisted credentials.

#### Required remediation

1. Never log raw bearer, client, Basic, OTP, or broker capability values; log only a non-reversible identifier.
2. Remove query-string bearer support. For EventSource constraints, exchange a header-authenticated request for a short-lived, one-use connection ticket or secure same-site cookie.
3. Add finite expiry, rotation, revocation, principal identity, scopes, and audience binding.
4. Rate-limit token exchange and use constant-time secret comparison.
5. Create token files atomically with no-follow behavior, verified owner, regular-file type, link count, and mode 0600; repair or reject unsafe existing files.
6. Redact Authorization and sensitive query keys in all request/error logs.

#### Regression criteria

Automated log-capture tests must prove that no credential appears in startup, request, exception, proxy, or debug output. Expired, revoked, wrong-audience, replayed one-use, and insufficient-scope tokens must fail.

### SR-10 — Spawn OTP values and history remain recoverable and unbounded

**Severity:** Medium  
**Confidence:** Confirmed  
**CWE:** CWE-312, Cleartext Storage of Sensitive Information; CWE-400  
**Affected deployment:** MCP spawn OTP administration

#### Evidence

- lib/mcpSpawnOtp.js:49-64 serializes the raw OTP value.
- lib/mcpSpawnOtp.js:216-225 returns both available and historical entries.
- lib/mcpSpawnOtp.js:228-263 retains newly created entries in a process-global map without a history cap.
- lib/mcpSpawnOtp.js:266-309 consumes an OTP before terminal validation and spawn have succeeded.
- pages/api/spawn-otps.js:24-44 exposes the dashboard and returns raw values.
- lib/mcpTools.js:336-357 applies the OTP specifically to MCP terminal spawning.

The OTP is not a general authentication layer, and the README documents it as an MCP spawn control. Direct terminal HTTP spawning is therefore not described here as an OTP bypass; it must instead be protected by the authentication and authorization fixes above.

#### Impact

Used and expired OTPs remain available to any caller that can access the dashboard, token creation can grow memory indefinitely, and invalid spawn parameters can consume a valid OTP without creating a terminal. Returning all token values also increases accidental disclosure through UI, API, and support logs.

#### Required remediation

1. Generate a token once, store only a keyed hash, and reveal the plaintext only in the creation response.
2. Redact token values from dashboards, history, logs, and error objects.
3. Prune expired and used entries promptly and enforce count/rate limits.
4. Validate the full spawn request first, then atomically consume the OTP immediately before the authorized operation.
5. Bind OTPs to principal, operation, expiry, and optionally a request digest.

### SR-11 — The collaboration control plane trusts unauthenticated loopback peers

**Severity:** Medium  
**Confidence:** Confirmed  
**CWE:** CWE-306  
**Affected deployment:** Collaboration enabled, with an untrusted same-host or same-container process

#### Evidence

- lib/collabSupervisor.js:5-34 uses a fixed loopback HTTP endpoint.
- lib/collabSupervisor.js:55-66 sends requests without a cryptographic capability.
- lib/collabSupervisor.js:222-313 accepts a daemon after checking public marker, version, and workspace fields.
- lib/collabSupervisor.js:316-344 starts the daemon with the complete server environment.
- lib/collabHttpApi.js:61-82 forwards administrative requests using a derived operator name rather than a daemon-authentication capability.
- lib/collabHttpApi.js:342-489 exposes multiple collaboration administration mutations once the outer optional server policy admits the caller.

Collaboration is disabled by default, and loopback limits remote access. The relevant adversary is a local process able to bind or connect to the control port.

#### Impact

A malicious process can race to impersonate the expected daemon, receive forwarded information, or invoke collaboration administration operations. A spawned compromised daemon also receives the server's secrets through its environment.

#### Required remediation

Use a permissioned Unix-domain socket where possible, or a random per-process capability mutually authenticated on every request. Verify peer ownership, add strict request/response size and time limits, scrub the child environment, and fail closed if daemon identity changes.

### SR-12 — Container builds execute unverified remote installers and one runtime remains root

**Severity:** High  
**Confidence:** Confirmed  
**CWE:** CWE-494, Download of Code Without Integrity Check; CWE-250, Execution With Unnecessary Privileges  
**Affected deployment:** Images built from Dockerfile and Dockerfile.nosh

#### Evidence

- Dockerfile:1 uses a digest-pinned Node base, which is a positive control.
- Dockerfile:9-16 downloads an Antigravity installer and pipes it to a root shell without a pinned digest or signature.
- Dockerfile:21-27 installs and builds in the same image.
- Dockerfile:29-30 defines the runtime command without switching to a non-root USER.
- Dockerfile.nosh:1 also digest-pins the Node base.
- Dockerfile.nosh:217-232 version-pins and SHA-256-verifies Ollama archives in the explicit Ollama stage, which is a positive example.
- Dockerfile.nosh:84-86 installs global npm tools outside the application lockfile.
- Dockerfile.nosh:90-93 runs another unverified remote installer.
- Dockerfile.nosh:183-186 runs the main Nosh service as a non-root user, a positive control.
- Dockerfile.nosh:270-276 pins a Python package version but does not use a hash-locked requirements set.

The release-audit flow has strong controls: scripts/release-audit-container.sh validates registry and SHA-512 lockfile metadata, installs with lifecycle scripts disabled, explicitly rebuilds node-pty offline, and checks that the lockfile does not change. release-audit.sh uses network-disabled, read-only, capability-dropped containers for later stages. These controls should be retained.

#### Impact

A compromised installer origin, DNS/TLS path, or mutable upstream script can execute arbitrary code during image build. In the primary Dockerfile that code runs as root and lands in a root runtime image with build tooling. Global npm and hashless Python dependencies expand the unreviewed supply chain beyond the application lockfile.

#### Required remediation

1. Download immutable versioned artifacts, verify a pinned cryptographic digest and preferably a publisher signature, then execute locally.
2. Use a multi-stage build and copy only required runtime artifacts.
3. Run every production image as a dedicated non-root UID/GID with a read-only filesystem where practical.
4. Lock global npm and Python transitive dependencies with integrity hashes, or vendor them through the same audited lock/build process.
5. Generate an SBOM and verify base-image, OS-package, global-tool, Python, and application dependency provenance.
6. Keep lifecycle scripts disabled except for an explicitly reviewed offline node-pty rebuild.

#### Verification note

No package advisory, container CVE, installer, build, or release-audit command was run. This finding concerns source-level supply-chain controls, not a claim about current third-party advisories.

### SR-13 — Browser policy permits unsafe script capabilities and broad outbound connections

**Severity:** Medium  
**Confidence:** Confirmed  
**CWE:** CWE-693, Protection Mechanism Failure  
**Affected deployment:** Browser UI in both Next.js configurations

#### Evidence

- next.config.mjs:6-16 and next.config.standalone.mjs:6-16 allow unsafe-eval and blob: in script-src, unsafe-inline in style-src, and broad HTTPS destinations in connect-src.
- The CSP omits base-uri and form-action restrictions.
- next.config.mjs:34-47 and the standalone equivalent set CSP and Permissions-Policy but do not explicitly set nosniff, Referrer-Policy, COOP, or a deployment-aware HSTS policy.
- No dangerouslySetInnerHTML use was found. The only innerHTML use found was a cleanup fallback.
- pages/index.js:711-733 and pages/copilot.js:80-102 correctly validate postMessage origin, source window, terminal UUID, and instance identity.

#### Impact

No direct client-side injection sink was confirmed. However, if an XSS or compromised dependency is introduced, unsafe-eval/blob capabilities and broad connect-src materially weaken CSP containment and facilitate data exfiltration from terminal sessions.

#### Required remediation

Adopt nonce- or hash-based production scripts, remove unsafe-eval outside explicit development mode, narrow connect-src to configured endpoints, and add base-uri 'none', form-action 'self', object-src 'none', and an explicit frame policy. Add X-Content-Type-Options, a deliberate Referrer-Policy, COOP/COEP where compatible, and HSTS only at deployments that guarantee HTTPS.

### SR-14 — The stdio proxy permits plaintext transport and can log complete MCP messages

**Severity:** Medium  
**Confidence:** Confirmed  
**CWE:** CWE-319, Cleartext Transmission of Sensitive Information; CWE-532  
**Affected deployment:** stdio-http-proxy.js used with a remote endpoint or debug logging

#### Evidence

- stdio-http-proxy.js:63-75 accepts both HTTP and HTTPS targets.
- stdio-http-proxy.js:87-105 establishes the configured remote connection without a policy restricting plaintext to loopback.
- stdio-http-proxy.js:135-155 logs complete local and remote MCP messages in debug mode.

#### Impact

MCP messages can contain terminal commands, output, credentials, paths, and tool arguments. A non-loopback HTTP target exposes them to interception or modification. Debug output copies the same sensitive content into logs.

#### Required remediation

Reject plaintext targets unless they are explicit loopback development endpoints, require authenticated TLS for remote use, support a configured trust/pinning policy, redact payloads by field and data classification, and add request/response size and timeout limits. Debug logging should default to metadata only.

### SR-15 — Advertised WebSocket URLs trust unvalidated forwarding headers

**Severity:** Low  
**Confidence:** Confirmed  
**Affected deployment:** Reverse-proxy deployments or clients that consume the /api/ws response

#### Evidence

- server.js:747-754 constructs the advertised client URL from X-Forwarded-Host and X-Forwarded-Proto without an explicit trusted-proxy decision.
- pages/api/ws.js:23-35 contains equivalent forwarded-header behavior.
- No current first-party client consumer of this response was found; terminal clients currently derive their WebSocket origin from the browser location.

#### Impact

A caller able to influence forwarding headers can cause the endpoint to advertise an attacker-controlled WebSocket destination. This is link/configuration poisoning rather than a confirmed server-side request forgery. Current impact is limited because no first-party consumer was identified.

#### Required remediation

Use an explicit configured public URL, or honor forwarding headers only from a configured trusted proxy and validate scheme, hostname, and port against an allowlist.

### SR-16 — A tracked development launcher publishes an insecure configuration

**Severity:** Low  
**Confidence:** Confirmed  
**CWE:** CWE-798, Use of Hard-coded Credentials  
**Affected deployment:** Manual execution of bpr.sh

#### Evidence

- bpr.sh:5-9 publishes port 3000 using Docker's all-interface host-port form.
- The same command supplies a fixed spawn OTP.
- A spawn OTP controls MCP spawning only and is not service authentication.

#### Impact

A developer can unintentionally publish a shell-capable development service beyond loopback while believing the fixed OTP protects it. The script is manually invoked, so this is not a default runtime exposure.

#### Required remediation

Bind development ports explicitly to 127.0.0.1, generate ephemeral secrets, enable the same authentication invariant as production, label the helper development-only, and avoid storing any reusable secret in tracked scripts.

## Positive controls worth retaining

The following controls materially reduce risk and should not be lost during remediation:

- Digest-pinned Node base images in both Dockerfiles
- SHA-256 verification of versioned Ollama archives in Dockerfile.nosh
- Lockfile registry/integrity validation and lifecycle-script suppression in the release-audit flow
- Explicit offline node-pty rebuild rather than general install-script execution
- Network-disabled, read-only, capability-dropped release audit stages
- Nosh's normal no-published-port behavior and generated Basic credential
- Guard gateway mTLS, certificate fingerprint checks, expiry/revocation checks, and run/container binding
- Guard proxy's strict origin/host contract and stripping of caller-controlled forwarding headers
- Guard runner's non-root UID/GID, no-new-privileges, capability removal, read-only root filesystem, no device/port exposure, tmpfs policy, and CPU/memory/PID limits
- Guard daemon socket/state ownership, mode, inode, link-count, locking, and no-follow checks
- Copilot analyzer read-only mode, explicit untrusted-data envelopes, default control mode off, and alternate-screen/prompt-state checks
- Browser postMessage validation of origin, source window, terminal UUID, and instance ID
- Absence of a React dangerouslySetInnerHTML sink in the reviewed UI

Guard's privileged daemon and OS enforcement still require dynamic validation. In particular, this static review could not prove Docker, nftables, dnsmasq, AppArmor, eBPF/event ingestion, IPv6/DNS/redirect egress handling, teardown races, or crash recovery behavior.

## Prioritized remediation roadmap

### P0 — Required before any untrusted-network exposure

1. Make loopback the default and refuse non-loopback startup without valid authentication.
2. Centralize authentication across custom Express, raw/standalone Next, HTTP, SSE, MCP, and WebSocket paths.
3. Introduce principals, scopes, object ownership, and opaque identifiers.
4. Scrub child environments and separate service credentials from shell-user credentials.
5. Remove model-only authorization for command execution; require a separate approval capability or a strongly isolated autonomous runner.

### P1 — Required for a resilient shared service

1. Add terminal/process/session/reader/connection quotas, TTLs, rate limits, hard buffer ceilings, and WebSocket backpressure.
2. Strictly schema-validate WebSocket and HTTP bodies and contain all operation exceptions.
3. Stop bearer/OTP logging and URL transport; add expiry, rotation, revocation, redaction, and safe token-file handling.
4. Make Guard or equivalent isolation the default and remove broad read/write credential mounts.
5. Replace remote installer pipelines, use non-root multi-stage runtime images, and lock all dependency ecosystems.
6. Authenticate the collaboration daemon and scrub its environment.

### P2 — Defense in depth and operational hardening

1. Tighten CSP and browser response headers.
2. Require secure stdio proxy transport and metadata-only logging.
3. Validate proxy forwarding headers or use an explicit public URL.
4. Replace insecure development helpers.
5. Inventory and redact all logs, including Authorization, query tokens, OTPs, terminal content, provider environment variables, and raw errors.

## Security validation matrix

Implementation should be considered complete only after automated coverage spans these dimensions:

| Dimension | Required cases |
| --- | --- |
| Entrypoint | Custom server, raw Next development, standalone Next, Nosh legacy, Guard, SSE, stdio proxy |
| Network | Loopback, wildcard, explicit LAN address, IPv4, IPv6, reverse proxy, cleartext, TLS |
| Authentication | Basic off/on/malformed, OAuth off/on/expired/revoked, both enabled, insufficient scope, query token rejected |
| Operation | List, spawn, inspect, read, write, resize, kill, copilot control, OTP admin, collaboration admin |
| Identity | Same owner, different owner, guessed numeric ID, copied UUID, copied MCP session, copied reader handle |
| Input | Shell, args, command, cwd, symlink/absolute/traversal path, UUID, metadata, rows/cols, large body, malformed frame |
| Abuse | Spawn flood, output bomb, CPU/fork bomb, slow reader, slow WebSocket, reconnect history, abandoned SSE, failed cleanup |
| Browser | Origin/Host/fetch metadata, preflight, missing/spoofed forwarding headers, CSP production/development modes |
| LLM | Prompt injection in terminal output, selected text, repository data, startup files, ANSI/OSC, agent messages |
| Secrets | Parent-env canaries, log capture, query capture, error serialization, token-file symlink/mode, mounted sibling files |
| Guard | Expiry/revocation, grant replay, principal/run binding, daemon/gateway crash, DNS/IPv6/redirect egress, teardown race |

## Review limitations

- This was a static review. No application code, tests, Docker images, package manager, security scanner, installer, or repository script was run.
- No network access was used. Current npm, OS, container, Python, global CLI, Ollama, or Antigravity advisories were not queried.
- Runtime-dependent findings are labeled accordingly. In particular, WebSocket process termination and LLM policy failure were not exercised.
- External services, reverse proxies, identity providers, Docker daemon configuration, kernel enforcement, and production logging/retention were not available for inspection.
- Third-party dependency source was not manually audited.
- The review did not establish formal absence of all vulnerabilities; it prioritizes security boundaries reachable from the inspected code.

## Release decision

Do not expose the direct server, raw Next.js API, or legacy terminal control plane to untrusted users or the public Internet in the current revision. A safe release requires closure of SR-01 and SR-02, followed by the ownership and secret-separation work in SR-03 and SR-04. If autonomous copilot execution is offered across a trust boundary, SR-07 must also be closed rather than accepted through prompt wording alone.
