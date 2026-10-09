# Notty Next Work — Priority Order

> Planning basis: SECURITY_REVIEW.md dated 2026-09-01
> Reviewed application base: 402aebf9934f2293ca5aa76d122d0f1f18d05fbb
> Current release posture: no-go for public, multi-user, or mutually
> untrusted-agent deployment

This is the dependency-ordered execution list. Detailed behavior and manual
steps remain in [todo.md](todo.md), [workflows.md](workflows.md), and
[SECURITY_REVIEW.md](SECURITY_REVIEW.md). Those files explain the individual
tests; this file decides what comes next.

Do not skip a gate because a later UI can be prototyped. In particular, the
network switch must not be built on a shared controller/agent identity, and a
passing release audit must not be treated as proof that the manual security
gates passed.

## Priority meanings

- **P0:** required before public, multi-user, or mutually untrusted-agent use
- **P1:** required before calling the release stable
- **P2:** optional hardening, convenience, or later research

## Critical path

| Order | Priority | Work | Exit gate |
| --- | --- | --- | --- |
| 0 | P0 | Freeze the release claim and identity model | No stable artifact can be published accidentally; every principal and authority is defined |
| 1 | P0 | Separate controller, auth state, credentials, and agent identities | Agents cannot read or mutate controller/auth/provider state |
| 2 | P0 | Add principal ownership to terminals, readers, Collab, and Copilot | Principal B cannot enumerate or control principal A |
| 3 | P0 | Bound memory, objects, WebSockets, and auth-state growth | Floods and malformed messages remain bounded and cannot kill the service |
| 4 | P0 | Fix release inputs, provenance, and the production image | Exact clean bytes produce a minimal non-root, inventoried image |
| 5 | P0 | Prove the current Guard/profile/audit/activation/enforce path | Current supported CIDR egress enforcement passes; unsupported gates fail closed |
| 6 | P0 | Implement Guard-owned OFF/LEARN/ENFORCE and per-agent isolation | Container and agent scopes are independently and authoritatively controlled |
| 7 | P1 | Finish split-auth, OTP, terminal-tab, Collab, and Copilot UX | The human workflows work without weakening the new authority model |
| 8 | P1 | Add independent Guard liveness and activation lifecycle controls | A wedged controller cannot silently defeat assurance or leave authority ambiguous |
| 9 | P1 | Finish browser, proxy, and helper hardening | Final public/runtime artifacts contain no known auxiliary bypass or stale launcher |
| 10 | P1 | Freeze one candidate and close every automated/manual release gate | Evidence is bound to the exact commit, tag, package, image, bundle, and policy |
| 11 | P2 | Optional preprofiles, domain views, swarm halt, QEMU, and bwrap | Each feature is explicit, bounded, and cannot weaken a P0/P1 boundary |

---

## 0 — Freeze the release claim and authority model

### Release identity

- [ ] Do not publish or sign the current v1.0.0 tag as stable.
- [ ] Determine whether v1.0.0 exists anywhere outside this checkout.
- [ ] If it is local and unpublished, use SemVer prerelease tags such as
      v1.0.0-rc.1, v1.0.0-rc.2, and so on for tested candidates; reserve
      v1.0.0 for the candidate that passes every gate.
- [ ] If v1.0.0 has already been published, do not silently move it. Document
      its status and issue a new corrected version.
- [ ] The v1.0.0d branch name may remain a private work-branch convention, but
      a trailing d is not the release artifact's SemVer prerelease marker.
- [ ] Preserve the existing successful audit report as evidence for commit
      402aebf only. It does not certify later documentation or code changes.
- [ ] Add the intended todo.md and workflows.md planning documents to version
      control before the next clean release-candidate audit.

### Authority/identity specification

- [ ] Write one operation matrix for the host operator, browser user, OAuth
      principal, Guard principal, local anonymous MCP principal, Notty
      controller, terminal owner, Collab operator, Collab agent, Copilot,
      provider harness, build worker, and policy signer.
- [ ] For every operation, record its owning principal, delegates, target
      object, capability, expiry, audit identity, UID/GID, cgroup, namespace,
      private state, and revocation path.
- [ ] Define the shared source-writer group as filesystem collaboration only.
      It must not imply terminal, credential, network, Docker, Guard, sudo, or
      signing authority.

**Gate:** the matrix has no operation authorized only by a caller-supplied
name, shared Unix UID, loopback source address, tmux target, or shared source
group.

## 1 — Separate controller, auth state, credentials, and agent identities

This closes SECURITY_REVIEW SR-01 and SR-06 before other controls rely on
principal identity.

- [ ] Run the web/auth controller under an identity that no terminal, agent,
      Copilot, Collab worker, or workspace process can assume.
- [ ] Move the auth SQLite database outside all worker-readable and
      worker-writable paths.
- [ ] Expose only a narrow, authenticated Unix-socket auth broker with peer
      credential checks and purpose-bound operations.
- [ ] Remove the plaintext HTTP Basic password from Docker inspect data,
      container environment, process arguments, tmux state, logs, and agent
      filesystem access.
- [ ] Give each managed agent a distinct UID, private home, private runtime
      directory, private credential input, and distinct child cgroup.
- [ ] Replace broad read/write .codex, .gemini, and .claude host mounts with
      narrow read-only inputs or short-lived credential brokerage. Keep
      writable caches private and disposable.
- [ ] Replace inherited-environment denylisting with a positive allowlist for
      terminals, agents, analyzers, catalog probes, and helpers.
- [ ] Implement the shared source-writer group/setgid or ACL plan without
      granting private-state access.

**Gate:** every supported agent independently fails to read/write the auth
database, Basic verifier/password, controller procfs state, provider peers,
Guard/signing material, private sockets, and inherited descriptors. Browser
HTTP and WebSocket authentication must still succeed normally.

## 2 — Add principal ownership and control-plane capabilities

This closes SECURITY_REVIEW SR-02, SR-03, and SR-11.

### Terminal and reader ownership

- [ ] Carry one normalized authorization context from HTTP, WebSocket, SSE,
      MCP, and local controller entrypoints into the terminal manager.
- [ ] Give every terminal, reader, subscription, Copilot binding, agent, and
      retained transcript an immutable owner plus explicit delegates.
- [ ] Filter inventories by principal and use opaque principal-bound handles.
- [ ] Make cross-owner attach, read, write, resize, close, or delegate an
      explicit audited administrator action.
- [ ] Represent OAuth-disabled local MCP as an explicit loopback-only
      anonymous principal with narrowly delegated objects. Do not bypass
      manager authorization.

### Collab and Copilot authority

- [ ] Split Collab operator administration from agent coordination.
- [ ] Put administration behind a mode-0600 Unix socket with peer credentials
      and an expiring operation-bound capability.
- [ ] Assign agent identity, session, channel, and tmux target server-side.
- [ ] Give each agent a capability bound to one exact session, agent, purpose,
      operation set, and expiry; rotation must revoke the prior value.
- [ ] Bind every Copilot broker message, not only initial connection, to a
      non-URL capability and the exact source-terminal owner.
- [ ] Revoke all object/capability authority on close, halt, source exit,
      permission relaunch, ownership loss, or session teardown.

**Gate:** principals A and B are exercised over HTTP, WebSocket, SSE, MCP, and
direct same-container attempts. B cannot discover, infer, read, write, resize,
kill, subscribe to, impersonate, relaunch, or change permission on A's
resources. Expired and replayed handles reveal no target existence.

## 3 — Bound availability and lifecycle state

This closes SECURITY_REVIEW SR-04 and the exhaustion portions of SR-10.

- [ ] Make terminal output a hard ring buffer independent of reader position;
      report an explicit gap to lagging readers.
- [ ] Add global and per-principal limits for terminals, readers,
      subscriptions, MCP sessions, Collab agents, Copilots, and pending output.
- [ ] Expire abandoned readers and transport sessions with bounded idle TTLs.
- [ ] Bound terminal columns, rows, write size, history size, output rate, and
      child-process creation.
- [ ] Set WebSocket payload limits, message rates, send-queue ceilings,
      backpressure behavior, and slow-client eviction.
- [ ] Validate each WebSocket frame and contain every operation exception
      inside the message handler.
- [ ] Rate-limit Basic, OAuth registration/authorization/token, OTP minting,
      recovery, and other state-creating paths.
- [ ] Cap OAuth clients and OTP records; paginate history and prune expired
      metadata.
- [ ] Generate new production OTPs server-side with at least 128 bits of
      entropy and a finite maximum lifetime. Continue displaying legacy
      no-expiry records, but do not issue new unlimited production grants.

**Gate:** abandoned readers, oversized output, malformed frames, invalid/huge
dimensions, slow clients, object floods, OAuth registration floods, and OTP
floods keep memory/disk bounded and leave the service responsive under an
external supervisor.

## 4 — Fix release inputs, provenance, and the production image

This closes SECURITY_REVIEW SR-08, SR-09, and SR-13 before later evidence
claims certify an artifact.

- [ ] Build release/package/image/Guard-bundle inputs from a captured clean Git
      tree or a minimal generated allowlisted context outside the checkout.
- [ ] Exclude provider state, credentials, VCS data, reports, sockets, local
      overrides, caches, and editor/host state from Docker contexts.
- [ ] Bind commit, tree, source-archive digest, build context, builder image,
      build configuration, bundle manifest, package, and final image in one
      provenance record.
- [ ] Make Guard host-bundle generation copy the captured tree, not live
      recursive checkout roots while merely recording HEAD.
- [ ] Replace remote shell installers with pinned, digest/signature-verified
      artifacts.
- [ ] Produce a minimal multi-stage production server image under a dedicated
      non-root UID; omit compilers, source, package caches, provider CLIs, and
      unrelated tooling.
- [ ] Lock or isolate global CLI and Python transitive dependencies.
- [ ] Resolve the Turbopack whole-project tracing warnings and inventory the
      actual standalone server output.
- [ ] Produce an SBOM, filesystem/layer inventory, base/image digests,
      vulnerability results, and reproducibility result.

**Gate:** seeded canary secrets are absent from the transmitted context, build
logs, cache, every image layer, exported filesystem, package, SBOM, and Guard
bundle. Rebuilding the exact captured inputs produces the expected immutable
identities.

## 5 — Prove the current Guard and profiling path

Use a disposable supported Linux host or VM. Record PASS, FAIL, SKIP, or
BLOCKED explicitly; a skip is never a pass. Follow the exact commands and
evidence checklist in [workflows.md](workflows.md).

### Current capability boundaries

- **Supported now:** build profiling, build-network learning, lower full-profile
  learn/audit, workspace-scoped net learn/audit, signed activation, and
  CIDR-based scoped net enforce.
- **Required negative gate:** full standalone security-mode enforce must return
  GUARD_STANDALONE_INGRESS_UNAVAILABLE before Docker or policy mutation.
- **Not implemented yet:** the HTTP OFF/LEARN/ENFORCE switch and true
  per-agent policy isolation inside one Notty container.
- **Not an isolation boundary:** the current agent-id value is replay/profile
  metadata; current signed activation and eBPF scope are workspace/run based.
- **FQDN gate:** the signed guard-ebpf backend currently advertises
  tcpDns:false. Accepted FQDN rules must remain activation-ineligible. Use an
  intentionally reviewed CIDR-only fixture for a successful enforce smoke.

### Execution sequence

1. [ ] Freeze the source/artifact/host identities and expected results.
2. [ ] Run unprivileged setup, build the captured-tree Guard bundle, verify its
       detached checksum, and elevate only the extracted installer.
3. [ ] Deep-verify the installed bundle, daemon socket, collectors, kernel/BTF,
       Docker/cgroup-v2 configuration, BPF baseline, and signing trust.
4. [ ] Prove full standalone enforce rejects without Docker, Guard state, BPF,
       profile, or evidence mutation. Repeat after profiling.
5. [ ] Capture complete cold/warm build evidence and a separate build-network
       learning run. Automatic Policy Review opening must not imply approval.
6. [ ] Exercise lower full-profile learn/audit only to its currently
       non-promotable gate; approval and full enforce must remain rejected.
7. [ ] Run granular workspace-scoped runtime learn against the exact built
       image, then use the correlated profile-build-and-run wrapper.
8. [ ] Run scoped audit and prove unmatched traffic is recorded as would-deny
       without training or widening policy.
9. [ ] Prove an accepted FQDN fixture stops as activation-ineligible.
10. [ ] Offline-review and project a controlled CIDR fixture; use separate
        review/deployment keys, issue one short-lived grant, and activate the
        exact bundle.
11. [ ] Run scoped net enforce and verify exact IPv4/IPv6 positive and negative
        IP/port/protocol/DNS/DoT/QUIC/platform controls plus final loss-free
        counters and cleanup.
12. [ ] Inject daemon, Docker, collector, BPF/map/link, containment, cleanup,
        restart, and reboot failures and retain exact evidence.

**Gate:** an immutable evidence index binds the source, host bundle, install,
kernel, Docker, image, workspace, run/container/cgroup/namespaces, BPF
program/link/map/object, evidence manifest, DecisionSet, projection, approval,
grant, activation, network vectors, watchdog result, containment, and cleanup.

## 6 — Implement the Guard-owned network control and per-agent isolation

This is the highest-priority new operator capability, but it depends on
priorities 1, 2, and 5.

### Architecture first

- [ ] Place general Notty traffic and each agent/descendant tree in exact,
      distinct child cgroups under one parent emergency-containment cgroup.
      If necessary, begin with one Guard runner per agent.
- [ ] Add an authenticated operator-only Guard RPC. The browser and Notty may
      request a transition but never receive Docker, BPF, firewall, signing,
      or Guard-management authority.
- [ ] Namespace candidate registry, subject, target context, grant, activation,
      audit, and status by workspace plus exact agent/harness/provider/model,
      tool version, image, backend, and cgroup identity.
- [ ] Make parent/container policy dominate children; a child transition may
      narrow only its own scope and must never widen a peer or parent.

### State machine

- [ ] Expose exactly **OFF**, time-bounded **LEARN**, and selected signed
      **ENFORCE**. Do not provide an ambiguous unrestricted ON state.
- [ ] OFF must install and verify a deny generation before acknowledgement.
      It must address established flows as well as new TCP/UDP, IPv4/IPv6,
      DNS, direct-IP, DoT, and QUIC attempts.
- [ ] If OFF cannot be installed or verified, report degraded/contained and
      pause, stop, then force-remove the exact container as required. Never
      label fallback termination as a successful OFF transition.
- [ ] LEARN is permissive observation with externally/kernel-enforced
      monotonic expiry back to OFF; a browser or Node timer is insufficient.
- [ ] ENFORCE selects one exact reviewed, signed, activated profile. A generic
      UI action can never become unrestricted networking.
- [ ] Reconcile display from Guard after refresh, reconnect, Notty restart,
      daemon restart, identity drift, and reboot. Browser state is never
      authority.

### Per-agent profile sequence

- [ ] Run OFF → bounded LEARN → review → audit → sign/grant/activate → ENFORCE
      independently for general service traffic and each Codex, Gemini, and
      Claude identity.
- [ ] Exercise login, model calls, streaming, tools, retries, refresh, and
      logout with ephemeral credentials while retaining destination metadata
      only.
- [ ] Prove agent A's profile cannot authorize agent B or general traffic.
- [ ] Invalidate authority when agent binary/tool version, harness, provider,
      model, image, workspace, process/cgroup, backend/object, or policy
      revision changes.
- [ ] Label domain views as DNS-derived IP/protocol/port observations. Shared
      CDN, rebinding, SNI, certificate, Host, and application-protocol
      separation require an L7 boundary; do not claim kernel hostname
      enforcement.

**Gate:** simultaneous-agent and failure-injection tests prove agent OFF
contains only that agent, container OFF contains every child, LEARN expires
authoritatively, ENFORCE selects one signed profile, and no stale UI/capability
can change state.

## 7 — Finish the human auth, OTP, terminal, Collab, and Copilot workflows

Implement these after the backend ownership model is stable.

### Split-auth and OTP UI

- [ ] Add an explicit no-mcp-auth launcher mode. Keep browser UI/REST/WebSocket
      behind Basic, public MCP credentialless, and spawn creation behind a
      one-time OTP.
- [ ] Restrict that mode to an explicit loopback publication; reject Guard,
      host networking, wildcard bind, non-loopback origin, and no-OTP
      combinations before Docker starts.
- [ ] Treat unauthenticated MCP as the local anonymous principal from priority
      2. Explicitly test and display which non-spawn tools it can use.
- [ ] Add live countdowns for multiple OTP records using one browser timer,
      server expiresAt values, visibility reconciliation, and authoritative
      refresh at zero.
- [ ] Reveal OTP plaintext once only. Dashboard/history remains metadata-only.

### Terminal tabs

- [ ] Add one accessible × control per live terminal tab.
- [ ] Close the tab's exact owned session without triggering selection.
- [ ] Check response.ok, suppress duplicate requests, remove every pane
      reference only after success, choose deterministic surviving focus, and
      preserve state/error visibility on failure.
- [ ] Preserve Copilot source-exit cleanup and keyboard tab navigation.

### Collab and Copilot

- [ ] Show each agent's Collab capability countdown, default one-hour lifetime,
      explicit bounded replacement, expiry, and revocation.
- [ ] Keep the operator-held public spawn OTP separate. Managed Collab agents
      do not receive or consume spawn OTPs.
- [ ] Add exact-agent **Interrupt** and **Halt** operations. Interrupt preserves
      the runtime for another task; Halt checkpoints, revokes authority,
      preserves evidence, and prevents automatic restart.
- [ ] Add session-wide interrupt/halt only after exact-agent behavior is proven.
- [ ] Bind Copilot to its source owner and retain Off/Insert/Approve controls.
      Autonomous execution requires a separate authority boundary or a
      disposable secret-free Guard environment.

**Gate:** all acceptance flows in workflows.md pass for two principals and
multiple agents without exposing Basic, OAuth, spawn, provider, signing, or
Guard secrets through environment, procfs, filesystem, sockets, URLs, logs,
prompts, channels, metadata, or inherited descriptors.

## 8 — Add independent Guard liveness and activation lifecycle

- [ ] Add an external watchdog/heartbeat capable of containing exact runners
      when the Node daemon is wedged or SIGSTOPed.
- [ ] Add explicit activation renew, revoke, deactivate, status, and emergency
      containment semantics.
- [ ] Display deployment-grant expiry separately from root activation-state
      lifetime and per-run attachment lifetime.
- [ ] Run recurring exact live-state attestations and controlled
      positive/negative probes for scoped eBPF and applicable host gateways.
- [ ] Reduce the privileged TCB toward a small broker; add justified systemd
      capability and syscall bounds.
- [ ] Test daemon deadlock/crash/OOM, Docker hang, collector loss/overflow,
      cgroup/PID reuse, BPF drift, firewall/dnsmasq drift, containment failure,
      cleanup retry, restart, and reboot.

**Gate:** a healthy pinned scoped-eBPF policy remains enforcing, a lost
controller is detected independently, permissive learn/audit evidence becomes
explicitly incomplete, and controls detach only after exact containment and
cleanup are proven.

## 9 — Finish browser, proxy, and helper hardening

- [ ] Remove unsafe-eval/blob capabilities where production framework output
      permits; narrow connect-src and add base-uri, form-action, nosniff,
      Referrer-Policy, COOP, and the intended frame policy.
- [ ] Decide whether the internal Policy Review UI also needs a bearer/session
      gate. Today the graph URL is tokenized; the unpublished attested UI
      service itself is not bearer-tokenized.
- [ ] Require HTTPS for non-loopback stdio proxy targets, reject URL
      credentials, and make debug logs bounded metadata-only.
- [ ] Delete or rewrite bpr.sh with fail-fast behavior, an existing reviewed
      Dockerfile, immutable image ID, loopback publication, normal auth, and a
      generated one-time capability.

**Gate:** browser and auxiliary entrypoints cannot widen authority, leak
credentials, or launch a stale/mutable artifact.

## 10 — Freeze one candidate and close the release gates

History-secret and legal/provenance work may start earlier, but final results
must bind the frozen candidate.

- [ ] Freeze one clean commit/tree and create exact package, production image,
      Guard bundle, SBOM/license inventory, and provenance identities.
- [ ] Run the history and secret scan, including deleted/history-only content.
- [ ] Complete license, notice, font, ANSI/art, asset, and third-party
      provenance review.
- [ ] Inspect the exact production image: context, layers, user, entrypoint,
      packages, CVEs, capabilities, writable mounts, secret canaries, SBOM,
      package/image comparison, and provenance.
- [ ] Run live provider, Basic/OAuth/OTP, HTTP/WS/SSE/MCP, terminal ownership,
      Collab, Copilot, Guard, profile, audit, signed activation, CIDR enforce,
      kill-switch, recovery, and cleanup smokes against those exact artifacts.
- [ ] Run ./scripts/release-audit.sh on the final committed candidate and archive the
      report plus console evidence.
- [ ] Confirm zero unexplained skips, warnings, blocked gates, dirty files, or
      untracked release inputs.
- [ ] Tag and sign the stable version only after the final decision is changed
      in SECURITY_REVIEW.md with evidence.

**Gate:** one immutable release index binds every result to the final commit,
tag, source archive, package hash, image/config digest, Guard bundle, SBOM,
policy/activation, host/kernel test environment, and live-smoke evidence.

## 11 — Optional work after the critical path

- [ ] Add a per-agent/general domain inventory with first/last seen,
      transport/port, process/DNS provenance, uncertainty, loss, and review
      disposition. Export only redacted portable data.
- [ ] Create Codex/Gemini/Claude preprofiles in a separate explicit release
      job with ephemeral credentials. Never run credential-bearing
      preprofiling as an ordinary Docker build step and never union profiles
      automatically.
- [ ] Add opt-in policy-aware blocked-by-network checkpoint/halt behavior.
      Preserve analysis, do not falsely report completion, deduplicate denial
      loops, and make any broadcast halt explicit.
- [ ] Use QEMU/KVM for reproducible clean-guest install, profile, enforce,
      failure, reboot, upgrade, rollback, and cleanup testing with pinned guest
      media and no retained credentials.
- [ ] Evaluate bubblewrap only as defense in depth after UID, credential,
      cgroup, and Guard boundaries exist. Define every namespace/mount/env rule,
      test escape paths, and fail closed when bwrap or user namespaces are
      unavailable.
- [ ] If actual hostname enforcement is required, design the forced L7
      DNS/SNI/certificate/Host boundary and block direct TCP/QUIC bypasses.

## Completed work removed from the old next position

The previous next.md described automatic Build Network Learn → Policy Review.
That is no longer the next implementation item:

- human-readable build-nosh net learn invokes the review handoff;
- no-review and machine/dry-run suppression exist;
- managed UI/graph images, dynamic Docker-bridge discovery, exact-origin graph
  access, OSC-8/plain links, nonfatal browser opening, incomplete-profile
  display, private state permissions, and stale-container rejection have
  deterministic coverage.

Keep those tests in the regression suite. Correct the old wording when this
behavior is documented elsewhere: Docker may choose any attested 172.16/12
bridge address, only the graph endpoint is bearer-tokenized, and opening a
review never implies approval or activation eligibility.

## Definition of done for every priority

- [ ] Implementation, negative tests, failure tests, and operator documentation
      agree on the same security boundary.
- [ ] Package-manager commands, tests, builds, audits, and packaging run only
      inside the required container workflow; never run npm, npx, or Node
      package work on the host.
- [ ] Secrets never appear in patches, prompts, command output, retained logs,
      screenshots, portable evidence, or committed fixtures.
- [ ] A result is PASS, FAIL, SKIP, or BLOCKED; skips and unsupported
      capabilities are never described as passing.
- [ ] Evidence is machine-readable, bounded, immutable, and bound to exact
      identities.
- [ ] SECURITY_REVIEW.md is updated when a finding closes or its assumptions
      change.
- [ ] The worktree is clean and the final release audit passes at the exact
      candidate before any tag is published.
