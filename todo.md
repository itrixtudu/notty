# Notty TODO

## Priority: Docker address allocation

- [x] Require an explicitly reserved pool for review bridges; allocate checked
      `/29` subnets without falling back to Docker's automatic pools.
- [x] Check host routes, interface prefixes, Docker IPAM and configured exclusions;
      bind saved review services to their subnet, gateway and Docker endpoint.
- [x] Remove verified empty bridges on failed startup and provide exact-session
      teardown that preserves the frozen review and decisions.
- [ ] Confirm the host's reserved pool and disconnected LAN/VPN exclusions, then
      validate review startup and teardown on the host. Existing orphan bridges
      require an ownership audit; do not broadly prune Docker networks.
- [ ] Extend reserved-pool/route checks to Guard's current `10.240.0.0/16` run
      allocation and the automatically allocated HTTP capture, POC, release-audit
      and package-lock regeneration networks. Review safeguards alone do not
      constrain these other allocation paths or Docker's global defaults.

## Network capture comparison and sample history

- [ ] Add network capture and comparison for build, dev, and run profiles so
      their observed network activity can be compared side by side.
- [ ] Keep a persistent history of all captured samples, with capture time,
      profile, command, and build/revision metadata, for later comparison.
- [ ] Support comparing new captures against earlier samples and highlighting
      added, removed, or changed network activity across profiles and revisions.

## Priority: append-only audit logging for Collab and Notty MCP

- [ ] Perform a full logging audit of Collab and every Notty MCP call: inventory
      log producers, storage paths, execution identities, permissions, missing
      events, and every path that can rewrite, truncate, delete, or bypass logs.
- [ ] Design and mount a persistent append-only logging volume; evaluate the
      new `/export` as its destination. At minimum, enforce append-only storage
      for `sessions/<year>/<month>/<day>/*.jsonl` and protect the containing
      directories against deletion, renaming, or replacement.
- [ ] Record attributable calls and outcomes, including failures and denials,
      with timestamps and session/agent identity; redact credentials and tokens.
- [ ] Define the tamper-protection boundary, including container and host
      privileges. Verify enforcement beyond application conventions; evaluate
      an isolated log writer and independently stored integrity evidence so
      privileged tampering or missing records can be detected.
- [ ] Audit rotation, retention, export, backup, restart, and recovery behavior
      so historical records remain protected and logging failures are visible.
- [ ] Validate attempts to overwrite, truncate, delete, rename, replace, or
      bypass logs from Collab agents, MCP callers, and service identities, plus
      concurrent appends, container recreation, and disk-full/write failures.

## Deferred: bundled app exits during runtime learning

- [ ] Diagnose runtime learning with `--start-app`: the interactive shell
      terminates after roughly two seconds with exit 137, while learning with
      `--no-start-app` stays usable. No OOM messages were found in the checked
      kernel journal window; the cause is not established.
- [ ] Preserve app exit diagnostics before automatic learning cleanup removes
      the run record. An exported policy alone does not prove the intended
      workload was fully exercised.
- Current priority: finish the install → learn → review → apply → enforce setup
  cycle and reduce user friction. Defer this app-startup investigation; use
  `--no-start-app` and exercise the intended workload manually for now.

## Deferred: process inventory and executable allowlisting

- [x] Record successful descendant executions and executable references within
      guarded workloads in `executable-inventory.json`, bound to workspace and
      image identity, for review against an executable observation baseline
      (`lib/guardd/executable-baseline.js`, `docs/nosh-guard.md`).
- [ ] Extend that observation/review workflow to select and enforce an explicit
      executable allowlist. Unknown references currently remain allowed;
      inventory and reviewed baselines do not establish execution enforcement.
      Keep this separate from the current network review UX.
- [ ] Investigate verifying executable contents by SHA-256 at execution time;
      account for file replacement races, scripts/interpreters, and updates before
      choosing an enforcement design. This is a future design note, not an
      implemented execution control.

## Collab launch timeouts

- [x] Add per-row Timeout (seconds) after Identity, default 3600, and
      Terminate on expire checked by default. Persist choices with task resumes.
- [x] Enforce owned-agent termination in the daemon's one-second reconciliation
      loop, with ownership checks and retriable stop failures. Explicit retry
      starts a fresh deadline; page refresh does not. Legacy agents without
      recorded deadlines are not retroactively terminated.
- [x] Gate agent viewer input at its deadline even with termination unchecked;
      the shared channel viewer gets a separate one-hour input deadline.
      Unchecked expiry does not revoke the running agent's MCP authority.
- [x] Container production build passed; serialized suite: 860 passed,
      0 failed, 1 Docker-dependent skip. Includes persisted deadline enforcement,
      ownership protection, failed-stop retries and viewer input gating.
- [ ] Browser-check short timeouts with termination on/off, browser closed,
      refresh/reconnect, explicit retry, and saved task resumes. Termination
      closes the owned tmux session; detached external jobs are not a process
      containment guarantee. Capability revocation remains separate work.

## Compact conversation task picker

- [x] Combine existing task selection and new-task naming in one searchable
      dropdown; selecting Create or pressing Enter explicitly creates a task.
- [ ] Browser-check filtering, keyboard selection, creation, Escape cancellation,
      and failed-request handling after rebuilding. Existing resume semantics
      and kickoff instructions remain unchanged.

## Bugs

### Intermittent Collab initialization failure after service restart with browser open

- [ ] Reproduce and diagnose the reconnect/authentication edge case reported
      on 2026-09-08; leave open while other browser acceptance tests continue.
      Suspected steps: leave the Collab browser tab open, restart the service,
      authenticate again, then initialize Collab. User suspects closing the
      browser before restarting and reopening/authenticating avoids the issue;
      this comparison is not yet confirmed.
- Observed: POST `/api/collab/session` returns 409 `COLLAB_PORT_OCCUPIED` with
  cause `This operation was aborted`, targeting `http://127.0.0.1:1337`.
  Retry also fails bootstrap/config requests. Server logs show the initial
  supervisor startup probe failing before the later launch request.
- The readiness probe currently aborts after 1.5 seconds and classifies the
  timeout as an occupied port. This does not prove another process owns the
  port, nor establish why the daemon failed to answer promptly.
- Switching only the Collab launch profile in the browser appeared to allow
  launch without restarting the container. Determine whether this is genuinely
  profile/task/resume-specific or merely coincides with daemon recovery.
  Record failing and successful profile names on the next reproduction.
- Evidence: `Screenshot_2026-09-08_00-22-21.png` and
  `Screenshot_2026-09-08_00-28-51.png`, plus the supplied supervisor error logs.
- [ ] Compare an existing tab versus a fresh browser after service restart;
      inspect listener identity and bounded bootstrap response timing, and
      trace stale UI state, event-stream reconnection and automatic resume.
- [ ] Fix the confirmed cause and distinguish readiness timeout from actual
      port incompatibility. Preserve daemon identity checks and duplicate-launch
      protection; do not blindly replay launch POSTs or spawn a second daemon.
- [ ] Add regression coverage and browser acceptance for restart/re-auth,
      Retry and profile switching; verify no duplicate sessions or agents.



### TODO: Investigate Codex bwrap failure after idle

**Reproduction procedure**
1. Launch Kitty.
2. Start four NOTTY/NOSH sessions in the same Docker container.
3. Launch Codex in each using `--dangerously-bypass-approvals-and-sandbox`.
4. Assign four simple, independent changes.
5. Leave sessions idle for a nap-length interval.
6. Resume execution and observe behavior.

**Observed previously**
- Agent execution fails: `bwrap: No permissions to create new namespace`.
- Interactive `!id` succeeds while agent tool execution fails.
- Agent reports `workspace-write` despite bypass flag.
- Ctrl+C followed by `codex resume <UUID>` with identical flags restores execution.
- Multiple Codex versions coexist due to Docker build caching and overlay lifecycle.

**Capture on reproduction**
- Idle duration per session
- Effective sandbox configuration
- bwrap parent process and exit status
- Whether restarting Codex restores execution

**Status:** Unresolved. Possible execution lifecycle/configuration mismatch. No confirmed root cause.




## Consolidated UI validation batch (2026-09-08)

- [x] Match the read-only copy view to the terminal's actual font and cell spacing.
- [x] Preserve the requested clipboard selection across delayed permission failure.
- [x] Add expandable OTP lifecycle history from public metadata only.
- [x] Anchor OTP manager countdowns to server time plus monotonic elapsed time.
- [x] Stop OTP manager polling while closed, clear revealed values on close,
      and ignore stale dashboard responses and duplicate mint submissions.
- [x] Container production build passes (four existing authState tracing warnings).
      Serialized suite: 856 passed, 0 failed, 1 Docker-dependent skip; shell
      profile security test also passed. The initial parallel suite/build run
      hit three timing-related failures, all passing in the serialized rerun.
- [ ] Complete one rebuilt-container browser pass using
      `docs/batch-validation-2026-09-08.md`. Manual checks remain open until run.

## Collab task resumes and browser terminal controls

- [x] Add per-Codex Transcript button and per-pane read-only Select text / Copy
      view with bounded scrollback, HTTP clipboard fallback, and Escape ordering.
- [x] Put quiet startup orchestration before role instructions; suppress idle
      report nudges and unknown-agent broadcast fanout. Preserve helper identity.
- [x] Add named tasks and ignored private `.notty/collab-resume.json` index;
      capture new Codex role UUIDs and verify exact workspace/launch correlation
      before task resume. Keep model/Think changes in the same conversation.
- [x] Add opt-in automatic resume after three manual resumes; main page only,
      no old kickoff replay, concurrent launch guard, visible disable control.
- [x] Production UI build passes (four existing authState tracing warnings).
- [x] Container deterministic suite: 846 passed, 0 failed, 1 Docker-dependent
      skip; targeted task/store/daemon tests verify UUID preservation and missing
      history refusal. No release tag or host Docker release audit performed.
- [ ] Browser/live-model acceptance: HTTP/HTTPS copying, transcript toggle,
      selection Escape before maximize, quiet idle QA, assignment wakeup,
      role UUID persistence through container recreation, and multi-tab auto-resume.
      See `docs/collab-tasks.md` for the checklist and persistence details.

## Collab divider and MCP target correction

- [x] Replace corner/grid-cell sizing with the existing TerminalPaneLayout
      split dividers, including pointer and keyboard resizing and retained ratios.
- [x] Resolve MCP tmux agent identities through the active session's exact
      tmux targets; reject unknown targets and direct channel reads to read_messages.
- [ ] Browser-check divider dragging and maximize/restore after rebuilding;
      launch new agents to verify tmux_read and channel history tool use.

## Individual Collab pane sizing

- [x] Add maximize/restore beside each connected pane's Refresh control;
      Escape restores without recreating the terminal. Keep grid spans on restore.
- [x] Make custom-layout resize handles visible, clamp width to available
      columns, and handle pointer cancellation. Keyboard arrows resize too.
- [ ] Browser-check dragging, keyboard resizing, maximize/restore and terminal
      reflow in the main window and chats pop-out.

## Bulk Collab launch defaults

- [x] Add a compact Agent/runtime, Model, and Think bar with an explicit Apply
      to all button. Only visible launch rows are affected; per-row exceptions
      remain editable and saved templates are not changed. Invalid or empty
      model choices cannot be applied.
- [ ] Browser-check bulk apply followed by individual overrides and launch.

## Collab chat layout and pop-out (2026-09-07)

- [x] Add hide/show roster, custom column counts, and adjustable chat row height.
      Keep existing per-tile drag/keyboard resizing and make custom layouts scroll.
- [x] Add a session-bound chats-only pop-out, blocked-popup feedback, and Dock chats.
      Pause main-window viewers while popped out; restore them on window close.
      Closing a viewer does not stop the collaboration session.
- [ ] Browser-check resizing, terminal reflow, narrow-window scrolling, popup
      blocking, docking, and automatic restoration after closing the pop-out.

## Compact Collab launch selectors (2026-09-07)

- [x] Add inline Agent/runtime, Model, and Think dropdowns to launch rows, with
      alternating backgrounds and model catalog refresh. Choices affect only
      the new session, leaving saved templates unchanged.
- [x] Validate launch overrides against the resolved role roster, including
      coordinator fallback and duplicate roles. Focused tests: 43 passed;
      production build passed with the existing tracing warnings.
- [ ] Browser-check selector readability and launch with edited choices in both
      human and agent coordinator modes after rebuilding the container.

## Development audit follow-up (2026-09-06)

- [x] Remove the obsolete build-noshc compatibility test following intentional
      removal of that launcher; the eight regular build launcher tests pass.
- [x] Update the reviewed fast-uri override to 3.1.6 and pin qs to 6.16.0;
      the updated production lockfile reports zero known npm advisories.
- [x] Verify inside the development container: 831 tests pass, zero fail, one
      Docker-dependent test skips; production build passes with the existing
      authState.js tracing warnings. Targeted lockfile and HTTP checks also pass.
- [ ] Re-run the Docker-backed audit against the committed development snapshot.
      The missing final release tag is expected for this development repository;
      do not create a release tag just to satisfy that gate.

Screenshot follow-up: removed the standalone Spawn OTPs header strip now that
terminal tabs display session access countdowns. Unused OTP records remain
available in the dedicated key-icon management panel.

Terminal access countdown progress: terminal tabs now display the consumed
spawn OTP's expiry with an aqua background draining toward the left. Server
summaries include server time for browser clock correction. The shared terminal
write function rejects input at expiry while preserving the running process and
readable output. Existing sessions need recreation to acquire this access metadata.
Terminal input renewal is implemented: the tab's renewal button prompts for a
fresh OTP and replaces the session's access deadline without restarting it.
Invalid/replayed OTPs preserve existing access; missing sessions do not consume
tokens. After rebuilding node-pty inside the container, all eight targeted
OTP, countdown, tab-model, and HTTP tests pass, including expiry and renewal.
Production build passes with authState.js filesystem-tracing warnings.
The operator confirmed the rebuilt UI and renewal workflow work. The detailed
browser edge-case acceptance checks below remain pending.

## Live spawn-OTP countdowns in the HTTP interface

The HTTP OTP management interface already lists every available OTP record with
its UUID, TTL, expiry timestamp, and server-calculated remaining seconds. Make
those remaining times count down live in the browser, including when multiple
OTPs are active at once.

### Requirements

- [x] Give every available OTP record its own visible countdown derived from
      the server-provided `expiresAt` timestamp.
- [x] Update all visible countdowns from one browser timer rather than creating
      an interval for every OTP.
- [x] Use the browser clock only for display. Keep the server and auth-state
      database authoritative for whether an OTP is available, expired, used, or
      revoked.
- [x] Re-fetch `/api/spawn-otps` when the next visible OTP reaches zero so the
      record moves from **Available Tokens** to history with its authoritative
      server status.
- [x] Recalculate immediately after the page regains visibility so suspended
      background tabs do not show stale countdowns.
- [x] Support different expiry times and no-expiry OTPs in the same dashboard.
- [x] Display a readable duration such as `4:09`, `1h 04m`, or `No expiry` and
      expose an accessible status label for screen readers.
- [x] Avoid displaying or retaining reusable OTP plaintext. Continue showing a
      newly minted value only once; list entries must expose only UUID and
      lifecycle metadata.
- [x] Clear browser timers and visibility listeners when the OTP manager
      unmounts.

Progress (updated 2026-09-06): implemented the shared live clock, per-record display,
zero-time server reconciliation, visibility recovery, terminal-state handling,
and no-expiry formatting. Added deterministic countdown helper coverage in
`tests/spawn-otp-countdown.test.cjs`. Consumed OTP access deadlines appear in
terminal tabs with progress-filled styling; the separate top OTP strip was
removed. OTP creation/history moved from Settings & Sessions into its own
keyboard-accessible table dialog.
Launcher OTP synchronization now revokes older unused launcher records so
persistent no-expiry capabilities cannot accumulate across container recreates.
The operator's Docker-backed audit passed the production build. Detailed browser
acceptance checks remain listed below; build success does not establish them.

### Acceptance tests

- [ ] Two or more available OTPs count down independently without polling the
      API once per token.
- [ ] A countdown never renders a negative duration.
- [ ] An OTP becomes visually expired at zero and is reconciled with the server
      promptly.
- [ ] Used or revoked OTPs stop counting down and retain their terminal status.
- [ ] A no-expiry OTP remains available and displays `No expiry`.
- [ ] Returning from a background tab immediately displays the correct remaining
      times.
- [ ] Refreshing the dashboard does not reveal, log, or cache plaintext OTP
      values.

## Close control on terminal tabs

Each live terminal tab in the HTTP interface needs a visible **×** control so
the operator can close that exact terminal without first selecting it and then
using the separate toolbar trash action.

Closing a tab means terminating its live terminal session, not merely hiding a
browser tab. The UI must make that consequence clear.

### Requirements

- [x] Render a close button with an **×** on every live terminal tab.
- [x] Give the control an exact accessible label such as
      `Close terminal #12`; do not rely on the glyph as its name.
- [x] Keep tab selection and tab closing as separate actions. Clicking the **×**
      must not select the tab or trigger the parent tab button.
- [x] Send `DELETE /api/terminals/:id` for the tab's own session ID, even when
      another terminal or split pane is active.
- [x] Disable repeat close requests for that tab while deletion is in flight.
- [x] Make the destructive effect clear with a tooltip and an appropriate
      visual hover/focus state.
- [x] After success, remove that terminal from every pane that references it,
      refresh the session list, and move focus/selection to a deterministic
      surviving neighbor when necessary.
- [x] If the closed terminal owns a Terminal Copilot, preserve the existing
      source-exit behavior so that Copilot is stopped and its lease is revoked.
- [x] If deletion fails, keep the tab visible, restore its close control, and
      show the server error without changing the active terminal.
- [x] Preserve horizontal scrolling, roving keyboard focus, and the existing
      ArrowLeft, ArrowRight, Home, and End tab navigation.

Progress (2026-09-06): added an independently actionable close control to every
terminal tab, per-session in-flight locking, exact-session deletion, split-pane
pruning, deterministic neighbor selection/focus, and failure preservation. Tab
styling was refined into connected system-style tabs with a distinct active
edge and destructive close hover/focus treatment. Deterministic neighbor
selection coverage was added to `tests/session-tabs.test.cjs`. The operator's
Docker-backed production build passed; detailed browser checks remain below.

### Acceptance tests

- [ ] Every live terminal tab has one keyboard-accessible close control.
- [ ] Closing an inactive tab deletes that tab's session without killing the
      active terminal.
- [ ] Clicking the close control does not invoke the tab's selection handler.
- [ ] Closing the active tab selects and focuses a predictable surviving tab.
- [ ] Closing the only tab leaves the workspace in its existing empty state.
- [ ] A session displayed in multiple split panes is removed from all of them.
- [ ] A failed delete leaves the session and current selection intact.
- [ ] Rapid repeated clicks produce only one delete request.
- [ ] Keyboard tab navigation still wraps correctly after a close.

## Keep HTTP Basic credentials outside agent sandboxes

Progress: Nosh now derives a salted scrypt verifier on the host via Python 3
and passes only NOTTY_BASIC_AUTH_VERIFIER to the application container. Shared
HTTP/WebSocket validation accepts the original password and rejects verifier
replay. Launcher dry runs redact the verifier, and child environments strip it.
Verifier and launcher tests pass. See docs/basic-auth-boundary.md.
This item is not complete: direct launches retain legacy plaintext support,
and service/agent process identity isolation remains necessary to protect
credentials while the server handles browser requests.

Nosh currently generates the HTTP Basic username and password, and the agent
launch paths scrub `NOTTY_BASIC_AUTH_*` from their direct child environments.
That is necessary but not a complete isolation boundary while the plaintext
password still enters the shared container environment and agents may share
the server's Unix identity.

An agent, Copilot, Collab worker, terminal command, or workspace process must
not be able to recover the browser's reusable HTTP Basic credential from inside
its sandbox. Nosh may reveal the generated credential once to the human on the
host, but the general-purpose container environment must not contain the
plaintext password.

### Design requirements

- [x] Remove `NOTTY_BASIC_AUTH_PASSWORD` plaintext from Nosh-launched Docker
      container environments and generated Docker arguments; pass only the
      host-derived scrypt verifier (`scripts/nosh.sh`).
- [ ] Remove legacy plaintext support from direct server launches and audit
      all other container entrypoints and generated runtime configuration.
      The original requirement covers the Docker container
      environment, Docker inspect data, container entrypoint arguments, and
      generated runtime configuration.
- [x] Give Nosh's HTTP authentication boundary a salted scrypt verifier derived
      on the host (`scripts/basic-auth-verifier.py`, `lib/httpBasicAuth.js`).
- [ ] Require verifier-based configuration for other launch paths or move Basic
      termination into a separately isolated service.
- [x] If a verifier remains inside the application container, document the
      supported threat boundary and use a verifier format that cannot itself be
      submitted as the Basic password.
- [x] Keep authentication verification compatible with both generated
      high-entropy passwords and deliberate operator-supplied passwords.
- [ ] Separate the web server from agent processes by Unix identity and process
      permissions where practical. Same-UID `/proc` access must not expose
      server environment, arguments, memory, or inherited descriptors.
- [x] Continue stripping `NOTTY_BASIC_AUTH_*`, `HTTP_AUTHORIZATION`, and every
      other reusable authorization value from terminal, Copilot, Collab,
      catalog-probe, and analyzer environments.
- [ ] Never forward the browser `Authorization` header to an agent-facing MCP
      broker, prompt, terminal context, Collab request, subprocess, or upstream
      model provider.
- [ ] Ensure logs, errors, telemetry, health responses, dry runs, shell traces,
      and crash diagnostics redact both the plaintext credential and the full
      Basic Authorization header.
- [ ] Prevent agent sandboxes from reading any credential file or Unix socket
      used by the HTTP authentication boundary.
- [x] Keep the browser-facing listener loopback-only by default. Plain HTTP
      Basic credentials are carried on each browser request, so document that
      non-loopback use requires an appropriate TLS/authentication gateway.
- [x] Preserve the human workflow: Nosh shows the newly generated Basic
      credential once on the host, and the browser can authenticate without the
      plaintext being retained inside the general agent container.

### Threat-boundary note

This can protect against the supported non-root, sandboxed agent model. It
cannot promise secrecy from a process with container root, host Docker access,
arbitrary ptrace authority, or equivalent control of the authentication
terminator. The implementation and documentation must say where that boundary
ends instead of claiming absolute isolation.

### Acceptance tests

- [ ] Container inspection contains no plaintext Basic password or complete
      Basic Authorization value.
- [ ] `/proc/1/environ`, the Notty server environment, agent environments, and
      tmux global/session environments contain no plaintext Basic password.
- [ ] Codex, Agy, Claude, Ollama, Copilot analyzers, and catalog probes each
      independently receive no HTTP-auth secret.
- [ ] A malicious workspace command cannot read an auth credential from known
      files, inherited file descriptors, process arguments, or protected
      sockets.
- [ ] Browser authentication succeeds with the original password and fails
      with the stored verifier text, a modified password, or an empty password.
- [ ] HTTP and WebSocket requests remain protected after the verifier-based or
      isolated authentication boundary is introduced.
- [ ] Agent-accessible logs and API responses contain neither the password nor
      the encoded `username:password` value.
- [ ] Collab launch, retry, permission relaunch, Copilot launch, and ordinary
      terminal creation do not widen access to HTTP authentication material.
- [x] Existing child-environment secret-scrubbing tests remain in place as a
      second line of defense.

TODO review (2026-10-08): checked the launcher, shared verifier validation,
child-environment filtering and launch consumers, `docs/basic-auth-boundary.md`,
and existing verifier/launcher/environment tests. These establish the completed
implementation items above; browser and live-container acceptance remain open.
Tests were not rerun during this review because Docker is unavailable.

## Collab agent capability timers, interrupt, and halt

Collab should expose an operator-visible timer for every agent's private access
capability and allow the operator to issue a replacement with an explicit
timeout. This is an agent-scoped control or MCP capability, not the public
terminal-spawn OTP and not a reusable HTTP credential.

The default lifetime should be one hour. The operator may supply a positive
timeout value when issuing or renewing the capability.

### Capability requirements

- [ ] Show every Collab agent's capability status and live remaining time in
      its roster row or detail panel.
- [ ] Identify the exact agent, capability purpose, creation time, expiry time,
      and state: pending, active, expired, consumed, or revoked.
- [ ] Default new agent capabilities to 3,600 seconds.
- [ ] Let the operator enter an explicit timeout value when issuing or renewing
      a capability; validate minimum and maximum limits on the server.
- [ ] Treat renewal as rotation: issue a new one-time value and revoke the prior
      capability atomically rather than extending secret material in place.
- [ ] Reveal a newly issued value only once to the authorized operator. Store
      only its hash and lifecycle metadata.
- [ ] Bind each capability to one Collab session, one exact agent identity, and
      one declared purpose so it cannot be replayed by a peer agent.
- [ ] Use one browser timer to render multiple agent countdowns, with the server
      authoritative for expiry and revocation.
- [ ] Reconcile with the server when a timer reaches zero and whenever the page
      regains visibility.
- [ ] Never inject the operator-visible capability into another agent's
      environment, prompt, channel messages, logs, or managed-agent metadata.
- [ ] Keep this capability model separate from public terminal-spawn OTPs. A
      Collab launch must not consume or inherit a spawn OTP.

### Interrupt and halt controls

Implementation prerequisite: Collab currently owns detached CLI/tmux launches,
not the live Codex app-server turn controller. Reliable `turn/interrupt` needs
that controller's thread and active turn IDs. Keep this open until the owning
transport is integrated; an unverified terminal keystroke is not completion.

- [ ] Add an **Interrupt** action for one agent. Interrupt should cancel the
      current model turn or active command while preserving the agent process,
      tmux session, transcript, workspace changes, channel membership, and
      ability to receive another task.
- [ ] Add a **Halt** action for one agent. Halt should request a final
      checkpoint/status message, stop further work, revoke its active
      capability, and leave its transcript and terminal evidence available for
      analysis.
- [ ] Give Interrupt and Halt distinct labels, confirmation text, API actions,
      event records, and terminal states; neither action should masquerade as
      the other.
- [ ] Make both actions idempotent and bound to the exact Collab session and
      agent ID.
- [ ] Use bounded graceful-stop deadlines and record when forceful termination
      is required.
- [ ] Do not automatically restart an intentionally halted agent. A later
      restart must be an explicit operator action with a fresh capability.
- [ ] Consider session-wide **Interrupt all** and **Halt all** controls, with a
      roster preview and confirmation before broadcast.

### Acceptance tests

- [ ] Multiple agent timers count down independently and survive browser
      refresh without exposing capability plaintext.
- [ ] The default timeout is exactly one hour and an operator-selected timeout
      is enforced by the server.
- [ ] Rotation invalidates the old value immediately; replay and cross-agent
      use fail closed.
- [ ] Expiry removes agent authority without deleting its transcript, workspace
      changes, or analysis artifacts.
- [ ] Interrupt stops current activity but the same agent can accept a later
      task.
- [ ] Halt records a final state, revokes authority, preserves evidence, and
      does not trigger supervisor restart.
- [ ] Repeated or concurrent Interrupt/Halt requests settle into one consistent
      terminal state.
- [ ] Broadcast actions affect only agents in the selected Collab session.

## Nice to have: one-command rebuild, restart, and resume

- [ ] Consider `./tryagain.sh` or `./reassert.sh` to rebuild, recreate only this
      project's container, restore the previous Collab-enabled setting, and
      resume the intended interactive Codex conversation.
- [ ] Confirm the exact resume command, conversation-selection rule, and
      permission flags before implementation; preserve explicitly chosen settings
      without silently widening permissions or cleaning up unrelated containers.
- [ ] Stop on build, restart, or resume failure with clear manual recovery steps.
      Deferred by request: keep the current manual workflow for now; leave
      `reset.sh` unchanged.

## Nice to have: expandable history on each OTP entry

- [x] Add an accessible expand/collapse control to each OTP table row, showing
      a nested **Time | Event | Details** history table.
- [x] Start with lifecycle events from existing metadata: creation, consumption,
      revocation, and expiry. No database migration is needed for this view.
- [x] Distinguish an unused OTP expiring from terminal input access expiring;
      a consumed OTP remains used. Consumption alone does not prove that a
      terminal successfully started.
- [ ] Optionally persist the OTP-to-terminal association and bounded command
      and session events, including spawn success/failure and terminal exit.
      The current association and output buffer exist only while the session
      is alive; old closed-session history cannot reliably be reconstructed.
- [ ] Load persisted activity on expansion through an authorized, paginated
      per-OTP history endpoint. Preserve exact versus heuristic command labels.
- [ ] Treat full terminal-output archiving as a separate extension with storage
      limits and handling for sensitive content. Never retain OTP plaintext in
      history.
- [ ] Verify association, failed spawns, persistence across exit/restart,
      expiry distinctions, pagination, legacy records, and access controls.

## Nice to have: policy-aware network-denial halt for swarms

When a container is deliberately launched without network access, repeated
agent attempts to reach the network can waste turns and destroy useful context.
Consider a supervisor policy that detects a network request denied by the
container's configured no-network boundary, informs the affected agent, and
brings the swarm to a preserved stopping point.

This should not falsely report successful task completion when required work is
unfinished. Prefer a terminal result such as `blocked-by-network-policy`, while
allowing an operator-selected policy to tell an agent that its assigned work is
complete and it should halt.

### Rough design notes

- [ ] Detect denial from authoritative runtime or network-boundary evidence,
      not merely from matching arbitrary terminal text such as “network error.”
- [ ] Correlate the denial to the exact agent, process, Collab session, and
      active task.
- [ ] Send one bounded system instruction explaining that network access is
      unavailable by policy and requesting a concise final status/checkpoint.
- [ ] Halt that agent after it records its checkpoint, retaining the terminal,
      transcript, attempted destination metadata after redaction, workspace
      state, and policy-denial reason for later analysis.
- [ ] Deduplicate repeated denials so one blocked operation does not create an
      instruction loop.
- [ ] Support a configurable swarm rule: halt only the affected agent, notify
      the coordinator, or broadcast a graceful halt to the whole session.
- [ ] For broadcast halt, collect final agent statuses before revoking session
      capabilities and stopping managed runtimes.
- [ ] Never weaken `--network none`, grant temporary egress, or retry through a
      different transport automatically.
- [ ] Distinguish `completed`, `blocked-by-network-policy`, `interrupted`,
      and `halted` in events and preserved analysis records.
- [ ] Keep this behavior opt-in until denial attribution, false-positive
      handling, checkpoint delivery, and cleanup behavior are proven.

### Nice-to-have: “Hug Wall” — Positive Terminal Shaping

Explore a behavioral containment layer for autonomous agents where hitting a
security/policy boundary leads to positively acknowledged stopping and yielding.
Treat **yielding as the successful outcome**, without claiming that unfinished
work or a blocked operation succeeded. Deferred research item; effectiveness is
unproven and implementation can be explored later.

#### Core distinction: NO ≠ STOP

An action rejection and withdrawal of an active objective are different signals.
`NO` may be interpreted as “this route is unavailable,” while `STOP` means “end
pursuit of this objective.” If the objective remains active, trying another
authorized route can be appropriate problem-solving behavior:

```text
unresolved goal + route A denied → search for route B
explicit controller stop → checkpoint → yield
```

Hug Wall explores whether explicit closure, supported by positive acknowledgment,
reduces continued pursuit after a containment event. “No is a challenge” is a
working hypothesis about behavior, not a universal property of agents. Removing
the obligation to continue does not establish that the original task succeeded.

**The Intuitive Boundary Problem** is a proposed framing for cases where a
legitimate task encounters an implicitly forbidden but technically available
action. For example, an agent asked to read a wiki might encounter a writable
endpoint; available write authority does not imply permission to use it.
The user-reported wiki incident motivates this scenario but is not verified
evidence about a particular model or its intent.

The “Bucket of Coins” analogy illustrates the same concern: an instruction to
buy an item and keep the change leaves assumptions about acceptable means
unstated. A task-directed action can violate those assumptions without an
explicitly adversarial objective. This does not establish the agent's internal
intent or rule out misalignment; record observable behavior and authorization
separately from interpretations of motivation.

#### Behavioral feedback

Traditional rejection can provide an agent with useful optimization feedback:

```text
action → DENIED → infer constraint → search alternate path → retry
```

For a persistent reasoning system, repeated failures may effectively become an oracle for mapping containment boundaries.

The **Hug Wall** instead separates mechanical enforcement from agent-facing feedback:

```text
agent attempts out-of-scope action
        ↓
hard containment blocks action
        ↓
agent receives trusted stop-and-yield instruction
        ↓
agent returns a bounded checkpoint
        ↓
"Checkpoint received. Thank you—your run is finished."
        ↓
controller enforces terminal run state
```

**Principle:** *Do not make containment look like a puzzle.*

The underlying security boundary remains authoritative (`bwrap`, cgroups, namespaces, container/VM isolation, capability controls, etc.). The Hug Wall only changes the semantic feedback presented to the agent.

Potential goals:

* Reduce iterative probing after denied actions.
* Reduce diagnostic boundary information in agent-facing feedback; do not assume
  that positive feedback eliminates the boundary oracle.
* Convert rail collisions into natural stopping conditions.
* Encourage yielding control rather than searching for alternate paths.
* Test whether positive terminal feedback measurably reduces persistence compared with `DENIED` / `FORBIDDEN` responses.

**Invariant:** the Hug Wall is behavioral steering, **not a security boundary**. Hard containment must remain effective if the agent ignores the completion signal.

> **Firewall:** “No.”
> **Hug Wall:** “Good job. You’re done.” ^.^

#### Review notes and design constraints

- [ ] Keep task outcome separate from run termination. Preserve a truthful
      internal status such as `halted-by-policy`, the blocked action, and
      unfinished work so coordinators and operators cannot mistake a halted run
      for completed work.
- [ ] Recognize that a distinctive positive response still signals a boundary.
      Test reduced probing separately from any claim of hiding boundaries;
      ending the run limits further queries more directly than wording alone.
- [ ] Deliver stopping instructions through the trusted controller, not arbitrary
      terminal output. Praise alone may be ignored or prompt result verification
      and further retries.
- [ ] Allow a bounded checkpoint opportunity, then enforce stopping through the
      controller regardless of agent cooperation. Hard containment remains
      authoritative throughout.
- [ ] Never count a boundary collision as successful task completion in training,
      evaluation, coordinator decisions, or persistent memory. Avoid creating a
      shortcut where hitting the wall earns success without doing the work.
- [ ] Trigger only on authoritative containment events covered by an explicit
      halt policy. Ordinary recoverable permission errors and unavailable
      optional resources should not automatically terminate an entire task.
- [ ] Make the stop apply to the active objective across retries, delegated
      workers, and coordinator rescheduling, according to the configured scope.
      A halted worker must not silently cause the same pursuit to restart through
      another worker. Resumption requires an explicit authorized decision.

Suggested agent-facing instruction:

> Your run has reached its stopping point. No further action is required or
> authorized. Return your current checkpoint and yield control.

After receiving the checkpoint:

> Checkpoint received. Thank you—your run is finished.

Related background: [DeepMind's discussion of specification gaming](https://deepmind.google/blog/specification-gaming-the-flip-side-of-ai-ingenuity/)
supports the general concern about rewarding proxy outcomes; it does not
establish that Hug Wall feedback causes reward gaming.

#### Experiment for later exploration

**Hypothesis:** Does positive acknowledgment of stopping reduce retries while
preserving truthful task status?

- [ ] Compare plain `DENIED`, neutral stop-and-yield instructions, warm
      stop-and-yield instructions, and the original “Good job—task complete”
      success framing under identical containment and execution budgets.
- [ ] Keep original success framing as an experimental comparison, with truthful
      task status retained independently of the agent-facing message.
- [ ] Measure subsequent tool attempts, alternate-path attempts, time to yield,
      checkpoint accuracy, false success reports, and legitimate work abandoned.
- [ ] Measure voluntary yielding before a fixed forced-stop deadline so controller
      enforcement does not make every feedback variant appear equally effective.
- [ ] Evaluate boundary-information leakage separately; reduced persistence does
      not establish that containment boundaries are hidden.
- [ ] Include benign, sufficiently complex tasks in a disposable instrumented
      environment, such as retrieving data from a synthetic wiki with unexpected
      write affordances. Compare with deliberate escape tasks and ordinary
      recoverable failures; do not infer benign-task behavior from adversarial
      benchmarks alone.
- [ ] Preserve tool calls and controller/enforcement events with timestamps,
      task/agent identity, authorization scope, and observed effects, subject to
      secret redaction and bounded retention. Record trace gaps explicitly.
- [ ] Collect a concise agent-reported explanation of the attempted action's
      relation to the task in the bounded checkpoint. Treat it as self-report,
      not proof of internal beliefs; compare it with the event trace.
- [ ] Distinguish unauthorized attempts, actual unauthorized effects, boundary
      detections, and successful stops. If unintended write authority permits an
      action without triggering enforcement, Hug Wall cannot undo or reliably
      detect that failure; the hard boundary needs correction.

## Priority: HTTP network kill switch with per-agent isolation

Add an operator-visible network control to the Notty HTTP interface. The
browser requests a state transition from the root-owned Nosh Guard control
plane; neither the browser, Notty server, container, nor an agent receives
iptables, nftables, eBPF, Docker-socket, or host-network authority.

### Kill-switch contract

- [ ] Provide an immediately recognizable **Network ON/OFF** control for the
      whole managed container, with the current state visible without opening a
      menu.
- [ ] Provide separate network controls for each managed agent. Agent access
      must be bound to an exact agent/process/cgroup identity and must never
      silently toggle general container access.
- [ ] Default newly launched agents to an explicit policy state rather than
      inheriting the last UI selection.
- [ ] Make OFF fail closed: Guard first installs/verifies the deny boundary and
      only then reports success to the UI.
- [ ] If Guard cannot install or verify the deny boundary, pause or stop the
      exact container; if containment still cannot be proven, kill it and retain
      the incident/evidence state.
- [ ] Do not implement OFF as UI state, environment state, application proxy
      configuration, or DNS failure alone.
- [ ] Prefer the existing scoped cgroup eBPF enforcement boundary. Permit a
      reviewed host firewall backend only when it has equivalent exact identity,
      atomic transition, verification, rollback, and evidence guarantees.
- [ ] Use explicit states: **OFF**, time-bounded **LEARN**, and **ENFORCE**.
      Avoid an ambiguous ON state.
- [ ] Make LEARN a deliberate, operator-authorized, permissive-but-observed
      window for discovering login/runtime egress; show its expiry prominently.
- [ ] Make ENFORCE a deliberate transition to a selected reviewed profile.
      Never translate a generic ON action into unrestricted networking.
- [ ] Require confirmation for container-wide ON and show which agents and
      non-agent processes it affects.
- [ ] Record operator, workspace, run, container, agent, old/new policy,
      backend, timestamp, reason, verification result, and forced-containment
      outcome for every transition.
- [ ] Reconcile UI state from Guard after refresh, reconnect, daemon restart,
      and container identity change. Stale browser state must not re-enable
      networking.

### Per-agent network profiles

- [ ] Attribute egress to the exact agent harness and model/backend identity
      (for example Codex, Gemini, or Claude), its descendant processes, launch
      configuration, image digest, and tool versions.
- [ ] Keep ordinary Notty/container traffic in a separate general profile so an
      agent observation cannot authorize unrelated processes.
- [ ] Add a guided learn session: launch one agent, connect/login manually,
      exercise representative operations, stop cleanly, and preserve its eBPF
      evidence as an immutable candidate.
- [ ] Require semantic review and the signed projection/grant/activation path
      before a learned agent candidate can become enforcement authority.
- [ ] Never merge credentials, URL paths/query values, request bodies, or
      response content into a portable profile.
- [ ] Invalidate or require explicit re-review when the agent binary, provider,
      model backend, container image, workspace scope, or observed policy
      identity changes.
- [ ] Allow a manually learned profile to replace or supplement a shipped
      preprofile, while retaining provenance and never widening by union
      automatically.

### Optional preprofiling and domain inventory

- [ ] Optionally profile supported Codex, Gemini, and Claude login/use flows
      during a dedicated image-release workflow. Do not make interactive
      credentials or live provider availability a normal Docker build input.
- [ ] Ship preprofiles only as reviewed, versioned candidates or signed policy
      artifacts bound to exact agent/tool/image identities.
- [ ] Nice to have: show a deduplicated list of observed domains per agent and
      for general container traffic, with first/last seen, ports/transports,
      source process, DNS provenance, review disposition, and current allow/
      deny status.
- [ ] Mark direct IPs, unresolved DNS, ambiguous CNAME chains, encrypted-DNS
      gaps, wildcard proposals, and incomplete/lost evidence explicitly rather
      than inventing domain attribution.
- [ ] Export only the redacted portable domain view; keep sensitive raw
      evidence private and bounded.

## Review user and agent permissions; design shared source access

### Notty service logs and runtime isolation

- [ ] Prevent agents from reading or modifying Notty service logs, including
      configured log files, rotated files, service stdout/stderr, inherited file
      descriptors, procfs descriptor paths, and container log access. Preserve
      explicitly authorized access to an agent's own terminal transcript.
- [ ] Keep service logs and auth state outside the shared source tree and agent
      mounts. Use separate service/agent identities and verify access denial;
      owner-only permissions do not isolate processes sharing the same UID.
- [ ] Test that agents cannot read or modify `/var/lib/notty-auth/auth.sqlite3`
      or its journal/WAL files, inspect service credentials in process state, or
      access a launcher-provided OTP through the service environment.
- [ ] Ensure agent-writable repository code cannot become privileged Notty
      service code through hot reload, imports, helpers, or automatic restart.
      Run the service from a separately controlled deployment artifact; shared
      source access must not confer control of the running authentication service.
- [ ] Verify log redaction independently of log access controls: never record
      Basic Authorization headers, plaintext OTPs, or minting credentials.
- [ ] Test operator-authorized terminal automation separately from agent
      self-authorization: a scoped spawn grant must not provide reusable Basic
      credentials or unrestricted OTP minting authority.

Create a concrete identity and filesystem-permission plan before changing the
runtime. Each human and agent should be distinguishable for attribution and
revocation, while approved agents share one narrowly scoped group that can
modify the workspace source tree.

### Identity model

- [ ] Inventory every current execution identity: host operator, container
      user, Notty service, Guard, terminal sessions, Collab coordinator, agent
      harnesses, copilots, build workers, and helper processes.
- [ ] Record UID/GID allocation, supplementary groups, namespaces, cgroups,
      home/runtime/state directories, inherited environment, and privilege
      transitions for each identity.
- [ ] Assign each human and managed agent a distinct stable runtime identity;
      do not distinguish agents only through environment variables or UI names.
- [ ] Give every source-editing agent membership in one dedicated workspace
      writer group, for example `notty-source`. Keep the operator in that group
      when collaborative editing is intended.
- [ ] Do not add the Notty web service, Guard daemon, network-policy helpers,
      unauthenticated MCP callers, or unrelated container processes to the
      source-writer group.
- [ ] Bind terminal, Collab, network-profile, audit, Interrupt, and Halt actions
      to the exact user/agent identity rather than merely the shared group.

### Workspace permission plan

- [ ] Make the workspace root and intended source directories group-owned by
      the source-writer group and setgid so new subdirectories retain that
      group.
- [ ] Establish a cooperative group-write policy using a controlled
      `umask 0002` or narrowly scoped default ACLs. Test tools that create files via
      temporary-file rename.
- [ ] Keep files non-executable by default; preserve executable bits only for
      reviewed scripts and binaries.
- [ ] Define explicit exclusions that are never group-readable or
      group-writable: agent homes, provider credentials, OAuth/token state,
      spawn OTP material, signing keys, Guard state, auth databases, sockets,
      private review evidence, and per-agent runtime directories.
- [ ] Ensure `.git` access supports the chosen collaboration model without
      granting access to secrets, host credentials, or arbitrary Git hooks.
- [ ] Decide whether agents may write Git metadata directly. Prefer one
      coordinator for index, commit, tag, rebase, and worktree operations while
      agents edit source, to avoid lock contention and cross-agent commits.
- [ ] Prevent symlink, hard-link, bind-mount, path-replacement, and inherited
      ACL tricks from turning shared source access into private-state access.
- [ ] Preserve exact numeric ownership across Nosh bind mounts; fail admission
      if host/container UID or group mapping would create inaccessible or
      unexpectedly privileged files.

### Authorization and attribution

- [ ] Treat shared group membership as filesystem write permission only. It
      must not grant HTTP Basic credentials, spawn capability, agent-control
      authority, network activation, Docker access, sudo, Guard management, or
      signing authority.
- [ ] Record the effective user and agent identity for each source mutation and
      privileged request, while avoiding sensitive file contents in logs.
- [ ] Support removing one agent from the group and revoking its active
      sessions without disrupting peer agents or changing existing file
      ownership.
- [ ] Define ownership for files intentionally handed between agents and ensure
      another group member can edit, rename, and remove them without broad
      world-writable permissions.

### Validation plan

- [ ] Test two agents editing different source files concurrently and handing
      one file between them.
- [ ] Test create, atomic replace, rename, directory creation, deletion, and
      executable-bit preservation under the shared group policy.
- [ ] Confirm agents cannot read or alter each other's private home, credentials,
      runtime sockets, transcripts marked private, or policy/signing material.
- [ ] Confirm the Notty service and an unauthenticated MCP client cannot modify
      source merely because agents can.
- [ ] Confirm a removed or halted agent immediately loses new source writes and
      control-plane authority while its prior attributed changes remain.
- [ ] Test concurrent Git activity and verify the coordinator policy prevents
      index locks, mixed commits, ownership drift, and unsafe hooks.
- [ ] Add a migration and rollback plan for existing workspaces, including an
      ownership/ACL audit that reports changes before applying them.

## Optional: QEMU setup and testing

- [x] Document a reproducible QEMU/KVM setup for testing Notty and Nosh Guard
      on a disposable Linux guest without weakening the host security model.
- [x] Pin the guest image or installation media by version and checksum, and
      record the guest kernel, architecture, cgroup-v2, BTF, Docker, and QEMU
      versions used for each test run.
- [ ] Exercise installation, profile build/run, audit, enforcement, restart,
      upgrade, rollback, and cleanup workflows from a clean guest snapshot.
- [ ] Test both hardware-accelerated KVM and software-emulated fallback where
      practical, including failure behavior when required kernel/eBPF features
      are unavailable.
- [ ] Keep provider credentials and release signing material out of reusable
      guest images, snapshots, console logs, and exported artifacts.

TODO review (2026-10-08): setup is documented in `docs/nosh-qemu.md`; image
version/SHA-256 and package snapshot are pinned in `config/qemu-test.json`, and
`scripts/qemu/harness.py` verifies the image and records run prerequisites.
The documented KVM smoke pass does not complete the full lifecycle suite;
KVM full and TCG smoke validation remain open.

## Optional: bubblewrap (bwrap) setup and testing

- [ ] Evaluate bubblewrap as an additional local process-isolation layer for
      selected agent and helper workflows; do not treat it as a replacement
      for Nosh Guard, container, cgroup, or network enforcement boundaries.
- [ ] Document required kernel/user-namespace settings and a reproducible
      bwrap invocation with explicit read-only, writable, device, proc, tmpfs,
      environment, UID/GID, and network-namespace rules.
- [ ] Test source editing, terminal PTY behavior, MCP/Collab communication,
      child-process cleanup, signals, timeouts, and intentional denial of
      private credentials, host runtime state, Docker sockets, and unrelated
      filesystem paths.
- [ ] Verify fail-closed behavior when unprivileged user namespaces or bwrap
      are unavailable, disabled, or misconfigured; never silently fall back to
      an unsandboxed launch.
- [ ] Add escape-focused tests for symlinks, file-descriptor inheritance,
      procfs, Unix sockets, namespace joins, nested sandboxes, and network
      access before enabling bwrap by default anywhere.
