# Nosh v0.9b — Build Profiler Privilege / Authorization Seam

**Target:** `xpatchdev/notty`  
**Branch reviewed:** `v0.9b`  
**Purpose:** implementation handoff for Codex  
**Scope:** `nosh build profile` and its privileged collector lifecycle

---

## TL;DR

The current v0.9b source already has the important privilege split.

The build itself is unprivileged. Docker/Buildx runs as the invoking Docker-authorized user. Root authority is used only for the hidden `build-session` lifecycle (`begin`, `finish`, `abort`, `exported`) which talks to the root-owned `nosh-guardd` daemon. The daemon validates the exact BuildKit container, derives the PID/cgroup itself, attaches the configured collectors, owns authoritative evidence, and fails closed if identity or cleanup invariants break.

**Do not redesign the profiler around arbitrary PIDs or cgroups.**  
**Do not make the daemon socket group-accessible.**  
**Do not run the whole profiler under sudo.**

The useful next seam is:

> Replace repeated stateless `sudo nosh-guard build-session <action>` calls with a single, short-lived, narrowly scoped privileged bridge/lease for one profile invocation.

That gives one authorization event, keeps the root daemon private, and gives the privileged side enough continuity to enforce an exact session state machine.

If the only immediate problem is repeated password prompts / unattended CI, v0.9b already has an installer-generated exact-command `NOPASSWD` sudoers rule. That can be used without an architectural change.

---

# 1. Existing v0.9b flow

Current source path:

```text
nosh build profile .
        |
        v
nosh.sh
        |
        | delegates "build profile ..."
        v
nosh-guard build profile
        |
        v
lib/guardd/build-orchestrator.js
        |
        | creates / validates dedicated Buildx docker-container builder
        | Buildx runs as invoking user
        |
        +--> sudo -- <root-owned-nos h-guard> build-session begin
        |        |
        |        v
        |   scripts/nosh-guard.mjs
        |        |
        |        | fixed /run/nosh-guardd.sock
        |        v
        |   nosh-guardd
        |        |
        |        v
        |   BuildSessionService.begin()
        |        - verifies exact container ID
        |        - verifies Buildx node/name/image
        |        - derives live PID from Docker inspect
        |        - derives cgroup-v2 target from /proc/<pid>/cgroup
        |        - verifies client PID/starttime/uid
        |        - health-checks collectors
        |        - attaches sensors
        |        - returns sensors-ready
        |
        +--> docker buildx build ...       [unprivileged]
        |
        +--> sudo -- <helper> build-session finish
        |        - revalidates builder identity
        |        - checks final collector health
        |        - detaches collectors
        |        - verifies final records / loss counters
        |        - seals authoritative evidence
        |
        +--> caller adopts private evidence copy
        |
        +--> sudo -- <helper> build-session exported
                 - acknowledges durable portable bundle
```

On build failure, `abort` replaces `finish`.

Relevant source:

- `nosh.sh`
  - `delegate_build_to_nosh_guard()`
  - `run_build_profile_command()`
- `lib/guardd/build-orchestrator.js`
  - `trustedPrivilegedHelper()`
  - `defaultPrivilegedInvoker()`
  - `runPass()`
- `scripts/nosh-guard.mjs`
  - `commandBuildSession()`
  - `assertTrustedBuildManagementSocket()`
  - `assertOwnedBuildSession()`
  - `stageBuildEvidenceForUser()`
- `lib/guardd/build-session-service.js`
  - `BuildSessionService.inspectBuilder()`
  - `BuildSessionService.begin()`
  - `BuildSessionService.finish()`
- `lib/guardd/server.js`
- `lib/guardd/client.js`

---

# 2. What is already good and should stay

## 2.1 Build process stays unprivileged

`build-orchestrator.js` runs Docker and Buildx in the invoking process.

The privileged helper is called only for the sensor lifecycle.

This is important because it preserves the invoking user's:

- Docker credentials
- credential helpers
- SSH forwarding
- BuildKit secret sessions
- local output ownership
- build cache ownership
- normal file permissions

Do not change this to:

```bash
sudo nosh build profile ...
```

The documentation and source intentionally reject the idea of running the complete profile as root.

---

## 2.2 The root helper path is strongly validated

`trustedPrivilegedHelper()` already requires the selected helper to be:

- absolute
- realpath-resolvable
- a regular file
- root-owned
- singly linked
- executable
- not group/world writable

It also walks parent directories and requires them to be root-owned and non-group/world-writable.

Keep this logic.

---

## 2.3 The privileged command surface is already narrow

The hidden helper supports exactly:

```text
build-session begin
build-session finish
build-session abort
build-session exported
```

`BUILD_SESSION_FLAGS` is empty.

So the privileged build helper cannot currently accept:

- `--socket`
- `--state-dir`
- arbitrary executable paths
- arbitrary collector paths
- arbitrary PIDs
- arbitrary cgroups

Keep that property.

---

## 2.4 The management socket is fixed and private

The privileged build helper uses:

```text
/run/nosh-guardd.sock
```

and authoritative build state lives under:

```text
/var/lib/nosh-guard
```

The socket is required to be:

```text
root-owned
mode 0600
Unix socket
inside a protected root-owned parent
```

Keep it `0600`.

`lib/guardd/server.js` explicitly notes that Node's HTTP-over-Unix implementation does not provide a convenient per-request `SO_PEERCRED` authorization seam, so the lifecycle socket is deliberately root-only.

Do **not** solve profiler authorization by simply changing the socket to `0660`.

---

## 2.5 The daemon does not trust caller-selected PIDs

This is the most important part of the current design.

`BuildSessionService.inspectBuilder()` starts from an **exact Docker container ID** and expected Buildx identity.

The daemon verifies:

- exact 64-character container ID
- exact expected Buildx container name
- running container
- exact BuildKit image identity
- expected privileged BuildKit worker shape

Then it derives:

```text
Docker inspected PID
      ↓
/proc/<pid>/cgroup
      ↓
canonical cgroup-v2 path
      ↓
cgroup inode / identity
```

The user does not get a general:

```text
profile PID
profile cgroup
attach BPF to path
```

interface.

Keep this invariant.

---

## 2.6 Client process identity is bound

`begin()` receives the unprivileged profiler's:

- PID
- `/proc/<pid>/stat` start time
- UID
- GID

The root daemon verifies that:

- the PID is still live
- the start time matches
- the process owner matches the claimed UID

This prevents simple PID reuse / stale-process confusion.

Keep this and extend it into the authorization lease below.

---

## 2.7 Evidence fails closed

At finish, the daemon already checks:

- builder identity still matches
- cgroup identity still matches
- build timestamps form a valid window
- required collectors remain healthy
- required collectors detach correctly
- cleanup-critical adapters report successful cleanup
- final records exist
- loss/error counters are zero where required
- final collector timestamp covers the build end
- required cgroup snapshots exist

If those conditions fail, the evidence is incomplete / failed / quarantined.

Do not weaken these checks while changing authorization.

---

# 3. Current authorization behavior

The default privileged call is effectively:

```text
sudo -- /usr/local/bin/nosh-guard build-session begin
sudo -- /usr/local/bin/nosh-guard build-session finish
sudo -- /usr/local/bin/nosh-guard build-session abort
sudo -- /usr/local/bin/nosh-guard build-session exported
```

JSON is passed on stdin.

The helper derives the invoking identity via sudo and checks session ownership before finalization/export.

This is already a reasonable privilege boundary.

The awkward part is that each action is a separate sudo invocation.

Depending on sudo timestamp policy this can mean:

- repeated auth prompts
- policy coupling to sudo timestamp caching
- stateless authorization across a multi-pass profile
- less obvious audit semantics for "one profile attempt"

---

# 4. Existing immediate solution: narrow sudoers rule

The v0.9b installer already knows how to install a rule equivalent to:

```sudoers
Cmnd_Alias NOSH_BUILD_SESSION = \
    /usr/local/bin/nosh-guard build-session begin, \
    /usr/local/bin/nosh-guard build-session finish, \
    /usr/local/bin/nosh-guard build-session abort, \
    /usr/local/bin/nosh-guard build-session exported

%nosh-profiler ALL=(root) NOPASSWD: NOSH_BUILD_SESSION
```

The real renderer substitutes the configured install prefix.

The installer already validates:

- the group exists
- `visudo` is available
- `/etc/sudoers.d` is a safe root-owned directory
- target is a regular non-symlink
- owner/mode/link count are correct
- existing policy has not drifted
- replacement requires explicit `--replace-sudoers`

This is a good current option for:

- CI
- a single-user workstation
- a dedicated profiler group
- environments where Docker authority is already explicitly granted

It does **not** authorize:

- `nosh-guard run`
- `nosh-guard net ...`
- profile approval
- arbitrary daemon lifecycle commands

If the immediate goal is simply "profile without typing sudo repeatedly", this mechanism may be sufficient.

---

# 5. Recommended next seam: one authorization lease

## Goal

Turn:

```text
sudo begin
sudo finish
sudo exported
```

into:

```text
sudo build-session bridge
       |
       +-- authorize caller once
       +-- accept only one profile's legal lifecycle
       +-- close / abort automatically
```

The daemon remains root-owned and persistent.

The bridge is root, but intentionally tiny and short-lived.

---

# 6. Proposed command

Add hidden command:

```bash
sudo -- /usr/local/bin/nosh-guard build-session bridge
```

The bridge:

- is not a shell
- never executes caller-selected commands
- does not run Docker
- does not load adapters itself
- does not accept a socket path
- does not accept a state root
- does not accept a PID or cgroup target
- connects only to the fixed root daemon socket
- speaks a bounded protocol over stdin/stdout
- exits when the profile completes
- aborts active sessions on EOF or caller death

The bridge becomes the privilege/authorization seam.

---

# 7. Add an unprivileged transport abstraction

In `lib/guardd/build-orchestrator.js`, replace direct stateless calls with an interface.

Suggested shape:

```js
class BuildSessionTransport {
  async open(intent) {}
  async begin(pass, builder) {}
  async finish(runId, result) {}
  async abort(runId, reason) {}
  async exported(runId, portableBundleHash) {}
  async close() {}
}
```

Recommended concrete implementations:

```text
LegacySudoBuildSessionTransport
    current v0.9b behavior, one sudo invocation per action

BridgeBuildSessionTransport
    one sudo process for the complete profile invocation
```

Use the legacy transport during migration and tests.

This is useful because a later native peer-credential broker can implement the same interface without changing `runPass()` or the profile store.

---

# 8. Profile intent

When the bridge starts, the unprivileged side sends a sanitized intent.

Example:

```json
{
  "schemaVersion": 1,
  "operation": "open",
  "intent": {
    "profileId": "generated-profile-id",
    "mode": "build-profile",
    "cacheMode": "compare",
    "depth": "balanced",
    "platform": "linux/amd64",
    "passes": ["cold", "warm"],
    "context": {
      "path": "/home/user/project",
      "dev": "123",
      "ino": "456"
    },
    "dockerfile": {
      "path": "/home/user/project/Dockerfile",
      "sha256": "sha256:...",
      "dev": "123",
      "ino": "789",
      "size": "2048"
    },
    "builder": {
      "name": "nosh-build-...",
      "node": "nosh-build-...0",
      "image": "moby/buildkit:v0.30.0@sha256:..."
    }
  },
  "client": {
    "pid": 12345,
    "startTime": "987654321"
  }
}
```

Do not put secrets in this document.

Acceptable audit metadata:

- build arg **names**
- secret **IDs**
- SSH forwarding presence

Not acceptable:

- build arg values
- secret contents
- private key paths unless already redacted
- credential helper output

The current profiler already has sanitized forms; reuse them.

---

# 9. Bridge-issued lease

On successful authorization:

```json
{
  "schemaVersion": 1,
  "operation": "opened",
  "leaseId": "opaque-random-id",
  "intentHash": "sha256:...",
  "principal": {
    "uid": 1000,
    "gid": 1000,
    "username": "kross"
  },
  "allowedPasses": ["cold", "warm"],
  "expiresAt": "2026-08-15T18:00:00Z"
}
```

Authority for the principal comes from privileged context:

- `SUDO_UID`
- `SUDO_GID`
- passwd lookup

Caller-provided UID/GID can be checked for consistency but must not establish authority.

---

# 10. Lifecycle protocol

Use newline-delimited JSON or another simple framed protocol.

Every request should contain:

```text
schemaVersion
sequence
leaseId
operation
```

Allowed operations after open:

```text
begin
finish
abort
exported
close
```

No other operations.

Example:

```json
{
  "schemaVersion": 1,
  "sequence": 2,
  "leaseId": "...",
  "operation": "begin",
  "pass": "cold",
  "builderContainerId": "64-hex...",
  "client": {
    "pid": 12345,
    "startTime": "987654321"
  }
}
```

The bridge still does **not** accept a PID/cgroup to profile.

The `builderContainerId` identifies the BuildKit worker. The daemon continues to derive the actual builder PID and cgroup itself.

---

# 11. Pass budget / state machine

The lease should know the declared pass plan.

```text
cache-mode compare -> cold, warm
cache-mode cold    -> cold
cache-mode warm    -> warm
build-net-learn    -> single clean pass
```

State machine:

```text
NEW
 |
 | open
 v
AUTHORIZED
 |
 | begin expected pass
 v
SENSORS_READY
 |
 | unprivileged Buildx runs
 v
BUILDING
 |
 +---- finish ----> TERMINAL
 |
 +---- abort -----> TERMINAL
                      |
                      | portable evidence adopted
                      v
                   EXPORTED
                      |
                      | next declared pass OR close
                      v
                   CLOSED
```

Reject:

```text
finish before begin
second begin for an active pass
warm before cold in compare mode
third pass in compare mode
unexpected pass name
different profile ID
different lease ID
different principal
different client PID identity
exported before terminal state
different portable bundle hash on repeated acknowledgement
operation after close
```

---

# 12. Automatic cleanup behavior

The bridge must abort any active session on:

- stdin EOF
- broken stdout
- bridge timeout
- malformed request
- oversized request
- invalid sequence
- caller PID death
- caller PID start-time change
- SIGINT
- SIGTERM
- daemon error after session begin

If abort cannot clean up critical collectors, preserve the daemon's existing quarantine behavior.

The bridge should never "pretend cleanup succeeded" merely to make the client exit cleanly.

---

# 13. Bind daemon runs to lease metadata

Extend `BuildSessionService.begin()` / stored run state with optional authorization metadata:

```text
leaseId
intentHash
principalUid
principalGid
profileId
authorizedPass
leaseExpiresAt
```

The daemon already persists:

```text
workspace identity
builder identity
client identity
adapter state
```

Lease metadata makes the authorization relationship explicit in the root-owned run record.

Suggested checks:

```text
request principal == lease principal
request pass == allowed next pass
request workspace dev/ino == intent workspace
builder name/node/image == intent builder
lease not expired
client PID/starttime still live
```

The daemon should continue to derive:

```text
builder PID
builder cgroup path
builder cgroup ID
```

Never copy those from the authorization request.

---

# 14. Strong rule: authorize workload identity, not arbitrary target identity

The privileged side should think in these terms:

```text
"Permit one Nosh build profile of this BuildKit worker"
```

not:

```text
"Permit tracing PID 1234"
```

Target resolution must stay:

```text
exact BuildKit container ID
        ↓
root Docker inspect
        ↓
expected Buildx name/node/image
        ↓
live init PID
        ↓
procfs cgroup membership
        ↓
canonical cgroup-v2 directory
        ↓
collector attachment
```

No API should expose:

```text
--pid
--cgroup
--namespace
--bpf-object
--collector-path
--daemon-socket
--state-root
```

---

# 15. Profiling authority must not become blocking authority

Keep build profiling separate from runtime policy approval/enforcement.

Profiling authorization permits:

```text
build-session begin
build-session finish
build-session abort
build-session exported
```

It does not permit:

```text
nosh-guard run
nosh-guard net learn
nosh-guard net audit
nosh-guard net approve
nosh-guard net enforce
nosh-guard profile approve
arbitrary Tetragon policy loading
adapter configuration changes
```

Current build candidates are observational and should stay that way.

A build candidate should continue to be non-promotable in v1:

```json
{
  "promotion": {
    "eligible": false,
    "reasons": [
      "build profile approval and enforcement are not implemented"
    ]
  }
}
```

If build-time blocking is ever added, it needs a **different reviewed artifact** and a **different authorization path**.

Never silently transform learned behavior into an enforced rule.

---

# 16. Do not loosen the daemon socket

Do not change:

```text
/run/nosh-guardd.sock
0600 root:root
```

to a broadly accessible group socket with the current server.

The daemon API contains more lifecycle surface than the build profiler needs, and the current HTTP-over-Unix server is intentionally root-only.

Preferred now:

```text
unprivileged orchestrator
       |
       | sudo once
       v
narrow build-session bridge
       |
       | root-only socket
       v
nosh-guardd
```

Possible future option:

```text
unprivileged orchestrator
       |
       | credential-aware Unix RPC
       v
small native broker using SO_PEERCRED
       |
       | root-only socket
       v
nosh-guardd
```

The `BuildSessionTransport` abstraction makes that future change local.

---

# 17. Suggested source modifications

## `lib/guardd/build-orchestrator.js`

### Add

```text
BuildSessionTransport interface
LegacySudoBuildSessionTransport
BridgeBuildSessionTransport
```

### Change

`runPass()` should receive the transport.

Today it effectively does:

```js
const privileged = dependencies.privilegedInvoker || defaultPrivilegedInvoker;
const session = privileged('begin', beginPayload, dependencies);
...
finish = privileged('finish', ...);
...
privileged('abort', ...);
```

Change toward:

```js
const session = await transport.begin(beginPayload);
...
finish = await transport.finish(session.runId, result);
...
await transport.abort(session.runId, error.message);
```

Open the transport once in `executeBuildProfile()` and close it in a `finally`.

---

## `scripts/nosh-guard.mjs`

Add hidden:

```text
build-session bridge
```

Requirements:

- root-only
- no CLI flags
- fixed socket
- fixed state root
- strict request schema
- reject unknown fields
- bounded line/message count
- no arbitrary command execution
- no Docker invocation
- no adapter invocation
- no filesystem destination from caller
- no general Guard dispatch
- derive principal from sudo context
- verify caller PID/starttime
- enforce pass state machine
- cleanup on exit

Keep the old actions for compatibility during rollout.

---

## `lib/guardd/build-session-service.js`

Add optional lease metadata to the persisted run.

Do not rewrite `inspectBuilder()`.

The current container/PID/cgroup derivation is the right side of the trust boundary.

Do not weaken:

- exact container ID validation
- Buildx container name validation
- image validation
- client PID/starttime/UID checks
- workspace dev/inode checks
- cgroup checks
- active builder lease exclusion
- final health checks
- final-record coverage
- loss counter checks
- cleanup quarantine

---

## `lib/guardd/server.js`

No need to expose an unprivileged socket.

Keep:

```text
socket mode = 0600
root-owned lifecycle control
```

If lease checks live in `BuildSessionService`, the bridge can continue to use the existing `GuardClient` routes.

---

## Installer

During migration, either retain the current sudoers alias or add a bridge alias:

```sudoers
Cmnd_Alias NOSH_BUILD_SESSION_BRIDGE = \
    /usr/local/bin/nosh-guard build-session bridge

%nosh-profiler ALL=(root) NOPASSWD: NOSH_BUILD_SESSION_BRIDGE
```

After bridge rollout is stable, the four action-specific NOPASSWD commands can be removed.

Interactive installs do not need NOPASSWD; normal sudo auth can start the bridge once.

---

# 18. Security boundary / threat model

## This design protects against

- non-authorized users invoking the profiling collector lifecycle
- accidental tracing of unrelated processes
- arbitrary PID targeting
- arbitrary cgroup targeting
- session finalization by another UID
- stale PID reuse
- helper path substitution
- management socket substitution
- state-root substitution
- builder identity drift
- cgroup identity drift
- concurrent Nosh profiling of the same worker
- incomplete collector cleanup being treated as success
- profiling authorization being reused as runtime enforcement authorization

## This design does not protect against a hostile rootful-Docker administrator

A conventional member of the rootful Docker group is already effectively host-root-equivalent.

Such a user can typically:

- run privileged containers
- mount host paths
- manipulate BuildKit workers
- access devices / namespaces through Docker
- alter the workload being observed

Therefore, do not claim the profiler creates a hostile-user boundary against a user who already has unrestricted Docker daemon authority.

For a materially stronger model, direct Docker access must also move behind an authorization service. That is a much larger architecture change and affects credential helpers, SSH sessions, secrets, cache, and caller-owned outputs.

---

# 19. Tests to add

## Bridge protocol

- open succeeds for authorized principal
- open rejects mismatched claimed UID/GID
- unknown fields rejected
- oversized message rejected
- invalid sequence rejected
- expired lease rejected
- second open rejected
- operation after close rejected

## Workload binding

- arbitrary PID cannot be supplied
- arbitrary cgroup cannot be supplied
- wrong builder container ID rejected
- wrong Buildx node rejected
- wrong builder image rejected
- workspace dev/inode drift rejected
- client PID starttime drift rejected
- client owner drift rejected
- undeclared pass rejected
- repeated pass rejected

## Cleanup

- client EOF aborts active run
- caller death aborts active run
- SIGINT aborts active run
- SIGTERM aborts active run
- daemon failure after begin triggers abort attempt
- detach failure leaves run quarantined
- exported cannot precede finish/abort
- different portable hash cannot replace prior acknowledgement

## Privilege separation

Static/behavior tests should confirm bridge code does not contain / call:

```text
spawn shell
docker buildx
AdapterController
nosh-guard net
nosh-guard run
profile approve
user-selected socket
user-selected state root
user-selected collector path
user-selected PID/cgroup target
```

## Preserve current tests

Existing v0.9b tests already cover useful invariants including:

- exact builder admission
- client PID-to-UID binding
- builder lease conflict
- cgroup drift
- watchdog cleanup
- fixed build-session socket/state roots
- invoking-user ownership
- narrow privileged invoker command shape
- safe evidence staging

Extend these rather than replacing them.

---

# 20. Acceptance criteria

- [ ] `nosh build profile` never runs the Docker/Buildx build as root.
- [ ] A full profile needs at most one interactive sudo authentication.
- [ ] Root never receives build-secret values.
- [ ] Privileged API accepts no arbitrary PID/cgroup target.
- [ ] Daemon derives the target cgroup from an exact validated BuildKit container.
- [ ] Lease is bound to caller UID/GID and client PID/starttime.
- [ ] Lease is bound to one profile intent and declared pass plan.
- [ ] Compare mode cannot grow additional undeclared passes.
- [ ] Caller death / bridge EOF cleans up active sensor sessions.
- [ ] Cleanup failure cannot yield complete evidence.
- [ ] Profiling permission cannot invoke runtime audit/approve/enforce.
- [ ] Main daemon socket remains root-owned mode `0600`.
- [ ] Existing private / portable profile outputs remain compatible.
- [ ] `nosh build status` stays unprivileged.
- [ ] Legacy per-action sudo transport can remain temporarily for rollback/tests.

---

# 21. Implementation order

Recommended incremental order:

```text
1. Add BuildSessionTransport abstraction.
2. Wrap existing per-action sudo behavior as Legacy transport.
3. Prove zero behavior change with existing tests.
4. Add root-only "build-session bridge".
5. Implement bridge transport.
6. Add lease + pass state machine.
7. Add caller-death/EOF cleanup.
8. Add optional bridge sudoers alias.
9. Make bridge preferred.
10. Retain legacy transport for one release.
11. Remove legacy NOPASSWD lifecycle actions later if desired.
```

This avoids turning the privilege refactor into another Proof of Scopecreep release.

---

# 22. Codex task statement

Implement a privilege/authorization seam for `nosh build profile` on top of the existing v0.9b architecture.

Do **not** redesign collector ownership.

The root daemon already owns collector attachment, authoritative evidence, and exact builder/cgroup validation. Preserve that.

Refactor the unprivileged build profiler to use a `BuildSessionTransport` abstraction, retain the current per-action sudo invoker as a compatibility transport, then add a single-sudo `nosh-guard build-session bridge` transport.

The bridge must:

1. authorize the invoking principal once;
2. bind authorization to one sanitized profile intent;
3. bind sessions to the caller's live PID/starttime;
4. permit only the declared build pass sequence;
5. forward only `begin`, `finish`, `abort`, and `exported` semantics to the fixed root daemon;
6. accept no arbitrary PID, cgroup, socket, state root, executable, or collector target;
7. abort active sessions on EOF, caller death, timeout, signal, or protocol failure;
8. keep `/run/nosh-guardd.sock` root-only mode `0600`;
9. preserve all existing identity/evidence/cleanup fail-closed checks;
10. keep build profiling observational and completely separate from runtime policy approval/enforcement.

Start by reading:

```text
lib/guardd/build-orchestrator.js
scripts/nosh-guard.mjs
lib/guardd/build-session-service.js
lib/guardd/server.js
lib/guardd/client.js
scripts/install-nosh-guard-host-bundle.sh
scripts/render-nosh-guard-install.mjs
docs/nosh-build-profiling.md
tests/build-session-service.test.cjs
tests/build-guard-api-cli.test.cjs
```

Before modifying behavior, characterize the current tests and add transport-level tests around the existing semantics.
