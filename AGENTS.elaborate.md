# Elaborate Agent Guidelines

This document is a proposed supplement to `AGENTS.md`. It contains generic
agent-planning and multi-agent coordination guidance that is not currently in
the repository guidelines. Project-specific structure, commands, style, and
testing guidance remain authoritative in `AGENTS.md`.

## Planning and Implementation Principles

- Follow the KISS principle: prefer the smallest solution that fully addresses
  the requested behavior.
- Favor clear, maintainable implementations over unnecessary abstraction.
- Reuse existing code and patterns where practical. New duplication should
  have a concrete justification.
- Preserve unrelated changes and existing uncommitted work.
- Use parallel agents only when tasks are independent and coordination costs do
  not outweigh the benefit.
- If review finds no concrete improvement to make, report that directly rather
  than proposing speculative changes.

## Concurrent Agent Safety

When multiple agents may modify the workspace, coordinate before writing.
Intent records and messages are advisory; a per-file lock is authoritative.

### Core Rules

- A file may have only one modifying agent at a time.
- An agent may hold only one file lock at a time unless the task explicitly
  requires an atomic multi-file change and the agents have coordinated it.
- Before modifying a file, inspect active agent intent and existing locks for
  overlap.
- Verify lock ownership immediately before writing and again before releasing
  the lock.
- Never remove a lock owned by another active agent.
- If another agent targets the same file, stop writing and coordinate instead
  of racing or repeatedly retrying forever.

### Suggested Coordination Layout

Repositories using concurrent agents may maintain:

```text
agents/
  locks/    authoritative per-file leases
  active/   current agent intent and status
  intent/   historical intent declarations
  msgs/     inter-agent coordination messages
  history/  append-only completed-task records
```

The lock path should mirror the target path. For example, the lock for
`lib/session.js` is `agents/locks/lib/session.js`.

## File-Lock Lifecycle

### Acquire

1. Choose a stable, unique agent ID.
2. Check `agents/active/` and `agents/locks/` for conflicting work.
3. Create the target lock atomically so an existing lock cannot be overwritten.
4. Wait briefly for the filesystem state to settle when required by the shared
   environment.
5. Read the lock back and confirm that it contains the current agent ID.

An example atomic claim in a POSIX shell is:

```sh
mkdir -p "agents/locks/$(dirname "$FILE_PATH")"
(set -o noclobber; printf '%s\n' "$AGENT_ID" > "agents/locks/$FILE_PATH") 2>/dev/null
```

Failure means another agent owns the lock. Inspect its intent and coordinate or
retry with bounded randomized backoff.

### Write

Immediately before changing the target file:

1. Read the lock.
2. Confirm that its owner is still the current agent.
3. Abort the write if ownership cannot be confirmed.

After writing, confirm ownership once more. If ownership unexpectedly changed,
do not remove the lock; record the anomaly and coordinate.

### Release

Release a lock only after the relevant write and verification are complete, and
only if it is still owned by the current agent.

## Stale Locks

- Treat a lock as stale only after a documented lease timeout that comfortably
  exceeds the expected write duration.
- Before taking over a stale lock, inspect the previous owner's active intent,
  recent activity, and messages.
- Record the previous owner, file path, age, and reason for takeover.
- Never infer that a lock is stale merely because progress appears slow.

## Active Intent

Each active agent should maintain one lightweight record, such as
`agents/active/$AGENT_ID.intent`, containing:

```text
agent_id: example-agent
state: working
lock: lib/session.js
files:
  - lib/session.js
priority: normal
requires_coordination: false
requires_human: false
timestamp: 2026-01-01T00:00:00Z
summary: Brief description of the task
```

Recommended states are:

- `idle`
- `working`
- `waiting_lock`
- `blocked`
- `error`
- `needs_coordination`
- `needs_human`

Keep the timestamp current while active. The `lock` field must match the owned
lock while writing. Remove the active intent record when work is complete.

## Conflict Handling

If an agent repeatedly fails to acquire a lock, detects overlapping intent, or
finds conflicting edits:

1. Stop attempting the write.
2. Inspect active intent, historical intent, and coordination messages.
3. Mark the task as requiring coordination.
4. Contact the conflicting agent or coordinator with the affected paths and
   intended changes.
5. Escalate for human direction if the conflict cannot be resolved safely.

Agents must use bounded retries and must not busy-wait indefinitely.

## Multi-Agent Coordination

When one coordinator starts parallel agents:

- Declare one coordinator and assign every participating agent a unique handle.
- Give each agent a clearly separated scope whenever possible.
- Record each agent's intended files before parallel modification begins.
- Avoid multiple coordinators for the same workspace and task.
- Merge or hand off work only after confirming that locks are released and the
  resulting changes are compatible.

## History and Messaging

- Use messages for awareness and negotiation; messages do not grant ownership.
- Keep completed-task history append-only.
- Record material lock takeovers, conflicts, and coordination decisions.
- Do not rewrite another agent's intent, messages, or history records except as
  part of an explicitly agreed recovery procedure.
