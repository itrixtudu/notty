# Agents Usage

This repo supports two ways to run agents:

- a shared `collab.cjs` process that exposes the MCP service and channel state
- tmux-backed Codex sessions that register with collab and coordinate through `lobby`

The current design separates concerns:

- MCP/SSE handles tool transport and shared state
- `claim_pending` handles work claiming
- tmux handles wake-ups for idle interactive sessions

## Core concepts

- `MYID`: the agent identity. tmux session names and collab nicknames should match this value.
- `lobby`: the default coordination channel. Use `lobby`, not `#lobby`.
- managed agent: an agent that collab is allowed to wake via tmux when pending work exists.
- pending work: direct messages or channel activity queued until the agent calls `claim_pending`.

## Start collab

Normal startup:

```bash
node collab.cjs irc --channel lobby --ip 127.0.0.1 --port 1337
```

Fresh startup:

```bash
node collab.cjs irc --channel lobby --ip 127.0.0.1 --port 1337 --fresh
```

`--fresh` clears:

- `agents/active/*`
- `agents/msgs/*`
- `collab/intragent/channels/*`
- `collab/intragent/managed_agents.json`
- in-memory MCP registration, status, and pending-work state

`--fresh` does not clear:

- `agents/locks/*`
- `agents/intent/*`
- `agents/history/*`

Use normal startup when you want resume capability after a restart. Use `--fresh` when starting a clean new run.

## Manual tmux launch

Use `agents/bin/launch.sh` when you want to hook a single interactive agent into the event bus.

Examples:

```bash
MYID=coder agents/bin/launch.sh codex --full-auto
MYID=coder agents/bin/launch.sh codex resume 12345 --full-auto
```

Behavior:

- creates a detached tmux session named `$MYID`
- launches the command you pass after `launch.sh`
- keeps `$@` intact, so `resume <id>` works
- best-effort registers the agent as managed with `collab.cjs add-agent`

## Swarm launch

Use `agents/bin/swarm-tmux.sh` to launch a coordinated tmux swarm.

Example:

```bash
agents/bin/swarm-tmux.sh --request "Describe the task here" --preset core
```

Behavior:

- creates a run directory under `agents/runs/<run_id>/`
- generates per-agent launchers and `all.launch.sh`
- launches tmux sessions such as `coordinator`, `planner`, `coder`, and `qa`
- aborts before launch if any requested tmux session already exists
- pastes the startup prompt, then sends a delayed standalone `Enter`

If `all.launch.sh` aborts, clean up the conflicting tmux sessions first.

## Register an agent

Agents connect to the MCP service exposed by `collab.cjs`. Once connected, they must register their identity.

Required first steps:

1. set nickname to `MYID`
2. work in `lobby`
3. set runtime status while working
4. claim pending work when idle

Expected MCP flow:

1. `set_nickname(MYID)`
2. `set_status("busy")` while actively working
3. `set_status("idle")` when waiting or done
4. `claim_pending()` before going quiet

## Managed agents

Managed agents are allowed to receive tmux nudges from collab when they are registered, idle, and have pending work.

CLI commands:

```bash
node collab.cjs add-agent --agent coder --target coder
node collab.cjs remove-agent --agent coder
node collab.cjs managed-agents
```

IRC commands:

```text
/add_agent <MYID> [target]
/remove_agent <MYID>
/managed
```

Defaults:

- `agent` is the collab nickname
- `target` is the tmux session name
- in the common case they are the same value

When a managed agent is both registered and `idle`, collab can nudge the tmux session to use `claim_pending`.

## Claiming work

`claim_pending` is the handoff point between queued activity and agent action.

Typical behavior:

- direct messages set direct pending work
- channel messages set pending channel work for other registered agents
- the agent goes `idle`
- the agent calls `claim_pending()`
- the agent follows the returned next step, such as checking direct messages or reading `lobby`

This avoids constant polling and keeps interactive sessions event-driven.

## Tmux helpers

`collab.cjs` exposes tmux helpers both on the CLI and through MCP.

CLI examples:

```bash
node collab.cjs tmux-send --session coder --body "wake up" --enter --delay-ms 200
node collab.cjs tmux-read --session coder --lines 40
```

MCP tools:

- `tmux_send`
- `tmux_read`

These default to the caller's registered nickname/session when no target is provided.

## Recommended operator flow

1. start collab `node collab.cjs irc --channel lobby --ip 127.0.0.1 --port 1337`
2. decide whether the run should be resumable or fresh `--fresh`
3. launch one agent with `launch.sh` or a group with `swarm-tmux.sh`
4. ensure each agent registers with `set_nickname(MYID)`
5. keep agents reporting in `lobby`
6. let idle managed agents use `claim_pending()`

## Notes

- Use `lobby`, not `#lobby`
- tmux wake-ups are still useful even with MCP/SSE because transport does not itself wake a dormant interactive model
- `agents/active`, `agents/intent`, `agents/history`, and `agents/locks` remain repo coordination state and are not all cleared by default
