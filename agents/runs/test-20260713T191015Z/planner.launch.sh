#!/usr/bin/env bash
set -euo pipefail
cd "/home/xpatchdev/notty"
export MYID="planner"
export COLLAB_AGENT_ID="planner"
export COLLAB_CHANNEL="lobby"
export SWARM_RUN_ID="test-20260713T191015Z"

if [[ "" == "--stdout" ]]; then
    exec "/home/xpatchdev/node_modules/.bin/codex" exec --output-last-message "/home/xpatchdev/notty/agents/runs/test-20260713T191015Z/planner.final.txt" -C "/home/xpatchdev/notty" --json --full-auto -m "gpt-5.4" - < "/home/xpatchdev/notty/agents/runs/test-20260713T191015Z/planner.prompt.txt"
fi

if [[ "" != "" ]]; then
    printf 'swarm role launcher: unknown argument: %s\n' "" >&2
    exit 1
fi

exec "/home/xpatchdev/node_modules/.bin/codex" exec --output-last-message "/home/xpatchdev/notty/agents/runs/test-20260713T191015Z/planner.final.txt" -C "/home/xpatchdev/notty" --json --full-auto -m "gpt-5.4" - < "/home/xpatchdev/notty/agents/runs/test-20260713T191015Z/planner.prompt.txt" >> "/home/xpatchdev/notty/agents/runs/test-20260713T191015Z/planner.log" 2>&1
