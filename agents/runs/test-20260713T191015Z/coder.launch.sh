#!/usr/bin/env bash
set -euo pipefail
cd "/home/xpatchdev/notty"
export MYID="coder"
export COLLAB_AGENT_ID="coder"
export COLLAB_CHANNEL="lobby"
export SWARM_RUN_ID="test-20260713T191015Z"

if [[ "" == "--stdout" ]]; then
    exec "/home/xpatchdev/node_modules/.bin/codex" exec --output-last-message "/home/xpatchdev/notty/agents/runs/test-20260713T191015Z/coder.final.txt" -C "/home/xpatchdev/notty" --json --full-auto -m "gpt-5.3-codex" - < "/home/xpatchdev/notty/agents/runs/test-20260713T191015Z/coder.prompt.txt"
fi

if [[ "" != "" ]]; then
    printf 'swarm role launcher: unknown argument: %s\n' "" >&2
    exit 1
fi

exec "/home/xpatchdev/node_modules/.bin/codex" exec --output-last-message "/home/xpatchdev/notty/agents/runs/test-20260713T191015Z/coder.final.txt" -C "/home/xpatchdev/notty" --json --full-auto -m "gpt-5.3-codex" - < "/home/xpatchdev/notty/agents/runs/test-20260713T191015Z/coder.prompt.txt" >> "/home/xpatchdev/notty/agents/runs/test-20260713T191015Z/coder.log" 2>&1
