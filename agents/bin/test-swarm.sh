#!/usr/bin/env bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
WATCH_USER="${1:-${USER:-operator}}"
RUN_ID="${RUN_ID:-test-$(date -u +%Y%m%dT%H%M%SZ)}"
REQUEST="${2:-Smoke-test the codex swarm launcher. Check in to lobby, summarize your role, and do not modify files.}"

"${ROOT}/agents/bin/swarm.sh" \
    --prepare-only \
    --dry-run \
    --preset core \
    --watch-user "${WATCH_USER}" \
    --run-id "${RUN_ID}" \
    --request "${REQUEST}"

RUN_DIR="${ROOT}/agents/runs/${RUN_ID}"

printf '\nmanifest:\n'
sed -n '1,120p' "${RUN_DIR}/manifest.env"

printf '\nwatch command:\n'
cat "${RUN_DIR}/watch.cmd"

printf '\ncoordinator prompt preview:\n'
sed -n '1,40p' "${RUN_DIR}/coordinator.prompt.txt"
