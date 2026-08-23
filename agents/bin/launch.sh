#!/usr/bin/env bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
WORKDIR="${PWD}"
ROLE=""

usage() {
    cat <<'EOF'
usage:
  MYID=coder agents/bin/launch.sh [--role coder] codex
  MYID=coder agents/bin/launch.sh [--role coder] codex resume <id>

options:
  --role <role>   annotate the launched agent role for bootstrap instructions
  -h, --help      show this help

notes:
  - launches a detached tmux session named $MYID through collab.cjs create-agent
  - passes command and args through unchanged
  - auto-registers $MYID as a managed agent for idle claim_pending nudges
EOF
}

die() {
    printf 'launch.sh: %s\n' "$*" >&2
    exit 1
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        -h|--help)
            usage
            exit 0
            ;;
        --role)
            [[ $# -ge 2 ]] || die '--role requires a value'
            ROLE="$2"
            shift 2
            ;;
        --)
            shift
            break
            ;;
        *)
            break
            ;;
    esac
done

[[ $# -gt 0 ]] || {
    usage
    exit 1
}

[[ -n "${MYID:-}" ]] || die 'MYID must be set'

cmd=(
    node
    collab.cjs
    create-agent
    --agent "${MYID}"
    --target "${MYID}"
    --channel "${COLLAB_CHANNEL:-lobby}"
    --mcp-url "${COLLAB_MCP_URL:-http://127.0.0.1:1337/mcp}"
    --workdir "${WORKDIR}"
)

if [[ -n "${ROLE}" ]]; then
    cmd+=(--role "${ROLE}")
fi

cmd+=(-- "$@")

(cd "${ROOT}" && "${cmd[@]}")
