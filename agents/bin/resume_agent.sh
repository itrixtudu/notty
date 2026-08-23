#!/usr/bin/env bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=./swarm.lib.sh
source "${SCRIPT_DIR}/swarm.lib.sh"

usage() {
    cat <<'USAGE'
usage:
  agents/bin/resume_agent.sh <name> <session_id> [role]
  agents/bin/resume_agent.sh --agent <name> --session-id <id> [--role <role>] [--harness codex|agy|claude] [--backend default|ollama] [--model <model>] [--think <level>]

notes:
  - resumes Codex, Agy, or Claude in a detached tmux session named <name>
  - Ollama is a Codex model backend and requires --model
  - --runtime codex|agy|ollama|claude remains as a legacy alias
  - COLLAB_HARNESS and COLLAB_BACKEND mirror the canonical flags; COLLAB_RUNTIME remains compatible
  - registers the tmux session as a managed collab agent
USAGE
}

case "${1:-}" in
    -h|--help)
        usage
        exit 0
        ;;
esac

ROOT="$(swarm_repo_root)"
WORKDIR="${PWD}"
CHANNEL="${COLLAB_CHANNEL:-$(swarm_default_channel)}"
MCP_URL="$(swarm_default_mcp_url)"
NAME=''
SESSION_ID=''
ROLE=''
CLI_HARNESS=''
CLI_BACKEND=''
CLI_RUNTIME=''
MODEL="${COLLAB_MODEL:-}"
THINK="${COLLAB_THINK:-}"

while [[ $# -gt 0 ]]; do
    case "$1" in
        -h|--help)
            usage
            exit 0
            ;;
        --agent|--name|--id)
            [[ $# -ge 2 && -n "$2" && "$2" != --* ]] || {
                printf 'resume_agent.sh: %s requires a value\n' "$1" >&2
                exit 1
            }
            NAME="$2"
            shift 2
            ;;
        --session-id|--session_id)
            [[ $# -ge 2 && -n "$2" && "$2" != --* ]] || {
                printf 'resume_agent.sh: %s requires a value\n' "$1" >&2
                exit 1
            }
            SESSION_ID="$2"
            shift 2
            ;;
        --role)
            [[ $# -ge 2 && -n "$2" && "$2" != --* ]] || {
                printf 'resume_agent.sh: --role requires a value\n' >&2
                exit 1
            }
            ROLE="$2"
            shift 2
            ;;
        --harness)
            [[ $# -ge 2 && -n "$2" && "$2" != --* ]] || {
                printf 'resume_agent.sh: --harness requires a value\n' >&2
                exit 1
            }
            CLI_HARNESS="${2,,}"
            shift 2
            ;;
        --backend)
            [[ $# -ge 2 && -n "$2" && "$2" != --* ]] || {
                printf 'resume_agent.sh: --backend requires a value\n' >&2
                exit 1
            }
            CLI_BACKEND="${2,,}"
            shift 2
            ;;
        --runtime)
            [[ $# -ge 2 && -n "$2" && "$2" != --* ]] || {
                printf 'resume_agent.sh: --runtime requires a value\n' >&2
                exit 1
            }
            CLI_RUNTIME="${2,,}"
            shift 2
            ;;
        --model)
            [[ $# -ge 2 && -n "$2" && "$2" != --* ]] || {
                printf 'resume_agent.sh: --model requires a value\n' >&2
                exit 1
            }
            MODEL="$2"
            shift 2
            ;;
        --think)
            [[ $# -ge 2 && -n "$2" && "$2" != --* ]] || {
                printf 'resume_agent.sh: --think requires a value\n' >&2
                exit 1
            }
            THINK="$2"
            shift 2
            ;;
        --*)
            printf 'resume_agent.sh: unknown option: %s\n' "$1" >&2
            exit 1
            ;;
        *)
            if [[ -z "${NAME}" ]]; then
                NAME="$1"
            elif [[ -z "${SESSION_ID}" ]]; then
                SESSION_ID="$1"
            elif [[ -z "${ROLE}" ]]; then
                ROLE="$1"
            else
                printf 'resume_agent.sh: unexpected argument: %s\n' "$1" >&2
                exit 1
            fi
            shift
            ;;
    esac
done

[[ -n "${NAME}" && -n "${SESSION_ID}" ]] || {
    usage
    exit 1
}
ROLE="${ROLE:-${COLLAB_ROLE:-${NAME}}}"

ENV_HARNESS="${COLLAB_HARNESS:-}"
ENV_BACKEND="${COLLAB_BACKEND:-}"
ENV_RUNTIME="${COLLAB_RUNTIME:-}"
ENV_HARNESS="${ENV_HARNESS,,}"
ENV_BACKEND="${ENV_BACKEND,,}"
ENV_RUNTIME="${ENV_RUNTIME,,}"
ENV_RUNTIME_HARNESS=''
ENV_RUNTIME_BACKEND=''
if [[ -n "${ENV_RUNTIME}" ]]; then
    ENV_RUNTIME_HARNESS="$(swarm_harness_for_runtime "${ENV_RUNTIME}")" || exit 1
    ENV_RUNTIME_BACKEND="$(swarm_backend_for_runtime "${ENV_RUNTIME}")" || exit 1
fi
if [[ -n "${ENV_HARNESS}" ]]; then
    swarm_validate_launch_target "${ENV_HARNESS}" "${ENV_BACKEND:-default}" || exit 1
fi
if [[ -n "${ENV_RUNTIME_HARNESS}" && -n "${ENV_HARNESS}" && "${ENV_RUNTIME_HARNESS}" != "${ENV_HARNESS}" ]]; then
    printf 'resume_agent.sh: COLLAB_RUNTIME=%s conflicts with COLLAB_HARNESS=%s\n' \
        "${ENV_RUNTIME}" "${ENV_HARNESS}" >&2
    exit 1
fi
if [[ -n "${ENV_RUNTIME_BACKEND}" && -n "${ENV_BACKEND}" && "${ENV_RUNTIME_BACKEND}" != "${ENV_BACKEND}" ]]; then
    printf 'resume_agent.sh: COLLAB_RUNTIME=%s conflicts with COLLAB_BACKEND=%s\n' \
        "${ENV_RUNTIME}" "${ENV_BACKEND}" >&2
    exit 1
fi
HARNESS="${ENV_HARNESS:-${ENV_RUNTIME_HARNESS:-codex}}"
BACKEND="${ENV_BACKEND:-${ENV_RUNTIME_BACKEND:-default}}"

if [[ -n "${CLI_RUNTIME}" ]]; then
    CLI_RUNTIME_HARNESS="$(swarm_harness_for_runtime "${CLI_RUNTIME}")" || exit 1
    CLI_RUNTIME_BACKEND="$(swarm_backend_for_runtime "${CLI_RUNTIME}")" || exit 1
    if [[ -n "${CLI_HARNESS}" && "${CLI_HARNESS}" != "${CLI_RUNTIME_HARNESS}" ]]; then
        printf 'resume_agent.sh: --runtime %s conflicts with --harness %s\n' \
            "${CLI_RUNTIME}" "${CLI_HARNESS}" >&2
        exit 1
    fi
    if [[ -n "${CLI_BACKEND}" && "${CLI_BACKEND}" != "${CLI_RUNTIME_BACKEND}" ]]; then
        printf 'resume_agent.sh: --runtime %s conflicts with --backend %s\n' \
            "${CLI_RUNTIME}" "${CLI_BACKEND}" >&2
        exit 1
    fi
    HARNESS="${CLI_RUNTIME_HARNESS}"
    BACKEND="${CLI_RUNTIME_BACKEND}"
else
    HARNESS="${CLI_HARNESS:-${HARNESS}}"
    BACKEND="${CLI_BACKEND:-${BACKEND}}"
fi

swarm_validate_launch_target "${HARNESS}" "${BACKEND}" || exit 1
RUNTIME="$(swarm_legacy_runtime_for "${HARNESS}" "${BACKEND}")" || exit 1
if [[ "${BACKEND}" == 'ollama' && -z "${MODEL}" ]]; then
    printf 'resume_agent.sh: --backend ollama requires --model\n' >&2
    exit 1
fi
THINK="$(swarm_normalize_think "${HARNESS}" "${THINK}" "${BACKEND}")" || exit 1
MCP_URL="$(swarm_mcp_url_for_runtime "${HARNESS}" "${MCP_URL}")"

swarm_launch_canonical_agent \
    "${ROOT}" "${NAME}" "${ROLE}" "${HARNESS}" "${BACKEND}" \
    "${MODEL}" "${THINK}" "${WORKDIR}" "${CHANNEL}" "${MCP_URL}" \
    resume "${SESSION_ID}"

printf 'agent=%s\ttarget=%s\trole=%s\tharness=%s\tbackend=%s\truntime=%s\tmodel=%s\tthink=%s\tchannel=%s\tsession_id=%s\n' \
    "${NAME}" "${NAME}" "${ROLE}" "${HARNESS}" "${BACKEND}" "${RUNTIME}" \
    "${MODEL:-default}" "${THINK:-default}" "${CHANNEL}" "${SESSION_ID}"
