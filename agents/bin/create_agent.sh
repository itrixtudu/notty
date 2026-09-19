#!/usr/bin/env bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=./swarm.lib.sh
source "${SCRIPT_DIR}/swarm.lib.sh"

usage() {
    cat <<'USAGE'
usage:
  agents/bin/create_agent.sh <name> [role]
  agents/bin/create_agent.sh [--agent <name>] --role <role> [--harness codex|agy|claude] [--backend default|ollama] [--model <model>] [--think <level>]

notes:
  - launches a detached tmux session named <name>
  - defaults to the Codex agent with its hosted/default model runtime
  - --runtime codex|agy|ollama|claude remains as a legacy alias
  - --runtime ollama maps to --harness codex --backend ollama
  - COLLAB_HARNESS and COLLAB_BACKEND mirror the canonical flags; COLLAB_RUNTIME remains compatible
  - Ollama is supported only with Codex and requires --model
  - --think sets Codex reasoning effort or Agy/Claude --effort
  - model names containing spaces must be passed as one quoted argument
  - Nosh defaults Codex and Ollama to full access; set NOTTY_COLLAB_UNSANDBOXED=false for workspace-write
  - Agy and Claude stay sandboxed by the Nosh default; explicit NOTTY_COLLAB_UNSANDBOXED=true unsandboxes all agents
  - registers the tmux session as a managed collab agent
  - bootstraps the agent to register with collab and use claim_pending
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
ROLE=''
ENV_HARNESS="${COLLAB_HARNESS:-}"
ENV_BACKEND="${COLLAB_BACKEND:-}"
ENV_RUNTIME="${COLLAB_RUNTIME:-}"
CLI_HARNESS=''
CLI_BACKEND=''
CLI_RUNTIME=''
HARNESS=''
BACKEND=''
RUNTIME=''
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
                printf 'create_agent.sh: %s requires a value\n' "$1" >&2
                exit 1
            }
            NAME="$2"
            shift 2
            ;;
        --role)
            [[ $# -ge 2 && -n "$2" && "$2" != --* ]] || {
                printf 'create_agent.sh: --role requires a value\n' >&2
                exit 1
            }
            ROLE="$2"
            shift 2
            ;;
        --harness)
            [[ $# -ge 2 && -n "$2" && "$2" != --* ]] || {
                printf 'create_agent.sh: --harness requires a value\n' >&2
                exit 1
            }
            CLI_HARNESS="$2"
            shift 2
            ;;
        --backend)
            [[ $# -ge 2 && -n "$2" && "$2" != --* ]] || {
                printf 'create_agent.sh: --backend requires a value\n' >&2
                exit 1
            }
            CLI_BACKEND="$2"
            shift 2
            ;;
        --runtime)
            [[ $# -ge 2 && -n "$2" && "$2" != --* ]] || {
                printf 'create_agent.sh: --runtime requires a value\n' >&2
                exit 1
            }
            CLI_RUNTIME="$2"
            shift 2
            ;;
        --model)
            [[ $# -ge 2 && -n "$2" && "$2" != --* ]] || {
                printf 'create_agent.sh: --model requires a value\n' >&2
                exit 1
            }
            MODEL="$2"
            shift 2
            ;;
        --think)
            if [[ $# -ge 2 && -n "$2" && "$2" != --* ]]; then
                THINK="$2"
                shift 2
            else
                THINK='true'
                shift
            fi
            ;;
        --)
            shift
            while [[ $# -gt 0 ]]; do
                if [[ -z "${NAME}" ]]; then
                    NAME="$1"
                elif [[ -z "${ROLE}" ]]; then
                    ROLE="$1"
                else
                    printf 'create_agent.sh: unexpected argument: %s\n' "$1" >&2
                    exit 1
                fi
                shift
            done
            ;;
        --*)
            printf 'create_agent.sh: unknown option: %s\n' "$1" >&2
            exit 1
            ;;
        *)
            if [[ -z "${NAME}" ]]; then
                NAME="$1"
            elif [[ -z "${ROLE}" ]]; then
                ROLE="$1"
            else
                printf 'create_agent.sh: unexpected argument: %s\n' "$1" >&2
                exit 1
            fi
            shift
            ;;
    esac
done

if [[ -z "${NAME}" ]]; then
    NAME="${ROLE}"
fi
[[ -n "${NAME}" ]] || {
    usage
    exit 1
}
ROLE="${ROLE:-${COLLAB_ROLE:-${NAME}}}"

ENV_HARNESS="${ENV_HARNESS,,}"
ENV_BACKEND="${ENV_BACKEND,,}"
ENV_RUNTIME="${ENV_RUNTIME,,}"
CLI_HARNESS="${CLI_HARNESS,,}"
CLI_BACKEND="${CLI_BACKEND,,}"
CLI_RUNTIME="${CLI_RUNTIME,,}"

ENV_RUNTIME_HARNESS=''
ENV_RUNTIME_BACKEND=''
if [[ -n "${ENV_RUNTIME}" ]]; then
    ENV_RUNTIME_HARNESS="$(swarm_harness_for_runtime "${ENV_RUNTIME}")" || exit 1
    ENV_RUNTIME_BACKEND="$(swarm_backend_for_runtime "${ENV_RUNTIME}")" || exit 1
fi
if [[ -n "${ENV_HARNESS}" ]]; then
    swarm_validate_launch_target "${ENV_HARNESS}" "${ENV_BACKEND:-default}" || exit 1
fi
if [[ -n "${ENV_BACKEND}" ]]; then
    case "${ENV_BACKEND}" in
        default|ollama) ;;
        *)
            printf 'create_agent.sh: unsupported model backend: %s\n' "${ENV_BACKEND}" >&2
            exit 1
            ;;
    esac
fi
if [[ -n "${ENV_RUNTIME_HARNESS}" && -n "${ENV_HARNESS}" && "${ENV_RUNTIME_HARNESS}" != "${ENV_HARNESS}" ]]; then
    printf 'create_agent.sh: COLLAB_RUNTIME=%s conflicts with COLLAB_HARNESS=%s\n' \
        "${ENV_RUNTIME}" "${ENV_HARNESS}" >&2
    exit 1
fi
if [[ -n "${ENV_RUNTIME_BACKEND}" && -n "${ENV_BACKEND}" && "${ENV_RUNTIME_BACKEND}" != "${ENV_BACKEND}" ]]; then
    printf 'create_agent.sh: COLLAB_RUNTIME=%s conflicts with COLLAB_BACKEND=%s\n' \
        "${ENV_RUNTIME}" "${ENV_BACKEND}" >&2
    exit 1
fi

HARNESS="${ENV_HARNESS:-${ENV_RUNTIME_HARNESS:-codex}}"
BACKEND="${ENV_BACKEND:-${ENV_RUNTIME_BACKEND:-default}}"

if [[ -n "${CLI_RUNTIME}" ]]; then
    CLI_RUNTIME_HARNESS="$(swarm_harness_for_runtime "${CLI_RUNTIME}")" || exit 1
    CLI_RUNTIME_BACKEND="$(swarm_backend_for_runtime "${CLI_RUNTIME}")" || exit 1
    if [[ -n "${CLI_HARNESS}" && "${CLI_RUNTIME_HARNESS}" != "${CLI_HARNESS}" ]]; then
        printf 'create_agent.sh: --runtime %s conflicts with --harness %s\n' \
            "${CLI_RUNTIME}" "${CLI_HARNESS}" >&2
        exit 1
    fi
    if [[ -n "${CLI_BACKEND}" && "${CLI_RUNTIME_BACKEND}" != "${CLI_BACKEND}" ]]; then
        printf 'create_agent.sh: --runtime %s conflicts with --backend %s\n' \
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
    if [[ "${CLI_RUNTIME}" == 'ollama' || ( -z "${CLI_BACKEND}" && "${ENV_RUNTIME}" == 'ollama' ) ]]; then
        printf 'create_agent.sh: --runtime ollama requires --model\n' >&2
    else
        printf 'create_agent.sh: --backend ollama requires --model\n' >&2
    fi
    exit 1
fi
THINK="$(swarm_normalize_think "${HARNESS}" "${THINK}" "${BACKEND}")" || exit 1
MCP_URL="$(swarm_mcp_url_for_runtime "${HARNESS}" "${MCP_URL}")"

swarm_launch_canonical_agent \
    "${ROOT}" "${NAME}" "${ROLE}" "${HARNESS}" "${BACKEND}" \
    "${MODEL}" "${THINK}" "${WORKDIR}" "${CHANNEL}" "${MCP_URL}" create

printf 'agent=%s\ttarget=%s\trole=%s\tharness=%s\tbackend=%s\truntime=%s\tmodel=%s\tthink=%s\tchannel=%s\n' \
    "${NAME}" "${NAME}" "${ROLE}" "${HARNESS}" "${BACKEND}" "${RUNTIME}" \
    "${MODEL:-default}" "${THINK:-default}" "${CHANNEL}"
