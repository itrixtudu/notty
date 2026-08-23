#!/usr/bin/env bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=agents/bin/swarm.lib.sh
source "${SCRIPT_DIR}/swarm.lib.sh"

usage() {
    cat <<'EOF'
usage:
  agents/bin/swarm.sh --request "..." [--preset core]
  agents/bin/swarm.sh --request-file path/to/request.txt [--agents coordinator,coder,qa]
  agents/bin/swarm.sh --prepare-only --request "..."
  agents/bin/swarm.sh --list-presets
  agents/bin/swarm.sh --list-agents

options:
  --request TEXT          Inline request text.
  --request-file PATH     Read request text from a file.
  --preset NAME           Agent preset: core, plan, build, full.
  --agents CSV            Explicit agent ids, comma separated.
  --channel NAME          Lobby channel name. Default: lobby.
  --watch-user NAME       Human/user MYID for the suggested watch command.
  --model MODEL           Override the default model for every agent.
  --run-id ID             Use a custom run id.
  --stdout                Run each role launcher in foreground and print codex output.
  --prepare-only          Create prompts/scripts/manifest but do not launch.
  --dry-run               Print launch plan after generating run files.
  --list-presets          Print available presets.
  --list-agents           Print available agent ids.
  -h, --help              Show this help.
EOF
}

die() {
    printf 'swarm: %s\n' "$*" >&2
    exit 1
}

join_by() {
    local sep="$1"
    shift
    local out=""
    local item
    for item in "$@"; do
        if [[ -n "${out}" ]]; then
            out+="${sep}"
        fi
        out+="${item}"
    done
    printf '%s\n' "${out}"
}

canonical_agent_list() {
    local raw="$1"
    local item trimmed
    local -a out=()
    IFS=',' read -r -a items <<<"${raw}"
    for item in "${items[@]}"; do
        trimmed="$(printf '%s' "${item}" | xargs)"
        [[ -n "${trimmed}" ]] || continue
        out+=("${trimmed}")
    done
    if [[ "${#out[@]}" -eq 0 ]]; then
        return 1
    fi
    printf '%s\n' "${out[@]}"
}

REQUEST_TEXT=""
REQUEST_FILE=""
PRESET="$(swarm_default_preset)"
AGENTS_CSV=""
CHANNEL="$(swarm_default_channel)"
WATCH_USER="$(swarm_default_watch_user)"
MODEL_OVERRIDE=""
RUN_ID=""
PREPARE_ONLY=0
DRY_RUN=0
STDOUT=0
LIST_PRESETS=0
LIST_AGENTS=0

while [[ $# -gt 0 ]]; do
    case "$1" in
        --request)
            REQUEST_TEXT="${2:-}"
            shift 2
            ;;
        --request-file)
            REQUEST_FILE="${2:-}"
            shift 2
            ;;
        --preset)
            PRESET="${2:-}"
            shift 2
            ;;
        --agents)
            AGENTS_CSV="${2:-}"
            shift 2
            ;;
        --channel)
            CHANNEL="${2:-}"
            shift 2
            ;;
        --watch-user|--watch-agent)
            WATCH_USER="${2:-}"
            shift 2
            ;;
        --model)
            MODEL_OVERRIDE="${2:-}"
            shift 2
            ;;
        --run-id)
            RUN_ID="${2:-}"
            shift 2
            ;;
        --stdout)
            STDOUT=1
            shift
            ;;
        --prepare-only)
            PREPARE_ONLY=1
            shift
            ;;
        --dry-run)
            DRY_RUN=1
            shift
            ;;
        --list-presets)
            LIST_PRESETS=1
            shift
            ;;
        --list-agents)
            LIST_AGENTS=1
            shift
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            if [[ -z "${REQUEST_TEXT}" ]]; then
                REQUEST_TEXT="$1"
            else
                REQUEST_TEXT="${REQUEST_TEXT} $1"
            fi
            shift
            ;;
    esac
done

if [[ "${LIST_PRESETS}" -eq 1 ]]; then
    swarm_list_presets
    exit 0
fi

if [[ "${LIST_AGENTS}" -eq 1 ]]; then
    swarm_list_agents
    exit 0
fi

ROOT="$(swarm_repo_root)"
RUNS_DIR="$(swarm_runs_dir "${ROOT}")"
mkdir -p "${RUNS_DIR}"

if [[ -n "${REQUEST_FILE}" ]]; then
    [[ -f "${REQUEST_FILE}" ]] || die "request file not found: ${REQUEST_FILE}"
    REQUEST_TEXT="$(cat "${REQUEST_FILE}")"
fi

if [[ -z "${REQUEST_TEXT}" && ! -t 0 ]]; then
    REQUEST_TEXT="$(cat)"
fi

[[ -n "${REQUEST_TEXT}" ]] || die "request text is required"

if [[ -z "${RUN_ID}" ]]; then
    RUN_ID="$(date -u +%Y%m%dT%H%M%SZ)"
fi

if [[ -n "${AGENTS_CSV}" ]]; then
    mapfile -t AGENTS < <(canonical_agent_list "${AGENTS_CSV}")
else
    mapfile -t AGENTS < <(swarm_resolve_preset "${PRESET}") || die "unknown preset: ${PRESET}"
fi

[[ "${#AGENTS[@]}" -gt 0 ]] || die "no agents selected"

if ! CODEX_BIN="$(swarm_codex_bin "${ROOT}")"; then
    die "unable to find codex CLI; set SWARM_CODEX_BIN or install codex under node_modules/.bin"
fi

RUN_DIR="${RUNS_DIR}/${RUN_ID}"
mkdir -p "${RUN_DIR}"

REQUEST_PATH="${RUN_DIR}/request.txt"
printf '%s\n' "${REQUEST_TEXT}" > "${REQUEST_PATH}"

WATCH_CMD="MYID=${WATCH_USER} node collab.cjs irc --agent ${WATCH_USER} --channel ${CHANNEL}"

{
    printf 'run_id=%s\n' "${RUN_ID}"
    printf 'root=%s\n' "${ROOT}"
    printf 'channel=%s\n' "${CHANNEL}"
    printf 'watch_user=%s\n' "${WATCH_USER}"
    printf 'preset=%s\n' "${PRESET}"
    printf 'prepare_only=%s\n' "${PREPARE_ONLY}"
    printf 'stdout=%s\n' "${STDOUT}"
    printf 'codex_bin=%s\n' "${CODEX_BIN}"
    printf 'selected_agents=%s\n' "$(join_by ',' "${AGENTS[@]}")"
    printf 'started_at=%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    printf 'watch_cmd=%s\n' "${WATCH_CMD}"
} > "${RUN_DIR}/manifest.env"

printf '%s\n' "${WATCH_CMD}" > "${RUN_DIR}/watch.cmd"

for agent in "${AGENTS[@]}"; do
    prompt_file="${RUN_DIR}/${agent}.prompt.txt"
    log_file="${RUN_DIR}/${agent}.log"
    final_file="${RUN_DIR}/${agent}.final.txt"
    pid_file="${RUN_DIR}/${agent}.pid"
    cmd_file="${RUN_DIR}/${agent}.launch.sh"
    model="$(swarm_agent_model "${agent}" "${MODEL_OVERRIDE}")" || die "unknown agent: ${agent}"

    swarm_render_prompt "${agent}" "${CHANNEL}" "${RUN_ID}" "${REQUEST_PATH}" "${ROOT}" > "${prompt_file}"

    cat > "${cmd_file}" <<EOF
#!/usr/bin/env bash
set -euo pipefail
cd "${ROOT}"
export MYID="${agent}"
export COLLAB_AGENT_ID="${agent}"
export COLLAB_CHANNEL="${CHANNEL}"
export SWARM_RUN_ID="${RUN_ID}"

if [[ "${1:-}" == "--stdout" ]]; then
    exec "${CODEX_BIN}" exec --output-last-message "${final_file}" -C "${ROOT}" --json --full-auto -m "${model}" - < "${prompt_file}"
fi

if [[ "${1:-}" != "" ]]; then
    printf 'swarm role launcher: unknown argument: %s\n' "${1:-}" >&2
    exit 1
fi

exec "${CODEX_BIN}" exec --output-last-message "${final_file}" -C "${ROOT}" --json --full-auto -m "${model}" - < "${prompt_file}" >> "${log_file}" 2>&1
EOF
    chmod +x "${cmd_file}"

    if [[ "${PREPARE_ONLY}" -eq 1 ]]; then
        continue
    fi

    if [[ "${STDOUT}" -eq 1 ]]; then
        bash "${cmd_file}" --stdout
    else
        nohup "${cmd_file}" >/dev/null 2>&1 &
        printf '%s\n' "$!" > "${pid_file}"
    fi
done

printf 'run_dir=%s\n' "${RUN_DIR}"
printf 'watch=%s\n' "${WATCH_CMD}"
printf 'agents=%s\n' "$(join_by ',' "${AGENTS[@]}")"

if [[ "${DRY_RUN}" -eq 1 ]]; then
    for agent in "${AGENTS[@]}"; do
        printf '%s\t%s\n' "${agent}" "${RUN_DIR}/${agent}.launch.sh"
    done
fi
