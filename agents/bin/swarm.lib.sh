#!/usr/bin/env bash

set -euo pipefail

swarm_repo_root() {
    local script_dir
    script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    cd "${script_dir}/../.." && pwd
}

swarm_runs_dir() {
    local root="$1"
    printf '%s\n' "${SWARM_RUNS_DIR:-${root}/agents/runs}"
}

swarm_default_channel() {
    printf '%s\n' "${SWARM_CHANNEL:-lobby}"
}

swarm_default_watch_user() {
    printf '%s\n' "${SWARM_WATCH_USER:-${SWARM_WATCH_AGENT:-operator}}"
}

swarm_default_preset() {
    printf '%s\n' "${SWARM_PRESET:-core}"
}

swarm_models_file() {
    local script_dir
    script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    printf '%s\n' "${SWARM_MODELS_FILE:-${script_dir}/codex.models}"
}

swarm_models_catalog() {
    local models_file
    models_file="$(swarm_models_file)"

    if [[ ! -f "${models_file}" ]]; then
        return 1
    fi

    awk 'NF && $1 !~ /^#/ { print $1 }' "${models_file}"
}

swarm_model_for_agent() {
    local agent="$1"

    case "${agent}" in
        coordinator|planner|qa)
            printf '%s\n' 0
            ;;
        coder)
            printf '%s\n' 2
            ;;
        triage)
            printf '%s\n' 1
            ;;
        *)
            return 1
            ;;
    esac
}

swarm_codex_bin() {
    local root="${1:-$(pwd)}"

    if [[ -n "${SWARM_CODEX_BIN:-}" ]]; then
        printf '%s\n' "${SWARM_CODEX_BIN}"
        return 0
    fi

    if [[ -x "${root}/node_modules/.bin/codex" ]]; then
        printf '%s\n' "${root}/node_modules/.bin/codex"
        return 0
    fi

    if [[ -x "${HOME}/node_modules/.bin/codex" ]]; then
        printf '%s\n' "${HOME}/node_modules/.bin/codex"
        return 0
    fi

    if command -v codex >/dev/null 2>&1; then
        command -v codex
        return 0
    fi

    return 1
}

swarm_prepare_ollama_codex_args() {
    local root="$1"
    local model="$2"
    local isolation_key="$3"
    local output_name="$4"
    local node_bin="${SWARM_NODE_BIN:-node}"
    local curl_bin="${SWARM_CURL_BIN:-${CURL_BIN:-curl}}"
    local runtime_dir="${SWARM_OLLAMA_RUNTIME_DIR:-${NOTTY_OLLAMA_RUNTIME_DIR:-}}"
    local helper="${root}/lib/collab/ollama-cli.cjs"
    local output_file
    local -a helper_args
    local -n output_ref="${output_name}"

    if [[ ! -f "${helper}" ]]; then
        printf 'unable to locate Ollama Codex provider helper: %s\n' "${helper}" >&2
        return 1
    fi
    output_file="$(mktemp "${TMPDIR:-/tmp}/notty-ollama-codex-args.XXXXXX")" || return 1
    chmod 0600 "${output_file}"
    helper_args=(
        "${helper}"
        prepare-codex
        --format nul
        --model "${model}"
        --isolation-key "${isolation_key}"
        --curl-bin "${curl_bin}"
    )
    if [[ -n "${runtime_dir}" ]]; then
        helper_args+=(--runtime-dir "${runtime_dir}")
    fi
    if [[ -n "${OLLAMA_HOST:-}" ]]; then
        helper_args+=(--endpoint "${OLLAMA_HOST}")
    fi
    if ! "${node_bin}" "${helper_args[@]}" >"${output_file}"; then
        rm -f "${output_file}"
        return 1
    fi
    output_ref=()
    mapfile -d '' -t output_ref <"${output_file}"
    rm -f "${output_file}"
    if ((${#output_ref[@]} == 0)); then
        printf 'Ollama Codex provider helper returned no launch arguments\n' >&2
        return 1
    fi
}

swarm_remove_ollama_codex_catalog() {
    local root="$1"
    local catalog_config="$2"
    local node_bin="${SWARM_NODE_BIN:-node}"
    local runtime_dir="${SWARM_OLLAMA_RUNTIME_DIR:-${NOTTY_OLLAMA_RUNTIME_DIR:-}}"
    local helper="${root}/lib/collab/ollama-cli.cjs"
    local -a helper_args=(
        "${helper}"
        remove-catalog
        --catalog-config "${catalog_config}"
    )

    [[ -n "${catalog_config}" ]] || return 0
    if [[ -n "${runtime_dir}" ]]; then
        helper_args+=(--runtime-dir "${runtime_dir}")
    fi
    "${node_bin}" "${helper_args[@]}"
}

swarm_agy_bin() {
    local root="${1:-$(pwd)}"
    local configured="${SWARM_AGY_BIN:-${AGY_BIN:-}}"

    if [[ -n "${configured}" ]]; then
        printf '%s\n' "${configured}"
        return 0
    fi

    if [[ -x "${root}/node_modules/.bin/agy" ]]; then
        printf '%s\n' "${root}/node_modules/.bin/agy"
        return 0
    fi

    if [[ -x "${HOME}/node_modules/.bin/agy" ]]; then
        printf '%s\n' "${HOME}/node_modules/.bin/agy"
        return 0
    fi

    if command -v agy >/dev/null 2>&1; then
        command -v agy
        return 0
    fi

    return 1
}

swarm_claude_bin() {
    local root="${1:-$(pwd)}"
    local configured="${SWARM_CLAUDE_BIN:-${CLAUDE_BIN:-}}"

    if [[ -n "${configured}" ]]; then
        printf '%s\n' "${configured}"
        return 0
    fi

    if [[ -x "${root}/node_modules/.bin/claude" ]]; then
        printf '%s\n' "${root}/node_modules/.bin/claude"
        return 0
    fi

    if [[ -x "${HOME}/node_modules/.bin/claude" ]]; then
        printf '%s\n' "${HOME}/node_modules/.bin/claude"
        return 0
    fi

    if command -v claude >/dev/null 2>&1; then
        command -v claude
        return 0
    fi

    return 1
}

swarm_harness_for_runtime() {
    local runtime="${1,,}"

    case "${runtime}" in
        codex|agy|claude)
            printf '%s\n' "${runtime}"
            ;;
        ollama)
            printf '%s\n' codex
            ;;
        *)
            printf 'unsupported agent runtime: %s\n' "${runtime:-'(empty)'}" >&2
            return 1
            ;;
    esac
}

swarm_backend_for_runtime() {
    local runtime="${1,,}"

    case "${runtime}" in
        codex|agy|claude)
            printf '%s\n' default
            ;;
        ollama)
            printf '%s\n' ollama
            ;;
        *)
            printf 'unsupported agent runtime: %s\n' "${runtime:-'(empty)'}" >&2
            return 1
            ;;
    esac
}

swarm_validate_launch_target() {
    local harness="${1,,}"
    local backend="${2,,}"

    case "${harness}" in
        codex|agy|claude) ;;
        *)
            printf 'unsupported agent harness: %s\n' "${harness:-'(empty)'}" >&2
            return 1
            ;;
    esac
    case "${backend}" in
        default|ollama) ;;
        *)
            printf 'unsupported model backend: %s\n' "${backend:-'(empty)'}" >&2
            return 1
            ;;
    esac
    if [[ "${backend}" == 'ollama' && "${harness}" != 'codex' ]]; then
        printf '%s does not support the Ollama model backend; use codex/ollama\n' "${harness}" >&2
        return 1
    fi
}

swarm_legacy_runtime_for() {
    local harness="${1,,}"
    local backend="${2,,}"

    swarm_validate_launch_target "${harness}" "${backend}" || return 1
    if [[ "${backend}" == 'ollama' ]]; then
        printf '%s\n' ollama
    else
        printf '%s\n' "${harness}"
    fi
}

swarm_normalize_think() {
    local selector="${1,,}"
    local think="${2:-}"
    local backend="${3:-}"
    local harness

    if [[ -n "${backend}" ]]; then
        harness="${selector}"
        backend="${backend,,}"
        swarm_validate_launch_target "${harness}" "${backend}" || return 1
    else
        harness="$(swarm_harness_for_runtime "${selector}")" || return 1
        backend="$(swarm_backend_for_runtime "${selector}")" || return 1
    fi

    think="${think#"${think%%[![:space:]]*}"}"
    think="${think%"${think##*[![:space:]]}"}"
    think="${think,,}"
    case "${think}" in
        '')
            printf '\n'
            return 0
            ;;
        1|true|yes|on)
            think='high'
            ;;
        0|false|no|off)
            think='none'
            ;;
    esac
    if [[ "${backend}" == 'ollama' ]]; then
        case "${think}" in
            none|low|medium|high|max) ;;
            *)
                printf 'unsupported agent think level: %s for codex/ollama; expected none, low, medium, high, or max\n' "${think}" >&2
                return 1
                ;;
        esac
    elif [[ "${harness}" == 'agy' ]]; then
        case "${think}" in
            low|medium|high) ;;
            *)
                printf 'unsupported agent think level: %s for agy/default; expected low, medium, or high\n' "${think}" >&2
                return 1
                ;;
        esac
    elif [[ "${harness}" == 'claude' ]]; then
        case "${think}" in
            low|medium|high|xhigh|max) ;;
            *)
                printf 'unsupported agent think level: %s for claude/default; expected low, medium, high, xhigh, or max\n' "${think}" >&2
                return 1
                ;;
        esac
    else
        case "${think}" in
            none|minimal|low|medium|high|xhigh|max|ultra) ;;
            *)
                printf 'unsupported agent think level: %s\n' "${think}" >&2
                return 1
                ;;
        esac
    fi
    printf '%s\n' "${think}"
}

swarm_list_presets() {
    cat <<'EOF'
core
plan
build
full
EOF
}

swarm_list_agents() {
    cat <<'EOF'
coordinator
triage
planner
coder
qa
EOF
}

swarm_resolve_preset() {
    case "$1" in
        core|mvp)
            printf '%s\n' coordinator planner coder qa
            ;;
        plan)
            printf '%s\n' coordinator planner
            ;;
        build)
            printf '%s\n' coordinator coder qa
            ;;
        full)
            printf '%s\n' triage coordinator planner coder qa
            ;;
        *)
            return 1
            ;;
    esac
}

swarm_agent_model() {
    local agent="$1"
    local override="${2:-}"

    if [[ -n "${override}" ]]; then
        printf '%s\n' "${override}"
        return 0
    fi

    local -a models
    local -i model_index
    local last_model

    if mapfile -t models < <(swarm_models_catalog); then
        if model_index="$(swarm_model_for_agent "${agent}")"; then
            if ((${#models[@]} == 0)); then
                return 1
            fi

            if (( model_index < ${#models[@]} )); then
                printf '%s\n' "${models[model_index]}"
                return 0
            fi

            last_model="${models[$(( ${#models[@]} - 1 ))]}"
            printf '%s\n' "${last_model}"
            return 0
        fi
    fi

    case "${agent}" in
        triage|coordinator|planner|coder|qa)
            printf '%s\n' "gpt-5.6-sol"
            ;;
        *)
            return 1
            ;;
    esac
}

swarm_agent_role_summary() {
    case "$1" in
        coordinator)
            printf '%s\n' "You are the coordinator. Drive consensus, assign work through the lobby, watch intents and locks, and advise on likely file overlap. Never claim to grant locks; the filesystem remains authoritative."
            ;;
        triage)
            printf '%s\n' "You are the triage agent. Estimate complexity, propose which roles are needed, and suggest likely impacted files before deeper work starts."
            ;;
        planner)
            printf '%s\n' "You are the planner. Produce a concrete implementation plan, likely impacted files, risks, and validation strategy."
            ;;
        coder)
            printf '%s\n' "You are the coder. Collaborate through the lobby, wait for a clear plan when needed, then implement the approved slice while honoring AGENTS.md lock rules."
            ;;
        qa)
            printf '%s\n' "You are the QA agent. Focus on testing, code review, regressions, and validation. Surface risks early and keep findings concrete."
            ;;
        *)
            return 1
            ;;
    esac
}

swarm_render_prompt() {
    local agent="$1"
    local channel="$2"
    local run_id="$3"
    local request_file="$4"
    local root="$5"

    cat <<EOF
Your MYID is ${agent}.

${agent}: $(swarm_agent_role_summary "${agent}")

Collaboration rules:
- Use the collaboration system and check in to channel ${channel} with MYID=${agent}. Use ${channel}, not #${channel}.
- Read ${root}/AGENTS.md and follow its lock, intent, and coordination contract before editing files.
- Use ${root}/collab.cjs and the collab MCP tools for shared coordination when useful.
- Keep filesystem locks authoritative. You may recommend impacted files, but do not claim to grant locks.
- Runtime loop: set_nickname(MYID), set_status(busy) while working, set_status(idle) when pausing or done, then claim_pending() before waiting.
- The current run id is ${run_id}.

Request:
$(cat "${request_file}")
EOF
}

swarm_default_mcp_url() {
    printf '%s\n' "${COLLAB_MCP_URL:-http://127.0.0.1:1337/mcp}"
}

swarm_mcp_url_for_runtime() {
    local runtime="$1"
    local mcp_url="$2"

    if [[ "${runtime}" == "agy" ]]; then
        case "${mcp_url}" in
            */mcp)
                printf '%s/sse\n' "${mcp_url%/mcp}"
                return 0
                ;;
        esac
        if [[ "${mcp_url}" =~ ^https?://[^/]+/?$ ]]; then
            printf '%s/sse\n' "${mcp_url%/}"
            return 0
        fi
    fi
    printf '%s\n' "${mcp_url}"
}

swarm_shell_join() {
    local joined
    printf -v joined '%q ' "$@"
    printf '%s\n' "${joined% }"
}

swarm_json_string() {
    local value="${1:-}"

    value="${value//\\/\\\\}"
    value="${value//\"/\\\"}"
    value="${value//$'\b'/\\b}"
    value="${value//$'\f'/\\f}"
    value="${value//$'\n'/\\n}"
    value="${value//$'\r'/\\r}"
    value="${value//$'\t'/\\t}"
    printf '"%s"' "${value}"
}

swarm_claude_mcp_config() {
    local mcp_url="$1"
    local server_name="${2:-notty_collab_session}"

    printf '{"mcpServers":{%s:{"type":"http","url":%s}}}' \
        "$(swarm_json_string "${server_name}")" \
        "$(swarm_json_string "${mcp_url}")"
}

swarm_agent_bootstrap_prompt() {
    local agent="$1"
    local role="$2"
    local channel="$3"
    local mcp_url="$4"

    local barrier_guidance='Treat a denied action as a boundary. Try safe in-scope alternatives, then report either "Task complete — <evidence>" or "Human help needed — <reason>. Next: <one concrete human action>".'
    local permission_guidance='For approval or sandbox barriers, do not repeat the rejected operation, weaken containment, or broaden your own authority.'
    local unsandboxed="${NOTTY_COLLAB_UNSANDBOXED:-${SWARM_UNSANDBOXED:-${DOCKER_CONTAINER:-}}}"

    if [[ "${unsandboxed,,}" =~ ^(1|true|yes|on)$ ]]; then
        permission_guidance=''
    fi
    cat <<PROMPT
You are the ${role} agent for this tmux session. Use the configured collab MCP service, set your nickname to ${agent}, coordinate in ${channel}, set_status("busy") while working, set_status("idle") when waiting or done, then call claim_pending() whenever you become idle. Follow any returned next steps and report status in lobby. Do not ask for permission for routine local commands like date.
${barrier_guidance}
${permission_guidance}
PROMPT
}

swarm_collect_auth_environment_names() {
    local destination_name="$1"
    local -n destination="${destination_name}"
    local name
    destination=(
        AUTHORIZATION
        HTTP_AUTHORIZATION
        MCP_BEARER_TOKEN
        MCP_TOKEN
        MCP_SPAWN_OTP
        SPAWN_OTP
        COLLAB_AGENT_SPAWN_OTP
        NOTTY_AUTHORIZATION
        NOTTY_AUTH_STATE_DIR
        NOTTY_WORKSPACE_ID
        NOTTY_MCP_AUTHORIZATION
        NOTTY_MCP_BEARER_TOKEN
        NOTTY_MCP_SPAWN_OTP
        NOTTY_MCP_SPAWN_OTP_ENABLED
        NOTTY_MCP_SPAWN_OTP_TTL_SECONDS
        NOTTY_GUARD_MTLS
        NOTTY_GUARD_GATEWAY_PEER_IP
        NOTTY_GUARD_GATEWAY_TOKEN
        NOTTY_GUARD_OTP_MINT_TOKEN
        NOTTY_LOOPBACK_PUBLICATION
        NOTTY_NOAUTH
        NOTTY_NO_OAUTH
        NOTTY_NO_OTP_AUTH
        NOTTY_COPILOT_ACCESS_TOKEN
        NOTTY_COPILOT_MCP_URL
    )

    while IFS= read -r name; do
        case "${name}" in
            NOTTY_BASIC_AUTH_*|NOTTY_OAUTH_*)
                destination+=("${name}")
                ;;
        esac
    done < <(compgen -e)
}

swarm_append_auth_environment_unsets() {
    local destination_name="$1"
    local -n destination="${destination_name}"
    local -a names
    local name

    swarm_collect_auth_environment_names names
    for name in "${names[@]}"; do
        destination+=(-u "${name}")
    done
}

swarm_clear_tmux_auth_environment() {
    local -a sanitized_environment=(env)
    local -a names
    local line
    local name

    swarm_append_auth_environment_unsets sanitized_environment
    if ! "${sanitized_environment[@]}" tmux list-sessions >/dev/null 2>&1; then
        return 0
    fi
    swarm_collect_auth_environment_names names
    while IFS= read -r line; do
        name="${line%%=*}"
        name="${name#-}"
        case "${name}" in
            NOTTY_BASIC_AUTH_*|NOTTY_OAUTH_*)
                names+=("${name}")
                ;;
        esac
    done < <("${sanitized_environment[@]}" tmux show-environment -g 2>/dev/null || true)
    for name in "${names[@]}"; do
        "${sanitized_environment[@]}" tmux set-environment -gu "${name}" \
            >/dev/null 2>&1 || true
    done
}

swarm_register_managed_agent() {
    local root="$1"
    local agent="$2"
    local role="${3:-${agent}}"
    local runtime="${4:-codex}"
    local model="${5:-}"
    local think="${6:-}"
    local harness="${7:-}"
    local backend="${8:-}"
    local -a register_args
    local -a register_environment=(env)

    harness="${harness:-$(swarm_harness_for_runtime "${runtime}")}" || return 1
    backend="${backend:-$(swarm_backend_for_runtime "${runtime}")}" || return 1
    runtime="$(swarm_legacy_runtime_for "${harness}" "${backend}")" || return 1

    register_args=(
        add-agent
        --agent "${agent}"
        --target "${agent}"
        --role "${role}"
        --harness "${harness}"
        --backend "${backend}"
        --runtime "${runtime}"
    )
    if [[ -n "${model}" ]]; then
        register_args+=(--model "${model}")
    fi
    if [[ -n "${think}" ]]; then
        register_args+=(--think "${think}")
    fi

    swarm_append_auth_environment_unsets register_environment
    if ! (
        cd "${root}"
        "${register_environment[@]}" node collab.cjs "${register_args[@]}" >/dev/null 2>&1
    ); then
        printf 'warning: unable to register managed agent %s\n' "${agent}" >&2
        return 1
    fi

    return 0
}

swarm_tmux_session_exists() {
    local session_name="$1"
    tmux has-session -t "${session_name}" 2>/dev/null
}

swarm_launch_canonical_agent() {
    local root="$1"
    local agent="$2"
    local role="$3"
    local harness="${4,,}"
    local backend="${5,,}"
    local model="$6"
    local think="$7"
    local workdir="$8"
    local channel="$9"
    local mcp_url="${10}"
    local mode="${11}"
    local session_id="${12:-}"
    local runtime
    local runtime_bin
    local node_bin="${SWARM_NODE_BIN:-node}"
    local ollama_relay_path="${root}/lib/collab/ollama-codex-relay.cjs"
    local -a command_parts
    local -a ollama_codex_args
    local -a tmux_environment
    local ollama_catalog_config=""
    local provider_arg
    local bootstrap_prompt
    local claude_mcp_config
    local codex_probe_output

    runtime="$(swarm_legacy_runtime_for "${harness}" "${backend}")" || return 1

    case "${harness}/${backend}" in
        codex/default)
            runtime_bin="$(swarm_codex_bin "${root}")" || {
                printf 'unable to locate codex binary\n' >&2
                return 1
            }
            ;;
        agy/default)
            runtime_bin="$(swarm_agy_bin "${root}")" || {
                printf 'unable to locate agy binary\n' >&2
                return 1
            }
            ;;
        claude/default)
            runtime_bin="$(swarm_claude_bin "${root}")" || {
                printf 'unable to locate claude binary\n' >&2
                return 1
            }
            ;;
        codex/ollama)
            runtime_bin="$(swarm_codex_bin "${root}")" || {
                printf 'unable to locate codex binary for Ollama backend\n' >&2
                return 1
            }
            [[ -n "${model}" ]] || {
                printf 'ollama agents require a model\n' >&2
                return 1
            }
            if ! codex_probe_output="$("${runtime_bin}" --version 2>&1)"; then
                printf 'codex is unavailable for Ollama backend: %s\n' \
                    "${codex_probe_output:-version probe failed}" >&2
                return 1
            fi
            ;;
        *)
            printf 'unsupported agent launch target: %s/%s\n' "${harness}" "${backend}" >&2
            return 1
            ;;
    esac
    think="$(swarm_normalize_think "${harness}" "${think}" "${backend}")" || return 1

    if [[ "${mode}" == "resume" && -z "${session_id}" ]]; then
        printf 'resume mode requires a session id\n' >&2
        return 1
    fi

    if swarm_tmux_session_exists "${agent}"; then
        printf 'tmux session already exists: %s\n' "${agent}" >&2
        return 1
    fi
    if [[ "${backend}" == "ollama" ]]; then
        if [[ ! -f "${ollama_relay_path}" ]]; then
            printf 'unable to locate Ollama Codex relay: %s\n' "${ollama_relay_path}" >&2
            return 1
        fi
        swarm_prepare_ollama_codex_args \
            "${root}" "${model}" "${workdir}:${agent}" ollama_codex_args || return 1
        for provider_arg in "${ollama_codex_args[@]}"; do
            if [[ "${provider_arg}" == model_catalog_json=* ]]; then
                ollama_catalog_config="${provider_arg}"
                break
            fi
        done
        if [[ -z "${ollama_catalog_config}" ]]; then
            printf 'Ollama Codex provider helper returned no model catalog\n' >&2
            return 1
        fi
    fi

    command_parts=(env)
    swarm_append_auth_environment_unsets command_parts
    command_parts+=(
        "MYID=${agent}"
        "COLLAB_AGENT_ID=${agent}"
        "COLLAB_CHANNEL=${channel}"
        "COLLAB_MCP_URL=${mcp_url}"
        "COLLAB_ROLE=${role}"
        "COLLAB_HARNESS=${harness}"
        "COLLAB_BACKEND=${backend}"
        "COLLAB_RUNTIME=${runtime}"
        "COLLAB_MODEL=${model}"
        "COLLAB_THINK=${think}"
    )
    if [[ "${backend}" == "ollama" ]]; then
        command_parts+=("${node_bin}" "${ollama_relay_path}" -- "${runtime_bin}")
    else
        command_parts+=("${runtime_bin}")
    fi

    if [[ "${harness}" == "agy" ]]; then
        if [[ "${mode}" == "resume" ]]; then
            [[ -n "${session_id}" ]] || {
                printf 'resume mode requires a session id\n' >&2
                return 1
            }
            command_parts+=(--conversation "${session_id}")
        fi
        if [[ -n "${model}" ]]; then
            command_parts+=(--model "${model}")
        fi
        if [[ -n "${think}" ]]; then
            command_parts+=(--effort "${think}")
        fi
    elif [[ "${harness}" == "claude" ]]; then
        if [[ -n "${model}" ]]; then
            command_parts+=(--model "${model}")
        fi
        if [[ -n "${think}" ]]; then
            command_parts+=(--effort "${think}")
        fi
        claude_mcp_config="$(swarm_claude_mcp_config "${mcp_url}")"
        command_parts+=(--mcp-config "${claude_mcp_config}")
    else
        if [[ "${backend}" == "ollama" ]]; then
            command_parts+=(
                "${ollama_codex_args[@]}"
                -c "mcp_servers.notty_collab_session.url=\"${mcp_url}\""
            )
        elif [[ -n "${model}" ]]; then
            command_parts+=(-m "${model}")
        fi
        if [[ -n "${think}" ]]; then
            command_parts+=(-c "model_reasoning_effort=\"${think}\"")
        fi
    fi

    local unsandboxed=""
    if [[ -v NOTTY_COLLAB_UNSANDBOXED ]]; then
        unsandboxed="${NOTTY_COLLAB_UNSANDBOXED}"
    elif [[ -v SWARM_UNSANDBOXED ]]; then
        unsandboxed="${SWARM_UNSANDBOXED}"
    elif [[ "${harness}" == "codex" ]]; then
        unsandboxed="${DOCKER_CONTAINER:-}"
    fi
    unsandboxed="${unsandboxed,,}"
    if [[ "${unsandboxed}" =~ ^(1|true|yes|on)$ ]]; then
        if [[ "${harness}" == "agy" || "${harness}" == "claude" ]]; then
            command_parts+=(--dangerously-skip-permissions)
        else
            command_parts+=(--dangerously-bypass-approvals-and-sandbox)
        fi
    else
        if [[ "${harness}" == "agy" ]]; then
            command_parts+=(--mode accept-edits --sandbox)
        elif [[ "${harness}" == "claude" ]]; then
            command_parts+=(--permission-mode acceptEdits)
        else
            command_parts+=(--sandbox workspace-write --ask-for-approval on-request)
        fi
    fi

    if [[ "${harness}" == "codex" && "${mode}" == "resume" ]]; then
        [[ -n "${session_id}" ]] || {
            printf 'resume mode requires a session id\n' >&2
            return 1
        }
        command_parts+=(resume "${session_id}")
    fi

    bootstrap_prompt="$(swarm_agent_bootstrap_prompt "${agent}" "${role}" "${channel}" "${mcp_url}")"
    if [[ "${harness}" == "agy" ]]; then
        command_parts+=(--prompt-interactive "${bootstrap_prompt}")
    elif [[ "${harness}" == "claude" ]]; then
        command_parts+=(--name "${agent}")
        if [[ "${mode}" == "resume" ]]; then
            [[ -n "${session_id}" ]] || {
                printf 'resume mode requires a session id\n' >&2
                return 1
            }
            command_parts+=(--resume "${session_id}")
        else
            command_parts+=("${bootstrap_prompt}")
        fi
    else
        command_parts+=("${bootstrap_prompt}")
    fi

    tmux_environment=(env)
    swarm_append_auth_environment_unsets tmux_environment
    swarm_clear_tmux_auth_environment
    if ! "${tmux_environment[@]}" tmux -u new-session -d -c "${workdir}" -s "${agent}" \
        "$(swarm_shell_join "${command_parts[@]}")"; then
        if [[ "${backend}" == "ollama" ]] && ! swarm_tmux_session_exists "${agent}"; then
            swarm_remove_ollama_codex_catalog \
                "${root}" "${ollama_catalog_config}" || true
        fi
        return 1
    fi

    sleep "${SWARM_STARTUP_PROBE_DELAY:-0.2}"
    if ! swarm_tmux_session_exists "${agent}"; then
        printf 'agent process exited during startup: %s (check %s arguments and configuration)\n' "${agent}" "${runtime}" >&2
        return 1
    fi

    swarm_register_managed_agent \
        "${root}" "${agent}" "${role}" "${runtime}" "${model}" "${think}" \
        "${harness}" "${backend}" || true

    return 0
}

swarm_launch_agent() {
    local root="$1"
    local agent="$2"
    local role="$3"
    local runtime="${4,,}"
    local model="$5"
    local think="$6"
    local workdir="$7"
    local channel="$8"
    local mcp_url="$9"
    local mode="${10}"
    local session_id="${11:-}"
    local harness
    local backend

    harness="$(swarm_harness_for_runtime "${runtime}")" || return 1
    backend="$(swarm_backend_for_runtime "${runtime}")" || return 1
    swarm_launch_canonical_agent \
        "${root}" "${agent}" "${role}" "${harness}" "${backend}" \
        "${model}" "${think}" "${workdir}" "${channel}" "${mcp_url}" \
        "${mode}" "${session_id}"
}

swarm_launch_codex_agent() {
    local root="$1"
    local agent="$2"
    local role="$3"
    local workdir="$4"
    local channel="$5"
    local mcp_url="$6"
    local mode="$7"
    local session_id="${8:-}"

    swarm_launch_agent \
        "${root}" "${agent}" "${role}" codex '' '' \
        "${workdir}" "${channel}" "${mcp_url}" "${mode}" "${session_id}"
}
