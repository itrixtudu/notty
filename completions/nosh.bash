# Bash completion for Nosh.
#
# Load for the current shell with:
#   source <(nosh completion bash)

_nosh_completion_add_words() {
  local current="$1"
  local words="$2"
  local prefix="${3:-}"
  local candidate

  while IFS= read -r candidate; do
    if [[ -n "$candidate" ]]; then
      COMPREPLY+=("${prefix}${candidate}")
    fi
  done < <(compgen -W "$words" -- "$current")
}

_nosh_completion_add_paths() {
  local current="$1"
  local kind="$2"
  local prefix="${3:-}"
  local preserved_prefix="${4:-}"
  local candidate
  local completion
  local has_directory="false"

  if [[ "$kind" == "directory" ]]; then
    while IFS= read -r candidate; do
      completion="$candidate"
      if [[ -d "$candidate" ]]; then
        completion="${candidate%/}/"
        has_directory="true"
      fi
      if [[ -n "$preserved_prefix" && "$completion" == "$preserved_prefix"* ]]; then
        completion="${completion#"$preserved_prefix"}"
      fi
      COMPREPLY+=("${prefix}${completion}")
    done < <(compgen -d -- "$current")
  else
    while IFS= read -r candidate; do
      completion="$candidate"
      if [[ -d "$candidate" ]]; then
        completion="${candidate%/}/"
        has_directory="true"
      fi
      if [[ -n "$preserved_prefix" && "$completion" == "$preserved_prefix"* ]]; then
        completion="${completion#"$preserved_prefix"}"
      fi
      COMPREPLY+=("${prefix}${completion}")
    done < <(compgen -f -- "$current")
  fi

  compopt -o filenames 2>/dev/null || true
  if [[ "$kind" == "directory" || "$has_directory" == "true" ]]; then
    compopt -o nospace 2>/dev/null || true
  fi
}

_nosh_completion_profile_candidates() {
  local config
  local user_config=""

  printf '%s\n' \
    codex \
    gemini \
    antigravity \
    claude \
    claud \
    agents \
    durdraw \
    zig \
    arduino \
    node-modules \
    tty-usb

  if [[ -n "${HOME:-}" ]]; then
    user_config="$HOME/.config/nosh/nosh.mounts.json"
  fi

  for config in "$PWD/nosh.mounts.json" "$user_config"; do
    if [[ -z "$config" || ! -r "$config" ]]; then
      continue
    fi

    if command -v jq >/dev/null 2>&1; then
      command jq -r '(.profiles // {}) | keys[]' "$config" 2>/dev/null || true
    elif command -v python3 >/dev/null 2>&1; then
      command python3 -c \
        'import json, sys; print(*(json.load(open(sys.argv[1], encoding="utf-8")).get("profiles") or {}).keys(), sep="\n")' \
        "$config" 2>/dev/null || true
    fi
  done
}

_nosh_completion_add_profiles() {
  local current="$1"
  local word_prefix="${2:-}"
  local list_prefix=""
  local fragment="$current"
  local selected=""
  local seen=$'\n'
  local candidate

  if [[ "$current" == *,* ]]; then
    list_prefix="${current%,*},"
    fragment="${current##*,}"
    selected=",${list_prefix%,},"
  fi

  while IFS= read -r candidate; do
    # Readline inserts non-filename candidates without shell quoting. Limit
    # config-provided names to the conventional Nosh profile alphabet so an
    # untrusted checkout cannot inject shell syntax through tab completion.
    if [[ ! "$candidate" =~ ^[A-Za-z0-9_.-]+$ ]]; then
      continue
    fi
    if [[ "$candidate" != "$fragment"* || "$selected" == *",$candidate,"* ]]; then
      continue
    fi
    if [[ "$seen" == *$'\n'"$candidate"$'\n'* ]]; then
      continue
    fi
    seen+="${candidate}"$'\n'
    COMPREPLY+=("${word_prefix}${list_prefix}${candidate}")
  done < <(_nosh_completion_profile_candidates)

  # Profiles are comma-separated, so do not close the argument with a space.
  compopt -o nospace 2>/dev/null || true
}

_nosh_completion_accepts_equals() {
  case "$1" in
    --scope|--tool-mode|--allow-mcp-tool|--workload|--agents|--codex-home|--agent-skills|--agent-settings|--agent-plugins|--agent-baseline|--profile|--config|--network|--security-mode|--security-profile-dir|\
      --image|--name|--otp|--workdir|--guard-prefix|--publish|--revision|--reviewer|\
      --file|--variant|--tag|--target|--platform|--build-arg|--cache-mode|\
      --depth|--http-capture|--duration|--output|--run|--bundle|--baseline|--base-policy|\
      --baseline-override-reason|--sbom-source|--sbom-image|--port|--origin|\
      --decisions|--policy|--key|--confirmation|--context|--approval|\
      --review-key|--review-audience|--deployment-key|--audience|\
      --target-binding-digest|--active-grant-set-digest|--ttl-seconds|--trust|\
      --grant)
      return 0
      ;;
    *)
      return 1
      ;;
  esac
}

_nosh_completion_docker() {
  local commands="tools init uninstall start attach stop rm recreate net build review policy gateway auth set-login-password completion"
  local options="--tool-mode --allow-mcp-tool --workload --agents --codex-home --agent-skills --agent-settings --agent-plugins --detach -p --profile --profile-list --collab --no-collab --config --persist --image --name --publish -P --network --security-mode --security-profile-dir --otp --workdir --start-app --no-start-app --dry-run --noauth --no-oauth --no-otp-auth --no-otp -h --help"
  local init_options="--review --policy-digest --workload --agents --codex-home --agent-baseline --workdir --image --guard-prefix --dry-run --check --advanced --step --help"
  local uninstall_options="--user-only --guard --purge-config --purge-state --dry-run --yes -h --help"
  local auth_commands="otp reset"
  local auth_options="--image --workdir --dry-run -h --help"
  local auth_reset_options="$auth_options --secure"
  local net_commands="learn audit approve enforce status"
  local net_launch_options="--tool-mode --workload --agents --codex-home --agent-skills --agent-settings --agent-plugins -p --profile --collab --no-collab --config --image --name --workdir --start-app --no-start-app --dry-run -h --help"
  local net_learn_options="$net_launch_options --agent-baseline --duration --json"
  local net_approve_options="--workload --revision --reviewer --yes --workdir --dry-run -h --help"
  local net_enforce_options="$net_launch_options --revision"
  local net_status_options="--workload --json --repair --workdir --dry-run -h --help"
  local build_commands="profile status net"
  local build_profile_options="--file --variant --tag --target --platform --build-arg --cache-mode --depth --push --output --no-load --private-json --dry-run -h --help"
  local build_status_options="--run --json --dry-run -h --help"
  local build_net_commands="learn status"
  local build_net_learn_options="--file --variant --tag --target --platform --build-arg --push --output --no-load --http-capture --json --private-json --dry-run -h --help"
  local build_net_status_options="--json --dry-run -h --help"
  local review_commands="bundle inspect serve keygen approve sbom"
  local review_bundle_options="--profile --output --baseline --base-policy --baseline-override-reason --sbom-source --sbom-image --allow-missing-sbom -h --help"
  local review_inspect_options="--bundle --json -h --help"
  local review_serve_options="--bundle --port --origin -h --help"
  local review_keygen_options="--output -h --help"
  local review_approve_options="--bundle --decisions --policy --reviewer --audience --key --confirmation --output -h --help"
  local review_sbom_options="--context --image --output -h --help"
  local policy_commands="project"
  local policy_project_options="--bundle --decisions --target --context --output -h --help"
  local gateway_commands="grant"
  local gateway_grant_options="--policy --approval --review-key --review-audience --deployment-key --audience --target-binding-digest --active-grant-set-digest --ttl-seconds --output -h --help"
  local current="${COMP_WORDS[COMP_CWORD]:-}"
  local previous=""
  local word_prefix=""
  local preserved_path_prefix=""
  local recovered_option=""
  local recovered_value=""
  local recovery_index
  local recovery_part
  local recovery_part_index
  local recovery_saw_separator
  local build_index

  COMPREPLY=()

  if ((COMP_CWORD > 0)); then
    previous="${COMP_WORDS[COMP_CWORD - 1]}"
  fi

  # Bash may either retain '=' in the current word or split it according to
  # COMP_WORDBREAKS. Normalize both representations.
  if [[ "$current" == --*=* ]] \
    && _nosh_completion_accepts_equals "${current%%=*}"; then
    previous="${current%%=*}"
    word_prefix="${previous}="
    current="${current#*=}"
  elif [[ "$previous" == "=" && $COMP_CWORD -gt 1 ]]; then
    if _nosh_completion_accepts_equals "${COMP_WORDS[COMP_CWORD - 2]}"; then
      previous="${COMP_WORDS[COMP_CWORD - 2]}"
    fi
  elif [[ "$current" == "=" && $COMP_CWORD -gt 0 ]]; then
    if _nosh_completion_accepts_equals "${COMP_WORDS[COMP_CWORD - 1]}"; then
      previous="${COMP_WORDS[COMP_CWORD - 1]}"
      current=""
    fi
  fi

  # '@' and ':' are word breaks in a default Bash session, so paths containing
  # them arrive as several COMP_WORDS entries. Reassemble a filesystem value
  # from the nearest path option, then remove the prefix Readline will preserve
  # when applying COMPREPLY.
  case "$previous" in
    -*)
      ;;
    *)
      for ((recovery_index = COMP_CWORD - 1; recovery_index > 0; recovery_index--)); do
        recovery_part="${COMP_WORDS[recovery_index]}"
        case "$recovery_part" in
          --config|--security-profile-dir|--workdir|--guard-prefix|--file|--bundle|--baseline|--base-policy|\
          --sbom-source|--sbom-image|--decisions|--policy|--key|--context|\
          --approval|--review-key|--deployment-key|--trust|--grant|--output)
            recovered_option="$recovery_part"
            recovered_value=""
            ;;
          --config=*|--security-profile-dir=*|--workdir=*|--guard-prefix=*|--file=*|--bundle=*|\
          --baseline=*|--base-policy=*|--sbom-source=*|--sbom-image=*|--decisions=*|--policy=*|\
          --key=*|--context=*|--approval=*|--review-key=*|--deployment-key=*|\
          --trust=*|--grant=*|--output=*)
            recovered_option="${recovery_part%%=*}"
            recovered_value="${recovery_part#*=}"
            ;;
          -*)
            break
            ;;
          *)
            continue
            ;;
        esac

        recovery_saw_separator="false"
        for ((recovery_part_index = recovery_index + 1;
          recovery_part_index <= COMP_CWORD;
          recovery_part_index++)); do
          recovery_part="${COMP_WORDS[recovery_part_index]}"
          recovered_value+="$recovery_part"
          if [[ "$recovery_part" =~ ^[@:=]+$ ]]; then
            recovery_saw_separator="true"
          fi
        done
        recovered_value="${recovered_value#=}"

        if [[ "$recovery_saw_separator" == "true" \
          && "$recovered_value" == *"$current" ]]; then
          preserved_path_prefix="${recovered_value%"$current"}"
          # Readline preserves ':' when replacing a completion fragment, but
          # replaces '@' itself. Keep a trailing '@' in the returned candidate.
          if [[ "$preserved_path_prefix" == *@ ]]; then
            preserved_path_prefix="${preserved_path_prefix%@}"
          fi
          previous="$recovered_option"
          current="$recovered_value"
          word_prefix=""
        fi
        break
      done
      ;;
  esac

  case "$previous" in
    --scope) _nosh_completion_add_words "$current" "repo directory all" "$word_prefix"; return ;;
    --tool-mode) _nosh_completion_add_words "$current" "read-only implementation" "$word_prefix"; return ;;
    --workload) _nosh_completion_add_words "$current" "dev run" "$word_prefix"; return ;;
    --agents) _nosh_completion_add_words "$current" "auto none codex claude gemini codex,claude,gemini" "$word_prefix"; return ;;
    --agent-skills|--agent-settings|--agent-plugins) _nosh_completion_add_words "$current" "ro rw" "$word_prefix"; return ;;
    --codex-home) _nosh_completion_add_paths "$current" directory "$word_prefix" "$preserved_path_prefix"; return ;;
    --agent-baseline) _nosh_completion_add_paths "$current" file "$word_prefix" "$preserved_path_prefix"; return ;;
  esac
  if [[ "${COMP_WORDS[1]:-}" == tools ]]; then
    if ((COMP_CWORD == 2)); then
      _nosh_completion_add_words "$current" "init review check apply status rollback doctor help"
    elif [[ "$previous" == --output-dir || "$previous" == --review || "$previous" == --workdir || "$previous" == --guard-prefix ]]; then
      _nosh_completion_add_paths "$current" directory "$word_prefix" "$preserved_path_prefix"
    elif [[ -z "$current" || "$current" == -* ]]; then
      if [[ "${COMP_WORDS[2]:-}" == init ]]; then
        _nosh_completion_add_words "$current" "--scope --codex-home --output-dir --no-prompt --request-details --workdir --help"
      elif [[ "${COMP_WORDS[2]:-}" == review ]]; then
        _nosh_completion_add_words "$current" "--review --build-ui --no-browser --workdir --help"
      else
        _nosh_completion_add_words "$current" "--review --workdir --guard-prefix --policy-digest --revision --container --json --help"
      fi
    fi
    return
  fi
  if [[ "${COMP_WORDS[1]:-}" == "init" ]]; then
    case "$previous" in
      --step)
        _nosh_completion_add_words "$current" "install setup build preflight network learn review signing apply status tools-review tools-check tools-apply tools-status tools-init"
        ;;
      --workdir)
        _nosh_completion_add_paths \
          "$current" directory "$word_prefix" "$preserved_path_prefix"
        ;;
      --guard-prefix)
        current="${current:-/}"
        if [[ "$current" == /* ]]; then
          _nosh_completion_add_paths \
            "$current" directory "$word_prefix" "$preserved_path_prefix"
        fi
        ;;
      --image)
        ;;
      *)
        if [[ -z "$current" || "$current" == -* ]]; then
          _nosh_completion_add_words "$current" "$init_options"
        fi
        ;;
    esac
    return
  fi

  if [[ "${COMP_WORDS[1]:-}" == "uninstall" ]]; then
    _nosh_completion_add_words "$current" "$uninstall_options"
    return
  fi

  if [[ "${COMP_WORDS[1]:-}" == "build" ]]; then
    for ((build_index = 2; build_index < COMP_CWORD; build_index++)); do
      if [[ "${COMP_WORDS[build_index]}" == "--" ]]; then
        return
      fi
    done
  fi

  case "$previous" in
    -p|--profile)
      if [[ "${COMP_WORDS[1]:-}" == "review" ]]; then
        _nosh_completion_add_paths \
          "$current" directory "$word_prefix" "$preserved_path_prefix"
      else
        _nosh_completion_add_profiles "$current" "$word_prefix"
      fi
      return
      ;;
    --security-mode)
      _nosh_completion_add_words \
        "$current" \
        "legacy learn audit enforce" \
        "$word_prefix"
      return
      ;;
    --config)
      _nosh_completion_add_paths \
        "$current" file "$word_prefix" "$preserved_path_prefix"
      return
      ;;
    --file)
      _nosh_completion_add_paths \
        "$current" file "$word_prefix" "$preserved_path_prefix"
      return
      ;;
    --security-profile-dir|--workdir)
      _nosh_completion_add_paths \
        "$current" directory "$word_prefix" "$preserved_path_prefix"
      return
      ;;
    --bundle|--baseline|--base-policy|--sbom-source|--sbom-image|--decisions|--policy|--key|\
    --context|--approval|--review-key|--deployment-key|--trust|--grant)
      _nosh_completion_add_paths \
        "$current" file "$word_prefix" "$preserved_path_prefix"
      return
      ;;
    --output)
      if [[ "${COMP_WORDS[1]:-}" == "review" \
        || "${COMP_WORDS[1]:-}" == "policy" \
        || "${COMP_WORDS[1]:-}" == "gateway" ]]; then
        _nosh_completion_add_paths \
          "$current" file "$word_prefix" "$preserved_path_prefix"
      fi
      return
      ;;
    --target)
      if [[ "${COMP_WORDS[1]:-}" == "policy" ]]; then
        _nosh_completion_add_words \
          "$current" "cilium guard-ebpf guard-nftables gateway-iptables gateway-pf gateway-ipfw gateway-ipfilter gateway-l7-proxy" "$word_prefix"
      fi
      return
      ;;
    --cache-mode)
      _nosh_completion_add_words "$current" "compare cold warm" "$word_prefix"
      return
      ;;
    --depth)
      _nosh_completion_add_words "$current" "balanced policy deep" "$word_prefix"
      return
      ;;
    --http-capture)
      _nosh_completion_add_words "$current" "none mitmproxy" "$word_prefix"
      return
      ;;
    --image|--name|--network|--otp|--publish|-P|--revision|--reviewer|--duration|\
      --variant|--tag|--platform|--build-arg|--http-capture|--run|--port|--origin|\
      --baseline-override-reason|--decisions|--policy|--key|--confirmation|\
      --context|--approval|--review-key|--review-audience|--deployment-key|\
      --audience|--target-binding-digest|--active-grant-set-digest|\
      --ttl-seconds|--trust|--grant)
      return
      ;;
  esac

  if [[ "${COMP_WORDS[1]:-}" == "completion" ]]; then
    if ((COMP_CWORD == 2)); then
      _nosh_completion_add_words "$current" "bash"
    fi
    return
  fi

  if [[ "${COMP_WORDS[1]:-}" == "auth" ]]; then
    if ((COMP_CWORD == 2)); then
      _nosh_completion_add_words "$current" "$auth_commands -h --help"
      return
    fi
    if [[ ( -z "$current" || "$current" == -* ) ]]; then
      if [[ "${COMP_WORDS[2]:-}" == "reset" ]]; then
        _nosh_completion_add_words "$current" "$auth_reset_options"
      elif [[ "${COMP_WORDS[2]:-}" == "otp" ]]; then
        _nosh_completion_add_words "$current" "$auth_options"
      fi
    fi
    return
  fi

  if [[ "${COMP_WORDS[1]:-}" == "net" ]]; then
    if ((COMP_CWORD == 2)); then
      _nosh_completion_add_words "$current" "$net_commands -h --help"
      return
    fi
    if [[ -z "$current" || "$current" == -* ]]; then
      case "${COMP_WORDS[2]:-}" in
        learn)
          _nosh_completion_add_words "$current" "$net_learn_options"
          ;;
        audit)
          _nosh_completion_add_words "$current" "$net_launch_options"
          ;;
        approve)
          _nosh_completion_add_words "$current" "$net_approve_options"
          ;;
        enforce)
          _nosh_completion_add_words "$current" "$net_enforce_options"
          ;;
        status)
          _nosh_completion_add_words "$current" "$net_status_options"
          ;;
      esac
    fi
    return
  fi

  if [[ "${COMP_WORDS[1]:-}" == "build" ]]; then
    if ((COMP_CWORD == 2)); then
      _nosh_completion_add_words "$current" "$build_commands -h --help"
      return
    fi

    if [[ "${COMP_WORDS[2]:-}" == "net" ]]; then
      if ((COMP_CWORD == 3)); then
        _nosh_completion_add_words "$current" "$build_net_commands -h --help"
        return
      fi
      if [[ -z "$current" || "$current" == -* ]]; then
        case "${COMP_WORDS[3]:-}" in
          learn)
            _nosh_completion_add_words "$current" "$build_net_learn_options"
            ;;
          status)
            _nosh_completion_add_words "$current" "$build_net_status_options"
            ;;
        esac
      else
        case "${COMP_WORDS[3]:-}" in
          learn|status)
            _nosh_completion_add_paths "$current" directory
            ;;
        esac
      fi
      return
    fi

    if [[ -z "$current" || "$current" == -* ]]; then
      case "${COMP_WORDS[2]:-}" in
        profile)
          _nosh_completion_add_words "$current" "$build_profile_options"
          ;;
        status)
          _nosh_completion_add_words "$current" "$build_status_options"
          ;;
      esac
    else
      case "${COMP_WORDS[2]:-}" in
        profile|status)
          _nosh_completion_add_paths "$current" directory
          ;;
      esac
    fi
    return
  fi

  if [[ "${COMP_WORDS[1]:-}" == "review" ]]; then
    if ((COMP_CWORD == 2)); then
      _nosh_completion_add_words "$current" "$review_commands -h --help"
      return
    fi
    if [[ -z "$current" || "$current" == -* ]]; then
      case "${COMP_WORDS[2]:-}" in
        bundle) _nosh_completion_add_words "$current" "$review_bundle_options" ;;
        inspect) _nosh_completion_add_words "$current" "$review_inspect_options" ;;
        serve) _nosh_completion_add_words "$current" "$review_serve_options" ;;
        keygen) _nosh_completion_add_words "$current" "$review_keygen_options" ;;
        approve) _nosh_completion_add_words "$current" "$review_approve_options" ;;
        sbom) _nosh_completion_add_words "$current" "$review_sbom_options" ;;
      esac
    fi
    return
  fi

  if [[ "${COMP_WORDS[1]:-}" == "policy" ]]; then
    if ((COMP_CWORD == 2)); then
      _nosh_completion_add_words "$current" "$policy_commands -h --help"
      return
    fi
    if [[ "${COMP_WORDS[2]:-}" == "project" \
      && ( -z "$current" || "$current" == -* ) ]]; then
      _nosh_completion_add_words "$current" "$policy_project_options"
    fi
    return
  fi

  if [[ "${COMP_WORDS[1]:-}" == "gateway" ]]; then
    if ((COMP_CWORD == 2)); then
      _nosh_completion_add_words "$current" "$gateway_commands -h --help"
      return
    fi
    if [[ "${COMP_WORDS[2]:-}" == "grant" \
      && ( -z "$current" || "$current" == -* ) ]]; then
      _nosh_completion_add_words "$current" "$gateway_grant_options"
    fi
    return
  fi

  if ((COMP_CWORD == 1)); then
    _nosh_completion_add_words "$current" "$commands $options"
    return
  fi

  if [[ -z "$current" || "$current" == -* ]]; then
    _nosh_completion_add_words "$current" "$options"
  fi
}

_nosh_completion() {
  local -a COMP_WORDS=("${COMP_WORDS[@]}")
  local COMP_CWORD="$COMP_CWORD"
  local backend="" selected current previous
  COMPREPLY=()
  while ((COMP_CWORD > 1)); do
    case "${COMP_WORDS[1]}" in
      --docker|--qemu|--bwrap)
        selected="${COMP_WORDS[1]#--}"
        [[ -z "$backend" || "$backend" == "$selected" ]] || return 0
        backend="$selected"
        COMP_WORDS=("${COMP_WORDS[0]}" "${COMP_WORDS[@]:2}")
        COMP_CWORD=$((COMP_CWORD - 1))
        ;;
      *) break ;;
    esac
  done
  current="${COMP_WORDS[COMP_CWORD]:-}"
  previous="${COMP_WORDS[COMP_CWORD - 1]:-}"
  case "$backend" in
    bwrap) return 0 ;;
    qemu)
      case "$previous" in
        --accel) _nosh_completion_add_words "$current" 'kvm tcg' ;;
        --agents) _nosh_completion_add_words "$current" 'codex' ;;
        --agent-skills|--agent-settings|--agent-plugins)
          _nosh_completion_add_words "$current" 'ro rw' ;;
        --workdir|--codex-home|--state-dir)
          _nosh_completion_add_paths "$current" directory ;;
        --name|--cpus|--memory-mib|--disk-gib|--boot-timeout|--timeout) ;;
        *)
          if ((COMP_CWORD == 1)); then
            _nosh_completion_add_words "$current" 'start attach stop status reset'
          fi
          if [[ -z "$current" || "$current" == -* ]]; then
            _nosh_completion_add_words "$current" '--name --detach --workdir --codex-home --agents --agent-skills --agent-settings --agent-plugins --accel --cpus --memory-mib --disk-gib --boot-timeout --timeout --state-dir -h --help'
          fi
          ;;
      esac
      ;;
    *)
      _nosh_completion_docker
      if [[ -z "$backend" ]] && ((COMP_CWORD == 1)); then
        _nosh_completion_add_words "$current" '--docker --qemu --bwrap'
      fi
      ;;
  esac
}

complete -F _nosh_completion nosh nosh.sh
