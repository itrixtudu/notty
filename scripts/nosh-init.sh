#!/usr/bin/env bash
# Interactive host driver; all builds and policy tooling stay in containers.
set -uo pipefail
umask 077

REPO=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)
WORKSPACE=$PWD
WORKLOAD=dev
AGENT_SELECTION=auto
CODEX_HOME_OPTION=${CODEX_HOME:-}
CODEX_HOME_EXPLICIT=false
AGENT_BASELINES=()
GUARD_PREFIX=/opt/notty
GUARD_RECEIPT=/etc/nosh-guard-install-layout.conf
INSTALLED_GUARD_PREFIX=''
IMAGE=''
STEP=''
TOOL_REPORT=''
TOOL_DIGEST=''
DRY_RUN=false
CHECK_ONLY=false
ADVANCED=false
CLASSIC=false
TUI_CONFIRMED=false
START_APP_OPTION=''
REVIEW_POOL=''
REVIEW_EXCLUSIONS=()
AUTHORITATIVE_STATUS=''
ANSWER=''
DETECTED_REVIEW_PATHS=()
DETECTED_REVIEW_DIGESTS=()
DETECTED_REVISION=''
APPROVED_REVISION=''
APPLY_RESULT=''
LAST_COMMAND_EXECUTED=false

usage() {
  cat <<'EOF'
Usage: nosh init [--dry-run] [--step STEP] [options]

Terminal wizard: install → setup → build → learn → review → apply.
Run as your normal Docker-authorized host user. Commands retain their terminal.
Local readiness checks are automatic. Builds, downloads, sudo and policy changes ask first.

Steps: install, setup, build, preflight, network, readiness, tooling, inventory, learn, prepare, review, signing, apply, status, tools-init, tools-review, tools-check, tools-apply, tools-status
Options:
  --review PATH        Saved tool audit directory for tools steps
  --policy-digest HASH Reviewed environment policy digest for tools-apply
  --workdir PATH       Checked-out repository/workspace (default: current directory)
  --workload dev|run   Runtime workload (default: dev)
  --start-app          Start the bundled application during runtime recording
  --no-start-app       Record without starting the bundled application
  --review-pool CIDR   Configure this review network pool with host overlap checks
  --exclude CIDR       Additional LAN/VPN network to exclude; repeatable
  --agents auto|none|NAMES  Dev agent homes (default: auto)
  --codex-home PATH    Custom Codex home, passed explicitly through sudo
  --agent-baseline FILE@sha256:DIGEST  Pinned dev baseline; repeatable
  --image REF          Existing local image tag or exact sha256 ID
  --guard-prefix PATH Guard installation prefix (default: /opt/notty)
  --dry-run           Print commands without executing them or creating files
  --check             Show read-only completion hints and suggested next step
  --advanced          Show the numbered menu instead of the guided setup cycle
  --classic           Use the original guided prompts instead of the host TUI
  --step STEP         Run one selected step instead of the menu
  -h, --help          Show help

Initialization stops after policy application; use nosh start to launch or attach.
Learning may run temporary containers during profiling.
No repository cloning or automatic policy approval.
Signing setup requires explicit confirmation before key generation and trust installation.
EOF
}

fail() { printf 'nosh init: %s\n' "$*" >&2; return 1; }
safe_text() { [[ -n $1 && ! $1 =~ [[:cntrl:]] ]]; }
ask() {
  local prompt=$1 default=${2:-}
  printf '%s' "$prompt"
  [[ -z $default ]] || printf ' [%s]' "$default"
  printf ': '
  IFS= read -r ANSWER || return 1
  ANSWER=${ANSWER:-$default}
}

read_guard_install_prefix() {
  local metadata owner mode links line key value schema_version='' manifest_digest=''
  local line_number=0
  local -A seen=()

  INSTALLED_GUARD_PREFIX=''
  [[ -e $GUARD_RECEIPT || -L $GUARD_RECEIPT ]] || return 0
  [[ -f $GUARD_RECEIPT && ! -L $GUARD_RECEIPT ]] \
    || { fail "unsafe Guard installation receipt: $GUARD_RECEIPT"; return 1; }
  metadata=$(stat -Lc '%u %a %h' -- "$GUARD_RECEIPT" 2>/dev/null) \
    || { fail "cannot inspect Guard installation receipt: $GUARD_RECEIPT"; return 1; }
  read -r owner mode links <<< "$metadata"
  [[ $owner == 0 && $mode == 644 && $links == 1 ]] \
    || { fail "unsafe Guard installation receipt owner, mode, or link count: $GUARD_RECEIPT"; return 1; }
  while IFS= read -r line || [[ -n $line ]]; do
    ((line_number += 1))
    [[ -n $line && $line == *=* && $line != *$'\r'* ]] \
      || { fail "malformed Guard installation receipt at line $line_number"; return 1; }
    key=${line%%=*}
    value=${line#*=}
    case $key in
      SCHEMA_VERSION|NOSH_GUARD_PREFIX|MANIFEST_SHA256) ;;
      *) fail "unknown Guard installation receipt key: $key"; return 1 ;;
    esac
    [[ ! -v "seen[$key]" ]] \
      || { fail "duplicate Guard installation receipt key: $key"; return 1; }
    seen["$key"]=1
    case $key in
      SCHEMA_VERSION) schema_version=$value ;;
      NOSH_GUARD_PREFIX) INSTALLED_GUARD_PREFIX=$value ;;
      MANIFEST_SHA256) manifest_digest=$value ;;
    esac
  done < "$GUARD_RECEIPT"
  for key in SCHEMA_VERSION NOSH_GUARD_PREFIX MANIFEST_SHA256; do
    [[ -v "seen[$key]" ]] \
      || { fail "missing Guard installation receipt key: $key"; return 1; }
  done
  [[ $schema_version == 1 ]] \
    || { fail "unsupported Guard installation receipt schema: $schema_version"; return 1; }
  [[ $INSTALLED_GUARD_PREFIX =~ ^/[a-zA-Z0-9._+-]+(/[a-zA-Z0-9._+-]+)*$ \
    && /$INSTALLED_GUARD_PREFIX/ != */../* && /$INSTALLED_GUARD_PREFIX/ != */./* ]] \
    || { fail 'Guard installation receipt contains an unsafe prefix'; return 1; }
  [[ $manifest_digest =~ ^[a-f0-9]{64}$ ]] \
    || { fail 'Guard installation receipt contains an invalid manifest digest'; return 1; }
}

prepare_guard_prefix_migration() {
  local installer
  local -a uninstall_args=(uninstall)

  read_guard_install_prefix || return 1
  [[ -n $INSTALLED_GUARD_PREFIX && $INSTALLED_GUARD_PREFIX != "$GUARD_PREFIX" ]] || return 0
  installer=$INSTALLED_GUARD_PREFIX/lib/notty/nosh-guard/current/install.sh
  printf 'Guard is installed under %s, but setup requested %s.\n' \
    "$INSTALLED_GUARD_PREFIX" "$GUARD_PREFIX"
  printf 'Migrating prefixes requires uninstalling the existing Guard first.\n'
  ask 'Uninstall the existing Guard and migrate? y/N' || return 1
  [[ $ANSWER == y || $ANSWER == Y ]] || return 2
  ask 'Purge bundle-managed Guard configuration? y/N' || return 1
  [[ $ANSWER != y && $ANSWER != Y ]] || uninstall_args+=(--purge-config)
  printf 'Guard evidence and state may be needed for audits or recovery.\n'
  ask 'Permanently purge all Guard evidence and state? y/N' || return 1
  [[ $ANSWER != y && $ANSWER != Y ]] || uninstall_args+=(--purge-state)
  [[ -f $installer && ! -L $installer ]] \
    || { fail "installed Guard uninstaller not found: $installer"; return 1; }
  uninstall_args+=(--prefix "$INSTALLED_GUARD_PREFIX")
  run_command sudo "$installer" "${uninstall_args[@]}"
}

run_command() {
  LAST_COMMAND_EXECUTED=false
  printf '\n  '
  printf '%q ' "$@"
  printf '\n'
  [[ $DRY_RUN == false ]] || return 0
  if [[ $TUI_CONFIRMED == false ]]; then
    ask 'Run this command? y/N' || return 1
    [[ $ANSWER == y || $ANSWER == Y ]] || { printf 'Skipped.\n'; return 2; }
  fi
  local result=0
  LAST_COMMAND_EXECUTED=true
  "$@" || result=$?
  if ((result != 0)); then
    printf 'Command exited with status %s. Check the result below before retrying.\n' "$result" >&2
  fi
  return "$result"
}

while (($#)); do
  case $1 in
    --help|-h) usage; exit 0 ;;
    --dry-run) DRY_RUN=true; shift ;;
    --check) CHECK_ONLY=true; shift ;;
    --advanced) ADVANCED=true; shift ;;
    --classic) CLASSIC=true; shift ;;
    --tui-confirmed) TUI_CONFIRMED=true; shift ;;
    --start-app|--no-start-app) START_APP_OPTION=$1; shift ;;
    --step=*|--workdir=*|--image=*|--guard-prefix=*|--workload=*|--agents=*|--codex-home=*|--agent-baseline=*|--review=*|--policy-digest=*|--review-pool=*|--exclude=*)
      option=${1%%=*}
      value=${1#*=}
      shift
      set -- "$option" "$value" "$@"
      ;;
    --step|--workdir|--image|--guard-prefix|--workload|--agents|--codex-home|--agent-baseline|--review|--policy-digest|--review-pool|--exclude)
      [[ $# -ge 2 ]] || { fail "$1 requires a value"; exit 2; }
      safe_text "$2" && [[ $2 != -* ]] || { fail "$1 requires nonempty text without control characters"; exit 2; }
      case $1 in
        --review) TOOL_REPORT=$2 ;;
        --review-pool) REVIEW_POOL=$2 ;;
        --exclude) REVIEW_EXCLUSIONS+=("$2") ;;
        --policy-digest) TOOL_DIGEST=$2 ;;
        --workload) WORKLOAD=$2 ;;
        --agents) AGENT_SELECTION=$2 ;;
        --codex-home) CODEX_HOME_OPTION=$2; CODEX_HOME_EXPLICIT=true ;;
        --agent-baseline) AGENT_BASELINES+=("$2") ;;
        --step) STEP=$2 ;;
        --workdir) WORKSPACE=$2 ;;
        --image) IMAGE=$2 ;;
        --guard-prefix) GUARD_PREFIX=$2 ;;
      esac
      shift 2 ;;
    *) fail "unknown option: $1"; exit 2 ;;
  esac
done

case "$WORKLOAD" in dev|run) ;; *) fail 'invalid workload'; exit 2 ;; esac
[[ "$WORKLOAD" == dev || ( "$CODEX_HOME_EXPLICIT" == false && ${#AGENT_BASELINES[@]} == 0 ) ]] || { fail 'agent home/baseline options require dev'; exit 2; }
[[ "$WORKLOAD" == dev || "$AGENT_SELECTION" == auto || "$AGENT_SELECTION" == none ]] || { fail 'agents require dev'; exit 2; }
[[ -d $WORKSPACE ]] || { fail 'workspace directory does not exist'; exit 2; }
WORKSPACE=$(cd -- "$WORKSPACE" && pwd -P)
safe_text "$WORKSPACE" || exit 2
[[ $GUARD_PREFIX =~ ^/[a-zA-Z0-9._+-]+(/[a-zA-Z0-9._+-]+)*$ \
  && /$GUARD_PREFIX/ != */../* && /$GUARD_PREFIX/ != */./* ]] \
  || { fail 'use a normalized absolute Guard prefix'; exit 2; }
if [[ $DRY_RUN == false && $CHECK_ONLY == false ]]; then
  [[ $EUID != 0 ]] || { fail 'run as your normal host user, without sudo'; exit 2; }
  [[ -t 0 && -t 1 ]] || { fail 'an interactive terminal is required; use --dry-run for previews'; exit 2; }
fi

detect_steps() {
  local output number status detail
  DETECTED_NEXT=1
  DETECTED_LINES=()
  DETECTED_REVIEW_PATHS=()
  DETECTED_REVIEW_DIGESTS=()
  DETECTED_REVISION=''
  DETECTED_STATES=()
  if [[ $DRY_RUN == true ]]; then
    printf 'Detection skipped in preview mode. Use --check for read-only discovery.\n'
    return
  fi
  if ! command -v python3 >/dev/null || [[ ! -f $REPO/scripts/nosh-init-status.py ]]; then
    printf 'Automatic detection unavailable (requires Python 3); choose a step manually.\n'
    return
  fi
  if ! output=$(timeout 12s python3 "$REPO/scripts/nosh-init-status.py" \
      --workdir "$WORKSPACE" --workload "$WORKLOAD" --guard-prefix "$GUARD_PREFIX" --repo "$REPO" \
      --image "$IMAGE" --authoritative-stdin <<< "$AUTHORITATIVE_STATUS"); then
    printf 'Detection unavailable or timed out; choose a step manually.\n'
    return
  fi
  while IFS=$'\t' read -r number status detail; do
    if [[ $number == next && $status =~ ^[1-8]$ ]]; then
      DETECTED_NEXT=$status
    elif [[ $number == image && $status =~ ^sha256:[a-f0-9]{64}$ && $detail == 1 ]]; then
      IMAGE=$status
    elif [[ $number =~ ^review:[0-9]+$ && $status == /* && $detail =~ ^sha256:[a-f0-9]{64}$ ]] && safe_text "$status"; then
      DETECTED_REVIEW_PATHS+=("$status")
      DETECTED_REVIEW_DIGESTS+=("$detail")
    elif [[ $number == revision && $status =~ ^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$ ]]; then
      DETECTED_REVISION=$status
    elif [[ $number =~ ^[1-8]$ ]]; then
      DETECTED_LINES+=("$number [$status] $detail")
      DETECTED_STATES[number]=$status
    fi
  done <<< "$output"
  printf '%s\n' "${DETECTED_LINES[@]}"
  printf 'Suggested next step: %s (hints only; launch/apply perform validation).\n' "$DETECTED_NEXT"
}

check_activation() {
  local -a command=(sudo "$GUARD_PREFIX/bin/nosh-guard" net status --workdir "$WORKSPACE" --workload "$WORKLOAD" --json)
  printf 'Privileged workspace activation status (uses sudo):\n\n  '
  printf '%q ' "${command[@]}"
  printf '\n'
  [[ $DRY_RUN == false ]] || return 0
  if [[ $TUI_CONFIRMED == false ]]; then
    ask 'Run this command? y/N' || return 1
    [[ $ANSWER == y || $ANSWER == Y ]] || return 2
  fi
  AUTHORITATIVE_STATUS=''
  local result=0
  AUTHORITATIVE_STATUS=$("${command[@]}") || result=$?
  printf '%s\n' "$AUTHORITATIVE_STATUS"
  if ((result != 0)); then
    AUTHORITATIVE_STATUS=''
    fail "status check failed (exit $result); activation remains unverified"
    return "$result"
  fi
  if [[ $TUI_CONFIRMED == true ]]; then
    detect_steps >/dev/null
    if [[ ${DETECTED_STATES[8]:-unchecked} != checked \
        || ${DETECTED_STATES[7]:-unknown} != active ]]; then
      fail 'the active policy does not match this workspace, workload, image, and learning revision'
      return 1
    fi
  fi
}

select_image() {
  if [[ -z $IMAGE && $DRY_RUN == false ]]; then
    detect_steps >/dev/null
  fi
  if [[ -z $IMAGE ]]; then
    ask 'Local workload image tag or sha256 ID' nosh || return 1
    IMAGE=$ANSWER
  fi
  safe_text "$IMAGE" && [[ $IMAGE != -* ]] || { fail 'invalid image reference'; return 1; }
  [[ $DRY_RUN == false ]] || return 0
  local identity abi
  identity=$(docker image inspect --format '{{.Id}}' "$IMAGE") || return 1
  [[ $identity =~ ^sha256:[a-f0-9]{64}$ ]] || { fail 'image did not resolve to an exact local ID'; return 1; }
  abi=$(docker image inspect --format '{{index .Config.Labels "io.notty.guard.runner-abi"}}' "$identity") || return 1
  [[ $abi == 1 ]] || { fail 'runtime needs a Guard-compatible runner image (runner ABI 1); see init.md'; return 1; }
  IMAGE=$identity
  printf 'Using local workload image: %s\n' "$IMAGE"
}

read_tooling_result() {
  python3 - "$1" "$2" <<'PY'
import json, os, re, stat, sys
filename, expected = sys.argv[1:]
fd = os.open(filename, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
with os.fdopen(fd) as stream:
    info = os.fstat(stream.fileno())
    if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
            or stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 1 or info.st_size > 65536):
        raise SystemExit('Unsafe tooling readiness result')
    result = json.load(stream)
if result.get('schemaVersion') != 1 or result.get('status') != expected:
    raise SystemExit('Unexpected tooling readiness result')
if expected == 'ready':
    image = result.get('toolingImage', '')
    if not re.fullmatch(r'sha256:[a-f0-9]{64}', image):
        raise SystemExit('Tooling did not resolve to an exact local image')
    print(image)
else:
    reason = result.get('reason', 'Local policy tooling needs a build.')
    if not isinstance(reason, str) or len(reason) > 2048 or any(ord(c) < 32 for c in reason):
        raise SystemExit('Invalid tooling readiness reason')
    print(reason)
PY
}

prepare_tooling() {
  local operation result=0 reason resolved tag
  operation=$(mktemp -d /tmp/nosh-init-tooling.XXXXXX) || return 1
  printf 'Checking local policy tooling offline…\n'
  bash "$REPO/scripts/nosh-net-review.sh" tooling-status --result-json "$operation/status.json" \
    > "$operation/probe.log" || result=$?
  if ((result == 0)); then
    resolved=$(read_tooling_result "$operation/status.json" ready) || return 1
    export NOSH_POLICY_TOOLING_IMAGE=$resolved
    printf 'Local policy tooling is ready.\n'
    rm -f -- "$operation/status.json" "$operation/probe.log"
    rmdir -- "$operation"
    return 0
  fi
  if ((result != 3)); then
    fail 'Could not check local policy tooling. Resolve the reported Docker/configuration error and resume nosh init.'
    return "$result"
  fi
  reason=$(read_tooling_result "$operation/status.json" needs-build) || return 1
  printf '%s\n' "$reason"
  printf 'The wizard can build the policy tools from this checkout. This may download build dependencies.\nYour saved workload image, learned traffic, signing keys and review choices are retained.\n'
  tag="nosh-policy-tooling:startup-$(printf '%s' "$REPO" | sha256sum | cut -c 1-12)"
  run_command env "IMAGE_NAME=$tag" TARGET=local "$REPO/scripts/build-nosh.sh" || return $?
  resolved=$(docker image inspect --format '{{.Id}}' "$tag") || return 1
  [[ $resolved =~ ^sha256:[a-f0-9]{64}$ ]] || { fail 'rebuilt tooling has no exact local image ID'; return 1; }
  export NOSH_POLICY_TOOLING_IMAGE=$resolved
  result=0
  bash "$REPO/scripts/nosh-net-review.sh" tooling-status --result-json "$operation/rebuilt.json" \
    > "$operation/rebuilt.log" || result=$?
  if ((result != 0)); then
    fail 'The rebuilt policy tools did not pass their offline check. Setup has stopped before learning or Apply.'
    return "$result"
  fi
  [[ $(read_tooling_result "$operation/rebuilt.json" ready) == "$resolved" ]] \
    || { fail 'rebuilt tooling identity changed during verification'; return 1; }
  python3 "$REPO/scripts/nosh-save-tooling.py" --image "$resolved" || return 1
  printf 'Policy tools are ready. Continuing setup.\n'
  rm -f -- "$operation/status.json" "$operation/probe.log" "$operation/rebuilt.json" "$operation/rebuilt.log"
  rmdir -- "$operation"
}

prepare_review_network() {
  local status result=0 pool exclusions exclusion expected suggestions pool_lines choice index require_configured=${1:-false}
  local -a excluded=("${REVIEW_EXCLUSIONS[@]}") entered_exclusions=() command suggest_command pools=()
  if [[ -n $REVIEW_POOL && $require_configured == false ]]; then
    printf 'Checking and saving review network pool: %s\n' "$REVIEW_POOL"
    command=(python3 -I -S "$REPO/scripts/nosh-review-network.py" configure --check-host --pool "$REVIEW_POOL")
    for exclusion in "${REVIEW_EXCLUSIONS[@]}"; do command+=(--exclude "$exclusion"); done
    run_command "${command[@]}" || return $?
    [[ $DRY_RUN == false ]] || return 0
    prepare_review_network true
    return $?
  fi
  if [[ $DRY_RUN == true ]]; then
    printf 'Suggest checked /26 pools (eight /29 review networks), then confirm one.\n'
    run_command python3 -I -S "$REPO/scripts/nosh-review-network.py" suggest
    run_command python3 -I -S "$REPO/scripts/nosh-review-network.py" configure --check-host --pool '<selected-private-CIDR>'
    return $?
  fi
  status=$(python3 "$REPO/scripts/nosh-review-network.py" status) || result=$?
  case $result in
    0) expected=configured ;;
    3) expected=missing ;;
    *) fail 'Could not check the reserved review network pool. Resolve the configuration error before continuing.'; return 1 ;;
  esac
  pool=$(printf '%s' "$status" | python3 -c '
import json, sys
text = sys.stdin.read(65537)
if len(text) > 65536:
    raise SystemExit("Review network status is too large")
document = json.loads(text)
if document.get("schemaVersion") != 1 or document.get("status") != sys.argv[1]:
    raise SystemExit("Unexpected review network status")
if sys.argv[1] == "configured":
    pool = document.get("pool")
    if not isinstance(pool, str) or not pool or len(pool) > 64 or any(ord(c) < 32 for c in pool):
        raise SystemExit("Invalid review network pool status")
    print(pool)
' "$expected") || return 1
  if [[ $expected == configured ]]; then
    printf 'Reserved review network pool: %s\n' "$pool"
    return 0
  fi
  [[ $require_configured == false ]] || { fail 'The review network configuration was not saved; setup cannot continue.'; return 1; }
  printf 'Suggest a small pool for eight review networks. Each review receives a /29 subnet.\nChecks use local Docker allocations, routes and interfaces; no network probes are sent.\n'
  ask 'Additional LAN/VPN CIDRs to exclude (comma or space separated; Enter for none)' || return 1
  exclusions=$ANSWER
  IFS=' ' read -r -a entered_exclusions <<< "${exclusions//,/ }"
  excluded+=("${entered_exclusions[@]}")
  suggest_command=(python3 -I -S "$REPO/scripts/nosh-review-network.py" suggest)
  for exclusion in "${excluded[@]}"; do
    safe_text "$exclusion" || { fail 'invalid excluded CIDR text'; return 1; }
    suggest_command+=(--exclude "$exclusion")
  done
  while ! suggestions=$("${suggest_command[@]}"); do
    printf 'Could not complete host inspection. No pool was selected.\n'
    ask 'Retry inspection? y/N' || return 1
    [[ $ANSWER == y || $ANSWER == Y ]] || return 1
  done
  pool_lines=$(printf '%s' "$suggestions" | python3 -c '
import ipaddress, json, sys
text = sys.stdin.read(65537)
if len(text) > 65536:
    raise SystemExit("Suggestion result is too large")
value = json.loads(text)
if value.get("schemaVersion") != 1 or value.get("status") != "checked":
    raise SystemExit("Host inspection did not provide checked suggestions")
items = value.get("suggestions")
if not isinstance(items, list) or len(items) > 3:
    raise SystemExit("Invalid suggested pools")
private = [ipaddress.ip_network(item) for item in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")]
for item in items:
    network = ipaddress.IPv4Network(item["pool"], strict=True)
    if network.prefixlen != 26 or not any(network.subnet_of(block) for block in private) or item.get("reviewNetworks") != 8:
        raise SystemExit("Invalid suggested capacity or network")
    print(network)
for rejected in value.get("rejectedExamples", [])[:6]:
    print("Skipped: " + json.dumps(rejected, sort_keys=True), file=sys.stderr)
for warning in value.get("warnings", []):
    print("Inspection note: " + json.dumps(warning), file=sys.stderr)
') || return 1
  [[ -z $pool_lines ]] || mapfile -t pools <<< "$pool_lines"
  printf 'No observed overlap in the checked host state; disconnected networks need your exclusions.\n'
  for index in "${!pools[@]}"; do
    printf '%s) %s — eight /29 review networks\n' "$((index + 1))" "${pools[index]}"
  done
  ((${#pools[@]})) || printf 'No clear suggestions were found. Enter a custom range or cancel.\n'
  printf 'c) Custom CIDR    0) Cancel\n'
  choice=c
  ((${#pools[@]} == 0)) || choice=1
  ask 'Review pool' "$choice" || return 1
  case $ANSWER in
    0) printf 'Review network setup skipped; no pool was saved.\n'; return 2 ;;
    c|C) ask 'Custom private IPv4 CIDR (Enter to cancel)' || return 1; pool=$ANSWER ;;
    [1-3]) index=$((ANSWER - 1)); pool=${pools[index]:-} ;;
    *) pool=$ANSWER ;;
  esac
  [[ -n $pool ]] && safe_text "$pool" || { fail 'No valid pool was selected.'; return 1; }
  printf 'Saving the review pool only; Docker daemon settings stay unchanged. Host checks run again before saving.\n'
  command=(python3 -I -S "$REPO/scripts/nosh-review-network.py" configure --check-host --pool "$pool")
  for exclusion in "${excluded[@]}"; do command+=(--exclude "$exclusion"); done
  run_command "${command[@]}" || return $?
  # Read the saved configuration through the same validation used on resume.
  prepare_review_network true
}

install_guard() {
  printf 'Build may download dependencies. Installation uses sudo and restarts Guard.\nFinish active guarded sessions first.\n'
  local stage archive checksum installer
  local -a archives installers
  if [[ $DRY_RUN == true ]]; then
    run_command bash "$REPO/scripts/build-nosh-guard-host-bundle.sh" --output-dir '<new-private-directory>/artifacts'
    printf 'Then verify the checksum, extract the archive, and run:\n'
    run_command sudo bash '<verified-extracted-bundle>/install.sh' install --prefix "$GUARD_PREFIX" --enable-now
    return
  fi
  prepare_guard_prefix_migration || return $?
  stage=$(mktemp -d "$REPO/.nosh-install.XXXXXX") || return 1
  mkdir -m 700 "$stage/artifacts" "$stage/extracted" || return 1
  printf 'Artifacts retained: %s\n' "$stage"
  run_command bash "$REPO/scripts/build-nosh-guard-host-bundle.sh" --output-dir "$stage/artifacts" || return $?
  shopt -s nullglob
  archives=("$stage/artifacts/"*.tar.gz)
  [[ ${#archives[@]} == 1 ]] || { fail 'expected one bundle archive'; return 1; }
  archive=${archives[0]}
  checksum=$archive.sha256
  [[ -f $archive && ! -L $archive && -f $checksum && ! -L $checksum ]] || return 1
  (cd "$stage/artifacts" && sha256sum --check --strict "$(basename -- "$checksum")") || return 1
  tar -xzf "$archive" -C "$stage/extracted" || return 1
  installers=("$stage/extracted/"*/install.sh)
  [[ ${#installers[@]} == 1 && -f ${installers[0]} && ! -L ${installers[0]} ]] || return 1
  installer=${installers[0]}
  run_command sudo bash "$installer" install --prefix "$GUARD_PREFIX" --enable-now
}

build_profile() {
  printf 'Build profiling can download dependencies and execute the repository Dockerfile.\nIt captures build traffic; runtime learning follows separately.\n'
  local tag dockerfile
  ask 'Output image tag' nosh || return 1
  tag=$ANSWER
  safe_text "$tag" && [[ $tag != -* ]] || { fail 'invalid image tag'; return 1; }
  if [[ $WORKSPACE == "$REPO" ]]; then
    run_command env "IMAGE_NAME=$tag" "$REPO/scripts/build-nosh.sh" net learn --no-review || return $?
  else
    ask 'Dockerfile path' "$WORKSPACE/Dockerfile" || return 1
    dockerfile=$ANSWER
    [[ -f $dockerfile ]] && safe_text "$dockerfile" || { fail 'Dockerfile not found'; return 1; }
    run_command "$REPO/scripts/nosh.sh" build net learn --file "$dockerfile" --tag "$tag" "$WORKSPACE" || return $?
  fi
  IMAGE=$tag
}

apply_policy() {
  local session digest choice index
  printf 'Application signs and activates the saved selection; it asks for confirmation and may use sudo.\n'
  # Refresh immediately before selection instead of reusing earlier menu hints.
  detect_steps >/dev/null
  if ((${#DETECTED_REVIEW_PATHS[@]})); then
    index=0
    if ((${#DETECTED_REVIEW_PATHS[@]} > 1)); then
      printf 'Multiple completed reviews match this workspace, image and learning revision:\n'
      for index in "${!DETECTED_REVIEW_PATHS[@]}"; do
        printf '%s) %s\n   Digest: %s\n' "$((index + 1))" "${DETECTED_REVIEW_PATHS[index]}" "${DETECTED_REVIEW_DIGESTS[index]}"
      done
      ask 'Review number (0 to cancel)' || return 1
      choice=$ANSWER
      [[ $choice != 0 ]] || return 2
      [[ $choice =~ ^[1-9][0-9]{0,2}$ ]] && ((choice <= ${#DETECTED_REVIEW_PATHS[@]})) || { fail 'invalid review number'; return 1; }
      index=$((choice - 1))
    fi
    session=${DETECTED_REVIEW_PATHS[index]}
    digest=${DETECTED_REVIEW_DIGESTS[index]}
    printf 'Selected saved review: %s\nDecision digest: %s\nApply will verify the saved digest and policy bindings.\n' "$session" "$digest"
  else
    printf 'No completed matching review was discovered. Use the path and digest from your saved Apply command, or return to step 5.\n'
    ask 'Review session directory' || return 1
    session=$ANSWER
    ask 'Saved decision digest (sha256:...)' || return 1
    digest=$ANSWER
  fi
  [[ $session == /* && -d $session ]] && safe_text "$session" || { fail 'expected an existing absolute session directory'; return 1; }
  [[ $digest =~ ^sha256:[a-f0-9]{64}$ ]] || { fail 'invalid decision digest'; return 1; }
  if [[ $ADVANCED == false && $DRY_RUN == false \
      && ( -z $STEP || $TUI_CONFIRMED == true ) ]]; then
    run_command bash "$REPO/scripts/nosh-net-review.sh" check --review "$session" --decision-digest "$digest" || return $?
    local operation
    operation=$(mktemp -d "${TMPDIR:-/tmp}/nosh-init-apply.XXXXXX") || return 1
    APPLY_RESULT="$operation/result.json"
    run_command "$REPO/scripts/nosh.sh" net apply --workload "$WORKLOAD" --review "$session" --decision-digest "$digest" --result-json "$APPLY_RESULT" || return $?
    local selected
    selected=$(python3 - "$APPLY_RESULT" "$WORKSPACE" "$IMAGE" "$session" "$digest" <<'PY'
import json, os, re, stat, sys
filename, workspace, image, session, digest = sys.argv[1:]
fd = os.open(filename, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
with os.fdopen(fd) as stream:
    info = os.fstat(stream.fileno())
    if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 1 or info.st_size > 1048576:
        raise SystemExit('Unsafe Apply result')
    result = json.load(stream)
activation = result.get('activation') or {}
revision = result.get('revision', '')
if (result.get('schemaVersion') != 1 or result.get('workspace') != workspace
        or result.get('session') != session or result.get('decisionDigest') != digest
        or activation.get('imageDigest') != image or activation.get('learnRevision') != revision
        or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,127}', revision)
        or not re.fullmatch(r'sha256:[a-f0-9]{64}', activation.get('leafBundleDigest', ''))):
    raise SystemExit('Apply result does not match the selected review')
print(revision)
PY
    ) || { fail 'Policy may have applied, but its result could not be validated. Use Advanced status before retrying.'; return 1; }
    APPROVED_REVISION=$selected
    printf 'Policy activated for this workspace and image. Enforcement will validate it again before launch.\n'
  else
    run_command "$REPO/scripts/nosh.sh" net apply --workload "$WORKLOAD" --review "$session" --decision-digest "$digest"
  fi
}

learn_runtime() {
  select_image || return $?
  local app_option=--no-start-app previous result=0
  [[ "$WORKLOAD" != run ]] || app_option=--start-app
  detect_steps >/dev/null
  previous=$DETECTED_REVISION
  if [[ -n $START_APP_OPTION ]]; then
    app_option=$START_APP_OPTION
  elif [[ ($ADVANCED == true || -n $STEP) && $DRY_RUN == false ]]; then
    if [[ "$WORKLOAD" == run ]]; then
      ask 'Start the bundled /app service during learning? Y/n' Y || return 1
      [[ $ANSWER != n && $ANSWER != N ]] || app_option=--no-start-app
    else
      ask 'Start the bundled /app service during learning? y/N' || return 1
      [[ $ANSWER != y && $ANSWER != Y ]] || app_option=--start-app
    fi
  fi
  printf 'Learning uses sudo and allows outbound traffic. Exercise the workload, then exit its shell.\nExercise only the commands you want to profile; the selected app-start option is shown below.\n'
  local -a workload_args=(--workload "$WORKLOAD")
  if [[ "$WORKLOAD" == dev ]]; then
    workload_args+=(--agents "$AGENT_SELECTION")
    [[ -z "$CODEX_HOME_OPTION" ]] || workload_args+=(--codex-home "$CODEX_HOME_OPTION")
  fi
  local baseline
  for baseline in "${AGENT_BASELINES[@]}"; do workload_args+=(--agent-baseline "$baseline"); done
  run_command sudo "$GUARD_PREFIX/bin/nosh-guard" net learn --workdir "$WORKSPACE" "${workload_args[@]}" \
    --image "$IMAGE" --name "profile-$(date +%s)-$$" --review-output "$app_option" --no-collab || result=$?
  if [[ $LAST_COMMAND_EXECUTED == true && -f $REPO/scripts/nosh-init-status.py ]]; then
    python3 "$REPO/scripts/nosh-init-status.py" --workdir "$WORKSPACE" --workload "$WORKLOAD" --guard-prefix "$GUARD_PREFIX" \
      --repo "$REPO" --image "$IMAGE" --record-learning-exit "$result" --previous-revision "$previous" \
      || printf 'Could not retain the learning exit status; review evidence before continuing.\n' >&2
  fi
  return "$result"
}

check_runtime_readiness() {
  select_image || return $?
  if [[ $DRY_RUN == true ]]; then
    printf 'Check IPv6 enabled state, host forwarding, the non-loopback default route, and router-advertisement handling.\n'
    run_command sudo "$GUARD_PREFIX/bin/nosh-guard" doctor --mode egress-learn \
      --guard-prefix "$GUARD_PREFIX" --runner-image "$IMAGE"
    return $?
  fi

  local disabled forwarding route iface='' accept_ra='' route_uses_ra=false
  command -v ip >/dev/null || { fail 'the ip command is required for IPv6 route inspection'; return 1; }
  disabled=$(cat /proc/sys/net/ipv6/conf/all/disable_ipv6 2>/dev/null) \
    || { fail 'cannot read the host IPv6 enabled state'; return 1; }
  forwarding=$(cat /proc/sys/net/ipv6/conf/all/forwarding 2>/dev/null) \
    || { fail 'cannot read the host IPv6 forwarding state'; return 1; }
  route=$(ip -6 route show default 2>/dev/null | awk '$0 !~ /(^|[[:space:]])dev[[:space:]]+lo([[:space:]]|$)/ { print; exit }')
  iface=$(awk '{ for (i = 1; i <= NF; i++) if ($i == "dev") { print $(i + 1); exit } }' <<< "$route")
  [[ -z $iface || $iface =~ ^[a-zA-Z0-9_.:-]+$ ]] \
    || { fail 'IPv6 default route returned an unsafe interface name'; return 1; }
  [[ $route != *' proto ra '* && $route != *' proto ra' ]] || route_uses_ra=true
  if [[ -n $iface && -r /proc/sys/net/ipv6/conf/$iface/accept_ra ]]; then
    accept_ra=$(cat "/proc/sys/net/ipv6/conf/$iface/accept_ra") || return 1
  fi
  printf 'Host runtime network readiness:\n'
  printf '  IPv6 enabled:      %s\n' "$([[ $disabled == 0 ]] && printf yes || printf no)"
  printf '  IPv6 forwarding:   %s\n' "$([[ $forwarding == 1 ]] && printf yes || printf no)"
  printf '  IPv6 default route: %s\n' "${route:-missing}"
  [[ -z $accept_ra ]] || printf '  Router advertisements on %s: accept_ra=%s\n' "$iface" "$accept_ra"
  if [[ $disabled != 0 || $forwarding != 1 || -z $route ]]; then
    printf '\nScoped runtime policy uses a dual-stack Docker bridge and requires host IPv6 routing.\n' >&2
    if [[ $forwarding != 1 ]]; then
      printf 'Enable forwarding temporarily, then re-run this step:\n  sudo sysctl -w net.ipv6.conf.all.forwarding=1\n' >&2
    fi
    if [[ $route_uses_ra == true && -n $iface && $accept_ra != 2 ]]; then
      printf 'Preserve this RA-learned route while forwarding:\n  sudo sysctl -w net.ipv6.conf.%s.accept_ra=2\n' "$iface" >&2
    fi
    printf 'Verify:\n  cat /proc/sys/net/ipv6/conf/all/forwarding\n  ip -6 route show default\n' >&2
    printf 'After validation, persist reviewed settings under /etc/sysctl.d and retain the host firewall configuration.\n' >&2
    printf 'The wizard does not change sysctls or firewall configuration automatically.\n' >&2
    return 1
  fi
  if [[ $route_uses_ra == true && -n $iface && $accept_ra != 2 ]]; then
    printf '\nThis default route was learned through router advertisements and may disappear while forwarding is enabled.\n' >&2
    printf 'Preserve RA handling, then recheck:\n  sudo sysctl -w net.ipv6.conf.%s.accept_ra=2\n' "$iface" >&2
    printf 'Continue only while the default route remains present; make accept_ra=2 persistent when this host relies on RA.\n' >&2
  fi
  printf '\nLive IPv6 routing checks passed. Guard will now verify the exact runner image and eBPF backend.\n'
  run_command sudo "$GUARD_PREFIX/bin/nosh-guard" doctor --mode egress-learn \
    --guard-prefix "$GUARD_PREFIX" --runner-image "$IMAGE"
}

configure_launchers() {
  run_command "$REPO/scripts/setup-nosh.sh" --guard-prefix "$GUARD_PREFIX" --require-guard || return $?
  printf '\nOptional: install the Bubble Bai Codex pet.\n'
  printf 'Bubble Bai has only been tested in Kitty terminal. Support in other terminals is unverified.\n'
  local styled_disclaimer=false
  if [[ -t 1 && $DRY_RUN == false && ${TERM:-dumb} != dumb && -z ${NO_COLOR:-} ]]; then
    styled_disclaimer=true
    printf '\033[1;5;91m'
  fi
  printf '\n>>> >>> >>>  ESCAPE HATCH ALERT  <<< <<< <<<\n'
  printf 'Disclaimer: using Codex with Kitty, pets, and voice is an escape hatch outside the coverage of the eBPF run profile.\n'
  printf 'Do not treat host terminal, pet, or voice integrations as contained or fully monitored by that profile.\n'
  printf '>>> >>> >>> >>> >>> >>> <<< <<< <<< <<< <<<\n'
  [[ $styled_disclaimer == false ]] || printf '\033[0m'
  printf '\n'
  printf 'Installs for the current user under ${CODEX_HOME:-$HOME/.codex}/pets/bubble-bai/.\n'
  if [[ $DRY_RUN == true ]]; then
    printf 'Optional command: '
    printf '%q ' sh "$REPO/bubble-bai-codex/install.sh"
    printf '\n'
    return 0
  fi
  ask 'Install the optional Bubble Bai Codex pet? y/N' || return 0
  if [[ $ANSWER != y && $ANSWER != Y ]]; then
    printf 'Bubble Bai installation skipped.\n'
    return 0
  fi
  local result=0
  sh "$REPO/bubble-bai-codex/install.sh" || result=$?
  if ((result != 0)); then
    printf 'Bubble Bai installation failed (exit %s); Nosh setup can continue.\n' "$result" >&2
    printf 'Retry separately: ' >&2
    printf '%q ' sh "$REPO/bubble-bai-codex/install.sh" >&2
    printf '\n' >&2
  fi
  return 0
}

run_step() {
  case $1 in
    install) install_guard ;;
    setup) configure_launchers ;;
    build) build_profile ;;
    preflight) run_command python3 -I -S "$REPO/scripts/nosh-network-preflight.py" ;;
    network) prepare_review_network ;;
    readiness) check_runtime_readiness ;;
    tooling) prepare_tooling ;;
    inventory)
      select_image || return $?
      run_command bash "$REPO/scripts/nosh-net-review.sh" inventory --workdir "$WORKSPACE" --image "$IMAGE" ;;
    learn) learn_runtime ;;
    prepare)
      run_command bash "$REPO/scripts/nosh-net-review.sh" prepare --workdir "$WORKSPACE" --workload "$WORKLOAD" ;;
    review)
      prepare_review_network || return $?
      printf 'Choose Allow/Deny; progress saves automatically. Open Review selections, enter a reviewer, acknowledge, then Save reviewed policy.\nFor manual JSON edits see docs/nosh-policy-review.md (CLI review and manual JSON edits).\n'
      run_command "$REPO/scripts/nosh.sh" net review --workdir "$WORKSPACE" --workload "$WORKLOAD" ;;
    signing)
      printf 'First-time setup generates separate keys in offline containers, then asks before installing public host trust with sudo. Existing configuration is never replaced.\n'
      run_command python3 "$REPO/scripts/nosh-signing-setup.py" --workdir "$WORKSPACE" ;;
    apply) apply_policy ;;
    status) check_activation ;;
    tools-init)
      [[ $WORKLOAD == dev ]] || { fail 'Tool environment policy requires dev'; return 1; }
      local init_args=(--workdir "$WORKSPACE")
      [[ -z $CODEX_HOME_OPTION ]] || init_args+=(--codex-home "$CODEX_HOME_OPTION")
      run_command "$REPO/scripts/nosh.sh" tools init "${init_args[@]}" ;;
    tools-review|tools-check|tools-apply|tools-status)
      [[ $WORKLOAD == dev ]] || { fail 'Tool environment policy requires dev'; return 1; }
      local operation=${1#tools-}
      local tool_args=(--workdir "$WORKSPACE" --guard-prefix "$GUARD_PREFIX")
      if [[ $operation != status ]]; then
        if [[ -z $TOOL_REPORT && $DRY_RUN != true ]]; then
          ask 'Saved tool audit directory' || return 1
          TOOL_REPORT=$ANSWER
        fi
        tool_args+=(--review "${TOOL_REPORT:-REPORT}")
      fi
      if [[ $operation == apply ]]; then
        if [[ -z $TOOL_DIGEST && $DRY_RUN != true ]]; then
          run_command "$REPO/scripts/nosh.sh" tools check "${tool_args[@]}" || return $?
          ask 'Exact policyDigest shown by check' || return 1
          TOOL_DIGEST=$ANSWER
        fi
        tool_args+=(--policy-digest "${TOOL_DIGEST:-sha256:REVIEWED_DIGEST}")
      fi
      run_command "$REPO/scripts/nosh.sh" tools "$operation" "${tool_args[@]}" ;;
    *) fail "unknown step: $1" ;;
  esac
}

guided_setup() {
  local phase label inventory_image='' prepared='' checked_image='' tooling_ready=false network_ready=false result
  while true; do
    detect_steps >/dev/null
    if [[ ${DETECTED_STATES[1]:-missing} != present ]]; then phase=install; label='Install Guard'
    elif [[ ${DETECTED_STATES[2]:-missing} != configured ]]; then phase=setup; label='Configure launchers'
    elif [[ ${DETECTED_STATES[3]:-missing} != available ]]; then phase=build; label='Build and profile the workload image'
    elif [[ $checked_image != "$IMAGE" ]]; then phase=health; label='Check installed Guard readiness'
    elif [[ $network_ready != true ]]; then phase=network; label='Reserve the review network pool'
    elif [[ $tooling_ready != true ]]; then phase=tooling; label='Prepare policy tools'
    elif [[ $inventory_image != "$IMAGE" ]]; then phase=inventory; label='Prepare source and image inventories offline'
    elif [[ ${DETECTED_STATES[4]:-missing} != saved ]]; then phase=learn; label='Learn runtime connections'
    elif [[ ${DETECTED_STATES[6]:-missing} != configured ]]; then phase=signing; label='Set up signing'
    elif [[ $prepared != "$IMAGE/$DETECTED_REVISION" ]]; then phase=prepare; label='Check evidence and policy prerequisites'
    elif [[ ${DETECTED_STATES[5]:-missing} != saved ]]; then phase=review; label='Review connections and save your selection'
    else phase=apply; label='Apply the saved selection'; fi
    printf '\nNext: %s\n' "$label"
    [[ ${DETECTED_STATES[4]:-} != interrupted ]] || printf 'The last learning session was interrupted. Its export is retained for inspection.\n'
    result=0
    case $phase in
      network)
        prepare_review_network || result=$?
        ((result != 0)) || network_ready=true ;;
      tooling)
        prepare_tooling || result=$?
        ((result != 0)) || tooling_ready=true ;;
      health)
        check_runtime_readiness || result=$?
        ((result != 0)) || checked_image=$IMAGE ;;
      inventory)
        select_image || return $?
        run_command bash "$REPO/scripts/nosh-net-review.sh" inventory --workdir "$WORKSPACE" --image "$IMAGE" || result=$?
        ((result != 0)) || inventory_image=$IMAGE ;;
      prepare)
        run_command bash "$REPO/scripts/nosh-net-review.sh" prepare --workdir "$WORKSPACE" --workload "$WORKLOAD" || result=$?
        ((result != 0)) || prepared="$IMAGE/$DETECTED_REVISION" ;;
      *) run_step "$phase" || result=$? ;;
    esac
    if ((result != 0)); then
      printf 'Setup stopped at %s. Your saved work remains available; resolve the reported prerequisite and resume nosh init.\n' "$label"
      [[ $phase != learn ]] || printf 'Learning was interrupted. A saved export does not establish a complete session.\n'
      return "$result"
    fi
    if [[ $phase == review ]]; then
      printf 'In the browser, finish Review selections and Save reviewed policy.\n'
      ask 'Press Enter after saving to check the result' || return 0
    elif [[ $phase == apply ]]; then
      printf 'Initialization complete. Workspace: %s\nImage: %s\nRevision: %s\n' "$WORKSPACE" "$IMAGE" "$APPROVED_REVISION"
      printf 'Start or attach: '
      printf '%q ' nosh start --workdir "$WORKSPACE" --workload "$WORKLOAD"
      printf '\nExisting containers retain their current settings and policy when attached.\n'
      if [[ $WORKLOAD == dev ]]; then
        printf 'Tool environment policy is separate from network policy. Use steps 9–13 in nosh init --advanced to initialize, review, check, apply, and inspect it.\n'
        ask 'Open tool environment review now? y/N' || return 0
        if [[ $ANSWER == y || $ANSWER == Y ]]; then
          if [[ -n $TOOL_REPORT ]]; then run_step tools-review || return $?;
          else run_step tools-init || return $?; fi
        fi
      fi
      return 0
    fi
  done
}

launch_tui() {
  local data_root=${XDG_DATA_HOME:-$HOME/.local/share}
  local tui_root=$data_root/nosh/tui venv=$data_root/nosh/tui/venv-v1
  local requirements=$REPO/config/nosh-tui-requirements.txt marker=$data_root/nosh/tui/requirements.sha256
  local expected installed=''
  local -a tui_args=(--repo "$REPO" --workdir "$WORKSPACE" --guard-prefix "$GUARD_PREFIX"
    --default-workload "$WORKLOAD" --agents "$AGENT_SELECTION")
  tui_root=$(realpath -m -- "$tui_root") || return 1
  venv=$tui_root/venv-v1
  marker=$tui_root/requirements.sha256
  if [[ $tui_root == "$REPO" || $tui_root == "$REPO"/* \
      || $tui_root == "$WORKSPACE" || $tui_root == "$WORKSPACE"/* ]]; then
    printf 'Refusing to create the TUI environment inside a source workspace: %s\n' "$tui_root" >&2
    printf 'Set XDG_DATA_HOME to a private directory outside the repository, or use --classic.\n' >&2
    return 2
  fi
  command -v python3 >/dev/null || { printf 'Python 3 is unavailable; using the classic wizard.\n' >&2; return 2; }
  python3 -c 'import sys; raise SystemExit(sys.version_info < (3, 9))' \
    || { printf 'The Nosh TUI requires Python 3.9 or newer; using the classic wizard.\n' >&2; return 2; }
  [[ -f $requirements && ! -L $requirements ]] \
    || { printf 'Pinned TUI requirements are unavailable; using the classic wizard.\n' >&2; return 2; }
  expected=$(sha256sum -- "$requirements" | cut -d ' ' -f 1) || return 1
  [[ ! -f $marker ]] || installed=$(<"$marker")
  if [[ ! -x $venv/bin/python || $installed != "$expected" ]] \
      || ! "$venv/bin/python" -c 'import textual; raise SystemExit(textual.__version__ != "8.2.8")' 2>/dev/null; then
    printf 'The host TUI uses an isolated Python environment at:\n  %s\n' "$venv"
    printf 'Packages are installed from exact versions and hashes in %s.\n' "$requirements"
    ask 'Create or update the isolated TUI environment? y/N' || return 2
    [[ $ANSWER == y || $ANSWER == Y ]] || { printf 'TUI setup skipped; using the classic wizard.\n'; return 2; }
    mkdir -p -m 700 -- "$tui_root" || return 1
    [[ -d $tui_root && ! -L $tui_root && $(stat -c '%u:%a' -- "$tui_root") == "$(id -u):700" ]] \
      || { fail "unsafe TUI data directory: $tui_root"; return 1; }
    if [[ -L $venv || ( -e $venv && ! -d $venv ) ]]; then
      fail "TUI environment path is not a safe directory: $venv"
      return 1
    fi
    python3 -m venv --clear "$venv" || {
      printf 'Could not create the venv. Install the OS python3-venv package, then retry.\n' >&2
      return 2
    }
    "$venv/bin/python" -m pip install --disable-pip-version-check --require-hashes -r "$requirements" || return 1
    local marker_tmp=$tui_root/.requirements.$$
    (umask 077; printf '%s\n' "$expected" > "$marker_tmp") || return 1
    mv -f -- "$marker_tmp" "$marker" || return 1
  fi
  [[ -z $IMAGE ]] || tui_args+=(--image "$IMAGE")
  [[ $CODEX_HOME_EXPLICIT == false ]] || tui_args+=(--codex-home "$CODEX_HOME_OPTION")
  local baseline
  for baseline in "${AGENT_BASELINES[@]}"; do tui_args+=(--agent-baseline "$baseline"); done
  [[ -z $TOOL_REPORT ]] || tui_args+=(--review "$TOOL_REPORT")
  [[ -z $TOOL_DIGEST ]] || tui_args+=(--policy-digest "$TOOL_DIGEST")
  exec "$venv/bin/python" "$REPO/scripts/nosh-init-tui.py" "${tui_args[@]}"
}

cd -- "$REPO" || exit 1
if [[ $CHECK_ONLY == true ]]; then
  detect_steps
  exit 0
fi
if [[ -n $STEP ]]; then
  run_step "$STEP"
  exit $?
fi

if [[ $CLASSIC == false && $ADVANCED == false && $DRY_RUN == false ]]; then
  launch_tui
  tui_result=$?
  [[ $tui_result == 2 ]] || exit "$tui_result"
fi

printf 'Nosh initialization wizard\nWorkspace: %s\nGuide: %s/init.md\n' "$WORKSPACE" "$REPO"
[[ $DRY_RUN == false ]] || printf 'PREVIEW: commands will not execute; no state is saved.\n'
if [[ $ADVANCED == false && $DRY_RUN == false ]]; then
  printf 'Guided setup resumes the next required action. Use --advanced for the numbered menu.\n'
  guided_setup || exit $?
  [[ $ADVANCED == true ]] || exit 0
fi
steps=(install setup build learn review signing apply status tools-review tools-check tools-apply tools-status tools-init)
next=1
retry=false
while true; do
  printf '\nDetected state for %s:\n' "$WORKSPACE"
  detect_steps
  [[ $retry == true || $DRY_RUN == true ]] || next=$DETECTED_NEXT
  printf '\n1 Install/update Guard   2 Configure launchers\n3 Build/profile          4 Learn runtime\n5 Review/edit            6 Set up signing\n7 Apply saved review     8 Activation status\n9 Review tools           10 Check tool policy\n11 Apply tool policy     12 Tool policy status\n13 Initialize tool history                   0 Quit\n'
  ask 'Step' "$next" || break
  [[ $ANSWER != 0 ]] || break
  [[ $ANSWER =~ ^([1-9]|1[0-3])$ ]] || { printf 'Choose 0–13.\n'; continue; }
  selected=$ANSWER
  next=$selected
  [[ $selected == 8 ]] || AUTHORITATIVE_STATUS=''
  if run_step "${steps[selected-1]}"; then
    if [[ $DRY_RUN == true ]]; then printf 'Preview finished.\n'; else printf 'Step returned successfully.\n'; fi
    next=$((selected % 13 + 1))
    retry=false
  else
    if [[ $selected == 4 ]]; then
      retry=false
      printf 'Learning ended with an error. A policy export may still have been saved; the detected state below will suggest the next step.\n'
      printf 'If the shell was interrupted, investigate the workload exit before treating that export as a complete profile. You can choose 5 to inspect saved evidence.\n'
    else
      retry=true
      printf 'Step not completed. You can retry it or choose another step.\n'
    fi
  fi
done
