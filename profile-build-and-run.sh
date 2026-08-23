#!/usr/bin/env bash
set -euo pipefail

umask 077

if [[ "${NOSH_PROFILE_RUN_CONTROL_SNAPSHOT_ACTIVE:-}" != 1 ]]; then
  original_control_script="$(realpath -e -- "${BASH_SOURCE[0]}")"
  original_control_dir="$(dirname "$original_control_script")"
  control_snapshot="$(mktemp /tmp/nosh-profile-run-control.XXXXXX)"
  trap 'rm -f -- "$control_snapshot"' EXIT
  install -m 0500 -- "$original_control_script" "$control_snapshot"
  exec 9<"$control_snapshot"
  rm -f -- "$control_snapshot"
  trap - EXIT
  exec env \
    NOSH_PROFILE_RUN_CONTROL_SNAPSHOT_ACTIVE=1 \
    NOSH_PROFILE_RUN_ORIGINAL_SCRIPT_DIR="$original_control_dir" \
    "${BASH:-/bin/bash}" /proc/self/fd/9 "$@"
fi

resolve_script_dir() {
  local source="${BASH_SOURCE[0]}"
  local directory

  while [[ -L "$source" ]]; do
    directory="$(cd -P "$(dirname "$source")" && pwd)"
    source="$(readlink "$source")"
    if [[ "$source" != /* ]]; then
      source="$directory/$source"
    fi
  done

  cd -P "$(dirname "$source")" && pwd
}

SCRIPT_DIR="${NOSH_PROFILE_RUN_ORIGINAL_SCRIPT_DIR:-$(resolve_script_dir)}"
NOSH_BIN="${NOSH_PROFILE_NOSH_BIN:-$SCRIPT_DIR/nosh.sh}"
BUILD_BIN="${NOSH_PROFILE_BUILD_BIN:-$SCRIPT_DIR/build-nosh.sh}"
SUDO_BIN="${NOSH_PROFILE_SUDO_BIN:-sudo}"
DOCKER_BIN="${NOSH_PROFILE_DOCKER_BIN:-docker}"
PRIVILEGED_GUARD_BIN=""
PROFILE_DURATION="180"
PROFILE_DURATION_SEEN="false"
PROFILE_IMAGE="${IMAGE_NAME:-nosh}"
PROFILE_TARGET="${TARGET:-local}"
PROFILE_CACHE_MODE="compare"
PROFILE_WORKDIR="$PWD"
PROFILE_START_APP="true"
PROFILE_DRY_RUN="false"
POLICY_TOOLING_IMAGE_REQUESTED="${NOSH_POLICY_TOOLING_IMAGE:-}"
POLICY_TOOLING_IMAGE_ID=""
PROFILE_TMPDIR=""
PROFILE_TMPDIR_IDENTITY=""
PROFILE_WORKDIR_IDENTITY=""
ACTIVE_CHILD_PID=""
ACTIVE_CHILD_STARTTIME=""
ACTIVE_CHILD_STARTING="false"
PENDING_SIGNAL=""
PENDING_SIGNAL_STATUS="0"
SIGNAL_FORWARD_COUNT="0"
BUILD_OPTIONS=()
PROFILE_NODE_MOUNTS=()

usage() {
  cat <<'EOF'
Usage: ./profile-build-and-run.sh [options] [-- BUILD_PROFILE_OPTIONS...]

Profile the canonical Nosh Docker build, display its report, observe a guarded
runtime for three minutes by default, and display both reviewable profile files
plus the commands that can use them. Each live workflow derives a unique Guard
runner name from its new build profile, so retained diagnostic runs do not
reserve the next workflow's runtime identity.

Options:
  --duration SECONDS       Runtime observation length, 1..86400 (default: 180)
  --image IMAGE            Build tag; runtime uses its exact config digest
                           (default tag: IMAGE_NAME/nosh)
  --target TARGET          Dockerfile.nosh target (default: TARGET/local)
  --cache-mode MODE        compare, cold, or warm (default: compare)
  --workdir PATH           Runtime workspace (default: current directory)
  --start-app              Run the bundled Notty service during observation
  --no-start-app           Observe an idle guarded runner
  --dry-run                Validate and print delegated commands only
  -h, --help               Show this help

Additional build-profile options may follow `--`. Output-changing options
(`--push`, `--output`, `--no-load`, and `--load`) are rejected because the
runtime phase must use the image produced by this build.

Run this script as the Docker-authorized user, not with sudo. Runtime learning
and authoritative verification are elevated. Set NOSH_POLICY_TOOLING_IMAGE to
the exact local sha256 image ID of a separately reviewed policy-tooling image
with io.notty.guard.policy-tooling-abi=1. JSON validation runs in that image
with networking disabled; candidate image code is never used as trusted
tooling, and this workflow never starts Node/npm on the host. The script never
approves a policy.
EOF
}

die() {
  printf 'profile-build-and-run: %s\n' "$*" >&2
  exit 1
}

validate_profile_absolute_path() {
  local label="$1"
  local value="$2"
  local segment
  local -a segments=()

  [[ -n "$value" && "$value" == /* && "$value" != *//* \
    && ( "$value" == / || "$value" != */ ) \
    && "$value" != *$'\r'* ]] \
    || die "$label must be a normalized absolute path"
  IFS=/ read -r -a segments <<<"$value"
  for segment in "${segments[@]}"; do
    [[ "$segment" != . && "$segment" != .. ]] \
      || die "$label must be a normalized absolute path"
  done
}

validate_profile_guard_prefix() {
  local value="$1"

  validate_profile_absolute_path NOSH_GUARD_PREFIX "$value"
  [[ "$value" =~ ^/[A-Za-z0-9][A-Za-z0-9._+-]*(/[A-Za-z0-9][A-Za-z0-9._+-]*)*$ ]] \
    || die 'NOSH_GUARD_PREFIX contains unsafe characters'
  case "$value" in
    /bin|/boot|/dev|/etc|/home|/lib|/lib64|/media|/mnt|/opt|/proc|/root|/run|/sbin|/srv|/sys|/tmp|/usr|/var)
      die "NOSH_GUARD_PREFIX is too broad: $value"
      ;;
  esac
}

validate_bind_directory() {
  local label="$1"
  local selected="$2"
  local canonical

  [[ "$selected" == /* && -d "$selected" && ! -L "$selected" \
    && "$selected" != *','* && "$selected" != *$'\n'* && "$selected" != *$'\r'* ]] \
    || die "$label cannot be used as a trusted Docker bind directory: $selected"
  canonical="$(realpath -e -- "$selected")" \
    || die "could not resolve $label: $selected"
  [[ "$canonical" == "$selected" ]] \
    || die "$label must already be canonical: $selected"
}

path_is_within() {
  local selected="$1"
  local parent="$2"

  if [[ "$parent" == / ]]; then
    [[ "$selected" == /* ]]
    return
  fi
  [[ "$selected" == "$parent" || "$selected" == "$parent/"* ]]
}

paths_overlap() {
  local first="$1"
  local second="$2"

  path_is_within "$first" "$second" || path_is_within "$second" "$first"
}

directory_identity() {
  local selected="$1"
  local canonical

  [[ "$selected" == /* && -d "$selected" && ! -L "$selected" ]] || return 1
  canonical="$(realpath -e -- "$selected" 2>/dev/null)" || return 1
  [[ "$canonical" == "$selected" ]] || return 1
  stat -c '%d:%i' -- "$selected" 2>/dev/null
}

private_directory_identity() {
  local selected="$1"
  local identity
  local stat_uid
  local stat_mode

  identity="$(directory_identity "$selected")" || return 1
  read -r stat_uid stat_mode < <(stat -c '%u %a' -- "$selected") || return 1
  [[ "$stat_uid" == "${EUID:-$(id -u)}" && "$stat_mode" == 700 ]] || return 1
  printf '%s\n' "$identity"
}

create_private_temp_directory() {
  local label="$1"
  local template="$2"
  local workdir="$3"
  local root
  local canonical_root
  local selected
  local canonical

  # Deliberately ignore TMPDIR: the candidate receives its workspace as a
  # writable bind mount, so a caller-controlled TMPDIR may cross that boundary.
  for root in /tmp /var/tmp; do
    [[ -d "$root" && ! -L "$root" && -w "$root" ]] || continue
    canonical_root="$(realpath -e -- "$root" 2>/dev/null)" || continue
    if ! selected="$(mktemp -d "$canonical_root/$template")"; then
      continue
    fi
    canonical="$(realpath -e -- "$selected" 2>/dev/null || true)"
    if [[ "$canonical" == "$selected" ]] \
      && ! paths_overlap "$selected" "$workdir" \
      && private_directory_identity "$selected" >/dev/null; then
      printf '%s\n' "$selected"
      return
    fi
    rm -rf -- "$selected"
  done
  die "could not create a canonical private $label disjoint from runtime workdir $workdir"
}

revalidate_directory_identity() {
  local label="$1"
  local selected="$2"
  local expected_identity="$3"
  local actual_identity

  actual_identity="$(directory_identity "$selected")" \
    || die "$label is no longer the same canonical non-symlink directory: $selected"
  [[ "$actual_identity" == "$expected_identity" ]] \
    || die "$label identity changed while profiling: $selected"
}

revalidate_private_directory() {
  local label="$1"
  local selected="$2"
  local expected_identity="$3"
  local workdir="$4"
  local actual_identity

  actual_identity="$(private_directory_identity "$selected")" \
    || die "$label is no longer a private canonical directory: $selected"
  [[ "$actual_identity" == "$expected_identity" ]] \
    || die "$label identity changed while profiling: $selected"
  ! paths_overlap "$selected" "$workdir" \
    || die "$label overlaps runtime workdir $workdir"
}

remove_private_directory_if_owned() {
  local selected="$1"
  local expected_identity="$2"
  local actual_identity

  [[ -n "$selected" && -n "$expected_identity" ]] || return 0
  actual_identity="$(private_directory_identity "$selected" 2>/dev/null || true)"
  [[ -n "$actual_identity" && "$actual_identity" == "$expected_identity" ]] || return 0
  rm -rf -- "$selected"
}

read_layout_value() {
  local layout_file="$1"
  local layout_kind="$2"
  local requested_key="$3"
  local expected_uid="$4"
  local expected_mode="$5"
  local stat_uid
  local stat_mode
  local stat_links
  local line
  local key
  local value
  local -A values=()

  [[ -e "$layout_file" || -L "$layout_file" ]] || return 3
  [[ -f "$layout_file" && ! -L "$layout_file" ]] \
    || die "$layout_kind must be a regular non-symlink file: $layout_file"
  read -r stat_uid stat_mode stat_links < <(stat -c '%u %a %h' -- "$layout_file") \
    || die "could not inspect $layout_kind: $layout_file"
  [[ "$stat_uid" == "$expected_uid" && "$stat_mode" == "$expected_mode" \
    && "$stat_links" == 1 ]] \
    || die "$layout_kind has unsafe ownership, mode, or link count: $layout_file"

  while IFS= read -r line || [[ -n "$line" ]]; do
    [[ "$line" =~ ^([A-Z][A-Z0-9_]*)=(.*)$ ]] \
      || die "$layout_kind contains a malformed line: $layout_file"
    key="${BASH_REMATCH[1]}"
    value="${BASH_REMATCH[2]}"
    [[ -z "${values[$key]+set}" ]] \
      || die "$layout_kind contains duplicate key $key"
    case "$layout_kind:$key" in
      user-paths:SCHEMA_VERSION|user-paths:BIN_DIR|user-paths:NOSH_BIN|\
      user-paths:NOSH_GUARD_BIN|user-paths:NOSH_GUARD_PREFIX|\
      user-paths:NOSH_GUARD_PRIVILEGED_BIN|\
      install-receipt:SCHEMA_VERSION|install-receipt:NOSH_GUARD_PREFIX|\
      install-receipt:MANIFEST_SHA256)
        ;;
      *) die "$layout_kind contains unknown key $key" ;;
    esac
    values[$key]="$value"
  done <"$layout_file"

  if [[ "$layout_kind" == user-paths ]]; then
    for key in SCHEMA_VERSION BIN_DIR NOSH_BIN NOSH_GUARD_BIN \
      NOSH_GUARD_PREFIX NOSH_GUARD_PRIVILEGED_BIN; do
      [[ -n "${values[$key]+set}" ]] || die "$layout_kind is missing $key"
    done
    validate_profile_absolute_path BIN_DIR "${values[BIN_DIR]}"
    validate_profile_absolute_path NOSH_BIN "${values[NOSH_BIN]}"
    validate_profile_absolute_path NOSH_GUARD_BIN "${values[NOSH_GUARD_BIN]}"
    validate_profile_guard_prefix "${values[NOSH_GUARD_PREFIX]}"
    validate_profile_absolute_path \
      NOSH_GUARD_PRIVILEGED_BIN "${values[NOSH_GUARD_PRIVILEGED_BIN]}"
    [[ "${values[NOSH_GUARD_PRIVILEGED_BIN]}" \
      == "${values[NOSH_GUARD_PREFIX]}/bin/nosh-guard" ]] \
      || die "$layout_kind has inconsistent privileged Guard paths"
  else
    for key in SCHEMA_VERSION NOSH_GUARD_PREFIX MANIFEST_SHA256; do
      [[ -n "${values[$key]+set}" ]] || die "$layout_kind is missing $key"
    done
    [[ "${values[MANIFEST_SHA256]}" =~ ^[a-f0-9]{64}$ ]] \
      || die "$layout_kind has an invalid manifest digest"
    validate_profile_guard_prefix "${values[NOSH_GUARD_PREFIX]}"
  fi
  [[ "${values[SCHEMA_VERSION]}" == 1 ]] \
    || die "$layout_kind uses an unsupported schema"
  printf '%s\n' "${values[$requested_key]}"
}

resolve_privileged_guard_bin() {
  local config_root
  local config_file
  local configured
  local read_status
  local receipt=/etc/nosh-guard-install-layout.conf

  if [[ -n "${NOSH_PROFILE_PRIVILEGED_GUARD_BIN:-}" ]]; then
    validate_profile_absolute_path \
      NOSH_PROFILE_PRIVILEGED_GUARD_BIN "$NOSH_PROFILE_PRIVILEGED_GUARD_BIN"
    printf '%s\n' "$NOSH_PROFILE_PRIVILEGED_GUARD_BIN"
    return
  fi
  if [[ -n "${NOSH_GUARD_PRIVILEGED_BIN:-}" ]]; then
    validate_profile_absolute_path \
      NOSH_GUARD_PRIVILEGED_BIN "$NOSH_GUARD_PRIVILEGED_BIN"
    printf '%s\n' "$NOSH_GUARD_PRIVILEGED_BIN"
    return
  fi
  if [[ -n "${NOSH_GUARD_PREFIX:-}" ]]; then
    validate_profile_guard_prefix "$NOSH_GUARD_PREFIX"
    printf '%s/bin/nosh-guard\n' "$NOSH_GUARD_PREFIX"
    return
  fi

  config_root="${XDG_CONFIG_HOME:-${HOME:?HOME is required}/.config}"
  validate_profile_absolute_path XDG_CONFIG_HOME "$config_root"
  config_file="$config_root/nosh/paths.conf"
  if configured="$(read_layout_value \
    "$config_file" user-paths NOSH_GUARD_PRIVILEGED_BIN \
    "${EUID:-$(id -u)}" 600)"; then
    printf '%s\n' "$configured"
    return
  else
    read_status=$?
    ((read_status == 3)) || exit "$read_status"
  fi
  if configured="$(read_layout_value \
    "$receipt" install-receipt NOSH_GUARD_PREFIX 0 644)"; then
    printf '%s/bin/nosh-guard\n' "$configured"
    return
  else
    read_status=$?
    ((read_status == 3)) || exit "$read_status"
  fi
  printf '%s/bin/nosh-guard\n' /usr/local
}

trust_privileged_guard_bin() {
  local requested="$1"
  local resolved
  local cursor
  local stat_uid
  local stat_mode
  local stat_links

  [[ "$requested" == /* ]] || die "privileged nosh-guard path must be absolute"
  resolved="$(realpath -e -- "$requested" 2>/dev/null)" \
    || die "privileged nosh-guard is not installed at $requested; run ./setup-nosh.sh"
  [[ -f "$resolved" ]] || die "privileged nosh-guard is not a regular file: $resolved"
  read -r stat_uid stat_mode stat_links < <(stat -c '%u %a %h' -- "$resolved") \
    || die "could not inspect privileged nosh-guard: $resolved"
  [[ "$stat_uid" == 0 && "$stat_links" == 1 \
    && $((8#$stat_mode & 8#22)) == 0 \
    && $((8#$stat_mode & 8#111)) != 0 ]] \
    || die "privileged nosh-guard must be singly linked, root-owned, executable, and non-writable: $resolved"
  cursor="$(dirname "$resolved")"
  while :; do
    read -r stat_uid stat_mode < <(stat -c '%u %a' -- "$cursor") \
      || die "could not inspect privileged nosh-guard ancestor: $cursor"
    [[ "$stat_uid" == 0 && $((8#$stat_mode & 8#22)) == 0 ]] \
      || die "privileged nosh-guard has an untrusted ancestor: $cursor"
    [[ "$cursor" == / ]] && break
    cursor="$(dirname "$cursor")"
  done
  printf '%s\n' "$resolved"
}

validate_duration() {
  local value="$1"

  if [[ ! "$value" =~ ^[1-9][0-9]*$ || ${#value} -gt 5 ]]; then
    die "--duration must be an integer from 1 to 86400"
  fi
  if ((10#$value > 86400)); then
    die "--duration must be an integer from 1 to 86400"
  fi
}

require_value() {
  local option="$1"
  local value="${2:-}"

  if [[ -z "$value" || "$value" == -* ]]; then
    die "$option requires a value"
  fi
}

print_command() {
  printf '  '
  printf '%q ' "$@"
  printf '\n'
}

section() {
  printf '\n== %s ==\n' "$1"
}

resolve_policy_tooling_image() {
  local requested="$1"
  local inspection

  [[ "$requested" =~ ^sha256:[a-f0-9]{64}$ ]] \
    || die 'NOSH_POLICY_TOOLING_IMAGE must be an exact local sha256 image ID'
  inspection="$("$DOCKER_BIN" image inspect \
    --format '{{.Id}}|{{index .Config.Labels "io.notty.guard.policy-tooling-abi"}}' \
    "$requested" 2>/dev/null)" \
    || die 'NOSH_POLICY_TOOLING_IMAGE is not installed locally; this workflow never pulls policy tooling'
  [[ "$inspection" =~ ^(sha256:[a-f0-9]{64})\|([^\|[:space:]]+)$ ]] \
    || die 'could not verify the configured policy-tooling image identity and ABI'
  [[ "${BASH_REMATCH[1]}" == "$requested" ]] \
    || die 'NOSH_POLICY_TOOLING_IMAGE did not resolve to its exact configured image ID'
  [[ "${BASH_REMATCH[2]}" == 1 ]] \
    || die "policy-tooling image ABI mismatch: expected io.notty.guard.policy-tooling-abi=1, got ${BASH_REMATCH[2]}"
  printf '%s\n' "$requested"
}

run_profile_node() {
  "$DOCKER_BIN" run --rm --pull never --network none \
    --user "$(id -u):$(id -g)" \
    --read-only --cap-drop ALL --security-opt no-new-privileges:true \
    --pids-limit 64 --memory 512m --memory-swap 512m \
    --tmpfs /tmp:rw,nosuid,nodev,noexec,size=67108864 \
    --env HOME=/tmp/nosh-profile-home \
    --mount "type=bind,src=$PROFILE_TMPDIR,dst=$PROFILE_TMPDIR" \
    "${PROFILE_NODE_MOUNTS[@]}" \
    --entrypoint /usr/local/bin/node \
    "$POLICY_TOOLING_IMAGE_ID" "$@"
}

process_start_time() {
  local selected_pid="$1"
  local stat_line
  local -a stat_fields=()

  [[ "$selected_pid" =~ ^[1-9][0-9]*$ ]] || return 1
  [[ -r "/proc/$selected_pid/stat" ]] || return 1
  IFS= read -r stat_line <"/proc/$selected_pid/stat" || return 1
  # comm is parenthesized and may contain spaces or ')'; remove through the
  # final closing parenthesis. The remaining zero-based field 19 is starttime
  # (proc_pid_stat(5) field 22).
  stat_line="${stat_line##*) }"
  read -r -a stat_fields <<<"$stat_line"
  ((${#stat_fields[@]} > 19)) || return 1
  [[ "${stat_fields[19]}" =~ ^[0-9]+$ ]] || return 1
  printf '%s\n' "${stat_fields[19]}"
}

forward_active_signal() {
  local signal_name="$1"
  local current_starttime

  [[ -n "$ACTIVE_CHILD_PID" && -n "$ACTIVE_CHILD_STARTTIME" ]] || return 0
  current_starttime="$(process_start_time "$ACTIVE_CHILD_PID" 2>/dev/null || true)"
  [[ -n "$current_starttime" && "$current_starttime" == "$ACTIVE_CHILD_STARTTIME" ]] \
    || return 0
  kill -s "$signal_name" "$ACTIVE_CHILD_PID" 2>/dev/null || true
}

wait_for_active_child() {
  local child_pid="$1"
  local before_wait
  local child_status

  while true; do
    before_wait="$SIGNAL_FORWARD_COUNT"
    if wait "$child_pid" 2>/dev/null; then
      child_status=0
    else
      child_status=$?
    fi
    if [[ "$SIGNAL_FORWARD_COUNT" == "$before_wait" ]]; then
      break
    fi
  done
  return 0
}

handle_signal() {
  local signal_name="$1"
  local signal_status="$2"

  SIGNAL_FORWARD_COUNT=$((SIGNAL_FORWARD_COUNT + 1))
  if [[ -n "$PENDING_SIGNAL" ]]; then
    forward_active_signal "$signal_name"
    return
  fi
  PENDING_SIGNAL="$signal_name"
  PENDING_SIGNAL_STATUS="$signal_status"
  if [[ -n "$ACTIVE_CHILD_PID" ]]; then
    forward_active_signal "$signal_name"
    return
  fi
  if [[ "$ACTIVE_CHILD_STARTING" == "true" ]]; then
    return
  fi
  exit "$signal_status"
}

run_interruptible() {
  local child_status

  ACTIVE_CHILD_STARTING="true"
  (
    trap - INT TERM
    exec "$@"
  ) &
  ACTIVE_CHILD_PID=$!
  ACTIVE_CHILD_STARTTIME="$(process_start_time "$ACTIVE_CHILD_PID" 2>/dev/null || true)"
  ACTIVE_CHILD_STARTING="false"

  if [[ -n "$PENDING_SIGNAL" ]]; then
    forward_active_signal "$PENDING_SIGNAL"
  fi
  if wait "$ACTIVE_CHILD_PID"; then
    child_status=0
  else
    child_status=$?
  fi
  if [[ -n "$PENDING_SIGNAL" ]]; then
    wait_for_active_child "$ACTIVE_CHILD_PID"
    ACTIVE_CHILD_PID=""
    ACTIVE_CHILD_STARTTIME=""
    exit "$PENDING_SIGNAL_STATUS"
  fi
  ACTIVE_CHILD_PID=""
  ACTIVE_CHILD_STARTTIME=""
  return "$child_status"
}

cleanup() {
  local original_status=$?

  trap - EXIT INT TERM
  if [[ -n "$ACTIVE_CHILD_PID" ]]; then
    forward_active_signal TERM
    wait_for_active_child "$ACTIVE_CHILD_PID"
    ACTIVE_CHILD_PID=""
    ACTIVE_CHILD_STARTTIME=""
  fi
  remove_private_directory_if_owned "$PROFILE_TMPDIR" "$PROFILE_TMPDIR_IDENTITY"
  return "$original_status"
}

show_file() {
  local label="$1"
  local selected="$2"
  local displayed="${3:-$selected}"

  printf '%s: %s\n' "$label" "$displayed"
  if [[ -f "$selected" && ! -L "$selected" ]]; then
    command cat -- "$selected"
    [[ "$(tail -c 1 -- "$selected" 2>/dev/null || true)" == "" ]] || printf '\n'
  else
    printf '  (not produced)\n'
  fi
}

while (($#)); do
  case "$1" in
    --duration)
      require_value "$1" "${2:-}"
      [[ "$PROFILE_DURATION_SEEN" != "true" ]] \
        || die "--duration may be specified only once"
      PROFILE_DURATION="$2"
      PROFILE_DURATION_SEEN="true"
      shift 2
      ;;
    --duration=*)
      [[ "$PROFILE_DURATION_SEEN" != "true" ]] \
        || die "--duration may be specified only once"
      PROFILE_DURATION="${1#*=}"
      PROFILE_DURATION_SEEN="true"
      shift
      ;;
    --image)
      require_value "$1" "${2:-}"
      PROFILE_IMAGE="$2"
      shift 2
      ;;
    --image=*)
      PROFILE_IMAGE="${1#*=}"
      [[ -n "$PROFILE_IMAGE" ]] || die "--image requires a value"
      shift
      ;;
    --target)
      require_value "$1" "${2:-}"
      PROFILE_TARGET="$2"
      shift 2
      ;;
    --target=*)
      PROFILE_TARGET="${1#*=}"
      [[ -n "$PROFILE_TARGET" ]] || die "--target requires a value"
      shift
      ;;
    --cache-mode)
      require_value "$1" "${2:-}"
      PROFILE_CACHE_MODE="$2"
      shift 2
      ;;
    --cache-mode=*)
      PROFILE_CACHE_MODE="${1#*=}"
      shift
      ;;
    --workdir)
      require_value "$1" "${2:-}"
      PROFILE_WORKDIR="$2"
      shift 2
      ;;
    --workdir=*)
      PROFILE_WORKDIR="${1#*=}"
      [[ -n "$PROFILE_WORKDIR" ]] || die "--workdir requires a value"
      shift
      ;;
    --start-app)
      PROFILE_START_APP="true"
      shift
      ;;
    --no-start-app)
      PROFILE_START_APP="false"
      shift
      ;;
    --dry-run)
      PROFILE_DRY_RUN="true"
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    --)
      shift
      BUILD_OPTIONS=("$@")
      break
      ;;
    *)
      die "unknown option: $1"
      ;;
  esac
done

validate_duration "$PROFILE_DURATION"
case "$PROFILE_CACHE_MODE" in
  compare|cold|warm) ;;
  *) die "--cache-mode must be compare, cold, or warm" ;;
esac
[[ -n "$PROFILE_IMAGE" ]] || die "--image requires a value"
[[ -n "$PROFILE_TARGET" ]] || die "--target requires a value"
if [[ ! -d "$PROFILE_WORKDIR" ]]; then
  die "runtime workdir is not a directory: $PROFILE_WORKDIR"
fi
PROFILE_WORKDIR="$(cd -P "$PROFILE_WORKDIR" && pwd)"
validate_bind_directory 'runtime workdir' "$PROFILE_WORKDIR"
PROFILE_WORKDIR_IDENTITY="$(directory_identity "$PROFILE_WORKDIR")" \
  || die "runtime workdir is not a stable canonical directory: $PROFILE_WORKDIR"
PRIVILEGED_GUARD_BIN="$(resolve_privileged_guard_bin)"

for option in "${BUILD_OPTIONS[@]}"; do
  case "$option" in
    --push|--push=*|--output|-o|--output=*|-o?*|--no-load|--no-load=*|\
    --load|--load=*|--private-json|--private-json=*|--dry-run|--dry-run=*|\
    --cache-mode|--cache-mode=*)
      die "$option is controlled by the combined profiling workflow"
      ;;
  esac
done

[[ -x "$NOSH_BIN" ]] || die "Nosh launcher is not executable: $NOSH_BIN"
[[ -x "$BUILD_BIN" ]] || die "build launcher is not executable: $BUILD_BIN"
command -v "$DOCKER_BIN" >/dev/null 2>&1 || die "Docker is unavailable: $DOCKER_BIN"
POLICY_TOOLING_IMAGE_ID="$(resolve_policy_tooling_image \
  "$POLICY_TOOLING_IMAGE_REQUESTED")"

RUNTIME_APP_OPTION="--start-app"
if [[ "$PROFILE_START_APP" != "true" ]]; then
  RUNTIME_APP_OPTION="--no-start-app"
fi

if [[ "$PROFILE_DRY_RUN" == "true" ]]; then
  section "Build profile (dry run)"
  env \
    IMAGE_NAME="$PROFILE_IMAGE" \
    TARGET="$PROFILE_TARGET" \
    "$BUILD_BIN" profile \
    --cache-mode "$PROFILE_CACHE_MODE" \
    --dry-run \
    "${BUILD_OPTIONS[@]}"

  section "Runtime egress profile (dry run)"
  print_command "$NOSH_BIN" net learn \
    --duration "$PROFILE_DURATION" \
    --image "$PROFILE_IMAGE" \
    --workdir "$PROFILE_WORKDIR" \
    --no-collab \
    "$RUNTIME_APP_OPTION" \
    --json \
    --dry-run
  "$NOSH_BIN" net learn \
    --duration "$PROFILE_DURATION" \
    --image "$PROFILE_IMAGE" \
    --workdir "$PROFILE_WORKDIR" \
    --no-collab \
    "$RUNTIME_APP_OPTION" \
    --json \
    --dry-run
  printf '%s\n' \
    '' \
    'No files or policies were created. Re-run without --dry-run.' \
    'The checkout launcher/tag command above is validation only.' \
    'The live phase substitutes the exact build config digest and invokes' \
    'a unique runner name derived from the new build profile ID before invoking' \
    "sudo -- $PRIVILEGED_GUARD_BIN for privileged runtime operations." \
    "Trusted JSON tooling image: $POLICY_TOOLING_IMAGE_ID"
  exit 0
fi

if [[ "${EUID:-$(id -u)}" == 0 ]]; then
  die "run this script as the Docker-authorized user without sudo"
fi
command -v "$SUDO_BIN" >/dev/null 2>&1 || die "sudo helper is unavailable: $SUDO_BIN"
PRIVILEGED_GUARD_BIN="$(trust_privileged_guard_bin "$PRIVILEGED_GUARD_BIN")"

PROFILE_TMPDIR="$(create_private_temp_directory \
  'profile temporary directory' nosh-build-run-profile.XXXXXX "$PROFILE_WORKDIR")"
PROFILE_TMPDIR_IDENTITY="$(private_directory_identity "$PROFILE_TMPDIR")" \
  || die "profile temporary directory is not private: $PROFILE_TMPDIR"
trap cleanup EXIT
trap 'handle_signal INT 130' INT
trap 'handle_signal TERM 143' TERM
BUILD_RESULT="$PROFILE_TMPDIR/build-result.json"
BUILD_RECORD="$PROFILE_TMPDIR/build-record.bin"
BUILD_SELECTED="$PROFILE_TMPDIR/build-selected.json"
BUILD_IDENTITY_RECORD="$PROFILE_TMPDIR/build-identity-record.bin"
BUILD_PROFILE_SNAPSHOT="$PROFILE_TMPDIR/build-profile.json"
RUNTIME_LEARN="$PROFILE_TMPDIR/runtime-learn.json"
RUNTIME_LEARN_RECORD="$PROFILE_TMPDIR/runtime-learn-record.bin"
RUNTIME_STATUS="$PROFILE_TMPDIR/runtime-status.json"
RUNTIME_POLICY_SNAPSHOT="$PROFILE_TMPDIR/runtime-policy.json"

section "Build profile"
set +e
run_interruptible env \
  IMAGE_NAME="$PROFILE_IMAGE" \
  TARGET="$PROFILE_TARGET" \
  "$BUILD_BIN" profile \
  --cache-mode "$PROFILE_CACHE_MODE" \
  --private-json \
  "${BUILD_OPTIONS[@]}" >"$BUILD_RESULT"
BUILD_EXIT=$?
set -e

if [[ ! -s "$BUILD_RESULT" ]]; then
  if ((BUILD_EXIT != 0)); then
    die "build profile command failed with status $BUILD_EXIT before producing private JSON"
  fi
  die "build profile command produced no private JSON"
fi

if ! run_profile_node - "$BUILD_RESULT" "$BUILD_EXIT" \
  >"$BUILD_RECORD" <<'NODE'
const fs = require('node:fs');
const path = require('node:path');
const [resultPath, buildExitText] = process.argv.slice(2);
const run = JSON.parse(fs.readFileSync(resultPath, 'utf8'));
const manifest = run?.manifest;
const buildExit = Number(buildExitText);
const safeRunId = typeof run?.profileId === 'string'
  && run.profileId.length > 0
  && run.profileId.length <= 256
  && !/[\0/\\\r\n]/u.test(run.profileId);
const normalizedBundle = typeof run?.bundleDir === 'string'
  && path.isAbsolute(run.bundleDir)
  && path.normalize(run.bundleDir) === run.bundleDir
  && !/[\r\n]/u.test(run.bundleDir);
const normalizedPortable = typeof run?.portableBundleDir === 'string'
  && path.isAbsolute(run.portableBundleDir)
  && path.normalize(run.portableBundleDir) === run.portableBundleDir
  && !/[\r\n]/u.test(run.portableBundleDir);
if (
  !Number.isSafeInteger(buildExit)
  || buildExit < 0
  || buildExit > 255
  || !safeRunId
  || run.mode !== 'build-profile'
  || !normalizedBundle
  || !normalizedPortable
  || run.portableBundleDir !== path.join(run.bundleDir, 'portable')
  || run.status !== buildExit
  || manifest?.schemaVersion !== 1
  || manifest?.apiVersion !== 'notty.dev/v1alpha1'
  || manifest?.kind !== 'NoshBuildEvidenceManifest'
  || manifest?.runId !== run.profileId
  || manifest?.mode !== 'build-profile'
  || typeof manifest?.complete !== 'boolean'
  || typeof manifest?.candidateEligible !== 'boolean'
  || Boolean(run.candidate) !== manifest.candidateEligible
) {
  process.stderr.write('private result for the new build profile is invalid\n');
  process.exit(1);
}
for (const value of [
  run.profileId,
  run.bundleDir,
  manifest.complete === true ? 'true' : 'false',
  manifest.candidateEligible === true ? 'true' : 'false',
]) {
  process.stdout.write(`${value}\0`);
}
NODE
then
  die "could not validate the new build profile result"
fi

mapfile -d '' -t BUILD_FIELDS <"$BUILD_RECORD"
if ((${#BUILD_FIELDS[@]} != 4)); then
  die "new build profile status was truncated"
fi
BUILD_RUN_ID="${BUILD_FIELDS[0]}"
BUILD_BUNDLE="${BUILD_FIELDS[1]}"
validate_bind_directory 'private build profile bundle' "$BUILD_BUNDLE"
BUILD_COMPLETE="${BUILD_FIELDS[2]}"
BUILD_CANDIDATE_ELIGIBLE="${BUILD_FIELDS[3]}"
BUILD_PORTABLE="$BUILD_BUNDLE/portable"
BUILD_PRIVATE_PROFILE="$BUILD_BUNDLE/build-profile-candidate.json"
BUILD_PROFILE_FILE="$BUILD_PORTABLE/candidate.json"

section "Build profile result"
set +e
run_interruptible \
  "$NOSH_BIN" build status --run "$BUILD_RUN_ID" "$SCRIPT_DIR"
BUILD_REPORT_EXIT=$?
set -e
printf 'Build profile file: %s\n' "$BUILD_PROFILE_FILE"
printf 'Private build candidate (sensitive): %s\n' "$BUILD_PRIVATE_PROFILE"
printf 'Portable CI bundle: %s\n' "$BUILD_PORTABLE"

if ((BUILD_EXIT != 0)) \
  || ((BUILD_REPORT_EXIT != 0)) \
  || [[ "$BUILD_COMPLETE" != "true" ]] \
  || [[ "$BUILD_CANDIDATE_ELIGIBLE" != "true" ]]; then
  show_file "Build portable report" "$BUILD_PORTABLE/report.txt"
  die "build profile is incomplete or the build failed; runtime profiling was not started"
fi

set +e
run_interruptible "$NOSH_BIN" build status \
  --run "$BUILD_RUN_ID" \
  --json \
  "$SCRIPT_DIR" >"$BUILD_SELECTED"
BUILD_SELECTED_EXIT=$?
set -e
if ((BUILD_SELECTED_EXIT != 0)) || [[ ! -s "$BUILD_SELECTED" ]]; then
  die "could not read the exact successful build profile"
fi

PROFILE_NODE_MOUNTS=(
  --mount "type=bind,src=$BUILD_BUNDLE,dst=$BUILD_BUNDLE,readonly"
)
if ! run_profile_node - \
  "$BUILD_SELECTED" \
  "$BUILD_RUN_ID" \
  "$BUILD_BUNDLE" \
  "$BUILD_PORTABLE" \
  "$BUILD_PROFILE_FILE" \
  "$BUILD_PROFILE_SNAPSHOT" \
  >"$BUILD_IDENTITY_RECORD" <<'NODE'
const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');
const [
  selectedPath,
  runId,
  bundleDirectory,
  portableDirectory,
  candidatePath,
  candidateSnapshot,
] = process.argv.slice(2);
const selected = JSON.parse(fs.readFileSync(selectedPath, 'utf8'));
const manifest = selected.manifest;
const portableBundle = selected.portableBundle;
const candidateDescriptor = portableBundle?.files?.['candidate.json'];
const outputImageDigest = manifest?.build?.outputImageDigest;
const configDigest = manifest?.build?.configDigest;
const digestPattern = /^sha256:[a-f0-9]{64}$/u;
if (
  selected?.directory !== bundleDirectory
  || selected?.portableDirectory !== portableDirectory
  || manifest?.runId !== runId
  || manifest?.complete !== true
  || manifest?.candidateEligible !== true
  || manifest?.build?.success !== true
  || manifest?.build?.exitCode !== 0
  || !digestPattern.test(outputImageDigest || '')
  || !digestPattern.test(configDigest || '')
  || selected?.candidate?.spec?.outputImageDigest !== outputImageDigest
  || selected?.report?.build?.outputImageDigest !== outputImageDigest
  || portableBundle?.schemaVersion !== 1
  || portableBundle?.apiVersion !== 'notty.dev/v1alpha1'
  || portableBundle?.kind !== 'NoshBuildPortableBundle'
  || portableBundle?.runId !== runId
  || portableBundle?.mode !== 'build-profile'
  || portableBundle?.authoritative !== false
  || portableBundle?.attested !== false
  || portableBundle?.integrityOnly !== true
  || portableBundle?.redacted !== true
  || !digestPattern.test(portableBundle?.contentHash || '')
  || candidatePath !== path.join(portableDirectory, 'candidate.json')
  || !digestPattern.test(candidateDescriptor?.hash || '')
  || !Number.isSafeInteger(candidateDescriptor?.bytes)
  || candidateDescriptor.bytes < 1
  || candidateDescriptor.bytes > 16 * 1024 * 1024
  || candidateDescriptor?.mediaType !== 'application/json'
) {
  throw new Error(
    'successful build profile does not contain exact image and portable candidate identities',
  );
}

const candidateStat = fs.lstatSync(candidatePath);
if (candidateStat.isSymbolicLink() || !candidateStat.isFile()) {
  throw new Error('portable build candidate is not a regular non-symlink file');
}
const candidateHandle = fs.openSync(
  candidatePath,
  fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW || 0),
);
let candidateBytes;
try {
  const openedStat = fs.fstatSync(candidateHandle);
  if (!openedStat.isFile() || openedStat.size !== candidateDescriptor.bytes) {
    throw new Error('portable build candidate size does not match its descriptor');
  }
  candidateBytes = fs.readFileSync(candidateHandle);
} finally {
  fs.closeSync(candidateHandle);
}
const candidateHash = `sha256:${crypto.createHash('sha256')
  .update(candidateBytes)
  .digest('hex')}`;
if (candidateHash !== candidateDescriptor.hash) {
  throw new Error('portable build candidate does not match its descriptor hash');
}
const snapshotHandle = fs.openSync(
  candidateSnapshot,
  fs.constants.O_WRONLY | fs.constants.O_CREAT | fs.constants.O_EXCL,
  0o600,
);
try {
  fs.writeFileSync(snapshotHandle, candidateBytes);
  fs.fsyncSync(snapshotHandle);
} finally {
  fs.closeSync(snapshotHandle);
}
const runtimeGuardName = `nosh-profile-${crypto.createHash('sha256')
  .update(runId, 'utf8')
  .digest('hex')
  .slice(0, 24)}`;
for (const value of [outputImageDigest, configDigest, runtimeGuardName]) {
  process.stdout.write(`${value}\0`);
}
NODE
then
  die "could not bind runtime profiling to the exact build image and portable candidate"
fi

mapfile -d '' -t BUILD_IDENTITY_FIELDS <"$BUILD_IDENTITY_RECORD"
if ((${#BUILD_IDENTITY_FIELDS[@]} != 3)); then
  die "build image identity was truncated"
fi
BUILD_OUTPUT_IMAGE_DIGEST="${BUILD_IDENTITY_FIELDS[0]}"
BUILD_CONFIG_DIGEST="${BUILD_IDENTITY_FIELDS[1]}"
RUNTIME_GUARD_NAME="${BUILD_IDENTITY_FIELDS[2]}"
printf '%s\n' \
  "Requested image tag: $PROFILE_IMAGE" \
  "Build output digest: $BUILD_OUTPUT_IMAGE_DIGEST" \
  "Immutable local runtime image ID: $BUILD_CONFIG_DIGEST" \
  "Unique runtime Guard name: $RUNTIME_GUARD_NAME"

revalidate_directory_identity \
  'runtime workdir' "$PROFILE_WORKDIR" "$PROFILE_WORKDIR_IDENTITY"
revalidate_private_directory \
  'profile temporary directory' "$PROFILE_TMPDIR" \
  "$PROFILE_TMPDIR_IDENTITY" "$PROFILE_WORKDIR"

section "Runtime egress profile (${PROFILE_DURATION}s)"
set +e
run_interruptible "$SUDO_BIN" -- "$PRIVILEGED_GUARD_BIN" net learn \
  --duration "$PROFILE_DURATION" \
  --image "$BUILD_CONFIG_DIGEST" \
  --name "$RUNTIME_GUARD_NAME" \
  --workdir "$PROFILE_WORKDIR" \
  --no-collab \
  "$RUNTIME_APP_OPTION" \
  --json >"$RUNTIME_LEARN"
RUNTIME_EXIT=$?
set -e
revalidate_directory_identity \
  'runtime workdir' "$PROFILE_WORKDIR" "$PROFILE_WORKDIR_IDENTITY"
revalidate_private_directory \
  'profile temporary directory' "$PROFILE_TMPDIR" \
  "$PROFILE_TMPDIR_IDENTITY" "$PROFILE_WORKDIR"
if ((RUNTIME_EXIT != 0)) || [[ ! -s "$RUNTIME_LEARN" ]]; then
  printf '%s\n' \
    "Runtime profile: not created (command status $RUNTIME_EXIT)" \
    "Build profile preserved: $BUILD_PROFILE_FILE" \
    "Portable build evidence preserved: $BUILD_PORTABLE" \
    "Immutable runtime image ID: $BUILD_CONFIG_DIGEST"
  if [[ -s "$RUNTIME_LEARN" ]]; then
    printf 'Unvalidated runtime command output: %s bytes (not displayed)\n' \
      "$(stat -c '%s' -- "$RUNTIME_LEARN")"
  fi
  printf '%s\n' \
    'Inspect the retained Guard failure (read-only):'
  print_command "$SUDO_BIN" -- "$PRIVILEGED_GUARD_BIN" runs
  printf '%s\n' \
    'Retry only the runtime phase with the loaded immutable image (no rebuild):'
  print_command "$SUDO_BIN" -- "$PRIVILEGED_GUARD_BIN" net learn \
    --duration "$PROFILE_DURATION" \
    --image "$BUILD_CONFIG_DIGEST" \
    --name "${RUNTIME_GUARD_NAME}-retry" \
    --workdir "$PROFILE_WORKDIR" \
    --no-collab \
    "$RUNTIME_APP_OPTION" \
    --json
  printf '%s\n' \
    'Choose another fresh retry suffix if that diagnostic name is already reserved.'
  die "timed runtime profiling failed with status $RUNTIME_EXIT"
fi

PROFILE_NODE_MOUNTS=()
if ! run_profile_node - \
  "$RUNTIME_LEARN" \
  "$PROFILE_DURATION" \
  "$BUILD_CONFIG_DIGEST" \
  >"$RUNTIME_LEARN_RECORD" <<'NODE'
const fs = require('node:fs');
const path = require('node:path');
const [learnPath, duration, buildConfigDigest] = process.argv.slice(2);
const learned = JSON.parse(fs.readFileSync(learnPath, 'utf8'));

function exactString(value, label) {
  if (
    typeof value !== 'string'
    || !value
    || /[\0\r\n]/u.test(value)
  ) {
    throw new Error(`runtime learn receipt has an invalid ${label}`);
  }
  return value;
}

function exactAbsolutePath(value, label) {
  const selected = exactString(value, label);
  if (!path.isAbsolute(selected) || path.normalize(selected) !== selected) {
    throw new Error(`runtime learn receipt has an invalid ${label}`);
  }
  return selected;
}

if (
  learned?.apiVersion !== 'notty.dev/v1alpha1'
  || learned?.kind !== 'NoshEgressLearnResult'
  || learned?.durationSeconds !== Number(duration)
  || learned?.requestedDurationSeconds !== Number(duration)
  || learned?.imageDigest !== buildConfigDigest
  || learned?.observationComplete !== true
  || !Number.isSafeInteger(learned?.observedDurationMilliseconds)
  || learned.observedDurationMilliseconds < Number(duration) * 1000
) {
  throw new Error('runtime learn receipt has an invalid identity or duration');
}

const runId = exactString(learned.runId, 'runId');
const revision = exactString(learned.revision, 'revision');
const profileDirectory = exactAbsolutePath(
  learned.profileDirectory,
  'profileDirectory',
);
const mirrorDirectory = exactAbsolutePath(
  learned.mirrorDirectory,
  'mirrorDirectory',
);
const authoritativePolicy = exactAbsolutePath(
  learned.authoritativePolicy,
  'authoritativePolicy',
);
const mirrorPolicy = exactAbsolutePath(
  learned.mirrorPolicy,
  'mirrorPolicy',
);
const evidenceManifest = exactAbsolutePath(
  learned.evidenceManifest,
  'evidenceManifest',
);
const reviewCandidateDirectory = exactAbsolutePath(
  learned.reviewCandidateDirectory,
  'reviewCandidateDirectory',
);
const reviewTargetContext = exactAbsolutePath(
  learned.reviewTargetContext,
  'reviewTargetContext',
);
const policyHash = exactString(learned.policyHash, 'policyHash');
const profileHash = exactString(learned.profileHash, 'profileHash');
const manifestHash = exactString(learned.manifestHash, 'manifestHash');
for (const [label, value] of [
  ['policyHash', policyHash],
  ['profileHash', profileHash],
  ['manifestHash', manifestHash],
]) {
  if (!/^sha256:[a-f0-9]{64}$/u.test(value)) {
    throw new Error(`runtime learn receipt has an invalid ${label}`);
  }
}

if (runId !== revision) {
  throw new Error('runtime learn runId and revision do not match');
}
if (authoritativePolicy !== path.join(profileDirectory, 'egress-policy.json')) {
  throw new Error('runtime learn authoritativePolicy is not the exact candidate artifact');
}
if (mirrorPolicy !== path.join(mirrorDirectory, 'candidate-egress-policy.json')) {
  throw new Error('runtime learn mirrorPolicy is not the exact mirrored artifact');
}
const reviewRelative = path.relative(mirrorDirectory, reviewCandidateDirectory);
const reviewParts = reviewRelative.split(path.sep);
if (
  reviewParts.length !== 3
  || reviewParts[0] !== 'review-candidates'
  || !/^[a-f0-9]{64}$/u.test(reviewParts[1])
  || reviewParts[2] !== revision
) {
  throw new Error('runtime review candidate escaped its exact mirror namespace');
}
if (
  reviewTargetContext
    !== path.join(reviewCandidateDirectory, 'guard-ebpf-target-context.json')
) {
  throw new Error('runtime review target context is not inside its immutable export');
}
for (const value of [
  runId,
  revision,
  profileDirectory,
  mirrorDirectory,
  authoritativePolicy,
  mirrorPolicy,
  evidenceManifest,
  reviewCandidateDirectory,
  reviewTargetContext,
  policyHash,
  profileHash,
  manifestHash,
  String(learned.observedDurationMilliseconds),
]) {
  process.stdout.write(`${value}\0`);
}
NODE
then
  die "could not validate the exact runtime learn receipt"
fi

mapfile -d '' -t RUNTIME_LEARN_FIELDS <"$RUNTIME_LEARN_RECORD"
if ((${#RUNTIME_LEARN_FIELDS[@]} != 13)); then
  die "runtime learn receipt was truncated"
fi
RUNTIME_RUN_ID="${RUNTIME_LEARN_FIELDS[0]}"
RUNTIME_REVISION="${RUNTIME_LEARN_FIELDS[1]}"
RUNTIME_AUTHORITY="${RUNTIME_LEARN_FIELDS[2]}"
RUNTIME_MIRROR="${RUNTIME_LEARN_FIELDS[3]}"
validate_bind_directory 'runtime candidate mirror' "$RUNTIME_MIRROR"
RUNTIME_AUTHORITATIVE_POLICY="${RUNTIME_LEARN_FIELDS[4]}"
RUNTIME_PROFILE_FILE="${RUNTIME_LEARN_FIELDS[5]}"
RUNTIME_EVIDENCE_MANIFEST="${RUNTIME_LEARN_FIELDS[6]}"
RUNTIME_REVIEW_CANDIDATE="${RUNTIME_LEARN_FIELDS[7]}"
RUNTIME_REVIEW_TARGET_CONTEXT="${RUNTIME_LEARN_FIELDS[8]}"
RUNTIME_POLICY_HASH="${RUNTIME_LEARN_FIELDS[9]}"
RUNTIME_PROFILE_HASH="${RUNTIME_LEARN_FIELDS[10]}"
RUNTIME_MANIFEST_HASH="${RUNTIME_LEARN_FIELDS[11]}"
RUNTIME_OBSERVED_MILLISECONDS="${RUNTIME_LEARN_FIELDS[12]}"
validate_bind_directory 'runtime review candidate' "$RUNTIME_REVIEW_CANDIDATE"
if [[ ! -f "$RUNTIME_REVIEW_TARGET_CONTEXT" || -L "$RUNTIME_REVIEW_TARGET_CONTEXT" ]]; then
  die "runtime review target context is not a regular non-symlink file"
fi

set +e
run_interruptible "$SUDO_BIN" -- "$PRIVILEGED_GUARD_BIN" net status \
  --workdir "$PROFILE_WORKDIR" \
  --repair \
  --json >"$RUNTIME_STATUS"
RUNTIME_STATUS_EXIT=$?
set -e
if ((RUNTIME_STATUS_EXIT != 0)) || [[ ! -s "$RUNTIME_STATUS" ]]; then
  die "runtime profile integrity verification or mirror repair failed"
fi

PROFILE_NODE_MOUNTS=(
  --mount "type=bind,src=$PROFILE_WORKDIR,dst=$PROFILE_WORKDIR,readonly"
  --mount "type=bind,src=$RUNTIME_MIRROR,dst=$RUNTIME_MIRROR,readonly"
)
if ! run_profile_node - \
  "$RUNTIME_STATUS" \
  "$PROFILE_WORKDIR" \
  "$RUNTIME_RUN_ID" \
  "$RUNTIME_REVISION" \
  "$RUNTIME_AUTHORITY" \
  "$RUNTIME_EVIDENCE_MANIFEST" \
  "$RUNTIME_POLICY_HASH" \
  "$RUNTIME_PROFILE_HASH" \
  "$RUNTIME_MANIFEST_HASH" \
  "$RUNTIME_PROFILE_FILE" \
  "$RUNTIME_POLICY_SNAPSHOT" \
  "$PROFILE_DURATION" \
  "$RUNTIME_GUARD_NAME" \
  "$BUILD_CONFIG_DIGEST" \
  <<'NODE'
const crypto = require('node:crypto');
const fs = require('node:fs');
const [
  statusPath,
  workdir,
  runId,
  revision,
  profileDirectory,
  evidenceManifest,
  policyHash,
  profileHash,
  manifestHash,
  mirrorPolicy,
  policySnapshot,
  duration,
  runtimeGuardName,
  imageDigest,
] = process.argv.slice(2);
const status = JSON.parse(fs.readFileSync(statusPath, 'utf8'));
// The learn receipt above is the identity source. These mutable status fields
// are read only to fail closed if authoritative state drifted before review.
const candidate = status.latestCandidate;
const launch = status.lastLaunch;
const expectedWorkdir = fs.realpathSync(workdir);
if (
  status.apiVersion !== 'notty.dev/v1alpha1'
  || status.kind !== 'NoshEgressProfileReceipt'
  || status.integrity?.ok !== true
  || status.integrity?.checks?.candidate?.present !== true
  || status.integrity?.checks?.candidate?.ok !== true
  || status.integrity?.checks?.candidate?.revision !== revision
  || status.workspace?.path !== expectedWorkdir
  || candidate?.runId !== runId
  || candidate?.revision !== revision
  || candidate?.directory !== profileDirectory
  || candidate?.imageDigest !== imageDigest
  || candidate?.evidenceManifest !== evidenceManifest
  || candidate?.policyHash !== policyHash
  || candidate?.profileHash !== profileHash
  || candidate?.manifestHash !== manifestHash
  || launch?.mode !== 'egress-learn'
  || launch?.runId !== runId
  || launch?.revision !== revision
  || launch?.profileDirectory !== profileDirectory
  || candidate.launchConfig?.image !== imageDigest
  || candidate.launchConfig?.imageDigest !== imageDigest
  || candidate.launchConfig?.name !== runtimeGuardName
  || candidate.launchConfig?.observationDurationSeconds !== Number(duration)
) {
  process.stderr.write(
    'authoritative runtime status does not match the exact learn receipt\n',
  );
  process.exit(1);
}

const mirrorStat = fs.lstatSync(mirrorPolicy);
if (mirrorStat.isSymbolicLink() || !mirrorStat.isFile()) {
  throw new Error('returned runtime mirror policy is not a regular non-symlink file');
}
const noFollow = fs.constants.O_NOFOLLOW || 0;
const source = fs.openSync(mirrorPolicy, fs.constants.O_RDONLY | noFollow);
let policyBytes;
try {
  const sourceStat = fs.fstatSync(source);
  if (!sourceStat.isFile() || sourceStat.size > 16 * 1024 * 1024) {
    throw new Error('returned runtime mirror policy is not a bounded regular file');
  }
  policyBytes = fs.readFileSync(source);
} finally {
  fs.closeSync(source);
}
const actualPolicyHash = `sha256:${crypto.createHash('sha256')
  .update(policyBytes)
  .digest('hex')}`;
if (actualPolicyHash !== policyHash) {
  throw new Error('returned runtime mirror policy does not match policyHash');
}
const snapshot = fs.openSync(
  policySnapshot,
  fs.constants.O_WRONLY | fs.constants.O_CREAT | fs.constants.O_EXCL,
  0o600,
);
try {
  fs.writeFileSync(snapshot, policyBytes);
  fs.fsyncSync(snapshot);
} finally {
  fs.closeSync(snapshot);
}
NODE
then
  die "runtime profile identity changed or failed authoritative verification"
fi

section "Runtime profile result"
printf '%s\n' \
  "Revision: $RUNTIME_REVISION" \
  "Run: $RUNTIME_RUN_ID" \
  "Authoritative bundle: $RUNTIME_AUTHORITY" \
  "Candidate policy: $RUNTIME_PROFILE_FILE" \
  "User mirror: $RUNTIME_MIRROR" \
  "Runtime review candidate: $RUNTIME_REVIEW_CANDIDATE" \
  "Guard eBPF target context: $RUNTIME_REVIEW_TARGET_CONTEXT" \
  "Evidence manifest: $RUNTIME_EVIDENCE_MANIFEST" \
  "Observed duration: ${RUNTIME_OBSERVED_MILLISECONDS}ms" \
  'Authoritative integrity: verified'

section "Profile files"
printf 'Private build candidate (not printed): %s\n' "$BUILD_PRIVATE_PROFILE"
show_file \
  "Build profile (redacted CI projection)" \
  "$BUILD_PROFILE_SNAPSHOT" \
  "$BUILD_PROFILE_FILE"
printf '\n'
show_file \
  "Runtime egress policy (non-authoritative user mirror)" \
  "$RUNTIME_POLICY_SNAPSHOT" \
  "$RUNTIME_PROFILE_FILE"
printf '\nAuthoritative runtime bundle: %s\n' "$RUNTIME_AUTHORITY"
printf 'Authoritative runtime profile: %s/egress-profile.json\n' "$RUNTIME_AUTHORITY"
printf 'Authoritative runtime policy: %s\n' "$RUNTIME_AUTHORITATIVE_POLICY"

section "How to use them"
printf '%s\n' \
  'Build profile:' \
  '  Version 1 build profiles are observational and cannot be approved or enforced.' \
  "  Preserve or upload the complete portable CI bundle: $BUILD_PORTABLE" \
  '' \
  'Runtime egress profile (egress-only; ingress is not policy-enforced):' \
  "  Review input: $RUNTIME_REVIEW_CANDIDATE" \
  "  Guard eBPF target context: $RUNTIME_REVIEW_TARGET_CONTEXT" \
  '  Run ./profile-build-and-review.sh for the containerized Policy Review workflow.' \
  '  The historical net approve command does not authorize enforcement.' \
  '  Optionally audit the workspace current candidate:'
print_command \
  "$SUDO_BIN" -- "$PRIVILEGED_GUARD_BIN" net audit --workdir "$PROFILE_WORKDIR"
printf '%s\n' \
  '  After signed guard-ebpf activation, launch a fresh guarded run:'
print_command "$SUDO_BIN" -- "$PRIVILEGED_GUARD_BIN" net enforce \
  --workdir "$PROFILE_WORKDIR"
