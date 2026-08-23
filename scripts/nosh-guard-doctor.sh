#!/usr/bin/env bash
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

installed_guard_prefix() {
  local receipt=/etc/nosh-guard-install-layout.conf
  local stat_uid
  local stat_mode
  local stat_links
  local line
  local key
  local value
  local line_count=0
  local -A values=()

  if [[ -n "${NOSH_GUARD_PREFIX:-}" ]]; then
    printf '%s\n' "$NOSH_GUARD_PREFIX"
    return
  fi
  if [[ ! -e "$receipt" && ! -L "$receipt" ]]; then
    printf '%s\n' /usr/local
    return
  fi
  [[ -f "$receipt" && ! -L "$receipt" ]] || {
    printf 'nosh-guard-doctor: unsafe install receipt: %s\n' "$receipt" >&2
    return 2
  }
  read -r stat_uid stat_mode stat_links < <(stat -c '%u %a %h' -- "$receipt") || return 2
  [[ "$stat_uid" == 0 && "$stat_mode" == 644 && "$stat_links" == 1 ]] || {
    printf 'nosh-guard-doctor: unsafe install receipt metadata: %s\n' "$receipt" >&2
    return 2
  }
  while IFS= read -r line || [[ -n "$line" ]]; do
    line_count=$((line_count + 1))
    [[ "$line" =~ ^([A-Z][A-Z0-9_]*)=(.*)$ ]] || return 2
    key="${BASH_REMATCH[1]}"
    value="${BASH_REMATCH[2]}"
    [[ -z "${values[$key]+set}" ]] || return 2
    case "$key" in
      SCHEMA_VERSION|NOSH_GUARD_PREFIX|MANIFEST_SHA256) ;;
      *) return 2 ;;
    esac
    values[$key]="$value"
  done <"$receipt"
  [[ "$line_count" == 3 \
    && "${values[SCHEMA_VERSION]:-}" == 1 \
    && "${values[NOSH_GUARD_PREFIX]:-}" == /* \
    && "${values[MANIFEST_SHA256]:-}" =~ ^[a-f0-9]{64}$ ]] || return 2
  printf '%s\n' "${values[NOSH_GUARD_PREFIX]}"
}

validate_guard_prefix() {
  local prefix="$1"

  [[ "$prefix" =~ ^/[A-Za-z0-9][A-Za-z0-9._+-]*(/[A-Za-z0-9][A-Za-z0-9._+-]*)*$ ]] \
    || return 1
  case "$prefix" in
    /bin|/boot|/dev|/etc|/home|/lib|/lib64|/media|/mnt|/opt|/proc|/root|/run|/sbin|/srv|/sys|/tmp|/usr|/var)
      return 1
      ;;
  esac
}

NOSH_GUARD_DOCTOR_MODE="${NOSH_GUARD_MODE:-learn}"
NOSH_GUARD_DOCTOR_DEEP="false"
NOSH_GUARD_DOCTOR_CONFIG_DIR="${NOSH_GUARD_CONFIG_DIR:-/etc/nosh-guard}"
NOSH_GUARD_DOCTOR_STATE_DIR="${NOSH_GUARD_STATE_DIR:-/var/lib/nosh-guard}"
NOSH_GUARD_DOCTOR_SOCKET="${NOSH_GUARD_SOCKET:-/run/nosh-guardd.sock}"
NOSH_GUARD_DOCTOR_TETRAGON_SOCKET="${NOSH_GUARD_TETRAGON_SOCKET:-/run/nosh-guard/tetragon/tetragon.sock}"
NOSH_GUARD_DOCTOR_NETWORK_CONTRACT="${NOSH_GUARD_NETWORK_CONTRACT:-}"
NOSH_GUARD_DOCTOR_EGRESS_IMAGE="${NOSH_GUARD_EGRESS_IMAGE:-nosh-guard-egress:0.1}"
NOSH_GUARD_DOCTOR_RUNNER_IMAGE="${NOSH_GUARD_RUNNER_IMAGE:-nosh}"
NOSH_GUARD_DOCTOR_PREFIX="${NOSH_GUARD_PREFIX:-}"
NOSH_GUARD_DOCTOR_L4_LOADER="${NOSH_GUARD_L4_LOADER:-}"
NOSH_GUARD_DOCTOR_SCOPED_EGRESS_LOADER="${NOSH_GUARD_EGRESS_LOADER:-}"
NOSH_GUARD_DOCTOR_EGRESS_ABI_LABEL="io.notty.guard.egress-abi"
NOSH_GUARD_DOCTOR_EGRESS_ABI_VERSION="1"
NOSH_GUARD_DOCTOR_RUNNER_ABI_LABEL="io.notty.guard.runner-abi"
NOSH_GUARD_DOCTOR_RUNNER_ABI_VERSION="1"
NOSH_GUARD_DOCTOR_PYTHON_BIN="${NOSH_GUARD_DOCTOR_PYTHON_BIN:-python3}"

NOSH_GUARD_DOCTOR_PASSES=0
NOSH_GUARD_DOCTOR_WARNINGS=0
NOSH_GUARD_DOCTOR_FAILURES=0

usage() {
  cat <<'EOF'
Usage: scripts/nosh-guard-doctor.sh [options]

Read-only host readiness checks for Nosh Guard. The script never installs,
starts, stops, mounts, creates, or rewrites anything.
Python 3 is used only for strict read-only JSON syntax validation; host Node,
npm, npx, and npm exec are never invoked.

Options:
  --mode MODE               learn, audit, enforce, or egress-* (default: learn)
  --config-dir PATH         deployed config directory
  --state-dir PATH          deployed state directory
  --socket PATH             nosh-guardd Unix socket
  --tetragon-socket PATH    Tetragon Unix socket
  --network-contract PATH   legacy managed DNS/egress contract to parse
  --egress-image IMAGE      legacy trusted gateway image to inspect
  --runner-image IMAGE      guarded runner image to inspect (default: nosh)
  --guard-prefix PATH       installed Guard software prefix
  --nosh-l4-loader PATH     installed nosh_l4 loader
  --nosh-egress-loader PATH installed scoped nosh-egress loader
  --deep                    run transient eBPF feature probes and runtime reads
  -h, --help                show this help

Environment equivalents use the NOSH_GUARD_ prefix.
EOF
}

doctor_pass() {
  NOSH_GUARD_DOCTOR_PASSES=$((NOSH_GUARD_DOCTOR_PASSES + 1))
  printf '[PASS] %s\n' "$*"
}

doctor_warn() {
  NOSH_GUARD_DOCTOR_WARNINGS=$((NOSH_GUARD_DOCTOR_WARNINGS + 1))
  printf '[WARN] %s\n' "$*"
}

doctor_fail() {
  NOSH_GUARD_DOCTOR_FAILURES=$((NOSH_GUARD_DOCTOR_FAILURES + 1))
  printf '[FAIL] %s\n' "$*"
}

doctor_skip() {
  printf '[SKIP] %s\n' "$*"
}

require_option_value() {
  local option_name="$1"
  local option_value="${2:-}"

  if [[ -z "$option_value" ]]; then
    printf 'nosh-guard-doctor: %s requires a value\n' "$option_name" >&2
    exit 2
  fi
}

version_at_least() {
  local actual="$1"
  local required_major="$2"
  local required_minor="$3"
  local actual_major
  local actual_minor

  actual="${actual%%-*}"
  IFS=. read -r actual_major actual_minor _ <<< "$actual"
  actual_major="${actual_major:-0}"
  actual_minor="${actual_minor:-0}"

  if ((actual_major > required_major)); then
    return 0
  fi
  if ((actual_major == required_major && actual_minor >= required_minor)); then
    return 0
  fi
  return 1
}

find_kernel_config() {
  local kernel_release="$1"

  if [[ -r /proc/config.gz ]] && command -v zgrep >/dev/null 2>&1; then
    printf '%s' /proc/config.gz
    return
  fi
  if [[ -r "/boot/config-$kernel_release" ]]; then
    printf '%s' "/boot/config-$kernel_release"
    return
  fi
  if [[ -r "/lib/modules/$kernel_release/build/.config" ]]; then
    printf '%s' "/lib/modules/$kernel_release/build/.config"
    return
  fi
}

kernel_config_enabled() {
  local config_path="$1"
  local config_name="$2"

  if [[ "$config_path" == *.gz ]]; then
    zgrep -q "^${config_name}=y$" "$config_path"
  else
    grep -q "^${config_name}=y$" "$config_path"
  fi
}

check_kernel_config() {
  local config_path="$1"
  local config_name="$2"
  local required="$3"

  if kernel_config_enabled "$config_path" "$config_name"; then
    doctor_pass "$config_name is enabled"
  elif [[ "$required" == "true" ]]; then
    doctor_fail "$config_name is not enabled"
  else
    doctor_warn "$config_name is not enabled"
  fi
}

check_json_file() {
  local json_path="$1"
  local label="$2"

  if [[ ! -r "$json_path" ]]; then
    doctor_fail "$label is not readable: $json_path"
    return
  fi
  if ! command -v "$NOSH_GUARD_DOCTOR_PYTHON_BIN" >/dev/null 2>&1; then
    doctor_fail "Python 3 is required to parse $label"
    return
  fi
  if "$NOSH_GUARD_DOCTOR_PYTHON_BIN" -I -c \
    'import json, sys
with open(sys.argv[1], "r", encoding="utf-8") as selected:
    json.load(selected)' \
    "$json_path" >/dev/null 2>&1; then
    doctor_pass "$label parses as JSON: $json_path"
  else
    doctor_fail "$label is invalid JSON: $json_path"
  fi
}

check_pinned_command_version() {
  local command_name="$1"
  local expected_version="$2"
  local required="$3"
  local version_output

  if ! command -v "$command_name" >/dev/null 2>&1; then
    if [[ "$required" == "true" ]]; then
      doctor_fail "$command_name is not installed (expected $expected_version)"
    else
      doctor_warn "$command_name is not installed (expected $expected_version)"
    fi
    return
  fi

  version_output="$("$command_name" version 2>&1 || true)"
  if [[ "$version_output" == *"$expected_version"* ]] ||
    [[ "$version_output" == *"${expected_version#v}"* ]]; then
    doctor_pass "$command_name matches pinned version $expected_version"
  elif [[ "$required" == "true" ]]; then
    doctor_fail "$command_name version does not match $expected_version: ${version_output%%$'\n'*}"
  else
    doctor_warn "$command_name version does not match $expected_version: ${version_output%%$'\n'*}"
  fi
}

while (($#)); do
  case "$1" in
    --mode)
      require_option_value "$1" "${2:-}"
      NOSH_GUARD_DOCTOR_MODE="$2"
      shift 2
      ;;
    --mode=*)
      NOSH_GUARD_DOCTOR_MODE="${1#*=}"
      shift
      ;;
    --config-dir)
      require_option_value "$1" "${2:-}"
      NOSH_GUARD_DOCTOR_CONFIG_DIR="$2"
      shift 2
      ;;
    --state-dir)
      require_option_value "$1" "${2:-}"
      NOSH_GUARD_DOCTOR_STATE_DIR="$2"
      shift 2
      ;;
    --socket)
      require_option_value "$1" "${2:-}"
      NOSH_GUARD_DOCTOR_SOCKET="$2"
      shift 2
      ;;
    --tetragon-socket)
      require_option_value "$1" "${2:-}"
      NOSH_GUARD_DOCTOR_TETRAGON_SOCKET="$2"
      shift 2
      ;;
    --network-contract)
      require_option_value "$1" "${2:-}"
      NOSH_GUARD_DOCTOR_NETWORK_CONTRACT="$2"
      shift 2
      ;;
    --egress-image)
      require_option_value "$1" "${2:-}"
      NOSH_GUARD_DOCTOR_EGRESS_IMAGE="$2"
      shift 2
      ;;
    --runner-image)
      require_option_value "$1" "${2:-}"
      NOSH_GUARD_DOCTOR_RUNNER_IMAGE="$2"
      shift 2
      ;;
    --guard-prefix)
      require_option_value "$1" "${2:-}"
      NOSH_GUARD_DOCTOR_PREFIX="$2"
      shift 2
      ;;
    --nosh-l4-loader)
      require_option_value "$1" "${2:-}"
      NOSH_GUARD_DOCTOR_L4_LOADER="$2"
      shift 2
      ;;
    --nosh-egress-loader)
      require_option_value "$1" "${2:-}"
      NOSH_GUARD_DOCTOR_SCOPED_EGRESS_LOADER="$2"
      shift 2
      ;;
    --deep)
      NOSH_GUARD_DOCTOR_DEEP="true"
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      printf 'nosh-guard-doctor: unknown option: %s\n' "$1" >&2
      usage >&2
      exit 2
      ;;
  esac
done

if [[ -z "$NOSH_GUARD_DOCTOR_PREFIX" ]]; then
  NOSH_GUARD_DOCTOR_PREFIX="$(installed_guard_prefix)" || exit $?
fi
if ! validate_guard_prefix "$NOSH_GUARD_DOCTOR_PREFIX"; then
  printf 'nosh-guard-doctor: guard prefix must be a safe normalized software prefix\n' >&2
  exit 2
fi
if [[ -z "$NOSH_GUARD_DOCTOR_L4_LOADER" ]]; then
  NOSH_GUARD_DOCTOR_L4_LOADER="$NOSH_GUARD_DOCTOR_PREFIX/libexec/nosh-guard/nosh-l4-loader"
fi
if [[ -z "$NOSH_GUARD_DOCTOR_SCOPED_EGRESS_LOADER" ]]; then
  NOSH_GUARD_DOCTOR_SCOPED_EGRESS_LOADER="$NOSH_GUARD_DOCTOR_PREFIX/libexec/nosh-guard/nosh-egress-loader"
fi

case "$NOSH_GUARD_DOCTOR_MODE" in
  learn|audit|enforce|egress-learn|egress-audit|egress-enforce)
    ;;
  *)
    printf 'nosh-guard-doctor: invalid mode: %s\n' "$NOSH_GUARD_DOCTOR_MODE" >&2
    exit 2
    ;;
esac

NOSH_GUARD_DOCTOR_NEEDS_EBPF="false"
NOSH_GUARD_DOCTOR_NEEDS_TETRAGON="false"
NOSH_GUARD_DOCTOR_NEEDS_L4="false"
NOSH_GUARD_DOCTOR_NEEDS_SCOPED_EGRESS="false"
NOSH_GUARD_DOCTOR_NEEDS_LEGACY_GATEWAY="false"
NOSH_GUARD_DOCTOR_NEEDS_LEGACY_NETWORK_TOOLS="false"
case "$NOSH_GUARD_DOCTOR_MODE" in
  learn|audit|enforce)
    NOSH_GUARD_DOCTOR_NEEDS_EBPF="true"
    NOSH_GUARD_DOCTOR_NEEDS_TETRAGON="true"
    NOSH_GUARD_DOCTOR_NEEDS_L4="true"
    NOSH_GUARD_DOCTOR_NEEDS_LEGACY_GATEWAY="true"
    NOSH_GUARD_DOCTOR_NEEDS_LEGACY_NETWORK_TOOLS="true"
    ;;
  egress-learn|egress-audit|egress-enforce)
    NOSH_GUARD_DOCTOR_NEEDS_EBPF="true"
    NOSH_GUARD_DOCTOR_NEEDS_SCOPED_EGRESS="true"
    ;;
esac

if [[ -z "$NOSH_GUARD_DOCTOR_NETWORK_CONTRACT" ]]; then
  NOSH_GUARD_DOCTOR_NETWORK_CONTRACT="$NOSH_GUARD_DOCTOR_CONFIG_DIR/network-contract.json"
fi

printf 'Nosh Guard host doctor (mode=%s, read-only=true)\n' "$NOSH_GUARD_DOCTOR_MODE"

if [[ "$(uname -s)" == "Linux" ]]; then
  doctor_pass "host operating system is Linux"
else
  doctor_fail "eBPF sensors require Linux"
fi

NOSH_GUARD_DOCTOR_KERNEL_RELEASE="$(uname -r)"
if [[ "$NOSH_GUARD_DOCTOR_NEEDS_TETRAGON" == "true" ]]; then
  if version_at_least "$NOSH_GUARD_DOCTOR_KERNEL_RELEASE" 4 19; then
    doctor_pass "kernel $NOSH_GUARD_DOCTOR_KERNEL_RELEASE satisfies Tetragon's 4.19 minimum"
  else
    doctor_fail "kernel $NOSH_GUARD_DOCTOR_KERNEL_RELEASE is older than Tetragon's 4.19 minimum"
  fi
else
  doctor_skip "Tetragon kernel-version check is not required by $NOSH_GUARD_DOCTOR_MODE"
fi

if [[ "$NOSH_GUARD_DOCTOR_NEEDS_L4" == "true" ]]; then
  if version_at_least "$NOSH_GUARD_DOCTOR_KERNEL_RELEASE" 5 8; then
    doctor_pass "kernel satisfies nosh_l4 ring-buffer support's 5.8 minimum"
  else
    doctor_fail "$NOSH_GUARD_DOCTOR_MODE requires kernel 5.8+ for the nosh_l4 evidence sensor"
  fi
else
  doctor_skip "nosh_l4 kernel-version check is not required by $NOSH_GUARD_DOCTOR_MODE"
fi

case "$NOSH_GUARD_DOCTOR_MODE" in
  learn)
    if version_at_least "$NOSH_GUARD_DOCTOR_KERNEL_RELEASE" 5 6; then
      doctor_pass "kernel satisfies advise_seccomp's 5.6 minimum"
    else
      doctor_fail "learn mode requires kernel 5.6+ for advise_seccomp"
    fi
    ;;
  audit)
    if version_at_least "$NOSH_GUARD_DOCTOR_KERNEL_RELEASE" 5 4; then
      doctor_pass "kernel satisfies trace_dns's 5.4 minimum"
    else
      doctor_fail "audit mode requires kernel 5.4+ for trace_dns"
    fi
    ;;
esac

if [[ "$NOSH_GUARD_DOCTOR_NEEDS_EBPF" == "true" ]]; then
  if version_at_least "$NOSH_GUARD_DOCTOR_KERNEL_RELEASE" 5 10; then
    doctor_pass "kernel is new enough for the recommended modern eBPF baseline"
  else
    doctor_warn "a current 5.10+ LTS kernel is recommended"
  fi

  if [[ -r /sys/kernel/btf/vmlinux ]]; then
    doctor_pass "kernel BTF is readable at /sys/kernel/btf/vmlinux"
  else
    doctor_fail "kernel BTF is missing at /sys/kernel/btf/vmlinux"
  fi
else
  doctor_skip "BTF is not required by $NOSH_GUARD_DOCTOR_MODE"
fi

NOSH_GUARD_DOCTOR_CGROUP_TYPE="$(stat -fc %T /sys/fs/cgroup 2>/dev/null || true)"
if [[ "$NOSH_GUARD_DOCTOR_CGROUP_TYPE" == "cgroup2fs" ]]; then
  doctor_pass "cgroup v2 is mounted at /sys/fs/cgroup"
else
  doctor_fail "cgroup v2 is required; found ${NOSH_GUARD_DOCTOR_CGROUP_TYPE:-unknown}"
fi

if [[ "$NOSH_GUARD_DOCTOR_NEEDS_EBPF" == "true" ]]; then
  NOSH_GUARD_DOCTOR_BPFFS_TYPE="$(stat -fc %T /sys/fs/bpf 2>/dev/null || true)"
  if [[ "$NOSH_GUARD_DOCTOR_BPFFS_TYPE" == "bpf_fs" ]]; then
    doctor_pass "bpffs is mounted at /sys/fs/bpf"
  else
    doctor_fail "bpffs is not mounted at /sys/fs/bpf"
  fi
else
  doctor_skip "bpffs is not required by $NOSH_GUARD_DOCTOR_MODE"
fi

if [[ "$NOSH_GUARD_DOCTOR_NEEDS_EBPF" == "true" ]]; then
  NOSH_GUARD_DOCTOR_KERNEL_CONFIG="$(find_kernel_config "$NOSH_GUARD_DOCTOR_KERNEL_RELEASE")"
  if [[ -n "$NOSH_GUARD_DOCTOR_KERNEL_CONFIG" ]]; then
    doctor_pass "kernel config is readable: $NOSH_GUARD_DOCTOR_KERNEL_CONFIG"
    for NOSH_GUARD_DOCTOR_CONFIG_NAME in \
      CONFIG_BPF \
      CONFIG_BPF_SYSCALL \
      CONFIG_CGROUPS \
      CONFIG_CGROUP_BPF; do
      check_kernel_config \
        "$NOSH_GUARD_DOCTOR_KERNEL_CONFIG" \
        "$NOSH_GUARD_DOCTOR_CONFIG_NAME" \
        "true"
    done
    for NOSH_GUARD_DOCTOR_CONFIG_NAME in \
      CONFIG_BPF_JIT \
      CONFIG_BPF_EVENTS \
      CONFIG_FTRACE_SYSCALLS; do
      check_kernel_config \
        "$NOSH_GUARD_DOCTOR_KERNEL_CONFIG" \
        "$NOSH_GUARD_DOCTOR_CONFIG_NAME" \
        "$([[ "$NOSH_GUARD_DOCTOR_NEEDS_TETRAGON" == "true" ]] && printf true || printf false)"
    done
    check_kernel_config \
      "$NOSH_GUARD_DOCTOR_KERNEL_CONFIG" \
      CONFIG_BPF_LSM \
      "$([[ "$NOSH_GUARD_DOCTOR_MODE" == "enforce" ]] && printf true || printf false)"
    check_kernel_config \
      "$NOSH_GUARD_DOCTOR_KERNEL_CONFIG" \
      CONFIG_BPF_KPROBE_OVERRIDE \
      "$([[ "$NOSH_GUARD_DOCTOR_MODE" == "enforce" ]] && printf true || printf false)"
  else
    if [[ "$NOSH_GUARD_DOCTOR_MODE" == "enforce" ]]; then
      doctor_fail "kernel config is unavailable; enforcement features cannot be attested"
    else
      doctor_warn "kernel config is unavailable; required options could not be checked"
    fi
  fi
else
  doctor_skip "eBPF kernel configuration is not required by $NOSH_GUARD_DOCTOR_MODE"
fi

if [[ "$NOSH_GUARD_DOCTOR_MODE" == egress-* ]]; then
  doctor_skip "BPF and AppArmor LSMs are not policy dependencies for $NOSH_GUARD_DOCTOR_MODE"
elif [[ -r /sys/kernel/security/lsm ]]; then
  NOSH_GUARD_DOCTOR_LSMS="$(< /sys/kernel/security/lsm)"
  if [[ ",$NOSH_GUARD_DOCTOR_LSMS," == *,bpf,* ]]; then
    doctor_pass "BPF LSM is active"
  elif [[ "$NOSH_GUARD_DOCTOR_MODE" == "enforce" ]]; then
    doctor_fail "BPF LSM is not active: $NOSH_GUARD_DOCTOR_LSMS"
  else
    doctor_warn "BPF LSM is not active: $NOSH_GUARD_DOCTOR_LSMS"
  fi
  if [[ ",$NOSH_GUARD_DOCTOR_LSMS," == *,apparmor,* ]]; then
    doctor_pass "AppArmor LSM is active"
  elif [[ "$NOSH_GUARD_DOCTOR_MODE" == "enforce" ]]; then
    doctor_fail "AppArmor LSM is not active: $NOSH_GUARD_DOCTOR_LSMS"
  else
    doctor_warn "AppArmor LSM is not active: $NOSH_GUARD_DOCTOR_LSMS"
  fi
elif [[ "$NOSH_GUARD_DOCTOR_MODE" == "enforce" ]]; then
  doctor_fail "/sys/kernel/security/lsm is not readable"
else
  doctor_warn "/sys/kernel/security/lsm is not readable"
fi

if ((EUID == 0)); then
  doctor_pass "doctor is running as root for privileged runtime probes"
else
  doctor_warn "sensor installation and deep probes require root; default checks remain read-only"
fi

if command -v docker >/dev/null 2>&1; then
  doctor_pass "docker CLI is installed"
  if docker info >/dev/null 2>&1; then
    doctor_pass "Docker daemon is reachable"
    if [[ "$NOSH_GUARD_DOCTOR_NEEDS_LEGACY_GATEWAY" == "true" ]]; then
      if docker image inspect "$NOSH_GUARD_DOCTOR_EGRESS_IMAGE" >/dev/null 2>&1; then
        doctor_pass "trusted egress image is present: $NOSH_GUARD_DOCTOR_EGRESS_IMAGE"
        NOSH_GUARD_DOCTOR_EGRESS_ABI="$(
          docker image inspect \
            --format "{{ index .Config.Labels \"$NOSH_GUARD_DOCTOR_EGRESS_ABI_LABEL\" }}" \
            "$NOSH_GUARD_DOCTOR_EGRESS_IMAGE" 2>/dev/null || true
        )"
        if [[ "$NOSH_GUARD_DOCTOR_EGRESS_ABI" == "$NOSH_GUARD_DOCTOR_EGRESS_ABI_VERSION" ]]; then
          doctor_pass "trusted egress image ABI matches $NOSH_GUARD_DOCTOR_EGRESS_ABI_LABEL=$NOSH_GUARD_DOCTOR_EGRESS_ABI_VERSION"
        else
          doctor_fail "trusted egress image ABI mismatch: expected $NOSH_GUARD_DOCTOR_EGRESS_ABI_LABEL=$NOSH_GUARD_DOCTOR_EGRESS_ABI_VERSION, got ${NOSH_GUARD_DOCTOR_EGRESS_ABI:-missing}"
        fi
      else
        doctor_fail "trusted egress image is missing: $NOSH_GUARD_DOCTOR_EGRESS_IMAGE"
      fi
    else
      doctor_skip "the legacy gateway image is not used by $NOSH_GUARD_DOCTOR_MODE"
    fi
    if docker image inspect "$NOSH_GUARD_DOCTOR_RUNNER_IMAGE" >/dev/null 2>&1; then
      doctor_pass "guarded runner image is present: $NOSH_GUARD_DOCTOR_RUNNER_IMAGE"
      NOSH_GUARD_DOCTOR_RUNNER_ABI="$(
        docker image inspect \
          --format "{{ index .Config.Labels \"$NOSH_GUARD_DOCTOR_RUNNER_ABI_LABEL\" }}" \
          "$NOSH_GUARD_DOCTOR_RUNNER_IMAGE" 2>/dev/null || true
      )"
      if [[ "$NOSH_GUARD_DOCTOR_RUNNER_ABI" == "$NOSH_GUARD_DOCTOR_RUNNER_ABI_VERSION" ]]; then
        doctor_pass "guarded runner image ABI matches $NOSH_GUARD_DOCTOR_RUNNER_ABI_LABEL=$NOSH_GUARD_DOCTOR_RUNNER_ABI_VERSION"
      else
        doctor_fail "guarded runner image ABI mismatch: expected $NOSH_GUARD_DOCTOR_RUNNER_ABI_LABEL=$NOSH_GUARD_DOCTOR_RUNNER_ABI_VERSION, got ${NOSH_GUARD_DOCTOR_RUNNER_ABI:-missing}"
      fi
    else
      doctor_fail "guarded runner image is missing: $NOSH_GUARD_DOCTOR_RUNNER_IMAGE"
    fi
  else
    doctor_fail "Docker daemon is not reachable by this user"
  fi
else
  doctor_fail "docker CLI is not installed"
fi

if [[ "$NOSH_GUARD_DOCTOR_NEEDS_TETRAGON" == "true" ]]; then
  check_pinned_command_version tetra v1.7.0 true
  if [[ "$NOSH_GUARD_DOCTOR_MODE" == "enforce" ]]; then
    check_pinned_command_version ig v0.54.1 false
  else
    check_pinned_command_version ig v0.54.1 true
  fi
else
  doctor_skip "Tetragon and Inspektor Gadget are not required by $NOSH_GUARD_DOCTOR_MODE"
fi

if [[ "$NOSH_GUARD_DOCTOR_NEEDS_L4" != "true" ]]; then
  doctor_skip "nosh_l4 is not required by $NOSH_GUARD_DOCTOR_MODE"
elif [[ -x "$NOSH_GUARD_DOCTOR_L4_LOADER" ]]; then
  NOSH_GUARD_DOCTOR_L4_VERSION="$(
    "$NOSH_GUARD_DOCTOR_L4_LOADER" --version 2>&1 || true
  )"
  if [[ "$NOSH_GUARD_DOCTOR_L4_VERSION" == *"nosh-l4-loader 1 schema 1"* ]]; then
    doctor_pass "nosh_l4 loader and evidence schema match version 1"
  else
    doctor_fail "nosh_l4 loader version is unexpected: ${NOSH_GUARD_DOCTOR_L4_VERSION%%$'\n'*}"
  fi
  if ((EUID == 0)); then
    if "$NOSH_GUARD_DOCTOR_L4_LOADER" health >/dev/null 2>&1; then
      doctor_pass "nosh_l4 loader host health check completed"
    else
      doctor_fail "nosh_l4 loader host health check failed"
    fi
  else
    doctor_warn "run the doctor as root to execute nosh_l4 loader health"
  fi
else
  doctor_fail "nosh_l4 loader is not executable: $NOSH_GUARD_DOCTOR_L4_LOADER"
fi

if [[ "$NOSH_GUARD_DOCTOR_NEEDS_SCOPED_EGRESS" != "true" ]]; then
  doctor_skip "nosh-egress is not required by $NOSH_GUARD_DOCTOR_MODE"
elif [[ -x "$NOSH_GUARD_DOCTOR_SCOPED_EGRESS_LOADER" ]]; then
  NOSH_GUARD_DOCTOR_SCOPED_EGRESS_VERSION="$(
    "$NOSH_GUARD_DOCTOR_SCOPED_EGRESS_LOADER" --version 2>&1 || true
  )"
  if [[ "$NOSH_GUARD_DOCTOR_SCOPED_EGRESS_VERSION" == \
    *"nosh-egress-loader 2 schema 2 map-abi 2 program-abi 2"* ]]; then
    doctor_pass "nosh-egress loader, evidence schema, map ABI, and program ABI match version 2"
  else
    doctor_fail "nosh-egress loader version is unexpected: ${NOSH_GUARD_DOCTOR_SCOPED_EGRESS_VERSION%%$'\n'*}"
  fi
  if ((EUID == 0)); then
    if "$NOSH_GUARD_DOCTOR_SCOPED_EGRESS_LOADER" health >/dev/null 2>&1; then
      doctor_pass "nosh-egress loader host health check completed"
    else
      doctor_fail "nosh-egress loader host health check failed"
    fi
  else
    doctor_warn "run the doctor as root to execute nosh-egress loader health"
  fi
else
  doctor_fail "nosh-egress loader is not executable: $NOSH_GUARD_DOCTOR_SCOPED_EGRESS_LOADER"
fi

if [[ "$NOSH_GUARD_DOCTOR_NEEDS_LEGACY_NETWORK_TOOLS" == "true" ]]; then
  for NOSH_GUARD_DOCTOR_RUNTIME_COMMAND in nsenter ip; do
    if command -v "$NOSH_GUARD_DOCTOR_RUNTIME_COMMAND" >/dev/null 2>&1; then
      doctor_pass "$NOSH_GUARD_DOCTOR_RUNTIME_COMMAND is installed"
    else
      doctor_fail "$NOSH_GUARD_DOCTOR_RUNTIME_COMMAND is required for legacy per-run network setup"
    fi
  done
else
  doctor_skip "nsenter and ip are not used by scoped eBPF network setup"
fi

if [[ -x /usr/bin/flock ]]; then
  doctor_pass "flock is installed at /usr/bin/flock"
elif [[ -x /bin/flock ]]; then
  doctor_pass "flock is installed at /bin/flock"
else
  doctor_fail "flock is required at /usr/bin/flock or /bin/flock for daemon exclusion"
fi

if [[ "$NOSH_GUARD_DOCTOR_NEEDS_LEGACY_GATEWAY" == "true" ]]; then
  doctor_skip "host nft is not required; the legacy trusted gateway image owns its nftables policy"
else
  doctor_skip "nftables and a managed gateway are not scoped eBPF policy authorities"
fi
if [[ "$NOSH_GUARD_DOCTOR_MODE" == "enforce" ]]; then
  if command -v apparmor_parser >/dev/null 2>&1; then
    doctor_pass "apparmor_parser is installed"
  else
    doctor_fail "apparmor_parser is required in enforce mode"
  fi
elif [[ "$NOSH_GUARD_DOCTOR_MODE" == egress-* ]]; then
  doctor_skip "AppArmor candidate policy is not loaded by $NOSH_GUARD_DOCTOR_MODE"
elif command -v apparmor_parser >/dev/null 2>&1; then
  doctor_pass "apparmor_parser is installed"
else
  doctor_warn "apparmor_parser is unavailable"
fi

if [[ "$NOSH_GUARD_DOCTOR_NEEDS_TETRAGON" != "true" ]]; then
  doctor_skip "Tetragon socket is not required by $NOSH_GUARD_DOCTOR_MODE"
elif [[ -S "$NOSH_GUARD_DOCTOR_TETRAGON_SOCKET" ]]; then
  doctor_pass "Tetragon Unix socket exists: $NOSH_GUARD_DOCTOR_TETRAGON_SOCKET"
else
  doctor_fail "Tetragon Unix socket is unavailable: $NOSH_GUARD_DOCTOR_TETRAGON_SOCKET"
fi

if [[ -d "$NOSH_GUARD_DOCTOR_CONFIG_DIR" ]]; then
  doctor_pass "guard config directory exists: $NOSH_GUARD_DOCTOR_CONFIG_DIR"
else
  doctor_fail "guard config directory is missing: $NOSH_GUARD_DOCTOR_CONFIG_DIR"
fi
check_json_file "$NOSH_GUARD_DOCTOR_CONFIG_DIR/adapters.json" "adapter configuration"
if [[ "$NOSH_GUARD_DOCTOR_NEEDS_LEGACY_GATEWAY" == "true" ]]; then
  check_json_file "$NOSH_GUARD_DOCTOR_NETWORK_CONTRACT" "managed network contract"
else
  doctor_skip "the legacy managed network contract is not used by $NOSH_GUARD_DOCTOR_MODE"
fi

if [[ -d "$NOSH_GUARD_DOCTOR_STATE_DIR" ]] &&
  [[ -r "$NOSH_GUARD_DOCTOR_STATE_DIR" ]] &&
  [[ -w "$NOSH_GUARD_DOCTOR_STATE_DIR" ]]; then
  doctor_pass "guard state directory is readable and writable: $NOSH_GUARD_DOCTOR_STATE_DIR"
else
  doctor_fail "guard state directory is not ready: $NOSH_GUARD_DOCTOR_STATE_DIR"
fi

if [[ -S "$NOSH_GUARD_DOCTOR_SOCKET" ]]; then
  doctor_pass "nosh-guardd socket exists: $NOSH_GUARD_DOCTOR_SOCKET"
else
  doctor_warn "nosh-guardd socket is not active yet: $NOSH_GUARD_DOCTOR_SOCKET"
fi

doctor_pass "per-run guard networks are allocated on demand; no shared runner bridge is required"

if [[ "$NOSH_GUARD_DOCTOR_MODE" == "enforce" ]]; then
  doctor_fail \
    "standalone enforce admission is disabled until a backend evaluates the compiled ingress policy"
fi

if [[ "$NOSH_GUARD_DOCTOR_DEEP" == "true" ]]; then
  printf 'Deep probes requested; these may load and immediately detach transient eBPF programs.\n'
  if [[ "$NOSH_GUARD_DOCTOR_NEEDS_TETRAGON" != "true" ]]; then
    doctor_skip "Tetragon and Inspektor Gadget deep probes are not required by $NOSH_GUARD_DOCTOR_MODE"
  elif command -v tetra >/dev/null 2>&1; then
    if tetra probe config >/dev/null 2>&1; then
      doctor_pass "tetra probe config completed"
    else
      doctor_fail "tetra probe config failed"
    fi
    if ((EUID == 0)); then
      if tetra probe >/dev/null 2>&1; then
        doctor_pass "tetra runtime feature probe completed"
      else
        doctor_fail "tetra runtime feature probe failed"
      fi
    else
      doctor_skip "tetra runtime feature probe requires root"
    fi
  else
    doctor_skip "tetra deep probes unavailable"
  fi

  if [[ "$NOSH_GUARD_DOCTOR_NEEDS_TETRAGON" != "true" ]]; then
    :
  elif command -v ig >/dev/null 2>&1; then
    if ig list-containers \
      --runtimes docker \
      --output json >/dev/null 2>&1; then
      doctor_pass "Inspektor Gadget can enumerate Docker containers"
    else
      doctor_fail "Inspektor Gadget cannot enumerate Docker containers"
    fi
  else
    doctor_skip "Inspektor Gadget runtime probe unavailable"
  fi
else
  doctor_skip "deep eBPF/runtime probes were not requested"
fi

printf '\nSummary: %d pass, %d warning, %d failure\n' \
  "$NOSH_GUARD_DOCTOR_PASSES" \
  "$NOSH_GUARD_DOCTOR_WARNINGS" \
  "$NOSH_GUARD_DOCTOR_FAILURES"
printf 'Reference pins: %s\n' "$REPO_DIR/config/nosh-guard/versions.json"

if ((NOSH_GUARD_DOCTOR_FAILURES > 0)); then
  exit 1
fi
