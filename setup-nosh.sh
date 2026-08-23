#!/usr/bin/env bash
set -euo pipefail

umask 077

resolve_script_dir() {
  local source="${BASH_SOURCE[0]}"
  local dir

  while [[ -L "$source" ]]; do
    dir="$(cd -P "$(dirname "$source")" && pwd)"
    source="$(readlink "$source")"
    if [[ "$source" != /* ]]; then
      source="$dir/$source"
    fi
  done

  cd -P "$(dirname "$source")" && pwd
}

SCRIPT_DIR="$(resolve_script_dir)"
CONFIG_BIN_DIR=""
CONFIG_NOSH_BIN=""
CONFIG_GUARD_BIN=""
CONFIG_GUARD_PREFIX=""
CONFIG_PRIVILEGED_BIN=""
CONFIG_PRESENT="false"
RECEIPT_PREFIX=""
BIN_DIR_REQUESTED=""
GUARD_PREFIX_REQUESTED=""
REPLACE_LINKS="false"
REQUIRE_GUARD="false"
CHECK_ONLY="false"
POLICY_TOOLING_IMAGE_REQUESTED=""
POLICY_REVIEW_UI_IMAGE_REQUESTED=""
TEMP_LINK_DIR=""
TEMP_CONFIG=""
TEMP_IMAGE_CONFIG=""
GUARD_DETAIL=""
GUARD_REMEDIATION="install"

usage() {
  cat <<'EOF'
Usage: ./setup-nosh.sh [options]

Configure user-facing Nosh launchers and record the reviewed Guard location.
This script is unprivileged: it never invokes sudo or edits shell startup files.

Options:
  --bin-dir DIR          user launcher directory (default: ~/.local/bin)
  --guard-prefix PREFIX  privileged Guard prefix (default: receipt or /usr/local)
  --replace-links        replace conflicting symlinks, but never other objects
  --require-guard        fail after setup unless the helper and daemon are ready
  --policy-tooling-image SHA256
                         record the approved local Policy Tooling image ID
  --policy-review-ui-image SHA256
                         record the approved local Policy Review UI image ID
  --check                verify setup without changing files
  -h, --help             show this help
EOF
}

die() {
  printf 'setup-nosh: %s\n' "$*" >&2
  exit 1
}

cleanup() {
  if [[ -n "$TEMP_LINK_DIR" && -d "$TEMP_LINK_DIR" ]]; then
    rm -rf -- "$TEMP_LINK_DIR"
  fi
  if [[ -n "$TEMP_CONFIG" && -f "$TEMP_CONFIG" ]]; then
    rm -f -- "$TEMP_CONFIG"
  fi
  if [[ -n "$TEMP_IMAGE_CONFIG" && -f "$TEMP_IMAGE_CONFIG" ]]; then
    rm -f -- "$TEMP_IMAGE_CONFIG"
  fi
}

trap cleanup EXIT

path_has_control_character() {
  local value="$1"
  [[ "$value" =~ [[:cntrl:]] ]]
}

validate_absolute_path() {
  local label="$1"
  local value="$2"
  local segment
  local -a segments=()

  if [[ -z "$value" || "$value" != /* || "$value" == *//* \
    || ( "$value" != / && "$value" == */ ) ]]; then
    die "$label must be a normalized absolute path: $value"
  fi
  if path_has_control_character "$value"; then
    die "$label may not contain control characters"
  fi
  IFS=/ read -r -a segments <<<"$value"
  for segment in "${segments[@]}"; do
    if [[ "$segment" == . || "$segment" == .. ]]; then
      die "$label must be a normalized absolute path: $value"
    fi
  done
}

validate_bin_dir() {
  validate_absolute_path '--bin-dir' "$1"
  [[ "$1" != / ]] || die '--bin-dir may not be the filesystem root'
}

validate_guard_prefix() {
  local prefix="$1"
  local cursor=""
  local segment
  local metadata
  local owner
  local mode
  local -a segments=()

  validate_absolute_path '--guard-prefix' "$prefix"
  if ((${#prefix} > 512)) || \
    [[ ! "$prefix" =~ ^/[A-Za-z0-9][A-Za-z0-9._+-]*(/[A-Za-z0-9][A-Za-z0-9._+-]*)*$ ]]; then
    die '--guard-prefix must contain only portable software-path characters'
  fi
  case "$prefix" in
    /|/bin|/boot|/dev|/etc|/home|/lib|/lib64|/media|/mnt|/opt|/proc|/root|/run|/sbin|/srv|/sys|/tmp|/usr|/var)
      die "--guard-prefix is too broad: $prefix"
      ;;
  esac

  IFS=/ read -r -a segments <<<"$prefix"
  for segment in "${segments[@]}"; do
    [[ -n "$segment" ]] || continue
    cursor="$cursor/$segment"
    if [[ -L "$cursor" ]]; then
      die "--guard-prefix contains a symlink component: $cursor"
    fi
    if [[ -e "$cursor" ]]; then
      [[ -d "$cursor" ]] || die "--guard-prefix component is not a directory: $cursor"
      metadata="$(stat -Lc '%u %a' -- "$cursor" 2>/dev/null)" \
        || die "cannot inspect --guard-prefix component: $cursor"
      read -r owner mode <<<"$metadata"
      if [[ "$owner" != 0 ]] || (( (8#$mode & 8#22) != 0 )); then
        die "--guard-prefix has a non-root-owned or writable ancestor: $cursor"
      fi
    fi
  done
}

config_path_for_environment() {
  local config_home

  if [[ -n "${XDG_CONFIG_HOME:-}" ]]; then
    config_home="$XDG_CONFIG_HOME"
  else
    [[ -n "${HOME:-}" ]] || die 'HOME is required when XDG_CONFIG_HOME is not set'
    validate_absolute_path HOME "$HOME"
    config_home="$HOME/.config"
  fi
  validate_absolute_path XDG_CONFIG_HOME "$config_home"
  printf '%s/nosh/paths.conf' "$config_home"
}

review_image_config_path_for_environment() {
  local config_path
  config_path="$(config_path_for_environment)"
  printf '%s/policy-review-images.conf\n' "$(dirname "$config_path")"
}

validate_image_id() {
  local label="$1"
  local value="$2"
  [[ "$value" =~ ^sha256:[a-f0-9]{64}$ ]] \
    || die "$label must be an exact local sha256 image ID"
}

read_user_config() {
  local config_path="$1"
  local metadata
  local owner
  local mode
  local links
  local line
  local key
  local value
  local schema_version=""
  local line_number=0
  local -A seen=()

  if [[ ! -e "$config_path" && ! -L "$config_path" ]]; then
    return
  fi
  if [[ -L "$config_path" || ! -f "$config_path" ]]; then
    die "unsafe path configuration (expected a regular non-symlink): $config_path"
  fi
  metadata="$(stat -Lc '%u %a %h' -- "$config_path" 2>/dev/null)" \
    || die "cannot inspect path configuration: $config_path"
  read -r owner mode links <<<"$metadata"
  if [[ "$owner" != "$EUID" || "$mode" != 600 || "$links" != 1 ]]; then
    die "unsafe path configuration (must be owned by uid $EUID, mode 0600, and singly linked): $config_path"
  fi

  while IFS= read -r line || [[ -n "$line" ]]; do
    ((line_number += 1))
    if [[ -z "$line" || "$line" != *=* || "$line" == *$'\r'* ]]; then
      die "malformed path configuration at $config_path:$line_number"
    fi
    key="${line%%=*}"
    value="${line#*=}"
    case "$key" in
      SCHEMA_VERSION|BIN_DIR|NOSH_BIN|NOSH_GUARD_BIN|NOSH_GUARD_PREFIX|NOSH_GUARD_PRIVILEGED_BIN) ;;
      *) die "unknown path configuration key at $config_path:$line_number: $key" ;;
    esac
    if [[ -v "seen[$key]" ]]; then
      die "duplicate path configuration key at $config_path:$line_number: $key"
    fi
    seen["$key"]=1
    case "$key" in
      SCHEMA_VERSION) schema_version="$value" ;;
      BIN_DIR) CONFIG_BIN_DIR="$value" ;;
      NOSH_BIN) CONFIG_NOSH_BIN="$value" ;;
      NOSH_GUARD_BIN) CONFIG_GUARD_BIN="$value" ;;
      NOSH_GUARD_PREFIX) CONFIG_GUARD_PREFIX="$value" ;;
      NOSH_GUARD_PRIVILEGED_BIN) CONFIG_PRIVILEGED_BIN="$value" ;;
    esac
  done <"$config_path"

  for key in \
    SCHEMA_VERSION \
    BIN_DIR \
    NOSH_BIN \
    NOSH_GUARD_BIN \
    NOSH_GUARD_PREFIX \
    NOSH_GUARD_PRIVILEGED_BIN
  do
    [[ -v "seen[$key]" ]] \
      || die "missing path configuration key in $config_path: $key"
  done
  [[ "$schema_version" == 1 ]] \
    || die "unsupported path configuration schema in $config_path: $schema_version"
  validate_absolute_path BIN_DIR "$CONFIG_BIN_DIR"
  validate_absolute_path NOSH_BIN "$CONFIG_NOSH_BIN"
  validate_absolute_path NOSH_GUARD_BIN "$CONFIG_GUARD_BIN"
  validate_guard_prefix "$CONFIG_GUARD_PREFIX"
  validate_absolute_path NOSH_GUARD_PRIVILEGED_BIN "$CONFIG_PRIVILEGED_BIN"
  [[ "$CONFIG_PRIVILEGED_BIN" == "$CONFIG_GUARD_PREFIX/bin/nosh-guard" ]] \
    || die "inconsistent NOSH_GUARD_PREFIX and NOSH_GUARD_PRIVILEGED_BIN in $config_path"
  CONFIG_PRESENT="true"
}

read_layout_receipt() {
  local receipt=/etc/nosh-guard-install-layout.conf
  local metadata
  local owner
  local mode
  local links
  local line
  local key
  local value
  local schema_version=""
  local manifest_sha256=""
  local line_number=0
  local -A seen=()

  if [[ ! -e "$receipt" && ! -L "$receipt" ]]; then
    return
  fi
  if [[ -L "$receipt" || ! -f "$receipt" ]]; then
    die "unsafe Guard layout receipt: $receipt"
  fi
  metadata="$(stat -Lc '%u %a %h' -- "$receipt" 2>/dev/null)" \
    || die "cannot inspect Guard layout receipt: $receipt"
  read -r owner mode links <<<"$metadata"
  if [[ "$owner" != 0 || "$mode" != 644 || "$links" != 1 ]]; then
    die "unsafe Guard layout receipt (expected root ownership, mode 0644, and one link): $receipt"
  fi
  while IFS= read -r line || [[ -n "$line" ]]; do
    ((line_number += 1))
    [[ -n "$line" && "$line" == *=* && "$line" != *$'\r'* ]] \
      || die "malformed Guard layout receipt at $receipt:$line_number"
    key="${line%%=*}"
    value="${line#*=}"
    case "$key" in
      SCHEMA_VERSION|NOSH_GUARD_PREFIX|MANIFEST_SHA256) ;;
      *) die "unknown Guard layout receipt key at $receipt:$line_number: $key" ;;
    esac
    [[ ! -v "seen[$key]" ]] \
      || die "duplicate Guard layout receipt key at $receipt:$line_number: $key"
    seen["$key"]=1
    case "$key" in
      SCHEMA_VERSION) schema_version="$value" ;;
      NOSH_GUARD_PREFIX) RECEIPT_PREFIX="$value" ;;
      MANIFEST_SHA256) manifest_sha256="$value" ;;
    esac
  done <"$receipt"
  for key in SCHEMA_VERSION NOSH_GUARD_PREFIX MANIFEST_SHA256; do
    [[ -v "seen[$key]" ]] || die "missing Guard layout receipt key in $receipt: $key"
  done
  [[ "$schema_version" == 1 ]] || die "unsupported Guard layout receipt schema: $schema_version"
  [[ "$manifest_sha256" =~ ^[a-f0-9]{64}$ ]] \
    || die "invalid MANIFEST_SHA256 in Guard layout receipt"
  validate_guard_prefix "$RECEIPT_PREFIX"
}

preflight_directory() {
  local requested="$1"
  local cursor="$requested"

  if [[ -L "$requested" ]]; then
    die "directory may not be a symlink: $requested"
  fi
  if [[ -e "$requested" ]]; then
    [[ -d "$requested" ]] || die "expected a directory: $requested"
    [[ -w "$requested" && -x "$requested" ]] || die "directory is not writable: $requested"
    return
  fi
  while [[ ! -e "$cursor" && ! -L "$cursor" ]]; do
    cursor="$(dirname "$cursor")"
  done
  [[ ! -L "$cursor" && -d "$cursor" ]] \
    || die "cannot create directory below unsafe parent: $cursor"
  [[ -w "$cursor" && -x "$cursor" ]] \
    || die "directory parent is not writable: $cursor"
}

preflight_link() {
  local destination="$1"
  local expected="$2"
  local current

  if [[ -L "$destination" ]]; then
    current="$(readlink "$destination")"
    if [[ "$current" == "$expected" ]]; then
      return
    fi
    [[ "$REPLACE_LINKS" == "true" ]] \
      || die "conflicting symlink (use --replace-links to replace it): $destination -> $current"
    return
  fi
  if [[ -e "$destination" ]]; then
    die "refusing to replace non-symlink launcher: $destination"
  fi
}

install_link() {
  local destination="$1"
  local expected="$2"
  local current

  if [[ -L "$destination" ]]; then
    current="$(readlink "$destination")"
    [[ "$current" != "$expected" ]] || return 0
    [[ "$REPLACE_LINKS" == "true" ]] \
      || die "conflicting symlink appeared during setup: $destination"
  elif [[ -e "$destination" ]]; then
    die "non-symlink launcher appeared during setup: $destination"
  fi

  TEMP_LINK_DIR="$(mktemp -d "$BIN_DIR/.nosh-link.XXXXXX")"
  ln -s -- "$expected" "$TEMP_LINK_DIR/link"
  if [[ -L "$destination" ]]; then
    mv -Tf -- "$TEMP_LINK_DIR/link" "$destination"
  else
    mv -T -- "$TEMP_LINK_DIR/link" "$destination"
  fi
  rmdir -- "$TEMP_LINK_DIR"
  TEMP_LINK_DIR=""
}

expected_config_content() {
  printf '%s\n' \
    'SCHEMA_VERSION=1' \
    "BIN_DIR=$BIN_DIR" \
    "NOSH_BIN=$SCRIPT_DIR/nosh.sh" \
    "NOSH_GUARD_BIN=$SCRIPT_DIR/bin/nosh-guard" \
    "NOSH_GUARD_PREFIX=$GUARD_PREFIX" \
    "NOSH_GUARD_PRIVILEGED_BIN=$PRIVILEGED_BIN"
}

config_matches_expected() {
  local config_path="$1"
  local expected
  local current

  [[ "$CONFIG_PRESENT" == "true" ]] || return 1
  expected="$(expected_config_content)"
  current="$(<"$config_path")"
  [[ "$current" == "$expected" ]]
}

write_config() {
  local config_path="$1"
  local config_dir

  config_matches_expected "$config_path" && return
  config_dir="$(dirname "$config_path")"
  TEMP_CONFIG="$(mktemp "$config_dir/.paths.conf.XXXXXX")"
  expected_config_content >"$TEMP_CONFIG"
  chmod 0600 "$TEMP_CONFIG"
  if [[ -L "$config_path" || ( -e "$config_path" && ! -f "$config_path" ) ]]; then
    die "unsafe path configuration appeared during setup: $config_path"
  fi
  mv -Tf -- "$TEMP_CONFIG" "$config_path"
  TEMP_CONFIG=""
}

expected_review_image_config_content() {
  printf '%s\n' \
    'SCHEMA_VERSION=1' \
    "NOSH_POLICY_TOOLING_IMAGE=$POLICY_TOOLING_IMAGE_REQUESTED" \
    "NOSH_POLICY_REVIEW_UI_IMAGE=$POLICY_REVIEW_UI_IMAGE_REQUESTED"
}

write_review_image_config() {
  local config_path="$1"
  local config_dir
  local current

  [[ -n "$POLICY_TOOLING_IMAGE_REQUESTED" && -n "$POLICY_REVIEW_UI_IMAGE_REQUESTED" ]] \
    || return 0
  validate_image_id NOSH_POLICY_TOOLING_IMAGE "$POLICY_TOOLING_IMAGE_REQUESTED"
  validate_image_id NOSH_POLICY_REVIEW_UI_IMAGE "$POLICY_REVIEW_UI_IMAGE_REQUESTED"
  config_dir="$(dirname "$config_path")"
  current=""
  if [[ -f "$config_path" && ! -L "$config_path" ]]; then
    current="$(<"$config_path")"
  fi
  [[ "$current" == "$(expected_review_image_config_content)" ]] && return 0
  TEMP_IMAGE_CONFIG="$(mktemp "$config_dir/.policy-review-images.conf.XXXXXX")"
  expected_review_image_config_content >"$TEMP_IMAGE_CONFIG"
  chmod 0600 "$TEMP_IMAGE_CONFIG"
  if [[ -L "$config_path" || ( -e "$config_path" && ! -f "$config_path" ) ]]; then
    die "unsafe Policy Review image configuration appeared during setup: $config_path"
  fi
  mv -Tf -- "$TEMP_IMAGE_CONFIG" "$config_path"
  TEMP_IMAGE_CONFIG=""
}

link_matches() {
  local destination="$1"
  local expected="$2"
  [[ -L "$destination" && "$(readlink "$destination")" == "$expected" ]]
}

privileged_guard_ready() {
  local helper="$1"
  local resolved
  local cursor
  local metadata
  local owner
  local mode
  local links

  GUARD_REMEDIATION="install"

  resolved="$(realpath -e -- "$helper" 2>/dev/null)" || {
    GUARD_DETAIL="trusted privileged helper is missing: $helper"
    return 1
  }
  if [[ ! -f "$resolved" ]]; then
    GUARD_DETAIL="trusted privileged helper is not a regular file: $resolved"
    return 1
  fi
  metadata="$(stat -Lc '%u %a %h' -- "$resolved" 2>/dev/null)" || {
    GUARD_DETAIL="cannot inspect privileged helper: $resolved"
    return 1
  }
  read -r owner mode links <<<"$metadata"
  if [[ "$owner" != 0 || "$links" != 1 ]] \
    || (( (8#$mode & 8#22) != 0 || (8#$mode & 8#111) == 0 )); then
    GUARD_DETAIL="privileged helper is not root-owned and protected: $resolved"
    return 1
  fi
  cursor="$(dirname "$resolved")"
  while :; do
    if [[ -L "$cursor" || ! -d "$cursor" ]]; then
      GUARD_DETAIL="privileged helper has an unsafe ancestor: $cursor"
      return 1
    fi
    metadata="$(stat -Lc '%u %a' -- "$cursor" 2>/dev/null)" || {
      GUARD_DETAIL="cannot inspect privileged helper ancestor: $cursor"
      return 1
    }
    read -r owner mode <<<"$metadata"
    if [[ "$owner" != 0 ]] || (( (8#$mode & 8#22) != 0 )); then
      GUARD_DETAIL="privileged helper has an unprotected ancestor: $cursor"
      return 1
    fi
    [[ "$cursor" == / ]] && break
    cursor="$(dirname "$cursor")"
  done
  GUARD_REMEDIATION="daemon"
  if [[ ! -S /run/nosh-guardd.sock ]]; then
    GUARD_DETAIL='Guard daemon socket is unavailable: /run/nosh-guardd.sock'
    return 1
  fi
  GUARD_DETAIL=""
  GUARD_REMEDIATION=""
  return 0
}

print_install_recipe() {
  printf '\nNosh Guard is not ready: %s\n' "$GUARD_DETAIL" >&2
  printf '%s\n' 'Review, build and verify unprivileged, then run only the installer with sudo:' >&2
  printf '%s\n' '  # Docker is required; the bundle build itself is unprivileged and containerized.' >&2
  printf '%s\n' \
    '  (' \
    '    set -euo pipefail' \
    '    work_dir="$(mktemp -d)"' \
    '    trap '\''rm -rf -- "$work_dir"'\'' EXIT' \
    '    artifact_dir="$work_dir/artifacts"' \
    '    extract_dir="$work_dir/extracted"' \
    '    install -d -m 0700 "$artifact_dir" "$extract_dir"' >&2
  printf '    %q --output-dir "$artifact_dir"\n' \
    "$SCRIPT_DIR/scripts/build-nosh-guard-host-bundle.sh" >&2
  printf '%s\n' \
    '    shopt -s nullglob' \
    '    archives=("$artifact_dir"/*.tar.gz)' \
    '    checksums=("$artifact_dir"/*.tar.gz.sha256)' \
    '    if (( ${#archives[@]} != 1 || ${#checksums[@]} != 1 )); then' \
    '      printf '\''expected exactly one Nosh Guard archive and checksum\n'\'' >&2' \
    '      exit 1' \
    '    fi' \
    '    archive="${archives[0]}"' \
    '    checksum="${checksums[0]}"' \
    '    if [[ ! -f "$archive" || -L "$archive" || ! -f "$checksum" || -L "$checksum"' \
    '      || "$checksum" != "$archive.sha256" ]]; then' \
    '      printf '\''Nosh Guard archive or checksum is unsafe or mismatched\n'\'' >&2' \
    '      exit 1' \
    '    fi' \
    '    (cd "$artifact_dir" && sha256sum --check --strict -- "$(basename "$checksum")")' \
    '    tar -xzf "$archive" -C "$extract_dir"' \
    '    installers=("$extract_dir"/*/install.sh)' \
    '    if (( ${#installers[@]} != 1 )) || [[ ! -f "${installers[0]}"' \
    '      || -L "${installers[0]}" || ! -x "${installers[0]}" ]]; then' \
    '      printf '\''expected exactly one safe Nosh Guard installer\n'\'' >&2' \
    '      exit 1' \
    '    fi' >&2
  printf '    sudo "${installers[0]}" install --prefix %q --enable-now --deep-verify\n' \
    "$GUARD_PREFIX" >&2
  printf '%s\n' '  )' >&2
}

print_guard_remediation() {
  if [[ "$GUARD_REMEDIATION" == "daemon" ]]; then
    printf '\nNosh Guard is not ready: %s\n' "$GUARD_DETAIL" >&2
    printf '%s\n' \
      'The configured privileged helper passed trust checks; troubleshoot the daemon before rebuilding:' \
      '  systemctl status nosh-guardd.service --no-pager --full' \
      '  sudo journalctl -u nosh-guardd.service -b --no-pager -n 200' \
      'After correcting the reported startup failure:' \
      '  sudo systemctl restart nosh-guardd.service' >&2
    return
  fi
  print_install_recipe
}

while (($#)); do
  case "$1" in
    --bin-dir)
      [[ -n "${2:-}" ]] || die '--bin-dir requires a value'
      BIN_DIR_REQUESTED="$2"
      shift 2
      ;;
    --bin-dir=*)
      BIN_DIR_REQUESTED="${1#*=}"
      [[ -n "$BIN_DIR_REQUESTED" ]] || die '--bin-dir requires a value'
      shift
      ;;
    --guard-prefix)
      [[ -n "${2:-}" ]] || die '--guard-prefix requires a value'
      GUARD_PREFIX_REQUESTED="$2"
      shift 2
      ;;
    --guard-prefix=*)
      GUARD_PREFIX_REQUESTED="${1#*=}"
      [[ -n "$GUARD_PREFIX_REQUESTED" ]] || die '--guard-prefix requires a value'
      shift
      ;;
    --replace-links)
      REPLACE_LINKS="true"
      shift
      ;;
    --require-guard)
      REQUIRE_GUARD="true"
      shift
      ;;
    --policy-tooling-image)
      [[ -n "${2:-}" ]] || die '--policy-tooling-image requires a value'
      POLICY_TOOLING_IMAGE_REQUESTED="$2"
      shift 2
      ;;
    --policy-tooling-image=*)
      POLICY_TOOLING_IMAGE_REQUESTED="${1#*=}"
      [[ -n "$POLICY_TOOLING_IMAGE_REQUESTED" ]] || die '--policy-tooling-image requires a value'
      shift
      ;;
    --policy-review-ui-image)
      [[ -n "${2:-}" ]] || die '--policy-review-ui-image requires a value'
      POLICY_REVIEW_UI_IMAGE_REQUESTED="$2"
      shift 2
      ;;
    --policy-review-ui-image=*)
      POLICY_REVIEW_UI_IMAGE_REQUESTED="${1#*=}"
      [[ -n "$POLICY_REVIEW_UI_IMAGE_REQUESTED" ]] || die '--policy-review-ui-image requires a value'
      shift
      ;;
    --check)
      CHECK_ONLY="true"
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      die "unknown option: $1"
      ;;
  esac
done

if [[ -n "${SUDO_UID:-}" || -n "${SUDO_GID:-}" || -n "${SUDO_USER:-}" ]]; then
  die 'do not run setup-nosh.sh through sudo; run it as the account being configured'
fi
if [[ "$CHECK_ONLY" == "true" && "$REPLACE_LINKS" == "true" ]]; then
  die '--replace-links cannot be used with --check'
fi
for command_name in chmod dirname find ln mkdir mktemp mv readlink realpath rm sort stat tail; do
  command -v "$command_name" >/dev/null 2>&1 \
    || die "required command is missing: $command_name"
done
[[ -f "$SCRIPT_DIR/nosh.sh" && -x "$SCRIPT_DIR/nosh.sh" ]] \
  || die "checkout launcher is missing or not executable: $SCRIPT_DIR/nosh.sh"
[[ -f "$SCRIPT_DIR/bin/nosh-guard" && -x "$SCRIPT_DIR/bin/nosh-guard" ]] \
  || die "checkout Guard launcher is missing or not executable: $SCRIPT_DIR/bin/nosh-guard"

CONFIG_PATH="$(config_path_for_environment)"
CONFIG_DIR="$(dirname "$CONFIG_PATH")"
IMAGE_CONFIG_PATH="$(review_image_config_path_for_environment)"
read_user_config "$CONFIG_PATH"

if [[ -n "$POLICY_TOOLING_IMAGE_REQUESTED" || -n "$POLICY_REVIEW_UI_IMAGE_REQUESTED" ]]; then
  [[ -n "$POLICY_TOOLING_IMAGE_REQUESTED" && -n "$POLICY_REVIEW_UI_IMAGE_REQUESTED" ]] \
    || die 'Policy Tooling and Policy Review UI image IDs must be configured together'
  validate_image_id NOSH_POLICY_TOOLING_IMAGE "$POLICY_TOOLING_IMAGE_REQUESTED"
  validate_image_id NOSH_POLICY_REVIEW_UI_IMAGE "$POLICY_REVIEW_UI_IMAGE_REQUESTED"
fi

if [[ -n "$BIN_DIR_REQUESTED" ]]; then
  BIN_DIR="$BIN_DIR_REQUESTED"
elif [[ "$CONFIG_PRESENT" == "true" ]]; then
  BIN_DIR="$CONFIG_BIN_DIR"
else
  [[ -n "${HOME:-}" ]] || die 'HOME is required for the default --bin-dir'
  validate_absolute_path HOME "$HOME"
  BIN_DIR="$HOME/.local/bin"
fi
validate_bin_dir "$BIN_DIR"

if [[ -n "$GUARD_PREFIX_REQUESTED" ]]; then
  GUARD_PREFIX="$GUARD_PREFIX_REQUESTED"
elif [[ "$CONFIG_PRESENT" == "true" ]]; then
  GUARD_PREFIX="$CONFIG_GUARD_PREFIX"
else
  read_layout_receipt
  GUARD_PREFIX="${RECEIPT_PREFIX:-/usr/local}"
fi
validate_guard_prefix "$GUARD_PREFIX"
PRIVILEGED_BIN="$GUARD_PREFIX/bin/nosh-guard"
NOSH_LINK="$BIN_DIR/nosh"
GUARD_LINK="$BIN_DIR/nosh-guard"

if [[ "$CHECK_ONLY" == "true" ]]; then
  config_matches_expected "$CONFIG_PATH" \
    || die "path configuration is missing or does not match this checkout: $CONFIG_PATH"
  link_matches "$NOSH_LINK" "$SCRIPT_DIR/nosh.sh" \
    || die "Nosh launcher link is missing or incorrect: $NOSH_LINK"
  link_matches "$GUARD_LINK" "$SCRIPT_DIR/bin/nosh-guard" \
    || die "Guard launcher link is missing or incorrect: $GUARD_LINK"
  if ! privileged_guard_ready "$PRIVILEGED_BIN"; then
    print_guard_remediation
    exit 1
  fi
  printf 'Nosh setup is ready: %s\n' "$BIN_DIR"
  exit 0
fi

# Validate every destination before the first filesystem update.
preflight_directory "$BIN_DIR"
preflight_directory "$CONFIG_DIR"
preflight_link "$NOSH_LINK" "$SCRIPT_DIR/nosh.sh"
preflight_link "$GUARD_LINK" "$SCRIPT_DIR/bin/nosh-guard"

(umask 022; mkdir -p -- "$BIN_DIR")
(umask 077; mkdir -p -- "$CONFIG_DIR")
install_link "$NOSH_LINK" "$SCRIPT_DIR/nosh.sh"
install_link "$GUARD_LINK" "$SCRIPT_DIR/bin/nosh-guard"
write_config "$CONFIG_PATH"
write_review_image_config "$IMAGE_CONFIG_PATH"

printf 'Configured Nosh launchers in %s\n' "$BIN_DIR"
printf 'Recorded Nosh paths in %s\n' "$CONFIG_PATH"
if [[ -n "$POLICY_TOOLING_IMAGE_REQUESTED" ]]; then
  printf 'Recorded Policy Review image IDs in %s\n' "$IMAGE_CONFIG_PATH"
fi
case ":${PATH:-}:" in
  *":$BIN_DIR:"*) ;;
  *)
    printf 'warning: %s is not in PATH; for this shell run:\n' "$BIN_DIR" >&2
    printf '  export PATH=%q:"$PATH"\n' "$BIN_DIR" >&2
    ;;
esac

if ! privileged_guard_ready "$PRIVILEGED_BIN"; then
  print_guard_remediation
  [[ "$REQUIRE_GUARD" == "false" ]] || exit 1
else
  printf 'Nosh Guard is ready: %s\n' "$PRIVILEGED_BIN"
fi
