#!/bin/bash
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

BUNDLE_ROOT="$(resolve_script_dir)"
PREFIX="/usr/local"
INSTALL_BASE=""
RELEASES_DIR=""
CURRENT_LINK=""
RECEIPT_PATH="/etc/nosh-guard-install-layout.conf"
ACTION="${1:-}"
REPLACE_CONFIG=0
REPLACE_SUDOERS=0
ENABLE_NOW=0
DEEP_VERIFY=0
PURGE_CONFIG=0
PURGE_STATE=0
FORCE=0
SUDOERS_GROUP=""
RECEIPT_MANIFEST_DIGEST=""
RECEIPT_PRESENT=0
SYSTEMD_WAS_ACTIVE=0
INSTALL_STAGING=""
RENDER_STAGING=""

usage() {
  cat <<'EOF'
Usage:
  ./install.sh install [options]
  ./install.sh verify [options]
  ./install.sh uninstall [options]

Common options:
  --prefix ABS             software prefix (default: /usr/local)

Install options:
  --enable-now             enable and start nosh-guardd after verification
  --replace-config         replace drifted authoritative adapter configuration
  --sudoers-group GROUP    install NOPASSWD build-session rules for GROUP
  --replace-sudoers        replace a reviewed, drifted Nosh sudoers policy
  --deep-verify            run loader health and non-attaching verifier checks

Verify options:
  --deep                   also run loader health and verifier checks

Uninstall options:
  --purge-config           remove only configuration files installed by bundle
  --purge-state            irreversibly remove /var/lib/nosh-guard
  --force                  remove deployed files even if they drifted

Uninstall preserves configuration and evidence state unless the corresponding
purge option is explicit. The archive supplies its pinned target-host Node
runtime; no action installs Docker, Tetragon, Inspektor Gadget, or toolchains.
EOF
}

cleanup() {
  if [[ -n "$INSTALL_STAGING" && -d "$INSTALL_STAGING" ]]; then
    rm -rf -- "$INSTALL_STAGING"
  fi
  if [[ -n "$RENDER_STAGING" && -d "$RENDER_STAGING" ]]; then
    rm -rf -- "$RENDER_STAGING"
  fi
}

trap cleanup EXIT

if [[ "$ACTION" == -h || "$ACTION" == --help ]]; then
  usage
  exit 0
fi
[[ -n "$ACTION" ]] || {
  usage >&2
  exit 2
}
shift

while (($#)); do
  case "$1" in
    --prefix)
      [[ -n "${2:-}" ]] || {
        printf 'install.sh: --prefix requires a value\n' >&2
        exit 2
      }
      PREFIX="$2"
      shift 2
      ;;
    --prefix=*)
      PREFIX="${1#*=}"
      shift
      ;;
    --enable-now)
      [[ "$ACTION" == install ]] || {
        printf 'install.sh: --enable-now is valid only with install\n' >&2
        exit 2
      }
      ENABLE_NOW=1
      shift
      ;;
    --replace-config)
      [[ "$ACTION" == install ]] || {
        printf 'install.sh: --replace-config is valid only with install\n' >&2
        exit 2
      }
      REPLACE_CONFIG=1
      shift
      ;;
    --replace-sudoers)
      [[ "$ACTION" == install ]] || {
        printf 'install.sh: --replace-sudoers is valid only with install\n' >&2
        exit 2
      }
      REPLACE_SUDOERS=1
      shift
      ;;
    --sudoers-group)
      [[ "$ACTION" == install && -n "${2:-}" ]] || {
        printf 'install.sh: --sudoers-group requires a value with install\n' >&2
        exit 2
      }
      SUDOERS_GROUP="$2"
      shift 2
      ;;
    --sudoers-group=*)
      [[ "$ACTION" == install ]] || {
        printf 'install.sh: --sudoers-group is valid only with install\n' >&2
        exit 2
      }
      SUDOERS_GROUP="${1#*=}"
      shift
      ;;
    --deep-verify)
      [[ "$ACTION" == install ]] || {
        printf 'install.sh: --deep-verify is valid only with install\n' >&2
        exit 2
      }
      DEEP_VERIFY=1
      shift
      ;;
    --deep)
      [[ "$ACTION" == verify ]] || {
        printf 'install.sh: --deep is valid only with verify\n' >&2
        exit 2
      }
      DEEP_VERIFY=1
      shift
      ;;
    --purge-config)
      [[ "$ACTION" == uninstall ]] || {
        printf 'install.sh: --purge-config is valid only with uninstall\n' >&2
        exit 2
      }
      PURGE_CONFIG=1
      shift
      ;;
    --purge-state)
      [[ "$ACTION" == uninstall ]] || {
        printf 'install.sh: --purge-state is valid only with uninstall\n' >&2
        exit 2
      }
      PURGE_STATE=1
      shift
      ;;
    --force)
      [[ "$ACTION" == uninstall ]] || {
        printf 'install.sh: --force is valid only with uninstall\n' >&2
        exit 2
      }
      FORCE=1
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      printf 'install.sh: unknown option: %s\n' "$1" >&2
      usage >&2
      exit 2
      ;;
  esac
done

case "$ACTION" in
  install|verify|uninstall) ;;
  *)
    printf 'install.sh: unknown action: %s\n' "$ACTION" >&2
    usage >&2
    exit 2
    ;;
esac

validate_prefix() {
  local component
  local remainder

  [[ "$PREFIX" == /* && "$PREFIX" != / ]] || {
    printf 'install.sh: --prefix must be an absolute path other than /\n' >&2
    return 1
  }
  [[ "$PREFIX" =~ ^/[A-Za-z0-9][A-Za-z0-9._+-]*(/[A-Za-z0-9][A-Za-z0-9._+-]*)*$ ]] || {
    printf 'install.sh: --prefix is not a canonical safe path: %s\n' "$PREFIX" >&2
    return 1
  }
  case "$PREFIX" in
    /bin|/boot|/dev|/etc|/home|/lib|/lib64|/media|/mnt|/opt|/proc|/root|/run|/sbin|/srv|/sys|/tmp|/usr|/var)
      printf 'install.sh: --prefix is a broad system root: %s\n' "$PREFIX" >&2
      return 1
      ;;
  esac
  remainder="${PREFIX#/}"
  while [[ -n "$remainder" ]]; do
    component="${remainder%%/*}"
    [[ "$component" != . && "$component" != .. ]] || {
      printf 'install.sh: --prefix contains an unsafe component\n' >&2
      return 1
    }
    if [[ "$remainder" == */* ]]; then
      remainder="${remainder#*/}"
    else
      remainder=""
    fi
  done
}

validate_prefix || exit 2
INSTALL_BASE="$PREFIX/lib/notty/nosh-guard"
RELEASES_DIR="$INSTALL_BASE/releases"
CURRENT_LINK="$INSTALL_BASE/current"

if ((REPLACE_SUDOERS == 1)) && [[ -z "$SUDOERS_GROUP" ]]; then
  printf 'install.sh: --replace-sudoers requires --sudoers-group\n' >&2
  exit 2
fi

[[ "${EUID:-$(id -u)}" == 0 ]] || {
  printf 'install.sh: run %s as root\n' "$ACTION" >&2
  exit 1
}

metadata_value() {
  local file="$1"
  local key="$2"
  local value

  value="$(sed -n "s/^${key}=//p" "$file")"
  [[ -n "$value" && "$value" != *$'\n'* ]] || return 1
  printf '%s' "$value"
}

load_install_receipt() {
  local expected_prefix
  local line_count
  local manifest_digest
  local schema_version

  [[ -e "$RECEIPT_PATH" || -L "$RECEIPT_PATH" ]] || return 1
  [[ -f "$RECEIPT_PATH" && ! -L "$RECEIPT_PATH" ]] || {
    printf 'install.sh: installation layout receipt is not a regular file\n' >&2
    return 2
  }
  [[ "$(stat -Lc '%u %a %h' "$RECEIPT_PATH")" == '0 644 1' ]] || {
    printf 'install.sh: installation layout receipt has unsafe owner/mode/links\n' >&2
    return 2
  }
  if sed -nE \
    '/^(SCHEMA_VERSION|NOSH_GUARD_PREFIX|MANIFEST_SHA256)=/!p' \
    "$RECEIPT_PATH" | grep -q .
  then
    printf 'install.sh: installation layout receipt has unknown fields\n' >&2
    return 2
  fi
  line_count="$(sed -n '$=' "$RECEIPT_PATH")"
  [[ "$line_count" == 3 ]] || {
    printf 'install.sh: installation layout receipt has an invalid field count\n' >&2
    return 2
  }
  schema_version="$(metadata_value "$RECEIPT_PATH" SCHEMA_VERSION)" || return 2
  expected_prefix="$(metadata_value "$RECEIPT_PATH" NOSH_GUARD_PREFIX)" || return 2
  manifest_digest="$(metadata_value "$RECEIPT_PATH" MANIFEST_SHA256)" || return 2
  [[ "$schema_version" == 1 ]] || {
    printf 'install.sh: unsupported installation layout receipt schema\n' >&2
    return 2
  }
  [[ "$expected_prefix" == /* && "$expected_prefix" != / && \
    "$expected_prefix" =~ ^/[A-Za-z0-9][A-Za-z0-9._+-]*(/[A-Za-z0-9][A-Za-z0-9._+-]*)*$ ]] || {
    printf 'install.sh: installation layout receipt contains an unsafe prefix\n' >&2
    return 2
  }
  [[ "$manifest_digest" =~ ^[a-f0-9]{64}$ ]] || {
    printf 'install.sh: installation layout receipt contains an invalid manifest digest\n' >&2
    return 2
  }
  RECEIPT_MANIFEST_DIGEST="$manifest_digest"
  RECEIPT_PRESENT=1
  [[ "$expected_prefix" == "$PREFIX" ]] || {
    printf 'install.sh: existing installation uses prefix %s; refusing cross-prefix %s\n' \
      "$expected_prefix" "$PREFIX" >&2
    return 2
  }
}

write_install_receipt() {
  local manifest_digest="$1"
  local temporary

  temporary="$(mktemp /etc/.nosh-guard-install-layout.XXXXXX)"
  printf '%s\n' \
    'SCHEMA_VERSION=1' \
    "NOSH_GUARD_PREFIX=$PREFIX" \
    "MANIFEST_SHA256=$manifest_digest" \
    >"$temporary"
  chown root:root "$temporary"
  chmod 0644 "$temporary"
  mv -Tf -- "$temporary" "$RECEIPT_PATH"
  [[ "$(stat -Lc '%u %a %h' "$RECEIPT_PATH")" == '0 644 1' ]] || {
    printf 'install.sh: could not create a safe installation layout receipt\n' >&2
    return 1
  }
}

verify_manifest_tree() {
  local root_path="$1"
  local context="$2"
  local expected_inventory
  local actual_inventory

  [[ -f "$root_path/manifest.sha256" && \
    ! -L "$root_path/manifest.sha256" ]] || {
    printf 'install.sh: %s manifest is missing\n' "$context" >&2
    return 1
  }
  if find "$root_path" -type l -print -quit | grep -q .; then
    printf 'install.sh: %s contains an unsupported symlink\n' "$context" >&2
    return 1
  fi
  if find "$root_path" ! -type d ! -type f -print -quit | grep -q .; then
    printf 'install.sh: %s contains an unsupported filesystem object\n' \
      "$context" >&2
    return 1
  fi
  if find "$root_path" -type f -links +1 -print -quit | grep -q .; then
    printf 'install.sh: %s contains a multiply linked file\n' "$context" >&2
    return 1
  fi

  expected_inventory="$(mktemp)"
  actual_inventory="$(mktemp)"
  sed -nE 's/^[a-f0-9]{64}  (\.\/.*)$/\1/p' \
    "$root_path/manifest.sha256" | LC_ALL=C sort >"$expected_inventory"
  (
    cd "$root_path"
    LC_ALL=C find . -type f ! -path ./manifest.sha256 | LC_ALL=C sort
  ) >"$actual_inventory"
  if ! cmp -s "$expected_inventory" "$actual_inventory"; then
    rm -f -- "$expected_inventory" "$actual_inventory"
    printf 'install.sh: %s manifest inventory is incomplete\n' \
      "$context" >&2
    return 1
  fi
  rm -f -- "$expected_inventory" "$actual_inventory"
  (
    cd "$root_path"
    sha256sum --check --strict --quiet manifest.sha256
  )
}

verify_bundle() {
  local trusted_uid="${SUDO_UID:-0}"
  local parent_mode

  [[ "$trusted_uid" =~ ^[0-9]+$ ]] || {
    printf 'install.sh: invalid invoking-user identity\n' >&2
    return 1
  }
  if find "$BUNDLE_ROOT" ! -uid "$trusted_uid" -print -quit | grep -q .; then
    printf 'install.sh: bundle must be owned entirely by the invoking user\n' >&2
    return 1
  fi
  if find "$BUNDLE_ROOT" -perm /022 -print -quit | grep -q .; then
    printf 'install.sh: bundle must not be group- or other-writable\n' >&2
    return 1
  fi
  parent_mode="$(stat -Lc '%a' "$(dirname "$BUNDLE_ROOT")")"
  if (( (8#$parent_mode & 8#22) != 0 )); then
    printf 'install.sh: bundle parent must not be group- or other-writable\n' >&2
    return 1
  fi

  [[ -f "$BUNDLE_ROOT/bundle.env" && ! -L "$BUNDLE_ROOT/bundle.env" ]] || {
    printf 'install.sh: bundle metadata is missing\n' >&2
    return 1
  }
  verify_manifest_tree "$BUNDLE_ROOT" bundle
}

check_node_runtime() {
  local node_binary="$1"
  local expected_version="$2"
  local expected_sha256="$3"
  local metadata

  [[ -f "$node_binary" && ! -L "$node_binary" && -x "$node_binary" ]] || {
    printf 'install.sh: bundled Node runtime is missing: %s\n' \
      "$node_binary" >&2
    return 1
  }
  metadata="$(stat -Lc '%u %a' "$node_binary")"
  if [[ "$metadata" != '0 755' ]]; then
    printf 'install.sh: bundled Node runtime has unsafe owner/mode: %s\n' \
      "$metadata" >&2
    return 1
  fi
  [[ "$(sha256sum "$node_binary" | awk '{print $1}')" == "$expected_sha256" ]] || {
    printf 'install.sh: bundled Node checksum does not match metadata\n' >&2
    return 1
  }
  [[ "$($node_binary --version)" == "$expected_version" ]] || {
    printf 'install.sh: %s must report exact version %s\n' \
      "$node_binary" "$expected_version" >&2
    return 1
  }
}

assert_safe_install_base() {
  local ancestor=""
  local component
  local remainder="${PREFIX#/}"

  check_managed_directory /
  while [[ -n "$remainder" ]]; do
    component="${remainder%%/*}"
    ancestor="$ancestor/$component"
    check_managed_directory "$ancestor"
    if [[ "$remainder" == */* ]]; then
      remainder="${remainder#*/}"
    else
      remainder=""
    fi
  done
  check_managed_directory "$PREFIX/lib"
  check_managed_directory "$PREFIX/lib/notty"
  check_managed_directory "$INSTALL_BASE"
}

check_managed_directory() {
  local directory="$1"
  local mode

  [[ ! -e "$directory" && ! -L "$directory" ]] && return 0
  [[ -d "$directory" && ! -L "$directory" ]] || {
    printf 'install.sh: managed directory is unsafe: %s\n' "$directory" >&2
    return 1
  }
  [[ "$(stat -Lc '%u' "$directory")" == 0 ]] || {
    printf 'install.sh: managed directory is not root-owned: %s\n' \
      "$directory" >&2
    return 1
  }
  mode="$(stat -Lc '%a' "$directory")"
  if (( (8#$mode & 8#22) != 0 )); then
    printf 'install.sh: managed directory is writable by non-root: %s\n' \
      "$directory" >&2
    return 1
  fi
}

check_deployment_target() {
  local destination="$1"
  local metadata
  local mode

  [[ ! -e "$destination" && ! -L "$destination" ]] && return 0
  [[ -f "$destination" && ! -L "$destination" ]] || {
    printf 'install.sh: deployment target is unsafe: %s\n' "$destination" >&2
    return 1
  }
  [[ "$(stat -Lc '%u' "$destination")" == 0 ]] || {
    printf 'install.sh: deployment target is not root-owned: %s\n' \
      "$destination" >&2
    return 1
  }
  [[ "$(stat -Lc '%h' "$destination")" == 1 ]] || {
    printf 'install.sh: deployment target has multiple links: %s\n' \
      "$destination" >&2
    return 1
  }
  metadata="$(stat -Lc '%u %a' "$destination")"
  mode="${metadata#* }"
  if (( (8#$mode & 8#22) != 0 )); then
    printf 'install.sh: deployment target is writable by non-root: %s\n' \
      "$destination" >&2
    return 1
  fi
}

check_config_preflight() {
  local source_path="$1"
  local destination_path="$2"

  if [[ -L "$destination_path" || \
    ( -e "$destination_path" && ! -f "$destination_path" ) ]]; then
    printf 'install.sh: configuration target is not a regular file: %s\n' \
      "$destination_path" >&2
    return 1
  fi
  if [[ -f "$destination_path" ]] && \
    [[ "$(stat -Lc '%h' "$destination_path")" != 1 ]]; then
    printf 'install.sh: configuration target has multiple links: %s\n' \
      "$destination_path" >&2
    return 1
  fi
  if [[ -f "$destination_path" ]] && \
    ! cmp -s -- "$source_path" "$destination_path" && \
    ((REPLACE_CONFIG == 0)); then
    printf 'install.sh: authoritative configuration drifted: %s\n' \
      "$destination_path" >&2
    printf 'install.sh: review it, then re-run with --replace-config\n' >&2
    return 1
  fi
}

check_operator_config() {
  local destination_path="$1"
  local metadata

  [[ ! -e "$destination_path" && ! -L "$destination_path" ]] && return 0
  [[ -f "$destination_path" && ! -L "$destination_path" ]] || {
    printf 'install.sh: operator configuration is not a regular file: %s\n' \
      "$destination_path" >&2
    return 1
  }
  metadata="$(stat -Lc '%u %a %h' "$destination_path")"
  [[ "$metadata" == '0 640 1' ]] || {
    printf 'install.sh: operator configuration has unsafe owner/mode/links: %s\n' \
      "$destination_path" >&2
    return 1
  }
}

install_config() {
  local source_path="$1"
  local destination_path="$2"

  install -D -o root -g root -m 0640 "$source_path" "$destination_path"
}

install_sudoers() {
  local group_name="$1"
  local action="${2:-check}"
  local destination=/etc/sudoers.d/nosh-build-profile
  local metadata
  local temporary
  local expected_alias

  [[ "$group_name" =~ ^[A-Za-z_][A-Za-z0-9_-]{0,63}$ ]] || {
    printf 'install.sh: invalid sudoers group: %s\n' "$group_name" >&2
    return 1
  }
  getent group "$group_name" >/dev/null || {
    printf 'install.sh: sudoers group does not exist: %s\n' "$group_name" >&2
    return 1
  }
  command -v visudo >/dev/null 2>&1 || {
    printf 'install.sh: visudo is required for --sudoers-group\n' >&2
    return 1
  }
  temporary="$(mktemp)"
  [[ -f "$RENDER_STAGING/sudoers/nosh-build-session.alias" && \
    ! -L "$RENDER_STAGING/sudoers/nosh-build-session.alias" ]] || {
    rm -f -- "$temporary"
    printf 'install.sh: rendered sudoers alias is missing\n' >&2
    return 1
  }
  [[ "$(sed -n '$=' "$RENDER_STAGING/sudoers/nosh-build-session.alias")" == 1 ]] || {
    rm -f -- "$temporary"
    printf 'install.sh: rendered sudoers alias has an invalid shape\n' >&2
    return 1
  }
  expected_alias="$(sed -n '1p' \
    "$RENDER_STAGING/sudoers/nosh-build-session.alias")"
  printf '%s\n' \
    "$expected_alias" \
    "%${group_name} ALL=(root) NOPASSWD: NOSH_BUILD_SESSION" \
    >"$temporary"
  chmod 0440 "$temporary"
  if ! visudo -cf "$temporary" >/dev/null; then
    rm -f -- "$temporary"
    return 1
  fi
  if [[ -e /etc/sudoers.d || -L /etc/sudoers.d ]] && \
    { [[ ! -d /etc/sudoers.d || -L /etc/sudoers.d ]] || \
      [[ "$(stat -Lc '%u' /etc/sudoers.d)" != 0 ]] || \
      (( (8#$(stat -Lc '%a' /etc/sudoers.d) & 8#22) != 0 )); }
  then
    rm -f -- "$temporary"
    printf 'install.sh: /etc/sudoers.d is not a safe root-owned directory\n' >&2
    return 1
  fi
  if [[ -e "$destination" || -L "$destination" ]]; then
    if [[ ! -f "$destination" || -L "$destination" ]]; then
      rm -f -- "$temporary"
      printf 'install.sh: sudoers target is not a safe regular file: %s\n' \
        "$destination" >&2
      return 1
    fi
    if [[ "$(stat -Lc '%h' "$destination")" != 1 ]]; then
      rm -f -- "$temporary"
      printf 'install.sh: sudoers target must have one link\n' >&2
      return 1
    fi
    metadata="$(stat -Lc '%u %a' "$destination")"
    if [[ "$metadata" != '0 440' ]] && ((REPLACE_SUDOERS == 0)); then
      rm -f -- "$temporary"
      printf 'install.sh: sudoers target has unsafe owner/mode: %s\n' \
        "$metadata" >&2
      printf 'install.sh: review it, then use --replace-sudoers\n' >&2
      return 1
    fi
    if ! cmp -s -- "$temporary" "$destination" && ((REPLACE_SUDOERS == 0)); then
      rm -f -- "$temporary"
      printf 'install.sh: existing Nosh sudoers policy drifted\n' >&2
      printf 'install.sh: review it, then use --replace-sudoers\n' >&2
      return 1
    fi
  fi
  if [[ "$action" == install ]]; then
    install -D -o root -g root -m 0440 "$temporary" "$destination"
  elif [[ "$action" != check ]]; then
    rm -f -- "$temporary"
    printf 'install.sh: internal invalid sudoers action\n' >&2
    return 1
  fi
  rm -f -- "$temporary"
}

adopt_existing_sudoers_group() {
  local destination=/etc/sudoers.d/nosh-build-profile
  local expected_alias
  local first_line
  local second_line

  [[ -e "$destination" || -L "$destination" ]] || return 1
  [[ -f "$destination" && ! -L "$destination" && \
    "$(stat -Lc '%u %a %h' "$destination")" == '0 440 1' ]] || {
    printf 'install.sh: existing Nosh sudoers policy is unsafe\n' >&2
    return 2
  }
  [[ "$(sed -n '$=' "$destination")" == 2 ]] || {
    printf 'install.sh: existing Nosh sudoers policy has an invalid shape\n' >&2
    return 2
  }
  expected_alias="$(sed -n '1p' \
    "$RENDER_STAGING/sudoers/nosh-build-session.alias")"
  first_line="$(sed -n '1p' "$destination")"
  second_line="$(sed -n '2p' "$destination")"
  [[ "$first_line" == "$expected_alias" && \
    "$second_line" =~ ^%([A-Za-z_][A-Za-z0-9_-]{0,63})[[:space:]]ALL=\(root\)[[:space:]]NOPASSWD:[[:space:]]NOSH_BUILD_SESSION$ ]] || {
    printf 'install.sh: existing Nosh sudoers policy drifted\n' >&2
    return 2
  }
  SUDOERS_GROUP="${BASH_REMATCH[1]}"
}

systemd_available() {
  command -v systemctl >/dev/null 2>&1 && [[ -d /run/systemd/system ]]
}

wait_for_guard_service_ready() {
  local socket_path="$1"
  local attempt
  local consecutive_ready=0

  for ((attempt = 1; attempt <= 10; attempt += 1)); do
    if systemctl is-active --quiet nosh-guardd.service &&
      [[ -S "$socket_path" && ! -L "$socket_path" ]] &&
      [[ "$(stat -Lc '%u %a %h' -- "$socket_path" 2>/dev/null)" == '0 600 1' ]] &&
      timeout --signal=KILL 2s \
        "$PREFIX/bin/nosh-guard" runs --socket "$socket_path" \
        >/dev/null 2>&1
    then
      ((consecutive_ready += 1))
      if ((consecutive_ready >= 2)); then
        return 0
      fi
    else
      consecutive_ready=0
    fi
    if ((attempt < 10)); then
      sleep 1
    fi
  done

  printf 'install.sh: nosh-guardd did not become ready at %s\n' \
    "$socket_path" >&2
  systemctl status --no-pager --full nosh-guardd.service >&2 || true
  return 1
}

render_release_layout() {
  local release_root="$1"
  local renderer="$release_root/payload/scripts/render-nosh-guard-install.mjs"
  local runtime="$release_root/payload/runtime/node"

  [[ -f "$renderer" && ! -L "$renderer" ]] || {
    printf 'install.sh: release layout renderer is missing\n' >&2
    return 1
  }
  [[ -f "$runtime" && ! -L "$runtime" && -x "$runtime" ]] || {
    printf 'install.sh: release Node runtime is missing\n' >&2
    return 1
  }
  if [[ -n "$RENDER_STAGING" && -d "$RENDER_STAGING" ]]; then
    rm -rf -- "$RENDER_STAGING"
  fi
  RENDER_STAGING="$(mktemp -d /tmp/nosh-guard-render.XXXXXX)"
  "$runtime" "$renderer" \
    --prefix "$PREFIX" \
    --source-root "$release_root" \
    --output-dir "$RENDER_STAGING"
}

run_install() {
  local package_version
  local node_version
  local node_sha256
  local architecture
  local manifest_digest
  local release_id
  local release_path
  local release_created=0
  local receipt_status
  local current_tmp
  local verify_args=()

  for command_name in cmp find getent install readlink sha256sum sleep stat timeout uname; do
    command -v "$command_name" >/dev/null 2>&1 || {
      printf 'install.sh: required command is missing: %s\n' "$command_name" >&2
      return 1
    }
  done
  if load_install_receipt; then
    :
  else
    receipt_status=$?
    ((receipt_status == 1)) || return "$receipt_status"
    if [[ "$PREFIX" != /usr/local ]] && \
      [[ -e /etc/systemd/system/nosh-guardd.service || \
        -L /etc/systemd/system/nosh-guardd.service ]]
    then
      printf '%s\n' \
        'install.sh: an unreceipted Nosh unit already exists; refusing a custom-prefix install' >&2
      return 1
    fi
  fi
  [[ -f "$BUNDLE_ROOT/manifest.sha256" && \
    ! -L "$BUNDLE_ROOT/manifest.sha256" ]] || {
    printf 'install.sh: bundle manifest is missing\n' >&2
    return 1
  }
  manifest_digest="$(sha256sum "$BUNDLE_ROOT/manifest.sha256" | awk '{print $1}')"
  verify_bundle
  [[ "$(sha256sum "$BUNDLE_ROOT/manifest.sha256" | awk '{print $1}')" \
    == "$manifest_digest" ]] || {
    printf 'install.sh: bundle manifest changed during verification\n' >&2
    return 1
  }
  [[ "$(metadata_value "$BUNDLE_ROOT/bundle.env" BUNDLE_FORMAT)" == 2 ]] || {
    printf 'install.sh: unsupported bundle format\n' >&2
    return 1
  }
  package_version="$(metadata_value "$BUNDLE_ROOT/bundle.env" NOTTY_VERSION)"
  node_version="$(metadata_value "$BUNDLE_ROOT/bundle.env" NODE_VERSION)"
  node_sha256="$(metadata_value "$BUNDLE_ROOT/bundle.env" NODE_SHA256)"
  architecture="$(metadata_value "$BUNDLE_ROOT/bundle.env" ARCHITECTURE)"
  [[ "$package_version" =~ ^[0-9A-Za-z][0-9A-Za-z.+-]{0,63}$ ]] || {
    printf 'install.sh: unsafe bundle version\n' >&2
    return 1
  }
  [[ "$architecture" == "$(uname -m)" ]] || {
    printf 'install.sh: bundle architecture is %s, host is %s\n' \
      "$architecture" "$(uname -m)" >&2
    return 1
  }
  [[ "$node_sha256" =~ ^[a-f0-9]{64}$ ]] || {
    printf 'install.sh: invalid Node runtime checksum in bundle\n' >&2
    return 1
  }
  assert_safe_install_base
  if [[ -e "$CURRENT_LINK" || -L "$CURRENT_LINK" ]]; then
    [[ -L "$CURRENT_LINK" ]] || {
      printf 'install.sh: current release selector is not a symlink\n' >&2
      return 1
    }
    case "$(readlink -f "$CURRENT_LINK")" in
      "$RELEASES_DIR"/*) ;;
      *)
        printf 'install.sh: current release selector escaped releases\n' >&2
        return 1
        ;;
    esac
    if ((RECEIPT_PRESENT == 1)); then
      local installed_root
      installed_root="$(readlink -f "$CURRENT_LINK")"
      [[ -f "$installed_root/manifest.sha256" && \
        "$(sha256sum "$installed_root/manifest.sha256" | awk '{print $1}')" \
          == "$RECEIPT_MANIFEST_DIGEST" ]] || {
        printf 'install.sh: installation receipt does not match the current release\n' >&2
        return 1
      }
    fi
  elif ((RECEIPT_PRESENT == 1)); then
    printf 'install.sh: installation receipt exists without its current release\n' >&2
    return 1
  fi
  for managed_directory in \
    /etc \
    /etc/systemd \
    /etc/systemd/system \
    /run \
    /var \
    /var/lib \
    "$PREFIX" \
    "$PREFIX/bin" \
    "$PREFIX/lib" \
    "$PREFIX/lib/notty" \
    "$PREFIX/libexec" \
    "$PREFIX/share" \
    "$PREFIX/share/doc" \
    /etc/nosh-guard \
    /var/lib/nosh-guard \
    /run/nosh-guard \
    /run/nosh-guard/tetragon \
    "$RELEASES_DIR" \
    "$PREFIX/libexec/nosh-build" \
    "$PREFIX/libexec/nosh-guard" \
    "$PREFIX/share/doc/notty"
  do
    check_managed_directory "$managed_directory"
  done
  if ((ENABLE_NOW == 1)) && ! systemd_available; then
    printf 'install.sh: --enable-now requires a running systemd manager\n' >&2
    return 1
  fi

  for required in \
    payload/bin/nosh-gateway \
    payload/config/nosh-gateway/trust.schema.json \
    payload/docs/nosh-gateway.md \
    payload/docs/nosh-policy-review.md \
    payload/docs/nosh-http-capture-contract.md \
    payload/lib/guard/review/gateway-host.js \
    payload/lib/guardd/http-capture-manager.js \
    payload/lib/guardd/http-content-store.js \
    payload/lib/guardd/http-evidence.js \
    payload/scripts/nosh-mitmproxy-addon.py \
    payload/scripts/nosh-mitmproxy-capture.sh \
    payload/scripts/nosh-gateway.mjs \
    payload/templates/deploy/host/nosh-gateway \
    payload/templates/deploy/host/nosh-guard \
    payload/templates/deploy/host/nosh-guardd \
    payload/templates/deploy/host/nosh-guard-fail-closed \
    payload/templates/deploy/host/nosh-guard-tetragon-verify \
    payload/templates/deploy/systemd/nosh-guardd.service \
    payload/templates/deploy/systemd/nosh-guard-bpffs.service \
    payload/libexec/nosh-build/nosh-build-loader \
    payload/libexec/nosh-build/nosh-url-loader \
    payload/libexec/nosh-guard/nosh-l4-loader \
    payload/libexec/nosh-guard/nosh-egress-loader \
    payload/libexec/nosh-guard/nosh_egress.bpf.o \
    payload/libexec/nosh-guard/nosh_egress.bpf.o.sha256 \
    payload/libexec/nosh-guard/ensure-nosh-guard-bpffs \
    payload/templates/libexec/nosh-guard/nosh-guard-host-verify \
    payload/runtime/node \
    payload/docs/NODE_LICENSE \
    payload/scripts/nosh-guard-doctor.sh \
    payload/scripts/render-nosh-guard-install.mjs
  do
    [[ -f "$BUNDLE_ROOT/$required" && ! -L "$BUNDLE_ROOT/$required" ]] || {
      printf 'install.sh: required bundle file is missing: %s\n' "$required" >&2
      return 1
    }
  done

  release_id="${package_version}-${architecture}-${manifest_digest}"
  release_path="$RELEASES_DIR/$release_id"
  install -d -o root -g root -m 0755 "$RELEASES_DIR"

  if [[ -e "$release_path" || -L "$release_path" ]]; then
    [[ -d "$release_path" && ! -L "$release_path" ]] || {
      printf 'install.sh: existing release path is unsafe: %s\n' "$release_path" >&2
      return 1
    }
    if find "$release_path" \( ! -user root -o -perm /022 \) \
      -print -quit | grep -q .
    then
      printf 'install.sh: existing release has unsafe ownership or modes\n' >&2
      return 1
    fi
    [[ "$(sha256sum "$release_path/manifest.sha256" | awk '{print $1}')" \
      == "$manifest_digest" ]] || {
      printf 'install.sh: existing release manifest does not match bundle\n' >&2
      return 1
    }
    verify_manifest_tree "$release_path" 'existing release'
  else
    INSTALL_STAGING="$RELEASES_DIR/.install-$$"
    [[ ! -e "$INSTALL_STAGING" && ! -L "$INSTALL_STAGING" ]] || {
      printf 'install.sh: staging path already exists\n' >&2
      return 1
    }
    install -d -o root -g root -m 0755 "$INSTALL_STAGING"
    cp -R -- "$BUNDLE_ROOT/." "$INSTALL_STAGING/"
    chown -R root:root "$INSTALL_STAGING"
    find "$INSTALL_STAGING" -type d -exec chmod 0755 {} +
    find "$INSTALL_STAGING" -type f -exec chmod 0644 {} +
    chmod 0755 \
      "$INSTALL_STAGING/install.sh" \
      "$INSTALL_STAGING/payload/templates/deploy/host/nosh-gateway" \
      "$INSTALL_STAGING/payload/templates/deploy/host/nosh-guard" \
      "$INSTALL_STAGING/payload/templates/deploy/host/nosh-guardd" \
      "$INSTALL_STAGING/payload/templates/deploy/host/nosh-guard-fail-closed" \
      "$INSTALL_STAGING/payload/templates/deploy/host/nosh-guard-tetragon-verify" \
      "$INSTALL_STAGING/payload/libexec/nosh-build/nosh-build-loader" \
      "$INSTALL_STAGING/payload/libexec/nosh-build/nosh-url-loader" \
      "$INSTALL_STAGING/payload/libexec/nosh-guard/nosh-l4-loader" \
      "$INSTALL_STAGING/payload/libexec/nosh-guard/nosh-egress-loader" \
      "$INSTALL_STAGING/payload/libexec/nosh-guard/ensure-nosh-guard-bpffs" \
      "$INSTALL_STAGING/payload/templates/libexec/nosh-guard/nosh-guard-host-verify" \
      "$INSTALL_STAGING/payload/runtime/node" \
      "$INSTALL_STAGING/payload/scripts/nosh-guard-doctor.sh"
    [[ "$(sha256sum "$INSTALL_STAGING/manifest.sha256" | awk '{print $1}')" \
      == "$manifest_digest" ]] || {
      printf 'install.sh: bundle changed while creating root-owned staging\n' >&2
      return 1
    }
    verify_manifest_tree "$INSTALL_STAGING" 'root-owned staging'
    mv -T -- "$INSTALL_STAGING" "$release_path"
    INSTALL_STAGING=""
    release_created=1
  fi

  if ! check_node_runtime \
    "$release_path/payload/runtime/node" \
    "$node_version" \
    "$node_sha256"
  then
    if ((release_created == 1)); then
      rm -rf -- "$release_path"
    fi
    return 1
  fi

  render_release_layout "$release_path"

  check_config_preflight \
    "$RENDER_STAGING/config/nosh-guard/adapters.json" \
    /etc/nosh-guard/adapters.json
  check_config_preflight \
    "$RENDER_STAGING/config/nosh-guard/versions.json" \
    /etc/nosh-guard/versions.json
  check_config_preflight \
    "$RENDER_STAGING/config/nosh-build/adapters.json" \
    /etc/nosh-guard/build-adapters.json
  check_config_preflight \
    "$RENDER_STAGING/config/nosh-build/versions.json" \
    /etc/nosh-guard/build-versions.json
  check_operator_config /etc/nosh-guard/network-contract.json
  for deployment_target in \
    "$PREFIX/bin/nosh-gateway" \
    "$PREFIX/bin/nosh-guard" \
    "$PREFIX/bin/nosh-guardd" \
    "$PREFIX/bin/nosh-guard-fail-closed" \
    "$PREFIX/bin/nosh-guard-tetragon-verify" \
    "$PREFIX/libexec/nosh-build/nosh-build-loader" \
    "$PREFIX/libexec/nosh-build/nosh-url-loader" \
    "$PREFIX/libexec/nosh-guard/nosh-l4-loader" \
    "$PREFIX/libexec/nosh-guard/nosh-egress-loader" \
    "$PREFIX/libexec/nosh-guard/nosh_egress.bpf.o" \
    "$PREFIX/libexec/nosh-guard/nosh_egress.bpf.o.sha256" \
    "$PREFIX/libexec/nosh-guard/ensure-nosh-guard-bpffs" \
    "$PREFIX/libexec/nosh-guard/nosh-guard-host-verify" \
    /etc/systemd/system/nosh-guardd.service \
    /etc/systemd/system/nosh-guard-bpffs.service \
    "$PREFIX/share/doc/notty/nosh-guard.md" \
    "$PREFIX/share/doc/notty/nosh-gateway.md" \
    "$PREFIX/share/doc/notty/nosh-policy-review.md" \
    "$PREFIX/share/doc/notty/nosh-build-profiling.md" \
    "$PREFIX/share/doc/notty/LICENSE" \
    "$PREFIX/share/doc/notty/THIRD_PARTY_NOTICES.md" \
    "$PREFIX/share/doc/notty/NODE_LICENSE" \
    "$PREFIX/share/doc/notty/nosh-bpf-0BSD.txt" \
    "$PREFIX/share/doc/notty/nosh-bpf-GPL-2.0-only.txt" \
    "$RECEIPT_PATH"
  do
    check_deployment_target "$deployment_target"
  done

  if [[ -z "$SUDOERS_GROUP" && "$RECEIPT_PRESENT" == 1 && \
    ( -e /etc/sudoers.d/nosh-build-profile || \
      -L /etc/sudoers.d/nosh-build-profile ) ]]
  then
    adopt_existing_sudoers_group
  fi
  if [[ -n "$SUDOERS_GROUP" ]]; then
    install_sudoers "$SUDOERS_GROUP" check
  elif [[ -e /etc/sudoers.d/nosh-build-profile || \
    -L /etc/sudoers.d/nosh-build-profile ]]; then
    printf '%s\n' \
      'install.sh: existing Nosh sudoers policy requires --sudoers-group validation' >&2
    return 1
  fi

  if systemd_available && systemctl is-active --quiet nosh-guardd.service; then
    SYSTEMD_WAS_ACTIVE=1
    systemctl stop nosh-guardd.service
  fi

  install -d -o root -g root -m 0750 /etc/nosh-guard
  install -d -o root -g root -m 0700 /var/lib/nosh-guard
  install -d -o root -g root -m 0750 /run/nosh-guard/tetragon
  install -d -o root -g root -m 0755 \
    "$PREFIX/bin" \
    "$PREFIX/libexec/nosh-build" \
    "$PREFIX/libexec/nosh-guard" \
    "$PREFIX/share/doc/notty"

  current_tmp="$INSTALL_BASE/.current-$$"
  ln -s "releases/$release_id" "$current_tmp"
  mv -Tf -- "$current_tmp" "$CURRENT_LINK"

  for launcher in \
    nosh-gateway \
    nosh-guard \
    nosh-guardd \
    nosh-guard-fail-closed \
    nosh-guard-tetragon-verify
  do
    install -o root -g root -m 0755 \
      "$RENDER_STAGING/deploy/host/$launcher" \
      "$PREFIX/bin/$launcher"
  done
  install -o root -g root -m 0755 \
    "$release_path/payload/libexec/nosh-build/nosh-build-loader" \
    "$PREFIX/libexec/nosh-build/nosh-build-loader"
  install -o root -g root -m 0755 \
    "$release_path/payload/libexec/nosh-build/nosh-url-loader" \
    "$PREFIX/libexec/nosh-build/nosh-url-loader"
  install -o root -g root -m 0755 \
    "$release_path/payload/libexec/nosh-guard/nosh-l4-loader" \
    "$PREFIX/libexec/nosh-guard/nosh-l4-loader"
  install -o root -g root -m 0755 \
    "$release_path/payload/libexec/nosh-guard/nosh-egress-loader" \
    "$PREFIX/libexec/nosh-guard/nosh-egress-loader"
  install -o root -g root -m 0644 \
    "$release_path/payload/libexec/nosh-guard/nosh_egress.bpf.o" \
    "$PREFIX/libexec/nosh-guard/nosh_egress.bpf.o"
  install -o root -g root -m 0644 \
    "$release_path/payload/libexec/nosh-guard/nosh_egress.bpf.o.sha256" \
    "$PREFIX/libexec/nosh-guard/nosh_egress.bpf.o.sha256"
  install -o root -g root -m 0755 \
    "$release_path/payload/libexec/nosh-guard/ensure-nosh-guard-bpffs" \
    "$PREFIX/libexec/nosh-guard/ensure-nosh-guard-bpffs"
  install -o root -g root -m 0755 \
    "$RENDER_STAGING/libexec/nosh-guard/nosh-guard-host-verify" \
    "$PREFIX/libexec/nosh-guard/nosh-guard-host-verify"
  install_config \
    "$RENDER_STAGING/config/nosh-guard/adapters.json" \
    /etc/nosh-guard/adapters.json
  install_config \
    "$RENDER_STAGING/config/nosh-guard/versions.json" \
    /etc/nosh-guard/versions.json
  install_config \
    "$RENDER_STAGING/config/nosh-build/adapters.json" \
    /etc/nosh-guard/build-adapters.json
  install_config \
    "$RENDER_STAGING/config/nosh-build/versions.json" \
    /etc/nosh-guard/build-versions.json
  if [[ ! -e /etc/nosh-guard/network-contract.json && \
    ! -L /etc/nosh-guard/network-contract.json ]]; then
    install_config \
      "$release_path/payload/config/nosh-guard/network-contract.example.json" \
      /etc/nosh-guard/network-contract.json
  fi
  install -o root -g root -m 0644 \
    "$RENDER_STAGING/deploy/systemd/nosh-guard-bpffs.service" \
    /etc/systemd/system/nosh-guard-bpffs.service
  install -o root -g root -m 0644 \
    "$RENDER_STAGING/deploy/systemd/nosh-guardd.service" \
    /etc/systemd/system/nosh-guardd.service
  install -o root -g root -m 0644 \
    "$release_path/payload/docs/nosh-gateway.md" \
    "$PREFIX/share/doc/notty/nosh-gateway.md"
  install -o root -g root -m 0644 \
    "$release_path/payload/docs/nosh-policy-review.md" \
    "$PREFIX/share/doc/notty/nosh-policy-review.md"
  install -o root -g root -m 0644 \
    "$release_path/payload/docs/nosh-guard.md" \
    "$PREFIX/share/doc/notty/nosh-guard.md"
  install -o root -g root -m 0644 \
    "$release_path/payload/docs/nosh-build-profiling.md" \
    "$PREFIX/share/doc/notty/nosh-build-profiling.md"
  for documentation in \
    LICENSE \
    THIRD_PARTY_NOTICES.md \
    NODE_LICENSE \
    nosh-bpf-0BSD.txt \
    nosh-bpf-GPL-2.0-only.txt
  do
    install -o root -g root -m 0644 \
      "$release_path/payload/docs/$documentation" \
      "$PREFIX/share/doc/notty/$documentation"
  done

  if [[ -n "$SUDOERS_GROUP" ]]; then
    install_sudoers "$SUDOERS_GROUP" install
  fi

  write_install_receipt "$manifest_digest"

  "$PREFIX/libexec/nosh-guard/ensure-nosh-guard-bpffs"

  if ((DEEP_VERIFY == 1)); then
    verify_args+=(--deep)
  fi
  "$PREFIX/libexec/nosh-guard/nosh-guard-host-verify" \
    --prefix "$PREFIX" "${verify_args[@]}"

  if systemd_available; then
    systemctl daemon-reload
    systemctl enable --now nosh-guard-bpffs.service
    if ((ENABLE_NOW == 1)); then
      systemctl enable --now nosh-guardd.service
      wait_for_guard_service_ready /run/nosh-guardd.sock
    elif ((SYSTEMD_WAS_ACTIVE == 1)); then
      systemctl start nosh-guardd.service
      wait_for_guard_service_ready /run/nosh-guardd.sock
    fi
  fi

  printf 'install.sh: installed Nosh Guard %s\n' "$package_version"
  printf 'install.sh: current release: %s\n' "$release_path"
  if [[ -z "$SUDOERS_GROUP" ]]; then
    printf '%s\n' \
      'install.sh: no sudoers rule installed; CI users need reviewed build-session elevation'
  fi
}

managed_paths() {
  printf '%s\n' \
    "$PREFIX/bin/nosh-gateway" \
    "$PREFIX/bin/nosh-guard" \
    "$PREFIX/bin/nosh-guardd" \
    "$PREFIX/bin/nosh-guard-fail-closed" \
    "$PREFIX/bin/nosh-guard-tetragon-verify" \
    "$PREFIX/libexec/nosh-build/nosh-build-loader" \
    "$PREFIX/libexec/nosh-build/nosh-url-loader" \
    "$PREFIX/libexec/nosh-guard/nosh-l4-loader" \
    "$PREFIX/libexec/nosh-guard/nosh-egress-loader" \
    "$PREFIX/libexec/nosh-guard/nosh_egress.bpf.o" \
    "$PREFIX/libexec/nosh-guard/nosh_egress.bpf.o.sha256" \
    "$PREFIX/libexec/nosh-guard/ensure-nosh-guard-bpffs" \
    "$PREFIX/libexec/nosh-guard/nosh-guard-host-verify" \
    /etc/systemd/system/nosh-guardd.service \
    /etc/systemd/system/nosh-guard-bpffs.service \
    "$PREFIX/share/doc/notty/nosh-guard.md" \
    "$PREFIX/share/doc/notty/nosh-gateway.md" \
    "$PREFIX/share/doc/notty/nosh-policy-review.md" \
    "$PREFIX/share/doc/notty/nosh-build-profiling.md" \
    "$PREFIX/share/doc/notty/LICENSE" \
    "$PREFIX/share/doc/notty/THIRD_PARTY_NOTICES.md" \
    "$PREFIX/share/doc/notty/NODE_LICENSE" \
    "$PREFIX/share/doc/notty/nosh-bpf-0BSD.txt" \
    "$PREFIX/share/doc/notty/nosh-bpf-GPL-2.0-only.txt" \
    /etc/sudoers.d/nosh-build-profile
}

validate_sudoers_removal() {
  local destination=/etc/sudoers.d/nosh-build-profile
  local expected_alias="Cmnd_Alias NOSH_BUILD_SESSION = $PREFIX/bin/nosh-guard build-session begin, $PREFIX/bin/nosh-guard build-session finish, $PREFIX/bin/nosh-guard build-session abort, $PREFIX/bin/nosh-guard build-session exported"
  local first_line
  local line_count
  local second_line
  local sudoers_directory_metadata
  local sudoers_directory_mode

  [[ ! -e "$destination" && ! -L "$destination" ]] && return 0
  if [[ ! -d /etc/sudoers.d || -L /etc/sudoers.d ]]; then
    printf 'install.sh: refusing removal through unsafe /etc/sudoers.d\n' >&2
    return 1
  fi
  sudoers_directory_metadata="$(stat -Lc '%u %a' /etc/sudoers.d)"
  sudoers_directory_mode="${sudoers_directory_metadata#* }"
  if [[ "${sudoers_directory_metadata%% *}" != 0 ]] || \
    (( (8#$sudoers_directory_mode & 8#22) != 0 )); then
    printf 'install.sh: refusing removal through unsafe /etc/sudoers.d\n' >&2
    return 1
  fi
  if [[ ! -f "$destination" || -L "$destination" ]] || \
    [[ "$(stat -Lc '%u %a %h' "$destination")" != '0 440 1' ]]
  then
    ((FORCE == 1)) && return 0
    printf 'install.sh: refusing unsafe sudoers removal; review and use --force\n' >&2
    return 1
  fi
  first_line="$(sed -n '1p' "$destination")"
  second_line="$(sed -n '2p' "$destination")"
  line_count="$(sed -n '$=' "$destination")"
  if [[ "$line_count" != 2 ]] || \
    [[ "$first_line" != "$expected_alias" ]] || \
    [[ ! "$second_line" =~ ^%[A-Za-z_][A-Za-z0-9_-]{0,63}[[:space:]]ALL=\(root\)[[:space:]]NOPASSWD:[[:space:]]NOSH_BUILD_SESSION$ ]]
  then
    ((FORCE == 1)) && return 0
    printf 'install.sh: sudoers policy is not bundle-managed; review and use --force\n' >&2
    return 1
  fi
}

run_uninstall() {
  local current_root=""
  local deployed_path
  local receipt_status

  [[ "$INSTALL_BASE" == "$PREFIX/lib/notty/nosh-guard" && \
    "$INSTALL_BASE" != /lib/notty/nosh-guard ]] || {
    printf 'install.sh: internal unsafe uninstall root\n' >&2
    return 1
  }
  if load_install_receipt; then
    :
  else
    receipt_status=$?
    if ((receipt_status == 1)); then
      printf 'install.sh: installation layout receipt is missing\n' >&2
    fi
    return 1
  fi
  for trusted_directory in \
    "$PREFIX" \
    "$PREFIX/bin" \
    "$PREFIX/lib" \
    "$PREFIX/lib/notty" \
    "$PREFIX/libexec" \
    "$PREFIX/libexec/nosh-build" \
    "$PREFIX/libexec/nosh-guard" \
    "$PREFIX/share" \
    "$PREFIX/share/doc" \
    "$PREFIX/share/doc/notty" \
    /etc \
    /etc/nosh-guard \
    /etc/systemd \
    /etc/systemd/system \
    /var \
    /var/lib \
    /var/lib/nosh-guard \
    "$INSTALL_BASE" \
    "$RELEASES_DIR"
  do
    check_managed_directory "$trusted_directory"
  done
  if [[ -L "$CURRENT_LINK" ]]; then
    current_root="$(readlink -f "$CURRENT_LINK")"
    case "$current_root" in
      "$INSTALL_BASE"/releases/*) ;;
      *)
        printf 'install.sh: current release escaped the install root\n' >&2
        return 1
        ;;
    esac
    [[ -f "$current_root/manifest.sha256" && \
      "$(sha256sum "$current_root/manifest.sha256" | awk '{print $1}')" \
        == "$RECEIPT_MANIFEST_DIGEST" ]] || {
      printf 'install.sh: current release does not match the installation receipt\n' >&2
      return 1
    }
  elif ((FORCE == 0)); then
    printf 'install.sh: current release link is missing; use --force to continue\n' >&2
    return 1
  fi

  if [[ -n "$current_root" ]] && ((FORCE == 0)); then
    "$PREFIX/libexec/nosh-guard/nosh-guard-host-verify" \
      --prefix "$PREFIX" --service || {
      printf 'install.sh: installation verification failed; use --force only after review\n' >&2
      return 1
    }
  fi
  validate_sudoers_removal

  if systemd_available; then
    systemctl disable --now nosh-guardd.service >/dev/null 2>&1 || true
    systemctl disable --now nosh-guard-bpffs.service >/dev/null 2>&1 || true
  fi
  while IFS= read -r deployed_path; do
    rm -f -- "$deployed_path"
  done < <(managed_paths)
  if [[ -d "$INSTALL_BASE" && ! -L "$INSTALL_BASE" ]]; then
    [[ "$(stat -Lc '%u' "$INSTALL_BASE")" == 0 ]] || {
      printf 'install.sh: refusing non-root-owned install tree removal\n' >&2
      return 1
    }
    rm -rf -- "$INSTALL_BASE"
  fi
  rm -f -- "$RECEIPT_PATH"

  if ((PURGE_CONFIG == 1)); then
    rm -f -- \
      /etc/nosh-guard/adapters.json \
      /etc/nosh-guard/build-adapters.json \
      /etc/nosh-guard/build-versions.json \
      /etc/nosh-guard/network-contract.json \
      /etc/nosh-guard/versions.json
    printf 'install.sh: removed bundle-managed configuration files\n'
  else
    printf 'install.sh: preserved /etc/nosh-guard configuration\n'
  fi
  if ((PURGE_STATE == 1)); then
    [[ /var/lib/nosh-guard == /var/lib/nosh-guard ]] || return 1
    rm -rf -- /var/lib/nosh-guard
    printf 'install.sh: permanently removed /var/lib/nosh-guard evidence and state\n'
  else
    printf 'install.sh: preserved /var/lib/nosh-guard evidence and state\n'
  fi
  if systemd_available; then
    systemctl daemon-reload
  fi
  printf 'install.sh: uninstalled Nosh Guard host binaries and service\n'
}

case "$ACTION" in
  install)
    run_install
    ;;
  verify)
    verify_args=()
    ((DEEP_VERIFY == 0)) || verify_args+=(--deep)
    "$PREFIX/libexec/nosh-guard/nosh-guard-host-verify" \
      --prefix "$PREFIX" "${verify_args[@]}"
    ;;
  uninstall)
    run_uninstall
    ;;
esac
