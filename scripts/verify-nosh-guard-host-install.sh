#!/bin/bash
set -euo pipefail

umask 077

PREFIX='@@NOSH_GUARD_PREFIX@@'
INSTALL_BASE=""
CURRENT_LINK=""
RECEIPT_PATH="/etc/nosh-guard-install-layout.conf"
RECEIPT_MANIFEST_DIGEST=""
RENDER_STAGING=""
DEEP=0
SYSTEMD_UNIT_DIR=/etc/systemd/system

usage() {
  cat <<'EOF'
Usage: nosh-guard-host-verify [--prefix ABS] [--systemd-unit-dir DIR] [--deep]

Verify the installed Nosh Guard release manifest, installation-layout receipt,
root ownership and modes, fixed Node runtime, prefix-derived launchers and
loaders, fixed FHS configuration and systemd unit, and optional sudoers policy.
Generated artifacts are rerendered from the installed release and compared
byte-for-byte. Safe launcher help paths are executed to reject inert entrypoints.
--deep also runs loader prerequisite health probes and a non-attaching kernel
verifier load of the balanced build collector.
EOF
}

cleanup() {
  if [[ -n "$RENDER_STAGING" && -d "$RENDER_STAGING" ]]; then
    rm -rf -- "$RENDER_STAGING"
  fi
}

trap cleanup EXIT

while (($#)); do
  case "$1" in
    --prefix)
      [[ -n "${2:-}" ]] || {
        printf 'nosh-guard-host-verify: --prefix requires a value\n' >&2
        exit 2
      }
      PREFIX="$2"
      shift 2
      ;;
    --prefix=*)
      PREFIX="${1#*=}"
      shift
      ;;
    --deep)
      DEEP=1
      shift
      ;;
    --systemd-unit-dir)
      [[ -n "${2:-}" ]] || {
        printf 'nosh-guard-host-verify: --systemd-unit-dir requires a value\n' >&2
        exit 2
      }
      SYSTEMD_UNIT_DIR="$2"
      shift 2
      ;;
    --systemd-unit-dir=*)
      SYSTEMD_UNIT_DIR="${1#*=}"
      shift
      ;;
    --service)
      # Reserved for systemd ExecStartPre; normal integrity checks still apply.
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      printf 'nosh-guard-host-verify: unknown option: %s\n' "$1" >&2
      exit 2
      ;;
  esac
done

validate_prefix() {
  local component
  local remainder

  [[ "$PREFIX" == /* && "$PREFIX" != / ]] || {
    printf '%s\n' \
      'nosh-guard-host-verify: --prefix must be an absolute path other than /' >&2
    return 1
  }
  [[ "$PREFIX" =~ ^/[A-Za-z0-9][A-Za-z0-9._+-]*(/[A-Za-z0-9][A-Za-z0-9._+-]*)*$ ]] || {
    printf 'nosh-guard-host-verify: --prefix is not a canonical safe path: %s\n' \
      "$PREFIX" >&2
    return 1
  }
  case "$PREFIX" in
    /bin|/boot|/dev|/etc|/home|/lib|/lib64|/media|/mnt|/opt|/proc|/root|/run|/sbin|/srv|/sys|/tmp|/usr|/var)
      printf 'nosh-guard-host-verify: --prefix is a broad system root: %s\n' \
        "$PREFIX" >&2
      return 1
      ;;
  esac
  remainder="${PREFIX#/}"
  while [[ -n "$remainder" ]]; do
    component="${remainder%%/*}"
    [[ "$component" != . && "$component" != .. ]] || return 1
    if [[ "$remainder" == */* ]]; then
      remainder="${remainder#*/}"
    else
      remainder=""
    fi
  done
}

validate_prefix || exit 2
case "$SYSTEMD_UNIT_DIR" in
  /etc/systemd/system|/usr/lib/systemd/system) ;;
  *)
    printf 'nosh-guard-host-verify: unsupported systemd unit directory: %s\n' \
      "$SYSTEMD_UNIT_DIR" >&2
    exit 2
    ;;
esac
INSTALL_BASE="$PREFIX/lib/notty/nosh-guard"
CURRENT_LINK="$INSTALL_BASE/current"

[[ "${EUID:-$(id -u)}" == 0 ]] || {
  printf 'nosh-guard-host-verify: run as root\n' >&2
  exit 1
}
command -v timeout >/dev/null 2>&1 || {
  printf 'nosh-guard-host-verify: required command is missing: timeout\n' >&2
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

check_root_file() {
  local path_name="$1"
  local expected_mode="$2"
  local metadata

  [[ -f "$path_name" && ! -L "$path_name" ]] || {
    printf 'nosh-guard-host-verify: missing regular file: %s\n' "$path_name" >&2
    return 1
  }
  metadata="$(stat -Lc '%u %a %h' "$path_name")"
  [[ "$metadata" == "0 $expected_mode 1" ]] || {
    printf 'nosh-guard-host-verify: unsafe owner/mode/links for %s: %s\n' \
      "$path_name" "$metadata" >&2
    return 1
  }
}

check_root_directory() {
  local path_name="$1"
  local metadata
  local mode

  [[ -d "$path_name" && ! -L "$path_name" ]] || {
    printf 'nosh-guard-host-verify: missing safe directory: %s\n' \
      "$path_name" >&2
    return 1
  }
  metadata="$(stat -Lc '%u %a' "$path_name")"
  mode="${metadata#* }"
  if [[ "${metadata%% *}" != 0 ]] || (( (8#$mode & 8#22) != 0 )); then
    printf 'nosh-guard-host-verify: unsafe directory owner/mode for %s: %s\n' \
      "$path_name" "$metadata" >&2
    return 1
  fi
}

check_prefix_ancestors() {
  local ancestor=""
  local component
  local remainder="${PREFIX#/}"

  check_root_directory /
  while [[ -n "$remainder" ]]; do
    component="${remainder%%/*}"
    ancestor="$ancestor/$component"
    check_root_directory "$ancestor"
    if [[ "$remainder" == */* ]]; then
      remainder="${remainder#*/}"
    else
      remainder=""
    fi
  done
}

load_install_receipt() {
  local line_count
  local receipt_prefix
  local schema_version

  check_root_file "$RECEIPT_PATH" 644
  if sed -nE \
    '/^(SCHEMA_VERSION|NOSH_GUARD_PREFIX|MANIFEST_SHA256)=/!p' \
    "$RECEIPT_PATH" | grep -q .
  then
    printf 'nosh-guard-host-verify: installation layout receipt has unknown fields\n' >&2
    return 1
  fi
  line_count="$(sed -n '$=' "$RECEIPT_PATH")"
  [[ "$line_count" == 3 ]] || {
    printf 'nosh-guard-host-verify: installation layout receipt has an invalid field count\n' >&2
    return 1
  }
  schema_version="$(metadata_value "$RECEIPT_PATH" SCHEMA_VERSION)" || return 1
  receipt_prefix="$(metadata_value "$RECEIPT_PATH" NOSH_GUARD_PREFIX)" || return 1
  RECEIPT_MANIFEST_DIGEST="$(metadata_value "$RECEIPT_PATH" MANIFEST_SHA256)" \
    || return 1
  [[ "$schema_version" == 1 ]] || {
    printf 'nosh-guard-host-verify: unsupported installation layout receipt schema\n' >&2
    return 1
  }
  [[ "$receipt_prefix" == "$PREFIX" ]] || {
    printf 'nosh-guard-host-verify: receipt prefix %s does not match requested %s\n' \
      "$receipt_prefix" "$PREFIX" >&2
    return 1
  }
  [[ "$RECEIPT_MANIFEST_DIGEST" =~ ^[a-f0-9]{64}$ ]] || {
    printf 'nosh-guard-host-verify: invalid receipt manifest digest\n' >&2
    return 1
  }
}

verify_manifest_inventory() {
  local release_root="$1"
  local expected_inventory
  local actual_inventory

  expected_inventory="$(mktemp)"
  actual_inventory="$(mktemp)"
  sed -nE 's/^[a-f0-9]{64}  (\.\/.*)$/\1/p' \
    "$release_root/manifest.sha256" | LC_ALL=C sort >"$expected_inventory"
  (
    cd "$release_root"
    LC_ALL=C find . -type f ! -path ./manifest.sha256 | LC_ALL=C sort
  ) >"$actual_inventory"
  if ! cmp -s "$expected_inventory" "$actual_inventory"; then
    rm -f -- "$expected_inventory" "$actual_inventory"
    printf 'nosh-guard-host-verify: release manifest inventory is incomplete\n' >&2
    return 1
  fi
  rm -f -- "$expected_inventory" "$actual_inventory"
}

compare_deployed() {
  local source_path="$1"
  local deployed_path="$2"
  local expected_mode="$3"

  check_root_file "$deployed_path" "$expected_mode"
  cmp -s -- "$source_path" "$deployed_path" || {
    printf 'nosh-guard-host-verify: deployed file drifted: %s\n' \
      "$deployed_path" >&2
    return 1
  }
}

check_launcher_help() {
  local launcher="$1"
  local expected_first_line="$2"
  local first_line
  local output

  if ! output="$(
    NOSH_GUARD_ALLOW_INCOMPLETE=1 \
      timeout --signal=KILL 2s "$launcher" --help
  )"; then
    printf 'nosh-guard-host-verify: launcher help failed: %s\n' \
      "$launcher" >&2
    return 1
  fi
  first_line="${output%%$'\n'*}"
  [[ "$first_line" == "$expected_first_line" ]] || {
    printf 'nosh-guard-host-verify: launcher did not execute its entrypoint: %s\n' \
      "$launcher" >&2
    return 1
  }
}

verify_sudoers() {
  local destination=/etc/sudoers.d/nosh-build-profile
  local expected_alias
  local first_line
  local line_count
  local second_line

  [[ ! -e "$destination" && ! -L "$destination" ]] && return 0
  check_root_directory /etc/sudoers.d
  check_root_file "$destination" 440
  expected_alias="$(sed -n '1p' \
    "$RENDER_STAGING/sudoers/nosh-build-session.alias")"
  first_line="$(sed -n '1p' "$destination")"
  second_line="$(sed -n '2p' "$destination")"
  line_count="$(sed -n '$=' "$destination")"
  if [[ "$line_count" != 2 ]] || [[ "$first_line" != "$expected_alias" ]] || \
    [[ ! "$second_line" =~ ^%[A-Za-z_][A-Za-z0-9_-]{0,63}[[:space:]]ALL=\(root\)[[:space:]]NOPASSWD:[[:space:]]NOSH_BUILD_SESSION$ ]]
  then
    printf 'nosh-guard-host-verify: optional sudoers policy drifted\n' >&2
    return 1
  fi
}

check_prefix_ancestors
for trusted_directory in \
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
  "$SYSTEMD_UNIT_DIR" \
  /var \
  /var/lib \
  /var/lib/nosh-guard \
  "$INSTALL_BASE" \
  "$INSTALL_BASE/releases"
do
  check_root_directory "$trusted_directory"
done

load_install_receipt

[[ -L "$CURRENT_LINK" ]] || {
  printf 'nosh-guard-host-verify: current release link is missing\n' >&2
  exit 1
}
[[ "$(stat -c '%u' "$CURRENT_LINK")" == 0 ]] || {
  printf 'nosh-guard-host-verify: current release link is not root-owned\n' >&2
  exit 1
}
CURRENT_ROOT="$(readlink -f "$CURRENT_LINK")"
case "$CURRENT_ROOT" in
  "$INSTALL_BASE"/releases/*) ;;
  *)
    printf 'nosh-guard-host-verify: current release escaped the release root\n' >&2
    exit 1
    ;;
esac
[[ -d "$CURRENT_ROOT" && ! -L "$CURRENT_ROOT" ]] || {
  printf 'nosh-guard-host-verify: current release is not a directory\n' >&2
  exit 1
}

if find "$CURRENT_ROOT" \( ! -user root -o -perm /022 \) -print -quit | grep -q .; then
  printf 'nosh-guard-host-verify: release contains unsafe ownership or modes\n' >&2
  exit 1
fi
if find "$CURRENT_ROOT" -type l -print -quit | grep -q .; then
  printf 'nosh-guard-host-verify: release unexpectedly contains a symlink\n' >&2
  exit 1
fi
if find "$CURRENT_ROOT" ! -type d ! -type f -print -quit | grep -q .; then
  printf 'nosh-guard-host-verify: release contains a special filesystem object\n' >&2
  exit 1
fi
if find "$CURRENT_ROOT" -type f -links +1 -print -quit | grep -q .; then
  printf 'nosh-guard-host-verify: release contains a multiply linked file\n' >&2
  exit 1
fi

check_root_file "$CURRENT_ROOT/manifest.sha256" 644
verify_manifest_inventory "$CURRENT_ROOT"
MANIFEST_DIGEST="$(sha256sum "$CURRENT_ROOT/manifest.sha256" | awk '{print $1}')"
[[ "$MANIFEST_DIGEST" == "$RECEIPT_MANIFEST_DIGEST" ]] || {
  printf 'nosh-guard-host-verify: receipt does not identify the current release\n' >&2
  exit 1
}
case "$(basename "$CURRENT_ROOT")" in
  *-"$MANIFEST_DIGEST") ;;
  *)
    printf 'nosh-guard-host-verify: release identity does not bind its manifest\n' >&2
    exit 1
    ;;
esac
(
  cd "$CURRENT_ROOT"
  sha256sum --check --strict --quiet manifest.sha256
)

EXPECTED_NODE_VERSION="$(metadata_value "$CURRENT_ROOT/bundle.env" NODE_VERSION)"
EXPECTED_NODE_SHA256="$(metadata_value "$CURRENT_ROOT/bundle.env" NODE_SHA256)"
EXPECTED_ARCHITECTURE="$(metadata_value "$CURRENT_ROOT/bundle.env" ARCHITECTURE)"
EXPECTED_NODE="$CURRENT_ROOT/payload/runtime/node"
[[ "$(uname -m)" == "$EXPECTED_ARCHITECTURE" ]] || {
  printf 'nosh-guard-host-verify: bundle architecture is %s, host is %s\n' \
    "$EXPECTED_ARCHITECTURE" "$(uname -m)" >&2
  exit 1
}
check_root_file "$EXPECTED_NODE" 755
[[ "$(sha256sum "$EXPECTED_NODE" | awk '{print $1}')" == "$EXPECTED_NODE_SHA256" ]] || {
  printf 'nosh-guard-host-verify: Node runtime checksum does not match bundle\n' >&2
  exit 1
}
[[ "$($EXPECTED_NODE --version)" == "$EXPECTED_NODE_VERSION" ]] || {
  printf 'nosh-guard-host-verify: expected Node %s at %s\n' \
    "$EXPECTED_NODE_VERSION" "$EXPECTED_NODE" >&2
  exit 1
}

RENDERER="$CURRENT_ROOT/payload/scripts/render-nosh-guard-install.mjs"
check_root_file "$RENDERER" 644
RENDER_STAGING="$(mktemp -d /tmp/nosh-guard-verify-render.XXXXXX)"
"$EXPECTED_NODE" "$RENDERER" \
  --prefix "$PREFIX" \
  --source-root "$CURRENT_ROOT" \
  --output-dir "$RENDER_STAGING"
if [[ "$SYSTEMD_UNIT_DIR" == /usr/lib/systemd/system ]]; then
  sed -i 's/ --service$/ --systemd-unit-dir \/usr\/lib\/systemd\/system --service/' \
    "$RENDER_STAGING/deploy/systemd/nosh-guardd.service"
fi

for launcher in \
  nosh-gateway \
  nosh-guard \
  nosh-guardd \
  nosh-guard-fail-closed \
  nosh-guard-tetragon-verify
do
  compare_deployed \
    "$RENDER_STAGING/deploy/host/$launcher" \
    "$PREFIX/bin/$launcher" \
    755
done

check_launcher_help \
  "$PREFIX/bin/nosh-gateway" \
  'Usage: nosh-gateway <verify|diff|apply|status> [options]'
check_launcher_help \
  "$PREFIX/bin/nosh-guard" \
  'Usage: nosh-guard <command> [options]'
check_launcher_help \
  "$PREFIX/bin/nosh-guardd" \
  'Usage: nosh-guard <command> [options]'
check_launcher_help \
  "$PREFIX/bin/nosh-guard-tetragon-verify" \
  'Usage: nosh-guard-tetragon-verify --policy-name NAME [options]'

compare_deployed \
  "$CURRENT_ROOT/payload/libexec/nosh-build/nosh-build-loader" \
  "$PREFIX/libexec/nosh-build/nosh-build-loader" \
  755
compare_deployed \
  "$CURRENT_ROOT/payload/libexec/nosh-build/nosh-url-loader" \
  "$PREFIX/libexec/nosh-build/nosh-url-loader" \
  755
compare_deployed \
  "$CURRENT_ROOT/payload/libexec/nosh-guard/nosh-l4-loader" \
  "$PREFIX/libexec/nosh-guard/nosh-l4-loader" \
  755
compare_deployed \
  "$CURRENT_ROOT/payload/libexec/nosh-guard/nosh-egress-loader" \
  "$PREFIX/libexec/nosh-guard/nosh-egress-loader" \
  755
compare_deployed \
  "$CURRENT_ROOT/payload/libexec/nosh-guard/nosh_egress.bpf.o" \
  "$PREFIX/libexec/nosh-guard/nosh_egress.bpf.o" \
  644
compare_deployed \
  "$CURRENT_ROOT/payload/libexec/nosh-guard/nosh_egress.bpf.o.sha256" \
  "$PREFIX/libexec/nosh-guard/nosh_egress.bpf.o.sha256" \
  644
compare_deployed \
  "$CURRENT_ROOT/payload/libexec/nosh-guard/ensure-nosh-guard-bpffs" \
  "$PREFIX/libexec/nosh-guard/ensure-nosh-guard-bpffs" \
  755
(
  cd "$PREFIX/libexec/nosh-guard"
  sha256sum --check --strict nosh_egress.bpf.o.sha256
)
compare_deployed \
  "$RENDER_STAGING/libexec/nosh-guard/nosh-guard-host-verify" \
  "$PREFIX/libexec/nosh-guard/nosh-guard-host-verify" \
  755
compare_deployed \
  "$RENDER_STAGING/config/nosh-guard/adapters.json" \
  /etc/nosh-guard/adapters.json \
  640
compare_deployed \
  "$RENDER_STAGING/config/nosh-guard/versions.json" \
  /etc/nosh-guard/versions.json \
  640
compare_deployed \
  "$RENDER_STAGING/config/nosh-build/adapters.json" \
  /etc/nosh-guard/build-adapters.json \
  640
compare_deployed \
  "$RENDER_STAGING/config/nosh-build/versions.json" \
  /etc/nosh-guard/build-versions.json \
  640
check_root_file /etc/nosh-guard/network-contract.json 640
compare_deployed \
  "$RENDER_STAGING/deploy/systemd/nosh-guard-bpffs.service" \
  "$SYSTEMD_UNIT_DIR/nosh-guard-bpffs.service" \
  644
compare_deployed \
  "$RENDER_STAGING/deploy/systemd/nosh-guardd.service" \
  "$SYSTEMD_UNIT_DIR/nosh-guardd.service" \
  644
compare_deployed \
  "$CURRENT_ROOT/payload/docs/nosh-gateway.md" \
  "$PREFIX/share/doc/notty/nosh-gateway.md" \
  644
compare_deployed \
  "$CURRENT_ROOT/payload/docs/nosh-policy-review.md" \
  "$PREFIX/share/doc/notty/nosh-policy-review.md" \
  644
compare_deployed \
  "$CURRENT_ROOT/payload/docs/nosh-guard.md" \
  "$PREFIX/share/doc/notty/nosh-guard.md" \
  644
compare_deployed \
  "$CURRENT_ROOT/payload/docs/nosh-build-profiling.md" \
  "$PREFIX/share/doc/notty/nosh-build-profiling.md" \
  644
for documentation in \
  LICENSE \
  THIRD_PARTY_NOTICES.md \
  NODE_LICENSE \
  nosh-bpf-0BSD.txt \
  nosh-bpf-GPL-2.0-only.txt
do
  compare_deployed \
    "$CURRENT_ROOT/payload/docs/$documentation" \
    "$PREFIX/share/doc/notty/$documentation" \
    644
done

verify_sudoers

if ((DEEP == 1)); then
  expected_egress_object_digest="$(sed -nE 's/^([0-9a-f]{64})  nosh_egress\.bpf\.o$/sha256:\1/p' \
    "$PREFIX/libexec/nosh-guard/nosh_egress.bpf.o.sha256")"
  [[ "$expected_egress_object_digest" =~ ^sha256:[0-9a-f]{64}$ ]] || {
    printf 'nosh-guard-host-verify: egress object receipt is malformed\n' >&2
    exit 1
  }
  "$PREFIX/libexec/nosh-build/nosh-build-loader" health --depth process
  "$PREFIX/libexec/nosh-build/nosh-build-loader" verify --depth process
  "$PREFIX/libexec/nosh-build/nosh-build-loader" health --depth balanced
  "$PREFIX/libexec/nosh-build/nosh-build-loader" verify --depth balanced
  "$PREFIX/libexec/nosh-guard/nosh-l4-loader" health
  egress_health="$($PREFIX/libexec/nosh-guard/nosh-egress-loader health)"
  printf '%s\n' "$egress_health"
  [[ "$egress_health" == *"\"objectDigest\":\"$expected_egress_object_digest\""* ]] || {
    printf 'nosh-guard-host-verify: loader/object digest attestation mismatch\n' >&2
    exit 1
  }
fi

printf 'nosh-guard-host-verify: installed bundle is valid (%s; prefix %s)\n' \
  "$(metadata_value "$CURRENT_ROOT/bundle.env" NOTTY_VERSION)" "$PREFIX"
