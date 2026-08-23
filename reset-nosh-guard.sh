#!/usr/bin/env bash
set -euo pipefail

# Rebuild and atomically refresh the host Guard without uninstalling it first.
# The bundle build and extraction remain unprivileged; only the manifest-
# selected installer is invoked through sudo.

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
RECEIPT_PATH="/etc/nosh-guard-install-layout.conf"
PREFIX_REQUESTED=""
INSTALLED_PREFIX=""
PREFIX=""
WORK_DIR=""
REPLACE_CONFIG=0

usage() {
  cat <<'EOF'
Usage: ./reset-nosh-guard.sh [--prefix ABS] [--replace-config]

Rebuild the Nosh Guard host bundle from this reviewed checkout, verify and
extract it as the current unprivileged user, then refresh the existing host
installation in place. The reset enables/starts nosh-guardd and performs deep
host verification. By default it preserves all configuration and fails closed
if bundle-authoritative configuration differs from the fresh bundle. It does
not purge configuration or delete Guard state or Guard evidence, and never
uninstalls the bundle.

This refresh installs the reviewed first-party eBPF loaders together with the
Guard control plane. Scoped egress modes do not use a separate managed
dnsmasq/nftables gateway. Any legacy full-profile gateway artifact is outside
this reset and is preserved.

--replace-config explicitly replaces only the bundle-authoritative Guard and
build adapter/version files.
It never replaces the operator-managed network contract or deletes Guard state
or Guard evidence.

Prefix selection:
  1. --prefix ABS
  2. NOSH_GUARD_PREFIX
  3. the validated installed layout receipt

An existing receipt or an explicit prefix selection is required.

Options:
  --prefix ABS       existing Nosh Guard software prefix
  --replace-config   replace reviewed bundle-authoritative adapter/version files
  -h, --help         show this help
EOF
}

die() {
  printf 'reset-nosh-guard: %s\n' "$*" >&2
  exit 1
}

invalid_usage() {
  printf 'reset-nosh-guard: %s\n' "$*" >&2
  usage >&2
  exit 2
}

cleanup() {
  if [[ -n "$WORK_DIR" && -d "$WORK_DIR" && ! -L "$WORK_DIR" ]]; then
    rm -rf -- "$WORK_DIR"
  fi
}

trap cleanup EXIT

validate_prefix() {
  local selected="$1"

  [[ "$selected" == /* && "$selected" != / ]] ||
    die '--prefix must be an absolute path other than /'
  [[ "$selected" =~ ^/[A-Za-z0-9][A-Za-z0-9._+-]*(/[A-Za-z0-9][A-Za-z0-9._+-]*)*$ ]] ||
    die "--prefix is not a canonical safe path: $selected"
  case "$selected" in
    /bin|/boot|/dev|/etc|/home|/lib|/lib64|/media|/mnt|/opt|/proc|/root|/run|/sbin|/srv|/sys|/tmp|/usr|/var)
      die "--prefix is a broad system root: $selected"
      ;;
  esac
}

read_layout_receipt() {
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

  if [[ ! -e "$RECEIPT_PATH" && ! -L "$RECEIPT_PATH" ]]; then
    return
  fi
  [[ -f "$RECEIPT_PATH" && ! -L "$RECEIPT_PATH" ]] ||
    die "unsafe Guard layout receipt: $RECEIPT_PATH"
  metadata="$(stat -Lc '%u %a %h' -- "$RECEIPT_PATH" 2>/dev/null)" ||
    die "cannot inspect Guard layout receipt: $RECEIPT_PATH"
  read -r owner mode links <<<"$metadata"
  [[ "$owner" == 0 && "$mode" == 644 && "$links" == 1 ]] ||
    die "unsafe Guard layout receipt: $RECEIPT_PATH"

  while IFS= read -r line || [[ -n "$line" ]]; do
    ((line_number += 1))
    [[ -n "$line" && "$line" == *=* && "$line" != *$'\r'* ]] ||
      die "malformed Guard layout receipt at $RECEIPT_PATH:$line_number"
    key="${line%%=*}"
    value="${line#*=}"
    case "$key" in
      SCHEMA_VERSION|NOSH_GUARD_PREFIX|MANIFEST_SHA256) ;;
      *) die "unknown Guard layout receipt key at $RECEIPT_PATH:$line_number: $key" ;;
    esac
    [[ ! -v "seen[$key]" ]] ||
      die "duplicate Guard layout receipt key at $RECEIPT_PATH:$line_number: $key"
    seen["$key"]=1
    case "$key" in
      SCHEMA_VERSION) schema_version="$value" ;;
      NOSH_GUARD_PREFIX) INSTALLED_PREFIX="$value" ;;
      MANIFEST_SHA256) manifest_sha256="$value" ;;
    esac
  done <"$RECEIPT_PATH"

  for key in SCHEMA_VERSION NOSH_GUARD_PREFIX MANIFEST_SHA256; do
    [[ -v "seen[$key]" ]] ||
      die "missing Guard layout receipt key in $RECEIPT_PATH: $key"
  done
  [[ "$schema_version" == 1 ]] ||
    die "unsupported Guard layout receipt schema: $schema_version"
  [[ "$manifest_sha256" =~ ^[a-f0-9]{64}$ ]] ||
    die 'invalid MANIFEST_SHA256 in Guard layout receipt'
  validate_prefix "$INSTALLED_PREFIX"
}

while (($#)); do
  case "$1" in
    --prefix)
      [[ -n "${2:-}" ]] || invalid_usage '--prefix requires a value'
      PREFIX_REQUESTED="$2"
      shift 2
      ;;
    --prefix=*)
      PREFIX_REQUESTED="${1#*=}"
      [[ -n "$PREFIX_REQUESTED" ]] || invalid_usage '--prefix requires a value'
      shift
      ;;
    --replace-config)
      REPLACE_CONFIG=1
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      invalid_usage "unknown option: $1"
      ;;
  esac
done

if [[ -n "$PREFIX_REQUESTED" ]]; then
  validate_prefix "$PREFIX_REQUESTED"
elif [[ -n "${NOSH_GUARD_PREFIX:-}" ]]; then
  validate_prefix "$NOSH_GUARD_PREFIX"
fi
read_layout_receipt
if [[ -n "$PREFIX_REQUESTED" ]]; then
  PREFIX="$PREFIX_REQUESTED"
elif [[ -n "${NOSH_GUARD_PREFIX:-}" ]]; then
  PREFIX="$NOSH_GUARD_PREFIX"
elif [[ -n "$INSTALLED_PREFIX" ]]; then
  PREFIX="$INSTALLED_PREFIX"
else
  die 'no installed Guard prefix found; pass --prefix ABS'
fi
validate_prefix "$PREFIX"
if [[ -n "$INSTALLED_PREFIX" && "$PREFIX" != "$INSTALLED_PREFIX" ]]; then
  die "requested prefix $PREFIX does not match installed prefix $INSTALLED_PREFIX"
fi

for command_name in basename id install mktemp readlink sha256sum stat sudo tar; do
  command -v "$command_name" >/dev/null 2>&1 ||
    die "required host command is missing: $command_name"
done

[[ "$(id -u)" != 0 ]] ||
  die 'refusing to run as root; invoke this script as the Docker-authorized user'
[[ -x "$SCRIPT_DIR/scripts/build-nosh-guard-host-bundle.sh" ]] ||
  die 'host bundle builder is missing or not executable'

WORK_DIR="$(mktemp -d)"
[[ -d "$WORK_DIR" && ! -L "$WORK_DIR" ]] ||
  die 'could not create a private reset workspace'
readonly WORK_DIR
artifact_dir="$WORK_DIR/artifacts"
extract_dir="$WORK_DIR/extracted"
install -d -m 0700 -- "$artifact_dir" "$extract_dir"

printf 'Rebuilding Nosh Guard host bundle for %s...\n' "$PREFIX" >&2
"$SCRIPT_DIR/scripts/build-nosh-guard-host-bundle.sh" \
  --output-dir "$artifact_dir"

shopt -s nullglob
archives=("$artifact_dir"/*.tar.gz)
checksums=("$artifact_dir"/*.tar.gz.sha256)
if (( ${#archives[@]} != 1 || ${#checksums[@]} != 1 )); then
  die 'expected exactly one Nosh Guard archive and checksum'
fi
archive="${archives[0]}"
checksum="${checksums[0]}"
if [[ ! -f "$archive" || -L "$archive" || ! -f "$checksum" || -L "$checksum" ||
  "$checksum" != "$archive.sha256" ]]; then
  die 'Nosh Guard archive or checksum is unsafe or mismatched'
fi
for artifact in "$archive" "$checksum"; do
  artifact_metadata="$(stat -Lc '%u %a %h' -- "$artifact")" ||
    die "cannot inspect bundle artifact: $artifact"
  read -r artifact_owner artifact_mode artifact_links <<<"$artifact_metadata"
  [[ "$artifact_owner" == "$(id -u)" && "$artifact_mode" == 644 &&
    "$artifact_links" == 1 ]] ||
    die "bundle artifact has unsafe owner, mode, or link count: $artifact"
done
mapfile -t checksum_lines <"$checksum"
[[ "${#checksum_lines[@]}" == 1 ]] ||
  die 'bundle checksum file must contain exactly one record'
read -r expected_digest expected_name checksum_extra <<<"${checksum_lines[0]}"
[[ -z "${checksum_extra:-}" && "$expected_digest" =~ ^[a-f0-9]{64}$ &&
  "$expected_name" == "$(basename "$archive")" ]] ||
  die 'bundle checksum record does not name the selected archive'
actual_digest="$(sha256sum "$archive")"
actual_digest="${actual_digest%% *}"
[[ "$actual_digest" == "$expected_digest" ]] ||
  die 'bundle archive checksum verification failed'

printf 'Verifying and extracting rebuilt host bundle...\n' >&2
(
  cd "$artifact_dir"
  sha256sum --check --strict -- "$(basename "$checksum")"
)
tar --extract --gzip --file "$archive" --directory "$extract_dir"

installers=("$extract_dir"/*/install.sh)
if (( ${#installers[@]} != 1 )); then
  die 'expected exactly one Nosh Guard installer'
fi
installer="${installers[0]}"
[[ -f "$installer" && ! -L "$installer" && -x "$installer" ]] ||
  die 'Nosh Guard installer is unsafe or not executable'
installer_metadata="$(stat -Lc '%u %a %h' -- "$installer")" ||
  die 'cannot inspect Nosh Guard installer'
read -r installer_owner installer_mode installer_links <<<"$installer_metadata"
[[ "$installer_owner" == "$(id -u)" && "$installer_links" == 1 ]] ||
  die 'Nosh Guard installer has unsafe owner or link count'
[[ "$installer_mode" == 700 || "$installer_mode" == 755 ]] ||
  die "Nosh Guard installer has an unsafe mode: $installer_mode"

replace_config_args=()
if ((REPLACE_CONFIG == 1)); then
  replace_config_args+=(--replace-config)
  printf '%s\n' \
    "Installing and deep-verifying Nosh Guard at $PREFIX (bundle-authoritative configuration replacement enabled)..." >&2
else
  printf 'Installing and deep-verifying Nosh Guard at %s...\n' "$PREFIX" >&2
fi
sudo -- "$installer" install \
  --prefix "$PREFIX" \
  "${replace_config_args[@]}" \
  --enable-now \
  --deep-verify

if ((REPLACE_CONFIG == 1)); then
  printf '%s\n' \
    "Nosh Guard reset complete at $PREFIX; bundle-authoritative adapter/version configuration was replaced; operator network contract, state, and evidence were preserved."
else
  printf 'Nosh Guard reset complete at %s; configuration and evidence were preserved.\n' \
    "$PREFIX"
fi
printf '%s\n' \
  'The installed host bundle includes the first-party eBPF enforcement backend; scoped egress uses no separate gateway image.'
