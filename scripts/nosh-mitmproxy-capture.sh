#!/usr/bin/env bash
set -euo pipefail

umask 077

readonly NOSH_MANAGED_MITMPROXY_IMAGE='mitmproxy/mitmproxy:12.2.3@sha256:00b77b5d8804c8ad18cb6caefbf9d5849e895e8986c5ce011f4ae30f4385962f'

usage() {
  cat <<'USAGE'
Usage: nosh-mitmproxy-capture.sh [options]

Required:
  --run-id ID
  --run-root ABSOLUTE_PRIVATE_DIRECTORY
  --evidence ABSOLUTE_NDJSON_PATH
  --cas-root ABSOLUTE_DIRECTORY
  --mode observe|offline-replay|live-buffer-verify

Required for offline-replay and live-buffer-verify:
  --content-manifest ABSOLUTE_JSON_PATH

Optional:
  --listen-host ADDRESS       default: 127.0.0.1
  --listen-port PORT          default: 8080
  --confdir ABSOLUTE          default: CAS_ROOT/mitmproxy-conf
  --max-body-bytes BYTES      default: 536870912
  --max-cas-bytes BYTES       default/hard limit: 8589934592
  --max-cas-objects COUNT     default/hard limit: 10000
  --image-digest SHA256       managed image identity (required)
  --addon-digest SHA256       mounted addon identity (required)
  --wrapper-digest SHA256     mounted wrapper identity (required)
  --mitmdump-bin ABSOLUTE     default: resolved mitmdump from PATH
  --addon ABSOLUTE            default: sibling nosh-mitmproxy-addon.py
  --print-image               print the required pinned OCI image and exit
  -h, --help

The wrapper emits normalized private NDJSON at --evidence and content-addressed
response objects below --cas-root. It never launches or imports Burp Suite.
USAGE
}

die() {
  printf 'nosh HTTP capture: %s\n' "$*" >&2
  exit 2
}

script_dir="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)"
run_id=''
run_root=''
evidence_path=''
cas_root=''
capture_mode=''
content_manifest=''
confdir=''
max_body_bytes='536870912'
max_cas_bytes='8589934592'
max_cas_objects='10000'
listen_host='127.0.0.1'
listen_port='8080'
mitmdump_bin=''
addon_path="$script_dir/nosh-mitmproxy-addon.py"
collector_image_digest=''
collector_addon_digest=''
collector_wrapper_digest=''

while (($#)); do
  case "$1" in
    --run-id|--run-root|--evidence|--cas-root|--mode|--content-manifest|--listen-host|--listen-port|--confdir|--max-body-bytes|--max-cas-bytes|--max-cas-objects|--mitmdump-bin|--addon|--image-digest|--addon-digest|--wrapper-digest)
      (($# >= 2)) || die "$1 requires a value"
      case "$1" in
        --run-id) run_id="$2" ;;
        --run-root) run_root="$2" ;;
        --evidence) evidence_path="$2" ;;
        --cas-root) cas_root="$2" ;;
        --mode) capture_mode="$2" ;;
        --content-manifest) content_manifest="$2" ;;
        --listen-host) listen_host="$2" ;;
        --listen-port) listen_port="$2" ;;
        --confdir) confdir="$2" ;;
        --max-body-bytes) max_body_bytes="$2" ;;
        --max-cas-bytes) max_cas_bytes="$2" ;;
        --max-cas-objects) max_cas_objects="$2" ;;
        --mitmdump-bin) mitmdump_bin="$2" ;;
        --addon) addon_path="$2" ;;
        --image-digest) collector_image_digest="$2" ;;
        --addon-digest) collector_addon_digest="$2" ;;
        --wrapper-digest) collector_wrapper_digest="$2" ;;
      esac
      shift 2
      ;;
    --print-image)
      printf '%s\n' "$NOSH_MANAGED_MITMPROXY_IMAGE"
      exit 0
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *) die "unsupported option: $1" ;;
  esac
done

[[ "$run_id" =~ ^[A-Za-z0-9_.-]{1,128}$ ]] || die '--run-id is missing or invalid'
case "$capture_mode" in
  observe|offline-replay|live-buffer-verify) ;;
  *) die '--mode is missing or invalid' ;;
esac
[[ "$evidence_path" == /* ]] || die '--evidence must be absolute'
[[ "$cas_root" == /* ]] || die '--cas-root must be absolute'
[[ "$run_root" == /* && "$run_root" != / ]] || die '--run-root must be an absolute private boundary other than /'
[[ -d "$run_root" && ! -L "$run_root" && -O "$run_root" ]] || die '--run-root is unsafe'
run_root_logical="$(realpath -sm -- "$run_root")"
run_root_physical="$(realpath -e -- "$run_root")"
[[ "$run_root_logical" == "$run_root_physical" ]] || die '--run-root contains a symlink'
[[ "$(stat -c '%a' -- "$run_root")" == 700 ]] || die '--run-root mode must be 700'

require_run_child() {
  local selected=''
  selected="$(realpath -sm -- "$1")"
  case "$selected" in
    "$run_root_logical"/*) ;;
    *) die "private path escapes --run-root: $1" ;;
  esac
}

require_run_child "$evidence_path"
require_run_child "$cas_root"
if [[ -z "$confdir" ]]; then
  confdir="$cas_root/mitmproxy-conf"
fi
[[ "$confdir" == /* ]] || die '--confdir must be absolute'
require_run_child "$confdir"
[[ "$addon_path" == /* && -f "$addon_path" && ! -L "$addon_path" ]] || {
  die '--addon must name an absolute regular non-symlink file'
}
[[ "$listen_port" =~ ^[0-9]+$ ]] || die '--listen-port must be numeric'
((${#listen_port} <= 5)) || die '--listen-port must be from 1 to 65535'
((listen_port >= 1 && listen_port <= 65535)) || die '--listen-port must be from 1 to 65535'
[[ "$max_body_bytes" =~ ^[1-9][0-9]*$ ]] || die '--max-body-bytes must be a positive integer'
((${#max_body_bytes} <= 9)) || die '--max-body-bytes exceeds the 536870912-byte hard limit'
((max_body_bytes <= 536870912)) || die '--max-body-bytes exceeds the 536870912-byte hard limit'
[[ "$max_cas_bytes" =~ ^[1-9][0-9]*$ ]] || die '--max-cas-bytes must be a positive integer'
((${#max_cas_bytes} <= 10)) || die '--max-cas-bytes exceeds the 8589934592-byte hard limit'
((max_cas_bytes <= 8589934592)) || die '--max-cas-bytes exceeds the 8589934592-byte hard limit'
[[ "$max_cas_objects" =~ ^[1-9][0-9]*$ ]] || die '--max-cas-objects must be a positive integer'
((${#max_cas_objects} <= 5)) || die '--max-cas-objects exceeds the 10000-object hard limit'
((max_cas_objects <= 10000)) || die '--max-cas-objects exceeds the 10000-object hard limit'
readonly digest_pattern='^sha256:[a-f0-9]{64}$'
[[ "$collector_image_digest" =~ $digest_pattern ]] || die '--image-digest is missing or invalid'
[[ "$collector_addon_digest" =~ $digest_pattern ]] || die '--addon-digest is missing or invalid'
[[ "$collector_wrapper_digest" =~ $digest_pattern ]] || die '--wrapper-digest is missing or invalid'
[[ "$collector_image_digest" == 'sha256:00b77b5d8804c8ad18cb6caefbf9d5849e895e8986c5ce011f4ae30f4385962f' ]] || {
  die '--image-digest does not match the managed image pin'
}

if [[ "$capture_mode" == observe ]]; then
  [[ -z "$content_manifest" ]] || die 'observe mode must not receive --content-manifest'
else
  [[ "$content_manifest" == /* && -f "$content_manifest" && ! -L "$content_manifest" ]] || {
    die "$capture_mode requires an absolute regular non-symlink --content-manifest"
  }
  require_run_child "$content_manifest"
fi

if [[ -z "$mitmdump_bin" ]]; then
  mitmdump_bin="$(command -v mitmdump || true)"
fi
[[ "$mitmdump_bin" == /* && -x "$mitmdump_bin" ]] || {
  die '--mitmdump-bin must resolve to an absolute executable file'
}

evidence_parent="$(dirname -- "$evidence_path")"
mkdir -p -- "$evidence_parent" "$cas_root" "$confdir"
[[ -d "$evidence_parent" && ! -L "$evidence_parent" ]] || die 'evidence parent is unsafe'
[[ -d "$cas_root" && ! -L "$cas_root" ]] || die 'CAS root is unsafe'
[[ -d "$confdir" && ! -L "$confdir" ]] || die 'mitmproxy confdir is unsafe'
for private_directory in "$evidence_parent" "$cas_root" "$confdir"; do
  [[ "$(realpath -s -- "$private_directory")" == "$(realpath -e -- "$private_directory")" ]] || {
    die "private directory contains a symlink: $private_directory"
  }
  [[ -O "$private_directory" ]] || die "private directory has an unexpected owner: $private_directory"
done
chmod 0700 -- "$evidence_parent" "$cas_root" "$confdir"
[[ ! -e "$confdir/config.yaml" ]] || die 'mitmproxy config.yaml is not allowed in the managed confdir'
if [[ -e "$evidence_path" && ( ! -f "$evidence_path" || -L "$evidence_path" ) ]]; then
  die 'evidence path must be a regular non-symlink file'
fi

digest_file() {
  local file="$1"
  local hexadecimal=''
  local ignored=''
  read -r hexadecimal ignored < <(sha256sum -- "$file")
  [[ "$hexadecimal" =~ ^[a-f0-9]{64}$ ]] || die "could not hash managed component: $file"
  printf 'sha256:%s\n' "$hexadecimal"
}

[[ "$(digest_file "$addon_path")" == "$collector_addon_digest" ]] || {
  die 'mounted addon digest does not match --addon-digest'
}
[[ "$(digest_file "$0")" == "$collector_wrapper_digest" ]] || {
  die 'mounted wrapper digest does not match --wrapper-digest'
}

export NOSH_HTTP_RUN_ID="$run_id"
export NOSH_HTTP_RUN_ROOT="$run_root_logical"
export NOSH_HTTP_EVIDENCE_PATH="$evidence_path"
export NOSH_HTTP_CAS_ROOT="$cas_root"
export NOSH_HTTP_CAPTURE_MODE="$capture_mode"
export NOSH_HTTP_MAX_BODY_BYTES="$max_body_bytes"
export NOSH_HTTP_MAX_CAS_BYTES="$max_cas_bytes"
export NOSH_HTTP_MAX_CAS_OBJECTS="$max_cas_objects"
export NOSH_HTTP_COLLECTOR_IMAGE_DIGEST="$collector_image_digest"
export NOSH_HTTP_COLLECTOR_ADDON_DIGEST="$collector_addon_digest"
export NOSH_HTTP_COLLECTOR_WRAPPER_DIGEST="$collector_wrapper_digest"
if [[ -n "$content_manifest" ]]; then
  export NOSH_HTTP_CONTENT_MANIFEST="$content_manifest"
else
  unset NOSH_HTTP_CONTENT_MANIFEST || true
fi

exec "$mitmdump_bin" \
  --quiet \
  --listen-host "$listen_host" \
  --listen-port "$listen_port" \
  --mode regular \
  --set block_global=false \
  --set connection_strategy=lazy \
  --set rawtcp=false \
  --set "body_size_limit=$max_body_bytes" \
  --set "confdir=$confdir" \
  --set ssl_insecure=false \
  --set termlog_verbosity=warn \
  --script "$addon_path"
