#!/usr/bin/env bash
set -euo pipefail

# All compilation and Debian tooling stays inside Docker. The host contributes
# only the read-only checkout, its kernel BTF, and an owned artifact directory.
umask 077

SCRIPT_DIR=$(cd -P "$(dirname "${BASH_SOURCE[0]}")" && pwd)
REPO_ROOT=$(cd -P "$SCRIPT_DIR/.." && pwd)
CALLER_CWD=$(pwd -P)
OUTPUT_REQUESTED=$REPO_ROOT/.nosh-deb
SOURCE_DATE_EPOCH_VALUE=${SOURCE_DATE_EPOCH:-0}
BUILDER_TAG=notty-nosh-deb-builder:node24.18.0
TEMP_ROOT=''

usage() {
  cat <<'EOF'
Usage: scripts/build-nosh-deb.sh [options]

Build a kernel-qualified Ubuntu 24.04 amd64 Nosh CLI + Guard .deb in Docker.
No Node, npm, compiler, or Debian packaging command runs on the host.

Options:
  --output-dir DIR   artifact directory (default: .nosh-deb)
  -h, --help         show this help
EOF
}

die() { printf 'build-nosh-deb: %s\n' "$*" >&2; exit 1; }
cleanup() { [[ -z $TEMP_ROOT || ! -d $TEMP_ROOT ]] || rm -rf -- "$TEMP_ROOT"; }
trap cleanup EXIT

while (($#)); do
  case $1 in
    --output-dir) [[ -n ${2:-} ]] || die '--output-dir requires a value'; OUTPUT_REQUESTED=$2; shift 2 ;;
    --output-dir=*) OUTPUT_REQUESTED=${1#*=}; [[ -n $OUTPUT_REQUESTED ]] || die '--output-dir requires a value'; shift ;;
    -h|--help) usage; exit 0 ;;
    *) usage >&2; die "unknown option: $1" ;;
  esac
done

[[ $SOURCE_DATE_EPOCH_VALUE =~ ^[0-9]+$ ]] || die 'SOURCE_DATE_EPOCH must be an integer'
[[ $(uname -m) == x86_64 ]] || die 'v1 Debian packaging supports amd64 hosts only'
[[ -r /sys/kernel/btf/vmlinux && -f /sys/kernel/btf/vmlinux && ! -L /sys/kernel/btf/vmlinux ]] \
  || die 'kernel BTF is unavailable at /sys/kernel/btf/vmlinux'
for command_name in docker find id mkdir mktemp realpath sha256sum stat uname; do
  command -v "$command_name" >/dev/null 2>&1 || die "required host command is missing: $command_name"
done
[[ $(id -u) != 0 ]] || die 'run as the unprivileged artifact owner, not root'
docker info >/dev/null 2>&1 || die 'Docker is unavailable; no host-tool fallback is allowed'

case $OUTPUT_REQUESTED in /*) ;; *) OUTPUT_REQUESTED=$CALLER_CWD/$OUTPUT_REQUESTED ;; esac
[[ ! -L $OUTPUT_REQUESTED ]] || die "output directory must not be a symlink: $OUTPUT_REQUESTED"
mkdir -p -- "$OUTPUT_REQUESTED"
OUTPUT_DIR=$(realpath -e -- "$OUTPUT_REQUESTED")
metadata=$(stat -Lc '%u %a' -- "$OUTPUT_DIR"); mode=${metadata#* }
[[ ${metadata%% *} == "$(id -u)" ]] && (( (8#$mode & 8#22) == 0 )) \
  || die 'output directory must be caller-owned and not group/world writable'

TEMP_ROOT=$(mktemp -d)
chmod 0700 "$TEMP_ROOT"
SOURCE_DATE_EPOCH=$SOURCE_DATE_EPOCH_VALUE \
  "$REPO_ROOT/scripts/build-nosh-guard-host-bundle.sh" --output-dir "$TEMP_ROOT"
mapfile -t bundles < <(find "$TEMP_ROOT" -maxdepth 1 -type f -name 'notty-nosh-guard-*.tar.gz' -print)
[[ ${#bundles[@]} == 1 ]] || die 'expected exactly one Guard host bundle'

docker build --pull --tag "$BUILDER_TAG" --file "$REPO_ROOT/Dockerfile.nosh-deb" "$REPO_ROOT"
image_id=$(docker image inspect --format '{{.Id}}' "$BUILDER_TAG")
[[ $image_id =~ ^sha256:[a-f0-9]{64}$ ]] || die 'Debian builder image has an invalid ID'
label=$(docker image inspect --format '{{index .Config.Labels "io.notty.nosh-deb-builder"}}' "$image_id")
[[ $label == 1 ]] || die 'Debian builder image is missing its identity label'

docker run --rm --init --read-only --network none --cap-drop ALL \
  --security-opt no-new-privileges=true --pids-limit 256 --cpus 2 --memory 2g \
  --user "$(id -u):$(id -g)" \
  --tmpfs "/tmp:rw,nosuid,nodev,noexec,size=64m,mode=1777,uid=$(id -u),gid=$(id -g)" \
  --tmpfs "/work:rw,nosuid,nodev,exec,size=2g,mode=0700,uid=$(id -u),gid=$(id -g)" \
  --mount "type=bind,src=$REPO_ROOT,dst=/input,readonly" \
  --mount "type=bind,src=$TEMP_ROOT,dst=/bundle,readonly" \
  --mount "type=bind,src=$OUTPUT_DIR,dst=/output" \
  --env NOSH_DEB_CONTAINER=1 --env NOSH_DEB_NETWORK=none \
  --env "SOURCE_DATE_EPOCH=$SOURCE_DATE_EPOCH_VALUE" \
  "$image_id"

printf 'Debian artifacts:\n'
find "$OUTPUT_DIR" -maxdepth 1 -type f -name 'notty-nosh_*' -printf '  %p\n' | sort
