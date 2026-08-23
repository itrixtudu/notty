#!/usr/bin/env bash
set -euo pipefail

# HOST POLICY: this wrapper must never execute Node, npm, npx, make, clang, or
# bpftool on the host. Docker is mandatory and there is no host-tool fallback.

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
REPOSITORY_ROOT="$(cd "$SCRIPT_DIR/.." && pwd -P)"
CALLER_CWD="$(pwd -P)"
IMAGE_TAG="notty-nosh-guard-host-bundle:node24.18.0"
OUTPUT_REQUESTED="$REPOSITORY_ROOT/.nosh-guard-host-bundles"
OUTPUT_DIR=""
BUILD_CONTEXT=""
RESULT_NAME=""
RESULT_PATH=""
USE_EXISTING_LOADERS=0
SOURCE_DATE_EPOCH_VALUE="${SOURCE_DATE_EPOCH:-0}"

usage() {
  cat <<'EOF'
Usage: scripts/build-nosh-guard-host-bundle.sh [options]

Build a checksummed Nosh Guard host archive in a dedicated Docker image.
Docker is mandatory. This wrapper never runs Node.js, npm, npx, make, clang,
or bpftool on the host and has no host-tool fallback. The packaging container
runs offline and non-root; only its output directory is writable on the host.

Options:
  --output-dir DIR          archive output directory
  --use-existing-loaders   package reviewed bpf/*/build loader binaries
  -h, --help                show this help
EOF
}

die() {
  printf 'build-nosh-guard-host-bundle: %s\n' "$*" >&2
  exit 1
}

invalid_usage() {
  printf 'build-nosh-guard-host-bundle: %s\n' "$*" >&2
  usage >&2
  exit 2
}

host_tool_forbidden() {
  printf 'build-nosh-guard-host-bundle: refusing to execute host %s; Docker is mandatory\n' \
    "$1" >&2
  exit 97
}

function npm { host_tool_forbidden npm; }
function npx { host_tool_forbidden npx; }
function node { host_tool_forbidden node; }
function make { host_tool_forbidden make; }
function clang { host_tool_forbidden clang; }
function bpftool { host_tool_forbidden bpftool; }
readonly -f npm npx node make clang bpftool

cleanup() {
  if [[ -n "$BUILD_CONTEXT" && -d "$BUILD_CONTEXT" ]]; then
    rm -rf -- "$BUILD_CONTEXT"
  fi
  if [[ -n "$RESULT_PATH" && ( -f "$RESULT_PATH" || -L "$RESULT_PATH" ) ]]; then
    rm -f -- "$RESULT_PATH"
  fi
}

trap cleanup EXIT

while (($#)); do
  case "$1" in
    --output-dir)
      [[ -n "${2:-}" ]] || invalid_usage '--output-dir requires a value'
      OUTPUT_REQUESTED="$2"
      shift 2
      ;;
    --output-dir=*)
      OUTPUT_REQUESTED="${1#*=}"
      [[ -n "$OUTPUT_REQUESTED" ]] || invalid_usage '--output-dir requires a value'
      shift
      ;;
    --use-existing-loaders)
      USE_EXISTING_LOADERS=1
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    --node|--node=*|--node-license|--node-license=*)
      invalid_usage 'host Node overrides are not supported; the runtime is pinned in the builder image'
      ;;
    *)
      invalid_usage "unknown option: $1"
      ;;
  esac
done

for command_name in docker id install mktemp readlink sed sha256sum stat uname; do
  command -v "$command_name" >/dev/null 2>&1 ||
    die "required host command is missing: $command_name"
done

[[ "$(id -u)" != 0 ]] ||
  die 'refusing to run as root; invoke Docker as the unprivileged artifact owner'
[[ -z "${DOCKER_DEFAULT_PLATFORM:-}" ]] ||
  die 'DOCKER_DEFAULT_PLATFORM is not supported; unset it to build for this host'
[[ "$SOURCE_DATE_EPOCH_VALUE" =~ ^[0-9]+$ ]] ||
  die 'SOURCE_DATE_EPOCH must be an integer'
[[ -r /sys/kernel/btf/vmlinux && -f /sys/kernel/btf/vmlinux && ! -L /sys/kernel/btf/vmlinux ]] ||
  die 'host kernel BTF is unavailable at /sys/kernel/btf/vmlinux'
PACKAGE_VERSION="$(sed -nE \
  's/^[[:space:]]*"version":[[:space:]]*"([^"[:space:]]+)"[,]?[[:space:]]*$/\1/p' \
  "$REPOSITORY_ROOT/package.json")"
[[ "$PACKAGE_VERSION" =~ ^[0-9A-Za-z][0-9A-Za-z.+-]{0,63}$ ]] ||
  die 'package version is missing or unsafe'
HOST_KERNEL_RELEASE="$(uname -r)"
[[ "$HOST_KERNEL_RELEASE" =~ ^[0-9A-Za-z._+-]+$ ]] ||
  die "host kernel release is unsafe: $HOST_KERNEL_RELEASE"

case "$OUTPUT_REQUESTED" in
  /*) ;;
  *) OUTPUT_REQUESTED="$CALLER_CWD/$OUTPUT_REQUESTED" ;;
esac
[[ ! -L "$OUTPUT_REQUESTED" ]] || die "output directory must not be a symlink: $OUTPUT_REQUESTED"
mkdir -p -- "$OUTPUT_REQUESTED"
[[ -d "$OUTPUT_REQUESTED" && ! -L "$OUTPUT_REQUESTED" ]] ||
  die "output path is not a directory: $OUTPUT_REQUESTED"
OUTPUT_DIR="$(cd -P "$OUTPUT_REQUESTED" && pwd)"
output_metadata="$(stat -Lc '%u %a' "$OUTPUT_DIR")"
output_mode="${output_metadata#* }"
if [[ "${output_metadata%% *}" != "$(id -u)" ]] ||
  (( (8#$output_mode & 8#22) != 0 )); then
  die "output directory must be owned by the caller and not group/world writable: $OUTPUT_DIR"
fi

for bind_source in "$REPOSITORY_ROOT" "$OUTPUT_DIR"; do
  case "$bind_source" in
    *','*$'\n'*) die "Docker bind path contains unsupported characters: $bind_source" ;;
    *','*) die "Docker bind path contains a comma: $bind_source" ;;
    *$'\n'*) die 'Docker bind path contains a newline' ;;
  esac
done

if ((USE_EXISTING_LOADERS == 1)); then
  for loader in \
    "$REPOSITORY_ROOT/bpf/nosh_build/build/nosh-build-loader" \
    "$REPOSITORY_ROOT/bpf/nosh_url/build/nosh-url-loader" \
    "$REPOSITORY_ROOT/bpf/nosh_l4/build/nosh-l4-loader" \
    "$REPOSITORY_ROOT/bpf/nosh_egress/build/nosh-egress-loader"
  do
    [[ -f "$loader" && ! -L "$loader" && -x "$loader" ]] ||
      die "reviewed loader is missing or unsafe: $loader"
  done
fi

docker info >/dev/null 2>&1 ||
  die 'Docker daemon is unavailable; refusing to fall back to host tools'
docker_endpoint="$(docker context inspect --format '{{.Endpoints.docker.Host}}')" ||
  die 'could not inspect the active Docker context'
[[ "$docker_endpoint" == unix://* ]] ||
  die 'a local Unix-socket Docker context is required for host BTF and source mounts'
docker_os="$(docker info --format '{{.OSType}}')" ||
  die 'could not inspect the Docker daemon platform'
[[ "$docker_os" == linux ]] || die "a Linux Docker daemon is required, found: $docker_os"
docker_security_options="$(docker info --format '{{json .SecurityOptions}}')" ||
  die 'could not inspect Docker security options'
[[ "$docker_security_options" != *rootless* &&
   "$docker_security_options" != *userns* ]] ||
  die 'rootless or userns-remapped Docker is not supported because caller-owned bind mounts cannot retain the required UID boundary'

host_architecture="$(uname -m)"
case "$host_architecture" in
  x86_64) docker_architecture=amd64; bundle_architecture=x86_64 ;;
  aarch64|arm64) docker_architecture=arm64; bundle_architecture=aarch64 ;;
  ppc64le) docker_architecture=ppc64le; bundle_architecture=ppc64le ;;
  *) die "the pinned Node builder image does not support host architecture: $host_architecture" ;;
esac
docker_platform="linux/$docker_architecture"

while :; do
  RESULT_NAME=".nosh-guard-host-bundle-result-${BASHPID}-${RANDOM}-${RANDOM}-${RANDOM}"
  RESULT_PATH="$OUTPUT_DIR/$RESULT_NAME"
  [[ ! -e "$RESULT_PATH" && ! -L "$RESULT_PATH" ]] && break
done

BUILD_CONTEXT="$(mktemp -d)"
install -d -m 0700 "$BUILD_CONTEXT/scripts"
install -m 0600 "$REPOSITORY_ROOT/Dockerfile.nosh-guard-host-bundle" "$BUILD_CONTEXT/Dockerfile"
install -m 0500 \
  "$REPOSITORY_ROOT/scripts/run-nosh-guard-host-bundle-container.sh" \
  "$BUILD_CONTEXT/scripts/run-nosh-guard-host-bundle-container.sh"

printf 'Building digest-pinned Nosh Guard bundle image...\n' >&2
docker build \
  --pull \
  --platform "$docker_platform" \
  --tag "$IMAGE_TAG" \
  "$BUILD_CONTEXT"

image_id="$(docker image inspect --format '{{.Id}}' "$IMAGE_TAG")" ||
  die 'could not inspect the built bundle image'
[[ "$image_id" =~ ^sha256:[0-9a-f]{64}$ ]] ||
  die "unexpected bundle image ID: $image_id"
image_label="$(docker image inspect \
  --format '{{index .Config.Labels "io.notty.nosh-guard-host-bundle"}}' \
  "$image_id")" || die 'could not verify the bundle image label'
[[ "$image_label" == 1 ]] || die 'built image is missing the Nosh Guard bundle label'

run_args=(
  --rm
  --init
  --read-only
  --user "$(id -u):$(id -g)"
  --platform "$docker_platform"
  --cap-drop ALL
  --security-opt no-new-privileges=true
  --pids-limit 512
  --cpus 2
  --memory 3g
  --ipc none
  --network none
  --tmpfs "/tmp:rw,nosuid,nodev,noexec,size=64m,mode=1777,uid=$(id -u),gid=$(id -g)"
  --tmpfs "/bundle-work:rw,nosuid,nodev,exec,size=3g,mode=0700,uid=$(id -u),gid=$(id -g)"
  --mount "type=bind,src=$REPOSITORY_ROOT,dst=/input,readonly"
  --mount "type=bind,src=$OUTPUT_DIR,dst=/output"
  --mount 'type=bind,src=/sys/kernel/btf/vmlinux,dst=/sys/kernel/btf/vmlinux,readonly'
  --env NOSH_GUARD_HOST_BUNDLE_CONTAINER=1
  --env NOSH_GUARD_HOST_BUNDLE_NETWORK_MODE=none
  --env TMPDIR=/bundle-work/tmp
  --env HOME=/bundle-work/home
  --env "SOURCE_DATE_EPOCH=$SOURCE_DATE_EPOCH_VALUE"
  --env "NOSH_GUARD_HOST_BUNDLE_RESULT=/output/$RESULT_NAME"
)
packager_args=()
if ((USE_EXISTING_LOADERS == 1)); then
  packager_args+=(--use-existing-loaders)
fi

printf 'Packaging Nosh Guard host bundle offline in Docker...\n' >&2
docker run "${run_args[@]}" "$image_id" "${packager_args[@]}"

[[ -f "$RESULT_PATH" && ! -L "$RESULT_PATH" ]] ||
  die 'bundle container completed without a result receipt'
result_metadata="$(stat -Lc '%u %a %h' "$RESULT_PATH")"
read -r result_owner result_mode result_links <<<"$result_metadata"
[[ "$result_owner" == "$(id -u)" && "$result_mode" == 600 && "$result_links" == 1 ]] ||
  die 'bundle result receipt has unsafe owner, mode, or link count'
mapfile -t result_lines <"$RESULT_PATH"
[[ "${#result_lines[@]}" == 2 &&
   "${result_lines[0]}" == ARCHIVE=* &&
   "${result_lines[1]}" == CHECKSUM=* ]] ||
  die 'bundle result receipt is malformed'
archive_name="${result_lines[0]#ARCHIVE=}"
checksum_name="${result_lines[1]#CHECKSUM=}"
expected_archive_name="notty-nosh-guard-${PACKAGE_VERSION}-${bundle_architecture}-${HOST_KERNEL_RELEASE}.tar.gz"
[[ "$archive_name" == "$expected_archive_name" &&
   "$checksum_name" == "$archive_name.sha256" ]] ||
  die 'bundle result receipt does not name the expected host artifact'
archive_path="$OUTPUT_DIR/$archive_name"
checksum_path="$OUTPUT_DIR/$checksum_name"
for artifact_path in "$archive_path" "$checksum_path"; do
  [[ -f "$artifact_path" && ! -L "$artifact_path" ]] ||
    die "bundle artifact is missing or unsafe: $artifact_path"
  artifact_metadata="$(stat -Lc '%u %a %h' "$artifact_path")"
  read -r artifact_owner artifact_mode artifact_links <<<"$artifact_metadata"
  [[ "$artifact_owner" == "$(id -u)" && "$artifact_mode" == 644 && "$artifact_links" == 1 ]] ||
    die "bundle artifact has unsafe owner, mode, or link count: $artifact_path"
done
mapfile -t checksum_lines <"$checksum_path"
[[ "${#checksum_lines[@]}" == 1 ]] || die 'bundle checksum file is malformed'
read -r expected_digest expected_name checksum_extra <<<"${checksum_lines[0]}"
[[ -z "${checksum_extra:-}" &&
   "$expected_digest" =~ ^[0-9a-f]{64}$ &&
   "$expected_name" == "$archive_name" ]] ||
  die 'bundle checksum file is malformed'
actual_digest="$(sha256sum "$archive_path")"
actual_digest="${actual_digest%% *}"
[[ "$actual_digest" == "$expected_digest" ]] || die 'bundle archive checksum verification failed'

printf 'host bundle: %s\n' "$archive_path"
printf 'checksum:    %s\n' "$checksum_path"
