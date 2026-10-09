#!/usr/bin/env bash
set -euo pipefail

# HOST POLICY: this wrapper must never execute npm, npx, or node on the host.
# The package manager runs only in the purpose-built, locked-down Docker image.

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
REPO_ROOT="$(cd -P "$SCRIPT_DIR/.." && pwd)"
PACKAGE_PATH="$REPO_ROOT/package.json"
LOCK_PATH="$REPO_ROOT/package-lock.json"
DOCKERFILE_PATH="$REPO_ROOT/Dockerfile.package-lock"
HELPER_PATH="$REPO_ROOT/scripts/regenerate-package-lock-container.sh"
TIMEOUT_SECONDS=1800
RUN_ID=""
RUN_TMP=""
TMP_BASE=""
IMAGE_TAG=""
IMAGE_ID=""
IMAGE_CREATED=0
NETWORK_NAME=""
NETWORK_CREATED=0
GENERATE_CONTAINER=""
VALIDATE_CONTAINER=""
PUBLISH_TMP=""
REPLACE_DIRTY_LOCK=0
PACKAGE_HASH_BEFORE=""
LOCK_HASH_BEFORE=""
WRAPPER_HASH_BEFORE=""
HELPER_HASH_BEFORE=""
DOCKERFILE_HASH_BEFORE=""
MANIFEST_SNAPSHOT_HASH=""
VALIDATED_CANDIDATE_HASH=""

host_package_manager_forbidden() {
  printf 'regenerate-package-lock: refusing to execute host %s; Docker is mandatory\n' \
    "$1" >&2
  exit 97
}

function npm {
  host_package_manager_forbidden npm
}

function npx {
  host_package_manager_forbidden npx
}

function node {
  host_package_manager_forbidden node
}

readonly -f npm npx node

usage() {
  cat <<'EOF'
Usage: ./scripts/regenerate-package-lock.sh [--replace-dirty-lock]

Generate package-lock.json from the current package.json inside a purpose-built
Docker container. The old lockfile, node_modules, repository, host home, npm
configuration, credentials, and Docker socket never enter the container.
Only a private snapshot of package.json is sent to the generator on stdin.

The generator uses a digest-pinned Node/npm image, an empty tmpfs workspace,
disabled lifecycle scripts and non-registry dependency sources, a dedicated
ephemeral bridge network, and a non-root capability-free process. A second
container validates the candidate with --network none before the host replaces
package-lock.json atomically. Normal registry and advisory access still require
bridge egress during generation, and Docker may first pull the digest-pinned
base image. This is hardened, not an offline operation.

Options:
  --replace-dirty-lock  Replace existing uncommitted package-lock.json changes.
                        Use only after reviewing or intentionally discarding
                        those generated changes; the committed lock remains in
                        Git history.
  -h, --help            Show this help.

This script never runs npm, npx, or node on the host. It never edits
package.json, commits, runs the release audit against a dirty checkout, or
creates/moves a release tag.
EOF
}

warn() {
  printf 'regenerate-package-lock: warning: %s\n' "$*" >&2
}

die() {
  printf 'regenerate-package-lock: %s\n' "$*" >&2
  exit 1
}

require_host_command() {
  command -v "$1" >/dev/null 2>&1 || die "required host command unavailable: $1"
}

hash_file() {
  sha256sum -- "$1" | awk '{ print $1 }'
}

make_run_id() {
  local random_hex

  random_hex="$(od -An -N12 -tx1 /dev/urandom | tr -d ' \n')"
  [[ "$random_hex" =~ ^[0-9a-f]{24}$ ]] || return 1
  printf '%s' "$random_hex"
}

run_bounded() {
  timeout \
    --signal=TERM \
    --kill-after=30s \
    "$TIMEOUT_SECONDS" \
    "$@"
}

docker_object_exists() {
  local object_type="$1"
  local object_name="$2"

  case "$object_type" in
    container) docker container inspect "$object_name" >/dev/null 2>&1 ;;
    network) docker network inspect "$object_name" >/dev/null 2>&1 ;;
    image) docker image inspect "$object_name" >/dev/null 2>&1 ;;
    *) return 2 ;;
  esac
}

docker_object_has_run_label() {
  local object_type="$1"
  local object_name="$2"
  local actual
  local format

  case "$object_type" in
    container) format='{{ index .Config.Labels "io.notty.package-lock.run" }}' ;;
    network) format='{{ index .Labels "io.notty.package-lock.run" }}' ;;
    image) format='{{ index .Config.Labels "io.notty.package-lock.run" }}' ;;
    *) return 2 ;;
  esac

  case "$object_type" in
    container)
      actual="$(docker container inspect --format "$format" "$object_name" 2>/dev/null || true)"
      ;;
    network)
      actual="$(docker network inspect --format "$format" "$object_name" 2>/dev/null || true)"
      ;;
    image)
      actual="$(docker image inspect --format "$format" "$object_name" 2>/dev/null || true)"
      ;;
  esac
  [[ -n "$RUN_ID" && "$actual" == "$RUN_ID" ]]
}

cleanup() {
  local cleanup_failed=0
  local container_name
  local docker_cleanup_needed=0

  if [[ -n "$GENERATE_CONTAINER" || -n "$VALIDATE_CONTAINER" ]] ||
     (( NETWORK_CREATED == 1 || IMAGE_CREATED == 1 ))
  then
    docker_cleanup_needed=1
  fi

  if (( docker_cleanup_needed == 1 )) &&
     ! command -v docker >/dev/null 2>&1
  then
    warn 'Docker disappeared before ephemeral resources could be checked'
    cleanup_failed=1
  elif (( docker_cleanup_needed == 1 )) &&
       ! timeout --signal=TERM --kill-after=5s 15s docker info >/dev/null 2>&1
  then
    warn 'Docker daemon is unavailable; ephemeral resources may require manual cleanup'
    cleanup_failed=1
  elif (( docker_cleanup_needed == 1 )); then
    for container_name in "$GENERATE_CONTAINER" "$VALIDATE_CONTAINER"; do
      if [[ -z "$container_name" ]] ||
         ! docker_object_exists container "$container_name"
      then
        continue
      fi
      if docker_object_has_run_label container "$container_name"; then
        docker rm --force "$container_name" >/dev/null 2>&1 || cleanup_failed=1
      else
        warn "refusing to remove container with the wrong run label: $container_name"
        cleanup_failed=1
      fi
    done

    if (( NETWORK_CREATED == 1 )) &&
       docker_object_exists network "$NETWORK_NAME"
    then
      if docker_object_has_run_label network "$NETWORK_NAME"; then
        docker network rm "$NETWORK_NAME" >/dev/null 2>&1 || cleanup_failed=1
      else
        warn "refusing to remove network with the wrong run label: $NETWORK_NAME"
        cleanup_failed=1
      fi
    fi

    if (( IMAGE_CREATED == 1 )) && docker_object_exists image "$IMAGE_TAG"; then
      if docker_object_has_run_label image "$IMAGE_TAG"; then
        docker image rm "$IMAGE_TAG" >/dev/null 2>&1 || cleanup_failed=1
      else
        warn "refusing to remove image with the wrong run label: $IMAGE_TAG"
        cleanup_failed=1
      fi
    fi
  fi

  if [[ -n "$PUBLISH_TMP" ]]; then
    case "$PUBLISH_TMP" in
      "$REPO_ROOT"/.package-lock.json.tmp.*)
        rm -f -- "$PUBLISH_TMP" || cleanup_failed=1
        ;;
      *)
        warn "refusing to remove unexpected atomic temp path: $PUBLISH_TMP"
        cleanup_failed=1
        ;;
    esac
  fi

  if [[ -n "$RUN_TMP" ]]; then
    case "$RUN_TMP" in
      "$TMP_BASE"/notty-package-lock.*)
        rm -rf -- "$RUN_TMP" || cleanup_failed=1
        ;;
      *)
        warn "refusing to remove unexpected run temp path: $RUN_TMP"
        cleanup_failed=1
        ;;
    esac
  fi

  return "$cleanup_failed"
}

finalize() {
  local status="$?"

  trap - EXIT
  trap ':' HUP INT TERM
  if ! cleanup; then
    warn 'ephemeral cleanup was incomplete'
    if (( status == 0 )); then
      status=1
    fi
  fi
  exit "$status"
}

handle_signal() {
  warn "interrupted by $1"
  exit "$2"
}

validate_repository_inputs() {
  local git_root
  local path

  [[ "$REPO_ROOT" != / && "$REPO_ROOT" != "${HOME:-}" ]] ||
    die 'refusing to operate on a filesystem or home-directory root'
  [[ "$REPO_ROOT" != *$'\n'* && "$REPO_ROOT" != *$'\r'* ]] ||
    die 'repository path contains a newline'

  git_root="$(git -C "$REPO_ROOT" rev-parse --show-toplevel 2>/dev/null)" ||
    die 'not a Git checkout'
  git_root="$(cd -P "$git_root" && pwd)"
  [[ "$git_root" == "$REPO_ROOT" ]] ||
    die 'the lockfile generator must live at the Git checkout root'

  for path in "$PACKAGE_PATH" "$LOCK_PATH" "$DOCKERFILE_PATH" "$HELPER_PATH"; do
    [[ -f "$path" && ! -L "$path" ]] ||
      die "required input must be a regular, non-symlink file: $path"
  done
  git -C "$REPO_ROOT" ls-files --error-unmatch package-lock.json >/dev/null 2>&1 ||
    die 'package-lock.json must be tracked before it can be regenerated'

  if ! git -C "$REPO_ROOT" diff --quiet -- package-lock.json ||
     ! git -C "$REPO_ROOT" diff --cached --quiet -- package-lock.json
  then
    if (( REPLACE_DIRTY_LOCK == 0 )); then
      die 'package-lock.json has uncommitted changes; review them, then rerun with --replace-dirty-lock to discard them'
    fi
    warn 'replacing reviewed uncommitted package-lock.json changes as requested'
  fi
}

capture_input_hashes() {
  PACKAGE_HASH_BEFORE="$(hash_file "$PACKAGE_PATH")"
  LOCK_HASH_BEFORE="$(hash_file "$LOCK_PATH")"
  WRAPPER_HASH_BEFORE="$(hash_file "$REPO_ROOT/scripts/regenerate-package-lock.sh")"
  HELPER_HASH_BEFORE="$(hash_file "$HELPER_PATH")"
  DOCKERFILE_HASH_BEFORE="$(hash_file "$DOCKERFILE_PATH")"

  [[ "$PACKAGE_HASH_BEFORE" =~ ^[0-9a-f]{64}$ &&
     "$LOCK_HASH_BEFORE" =~ ^[0-9a-f]{64}$ &&
     "$WRAPPER_HASH_BEFORE" =~ ^[0-9a-f]{64}$ &&
     "$HELPER_HASH_BEFORE" =~ ^[0-9a-f]{64}$ &&
     "$DOCKERFILE_HASH_BEFORE" =~ ^[0-9a-f]{64}$ ]] ||
    die 'could not capture stable SHA-256 input hashes'
}

assert_inputs_unchanged() {
  [[ -f "$PACKAGE_PATH" && ! -L "$PACKAGE_PATH" &&
     "$(hash_file "$PACKAGE_PATH")" == "$PACKAGE_HASH_BEFORE" ]] || {
    warn 'package.json changed during lockfile generation'
    return 1
  }
  [[ -f "$LOCK_PATH" && ! -L "$LOCK_PATH" &&
     "$(hash_file "$LOCK_PATH")" == "$LOCK_HASH_BEFORE" ]] || {
    warn 'the existing package-lock.json changed during lockfile generation'
    return 1
  }
  [[ "$(hash_file "$REPO_ROOT/scripts/regenerate-package-lock.sh")" == "$WRAPPER_HASH_BEFORE" &&
     "$(hash_file "$HELPER_PATH")" == "$HELPER_HASH_BEFORE" &&
     "$(hash_file "$DOCKERFILE_PATH")" == "$DOCKERFILE_HASH_BEFORE" ]] || {
    warn 'the lockfile generator implementation changed during the run'
    return 1
  }
}

build_image() {
  local build_context="$RUN_TMP/image-context"

  mkdir -p "$build_context/scripts"
  cp -- "$DOCKERFILE_PATH" "$build_context/Dockerfile"
  cp -- "$HELPER_PATH" "$build_context/scripts/regenerate-package-lock-container.sh"
  [[ "$(hash_file "$build_context/Dockerfile")" == "$DOCKERFILE_HASH_BEFORE" &&
     "$(hash_file "$build_context/scripts/regenerate-package-lock-container.sh")" == "$HELPER_HASH_BEFORE" ]] ||
    die 'Docker build-context inputs do not match the captured generator inputs'

  printf '\n=== Build digest-pinned package-lock image ===\n'
  IMAGE_CREATED=1
  run_bounded docker build \
    --pull \
    --network none \
    --label "io.notty.package-lock.run=$RUN_ID" \
    --tag "$IMAGE_TAG" \
    "$build_context"

  IMAGE_ID="$(docker image inspect --format '{{ .Id }}' "$IMAGE_TAG")" ||
    die 'could not inspect the package-lock image'
  [[ "$IMAGE_ID" == sha256:* ]] || die "unexpected image ID: $IMAGE_ID"
  docker_object_has_run_label image "$IMAGE_TAG" ||
    die 'package-lock image is missing its run label'
  printf 'image_id=%s\n' "$IMAGE_ID"
}

create_network() {
  NETWORK_CREATED=1
  docker network create \
    --driver bridge \
    --label "io.notty.package-lock.run=$RUN_ID" \
    "$NETWORK_NAME" >/dev/null
  docker_object_has_run_label network "$NETWORK_NAME" ||
    die 'package-lock network is missing its run label'
}

container_args() {
  local container_name="$1"
  local network_mode="$2"

  printf '%s\0' \
    --name "$container_name" \
    --label "io.notty.package-lock.run=$RUN_ID" \
    --rm \
    --init \
    --interactive \
    --read-only \
    --user 1000:1000 \
    --cap-drop ALL \
    --security-opt=no-new-privileges=true \
    --pids-limit 128 \
    --cpus 2 \
    --memory 2g \
    --ulimit nofile=4096:4096 \
    --ipc none \
    --network "$network_mode" \
    --tmpfs '/tmp:rw,nosuid,nodev,noexec,size=128m,mode=1777,uid=1000,gid=1000' \
    --tmpfs '/lock/runtime:rw,nosuid,nodev,noexec,size=1g,mode=0700,uid=1000,gid=1000' \
    --env DOCKER_CONTAINER=1 \
    --env CI=1 \
    --env HOME=/lock/runtime/home \
    --env XDG_CACHE_HOME=/lock/runtime/xdg-cache \
    --env XDG_CONFIG_HOME=/lock/runtime/xdg-config \
    --env NPM_CONFIG_CACHE=/lock/runtime/npm-cache \
    --env NPM_CONFIG_USERCONFIG=/dev/null \
    --env NPM_CONFIG_GLOBALCONFIG=/lock/runtime/global-npmrc \
    --env NPM_CONFIG_REGISTRY=https://registry.npmjs.org/ \
    --env NPM_CONFIG_OMIT_LOCKFILE_REGISTRY_RESOLVED=false \
    --env HTTP_PROXY= \
    --env HTTPS_PROXY= \
    --env ALL_PROXY= \
    --env NO_PROXY= \
    --env http_proxy= \
    --env https_proxy= \
    --env all_proxy= \
    --env no_proxy= \
    --env "PACKAGE_LOCK_NETWORK_MODE=$network_mode"
}

generate_candidate() {
  local args=()
  local candidate_path="$RUN_TMP/package-lock.candidate.json"
  local manifest_snapshot="$RUN_TMP/package.json"

  cp -- "$PACKAGE_PATH" "$manifest_snapshot"
  chmod 0400 "$manifest_snapshot"
  MANIFEST_SNAPSHOT_HASH="$(hash_file "$manifest_snapshot")"
  [[ "$MANIFEST_SNAPSHOT_HASH" == "$PACKAGE_HASH_BEFORE" ]] ||
    die 'package.json changed while it was being snapshotted'

  while IFS= read -r -d '' item; do
    args+=("$item")
  done < <(container_args "$GENERATE_CONTAINER" "$NETWORK_NAME")

  printf '\n=== Generate fresh package-lock.json from package.json only ===\n'
  if ! run_bounded docker run \
    "${args[@]}" \
    "$IMAGE_ID" generate <"$manifest_snapshot" >"$candidate_path"
  then
    die 'locked-down package-lock generation failed; the existing lockfile was not changed'
  fi

  [[ -s "$candidate_path" && -f "$candidate_path" && ! -L "$candidate_path" ]] ||
    die 'generator did not return a regular, non-empty candidate lockfile'
  printf 'candidate_sha256=%s\n' "$(hash_file "$candidate_path")"
}

validate_candidate_offline() {
  local args=()
  local candidate_path="$RUN_TMP/package-lock.candidate.json"
  local manifest_snapshot="$RUN_TMP/package.json"
  local manifest_size
  local candidate_size
  local candidate_hash

  manifest_size="$(wc -c <"$manifest_snapshot" | tr -d '[:space:]')"
  candidate_size="$(wc -c <"$candidate_path" | tr -d '[:space:]')"
  [[ "$manifest_size" =~ ^[1-9][0-9]*$ && "$manifest_size" -le 1048576 ]] ||
    die 'package.json byte count is invalid or exceeds 1 MiB'
  [[ "$candidate_size" =~ ^[1-9][0-9]*$ && "$candidate_size" -le 67108864 ]] ||
    die 'candidate lockfile byte count is invalid or exceeds 64 MiB'
  candidate_hash="$(hash_file "$candidate_path")"
  [[ "$(hash_file "$manifest_snapshot")" == "$MANIFEST_SNAPSHOT_HASH" ]] ||
    die 'package.json snapshot changed before offline validation'

  while IFS= read -r -d '' item; do
    args+=("$item")
  done < <(container_args "$VALIDATE_CONTAINER" none)

  printf '\n=== Validate candidate in a fresh no-network container ===\n'
  if ! {
    printf '%s\n' "$manifest_size"
    command cat "$manifest_snapshot"
    command cat "$candidate_path"
  } | run_bounded docker run "${args[@]}" "$IMAGE_ID" validate
  then
    die 'offline candidate validation failed; the existing lockfile was not changed'
  fi

  [[ "$(hash_file "$candidate_path")" == "$candidate_hash" ]] ||
    die 'candidate lockfile changed during offline validation'
  [[ "$(hash_file "$manifest_snapshot")" == "$MANIFEST_SNAPSHOT_HASH" ]] ||
    die 'package.json snapshot changed during offline validation'
  VALIDATED_CANDIDATE_HASH="$candidate_hash"
}

publish_candidate() {
  local candidate_path="$RUN_TMP/package-lock.candidate.json"
  local candidate_hash

  assert_inputs_unchanged ||
    die 'inputs changed concurrently; the existing lockfile was not changed'
  candidate_hash="$(hash_file "$candidate_path")"
  [[ "$VALIDATED_CANDIDATE_HASH" =~ ^[0-9a-f]{64}$ &&
     "$candidate_hash" == "$VALIDATED_CANDIDATE_HASH" ]] ||
    die 'candidate lockfile no longer matches the offline-validated bytes'
  [[ "$(hash_file "$RUN_TMP/package.json")" == "$MANIFEST_SNAPSHOT_HASH" &&
     "$MANIFEST_SNAPSHOT_HASH" == "$PACKAGE_HASH_BEFORE" ]] ||
    die 'package.json snapshot no longer matches the validated manifest'

  if cmp -s -- "$candidate_path" "$LOCK_PATH"; then
    printf '\npackage-lock.json is already identical to the validated candidate.\n'
    return
  fi

  PUBLISH_TMP="$(mktemp "$REPO_ROOT/.package-lock.json.tmp.XXXXXXXX")" ||
    die 'could not create the same-directory atomic output file'
  cp -- "$candidate_path" "$PUBLISH_TMP"
  chmod 0644 "$PUBLISH_TMP"
  [[ "$(hash_file "$PUBLISH_TMP")" == "$VALIDATED_CANDIDATE_HASH" ]] ||
    die 'atomic output copy does not match the validated candidate'

  assert_inputs_unchanged ||
    die 'inputs changed before publication; the existing lockfile was not changed'
  [[ "$(hash_file "$candidate_path")" == "$VALIDATED_CANDIDATE_HASH" &&
     "$(hash_file "$RUN_TMP/package.json")" == "$MANIFEST_SNAPSHOT_HASH" ]] ||
    die 'validated candidate inputs changed before atomic publication'
  mv -T -- "$PUBLISH_TMP" "$LOCK_PATH"
  PUBLISH_TMP=""

  printf '\npackage-lock.json replaced atomically.\n'
  printf 'package_json_sha256=%s\n' "$PACKAGE_HASH_BEFORE"
  printf 'package_lock_sha256=%s\n' "$VALIDATED_CANDIDATE_HASH"
}

print_handoff() {
  cat <<'EOF'

Next steps:
  1. Review: git diff -- package.json package-lock.json
  2. Commit the reviewed manifest, lockfile, generator, tests, and docs.
  3. Run: ./scripts/release-audit.sh
  4. Resolve every remaining automated and applicable manual gate.
  5. Create v1.0.0 only when the missing tag is the sole automated failure.
  6. Rerun ./scripts/release-audit.sh against that exact tagged commit.

No commit, release audit, or tag was created automatically.
EOF
}

main() {
  local command_name

  while (( $# > 0 )); do
    case "$1" in
      --replace-dirty-lock)
        REPLACE_DIRTY_LOCK=1
        ;;
      -h|--help)
        usage
        return 0
        ;;
      *)
        usage >&2
        return 2
        ;;
    esac
    shift
  done

  trap finalize EXIT
  trap 'handle_signal HUP 129' HUP
  trap 'handle_signal INT 130' INT
  trap 'handle_signal TERM 143' TERM

  for command_name in \
    awk cat chmod cmp cp dirname docker git mkdir mktemp mv od pwd readlink \
    realpath rm sha256sum timeout tr wc
  do
    require_host_command "$command_name"
  done

  validate_repository_inputs
  docker info >/dev/null 2>&1 ||
    die 'Docker daemon is unavailable; refusing to fall back to host npm'

  TMP_BASE="$(cd -P "${TMPDIR:-/tmp}" && pwd)" ||
    die 'could not resolve the host temporary directory'
  [[ "$TMP_BASE" != / && "$TMP_BASE" != "${HOME:-}" ]] ||
    die 'refusing to use a filesystem or home-directory root as temporary storage'

  RUN_ID="$(make_run_id)" || die 'could not create a random run ID'
  RUN_TMP="$(mktemp -d "$TMP_BASE/notty-package-lock.XXXXXXXX")" ||
    die 'could not create the private run directory'
  chmod 0700 "$RUN_TMP"

  IMAGE_TAG="notty-package-lock:node24.18.0-$RUN_ID"
  NETWORK_NAME="notty-package-lock-net-$RUN_ID"
  GENERATE_CONTAINER="notty-package-lock-generate-$RUN_ID"
  VALIDATE_CONTAINER="notty-package-lock-validate-$RUN_ID"

  capture_input_hashes
  build_image
  create_network
  generate_candidate
  validate_candidate_offline
  publish_candidate
  print_handoff
}

main "$@"
