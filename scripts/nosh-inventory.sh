#!/usr/bin/env bash
# Host orchestration only. Package metadata is parsed in the reviewed container.
set -euo pipefail
umask 077
WORKDIR='' IMAGE='' TOOLING='' OUTPUT='' SOURCE_ONLY=false
DOCKER=${NOSH_NET_REVIEW_DOCKER_BIN:-docker}
fail() { printf 'nosh inventory: %s\n' "$*" >&2; exit 1; }
while (($#)); do
  case "$1" in
    --source-only) SOURCE_ONLY=true; shift ;;
    --workdir|--image|--tooling|--output)
      (($# >= 2)) || fail "$1 requires a value"
      case "$1" in
        --workdir) WORKDIR=$2 ;; --image) IMAGE=$2 ;;
        --tooling) TOOLING=$2 ;; --output) OUTPUT=$2 ;;
      esac; shift 2 ;;
    *) fail "unknown option: $1" ;;
  esac
done
for tool in "$DOCKER" jq realpath timeout; do command -v "$tool" >/dev/null || fail "missing command: $tool"; done
[[ "$TOOLING" =~ ^sha256:[a-f0-9]{64}$ ]] || fail 'an exact local tooling image ID is required'
[[ $("$DOCKER" image inspect --format '{{.Id}}|{{index .Config.Labels "io.notty.guard.policy-tooling-abi"}}' "$TOOLING") == "$TOOLING|1" ]] || fail 'tooling image identity/ABI mismatch'
WORKDIR=$(realpath -e -- "$WORKDIR")
[[ -d "$WORKDIR" && "$OUTPUT" == /* ]] || fail 'workspace and absolute output directory are required'
for bind in "$WORKDIR" "$OUTPUT"; do
  [[ "$bind" != *','* && "$bind" != *$'\n'* && "$bind" != *$'\r'* ]] || fail 'unsafe mount path'
done
parent=$(dirname -- "$OUTPUT")
[[ $(realpath -e -- "$parent") == "$parent" && ! -L "$OUTPUT" && ! -e "$OUTPUT" ]] || fail 'output must be a new directory under a canonical parent'
[[ $(stat -c %u -- "$parent") == "$(id -u)" ]] || fail 'output parent must be caller-owned'
parent_mode=$(stat -c %a -- "$parent")
(( (8#$parent_mode & 0022) == 0 )) || fail 'output parent must not be writable by other users'
COLLECTOR='' CLIENT='' ARCHIVE='' ARCHIVE_DIR=''
RUN_STATE=$(mktemp -d "$parent/.nosh-inventory-run.XXXXXX")
COLLECTOR_CID_FILE=''
CREATED_CID_FILE="$RUN_STATE/export.cid"
cleanup() {
  local result=$?
  trap - EXIT INT TERM
  # Only Docker-created IDs recorded in our exclusive operation directory can
  # be removed. A failed create/name collision must never remove a foreign name.
  for cid_file in "$COLLECTOR_CID_FILE" "$CREATED_CID_FILE"; do
    [[ -n "$cid_file" && -f "$cid_file" && ! -L "$cid_file" ]] || continue
    owned_id=$(cat -- "$cid_file")
    [[ "$owned_id" =~ ^[a-f0-9]{64}$ ]] || { result=1; continue; }
    if "$DOCKER" container inspect "$owned_id" >/dev/null 2>&1; then
      "$DOCKER" rm -fv "$owned_id" >/dev/null 2>&1 || result=1
    fi
  done
  [[ -z "$ARCHIVE" ]] || rm -f -- "$ARCHIVE"
  [[ -z "$ARCHIVE_DIR" ]] || rmdir -- "$ARCHIVE_DIR"
  rm -f -- "$RUN_STATE"/*.cid
  rmdir -- "$RUN_STATE"
  exit "$result"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
run_collector() {
  COLLECTOR="nosh-inventory-$(id -u)-$$-$RANDOM"
  local result=0
  COLLECTOR_CID_FILE="$RUN_STATE/collector-$RANDOM.cid"
  timeout --signal=TERM --kill-after=5s 900s "$DOCKER" run --name "$COLLECTOR" --cidfile "$COLLECTOR_CID_FILE" --rm --pull never \
    --network none --user "$(id -u):$(id -g)" --read-only --cap-drop ALL \
    --security-opt no-new-privileges:true --pids-limit 32 --memory 512m --cpus 1 \
    --tmpfs /tmp:rw,nosuid,nodev,noexec,size=16777216 --env PYTHONDONTWRITEBYTECODE=1 \
    --entrypoint /usr/bin/python3 "$@" || result=$?
  # --rm removes normal exits; explicitly remove an interrupted collector.
  if [[ -f "$COLLECTOR_CID_FILE" && ! -L "$COLLECTOR_CID_FILE" ]]; then
    local owned_id
    owned_id=$(cat -- "$COLLECTOR_CID_FILE")
    [[ "$owned_id" =~ ^[a-f0-9]{64}$ ]] || return 1
    if "$DOCKER" container inspect "$owned_id" >/dev/null 2>&1; then
      "$DOCKER" rm -f "$owned_id" >/dev/null || return 1
    fi
    rm -- "$COLLECTOR_CID_FILE"
  fi
  COLLECTOR=''; COLLECTOR_CID_FILE=''
  return "$result"
}
run_collector "$TOOLING" -I -S /app/scripts/nosh-inventory.py --version >/dev/null \
  || fail 'rebuild the local policy tooling image: offline inventory collector is unavailable'
mkdir -m 0700 -- "$OUTPUT"
incomplete=0
run_collector --mount "type=bind,src=$WORKDIR,dst=/source,readonly" \
  --mount "type=bind,src=$OUTPUT,dst=/output" "$TOOLING" -I -S /app/scripts/nosh-inventory.py \
  source --input /source --output /output || incomplete=$?
[[ $incomplete == 0 || $incomplete == 2 ]] || fail 'source inventory failed; diagnostics retained in output directory'
if [[ "$SOURCE_ONLY" != true ]]; then
  [[ -n "$IMAGE" && "$IMAGE" != -* && "$IMAGE" != *[[:space:]]* ]] || fail 'a local workload image is required'
  requested_image=$IMAGE
  image_json=$("$DOCKER" image inspect "$IMAGE")
  IMAGE=$(jq -er '.[0].Id' <<<"$image_json")
  [[ "$IMAGE" =~ ^sha256:[a-f0-9]{64}$ ]] || fail 'invalid workload image ID'
  if [[ "$requested_image" == sha256:* && "$requested_image" != "$IMAGE" ]]; then
    fail 'exact requested image identity changed during inspection'
  fi
  jq -e '.[0].Config.Volumes // {} | length == 0' <<<"$image_json" >/dev/null \
    || fail 'image-declared volumes are unsupported by filesystem inventory; supply a volume-free image'
  CLIENT="nosh-inventory-export-$(id -u)-$$-$RANDOM"
  "$DOCKER" create --name "$CLIENT" --cidfile "$CREATED_CID_FILE" --pull never --network none --read-only --cap-drop ALL \
    --security-opt no-new-privileges:true --entrypoint /bin/false "$IMAGE" >/dev/null
  CLIENT=$(cat -- "$CREATED_CID_FILE")
  [[ "$CLIENT" =~ ^[a-f0-9]{64}$ ]] || fail 'invalid created export container ID'
  [[ $("$DOCKER" container inspect --format '{{.Image}}|{{.State.Status}}|{{len .Mounts}}' "$CLIENT") == "$IMAGE|created|0" ]] \
    || fail 'export container image, state or mounts changed'
  ARCHIVE_DIR=$(mktemp -d "$parent/.nosh-inventory-export.XXXXXX")
  ARCHIVE="$ARCHIVE_DIR/image.tar"
  # Bound the export before parsing too (16 GiB, 15 minutes).
  (ulimit -f 16777216; timeout --kill-after=5s 900s "$DOCKER" export --output "$ARCHIVE" "$CLIENT")
  chmod 0600 -- "$ARCHIVE"
  "$DOCKER" rm -v "$CLIENT" >/dev/null
  CLIENT=''; rm -- "$CREATED_CID_FILE"
  image_result=0
  run_collector --mount "type=bind,src=$ARCHIVE,dst=/input/image.tar,readonly" \
    --mount "type=bind,src=$OUTPUT,dst=/output" "$TOOLING" -I -S /app/scripts/nosh-inventory.py \
    image --input /input/image.tar --image-id "$IMAGE" --output /output || image_result=$?
  [[ $image_result == 0 || $image_result == 2 ]] || fail 'image inventory failed; diagnostics retained in output directory'
  (( image_result == 0 )) || incomplete=2
  rm -- "$ARCHIVE"; ARCHIVE=''
fi
exit "$incomplete"
