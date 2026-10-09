#!/usr/bin/env bash
set -euo pipefail
umask 077
REPO=$(cd -P -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
MODE=${1:-help}
(($# == 0)) || shift
WORKDIR=$PWD
WORKLOAD=dev
WORKLOAD_EXPLICIT=false
REVISION=''
SESSION=''
DIGEST=''
YES=false
SBOM_SOURCE=''
SBOM_IMAGE=''
DOCKER=${NOSH_NET_REVIEW_DOCKER_BIN:-docker}
STATE_ROOT=${NOSH_PROFILE_REVIEW_STATE_ROOT:-${XDG_STATE_HOME:-$HOME/.local/state}/nosh/policy-review}
CONFIG_HOME=${XDG_CONFIG_HOME:-$HOME/.config}
APPLY_CONFIG=${NOSH_POLICY_APPLY_CONFIG:-$CONFIG_HOME/nosh/policy-apply.json}
TOOLING=${NOSH_POLICY_TOOLING_IMAGE:-}
UI_IMAGE=${NOSH_POLICY_REVIEW_UI_IMAGE:-}
APPLY_DIR=''
IMAGE=''
RESULT_JSON=''
EXPECTED_IMAGE=''

die() { printf 'nosh net %s: %s\n' "$MODE" "$*" >&2; exit 1; }
usage() {
  cat <<'HELP'
Usage:
  nosh net review [--workload dev|run] [--revision LEARN_ID] [--workdir DIR]
                  [--expected-image sha256:ID]
                  [--sbom-source FILE --sbom-image FILE]
  nosh net apply --review SESSION --decision-digest SHA256 [--yes] [--result-json FILE]
  nosh net inventory --workdir DIR --image LOCAL_IMAGE
  nosh net prepare --workdir DIR
  nosh net check --review SESSION [--decision-digest SHA256]
  nosh net tooling-status [--result-json FILE]

Review reopens the exact runtime candidate; it never rebuilds or learns traffic.
Inventories are generated offline inside the local policy tooling image.
Apply verifies, snapshots, projects, approves, grants and activates a saved IP
policy for future guarded runs. It does not change already-running containers.

First-time setup: run nosh init --step signing as your normal host user.

One-time signing configuration: ~/.config/nosh/policy-apply.json, mode 0600
(or NOSH_POLICY_APPLY_CONFIG). Example:
{
  "schemaVersion": 1,
  "reviewPrivateKey": "/absolute/review/private.pem",
  "reviewPublicKey": "/absolute/review/public.pem",
  "deploymentPrivateKey": "/absolute/deployment/private.pem",
  "reviewAudience": "your-configured-review-audience",
  "deploymentAudience": "your-configured-guard-instance-audience"
}
Keys and audiences must match the installed root-owned Guard trust. This command
never creates keys or modifies that trust. Signing keys are mounted separately.
HELP
}
[[ "$MODE" == review || "$MODE" == apply || "$MODE" == inventory || "$MODE" == prepare || "$MODE" == check || "$MODE" == tooling-status ]] || { usage; exit 0; }
while (($#)); do
  case "$1" in
    -h|--help) usage; exit 0 ;;
    --yes) YES=true; shift ;;
    --workload|--revision|--workdir|--review|--decision-digest|--sbom-source|--sbom-image|--image|--result-json|--expected-image)
      [[ -n "${2:-}" ]] || die "$1 requires a value"
      case "$1" in
        --workload) WORKLOAD=$2; WORKLOAD_EXPLICIT=true ;;
        --revision) REVISION=$2 ;;
        --workdir) WORKDIR=$2 ;;
        --review) SESSION=$2 ;;
        --decision-digest) DIGEST=$2 ;;
        --sbom-source) SBOM_SOURCE=$2 ;;
        --sbom-image) SBOM_IMAGE=$2 ;;
        --image) IMAGE=$2 ;;
        --expected-image) EXPECTED_IMAGE=$2 ;;
        --result-json) RESULT_JSON=$2 ;;
      esac
      shift 2 ;;
    *) die "unknown option: $1" ;;
  esac
done
case "$WORKLOAD" in dev|run) ;; *) die 'invalid workload' ;; esac
if [[ -n "$EXPECTED_IMAGE" ]]; then
  [[ "$MODE" == review || "$MODE" == prepare ]] || die '--expected-image is only supported by review or prepare'
  [[ "$EXPECTED_IMAGE" =~ ^sha256:[a-f0-9]{64}$ ]] || die 'invalid expected image ID'
fi
WORKLOAD_SUFFIX="-$WORKLOAD"
for required in "$DOCKER" jq realpath sha256sum; do command -v "$required" >/dev/null || die "missing command: $required"; done
private_file() {
  [[ -f "$1" && ! -L "$1" && $(stat -c '%u:%a:%h' -- "$1") == "$(id -u):600:1" ]] || die "expected a caller-owned mode 0600 regular file: $1"
}
bind_path() {
  [[ "$1" == /* && "$1" != *','* && "$1" != *$'\n'* && "$1" != *$'\r'* && $(realpath -e -- "$1") == "$1" ]] || die "unsafe Docker bind path: $1"
}
IMAGE_CONFIG=${NOSH_PROFILE_REVIEW_IMAGE_CONFIG:-$CONFIG_HOME/nosh/policy-review-images.conf}
if [[ -e "$IMAGE_CONFIG" ]]; then
  private_file "$IMAGE_CONFIG"
  [[ -n "$TOOLING" ]] || TOOLING=$(sed -n 's/^NOSH_POLICY_TOOLING_IMAGE=//p' "$IMAGE_CONFIG")
  [[ -n "$UI_IMAGE" ]] || UI_IMAGE=$(sed -n 's/^NOSH_POLICY_REVIEW_UI_IMAGE=//p' "$IMAGE_CONFIG")
fi
verify_tooling() {
  [[ "$TOOLING" =~ ^sha256:[a-f0-9]{64}$ ]] || die 'configure NOSH_POLICY_TOOLING_IMAGE with an exact local image ID (see profile-build-and-review.sh --help)'
  [[ $("$DOCKER" image inspect --format '{{.Id}}|{{index .Config.Labels "io.notty.guard.policy-tooling-abi"}}' "$TOOLING") == "$TOOLING|1" ]] || die 'policy tooling identity/ABI mismatch'
}
tooling_run() {
  "$DOCKER" run --rm --pull never --network none --user "$(id -u):$(id -g)" \
    --read-only --cap-drop ALL --security-opt no-new-privileges:true \
    --pids-limit 128 --memory 1g --tmpfs /tmp:rw,nosuid,nodev,noexec,size=67108864 \
    --env HOME=/tmp/nosh-policy-home --entrypoint /usr/local/bin/node "$@"
}

resolve_tooling() {
  if [[ -z "$TOOLING" ]]; then
    TOOLING=$("$DOCKER" image inspect --format '{{.Id}}' nosh 2>/dev/null) || die 'build/configure the local policy tooling image first'
  fi
  verify_tooling
}

if [[ "$MODE" == tooling-status ]]; then
  [[ -z "$REVISION$SESSION$DIGEST$SBOM_SOURCE$SBOM_IMAGE$IMAGE" && "$YES" == false ]] || die 'unexpected options for tooling-status'
  command -v timeout >/dev/null || die 'missing command: timeout'
  [[ -z "$TOOLING" || "$TOOLING" =~ ^sha256:[a-f0-9]{64}$ ]] || die 'configure policy tooling with an exact local image ID'
  if [[ -n "$RESULT_JSON" ]]; then
    [[ "$RESULT_JSON" == /* && ! -e "$RESULT_JSON" && ! -L "$RESULT_JSON" ]] || die 'result file must be a new absolute path'
    probe_result_parent=$(dirname -- "$RESULT_JSON")
    bind_path "$probe_result_parent"
    [[ $(stat -c '%u:%a' -- "$probe_result_parent") == "$(id -u):700" ]] || die 'result parent must be caller-owned mode 0700'
  fi
  # Infrastructure failures must not be turned into recommendations to rebuild.
  timeout --signal=TERM --kill-after=5s 30s "$DOCKER" info --format '{{.ID}}' >/dev/null || die 'Docker daemon is unavailable; restore Docker access before checking tooling'
  probe_state=$(mktemp -d /tmp/nosh-tooling-check.XXXXXX)
  probe_cid="$probe_state/container.cid"
  probe_cleanup() {
    local result=$? owned_id
    trap - EXIT INT TERM
    if [[ -f "$probe_cid" && ! -L "$probe_cid" ]]; then
      owned_id=$(cat -- "$probe_cid")
      if [[ "$owned_id" =~ ^[a-f0-9]{64}$ ]]; then
        if timeout --signal=TERM --kill-after=5s 15s "$DOCKER" container inspect "$owned_id" >/dev/null 2>"$probe_state/cleanup.err"; then
          timeout --signal=TERM --kill-after=5s 15s "$DOCKER" rm -f "$owned_id" >/dev/null || result=1
        else
          cleanup_error=$(<"$probe_state/cleanup.err")
          if [[ "${cleanup_error,,}" != *'no such container'* && "${cleanup_error,,}" != *'no such object'* ]]; then
            printf 'nosh net tooling-status: could not verify probe container cleanup\n' >&2
            result=1
          fi
        fi
      else
        printf 'nosh net tooling-status: invalid probe container identity\n' >&2
        result=1
      fi
    fi
    rm -f -- "$probe_cid" "$probe_state/inspect.err" "$probe_state/cleanup.err"
    rmdir -- "$probe_state" || result=1
    return "$result"
  }
  trap 'probe_cleanup; exit $?' EXIT
  trap 'exit 130' INT
  trap 'exit 143' TERM
  probe_result() {
    local status=$1 reason=$2 result=$3 document result_temporary
    # Emit success only after confirming that no probe container remains.
    probe_cleanup || exit 1
    document=$(jq -n --arg status "$status" --arg image "$TOOLING" --arg reason "$reason" \
      '{schemaVersion:1,status:$status,toolingImage:(if $image == "" then null else $image end),reason:$reason}')
    if [[ -n "$RESULT_JSON" ]]; then
      result_temporary=$(mktemp "$probe_result_parent/.tooling-status.XXXXXX")
      if ! printf '%s\n' "$document" > "$result_temporary" || ! ln -T -- "$result_temporary" "$RESULT_JSON"; then
        rm -f -- "$result_temporary"
        die 'could not publish the tooling status result without replacing an existing file'
      fi
      rm -- "$result_temporary"
    fi
    printf '%s\n' "$document"
    exit "$result"
  }
  probe_reference=${TOOLING:-nosh}
  if ! probe_identity=$(timeout --signal=TERM --kill-after=5s 30s "$DOCKER" image inspect \
    --format '{{.Id}}|{{index .Config.Labels "io.notty.guard.policy-tooling-abi"}}' "$probe_reference" 2>"$probe_state/inspect.err"); then
    inspect_error=$(<"$probe_state/inspect.err")
    if [[ "${inspect_error,,}" == *'no such image'* || "${inspect_error,,}" == *'no such object'* ]]; then
      probe_result needs-build 'The selected local policy tooling image is missing.' 3
    fi
    cat -- "$probe_state/inspect.err" >&2
    die 'could not inspect the selected tooling image'
  fi
  probe_id=${probe_identity%%|*}
  [[ "$probe_id" =~ ^sha256:[a-f0-9]{64}$ && "$probe_identity" == *'|'* ]] || die 'Docker returned an invalid tooling image identity'
  [[ -z "$TOOLING" || "$TOOLING" == "$probe_id" ]] || die 'the selected tooling image identity changed during inspection'
  TOOLING=$probe_id
  [[ "$probe_identity" == "$TOOLING|1" ]] || probe_result needs-build 'The selected image does not support the policy tooling ABI.' 3
  probe_code=$(cat <<'JAVASCRIPT'
import { existsSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
const inventory = '/app/scripts/nosh-inventory.py';
const session = '/app/lib/guard/review/session.js';
const reviewCli = '/app/lib/guard/review/cli.js';
if (!existsSync(inventory) || !existsSync(session) || !existsSync(reviewCli) || !existsSync('/app/scripts/nosh-policy-session.mjs')) process.exit(42);
const version = spawnSync('/usr/bin/python3', ['-I', '-S', inventory, '--version'], { encoding: 'utf8', timeout: 10000, maxBuffer: 16384 });
if (version.error?.code === 'ENOENT') process.exit(42);
if (version.error || version.status !== 0) {
  console.error('Inventory version check failed:', version.error?.message || version.stderr || version.signal || version.status);
  process.exit(1);
}
if (version.stdout.trim() !== 'nosh-inventory 1') process.exit(42);
const api = await import(session);
if (!['checkReviewSession', 'snapshotReviewSelection', 'migrateReviewDraft'].every(name => typeof api[name] === 'function')) process.exit(42);
const { resolveReviewGraphHosts } = await import(reviewCli);
if (typeof resolveReviewGraphHosts !== 'function') process.exit(42);
// Exercise the pure resolver with synthetic interfaces. The offline probe
// must detect older tooling before Docker assigns a non-172 private subnet.
for (const address of ['192.168.240.2', '10.240.0.2']) {
  let resolved;
  try {
    resolved = resolveReviewGraphHosts({ host: '0.0.0.0', advertiseHost: 'auto' }, {
      networkInterfaces: () => ({
        lo: [{ address: '127.0.0.1', family: 'IPv4', internal: true }],
        eth0: [{ address, family: 'IPv4', internal: false }],
      }),
    });
  } catch (error) {
    if (error instanceof TypeError && /^review graph /.test(error.message)) process.exit(42);
    throw error;
  }
  if (resolved?.listenHost !== '0.0.0.0' || resolved?.advertiseHost !== address) process.exit(42);
}
JAVASCRIPT
  )
  probe_exit=0
  timeout --signal=TERM --kill-after=5s 30s "$DOCKER" run --rm --pull never \
    --name "nosh-tooling-check-$(id -u)-$$-$RANDOM" --cidfile "$probe_cid" \
    --network none --user "$(id -u):$(id -g)" --read-only --cap-drop ALL \
    --security-opt no-new-privileges:true --pids-limit 32 --memory 256m --cpus 1 \
    --tmpfs /tmp:rw,nosuid,nodev,noexec,size=16777216 \
    --env HOME=/tmp --env PYTHONDONTWRITEBYTECODE=1 \
    --entrypoint /usr/local/bin/node "$TOOLING" --input-type=module -e "$probe_code" >&2 || probe_exit=$?
  case "$probe_exit" in
    0) probe_result ready 'The local policy tooling supports inventories and guided review.' 0 ;;
    42) probe_result needs-build 'The local policy tooling needs updated inventory, guided review, or private bridge support.' 3 ;;
    *) die "policy tooling capability check failed (exit $probe_exit); inspect Docker and tooling diagnostics" ;;
  esac
fi
prepare_state() {
  install -d -m 0700 -- "$STATE_ROOT"
  STATE_ROOT=$(realpath -e -- "$STATE_ROOT")
  bind_path "$STATE_ROOT"
}
collect_inventories() {
  local target_image=$1 index cached='' reuse=false operation result=0
  bind_path "$WORKDIR"
  prepare_state
  index="$STATE_ROOT/inventory-$(printf '%s' "$WORKDIR" | sha256sum | cut -d' ' -f1).json"
  if [[ -f "$index" && ! -L "$index" ]]; then
    private_file "$index"
    if jq -e --arg image "$target_image" --arg tooling "$TOOLING" \
      '.image == $image and .tooling == $tooling' "$index" >/dev/null; then
      cached=$(jq -er '.directory' "$index")
      if [[ "$cached" == "$STATE_ROOT"/* && -f "$cached/image.spdx.json" && -f "$cached/image.collection.json" ]]; then
        bind_path "$cached"
        private_file "$cached/image.spdx.json"; private_file "$cached/image.collection.json"
        if jq -e --arg image "$target_image" --arg digest "sha256:$(sha256sum "$cached/image.spdx.json" | cut -d' ' -f1)" \
          '.status == "complete" and .input.imageDigest == $image and .sbomDigest == $digest' "$cached/image.collection.json" >/dev/null; then reuse=true; fi
      fi
    fi
  fi
  operation=$(mktemp -d "$STATE_ROOT/inventory.XXXXXX")
  local -a command=(bash "$REPO/scripts/nosh-inventory.sh" --workdir "$WORKDIR" --tooling "$TOOLING" --output "$operation/data")
  if [[ "$reuse" == true ]]; then command+=(--source-only); else command+=(--image "$target_image"); fi
  "${command[@]}" >&2 || result=$?
  if [[ "$reuse" == true && ( $result == 0 || $result == 2 ) ]]; then
    cp -- "$cached/image.spdx.json" "$cached/image.collection.json" "$operation/data/"
  fi
  if [[ $result != 0 && $result != 2 ]]; then return "$result"; fi
  SBOM_SOURCE="$operation/data/source.spdx.json"
  SBOM_IMAGE="$operation/data/image.spdx.json"
  jq -n --arg image "$target_image" --arg tooling "$TOOLING" --arg directory "$operation/data" \
    '{schemaVersion:1,image:$image,tooling:$tooling,directory:$directory}' > "$operation/index.json"
  mv -- "$operation/index.json" "$index"
  if [[ $result != 0 ]]; then
    printf 'Inventory incomplete; collection reports: %s/data\n' "$operation" >&2
  fi
  return "$result"
}

if [[ "$MODE" == inventory ]]; then
  [[ -z "$SESSION$DIGEST$RESULT_JSON$SBOM_SOURCE$SBOM_IMAGE" ]] || die 'unexpected review/apply options'
  WORKDIR=$(realpath -e -- "$WORKDIR")
  [[ -n "$IMAGE" ]] || die 'inventory requires --image'
  resolve_tooling
  requested_image=$IMAGE
  IMAGE=$("$DOCKER" image inspect --format '{{.Id}}' "$IMAGE")
  [[ "$requested_image" != sha256:* || "$requested_image" == "$IMAGE" ]] || die 'exact workload image identity changed'
  [[ "$IMAGE" =~ ^sha256:[a-f0-9]{64}$ ]] || die 'invalid workload image ID'
  result=0; collect_inventories "$IMAGE" || result=$?
  if [[ $result == 0 || $result == 2 ]]; then
    jq -n --arg source "$SBOM_SOURCE" --arg image "$SBOM_IMAGE" --argjson ready "$([[ $result == 0 ]] && printf true || printf false)" \
      '{ready:$ready,source:$source,image:$image}'
  fi
  exit "$result"
fi

if [[ "$MODE" == review || "$MODE" == prepare ]]; then
  [[ -z "$SESSION$DIGEST$RESULT_JSON$IMAGE" && "$YES" == false ]] || die 'apply options are not accepted by review'
  WORKDIR=$(realpath -e -- "$WORKDIR")
  key=$(printf '%s' "$WORKDIR" | sha256sum | awk '{print $1}')
  mirrors=("$HOME"/.nosh/net-profiles/*-"$key$WORKLOAD_SUFFIX")
  [[ ${#mirrors[@]} == 1 && -d "${mirrors[0]}" ]] || die 'no learned workspace profile; run nosh net learn first'
  mirror=${mirrors[0]}
  private_file "$mirror/current.json"
  [[ $(jq -r '.workspace.path' "$mirror/current.json") == "$WORKDIR" ]] || die 'workspace mirror mismatch'
  [[ -n "$REVISION" ]] || REVISION=$(jq -er '.latestCandidate.revision' "$mirror/current.json")
  [[ "$REVISION" =~ ^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$ ]] || die 'invalid learn revision'
  candidate="$mirror/review-candidates/$key/$REVISION"
  [[ -d "$candidate" ]] || die 'this revision has no review export; run nosh net learn using the updated launcher'
  bind_path "$candidate"
  [[ -z "$EXPECTED_IMAGE" || $(jq -er '.spec.target.imageDigest' "$candidate/egress-profile.json") == "$EXPECTED_IMAGE" ]] || die 'recording belongs to a different image; refresh policy selection'
  resolve_tooling
  if [[ -z "$SBOM_SOURCE$SBOM_IMAGE" ]]; then
    image_id=$(jq -er '.spec.target.imageDigest' "$candidate/egress-profile.json")
    [[ "$image_id" =~ ^sha256:[a-f0-9]{64}$ ]] || die 'invalid candidate image ID'
    result=0; collect_inventories "$image_id" || result=$?
    [[ $result == 0 || ( "$MODE" == review && $result == 2 ) ]] || exit "$result"
  fi
  # Resolve collection prerequisites before spending time rebuilding the UI.
  if [[ -z "$UI_IMAGE" ]]; then
    "$DOCKER" build --pull=false -f "$REPO/policy-review/Dockerfile" -t nosh-policy-review:managed "$REPO/policy-review" >&2
    UI_IMAGE=$("$DOCKER" image inspect --format '{{.Id}}' nosh-policy-review:managed)
  fi
  args=(--runtime-candidate "$candidate")
  [[ "$MODE" != prepare ]] || args+=(--prepare-only)
  if [[ -n "$SBOM_SOURCE" ]]; then args+=(--sbom-source "$SBOM_SOURCE"); fi
  if [[ -n "$SBOM_IMAGE" ]]; then args+=(--sbom-image "$SBOM_IMAGE"); fi
  [[ -n "$SBOM_SOURCE" && -n "$SBOM_IMAGE" ]] || args+=(--allow-missing-sbom)
  exec env NOSH_POLICY_TOOLING_IMAGE="$TOOLING" NOSH_POLICY_REVIEW_UI_IMAGE="$UI_IMAGE" \
    NOSH_PROFILE_REVIEW_WORKDIR="$WORKDIR" "$REPO/scripts/profile-build-and-review.sh" "${args[@]}"
fi

if [[ "$MODE" == check ]]; then
  [[ -z "$REVISION$SBOM_SOURCE$SBOM_IMAGE$RESULT_JSON$IMAGE" && "$YES" == false ]] || die 'unexpected options for check'
  bind_path "$SESSION"; private_file "$SESSION/runtime/review-session.json"
  TOOLING=$(jq -er '.toolingImage' "$SESSION/runtime/review-session.json"); verify_tooling
  candidate=$(jq -er '.runtimeCandidate' "$SESSION/runtime/review-session.json")
  WORKDIR=$(jq -er '.workdir' "$SESSION/runtime/review-session.json")
  candidate_root=$(dirname -- "$(dirname -- "$candidate")")
  bind_path "$candidate_root"; bind_path "$WORKDIR"
  prepare_state
  check_dir=$(mktemp -d "$STATE_ROOT/check.XXXXXX")
  bash "$REPO/scripts/nosh-inventory.sh" --workdir "$WORKDIR" --tooling "$TOOLING" \
    --output "$check_dir/source" --source-only >&2 || die 'source inventory is incomplete; reopen review'
  [[ -f "$APPLY_CONFIG" ]] || die 'signing configuration is missing; run wizard signing setup'
  private_file "$APPLY_CONFIG"
  jq -e '.schemaVersion == 1 and (.reviewPrivateKey != .deploymentPrivateKey) and ([.reviewPrivateKey,.reviewPublicKey,.deploymentPrivateKey,.reviewAudience,.deploymentAudience] | all(type == "string" and length > 0))' "$APPLY_CONFIG" >/dev/null \
    || die 'signing configuration is invalid; inspect signing setup'
  for field in reviewPrivateKey deploymentPrivateKey; do
    signing_key=$(jq -er --arg field "$field" '.[$field]' "$APPLY_CONFIG")
    bind_path "$signing_key"; private_file "$signing_key"
  done
  signing_public=$(jq -er '.reviewPublicKey' "$APPLY_CONFIG"); bind_path "$signing_public"
  args=(/app/scripts/nosh-policy-session.mjs check --session "$SESSION" --current-source "$check_dir/source/source.spdx.json")
  [[ -z "$DIGEST" ]] || args+=(--digest "$DIGEST")
  tooling_run --mount "type=bind,src=$SESSION,dst=$SESSION,readonly" \
    --mount "type=bind,src=$candidate_root,dst=$candidate_root,readonly" \
    --mount "type=bind,src=$WORKDIR,dst=$WORKDIR,readonly" \
    --mount "type=bind,src=$check_dir,dst=$check_dir,readonly" "$TOOLING" "${args[@]}"
  exit $?
fi

[[ -z "$REVISION$SBOM_SOURCE$SBOM_IMAGE$IMAGE" ]] || die 'review options are not accepted by apply'
[[ "$DIGEST" =~ ^sha256:[a-f0-9]{64}$ && "$SESSION" == /* ]] || die 'apply requires --review SESSION and --decision-digest SHA256'
bind_path "$SESSION"
private_file "$SESSION/runtime/review-session.json"
if [[ -n "$RESULT_JSON" ]]; then
  [[ "$RESULT_JSON" == /* && ! -e "$RESULT_JSON" && ! -L "$RESULT_JSON" ]] || die 'result file must be a new absolute path'
  result_parent=$(dirname -- "$RESULT_JSON")
  bind_path "$result_parent"
  [[ $(stat -c '%u:%a' -- "$result_parent") == "$(id -u):700" ]] || die 'result parent must be caller-owned mode 0700'
fi
metadata=$SESSION/runtime/review-session.json
session_tooling=$(jq -er '.toolingImage' "$metadata")
[[ -z "$TOOLING" || "$TOOLING" == "$session_tooling" ]] || die 'configured tooling image differs from the saved review'
TOOLING=$session_tooling
verify_tooling
candidate=$(jq -er '.runtimeCandidate' "$metadata")
WORKDIR=$(jq -er '.workdir' "$metadata")
learned_workload=$(jq -r '.spec.launch.config.workload' "$candidate/egress-profile.json")
[[ "$WORKLOAD_EXPLICIT" != true || "$WORKLOAD" == "$learned_workload" ]] || die 'review belongs to another workload'
WORKLOAD=$learned_workload
case "$WORKLOAD" in dev|run) ;; *) die 'invalid learned workload' ;; esac
bind_path "$candidate"
bind_path "$WORKDIR"
[[ -f "$APPLY_CONFIG" ]] || die "signing configuration is missing: $APPLY_CONFIG; use nosh init --step signing for first-time setup, or nosh net apply --help for existing trust"
private_file "$APPLY_CONFIG"
jq -e '.schemaVersion == 1 and ([.reviewPrivateKey,.reviewPublicKey,.deploymentPrivateKey,.reviewAudience,.deploymentAudience] | all(type == "string" and length > 0))' "$APPLY_CONFIG" >/dev/null || die 'invalid signing configuration; use nosh net apply --help'
review_key=$(jq -er '.reviewPrivateKey' "$APPLY_CONFIG")
review_public=$(jq -er '.reviewPublicKey' "$APPLY_CONFIG")
deploy_key=$(jq -er '.deploymentPrivateKey' "$APPLY_CONFIG")
review_audience=$(jq -er '.reviewAudience' "$APPLY_CONFIG")
deploy_audience=$(jq -er '.deploymentAudience' "$APPLY_CONFIG")
for keyfile in "$review_key" "$review_public" "$deploy_key"; do bind_path "$keyfile"; done
[[ "$review_key" != "$deploy_key" ]] || die 'review and deployment roles must use separate private keys'
install -d -m 0700 -- "$STATE_ROOT"
APPLY_DIR=$(mktemp -d "$STATE_ROOT/apply.XXXXXX")
APPLY_DIR=$(realpath -e -- "$APPLY_DIR")
for keyfile in "$review_key" "$deploy_key"; do
  private_file "$keyfile"
  case "$keyfile" in "$SESSION"/*|"$candidate"/*|"$WORKDIR"/*|"$APPLY_DIR"/*) die 'private keys must be outside review, candidate, workspace and apply directories' ;; esac
done
printf 'Apply artifacts: %s\n' "$APPLY_DIR" >&2
# Recollect source metadata immediately before snapshotting the reviewed selection.
# Image evidence is bound to an immutable image ID; workspace metadata can change.
source_check="$APPLY_DIR/current-source"
bash "$REPO/scripts/nosh-inventory.sh" --workdir "$WORKDIR" --tooling "$TOOLING" \
  --output "$source_check" --source-only >&2 || die 'current source inventory is incomplete; reopen review'
candidate_root=$(dirname -- "$(dirname -- "$candidate")")
bind_path "$candidate_root"
tooling_run --mount "type=bind,src=$SESSION,dst=$SESSION,readonly" \
  --mount "type=bind,src=$candidate_root,dst=$candidate_root,readonly" \
  --mount "type=bind,src=$WORKDIR,dst=$WORKDIR,readonly" \
  --mount "type=bind,src=$APPLY_DIR,dst=$APPLY_DIR" "$TOOLING" \
  /app/scripts/nosh-policy-session.mjs snapshot --session "$SESSION" --digest "$DIGEST" --output "$APPLY_DIR" > "$APPLY_DIR/snapshot.json"
policy_run() { tooling_run --mount "type=bind,src=$APPLY_DIR,dst=/policy-io" "$@"; }
policy_run "$TOOLING" /app/scripts/nosh-guard.mjs policy project --bundle /policy-io/bundle \
  --decisions /policy-io/decisions.json --target guard-ebpf --context /policy-io/target-context.json \
  --output /policy-io/projected > "$APPLY_DIR/project-result.json" || die "projection is blocked; inspect $APPLY_DIR/project-result.json and $APPLY_DIR/projected"
jq -e '.activationEligible == true' "$APPLY_DIR/project-result.json" >/dev/null || die 'projection is not activation eligible'
# Resolve the installed, reviewed privileged helper; never elevate repository JS.
guard=${NOSH_GUARD_PRIVILEGED_BIN:-}
if [[ -z "$guard" && -f "$CONFIG_HOME/nosh/paths.conf" ]]; then
  private_file "$CONFIG_HOME/nosh/paths.conf"
  guard=$(sed -n 's/^NOSH_GUARD_PRIVILEGED_BIN=//p' "$CONFIG_HOME/nosh/paths.conf")
fi
[[ -n "$guard" && -x "$guard" ]] || die 'configure the installed privileged Guard with setup-nosh.sh'
privileged() { if [[ $EUID == 0 ]]; then "$guard" "$@"; else sudo -- "$guard" "$@"; fi; }
privileged ebpf status --workload "$WORKLOAD" --workdir "$WORKDIR" --json > "$APPLY_DIR/status.json"
leaf=$(jq -er '.leafBundleDigest' "$APPLY_DIR/project-result.json")
active_leaf=$(jq -r '.activation.leafBundleDigest // ""' "$APPLY_DIR/status.json")
active_decisions=$(jq -r '.activation.decisionSetDigest // ""' "$APPLY_DIR/status.json")
if [[ "$DIGEST" != "$active_decisions" ]]; then
  printf 'Workspace: %s\nImage: %s\nSelected rules:\n' "$WORKDIR" "$(jq -r '.session.imageDigest' "$APPLY_DIR/snapshot.json")"
  jq '.rules // .spec.rules // .' "$APPLY_DIR/projected/rendered/ebpf-policy.json"
  printf 'Current deployment: %s\nNew deployment: %s\n' "${active_leaf:-none}" "$leaf"
  if [[ "$YES" != true ]]; then
    [[ -t 0 ]] || die 'non-interactive apply requires --yes after reviewing the projected policy'
    read -r -p 'Apply this policy to future guarded runs? [y/N] ' answer
    [[ "$answer" == y || "$answer" == Y ]] || die 'not applied; saved review preserved'
  fi
  reviewer=$(jq -er '.reviewer' "$APPLY_DIR/snapshot.json")
  confirmation=$(jq -er '.targetReviewSetDigest' "$APPLY_DIR/project-result.json")
  binding=$(jq -er '.targetBindingDigest' "$APPLY_DIR/project-result.json")
  policy_run --mount "type=bind,src=$review_key,dst=/run/review-private.pem,readonly" "$TOOLING" \
    /app/scripts/nosh-guard.mjs review approve --bundle /policy-io/bundle --decisions /policy-io/decisions.json \
    --policy /policy-io/projected --reviewer "$reviewer" --audience "$review_audience" \
    --key /run/review-private.pem --confirmation "$confirmation" --output /policy-io/approval > "$APPLY_DIR/approval-result.json"
  install -m 0600 -- "$review_public" "$APPLY_DIR/review-public.pem"
  # Read replay state just before minting; a concurrent activation fails closed.
  privileged ebpf status --workload "$WORKLOAD" --workdir "$WORKDIR" --json > "$APPLY_DIR/status.json"
  active_grants=$(jq -er '.activeGrantSetDigest' "$APPLY_DIR/status.json")
  policy_run --mount "type=bind,src=$deploy_key,dst=/run/deployment-private.pem,readonly" "$TOOLING" \
    /app/scripts/nosh-guard.mjs deployment grant --policy /policy-io/projected \
    --approval /policy-io/approval/approval-envelope.dsse.json --review-key /policy-io/review-public.pem \
    --review-audience "$review_audience" --deployment-key /run/deployment-private.pem \
    --audience "$deploy_audience" --target-binding-digest "$binding" --active-grant-set-digest "$active_grants" \
    --output /policy-io/deployment > "$APPLY_DIR/grant-result.json"
  install -d -m 0700 -- "$APPLY_DIR/activation"
  cp -a -- "$APPLY_DIR/projected" "$APPLY_DIR/activation/policy"
  install -m 0600 -- "$APPLY_DIR/approval/approval-envelope.dsse.json" "$APPLY_DIR/activation/approval-envelope.dsse.json"
  install -m 0600 -- "$APPLY_DIR/deployment/deployment-grant.dsse.json" "$APPLY_DIR/activation/deployment-grant.dsse.json"
  revision=$(jq -er '.session.revision' "$APPLY_DIR/snapshot.json")
  privileged ebpf activate --workload "$WORKLOAD" --bundle "$APPLY_DIR/activation" --target-context "$APPLY_DIR/target-context.json" \
    --learn-revision "$revision" --workdir "$WORKDIR" > "$APPLY_DIR/activation-result.json"
else
  printf '%s\n' 'This exact policy is already applied; no new grant was issued.'
  leaf=$active_leaf
fi
privileged ebpf status --workload "$WORKLOAD" --workdir "$WORKDIR" --json > "$APPLY_DIR/final-status.json"
[[ $(jq -r '.activation.leafBundleDigest' "$APPLY_DIR/final-status.json") == "$leaf" && $(jq -r '.activation.decisionSetDigest' "$APPLY_DIR/final-status.json") == "$DIGEST" ]] || die 'active policy changed; check nosh net status'
jq --arg digest "$DIGEST" --arg artifacts "$APPLY_DIR" '.activation + {decisionDigest:$digest, artifacts:$artifacts}' "$APPLY_DIR/final-status.json" > "$SESSION/decisions/.applied.$$.tmp"
chmod 0600 -- "$SESSION/decisions/.applied.$$.tmp"
mv -- "$SESSION/decisions/.applied.$$.tmp" "$SESSION/decisions/applied.json"
if [[ -n "$RESULT_JSON" ]]; then
  jq --arg workspace "$WORKDIR" --arg revision "$(jq -r '.session.revision' "$APPLY_DIR/snapshot.json")" \
    --arg session "$SESSION" --arg digest "$DIGEST" \
    '{schemaVersion:1,workspace:$workspace,revision:$revision,session:$session,decisionDigest:$digest,activation:.activation}' \
    "$APPLY_DIR/final-status.json" > "$APPLY_DIR/result.json"
  result_temporary=$(mktemp "$result_parent/.nosh-apply-result.XXXXXX")
  cat "$APPLY_DIR/result.json" > "$result_temporary"
  # Exclusive hardlink publication cannot replace an existing file or symlink.
  if ! ln -T -- "$result_temporary" "$RESULT_JSON"; then
    rm -- "$result_temporary"
    die "activation succeeded but result publication failed: $RESULT_JSON"
  fi
  rm -- "$result_temporary"
fi
printf 'Applied for future guarded runs. Existing containers are unchanged.\nLaunch: '
if [[ $EUID != 0 ]]; then printf 'sudo -- '; fi
printf '%q ' "$guard" net enforce --workdir "$WORKDIR" --workload "$WORKLOAD" --revision "$(jq -r '.session.revision' "$APPLY_DIR/snapshot.json")"
printf '\nCheck: '
if [[ $EUID != 0 ]]; then printf 'sudo -- '; fi
printf '%q ' "$guard" net status --workdir "$WORKDIR" --workload "$WORKLOAD"
printf '\n'
