#!/usr/bin/env bash
set -euo pipefail
umask 077
REPO=$(cd -P -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
MODE=${1:-help}
(($# == 0)) || shift
WORKDIR=$PWD
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

die() { printf 'nosh net %s: %s\n' "$MODE" "$*" >&2; exit 1; }
usage() {
  cat <<'HELP'
Usage:
  nosh net review [--revision LEARN_ID] [--workdir DIR]
                  [--sbom-source FILE --sbom-image FILE]
  nosh net apply --review SESSION --decision-digest SHA256 [--yes]

Review reopens the exact runtime candidate; it never rebuilds or learns traffic.
Missing SBOMs are generated with the configured offline Syft image if installed.
Apply verifies, snapshots, projects, approves, grants and activates a saved IP
policy for future guarded runs. It does not change already-running containers.

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
[[ "$MODE" == review || "$MODE" == apply ]] || { usage; exit 0; }
while (($#)); do
  case "$1" in
    -h|--help) usage; exit 0 ;;
    --yes) YES=true; shift ;;
    --revision|--workdir|--review|--decision-digest|--sbom-source|--sbom-image)
      [[ -n "${2:-}" ]] || die "$1 requires a value"
      case "$1" in
        --revision) REVISION=$2 ;;
        --workdir) WORKDIR=$2 ;;
        --review) SESSION=$2 ;;
        --decision-digest) DIGEST=$2 ;;
        --sbom-source) SBOM_SOURCE=$2 ;;
        --sbom-image) SBOM_IMAGE=$2 ;;
      esac
      shift 2 ;;
    *) die "unknown option: $1" ;;
  esac
done
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

if [[ "$MODE" == review ]]; then
  [[ -z "$SESSION$DIGEST" && "$YES" == false ]] || die 'apply options are not accepted by review'
  WORKDIR=$(realpath -e -- "$WORKDIR")
  key=$(printf '%s' "$WORKDIR" | sha256sum | awk '{print $1}')
  mirrors=("$HOME"/.nosh/net-profiles/*-"$key")
  [[ ${#mirrors[@]} == 1 && -d "${mirrors[0]}" ]] || die 'no learned workspace profile; run nosh net learn first'
  mirror=${mirrors[0]}
  private_file "$mirror/current.json"
  [[ $(jq -r '.workspace.path' "$mirror/current.json") == "$WORKDIR" ]] || die 'workspace mirror mismatch'
  [[ -n "$REVISION" ]] || REVISION=$(jq -er '.latestCandidate.revision' "$mirror/current.json")
  [[ "$REVISION" =~ ^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$ ]] || die 'invalid learn revision'
  candidate="$mirror/review-candidates/$key/$REVISION"
  [[ -d "$candidate" ]] || die 'this revision has no review export; run nosh net learn using the updated launcher'
  bind_path "$candidate"
  if [[ -z "$TOOLING" ]]; then
    TOOLING=$("$DOCKER" image inspect --format '{{.Id}}' nosh 2>/dev/null) || die 'build/configure the local policy tooling image first'
  fi
  verify_tooling
  if [[ -z "$UI_IMAGE" ]]; then
    # Docker layer caching makes this cheap, while source changes cannot leave
    # the managed UI silently stuck on an old local tag.
    "$DOCKER" build --pull=false -f "$REPO/policy-review/Dockerfile" -t nosh-policy-review:managed "$REPO/policy-review" >&2
    UI_IMAGE=$("$DOCKER" image inspect --format '{{.Id}}' nosh-policy-review:managed)
  fi
  install -d -m 0700 -- "$STATE_ROOT"
  STATE_ROOT=$(realpath -e -- "$STATE_ROOT")
  if [[ -z "$SBOM_SOURCE$SBOM_IMAGE" ]]; then
    for metadata in "$STATE_ROOT"/*/runtime/review-session.json; do
      [[ -f "$metadata" && ! -L "$metadata" ]] || continue
      private_file "$metadata"
      if jq -e --arg candidate "$candidate" '.runtimeCandidate == $candidate' "$metadata" >/dev/null; then
        SBOM_SOURCE=$(jq -r '.sbomSource // ""' "$metadata")
        SBOM_IMAGE=$(jq -r '.sbomImage // ""' "$metadata")
        break
      fi
    done
  fi
  if [[ -z "$SBOM_SOURCE$SBOM_IMAGE" ]]; then
    syft=$(jq -er '.syft.image' "$REPO/config/nosh-review/tools.json")
    if "$DOCKER" image inspect "$syft" >/dev/null 2>&1; then
      sbom_dir=$(mktemp -d "$STATE_ROOT/sbom.XXXXXX")
      bind_path "$WORKDIR"
      image_id=$(jq -er '.spec.target.imageDigest' "$candidate/egress-profile.json")
      [[ "$image_id" =~ ^sha256:[a-f0-9]{64}$ ]] || die 'invalid candidate image ID'
      printf '%s\n' 'Generating source and exact-image SBOMs with the installed offline Syft image…' >&2
      "$DOCKER" run --rm --pull never --network none --user "$(id -u):$(id -g)" \
        --env SYFT_CHECK_FOR_APP_UPDATE=false --mount "type=bind,src=$WORKDIR,dst=/source,readonly" \
        --mount "type=bind,src=$sbom_dir,dst=/output" "$syft" dir:/source -o spdx-json=/output/source.spdx.json
      "$DOCKER" image save --output "$sbom_dir/image.tar" "$image_id"
      "$DOCKER" run --rm --pull never --network none --user "$(id -u):$(id -g)" \
        --env SYFT_CHECK_FOR_APP_UPDATE=false --mount "type=bind,src=$sbom_dir,dst=/input" \
        "$syft" docker-archive:/input/image.tar -o spdx-json=/input/image.spdx.json
      rm -- "$sbom_dir/image.tar"
      chmod 0600 -- "$sbom_dir/source.spdx.json" "$sbom_dir/image.spdx.json"
      SBOM_SOURCE=$sbom_dir/source.spdx.json
      SBOM_IMAGE=$sbom_dir/image.spdx.json
    else
      printf 'Offline Syft image is not installed: %s\nReview and draft saving are available; supply both SBOMs to enable signed Apply.\n' "$syft" >&2
    fi
  fi
  args=(--runtime-candidate "$candidate")
  if [[ -n "$SBOM_SOURCE" ]]; then args+=(--sbom-source "$SBOM_SOURCE"); fi
  if [[ -n "$SBOM_IMAGE" ]]; then args+=(--sbom-image "$SBOM_IMAGE"); fi
  [[ -n "$SBOM_SOURCE" && -n "$SBOM_IMAGE" ]] || args+=(--allow-missing-sbom)
  exec env NOSH_POLICY_TOOLING_IMAGE="$TOOLING" NOSH_POLICY_REVIEW_UI_IMAGE="$UI_IMAGE" \
    NOSH_PROFILE_REVIEW_WORKDIR="$WORKDIR" "$REPO/profile-build-and-review.sh" "${args[@]}"
fi

[[ -z "$REVISION$SBOM_SOURCE$SBOM_IMAGE" ]] || die 'review options are not accepted by apply'
[[ "$DIGEST" =~ ^sha256:[a-f0-9]{64}$ && "$SESSION" == /* ]] || die 'apply requires --review SESSION and --decision-digest SHA256'
bind_path "$SESSION"
private_file "$SESSION/runtime/review-session.json"
metadata=$SESSION/runtime/review-session.json
session_tooling=$(jq -er '.toolingImage' "$metadata")
[[ -z "$TOOLING" || "$TOOLING" == "$session_tooling" ]] || die 'configured tooling image differs from the saved review'
TOOLING=$session_tooling
verify_tooling
candidate=$(jq -er '.runtimeCandidate' "$metadata")
WORKDIR=$(jq -er '.workdir' "$metadata")
bind_path "$candidate"
bind_path "$WORKDIR"
[[ -f "$APPLY_CONFIG" ]] || die "signing configuration is missing: $APPLY_CONFIG; run nosh net apply --help for the required fields"
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
privileged ebpf status --json > "$APPLY_DIR/status.json"
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
  privileged ebpf status --json > "$APPLY_DIR/status.json"
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
  privileged ebpf activate --bundle "$APPLY_DIR/activation" --target-context "$APPLY_DIR/target-context.json" \
    --learn-revision "$revision" --workdir "$WORKDIR" > "$APPLY_DIR/activation-result.json"
else
  printf '%s\n' 'This exact policy is already applied; no new grant was issued.'
  leaf=$active_leaf
fi
privileged ebpf status --json > "$APPLY_DIR/final-status.json"
[[ $(jq -r '.activation.leafBundleDigest' "$APPLY_DIR/final-status.json") == "$leaf" ]] || die 'active policy changed; check nosh net status'
jq --arg digest "$DIGEST" --arg artifacts "$APPLY_DIR" '.activation + {decisionDigest:$digest, artifacts:$artifacts}' "$APPLY_DIR/final-status.json" > "$SESSION/decisions/.applied.$$.tmp"
chmod 0600 -- "$SESSION/decisions/.applied.$$.tmp"
mv -- "$SESSION/decisions/.applied.$$.tmp" "$SESSION/decisions/applied.json"
printf 'Applied for future guarded runs. Existing containers are unchanged.\nLaunch: '
printf '%q ' "$REPO/nosh.sh" net enforce --workdir "$WORKDIR" --revision "$(jq -r '.session.revision' "$APPLY_DIR/snapshot.json")"
printf '\nCheck: '
if [[ $EUID != 0 ]]; then printf 'sudo -- '; fi
printf '%q ' "$guard" net status --workdir "$WORKDIR"
printf '\n'
