#!/usr/bin/env bash
set -euo pipefail

#docker build --no-cache  -f Dockerfile.nosh  -t nosh .
SCRIPT_DIR="$(cd -P "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd -P "$SCRIPT_DIR/.." && pwd)"
DEFAULT_USERNAME="${SUDO_USER:-${USER:-$(id -un)}}"
DEFAULT_USER_UID="${SUDO_UID:-$(id -u)}"
DEFAULT_USER_GID="${SUDO_GID:-$(id -g)}"

USERNAME="${USERNAME:-$DEFAULT_USERNAME}"
USER_UID="${USER_UID:-$DEFAULT_USER_UID}"
USER_GID="${USER_GID:-$DEFAULT_USER_GID}"
IMAGE_NAME="${IMAGE_NAME:-nosh}"
TARGET="${TARGET:-local}"

REVIEW_LAUNCHER="${NOSH_BUILD_REVIEW_LAUNCHER:-$REPO_ROOT/scripts/profile-build-and-review.sh}"
LEARN_OUTPUT_FILE=""
REVIEW_UI_IMAGE_TAG="${NOSH_BUILD_REVIEW_UI_IMAGE_TAG:-nosh-policy-review:managed}"

cleanup_learn_output() {
  if [[ -n "$LEARN_OUTPUT_FILE" ]]; then
    rm -f -- "$LEARN_OUTPUT_FILE"
    LEARN_OUTPUT_FILE=""
  fi
}

prepare_automatic_review_images() {
  local output_image
  local ui_image_id

  if [[ -z "${NOSH_POLICY_TOOLING_IMAGE:-}" ]]; then
    output_image="$(sed -n 's/^Output image config (local ID): //p' "$LEARN_OUTPUT_FILE" | tail -n 1)"
    if [[ "$output_image" =~ ^sha256:[a-f0-9]{64}$ ]]; then
      export NOSH_POLICY_TOOLING_IMAGE="$output_image"
    fi
  fi

  [[ -n "${NOSH_POLICY_TOOLING_IMAGE:-}" ]] || return 0

  if [[ -n "${NOSH_POLICY_REVIEW_UI_IMAGE:-}" ]]; then
    return 0
  fi

  if ! ui_image_id="$(docker image inspect --format '{{.Id}}' "$REVIEW_UI_IMAGE_TAG" 2>/dev/null)" \
    || [[ ! "$ui_image_id" =~ ^sha256:[a-f0-9]{64}$ ]]; then
    printf '%s\n' 'build-nosh: building the managed Policy Review UI image' >&2
    DOCKER_BUILDKIT=1 docker build --pull=false \
      -f "$REPO_ROOT/policy-review/Dockerfile" \
      -t "$REVIEW_UI_IMAGE_TAG" \
      "$REPO_ROOT/policy-review" >&2 \
      || return 1
    ui_image_id="$(docker image inspect --format '{{.Id}}' "$REVIEW_UI_IMAGE_TAG")" \
      || return 1
  fi
  [[ "$ui_image_id" =~ ^sha256:[a-f0-9]{64}$ ]] || return 1
  export NOSH_POLICY_REVIEW_UI_IMAGE="$ui_image_id"
}

trap cleanup_learn_output EXIT

profile_build() {
  local -a command=(
    "$REPO_ROOT/scripts/nosh.sh"
    build
    profile
    --file "$REPO_ROOT/Dockerfile.nosh"
    --tag "$IMAGE_NAME"
    --target "$TARGET"
    --build-arg "USERNAME=${USERNAME}"
    --build-arg "USER_UID=${USER_UID}"
    --build-arg "USER_GID=${USER_GID}"
    "$REPO_ROOT"
  )

  exec "${command[@]}" "$@"
}

learn_build_network() {
  local -a forwarded=()
  local open_review=true
  local machine_output=false
  local guard_options=true
  local argument
  for argument in "$@"; do
    if [[ "$argument" == -- ]]; then
      guard_options=false
      forwarded+=("$argument")
      continue
    fi
    if [[ "$guard_options" != true ]]; then
      forwarded+=("$argument")
      continue
    fi
    case "$argument" in
      --no-review)
        open_review=false
        ;;
      --private-json|--json|--dry-run)
        machine_output=true
        forwarded+=("$argument")
        ;;
      -h|--help)
        machine_output=true
        forwarded+=("$argument")
        ;;
      *)
        forwarded+=("$argument")
        ;;
    esac
  done

  local -a command=(
    "$REPO_ROOT/scripts/nosh.sh"
    build
    net
    learn
    --file "$REPO_ROOT/Dockerfile.nosh"
    --tag "$IMAGE_NAME"
    --target "$TARGET"
    --build-arg "USERNAME=${USERNAME}"
    --build-arg "USER_UID=${USER_UID}"
    --build-arg "USER_GID=${USER_GID}"
    "$REPO_ROOT"
  )
  if [[ "$open_review" == false || "$machine_output" == true ]]; then
    "${command[@]}" "${forwarded[@]}"
    return $?
  fi

  LEARN_OUTPUT_FILE="$(mktemp "${TMPDIR:-/tmp}/nosh-build-net-learn.XXXXXX")"
  set +e
  "${command[@]}" "${forwarded[@]}" | tee "$LEARN_OUTPUT_FILE"
  local learn_status=${PIPESTATUS[0]}
  set -e

  if [[ "$open_review" == true ]]; then
    local profile_dir
    profile_dir="$(sed -n "s/^Private bundle: //p" "$LEARN_OUTPUT_FILE" | tail -n 1)"
    if [[ "$profile_dir" == /* && -d "$profile_dir" && ! -L "$profile_dir" ]]; then
      if ! prepare_automatic_review_images; then
        printf "%s\n" "build-nosh: managed Policy Review images could not be prepared; the learned evidence was preserved" >&2
      elif ! "$REVIEW_LAUNCHER" \
        --build-profile "$profile_dir" \
        --allow-missing-sbom; then
        printf "%s\n" "build-nosh: review launch failed; the learned evidence was preserved" >&2
      fi
    else
      printf "%s\n" "build-nosh: no persisted private bundle was reported; review was not launched" >&2
    fi
  fi
  if [[ "$machine_output" == false ]]; then
    local runtime_image
    runtime_image="$(sed -n 's/^Output image config (local ID): //p' "$LEARN_OUTPUT_FILE" | tail -n 1)"
    printf '\n%s\n' 'Build traffic is not a runtime policy. Learn the workload before applying an endpoint selection:'
    if [[ "$runtime_image" =~ ^sha256:[a-f0-9]{64}$ ]]; then
      printf '  %q net learn --image %q\n' "$REPO_ROOT/scripts/nosh.sh" "$runtime_image"
    else
      printf '  %q net learn --image %q\n' "$REPO_ROOT/scripts/nosh.sh" "$IMAGE_NAME"
    fi
  fi
  cleanup_learn_output
  return "$learn_status"
}

case "${1:-}" in
  profile)
    shift
    profile_build "$@"
    ;;
  net)
    if [[ "${2:-}" != "learn" ]]; then
      printf 'build-nosh: expected `net learn`\n' >&2
      exit 1
    fi
    shift 2
    learn_build_network "$@"
    exit $?
    ;;
esac

printf 'Building %s target=%s with USERNAME=%s USER_UID=%s USER_GID=%s\n' \
  "$IMAGE_NAME" "$TARGET" "$USERNAME" "$USER_UID" "$USER_GID"

DOCKER_BUILDKIT=1 docker build \
  --build-arg "USERNAME=${USERNAME}" \
  --build-arg "USER_UID=${USER_UID}" \
  --build-arg "USER_GID=${USER_GID}" \
  --target "${TARGET}" \
  -f Dockerfile.nosh \
  -t "${IMAGE_NAME}" \
  "$@" \
  .
