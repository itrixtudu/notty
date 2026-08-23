#!/usr/bin/env bash
set -euo pipefail

# Profile Nosh, materialize the frozen review graph inside a separately
# reviewed immutable policy-tooling image, keep its Docker-bridge graph server
# running, start the exact reviewed Policy Review UI, and open it via xdg-open.
# No host Node/npm process is used by this wrapper.

umask 077

if [[ "${NOSH_PROFILE_REVIEW_CONTROL_SNAPSHOT_ACTIVE:-}" != 1 ]]; then
  original_control_script="$(realpath -e -- "${BASH_SOURCE[0]}")"
  original_control_dir="$(dirname "$original_control_script")"
  control_snapshot="$(mktemp /tmp/nosh-profile-review-control.XXXXXX)"
  trap 'rm -f -- "$control_snapshot"' EXIT
  install -m 0500 -- "$original_control_script" "$control_snapshot"
  exec 9<"$control_snapshot"
  rm -f -- "$control_snapshot"
  trap - EXIT
  exec env \
    NOSH_PROFILE_REVIEW_CONTROL_SNAPSHOT_ACTIVE=1 \
    NOSH_PROFILE_REVIEW_ORIGINAL_SCRIPT_DIR="$original_control_dir" \
    "${BASH:-/bin/bash}" /proc/self/fd/9 "$@"
fi

resolve_script_dir() {
  local source="${BASH_SOURCE[0]}"
  local directory
  while [[ -L "$source" ]]; do
    directory="$(cd -P "$(dirname "$source")" && pwd)"
    source="$(readlink "$source")"
    [[ "$source" == /* ]] || source="$directory/$source"
  done
  cd -P "$(dirname "$source")" && pwd
}

SCRIPT_DIR="${NOSH_PROFILE_REVIEW_ORIGINAL_SCRIPT_DIR:-$(resolve_script_dir)}"
PROFILE_BIN="${NOSH_PROFILE_REVIEW_PROFILE_BIN:-$SCRIPT_DIR/profile-build-and-run.sh}"
DOCKER_BIN="${NOSH_PROFILE_REVIEW_DOCKER_BIN:-docker}"
XDG_OPEN_BIN="${NOSH_PROFILE_REVIEW_XDG_OPEN_BIN:-xdg-open}"
PROFILE_WORKDIR="${NOSH_PROFILE_REVIEW_WORKDIR:-$PWD}"
REVIEW_ORIGIN=""
REVIEW_UI_URL=""
UI_HOST=""
GRAPH_HOST=""
REVIEW_STATE_ROOT="${NOSH_PROFILE_REVIEW_STATE_ROOT:-${XDG_STATE_HOME:-$HOME/.local/state}/nosh/policy-review}"
POLICY_TOOLING_IMAGE_REQUESTED="${NOSH_POLICY_TOOLING_IMAGE:-}"
POLICY_TOOLING_IMAGE_ID=""
POLICY_REVIEW_UI_IMAGE_REQUESTED="${NOSH_POLICY_REVIEW_UI_IMAGE:-}"
POLICY_REVIEW_UI_IMAGE_ID=""
POLICY_REVIEW_IMAGE_CONFIG="${NOSH_PROFILE_REVIEW_IMAGE_CONFIG:-}"
REVIEW_ALLOW_MISSING_SBOM="false"
REVIEW_SBOM_SOURCE=""
REVIEW_SBOM_IMAGE=""
REVIEW_SBOM_SOURCE_DIGEST="none"
REVIEW_SBOM_IMAGE_DIGEST="none"
PROFILE_ARGS=()
EXISTING_PROFILE=""
TEMP_DIR=""
TEMP_DIR_IDENTITY=""
PROFILE_WORKDIR_IDENTITY=""
REVIEW_STATE_ROOT_IDENTITY=""
GRAPH_CONTAINER=""
GRAPH_CONTAINER_ID=""
UI_CONTAINER=""
UI_CONTAINER_ID=""
REVIEW_NETWORK=""
REVIEW_NETWORK_ID=""
UI_CONTAINER_STARTED="false"
GRAPH_CONTAINER_STARTED="false"
KEEP_REVIEW_CONTAINERS="false"
PROFILE_ID=""
PROFILE_EVIDENCE_DIGEST=""
GRAPH_DIGEST=""
GRAPH_CONTENT_DIGEST=""
SESSION_DIR=""
RUNTIME_DIR=""
DECISIONS_DIR=""
SERVICE_STATE=""

usage() {
  cat <<'EOF'
Usage: ./profile-build-and-review.sh [review options] [profile-build-and-run options] [-- BUILD_PROFILE_OPTIONS...]

Run the Docker-backed build/runtime profile, compose its exact runtime egress
candidate into a frozen Policy Review bundle inside a separately reviewed
immutable policy-tooling image, start a tokenized graph server from
that image, start and health-check the exact reviewed UI image on its Docker
bridge address, and open it with xdg-open.

The wrapper starts its reviewed UI and graph server on a dedicated internal
Docker bridge and discovers both current 172.* addresses after startup. Review
artifacts are written below
$XDG_STATE_HOME/nosh/policy-review (or set NOSH_PROFILE_REVIEW_STATE_ROOT). No
host Node, npm, npx, or npm exec is used by this wrapper. Warm-only evidence is
rejected because it cannot advance a behavioral candidate; use --cache-mode
cold or compare.

When invoked by ./build-nosh.sh net learn, the tooling image ID is taken from
the learned build's reported output image and the managed UI image is built or
reused locally; no image export is required. ./setup-nosh.sh may still pin
separately reviewed image IDs for deployments that require that trust policy.
NOSH_POLICY_TOOLING_IMAGE and NOSH_POLICY_REVIEW_UI_IMAGE remain explicit
overrides. The wrapper never pulls images. It reuses a running managed UI or
graph server only when the persisted container IDs, exact images, profile and
graph digests, labels, and isolated-network attachments all attest.
By default a missing SBOM remains a blocking coverage finding. The explicit
--allow-missing-sbom option records a review-only coverage downgrade; it never
makes the resulting graph eligible for signed activation.

Review bundle options (before `--`):
  --build-profile PATH     Open an existing persisted build profile directly
  --sbom-source FILE       Reviewed source SPDX JSON (mounted read-only)
  --sbom-image FILE        Reviewed exact-image SPDX JSON (mounted read-only)
EOF
}

die() {
  printf 'profile-build-and-review: %s\n' "$*" >&2
  exit 1
}

is_docker_bridge_ipv4() {
  local address="$1"
  local first second third fourth extra
  IFS=. read -r first second third fourth extra <<< "$address"
  [[ -z "$extra"
    && "$first" == 172
    && "$second" =~ ^(0|[1-9][0-9]{0,2})$
    && "$third" =~ ^(0|[1-9][0-9]{0,2})$
    && "$fourth" =~ ^(0|[1-9][0-9]{0,2})$ ]] || return 1
  ((10#$second >= 16 && 10#$second <= 31
    && 10#$third <= 255 && 10#$fourth <= 255))
}

cleanup() {
  if [[ "$KEEP_REVIEW_CONTAINERS" != true ]]; then
    if [[ "$GRAPH_CONTAINER_STARTED" == true ]]; then
      stop_owned_review_container \
        "$GRAPH_CONTAINER_ID" graph "$GRAPH_CONTAINER" \
        "$POLICY_TOOLING_IMAGE_ID" >/dev/null 2>&1 || true
    fi
    if [[ "$UI_CONTAINER_STARTED" == true ]]; then
      stop_owned_review_container \
        "$UI_CONTAINER_ID" ui "$UI_CONTAINER" \
        "$POLICY_REVIEW_UI_IMAGE_ID" >/dev/null 2>&1 || true
    fi
  fi
  remove_private_directory_if_owned "$TEMP_DIR" "$TEMP_DIR_IDENTITY"
}

canonical_directory() {
  local label="$1"
  local selected="$2"
  local canonical
  [[ "$selected" == /* && -d "$selected" && ! -L "$selected" ]] \
    || die "$label must be an existing absolute non-symlink directory: $selected"
  canonical="$(realpath -e -- "$selected")" \
    || die "could not resolve $label: $selected"
  [[ "$canonical" != *','* && "$canonical" != *$'\n'* && "$canonical" != *$'\r'* ]] \
    || die "$label cannot be represented as a Docker bind mount: $canonical"
  printf '%s\n' "$canonical"
}

canonical_file() {
  local label="$1"
  local selected="$2"
  local canonical

  [[ "$selected" == /* && -f "$selected" && ! -L "$selected" ]] \
    || die "$label must be an existing absolute regular non-symlink file: $selected"
  canonical="$(realpath -e -- "$selected")" \
    || die "could not resolve $label: $selected"
  [[ "$canonical" != *','* && "$canonical" != *$'\n'* && "$canonical" != *$'\r'* ]] \
    || die "$label cannot be represented as a Docker bind mount: $canonical"
  printf '%s\n' "$canonical"
}

path_is_within() {
  local selected="$1"
  local parent="$2"

  if [[ "$parent" == / ]]; then
    [[ "$selected" == /* ]]
    return
  fi
  [[ "$selected" == "$parent" || "$selected" == "$parent/"* ]]
}

paths_overlap() {
  local first="$1"
  local second="$2"

  path_is_within "$first" "$second" || path_is_within "$second" "$first"
}

directory_identity() {
  local selected="$1"
  local canonical

  [[ "$selected" == /* && -d "$selected" && ! -L "$selected" ]] || return 1
  canonical="$(realpath -e -- "$selected" 2>/dev/null)" || return 1
  [[ "$canonical" == "$selected" ]] || return 1
  stat -c '%d:%i' -- "$selected" 2>/dev/null
}

private_directory_identity() {
  local selected="$1"
  local identity
  local stat_uid
  local stat_mode

  identity="$(directory_identity "$selected")" || return 1
  read -r stat_uid stat_mode < <(stat -c '%u %a' -- "$selected") || return 1
  [[ "$stat_uid" == "${EUID:-$(id -u)}" && "$stat_mode" == 700 ]] || return 1
  printf '%s\n' "$identity"
}

create_private_temp_directory() {
  local label="$1"
  local template="$2"
  local workdir="$3"
  local root
  local canonical_root
  local selected
  local canonical

  # Do not honor TMPDIR here. It is caller-controlled and may be located in the
  # workspace that the learned candidate receives as a writable bind mount.
  for root in /tmp /var/tmp; do
    [[ -d "$root" && ! -L "$root" && -w "$root" ]] || continue
    canonical_root="$(realpath -e -- "$root" 2>/dev/null)" || continue
    if ! selected="$(mktemp -d "$canonical_root/$template")"; then
      continue
    fi
    canonical="$(realpath -e -- "$selected" 2>/dev/null || true)"
    if [[ "$canonical" == "$selected" ]] \
      && ! paths_overlap "$selected" "$workdir" \
      && private_directory_identity "$selected" >/dev/null; then
      printf '%s\n' "$selected"
      return
    fi
    rm -rf -- "$selected"
  done
  die "could not create a canonical private $label disjoint from profile workdir $workdir"
}

revalidate_directory_identity() {
  local label="$1"
  local selected="$2"
  local expected_identity="$3"
  local actual_identity

  actual_identity="$(directory_identity "$selected")" \
    || die "$label is no longer the same canonical non-symlink directory: $selected"
  [[ "$actual_identity" == "$expected_identity" ]] \
    || die "$label identity changed while profiling: $selected"
}

revalidate_private_directory() {
  local label="$1"
  local selected="$2"
  local expected_identity="$3"
  local workdir="$4"
  local actual_identity

  actual_identity="$(private_directory_identity "$selected")" \
    || die "$label is no longer a private canonical directory: $selected"
  [[ "$actual_identity" == "$expected_identity" ]] \
    || die "$label identity changed while profiling: $selected"
  ! paths_overlap "$selected" "$workdir" \
    || die "$label overlaps profile workdir $workdir"
}

remove_private_directory_if_owned() {
  local selected="$1"
  local expected_identity="$2"
  local actual_identity

  [[ -n "$selected" && -n "$expected_identity" ]] || return 0
  actual_identity="$(private_directory_identity "$selected" 2>/dev/null || true)"
  [[ -n "$actual_identity" && "$actual_identity" == "$expected_identity" ]] || return 0
  rm -rf -- "$selected"
}

verify_owned_review_container() {
  local container_id="$1"
  local component="$2"
  local container_name="$3"
  local image_id="$4"
  local inspection
  local attachment

  [[ "$container_id" =~ ^[a-f0-9]{64}$ \
    && "$component" =~ ^(ui|graph)$ \
    && -n "$container_name" \
    && "$PROFILE_ID" =~ ^[A-Za-z0-9_.-]{1,128}$ \
    && "$image_id" =~ ^sha256:[a-f0-9]{64}$ \
    && "$PROFILE_EVIDENCE_DIGEST" =~ ^sha256:[a-f0-9]{64}$ \
    && "$GRAPH_DIGEST" =~ ^sha256:[a-f0-9]{64}$ \
    && "$GRAPH_CONTENT_DIGEST" =~ ^sha256:[a-f0-9]{64}$ \
    && "$REVIEW_NETWORK_ID" =~ ^[a-f0-9]{64}$ \
    && "$REVIEW_NETWORK" =~ ^[A-Za-z0-9_.-]{1,63}$ ]] || return 1
  inspection="$("$DOCKER_BIN" inspect --type container \
    --format '{{.Id}}|{{.Image}}|{{index .Config.Labels "io.notty.policy-review.managed"}}|{{index .Config.Labels "io.notty.policy-review.component"}}|{{index .Config.Labels "io.notty.policy-review.profile"}}|{{index .Config.Labels "io.notty.policy-review.profile-evidence-digest"}}|{{index .Config.Labels "io.notty.policy-review.graph-digest"}}|{{index .Config.Labels "io.notty.policy-review.graph-content-digest"}}|{{.Name}}|{{.State.Running}}' \
    "$container_id" 2>/dev/null)" || return 1
  [[ "$inspection" == "$container_id|$image_id|true|$component|$PROFILE_ID|$PROFILE_EVIDENCE_DIGEST|$GRAPH_DIGEST|$GRAPH_CONTENT_DIGEST|/$container_name|true" ]] \
    || return 1
  attachment="$("$DOCKER_BIN" inspect --type container \
    --format "{{len .NetworkSettings.Networks}}|{{with index .NetworkSettings.Networks \"$REVIEW_NETWORK\"}}{{.NetworkID}}|{{.IPAddress}}{{end}}" \
    "$container_id" 2>/dev/null)" || return 1
  [[ "$attachment" == "1|$REVIEW_NETWORK_ID|"* ]] || return 1
  is_docker_bridge_ipv4 "${attachment##*|}"
}

stop_owned_review_container() {
  local container_id="$1"
  local component="$2"
  local container_name="$3"
  local image_id="$4"

  [[ -n "$container_id" ]] || return 0
  verify_owned_review_container "$container_id" "$component" "$container_name" "$image_id" \
    || return 1
  "$DOCKER_BIN" stop --time 3 "$container_id"
}

container_bridge_ip() {
  local container_id="$1"
  local attachment

  attachment="$("$DOCKER_BIN" inspect --type container \
    --format "{{len .NetworkSettings.Networks}}|{{with index .NetworkSettings.Networks \"$REVIEW_NETWORK\"}}{{.NetworkID}}|{{.IPAddress}}{{end}}" \
    "$container_id" 2>/dev/null)" || return 1
  [[ "$attachment" == "1|$REVIEW_NETWORK_ID|"* ]] || return 1
  is_docker_bridge_ipv4 "${attachment##*|}" || return 1
  printf '%s\n' "${attachment##*|}"
}

verify_owned_review_network() {
  local network_id="$1"
  local network_name="$2"
  local inspection

  [[ "$network_id" =~ ^[a-f0-9]{64}$ \
    && "$network_name" =~ ^[A-Za-z0-9_.-]{1,63}$ \
    && "$PROFILE_ID" =~ ^[A-Za-z0-9_.-]{1,128}$ \
    && "$PROFILE_EVIDENCE_DIGEST" =~ ^sha256:[a-f0-9]{64}$ \
    && "$GRAPH_DIGEST" =~ ^sha256:[a-f0-9]{64}$ \
    && "$GRAPH_CONTENT_DIGEST" =~ ^sha256:[a-f0-9]{64}$ ]] || return 1
  inspection="$("$DOCKER_BIN" network inspect \
    --format '{{.Id}}|{{.Name}}|{{.Driver}}|{{.Internal}}|{{index .Labels "io.notty.policy-review.managed"}}|{{index .Labels "io.notty.policy-review.component"}}|{{index .Labels "io.notty.policy-review.profile"}}|{{index .Labels "io.notty.policy-review.profile-evidence-digest"}}|{{index .Labels "io.notty.policy-review.graph-digest"}}|{{index .Labels "io.notty.policy-review.graph-content-digest"}}' \
    "$network_id" 2>/dev/null)" || return 1
  [[ "$inspection" == "$network_id|$network_name|bridge|true|true|network|$PROFILE_ID|$PROFILE_EVIDENCE_DIGEST|$GRAPH_DIGEST|$GRAPH_CONTENT_DIGEST" ]]
}

trusted_private_file() {
  local selected="$1"
  local canonical
  local stat_uid stat_mode stat_links

  [[ "$selected" == /* && -f "$selected" && ! -L "$selected" ]] || return 1
  canonical="$(realpath -e -- "$selected" 2>/dev/null)" || return 1
  [[ "$canonical" == "$selected" ]] || return 1
  read -r stat_uid stat_mode stat_links < <(stat -c '%u %a %h' -- "$selected") \
    || return 1
  [[ "$stat_uid" == "${EUID:-$(id -u)}" && "$stat_mode" == 600 && "$stat_links" == 1 ]]
}

state_value() {
  local file="$1"
  local key="$2"
  sed -n "s/^${key}=//p" "$file"
}

print_command() {
  printf '  '
  printf '%q ' "$@"
  printf '\n'
}

encoded_graph_url() {
  local encoded="$1"
  encoded="${encoded//%/%25}"
  encoded="${encoded//:/%3A}"
  encoded="${encoded//\//%2F}"
  printf '%s\n' "$encoded"
}

resolve_reviewed_image() {
  local requested="$1"
  local abi_label="$2"
  local expected_abi="$3"
  local description="$4"
  local inspection

  [[ "$requested" =~ ^sha256:[a-f0-9]{64}$ ]] \
    || die "$description must be an exact local sha256 image ID"
  inspection="$("$DOCKER_BIN" image inspect \
    --format "{{.Id}}|{{index .Config.Labels \"$abi_label\"}}" \
    "$requested" 2>/dev/null)" \
    || die "$description is not installed locally; this workflow never pulls reviewed images"
  [[ "$inspection" =~ ^(sha256:[a-f0-9]{64})\|([^\|[:space:]]+)$ ]] \
    || die "could not verify $description identity and ABI"
  [[ "${BASH_REMATCH[1]}" == "$requested" ]] \
    || die "$description did not resolve to its exact configured image ID"
  [[ "${BASH_REMATCH[2]}" == "$expected_abi" ]] \
    || die "$description ABI mismatch: expected $abi_label=$expected_abi, got ${BASH_REMATCH[2]}"
  printf '%s\n' "$requested"
}

load_review_image_config() {
  local config_home
  local config_path
  local metadata owner mode links line key value schema_version=""
  local line_number=0
  local -A seen=()

  if [[ -z "$POLICY_REVIEW_IMAGE_CONFIG" ]]; then
    if [[ -n "${XDG_CONFIG_HOME:-}" ]]; then
      config_home="$XDG_CONFIG_HOME"
    else
      [[ -n "${HOME:-}" ]] || return 0
      config_home="$HOME/.config"
    fi
    POLICY_REVIEW_IMAGE_CONFIG="$config_home/nosh/policy-review-images.conf"
  fi
  config_path="$POLICY_REVIEW_IMAGE_CONFIG"
  [[ "$config_path" == /* ]] || die 'Policy Review image configuration must be an absolute path'
  [[ ! -e "$config_path" && ! -L "$config_path" ]] && return 0
  [[ -f "$config_path" && ! -L "$config_path" ]] \
    || die "unsafe Policy Review image configuration: $config_path"
  metadata="$(stat -Lc '%u %a %h' -- "$config_path" 2>/dev/null)" \
    || die "cannot inspect Policy Review image configuration: $config_path"
  read -r owner mode links <<<"$metadata"
  [[ "$owner" == "${EUID:-$(id -u)}" && "$mode" == 600 && "$links" == 1 ]] \
    || die "unsafe Policy Review image configuration (must be caller-owned, mode 0600, and singly linked): $config_path"
  while IFS= read -r line || [[ -n "$line" ]]; do
    ((line_number += 1))
    [[ -z "$line" || "$line" == *=* ]] \
      || die "malformed Policy Review image configuration at $config_path:$line_number"
    [[ -n "$line" ]] || continue
    key="${line%%=*}"
    value="${line#*=}"
    case "$key" in
      SCHEMA_VERSION|NOSH_POLICY_TOOLING_IMAGE|NOSH_POLICY_REVIEW_UI_IMAGE) ;;
      *) die "unknown Policy Review image configuration key at $config_path:$line_number: $key" ;;
    esac
    [[ ! -v "seen[$key]" ]] \
      || die "duplicate Policy Review image configuration key at $config_path:$line_number: $key"
    seen["$key"]=1
    case "$key" in
      SCHEMA_VERSION) schema_version="$value" ;;
      NOSH_POLICY_TOOLING_IMAGE)
        [[ -n "$POLICY_TOOLING_IMAGE_REQUESTED" ]] || POLICY_TOOLING_IMAGE_REQUESTED="$value"
        ;;
      NOSH_POLICY_REVIEW_UI_IMAGE)
        [[ -n "$POLICY_REVIEW_UI_IMAGE_REQUESTED" ]] || POLICY_REVIEW_UI_IMAGE_REQUESTED="$value"
        ;;
    esac
  done <"$config_path"
  [[ "$schema_version" == 1 \
    && -v "seen[NOSH_POLICY_TOOLING_IMAGE]" \
    && -v "seen[NOSH_POLICY_REVIEW_UI_IMAGE]" ]] \
    || die "incomplete Policy Review image configuration: $config_path"
}

trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
  usage
  exit 0
fi

while (($#)); do
  case "$1" in
    --build-profile)
      [[ -z "$EXISTING_PROFILE" ]] || die "--build-profile may be specified only once"
      (($# >= 2)) || die "--build-profile requires a value"
      EXISTING_PROFILE="$2"
      shift 2
      ;;
    --build-profile=*)
      [[ -z "$EXISTING_PROFILE" ]] || die "--build-profile may be specified only once"
      EXISTING_PROFILE="${1#*=}"
      [[ -n "$EXISTING_PROFILE" ]] || die "--build-profile requires a value"
      shift
      ;;
    --allow-missing-sbom)
      [[ "$REVIEW_ALLOW_MISSING_SBOM" == false ]] \
        || die '--allow-missing-sbom may be specified only once'
      REVIEW_ALLOW_MISSING_SBOM="true"
      shift
      ;;
    --sbom-source|--sbom-image)
      option="$1"
      (($# >= 2)) || die "$option requires a value"
      [[ -n "$2" ]] || die "$option requires a value"
      if [[ "$option" == --sbom-source ]]; then
        [[ -z "$REVIEW_SBOM_SOURCE" ]] \
          || die '--sbom-source may be specified only once'
        REVIEW_SBOM_SOURCE="$2"
      else
        [[ -z "$REVIEW_SBOM_IMAGE" ]] \
          || die '--sbom-image may be specified only once'
        REVIEW_SBOM_IMAGE="$2"
      fi
      shift 2
      ;;
    --sbom-source=*)
      [[ -z "$REVIEW_SBOM_SOURCE" ]] \
        || die '--sbom-source may be specified only once'
      REVIEW_SBOM_SOURCE="${1#*=}"
      [[ -n "$REVIEW_SBOM_SOURCE" ]] || die '--sbom-source requires a value'
      shift
      ;;
    --sbom-image=*)
      [[ -z "$REVIEW_SBOM_IMAGE" ]] \
        || die '--sbom-image may be specified only once'
      REVIEW_SBOM_IMAGE="${1#*=}"
      [[ -n "$REVIEW_SBOM_IMAGE" ]] || die '--sbom-image requires a value'
      shift
      ;;
    --)
      PROFILE_ARGS+=("$@")
      break
      ;;
    *)
      PROFILE_ARGS+=("$1")
      shift
      ;;
  esac
done

review_argument_index=0
while ((review_argument_index < ${#PROFILE_ARGS[@]})); do
  review_argument="${PROFILE_ARGS[$review_argument_index]}"
  [[ "$review_argument" != -- ]] || break
  if [[ "$review_argument" == --cache-mode=warm ]]; then
    die 'warm-only evidence cannot generate the behavioral candidate required for review; use --cache-mode cold or compare'
  fi
  if [[ "$review_argument" == --cache-mode ]]; then
    review_value_index=$((review_argument_index + 1))
    review_value="${PROFILE_ARGS[$review_value_index]:-}"
    if [[ "$review_value" == warm ]]; then
      die 'warm-only evidence cannot generate the behavioral candidate required for review; use --cache-mode cold or compare'
    fi
    review_argument_index=$((review_argument_index + 2))
    continue
  fi
  review_argument_index=$((review_argument_index + 1))
done

if [[ -z "$EXISTING_PROFILE" ]]; then
  [[ -x "$PROFILE_BIN" ]] || die "profile runner is not executable: $PROFILE_BIN"
else
  [[ "$EXISTING_PROFILE" == /* ]] || die "--build-profile must be an absolute path"
  [[ -d "$EXISTING_PROFILE" && ! -L "$EXISTING_PROFILE" ]] || die "build profile is not an existing non-symlink directory: $EXISTING_PROFILE"
  EXISTING_PROFILE="$(realpath -e -- "$EXISTING_PROFILE")" || die "could not resolve build profile: $EXISTING_PROFILE"
  [[ "$EXISTING_PROFILE" =~ /[A-Za-z0-9_.-]{1,128}$ ]] || die "build profile directory name is not a safe run identifier"
  REVIEW_ALLOW_MISSING_SBOM="true"
fi
command -v "$DOCKER_BIN" >/dev/null 2>&1 || die "Docker is unavailable: $DOCKER_BIN"
[[ -z "${NOSH_PROFILE_REVIEW_ORIGIN:-}" && -z "${NOSH_PROFILE_REVIEW_UI_URL:-}" ]] \
  || die 'custom review origins are not accepted; use the wrapper-managed Docker bridge UI'
load_review_image_config
POLICY_TOOLING_IMAGE_ID="$(resolve_reviewed_image \
  "$POLICY_TOOLING_IMAGE_REQUESTED" \
  io.notty.guard.policy-tooling-abi 1 NOSH_POLICY_TOOLING_IMAGE)"
POLICY_REVIEW_UI_IMAGE_ID="$(resolve_reviewed_image \
  "$POLICY_REVIEW_UI_IMAGE_REQUESTED" \
  io.notty.policy-review.ui-abi 1 NOSH_POLICY_REVIEW_UI_IMAGE)"
PROFILE_WORKDIR="$(canonical_directory 'profile workdir' "$PROFILE_WORKDIR")"
PROFILE_WORKDIR_IDENTITY="$(directory_identity "$PROFILE_WORKDIR")" \
  || die "profile workdir is not a stable canonical directory: $PROFILE_WORKDIR"
if [[ -n "$REVIEW_SBOM_SOURCE" ]]; then
  REVIEW_SBOM_SOURCE="$(canonical_file 'source SBOM' "$REVIEW_SBOM_SOURCE")"
fi
if [[ -n "$REVIEW_SBOM_IMAGE" ]]; then
  REVIEW_SBOM_IMAGE="$(canonical_file 'image SBOM' "$REVIEW_SBOM_IMAGE")"
fi
[[ -z "$REVIEW_SBOM_SOURCE" || "$REVIEW_SBOM_SOURCE" != "$REVIEW_SBOM_IMAGE" ]] \
  || die 'source and image SBOMs must be distinct files'

install -d -m 0700 -- "$REVIEW_STATE_ROOT"
REVIEW_STATE_ROOT="$(canonical_directory 'review state root' "$REVIEW_STATE_ROOT")"
! paths_overlap "$REVIEW_STATE_ROOT" "$PROFILE_WORKDIR" \
  || die "review state root overlaps profile workdir: $REVIEW_STATE_ROOT"
REVIEW_STATE_ROOT_IDENTITY="$(private_directory_identity "$REVIEW_STATE_ROOT")" \
  || die "review state root must be caller-owned with mode 0700: $REVIEW_STATE_ROOT"

TEMP_DIR="$(create_private_temp_directory \
  'review temporary directory' nosh-profile-review.XXXXXX "$PROFILE_WORKDIR")"
TEMP_DIR_IDENTITY="$(private_directory_identity "$TEMP_DIR")" \
  || die "review temporary directory is not private: $TEMP_DIR"
if [[ -n "$REVIEW_SBOM_SOURCE" ]]; then
  install -m 0400 -- "$REVIEW_SBOM_SOURCE" "$TEMP_DIR/source.spdx.json"
  REVIEW_SBOM_SOURCE="$TEMP_DIR/source.spdx.json"
  REVIEW_SBOM_SOURCE_DIGEST="sha256:$(sha256sum -- "$REVIEW_SBOM_SOURCE" | awk '{print $1}')"
fi
if [[ -n "$REVIEW_SBOM_IMAGE" ]]; then
  install -m 0400 -- "$REVIEW_SBOM_IMAGE" "$TEMP_DIR/image.spdx.json"
  REVIEW_SBOM_IMAGE="$TEMP_DIR/image.spdx.json"
  REVIEW_SBOM_IMAGE_DIGEST="sha256:$(sha256sum -- "$REVIEW_SBOM_IMAGE" | awk '{print $1}')"
fi
if [[ -n "$EXISTING_PROFILE" ]]; then
  PROFILE_DIR="$EXISTING_PROFILE"
  PROFILE_ID="$(basename -- "$PROFILE_DIR")"
  PROFILE_OUTPUT=""
  PROFILE_STATUS=0
  IMAGE_DIGEST=""
  RUNTIME_CANDIDATE=""
  TARGET_CONTEXT=""
else
  PROFILE_OUTPUT="$TEMP_DIR/profile-output.log"
  printf '%s\n' '== Running build/runtime profile ==' >&2

  set +e
  (cd "$PROFILE_WORKDIR" && "$PROFILE_BIN" "${PROFILE_ARGS[@]}") 2>&1 | tee "$PROFILE_OUTPUT"
  PROFILE_STATUS=${PIPESTATUS[0]}
  set -e
  revalidate_directory_identity \
    'profile workdir' "$PROFILE_WORKDIR" "$PROFILE_WORKDIR_IDENTITY"
  revalidate_private_directory \
    'review state root' "$REVIEW_STATE_ROOT" \
    "$REVIEW_STATE_ROOT_IDENTITY" "$PROFILE_WORKDIR"
  revalidate_private_directory \
    'review temporary directory' "$TEMP_DIR" \
    "$TEMP_DIR_IDENTITY" "$PROFILE_WORKDIR"
  ((PROFILE_STATUS == 0)) || die "profile-build-and-run failed with status $PROFILE_STATUS"

  PROFILE_ID="$(sed -n 's/^Nosh build profile: //p' "$PROFILE_OUTPUT" | tail -n 1)"
  PROFILE_DIR="$(sed -n 's/^Private bundle: //p' "$PROFILE_OUTPUT" | tail -n 1)"
  IMAGE_DIGEST="$(sed -n 's/^Immutable local runtime image ID: //p' "$PROFILE_OUTPUT" | tail -n 1)"
  RUNTIME_CANDIDATE="$(sed -n 's/^Runtime review candidate: //p' "$PROFILE_OUTPUT" | tail -n 1)"
  TARGET_CONTEXT="$(sed -n 's/^Guard eBPF target context: //p' "$PROFILE_OUTPUT" | tail -n 1)"
fi

[[ "$PROFILE_ID" =~ ^[A-Za-z0-9_.-]{1,128}$ ]] \
  || die 'profile runner did not report a safe build profile ID'
if [[ -n "$IMAGE_DIGEST" ]]; then
  [[ "$IMAGE_DIGEST" =~ ^sha256:[a-f0-9]{64}$ ]] || die 'profile runner did not report an immutable runtime image ID'
fi
PROFILE_DIR="$(canonical_directory 'private build profile' "$PROFILE_DIR")"
PROFILE_EVIDENCE_FILE="$PROFILE_DIR/evidence-manifest.json"
trusted_private_file "$PROFILE_EVIDENCE_FILE" \
  || die "build profile evidence manifest must be a caller-owned 0600 regular file: $PROFILE_EVIDENCE_FILE"
PROFILE_EVIDENCE_DIGEST="sha256:$(sha256sum -- "$PROFILE_EVIDENCE_FILE" | awk '{print $1}')"
[[ "$PROFILE_EVIDENCE_DIGEST" =~ ^sha256:[a-f0-9]{64}$ ]] \
  || die 'could not digest the build profile evidence manifest'
if [[ -n "$RUNTIME_CANDIDATE" ]]; then
  RUNTIME_CANDIDATE="$(canonical_directory 'runtime review candidate' "$RUNTIME_CANDIDATE")"
fi
if [[ -n "$TARGET_CONTEXT" ]]; then
  [[ "$TARGET_CONTEXT" == /* && -f "$TARGET_CONTEXT" && ! -L "$TARGET_CONTEXT" ]] || die 'profile runner did not report a regular Guard eBPF target context file'
  TARGET_CONTEXT="$(realpath -e -- "$TARGET_CONTEXT")"
fi

PROFILE_STORE_ROOT="$(canonical_directory 'build profile store' "$(dirname "$(dirname "$PROFILE_DIR")")")"
RUNTIME_EXPORT_ROOT=""
if [[ -n "$RUNTIME_CANDIDATE" ]]; then
  RUNTIME_EXPORT_ROOT="$(canonical_directory 'runtime review export store' "$(dirname "$(dirname "$RUNTIME_CANDIDATE")")")"
fi
PROFILE_SLUG="${PROFILE_ID//[^A-Za-z0-9_.-]/-}"
PROFILE_SLUG="${PROFILE_SLUG:0:36}"
PROFILE_EVIDENCE_HEX="${PROFILE_EVIDENCE_DIGEST#sha256:}"
RUNTIME_COMPOSITION_ID="none"
if [[ -n "$RUNTIME_CANDIDATE" ]]; then
  RUNTIME_PROFILE_FILE="$RUNTIME_CANDIDATE/egress-profile.json"
  RUNTIME_POLICY_FILE="$RUNTIME_CANDIDATE/egress-policy.json"
  RUNTIME_MANIFEST_FILE="$RUNTIME_CANDIDATE/manifest.json"
  for runtime_file in \
    "$RUNTIME_PROFILE_FILE" "$RUNTIME_POLICY_FILE" "$RUNTIME_MANIFEST_FILE"; do
    trusted_private_file "$runtime_file" \
      || die "runtime review candidate artifact must be a caller-owned 0600 regular file: $runtime_file"
  done
  RUNTIME_COMPOSITION_ID="$(printf '%s\n' \
    "profile=sha256:$(sha256sum -- "$RUNTIME_PROFILE_FILE" | awk '{print $1}')" \
    "policy=sha256:$(sha256sum -- "$RUNTIME_POLICY_FILE" | awk '{print $1}')" \
    "manifest=sha256:$(sha256sum -- "$RUNTIME_MANIFEST_FILE" | awk '{print $1}')" \
    | sha256sum | awk '{print $1}')"
fi
REVIEW_COMPOSITION_DIGEST="sha256:$(printf '%s\n' \
  "allow_missing_sbom=$REVIEW_ALLOW_MISSING_SBOM" \
  "runtime_candidate=$RUNTIME_COMPOSITION_ID" \
  "source_sbom=$REVIEW_SBOM_SOURCE_DIGEST" \
  "image_sbom=$REVIEW_SBOM_IMAGE_DIGEST" | sha256sum | awk '{print $1}')"
[[ "$REVIEW_COMPOSITION_DIGEST" =~ ^sha256:[a-f0-9]{64}$ ]] \
  || die 'could not bind the review graph composition inputs'
REVIEW_COMPOSITION_HEX="${REVIEW_COMPOSITION_DIGEST#sha256:}"
SESSION_KEY="$PROFILE_SLUG-${PROFILE_EVIDENCE_HEX:0:12}-${REVIEW_COMPOSITION_HEX:0:12}"
SESSION_DIR="$REVIEW_STATE_ROOT/$SESSION_KEY"
RUNTIME_DIR="$SESSION_DIR/runtime"
DECISIONS_DIR="$SESSION_DIR/decisions"
REVIEW_DIR="$SESSION_DIR/bundle"
PROFILE_STATE="$SESSION_DIR/profile.state"
SERVICE_STATE="$SESSION_DIR/services.state"
install -d -m 0700 -- "$SESSION_DIR" "$RUNTIME_DIR" "$DECISIONS_DIR"
SESSION_DIR="$(canonical_directory 'review session directory' "$SESSION_DIR")"
RUNTIME_DIR="$(canonical_directory 'review runtime directory' "$RUNTIME_DIR")"
private_directory_identity "$SESSION_DIR" >/dev/null \
  || die "review session directory must be caller-owned with mode 0700: $SESSION_DIR"
private_directory_identity "$RUNTIME_DIR" >/dev/null \
  || die "review runtime directory must be caller-owned with mode 0700: $RUNTIME_DIR"
DECISIONS_DIR="$(canonical_directory 'review DecisionSet directory' "$DECISIONS_DIR")"
private_directory_identity "$DECISIONS_DIR" >/dev/null \
  || die "review DecisionSet directory must be caller-owned with mode 0700: $DECISIONS_DIR"

HOST_UID="$(id -u)"
HOST_GID="$(id -g)"
REVIEW_LOG="$TEMP_DIR/review-bundle.log"
declare -a REVIEW_MOUNTS=(
  --mount "type=bind,src=$PROFILE_STORE_ROOT,dst=$PROFILE_STORE_ROOT,readonly"
  --mount "type=bind,src=$REVIEW_STATE_ROOT,dst=$REVIEW_STATE_ROOT"
)
if [[ -n "$RUNTIME_EXPORT_ROOT" ]]; then
  REVIEW_MOUNTS+=(--mount "type=bind,src=$RUNTIME_EXPORT_ROOT,dst=$RUNTIME_EXPORT_ROOT,readonly")
fi
if [[ -n "$REVIEW_SBOM_SOURCE" ]]; then
  REVIEW_MOUNTS+=(--mount "type=bind,src=$REVIEW_SBOM_SOURCE,dst=$REVIEW_SBOM_SOURCE,readonly")
fi
if [[ -n "$REVIEW_SBOM_IMAGE" ]]; then
  REVIEW_MOUNTS+=(--mount "type=bind,src=$REVIEW_SBOM_IMAGE,dst=$REVIEW_SBOM_IMAGE,readonly")
fi

REVIEW_REUSED="false"
if [[ -d "$REVIEW_DIR" && ! -L "$REVIEW_DIR" ]]; then
  REVIEW_REUSED="true"
  trusted_private_file "$PROFILE_STATE" \
    || die "persisted review profile identity is missing or insecure: $PROFILE_STATE"
  [[ "$(wc -l <"$PROFILE_STATE")" == 6 \
    && "$(state_value "$PROFILE_STATE" profile_id)" == "$PROFILE_ID" \
    && "$(state_value "$PROFILE_STATE" profile_evidence_digest)" == "$PROFILE_EVIDENCE_DIGEST" \
    && "$(state_value "$PROFILE_STATE" review_composition_digest)" == "$REVIEW_COMPOSITION_DIGEST" ]] \
    || die "persisted review profile identity does not match $PROFILE_DIR"
  GRAPH_DIGEST="$(state_value "$PROFILE_STATE" graph_digest)"
  GRAPH_CONTENT_DIGEST="$(state_value "$PROFILE_STATE" graph_content_digest)"
  [[ "$GRAPH_DIGEST" =~ ^sha256:[a-f0-9]{64}$ \
    && "$GRAPH_CONTENT_DIGEST" =~ ^sha256:[a-f0-9]{64}$ \
    && "$(state_value "$PROFILE_STATE" policy_tooling_image)" == "$POLICY_TOOLING_IMAGE_ID" ]] \
    || die 'persisted review profile identity contains invalid digests or tooling identity'
  printf '\n%s\n' '== Verifying persisted frozen review bundle ==' >&2
  REVIEW_COMMAND=(
    /app/scripts/nosh-guard.mjs review inspect
    --bundle "$REVIEW_DIR"
  )
else
  [[ ! -e "$REVIEW_DIR" && ! -L "$REVIEW_DIR" \
    && ! -e "$PROFILE_STATE" && ! -L "$PROFILE_STATE" ]] \
    || die "review session contains incomplete or foreign artifacts: $SESSION_DIR"
  printf '\n%s\n' '== Materializing frozen review bundle ==' >&2
  REVIEW_COMMAND=(
    /app/scripts/nosh-guard.mjs review bundle
    --profile "$PROFILE_DIR"
    --output "$REVIEW_DIR"
  )
  if [[ -n "$RUNTIME_CANDIDATE" ]]; then
    REVIEW_COMMAND+=(--runtime-candidate "$RUNTIME_CANDIDATE")
  fi
  if [[ "$REVIEW_ALLOW_MISSING_SBOM" == true ]]; then
    REVIEW_COMMAND+=(--allow-missing-sbom)
    printf '%s\n' \
      'profile-build-and-review: WARNING: explicit missing-SBOM coverage downgrade requested; signed activation remains blocked' >&2
  fi
  if [[ -n "$REVIEW_SBOM_SOURCE" ]]; then
    REVIEW_COMMAND+=(--sbom-source "$REVIEW_SBOM_SOURCE")
  fi
  if [[ -n "$REVIEW_SBOM_IMAGE" ]]; then
    REVIEW_COMMAND+=(--sbom-image "$REVIEW_SBOM_IMAGE")
  fi
fi
set +e
"$DOCKER_BIN" run --rm --pull never --network none \
  --user "$HOST_UID:$HOST_GID" \
  --read-only --cap-drop ALL --security-opt no-new-privileges:true \
  --tmpfs /tmp:rw,nosuid,nodev,noexec,size=67108864 \
  --env HOME=/tmp/nosh-review-home \
  "${REVIEW_MOUNTS[@]}" \
  --entrypoint /usr/local/bin/node \
  "$POLICY_TOOLING_IMAGE_ID" \
  "${REVIEW_COMMAND[@]}" 2>&1 | tee "$REVIEW_LOG"
REVIEW_STATUS=${PIPESTATUS[0]}
set -e
if ((REVIEW_STATUS != 0 && REVIEW_STATUS != 2)); then
  die "containerized review bundle verification/materialization failed with status $REVIEW_STATUS"
fi
[[ -d "$REVIEW_DIR" && ! -L "$REVIEW_DIR" ]] \
  || die 'review bundle command did not create its expected directory'
private_directory_identity "$REVIEW_DIR" >/dev/null \
  || die "review bundle directory must be caller-owned with mode 0700: $REVIEW_DIR"
REPORTED_GRAPH_DIGEST="$(sed -n 's/^[[:space:]]*"graphDigest": "\(sha256:[a-f0-9]\{64\}\)",\{0,1\}$/\1/p' "$REVIEW_LOG")"
REPORTED_GRAPH_CONTENT_DIGEST="$(sed -n 's/^[[:space:]]*"graphContentDigest": "\(sha256:[a-f0-9]\{64\}\)",\{0,1\}$/\1/p' "$REVIEW_LOG")"
[[ "$REPORTED_GRAPH_DIGEST" =~ ^sha256:[a-f0-9]{64}$ \
  && "$REPORTED_GRAPH_CONTENT_DIGEST" =~ ^sha256:[a-f0-9]{64}$ ]] \
  || die 'review bundle command did not report exact graph digests'
if [[ "$REVIEW_REUSED" == true ]]; then
  [[ "$REPORTED_GRAPH_DIGEST" == "$GRAPH_DIGEST" \
    && "$REPORTED_GRAPH_CONTENT_DIGEST" == "$GRAPH_CONTENT_DIGEST" ]] \
    || die 'persisted review bundle digest changed since materialization'
else
  GRAPH_DIGEST="$REPORTED_GRAPH_DIGEST"
  GRAPH_CONTENT_DIGEST="$REPORTED_GRAPH_CONTENT_DIGEST"
  PROFILE_STATE_TEMP="$SESSION_DIR/.profile.state.$$"
  (umask 077; printf '%s\n' \
    "profile_id=$PROFILE_ID" \
    "profile_evidence_digest=$PROFILE_EVIDENCE_DIGEST" \
    "review_composition_digest=$REVIEW_COMPOSITION_DIGEST" \
    "graph_digest=$GRAPH_DIGEST" \
    "graph_content_digest=$GRAPH_CONTENT_DIGEST" \
    "policy_tooling_image=$POLICY_TOOLING_IMAGE_ID" >"$PROFILE_STATE_TEMP")
  chmod 0600 -- "$PROFILE_STATE_TEMP"
  mv -- "$PROFILE_STATE_TEMP" "$PROFILE_STATE"
  trusted_private_file "$PROFILE_STATE" \
    || die 'could not persist the private review profile identity'
fi
if ((REVIEW_STATUS == 2)); then
  printf '%s\n' \
    'profile-build-and-review: the graph has blocking coverage/findings; it is reviewable but cannot yet be activated' >&2
fi

EXPECTED_NETWORK_ID=""
EXPECTED_UI_CONTAINER_ID=""
EXPECTED_GRAPH_CONTAINER_ID=""
EXPECTED_UI_HOST=""
EXPECTED_GRAPH_HOST=""
EXPECTED_GRAPH_URL=""
GRAPH_HEX="${GRAPH_DIGEST#sha256:}"
SERVICE_KEY="${PROFILE_SLUG:0:15}-${PROFILE_EVIDENCE_HEX:0:8}-${REVIEW_COMPOSITION_HEX:0:8}-${GRAPH_HEX:0:8}"
if [[ -e "$SERVICE_STATE" || -L "$SERVICE_STATE" ]]; then
  trusted_private_file "$SERVICE_STATE" \
    || die "persisted review service identity is insecure: $SERVICE_STATE"
  [[ "$(wc -l <"$SERVICE_STATE")" == 11 \
    && "$(state_value "$SERVICE_STATE" profile_id)" == "$PROFILE_ID" \
    && "$(state_value "$SERVICE_STATE" profile_evidence_digest)" == "$PROFILE_EVIDENCE_DIGEST" \
    && "$(state_value "$SERVICE_STATE" graph_digest)" == "$GRAPH_DIGEST" \
    && "$(state_value "$SERVICE_STATE" ui_image)" == "$POLICY_REVIEW_UI_IMAGE_ID" \
    && "$(state_value "$SERVICE_STATE" tooling_image)" == "$POLICY_TOOLING_IMAGE_ID" ]] \
    || die 'persisted review service identity does not match this profile graph and images'
  EXPECTED_NETWORK_ID="$(state_value "$SERVICE_STATE" network_id)"
  EXPECTED_UI_CONTAINER_ID="$(state_value "$SERVICE_STATE" ui_container_id)"
  EXPECTED_GRAPH_CONTAINER_ID="$(state_value "$SERVICE_STATE" graph_container_id)"
  EXPECTED_UI_HOST="$(state_value "$SERVICE_STATE" ui_host)"
  EXPECTED_GRAPH_HOST="$(state_value "$SERVICE_STATE" graph_host)"
  EXPECTED_GRAPH_URL="$(state_value "$SERVICE_STATE" graph_url)"
  [[ "$EXPECTED_NETWORK_ID" =~ ^[a-f0-9]{64}$ \
    && "$EXPECTED_UI_CONTAINER_ID" =~ ^[a-f0-9]{64}$ \
    && "$EXPECTED_GRAPH_CONTAINER_ID" =~ ^[a-f0-9]{64}$ \
    && "$EXPECTED_GRAPH_URL" == http://* ]] \
    || die 'persisted review service identity contains invalid object IDs or URL'
  is_docker_bridge_ipv4 "$EXPECTED_UI_HOST" \
    && is_docker_bridge_ipv4 "$EXPECTED_GRAPH_HOST" \
    || die 'persisted review service identity contains invalid bridge addresses'
fi

REVIEW_NETWORK="nosh-review-$SERVICE_KEY"
REVIEW_NETWORK="${REVIEW_NETWORK:0:63}"
REVIEW_NETWORK_ID="$("$DOCKER_BIN" network inspect \
  --format '{{.Id}}' "$REVIEW_NETWORK" 2>/dev/null || true)"
if [[ -n "$REVIEW_NETWORK_ID" ]]; then
  [[ "$REVIEW_NETWORK_ID" =~ ^[a-f0-9]{64}$ ]] \
    || die "foreign object occupies managed review network name: $REVIEW_NETWORK"
  [[ -z "$EXPECTED_NETWORK_ID" || "$REVIEW_NETWORK_ID" == "$EXPECTED_NETWORK_ID" ]] \
    || die 'persisted review network identity changed; refusing stale service reuse'
  verify_owned_review_network "$REVIEW_NETWORK_ID" "$REVIEW_NETWORK" \
    || die "existing review network failed ownership, digest, or isolation attestation: $REVIEW_NETWORK"
else
  [[ -z "$EXPECTED_NETWORK_ID" ]] \
    || die 'persisted managed review network is missing; refusing stale service reuse'
  REVIEW_NETWORK_ID="$("$DOCKER_BIN" network create \
    --driver bridge --internal \
    --label io.notty.policy-review.managed=true \
    --label io.notty.policy-review.component=network \
    --label "io.notty.policy-review.profile=$PROFILE_ID" \
    --label "io.notty.policy-review.profile-evidence-digest=$PROFILE_EVIDENCE_DIGEST" \
    --label "io.notty.policy-review.graph-digest=$GRAPH_DIGEST" \
    --label "io.notty.policy-review.graph-content-digest=$GRAPH_CONTENT_DIGEST" \
    "$REVIEW_NETWORK")"
  [[ "$REVIEW_NETWORK_ID" =~ ^[a-f0-9]{64}$ ]] \
    || die 'Docker did not return an exact managed review network ID'
  verify_owned_review_network "$REVIEW_NETWORK_ID" "$REVIEW_NETWORK" \
    || die 'new managed review network failed ownership or isolation attestation'
fi

UI_CONTAINER="nosh-review-ui-$SERVICE_KEY"
UI_CONTAINER="${UI_CONTAINER:0:63}"
GRAPH_CONTAINER="nosh-review-graph-$SERVICE_KEY"
GRAPH_CONTAINER="${GRAPH_CONTAINER:0:63}"
FOUND_UI_CONTAINER_ID="$("$DOCKER_BIN" inspect --type container \
  --format '{{.Id}}' "$UI_CONTAINER" 2>/dev/null || true)"
FOUND_GRAPH_CONTAINER_ID="$("$DOCKER_BIN" inspect --type container \
  --format '{{.Id}}' "$GRAPH_CONTAINER" 2>/dev/null || true)"
if [[ -z "$EXPECTED_UI_CONTAINER_ID" ]]; then
  [[ -z "$FOUND_UI_CONTAINER_ID" && -z "$FOUND_GRAPH_CONTAINER_ID" ]] \
    || die 'unattested containers occupy managed review service names'
else
  [[ -z "$FOUND_UI_CONTAINER_ID" || "$FOUND_UI_CONTAINER_ID" == "$EXPECTED_UI_CONTAINER_ID" ]] \
    || die 'Policy Review UI container identity changed; refusing foreign or stale reuse'
  [[ -z "$FOUND_GRAPH_CONTAINER_ID" || "$FOUND_GRAPH_CONTAINER_ID" == "$EXPECTED_GRAPH_CONTAINER_ID" ]] \
    || die 'review graph container identity changed; refusing foreign or stale reuse'
fi

if [[ -n "$FOUND_UI_CONTAINER_ID" ]]; then
  UI_CONTAINER_ID="$FOUND_UI_CONTAINER_ID"
  verify_owned_review_container \
    "$UI_CONTAINER_ID" ui "$UI_CONTAINER" "$POLICY_REVIEW_UI_IMAGE_ID" \
    || die 'running Policy Review UI failed profile, graph, image, network, or identity attestation'
  printf '\n%s\n' '== Reusing attested Policy Review UI ==' >&2
else
  printf '\n%s\n' '== Starting reviewed Policy Review UI ==' >&2
  UI_CONTAINER_ID="$("$DOCKER_BIN" run --detach --rm --pull never \
    --name "$UI_CONTAINER" \
    --label io.notty.policy-review.managed=true \
    --label io.notty.policy-review.component=ui \
    --label io.notty.policy-review.ui=true \
    --label "io.notty.policy-review.profile=$PROFILE_ID" \
    --label "io.notty.policy-review.profile-evidence-digest=$PROFILE_EVIDENCE_DIGEST" \
    --label "io.notty.policy-review.graph-digest=$GRAPH_DIGEST" \
    --label "io.notty.policy-review.graph-content-digest=$GRAPH_CONTENT_DIGEST" \
    --network "$REVIEW_NETWORK" \
    --user "$HOST_UID:$HOST_GID" \
    --read-only --cap-drop ALL --security-opt no-new-privileges:true \
    --pids-limit 128 --memory 512m --memory-swap 512m \
    --env HOME=/tmp/nosh-review-home \
    --env HOSTNAME=0.0.0.0 --env PORT=3000 \
    --env NOTTY_POLICY_REVIEW_ATTESTATION_FILE=/run/notty/policy-review-attestation.json \
    --mount "type=bind,src=$RUNTIME_DIR,dst=/run/notty,readonly" \
    --env NOTTY_POLICY_REVIEW_DECISIONS_DIR=/run/notty-decisions \
    --mount "type=bind,src=$DECISIONS_DIR,dst=/run/notty-decisions" \
    --tmpfs /tmp:rw,nosuid,nodev,noexec,size=33554432 \
    --tmpfs /app/.next/cache:rw,nosuid,nodev,noexec,size=33554432 \
    "$POLICY_REVIEW_UI_IMAGE_ID")"
  [[ "$UI_CONTAINER_ID" =~ ^[a-f0-9]{64}$ ]] \
    || die 'reviewed Policy Review UI did not return an exact container ID'
  UI_CONTAINER_STARTED="true"
  verify_owned_review_container \
    "$UI_CONTAINER_ID" ui "$UI_CONTAINER" "$POLICY_REVIEW_UI_IMAGE_ID" \
    || die 'reviewed Policy Review UI ownership or identity did not attest'
fi
UI_HOST="$(container_bridge_ip "$UI_CONTAINER_ID")" \
  || die 'reviewed Policy Review UI did not report its dedicated bridge address'
[[ -z "$FOUND_UI_CONTAINER_ID" || "$UI_HOST" == "$EXPECTED_UI_HOST" ]] \
  || die 'running Policy Review UI bridge address changed; exact CORS can no longer be attested'
REVIEW_ORIGIN="http://$UI_HOST:3000"
REVIEW_UI_URL="$REVIEW_ORIGIN/policy-review"

UI_HEALTH=""
for _ in {1..300}; do
  UI_HEALTH="$("$DOCKER_BIN" inspect \
    --format '{{if .State.Health}}{{.State.Health.Status}}{{else}}missing{{end}}' \
    "$UI_CONTAINER_ID" 2>/dev/null || true)"
  [[ "$UI_HEALTH" == healthy ]] && break
  [[ "$UI_HEALTH" != unhealthy && "$UI_HEALTH" != missing ]] || break
  sleep 0.1
done
if [[ "$UI_HEALTH" != healthy ]]; then
  "$DOCKER_BIN" logs "$UI_CONTAINER_ID" >&2 2>/dev/null || true
  die "reviewed Policy Review UI did not become healthy (status: ${UI_HEALTH:-unavailable})"
fi

GRAPH_LOG="$TEMP_DIR/graph-server.log"
if [[ -n "$FOUND_GRAPH_CONTAINER_ID" ]]; then
  GRAPH_CONTAINER_ID="$FOUND_GRAPH_CONTAINER_ID"
  verify_owned_review_container \
    "$GRAPH_CONTAINER_ID" graph "$GRAPH_CONTAINER" "$POLICY_TOOLING_IMAGE_ID" \
    || die 'running review graph failed profile, graph, image, network, or identity attestation'
  GRAPH_ALLOWED_ORIGIN="$("$DOCKER_BIN" inspect --type container \
    --format '{{index .Config.Labels "io.notty.policy-review.ui-origin"}}' \
    "$GRAPH_CONTAINER_ID" 2>/dev/null || true)"
  [[ "$GRAPH_ALLOWED_ORIGIN" == "$REVIEW_ORIGIN" ]] \
    || die 'running review graph exact-origin CORS attestation is stale'
  printf '\n%s\n' '== Reusing attested tokenized review graph server ==' >&2
else
  printf '\n%s\n' '== Starting tokenized review graph server ==' >&2
  GRAPH_CONTAINER_ID="$("$DOCKER_BIN" run --detach --rm --pull never \
    --name "$GRAPH_CONTAINER" \
    --label io.notty.policy-review.managed=true \
    --label io.notty.policy-review.component=graph \
    --label io.notty.policy-review.graph=true \
    --label "io.notty.policy-review.profile=$PROFILE_ID" \
    --label "io.notty.policy-review.profile-evidence-digest=$PROFILE_EVIDENCE_DIGEST" \
    --label "io.notty.policy-review.graph-digest=$GRAPH_DIGEST" \
    --label "io.notty.policy-review.graph-content-digest=$GRAPH_CONTENT_DIGEST" \
    --label "io.notty.policy-review.ui-origin=$REVIEW_ORIGIN" \
    --network "$REVIEW_NETWORK" \
    --user "$HOST_UID:$HOST_GID" \
    --read-only --cap-drop ALL --security-opt no-new-privileges:true \
    --pids-limit 128 --memory 256m --memory-swap 256m \
    --tmpfs /tmp:rw,nosuid,nodev,noexec,size=16777216 \
    --env HOME=/tmp/nosh-review-home \
    --mount "type=bind,src=$REVIEW_DIR,dst=$REVIEW_DIR,readonly" \
    --entrypoint /usr/local/bin/node \
    "$POLICY_TOOLING_IMAGE_ID" \
    /app/scripts/nosh-guard.mjs review serve \
    --bundle "$REVIEW_DIR" \
    --port 0 \
    --host 0.0.0.0 \
    --advertise-host auto \
    --origin "$REVIEW_ORIGIN")"
  [[ "$GRAPH_CONTAINER_ID" =~ ^[a-f0-9]{64}$ ]] \
    || die 'containerized review graph server did not return an exact container ID'
  GRAPH_CONTAINER_STARTED="true"
  verify_owned_review_container \
    "$GRAPH_CONTAINER_ID" graph "$GRAPH_CONTAINER" "$POLICY_TOOLING_IMAGE_ID" \
    || die 'containerized review graph ownership or identity did not attest'
fi
GRAPH_HOST="$(container_bridge_ip "$GRAPH_CONTAINER_ID")" \
  || die 'review graph server did not report its dedicated bridge address'
[[ -z "$FOUND_GRAPH_CONTAINER_ID" || "$GRAPH_HOST" == "$EXPECTED_GRAPH_HOST" ]] \
  || die 'running review graph bridge address changed; refusing stale URL reuse'

graph_url_matches_host() {
  local selected_url="$1"
  local selected_host="$2"
  local selected_port
  [[ "$selected_url" =~ ^http://([0-9.]+):([1-9][0-9]{0,4})/v1/graph/([a-f0-9]{64})$ ]] \
    || return 1
  [[ "${BASH_REMATCH[1]}" == "$selected_host" ]] || return 1
  selected_port="${BASH_REMATCH[2]}"
  ((10#$selected_port <= 65535))
}

GRAPH_URL=""
for _ in {1..100}; do
  "$DOCKER_BIN" logs "$GRAPH_CONTAINER_ID" >"$GRAPH_LOG" 2>&1 || true
  GRAPH_URL="$(sed -n 's/^Nosh policy review graph: //p' "$GRAPH_LOG" | tail -n 1)"
  graph_url_matches_host "$GRAPH_URL" "$GRAPH_HOST" && break
  GRAPH_RUNNING="$("$DOCKER_BIN" inspect \
    --format '{{.State.Running}}' "$GRAPH_CONTAINER_ID" 2>/dev/null || true)"
  [[ "$GRAPH_RUNNING" == true ]] || break
  sleep 0.1
done
if ! graph_url_matches_host "$GRAPH_URL" "$GRAPH_HOST"; then
  "$DOCKER_BIN" logs "$GRAPH_CONTAINER_ID" >&2 2>/dev/null || true
  die 'containerized review graph URL did not match its inspected bridge address'
fi
[[ -z "$FOUND_GRAPH_CONTAINER_ID" || "$GRAPH_URL" == "$EXPECTED_GRAPH_URL" ]] \
  || die 'running review graph tokenized URL changed; refusing stale service reuse'
GRAPH_ORIGIN="${GRAPH_URL%%/v1/graph/*}"

ATTESTATION_FILE="$RUNTIME_DIR/policy-review-attestation.json"
ATTESTATION_TEMP="$RUNTIME_DIR/.policy-review-attestation.$$"
(umask 077; printf '%s\n' \
  "{\"schemaVersion\":1,\"uiOrigin\":\"$REVIEW_ORIGIN\",\"graphOrigin\":\"$GRAPH_ORIGIN\"}" \
  >"$ATTESTATION_TEMP")
chmod 0600 -- "$ATTESTATION_TEMP"
mv -- "$ATTESTATION_TEMP" "$ATTESTATION_FILE"
trusted_private_file "$ATTESTATION_FILE" \
  || die 'could not persist the private managed graph attestation'

SERVICE_STATE_TEMP="$SESSION_DIR/.services.state.$$"
(umask 077; printf '%s\n' \
  "profile_id=$PROFILE_ID" \
  "profile_evidence_digest=$PROFILE_EVIDENCE_DIGEST" \
  "graph_digest=$GRAPH_DIGEST" \
  "network_id=$REVIEW_NETWORK_ID" \
  "ui_container_id=$UI_CONTAINER_ID" \
  "graph_container_id=$GRAPH_CONTAINER_ID" \
  "ui_host=$UI_HOST" \
  "graph_host=$GRAPH_HOST" \
  "graph_url=$GRAPH_URL" \
  "ui_image=$POLICY_REVIEW_UI_IMAGE_ID" \
  "tooling_image=$POLICY_TOOLING_IMAGE_ID" >"$SERVICE_STATE_TEMP")
chmod 0600 -- "$SERVICE_STATE_TEMP"
mv -- "$SERVICE_STATE_TEMP" "$SERVICE_STATE"
trusted_private_file "$SERVICE_STATE" \
  || die 'could not persist private review service identities'

ENCODED_GRAPH="$(encoded_graph_url "$GRAPH_URL")"
OPEN_URL="$REVIEW_UI_URL?graph=$ENCODED_GRAPH"
printf '\n%s\n' '== Policy Review ready ==' >&2
printf '%s\n' \
  "Private build profile: $PROFILE_DIR" \
  "Runtime review candidate: $RUNTIME_CANDIDATE" \
  "Guard eBPF target context: $TARGET_CONTEXT" \
  "Reviewed policy tooling image: $POLICY_TOOLING_IMAGE_ID" \
  "Reviewed Policy Review UI image: $POLICY_REVIEW_UI_IMAGE_ID" \
  "Frozen review bundle: $REVIEW_DIR" \
  "DecisionSet output: $DECISIONS_DIR/decisions.json" \
  "Managed review network: $REVIEW_NETWORK ($REVIEW_NETWORK_ID)" \
  "Policy Review UI container: $UI_CONTAINER ($UI_CONTAINER_ID)" \
  "Graph server container: $GRAPH_CONTAINER ($GRAPH_CONTAINER_ID)" \
  "Graph URL: $GRAPH_URL"
printf '\033]8;;%s\033\\Open Policy Review\033]8;;\033\\\n' "$OPEN_URL"
printf 'Policy Review: %s\n' "$OPEN_URL"

if command -v "$XDG_OPEN_BIN" >/dev/null 2>&1; then
  "$XDG_OPEN_BIN" "$OPEN_URL" >/dev/null 2>&1 || \
    printf 'profile-build-and-review: xdg-open could not launch the browser; use the Policy Review link above\n' >&2
else
  printf 'profile-build-and-review: xdg-open is unavailable; use the Policy Review link above\n' >&2
fi

printf '%s\n' \
  '' \
  'Review every proposal and coverage finding before exporting a complete DecisionSet JSON.' \
  'Opening an incomplete graph does not make it activation eligible. Stop these exact containers when review is finished with:'
print_command "$DOCKER_BIN" stop "$GRAPH_CONTAINER_ID"
print_command "$DOCKER_BIN" stop "$UI_CONTAINER_ID"
KEEP_REVIEW_CONTAINERS="true"
