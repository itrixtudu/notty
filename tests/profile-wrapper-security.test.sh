#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -P "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd -P "$SCRIPT_DIR/.." && pwd)"
RUN_WRAPPER="$REPO_DIR/scripts/profile-build-and-run.sh"
REVIEW_WRAPPER="$REPO_DIR/scripts/profile-build-and-review.sh"
BUILD_WRAPPER="$REPO_DIR/scripts/build-nosh.sh"

fail() {
  printf 'profile-wrapper-security.test: %s\n' "$*" >&2
  exit 1
}

require_literal() {
  local selected="$1"
  local literal="$2"

  grep -Fq -- "$literal" "$selected" \
    || fail "missing required hardening in ${selected#$REPO_DIR/}: $literal"
}

reject_literal() {
  local selected="$1"
  local literal="$2"

  if grep -Fq -- "$literal" "$selected"; then
    fail "unsafe construct remains in ${selected#$REPO_DIR/}: $literal"
  fi
}

for selected in "$RUN_WRAPPER" "$REVIEW_WRAPPER"; do
  bash -n "$selected"
  require_literal "$selected" 'create_private_temp_directory() {'
  require_literal "$selected" 'for root in /tmp /var/tmp; do'
  require_literal "$selected" 'private_directory_identity "$selected"'
  require_literal "$selected" 'revalidate_private_directory'
  reject_literal "$selected" 'mktemp -d "${TMPDIR:-/tmp}'
done

bash -n "$BUILD_WRAPPER"

require_literal "$REVIEW_WRAPPER" 'io.notty.policy-review.managed=true'
require_literal "$REVIEW_WRAPPER" 'io.notty.policy-review.component=ui'
require_literal "$REVIEW_WRAPPER" 'io.notty.policy-review.component=graph'
require_literal "$REVIEW_WRAPPER" 'verify_owned_review_container() {'
require_literal "$REVIEW_WRAPPER" '"$DOCKER_BIN" stop --time 3 "$container_id"'
require_literal "$REVIEW_WRAPPER" '"$GRAPH_CONTAINER_ID" graph "$GRAPH_CONTAINER"'
require_literal "$REVIEW_WRAPPER" '"$UI_CONTAINER_ID" ui "$UI_CONTAINER"'
reject_literal "$REVIEW_WRAPPER" '"$DOCKER_BIN" stop --time 3 "$container"'
reject_literal "$REVIEW_WRAPPER" '"$DOCKER_BIN" stop --time 3 "$GRAPH_CONTAINER"'
reject_literal "$REVIEW_WRAPPER" '"$DOCKER_BIN" stop --time 3 "$UI_CONTAINER"'

printf '%s\n' 'profile-wrapper-security.test: passed'
