#!/usr/bin/env bash
set -uo pipefail

# HOST POLICY: this wrapper must never execute npm, npx, or node on the host.
# Package-manager operations live only in scripts/release-audit-container.sh,
# whose runtime guard refuses to execute outside the locked-down audit image.

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

REPO_ROOT="$(resolve_script_dir)"
CALLER_CWD="$(pwd -P)"
AUDIT_IMAGE="notty-release-audit:node24.18.0"
AUDIT_IMAGE_ID=""
RUN_ID=""
RUN_TMP=""
DEPS_VOLUME=""
AUDIT_NETWORK=""
DEPS_VOLUME_CREATED=0
AUDIT_NETWORK_CREATED=0
CONTAINER_NAMES=()
PASS_COUNT=0
WARN_COUNT=0
FAIL_COUNT=0
PHASE_TIMEOUT_SECONDS=1800
REPORT_PATH="$REPO_ROOT/.release-audit/latest.md"
REPORT_TMP=""
REPORT_WRITTEN=0
REPORT_ERROR=""
REPORT_TARGET_VALID=0
FINALIZER_RUNNING=0
CLEANUP_ARMED=0
AUDIT_COMPLETE=0
AUDIT_SIGNAL=""
AUDIT_STARTED_AT=""
AUDIT_FINISHED_AT=""
AUDIT_OUTCOME="INCOMPLETE"
FINAL_EXIT_STATUS=1
REPOSITORY_COMMIT=""
REPOSITORY_BRANCH=""
REPOSITORY_EXACT_TAGS=""
REPOSITORY_PACKAGE_VERSION=""
REPOSITORY_RELEASE_CANDIDATE=""
REPOSITORY_WORKTREE_STATUS=""
REPOSITORY_CONTEXT_CAPTURED=0
SOURCE_ARCHIVE_SHA256=""
AUDIT_WRAPPER_SHA256=""
AUDIT_CONTAINER_HELPER_SHA256=""
AUDIT_DOCKERFILE_SHA256=""
PASS_MESSAGES=()
WARN_MESSAGES=()
FAIL_MESSAGES=()
GATE_ORDER=(
  host_prerequisites
  docker_daemon
  repository_whitespace
  repository_clean
  release_tag
  audit_image
  ephemeral_objects
  source_archive
  manifest_binding
  dependency_acquisition
  production_advisories
  offline_verification
  full_checkout_inventory
  input_stability
  cleanup
)
declare -A GATE_LABELS=(
  [host_prerequisites]='Required host tools'
  [docker_daemon]='Docker daemon availability'
  [repository_whitespace]='Git whitespace checks'
  [repository_clean]='Clean Git worktree'
  [release_tag]='RELEASE.md version and exact release tag'
  [audit_image]='Digest-pinned audit image'
  [ephemeral_objects]='Ephemeral audit volume and network'
  [source_archive]='Captured-commit source archive and SHA-256'
  [manifest_binding]='Networked phases bound to captured manifests'
  [dependency_acquisition]='Manifest-only dependency acquisition'
  [production_advisories]='Production dependency advisory audit'
  [offline_verification]='Offline metadata, release files, rebuild, tests, build, and package verification'
  [full_checkout_inventory]='Offline full-checkout package leak inventory'
  [input_stability]='Repository and audit inputs stable for the run'
  [cleanup]='Ephemeral audit object cleanup'
)
declare -A GATE_STATES=()
for gate_name in "${GATE_ORDER[@]}"; do
  GATE_STATES["$gate_name"]='NOT RUN'
done
unset gate_name

host_package_manager_forbidden() {
  printf 'release-audit: refusing to execute host %s; Docker is mandatory\n' \
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

run_bounded() {
  timeout \
    --signal=TERM \
    --kill-after=30s \
    "$PHASE_TIMEOUT_SECONDS" \
    "$@"
}

usage() {
  cat <<'EOF'
Usage: ./release-audit.sh [--report PATH]

Run the Notty release audit from the host. Docker is mandatory. This script
never runs npm, npx, or node on the host and has no host-package-manager
fallback. Every package-manager command runs as a non-root user in a dedicated
container. The wrapper also requires Git, Python 3 for strict JSON metadata
parsing, and standard GNU userland tools.

Network policy:
  - image/toolchain acquisition: Docker build network
  - dependency acquisition:     manifest-only networked container
  - dependency advisories:      manifest-only networked container
  - rebuild, tests, build, pack: --network none
  - full-checkout inventory:    --network none, ephemeral copy, no scripts

The networked phases use normal Docker bridge egress. They receive no source,
host home, npm configuration, agent credentials, environment secrets, or
Docker socket. Registry allowlisting is not yet implemented, so Docker lowers
the blast radius but is not a substitute for a disposable/rootless audit host.

This script covers automated repository, dependency, test, build, and package
gates. History secret scanning, legal/art provenance, production-image scans,
and live provider or Nosh Guard validation remain explicit manual gates. The
release-identity gate requires `package.json` to equal the release candidate
declared in the captured `RELEASE.md` and the captured commit to have that exact
tag, with an optional `v` prefix. The Node base is digest-pinned; Debian
audit-tool packages are resolved at build time until a snapshot-pinned
toolchain image is published. Each Docker build or run phase is limited to 30
minutes.

Every valid audit invocation atomically writes a private Markdown report to
`.release-audit/latest.md`. Use `--report PATH` (or `--report=PATH`) to retain
the report elsewhere. A report inside the checkout must stay below
`.release-audit`; an external absolute or relative path is also accepted.
Relative paths are resolved from the caller's current directory. The report
records automated evidence and outstanding manual gates; it never edits or
checks boxes in RELEASE.md.

Exit status: 0 means every automated gate passed, 1 means the release is not
ready or the audit was incomplete, and 2 means the command line is invalid.
EOF
}

pass() {
  PASS_COUNT=$((PASS_COUNT + 1))
  PASS_MESSAGES+=("$*")
  printf '[PASS] %s\n' "$*"
}

warn() {
  WARN_COUNT=$((WARN_COUNT + 1))
  WARN_MESSAGES+=("$*")
  printf '[WARN] %s\n' "$*" >&2
}

fail() {
  FAIL_COUNT=$((FAIL_COUNT + 1))
  FAIL_MESSAGES+=("$*")
  printf '[FAIL] %s\n' "$*" >&2
}

fatal() {
  fail "$*"
  exit 1
}

print_summary() {
  printf '\n=== Release audit summary ===\n'
  printf 'passes=%d warnings=%d failures=%d\n' \
    "$PASS_COUNT" "$WARN_COUNT" "$FAIL_COUNT"
  printf 'automated_result=%s\n' "$AUDIT_OUTCOME"
  printf 'exit_status=%d\n' "$FINAL_EXIT_STATUS"
  if (( REPORT_WRITTEN == 1 )); then
    printf 'report=%s\n' "$REPORT_PATH"
  else
    printf 'report=UNAVAILABLE\n'
  fi
  printf '%s\n' \
    'manual_required=history-secrets,legal-provenance,production-image,live-security-smokes'
}

set_report_path() {
  local requested="$1"

  if [[ -z "$requested" || "$requested" == *$'\n'* || "$requested" == *$'\r'* ]]; then
    return 1
  fi

  if [[ "$requested" == /* ]]; then
    REPORT_PATH="$requested"
  else
    REPORT_PATH="$CALLER_CWD/$requested"
  fi
}

set_gate_state() {
  local gate_name="$1"
  local gate_state="$2"

  if [[ -z "${GATE_STATES[$gate_name]+present}" ]]; then
    fail "internal error: unknown release audit gate: $gate_name"
    return 1
  fi
  case "$gate_state" in
    PASS|FAIL|WARN|SKIPPED|'NOT RUN')
      GATE_STATES["$gate_name"]="$gate_state"
      ;;
    *)
      fail "internal error: invalid state for $gate_name: $gate_state"
      return 1
      ;;
  esac
}

render_gate_matrix() {
  local gate_name
  local gate_state
  local checkbox

  for gate_name in "${GATE_ORDER[@]}"; do
    gate_state="${GATE_STATES[$gate_name]}"
    checkbox=' '
    if [[ "$gate_state" == PASS ]]; then
      checkbox=x
    fi
    printf -- '- [%s] `%s` - %s\n' \
      "$checkbox" "$gate_state" "${GATE_LABELS[$gate_name]}"
  done
}

capture_repository_context() {
  local commit
  local branch
  local exact_tags
  local package_version
  local release_candidate
  local status_output

  if (( REPOSITORY_CONTEXT_CAPTURED == 1 )); then
    return
  fi
  if command -v sha256sum >/dev/null 2>&1; then
    AUDIT_WRAPPER_SHA256="$(sha256sum "$REPO_ROOT/release-audit.sh" 2>/dev/null |
      awk '{ print $1 }')"
    AUDIT_CONTAINER_HELPER_SHA256="$(
      sha256sum "$REPO_ROOT/scripts/release-audit-container.sh" 2>/dev/null |
        awk '{ print $1 }'
    )"
    AUDIT_DOCKERFILE_SHA256="$(sha256sum "$REPO_ROOT/Dockerfile.release-audit" 2>/dev/null |
      awk '{ print $1 }')"
  fi
  if ! command -v git >/dev/null 2>&1 || [[ ! -d "$REPO_ROOT/.git" ]]; then
    return
  fi

  if ! commit="$(git -C "$REPO_ROOT" rev-parse HEAD 2>/dev/null)" ||
     [[ -z "$commit" ]]
  then
    return
  fi
  if ! branch="$(git -C "$REPO_ROOT" branch --show-current 2>/dev/null)"; then
    return
  fi
  if ! status_output="$(git -C "$REPO_ROOT" status \
    --porcelain=v1 \
    --untracked-files=all 2>/dev/null)"
  then
    return
  fi
  if ! exact_tags="$(git -C "$REPO_ROOT" tag \
    --list \
    --points-at="$commit" \
    --sort=refname 2>/dev/null)"
  then
    return
  fi
  if ! package_version="$(
    git -C "$REPO_ROOT" show "$commit:package.json" 2>/dev/null |
      python3 -I -c '
import json
import sys

version = json.load(sys.stdin).get("version")
if not isinstance(version, str) or not version:
    raise SystemExit(1)
sys.stdout.write(version)
' 2>/dev/null
  )"
  then
    package_version=""
  fi
  if ! release_candidate="$(
    git -C "$REPO_ROOT" show "$commit:RELEASE.md" 2>/dev/null |
      python3 -I -c '
import re
import sys

text = sys.stdin.read()
matches = re.findall(r"^\*\*Release candidate:\*\* `([^`\r\n]+)`[ \t]*$", text, re.MULTILINE)
if len(matches) != 1:
    raise SystemExit(1)
sys.stdout.write(matches[0])
' 2>/dev/null
  )"
  then
    release_candidate=""
  fi

  REPOSITORY_COMMIT="$commit"
  REPOSITORY_BRANCH="${branch:-(detached)}"
  REPOSITORY_EXACT_TAGS="$exact_tags"
  REPOSITORY_PACKAGE_VERSION="$package_version"
  REPOSITORY_RELEASE_CANDIDATE="$release_candidate"
  REPOSITORY_WORKTREE_STATUS="$status_output"
  REPOSITORY_CONTEXT_CAPTURED=1
}

report_code_span() {
  local value="$1"
  local fence='`'

  value="${value//$'\r'/\\r}"
  value="${value//$'\n'/\\n}"
  while [[ "$value" == *"$fence"* ]]; do
    fence+='`'
  done
  printf '%s %s %s' "$fence" "$value" "$fence"
}

report_message_list() {
  local marker="$1"
  shift
  local message

  if (( $# == 0 )); then
    printf '%s\n' '- None recorded.'
    return
  fi

  for message in "$@"; do
    message="${message//$'\n'/ }"
    message="${message//$'\r'/ }"
    printf -- '- [%s] %s\n' "$marker" "$(report_code_span "$message")"
  done
}

render_report() {
  printf '%s\n\n' '# Notty Release Audit Report'
  printf '%s\n' \
    "> Outcome: **$AUDIT_OUTCOME** (exit status \`$FINAL_EXIT_STATUS\`)" \
    ''
  printf '%s\n' \
    'This is generated evidence for automated gates. It does not modify' \
    '`RELEASE.md`, does not check its boxes, and does not certify the manual or' \
    'compound release requirements.' \
    ''

  printf '%s\n\n' '## Run identity'
  printf '%s\n' \
    "- Started (UTC): $(report_code_span "${AUDIT_STARTED_AT:-unavailable}")" \
    "- Finished (UTC): $(report_code_span "${AUDIT_FINISHED_AT:-unavailable}")" \
    "- Repository: $(report_code_span "$REPO_ROOT")" \
    "- Branch: $(report_code_span "${REPOSITORY_BRANCH:-unavailable}")" \
    "- Commit: $(report_code_span "${REPOSITORY_COMMIT:-unavailable}")" \
    "- Release candidate at captured commit: $(report_code_span "${REPOSITORY_RELEASE_CANDIDATE:-unavailable}")" \
    "- Package version at captured commit: $(report_code_span "${REPOSITORY_PACKAGE_VERSION:-unavailable}")" \
    "- Exact tags at captured commit: $(report_code_span "${REPOSITORY_EXACT_TAGS:-none}")" \
    "- Audit run ID: $(report_code_span "${RUN_ID:-unavailable}")" \
    "- Host wrapper SHA-256: $(report_code_span "${AUDIT_WRAPPER_SHA256:-unavailable}")" \
    "- Container helper SHA-256: $(report_code_span "${AUDIT_CONTAINER_HELPER_SHA256:-unavailable}")" \
    "- Audit Dockerfile SHA-256: $(report_code_span "${AUDIT_DOCKERFILE_SHA256:-unavailable}")" \
    "- Audit image ID: $(report_code_span "${AUDIT_IMAGE_ID:-unavailable}")" \
    "- Source archive SHA-256: $(report_code_span "${SOURCE_ARCHIVE_SHA256:-unavailable}")" \
    ''
  printf '%s\n' \
    'The audit wrapper comes from the current checkout, deterministic source' \
    'verification uses an archive of the captured commit, and the package-leak' \
    'inventory uses an ephemeral copy of the current checkout. A dirty' \
    'worktree therefore means the report does not certify uncommitted code.' \
    ''

  printf '%s\n\n' '## Repository worktree'
  if (( REPOSITORY_CONTEXT_CAPTURED == 0 )); then
    printf '%s\n\n' 'Unavailable because Git repository context could not be read.'
  elif [[ -z "$REPOSITORY_WORKTREE_STATUS" ]]; then
    printf '%s\n\n' 'Clean, including untracked files.'
  else
    local worktree_line
    printf '%s\n\n' 'Dirty:'
    while IFS= read -r worktree_line; do
      printf '    %s\n' "$worktree_line"
    done <<<"$REPOSITORY_WORKTREE_STATUS"
    printf '\n'
  fi

  printf '%s\n\n' '## Automated gates'
  render_gate_matrix
  printf '\n'
  printf '%s\n\n' '### Passed'
  if (( ${#PASS_MESSAGES[@]} == 0 )); then
    printf '%s\n' '- None recorded.'
  else
    report_message_list x "${PASS_MESSAGES[@]}"
  fi
  printf '\n%s\n\n' '### Failed or incomplete'
  if (( ${#FAIL_MESSAGES[@]} == 0 )); then
    printf '%s\n' '- None recorded.'
  else
    report_message_list ' ' "${FAIL_MESSAGES[@]}"
  fi
  printf '\n%s\n\n' '### Warnings'
  if (( ${#WARN_MESSAGES[@]} == 0 )); then
    printf '%s\n' '- None recorded.'
  else
    report_message_list ' ' "${WARN_MESSAGES[@]}"
  fi

  printf '\n%s\n\n' '## Manual gates (not evaluated)'
  printf '%s\n' \
    '- [ ] Scan the complete Git history for secrets.' \
    '- [ ] Complete legal, third-party, and artwork provenance review.' \
    '- [ ] Build, inspect, and scan the production image.' \
    '- [ ] Complete live provider, Nosh Guard, and release-candidate security smokes.'

  if [[ -n "$AUDIT_SIGNAL" ]]; then
    printf '\n%s\n' \
      "The audit was interrupted by $(report_code_span "$AUDIT_SIGNAL"); unrun gates remain incomplete."
  fi
}

validate_report_target() {
  local report_dir
  local report_name
  local canonical_dir
  local first_line=""
  local requested_in_repository=0
  local probe_requested="${1:-0}"
  local probe_path=""

  REPORT_ERROR=""
  report_dir="$(dirname -- "$REPORT_PATH")"
  report_name="$(basename -- "$REPORT_PATH")"

  if [[ "$REPORT_PATH" == "$REPO_ROOT/RELEASE.md" ]]; then
    REPORT_ERROR="refusing to use RELEASE.md as the generated report target"
    return 1
  fi
  case "$REPORT_PATH" in
    "$REPO_ROOT/.release-audit"/*)
      requested_in_repository=1
      ;;
    "$REPO_ROOT"/*)
      REPORT_ERROR="in-repository reports must stay under $REPO_ROOT/.release-audit"
      return 1
      ;;
  esac

  if (( requested_in_repository == 1 )) &&
     [[ -L "$REPO_ROOT/.release-audit" ]]
  then
    REPORT_ERROR="refusing symlink report directory: $REPO_ROOT/.release-audit"
    return 1
  fi

  if [[ -L "$report_dir" ]]; then
    REPORT_ERROR="refusing symlink report directory: $report_dir"
    return 1
  fi
  if ! command -v realpath >/dev/null 2>&1; then
    REPORT_ERROR="required host command unavailable: realpath"
    return 1
  fi
  canonical_dir="$(realpath -m -- "$report_dir" 2>/dev/null)" || {
    REPORT_ERROR="could not resolve report directory: $report_dir"
    return 1
  }
  report_dir="$canonical_dir"
  REPORT_PATH="$report_dir/$report_name"
  case "$REPORT_PATH" in
    "$REPO_ROOT/.release-audit"/*)
      ;;
    "$REPO_ROOT"/*)
      REPORT_ERROR="in-repository reports must stay under $REPO_ROOT/.release-audit"
      return 1
      ;;
    *)
      if (( requested_in_repository == 1 )); then
        REPORT_ERROR="in-repository report path resolved outside $REPO_ROOT/.release-audit"
        return 1
      fi
      ;;
  esac
  if ! mkdir -p -- "$report_dir"; then
    REPORT_ERROR="could not create report directory: $report_dir"
    return 1
  fi
  canonical_dir="$(cd -P -- "$report_dir" 2>/dev/null && pwd)" || {
    REPORT_ERROR="could not re-resolve report directory: $report_dir"
    return 1
  }
  report_dir="$canonical_dir"
  REPORT_PATH="$report_dir/$report_name"
  case "$REPORT_PATH" in
    "$REPO_ROOT/.release-audit"/*)
      ;;
    "$REPO_ROOT"/*)
      REPORT_ERROR="in-repository reports must stay under $REPO_ROOT/.release-audit"
      return 1
      ;;
    *)
      if (( requested_in_repository == 1 )); then
        REPORT_ERROR="in-repository report path resolved outside $REPO_ROOT/.release-audit"
        return 1
      fi
      ;;
  esac
  if [[ "$REPORT_PATH" == "$REPO_ROOT/.release-audit/"* ]]; then
    chmod 0700 "$REPO_ROOT/.release-audit" || {
      REPORT_ERROR="could not protect report directory: $REPO_ROOT/.release-audit"
      return 1
    }
  fi
  if [[ -L "$REPORT_PATH" ]]; then
    REPORT_ERROR="refusing symlink report target: $REPORT_PATH"
    return 1
  fi
  if [[ -e "$REPORT_PATH" && ! -f "$REPORT_PATH" ]]; then
    REPORT_ERROR="report target is not a regular file: $REPORT_PATH"
    return 1
  fi
  if [[ "$REPORT_PATH" == "$REPO_ROOT/RELEASE.md" ]]; then
    REPORT_ERROR="refusing to use RELEASE.md as the generated report target"
    return 1
  fi
  if [[ -f "$REPORT_PATH" ]]; then
    IFS= read -r first_line <"$REPORT_PATH" || true
    if [[ "$first_line" != '# Notty Release Audit Report' ]]; then
      REPORT_ERROR="refusing to replace a file that is not a Notty audit report: $REPORT_PATH"
      return 1
    fi
  fi

  if [[ "$probe_requested" == 1 ]]; then
    probe_path="$(mktemp "$report_dir/.${report_name}.probe.XXXXXXXX")" || {
      REPORT_ERROR="report directory is not writable: $report_dir"
      return 1
    }
    if ! chmod 0600 "$probe_path"; then
      rm -f -- "$probe_path"
      REPORT_ERROR="could not protect a report preflight file in $report_dir"
      return 1
    fi
    if ! rm -f -- "$probe_path"; then
      REPORT_ERROR="could not remove a report preflight file: $probe_path"
      return 1
    fi
  fi

  return 0
}

write_report() {
  local report_dir
  local report_name

  capture_repository_context
  validate_report_target || return 1
  report_dir="$(dirname -- "$REPORT_PATH")"
  report_name="$(basename -- "$REPORT_PATH")"

  REPORT_TMP="$(mktemp "$report_dir/.${report_name}.tmp.XXXXXXXX")" || {
    REPORT_ERROR="could not create an atomic report temporary file in $report_dir"
    return 1
  }
  chmod 0600 "$REPORT_TMP" || {
    REPORT_ERROR="could not protect report temporary file: $REPORT_TMP"
    rm -f -- "$REPORT_TMP"
    REPORT_TMP=""
    return 1
  }
  if ! render_report >"$REPORT_TMP"; then
    REPORT_ERROR="could not render report: $REPORT_PATH"
    rm -f -- "$REPORT_TMP"
    REPORT_TMP=""
    return 1
  fi
  if ! mv -T -- "$REPORT_TMP" "$REPORT_PATH"; then
    REPORT_ERROR="could not publish report atomically: $REPORT_PATH"
    rm -f -- "$REPORT_TMP"
    REPORT_TMP=""
    return 1
  fi
  REPORT_TMP=""
  REPORT_WRITTEN=1
  return 0
}

handle_signal() {
  AUDIT_SIGNAL="$1"
  fail "release audit interrupted by $1"
  exit "$2"
}

verify_audit_identity_unchanged() {
  local current_commit
  local current_branch
  local current_tags
  local current_status
  local current_wrapper_hash
  local current_helper_hash
  local current_dockerfile_hash
  local changed=0
  local hashes_available=1

  if (( REPOSITORY_CONTEXT_CAPTURED == 0 )); then
    set_gate_state input_stability SKIPPED
    return
  fi

  if ! current_commit="$(git -C "$REPO_ROOT" rev-parse HEAD 2>/dev/null)" ||
     [[ -z "$current_commit" ]]
  then
    fail 'could not re-read repository HEAD at the end of the audit'
    set_gate_state input_stability FAIL
    return
  fi
  if ! current_branch="$(git -C "$REPO_ROOT" branch --show-current 2>/dev/null)"; then
    fail 'could not re-read repository branch at the end of the audit'
    set_gate_state input_stability FAIL
    return
  fi
  current_branch="${current_branch:-(detached)}"
  if ! current_tags="$(git -C "$REPO_ROOT" tag \
    --list \
    --points-at="$current_commit" \
    --sort=refname 2>/dev/null)"
  then
    fail 'could not re-read exact tags at the end of the audit'
    set_gate_state input_stability FAIL
    return
  fi
  if ! current_status="$(git -C "$REPO_ROOT" status \
    --porcelain=v1 \
    --untracked-files=all 2>/dev/null)"
  then
    fail 'could not re-read repository worktree at the end of the audit'
    set_gate_state input_stability FAIL
    return
  fi

  if command -v sha256sum >/dev/null 2>&1; then
    current_wrapper_hash="$(sha256sum "$REPO_ROOT/release-audit.sh" 2>/dev/null |
      awk '{ print $1 }')"
    current_helper_hash="$(sha256sum \
      "$REPO_ROOT/scripts/release-audit-container.sh" 2>/dev/null |
      awk '{ print $1 }')"
    current_dockerfile_hash="$(sha256sum \
      "$REPO_ROOT/Dockerfile.release-audit" 2>/dev/null |
      awk '{ print $1 }')"
    if [[ -z "$AUDIT_WRAPPER_SHA256" ||
          -z "$AUDIT_CONTAINER_HELPER_SHA256" ||
          -z "$AUDIT_DOCKERFILE_SHA256" ||
          -z "$current_wrapper_hash" ||
          -z "$current_helper_hash" ||
          -z "$current_dockerfile_hash" ]]
    then
      hashes_available=0
    fi
  else
    hashes_available=0
  fi

  if [[ "$current_commit" != "$REPOSITORY_COMMIT" ]]; then
    fail 'repository HEAD changed during the audit'
    changed=1
  fi
  if [[ "$current_branch" != "$REPOSITORY_BRANCH" ]]; then
    fail 'repository branch changed during the audit'
    changed=1
  fi
  if [[ "$current_tags" != "$REPOSITORY_EXACT_TAGS" ]]; then
    fail 'repository exact-tag identity changed during the audit'
    changed=1
  fi
  if [[ "$current_status" != "$REPOSITORY_WORKTREE_STATUS" ]]; then
    fail 'repository worktree changed during the audit'
    changed=1
  fi
  if (( hashes_available == 1 )); then
    if [[ "$current_wrapper_hash" != "$AUDIT_WRAPPER_SHA256" ]]; then
      fail 'release-audit.sh changed during the audit'
      changed=1
    fi
    if [[ "$current_helper_hash" != "$AUDIT_CONTAINER_HELPER_SHA256" ]]; then
      fail 'release audit container helper changed during the audit'
      changed=1
    fi
    if [[ "$current_dockerfile_hash" != "$AUDIT_DOCKERFILE_SHA256" ]]; then
      fail 'release audit Dockerfile changed during the audit'
      changed=1
    fi
  fi

  if (( changed != 0 )); then
    set_gate_state input_stability FAIL
  elif (( hashes_available == 1 )); then
    set_gate_state input_stability PASS
    pass 'repository and audit inputs remained unchanged during the run'
  else
    set_gate_state input_stability FAIL
    fail 'audit input hash stability could not be fully verified'
  fi
}

finalize_audit() {
  local initial_status="$?"
  local cleanup_ok=1
  local all_gates_pass=1
  local gate_name

  trap ':' INT HUP TERM
  trap - EXIT
  if (( FINALIZER_RUNNING == 1 )); then
    exit "$initial_status"
  fi
  FINALIZER_RUNNING=1
  trap 'if [[ -n "${REPORT_TMP:-}" ]]; then rm -f -- "$REPORT_TMP"; fi' EXIT

  if (( CLEANUP_ARMED == 1 )); then
    if cleanup; then
      set_gate_state cleanup PASS
      pass 'ephemeral containers, volume, network, and host temp files cleaned up'
    else
      set_gate_state cleanup FAIL
      fail 'release audit cleanup was incomplete'
      cleanup_ok=0
    fi
    CLEANUP_ARMED=0
  fi

  verify_audit_identity_unchanged
  for gate_name in "${GATE_ORDER[@]}"; do
    if [[ "${GATE_STATES[$gate_name]}" != PASS ]]; then
      all_gates_pass=0
    fi
  done

  AUDIT_FINISHED_AT="$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
  FINAL_EXIT_STATUS="$initial_status"
  if [[ -n "$AUDIT_SIGNAL" ]]; then
    AUDIT_OUTCOME="INTERRUPTED"
  elif (( AUDIT_COMPLETE == 0 )); then
    AUDIT_OUTCOME="INCOMPLETE"
  elif (( FAIL_COUNT == 0 && cleanup_ok == 1 && initial_status == 0 &&
          all_gates_pass == 1 )); then
    AUDIT_OUTCOME="PASS"
  else
    AUDIT_OUTCOME="FAIL"
  fi

  if (( FAIL_COUNT != 0 || cleanup_ok == 0 )) && (( FINAL_EXIT_STATUS == 0 )); then
    FINAL_EXIT_STATUS=1
  fi
  if [[ "$AUDIT_OUTCOME" == "INCOMPLETE" ]] && (( FINAL_EXIT_STATUS == 0 )); then
    FINAL_EXIT_STATUS=1
  fi
  if [[ "$AUDIT_OUTCOME" == "FAIL" ]] && (( FINAL_EXIT_STATUS == 0 )); then
    FINAL_EXIT_STATUS=1
  fi
  if (( REPORT_TARGET_VALID == 1 )); then
    if ! write_report; then
      fail "release audit report was not written: ${REPORT_ERROR:-unknown error}"
      REPORT_WRITTEN=0
      FINAL_EXIT_STATUS=1
      if [[ "$AUDIT_OUTCOME" == "PASS" ]]; then
        AUDIT_OUTCOME="FAIL"
      fi
    fi
  fi

  print_summary
  exit "$FINAL_EXIT_STATUS"
}

require_host_command() {
  local command_name="$1"

  if command -v "$command_name" >/dev/null 2>&1; then
    pass "host command available: $command_name"
  else
    fail "required host command unavailable: $command_name"
  fi
}

docker_object_has_run_label() {
  local object_type="$1"
  local object_name="$2"
  local actual
  local format

  if [[ "$object_type" == "container" ]]; then
    format='{{ index .Config.Labels "io.notty.release-audit.run" }}'
  else
    format='{{ index .Labels "io.notty.release-audit.run" }}'
  fi

  actual="$(docker "$object_type" inspect \
    --format "$format" \
    "$object_name" 2>/dev/null || true)"
  [[ "$actual" == "$RUN_ID" ]]
}

cleanup() {
  local container_name
  local cleanup_failed=0

  if (( ${#CONTAINER_NAMES[@]} != 0 )); then
    for container_name in "${CONTAINER_NAMES[@]}"; do
      if docker_object_has_run_label container "$container_name"; then
        docker rm --force "$container_name" >/dev/null 2>&1 || cleanup_failed=1
      fi
    done
  fi

  if (( DEPS_VOLUME_CREATED == 1 )) &&
     docker_object_has_run_label volume "$DEPS_VOLUME"
  then
    docker volume rm "$DEPS_VOLUME" >/dev/null 2>&1 || cleanup_failed=1
  elif (( DEPS_VOLUME_CREATED == 1 )); then
    printf '[WARN] dependency volume was missing or had the wrong audit label: %s\n' \
      "$DEPS_VOLUME" >&2
    cleanup_failed=1
  fi

  if (( AUDIT_NETWORK_CREATED == 1 )) &&
     docker_object_has_run_label network "$AUDIT_NETWORK"
  then
    docker network rm "$AUDIT_NETWORK" >/dev/null 2>&1 || cleanup_failed=1
  elif (( AUDIT_NETWORK_CREATED == 1 )); then
    printf '[WARN] audit network was missing or had the wrong audit label: %s\n' \
      "$AUDIT_NETWORK" >&2
    cleanup_failed=1
  fi

  if [[ -n "$RUN_TMP" ]]; then
    case "$RUN_TMP" in
      "${TMPDIR:-/tmp}"/notty-release-audit.*)
        rm -rf -- "$RUN_TMP" || cleanup_failed=1
        ;;
      *)
        printf '[WARN] refusing to remove unexpected temp path: %s\n' \
          "$RUN_TMP" >&2
        cleanup_failed=1
        ;;
    esac
  fi

  return "$cleanup_failed"
}

make_run_id() {
  local random_hex

  random_hex="$(od -An -N12 -tx1 /dev/urandom | tr -d ' \n')"
  [[ "$random_hex" =~ ^[0-9a-f]{24}$ ]] || return 1
  printf '%s' "$random_hex"
}

common_container_args() {
  local container_name="$1"
  local network_name="$2"

  printf '%s\0' \
    --name "$container_name" \
    --label "io.notty.release-audit.run=$RUN_ID" \
    --rm \
    --init \
    --read-only \
    --user 1000:1000 \
    --cap-drop ALL \
    --security-opt=no-new-privileges=true \
    --pids-limit 512 \
    --cpus 2 \
    --memory 4g \
    --ulimit nofile=4096:4096 \
    --network "$network_name" \
    --tmpfs '/tmp:rw,nosuid,nodev,noexec,size=256m,mode=1777,uid=1000,gid=1000' \
    --tmpfs '/audit/runtime:rw,nosuid,nodev,noexec,size=4g,mode=0700,uid=1000,gid=1000' \
    --env CI=1 \
    --env NEXT_TELEMETRY_DISABLED=1 \
    --env HOME=/audit/runtime/home \
    --env XDG_CACHE_HOME=/audit/runtime/xdg-cache \
    --env XDG_CONFIG_HOME=/audit/runtime/xdg-config \
    --env NPM_CONFIG_CACHE=/audit/runtime/npm-cache \
    --env NPM_CONFIG_USERCONFIG=/dev/null \
    --env "RELEASE_AUDIT_NETWORK_MODE=$network_name"
}

run_container() {
  local label="$1"
  local container_name="$2"
  local network_name="$3"
  shift 3
  local common=()

  while IFS= read -r -d '' item; do
    common+=("$item")
  done < <(common_container_args "$container_name" "$network_name")

  printf '\n=== %s ===\n' "$label"
  if run_bounded docker run "${common[@]}" "$@"; then
    pass "$label"
    return 0
  fi

  fail "$label"
  return 1
}

build_audit_image() {
  local build_context="$RUN_TMP/image-context"

  mkdir -p "$build_context/scripts"
  cp "$REPO_ROOT/Dockerfile.release-audit" "$build_context/Dockerfile"
  cp \
    "$REPO_ROOT/scripts/release-audit-container.sh" \
    "$build_context/scripts/release-audit-container.sh"

  printf '\n=== Build digest-pinned Node-base audit image ===\n'
  if ! run_bounded docker build \
    --pull \
    --tag "$AUDIT_IMAGE" \
    "$build_context"
  then
    set_gate_state audit_image FAIL
    fatal 'could not build the pinned release audit image'
  fi

  if ! AUDIT_IMAGE_ID="$(docker image inspect --format '{{ .Id }}' "$AUDIT_IMAGE")"; then
    set_gate_state audit_image FAIL
    fatal 'could not inspect the release audit image'
  fi
  if [[ "$AUDIT_IMAGE_ID" != sha256:* ]]; then
    set_gate_state audit_image FAIL
    fatal "unexpected release audit image ID: $AUDIT_IMAGE_ID"
  fi
  printf 'audit_image=%s\naudit_image_id=%s\n' "$AUDIT_IMAGE" "$AUDIT_IMAGE_ID"
  set_gate_state audit_image PASS
  pass 'release audit image built from a digest-pinned Node base'
  warn 'Debian audit-tool packages are resolved at build time, not snapshot-pinned'
}

check_repository() {
  local exact_tag
  local tag_matches_candidate=0

  if [[ -z "$REPOSITORY_COMMIT" ]]; then
    set_gate_state repository_whitespace SKIPPED
    set_gate_state repository_clean SKIPPED
    set_gate_state release_tag SKIPPED
    fatal 'could not capture repository commit identity'
  fi
  printf '\n=== Repository state ===\n'
  printf 'repository=%s\n' "$REPO_ROOT"
  printf 'commit=%s\n' "$REPOSITORY_COMMIT"
  printf 'branch=%s\n' "$REPOSITORY_BRANCH"

  if git -C "$REPO_ROOT" diff --check HEAD -- &&
     git -C "$REPO_ROOT" diff --cached --check
  then
    set_gate_state repository_whitespace PASS
    pass 'Git whitespace checks'
  else
    set_gate_state repository_whitespace FAIL
    fail 'Git whitespace checks'
  fi

  if [[ -z "$REPOSITORY_WORKTREE_STATUS" ]]; then
    set_gate_state repository_clean PASS
    pass 'Git worktree is clean, including untracked files'
  else
    set_gate_state repository_clean FAIL
    fail 'Git worktree is not clean'
    printf '%s\n' "$REPOSITORY_WORKTREE_STATUS"
  fi

  if [[ -n "$REPOSITORY_RELEASE_CANDIDATE" &&
        "$REPOSITORY_PACKAGE_VERSION" == "$REPOSITORY_RELEASE_CANDIDATE" ]]
  then
    while IFS= read -r exact_tag; do
      if [[ "$exact_tag" == "$REPOSITORY_RELEASE_CANDIDATE" ||
            "$exact_tag" == "v$REPOSITORY_RELEASE_CANDIDATE" ]]
      then
        tag_matches_candidate=1
        break
      fi
    done <<<"$REPOSITORY_EXACT_TAGS"
  fi
  if [[ -z "$REPOSITORY_RELEASE_CANDIDATE" ]]; then
    set_gate_state release_tag FAIL
    fail 'could not capture the release candidate from RELEASE.md'
  elif [[ "$REPOSITORY_PACKAGE_VERSION" != "$REPOSITORY_RELEASE_CANDIDATE" ]]; then
    set_gate_state release_tag FAIL
    fail "captured package version ${REPOSITORY_PACKAGE_VERSION:-<unavailable>} does not match RELEASE.md candidate $REPOSITORY_RELEASE_CANDIDATE"
  elif (( tag_matches_candidate == 1 )); then
    set_gate_state release_tag PASS
    pass "captured commit has expected release tag: $exact_tag"
  else
    set_gate_state release_tag FAIL
    fail "captured commit lacks release tag $REPOSITORY_RELEASE_CANDIDATE or v$REPOSITORY_RELEASE_CANDIDATE"
  fi
}

create_audit_objects() {
  DEPS_VOLUME="notty-release-audit-deps-$RUN_ID"
  AUDIT_NETWORK="notty-release-audit-net-$RUN_ID"

  docker volume create \
    --label "io.notty.release-audit.run=$RUN_ID" \
    "$DEPS_VOLUME" >/dev/null || {
      set_gate_state ephemeral_objects FAIL
      fatal 'could not create the ephemeral dependency volume'
    }
  DEPS_VOLUME_CREATED=1
  docker network create \
    --driver bridge \
    --label "io.notty.release-audit.run=$RUN_ID" \
    "$AUDIT_NETWORK" >/dev/null || {
      set_gate_state ephemeral_objects FAIL
      fatal 'could not create the ephemeral audit network'
    }
  AUDIT_NETWORK_CREATED=1
  set_gate_state ephemeral_objects PASS
  pass 'ephemeral audit volume and network created'
}

run_audit_phases() {
  local manifest_root="$RUN_TMP/manifests"
  local package_json="$manifest_root/package.json"
  local package_lock="$manifest_root/package-lock.json"
  local source_archive="$RUN_TMP/source.tar"
  local source_archive_status
  local source_hash
  local acquire_name="notty-release-audit-acquire-$RUN_ID"
  local advisory_name="notty-release-audit-advisories-$RUN_ID"
  local verify_name="notty-release-audit-verify-$RUN_ID"
  local inventory_name="notty-release-audit-inventory-$RUN_ID"
  local acquire_ok=0
  local common=()

  CONTAINER_NAMES+=(
    "$acquire_name"
    "$advisory_name"
    "$verify_name"
    "$inventory_name"
  )

  if ! git -C "$REPO_ROOT" archive \
    --format=tar \
    --output="$source_archive" \
    "$REPOSITORY_COMMIT"
  then
    set_gate_state source_archive FAIL
    fatal 'could not create a clean Git source archive'
  fi
  if ! source_hash="$(sha256sum "$source_archive" | awk '{ print $1 }')" ||
     [[ ! "$source_hash" =~ ^[0-9a-f]{64}$ ]]
  then
    set_gate_state source_archive FAIL
    fatal 'could not hash the clean Git source archive'
  fi
  SOURCE_ARCHIVE_SHA256="$source_hash"
  printf 'source_archive_sha256=%s\n' "$SOURCE_ARCHIVE_SHA256"
  python3 - "$source_archive" <<'PY'
import sys
import tarfile
from pathlib import PurePosixPath

try:
    with tarfile.open(sys.argv[1], mode="r:") as source:
        for member in source:
            if "node_modules" in PurePosixPath(member.name).parts:
                raise SystemExit(3)
except (OSError, tarfile.TarError) as error:
    print(f"source archive inspection failed: {error}", file=sys.stderr)
    raise SystemExit(2)
PY
  source_archive_status=$?
  case "$source_archive_status" in
    0) ;;
    3)
      set_gate_state source_archive FAIL
      fatal 'captured commit contains a tracked node_modules path'
      ;;
    *)
      set_gate_state source_archive FAIL
      fatal 'could not inspect the captured-commit source archive'
      ;;
  esac
  set_gate_state source_archive PASS
  pass 'clean Git source archive created outside the checkout'

  if ! mkdir -p "$manifest_root"; then
    set_gate_state manifest_binding FAIL
    fatal 'could not create the manifest extraction directory'
  fi
  if ! tar \
    --extract \
    --file "$source_archive" \
    --directory "$manifest_root" \
    package.json \
    package-lock.json
  then
    set_gate_state manifest_binding FAIL
    fatal 'could not extract package manifests from the source archive'
  fi
  if ! chmod 0444 "$package_json" "$package_lock"; then
    set_gate_state manifest_binding FAIL
    fatal 'could not make the captured package manifests read-only'
  fi
  set_gate_state manifest_binding PASS
  pass 'networked phases are bound to manifests from the clean source archive'

  while IFS= read -r -d '' item; do
    common+=("$item")
  done < <(common_container_args "$acquire_name" "$AUDIT_NETWORK")

  printf '\n=== Manifest-only dependency acquisition ===\n'
  if run_bounded docker run \
    "${common[@]}" \
    --mount "type=bind,src=$package_json,dst=/input/package.json,readonly,bind-propagation=rprivate" \
    --mount "type=bind,src=$package_lock,dst=/input/package-lock.json,readonly,bind-propagation=rprivate" \
    --mount "type=volume,src=$DEPS_VOLUME,dst=/audit/volume" \
    "$AUDIT_IMAGE_ID" acquire
  then
    set_gate_state dependency_acquisition PASS
    pass 'manifest-only dependency acquisition'
    acquire_ok=1
  else
    set_gate_state dependency_acquisition FAIL
    fail 'manifest-only dependency acquisition'
  fi

  if run_container \
      'Manifest-only production advisory audit' \
      "$advisory_name" \
      "$AUDIT_NETWORK" \
      --mount "type=bind,src=$package_json,dst=/input/package.json,readonly,bind-propagation=rprivate" \
      --mount "type=bind,src=$package_lock,dst=/input/package-lock.json,readonly,bind-propagation=rprivate" \
      "$AUDIT_IMAGE_ID" advisories
  then
    set_gate_state production_advisories PASS
  else
    set_gate_state production_advisories FAIL
  fi

  if (( acquire_ok == 1 )); then
    common=()
    while IFS= read -r -d '' item; do
      common+=("$item")
    done < <(common_container_args "$verify_name" none)

    printf '\n=== Offline tests, build, and package artifact ===\n'
    if run_bounded docker run \
      --interactive \
      "${common[@]}" \
      --tmpfs '/audit/exec-tmp:rw,nosuid,nodev,exec,size=512m,mode=0700,uid=1000,gid=1000' \
      --env TMPDIR=/audit/exec-tmp \
      --mount "type=volume,src=$DEPS_VOLUME,dst=/audit/volume" \
      "$AUDIT_IMAGE_ID" verify <"$source_archive"
    then
      set_gate_state offline_verification PASS
      pass 'offline tests, build, and package artifact'
    else
      set_gate_state offline_verification FAIL
      fail 'offline tests, build, and package artifact'
    fi
  else
    set_gate_state offline_verification SKIPPED
    fail 'offline verification skipped because dependency acquisition failed'
  fi

  common=()
  while IFS= read -r -d '' item; do
    common+=("$item")
  done < <(common_container_args "$inventory_name" none)

  printf '\n=== Offline full-checkout package leak inventory ===\n'
  if tar \
    --create \
    --file - \
    --directory "$REPO_ROOT" \
    --exclude='./.git' \
    --exclude='*/.git' \
    --exclude='./node_modules' \
    --exclude='*/node_modules' \
    --exclude='./.next' \
    --exclude='*/.next' \
    --exclude='./.release-audit' \
    . |
    run_bounded docker run \
      --interactive \
      "${common[@]}" \
      "$AUDIT_IMAGE_ID" inventory
  then
    set_gate_state full_checkout_inventory PASS
    pass 'offline streamed full-checkout package leak inventory'
  else
    set_gate_state full_checkout_inventory FAIL
    fail 'offline streamed full-checkout package leak inventory'
  fi
}

main() {
  local command_name
  local host_failure_count

  while (( $# > 0 )); do
    case "$1" in
      -h|--help)
        usage
        return 0
        ;;
      --report)
        shift
        if (( $# == 0 )) || ! set_report_path "$1"; then
          printf 'release-audit: --report requires a non-empty path\n' >&2
          usage >&2
          return 2
        fi
        ;;
      --report=*)
        if ! set_report_path "${1#--report=}"; then
          printf 'release-audit: --report requires a non-empty path\n' >&2
          usage >&2
          return 2
        fi
        ;;
      *)
        usage >&2
        return 2
        ;;
    esac
    shift
  done

  AUDIT_STARTED_AT="$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
  trap finalize_audit EXIT
  trap 'handle_signal HUP 129' HUP
  trap 'handle_signal INT 130' INT
  trap 'handle_signal TERM 143' TERM

  printf '%s\n' \
    'HOST POLICY: npm, npx, and node are never executed on the host.' \
    'Docker is required; there is no host fallback.'

  host_failure_count="$FAIL_COUNT"
  for command_name in \
    awk basename chmod cp date dirname docker git mkdir mktemp mv od pwd readlink \
    python3 realpath rm sha256sum tar timeout tr
  do
    require_host_command "$command_name"
  done
  if (( FAIL_COUNT == host_failure_count )); then
    set_gate_state host_prerequisites PASS
  else
    set_gate_state host_prerequisites FAIL
  fi

  if ! validate_report_target 1; then
    fail "release audit report target rejected: ${REPORT_ERROR:-unknown error}"
    return 1
  fi
  REPORT_TARGET_VALID=1

  capture_repository_context
  if (( FAIL_COUNT != 0 )); then
    return 1
  fi

  [[ "$REPO_ROOT" != "/" ]] || fatal 'refusing to audit the filesystem root'
  [[ "$REPO_ROOT" != "${HOME:-}" ]] || fatal 'refusing to audit the host home directory'

  if ! docker info >/dev/null 2>&1; then
    set_gate_state docker_daemon FAIL
    fatal 'Docker daemon is unavailable; refusing to fall back to host npm'
  fi
  set_gate_state docker_daemon PASS
  pass 'Docker daemon is available'

  [[ -d "$REPO_ROOT/.git" ]] || fatal "not a Git checkout: $REPO_ROOT"
  [[ -f "$REPO_ROOT/package.json" ]] || fatal 'missing package.json'
  [[ -f "$REPO_ROOT/package-lock.json" ]] || fatal 'missing package-lock.json'

  RUN_ID="$(make_run_id)" || fatal 'could not create a random audit run ID'
  RUN_TMP="$(mktemp -d "${TMPDIR:-/tmp}/notty-release-audit.XXXXXXXX")" ||
    fatal 'could not create the audit temp directory'
  CLEANUP_ARMED=1
  chmod 0700 "$RUN_TMP" || fatal 'could not protect the audit temp directory'

  check_repository
  build_audit_image
  create_audit_objects
  run_audit_phases
  AUDIT_COMPLETE=1
  (( FAIL_COUNT == 0 ))
}

main "$@"
