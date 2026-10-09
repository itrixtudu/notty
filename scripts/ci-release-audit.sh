#!/usr/bin/env bash
set -euo pipefail

# HOST POLICY: this CI wrapper delegates all npm, npx, and Node.js work to the
# Docker-only release audit. Only Bash, Python, Git, Docker, and GNU tools run
# on the ephemeral CI host.

umask 077

SCRIPT_DIR="$(cd -P "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd -P "$SCRIPT_DIR/.." && pwd)"
REPORT_PATH="$REPO_ROOT/.release-audit/ci-${GITHUB_RUN_ID:-local}-${GITHUB_RUN_ATTEMPT:-0}-$$.md"

host_package_manager_forbidden() {
  printf 'ci-release-audit: refusing to execute host %s\n' "$1" >&2
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

if [[ -e "$REPORT_PATH" || -L "$REPORT_PATH" ]]; then
  printf 'ci-release-audit: refusing pre-existing report path: %s\n' \
    "$REPORT_PATH" >&2
  exit 1
fi

audit_status=0
"$REPO_ROOT/scripts/release-audit.sh" --report "$REPORT_PATH" || audit_status=$?

if (( audit_status == 0 || audit_status == 1 )) &&
   [[ ! -f "$REPORT_PATH" || -L "$REPORT_PATH" ]]
then
  printf 'ci-release-audit: audit did not publish a fresh regular report: %s\n' \
    "$REPORT_PATH" >&2
  exit 1
fi

if (( audit_status == 0 )); then
  printf 'ci-release-audit: all automated release gates passed\n'
  exit 0
fi
if (( audit_status != 1 )); then
  printf 'ci-release-audit: release audit exited unexpectedly with status %d\n' \
    "$audit_status" >&2
  exit "$audit_status"
fi

exec python3 "$SCRIPT_DIR/check-pretag-audit-report.py" "$REPORT_PATH"
