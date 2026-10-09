#!/usr/bin/env bash
set -euo pipefail

# Host orchestration only. Package managers and application tests run in the
# guest's Docker containers; there is no host Node/npm fallback.
SCRIPT_DIR="$(cd -P "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
exec python3 -B "$SCRIPT_DIR/qemu/harness.py" "$@"
