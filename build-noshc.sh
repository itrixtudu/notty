#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -P "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TARGET="${TARGET:-cdev}" IMAGE_NAME="${IMAGE_NAME:-noshc}" \
  "$SCRIPT_DIR/build-nosh.sh" "$@"
