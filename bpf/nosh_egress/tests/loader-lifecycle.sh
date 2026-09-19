#!/usr/bin/env bash
set -euo pipefail

COMPONENT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
LIFECYCLE_TEST_DIR=$(mktemp -d)
trap 'rm -rf -- "$LIFECYCLE_TEST_DIR"' EXIT
"${CC:-cc}" -std=c17 -O2 -g -Wall -Wextra -Werror -fsanitize=undefined \
  -I"$COMPONENT_DIR/tests/include" -I"$COMPONENT_DIR/include" \
  "$COMPONENT_DIR/tests/loader-lifecycle.test.c" \
  -o "$LIFECYCLE_TEST_DIR/loader-lifecycle.test" -lbpf -lelf -lz
"$LIFECYCLE_TEST_DIR/loader-lifecycle.test"
