#!/usr/bin/env bash
set -euo pipefail
component_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
test_dir="$(mktemp -d)"
trap 'rm -rf "$test_dir"' EXIT
"${CC:-cc}" -std=c17 -O2 -g -Wall -Wextra -Werror \
  -fsanitize=undefined '-D__noinline=__attribute__((noinline))' -I"$component_dir/include" \
  "$component_dir/tests/dns-stage.test.c" -o "$test_dir/dns-stage-test"
"$test_dir/dns-stage-test"
