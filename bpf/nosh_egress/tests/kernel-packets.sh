#!/usr/bin/env bash
set -euo pipefail

# Explicit opt-in kernel test, run only in the offline test container with
# CAP_BPF/CAP_PERFMON/CAP_NET_ADMIN. Builds against an already generated
# skeleton; never attaches, pins, or transmits packets.
if [[ ! -e /.dockerenv ]]; then
  printf 'kernel-packets.sh: run this test inside a container\n' >&2
  exit 1
fi

COMPONENT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
KERNEL_BUILD_DIR=${NOSH_EGRESS_KERNEL_BUILD_DIR:-"$COMPONENT_DIR/build"}
if [[ ! -f "$KERNEL_BUILD_DIR/nosh_egress.skel.h" ]]; then
  printf 'kernel-packets.sh: generate the BPF skeleton first\n' >&2
  exit 1
fi
KERNEL_TEST_DIR=$(mktemp -d)
trap 'rm -rf -- "$KERNEL_TEST_DIR"' EXIT
"${CC:-cc}" -std=c17 -O2 -g -Wall -Wextra -Werror \
  -I"$KERNEL_BUILD_DIR" -I"$COMPONENT_DIR/include" \
  "$COMPONENT_DIR/tests/kernel-packets.test.c" \
  -o "$KERNEL_TEST_DIR/kernel-packets.test" -lbpf -lelf -lz
"$KERNEL_TEST_DIR/kernel-packets.test"
