#!/usr/bin/env bash
set -euo pipefail

BPFFS_PATH=/sys/fs/bpf
BPFFS_MAGIC=cafe4a11

[[ "$(id -u)" == 0 ]] || {
  printf 'ensure-nosh-guard-bpffs: root is required\n' >&2
  exit 1
}
[[ -d "$BPFFS_PATH" && ! -L "$BPFFS_PATH" ]] || {
  printf 'ensure-nosh-guard-bpffs: unsafe or missing path: %s\n' "$BPFFS_PATH" >&2
  exit 1
}

current_magic="$(stat -f -c '%t' "$BPFFS_PATH")"
if [[ "$current_magic" == "$BPFFS_MAGIC" ]]; then
  exit 0
fi
if mountpoint --quiet "$BPFFS_PATH"; then
  printf 'ensure-nosh-guard-bpffs: %s is mounted with filesystem magic %s, expected %s\n' \
    "$BPFFS_PATH" "$current_magic" "$BPFFS_MAGIC" >&2
  exit 1
fi

mount --types bpf --options nosuid,nodev,noexec bpf "$BPFFS_PATH"
[[ "$(stat -f -c '%t' "$BPFFS_PATH")" == "$BPFFS_MAGIC" ]] || {
  printf 'ensure-nosh-guard-bpffs: bpffs mount attestation failed\n' >&2
  exit 1
}
