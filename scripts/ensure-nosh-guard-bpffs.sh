#!/usr/bin/env bash
set -euo pipefail

BPFFS_PATH=/sys/fs/bpf
BPFFS_MAGIC=cafe4a11
PIN_BASE="$BPFFS_PATH/nosh-guard"

[[ "$(id -u)" == 0 ]] || {
  printf 'ensure-nosh-guard-bpffs: root is required\n' >&2
  exit 1
}
[[ -d "$BPFFS_PATH" && ! -L "$BPFFS_PATH" ]] || {
  printf 'ensure-nosh-guard-bpffs: unsafe or missing path: %s\n' "$BPFFS_PATH" >&2
  exit 1
}

current_magic="$(stat -f -c '%t' "$BPFFS_PATH")"
if [[ "$current_magic" != "$BPFFS_MAGIC" ]]; then
  if mountpoint --quiet "$BPFFS_PATH"; then
    printf 'ensure-nosh-guard-bpffs: %s is mounted with filesystem magic %s, expected %s\n' \
      "$BPFFS_PATH" "$current_magic" "$BPFFS_MAGIC" >&2
    exit 1
  fi
  mount --types bpf --options nosuid,nodev,noexec bpf "$BPFFS_PATH"
fi
[[ "$(stat -f -c '%t' "$BPFFS_PATH")" == "$BPFFS_MAGIC" ]] || {
  printf 'ensure-nosh-guard-bpffs: bpffs mount attestation failed\n' >&2
  exit 1
}

# Create this on the host before systemd makes the bpffs parent read-only.
# The daemon receives a writable exception for this child only. Preserve
# existing pins and reject an unsafe pre-existing directory without repair.
if [[ ! -e "$PIN_BASE" && ! -L "$PIN_BASE" ]]; then
  mkdir --mode=0700 "$PIN_BASE"
fi
[[ -d "$PIN_BASE" && ! -L "$PIN_BASE" \
   && "$(stat -c '%u' "$PIN_BASE")" == 0 \
   && "$(stat -f -c '%t' "$PIN_BASE")" == "$BPFFS_MAGIC" ]] || {
  printf 'ensure-nosh-guard-bpffs: unsafe pin base: %s\n' "$PIN_BASE" >&2
  exit 1
}
pin_mode="$(stat -c '%a' "$PIN_BASE")"
(( (8#$pin_mode & 0022) == 0 )) || {
  printf 'ensure-nosh-guard-bpffs: pin base is group/other writable: %s\n' "$PIN_BASE" >&2
  exit 1
}
