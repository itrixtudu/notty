#!/usr/bin/env bash
set -euo pipefail

umask 077

die() {
  printf 'run-nosh-guard-host-bundle container: %s\n' "$*" >&2
  exit 2
}

[[ "${NOSH_GUARD_HOST_BUNDLE_CONTAINER:-}" == 1 ]] ||
  die 'refusing to run outside the dedicated bundle container'
[[ -f /.dockerenv ]] || die 'refusing to run outside Docker'
[[ "$(id -u)" != 0 ]] || die 'refusing to run as root'
effective_caps="$(awk '$1 == "CapEff:" { print $2 }' /proc/self/status)"
[[ "$effective_caps" == 0000000000000000 ]] ||
  die "effective Linux capabilities are not empty: ${effective_caps:-unavailable}"
[[ "${NOSH_GUARD_HOST_BUNDLE_NETWORK_MODE:-}" == none ]] ||
  die 'Docker --network none is required'
[[ "${TMPDIR:-}" == /bundle-work/tmp ]] ||
  die "unexpected executable scratch: ${TMPDIR:-<unset>}"
[[ "${HOME:-}" == /bundle-work/home ]] ||
  die "unexpected container HOME: ${HOME:-<unset>}"
[[ -d /input && ! -L /input ]] || die 'read-only checkout mount is unavailable'
[[ -d /output && ! -L /output ]] || die 'bundle output mount is unavailable'
[[ -r /sys/kernel/btf/vmlinux && -f /sys/kernel/btf/vmlinux ]] ||
  die 'read-only host kernel BTF mount is unavailable'
[[ ! -e /var/run/docker.sock ]] || die 'the Docker socket must not enter the container'
[[ -x /input/scripts/build-nosh-guard-host-bundle-container.sh ]] ||
  die 'container packager is missing from the checkout'

install -d -m 0700 "$TMPDIR" "$HOME"

exec /input/scripts/build-nosh-guard-host-bundle-container.sh "$@"
