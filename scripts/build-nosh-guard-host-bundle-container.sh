#!/usr/bin/env bash
set -euo pipefail

# CONTAINER POLICY: this packager is internal to the dedicated host-bundle
# image. The public host wrapper never executes Node, npm, npx, make, or clang.
# The guard host payload has no third-party JavaScript imports. This helper uses
# only the image's pinned Node runtime and reviewed BPF toolchain.

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

SCRIPT_DIR="$(resolve_script_dir)"
REPOSITORY_ROOT="$(cd "$SCRIPT_DIR/.." && pwd -P)"
OUTPUT_DIR="/output"
BUILD_LOADERS=1
NODE_REQUESTED="/usr/local/bin/node"
NODE_LICENSE_REQUESTED="/usr/local/LICENSE"
LOADER_BUILD_ROOT=""
STAGING_ROOT=""
ARCHIVE_TMP=""
CHECKSUM_TMP=""
RENDER_CHECK_ROOT=""
RESULT_REQUESTED="${NOSH_GUARD_HOST_BUNDLE_RESULT:-}"
RESULT_TMP=""

usage() {
  cat <<'EOF'
Usage: scripts/build-nosh-guard-host-bundle-container.sh [options]

Internal container-only packager for the checksummed, target-host Nosh Guard
installation archive. Use scripts/build-nosh-guard-host-bundle.sh on the host.

Options:
  --use-existing-loaders   package the existing bpf/*/build loader binaries
  -h, --help                show this help
EOF
}

die() {
  printf 'build-nosh-guard-host-bundle container: %s\n' "$*" >&2
  exit 2
}

assert_container_boundary() {
  local effective_caps=""
  local network_interface
  local status_key
  local status_value

  mount_has_option() {
    local mount_target="$1"
    local required_option="$2"

    awk -v target="$mount_target" -v required="$required_option" '
      $5 == target {
        count = split($6, options, ",")
        for (option_index = 1; option_index <= count; option_index += 1) {
          if (options[option_index] == required) found = 1
        }
      }
      END { exit(found ? 0 : 1) }
    ' /proc/self/mountinfo
  }

  [[ "${NOSH_GUARD_HOST_BUNDLE_CONTAINER:-}" == 1 ]] ||
    die 'refusing to package outside the dedicated container'
  [[ -f /.dockerenv ]] || die 'refusing to package outside Docker'
  [[ "$(id -u)" != 0 ]] || die 'refusing to package as root'
  while read -r status_key status_value _; do
    if [[ "$status_key" == CapEff: ]]; then
      effective_caps="$status_value"
      break
    fi
  done </proc/self/status
  [[ "$effective_caps" == 0000000000000000 ]] ||
    die "effective Linux capabilities are not empty: ${effective_caps:-unavailable}"
  [[ "${NOSH_GUARD_HOST_BUNDLE_NETWORK_MODE:-}" == none ]] ||
    die 'the packager requires Docker --network none'
  [[ "${TMPDIR:-}" == /bundle-work/tmp ]] ||
    die "unexpected executable scratch: ${TMPDIR:-<unset>}"
  [[ "$RESULT_REQUESTED" =~ ^/output/\.nosh-guard-host-bundle-result-[0-9]+-[0-9]+-[0-9]+-[0-9]+$ ]] ||
    die 'the bundle result receipt path is missing or unsafe'
  mount_has_option / ro || die 'the container root filesystem is not read-only'
  mount_has_option /input ro || die 'the checkout mount is not read-only'
  mount_has_option /output rw || die 'the output mount is not writable'
  mount_has_option /sys/kernel/btf/vmlinux ro ||
    die 'the host kernel BTF mount is not read-only'
  mount_has_option /bundle-work rw || die 'the scratch mount is not writable'
  for network_interface in /sys/class/net/*; do
    [[ "${network_interface##*/}" == lo ]] ||
      die "unexpected network interface in offline packager: ${network_interface##*/}"
  done
  [[ "$NODE_REQUESTED" == /usr/local/bin/node ]] ||
    die 'the packager Node path is not pinned'
  [[ "$NODE_LICENSE_REQUESTED" == /usr/local/LICENSE ]] ||
    die 'the packager Node license path is not pinned'
  [[ ! -e /var/run/docker.sock ]] ||
    die 'the Docker socket must not enter the packager'
}

assert_container_boundary

cleanup() {
  if [[ -n "$STAGING_ROOT" && -d "$STAGING_ROOT" ]]; then
    rm -rf -- "$STAGING_ROOT"
  fi
  [[ -z "$ARCHIVE_TMP" ]] || rm -f -- "$ARCHIVE_TMP"
  [[ -z "$CHECKSUM_TMP" ]] || rm -f -- "$CHECKSUM_TMP"
  [[ -z "$RESULT_TMP" ]] || rm -f -- "$RESULT_TMP"
  if [[ -n "$RENDER_CHECK_ROOT" && -d "$RENDER_CHECK_ROOT" ]]; then
    rm -rf -- "$RENDER_CHECK_ROOT"
  fi
}

trap cleanup EXIT

while (($#)); do
  case "$1" in
    --use-existing-loaders)
      BUILD_LOADERS=0
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      printf 'build-nosh-guard-host-bundle: unknown option: %s\n' "$1" >&2
      usage >&2
      exit 2
      ;;
  esac
done

for command_name in find install make mktemp readlink sha256sum sort stat tar uname; do
  command -v "$command_name" >/dev/null 2>&1 || {
    printf 'build-nosh-guard-host-bundle: required command is missing: %s\n' \
      "$command_name" >&2
    exit 1
  }
done

PACKAGE_VERSION="$({
  sed -nE 's/^[[:space:]]*"version":[[:space:]]*"([^"[:space:]]+)"[,]?[[:space:]]*$/\1/p' \
    "$REPOSITORY_ROOT/package.json"
} | head -n 1)"
if [[ ! "$PACKAGE_VERSION" =~ ^[0-9A-Za-z][0-9A-Za-z.+-]{0,63}$ ]]; then
  printf 'build-nosh-guard-host-bundle: package version is missing or unsafe\n' >&2
  exit 1
fi

ARCHITECTURE="$(uname -m)"
KERNEL_RELEASE="$(uname -r)"
for value in "$ARCHITECTURE" "$KERNEL_RELEASE"; do
  [[ "$value" =~ ^[0-9A-Za-z._+-]+$ ]] || {
    printf 'build-nosh-guard-host-bundle: unsafe host identity: %s\n' "$value" >&2
    exit 1
  }
done

[[ "$NODE_REQUESTED" == /* ]] || {
  printf 'build-nosh-guard-host-bundle: Node path must be absolute\n' >&2
  exit 1
}
NODE_BINARY="$(readlink -f "$NODE_REQUESTED")"
[[ -f "$NODE_BINARY" && ! -L "$NODE_BINARY" && -x "$NODE_BINARY" ]] || {
  printf 'build-nosh-guard-host-bundle: trusted runtime is missing: %s\n' \
    "$NODE_REQUESTED" >&2
  exit 1
}
NODE_METADATA="$(stat -Lc '%u %a' "$NODE_BINARY")"
NODE_MODE="${NODE_METADATA#* }"
if [[ "${NODE_METADATA%% *}" != 0 ]] || (( (8#$NODE_MODE & 8#22) != 0 )); then
  printf 'build-nosh-guard-host-bundle: pinned runtime is not root-owned and protected\n' >&2
  exit 1
fi
NODE_CURSOR="$(dirname "$NODE_BINARY")"
while :; do
  [[ -d "$NODE_CURSOR" && ! -L "$NODE_CURSOR" ]] || {
    printf 'build-nosh-guard-host-bundle: unsafe Node ancestor: %s\n' \
      "$NODE_CURSOR" >&2
    exit 1
  }
  NODE_METADATA="$(stat -Lc '%u %a' "$NODE_CURSOR")"
  NODE_MODE="${NODE_METADATA#* }"
  if [[ "${NODE_METADATA%% *}" != 0 ]] || (( (8#$NODE_MODE & 8#22) != 0 )); then
    printf 'build-nosh-guard-host-bundle: unsafe Node ancestor: %s\n' \
      "$NODE_CURSOR" >&2
    exit 1
  fi
  [[ "$NODE_CURSOR" == / ]] && break
  NODE_CURSOR="$(dirname "$NODE_CURSOR")"
done
NODE_VERSION="$($NODE_BINARY --version)"
[[ "$NODE_VERSION" == v24.18.0 ]] || {
  printf 'build-nosh-guard-host-bundle: expected Node v24.18.0, found %s\n' \
    "$NODE_VERSION" >&2
  exit 1
}
NODE_SHA256="$(sha256sum "$NODE_BINARY" | awk '{print $1}')"

[[ -f "$NODE_LICENSE_REQUESTED" && ! -L "$NODE_LICENSE_REQUESTED" ]] || {
  printf 'build-nosh-guard-host-bundle: pinned Node license is missing: %s\n' \
    "$NODE_LICENSE_REQUESTED" >&2
  exit 1
}

if ((BUILD_LOADERS == 1)); then
  for collector in nosh_build nosh_url nosh_l4 nosh_egress; do
    if find "$REPOSITORY_ROOT/bpf/$collector" -type l -print -quit | grep -q .; then
      printf 'build-nosh-guard-host-bundle: collector source contains a symlink: %s\n' \
        "$collector" >&2
      exit 1
    fi
  done
  make -C "$REPOSITORY_ROOT/bpf/nosh_build" test
  make -C "$REPOSITORY_ROOT/bpf/nosh_url" test
  make -C "$REPOSITORY_ROOT/bpf/nosh_l4" test
  make -C "$REPOSITORY_ROOT/bpf/nosh_egress" test
  LOADER_BUILD_ROOT="$TMPDIR/loader-source"
  install -d -m 0700 "$LOADER_BUILD_ROOT"
  cp -R "$REPOSITORY_ROOT/bpf/nosh_build" "$LOADER_BUILD_ROOT/nosh_build"
  cp -R "$REPOSITORY_ROOT/bpf/nosh_url" "$LOADER_BUILD_ROOT/nosh_url"
  cp -R "$REPOSITORY_ROOT/bpf/nosh_l4" "$LOADER_BUILD_ROOT/nosh_l4"
  cp -R "$REPOSITORY_ROOT/bpf/nosh_egress" "$LOADER_BUILD_ROOT/nosh_egress"
  make -C "$LOADER_BUILD_ROOT/nosh_build" clean
  make -C "$LOADER_BUILD_ROOT/nosh_url" clean
  make -C "$LOADER_BUILD_ROOT/nosh_l4" clean
  make -C "$LOADER_BUILD_ROOT/nosh_egress" clean
  make -C "$LOADER_BUILD_ROOT/nosh_build" CLANG=clang-14 loader
  make -C "$LOADER_BUILD_ROOT/nosh_url" CLANG=clang-14 loader
  make -C "$LOADER_BUILD_ROOT/nosh_l4" CLANG=clang-14 loader
  make -C "$LOADER_BUILD_ROOT/nosh_egress" CLANG=clang-14 loader
  BUILD_LOADER="$LOADER_BUILD_ROOT/nosh_build/build/nosh-build-loader"
  URL_LOADER="$LOADER_BUILD_ROOT/nosh_url/build/nosh-url-loader"
  L4_LOADER="$LOADER_BUILD_ROOT/nosh_l4/build/nosh-l4-loader"
  EGRESS_LOADER="$LOADER_BUILD_ROOT/nosh_egress/build/nosh-egress-loader"
  EGRESS_OBJECT="$LOADER_BUILD_ROOT/nosh_egress/build/nosh_egress.bpf.o"
else
  BUILD_LOADER="$REPOSITORY_ROOT/bpf/nosh_build/build/nosh-build-loader"
  URL_LOADER="$REPOSITORY_ROOT/bpf/nosh_url/build/nosh-url-loader"
  L4_LOADER="$REPOSITORY_ROOT/bpf/nosh_l4/build/nosh-l4-loader"
  EGRESS_LOADER="$REPOSITORY_ROOT/bpf/nosh_egress/build/nosh-egress-loader"
  EGRESS_OBJECT="$REPOSITORY_ROOT/bpf/nosh_egress/build/nosh_egress.bpf.o"
fi
for loader in "$BUILD_LOADER" "$URL_LOADER" "$L4_LOADER" "$EGRESS_LOADER"; do
  [[ -f "$loader" && ! -L "$loader" && -x "$loader" ]] || {
    printf 'build-nosh-guard-host-bundle: loader is missing or unsafe: %s\n' \
      "$loader" >&2
    exit 1
  }
done
[[ -f "$EGRESS_OBJECT" && ! -L "$EGRESS_OBJECT" ]] || {
  printf 'build-nosh-guard-host-bundle: egress object is missing or unsafe: %s\n' \
    "$EGRESS_OBJECT" >&2
  exit 1
}

OUTPUT_DIR="$(mkdir -p "$OUTPUT_DIR" && cd -P "$OUTPUT_DIR" && pwd)"
STAGING_ROOT="$(mktemp -d)"
BUNDLE_NAME="notty-nosh-guard-${PACKAGE_VERSION}-${ARCHITECTURE}-${KERNEL_RELEASE}"
BUNDLE_ROOT="$STAGING_ROOT/$BUNDLE_NAME"
PAYLOAD_ROOT="$BUNDLE_ROOT/payload"

install -d -m 0755 \
  "$PAYLOAD_ROOT/bin" \
  "$PAYLOAD_ROOT/config/nosh-build" \
  "$PAYLOAD_ROOT/config/nosh-gateway" \
  "$PAYLOAD_ROOT/config/nosh-guard" \
  "$PAYLOAD_ROOT/config/nosh-review" \
  "$PAYLOAD_ROOT/docs" \
  "$PAYLOAD_ROOT/lib" \
  "$PAYLOAD_ROOT/libexec/nosh-build" \
  "$PAYLOAD_ROOT/libexec/nosh-guard" \
  "$PAYLOAD_ROOT/runtime" \
  "$PAYLOAD_ROOT/scripts" \
  "$PAYLOAD_ROOT/templates/deploy/host" \
  "$PAYLOAD_ROOT/templates/deploy/systemd" \
  "$PAYLOAD_ROOT/templates/libexec/nosh-guard"

install -m 0755 "$NODE_BINARY" "$PAYLOAD_ROOT/runtime/node"
install -m 0644 "$NODE_LICENSE_REQUESTED" "$PAYLOAD_ROOT/docs/NODE_LICENSE"
[[ "$(sha256sum "$PAYLOAD_ROOT/runtime/node" | awk '{print $1}')" == "$NODE_SHA256" ]] || {
  printf 'build-nosh-guard-host-bundle: Node changed while it was copied\n' >&2
  exit 1
}
[[ "$("$PAYLOAD_ROOT/runtime/node" --version)" == "$NODE_VERSION" ]] || {
  printf '%s\n' \
    'build-nosh-guard-host-bundle: copied Node runtime is not relocatable' >&2
  exit 1
}

install -m 0644 "$REPOSITORY_ROOT/package.json" "$PAYLOAD_ROOT/package.json"
cp -R "$REPOSITORY_ROOT/lib/guard" "$PAYLOAD_ROOT/lib/guard"
cp -R "$REPOSITORY_ROOT/lib/guardd" "$PAYLOAD_ROOT/lib/guardd"
cp -R "$REPOSITORY_ROOT/config/nosh-guard/." "$PAYLOAD_ROOT/config/nosh-guard/"
cp -R "$REPOSITORY_ROOT/config/nosh-review/." "$PAYLOAD_ROOT/config/nosh-review/"
cp -R "$REPOSITORY_ROOT/config/nosh-gateway/." "$PAYLOAD_ROOT/config/nosh-gateway/"
install -m 0644 \
  "$REPOSITORY_ROOT/config/nosh-build/adapters.json" \
  "$PAYLOAD_ROOT/config/nosh-build/adapters.json"
install -m 0644 \
  "$REPOSITORY_ROOT/config/nosh-build/versions.json" \
  "$PAYLOAD_ROOT/config/nosh-build/versions.json"

for entrypoint in \
  nosh-gateway.mjs \
  nosh-guard.mjs \
  nosh-guard-fail-closed.mjs \
  nosh-guard-tetragon-verify.mjs \
  render-nosh-guard-install.mjs
do
  install -m 0644 \
    "$REPOSITORY_ROOT/scripts/$entrypoint" \
    "$PAYLOAD_ROOT/scripts/$entrypoint"
done
for capture_component in \
  nosh-mitmproxy-addon.py \
  nosh-mitmproxy-capture.sh
do
  install -m 0755 \
    "$REPOSITORY_ROOT/scripts/$capture_component" \
    "$PAYLOAD_ROOT/scripts/$capture_component"
done
install -m 0755 \
  "$REPOSITORY_ROOT/scripts/nosh-guard-doctor.sh" \
  "$PAYLOAD_ROOT/scripts/nosh-guard-doctor.sh"
install -m 0755 \
  "$REPOSITORY_ROOT/scripts/ensure-nosh-guard-bpffs.sh" \
  "$PAYLOAD_ROOT/libexec/nosh-guard/ensure-nosh-guard-bpffs"

for launcher in \
  nosh-gateway \
  nosh-guard \
  nosh-guardd \
  nosh-guard-fail-closed \
  nosh-guard-tetragon-verify
do
  install -m 0755 \
    "$REPOSITORY_ROOT/bin/$launcher" \
    "$PAYLOAD_ROOT/bin/$launcher"
  install -m 0755 \
    "$REPOSITORY_ROOT/deploy/host/$launcher" \
    "$PAYLOAD_ROOT/templates/deploy/host/$launcher"
done

install -m 0755 "$BUILD_LOADER" \
  "$PAYLOAD_ROOT/libexec/nosh-build/nosh-build-loader"
install -m 0755 "$URL_LOADER" \
  "$PAYLOAD_ROOT/libexec/nosh-build/nosh-url-loader"
install -m 0755 "$L4_LOADER" \
  "$PAYLOAD_ROOT/libexec/nosh-guard/nosh-l4-loader"
install -m 0755 "$EGRESS_LOADER" \
  "$PAYLOAD_ROOT/libexec/nosh-guard/nosh-egress-loader"
install -m 0644 "$EGRESS_OBJECT" \
  "$PAYLOAD_ROOT/libexec/nosh-guard/nosh_egress.bpf.o"
printf '%s  %s\n' "$(sha256sum "$EGRESS_OBJECT" | awk '{print $1}')" \
  'nosh_egress.bpf.o' \
  >"$PAYLOAD_ROOT/libexec/nosh-guard/nosh_egress.bpf.o.sha256"
chmod 0644 "$PAYLOAD_ROOT/libexec/nosh-guard/nosh_egress.bpf.o.sha256"
install -m 0755 \
  "$REPOSITORY_ROOT/scripts/verify-nosh-guard-host-install.sh" \
  "$PAYLOAD_ROOT/templates/libexec/nosh-guard/nosh-guard-host-verify"
install -m 0644 \
  "$REPOSITORY_ROOT/deploy/systemd/nosh-guard-bpffs.service" \
  "$PAYLOAD_ROOT/templates/deploy/systemd/nosh-guard-bpffs.service"
install -m 0644 \
  "$REPOSITORY_ROOT/deploy/systemd/nosh-guardd.service" \
  "$PAYLOAD_ROOT/templates/deploy/systemd/nosh-guardd.service"
install -m 0644 \
  "$REPOSITORY_ROOT/docs/nosh-gateway.md" \
  "$PAYLOAD_ROOT/docs/nosh-gateway.md"
install -m 0644 \
  "$REPOSITORY_ROOT/docs/nosh-guard.md" \
  "$PAYLOAD_ROOT/docs/nosh-guard.md"
install -m 0644 \
  "$REPOSITORY_ROOT/docs/nosh-build-profiling.md" \
  "$PAYLOAD_ROOT/docs/nosh-build-profiling.md"
install -m 0644 \
  "$REPOSITORY_ROOT/docs/nosh-policy-review.md" \
  "$PAYLOAD_ROOT/docs/nosh-policy-review.md"
install -m 0644 \
  "$REPOSITORY_ROOT/docs/nosh-http-capture-contract.md" \
  "$PAYLOAD_ROOT/docs/nosh-http-capture-contract.md"
install -m 0644 "$REPOSITORY_ROOT/LICENSE" "$PAYLOAD_ROOT/docs/LICENSE"
install -m 0644 \
  "$REPOSITORY_ROOT/THIRD_PARTY_NOTICES.md" \
  "$PAYLOAD_ROOT/docs/THIRD_PARTY_NOTICES.md"
install -m 0644 \
  "$REPOSITORY_ROOT/bpf/nosh_l4/LICENSES/0BSD.txt" \
  "$PAYLOAD_ROOT/docs/nosh-bpf-0BSD.txt"
install -m 0644 \
  "$REPOSITORY_ROOT/bpf/nosh_l4/LICENSES/GPL-2.0-only.txt" \
  "$PAYLOAD_ROOT/docs/nosh-bpf-GPL-2.0-only.txt"

# Refuse to publish a bundle whose prefix-neutral templates or structured JSON
# cannot produce the reviewed default deployment inventory.
RENDER_CHECK_ROOT="$(mktemp -d)"
"$PAYLOAD_ROOT/runtime/node" \
  "$PAYLOAD_ROOT/scripts/render-nosh-guard-install.mjs" \
  --prefix /usr/local \
  --source-root "$BUNDLE_ROOT" \
  --output-dir "$RENDER_CHECK_ROOT"
rm -rf -- "$RENDER_CHECK_ROOT"
RENDER_CHECK_ROOT=""

install -m 0755 \
  "$REPOSITORY_ROOT/scripts/install-nosh-guard-host-bundle.sh" \
  "$BUNDLE_ROOT/install.sh"

if find "$BUNDLE_ROOT" -type l -print -quit | grep -q .; then
  printf 'build-nosh-guard-host-bundle: bundle payload contains a symlink\n' >&2
  exit 1
fi

SOURCE_COMMIT="unavailable"
if command -v git >/dev/null 2>&1 &&
  git -C "$REPOSITORY_ROOT" rev-parse --verify HEAD >/dev/null 2>&1; then
  SOURCE_COMMIT="$(git -C "$REPOSITORY_ROOT" rev-parse --verify HEAD)"
fi
[[ "$SOURCE_COMMIT" == unavailable || "$SOURCE_COMMIT" =~ ^[0-9a-f]{40}$ ]] || {
  printf 'build-nosh-guard-host-bundle: source commit is unsafe: %s\n' \
    "$SOURCE_COMMIT" >&2
  exit 1
}
SOURCE_DATE_EPOCH="${SOURCE_DATE_EPOCH:-0}"
[[ "$SOURCE_DATE_EPOCH" =~ ^[0-9]+$ ]] || {
  printf 'build-nosh-guard-host-bundle: SOURCE_DATE_EPOCH must be an integer\n' >&2
  exit 1
}

printf '%s\n' \
  'BUNDLE_FORMAT=2' \
  "NOTTY_VERSION=$PACKAGE_VERSION" \
  "NODE_VERSION=$NODE_VERSION" \
  "NODE_SHA256=$NODE_SHA256" \
  "ARCHITECTURE=$ARCHITECTURE" \
  "BUILD_KERNEL_RELEASE=$KERNEL_RELEASE" \
  "SOURCE_COMMIT=$SOURCE_COMMIT" \
  >"$BUNDLE_ROOT/bundle.env"
chmod 0644 "$BUNDLE_ROOT/bundle.env"

(
  cd "$BUNDLE_ROOT"
  LC_ALL=C find . -type f ! -path ./manifest.sha256 -print0 |
    LC_ALL=C sort -z |
    xargs -0 sha256sum >manifest.sha256
  chmod 0644 manifest.sha256
)

ARCHIVE_PATH="$OUTPUT_DIR/$BUNDLE_NAME.tar.gz"
ARCHIVE_TMP="$(mktemp "$OUTPUT_DIR/.${BUNDLE_NAME}.tar.gz.XXXXXXXXXX")"
CHECKSUM_PATH="$ARCHIVE_PATH.sha256"
CHECKSUM_TMP="$(mktemp "$OUTPUT_DIR/.${BUNDLE_NAME}.tar.gz.sha256.XXXXXXXXXX")"

tar \
  --create \
  --gzip \
  --file "$ARCHIVE_TMP" \
  --directory "$STAGING_ROOT" \
  --sort=name \
  --mtime="@$SOURCE_DATE_EPOCH" \
  --owner=0 \
  --group=0 \
  --numeric-owner \
  "$BUNDLE_NAME"
chmod 0644 "$ARCHIVE_TMP"
printf '%s  %s\n' \
  "$(sha256sum "$ARCHIVE_TMP" | awk '{print $1}')" \
  "$(basename "$ARCHIVE_PATH")" \
  >"$CHECKSUM_TMP"
chmod 0644 "$CHECKSUM_TMP"
mv -f -- "$ARCHIVE_TMP" "$ARCHIVE_PATH"
ARCHIVE_TMP=""
mv -f -- "$CHECKSUM_TMP" "$CHECKSUM_PATH"
CHECKSUM_TMP=""

RESULT_TMP="$(mktemp "${RESULT_REQUESTED}.tmp.XXXXXXXXXX")"
printf 'ARCHIVE=%s\nCHECKSUM=%s\n' \
  "$(basename "$ARCHIVE_PATH")" \
  "$(basename "$CHECKSUM_PATH")" \
  >"$RESULT_TMP"
chmod 0600 "$RESULT_TMP"
mv -f -- "$RESULT_TMP" "$RESULT_REQUESTED"
RESULT_TMP=""

printf 'node:        bundled %s (%s)\n' "$NODE_VERSION" "$NODE_SHA256"
