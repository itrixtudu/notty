#!/usr/bin/env bash
set -euo pipefail

umask 077
die() { printf 'build-nosh-deb container: %s\n' "$*" >&2; exit 2; }
[[ ${NOSH_DEB_CONTAINER:-} == 1 && ${NOSH_DEB_NETWORK:-} == none ]] || die 'invalid container boundary'
[[ -f /.dockerenv && $(id -u) != 0 ]] || die 'must run non-root inside Docker'
[[ ! -e /var/run/docker.sock ]] || die 'Docker socket must not enter the packager'
[[ -d /input && -d /bundle && -d /output ]] || die 'required mounts are unavailable'
SOURCE_DATE_EPOCH=${SOURCE_DATE_EPOCH:-0}
[[ $SOURCE_DATE_EPOCH =~ ^[0-9]+$ ]] || die 'invalid SOURCE_DATE_EPOCH'
PUBLISH_ROOT="/output/.notty-nosh-deb-${BASHPID}-${RANDOM}"
install -d -m 0700 "$PUBLISH_ROOT"
cleanup() { rm -rf -- "$PUBLISH_ROOT"; }
trap cleanup EXIT

mapfile -t archives < <(find /bundle -maxdepth 1 -type f -name 'notty-nosh-guard-*.tar.gz' -print)
[[ ${#archives[@]} == 1 ]] || die 'expected one Guard bundle'
install -d -m 0700 /work/extracted
install -d -m 0755 /work/pkg /work/pkg/DEBIAN
for required_source in \
  scripts/nosh.sh \
  scripts/uninstall-nosh.sh \
  scripts/nosh-init.sh \
  scripts/nosh-init-tui.py \
  scripts/nosh_init_model.py \
  scripts/nosh_policy_manager.py \
  scripts/nosh_policy_ui.py \
  config/nosh-tui-requirements.txt \
  Dockerfile.nosh \
  package.json \
  package-lock.json
do
  git -C /input ls-files --error-unmatch -- "$required_source" >/dev/null 2>&1 \
    || die "required package source is not committed: $required_source"
done
tar -xzf "${archives[0]}" -C /work/extracted
mapfile -t bundle_roots < <(find /work/extracted -mindepth 1 -maxdepth 1 -type d -print)
[[ ${#bundle_roots[@]} == 1 ]] || die 'Guard bundle layout is ambiguous'
BUNDLE=${bundle_roots[0]}
# shellcheck disable=SC1090
source "$BUNDLE/bundle.env"
[[ ${NOTTY_VERSION:-} =~ ^[0-9A-Za-z][0-9A-Za-z.+-]{0,63}$ ]] || die 'invalid bundle version'
[[ ${ARCHITECTURE:-} == x86_64 ]] || die 'Guard bundle is not amd64'
[[ ${BUILD_KERNEL_RELEASE:-} =~ ^[0-9A-Za-z._+-]+$ ]] || die 'invalid build kernel'
KERNEL_VERSION=${BUILD_KERNEL_RELEASE//-/.}
KERNEL_VERSION=${KERNEL_VERSION//_/.}
DEB_VERSION="${NOTTY_VERSION}+ubuntu24.04.k${KERNEL_VERSION}"
RELEASE_ID="${NOTTY_VERSION}-x86_64-$(sha256sum "$BUNDLE/manifest.sha256" | awk '{print $1}')"
PKG=/work/pkg

install -d -m 0755 \
  "$PKG/opt/notty/lib/notty/nosh-guard/releases" "$PKG/opt/notty/bin" \
  "$PKG/opt/notty/libexec/nosh-build" "$PKG/opt/notty/libexec/nosh-guard" \
  "$PKG/opt/notty/share/doc/notty" "$PKG/usr/lib/notty/nosh" \
  "$PKG/usr/bin" "$PKG/usr/lib/systemd/system" "$PKG/etc"
install -d -m 0750 "$PKG/etc/nosh-guard"
cp -a "$BUNDLE" "$PKG/opt/notty/lib/notty/nosh-guard/releases/$RELEASE_ID"
ln -s "releases/$RELEASE_ID" "$PKG/opt/notty/lib/notty/nosh-guard/current"

RENDER=/work/rendered
install -d -m 0700 "$RENDER"
"$BUNDLE/payload/runtime/node" "$BUNDLE/payload/scripts/render-nosh-guard-install.mjs" \
  --prefix /opt/notty --source-root "$BUNDLE" --output-dir "$RENDER"
install -m 0755 "$RENDER"/deploy/host/* "$PKG/opt/notty/bin/"
install -m 0755 "$BUNDLE/payload/libexec/nosh-build/nosh-build-loader" "$PKG/opt/notty/libexec/nosh-build/"
install -m 0755 "$BUNDLE/payload/libexec/nosh-build/nosh-url-loader" "$PKG/opt/notty/libexec/nosh-build/"
install -m 0755 "$BUNDLE/payload/libexec/nosh-guard/nosh-l4-loader" "$PKG/opt/notty/libexec/nosh-guard/"
install -m 0755 "$BUNDLE/payload/libexec/nosh-guard/nosh-egress-loader" "$PKG/opt/notty/libexec/nosh-guard/"
install -m 0644 "$BUNDLE/payload/libexec/nosh-guard/nosh_egress.bpf.o"* "$PKG/opt/notty/libexec/nosh-guard/"
install -m 0755 "$BUNDLE/payload/libexec/nosh-guard/ensure-nosh-guard-bpffs" "$PKG/opt/notty/libexec/nosh-guard/"
install -m 0755 "$RENDER/libexec/nosh-guard/nosh-guard-host-verify" "$PKG/opt/notty/libexec/nosh-guard/"
install -m 0644 "$RENDER/deploy/systemd/"*.service "$PKG/usr/lib/systemd/system/"
sed -i 's/ --service$/ --systemd-unit-dir \/usr\/lib\/systemd\/system --service/' \
  "$PKG/usr/lib/systemd/system/nosh-guardd.service"
install -m 0640 "$RENDER/config/nosh-guard/adapters.json" "$PKG/etc/nosh-guard/adapters.json"
install -m 0640 "$RENDER/config/nosh-guard/versions.json" "$PKG/etc/nosh-guard/versions.json"
install -m 0640 "$RENDER/config/nosh-build/adapters.json" "$PKG/etc/nosh-guard/build-adapters.json"
install -m 0640 "$RENDER/config/nosh-build/versions.json" "$PKG/etc/nosh-guard/build-versions.json"
install -m 0640 "$BUNDLE/payload/config/nosh-guard/network-contract.example.json" "$PKG/etc/nosh-guard/network-contract.json"
install -m 0644 "$BUNDLE/payload/docs/"* "$PKG/opt/notty/share/doc/notty/"

# The CLI intentionally carries its tracked Docker build context. Using Git's
# inventory excludes untracked credentials, local state, and generated output.
git -C /input ls-files -z -- . ':(exclude,glob).nosh/**' ':(exclude,glob)**/.nosh/**' \
  | tar -C /input --null --files-from=- -cf - \
  | tar -C "$PKG/usr/lib/notty/nosh" -xf -
ln -s /usr/lib/notty/nosh/scripts/nosh.sh "$PKG/usr/bin/nosh"

MANIFEST_DIGEST=$(sha256sum "$BUNDLE/manifest.sha256" | awk '{print $1}')
cat >"$PKG/etc/nosh-guard-install-layout.conf" <<EOF
SCHEMA_VERSION=1
NOSH_GUARD_PREFIX=/opt/notty
MANIFEST_SHA256=$MANIFEST_DIGEST
EOF
chmod 0644 "$PKG/etc/nosh-guard-install-layout.conf"

cat >"$PKG/DEBIAN/control" <<EOF
Package: notty-nosh
Version: $DEB_VERSION
Section: admin
Priority: optional
Architecture: amd64
Maintainer: Notty maintainers
Depends: bash, coreutils, libc6, libbpf1, libelf1, python3, python3-venv, systemd, zlib1g, docker.io | docker-ce
Description: Nosh container launcher and kernel-qualified Nosh Guard
 Nosh manages project container workflows and reviewed network/tool policy.
 This build is qualified for Ubuntu 24.04 amd64 kernel $BUILD_KERNEL_RELEASE.
EOF
cat >"$PKG/DEBIAN/conffiles" <<'EOF'
/etc/nosh-guard/adapters.json
/etc/nosh-guard/build-adapters.json
/etc/nosh-guard/build-versions.json
/etc/nosh-guard/network-contract.json
/etc/nosh-guard/versions.json
EOF
chmod 0644 "$PKG/DEBIAN/control" "$PKG/DEBIAN/conffiles"
cat >"$PKG/DEBIAN/preinst" <<EOF
#!/bin/sh
set -eu
[ "\$(dpkg --print-architecture)" = amd64 ] || { echo 'notty-nosh: amd64 is required' >&2; exit 1; }
[ -r /etc/os-release ] && . /etc/os-release
[ "\${ID:-}" = ubuntu ] && [ "\${VERSION_ID:-}" = 24.04 ] || { echo 'notty-nosh: Ubuntu 24.04 is required' >&2; exit 1; }
[ "\$(uname -r)" = '$BUILD_KERNEL_RELEASE' ] || { echo 'notty-nosh: this package was built for kernel $BUILD_KERNEL_RELEASE; rebuild it for the running kernel' >&2; exit 1; }
[ -r /sys/kernel/btf/vmlinux ] || { echo 'notty-nosh: kernel BTF is required' >&2; exit 1; }
if [ -f /etc/nosh-guard-install-layout.conf ] && ! dpkg-query -W -f='\${Status}' notty-nosh 2>/dev/null | grep -q 'install ok installed'; then
  echo 'notty-nosh: a legacy Guard bundle is installed; uninstall it without purge before installing this package' >&2
  exit 1
fi
exit 0
EOF
cat >"$PKG/DEBIAN/postinst" <<'EOF'
#!/bin/sh
set -eu
install -d -o root -g root -m 0750 /etc/nosh-guard
install -d -o root -g root -m 0700 /var/lib/nosh-guard /run/nosh-guard
/opt/notty/libexec/nosh-guard/ensure-nosh-guard-bpffs
systemctl daemon-reload
systemctl enable --now nosh-guard-bpffs.service
systemctl enable --now nosh-guardd.service
/opt/notty/libexec/nosh-guard/nosh-guard-host-verify --prefix /opt/notty --systemd-unit-dir /usr/lib/systemd/system --service
exit 0
EOF
cat >"$PKG/DEBIAN/prerm" <<'EOF'
#!/bin/sh
set -eu
case "${1:-}" in
  upgrade) systemctl stop nosh-guardd.service >/dev/null 2>&1 || true ;;
  remove|deconfigure) systemctl disable --now nosh-guardd.service nosh-guard-bpffs.service >/dev/null 2>&1 || true ;;
esac
exit 0
EOF
cat >"$PKG/DEBIAN/postrm" <<'EOF'
#!/bin/sh
set -eu
systemctl daemon-reload >/dev/null 2>&1 || true
if [ "${1:-}" = purge ]; then
  rm -f -- /etc/nosh-guard-install-layout.conf
  rmdir /etc/nosh-guard 2>/dev/null || true
fi
exit 0
EOF
chmod 0755 "$PKG/DEBIAN/preinst" "$PKG/DEBIAN/postinst" "$PKG/DEBIAN/prerm" "$PKG/DEBIAN/postrm"

assert_mode() {
  local expected=$1 target=$2 actual
  actual=$(stat -Lc '%a' -- "$target")
  [[ $actual == "$expected" ]] \
    || die "package staging mode is $actual, expected $expected: ${target#"$PKG"/}"
}
assert_mode 755 "$PKG"
assert_mode 755 "$PKG/DEBIAN"
assert_mode 644 "$PKG/DEBIAN/control"
assert_mode 644 "$PKG/DEBIAN/conffiles"
for maintainer_script in preinst postinst prerm postrm; do
  assert_mode 755 "$PKG/DEBIAN/$maintainer_script"
done
assert_mode 755 "$PKG/opt"
assert_mode 755 "$PKG/usr"
assert_mode 755 "$PKG/etc"
assert_mode 750 "$PKG/etc/nosh-guard"

find "$PKG" -exec touch -h -d "@$SOURCE_DATE_EPOCH" {} +
ARTIFACT="notty-nosh_${DEB_VERSION}_amd64.deb"
dpkg-deb --root-owner-group --build "$PKG" "$PUBLISH_ROOT/$ARTIFACT"
chmod 0644 "$PUBLISH_ROOT/$ARTIFACT"
(cd "$PUBLISH_ROOT" && sha256sum "$ARTIFACT" >"$ARTIFACT.sha256")

python3 - "$PUBLISH_ROOT" "$ARTIFACT" "$DEB_VERSION" "$BUILD_KERNEL_RELEASE" "$SOURCE_COMMIT" "$SOURCE_DATE_EPOCH" <<'PY'
import datetime, hashlib, json, pathlib, sys
publish_root, artifact, version, kernel, commit, epoch = sys.argv[1:]
output = pathlib.Path(publish_root)
path = output / artifact
digest = hashlib.sha256(path.read_bytes()).hexdigest()
files = []
verification_hashes = []
relationships = []
for index, item in enumerate(sorted(p for p in pathlib.Path('/work/pkg').rglob('*') if p.is_file()), 1):
    file_digest = hashlib.sha256(item.read_bytes()).hexdigest()
    verification_hashes.append(file_digest)
    spdx_id = f'SPDXRef-File-{index}'
    files.append({'fileName': '/' + item.relative_to('/work/pkg').as_posix(),
                  'SPDXID': spdx_id,
                  'checksums': [{'algorithm': 'SHA256', 'checksumValue': file_digest}],
                  'licenseConcluded': 'NOASSERTION', 'copyrightText': 'NOASSERTION'})
    relationships.append({'spdxElementId': 'SPDXRef-Package',
                          'relationshipType': 'CONTAINS', 'relatedSpdxElement': spdx_id})
relationships.insert(0, {'spdxElementId': 'SPDXRef-DOCUMENT',
                         'relationshipType': 'DESCRIBES',
                         'relatedSpdxElement': 'SPDXRef-Package'})
created = datetime.datetime.fromtimestamp(int(epoch), datetime.timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')
spdx = {
    'spdxVersion': 'SPDX-2.3', 'dataLicense': 'CC0-1.0',
    'SPDXID': 'SPDXRef-DOCUMENT', 'name': artifact,
    'documentNamespace': f'https://notty.example/spdx/{digest}',
    'creationInfo': {'created': created, 'creators': ['Tool: nosh-deb-builder']},
    'packages': [{'name': 'notty-nosh', 'SPDXID': 'SPDXRef-Package',
                  'versionInfo': version, 'downloadLocation': 'NOASSERTION',
                  'filesAnalyzed': True,
                  'packageVerificationCode': {'packageVerificationCodeValue':
                      hashlib.sha1(''.join(sorted(verification_hashes)).encode()).hexdigest()},
                  'checksums': [{'algorithm': 'SHA256', 'checksumValue': digest}] }],
    'files': files, 'relationships': relationships,
}
(output / f'{artifact}.spdx.json').write_text(json.dumps(spdx, indent=2, sort_keys=True) + '\n')
manifest = {'schemaVersion': 1, 'artifact': artifact, 'sha256': digest,
            'version': version, 'architecture': 'amd64', 'ubuntuRelease': '24.04',
            'kernelRelease': kernel, 'sourceCommit': commit}
(output / f'{artifact}.manifest.json').write_text(json.dumps(manifest, indent=2, sort_keys=True) + '\n')
PY
chmod 0644 "$PUBLISH_ROOT/$ARTIFACT".*
dpkg-deb --info "$PUBLISH_ROOT/$ARTIFACT" >/dev/null
dpkg-deb --contents "$PUBLISH_ROOT/$ARTIFACT" >/dev/null
for completed in "$PUBLISH_ROOT/$ARTIFACT" "$PUBLISH_ROOT/$ARTIFACT.sha256" \
  "$PUBLISH_ROOT/$ARTIFACT.spdx.json" "$PUBLISH_ROOT/$ARTIFACT.manifest.json"; do
  mv -f -- "$completed" "/output/${completed##*/}"
done
