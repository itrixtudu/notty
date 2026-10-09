const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');

const repository = path.resolve(__dirname, '..');
const read = (file) => fs.readFileSync(path.join(repository, file), 'utf8');

test('Debian package builder keeps compilation and packaging in Docker', () => {
  const host = read('scripts/build-nosh-deb.sh');
  const dockerfile = read('Dockerfile.nosh-deb');
  assert.match(host, /build-nosh-guard-host-bundle\.sh/);
  assert.match(host, /docker build/);
  assert.match(host, /docker run/);
  assert.match(host, /--network none/);
  assert.match(host, /--read-only/);
  assert.match(host, /--cap-drop ALL/);
  assert.doesNotMatch(host, /(^|\s)(npm|npx|node|dpkg-deb)\s/m);
  assert.match(dockerfile, /@sha256:[a-f0-9]{64}/);
  assert.match(dockerfile, /dpkg-dev/);
  assert.match(dockerfile, /\n\s+python3 \\/);
  assert.doesNotMatch(dockerfile, /python3-minimal/);
});

test('Debian lifecycle preserves state on remove and purges only explicitly', () => {
  const builder = read('scripts/build-nosh-deb-container.sh');
  assert.match(builder, /Package: notty-nosh/);
  assert.match(builder, /Version: \$DEB_VERSION/);
  assert.match(builder, /Architecture: amd64/);
  assert.match(builder, /\/usr\/lib\/notty\/nosh/);
  assert.match(builder, /\/usr\/lib\/systemd\/system/);
  assert.match(builder, /this package was built for kernel/);
  const postrm = builder.slice(builder.indexOf('cat >"$PKG/DEBIAN/postrm"'));
  assert.match(postrm, /if \[ "\$\{1:-\}" = purge \]/);
  assert.doesNotMatch(postrm, /rm -rf -- \/var\/lib\/nosh-guard/);
  assert.match(read('scripts/uninstall-nosh.sh'), /sudo rm -rf -- \/var\/lib\/nosh-guard/);
  assert.match(builder, /\.spdx\.json/);
  assert.match(builder, /\.manifest\.json/);
});

test('Debian staging assigns dpkg-compatible control and payload modes', () => {
  const builder = read('scripts/build-nosh-deb-container.sh');
  assert.match(builder, /install -d -m 0755 \/work\/pkg \/work\/pkg\/DEBIAN/);
  assert.match(builder, /install -d -m 0750 "\$PKG\/etc\/nosh-guard"/);
  assert.match(builder, /chmod 0644 "\$PKG\/DEBIAN\/control" "\$PKG\/DEBIAN\/conffiles"/);
  assert.match(builder, /chmod 0755 "\$PKG\/DEBIAN\/preinst"/);
  assert.match(builder, /assert_mode 755 "\$PKG\/DEBIAN"/);
  assert.match(builder, /assert_mode 644 "\$PKG\/DEBIAN\/control"/);
  assert.match(builder, /assert_mode 750 "\$PKG\/etc\/nosh-guard"/);
  assert.ok(
    builder.indexOf('assert_mode 755 "$PKG/DEBIAN"') < builder.indexOf('dpkg-deb --root-owner-group'),
    'permission assertions must run before dpkg-deb',
  );
});

test('CLI exposes safe uninstall and never makes yes imply purge', () => {
  const cli = read('scripts/nosh.sh');
  const uninstall = read('scripts/uninstall-nosh.sh');
  assert.match(cli, /exec bash "\$REPO_ROOT\/scripts\/uninstall-nosh\.sh"/);
  assert.match(uninstall, /--user-only/);
  assert.match(uninstall, /--purge-config/);
  assert.match(uninstall, /--purge-state/);
  assert.doesNotMatch(uninstall, /YES=true[^\n]*PURGE_(?:CONFIG|STATE)=true/);
  assert.match(uninstall, /foreign launcher/);
});
