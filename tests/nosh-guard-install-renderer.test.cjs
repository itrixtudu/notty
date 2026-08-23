const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawnSync } = require('node:child_process');
const test = require('node:test');

const repository = path.resolve(__dirname, '..');
const renderer = path.join(repository, 'scripts', 'render-nosh-guard-install.mjs');

const templateFiles = [
  ['deploy/host/nosh-gateway', 'deploy/host/nosh-gateway'],
  ['deploy/host/nosh-guard', 'deploy/host/nosh-guard'],
  ['deploy/host/nosh-guardd', 'deploy/host/nosh-guardd'],
  ['deploy/host/nosh-guard-fail-closed', 'deploy/host/nosh-guard-fail-closed'],
  [
    'deploy/host/nosh-guard-tetragon-verify',
    'deploy/host/nosh-guard-tetragon-verify',
  ],
  [
    'deploy/systemd/nosh-guard-bpffs.service',
    'deploy/systemd/nosh-guard-bpffs.service',
  ],
  ['deploy/systemd/nosh-guardd.service', 'deploy/systemd/nosh-guardd.service'],
  [
    'scripts/verify-nosh-guard-host-install.sh',
    'libexec/nosh-guard/nosh-guard-host-verify',
  ],
];

const configFiles = [
  'config/nosh-guard/adapters.json',
  'config/nosh-guard/versions.json',
  'config/nosh-build/adapters.json',
  'config/nosh-build/versions.json',
];

const expectedOutputs = [
  'config/nosh-build/adapters.json',
  'config/nosh-build/versions.json',
  'config/nosh-guard/adapters.json',
  'config/nosh-guard/versions.json',
  'deploy/host/nosh-gateway',
  'deploy/host/nosh-guard',
  'deploy/host/nosh-guard-fail-closed',
  'deploy/host/nosh-guard-tetragon-verify',
  'deploy/host/nosh-guardd',
  'deploy/systemd/nosh-guard-bpffs.service',
  'deploy/systemd/nosh-guardd.service',
  'libexec/nosh-guard/nosh-guard-host-verify',
  'sudoers/nosh-build-session.alias',
];

function makeRoot() {
  return fs.mkdtempSync(path.join(os.tmpdir(), 'nosh-guard-renderer-'));
}

function copyFile(source, destination) {
  fs.mkdirSync(path.dirname(destination), { recursive: true });
  fs.copyFileSync(source, destination);
}

function createReleaseFixture(root) {
  const release = path.join(root, 'release');
  for (const [sourceRelative, templateRelative] of templateFiles) {
    copyFile(
      path.join(repository, sourceRelative),
      path.join(release, 'payload', 'templates', templateRelative),
    );
  }
  for (const relative of configFiles) {
    copyFile(
      path.join(repository, relative),
      path.join(release, 'payload', relative),
    );
  }
  return release;
}

function listFiles(root) {
  function visit(directory, relative = '') {
    return fs.readdirSync(directory, { withFileTypes: true }).flatMap((entry) => {
      const childRelative = relative
        ? path.posix.join(relative, entry.name)
        : entry.name;
      if (entry.isDirectory()) {
        return visit(path.join(directory, entry.name), childRelative);
      }
      return [childRelative];
    });
  }
  return visit(root).sort();
}

function runRenderer(release, output, prefix = '/usr/local', extra = []) {
  return spawnSync(process.execPath, [
    renderer,
    '--prefix',
    prefix,
    '--source-root',
    release,
    '--output-dir',
    output,
    ...extra,
  ], {
    encoding: 'utf8',
  });
}

function readJson(root, relative) {
  return JSON.parse(fs.readFileSync(path.join(root, relative), 'utf8'));
}

function adapter(document, name) {
  return document.adapters.find((entry) => entry.name === name);
}

test('renderer emits the exact prefix-specific deployment inventory', (t) => {
  const root = makeRoot();
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const release = createReleaseFixture(root);
  const output = path.join(root, 'rendered');
  fs.mkdirSync(output);

  const result = runRenderer(release, output, '/opt/notty');
  assert.equal(result.status, 0, result.stderr);
  assert.deepEqual(listFiles(output), expectedOutputs);

  for (const relative of expectedOutputs) {
    const contents = fs.readFileSync(path.join(output, relative), 'utf8');
    assert.doesNotMatch(contents, /@@[^@\r\n]+@@/);
    assert.doesNotMatch(contents, /\/usr\/local\/lib\/notty\/nosh-guard/);
    assert.doesNotMatch(contents, /\/usr\/local\/libexec\/nosh-/);
    assert.doesNotMatch(contents, /\/usr\/local\/bin\/nosh-guard/);
  }

  const guardAdapters = readJson(output, 'config/nosh-guard/adapters.json');
  assert.equal(
    adapter(guardAdapters, 'nosh-l4').health.command,
    '/opt/notty/libexec/nosh-guard/nosh-l4-loader',
  );
  assert.equal(
    adapter(guardAdapters, 'nosh-egress').health.command,
    '/opt/notty/libexec/nosh-guard/nosh-egress-loader',
  );
  assert.equal(
    adapter(guardAdapters, 'nosh-egress').attach.command,
    '/opt/notty/libexec/nosh-guard/nosh-egress-loader',
  );
  assert.equal(
    adapter(guardAdapters, 'tetragon-enforce-policy').verify.command,
    '/opt/notty/bin/nosh-guard-tetragon-verify',
  );

  const buildAdapters = readJson(output, 'config/nosh-build/adapters.json');
  assert.equal(
    adapter(buildAdapters, 'nosh-build').attach.command,
    '/opt/notty/libexec/nosh-build/nosh-build-loader',
  );
  assert.equal(
    adapter(buildAdapters, 'nosh-l4').attach.command,
    '/opt/notty/libexec/nosh-guard/nosh-l4-loader',
  );
  assert.equal(
    adapter(buildAdapters, 'nosh-url').attach.command,
    '/opt/notty/libexec/nosh-build/nosh-url-loader',
  );
  assert.equal(adapter(buildAdapters, 'nosh-url').evidenceRequired, false);

  const buildVersions = readJson(output, 'config/nosh-build/versions.json');
  assert.equal(
    buildVersions.noshBuild.loaderPath,
    '/opt/notty/libexec/nosh-build/nosh-build-loader',
  );
  assert.equal(
    buildVersions.noshL4.loaderPath,
    '/opt/notty/libexec/nosh-guard/nosh-l4-loader',
  );
  assert.equal(
    buildVersions.noshUrl.loaderPath,
    '/opt/notty/libexec/nosh-build/nosh-url-loader',
  );
  assert.equal(buildVersions.noshUrl.optional, true);
  const guardVersions = readJson(output, 'config/nosh-guard/versions.json');
  assert.equal(
    guardVersions.noshEgress.loaderPath,
    '/opt/notty/libexec/nosh-guard/nosh-egress-loader',
  );

  assert.equal(
    fs.readFileSync(path.join(output, 'sudoers/nosh-build-session.alias'), 'utf8'),
    'Cmnd_Alias NOSH_BUILD_SESSION = /opt/notty/bin/nosh-guard build-session begin, /opt/notty/bin/nosh-guard build-session finish, /opt/notty/bin/nosh-guard build-session abort, /opt/notty/bin/nosh-guard build-session exported\n',
  );
  assert.equal(
    fs.statSync(path.join(output, 'deploy/host/nosh-guard')).mode & 0o777,
    0o755,
  );
  assert.equal(
    fs.statSync(path.join(output, 'deploy/systemd/nosh-guardd.service')).mode & 0o777,
    0o644,
  );
  assert.equal(
    fs.statSync(path.join(output, 'deploy/systemd/nosh-guard-bpffs.service')).mode & 0o777,
    0o644,
  );
});

test('renderer preserves the default /usr/local layout', (t) => {
  const root = makeRoot();
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const release = createReleaseFixture(root);
  const output = path.join(root, 'rendered');
  fs.mkdirSync(output);

  const result = runRenderer(release, output);
  assert.equal(result.status, 0, result.stderr);
  assert.match(
    fs.readFileSync(path.join(output, 'deploy/host/nosh-guard'), 'utf8'),
    /exec \/usr\/local\/lib\/notty\/nosh-guard\/current\/payload\/runtime\/node/,
  );
  assert.match(
    fs.readFileSync(path.join(output, 'deploy/host/nosh-guard'), 'utf8'),
    /\/usr\/local\/lib\/notty\/nosh-guard\/current\/payload\/bin\/nosh-guard/,
  );
  assert.match(
    fs.readFileSync(path.join(output, 'deploy/systemd/nosh-guardd.service'), 'utf8'),
    /ExecStart=\/usr\/local\/bin\/nosh-guardd/,
  );
  assert.match(
    fs.readFileSync(path.join(output, 'deploy/systemd/nosh-guard-bpffs.service'), 'utf8'),
    /ExecStart=\/usr\/local\/libexec\/nosh-guard\/ensure-nosh-guard-bpffs/,
  );
});

test('rendered launchers execute packaged entrypoints through the current symlink', (t) => {
  const root = makeRoot();
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const sourceRelease = createReleaseFixture(root);
  const prefix = path.join(root, 'installed');
  const renderedPrefix = '/opt/notty-symlink-launcher-test';
  const output = path.join(root, 'rendered');
  const installedRelease = path.join(
    prefix,
    'lib',
    'notty',
    'nosh-guard',
    'releases',
    'test-release',
  );
  const payload = path.join(installedRelease, 'payload');
  fs.mkdirSync(path.join(payload, 'runtime'), { recursive: true });
  fs.symlinkSync(process.execPath, path.join(payload, 'runtime', 'node'));
  for (const directory of ['bin', 'lib', 'scripts']) {
    fs.symlinkSync(
      path.join(repository, directory),
      path.join(payload, directory),
    );
  }
  fs.symlinkSync(
    'releases/test-release',
    path.join(prefix, 'lib', 'notty', 'nosh-guard', 'current'),
  );
  fs.mkdirSync(output);

  const rendered = runRenderer(sourceRelease, output, renderedPrefix);
  assert.equal(rendered.status, 0, rendered.stderr);
  fs.mkdirSync(path.join(prefix, 'bin'), { recursive: true });

  const safeHelpLaunchers = [
    ['nosh-gateway', 'Usage: nosh-gateway <verify|diff|apply|status> [options]'],
    ['nosh-guard', 'Usage: nosh-guard <command> [options]'],
    ['nosh-guardd', 'Usage: nosh-guard <command> [options]'],
    [
      'nosh-guard-tetragon-verify',
      'Usage: nosh-guard-tetragon-verify --policy-name NAME [options]',
    ],
  ];
  for (const [launcher, expectedFirstLine] of safeHelpLaunchers) {
    const destination = path.join(prefix, 'bin', launcher);
    fs.writeFileSync(
      destination,
      fs.readFileSync(
        path.join(output, 'deploy', 'host', launcher),
        'utf8',
      ).replaceAll(renderedPrefix, prefix),
    );
    fs.chmodSync(destination, 0o755);
    const result = spawnSync(destination, ['--help'], {
      encoding: 'utf8',
      timeout: 5_000,
    });
    assert.equal(
      result.status,
      0,
      `${launcher}: ${result.error || ''}\n${result.stdout}${result.stderr}`,
    );
    assert.equal(result.stdout.split(/\r?\n/, 1)[0], expectedFirstLine);
  }
});

test('renderer rejects unsafe and ambiguous prefixes', (t) => {
  const root = makeRoot();
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const release = createReleaseFixture(root);

  for (const prefix of [
    'usr/local',
    '/',
    '/usr',
    '/opt/',
    '/opt/../usr/local',
    '/opt/not ty',
    '/opt/$notty',
  ]) {
    const output = path.join(root, `rendered-${Math.random()}`);
    fs.mkdirSync(output);
    const result = runRenderer(release, output, prefix);
    assert.notEqual(result.status, 0, prefix);
    assert.match(result.stderr, /^render-nosh-guard-install:/);
    assert.deepEqual(fs.readdirSync(output), []);
  }
});

test('renderer rejects unexpected source inventory and nonempty output', (t) => {
  const root = makeRoot();
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const release = createReleaseFixture(root);
  const extra = path.join(release, 'payload', 'templates', 'unexpected');
  fs.writeFileSync(extra, 'unexpected\n');
  const output = path.join(root, 'rendered');
  fs.mkdirSync(output);

  let result = runRenderer(release, output);
  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /template root has an unexpected inventory/);

  fs.rmSync(extra);
  fs.writeFileSync(path.join(output, 'existing'), 'do not replace\n');
  result = runRenderer(release, output);
  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /output directory must be empty/);
});

test('renderer rejects unknown markers and JSON shape drift', (t) => {
  const root = makeRoot();
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const release = createReleaseFixture(root);
  const output = path.join(root, 'rendered');
  fs.mkdirSync(output);
  const launcher = path.join(
    release,
    'payload',
    'templates',
    'deploy',
    'host',
    'nosh-guard',
  );
  fs.appendFileSync(launcher, '@@UNEXPECTED@@\n');

  let result = runRenderer(release, output);
  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /template contains an unknown marker/);

  fs.copyFileSync(path.join(repository, 'deploy/host/nosh-guard'), launcher);
  const versionsPath = path.join(
    release,
    'payload',
    'config',
    'nosh-build',
    'versions.json',
  );
  const versions = JSON.parse(fs.readFileSync(versionsPath, 'utf8'));
  versions.unreviewed = true;
  fs.writeFileSync(versionsPath, `${JSON.stringify(versions, null, 2)}\n`);

  result = runRenderer(release, output);
  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /unexpected top-level fields/);
});
