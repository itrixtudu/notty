'use strict';

const assert = require('node:assert/strict');
const childProcess = require('node:child_process');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const test = require('node:test');

const appRoot = path.resolve(__dirname, '..');
const setupPath = path.join(appRoot, 'setup-nosh.sh');
const noshPath = path.join(appRoot, 'nosh.sh');
const checkoutGuardPath = path.join(appRoot, 'bin', 'nosh-guard');
const missingPrefix = `/opt/notty-setup-test-${process.pid}`;

function createFixture(t) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'notty-setup-'));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const home = path.join(root, 'home');
  const configHome = path.join(root, 'config');
  fs.mkdirSync(home, { recursive: true });
  return {
    root,
    home,
    configHome,
    configPath: path.join(configHome, 'nosh', 'paths.conf'),
    defaultBin: path.join(home, '.local', 'bin'),
  };
}

function cleanEnvironment(fixture, extra = {}) {
  const env = {
    PATH: '/usr/bin:/bin',
    HOME: fixture.home,
    XDG_CONFIG_HOME: fixture.configHome,
    ...extra,
  };
  delete env.SUDO_UID;
  delete env.SUDO_GID;
  delete env.SUDO_USER;
  return env;
}

function runSetup(fixture, args = [], env = {}) {
  return childProcess.spawnSync('bash', [setupPath, ...args], {
    cwd: appRoot,
    encoding: 'utf8',
    env: cleanEnvironment(fixture, env),
  });
}

function runNosh(fixture, args, env = {}) {
  return childProcess.spawnSync('bash', [noshPath, ...args], {
    cwd: appRoot,
    encoding: 'utf8',
    env: cleanEnvironment(fixture, env),
  });
}

function output(result) {
  return `${result.stdout || ''}${result.stderr || ''}`;
}

function expectedConfig(binDir, guardPrefix = missingPrefix) {
  return [
    'SCHEMA_VERSION=1',
    `BIN_DIR=${binDir}`,
    `NOSH_BIN=${noshPath}`,
    `NOSH_GUARD_BIN=${checkoutGuardPath}`,
    `NOSH_GUARD_PREFIX=${guardPrefix}`,
    `NOSH_GUARD_PRIVILEGED_BIN=${guardPrefix}/bin/nosh-guard`,
    '',
  ].join('\n');
}

function writeConfig(fixture, source, mode = 0o600) {
  fs.mkdirSync(path.dirname(fixture.configPath), { recursive: true });
  fs.writeFileSync(fixture.configPath, source, { mode });
  fs.chmodSync(fixture.configPath, mode);
}

test('setup creates absolute launchers and the strict user path configuration', (t) => {
  const fixture = createFixture(t);
  const result = runSetup(fixture, ['--guard-prefix', missingPrefix]);

  assert.equal(result.status, 0, output(result));
  assert.equal(fs.readlinkSync(path.join(fixture.defaultBin, 'nosh')), noshPath);
  assert.equal(
    fs.readlinkSync(path.join(fixture.defaultBin, 'nosh-guard')),
    checkoutGuardPath,
  );
  assert.equal(
    fs.readFileSync(fixture.configPath, 'utf8'),
    expectedConfig(fixture.defaultBin),
  );
  const configStat = fs.lstatSync(fixture.configPath);
  assert.equal(configStat.isFile(), true);
  assert.equal(configStat.isSymbolicLink(), false);
  assert.equal(configStat.nlink, 1);
  assert.equal(configStat.uid, process.getuid());
  assert.equal(configStat.mode & 0o777, 0o600);
  assert.match(result.stderr, /is not in PATH/);
  assert.match(
    result.stderr,
    /Review, build and verify unprivileged, then run only the installer with sudo/,
  );
  assert.match(result.stderr, /bundle build itself is unprivileged and containerized/);
  assert.match(result.stderr, /\(\n    set -euo pipefail/);
  assert.match(result.stderr, /work_dir="\$\(mktemp -d\)"/);
  assert.match(result.stderr, /trap 'rm -rf -- "\$work_dir"' EXIT/);
  assert.match(result.stderr, /--output-dir "\$artifact_dir"/);
  assert.match(result.stderr, /archives=\("\$artifact_dir"\/\*\.tar\.gz\)/);
  assert.match(result.stderr, /checksums=\("\$artifact_dir"\/\*\.tar\.gz\.sha256\)/);
  assert.match(result.stderr, /expected exactly one Nosh Guard archive and checksum/);
  assert.match(result.stderr, /"\$checksum" != "\$archive\.sha256"/);
  assert.match(result.stderr, /sha256sum --check --strict/);
  assert.match(result.stderr, /expected exactly one safe Nosh Guard installer/);
  const recipeMatch = result.stderr.match(/  \(\n[\s\S]*?\n  \)/);
  assert.ok(recipeMatch, 'setup must print a grouped Guard installation recipe');
  const recipe = recipeMatch[0].replace(/^  /gm, '');
  const recipeSyntax = childProcess.spawnSync('/bin/bash', ['-n'], {
    encoding: 'utf8',
    input: recipe,
  });
  assert.equal(recipeSyntax.status, 0, recipeSyntax.stderr);

  const continuedMarker = path.join(fixture.root, 'recipe-continued');
  const failingRecipe = recipe.replace(
    /^  .*\/build-nosh-guard-host-bundle\.sh --output-dir "\$artifact_dir"$/m,
    '  /bin/false\n  : > "$NOTTY_TEST_RECIPE_CONTINUED"',
  );
  assert.notEqual(failingRecipe, recipe, 'test must replace the bundle builder');
  const failedBuild = childProcess.spawnSync('/bin/bash', {
    encoding: 'utf8',
    env: cleanEnvironment(fixture, {
      NOTTY_TEST_RECIPE_CONTINUED: continuedMarker,
    }),
    input: failingRecipe,
  });
  assert.equal(failedBuild.status, 1, output(failedBuild));
  assert.equal(fs.existsSync(continuedMarker), false);
  assert.match(
    result.stderr,
    new RegExp(`install --prefix ${missingPrefix} --enable-now --deep-verify`),
  );
});

test('setup is idempotent and preserves already-correct objects', (t) => {
  const fixture = createFixture(t);
  const args = ['--guard-prefix', missingPrefix];
  const first = runSetup(fixture, args);
  assert.equal(first.status, 0, output(first));
  const before = {
    config: fs.lstatSync(fixture.configPath).ino,
    nosh: fs.lstatSync(path.join(fixture.defaultBin, 'nosh')).ino,
    guard: fs.lstatSync(path.join(fixture.defaultBin, 'nosh-guard')).ino,
  };

  const second = runSetup(fixture, args);
  assert.equal(second.status, 0, output(second));
  assert.deepEqual({
    config: fs.lstatSync(fixture.configPath).ino,
    nosh: fs.lstatSync(path.join(fixture.defaultBin, 'nosh')).ino,
    guard: fs.lstatSync(path.join(fixture.defaultBin, 'nosh-guard')).ino,
  }, before);
});

test('setup records approved Policy Review image IDs in a private config', (t) => {
  const fixture = createFixture(t);
  const tooling = `sha256:${'a'.repeat(64)}`;
  const ui = `sha256:${'b'.repeat(64)}`;
  const result = runSetup(fixture, [
    '--guard-prefix', missingPrefix,
    '--policy-tooling-image', tooling,
    '--policy-review-ui-image', ui,
  ]);

  assert.equal(result.status, 0, output(result));
  const imageConfig = path.join(fixture.configHome, 'nosh', 'policy-review-images.conf');
  assert.equal(
    fs.readFileSync(imageConfig, 'utf8'),
    [
      'SCHEMA_VERSION=1',
      `NOSH_POLICY_TOOLING_IMAGE=${tooling}`,
      `NOSH_POLICY_REVIEW_UI_IMAGE=${ui}`,
      '',
    ].join('\n'),
  );
  const stat = fs.lstatSync(imageConfig);
  assert.equal(stat.isSymbolicLink(), false);
  assert.equal(stat.nlink, 1);
  assert.equal(stat.mode & 0o777, 0o600);
  assert.match(result.stdout, /Recorded Policy Review image IDs/);
});

test('custom launcher directory and Guard prefix are recorded together', (t) => {
  const fixture = createFixture(t);
  const binDir = path.join(fixture.home, 'commands');
  const result = runSetup(fixture, [
    '--bin-dir',
    binDir,
    '--guard-prefix=/opt/notty',
  ]);

  assert.equal(result.status, 0, output(result));
  assert.equal(fs.readlinkSync(path.join(binDir, 'nosh')), noshPath);
  assert.equal(
    fs.readFileSync(fixture.configPath, 'utf8'),
    expectedConfig(binDir, '/opt/notty'),
  );
  assert.match(result.stderr, /install --prefix \/opt\/notty --enable-now/);
});

test('setup preflights both launcher collisions before writing configuration', (t) => {
  const fixture = createFixture(t);
  fs.mkdirSync(fixture.defaultBin, { recursive: true });
  const collision = path.join(fixture.defaultBin, 'nosh');
  fs.writeFileSync(collision, 'keep me\n');

  const result = runSetup(fixture, ['--guard-prefix', missingPrefix]);

  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /refusing to replace non-symlink launcher/);
  assert.equal(fs.readFileSync(collision, 'utf8'), 'keep me\n');
  assert.equal(fs.existsSync(path.join(fixture.defaultBin, 'nosh-guard')), false);
  assert.equal(fs.existsSync(fixture.configPath), false);
});

test('--replace-links replaces only conflicting symlinks', (t) => {
  const fixture = createFixture(t);
  fs.mkdirSync(fixture.defaultBin, { recursive: true });
  const noshLink = path.join(fixture.defaultBin, 'nosh');
  const guardLink = path.join(fixture.defaultBin, 'nosh-guard');
  fs.symlinkSync('/old/nosh', noshLink);
  fs.symlinkSync('/old/nosh-guard', guardLink);

  const refused = runSetup(fixture, ['--guard-prefix', missingPrefix]);
  assert.notEqual(refused.status, 0);
  assert.match(refused.stderr, /use --replace-links/);
  assert.equal(fs.readlinkSync(noshLink), '/old/nosh');
  assert.equal(fs.existsSync(fixture.configPath), false);

  const replaced = runSetup(fixture, [
    '--guard-prefix',
    missingPrefix,
    '--replace-links',
  ]);
  assert.equal(replaced.status, 0, output(replaced));
  assert.equal(fs.readlinkSync(noshLink), noshPath);
  assert.equal(fs.readlinkSync(guardLink), checkoutGuardPath);

  fs.unlinkSync(noshLink);
  fs.writeFileSync(noshLink, 'still keep me\n');
  const regular = runSetup(fixture, [
    '--guard-prefix',
    missingPrefix,
    '--replace-links',
  ]);
  assert.notEqual(regular.status, 0);
  assert.match(regular.stderr, /refusing to replace non-symlink launcher/);
  assert.equal(fs.readFileSync(noshLink, 'utf8'), 'still keep me\n');
});

test('setup rejects unsafe or malformed path configuration before link updates', (t) => {
  const cases = [
    {
      name: 'mode',
      source: expectedConfig('/tmp/bin'),
      mode: 0o644,
      expected: /mode 0600/,
    },
    {
      name: 'unknown key',
      source: `${expectedConfig('/tmp/bin')}UNKNOWN=value\n`,
      mode: 0o600,
      expected: /unknown path configuration key/,
    },
    {
      name: 'duplicate key',
      source: `${expectedConfig('/tmp/bin')}BIN_DIR=\/tmp\/again\n`,
      mode: 0o600,
      expected: /duplicate path configuration key/,
    },
  ];

  for (const scenario of cases) {
    const fixture = createFixture(t);
    writeConfig(fixture, scenario.source, scenario.mode);
    const result = runSetup(fixture, ['--guard-prefix', missingPrefix]);
    assert.notEqual(result.status, 0, `${scenario.name}: ${output(result)}`);
    assert.match(result.stderr, scenario.expected);
    assert.equal(fs.existsSync(fixture.defaultBin), false);
  }
});

test('--require-guard configures user paths and then fails when Guard is unavailable', (t) => {
  const fixture = createFixture(t);
  const result = runSetup(fixture, [
    '--guard-prefix',
    missingPrefix,
    '--require-guard',
  ]);

  assert.notEqual(result.status, 0);
  assert.equal(fs.readlinkSync(path.join(fixture.defaultBin, 'nosh')), noshPath);
  assert.equal(fs.existsSync(fixture.configPath), true);
  assert.match(result.stderr, /trusted privileged helper is missing/);
});

test('--check performs no writes and requires complete Guard readiness', (t) => {
  const fixture = createFixture(t);
  const absent = runSetup(fixture, [
    '--guard-prefix',
    missingPrefix,
    '--check',
  ]);
  assert.notEqual(absent.status, 0);
  assert.match(absent.stderr, /path configuration is missing/);
  assert.equal(fs.existsSync(fixture.defaultBin), false);
  assert.equal(fs.existsSync(fixture.configHome), false);

  const configured = runSetup(fixture, ['--guard-prefix', missingPrefix]);
  assert.equal(configured.status, 0, output(configured));
  const checked = runSetup(fixture, [
    '--guard-prefix',
    missingPrefix,
    '--check',
  ]);
  assert.notEqual(checked.status, 0);
  assert.match(checked.stderr, /trusted privileged helper is missing/);
});

test('setup distinguishes an unavailable Guard daemon from a missing installation', (t) => {
  const fixture = createFixture(t);
  const fakeBin = path.join(fixture.root, 'fake-bin');
  const configuredHelper = '/usr/local/bin/nosh-guard';
  fs.mkdirSync(fakeBin);
  fs.writeFileSync(path.join(fakeBin, 'realpath'), [
    '#!/bin/sh',
    'if [ "$#" -eq 3 ] && [ "$1" = "-e" ] && [ "$2" = "--" ] && [ "$3" = "$NOTTY_TEST_GUARD_HELPER" ]; then',
    '  printf \'%s\\n\' /usr/bin/true',
    '  exit 0',
    'fi',
    'exec /usr/bin/realpath "$@"',
    '',
  ].join('\n'), { mode: 0o755 });
  const env = {
    PATH: `${fakeBin}:/usr/bin:/bin`,
    NOTTY_TEST_GUARD_HELPER: configuredHelper,
  };

  const configured = runSetup(fixture, ['--guard-prefix', '/usr/local'], env);
  assert.equal(configured.status, 0, output(configured));

  const checked = runSetup(
    fixture,
    ['--guard-prefix', '/usr/local', '--check'],
    env,
  );
  assert.notEqual(checked.status, 0);
  assert.match(checked.stderr, /Guard daemon socket is unavailable/);
  assert.match(checked.stderr, /systemctl status nosh-guardd\.service/);
  assert.match(checked.stderr, /journalctl -u nosh-guardd\.service/);
  assert.match(checked.stderr, /systemctl restart nosh-guardd\.service/);
  assert.doesNotMatch(checked.stderr, /build-nosh-guard-host-bundle/);
  assert.doesNotMatch(checked.stderr, /Docker is required/);
});

test('setup refuses sudo invocation and does not mutate user paths', (t) => {
  const fixture = createFixture(t);
  const result = childProcess.spawnSync('bash', [
    setupPath,
    '--guard-prefix',
    missingPrefix,
  ], {
    cwd: appRoot,
    encoding: 'utf8',
    env: {
      ...cleanEnvironment(fixture),
      SUDO_UID: '1000',
      SUDO_GID: '1000',
      SUDO_USER: 'test-user',
    },
  });

  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /do not run .* through sudo/);
  assert.equal(fs.existsSync(fixture.defaultBin), false);
  assert.equal(fs.existsSync(fixture.configHome), false);
});

test('nosh resolves the ordinary Guard from user config before checkout and PATH', (t) => {
  const fixture = createFixture(t);
  const guard = path.join(fixture.root, 'configured-guard');
  fs.writeFileSync(guard, [
    '#!/usr/bin/env bash',
    'printf "configured:%s\\n" "$*"',
    '',
  ].join('\n'), { mode: 0o755 });
  writeConfig(fixture, [
    'SCHEMA_VERSION=1',
    `BIN_DIR=${fixture.defaultBin}`,
    `NOSH_BIN=${noshPath}`,
    `NOSH_GUARD_BIN=${guard}`,
    `NOSH_GUARD_PREFIX=${missingPrefix}`,
    `NOSH_GUARD_PRIVILEGED_BIN=${missingPrefix}/bin/nosh-guard`,
    '',
  ].join('\n'));

  const result = runNosh(fixture, ['build', 'status', appRoot]);

  assert.equal(result.status, 0, output(result));
  assert.match(result.stdout, /^configured:build status /);
});

test('NOSH_GUARD_BIN takes precedence without reading an invalid user config', (t) => {
  const fixture = createFixture(t);
  const guard = path.join(fixture.root, 'environment-guard');
  fs.writeFileSync(guard, [
    '#!/usr/bin/env bash',
    'printf "environment:%s\\n" "$*"',
    '',
  ].join('\n'), { mode: 0o755 });
  writeConfig(fixture, 'THIS_CONFIG_IS=invalid\n', 0o644);

  const result = runNosh(fixture, ['build', 'status', appRoot], {
    NOSH_GUARD_BIN: guard,
  });

  assert.equal(result.status, 0, output(result));
  assert.match(result.stdout, /^environment:build status /);
});

test('nosh rejects an unsafe user path configuration instead of sourcing it', (t) => {
  const fixture = createFixture(t);
  writeConfig(fixture, [
    'SCHEMA_VERSION=1',
    `BIN_DIR=${fixture.defaultBin}`,
    `NOSH_BIN=${noshPath}`,
    `NOSH_GUARD_BIN=${checkoutGuardPath}`,
    `NOSH_GUARD_PREFIX=${missingPrefix}`,
    `NOSH_GUARD_PRIVILEGED_BIN=${missingPrefix}/bin/nosh-guard`,
    'UNEXPECTED=$(touch /tmp/nosh-setup-must-not-run)',
    '',
  ].join('\n'));

  const result = runNosh(fixture, ['build', 'status', '--dry-run', appRoot]);

  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /unknown Nosh path configuration key/);
});
