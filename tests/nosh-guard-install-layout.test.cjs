'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const test = require('node:test');
const { pathToFileURL } = require('node:url');

const appRoot = path.resolve(__dirname, '..');

async function layoutModule() {
  return import(pathToFileURL(path.join(
    appRoot,
    'lib/guardd/install-layout.js',
  )).href);
}

function temporaryDirectory(t) {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'nosh-install-layout-'));
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  return directory;
}

function userConfig(prefix, checkout = '/work/notty') {
  return [
    'SCHEMA_VERSION=1',
    'BIN_DIR=/home/test/.local/bin',
    `NOSH_BIN=${checkout}/nosh.sh`,
    `NOSH_GUARD_BIN=${checkout}/bin/nosh-guard`,
    `NOSH_GUARD_PREFIX=${prefix}`,
    `NOSH_GUARD_PRIVILEGED_BIN=${prefix}/bin/nosh-guard`,
    '',
  ].join('\n');
}

test('privileged Guard path follows exact, prefix, config, receipt, default precedence', async (t) => {
  const directory = temporaryDirectory(t);
  const configPath = path.join(directory, '.config/nosh/paths.conf');
  fs.mkdirSync(path.dirname(configPath), { recursive: true });
  fs.writeFileSync(configPath, userConfig('/opt/notty'), { mode: 0o600 });
  const { resolvePrivilegedGuardPath } = await layoutModule();

  assert.equal(resolvePrivilegedGuardPath({
    guardBin: '/custom/helper',
    env: { NOSH_GUARD_PRIVILEGED_BIN: '/ignored/helper' },
    home: directory,
  }), '/custom/helper');
  assert.equal(resolvePrivilegedGuardPath({
    env: { NOSH_GUARD_PRIVILEGED_BIN: '/safe/guard' },
    home: directory,
  }), '/safe/guard');
  assert.equal(resolvePrivilegedGuardPath({
    env: { NOSH_GUARD_PREFIX: '/opt/env-notty' },
    home: directory,
  }), '/opt/env-notty/bin/nosh-guard');
  assert.equal(resolvePrivilegedGuardPath({ env: {}, home: directory }),
    '/opt/notty/bin/nosh-guard');

  fs.rmSync(configPath);
  const receiptSource = [
    'SCHEMA_VERSION=1',
    'NOSH_GUARD_PREFIX=/opt/receipt-notty',
    `MANIFEST_SHA256=${'a'.repeat(64)}`,
    '',
  ].join('\n');
  const receiptFs = {
    lstatSync(filename) {
      if (filename !== '/receipt') {
        const error = new Error('missing');
        error.code = 'ENOENT';
        throw error;
      }
      return {
        isFile: () => true,
        isSymbolicLink: () => false,
        nlink: 1,
        uid: 0,
        mode: 0o100644,
      };
    },
    readFileSync(filename) {
      assert.equal(filename, '/receipt');
      return receiptSource;
    },
  };
  assert.equal(resolvePrivilegedGuardPath({
    env: {},
    home: directory,
    receiptPath: '/receipt',
    fsImpl: receiptFs,
  }), '/opt/receipt-notty/bin/nosh-guard');

  assert.equal(resolvePrivilegedGuardPath({
    env: {},
    home: path.join(directory, 'missing-home'),
    receiptPath: path.join(directory, 'missing-receipt'),
  }), '/usr/local/bin/nosh-guard');
});

test('user paths config is strict data with protected metadata', async (t) => {
  const directory = temporaryDirectory(t);
  const configPath = path.join(directory, 'paths.conf');
  const { readUserPathsConfig } = await layoutModule();
  fs.writeFileSync(configPath, userConfig('/opt/notty'), { mode: 0o600 });

  const parsed = readUserPathsConfig({
    userConfigPath: configPath,
    env: {},
  });
  assert.equal(parsed.NOSH_GUARD_PREFIX, '/opt/notty');

  fs.chmodSync(configPath, 0o644);
  assert.throws(() => readUserPathsConfig({
    userConfigPath: configPath,
    env: {},
  }), /mode 0600/);

  fs.chmodSync(configPath, 0o600);
  fs.appendFileSync(configPath, 'UNKNOWN=value\n');
  assert.throws(() => readUserPathsConfig({
    userConfigPath: configPath,
    env: {},
  }), /unknown key UNKNOWN/);
});

test('missing privileged helper fails with setup guidance before Docker preflight', async (t) => {
  const directory = temporaryDirectory(t);
  fs.writeFileSync(path.join(directory, 'Dockerfile'), 'FROM scratch\n', { mode: 0o600 });
  const { executeBuildProfile } = await import(pathToFileURL(path.join(
    appRoot,
    'lib/guardd/build-orchestrator.js',
  )).href);
  let dockerCalled = false;

  await assert.rejects(executeBuildProfile({
    context: directory,
    platform: 'linux/amd64',
    cacheMode: 'cold',
  }, {
    guardBin: path.join(directory, 'missing-nosh-guard'),
    dockerInfo() {
      dockerCalled = true;
      throw new Error('Docker preflight should not run');
    },
    reportProgress() {},
  }), /run the checkout's \.\/setup-nosh\.sh/);
  assert.equal(dockerCalled, false);
});

test('privileged helper trust rejects relative and user-controlled executables', async (t) => {
  const directory = temporaryDirectory(t);
  const userHelper = path.join(directory, 'nosh-guard');
  fs.writeFileSync(userHelper, '#!/bin/sh\nexit 0\n', { mode: 0o755 });
  const { buildOrchestratorInternals } = await import(pathToFileURL(path.join(
    appRoot,
    'lib/guardd/build-orchestrator.js',
  )).href);

  assert.throws(
    () => buildOrchestratorInternals.trustedPrivilegedHelper('nosh-guard'),
    /must be absolute/,
  );
  assert.throws(
    () => buildOrchestratorInternals.trustedPrivilegedHelper(userHelper),
    /root-owned, executable, non-writable file/,
  );
  assert.equal(
    buildOrchestratorInternals.trustedPrivilegedHelper('/usr/bin/true'),
    fs.realpathSync('/usr/bin/true'),
  );
});
