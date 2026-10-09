'use strict';

const assert = require('node:assert/strict');
const childProcess = require('node:child_process');
const crypto = require('node:crypto');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const test = require('node:test');

const appRoot = path.resolve(__dirname, '..');
const noshPath = path.join(appRoot, 'scripts/nosh.sh');

function createFixture(t) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'notty-nosh-auth-'));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const home = path.join(root, 'home');
  const workspace = path.join(root, 'workspace');
  const stateHome = path.join(root, 'state');
  fs.mkdirSync(home, { mode: 0o700 });
  fs.mkdirSync(workspace, { mode: 0o700 });
  return { root, home, workspace, stateHome };
}

function runNosh(fixture, args = [], options = {}) {
  const result = childProcess.spawnSync('bash', [
    noshPath,
    ...(options.command || ['start']),
    ...(options.dryRun === false ? [] : ['--dry-run']),
    '--no-start-app',
    '--workdir', fixture.workspace,
    ...args,
  ], {
    cwd: fixture.workspace,
    encoding: 'utf8',
    env: {
      PATH: options.path || process.env.PATH,
      HOME: fixture.home,
      XDG_CONFIG_HOME: path.join(fixture.home, '.config'),
      XDG_STATE_HOME: fixture.stateHome,
      ...(options.env || {}),
    },
  });
  const output = `${result.stdout || ''}${result.stderr || ''}`;
  const dockerRun = String(result.stdout || '')
    .split(/\r?\n/)
    .find((line) => line.startsWith('docker run ')) || '';
  return { ...result, output, dockerRun };
}

function assignment(command, key) {
  const match = command.match(new RegExp(`(?:^| )${key}=([^ ]+)`));
  return match?.[1] || '';
}

test('Nosh emits the complete default and explicit authentication mode matrix', (t) => {
  const fixture = createFixture(t);
  const cases = [
    {
      args: ['--otp', 'default-otp'],
      expected: ['true', 'true', 'true', 'false'],
    },
    {
      args: ['--noauth', '--otp', 'noauth-otp'],
      expected: ['false', 'true', 'true', 'false'],
    },
    {
      args: ['--no-oauth', '--otp', 'no-oauth-otp'],
      expected: ['true', 'false', 'true', 'false'],
    },
    {
      args: ['--no-otp-auth', '--otp', 'otp-only-value'],
      expected: ['false', 'false', 'true', 'true'],
    },
    {
      args: ['--noauth', '--no-oauth', '--otp', 'equivalent-otp-only'],
      expected: ['false', 'false', 'true', 'true'],
    },
    {
      args: ['--no-otp'],
      expected: ['true', 'true', 'false', 'false'],
    },
    {
      args: [],
      env: { NOTTY_BASIC_AUTH_ENABLED: 'false' },
      expected: ['false', 'true', 'true', 'false'],
    },
    {
      args: ['--no-oauth'],
      env: { NOTTY_BASIC_AUTH_ENABLED: 'false' },
      expected: ['false', 'false', 'true', 'true'],
    },
  ];

  for (const { args, env, expected } of cases) {
    const result = runNosh(fixture, args, { env });
    assert.equal(result.status, 0, result.output);
    assert.deepEqual([
      assignment(result.dockerRun, 'NOTTY_BASIC_AUTH_ENABLED'),
      assignment(result.dockerRun, 'NOTTY_OAUTH_ENABLED'),
      assignment(result.dockerRun, 'NOTTY_MCP_SPAWN_OTP_ENABLED'),
      assignment(result.dockerRun, 'NOTTY_NO_OTP_AUTH'),
    ], expected);
    assert.doesNotMatch(
      result.output,
      /(?:default-otp|noauth-otp|no-oauth-otp|otp-only-value|equivalent-otp-only)/,
    );
  }
});

test('Nosh rejects contradictory and empty OTP flags', (t) => {
  const fixture = createFixture(t);
  for (const args of [
    ['--no-otp-auth', '--no-otp'],
    ['--no-otp', '--otp', 'unused'],
    ['--no-oauth', '--no-otp'],
    ['--otp='],
    ['--otp', '   '],
  ]) {
    const result = runNosh(fixture, args, args[0] === '--no-oauth'
      ? { env: { NOTTY_BASIC_AUTH_ENABLED: 'false' } }
      : {});
    assert.notEqual(result.status, 0);
    assert.equal(result.dockerRun, '');
  }
});

test('Nosh dry-run endpoint summaries redact Basic and spawn secrets', (t) => {
  const fixture = createFixture(t);
  const result = runNosh(fixture, [
    '--start-app',
    '--publish', '127.0.0.1:3300',
    '--otp', 'dry-run-spawn-canary',
  ], {
    env: {
      NOTTY_BASIC_AUTH_PASSWORD: 'dry-run-basic-canary',
    },
  });

  assert.equal(result.status, 0, result.output);
  assert.doesNotMatch(result.output, /dry-run-(?:spawn|basic)-canary/);
  assert.match(result.output, /basic auth password: <redacted in dry run>/);
  assert.match(result.output, /spawn otp: <redacted in dry run>/);
  assert.doesNotMatch(result.dockerRun, /NOTTY_BASIC_AUTH_PASSWORD=/);
  assert.match(result.dockerRun, /NOTTY_BASIC_AUTH_VERIFIER=/);
  assert.doesNotMatch(result.output, /scrypt-v1:[a-f0-9]/);
});

test('auth-disabling modes require loopback publication and public origins', (t) => {
  const fixture = createFixture(t);

  for (const args of [
    ['--noauth', '--publish', '3000'],
    ['--no-oauth', '--publish', '0.0.0.0:3000'],
    ['--no-otp-auth', '--publish', '192.0.2.10:3000'],
    ['--no-otp', '--network', 'host'],
  ]) {
    const result = runNosh(fixture, args);
    assert.notEqual(result.status, 0);
    assert.match(result.output, /loopback/i);
  }

  const remoteOrigin = runNosh(fixture, ['--no-otp'], {
    env: { NOTTY_PUBLIC_ORIGIN: 'https://notty.example' },
  });
  assert.notEqual(remoteOrigin.status, 0);
  assert.match(remoteOrigin.output, /loopback NOTTY_PUBLIC_ORIGIN/);

  const loopback = runNosh(fixture, [
    '--no-otp-auth', '--otp', 'local-only', '--publish', '127.0.0.1:3300',
  ]);
  assert.equal(loopback.status, 0, loopback.output);
  assert.equal(
    assignment(loopback.dockerRun, 'NOTTY_PUBLIC_ORIGIN'),
    'http://127.0.0.1:3300',
  );
  assert.equal(assignment(loopback.dockerRun, 'NOTTY_LOOPBACK_PUBLICATION'), 'true');

  const unpublished = runNosh(fixture, ['--noauth', '--otp', 'not-published']);
  assert.equal(unpublished.status, 0, unpublished.output);
  assert.equal(assignment(unpublished.dockerRun, 'NOTTY_LOOPBACK_PUBLICATION'), 'false');
  assert.equal(assignment(unpublished.dockerRun, 'NOTTY_BIND_HOST'), '127.0.0.1');
});

test('OTP-only auth is rejected in Guard mode while Guard ignores --no-otp', (t) => {
  const fixture = createFixture(t);
  const otpOnly = runNosh(fixture, ['--security-mode', 'learn', '--no-otp-auth']);
  assert.notEqual(otpOnly.status, 0);
  assert.match(otpOnly.output, /not available in Guard mTLS mode/);

  const noOtp = runNosh(fixture, ['--security-mode', 'learn', '--no-otp']);
  assert.equal(noOtp.status, 0, noOtp.output);
  assert.match(noOtp.output, /remain OTP-locked/);
  assert.doesNotMatch(noOtp.output, /NOTTY_MCP_SPAWN_OTP_ENABLED=false/);
});

test('Nosh mounts isolated per-workspace auth state and auth reset dry-run is non-mutating', (t) => {
  const fixture = createFixture(t);
  const workspaceId = crypto.createHash('sha256')
    .update(fs.realpathSync(fixture.workspace))
    .digest('hex')
    .slice(0, 32);
  const stateDirectory = path.join(fixture.stateHome, 'notty', 'auth', workspaceId);
  const containerDirectory = '/var/lib/notty-auth';

  const start = runNosh(fixture, ['--noauth', '--otp', 'mount-test']);
  assert.equal(start.status, 0, start.output);
  assert.match(start.dockerRun, new RegExp(
    `-v ${stateDirectory.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}:`
      + `${containerDirectory.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}:rw`,
  ));
  assert.equal(assignment(start.dockerRun, 'NOTTY_WORKSPACE_ID'), workspaceId);
  assert.equal(assignment(start.dockerRun, 'NOTTY_AUTH_STATE_DIR'), containerDirectory);
  assert.equal(fs.existsSync(fixture.stateHome), false);

  const reset = runNosh(fixture, [], { command: ['auth', 'reset'] });
  assert.equal(reset.status, 0, reset.output);
  assert.match(reset.dockerRun, /node \/app\/scripts\/auth-state-cli\.mjs reset$/);
  assert.equal(fs.existsSync(fixture.stateHome), false);

  const mint = runNosh(fixture, [], { command: ['auth', 'otp'] });
  assert.equal(mint.status, 0, mint.output);
  assert.match(mint.dockerRun, /node \/app\/scripts\/auth-state-cli\.mjs otp$/);
  assert.match(mint.dockerRun, /NOTTY_MCP_SPAWN_OTP_ENABLED=true/);
  assert.equal(fs.existsSync(fixture.stateHome), false);
});

test('auth state setup creates only owner-accessible host directories', (t) => {
  const fixture = createFixture(t);
  const fakeBin = path.join(fixture.root, 'bin');
  fs.mkdirSync(fakeBin, { mode: 0o700 });
  fs.writeFileSync(
    path.join(fakeBin, 'docker'),
    '#!/usr/bin/env bash\nexit 0\n',
    { mode: 0o700 },
  );

  const result = runNosh(fixture, [], {
    command: ['auth', 'reset'],
    dryRun: false,
    path: `${fakeBin}:${process.env.PATH}`,
  });
  assert.equal(result.status, 0, result.output);

  const workspaceId = crypto.createHash('sha256')
    .update(fs.realpathSync(fixture.workspace))
    .digest('hex')
    .slice(0, 32);
  for (const directory of [
    fixture.stateHome,
    path.join(fixture.stateHome, 'notty'),
    path.join(fixture.stateHome, 'notty', 'auth'),
    path.join(fixture.stateHome, 'notty', 'auth', workspaceId),
  ]) {
    assert.equal(fs.statSync(directory).mode & 0o777, 0o700, directory);
  }
});

test('auth state setup rejects symlinks in ancestor components', (t) => {
  const fixture = createFixture(t);
  const realParent = path.join(fixture.root, 'real-state-parent');
  const linkedParent = path.join(fixture.root, 'linked-state-parent');
  fs.mkdirSync(realParent, { mode: 0o700 });
  fs.symlinkSync(realParent, linkedParent, 'dir');

  const result = runNosh(fixture, [], {
    env: { XDG_STATE_HOME: path.join(linkedParent, 'state') },
  });
  assert.notEqual(result.status, 0);
  assert.match(result.output, /must not contain symlinks/);
  assert.equal(result.dockerRun, '');
});
