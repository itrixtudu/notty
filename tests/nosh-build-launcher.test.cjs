'use strict';

const assert = require('node:assert/strict');
const childProcess = require('node:child_process');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const test = require('node:test');

const appRoot = path.resolve(__dirname, '..');
const noshPath = path.join(appRoot, 'scripts/nosh.sh');

function createFixture(t) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'notty-nosh-build-'));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const home = path.join(root, 'home');
  const context = path.join(root, 'context');
  fs.mkdirSync(home, { recursive: true });
  fs.mkdirSync(context, { recursive: true });
  fs.writeFileSync(path.join(context, 'Dockerfile'), 'FROM scratch\n');
  return { root, home, context };
}

function runNosh(fixture, args, env = {}) {
  return childProcess.spawnSync('bash', [noshPath, ...args], {
    cwd: fixture.context,
    encoding: 'utf8',
    env: {
      PATH: process.env.PATH,
      HOME: fixture.home,
      ...env,
    },
  });
}

function output(result) {
  return `${result.stdout || ''}${result.stderr || ''}`;
}

function guardCommand(result) {
  return String(result.stdout || '')
    .split(/\r?\n/)
    .find((line) => /(?:^|\/)nosh-guard build(?: |$)/.test(line)) || '';
}

test('build command parsing exposes profile, status, and network help', (t) => {
  const fixture = createFixture(t);
  const help = runNosh(fixture, ['build', '--help']);
  const profileHelp = runNosh(fixture, ['build', 'profile', '--help']);
  const netHelp = runNosh(fixture, ['build', 'net', '--help']);
  const missing = runNosh(fixture, ['build']);
  const missingNet = runNosh(fixture, ['build', 'net']);

  assert.equal(help.status, 0, output(help));
  assert.match(help.stdout, /profile.*status.*net/s);
  assert.equal(profileHelp.status, 0, output(profileHelp));
  assert.match(profileHelp.stdout, /cache-mode.*compare.*cold.*warm/s);
  assert.match(profileHelp.stdout, /-- buildx-options/);
  assert.equal(netHelp.status, 0, output(netHelp));
  assert.match(netHelp.stdout, /learn.*status/s);
  assert.notEqual(missing.status, 0);
  assert.match(missing.stderr, /build requires a command/);
  assert.notEqual(missingNet.status, 0);
  assert.match(missingNet.stderr, /build net requires a command/);
});

test('build profile delegates structured and passthrough options in distinct regions', (t) => {
  const fixture = createFixture(t);
  const result = runNosh(fixture, [
    'build',
    'profile',
    '--dry-run',
    '--file',
    'Containerfile',
    '--tag',
    'example:first',
    '--tag=example:second',
    '--target',
    'release',
    '--platform=linux/amd64',
    '--build-arg',
    'FIRST=one',
    '--build-arg=SECOND=two',
    '--cache-mode',
    'cold',
    '--depth=policy',
    '--no-load',
    fixture.context,
    '--',
    '--secret',
    'id=token,src=/tmp/token',
  ]);

  assert.equal(result.status, 0, output(result));
  const command = guardCommand(result);
  assert.match(command, /build profile(?: |$)/);
  assert.match(command, /--file Containerfile(?: |$)/);
  assert.match(command, /--tag example:first .*--tag example:second/);
  assert.match(
    command,
    /--build-arg 'FIRST=<redacted>' .*--build-arg 'SECOND=<redacted>'/,
  );
  assert.match(command, /--cache-mode cold .*--depth policy .*--no-load/);
  assert.match(command, new RegExp(`${fixture.context} --dry-run -- --secret`));
  assert.match(command, /'<redacted>'$/);
  assert.doesNotMatch(command, /FIRST=one|SECOND=two|\/tmp\/token/);
});

test('build profile validates owned options before delegation', (t) => {
  const fixture = createFixture(t);
  const cases = [
    [
      ['build', 'profile', '--dry-run', '--file', 'A', '--variant', 'dev'],
      /mutually exclusive/,
    ],
    [
      ['build', 'profile', '--dry-run', '--platform', 'linux\/amd64,linux\/arm64'],
      /exactly one platform/,
    ],
    [
      ['build', 'profile', '--dry-run', '--cache-mode', 'sometimes'],
      /invalid --cache-mode/,
    ],
    [
      ['build', 'profile', '--dry-run', '--builder', 'shared'],
      /must follow --/,
    ],
    [
      ['build', 'profile', '--dry-run', fixture.context, fixture.context],
      /exactly one context/,
    ],
  ];

  for (const [args, expected] of cases) {
    const result = runNosh(fixture, args);
    assert.notEqual(result.status, 0, output(result));
    assert.match(output(result), expected);
    assert.equal(guardCommand(result), '');
  }
});

test('build network learn is separate from performance cache and depth modes', (t) => {
  const fixture = createFixture(t);
  const learned = runNosh(fixture, [
    'build',
    'net',
    'learn',
    '--dry-run',
    '--variant',
    'ci',
    '--build-arg',
    'CI=true',
    '--json',
    fixture.context,
  ]);
  const cacheMode = runNosh(fixture, [
    'build',
    'net',
    'learn',
    '--dry-run',
    '--cache-mode',
    'warm',
  ]);
  const depth = runNosh(fixture, [
    'build',
    'net',
    'learn',
    '--dry-run',
    '--depth',
    'deep',
  ]);

  assert.equal(learned.status, 0, output(learned));
  assert.match(
    guardCommand(learned),
    new RegExp(`build net learn --variant ci --build-arg 'CI=<redacted>' --json ${fixture.context} --dry-run$`),
  );
  assert.notEqual(cacheMode.status, 0);
  assert.match(cacheMode.stderr, /always performs a clean build/);
  assert.notEqual(depth.status, 0);
  assert.match(depth.stderr, /--depth is not supported/);
});

test('build and build-network status delegate their scoped options', (t) => {
  const fixture = createFixture(t);
  const status = runNosh(fixture, [
    'build',
    'status',
    '--dry-run',
    '--run',
    'run-42',
    '--json',
    fixture.context,
  ]);
  const netStatus = runNosh(fixture, [
    'build',
    'net',
    'status',
    '--dry-run',
    '--json',
    fixture.context,
  ]);
  const invalid = runNosh(fixture, [
    'build',
    'net',
    'status',
    '--dry-run',
    '--run',
    'run-42',
  ]);

  assert.equal(status.status, 0, output(status));
  assert.match(
    guardCommand(status),
    new RegExp(`build status --run run-42 --json ${fixture.context} --dry-run$`),
  );
  assert.equal(netStatus.status, 0, output(netStatus));
  assert.match(
    guardCommand(netStatus),
    new RegExp(`build net status --json ${fixture.context} --dry-run$`),
  );
  assert.notEqual(invalid.status, 0);
  assert.match(invalid.stderr, /supported only by nosh build status/);
});

test('executed build delegation strips legacy runtime credentials', (t) => {
  const fixture = createFixture(t);
  const guardPath = path.join(fixture.root, 'fake-nosh-guard');
  const argvLog = path.join(fixture.root, 'argv.log');
  const envLog = path.join(fixture.root, 'env.log');
  fs.writeFileSync(guardPath, [
    '#!/usr/bin/env bash',
    'set -euo pipefail',
    'printf "%s\\n" "$@" > "$NOSH_TEST_ARGV_LOG"',
    'printf "otp=%s\\nenabled=%s\\nusername=%s\\npassword=%s\\n" "${NOTTY_MCP_SPAWN_OTP-unset}" "${NOTTY_BASIC_AUTH_ENABLED-unset}" "${NOTTY_BASIC_AUTH_USERNAME-unset}" "${NOTTY_BASIC_AUTH_PASSWORD-unset}" > "$NOSH_TEST_ENV_LOG"',
    '',
  ].join('\n'), { mode: 0o755 });

  const result = runNosh(fixture, [
    'build',
    'status',
    '--json',
    fixture.context,
  ], {
    NOSH_GUARD_BIN: guardPath,
    NOSH_TEST_ARGV_LOG: argvLog,
    NOSH_TEST_ENV_LOG: envLog,
    NOTTY_MCP_SPAWN_OTP: 'secret-otp',
    NOTTY_BASIC_AUTH_ENABLED: 'true',
    NOTTY_BASIC_AUTH_USERNAME: 'legacy-user',
    NOTTY_BASIC_AUTH_PASSWORD: 'legacy-password',
  });

  assert.equal(result.status, 0, output(result));
  assert.equal(
    fs.readFileSync(argvLog, 'utf8'),
    `build\nstatus\n--json\n${fixture.context}\n`,
  );
  assert.equal(
    fs.readFileSync(envLog, 'utf8'),
    'otp=unset\nenabled=unset\nusername=unset\npassword=unset\n',
  );
});
