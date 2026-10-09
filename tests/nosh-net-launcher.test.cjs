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
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'notty-nosh-net-'));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const home = path.join(root, 'home');
  const workspace = path.join(root, 'workspace');
  fs.mkdirSync(home, { recursive: true });
  fs.mkdirSync(workspace, { recursive: true });
  return { root, home, workspace };
}

function runNosh(fixture, args, env = {}) {
  return childProcess.spawnSync('bash', [noshPath, ...args], {
    cwd: fixture.workspace,
    encoding: 'utf8',
    env: {
      PATH: process.env.PATH,
      HOME: fixture.home,
      XDG_CONFIG_HOME: path.join(fixture.home, '.config'),
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
    .find((line) => /(?:^|\/)nosh-guard net(?: |$)/.test(line)) || '';
}

test('init learning previews the wizard learning step with its safe defaults', (t) => {
  const fixture = createFixture(t);
  const result = runNosh(fixture, [
    'init', '--step', 'learn', '--dry-run', '--workdir', fixture.workspace,
    '--image', 'nosh:test', '--guard-prefix', '/opt/example',
  ]);
  assert.equal(result.status, 0, output(result));
  assert.match(result.stdout, /sudo \/opt\/example\/bin\/nosh-guard net learn/);
  assert.match(result.stdout, /--image nosh:test/);
  assert.match(result.stdout, /--review-output --no-start-app --no-collab/);
  assert.doesNotMatch(result.stdout, /docker run|net enforce/);
});

test('init learning supports the installed symlink, preserves literal arguments and forwards failure', (t) => {
  const fixture = createFixture(t);
  const checkout = path.join(fixture.root, 'checkout');
  const bin = path.join(fixture.root, 'bin');
  fs.mkdirSync(path.join(checkout, 'scripts'), { recursive: true });
  fs.mkdirSync(bin);
  fs.copyFileSync(noshPath, path.join(checkout, 'scripts/nosh.sh'));
  fs.symlinkSync('../checkout/scripts/nosh.sh', path.join(bin, 'nosh'));
  fs.writeFileSync(path.join(checkout, 'scripts/nosh-init.sh'), '#!/bin/bash\nprintf "%s\\n" "$PWD" "$@"\nexit 17\n');
  const workspace = path.join(fixture.workspace, 'space $(touch INJECTED)');
  const result = childProcess.spawnSync('bash', [path.join(bin, 'nosh'), 'init', '--step', 'learn',
    '--workdir', workspace, '--image', 'nosh:test'], { cwd: fixture.workspace, encoding: 'utf8' });
  assert.equal(result.status, 17, output(result));
  assert.deepEqual(result.stdout.trimEnd().split('\n'), [fixture.workspace, '--step', 'learn',
    '--workdir', workspace, '--image', 'nosh:test']);
  assert.equal(fs.existsSync(path.join(fixture.workspace, 'INJECTED')), false);

});

test('init help exposes configuration and rejects invalid options', t => {
  const fixture = createFixture(t);
  const help = runNosh(fixture, ['--help']);
  assert.equal(help.status, 0, output(help));
  assert.match(help.stdout, /init.*Configure/);
  const initHelp = runNosh(fixture, ['init', '--help']);
  assert.equal(initHelp.status, 0, output(initHelp));
  assert.match(initHelp.stdout, /Usage: nosh init/);
  assert.match(initHelp.stdout, /--advanced/);
  assert.match(initHelp.stdout, /--check/);
  for (const args of [['--workdir'], ['--unknown'], ['--step', 'enforce']]) {
    const rejected = runNosh(fixture, ['init', '--dry-run', ...args]);
    assert.notEqual(rejected.status, 0, output(rejected));
  }
});

test('net command parsing exposes nested help and rejects missing stages', (t) => {
  const fixture = createFixture(t);
  const help = runNosh(fixture, ['net', '--help']);
  const missing = runNosh(fixture, ['net']);
  const unknown = runNosh(fixture, ['net', 'observe']);

  assert.equal(help.status, 0, output(help));
  assert.match(help.stdout, /nosh\.sh net <command>/);
  assert.match(help.stdout, /learn.*audit.*approve.*enforce.*status/s);
  assert.notEqual(missing.status, 0);
  assert.match(missing.stderr, /net requires a command/);
  assert.notEqual(unknown.status, 0);
  assert.match(unknown.stderr, /unknown net command: observe/);
});

test('net learn delegates resolved launch settings without a basename-only name', (t) => {
  const fixture = createFixture(t);
  const defaults = runNosh(fixture, [
    'net',
    'learn',
    '--dry-run',
    '--workdir',
    fixture.workspace,
  ]);

  assert.equal(defaults.status, 0, output(defaults));
  const defaultCommand = guardCommand(defaults);
  assert.match(
    defaultCommand,
    new RegExp(
      `net learn --workload dev --workdir ${fixture.workspace} --image nosh(?: |$)`,
    ),
  );
  assert.match(defaultCommand, /--no-collab(?: |$)/);
  assert.match(defaultCommand, /--no-start-app(?: |$)/);
  assert.match(defaultCommand, /--dry-run(?: |$)/);
  assert.doesNotMatch(defaultCommand, /--name(?: |$)/);
  assert.doesNotMatch(defaultCommand, /--config(?: |$)/);
  assert.doesNotMatch(defaultCommand, /--profile(?: |$)/);

  const configPath = path.join(fixture.workspace, 'net-config.json');
  fs.writeFileSync(
    configPath,
    '{"schemaVersion":1,"switches":{"collab":false}}\n',
    'utf8',
  );
  const explicit = runNosh(fixture, [
    'net',
    'learn',
    '--dry-run',
    '--workdir',
    fixture.workspace,
    '--image',
    'nosh:test',
    '--name',
    'explicit-runner',
    '--profile',
    'codex',
    '--config',
    configPath,
    '--collab',
    '--no-start-app',
  ]);

  assert.equal(explicit.status, 0, output(explicit));
  const explicitCommand = guardCommand(explicit);
  assert.match(explicitCommand, /--image nosh:test(?: |$)/);
  assert.match(explicitCommand, /--name explicit-runner(?: |$)/);
  assert.match(explicitCommand, /--profile codex,agents(?: |$)/);
  assert.match(
    explicitCommand,
    new RegExp(`--config ${configPath}(?: |$)`),
  );
  assert.match(explicitCommand, /--collab(?: |$)/);
  assert.match(explicitCommand, /--no-start-app(?: |$)/);
});

test('net learn delegates one validated headless observation duration', (t) => {
  const fixture = createFixture(t);
  const valid = runNosh(fixture, [
    'net',
    'learn',
    '--duration',
    '180',
    '--json',
    '--dry-run',
    '--workdir',
    fixture.workspace,
  ]);

  assert.equal(valid.status, 0, output(valid));
  assert.match(guardCommand(valid), /net learn .*--duration 180(?: |$)/);
  assert.match(guardCommand(valid), /--json(?: |$)/);

  const jsonWithoutDuration = runNosh(fixture, [
    'net', 'learn', '--json', '--dry-run', '--workdir', fixture.workspace,
  ]);
  assert.notEqual(jsonWithoutDuration.status, 0, output(jsonWithoutDuration));
  assert.match(
    jsonWithoutDuration.stderr,
    /nosh net learn --json requires --duration/,
  );

  for (const duration of ['0', '1.5', '86401', 'forever']) {
    const invalid = runNosh(fixture, [
      'net',
      'learn',
      `--duration=${duration}`,
      '--dry-run',
      '--workdir',
      fixture.workspace,
    ]);
    assert.notEqual(invalid.status, 0, output(invalid));
    assert.match(invalid.stderr, /--duration must be an integer from 1 to 86400/);
    assert.equal(guardCommand(invalid), '');
  }

  const duplicate = runNosh(fixture, [
    'net', 'learn', '--duration', '1', '--duration=2', '--dry-run',
  ]);
  assert.notEqual(duplicate.status, 0, output(duplicate));
  assert.match(duplicate.stderr, /--duration may be specified only once/);
});

test('net audit and enforce omit defaults and pass only explicit launch overrides', (t) => {
  const fixture = createFixture(t);
  const audit = runNosh(
    fixture,
    ['net', 'audit', '--dry-run', '--workdir', fixture.workspace],
    {
      NOSH_IMAGE: 'environment:image',
      NOSH_START_APP: 'true',
      NOTTY_COLLAB_ENABLED: 'true',
    },
  );

  assert.equal(audit.status, 0, output(audit));
  const auditCommand = guardCommand(audit);
  assert.match(
    auditCommand,
    new RegExp(`net audit --workload dev --workdir ${fixture.workspace}(?: |$)`),
  );
  assert.doesNotMatch(
    auditCommand,
    /--image|--name|--profile|--config|--collab|--start-app|--no-start-app/,
  );

  const enforce = runNosh(fixture, [
    'net',
    'enforce',
    '--dry-run',
    '--workdir',
    fixture.workspace,
    '--revision',
    'approved-7',
    '--image',
    'nosh:override',
    '--name',
    'override-runner',
    '--profile',
    'codex',
    '--collab',
    '--no-start-app',
  ]);

  assert.equal(enforce.status, 0, output(enforce));
  const enforceCommand = guardCommand(enforce);
  assert.match(enforceCommand, /--revision approved-7(?: |$)/);
  assert.match(enforceCommand, /--image nosh:override(?: |$)/);
  assert.match(enforceCommand, /--name override-runner(?: |$)/);
  assert.match(enforceCommand, /--profile codex,agents(?: |$)/);
  assert.match(enforceCommand, /--collab(?: |$)/);
  assert.match(enforceCommand, /--no-start-app(?: |$)/);
});

test('net approve and status delegate their scoped workflow options', (t) => {
  const fixture = createFixture(t);
  const approve = runNosh(fixture, [
    'net',
    'approve',
    '--dry-run',
    '--workdir',
    fixture.workspace,
    '--revision',
    'candidate-3',
    '--reviewer',
    'reviewer@example.test',
    '--yes',
  ]);
  const status = runNosh(fixture, [
    'net',
    'status',
    '--dry-run',
    '--workdir',
    fixture.workspace,
    '--json',
    '--repair',
  ]);

  assert.equal(approve.status, 0, output(approve));
  assert.match(
    guardCommand(approve),
    /net approve .*--revision candidate-3 .*--reviewer reviewer@example.test .*--yes .*--dry-run$/,
  );
  assert.equal(status.status, 0, output(status));
  assert.match(
    guardCommand(status),
    /net status .*--json .*--repair .*--dry-run$/,
  );
});

test('net workflow rejects legacy lifecycle and network controls', (t) => {
  const fixture = createFixture(t);
  const cases = [
    ['--persist'],
    ['--profile-list'],
    ['--security-mode', 'learn'],
    ['--security-profile-dir', '/tmp/profile'],
    ['--network', 'none'],
    ['--publish', '3300'],
    ['-P', '3300'],
  ];

  for (const args of cases) {
    const result = runNosh(fixture, [
      'net',
      'learn',
      '--dry-run',
      '--workdir',
      fixture.workspace,
      ...args,
    ]);

    assert.notEqual(result.status, 0, output(result));
    assert.match(output(result), /is not supported by nosh net/);
    assert.equal(guardCommand(result), '');
  }
});

test('net workflow rejects a nested legacy lifecycle verb', (t) => {
  const fixture = createFixture(t);
  const result = runNosh(fixture, [
    'net',
    'learn',
    'start',
    '--dry-run',
    '--workdir',
    fixture.workspace,
  ]);

  assert.notEqual(result.status, 0, output(result));
  assert.match(output(result), /lifecycle command start is not supported/);
  assert.equal(guardCommand(result), '');
});

test('net commands reject options belonging to a different workflow stage', (t) => {
  const fixture = createFixture(t);
  const cases = [
    ['learn', '--revision', 'candidate-1', /--revision/],
    ['audit', '--duration', '180', /--duration/],
    ['audit', '--yes', /--yes/],
    ['enforce', '--reviewer', 'alice', /--reviewer/],
    ['approve', '--image', 'nosh:test', /--image/],
    ['approve', '--json', /--json/],
    ['status', '--profile', 'codex', /--profile/],
    ['status', '--revision', 'candidate-1', /--revision/],
  ];

  for (const [command, ...rest] of cases) {
    const expected = rest.pop();
    const result = runNosh(fixture, [
      'net',
      command,
      '--dry-run',
      '--workdir',
      fixture.workspace,
      ...rest,
    ]);

    assert.notEqual(result.status, 0, output(result));
    assert.match(output(result), expected);
    assert.equal(guardCommand(result), '');
  }
});

test('net status delegates without sudo and strips legacy credentials', (t) => {
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
    'net',
    'status',
    '--workdir',
    fixture.workspace,
    '--json',
    '--otp',
    'cli-secret',
    '--noauth',
  ], {
    NOSH_GUARD_BIN: guardPath,
    NOSH_TEST_ARGV_LOG: argvLog,
    NOSH_TEST_ENV_LOG: envLog,
    NOTTY_MCP_SPAWN_OTP: 'environment-secret',
    NOTTY_BASIC_AUTH_ENABLED: 'true',
    NOTTY_BASIC_AUTH_USERNAME: 'legacy-user',
    NOTTY_BASIC_AUTH_PASSWORD: 'legacy-password',
  });

  assert.equal(result.status, 0, output(result));
  assert.equal(
    fs.readFileSync(argvLog, 'utf8'),
    `net\nstatus\n--workload\ndev\n--workdir\n${fixture.workspace}\n--json\n`,
  );
  assert.equal(
    fs.readFileSync(envLog, 'utf8'),
    'otp=unset\nenabled=unset\nusername=unset\npassword=unset\n',
  );
  assert.match(result.stderr, /--otp has no effect/);
  assert.match(result.stderr, /--noauth has no effect/);
});

test('net status canonicalizes a symlinked workspace before delegation', (t) => {
  const fixture = createFixture(t);
  const symlink = path.join(fixture.root, 'workspace-link');
  fs.symlinkSync(fixture.workspace, symlink);
  const result = runNosh(fixture, [
    'net',
    'status',
    '--dry-run',
    '--workdir',
    symlink,
  ]);

  assert.equal(result.status, 0, output(result));
  assert.match(
    guardCommand(result),
    new RegExp(`--workdir ${fixture.workspace}(?: |$)`),
  );
  assert.doesNotMatch(guardCommand(result), /workspace-link/);
});


test('init defaults to the caller workspace and honors an explicit override', t => {
  const fixture = createFixture(t);
  const other = path.join(fixture.root, 'other');
  fs.mkdirSync(other);
  for (const [args, workspace] of [[[], fixture.workspace], [['--workdir', other], other]]) {
    const result = runNosh(fixture, ['init', '--dry-run', '--step=learn', '--image=nosh:test', ...args]);
    assert.equal(result.status, 0, output(result));
    assert.ok(result.stdout.includes(`--workdir ${workspace} `), result.stdout);
    assert.doesNotMatch(result.stdout, /net enforce/);
  }
});


test('dev is the default; explicit run and agent-home options are forwarded', (t) => {
  const fixture = createFixture(t);
  const dev = runNosh(fixture, ['net', 'learn', '--dry-run', '--agents', 'codex', '--codex-home', fixture.home]);
  assert.equal(dev.status, 0, output(dev));
  assert.match(guardCommand(dev), /--workload dev/);
  assert.match(guardCommand(dev), /--agents codex/);
  assert.match(guardCommand(dev), new RegExp(`--codex-home ${fixture.home}`));
  const run = runNosh(fixture, ['net', 'learn', '--dry-run', '--workload', 'run']);
  assert.equal(run.status, 0, output(run));
  assert.match(guardCommand(run), /--workload run/);
  assert.doesNotMatch(guardCommand(run), /--agents|--codex-home/);
  const invalid = runNosh(fixture, ['net', 'learn', '--dry-run', '--workload', 'run', '--agents', 'codex']);
  assert.notEqual(invalid.status, 0);
});
