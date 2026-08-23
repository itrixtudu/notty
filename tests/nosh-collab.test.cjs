'use strict';

const assert = require('node:assert/strict');
const childProcess = require('node:child_process');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const test = require('node:test');

const appRoot = path.resolve(__dirname, '..');
const noshPath = path.join(appRoot, 'nosh.sh');

function writeJson(filePath, value) {
  fs.mkdirSync(path.dirname(filePath), { recursive: true });
  fs.writeFileSync(filePath, `${JSON.stringify(value, null, 2)}\n`, 'utf8');
}

function createFixture(t) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'notty-nosh-collab-'));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const home = path.join(root, 'home');
  const workspace = path.join(root, 'workspace');
  fs.mkdirSync(home, { recursive: true });
  fs.mkdirSync(workspace, { recursive: true });
  return { root, home, workspace };
}

function runNosh(fixture, options = {}) {
  const result = childProcess.spawnSync('bash', [
    noshPath,
    options.command || 'start',
    ...(options.dryRun === false ? [] : ['--dry-run']),
    '--noauth',
    '--otp',
    'fixed-test-otp',
    '--no-start-app',
    '--workdir',
    fixture.workspace,
    ...(options.args || []),
  ], {
    cwd: fixture.workspace,
    encoding: 'utf8',
    env: {
      PATH: process.env.PATH,
      HOME: fixture.home,
      XDG_CONFIG_HOME: path.join(fixture.home, '.config'),
      ...(options.env || {}),
    },
  });
  const output = `${result.stdout || ''}${result.stderr || ''}`;
  const dockerRun = String(result.stdout || '')
    .split(/\r?\n/)
    .find((line) => line.startsWith('docker run ')) || '';
  return { ...result, output, dockerRun };
}

function guardRun(output) {
  return String(output || '')
    .split(/\r?\n/)
    .find((line) => /(?:^|\/)nosh-guard run(?: |$)/.test(line)) || '';
}

function collabAssignments(command) {
  return command.match(/NOTTY_COLLAB_ENABLED=(?:true|false)/g) || [];
}

function unsandboxedAssignments(command) {
  return command.match(/NOTTY_COLLAB_UNSANDBOXED=(?:true|false)/g) || [];
}

function ollamaHostAssignments(command) {
  return command.match(/OLLAMA_HOST=[^ ]+/g) || [];
}

function spawnOtpTtlAssignments(command) {
  return command.match(/NOTTY_MCP_SPAWN_OTP_TTL_SECONDS=[^ ]+/g) || [];
}

test('Nosh enables Docker init for descendant process reaping', (t) => {
  const fixture = createFixture(t);
  const result = runNosh(fixture);
  const explicitLegacy = runNosh(fixture, {
    args: ['--security-mode', 'legacy'],
  });

  assert.equal(result.status, 0, result.output);
  assert.match(result.dockerRun, /^docker run -d --init(?: |$)/);
  assert.equal(guardRun(result.output), '');
  assert.equal(explicitLegacy.status, 0, explicitLegacy.output);
  assert.match(explicitLegacy.dockerRun, /^docker run -d --init(?: |$)/);
  assert.equal(guardRun(explicitLegacy.output), '');
});

test('Nosh skips tty USB discovery by default and runs it for Arduino', (t) => {
  const fixture = createFixture(t);
  const withoutArduino = runNosh(fixture);
  const withArduino = runNosh(fixture, {
    args: ['--profile', 'arduino'],
  });

  assert.equal(withoutArduino.status, 0, withoutArduino.output);
  assert.doesNotMatch(withoutArduino.output, /\/dev\/ttyUSB/);
  assert.equal(withArduino.status, 0, withArduino.output);
  assert.match(withArduino.output, /\/dev\/ttyUSB/);
});

test('Nosh secure modes delegate dry runs to nosh-guard without requiring the binary', (t) => {
  const fixture = createFixture(t);
  const profileDir = path.join(fixture.root, 'security-profile');
  fs.mkdirSync(profileDir);

  for (const mode of ['learn', 'audit', 'enforce']) {
    const result = runNosh(fixture, {
      args: [
        '--security-mode', mode,
        ...(['audit', 'enforce'].includes(mode)
          ? ['--security-profile-dir', profileDir]
          : []),
        '--profile', 'agents',
        '--persist',
      ],
    });

    assert.equal(result.status, 0, result.output);
    assert.equal(result.dockerRun, '');
    const command = guardRun(result.output);
    assert.match(command, new RegExp(
      `^(?:.*/)?nosh-guard run --mode ${mode} --image nosh --name nosh-workspace `
        + `--workdir ${fixture.workspace} --action start(?: |$)`,
    ));
    assert.match(command, /--profile agents(?: |$)/);
    if (mode === 'learn') {
      assert.doesNotMatch(command, /--profile-dir(?: |$)/);
    } else {
      assert.match(command, new RegExp(
        `--profile-dir ${profileDir.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}(?: |$)`,
      ));
    }
    assert.match(command, /--no-collab(?: |$)/);
    assert.match(command, /--persist(?: |$)/);
    assert.match(command, /--no-start-app(?: |$)/);
    assert.doesNotMatch(command, /--noauth(?: |$)/);
    assert.match(command, /--dry-run(?: |$)/);
    assert.doesNotMatch(command, /fixed-test-otp/);
  }
});

test('Nosh rejects legacy network and publish controls in secure modes', (t) => {
  const fixture = createFixture(t);

  for (const args of [
    ['--network', 'bridge'],
    ['--publish', '127.0.0.1:3300'],
  ]) {
    const result = runNosh(fixture, {
      args: ['--security-mode', 'learn', ...args],
    });

    assert.notEqual(result.status, 0);
    assert.match(
      result.output,
      /is not supported in secure mode/,
    );
    assert.equal(guardRun(result.output), '');
    assert.equal(result.dockerRun, '');
  }
});

test('Nosh delegates every secure lifecycle action to nosh-guard', (t) => {
  const fixture = createFixture(t);
  const profileDir = path.join(fixture.root, 'security-profile');
  fs.mkdirSync(profileDir);

  for (const action of ['start', 'attach', 'stop', 'rm', 'recreate']) {
    const result = runNosh(fixture, {
      command: action,
      args: [
        '--security-mode=audit',
        ...(['start', 'recreate'].includes(action)
          ? ['--security-profile-dir', profileDir]
          : []),
      ],
    });

    assert.equal(result.status, 0, result.output);
    assert.equal(result.dockerRun, '');
    assert.match(guardRun(result.output), new RegExp(`--action ${action}(?: |$)`));
  }
});

test('Nosh does not forward legacy credentials to guarded lifecycle commands', (t) => {
  const fixture = createFixture(t);
  const guardPath = path.join(fixture.root, 'fake-nosh-guard');
  const argvLog = path.join(fixture.root, 'guard-argv.log');
  const envLog = path.join(fixture.root, 'guard-env.log');
  fs.writeFileSync(guardPath, [
    '#!/usr/bin/env bash',
    'set -euo pipefail',
    'printf "%s\\n" "$@" > "$NOSH_GUARD_ARGV_LOG"',
    'printf "otp=%s\\nauth=%s\\n" "${NOTTY_MCP_SPAWN_OTP-unset}" "${NOTTY_BASIC_AUTH_ENABLED-unset}" > "$NOSH_GUARD_ENV_LOG"',
    '',
  ].join('\n'), { mode: 0o755 });

  const result = runNosh(fixture, {
    dryRun: false,
    args: ['--security-mode', 'learn'],
    env: {
      NOSH_GUARD_BIN: guardPath,
      NOSH_GUARD_ARGV_LOG: argvLog,
      NOSH_GUARD_ENV_LOG: envLog,
    },
  });

  assert.equal(result.status, 0, result.output);
  const guardArgv = fs.readFileSync(argvLog, 'utf8');
  assert.match(guardArgv, /^run\n--mode\nlearn\n/);
  assert.match(guardArgv, /--action\nstart\n/);
  assert.doesNotMatch(guardArgv, /fixed-test-otp/);
  assert.equal(
    fs.readFileSync(envLog, 'utf8'),
    'otp=unset\nauth=unset\n',
  );
});

test('Nosh rejects unsupported security modes before Docker or guard execution', (t) => {
  const fixture = createFixture(t);
  for (const argument of ['--security-mode=observe', '--security-mode=']) {
    const result = runNosh(fixture, { args: [argument] });

    assert.notEqual(result.status, 0);
    assert.match(result.output, /invalid security mode/i);
    assert.equal(result.dockerRun, '');
    assert.equal(guardRun(result.output), '');
  }
});

test('Nosh supplies a default Ollama host with profile and host override precedence', (t) => {
  const fixture = createFixture(t);

  const fromDefault = runNosh(fixture);
  assert.equal(fromDefault.status, 0, fromDefault.output);
  assert.deepEqual(
    ollamaHostAssignments(fromDefault.dockerRun),
    ['OLLAMA_HOST=172.17.0.1:11434'],
  );

  writeJson(path.join(fixture.workspace, 'nosh.mounts.json'), {
    profiles: {
      ollama: {
        env: { OLLAMA_HOST: '192.0.2.10:11434' },
      },
    },
  });
  const fromProfile = runNosh(fixture, {
    args: ['--profile', 'ollama'],
  });
  assert.equal(fromProfile.status, 0, fromProfile.output);
  assert.deepEqual(
    ollamaHostAssignments(fromProfile.dockerRun),
    ['OLLAMA_HOST=192.0.2.10:11434'],
  );

  const fromHost = runNosh(fixture, {
    args: ['--profile', 'ollama'],
    env: { OLLAMA_HOST: '198.51.100.20:11434' },
  });
  assert.equal(fromHost.status, 0, fromHost.output);
  assert.deepEqual(
    ollamaHostAssignments(fromHost.dockerRun),
    ['OLLAMA_HOST=198.51.100.20:11434'],
  );
});

test('Nosh supplies a 3600-second spawn OTP TTL with profile and host precedence', (t) => {
  const fixture = createFixture(t);

  const fromDefault = runNosh(fixture);
  assert.equal(fromDefault.status, 0, fromDefault.output);
  assert.deepEqual(
    spawnOtpTtlAssignments(fromDefault.dockerRun),
    ['NOTTY_MCP_SPAWN_OTP_TTL_SECONDS=3600'],
  );

  writeJson(path.join(fixture.workspace, 'nosh.mounts.json'), {
    profiles: {
      shortOtp: {
        env: { NOTTY_MCP_SPAWN_OTP_TTL_SECONDS: '900' },
      },
    },
  });
  const fromProfile = runNosh(fixture, { args: ['--profile', 'shortOtp'] });
  assert.equal(fromProfile.status, 0, fromProfile.output);
  assert.deepEqual(
    spawnOtpTtlAssignments(fromProfile.dockerRun),
    ['NOTTY_MCP_SPAWN_OTP_TTL_SECONDS=900'],
  );

  const fromHost = runNosh(fixture, {
    args: ['--profile', 'shortOtp'],
    env: { NOTTY_MCP_SPAWN_OTP_TTL_SECONDS: '7200' },
  });
  assert.equal(fromHost.status, 0, fromHost.output);
  assert.deepEqual(
    spawnOtpTtlAssignments(fromHost.dockerRun),
    ['NOTTY_MCP_SPAWN_OTP_TTL_SECONDS=7200'],
  );
});

test('Nosh mirrors the default and workspace collab config into the container', (t) => {
  const fixture = createFixture(t);

  const fromBuiltin = runNosh(fixture);
  assert.equal(fromBuiltin.status, 0, fromBuiltin.output);
  assert.deepEqual(
    collabAssignments(fromBuiltin.dockerRun),
    ['NOTTY_COLLAB_ENABLED=false'],
  );

  writeJson(path.join(fixture.workspace, '.notty', 'config.json'), {
    schemaVersion: 1,
    switches: { collab: true },
  });

  const fromWorkspace = runNosh(fixture);
  assert.equal(fromWorkspace.status, 0, fromWorkspace.output);
  assert.match(fromWorkspace.dockerRun, /^docker run /);
  assert.deepEqual(
    collabAssignments(fromWorkspace.dockerRun),
    ['NOTTY_COLLAB_ENABLED=true'],
  );
  assert.match(fromWorkspace.dockerRun, /NOTTY_NOSH_PROFILES=agents/);
});

test('Nosh normalizes and propagates the host collab environment switch', (t) => {
  const fixture = createFixture(t);

  const enabled = runNosh(fixture, {
    env: { NOTTY_COLLAB_ENABLED: 'yes' },
  });
  assert.equal(enabled.status, 0, enabled.output);
  assert.deepEqual(collabAssignments(enabled.dockerRun), ['NOTTY_COLLAB_ENABLED=true']);

  const disabled = runNosh(fixture, {
    env: { NOTTY_COLLAB_ENABLED: 'off' },
  });
  assert.equal(disabled.status, 0, disabled.output);
  assert.deepEqual(collabAssignments(disabled.dockerRun), ['NOTTY_COLLAB_ENABLED=false']);
});

test('Nosh forwards an explicit agent permission override without inventing one', (t) => {
  const fixture = createFixture(t);

  const automatic = runNosh(fixture);
  assert.equal(automatic.status, 0, automatic.output);
  assert.deepEqual(unsandboxedAssignments(automatic.dockerRun), []);

  const enabled = runNosh(fixture, {
    env: { NOTTY_COLLAB_UNSANDBOXED: 'yes' },
  });
  assert.equal(enabled.status, 0, enabled.output);
  assert.deepEqual(
    unsandboxedAssignments(enabled.dockerRun),
    ['NOTTY_COLLAB_UNSANDBOXED=true'],
  );

  const disabled = runNosh(fixture, {
    env: { NOTTY_COLLAB_UNSANDBOXED: 'off' },
  });
  assert.equal(disabled.status, 0, disabled.output);
  assert.deepEqual(
    unsandboxedAssignments(disabled.dockerRun),
    ['NOTTY_COLLAB_UNSANDBOXED=false'],
  );

  writeJson(path.join(fixture.workspace, 'nosh.mounts.json'), {
    profiles: {
      unsafe: {
        env: { NOTTY_COLLAB_UNSANDBOXED: 'true' },
      },
    },
  });
  const hostOverride = runNosh(fixture, {
    args: ['--profile', 'unsafe'],
    env: { NOTTY_COLLAB_UNSANDBOXED: 'false' },
  });
  assert.equal(hostOverride.status, 0, hostOverride.output);
  assert.deepEqual(
    unsandboxedAssignments(hostOverride.dockerRun),
    ['NOTTY_COLLAB_UNSANDBOXED=false'],
  );

  const invalid = runNosh(fixture, {
    env: { NOTTY_COLLAB_UNSANDBOXED: 'sometimes' },
  });
  assert.notEqual(invalid.status, 0);
  assert.match(invalid.output, /NOTTY_COLLAB_UNSANDBOXED must be one of/i);
  assert.equal(invalid.dockerRun, '');
});

test('Nosh image exposes container detection to non-interactive services', () => {
  const dockerfile = fs.readFileSync(path.join(appRoot, 'Dockerfile.nosh'), 'utf8');
  assert.match(dockerfile, /\bDOCKER_CONTAINER=1\b/);
  assert.doesNotMatch(
    dockerfile,
    /echo ['"]export DOCKER_CONTAINER=1['"] >> .*\.bashrc/,
  );
});

test('Nosh mounts Antigravity CLI state with the antigravity profile', (t) => {
  const fixture = createFixture(t);
  const statePath = path.join(fixture.home, '.gemini', 'antigravity-cli');
  fs.mkdirSync(statePath, { recursive: true });

  const result = runNosh(fixture, {
    args: ['--profile', 'antigravity'],
  });

  assert.equal(result.status, 0, result.output);
  assert.match(result.dockerRun, /NOTTY_NOSH_PROFILES=antigravity/);
  assert.match(result.dockerRun, new RegExp(`${statePath}:${statePath}:rw`));
});

test('Nosh uses the last CLI collab switch and CLI wins over the host environment', (t) => {
  const fixture = createFixture(t);

  const enabled = runNosh(fixture, {
    args: ['--no-collab', '--collab'],
    env: { NOTTY_COLLAB_ENABLED: 'false' },
  });
  assert.equal(enabled.status, 0, enabled.output);
  assert.deepEqual(collabAssignments(enabled.dockerRun), ['NOTTY_COLLAB_ENABLED=true']);

  const disabled = runNosh(fixture, {
    args: ['--collab', '--no-collab'],
    env: { NOTTY_COLLAB_ENABLED: 'true' },
  });
  assert.equal(disabled.status, 0, disabled.output);
  assert.deepEqual(collabAssignments(disabled.dockerRun), ['NOTTY_COLLAB_ENABLED=false']);
});

test('Nosh applies an explicit collab switch after profile environment values', (t) => {
  const fixture = createFixture(t);
  writeJson(path.join(fixture.workspace, 'nosh.mounts.json'), {
    profiles: {
      'collab-off': {
        env: { NOTTY_COLLAB_ENABLED: 'false' },
      },
    },
  });

  const result = runNosh(fixture, {
    args: ['--profile', 'collab-off', '--collab'],
  });
  assert.equal(result.status, 0, result.output);
  assert.deepEqual(collabAssignments(result.dockerRun), ['NOTTY_COLLAB_ENABLED=true']);
  assert.match(result.dockerRun, /NOTTY_NOSH_PROFILES=collab-off,agents/);
});

test('Nosh explicit config overrides workspace config before environment and CLI', (t) => {
  const fixture = createFixture(t);
  const explicitPath = path.join(fixture.workspace, 'explicit-config.json');
  writeJson(path.join(fixture.workspace, '.notty', 'config.json'), {
    schemaVersion: 1,
    switches: { collab: true },
  });
  writeJson(explicitPath, {
    schemaVersion: 1,
    switches: { collab: false },
  });

  const fromExplicit = runNosh(fixture, {
    args: ['--config', explicitPath],
  });
  assert.equal(fromExplicit.status, 0, fromExplicit.output);
  assert.deepEqual(
    collabAssignments(fromExplicit.dockerRun),
    ['NOTTY_COLLAB_ENABLED=false'],
  );

  const fromEnvironment = runNosh(fixture, {
    args: ['--config', explicitPath],
    env: { NOTTY_COLLAB_ENABLED: 'true' },
  });
  assert.equal(fromEnvironment.status, 0, fromEnvironment.output);
  assert.deepEqual(
    collabAssignments(fromEnvironment.dockerRun),
    ['NOTTY_COLLAB_ENABLED=true'],
  );
});

test('Nosh rejects invalid host collab switches before invoking Docker', (t) => {
  const fixture = createFixture(t);
  const result = runNosh(fixture, {
    env: { NOTTY_COLLAB_ENABLED: 'sometimes' },
  });

  assert.notEqual(result.status, 0);
  assert.match(result.output, /NOTTY_COLLAB_ENABLED|invalid boolean/i);
  assert.equal(result.dockerRun, '');
});

test('Nosh rejects malformed config before invoking Docker', (t) => {
  const fixture = createFixture(t);
  const configPath = path.join(fixture.workspace, '.notty', 'config.json');
  fs.mkdirSync(path.dirname(configPath), { recursive: true });
  fs.writeFileSync(configPath, '{', 'utf8');

  const result = runNosh(fixture);
  assert.notEqual(result.status, 0);
  assert.match(result.output, /invalid Notty config|failed to load Notty config/);
  assert.equal(result.dockerRun, '');
});

test('Nosh help documents both collab creation switches', () => {
  const result = childProcess.spawnSync('bash', [noshPath, '--help'], {
    encoding: 'utf8',
    env: { PATH: process.env.PATH, HOME: process.env.HOME },
  });

  assert.equal(result.status, 0, result.stderr);
  assert.match(result.stdout, /--collab/);
  assert.match(result.stdout, /--no-collab/);
  assert.match(result.stdout, /--config/);
  assert.match(result.stdout, /--profile-list\s+List available profiles and exit/);
  assert.match(result.stdout, /--name NAME\s+Override name \(default: nosh-<workdir-basename>\)/);
  assert.match(result.stdout, /--security-mode MODE/);
  assert.match(result.stdout, /--security-profile-dir PATH/);
  assert.match(result.stdout, /legacy \(default\), learn, audit, or enforce/);
});

test('Nosh reports an invalid workdir without invoking Docker', (t) => {
  const fixture = createFixture(t);
  const missingWorkdir = path.join(fixture.workspace, 'missing');
  const result = runNosh(fixture, {
    args: ['--workdir', missingWorkdir],
  });

  assert.notEqual(result.status, 0);
  assert.match(result.output, new RegExp(`nosh: invalid workdir: ${missingWorkdir}`));
  assert.equal(result.dockerRun, '');
});

test('Nosh image shell startup only invokes supported completion generators', () => {
  const dockerfile = fs.readFileSync(path.join(appRoot, 'Dockerfile.nosh'), 'utf8');
  const completionCalls = [...dockerfile.matchAll(
    /printf '%s\\n' '_nosh_source_completion ([^']+)'/g,
  )].map((match) => match[1]);

  assert.deepEqual(completionCalls, ['codex']);
});
