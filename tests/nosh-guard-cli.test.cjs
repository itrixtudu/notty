'use strict';

const assert = require('node:assert/strict');
const childProcess = require('node:child_process');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const test = require('node:test');
const { pathToFileURL } = require('node:url');

const appRoot = path.resolve(__dirname, '..');

async function cliModule() {
  return import(
    pathToFileURL(path.join(appRoot, 'scripts', 'nosh-guard.mjs')).href
  );
}

function guardedRun(overrides = {}) {
  return {
    runId: 'run-interactive',
    name: 'interactive',
    action: 'start',
    persist: false,
    ...overrides,
  };
}

function attachment() {
  return {
    runId: 'run-interactive',
    name: 'interactive',
    status: 'running',
    containerId: 'a'.repeat(64),
    workdir: '/workspace',
    attachment: {
      validated: true,
      dockerSocket: '/run/docker-test.sock',
    },
  };
}

test('interactive guarded start revalidates, attaches, stops, and removes', async () => {
  const { executeRunRequest } = await cliModule();
  const calls = [];
  const client = {
    async startRun(request) {
      calls.push(['start', request.name]);
      return attachment();
    },
    async action(identifier, action) {
      calls.push([action, identifier]);
      return attachment();
    },
  };
  const spawns = [];
  const status = await executeRunRequest(guardedRun(), {
    client,
    interactive: true,
    spawnSyncImpl(command, argv, options) {
      spawns.push({ command, argv, options });
      return { status: 7, signal: null };
    },
  });

  assert.equal(status, 7);
  assert.deepEqual(calls, [
    ['start', 'interactive'],
    ['attach', 'run-interactive'],
    ['stop', 'run-interactive'],
    ['rm', 'run-interactive'],
  ]);
  assert.equal(spawns.length, 1);
  assert.equal(spawns[0].command, 'docker');
  assert.deepEqual(spawns[0].argv, [
    '--host',
    'unix:///run/docker-test.sock',
    'exec',
    '-it',
    '--workdir',
    '/workspace',
    'a'.repeat(64),
    '/bin/bash',
  ]);
  assert.deepEqual(spawns[0].options, { stdio: 'inherit' });
});

test('interactive guarded start honors persist after exact attach validation', async () => {
  const { executeRunRequest } = await cliModule();
  const calls = [];
  const client = {
    async startRun() {
      calls.push('start');
      return attachment();
    },
    async action(identifier, action) {
      calls.push(action);
      return attachment();
    },
  };

  const status = await executeRunRequest(
    guardedRun({ persist: true }),
    {
      client,
      interactive: true,
      spawnSyncImpl() {
        return { status: 0, signal: null };
      },
    },
  );

  assert.equal(status, 0);
  assert.deepEqual(calls, ['start', 'attach']);
});

test('interactive guarded start never opens a shell after revalidation failure', async () => {
  const { executeRunRequest } = await cliModule();
  const calls = [];
  const client = {
    async startRun() {
      calls.push('start');
      return attachment();
    },
    async action(identifier, action) {
      calls.push(action);
      if (action === 'attach') {
        const error = new Error('runtime identity changed');
        error.code = 'GUARD_ATTACH_REVALIDATION_FAILED';
        throw error;
      }
      return { runId: identifier, status: action };
    },
  };
  let spawned = false;

  await assert.rejects(
    executeRunRequest(guardedRun(), {
      client,
      interactive: true,
      spawnSyncImpl() {
        spawned = true;
        return { status: 0, signal: null };
      },
    }),
    (error) => error.code === 'GUARD_ATTACH_REVALIDATION_FAILED',
  );
  assert.equal(spawned, false);
  assert.deepEqual(calls, ['start', 'attach', 'stop', 'rm']);
});

test('non-TTY guarded start preserves JSON/API behavior without attaching', async () => {
  const { executeRunRequest } = await cliModule();
  const calls = [];
  const printed = [];
  const started = attachment();
  const client = {
    async startRun() {
      calls.push('start');
      return started;
    },
    async action() {
      throw new Error('non-interactive start must not attach');
    },
  };

  const status = await executeRunRequest(guardedRun(), {
    client,
    interactive: false,
    print(value) {
      printed.push(value);
    },
  });

  assert.equal(status, 0);
  assert.deepEqual(calls, ['start']);
  assert.deepEqual(printed, [started]);
});

test('guard management requires explicit root and honors socket overrides', async () => {
  const {
    assertRootManagement,
    guardClientForOptions,
  } = await cliModule();

  assert.throws(
    () => assertRootManagement(() => 1001),
    (error) =>
      error.code === 'GUARD_ROOT_REQUIRED'
      && /explicit root authority/.test(error.message),
  );
  assert.doesNotThrow(() => assertRootManagement(() => 0));
  assert.equal(
    guardClientForOptions({ socket: '/run/test-guard.sock' }).socketPath,
    '/run/test-guard.sock',
  );
});

test('grant CLI rejects revision-scoped grants', async () => {
  const { main } = await cliModule();
  await assert.rejects(
    main([
      'grant',
      'create',
      '--profile-revision',
      'candidate-1',
      '--destination',
      'registry.npmjs.org',
      '--protocol',
      'tcp',
      '--ports',
      '443',
      '--reason',
      'revision-wide access',
    ]),
    /grant create does not support --profile-revision/,
  );
});

test('doctor CLI and package command faithfully expose the full doctor', () => {
  const direct = childProcess.spawnSync(
    path.join(appRoot, 'bin', 'nosh-guard'),
    ['doctor', '--help'],
    { cwd: appRoot, encoding: 'utf8' },
  );
  assert.equal(direct.status, 0, direct.stderr);
  assert.match(direct.stdout, /Read-only host readiness checks/);
  assert.match(direct.stdout, /--runner-image IMAGE/);

  const packaged = childProcess.spawnSync(
    'npm',
    ['run', '--silent', 'guard:doctor', '--', '--help'],
    { cwd: appRoot, encoding: 'utf8' },
  );
  assert.equal(packaged.status, 0, packaged.stderr);
  assert.equal(packaged.stdout, direct.stdout);

  const invalid = childProcess.spawnSync(
    path.join(appRoot, 'bin', 'nosh-guard'),
    ['doctor', '--not-a-doctor-option'],
    { cwd: appRoot, encoding: 'utf8' },
  );
  assert.equal(invalid.status, 2);
  assert.match(invalid.stderr, /unknown option: --not-a-doctor-option/);
});

test('checkout doctor parses JSON without invoking host Node', () => {
  const source = fs.readFileSync(
    path.join(appRoot, 'scripts', 'nosh-guard-doctor.sh'),
    'utf8',
  );
  assert.doesNotMatch(source, /command -v node|(?:^|\s)node\s+-e/m);
  assert.match(source, /NOSH_GUARD_DOCTOR_PYTHON_BIN/);
  assert.match(source, /json\.load\(selected\)/);
});

test('doctor verifies runner, legacy gateway, and scoped eBPF contracts by mode', (t) => {
  const fakeBin = fs.mkdtempSync(
    path.join(os.tmpdir(), 'nosh-guard-doctor-test-'),
  );
  t.after(() => fs.rmSync(fakeBin, { recursive: true, force: true }));
  const dockerPath = path.join(fakeBin, 'docker');
  const dockerLog = path.join(fakeBin, 'docker.log');
  const scopedLoaderPath = path.join(fakeBin, 'nosh-egress-loader');
  fs.writeFileSync(
    dockerPath,
    [
      '#!/bin/sh',
      'if [ "$1" = "info" ]; then exit 0; fi',
      'if [ "$1" = "image" ] && [ "$2" = "inspect" ]; then',
      '  printf "%s\\n" "${5:-$3}" >>"$FAKE_DOCKER_LOG"',
      '  if [ "$3" = "--format" ]; then',
      '    if [ "$5" = "nosh-egress:test" ]; then',
      '      printf "%s\\n" "${FAKE_EGRESS_ABI:-}"',
      '    else',
      '      printf "%s\\n" "${FAKE_RUNNER_ABI:-}"',
      '    fi',
      '  fi',
      '  exit 0',
      'fi',
      'exit 1',
      '',
    ].join('\n'),
    { mode: 0o700 },
  );
  fs.writeFileSync(
    scopedLoaderPath,
    [
      '#!/bin/sh',
      'if [ "$1" = "--version" ]; then',
      '  echo "nosh-egress-loader 2 schema 2 map-abi 2 program-abi 2"',
      '  exit 0',
      'fi',
      'if [ "$1" = "health" ]; then exit 0; fi',
      'exit 2',
      '',
    ].join('\n'),
    { mode: 0o700 },
  );
  const doctorPath = path.join(appRoot, 'scripts', 'nosh-guard-doctor.sh');
  const runDoctor = (runnerAbi, mode = 'learn', egressAbi = '1') =>
    childProcess.spawnSync(
      'bash',
      [
        doctorPath,
        '--mode',
        mode,
        '--runner-image',
        'nosh:test',
        '--egress-image',
        'nosh-egress:test',
        '--nosh-egress-loader',
        scopedLoaderPath,
      ],
      {
        cwd: appRoot,
        encoding: 'utf8',
        env: {
          ...process.env,
          FAKE_EGRESS_ABI: egressAbi,
          FAKE_RUNNER_ABI: runnerAbi,
          FAKE_DOCKER_LOG: dockerLog,
          PATH: `${fakeBin}:/usr/bin:/bin`,
        },
      },
    );

  const matching = runDoctor('1');
  assert.match(
    matching.stdout,
    /\[PASS\] guarded runner image ABI matches io\.notty\.guard\.runner-abi=1/,
  );
  assert.match(
    matching.stdout,
    /\[PASS\] trusted egress image ABI matches io\.notty\.guard\.egress-abi=1/,
  );

  const mismatched = runDoctor('2');
  assert.match(
    mismatched.stdout,
    /\[FAIL\] guarded runner image ABI mismatch: expected io\.notty\.guard\.runner-abi=1, got 2/,
  );

  const staleEgress = runDoctor('1', 'learn', '0');
  assert.notEqual(staleEgress.status, 0);
  assert.match(
    staleEgress.stdout,
    /\[FAIL\] trusted egress image ABI mismatch: expected io\.notty\.guard\.egress-abi=1, got 0/,
  );

  fs.writeFileSync(dockerLog, '');
  const scoped = runDoctor('1', 'egress-learn', '0');
  assert.match(
    scoped.stdout,
    /\[SKIP\] the legacy gateway image is not used by egress-learn/,
  );
  assert.match(
    scoped.stdout,
    /\[PASS\] nosh-egress loader, evidence schema, map ABI, and program ABI match version 2/,
  );
  assert.doesNotMatch(fs.readFileSync(dockerLog, 'utf8'), /nosh-egress:test/);

  const enforce = runDoctor('1', 'enforce');
  assert.notEqual(enforce.status, 0);
  assert.match(
    enforce.stdout,
    /\[FAIL\] standalone enforce admission is disabled until a backend evaluates the compiled ingress policy/,
  );
});

test('run rejects unknown and legacy-auth flags before management access', () => {
  for (const extra of [
    ['--unexpected', 'value'],
    ['--noauth'],
  ]) {
    const result = childProcess.spawnSync(
      path.join(appRoot, 'bin', 'nosh-guard'),
      [
        'run',
        '--mode',
        'learn',
        '--action',
        'attach',
        '--image',
        'nosh',
        '--name',
        'unknown-flag-test',
        '--workdir',
        appRoot,
        ...extra,
      ],
      { cwd: appRoot, encoding: 'utf8' },
    );
    assert.equal(result.status, 1);
    assert.match(result.stderr, /run does not support/);
  }
});

test('run rejects Docker network and publish bypasses before management access', () => {
  for (const extra of [
    ['--network', 'bridge'],
    ['--publish', '127.0.0.1:3300'],
  ]) {
    const result = childProcess.spawnSync(
      path.join(appRoot, 'bin', 'nosh-guard'),
      [
        'run',
        '--mode',
        'learn',
        '--action',
        'start',
        '--image',
        'nosh',
        '--name',
        'bypass-test',
        '--workdir',
        appRoot,
        '--dry-run',
        ...extra,
      ],
      { cwd: appRoot, encoding: 'utf8' },
    );
    assert.equal(result.status, 1);
    assert.match(
      result.stderr,
      /cannot (?:publish Docker ports|select a Docker network)/,
    );
  }
});
