'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const http = require('node:http');
const os = require('node:os');
const path = require('node:path');
const test = require('node:test');
const { pathToFileURL } = require('node:url');

const appRoot = path.resolve(__dirname, '..');

async function importModule(relativePath) {
  return import(pathToFileURL(path.join(appRoot, relativePath)).href);
}

function tempBuildContext(t) {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'nosh-build-cli-'));
  fs.writeFileSync(path.join(directory, 'Dockerfile'), 'FROM scratch\n', {
    mode: 0o600,
  });
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  return directory;
}

async function captureStdout(callback) {
  const chunks = [];
  const original = process.stdout.write;
  process.stdout.write = function capture(chunk, encoding, done) {
    if (Buffer.isBuffer(chunk) || ArrayBuffer.isView(chunk)) {
      return original.call(this, chunk, encoding, done);
    }
    chunks.push(String(chunk));
    if (typeof encoding === 'function') {
      encoding();
    } else if (typeof done === 'function') {
      done();
    }
    return true;
  };
  try {
    const result = await callback();
    return { result, output: chunks.join('') };
  } finally {
    process.stdout.write = original;
  }
}

function fakeRuntimeService() {
  return {
    initialized: 0,
    async initialize() {
      this.initialized += 1;
    },
    health() {
      return { ok: true };
    },
    async listRuns() {
      return [{ runId: 'runtime-only' }];
    },
    async startRun(input) {
      return { runId: input.runId || 'runtime-started' };
    },
    async watchdogTick() {
      return [];
    },
  };
}

function fakeBuildService() {
  const calls = [];
  return {
    calls,
    initialized: 0,
    async initialize() {
      this.initialized += 1;
    },
    async listRuns() {
      calls.push(['list']);
      return [{ runId: 'build-existing', status: 'sensors-ready' }];
    },
    async begin(input) {
      calls.push(['begin', input]);
      return { ...input, status: 'sensors-ready' };
    },
    async finish(runId, input) {
      calls.push(['finish', runId, input]);
      if (runId === 'conflict') {
        const error = new Error('builder identity changed');
        error.code = 'GUARD_BUILD_IDENTITY_MISMATCH';
        error.statusCode = 409;
        throw error;
      }
      return { runId, status: 'complete', result: input };
    },
    async abort(runId, input) {
      calls.push(['abort', runId, input]);
      return { runId, status: 'aborted', reason: input.reason };
    },
    async acknowledgeExport(runId, input) {
      calls.push(['exported', runId, input]);
      return { runId, status: 'complete', portableExport: input };
    },
    async watchdogTick() {
      return [];
    },
  };
}

test('GuardClient exercises the daemon build lifecycle routes without runtime coupling', async (t) => {
  const { GuardClient } = await importModule('lib/guardd/client.js');
  const { createGuardServer } = await importModule('lib/guardd/server.js');
  const runtime = fakeRuntimeService();
  const builds = fakeBuildService();
  const { server } = await createGuardServer({
    service: runtime,
    buildService: builds,
    watchdogIntervalMs: 0,
  });
  t.after(() => new Promise((resolve) => server.close(resolve)));
  await new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', resolve);
  });
  const { port } = server.address();
  const client = new GuardClient({
    socketPath: '/not-used-by-test',
    requestImpl(options, callback) {
      const forwarded = { ...options };
      delete forwarded.socketPath;
      return http.request({
        ...forwarded,
        hostname: '127.0.0.1',
        port,
      }, callback);
    },
  });

  assert.deepEqual(await client.listBuildRuns(), {
    runs: [{ runId: 'build-existing', status: 'sensors-ready' }],
  });
  assert.deepEqual(
    await client.startBuildRun({ runId: 'build-new', mode: 'build-profile' }),
    { runId: 'build-new', mode: 'build-profile', status: 'sensors-ready' },
  );
  assert.deepEqual(
    await client.finishBuildRun('build with space', { buildExitCode: 0 }),
    {
      runId: 'build with space',
      status: 'complete',
      result: { buildExitCode: 0 },
    },
  );
  assert.deepEqual(
    await client.abortBuildRun('build-new', { reason: 'client exited' }),
    { runId: 'build-new', status: 'aborted', reason: 'client exited' },
  );
  const portableBundleHash = `sha256:${'e'.repeat(64)}`;
  assert.deepEqual(
    await client.acknowledgeBuildExport('build with space', {
      portableBundleHash,
    }),
    {
      runId: 'build with space',
      status: 'complete',
      portableExport: { portableBundleHash },
    },
  );

  assert.equal(runtime.initialized, 1);
  assert.equal(builds.initialized, 1);
  assert.deepEqual(builds.calls, [
    ['list'],
    ['begin', { runId: 'build-new', mode: 'build-profile' }],
    ['finish', 'build with space', { buildExitCode: 0 }],
    ['abort', 'build-new', { reason: 'client exited' }],
    ['exported', 'build with space', { portableBundleHash }],
  ]);

  await assert.rejects(
    client.finishBuildRun('conflict', { buildExitCode: 0 }),
    (error) =>
      error.code === 'GUARD_BUILD_IDENTITY_MISMATCH'
      && error.statusCode === 409
      && /builder identity changed/.test(error.message),
  );
});

test('build CLI maps structured options and explicit passthrough into profiler input', async () => {
  const { executeBuildCommand } = await importModule('scripts/nosh-guard.mjs');
  const calls = [];
  const dependencies = {
    async executeProfile(input, receivedDependencies) {
      calls.push([input, receivedDependencies]);
      return { status: 17, profileId: 'candidate-only' };
    },
  };
  const { result, output } = await captureStdout(() => executeBuildCommand(
    'profile',
    {
      file: 'Dockerfile.ci',
      tag: ['example:one', 'example:two'],
      target: 'release',
      platform: 'linux/amd64',
      'build-arg': ['TOKEN=secret'],
      'cache-mode': 'compare',
      depth: 'balanced',
      output: ['type=oci,dest=result.tar'],
      push: false,
      'no-load': true,
      'private-json': true,
    },
    '/workspace/project',
    ['--secret', 'id=npmrc,src=/private/npmrc'],
    dependencies,
  ));

  assert.equal(result, 17);
  assert.deepEqual(JSON.parse(output), {
    status: 17,
    profileId: 'candidate-only',
  });
  assert.equal(calls.length, 1);
  assert.equal(calls[0][1], dependencies);
  assert.deepEqual(calls[0][0], {
    mode: 'build-profile',
    context: '/workspace/project',
    file: 'Dockerfile.ci',
    variant: undefined,
    tag: ['example:one', 'example:two'],
    target: 'release',
    platform: 'linux/amd64',
    buildArg: ['TOKEN=secret'],
    cacheMode: 'compare',
    depth: 'balanced',
    push: false,
    output: ['type=oci,dest=result.tar'],
    noLoad: true,
    httpCapture: undefined,
    dryRun: false,
    passthrough: ['--secret', 'id=npmrc,src=/private/npmrc'],
  });
});

test('top-level build dry-run redacts secrets and honors the passthrough delimiter', async (t) => {
  const context = tempBuildContext(t);
  const { main } = await importModule('scripts/nosh-guard.mjs');
  const { result, output } = await captureStdout(() => main([
    'build',
    'profile',
    '--tag',
    'example:test',
    '--build-arg',
    'TOKEN=top-secret',
    '--dry-run',
    '--platform',
    'linux/amd64',
    context,
    '--',
    '--secret',
    'id=npmrc,src=/private/npmrc',
    '--ssh=default=/private/agent.sock',
  ]));

  assert.equal(result, 0);
  const resultDocument = JSON.parse(output);
  assert.equal(resultDocument.dryRun, true);
  assert.equal(resultDocument.mode, 'build-profile');
  assert.deepEqual(resultDocument.invocation.tags, ['example:test']);
  assert.deepEqual(resultDocument.invocation.buildArgNames, ['TOKEN']);
  assert.deepEqual(resultDocument.invocation.passthrough, [
    '--secret=id=npmrc,<redacted>',
    '--ssh=<redacted>',
  ]);
  assert.doesNotMatch(output, /top-secret|\/private\/npmrc|\/private\/agent\.sock/);
});

test('build network learning selects its dedicated profiler mode', async () => {
  const { executeBuildCommand } = await importModule('scripts/nosh-guard.mjs');
  let received;
  const { result } = await captureStdout(() => executeBuildCommand(
    'net-learn',
    { tag: ['example:test'], 'no-load': true, 'private-json': true },
    '/workspace/project',
    [],
    {
      async executeProfile(input) {
        received = input;
        return { status: 0 };
      },
    },
  ));
  assert.equal(result, 0);
  assert.equal(received.mode, 'build-net-learn');
  assert.equal(received.cacheMode, undefined);
  assert.equal(received.depth, undefined);
});

test('build network learning emits a redacted portable JSON result', async (t) => {
  const { createBuildEvidenceManifest } = await importModule(
    'lib/guardd/build-profile-artifacts.js',
  );
  const { executeBuildCommand } = await importModule('scripts/nosh-guard.mjs');
  const context = tempBuildContext(t);
  const contextStat = fs.statSync(context, { bigint: true });
  const manifest = createBuildEvidenceManifest({
    runId: 'build-json-result',
    mode: 'build-net-learn',
    generatedAt: '2026-08-22T00:00:02.000Z',
    startedAt: '2026-08-22T00:00:00.000Z',
    endedAt: '2026-08-22T00:00:02.000Z',
    project: {
      canonicalPath: context,
      dev: String(contextStat.dev),
      ino: String(contextStat.ino),
    },
    builder: {},
    build: {
      success: true,
      exitCode: 0,
      platform: 'linux/amd64',
      cacheMode: 'cold',
      depth: 'balanced',
      passes: [{ name: 'cold', success: true, exitCode: 0, durationMs: 2_000 }],
    },
    coverage: {
      builderIdentityStable: true,
      exclusiveBuilderLease: true,
      parentObserved: true,
      cleanupComplete: true,
      freshBuilder: true,
      forcedSourcePulls: true,
      cacheImportsDisabled: true,
      allReachableStepsExecuted: true,
    },
    sources: [],
    metrics: { retainedCount: 7, raw: 'private metric payload' },
    observations: {
      retainedSignal: 'present',
      command: 'RUN printf top-secret',
      path: '/private/build/context',
      network: {},
    },
    incompleteReasons: ['private artifact at /private/build/evidence.json'],
  });
  const { result, output } = await captureStdout(() => executeBuildCommand(
    'net-learn',
    { json: true },
    context,
    [],
    {
      async executeProfile() {
        return {
          status: 23,
          bundleDir: '/private/build/profile',
          portableBundleDir: '/private/build/portable',
          manifest,
          candidate: null,
        };
      },
    },
  ));

  assert.equal(result, 23);
  const document = JSON.parse(output);
  assert.equal(document.kind, 'NoshBuildPortableReport');
  assert.equal(document.mode, 'build-net-learn');
  assert.equal(document.summary.status, 'incomplete');
  assert.equal(document.metrics.retainedCount, 7);
  assert.equal(document.metrics.raw, undefined);
  assert.equal(document.observations.retainedSignal, 'present');
  assert.equal(document.observations.command, undefined);
  assert.equal(document.observations.path, undefined);
  assert.ok(document.evidence.incompleteReasons.includes('[redacted-path]'));
  assert.doesNotMatch(
    output,
    /top-secret|private metric payload|\/private\/build|bundleDir|portableBundleDir/,
  );
});

test('top-level build network learning accepts JSON mode', async (t) => {
  const context = tempBuildContext(t);
  const { main } = await importModule('scripts/nosh-guard.mjs');
  const { result, output } = await captureStdout(() => main([
    'build',
    'net',
    'learn',
    '--json',
    '--dry-run',
    context,
  ]));

  assert.equal(result, 0);
  const document = JSON.parse(output);
  assert.equal(document.dryRun, true);
  assert.equal(document.mode, 'build-net-learn');
});

test('failed human network learning exposes its preserved private bundle without corrupting machine output', async () => {
  const { emitPreservedBuildBundleNotice } = await importModule('scripts/nosh-guard.mjs');
  const error = { bundleDir: '/tmp/nosh-build-evidence-preserved' };
  const human = [];
  assert.equal(
    emitPreservedBuildBundleNotice(error, ['build', 'net', 'learn'], human.push.bind(human)),
    true,
  );
  assert.deepEqual(human, ['Private bundle: /tmp/nosh-build-evidence-preserved\n']);

  for (const mode of ['--json', '--private-json', '--dry-run']) {
    const machine = [];
    assert.equal(
      emitPreservedBuildBundleNotice(
        error,
        ['build', 'net', 'learn', mode],
        machine.push.bind(machine),
      ),
      false,
    );
    assert.deepEqual(machine, []);
  }
});

test('build network learning CLI rejects cache and collector-depth overrides', async (t) => {
  const context = tempBuildContext(t);
  const { main } = await importModule('scripts/nosh-guard.mjs');
  await assert.rejects(
    main([
      'build',
      'net',
      'learn',
      '--cache-mode',
      'warm',
      '--dry-run',
      context,
    ]),
    /does not support --cache-mode/,
  );
  await assert.rejects(
    main([
      'build',
      'net',
      'learn',
      '--depth',
      'deep',
      '--dry-run',
      context,
    ]),
    /does not support --depth/,
  );
});

test('build lifecycle authority is explicitly root-only', async () => {
  const { assertRootManagement } = await importModule('scripts/nosh-guard.mjs');
  assert.doesNotThrow(() => assertRootManagement(() => 0));
  assert.throws(
    () => assertRootManagement(() => 1000),
    (error) => error.code === 'GUARD_ROOT_REQUIRED' && /explicit root authority/.test(error.message),
  );
});

test('hidden privileged lifecycle command rejects management-socket overrides', async () => {
  const { main } = await importModule('scripts/nosh-guard.mjs');
  await assert.rejects(
    main(['build-session', 'begin', '--socket', '/tmp/user-controlled.sock']),
    /build-session does not support --socket/,
  );
});

test('privileged build helper is constrained to lifecycle RPCs and invoking-user ownership', () => {
  const source = fs.readFileSync(
    path.join(appRoot, 'scripts', 'nosh-guard.mjs'),
    'utf8',
  );
  const start = source.indexOf('async function commandBuildSession(argv)');
  const end = source.indexOf('\nasync function commandProfileCompile', start);
  assert.ok(start >= 0 && end > start);
  const contract = source.slice(start, end);

  assert.match(source, /const PRIVILEGED_BUILD_SOCKET = '\/run\/nosh-guardd\.sock';/);
  assert.match(source, /const PRIVILEGED_BUILD_STATE_DIR = '\/var\/lib\/nosh-guard';/);
  assert.match(source, /const BUILD_SESSION_FLAGS = new Set\(\);/);
  assert.ok(
    contract.indexOf('assertRootManagement()')
      < contract.indexOf('assertTrustedBuildManagementSocket()'),
  );
  assert.ok(
    contract.indexOf('assertTrustedBuildManagementSocket()')
      < contract.indexOf('readBoundedStdin()'),
  );
  assert.match(contract, /resolveInvokingUser\(\)/);
  assert.match(contract, /new GuardClient\(\{ socketPath: PRIVILEGED_BUILD_SOCKET \}\)/);
  assert.match(contract, /Number\(input\.clientUid\) !== invokingUser\.uid/);
  assert.match(contract, /Number\(input\.clientGid\) !== invokingUser\.gid/);
  assert.match(contract, /client\.startBuildRun\(input\)/);
  assert.match(contract, /assertOwnedBuildSession\(client, input\.runId, invokingUser\)/);
  assert.match(contract, /client\.finishBuildRun\(input\.runId, input\.result \|\| \{\}\)/);
  assert.match(contract, /client\.abortBuildRun\(input\.runId, \{ reason: input\.reason \}\)/);
  assert.match(contract, /client\.acknowledgeBuildExport\(input\.runId/);
  assert.match(contract, /stageBuildEvidenceForUser/);
  assert.doesNotMatch(contract, /options\.socket|spawnSync|docker buildx|AdapterController/);

  const copyStart = source.indexOf('async function stageBuildEvidenceForUser(');
  const copyEnd = source.indexOf('\nasync function assertTrustedBuildManagementSocket', copyStart);
  assert.ok(copyStart >= 0 && copyEnd > copyStart);
  const copyContract = source.slice(copyStart, copyEnd);
  assert.match(
    copyContract,
    /path\.join\(\s*PRIVILEGED_BUILD_STATE_DIR,\s*'build-evidence',\s*run\.runId,\s*\)/,
  );
  assert.match(copyContract, /source !== expectedSource/);
  assert.match(copyContract, /fs\.mkdtemp\(path\.join\(exportRoot, 'nosh-build-evidence-'\)\)/);
  assert.doesNotMatch(copyContract, /exportDirectory|destinationParent/);

  const orchestratorSource = fs.readFileSync(
    path.join(appRoot, 'lib/guardd/build-orchestrator.js'),
    'utf8',
  );
  const invokerStart = orchestratorSource.indexOf('function defaultPrivilegedInvoker(');
  const invokerEnd = orchestratorSource.indexOf('\nfunction dockerInfo(', invokerStart);
  assert.ok(invokerStart >= 0 && invokerEnd > invokerStart);
  const invokerContract = orchestratorSource.slice(invokerStart, invokerEnd);
  assert.match(invokerContract, /\['build-session', action\]/);
  assert.match(invokerContract, /\['--', guardBin, 'build-session', action\]/);
  assert.doesNotMatch(invokerContract, /--socket|NOSH_GUARD_SOCKET|options\.socket/);
});
