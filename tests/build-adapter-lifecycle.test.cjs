'use strict';

const assert = require('node:assert/strict');
const { EventEmitter } = require('node:events');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { PassThrough } = require('node:stream');
const test = require('node:test');
const { pathToFileURL } = require('node:url');

const appRoot = path.resolve(__dirname, '..');

async function adapterModule() {
  return import(
    pathToFileURL(path.join(appRoot, 'lib/guardd/adapters.js')).href
  );
}

function fixture(t, adapter = {}) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'nosh-build-adapter-'));
  const evidenceDir = path.join(root, 'evidence');
  const configPath = path.join(root, 'adapters.json');
  fs.writeFileSync(
    configPath,
    `${JSON.stringify({
      schemaVersion: 1,
      adapters: [{
        name: 'collector',
        requiredModes: ['build-profile'],
        attach: { command: 'collector', args: [] },
        detach: { command: 'true', args: [] },
        readiness: {
          stream: 'stderr',
          match: { recordKind: 'status', status: 'ready' },
          timeoutMs: 1_000,
        },
        startupGraceMs: 1,
        cleanupCritical: true,
        longRunning: true,
        ...adapter,
      }],
    })}\n`,
    { mode: 0o600 },
  );
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  return { root, evidenceDir, configPath };
}

class FakeChild extends EventEmitter {
  constructor(pid, options = {}) {
    super();
    this.pid = pid;
    this.stdout = new PassThrough();
    this.stderr = new PassThrough();
    this.exitCode = null;
    this.signalCode = null;
    this.killSignals = [];
    this.killExitCode = options.killExitCode;
    this.ignoreSignals = new Set(options.ignoreSignals || []);
    this.outputOnKill = options.outputOnKill || null;
    this.outputOnKillWritten = false;
    this.closed = false;
  }

  start() {
    queueMicrotask(() => {
      this.emit('spawn');
      this.stderr.write('{"recordKind":"status","status":"ready"}\n');
    });
  }

  close(code, signal = null) {
    if (this.closed) return;
    this.closed = true;
    this.exitCode = Number.isInteger(code) ? code : null;
    this.signalCode = signal;
    this.stdout.end();
    this.stderr.end();
    setImmediate(() => {
      this.emit('exit', this.exitCode, this.signalCode);
      this.emit('close', this.exitCode, this.signalCode);
    });
  }

  kill(signal) {
    this.killSignals.push(signal);
    if (this.outputOnKill && !this.outputOnKillWritten) {
      this.outputOnKillWritten = true;
      this.stdout.write(this.outputOnKill);
    }
    if (this.ignoreSignals.has(signal)) return true;
    if (this.killExitCode != null) {
      this.close(this.killExitCode, null);
    } else {
      this.close(null, signal);
    }
    return true;
  }

  unref() {}
}

async function eventually(predicate, message) {
  const deadline = Date.now() + 2_000;
  while (Date.now() < deadline) {
    const result = predicate();
    if (result) return result;
    await new Promise((resolve) => setTimeout(resolve, 10));
  }
  throw new Error(message);
}

function controllerOptions(selected, child, overrides = {}) {
  return {
    configPath: selected.configPath,
    spawnImpl() {
      child.start();
      return child;
    },
    spawnSyncImpl() {
      return { status: 0, stdout: '', stderr: '' };
    },
    processStartTimeProvider: async () => 'fake-start-time',
    signalProcessImpl(_pid, signal) {
      return child.kill(signal);
    },
    ...overrides,
  };
}

function startupFailureChild(pid, diagnostics, exitCode = 1) {
  const child = new FakeChild(pid);
  child.start = () => {
    queueMicrotask(() => {
      child.emit('spawn');
      child.exitCode = exitCode;
      child.emit('exit', exitCode, null);
      setTimeout(() => {
        child.closed = true;
        child.stdout.end();
        child.stderr.end(diagnostics);
        setImmediate(() => child.emit('close', exitCode, null));
      }, 25);
    });
  };
  return child;
}

test('optional collector pre-spawn failure is retained without aborting build learning', async (t) => {
  const selected = fixture(t, {
    requiredModes: [],
    modes: ['build-net-learn'],
    evidenceRequired: false,
  });
  const child = new FakeChild(41000);
  const snapshots = [];
  const { AdapterController } = await adapterModule();
  const controller = new AdapterController(controllerOptions(selected, child, {
    spawnImpl() {
      throw new Error('injected synchronous spawn failure');
    },
  }));
  const context = {
    runId: 'optional-pre-spawn-failure',
    evidenceDir: selected.evidenceDir,
  };
  const attached = await controller.attach('build-net-learn', context, {
    async onAttached(current) {
      snapshots.push(JSON.parse(JSON.stringify(current)));
    },
  });

  assert.equal(attached.length, 1);
  assert.equal(attached[0].required, false);
  assert.equal(attached[0].evidenceRequired, false);
  assert.equal(attached[0].startupCleanupOk, true);
  assert.match(attached[0].error, /optional adapter setup failed/);
  assert.match(attached[0].error, /injected synchronous spawn failure/);
  assert.equal(Number.isSafeInteger(attached[0].pid), false);
  assert.equal(snapshots.at(-1)[0].error, attached[0].error);

  const detached = await controller.detach({ adapters: attached }, context);
  assert.equal(detached.some((entry) => entry.ok === true), true);
});

test('optional cleanup-critical collector is force-killed after readiness failure', async (t) => {
  const selected = fixture(t, {
    requiredModes: [],
    modes: ['build-net-learn'],
    evidenceRequired: false,
    readiness: {
      stream: 'stderr',
      match: { recordKind: 'status', status: 'ready' },
      timeoutMs: 1,
    },
    startupGraceMs: 0,
    detachTimeoutMs: 1,
  });
  const child = new FakeChild(41011, { ignoreSignals: ['SIGTERM'] });
  child.start = () => queueMicrotask(() => child.emit('spawn'));
  const signals = [];
  const { AdapterController } = await adapterModule();
  const controller = new AdapterController(controllerOptions(selected, child, {
    limitKillGraceMs: 100,
    signalProcessImpl(pid, signal) {
      signals.push({ pid, signal });
      return child.kill(signal);
    },
  }));
  const context = {
    runId: 'optional-readiness-force-kill',
    evidenceDir: selected.evidenceDir,
  };

  const attached = await controller.attach('build-net-learn', context);

  assert.equal(attached.length, 1);
  assert.equal(attached[0].required, false);
  assert.equal(attached[0].startupCleanupOk, true);
  assert.equal(attached[0].startupCleanupForced, true);
  assert.equal(attached[0].startupCleanupSignal, 'SIGKILL');
  assert.match(attached[0].error, /did not report readiness/);
  assert.deepEqual(signals, [
    { pid: 41011, signal: 'SIGTERM' },
    { pid: -41011, signal: 'SIGKILL' },
  ]);
});

test('optional cleanup-critical collector aborts when startup cleanup cannot be proven', async (t) => {
  const selected = fixture(t, {
    requiredModes: [],
    modes: ['build-net-learn'],
    evidenceRequired: false,
    readiness: {
      stream: 'stderr',
      match: { recordKind: 'status', status: 'ready' },
      timeoutMs: 1,
    },
    startupGraceMs: 0,
    detachTimeoutMs: 1,
  });
  const child = new FakeChild(41012, {
    ignoreSignals: ['SIGTERM', 'SIGKILL'],
  });
  child.start = () => queueMicrotask(() => child.emit('spawn'));
  const signals = [];
  const { AdapterController } = await adapterModule();
  const controller = new AdapterController(controllerOptions(selected, child, {
    limitKillGraceMs: 1,
    signalProcessImpl(pid, signal) {
      signals.push({ pid, signal });
      return child.kill(signal);
    },
  }));
  const context = {
    runId: 'optional-readiness-cleanup-failed',
    evidenceDir: selected.evidenceDir,
  };
  let startupError;

  await assert.rejects(
    controller.attach('build-net-learn', context),
    (error) => {
      startupError = error;
      assert.match(error.message, /could not be proven stopped/);
      return true;
    },
  );

  assert.deepEqual(signals, [
    { pid: 41012, signal: 'SIGTERM' },
    { pid: -41012, signal: 'SIGKILL' },
  ]);
  assert.equal(startupError.attachedAdapters.length, 1);
  assert.equal(startupError.attachedAdapters[0].startupCleanupOk, false);
  assert.equal(startupError.attachedAdapters[0].startupCleanupForced, true);
  assert.match(
    startupError.attachedAdapters[0].startupCleanupError,
    /did not exit after SIGTERM and SIGKILL/,
  );
  child.close(null, 'SIGKILL');
});

test('required collector startup failure includes drained JSON diagnostics', async (t) => {
  const selected = fixture(t);
  const verifierDiagnostic = [
    '-- BEGIN PROG LOAD LOG --',
    'verifier at insn 123: Invalid argument',
    '-- END PROG LOAD LOG --',
  ].join('\n');
  const diagnostics = [
    'x'.repeat(70 * 1024),
    JSON.stringify({
      recordKind: 'diagnostic',
      level: 'warning',
      component: 'libbpf',
      message: verifierDiagnostic,
    }),
    JSON.stringify({
      recordKind: 'diagnostic',
      level: 'warning',
      component: 'libbpf',
      message: 'failed to load object',
    }),
    JSON.stringify({
      recordKind: 'status',
      status: 'error',
      message: 'older collector error',
    }),
    JSON.stringify({
      recordKind: 'status',
      status: 'error',
      message: 'Invalid argument',
    }),
    '',
  ].join('\n');
  const child = startupFailureChild(41008, diagnostics);
  const { AdapterController } = await adapterModule();
  const controller = new AdapterController(controllerOptions(selected, child));
  const context = {
    runId: 'startup-diagnostics',
    evidenceDir: selected.evidenceDir,
  };
  let startupError;

  await assert.rejects(
    controller.attach('build-profile', context),
    (error) => {
      startupError = error;
      assert.match(
        error.message,
        /status error: Invalid argument/,
      );
      assert.match(
        error.message,
        /libbpf diagnostic: -- BEGIN PROG LOAD LOG -- verifier at insn 123: Invalid argument -- END PROG LOAD LOG --/,
      );
      assert.doesNotMatch(error.message, /older collector error/);
      assert.equal(error.message.match(/status error:/g)?.length, 1);
      return true;
    },
  );

  assert.equal(startupError.attachedAdapters.length, 1);
  assert.equal(
    fs.readFileSync(
      startupError.attachedAdapters[0].diagnosticsPath,
      'utf8',
    ),
    diagnostics,
  );
  const detached = await controller.detach(
    { adapters: startupError.attachedAdapters },
    context,
  );
  assert.ok(detached.some((entry) => entry.cleanupOk === true));
});

test('live collector buffered ready then error rejects with diagnostics', async (t) => {
  const selected = fixture(t);
  const child = new FakeChild(41009);
  child.start = () => {
    queueMicrotask(() => {
      child.emit('spawn');
      setTimeout(() => {
        child.stderr.write(`${[
          JSON.stringify({
            recordKind: 'diagnostic',
            level: 'error',
            component: 'libbpf',
            message: 'attach_btf_id 55 rejected by cgroup policy',
          }),
          JSON.stringify({
            recordKind: 'status',
            status: 'ready',
          }),
          JSON.stringify({
            recordKind: 'status',
            status: 'error',
            message: 'cannot attach cgroup/connect4: Operation not permitted',
          }),
        ].join('\n')}\n`);
      }, 10);
    });
  };
  const { AdapterController } = await adapterModule();
  const controller = new AdapterController(controllerOptions(selected, child));
  const context = {
    runId: 'live-startup-status-error',
    evidenceDir: selected.evidenceDir,
  };
  let startupError;

  await assert.rejects(
    controller.attach('build-profile', context),
    (error) => {
      startupError = error;
      assert.match(
        error.message,
        /status error: cannot attach cgroup\/connect4: Operation not permitted/,
      );
      assert.match(
        error.message,
        /libbpf diagnostic: attach_btf_id 55 rejected by cgroup policy/,
      );
      assert.equal(error.message.match(/status error:/g)?.length, 1);
      return true;
    },
  );

  const detached = await controller.detach(
    { adapters: startupError.attachedAdapters },
    context,
  );
  assert.ok(detached.some((entry) => entry.cleanupOk === true));
});

test('collector exit status is persisted and survives supervisor restart', async (t) => {
  const selected = fixture(t);
  const child = new FakeChild(41001);
  const snapshots = [];
  const { AdapterController } = await adapterModule();
  const controller = new AdapterController(
    controllerOptions(selected, child),
  );
  const context = { runId: 'exit-status', evidenceDir: selected.evidenceDir };
  const attached = await controller.attach('build-profile', context, {
    async onAttached(current) {
      snapshots.push(JSON.parse(JSON.stringify(current)));
    },
  });

  child.close(7);
  const persisted = await eventually(
    () => snapshots.findLast((snapshot) => snapshot[0]?.exitStatusKnown),
    'collector exit status was not persisted',
  );
  assert.equal(persisted[0].exitCode, 7);
  assert.equal(persisted[0].exitSignal, null);

  const restarted = new AdapterController({
    configPath: selected.configPath,
    spawnSyncImpl() {
      return { status: 0, stdout: '', stderr: '' };
    },
    processStartTimeProvider: async () => {
      throw Object.assign(new Error('process exited'), { code: 'ENOENT' });
    },
  });
  const [health] = await restarted.runtimeHealth({
    mode: 'build-profile',
    adapters: persisted,
  }, context);
  assert.equal(health.ok, false);
  assert.match(health.error, /status 7/);

  const detach = await restarted.detach({ adapters: persisted }, context);
  const processResult = detach.find((result) => result.exitStatusKnown);
  assert.equal(processResult.exitCode, 7);
  assert.equal(processResult.cleanupOk, true);
  assert.equal(processResult.ok, false);
  assert.match(processResult.error, /status 7/);
  assert.equal(attached[0].exitStatusKnown, true);
});

test('supervised detach waits for a clean exact collector exit status', async (t) => {
  const selected = fixture(t);
  const child = new FakeChild(41002, { killExitCode: 0 });
  const { AdapterController } = await adapterModule();
  const controller = new AdapterController(
    controllerOptions(selected, child),
  );
  const context = { runId: 'clean-detach', evidenceDir: selected.evidenceDir };
  const attached = await controller.attach('build-profile', context);

  const detach = await controller.detach({ adapters: attached }, context);
  const processResult = detach.find((result) => result.exitStatusKnown);
  assert.deepEqual(child.killSignals, ['SIGTERM']);
  assert.equal(processResult.exitCode, 0);
  assert.equal(processResult.exitSignal, null);
  assert.equal(processResult.cleanupOk, true);
});

test('signal-oriented third-party adapters may accept supervised SIGTERM', async (t) => {
  const selected = fixture(t);
  const child = new FakeChild(41007);
  const { AdapterController } = await adapterModule();
  const controller = new AdapterController(
    controllerOptions(selected, child),
  );
  const context = { runId: 'signal-detach', evidenceDir: selected.evidenceDir };
  const attached = await controller.attach('build-profile', context);

  const detach = await controller.detach({ adapters: attached }, context);
  const processResult = detach.find((result) => result.exitStatusKnown);
  assert.equal(processResult.requireCleanExit, false);
  assert.equal(processResult.exitSignal, 'SIGTERM');
  assert.equal(processResult.cleanupOk, true);
  assert.equal(processResult.ok, true);
});

test('live adapter output is capped and the evidence failure is persisted', async (t) => {
  const selected = fixture(t, { maxOutputBytes: 32 });
  const child = new FakeChild(41003);
  const snapshots = [];
  const { AdapterController } = await adapterModule();
  const controller = new AdapterController(controllerOptions(selected, child, {
    outputMaxBytes: 64,
    diagnosticsMaxBytes: 64,
    limitKillGraceMs: 10,
  }));
  const context = { runId: 'bounded-output', evidenceDir: selected.evidenceDir };
  const attached = await controller.attach('build-profile', context, {
    async onAttached(current) {
      snapshots.push(JSON.parse(JSON.stringify(current)));
    },
  });

  child.stdout.write(Buffer.alloc(256, 0x61));
  const persisted = await eventually(
    () => snapshots.findLast(
      (snapshot) => snapshot[0]?.evidenceFailures?.length,
    ),
    'collector evidence overflow was not persisted',
  );
  await eventually(
    () => attached[0].exitStatusKnown === true,
    'collector did not terminate after evidence overflow',
  );

  assert.equal(fs.statSync(attached[0].logPath).size, 32);
  assert.equal(persisted[0].evidenceFailures[0].stream, 'stdout');
  assert.match(persisted[0].error, /exceeded 32 bytes/);
  assert.deepEqual(child.killSignals, ['SIGTERM']);

  const [health] = await controller.runtimeHealth({
    mode: 'build-profile',
    adapters: attached,
  }, context);
  assert.equal(health.ok, false);
  assert.match(health.error, /exceeded 32 bytes/);
});

test('required adapter exit emits an immediate containment notification', async (t) => {
  const selected = fixture(t);
  const child = new FakeChild(41010);
  const { AdapterController } = await adapterModule();
  const controller = new AdapterController(controllerOptions(selected, child));
  const context = {
    runId: 'unexpected-required-exit',
    evidenceDir: selected.evidenceDir,
  };
  let failure = null;
  await controller.attach('build-profile', context, {
    onRequiredAdapterExit(current) {
      failure = current;
    },
  });

  child.close(7);
  await eventually(
    () => failure,
    'required-adapter containment callback timed out',
  );
  assert.equal(failure.name, 'collector');
  assert.equal(failure.required, true);
  assert.equal(failure.ok, false);
  assert.equal(failure.exitCode, 7);
  assert.equal(failure.exitSignal, null);
  assert.match(failure.error, /status 7/);
});

test('detach escalates a hung collector to SIGKILL and records forced exit', async (t) => {
  const selected = fixture(t, { detachTimeoutMs: 10 });
  const child = new FakeChild(41004, { ignoreSignals: ['SIGTERM'] });
  const { AdapterController } = await adapterModule();
  const controller = new AdapterController(controllerOptions(selected, child, {
    limitKillGraceMs: 100,
  }));
  const context = { runId: 'forced-detach', evidenceDir: selected.evidenceDir };
  const attached = await controller.attach('build-profile', context);

  const detach = await controller.detach({ adapters: attached }, context);
  const processResult = detach.find((result) => result.exitStatusKnown);
  assert.deepEqual(child.killSignals, ['SIGTERM', 'SIGKILL']);
  assert.equal(processResult.forced, true);
  assert.equal(processResult.signal, 'SIGKILL');
  assert.equal(processResult.exitSignal, 'SIGKILL');
  assert.equal(processResult.cleanupOk, true);
  assert.equal(processResult.ok, false);
});

test('evidence overflow during detach drain makes the result incomplete', async (t) => {
  const selected = fixture(t, { maxOutputBytes: 32 });
  const child = new FakeChild(41005, {
    killExitCode: 0,
    outputOnKill: Buffer.alloc(256, 0x62),
  });
  const { AdapterController } = await adapterModule();
  const controller = new AdapterController(controllerOptions(selected, child, {
    outputMaxBytes: 64,
    diagnosticsMaxBytes: 64,
  }));
  const context = { runId: 'drain-overflow', evidenceDir: selected.evidenceDir };
  const attached = await controller.attach('build-profile', context);

  const detach = await controller.detach({ adapters: attached }, context);
  const processResult = detach.find((result) => result.exitStatusKnown);
  assert.equal(processResult.cleanupOk, true);
  assert.equal(processResult.evidenceOk, false);
  assert.equal(processResult.ok, false);
  assert.match(processResult.error, /exceeded 32 bytes/);
  assert.equal(processResult.evidenceFailures[0].stream, 'stdout');
  assert.equal(fs.statSync(attached[0].logPath).size, 32);
});

test('detach never escalates a reused collector PID', async (t) => {
  const selected = fixture(t, { detachTimeoutMs: 10 });
  const child = new FakeChild(41006, { ignoreSignals: ['SIGTERM'] });
  let identityChecks = 0;
  const { AdapterController } = await adapterModule();
  const controller = new AdapterController(controllerOptions(selected, child, {
    limitKillGraceMs: 10,
    processStartTimeProvider: async () => {
      identityChecks += 1;
      return identityChecks < 3 ? 'fake-start-time' : 'reused-start-time';
    },
  }));
  const context = { runId: 'pid-reuse', evidenceDir: selected.evidenceDir };
  const attached = await controller.attach('build-profile', context);

  const detach = await controller.detach({ adapters: attached }, context);
  const processResult = detach.find((result) => 'identityLost' in result);
  assert.deepEqual(child.killSignals, ['SIGTERM']);
  assert.equal(processResult.identityLost, true);
  assert.equal(processResult.cleanupOk, true);
  assert.equal(processResult.evidenceOk, false);
  assert.equal(processResult.exitStatusKnown, false);
});
