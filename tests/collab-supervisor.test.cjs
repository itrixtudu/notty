'use strict';

const assert = require('node:assert/strict');
const { EventEmitter } = require('node:events');
const path = require('node:path');
const test = require('node:test');

const appRoot = path.resolve(__dirname, '..');
const UNAVAILABLE = Symbol('unavailable');

function bootstrap() {
  return {
    apiVersion: 'v1',
    daemon: {
      marker: 'notty-collab-daemon',
      version: 1,
      pid: 4321,
    },
    workspaceRoot: appRoot,
  };
}

function refusedConnection() {
  const error = new Error('connect ECONNREFUSED 127.0.0.1:1337');
  error.code = 'ECONNREFUSED';
  return error;
}

function createFetchScript(results) {
  const calls = [];
  const pending = [...results];

  return {
    calls,
    fetchImpl: async (url, options) => {
      calls.push({ url: String(url), options });
      if (pending.length === 0) {
        throw new Error('unexpected collab supervisor probe');
      }
      const result = pending.shift();
      if (result === UNAVAILABLE) {
        throw refusedConnection();
      }
      return {
        ok: true,
        status: 200,
        json: async () => result,
      };
    },
  };
}

class FakeChild extends EventEmitter {
  constructor(pid) {
    super();
    this.pid = pid;
    this.exitCode = null;
    this.killed = false;
    this.stderr = new EventEmitter();
    this.killSignals = [];
  }

  kill(signal) {
    this.killed = true;
    this.killSignals.push(signal);
    return true;
  }

  crash(code = 1, signal = null) {
    this.exitCode = code;
    this.emit('exit', code, signal);
  }
}

function createSpawnRecorder() {
  const calls = [];
  return {
    calls,
    spawnImpl(command, args, options) {
      const child = new FakeChild(10_000 + calls.length);
      calls.push({ command, args, options, child });
      return child;
    },
  };
}

async function flushMicrotasks(turns = 20) {
  for (let index = 0; index < turns; index += 1) {
    await Promise.resolve();
  }
}

async function startOwnedSupervisor(t, supervisor, spawnCalls) {
  const ready = supervisor.start();
  await flushMicrotasks();
  assert.equal(spawnCalls.length, 1, 'an unavailable daemon should be spawned');
  t.mock.timers.tick(125);
  await flushMicrotasks();
  return ready;
}

async function loadSupervisor() {
  return import('../lib/collabSupervisor.js');
}

test('crashed daemon restarts with capped exponential backoff and honors the restart limit', async (t) => {
  t.mock.timers.enable({ apis: ['setTimeout', 'Date'], now: 1_000 });
  t.mock.method(console, 'error', () => {});

  const { CollabSupervisor } = await loadSupervisor();
  const readyBootstrap = bootstrap();
  const fetch = createFetchScript([
    UNAVAILABLE, readyBootstrap,
    UNAVAILABLE, readyBootstrap,
    UNAVAILABLE, readyBootstrap,
    UNAVAILABLE, readyBootstrap,
    UNAVAILABLE, readyBootstrap,
  ]);
  const spawned = createSpawnRecorder();
  const supervisor = new CollabSupervisor({
    appRoot,
    workspaceRoot: appRoot,
    baseUrl: 'http://127.0.0.1:1337',
    startupTimeoutMs: 1_000,
    probeTimeoutMs: 500,
    restartBaseDelayMs: 10,
    restartMaxDelayMs: 25,
    maxRestartAttempts: 3,
    fetchImpl: fetch.fetchImpl,
    spawnImpl: spawned.spawnImpl,
  });
  t.after(() => supervisor.stop());

  assert.equal(await startOwnedSupervisor(t, supervisor, spawned.calls), readyBootstrap);
  assert.equal(supervisor.getState().ready, true);

  const restartDelays = [10, 20, 25];
  for (const [index, delay] of restartDelays.entries()) {
    const child = spawned.calls[index].child;
    const probesBeforeRestart = fetch.calls.length;
    child.crash();

    assert.equal(supervisor.getState().ready, false);
    assert.equal(supervisor.getState().restartAttempts, index + 1);

    t.mock.timers.tick(delay - 1);
    await flushMicrotasks();
    assert.equal(spawned.calls.length, index + 1);
    assert.equal(fetch.calls.length, probesBeforeRestart);

    t.mock.timers.tick(1);
    await flushMicrotasks();
    assert.equal(spawned.calls.length, index + 2);

    t.mock.timers.tick(125);
    await flushMicrotasks();
    assert.equal(supervisor.getState().ready, true);
  }

  spawned.calls[3].child.crash();
  const probesAtLimit = fetch.calls.length;
  t.mock.timers.tick(1_000);
  await flushMicrotasks();
  assert.equal(spawned.calls.length, 4, 'the automatic restart limit should prevent another spawn');
  assert.equal(fetch.calls.length, probesAtLimit);

  const explicitlyRequested = supervisor.ensureReady();
  await flushMicrotasks();
  assert.equal(spawned.calls.length, 5, 'a later API request should retry after the limit');
  t.mock.timers.tick(125);
  await flushMicrotasks();
  assert.equal(await explicitlyRequested, readyBootstrap);
});

test('stop terminates an owned daemon and prevents its exit from scheduling a restart', async (t) => {
  t.mock.timers.enable({ apis: ['setTimeout', 'Date'], now: 1_000 });
  t.mock.method(console, 'error', () => {});

  const { CollabSupervisor, CollabSupervisorError } = await loadSupervisor();
  const fetch = createFetchScript([UNAVAILABLE, bootstrap()]);
  const spawned = createSpawnRecorder();
  const supervisor = new CollabSupervisor({
    appRoot,
    workspaceRoot: appRoot,
    baseUrl: 'http://127.0.0.1:1337',
    startupTimeoutMs: 1_000,
    fetchImpl: fetch.fetchImpl,
    spawnImpl: spawned.spawnImpl,
  });
  t.after(() => supervisor.stop());

  await startOwnedSupervisor(t, supervisor, spawned.calls);
  const child = spawned.calls[0].child;
  supervisor.stop();

  assert.deepEqual(child.killSignals, ['SIGTERM']);
  assert.equal(supervisor.getState().owned, false);
  assert.equal(supervisor.getState().ready, false);
  await assert.rejects(
    supervisor.ensureReady(),
    (error) => error instanceof CollabSupervisorError && error.code === 'COLLAB_UNAVAILABLE',
  );

  child.crash(null, 'SIGTERM');
  t.mock.timers.tick(1_000);
  await flushMicrotasks();
  assert.equal(spawned.calls.length, 1);
  assert.equal(fetch.calls.length, 2);
});

test('stop cancels a restart that is already waiting in backoff', async (t) => {
  t.mock.timers.enable({ apis: ['setTimeout', 'Date'], now: 1_000 });
  t.mock.method(console, 'error', () => {});

  const { CollabSupervisor } = await loadSupervisor();
  const fetch = createFetchScript([UNAVAILABLE, bootstrap()]);
  const spawned = createSpawnRecorder();
  const supervisor = new CollabSupervisor({
    appRoot,
    workspaceRoot: appRoot,
    baseUrl: 'http://127.0.0.1:1337',
    restartBaseDelayMs: 50,
    startupTimeoutMs: 1_000,
    fetchImpl: fetch.fetchImpl,
    spawnImpl: spawned.spawnImpl,
  });
  t.after(() => supervisor.stop());

  await startOwnedSupervisor(t, supervisor, spawned.calls);
  spawned.calls[0].child.crash();
  assert.equal(supervisor.getState().restartAttempts, 1);

  supervisor.stop();
  t.mock.timers.tick(1_000);
  await flushMicrotasks();

  assert.equal(spawned.calls.length, 1);
  assert.equal(fetch.calls.length, 2);
});

test('stop tolerates a child that exits before SIGTERM is delivered', async (t) => {
  t.mock.timers.enable({ apis: ['setTimeout', 'Date'], now: 1_000 });
  t.mock.method(console, 'error', () => {});

  const { CollabSupervisor } = await loadSupervisor();
  const fetch = createFetchScript([UNAVAILABLE, bootstrap()]);
  const spawned = createSpawnRecorder();
  const supervisor = new CollabSupervisor({
    appRoot,
    workspaceRoot: appRoot,
    baseUrl: 'http://127.0.0.1:1337',
    startupTimeoutMs: 1_000,
    fetchImpl: fetch.fetchImpl,
    spawnImpl: spawned.spawnImpl,
  });
  t.after(() => supervisor.stop());

  await startOwnedSupervisor(t, supervisor, spawned.calls);
  const child = spawned.calls[0].child;
  child.kill = () => {
    throw new Error('ESRCH');
  };

  assert.doesNotThrow(() => supervisor.stop());
  assert.equal(supervisor.getState().owned, false);
  assert.equal(supervisor.getState().ready, false);
});
