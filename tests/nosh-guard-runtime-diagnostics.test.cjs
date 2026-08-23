'use strict';

const assert = require('node:assert/strict');
const http = require('node:http');
const path = require('node:path');
const test = require('node:test');
const { pathToFileURL } = require('node:url');

const appRoot = path.resolve(__dirname, '..');

async function importModule(relativePath) {
  return import(pathToFileURL(path.join(appRoot, relativePath)).href);
}

test('runtime start HTTP errors expose only retained stopped-container diagnostics', async (t) => {
  const { GuardClient } = await importModule('lib/guardd/client.js');
  const { createGuardServer } = await importModule('lib/guardd/server.js');
  const runId = 'run-http-stopped';
  const containerId = 'a'.repeat(64);
  const runtimeState = {
    ExitCode: 126,
    Error: 'permission denied',
    OOMKilled: false,
    Dead: false,
    StartedAt: '2026-08-20T12:00:00.000000000Z',
    FinishedAt: '2026-08-20T12:00:00.250000000Z',
  };
  const runtimeLogTail = {
    text: 'gate diagnostic\nsecret=[redacted]',
    truncated: true,
  };
  const runtime = {
    async initialize() {},
    health() {
      return { ok: true };
    },
    async listRuns() {
      return [];
    },
    async startRun() {
      const error = new Error(
        'runner runtime identity mismatch: container is not running',
      );
      error.code = 'GUARD_RUNTIME_IDENTITY_MISMATCH';
      error.runId = runId;
      error.containerId = containerId;
      error.runtimeState = {
        ...runtimeState,
        Running: false,
        Pid: 0,
      };
      error.runtimeLogTail = {
        text: 'gate diagnostic\nsecret=do-not-expose',
        truncated: true,
        ignored: 'not part of the public diagnostic shape',
      };
      error.containerRemoved = true;
      throw error;
    },
    async watchdogTick() {
      return [];
    },
  };
  const builds = {
    async initialize() {},
    async listRuns() {
      return [];
    },
    async watchdogTick() {
      return [];
    },
  };
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

  await assert.rejects(
    client.startRun({ name: 'stopped' }),
    (error) => {
      assert.equal(error.code, 'GUARD_RUNTIME_IDENTITY_MISMATCH');
      assert.equal(error.runId, runId);
      assert.equal(error.containerId, containerId);
      assert.equal(error.containerRemoved, true);
      assert.deepEqual(error.runtimeState, runtimeState);
      assert.deepEqual(error.runtimeLogTail, runtimeLogTail);
      assert.deepEqual(error.document, {
        error: {
          code: 'GUARD_RUNTIME_IDENTITY_MISMATCH',
          message: 'runner runtime identity mismatch: container is not running',
          runId,
          containerId,
          runtimeState,
          runtimeLogTail,
          containerRemoved: true,
        },
      });
      return true;
    },
  );
});
