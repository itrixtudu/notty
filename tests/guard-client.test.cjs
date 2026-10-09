'use strict';

const assert = require('node:assert/strict');
const { EventEmitter } = require('node:events');
const { spawn, spawnSync } = require('node:child_process');
const { once } = require('node:events');
const fs = require('node:fs/promises');
const os = require('node:os');
const path = require('node:path');
const test = require('node:test');
const { pathToFileURL } = require('node:url');

const appRoot = path.resolve(__dirname, '..');

async function clientModule() {
  return import(
    pathToFileURL(path.join(appRoot, 'lib', 'guardd', 'client.js')).href
  );
}

test('GuardClient can stop after a synchronous shell outlives the daemon idle connection', async (t) => {
  const { GuardClient } = await clientModule();
  const directory = await fs.mkdtemp(path.join(os.tmpdir(), 'guard-client-'));
  const socketPath = path.join(directory, 'guard.sock');
  const daemon = spawn(process.execPath, ['-e', `
    const http = require('node:http');
    const server = http.createServer((request, response) => {
      request.resume();
      request.on('end', () => {
        response.setHeader('content-type', 'application/json');
        response.end(JSON.stringify({ path: request.url }));
      });
    });
    server.keepAliveTimeout = 2000;
    server.keepAliveTimeoutBuffer = 0;
    server.listen(process.argv[1], () => process.stdout.write('ready\\n'));
  `, socketPath], { stdio: ['ignore', 'pipe', 'inherit'] });
  t.after(async () => {
    const exited = once(daemon, 'exit');
    daemon.kill();
    await exited;
    await fs.rm(directory, { recursive: true, force: true });
  });
  await once(daemon.stdout, 'data');
  const client = new GuardClient({ socketPath });
  await client.action('test-run', 'attach');
  // Like docker exec via spawnSync: the client cannot process socket EOF while
  // the separate daemon expires its idle connection.
  const shell = spawnSync(process.execPath, ['-e',
    'Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 2400)']);
  assert.equal(shell.status, 0);
  assert.deepEqual(await client.action('test-run', 'stop'), {
    path: '/v1/runs/test-run/stop',
  });
});

test('GuardClient destroys a request that exceeds its bounded timeout', async () => {
  const { GuardClient } = await clientModule();
  let requestHandle = null;
  const client = new GuardClient({
    requestTimeoutMs: 20,
    requestImpl() {
      requestHandle = new EventEmitter();
      requestHandle.write = () => {};
      requestHandle.end = () => {};
      requestHandle.destroy = () => {
        requestHandle.destroyed = true;
      };
      return requestHandle;
    },
  });

  await assert.rejects(
    client.listRuns(),
    (error) =>
      error.code === 'GUARD_REQUEST_TIMEOUT'
      && error.timeoutMs === 20
      && /GET \/v1\/runs.*20ms/.test(error.message),
  );
  assert.equal(requestHandle.destroyed, true);
  assert.throws(
    () => new GuardClient({ requestTimeoutMs: 0 }),
    /requestTimeoutMs must be an integer/,
  );
  assert.throws(
    () => new GuardClient({ requestTimeoutMs: 600_001 }),
    /requestTimeoutMs must be an integer/,
  );
});
