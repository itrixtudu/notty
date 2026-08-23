'use strict';

const assert = require('node:assert/strict');
const { EventEmitter } = require('node:events');
const path = require('node:path');
const test = require('node:test');
const { pathToFileURL } = require('node:url');

const appRoot = path.resolve(__dirname, '..');

async function clientModule() {
  return import(
    pathToFileURL(path.join(appRoot, 'lib', 'guardd', 'client.js')).href
  );
}

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
