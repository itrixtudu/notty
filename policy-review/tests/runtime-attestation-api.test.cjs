'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const test = require('node:test');

const apiModule = import('../pages/api/policy-review-attestation.js');

function privateDirectory(t) {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'policy-review-attestation-'));
  fs.chmodSync(directory, 0o700);
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  return directory;
}

function writeAttestation(directory, overrides = {}) {
  const file = path.join(directory, 'policy-review-attestation.json');
  fs.writeFileSync(file, `${JSON.stringify({
    schemaVersion: 1,
    uiOrigin: 'http://172.24.0.2:3000',
    graphOrigin: 'http://172.24.0.3:43117',
    ...overrides,
  })}\n`, { mode: 0o600 });
  fs.chmodSync(file, 0o600);
  return file;
}

function mockResponse() {
  const headers = new Map();
  return {
    statusCode: 200,
    body: '',
    headers,
    setHeader(name, value) {
      headers.set(String(name).toLowerCase(), value);
    },
    end(value = '') {
      this.body += value;
    },
  };
}

async function callHandler(handler, { method = 'GET', host = '172.24.0.2:3000' } = {}) {
  const response = mockResponse();
  await handler({ method, headers: { host }, socket: { encrypted: false } }, response);
  return response;
}

test('runtime attestation API returns only the graph origin to its exact UI origin', async (t) => {
  const directory = privateDirectory(t);
  const file = writeAttestation(directory);
  const previous = process.env.NOTTY_POLICY_REVIEW_ATTESTATION_FILE;
  process.env.NOTTY_POLICY_REVIEW_ATTESTATION_FILE = file;
  t.after(() => {
    if (previous === undefined) delete process.env.NOTTY_POLICY_REVIEW_ATTESTATION_FILE;
    else process.env.NOTTY_POLICY_REVIEW_ATTESTATION_FILE = previous;
  });
  const { default: handler } = await apiModule;

  const accepted = await callHandler(handler);
  assert.equal(accepted.statusCode, 200);
  assert.deepEqual(JSON.parse(accepted.body), {
    schemaVersion: 1,
    graphOrigin: 'http://172.24.0.3:43117',
  });
  assert.equal(accepted.headers.get('cache-control'), 'no-store');
  assert.equal(accepted.headers.has('access-control-allow-origin'), false);

  const foreign = await callHandler(handler, { host: '172.24.0.9:3000' });
  assert.equal(foreign.statusCode, 403);
  assert.equal(foreign.headers.get('cache-control'), 'no-store');
  assert.match(foreign.body, /does not match/);
});

test('runtime attestation API fails closed and no-store while a configured file is absent', async (t) => {
  const directory = privateDirectory(t);
  const previous = process.env.NOTTY_POLICY_REVIEW_ATTESTATION_FILE;
  process.env.NOTTY_POLICY_REVIEW_ATTESTATION_FILE = path.join(directory, 'not-ready.json');
  t.after(() => {
    if (previous === undefined) delete process.env.NOTTY_POLICY_REVIEW_ATTESTATION_FILE;
    else process.env.NOTTY_POLICY_REVIEW_ATTESTATION_FILE = previous;
  });
  const { default: handler } = await apiModule;
  const response = await callHandler(handler);

  assert.equal(response.statusCode, 503);
  assert.equal(response.headers.get('cache-control'), 'no-store');
  assert.match(response.body, /unavailable/);
});

test('private Docker ranges still require the exact attested UI host', async (t) => {
  const directory = privateDirectory(t);
  const previous = process.env.NOTTY_POLICY_REVIEW_ATTESTATION_FILE;
  t.after(() => {
    if (previous === undefined) delete process.env.NOTTY_POLICY_REVIEW_ATTESTATION_FILE;
    else process.env.NOTTY_POLICY_REVIEW_ATTESTATION_FILE = previous;
  });
  const { default: handler } = await apiModule;
  for (const prefix of ['192.168.16', '10.20.0']) {
    const graphOrigin = `http://${prefix}.3:43117`;
    process.env.NOTTY_POLICY_REVIEW_ATTESTATION_FILE = writeAttestation(directory, {
      uiOrigin: `http://${prefix}.2:3000`, graphOrigin,
    });
    const accepted = await callHandler(handler, { host: `${prefix}.2:3000` });
    assert.equal(accepted.statusCode, 200);
    assert.deepEqual(JSON.parse(accepted.body), { schemaVersion: 1, graphOrigin });
    assert.equal(accepted.headers.get('cache-control'), 'no-store');
    assert.equal(accepted.headers.has('access-control-allow-origin'), false);
    for (const host of [`${prefix}.4:3000`, `${prefix}.2:3001`]) {
      const foreign = await callHandler(handler, { host });
      assert.equal(foreign.statusCode, 403);
      assert.match(foreign.body, /does not match/);
    }
  }
});

test('runtime attestation reader rejects non-private files and hard links', async (t) => {
  const directory = privateDirectory(t);
  const { readPolicyReviewRuntimeAttestation } = await apiModule;

  const publicFile = writeAttestation(directory);
  fs.chmodSync(publicFile, 0o644);
  await assert.rejects(
    readPolicyReviewRuntimeAttestation({
      NOTTY_POLICY_REVIEW_ATTESTATION_FILE: publicFile,
    }),
    /private owned regular file/,
  );

  fs.chmodSync(publicFile, 0o600);
  fs.linkSync(publicFile, path.join(directory, 'attestation-hard-link.json'));
  await assert.rejects(
    readPolicyReviewRuntimeAttestation({
      NOTTY_POLICY_REVIEW_ATTESTATION_FILE: publicFile,
    }),
    /private owned regular file/,
  );
});

test('diagnostic mode advertises no bridge origin when no file is configured', async () => {
  const previous = process.env.NOTTY_POLICY_REVIEW_ATTESTATION_FILE;
  delete process.env.NOTTY_POLICY_REVIEW_ATTESTATION_FILE;
  try {
    const { default: handler } = await apiModule;
    const response = await callHandler(handler, { host: '127.0.0.1:3000' });
    assert.equal(response.statusCode, 200);
    assert.deepEqual(JSON.parse(response.body), {
      schemaVersion: 1,
      graphOrigin: null,
    });
    assert.equal(response.headers.get('cache-control'), 'no-store');
  } finally {
    if (previous === undefined) delete process.env.NOTTY_POLICY_REVIEW_ATTESTATION_FILE;
    else process.env.NOTTY_POLICY_REVIEW_ATTESTATION_FILE = previous;
  }
});
