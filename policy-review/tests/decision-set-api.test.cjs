'use strict';

const assert = require('node:assert/strict');
const EventEmitter = require('node:events');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const test = require('node:test');

const apiModule = import('../pages/api/policy-review-decision-set.js');

function response() {
  const headers = new Map();
  return { statusCode: 200, body: '', headers,
    setHeader(k, v) { headers.set(String(k).toLowerCase(), v); },
    end(v = '') { this.body += v; },
  };
}

async function call(handler, body, host = '172.24.0.2:3000') {
  const request = new EventEmitter();
  request.method = 'POST';
  request.headers = { host };
  request.socket = { encrypted: false };
  const resultResponse = response();
  const result = handler(request, resultResponse);
  setTimeout(() => {
    request.emit('data', Buffer.from(body));
    request.emit('end');
  }, 25);
  await result;
  return resultResponse;
}

function setup(t) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'policy-review-decisions-'));
  const attestation = path.join(root, 'attestation.json');
  const decisions = path.join(root, 'decisions');
  fs.mkdirSync(decisions, { mode: 0o700 });
  fs.chmodSync(decisions, 0o700);
  fs.writeFileSync(attestation, JSON.stringify({ schemaVersion: 1, uiOrigin: 'http://172.24.0.2:3000', graphOrigin: 'http://172.24.0.3:43117' }), { mode: 0o600 });
  fs.chmodSync(attestation, 0o600);
  const old = { attestation: process.env.NOTTY_POLICY_REVIEW_ATTESTATION_FILE, decisions: process.env.NOTTY_POLICY_REVIEW_DECISIONS_DIR };
  process.env.NOTTY_POLICY_REVIEW_ATTESTATION_FILE = attestation;
  process.env.NOTTY_POLICY_REVIEW_DECISIONS_DIR = decisions;
  t.after(() => {
    if (old.attestation === undefined) delete process.env.NOTTY_POLICY_REVIEW_ATTESTATION_FILE; else process.env.NOTTY_POLICY_REVIEW_ATTESTATION_FILE = old.attestation;
    if (old.decisions === undefined) delete process.env.NOTTY_POLICY_REVIEW_DECISIONS_DIR; else process.env.NOTTY_POLICY_REVIEW_DECISIONS_DIR = old.decisions;
    fs.rmSync(root, { recursive: true, force: true });
  });
  return decisions;
}

test('managed UI DecisionSet export is saved as a private file', async (t) => {
  const decisions = setup(t);
  const { default: handler } = await apiModule;
  const document = { kind: 'NoshPolicyDecisionSet', schemaVersion: 1, graphContentDigest: `sha256:${'a'.repeat(64)}`, decisions: [{ id: 'allow-1' }] };
  const result = await call(handler, JSON.stringify(document));
  assert.equal(result.statusCode, 201, result.body);
  const file = path.join(decisions, 'decisions.json');
  assert.deepEqual(JSON.parse(fs.readFileSync(file, 'utf8')), document);
  assert.equal(fs.statSync(file).mode & 0o777, 0o600);
});

test('DecisionSet export rejects foreign origins and invalid documents', async (t) => {
  setup(t);
  const { default: handler } = await apiModule;
  assert.equal((await call(handler, '{}')).statusCode, 422);
  assert.equal((await call(handler, '{}', '172.24.0.9:3000')).statusCode, 403);
});
