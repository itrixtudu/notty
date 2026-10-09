'use strict';

const assert = require('node:assert/strict');
const { spawnSync } = require('node:child_process');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const test = require('node:test');

test('QEMU harness lifecycle and input validation', () => {
  const result = spawnSync('python3', ['-B', path.join(__dirname, 'qemu-harness.test.py')], {
    encoding: 'utf8',
    timeout: 30000,
  });
  assert.equal(result.error, undefined, result.error?.message);
  assert.equal(result.status, 0, result.stdout + result.stderr);
});

test('QEMU evidence assertions require complete matching endpoint decisions', (t) => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'notty-qemu-evidence-'));
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  const manifestPath = path.join(directory, 'manifest.json');
  const evidencePath = path.join(directory, 'egress.ndjson');
  const approved = '198.18.0.1';
  const rejected = '198.18.0.2';
  const decision = (ip, verdict) => ({
    recordKind: 'decision', destinationAddress: ip, verdict,
  });
  const run = (mode, manifest, records) => {
    fs.writeFileSync(manifestPath, JSON.stringify(manifest));
    fs.writeFileSync(evidencePath, records.map((record) => JSON.stringify(record)).join('\n'));
    return spawnSync(process.execPath, [
      path.join(__dirname, '../scripts/qemu/guard-scenarios.mjs'), 'evidence',
      manifestPath, mode, approved, rejected, evidencePath,
    ], { encoding: 'utf8', timeout: 5000 });
  };
  for (const [mode, verdict] of [['learn', 'allow'], ['audit', 'would-deny'], ['enforce', 'deny']]) {
    const manifest = {
      complete: true, mode: `egress-${mode}`,
      egressEvaluation: { complete: true, wouldDenyCount: 1, deniedCount: 1 },
    };
    const decisions = [decision(approved, 'allow'), decision(rejected, verdict)];
    const success = run(mode, manifest, decisions);
    assert.equal(success.status, 0, success.stdout + success.stderr);
    assert.equal(JSON.parse(success.stdout).status, 'passed');
    for (const [invalidManifest, invalidDecisions] of [
      [{ ...manifest, complete: false }, decisions],
      [{ ...manifest, egressEvaluation: { ...manifest.egressEvaluation, complete: false } }, decisions],
      [{ ...manifest, mode: 'another-mode' }, decisions],
      [manifest, decisions.slice(0, 1)],
      [manifest, decisions.slice(1)],
      [manifest, [decision(approved, 'allow'), decision(rejected, 'unknown')]],
    ]) {
      const rejectedResult = run(mode, invalidManifest, invalidDecisions);
      assert.equal(rejectedResult.error, undefined, rejectedResult.error?.message);
      assert.notEqual(rejectedResult.status, 0, `${mode}: invalid evidence passed`);
    }
  }
});
