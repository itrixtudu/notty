'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { spawnSync } = require('node:child_process');
const path = require('node:path');

test('offline Codex tool audit classification, reconciliation, and privacy', () => {
  const result = spawnSync('python3', ['-B', path.join(__dirname, 'codex-tool-audit.test.py')], {
    encoding: 'utf8',
    timeout: 30000,
  });
  assert.equal(result.status, 0, result.stdout + result.stderr);
});
