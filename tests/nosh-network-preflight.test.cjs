'use strict';
const assert = require('node:assert/strict');
const { spawnSync } = require('node:child_process');
const path = require('node:path');
const test = require('node:test');

test('read-only Docker network preflight fixtures', () => {
  const result = spawnSync('python3', ['-B', path.join(__dirname, 'nosh-network-preflight.test.py')], {
    encoding: 'utf8', timeout: 30000,
  });
  assert.equal(result.status, 0, result.stdout + result.stderr);
});
