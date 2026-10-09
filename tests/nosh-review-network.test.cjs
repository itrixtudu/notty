'use strict';

const assert = require('node:assert/strict');
const { spawnSync } = require('node:child_process');
const path = require('node:path');
const test = require('node:test');

const hasPython = spawnSync('python3', ['--version']).status === 0;
for (const suite of ['nosh-review-network.test.py', 'nosh-review-stop.test.py']) {
  test(`offline review network checks: ${suite}`, { skip: !hasPython }, () => {
    const result = spawnSync('python3', ['-B', path.join(__dirname, suite)], {
      encoding: 'utf8', timeout: 30000,
    });
    assert.equal(result.status, 0, result.stdout + result.stderr);
  });
}
