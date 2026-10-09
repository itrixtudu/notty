'use strict';
const assert = require('node:assert/strict');
const { spawnSync } = require('node:child_process');
const path = require('node:path');
const test = require('node:test');

test('interactive saved-policy launcher menu', () => {
  const result = spawnSync('python3', ['-I', '-S', path.join(__dirname, 'nosh-launch-menu.test.py')], {
    encoding: 'utf8', timeout: 30000,
  });
  assert.equal(result.status, 0, result.stdout + result.stderr);
});
