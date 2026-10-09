const test = require('node:test');
const assert = require('node:assert/strict');
const { spawnSync } = require('node:child_process');
const path = require('node:path');
test('Nosh environment authority, container modes, mount rejection, and release gate', () => {
  const result = spawnSync('python3', [path.join(__dirname, 'nosh-tool-policy.test.py')], { encoding: 'utf8' });
  assert.equal(result.status, 0, result.stdout + result.stderr);
});
