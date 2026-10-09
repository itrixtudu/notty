const test = require('node:test');
const assert = require('node:assert/strict');
const { spawnSync } = require('node:child_process');
const path = require('node:path');

test('repository configuration storage, portable exports and CI boundary', () => {
  const result = spawnSync('python3', ['-B', path.join(__dirname, 'nosh-config.test.py')], { encoding: 'utf8', timeout: 30000 });
  assert.equal(result.status, 0, result.stdout + result.stderr);
});
test('nosh config dispatches help before Docker or launch initialization', () => {
  const result = spawnSync('bash', [path.join(__dirname, '../scripts/nosh.sh'), 'config', '--help'], { encoding: 'utf8', timeout: 5000 });
  assert.equal(result.status, 0, result.stderr);
  assert.match(result.stdout, /refresh.*export.*import.*ci/);
});
