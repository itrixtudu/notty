const test = require('node:test');
const assert = require('node:assert/strict');
const { spawnSync } = require('node:child_process');
const path = require('node:path');

function run(args) {
  return spawnSync('bash', [path.join(__dirname, '../scripts/nosh.sh'), ...args, '--dry-run'], {
    encoding: 'utf8', env: { ...process.env, NOTTY_COLLAB_ENABLED: 'false' },
  });
}
test('resume shortcut enables Collab and bundled service and launches the exact Codex argv', () => {
  const result = run(['--resume']);
  assert.equal(result.status, 0, result.stderr);
  assert.match(result.stdout, /NOTTY_COLLAB_ENABLED=true/);
  assert.match(result.stdout, /start:next:sse/);
  assert.match(result.stdout, /docker exec .* codex resume --dangerously-bypass-approvals-and-sandbox/);
  assert.doesNotMatch(result.stdout, /Start bundled .*\[y\/N\]/);
});
test('resume shortcut rejects contradictory Collab and unsupported lifecycle actions', () => {
  for (const args of [['--resume', '--no-collab'], ['stop', '--resume']]) {
    const result = run(args);
    assert.notEqual(result.status, 0);
    assert.doesNotMatch(result.stdout, /docker exec/);
  }
});
