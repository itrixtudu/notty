const test = require('node:test');
const assert = require('node:assert/strict');
const { timeoutPolicy, enforceAgentDeadline } = require('../lib/collab/timeout.cjs');

test('Collab timeout defaults and strict bounds preserve explicit non-termination', () => {
  assert.deepEqual(timeoutPolicy(), { timeoutSeconds: 3600, terminateOnExpire: true });
  assert.deepEqual(timeoutPolicy({ timeoutSeconds: 2, terminateOnExpire: false }), { timeoutSeconds: 2, terminateOnExpire: false });
  for (const value of [0, -1, 1.2, '3600', null, Infinity, 604801]) {
    assert.throws(() => timeoutPolicy({ timeoutSeconds: value }));
  }
  assert.throws(() => timeoutPolicy({ terminateOnExpire: 'false' }));
});

test('expiry stops only an exact owned agent at its deadline, retries failures and is idempotent', () => {
  const agent = { identity: 'qa', tmuxTarget: 'exact', expiresAt: 1000, terminateOnExpire: true };
  const session = { id: 'session' };
  let present = true;
  let owned = true;
  let kills = 0;
  let clear = 0;
  const controls = { present: () => present, owned: (target, id) => {
    assert.equal(target, 'exact'); assert.equal(id, 'session'); return owned;
  }, stop: () => { kills++; }, clear: () => { clear++; } };
  assert.equal(enforceAgentDeadline(agent, session, controls, 999), agent);
  assert.equal(enforceAgentDeadline({ ...agent, terminateOnExpire: false }, session, controls, 1000).status, undefined);
  owned = false;
  assert.equal(enforceAgentDeadline(agent, session, controls, 1000), agent);
  assert.equal(kills, 0);
  owned = true;
  const failed = enforceAgentDeadline(agent, session, controls, 1000);
  assert.equal(failed.status, 'stop-failed'); assert.equal(clear, 0);
  controls.stop = () => { kills++; present = false; };
  const stopped = enforceAgentDeadline(failed, session, controls, 1001);
  assert.equal(stopped.status, 'stopped'); assert.equal(kills, 2); assert.equal(clear, 1);
  enforceAgentDeadline(stopped, session, controls, 2000);
  assert.equal(clear, 1);
  assert.equal(enforceAgentDeadline(agent, { ...session, recovered: true }, controls, 2000), agent);
});
