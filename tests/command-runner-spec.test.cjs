const test = require('node:test');
const assert = require('node:assert/strict');

test('worker candidates isolate execution and cannot claim activation', async () => {
  const { candidateWorkerSpec } = await import('../lib/command-policy/runner-spec.js');
  const parameters = { image: 'sha256:' + 'a'.repeat(64), workspace: '/private/workspace', uid: 1000, gid: 1000,
    name: 'nosh-command-probe-' + 'b'.repeat(16), argv: ['sed', '--sandbox', '-n', '1p'],
    rules: { kind: 'NoshCommandPolicyDraft', schemaVersion: 1, enforcing: false, snapshotDigest: 'sha256:' + 'c'.repeat(64),
      rules: [{ id: 'sed', command: 'sed', mode: 'read-only', anySwitches: false,
        allowedSwitches: ['-n'], requiredSwitches: ['--sandbox'], optionValues: {} }] } };
  const candidate = candidateWorkerSpec(parameters);
  assert.equal(candidate.enforcing, false);
  assert.ok(candidate.args.includes('--network=none'));
  assert.ok(candidate.args.includes('--read-only'));
  assert.ok(candidate.args.includes('type=bind,src=/private/workspace,dst=/workspace,readonly'));
  assert.match(candidate.profile, /deny \/\*\* x,/);
  assert.match(candidate.profile, /px -> nosh-command-probe-/);
  for (const changes of [{ uid: 0 }, { image: 'mutable:tag' }, { workspace: '/tmp/a,other' },
    { argv: ['xargs', 'sh'] }, { argv: ['/tmp/sed', '--sandbox', '-n', '1p'] }, { argv: ['sed', '--sandbox', '-i', '1p'] }]) {
    assert.throws(() => candidateWorkerSpec({ ...parameters, ...changes }));
  }
});
