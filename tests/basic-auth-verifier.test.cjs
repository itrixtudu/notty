const assert = require('node:assert/strict');
const { spawnSync } = require('node:child_process');
const test = require('node:test');

test('launcher scrypt verifier authenticates passwords but cannot be replayed as one', async () => {
  const { validateHttpBasicAuthRequest, getHttpBasicAuthInfo } = await import('../lib/httpBasicAuth.js');
  const password = 'operator supplied: password ü';
  const generate = () => {
    const result = spawnSync('python3', ['scripts/basic-auth-verifier.py'], { input: password, encoding: 'utf8' });
    assert.equal(result.status, 0, result.stderr);
    return result.stdout.trim();
  };
  const verifier = generate();
  assert.notEqual(verifier, generate(), 'random salts produce different verifiers');
  const config = { enabled: true, username: 'operator', verifier, env: {} };
  const check = (value) => validateHttpBasicAuthRequest({ headers: {
    authorization: `Basic ${Buffer.from(`operator:${value}`).toString('base64')}`
  } }, config);
  assert.equal(check(password).ok, true);
  for (const value of [verifier, '', `${password}!`]) assert.equal(check(value).ok, false);
  assert.equal(JSON.stringify(getHttpBasicAuthInfo(config)).includes(verifier), false);
  assert.equal(validateHttpBasicAuthRequest({ headers: {} }, { ...config, verifier: 'malformed' }).code, 'misconfigured');
});
