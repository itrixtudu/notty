'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');

test('purpose-scoped OTPs enforce binding, purpose, replay, and exact expiry', async () => {
  const {
    PurposeScopedAccessRegistry,
  } = await import('../lib/copilotAccessRegistry.js');
  let now = 10_000;
  let nextId = 1;
  let nextToken = 1;
  const registry = new PurposeScopedAccessRegistry({
    now: () => now,
    idFactory: () => `id-${nextId++}`,
    tokenFactory: () => `secret-token-${nextToken++}`,
  });

  const issued = registry.issue({
    bindingId: 'terminal-a',
    purpose: 'visible-agent',
    runtime: 'codex',
    ttlSeconds: 10,
    leaseTtlSeconds: 20,
  });
  assert.equal(issued.token, 'secret-token-1');
  assert.equal(issued.otp.status, 'available');
  assert.equal(issued.otp.expiresAt, 20_000);
  assert.doesNotMatch(JSON.stringify(registry.snapshot()), /secret-token/);

  assert.equal(
    registry.consume(issued.token, {
      bindingId: 'terminal-b',
      purpose: 'visible-agent',
    }).error.code,
    'copilot_access_otp_wrong_binding',
  );
  assert.equal(
    registry.consume(issued.token, {
      bindingId: 'terminal-a',
      purpose: 'analyzer',
    }).error.code,
    'copilot_access_otp_wrong_purpose',
  );

  const consumed = registry.consume(issued.token, {
    bindingId: 'terminal-a',
    purpose: 'visible-agent',
  });
  assert.equal(consumed.ok, true);
  assert.equal(consumed.lease.expiresAt, 30_000);
  assert.equal(
    registry.consume(issued.token, {
      bindingId: 'terminal-a',
      purpose: 'visible-agent',
    }).error.code,
    'copilot_access_otp_used',
  );
  assert.equal(
    registry.validateLease(consumed.lease.id, {
      bindingId: 'terminal-b',
      purpose: 'visible-agent',
    }).error.code,
    'copilot_access_lease_wrong_binding',
  );

  now = 30_000;
  assert.equal(
    registry.validateLease(consumed.lease.id, {
      bindingId: 'terminal-a',
      purpose: 'visible-agent',
    }).error.code,
    'copilot_access_lease_expired',
    'a lease expires inclusively at now >= expiresAt',
  );

  const expiring = registry.issue({
    bindingId: 'terminal-a',
    purpose: 'analyzer',
    runtime: 'codex',
    ttlSeconds: 1,
  });
  now += 1_000;
  assert.equal(
    registry.consume(expiring.token, {
      bindingId: 'terminal-a',
      purpose: 'analyzer',
    }).error.code,
    'copilot_access_otp_expired',
    'an OTP expires inclusively at now >= expiresAt',
  );
});

test('runtime defaults and binding revocation distinguish local and remote access', async () => {
  const {
    COPILOT_LOCAL_ACCESS_TTL_SECONDS,
    COPILOT_REMOTE_ACCESS_TTL_SECONDS,
    PurposeScopedAccessRegistry,
  } = await import('../lib/copilotAccessRegistry.js');
  let now = 50_000;
  let sequence = 1;
  const registry = new PurposeScopedAccessRegistry({
    now: () => now,
    idFactory: () => `uuid-${sequence++}`,
    tokenFactory: () => `token-${sequence++}`,
  });

  const remote = registry.issue({
    bindingId: 'terminal-a',
    purpose: 'visible-agent',
    runtime: 'agy',
  });
  const local = registry.issue({
    bindingId: 'terminal-a',
    purpose: 'analyzer',
    runtime: 'ollama',
  });
  assert.equal(remote.otp.ttlSeconds, COPILOT_REMOTE_ACCESS_TTL_SECONDS);
  assert.equal(local.otp.ttlSeconds, COPILOT_LOCAL_ACCESS_TTL_SECONDS);

  const localLease = registry.consume(local.token, {
    bindingId: 'terminal-a',
    purpose: 'analyzer',
  });
  assert.equal(localLease.ok, true);
  assert.equal(registry.revokeBinding('terminal-a'), 2);
  const snapshot = registry.snapshot({ bindingId: 'terminal-a' });
  assert.equal(snapshot.otps.find((otp) => otp.uuid === remote.otp.uuid).status, 'revoked');
  assert.equal(snapshot.otps.find((otp) => otp.uuid === local.otp.uuid).status, 'used');
  assert.equal(snapshot.leases[0].status, 'revoked');
  assert.equal(
    registry.validateLease(localLease.lease.id).error.code,
    'copilot_access_lease_revoked',
  );
});
