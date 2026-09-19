'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');

test('OTP lifecycle projection separates unused expiry from consumed access deadlines', async () => {
  const { spawnOtpHistory } = await import('../lib/spawnOtpHistory.js');
  const token = { createdAt: 0, expiresAt: 10000, status: 'available' };
  assert.deepEqual(spawnOtpHistory(token, 9999).map((event) => event.event), ['Created']);
  assert.deepEqual(spawnOtpHistory(token, 10000).map((event) => event.event), ['Created', 'Unused token expired']);
  const used = { ...token, consumedAt: 1000, status: 'used', value: 'SECRET', token_hash: 'PRIVATE' };
  const events = spawnOtpHistory(used, 10000);
  assert.deepEqual(events.map((event) => event.event), ['Created', 'Consumed', 'Input-access deadline reached']);
  assert.match(events[1].details, /does not prove a terminal started/);
  assert.match(events[2].details, /renewed access/);
  assert.doesNotMatch(JSON.stringify(events), /SECRET|PRIVATE|token_hash/);
  assert.equal(used.status, 'used');
});

test('revocation, no-expiry and legacy metadata have truthful bounded histories', async () => {
  const { spawnOtpHistory } = await import('../lib/spawnOtpHistory.js');
  assert.deepEqual(spawnOtpHistory({ createdAt: 0, expiresAt: 10000, revokedAt: 5000 }, 20000)
    .map((event) => event.event), ['Created', 'Revoked']);
  assert.deepEqual(spawnOtpHistory({ createdAt: 0, expiresAt: 10000, revokedAt: 15000 }, 20000)
    .map((event) => event.event), ['Created', 'Unused token expired', 'Revoked']);
  assert.deepEqual(spawnOtpHistory({ createdAt: 0, expiresAt: null }, 20000).map((event) => event.event), ['Created']);
  assert.deepEqual(spawnOtpHistory({ createdAt: 'invalid', usedAt: '2026-09-01T00:00:00Z' })
    .map((event) => event.event), ['Consumed']);
  assert.deepEqual(spawnOtpHistory({}), []);
});

test('OTP display clock follows server time and monotonic elapsed time instead of wall-clock skew', async () => {
  const { otpClockNow, otpRemainingSeconds } = await import('../lib/spawnOtpCountdown.js');
  const anchor = { serverTime: 100000, elapsedAt: 50 };
  const token = { status: 'available', expiresAt: 110000 };
  assert.equal(otpRemainingSeconds(token, otpClockNow(anchor, 1050, 999999999)), 9);
  assert.equal(otpRemainingSeconds(token, otpClockNow(anchor, 1050, -999999999)), 9);
  assert.equal(otpRemainingSeconds(token, otpClockNow(anchor, 60050, 1)), 0);
  assert.equal(otpClockNow(null, 1050, 123), 123);
  assert.equal(otpClockNow({ serverTime: 'invalid', elapsedAt: 0 }, 1050, 123), 123);
});
