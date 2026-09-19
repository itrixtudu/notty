'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');

test('OTP countdowns derive independent, non-negative display values', async () => {
  const {
    formatOtpRemaining,
    otpDisplayStatus,
    otpRemainingSeconds
  } = await import('../lib/spawnOtpCountdown.js');
  const now = Date.parse('2026-09-02T10:00:00.000Z');
  const short = { status: 'available', expiresAt: '2026-09-02T10:04:09.000Z' };
  const long = { status: 'available', expiresAt: '2026-09-02T11:04:00.000Z' };

  assert.equal(formatOtpRemaining(short, now), '4:09');
  const apiRecord = { status: 'available', expiresAt: now + 249_000 };
  assert.equal(formatOtpRemaining(apiRecord, now), '4:09');
  assert.equal(otpRemainingSeconds(apiRecord, now + 249_000), 0);
  assert.equal(otpDisplayStatus(apiRecord, now + 249_000), 'expired');
  assert.equal(formatOtpRemaining(long, now), '1h 04m');
  assert.equal(otpRemainingSeconds(short, now + 300_000), 0);
  assert.equal(formatOtpRemaining(short, now + 300_000), '0:00');
  assert.equal(otpDisplayStatus(short, now + 300_000), 'expired');
});

test('no-expiry and terminal OTP records retain their authoritative state', async () => {
  const { formatOtpRemaining, otpDisplayStatus, otpRemainingSeconds } = await import(
    '../lib/spawnOtpCountdown.js'
  );
  const now = Date.parse('2026-09-02T10:00:00.000Z');
  const permanent = { status: 'available', expiresAt: null };
  const used = { status: 'used', expiresAt: '2026-09-02T09:00:00.000Z' };
  const revoked = { status: 'revoked', expiresAt: '2026-09-02T11:00:00.000Z' };

  assert.equal(otpRemainingSeconds(permanent, now), null);
  assert.equal(formatOtpRemaining(permanent, now), 'No expiry');
  assert.equal(otpDisplayStatus(permanent, now), 'available');
  assert.equal(otpRemainingSeconds(used, now), null);
  assert.equal(formatOtpRemaining(used, now), 'Used');
  assert.equal(otpDisplayStatus(used, now), 'used');
  assert.equal(otpRemainingSeconds(revoked, now), null);
  assert.equal(formatOtpRemaining(revoked, now), 'Revoked');
  assert.equal(otpDisplayStatus(revoked, now), 'revoked');
});
