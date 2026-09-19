function timestamp(value) {
  if (value === null || value === undefined || value === '') return null;
  const parsed = typeof value === 'number' ? value : Date.parse(value);
  return Number.isFinite(parsed) ? parsed : null;
}

// Project only public lifecycle metadata. Never spread a token or its value.
export function spawnOtpHistory(otp, now = Date.now()) {
  const events = [];
  const created = timestamp(otp.createdAt);
  const consumed = timestamp(otp.consumedAt ?? otp.usedAt);
  const revoked = timestamp(otp.revokedAt);
  const expires = timestamp(otp.expiresAt);
  if (created !== null) events.push({ time: created, event: 'Created', details: 'One-time spawn capability issued.' });
  if (consumed !== null) events.push({ time: consumed, event: 'Consumed', details: 'The one-time value was consumed. This alone does not prove a terminal started successfully.' });
  if (revoked !== null) events.push({ time: revoked, event: 'Revoked', details: 'The token was revoked and cannot authorize another spawn.' });
  if (expires !== null && expires <= now) {
    if (consumed !== null && consumed <= expires) {
      events.push({ time: expires, event: 'Input-access deadline reached', details: 'This used token reached its configured access deadline. A terminal may have renewed access with another token; current terminal state is not retained here.' });
    } else if (revoked === null || revoked > expires) {
      events.push({ time: expires, event: 'Unused token expired', details: 'The unused spawn capability expired without being consumed.' });
    }
  }
  return events.sort((left, right) => left.time - right.time);
}
