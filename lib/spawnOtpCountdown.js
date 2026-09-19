export function otpClockNow(anchor, elapsedNow, wallNow = Date.now()) {
  if (Number.isFinite(anchor?.serverTime) && Number.isFinite(anchor?.elapsedAt)
    && Number.isFinite(elapsedNow) && elapsedNow >= anchor.elapsedAt) {
    return anchor.serverTime + elapsedNow - anchor.elapsedAt;
  }
  return wallNow;
}

export function otpRemainingSeconds(otp, now = Date.now()) {
  if (!otp?.expiresAt || (otp.status && otp.status !== 'available')) {
    return null;
  }
  const expiresAt = typeof otp.expiresAt === 'number'
    ? otp.expiresAt
    : Date.parse(otp.expiresAt);
  if (!Number.isFinite(expiresAt)) {
    return null;
  }
  return Math.max(0, Math.ceil((expiresAt - now) / 1000));
}

export function otpDisplayStatus(otp, now = Date.now()) {
  if (otp?.status === 'available' && otpRemainingSeconds(otp, now) === 0) {
    return 'expired';
  }
  return otp?.status || 'available';
}

export function formatOtpRemaining(otp, now = Date.now()) {
  if (otp?.status && otp.status !== 'available') {
    return `${otp.status.charAt(0).toUpperCase()}${otp.status.slice(1)}`;
  }
  const remaining = otpRemainingSeconds(otp, now);
  if (remaining === null) {
    return 'No expiry';
  }
  if (remaining >= 3600) {
    const hours = Math.floor(remaining / 3600);
    const minutes = Math.floor((remaining % 3600) / 60);
    return `${hours}h ${String(minutes).padStart(2, '0')}m`;
  }
  const minutes = Math.floor(remaining / 60);
  const seconds = remaining % 60;
  return `${minutes}:${String(seconds).padStart(2, '0')}`;
}
