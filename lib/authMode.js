import { assertLoopbackExposure } from './publicOrigin.js';

export function parseAuthBoolean(value, fallback = false) {
  if (value === undefined || value === null || value === '') {
    return fallback;
  }
  const normalized = String(value).trim().toLowerCase();
  if (['1', 'true', 'yes', 'on'].includes(normalized)) {
    return true;
  }
  if (['0', 'false', 'no', 'off'].includes(normalized)) {
    return false;
  }
  throw new Error(`Invalid boolean authentication setting: ${value}`);
}

export function resolveAuthMode(env = process.env) {
  const guardMtls = parseAuthBoolean(env.NOTTY_GUARD_MTLS, false);
  const basicDisabled = parseAuthBoolean(env.NOTTY_NOAUTH, false);
  const oauthDisabled = parseAuthBoolean(env.NOTTY_NO_OAUTH, false);
  const explicitOtpOnly = parseAuthBoolean(env.NOTTY_NO_OTP_AUTH, false)
    || (basicDisabled && oauthDisabled);
  const noauthRequested = explicitOtpOnly || basicDisabled;
  const noOauthRequested = explicitOtpOnly || oauthDisabled;
  const oauthEnabled = noOauthRequested || guardMtls
    ? false
    : parseAuthBoolean(env.NOTTY_OAUTH_ENABLED, true);
  const basicEnabled = noauthRequested || guardMtls
    ? false
    : parseAuthBoolean(env.NOTTY_BASIC_AUTH_ENABLED, true);
  // Treat every effective "both HTTP schemes off" configuration as OTP-only.
  // This keeps legacy environment toggles from accidentally exposing the OTP
  // mint endpoint to an otherwise unauthenticated client.
  const otpOnly = !guardMtls && (explicitOtpOnly || (!oauthEnabled && !basicEnabled));
  const noauth = !guardMtls && (noauthRequested || !basicEnabled);
  const noOauth = !guardMtls && (noOauthRequested || !oauthEnabled);
  const spawnOtpEnabled = parseAuthBoolean(env.NOTTY_MCP_SPAWN_OTP_ENABLED, true);

  if (otpOnly && !spawnOtpEnabled) {
    throw new Error('--no-otp-auth cannot be combined with --no-otp');
  }
  if (guardMtls && explicitOtpOnly) {
    throw new Error('--no-otp-auth is not available in Guard mTLS mode');
  }
  if (guardMtls && !spawnOtpEnabled) {
    throw new Error('Guard mTLS runners must keep terminal spawn OTP enforcement enabled');
  }
  let name = 'default';
  if (guardMtls) {
    name = 'guard-mtls';
  } else if (otpOnly) {
    name = 'otp-only';
  } else if (!spawnOtpEnabled) {
    name = 'no-otp';
  } else if (noauth) {
    name = 'noauth';
  } else if (noOauth || !oauthEnabled) {
    name = 'no-oauth';
  }

  return {
    name,
    guardMtls,
    otpOnly,
    noauth,
    noOauth,
    oauthEnabled,
    basicEnabled,
    spawnOtpEnabled,
    requiresLoopback: !guardMtls && (otpOnly || noauth || noOauth || !spawnOtpEnabled)
  };
}

export function validateAuthModeExposure(mode, options = {}) {
  if (!mode.requiresLoopback) {
    return mode;
  }
  assertLoopbackExposure(options);
  return mode;
}
