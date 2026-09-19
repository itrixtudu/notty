'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');

test('public origins are exact and HTTP is loopback-only', async () => {
  const { parsePublicOrigin, validateOAuthRedirectUri } = await import('../lib/publicOrigin.js');
  assert.equal(parsePublicOrigin('https://notty.example'), 'https://notty.example');
  assert.equal(parsePublicOrigin('http://127.0.0.1:3000'), 'http://127.0.0.1:3000');
  assert.equal(validateOAuthRedirectUri('https://client.example/callback'), true);
  assert.equal(validateOAuthRedirectUri('http://localhost:1455/callback'), true);
  assert.equal(validateOAuthRedirectUri('http://client.example/callback'), false);
  assert.throws(() => parsePublicOrigin('http://notty.example'), /HTTP only/);
  assert.throws(() => parsePublicOrigin('https://user:not-secret@notty.example'), /credentials/);
  assert.throws(() => parsePublicOrigin('https://notty.example/path'), /path/);
  assert.throws(() => parsePublicOrigin('https://notty.example/'), /exact origin/);
});

test('authentication mode matrix preserves OTP-only and no-OTP invariants', async () => {
  const { resolveAuthMode } = await import('../lib/authMode.js');
  assert.deepEqual(
    resolveAuthMode({ NOTTY_BASIC_AUTH_ENABLED: 'true' }),
    {
      name: 'default',
      guardMtls: false,
      otpOnly: false,
      noauth: false,
      noOauth: false,
      oauthEnabled: true,
      basicEnabled: true,
      spawnOtpEnabled: true,
      requiresLoopback: false
    }
  );
  assert.equal(resolveAuthMode({ NOTTY_NOAUTH: 'true' }).oauthEnabled, true);
  assert.equal(resolveAuthMode({
    NOTTY_NO_OAUTH: 'true',
    NOTTY_BASIC_AUTH_ENABLED: 'true'
  }).basicEnabled, true);
  assert.deepEqual(
    resolveAuthMode({ NOTTY_NO_OTP_AUTH: 'true' }),
    {
      name: 'otp-only',
      guardMtls: false,
      otpOnly: true,
      noauth: true,
      noOauth: true,
      oauthEnabled: false,
      basicEnabled: false,
      spawnOtpEnabled: true,
      requiresLoopback: true
    }
  );
  assert.deepEqual(
    resolveAuthMode({
      NOTTY_BASIC_AUTH_ENABLED: 'false',
      NOTTY_OAUTH_ENABLED: 'false'
    }),
    {
      name: 'otp-only',
      guardMtls: false,
      otpOnly: true,
      noauth: true,
      noOauth: true,
      oauthEnabled: false,
      basicEnabled: false,
      spawnOtpEnabled: true,
      requiresLoopback: true
    }
  );
  assert.throws(
    () => resolveAuthMode({
      NOTTY_NO_OTP_AUTH: 'true',
      NOTTY_MCP_SPAWN_OTP_ENABLED: 'false'
    }),
    /cannot be combined/
  );
  assert.throws(
    () => resolveAuthMode({
      NOTTY_BASIC_AUTH_ENABLED: 'false',
      NOTTY_OAUTH_ENABLED: 'false',
      NOTTY_MCP_SPAWN_OTP_ENABLED: 'false'
    }),
    /cannot be combined/
  );
  assert.throws(
    () => resolveAuthMode({
      NOTTY_GUARD_MTLS: 'true',
      NOTTY_NO_OTP_AUTH: 'true'
    }),
    /not available in Guard/
  );
});
