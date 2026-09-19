'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const test = require('node:test');

function createResponse() {
  return {
    statusCode: 200,
    body: null,
    headers: {},
    setHeader(name, value) {
      this.headers[name.toLowerCase()] = value;
    },
    status(value) {
      this.statusCode = value;
      return this;
    },
    json(value) {
      this.body = value;
      return this;
    },
    end() {
      return this;
    },
  };
}

function nextRequest(body) {
  return {
    method: 'POST',
    body,
    headers: { 'content-type': 'application/json' },
    socket: { remoteAddress: '127.0.0.1' },
  };
}

async function stopTerminal(terminalManager, terminalUuid) {
  try {
    await new Promise((resolve) => {
      const timeout = setTimeout(resolve, 2_000);
      terminalManager.onTerminalExit(terminalUuid, () => {
        clearTimeout(timeout);
        resolve();
      });
      terminalManager.killTerminal(terminalUuid);
    });
  } catch {
    // The terminal may already have exited.
  }
}

test('Next and Express terminal POST routes share one-time fail-closed OTP enforcement', {
  timeout: 15_000,
}, async (t) => {
  const originalStateDirectory = process.env.NOTTY_AUTH_STATE_DIR;
  const originalOtpEnabled = process.env.NOTTY_MCP_SPAWN_OTP_ENABLED;
  const originalLockdown = process.env.NOTTY_LOCKDOWN;
  const originalOtpOnly = process.env.NOTTY_NO_OTP_AUTH;
  const originalGuardMtls = process.env.NOTTY_GUARD_MTLS;
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'notty-terminal-http-'));
  process.env.NOTTY_AUTH_STATE_DIR = path.join(root, 'auth');
  delete process.env.NOTTY_MCP_SPAWN_OTP_ENABLED;
  delete process.env.NOTTY_LOCKDOWN;
  delete process.env.NOTTY_NO_OTP_AUTH;
  delete process.env.NOTTY_GUARD_MTLS;

  const express = (await import('express')).default;
  const authState = await import('../lib/authState.js');
  const { createSpawnOtp } = await import('../lib/mcpSpawnOtp.js');
  const terminalManager = await import('../lib/terminalManager.js');
  const nextHandler = (await import('../pages/api/terminals/index.js')).default;
  const spawnOtpHandler = (await import('../pages/api/spawn-otps.js')).default;
  const { registerTerminalHttpRoutes } = await import('../lib/terminalHttpApi.js');
  const terminalUuids = new Set();
  let server = null;

  t.after(async () => {
    if (server) {
      server.closeAllConnections?.();
      await new Promise((resolve) => server.close(resolve));
    }
    for (const terminalUuid of terminalUuids) {
      await stopTerminal(terminalManager, terminalUuid);
    }
    authState.closeAuthState({ stateDirectory: process.env.NOTTY_AUTH_STATE_DIR });
    if (originalStateDirectory === undefined) delete process.env.NOTTY_AUTH_STATE_DIR;
    else process.env.NOTTY_AUTH_STATE_DIR = originalStateDirectory;
    if (originalOtpEnabled === undefined) delete process.env.NOTTY_MCP_SPAWN_OTP_ENABLED;
    else process.env.NOTTY_MCP_SPAWN_OTP_ENABLED = originalOtpEnabled;
    if (originalLockdown === undefined) delete process.env.NOTTY_LOCKDOWN;
    else process.env.NOTTY_LOCKDOWN = originalLockdown;
    if (originalOtpOnly === undefined) delete process.env.NOTTY_NO_OTP_AUTH;
    else process.env.NOTTY_NO_OTP_AUTH = originalOtpOnly;
    if (originalGuardMtls === undefined) delete process.env.NOTTY_GUARD_MTLS;
    else process.env.NOTTY_GUARD_MTLS = originalGuardMtls;
    fs.rmSync(root, { recursive: true, force: true });
  });

  const missingNext = createResponse();
  nextHandler(nextRequest({}), missingNext);
  assert.equal(missingNext.statusCode, 403);
  assert.equal(missingNext.body.error.code, 'spawn_terminal_otp_required');

  const nonJsonNext = createResponse();
  nextHandler({ ...nextRequest({}), headers: { 'content-type': 'text/plain' } }, nonJsonNext);
  assert.equal(nonJsonNext.statusCode, 415);
  assert.equal(nonJsonNext.body.error.code, 'terminal_spawn_json_required');

  const nextOtp = createSpawnOtp({ source: 'next-route-test' });
  const createdNext = createResponse();
  nextHandler(nextRequest({ otp: nextOtp.value }), createdNext);
  assert.equal(createdNext.statusCode, 201);
  terminalUuids.add(createdNext.body.session.terminal_uuid);

  const replayNext = createResponse();
  nextHandler(nextRequest({ otp: nextOtp.value }), replayNext);
  assert.equal(replayNext.statusCode, 403);
  assert.equal(replayNext.body.error.code, 'spawn_terminal_otp_used');

  const app = express();
  registerTerminalHttpRoutes(app, {
    publicOrigin: 'https://notty.example',
    trustedHosts: ['notty.example'],
  });
  server = await new Promise((resolve) => {
    const listener = app.listen(0, '127.0.0.1', () => resolve(listener));
  });
  const address = server.address();
  const endpoint = `http://127.0.0.1:${address.port}/api/terminals`;

  const tlsTerminatedBrowser = await fetch(endpoint, {
    method: 'POST',
    headers: {
      Host: 'notty.example',
      Origin: 'https://notty.example',
      'content-type': 'application/json',
    },
    body: '{}',
  });
  assert.equal(tlsTerminatedBrowser.status, 403);
  assert.equal(
    (await tlsTerminatedBrowser.json()).error.code,
    'spawn_terminal_otp_required',
  );

  const missingExpress = await fetch(endpoint, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: '{}',
  });
  assert.equal(missingExpress.status, 403);
  assert.equal((await missingExpress.json()).error.code, 'spawn_terminal_otp_required');

  const nonJsonExpress = await fetch(endpoint, {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: 'otp=not-accepted',
  });
  assert.equal(nonJsonExpress.status, 415);
  assert.equal((await nonJsonExpress.json()).error.code, 'terminal_spawn_json_required');

  const otpLogCanary = 'otp-must-never-appear-in-parser-logs';
  const capturedErrors = [];
  const originalConsoleError = console.error;
  console.error = (...parts) => capturedErrors.push(parts);
  let malformedExpress;
  try {
    malformedExpress = await fetch(endpoint, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: `{"otp":"${otpLogCanary}"`,
    });
  } finally {
    console.error = originalConsoleError;
  }
  assert.equal(malformedExpress.status, 400);
  assert.equal((await malformedExpress.json()).error.code, 'invalid_json_body');
  assert.equal(JSON.stringify(capturedErrors).includes(otpLogCanary), false);

  const expressOtp = createSpawnOtp({ source: 'express-route-test' });
  const createdExpress = await fetch(endpoint, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ otp: expressOtp.value }),
  });
  assert.equal(createdExpress.status, 201);
  const expressPayload = await createdExpress.json();
  terminalUuids.add(expressPayload.session.terminal_uuid);

  const renewalOtp = createSpawnOtp({ ttlSeconds: 120 });
  const renewalUrl = `${endpoint}/${expressPayload.session.id}/renew`;
  const renewedResponse = await fetch(renewalUrl, {
    method: 'POST', headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ otp: renewalOtp.value }),
  });
  assert.equal(renewedResponse.status, 200);
  const renewedPayload = await renewedResponse.json();
  assert.equal(renewedPayload.session.inputAccess.expiresAt, renewalOtp.expiresAt);
  assert.equal(renewedPayload.session.terminal_uuid, expressPayload.session.terminal_uuid);
  const renewHandler = (await import('../pages/api/terminals/[id]/renew.js')).default;
  const replayResponse = createResponse();
  renewHandler({ ...nextRequest({ otp: renewalOtp.value }), query: { id: expressPayload.session.id } }, replayResponse);
  assert.equal(replayResponse.statusCode, 403);
  const nextRenewOtp = createSpawnOtp({ ttlSeconds: 180 });
  const nextRenewResponse = createResponse();
  renewHandler({ ...nextRequest({ otp: nextRenewOtp.value }), query: { id: expressPayload.session.id } }, nextRenewResponse);
  assert.equal(nextRenewResponse.statusCode, 200);
  assert.equal(nextRenewResponse.body.session.inputAccess.expiresAt, nextRenewOtp.expiresAt);

  const nonJsonMint = createResponse();
  spawnOtpHandler(
    { ...nextRequest({}), headers: { 'content-type': 'application/x-www-form-urlencoded' } },
    nonJsonMint,
  );
  assert.equal(nonJsonMint.statusCode, 415);
  assert.equal(nonJsonMint.body.error.code, 'spawn_otp_json_required');

  process.env.NOTTY_NO_OTP_AUTH = 'true';
  const otpOnlyMint = createResponse();
  spawnOtpHandler(nextRequest({}), otpOnlyMint);
  assert.equal(otpOnlyMint.statusCode, 403);
  assert.equal(otpOnlyMint.body.error.code, 'spawn_otp_http_mint_disabled');
});
