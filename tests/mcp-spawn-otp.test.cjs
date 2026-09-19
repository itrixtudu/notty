'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const test = require('node:test');

const SPAWN_OTP_ENV_KEYS = [
  'NOTTY_AUTH_STATE_DIR',
  'NOTTY_MCP_SPAWN_OTP',
  'NOTTY_MCP_SPAWN_OTP_ENABLED',
  'NOTTY_MCP_SPAWN_OTP_TTL_SECONDS',
  'NOTTY_BASIC_AUTH_PASSWORD',
  'MCP_BEARER_TOKEN',
  'MCP_TOKEN',
  'NOTTY_GUARD_MTLS',
  'NOTTY_GUARD_GATEWAY_PEER_IP',
  'NOTTY_GUARD_GATEWAY_TOKEN',
  'NOTTY_GUARD_OTP_MINT_TOKEN',
  'NOTTY_LOOPBACK_PUBLICATION',
  'NOTTY_OAUTH_CLIENT_SECRET',
  'NOTTY_SAFE_CHILD_CANARY',
];

function snapshotEnvironment(keys) {
  return new Map(keys.map((key) => [
    key,
    {
      present: Object.hasOwn(process.env, key),
      value: process.env[key],
    },
  ]));
}

function restoreEnvironment(snapshot) {
  for (const [key, saved] of snapshot) {
    if (saved.present) {
      process.env[key] = saved.value;
    } else {
      delete process.env[key];
    }
  }
}

function parseToolJson(result) {
  assert.equal(result?.content?.[0]?.type, 'text');
  return JSON.parse(result.content[0].text);
}

async function waitFor(predicate, timeoutMs = 2000) {
  const deadline = Date.now() + timeoutMs;
  while (!predicate()) {
    if (Date.now() >= deadline) {
      return false;
    }
    await new Promise((resolve) => setTimeout(resolve, 20));
  }
  return true;
}

test('spawn OTP registry is persistent, value-less, atomic, and fail closed', {
  timeout: 15_000,
}, async (t) => {
  const savedEnvironment = snapshotEnvironment(SPAWN_OTP_ENV_KEYS);
  const stateRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'notty-spawn-otp-'));
  process.env.NOTTY_AUTH_STATE_DIR = path.join(stateRoot, 'auth');
  delete process.env.NOTTY_MCP_SPAWN_OTP;
  delete process.env.NOTTY_MCP_SPAWN_OTP_ENABLED;
  delete process.env.NOTTY_MCP_SPAWN_OTP_TTL_SECONDS;

  const otpRegistry = await import('../lib/mcpSpawnOtp.js');
  const authState = await import('../lib/authState.js');
  const { callTool } = await import('../lib/mcpTools.js');
  const { callTool: callSimpleTool } = await import('../lib/mcpToolsSimple.js');
  const { callTool: callDurdrawTool } = await import('../lib/mcpDurdraw.js');
  const {
    listTerminals,
    onTerminalExit,
    spawnTerminal,
    subscribeToTerminal,
  } = await import('../lib/terminalManager.js');
  const spawnedTerminalUuids = new Set();

  t.after(async () => {
    for (const terminalUuid of spawnedTerminalUuids) {
      try {
        callTool('kill_terminal', { terminal_uuid: terminalUuid });
      } catch {
        // Best-effort cleanup for assertion failures.
      }
    }
    await waitFor(() => listTerminals().every(
      (terminal) => !spawnedTerminalUuids.has(terminal.terminal_uuid),
    ));
    authState.closeAuthState({ stateDirectory: process.env.NOTTY_AUTH_STATE_DIR });
    restoreEnvironment(savedEnvironment);
    fs.rmSync(stateRoot, { recursive: true, force: true });
  });

  assert.equal(otpRegistry.isSpawnOtpProtected(), true);
  assert.deepEqual(otpRegistry.getSpawnOtpSummary(), {
    enabled: true,
    totalCount: 0,
    availableCount: 0,
    usedCount: 0,
    expiredCount: 0,
    revokedCount: 0,
    defaultTtlSeconds: null,
  });

  const emptyRegistryAttempt = callTool('spawn_terminal', {
    cwd: process.cwd(),
  });
  assert.equal(emptyRegistryAttempt.isError, true);
  assert.equal(parseToolJson(emptyRegistryAttempt).error.code, 'spawn_terminal_otp_required');
  assert.throws(
    () => spawnTerminal(
      { trusted: true, capability: 'trusted' },
      { capability: Symbol('notty.trustedTerminalSpawn') },
    ),
    (error) => error?.code === 'spawn_terminal_otp_required',
    'request data and lookalike symbols must not select the trusted internal bypass',
  );
  const listWithoutOtp = callTool('list_terminals', {});
  assert.notEqual(listWithoutOtp.isError, true, 'non-spawn tools must not require an OTP');

  const simpleAttempt = await callSimpleTool('spawn_terminal', {});
  assert.equal(simpleAttempt.isError, true);
  assert.equal(parseToolJson(simpleAttempt).error.code, 'spawn_terminal_otp_required');
  const implicitSimpleAttempt = await callSimpleTool('run_command', { command: 'pwd' });
  assert.equal(implicitSimpleAttempt.isError, true);
  assert.equal(parseToolJson(implicitSimpleAttempt).error.code, 'spawn_terminal_otp_required');
  const durdrawAttempt = await callDurdrawTool('spawn_durdraw', { command: 'true' });
  assert.equal(durdrawAttempt.isError, true);
  assert.equal(parseToolJson(durdrawAttempt).error.code, 'spawn_terminal_otp_required');
  assert.throws(
    () => otpRegistry.createSpawnOtp({ ttlSeconds: '1.5' }),
    /TTL must be a positive integer/,
  );
  assert.throws(
    () => otpRegistry.consumeSpawnOtp({ otp: 'unknown-otp-value' }),
    (error) => error?.code === 'spawn_terminal_otp_invalid',
  );

  const expiredOtp = otpRegistry.createSpawnOtp({ source: 'expired-test', ttlSeconds: 60 });
  authState.getAuthState().database.prepare(
    'UPDATE spawn_otps SET expires_at = ? WHERE uuid = ?',
  ).run(Date.now() - 1, expiredOtp.uuid);
  assert.throws(
    () => otpRegistry.consumeSpawnOtp({ otp: expiredOtp.value }),
    (error) => error?.code === 'spawn_terminal_otp_expired',
  );

  const revokedOtp = otpRegistry.createSpawnOtp({ source: 'revoked-test' });
  authState.getAuthState().database.prepare(
    'UPDATE spawn_otps SET revoked_at = ? WHERE uuid = ?',
  ).run(Date.now(), revokedOtp.uuid);
  assert.throws(
    () => otpRegistry.consumeSpawnOtp({ otp: revokedOtp.value }),
    (error) => error?.code === 'spawn_terminal_otp_revoked',
  );

  const otp = otpRegistry.createSpawnOtp({ source: 'test' });
  assert.match(otp.value, /^[A-Za-z0-9_-]{24}$/);
  const dashboardBefore = otpRegistry.getSpawnOtpDashboard();
  const dashboardEntry = dashboardBefore.otps.find((entry) => entry.uuid === otp.uuid);
  assert.ok(dashboardEntry);
  assert.equal(Object.hasOwn(dashboardEntry, 'value'), false);
  assert.equal(JSON.stringify(dashboardBefore).includes(otp.value), false);

  const databaseRow = authState.getAuthState().database.prepare(`
    SELECT token_hash FROM spawn_otps WHERE uuid = ?
  `).get(otp.uuid);
  assert.notEqual(databaseRow.token_hash, otp.value);
  assert.equal(databaseRow.token_hash.length, 64);

  assert.throws(
    () => spawnTerminal({ cols: 0, rows: 30, otp: otp.value }),
    /cols and rows must be positive/,
    'request validation must happen before OTP consumption',
  );
  assert.equal(
    otpRegistry.getSpawnOtpDashboard().otps.find((entry) => entry.uuid === otp.uuid).status,
    'available',
  );

  const success = callTool('spawn_terminal', {
    otp: otp.value,
    cols: 80,
    rows: 30,
    cwd: process.cwd(),
  });
  assert.notEqual(success.isError, true);
  const terminalUuid = parseToolJson(success).terminal_uuid;
  spawnedTerminalUuids.add(terminalUuid);

  const replay = callTool('spawn_terminal', {
    otp: otp.value,
    cwd: process.cwd(),
  });
  assert.equal(replay.isError, true);
  assert.equal(parseToolJson(replay).error.code, 'spawn_terminal_otp_used');

  const consumed = otpRegistry.getSpawnOtpDashboard().otps.find((entry) => entry.uuid === otp.uuid);
  assert.equal(consumed.status, 'used');
  assert.equal(typeof consumed.consumedAt, 'number');
  assert.equal(Object.hasOwn(consumed, 'value'), false);

  authState.closeAuthState();
  assert.throws(
    () => otpRegistry.consumeSpawnOtp({ otp: otp.value }),
    (error) => error?.code === 'spawn_terminal_otp_used',
    'consumption tombstones must survive reopening the database',
  );

  const failedSpawnOtp = otpRegistry.createSpawnOtp({ source: 'failed-spawn-test' });
  assert.throws(
    () => spawnTerminal({ shell: '/definitely/missing/notty-shell', otp: failedSpawnOtp.value }),
  );
  assert.throws(
    () => otpRegistry.consumeSpawnOtp({ otp: failedSpawnOtp.value }),
    (error) => error?.code === 'spawn_terminal_otp_used',
    'a spawn failure after acceptance must still consume the OTP',
  );

  process.env.NOTTY_MCP_SPAWN_OTP = 'launcher-secret-must-not-leak';
  process.env.NOTTY_BASIC_AUTH_PASSWORD = 'basic-secret-must-not-leak';
  process.env.MCP_BEARER_TOKEN = 'mcp-bearer-must-not-leak';
  process.env.MCP_TOKEN = 'mcp-token-must-not-leak';
  process.env.NOTTY_OAUTH_CLIENT_SECRET = 'oauth-secret-must-not-leak';
  process.env.NOTTY_GUARD_MTLS = 'true';
  process.env.NOTTY_GUARD_GATEWAY_PEER_IP = '10.240.9.2';
  process.env.NOTTY_GUARD_GATEWAY_TOKEN = 'guard-gateway-must-not-leak';
  process.env.NOTTY_GUARD_OTP_MINT_TOKEN = 'guard-mint-must-not-leak';
  process.env.NOTTY_LOOPBACK_PUBLICATION = 'true';
  process.env.NOTTY_SAFE_CHILD_CANARY = 'safe-value-is-present';
  const environmentOtp = otpRegistry.createSpawnOtp({ source: 'environment-test' });
  const environmentSession = spawnTerminal({
    shell: 'bash',
    command: 'sleep 0.1; env; sleep 0.1',
    shellIntegration: false,
    otp: environmentOtp.value,
  });
  const environmentOutput = [];
  subscribeToTerminal(environmentSession.terminal_uuid, (data) => environmentOutput.push(data));
  await new Promise((resolve, reject) => {
    const timeout = setTimeout(() => reject(new Error('environment canary terminal did not exit')), 3000);
    onTerminalExit(environmentSession.terminal_uuid, () => {
      clearTimeout(timeout);
      resolve();
    });
  });
  const environmentText = environmentOutput.join('');
  assert.match(environmentText, /NOTTY_SAFE_CHILD_CANARY=safe-value-is-present/);
  for (const secret of [
    'launcher-secret-must-not-leak',
    'basic-secret-must-not-leak',
    'mcp-bearer-must-not-leak',
    'mcp-token-must-not-leak',
    'oauth-secret-must-not-leak',
    'guard-gateway-must-not-leak',
    'guard-mint-must-not-leak',
  ]) {
    assert.equal(environmentText.includes(secret), false);
  }
  assert.doesNotMatch(
    environmentText,
    /(?:MCP_(?:BEARER_)?TOKEN|NOTTY_(?:MCP_SPAWN_OTP(?:_ENABLED|_TTL_SECONDS)?|BASIC_AUTH_PASSWORD|OAUTH_CLIENT_SECRET|GUARD_(?:MTLS|GATEWAY_(?:PEER_IP|TOKEN)|OTP_MINT_TOKEN)|LOOPBACK_PUBLICATION))=/,
  );

  const firstLauncherRecord = otpRegistry.getSpawnOtpDashboard().otps.find(
    (otp) => otp.source === 'env' && otp.status === 'available',
  );
  assert.ok(firstLauncherRecord);
  process.env.NOTTY_MCP_SPAWN_OTP = 'replacement-launcher-secret-must-not-leak';
  const rotatedDashboard = otpRegistry.getSpawnOtpDashboard();
  const launcherRecords = rotatedDashboard.otps.filter((otp) => otp.source === 'env');
  assert.equal(launcherRecords.filter((otp) => otp.status === 'available').length, 1);
  assert.equal(
    launcherRecords.find((otp) => otp.uuid === firstLauncherRecord.uuid).status,
    'revoked',
    'rotating the launcher OTP revokes the previous unused launcher capability',
  );

  const concurrentOtp = otpRegistry.createSpawnOtp({ source: 'concurrency-test' });
  const timedOtp = otpRegistry.createSpawnOtp({ source: 'input-expiry-test', ttlSeconds: 60 });
  const timedSession = spawnTerminal({ shell: 'bash', otp: timedOtp.value });
  spawnedTerminalUuids.add(timedSession.terminal_uuid);
  const { writeToTerminal, getTerminalSummary } = await import('../lib/terminalManager.js');
  const { renewTerminalInputAccess } = await import('../lib/terminalManager.js');
  assert.equal(getTerminalSummary(timedSession.id).inputAccess.expiresAt, timedOtp.expiresAt);
  const originalNow = Date.now;
  try {
    Date.now = () => timedOtp.expiresAt - 1;
    assert.doesNotThrow(() => writeToTerminal(timedSession.id, ''));
    Date.now = () => timedOtp.expiresAt;
    assert.throws(() => writeToTerminal(timedSession.id, 'echo forbidden\r'),
      (error) => error.code === 'TERMINAL_INPUT_EXPIRED' && error.statusCode === 403);
    assert.equal(getTerminalSummary(timedSession.id).alive, true);
    const replacement = otpRegistry.createSpawnOtp({ source: 'renewal-test', ttlSeconds: 120 });
    assert.throws(() => renewTerminalInputAccess(timedSession.id, { otp: timedOtp.value }),
      (error) => error.code === 'spawn_terminal_otp_used');
    assert.equal(getTerminalSummary(timedSession.id).inputAccess.expiresAt, timedOtp.expiresAt);
    const renewed = renewTerminalInputAccess(timedSession.id, { otp: replacement.value });
    assert.equal(renewed.terminal_uuid, timedSession.terminal_uuid);
    assert.equal(renewed.inputAccess.expiresAt, replacement.expiresAt);
    assert.doesNotThrow(() => writeToTerminal(timedSession.id, ''));
    assert.throws(() => renewTerminalInputAccess(timedSession.id, { otp: replacement.value }),
      (error) => error.code === 'spawn_terminal_otp_used');
    const unused = otpRegistry.createSpawnOtp({ source: 'missing-session-renewal', ttlSeconds: 120 });
    assert.throws(() => renewTerminalInputAccess('missing-session', { otp: unused.value }));
    assert.equal(otpRegistry.getSpawnOtpDashboard().available.some((entry) => entry.uuid === unused.uuid), true);
  } finally {
    Date.now = originalNow;
  }
  const results = await Promise.allSettled([
    Promise.resolve().then(() => otpRegistry.consumeSpawnOtp({ otp: concurrentOtp.value })),
    Promise.resolve().then(() => otpRegistry.consumeSpawnOtp({ otp: concurrentOtp.value })),
  ]);
  assert.equal(results.filter((result) => result.status === 'fulfilled').length, 1);
  assert.equal(results.filter((result) => result.status === 'rejected').length, 1);
  assert.equal(results.find((result) => result.status === 'rejected').reason.code, 'spawn_terminal_otp_used');

  process.env.NOTTY_MCP_SPAWN_OTP_ENABLED = 'false';
  const disabledAttempt = callTool('spawn_terminal', { cwd: process.cwd() });
  assert.notEqual(disabledAttempt.isError, true);
  spawnedTerminalUuids.add(parseToolJson(disabledAttempt).terminal_uuid);
});
