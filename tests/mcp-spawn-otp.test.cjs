'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');

const SPAWN_OTP_ENV_KEYS = [
  'NOTTY_MCP_SPAWN_OTP',
  'NOTTY_MCP_SPAWN_OTP_TTL_SECONDS',
];

function snapshotEnvironment(keys) {
  return new Map(keys.map((key) => [
    key,
    {
      present: Object.prototype.hasOwnProperty.call(process.env, key),
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

function terminalUuids(listTerminals) {
  return listTerminals()
    .map((terminal) => terminal.terminal_uuid)
    .sort();
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

test('each agent runtime gets a distinct single-use OTP for one terminal spawn', {
  timeout: 10_000,
}, async () => {
  const savedEnvironment = snapshotEnvironment(SPAWN_OTP_ENV_KEYS);
  const savedOtpState = globalThis.__mcpSpawnOtpState;
  const savedTerminalState = globalThis.__terminalManagerState;
  const spawnedTerminalUuids = new Set();
  let callTool;
  let listTerminals;

  for (const key of SPAWN_OTP_ENV_KEYS) {
    delete process.env[key];
  }

  try {
    const otpRegistry = await import('../lib/mcpSpawnOtp.js');
    ({ callTool } = await import('../lib/mcpTools.js'));
    ({ listTerminals } = await import('../lib/terminalManager.js'));

    const baselineTerminalUuids = terminalUuids(listTerminals);
    const runtimeOtps = ['codex', 'agy', 'ollama'].map((runtime) => ({
      runtime,
      otp: otpRegistry.createSpawnOtp(),
    }));

    assert.equal(
      new Set(runtimeOtps.map(({ otp }) => otp.value)).size,
      runtimeOtps.length,
      'each runtime should receive a distinct OTP value',
    );
    assert.equal(
      new Set(runtimeOtps.map(({ otp }) => otp.uuid)).size,
      runtimeOtps.length,
      'each runtime OTP should have distinct UUID metadata',
    );

    for (const { runtime, otp } of runtimeOtps) {
      assert.match(otp.value, /^[A-Za-z0-9_-]{24}$/, `${runtime} OTP should be generated`);
      assert.match(
        otp.uuid,
        /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i,
        `${runtime} OTP should include UUID metadata`,
      );
      assert.equal(otp.source, 'ui');
      assert.equal(otp.status, 'available');
      assert.equal(otp.usedAt, null);

      const beforeSpawn = terminalUuids(listTerminals);
      const spawnResult = callTool('spawn_terminal', {
        otp: otp.value,
        cols: 80,
        rows: 30,
        cwd: process.cwd(),
      });
      assert.notEqual(spawnResult.isError, true, `${runtime} spawn should succeed`);

      const spawnPayload = parseToolJson(spawnResult);
      assert.match(
        spawnPayload.terminal_uuid,
        /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i,
        `${runtime} spawn should return a terminal UUID`,
      );
      spawnedTerminalUuids.add(spawnPayload.terminal_uuid);

      const afterSpawn = terminalUuids(listTerminals);
      assert.equal(afterSpawn.length, beforeSpawn.length + 1);
      assert.ok(afterSpawn.includes(spawnPayload.terminal_uuid));

      const replayResult = callTool('spawn_terminal', {
        otp: otp.value,
        cols: 80,
        rows: 30,
        cwd: process.cwd(),
      });
      assert.equal(replayResult.isError, true, `${runtime} OTP replay should fail`);
      assert.equal(
        parseToolJson(replayResult).error.code,
        'spawn_terminal_otp_used',
      );
      assert.deepEqual(
        terminalUuids(listTerminals),
        afterSpawn,
        `${runtime} OTP replay must not spawn a second terminal`,
      );
    }

    assert.equal(
      spawnedTerminalUuids.size,
      runtimeOtps.length,
      'successful runtime spawns should return distinct terminal UUIDs',
    );

    const dashboard = otpRegistry.getSpawnOtpDashboard();
    for (const { runtime, otp } of runtimeOtps) {
      const storedOtp = dashboard.otps.find((entry) => entry.uuid === otp.uuid);
      assert.ok(storedOtp, `${runtime} OTP metadata should remain auditable`);
      assert.equal(storedOtp.value, otp.value);
      assert.equal(storedOtp.status, 'used');
      assert.equal(typeof storedOtp.usedAt, 'number');
    }

    for (const terminalUuid of spawnedTerminalUuids) {
      const killResult = callTool('kill_terminal', {
        terminal_uuid: terminalUuid,
      });
      assert.notEqual(killResult.isError, true);
      assert.equal(parseToolJson(killResult).killed, true);
    }

    assert.equal(
      await waitFor(
        () => terminalUuids(listTerminals).length === baselineTerminalUuids.length,
      ),
      true,
      'spawned terminals should exit after cleanup',
    );
    assert.deepEqual(terminalUuids(listTerminals), baselineTerminalUuids);
  } finally {
    if (callTool && listTerminals) {
      for (const terminalUuid of spawnedTerminalUuids) {
        if (!terminalUuids(listTerminals).includes(terminalUuid)) {
          continue;
        }
        try {
          callTool('kill_terminal', { terminal_uuid: terminalUuid });
        } catch {
          // Best-effort cleanup for a failed assertion.
        }
      }
      await waitFor(
        () => terminalUuids(listTerminals)
          .every((terminalUuid) => !spawnedTerminalUuids.has(terminalUuid)),
      );
    }

    if (
      globalThis.__mcpSpawnOtpState
      && globalThis.__mcpSpawnOtpState !== savedOtpState
    ) {
      globalThis.__mcpSpawnOtpState.entries.clear();
    }
    if (savedOtpState === undefined) {
      delete globalThis.__mcpSpawnOtpState;
    } else {
      globalThis.__mcpSpawnOtpState = savedOtpState;
    }

    if (savedTerminalState === undefined) {
      delete globalThis.__terminalManagerState;
    } else {
      globalThis.__terminalManagerState = savedTerminalState;
    }
    restoreEnvironment(savedEnvironment);
  }
});
