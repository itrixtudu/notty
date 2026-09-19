'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');

function jsonResponse(status, payload, statusText = '') {
  return {
    ok: status >= 200 && status < 300,
    status,
    statusText,
    json: async () => payload,
  };
}

test('browser terminal spawning sends a manually supplied OTP only in the JSON body', async (t) => {
  const originalFetch = globalThis.fetch;
  const requests = [];
  globalThis.fetch = async (url, options = {}) => {
    requests.push({ url, options });
    return jsonResponse(201, { session: { id: 7 } });
  };
  t.after(() => {
    globalThis.fetch = originalFetch;
  });

  const { spawnBrowserTerminal } = await import('../lib/browserTerminalSpawn.js');
  const payload = await spawnBrowserTerminal({
    cwd: '/workspace',
    otp: 'caller-injected-value-must-be-ignored',
  }, '  manually-entered-value  ');

  assert.equal(payload.session.id, 7);
  assert.equal(requests.length, 1);
  assert.equal(requests[0].url, '/api/terminals');
  assert.equal(new URL(requests[0].url, 'http://localhost').search, '');
  assert.equal(requests[0].options.headers.Authorization, undefined);
  assert.deepEqual(JSON.parse(requests[0].options.body), {
    cwd: '/workspace',
    otp: 'manually-entered-value',
  });
});

test('browser OTP status probing fails closed and recognizes explicit no-OTP mode', async (t) => {
  const originalFetch = globalThis.fetch;
  const { browserSpawnOtpRequired } = await import('../lib/browserTerminalSpawn.js');
  t.after(() => {
    globalThis.fetch = originalFetch;
  });

  globalThis.fetch = async () => jsonResponse(200, { enabled: false });
  assert.equal(await browserSpawnOtpRequired(), false);

  globalThis.fetch = async () => jsonResponse(200, { enabled: true });
  assert.equal(await browserSpawnOtpRequired(), true);

  globalThis.fetch = async () => {
    throw new Error('status endpoint unavailable');
  };
  assert.equal(await browserSpawnOtpRequired(), true);
});

test('MCP browser calls recognize spawn-capable tools and never retain caller OTP values', async () => {
  const {
    mcpToolRequiresSpawnOtp,
    prepareMcpToolArguments,
  } = await import('../lib/browserTerminalSpawn.js');
  const spawnTool = {
    name: 'spawn_terminal',
    inputSchema: {
      properties: {
        cwd: { type: 'string' },
        otp: { type: 'string' },
      },
    },
  };

  assert.equal(mcpToolRequiresSpawnOtp(spawnTool, { cwd: '/workspace' }), true);
  assert.deepEqual(
    prepareMcpToolArguments(
      spawnTool,
      { cwd: '/workspace', otp: 'caller-value' },
      '  manual-value  ',
    ),
    { cwd: '/workspace', otp: 'manual-value' },
  );
  assert.deepEqual(
    prepareMcpToolArguments(spawnTool, { cwd: '/workspace', otp: 'caller-value' }),
    { cwd: '/workspace' },
  );
});

test('simplified run_command asks for an OTP only when it must create a terminal', async () => {
  const {
    mcpToolRequiresSpawnOtp,
    prepareMcpToolArguments,
  } = await import('../lib/browserTerminalSpawn.js');
  const runCommandTool = {
    name: 'run_command',
    inputSchema: {
      properties: {
        command: { type: 'string' },
        terminal_uuid: { type: 'string' },
        otp: { type: 'string' },
      },
    },
  };

  assert.equal(mcpToolRequiresSpawnOtp(runCommandTool, { command: 'pwd' }), true);
  assert.equal(mcpToolRequiresSpawnOtp(runCommandTool, {
    command: 'pwd',
    terminal_uuid: 'terminal-uuid',
  }), false);
  assert.equal(mcpToolRequiresSpawnOtp(runCommandTool, {
    command: 'pwd',
    terminalUuid: 'terminal-uuid-alias',
  }), false);
  assert.deepEqual(prepareMcpToolArguments({
    name: 'read_terminal',
    inputSchema: { properties: { terminal_uuid: { type: 'string' } } },
  }, {
    terminal_uuid: 'terminal-uuid',
    otp: 'must-be-discarded',
  }, 'also-discarded'), {
    terminal_uuid: 'terminal-uuid',
  });
});
