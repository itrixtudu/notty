'use strict';

const assert = require('node:assert/strict');
const { EventEmitter } = require('node:events');
const test = require('node:test');

class FakeWebSocket extends EventEmitter {
  constructor() {
    super();
    this.OPEN = 1;
    this.readyState = this.OPEN;
    this.sent = [];
  }

  send(payload) {
    this.sent.push(JSON.parse(payload));
  }

  close() {
    this.readyState = 3;
    this.emit('close');
  }
}

function createResponse() {
  return {
    statusCode: 200,
    body: null,
    headers: {},
    setHeader(name, value) {
      this.headers[name] = value;
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

test('browser, HTTP, and MCP write boundaries attach trustworthy actors', async (t) => {
  const express = (await import('express')).default;
  const { callTool } = await import('../lib/mcpTools.js');
  const { registerTerminalHttpRoutes } = await import('../lib/terminalHttpApi.js');
  const { createTerminalWebSocketHandler } = await import('../lib/terminalWsHandlers.js');
  const nextWriteHandler = (await import('../pages/api/terminals/[id]/write.js')).default;
  const {
    killTerminal,
    onTerminalExit,
    spawnTrustedTerminal,
    subscribeToTerminalInput,
  } = await import('../lib/terminalManager.js');

  const session = spawnTrustedTerminal({
    shell: 'bash',
    command: 'sleep 30',
    shellIntegration: false,
  });
  const actors = [];
  const unsubscribe = subscribeToTerminalInput(session.terminal_uuid, (event) => {
    actors.push(event.actor);
  });
  t.after(async () => {
    unsubscribe();
    try {
      await new Promise((resolve) => {
        onTerminalExit(session.terminal_uuid, resolve);
        killTerminal(session.terminal_uuid);
      });
    } catch {
      // The terminal may already have exited after a failed assertion.
    }
  });

  const ws = new FakeWebSocket();
  createTerminalWebSocketHandler({ parseId: () => session.terminal_uuid })(ws, {
    url: `/ws/terminals?id=${session.terminal_uuid}`,
    headers: {},
    socket: { remoteAddress: '127.0.0.1' },
  });
  ws.emit('message', Buffer.from(JSON.stringify({ type: 'input', data: 'w' })));

  const nextResponse = createResponse();
  nextWriteHandler({
    method: 'POST',
    query: { id: session.terminal_uuid },
    body: { data: 'n' },
    headers: {},
    socket: { remoteAddress: '127.0.0.1' },
  }, nextResponse);
  assert.equal(nextResponse.statusCode, 200);

  const app = express();
  registerTerminalHttpRoutes(app);
  const server = await new Promise((resolve) => {
    const listener = app.listen(0, '127.0.0.1', () => resolve(listener));
  });
  t.after(() => new Promise((resolve) => server.close(resolve)));
  const address = server.address();
  const response = await fetch(
    `http://127.0.0.1:${address.port}/api/terminals/${session.terminal_uuid}/write`,
    {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ data: 'h' }),
    },
  );
  assert.equal(response.status, 200);

  const mcpResult = callTool('write_terminal', {
    terminal_uuid: session.terminal_uuid,
    data: 'm',
  });
  assert.notEqual(mcpResult.isError, true);

  const typeResult = callTool('set_terminal_type', {
    terminal_uuid: session.terminal_uuid,
    terminal_type: 'xterm',
  });
  assert.notEqual(typeResult.isError, true);

  assert.deepEqual(actors, ['human', 'human', 'human', 'agent-mcp', 'agent-mcp']);
  ws.close();
});
