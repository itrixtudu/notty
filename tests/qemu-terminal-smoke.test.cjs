'use strict';

const assert = require('node:assert/strict');
const { spawn } = require('node:child_process');
const { randomUUID } = require('node:crypto');
const { once } = require('node:events');
const http = require('node:http');
const path = require('node:path');
const test = require('node:test');
const { Server } = require('@modelcontextprotocol/sdk/server/index.js');
const { SSEServerTransport } = require('@modelcontextprotocol/sdk/server/sse.js');
const { StreamableHTTPServerTransport } = require('@modelcontextprotocol/sdk/server/streamableHttp.js');
const { CallToolRequestSchema, ListToolsRequestSchema } = require('@modelcontextprotocol/sdk/types.js');

const root = path.resolve(__dirname, '..');
const toolNames = ['spawn_terminal', 'read_terminal', 'write_terminal', 'resize_terminal', 'kill_terminal', 'list_terminals'];
const result = (value) => ({ content: [{ type: 'text', text: JSON.stringify(value) }] });

async function fixture(t, sseMode = 'delayed-exit') {
  const sessions = new Map();
  const servers = [];
  const states = new Map();
  const errors = [];
  const sockets = new Set();
  function createServer(label) {
    const state = { terminal: randomUUID(), killCalls: 0, listCalls: 0, pendingLists: 0, removedLists: 0, exitAt: Infinity, output: '' };
    states.set(label, state);
    const server = new Server({ name: `qemu-exit-fixture-${label}`, version: '1.0.0' }, { capabilities: { tools: {} } });
    servers.push(server);
    server.setRequestHandler(ListToolsRequestSchema, async () => ({
      tools: toolNames.map((name) => ({ name, inputSchema: { type: 'object' } })),
    }));
    server.setRequestHandler(CallToolRequestSchema, async ({ params }) => {
      const args = params.arguments || {};
      if (params.name !== 'spawn_terminal' && params.name !== 'list_terminals') {
        assert.equal(args.terminal_uuid, state.terminal);
      }
      switch (params.name) {
        case 'spawn_terminal':
          return result({ terminal_uuid: state.terminal });
        case 'resize_terminal':
          state.cols = args.cols;
          state.rows = args.rows;
          return result({ cols: state.cols, rows: state.rows });
        case 'write_terminal': {
          // Emulate the printf output, rather than returning the echoed command.
          const marker = [...args.data.matchAll(/'([^']*)'/g)].slice(-2).map((match) => match[1]).join('');
          assert.match(marker, /^QEMU_[a-f0-9]+$/);
          state.output = `${marker}\n${state.rows} ${state.cols}\n`;
          return result({ written: args.data.length });
        }
        case 'read_terminal':
          return result({ output: state.output });
        case 'kill_terminal':
          state.killCalls += 1;
          if (state.killCalls === 1 && !(label === 'sse' && sseMode === 'stays-alive')) {
            state.exitAt = Date.now() + 250;
          }
          return result({ killed: true });
        case 'list_terminals': {
          state.listCalls += 1;
          if (label === 'sse' && sseMode === 'list-error') {
            return { isError: true, content: [{ type: 'text', text: 'fixture terminal listing failed' }] };
          }
          const pending = Date.now() < state.exitAt;
          if (pending) state.pendingLists += 1;
          else state.removedLists += 1;
          // A retained UUID still awaits exit even if its alive flag is false.
          const terminals = [{ terminal_uuid: 'unrelated-terminal', alive: true }];
          if (pending) terminals.push({ terminal_uuid: state.terminal, alive: label === 'http' || sseMode === 'stays-alive' });
          return result({ terminals });
        }
        default:
          throw new Error(`unexpected tool ${params.name}`);
      }
    });
    return server;
  }

  const httpTransport = new StreamableHTTPServerTransport({ sessionIdGenerator: randomUUID });
  await createServer('http').connect(httpTransport);
  const listener = http.createServer((request, response) => {
    const handle = async () => {
      const url = new URL(request.url, 'http://127.0.0.1');
      if (url.pathname === '/mcp') return httpTransport.handleRequest(request, response);
      if (url.pathname === '/sse' && request.method === 'GET') {
        const transport = new SSEServerTransport('/messages', response);
        sessions.set(transport.sessionId, transport);
        return createServer('sse').connect(transport);
      }
      if (url.pathname === '/messages' && request.method === 'POST') {
        const transport = sessions.get(url.searchParams.get('sessionId'));
        if (transport) return transport.handlePostMessage(request, response);
      }
      response.writeHead(404).end();
    };
    handle().catch((error) => {
      errors.push(error);
      response.destroy();
    });
  });
  listener.on('connection', (socket) => {
    sockets.add(socket);
    socket.on('close', () => sockets.delete(socket));
  });
  t.after(async () => {
    await Promise.all(servers.map((server) => server.close()));
    for (const socket of sockets) socket.destroy();
    await new Promise((resolve) => listener.close(resolve));
    assert.deepEqual(errors, []);
  });
  listener.listen(0, '127.0.0.1');
  await once(listener, 'listening');
  return { origin: `http://127.0.0.1:${listener.address().port}`, states };
}

async function runSmoke(t, origin) {
  const child = spawn(process.execPath, [path.join(root, 'scripts/qemu/terminal-smoke.mjs'), origin], {
    env: { ...process.env, NOSH_QEMU_APP_ROOT: root },
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  let stdout = '';
  let stderr = '';
  child.stdout.setEncoding('utf8').on('data', (chunk) => { stdout += chunk; });
  child.stderr.setEncoding('utf8').on('data', (chunk) => { stderr += chunk; });
  let timedOut = false;
  const closed = once(child, 'close');
  const timer = setTimeout(() => {
    timedOut = true;
    child.kill('SIGKILL');
  }, 30_000);
  t.after(async () => {
    clearTimeout(timer);
    if (child.exitCode === null && child.signalCode === null) child.kill('SIGKILL');
    await closed;
  });
  const [code, signal] = await closed;
  clearTimeout(timer);
  assert.equal(timedOut, false, `smoke CLI exceeded fixture deadline\n${stdout}\n${stderr}`);
  assert.equal(signal, null, stdout + stderr);
  return { code, stdout, stderr };
}

test('QEMU terminal smoke waits for asynchronous exit over HTTP and SSE', async (t) => {
  const { origin, states } = await fixture(t);
  const run = await runSmoke(t, origin);
  assert.equal(run.code, 0, run.stdout + run.stderr);
  assert.deepEqual(run.stdout.trim().split('\n').map(JSON.parse).map((item) => item.test), ['terminal-http', 'terminal-sse']);
  for (const state of states.values()) {
    assert.ok(state.pendingLists > 0, 'fixture must expose the pending exit');
    assert.ok(state.removedLists > 0, 'smoke must observe removal even with a false alive flag and an unrelated terminal');
    assert.equal(state.killCalls, 1);
  }
});

test('QEMU terminal smoke fails when a killed terminal remains alive and retries cleanup', async (t) => {
  const { origin, states } = await fixture(t, 'stays-alive');
  const run = await runSmoke(t, origin);
  assert.equal(run.code, 1, run.stdout + run.stderr);
  assert.match(run.stderr, /sse.*(?:timed out|still alive|did not exit)/i);
  assert.doesNotMatch(run.stdout, /terminal-sse/);
  assert.ok(states.get('sse').listCalls > 1, 'a pending exit must be retried before failure');
  assert.equal(states.get('sse').killCalls, 2, 'failed confirmation must retain the terminal for cleanup');
});

test('QEMU terminal smoke preserves list errors and retries cleanup', async (t) => {
  const { origin, states } = await fixture(t, 'list-error');
  const run = await runSmoke(t, origin);
  assert.equal(run.code, 1, run.stdout + run.stderr);
  assert.match(run.stderr, /list_terminals.*fixture terminal listing failed/);
  assert.doesNotMatch(run.stdout, /terminal-sse/);
  assert.equal(states.get('sse').listCalls, 1, 'tool errors must not be retried as pending exits');
  assert.equal(states.get('sse').killCalls, 2);
});
