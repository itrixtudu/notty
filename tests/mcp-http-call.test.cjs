'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');

function createResponse() {
  return {
    body: undefined,
    headersSent: false,
    statusCode: 200,
    status(code) {
      this.statusCode = code;
      return this;
    },
    json(body) {
      this.body = body;
      this.headersSent = true;
      return this;
    },
  };
}

function createHandler(createMcpHttpCallHandler, callTool, errors = []) {
  return createMcpHttpCallHandler({
    getMcpToolset: () => ({ callTool }),
    getHttpProtocol: () => 'http',
    getRequestIpInfo: () => ({ sourceIp: '127.0.0.1', forwardedFor: null }),
    withLogContext: (_context, fn) => fn(),
    logError: (...args) => errors.push(args),
  });
}

test('MCP HTTP calls await asynchronous toolsets before responding', async () => {
  const { createMcpHttpCallHandler } = await import('../lib/mcpHttpCallHandler.js');
  let finishCall;
  const callResult = new Promise((resolve) => {
    finishCall = resolve;
  });
  const calls = [];
  const handler = createHandler(createMcpHttpCallHandler, (name, args) => {
    calls.push({ name, args });
    return callResult;
  });
  const response = createResponse();
  const pending = handler({ body: { name: 'run_command', arguments: { command: 'pwd' } } }, response);

  await Promise.resolve();
  assert.equal(response.body, undefined);

  const result = { content: [{ type: 'text', text: '/workspace' }] };
  finishCall(result);
  await pending;

  assert.deepEqual(calls, [{ name: 'run_command', args: { command: 'pwd' } }]);
  assert.equal(response.statusCode, 200);
  assert.equal(response.body, result);
});

test('MCP HTTP calls convert rejected tool promises into a JSON 500 response', async () => {
  const { createMcpHttpCallHandler } = await import('../lib/mcpHttpCallHandler.js');
  const errors = [];
  const handler = createHandler(
    createMcpHttpCallHandler,
    async () => {
      throw new Error('toolset failed');
    },
    errors,
  );
  const response = createResponse();

  await handler({ body: { name: 'run_command', arguments: {} } }, response);

  assert.equal(response.statusCode, 500);
  assert.deepEqual(response.body, { error: 'toolset failed' });
  assert.equal(errors.length, 1);
  assert.match(String(errors[0][0]), /tool call error/);
});

test('MCP HTTP calls reject missing tool names before resolving a toolset', async () => {
  const { createMcpHttpCallHandler } = await import('../lib/mcpHttpCallHandler.js');
  let called = false;
  const handler = createHandler(createMcpHttpCallHandler, () => {
    called = true;
  });
  const response = createResponse();

  await handler({ body: { arguments: {} } }, response);

  assert.equal(called, false);
  assert.equal(response.statusCode, 400);
  assert.deepEqual(response.body, { error: 'Tool name is required' });
});
