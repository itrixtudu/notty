'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');

test('ordinary /mcp browser GETs skip the transport while MCP traffic does not', async () => {
  const {
    isMcpTransportRequest,
    routeMcpTransportOrUi,
  } = await import('../lib/mcpHttpCallHandler.js');

  assert.equal(isMcpTransportRequest({
    method: 'GET',
    headers: { accept: 'text/html,application/xhtml+xml' },
  }), false);
  assert.equal(isMcpTransportRequest({
    method: 'GET',
    headers: { accept: 'application/json, TEXT/EVENT-STREAM' },
  }), true);
  assert.equal(isMcpTransportRequest({ method: 'POST', headers: {} }), true);

  const nextValues = [];
  routeMcpTransportOrUi(
    { method: 'GET', headers: { accept: 'text/html' } },
    {},
    (value) => nextValues.push(value),
  );
  routeMcpTransportOrUi(
    { method: 'POST', headers: {} },
    {},
    (value) => nextValues.push(value),
  );
  assert.deepEqual(nextValues, ['router', undefined]);
});
