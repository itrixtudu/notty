'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');
const {
  createMcpToolFilter,
  normalizeAllowedMcpTools,
  toolFilterGuidance,
} = require('../lib/mcpToolFilter.cjs');

const definitions = [
  { name: 'read_terminal' },
  { name: 'write_terminal' },
  { name: 'list_terminals' },
];

test('MCP tools remain unfiltered by default', () => {
  const filter = createMcpToolFilter(definitions, null);
  assert.equal(filter.active, false);
  assert.deepEqual(filter.definitions, definitions);
  assert.doesNotThrow(() => filter.assertAllowed('not_present'));
  assert.equal(toolFilterGuidance(filter.active), '');
});

test('an explicit MCP allowlist filters discovery and dispatch', () => {
  const filter = createMcpToolFilter(definitions, ['list_terminals', 'read_terminal']);
  assert.equal(filter.active, true);
  assert.deepEqual(filter.definitions.map((tool) => tool.name), [
    'read_terminal',
    'list_terminals',
  ]);
  assert.doesNotThrow(() => filter.assertAllowed('read_terminal'));
  assert.throws(
    () => filter.assertAllowed('write_terminal'),
    (error) => error.code === 'TOOL_NOT_AVAILABLE'
      && /Inspect tools\/list once/.test(error.message)
      && /Human help needed/.test(error.message),
  );
  assert.match(toolFilterGuidance(filter.active), /Only tools returned/);
});

test('MCP allowlists deduplicate names and reject invalid or unknown tools', () => {
  assert.deepEqual(
    normalizeAllowedMcpTools('read_terminal, read_terminal,list_terminals'),
    ['read_terminal', 'list_terminals'],
  );
  assert.throws(() => normalizeAllowedMcpTools('read terminal'), /invalid MCP tool name/);
  assert.throws(
    () => createMcpToolFilter(definitions, ['missing_tool']),
    /unknown MCP tool: missing_tool.*available tools:/,
  );
});
