'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const test = require('node:test');

const { createLaunchCatalog } = require('../lib/collab/catalog.cjs');

test('structured launch catalog separates agent harnesses from Ollama', (t) => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'notty-catalog-'));
  fs.mkdirSync(path.join(root, 'agents', 'bin'), { recursive: true });
  fs.writeFileSync(path.join(root, 'agents', 'bin', 'codex.models'), 'gpt-5.4  Frontier model\n');
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const calls = [];
  const catalog = createLaunchCatalog({
    appRoot: root,
    environment: {},
    spawnSync: (command, args) => {
      calls.push([command, ...args]);
      if (command === 'agy') {
        return {
          status: 0,
          stdout: 'Available models:\ngemini-3.6-flash-medium\nclaude-opus-4-6-thinking\nClaude Opus 4.6 (Thinking)\n',
          stderr: '',
        };
      }
      if (command === 'curl') {
        return {
          status: 0,
          stdout: JSON.stringify({
            models: [{
              name: 'qwen3:4b',
              details: { parameter_size: '4.0B', quantization_level: 'Q4_K_M' },
            }],
          }),
          stderr: '',
        };
      }
      return { status: 0, stdout: '2.1.197 (Claude Code)\n', stderr: '' };
    },
  });

  const entries = catalog.read();
  assert.deepEqual(entries.map(({ harness, backend }) => [harness, backend]), [
    ['codex', 'default'],
    ['codex', 'ollama'],
    ['agy', 'default'],
    ['claude', 'default'],
  ]);
  assert.deepEqual(catalog.legacy().ollama.map((entry) => entry.id), ['qwen3:4b']);
  assert.equal(catalog.legacy().ollama[0].description, '4.0B · Q4_K_M');
  assert.deepEqual(catalog.legacy().agy.map((entry) => entry.id), [
    'gemini-3.6-flash-medium',
    'claude-opus-4-6-thinking',
    'Claude Opus 4.6 (Thinking)',
  ]);
  assert.equal(entries.find((entry) => entry.harness === 'agy').thinkLevels.includes('high'), true);
  assert.equal(calls.filter((call) => call[0] === 'agy').length, 1);
  assert.equal(calls.filter((call) => call[0] === 'curl').length, 1);
  assert.equal(calls.some((call) => call[0] === 'ollama'), false);
});

test('catalog failures are explicit and refreshable', () => {
  let available = false;
  const catalog = createLaunchCatalog({
    appRoot: path.resolve(__dirname, '..'),
    environment: {},
    spawnSync: (command) => {
      if (command === 'agy') {
        return available
          ? { status: 0, stdout: 'gemini-3.6-flash-high\n', stderr: '' }
          : { status: 1, stdout: '', stderr: 'not signed in' };
      }
      if (command === 'curl') {
        return { status: 0, stdout: JSON.stringify({ models: [{ name: 'qwen3:4b' }] }), stderr: '' };
      }
      return { status: 0, stdout: 'ok\n', stderr: '' };
    },
  });
  const failed = catalog.getTarget('agy', 'default');
  assert.deepEqual({ ...failed, refreshedAt: '<time>' }, {
    harness: 'agy',
    backend: 'default',
    status: 'error',
    available: false,
    error: 'not signed in',
    refreshedAt: '<time>',
    models: [],
    thinkMode: 'explicit',
    thinkLevels: ['low', 'medium', 'high'],
  });
  available = true;
  assert.equal(catalog.getTarget('agy', 'default').status, 'error');
  assert.equal(catalog.getTarget('agy', 'default', { refresh: true }).status, 'ready');
});
