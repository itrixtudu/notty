#!/usr/bin/env node
// Run in the Nosh image, sharing only the smoke server's network namespace.
import assert from 'node:assert/strict';
import { createRequire } from 'node:module';
import { pathToFileURL } from 'node:url';
import { randomUUID } from 'node:crypto';
import { setTimeout as delay } from 'node:timers/promises';
import path from 'node:path';

const require = createRequire(path.join(process.env.NOSH_QEMU_APP_ROOT || '/app', 'package.json'));
const { Client } = await import(pathToFileURL(require.resolve('@modelcontextprotocol/sdk/client/index.js')));
const { SSEClientTransport } = await import(pathToFileURL(require.resolve('@modelcontextprotocol/sdk/client/sse.js')));
const { StreamableHTTPClientTransport } = await import(pathToFileURL(require.resolve('@modelcontextprotocol/sdk/client/streamableHttp.js')));
const { ErrorCode } = await import(pathToFileURL(require.resolve('@modelcontextprotocol/sdk/types.js')));
const origin = process.argv[2] || 'http://127.0.0.1:3000';
// Public fixture credentials are confined to the disposable loopback listener.
const authorization = `Basic ${Buffer.from('qemu-smoke:qemu-smoke').toString('base64')}`;

async function call(client, name, args = {}, timeout = 15_000) {
  const result = await client.callTool({ name, arguments: args }, undefined, { timeout });
  assert.notEqual(result.isError, true, `${name}: ${JSON.stringify(result.content)}`);
  const text = result.content.filter((item) => item.type === 'text').map((item) => item.text).join('\n');
  return JSON.parse(text);
}

async function exercise(label, Transport, endpoint) {
  let client;
  let transport;
  const deadline = Date.now() + 90_000;
  while (true) {
    client = new Client({ name: `qemu-${label}`, version: '1.0.0' });
    transport = new Transport(new URL(endpoint, origin), {
      requestInit: { headers: { Authorization: authorization } },
    });
    try {
      await client.connect(transport, { timeout: 10_000 });
      break;
    } catch (error) {
      await client.close().catch(() => {});
      if (Date.now() >= deadline) throw error;
      await delay(500);
    }
  }
  let terminal;
  try {
    const { tools } = await client.listTools();
    for (const name of ['spawn_terminal', 'read_terminal', 'write_terminal', 'resize_terminal', 'kill_terminal', 'list_terminals']) {
      assert.ok(tools.some((tool) => tool.name === name), `${label}: missing ${name}`);
    }
    terminal = (await call(client, 'spawn_terminal', { cols: 80, rows: 24 })).terminal_uuid;
    assert.equal(typeof terminal, 'string');
    const ref = { terminal_uuid: terminal };
    const resized = await call(client, 'resize_terminal', { ...ref, cols: 93, rows: 31 });
    assert.equal(resized.cols, 93);
    assert.equal(resized.rows, 31);
    // Disable echo and split the marker to ensure an echoed command cannot pass.
    const marker = `QEMU_${randomUUID().replaceAll('-', '')}`;
    const half = Math.floor(marker.length / 2);
    await call(client, 'write_terminal', {
      ...ref,
      data: `stty -echo; printf '\\n%s%s\\n' '${marker.slice(0, half)}' '${marker.slice(half)}'; stty size\r`,
    });
    let output = '';
    const deadline = Date.now() + 15_000;
    while (Date.now() < deadline && !(output.includes(marker) && /31\s+93/.test(output))) {
      output += (await call(client, 'read_terminal', ref)).output || '';
      await delay(100);
    }
    assert.ok(output.includes(marker), `${label}: command output missing`);
    assert.match(output, /31\s+93/, `${label}: PTY did not resize`);
    assert.equal((await call(client, 'kill_terminal', ref)).killed, true);
    // kill_terminal requests termination; the exit callback removes the session.
    const closeDeadline = performance.now() + 15_000;
    const closeTimeout = `${label}: timed out waiting for terminal ${terminal} to disappear within 15000ms after kill_terminal`;
    while (true) {
      const remaining = closeDeadline - performance.now();
      assert.ok(remaining > 0, closeTimeout);
      let listed;
      try {
        listed = await call(client, 'list_terminals', {}, Math.max(1, Math.ceil(remaining)));
      } catch (error) {
        if (error.code === ErrorCode.RequestTimeout) throw new Error(closeTimeout, { cause: error });
        throw error;
      }
      assert.ok(Array.isArray(listed.terminals), `${label}: list_terminals returned no terminal list`);
      if (!listed.terminals.some((entry) => entry.terminal_uuid === terminal)) break;
      await delay(Math.min(100, Math.max(0, closeDeadline - performance.now())));
    }
    terminal = null;
    console.log(JSON.stringify({ test: `terminal-${label}`, status: 'passed', operations: ['create', 'write', 'read', 'resize', 'close'] }));
  } finally {
    if (terminal) await call(client, 'kill_terminal', { terminal_uuid: terminal }).catch(() => {});
    await client.close();
  }
}

await exercise('http', StreamableHTTPClientTransport, '/mcp');
await exercise('sse', SSEClientTransport, '/sse');
