#!/usr/bin/env node

// Simple SSE integration test for notty.
// 1. Spawns `server.js` in MCP_TRANSPORT=sse mode on a test port.
// 2. Opens an SSE client transport and issues listTools via MCP.
// 3. Verifies that tools are returned, ensuring the roundtrip works.

import { spawn } from 'node:child_process';
import { once } from 'node:events';
import process from 'node:process';
import { setTimeout as delay } from 'node:timers/promises';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { SSEClientTransport } from '@modelcontextprotocol/sdk/client/sse.js';

const DEFAULT_PORT = 3333;
const port = Number(process.env.SSE_TEST_PORT) || DEFAULT_PORT;

const log = (...parts) => console.error('[sse-roundtrip]', ...parts);

function startSseServer(testPort) {
  log('Starting server.js in SSE mode on port', testPort);
  const child = spawn('node', ['server.js'], {
    env: {
      ...process.env,
      MCP_TRANSPORT: 'sse',
      PORT: String(testPort)
    },
    stdio: ['ignore', 'pipe', 'pipe']
  });

  child.stdout?.on('data', chunk => {
    process.stdout.write(`[server stdout] ${chunk}`);
  });

  child.stderr?.on('data', chunk => {
    process.stderr.write(`[server stderr] ${chunk}`);
  });

  return child;
}

async function waitForServerReady(child, testPort, timeoutMs = 8000) {
  const readyNeedle = `:${testPort}/sse`;
  let buffered = '';
  await new Promise((resolve, reject) => {
    let timer;

    const cleanup = () => {
      if (timer) {
        clearTimeout(timer);
      }
      child.stderr?.off('data', handleData);
      child.off('exit', handleExit);
    };

    const handleData = chunk => {
      buffered += chunk.toString();
      if (buffered.includes('SSE server listening') && buffered.includes(readyNeedle)) {
        cleanup();
        resolve();
      }
    };

    const handleExit = code => {
      cleanup();
      reject(new Error(`server.js exited before ready (code ${code ?? 'null'})`));
    };

    timer = setTimeout(() => {
      cleanup();
      reject(new Error(`Timed out waiting for SSE server on port ${testPort}`));
    }, timeoutMs);

    child.stderr?.on('data', handleData);
    child.on('exit', handleExit);
  });
  log('SSE server reported ready');
}

async function stopServer(child) {
  if (!child || child.killed) {
    return;
  }

  child.kill('SIGTERM');

  try {
    await Promise.race([
      once(child, 'exit').catch(() => {}),
      delay(2000)
    ]);
  } catch {
    // ignore
  }

  if (!child.killed && child.exitCode === null) {
    child.kill('SIGKILL');
  }
}

async function runRoundtrip(testPort) {
  const targetUrl = new URL(`http://127.0.0.1:${testPort}/sse`);
  const client = new Client({
    name: 'notty-sse-roundtrip',
    version: '1.0.0'
  }, {
    capabilities: {
      tools: {}
    }
  });

  const transport = new SSEClientTransport(targetUrl);

  try {
    await client.connect(transport);
    log('Connected to SSE transport');

    const { tools } = await client.listTools({});
    if (!Array.isArray(tools) || tools.length === 0) {
      throw new Error('listTools returned no tools');
    }

    log(`Received ${tools.length} tool(s). Sample: ${tools[0].name}`);
  } finally {
    const cleanupPromises = [client.close()];
    if (typeof transport.close === 'function') {
      cleanupPromises.push(transport.close());
    }
    await Promise.allSettled(cleanupPromises);
  }
}

async function main() {
  const server = startSseServer(port);
  let hadError = false;

  try {
    await waitForServerReady(server, port);
    await runRoundtrip(port);
    log('SSE roundtrip succeeded');
  } catch (err) {
    hadError = true;
    console.error('[sse-roundtrip] FAILED:', err.stack || err);
  } finally {
    await stopServer(server);
  }

  if (hadError) {
    process.exitCode = 1;
  }
}

main().catch(err => {
  console.error('[sse-roundtrip] Unhandled error:', err);
  process.exit(1);
});
