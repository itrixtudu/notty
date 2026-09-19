#!/usr/bin/env node

// list-tools.js
// Connects to an MCP service (stdio executable or HTTP SSE) and prints available tools.

import process from 'node:process';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { SSEClientTransport } from '@modelcontextprotocol/sdk/client/sse.js';
import { StreamableHTTPClientTransport } from '@modelcontextprotocol/sdk/client/streamableHttp.js';
import { StdioClientTransport } from '@modelcontextprotocol/sdk/client/stdio.js';

const rawArgs = process.argv.slice(2);
const TOKEN = consumeToken(rawArgs);
const DEBUG = process.env.DEBUG === '1' || rawArgs.includes('--debug');
const JSON_OUTPUT = rawArgs.includes('--json');

function usage() {
  console.error('Usage: node scripts/list-tools.js <executable | http://server:port/mcp> [args...] [--json] [--debug]');
  console.error('Examples:');
  console.error('  node scripts/list-tools.js ./server.js');
  console.error('  node scripts/list-tools.js ./server.js --json -- --mode stdio');
  console.error('  node scripts/list-tools.js http://localhost:3000/mcp');
}

function consumeToken(args) {
  let token =
    process.env.MCP_BEARER_TOKEN ||
    process.env.MCP_TOKEN ||
    null;

  for (let i = 0; i < args.length; i += 1) {
    const arg = args[i];
    if (arg === '--token') {
      token = args[i + 1];
      args.splice(i, 2);
      break;
    }
    if (arg && typeof arg === 'string' && arg.startsWith('--token=')) {
      token = arg.slice('--token='.length);
      args.splice(i, 1);
      break;
    }
  }

  return token && typeof token === 'string' ? token.trim() : null;
}

function wrapFetchWithAuth(token) {
  if (!token || typeof fetch !== 'function') {
    return;
  }

  const baseFetch = globalThis.fetch;
  globalThis.fetch = (input, init = {}) => {
    const headers = new Headers(init.headers || {});
    if (!headers.has('authorization')) {
      headers.set('authorization', `Bearer ${token}`);
    }
    return baseFetch(input, { ...init, headers });
  };
}

function parseArgs(args) {
  const filtered = args.filter(arg => arg !== '--debug' && arg !== '--json');
  if (filtered.length === 0) {
    usage();
    process.exit(1);
  }

  const separatorIndex = filtered.indexOf('--');
  if (separatorIndex !== -1) {
    return {
      target: filtered[0],
      rest: filtered.slice(separatorIndex + 1)
    };
  }

  return {
    target: filtered[0],
    rest: filtered.slice(1)
  };
}

function isHttpTarget(target) {
  return /^https?:\/\//i.test(target);
}

function normalizeHttpUrl(rawUrl) {
  let parsed;
  try {
    parsed = new URL(rawUrl);
  } catch (err) {
    throw new Error(`Invalid URL "${rawUrl}": ${err.message}`);
  }

  if (!['http:', 'https:'].includes(parsed.protocol)) {
    throw new Error(`Unsupported protocol "${parsed.protocol}". Use http:// or https://.`);
  }
  if (parsed.searchParams.has('access_token')) {
    throw new Error('Bearer tokens must use the Authorization header, not the URL query string.');
  }

  return parsed;
}

function buildSseUrl(baseUrl) {
  const parsed = new URL(baseUrl.href);
  if (!parsed.pathname || parsed.pathname === '/') {
    parsed.pathname = '/sse';
  }
  return parsed;
}

const { target, rest } = parseArgs(rawArgs);

const log = (...parts) => {
  if (DEBUG) {
    console.error('[list-tools]', ...parts);
  }
};

async function cleanup(client, transport) {
  const tasks = [];
  if (typeof client?.close === 'function') {
    tasks.push(client.close());
  }
  if (typeof transport?.close === 'function') {
    tasks.push(transport.close());
  }
  if (tasks.length > 0) {
    await Promise.allSettled(tasks);
  }
}

function createClient() {
  return new Client({
    name: 'notty-tool-lister',
    version: '1.0.0'
  }, {
    capabilities: {
      tools: {}
    }
  });
}

async function connectViaHttp(targetUrl) {
  const baseUrl = normalizeHttpUrl(targetUrl);
  if (TOKEN) {
    wrapFetchWithAuth(TOKEN);
  }
  const authOptions = TOKEN ? { headers: { Authorization: `Bearer ${TOKEN}` } } : undefined;

  log('Attempting Streamable HTTP connection to', baseUrl.href);
  let client;
  let transport;
  try {
    transport = new StreamableHTTPClientTransport(baseUrl, authOptions);
    client = createClient();
    await client.connect(transport);
    log('Connected via Streamable HTTP');
    return { client, transport };
  } catch (err) {
    await cleanup(client, transport);
    log('Streamable HTTP connection failed, falling back to SSE:', err.message || err);
    try {
      const sseUrl = buildSseUrl(baseUrl);
      log('Connecting via HTTP SSE to', sseUrl.href);
      const sseTransport = new SSEClientTransport(sseUrl);
      const sseClient = createClient();
      try {
        await sseClient.connect(sseTransport);
      } catch (sseErr) {
        await cleanup(sseClient, sseTransport);
        throw sseErr;
      }
      log('Connected via SSE transport');
      return { client: sseClient, transport: sseTransport };
    } catch (sseErr) {
      const combined = new Error(
        `Failed to connect via Streamable HTTP (${err.message || err}) and SSE (${sseErr.message || sseErr})`
      );
      combined.streamableError = err;
      combined.sseError = sseErr;
      throw combined;
    }
  }
}

async function connectViaExec(command, args) {
  log('Spawning executable:', command, args.length ? `Args: ${args.join(' ')}` : '');
  const transport = new StdioClientTransport({
    command,
    args,
    env: process.env,
    stderr: 'pipe'
  });

  if (DEBUG && transport.stderr) {
    transport.stderr.on('data', chunk => {
      process.stderr.write(`[server stderr] ${chunk}`);
    });
  }

  const client = createClient();

  await client.connect(transport);
  return { client, transport };
}

async function main() {
  let client;
  let transport;

  try {
    if (isHttpTarget(target)) {
      ({ client, transport } = await connectViaHttp(target));
    } else {
      ({ client, transport } = await connectViaExec(target, rest));
    }

    const { tools } = await client.listTools({});

    if (JSON_OUTPUT) {
      console.log(JSON.stringify(tools, null, 2));
    } else {
      console.log(`Found ${tools.length} tool${tools.length === 1 ? '' : 's'}:`);
      for (const tool of tools) {
        const description = tool.description ? ` - ${tool.description}` : '';
        console.log(`- ${tool.name}${description}`);
      }
    }
  } catch (err) {
    console.error('[list-tools] Error:', err.stack || err);
    process.exitCode = 1;
  } finally {
    try {
      await client?.close();
    } catch (err) {
      log('Error closing client:', err);
    }
    try {
      await transport?.close();
    } catch (err) {
      log('Error closing transport:', err);
    }
  }
}

main()
  .then(() => {
    const code = process.exitCode ?? 0;
    process.exit(code);
  })
  .catch(err => {
    console.error('[list-tools] Unhandled error:', err.stack || err);
    process.exit(1);
  });
