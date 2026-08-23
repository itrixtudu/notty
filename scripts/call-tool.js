#!/usr/bin/env node

// call-tool.js
// Connects to an MCP service over HTTP (Streamable or SSE) and invokes a specific tool.

import process from 'node:process';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { SSEClientTransport } from '@modelcontextprotocol/sdk/client/sse.js';
import { StreamableHTTPClientTransport } from '@modelcontextprotocol/sdk/client/streamableHttp.js';

const rawArgs = process.argv.slice(2);
const TOKEN = consumeToken(rawArgs);
const DEBUG = process.env.DEBUG === '1' || rawArgs.includes('--debug');
const JSON_OUTPUT = rawArgs.includes('--json');

function usage() {
  console.error('Usage: node scripts/call-tool.js <http://server:port/mcp> <toolName> [toolArgsJSON] [--json] [--debug]');
  console.error('Examples:');
  console.error('  node scripts/call-tool.js http://localhost:7000/mcp register');
  console.error('  node scripts/call-tool.js http://localhost:7000/mcp register \'{"username":"alice","password":"secret"}\' --json');
}

function consumeToken(args) {
  let token =
    process.env.MCP_BEARER_TOKEN ||
    process.env.MCP_TOKEN ||
    process.env.NOTTY_OAUTH_BOOT_TOKEN ||
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
  if (filtered.length < 2) {
    usage();
    process.exit(1);
  }

  if (filtered.includes('--')) {
    console.error('[call-tool] Unexpected "--". Pass the HTTP MCP endpoint as the first argument.');
    usage();
    process.exit(1);
  }

  const target = filtered[0];
  const toolName = filtered[1];
  const rawToolArgs = filtered[2];

  let toolArgs;
  if (rawToolArgs !== undefined) {
    try {
      toolArgs = JSON.parse(rawToolArgs);
      if (toolArgs === null || typeof toolArgs !== 'object') {
        throw new Error('Tool arguments JSON must evaluate to an object');
      }
    } catch (err) {
      console.error('[call-tool] Failed to parse tool arguments JSON:', err.message);
      process.exit(1);
    }
  }

  return { target, toolName, toolArgs };
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

  return parsed;
}

function buildSseUrl(baseUrl) {
  const parsed = new URL(baseUrl.href);
  if (!parsed.pathname || parsed.pathname === '/') {
    parsed.pathname = '/sse';
  }
  if (TOKEN && !parsed.searchParams.has('access_token')) {
    parsed.searchParams.set('access_token', TOKEN);
  }

  return parsed;
}

const { target, toolName, toolArgs } = parseArgs(rawArgs);

const log = (...parts) => {
  if (DEBUG) {
    console.error('[call-tool]', ...parts);
  }
};

async function cleanup(client, transport) {
  const work = [];
  if (typeof client?.close === 'function') {
    work.push(client.close());
  }
  if (typeof transport?.close === 'function') {
    work.push(transport.close());
  }
  if (work.length > 0) {
    await Promise.allSettled(work);
  }
}

function createClient() {
  return new Client({
    name: 'notty-tool-runner',
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

async function main() {
  let client;
  let transport;

  try {
    ({ client, transport } = await connectViaHttp(target));

    const response = await client.callTool({
      name: toolName,
      arguments: toolArgs
    });

    if (JSON_OUTPUT) {
      console.log(JSON.stringify(response, null, 2));
    } else if (response.isError) {
      const text = response.content?.[0]?.text ?? 'Unknown error';
      console.error(`[call-tool] Tool error: ${text}`);
      process.exitCode = 1;
    } else if (response.structuredContent) {
      console.log(JSON.stringify(response.structuredContent, null, 2));
    } else if (response.content?.length) {
      for (const part of response.content) {
        if (part.type === 'text') {
          console.log(part.text);
        } else {
          console.log(JSON.stringify(part, null, 2));
        }
      }
    } else {
      console.log(JSON.stringify(response, null, 2));
    }
  } catch (err) {
    console.error('[call-tool] Error:', err.stack || err);
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
    console.error('[call-tool] Unhandled error:', err.stack || err);
    process.exit(1);
  });
