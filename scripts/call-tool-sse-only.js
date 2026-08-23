#!/usr/bin/env node

// call-tool-sse-only.js
// Connects to an MCP service over SSE and invokes a specific tool.

import process from 'node:process';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { SSEClientTransport } from '@modelcontextprotocol/sdk/client/sse.js';
import { StdioClientTransport } from '@modelcontextprotocol/sdk/client/stdio.js';

const rawArgs = process.argv.slice(2);
const DEBUG = process.env.DEBUG === '1' || rawArgs.includes('--debug');
const JSON_OUTPUT = rawArgs.includes('--json');

function usage() {
  console.error('Usage: node scripts/call-tool-sse-only.js <target> <toolName> [toolArgsJSON] [--json] [--debug] [-- targetArgs...]');
  console.error('Examples:');
  console.error('  node scripts/call-tool-sse-only.js http://localhost:3000/sse spawn_terminal');
  console.error('  node scripts/call-tool-sse-only.js http://localhost:3000/sse spawn_terminal \'{"cols": 120}\' --json');
  console.error('  node scripts/call-tool-sse-only.js ./stdio-http-proxy.js spawn_terminal \'{"shell":"/bin/bash"}\' -- http://localhost:3000/mcp');
}

function parseArgs(args) {
  const filtered = args.filter(arg => arg !== '--debug' && arg !== '--json');
  if (!filtered.length) {
    usage();
    process.exit(1);
  }

  const separatorIndex = filtered.indexOf('--');
  let targetArgs = [];
  let positional = filtered;

  if (separatorIndex !== -1) {
    targetArgs = filtered.slice(separatorIndex + 1);
    positional = filtered.slice(0, separatorIndex);
  }

  if (positional.length < 2) {
    usage();
    process.exit(1);
  }

  const target = positional[0];
  const toolName = positional[1];
  const rawToolArgs = positional[2];

  let toolArgs;
  if (rawToolArgs !== undefined) {
    try {
      toolArgs = JSON.parse(rawToolArgs);
      if (toolArgs === null || typeof toolArgs !== 'object') {
        throw new Error('Tool arguments JSON must evaluate to an object');
      }
    } catch (err) {
      console.error('[call-tool-sse-only] Failed to parse tool arguments JSON:', err.message);
      process.exit(1);
    }
  }

  return { target, toolName, toolArgs, targetArgs };
}

function isHttpTarget(target) {
  return /^https?:\/\//i.test(target);
}

function normalizeSseUrl(rawUrl) {
  let parsed;
  try {
    parsed = new URL(rawUrl);
  } catch (err) {
    throw new Error(`Invalid URL "${rawUrl}": ${err.message}`);
  }

  if (!['http:', 'https:'].includes(parsed.protocol)) {
    throw new Error(`Unsupported protocol "${parsed.protocol}". Use http:// or https://.`);
  }

  if (!parsed.pathname || parsed.pathname === '/') {
    parsed.pathname = '/sse';
  }

  return parsed;
}

const { target, toolName, toolArgs, targetArgs } = parseArgs(rawArgs);

const log = (...parts) => {
  if (DEBUG) {
    console.error('[call-tool-sse-only]', ...parts);
  }
};

async function connectViaHttp(targetUrl) {
  const url = normalizeSseUrl(targetUrl);
  log('Connecting via HTTP SSE to', url.href);
  const transport = new SSEClientTransport(url);
  const client = new Client({
    name: 'notty-tool-runner',
    version: '1.0.0'
  }, {
    capabilities: {
      tools: {}
    }
  });

  await client.connect(transport);
  return { client, transport };
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

  const client = new Client({
    name: 'notty-tool-runner',
    version: '1.0.0'
  }, {
    capabilities: {
      tools: {}
    }
  });

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
      ({ client, transport } = await connectViaExec(target, targetArgs));
    }

    const response = await client.callTool({
      name: toolName,
      arguments: toolArgs
    });

    if (JSON_OUTPUT) {
      console.log(JSON.stringify(response, null, 2));
    } else if (response.isError) {
      const text = response.content?.[0]?.text ?? 'Unknown error';
      console.error(`[call-tool-sse-only] Tool error: ${text}`);
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
    console.error('[call-tool-sse-only] Error:', err.stack || err);
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
    console.error('[call-tool-sse-only] Unhandled error:', err.stack || err);
    process.exit(1);
  });
