#!/usr/bin/env node

// stdio-http-proxy.js
// Bridges stdio MCP transports to remote Streamable HTTP/SSE transports.

import process from 'node:process';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { SSEClientTransport } from '@modelcontextprotocol/sdk/client/sse.js';
import { StreamableHTTPClientTransport } from '@modelcontextprotocol/sdk/client/streamableHttp.js';

const RAW_ARGS = process.argv.slice(2);
const DEBUG = process.env.DEBUG === '1' || RAW_ARGS.includes('--debug');
const args = RAW_ARGS.filter(arg => arg !== '--debug');
const targetArg = args[0] || process.env.HTTP_MCP_URL;

if (!targetArg) {
  console.error('Usage: node stdio-http-proxy.js <http://server:port/mcp> [--debug]');
  console.error('   or: HTTP_MCP_URL=http://server:port/mcp node stdio-http-proxy.js');
  process.exit(1);
}

const log = (...parts) => {
  if (DEBUG) {
    console.error('[stdio-http-proxy]', ...parts);
  }
};

const warn = (...parts) => {
  console.error('[stdio-http-proxy]', ...parts);
};

function decodeEscapeSequences(data) {
  if (typeof data !== 'string' || !data.includes('\\')) {
    return data;
  }

  return data.replace(/\\(n|r|t|\\)/g, (_, ch) => {
    switch (ch) {
      case 'n':
        return '\n';
      case 'r':
        return '\r';
      case 't':
        return '\t';
      case '\\':
        return '\\';
      default:
        return ch;
    }
  });
}

async function closeQuietly(transport) {
  try {
    if (typeof transport?.close === 'function') {
      await transport.close();
    }
  } catch (err) {
    log('Error closing transport during cleanup:', err);
  }
}

function normalizeHttpUrl(rawUrl) {
  let parsed;
  try {
    parsed = new URL(rawUrl);
  } catch (err) {
    throw new Error(`Invalid URL "${rawUrl}": ${err.message}`);
  }

  if (!['http:', 'https:'].includes(parsed.protocol)) {
    throw new Error(`Unsupported protocol "${parsed.protocol}". Use http or https.`);
  }

  return parsed;
}

function buildSseUrl(baseUrl) {
  const parsed = new URL(baseUrl.href);
  if (parsed.pathname === '' || parsed.pathname === '/') {
    parsed.pathname = '/sse';
  }

  return parsed;
}

async function main() {
  const baseUrl = normalizeHttpUrl(targetArg);
  log('Starting proxy. Remote base URL:', baseUrl.href);

  const stdioTransport = new StdioServerTransport();
  let remoteTransport;
  let remoteKind = 'streamable';

  try {
    log('Attempting Streamable HTTP transport...');
    remoteTransport = new StreamableHTTPClientTransport(baseUrl);
    await remoteTransport.start();
    log('Streamable HTTP transport ready.');
  } catch (streamableErr) {
    await closeQuietly(remoteTransport);
    remoteKind = 'sse';
    const sseUrl = buildSseUrl(baseUrl);
    log('Streamable HTTP transport failed, falling back to SSE endpoint:', sseUrl.href, '-', streamableErr.message || streamableErr);
    remoteTransport = new SSEClientTransport(sseUrl);
    try {
      await remoteTransport.start();
    } catch (sseErr) {
      await closeQuietly(remoteTransport);
      throw new Error(`Failed to start SSE fallback transport: ${sseErr.message || sseErr}`);
    }
    log('SSE transport ready.');
  }

  let shuttingDown = false;

  const shutdown = async (code = 0) => {
    if (shuttingDown) {
      return;
    }
    shuttingDown = true;
    log('Shutting down proxy...');
    try {
      await Promise.allSettled([
        stdioTransport.close(),
        remoteTransport.close()
      ]);
    } catch (err) {
      log('Error during shutdown:', err);
    } finally {
      process.exit(code);
    }
  };

  remoteTransport.onmessage = async (message) => {
    log('<- remote message:', JSON.stringify(message));
    try {
      await stdioTransport.send(message);
    } catch (err) {
      warn('Failed to forward message to stdio:', err.message || err);
      await shutdown(1);
    }
  };

  remoteTransport.onerror = (err) => {
    warn(`Remote ${remoteKind} transport error:`, err.message || err);
  };

  remoteTransport.onclose = () => {
    warn(`Remote ${remoteKind} transport closed. Exiting.`);
    void shutdown(0);
  };

  stdioTransport.onmessage = async (message) => {
    log('-> local message:', JSON.stringify(message));
    try {
      if (
        message &&
        message.method === 'tools/call' &&
        message.params?.name === 'write_terminal' &&
        typeof message.params?.arguments?.data === 'string'
      ) {
        message = {
          ...message,
          params: {
            ...message.params,
            arguments: {
              ...message.params.arguments,
              data: decodeEscapeSequences(message.params.arguments.data)
            }
          }
        };
      }

      await remoteTransport.send(message);
    } catch (err) {
      warn('Failed to forward message to remote:', err.message || err);
      if (message && Object.prototype.hasOwnProperty.call(message, 'id')) {
        const errorResponse = {
          jsonrpc: '2.0',
          id: message.id,
          error: {
            code: -32603,
            message: `Proxy failed to deliver request: ${err.message || err}`
          }
        };
        try {
          await stdioTransport.send(errorResponse);
        } catch (sendErr) {
          warn('Failed to send error response to stdio:', sendErr.message || sendErr);
        }
      }
    }
  };

  stdioTransport.onerror = (err) => {
    warn('STDIO transport error:', err.message || err);
    void shutdown(1);
  };

  stdioTransport.onclose = () => {
    log('STDIO transport closed.');
    void shutdown(0);
  };

  process.on('SIGINT', () => {
    warn('Received SIGINT');
    void shutdown(0);
  });

  process.on('SIGTERM', () => {
    warn('Received SIGTERM');
    void shutdown(0);
  });

  try {
    log('Starting stdio transport...');
    await stdioTransport.start();
    log('STDIO transport ready.');
  } catch (err) {
    warn('Failed to start proxy:', err.message || err);
    await shutdown(1);
  }

  // Ensure stdin stays open to receive messages.
  process.stdin.resume();
  log('Proxy is operational.');
}

main().catch(async (err) => {
  warn('Unhandled error starting proxy:', err.stack || err);
  process.exit(1);
});
