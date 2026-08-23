import http from 'node:http';
import express from 'express';
import { randomUUID } from 'node:crypto';
import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { StreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/streamableHttp.js';
import { SSEServerTransport } from '@modelcontextprotocol/sdk/server/sse.js';
import {
  CallToolRequestSchema,
  ListToolsRequestSchema
} from '@modelcontextprotocol/sdk/types.js';
import { captureTerminalContext } from './agentManager.js';

const BROKER_HOST = '127.0.0.1';
const MAX_CONTEXT_CHARS = 20_000;

const TOOL_DEFINITIONS = Object.freeze([
  {
    name: 'read_bound_terminal',
    description: 'Read bounded, redacted context from the one source terminal bound to this copilot.',
    inputSchema: {
      type: 'object',
      properties: {
        max_chars: {
          type: 'integer',
          minimum: 1,
          maximum: MAX_CONTEXT_CHARS,
          default: MAX_CONTEXT_CHARS
        }
      },
      additionalProperties: false
    }
  },
  {
    name: 'read_copilot_events',
    description: 'Read recent command, mode, and lifecycle events for the bound copilot only.',
    inputSchema: {
      type: 'object',
      properties: {
        limit: { type: 'integer', minimum: 1, maximum: 100, default: 20 }
      },
      additionalProperties: false
    }
  },
  {
    name: 'post_feedback',
    description: 'Post concise analysis or a tip to the bound terminal copilot feed.',
    inputSchema: {
      type: 'object',
      properties: {
        body: { type: 'string', minLength: 1, maxLength: 20000 },
        kind: { type: 'string', maxLength: 80 }
      },
      required: ['body'],
      additionalProperties: false
    }
  },
  {
    name: 'submit_command',
    description: 'Submit one single-line command through the bound terminal control policy. The server decides whether it is only proposed, inserted, approved, or executed.',
    inputSchema: {
      type: 'object',
      properties: {
        command: { type: 'string', minLength: 1, maxLength: 4096 }
      },
      required: ['command'],
      additionalProperties: false
    }
  }
]);

function wrapJson(value) {
  return {
    content: [{ type: 'text', text: JSON.stringify(value, null, 2) }]
  };
}

function wrapError(error) {
  return {
    isError: true,
    content: [{
      type: 'text',
      text: JSON.stringify({
        error: {
          code: error?.code || 'COPILOT_TOOL_FAILED',
          message: error?.message || String(error)
        }
      })
    }]
  };
}

function normalizeRole(value) {
  const role = String(value || '').trim().toLowerCase();
  if (!['visible', 'analyzer'].includes(role)) {
    const error = new Error('copilot role must be visible or analyzer');
    error.statusCode = 404;
    throw error;
  }
  return role;
}

function assertRoleLease(copilot, role) {
  const lease = role === 'analyzer'
    ? copilot?.leases?.analyzer
    : copilot?.leases?.visible;
  if (!lease || lease.status !== 'active') {
    const error = new Error(`${role} copilot access lease has expired or is unavailable`);
    error.code = 'COPILOT_LEASE_EXPIRED';
    throw error;
  }
  return lease;
}

function createBoundMcpServer({ bindingId, role, getOperations }) {
  const server = new Server(
    { name: `notty-copilot-${role}`, version: '1.0.0' },
    { capabilities: { tools: {} } }
  );

  server.setRequestHandler(ListToolsRequestSchema, async () => ({
    tools: role === 'analyzer'
      ? TOOL_DEFINITIONS.filter((tool) => tool.name !== 'submit_command')
      : [...TOOL_DEFINITIONS]
  }));

  server.setRequestHandler(CallToolRequestSchema, async (request) => {
    try {
      const operations = getOperations();
      const copilot = operations.get(bindingId);
      assertRoleLease(copilot, role);
      const args = request.params.arguments || {};

      switch (request.params.name) {
        case 'read_bound_terminal': {
          const requested = Number(args.max_chars ?? MAX_CONTEXT_CHARS);
          const maxContextChars = Number.isInteger(requested)
            ? Math.min(MAX_CONTEXT_CHARS, Math.max(1, requested))
            : MAX_CONTEXT_CHARS;
          return wrapJson(captureTerminalContext({
            terminal_uuid: copilot.sourceTerminalUuid,
            scope: 'tail',
            maxContextChars
          }));
        }
        case 'read_copilot_events': {
          const requested = Number(args.limit ?? 20);
          const limit = Number.isInteger(requested)
            ? Math.min(100, Math.max(1, requested))
            : 20;
          return wrapJson({
            bindingId,
            events: operations.getEventSnapshot({ bindingId, limit })
          });
        }
        case 'post_feedback':
          return wrapJson(operations.postFeedback(bindingId, {
            body: args.body,
            kind: args.kind,
            source: role
          }));
        case 'submit_command':
          if (role !== 'visible') {
            throw Object.assign(new Error('background analyzers cannot submit commands'), {
              code: 'COPILOT_ANALYZER_READ_ONLY'
            });
          }
          return wrapJson(operations.submitCommand(bindingId, {
            command: args.command,
            sourceTerminalUuid: copilot.sourceTerminalUuid,
            source: 'agent-mcp'
          }));
        default:
          throw Object.assign(new Error(`Unknown copilot tool: ${request.params.name}`), {
            code: 'COPILOT_TOOL_NOT_FOUND'
          });
      }
    } catch (error) {
      return wrapError(error);
    }
  });

  return server;
}

function extractSessionId(req) {
  const header = req.headers['mcp-session-id'] || req.headers['x-session-id'];
  if (typeof header === 'string' && header.trim()) {
    return header.trim();
  }
  const query = typeof req.query?.sessionId === 'string' ? req.query.sessionId.trim() : '';
  return query || randomUUID();
}

function extractAccessToken(req) {
  const authorization = typeof req.headers.authorization === 'string'
    ? req.headers.authorization.trim()
    : '';
  const bearer = authorization.match(/^Bearer\s+(.+)$/i);
  if (bearer?.[1]) {
    return bearer[1].trim();
  }
  return typeof req.query?.access_token === 'string'
    ? req.query.access_token.trim()
    : '';
}

export async function startCopilotMcpBroker(options = {}) {
  const host = String(options.host || BROKER_HOST);
  const getOperations = typeof options.getOperations === 'function'
    ? options.getOperations
    : () => options.operations;
  const app = express();
  const sessions = new Map();
  app.use(express.json({ limit: '4mb' }));

  const requireBinding = (req, res, next) => {
    try {
      const operations = getOperations();
      if (!operations) {
        throw Object.assign(new Error('copilot manager is not ready'), { statusCode: 503 });
      }
      req.copilotRole = normalizeRole(req.params.role);
      operations.get(req.params.bindingId);
      if (typeof operations.authorizeBroker !== 'function') {
        throw Object.assign(new Error('copilot broker authorization is unavailable'), {
          statusCode: 503
        });
      }
      operations.authorizeBroker(req.params.bindingId, {
        role: req.copilotRole,
        token: extractAccessToken(req)
      });
      next();
    } catch (error) {
      res.status(Number.isInteger(error?.statusCode) ? error.statusCode : 404).json({
        error: error?.message || 'Copilot binding not found'
      });
    }
  };

  app.all('/bindings/:bindingId/:role/mcp', requireBinding, async (req, res) => {
    const sessionId = extractSessionId(req);
    const key = `http:${req.params.bindingId}:${req.copilotRole}:${sessionId}`;
    let session = sessions.get(key);
    try {
      if (!session) {
        const transport = new StreamableHTTPServerTransport({
          sessionIdGenerator: () => sessionId,
          enableJsonResponse: true
        });
        const mcpServer = createBoundMcpServer({
          bindingId: req.params.bindingId,
          role: req.copilotRole,
          getOperations
        });
        await mcpServer.connect(transport);
        session = { transport, server: mcpServer };
        sessions.set(key, session);
        transport.onclose = () => sessions.delete(key);
      }
      res.setHeader('X-Session-Id', sessionId);
      await session.transport.handleRequest(req, res, req.body);
    } catch (error) {
      if (!res.headersSent) {
        res.status(500).json({ error: error?.message || 'Copilot MCP request failed' });
      }
    }
  });

  app.get('/bindings/:bindingId/:role/sse', requireBinding, async (req, res) => {
    try {
      const messagePath = `/bindings/${encodeURIComponent(req.params.bindingId)}/${req.copilotRole}/message`;
      const transport = new SSEServerTransport(messagePath, res);
      const mcpServer = createBoundMcpServer({
        bindingId: req.params.bindingId,
        role: req.copilotRole,
        getOperations
      });
      await mcpServer.connect(transport);
      const key = `sse:${transport.sessionId}`;
      sessions.set(key, {
        transport,
        server: mcpServer,
        bindingId: req.params.bindingId,
        role: req.copilotRole
      });
      transport.onclose = () => sessions.delete(key);
    } catch (error) {
      if (!res.headersSent) {
        res.status(500).end(error?.message || 'Unable to open copilot SSE transport');
      }
    }
  });

  app.post('/bindings/:bindingId/:role/message', async (req, res) => {
    try {
      const sessionId = typeof req.query.sessionId === 'string' ? req.query.sessionId : '';
      const session = sessions.get(`sse:${sessionId}`);
      const role = normalizeRole(req.params.role);
      if (
        !session
        || session.bindingId !== req.params.bindingId
        || session.role !== role
      ) {
        res.status(404).send('Copilot MCP session not found');
        return;
      }
      await session.transport.handlePostMessage(req, res, req.body);
    } catch (error) {
      if (!res.headersSent) {
        res.status(Number.isInteger(error?.statusCode) ? error.statusCode : 500)
          .send(error?.message || 'Copilot MCP message failed');
      }
    }
  });

  const httpServer = http.createServer(app);
  await new Promise((resolve, reject) => {
    httpServer.once('error', reject);
    httpServer.listen(0, host, () => {
      httpServer.off('error', reject);
      resolve();
    });
  });
  const address = httpServer.address();
  const port = typeof address === 'object' && address ? address.port : 0;
  const baseUrl = `http://${host}:${port}`;
  let closingPromise = null;

  return {
    host,
    port,
    baseUrl,
    urlFor(bindingId, role, runtime, accessToken = '') {
      const encodedBinding = encodeURIComponent(String(bindingId));
      const encodedRole = encodeURIComponent(normalizeRole(role));
      const transport = runtime === 'agy' ? 'sse' : 'mcp';
      const url = `${baseUrl}/bindings/${encodedBinding}/${encodedRole}/${transport}`;
      return runtime === 'agy' && accessToken
        ? `${url}?access_token=${encodeURIComponent(String(accessToken))}`
        : url;
    },
    async close() {
      if (!closingPromise) {
        closingPromise = (async () => {
          for (const session of sessions.values()) {
            try {
              await session.transport.close?.();
            } catch {
              // Best-effort process shutdown.
            }
          }
          sessions.clear();
          if (!httpServer.listening) {
            return;
          }
          await new Promise((resolve) => httpServer.close(() => resolve()));
        })();
        try {
          await closingPromise;
        } finally {
          closingPromise = Promise.resolve();
        }
        return;
      }
      await closingPromise;
    }
  };
}
