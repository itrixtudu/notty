import { StreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/streamableHttp.js';
import { SSEServerTransport } from '@modelcontextprotocol/sdk/server/sse.js';
import { randomUUID } from 'crypto';
import { createMcpServer } from './createMcpServer.js';

const state = globalThis.__httpMcpState || {
  sessions: new Map(),
  closedSessions: new Set()
};

globalThis.__httpMcpState = state;

function extractSessionId(req) {
  const url = new URL(req.url || '/', `http://${req.headers.host || 'localhost'}`);
  const querySessionId = url.searchParams.get('sessionId');
  if (querySessionId) {
    return querySessionId;
  }

  const headerSessionId = req.headers['x-session-id'] || req.headers['mcp-session-id'];
  if (headerSessionId) {
    return headerSessionId;
  }

  return randomUUID();
}

async function createSessionState({ sessionId, type, transport }) {
  const server = createMcpServer({ name: 'node-pty-http' });
  await server.connect(transport);

  const sessionState = {
    sessionId,
    type,
    server,
    transport,
    createdAt: Date.now(),
    closed: false
  };

  state.sessions.set(sessionId, sessionState);
  state.closedSessions.delete(sessionId);

  return sessionState;
}

async function ensureHttpSession(sessionId) {
  const existing = state.sessions.get(sessionId);
  if (existing && existing.type === 'http' && !existing.closed) {
    return existing;
  }

  const transport = new StreamableHTTPServerTransport({
    sessionIdGenerator: () => sessionId,
    enableJsonResponse: true
  });

  return createSessionState({ sessionId, type: 'http', transport });
}

export async function getServerForRequest(req) {
  const sessionId = extractSessionId(req);
  const sessionState = await ensureHttpSession(sessionId);
  return sessionState;
}

export async function createSseSession(res, { messagePath = '/mcp/message' } = {}) {
  const transport = new SSEServerTransport(messagePath, res);
  const sessionId = transport.sessionId;

  const sessionState = await createSessionState({
    sessionId,
    type: 'sse',
    transport
  });

  transport.onclose = () => {
    sessionState.closed = true;
    state.sessions.delete(sessionId);
    state.closedSessions.add(sessionId);
  };

  transport.onerror = (error) => {
    console.error(`[mcp-http] SSE transport error (${sessionId}):`, error);
  };

  return sessionState;
}

export async function handleSsePost(sessionId, req, res, body) {
  const sessionState = state.sessions.get(sessionId);
  if (!sessionState || sessionState.type !== 'sse') {
    if (state.closedSessions.has(sessionId)) {
      res.status(410).send('Session closed');
      return;
    }

    res.status(404).send('Session not found');
    return;
  }

  try {
    await sessionState.transport.handlePostMessage(req, res, body);
  } catch (err) {
    if (!res.headersSent) {
      res.status(500).send('Internal Server Error');
    }
    console.error(`[mcp-http] Error handling POST for session ${sessionId}:`, err);
  }
}

export function cleanupSession(sessionId) {
  const sessionState = state.sessions.get(sessionId);
  if (sessionState) {
    if (typeof sessionState.transport.close === 'function') {
      try {
        sessionState.transport.close();
      } catch (err) {
        console.error(`[mcp-http] Error closing transport for ${sessionId}:`, err);
      }
    }
    sessionState.closed = true;
    state.sessions.delete(sessionId);
    state.closedSessions.add(sessionId);
    return true;
  }

  return false;
}

export function getActiveSessions() {
  return Array.from(state.sessions.values())
    .filter((session) => !session.closed)
    .map((session) => ({
      sessionId: session.sessionId,
      createdAt: session.createdAt,
      type: session.type
    }));
}

