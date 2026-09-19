import { StreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/streamableHttp.js';
import { SSEServerTransport } from '@modelcontextprotocol/sdk/server/sse.js';
import { randomUUID } from 'crypto';
import { createMcpServer } from './createMcpServer.js';
import { safeRequestErrorDetails } from './safeRequestError.js';

const state = globalThis.__httpMcpState || {
  sessions: new Map(),
  closedSessions: new Set(),
  pendingSessions: new Map()
};

state.pendingSessions ||= new Map();

globalThis.__httpMcpState = state;

function extractSessionId(req) {
  const legacy = req.headers['x-session-id'];
  const standard = req.headers['mcp-session-id'];
  if (legacy && standard && legacy !== standard) {
    const error = new Error('Conflicting MCP session identifiers');
    error.code = 'mcp_session_id_invalid';
    error.statusCode = 400;
    throw error;
  }
  const headerSessionId = standard || legacy;
  if (headerSessionId !== undefined) {
    if (
      typeof headerSessionId !== 'string'
      || !/^[A-Za-z0-9_.:-]{1,200}$/.test(headerSessionId)
    ) {
      const error = new Error('Invalid MCP session identifier');
      error.code = 'mcp_session_id_invalid';
      error.statusCode = 400;
      throw error;
    }
    return headerSessionId;
  }

  return randomUUID();
}

function requestAuthorizationBinding(req) {
  const principal = req?.oauthPrincipal || req?.nottyAuthPrincipal || null;
  if (principal) {
    return Object.freeze({
      kind: String(principal.kind || 'oauth'),
      clientId: String(principal.clientId || ''),
      agentId: String(principal.agentId || ''),
      subject: String(principal.subject || ''),
      scope: String(principal.scope || ''),
      resource: String(principal.resource || req?.nottyResource || '')
    });
  }
  if (req?.nottyBasicAuth) {
    return Object.freeze({
      kind: 'basic',
      clientId: '',
      agentId: '',
      subject: String(req.nottyBasicAuth.subject || ''),
      scope: '',
      resource: String(req.nottyResource || '')
    });
  }
  return Object.freeze({
    kind: 'anonymous',
    clientId: '',
    agentId: '',
    subject: 'local-anonymous',
    scope: '',
    resource: String(req?.nottyResource || '')
  });
}

function bindingsMatch(left, right) {
  return left.kind === right.kind
    && left.clientId === right.clientId
    && left.agentId === right.agentId
    && left.subject === right.subject
    && left.scope === right.scope
    && left.resource === right.resource;
}

function sessionAuthorizationError() {
  const error = new Error('MCP session authorization does not match the authenticated request');
  error.code = 'mcp_session_authorization_mismatch';
  error.statusCode = 403;
  return error;
}

function rememberClosedSession(sessionId) {
  state.closedSessions.add(sessionId);
  if (state.closedSessions.size > 1024) {
    const oldest = state.closedSessions.values().next().value;
    state.closedSessions.delete(oldest);
  }
}

async function createSessionState({ sessionId, type, transport, authorization }) {
  const server = createMcpServer({ name: 'node-pty-http' });
  await server.connect(transport);

  const sessionState = {
    sessionId,
    type,
    server,
    transport,
    authorization,
    createdAt: Date.now(),
    closed: false
  };

  state.sessions.set(sessionId, sessionState);
  state.closedSessions.delete(sessionId);
  const sdkOnClose = transport.onclose;
  transport.onclose = (...args) => {
    try {
      if (typeof sdkOnClose === 'function') {
        sdkOnClose.apply(transport, args);
      }
    } finally {
      sessionState.closed = true;
      if (state.sessions.get(sessionId) === sessionState) {
        state.sessions.delete(sessionId);
      }
      rememberClosedSession(sessionId);
    }
  };

  return sessionState;
}

async function ensureHttpSession(sessionId, authorization) {
  const existing = state.sessions.get(sessionId);
  if (existing && !existing.closed) {
    if (existing.type !== 'http') {
      const error = new Error('MCP session identifier belongs to another transport');
      error.code = 'mcp_session_transport_mismatch';
      error.statusCode = 409;
      throw error;
    }
    if (!bindingsMatch(existing.authorization, authorization)) {
      throw sessionAuthorizationError();
    }
    return existing;
  }

  if (state.closedSessions.has(sessionId)) {
    const error = new Error('MCP session is closed');
    error.code = 'mcp_session_closed';
    error.statusCode = 410;
    throw error;
  }

  const pending = state.pendingSessions.get(sessionId);
  if (pending) {
    if (pending.type !== 'http') {
      const error = new Error('MCP session identifier belongs to another transport');
      error.code = 'mcp_session_transport_mismatch';
      error.statusCode = 409;
      throw error;
    }
    if (!bindingsMatch(pending.authorization, authorization)) {
      throw sessionAuthorizationError();
    }
    return pending.promise;
  }

  const transport = new StreamableHTTPServerTransport({
    sessionIdGenerator: () => sessionId,
    enableJsonResponse: true
  });

  const promise = createSessionState({ sessionId, type: 'http', transport, authorization });
  state.pendingSessions.set(sessionId, {
    type: 'http',
    authorization,
    promise
  });
  try {
    return await promise;
  } finally {
    if (state.pendingSessions.get(sessionId)?.promise === promise) {
      state.pendingSessions.delete(sessionId);
    }
  }
}

export async function getServerForRequest(req) {
  const sessionId = extractSessionId(req);
  const sessionState = await ensureHttpSession(sessionId, requestAuthorizationBinding(req));
  return sessionState;
}

export async function createSseSession(req, res, { messagePath = '/mcp/message' } = {}) {
  const transport = new SSEServerTransport(messagePath, res);
  const sessionId = transport.sessionId;

  if (state.sessions.has(sessionId) || state.pendingSessions.has(sessionId)) {
    const error = new Error('MCP session identifier collision');
    error.code = 'mcp_session_id_collision';
    error.statusCode = 409;
    throw error;
  }

  const authorization = requestAuthorizationBinding(req);
  const promise = createSessionState({
    sessionId,
    type: 'sse',
    transport,
    authorization
  });
  state.pendingSessions.set(sessionId, {
    type: 'sse',
    authorization,
    promise
  });
  let sessionState;
  try {
    sessionState = await promise;
  } finally {
    if (state.pendingSessions.get(sessionId)?.promise === promise) {
      state.pendingSessions.delete(sessionId);
    }
  }

  const sdkOnError = transport.onerror;
  transport.onerror = (error) => {
    try {
      if (typeof sdkOnError === 'function') {
        sdkOnError.call(transport, error);
      }
    } finally {
      console.error(
        `[mcp-http] SSE transport error (${sessionId}):`,
        safeRequestErrorDetails(error)
      );
    }
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

  if (!bindingsMatch(sessionState.authorization, requestAuthorizationBinding(req))) {
    res.status(403).json({
      error: 'mcp_session_authorization_mismatch',
      detail: 'MCP session authorization does not match the authenticated request'
    });
    return;
  }

  try {
    await sessionState.transport.handlePostMessage(req, res, body);
  } catch (err) {
    if (!res.headersSent) {
      res.status(500).send('Internal Server Error');
    }
    console.error(
      `[mcp-http] Error handling POST for session ${sessionId}:`,
      safeRequestErrorDetails(err)
    );
  }
}

export function cleanupSession(sessionId, req = null) {
  const sessionState = state.sessions.get(sessionId);
  if (sessionState) {
    if (req && !bindingsMatch(sessionState.authorization, requestAuthorizationBinding(req))) {
      return false;
    }
    if (typeof sessionState.transport.close === 'function') {
      try {
        sessionState.transport.close();
      } catch (err) {
        console.error(
          `[mcp-http] Error closing transport for ${sessionId}:`,
          safeRequestErrorDetails(err)
        );
      }
    }
    sessionState.closed = true;
    state.sessions.delete(sessionId);
    rememberClosedSession(sessionId);
    return true;
  }

  return false;
}

export function getActiveSessions(req = null) {
  const authorization = req ? requestAuthorizationBinding(req) : null;
  return Array.from(state.sessions.values())
    .filter((session) => !session.closed)
    .filter((session) => !authorization || bindingsMatch(session.authorization, authorization))
    .map((session) => ({
      sessionId: session.sessionId,
      createdAt: session.createdAt,
      type: session.type
    }));
}
