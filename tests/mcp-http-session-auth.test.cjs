'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');

function oauthRequest(sessionId, overrides = {}) {
  return {
    headers: sessionId ? { 'mcp-session-id': sessionId } : {},
    nottyResource: 'https://notty.example/mcp',
    oauthPrincipal: {
      clientId: 'codex-client',
      subject: 'operator',
      scope: 'mcp:tools',
      resource: 'https://notty.example/mcp',
      ...overrides
    }
  };
}

function guardRequest(sessionId, overrides = {}) {
  return {
    headers: sessionId ? { 'mcp-session-id': sessionId } : {},
    nottyResource: 'https://guard.example/mcp',
    nottyAuthPrincipal: {
      kind: 'guard-mtls',
      clientId: 'run-one',
      subject: 'operator-one',
      scope: '',
      resource: '',
      ...overrides
    }
  };
}

test('MCP HTTP sessions are bound to transport and complete authorization identity', async () => {
  const sessionState = {
    sessions: new Map(),
    closedSessions: new Set(),
    pendingSessions: new Map()
  };
  globalThis.__httpMcpState = sessionState;
  const {
    cleanupSession,
    getActiveSessions,
    getServerForRequest
  } = await import('../lib/mcpHttpServer.js');

  const sessionId = 'oauth-session-one';
  const request = oauthRequest(sessionId);
  const [first, concurrent] = await Promise.all([
    getServerForRequest(request),
    getServerForRequest(request)
  ]);
  assert.strictEqual(concurrent, first);
  assert.equal(first.sessionId, sessionId);
  assert.deepEqual(getActiveSessions(request), [{
    sessionId,
    createdAt: first.createdAt,
    type: 'http'
  }]);

  for (const changed of [
    { clientId: 'other-client' },
    { agentId: 'other-agent' },
    { subject: 'other-operator' },
    { scope: 'other-scope' },
    { resource: 'https://notty.example/sse' }
  ]) {
    await assert.rejects(
      getServerForRequest(oauthRequest(sessionId, changed)),
      (error) => error.code === 'mcp_session_authorization_mismatch'
        && error.statusCode === 403
    );
  }

  assert.equal(cleanupSession(sessionId, oauthRequest(sessionId, { subject: 'intruder' })), false);
  assert.equal(cleanupSession(sessionId, request), true);
  await assert.rejects(
    getServerForRequest(request),
    (error) => error.code === 'mcp_session_closed' && error.statusCode === 410
  );

  const transportClosedId = 'transport-closed-session';
  const transportClosedRequest = oauthRequest(transportClosedId);
  const transportClosedSession = await getServerForRequest(transportClosedRequest);
  await transportClosedSession.transport.close();
  assert.equal(
    getActiveSessions(transportClosedRequest).some(
      (session) => session.sessionId === transportClosedId
    ),
    false
  );
  await assert.rejects(
    getServerForRequest(transportClosedRequest),
    (error) => error.code === 'mcp_session_closed' && error.statusCode === 410
  );
});

test('MCP sessions reject conflicting IDs, cross-transport reuse, and Guard principal crossover', async () => {
  const {
    cleanupSession,
    getServerForRequest
  } = await import('../lib/mcpHttpServer.js');

  await assert.rejects(
    getServerForRequest({
      ...oauthRequest(null),
      headers: {
        'mcp-session-id': 'standard-id',
        'x-session-id': 'different-legacy-id'
      }
    }),
    (error) => error.code === 'mcp_session_id_invalid' && error.statusCode === 400
  );

  const guardId = 'guard-session-one';
  const guard = guardRequest(guardId);
  const guardSession = await getServerForRequest(guard);
  await assert.rejects(
    getServerForRequest(guardRequest(guardId, { clientId: 'run-two' })),
    (error) => error.code === 'mcp_session_authorization_mismatch'
      && error.statusCode === 403
  );
  await assert.rejects(
    getServerForRequest(guardRequest(guardId, { agentId: 'runner-agent' })),
    (error) => error.code === 'mcp_session_authorization_mismatch'
      && error.statusCode === 403
  );
  await assert.rejects(
    getServerForRequest(oauthRequest(guardId)),
    (error) => error.code === 'mcp_session_authorization_mismatch'
      && error.statusCode === 403
  );
  assert.equal(cleanupSession(guardSession.sessionId, guard), true);

  const crossTransportId = 'reserved-sse-session';
  globalThis.__httpMcpState.sessions.set(crossTransportId, {
    sessionId: crossTransportId,
    type: 'sse',
    authorization: {
      kind: 'anonymous',
      clientId: '',
      agentId: '',
      subject: 'local-anonymous',
      scope: '',
      resource: 'http://127.0.0.1:3000/mcp'
    },
    transport: { close() {} },
    createdAt: Date.now(),
    closed: false
  });
  await assert.rejects(
    getServerForRequest({
      headers: { 'mcp-session-id': crossTransportId },
      nottyResource: 'http://127.0.0.1:3000/mcp'
    }),
    (error) => error.code === 'mcp_session_transport_mismatch'
      && error.statusCode === 409
  );
  assert.equal(cleanupSession(crossTransportId), true);
});
