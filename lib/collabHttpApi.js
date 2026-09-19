import http from 'node:http';
import path from 'node:path';
import express from 'express';
import { createCollabSupervisor, CollabSupervisorError } from './collabSupervisor.js';
import { isAgentViewEligible } from './collabViewPolicy.js';
import {
  killTerminal,
  listTerminalsByMetadata,
  spawnTrustedTerminal
} from './terminalManager.js';
import {
  isTerminalLockdownEnabled,
  sendTerminalLockdownResponse
} from './lockdown.js';
import { createCorsMiddleware } from './corsPolicy.js';

const VIEW_METADATA_TYPE = 'collab-view';
const viewOperations = new Map();
const retiredViewTerminals = new Set();

function asyncHandler(fn) {
  return async (req, res, next) => {
    try {
      await fn(req, res, next);
    } catch (error) {
      next(error);
    }
  };
}

function requestSearch(req) {
  return new URL(req.originalUrl || req.url, 'http://notty.local').search;
}

function copyResponseHeaders(upstream, res) {
  for (const name of ['content-type', 'cache-control', 'etag', 'last-modified']) {
    const value = upstream.headers.get(name);
    if (value) {
      res.setHeader(name, value);
    }
  }
}

function basicAuthUsername(headerValue) {
  if (typeof headerValue !== 'string') {
    return '';
  }
  const match = headerValue.match(/^Basic\s+([^\s]+)$/i);
  if (!match) {
    return '';
  }
  try {
    const decoded = Buffer.from(match[1], 'base64').toString('utf8');
    const separator = decoded.indexOf(':');
    return String(separator === -1 ? decoded : decoded.slice(0, separator)).trim();
  } catch {
    return '';
  }
}

function requestOperator(req) {
  const basicAuthEnabled = ['1', 'true', 'yes', 'on'].includes(
    String(process.env.NOTTY_BASIC_AUTH_ENABLED || '').trim().toLowerCase()
  );
  return (basicAuthEnabled ? basicAuthUsername(req.headers.authorization) : '')
    || String(process.env.NOTTY_COLLAB_OPERATOR || 'operator').trim()
    || 'operator';
}

async function forwardRequest(supervisor, req, res, upstreamPath) {
  const hasBody = !['GET', 'HEAD'].includes(req.method);
  const body = hasBody ? JSON.stringify(req.body ?? {}) : undefined;
  const upstream = await supervisor.request(upstreamPath, {
    method: req.method,
    search: requestSearch(req),
    headers: {
      Accept: req.headers.accept || 'application/json',
      'X-Notty-Collab-Operator': requestOperator(req),
      ...(hasBody ? { 'Content-Type': 'application/json' } : {})
    },
    body
  });
  const payload = Buffer.from(await upstream.arrayBuffer());
  copyResponseHeaders(upstream, res);
  res.status(upstream.status);
  if (req.method === 'HEAD' || upstream.status === 204) {
    res.end();
  } else {
    res.send(payload);
  }
  let responseBody = null;
  if (payload.length > 0 && upstream.headers.get('content-type')?.includes('application/json')) {
    try {
      responseBody = JSON.parse(payload.toString('utf8'));
    } catch {
      // The response has already been forwarded; callers can safely treat it as opaque.
    }
  }
  return { status: upstream.status, body: responseBody };
}

async function streamEvents(supervisor, req, res) {
  await supervisor.ensureReady();
  return new Promise((resolve, reject) => {
    const url = supervisor.resolveUrl('/admin/v1/events', requestSearch(req));
    const upstreamRequest = http.request(url, {
      method: 'GET',
      headers: {
        Accept: 'text/event-stream',
        ...(req.headers['last-event-id']
          ? { 'Last-Event-ID': req.headers['last-event-id'] }
          : {})
      }
    });

    let upstreamResponse = null;
    const closeUpstream = () => {
      upstreamResponse?.destroy();
      upstreamRequest.destroy();
    };
    res.once('close', closeUpstream);

    upstreamRequest.once('response', (upstream) => {
      upstreamResponse = upstream;
      res.statusCode = upstream.statusCode || 502;
      res.setHeader('Content-Type', upstream.headers['content-type'] || 'text/event-stream');
      res.setHeader('Cache-Control', upstream.headers['cache-control'] || 'no-cache');
      res.setHeader('Connection', 'keep-alive');
      res.setHeader('X-Accel-Buffering', upstream.headers['x-accel-buffering'] || 'no');
      res.flushHeaders?.();
      upstream.on('error', () => {
        if (!res.writableEnded) {
          res.end();
        }
      });
      upstream.pipe(res);
      resolve();
    });
    upstreamRequest.once('error', (error) => {
      res.off('close', closeUpstream);
      reject(error);
    });
    upstreamRequest.end();
  });
}

function sessionFromPayload(payload) {
  if (payload && Object.prototype.hasOwnProperty.call(payload, 'session')) {
    return payload.session;
  }
  return payload;
}

function terminalsForView(sessionId, view) {
  return listTerminalsByMetadata({
    type: VIEW_METADATA_TYPE,
    collabSessionId: sessionId,
    view
  }).filter((terminal) => !retiredViewTerminals.has(terminal.terminal_uuid));
}

function terminalForView(sessionId, view, agentId = null) {
  const matches = terminalsForView(sessionId, view);
  if (view === 'agent') {
    return matches.find((terminal) => terminal.metadata?.agentId === agentId) || null;
  }
  return matches[0] || null;
}

function retireViewTerminal(terminal) {
  if (!terminal || retiredViewTerminals.has(terminal.terminal_uuid)) {
    return;
  }
  retiredViewTerminals.add(terminal.terminal_uuid);
  try {
    killTerminal(terminal.terminal_uuid);
  } catch {
    // The PTY may have exited between listing and retirement.
  }
  const expiry = setTimeout(() => {
    retiredViewTerminals.delete(terminal.terminal_uuid);
  }, 30_000);
  expiry.unref?.();
}

function agentViewGeneration(agent) {
  return JSON.stringify({
    tmuxTarget: String(agent.tmuxTarget || agent.target || ''),
    startedAt: String(agent.startedAt || ''),
    permissionMode: String(agent.permissionMode || ''),
    runtimeSessionId: String(agent.runtimeSessionId || '')
  });
}

function spawnChannelViewer({ appRoot, workspaceRoot, supervisor, session }) {
  const channel = String(session.channel || 'lobby');
  const operator = String(process.env.NOTTY_COLLAB_OPERATOR || 'operator');
  return spawnTrustedTerminal({
    shell: process.execPath,
    args: [
      path.join(appRoot, 'collab.cjs'),
      'irc',
      '--server',
      supervisor.daemonUrl,
      '--agent',
      operator,
      '--channel',
      channel
    ],
    cwd: workspaceRoot,
    cols: 120,
    rows: 36,
    terminalType: 'xterm',
    metadata: {
      type: VIEW_METADATA_TYPE,
      collabSessionId: String(session.id),
      view: 'channel',
      channel,
      label: `#${channel}`
    }
  }, { inputAccess: { purpose: 'collab-viewer', createdAt: Date.parse(session.createdAt), expiresAt: Date.parse(session.createdAt) + 3600000 } });
}

function spawnAgentViewer({ workspaceRoot, session, agent, agentId, generation }) {
  const tmuxTarget = String(agent.tmuxTarget || agent.target || '').trim();
  if (!tmuxTarget) {
    throw new Error(`Session agent ${agentId} does not have a tmux target`);
  }
  return spawnTrustedTerminal(
    {
      shell: 'tmux',
      args: ['-u', 'attach-session', '-t', tmuxTarget],
      cwd: workspaceRoot,
      cols: 120,
      rows: 36,
      terminalType: 'xterm',
      metadata: {
        type: VIEW_METADATA_TYPE,
        collabSessionId: String(session.id),
        view: 'agent',
        agentId,
        identity: String(agent.identity || agent.id || agentId),
        role: String(agent.role || agent.prompt || ''),
        model: String(agent.model || ''),
        tmuxTarget,
        generation,
        label: String(agent.identity || agent.id || agentId)
      }
    },
    { env: { TMUX: null, TMUX_PANE: null },
      inputAccess: Number.isFinite(agent.expiresAt)
        ? { purpose: 'collab-viewer', createdAt: Date.parse(agent.startedAt), expiresAt: agent.expiresAt } : null }
  );
}

function withViewOperation(key, operation) {
  const previous = viewOperations.get(key) || Promise.resolve();
  const current = previous.catch(() => {}).then(operation);
  viewOperations.set(key, current);
  return current.finally(() => {
    if (viewOperations.get(key) === current) {
      viewOperations.delete(key);
    }
  });
}

async function ensureSessionViews({ appRoot, workspaceRoot, supervisor }) {
  const payload = await supervisor.requestJson('/admin/v1/session');
  const session = sessionFromPayload(payload);
  if (!session || !session.id) {
    throw new CollabSupervisorError('No active collaboration session', {
      code: 'COLLAB_SESSION_NOT_FOUND',
      statusCode: 404
    });
  }

  const sessionId = String(session.id);
  return withViewOperation(sessionId, async () => {
    let channelTerminal = terminalForView(sessionId, 'channel');
    if (!channelTerminal) {
      channelTerminal = spawnChannelViewer({ appRoot, workspaceRoot, supervisor, session });
    }

    const agentTerminals = [];
    const agents = Array.isArray(session.agents) ? session.agents : [];
    for (let index = 0; index < agents.length; index += 1) {
      const agent = agents[index] || {};
      const agentId = String(agent.id || agent.identity || `agent-${index + 1}`);
      const generation = agentViewGeneration(agent);
      const existingTerminals = terminalsForView(sessionId, 'agent')
        .filter((terminal) => terminal.metadata?.agentId === agentId);
      let terminal = existingTerminals.find(
        (entry) => entry.metadata?.generation === generation
      ) || null;
      existingTerminals
        .filter((entry) => entry.terminal_uuid !== terminal?.terminal_uuid)
        .forEach(retireViewTerminal);
      if (!isAgentViewEligible(session, agent)) {
        if (terminal) {
          retireViewTerminal(terminal);
        }
        agentTerminals.push([agentId, null]);
        continue;
      }
      if (!terminal) {
        terminal = spawnAgentViewer({
          workspaceRoot,
          session,
          agent,
          agentId,
          generation
        });
      }
      agentTerminals.push([agentId, terminal]);
    }

    return {
      session,
      layout: session.layout || null,
      terminals: {
        channel: channelTerminal,
        agents: Object.fromEntries(agentTerminals)
      }
    };
  });
}

function cleanupSessionViews(sessionId = null) {
  const criteria = { type: VIEW_METADATA_TYPE };
  if (sessionId) {
    criteria.collabSessionId = String(sessionId);
  }
  const viewers = listTerminalsByMetadata(criteria);
  for (const viewer of viewers) {
    try {
      killTerminal(viewer.terminal_uuid);
    } catch {
      // The PTY may have exited between listing and cleanup.
    }
  }
  return viewers.length;
}

export function registerCollabHttpRoutes(app, options = {}) {
  const {
    allowedOrigin = process.env.ALLOWED_ORIGIN,
    publicOrigin = process.env.NOTTY_PUBLIC_ORIGIN,
    trustedHosts = process.env.NOTTY_TRUSTED_HOSTS,
    appRoot = process.cwd(),
    workspaceRoot = process.env.NOTTY_WORKDIR || appRoot,
    basePath = '/api/collab',
    lockdown = isTerminalLockdownEnabled()
  } = options;
  const supervisor = options.supervisor || createCollabSupervisor({ appRoot, workspaceRoot });
  const router = express.Router();

  router.use(createCorsMiddleware({
    allowedOrigin,
    publicOrigin,
    allowedHeaders: 'Content-Type, Authorization, Last-Event-ID',
    allowedMethods: 'GET,POST,PUT,PATCH,DELETE,OPTIONS',
    trustedHosts
  }));
  router.use((req, res, next) => {
    if (['POST', 'PUT', 'PATCH'].includes(req.method) && !req.is('application/json')) {
      res.status(415).json({
        error: { code: 'COLLAB_JSON_REQUIRED', message: 'Collab mutations require application/json' }
      });
      return;
    }
    next();
  });
  router.use(express.json({ limit: '4mb' }));

  if (lockdown) {
    router.all('*', (_req, res) => sendTerminalLockdownResponse(res));
    app.use(basePath, router);
    return supervisor;
  }

  router.get('/bootstrap', asyncHandler((req, res) => (
    forwardRequest(supervisor, req, res, '/admin/v1/bootstrap')
  )));
  router.post('/catalog/refresh', asyncHandler((req, res) => (
    forwardRequest(supervisor, req, res, '/admin/v1/catalog/refresh')
  )));
  router.get('/config', asyncHandler((req, res) => (
    forwardRequest(supervisor, req, res, '/admin/v1/config')
  )));
  router.put('/config/:scope', asyncHandler((req, res) => (
    forwardRequest(
      supervisor,
      req,
      res,
      `/admin/v1/config/${encodeURIComponent(req.params.scope)}`
    )
  )));

  for (const method of ['get', 'post', 'patch']) {
    router[method]('/tasks', asyncHandler((req, res) => (
      forwardRequest(supervisor, req, res, '/admin/v1/tasks')
    )));
  }
  router.get('/session', asyncHandler((req, res) => (
    forwardRequest(supervisor, req, res, '/admin/v1/session')
  )));
  router.post('/session', asyncHandler(async (req, res) => {
    if (!req.body || typeof req.body !== 'object' || Array.isArray(req.body)) {
      res.status(400).json({
        error: { code: 'COLLAB_INVALID_BODY', message: 'Session request body must be an object' }
      });
      return;
    }
    await forwardRequest(supervisor, req, res, '/admin/v1/session');
  }));
  router.patch('/session', asyncHandler((req, res) => (
    forwardRequest(supervisor, req, res, '/admin/v1/session')
  )));
  router.delete('/session', asyncHandler(async (req, res) => {
    const { status, body } = await forwardRequest(supervisor, req, res, '/admin/v1/session');
    if (status >= 200 && status < 300) {
      const sessionId = body?.result?.id;
      if (sessionId) {
        cleanupSessionViews(String(sessionId));
      } else {
        // With no active session, any remaining viewers are stale under the
        // current one-session-per-workspace invariant.
        cleanupSessionViews();
      }
    }
  }));
  router.post('/session/agents/:id/retry', asyncHandler((req, res) => (
    forwardRequest(
      supervisor,
      req,
      res,
      `/admin/v1/session/agents/${encodeURIComponent(req.params.id)}/retry`
    )
  )));
  router.put('/session/agents/:id/health', asyncHandler((req, res) => (
    forwardRequest(
      supervisor,
      req,
      res,
      `/admin/v1/session/agents/${encodeURIComponent(req.params.id)}/health`
    )
  )));
  router.post('/session/agents/:id/permission-mode', asyncHandler((req, res) => (
    forwardRequest(
      supervisor,
      req,
      res,
      `/admin/v1/session/agents/${encodeURIComponent(req.params.id)}/permission-mode`
    )
  )));

  router.post('/session/views', asyncHandler(async (_req, res) => {
    const result = await ensureSessionViews({
      appRoot: path.resolve(appRoot),
      workspaceRoot: path.resolve(workspaceRoot),
      supervisor
    });
    res.status(201).json(result);
  }));
  router.delete('/session/views', asyncHandler(async (_req, res) => {
    cleanupSessionViews();
    res.status(204).end();
  }));

  router.get('/channels/:channel/messages', asyncHandler((req, res) => (
    forwardRequest(
      supervisor,
      req,
      res,
      `/admin/v1/channels/${encodeURIComponent(req.params.channel)}/messages`
    )
  )));
  router.post('/channels/:channel/messages', asyncHandler((req, res) => (
    forwardRequest(
      supervisor,
      req,
      res,
      `/admin/v1/channels/${encodeURIComponent(req.params.channel)}/messages`
    )
  )));
  router.put('/channels/:channel/messages/:messageId/feedback', asyncHandler((req, res) => (
    forwardRequest(
      supervisor,
      req,
      res,
      `/admin/v1/channels/${encodeURIComponent(req.params.channel)}`
        + `/messages/${encodeURIComponent(req.params.messageId)}/feedback`
    )
  )));
  router.get('/stats', asyncHandler((req, res) => (
    forwardRequest(supervisor, req, res, '/admin/v1/stats')
  )));
  router.get('/events', asyncHandler((req, res) => streamEvents(supervisor, req, res)));

  router.use((error, _req, res, _next) => {
    console.error('[collab-http] error:', error);
    if (res.headersSent) {
      if (!res.writableEnded) {
        res.end();
      }
      return;
    }
    const status = Number.isInteger(error.statusCode)
      ? error.statusCode
      : Number.isInteger(error.status)
          ? error.status
          : 502;
    res.status(status).json({
      error: {
        code: error.code || 'COLLAB_BRIDGE_ERROR',
        message: error.message || 'Collab bridge request failed',
        ...(error.details === undefined ? {} : { details: error.details })
      }
    });
  });

  app.use(basePath, router);
  supervisor.start().catch((error) => {
    console.error(`[collab-supervisor] initial startup failed: ${error.message}`);
  });
  return supervisor;
}
