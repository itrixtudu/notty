import express from 'express';
import { getHttpProtocol, getRequestIpInfo, withLogContext } from './terminalLogging.js';
import {
  askAgents,
  listAgents,
  postCopilotMessage,
  readAgentMessages
} from './agentManager.js';
import {
  isTerminalLockdownEnabled,
  sendTerminalLockdownResponse
} from './lockdown.js';
import { createCorsMiddleware } from './corsPolicy.js';

function asyncHandler(fn) {
  return async (req, res, next) => {
    try {
      await fn(req, res, next);
    } catch (err) {
      next(err);
    }
  };
}

function withHttpContext(req, route, fn) {
  const protocol = getHttpProtocol(req);
  const { sourceIp, forwardedFor } = getRequestIpInfo(req);
  return withLogContext(
    {
      protocol,
      transport: 'http',
      source: 'agentHttpApi',
      route,
      source_ip: sourceIp,
      x_forwarded_for: forwardedFor
    },
    fn
  );
}

export function registerAgentHttpRoutes(app, options = {}) {
  const {
    allowedOrigin = process.env.ALLOWED_ORIGIN,
    trustedHosts = process.env.NOTTY_TRUSTED_HOSTS,
    basePath = '/api/agents',
    lockdown = isTerminalLockdownEnabled()
  } = options;

  const router = express.Router();
  router.use(createCorsMiddleware({ allowedOrigin, trustedHosts }));

  router.use(express.json({ limit: '4mb' }));

  if (lockdown) {
    router.all('*', (_req, res) => {
      sendTerminalLockdownResponse(res);
    });
    app.use(basePath, router);
    return;
  }

  router.get('/', asyncHandler(async (req, res) => {
    await withHttpContext(req, 'GET /api/agents', async () => {
      res.json(listAgents());
    });
  }));

  router.get('/messages', asyncHandler(async (req, res) => {
    await withHttpContext(req, 'GET /api/agents/messages', async () => {
      res.json(readAgentMessages(req.query || {}));
    });
  }));

  router.post('/messages', asyncHandler(async (req, res) => {
    await withHttpContext(req, 'POST /api/agents/messages', async () => {
      const message = postCopilotMessage(req.body || {});
      res.status(201).json({ message });
    });
  }));

  router.post('/ask', asyncHandler(async (req, res) => {
    await withHttpContext(req, 'POST /api/agents/ask', async () => {
      const result = askAgents(req.body || {});
      res.status(202).json(result);
    });
  }));

  router.use((err, _req, res, _next) => {
    console.error('[agent-http] error:', err);
    res.status(400).json({ error: err.message || 'Unknown error' });
  });

  app.use(basePath, router);
}
