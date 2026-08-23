import express from 'express';
import { getHttpProtocol, getRequestIpInfo, withLogContext } from './terminalLogging.js';
import {
  spawnTerminal,
  listTerminals,
  getTerminalSummary,
  writeToTerminal,
  createTerminalReader,
  resizeTerminal,
  killTerminal,
  inspectTerminal
} from './terminalManager.js';
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

function parseTerminalRef(value) {
  if (typeof value === 'number' && Number.isInteger(value)) {
    return value;
  }

  const raw = typeof value === 'string' ? value.trim() : '';
  if (!raw) {
    throw new Error('Invalid session reference');
  }
  return raw;
}

function withHttpContext(req, route, fn) {
  const protocol = getHttpProtocol(req);
  const { sourceIp, forwardedFor } = getRequestIpInfo(req);
  return withLogContext(
    {
      protocol,
      transport: 'http',
      source: 'terminalHttpApi',
      route,
      source_ip: sourceIp,
      x_forwarded_for: forwardedFor
    },
    fn
  );
}

export function registerTerminalHttpRoutes(app, options = {}) {
  const {
    allowedOrigin = process.env.ALLOWED_ORIGIN,
    trustedHosts = process.env.NOTTY_TRUSTED_HOSTS,
    basePath = '/api/terminals',
    lockdown = isTerminalLockdownEnabled()
  } = options;

  app.get('/health', (_req, res) => {
    res.json({ status: 'ok', lockdown });
  });

  const router = express.Router();
  router.use(createCorsMiddleware({
    allowedOrigin,
    allowedMethods: 'GET,POST,DELETE,OPTIONS',
    trustedHosts
  }));

  router.use(express.json());

  if (lockdown) {
    router.all('*', (_req, res) => {
      sendTerminalLockdownResponse(res);
    });
    app.use(basePath, router);
    return;
  }

  router.get('/', asyncHandler(async (req, res) => {
    await withHttpContext(req, 'GET /api/terminals', async () => {
      res.json({ sessions: listTerminals() });
    });
  }));

  router.post('/', asyncHandler(async (req, res) => {
    await withHttpContext(req, 'POST /api/terminals', async () => {
      const session = spawnTerminal(req.body || {});
      res.status(201).json({ session });
    });
  }));

  router.get('/:id', asyncHandler(async (req, res) => {
    await withHttpContext(req, 'GET /api/terminals/:id', async () => {
      const session = getTerminalSummary(parseTerminalRef(req.params.id));
      res.json({ session });
    });
  }));

  router.get('/:id/inspect', asyncHandler(async (req, res) => {
    await withHttpContext(req, 'GET /api/terminals/:id/inspect', async () => {
      const inspection = inspectTerminal(parseTerminalRef(req.params.id));
      res.json({ inspection });
    });
  }));

  router.post('/:id/write', asyncHandler(async (req, res) => {
    await withHttpContext(req, 'POST /api/terminals/:id/write', async () => {
      const id = parseTerminalRef(req.params.id);
      const data = req.body?.data ?? '';
      if (typeof data !== 'string') {
        throw new Error('data must be a string');
      }
      const bytes = writeToTerminal(id, data, { actor: 'human' });
      res.json({ bytesWritten: bytes });
    });
  }));

  router.post('/:id/read', asyncHandler(async (req, res) => {
    await withHttpContext(req, 'POST /api/terminals/:id/read', async () => {
      const id = parseTerminalRef(req.params.id);
      const reader = createTerminalReader(id, { includeHistory: true });
      const data = reader.read();
      reader.dispose();
      res.json({ data });
    });
  }));

  router.post('/:id/resize', asyncHandler(async (req, res) => {
    await withHttpContext(req, 'POST /api/terminals/:id/resize', async () => {
      const id = parseTerminalRef(req.params.id);
      const cols = req.body?.cols;
      const rows = req.body?.rows;
      const session = resizeTerminal(id, cols, rows);
      res.json({ session });
    });
  }));

  router.delete('/:id', asyncHandler(async (req, res) => {
    await withHttpContext(req, 'DELETE /api/terminals/:id', async () => {
      const id = parseTerminalRef(req.params.id);
      killTerminal(id);
      res.status(204).end();
    });
  }));

  router.use((err, _req, res, _next) => {
    console.error('[terminal-http] error:', err);
    res.status(400).json({ error: err.message || 'Unknown error' });
  });

  app.use(basePath, router);
}
