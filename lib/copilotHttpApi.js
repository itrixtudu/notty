import express from 'express';
import {
  approveCopilotProposal,
  askCopilot,
  createCopilot,
  getCopilot,
  getCopilotCatalog,
  listCopilots,
  renewCopilot,
  stopCopilot,
  subscribeToCopilotEvents,
  updateCopilot
} from './copilotManager.js';
import { createCorsMiddleware } from './corsPolicy.js';
import {
  isTerminalLockdownEnabled,
  sendTerminalLockdownResponse
} from './lockdown.js';
import { getHttpProtocol, getRequestIpInfo, withLogContext } from './terminalLogging.js';

function asyncHandler(fn) {
  return async (req, res, next) => {
    try {
      await fn(req, res, next);
    } catch (error) {
      next(error);
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
      source: 'copilotHttpApi',
      route,
      source_ip: sourceIp,
      x_forwarded_for: forwardedFor
    },
    fn
  );
}

function defaultOperations() {
  return {
    list: listCopilots,
    get: getCopilot,
    create: createCopilot,
    update: updateCopilot,
    stop: stopCopilot,
    ask: askCopilot,
    renew: renewCopilot,
    approveProposal: approveCopilotProposal,
    catalog: getCopilotCatalog,
    subscribe: subscribeToCopilotEvents
  };
}

export function registerCopilotHttpRoutes(app, options = {}) {
  const {
    allowedOrigin = process.env.ALLOWED_ORIGIN,
    trustedHosts = process.env.NOTTY_TRUSTED_HOSTS,
    basePath = '/api/copilots',
    lockdown = isTerminalLockdownEnabled(),
    operations = defaultOperations()
  } = options;

  const router = express.Router();
  router.use(createCorsMiddleware({
    allowedOrigin,
    allowedMethods: 'GET,POST,PATCH,DELETE,OPTIONS',
    trustedHosts
  }));
  router.use(express.json({ limit: '64kb' }));

  if (lockdown) {
    router.all('*', (_req, res) => sendTerminalLockdownResponse(res));
    app.use(basePath, router);
    return operations;
  }

  router.get('/', asyncHandler(async (req, res) => {
    await withHttpContext(req, 'GET /api/copilots', async () => {
      res.setHeader('Cache-Control', 'no-store');
      // Runtime probes can take longer than the in-memory snapshot. Read bindings last so a
      // completed request never returns state from before its catalog refresh.
      const catalog = operations.catalog();
      const copilots = operations.list();
      res.json({ copilots, catalog });
    });
  }));

  router.post('/', asyncHandler(async (req, res) => {
    await withHttpContext(req, 'POST /api/copilots', async () => {
      const copilot = operations.create(req.body || {});
      res.status(201).json({ copilot });
    });
  }));

  // This must precede /:id so "events" cannot be interpreted as a binding id.
  router.get('/events', asyncHandler(async (req, res) => {
    await withHttpContext(req, 'GET /api/copilots/events', async () => {
      res.statusCode = 200;
      res.setHeader('Content-Type', 'text/event-stream');
      res.setHeader('Cache-Control', 'no-cache, no-transform');
      res.setHeader('Connection', 'keep-alive');
      res.setHeader('X-Accel-Buffering', 'no');
      res.flushHeaders?.();

      const send = (event) => {
        if (!res.writableEnded) {
          let payload = event;
          if (event?.bindingId) {
            try {
              const copilot = operations.get(event.bindingId);
              if (copilot) {
                payload = { ...event, copilot };
              }
            } catch {
              // Stopped bindings are intentionally absent; the client will refresh its list.
            }
          }
          res.write(`id: ${event.id}\n`);
          res.write('event: copilot\n');
          res.write(`data: ${JSON.stringify(payload)}\n\n`);
        }
      };
      const unsubscribe = operations.subscribe(send);
      const heartbeat = setInterval(() => {
        if (!res.writableEnded) {
          res.write(': heartbeat\n\n');
        }
      }, 15_000);
      heartbeat.unref?.();
      req.once('close', () => {
        clearInterval(heartbeat);
        unsubscribe();
      });
      res.write(': connected\n\n');
    });
  }));

  router.get('/:id', asyncHandler(async (req, res) => {
    await withHttpContext(req, 'GET /api/copilots/:id', async () => {
      res.setHeader('Cache-Control', 'no-store');
      res.json({ copilot: operations.get(req.params.id) });
    });
  }));

  router.patch('/:id', asyncHandler(async (req, res) => {
    await withHttpContext(req, 'PATCH /api/copilots/:id', async () => {
      res.json({ copilot: operations.update(req.params.id, req.body || {}) });
    });
  }));

  router.delete('/:id', asyncHandler(async (req, res) => {
    await withHttpContext(req, 'DELETE /api/copilots/:id', async () => {
      operations.stop(req.params.id, 'user');
      res.status(204).end();
    });
  }));

  router.post('/:id/ask', asyncHandler(async (req, res) => {
    await withHttpContext(req, 'POST /api/copilots/:id/ask', async () => {
      const result = operations.ask(req.params.id, req.body || {});
      res.status(202).json(result);
    });
  }));

  router.post('/:id/renew', asyncHandler(async (req, res) => {
    await withHttpContext(req, 'POST /api/copilots/:id/renew', async () => {
      res.json(operations.renew(req.params.id, req.body || {}));
    });
  }));

  router.post('/:id/proposals/:proposalId/approve', asyncHandler(async (req, res) => {
    await withHttpContext(req, 'POST /api/copilots/:id/proposals/:proposalId/approve', async () => {
      res.json(operations.approveProposal(req.params.id, req.params.proposalId));
    });
  }));

  router.use((error, _req, res, _next) => {
    const statusCode = Number.isInteger(error?.statusCode) ? error.statusCode : 400;
    if (statusCode >= 500) {
      console.error('[copilot-http] error:', error);
    }
    res.status(statusCode).json({
      error: error?.message || 'Unknown copilot error',
      code: error?.code || 'COPILOT_REQUEST_FAILED'
    });
  });

  app.use(basePath, router);
  return operations;
}
