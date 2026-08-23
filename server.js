#!/usr/bin/env node

import http from 'node:http';
import { URL, fileURLToPath } from 'node:url';
import express from 'express';
import next from 'next';
import { WebSocketServer } from 'ws';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { registerTerminalHttpRoutes } from './lib/terminalHttpApi.js';
import { registerAgentHttpRoutes } from './lib/agentHttpApi.js';
import { registerCopilotHttpRoutes } from './lib/copilotHttpApi.js';
import { createCopilotManager } from './lib/copilotManager.js';
import { startCopilotMcpBroker } from './lib/copilotMcpBroker.js';
import { registerCollabHttpRoutes } from './lib/collabHttpApi.js';
import {
  getServerForRequest,
  getActiveSessions,
  cleanupSession,
  createSseSession,
  handleSsePost
} from './lib/mcpHttpServer.js';
import { getMcpToolset, getToolsetMode } from './lib/mcpToolset.js';
import { registerExternalWsServer } from './lib/standaloneWsServer.js';
import { createMcpServer } from './lib/createMcpServer.js';
import { listenHttpServer } from './lib/httpServerListen.js';
import { createMcpHttpCallHandler } from './lib/mcpHttpCallHandler.js';
import { createCorsMiddleware, resolveOriginPolicy } from './lib/corsPolicy.js';
import { createTokenHandler, getAuthMiddleware, getPublicTokenInfo } from './lib/authToken.js';
import {
  getHttpBasicAuthInfo,
  getHttpBasicAuthMiddleware,
  validateHttpBasicAuthRequest,
  writeHttpBasicAuthChallenge
} from './lib/httpBasicAuth.js';
import { getSpawnOtpSummary } from './lib/mcpSpawnOtp.js';
import {
  getTerminalSummary,
  killTerminal,
  listTerminals,
  spawnTerminal
} from './lib/terminalManager.js';
import { isTerminalLockdownEnabled } from './lib/lockdown.js';
import {
  getHttpProtocol,
  getRequestIpInfo,
  isLoggingEnabled,
  logTerminalEvent,
  shouldLogReads,
  withLogContext
} from './lib/terminalLogging.js';
import {
  buildHttpUrl,
  buildWsUrl,
  resolveServerAddress
} from './lib/serverAddress.js';
import {
  applyRuntimeConfigToEnv,
  resolveRuntimeConfig,
  runtimeHelp
} from './lib/runtimeConfig.js';

const APP_WORKDIR = process.env.NOTTY_APP_WORKDIR || fileURLToPath(new URL('.', import.meta.url));
const TERMINAL_WORKDIR = process.env.NOTTY_WORKDIR || APP_WORKDIR;
const RUNTIME_CONFIG = resolveRuntimeConfig({
  argv: process.argv.slice(2),
  appRoot: APP_WORKDIR,
  workspaceRoot: TERMINAL_WORKDIR
});
applyRuntimeConfigToEnv(RUNTIME_CONFIG);
const MODE = RUNTIME_CONFIG.mode;

if (RUNTIME_CONFIG.help) {
  console.log(runtimeHelp());
  process.exit(0);
}

const lockdownState = {
  enabled: isTerminalLockdownEnabled(),
  sessionId: null,
  command: `${APP_WORKDIR}/scripts/notty-lockdown-screen.sh`,
  cwd: TERMINAL_WORKDIR
};

function summarizeOauthState() {
  const info = getPublicTokenInfo({ eager: false });

  if (!info.enabled) {
    return 'disabled';
  }

  if (!info.configured) {
    return 'enabled (missing client id/secret)';
  }

  if (info.ttlSeconds === null) {
    return 'enabled (no ttl)';
  }

  return `enabled (ttl=${info.ttlSeconds}s)`;
}

function summarizeHttpBasicAuthState() {
  const info = getHttpBasicAuthInfo();
  if (!info.enabled) {
    return 'disabled';
  }
  if (!info.configured) {
    return 'enabled (missing username/password)';
  }
  return `enabled (user=${info.username})`;
}

function summarizeSpawnOtpState() {
  const summary = getSpawnOtpSummary();
  if (!summary.enabled) {
    return 'disabled';
  }

  const parts = [`available=${summary.availableCount}`];
  if (summary.usedCount > 0) {
    parts.push(`used=${summary.usedCount}`);
  }
  if (summary.expiredCount > 0) {
    parts.push(`expired=${summary.expiredCount}`);
  }
  if (summary.defaultTtlSeconds !== null) {
    parts.push(`default_ttl=${summary.defaultTtlSeconds}s`);
  }

  return `enabled (${parts.join(', ')})`;
}

function summarizeLoggingState() {
  const enabled = isLoggingEnabled();
  if (!enabled) {
    return 'disabled';
  }

  const logReads = shouldLogReads();
  const logFile =
    typeof process.env.NOTTY_LOG_FILE === 'string' && process.env.NOTTY_LOG_FILE.trim()
      ? process.env.NOTTY_LOG_FILE.trim()
      : 'stderr';

  return `enabled (reads=${logReads ? 'on' : 'off'}, destination=${logFile})`;
}

function summarizeToolsetState() {
  const raw = process.env.NOTTY_MCP_TOOLSET;
  const mode = getToolsetMode(raw);
  if (typeof raw !== 'string' || !raw.trim()) {
    return mode;
  }
  const trimmed = raw.trim();
  if (trimmed.toLowerCase() === mode) {
    return mode;
  }
  return `${mode} (env=${trimmed})`;
}

function logSystemState({ mcpTransport, allowedOrigin, publicWsUrl, showWsUrl = false } = {}) {
  const lockdownEnabled = isTerminalLockdownEnabled();
  const lockdownUiEnabled = isTerminalLockdownEnabled(process.env.NOTTY_LOCKDOWN_UI ?? '');
  const lockdownSessionIdRaw = process.env.NOTTY_LOCKDOWN_SESSION_ID;
  const lockdownSessionId = (
    lockdownEnabled
    && typeof lockdownSessionIdRaw === 'string'
    && lockdownSessionIdRaw.trim()
  )
    ? lockdownSessionIdRaw.trim()
    : null;

  const primaryParts = [
    `mode=${MODE}`,
    `mcp_transport=${mcpTransport || 'unknown'}`,
    `collab=${RUNTIME_CONFIG.switches.collab ? 'on' : 'off'}(${RUNTIME_CONFIG.sources.collab})`,
    `lockdown=${lockdownEnabled ? 'on' : 'off'}`,
    `lockdown_ui=${lockdownUiEnabled ? 'on' : 'off'}`,
    lockdownSessionId ? `lockdown_session=${lockdownSessionId}` : null,
    `basic_auth=${summarizeHttpBasicAuthState()}`,
    `oauth=${summarizeOauthState()}`,
    `spawn_otp=${summarizeSpawnOtpState()}`,
    `mcp_toolset=${summarizeToolsetState()}`
  ].filter(Boolean);

  console.error(`[notty] state: ${primaryParts.join(', ')}`);

  const secondaryParts = [`logging=${summarizeLoggingState()}`];
  if (typeof allowedOrigin === 'string') {
    secondaryParts.push(`cors_origin=${allowedOrigin}`);
  }
  if (showWsUrl) {
    secondaryParts.push(`public_ws_url=${publicWsUrl || 'auto'}`);
  }

  console.error(`[notty] state: ${secondaryParts.join(', ')}`);
}

function logOauthStatus() {
  const info = getPublicTokenInfo({ eager: false });

  if (!info.enabled) {
    console.error('[auth] OAuth shim disabled');
    return;
  }

  if (!info.configured) {
    console.error('[auth] OAuth shim enabled but NOTTY_OAUTH_CLIENT_ID/SECRET are missing');
    return;
  }

  const ttlText =
    info.ttlSeconds === null
      ? 'no TTL configured (tokens persist until restart)'
      : `${info.ttlSeconds}s TTL`;

  if (!info.createdAt) {
    console.error(`[auth] OAuth shim enabled (${ttlText}); token not yet issued`);
    return;
  }

  const expiresIn =
    info.expiresAt === null ? null : Math.max(0, Math.floor((info.expiresAt - Date.now()) / 1000));
  const issuedAt = new Date(info.createdAt).toISOString();
  const expiryText = expiresIn === null ? 'no expiry' : `expires in ${expiresIn}s`;

  console.error(`[auth] OAuth shim enabled (${ttlText}); issued ${issuedAt}, ${expiryText}`);
}

function ensureLockdownSession() {
  if (!lockdownState.enabled) {
    return null;
  }

  if (lockdownState.sessionId !== null) {
    try {
      const session = getTerminalSummary(lockdownState.sessionId);
      if (session.alive) {
        return lockdownState.sessionId;
      }
      console.error('[notty] Lockdown session exited, restarting');
    } catch (err) {
      console.error('[notty] Lockdown session missing, restarting:', err.message);
    }

    lockdownState.sessionId = null;
  }

  try {
    const session = spawnTerminal({
      shell: 'bash',
      args: ['-c', 'exec "$0"', lockdownState.command],
      cwd: lockdownState.cwd
    });
    lockdownState.sessionId = session.id;
    process.env.NOTTY_LOCKDOWN_SESSION_ID = String(session.id);
    console.error(`[notty] Lockdown terminal session ready (#${session.id})`);
  } catch (err) {
    console.error('[notty] Failed to start lockdown terminal session:', err);
  }

  return lockdownState.sessionId;
}

logOauthStatus();

try {
  if (MODE === 'stdio') {
    await startStdioServer();
  } else if (MODE === 'sse') {
    await startStandaloneSseServer();
  } else {
    await startNextServer();
  }
} catch (err) {
  console.error(`[notty] Failed to start ${MODE} mode:`, err);
  process.exitCode = 1;
}

async function startStdioServer() {
  console.error('[notty] Starting MCP server in stdio mode');
  try {
    const server = createMcpServer();
    const transport = new StdioServerTransport();
    await server.connect(transport);
    console.error('[notty] Stdio transport connected');
    logSystemState({ mcpTransport: 'stdio' });
  } catch (err) {
    console.error('[notty] Failed to start stdio transport:', err);
    throw err;
  }
}

async function startStandaloneSseServer() {
  const { port, bindHost, publicHost } = resolveServerAddress();
  const trustedHosts = [publicHost, bindHost, process.env.NOTTY_TRUSTED_HOSTS];
  console.error('[notty] Starting MCP server in standalone SSE mode');

  const app = express();
  const allowedOrigin = process.env.ALLOWED_ORIGIN;
  const httpBasicAuthMiddleware = getHttpBasicAuthMiddleware();
  const authMiddleware = getAuthMiddleware({ allowQueryToken: true });
  const tokenHandler = createTokenHandler();
  const jsonParser = express.json({ type: 'application/json', limit: '4mb' });
  const urlencodedParser = express.urlencoded({ extended: false });

  app.use(createCorsMiddleware({
    allowedOrigin,
    allowedHeaders: 'Content-Type, Authorization, Last-Event-ID, MCP-Protocol-Version',
    exposedHeaders: 'X-Session-Id, MCP-Session-Id',
    trustedHosts
  }));

  app.use(httpBasicAuthMiddleware);
  app.post('/oauth/token', urlencodedParser, jsonParser, tokenHandler);

  app.get('/sse', authMiddleware, async (_req, res) => {
    try {
      const { sessionId } = await createSseSession(res, { messagePath: '/message' });
      console.error(`[notty] SSE session established (${sessionId})`);
    } catch (err) {
      console.error('[notty] Failed to establish SSE session:', err);
      if (!res.headersSent) {
        res.status(500).end('Failed to establish SSE session');
      }
    }
  });

  app.post('/message', authMiddleware, jsonParser, async (req, res) => {
    const sessionIdParam = req.query.sessionId;
    const sessionId = Array.isArray(sessionIdParam) ? sessionIdParam[0] : sessionIdParam;

    if (typeof sessionId !== 'string' || sessionId.length === 0) {
      res.status(400).send('Missing sessionId');
      return;
    }

    const { sourceIp, forwardedFor } = getRequestIpInfo(req);
    await withLogContext(
      {
        protocol: 'mcp',
        transport: 'sse',
        source: 'mcpSse',
        route: `${req.method || 'POST'} ${req.path || '/message'}`,
        http_protocol: getHttpProtocol(req),
        source_ip: sourceIp,
        x_forwarded_for: forwardedFor
      },
      async () => {
        await handleSsePost(sessionId, req, res, req.body);
      }
    );
  });

  const listenArgs = bindHost ? [port, bindHost] : [port];
  const server = http.createServer(app);
  await listenHttpServer(server, listenArgs);
  console.error(
    `[notty] SSE server listening on ${buildHttpUrl({ host: publicHost, port, path: '/sse' })}`
  );
  if (bindHost && bindHost !== publicHost) {
    console.error(`[notty] SSE bind host ${bindHost}`);
  }
  logSystemState({ mcpTransport: 'sse', allowedOrigin: allowedOrigin || 'same-origin' });
}

async function startNextServer() {
  const allowedOrigin = process.env.ALLOWED_ORIGIN;
  const dev = process.env.NODE_ENV !== 'production';
  const nextDir = fileURLToPath(new URL('.', import.meta.url));
  const { port, bindHost, publicHost } = resolveServerAddress();
  const trustedHosts = [publicHost, bindHost, process.env.NOTTY_TRUSTED_HOSTS];
  const nextApp = next({ dev, dir: nextDir, hostname: publicHost, port });
  let nextRequestHandler = null;
  let nextUpgradeHandler = null;
  const explicitPublicWsUrl = process.env.NOTTY_PUBLIC_WS_URL;

  const app = express();
  let copilotManager = null;
  let copilotBroker = null;
  const httpBasicAuthMiddleware = getHttpBasicAuthMiddleware();
  app.use(httpBasicAuthMiddleware);

  const readApiCorsMiddleware = createCorsMiddleware({
    allowedOrigin,
    allowedMethods: 'GET,OPTIONS',
    trustedHosts
  });
  app.use('/api/features', readApiCorsMiddleware);
  app.use('/api/lockdown', readApiCorsMiddleware);
  app.use('/api/ws', readApiCorsMiddleware);

  ensureLockdownSession();
  registerTerminalHttpRoutes(app, {
    allowedOrigin,
    trustedHosts,
    lockdown: lockdownState.enabled
  });
  registerAgentHttpRoutes(app, {
    allowedOrigin,
    trustedHosts,
    lockdown: lockdownState.enabled
  });
  copilotBroker = await startCopilotMcpBroker({
    getOperations: () => copilotManager
  });
  copilotManager = createCopilotManager({
    workspaceRoot: TERMINAL_WORKDIR,
    brokerUrlResolver: (bindingId, role, runtime, accessToken) => (
      copilotBroker.urlFor(bindingId, role, runtime, accessToken)
    )
  });
  registerCopilotHttpRoutes(app, {
    allowedOrigin,
    trustedHosts,
    lockdown: lockdownState.enabled,
    operations: copilotManager
  });
  let collabSupervisor = null;

  app.get('/api/features', (_req, res) => {
    res.setHeader('Cache-Control', 'no-store');
    res.json({
      collab: RUNTIME_CONFIG.switches.collab,
      sources: { collab: RUNTIME_CONFIG.sources.collab }
    });
  });

  app.get('/api/lockdown', (_req, res) => {
    const sessionId = ensureLockdownSession();
    res.setHeader('Cache-Control', 'no-store');
    res.json({ lockdown: lockdownState.enabled, sessionId });
  });

  app.use('/oauth', createCorsMiddleware({
    allowedOrigin,
    allowedMethods: 'POST,OPTIONS',
    trustedHosts
  }));

  const mcpRouter = express.Router();
  const authMiddleware = getAuthMiddleware({ allowQueryToken: true });
  const tokenHandler = createTokenHandler();
  const urlencodedParser = express.urlencoded({ extended: false });
  mcpRouter.use(createCorsMiddleware({
    allowedOrigin,
    allowedHeaders: 'Content-Type, Authorization, X-Session-Id, MCP-Session-Id, MCP-Protocol-Version, Last-Event-ID',
    allowedMethods: 'GET,POST,DELETE,OPTIONS',
    exposedHeaders: 'X-Session-Id, MCP-Session-Id',
    trustedHosts
  }));

  app.post('/oauth/token', urlencodedParser, express.json(), tokenHandler);
  mcpRouter.use(authMiddleware);

  mcpRouter.get('/tools', (req, res) => {
    const { toolDefinitions } = getMcpToolset();
    const { sourceIp, forwardedFor } = getRequestIpInfo(req);
    withLogContext(
      {
        protocol: 'mcp',
        transport: 'http',
        source: 'mcpRouter',
        route: 'GET /mcp/tools',
        http_protocol: getHttpProtocol(req),
        source_ip: sourceIp,
        x_forwarded_for: forwardedFor
      },
      () => {
        logTerminalEvent({
          op: 'listTools',
          count: toolDefinitions.length
        });
        res.json({ tools: toolDefinitions });
      }
    );
  });

  mcpRouter.post('/call', express.json(), createMcpHttpCallHandler({
    getMcpToolset,
    getHttpProtocol,
    getRequestIpInfo,
    withLogContext
  }));

  mcpRouter.get('/sessions', (_req, res) => {
    const sessions = getActiveSessions();
    res.json({ sessions, count: sessions.length });
  });

  mcpRouter.delete('/sessions/:sessionId', (req, res) => {
    const { sessionId } = req.params;
    if (!sessionId) {
      res.status(400).json({ error: 'sessionId is required' });
      return;
    }

    const success = cleanupSession(sessionId);
    if (success) {
      res.json({ message: 'Session cleaned up', sessionId });
    } else {
      res.status(404).json({ error: 'Session not found', sessionId });
    }
  });

  const enableSse = (process.env.MCP_TRANSPORT || '').toLowerCase() === 'sse';
  if (enableSse) {
    const messagePath = '/message';
    const jsonParser = express.json({ type: 'application/json', limit: '4mb' });

    const handleSseConnection = async (req, res) => {
      try {
        const resolvedMessagePath = `${req.baseUrl || ''}${messagePath}`;
        const { sessionId } = await createSseSession(res, { messagePath: resolvedMessagePath });
        console.error(
          `[mcp-http] SSE transport connected (${sessionId}) -> ${resolvedMessagePath}`
        );
      } catch (err) {
        console.error('[mcp-http] Failed to establish SSE session:', err);
        if (!res.headersSent) {
          res.status(500).end('Failed to establish SSE session');
        }
      }
    };

    const handleSseMessage = async (req, res) => {
      const sessionIdParam = req.query.sessionId;
      const sessionId = Array.isArray(sessionIdParam) ? sessionIdParam[0] : sessionIdParam;

      if (typeof sessionId !== 'string' || sessionId.length === 0) {
        res.status(400).send('Missing sessionId');
        return;
      }

      const { sourceIp, forwardedFor } = getRequestIpInfo(req);
      await withLogContext(
        {
          protocol: 'mcp',
          transport: 'sse',
          source: 'mcpSse',
          route: `${req.method || 'POST'} ${req.path || messagePath}`,
          http_protocol: getHttpProtocol(req),
          source_ip: sourceIp,
          x_forwarded_for: forwardedFor
        },
        async () => {
          await handleSsePost(sessionId, req, res, req.body);
        }
      );
    };

    const legacySseCorsMiddleware = createCorsMiddleware({
      allowedOrigin,
      allowedHeaders: 'Content-Type, Authorization, Last-Event-ID, MCP-Protocol-Version',
      exposedHeaders: 'X-Session-Id, MCP-Session-Id',
      trustedHosts
    });
    app.use('/sse', legacySseCorsMiddleware);
    app.use(messagePath, legacySseCorsMiddleware);
    app.get('/sse', authMiddleware, handleSseConnection);
    app.post(messagePath, authMiddleware, jsonParser, handleSseMessage);

    mcpRouter.get('/sse', authMiddleware, handleSseConnection);
    mcpRouter.post('/message', authMiddleware, jsonParser, handleSseMessage);
  }

  mcpRouter.all('/', async (req, res) => {
    const { sourceIp, forwardedFor } = getRequestIpInfo(req);
    await withLogContext(
      {
        protocol: 'mcp',
        transport: 'http',
        source: 'mcpRouter',
        route: `${req.method || 'REQUEST'} /mcp`,
        http_protocol: getHttpProtocol(req),
        source_ip: sourceIp,
        x_forwarded_for: forwardedFor
      },
      async () => {
        try {
          const { transport, sessionId } = await getServerForRequest(req);
          res.setHeader('X-Session-Id', sessionId);
          await transport.handleRequest(req, res);
        } catch (err) {
          console.error('[mcp-http] request error:', err);
          if (!res.headersSent) {
            res.statusCode = 500;
            res.setHeader('Content-Type', 'application/json');
            res.end(
              JSON.stringify({
                jsonrpc: '2.0',
                error: {
                  code: -32603,
                  message: err?.message || 'Internal error'
                },
                id: null
              })
            );
          }
        }
      }
    );
  });

  app.use('/mcp', mcpRouter);

  const server = http.createServer(app);
  let removeSignalHandlers = () => {};
  let runtimeCleanupPromise = null;
  const cleanupRuntime = () => {
    if (!runtimeCleanupPromise) {
      runtimeCleanupPromise = (async () => {
        const failures = [];
        try {
          await collabSupervisor?.stop();
        } catch (error) {
          failures.push(error);
        }
        try {
          copilotManager?.dispose();
        } catch (error) {
          failures.push(error);
        }
        for (const terminal of listTerminals()) {
          if (!terminal.alive) {
            continue;
          }
          try {
            killTerminal(terminal.terminal_uuid);
          } catch (error) {
            failures.push(error);
          }
        }
        try {
          await copilotBroker?.close();
        } catch (error) {
          failures.push(error);
        }
        if (typeof nextApp.close === 'function') {
          try {
            await nextApp.close();
          } catch (error) {
            failures.push(error);
          }
        }
        if (failures.length) {
          throw new AggregateError(failures, 'Notty runtime cleanup failed');
        }
      })();
    }
    return runtimeCleanupPromise;
  };
  server.once('close', () => {
    removeSignalHandlers();
    cleanupRuntime().catch((error) => {
      console.error('[notty] Runtime cleanup failed:', error);
    });
  });

  const wsPath = '/ws/terminals';
  const defaultPublicWsUrl = buildWsUrl({ host: publicHost, port, path: wsPath });
  const advertisedWsUrl = explicitPublicWsUrl || defaultPublicWsUrl;

  const wss = new WebSocketServer({ noServer: true });
  const wsState = registerExternalWsServer({
    wss,
    port,
    path: wsPath,
    host: publicHost,
    url: advertisedWsUrl
  });

  server.on('upgrade', (request, socket, head) => {
    const { pathname } = new URL(request.url, 'http://localhost');
    if (pathname === wsPath) {
      const originDecision = resolveOriginPolicy({
        origin: request.headers.origin,
        host: request.headers.host,
        protocol: request.socket.encrypted ? 'https' : 'http',
        allowedOrigin,
        fetchSite: request.headers['sec-fetch-site'],
        trustedHosts
      });
      if (!originDecision.allowed) {
        socket.end(
          'HTTP/1.1 403 Forbidden\r\n'
            + 'Content-Type: text/plain; charset=utf-8\r\n'
            + 'Connection: close\r\n\r\n'
            + 'Cross-origin WebSocket connections are not allowed'
        );
        return;
      }

      const authResult = validateHttpBasicAuthRequest(request);
      if (!authResult.ok) {
        if (authResult.code === 'misconfigured') {
          socket.end(
            'HTTP/1.1 503 Service Unavailable\r\n'
              + 'Content-Type: text/plain; charset=utf-8\r\n\r\n'
              + 'HTTP basic auth is enabled but not configured'
          );
        } else {
          writeHttpBasicAuthChallenge(socket, { socket: true });
        }
        return;
      }

      wss.handleUpgrade(request, socket, head, (ws) => {
        wss.emit('connection', ws, request);
      });
      return;
    }

    if (nextUpgradeHandler) {
      nextUpgradeHandler(request, socket, head);
      return;
    }

    socket.destroy();
  });

  try {
    await nextApp.prepare();
  } catch (err) {
    await cleanupRuntime().catch((cleanupError) => {
      console.error('[notty] Failed to clean up after prepare error:', cleanupError);
    });
    throw err;
  }

  nextRequestHandler = nextApp.getRequestHandler();
  nextUpgradeHandler =
    typeof nextApp.getUpgradeHandler === 'function'
      ? nextApp.getUpgradeHandler()
      : null;

  collabSupervisor = RUNTIME_CONFIG.switches.collab
    ? registerCollabHttpRoutes(app, {
        appRoot: APP_WORKDIR,
        workspaceRoot: TERMINAL_WORKDIR,
        allowedOrigin,
        trustedHosts,
        lockdown: lockdownState.enabled
      })
    : null;

  app.get('/api/ws', (req, res) => {
    const headerHost =
      req.headers['x-forwarded-host'] || req.headers.host || `${wsState.host}:${port}`;
    const protocolHeader = req.headers['x-forwarded-proto'] || req.protocol;
    const secure = protocolHeader === 'https';
    const scheme = secure ? 'wss' : 'ws';
    const defaultUrl = `${scheme}://${headerHost}${wsPath}`;
    const url = explicitPublicWsUrl || defaultUrl;

    res.setHeader('Cache-Control', 'no-store');
    res.json({
      ready: true,
      url,
      host: wsState.host,
      port,
      path: wsPath,
      sessionId: lockdownState.enabled ? ensureLockdownSession() : undefined
    });
  });

  app.all('*', (req, res) => {
    return nextRequestHandler(req, res);
  });

  const listenArgs = bindHost ? [port, bindHost] : [port];
  try {
    await listenHttpServer(server, listenArgs);
  } catch (err) {
    await cleanupRuntime().catch((cleanupError) => {
      console.error('[notty] Failed to clean up after listen error:', cleanupError);
    });
    throw err;
  }

  let signalShutdownPromise = null;
  const shutdownFromSignal = (signal) => {
    if (!signalShutdownPromise) {
      signalShutdownPromise = (async () => {
        console.error(`[notty] Received ${signal}; shutting down`);
        removeSignalHandlers();
        const cleanupPromise = cleanupRuntime();
        for (const client of wss.clients) {
          client.terminate();
        }
        if (server.listening) {
          await new Promise((resolve, reject) => {
            const forceTimer = setTimeout(() => {
              server.closeAllConnections?.();
            }, 5000);
            forceTimer.unref?.();
            server.close((error) => {
              clearTimeout(forceTimer);
              if (error) {
                reject(error);
              } else {
                resolve();
              }
            });
            server.closeIdleConnections?.();
          });
        }
        await cleanupPromise;
      })().catch((error) => {
        process.exitCode = 1;
        console.error(`[notty] Failed to shut down after ${signal}:`, error);
      });
    }
    return signalShutdownPromise;
  };
  const onSigint = () => {
    void shutdownFromSignal('SIGINT');
  };
  const onSigterm = () => {
    void shutdownFromSignal('SIGTERM');
  };
  process.once('SIGINT', onSigint);
  process.once('SIGTERM', onSigterm);
  removeSignalHandlers = () => {
    process.off('SIGINT', onSigint);
    process.off('SIGTERM', onSigterm);
  };

  const publicHttpUrl = buildHttpUrl({ host: publicHost, port });

  console.error(`[notty] listening on ${publicHttpUrl}`);
  if (bindHost && bindHost !== publicHost) {
    console.error(`[notty] bind host ${bindHost}`);
  }
  console.error(`[notty] websocket upgrade path ${wsPath}`);
  console.error(`[notty] websocket public url ${advertisedWsUrl}`);
  console.error(`[notty] MCP endpoint ${buildHttpUrl({ host: publicHost, port, path: '/mcp' })}`);
  if (enableSse) {
    console.error(`[notty] MCP SSE endpoint ${buildHttpUrl({ host: publicHost, port, path: '/sse' })}`);
    console.error(`[notty] MCP SSE alias ${buildHttpUrl({ host: publicHost, port, path: '/mcp/sse' })}`);
    console.error(
      `[notty] MCP SSE message endpoint ${buildHttpUrl({ host: publicHost, port, path: '/message' })}`
    );
    console.error(
      `[notty] MCP SSE alias message endpoint ${buildHttpUrl({ host: publicHost, port, path: '/mcp/message' })}`
    );
  }
  logSystemState({
    mcpTransport: enableSse ? 'http+sse' : 'http',
    allowedOrigin: allowedOrigin || 'same-origin',
    publicWsUrl: advertisedWsUrl,
    showWsUrl: true
  });
}
