import fs from 'node:fs/promises';
import http from 'node:http';
import https from 'node:https';
import net from 'node:net';

import { PrincipalStore, normalizeFingerprint } from './principals.js';
import {
  canonicalProxyHeaders,
  normalizeGatewayPublicOrigin,
  validatePublicRequestHeaders,
} from './proxy-contract.js';

const RESPONSE_HOP_BY_HOP_HEADERS = new Set([
  'connection',
  'keep-alive',
  'proxy-authenticate',
  'proxy-authorization',
  'te',
  'trailer',
  'transfer-encoding',
  'upgrade',
]);

const DEFAULT_SESSION_REVALIDATE_MS = 5_000;
const MIN_SESSION_REVALIDATE_MS = 100;
const MAX_SESSION_REVALIDATE_MS = 5_000;
const MAX_TIMER_DELAY_MS = 2_147_000_000;

function allowedPath(pathname, prefixes) {
  return prefixes.some(
    (prefix) => pathname === prefix || pathname.startsWith(`${prefix}/`),
  );
}

function normalizeSessionRevalidateMs(value) {
  const interval = value ?? DEFAULT_SESSION_REVALIDATE_MS;
  if (
    !Number.isSafeInteger(interval) ||
    interval < MIN_SESSION_REVALIDATE_MS ||
    interval > MAX_SESSION_REVALIDATE_MS
  ) {
    throw new TypeError(
      `gateway session revalidation interval must be an integer from ${
        MIN_SESSION_REVALIDATE_MS
      } to ${MAX_SESSION_REVALIDATE_MS} milliseconds`,
    );
  }
  return interval;
}

function sessionAuthorizationError(code, message) {
  const error = new Error(message);
  error.code = code;
  return error;
}

function principalAuthorizationIdentity(principal) {
  return JSON.stringify({
    id: principal.id,
    certificateFingerprint: normalizeFingerprint(
      principal.certificateFingerprint,
    ),
    runId: principal.runId || null,
    agentId: principal.agentId || null,
    expiresAt: principal.expiresAt,
    allowedPrefixes: principal.allowedPrefixes,
    createdAt: principal.createdAt || null,
  });
}

async function revalidateGatewaySession(options) {
  const now = (options.now || Date.now)();
  const expiresAt = new Date(options.principal.expiresAt).getTime();
  if (!Number.isFinite(expiresAt) || expiresAt <= now) {
    throw sessionAuthorizationError(
      'GUARD_GATEWAY_PRINCIPAL_EXPIRED',
      'gateway principal expired',
    );
  }
  const fingerprint = normalizeFingerprint(
    options.principal.certificateFingerprint,
  );
  const currentPrincipal =
    await options.principalStore.findByFingerprint(fingerprint);
  if (
    !currentPrincipal ||
    principalAuthorizationIdentity(currentPrincipal) !==
      principalAuthorizationIdentity(options.principal) ||
    !allowedPath(options.pathname, currentPrincipal.allowedPrefixes)
  ) {
    throw sessionAuthorizationError(
      'GUARD_GATEWAY_PRINCIPAL_REVOKED',
      'gateway principal was revoked or changed',
    );
  }
  const currentRun = await resolveRun(currentPrincipal, options.service);
  if (
    !currentRun ||
    currentRun.runId !== options.run.runId ||
    currentRun.status !== 'running' ||
    !currentRun.containerId ||
    currentRun.containerId !== options.run.containerId ||
    (options.principal.agentId &&
      currentRun.agentId !== options.principal.agentId)
  ) {
    throw sessionAuthorizationError(
      'GUARD_GATEWAY_RUN_UNAVAILABLE',
      'gateway session runner is no longer running',
    );
  }
  return { principal: currentPrincipal, run: currentRun };
}

function createGatewaySessionMonitor(options) {
  const revalidateMs = normalizeSessionRevalidateMs(options.revalidateMs);
  const expiresAt = new Date(options.principal.expiresAt).getTime();
  if (!Number.isFinite(expiresAt)) {
    throw new TypeError('gateway principal expiry is invalid');
  }
  if (typeof options.terminate !== 'function') {
    throw new TypeError('gateway session terminate callback is required');
  }
  const scheduler = options.scheduler || globalThis;
  const now = options.now || Date.now;
  let intervalHandle = null;
  let expiryHandle = null;
  let checking = false;
  let stopped = false;
  let terminationError = null;

  const stop = () => {
    if (stopped) {
      return;
    }
    stopped = true;
    if (intervalHandle !== null) {
      scheduler.clearInterval(intervalHandle);
      intervalHandle = null;
    }
    if (expiryHandle !== null) {
      scheduler.clearTimeout(expiryHandle);
      expiryHandle = null;
    }
  };
  const terminate = (error) => {
    if (stopped) {
      return;
    }
    terminationError = error;
    stop();
    try {
      options.terminate(error);
    } catch {
      // Authorization teardown is fail-closed even if a stream already closed.
    }
  };
  const check = async () => {
    if (stopped || checking) {
      return !terminationError;
    }
    checking = true;
    try {
      await revalidateGatewaySession({
        ...options,
        now,
      });
      return true;
    } catch (error) {
      terminate(error);
      return false;
    } finally {
      checking = false;
    }
  };
  const armExpiry = () => {
    if (stopped) {
      return;
    }
    const remaining = expiresAt - now();
    if (remaining <= 0) {
      terminate(
        sessionAuthorizationError(
          'GUARD_GATEWAY_PRINCIPAL_EXPIRED',
          'gateway principal expired',
        ),
      );
      return;
    }
    expiryHandle = scheduler.setTimeout(
      armExpiry,
      Math.min(remaining, MAX_TIMER_DELAY_MS),
    );
    expiryHandle?.unref?.();
  };

  intervalHandle = scheduler.setInterval(() => void check(), revalidateMs);
  intervalHandle?.unref?.();
  armExpiry();
  return {
    check,
    stop,
    revalidateMs,
    get stopped() {
      return stopped;
    },
    get terminationError() {
      return terminationError;
    },
  };
}

function runnerProxySocket(service) {
  const socketPath = service?.egress?.controlSocketPath;
  if (typeof socketPath !== 'string' || !socketPath) {
    throw new Error('managed runner proxy socket is unavailable');
  }
  return socketPath;
}

function proxyHeaders(headers, principal, run, publicOrigin, gatewayToken = null) {
  return canonicalProxyHeaders(headers, publicOrigin, {
    'x-nosh-guard-principal': principal.id,
    'x-nosh-guard-agent': principal.agentId || '',
    'x-nosh-guard-upstream-run': run.runId,
    ...(gatewayToken
      ? { 'x-nosh-guard-gateway-token': gatewayToken }
      : {}),
  });
}

function validateGatewayRequest(request, publicOrigin) {
  let contract;
  try {
    ({ contract } = validatePublicRequestHeaders(request.headers, publicOrigin));
  } catch (error) {
    error.statusCode = 403;
    throw error;
  }
  if (
    typeof request.url !== 'string' ||
    !request.url.startsWith('/') ||
    request.url.startsWith('//') ||
    /[\\\u0000-\u001f\u007f]/.test(request.url)
  ) {
    const error = new Error('gateway requires a canonical origin-form request target');
    error.statusCode = 400;
    throw error;
  }
  return new URL(request.url, contract.origin);
}

async function authenticate(request, principalStore) {
  if (!request.socket.authorized) {
    const error = new Error(
      request.socket.authorizationError || 'client certificate is not authorized',
    );
    error.statusCode = 401;
    throw error;
  }
  const certificate = request.socket.getPeerCertificate();
  if (!certificate?.fingerprint256) {
    const error = new Error('client certificate fingerprint is unavailable');
    error.statusCode = 401;
    throw error;
  }
  const principal = await principalStore.findByFingerprint(
    normalizeFingerprint(certificate.fingerprint256),
  );
  if (!principal) {
    const error = new Error('client certificate is not assigned to a live principal');
    error.statusCode = 403;
    throw error;
  }
  return principal;
}

async function resolveRun(principal, service) {
  let run = null;
  if (principal.runId) {
    run = await service.store.findRun(principal.runId);
  } else {
    const runs = await service.store.listRuns();
    const matches = runs.filter(
      (entry) => entry.agentId === principal.agentId && entry.status === 'running',
    );
    if (matches.length > 1) {
      const error = new Error(
        'principal matches multiple live runners; bind it to an exact runId',
      );
      error.statusCode = 409;
      throw error;
    }
    [run] = matches;
  }
  if (!run || run.status !== 'running' || !run.containerId) {
    const error = new Error('assigned runner is not running');
    error.statusCode = 503;
    throw error;
  }
  return run;
}

function sendError(response, error) {
  const body = Buffer.from(
    `${JSON.stringify({
      error: {
        code: error.statusCode === 403 ? 'GUARD_FORBIDDEN' : 'GUARD_GATEWAY_ERROR',
        message: error.message,
      },
    })}\n`,
    'utf8',
  );
  response.writeHead(error.statusCode || 502, {
    'content-type': 'application/json',
    'content-length': body.length,
    'cache-control': 'no-store',
  });
  response.end(body);
}

async function proxyHttp(
  request,
  response,
  principalStore,
  service,
  publicOrigin,
  sessionOptions = {},
) {
  let monitor = null;
  let proxy = null;
  let upstreamResponse = null;
  try {
    const principal = await authenticate(request, principalStore);
    const url = validateGatewayRequest(request, publicOrigin);
    if (!allowedPath(url.pathname, principal.allowedPrefixes)) {
      const error = new Error(`gateway path is not allowed: ${url.pathname}`);
      error.statusCode = 403;
      throw error;
    }
    const run = await resolveRun(principal, service);
    if (request.method === 'POST' && url.pathname === '/api/spawn-otps'
      && (!principal.runId || principal.agentId)) {
      const error = new Error('only a run-bound operator principal may mint spawn OTPs');
      error.statusCode = 403;
      throw error;
    }
    const gatewayToken = service.guardGatewayToken?.(run.runId) || null;
    if (!gatewayToken) {
      const error = new Error('runner gateway authentication capability is unavailable');
      error.statusCode = 503;
      throw error;
    }
    const socketPath = runnerProxySocket(service);
    proxy = http.request(
      {
        socketPath,
        method: request.method,
        path: request.url,
        headers: proxyHeaders(
          request.headers,
          principal,
          run,
          publicOrigin,
          gatewayToken,
        ),
      },
      (incoming) => {
        upstreamResponse = incoming;
        const headers = {};
        for (const [name, value] of Object.entries(incoming.headers)) {
          if (
            !RESPONSE_HOP_BY_HOP_HEADERS.has(name.toLowerCase()) &&
            value != null
          ) {
            headers[name] = value;
          }
        }
        response.writeHead(incoming.statusCode || 502, headers);
        incoming.once('end', () => monitor?.stop());
        incoming.once('aborted', () => monitor?.stop());
        incoming.pipe(response);
      },
    );
    monitor = createGatewaySessionMonitor({
      principal,
      run,
      pathname: url.pathname,
      principalStore,
      service,
      revalidateMs: sessionOptions.revalidateMs,
      terminate() {
        upstreamResponse?.destroy();
        proxy?.destroy();
        response.destroy();
      },
    });
    response.once('close', () => monitor?.stop());
    request.once('aborted', () => monitor?.stop());
    proxy.on('error', (error) => {
      monitor?.stop();
      if (response.headersSent || response.destroyed) {
        response.destroy(error);
      } else {
        sendError(response, error);
      }
    });
    request.pipe(proxy);
  } catch (error) {
    monitor?.stop();
    upstreamResponse?.destroy();
    proxy?.destroy();
    if (!response.headersSent && !response.destroyed) {
      sendError(response, error);
    } else {
      response.destroy(error);
    }
  }
}

async function proxyUpgrade(
  request,
  clientSocket,
  head,
  principalStore,
  service,
  publicOrigin,
  sessionOptions = {},
) {
  let monitor = null;
  let upstreamSocket = null;
  try {
    const principal = await authenticate(request, principalStore);
    const url = validateGatewayRequest(request, publicOrigin);
    if (!allowedPath(url.pathname, principal.allowedPrefixes)) {
      const error = new Error(`gateway path is not allowed: ${url.pathname}`);
      error.statusCode = 403;
      throw error;
    }
    const requestedUpgrade = request.headers.upgrade;
    if (
      typeof requestedUpgrade !== 'string' ||
      requestedUpgrade.toLowerCase() !== 'websocket'
    ) {
      const error = new Error('only WebSocket upgrades are allowed');
      error.statusCode = 400;
      throw error;
    }
    const run = await resolveRun(principal, service);
    const gatewayToken = service.guardGatewayToken?.(run.runId) || null;
    if (!gatewayToken) {
      const error = new Error('runner gateway authentication capability is unavailable');
      error.statusCode = 503;
      throw error;
    }
    const socketPath = runnerProxySocket(service);
    upstreamSocket = net.connect({ path: socketPath }, () => {
      const headers = proxyHeaders(
        request.headers,
        principal,
        run,
        publicOrigin,
        gatewayToken,
      );
      headers.connection = 'Upgrade';
      headers.upgrade = 'websocket';
      const headerLines = Object.entries(headers).flatMap(([name, value]) => {
        const values = Array.isArray(value) ? value : [value];
        return values.map((entry) => `${name}: ${entry}`);
      });
      upstreamSocket.write(
        `${request.method} ${request.url} HTTP/${request.httpVersion}\r\n${headerLines.join(
          '\r\n',
        )}\r\n\r\n`,
      );
      if (head?.length) {
        upstreamSocket.write(head);
      }
      clientSocket.pipe(upstreamSocket).pipe(clientSocket);
    });
    monitor = createGatewaySessionMonitor({
      principal,
      run,
      pathname: url.pathname,
      principalStore,
      service,
      revalidateMs: sessionOptions.revalidateMs,
      terminate() {
        upstreamSocket?.destroy();
        clientSocket.destroy();
      },
    });
    clientSocket.once('close', () => monitor?.stop());
    upstreamSocket.once('close', () => monitor?.stop());
    upstreamSocket.on('error', () => {
      monitor?.stop();
      clientSocket.destroy();
    });
  } catch {
    monitor?.stop();
    upstreamSocket?.destroy();
    clientSocket.end('HTTP/1.1 403 Forbidden\r\nConnection: close\r\n\r\n');
  }
}

export async function listenGuardGateway(options) {
  const publicOrigin = normalizeGatewayPublicOrigin(options.publicOrigin);
  const sessionRevalidateMs = normalizeSessionRevalidateMs(
    options.sessionRevalidateMs,
  );
  const [key, cert, ca] = await Promise.all([
    fs.readFile(options.keyPath),
    fs.readFile(options.certPath),
    fs.readFile(options.caPath),
  ]);
  const principalStore =
    options.principalStore ||
    new PrincipalStore({ stateDir: options.stateDir });
  await principalStore.initialize();
  const server = https.createServer(
    {
      key,
      cert,
      ca,
      minVersion: 'TLSv1.3',
      requestCert: true,
      rejectUnauthorized: true,
    },
    (request, response) =>
      proxyHttp(
        request,
        response,
        principalStore,
        options.service,
        publicOrigin,
        { revalidateMs: sessionRevalidateMs },
      ),
  );
  server.on('upgrade', (request, socket, head) =>
    proxyUpgrade(
      request,
      socket,
      head,
      principalStore,
      options.service,
      publicOrigin,
      { revalidateMs: sessionRevalidateMs },
    ),
  );
  await new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(options.port || 3443, options.host || '127.0.0.1', resolve);
  });
  return { server, principalStore, publicOrigin, sessionRevalidateMs };
}

export {
  allowedPath,
  createGatewaySessionMonitor,
  normalizeSessionRevalidateMs,
  proxyHttp,
  proxyHeaders,
  proxyUpgrade,
  revalidateGatewaySession,
  resolveRun,
  runnerProxySocket,
  validateGatewayRequest,
};
