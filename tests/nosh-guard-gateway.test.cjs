'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const http = require('node:http');
const net = require('node:net');
const os = require('node:os');
const path = require('node:path');
const test = require('node:test');
const { pathToFileURL } = require('node:url');

const appRoot = path.resolve(__dirname, '..');

async function importModule(relativePath) {
  return import(pathToFileURL(path.join(appRoot, relativePath)).href);
}

function tempDir(t) {
  const directory = fs.mkdtempSync(
    path.join(os.tmpdir(), 'nosh-guard-gateway-test-'),
  );
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  return directory;
}

function listen(server, ...args) {
  return new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(...args, () => {
      server.off('error', reject);
      resolve(server.address());
    });
  });
}

function closeServer(server) {
  return new Promise((resolve) => {
    if (!server.listening) {
      resolve();
      return;
    }
    server.close(() => resolve());
  });
}

function withTimeout(promise, timeoutMs, label) {
  let timer;
  return Promise.race([
    promise,
    new Promise((_, reject) => {
      timer = setTimeout(
        () => reject(new Error(`${label} timed out after ${timeoutMs}ms`)),
        timeoutMs,
      );
    }),
  ]).finally(() => clearTimeout(timer));
}

function livePrincipal(overrides = {}) {
  return {
    id: 'principal-live',
    certificateFingerprint: 'AA'.repeat(32),
    runId: 'run-live',
    agentId: null,
    expiresAt: new Date(Date.now() + 60_000).toISOString(),
    allowedPrefixes: ['/sse', '/ws/terminals'],
    createdAt: '2026-07-25T00:00:00.000Z',
    ...overrides,
  };
}

test('guard gateway accepts only a canonical HTTPS public origin', async () => {
  const { normalizeGatewayPublicOrigin } = await importModule(
    'lib/guardd/proxy-contract.js',
  );

  assert.deepEqual(
    { ...normalizeGatewayPublicOrigin('https://guard.example:3443') },
    {
      origin: 'https://guard.example:3443',
      protocol: 'https',
      host: 'guard.example:3443',
      hostname: 'guard.example',
      port: '3443',
      websocketOrigin: 'wss://guard.example:3443',
    },
  );
  for (const invalid of [
    '',
    'http://guard.example:3443',
    'https://user@guard.example',
    'https://guard.example/ui',
    'https://guard.example?mode=unsafe',
    'https://guard.example#fragment',
  ]) {
    assert.throws(
      () => normalizeGatewayPublicOrigin(invalid),
      /gateway public origin|HTTPS origin/,
    );
  }
});

test('TLS gateway strips spoofed proxy controls and injects canonical values', async () => {
  const { proxyHeaders } = await importModule('lib/guardd/gateway.js');
  const headers = proxyHeaders(
    {
      host: 'guard.example:3443',
      origin: 'https://guard.example:3443',
      authorization: 'Bearer runner-token',
      connection: 'keep-alive, x-remove-me',
      'x-remove-me': 'smuggled',
      forwarded: 'for=attacker;proto=http',
      'x-forwarded-for': '203.0.113.5',
      'x-forwarded-host': 'attacker.example',
      'x-forwarded-proto': 'http',
      'x-real-ip': '203.0.113.5',
      'x-middleware-subrequest': 'middleware:middleware',
      'x-original-url': '/admin',
      'x-nosh-guard-principal': 'spoofed',
      'x-nosh-guard-upstream-run': 'spoofed-run',
      'sec-fetch-site': 'cross-site',
    },
    { id: 'reviewed-principal', agentId: 'coding-agent' },
    { runId: 'run-exact' },
    'https://guard.example:3443',
  );

  assert.equal(headers.host, 'guard.example:3443');
  assert.equal(headers.origin, 'https://guard.example:3443');
  assert.equal(headers['x-forwarded-host'], 'guard.example:3443');
  assert.equal(headers['x-forwarded-proto'], 'https');
  assert.equal(headers['x-forwarded-port'], '3443');
  assert.equal(headers['sec-fetch-site'], 'same-origin');
  assert.equal(headers.authorization, 'Bearer runner-token');
  assert.equal(headers['x-nosh-guard-principal'], 'reviewed-principal');
  assert.equal(headers['x-nosh-guard-agent'], 'coding-agent');
  assert.equal(headers['x-nosh-guard-upstream-run'], 'run-exact');
  for (const stripped of [
    'connection',
    'forwarded',
    'x-forwarded-for',
    'x-middleware-subrequest',
    'x-original-url',
    'x-real-ip',
    'x-remove-me',
  ]) {
    assert.equal(headers[stripped], undefined);
  }
});

test('both proxy hops enforce Host, Origin, and exact run-owned forwarding', async () => {
  const {
    validatePublicRequestHeaders,
  } = await importModule('lib/guardd/proxy-contract.js');
  const { proxyHeaders, validateGatewayRequest } = await importModule(
    'lib/guardd/gateway.js',
  );
  const { runnerProxyHeaders } = await importModule(
    'scripts/nosh-guard-egress-gateway.mjs',
  );
  const publicOrigin = 'https://guard.example:3443';
  const request = {
    url: '/api/terminals?view=active',
    headers: {
      host: 'guard.example:3443',
      origin: publicOrigin,
    },
  };
  const parsed = validateGatewayRequest(request, publicOrigin);
  assert.equal(parsed.pathname, '/api/terminals');

  const outer = proxyHeaders(
    request.headers,
    { id: 'principal-one', agentId: 'agent-one' },
    { runId: 'run-one' },
    publicOrigin,
  );
  validatePublicRequestHeaders(outer, publicOrigin, {
    requireForwarded: true,
  });
  const inner = runnerProxyHeaders(outer, {
    runId: 'run-one',
    publicOrigin,
  });
  assert.equal(inner['x-nosh-guard-upstream-run'], undefined);
  assert.equal(inner['x-nosh-guard-principal'], 'principal-one');

  for (const badHeaders of [
    { ...request.headers, host: 'attacker.example' },
    { ...request.headers, origin: 'https://attacker.example' },
    { ...request.headers, 'sec-fetch-site': 'cross-site' },
    {
      host: 'guard.example:3443',
      'sec-fetch-site': 'cross-site',
    },
  ]) {
    assert.throws(
      () => validateGatewayRequest({ ...request, headers: badHeaders }, publicOrigin),
      /does not match/,
    );
  }
  assert.throws(
    () =>
      validateGatewayRequest(
        { ...request, url: 'https://attacker.example/api/terminals' },
        publicOrigin,
      ),
    /origin-form/,
  );
  assert.throws(
    () =>
      validatePublicRequestHeaders(
        { ...outer, 'x-forwarded-proto': 'http' },
        publicOrigin,
        { requireForwarded: true },
    ),
    /forwarded protocol/,
  );
  assert.throws(
    () =>
      runnerProxyHeaders(outer, {
        runId: 'different-run',
        publicOrigin,
      }),
    /not bound to the selected run/,
  );
});

test('WebSocket handshake metadata survives both guarded proxy hops', async () => {
  const { validatePublicRequestHeaders } = await importModule(
    'lib/guardd/proxy-contract.js',
  );
  const { proxyHeaders } = await importModule('lib/guardd/gateway.js');
  const { runnerProxyHeaders } = await importModule(
    'scripts/nosh-guard-egress-gateway.mjs',
  );
  const publicOrigin = 'https://guard.example:3443';
  const outer = proxyHeaders(
    {
      host: 'guard.example:3443',
      origin: publicOrigin,
      connection: 'Upgrade',
      upgrade: 'websocket',
      'sec-websocket-key': 'dGhlIHNhbXBsZSBub25jZQ==',
      'sec-websocket-version': '13',
      'sec-websocket-protocol': 'notty.v1',
    },
    { id: 'principal-one', agentId: 'agent-one' },
    { runId: 'run-one' },
    publicOrigin,
  );
  outer.connection = 'Upgrade';
  outer.upgrade = 'websocket';

  validatePublicRequestHeaders(outer, publicOrigin, {
    requireForwarded: true,
  });
  const inner = runnerProxyHeaders(outer, {
    runId: 'run-one',
    publicOrigin,
  });
  inner.connection = 'Upgrade';
  inner.upgrade = 'websocket';

  assert.equal(inner.host, 'guard.example:3443');
  assert.equal(inner.origin, publicOrigin);
  assert.equal(inner.connection, 'Upgrade');
  assert.equal(inner.upgrade, 'websocket');
  assert.equal(inner['sec-websocket-key'], 'dGhlIHNhbXBsZSBub25jZQ==');
  assert.equal(inner['sec-websocket-version'], '13');
  assert.equal(inner['sec-websocket-protocol'], 'notty.v1');
});

test('runner public environment advertises the guarded HTTPS and WSS endpoint', async () => {
  const { runnerPublicEnvironment } = await importModule(
    'lib/guardd/proxy-contract.js',
  );
  assert.deepEqual(
    runnerPublicEnvironment('https://guard.example:3443'),
    {
      ALLOWED_ORIGIN: 'https://guard.example:3443',
      NOTTY_PUBLIC_HOST: 'guard.example',
      NOTTY_PUBLIC_WS_URL: 'wss://guard.example:3443/ws/terminals',
      NOTTY_TRUSTED_HOSTS: 'guard.example',
    },
  );
});

test('gateway session monitor enforces an exact expiry timer and bounded polling', async () => {
  const {
    createGatewaySessionMonitor,
    normalizeSessionRevalidateMs,
  } = await importModule('lib/guardd/gateway.js');
  const start = Date.parse('2026-07-25T12:00:00.000Z');
  let now = start;
  const intervals = [];
  const timeouts = [];
  const clearedIntervals = [];
  const clearedTimeouts = [];
  const scheduler = {
    setInterval(callback, delay) {
      const handle = { callback, delay, unref() {} };
      intervals.push(handle);
      return handle;
    },
    clearInterval(handle) {
      clearedIntervals.push(handle);
    },
    setTimeout(callback, delay) {
      const handle = { callback, delay, unref() {} };
      timeouts.push(handle);
      return handle;
    },
    clearTimeout(handle) {
      clearedTimeouts.push(handle);
    },
  };
  const terminations = [];
  const principal = livePrincipal({
    expiresAt: new Date(start + 2_500).toISOString(),
  });
  const monitor = createGatewaySessionMonitor({
    principal,
    run: {
      runId: principal.runId,
      containerId: 'container-live',
    },
    pathname: '/sse',
    principalStore: {},
    service: { store: {} },
    revalidateMs: 100,
    scheduler,
    now: () => now,
    terminate(error) {
      terminations.push(error);
    },
  });

  assert.equal(monitor.revalidateMs, 100);
  assert.equal(intervals[0].delay, 100);
  assert.equal(timeouts[0].delay, 2_500);
  now += 2_500;
  timeouts[0].callback();
  assert.equal(monitor.stopped, true);
  assert.equal(terminations[0].code, 'GUARD_GATEWAY_PRINCIPAL_EXPIRED');
  assert.deepEqual(clearedIntervals, [intervals[0]]);
  assert.deepEqual(clearedTimeouts, [timeouts[0]]);
  assert.equal(normalizeSessionRevalidateMs(), 5_000);
  assert.throws(() => normalizeSessionRevalidateMs(99), /100 to 5000/);
  assert.throws(() => normalizeSessionRevalidateMs(5_001), /100 to 5000/);
});

test('an existing SSE proxy session closes after principal revocation', async (t) => {
  const root = tempDir(t);
  const socketPath = path.join(root, 'runner-proxy.sock');
  const principal = livePrincipal({
    allowedPrefixes: ['/sse'],
  });
  const run = {
    runId: principal.runId,
    agentId: 'agent-live',
    status: 'running',
    containerId: 'container-live',
  };
  let revoked = false;
  const principalStore = {
    async findByFingerprint() {
      return revoked ? null : { ...principal };
    },
  };
  const service = {
    egress: { controlSocketPath: socketPath },
    store: {
      async findRun(runId) {
        return runId === run.runId ? { ...run } : null;
      },
    },
  };
  const upstream = http.createServer((_request, response) => {
    response.writeHead(200, {
      'content-type': 'text/event-stream',
      'cache-control': 'no-cache',
    });
    response.write('data: ready\n\n');
  });
  await listen(upstream, socketPath);
  t.after(() => closeServer(upstream));

  const { proxyHttp } = await importModule('lib/guardd/gateway.js');
  const gateway = http.createServer((request, response) => {
    request.socket.authorized = true;
    request.socket.getPeerCertificate = () => ({
      fingerprint256: principal.certificateFingerprint,
    });
    void proxyHttp(
      request,
      response,
      principalStore,
      service,
      'https://guard.example:3443',
      { revalidateMs: 100 },
    );
  });
  const address = await listen(gateway, 0, '127.0.0.1');
  t.after(() => closeServer(gateway));

  let revokedAt = 0;
  let request;
  const closed = new Promise((resolve, reject) => {
    request = http.get(
      {
        host: '127.0.0.1',
        port: address.port,
        path: '/sse',
        headers: {
          host: 'guard.example:3443',
          origin: 'https://guard.example:3443',
        },
      },
      (response) => {
        response.on('data', (chunk) => {
          if (!revoked && chunk.toString('utf8').includes('data: ready')) {
            revoked = true;
            revokedAt = Date.now();
          }
        });
        response.once('aborted', resolve);
        response.once('close', resolve);
        response.once('error', (error) => {
          if (revoked) {
            resolve();
          } else {
            reject(error);
          }
        });
      },
    );
    request.once('error', (error) => {
      if (revoked) {
        resolve();
      } else {
        reject(error);
      }
    });
  });
  t.after(() => request?.destroy());

  await withTimeout(closed, 2_000, 'revoked SSE session close');
  assert.ok(revokedAt > 0);
  assert.ok(Date.now() - revokedAt < 1_500);
});

test('an existing WebSocket proxy session closes when its bound run stops', async (t) => {
  const root = tempDir(t);
  const socketPath = path.join(root, 'runner-proxy.sock');
  const principal = livePrincipal({
    allowedPrefixes: ['/ws/terminals'],
  });
  const run = {
    runId: principal.runId,
    agentId: 'agent-live',
    status: 'running',
    containerId: 'container-live',
  };
  const principalStore = {
    async findByFingerprint() {
      return { ...principal };
    },
  };
  const service = {
    egress: { controlSocketPath: socketPath },
    store: {
      async findRun(runId) {
        return runId === run.runId ? { ...run } : null;
      },
    },
  };
  const upstream = net.createServer((socket) => {
    let request = '';
    socket.on('data', (chunk) => {
      request += chunk.toString('utf8');
      if (request.includes('\r\n\r\n')) {
        socket.write(
          'HTTP/1.1 101 Switching Protocols\r\n' +
            'Connection: Upgrade\r\n' +
            'Upgrade: websocket\r\n\r\n',
        );
      }
    });
  });
  await listen(upstream, socketPath);
  t.after(() => closeServer(upstream));

  const { proxyUpgrade } = await importModule('lib/guardd/gateway.js');
  const gateway = http.createServer();
  gateway.on('upgrade', (request, socket, head) => {
    request.socket.authorized = true;
    request.socket.getPeerCertificate = () => ({
      fingerprint256: principal.certificateFingerprint,
    });
    void proxyUpgrade(
      request,
      socket,
      head,
      principalStore,
      service,
      'https://guard.example:3443',
      { revalidateMs: 100 },
    );
  });
  const address = await listen(gateway, 0, '127.0.0.1');
  t.after(() => closeServer(gateway));

  let stoppedAt = 0;
  let client;
  const closed = new Promise((resolve, reject) => {
    client = net.connect(
      { host: '127.0.0.1', port: address.port },
      () => {
        client.write(
          'GET /ws/terminals HTTP/1.1\r\n' +
            'Host: guard.example:3443\r\n' +
            'Origin: https://guard.example:3443\r\n' +
            'Connection: Upgrade\r\n' +
            'Upgrade: websocket\r\n' +
            'Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n' +
            'Sec-WebSocket-Version: 13\r\n\r\n',
        );
      },
    );
    let response = '';
    client.on('data', (chunk) => {
      response += chunk.toString('utf8');
      if (
        run.status === 'running' &&
        response.includes('101 Switching Protocols')
      ) {
        run.status = 'stopped';
        stoppedAt = Date.now();
      }
    });
    client.once('close', resolve);
    client.once('error', (error) => {
      if (run.status === 'stopped') {
        resolve();
      } else {
        reject(error);
      }
    });
  });
  t.after(() => client?.destroy());

  await withTimeout(closed, 2_000, 'stopped-run WebSocket session close');
  assert.ok(stoppedAt > 0);
  assert.ok(Date.now() - stoppedAt < 1_500);
});
