'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');

async function loadPolicy() {
  return import('../lib/corsPolicy.js');
}

test('origin policy is same-origin by default and keeps non-browser clients working', async () => {
  const { resolveOriginPolicy } = await loadPolicy();

  assert.deepEqual(resolveOriginPolicy({ host: 'localhost:3000' }), {
    allowed: true,
    responseOrigin: null,
    reason: 'non-browser',
  });
  assert.deepEqual(resolveOriginPolicy({
    origin: 'http://localhost:3000',
    host: 'localhost:3000',
    protocol: 'http',
  }), {
    allowed: true,
    responseOrigin: 'http://localhost:3000',
    reason: 'same-origin',
  });
  assert.equal(resolveOriginPolicy({
    origin: 'https://attacker.example',
    host: 'localhost:3000',
    protocol: 'http',
  }).allowed, false);
  assert.equal(resolveOriginPolicy({
    origin: 'not a URL',
    host: 'localhost:3000',
    protocol: 'http',
  }).reason, 'invalid-origin');
  assert.equal(resolveOriginPolicy({
    host: 'localhost:3000',
    fetchSite: 'cross-site',
  }).allowed, false);
  assert.equal(resolveOriginPolicy({
    host: 'localhost:3000',
    fetchSite: 'same-origin',
  }).allowed, true);
});

test('cross-origin access requires an explicit exact origin or wildcard opt-in', async () => {
  const { resolveOriginPolicy } = await loadPolicy();

  assert.deepEqual(resolveOriginPolicy({
    origin: 'https://console.example',
    host: 'localhost:3000',
    protocol: 'http',
    allowedOrigin: 'https://console.example/app',
  }), {
    allowed: true,
    responseOrigin: 'https://console.example',
    reason: 'configured-origin',
  });
  assert.equal(resolveOriginPolicy({
    origin: 'https://attacker.example',
    host: 'localhost:3000',
    protocol: 'http',
    allowedOrigin: 'https://console.example',
  }).allowed, false);
  assert.deepEqual(resolveOriginPolicy({
    origin: 'https://attacker.example',
    host: 'localhost:3000',
    protocol: 'http',
    allowedOrigin: '*',
  }), {
    allowed: true,
    responseOrigin: '*',
    reason: 'configured-origin',
  });
});

test('same-origin checks include scheme and reject untrusted DNS hostnames', async () => {
  const { resolveOriginPolicy } = await loadPolicy();

  assert.equal(resolveOriginPolicy({
    origin: 'http://notty.example',
    host: 'notty.example',
    protocol: 'https',
    trustedHosts: ['notty.example'],
  }).allowed, false);
  assert.deepEqual(resolveOriginPolicy({
    origin: 'https://notty.example',
    host: 'notty.example',
    protocol: 'https',
    trustedHosts: ['notty.example'],
  }), {
    allowed: true,
    responseOrigin: 'https://notty.example',
    reason: 'same-origin',
  });
  assert.equal(resolveOriginPolicy({
    origin: 'http://attacker.example:3000',
    host: 'attacker.example:3000',
    protocol: 'http',
    allowedOrigin: 'https://console.example',
    trustedHosts: ['notty.example'],
  }).reason, 'untrusted-host');
  assert.equal(resolveOriginPolicy({
    origin: 'https://public.example',
    host: 'notty:3000',
    protocol: 'http',
    allowedOrigin: 'https://public.example',
    trustedHosts: 'notty,other-service',
  }).reason, 'configured-origin');
});

test('configured public HTTPS origin stays same-origin behind TLS termination', async () => {
  const { resolveOriginPolicy } = await loadPolicy();
  const input = {
    origin: 'https://notty.example',
    host: 'notty.example',
    protocol: 'http',
    publicOrigin: 'https://notty.example',
    trustedHosts: ['notty.example'],
  };

  // Both Express CORS and the WebSocket upgrade path use this decision.
  assert.deepEqual(resolveOriginPolicy(input), {
    allowed: true,
    responseOrigin: 'https://notty.example',
    reason: 'same-origin',
  });
  assert.equal(resolveOriginPolicy({
    ...input,
    origin: 'http://notty.example',
  }).allowed, false);
  assert.equal(resolveOriginPolicy({
    ...input,
    host: 'attacker.example',
  }).reason, 'untrusted-host');
});

test('configured loopback HTTP origin accepts equivalent local browser addresses', async () => {
  const { resolveOriginPolicy } = await loadPolicy();

  assert.deepEqual(resolveOriginPolicy({
    origin: 'http://localhost:3000',
    host: 'localhost:3000',
    protocol: 'http',
    publicOrigin: 'http://127.0.0.1:3000',
    trustedHosts: ['127.0.0.1'],
  }), {
    allowed: true,
    responseOrigin: 'http://localhost:3000',
    reason: 'same-origin',
  });
  assert.deepEqual(resolveOriginPolicy({
    origin: 'http://172.17.0.2:3000',
    host: '172.17.0.2:3000',
    protocol: 'http',
    publicOrigin: 'http://127.0.0.1:3000',
  }), {
    allowed: true,
    responseOrigin: 'http://172.17.0.2:3000',
    reason: 'same-origin',
  });
  assert.equal(resolveOriginPolicy({
    origin: 'http://localhost:3001',
    host: 'localhost:3001',
    protocol: 'http',
    publicOrigin: 'http://127.0.0.1:3000',
  }).allowed, false, 'loopback aliases still require the configured port');
  assert.equal(resolveOriginPolicy({
    origin: 'http://notty.example:3000',
    host: 'notty.example:3000',
    protocol: 'http',
    publicOrigin: 'http://127.0.0.1:3000',
    trustedHosts: ['notty.example'],
  }).allowed, false, 'non-loopback aliases are not equivalent');
  assert.equal(resolveOriginPolicy({
    origin: 'http://203.0.113.10:3000',
    host: '203.0.113.10:3000',
    protocol: 'http',
    publicOrigin: 'http://127.0.0.1:3000',
  }).allowed, false, 'public IP addresses are not treated as local container routes');
});

test('CORS middleware rejects foreign origins before invoking a route', async () => {
  const { createCorsMiddleware } = await loadPolicy();
  const middleware = createCorsMiddleware();
  let nextCalled = false;
  let statusCode = null;
  let payload = null;
  const req = {
    method: 'POST',
    protocol: 'http',
    get(name) {
      return name.toLowerCase() === 'origin'
        ? 'https://attacker.example'
        : 'localhost:3000';
    },
  };
  const res = {
    status(code) {
      statusCode = code;
      return this;
    },
    json(value) {
      payload = value;
      return this;
    },
  };

  middleware(req, res, () => {
    nextCalled = true;
  });

  assert.equal(statusCode, 403);
  assert.equal(payload.error.code, 'ORIGIN_REJECTED');
  assert.equal(nextCalled, false);
});

test('trusted preflights expose the configured methods and headers', async () => {
  const { createCorsMiddleware } = await loadPolicy();
  const middleware = createCorsMiddleware({
    allowedHeaders: 'Content-Type, MCP-Protocol-Version, Last-Event-ID',
    allowedMethods: 'GET,POST,DELETE,OPTIONS',
    exposedHeaders: 'X-Session-Id, MCP-Session-Id',
  });
  const headers = new Map();
  let statusCode = null;
  const req = {
    method: 'OPTIONS',
    protocol: 'http',
    get(name) {
      return name.toLowerCase() === 'origin'
        ? 'http://localhost:3000'
        : 'localhost:3000';
    },
  };
  const res = {
    setHeader(name, value) {
      headers.set(name.toLowerCase(), value);
    },
    vary(value) {
      headers.set('vary', value);
    },
    sendStatus(code) {
      statusCode = code;
    },
  };

  middleware(req, res, () => assert.fail('preflight must not reach the route'));

  assert.equal(statusCode, 204);
  assert.equal(headers.get('access-control-allow-origin'), 'http://localhost:3000');
  assert.equal(headers.get('access-control-allow-methods'), 'GET,POST,DELETE,OPTIONS');
  assert.equal(
    headers.get('access-control-allow-headers'),
    'Content-Type, MCP-Protocol-Version, Last-Event-ID',
  );
  assert.equal(headers.get('access-control-expose-headers'), 'X-Session-Id, MCP-Session-Id');
  assert.equal(headers.get('vary'), 'Origin');
});

test('CORS middleware uses the configured public origin instead of inner HTTP', async () => {
  const { createCorsMiddleware } = await loadPolicy();
  const middleware = createCorsMiddleware({
    publicOrigin: 'https://notty.example',
    trustedHosts: ['notty.example'],
  });
  const headers = new Map();
  let nextCalled = false;
  const req = {
    method: 'POST',
    protocol: 'http',
    get(name) {
      const normalized = name.toLowerCase();
      if (normalized === 'origin') return 'https://notty.example';
      if (normalized === 'host') return 'notty.example';
      return undefined;
    },
  };
  const res = {
    setHeader(name, value) {
      headers.set(name.toLowerCase(), value);
    },
    vary(value) {
      headers.set('vary', value);
    },
  };

  middleware(req, res, () => {
    nextCalled = true;
  });

  assert.equal(nextCalled, true);
  assert.equal(headers.get('access-control-allow-origin'), 'https://notty.example');
});

test('invalid ALLOWED_ORIGIN configuration fails during middleware creation', async () => {
  const { createCorsMiddleware } = await loadPolicy();

  assert.throws(
    () => createCorsMiddleware({ allowedOrigin: 'not a URL' }),
    /ALLOWED_ORIGIN must be an absolute URL or \*/,
  );
});
