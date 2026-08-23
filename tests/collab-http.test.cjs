'use strict';

const assert = require('node:assert/strict');
const http = require('node:http');
const test = require('node:test');

function listen(server) {
  return new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', () => {
      server.off('error', reject);
      resolve();
    });
  });
}

function close(server) {
  return new Promise((resolve, reject) => {
    server.close((error) => error ? reject(error) : resolve());
  });
}

test('agent viewers fail closed when an owned session loses tmux ownership', async () => {
  const { isAgentViewEligible } = await import('../lib/collabViewPolicy.js');

  assert.equal(isAgentViewEligible(
    { recovered: false },
    { tmuxAlive: true, tmuxOwned: true },
  ), true);
  assert.equal(isAgentViewEligible(
    { recovered: false },
    { tmuxAlive: true, tmuxOwned: false },
  ), false);
  assert.equal(isAgentViewEligible(
    { recovered: false },
    { tmuxAlive: false, tmuxOwned: true },
  ), false);
  assert.equal(isAgentViewEligible(
    { recovered: true },
    { tmuxAlive: true, tmuxOwned: null },
  ), true);
  assert.equal(isAgentViewEligible(
    { recovered: 'false' },
    { tmuxAlive: true, tmuxOwned: false },
  ), false);
});

test('permission-mode HTTP route forwards the encoded agent and JSON body', async (t) => {
  const express = (await import('express')).default;
  const { registerCollabHttpRoutes } = await import('../lib/collabHttpApi.js');
  const forwarded = [];
  const responsePayload = JSON.stringify({
    session: {
      id: 'session-test',
      agents: [{ id: 'agent/one', permissionMode: 'danger-full-access' }],
    },
  });
  const supervisor = {
    daemonUrl: 'http://127.0.0.1:65535',
    async start() {},
    async request(pathname, init) {
      forwarded.push({ pathname, init });
      return {
        status: 200,
        headers: {
          get(name) {
            return name.toLowerCase() === 'content-type'
              ? 'application/json'
              : null;
          },
        },
        async arrayBuffer() {
          return Buffer.from(responsePayload);
        },
      };
    },
  };
  const app = express();
  registerCollabHttpRoutes(app, {
    supervisor,
    lockdown: false,
  });
  const server = http.createServer(app);
  await listen(server);
  t.after(() => close(server));
  const { port } = server.address();

  const response = await fetch(
    `http://127.0.0.1:${port}/api/collab/session/agents/agent%2Fone/permission-mode`,
    {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ permissionMode: 'danger-full-access' }),
    },
  );

  assert.equal(response.status, 200);
  assert.deepEqual(await response.json(), JSON.parse(responsePayload));
  assert.equal(forwarded.length, 1);
  assert.equal(
    forwarded[0].pathname,
    '/admin/v1/session/agents/agent%2Fone/permission-mode',
  );
  assert.equal(forwarded[0].init.method, 'POST');
  assert.equal(forwarded[0].init.headers['Content-Type'], 'application/json');
  assert.deepEqual(JSON.parse(forwarded[0].init.body), {
    permissionMode: 'danger-full-access',
  });
});

test('message, feedback, and stats routes preserve pagination and forward the authenticated operator', async (t) => {
  const previousBasicAuth = process.env.NOTTY_BASIC_AUTH_ENABLED;
  process.env.NOTTY_BASIC_AUTH_ENABLED = 'true';
  t.after(() => {
    if (previousBasicAuth === undefined) {
      delete process.env.NOTTY_BASIC_AUTH_ENABLED;
    } else {
      process.env.NOTTY_BASIC_AUTH_ENABLED = previousBasicAuth;
    }
  });
  const express = (await import('express')).default;
  const { registerCollabHttpRoutes } = await import('../lib/collabHttpApi.js');
  const forwarded = [];
  const supervisor = {
    daemonUrl: 'http://127.0.0.1:65535',
    async start() {},
    async request(pathname, init) {
      forwarded.push({ pathname, init });
      return {
        status: 200,
        headers: {
          get(name) {
            return name.toLowerCase() === 'content-type'
              ? 'application/json'
              : null;
          },
        },
        async arrayBuffer() {
          return Buffer.from(JSON.stringify({ ok: true }));
        },
      };
    },
  };
  const app = express();
  registerCollabHttpRoutes(app, { supervisor, lockdown: false });
  const server = http.createServer(app);
  await listen(server);
  t.after(() => close(server));
  const { port } = server.address();
  const authorization = `Basic ${Buffer.from('alice:secret').toString('base64')}`;

  const messages = await fetch(
    `http://127.0.0.1:${port}/api/collab/channels/release%20notes/messages?limit=12&cursor=345`,
    { headers: { authorization } },
  );
  assert.equal(messages.status, 200);

  const feedback = await fetch(
    `http://127.0.0.1:${port}/api/collab/channels/release%20notes/messages/message%2Fone/feedback`,
    {
      method: 'PUT',
      headers: { authorization, 'Content-Type': 'application/json' },
      body: JSON.stringify({ rating: 'helpful' }),
    },
  );
  assert.equal(feedback.status, 200);

  const stats = await fetch(
    `http://127.0.0.1:${port}/api/collab/stats?scope=lifetime`,
    { headers: { authorization } },
  );
  assert.equal(stats.status, 200);

  assert.equal(forwarded[0].pathname, '/admin/v1/channels/release%20notes/messages');
  assert.equal(forwarded[0].init.search, '?limit=12&cursor=345');
  assert.equal(forwarded[0].init.headers['X-Notty-Collab-Operator'], 'alice');
  assert.equal(
    forwarded[1].pathname,
    '/admin/v1/channels/release%20notes/messages/message%2Fone/feedback',
  );
  assert.equal(forwarded[1].init.method, 'PUT');
  assert.deepEqual(JSON.parse(forwarded[1].init.body), { rating: 'helpful' });
  assert.equal(forwarded[1].init.headers['X-Notty-Collab-Operator'], 'alice');
  assert.equal(forwarded[2].pathname, '/admin/v1/stats');
  assert.equal(forwarded[2].init.search, '?scope=lifetime');
});

test('catalog refresh and agent health routes preserve methods, encoding, and JSON', async (t) => {
  const express = (await import('express')).default;
  const { registerCollabHttpRoutes } = await import('../lib/collabHttpApi.js');
  const forwarded = [];
  const supervisor = {
    daemonUrl: 'http://127.0.0.1:65535',
    async start() {},
    async request(pathname, init) {
      forwarded.push({ pathname, init });
      return {
        status: 200,
        headers: { get: () => 'application/json' },
        async arrayBuffer() {
          return Buffer.from(JSON.stringify({ ok: true }));
        },
      };
    },
  };
  const app = express();
  registerCollabHttpRoutes(app, { supervisor, lockdown: false });
  const server = http.createServer(app);
  await listen(server);
  t.after(() => close(server));
  const { port } = server.address();

  const refresh = await fetch(`http://127.0.0.1:${port}/api/collab/catalog/refresh`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({}),
  });
  assert.equal(refresh.status, 200);
  const health = await fetch(
    `http://127.0.0.1:${port}/api/collab/session/agents/observer%2Fone/health`,
    {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ code: 'rate-limited' }),
    },
  );
  assert.equal(health.status, 200);

  assert.equal(forwarded[0].pathname, '/admin/v1/catalog/refresh');
  assert.equal(forwarded[0].init.method, 'POST');
  assert.deepEqual(JSON.parse(forwarded[0].init.body), {});
  assert.equal(
    forwarded[1].pathname,
    '/admin/v1/session/agents/observer%2Fone/health',
  );
  assert.equal(forwarded[1].init.method, 'PUT');
  assert.deepEqual(JSON.parse(forwarded[1].init.body), { code: 'rate-limited' });
});
