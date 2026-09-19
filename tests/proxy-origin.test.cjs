'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');

test('public origin configuration rejects surrounding whitespace', async () => {
  const { resolvePublicOrigin } = await import('../lib/publicOrigin.js');

  assert.throws(
    () => resolvePublicOrigin({
      env: { NOTTY_PUBLIC_ORIGIN: ' https://notty.example' }
    }),
    /surrounding whitespace/
  );
  assert.throws(
    () => resolvePublicOrigin({
      env: { NOTTY_PUBLIC_ORIGIN: 'https://notty.example ' }
    }),
    /surrounding whitespace/
  );
});

test('Next proxy honors canonical HTTPS origin behind an inner HTTP listener', async (t) => {
  const saved = {
    NOTTY_INTEGRATED_SERVER: process.env.NOTTY_INTEGRATED_SERVER,
    NOTTY_PUBLIC_ORIGIN: process.env.NOTTY_PUBLIC_ORIGIN,
    NOTTY_PUBLIC_HOST: process.env.NOTTY_PUBLIC_HOST,
  };
  process.env.NOTTY_INTEGRATED_SERVER = 'true';
  process.env.NOTTY_PUBLIC_ORIGIN = 'https://notty.example';
  process.env.NOTTY_PUBLIC_HOST = 'notty.example';
  t.after(() => {
    for (const [name, value] of Object.entries(saved)) {
      if (value === undefined) delete process.env[name];
      else process.env[name] = value;
    }
  });

  const { proxy } = await import('../proxy.js');
  const response = proxy({
    method: 'POST',
    nextUrl: {
      pathname: '/api/spawn-otps',
      protocol: 'http:',
    },
    headers: new Headers({
      Host: 'notty.example',
      Origin: 'https://notty.example',
    }),
  });

  assert.notEqual(response.status, 403);
  assert.equal(
    response.headers.get('access-control-allow-origin'),
    'https://notty.example',
  );
});
