'use strict';

const assert = require('node:assert/strict');
const http = require('node:http');
const test = require('node:test');

function closeServer(server) {
  return new Promise((resolve, reject) => {
    server.close((error) => error ? reject(error) : resolve());
  });
}

test('HTTP listen helper resolves on listening and rejects bind errors', async (t) => {
  const { listenHttpServer } = await import('../lib/httpServerListen.js');
  const owner = http.createServer((_req, res) => res.end('ok'));
  await listenHttpServer(owner, [0, '127.0.0.1']);
  t.after(() => closeServer(owner));

  const address = owner.address();
  assert.equal(typeof address, 'object');
  assert.ok(address.port > 0);

  const contender = http.createServer();
  await assert.rejects(
    listenHttpServer(contender, [address.port, '127.0.0.1']),
    (error) => error?.code === 'EADDRINUSE',
  );
  assert.equal(contender.listenerCount('error'), 0);
});
