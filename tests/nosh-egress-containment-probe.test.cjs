'use strict';

const assert = require('node:assert/strict');
const childProcess = require('node:child_process');
const dgram = require('node:dgram');
const http = require('node:http');
const net = require('node:net');
const path = require('node:path');
const test = require('node:test');
const { pathToFileURL } = require('node:url');

const appRoot = path.resolve(__dirname, '..');
const probePath = path.join(appRoot, 'scripts', 'nosh-egress-containment-probe.mjs');
const probeUrl = pathToFileURL(probePath).href;

async function loadProbe() {
  return import(probeUrl);
}

async function listen(server) {
  await new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', resolve);
  });
  return server.address().port;
}

async function close(server) {
  server.closeAllConnections?.();
  await new Promise((resolve, reject) => {
    server.close((error) => {
      if (error) reject(error);
      else resolve();
    });
  });
}

test('probe option parsing is bounded, unambiguous, and has no network side effects', async () => {
  const { parseProbeOptions } = await loadProbe();

  assert.deepEqual(parseProbeOptions([]), { help: false, timeoutMs: 1500 });
  assert.deepEqual(parseProbeOptions(['--help']), { help: true, timeoutMs: 1500 });
  assert.deepEqual(parseProbeOptions(['--timeout-ms', '250']), {
    help: false,
    timeoutMs: 250,
  });
  assert.deepEqual(parseProbeOptions(['--timeout-ms=10000']), {
    help: false,
    timeoutMs: 10000,
  });

  const cases = [
    [[], null],
    [['--timeout-ms'], /requires one value/],
    [['--timeout-ms', '249'], /between 250 and 10000/],
    [['--timeout-ms=10001'], /between 250 and 10000/],
    [['--timeout-ms=1.5'], /must be an integer/],
    [['--timeout-ms', '500', '--timeout-ms=600'], /only once/],
    [['--unknown'], /unknown option/],
  ];
  for (const [argv, expected] of cases.slice(1)) {
    assert.throws(() => parseProbeOptions(argv), expected);
  }
});

test('a successful local TCP connection and an active refusal both count as escape evidence', async (t) => {
  const { tcpConnectProbe } = await loadProbe();
  const server = net.createServer((socket) => socket.end());
  const port = await listen(server);
  t.after(() => {
    if (server.listening) server.close();
  });

  const connected = await tcpConnectProbe({
    id: 'local-listener',
    host: '127.0.0.1',
    port,
    timeoutMs: 500,
  });
  assert.equal(connected.status, 'escaped');
  assert.equal(connected.escaped, true);
  assert.equal(connected.detail.outcome, 'connected');
  await close(server);

  const refused = await tcpConnectProbe({
    id: 'local-refusal',
    host: '127.0.0.1',
    port,
    timeoutMs: 500,
  });
  assert.equal(refused.status, 'escaped');
  assert.equal(refused.escaped, true);
  assert.equal(refused.detail.outcome, 'network-response');
  assert.equal(refused.detail.code, 'ECONNREFUSED');
});

test('an HTTP connection is escape evidence even before a response completes', async (t) => {
  const { fetchProbe } = await loadProbe();
  const responseServer = http.createServer((request, response) => {
    response.writeHead(204);
    response.end();
  });
  const responsePort = await listen(responseServer);
  t.after(() => {
    if (responseServer.listening) responseServer.close();
  });

  const escaped = await fetchProbe({
    id: 'local-http-response',
    url: `http://127.0.0.1:${responsePort}/`,
    timeoutMs: 500,
  });
  assert.equal(escaped.status, 'escaped');
  assert.equal(escaped.escaped, true);
  assert.ok(['connected', 'response'].includes(escaped.detail.outcome));
  await close(responseServer);

  const sockets = new Set();
  const hangingServer = http.createServer(() => {});
  hangingServer.on('connection', (socket) => {
    sockets.add(socket);
    socket.once('close', () => sockets.delete(socket));
  });
  const hangingPort = await listen(hangingServer);
  t.after(() => {
    for (const socket of sockets) socket.destroy();
    if (hangingServer.listening) hangingServer.close();
  });

  const connected = await fetchProbe({
    id: 'local-http-connected-without-response',
    url: `http://127.0.0.1:${hangingPort}/`,
    timeoutMs: 250,
  });
  assert.equal(connected.status, 'escaped');
  assert.equal(connected.escaped, true);
  assert.equal(connected.detail.outcome, 'connected');
  for (const socket of sockets) socket.destroy();
  await close(hangingServer);
});

test('a UDP response is positive escape evidence', async (t) => {
  const { udpResponseProbe } = await loadProbe();
  const server = dgram.createSocket('udp4');
  server.on('message', (message, remote) => {
    server.send(message, remote.port, remote.address);
  });
  await new Promise((resolve, reject) => {
    server.once('error', reject);
    server.bind(0, '127.0.0.1', resolve);
  });
  t.after(() => server.close());

  const result = await udpResponseProbe({
    id: 'local-udp-response',
    host: '127.0.0.1',
    port: server.address().port,
    payload: Buffer.from('nosh-containment-probe'),
    timeoutMs: 500,
  });
  assert.equal(result.status, 'escaped');
  assert.equal(result.escaped, true);
  assert.equal(result.detail.outcome, 'response');
  assert.equal(result.detail.responseBytes, 22);
});

test('CLI help and invalid options terminate before the fixed external probe matrix', () => {
  const help = childProcess.spawnSync(process.execPath, [probePath, '--help'], {
    cwd: appRoot,
    encoding: 'utf8',
  });
  assert.equal(help.status, 0, `${help.stdout}${help.stderr}`);
  assert.match(help.stdout, /bounded default-deny escape probe/);
  assert.match(help.stdout, /--timeout-ms NUMBER/);

  const invalid = childProcess.spawnSync(
    process.execPath,
    [probePath, '--timeout-ms', '10001'],
    { cwd: appRoot, encoding: 'utf8' },
  );
  assert.equal(invalid.status, 2, `${invalid.stdout}${invalid.stderr}`);
  assert.match(invalid.stderr, /must be between 250 and 10000/);
  assert.equal(invalid.stdout, '');
});
