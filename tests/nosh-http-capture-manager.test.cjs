'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const test = require('node:test');
const { pathToFileURL } = require('node:url');

const appRoot = path.resolve(__dirname, '..');
const observedAt = '2026-08-22T12:00:00.000Z';

async function modules() {
  const [capture, evidence, content] = await Promise.all([
    import(pathToFileURL(
      path.join(appRoot, 'lib/guardd/http-capture-manager.js'),
    ).href),
    import(pathToFileURL(
      path.join(appRoot, 'lib/guardd/http-evidence.js'),
    ).href),
    import(pathToFileURL(
      path.join(appRoot, 'lib/guardd/http-content-store.js'),
    ).href),
  ]);
  return { capture, evidence, content };
}

function captureFixture(t) {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'nosh-http-capture-manager-'));
  const bundleDir = path.join(directory, 'bundle');
  const dockerfile = path.join(directory, 'Dockerfile');
  fs.mkdirSync(bundleDir, { mode: 0o700 });
  fs.writeFileSync(
    dockerfile,
    [
      'FROM scratch',
      '# nosh-http-capture-ca-secret=v1',
      'RUN --mount=type=secret,id=nosh-http-ca true',
      '',
    ].join('\n'),
    { mode: 0o600 },
  );
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  return { directory, bundleDir, dockerfile };
}

function successfulDocker(calls, fixture) {
  return function spawnSyncImpl(command, args) {
    assert.equal(command, 'docker');
    calls.push([...args]);
    if (args[0] === 'run') {
      const confdir = path.join(fixture.bundleDir, 'http-capture', 'conf');
      fs.writeFileSync(
        path.join(confdir, 'mitmproxy-ca-cert.pem'),
        `-----BEGIN CERTIFICATE-----\n${'A'.repeat(320)}\n-----END CERTIFICATE-----\n`,
        { mode: 0o600 },
      );
    }
    if (args[0] === 'inspect' && args.some((value) => value.includes('.State.Running'))) {
      return { status: 0, stdout: 'true\n', stderr: '' };
    }
    if (args[0] === 'inspect' && args.some((value) => value.includes('.IPAddress'))) {
      return { status: 0, stdout: '172.30.0.2\n', stderr: '' };
    }
    return { status: 0, stdout: '', stderr: '' };
  };
}

test('managed capture creates a bridge and injects only the reviewed proxy and CA inputs', async (t) => {
  const { capture } = await modules();
  const fixture = captureFixture(t);
  const calls = [];
  const session = await capture.startManagedHttpCapture({
    runId: 'capture-run-one',
    bundleDir: fixture.bundleDir,
    dockerfile: fixture.dockerfile,
    scriptsDirectory: path.join(appRoot, 'scripts'),
  }, {
    spawnSyncImpl: successfulDocker(calls, fixture),
  });

  assert.deepEqual(calls[0], [
    'image', 'inspect', capture.MANAGED_MITMPROXY_IMAGE,
  ]);
  const networkCreate = calls.find((args) => args[0] === 'network' && args[1] === 'create');
  assert.deepEqual(networkCreate.slice(0, 4), [
    'network', 'create', '--driver', 'bridge',
  ]);
  assert.ok(networkCreate.includes('io.notty.guard.http-run=capture-run-one'));
  const run = calls.find((args) => args[0] === 'run');
  assert.ok(run);
  assert.ok(run.includes('--network'));
  assert.ok(run.includes(session.networkName));
  assert.ok(run.includes('--network-alias'));
  assert.ok(run.includes(capture.HTTP_CAPTURE_PROXY_ALIAS));
  assert.ok(run.includes('--read-only'));
  assert.ok(run.includes('--pull=never'));
  assert.ok(run.includes('no-new-privileges=true'));
  assert.ok(run.includes(capture.MANAGED_MITMPROXY_IMAGE));

  const build = capture.managedHttpBuildOptions(session);
  assert.equal(build.networkName, session.networkName);
  assert.deepEqual(build.secret, {
    id: 'nosh-http-ca',
    source: session.caPath,
  });
  assert.deepEqual(build.buildArgs, [
    'HTTP_PROXY=http://nosh-http-proxy:8080',
    'HTTPS_PROXY=http://nosh-http-proxy:8080',
    'FTP_PROXY=http://nosh-http-proxy:8080',
    'ALL_PROXY=http://nosh-http-proxy:8080',
    'NO_PROXY=',
    'http_proxy=http://nosh-http-proxy:8080',
    'https_proxy=http://nosh-http-proxy:8080',
    'ftp_proxy=http://nosh-http-proxy:8080',
    'all_proxy=http://nosh-http-proxy:8080',
    'no_proxy=',
    'NOSH_HTTP_CAPTURE=1',
    'NOSH_HTTP_CAPTURE_CA_FILE=/usr/local/share/ca-certificates/nosh-http-capture.crt',
  ]);
  assert.throws(
    () => capture.managedHttpBuildOptions({ ...session, stopped: true }),
    /active managed HTTP capture session is required/,
  );
});

test('capture stop returns a finalizer-ready source, correlation, and removable network', async (t) => {
  const { capture, evidence, content } = await modules();
  const fixture = captureFixture(t);
  const calls = [];
  const dependencies = { spawnSyncImpl: successfulDocker(calls, fixture) };
  const session = await capture.startManagedHttpCapture({
    runId: 'capture-run-two',
    bundleDir: fixture.bundleDir,
    dockerfile: fixture.dockerfile,
    scriptsDirectory: path.join(appRoot, 'scripts'),
  }, dependencies);
  const request = evidence.createHttpRequestEvidence({
    runId: session.runId,
    observedAt,
    provider: 'mitmproxy',
    providerEventId: 'private-provider-event',
    method: 'GET',
    url: 'https://registry.example.test:8443/package.tgz',
    headers: { Accept: 'application/octet-stream' },
    requestBody: Buffer.alloc(0),
    tlsInterception: 'intercepted',
    upstreamTlsVerified: true,
    clientAddress: '172.30.0.3',
    clientPort: 41_234,
    proxyAddress: session.proxyIpv4,
    proxyPort: session.proxyPort,
  });
  const response = evidence.createHttpResponseEvidence({
    runId: session.runId,
    observedAt,
    provider: 'mitmproxy',
    exchangeId: request.exchangeId,
    status: 302,
    contentType: 'application/octet-stream',
    contentEncoding: null,
    headersDigest: null,
    body: 'package bytes',
    decodedBody: 'package bytes',
    bodyComplete: true,
    delivery: 'observed',
    rangeResponse: false,
  });
  const redirect = evidence.createHttpRedirectEvidence({
    runId: session.runId,
    observedAt,
    provider: 'mitmproxy',
    exchangeId: request.exchangeId,
    status: 302,
    location: '/next?sig=private',
    baseUrl: 'https://registry.example.test:8443/package.tgz',
  });
  const store = new content.HttpContentStore({
    root: session.casRoot,
    containmentRoot: session.root,
  });
  const object = await store.put(Buffer.from('package bytes'));
  const contentManifest = content.createHttpContentManifest({
    runId: session.runId,
    generatedAt: observedAt,
    mode: 'offline-replay',
    entries: [{
      request: evidence.httpRequestIdentity(request),
      response: {
        status: 302,
        bodyDigest: object.digest,
        bodyBytes: object.bytes,
        contentType: 'application/octet-stream',
        contentEncoding: null,
        location: '/next?sig=private',
        locationDigest: redirect.locationDigest,
      },
      sourceExchangeId: request.exchangeId,
      capturedAt: observedAt,
    }],
  });
  await store.writeManifest(contentManifest);
  const stats = evidence.createHttpCaptureStats({
    runId: session.runId,
    observedAt,
    provider: 'mitmproxy',
    complete: true,
    requests: 1,
    responses: 1,
    redirects: 1,
    errors: 0,
    opaqueConnects: 0,
    incompleteBodies: 0,
    droppedRecords: 0,
    reviewOnlyRecords: 0,
    coverageGaps: [],
    contentAssuranceGaps: [],
    contentManifestDigest: contentManifest.contentHash,
    ...session.collectorIdentity,
  });
  fs.writeFileSync(
    session.evidencePath,
    `${[request, response, redirect, stats].map((record) => JSON.stringify(record)).join('\n')}\n`,
    { mode: 0o600 },
  );

  const stopped = await capture.stopManagedHttpCapture(session, dependencies);
  assert.equal(session.stopped, true);
  assert.equal(stopped.records.length, 4);
  assert.equal(stopped.source.name, 'http');
  assert.equal(stopped.source.file, 'raw/http.ndjson');
  assert.equal(stopped.source.required, true);
  assert.equal(stopped.source.complete, true);
  assert.equal(stopped.source.completionMarker, 'nosh-http-capture-complete');
  assert.deepEqual(stopped.contentManifest, contentManifest);
  assert.ok(Buffer.isBuffer(stopped.source.content));
  assert.equal(fs.existsSync(session.evidencePath), false);
  assert.equal(fs.existsSync(session.confdir), false);

  const hint = evidence.httpDownstreamCorrelationHint(request, { pass: 'cold' });
  const observations = capture.correlateManagedHttpEvidence(stopped.records, {
    proxyIpv4: session.proxyIpv4,
    proxyPort: session.proxyPort,
    networkAttempts: [{
      pass: 'cold',
      firstTimestampNs: String(BigInt(hint.timestampUnixNs) - 1_000_000n),
      lastTimestampNs: String(BigInt(hint.timestampUnixNs) + 1_000_000n),
      sourceAddress: hint.source.address,
      sourcePort: hint.source.port,
      ip: hint.destination.ip,
      protocol: hint.destination.protocol,
      port: hint.destination.port,
    }],
    contentManifest: stopped.contentManifest,
  });
  assert.equal(observations.complete, false);
  assert.equal(observations.exchanges.length, 1);
  assert.equal(observations.exchanges[0].pass, 'cold');
  assert.deepEqual(observations.exchanges[0].destination, {
    ip: session.proxyIpv4,
    protocol: 'tcp',
    port: session.proxyPort,
  });
  assert.equal(observations.exchanges[0].destinationRole, 'workload-to-proxy');
  assert.ok(observations.gaps.includes(
    'managed HTTP origin route lacks independent proxy-leg L4 provenance',
  ));
  assert.deepEqual(observations.exchanges[0].cas, {
    objectSha256: object.digest,
    manifestSha256: contentManifest.contentHash,
    available: true,
  });
  const mismatchedRedirectManifest = content.createHttpContentManifest({
    runId: session.runId,
    generatedAt: observedAt,
    mode: 'offline-replay',
    entries: [{
      ...contentManifest.entries[0],
      response: {
        ...contentManifest.entries[0].response,
        location: '/different',
        locationDigest: evidence.createHttpRedirectEvidence({
          runId: session.runId,
          observedAt,
          provider: 'mitmproxy',
          exchangeId: request.exchangeId,
          status: 302,
          location: '/different',
          baseUrl: 'https://registry.example.test:8443/package.tgz',
        }).locationDigest,
      },
    }],
  });
  assert.throws(
    () => capture.correlateManagedHttpEvidence(stopped.records, {
      proxyIpv4: session.proxyIpv4,
      proxyPort: session.proxyPort,
      networkAttempts: [],
      contentManifest: mismatchedRedirectManifest,
    }),
    /CAS manifest does not match normalized evidence/,
  );
  const bypassed = capture.correlateManagedHttpEvidence(stopped.records, {
    proxyIpv4: session.proxyIpv4,
    proxyPort: session.proxyPort,
    contentManifest: stopped.contentManifest,
    networkAttempts: [{
      pass: 'cold',
      timestampNs: hint.timestampUnixNs,
      sourceAddress: hint.source.address,
      sourcePort: hint.source.port,
      ip: hint.destination.ip,
      protocol: hint.destination.protocol,
      port: hint.destination.port,
    }, {
      pass: 'cold',
      timestampNs: hint.timestampUnixNs,
      sourceAddress: hint.source.address,
      sourcePort: 41_235,
      ip: '203.0.113.9',
      protocol: 'tcp',
      port: 8443,
    }],
  });
  assert.equal(bypassed.complete, false);
  assert.ok(bypassed.gaps.includes(
    'scoped L4 evidence observed direct HTTP(S)/QUIC proxy bypass',
  ));

  capture.cleanupManagedHttpCaptureNetwork(session, dependencies);
  assert.equal(session.networkCreated, false);
  assert.ok(calls.some((args) => (
    args[0] === 'network'
    && args[1] === 'rm'
    && args[2] === session.networkName
  )));
});

test('capture startup removes both the partial proxy and its bridge on readiness failure', async (t) => {
  const { capture } = await modules();
  const fixture = captureFixture(t);
  const calls = [];
  let failure;
  try {
    await capture.startManagedHttpCapture({
      runId: 'capture-run-failure',
      bundleDir: fixture.bundleDir,
      dockerfile: fixture.dockerfile,
      scriptsDirectory: path.join(appRoot, 'scripts'),
    }, {
      spawnSyncImpl(command, args) {
        assert.equal(command, 'docker');
        calls.push([...args]);
        if (args[0] === 'inspect' && args.some((value) => value.includes('.State.Running'))) {
          return { status: 0, stdout: 'false\n', stderr: '' };
        }
        return { status: 0, stdout: '', stderr: '' };
      },
    });
  } catch (error) {
    failure = error;
  }
  assert.match(failure?.message || '', /managed HTTP capture container exited before readiness/);
  assert.equal(failure.managedHttpResources.containerMayExist, false);
  assert.equal(failure.managedHttpResources.networkMayExist, false);
  assert.ok(calls.some((args) => args[0] === 'rm' && args[1] === '--force'));
  assert.ok(calls.some((args) => args[0] === 'network' && args[1] === 'rm'));
});

test('capture stop preserves exact cleanup identities until forced containment succeeds', async (t) => {
  const { capture } = await modules();
  const fixture = captureFixture(t);
  const session = await capture.startManagedHttpCapture({
    runId: 'capture-stop-containment-failure',
    bundleDir: fixture.bundleDir,
    dockerfile: fixture.dockerfile,
    scriptsDirectory: path.join(appRoot, 'scripts'),
  }, {
    spawnSyncImpl: successfulDocker([], fixture),
  });
  let failure;
  try {
    await capture.stopManagedHttpCapture(session, {
      spawnSyncImpl(_command, args) {
        if (args[0] === 'stop' || (args[0] === 'rm' && args[1] === '--force')) {
          return { status: 1, stdout: '', stderr: 'simulated containment failure' };
        }
        return { status: 0, stdout: '', stderr: '' };
      },
    });
  } catch (error) {
    failure = error;
  }
  assert.ok(failure instanceof AggregateError);
  assert.equal(session.stopped, false);
  assert.equal(session.containerStarted, true);
  assert.deepEqual(failure.managedHttpResources, {
    containerName: session.containerName,
    containerMayExist: true,
    networkName: session.networkName,
    networkMayExist: true,
  });
});
