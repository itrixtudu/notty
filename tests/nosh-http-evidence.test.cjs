'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawnSync } = require('node:child_process');
const test = require('node:test');
const { pathToFileURL } = require('node:url');

const appRoot = path.resolve(__dirname, '..');
const at = '2026-08-22T12:00:00.000Z';

async function evidenceModule() {
  return import(pathToFileURL(
    path.join(appRoot, 'lib/guardd/http-evidence.js'),
  ).href);
}

async function contentModule() {
  return import(pathToFileURL(
    path.join(appRoot, 'lib/guardd/http-content-store.js'),
  ).href);
}

async function stableModule() {
  return import(pathToFileURL(
    path.join(appRoot, 'lib/guard/stable.js'),
  ).href);
}

async function buildReviewModule() {
  return import(pathToFileURL(
    path.join(appRoot, 'lib/guard/review/build-adapter.js'),
  ).href);
}

async function collectorIdentityFixture() {
  const stable = await stableModule();
  return {
    collectorImageDigest: 'sha256:00b77b5d8804c8ad18cb6caefbf9d5849e895e8986c5ce011f4ae30f4385962f',
    collectorAddonDigest: stable.sha256(fs.readFileSync(path.join(
      appRoot,
      'scripts/nosh-mitmproxy-addon.py',
    ))),
    collectorWrapperDigest: stable.sha256(fs.readFileSync(path.join(
      appRoot,
      'scripts/nosh-mitmproxy-capture.sh',
    ))),
  };
}

async function requestFixture(options = {}) {
  const evidence = await evidenceModule();
  const credentialed = options.credentialed !== false;
  return evidence.createHttpRequestEvidence({
    runId: 'http-run-one',
    observedAt: at,
    provider: 'mitmproxy',
    providerEventId: 'private-provider-id',
    method: 'get',
    url: credentialed
      ? 'https://user:password@example.test/npm/pkg.tgz?token=secret&version=1'
      : 'https://example.test/npm/pkg.tgz?version=1',
    headers: credentialed
      ? {
          Accept: 'application/octet-stream',
          Authorization: 'Bearer do-not-store',
        }
      : { Accept: 'application/octet-stream' },
    requestBody: Buffer.alloc(0),
    tlsInterception: 'intercepted',
    upstreamTlsVerified: true,
    clientAddress: '172.18.0.3',
    clientPort: 41_234,
    proxyAddress: '172.18.0.2',
    proxyPort: 8080,
  });
}

function contentEntry(request, object, mode = 'offline-replay') {
  return {
    mode,
    entry: {
      request,
      response: {
        status: 200,
        bodyDigest: object.digest,
        bodyBytes: object.bytes,
        contentType: 'application/octet-stream',
        contentEncoding: null,
        location: null,
        locationDigest: null,
      },
      sourceExchangeId: request.exchangeId,
      capturedAt: at,
    },
  };
}

test('HTTP normalization binds exact targets without retaining credentials or query values', async () => {
  const evidence = await evidenceModule();
  const request = await requestFixture();
  assert.equal(request.method, 'GET');
  assert.equal(request.hostname, 'example.test');
  assert.equal(request.port, 443);
  assert.equal(request.credentialed, true);
  assert.equal(
    request.displayUrl,
    'https://example.test/npm/pkg.tgz?%3Credacted-key%3E=<redacted>&version=<redacted>',
  );
  assert.doesNotMatch(JSON.stringify(request), /password|secret|do-not-store|private-provider-id/);
  assert.match(request.requestTargetDigest, /^sha256:[a-f0-9]{64}$/);
  assert.deepEqual(evidence.validateHttpEvidenceRecord(request), request);

  assert.throws(
    () => evidence.validateHttpEvidenceRecord({ ...request, rawUrl: 'secret' }),
    /missing or unrecognized fields/,
  );
  assert.throws(
    () => evidence.createHttpRequestEvidence({
      ...request,
      displayUrl: 'https://example.test/npm/pkg.tgz?token=plaintext-secret',
    }),
    /query values must be redacted/,
  );
  const other = evidence.createHttpRequestEvidence({
    ...request,
    url: 'https://example.test/npm/other.tgz?version=1',
    displayUrl: undefined,
    requestTargetDigest: undefined,
  });
  assert.notEqual(other.requestTargetDigest, request.requestTargetDigest);
  assert.notEqual(
    evidence.httpRequestIdentityKey(other),
    evidence.httpRequestIdentityKey(request),
  );
  assert.throws(
    () => evidence.createHttpRequestEvidence({
      ...request,
      url: 'https://user:password@example.test/npm/pkg.tgz',
      displayUrl: undefined,
      requestTargetDigest: undefined,
      credentialed: false,
    }),
    /cannot contradict observed credentials/,
  );
  assert.throws(
    () => evidence.createHttpRequestEvidence({
      ...request,
      observedAt: '1969-12-31T23:59:59.999Z',
    }),
    /at or after the Unix epoch/,
  );
});

test('strict response, redirect, stats, NDJSON, and source descriptors fail closed', async () => {
  const evidence = await evidenceModule();
  const stable = await stableModule();
  const buildReview = await buildReviewModule();
  const request = await requestFixture();
  const collectorIdentity = await collectorIdentityFixture();
  const response = evidence.createHttpResponseEvidence({
    runId: request.runId,
    observedAt: at,
    provider: 'mitmproxy',
    exchangeId: request.exchangeId,
    status: 302,
    contentType: 'text/plain',
    contentEncoding: null,
    headersDigest: null,
    body: 'redirecting',
    decodedBody: 'redirecting',
    bodyComplete: true,
    delivery: 'observed',
    rangeResponse: false,
  });
  const redirect = evidence.createHttpRedirectEvidence({
    runId: request.runId,
    observedAt: at,
    provider: 'mitmproxy',
    exchangeId: request.exchangeId,
    status: 302,
    location: '/next?signature=private',
    baseUrl: 'https://example.test/npm/pkg.tgz',
  });
  assert.doesNotMatch(JSON.stringify(redirect), /private/);
  assert.equal(redirect.locationDigest, stable.sha256('/next?signature=private'));
  const stats = evidence.createHttpCaptureStats({
    runId: request.runId,
    observedAt: at,
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
    contentManifestDigest: null,
    ...collectorIdentity,
  });
  const content = Buffer.from(
    [request, response, redirect, stats].map((record) => JSON.stringify(record)).join('\n') + '\n',
    'utf8',
  );
  assert.equal(evidence.parseHttpEvidenceNdjson(content).length, 4);
  const source = evidence.createHttpEvidenceSourceDescriptor({
    file: 'raw/http.ndjson',
    content,
    expectedCollectorIdentity: collectorIdentity,
  });
  assert.deepEqual(source, {
    name: 'http',
    format: 'ndjson',
    file: 'raw/http.ndjson',
    required: true,
    present: true,
    complete: true,
    bytes: content.length,
    records: 4,
    hash: stable.sha256(content),
    lostEvents: 0,
    parseErrors: 0,
    completionMarker: 'nosh-http-capture-complete',
    content,
  });
  assert.deepEqual(evidence.httpDownstreamCorrelationHint(request), {
    exchangeId: request.exchangeId,
    pass: 'cold',
    timestampUnixNs: '1787400000000000000',
    source: { address: '172.18.0.3', port: 41_234 },
    destination: { ip: '172.18.0.2', protocol: 'tcp', port: 8080 },
  });
  const observations = evidence.createBuildHttpObservations(
    [request, response, redirect, stats],
    {
      pass: 'cold',
      destinationByExchangeId: {
        [request.exchangeId]: { ip: '172.18.0.2', protocol: 'tcp', port: 8080 },
      },
      destinationRoleByExchangeId: {
        [request.exchangeId]: 'workload-to-proxy',
      },
      upstreamDestinationByExchangeId: {
        [request.exchangeId]: { ip: '203.0.113.8', protocol: 'tcp', port: 443 },
      },
    },
  );
  assert.equal(observations.contractVersion, 2);
  assert.equal(observations.exchanges[0].displayUrl, 'https://example.test/npm/pkg.tgz');
  assert.equal(observations.exchanges[0].destinationRole, 'workload-to-proxy');
  assert.equal(
    observations.exchanges[0].response.redirectLocationSha256,
    stable.sha256('/next?signature=private'),
  );
  assert.deepEqual(
    buildReview.validateBuildHttpEvidence(observations),
    observations,
  );
  const redactedSegment = 'a'.repeat(48);
  const oversizedReviewRequest = evidence.createHttpRequestEvidence({
    ...request,
    url: `https://example.test/${Array(600).fill(redactedSegment).join('/')}`,
    displayUrl: undefined,
    requestTargetDigest: undefined,
  });
  const oversizedReviewResponse = evidence.createHttpResponseEvidence({
    ...response,
    exchangeId: oversizedReviewRequest.exchangeId,
  });
  assert.ok(oversizedReviewRequest.displayUrl.length <= 8192);
  assert.throws(
    () => evidence.createBuildHttpObservations([
      oversizedReviewRequest,
      oversizedReviewResponse,
      { ...stats, redirects: 0 },
    ]),
    /canonical HTTP review display URL exceeds/,
  );
  assert.throws(
    () => evidence.createHttpCaptureStats({ ...stats, coverageGaps: ['capture-error'] }),
    /complete HTTP capture stats/,
  );
  assert.throws(
    () => evidence.createHttpCaptureStats({ ...stats, complete: false }),
    /explicit coverage gap/,
  );
  assert.equal(evidence.createHttpCaptureStats({
    ...stats,
    complete: false,
    coverageGaps: ['interim-response'],
    contentAssuranceGaps: ['interim-response'],
  }).complete, false);
  assert.throws(
    () => evidence.createHttpEvidenceSourceDescriptor({
      file: '../escape.ndjson',
      content,
    }),
    /escapes or ambiguously names/,
  );
  assert.throws(
    () => evidence.parseHttpEvidenceNdjson(`${JSON.stringify(request)}\nnot-json\n`),
    /line 2 is not valid JSON/,
  );
  assert.throws(
    () => evidence.createHttpResponseEvidence({
      ...response,
      status: 206,
      rangeResponse: false,
    }),
    /must be marked as range responses/,
  );
});

test('Burp HAR import is sanitized, bounded, and permanently review-only', async () => {
  const evidence = await evidenceModule();
  const records = evidence.normalizeBurpHarImport({
    log: {
      version: '1.2',
      entries: [{
        startedDateTime: at,
        request: {
          method: 'GET',
          url: 'https://user:password@example.test/a.tgz?token=top-secret',
          headers: [
            { name: 'Accept', value: 'application/octet-stream' },
            { name: 'Cookie', value: 'session=private-cookie' },
          ],
        },
        response: {
          status: 302,
          headers: [{ name: 'Location', value: '/b.tgz?sig=redirect-secret' }],
          redirectURL: '/b.tgz?sig=redirect-secret',
          content: {
            mimeType: 'text/plain',
            encoding: 'base64',
            text: Buffer.from('redirect').toString('base64'),
          },
        },
      }],
    },
  }, {
    runId: 'burp-import-one',
    importedAt: at,
  });
  assert.deepEqual(records.map((record) => record.recordKind), [
    'http-request',
    'http-response',
    'http-redirect',
    'http-capture-stats',
  ]);
  assert.ok(records.every((record) => record.captureAuthority === 'review-only'));
  assert.equal(records.at(-1).complete, false);
  assert.deepEqual(records.at(-1).coverageGaps, [
    'incomplete-response-body',
    'manual-import',
  ]);
  assert.doesNotMatch(
    JSON.stringify(records),
    /password|top-secret|private-cookie|redirect-secret/,
  );
  assert.throws(
    () => evidence.normalizeBurpHarImport({ log: { entries: [{}, {}] } }, {
      runId: 'burp-too-many',
      importedAt: at,
      maximumEntries: 1,
    }),
    /entry import limit/,
  );

  const malformed = evidence.normalizeBurpHarImport({
    log: {
      entries: [{
        startedDateTime: at,
        request: { method: 'GET', url: 'https://example.test/a', headers: [] },
        response: {
          status: 200,
          headers: [],
          content: { text: 'too large' },
        },
      }],
    },
  }, {
    runId: 'burp-malformed-response',
    importedAt: at,
    maximumBodyBytes: 4,
  });
  assert.deepEqual(malformed.map((record) => record.recordKind), [
    'http-capture-stats',
  ]);
  assert.equal(malformed[0].requests, 0);
  assert.equal(malformed[0].responses, 0);
  assert.equal(malformed[0].errors, 1);
  assert.equal(evidence.createBuildHttpObservations(malformed).exchanges.length, 0);

  const ranged = evidence.normalizeBurpHarImport({
    log: {
      entries: [{
        startedDateTime: at,
        request: { method: 'GET', url: 'https://example.test/partial', headers: [] },
        response: {
          status: 206,
          headers: [{ name: 'Content-Range', value: 'bytes 0-3/10' }],
          content: { text: 'part' },
        },
      }],
    },
  }, {
    runId: 'burp-range-response',
    importedAt: at,
  });
  assert.ok(ranged.at(-1).coverageGaps.includes('range-response'));
  assert.equal(evidence.createBuildHttpObservations(ranged).complete, false);
});

test('content-addressed store is write-once, verified, and manifest-bound', async (t) => {
  const content = await contentModule();
  const evidence = await evidenceModule();
  const stable = await stableModule();
  const request = await requestFixture({ credentialed: false });
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'nosh-http-cas-'));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const store = new content.HttpContentStore({
    root,
    containmentRoot: path.dirname(root),
    maxObjectBytes: 1024 * 1024,
  });
  const object = await store.put(Buffer.from('reviewed bytes'));
  assert.equal(object.created, true);
  assert.equal((await store.put(Buffer.from('reviewed bytes'))).created, false);
  assert.deepEqual(await store.read(object.digest), Buffer.from('reviewed bytes'));
  assert.equal(fs.statSync(store.objectPath(object.digest)).mode & 0o777, 0o400);
  await assert.rejects(
    store.put(Buffer.from('different'), { expectedDigest: object.digest }),
    (error) => error.code === 'NOSH_HTTP_CONTENT_MISMATCH',
  );

  const selected = contentEntry(request, object);
  const manifest = content.createHttpContentManifest({
    runId: request.runId,
    generatedAt: at,
    mode: selected.mode,
    entries: [selected.entry],
  });
  const written = await store.writeManifest(manifest);
  assert.equal(written.created, true);
  assert.equal(
    fs.readFileSync(store.manifestPath(manifest.contentHash), 'utf8'),
    `${stable.stableStringify(manifest)}\n`,
  );
  assert.equal((await store.writeManifest(manifest)).created, false);
  assert.deepEqual(await store.readManifest(manifest.contentHash), manifest);

  const altered = structuredClone(manifest);
  altered.entries[0].response.bodyBytes += 1;
  assert.throws(
    () => content.verifyHttpContentManifest(altered),
    /not normalized or its hash is invalid/,
  );
  assert.throws(
    () => content.createHttpContentManifest({
      runId: request.runId,
      generatedAt: at,
      mode: selected.mode,
      entries: [{
        ...selected.entry,
        request: { ...selected.entry.request, credentialed: undefined },
      }],
    }),
    /explicit credentialed classification/,
  );
  const headRequest = evidence.createHttpRequestEvidence({
    ...request,
    method: 'HEAD',
  });
  assert.throws(
    () => content.createHttpContentManifest({
      runId: request.runId,
      generatedAt: at,
      mode: selected.mode,
      entries: [{ ...selected.entry, request: headRequest }],
    }),
    /HEAD responses cannot enter/,
  );
  assert.throws(
    () => content.createHttpContentManifest({
      runId: request.runId,
      generatedAt: at,
      mode: selected.mode,
      entries: [{
        ...selected.entry,
        response: { ...selected.entry.response, status: 304 },
      }],
    }),
    /304 responses cannot enter/,
  );
  for (const status of [101, 206]) {
    assert.throws(
      () => content.createHttpContentManifest({
        runId: request.runId,
        generatedAt: at,
        mode: selected.mode,
        entries: [{
          ...selected.entry,
          response: { ...selected.entry.response, status },
        }],
      }),
      status === 206
        ? /206 responses cannot enter/
        : /terminal status from 200 to 599/,
    );
  }
  assert.throws(
    () => new content.HttpContentStore({ root: '/', containmentRoot: '/' }),
    /must be a child of containmentRoot/,
  );

  const quotaRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'nosh-http-cas-quota-'));
  t.after(() => fs.rmSync(quotaRoot, { recursive: true, force: true }));
  const quotaStore = new content.HttpContentStore({
    root: quotaRoot,
    containmentRoot: path.dirname(quotaRoot),
    maxObjectBytes: 1024,
    maxTotalBytes: 4,
    maxObjects: 1,
  });
  await assert.rejects(
    quotaStore.put(Buffer.from('12345')),
    (error) => error.code === 'NOSH_HTTP_CONTENT_QUOTA',
  );

  const serializedRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'nosh-http-cas-serialized-'));
  t.after(() => fs.rmSync(serializedRoot, { recursive: true, force: true }));
  const serializedStore = new content.HttpContentStore({
    root: serializedRoot,
    containmentRoot: path.dirname(serializedRoot),
    maxObjectBytes: 1024,
    maxTotalBytes: 5,
    maxObjects: 1,
  });
  assert.equal((await serializedStore.put(Buffer.from('12345'))).created, true);
  assert.equal((await serializedStore.put(Buffer.from('12345'))).created, false);
  await assert.rejects(
    serializedStore.put(Buffer.from('x')),
    (error) => error.code === 'NOSH_HTTP_CONTENT_QUOTA',
  );

  const concurrentRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'nosh-http-cas-concurrent-'));
  t.after(() => fs.rmSync(concurrentRoot, { recursive: true, force: true }));
  const concurrentStore = new content.HttpContentStore({
    root: concurrentRoot,
    containmentRoot: path.dirname(concurrentRoot),
    maxObjectBytes: 1024,
    maxTotalBytes: 16,
    maxObjects: 1,
  });
  const concurrent = await Promise.allSettled([
    concurrentStore.put(Buffer.from('first')),
    concurrentStore.put(Buffer.from('second')),
  ]);
  assert.equal(concurrent.filter((result) => result.status === 'fulfilled').length, 1);
  assert.equal(concurrent.filter((result) => (
    result.status === 'rejected'
    && result.reason.code === 'NOSH_HTTP_CONTENT_QUOTA'
  )).length, 1);

  fs.chmodSync(store.objectPath(object.digest), 0o600);
  await assert.rejects(
    store.read(object.digest),
    /mode must be 400/,
  );
});

test('observe, offline replay, and live verification never weaken reviewed bytes', async (t) => {
  const content = await contentModule();
  const evidence = await evidenceModule();
  const request = await requestFixture({ credentialed: false });
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'nosh-http-gate-'));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const store = new content.HttpContentStore({
    root,
    containmentRoot: path.dirname(root),
    maxObjectBytes: 1024 * 1024,
  });

  const observe = new content.HttpContentGate({
    mode: 'observe',
    store,
    persistObserved: true,
    maximumBytes: 1024,
  });
  const observed = await observe.process({
    request,
    responseBody: (async function *stream() {
      yield 'reviewed ';
      yield 'bytes';
    }()),
  });
  assert.equal(observed.action, 'observed');
  assert.equal(observed.persisted, true);
  assert.deepEqual(await store.read(observed.bodyDigest), Buffer.from('reviewed bytes'));

  const selected = contentEntry(request, {
    digest: observed.bodyDigest,
    bytes: observed.bodyBytes,
  });
  const replayManifest = content.createHttpContentManifest({
    runId: request.runId,
    generatedAt: at,
    mode: 'offline-replay',
    entries: [selected.entry],
  });
  const replay = new content.HttpContentGate({
    mode: 'offline-replay',
    store,
    manifest: replayManifest,
  });
  const replayed = await replay.process({ request });
  assert.equal(replayed.action, 'replayed');
  assert.deepEqual(replayed.body, Buffer.from('reviewed bytes'));
  await assert.rejects(
    replay.process({ request, responseBody: Buffer.from('origin bytes') }),
    (error) => error.code === 'NOSH_HTTP_OFFLINE_ORIGIN_CONTACT',
  );
  const changedRequest = evidence.createHttpRequestEvidence({
    ...request,
    url: 'https://example.test/npm/other.tgz',
    displayUrl: undefined,
    requestTargetDigest: undefined,
  });
  await assert.rejects(
    replay.process({ request: changedRequest }),
    (error) => error.code === 'NOSH_HTTP_POLICY_MISS',
  );

  const liveManifest = content.createHttpContentManifest({
    runId: request.runId,
    generatedAt: at,
    mode: 'live-buffer-verify',
    entries: [selected.entry],
  });
  const live = new content.HttpContentGate({
    mode: 'live-buffer-verify',
    store,
    manifest: liveManifest,
  });
  const verified = await live.process({
    request,
    status: 200,
    contentType: 'application/octet-stream',
    contentEncoding: null,
    location: null,
    responseBody: Buffer.from('reviewed bytes'),
  });
  assert.equal(verified.action, 'verified');
  await assert.rejects(
    live.process({
      request,
      status: 200,
      contentType: 'application/octet-stream',
      contentEncoding: null,
      location: null,
      responseBody: Buffer.from('timebomb replacement'),
    }),
    (error) => error.code === 'NOSH_HTTP_CONTENT_MISMATCH',
  );
});

test('managed mitmproxy boundary is pinned, syntactically valid, and self-tests redaction', () => {
  const wrapper = path.join(appRoot, 'scripts/nosh-mitmproxy-capture.sh');
  const addon = path.join(appRoot, 'scripts/nosh-mitmproxy-addon.py');
  assert.equal(spawnSync('bash', ['-n', wrapper]).status, 0);
  const image = spawnSync(wrapper, ['--print-image'], { encoding: 'utf8' });
  assert.equal(image.status, 0);
  assert.equal(
    image.stdout.trim(),
    'mitmproxy/mitmproxy:12.2.3@sha256:00b77b5d8804c8ad18cb6caefbf9d5849e895e8986c5ce011f4ae30f4385962f',
  );
  const selfTest = spawnSync('python3', [addon, '--self-test'], { encoding: 'utf8' });
  assert.equal(selfTest.status, 0, selfTest.stderr);
  const addonSource = fs.readFileSync(addon, 'utf8');
  assert.match(addonSource, /flow\.metadata\["nosh_manifest_entry"\] = entry/);
  assert.match(addonSource, /if self\.mode != "offline-replay":\s+return/);
  assert.match(addonSource, /flow\.response = self\._response_from_entry\(entry, raw_body\)/);
  assert.doesNotMatch(addonSource, /flow\.response = response\s*$/m);
});

test('HTTP evidence and content manifests publish strict standalone schemas', () => {
  for (const filename of [
    'http-exchange-evidence.schema.json',
    'http-content-manifest.schema.json',
  ]) {
    const schema = JSON.parse(fs.readFileSync(path.join(
      appRoot,
      'config/nosh-guard/schemas',
      filename,
    ), 'utf8'));
    assert.equal(schema.$schema, 'https://json-schema.org/draft/2020-12/schema');
    assert.match(schema.$id, /^https:\/\/notty\.dev\/schemas\/nosh-guard\//);
    if (schema.type === 'object') assert.equal(schema.additionalProperties, false);
    if (filename === 'http-content-manifest.schema.json') {
      assert.equal(schema.$defs.response.properties.status.minimum, 200);
      assert.deepEqual(
        schema.$defs.response.properties.status.not.enum,
        [206, 304],
      );
    }
  }
});
