'use strict';

const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const test = require('node:test');
const { pathToFileURL } = require('node:url');

const appRoot = path.resolve(__dirname, '..');
const parentObservationReason =
  'collector did not observe activity below the builder cgroup';
const legacyParentObservationReason =
  'collector did not observe its parent';

async function artifactsModule() {
  return import(pathToFileURL(
    path.join(appRoot, 'lib/guardd/build-profile-artifacts.js'),
  ).href);
}

async function stableModule() {
  return import(pathToFileURL(
    path.join(appRoot, 'lib/guard/stable.js'),
  ).href);
}

function digest(value) {
  return `sha256:${crypto.createHash('sha256').update(value).digest('hex')}`;
}

function project(t) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'nosh-build-artifacts-'));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const stat = fs.statSync(root, { bigint: true });
  return {
    canonicalPath: root,
    dev: String(stat.dev),
    ino: String(stat.ino),
  };
}

async function completeInput(t, overrides = {}) {
  const module = await artifactsModule();
  const mode = overrides.mode || 'build-profile';
  const depth = overrides.depth || 'balanced';
  const sources = module.requiredBuildEvidenceSources(mode, depth).map((name) => ({
    name,
    format: 'ndjson',
    file: `raw/${name}.ndjson`,
    required: true,
    present: true,
    complete: true,
    bytes: 3,
    records: 1,
    hash: digest(name),
    lostEvents: 0,
    parseErrors: 0,
    completionMarker: 'clean-supervised-stop',
  }));
  const network = mode === 'build-net-learn';
  return {
    runId: overrides.runId || 'build-one',
    mode,
    generatedAt: '2026-08-10T00:00:02.000Z',
    startedAt: '2026-08-10T00:00:00.000Z',
    endedAt: '2026-08-10T00:00:02.000Z',
    project: project(t),
    builder: {
      id: 'nosh-build-one',
      containerId: 'builder-container',
      image: 'moby/buildkit:test',
      imageDigest: `sha256:${'a'.repeat(64)}`,
      pid: 123,
      cgroup: '/docker/builder-container',
      dockerEndpoint: 'unix:///var/run/docker.sock',
    },
    build: {
      success: true,
      exitCode: 0,
      platform: 'linux/amd64',
      cacheMode: network ? 'cold' : 'compare',
      depth,
      outputImageDigest: `sha256:${'b'.repeat(64)}`,
      configDigest: `sha256:${'c'.repeat(64)}`,
      passes: network
        ? [{ name: 'cold', success: true, exitCode: 0, durationMs: 2_000 }]
        : [
            { name: 'cold', success: true, exitCode: 0, durationMs: 2_000 },
            { name: 'warm', success: true, exitCode: 0, durationMs: 500 },
          ],
    },
    coverage: {
      builderIdentityStable: true,
      exclusiveBuilderLease: true,
      parentObserved: true,
      cleanupComplete: true,
      freshBuilder: network,
      forcedSourcePulls: network,
      cacheImportsDisabled: network,
      allReachableStepsExecuted: network,
    },
    sources,
    metrics: { cpu: { totalUsec: 20 }, raw: 'must disappear' },
    observations: {
      command: 'RUN printf secret',
      path: '/workspace/private/Dockerfile',
      provenance: { sourceHost: 'registry.example.test' },
      network: {
        destinations: [
          {
            ip: '203.0.113.8',
            protocol: 'TCP',
            port: 443,
            source: 'nosh-l4',
          },
          {
            ip: '203.0.113.8',
            protocol: 'tcp',
            port: 443,
            source: 'nosh-l4',
          },
        ],
        directIp: [{ ip: '203.0.113.8', protocol: 'tcp', port: 443 }],
        encryptedDns: [],
        privateDestinations: [],
        parseFailures: [],
        unresolved: [],
      },
    },
    ...overrides,
  };
}

function buildNetworkObservationFixture() {
  const queryId = 'cold:udp53:77:4660:53000:10.0.0.53:53:dns-query:1100';
  const snapshotId = 'cold:udp53:77:4660:53000:10.0.0.53:53:dns-response:1200';
  const destination = {
    fqdn: 'registry.example.test',
    ip: '203.0.113.8',
    protocol: 'tcp',
    port: 443,
    source: 'nosh-build-dns+nosh-l4',
  };
  const destinationKey = JSON.stringify(destination);
  const resolverDestination = {
    fqdn: null,
    ip: '10.0.0.53',
    protocol: 'udp',
    port: 53,
    source: 'nosh-l4',
  };
  const process = { pid: 42, comm: 'git-remote-http' };
  const resourceOneId = `url:${digest(JSON.stringify([
    'cold', '900', '800', '801', 42, 43,
    'https', 'registry.example.test', 443,
  ]))}`;
  const resourceTwoId = `url:${digest(JSON.stringify([
    'cold', '900', '800', '801', 42, 44,
    'https', '203.0.113.8', 443,
  ]))}`;
  return {
    destinations: [destination, resolverDestination],
    dns: {
      queries: [{
        id: queryId,
        pass: 'cold',
        timestampNs: '1100',
        transport: 'udp',
        qname: 'registry.example.test',
        queryType: 1,
        queryClass: 1,
        resolver: { address: '10.0.0.53', port: 53 },
        clientPort: 53_000,
        socketCookie: '77',
        transactionId: 4_660,
        correlationComplete: true,
      }],
      answers: [{
        snapshotId,
        queryId,
        pass: 'cold',
        index: 0,
        ownerName: 'registry.example.test',
        type: 1,
        class: 1,
        ttl: 60,
        valueKind: 'ipv4',
        value: '203.0.113.8',
      }],
      snapshots: [{
        id: snapshotId,
        queryId,
        pass: 'cold',
        timestampNs: '1200',
        socketCookie: '77',
        transactionId: 4_660,
        clientPort: 53_000,
        queryTimestampNs: '1100',
        qname: 'registry.example.test',
        queryType: 1,
        queryClass: 1,
        resolver: { address: '10.0.0.53', port: 53 },
        correlationComplete: true,
        responseCode: 0,
        truncated: false,
        parseComplete: true,
        answerLimitReached: false,
        answersDeclared: 1,
        answersCaptured: 1,
        cnameChain: ['registry.example.test'],
        addresses: [{
          address: '203.0.113.8',
          family: 'ipv4',
          ownerName: 'registry.example.test',
          ttl: 60,
        }],
      }],
    },
    resources: [{
      id: resourceOneId,
      provider: 'libcurl',
      scheme: 'https',
      host: 'registry.example.test',
      port: 443,
      path: '/repository.git/info/refs',
      pathTruncated: false,
      process: process.comm,
      pid: process.pid,
      tid: 43,
      timestampUnixNs: '1000',
      timestampMonotonicNs: '900',
      targetCgroupId: '800',
      cgroupId: '801',
      pass: 'cold',
      source: 'nosh-url',
    }, {
      id: resourceTwoId,
      provider: 'libcurl',
      scheme: 'https',
      host: '203.0.113.8',
      port: 443,
      path: '/direct-resource',
      pathTruncated: false,
      process: process.comm,
      pid: process.pid,
      tid: 44,
      timestampUnixNs: '1000',
      timestampMonotonicNs: '900',
      targetCgroupId: '800',
      cgroupId: '801',
      pass: 'cold',
      source: 'nosh-url',
    }],
    correlations: [{
      kind: 'dns-destination',
      pass: 'cold',
      snapshotId,
      queryId,
      qname: 'registry.example.test',
      ownerName: 'registry.example.test',
      address: '203.0.113.8',
      protocol: 'tcp',
      port: 443,
      destinationKey,
      process,
      timestampNs: '1300',
    }, {
      kind: 'dns-query-process',
      correlationConfidence: 'heuristic-socket-resolver-bounded-time',
      pass: 'cold',
      queryId,
      socketCookie: '77',
      clientPort: 53_000,
      qname: 'registry.example.test',
      resolver: { address: '10.0.0.53', port: 53 },
      process,
      timestampNs: '1100',
      attemptTimestampNs: '1050',
    }, {
      kind: 'resource-dns-query',
      correlationConfidence: 'heuristic-same-pid-host-bounded-time',
      pass: 'cold',
      resourceId: resourceOneId,
      provider: 'libcurl',
      host: 'registry.example.test',
      queryId,
      qname: 'registry.example.test',
      resolver: { address: '10.0.0.53', port: 53 },
      resourceTimestampUnixNs: '1000',
      queryTimestampNs: '1100',
      resourceProcess: process,
      dnsProcess: process,
    }, {
      kind: 'resource-destination',
      correlationConfidence: 'heuristic-same-pid-host-port-bounded-time',
      pass: 'cold',
      resourceId: resourceOneId,
      provider: 'libcurl',
      host: 'registry.example.test',
      snapshotId,
      queryId,
      qname: 'registry.example.test',
      ownerName: 'registry.example.test',
      address: '203.0.113.8',
      protocol: 'tcp',
      port: 443,
      destinationKey,
      resourceTimestampUnixNs: '1000',
      destinationTimestampNs: '1300',
      resourceProcess: process,
      networkProcess: process,
    }, {
      kind: 'resource-direct-destination',
      correlationConfidence: 'heuristic-direct-ip-same-pid-port-bounded-time',
      pass: 'cold',
      resourceId: resourceTwoId,
      provider: 'libcurl',
      host: '203.0.113.8',
      address: '203.0.113.8',
      protocol: 'tcp',
      port: 443,
      destinationKey,
      resourceTimestampUnixNs: '1000',
      destinationTimestampNs: '1300',
      resourceProcess: process,
      networkProcess: process,
    }],
    coverage: {
      dns: {
        queries: 1,
        responses: 1,
        answers: 1,
        transactionMisses: 0,
        parseFailures: 0,
        complete: true,
      },
      url: {
        enabled: true,
        providers: ['libcurl'],
        observations: 2,
        discoveryMisses: 0,
        readErrors: 0,
        complete: false,
        limitations: ['observational only'],
      },
    },
    directIp: [destination],
    encryptedDns: [],
    privateDestinations: [],
    parseFailures: [],
    unresolved: [],
  };
}

test('complete compare evidence produces an unapproved build candidate', async (t) => {
  const module = await artifactsModule();
  const manifest = module.createBuildEvidenceManifest(await completeInput(t));
  assert.equal(manifest.kind, 'NoshBuildEvidenceManifest');
  assert.equal(manifest.complete, true);
  assert.equal(manifest.candidateEligible, true);
  assert.equal(manifest.attestation.attested, false);

  const candidate = module.createBuildProfileCandidate(manifest);
  assert.equal(candidate.kind, 'NoshBuildProfileCandidate');
  assert.equal(candidate.approved, false);
  assert.equal(candidate.authoritative, false);
  assert.equal(candidate.spec.outputImageDigestUse, 'informational-only');
  assert.match(candidate.contentHash, /^sha256:[a-f0-9]{64}$/);
  assert.equal(module.verifyBuildCandidate(candidate, manifest), candidate);
});

test('new parent-observation failures use the current schema-v1 wording', async (t) => {
  const module = await artifactsModule();
  const input = await completeInput(t);
  input.coverage.parentObserved = false;
  const manifest = module.createBuildEvidenceManifest(input);

  assert.deepEqual(manifest.incompleteReasons, [parentObservationReason]);
  assert.deepEqual(manifest.candidateIneligibleReasons, [parentObservationReason]);
});

test('schema-v1 validation accepts the legacy parent-observation wording unchanged', async (t) => {
  const module = await artifactsModule();
  const input = await completeInput(t);
  input.coverage.parentObserved = false;
  const manifest = module.createBuildEvidenceManifest(input);
  const legacy = structuredClone(manifest);
  for (const field of ['incompleteReasons', 'candidateIneligibleReasons']) {
    legacy[field] = legacy[field].map((reason) =>
      reason === parentObservationReason ? legacyParentObservationReason : reason);
  }
  const before = JSON.stringify(legacy);

  assert.equal(module.validateBuildEvidenceManifest(legacy), legacy);
  assert.equal(JSON.stringify(legacy), before);
});

test('legacy parent-observation compatibility does not mask other derived-state tampering', async (t) => {
  const module = await artifactsModule();
  const input = await completeInput(t);
  input.coverage.parentObserved = false;
  const tampered = structuredClone(module.createBuildEvidenceManifest(input));
  for (const field of ['incompleteReasons', 'candidateIneligibleReasons']) {
    tampered[field] = tampered[field].map((reason) =>
      reason === parentObservationReason ? legacyParentObservationReason : reason);
  }
  tampered.complete = true;

  assert.throws(
    () => module.validateBuildEvidenceManifest(tampered),
    /build evidence manifest fields or derived state are invalid/,
  );
});

test('policy depth requires file evidence without changing deep requirements', async (t) => {
  const module = await artifactsModule();
  const balanced = module.requiredBuildEvidenceSources('build-profile', 'balanced');
  const policy = module.requiredBuildEvidenceSources('build-profile', 'policy');
  const deep = module.requiredBuildEvidenceSources('build-profile', 'deep');

  assert.equal(balanced.includes('ebpf-file'), false);
  assert.deepEqual(policy, [...balanced, 'ebpf-file']);
  assert.ok(deep.includes('ebpf-file'));
  assert.ok(deep.includes('ebpf-offcpu'));
  assert.ok(deep.includes('ebpf-block'));

  const input = await completeInput(t, { runId: 'policy-one', depth: 'policy' });
  input.sources = input.sources.filter((source) => source.name !== 'ebpf-file');
  const manifest = module.createBuildEvidenceManifest(input);
  assert.equal(manifest.complete, false);
  assert.match(manifest.incompleteReasons.join('\n'), /ebpf-file/);
});

test('warm-only and lost-event evidence never advances a candidate', async (t) => {
  const module = await artifactsModule();
  const warm = await completeInput(t, { runId: 'warm-one' });
  warm.build.cacheMode = 'warm';
  warm.build.passes = [
    { name: 'warm', success: true, exitCode: 0, durationMs: 250 },
  ];
  const warmManifest = module.createBuildEvidenceManifest(warm);
  assert.equal(warmManifest.complete, true);
  assert.equal(warmManifest.candidateEligible, false);
  assert.match(warmManifest.candidateIneligibleReasons.join('\n'), /warm-only/);
  assert.throws(
    () => module.createBuildProfileCandidate(warmManifest),
    /complete eligible build evidence/,
  );

  const lost = await completeInput(t, { runId: 'lost-one' });
  lost.sources[0].lostEvents = 3;
  const lostManifest = module.createBuildEvidenceManifest(lost);
  assert.equal(lostManifest.complete, false);
  assert.equal(lostManifest.candidateEligible, false);
  assert.match(lostManifest.incompleteReasons.join('\n'), /lost events/);
});

test('network learning has an independent kind and retains unresolved evidence', async (t) => {
  const module = await artifactsModule();
  const manifest = module.createBuildEvidenceManifest(await completeInput(t, {
    runId: 'network-one',
    mode: 'build-net-learn',
  }));
  const candidate = module.createBuildNetworkCandidate(manifest);
  assert.equal(candidate.kind, 'NoshBuildNetworkCandidate');
  assert.deepEqual(candidate.spec.observations.destinations, [
    {
      fqdn: null,
      ip: '203.0.113.8',
      protocol: 'tcp',
      port: 443,
      source: 'nosh-l4',
    },
  ]);
  assert.deepEqual(candidate.spec.observations.directIp, [
    { ip: '203.0.113.8', protocol: 'tcp', port: 443 },
  ]);
  assert.throws(
    () => module.createBuildProfileCandidate(manifest),
    /requires build-profile evidence/,
  );
});

test('build network v2 binds immutable evidence to an editable policy draft', async (t) => {
  const module = await artifactsModule();
  const { serializeJson, stableStringify } = await stableModule();
  const input = await completeInput(t, {
    runId: 'network-v2-binding',
    mode: 'build-net-learn',
  });
  input.observations.network = buildNetworkObservationFixture();

  const manifest = module.createBuildEvidenceManifest(input);
  const candidate = module.createBuildNetworkCandidate(manifest);
  const draft = module.createBuildNetworkPolicyDraft(candidate);
  assert.equal(candidate.spec.observations.evidenceContractVersion, 2);
  assert.equal(candidate.spec.observations.dns.queries.length, 1);
  assert.equal(candidate.spec.observations.dns.answers.length, 1);
  assert.equal(candidate.spec.observations.dns.snapshots.length, 1);
  assert.notEqual(
    candidate.spec.observations.dns.snapshots[0].id,
    candidate.spec.observations.dns.snapshots[0].queryId,
  );
  assert.equal(
    candidate.spec.observations.dns.answers[0].snapshotId,
    candidate.spec.observations.dns.snapshots[0].id,
  );
  assert.equal(candidate.spec.observations.correlations.length, 5);
  assert.equal(candidate.spec.observations.coverage.dns.complete, true);
  assert.equal(
    candidate.evidence.manifestHash,
    digest(serializeJson(manifest)),
  );
  const unsignedCandidate = structuredClone(candidate);
  delete unsignedCandidate.contentHash;
  assert.equal(candidate.contentHash, digest(stableStringify(unsignedCandidate)));
  assert.deepEqual(draft.source, {
    runId: manifest.runId,
    candidateHash: candidate.contentHash,
    evidenceManifestHash: candidate.evidence.manifestHash,
  });
  const portable = module.portableBuildProjection(manifest, candidate);
  const privateResourceId = candidate.spec.observations.resources.find((entry) =>
    entry.host === 'registry.example.test').id;
  assert.equal(
    portable.candidate.spec.observations.correlations.find((entry) =>
      entry.kind === 'resource-dns-query').resourceId,
    privateResourceId,
  );

  const edited = structuredClone(draft);
  edited.rules[0].decision = 'allow';
  edited.notes.push('operator narrowed and accepted this destination');
  assert.equal(module.validateBuildNetworkPolicyDraft(edited, candidate), edited);

  const wrongCandidate = structuredClone(edited);
  wrongCandidate.source.candidateHash = `sha256:${'0'.repeat(64)}`;
  assert.throws(
    () => module.validateBuildNetworkPolicyDraft(wrongCandidate, candidate),
    /identity or evidence binding is invalid/,
  );
  const wrongEvidence = structuredClone(edited);
  wrongEvidence.source.evidenceManifestHash = `sha256:${'1'.repeat(64)}`;
  assert.throws(
    () => module.validateBuildNetworkPolicyDraft(wrongEvidence, candidate),
    /identity or evidence binding is invalid/,
  );
});

test('build network records reject unrecognized fields at the immutable boundary', async (t) => {
  const module = await artifactsModule();
  const cases = [
    ['query', (network) => network.dns.queries[0], 'authorization'],
    ['answer', (network) => network.dns.answers[0], 'password'],
    ['snapshot', (network) => network.dns.snapshots[0], 'headers'],
    ['correlation', (network) => network.correlations[0], 'accessToken'],
  ];

  for (const [label, select, field] of cases) {
    const input = await completeInput(t, {
      runId: `network-extra-${label}`,
      mode: 'build-net-learn',
    });
    input.observations.network = buildNetworkObservationFixture();
    select(input.observations.network)[field] = 'must-not-enter-the-candidate';
    assert.throws(
      () => module.createBuildEvidenceManifest(input),
      /unsupported fields/,
    );
  }
});

test('DNS query correlations require exact complete bounded resolver evidence', async (t) => {
  const module = await artifactsModule();
  const cases = [
    ['query-id', (network) => { network.dns.queries[0].id = 'forged-query-id'; }],
    ['snapshot-id', (network) => {
      network.dns.snapshots[0].id = 'forged-snapshot-id';
    }],
    ['query-resolver-port', (network) => {
      network.dns.queries[0].resolver.port = 0;
    }],
    ['snapshot-resolver-port', (network) => {
      network.dns.snapshots[0].resolver.port = 5_353;
    }],
    ['query-zero-cookie-complete', (network) => {
      network.dns.queries[0].socketCookie = '0';
    }],
    ['query-nonzero-cookie-incomplete', (network) => {
      network.dns.queries[0].correlationComplete = false;
    }],
    ['snapshot-zero-cookie-complete', (network) => {
      network.dns.snapshots[0].socketCookie = '0';
    }],
    ['missing-query', (network) => { network.dns.queries = []; }],
    ['duplicate-query-id', (network) => {
      network.dns.queries.push(structuredClone(network.dns.queries[0]));
    }],
    ['snapshot-socket', (network) => { network.dns.snapshots[0].socketCookie = '78'; }],
    ['query-client-port', (network) => {
      network.correlations.find((entry) =>
        entry.kind === 'dns-query-process').clientPort = 53_001;
    }],
    ['query-attempt-order', (network) => {
      network.correlations.find((entry) =>
        entry.kind === 'dns-query-process').attemptTimestampNs = '1101';
    }],
    ['query-attempt-window', (network) => {
      network.dns.queries[0].timestampNs = '30000001101';
      network.dns.snapshots[0].queryTimestampNs = '30000001101';
      network.correlations.find((entry) =>
        entry.kind === 'dns-query-process').timestampNs = '30000001101';
    }],
    ['missing-resolver-destination', (network) => {
      network.destinations = network.destinations.filter((entry) => entry.port !== 53);
    }],
  ];

  for (const [label, mutate] of cases) {
    const input = await completeInput(t, {
      runId: `network-query-relation-${label}`,
      mode: 'build-net-learn',
    });
    input.observations.network = buildNetworkObservationFixture();
    mutate(input.observations.network);
    assert.throws(
      () => module.createBuildEvidenceManifest(input),
      /DNS (?:query|answer snapshot) (?:id must match|resolver port must be 53|correlationComplete must exactly match)|DNS queries contain a duplicate|complete DNS answer snapshot|dns-query-process correlation/,
      label,
    );
  }
});

test('DNS destination correlations require complete untruncated TTL-valid answers', async (t) => {
  const module = await artifactsModule();
  const cases = [
    ['incomplete-snapshot', (network) => {
      network.dns.snapshots[0].correlationComplete = false;
      network.dns.snapshots[0].queryId = null;
      network.dns.snapshots[0].queryTimestampNs = null;
    }],
    ['incomplete-snapshot-query-claim', (network) => {
      network.dns.snapshots[0].correlationComplete = false;
    }],
    ['response-code', (network) => { network.dns.snapshots[0].responseCode = 2; }],
    ['answer-type', (network) => { network.dns.answers[0].type = 28; }],
    ['answer-class', (network) => { network.dns.answers[0].class = 3; }],
    ['query-class', (network) => {
      network.dns.queries[0].queryClass = 3;
      network.dns.snapshots[0].queryClass = 3;
    }],
    ['query-address-family', (network) => {
      network.dns.queries[0].queryType = 28;
      network.dns.snapshots[0].queryType = 28;
    }],
    ['truncated', (network) => { network.dns.snapshots[0].truncated = true; }],
    ['parse-incomplete', (network) => { network.dns.snapshots[0].parseComplete = false; }],
    ['answer-limit', (network) => {
      network.dns.snapshots[0].answerLimitReached = true;
    }],
    ['answer-count', (network) => { network.dns.snapshots[0].answersDeclared = 2; }],
    ['captured-answer-count', (network) => {
      network.dns.snapshots[0].answersDeclared = 2;
      network.dns.snapshots[0].answersCaptured = 2;
    }],
    ['answer-index-gap', (network) => { network.dns.answers[0].index = 1; }],
    ['address', (network) => { network.dns.snapshots[0].addresses = []; }],
    ['duplicate-address', (network) => {
      network.dns.snapshots[0].addresses.push(
        structuredClone(network.dns.snapshots[0].addresses[0]),
      );
    }],
    ['answer-query', (network) => {
      network.dns.answers[0].queryId = 'missing-query';
    }],
    ['duplicate-snapshot-id', (network) => {
      network.dns.snapshots.push(structuredClone(network.dns.snapshots[0]));
    }],
    ['duplicate-answer-index', (network) => {
      network.dns.answers.push(structuredClone(network.dns.answers[0]));
    }],
    ['answer-snapshot', (network) => {
      network.dns.answers[0].snapshotId = 'missing-snapshot';
    }],
    ['destination-snapshot', (network) => {
      network.correlations.find((entry) =>
        entry.kind === 'dns-destination').snapshotId = 'missing-snapshot';
    }],
    ['pre-response-attempt', (network) => {
      network.correlations.find((entry) =>
        entry.kind === 'dns-destination').timestampNs = '1199';
    }],
    ['expired-attempt', (network) => {
      network.correlations.find((entry) =>
        entry.kind === 'dns-destination').timestampNs = '60000001201';
    }],
    ['zero-ttl', (network) => {
      network.dns.answers[0].ttl = 0;
      network.dns.snapshots[0].addresses[0].ttl = 0;
      network.correlations.find((entry) =>
        entry.kind === 'dns-destination').timestampNs = '1200';
    }],
    ['nonterminal-address', (network) => {
      const snapshot = network.dns.snapshots[0];
      network.dns.answers = [{
        snapshotId: snapshot.id,
        queryId: snapshot.queryId,
        pass: 'cold',
        index: 0,
        ownerName: 'registry.example.test',
        type: 5,
        class: 1,
        ttl: 1,
        valueKind: 'cname',
        value: 'alias.example.test',
      }, {
        snapshotId: snapshot.id,
        queryId: snapshot.queryId,
        pass: 'cold',
        index: 1,
        ownerName: 'registry.example.test',
        type: 1,
        class: 1,
        ttl: 300,
        valueKind: 'ipv4',
        value: '203.0.113.8',
      }];
      snapshot.answersDeclared = 2;
      snapshot.answersCaptured = 2;
      snapshot.cnameChain = [
        'registry.example.test',
        'alias.example.test',
      ];
      snapshot.addresses[0].ttl = 300;
    }],
    ['shortened-cname-chain', (network) => {
      const snapshot = network.dns.snapshots[0];
      network.dns.answers = [{
        snapshotId: snapshot.id,
        queryId: snapshot.queryId,
        pass: 'cold',
        index: 0,
        ownerName: 'registry.example.test',
        type: 5,
        class: 1,
        ttl: 1,
        valueKind: 'cname',
        value: 'alias.example.test',
      }, {
        snapshotId: snapshot.id,
        queryId: snapshot.queryId,
        pass: 'cold',
        index: 1,
        ownerName: 'registry.example.test',
        type: 1,
        class: 1,
        ttl: 300,
        valueKind: 'ipv4',
        value: '203.0.113.8',
      }];
      snapshot.answersDeclared = 2;
      snapshot.answersCaptured = 2;
      snapshot.cnameChain = ['registry.example.test'];
      snapshot.addresses[0].ttl = 300;
    }],
    ['duplicate-cname-owner', (network) => {
      network.dns.answers.push({
        snapshotId: network.dns.snapshots[0].id,
        queryId: network.dns.queries[0].id,
        pass: 'cold',
        index: 1,
        ownerName: 'alias.example.test',
        type: 5,
        class: 1,
        ttl: 60,
        valueKind: 'cname',
        value: 'first.example.test',
      }, {
        snapshotId: network.dns.snapshots[0].id,
        queryId: network.dns.queries[0].id,
        pass: 'cold',
        index: 2,
        ownerName: 'alias.example.test',
        type: 5,
        class: 1,
        ttl: 60,
        valueKind: 'cname',
        value: 'second.example.test',
      });
    }],
  ];

  for (const [label, mutate] of cases) {
    const input = await completeInput(t, {
      runId: `network-dns-relation-${label}`,
      mode: 'build-net-learn',
    });
    input.observations.network = buildNetworkObservationFixture();
    mutate(input.observations.network);
    assert.throws(
      () => module.createBuildEvidenceManifest(input),
      /DNS answer type, valueKind, and class|DNS (?:answer snapshots|answers) contain a duplicate|DNS answer snapshot query identity|DNS answer does not reference|DNS snapshot answers must exactly match|DNS answers contain more than one CNAME|dns-destination correlation/,
      label,
    );
  }
});

test('ambiguous DNS chains remain evidence but cannot back destination authority', async (t) => {
  const module = await artifactsModule();
  const cases = [
    ['duplicate-owner', [{
      ownerName: 'registry.example.test',
      value: 'alias.example.test',
    }, {
      ownerName: 'registry.example.test',
      value: 'other.example.test',
    }], ['registry.example.test', 'alias.example.test']],
    ['cycle', [{
      ownerName: 'registry.example.test',
      value: 'alias.example.test',
    }, {
      ownerName: 'alias.example.test',
      value: 'registry.example.test',
    }], ['registry.example.test', 'alias.example.test']],
  ];

  for (const [label, cnameAnswers, cnameChain] of cases) {
    const input = await completeInput(t, {
      runId: `network-diagnostic-cname-${label}`,
      mode: 'build-net-learn',
    });
    const network = buildNetworkObservationFixture();
    const snapshot = network.dns.snapshots[0];
    network.dns.answers.push(...cnameAnswers.map((answer, offset) => ({
      snapshotId: snapshot.id,
      queryId: snapshot.queryId,
      pass: snapshot.pass,
      index: offset + 1,
      ownerName: answer.ownerName,
      type: 5,
      class: 1,
      ttl: 1,
      valueKind: 'cname',
      value: answer.value,
    })));
    snapshot.answersDeclared = 3;
    snapshot.answersCaptured = 3;
    snapshot.cnameChain = cnameChain;
    network.coverage.dns.answers = 3;
    network.correlations = network.correlations.filter((entry) => ![
      'dns-destination',
      'resource-destination',
    ].includes(entry.kind));
    const destination = network.destinations.find((entry) => entry.port === 443);
    const previousDestinationKey = JSON.stringify(destination);
    destination.fqdn = null;
    destination.source = 'nosh-l4';
    const destinationKey = JSON.stringify(destination);
    for (const correlation of network.correlations) {
      if (correlation.destinationKey === previousDestinationKey) {
        correlation.destinationKey = destinationKey;
      }
    }
    input.observations.network = network;

    const manifest = module.createBuildEvidenceManifest(input);
    const candidate = module.createBuildNetworkCandidate(manifest);
    assert.equal(candidate.spec.observations.dns.answers.length, 3, label);
    assert.equal(
      candidate.spec.observations.correlations.some((entry) => [
        'dns-destination',
        'resource-destination',
      ].includes(entry.kind)),
      false,
      label,
    );
    assert.equal(candidate.spec.observations.destinations[0].fqdn, null, label);
  }
});

test('non-address DNS queries remain evidence but cannot back destination authority', async (t) => {
  const module = await artifactsModule();
  const input = await completeInput(t, {
    runId: 'network-non-address-query',
    mode: 'build-net-learn',
  });
  input.observations.network = buildNetworkObservationFixture();
  input.observations.network.dns.queries[0].queryType = 16;
  input.observations.network.dns.snapshots[0].queryType = 16;
  input.observations.network.correlations =
    input.observations.network.correlations.filter((entry) => ![
      'dns-destination',
      'resource-destination',
    ].includes(entry.kind));
  const destination = input.observations.network.destinations.find((entry) =>
    entry.port === 443);
  const previousDestinationKey = JSON.stringify(destination);
  destination.fqdn = null;
  destination.source = 'nosh-l4';
  const destinationKey = JSON.stringify(destination);
  for (const correlation of input.observations.network.correlations) {
    if (correlation.destinationKey === previousDestinationKey) {
      correlation.destinationKey = destinationKey;
    }
  }

  const manifest = module.createBuildEvidenceManifest(input);
  const candidate = module.createBuildNetworkCandidate(manifest);
  assert.equal(candidate.spec.observations.dns.queries[0].queryType, 16);
  assert.equal(candidate.spec.observations.dns.snapshots[0].queryType, 16);
  assert.equal(
    candidate.spec.observations.correlations.some((entry) =>
      entry.kind === 'dns-destination'),
    false,
  );
});

test('network destinations require exact L4 and DNS-derived provenance', async (t) => {
  const module = await artifactsModule();
  const cases = [
    ['invalid-ip', (network) => {
      network.destinations.find((entry) => entry.port === 443).ip = 'not-an-ip';
    }],
    ['source-tamper', (network) => {
      const destination = network.destinations.find((entry) => entry.port === 443);
      const previousKey = JSON.stringify(destination);
      destination.source = 'operator-claim';
      const nextKey = JSON.stringify(destination);
      for (const correlation of network.correlations) {
        if (correlation.destinationKey === previousKey) {
          correlation.destinationKey = nextKey;
        }
      }
    }],
    ['unbacked-fqdn', (network) => {
      network.correlations = network.correlations.filter((entry) => ![
        'dns-destination',
        'resource-destination',
      ].includes(entry.kind));
    }],
    ['renamed-fqdn', (network) => {
      const destination = network.destinations.find((entry) => entry.port === 443);
      const previousKey = JSON.stringify(destination);
      destination.fqdn = 'invented.example.test';
      const nextKey = JSON.stringify(destination);
      for (const correlation of network.correlations) {
        if (correlation.destinationKey === previousKey) {
          correlation.destinationKey = nextKey;
        }
      }
    }],
  ];

  for (const [label, mutate] of cases) {
    const input = await completeInput(t, {
      runId: `network-destination-provenance-${label}`,
      mode: 'build-net-learn',
    });
    input.observations.network = buildNetworkObservationFixture();
    mutate(input.observations.network);
    assert.throws(
      () => module.createBuildEvidenceManifest(input),
      /network destination (?:IP address must be a valid IP address|source does not match|FQDN is not backed)/,
      label,
    );
  }
});

test('network coverage counts and completeness are bound to immutable records', async (t) => {
  const module = await artifactsModule();
  const cases = [
    ['queries', (network) => { network.coverage.dns.queries = 2; }],
    ['responses', (network) => { network.coverage.dns.responses = 2; }],
    ['answers', (network) => { network.coverage.dns.answers = 2; }],
    ['url-observations', (network) => { network.coverage.url.observations = 1; }],
    ['transaction-gap', (network) => {
      network.coverage.dns.transactionMisses = 1;
    }],
    ['parse-gap', (network) => { network.coverage.dns.parseFailures = 1; }],
  ];

  for (const [label, mutate] of cases) {
    const input = await completeInput(t, {
      runId: `network-coverage-${label}`,
      mode: 'build-net-learn',
    });
    input.observations.network = buildNetworkObservationFixture();
    mutate(input.observations.network);
    assert.throws(
      () => module.createBuildEvidenceManifest(input),
      /coverage (?:counts|observations)|complete DNS coverage/,
      label,
    );
  }
});

test('URL correlations require compatible resource, DNS, and destination records', async (t) => {
  const module = await artifactsModule();
  const cases = [
    ['missing-resource', (network) => { network.resources = []; }],
    ['duplicate-resource-id', (network) => {
      network.resources.push(structuredClone(network.resources[0]));
    }],
    ['resource-provider', (network) => { network.resources[0].provider = 'other'; }],
    ['resource-query', (network) => {
      network.correlations.find((entry) =>
        entry.kind === 'resource-dns-query').queryId = 'missing-query';
    }],
    ['resource-snapshot', (network) => {
      network.correlations.find((entry) =>
        entry.kind === 'resource-destination').snapshotId = 'missing-snapshot';
    }],
    ['missing-query-process', (network) => {
      network.correlations = network.correlations.filter((entry) =>
        entry.kind !== 'dns-query-process');
    }],
    ['missing-dns-destination', (network) => {
      network.correlations = network.correlations.filter((entry) =>
        entry.kind !== 'dns-destination');
    }],
    ['resource-chronology', (network) => {
      const resourceId = network.resources[0].id;
      network.resources[0].timestampUnixNs = '1400';
      for (const correlation of network.correlations) {
        if (correlation.resourceId === resourceId) {
          correlation.resourceTimestampUnixNs = '1400';
        }
      }
    }],
    ['direct-host', (network) => {
      network.correlations.find((entry) =>
        entry.kind === 'resource-direct-destination').host = 'registry.example.test';
    }],
  ];

  for (const [label, mutate] of cases) {
    const input = await completeInput(t, {
      runId: `network-resource-relation-${label}`,
      mode: 'build-net-learn',
    });
    input.observations.network = buildNetworkObservationFixture();
    mutate(input.observations.network);
    assert.throws(
      () => module.createBuildEvidenceManifest(input),
      /duplicate nosh-url event ID|resource-(?:dns-query|destination|direct-destination) correlation/,
      label,
    );
  }
});

test('optional URL coverage can never claim authoritative completeness', async (t) => {
  const module = await artifactsModule();
  const input = await completeInput(t, {
    runId: 'network-url-authority-claim',
    mode: 'build-net-learn',
  });
  input.observations.network = buildNetworkObservationFixture();
  input.observations.network.coverage.url.complete = true;

  assert.throws(
    () => module.createBuildEvidenceManifest(input),
    /URL coverage complete must be false because enrichment is non-authoritative/,
  );
});

test('resource hosts accept only canonical bracketed IPv6 literals', async (t) => {
  const module = await artifactsModule();
  const resourceId = `url:${digest(JSON.stringify([
    'cold', '900', '800', '801', 42, 43,
    'https', '[2001:db8::1]', 443,
  ]))}`;
  const resource = {
    id: resourceId,
    provider: 'libcurl',
    scheme: 'https',
    host: '[2001:db8::1]',
    port: 443,
    path: '/',
    pathTruncated: false,
    process: 'curl',
    pid: 42,
    tid: 43,
    timestampUnixNs: '1000',
    timestampMonotonicNs: '900',
    targetCgroupId: '800',
    cgroupId: '801',
    pass: 'cold',
    source: 'nosh-url',
  };
  const valid = await completeInput(t, {
    runId: 'network-ipv6-resource',
    mode: 'build-net-learn',
  });
  valid.observations.network.resources = [resource];
  valid.observations.network.coverage = {
    dns: {
      queries: 0,
      responses: 0,
      answers: 0,
      transactionMisses: 0,
      parseFailures: 0,
      complete: true,
    },
    url: {
      enabled: true,
      providers: ['libcurl'],
      observations: 1,
      discoveryMisses: 0,
      readErrors: 0,
      complete: false,
      limitations: ['observational only'],
    },
  };
  const manifest = module.createBuildEvidenceManifest(valid);
  assert.equal(
    manifest.observations.network.resources[0].host,
    '[2001:db8::1]',
  );

  for (const [index, host] of [
    '2001:db8::1',
    '[2001:DB8::1]',
    '[2001:0db8::1]',
    '[2001:db8::1]:443',
    '[[2001:db8::1]]',
    '[fe80::1%eth0]',
  ].entries()) {
    const invalid = await completeInput(t, {
      runId: `network-invalid-ipv6-${index}`,
      mode: 'build-net-learn',
    });
    invalid.observations.network.resources = [{ ...resource, host }];
    assert.throws(
      () => module.createBuildEvidenceManifest(invalid),
      /network resource host/,
    );
  }
});

test('private resource evidence keeps a sanitized path while portable evidence removes it', async (t) => {
  const module = await artifactsModule();
  const resourcePath = '/private-org/private-repository.git/info/refs';
  const resourceId = `url:${digest(JSON.stringify([
    'cold', '900', '800', '801', 42, 43,
    'https', 'registry.example.test', 443,
  ]))}`;
  const input = await completeInput(t, {
    runId: 'network-resource-redaction',
    mode: 'build-net-learn',
  });
  input.observations.network.resources = [{
    id: resourceId,
    provider: 'libcurl',
    scheme: 'HTTPS',
    host: 'Registry.Example.Test.',
    port: 443,
    path: resourcePath,
    pathTruncated: false,
    process: 'git-remote-http',
    pid: 42,
    tid: 43,
    timestampUnixNs: '1000',
    timestampMonotonicNs: '900',
    targetCgroupId: '800',
    cgroupId: '801',
    pass: 'cold',
    source: 'nosh-url',
    userinfo: 'builder:secret-password',
    query: 'access_token=secret-query-value',
    fragment: 'secret-fragment',
    headers: { authorization: 'Bearer secret-header-value' },
    body: 'secret-body-value',
  }];
  input.observations.network.coverage = {
    dns: {
      queries: 0,
      responses: 0,
      answers: 0,
      transactionMisses: 0,
      parseFailures: 0,
      complete: true,
    },
    url: {
      enabled: true,
      providers: ['libcurl'],
      observations: 1,
      discoveryMisses: 0,
      readErrors: 0,
      complete: false,
      limitations: ['observational only'],
    },
  };

  const manifest = module.createBuildEvidenceManifest(input);
  const candidate = module.createBuildNetworkCandidate(manifest);
  const privateResource = candidate.spec.observations.resources[0];
  assert.deepEqual(privateResource, {
    id: resourceId,
    provider: 'libcurl',
    scheme: 'https',
    host: 'registry.example.test',
    port: 443,
    path: resourcePath,
    pathTruncated: false,
    process: 'git-remote-http',
    pid: 42,
    tid: 43,
    timestampUnixNs: '1000',
    timestampMonotonicNs: '900',
    targetCgroupId: '800',
    cgroupId: '801',
    pass: 'cold',
    source: 'nosh-url',
  });
  assert.deepEqual(manifest.observations.network.resources, [privateResource]);
  const privateSource = JSON.stringify(candidate);
  assert.doesNotMatch(
    privateSource,
    /secret-password|secret-query-value|secret-fragment|secret-header-value|secret-body-value/,
  );

  const portable = module.portableBuildProjection(manifest, candidate);
  const portableResource = portable.observations.network.resources[0];
  assert.equal(portableResource.path, undefined);
  assert.equal(portableResource.resourcePathHash, undefined);
  assert.equal(portableResource.id, resourceId);
  assert.equal(portableResource.scheme, 'https');
  assert.equal(portableResource.host, 'registry.example.test');
  assert.equal(portableResource.port, 443);
  assert.equal(portableResource.cgroupId, undefined);
  assert.equal(portableResource.targetCgroupId, undefined);
  assert.equal(portableResource.timestampMonotonicNs, undefined);
  assert.equal(portableResource.tid, undefined);
  assert.equal(candidate.spec.observations.coverage.url.complete, false);
  const portableSource = JSON.stringify(portable);
  assert.equal(portableSource.includes(resourcePath), false);
  assert.doesNotMatch(
    portableSource,
    /secret-password|secret-query-value|secret-fragment|secret-header-value|secret-body-value/,
  );

  const alternatePath = {
    ...privateResource,
    path: '/another-private-resource',
  };
  assert.equal(alternatePath.id, privateResource.id);
  assert.deepEqual(
    module.redactBuildValue(alternatePath),
    module.redactBuildValue(privateResource),
  );

  const forged = await completeInput(t, {
    runId: 'network-resource-path-derived-id',
    mode: 'build-net-learn',
  });
  forged.observations.network.resources = [{
    ...input.observations.network.resources[0],
    id: `url:${digest(resourcePath)}`,
  }];
  assert.throws(
    () => module.createBuildEvidenceManifest(forged),
    /path-independent observation identity/,
  );
});

test('optional enrichment source gaps remain explicit without invalidating required evidence', async (t) => {
  const module = await artifactsModule();
  const input = await completeInput(t, {
    runId: 'network-optional-source',
    mode: 'build-net-learn',
  });
  input.sources.push({
    name: 'userspace-url',
    format: 'ndjson',
    file: 'raw/userspace-url.ndjson',
    required: false,
    present: true,
    complete: false,
    bytes: 3,
    records: 0,
    hash: digest('userspace-url'),
    lostEvents: 2,
    parseErrors: 1,
    completionMarker: null,
  });
  input.observations.network.coverage = {
    dns: {
      queries: 0,
      responses: 0,
      answers: 0,
      transactionMisses: 0,
      parseFailures: 0,
      complete: true,
    },
    url: {
      enabled: true,
      providers: ['libcurl'],
      observations: 0,
      discoveryMisses: 1,
      readErrors: 1,
      complete: false,
      limitations: ['optional collector did not complete'],
    },
  };

  const manifest = module.createBuildEvidenceManifest(input);
  const optional = manifest.sources.find((source) => source.name === 'userspace-url');
  assert.equal(optional.required, false);
  assert.equal(optional.complete, false);
  assert.equal(optional.lostEvents, 2);
  assert.equal(optional.parseErrors, 1);
  assert.equal(manifest.complete, true);
  assert.equal(manifest.candidateEligible, true);
  const candidate = module.createBuildNetworkCandidate(manifest);
  assert.equal(candidate.spec.observations.coverage.url.enabled, true);
  assert.equal(candidate.spec.observations.coverage.url.complete, false);
  assert.deepEqual(candidate.spec.observations.coverage.url.limitations, [
    'optional collector did not complete',
  ]);
});

test('portable projection excludes raw commands, paths, logs, and event streams', async (t) => {
  const module = await artifactsModule();
  const input = await completeInput(t);
  input.metrics.stderr = 'secret build log';
  input.metrics.authorization = 'Bearer portable-secret';
  input.metrics.proxyAuthorization = 'Basic another-portable-secret';
  input.metrics.password = 'portable-password';
  input.metrics.diagnostic = 'failed while opening "/home/builder/private.key"';
  input.metrics.option = '--config="/etc/notty/private.conf"';
  input.observations.events = [{ raw: 'secret event' }];
  input.observations.http = {
    exchanges: [{
      displayUrl: 'https://registry.example.test/private/package-name.tgz',
      host: 'registry.example.test',
      requestTargetSha256: digest('/private/package-name.tgz'),
    }],
  };
  const manifest = module.createBuildEvidenceManifest(input);
  const candidate = module.createBuildProfileCandidate(manifest);
  const portable = module.portableBuildProjection(manifest, candidate);
  const source = JSON.stringify(portable);
  assert.doesNotMatch(source, /RUN printf secret/);
  assert.doesNotMatch(source, /private\/Dockerfile/);
  assert.doesNotMatch(source, /secret build log/);
  assert.doesNotMatch(source, /secret event/);
  assert.doesNotMatch(
    source,
    /portable-secret|another-portable-secret|portable-password/,
  );
  assert.doesNotMatch(source, /home\/builder\/private\.key|etc\/notty\/private\.conf/);
  assert.doesNotMatch(source, /private\/package-name\.tgz|displayUrl/);
  assert.match(source, /registry\.example\.test/);
  assert.equal(portable.metrics.diagnostic, '[redacted-path]');
  assert.equal(portable.metrics.option, '[redacted-path]');
  assert.doesNotMatch(source, /dockerEndpoint|canonicalPath|"cgroup":/);
  assert.equal(portable.attestation.attested, false);
});
