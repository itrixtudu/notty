'use strict';

const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const test = require('node:test');
const { pathToFileURL } = require('node:url');

const appRoot = path.resolve(__dirname, '..');
const platformContainmentCidrs = Object.freeze([
  '172.31.0.1/32',
  'fd42:6e6f:7368:1::1/128',
]);

function sha256(value) {
  return `sha256:${crypto.createHash('sha256').update(value).digest('hex')}`;
}

function platformContainmentDigest(cidrs = platformContainmentCidrs) {
  return sha256([...cidrs].sort().map((cidr) => {
    const address = cidr.split('/', 1)[0];
    return `platform-endpoint:${address}\t${cidr}\n`;
  }).join(''));
}

async function importModule(relativePath) {
  return import(pathToFileURL(path.join(appRoot, relativePath)).href);
}

function tempDir(t) {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'nosh-ebpf-runtime-'));
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  return directory;
}

test('guard renders one canonical collision-checked nosh-egress manifest', async () => {
  const {
    normalizeEbpfCidr,
    renderEbpfEgressManifest: renderManifestContract,
  } = await importModule('lib/guardd/enforcement-backend.js');
  const renderEbpfEgressManifest = (rules, resolvers) => (
    renderManifestContract(rules, resolvers, platformContainmentCidrs)
  );
  const first = renderEbpfEgressManifest([
    {
      id: 'rule:web',
      effect: 'allow',
      direction: 'egress',
      peer: { value: '2001:db8::/32' },
      transport: { protocol: 'tcp', ports: [443] },
    },
  ], ['8.8.8.8', '1.1.1.1']);
  const second = renderEbpfEgressManifest([
    {
      id: 'rule:web',
      effect: 'allow',
      direction: 'egress',
      peer: { value: '2001:0db8:0000::/32' },
      transport: { protocol: 'tcp', ports: [443] },
    },
  ], ['1.1.1.1', '8.8.8.8']);
  assert.equal(normalizeEbpfCidr('2001:0db8:0000::/32'), '2001:db8::/32');
  assert.equal(first.source, second.source);
  assert.deepEqual(first.ruleIdMap, second.ruleIdMap);
  assert.match(first.source, /^NOSH_EGRESS_POLICY_V2\nresolver\t1\.1\.1\.1\n/);
  assert.match(first.source, /containment\t172\.31\.0\.1\/32\n/);
  assert.match(
    first.source,
    /containment\tfd42:6e6f:7368:1::1\/128\n/,
  );
  assert.match(first.source, /cidr\t2001:db8::\/32\ttcp\t443\t[1-9][0-9]*\n$/);
  const mixedResolvers = renderEbpfEgressManifest([], [
    '2001:0db8:0000:0000:0000:0000:0000:0053',
    '8.8.8.8',
  ]);
  assert.match(
    mixedResolvers.source,
    /^NOSH_EGRESS_POLICY_V2\nresolver\t8\.8\.8\.8\nresolver\t2001:db8::53\n/,
  );
  assert.throws(() => normalizeEbpfCidr('10.0.0.1/8'), /host bits/);
  assert.throws(() => normalizeEbpfCidr('10.0.0.0/999'), /prefix/);
  assert.throws(
    () => renderEbpfEgressManifest([{
      id: 'rule:icmp-selector',
      peer: { value: '2001:db8::/32' },
      transport: { protocol: 'icmpv6', ports: [], icmpType: 128 },
    }], ['1.1.1.1']),
    /cannot enforce ICMP type\/code selectors/,
  );
  assert.throws(
    () => renderEbpfEgressManifest([{
      id: 'rule:icmp-family',
      peer: { value: '2001:db8::/32' },
      transport: { protocol: 'icmp', ports: [] },
    }], ['1.1.1.1']),
    /does not match the address family/,
  );
  assert.throws(
    () => renderEbpfEgressManifest([{
      id: 'rule:domain-too-long',
      peer: { value: `${'a'.repeat(63)}.${'b'.repeat(63)}.example` },
      transport: { protocol: 'tcp', ports: [443] },
    }], ['1.1.1.1']),
    /invalid eBPF egress destination/,
  );
  const sixteenLabelDomain = Array.from(
    { length: 16 },
    (_, index) => `l${index}`,
  ).join('.');
  assert.match(
    renderEbpfEgressManifest([{
      id: 'rule:domain-sixteen-labels',
      peer: { value: sixteenLabelDomain },
      transport: { protocol: 'tcp', ports: [443] },
    }], ['1.1.1.1']).source,
    new RegExp(`domain\\t${sixteenLabelDomain.replaceAll('.', '\\.')}\\t`),
  );
  assert.throws(
    () => renderEbpfEgressManifest([{
      id: 'rule:domain-seventeen-labels',
      peer: {
        value: Array.from({ length: 17 }, (_, index) => `l${index}`).join('.'),
      },
      transport: { protocol: 'tcp', ports: [443] },
    }], ['1.1.1.1']),
    /invalid eBPF egress destination/,
  );
  assert.throws(
    () => renderEbpfEgressManifest([{
      id: 'rule:wildcard-sixteen-label-suffix',
      peer: { value: `*.${sixteenLabelDomain}` },
      transport: { protocol: 'tcp', ports: [443] },
    }], ['1.1.1.1']),
    /invalid eBPF egress destination/,
  );
  assert.throws(
    () => renderEbpfEgressManifest([
      {
        id: 'rule:web-a',
        peer: { value: 'example.com' },
        transport: { protocol: 'tcp', ports: [443] },
      },
      {
        id: 'rule:web-b',
        peer: { value: 'example.com' },
        transport: { protocol: 'tcp', ports: [443] },
      },
    ], ['1.1.1.1']),
    /have the same match/,
  );
  assert.throws(
    () => renderEbpfEgressManifest([
      {
        id: 'rule:overlap-a',
        peer: { value: 'overlap.example' },
        transport: { protocol: 'tcp', ports: [80, 443] },
      },
      {
        id: 'rule:overlap-b',
        peer: { value: 'overlap.example' },
        transport: { protocol: 'tcp', ports: [443] },
      },
    ], ['1.1.1.1']),
    /have the same expanded match/,
  );
  assert.throws(
    () => renderEbpfEgressManifest([{
      id: 'rule:too-many-ports',
      peer: { value: 'capacity.example' },
      transport: {
        protocol: 'tcp',
        ports: [80, 81, 82, 83, 84, 85, 86, 87, 88],
      },
    }], ['1.1.1.1']),
    /exceeds the 8-rule slot limit/,
  );
  assert.throws(
    () => renderEbpfEgressManifest([
      {
        id: 'rule:exact-capacity',
        peer: { value: 'api.example.com' },
        transport: { protocol: 'tcp', ports: [80, 81, 82, 83, 84] },
      },
      {
        id: 'rule:wildcard-capacity',
        peer: { value: '*.example.com' },
        transport: { protocol: 'tcp', ports: [85, 86, 87, 88] },
      },
    ], ['1.1.1.1']),
    /domain union .* exceeds the 8-rule slot limit/,
  );
  assert.throws(
    () => renderEbpfEgressManifest([], Array.from(
      { length: 33 },
      (_, index) => `192.0.2.${index + 1}`,
    )),
    /at most 32 resolvers/,
  );
});

test('installed eBPF backend health is an exact root prerequisite attestation', async () => {
  const { readInstalledEbpfBackendHealth } = await importModule(
    'lib/guardd/enforcement-backend.js',
  );
  const objectDigest = `sha256:${'a'.repeat(64)}`;
  const record = {
    schemaVersion: 2,
    recordKind: 'status',
    timestampUnixNs: '123',
    status: 'healthy',
    cgroupId: null,
    attachedPrograms: 0,
    mapAbi: 2,
    programAbi: 2,
    objectDigest,
    message: 'host prerequisites satisfied',
    checks: {
      effectiveRoot: true,
      kernelIdentity: true,
      kernelBtf: true,
      cgroupV2: true,
      bpffs: true,
      targetCgroup: true,
    },
  };
  const health = readInstalledEbpfBackendHealth({
    loaderPath: '/test/nosh-egress-loader',
    spawnSyncImpl(command, args) {
      assert.equal(command, '/test/nosh-egress-loader');
      assert.deepEqual(args, ['health']);
      return { status: 0, stdout: `${JSON.stringify(record)}\n`, stderr: '' };
    },
  });
  assert.equal(health.objectDigest, objectDigest);
  for (const drift of [
    { ...record, attachedPrograms: 1 },
    { ...record, cgroupId: '42' },
    { ...record, checks: { ...record.checks, bpffs: false } },
    { ...record, unexpected: true },
  ]) {
    assert.throws(
      () => readInstalledEbpfBackendHealth({
        loaderPath: '/test/nosh-egress-loader',
        spawnSyncImpl: () => ({
          status: drift.status === 'healthy' ? 0 : 1,
          stdout: `${JSON.stringify(drift)}\n`,
          stderr: '',
        }),
      }),
      (error) => error.code === 'GUARD_EBPF_EGRESS_BACKEND_UNHEALTHY',
    );
  }
});

test('scoped backend binds the loader top-level pin root to its nested attestation', async () => {
  const { EbpfEgressBackend } = await importModule(
    'lib/guardd/enforcement-backend.js',
  );
  const policyDigest = `sha256:${'1'.repeat(64)}`;
  const objectDigest = `sha256:${'2'.repeat(64)}`;
  const containmentDigest = platformContainmentDigest();
  const pinRoot = '/sys/fs/bpf/nosh-guard/ready-run';
  const run = {
    runId: 'ready-run',
    containerId: 'c'.repeat(64),
    imageDigest: `sha256:${'3'.repeat(64)}`,
    workspaceKey: '4'.repeat(64),
    cgroup: { id: '42' },
    egress: {
      backendMode: 'learn',
      policyDigest,
      containmentDigest,
      containmentCount: platformContainmentCidrs.length,
      objectDigest,
      pinRoot,
    },
  };
  const attestation = {
    targetCgroupId: '42',
    policyDigest,
    containmentDigest,
    containmentCount: platformContainmentCidrs.length,
    mode: 'learn',
    objectDigest,
    mapAbi: 2,
    programAbi: 2,
    policyGeneration: '1',
    runId: run.runId,
    imageDigest: run.imageDigest,
    workspaceKey: run.workspaceKey,
    linkIds: [1, 2, 3, 4, 5, 6],
    programIds: [11, 12, 13, 14, 15, 16],
    mapIds: [21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32],
  };
  const readiness = {
    schemaVersion: 2,
    recordKind: 'status',
    timestampUnixNs: '123',
    status: 'ready',
    cgroupId: '42',
    attachedPrograms: 6,
    mode: 'learn',
    policyDigest,
    containmentDigest,
    containmentCount: platformContainmentCidrs.length,
    objectDigest,
    mapAbi: 2,
    programAbi: 2,
    pinRoot,
    message: 'all programs attached and pinned',
    attestation,
  };
  const backend = new EbpfEgressBackend({ networkManager: {} });
  const verified = backend.attestRun(run, [{ name: 'nosh-egress', readiness }]);
  assert.equal(verified.pinRoot, pinRoot);
  assert.deepEqual(verified.linkIds, attestation.linkIds);
  assert.throws(
    () => backend.attestRun(run, [{
      name: 'nosh-egress',
      readiness: { ...readiness, pinRoot: `${pinRoot}-drifted` },
    }]),
    (error) => error.code === 'GUARD_EBPF_EGRESS_ATTESTATION_MISMATCH',
  );
});

test('scoped backend accepts only the exact pinned snapshot header', async () => {
  const { EbpfEgressBackend } = await importModule(
    'lib/guardd/enforcement-backend.js',
  );
  const policyDigest = `sha256:${'1'.repeat(64)}`;
  const objectDigest = `sha256:${'2'.repeat(64)}`;
  const containmentDigest = platformContainmentDigest();
  const pinRoot = '/sys/fs/bpf/nosh-guard/snapshot-run';
  const header = {
    schemaVersion: 2,
    recordKind: 'snapshot-header',
    policyDigest,
    objectDigest,
    containmentDigest,
    containmentCount: platformContainmentCidrs.length,
    pinRoot,
  };
  const stats = {
    recordKind: 'stats',
    final: true,
    cgroupId: '42',
    policyGeneration: '7',
  };
  let selectedHeader = header;
  const backend = new EbpfEgressBackend({
    networkManager: {},
    spawnSyncImpl(command, args) {
      assert.deepEqual(args, ['snapshot', '--pin-root', pinRoot]);
      return {
        status: 0,
        stdout: `${JSON.stringify(selectedHeader)}\n${JSON.stringify(stats)}\n`,
        stderr: '',
      };
    },
  });
  const run = {
    runId: 'snapshot-run',
    cgroup: { id: '42' },
    egress: {
      policyDigest,
      objectDigest,
      containmentDigest,
      containmentCount: platformContainmentCidrs.length,
      pinRoot,
      attestation: { policyGeneration: '7' },
    },
  };
  assert.equal(backend.snapshotRun(run).policyDigest, policyDigest);
  selectedHeader = { ...header, unexpected: true };
  assert.throws(
    () => backend.snapshotRun(run),
    (error) => error.code === 'GUARD_EBPF_EGRESS_SNAPSHOT_MISMATCH',
  );
});

test('scoped backend allocates one loader-safe bpffs child per run', async (t) => {
  const root = tempDir(t);
  const evidenceDir = path.join(root, 'evidence');
  fs.mkdirSync(evidenceDir);
  const { EbpfEgressBackend } = await importModule(
    'lib/guardd/enforcement-backend.js',
  );
  const backend = new EbpfEgressBackend({
    networkManager: {},
    stateDir: root,
  });
  const previousUmask = process.umask(0o077);
  let prepared;
  try {
    prepared = await backend.prepareRun({
      runId: 'loader-safe-run',
      mode: 'egress-learn',
      imageDigest: `sha256:${'1'.repeat(64)}`,
      workspaceKey: '2'.repeat(64),
      workspaceIdentity: { dev: '3', ino: '4' },
      evidenceDir,
      objectDigest: `sha256:${'5'.repeat(64)}`,
      platformContainmentCidrs,
      rules: [],
    });
  } finally {
    process.umask(previousUmask);
  }
  assert.equal(backend.pinRoot, '/sys/fs/bpf/nosh-guard');
  assert.equal(prepared.pinRoot, '/sys/fs/bpf/nosh-guard/loader-safe-run');
  assert.equal(path.dirname(prepared.pinRoot), backend.pinRoot);
  assert.deepEqual(
    prepared.platformContainmentCidrs,
    platformContainmentCidrs,
  );
  assert.equal(prepared.containmentDigest, platformContainmentDigest());
  assert.equal(prepared.containmentCount, platformContainmentCidrs.length);
  assert.deepEqual(prepared.targetContext.platformContainment, {
    strategy: 'per-run-docker-bridge-gateways',
    ipv4PrefixLength: 32,
    ipv6PrefixLength: 128,
  });
  assert.equal(fs.statSync(prepared.resolverConfigPath).mode & 0o777, 0o644);
  await assert.rejects(
    backend.prepareRun({
      runId: '..',
      mode: 'egress-learn',
      imageDigest: `sha256:${'1'.repeat(64)}`,
      workspaceKey: '2'.repeat(64),
      workspaceIdentity: { dev: '3', ino: '4' },
      evidenceDir,
      objectDigest: `sha256:${'5'.repeat(64)}`,
      platformContainmentCidrs,
      rules: [],
    }),
    /safe bpffs path segment/,
  );
});

test('scoped backend verifies the exact detach receipt and removed pin tree', async (t) => {
  const root = tempDir(t);
  const pinBase = path.join(root, 'bpffs', 'nosh-guard');
  const pinRoot = path.join(pinBase, 'detach-run');
  fs.mkdirSync(pinRoot, { recursive: true });
  const networkCalls = [];
  const { EbpfEgressBackend } = await importModule(
    'lib/guardd/enforcement-backend.js',
  );
  const policyDigest = `sha256:${'3'.repeat(64)}`;
  const containmentDigest = platformContainmentDigest();
  const backend = new EbpfEgressBackend({
    stateDir: root,
    pinRoot: pinBase,
    networkManager: {
      async detachDirectRun(run) {
        networkCalls.push(run.runId);
        return { ok: true, networkName: 'direct-network' };
      },
    },
    spawnSyncImpl(command, args) {
      assert.deepEqual(args, ['detach', '--pin-root', pinRoot]);
      fs.rmSync(pinRoot, { recursive: true });
      return {
        status: 0,
        stdout: `${JSON.stringify({
          schemaVersion: 2,
          recordKind: 'status',
          timestampUnixNs: '123',
          status: 'detached',
          cgroupId: '456',
          policyDigest,
          containmentDigest,
          containmentCount: platformContainmentCidrs.length,
          pinRoot,
          message: 'pinned enforcement removed',
        })}\n`,
        stderr: '',
      };
    },
  });
  const result = await backend.detachRun({
    runId: 'detach-run',
    cgroup: { id: '456' },
    egress: {
      pinRoot,
      policyDigest,
      containmentDigest,
      containmentCount: platformContainmentCidrs.length,
    },
  });
  assert.equal(fs.existsSync(pinRoot), false);
  assert.deepEqual(networkCalls, ['detach-run']);
  assert.equal(result.detachment.status, 'detached');
  assert.equal(result.detachment.policyDigest, policyDigest);
});

test('scoped backend rejects a detach receipt for another policy', async (t) => {
  const root = tempDir(t);
  const pinBase = path.join(root, 'bpffs', 'nosh-guard');
  const pinRoot = path.join(pinBase, 'mismatch-run');
  fs.mkdirSync(pinRoot, { recursive: true });
  let networkDetached = false;
  const { EbpfEgressBackend } = await importModule(
    'lib/guardd/enforcement-backend.js',
  );
  const containmentDigest = platformContainmentDigest();
  const backend = new EbpfEgressBackend({
    stateDir: root,
    pinRoot: pinBase,
    networkManager: {
      async detachDirectRun() {
        networkDetached = true;
        return { ok: true, networkName: 'must-not-detach' };
      },
    },
    spawnSyncImpl() {
      fs.rmSync(pinRoot, { recursive: true });
      return {
        status: 0,
        stdout: `${JSON.stringify({
          schemaVersion: 2,
          recordKind: 'status',
          timestampUnixNs: '123',
          status: 'detached',
          cgroupId: '456',
          policyDigest: `sha256:${'9'.repeat(64)}`,
          containmentDigest,
          containmentCount: platformContainmentCidrs.length,
          pinRoot,
          message: 'pinned enforcement removed',
        })}\n`,
        stderr: '',
      };
    },
  });
  await assert.rejects(
    backend.detachRun({
      runId: 'mismatch-run',
      cgroup: { id: '456' },
      egress: {
        pinRoot,
        policyDigest: `sha256:${'3'.repeat(64)}`,
        containmentDigest,
        containmentCount: platformContainmentCidrs.length,
      },
    }),
    (error) => error.code === 'GUARD_EBPF_EGRESS_DETACH_MISMATCH',
  );
  assert.equal(networkDetached, false);
});

test('nosh-egress evidence requires one last monotonic loss-free stats record', async (t) => {
  const root = tempDir(t);
  const evidenceDir = path.join(root, 'evidence');
  const logPath = path.join(evidenceDir, 'nosh-egress.jsonl');
  fs.mkdirSync(evidenceDir);
  const policyDigest = `sha256:${'3'.repeat(64)}`;
  const objectDigest = `sha256:${'4'.repeat(64)}`;
  const counters = (overrides = {}) => ({
    allowed: '0',
    wouldDeny: '0',
    denied: '0',
    ringbufDrops: '0',
    parseErrors: '0',
    fragments: '0',
    configInvalid: '0',
    policyMisses: '0',
    dnsQueries: '0',
    dnsResponses: '0',
    dnsTransactionMisses: '0',
    dnsGrantUpdates: '0',
    dnsGrantFailures: '0',
    dnsUnsupported: '0',
    unsupportedProtocol: '0',
    coverageAllowed: '0',
    coverageWouldDeny: '0',
    coverageDenied: '0',
    containmentDenied: '0',
    backendDenied: '0',
    dnsAnswers: '0',
    ...overrides,
  });
  const stats = (final, eventsSeen, selectedCounters, mode = 'learn') => ({
    schemaVersion: 2,
    recordKind: 'stats',
    timestampUnixNs: final ? '200' : '100',
    cgroupId: '42',
    policyGeneration: '1',
    mode,
    final,
    eventsSeen: String(eventsSeen),
    decoderErrors: '0',
    counters: selectedCounters,
  });
  const decision = {
    schemaVersion: 2,
    recordKind: 'decision',
    timestampMonotonicNs: '150',
    cgroupId: '42',
    policyGeneration: '1',
    hook: 1,
    family: 4,
    protocol: 6,
    sourceAddress: '10.0.0.2',
    destinationAddress: '203.0.113.8',
    sourcePort: 41000,
    destinationPort: 443,
    verdict: 'allow',
    decisionClass: 'observed',
    reason: 'learn-observed',
    reasonCode: 4,
    enforcementApplied: false,
    containmentId: '',
    ruleId: 0,
    packetBytes: 0,
    transactionId: 0,
    domain: '',
    expiresMonotonicNs: '0',
  };
  const readiness = {
    attestation: {
      targetCgroupId: '42',
      policyGeneration: '1',
      mode: 'learn',
      policyDigest,
      objectDigest,
      containmentDigest: platformContainmentDigest(),
      containmentCount: platformContainmentCidrs.length,
    },
  };
  const runFor = (finalCounters, mode = 'learn') => ({
    runId: 'evidence-run',
    name: 'evidence-runner',
    mode: `egress-${mode}`,
    profileRevision: 'candidate',
    containerId: 'c'.repeat(64),
    imageRequested: 'nosh:test',
    imageDigest: `sha256:${'5'.repeat(64)}`,
    workdir: root,
    workspaceIdentity: { dev: '1', ino: '2' },
    evidenceDir,
    evidenceComplete: true,
    createdAt: '2026-08-21T00:00:00.000Z',
    adapters: [{
      name: 'nosh-egress',
      logPath,
      required: true,
      evidence: true,
      readiness: {
        attestation: {
          ...readiness.attestation,
          mode,
        },
      },
    }],
    detachResults: [],
    egress: {
      backend: 'nosh-egress',
      backendAbi: 'nosh-egress-v2',
      policyDigest,
      objectDigest,
      containmentDigest: platformContainmentDigest(),
      containmentCount: platformContainmentCidrs.length,
      targetContextHash: `sha256:${'6'.repeat(64)}`,
      ruleIdMap: {},
      finalSnapshot: {
        schemaVersion: 2,
        recordKind: 'snapshot-header',
        policyDigest,
        objectDigest,
        containmentDigest: platformContainmentDigest(),
        containmentCount: platformContainmentCidrs.length,
        pinRoot: '/sys/fs/bpf/nosh-guard/evidence-run',
        stats: stats(true, 0, finalCounters, mode),
      },
    },
  });
  const writeRecords = (records) => fs.writeFileSync(
    logPath,
    `${records.map((record) => JSON.stringify(record)).join('\n')}\n`,
  );
  const { finalizeRunEvidence } = await importModule(
    'lib/guardd/evidence-finalizer.js',
  );

  const cleanCounters = counters({ allowed: '1' });
  const initial = stats(false, 0, counters());
  const final = stats(true, 1, cleanCounters);
  writeRecords([initial, decision, final]);
  const clean = await finalizeRunEvidence(runFor(cleanCounters), {
    stateDir: root,
  });
  assert.equal(clean.manifest.complete, true);
  assert.equal(clean.manifest.ebpfEgressEvaluation.eligible, true);

  for (const observed of [
    {
      mode: 'audit',
      record: {
        ...decision,
        verdict: 'would-deny',
        decisionClass: 'would-deny',
        reason: 'default-deny',
        reasonCode: 5,
      },
      finalCounters: counters({ wouldDeny: '1' }),
    },
    {
      mode: 'enforce',
      record: {
        ...decision,
        verdict: 'deny',
        decisionClass: 'policy-deny',
        reason: 'default-deny',
        reasonCode: 5,
        enforcementApplied: true,
      },
      finalCounters: counters({ denied: '1' }),
    },
    {
      mode: 'enforce',
      record: {
        ...decision,
        decisionClass: 'policy-allow',
        reason: 'static-policy',
        reasonCode: 1,
        enforcementApplied: true,
        ruleId: 1,
      },
      finalCounters: counters({ allowed: '1' }),
    },
  ]) {
    writeRecords([
      stats(false, 0, counters(), observed.mode),
      observed.record,
      stats(true, 1, observed.finalCounters, observed.mode),
    ]);
    const accepted = await finalizeRunEvidence(
      runFor(observed.finalCounters, observed.mode),
      { stateDir: root },
    );
    assert.equal(accepted.manifest.sources[0].complete, true);
    assert.equal(
      accepted.manifest.sources[0].completionMarker,
      'final-stats-clean',
    );
  }

  for (const forgedRuleIdentity of [
    {
      ...decision,
      decisionClass: 'policy-allow',
      reason: 'static-policy',
      reasonCode: 1,
      ruleId: 0,
    },
    {
      ...decision,
      hook: 5,
      sourceAddress: '1.1.1.1',
      destinationAddress: '203.0.113.9',
      sourcePort: 53,
      decisionClass: 'policy-allow',
      reason: 'dns-grant',
      reasonCode: 3,
      ruleId: 0,
      transactionId: 0,
      domain: 'example.com',
      expiresMonotonicNs: '1000000150',
    },
  ]) {
    const forgedRuleCounters = counters({ allowed: '1' });
    writeRecords([
      stats(false, 0, counters(), 'audit'),
      forgedRuleIdentity,
      stats(true, 1, forgedRuleCounters, 'audit'),
    ]);
    const rejected = await finalizeRunEvidence(
      runFor(forgedRuleCounters, 'audit'),
      { stateDir: root },
    );
    assert.equal(
      rejected.manifest.sources[0].completionMarker,
      'invalid-nosh-egress-v2-record',
    );
  }

  for (const forged of [
    {
      ...decision,
      verdict: 'would-deny',
      decisionClass: 'would-deny',
      reason: 'default-deny',
      reasonCode: 5,
      enforcementApplied: false,
    },
    {
      ...decision,
      verdict: 'deny',
      decisionClass: 'policy-deny',
      reason: 'default-deny',
      reasonCode: 5,
      enforcementApplied: true,
    },
    {
      ...decision,
      decisionClass: 'policy-allow',
      reason: 'static-policy',
      reasonCode: 1,
    },
  ]) {
    const forgedCounters = counters({
      allowed: forged.verdict === 'allow' ? '1' : '0',
      wouldDeny: forged.verdict === 'would-deny' ? '1' : '0',
      denied: forged.verdict === 'deny' ? '1' : '0',
    });
    writeRecords([initial, forged, stats(true, 1, forgedCounters)]);
    const rejected = await finalizeRunEvidence(runFor(forgedCounters), {
      stateDir: root,
    });
    assert.equal(rejected.manifest.sources[0].complete, false);
    assert.equal(
      rejected.manifest.sources[0].completionMarker,
      'invalid-nosh-egress-v2-record',
    );
  }

  const mismatchedCounters = counters({ allowed: '2' });
  writeRecords([initial, decision, stats(true, 1, mismatchedCounters)]);
  const mismatched = await finalizeRunEvidence(runFor(mismatchedCounters), {
    stateDir: root,
  });
  assert.equal(
    mismatched.manifest.sources[0].completionMarker,
    'nosh-egress-counter-evidence-mismatch',
  );

  const dnsAnswer = {
    schemaVersion: 2,
    recordKind: 'dns-answer',
    timestampMonotonicNs: '160',
    cgroupId: '42',
    policyGeneration: '1',
    hook: 5,
    transportFamily: 4,
    transportProtocol: 17,
    resolverAddress: '1.1.1.1',
    resolverPort: 53,
    clientPort: 53000,
    domain: 'example.com',
    dnsRecordType: 'A',
    answerAddress: '203.0.113.9',
    decisionClass: 'dns-observation',
    reason: 'dns-answer',
    reasonCode: 16,
    enforcementApplied: false,
    transactionId: 7,
    expiresMonotonicNs: '1000000160',
  };
  const dnsAnswerCounters = counters({ dnsAnswers: '1' });
  writeRecords([
    initial,
    dnsAnswer,
    stats(true, 1, dnsAnswerCounters),
  ]);
  const dnsAnswerResult = await finalizeRunEvidence(
    runFor(dnsAnswerCounters),
    { stateDir: root },
  );
  assert.equal(dnsAnswerResult.manifest.sources[0].complete, true);
  assert.deepEqual(
    dnsAnswerResult.manifest.ebpfEgressEvaluation.counts,
    { allow: 0, 'would-deny': 0, deny: 0 },
  );

  const dnsQuery = {
    ...decision,
    hook: 6,
    protocol: 17,
    destinationAddress: '1.1.1.1',
    sourcePort: 53000,
    destinationPort: 53,
    decisionClass: 'infrastructure-allow',
    reason: 'configured-resolver',
    reasonCode: 2,
    ruleId: 1,
    packetBytes: 80,
    transactionId: 0,
    domain: 'example.com',
  };
  const zeroTransactionAnswer = {
    ...dnsAnswer,
    transactionId: 0,
  };
  const zeroTransactionGrant = {
    ...decision,
    hook: 5,
    sourceAddress: '1.1.1.1',
    destinationAddress: '203.0.113.9',
    sourcePort: 53,
    destinationPort: 443,
    decisionClass: 'policy-allow',
    reason: 'dns-grant',
    reasonCode: 3,
    ruleId: 1,
    transactionId: 0,
    domain: 'example.com',
    expiresMonotonicNs: '1000000150',
  };
  const dnsResponse = {
    ...zeroTransactionGrant,
    protocol: 17,
    destinationAddress: '10.0.0.2',
    destinationPort: 53000,
    packetBytes: 120,
  };
  const dnsGrantCounters = counters({
    allowed: '2',
    dnsQueries: '1',
    dnsResponses: '1',
    dnsAnswers: '1',
  });
  writeRecords([
    stats(false, 0, counters(), 'audit'),
    dnsQuery,
    zeroTransactionAnswer,
    zeroTransactionGrant,
    dnsResponse,
    stats(true, 4, dnsGrantCounters, 'audit'),
  ]);
  const zeroTransactionResult = await finalizeRunEvidence(
    runFor(dnsGrantCounters, 'audit'),
    { stateDir: root },
  );
  assert.equal(zeroTransactionResult.manifest.sources[0].complete, true);
  assert.equal(
    zeroTransactionResult.manifest.sources[0].completionMarker,
    'final-stats-clean',
  );
  assert.equal(
    zeroTransactionResult.manifest.ebpfEgressEvaluation.counts.allow,
    3,
  );

  const outOfRangeTransaction = {
    ...decision,
    transactionId: 65_536,
  };
  writeRecords([
    initial,
    outOfRangeTransaction,
    stats(true, 1, cleanCounters),
  ]);
  const outOfRangeTransactionResult = await finalizeRunEvidence(
    runFor(cleanCounters),
    { stateDir: root },
  );
  assert.equal(
    outOfRangeTransactionResult.manifest.sources[0].completionMarker,
    'invalid-nosh-egress-v2-record',
  );

  const forgedCoverage = {
    ...decision,
    decisionClass: 'coverage-gap',
    reason: 'parse-gap',
    reasonCode: 7,
  };
  const forgedCoverageCounters = counters({
    allowed: '1',
    parseErrors: '1',
  });
  writeRecords([
    initial,
    forgedCoverage,
    stats(true, 1, forgedCoverageCounters),
  ]);
  const coverageMismatch = await finalizeRunEvidence(
    runFor(forgedCoverageCounters),
    { stateDir: root },
  );
  assert.equal(
    coverageMismatch.manifest.sources[0].completionMarker,
    'nosh-egress-counter-evidence-mismatch',
  );

  const forgedBackend = {
    ...decision,
    verdict: 'deny',
    decisionClass: 'backend-deny',
    reason: 'hidden-destination',
    reasonCode: 14,
    enforcementApplied: true,
  };
  const forgedBackendCounters = counters({
    denied: '1',
    parseErrors: '1',
  });
  writeRecords([
    initial,
    forgedBackend,
    stats(true, 1, forgedBackendCounters),
  ]);
  const backendMismatch = await finalizeRunEvidence(
    runFor(forgedBackendCounters),
    { stateDir: root },
  );
  assert.equal(
    backendMismatch.manifest.sources[0].completionMarker,
    'nosh-egress-counter-evidence-mismatch',
  );

  const containment = {
    ...decision,
    destinationAddress: '10.240.0.1',
    verdict: 'deny',
    decisionClass: 'containment-deny',
    reason: 'platform-containment',
    reasonCode: 13,
    enforcementApplied: true,
    containmentId: 'platform-endpoint:10.240.0.1',
  };
  const containmentCounters = counters({
    denied: '1',
    containmentDenied: '1',
  });
  writeRecords([
    initial,
    containment,
    stats(true, 1, containmentCounters),
  ]);
  const contained = await finalizeRunEvidence(runFor(containmentCounters), {
    stateDir: root,
  });
  assert.equal(contained.manifest.sources[0].complete, true);
  assert.equal(contained.manifest.sources[0].completionMarker, 'final-stats-clean');
  assert.equal(contained.manifest.ebpfEgressEvaluation.eligible, false);
  assert.deepEqual(
    contained.manifest.ebpfEgressEvaluation.unresolved,
    [{
      kind: 'platform-containment',
      name: 'containmentDenied',
      value: '1',
    }],
  );

  const forgedContainmentCounters = counters({ denied: '1' });
  writeRecords([
    initial,
    containment,
    stats(true, 1, forgedContainmentCounters),
  ]);
  const containmentCounterMismatch = await finalizeRunEvidence(
    runFor(forgedContainmentCounters),
    { stateDir: root },
  );
  assert.equal(
    containmentCounterMismatch.manifest.sources[0].completionMarker,
    'nosh-egress-counter-evidence-mismatch',
  );

  const forgedContainment = {
    ...containment,
    containmentId: 'platform-endpoint:10.240.0.2',
  };
  writeRecords([
    initial,
    forgedContainment,
    stats(true, 1, containmentCounters),
  ]);
  const containmentMismatch = await finalizeRunEvidence(
    runFor(containmentCounters),
    { stateDir: root },
  );
  assert.equal(
    containmentMismatch.manifest.sources[0].completionMarker,
    'invalid-nosh-egress-v2-record',
  );

  writeRecords([initial, decision, final, final]);
  const duplicate = await finalizeRunEvidence(runFor(cleanCounters), {
    stateDir: root,
  });
  assert.equal(duplicate.manifest.complete, false);
  assert.equal(
    duplicate.manifest.sources[0].completionMarker,
    'duplicate-final-stats',
  );

  const lossyCounters = counters({ allowed: '1', dnsUnsupported: '1' });
  writeRecords([initial, decision, stats(true, 1, lossyCounters)]);
  const lossy = await finalizeRunEvidence(runFor(lossyCounters), {
    stateDir: root,
  });
  assert.equal(lossy.manifest.complete, false);
  assert.equal(lossy.manifest.sources[0].lostEvents, 0);
  assert.equal(lossy.manifest.ebpfEgressEvaluation.eligible, false);
  assert.deepEqual(
    lossy.manifest.ebpfEgressEvaluation.unresolved,
    [{ kind: 'coverage-gap', name: 'dnsUnsupported', value: '1' }],
  );
});

test('scoped runner mounts a root-owned 0644 resolver file read-only', async (t) => {
  const root = tempDir(t);
  const workdir = path.join(root, 'workspace');
  const resolver = path.join(root, 'resolv.conf');
  fs.mkdirSync(workdir);
  fs.writeFileSync(resolver, 'nameserver 1.1.1.1\n', { mode: 0o644 });
  fs.chmodSync(resolver, 0o644);
  const { buildRunnerSpec } = await importModule('lib/guardd/runner-spec.js');
  const runner = buildRunnerSpec({
    runId: 'resolver-run',
    name: 'resolver-run',
    mode: 'egress-learn',
    image: `sha256:${'1'.repeat(64)}`,
    imageDigest: `sha256:${'1'.repeat(64)}`,
    workdir,
    resolverConfigPath: resolver,
  });
  assert.equal(fs.statSync(resolver).mode & 0o777, 0o644);
  assert.ok(runner.spec.HostConfig.Binds.includes(`${resolver}:/etc/resolv.conf:ro`));
  assert.deepEqual(runner.spec.HostConfig.Dns, []);
  fs.chmodSync(resolver, 0o600);
  assert.throws(
    () => buildRunnerSpec({
      runId: 'unreadable-resolver-run',
      name: 'unreadable-resolver-run',
      mode: 'egress-learn',
      image: `sha256:${'1'.repeat(64)}`,
      workdir,
      resolverConfigPath: resolver,
    }),
    /mode 0644/,
  );
});

test('direct eBPF egress network is an attested dual-stack NAT bridge', async (t) => {
  const root = tempDir(t);
  const networks = new Map();
  let created = null;
  const docker = {
    async inspectNetwork(name) {
      if (!networks.has(name)) {
        const error = new Error('not found');
        error.statusCode = 404;
        throw error;
      }
      return networks.get(name);
    },
    async createNetwork(name, options) {
      created = { name, options };
      networks.set(name, {
        Name: name,
        Internal: options.internal,
        EnableIPv6: options.enableIPv6,
        Labels: options.labels,
        Options: options.options,
        IPAM: {
          Config: options.ipam.config.map((entry) => ({
            Subnet: entry.subnet,
            Gateway: entry.gateway,
          })),
        },
      });
    },
    async removeNetwork(name) {
      networks.delete(name);
    },
  };
  const { EgressManager } = await importModule('lib/guardd/egress-manager.js');
  const manager = new EgressManager({
    docker,
    stateDir: root,
    ipv6RoutingProvider: async () => ({
      ok: true,
      ipv6Enabled: true,
      forwarding: true,
      defaultRoute: true,
    }),
  });
  const allocation = await manager.prepareDirectNetwork('dual-stack-run');
  assert.equal(created.options.internal, false);
  assert.equal(created.options.enableIPv6, true);
  assert.equal(
    created.options.options['com.docker.network.bridge.enable_ip_masquerade'],
    'true',
  );
  assert.match(allocation.runnerIp, /^10\.240\./);
  assert.match(allocation.runnerIpv6, /^fd42:6e6f:7368:/);
  assert.equal(allocation.backend, 'nosh-egress');
  assert.deepEqual(await manager.detachDirectRun({
    runId: 'dual-stack-run',
    egress: { networkName: allocation.networkName },
  }), {
    ok: true,
    networkName: allocation.networkName,
  });
  assert.equal(networks.size, 0);
});

test('direct network admission rolls back a just-created network after inspect failure', async (t) => {
  const root = tempDir(t);
  let network = null;
  let inspectCount = 0;
  let removed = false;
  const docker = {
    async inspectNetwork() {
      inspectCount += 1;
      if (!network) {
        const error = new Error('not found');
        error.statusCode = 404;
        throw error;
      }
      if (inspectCount === 2) {
        throw new Error('post-create inspect failed');
      }
      return network;
    },
    async createNetwork(name, options) {
      network = {
        Name: name,
        Internal: options.internal,
        EnableIPv6: options.enableIPv6,
        Labels: options.labels,
        Options: options.options,
        IPAM: { Config: options.ipam.config },
      };
    },
    async removeNetwork() {
      removed = true;
      network = null;
    },
  };
  const { EgressManager } = await importModule('lib/guardd/egress-manager.js');
  const manager = new EgressManager({
    docker,
    stateDir: root,
    ipv6RoutingProvider: async () => ({ ok: true }),
  });
  await assert.rejects(
    manager.prepareDirectNetwork('rollback-inspect-run'),
    (error) => (
      error.code === 'GUARD_EBPF_NETWORK_ROLLED_BACK'
      && error.networkCleanupVerified === true
      && /post-create inspect failed/.test(error.message)
    ),
  );
  assert.equal(removed, true);
  assert.equal(network, null);
});

test('direct network admission rolls back only its exact invalid labeled network', async (t) => {
  const root = tempDir(t);
  let network = null;
  let removed = false;
  const docker = {
    async inspectNetwork() {
      if (!network) {
        const error = new Error('not found');
        error.statusCode = 404;
        throw error;
      }
      return network;
    },
    async createNetwork(name, options) {
      network = {
        Name: name,
        Internal: options.internal,
        EnableIPv6: false,
        Labels: options.labels,
        Options: options.options,
        IPAM: { Config: options.ipam.config },
      };
    },
    async removeNetwork() {
      removed = true;
      network = null;
    },
  };
  const { EgressManager } = await importModule('lib/guardd/egress-manager.js');
  const manager = new EgressManager({
    docker,
    stateDir: root,
    ipv6RoutingProvider: async () => ({ ok: true }),
  });
  await assert.rejects(
    manager.prepareDirectNetwork('rollback-invalid-run'),
    (error) => (
      error.code === 'GUARD_EBPF_NETWORK_ROLLED_BACK'
      && error.networkCleanupVerified === true
      && /refusing invalid eBPF egress runner network/.test(error.message)
    ),
  );
  assert.equal(removed, true);
  assert.equal(network, null);
});

test('direct network admission never removes a preexisting drifted network', async (t) => {
  const root = tempDir(t);
  let removed = false;
  const docker = {
    async inspectNetwork(name) {
      return {
        Name: name,
        Internal: false,
        EnableIPv6: false,
        Labels: {
          'io.notty.guard.managed': 'true',
          'io.notty.guard.run-id': 'different-run',
          'io.notty.guard.egress-backend': 'nosh-egress',
        },
        Options: {
          'com.docker.network.bridge.enable_ip_masquerade': 'true',
        },
        IPAM: { Config: [] },
      };
    },
    async createNetwork() {
      throw new Error('must not create over a preexisting network');
    },
    async removeNetwork() {
      removed = true;
    },
  };
  const { EgressManager } = await importModule('lib/guardd/egress-manager.js');
  const manager = new EgressManager({
    docker,
    stateDir: root,
    ipv6RoutingProvider: async () => ({ ok: true }),
  });
  await assert.rejects(
    manager.prepareDirectNetwork('preexisting-run'),
    /refusing invalid eBPF egress runner network/,
  );
  assert.equal(removed, false);
});

test('required eBPF adapter exit contains a runner that is still gated', async () => {
  const { GuardService } = await importModule('lib/guardd/service.js');
  const service = Object.create(GuardService.prototype);
  const paused = [];
  service.pendingRunStarts = new Set(['startup-exit-run']);
  service.pendingRunActions = new Set(['startup-exit-run']);
  service.requiredAdapterExitFailures = new Map();
  service.store = {
    async readRun() {
      return {
        runId: 'startup-exit-run',
        status: 'gated',
        containerId: 'runner-container',
        containerRemoved: false,
      };
    },
  };
  service.docker = {
    async pauseContainer(containerId) {
      paused.push(containerId);
    },
    async removeContainer() {
      throw new Error('pause should contain the runner first');
    },
  };

  const result = await service.handleRequiredAdapterExit(
    'startup-exit-run',
    { name: 'nosh-egress', exitCode: 9, error: 'collector exited' },
  );
  assert.deepEqual(paused, ['runner-container']);
  assert.equal(result.status, 'startup-run-paused');
  assert.equal(
    service.requiredAdapterExitFailures.get('startup-exit-run').name,
    'nosh-egress',
  );
  assert.throws(
    () => service.assertRequiredAdaptersStillRunning('startup-exit-run'),
    (error) => error.code === 'GUARD_REQUIRED_ADAPTER_EXITED',
  );
});

test('scoped async quarantine removes the runner before detaching pinned eBPF state', async (t) => {
  const root = tempDir(t);
  const evidenceDir = path.join(root, 'evidence');
  fs.mkdirSync(evidenceDir);
  const operations = [];
  const { GuardService } = await importModule('lib/guardd/service.js');
  const service = Object.create(GuardService.prototype);
  service.store = {
    root,
    evidencePath() {
      return evidenceDir;
    },
    async writeRun(run) {
      return structuredClone(run);
    },
  };
  service.docker = {
    async pauseContainer() {
      operations.push('pause-runner');
    },
    async removeContainer() {
      operations.push('remove-runner');
    },
  };
  service.adapters = {
    async detach() {
      operations.push('stop-adapter');
      return [{
        name: 'nosh-egress',
        ok: true,
        cleanupCritical: true,
        cleanupOk: true,
      }];
    },
  };
  service.captureFinalEgressSnapshot = async (run) => {
    operations.push('snapshot-pins');
    return run;
  };
  service.scopedEgress = {
    async detachRun(run) {
      operations.push('detach-pins-and-network');
      assert.equal(run.containerRemoved, true);
      return { ok: true, networkName: 'nosh-guard-scoped-quarantine' };
    },
  };
  service.hostProfiles = {};

  const quarantined = await service.quarantineRun({
    runId: 'scoped-quarantine-run',
    name: 'scoped-quarantine-run',
    mode: 'egress-learn',
    status: 'running',
    containerId: 'runner-container',
    evidenceDir,
    evidenceComplete: true,
    adapters: [{
      name: 'nosh-egress',
      evidence: false,
      required: true,
      cleanupCritical: true,
    }],
    egress: {
      backend: 'nosh-egress',
      networkName: 'nosh-guard-scoped-quarantine',
    },
  }, [{ name: 'nosh-egress', error: 'unexpected exit' }]);

  assert.equal(quarantined.containerRemoved, true);
  assert.equal(quarantined.quarantineActive, false);
  assert.ok(
    operations.indexOf('remove-runner')
      < operations.indexOf('detach-pins-and-network'),
    operations.join(', '),
  );
  assert.deepEqual(operations, [
    'pause-runner',
    'stop-adapter',
    'snapshot-pins',
    'remove-runner',
    'detach-pins-and-network',
  ]);
});
