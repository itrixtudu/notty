'use strict';

const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawnSync } = require('node:child_process');
const test = require('node:test');
const { pathToFileURL } = require('node:url');

const appRoot = path.resolve(__dirname, '..');
const helperPath = path.join(appRoot, 'scripts/nosh-egress-poc.mjs');
const counterNames = [
  'allowed', 'wouldDeny', 'denied', 'ringbufDrops', 'parseErrors', 'fragments',
  'configInvalid', 'policyMisses', 'dnsQueries', 'dnsResponses',
  'dnsTransactionMisses', 'dnsGrantUpdates', 'dnsGrantFailures', 'dnsUnsupported',
  'unsupportedProtocol', 'coverageAllowed', 'coverageWouldDeny', 'coverageDenied',
  'containmentDenied', 'backendDenied', 'dnsAnswers',
];
const hash = (text) => `sha256:${crypto.createHash('sha256').update(text).digest('hex')}`;
const importHelper = () => import(pathToFileURL(helperPath).href);

async function fixture(t, ruleCount = 1) {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'nosh-egress-poc-test-'));
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  const documents = {};
  const endpoints = {
    capacityRuleCount: ruleCount,
    a: '172.30.201.2', b: '172.30.201.3', gateway: '172.30.201.1',
    clientImage: `sha256:${'a'.repeat(64)}`, clientId: 'b'.repeat(64),
    cgroupId: '123456', objectDigest: `sha256:${'c'.repeat(64)}`,
    workspaceKey: 'd'.repeat(64),
    phases: {
      allowA: { runId: 'poc-a', pinRoot: '/sys/fs/bpf/nosh-guard/poc-a', policyGeneration: '1' },
      allowB: { runId: 'poc-b', pinRoot: '/sys/fs/bpf/nosh-guard/poc-b', policyGeneration: '2' },
    },
  };
  const { createPocPolicies } = await importHelper();
  const { phases } = createPocPolicies(endpoints.a, endpoints.b, endpoints.gateway, ruleCount);
  documents['endpoints.json'] = endpoints;
  documents['probes.jsonl'] = [];
  for (const phase of ['baseline', 'allowA', 'allowB']) {
    for (const endpoint of ['a', 'b']) {
      const allowed = phase === 'baseline' || phase === `allow${endpoint.toUpperCase()}`;
      documents['probes.jsonl'].push({
        phase, endpoint, address: endpoints[endpoint], port: 8080,
        exitCode: allowed ? 0 : 7,
        httpCode: allowed ? '200' : '000',
        body: allowed ? `${endpoint.toUpperCase()}\n` : '',
        error: allowed ? '' : 'curl: (7) Could not connect to server',
      });
    }
  }
  for (const endpoint of ['a', 'b']) {
    documents[`server-${endpoint}.jsonl`] = [
      { endpoint, ready: true },
      { endpoint, path: `/baseline/${endpoint}` },
      { endpoint, path: `/allow${endpoint.toUpperCase()}/${endpoint}` },
    ];
  }
  for (const [phase, generated] of Object.entries(phases)) {
    const meta = endpoints.phases[phase];
    const containmentDigest = hash(`platform-endpoint:${endpoints.gateway}\t${endpoints.gateway}/32\n`);
    const status = {
      schemaVersion: 2, recordKind: 'status', timestampUnixNs: '1234567890',
      status: 'ready', cgroupId: endpoints.cgroupId, attachedPrograms: 6,
      mode: 'enforce', policyDigest: generated.policyDigest,
      objectDigest: endpoints.objectDigest, containmentDigest, containmentCount: 1,
      mapAbi: 2, programAbi: 2, pinRoot: meta.pinRoot, message: 'pinned enforcement active',
      attestation: {
        targetCgroupId: endpoints.cgroupId, policyDigest: generated.policyDigest,
        objectDigest: endpoints.objectDigest, containmentDigest, containmentCount: 1,
        mode: 'enforce', mapAbi: 2, programAbi: 2,
        policyGeneration: meta.policyGeneration, runId: meta.runId,
        imageDigest: endpoints.clientImage, workspaceKey: endpoints.workspaceKey,
        linkIds: [1, 2, 3, 4, 5, 6], programIds: [7, 8, 9, 10, 11, 12],
        mapIds: [13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24],
      },
    };
    const stopped = { ...status, status: 'stopped' };
    delete stopped.attestation;
    const initial = {
      schemaVersion: 2, recordKind: 'stats', timestampUnixNs: '1234567890',
      cgroupId: endpoints.cgroupId, policyGeneration: meta.policyGeneration,
      mode: 'enforce', final: false, eventsSeen: '0', decoderErrors: '0',
      counters: Object.fromEntries(counterNames.map((name) => [name, '0'])),
    };
    const final = structuredClone(initial);
    final.final = true;
    final.eventsSeen = '2';
    final.counters.allowed = '1';
    final.counters.denied = '1';
    final.counters.policyMisses = '1';
    const allowEndpoint = phase === 'allowA' ? 'a' : 'b';
    const endpointLine = generated.manifest.split('\n').find(line => line.startsWith(`cidr\t${endpoints[allowEndpoint]}/32\ttcp\t8080\t`));
    const ruleId = Number(endpointLine.split('\t').at(-1));
    const denyEndpoint = allowEndpoint === 'a' ? 'b' : 'a';
    const allowed = {
      schemaVersion: 2, recordKind: 'decision', timestampMonotonicNs: '3456789',
      cgroupId: endpoints.cgroupId, policyGeneration: meta.policyGeneration,
      hook: 1, family: 4, protocol: 6, sourceAddress: '0.0.0.0',
      destinationAddress: endpoints[allowEndpoint], sourcePort: 0, destinationPort: 8080,
      verdict: 'allow', decisionClass: 'policy-allow', reason: 'static-policy',
      reasonCode: 1, enforcementApplied: true, containmentId: '', ruleId,
      packetBytes: 0, transactionId: 0, domain: '', expiresMonotonicNs: '0',
    };
    const denied = {
      ...allowed, destinationAddress: endpoints[denyEndpoint], verdict: 'deny',
      decisionClass: 'policy-deny', reason: 'default-deny', reasonCode: 5, ruleId: 0,
    };
    documents[`${phase}/policy.json`] = generated.policy;
    documents[`${phase}/policy.manifest`] = generated.manifest;
    documents[`${phase}/status.json`] = status;
    documents[`${phase}/collector-status.jsonl`] = [structuredClone(status), stopped];
    documents[`${phase}/events.jsonl`] = [initial, allowed, denied, final];
    documents[`${phase}/snapshot.jsonl`] = [{
      schemaVersion: 2, recordKind: 'snapshot-header', policyDigest: generated.policyDigest,
      objectDigest: endpoints.objectDigest, containmentDigest, containmentCount: 1,
      pinRoot: meta.pinRoot,
    }, { ...structuredClone(final), eventsSeen: '0' }];
  }
  documents['cleanup.json'] = { ok: true, containersRemoved: true, networkRemoved: true, pinRootsRemoved: true };
  function write() {
    for (const [relative, value] of Object.entries(documents)) {
      fs.mkdirSync(path.dirname(path.join(directory, relative)), { recursive: true });
      const text = relative.endsWith('.jsonl')
        ? value.map((record) => JSON.stringify(record)).join('\n') + '\n'
        : relative.endsWith('.manifest') ? value : JSON.stringify(value) + '\n';
      fs.writeFileSync(path.join(directory, relative), text);
    }
  }
  write();
  return { directory, documents, write };
}

test('POC policies render exact opposite /32 TCP8080 rules with gateway containment', async () => {
  const { createPocPolicies } = await importHelper();
  const generated = createPocPolicies('172.30.201.2', '172.30.201.3', '172.30.201.1');
  assert.match(generated.phases.allowA.manifest, /\ncidr\t172\.30\.201\.2\/32\ttcp\t8080\t[1-9][0-9]*\n$/);
  assert.match(generated.phases.allowB.manifest, /\ncidr\t172\.30\.201\.3\/32\ttcp\t8080\t[1-9][0-9]*\n$/);
  assert.match(generated.phases.allowA.manifest, /\ncontainment\t172\.30\.201\.1\/32\n/);
  assert.notEqual(generated.phases.allowA.policyDigest, generated.phases.allowB.policyDigest);
  for (const phase of Object.values(generated.phases)) assert.equal(phase.policyDigest, hash(phase.manifest));
  assert.throws(() => createPocPolicies('172.30.201.2', '172.30.201.2', '172.30.201.1'), /distinct/);
  assert.throws(() => createPocPolicies('example.com', '172.30.201.3', '172.30.201.1'), /IPv4/);
});

test('POC verifies complete matching evidence and CLI emits JSON', async (t) => {
  const { directory } = await fixture(t);
  const { verifyPocEvidence } = await importHelper();
  const result = verifyPocEvidence(directory);
  assert.equal(result.status, 'passed');
  assert.equal(result.phases.allowA.allowedAddress, '172.30.201.2');
  assert.equal(result.phases.allowB.deniedAddress, '172.30.201.2');
  const cli = spawnSync(process.execPath, [helperPath, 'verify', directory], { encoding: 'utf8' });
  assert.equal(cli.status, 0, cli.stderr);
  assert.equal(JSON.parse(cli.stdout).status, 'passed');
  const policies = spawnSync(process.execPath, [helperPath, 'policies', '172.30.201.2', '172.30.201.3', '172.30.201.1'], { encoding: 'utf8' });
  assert.equal(policies.status, 0, policies.stderr);
  assert.equal(JSON.parse(policies.stdout).phases.allowA.policy.mode, 'enforce');
});

test('POC rejects incomplete or contradictory evidence', async (t) => {
  const { verifyPocEvidence } = await importHelper();
  const mutations = {
    'missing probe': (d) => d['probes.jsonl'].pop(),
    'duplicate probe': (d) => { d['probes.jsonl'][1] = d['probes.jsonl'][0]; },
    'baseline body wrong': (d) => { d['probes.jsonl'][0].body = 'B'; },
    'blocked request succeeded': (d) => { d['probes.jsonl'][3].httpCode = '200'; },
    'server received blocked request': (d) => d['server-b.jsonl'].push({ endpoint: 'b', path: '/allowA/b' }),
    'wrong policy CIDR': (d) => { d['allowA/policy.json'].rules[0].destination = '0.0.0.0/0'; },
    'manifest edited independently': (d) => { d['allowA/policy.manifest'] += 'resolver\t8.8.8.8\n'; },
    'status digest forged': (d) => { d['allowA/status.json'].policyDigest = `sha256:${'e'.repeat(64)}`; },
    'wrong cgroup': (d) => { d['allowA/events.jsonl'][2].cgroupId = '999'; },
    'wrong generation': (d) => { d['allowB/events.jsonl'][2].policyGeneration = '1'; },
    'wrong denied address': (d) => { d['allowA/events.jsonl'][2].destinationAddress = d['endpoints.json'].a; },
    'wrong denied protocol': (d) => { d['allowA/events.jsonl'][2].protocol = 17; },
    'wrong denied port': (d) => { d['allowA/events.jsonl'][2].destinationPort = 443; },
    'audit-only denied record': (d) => { d['allowA/events.jsonl'][2].enforcementApplied = false; },
    'allowed rule ID forged': (d) => { d['allowA/events.jsonl'][1].ruleId = 1; },
    'missing decision metadata': (d) => { delete d['allowA/events.jsonl'][2].expiresMonotonicNs; },
    'missing connect4 denial': (d) => { d['allowA/events.jsonl'][2].hook = 6; },
    'missing final stats': (d) => d['allowA/events.jsonl'].pop(),
    'wrong event count': (d) => { d['allowA/events.jsonl'].at(-1).eventsSeen = '3'; },
    'lost event': (d) => { d['allowA/events.jsonl'].at(-1).counters.ringbufDrops = '1'; },
    'decoder error': (d) => { d['allowA/events.jsonl'].at(-1).decoderErrors = '1'; },
    'counter fabrication': (d) => { d['allowA/events.jsonl'].at(-1).counters.denied = '2'; },
    'policy miss counter fabricated': (d) => { d['allowA/events.jsonl'].at(-1).counters.policyMisses = '0'; },
    'snapshot mismatch': (d) => { d['allowA/snapshot.jsonl'][1].counters.allowed = '2'; },
    'snapshot mistaken for collector': (d) => { d['allowA/snapshot.jsonl'][1].eventsSeen = '2'; },
    'collector did not stop': (d) => d['allowA/collector-status.jsonl'].pop(),
    'incomplete kernel attachment': (d) => { d['allowA/status.json'].attestation.linkIds.pop(); },
    'incomplete cleanup': (d) => { d['cleanup.json'].pinRootsRemoved = false; },
  };
  for (const [name, mutate] of Object.entries(mutations)) {
    await t.test(name, async (t) => {
      const { directory, documents, write } = await fixture(t);
      mutate(documents);
      write();
      assert.throws(() => verifyPocEvidence(directory));
    });
  }
});

test('POC correlates ingress replies using their source endpoint', async (t) => {
  const { directory, documents, write } = await fixture(t);
  const events = documents['allowA/events.jsonl'];
  events.splice(2, 0, {
    ...events[1], hook: 5, sourceAddress: documents['endpoints.json'].a,
    sourcePort: 8080, destinationAddress: '172.30.201.4', destinationPort: 40000,
    packetBytes: 128,
  });
  events.at(-1).eventsSeen = '3';
  events.at(-1).counters.allowed = '2';
  documents['allowA/snapshot.jsonl'][1].counters.allowed = '2';
  write();
  const { verifyPocEvidence } = await importHelper();
  assert.equal(verifyPocEvidence(directory).phases.allowA.allowedEvents, '2');
});

test('POC rejects truncated JSONL and CLI reports failure without passed output', async (t) => {
  const { directory } = await fixture(t);
  const file = path.join(directory, 'allowA/events.jsonl');
  fs.writeFileSync(file, fs.readFileSync(file, 'utf8').trimEnd());
  const cli = spawnSync(process.execPath, [helperPath, 'verify', directory], { encoding: 'utf8' });
  assert.equal(cli.status, 1);
  assert.equal(cli.stdout, '');
  assert.match(cli.stderr, /missing complete final line/);
});


test('capacity evidence binds allowed decisions to the endpoint rule, not the lowest numeric ID', async t => {
  const { directory, documents, write } = await fixture(t, 16384);
  const { verifyPocEvidence } = await importHelper();
  const { renderEbpfEgressManifest } = await import('../lib/guardd/enforcement-backend.js');
  assert.equal(verifyPocEvidence(directory).status, 'passed');
  for (const phase of ['allowA', 'allowB']) {
    const policy = documents[`${phase}/policy.json`];
    const { ruleIdMap } = renderEbpfEgressManifest(policy.rules, policy.resolvers, policy.platformContainmentCidrs);
    const event = documents[`${phase}/events.jsonl`].find(record => record.verdict === 'allow');
    const correctId = event.ruleId;
    const lowestId = Number(Object.keys(ruleIdMap)[0]);
    assert.notEqual(correctId, lowestId);
    assert.match(ruleIdMap[lowestId], /^capacity-/);
    event.ruleId = lowestId;
    write();
    assert.throws(() => verifyPocEvidence(directory), /invalid allowed decision/);
    event.ruleId = correctId;
    write();
  }
  assert.equal(verifyPocEvidence(directory).status, 'passed');
});
