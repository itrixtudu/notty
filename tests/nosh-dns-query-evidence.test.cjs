'use strict';

const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const test = require('node:test');

const DIGEST = `sha256:${'a'.repeat(64)}`;
const CREATED_AT = '2026-09-20T00:00:00.000Z';

function query(overrides = {}) {
  return {
    schemaVersion: 2, recordKind: 'decision', timestampMonotonicNs: '1000000000',
    cgroupId: '42', policyGeneration: '1', hook: 6, family: 4, protocol: 17,
    sourceAddress: '10.240.1.3', destinationAddress: '1.1.1.1',
    sourcePort: 43000, destinationPort: 53, verdict: 'allow',
    decisionClass: 'dns-observation', reason: 'dns-query-observed', reasonCode: 17,
    enforcementApplied: false, containmentId: '', ruleId: 0, packetBytes: 70,
    transactionId: 1, domain: 'api.example.com', expiresMonotonicNs: '0',
    ...overrides,
  };
}

function answer() {
  return {
    schemaVersion: 2, recordKind: 'dns-answer', timestampMonotonicNs: '1100000000',
    cgroupId: '42', policyGeneration: '1', hook: 5, transportFamily: 4,
    transportProtocol: 17, resolverAddress: '1.1.1.1', resolverPort: 53,
    clientPort: 43000, domain: 'api.example.com', dnsRecordType: 'A',
    answerAddress: '203.0.113.10', decisionClass: 'dns-observation',
    reason: 'dns-answer', reasonCode: 16, enforcementApplied: false,
    transactionId: 1, expiresMonotonicNs: '5000000000',
  };
}

function connection() {
  return query({
    timestampMonotonicNs: '1200000000', hook: 1, protocol: 6,
    destinationAddress: '203.0.113.10', destinationPort: 443,
    decisionClass: 'observed', reason: 'learn-observed', reasonCode: 4,
    domain: '', transactionId: 0, packetBytes: 0,
  });
}

function writeEvidence(t, records, sourceOverrides = {}) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'nosh-dns-query-'));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const content = records.map(record => JSON.stringify(record)).join('\n') + '\n';
  fs.writeFileSync(path.join(root, 'nosh-egress.jsonl'), content);
  const manifest = {
    schemaVersion: 1, apiVersion: 'notty.dev/v1alpha1',
    kind: 'NoshSecurityEvidenceManifest', generatedAt: CREATED_AT,
    runId: 'dns-query-test', mode: 'egress-learn',
    subject: { containerId: 'b'.repeat(64), imageDigest: DIGEST, workspace: root },
    startedAt: CREATED_AT, endedAt: '2026-09-20T00:00:05.000Z',
    profileRevision: 'candidate', trainingEligible: true,
    evidenceUse: 'training', complete: true,
    sources: [{ name: 'nosh-egress', path: 'nosh-egress.jsonl', format: 'ndjson',
      required: true, present: true, bytes: Buffer.byteLength(content),
      records: records.length, hash: crypto.createHash('sha256').update(content).digest('hex'),
      lostEvents: 0, parseErrors: 0, completionMarker: 'final-stats-clean', complete: true,
      ...sourceOverrides }],
  };
  const manifestPath = path.join(root, 'evidence-manifest.json');
  fs.writeFileSync(manifestPath, JSON.stringify(manifest));
  return manifestPath;
}

function legacyQuery(decision = query()) {
  return {
    direction: 'egress', protocol: decision.protocol === 17 ? 'udp' : 'tcp',
    destination: decision.destinationAddress, port: 53,
    reason: 'dns-observation evidence cannot become reviewed network authority',
    observation: { address: decision.destinationAddress, count: 1, decision },
  };
}

function candidate(unresolvedObservations) {
  return {
    workspaceKey: 'a'.repeat(64), workspaceIdentity: { dev: '1', ino: '2' },
    imageDigest: DIGEST, manifestHash: DIGEST, policyHash: DIGEST, rulesHash: DIGEST,
    rules: [], unresolvedObservations, revision: 'dns-query-test', createdAt: CREATED_AT,
    evidenceRunId: 'dns-query-test', evidenceManifestHash: DIGEST,
  };
}

test('successful DNS queries and answers are retained without inventing authority or capture gaps', async t => {
  const { loadEvidenceInputs } = await import('../lib/guard/ingestion.js');
  const { compileNetworkArtifact } = await import('../lib/guard/network.js');
  const loaded = await loadEvidenceInputs([writeEvidence(t, [query(), answer()])]);
  const policy = compileNetworkArtifact(loaded.records);
  assert.deepEqual(policy.spec.egress, []);
  assert.deepEqual(policy.spec.unresolvedObservations, []);
  const advisory = loaded.records.find(record => record.event?.type === 'recommendation');
  assert.deepEqual(advisory.event.value.decision, query());
  assert.match(advisory.event.value.reason, /correlation evidence/);
});

test('DNS queries retain correlation while only an actual connection creates a literal proposal', async t => {
  const { loadEvidenceInputs } = await import('../lib/guard/ingestion.js');
  const { compileNetworkArtifact } = await import('../lib/guard/network.js');
  const { literalRuntimeRules } = await import('../lib/guard/review/runtime-adapter.js');
  const loaded = await loadEvidenceInputs([writeEvidence(t, [query(), answer(), connection()])]);
  const policy = compileNetworkArtifact(loaded.records);
  assert.deepEqual(policy.spec.unresolvedObservations, []);
  assert.equal(policy.spec.egress.length, 1);
  assert.equal(policy.spec.egress[0].destination, 'api.example.com');
  assert.equal(policy.spec.egress[0].observations[0].dnsChain[0].address, '203.0.113.10');
  const rules = literalRuntimeRules(policy.spec.egress);
  assert.equal(rules.length, 1);
  assert.equal(rules[0].destination, '203.0.113.10/32');
  assert.deepEqual(rules[0].ports, [443]);
});

test('legacy query evidence remains visible without changing its immutable candidate', async () => {
  const { createRuntimeCandidateGraphRecords, runtimeReviewScope } =
    await import('../lib/guard/review/runtime-adapter.js');
  const current = candidate([legacyQuery()]);
  const before = JSON.stringify(current);
  const result = createRuntimeCandidateGraphRecords(runtimeReviewScope(current), current);
  assert.equal(JSON.stringify(current), before);
  assert.equal(result.records.proposals.length, 0);
  assert.equal(result.records.coverage[0].blocking, false);
  assert.equal(result.records.coverage[0].status, 'complete');
  assert.equal(result.records.coverage[0].counters.dnsQueries, '1');
  assert.equal(result.records.findings[0].severity, 'info');
  assert.equal(result.records.findings[0].blocking, false);
  assert.deepEqual(result.records.findings[0].properties.observation, current.unresolvedObservations[0]);
  assert.equal(result.source.artifactDigest, current.manifestHash);
});

test('reclassifying legacy evidence requires decisions bound to the new graph', async () => {
  const { createRuntimeCandidateGraphRecords, runtimeReviewScope } =
    await import('../lib/guard/review/runtime-adapter.js');
  const { createReviewBundleArtifact } = await import('../lib/guard/review/bundle-store.js');
  const { createDecisionSet, createPolicyIR } = await import('../lib/guard/review/documents.js');
  const current = candidate([legacyQuery()]);
  const scope = runtimeReviewScope(current);
  const result = createRuntimeCandidateGraphRecords(scope, current, { includeSubject: true });
  const old = structuredClone(result);
  old.records.coverage[0].blocking = true;
  old.records.coverage[0].status = 'degraded';
  old.records.coverage[0].counters.unresolved = '1';
  delete old.records.coverage[0].counters.dnsQueries;
  old.records.coverage[0].gaps = [legacyQuery().reason];
  old.records.findings[0].severity = 'high';
  old.records.findings[0].blocking = true;
  old.records.findings[0].message = legacyQuery().reason;
  delete old.records.findings[0].properties.classification;
  old.source.coverage.status = 'degraded';
  old.source.coverage.gaps = [legacyQuery().reason];
  const artifact = value => createReviewBundleArtifact({
    scope, sources: [value.source], records: value.records,
    baseline: { selection: 'none', bundleDigest: null, reason: null },
    basePolicyDigest: DIGEST, privacyProfile: 'private-review', createdAt: CREATED_AT,
  });
  const previous = artifact(old);
  const updated = artifact(result);
  const decisions = createDecisionSet({ graph: previous.graph, decisions: [],
    reviewer: 'dns-reviewer', createdAt: CREATED_AT });
  assert.notEqual(previous.graph.contentDigest, updated.graph.contentDigest);
  assert.notEqual(previous.bundle.bundleDigest, updated.bundle.bundleDigest);
  assert.throws(() => createPolicyIR({ graph: updated.graph, decisionSet: decisions }),
    /graph .* does not match the decision set/);
});

test('malformed query tuples and unrelated unresolved observations stay blocking', async t => {
  const { isLearningDnsQueryEvidence } = await import('../lib/guard/dns-query-evidence.js');
  const { createRuntimeCandidateGraphRecords, runtimeReviewScope } =
    await import('../lib/guard/review/runtime-adapter.js');
  const invalid = [
    ['unknown schema', { schemaVersion: 3 }], ['unknown field', { unknown: true }],
    ['wrong class', { decisionClass: 'coverage-gap' }], ['unknown reason', { reasonCode: 99 }],
    ['wrong reason name', { reason: 'dns-response-unmatched' }], ['denied', { verdict: 'deny' }],
    ['enforced', { enforcementApplied: true }], ['socket hook', { hook: 1 }],
    ['non-DNS port', { destinationPort: 443 }], ['invalid address', { destinationAddress: 'invalid' }],
    ['family mismatch', { family: 6 }], ['invalid protocol', { protocol: 0 }],
    ['invalid source port', { sourcePort: 0 }], ['empty packet', { packetBytes: 0 }],
    ['invalid domain', { domain: 'api..example.com' }], ['bad transaction', { transactionId: 65536 }],
    ['rule authority', { ruleId: 1 }], ['containment', { containmentId: 'platform-endpoint:1.1.1.1' }],
    ['grant expiry', { expiresMonotonicNs: '5000000000' }], ['invalid time', { timestampMonotonicNs: '-1' }],
  ];
  for (const [name, overrides] of invalid) await t.test(name, () => {
    const decision = query(overrides);
    assert.equal(isLearningDnsQueryEvidence(decision), false);
    const current = candidate([legacyQuery(decision)]);
    const result = createRuntimeCandidateGraphRecords(runtimeReviewScope(current), current);
    assert.equal(result.records.coverage[0].blocking, true);
    assert.equal(result.records.findings[0].blocking, true);
  });
  for (const mutation of [
    entry => { entry.reason = 'lost runtime event'; },
    entry => { entry.destination = '203.0.113.10'; },
    entry => { entry.direction = 'ingress'; },
    entry => { delete entry.observation; },
    entry => { entry.unknown = 'unresolved'; },
    entry => { entry.observation.unknown = true; },
    entry => { entry.observation.count = -1; },
  ]) {
    const entry = legacyQuery();
    mutation(entry);
    const current = candidate([entry, legacyQuery()]);
    const result = createRuntimeCandidateGraphRecords(runtimeReviewScope(current), current);
    assert.equal(result.records.coverage[0].blocking, true);
    assert.equal(result.records.coverage[0].counters.unresolved, '1');
  }
});

test('successful IPv6 and TCP DNS queries use the same advisory classification', async () => {
  const { isLearningDnsQueryEvidence, isLegacyLearningDnsQueryObservation } =
    await import('../lib/guard/dns-query-evidence.js');
  for (const family of [4, 6]) for (const protocol of [6, 17]) {
    const decision = query({ family, protocol,
      ...(family === 6 ? { sourceAddress: 'fd42::3', destinationAddress: '2606:4700:4700::1111' } : {}) });
    assert.equal(isLearningDnsQueryEvidence(decision), true);
    assert.equal(isLegacyLearningDnsQueryObservation(legacyQuery(decision)), true);
  }
});

test('real capture gaps and event loss are not reclassified as successful DNS', async t => {
  const { loadEvidenceInputs } = await import('../lib/guard/ingestion.js');
  const { compileNetworkArtifact } = await import('../lib/guard/network.js');
  for (const [reasonCode, reason] of [[7, 'parse-gap'], [11, 'unsupported-gap'], [10, 'dns-response-unmatched']]) {
    const loaded = await loadEvidenceInputs([writeEvidence(t, [query(), query({
      reasonCode, reason, decisionClass: 'coverage-gap',
    })])]);
    const policy = compileNetworkArtifact(loaded.records);
    assert.deepEqual(policy.spec.egress, []);
    assert.equal(policy.spec.unresolvedObservations.length, 1);
    assert.match(policy.spec.unresolvedObservations[0].reason, /must be resolved before policy authorization/);
  }
  for (const loss of [{ lostEvents: 1 }, { parseErrors: 1 }]) {
    await assert.rejects(loadEvidenceInputs([writeEvidence(t, [query()], loss)]),
      /lost events|parse errors/);
  }
});

test('ingestion cannot normalize malformed queries into legacy successful-query exceptions', async t => {
  const { loadEvidenceInputs } = await import('../lib/guard/ingestion.js');
  const { compileNetworkArtifact } = await import('../lib/guard/network.js');
  const { createRuntimeCandidateGraphRecords, runtimeReviewScope } =
    await import('../lib/guard/review/runtime-adapter.js');
  for (const overrides of [
    { unknown: true }, { enforcementApplied: 'false' }, { schemaVersion: 1 },
    { hook: 5 }, { destinationPort: 0 }, { reasonCode: '17' },
  ]) {
    const loaded = await loadEvidenceInputs([writeEvidence(t, [query(overrides)])]);
    const policy = compileNetworkArtifact(loaded.records);
    assert.deepEqual(policy.spec.egress, []);
    assert.equal(policy.spec.unresolvedObservations.length, 1);
    const current = candidate(policy.spec.unresolvedObservations);
    const result = createRuntimeCandidateGraphRecords(runtimeReviewScope(current), current);
    assert.equal(result.records.coverage[0].blocking, true);
    assert.equal(result.records.findings[0].blocking, true);
  }
});
