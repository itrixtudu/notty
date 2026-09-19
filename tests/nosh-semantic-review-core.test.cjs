'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');
const os = require('node:os');

async function loadReviewCore() {
  return import('../lib/guard/review/index.js');
}

const CREATED_AT = '2026-08-16T12:00:00.000Z';

test('CLI decisions round-trips manual edits and refuses graph rebinding or overwrite', async (t) => {
  const fixture = await createFixture();
  const bundles = await import('../lib/guard/review/bundle-store.js');
  const { commandReview } = await import('../lib/guard/review/cli.js');
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'nosh-cli-decisions-'));
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  const bundle = path.join(directory, 'bundle');
  const artifact = bundles.createReviewBundleArtifact({
    createdAt: CREATED_AT,
    scope: fixture.scope,
    sources: [fixture.source],
    basePolicyDigest: fixture.basePolicyDigest,
    records: Object.fromEntries([
      'nodes', 'observations', 'coverage', 'findings', 'proposals', 'diff',
    ].map((role) => [role, fixture.graph[role]])),
  });
  await bundles.writeReviewBundleArtifact(bundle, artifact);
  const draft = path.join(directory, 'draft.json');
  const output = path.join(directory, 'decisions.json');
  const args = ['decisions', '--bundle', bundle, '--reviewer', 'operator'];
  assert.equal(await commandReview([...args, '--output', draft]), 0);
  const edited = JSON.parse(fs.readFileSync(draft, 'utf8'));
  assert.equal(edited.decisions[0].disposition, 'needs-review');
  edited.decisions[0].disposition = 'reject';
  edited.decisions[0].rationale = 'Deny this destination for the negative control';
  fs.writeFileSync(draft, JSON.stringify(edited));
  assert.equal(await commandReview([...args, '--input', draft, '--output', output]), 0);
  const rebuilt = JSON.parse(fs.readFileSync(output, 'utf8'));
  fixture.core.validateDecisionSet(rebuilt);
  assert.equal(rebuilt.decisions[0].disposition, 'reject');
  assert.notEqual(rebuilt.contentDigest, edited.contentDigest);
  await assert.rejects(commandReview([...args, '--output', output]), /EEXIST/);
  edited.graphContentDigest = fixture.core.sha256Digest('different graph');
  fs.writeFileSync(draft, JSON.stringify(edited));
  await assert.rejects(commandReview([
    ...args, '--input', draft, '--output', path.join(directory, 'wrong.json'),
  ]), /graphContentDigest does not match/);
  assert.equal(fs.existsSync(path.join(directory, 'wrong.json')), false);
});

async function createFixture() {
  const core = await loadReviewCore();
  const subjectId = core.createStableId('subject', { project: 'threejsui-cleaning' });
  const scope = core.createScope({
    class: 'build',
    subjectId,
    projectKey: 'a'.repeat(64),
    platform: 'linux/amd64',
    target: null,
    dockerfileDigest: core.sha256Digest('FROM node'),
  });
  const artifactDigest = core.sha256Digest('build evidence');
  const sourceId = core.createSourceId(
    core.createStableId('build-pass', { run: 'fixture', pass: 'cold' }),
    'ebpf-network',
    artifactDigest,
  );
  const evidenceRef = core.createSourceRecordId(sourceId, 0);
  const projectNode = core.createGraphNode({
    scopeDigest: scope.scopeDigest,
    nodeType: 'project',
    label: 'threejsui-cleaning',
    identity: { projectKey: scope.projectKey },
    properties: { phase: 'cold' },
    evidenceRefs: [evidenceRef],
  });
  const endpointNode = core.createGraphNode({
    scopeDigest: scope.scopeDigest,
    nodeType: 'domain',
    label: 'registry.npmjs.org',
    identity: { fqdn: 'registry.npmjs.org' },
    properties: { protocol: 'tcp', port: 443 },
    evidenceRefs: [evidenceRef],
  });
  const observation = core.createObservation({
    scopeDigest: scope.scopeDigest,
    observationType: 'connects',
    subjectId: projectNode.id,
    objectId: endpointNode.id,
    basis: 'observed',
    confidence: 100,
    count: '4',
    firstObservedAt: '2026-08-16T11:00:00.000Z',
    lastObservedAt: '2026-08-16T11:00:04.000Z',
    evidenceRefs: [evidenceRef],
    properties: { direction: 'egress' },
  });
  const coverage = core.createCoverageMarker({
    scopeDigest: scope.scopeDigest,
    domain: 'network',
    status: 'complete',
    sourceIds: [sourceId],
    counters: { lostEvents: '0', parseErrors: '0' },
    gaps: [],
    blocking: false,
  });
  const proposal = core.createPolicyProposal({
    scopeDigest: scope.scopeDigest,
    scopeClass: 'build',
    proposalType: 'network-egress',
    intent: {
      domain: 'network',
      subjectId: projectNode.id,
      effect: 'allow',
      direction: 'egress',
      peer: { kind: 'fqdn', value: 'registry.npmjs.org' },
      transport: { protocol: 'tcp', ports: [443] },
    },
    baselineState: 'new',
    rationale: 'Observed during the cold build pass.',
    evidenceRefs: [evidenceRef],
    observationRefs: [observation.id],
    targetFeasibility: [
      { target: 'cilium', status: 'exact', reasons: [] },
      { target: 'guard-nftables', status: 'conditional', reasons: ['Managed DNS is required.'] },
      { target: 'gateway-iptables', status: 'conditional', reasons: ['Managed DNS is required.'] },
    ],
  });
  const finding = core.createFinding({
    scopeDigest: scope.scopeDigest,
    findingType: 'drift-new',
    severity: 'medium',
    blocking: true,
    message: 'New registry egress requires review.',
    semanticRefs: [proposal.id],
    evidenceRefs: [evidenceRef],
    properties: {},
  });
  const diff = core.createGraphDiff({
    scopeDigest: scope.scopeDigest,
    entityId: endpointNode.id,
    changeType: 'added',
    beforeDigest: null,
    afterDigest: core.sha256Digest(endpointNode),
    policyRelevant: true,
    summary: 'A new package registry destination was observed.',
    evidenceRefs: [evidenceRef],
  });
  const records = {
    nodes: [endpointNode, projectNode],
    observations: [observation],
    coverage: [coverage],
    findings: [finding],
    proposals: [proposal],
    diff: [diff],
  };
  const streams = Object.fromEntries(Object.entries(records).map(([role, roleRecords]) => (
    [role, core.createHashAddressedStream(role, roleRecords)]
  )));
  const source = {
    id: sourceId,
    artifactKind: 'NoshBuildEvidenceManifest',
    artifactDigest,
    coverage: {
      status: 'complete',
      lostEvents: '0',
      parseErrors: '0',
      gaps: [],
    },
  };
  const basePolicyDigest = core.sha256Digest({ rules: [] });
  const bundle = core.createReviewBundle({
    createdAt: CREATED_AT,
    scope,
    sources: [source],
    streams: Object.values(streams),
    basePolicyDigest,
  });
  const graph = core.materializeSemanticGraph(bundle, streams);
  return {
    core,
    scope,
    source,
    evidenceRef,
    projectNode,
    endpointNode,
    observation,
    coverage,
    finding,
    proposal,
    diff,
    streams,
    bundle,
    graph,
    basePolicyDigest,
  };
}

test('JCS canonicalization and semantic IDs are deterministic', async () => {
  const core = await loadReviewCore();
  const first = { z: [true, null], b: 1, a: 'é' };
  const second = { a: 'é', b: 1, z: [true, null] };
  assert.equal(core.jcsCanonicalize(first), '{"a":"é","b":1,"z":[true,null]}');
  assert.equal(core.sha256Digest(first), core.sha256Digest(second));
  assert.equal(
    core.createStableId('node', first),
    core.createStableId('node', second),
  );
  assert.throws(
    () => core.jcsCanonicalize({ invalid: Number.POSITIVE_INFINITY }),
    /finite JSON number/,
  );
  assert.throws(
    () => core.jcsCanonicalize({ invalid: '\ud800' }),
    /unpaired high surrogate/,
  );
});

test('hash-addressed streams sort records and reject content tampering', async () => {
  const fixture = await createFixture();
  const stream = fixture.streams.nodes;
  assert.deepEqual(
    stream.records.map((record) => record.id),
    [...stream.records.map((record) => record.id)].sort(),
  );
  assert.match(stream.descriptor.path, /^streams\/nodes\.[a-f0-9]{64}\.ndjson$/);
  assert.deepEqual(
    fixture.core.parseHashAddressedStream('nodes', stream.content, stream.descriptor),
    stream.records,
  );
  const reordered = fixture.core.createHashAddressedStream(
    'nodes',
    [...stream.records].reverse(),
  );
  assert.equal(reordered.content, stream.content);
  assert.equal(reordered.descriptor.sha256, stream.descriptor.sha256);
  assert.throws(
    () => fixture.core.parseHashAddressedStream(
      'nodes',
      stream.content.replace('threejsui-cleaning', 'tampered-project'),
      stream.descriptor,
    ),
    /byte count|digest/,
  );
  const nonCanonicalRecord = Object.fromEntries(
    Object.entries(stream.records[0]).reverse(),
  );
  const pretty = `${JSON.stringify(nonCanonicalRecord)}\n`;
  const prettyDescriptor = {
    ...stream.descriptor,
    sha256: fixture.core.sha256Digest(pretty),
    bytes: String(Buffer.byteLength(pretty)),
    records: '1',
  };
  prettyDescriptor.path = `streams/nodes.${prettyDescriptor.sha256.slice(7)}.ndjson`;
  assert.throws(
    () => fixture.core.parseHashAddressedStream('nodes', pretty, prettyDescriptor),
    /not JCS canonical/,
  );
});

test('review bundle materializes a frozen graph and binds every stream', async () => {
  const fixture = await createFixture();
  const graph = fixture.core.materializeSemanticGraph(fixture.bundle, fixture.streams);
  assert.equal(graph.kind, 'NoshSemanticGraph');
  assert.equal(graph.frozen, true);
  assert.equal(graph.revision, fixture.bundle.bundleDigest);
  assert.equal(graph.graphDigest, fixture.bundle.graphDigest);
  assert.equal(graph.proposalSetDigest, fixture.bundle.proposalSetDigest);
  assert.equal(graph.basePolicyDigest, fixture.basePolicyDigest);
  assert.equal(graph.nodes.length, 2);
  assert.equal(graph.proposals[0].id, fixture.proposal.id);
  assert.deepEqual(graph.proposals[0].observationRefs, [fixture.observation.id]);
  assert.equal(graph.contentDigest, fixture.core.computeSemanticGraphContentDigest(graph));

  const materializedTampering = structuredClone(graph);
  materializedTampering.proposals[0].intent.peer.value = 'attacker.example';
  assert.throws(
    () => fixture.core.validateSemanticGraph(materializedTampering),
    /contentDigest does not match the materialized graph/,
  );

  const danglingObservation = structuredClone(graph);
  danglingObservation.proposals[0].observationRefs = [
    fixture.core.createStableId('observation', { missing: true }),
  ];
  danglingObservation.contentDigest = fixture.core.computeSemanticGraphContentDigest(
    danglingObservation,
  );
  assert.throws(
    () => fixture.core.validateSemanticGraph(danglingObservation),
    /missing observation reference/,
  );

  const sameContentDifferentTime = fixture.core.createReviewBundle({
    createdAt: '2026-08-17T12:00:00.000Z',
    scope: fixture.scope,
    sources: [fixture.source],
    streams: Object.values(fixture.streams),
    basePolicyDigest: fixture.basePolicyDigest,
  });
  assert.equal(sameContentDifferentTime.graphDigest, fixture.bundle.graphDigest);
  assert.notEqual(sameContentDifferentTime.bundleDigest, fixture.bundle.bundleDigest);

  const timestampTampered = structuredClone(fixture.bundle);
  timestampTampered.createdAt = '2026-08-17T12:00:00.000Z';
  assert.throws(
    () => fixture.core.validateReviewBundle(timestampTampered),
    /bundleDigest does not match/,
  );

  const tampered = structuredClone(fixture.bundle);
  tampered.streams[0].records = '100';
  assert.throws(
    () => fixture.core.validateReviewBundle(tampered),
    /graphDigest does not match|bundleDigest does not match/,
  );
});

test('portable projection redacts, salts hashes, drops private records, and enforces never-store', async () => {
  const fixture = await createFixture();
  const privateFieldsNode = fixture.core.createGraphNode({
    scopeDigest: fixture.scope.scopeDigest,
    nodeType: 'file',
    label: 'package file',
    identity: { path: '/workspace/package-lock.json' },
    properties: {
      pid: '4294967297',
      owner: 'kross',
    },
    evidenceRefs: [fixture.evidenceRef],
    privacy: {
      classification: 'portable-sensitive',
      fields: [
        { path: '/identity/path', class: 'portable-hashed' },
        { path: '/properties/owner', class: 'private' },
        { path: '/properties/environment', class: 'never-store' },
      ],
    },
  });
  const projected = fixture.core.projectPortableRecord('nodes', privateFieldsNode, {
    salt: 'fixture-portable-salt-2026',
  });
  assert.match(projected.identity.path, /^sha256:[a-f0-9]{64}$/);
  assert.equal(projected.properties.owner, '[redacted]');
  assert.equal(projected.properties.pid, '4294967297');

  const whollyPrivate = fixture.core.createGraphNode({
    scopeDigest: fixture.scope.scopeDigest,
    nodeType: 'file',
    label: 'secret file',
    identity: { path: '/run/secrets/token' },
    properties: {},
    evidenceRefs: [fixture.evidenceRef],
    privacy: { classification: 'private', fields: [] },
  });
  assert.equal(fixture.core.projectPortableRecord('nodes', whollyPrivate), null);
  assert.throws(
    () => fixture.core.createGraphNode({
      scopeDigest: fixture.scope.scopeDigest,
      nodeType: 'process',
      label: 'bad process',
      identity: { pid: '123' },
      properties: { environment: 'TOKEN=secret' },
      evidenceRefs: [fixture.evidenceRef],
      privacy: {
        classification: 'portable-sensitive',
        fields: [{ path: '/properties/environment', class: 'never-store' }],
      },
    }),
    /must never be stored/,
  );
});

test('DecisionSet binds graph, proposal set, base policy, and scope into PolicyIR', async () => {
  const fixture = await createFixture();
  const decisions = fixture.core.createDecisionSet({
    createdAt: CREATED_AT,
    reviewer: 'reviewer@example.test',
    graph: fixture.graph,
    decisions: [{
      proposalId: fixture.proposal.id,
      disposition: 'accept',
      rationale: 'Required for deterministic package installation.',
      targetAcknowledgements: [{
        target: 'guard-nftables',
        status: 'conditional',
        rationale: 'The managed DNS prerequisite is part of the deployment target.',
      }],
    }],
  });
  const policyIR = fixture.core.createPolicyIR({
    createdAt: CREATED_AT,
    decisionSet: decisions,
    graph: fixture.graph,
  });
  assert.equal(policyIR.graphDigest, fixture.bundle.graphDigest);
  assert.equal(policyIR.graphContentDigest, fixture.graph.contentDigest);
  assert.equal(policyIR.proposalSetDigest, fixture.bundle.proposalSetDigest);
  assert.equal(policyIR.basePolicyDigest, fixture.basePolicyDigest);
  assert.equal(policyIR.decisionSetDigest, decisions.contentDigest);
  assert.deepEqual(policyIR.defaults, { ingress: 'deny', egress: 'deny' });
  assert.equal(policyIR.rules.length, 1);
  assert.equal(policyIR.rules[0].peer.value, 'registry.npmjs.org');
  assert.equal(policyIR.rules[0].proposalId, fixture.proposal.id);

  const substitutedGraph = structuredClone(fixture.graph);
  substitutedGraph.proposals[0].intent.peer.value = 'attacker.example';
  substitutedGraph.contentDigest = fixture.core.computeSemanticGraphContentDigest(substitutedGraph);
  assert.equal(
    fixture.core.validateSemanticGraph(substitutedGraph).contentDigest,
    substitutedGraph.contentDigest,
  );
  assert.throws(
    () => fixture.core.createPolicyIR({
      decisionSet: decisions,
      graph: substitutedGraph,
    }),
    /graphContentDigest does not match the decision set/,
  );

  const unresolved = fixture.core.createDecisionSet({
    createdAt: CREATED_AT,
    reviewer: 'reviewer@example.test',
    graph: fixture.graph,
    decisions: [{
      proposalId: fixture.proposal.id,
      disposition: 'needs-review',
      rationale: 'Ownership is unresolved.',
    }],
  });
  assert.throws(
    () => fixture.core.createPolicyIR({
      decisionSet: unresolved,
      graph: fixture.graph,
    }),
    /still needs review/,
  );
});

test('HTTP assurance variants are evidence-bound and mutually exclusive', async () => {
  const fixture = await createFixture();
  const requestTargetSha256 = fixture.core.sha256Digest('/package/-/package-1.0.0.tgz');
  const contentSha256 = fixture.core.sha256Digest('reviewed package bytes');
  const redirectLocationSha256 = fixture.core.sha256Digest(
    'https://cdn.example.test/package-1.0.0.tgz',
  );
  const requestNode = fixture.core.createGraphNode({
    scopeDigest: fixture.scope.scopeDigest,
    nodeType: 'httpRequest',
    label: 'https://registry.npmjs.org:443',
    identity: {
      method: 'GET',
      scheme: 'https',
      host: 'registry.npmjs.org',
      port: 443,
      requestTargetSha256,
      representationHeadersSha256: fixture.core.sha256Digest({ accept: '*/*' }),
      requestBodySha256: null,
    },
    properties: { displayUrl: 'https://registry.npmjs.org/[redacted]' },
    evidenceRefs: [fixture.evidenceRef],
    privacy: {
      classification: 'portable-sensitive',
      fields: [{ path: '/properties/displayUrl', class: 'private' }],
    },
  });
  const responseNode = fixture.core.createGraphNode({
    scopeDigest: fixture.scope.scopeDigest,
    nodeType: 'httpResponse',
    label: 'HTTP 200',
    identity: { status: 200, contentSha256, redirectLocationSha256 },
    properties: { complete: true },
    evidenceRefs: [fixture.evidenceRef],
  });
  const requestObservation = fixture.core.createObservation({
    scopeDigest: fixture.scope.scopeDigest,
    observationType: 'requests',
    subjectId: fixture.projectNode.id,
    objectId: requestNode.id,
    basis: 'observed',
    confidence: 100,
    count: '1',
    evidenceRefs: [fixture.evidenceRef],
    properties: { provider: 'mitmproxy' },
  });
  const responseObservation = fixture.core.createObservation({
    scopeDigest: fixture.scope.scopeDigest,
    observationType: 'respondsWith',
    subjectId: requestNode.id,
    objectId: responseNode.id,
    basis: 'observed',
    confidence: 100,
    count: '1',
    evidenceRefs: [fixture.evidenceRef],
    properties: { complete: true },
  });
  const authorityGroupId = fixture.core.createStableId('authority', {
    requestNodeId: requestNode.id,
    endpointNodeId: fixture.endpointNode.id,
  });
  const endpoint = fixture.core.createPolicyProposal({
    scopeDigest: fixture.scope.scopeDigest,
    scopeClass: 'build',
    proposalType: 'observed-network-egress-endpoint-only',
    intent: fixture.proposal.intent,
    authorityGroupId,
    assurance: {
      contractVersion: 2,
      level: 'endpoint-only',
      mutableContent: true,
      evidenceBacked: true,
      requestEvidenceRefs: [requestNode.id],
      responseEvidenceRefs: [],
      integrityKind: 'none',
    },
    baselineState: 'new',
    rationale: 'Endpoint-only alternative.',
    evidenceRefs: [fixture.evidenceRef],
    observationRefs: [requestObservation.id],
    targetFeasibility: [{ target: 'gateway-iptables', status: 'exact', reasons: [] }],
  });
  const pinned = fixture.core.createPolicyProposal({
    scopeDigest: fixture.scope.scopeDigest,
    scopeClass: 'build',
    proposalType: 'observed-http-live-digest-gate',
    intent: {
      domain: 'http',
      subjectId: fixture.projectNode.id,
      effect: 'allow',
      direction: 'egress',
      peer: { kind: 'http-resource', value: requestNode.id },
      http: {
        contractVersion: 2,
        method: 'GET',
        scheme: 'https',
        host: 'registry.npmjs.org',
        port: 443,
        requestTargetSha256,
        representationHeadersSha256: fixture.core.sha256Digest({ accept: '*/*' }),
        response: {
          kind: 'live-digest',
          contentSha256,
          redirectLocationSha256,
          status: 200,
        },
      },
    },
    authorityGroupId,
    assurance: {
      contractVersion: 2,
      level: 'live-digest-gate',
      mutableContent: false,
      evidenceBacked: true,
      requestEvidenceRefs: [requestNode.id],
      responseEvidenceRefs: [responseNode.id],
      integrityKind: 'live-response-digest',
      contentDigest: contentSha256,
      proofDigest: contentSha256,
    },
    baselineState: 'new',
    rationale: 'Buffer and verify the observed bytes before release.',
    evidenceRefs: [fixture.evidenceRef],
    observationRefs: [requestObservation.id, responseObservation.id],
    targetFeasibility: [{ target: 'gateway-l7-proxy', status: 'exact', reasons: [] }],
  });
  const ipv6Input = structuredClone(pinned);
  delete ipv6Input.id;
  ipv6Input.intent.http.host = '2001:db8::1';
  const ipv6Proposal = fixture.core.createPolicyProposal(ipv6Input);
  assert.equal(ipv6Proposal.intent.http.host, '2001:db8::1');
  const bracketedIpv6Input = structuredClone(ipv6Input);
  bracketedIpv6Input.intent.http.host = '[2001:db8::1]';
  assert.throws(
    () => fixture.core.createPolicyProposal(bracketedIpv6Input),
    /canonical unbracketed hostname or IP literal/,
  );
  const graph = structuredClone(fixture.graph);
  graph.nodes = [...graph.nodes, requestNode, responseNode].sort((a, b) => a.id.localeCompare(b.id));
  graph.observations = [
    ...graph.observations,
    requestObservation,
    responseObservation,
  ].sort((a, b) => a.id.localeCompare(b.id));
  graph.proposals = [...graph.proposals, endpoint, pinned]
    .sort((a, b) => a.id.localeCompare(b.id));
  graph.contentDigest = fixture.core.computeSemanticGraphContentDigest(graph);
  fixture.core.validateSemanticGraph(graph);

  const decision = (proposal, disposition) => ({
    proposalId: proposal.id,
    disposition,
    rationale: `${disposition} for test.`,
  });
  assert.throws(
    () => fixture.core.createDecisionSet({
      createdAt: CREATED_AT,
      reviewer: 'reviewer@example.test',
      graph,
      decisions: [
        decision(fixture.proposal, 'reject'),
        decision(endpoint, 'accept'),
        decision(pinned, 'accept'),
      ],
    }),
    /more than one assurance variant/,
  );
  const decisionSet = fixture.core.createDecisionSet({
    createdAt: CREATED_AT,
    reviewer: 'reviewer@example.test',
    graph,
    decisions: [
      decision(fixture.proposal, 'reject'),
      decision(endpoint, 'reject'),
      decision(pinned, 'accept'),
    ],
  });
  const policyIR = fixture.core.createPolicyIR({
    createdAt: CREATED_AT,
    decisionSet,
    graph,
  });
  assert.equal(policyIR.rules.length, 1);
  assert.equal(policyIR.rules[0].domain, 'http');
  assert.equal(policyIR.rules[0].authorityGroupId, authorityGroupId);
  assert.equal(policyIR.rules[0].assurance.level, 'live-digest-gate');
  assert.equal(policyIR.rules[0].http.response.contentSha256, contentSha256);
  assert.equal(
    policyIR.rules[0].http.response.redirectLocationSha256,
    redirectLocationSha256,
  );
  const portableRequest = fixture.core.projectPortableRecord('nodes', requestNode);
  assert.equal(portableRequest.properties.displayUrl, '[redacted]');
  assert.equal(portableRequest.identity.requestTargetSha256, requestTargetSha256);

  const genericConstraint = structuredClone(pinned.intent);
  genericConstraint.constraints = { path: '/broader-than-reviewed' };
  assert.throws(
    () => fixture.core.validatePolicyIntent(genericConstraint),
    /generic constraints are not valid for HTTP policy/,
  );

  const mismatchedIntent = structuredClone(pinned.intent);
  mismatchedIntent.http.requestTargetSha256 = fixture.core.sha256Digest('/different.tgz');
  const { id: ignoredProposalId, ...pinnedInput } = pinned;
  const mismatchedProposal = fixture.core.createPolicyProposal({
    ...pinnedInput,
    intent: mismatchedIntent,
  });
  assert.ok(ignoredProposalId);
  const mismatchedGraph = structuredClone(graph);
  mismatchedGraph.proposals = mismatchedGraph.proposals
    .map((proposal) => proposal.id === pinned.id ? mismatchedProposal : proposal)
    .sort((left, right) => left.id.localeCompare(right.id));
  mismatchedGraph.contentDigest = fixture.core.computeSemanticGraphContentDigest(
    mismatchedGraph,
  );
  assert.throws(
    () => fixture.core.validateSemanticGraph(mismatchedGraph),
    /requestTargetSha256 is not backed by its frozen request node/,
  );

  const mismatchedRedirectIntent = structuredClone(pinned.intent);
  mismatchedRedirectIntent.http.response.redirectLocationSha256 =
    fixture.core.sha256Digest('https://cdn.example.test/different.tgz');
  const mismatchedRedirectProposal = fixture.core.createPolicyProposal({
    ...pinnedInput,
    intent: mismatchedRedirectIntent,
  });
  const mismatchedRedirectGraph = structuredClone(graph);
  mismatchedRedirectGraph.proposals = mismatchedRedirectGraph.proposals
    .map((proposal) => (
      proposal.id === pinned.id ? mismatchedRedirectProposal : proposal
    ))
    .sort((left, right) => left.id.localeCompare(right.id));
  mismatchedRedirectGraph.contentDigest = fixture.core.computeSemanticGraphContentDigest(
    mismatchedRedirectGraph,
  );
  assert.throws(
    () => fixture.core.validateSemanticGraph(mismatchedRedirectGraph),
    /HTTP response identity is not backed by frozen response evidence/,
  );
});

test('target projections classify every accepted rule and bind compiler artifacts', async () => {
  const fixture = await createFixture();
  const decisions = fixture.core.createDecisionSet({
    createdAt: CREATED_AT,
    reviewer: 'reviewer@example.test',
    graph: fixture.graph,
    decisions: [{
      proposalId: fixture.proposal.id,
      disposition: 'accept',
      rationale: 'Approved.',
    }],
  });
  const policyIR = fixture.core.createPolicyIR({
    createdAt: CREATED_AT,
    decisionSet: decisions,
    graph: fixture.graph,
  });
  const rule = policyIR.rules[0];
  const artifactBytes = Buffer.from('apiVersion: cilium.io/v2\n', 'utf8');
  const targetReviewSet = fixture.core.createTargetReviewSet({
    createdAt: CREATED_AT,
    policyIR,
    projections: [{
      target: 'cilium',
      targetContextDigest: fixture.core.sha256Digest({ cluster: 'review' }),
      compiler: {
        id: 'cpg',
        version: '0.1.0',
        digest: fixture.core.sha256Digest('cpg compiler'),
      },
      status: 'exact',
      activationEligible: true,
      artifacts: [{
        name: 'policy.yaml',
        mediaType: 'application/yaml',
        sha256: fixture.core.sha256Digest(artifactBytes),
        bytes: String(artifactBytes.length),
      }],
      ruleMappings: [{
        ruleId: rule.id,
        proposalId: rule.proposalId,
        pointer: '/items/0/spec/egress/0/toFQDNs/0',
        parity: 'exact',
        reasons: [],
      }],
      diagnostics: [],
    }],
  });
  assert.equal(targetReviewSet.projections[0].activationEligible, true);
  assert.equal(targetReviewSet.projections[0].requiresAcknowledgement, false);
  assert.equal(targetReviewSet.policyIrDigest, policyIR.contentDigest);

  assert.throws(
    () => fixture.core.createTargetReviewSet({
      policyIR,
      projections: [{
        target: 'cilium',
        targetContextDigest: fixture.core.sha256Digest({ cluster: 'review' }),
        compiler: {
          id: 'cpg',
          version: '0.1.0',
          digest: fixture.core.sha256Digest('cpg compiler'),
        },
        status: 'exact',
        artifacts: [],
        ruleMappings: [],
        diagnostics: [],
      }],
    }),
    /must classify every policy rule/,
  );
});

test('view state stays non-authoritative and graph deltas are content addressed', async () => {
  const fixture = await createFixture();
  const graph = fixture.core.materializeSemanticGraph(fixture.bundle, fixture.streams);
  const view = fixture.core.createGraphViewState({
    graphDigest: graph.graphDigest,
    updatedAt: CREATED_AT,
    renderer: { name: 'nosh-policy-review', version: '1.0.0' },
    positions: [
      { nodeId: fixture.endpointNode.id, x: 20, y: 5, z: null, pinned: false },
      { nodeId: fixture.projectNode.id, x: 0, y: 0, z: null, pinned: true },
    ],
    collapsedNodeIds: [fixture.endpointNode.id],
    filters: { severity: ['medium', 'high'] },
  });
  assert.equal(view.authoritative, false);
  assert.equal(graph.graphDigest, fixture.bundle.graphDigest);

  const delta = fixture.core.createGraphDelta({
    graphId: graph.graphId,
    baseRevision: graph.revision,
    scopeDigest: fixture.scope.scopeDigest,
    sequence: '1',
    createdAt: CREATED_AT,
    sourceWatermarks: [{
      sourceId: fixture.source.id,
      sequence: '8',
      observedAt: CREATED_AT,
    }],
    operations: [{ op: 'upsert', role: 'nodes', record: fixture.endpointNode }],
  });
  assert.equal(delta.frozen, false);
  assert.equal(delta.operations[0].recordId, fixture.endpointNode.id);
  const tampered = structuredClone(delta);
  tampered.createdAt = '2026-08-16T12:00:01.000Z';
  assert.throws(() => fixture.core.validateGraphDelta(tampered), /deltaDigest does not match/);
});

test('validators reject unknown fields and every review JSON schema is strict JSON', async () => {
  const fixture = await createFixture();
  assert.throws(
    () => fixture.core.validateGraphNode({ ...fixture.projectNode, executableScript: 'alert(1)' }),
    /is not allowed/,
  );
  assert.throws(
    () => fixture.core.createGraphNode({
      scopeDigest: fixture.scope.scopeDigest,
      nodeType: 'process',
      label: 'unsafe integer',
      identity: { pid: 9007199254740992 },
      properties: {},
      evidenceRefs: [fixture.evidenceRef],
    }),
    /unsafe integers must be decimal strings/,
  );

  const schemaDirectory = path.join(
    __dirname,
    '..',
    'config',
    'nosh-guard',
    'schemas',
    'review',
  );
  const files = fs.readdirSync(schemaDirectory)
    .filter((name) => name.endsWith('.schema.json'))
    .sort();
  assert.deepEqual(files, [
    'build-http-observations.schema.json',
    'common.schema.json',
    'deployment-grant-statement.schema.json',
    'dsse-envelope.schema.json',
    'ebpf-egress-policy.schema.json',
    'ebpf-target-context.schema.json',
    'gateway-grant-statement.schema.json',
    'graph-record.schema.json',
    'graph-view-state.schema.json',
    'policy-decision-set.schema.json',
    'policy-ir.schema.json',
    'policy-leaf-bundle.schema.json',
    'portable-gateway-policy.schema.json',
    'portable-gateway-target-context.schema.json',
    'review-approval-statement.schema.json',
    'review-bundle.schema.json',
    'semantic-graph-delta.schema.json',
    'semantic-graph.schema.json',
    'target-review-set.schema.json',
  ]);
  const ids = new Set();
  for (const filename of files) {
    const schema = JSON.parse(fs.readFileSync(path.join(schemaDirectory, filename), 'utf8'));
    assert.equal(schema.$schema, 'https://json-schema.org/draft/2020-12/schema');
    assert.match(schema.$id, /^https:\/\/notty\.dev\/schemas\/nosh-guard\/review\//);
    assert.equal(ids.has(schema.$id), false);
    ids.add(schema.$id);
    if (schema.type === 'object') {
      assert.ok(
        schema.additionalProperties === false || schema.unevaluatedProperties === false,
        `${filename} must close its top-level object`,
      );
    }
  }
  const commonSchema = JSON.parse(
    fs.readFileSync(path.join(schemaDirectory, 'common.schema.json'), 'utf8'),
  );
  const httpHostPattern = new RegExp(
    commonSchema.$defs.httpIntent.properties.host.pattern,
  );
  assert.match('2001:db8::1', httpHostPattern);
  assert.doesNotMatch('[2001:db8::1]', httpHostPattern);
});
