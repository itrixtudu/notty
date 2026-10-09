'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const test = require('node:test');

const CREATED_AT = '2026-08-16T12:00:00.000Z';
const EXPIRES_AT = '2026-08-16T13:00:00.000Z';

async function modules() {
  const [
    core,
    signing,
    compilers,
    bundles,
    cli,
    buildAdapter,
    sbom,
    buildStore,
    buildArtifacts,
    reviewService,
    projectionService,
    approvalService,
    grantService,
    io,
    activationStore,
    timelineProjection,
    reviewerSemanticGraph,
    reviewerIptablesExport,
  ] = await Promise.all([
    import('../lib/guard/review/index.js'),
    import('../lib/guard/review/signing.js'),
    import('../lib/guard/review/policy-compilers.js'),
    import('../lib/guard/review/bundle-store.js'),
    import('../lib/guard/review/cli.js'),
    import('../lib/guard/review/build-adapter.js'),
    import('../lib/guard/review/sbom.js'),
    import('../lib/guardd/build-profile-store.js'),
    import('../lib/guardd/build-profile-artifacts.js'),
    import('../lib/guard/review/review-service.js'),
    import('../lib/guard/review/projection-service.js'),
    import('../lib/guard/review/approval-service.js'),
    import('../lib/guard/review/grant-service.js'),
    import('../lib/guard/review/io.js'),
    import('../lib/guardd/ebpf-activation-store.js'),
    import('../policy-review/modules/policy-review/timelineProjection.js'),
    import('../policy-review/modules/policy-review/semanticGraph.js'),
    import('../policy-review/modules/policy-review/iptablesExport.js'),
  ]);
  return {
    core,
    signing,
    compilers,
    bundles,
    cli,
    buildAdapter,
    sbom,
    buildStore,
    buildArtifacts,
    reviewService,
    projectionService,
    approvalService,
    grantService,
    io,
    activationStore,
    timelineProjection,
    reviewerSemanticGraph,
    reviewerIptablesExport,
  };
}

function privateTemporaryDirectory(t) {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'nosh-policy-review-'));
  fs.chmodSync(directory, 0o700);
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  return directory;
}

function digestFields(core) {
  return {
    leafBundleDigest: core.sha256Digest('leaf'),
    approvalEnvelopeDigest: core.sha256Digest('approval'),
    targetBindingDigest: core.sha256Digest('target-binding'),
    capabilityDigest: core.sha256Digest('capabilities'),
    activeGrantSetDigest: core.sha256Digest('active-grants'),
    renderedArtifactsDigest: core.sha256Digest('rendered-artifacts'),
  };
}

function materializeReviewerDecisionSetFixture(core, graph, decisions, reviewer) {
  const normalizedDecisions = decisions.map((decision) => ({
    id: core.createStableId('decision', {
      scopeDigest: graph.scope.scopeDigest,
      proposalId: decision.proposalId,
    }),
    proposalId: decision.proposalId,
    disposition: decision.disposition,
    rationale: decision.rationale,
    targetAcknowledgements: [...(decision.targetAcknowledgements || [])]
      .sort((left, right) => left.target.localeCompare(right.target)),
  })).sort((left, right) => left.proposalId.localeCompare(right.proposalId));
  const payload = {
    apiVersion: 'notty.dev/v1alpha1',
    kind: 'NoshPolicyDecisionSet',
    schemaVersion: 1,
    createdAt: CREATED_AT,
    reviewer,
    scopeDigest: graph.scope.scopeDigest,
    graphDigest: graph.graphDigest,
    graphContentDigest: graph.contentDigest,
    proposalSetDigest: graph.proposalSetDigest,
    basePolicyDigest: graph.basePolicyDigest,
    decisions: normalizedDecisions,
  };
  const contentDigest = core.sha256Digest(payload);
  return {
    ...payload,
    decisionSetId: core.createStableId('decision-set', contentDigest),
    contentDigest,
  };
}

test('review bundles fail closed before exceeding the browser graph contract', async () => {
  const { bundles, reviewService } = await modules();
  assert.deepEqual(bundles.REVIEW_VIEW_LIMITS, {
    bytes: 25 * 1024 * 1024,
    nodes: 5_000,
    observations: 20_000,
    coverage: 5_000,
    findings: 5_000,
    proposals: 5_000,
    diff: 5_000,
  });
  assert.throws(
    () => bundles.assertReviewableSemanticGraph({
      nodes: Array.from({ length: 5_001 }, () => null),
      observations: [],
      coverage: [],
      findings: [],
      proposals: [],
      diff: [],
    }),
    /5001 nodes records; the review limit is 5000/,
  );
  await assert.rejects(
    () => reviewService.createBuildReviewArtifact({
      profile: '/unread-profile',
      basePolicy: '/unread-policy',
    }),
    /base policy requires.*--baseline/,
  );
});

async function policyFixture(
  peer,
  direction = 'egress',
  transport = { protocol: 'tcp', ports: [443] },
) {
  const { core } = await modules();
  const subjectId = core.createStableId('subject', { project: 'policy-review' });
  const scope = core.createScope({
    class: 'build',
    subjectId,
    projectKey: 'a'.repeat(64),
    platform: 'linux/amd64',
    target: null,
  });
  const evidenceRef = core.createStableId('source', { fixture: 'network' });
  const proposal = core.createPolicyProposal({
    scopeDigest: scope.scopeDigest,
    scopeClass: 'build',
    proposalType: 'observed-network-egress',
    intent: {
      domain: 'network',
      subjectId,
      effect: 'allow',
      direction,
      peer,
      transport,
    },
    baselineState: 'new',
    rationale: 'Deterministic compiler fixture.',
    evidenceRefs: [evidenceRef],
    targetFeasibility: [],
  });
  const subject = core.createGraphNode({
    id: subjectId,
    scopeDigest: scope.scopeDigest,
    nodeType: 'project',
    label: 'policy-review',
    identity: { projectKey: scope.projectKey },
    properties: {},
    evidenceRefs: [evidenceRef],
  });
  const records = {
    nodes: [subject],
    observations: [],
    coverage: [],
    findings: [],
    proposals: [proposal],
    diff: [],
  };
  const streams = Object.fromEntries(Object.entries(records).map(([role, roleRecords]) => (
    [role, core.createHashAddressedStream(role, roleRecords)]
  )));
  const bundle = core.createReviewBundle({
    createdAt: CREATED_AT,
    scope,
    sources: [],
    streams: Object.values(streams),
    basePolicyDigest: core.sha256Digest('base-policy'),
  });
  const graph = core.materializeSemanticGraph(bundle, streams);
  const decisionSet = core.createDecisionSet({
    createdAt: CREATED_AT,
    reviewer: 'integration-test',
    graph,
    decisions: [{
      proposalId: proposal.id,
      disposition: 'accept',
      rationale: 'Approved for deterministic projection testing.',
      targetAcknowledgements: [],
    }],
  });
  const policy = core.createPolicyIR({
    createdAt: CREATED_AT,
    decisionSet,
    graph,
  });
  return { core, scope, graph, proposal, decisionSet, policy };
}

async function runtimePolicyFixture(ruleInputs) {
  const { core } = await modules();
  const workspaceKey = 'c'.repeat(64);
  const workspaceIdentity = { dev: '2050', ino: '57588573' };
  const imageDigest = `sha256:${'d'.repeat(64)}`;
  const workspaceDigest = core.sha256Digest({ workspaceKey, workspaceIdentity });
  const subjectId = core.createStableId('subject', {
    workspaceKey,
    workspaceIdentity,
    imageDigest,
  });
  const scope = core.createScope({
    class: 'runtime',
    subjectId,
    projectKey: 'a'.repeat(64),
    platform: 'linux/amd64',
    target: null,
    imageDigest,
    workspaceDigest,
  });
  const evidenceRef = core.createStableId('source', { fixture: 'runtime-network' });
  const proposals = ruleInputs.map((entry, index) => core.createPolicyProposal({
    scopeDigest: scope.scopeDigest,
    scopeClass: entry.scopeClass || 'runtime',
    proposalType: entry.scopeClass === 'build'
      ? 'observed-build-egress'
      : 'learned-runtime-egress',
    intent: {
      domain: 'network',
      subjectId,
      effect: 'allow',
      direction: 'egress',
      peer: entry.peer,
      transport: entry.transport,
    },
    baselineState: 'new',
    rationale: `Deterministic runtime compiler fixture ${index}.`,
    evidenceRefs: [evidenceRef],
    targetFeasibility: [],
  }));
  const subject = core.createGraphNode({
    id: subjectId,
    scopeDigest: scope.scopeDigest,
    nodeType: 'project',
    label: 'runtime policy fixture',
    identity: { workspaceKey, workspaceIdentity, imageDigest },
    properties: {},
    evidenceRefs: [evidenceRef],
  });
  const records = {
    nodes: [subject],
    observations: [],
    coverage: [],
    findings: [],
    proposals,
    diff: [],
  };
  const streams = Object.fromEntries(Object.entries(records).map(([role, roleRecords]) => (
    [role, core.createHashAddressedStream(role, roleRecords)]
  )));
  const bundle = core.createReviewBundle({
    createdAt: CREATED_AT,
    scope,
    sources: [],
    streams: Object.values(streams),
    basePolicyDigest: core.sha256Digest('runtime-base-policy'),
  });
  const graph = core.materializeSemanticGraph(bundle, streams);
  const decisionSet = core.createDecisionSet({
    createdAt: CREATED_AT,
    reviewer: 'runtime-integration-test',
    graph,
    decisions: proposals.map((proposal) => ({
      proposalId: proposal.id,
      disposition: 'accept',
      rationale: 'Approved for deterministic runtime projection testing.',
      targetAcknowledgements: [],
    })),
  });
  const policy = core.createPolicyIR({
    createdAt: CREATED_AT,
    decisionSet,
    graph,
  });
  return {
    core,
    scope,
    policy,
    contextSubject: { workspaceKey, workspaceIdentity, imageDigest },
  };
}

test('DSSE verification rejects payload tampering and expired gateway grants', async () => {
  const { core, signing } = await modules();
  const pair = signing.generateEd25519KeyPair();
  const grant = signing.createGatewayGrantStatement({
    issuedAt: CREATED_AT,
    notBefore: CREATED_AT,
    expiresAt: EXPIRES_AT,
    nonce: 'integration-grant-1',
    audience: 'gateway.review.test',
    target: 'gateway-iptables',
    ...digestFields(core),
  }, { now: new Date(CREATED_AT) });
  const envelope = signing.createDsseEnvelope(
    signing.GATEWAY_GRANT_PAYLOAD_TYPE,
    grant,
    pair.privateKeyPem,
  );
  const verified = signing.verifyDsseEnvelope(envelope, {
    payloadType: signing.GATEWAY_GRANT_PAYLOAD_TYPE,
    role: 'deployment',
    audience: 'gateway.review.test',
    trustedKeys: [{
      keyId: pair.keyId,
      publicKeyPem: pair.publicKeyPem,
      roles: ['deployment'],
      audiences: ['gateway.review.test'],
    }],
  });
  assert.deepEqual(verified.statement, grant);
  assert.deepEqual(
    signing.validateGatewayGrantStatement(grant, {
      now: new Date('2026-08-16T12:30:00.000Z'),
      audience: 'gateway.review.test',
      target: 'gateway-iptables',
    }),
    grant,
  );

  const changedStatement = { ...grant, target: 'guard-nftables' };
  const tampered = {
    ...envelope,
    payload: Buffer.from(core.jcsCanonicalize(changedStatement), 'utf8').toString('base64'),
  };
  assert.throws(
    () => signing.verifyDsseEnvelope(tampered, {
      payloadType: signing.GATEWAY_GRANT_PAYLOAD_TYPE,
      role: 'deployment',
      audience: 'gateway.review.test',
      trustedKeys: [{
        publicKeyPem: pair.publicKeyPem,
        roles: ['deployment'],
        audiences: ['gateway.review.test'],
      }],
    }),
    /no valid trusted signature/,
  );
  assert.throws(
    () => signing.validateGatewayGrantStatement(grant, {
      now: new Date(EXPIRES_AT),
    }),
    /expired/,
  );
  assert.throws(
    () => signing.createGatewayGrantStatement({
      issuedAt: CREATED_AT,
      notBefore: '2026-08-17T12:00:00.000Z',
      expiresAt: '2026-08-17T13:00:00.000Z',
      nonce: 'deferred-grant',
      audience: 'gateway.review.test',
      target: 'gateway-iptables',
      ...digestFields(core),
    }, { now: new Date(CREATED_AT) }),
    /expire more than 86400 seconds after issuance/,
  );
  assert.throws(
    () => signing.verifyDsseEnvelope({ ...envelope, unsigned: true }, {
      trustedKeys: [{ publicKeyPem: pair.publicKeyPem }],
    }),
    /unsupported field unsigned/,
  );
});

test('deployment grants bind one eBPF subject, ABI, and pre-activation state', async () => {
  const { core, signing } = await modules();
  const pair = signing.generateEd25519KeyPair();
  const subjectBindingDigest = core.sha256Digest('runtime-subject');
  const grant = signing.createDeploymentGrantStatement({
    issuedAt: CREATED_AT,
    notBefore: CREATED_AT,
    expiresAt: EXPIRES_AT,
    nonce: 'ebpf-deployment-grant-1',
    audience: 'guard.review.test',
    target: 'guard-ebpf',
    subjectBindingDigest,
    backendAbi: 'nosh-egress-v2',
    ...digestFields(core),
  }, { now: new Date(CREATED_AT) });
  const envelope = signing.createDsseEnvelope(
    signing.DEPLOYMENT_GRANT_PAYLOAD_TYPE,
    grant,
    pair.privateKeyPem,
  );
  const verified = signing.verifyDsseEnvelope(envelope, {
    payloadType: signing.DEPLOYMENT_GRANT_PAYLOAD_TYPE,
    role: 'guard-ebpf-deployment',
    audience: 'guard.review.test',
    trustedKeys: [{
      publicKeyPem: pair.publicKeyPem,
      roles: ['guard-ebpf-deployment'],
      audiences: ['guard.review.test'],
    }],
  });
  assert.deepEqual(verified.statement, grant);
  assert.deepEqual(signing.validateDeploymentGrantStatement(grant, {
    now: new Date('2026-08-16T12:30:00.000Z'),
    audience: 'guard.review.test',
    target: 'guard-ebpf',
    backendAbi: 'nosh-egress-v2',
    subjectBindingDigest,
  }), grant);
  assert.throws(
    () => signing.validateDeploymentGrantStatement(grant, {
      now: new Date('2026-08-16T12:30:00.000Z'),
      backendAbi: 'nosh-egress-v1',
    }),
    /ABI does not match/,
  );
});

test('policy compilers classify exact and unsupported rules without permissive omission', async () => {
  const exactFixture = await policyFixture({
    kind: 'fqdn',
    value: 'registry.npmjs.org',
  });
  const { compilers, buildAdapter } = await modules();
  const cilium = compilers.compileCiliumPolicy(exactFixture.policy, {
    namespace: 'default',
    name: 'nosh-reviewed-policy',
    endpointSelector: { app: 'builder' },
    exclusiveOwnership: true,
  });
  assert.equal(cilium.activationEligible, true);
  assert.equal(cilium.policyIrDigest, exactFixture.policy.contentDigest);
  assert.equal(cilium.projections[0].parity, 'exact');
  assert.match(cilium.artifacts['cilium-network-policy.yaml'], /"matchName": "registry\.npmjs\.org"/);
  const unverifiedInventory = compilers.compileCiliumPolicy(exactFixture.policy, {
    namespace: 'default',
    name: 'nosh-reviewed-policy',
    endpointSelector: { app: 'builder' },
    selectingPolicyInventoryDigest: exactFixture.core.sha256Digest('unverified-inventory'),
  });
  assert.equal(unverifiedInventory.activationEligible, false);
  assert.equal(unverifiedInventory.projections[0].parity, 'conditional');

  const nft = compilers.compileNftGatewayPolicy(exactFixture.policy, {
    networkName: 'review-net',
    sourceIpv4: '10.240.8.3',
    gatewayIpv4: '10.240.8.2',
    uplinkInterface: 'eth0',
    internalInterfaces: ['review0'],
    upstreamServers: ['1.1.1.1'],
    capabilities: {
      connmarkAllowlist: true,
      exclusiveFirewallOwnership: true,
      managedDnsExclusive: true,
      strictSourceMarking: true,
      nftset: true,
      nftAtomic: true,
    },
  });
  assert.equal(nft.activationEligible, true);
  assert.equal(nft.projections[0].parity, 'exact');
  assert.match(nft.artifacts['dnsmasq.conf'], /connmark-allowlist=1,registry\.npmjs\.org/);

  const bypassFixture = await policyFixture(
    { kind: 'ipv4', value: '203.0.113.8' },
    'egress',
    { protocol: 'udp', ports: [443] },
  );
  const bypass = compilers.compileNftGatewayPolicy(bypassFixture.policy, {
    networkName: 'review-net',
    sourceIpv4: '10.240.8.3',
    gatewayIpv4: '10.240.8.2',
    uplinkInterface: 'eth0',
    capabilities: {
      connmarkAllowlist: true,
      exclusiveFirewallOwnership: true,
      managedDnsExclusive: true,
      strictSourceMarking: true,
      nftset: true,
      nftAtomic: true,
    },
  });
  assert.equal(bypass.projections[0].parity, 'exact');
  assert.deepEqual(bypass.projections[0].reasons, []);
  const feasibility = buildAdapter.buildTargetFeasibility(
    'network',
    'ipv4-cidr',
    { protocol: 'udp', port: 443 },
  );
  assert.equal(feasibility.find((entry) => entry.target === 'cilium').status, 'conditional');
  for (const target of ['guard-nftables', 'gateway-iptables']) {
    const entry = feasibility.find((candidate) => candidate.target === target);
    assert.equal(entry.status, 'exact');
    assert.deepEqual(entry.reasons, []);
  }

  const unsupportedFixture = await policyFixture({
    kind: 'fqdn',
    value: 'registry.npmjs.org',
  }, 'ingress');
  const unsupported = compilers.compileCiliumPolicy(unsupportedFixture.policy, {
    namespace: 'default',
    endpointSelector: { app: 'builder' },
    exclusiveOwnership: true,
  });
  assert.equal(unsupported.activationEligible, false);
  assert.equal(unsupported.projections[0].parity, 'unsupported');
  assert.equal(JSON.parse(unsupported.artifacts['cilium-network-policy.yaml']).spec.ingress.length, 0);

  const tampered = structuredClone(exactFixture.policy);
  tampered.defaults.egress = 'allow';
  assert.throws(
    () => compilers.compileCiliumPolicy(tampered, {
      namespace: 'default',
      endpointSelector: { app: 'builder' },
      exclusiveOwnership: true,
    }),
    /defaults must be default deny|contentDigest does not match/,
  );
  assert.throws(
    () => compilers.compileNftGatewayPolicy(exactFixture.policy, {
      networkName: 'review-net',
      sourceIpv4: '10.240.8.3',
      gatewayIpv4: '10.240.8.2',
      uplinkInterface: 'eth0\nflush ruleset',
      capabilities: {},
    }),
    /bounded non-empty string|unsupported characters/,
  );
});

test('portable gateway compilers render reviewed default-deny NAT exports without activating them', async () => {
  const ipv4Fixture = await policyFixture(
    { kind: 'ipv4', value: '203.0.113.8' },
    'egress',
    { protocol: 'tcp', ports: [443] },
  );
  const fqdnFixture = await policyFixture(
    { kind: 'fqdn', value: 'registry.npmjs.org' },
    'egress',
    { protocol: 'tcp', ports: [443] },
  );
  const { compilers } = await modules();
  const contexts = {
    'gateway-pf': { platform: 'openbsd', expected: 'pf.anchor.conf' },
    'gateway-ipfw': { platform: 'freebsd', expected: 'ipfw.rules' },
    'gateway-ipfilter': { platform: 'illumos', expected: 'ipf.conf' },
  };
  for (const [target, selected] of Object.entries(contexts)) {
    const context = {
      target,
      platform: selected.platform,
      networkName: 'review-net',
      sourceIpv4: '10.240.8.3',
      gatewayIpv4: '10.240.8.2',
      uplinkInterface: 'eth0',
      capabilities: {},
    };
    const literal = compilers.compilePortableGatewayPolicy(
      target,
      ipv4Fixture.policy,
      context,
    );
    assert.equal(literal.target, target);
    assert.equal(literal.activationEligible, false);
    assert.equal(literal.projections[0].parity, 'exact');
    assert.ok(Object.hasOwn(literal.artifacts, selected.expected));
    assert.match(Object.values(literal.artifacts).join('\n'), /203\.0\.113\.8\/32/);
    assert.match(literal.artifacts[selected.expected], /deny|block/);
    const portable = JSON.parse(literal.artifacts['gateway-policy.json']);
    assert.equal(portable.kind, 'NoshPortableGatewayPolicy');
    assert.equal(portable.defaults.forwarding, 'deny');
    assert.equal(portable.bindings.policyIrDigest, ipv4Fixture.policy.contentDigest);
    assert.equal(portable.nat.mode, 'uplink-interface-address');
    const plan = JSON.parse(literal.artifacts['apply-plan.json']);
    assert.equal(plan.mode, 'render-only');
    assert.equal(plan.failureState, 'retain-source-quarantine');
    const verifyPlan = JSON.parse(literal.artifacts['verify-plan.json']);
    assert.equal(verifyPlan.expectedDefault, 'deny');
    assert.equal(verifyPlan.requireNoBypassRoute, true);
    assert.equal(verifyPlan.verified, false);

    const fqdn = compilers.compilePortableGatewayPolicy(
      target,
      fqdnFixture.policy,
      context,
    );
    assert.equal(fqdn.activationEligible, false);
    assert.equal(fqdn.projections[0].parity, 'conditional');
    assert.match(
      fqdn.projections[0].preconditions.join(' '),
      /TTL-aware managed DNS table updater/,
    );
    const dnsTables = JSON.parse(fqdn.artifacts['dns-tables.json']);
    assert.equal(dnsTables.failureBehavior, 'empty-table-default-deny');
    assert.equal(dnsTables.tables[0].fqdn, 'registry.npmjs.org');
    assert.deepEqual(dnsTables.tables[0].addresses, []);
  }
  assert.throws(
    () => compilers.compilePortableGatewayPolicy('gateway-pf', ipv4Fixture.policy, {
      target: 'gateway-pf',
      platform: 'freebsd',
      networkName: 'review-net',
      sourceIpv4: '10.240.8.3',
      gatewayIpv4: '10.240.8.2',
      uplinkInterface: 'em0',
      capabilities: {},
    }),
    /platform must be one of: openbsd/,
  );

  const oversized = structuredClone(ipv4Fixture.policy);
  const sourceRule = oversized.rules[0];
  oversized.rules = Array.from({ length: 4097 }, (_, index) => {
    const proposalId = ipv4Fixture.core.createStableId('proposal', {
      source: sourceRule.proposalId,
      index,
    });
    const rule = {
      ...sourceRule,
      proposalId,
      decisionRefs: [ipv4Fixture.core.createStableId('decision', { index })],
    };
    const intent = structuredClone(rule);
    delete intent.id;
    delete intent.proposalId;
    delete intent.scopeClass;
    delete intent.evidenceRefs;
    delete intent.decisionRefs;
    rule.id = ipv4Fixture.core.createStableId('rule', {
      scopeDigest: oversized.scope.scopeDigest,
      proposalId,
      scopeClass: rule.scopeClass,
      intent,
    });
    return rule;
  }).sort((left, right) => left.id.localeCompare(right.id));
  const oversizedDigestPayload = structuredClone(oversized);
  delete oversizedDigestPayload.policyIrId;
  delete oversizedDigestPayload.contentDigest;
  oversized.contentDigest = ipv4Fixture.core.sha256Digest(oversizedDigestPayload);
  oversized.policyIrId = ipv4Fixture.core.createStableId(
    'policy-ir',
    oversized.contentDigest,
  );
  assert.throws(
    () => compilers.compilePortableGatewayPolicy('gateway-pf', oversized, {
      target: 'gateway-pf',
      platform: 'openbsd',
      networkName: 'review-net',
      sourceIpv4: '10.240.8.3',
      gatewayIpv4: '10.240.8.2',
      uplinkInterface: 'em0',
      capabilities: {},
    }),
    /supports at most 4096 rules/,
  );
});

test('guard-ebpf v2 projection binds the runtime subject and retains reviewed DNS transports', async () => {
  const fixture = await runtimePolicyFixture([
    {
      peer: { kind: 'fqdn', value: '*.example.com' },
      transport: { protocol: 'tcp', ports: [80, 443] },
    },
    {
      peer: { kind: 'ipv4', value: '1.1.1.1' },
      transport: { protocol: 'udp', ports: [53] },
    },
    {
      peer: { kind: 'ipv4', value: '9.9.9.9' },
      transport: { protocol: 'udp', ports: [53] },
    },
    {
      peer: { kind: 'ipv4', value: '9.9.9.9' },
      transport: { protocol: 'tcp', ports: [853] },
    },
    {
      peer: { kind: 'ipv6', value: '2001:4860:4860::8888' },
      transport: { protocol: 'icmpv6', ports: [], icmpType: 128, icmpCode: 0 },
    },
    {
      peer: { kind: 'ipv4', value: '203.0.113.10' },
      transport: { protocol: 'icmp', ports: [] },
    },
    {
      scopeClass: 'build',
      peer: { kind: 'ipv4', value: '198.51.100.7' },
      transport: { protocol: 'tcp', ports: [443] },
    },
  ]);
  const { compilers } = await modules();
  const unsignedContext = {
    apiVersion: 'notty.dev/v1alpha1',
    kind: 'NoshGuardEbpfTargetContext',
    schemaVersion: 2,
    createdAt: CREATED_AT,
    backendAbi: 'nosh-egress-v2',
    objectDigest: fixture.core.sha256Digest('nosh-egress.bpf.o'),
    subject: fixture.contextSubject,
    capabilities: {
      atomicPolicyGeneration: true,
      cgroupConnect: true,
      cgroupSendmsg: true,
      cgroupSkb: true,
      dnsParser: true,
      exactPlatformContainment: true,
      ipv6: true,
      tcpDns: true,
      ttlGrants: true,
    },
    resolvers: ['1.1.1.1', '8.8.8.8'],
    platformContainment: {
      strategy: 'per-run-docker-bridge-gateways',
      ipv4PrefixLength: 32,
      ipv6PrefixLength: 128,
    },
  };
  const context = {
    ...unsignedContext,
    contentHash: fixture.core.sha256Digest(unsignedContext),
  };
  const projected = compilers.compileEbpfPolicy(fixture.policy, context);
  assert.equal(projected.activationEligible, false);
  const native = JSON.parse(projected.artifacts['ebpf-policy.json']);
  assert.deepEqual(native.subject.workspaceIdentity, fixture.contextSubject.workspaceIdentity);
  assert.equal(native.subject.imageDigest, fixture.contextSubject.imageDigest);
  assert.equal(native.backend.objectDigest, unsignedContext.objectDigest);
  assert.equal(native.bindings.targetContextDigest, projected.targetContextDigest);
  assert.equal(
    projected.capabilityDigest,
    fixture.core.sha256Digest(unsignedContext.capabilities),
  );
  assert.equal(native.schemaVersion, 2);
  assert.deepEqual(native.platformContainment, unsignedContext.platformContainment);
  assert.equal(native.rules.length, 5);
  assert.deepEqual(
    native.rules.find((rule) => rule.peer.value === '*.example.com').transport.ports,
    [80, 443],
  );
  assert.equal(native.rules.some((rule) => (
    rule.peer.value === '1.1.1.1/32'
      && rule.transport.protocol === 'udp'
      && rule.transport.ports[0] === 53
  )), true);
  assert.equal(native.rules.some((rule) => rule.transport.protocol === 'icmpv6'), false);
  assert.ok(native.rules.some((rule) => (
    rule.peer.value === '203.0.113.10/32'
      && rule.transport.protocol === 'icmp'
      && rule.transport.ports.length === 0
  )));
  assert.ok(projected.projections.some((entry) => (
    entry.parity === 'unsupported'
      && entry.reasons.some((reason) => reason.includes('ICMP type/code selectors'))
  )));
  assert.equal(
    native.rules.filter((rule) => rule.peer.value === '9.9.9.9/32').length,
    2,
  );
  assert.equal(native.rules.some((rule) => rule.peer.value === '198.51.100.7/32'), false);
  assert.deepEqual(
    projected.projections.map((entry) => entry.parity).sort(),
    [
      'exact',
      'exact',
      'exact',
      'exact',
      'exact',
      'outsideScope',
      'unsupported',
    ].sort(),
  );
  assert.equal(
    projected.artifacts['ebpf-policy.json'],
    `${fixture.core.jcsCanonicalize(native)}\n`,
  );
});

test('guard-ebpf v2 rejects unrepresentable DNS and ICMP while private ranges remain reviewable', async () => {
  const seventeenLabels = Array.from(
    { length: 17 },
    (_, index) => `l${index}`,
  ).join('.');
  const fixture = await runtimePolicyFixture([
    {
      peer: { kind: 'fqdn', value: seventeenLabels },
      transport: { protocol: 'tcp', ports: [443] },
    },
    {
      peer: { kind: 'ipv6', value: '2001:db8::1' },
      transport: { protocol: 'icmp', ports: [] },
    },
    {
      peer: { kind: 'ipv4', value: '10.1.2.3' },
      transport: { protocol: 'tcp', ports: [443] },
    },
    {
      peer: { kind: 'ipv6', value: 'fc00::1' },
      transport: { protocol: 'tcp', ports: [443] },
    },
  ]);
  const { compilers } = await modules();
  const unsignedContext = {
    apiVersion: 'notty.dev/v1alpha1',
    kind: 'NoshGuardEbpfTargetContext',
    schemaVersion: 2,
    createdAt: CREATED_AT,
    backendAbi: 'nosh-egress-v2',
    objectDigest: fixture.core.sha256Digest('nosh-egress.bpf.o'),
    subject: fixture.contextSubject,
    capabilities: {
      atomicPolicyGeneration: true,
      cgroupConnect: true,
      cgroupSendmsg: true,
      cgroupSkb: true,
      dnsParser: true,
      exactPlatformContainment: true,
      ipv6: true,
      tcpDns: true,
      ttlGrants: true,
    },
    resolvers: ['1.1.1.1', '8.8.8.8'],
    platformContainment: {
      strategy: 'per-run-docker-bridge-gateways',
      ipv4PrefixLength: 32,
      ipv6PrefixLength: 128,
    },
  };
  const projected = compilers.compileEbpfPolicy(fixture.policy, {
    ...unsignedContext,
    contentHash: fixture.core.sha256Digest(unsignedContext),
  });
  const native = JSON.parse(projected.artifacts['ebpf-policy.json']);
  assert.equal(projected.activationEligible, false);
  assert.deepEqual(
    native.rules.map((rule) => rule.peer.value).sort(),
    ['10.1.2.3/32', 'fc00::1/128'],
  );
  assert.deepEqual(
    projected.projections.map((entry) => entry.parity).sort(),
    ['exact', 'exact', 'unsupported', 'unsupported'],
  );
  const reasons = projected.projections.flatMap((entry) => entry.reasons);
  assert.ok(reasons.some((reason) => /at most 16 labels/.test(reason)));
  assert.ok(reasons.some((reason) => /require an IPv4 peer/.test(reason)));
  assert.equal(reasons.some((reason) => /10\.0\.0\.0\/8|fc00::\/7/.test(reason)), false);

  const legacyContext = {
    ...unsignedContext,
    schemaVersion: 1,
    backendAbi: 'nosh-egress-v1',
  };
  legacyContext.contentHash = fixture.core.sha256Digest(legacyContext);
  assert.throws(
    () => compilers.compileEbpfPolicy(fixture.policy, legacyContext),
    /target context document header is invalid|requires backend ABI nosh-egress-v2/,
  );
  const malformedContainment = {
    ...unsignedContext,
    platformContainment: {
      strategy: 'per-run-docker-bridge-gateways',
      ipv4PrefixLength: 24,
      ipv6PrefixLength: 128,
    },
  };
  malformedContainment.contentHash = fixture.core.sha256Digest(malformedContainment);
  assert.throws(
    () => compilers.compileEbpfPolicy(fixture.policy, malformedContainment),
    /exact per-run Docker bridge gateway \/32 and \/128 identities/,
  );
});

test('guard-ebpf v2 requires TCP DNS only for reviewed FQDN authority', async () => {
  const { compilers } = await modules();
  const contextFor = (fixture) => {
    const unsigned = {
      apiVersion: 'notty.dev/v1alpha1',
      kind: 'NoshGuardEbpfTargetContext',
      schemaVersion: 2,
      createdAt: CREATED_AT,
      backendAbi: 'nosh-egress-v2',
      objectDigest: fixture.core.sha256Digest('nosh-egress.bpf.o'),
      subject: fixture.contextSubject,
      capabilities: {
        atomicPolicyGeneration: true,
        cgroupConnect: true,
        cgroupSendmsg: true,
        cgroupSkb: true,
        dnsParser: true,
        exactPlatformContainment: true,
        ipv6: true,
        tcpDns: false,
        ttlGrants: true,
      },
      resolvers: ['1.1.1.1', '8.8.8.8'],
      platformContainment: {
        strategy: 'per-run-docker-bridge-gateways',
        ipv4PrefixLength: 32,
        ipv6PrefixLength: 128,
      },
    };
    return {
      ...unsigned,
      contentHash: fixture.core.sha256Digest(unsigned),
    };
  };

  const literalFixture = await runtimePolicyFixture([{
    peer: { kind: 'ipv4', value: '192.168.1.65' },
    transport: { protocol: 'tcp', ports: [9001] },
  }]);
  const literalProjection = compilers.compileEbpfPolicy(
    literalFixture.policy,
    contextFor(literalFixture),
  );
  const literalPolicy = JSON.parse(literalProjection.artifacts['ebpf-policy.json']);
  assert.equal(literalProjection.activationEligible, true);
  assert.equal(literalProjection.projections[0].parity, 'exact');
  assert.deepEqual(literalProjection.projections[0].preconditions, []);
  assert.equal(literalPolicy.dns.tcp, false);
  assert.equal(literalPolicy.rules[0].peer.value, '192.168.1.65/32');
  assert.deepEqual(literalPolicy.rules[0].transport.ports, [9001]);

  const fqdnFixture = await runtimePolicyFixture([{
    peer: { kind: 'fqdn', value: 'collector.example' },
    transport: { protocol: 'tcp', ports: [9001] },
  }]);
  const fqdnProjection = compilers.compileEbpfPolicy(
    fqdnFixture.policy,
    contextFor(fqdnFixture),
  );
  const fqdnPolicy = JSON.parse(fqdnProjection.artifacts['ebpf-policy.json']);
  assert.equal(fqdnProjection.activationEligible, false);
  assert.equal(fqdnProjection.projections[0].parity, 'unsupported');
  assert.deepEqual(
    fqdnProjection.projections[0].preconditions,
    ['missing capability tcpDns'],
  );
  assert.deepEqual(fqdnPolicy.rules, []);
});

test('runtime review keeps immutable decision evidence separate from the editable allow proposal', async () => {
  const { core } = await modules();
  const runtimeAdapter = await import('../lib/guard/review/runtime-adapter.js');
  const workspaceKey = '7'.repeat(64);
  const workspaceIdentity = { dev: '2050', ino: '57588573' };
  const imageDigest = `sha256:${'8'.repeat(64)}`;
  const scope = core.createScope({
    class: 'runtime',
    subjectId: core.createStableId('subject', {
      workspaceKey,
      workspaceIdentity,
      imageDigest,
    }),
    projectKey: '9'.repeat(64),
    platform: 'linux/amd64',
    target: null,
    imageDigest,
    workspaceDigest: core.sha256Digest({ workspaceKey, workspaceIdentity }),
  });
  const runtimeEvidence = [{
    address: '192.168.1.65',
    dnsNames: ['collector.lan'],
    dnsChain: [{
      dnsName: 'collector.lan',
      address: '192.168.1.65',
      protocol: 'any',
      port: 0,
      transactionId: 42,
      observedMonotonicNs: '1000',
      expiresMonotonicNs: '2000',
    }],
    decision: {
      verdict: 'would-deny',
      decisionClass: 'would-deny',
      reason: 'default-deny',
      reasonCode: 5,
      hook: 1,
      destinationAddress: '192.168.1.65',
      destinationPort: 9001,
      enforcementApplied: false,
    },
  }];
  const candidate = {
    revision: 'runtime-review-one',
    createdAt: CREATED_AT,
    evidenceRunId: 'runtime-learn-one',
    evidenceManifestHash: core.sha256Digest('immutable-evidence-manifest'),
    manifestHash: core.sha256Digest('immutable-candidate-manifest'),
    policyHash: core.sha256Digest('editable-candidate-policy'),
    rulesHash: core.sha256Digest('editable-candidate-rules'),
    imageDigest,
    workspaceKey,
    workspaceIdentity,
    unresolvedObservations: [],
    rules: [{
      destination: '192.168.1.65/32',
      protocol: 'tcp',
      ports: [9001],
      observations: runtimeEvidence,
    }],
  };
  const composed = runtimeAdapter.createRuntimeCandidateGraphRecords(scope, candidate);
  const source = composed.records.nodes.find((node) => node.nodeType === 'evidenceSource');
  const endpoint = composed.records.nodes.find((node) => node.nodeType === 'networkEndpoint');
  assert.equal(source.properties.evidenceManifestHash, candidate.evidenceManifestHash);
  assert.deepEqual(endpoint.properties.runtimeEvidence, runtimeEvidence);
  assert.equal(composed.records.proposals[0].intent.effect, 'allow');
  assert.equal(
    composed.records.observations.find((entry) => entry.observationType === 'connects')
      .properties.runtimeEvidence[0].decision.verdict,
    'would-deny',
  );
  assert.equal(
    composed.records.proposals[0].targetFeasibility.find(
      (entry) => entry.target === 'guard-ebpf',
    ).status,
    'exact',
  );
});

test('guard-ebpf authority verifies the reviewed leaf and rejects role, context, and chronology drift', async (t) => {
  const {
    approvalService,
    activationStore,
    bundles,
    core,
    grantService,
    io,
    projectionService,
    signing,
  } = await modules();
  const parent = privateTemporaryDirectory(t);
  const workspaceKey = '4'.repeat(64);
  const workspaceIdentity = { dev: '2050', ino: '57588573' };
  const imageDigest = `sha256:${'5'.repeat(64)}`;
  const objectDigest = core.sha256Digest('nosh-egress-authority-fixture.o');
  const workspaceDigest = core.sha256Digest({ workspaceKey, workspaceIdentity });
  const subjectId = core.createStableId('subject', {
    workspaceKey,
    workspaceIdentity,
    imageDigest,
  });
  const scope = core.createScope({
    class: 'runtime',
    subjectId,
    projectKey: '6'.repeat(64),
    platform: 'linux/amd64',
    target: null,
    imageDigest,
    workspaceDigest,
  });
  const evidenceRef = core.createStableId('source', {
    fixture: 'guard-ebpf-authority',
  });
  const subject = core.createGraphNode({
    id: subjectId,
    scopeDigest: scope.scopeDigest,
    nodeType: 'project',
    label: 'guard-ebpf authority fixture',
    identity: { workspaceKey, workspaceIdentity, imageDigest },
    properties: {},
    evidenceRefs: [evidenceRef],
  });
  const proposal = core.createPolicyProposal({
    scopeDigest: scope.scopeDigest,
    scopeClass: 'runtime',
    proposalType: 'learned-runtime-egress',
    intent: {
      domain: 'network',
      subjectId,
      effect: 'allow',
      direction: 'egress',
      peer: { kind: 'fqdn', value: 'registry.example.test' },
      transport: { protocol: 'tcp', ports: [443] },
    },
    baselineState: 'new',
    rationale: 'Bounded authority-path fixture.',
    evidenceRefs: [evidenceRef],
    targetFeasibility: [{ target: 'guard-ebpf', status: 'exact', reasons: [] }],
  });
  const sourceSbomCoverage = core.createCoverageMarker({
    scopeDigest: scope.scopeDigest,
    domain: 'sbom-source',
    status: 'complete',
    sourceIds: [],
    counters: { packages: '1' },
    gaps: [],
    blocking: false,
    privacy: { classification: 'portable', fields: [] },
  });
  const imageSbomCoverage = core.createCoverageMarker({
    scopeDigest: scope.scopeDigest,
    domain: 'sbom-image',
    status: 'complete',
    sourceIds: [],
    counters: { packages: '1' },
    gaps: [],
    blocking: false,
    privacy: { classification: 'portable', fields: [] },
  });
  const review = bundles.createReviewBundleArtifact({
    createdAt: CREATED_AT,
    scope,
    sources: [],
    records: {
      nodes: [subject],
      observations: [],
      coverage: [sourceSbomCoverage, imageSbomCoverage],
      findings: [],
      proposals: [proposal],
      diff: [],
    },
    basePolicyDigest: core.sha256Digest(null),
    privacyProfile: 'private-review',
  });
  const reviewDirectory = path.join(parent, 'review');
  await bundles.writeReviewBundleArtifact(reviewDirectory, review);
  const loadedReview = await bundles.readReviewBundleArtifact(reviewDirectory);
  const decisions = core.createDecisionSet({
    createdAt: CREATED_AT,
    reviewer: 'authority-reviewer',
    graph: loadedReview.graph,
    decisions: [{
      proposalId: proposal.id,
      disposition: 'accept',
      rationale: 'Required by the reviewed runtime workload.',
      targetAcknowledgements: [],
    }],
  });
  const decisionsPath = path.join(parent, 'decisions.json');
  fs.writeFileSync(
    decisionsPath,
    `${core.jcsCanonicalize(decisions)}\n`,
    { mode: 0o600 },
  );

  // Exercise the activation-eligible authority path with the complete v2
  // contract; the live backend remains intentionally ineligible while it
  // advertises tcpDns=false.
  const capabilities = {
    atomicPolicyGeneration: true,
    cgroupConnect: true,
    cgroupSendmsg: true,
    cgroupSkb: true,
    dnsParser: true,
    exactPlatformContainment: true,
    ipv6: true,
    tcpDns: true,
    ttlGrants: true,
  };
  const resolvers = ['1.1.1.1', '8.8.8.8'];
  const platformContainment = {
    strategy: 'per-run-docker-bridge-gateways',
    ipv4PrefixLength: 32,
    ipv6PrefixLength: 128,
  };
  const unsignedContext = {
    apiVersion: 'notty.dev/v1alpha1',
    kind: 'NoshGuardEbpfTargetContext',
    schemaVersion: 2,
    createdAt: CREATED_AT,
    backendAbi: 'nosh-egress-v2',
    objectDigest,
    subject: { workspaceKey, workspaceIdentity, imageDigest },
    capabilities,
    resolvers,
    platformContainment,
  };
  const context = {
    ...unsignedContext,
    contentHash: core.sha256Digest(unsignedContext),
  };
  const projection = await projectionService.createPolicyProjectionArtifact({
    bundle: reviewDirectory,
    decisions: decisionsPath,
    target: 'guard-ebpf',
    context,
    createdAt: CREATED_AT,
  });
  assert.equal(projection.leaf.activationEligible, true);
  const policyDirectory = path.join(parent, 'policy');
  await projectionService.writePolicyProjectionArtifact(
    policyDirectory,
    projection,
  );
  const nativePolicy = JSON.parse(
    projection.compilerResult.artifacts['ebpf-policy.json'],
  );
  const targetBindingDigest = core.sha256Digest(core.jcsCanonicalize({
    backend: nativePolicy.backend,
    subject: nativePolicy.subject,
  }));

  const reviewPair = signing.generateEd25519KeyPair();
  const deploymentPair = signing.generateEd25519KeyPair();
  const reviewPrivateKey = path.join(parent, 'review-private.pem');
  const reviewPublicKey = path.join(parent, 'review-public.pem');
  const deploymentPrivateKey = path.join(parent, 'deployment-private.pem');
  const deploymentPublicKey = path.join(parent, 'deployment-public.pem');
  for (const [file, content] of [
    [reviewPrivateKey, reviewPair.privateKeyPem],
    [reviewPublicKey, reviewPair.publicKeyPem],
    [deploymentPrivateKey, deploymentPair.privateKeyPem],
    [deploymentPublicKey, deploymentPair.publicKeyPem],
  ]) {
    fs.writeFileSync(file, content, { mode: 0o600 });
  }
  const reviewAudience = 'review.guard-ebpf.test';
  const deploymentAudience = 'guard-instance.ebpf.test';
  const trustPath = path.join(parent, 'ebpf-deployment-trust.json');
  fs.writeFileSync(trustPath, `${core.jcsCanonicalize({
    schemaVersion: 1,
    kind: 'NoshGuardEbpfDeploymentTrust',
    backendAbi: context.backendAbi,
    reviewPublicKey,
    deploymentPublicKey,
    reviewAudience,
    deploymentAudience,
  })}\n`, { mode: 0o600 });
  const activation = new activationStore.EbpfActivationStore({
    workspaceKey,
    stateRoot: path.join(parent, 'activation-state'),
    trustPath,
    enforceTrustPathChains: false,
  });
  const initialActivationState = await activation.initialize();
  const unavailableImageSbom = core.createCoverageMarker({
    scopeDigest: scope.scopeDigest,
    domain: 'sbom-image',
    status: 'unavailable',
    sourceIds: [],
    counters: { packages: '0' },
    gaps: ['image SBOM was not supplied or generated'],
    blocking: false,
    privacy: { classification: 'portable', fields: [] },
  });
  const missingSbomReview = bundles.createReviewBundleArtifact({
    createdAt: CREATED_AT,
    scope,
    sources: [],
    records: {
      nodes: [subject],
      observations: [],
      coverage: [sourceSbomCoverage, unavailableImageSbom],
      findings: [],
      proposals: [proposal],
      diff: [],
    },
    basePolicyDigest: core.sha256Digest(null),
    privacyProfile: 'private-review',
  });
  const missingSbomReviewDirectory = path.join(parent, 'review-missing-sbom');
  await bundles.writeReviewBundleArtifact(
    missingSbomReviewDirectory,
    missingSbomReview,
  );
  const loadedMissingSbomReview = await bundles.readReviewBundleArtifact(
    missingSbomReviewDirectory,
  );
  const missingSbomDecisions = core.createDecisionSet({
    createdAt: CREATED_AT,
    reviewer: 'authority-reviewer',
    graph: loadedMissingSbomReview.graph,
    decisions: [{
      proposalId: proposal.id,
      disposition: 'accept',
      rationale: 'Required by the reviewed runtime workload.',
      targetAcknowledgements: [],
    }],
  });
  const missingSbomDecisionsPath = path.join(parent, 'decisions-missing-sbom.json');
  fs.writeFileSync(
    missingSbomDecisionsPath,
    `${core.jcsCanonicalize(missingSbomDecisions)}\n`,
    { mode: 0o600 },
  );
  const missingSbomProjection = await projectionService.createPolicyProjectionArtifact({
    bundle: missingSbomReviewDirectory,
    decisions: missingSbomDecisionsPath,
    target: 'guard-ebpf',
    context,
    createdAt: CREATED_AT,
  });
  const missingSbomPolicyDirectory = path.join(parent, 'policy-missing-sbom');
  await projectionService.writePolicyProjectionArtifact(
    missingSbomPolicyDirectory,
    missingSbomProjection,
  );
  await assert.rejects(
    () => approvalService.createReviewApprovalArtifact({
      bundle: missingSbomReviewDirectory,
      decisions: missingSbomDecisionsPath,
      policy: missingSbomPolicyDirectory,
      reviewer: missingSbomDecisions.reviewer,
      audience: reviewAudience,
      privateKey: reviewPrivateKey,
      confirmation: missingSbomProjection.targetReviewSet.contentDigest,
      createdAt: CREATED_AT,
    }),
    /non-approvable missing SBOM coverage gaps/,
  );
  const approval = await approvalService.createReviewApprovalArtifact({
    bundle: reviewDirectory,
    decisions: decisionsPath,
    policy: policyDirectory,
    reviewer: decisions.reviewer,
    audience: reviewAudience,
    privateKey: reviewPrivateKey,
    confirmation: projection.targetReviewSet.contentDigest,
    createdAt: CREATED_AT,
  });
  const approvalDirectory = path.join(parent, 'approval');
  await approvalService.writeReviewApprovalArtifact(
    approvalDirectory,
    approval,
  );
  const approvalPath = path.join(
    approvalDirectory,
    'approval-envelope.dsse.json',
  );
  const trustedReviewKey = {
    publicKeyPem: reviewPair.publicKeyPem,
    roles: ['review-approval'],
    audiences: [reviewAudience, 'review.guard-ebpf.drifted'],
  };
  const verifiedApproval = await approvalService.verifyReviewApproval({
    envelope: approvalPath,
    trustedKeys: [trustedReviewKey],
    audience: reviewAudience,
  });
  assert.equal(verifiedApproval.statement.audience, reviewAudience);
  await assert.rejects(
    () => approvalService.verifyReviewApproval({
      envelope: approvalPath,
      trustedKeys: [trustedReviewKey],
      audience: 'review.guard-ebpf.drifted',
    }),
    /review approval audience does not match/,
  );
  await assert.rejects(
    () => approvalService.verifyReviewApproval({
      envelope: approvalPath,
      trustedKeys: [trustedReviewKey],
    }),
    /requires an exact audience/,
  );
  const activeGrantSetDigest = initialActivationState.activeGrantSetDigest;
  const createGrant = (privateKey, now) => (
    grantService.createDeploymentGrantArtifact({
      policy: policyDirectory,
      approval: approvalPath,
      reviewPublicKey,
      reviewAudience,
      deploymentPrivateKey: privateKey,
      audience: deploymentAudience,
      targetBindingDigest,
      activeGrantSetDigest,
      ttlSeconds: 3600,
      now: new Date(now),
    })
  );
  const grant = await createGrant(
    deploymentPrivateKey,
    '2026-08-16T12:05:00.000Z',
  );
  const grantDirectory = path.join(parent, 'grant');
  await grantService.writeDeploymentGrantArtifact(grantDirectory, grant);
  const grantPath = path.join(grantDirectory, 'deployment-grant.dsse.json');
  const expected = {
    imageDigest,
    workspaceKey,
    workspaceIdentity,
    backendAbi: context.backendAbi,
    objectDigest,
    capabilities,
    resolvers,
    platformContainment,
  };
  const authorityInput = {
    policy: policyDirectory,
    approval: approvalPath,
    grant: grantPath,
    reviewPublicKey,
    deploymentPublicKey,
    reviewAudience,
    deploymentAudience,
    activeGrantSetDigest,
    expected,
    now: new Date('2026-08-16T12:30:00.000Z'),
  };
  const verified = await grantService.verifyEbpfDeploymentAuthority(
    authorityInput,
  );
  assert.equal(verified.policy.leaf.bundleDigest, projection.leaf.bundleDigest);
  assert.equal(verified.ebpfPolicy.bindings.targetContextDigest,
    projection.compilerResult.targetContextDigest);
  assert.equal(verified.grant.statement.activeGrantSetDigest,
    activeGrantSetDigest);
  assert.equal(verified.approval.statement.audience, reviewAudience);

  const activationBundle = path.join(parent, 'activation-bundle');
  fs.mkdirSync(activationBundle, { mode: 0o700 });
  const activationPolicy = path.join(activationBundle, 'policy');
  fs.cpSync(policyDirectory, activationPolicy, { recursive: true });
  fs.chmodSync(activationPolicy, 0o700);
  for (const [source, name] of [
    [approvalPath, 'approval-envelope.dsse.json'],
    [grantPath, 'deployment-grant.dsse.json'],
  ]) {
    const destination = path.join(activationBundle, name);
    fs.copyFileSync(source, destination);
    fs.chmodSync(destination, 0o600);
  }
  const sourceUid = typeof process.getuid === 'function' ? process.getuid() : null;
  const imported = await activation.importActivation(activationBundle, {
    sourceUid,
    expected,
    now: new Date('2026-08-16T12:30:00.000Z'),
  });
  assert.equal(imported.current.leafBundleDigest, projection.leaf.bundleDigest);
  assert.equal(imported.current.decisionSetDigest, projection.policyIR.decisionSetDigest);
  assert.equal(imported.current.approvalEnvelopeDigest,
    verified.approval.envelopeDigest);
  assert.equal(imported.current.grantEnvelopeDigest, verified.grant.envelopeDigest);
  assert.notEqual(imported.state.activeGrantSetDigest, activeGrantSetDigest);
  const active = await activation.verifyActive(expected, {
    leafBundleDigest: projection.leaf.bundleDigest });
  assert.equal(active.current.grantEnvelopeDigest, verified.grant.envelopeDigest);
  await assert.rejects(
    () => activation.verifyActive(expected, { leafBundleDigest: `sha256:${'0'.repeat(64)}` }),
    /deployment changed after launch selection/,
  );
  await assert.rejects(
    () => activation.importActivation(activationBundle, {
      sourceUid,
      expected,
      now: new Date('2026-08-16T12:31:00.000Z'),
    }),
    /activeGrantSetDigest|already consumed/,
  );

  await assert.rejects(
    () => grantService.verifyEbpfDeploymentAuthority({
      ...authorityInput,
      expected: {
        ...expected,
        resolvers: [...resolvers, '9.9.9.9'],
      },
    }),
    /live backend context|fresh trusted compilation/,
  );
  await assert.rejects(
    () => grantService.verifyEbpfDeploymentAuthority({
      ...authorityInput,
      activeGrantSetDigest: core.sha256Digest('stale-guard-grant-set'),
    }),
    /activeGrantSetDigest does not bind/,
  );
  await assert.rejects(
    () => grantService.verifyEbpfDeploymentAuthority({
      ...authorityInput,
      reviewAudience: 'review.guard-ebpf.drifted',
    }),
    /review approval audience does not match/,
  );

  await assert.rejects(
    () => createGrant(
      reviewPrivateKey,
      '2026-08-16T12:06:00.000Z',
    ),
    /distinct signing keys/,
  );
  const sameKeyGrantPath = path.join(parent, 'same-key-grant.dsse.json');
  fs.writeFileSync(
    sameKeyGrantPath,
    `${core.jcsCanonicalize(signing.createDsseEnvelope(
      signing.DEPLOYMENT_GRANT_PAYLOAD_TYPE,
      grant.statement,
      reviewPair.privateKeyPem,
    ))}\n`,
    { mode: 0o600 },
  );
  await assert.rejects(
    () => grantService.verifyEbpfDeploymentAuthority({
      ...authorityInput,
      grant: sameKeyGrantPath,
      deploymentPublicKey: reviewPublicKey,
    }),
    /distinct signing keys/,
  );

  await assert.rejects(
    () => createGrant(
      deploymentPrivateKey,
      '2026-08-16T11:59:00.000Z',
    ),
    /future-dated/,
  );
  const earlyIssuedAt = '2026-08-16T11:59:00.000Z';
  const earlyStatement = signing.createDeploymentGrantStatement({
    ...grant.statement,
    issuedAt: earlyIssuedAt,
    notBefore: earlyIssuedAt,
    expiresAt: '2026-08-16T12:59:00.000Z',
    nonce: 'guard-ebpf-authority-early-grant',
  }, { now: new Date(earlyIssuedAt) });
  const earlyGrantPath = path.join(parent, 'early-grant.dsse.json');
  fs.writeFileSync(
    earlyGrantPath,
    `${core.jcsCanonicalize(signing.createDsseEnvelope(
      signing.DEPLOYMENT_GRANT_PAYLOAD_TYPE,
      earlyStatement,
      deploymentPair.privateKeyPem,
    ))}\n`,
    { mode: 0o600 },
  );
  await assert.rejects(
    () => grantService.verifyEbpfDeploymentAuthority({
      ...authorityInput,
      grant: earlyGrantPath,
    }),
    /predates its review approval/,
  );

  const misleadingPolicyDirectory = path.join(parent, 'misleading-policy');
  fs.cpSync(policyDirectory, misleadingPolicyDirectory, { recursive: true });
  fs.chmodSync(misleadingPolicyDirectory, 0o700);
  const misleadingTargetReviewSet = core.createTargetReviewSet({
    policyIR: projection.policyIR,
    projections: [{
      ...projection.targetReviewSet.projections[0],
      ruleMappings: projection.targetReviewSet.projections[0].ruleMappings.map(
        (mapping, index) => index === 0
          ? { ...mapping, pointer: 'guard-ebpf:misleading-review-pointer' }
          : mapping,
      ),
    }],
    createdAt: projection.targetReviewSet.createdAt,
  });
  const misleadingTargetReviewText = `${core.jcsCanonicalize(
    misleadingTargetReviewSet,
  )}\n`;
  fs.writeFileSync(
    path.join(misleadingPolicyDirectory, 'target-review-set.json'),
    misleadingTargetReviewText,
    { mode: 0o600 },
  );
  const misleadingArtifacts = Object.fromEntries(
    projection.leaf.artifacts.map((entry) => [
      entry.path,
      fs.readFileSync(path.join(misleadingPolicyDirectory, entry.path)),
    ]),
  );
  const misleadingLeaf = io.createLeafManifest({
    target: projection.leaf.target,
    activationEligible: projection.leaf.activationEligible,
    graphDigest: projection.leaf.graphDigest,
    decisionSetDigest: projection.leaf.decisionSetDigest,
    policyIrDigest: projection.leaf.policyIrDigest,
    targetContextDigest: projection.leaf.targetContextDigest,
    capabilityDigest: projection.leaf.capabilityDigest,
    projectionDigest: misleadingTargetReviewSet.contentDigest,
    artifacts: misleadingArtifacts,
    createdAt: projection.leaf.createdAt,
  });
  fs.writeFileSync(
    path.join(misleadingPolicyDirectory, 'leaf-bundle.json'),
    `${core.jcsCanonicalize(misleadingLeaf)}\n`,
    { mode: 0o600 },
  );
  const misleadingApproval = await approvalService.createReviewApprovalArtifact({
    bundle: reviewDirectory,
    decisions: decisionsPath,
    policy: misleadingPolicyDirectory,
    reviewer: decisions.reviewer,
    audience: reviewAudience,
    privateKey: reviewPrivateKey,
    confirmation: misleadingTargetReviewSet.contentDigest,
    createdAt: CREATED_AT,
  });
  const misleadingApprovalDirectory = path.join(parent, 'misleading-approval');
  await approvalService.writeReviewApprovalArtifact(
    misleadingApprovalDirectory,
    misleadingApproval,
  );
  const misleadingApprovalPath = path.join(
    misleadingApprovalDirectory,
    'approval-envelope.dsse.json',
  );
  const misleadingGrant = await grantService.createDeploymentGrantArtifact({
    policy: misleadingPolicyDirectory,
    approval: misleadingApprovalPath,
    reviewPublicKey,
    reviewAudience,
    deploymentPrivateKey,
    audience: deploymentAudience,
    targetBindingDigest,
    activeGrantSetDigest,
    ttlSeconds: 3600,
    now: new Date('2026-08-16T12:10:00.000Z'),
  });
  const misleadingGrantDirectory = path.join(parent, 'misleading-grant');
  await grantService.writeDeploymentGrantArtifact(
    misleadingGrantDirectory,
    misleadingGrant,
  );
  await assert.rejects(
    () => grantService.verifyEbpfDeploymentAuthority({
      ...authorityInput,
      policy: misleadingPolicyDirectory,
      approval: misleadingApprovalPath,
      grant: path.join(
        misleadingGrantDirectory,
        'deployment-grant.dsse.json',
      ),
    }),
    /target review projection does not match a fresh trusted compilation/,
  );
});

test('review bundles round-trip, bind projection to exact graph content, and never clobber', async (t) => {
  const { core, bundles, projectionService } = await modules();
  const parent = privateTemporaryDirectory(t);
  const destination = path.join(parent, 'review-bundle');
  const subjectId = core.createStableId('subject', { fixture: 'bundle' });
  const scope = core.createScope({ class: 'build', subjectId });
  const evidenceRef = core.createStableId('source-record', { fixture: 'bundle' });
  const subject = core.createGraphNode({
    id: subjectId,
    scopeDigest: scope.scopeDigest,
    nodeType: 'project',
    label: 'bundle fixture',
    identity: { fixture: 'bundle' },
    properties: {},
    evidenceRefs: [evidenceRef],
  });
  const proposal = core.createPolicyProposal({
    scopeDigest: scope.scopeDigest,
    scopeClass: 'build',
    proposalType: 'network-egress',
    intent: {
      domain: 'network',
      subjectId,
      effect: 'allow',
      direction: 'egress',
      peer: { kind: 'fqdn', value: 'registry.example.test' },
      transport: { protocol: 'tcp', ports: [443] },
    },
    baselineState: 'new',
    rationale: 'Fixture registry access.',
    evidenceRefs: [evidenceRef],
    targetFeasibility: [{ target: 'cilium', status: 'exact', reasons: [] }],
  });
  const artifact = bundles.createReviewBundleArtifact({
    createdAt: CREATED_AT,
    scope,
    sources: [],
    records: {
      nodes: [subject],
      observations: [],
      coverage: [],
      findings: [],
      proposals: [proposal],
      diff: [],
    },
    basePolicyDigest: core.sha256Digest(null),
    privacyProfile: 'private-review',
  });
  const written = await bundles.writeReviewBundleArtifact(destination, artifact);
  assert.equal(written.bundle.bundleDigest, artifact.bundle.bundleDigest);
  const loaded = await bundles.readReviewBundleArtifact(destination);
  assert.equal(loaded.graph.nodes[0].id, subjectId);

  const decisions = core.createDecisionSet({
    createdAt: CREATED_AT,
    reviewer: 'integration-reviewer',
    graph: loaded.graph,
    decisions: [{
      proposalId: proposal.id,
      disposition: 'accept',
      rationale: 'Required for the reviewed build.',
      targetAcknowledgements: [{
        target: 'cilium',
        status: 'conditional',
        rationale: 'Composition is intentionally unproven for this negative test.',
      }],
    }],
  });
  const decisionsPath = path.join(parent, 'decisions.json');
  fs.writeFileSync(decisionsPath, `${core.jcsCanonicalize(decisions)}\n`, { mode: 0o600 });
  const projection = await projectionService.createPolicyProjectionArtifact({
    bundle: destination,
    decisions: decisionsPath,
    target: 'cilium',
    context: {
      namespace: 'default',
      endpointSelector: { app: 'builder' },
      exclusiveOwnership: true,
    },
    createdAt: CREATED_AT,
  });
  assert.equal(projection.policyIR.graphContentDigest, loaded.graph.contentDigest);
  const conditionalProjection = await projectionService.createPolicyProjectionArtifact({
    bundle: destination,
    decisions: decisionsPath,
    target: 'cilium',
    context: {
      namespace: 'default',
      endpointSelector: { app: 'builder' },
      selectingPolicyInventoryDigest: core.sha256Digest('unverified-inventory'),
    },
    createdAt: CREATED_AT,
  });
  assert.equal(conditionalProjection.compilerResult.activationEligible, false);
  assert.equal(conditionalProjection.targetReviewSet.projections[0].status, 'conditional');
  assert.equal(
    conditionalProjection.targetReviewSet.projections[0].activationEligible,
    false,
  );
  assert.equal(conditionalProjection.leaf.activationEligible, false);

  const substitutedGraph = structuredClone(loaded.graph);
  substitutedGraph.nodes[0].label = 'semantically substituted build';
  substitutedGraph.contentDigest = core.computeSemanticGraphContentDigest(substitutedGraph);
  const substitutedDecisions = core.createDecisionSet({
    createdAt: CREATED_AT,
    reviewer: 'integration-reviewer',
    graph: substitutedGraph,
    decisions: [{
      proposalId: proposal.id,
      disposition: 'accept',
      rationale: 'Reviewed against substituted content.',
    }],
  });
  const substitutedPath = path.join(parent, 'substituted-decisions.json');
  fs.writeFileSync(substitutedPath, `${core.jcsCanonicalize(substitutedDecisions)}\n`, { mode: 0o600 });
  await assert.rejects(
    () => projectionService.createPolicyProjectionArtifact({
      bundle: destination,
      decisions: substitutedPath,
      target: 'cilium',
      context: {
        namespace: 'default',
        endpointSelector: { app: 'builder' },
        exclusiveOwnership: true,
      },
      createdAt: CREATED_AT,
    }),
    /graphContentDigest does not match the frozen review graph/,
  );

  await assert.rejects(
    () => bundles.writeReviewBundleArtifact(destination, artifact),
    /EEXIST|exist/i,
  );
  assert.equal(
    (await bundles.readReviewBundleArtifact(destination)).bundle.bundleDigest,
    artifact.bundle.bundleDigest,
  );

  const nodeStream = artifact.bundle.streams.find((entry) => entry.role === 'nodes');
  fs.appendFileSync(path.join(destination, nodeStream.path), ' ');
  await assert.rejects(
    () => bundles.readReviewBundleArtifact(destination),
    /byte count changed|digest does not match/,
  );
});

test('standalone reviewer emits an unsigned browser sketch without implicit network policy', async () => {
  const { reviewerSemanticGraph, reviewerIptablesExport } = await modules();
  const graph = reviewerSemanticGraph.createSampleSemanticGraph();
  const proposal = graph.proposals[0];
  const output = await reviewerIptablesExport.createSelectedIptablesExport({
    graph,
    proposalIds: [proposal.id],
    decisions: {
      [proposal.id]: {
        disposition: 'accept',
        rationale: 'The selected registry endpoint is required by this build.',
      },
    },
    context: {
      sourceIpv4: '198.51.100.10',
      uplinkInterface: 'eth0',
      includeMasquerade: false,
    },
  });

  assert.deepEqual(output.exportedProposalIds, [proposal.id]);
  assert.equal(output.mappings[0].status, 'exact');
  assert.match(output.filename, /^nosh-selected-[a-f0-9]{16}\.iptables-sketch\.sh$/);
  assert.match(output.scriptDigest, /^sha256:[a-f0-9]{64}$/);
  assert.match(output.script, /^#!\/bin\/sh\nset -eu\n/);
  assert.match(output.script, /cat <<'NOSH_SELECTED_IPTABLES_EOF'/);
  assert.doesNotMatch(output.script, /^iptables(?:-restore)?\b/m);
  const encodedManifest = output.script
    .split('\n')
    .filter((line) => line.startsWith('# NSH-MANIFEST-B64:'))
    .map((line) => line.slice('# NSH-MANIFEST-B64:'.length))
    .join('');
  assert.deepEqual(
    JSON.parse(Buffer.from(encodedManifest, 'base64').toString('utf8')),
    output.selectionManifest,
  );
  assert.equal(output.selectionManifest.subjectId, proposal.intent.subjectId);
  assert.equal(output.selectionManifest.schemaVersion, 2);
  assert.equal(output.selectionManifest.artifactClass, 'unsigned-browser-sketch');
  assert.equal(output.selectionManifest.signed, false);
  assert.equal(output.selectionManifest.renderOnly, true);
  assert.equal(output.selectionManifest.activationEligible, false);
  assert.doesNotMatch(output.script, /:invariant|:dns-guard/);

  const reviewedPrivateDnsGraph = structuredClone(graph);
  const reviewedPrivateDnsProposal = reviewedPrivateDnsGraph.proposals[0];
  reviewedPrivateDnsProposal.intent.peer = {
    kind: 'ipv4',
    value: '192.168.1.65',
  };
  reviewedPrivateDnsProposal.intent.transport = {
    protocol: 'udp',
    ports: [53],
  };
  reviewedPrivateDnsGraph.contentDigest =
    await reviewerSemanticGraph.computeSemanticGraphContentDigest(reviewedPrivateDnsGraph);
  const privateDnsOutput = await reviewerIptablesExport.createSelectedIptablesExport({
    graph: reviewedPrivateDnsGraph,
    proposalIds: [reviewedPrivateDnsProposal.id],
    decisions: {
      [reviewedPrivateDnsProposal.id]: {
        disposition: 'accept',
        rationale: 'This private resolver authority was explicitly reviewed.',
      },
    },
    context: {
      sourceIpv4: '198.51.100.10',
      uplinkInterface: 'eth0',
      includeMasquerade: false,
    },
  });
  assert.equal(privateDnsOutput.mappings[0].status, 'exact');
  assert.match(
    privateDnsOutput.script,
    /-d 192\.168\.1\.65\/32 -p udp --dport 53/,
  );
  assert.doesNotMatch(privateDnsOutput.script, /:invariant|:dns-guard/);
  assert.match(privateDnsOutput.script, /:default-deny/);
});

test('a finalized policy-depth build profile materializes every captured review domain', async (t) => {
  const {
    core,
    buildAdapter,
    buildArtifacts,
    buildStore,
    bundles,
    cli,
    reviewService,
    timelineProjection,
  } = await modules();
  const parent = privateTemporaryDirectory(t);
  const home = path.join(parent, 'home');
  const context = path.join(parent, 'context');
  fs.mkdirSync(home, { mode: 0o700 });
  fs.mkdirSync(context, { mode: 0o700 });
  const sourceRecords = {
    'buildkit-progress': [{
      pass: 'cold',
      vertexes: [{
        digest: `sha256:${'b'.repeat(64)}`,
        name: '[1/1] RUN curl https://registry.example.test',
        started: CREATED_AT,
        completed: '2026-08-16T12:00:01.000Z',
      }],
    }],
    'buildx-history': [{ name: 'policy-depth-fixture' }],
    'cgroup-metrics': [{ pass: 'cold', memoryCurrent: '4096' }],
    'ebpf-process': [{
      pass: 'cold',
      eventKind: 'process-exec',
      timestampNs: '1786881600000000000',
      targetCgroupId: '700',
      observedCgroupId: '701',
      executable: '/usr/bin/curl',
      process: {
        pid: 101,
        tid: 101,
        ppid: 100,
        uid: 1000,
        gid: 1000,
        comm: 'curl',
      },
    }],
    'ebpf-syscall': [{
      pass: 'cold',
      recordKind: 'syscall-summary',
      targetCgroupId: '700',
      syscallNumber: '42',
      calls: '1',
      completions: '1',
      errors: '0',
      totalDurationNs: '1000',
      maxDurationNs: '1000',
    }],
    'ebpf-network': [{
      pass: 'cold',
      recordKind: 'flow-summary',
      cgroupId: '701',
      socketCookie: '88',
      firstObservedNs: '1786881600000000000',
      lastObservedNs: '1786881600001000000',
      accounting: { packets: '3', bytes: '256' },
      network: {
        direction: 'egress',
        family: 'ipv4',
        protocol: 'tcp',
        sourceAddress: '10.0.0.2',
        destinationAddress: '203.0.113.10',
        sourcePort: 40000,
        destinationPort: 443,
      },
    }],
    dns: [{
      pass: 'cold',
      eventKind: 'dns-query',
      timestampNs: '1786881600000000000',
      dns: { qname: 'registry.example.test' },
    }],
    'ebpf-file': [{
      pass: 'cold',
      recordKind: 'file-summary',
      path: '/app/package.json',
      firstObservedNs: '1786881600000000000',
      lastObservedNs: '1786881600001000000',
      accessCounts: { read: '2', write: '0', execute: '0', create: '0' },
    }],
  };
  const requiredSources = buildArtifacts.requiredBuildEvidenceSources(
    'build-profile',
    'policy',
  );
  assert.deepEqual([...requiredSources].sort(), Object.keys(sourceRecords).sort());
  const store = new buildStore.BuildProfileStore({ home });
  const finalized = await store.finalizeRun({
    context,
    runId: 'policy-depth-review-fixture',
    mode: 'build-profile',
    generatedAt: '2026-08-16T12:00:02.000Z',
    startedAt: CREATED_AT,
    endedAt: '2026-08-16T12:00:02.000Z',
    builder: { imageDigest: `sha256:${'a'.repeat(64)}` },
    build: {
      success: true,
      exitCode: 0,
      platform: 'linux/amd64',
      cacheMode: 'compare',
      depth: 'policy',
      passes: [
        { name: 'cold', success: true, exitCode: 0, durationMs: 1500 },
        { name: 'warm', success: true, exitCode: 0, durationMs: 500 },
      ],
    },
    coverage: {
      builderIdentityStable: true,
      exclusiveBuilderLease: true,
      parentObserved: true,
      cleanupComplete: true,
      freshBuilder: false,
      forcedSourcePulls: false,
      cacheImportsDisabled: false,
      allReachableStepsExecuted: false,
    },
    sources: requiredSources.map((name) => ({
      name,
      format: 'ndjson',
      content: `${sourceRecords[name].map((record) => JSON.stringify(record)).join('\n')}\n`,
      required: true,
      complete: true,
      lostEvents: 0,
      parseErrors: 0,
      completionMarker: 'clean-supervised-stop',
    })),
    observations: {
      http: {
        contractVersion: 2,
        provider: 'mitmproxy',
        captureMode: 'managed',
        required: true,
        complete: true,
        gaps: [],
        contentAssuranceGaps: [],
        exchanges: [{
          id: 'exchange-policy-depth-1',
          pass: 'cold',
          timestampUnixNs: '1786881600000000000',
          method: 'GET',
          scheme: 'https',
          host: 'registry.example.test',
          port: 443,
          displayUrl: 'https://registry.example.test/packages/example.tgz',
          requestTargetSha256: core.sha256Digest('/packages/example.tgz'),
          representationHeadersSha256: core.sha256Digest({ accept: '*/*' }),
          destination: { ip: '203.0.113.10', protocol: 'tcp', port: 443 },
          destinationRole: 'workload-to-origin',
          response: {
            status: 200,
            complete: true,
            contentSha256: core.sha256Digest('example package bytes'),
            length: '21',
          },
        }, {
          id: 'exchange-policy-depth-proxy-leg',
          pass: 'cold',
          timestampUnixNs: '1786881600000000000',
          method: 'GET',
          scheme: 'https',
          host: 'registry.example.test',
          port: 443,
          displayUrl: 'https://registry.example.test/proxy-only.tgz',
          requestTargetSha256: core.sha256Digest('/proxy-only.tgz'),
          representationHeadersSha256: core.sha256Digest({ accept: '*/*' }),
          destination: { ip: '203.0.113.10', protocol: 'tcp', port: 443 },
          destinationRole: 'workload-to-proxy',
          response: {
            status: 200,
            complete: true,
            contentSha256: core.sha256Digest('proxy-only package bytes'),
            length: '24',
          },
        }],
      },
    },
  });
  const graph = await buildAdapter.createBuildReviewGraph(finalized.directory);
  assert.equal(graph.frozen, true);
  assert.equal(graph.profile.complete, true);
  assert.equal(
    graph.sources.find((source) => source.sourceName === 'ebpf-file').coverage.status,
    'complete',
  );
  for (const nodeType of [
    'domain',
    'executable',
    'file',
    'httpRequest',
    'httpResponse',
    'networkEndpoint',
    'syscall',
  ]) {
    assert.ok(graph.nodes.some((node) => node.nodeType === nodeType), nodeType);
  }
  assert.deepEqual(
    [...new Set(graph.proposals.map((proposal) => proposal.intent.domain))].sort(),
    ['filesystem', 'http', 'network', 'process', 'syscall'],
  );
  const assuranceVariants = graph.proposals.filter((proposal) => (
    proposal.authorityGroupId
  ));
  assert.deepEqual(
    assuranceVariants.map((proposal) => proposal.assurance.level).sort(),
    ['endpoint-only', 'live-digest-gate', 'url-restricted'],
  );
  assert.equal(
    graph.coverage.find((entry) => entry.domain === 'http-capture').status,
    'incomplete',
  );
  assert.ok(graph.findings.some((finding) => (
    finding.properties?.authorityCreated === false
    && finding.message.includes('proxy-to-origin flow')
  )));
  assert.equal(
    graph.coverage.find((entry) => entry.domain === 'artifact-integrity').status,
    'incomplete',
  );
  const networkProposal = graph.proposals.find(proposal => (
    proposal.intent.domain === 'network'
  ));
  assert.ok(networkProposal.observationRefs.length > 0);
  assert.ok(networkProposal.observationRefs.every(observationId => (
    graph.observations.some(observation => observation.id === observationId)
  )));
  const timeline = timelineProjection.createTimelineProjection(graph);
  assert.deepEqual(timeline.extent, {
    startMs: Date.parse(CREATED_AT),
    endMs: Date.parse('2026-08-16T12:00:02.000Z'),
    startAt: CREATED_AT,
    endAt: '2026-08-16T12:00:02.000Z',
    durationMs: 2000,
  });
  for (const domain of ['build', 'process', 'dns', 'network', 'filesystem', 'syscall']) {
    assert.ok(timeline.domains.includes(domain), `timeline domain ${domain}`);
  }
  for (const domain of ['process', 'dns', 'network', 'filesystem']) {
    assert.ok(
      timeline.items.some((item) => (
        item.recordType === 'observation'
        && item.domain === domain
        && item.temporalKind !== 'untimed'
      )),
      `timed observation domain ${domain}`,
    );
  }
  assert.ok(
    timeline.items.some((item) => (
      item.recordType === 'observation'
      && item.domain === 'syscall'
      && item.temporalKind === 'untimed'
    )),
    'syscall summaries remain explicit untimed context',
  );
  const activity = timelineProjection.selectTimelineActivity(timeline, {
    cursorMs: timeline.extent.endMs,
    mode: 'cumulative',
    includeUntimed: true,
  });
  assert.ok(activity.observationIds.length >= 5);
  assert.ok(activity.items.some((item) => (
    item.recordType === 'observation'
    && item.temporalKind === 'untimed'
  )));
  const review = await reviewService.createBuildReviewArtifact({
    profile: finalized.directory,
    requireSbom: false,
    createdAt: '2026-08-16T12:00:03.000Z',
  });
  assert.equal(review.graph.frozen, true);
  assert.equal(review.bundle.scope.scopeDigest, graph.scope.scopeDigest);
  assert.deepEqual(
    review.graph.coverage
      .filter((entry) => entry.blocking)
      .map((entry) => entry.domain),
    ['http-capture'],
  );
  assert.deepEqual(
    review.graph.coverage
      .filter((entry) => (
        ['sbom-source', 'sbom-image'].includes(entry.domain)
        && entry.status !== 'complete'
      ))
      .map((entry) => entry.domain)
      .sort(),
    ['sbom-image', 'sbom-source'],
  );
  const reviewDirectory = path.join(parent, 'review-with-missing-sboms');
  await bundles.writeReviewBundleArtifact(reviewDirectory, review);
  assert.equal(
    await cli.commandReview(['inspect', '--bundle', reviewDirectory]),
    2,
    'review-only SBOM downgrade must remain ineligible for signed approval',
  );
});

test('review HTTP evidence contract fails closed on incomplete or secret-bearing input', async () => {
  const { buildAdapter, core } = await modules();
  const base = {
    contractVersion: 2,
    provider: 'mitmproxy',
    captureMode: 'managed',
    required: true,
    complete: true,
    gaps: [],
    contentAssuranceGaps: [],
    exchanges: [{
      id: 'http-contract-fixture',
      pass: 'cold',
      timestampUnixNs: '1786881600000000000',
      method: 'GET',
      scheme: 'https',
      host: 'registry.example.test',
      port: 443,
      displayUrl: 'https://registry.example.test/package.tgz',
      requestTargetSha256: core.sha256Digest('/package.tgz?token=[redacted]'),
      representationHeadersSha256: core.sha256Digest({ accept: '*/*' }),
      destination: { ip: '203.0.113.10', protocol: 'tcp', port: 443 },
      destinationRole: 'workload-to-origin',
      response: {
        status: 200,
        complete: true,
        contentSha256: core.sha256Digest('package bytes'),
      },
    }],
  };
  assert.equal(buildAdapter.validateBuildHttpEvidence(base).exchanges.length, 1);
  assert.throws(
    () => buildAdapter.validateBuildHttpEvidence({
      ...base,
      captureMode: 'manual-import',
    }),
    /manual imports cannot claim complete capture/,
  );
  assert.throws(
    () => buildAdapter.validateBuildHttpEvidence({
      ...base,
      provider: 'burp',
    }),
    /only managed mitmproxy capture may create authority/,
  );
  const secretDisplay = structuredClone(base);
  secretDisplay.exchanges[0].displayUrl = 'https://registry.example.test/package.tgz?token=secret';
  assert.throws(
    () => buildAdapter.validateBuildHttpEvidence(secretDisplay),
    /sanitized origin/,
  );
  const mismatchedIntegrity = structuredClone(base);
  mismatchedIntegrity.exchanges[0].integrity = {
    kind: 'npm-sri',
    contentSha256: core.sha256Digest('different bytes'),
    verificationEvidenceSha256: core.sha256Digest('package-lock evidence'),
    verified: true,
  };
  assert.throws(
    () => buildAdapter.validateBuildHttpEvidence(mismatchedIntegrity),
    /integrity does not match/,
  );
});

test('review CLI option parsing fails closed before performing work', async () => {
  const { cli } = await modules();
  await assert.rejects(
    () => cli.commandReview(['unknown', '--help']),
    /unknown review command/,
  );
  await assert.rejects(
    () => cli.commandReview(['inspect', '--json', '--json']),
    /may be supplied only once/,
  );
  await assert.rejects(
    () => cli.commandReview(['inspect']),
    /--bundle is required/,
  );
  await assert.rejects(
    () => cli.commandReview(['approve']),
    /--bundle is required/,
  );
  await assert.rejects(
    () => cli.commandReview(['sbom']),
    /--context is required/,
  );
  await assert.rejects(
    () => cli.commandReview(['serve', '--bundle', '/not/read', '--port', '01']),
    /canonical decimal port/,
  );
  await assert.rejects(
    () => cli.commandReview(['bundle', '--baseline-override-reason', 'manual']),
    /requires --baseline/,
  );
  await assert.rejects(
    () => cli.commandReview(['inspect', '--help', '--json']),
    /does not accept other arguments/,
  );
  await assert.rejects(
    () => cli.commandReview(['help', '--json']),
    /does not accept other arguments/,
  );
  await assert.rejects(
    () => cli.commandReview(['inspect', '--bundle=']),
    /requires a value/,
  );
});

test('offline SBOM generation delegates to container orchestration with exact tooling identity', async (t) => {
  const { sbom } = await modules();
  const { inventoryDocument } = require('./helpers/inventory-fixture.cjs');
  const parent = privateTemporaryDirectory(t);
  const context = path.join(parent, 'context');
  const output = path.join(parent, 'sboms');
  const image = 'sha256:' + 'a'.repeat(64);
  fs.mkdirSync(context, {mode:0o700});
  const calls = [];
  const runCommand = async (command, args) => {
    calls.push({command,args});
    fs.mkdirSync(output, {mode:0o700});
    for (const role of ['source','image']) fs.writeFileSync(path.join(output, role+'.spdx.json'),
      JSON.stringify(inventoryDocument(role,image)), {mode:0o600});
  };
  const generated = await sbom.generateBuildSboms({context,imageReference:image,toolingImage:image,output}, {runCommand});
  assert.equal(generated.source.format,'spdx-json');
  assert.equal(generated.image.collection.input.imageDigest,image);
  assert.equal(calls.length,1);
  assert.equal(calls[0].command,'bash');
  assert.match(calls[0].args[0], /nosh-inventory\.sh$/);
  assert.equal(calls[0].args[calls[0].args.indexOf('--tooling')+1],image);
  await assert.rejects(sbom.generateBuildSboms({context,output}), /exact local policy tooling/);
});

test('root-owned reviewer DecisionSet fixture is accepted and graph-content-bound', async () => {
  const { core, graph, proposal } = await policyFixture({
    kind: 'fqdn',
    value: 'review-fixture.example.test',
  });
  const decisionSet = materializeReviewerDecisionSetFixture(core, graph, [{
    proposalId: proposal.id,
    disposition: 'accept',
    rationale: 'Reviewed and required by the captured build.',
    targetAcknowledgements: [],
  }], 'root-fixture-reviewer');
  assert.equal(decisionSet.graphContentDigest, graph.contentDigest);
  assert.equal(core.validateDecisionSet(decisionSet), decisionSet);
  assert.equal(
    core.createPolicyIR({ createdAt: CREATED_AT, decisionSet, graph }).graphContentDigest,
    graph.contentDigest,
  );

  const substitutedGraphDigest = core.sha256Digest('substituted graph content');
  const substitutedPayload = {
    ...decisionSet,
    graphContentDigest: substitutedGraphDigest,
  };
  delete substitutedPayload.decisionSetId;
  delete substitutedPayload.contentDigest;
  const substitutedContentDigest = core.sha256Digest(substitutedPayload);
  const substitutedDecisionSet = {
    ...substitutedPayload,
    decisionSetId: core.createStableId('decision-set', substitutedContentDigest),
    contentDigest: substitutedContentDigest,
  };
  core.validateDecisionSet(substitutedDecisionSet);
  assert.throws(
    () => core.createPolicyIR({
      createdAt: CREATED_AT,
      decisionSet: substitutedDecisionSet,
      graph,
    }),
    /graphContentDigest does not match the decision set/,
  );
});
