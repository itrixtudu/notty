'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');

const CREATED_AT = '2026-08-16T12:00:00.000Z';

const IPTABLES_CAPABILITIES = Object.freeze({
  connmarkAllowlist: true,
  conntrack: true,
  dnsmasqIpSet: true,
  exclusiveFirewallOwnership: true,
  ipset: true,
  iptablesRestore: true,
  managedDnsExclusive: true,
  strictSourceMarking: true,
});

const NFT_CAPABILITIES = Object.freeze({
  connmarkAllowlist: true,
  exclusiveFirewallOwnership: true,
  managedDnsExclusive: true,
  nftAtomic: true,
  nftset: true,
  strictSourceMarking: true,
});

const L7_CAPABILITIES = Object.freeze({
  completeCapture: true,
  directWebDeny: true,
  forcedRouting: true,
  proxyPolicyAtomic: true,
  quicDeny: true,
  tlsInterception: true,
});

async function modules() {
  const [core, compilers, contentStore] = await Promise.all([
    import('../lib/guard/review/index.js'),
    import('../lib/guard/review/policy-compilers.js'),
    import('../lib/guardd/http-content-store.js'),
  ]);
  return { core, compilers, contentStore };
}

async function httpPolicyFixture(
  level = 'url-restricted',
  networkIntents = [],
  manifestEvidence = {},
) {
  const { core, compilers, contentStore } = await modules();
  const subjectId = core.createStableId('subject', { project: 'l7-proxy-compiler' });
  const scope = core.createScope({
    class: 'build',
    subjectId,
    projectKey: 'a'.repeat(64),
    platform: 'linux/amd64',
    target: null,
  });
  const evidenceRef = core.createStableId('source', { fixture: `http-${level}` });
  const httpPort = manifestEvidence.httpPort || 443;
  const requestTarget = '/package/-/package-1.0.0.tgz?download=1';
  const requestTargetSha256 = core.sha256Digest(requestTarget);
  const representationHeadersSha256 = core.sha256Digest('representation headers');
  const contentSha256 = core.sha256Digest('immutable package bytes');
  const subject = core.createGraphNode({
    id: subjectId,
    scopeDigest: scope.scopeDigest,
    nodeType: 'project',
    label: 'l7-proxy-compiler',
    identity: { projectKey: scope.projectKey },
    properties: {},
    evidenceRefs: [evidenceRef],
  });
  const request = core.createGraphNode({
    scopeDigest: scope.scopeDigest,
    nodeType: 'httpRequest',
    label: `https://registry.npmjs.org:${httpPort}`,
    identity: {
      method: 'GET',
      scheme: 'https',
      host: 'registry.npmjs.org',
      port: httpPort,
      requestTargetSha256,
      requestBodySha256: null,
      representationHeadersSha256,
    },
    properties: {
      displayUrl: `https://registry.npmjs.org:${httpPort}/[redacted]`,
    },
    evidenceRefs: [evidenceRef],
  });
  const contentManifest = level === 'cas-replay'
    ? contentStore.createHttpContentManifest({
        generatedAt: CREATED_AT,
        runId: 'l7-proxy-compiler',
        mode: 'offline-replay',
        entries: [{
          request: {
            method: 'GET',
            scheme: 'https',
            hostname: 'registry.npmjs.org',
            port: httpPort,
            requestTargetDigest: manifestEvidence.requestTargetDigest
              || requestTargetSha256,
            requestBodyDigest: null,
            representationHeadersDigest: representationHeadersSha256,
            credentialed: false,
          },
          response: {
            status: manifestEvidence.location ? 302 : 200,
            bodyDigest: manifestEvidence.bodyDigest || contentSha256,
            bodyBytes: 23,
            contentType: 'application/octet-stream',
            contentEncoding: null,
            location: manifestEvidence.location || null,
            locationDigest: manifestEvidence.location
              ? core.sha256Digest(manifestEvidence.location)
              : null,
          },
          sourceExchangeId: core.sha256Digest('source exchange'),
          capturedAt: CREATED_AT,
        }],
      })
    : null;
  const response = level === 'cas-replay'
    ? core.createGraphNode({
        scopeDigest: scope.scopeDigest,
        nodeType: 'httpResponse',
        label: 'HTTP 200',
        identity: {
          status: 200,
          contentSha256,
          decodedContentSha256: null,
          length: '23',
        },
        properties: {
          complete: true,
          cas: {
            objectSha256: contentSha256,
            manifestSha256: contentManifest.contentHash,
            available: true,
          },
        },
        evidenceRefs: [evidenceRef],
      })
    : null;
  const http = {
    contractVersion: 2,
    method: 'GET',
    scheme: 'https',
    host: 'registry.npmjs.org',
    port: httpPort,
    requestTargetSha256,
    representationHeadersSha256,
    ...(response ? {
      response: {
        kind: 'cas',
        contentSha256,
        status: 200,
        length: '23',
      },
    } : {}),
  };
  const assurance = level === 'cas-replay'
    ? {
        contractVersion: 2,
        level,
        mutableContent: false,
        evidenceBacked: true,
        requestEvidenceRefs: [request.id],
        responseEvidenceRefs: [response.id],
        integrityKind: 'cas-object',
        contentDigest: contentSha256,
        proofDigest: contentManifest.contentHash,
      }
    : {
        contractVersion: 2,
        level,
        mutableContent: true,
        evidenceBacked: true,
        requestEvidenceRefs: [request.id],
        responseEvidenceRefs: [],
        integrityKind: 'none',
      };
  const authorityGroupId = core.createStableId('authority', {
    scopeDigest: scope.scopeDigest,
    requestNodeId: request.id,
  });
  const proposal = core.createPolicyProposal({
    scopeDigest: scope.scopeDigest,
    scopeClass: 'build',
    proposalType: `observed-http-${level}`,
    intent: {
      domain: 'http',
      subjectId,
      effect: 'allow',
      direction: 'egress',
      peer: { kind: 'http-resource', value: request.id },
      http,
    },
    authorityGroupId,
    assurance,
    baselineState: 'new',
    rationale: 'Deterministic L7 compiler fixture.',
    evidenceRefs: [evidenceRef],
    targetFeasibility: [{
      target: 'gateway-l7-proxy',
      status: 'exact',
      reasons: [],
    }],
  });
  const networkProposals = networkIntents.map((intent, index) => (
    core.createPolicyProposal({
      scopeDigest: scope.scopeDigest,
      scopeClass: 'build',
      proposalType: `observed-network-egress-${index}`,
      intent: {
        domain: 'network',
        subjectId,
        effect: 'allow',
        direction: 'egress',
        ...intent,
      },
      baselineState: 'new',
      rationale: `Deterministic network companion fixture ${index}.`,
      evidenceRefs: [evidenceRef],
      targetFeasibility: [],
    })
  ));
  const records = {
    nodes: [subject, request, ...(response ? [response] : [])],
    observations: [],
    coverage: [],
    findings: [],
    proposals: [proposal, ...networkProposals],
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
    reviewer: 'l7-compiler-test',
    graph,
    decisions: [proposal, ...networkProposals].map((candidate) => ({
      proposalId: candidate.id,
      disposition: 'accept',
      rationale: 'Approved for deterministic projection testing.',
      targetAcknowledgements: [],
    })),
  });
  const policy = core.createPolicyIR({
    createdAt: CREATED_AT,
    decisionSet,
    graph,
  });
  assert.equal(graph.frozen, true);
  assert.equal(Object.isFrozen(policy), true);
  assert.equal(policy.rules.length, 1 + networkProposals.length);
  assert.equal(policy.rules.filter((rule) => rule.domain === 'http').length, 1);
  return {
    core,
    compilers,
    graph,
    policy,
    contentManifest,
    contentStore,
    requestTargetSha256,
    contentSha256,
  };
}

function iptablesNetworkContext(sourceIpv4, networkName) {
  return {
    target: 'gateway-iptables',
    networkName,
    sourceIpv4,
    gatewayIpv4: '10.240.8.2',
    uplinkInterface: 'eth0',
    iptablesVariant: 'nft',
    internalInterfaces: ['review0'],
    upstreamServers: ['1.1.1.1'],
    capabilities: { ...IPTABLES_CAPABILITIES },
  };
}

function l7IptablesContext(overrides = {}) {
  return {
    target: 'gateway-l7-proxy',
    networkBackend: 'gateway-iptables',
    provider: 'mitmproxy',
    proxyEndpoint: { ipv4: '10.240.8.9', port: 8080 },
    workloadNetwork: iptablesNetworkContext('10.240.8.3', 'review-workload'),
    proxyNetwork: iptablesNetworkContext('10.240.8.9', 'review-proxy'),
    capabilities: { ...L7_CAPABILITIES },
    ...overrides,
  };
}

function portableNetworkContext(target, sourceIpv4, networkName) {
  const platforms = {
    'gateway-pf': 'openbsd',
    'gateway-ipfw': 'freebsd',
    'gateway-ipfilter': 'illumos',
  };
  return {
    target,
    platform: platforms[target],
    networkName,
    sourceIpv4,
    gatewayIpv4: '10.240.8.2',
    uplinkInterface: target === 'gateway-pf' ? 'em0' : 'igb0',
    capabilities: {},
  };
}

test('exact URL policy compiles separate default-deny workload and proxy identities', async () => {
  const fixture = await httpPolicyFixture('url-restricted');
  const result = fixture.compilers.compileL7ProxyGatewayPolicy(
    fixture.policy,
    l7IptablesContext(),
  );

  assert.equal(result.target, 'gateway-l7-proxy');
  assert.equal(result.policyIrDigest, fixture.policy.contentDigest);
  assert.equal(result.activationEligible, false);
  assert.match(
    result.limitations.join('\n'),
    /render-only composite export until a host actuator atomically applies and verifies both network legs and the proxy content gate/,
  );
  assert.equal(result.projections.length, 1);
  assert.equal(result.projections[0].parity, 'exact');
  assert.ok(result.projections[0].targetIds.some((id) => id.startsWith('workload:')));
  assert.ok(result.projections[0].targetIds.some((id) => id.startsWith('proxy:')));
  assert.ok(result.projections[0].targetIds.includes(`proxy-policy:${fixture.policy.rules[0].id}`));

  const proxyPolicy = JSON.parse(result.artifacts['http-proxy-policy.json']);
  assert.equal(proxyPolicy.bindings.graphDigest, fixture.policy.graphDigest);
  assert.equal(proxyPolicy.bindings.decisionSetDigest, fixture.policy.decisionSetDigest);
  assert.equal(proxyPolicy.bindings.policyIrDigest, fixture.policy.contentDigest);
  assert.equal(proxyPolicy.defaults.requests, 'deny');
  assert.equal(proxyPolicy.defaults.redirects, 'deny-each-unreviewed-hop');
  assert.equal(proxyPolicy.defaults.directWeb, 'deny');
  assert.equal(proxyPolicy.defaults.quic, 'deny');
  assert.equal(proxyPolicy.rules[0].assurance.level, 'url-restricted');
  assert.equal(proxyPolicy.rules[0].request.requestTargetSha256, fixture.requestTargetSha256);
  assert.equal(Object.hasOwn(proxyPolicy.rules[0].request, 'response'), false);

  const topology = JSON.parse(result.artifacts['proxy-topology.json']);
  assert.equal(topology.workload.sourceIpv4, '10.240.8.3');
  assert.equal(topology.proxy.sourceIpv4, '10.240.8.9');
  assert.notEqual(topology.workload.sourceIpv4, topology.proxy.sourceIpv4);
  assert.deepEqual(topology.workload.allowedWebEndpoint, {
    ipv4: '10.240.8.9',
    port: 8080,
  });
  assert.deepEqual(topology.workload.deniedDirectTcpPorts, [80, 443]);
  assert.deepEqual(topology.workload.deniedDirectUdpPorts, [443]);
  assert.equal(topology.proxy.unrestrictedConnect, false);

  assert.match(result.artifacts['workload-ipset.restore'], /10\.240\.8\.9\/32/);
  assert.doesNotMatch(result.artifacts['workload-dnsmasq.conf'], /registry\.npmjs\.org/);
  assert.match(result.artifacts['proxy-dnsmasq.conf'], /registry\.npmjs\.org/);
  assert.match(result.artifacts['workload-iptables-restore.v4'], /-s 10\.240\.8\.3/);
  assert.match(result.artifacts['proxy-iptables-restore.v4'], /-s 10\.240\.8\.9/);
  assert.match(result.artifacts['workload-iptables-restore.v4'], /-j DROP/);

  const apply = JSON.parse(result.artifacts['composite-apply-plan.json']);
  assert.deepEqual(apply.phases, [
    'install-workload-and-proxy-quarantine',
    'validate-content-and-proxy-policy',
    'load-workload-network-policy',
    'load-proxy-origin-network-policy',
    'start-policy-bound-proxy',
    'verify-direct-web-and-quic-bypass-denied',
    'verify-proxy-policy-and-content-gate',
    'remove-quarantine',
  ]);
  assert.equal(apply.failureState, 'retain-workload-and-proxy-quarantine');
  assert.equal(apply.requireAllLayersVerified, true);
  const verify = JSON.parse(result.artifacts['composite-verify-plan.json']);
  assert.deepEqual(verify.requiredDirectTcpDenyPorts, [80, 443]);
  assert.deepEqual(verify.requiredDirectUdpDenyPorts, [443]);
  assert.equal(verify.requireOpaqueConnectDeny, true);
  assert.equal(verify.requireCompleteCapture, true);
  assert.equal(verify.verified, false);
});

test('forced proxy rejects separately accepted direct TCP and QUIC web grants', async () => {
  const directRules = [
    {
      peer: { kind: 'ipv4-cidr', value: '203.0.113.80/32' },
      transport: { protocol: 'tcp', ports: [80] },
    },
    {
      peer: { kind: 'ipv4-cidr', value: '203.0.113.44/32' },
      transport: { protocol: 'tcp', ports: [443] },
    },
    {
      peer: { kind: 'ipv4-cidr', value: '203.0.113.43/32' },
      transport: { protocol: 'udp', ports: [443] },
    },
    {
      peer: { kind: 'ipv4-cidr', value: '203.0.113.84/32' },
      transport: { protocol: 'tcp', ports: [8443] },
    },
    {
      peer: { kind: 'ipv4-cidr', value: '203.0.113.85/32' },
      transport: { protocol: 'udp', ports: [8443] },
    },
    {
      peer: { kind: 'ipv4-cidr', value: '203.0.113.22/32' },
      transport: { protocol: 'tcp', ports: [22] },
    },
  ];
  const fixture = await httpPolicyFixture(
    'url-restricted',
    directRules,
    { httpPort: 8443 },
  );
  const result = fixture.compilers.compileL7ProxyGatewayPolicy(
    fixture.policy,
    l7IptablesContext(),
  );

  assert.equal(result.activationEligible, false);
  const projectionsByPeer = new Map(fixture.policy.rules
    .filter((rule) => rule.domain === 'network')
    .map((rule) => [
      rule.peer.value,
      result.projections.find((projection) => projection.ruleId === rule.id),
    ]));
  for (const peer of [
    '203.0.113.80/32',
    '203.0.113.44/32',
    '203.0.113.43/32',
    '203.0.113.84/32',
    '203.0.113.85/32',
  ]) {
    assert.equal(projectionsByPeer.get(peer).parity, 'unsupported');
    assert.match(
      projectionsByPeer.get(peer).reasons.join('\n'),
      /TCP ports 80, 443, 8443 or UDP ports 443, 8443/,
    );
  }
  assert.equal(projectionsByPeer.get('203.0.113.22/32').parity, 'exact');
  assert.doesNotMatch(
    result.artifacts['workload-ipset.restore'],
    /203\.0\.113\.(?:80|44|43|84|85)\/32/,
  );
  assert.match(result.artifacts['workload-ipset.restore'], /203\.0\.113\.22\/32/);
  const topology = JSON.parse(result.artifacts['proxy-topology.json']);
  assert.deepEqual(topology.workload.deniedDirectTcpPorts, [80, 443, 8443]);
  assert.deepEqual(topology.workload.deniedDirectUdpPorts, [443, 8443]);
  const verify = JSON.parse(result.artifacts['composite-verify-plan.json']);
  assert.deepEqual(verify.requiredDirectTcpDenyPorts, [80, 443, 8443]);
  assert.deepEqual(verify.requiredDirectUdpDenyPorts, [443, 8443]);
});

test('CAS response rendering requires verified manifest membership, not a digest alone', async () => {
  const fixture = await httpPolicyFixture('cas-replay');
  const contentManifestDigest = fixture.contentManifest.contentHash;
  const context = l7IptablesContext({
    contentManifest: fixture.contentManifest,
    contentManifestDigest,
    capabilities: {
      ...L7_CAPABILITIES,
      offlineReplay: true,
    },
  });
  const result = fixture.compilers.compileL7ProxyGatewayPolicy(fixture.policy, context);

  assert.equal(result.activationEligible, false);
  assert.equal(result.projections[0].parity, 'exact');
  assert.match(result.limitations.join('\n'), /render-only composite export.*host actuator/);
  const proxyPolicy = JSON.parse(result.artifacts['http-proxy-policy.json']);
  assert.equal(proxyPolicy.bindings.contentManifestDigest, contentManifestDigest);
  assert.equal(proxyPolicy.bindings.policyIrDigest, fixture.policy.contentDigest);
  assert.equal(proxyPolicy.rules[0].assurance.level, 'cas-replay');
  assert.equal(proxyPolicy.rules[0].assurance.contentDigest, fixture.contentSha256);
  assert.equal(proxyPolicy.rules[0].assurance.proofDigest, contentManifestDigest);
  assert.equal(proxyPolicy.rules[0].request.response.kind, 'cas');
  assert.equal(proxyPolicy.rules[0].request.response.contentSha256, fixture.contentSha256);
  assert.deepEqual(
    JSON.parse(result.artifacts['http-content-manifest.json']),
    fixture.contentManifest,
  );

  const digestOnly = fixture.compilers.compileL7ProxyGatewayPolicy(
    fixture.policy,
    l7IptablesContext({
      contentManifestDigest,
      capabilities: { ...L7_CAPABILITIES, offlineReplay: true },
    }),
  );
  assert.equal(digestOnly.activationEligible, false);
  assert.equal(digestOnly.projections[0].parity, 'unsupported');
  assert.match(
    digestOnly.projections[0].preconditions.join('\n'),
    /reviewed CAS manifest membership/,
  );
  assert.equal(Object.hasOwn(digestOnly.artifacts, 'http-content-manifest.json'), false);

  const alternateContentManifest = fixture.contentStore.createHttpContentManifest({
    ...fixture.contentManifest,
    runId: 'different-l7-proxy-run',
  });
  const alternateManifest = fixture.compilers.compileL7ProxyGatewayPolicy(
    fixture.policy,
    l7IptablesContext({
      contentManifest: alternateContentManifest,
      capabilities: { ...L7_CAPABILITIES, offlineReplay: true },
    }),
  );
  assert.notEqual(alternateManifest.targetContextDigest, result.targetContextDigest);
  assert.notEqual(alternateManifest.artifactsDigest, result.artifactsDigest);
  assert.equal(alternateManifest.activationEligible, false);
  assert.equal(alternateManifest.projections[0].parity, 'unsupported');
  assert.match(
    alternateManifest.projections[0].preconditions.join('\n'),
    /reviewed CAS manifest membership/,
  );

  for (const mismatch of [
    { requestTargetDigest: fixture.core.sha256Digest('/different-resource.tgz') },
    { bodyDigest: fixture.core.sha256Digest('different response bytes') },
    { location: 'https://registry.npmjs.org/different-resource.tgz' },
  ]) {
    const mismatched = await httpPolicyFixture('cas-replay', [], mismatch);
    const mismatchedResult = mismatched.compilers.compileL7ProxyGatewayPolicy(
      mismatched.policy,
      l7IptablesContext({
        contentManifest: mismatched.contentManifest,
        capabilities: { ...L7_CAPABILITIES, offlineReplay: true },
      }),
    );
    assert.equal(mismatchedResult.activationEligible, false);
    assert.equal(mismatchedResult.projections[0].parity, 'unsupported');
    assert.match(
      mismatchedResult.projections[0].preconditions.join('\n'),
      /reviewed CAS manifest membership/,
    );
  }

  const withoutManifest = fixture.compilers.compileL7ProxyGatewayPolicy(
    fixture.policy,
    l7IptablesContext({
      capabilities: { ...L7_CAPABILITIES, offlineReplay: true },
    }),
  );
  assert.equal(withoutManifest.activationEligible, false);
  assert.equal(withoutManifest.projections[0].parity, 'unsupported');
  assert.match(
    withoutManifest.projections[0].preconditions.join('\n'),
    /contentManifestDigest/,
  );

  const withoutReplay = fixture.compilers.compileL7ProxyGatewayPolicy(
    fixture.policy,
    l7IptablesContext({
      contentManifest: fixture.contentManifest,
      contentManifestDigest,
    }),
  );
  assert.equal(withoutReplay.activationEligible, false);
  assert.equal(withoutReplay.projections[0].parity, 'unsupported');
  assert.match(withoutReplay.projections[0].preconditions.join('\n'), /offlineReplay/);

  assert.throws(
    () => fixture.compilers.compileL7ProxyGatewayPolicy(
      fixture.policy,
      l7IptablesContext({
        contentManifest: fixture.contentManifest,
        contentManifestDigest: 'sha256:not-a-digest',
        capabilities: { ...L7_CAPABILITIES, offlineReplay: true },
      }),
    ),
    /contentManifestDigest must be an exact SHA-256 digest/,
  );
});

test('L7 deployment fails closed on capability, identity, and provider mismatches', async () => {
  const fixture = await httpPolicyFixture('url-restricted');
  const missingQuicDeny = fixture.compilers.compileL7ProxyGatewayPolicy(
    fixture.policy,
    l7IptablesContext({
      capabilities: { ...L7_CAPABILITIES, quicDeny: false },
    }),
  );
  assert.equal(missingQuicDeny.activationEligible, false);
  assert.equal(missingQuicDeny.projections[0].parity, 'unsupported');
  assert.match(missingQuicDeny.projections[0].preconditions.join('\n'), /quicDeny/);

  const sameIdentity = l7IptablesContext();
  sameIdentity.workloadNetwork = iptablesNetworkContext('10.240.8.9', 'review-workload');
  assert.throws(
    () => fixture.compilers.compileL7ProxyGatewayPolicy(fixture.policy, sameIdentity),
    /workload and proxy network identities must be distinct/,
  );

  assert.throws(
    () => fixture.compilers.compileL7ProxyGatewayPolicy(
      fixture.policy,
      l7IptablesContext({ provider: 'burp' }),
    ),
    /supports only mitmproxy; Burp evidence remains review-only/,
  );
});

test('L3 and L4 gateway compilers classify HTTP authority as permissive', async () => {
  const fixture = await httpPolicyFixture('url-restricted');
  const cases = [
    ['guard-nftables', () => fixture.compilers.compileNftGatewayPolicy(
      fixture.policy,
      {
        networkName: 'review-net',
        sourceIpv4: '10.240.8.3',
        gatewayIpv4: '10.240.8.2',
        uplinkInterface: 'eth0',
        internalInterfaces: ['review0'],
        upstreamServers: ['1.1.1.1'],
        capabilities: { ...NFT_CAPABILITIES },
      },
    )],
    ['gateway-iptables', () => fixture.compilers.compileIptablesGatewayPolicy(
      fixture.policy,
      iptablesNetworkContext('10.240.8.3', 'review-net'),
    )],
    ...[
      'gateway-pf',
      'gateway-ipfw',
      'gateway-ipfilter',
    ].map((target) => [target, () => fixture.compilers.compilePortableGatewayPolicy(
      target,
      fixture.policy,
      portableNetworkContext(target, '10.240.8.3', 'review-net'),
    )]),
  ];

  for (const [target, compile] of cases) {
    const result = compile();
    assert.equal(result.target, target);
    assert.equal(result.activationEligible, false);
    assert.equal(result.projections.length, 1);
    assert.equal(result.projections[0].domain, 'http');
    assert.equal(result.projections[0].parity, 'permissive');
    assert.match(
      result.projections[0].reasons.join('\n'),
      /L3\/L4 target and cannot enforce the reviewed HTTP request or response identity/,
    );
  }
});

test('portable composite output stays render-only even with complete L7 capabilities', async () => {
  const fixture = await httpPolicyFixture('url-restricted');
  const target = 'gateway-pf';
  const result = fixture.compilers.compileL7ProxyGatewayPolicy(fixture.policy, {
    target: 'gateway-l7-proxy',
    networkBackend: target,
    provider: 'mitmproxy',
    proxyEndpoint: { ipv4: '10.240.8.9', port: 8080 },
    workloadNetwork: portableNetworkContext(target, '10.240.8.3', 'review-workload'),
    proxyNetwork: portableNetworkContext(target, '10.240.8.9', 'review-proxy'),
    capabilities: { ...L7_CAPABILITIES },
  });

  assert.equal(result.target, 'gateway-l7-proxy');
  assert.equal(result.activationEligible, false);
  assert.equal(result.projections[0].parity, 'conditional');
  assert.ok(Object.hasOwn(result.artifacts, 'workload-pf.anchor.conf'));
  assert.ok(Object.hasOwn(result.artifacts, 'proxy-pf.anchor.conf'));
  assert.equal(
    JSON.parse(result.artifacts['workload-apply-plan.json']).mode,
    'render-only',
  );
  assert.equal(
    JSON.parse(result.artifacts['proxy-apply-plan.json']).mode,
    'render-only',
  );
  assert.match(result.limitations.join('\n'), /render-only/);
  assert.match(result.projections[0].preconditions.join('\n'), /TTL-aware managed DNS/);
});
