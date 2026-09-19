'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const test = require('node:test');

const CREATED_AT = '2026-09-14T12:00:00.000Z';
const ROLES = ['nodes', 'observations', 'coverage', 'findings', 'proposals', 'diff'];

async function fixture(t) {
  const [core, buildAdapter, buildArtifacts, buildStore, runtimeAdapter, sbom,
    bundles, projectionService, approvalService, signing] = await Promise.all([
    import('../lib/guard/review/index.js'),
    import('../lib/guard/review/build-adapter.js'),
    import('../lib/guardd/build-profile-artifacts.js'),
    import('../lib/guardd/build-profile-store.js'),
    import('../lib/guard/review/runtime-adapter.js'),
    import('../lib/guard/review/sbom.js'),
    import('../lib/guard/review/bundle-store.js'),
    import('../lib/guard/review/projection-service.js'),
    import('../lib/guard/review/approval-service.js'),
    import('../lib/guard/review/signing.js'),
  ]);
  const parent = fs.mkdtempSync(path.join(os.tmpdir(), 'nosh-finding-target-'));
  t.after(() => fs.rmSync(parent, { recursive: true, force: true }));
  const home = path.join(parent, 'home');
  const context = path.join(parent, 'context');
  fs.mkdirSync(home, { mode: 0o700 });
  fs.mkdirSync(context, { mode: 0o700 });
  const networkRecords = [
    { family: 'ipv4', sourceAddress: '10.0.0.2', destinationAddress: '203.0.113.10' },
    { family: 'ipv6', sourceAddress: '2001:db8::2', destinationAddress: '2001:db8::10' },
  ].map((addresses) => ({
    pass: 'cold', recordKind: 'flow-summary', cgroupId: '701',
    firstObservedNs: '1789387200000000000', lastObservedNs: '1789387200001000000',
    accounting: { packets: '1', bytes: '64' },
    network: {
      ...addresses, direction: 'egress', protocol: 'tcp',
      sourcePort: 40000, destinationPort: 443,
    },
  }));
  const required = buildArtifacts.requiredBuildEvidenceSources('build-net-learn', 'balanced');
  const finalized = await new buildStore.BuildProfileStore({ home }).finalizeRun({
    context, runId: 'build-ipv6-applicability', mode: 'build-net-learn',
    generatedAt: CREATED_AT, startedAt: CREATED_AT, endedAt: CREATED_AT,
    builder: { imageDigest: core.sha256Digest('builder') },
    build: {
      success: true, exitCode: 0, platform: 'linux/amd64', cacheMode: 'cold',
      depth: 'balanced', passes: [{ name: 'cold', success: true, exitCode: 0, durationMs: 1 }],
    },
    coverage: {
      builderIdentityStable: true, exclusiveBuilderLease: true, parentObserved: true,
      cleanupComplete: true, freshBuilder: true, forcedSourcePulls: true,
      cacheImportsDisabled: true, allReachableStepsExecuted: true,
    },
    sources: required.map((name) => ({
      name, format: 'ndjson', required: true, complete: true,
      lostEvents: 0, parseErrors: 0, completionMarker: 'clean-supervised-stop',
      content: `${(name === 'ebpf-network' ? networkRecords : [{ source: name, final: true }])
        .map((record) => JSON.stringify(record)).join('\n')}\n`,
    })),
    observations: {
      network: {
        destinations: [], directIp: [], encryptedDns: [], privateDestinations: [],
        parseFailures: [], unresolved: [],
      },
    },
  });
  const candidate = {
    revision: 'runtime-one', createdAt: CREATED_AT, evidenceRunId: 'runtime-one',
    evidenceManifestHash: core.sha256Digest('runtime-evidence'),
    manifestHash: core.sha256Digest('runtime-manifest'),
    policyHash: core.sha256Digest('runtime-policy'), rulesHash: core.sha256Digest('runtime-rules'),
    imageDigest: core.sha256Digest('runtime-image'), workspaceKey: '4'.repeat(64),
    workspaceIdentity: { dev: '2050', ino: '1234' }, unresolvedObservations: [],
    rules: [{ destination: '1.1.1.1/32', protocol: 'tcp', ports: [443] }],
  };
  const graph = await buildAdapter.createBuildReviewGraph(finalized.directory, {
    runtimeBinding: runtimeAdapter.runtimeCandidateBinding(candidate),
  });
  assert.equal(graph.profile.complete, true);
  const runtime = runtimeAdapter.createRuntimeCandidateGraphRecords(graph.scope, candidate);
  const records = Object.fromEntries(ROLES.map((role) => [
    role, [...graph[role], ...(runtime.records[role] || [])],
  ]));
  const sources = [...graph.sources, runtime.source];
  for (const role of ['source', 'image']) {
    const document = {
      spdxVersion: 'SPDX-2.3', name: `${role}-fixture`,
      packages: [{ SPDXID: 'SPDXRef-Package', name: `${role}-package`, versionInfo: '1.0.0' }],
    };
    const generated = sbom.sbomGraphRecords({
      scope: graph.scope, role, digest: core.sha256Digest(document),
      sbom: sbom.normalizeSbomDocument(document),
    });
    records.nodes.push(...generated.nodes);
    records.observations.push(...generated.observations);
    records.coverage.push(generated.coverage);
    sources.push({
      id: generated.sourceNode.id, sourceType: 'software-bill-of-materials',
      artifactKind: 'SPDXDocument', artifactDigest: core.sha256Digest(document),
      sourceName: `${role}-sbom`, sourceDigest: core.sha256Digest(document),
      coverage: { status: 'complete', lostEvents: '0', parseErrors: '0', gaps: [] },
    });
  }
  const ipv6Finding = records.findings.find((entry) => entry.properties.family === 'ipv6');
  assert.ok(ipv6Finding);
  assert.equal(ipv6Finding.blocking, true);
  assert.equal(ipv6Finding.findingType, 'unsupported-target');
  assert.equal(ipv6Finding.evidenceRefs.length, 1);
  assert.equal(ipv6Finding.semanticRefs.length, 1);
  assert.deepEqual(ipv6Finding.properties.targetApplicability, {
    kind: 'build-network-ipv6-v1', scopeClass: 'build',
    targets: buildAdapter.buildTargetFeasibility('network', 'ipv6-cidr')
      .map(({ target, status }) => ({ target, status })),
  });
  assert.deepEqual(records.findings.filter((entry) => entry.blocking), [ipv6Finding]);
  assert.equal(records.proposals.filter((entry) => entry.scopeClass === 'build').length, 1);
  const unsignedContext = {
    apiVersion: 'notty.dev/v1alpha1', kind: 'NoshGuardEbpfTargetContext', schemaVersion: 2,
    createdAt: CREATED_AT, backendAbi: 'nosh-egress-v2',
    objectDigest: core.sha256Digest('backend-object'),
    subject: runtimeAdapter.runtimeCandidateBinding(candidate),
    capabilities: {
      atomicPolicyGeneration: true, cgroupConnect: true, cgroupSendmsg: true,
      cgroupSkb: true, dnsParser: true, exactPlatformContainment: true, ipv6: true,
      tcpDns: false, ttlGrants: true,
    },
    resolvers: ['1.1.1.1', '8.8.8.8'],
    platformContainment: {
      strategy: 'per-run-docker-bridge-gateways', ipv4PrefixLength: 32, ipv6PrefixLength: 128,
    },
  };
  const targetContext = { ...unsignedContext, contentHash: core.sha256Digest(unsignedContext) };
  const privateKey = path.join(parent, 'private.pem');
  fs.writeFileSync(privateKey, signing.generateEd25519KeyPair().privateKeyPem, { mode: 0o600 });
  let sequence = 0;
  async function prepare(options = {}) {
    const directory = path.join(parent, `case-${++sequence}`);
    fs.mkdirSync(directory, { mode: 0o700 });
    const changed = structuredClone(records);
    options.mutate?.(changed);
    const review = bundles.createReviewBundleArtifact({
      createdAt: CREATED_AT, scope: graph.scope, sources,
      records: changed, basePolicyDigest: core.sha256Digest(null), privacyProfile: 'private-review',
    });
    const bundle = path.join(directory, 'review');
    await bundles.writeReviewBundleArtifact(bundle, review);
    const loaded = await bundles.readReviewBundleArtifact(bundle);
    const decisions = core.createDecisionSet({
      createdAt: CREATED_AT, reviewer: 'target-reviewer', graph: loaded.graph,
      decisions: changed.proposals.map((proposal) => ({
        proposalId: proposal.id,
        disposition: options.disposition?.(proposal)
          || (proposal.scopeClass === 'runtime' ? 'accept' : 'reject'),
        rationale: 'Explicitly reviewed for this target.', targetAcknowledgements: [],
      })),
    });
    const decisionsPath = path.join(directory, 'decisions.json');
    fs.writeFileSync(decisionsPath, `${core.jcsCanonicalize(decisions)}\n`, { mode: 0o600 });
    const projection = await projectionService.createPolicyProjectionArtifact({
      bundle, decisions: decisionsPath, target: options.target || 'guard-ebpf',
      context: options.context || targetContext, createdAt: CREATED_AT,
    });
    const policy = path.join(directory, 'policy');
    await projectionService.writePolicyProjectionArtifact(policy, projection);
    return {
      projection,
      approve: () => approvalService.createReviewApprovalArtifact({
        bundle, decisions: decisionsPath, policy, reviewer: decisions.reviewer,
        audience: 'target-test', privateKey,
        confirmation: projection.targetReviewSet.contentDigest, createdAt: CREATED_AT,
      }),
    };
  }
  return { core, records, ipv6Finding, prepare };
}

test('build IPv6 compatibility applies to its target without suppressing approval evidence gates', async (t) => {
  const current = await fixture(t);
  const { core, prepare } = current;
  const findIpv6 = (records) => records.findings.find((entry) => entry.properties.family === 'ipv6');
  await t.test('complete SBOMs and reviewed literal runtime authority can be signed', async () => {
    const result = await prepare();
    assert.equal(result.projection.leaf.activationEligible, true);
    const native = JSON.parse(result.projection.compilerResult.artifacts['ebpf-policy.json']);
    assert.equal(native.rules.length, 1);
    assert.equal(native.rules[0].peer.value, '1.1.1.1/32');
    const approval = await result.approve();
    assert.equal(approval.statement.reviewer, 'target-reviewer');
    assert.equal(approval.review.graph.findings.filter((entry) => entry.blocking).length, 1);
  });
  const mutations = [
    ['old bundle without applicability', (finding) => { delete finding.properties.targetApplicability; }],
    ['unknown compatibility kind', (finding) => { finding.properties.targetApplicability.kind = 'other'; }],
    ['runtime applicability scope', (finding) => { finding.properties.targetApplicability.scopeClass = 'runtime'; }],
    ['malformed applicability', (finding) => { finding.properties.targetApplicability = 'guard-ebpf'; }],
    ['unknown applicability field', (finding) => { finding.properties.targetApplicability.ignore = true; }],
    ['missing target', (finding) => { finding.properties.targetApplicability.targets.pop(); }],
    ['duplicate target', (finding) => {
      const targets = finding.properties.targetApplicability.targets;
      targets.push(structuredClone(targets.find((entry) => entry.target === 'guard-ebpf')));
    }],
    ['unknown target', (finding) => { finding.properties.targetApplicability.targets[0].target = 'other'; }],
    ['target remains unsupported', (finding) => {
      finding.properties.targetApplicability.targets.find((entry) => entry.target === 'guard-ebpf')
        .status = 'unsupported';
    }],
    ['unrelated unsupported-target family', (finding) => { finding.properties.family = 'ipv4'; }],
    ['unresolved runtime evidence', (finding) => { finding.findingType = 'unresolved-evidence'; }],
  ];
  for (const [name, mutate] of mutations) {
    await t.test(name, async () => {
      const result = await prepare({ mutate: (records) => mutate(findIpv6(records)) });
      await assert.rejects(result.approve, /blocking findings/);
    });
  }
  for (const domain of ['sbom-source', 'sbom-image']) {
    await t.test(`${domain} cannot be waived`, async () => {
      const result = await prepare({ mutate(records) {
        records.coverage = records.coverage.filter((entry) => entry.domain !== domain);
      } });
      await assert.rejects(result.approve, /non-approvable missing SBOM coverage gaps/);
    });
  }
  await t.test('runtime capture coverage remains blocking', async () => {
    const result = await prepare({ mutate(records) {
      const marker = records.coverage.find((entry) => entry.domain === 'runtime-network');
      marker.status = 'degraded';
      marker.blocking = true;
      marker.gaps = ['lost runtime event'];
    } });
    await assert.rejects(result.approve, /blocking coverage gaps/);
  });
  await t.test('an unrelated blocking finding is not suppressed', async () => {
    const result = await prepare({ mutate(records) {
      const original = findIpv6(records);
      records.findings.push(core.createFinding({
        ...original, id: undefined, semanticKey: { test: 'runtime-parser-gap' },
        findingType: 'unresolved-evidence', message: 'Runtime DNS parsing was incomplete.',
        properties: {},
      }));
    } });
    await assert.rejects(result.approve, /blocking findings/);
  });
  await t.test('accepting build authority still prevents runtime activation', async () => {
    const result = await prepare({ disposition: () => 'accept' });
    // Projection classifies the build rule outsideScope and omits it. The
    // compatibility finding still blocks approval of this mixed authority.
    assert.equal(result.projection.leaf.activationEligible, true);
    await assert.rejects(result.approve, /blocking findings/);
  });
  await t.test('pending decisions still cannot enter an approved policy', async () => {
    await assert.rejects(
      () => prepare({ disposition: () => 'needs-review' }),
      /still needs review/,
    );
  });
  await t.test('build capture coverage remains blocking', async () => {
    const result = await prepare({ mutate(records) {
      const marker = records.coverage.find((entry) => entry.domain === 'network');
      marker.status = 'degraded';
      marker.blocking = true;
      marker.gaps = ['lost build event'];
    } });
    await assert.rejects(result.approve, /blocking coverage gaps/);
  });
  await t.test('build target still rejects its unsupported IPv6 observation', async () => {
    const result = await prepare({
      target: 'guard-nftables',
      disposition: (proposal) => proposal.scopeClass === 'build' ? 'accept' : 'reject',
      context: {
        networkName: 'review-net', sourceIpv4: '10.240.8.3', gatewayIpv4: '10.240.8.2',
        uplinkInterface: 'eth0', internalInterfaces: ['review0'], upstreamServers: ['1.1.1.1'],
        capabilities: {
          connmarkAllowlist: true, exclusiveFirewallOwnership: true, managedDnsExclusive: true,
          strictSourceMarking: true, nftset: true, nftAtomic: true,
        },
      },
    });
    assert.equal(result.projection.leaf.activationEligible, true);
    await assert.rejects(result.approve, /blocking findings/);
  });
});
