const assert = require('node:assert/strict');
const fs = require('node:fs');
const fsp = require('node:fs/promises');
const os = require('node:os');
const path = require('node:path');
const test = require('node:test');

async function modules() {
  const host = await import('../lib/guard/review/gateway-host.js');
  const signing = await import('../lib/guard/review/signing.js');
  const jcs = await import('../lib/guard/review/jcs.js');
  return { host, signing, jcs };
}

function digest(seed) {
  return `sha256:${String(seed).padStart(64, '0').slice(-64)}`;
}

async function fixture() {
  const { host, signing, jcs } = await modules();
  const review = signing.generateEd25519KeyPair();
  const deployment = signing.generateEd25519KeyPair();
  const now = new Date('2026-08-17T12:00:00.000Z');
  const targetContextDigest = digest('11');
  const capabilityDigest = digest('12');
  const activeGrantSetDigest = digest('13');
  const compiler = {
    id: 'nosh-guard-nftables-policy-v1',
    version: '1',
  };
  compiler.digest = jcs.sha256Digest(compiler);
  const policy = {
    directory: '/var/lib/nosh-gateway/incoming/leaf',
    leaf: {
      activationEligible: true,
      target: 'guard-nftables',
      targetContextDigest,
      capabilityDigest,
      bundleDigest: digest('14'),
      artifacts: [
        'apply-plan.json',
        'dnsmasq.conf',
        'gateway-policy.json',
        'nftables.nft',
      ].map((name) => ({ path: `rendered/${name}` })),
    },
    policyIR: {
      graphDigest: digest('15'),
      proposalSetDigest: digest('16'),
      decisionSetDigest: digest('17'),
      contentDigest: digest('18'),
      scope: { scopeDigest: digest('19') },
    },
    targetReviewSet: {
      contentDigest: digest('20'),
      projections: [{
        target: 'guard-nftables',
        targetContextDigest,
        activationEligible: true,
        compiler,
      }],
    },
    projection: {
      target: 'guard-nftables',
      targetContextDigest,
      capabilityDigest,
      activationEligible: true,
      artifactsDigest: digest('21'),
    },
  };
  const trust = host.validateGatewayTrustConfig({
    apiVersion: 'notty.dev/v1alpha1',
    kind: 'NoshGatewayTrustConfig',
    schemaVersion: 1,
    audience: 'edge-gateway-01',
    target: 'guard-nftables',
    targetBindingDigest: digest('22'),
    targetContextDigest,
    capabilityDigest,
    activeGrantSetDigest,
    reviewKeys: [{ keyId: review.keyId, publicKeyPem: review.publicKeyPem }],
    deploymentKeys: [{
      keyId: deployment.keyId,
      publicKeyPem: deployment.publicKeyPem,
    }],
    commands: {
      conntrack: '/usr/sbin/conntrack',
      dnsmasq: '/usr/sbin/dnsmasq',
      nft: '/usr/sbin/nft',
      systemctl: '/usr/bin/systemctl',
    },
    paths: {
      dnsmasqConfig: '/etc/nosh-gateway/dnsmasq.conf',
      nftablesConfig: '/etc/nosh-gateway/nftables.nft',
      stateDirectory: '/var/lib/nosh-gateway',
    },
    services: { dnsmasq: 'nosh-gateway-dnsmasq.service' },
  });
  const approvalStatement = signing.createReviewApprovalStatement({
    issuedAt: now.toISOString(),
    reviewer: 'reviewer@example.test',
    audience: trust.audience,
    bundleDigest: digest('23'),
    graphDigest: policy.policyIR.graphDigest,
    proposalSetDigest: policy.policyIR.proposalSetDigest,
    decisionSetDigest: policy.policyIR.decisionSetDigest,
    policyIrDigest: policy.policyIR.contentDigest,
    targetReviewSetDigest: policy.targetReviewSet.contentDigest,
    baselineDigest: null,
    scopeDigest: policy.policyIR.scope.scopeDigest,
    confirmationDigest: jcs.sha256Digest(policy.targetReviewSet.contentDigest),
  });
  const approvalEnvelope = signing.createDsseEnvelope(
    signing.REVIEW_APPROVAL_PAYLOAD_TYPE,
    approvalStatement,
    review.privateKeyPem,
  );
  const approvalEnvelopeDigest = jcs.sha256Digest(jcs.jcsCanonicalize(approvalEnvelope));
  const grantStatement = signing.createGatewayGrantStatement({
    audience: trust.audience,
    target: trust.target,
    leafBundleDigest: policy.leaf.bundleDigest,
    approvalEnvelopeDigest,
    targetBindingDigest: trust.targetBindingDigest,
    capabilityDigest,
    activeGrantSetDigest,
    renderedArtifactsDigest: policy.projection.artifactsDigest,
    notBefore: now.toISOString(),
    expiresAt: new Date(now.getTime() + 60 * 60 * 1000).toISOString(),
    nonce: 'grant-0001',
  }, { now });
  const grantEnvelope = signing.createDsseEnvelope(
    signing.GATEWAY_GRANT_PAYLOAD_TYPE,
    grantStatement,
    deployment.privateKeyPem,
  );
  const state = host.createInitialGatewayState(trust);
  return {
    host,
    signing,
    jcs,
    review,
    deployment,
    now,
    policy,
    trust,
    approvalEnvelope,
    grantEnvelope,
    state,
  };
}

test('gateway activation verifies both signing roles and every deployment binding', async () => {
  const value = await fixture();
  const activation = value.host.verifyGatewayActivation({
    policy: value.policy,
    approvalEnvelope: value.approvalEnvelope,
    grantEnvelope: value.grantEnvelope,
    trust: value.trust,
    state: value.state,
    now: value.now,
  });
  assert.equal(activation.approval.verifiedKeys[0].keyId, value.review.keyId);
  assert.equal(activation.grant.verifiedKeys[0].keyId, value.deployment.keyId);
  assert.equal(activation.grant.statement.activeGrantSetDigest, value.state.activeGrantSetDigest);
});

test('gateway activation rejects replay and a stale active grant-set binding', async () => {
  const value = await fixture();
  const verified = value.host.verifyGatewayActivation({
    policy: value.policy,
    approvalEnvelope: value.approvalEnvelope,
    grantEnvelope: value.grantEnvelope,
    trust: value.trust,
    state: value.state,
    now: value.now,
  });
  const replayState = {
    ...value.state,
    usedGrants: [{
      nonce: verified.grant.statement.nonce,
      expiresAt: verified.grant.statement.expiresAt,
      grantEnvelopeDigest: verified.grant.envelopeDigest,
    }],
    stateDigest: '',
  };
  replayState.stateDigest = value.jcs.sha256Digest(
    Object.fromEntries(Object.entries(replayState).filter(([name]) => name !== 'stateDigest')),
  );
  assert.throws(() => value.host.verifyGatewayActivation({
    policy: value.policy,
    approvalEnvelope: value.approvalEnvelope,
    grantEnvelope: value.grantEnvelope,
    trust: value.trust,
    state: replayState,
    now: value.now,
  }), /already applied/);

  const staleState = value.host.createInitialGatewayState({
    ...value.trust,
    activeGrantSetDigest: digest('99'),
  });
  assert.throws(() => value.host.verifyGatewayActivation({
    policy: value.policy,
    approvalEnvelope: value.approvalEnvelope,
    grantEnvelope: value.grantEnvelope,
    trust: { ...value.trust, activeGrantSetDigest: digest('99') },
    state: staleState,
    now: value.now,
  }), /activeGrantSetDigest/);
});

test('gateway activation rejects target capability drift and signed-payload tampering', async () => {
  const value = await fixture();
  assert.throws(() => value.host.verifyGatewayActivation({
    policy: value.policy,
    approvalEnvelope: value.approvalEnvelope,
    grantEnvelope: value.grantEnvelope,
    trust: { ...value.trust, capabilityDigest: digest('77') },
    state: value.state,
    now: value.now,
  }), /capability/);

  const driftedTrust = {
    ...value.trust,
    audience: 'edge-gateway-02',
  };
  assert.throws(() => value.host.verifyGatewayActivation({
    policy: value.policy,
    approvalEnvelope: value.approvalEnvelope,
    grantEnvelope: value.grantEnvelope,
    trust: driftedTrust,
    state: value.host.createInitialGatewayState(driftedTrust),
    now: value.now,
  }), /review approval audience does not match/);

  const tampered = structuredClone(value.grantEnvelope);
  const statement = JSON.parse(Buffer.from(tampered.payload, 'base64').toString('utf8'));
  statement.expiresAt = new Date(value.now.getTime() + 2 * 60 * 60 * 1000).toISOString();
  tampered.payload = Buffer.from(value.jcs.jcsCanonicalize(statement)).toString('base64');
  assert.throws(() => value.host.verifyGatewayActivation({
    policy: value.policy,
    approvalEnvelope: value.approvalEnvelope,
    grantEnvelope: tampered,
    trust: value.trust,
    state: value.state,
    now: value.now,
  }), /no valid trusted signature/);
});

test('gateway trust requires distinct review and deployment keys and strict fields', async () => {
  const value = await fixture();
  assert.throws(() => value.host.validateGatewayTrustConfig({
    ...value.trust,
    deploymentKeys: value.trust.reviewKeys,
  }), /separate keys/);
  assert.throws(() => value.host.validateGatewayTrustConfig({
    ...value.trust,
    permissiveFallback: true,
  }), /unsupported fields/);
  assert.throws(() => value.host.validateGatewayTrustConfig({
    ...value.trust,
    commands: { ...value.trust.commands, nft: '/usr/bin/true' },
  }), /unexpected executable name/);
});

test('active grant-set evolution binds the complete prior grant identity', async () => {
  const { host } = await modules();
  const input = {
    previousActiveGrantSetDigest: digest('31'),
    grantEnvelopeDigest: digest('32'),
    leafBundleDigest: digest('33'),
    nonce: 'unique-nonce',
  };
  const first = host.computeNextActiveGrantSetDigest(input);
  assert.equal(first, host.computeNextActiveGrantSetDigest(input));
  assert.notEqual(first, host.computeNextActiveGrantSetDigest({
    ...input,
    nonce: 'different-nonce',
  }));
});

test('active gateway state requires backend-bound live verification metadata', async () => {
  const value = await fixture();
  const active = {
    ...value.state,
    status: 'active',
    currentLeafBundleDigest: value.policy.leaf.bundleDigest,
    currentGrantEnvelopeDigest: digest('34'),
    lastAppliedAt: value.now.toISOString(),
    liveStateDigest: digest('35'),
    liveVerification: {
      backend: 'guard-nftables',
      dnsmasqConfigDigest: digest('36'),
    },
    stateDigest: '',
  };
  active.stateDigest = value.jcs.sha256Digest(
    Object.fromEntries(Object.entries(active).filter(([name]) => name !== 'stateDigest')),
  );
  assert.equal(value.host.validateGatewayState(active, value.trust), active);

  const missing = { ...active, liveVerification: null, stateDigest: '' };
  missing.stateDigest = value.jcs.sha256Digest(
    Object.fromEntries(Object.entries(missing).filter(([name]) => name !== 'stateDigest')),
  );
  assert.throws(
    () => value.host.validateGatewayState(missing, value.trust),
    /missing its activation identity/,
  );
});

test('runtime status fails active policy on DNS config drift or inactive service', async () => {
  const { host } = await modules();
  const expectedDigest = digest('37');
  const state = {
    status: 'active',
    liveVerification: {
      backend: 'guard-nftables',
      dnsmasqConfigDigest: expectedDigest,
    },
  };
  const firewall = { matchesExpected: true, matchesRecorded: true };
  const config = {
    path: '/etc/nosh-gateway/dnsmasq.conf',
    exists: true,
    digest: expectedDigest,
  };
  const service = {
    unit: 'nosh-gateway-dnsmasq.service',
    code: 0,
  };
  const healthy = host.evaluateGatewayRuntimeStatus(
    state,
    firewall,
    config,
    service,
  );
  assert.equal(healthy.matchesExpected, true);
  assert.equal(healthy.dnsmasqConfig.matchesExpected, true);
  assert.equal(healthy.dnsmasqService.active, true);

  const drifted = host.evaluateGatewayRuntimeStatus(
    state,
    firewall,
    { ...config, digest: digest('38') },
    service,
  );
  assert.equal(drifted.firewallMatchesExpected, true);
  assert.equal(drifted.dnsmasqConfig.matchesExpected, false);
  assert.equal(drifted.matchesExpected, false);

  const inactive = host.evaluateGatewayRuntimeStatus(
    state,
    firewall,
    config,
    { ...service, code: 3 },
  );
  assert.equal(inactive.dnsmasqService.active, false);
  assert.equal(inactive.matchesExpected, false);
});

test('iptables activation uses no-flush insertion and isolates managed generation cleanup', async () => {
  const { host } = await modules();
  const verifyPlan = {
    schemaVersion: 1,
    backend: 'iptables-nft-ipset-dnsmasq',
    expectedSourceIpv4: '10.24.0.7',
    expectedChain: 'NG_0123456789ABCDEF',
    expectedFlowMark: '0x12345678',
    expectedHookComment: 'nosh-gateway:0123456789ab:hook',
    infrastructureCommentPrefix: 'nosh-gateway:abcdef012345:infra',
  };
  const rendered = Buffer.from([
    '*mangle',
    '-A PREROUTING -s 10.24.0.7 -d 10.24.0.1 -p udp --dport 53 -m comment --comment "nosh-gateway:abcdef012345:infra:dns-mark-udp" -j CONNMARK --set-mark 0x1',
    '-A PREROUTING -s 10.24.0.7 -d 10.24.0.1 -p tcp --dport 53 -m comment --comment "nosh-gateway:abcdef012345:infra:dns-mark-tcp" -j CONNMARK --set-mark 0x1',
    'COMMIT',
    '*filter',
    '-A INPUT -s 10.24.0.7 -d 10.24.0.1 -p udp --dport 53 -m comment --comment "nosh-gateway:abcdef012345:infra:dns-input-udp" -j ACCEPT',
    '-A INPUT -s 10.24.0.7 -d 10.24.0.1 -p tcp --dport 53 -m comment --comment "nosh-gateway:abcdef012345:infra:dns-input-tcp" -j ACCEPT',
    ':NG_0123456789ABCDEF - [0:0]',
    '-A FORWARD -s 10.24.0.7 -m comment --comment "nosh-gateway:0123456789ab:hook" -j NG_0123456789ABCDEF',
    '-A FORWARD -d 10.24.0.7 -m conntrack --ctstate ESTABLISHED,RELATED -m connmark --mark 0x12345678 -m comment --comment "nosh-gateway:0123456789ab:return" -j ACCEPT',
    '-A NG_0123456789ABCDEF -j DROP',
    'COMMIT',
    '*nat',
    '-A POSTROUTING -s 10.24.0.7 -o eth0 -m comment --comment "nosh-gateway:abcdef012345:infra:masquerade" -j MASQUERADE',
    'COMMIT',
    '',
  ].join('\n'));
  const isolated = host.createIsolationSafeIptablesRestore(rendered, verifyPlan)
    .toString('utf8');
  assert.match(isolated, /-I FORWARD 1 -s 10\.24\.0\.7 .* -j NG_0123456789ABCDEF/);
  assert.match(isolated, /-I FORWARD 1 -s 10\.24\.0\.7 -m comment/);
  assert.doesNotMatch(isolated, /:FORWARD /);
  assert.throws(() => host.createIsolationSafeIptablesRestore(Buffer.from(
    rendered.toString('utf8').replace(
      ':NG_0123456789ABCDEF - [0:0]',
      ':FORWARD ACCEPT [0:0]\n:NG_0123456789ABCDEF - [0:0]',
    ),
  ), verifyPlan), /unsupported chain/);

  const cleanup = host.createIptablesGenerationCleanup([
    '*mangle',
    '-A PREROUTING -s 10.24.0.7/32 -p udp --dport 53 -m comment --comment "nosh-gateway:abcdef012345:infra:dns-mark-udp" -j CONNMARK --set-xmark 0x1/0xffffffff',
    '-A PREROUTING -s 10.24.0.7/32 -p tcp --dport 53 -m comment --comment "nosh-gateway:abcdef012345:infra:dns-mark-tcp" -j CONNMARK --set-xmark 0x1/0xffffffff',
    'COMMIT',
    '*filter',
    ':NG_AAAAAAAA11111111 - [0:0]',
    ':UNRELATED - [0:0]',
    '-A INPUT -s 10.24.0.7/32 -p udp --dport 53 -m comment --comment "nosh-gateway:abcdef012345:infra:dns-input-udp" -j ACCEPT',
    '-A INPUT -s 10.24.0.7/32 -p tcp --dport 53 -m comment --comment "nosh-gateway:abcdef012345:infra:dns-input-tcp" -j ACCEPT',
    '-A FORWARD -s 10.24.0.7/32 -m comment --comment "nosh-gateway:aaaaaaaa1111:hook" -j NG_AAAAAAAA11111111',
    '-A FORWARD -s 10.99.0.4/32 -j UNRELATED',
    '-A FORWARD -d 10.24.0.7/32 -m conntrack --ctstate RELATED,ESTABLISHED -m connmark --mark 0x12345678 -m comment --comment "nosh-gateway:aaaaaaaa1111:return" -j ACCEPT',
    '-A FORWARD -d 10.24.0.7/32 -m conntrack --ctstate RELATED,ESTABLISHED -m connmark --mark 0xdeadbeef -j ACCEPT',
    'COMMIT',
    '*nat',
    '-A POSTROUTING -s 10.24.0.7/32 -m comment --comment "nosh-gateway:abcdef012345:infra:masquerade" -j MASQUERADE',
    'COMMIT',
    '',
  ].join('\n'), verifyPlan);
  assert.match(cleanup.transaction, /-D FORWARD -s 10\.24\.0\.7\/32 .* -j NG_AAAAAAAA11111111/);
  assert.match(cleanup.transaction, /-F NG_AAAAAAAA11111111/);
  assert.doesNotMatch(cleanup.transaction, /UNRELATED/);
  assert.doesNotMatch(cleanup.transaction, /0xdeadbeef/);
  assert.match(cleanup.transaction, /-D PREROUTING .*infra:dns-mark-udp/);
  assert.match(cleanup.transaction, /-D INPUT .*infra:dns-input-udp/);
  assert.match(cleanup.transaction, /-D POSTROUTING .*infra:masquerade/);
  assert.equal((cleanup.transaction.match(/infra:/g) || []).length, 5);
  assert.deepEqual(cleanup.obsoleteSetPrefixes, ['aaaaaaaa']);
});

test('nft replacement atomically deletes the exclusively owned table before redeclaration', async () => {
  const { host } = await modules();
  const artifact = Buffer.from('table inet nosh_guard {\n}\n');
  assert.equal(
    host.createNftReplacementTransaction(artifact, true).toString('utf8'),
    'delete table inet nosh_guard\ntable inet nosh_guard {\n}\n',
  );
  assert.equal(
    host.createNftReplacementTransaction(artifact, false).toString('utf8'),
    artifact.toString('utf8'),
  );
  assert.throws(() => host.createNftReplacementTransaction(
    'table inet unrelated {\n}\n',
    true,
  ), /exclusively declare/);
  assert.throws(() => host.createNftReplacementTransaction(
    'table inet nosh_guard {\n}\ntable inet unrelated {\n}\n',
    true,
  ), /content after/);
  assert.throws(() => host.createNftReplacementTransaction(
    'table inet nosh_guard {\n  include "/etc/nftables.conf"\n}\n',
    true,
  ), /unsupported operation/);
});

test('nft live-state normalization ignores only counters and expiring set members', async () => {
  const { host } = await modules();
  const artifact = [
    'table inet nosh_guard {',
    '  set dynamic_v4 {',
    '    type ipv4_addr',
    '    flags interval,timeout',
    '    timeout 5m',
    '  }',
    '  set static_v4 {',
    '    type ipv4_addr',
    '    flags interval',
    '    elements = { 10.0.0.0/8 }',
    '  }',
    '  chain forward {',
    '    type filter hook forward priority filter; policy drop;',
    '    ip saddr 10.24.0.7 counter accept',
    '  }',
    '}',
    '',
  ].join('\n');
  const live = [
    'table inet nosh_guard {',
    '  set dynamic_v4 {',
    '    type ipv4_addr;',
    '    flags interval,timeout;',
    '    timeout 5m;',
    '    elements = { 192.0.2.8 expires 4m12s }',
    '  }',
    '  set static_v4 {',
    '    type ipv4_addr;',
    '    flags interval;',
    '    elements = { 10.0.0.0/8 };',
    '  }',
    '  chain forward {',
    '    type filter hook forward priority filter; policy drop;',
    '    ip saddr 10.24.0.7 counter packets 12 bytes 840 accept',
    '  }',
    '}',
    '',
  ].join('\n');
  assert.equal(
    host.normalizeNftManagedRuleset(live),
    host.normalizeNftManagedRuleset(artifact),
  );
  assert.notEqual(
    host.normalizeNftManagedRuleset(live.replace('10.0.0.0/8', '10.1.0.0/16')),
    host.normalizeNftManagedRuleset(artifact),
  );
});

test('iptables live verification binds signed chains, hooks, infrastructure, marks, and sets', async () => {
  const { host } = await modules();
  const verifyPlan = {
    schemaVersion: 1,
    backend: 'iptables-nft-ipset-dnsmasq',
    expectedSourceIpv4: '10.24.0.7',
    expectedChain: 'NG_0123456789ABCDEF',
    expectedFlowMark: '0x12345678',
    expectedHookComment: 'nosh-gateway:0123456789ab:hook',
    expectedSets: ['ng_01234567_dynamic', 'ng_01234567_static'],
    infrastructureCommentPrefix: 'nosh-gateway:abcdef012345:infra',
    requireManagedDns: true,
  };
  const iptables = Buffer.from([
    '*mangle',
    '-A PREROUTING -s 10.24.0.7 -d 10.24.0.1 -p udp --dport 53 -m comment --comment "nosh-gateway:abcdef012345:infra:dns-mark-udp" -j CONNMARK --set-mark 0x1',
    '-A PREROUTING -s 10.24.0.7 -d 10.24.0.1 -p tcp --dport 53 -m comment --comment "nosh-gateway:abcdef012345:infra:dns-mark-tcp" -j CONNMARK --set-mark 0x1',
    'COMMIT',
    '*filter',
    '-A INPUT -s 10.24.0.7 -d 10.24.0.1 -p udp --dport 53 -m comment --comment "nosh-gateway:abcdef012345:infra:dns-input-udp" -j ACCEPT',
    '-A INPUT -s 10.24.0.7 -d 10.24.0.1 -p tcp --dport 53 -m comment --comment "nosh-gateway:abcdef012345:infra:dns-input-tcp" -j ACCEPT',
    ':NG_0123456789ABCDEF - [0:0]',
    '-A FORWARD -s 10.24.0.7 -m comment --comment "nosh-gateway:0123456789ab:hook" -j NG_0123456789ABCDEF',
    '-A FORWARD -d 10.24.0.7 -m conntrack --ctstate ESTABLISHED,RELATED -m connmark --mark 0x12345678 -m comment --comment "nosh-gateway:0123456789ab:return" -j ACCEPT',
    '-A NG_0123456789ABCDEF -m set --match-set ng_01234567_static dst -p tcp --dport 443 -j CONNMARK --set-mark 0x12345678',
    '-A NG_0123456789ABCDEF -m set --match-set ng_01234567_static dst -p tcp --dport 443 -m connmark --mark 0x12345678 -j ACCEPT',
    '-A NG_0123456789ABCDEF -m limit --limit 20/second -j LOG --log-prefix "nosh deny "',
    '-A NG_0123456789ABCDEF -j DROP',
    'COMMIT',
    '*nat',
    '-A POSTROUTING -s 10.24.0.7 -o eth0 -m comment --comment "nosh-gateway:abcdef012345:infra:masquerade" -j MASQUERADE',
    'COMMIT',
    '',
  ].join('\n'));
  const ipset = Buffer.from([
    'create ng_01234567_dynamic hash:ip family inet timeout 300 maxelem 65536 -exist',
    'flush ng_01234567_dynamic',
    'create ng_01234567_static hash:net family inet maxelem 65536 -exist',
    'flush ng_01234567_static',
    'add ng_01234567_static 10.0.0.0/8 -exist',
    '',
  ].join('\n'));
  const artifacts = { iptables, ipset, verifyPlan };
  const liveRules = [
    '# Generated by iptables-save v1.8.9',
    '*mangle',
    ':PREROUTING ACCEPT [0:0]',
    '-A PREROUTING -s 10.24.0.7/32 -d 10.24.0.1/32 -p udp -m udp --dport 53 -m comment --comment "nosh-gateway:abcdef012345:infra:dns-mark-udp" -j CONNMARK --set-xmark 0x1/0xffffffff',
    '-A PREROUTING -s 10.24.0.7/32 -d 10.24.0.1/32 -p tcp -m tcp --dport 53 -m comment --comment "nosh-gateway:abcdef012345:infra:dns-mark-tcp" -j CONNMARK --set-xmark 0x1/0xffffffff',
    'COMMIT',
    '*filter',
    ':INPUT ACCEPT [0:0]',
    ':FORWARD ACCEPT [0:0]',
    ':NG_0123456789ABCDEF - [0:0]',
    '-A FORWARD -s 10.24.0.7/32 -m comment --comment "nosh-gateway:0123456789ab:hook" -j NG_0123456789ABCDEF',
    '-A INPUT -s 10.24.0.7/32 -d 10.24.0.1/32 -p udp -m udp --dport 53 -m comment --comment "nosh-gateway:abcdef012345:infra:dns-input-udp" -j ACCEPT',
    '-A INPUT -s 10.24.0.7/32 -d 10.24.0.1/32 -p tcp -m tcp --dport 53 -m comment --comment "nosh-gateway:abcdef012345:infra:dns-input-tcp" -j ACCEPT',
    '-A FORWARD -d 10.24.0.7/32 -m conntrack --ctstate RELATED,ESTABLISHED -m connmark --mark 0x12345678/0xffffffff -m comment --comment "nosh-gateway:0123456789ab:return" -j ACCEPT',
    '-A NG_0123456789ABCDEF -m set --match-set ng_01234567_static dst -p tcp -m tcp --dport 443 -j CONNMARK --set-xmark 0x12345678/0xffffffff',
    '-A NG_0123456789ABCDEF -m set --match-set ng_01234567_static dst -p tcp -m tcp --dport 443 -m connmark --mark 0x12345678/0xffffffff -j ACCEPT',
    '-A NG_0123456789ABCDEF -m limit --limit 20/sec --limit-burst 5 -j LOG --log-prefix "nosh deny "',
    '-A NG_0123456789ABCDEF -j DROP',
    'COMMIT',
    '*nat',
    ':POSTROUTING ACCEPT [0:0]',
    '-A POSTROUTING -s 10.24.0.7/32 -o eth0 -m comment --comment "nosh-gateway:abcdef012345:infra:masquerade" -j MASQUERADE',
    'COMMIT',
    '',
  ].join('\n');
  const liveSets = [
    'create ng_01234567_dynamic hash:ip family inet hashsize 1024 maxelem 65536 timeout 300 bucketsize 12 initval 0x1234',
    'add ng_01234567_dynamic 192.0.2.8 timeout 240',
    'create ng_01234567_static hash:net family inet hashsize 1024 maxelem 65536 bucketsize 12 initval 0x5678',
    'add ng_01234567_static 10.0.0.0/8',
    '',
  ].join('\n');
  const verified = host.verifyManagedIptablesLive(artifacts, liveRules, liveSets);
  const differentDynamicMember = host.verifyManagedIptablesLive(
    artifacts,
    liveRules,
    liveSets.replace('192.0.2.8', '198.51.100.9'),
  );
  assert.equal(verified.digest, differentDynamicMember.digest);
  const trust = {
    target: 'gateway-iptables',
    commands: {
      iptablesSave: '/usr/sbin/iptables-save',
      ipset: '/usr/sbin/ipset',
    },
  };
  const state = { quarantine: null, liveStateDigest: verified.digest };
  const statusRunner = async (file, args) => ({
    code: 0,
    stdout: file.endsWith('iptables-save') ? liveRules : liveSets,
    stderr: '',
    file,
    args,
  });
  const recorded = await host.readGatewayLiveState(
    { trust, state },
    statusRunner,
    null,
    { verifyPlan },
  );
  assert.equal(recorded.matchesExpected, true);
  const drifted = await host.readGatewayLiveState(
    { trust, state },
    async (file, args) => ({
      code: 0,
      stdout: file.endsWith('iptables-save')
        ? liveRules.replace('-A NG_0123456789ABCDEF -j DROP', '')
        : liveSets,
      stderr: '',
      file,
      args,
    }),
    null,
    { verifyPlan },
  );
  assert.equal(drifted.matchesExpected, false);
  assert.notEqual(drifted.digest, verified.digest);
  assert.throws(() => host.verifyManagedIptablesLive(
    artifacts,
    liveRules.replace('-A NG_0123456789ABCDEF -j DROP', '-A NG_0123456789ABCDEF -j ACCEPT'),
    liveSets,
  ), /managed projection/);
  assert.throws(() => host.verifyManagedIptablesLive(
    artifacts,
    liveRules.replace('0x12345678/0xffffffff', '0x12345678/0x0000ffff'),
    liveSets,
  ), /managed projection/);
  assert.throws(() => host.verifyManagedIptablesLive(
    artifacts,
    liveRules,
    liveSets.replace('10.0.0.0/8', '10.1.0.0/16'),
  ), /static ipset/);
  assert.throws(() => host.verifyManagedIptablesLive(
    artifacts,
    liveRules.replace(
      'nosh-gateway:abcdef012345:infra:masquerade',
      'nosh-gateway:bbbbbbbbbbbb:infra:masquerade',
    ),
    liveSets,
  ), /managed projection/);
});

test('live-state discovery reports crash-left quarantines that state does not track', async () => {
  const { host } = await modules();
  const trust = {
    target: 'guard-nftables',
    commands: { nft: '/usr/sbin/nft' },
  };
  const state = { quarantine: null };
  const runner = async (_file, args) => {
    if (args.includes('nosh_guard')) {
      return { code: 1, stdout: '', stderr: '', file: _file, args };
    }
    return {
      code: 0,
      stdout: 'table inet ngq_0123456789ab\ntable inet unrelated\n',
      stderr: '',
      file: _file,
      args,
    };
  };
  const live = await host.readGatewayLiveState({ trust, state }, runner);
  assert.deepEqual(live.untrackedQuarantines, ['ngq_0123456789ab']);
  assert.equal(live.present, false);
  assert.equal(live.trackedQuarantineMissing, false);

  const tracked = await host.readGatewayLiveState({
    trust,
    state: { quarantine: { id: 'ngq_0123456789ab' } },
  }, runner);
  assert.deepEqual(tracked.untrackedQuarantines, []);
  assert.equal(tracked.trackedQuarantineMissing, false);
});

test('nft status digest reports deletion of the recorded managed table', async () => {
  const { host } = await modules();
  const trust = {
    target: 'guard-nftables',
    commands: { nft: '/usr/sbin/nft' },
  };
  const rules = 'table inet nosh_guard {\n}\n';
  const runner = async (file, args) => ({
    code: 0,
    stdout: args.includes('nosh_guard') ? rules : '',
    stderr: '',
    file,
    args,
  });
  const baseline = await host.readGatewayLiveState({
    trust,
    state: { quarantine: null, liveStateDigest: null },
  }, runner);
  const recordedState = {
    quarantine: null,
    liveStateDigest: baseline.digest,
  };
  const healthy = await host.readGatewayLiveState({
    trust,
    state: recordedState,
  }, runner);
  assert.equal(healthy.matchesExpected, true);
  const deleted = await host.readGatewayLiveState({
    trust,
    state: recordedState,
  }, async (file, args) => ({
    code: args.includes('nosh_guard') ? 1 : 0,
    stdout: '',
    stderr: '',
    file,
    args,
  }));
  assert.equal(deleted.present, false);
  assert.equal(deleted.matchesExpected, false);
});

test('gateway rejects an intermediate symlink before reading policy leaf artifacts', async (t) => {
  const { host } = await modules();
  const temporary = fs.mkdtempSync(path.join(os.tmpdir(), 'nosh-gateway-tree-'));
  t.after(() => fs.rmSync(temporary, { recursive: true, force: true }));
  fs.chmodSync(temporary, 0o700);
  const outside = fs.mkdtempSync(path.join(os.tmpdir(), 'nosh-gateway-outside-'));
  t.after(() => fs.rmSync(outside, { recursive: true, force: true }));
  fs.chmodSync(outside, 0o700);
  fs.writeFileSync(path.join(outside, 'nftables.nft'), 'table inet x {}\n', {
    mode: 0o600,
  });
  fs.symlinkSync(outside, path.join(temporary, 'rendered'));
  await assert.rejects(host.assertTrustedPolicyLeafTree(temporary, {
    expectedUid: process.geteuid(),
    checkPathChain: false,
  }), /symlink/);

  await fsp.unlink(path.join(temporary, 'rendered'));
  await fsp.mkdir(path.join(temporary, 'rendered'), { mode: 0o700 });
  await fsp.writeFile(path.join(temporary, 'rendered', 'nftables.nft'), 'table inet x {}\n', {
    mode: 0o600,
  });
  const verified = await host.assertTrustedPolicyLeafTree(temporary, {
    expectedUid: process.geteuid(),
    checkPathChain: false,
  });
  assert.equal(verified.entries, 2);
});
