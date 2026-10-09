'use strict';

const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const test = require('node:test');
const { pathToFileURL } = require('node:url');

const appRoot = path.resolve(__dirname, '..');
const trustedUid = typeof process.geteuid === 'function' ? process.geteuid() : 0;

async function loadStore() {
  return import(
    pathToFileURL(path.join(appRoot, 'lib/guardd/net-profile-store.js')).href
  );
}

function tempDir(t) {
  const directory = fs.mkdtempSync(
    path.join(os.tmpdir(), 'nosh-net-profile-store-test-'),
  );
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  return directory;
}

function hash(content) {
  return `sha256:${crypto.createHash('sha256').update(content).digest('hex')}`;
}

function makeLearningEvidence(stateDir, options = {}) {
  const runId = options.runId || 'learn-one';
  const imageDigest = options.imageDigest || `sha256:${'a'.repeat(64)}`;
  const evidenceDir = path.join(stateDir, 'evidence', runId);
  fs.mkdirSync(evidenceDir, { recursive: true, mode: 0o700 });
  const sources = ['nosh-egress', 'nosh-exec'].map((name) => {
    const sourcePath = path.join(evidenceDir, `${name}.jsonl`);
    const source = Buffer.from(
      `${JSON.stringify({
        schemaVersion: 2,
        source: name,
        recordKind: 'stats',
        final: true,
      })}\n`,
    );
    fs.writeFileSync(sourcePath, source, { mode: 0o600 });
    return {
      name,
      path: sourcePath,
      format: 'ndjson',
      required: true,
      present: true,
      complete: options.complete ?? true,
      bytes: source.length,
      records: 1,
      hash: hash(source),
      lostEvents: options.lostEvents ?? 0,
      parseErrors: options.parseErrors ?? 0,
      completionMarker: 'clean-supervised-stop',
    };
  });
  const workspaceStat = options.workspace
    ? fs.statSync(options.workspace, { bigint: true })
    : null;
  const manifest = {
    schemaVersion: 1,
    apiVersion: 'notty.dev/v1alpha1',
    kind: 'NoshSecurityEvidenceManifest',
    generatedAt: '2026-08-08T00:00:00.000Z',
    runId,
    mode: 'egress-learn',
    subject: {
      containerId: 'container-one',
      containerName: 'nosh-test',
      image: 'nosh:test',
      imageDigest,
      workspace: options.workspace,
      workspaceIdentity: workspaceStat
        ? {
            dev: String(workspaceStat.dev),
            ino: String(workspaceStat.ino),
          }
        : null,
    },
    startedAt: '2026-08-08T00:00:00.000Z',
    endedAt: '2026-08-08T00:00:01.000Z',
    profileRevision: 'candidate',
    complete: options.complete ?? true,
    trainingEligible: true,
    evidenceUse: 'training',
    egressEvaluation: {
      schemaVersion: 1,
      backend: 'nosh-egress',
      policyHash: `sha256:${'b'.repeat(64)}`,
      wouldDenyCount: 0,
      deniedCount: 0,
      dnsWouldDenyCount: 0,
      dnsDeniedCount: 0,
      dnsEvaluationComplete: true,
      dnsEvaluationError: null,
      complete: true,
    },
    ebpfEgressEvaluation: {
      schemaVersion: 2,
      backend: 'nosh-egress',
      backendAbi: 'nosh-egress-v2',
      objectDigest: `sha256:${'c'.repeat(64)}`,
      policyDigest: `sha256:${'d'.repeat(64)}`,
      targetContextHash: `sha256:${'e'.repeat(64)}`,
      ruleIdMap: {},
      counts: { allow: 1, 'would-deny': 0, deny: 0 },
      decisionClasses: {
        'backend-deny': 0,
        'containment-deny': 0,
        'coverage-gap': 0,
        'dns-observation': 0,
        'infrastructure-allow': 0,
        observed: 1,
        'policy-allow': 0,
        'policy-deny': 0,
        'would-deny': 0,
      },
      fatalCounters: {
        decoderErrors: '0',
        ringbufDrops: '0',
        configInvalid: '0',
        dnsGrantFailures: '0',
        backendDenied: '0',
      },
      coverageCounters: {
        parseErrors: '0',
        fragments: '0',
        dnsTransactionMisses: '0',
        dnsUnsupported: '0',
        unsupportedProtocol: '0',
        coverageAllowed: '0',
        coverageWouldDeny: '0',
        coverageDenied: '0',
      },
      containmentDenied: '0',
      unresolved: [],
      eligible: true,
    },
    sources,
  };
  const manifestPath = path.join(evidenceDir, 'evidence-manifest.json');
  fs.writeFileSync(manifestPath, `${JSON.stringify(manifest, null, 2)}\n`, {
    mode: 0o600,
  });
  return {
    imageDigest,
    manifest,
    manifestPath,
    runId,
    sourcePath: sources.find((source) => source.name === 'nosh-egress').path,
  };
}

function candidateInput(stateDir, workdir, evidence, overrides = {}) {
  return {
    stateDir,
    trustedUid,
    workdir,
    runId: evidence.runId,
    imageDigest: evidence.imageDigest,
    imageReference: 'nosh:test',
    evidenceManifestPath: evidence.manifestPath,
    rules: [
      {
        destination: 'API.OPENAI.COM',
        protocol: 'TCP',
        ports: [443, 443],
      },
      {
        destination: 'api.openai.com',
        protocol: 'tcp',
        ports: [443],
      },
      {
        destination: '1.1.1.1',
        protocol: 'udp',
        ports: [53],
      },
    ],
    unresolvedObservations: [
      { protocol: 'any', reason: 'cannot represent protocol any' },
    ],
    launchConfig: {
      image: 'nosh:test',
      imageDigest: evidence.imageDigest,
      collab: false,
    },
    createdAt: '2026-08-08T00:01:00.000Z',
    ...overrides,
  };
}

test('canonical workspace keys use the physical path and avoid basename collisions', async (t) => {
  const root = tempDir(t);
  const first = path.join(root, 'one', 'project');
  const second = path.join(root, 'two', 'project');
  const alias = path.join(root, 'project-link');
  fs.mkdirSync(first, { recursive: true });
  fs.mkdirSync(second, { recursive: true });
  fs.symlinkSync(first, alias);
  const { canonicalWorkspace, workspaceKey } = await loadStore();

  assert.equal(await canonicalWorkspace(alias), fs.realpathSync(first));
  assert.equal(await workspaceKey(alias), await workspaceKey(first));
  assert.notEqual(await workspaceKey(first), await workspaceKey(second));
  assert.match(await workspaceKey(first), /^[a-f0-9]{64}$/);
});

test('candidate bundles are immutable, scoped, normalized, and registered', async (t) => {
  const root = tempDir(t);
  const stateDir = path.join(root, 'state');
  const workdir = path.join(root, 'workspace');
  fs.mkdirSync(workdir);
  const evidence = makeLearningEvidence(stateDir, { workspace: workdir });
  const {
    EGRESS_BUNDLE_FILES,
    NetProfileRegistry,
    createEgressCandidateBundle,
    verifyEgressCandidateBundle,
    workspaceKey,
  } = await loadStore();

  const candidate = await createEgressCandidateBundle(
    candidateInput(stateDir, workdir, evidence),
  );
  const key = await workspaceKey(workdir);
  assert.equal(
    candidate.directory,
    path.join(stateDir, 'profiles', 'net', key, evidence.runId),
  );
  assert.equal(candidate.profile.kind, 'NoshEgressProfile');
  assert.equal(candidate.profile.spec.launch.config.workload, 'dev');
  assert.equal(candidate.policy.kind, 'NoshEgressPolicy');
  assert.equal(candidate.manifest.kind, 'NoshEgressBundleManifest');
  assert.equal(candidate.profile.spec.workspace.canonicalPath, workdir);
  const workspaceStat = fs.statSync(workdir, { bigint: true });
  assert.equal(candidate.profile.spec.workspace.dev, String(workspaceStat.dev));
  assert.equal(candidate.profile.spec.workspace.ino, String(workspaceStat.ino));
  assert.deepEqual(candidate.workspaceIdentity, {
    dev: String(workspaceStat.dev),
    ino: String(workspaceStat.ino),
  });
  assert.equal(candidate.imageDigest, evidence.imageDigest);
  assert.deepEqual(candidate.rules, [
    { destination: '1.1.1.1/32', protocol: 'udp', ports: [53] },
    { destination: 'api.openai.com', protocol: 'tcp', ports: [443] },
  ]);
  assert.deepEqual(candidate.policy.spec.platformContainment, []);
  assert.deepEqual(candidate.policy.spec.unresolvedObservations, [
    { protocol: 'any', reason: 'cannot represent protocol any' },
  ]);
  for (const filename of [
    EGRESS_BUNDLE_FILES.profile,
    EGRESS_BUNDLE_FILES.policy,
    EGRESS_BUNDLE_FILES.manifest,
  ]) {
    assert.equal(fs.statSync(path.join(candidate.directory, filename)).mode & 0o777, 0o600);
  }
  const verified = await verifyEgressCandidateBundle(candidate.directory, {
    trustedRoot: path.join(stateDir, 'profiles', 'net'),
    trustedUid,
    workdir,
  });
  assert.equal(verified.ok, true);
  assert.equal(verified.rulesHash, candidate.rulesHash);

  const registry = new NetProfileRegistry({ stateDir, trustedUid });
  const workspace = await registry.readWorkspace(workdir);
  assert.equal(workspace.latestCandidate.runId, evidence.runId);
  assert.equal(workspace.approved, null);
  assert.deepEqual(workspace.audits, []);
  assert.equal(workspace.lastLaunch, null);

  await assert.rejects(
    createEgressCandidateBundle(candidateInput(stateDir, workdir, evidence)),
    /revision already exists/,
  );

  const nextEvidence = makeLearningEvidence(stateDir, {
    runId: 'learn-two',
    imageDigest: evidence.imageDigest,
    workspace: workdir,
  });
  const next = await createEgressCandidateBundle(
    candidateInput(stateDir, workdir, nextEvidence),
  );
  assert.notEqual(next.directory, candidate.directory);
  assert.equal(fs.existsSync(candidate.directory), true);
  assert.equal(
    (await registry.readWorkspace(workdir)).latestCandidate.runId,
    'learn-two',
  );
});

test('approval is explicit, write-once, and binds every candidate scope and hash', async (t) => {
  const root = tempDir(t);
  const stateDir = path.join(root, 'state');
  const workdir = path.join(root, 'workspace');
  fs.mkdirSync(workdir);
  const evidence = makeLearningEvidence(stateDir, {
    runId: 'approve-one',
    workspace: workdir,
  });
  const {
    NetProfileRegistry,
    approveEgressCandidateBundle,
    createEgressCandidateBundle,
    verifyEgressApprovalBundle,
  } = await loadStore();
  const candidate = await createEgressCandidateBundle(
    candidateInput(stateDir, workdir, evidence),
  );
  const trustedRoot = path.join(stateDir, 'profiles', 'net');

  await assert.rejects(
    approveEgressCandidateBundle(candidate.directory, {
      stateDir,
      trustedRoot,
      trustedUid,
    }),
    /explicit reviewer/,
  );
  const approved = await approveEgressCandidateBundle(candidate.directory, {
    stateDir,
    trustedRoot,
    trustedUid,
    workdir,
    reviewer: 'security-reviewer',
    revision: 'approved-one',
    approvedAt: '2026-08-08T00:02:00.000Z',
  });
  assert.equal(approved.ok, true);
  assert.equal(approved.revision, 'approved-one');
  assert.equal(approved.approval.reviewer, 'security-reviewer');
  assert.equal(approved.approval.scope, 'egress-only');
  assert.equal(approved.approval.contractVersion, 1);
  assert.equal(approved.approval.defaultDeny, true);
  assert.deepEqual(approved.approval.rules, candidate.rules);
  assert.deepEqual(approved.approval.limitations, [
    'ingress policy is not enforced',
    'Tetragon policy is not applied',
    'seccomp policy is not applied',
    'AppArmor policy is not applied',
    'stored launch settings are replay guidance, not an egress authorization boundary',
  ]);
  assert.equal(approved.approval.workspace, workdir);
  assert.equal(approved.approval.imageDigest, evidence.imageDigest);
  assert.equal(approved.approval.rulesHash, candidate.rulesHash);
  assert.deepEqual(
    Object.keys(approved.approval.artifacts).sort(),
    ['egress-policy.json', 'egress-profile.json', 'manifest.json'],
  );
  const runtime = await verifyEgressApprovalBundle(candidate.directory, {
    trustedRoot,
    trustedUid,
    workdir,
  });
  assert.equal(runtime.policyPath, path.join(candidate.directory, 'egress-policy.json'));
  assert.equal(runtime.policyHash, runtime.artifacts['egress-policy.json']);
  assert.deepEqual(runtime.rules, candidate.rules);

  const approvalPath = path.join(candidate.directory, 'egress-approval.json');
  const scopedApprovalSource = fs.readFileSync(approvalPath, 'utf8');
  const wrongApprovalKind = JSON.parse(scopedApprovalSource);
  wrongApprovalKind.kind = 'NoshSecurityProfileApproval';
  fs.writeFileSync(
    approvalPath,
    `${JSON.stringify(wrongApprovalKind, null, 2)}\n`,
    { mode: 0o600 },
  );
  await assert.rejects(
    verifyEgressApprovalBundle(candidate.directory, {
      trustedRoot,
      trustedUid,
      workdir,
    }),
    /approval identity|not canonical/,
  );
  fs.writeFileSync(approvalPath, scopedApprovalSource, { mode: 0o600 });

  const registry = new NetProfileRegistry({ stateDir, trustedUid });
  await registry.recordAudit(workdir, {
    runId: 'audit-one',
    wouldDenyCount: 0,
  });
  await Promise.all(
    ['audit-two', 'audit-three', 'audit-four'].map((runId) =>
      registry.recordAudit(workdir, { runId, wouldDenyCount: 0 }),
    ),
  );
  await registry.recordLastLaunch(workdir, {
    runId: 'enforce-one',
    mode: 'egress-enforce',
    revision: 'approved-one',
    profileDirectory: candidate.directory,
  });
  const workspace = await registry.readWorkspace(workdir);
  assert.equal(workspace.latestCandidate.runId, evidence.runId);
  assert.equal(workspace.approved.revision, 'approved-one');
  assert.equal(workspace.audits[0].runId, 'audit-one');
  assert.deepEqual(
    workspace.audits.map((audit) => audit.runId).sort(),
    ['audit-four', 'audit-one', 'audit-three', 'audit-two'],
  );
  assert.equal(workspace.lastLaunch.mode, 'egress-enforce');
  assert.equal(workspace.lastLaunch.profileDirectory, candidate.directory);

  await assert.rejects(
    approveEgressCandidateBundle(candidate.directory, {
      stateDir,
      trustedRoot,
      trustedUid,
      reviewer: 'second-reviewer',
    }),
    (error) => error.code === 'EEXIST',
  );
});

test('verification rejects tampering, symlinked bundles, and workspace mismatch', async (t) => {
  const root = tempDir(t);
  const stateDir = path.join(root, 'state');
  const workdir = path.join(root, 'workspace');
  const other = path.join(root, 'other-workspace');
  fs.mkdirSync(workdir);
  fs.mkdirSync(other);
  const evidence = makeLearningEvidence(stateDir, {
    runId: 'trust-one',
    workspace: workdir,
  });
  const {
    createEgressCandidateBundle,
    verifyEgressCandidateBundle,
  } = await loadStore();
  const candidate = await createEgressCandidateBundle(
    candidateInput(stateDir, workdir, evidence),
  );
  const trustedRoot = path.join(stateDir, 'profiles', 'net');
  const link = path.join(trustedRoot, candidate.workspaceKey, 'candidate-link');
  fs.symlinkSync(candidate.directory, link);

  await assert.rejects(
    verifyEgressCandidateBundle(link, { trustedRoot, trustedUid }),
    /must not contain symbolic links/,
  );
  await assert.rejects(
    verifyEgressCandidateBundle(candidate.directory, {
      trustedRoot,
      trustedUid,
      workdir: other,
    }),
    /different workspace/,
  );

  const replaced = path.join(root, 'original-workspace');
  fs.renameSync(workdir, replaced);
  fs.mkdirSync(workdir);
  await assert.rejects(
    verifyEgressCandidateBundle(candidate.directory, {
      trustedRoot,
      trustedUid,
      workdir,
    }),
    (error) => error.code === 'GUARD_EGRESS_WORKSPACE_IDENTITY_CHANGED',
  );
  fs.rmdirSync(workdir);
  fs.renameSync(replaced, workdir);

  const profilesDir = path.join(stateDir, 'profiles');
  fs.chmodSync(profilesDir, 0o770);
  await assert.rejects(
    verifyEgressCandidateBundle(candidate.directory, {
      trustedRoot,
      trustedUid,
    }),
    /owned by uid .*not group\/other-writable/,
  );
  fs.chmodSync(profilesDir, 0o700);

  fs.chmodSync(candidate.directory, 0o770);
  await assert.rejects(
    verifyEgressCandidateBundle(candidate.directory, {
      trustedRoot,
      trustedUid,
    }),
    /owned by uid .*not group\/other-writable/,
  );
  fs.chmodSync(candidate.directory, 0o700);

  const policyPath = path.join(candidate.directory, 'egress-policy.json');
  const policy = JSON.parse(fs.readFileSync(policyPath, 'utf8'));
  policy.spec.egress[0].ports = [5353];
  fs.writeFileSync(policyPath, `${JSON.stringify(policy, null, 2)}\n`, {
    mode: 0o600,
  });
  await assert.rejects(
    verifyEgressCandidateBundle(candidate.directory, {
      trustedRoot,
      trustedUid,
    }),
    /rules hash|artifact hash|cross-artifact/,
  );
});

test('candidate creation rejects incomplete or altered learning evidence', async (t) => {
  const root = tempDir(t);
  const stateDir = path.join(root, 'state');
  const workdir = path.join(root, 'workspace');
  fs.mkdirSync(workdir);
  const { createEgressCandidateBundle } = await loadStore();
  const legacy = makeLearningEvidence(stateDir, {
    runId: 'legacy-v1',
    workspace: workdir,
  });
  legacy.manifest.ebpfEgressEvaluation.schemaVersion = 1;
  legacy.manifest.ebpfEgressEvaluation.backendAbi = 'nosh-egress-v1';
  fs.writeFileSync(
    legacy.manifestPath,
    `${JSON.stringify(legacy.manifest, null, 2)}\n`,
    { mode: 0o600 },
  );
  await assert.rejects(
    createEgressCandidateBundle(candidateInput(stateDir, workdir, legacy)),
    /requires complete, resolved nosh-egress-v2 evidence/,
  );

  const incomplete = makeLearningEvidence(stateDir, {
    runId: 'incomplete',
    complete: false,
    workspace: workdir,
  });
  await assert.rejects(
    createEgressCandidateBundle(candidateInput(stateDir, workdir, incomplete)),
    /complete learn evidence manifest/,
  );

  const altered = makeLearningEvidence(stateDir, {
    runId: 'altered',
    workspace: workdir,
  });
  fs.appendFileSync(altered.sourcePath, '{"tampered":true}\n');
  await assert.rejects(
    createEgressCandidateBundle(candidateInput(stateDir, workdir, altered)),
    /source hash mismatch/,
  );

  const lost = makeLearningEvidence(stateDir, {
    runId: 'lost-events',
    lostEvents: 1,
    workspace: workdir,
  });
  await assert.rejects(
    createEgressCandidateBundle(candidateInput(stateDir, workdir, lost)),
    /reports lost events/,
  );

  const parseFailure = makeLearningEvidence(stateDir, {
    runId: 'parse-errors',
    parseErrors: 1,
    workspace: workdir,
  });
  await assert.rejects(
    createEgressCandidateBundle(candidateInput(
      stateDir,
      workdir,
      parseFailure,
    )),
    /reports parse errors/,
  );
});

test('candidate creation rejects a workspace replaced after learning', async (t) => {
  const root = tempDir(t);
  const stateDir = path.join(root, 'state');
  const workdir = path.join(root, 'workspace');
  const previous = path.join(root, 'workspace-during-learn');
  fs.mkdirSync(workdir);
  const evidence = makeLearningEvidence(stateDir, {
    runId: 'replaced-after-learn',
    workspace: workdir,
  });
  fs.renameSync(workdir, previous);
  fs.mkdirSync(workdir);
  const { createEgressCandidateBundle } = await loadStore();

  await assert.rejects(
    createEgressCandidateBundle(candidateInput(
      stateDir,
      workdir,
      evidence,
    )),
    (error) => error.code === 'GUARD_EGRESS_WORKSPACE_IDENTITY_CHANGED',
  );
});

test('private, local, multicast, and DNS transports remain reviewable candidate rules', async (t) => {
  const root = tempDir(t);
  const stateDir = path.join(root, 'state');
  const workdir = path.join(root, 'workspace');
  fs.mkdirSync(workdir);
  const evidence = makeLearningEvidence(stateDir, {
    runId: 'reviewable-special-use',
    workspace: workdir,
  });
  const {
    createEgressCandidateBundle,
    verifyEgressCandidateBundle,
  } = await loadStore();
  const candidate = await createEgressCandidateBundle(
    candidateInput(stateDir, workdir, evidence, {
      rules: [
        {
          destination: '192.168.1.65/32',
          protocol: 'tcp',
          ports: [9001],
          observations: [{
            address: '192.168.1.65',
            decision: {
              verdict: 'would-deny',
              decisionClass: 'would-deny',
              reason: 'default-deny',
              reasonCode: 5,
            },
          }],
        },
        {
          destination: '192.168.1.65/32',
          protocol: 'tcp',
          ports: [9001],
          observations: [{
            address: '192.168.1.65',
            decision: {
              verdict: 'allow',
              decisionClass: 'policy-allow',
              reason: 'exact-rule',
              reasonCode: 3,
            },
          }],
        },
        { destination: '127.0.0.1/32', protocol: 'tcp', ports: [9001] },
        { destination: '169.254.169.254/32', protocol: 'tcp', ports: [80] },
        { destination: '224.0.0.251/32', protocol: 'udp', ports: [5353] },
        { destination: '1.1.1.1/32', protocol: 'udp', ports: [53, 443, 853] },
        { destination: '9.9.9.9/32', protocol: 'tcp', ports: [53, 853] },
        { destination: 'fc00::1/128', protocol: 'tcp', ports: [9001] },
        { destination: 'ff02::fb/128', protocol: 'udp', ports: [5353] },
      ],
      unresolvedObservations: [],
    }),
  );
  const privateRule = candidate.rules.find(
    (rule) => rule.destination === '192.168.1.65/32',
  );
  assert.equal(privateRule.observations.length, 2);
  assert.deepEqual(
    new Set(privateRule.observations.map((entry) => entry.decision.verdict)),
    new Set(['allow', 'would-deny']),
  );
  assert.deepEqual(
    candidate.rules.map((rule) => rule.destination),
    [
      '1.1.1.1/32',
      '127.0.0.1/32',
      '169.254.169.254/32',
      '192.168.1.65/32',
      '224.0.0.251/32',
      '9.9.9.9/32',
      'fc00::1/128',
      'ff02::fb/128',
    ],
  );
  assert.deepEqual(candidate.policy.spec.platformContainment, []);
  const verified = await verifyEgressCandidateBundle(candidate.directory, {
    trustedRoot: path.join(stateDir, 'profiles', 'net'),
    trustedUid,
    workdir,
  });
  assert.equal(verified.ok, true);
  assert.equal(verified.rulesHash, candidate.rulesHash);
});

test('registry recovers an identity-checked stale interprocess lock', async (t) => {
  const root = tempDir(t);
  const stateDir = path.join(root, 'state');
  const workdir = path.join(root, 'workspace');
  fs.mkdirSync(workdir);
  const { NetProfileRegistry } = await loadStore();
  const registry = new NetProfileRegistry({ stateDir, trustedUid });
  await registry.initialize();
  const lockDir = path.join(stateDir, 'profiles', 'net', '.workspaces-dev.lock');
  fs.mkdirSync(lockDir, { mode: 0o700 });
  fs.writeFileSync(
    path.join(lockDir, 'owner.json'),
    `${JSON.stringify({
      acquiredAt: '2000-01-01T00:00:00.000Z',
      pid: process.pid,
      processStartIdentity: 'not-the-current-process',
      token: 'abandoned-lock',
    }, null, 2)}\n`,
    { mode: 0o600 },
  );
  const stale = new Date(Date.now() - 60_000);
  fs.utimesSync(lockDir, stale, stale);

  await registry.recordAudit(workdir, {
    runId: 'after-stale-lock',
    wouldDenyCount: 0,
  });
  assert.equal(fs.existsSync(lockDir), false);
  assert.equal(
    (await registry.readWorkspace(workdir)).audits[0].runId,
    'after-stale-lock',
  );
});

test('runtime-only review binds a subject and freezes literal DNS-associated endpoints', async t => {
  const root = tempDir(t);
  const stateDir = path.join(root, 'state');
  const workdir = path.join(root, 'workspace');
  fs.mkdirSync(workdir);
  const evidence = makeLearningEvidence(stateDir, { workspace: workdir });
  const { createEgressCandidateBundle } = await loadStore();
  const candidate = await createEgressCandidateBundle(candidateInput(stateDir, workdir, evidence, {
    unresolvedObservations: [],
    rules: [{ destination: 'api.example.test', protocol: 'tcp', ports: [443], observations: [{
      address: '203.0.113.5', dnsNames: ['api.example.test'],
      decision: { destinationAddress: '203.0.113.5', destinationPort: 443,
        hook: 1, protocol: 6, decisionClass: 'would-deny' },
    }] }],
  }));
  const { createBuildReviewArtifact } = await import('../lib/guard/review/review-service.js');
  const artifact = await createBuildReviewArtifact({ runtimeCandidate: candidate.directory, requireSbom: false });
  assert.equal(artifact.graph.scope.class, 'runtime');
  assert.equal(artifact.graph.scope.imageDigest, evidence.imageDigest);
  assert.ok(artifact.graph.nodes.some(node => node.id === artifact.graph.scope.subjectId));
  assert.equal(artifact.graph.proposals[0].intent.peer.value, '203.0.113.5/32');
  assert.equal(artifact.graph.proposals[0].intent.peer.kind, 'ipv4-cidr');
  const endpoint = artifact.graph.nodes.find(node => node.nodeType === 'networkEndpoint');
  assert.deepEqual(endpoint.properties.runtimeEvidence[0].dnsNames, ['api.example.test']);
  const { writeReviewBundleArtifact } = await import('../lib/guard/review/bundle-store.js');
  const { createDecisionSet } = await import('../lib/guard/review/documents.js');
  const { prepareReviewSession, snapshotReviewSelection, atomicSessionJson, checkReviewSession, migrateReviewDraft } = await import('../lib/guard/review/session.js');
  const sessionDir = path.join(root, 'review-session');
  for (const directory of [sessionDir, path.join(sessionDir, 'runtime'), path.join(sessionDir, 'decisions')]) {
    fs.mkdirSync(directory, { mode: 0o700 });
  }
  const bundleDir = path.join(sessionDir, 'bundle');
  await writeReviewBundleArtifact(bundleDir, artifact);
  const session = await prepareReviewSession({ session: sessionDir, bundle: bundleDir,
    candidate: candidate.directory, workdir, launcher: '/repo/scripts/nosh.sh',
    tooling: `sha256:${'a'.repeat(64)}`, context: path.join(candidate.directory, 'context.json'),
    applyConfig: '/config/apply.json', configAvailable: 'no' });
  assert.equal(session.runtimeCandidate, candidate.directory);
  assert.ok(session.preflight.some(message => /SBOM/.test(message)));
  const readiness = await checkReviewSession(sessionDir);
  assert.equal(readiness.readyForReview, false);
  assert.equal(readiness.readyForApply, false);
  assert.ok(readiness.blockers.some(blocker => blocker.code === 'inventory'));
  const staleReadiness = await checkReviewSession(sessionDir, null, path.join(root, 'unavailable-source.spdx.json'));
  assert.equal(staleReadiness.readyForApply, false);
  assert.ok(staleReadiness.blockers.some(blocker => blocker.code === 'source-inventory'));
  const decisions = createDecisionSet({ graph: artifact.graph, reviewer: 'Operator',
    decisions: artifact.graph.proposals.map(proposal => ({ proposalId: proposal.id,
      disposition: 'accept', rationale: 'Required endpoint', targetAcknowledgements: [] })) });
  await atomicSessionJson(path.join(sessionDir, 'decisions', 'decisions.json'), decisions);
  await assert.rejects(snapshotReviewSelection(sessionDir, `sha256:${'f'.repeat(64)}`, path.join(root, 'apply')), /Saved decisions changed/);
  await assert.rejects(snapshotReviewSelection(sessionDir, decisions.contentDigest, path.join(root, 'apply')), /missing.*sbom/i);

  // A tooling rebuild may produce the exact same graph. Restore its reviewed
  // choices without carrying approval or finalization into the new session.
  const updatedDir = path.join(root, 'updated-tooling-session');
  for (const directory of [updatedDir, path.join(updatedDir, 'runtime'), path.join(updatedDir, 'decisions')]) {
    fs.mkdirSync(directory, { mode: 0o700 });
  }
  await writeReviewBundleArtifact(path.join(updatedDir, 'bundle'), artifact);
  await prepareReviewSession({ session: updatedDir, bundle: path.join(updatedDir, 'bundle'),
    candidate: candidate.directory, workdir, launcher: '/repo/scripts/nosh.sh',
    tooling: `sha256:${'b'.repeat(64)}`, context: path.join(candidate.directory, 'context.json'),
    applyConfig: '/config/apply.json', configAvailable: 'no' });
  const restored = await migrateReviewDraft(updatedDir);
  assert.equal(restored.status, 'migrated');
  assert.equal(restored.source, sessionDir);
  const draft = JSON.parse(fs.readFileSync(path.join(updatedDir, 'decisions/draft.json'), 'utf8'));
  assert.equal(draft.graphContentDigest, artifact.graph.contentDigest);
  assert.equal(draft.reviewerAcknowledged, false);
  assert.equal(draft.decisions[artifact.graph.proposals[0].id].disposition, 'accept');
  assert.deepEqual(draft.decisions[artifact.graph.proposals[0].id].targetAcknowledgements, {});
  assert.equal(fs.existsSync(path.join(updatedDir, 'decisions/decisions.json')), false);
  assert.equal(JSON.parse(fs.readFileSync(path.join(sessionDir, 'decisions/decisions.json'), 'utf8')).contentDigest, decisions.contentDigest);
});
