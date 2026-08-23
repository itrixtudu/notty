'use strict';

const assert = require('node:assert/strict');
const childProcess = require('node:child_process');
const crypto = require('node:crypto');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const test = require('node:test');

async function loadGuard() {
  return import('../lib/guard/index.js');
}

function fixtureEvents() {
  return [
    {
      schemaVersion: 1,
      source: { kind: 'tetragon', name: 'tetragon', version: '1.7.0' },
      runId: 'run-42',
      observedAt: '2026-07-20T10:00:00Z',
      container: {
        id: 'container-123',
        name: 'nosh-dev',
        image: 'nosh:test',
        imageDigest: 'sha256:image',
      },
      event: {
        type: 'process.exec',
        executable: '/usr/bin/node',
        parentExecutable: '/usr/bin/tmux',
        arguments: ['node', '--token=do-not-retain'],
      },
    },
    {
      schemaVersion: 1,
      source: { kind: 'tetragon', name: 'tetragon', version: '1.7.0' },
      runId: 'run-42',
      observedAt: '2026-07-20T10:00:02Z',
      container: { id: 'container-123', name: 'nosh-dev', image: 'nosh:test' },
      event: {
        type: 'syscall',
        name: '__x64_sys_read',
        architecture: 'SCMP_ARCH_X86_64',
      },
    },
    {
      schemaVersion: 1,
      source: { kind: 'tetragon', name: 'tetragon', version: '1.7.0' },
      runId: 'run-42',
      event: {
        type: 'syscall',
        name: 'write',
        architecture: 'SCMP_ARCH_X86_64',
      },
    },
    {
      schemaVersion: 1,
      source: { kind: 'tetragon', name: 'tetragon', version: '1.7.0' },
      runId: 'run-42',
      event: {
        type: 'file',
        operation: 'read',
        path: '/workspace/package.json',
      },
    },
    {
      schemaVersion: 1,
      source: { kind: 'tetragon', name: 'tetragon', version: '1.7.0' },
      runId: 'run-42',
      event: {
        type: 'network',
        direction: 'egress',
        protocol: 'tcp',
        dnsName: 'api.openai.com.',
        port: 443,
      },
    },
    {
      schemaVersion: 1,
      source: { kind: 'ig', name: 'advise_seccomp', version: '0.54.1' },
      runId: 'run-42',
      event: {
        type: 'recommendation',
        domain: 'seccomp',
        action: 'allow',
        value: { syscalls: ['mount', 'ptrace'] },
      },
    },
  ];
}

const TEST_IMAGE_DIGEST = `sha256:${'a'.repeat(64)}`;
const TEST_CONTAINER_ID = 'b'.repeat(64);
const TEST_CONTAINER = Object.freeze({
  id: TEST_CONTAINER_ID,
  name: 'nosh-fixture',
  image: 'nosh:fixture',
  imageDigest: TEST_IMAGE_DIGEST,
});

function hashBytes(bytes) {
  return `sha256:${crypto.createHash('sha256').update(bytes).digest('hex')}`;
}

function writeAuditRun(root, runId, options = {}) {
  const runDirectory = path.join(root, options.directoryName || runId);
  fs.mkdirSync(runDirectory, { recursive: true });
  const sourceContainer = {
    ...TEST_CONTAINER,
    imageDigest: options.imageDigest || TEST_IMAGE_DIGEST,
  };
  const sourceRecords = {
    'tetragon-events': [
      {
        schemaVersion: 1,
        source: { kind: 'tetragon', name: 'tetragon' },
        runId,
        observedAt: '2026-07-25T12:00:01.000Z',
        container: sourceContainer,
        event: {
          type: 'process.exec',
          executable: '/usr/bin/node',
          parentExecutable: '/bin/sh',
        },
      },
      {
        schemaVersion: 1,
        source: { kind: 'tetragon', name: 'tetragon' },
        runId,
        observedAt: '2026-07-25T12:00:02.000Z',
        container: sourceContainer,
        event: {
          type: 'syscall',
          name: 'read',
          architecture: 'SCMP_ARCH_X86_64',
        },
      },
      {
        schemaVersion: 1,
        source: { kind: 'tetragon', name: 'tetragon' },
        runId,
        observedAt: '2026-07-25T12:00:03.000Z',
        container: sourceContainer,
        event: {
          type: 'file',
          operation: 'read',
          path: '/workspace/package.json',
        },
      },
    ],
    'ig-dns': [{
      name: 'api.openai.com.',
      src: { addr: '10.240.8.3', port: 45000, proto: 17 },
      dst: { addr: '10.240.8.2', port: 53, proto: 17 },
      timestamp: '2026-07-25T12:00:04.000Z',
    }],
    'ig-syscalls': [{
      defaultAction: 'SCMP_ACT_ERRNO',
      architectures: ['SCMP_ARCH_X86_64'],
      syscalls: [{
        names: ['mount', 'read'],
        action: 'SCMP_ACT_ALLOW',
      }],
    }],
    'nosh-l4': [{
      observedAt: '2026-07-25T12:00:05.000Z',
      network: {
        direction: 'egress',
        protocol: 'tcp',
        destinationAddress: '104.18.7.192',
        destinationPort: 443,
      },
      sensorDecision: { verdict: 'allow', observedOnly: true },
    }],
    managed_dns: [{
      observedAt: '2026-07-25T12:00:04.050Z',
      qname: 'api.openai.com',
      answer: '104.18.7.192',
      decision: 'allowed',
    }],
    managed_gateway: [
      {
        type: 'policy_attestation',
        runId,
        policyRevision: 'candidate-1',
      },
      {
        runId,
        observedAt: '2026-07-25T12:00:05.050Z',
        direction: 'egress',
        protocol: 'tcp',
        destinationAddress: '104.18.7.192',
        destinationPort: 443,
        dnsName: 'api.openai.com',
        decision: options.wouldDeny ? 'would-deny' : 'allowed',
      },
    ],
  };
  if (options.reverseTetragonRecords) {
    sourceRecords['tetragon-events'].reverse();
  }
  const sources = [];
  for (const [name, records] of Object.entries(sourceRecords)) {
    const fileName = `${name}.jsonl`;
    const content = Buffer.from(
      `${records.map((record) => JSON.stringify(record)).join('\n')}\n`,
      'utf8',
    );
    fs.writeFileSync(path.join(runDirectory, fileName), content);
    sources.push({
      name,
      path: fileName,
      format: name === 'ig-syscalls' ? 'ig-seccomp-advice' : 'ndjson',
      required: true,
      present: true,
      bytes: content.length,
      records: records.length,
      hash: hashBytes(content),
      lostEvents: options.lostSource === name ? 1 : 0,
      parseErrors: 0,
      completionMarker: name === 'ig-syscalls'
        ? 'advisor-profile-flushed'
        : name === 'nosh-l4'
          ? 'final-stats-clean'
          : name === 'managed_gateway'
            ? 'policy-attested'
            : 'clean-supervised-stop',
      complete: options.incompleteSource === name ? false : true,
    });
  }
  const selected = (name) => sources.find((source) => source.name === name);
  if (options.badHashSource) {
    selected(options.badHashSource).hash = `sha256:${'f'.repeat(64)}`;
  }
  if (options.missingHashSource) {
    selected(options.missingHashSource).hash = null;
  }
  if (options.escapeSource) {
    selected(options.escapeSource).path = '../outside.jsonl';
  }
  const manifest = {
    schemaVersion: 1,
    apiVersion: 'notty.dev/v1alpha1',
    kind: 'NoshSecurityEvidenceManifest',
    generatedAt: '2026-07-25T12:05:01.000Z',
    runId,
    mode: options.mode || 'audit',
    subject: {
      containerId: TEST_CONTAINER_ID,
      containerName: TEST_CONTAINER.name,
      image: TEST_CONTAINER.image,
      imageDigest: options.imageDigest || TEST_IMAGE_DIGEST,
    },
    startedAt: '2026-07-25T12:00:00.000Z',
    endedAt: '2026-07-25T12:05:00.000Z',
    profileRevision: 'candidate-1',
    ...(options.auditEvaluation
      ? { auditEvaluation: options.auditEvaluation }
      : {}),
    complete: options.incompleteManifest !== true,
    sources: options.reverseSources ? sources.reverse() : sources,
  };
  const manifestPath = path.join(runDirectory, 'evidence-manifest.json');
  fs.writeFileSync(manifestPath, `${JSON.stringify(manifest, null, 2)}\n`);
  return manifestPath;
}

function replaceManifestSourceRecords(manifestPath, sourceName, records) {
  const manifest = JSON.parse(fs.readFileSync(manifestPath, 'utf8'));
  const descriptor = manifest.sources.find((source) => source.name === sourceName);
  assert.ok(descriptor, `missing source descriptor ${sourceName}`);
  const content = Buffer.from(
    `${records.map((record) => JSON.stringify(record)).join('\n')}\n`,
    'utf8',
  );
  fs.writeFileSync(path.join(path.dirname(manifestPath), descriptor.path), content);
  descriptor.bytes = content.length;
  descriptor.records = records.length;
  descriptor.hash = hashBytes(content);
  fs.writeFileSync(manifestPath, `${JSON.stringify(manifest, null, 2)}\n`);
}

function reviewedTetragonOptions() {
  return {
    reviewedEnforcement: true,
    enforcementRules: {
      lsmhooks: [{
        hook: 'file_open',
        args: [{ index: 0, type: 'file' }],
        selectors: [{
          matchNamespaces: [{
            namespace: 'Cgroup',
            operator: 'In',
            values: ['{cgroupNamespace}'],
          }],
          matchActions: [{ action: 'Override', argError: -13 }],
        }],
      }],
    },
  };
}

const AUDIT_BACKEND_ARTIFACTS = {
  tetragon: 'tetragon.yaml',
  seccomp: 'seccomp.json',
  apparmor: 'apparmor.profile',
  docker: 'docker.json',
  network: 'network-policy.yaml',
};

function completeAuditEvaluation(artifactHashes, backendOverrides = {}) {
  return {
    schemaVersion: 1,
    candidateArtifacts: Object.fromEntries(
      Object.values(AUDIT_BACKEND_ARTIFACTS).map((filename) => [
        filename,
        artifactHashes[filename],
      ]),
    ),
    backends: Object.fromEntries(
      Object.keys(AUDIT_BACKEND_ARTIFACTS).map((backend) => [
        backend,
        {
          evaluator: `test-${backend}`,
          complete: true,
          wouldDenyCount: 0,
          reason: null,
          ...(backendOverrides[backend] || {}),
        },
      ]),
    ),
  };
}

async function bindAuditManifests(
  manifests,
  compilerOptions = {},
  backendOverridesByRun = {},
) {
  const { compileGuardProfile, loadEvidenceInputs } = await loadGuard();
  const loaded = await loadEvidenceInputs(manifests);
  const provisional = compileGuardProfile(loaded.records, {
    ...compilerOptions,
    runProvenance: loaded.runProvenance,
    ingestion: loaded.ingestion,
  });
  const artifactHashes = Object.fromEntries(
    Object.entries(AUDIT_BACKEND_ARTIFACTS).map(([backend, filename]) => [
      filename,
      provisional.artifacts[backend].hash,
    ]),
  );
  for (const manifestPath of manifests) {
    const manifest = JSON.parse(fs.readFileSync(manifestPath, 'utf8'));
    manifest.auditEvaluation = completeAuditEvaluation(
      artifactHashes,
      backendOverridesByRun[manifest.runId],
    );
    fs.writeFileSync(
      manifestPath,
      `${JSON.stringify(manifest, null, 2)}\n`,
    );
  }
  return artifactHashes;
}

test('normalizes evidence deterministically and keeps IG advice out of observations', async () => {
  const { normalizeEvidence } = await loadGuard();
  const forward = normalizeEvidence(fixtureEvents());
  const reverse = normalizeEvidence(fixtureEvents().reverse());

  assert.deepEqual(forward, reverse);
  assert.equal(forward.apiVersion, 'notty.dev/v1alpha1');
  assert.equal(forward.kind, 'NoshSecurityEvidence');
  assert.equal(forward.subject.containerId, 'container-123');
  assert.equal(forward.subject.identityUse, 'provenance-only');
  assert.deepEqual(
    forward.observations.syscalls.map((entry) => entry.name),
    ['read', 'write'],
  );
  assert.equal(forward.advisoryEvidence.length, 1);
  assert.equal(forward.advisoryEvidence[0].policyUse, 'evidence-only');
  assert.doesNotMatch(JSON.stringify(forward), /do-not-retain/);
  assert.equal(
    forward.observations.syscalls.some((entry) => ['mount', 'ptrace'].includes(entry.name)),
    false,
  );
  assert.equal(
    forward.provenance.find((entry) => entry.source.kind === 'ig').policyUse,
    'evidence-only',
  );
});

test('normalizes raw Tetragon envelopes and multiline Inspektor Gadget advice', async () => {
  const { normalizeEvidence } = await loadGuard();
  const tetragon = normalizeEvidence({
    process_kprobe: {
      function_name: '__x64_sys_connect',
      syscall: true,
      process: {
        binary: '/usr/bin/node',
        docker: 'abc',
      },
      args: [{
        sock_arg: {
          address: '203.0.113.10',
          port: 443,
          protocol: 'TCP',
        },
      }],
    },
  });
  assert.deepEqual(
    tetragon.observations.syscalls.map((entry) => entry.name),
    ['connect'],
  );
  assert.deepEqual(tetragon.observations.network[0], {
    address: '203.0.113.10',
    count: 1,
    direction: 'egress',
    port: 443,
    protocol: 'tcp',
  });

  const advice = normalizeEvidence([
    '// container: nosh-dev',
    '{',
    '  "defaultAction": "SCMP_ACT_ERRNO",',
    '  "syscalls": [{"names": ["mount"], "action": "SCMP_ACT_ALLOW"}]',
    '}',
  ].join('\n'));
  assert.equal(advice.observations.syscalls.length, 0);
  assert.equal(advice.advisoryEvidence.length, 1);
  assert.equal(advice.advisoryEvidence[0].domain, 'seccomp');
  assert.equal(advice.advisoryEvidence[0].policyUse, 'evidence-only');
});

test('compiles deterministic independent candidates with hashes and review gates', async () => {
  const {
    compileGuardProfile,
    normalizeEvidence,
  } = await loadGuard();
  const evidence = normalizeEvidence(fixtureEvents());
  const first = compileGuardProfile(evidence, {
    role: 'coding-agent',
    architecture: 'x64',
    kernel: '6.8.0',
  });
  const second = compileGuardProfile(evidence, {
    role: 'coding-agent',
    architecture: 'x64',
    kernel: '6.8.0',
  });

  assert.deepEqual(first, second);
  assert.equal(first.status, 'candidate');
  assert.equal(first.profile.apiVersion, 'notty.dev/v1alpha1');
  assert.equal(first.profile.kind, 'NoshSecurityProfile');
  assert.equal(first.profile.spec.lifecycle.phase, 'candidate');
  assert.equal(first.profile.spec.lifecycle.reviewRequired, true);
  assert.equal(first.profile.spec.lifecycle.automaticApply, false);
  assert.equal(first.profile.spec.lifecycle.sensorOutputAuthoritative, false);
  assert.equal(first.profile.spec.lifecycle.enforcementReady, false);
  assert.equal(first.profile.spec.target.role, 'coding-agent');
  assert.equal(first.profile.spec.target.architecture, 'x64');
  assert.deepEqual(
    Object.keys(first.artifacts).sort(),
    ['apparmor', 'docker', 'network', 'seccomp', 'tetragon'],
  );
  for (const [name, artifact] of Object.entries(first.artifacts)) {
    assert.match(artifact.hash, /^sha256:[a-f0-9]{64}$/);
    assert.equal(first.profile.spec.artifacts[name].hash, artifact.hash);
    assert.equal(artifact.status, 'candidate');
    assert.deepEqual(artifact.errors, []);
  }
  assert.equal(first.artifacts.tetragon.content.spec.options[0].value, 'monitor');
  assert.deepEqual(
    first.artifacts.tetragon.content.spec.kprobes.map((entry) => entry.call),
    ['sys_connect', 'sys_execve', 'sys_openat', 'sys_read', 'sys_write'],
  );
  assert.equal(first.artifacts.tetragon.enforceable, false);
  assert.match(
    first.artifacts.tetragon.warnings.join('\n'),
    /monitor-only/,
  );
  assert.deepEqual(
    first.artifacts.seccomp.content.syscalls[0].names,
    ['read', 'write'],
  );
  assert.deepEqual(
    first.artifacts.seccomp.content.architectures,
    ['SCMP_ARCH_X86_64'],
  );
  assert.doesNotMatch(
    JSON.stringify(first.artifacts.seccomp.content),
    /mount|ptrace/,
  );
  assert.equal(first.artifacts.network.content.spec.egress[0].destination, 'api.openai.com');
});

test('artifact validators operate independently and identify unsafe mutations', async () => {
  const {
    compileGuardProfile,
    validateAppArmorArtifact,
    validateDockerArtifact,
    validateNetworkArtifact,
    validateSeccompArtifact,
    validateTetragonArtifact,
  } = await loadGuard();
  const result = compileGuardProfile(fixtureEvents());

  const tetragon = structuredClone(result.artifacts.tetragon.content);
  tetragon.spec.options[0].value = 'enforce';
  assert.equal(validateTetragonArtifact(tetragon).valid, false);

  const seccomp = structuredClone(result.artifacts.seccomp.content);
  seccomp.defaultAction = 'SCMP_ACT_ALLOW';
  assert.equal(validateSeccompArtifact(seccomp).valid, false);

  const docker = structuredClone(result.artifacts.docker.content);
  docker.spec.runArgs = docker.spec.runArgs.filter(
    (argument) => argument !== '--cap-drop=ALL',
  );
  assert.equal(validateDockerArtifact(docker).valid, false);

  const network = structuredClone(result.artifacts.network.content);
  network.spec.defaultDeny.egress = false;
  assert.equal(validateNetworkArtifact(network).valid, false);

  const apparmor = `${result.artifacts.apparmor.content}\n/** rwix,\n`;
  assert.equal(validateAppArmorArtifact(apparmor).valid, false);

  assert.equal(validateSeccompArtifact(result.artifacts.seccomp.content).valid, true);
  assert.equal(validateNetworkArtifact(result.artifacts.network.content).valid, true);
});

test('network artifact uses the external egress manager rule contract', async () => {
  const { compileGuardProfile } = await loadGuard();
  const { normalizeEgressPolicy } = await import('../lib/guardd/egress-policy.js');
  const result = compileGuardProfile(fixtureEvents());
  const policy = normalizeEgressPolicy({
    runId: 'run-42',
    mode: 'enforce',
    profileRevision: 'candidate',
    networkName: 'nosh-guard-run-42',
    sourceIpv4: '10.240.0.3',
    gatewayIpv4: '10.240.0.2',
    egress: result.artifacts.network.content.spec.egress,
  });

  assert.equal(policy.rules.length, 1);
  assert.equal(policy.rules[0].destination.kind, 'fqdn');
  assert.equal(policy.rules[0].destination.value, 'api.openai.com');
  assert.equal(policy.rules[0].protocol, 'tcp');
  assert.deepEqual(policy.rules[0].ports, [443]);
});

test('managed DNS answers correlate scoped L4 flows into conservative FQDN rules', async () => {
  const { compileNetworkArtifact } = await loadGuard();
  const container = {
    id: TEST_CONTAINER_ID,
    name: 'nosh-fixture',
    image: 'nosh:fixture',
    imageDigest: TEST_IMAGE_DIGEST,
  };
  const record = (source, event, observedAt, recordContainer = container) => ({
    schemaVersion: 1,
    source,
    runId: 'scoped-learn',
    observedAt,
    container: recordContainer,
    event: { type: 'network', direction: 'egress', ...event },
  });
  const managedDns = { kind: 'managed_dns', name: 'managed-resolver' };
  const noshL4 = { kind: 'nosh_l4', name: 'docker-network' };
  const correlated = compileNetworkArtifact([
    record(managedDns, {
      protocol: 'any',
      address: '203.0.113.9',
      dnsName: 'api.example.com',
    }, '2026-07-25T12:00:00.000Z'),
    record(noshL4, {
      protocol: 'tcp',
      address: '203.0.113.9',
      port: 443,
    }, '2026-07-25T12:00:01.000Z'),
  ]);
  assert.deepEqual(correlated.spec.egress, [{
    destination: 'api.example.com',
    protocol: 'tcp',
    ports: [443],
  }]);
  assert.deepEqual(correlated.spec.unresolvedObservations, []);

  const ambiguous = compileNetworkArtifact([
    record(managedDns, {
      protocol: 'any',
      address: '203.0.113.10',
      dnsName: 'one.example.com',
    }, '2026-07-25T12:00:00.100Z'),
    record(managedDns, {
      protocol: 'any',
      address: '203.0.113.10',
      dnsName: 'two.example.com',
    }, '2026-07-25T12:00:00.200Z'),
    record(noshL4, {
      protocol: 'tcp',
      address: '203.0.113.10',
      port: 443,
    }, '2026-07-25T12:00:01.000Z'),
  ]);
  assert.deepEqual(ambiguous.spec.egress, []);
  assert.equal(ambiguous.spec.unresolvedObservations.length, 1);
  assert.match(
    ambiguous.spec.unresolvedObservations[0].reason,
    /shared by multiple DNS names/,
  );

  const staleOrWrongContainer = compileNetworkArtifact([
    record(managedDns, {
      protocol: 'any',
      address: '203.0.113.11',
      dnsName: 'stale.example.com',
    }, '2026-07-25T12:00:00.000Z'),
    record(managedDns, {
      protocol: 'any',
      address: '203.0.113.11',
      dnsName: 'other-container.example.com',
    }, '2026-07-25T12:00:02.000Z', {
      ...container,
      id: 'c'.repeat(64),
    }),
    record(managedDns, {
      protocol: 'any',
      address: '203.0.113.11',
      dnsName: 'unstamped.example.com',
    }, undefined),
    record(noshL4, {
      protocol: 'tcp',
      address: '203.0.113.11',
      port: 443,
    }, '2026-07-25T12:00:02.000Z'),
  ]);
  assert.deepEqual(staleOrWrongContainer.spec.egress, []);
  assert.equal(staleOrWrongContainer.spec.unresolvedObservations.length, 1);
  assert.match(
    staleOrWrongContainer.spec.unresolvedObservations[0].reason,
    /no managed DNS answer matched.*1000ms window/,
  );
});

test('only explicit reviewed and scoped Tetragon rules become enforce-capable', async () => {
  const {
    compileTetragonArtifact,
    normalizeEvidence,
    validateTetragonArtifact,
  } = await loadGuard();
  const evidence = normalizeEvidence(fixtureEvents());
  const operatorRule = {
    lsmhooks: [{
      hook: 'file_open',
      args: [{ index: 0, type: 'file' }],
      selectors: [{
        matchNamespaces: [{
          namespace: 'Cgroup',
          operator: 'In',
          values: ['{cgroupNamespace}'],
        }],
        matchActions: [{
          action: 'Override',
          argError: -13,
        }],
      }],
    }],
  };

  const ignored = compileTetragonArtifact(evidence, {
    tetragon: { enforcementRules: operatorRule },
  });
  assert.equal(validateTetragonArtifact(ignored).enforceable, false);

  const candidate = compileTetragonArtifact(evidence, {
    tetragon: {
      reviewedEnforcement: true,
      enforcementRules: operatorRule,
    },
  });
  const validation = validateTetragonArtifact(candidate);
  assert.equal(validation.valid, true);
  assert.equal(validation.enforceable, true);
  assert.equal(candidate.spec.options[0].value, 'monitor');

  candidate.spec.lsmhooks[0].selectors[0].matchNamespaces[0].values = [
    '12345',
  ];
  assert.equal(validateTetragonArtifact(candidate).valid, false);
});

test('generates deterministic JSON and static escaped HTML reports', async () => {
  const {
    compileGuardProfile,
    createProfileReport,
    generateHtmlReport,
    generateJsonReport,
  } = await loadGuard();
  const result = compileGuardProfile(fixtureEvents(), {
    name: 'nosh<script>alert(1)</script>',
  });
  const report = createProfileReport(result);
  const json = generateJsonReport(result);
  const html = generateHtmlReport(result);

  assert.deepEqual(JSON.parse(json), report);
  assert.equal(generateJsonReport(result), json);
  assert.match(html, /Content-Security-Policy/);
  assert.match(html, /Observed sensor output is evidence, not approval/);
  assert.doesNotMatch(html, /<script>alert/);
  assert.doesNotMatch(html, /<script\b/);
  assert.match(html, /Enforcement ready: no/);
});

test('writes the fixed candidate bundle without overwriting and hashes every payload', async (t) => {
  const {
    compileGuardProfile,
    writeCompiledProfile,
  } = await loadGuard();
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'notty-guard-compiler-'));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const outputDir = path.join(root, 'candidate');
  const result = compileGuardProfile(fixtureEvents());
  const written = writeCompiledProfile(outputDir, result);
  const expected = [
    'apparmor.profile',
    'docker.json',
    'manifest.json',
    'network-policy.yaml',
    'profile.yaml',
    'report.html',
    'report.json',
    'seccomp.json',
    'tetragon.yaml',
  ];

  assert.deepEqual(
    written.files.map((filePath) => path.basename(filePath)),
    expected,
  );
  assert.equal(JSON.parse(fs.readFileSync(path.join(outputDir, 'profile.yaml'))).kind, 'NoshSecurityProfile');
  assert.equal(JSON.parse(fs.readFileSync(path.join(outputDir, 'network-policy.yaml'))).kind, 'NoshNetworkPolicy');
  assert.equal(JSON.parse(fs.readFileSync(path.join(outputDir, 'tetragon.yaml'))).kind, 'TracingPolicy');
  for (const [fileName, entry] of Object.entries(written.manifest.files)) {
    const bytes = fs.readFileSync(path.join(outputDir, fileName));
    const hash = `sha256:${crypto.createHash('sha256').update(bytes).digest('hex')}`;
    assert.equal(entry.hash, hash);
    assert.equal(entry.bytes, bytes.length);
  }
  for (const [name, artifact] of Object.entries(result.artifacts)) {
    assert.equal(written.manifest.files[artifact.fileName].hash, artifact.hash, name);
  }
  assert.throws(
    () => writeCompiledProfile(outputDir, result),
    /refusing to overwrite existing guard output/,
  );
});

test('ingests completed manifests deterministically and requires three clean audit runs', async (t) => {
  const {
    compileGuardProfile,
    loadEvidenceInputs,
  } = await loadGuard();
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'notty-guard-ingestion-'));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const first = writeAuditRun(root, 'audit-1', { reverseSources: true });
  const second = writeAuditRun(root, 'audit-2', {
    reverseTetragonRecords: true,
  });
  const third = writeAuditRun(root, 'audit-3');
  await bindAuditManifests(
    [first, second, third],
    { name: 'manifest-profile' },
  );

  const forward = await loadEvidenceInputs([third, first, second]);
  const reverse = await loadEvidenceInputs([second, third, first]);
  assert.deepEqual(forward, reverse);
  assert.equal(forward.ingestion.mode, 'completed-manifests');
  assert.equal(forward.ingestion.manifestCount, 3);
  assert.equal(forward.ingestion.promotionInputEligible, true);
  assert.deepEqual(
    forward.runProvenance.map((run) => run.runId),
    ['audit-1', 'audit-2', 'audit-3'],
  );
  assert.equal(
    forward.runProvenance.every((run) => run.cleanAudit && run.manifestVerified),
    true,
  );

  const compiled = compileGuardProfile(forward.records, {
    name: 'manifest-profile',
    runProvenance: forward.runProvenance,
    ingestion: forward.ingestion,
  });
  assert.equal(compiled.profile.spec.target.imageDigest, TEST_IMAGE_DIGEST);
  assert.equal(compiled.profile.spec.promotion.cleanAuditThreshold, 3);
  assert.equal(compiled.profile.spec.promotion.cleanAuditRunCount, 3);
  assert.equal(compiled.profile.spec.promotion.thresholdSatisfied, true);
  assert.deepEqual(
    compiled.profile.spec.evidence.observations.syscalls.map((entry) => entry.name),
    ['read'],
  );
  assert.equal(
    compiled.profile.spec.evidence.advisoryEvidence.some(
      (entry) => entry.source.kind === 'ig' && entry.domain === 'seccomp',
    ),
    true,
  );
});

test('keeps would-deny audit runs out of the clean promotion count', async (t) => {
  const {
    compileGuardProfile,
    loadEvidenceInputs,
  } = await loadGuard();
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'notty-guard-dirty-audit-'));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const manifests = [
    writeAuditRun(root, 'audit-clean-1'),
    writeAuditRun(root, 'audit-clean-2'),
    writeAuditRun(root, 'audit-dirty', { wouldDeny: true }),
  ];
  await bindAuditManifests(manifests, {}, {
    'audit-dirty': {
      network: { wouldDenyCount: 1 },
    },
  });
  const loaded = await loadEvidenceInputs(manifests);
  const dirty = loaded.runProvenance.find((run) => run.runId === 'audit-dirty');
  assert.equal(dirty.cleanAudit, false);
  assert.equal(dirty.wouldDenyCount, 1);

  const compiled = compileGuardProfile(loaded.records, {
    runProvenance: loaded.runProvenance,
    ingestion: loaded.ingestion,
  });
  assert.deepEqual(
    compiled.profile.spec.promotion.cleanAuditRuns,
    ['audit-clean-1', 'audit-clean-2'],
  );
  assert.equal(compiled.profile.spec.promotion.thresholdSatisfied, false);
});

test('audit evaluation coverage and artifact identity fail promotion closed', async (t) => {
  const {
    compileGuardProfile,
    loadEvidenceInputs,
    writeCompiledProfile,
  } = await loadGuard();
  const {
    approveArtifactSet,
    evaluatePromotionGate,
  } = await import('../lib/guardd/approval.js');
  const root = fs.mkdtempSync(
    path.join(os.tmpdir(), 'notty-guard-audit-evaluation-'),
  );
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));

  const missingManifest = writeAuditRun(root, 'audit-evaluation-missing');
  const missingLoaded = await loadEvidenceInputs([missingManifest]);
  assert.equal(missingLoaded.runProvenance[0].cleanAudit, false);
  assert.equal(missingLoaded.runProvenance[0].promotionEligible, false);
  assert.match(
    missingLoaded.runProvenance[0].auditEvaluationErrors.join('\n'),
    /audit evaluation is missing/,
  );
  const missingResult = compileGuardProfile(missingLoaded.records, {
    name: 'missing-audit-evaluation',
    runProvenance: missingLoaded.runProvenance,
    ingestion: missingLoaded.ingestion,
    tetragon: reviewedTetragonOptions(),
  });
  const missingGate = evaluatePromotionGate(missingResult.profile);
  assert.equal(missingGate.overrideEligible, false);
  assert.match(missingGate.errors.join('\n'), /audit evaluation is missing/);
  const missingDirectory = path.join(root, 'missing-candidate');
  writeCompiledProfile(missingDirectory, missingResult);
  await assert.rejects(
    approveArtifactSet(missingDirectory, {
      reviewer: 'security-reviewer',
      promotionOverrideReason: 'must not override missing backend coverage',
    }),
    /candidate promotion provenance is invalid/,
  );

  const boundManifest = writeAuditRun(root, 'audit-evaluation-bound');
  const compilerOptions = {
    name: 'bound-audit-evaluation',
    tetragon: reviewedTetragonOptions(),
  };
  await bindAuditManifests([boundManifest], compilerOptions);
  const boundLoaded = await loadEvidenceInputs([boundManifest]);
  const boundResult = compileGuardProfile(boundLoaded.records, {
    ...compilerOptions,
    runProvenance: boundLoaded.runProvenance,
    ingestion: boundLoaded.ingestion,
  });
  assert.deepEqual(
    boundResult.profile.spec.promotion.cleanAuditRuns,
    ['audit-evaluation-bound'],
  );

  for (const filename of Object.values(AUDIT_BACKEND_ARTIFACTS)) {
    const mismatched = structuredClone(boundResult.profile);
    mismatched.spec.evidence.runProvenance[0]
      .auditEvaluation.candidateArtifacts[filename] =
        `sha256:${'f'.repeat(64)}`;
    const gate = evaluatePromotionGate(mismatched);
    assert.equal(gate.overrideEligible, false, filename);
    assert.match(gate.errors.join('\n'), new RegExp(`${filename} hash`));
  }
  for (const backend of Object.keys(AUDIT_BACKEND_ARTIFACTS)) {
    const missingBackend = structuredClone(boundResult.profile);
    delete missingBackend.spec.evidence.runProvenance[0]
      .auditEvaluation.backends[backend];
    const gate = evaluatePromotionGate(missingBackend);
    assert.equal(gate.overrideEligible, false, backend);
    assert.match(gate.errors.join('\n'), /missing backends/);

    const incompleteBackend = structuredClone(boundResult.profile);
    incompleteBackend.spec.evidence.runProvenance[0]
      .auditEvaluation.backends[backend].complete = false;
    incompleteBackend.spec.evidence.runProvenance[0]
      .auditEvaluation.backends[backend].reason =
        'test evaluator did not complete';
    const incompleteGate = evaluatePromotionGate(incompleteBackend);
    assert.equal(incompleteGate.overrideEligible, false, backend);
    assert.match(
      incompleteGate.errors.join('\n'),
      new RegExp(`backend ${backend} is incomplete`),
    );
  }
});

test('runtime audit manifests attest current evaluator gaps as non-promotable', async (t) => {
  const root = fs.mkdtempSync(
    path.join(os.tmpdir(), 'notty-guard-runtime-audit-evaluation-'),
  );
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const evidenceDir = path.join(root, 'runs', 'runtime-audit');
  fs.mkdirSync(evidenceDir, { recursive: true });
  const candidateArtifacts = Object.fromEntries(
    Object.values(AUDIT_BACKEND_ARTIFACTS).map((filename, index) => [
      filename,
      `sha256:${String(index + 1).repeat(64)}`,
    ]),
  );
  const { finalizeRunEvidence } = await import(
    '../lib/guardd/evidence-finalizer.js'
  );
  const { manifest } = await finalizeRunEvidence(
    {
      runId: 'runtime-audit',
      mode: 'audit',
      profileRevision: 'candidate-1',
      evidenceDir,
      evidenceComplete: false,
      adapters: [],
      detachResults: [],
      runtimeAttestations: [
        {
          apiVersion: 'notty.dev/v1alpha1',
          kind: 'NoshRuntimeArtifactSnapshot',
          runId: 'runtime-audit',
          artifacts: candidateArtifacts,
        },
      ],
      egress: {
        evidenceOffsets: {
          dns: null,
          gateway: null,
        },
      },
    },
    { stateDir: root },
  );

  assert.deepEqual(
    manifest.auditEvaluation.candidateArtifacts,
    candidateArtifacts,
  );
  assert.equal(
    Object.values(manifest.auditEvaluation.backends).every(
      (backend) => backend.complete === false,
    ),
    true,
  );
  assert.match(
    manifest.auditEvaluation.backends.tetragon.reason,
    /not evaluated in audit mode/,
  );
  assert.match(
    manifest.auditEvaluation.backends.network.reason,
    /egress but not.*ingress policy/,
  );

  const { evaluateAuditEvaluation } = await import(
    '../lib/guard/audit-evaluation.js'
  );
  const evaluation = evaluateAuditEvaluation(
    manifest.auditEvaluation,
    candidateArtifacts,
  );
  assert.equal(evaluation.complete, false);
  assert.equal(evaluation.clean, false);
});

test('manifest ingestion accepts exact canonical and native Tetragon container identities', async (t) => {
  const { loadEvidenceInputs } = await loadGuard();
  const root = fs.mkdtempSync(
    path.join(os.tmpdir(), 'notty-guard-tetragon-identity-positive-'),
  );
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));

  const canonicalManifest = writeAuditRun(root, 'tetragon-canonical-exact');
  const nativeManifest = writeAuditRun(root, 'tetragon-native-exact');
  replaceManifestSourceRecords(nativeManifest, 'tetragon-events', [
    {
      process_exec: {
        process: {
          binary: '/usr/bin/node',
          arguments: '/app/server.js',
          docker: TEST_CONTAINER_ID,
        },
        parent: {
          binary: '/bin/sh',
          docker: TEST_CONTAINER_ID,
        },
      },
      time: '2026-07-25T12:00:01.000000000Z',
    },
  ]);

  const loaded = await loadEvidenceInputs([nativeManifest, canonicalManifest]);
  const tetragonRecords = loaded.records.filter(
    (record) => record.source?.kind === 'tetragon',
  );
  assert.equal(tetragonRecords.length, 4);
  assert.equal(
    tetragonRecords.every((record) => record.container?.id === TEST_CONTAINER_ID),
    true,
  );
});

test('manifest ingestion rejects missing or mismatched Tetragon container identities', async (t) => {
  const { loadEvidenceInputs } = await loadGuard();
  const root = fs.mkdtempSync(
    path.join(os.tmpdir(), 'notty-guard-tetragon-identity-negative-'),
  );
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));

  const canonicalMissing = writeAuditRun(root, 'tetragon-canonical-missing');
  replaceManifestSourceRecords(canonicalMissing, 'tetragon-events', [
    {
      schemaVersion: 1,
      source: { kind: 'tetragon', name: 'tetragon' },
      runId: 'tetragon-canonical-missing',
      observedAt: '2026-07-25T12:00:01.000Z',
      event: {
        type: 'process.exec',
        executable: '/usr/bin/node',
      },
    },
  ]);

  const canonicalMismatch = writeAuditRun(root, 'tetragon-canonical-mismatch');
  replaceManifestSourceRecords(canonicalMismatch, 'tetragon-events', [
    {
      schemaVersion: 1,
      source: { kind: 'tetragon', name: 'tetragon' },
      runId: 'tetragon-canonical-mismatch',
      observedAt: '2026-07-25T12:00:01.000Z',
      container: {
        ...TEST_CONTAINER,
        id: 'c'.repeat(64),
      },
      event: {
        type: 'process.exec',
        executable: '/usr/bin/node',
      },
    },
  ]);

  const nativeMissing = writeAuditRun(root, 'tetragon-native-missing');
  replaceManifestSourceRecords(nativeMissing, 'tetragon-events', [
    {
      process_exec: {
        process: {
          binary: '/usr/bin/node',
        },
      },
      time: '2026-07-25T12:00:01.000000000Z',
    },
  ]);

  const nativeMismatch = writeAuditRun(root, 'tetragon-native-mismatch');
  replaceManifestSourceRecords(nativeMismatch, 'tetragon-events', [
    {
      process_kprobe: {
        process: {
          binary: '/usr/bin/node',
          docker: 'd'.repeat(64),
        },
        function_name: '__x64_sys_read',
        syscall: true,
      },
      time: '2026-07-25T12:00:01.000000000Z',
    },
  ]);

  await assert.rejects(
    loadEvidenceInputs([canonicalMissing]),
    /canonical event is missing an attributable container id/,
  );
  await assert.rejects(
    loadEvidenceInputs([canonicalMismatch]),
    /container id .* does not match manifest/,
  );
  await assert.rejects(
    loadEvidenceInputs([nativeMissing]),
    /native event is missing an attributable container id/,
  );
  await assert.rejects(
    loadEvidenceInputs([nativeMismatch]),
    /container id .* does not match manifest/,
  );
});

test('rejects incomplete, lost, corrupt, escaped, duplicate, and mixed manifest evidence', async (t) => {
  const { loadEvidenceInputs } = await loadGuard();
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'notty-guard-rejections-'));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const incomplete = writeAuditRun(root, 'incomplete', {
    incompleteManifest: true,
  });
  const lost = writeAuditRun(root, 'lost', { lostSource: 'nosh-l4' });
  const corrupt = writeAuditRun(root, 'corrupt', {
    badHashSource: 'tetragon-events',
  });
  const unsigned = writeAuditRun(root, 'unsigned', {
    missingHashSource: 'managed_gateway',
  });
  const escaped = writeAuditRun(root, 'escaped', {
    escapeSource: 'managed_dns',
  });
  const duplicateOne = writeAuditRun(root, 'same-run', {
    directoryName: 'duplicate-one',
  });
  const duplicateTwo = writeAuditRun(root, 'same-run', {
    directoryName: 'duplicate-two',
  });
  const differentImage = writeAuditRun(root, 'different-image', {
    imageDigest: `sha256:${'c'.repeat(64)}`,
  });
  const clean = writeAuditRun(root, 'clean');
  const directFixture = path.join(
    __dirname,
    '..',
    'config',
    'nosh-guard',
    'fixtures',
    'tetragon-events.json',
  );

  await assert.rejects(loadEvidenceInputs([incomplete]), /incomplete/);
  await assert.rejects(loadEvidenceInputs([lost]), /lost events/);
  await assert.rejects(loadEvidenceInputs([corrupt]), /hash mismatch/);
  await assert.rejects(loadEvidenceInputs([unsigned]), /valid SHA-256 hash/);
  await assert.rejects(loadEvidenceInputs([escaped]), /escapes its manifest directory/);
  await assert.rejects(
    loadEvidenceInputs([duplicateOne, duplicateTwo]),
    /duplicate evidence runId/,
  );
  await assert.rejects(
    loadEvidenceInputs([clean, differentImage]),
    /same immutable image digest/,
  );
  await assert.rejects(
    loadEvidenceInputs([clean, directFixture]),
    /cannot be mixed/,
  );
});

test('rejects audit and enforcement egress evidence as training input', async (t) => {
  const { loadEvidenceInputs } = await loadGuard();
  const root = fs.mkdtempSync(
    path.join(os.tmpdir(), 'notty-egress-diagnostic-evidence-'),
  );
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));

  for (const mode of ['egress-audit', 'egress-enforce']) {
    const manifestPath = path.join(root, `${mode}.json`);
    fs.writeFileSync(
      manifestPath,
      `${JSON.stringify({
        schemaVersion: 1,
        apiVersion: 'notty.dev/v1alpha1',
        kind: 'NoshSecurityEvidenceManifest',
        runId: `run-${mode}`,
        mode,
      })}\n`,
    );
    await assert.rejects(
      loadEvidenceInputs([manifestPath]),
      /diagnostic-only and cannot train or promote/,
    );
  }
});

test('egress learning evidence cannot become full-profile promotion input', async (t) => {
  const { compileGuardProfile, loadEvidenceInputs } = await loadGuard();
  const { evaluatePromotionGate } = await import('../lib/guardd/approval.js');
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'notty-egress-scope-'));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const runId = 'egress-scope-run';
  const imageDigest = `sha256:${'d'.repeat(64)}`;
  const sources = [];
  for (const name of ['nosh-egress']) {
    const sourcePath = path.join(root, `${name}.jsonl`);
    const source = `${JSON.stringify({ source: name, recordKind: 'stats', final: true })}\n`;
    fs.writeFileSync(sourcePath, source);
    sources.push({
      name,
      path: sourcePath,
      format: 'ndjson',
      required: true,
      present: true,
      bytes: Buffer.byteLength(source),
      records: 1,
      hash: `sha256:${crypto.createHash('sha256').update(source).digest('hex')}`,
      lostEvents: 0,
      parseErrors: 0,
      completionMarker: 'complete',
      complete: true,
    });
  }
  const manifestPath = path.join(root, 'evidence-manifest.json');
  fs.writeFileSync(manifestPath, `${JSON.stringify({
    schemaVersion: 1,
    apiVersion: 'notty.dev/v1alpha1',
    kind: 'NoshSecurityEvidenceManifest',
    generatedAt: '2026-08-08T00:00:03.000Z',
    runId,
    mode: 'egress-learn',
    subject: {
      containerId: 'e'.repeat(64),
      containerName: 'egress-scope',
      image: 'nosh:test',
      imageDigest,
      workspace: root,
      workspaceIdentity: (() => {
        const stat = fs.statSync(root, { bigint: true });
        return { dev: String(stat.dev), ino: String(stat.ino) };
      })(),
    },
    startedAt: '2026-08-08T00:00:00.000Z',
    endedAt: '2026-08-08T00:00:02.000Z',
    profileRevision: 'candidate',
    trainingEligible: true,
    evidenceUse: 'training',
    complete: true,
    egressEvaluation: {
      schemaVersion: 1,
      backend: 'nosh-egress',
      policyHash: `sha256:${'1'.repeat(64)}`,
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
      objectDigest: `sha256:${'2'.repeat(64)}`,
      policyDigest: `sha256:${'3'.repeat(64)}`,
      targetContextHash: `sha256:${'4'.repeat(64)}`,
      ruleIdMap: {},
      counts: { allow: 0, 'would-deny': 0, deny: 0 },
      decisionClasses: {
        'backend-deny': 0,
        'containment-deny': 0,
        'coverage-gap': 0,
        'dns-observation': 0,
        'infrastructure-allow': 0,
        observed: 0,
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
  }, null, 2)}\n`);
  const loaded = await loadEvidenceInputs([manifestPath]);
  assert.equal(loaded.runProvenance[0].profileScope, 'egress-only');
  assert.equal(loaded.runProvenance[0].promotionEligible, false);
  assert.equal(loaded.ingestion.promotionInputEligible, false);
  const compiled = compileGuardProfile(loaded.records, {
    runProvenance: loaded.runProvenance,
    ingestion: loaded.ingestion,
  });
  const gate = evaluatePromotionGate(compiled.profile);
  assert.equal(gate.overrideEligible, false);
  assert.match(gate.errors.join('\n'), /scoped to egress-only evidence/);
});

test('nosh-egress v2 retains decisions and bounded DNS chains without authorizing containment', async (t) => {
  const { compileGuardProfile, loadEvidenceInputs } = await loadGuard();
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'notty-ebpf-correlation-'));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const decision = (overrides) => ({
    schemaVersion: 2,
    recordKind: 'decision',
    timestampMonotonicNs: '1000000000',
    cgroupId: '42',
    policyGeneration: '1',
    hook: 1,
    family: 4,
    protocol: 6,
    sourceAddress: '10.240.1.3',
    destinationAddress: '203.0.113.10',
    sourcePort: 45000,
    destinationPort: 443,
    verdict: 'allow',
    decisionClass: 'observed',
    reason: 'learn-observed',
    reasonCode: 4,
    enforcementApplied: false,
    containmentId: '',
    ruleId: 0,
    packetBytes: 64,
    transactionId: 0,
    domain: '',
    expiresMonotonicNs: '0',
    ...overrides,
  });
  const dnsAnswer = (overrides) => ({
    schemaVersion: 2,
    recordKind: 'dns-answer',
    timestampMonotonicNs: '1000000000',
    cgroupId: '42',
    policyGeneration: '1',
    hook: 6,
    transportFamily: 4,
    transportProtocol: 17,
    resolverAddress: '10.240.1.2',
    resolverPort: 53,
    clientPort: 53000,
    domain: 'api.example.com',
    dnsRecordType: 'A',
    answerAddress: '203.0.113.10',
    decisionClass: 'dns-observation',
    reason: 'dns-answer',
    reasonCode: 16,
    enforcementApplied: false,
    transactionId: 1,
    expiresMonotonicNs: '5000000000',
    ...overrides,
  });
  const records = [
    dnsAnswer({}),
    dnsAnswer({
      timestampMonotonicNs: '1100000000',
      answerAddress: '203.0.113.11',
      transactionId: 2,
      domain: 'one.example.com',
    }),
    dnsAnswer({
      timestampMonotonicNs: '1200000000',
      answerAddress: '203.0.113.11',
      transactionId: 3,
      domain: 'two.example.com',
    }),
    decision({
      timestampMonotonicNs: '2000000000',
    }),
    decision({
      timestampMonotonicNs: '2100000000',
      destinationAddress: '203.0.113.11',
    }),
    decision({
      timestampMonotonicNs: '2200000000',
      destinationAddress: '203.0.113.12',
    }),
    decision({
      timestampMonotonicNs: '2300000000',
      destinationAddress: '192.168.1.65',
      destinationPort: 9001,
    }),
    decision({
      timestampMonotonicNs: '2400000000',
      destinationAddress: '10.240.1.1',
      destinationPort: 9001,
      verdict: 'deny',
      decisionClass: 'containment-deny',
      reason: 'platform-containment',
      reasonCode: 13,
      enforcementApplied: true,
      containmentId: 'docker-bridge-ipv4-gateway',
    }),
    decision({
      timestampMonotonicNs: '2500000000',
      destinationAddress: '203.0.113.13',
      verdict: 'allow',
      decisionClass: 'coverage-gap',
      reason: 'fragment-gap',
      reasonCode: 8,
    }),
    decision({
      timestampMonotonicNs: '2600000000',
      hook: 6,
      family: 0,
      protocol: 0,
      sourceAddress: '',
      destinationAddress: '',
      sourcePort: 0,
      destinationPort: 0,
      verdict: 'deny',
      decisionClass: 'backend-deny',
      reason: 'hidden-destination',
      reasonCode: 14,
      enforcementApplied: true,
    }),
    {
      schemaVersion: 2,
      recordKind: 'stats',
      timestampUnixNs: '1787270403000000000',
      cgroupId: '42',
      policyGeneration: '1',
      mode: 'learn',
      final: true,
      eventsSeen: '10',
      decoderErrors: '0',
      counters: {
        allowed: '5',
        wouldDeny: '0',
        denied: '2',
        ringbufDrops: '0',
        parseErrors: '0',
        fragments: '0',
        configInvalid: '0',
        policyMisses: '4',
        dnsQueries: '3',
        dnsResponses: '3',
        dnsTransactionMisses: '0',
        dnsGrantUpdates: '3',
        dnsGrantFailures: '0',
        dnsUnsupported: '0',
        unsupportedProtocol: '0',
        coverageAllowed: '1',
        coverageWouldDeny: '0',
        coverageDenied: '0',
        containmentDenied: '1',
        backendDenied: '1',
        dnsAnswers: '3',
      },
    },
  ];
  const source = `${records.map((record) => JSON.stringify(record)).join('\n')}\n`;
  const sourcePath = path.join(root, 'nosh-egress.jsonl');
  fs.writeFileSync(sourcePath, source);
  const manifestPath = path.join(root, 'evidence-manifest.json');
  fs.writeFileSync(manifestPath, `${JSON.stringify({
    schemaVersion: 1,
    apiVersion: 'notty.dev/v1alpha1',
    kind: 'NoshSecurityEvidenceManifest',
    generatedAt: '2026-08-21T00:00:03.000Z',
    runId: 'ebpf-correlation-run',
    mode: 'egress-learn',
    subject: {
      containerId: 'f'.repeat(64),
      containerName: 'ebpf-correlation',
      image: 'nosh:test',
      imageDigest: `sha256:${'e'.repeat(64)}`,
      workspace: root,
    },
    startedAt: '2026-08-21T00:00:00.000Z',
    endedAt: '2026-08-21T00:00:03.000Z',
    profileRevision: 'candidate',
    trainingEligible: true,
    evidenceUse: 'training',
    complete: true,
    sources: [{
      name: 'nosh-egress',
      path: path.basename(sourcePath),
      format: 'ndjson',
      required: true,
      present: true,
      bytes: Buffer.byteLength(source),
      records: records.length,
      hash: hashBytes(source),
      lostEvents: 0,
      parseErrors: 0,
      completionMarker: 'final-stats-clean',
      complete: true,
    }],
  }, null, 2)}\n`);

  const loaded = await loadEvidenceInputs([manifestPath]);
  const network = loaded.records
    .filter((record) => record.event?.type === 'network')
    .map((record) => ({ observedAt: record.observedAt, ...record.event }));
  const named = network.find((event) => event.dnsName === 'api.example.com');
  assert.equal(named.address, '203.0.113.10');
  assert.deepEqual(named.dnsNames, ['api.example.com']);
  assert.equal(named.dnsChain[0].address, '203.0.113.10');
  assert.equal(named.dnsChain[0].dnsRecordType, 'A');
  assert.equal(named.dnsChain[0].recordKind, 'dns-answer');
  assert.equal(named.dnsChain[0].hook, 6);
  assert.equal(named.dnsChain[0].resolverAddress, '10.240.1.2');
  assert.equal(named.dnsChain[0].transportProtocol, 'udp');
  assert.equal(named.decision.verdict, 'allow');
  assert.equal(named.decision.recordKind, 'decision');
  assert.equal(named.decision.hook, 1);
  assert.equal(named.decision.reason, 'learn-observed');
  assert.equal(named.decision.enforcementApplied, false);

  const ambiguous = network.find((event) => event.address === '203.0.113.11');
  assert.deepEqual(ambiguous.dnsNames, ['one.example.com', 'two.example.com']);
  assert.equal(ambiguous.dnsChain.length, 2);
  assert.match(ambiguous.unresolvedReason, /shared by multiple DNS names/);

  const unnamed = network.find((event) => event.address === '203.0.113.12');
  assert.equal(unnamed.dnsName, undefined);
  assert.equal(unnamed.decision.decisionClass, 'observed');

  const privateEndpoint = network.find((event) => event.address === '192.168.1.65');
  assert.equal(privateEndpoint.port, 9001);
  assert.equal(privateEndpoint.unresolvedReason, undefined);
  assert.equal(privateEndpoint.decision.verdict, 'allow');

  const containment = network.find((event) => event.address === '10.240.1.1');
  assert.equal(containment.decision.containmentId, 'docker-bridge-ipv4-gateway');
  assert.match(containment.unresolvedReason, /cannot be authorized by reviewed policy/);
  const coverageGap = network.find((event) => event.address === '203.0.113.13');
  assert.equal(coverageGap.decision.reason, 'fragment-gap');
  assert.match(coverageGap.unresolvedReason, /must be resolved before policy authorization/);
  const hidden = loaded.records.find((record) => (
    record.event?.type === 'recommendation'
      && record.event?.value?.decision?.reason === 'hidden-destination'
  ));
  assert.equal(hidden.event.value.decision.decisionClass, 'backend-deny');

  const compiled = compileGuardProfile(loaded.records);
  const privateRule = compiled.artifacts.network.content.spec.egress.find(
    (rule) => rule.destination === '192.168.1.65',
  );
  assert.equal(privateRule.ports[0], 9001);
  assert.equal(privateRule.observations[0].decision.verdict, 'allow');
  assert.equal(
    compiled.artifacts.network.content.spec.egress.some(
      (rule) => ['10.240.1.1', '203.0.113.13'].includes(rule.destination),
    ),
    false,
  );
  assert.match(
    compiled.artifacts.network.content.spec.unresolvedObservations
      .map((entry) => entry.reason)
      .join('\n'),
    /platform containment docker-bridge-ipv4-gateway/,
  );
});

test('preserves direct raw fixture ingestion without making it promotion eligible', async () => {
  const {
    compileGuardProfile,
    loadEvidenceInputs,
  } = await loadGuard();
  const fixtures = ['tetragon-events.json', 'ig-dns.json'].map((fileName) => path.join(
    __dirname,
    '..',
    'config',
    'nosh-guard',
    'fixtures',
    fileName,
  ));
  const loaded = await loadEvidenceInputs(fixtures);
  assert.equal(loaded.ingestion.mode, 'direct');
  assert.equal(loaded.ingestion.manifestCount, 0);
  assert.equal(loaded.ingestion.promotionInputEligible, false);
  assert.equal(loaded.runProvenance.length, 1);
  assert.equal(loaded.runProvenance[0].cleanAudit, false);
  assert.equal(loaded.records.length, 2);

  const compiled = compileGuardProfile(loaded.records, {
    runProvenance: loaded.runProvenance,
    ingestion: loaded.ingestion,
  });
  assert.equal(compiled.profile.spec.promotion.allInputsManifested, false);
  assert.equal(compiled.profile.spec.promotion.thresholdSatisfied, false);
});

test('profile compile accepts repeatable evidence flags', async (t) => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'notty-guard-cli-'));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const manifests = [
    writeAuditRun(root, 'cli-audit-1'),
    writeAuditRun(root, 'cli-audit-2'),
    writeAuditRun(root, 'cli-audit-3'),
  ];
  const outputDir = path.join(root, 'candidate');
  await bindAuditManifests(manifests, {
    name: path.basename(outputDir),
    architecture: process.arch,
  });
  const result = childProcess.spawnSync(
    process.execPath,
    [
      path.join(__dirname, '..', 'scripts', 'nosh-guard.mjs'),
      'profile',
      'compile',
      '--evidence',
      manifests[2],
      '--evidence',
      manifests[0],
      '--evidence',
      manifests[1],
      '--output',
      outputDir,
    ],
    {
      cwd: path.join(__dirname, '..'),
      encoding: 'utf8',
    },
  );
  assert.equal(result.status, 0, result.stderr);
  const output = JSON.parse(result.stdout);
  assert.equal(output.promotion.cleanAuditRunCount, 3);
  assert.equal(output.promotion.thresholdSatisfied, true);
  assert.equal(
    JSON.parse(fs.readFileSync(path.join(outputDir, 'profile.yaml'), 'utf8'))
      .spec.promotion.thresholdSatisfied,
    true,
  );
});

test('approval enforces the clean-run floor and records an explicit override', async (t) => {
  const {
    compileGuardProfile,
    loadEvidenceInputs,
    writeCompiledProfile,
  } = await loadGuard();
  const {
    approveArtifactSet,
    evaluatePromotionGate,
    verifyArtifactSet,
  } = await import('../lib/guardd/approval.js');
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'notty-guard-promotion-'));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const manifests = [
    writeAuditRun(root, 'approval-audit-1'),
    writeAuditRun(root, 'approval-audit-2'),
    writeAuditRun(root, 'approval-audit-3'),
  ];
  const compile = async (selected, outputDirectory, cleanAuditThreshold) => {
    const compilerOptions = {
      name: path.basename(outputDirectory),
      cleanAuditThreshold,
      tetragon: reviewedTetragonOptions(),
    };
    await bindAuditManifests(selected, compilerOptions);
    const loaded = await loadEvidenceInputs(selected);
    const result = compileGuardProfile(loaded.records, {
      ...compilerOptions,
      runProvenance: loaded.runProvenance,
      ingestion: loaded.ingestion,
    });
    writeCompiledProfile(outputDirectory, result);
    return result;
  };

  const belowDirectory = path.join(root, 'below-threshold');
  await compile(manifests.slice(0, 2), belowDirectory);
  await assert.rejects(
    approveArtifactSet(belowDirectory, { reviewer: 'security-reviewer' }),
    /requires 3 distinct clean audit runs/,
  );
  const override = await approveArtifactSet(belowDirectory, {
    reviewer: 'security-reviewer',
    promotionOverrideReason: 'two-run emergency rollout reviewed under change 42',
  });
  assert.equal(override.promotionGate.satisfied, false);
  assert.equal(override.promotionGate.override.reviewer, 'security-reviewer');
  assert.equal(
    override.promotionGate.override.reason,
    'two-run emergency rollout reviewed under change 42',
  );
  assert.equal((await verifyArtifactSet(belowDirectory)).ok, true);

  const readyDirectory = path.join(root, 'threshold-satisfied');
  const ready = await compile(manifests, readyDirectory);
  assert.equal(evaluatePromotionGate(ready.profile).satisfied, true);
  const approval = await approveArtifactSet(readyDirectory, {
    reviewer: 'security-reviewer',
  });
  assert.equal(approval.promotionGate.satisfied, true);
  assert.equal(approval.promotionGate.override, null);
  assert.equal((await verifyArtifactSet(readyDirectory)).ok, true);

  const stricter = await compile(
    manifests,
    path.join(root, 'stricter-threshold'),
    4,
  );
  const stricterGate = evaluatePromotionGate(stricter.profile);
  assert.equal(stricterGate.threshold, 4);
  assert.equal(stricterGate.satisfied, false);
  assert.equal(stricterGate.overrideEligible, true);
});
