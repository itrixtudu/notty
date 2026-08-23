'use strict';

const assert = require('node:assert/strict');
const childProcess = require('node:child_process');
const crypto = require('node:crypto');
const { EventEmitter } = require('node:events');
const fs = require('node:fs');
const net = require('node:net');
const os = require('node:os');
const path = require('node:path');
const test = require('node:test');
const { pathToFileURL } = require('node:url');

const appRoot = path.resolve(__dirname, '..');

function platformContainmentIdentity(cidrs) {
  const selected = [...cidrs].sort();
  const source = selected.map((cidr) => {
    const address = cidr.split('/', 1)[0];
    return `platform-endpoint:${address}\t${cidr}\n`;
  }).join('');
  return {
    cidrs: selected,
    digest: `sha256:${crypto.createHash('sha256').update(source).digest('hex')}`,
    count: selected.length,
  };
}

async function importModule(relativePath) {
  return import(pathToFileURL(path.join(appRoot, relativePath)).href);
}

function tempDir(t) {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'nosh-guard-test-'));
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  return directory;
}

function trustedDaemonTempDir(t) {
  const directory = fs.mkdtempSync(
    path.join(os.homedir(), '.nosh-guard-daemon-test-'),
  );
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  return directory;
}

function healthyHost() {
  return {
    checks: {},
    gates: {
      learn: true,
      audit: true,
      enforce: true,
      'egress-learn': true,
      'egress-audit': true,
      'egress-enforce': true,
    },
  };
}

function scopedBackendFromLegacy(legacy = {}, overrides = {}) {
  const objectDigest = `sha256:${'e'.repeat(64)}`;
  return {
    resolvers: ['1.1.1.1', '8.8.8.8'],
    async initialize() {},
    preflight() {
      return { objectDigest };
    },
    async prepareNetwork(runId) {
      if (overrides.prepareNetwork) {
        return overrides.prepareNetwork(runId);
      }
      return legacy.prepareNetwork(runId);
    },
    async prepareRun(input) {
      if (overrides.prepareRun) return overrides.prepareRun(input);
      const containment = platformContainmentIdentity(
        input.platformContainmentCidrs,
      );
      return {
        backend: 'nosh-egress',
        backendAbi: 'nosh-egress-v2',
        backendMode: input.mode.slice('egress-'.length),
        policyPath: `/guard-test/${input.runId}/policy.manifest`,
        policyDigest: `sha256:${'f'.repeat(64)}`,
        ruleIdMap: {},
        ruleIdMapPath: `/guard-test/${input.runId}/rule-id-map.json`,
        pinRoot: `/sys/fs/bpf/nosh-guard/${input.runId}`,
        resolverConfigPath: null,
        resolvers: [...input.resolvers],
        platformContainment: {
          strategy: 'per-run-docker-bridge-gateways',
          ipv4PrefixLength: 32,
          ipv6PrefixLength: 128,
        },
        platformContainmentCidrs: containment.cidrs,
        containmentDigest: containment.digest,
        containmentCount: containment.count,
        objectDigest,
        mapAbi: 2,
        programAbi: 2,
        targetContextHash: `sha256:${'d'.repeat(64)}`,
        targetContextPath: path.join(
          input.evidenceDir,
          'guard-ebpf-target-context.json',
        ),
      };
    },
    async bindRun(run, inspected, allocation, preparation) {
      const attached = legacy.attachRun
        ? await legacy.attachRun(run, inspected, allocation)
        : {};
      return {
        ...preparation,
        networkName: allocation.networkName,
        sourceIpv4: allocation.runnerIp,
        sourceIpv6: allocation.runnerIpv6 || null,
        gatewayIpv4:
          allocation.dockerGateway || allocation.egressGateway || null,
        gatewayContainerId: null,
        ...attached,
      };
    },
    attestRun(run) {
      if (overrides.attestRun) return overrides.attestRun(run);
      return {
        apiVersion: 'notty.dev/v1alpha1',
        kind: 'NoshEbpfEgressRuntimeAttestation',
        runId: run.runId,
        policyDigest: run.egress.policyDigest,
        containmentDigest: run.egress.containmentDigest,
        containmentCount: run.egress.containmentCount,
        policyGeneration: '1',
      };
    },
    async runtimeHealth(run) {
      if (overrides.runtimeHealth) return overrides.runtimeHealth(run);
      if (legacy.runtimeHealth) return legacy.runtimeHealth(run);
      return { ok: true };
    },
    async snapshotRun(run) {
      if (overrides.snapshotRun) return overrides.snapshotRun(run);
      if (legacy.snapshotRun) return legacy.snapshotRun(run);
      return { complete: true };
    },
    async detachRun(run) {
      if (overrides.detachRun) return overrides.detachRun(run);
      if (legacy.detachRun) return legacy.detachRun(run);
      return { ok: true };
    },
  };
}

test('standalone service rejects enforce mode before touching Docker', async () => {
  const { GuardService } = await importModule('lib/guardd/service.js');
  let inspected = false;
  const service = new GuardService({
    healthProvider: healthyHost,
    docker: {
      async inspectImage() {
        inspected = true;
        throw new Error('must not inspect an image');
      },
    },
    egress: {
      async initialize() {},
    },
  });

  await assert.rejects(
    service.startRun({
      runId: 'standalone-enforce-rejected',
      mode: 'enforce',
      image: 'nosh',
      name: 'standalone-enforce-rejected',
      workdir: '/workspace',
      profileDir: '/var/lib/nosh-guard/profiles/example',
    }),
    (error) => error.code === 'GUARD_STANDALONE_INGRESS_UNAVAILABLE',
  );
  assert.equal(inspected, false);
});

test('scoped egress snapshots hash every verified runtime artifact', async (t) => {
  const root = tempDir(t);
  const evidenceDir = path.join(root, 'evidence');
  fs.mkdirSync(evidenceDir);
  const { stableStringify } = await importModule('lib/guard/stable.js');
  const { snapshotEgressProfile } = await importModule(
    'lib/guardd/service.js',
  );
  const encode = (value) => `${stableStringify(value, 2)}\n`;
  const hash = (value) =>
    `sha256:${crypto.createHash('sha256').update(encode(value)).digest('hex')}`;
  const profile = { kind: 'NoshEgressProfile', value: 1 };
  const policy = { kind: 'NoshEgressPolicy', value: 2 };
  const manifest = { kind: 'NoshEgressBundleManifest', value: 3 };
  const approval = {
    kind: 'NoshEgressPolicyApproval',
    contentHash: `sha256:${'a'.repeat(64)}`,
  };
  const verification = {
    ok: true,
    revision: 'approved-1',
    workspace: '/workspace',
    workspaceKey: 'b'.repeat(64),
    imageDigest: `sha256:${'c'.repeat(64)}`,
    policyHash: hash(policy),
    artifacts: {
      'egress-profile.json': hash(profile),
      'egress-policy.json': hash(policy),
    },
    manifestHash: hash(manifest),
    approvalHash: approval.contentHash,
    approvalFileHash: hash(approval),
    profile,
    policy,
    manifest,
    approval,
  };

  const snapshot = await snapshotEgressProfile({
    verification,
    evidenceDir,
    runId: 'snapshot-run',
    mode: 'egress-enforce',
  });
  for (const [name, expectedHash] of [
    ['egress-profile.json', verification.artifacts['egress-profile.json']],
    ['egress-policy.json', verification.artifacts['egress-policy.json']],
    ['manifest.json', verification.manifestHash],
    ['egress-approval.json', verification.approvalFileHash],
  ]) {
    const filePath = path.join(snapshot.snapshotDir, name);
    const contents = fs.readFileSync(filePath);
    assert.equal(
      `sha256:${crypto.createHash('sha256').update(contents).digest('hex')}`,
      expectedHash,
    );
    assert.equal(fs.statSync(filePath).mode & 0o7777, 0o600);
    assert.equal(snapshot.attestation.files[name].hash, expectedHash);
  }
  assert.equal(fs.statSync(snapshot.snapshotDir).mode & 0o7777, 0o700);
  assert.equal(fs.statSync(snapshot.attestationPath).mode & 0o7777, 0o600);
  assert.equal(
    snapshot.attestation.approvalHash,
    approval.contentHash,
  );

  const rejectedEvidence = path.join(root, 'rejected-evidence');
  fs.mkdirSync(rejectedEvidence);
  await assert.rejects(
    snapshotEgressProfile({
      verification: {
        ...verification,
        artifacts: {
          ...verification.artifacts,
          'egress-policy.json': `sha256:${'d'.repeat(64)}`,
        },
      },
      evidenceDir: rejectedEvidence,
      runId: 'snapshot-tampered',
      mode: 'egress-enforce',
    }),
    (error) => error.code === 'GUARD_EGRESS_SNAPSHOT_HASH_MISMATCH',
  );
  assert.equal(
    fs.existsSync(path.join(rejectedEvidence, 'egress-profile-snapshot')),
    false,
  );
});

test('retained evidence permanently prevents run-ID reuse', async (t) => {
  const root = tempDir(t);
  const stateDir = path.join(root, 'state');
  const { GuardStateStore } = await importModule('lib/guardd/state-store.js');
  const { GuardService } = await importModule('lib/guardd/service.js');
  const store = new GuardStateStore(stateDir);
  let inspected = false;
  const service = new GuardService({
    store,
    healthProvider: healthyHost,
    docker: {
      async inspectImage() {
        inspected = true;
        throw new Error('must not inspect an image for a reused run ID');
      },
    },
    egress: {
      async initialize() {},
    },
    scopedEgress: {
      async initialize() {},
    },
  });
  await service.initialize();
  fs.mkdirSync(store.evidencePath('immutable-run-id'), { mode: 0o700 });

  await assert.rejects(
    service.startRun({
      runId: 'immutable-run-id',
      mode: 'learn',
      image: 'nosh',
      name: 'immutable-run-id',
      workdir: root,
    }),
    (error) =>
      error.code === 'GUARD_RUN_ID_REUSED' &&
      error.statusCode === 409,
  );
  assert.equal(inspected, false);
});

test('trusted profiles cannot escape their root or use writable ancestry', async (t) => {
  const root = tempDir(t);
  const trustedRoot = path.join(root, 'profiles');
  const candidate = path.join(trustedRoot, 'candidate');
  fs.mkdirSync(candidate, { recursive: true });
  const { assertTrustedCandidateDirectory } = await importModule(
    'lib/guardd/approval.js',
  );

  await assert.rejects(
    assertTrustedCandidateDirectory(candidate, {
      trustedRoot: path.join(root, 'other-profiles'),
    }),
    /must already exist|beneath the trusted profile root/,
  );
  await assert.rejects(
    assertTrustedCandidateDirectory(candidate, { trustedRoot }),
    /root-owned and not group\/other-writable/,
  );
});

test('guard runner spec creates a credential-free, hardened Docker request', async (t) => {
  const workdir = tempDir(t);
  const {
    assertRunnerImageAbi,
    buildRunnerSpec,
    summarizeRunnerSpec,
  } = await importModule(
    'lib/guardd/runner-spec.js',
  );
  assert.match(
    fs.readFileSync(path.join(appRoot, 'Dockerfile.nosh'), 'utf8'),
    /^LABEL io\.notty\.guard\.runner-abi="1"$/m,
  );
  assert.match(
    fs.readFileSync(path.join(appRoot, 'Dockerfile.nosh'), 'utf8'),
    /^LABEL io\.notty\.guard\.policy-tooling-abi="1"$/m,
  );
  assert.deepEqual(
    assertRunnerImageAbi({
      Config: {
        Labels: {
          'io.notty.guard.runner-abi': '1',
        },
      },
    }),
    {
      label: 'io.notty.guard.runner-abi',
      version: '1',
    },
  );
  assert.throws(
    () => assertRunnerImageAbi({ Config: { Labels: {} } }),
    (error) =>
      error.code === 'GUARD_RUNNER_IMAGE_ABI_MISMATCH' &&
      error.actual === null,
  );

  const runner = buildRunnerSpec({
    runId: 'run-1',
    mode: 'learn',
    image: 'nosh@sha256:test',
    imageDigest: 'sha256:test',
    name: 'agent-one',
    workdir,
    environment: {
      NOTTY_MCP_SPAWN_OTP: 'runner-otp',
      NOTTY_BASIC_AUTH_PASSWORD: 'runner-password',
      ALLOWED_ORIGIN: 'https://attacker.example',
      HOME: '/home/attacker',
      NOTTY_PUBLIC_WS_URL: 'wss://attacker.example/ws',
      XDG_CONFIG_HOME: '/home/attacker/.config',
    },
    gatewayPublicOrigin: 'https://guard.example:3443',
  });
  const summary = summarizeRunnerSpec(runner);
  const serialized = JSON.stringify(summary);

  assert.equal(runner.spec.HostConfig.Privileged, false);
  assert.equal(runner.spec.HostConfig.ReadonlyRootfs, true);
  assert.deepEqual(runner.spec.HostConfig.CapDrop, ['ALL']);
  assert.match(runner.spec.HostConfig.SecurityOpt.join(','), /no-new-privileges/);
  assert.deepEqual(runner.spec.HostConfig.Devices, []);
  assert.deepEqual(runner.spec.HostConfig.PortBindings, {});
  assert.deepEqual(runner.spec.HostConfig.Binds, [`${workdir}:${workdir}:rw`]);
  assert.equal(runner.spec.HostConfig.PidsLimit, 512);
  assert.deepEqual(runner.spec.HostConfig.Ulimits, [
    { Name: 'nofile', Soft: 8192, Hard: 8192 },
  ]);
  assert.equal(
    runner.spec.HostConfig.Ulimits.some((limit) => limit.Name === 'nproc'),
    false,
  );
  const lowerTaskBudget = buildRunnerSpec({
    runId: 'run-low-task-budget',
    mode: 'learn',
    image: 'nosh@sha256:test',
    name: 'agent-low-task-budget',
    workdir,
    resources: { pids: 7 },
  });
  assert.equal(lowerTaskBudget.spec.HostConfig.PidsLimit, 7);
  assert.deepEqual(lowerTaskBudget.spec.HostConfig.Ulimits, [
    { Name: 'nofile', Soft: 8192, Hard: 8192 },
  ]);
  const identity = fs.statSync(workdir);
  assert.equal(
    runner.spec.HostConfig.Tmpfs['/home/nosh-guard'],
    'rw,nosuid,nodev,noexec,size=536870912,mode=0700,' +
      `uid=${identity.uid},gid=${identity.gid}`,
  );
  for (const expected of [
    'HOME=/home/nosh-guard',
    'XDG_CACHE_HOME=/home/nosh-guard/.cache',
    'XDG_CONFIG_HOME=/home/nosh-guard/.config',
    'XDG_DATA_HOME=/home/nosh-guard/.local/share',
    'XDG_RUNTIME_DIR=/home/nosh-guard/.runtime',
    'XDG_STATE_HOME=/home/nosh-guard/.local/state',
  ]) {
    assert.ok(runner.spec.Env.includes(expected), `missing ${expected}`);
  }
  assert.doesNotMatch(runner.spec.Env.join('\n'), /HOME=\/home\/attacker/);
  assert.match(runner.spec.Cmd[0], /mkdir -p "\$XDG_CONFIG_HOME"/);
  assert.doesNotMatch(
    runner.spec.Env.join('\n'),
    /NOTTY_MCP_SPAWN_OTP|NOTTY_BASIC_AUTH_(?:PASSWORD|USERNAME)/,
  );
  assert.doesNotMatch(serialized, /runner-otp|runner-password/);
  assert.doesNotMatch(serialized, /\.codex|\.claude|\.gemini|docker\.sock/);
  assert.ok(
    runner.spec.Env.includes('ALLOWED_ORIGIN=https://guard.example:3443'),
  );
  assert.ok(
    runner.spec.Env.includes(
      'NOTTY_PUBLIC_WS_URL=wss://guard.example:3443/ws/terminals',
    ),
  );
  assert.doesNotMatch(runner.spec.Env.join('\n'), /attacker\.example/);
  assert.equal(runner.spec.Labels['io.notty.guard.run-id'], 'run-1');
  assert.equal(runner.spec.Labels['io.notty.guard.image-digest'], 'sha256:test');

  for (const mode of ['egress-learn', 'egress-audit', 'egress-enforce']) {
    const scoped = buildRunnerSpec({
      runId: `run-${mode}`,
      mode,
      image: 'nosh@sha256:test',
      imageDigest: 'sha256:test',
      name: mode,
      workdir,
    });
    assert.deepEqual(scoped.spec.HostConfig.SecurityOpt, [
      'no-new-privileges:true',
    ]);
    assert.equal(scoped.spec.HostConfig.ReadonlyRootfs, true);
    assert.deepEqual(scoped.spec.HostConfig.CapDrop, ['ALL']);
    assert.ok(scoped.spec.Env.includes(`NOTTY_SECURITY_MODE=${mode}`));
    assert.equal(
      scoped.spec.Env.includes('NOSH_GUARD_ENFORCEMENT_SCOPE=egress-only'),
      mode === 'egress-enforce',
    );
  }
});

test('runner gate uses a non-login shell and defers the app until release', async (t) => {
  const workdir = tempDir(t);
  const { buildRunnerSpec } = await importModule(
    'lib/guardd/runner-spec.js',
  );
  const runner = buildRunnerSpec({
    runId: 'run-gate-order',
    mode: 'egress-learn',
    image: 'nosh@sha256:test',
    imageDigest: 'sha256:test',
    name: 'gate-order',
    workdir,
    startApp: true,
  });

  assert.deepEqual(runner.spec.Entrypoint, ['/bin/sh', '-c']);
  assert.equal(runner.spec.Cmd.length, 1);
  const gate = runner.spec.Cmd[0];
  const gateEntered = "printf '%s\\n' 'nosh-guard: phase=gate-entered'";
  const makeRuntimeDirs = 'mkdir -p "$XDG_CONFIG_HOME"';
  const secureRuntimeDirs = 'chmod 0700 "$HOME"';
  const gateReady = "printf '%s\\n' 'nosh-guard: phase=gate-ready'";
  const releaseWait =
    'while [ ! -e /run/nosh-guard/release ]; do sleep 0.05; done';
  const commandExport = 'export NOSH_GUARD_COMMAND_B64=';
  assert.ok(gate.includes(gateEntered));
  assert.ok(gate.indexOf(gateEntered) < gate.indexOf(makeRuntimeDirs));
  assert.ok(gate.indexOf(secureRuntimeDirs) < gate.indexOf(gateReady));
  assert.ok(gate.indexOf(gateReady) < gate.indexOf(releaseWait));
  assert.ok(gate.indexOf(releaseWait) < gate.indexOf(commandExport));
  assert.ok(gate.indexOf(commandExport) < gate.indexOf('exec node -e'));

  const encodedCommand = gate.match(
    /(?:^|; )export NOSH_GUARD_COMMAND_B64=([A-Za-z0-9_-]+)(?:; |$)/,
  )?.[1];
  assert.ok(encodedCommand, 'gate must carry the deferred runner command');
  assert.deepEqual(
    JSON.parse(Buffer.from(encodedCommand, 'base64url').toString('utf8')),
    ['/bin/bash', '-lc', 'cd "/app" && exec npm run start:next:sse'],
  );
});

test('workspace admission binds the container mount to the verified directory inode', async (t) => {
  const workdir = tempDir(t);
  const { assertWorkspaceMountIdentity } = await importModule(
    'lib/guardd/service.js',
  );
  const stat = fs.statSync(workdir, { bigint: true });
  const expected = { dev: String(stat.dev), ino: String(stat.ino) };
  const verified = await assertWorkspaceMountIdentity({
    workdir,
    initPid: process.pid,
    expected,
  });
  assert.deepEqual(verified.host, expected);
  assert.deepEqual(verified.mounted, expected);
  await assert.rejects(
    assertWorkspaceMountIdentity({
      workdir,
      initPid: process.pid,
      expected: { ...expected, ino: String(stat.ino + 1n) },
    }),
    (error) => error.code === 'GUARD_EGRESS_WORKSPACE_IDENTITY_CHANGED',
  );
});

test('scoped egress mode contract activates only the intended evidence adapter', () => {
  const contract = JSON.parse(
    fs.readFileSync(
      path.join(appRoot, 'config', 'nosh-guard', 'mode-contract.json'),
      'utf8',
    ),
  );
  const adapters = JSON.parse(
    fs.readFileSync(
      path.join(appRoot, 'config', 'nosh-guard', 'adapters.json'),
      'utf8',
    ),
  ).adapters;
  const inputs = JSON.parse(
    fs.readFileSync(
      path.join(appRoot, 'config', 'nosh-guard', 'evidence-inputs.json'),
      'utf8',
    ),
  ).inputs;
  const evidenceSchema = JSON.parse(
    fs.readFileSync(
      path.join(
        appRoot,
        'config',
        'nosh-guard',
        'schemas',
        'evidence-manifest.schema.json',
      ),
      'utf8',
    ),
  );
  const requiredFor = (mode) =>
    adapters
      .filter((adapter) => adapter.requiredModes.includes(mode))
      .map((adapter) => adapter.name)
      .sort();
  const declaredEvidenceFor = (mode) =>
    inputs
      .filter((input) => input.requiredModes.includes(mode))
      .map((input) => input.name)
      .sort();

  assert.deepEqual(requiredFor('egress-learn'), ['nosh-egress']);
  assert.deepEqual(requiredFor('egress-audit'), ['nosh-egress']);
  assert.deepEqual(requiredFor('egress-enforce'), ['nosh-egress']);
  assert.deepEqual(
    contract.modes['egress-learn'].requiredEvidence,
    ['nosh-egress'],
  );
  assert.deepEqual(
    contract.modes['egress-audit'].requiredEvidence,
    ['nosh-egress'],
  );
  assert.deepEqual(
    contract.modes['egress-enforce'].requiredEvidence,
    ['nosh-egress'],
  );
  for (const mode of ['egress-learn', 'egress-audit', 'egress-enforce']) {
    assert.deepEqual(
      declaredEvidenceFor(mode),
      [...contract.modes[mode].requiredEvidence].sort(),
    );
  }
  assert.equal(
    contract.modes['egress-enforce'].fullProfileArtifactsLoaded,
    false,
  );
  assert.deepEqual(
    evidenceSchema.$defs.workspaceIdentity.required,
    ['dev', 'ino'],
  );
  const scopedSubjectRule = evidenceSchema.allOf.find((rule) =>
    rule.if?.properties?.mode?.enum?.includes('egress-learn')
    && rule.if.properties.mode.enum.includes('egress-audit')
    && rule.if.properties.mode.enum.includes('egress-enforce')
    && rule.then?.properties?.subject,
  );
  assert.ok(scopedSubjectRule);
  assert.ok(
    scopedSubjectRule.then.properties.subject.required.includes(
      'workspaceIdentity',
    ),
  );
});

test('egress health bypasses full ingress admission and host nft', async () => {
  const { guardModeGates } = await importModule('lib/guardd/health.js');
  const checks = Object.fromEntries(
    [
      'linux',
      'btf',
      'cgroupV2',
      'bpfLsm',
      'dockerSocket',
      'tetra',
      'nft',
      'apparmorParser',
      'standaloneIngress',
    ].map((name) => [name, { ok: true }]),
  );
  checks.standaloneIngress.ok = false;

  const gates = guardModeGates(checks);
  assert.equal(gates.enforce, false);
  assert.equal(gates['egress-enforce'], true);
  assert.equal(gates['egress-audit'], true);
  assert.equal(gates['egress-learn'], true);

  checks.nft.ok = false;
  const withoutNft = guardModeGates(checks);
  assert.equal(withoutNft['egress-enforce'], true);
  assert.equal(withoutNft['egress-audit'], true);
  assert.equal(withoutNft['egress-learn'], true);
});

test('scoped egress admission fails closed without installed eBPF backend health', async () => {
  const { GuardService } = await importModule('lib/guardd/service.js');
  const service = new GuardService({
    docker: {},
    egress: {},
    adapters: {},
    store: {},
  });

  for (const mode of ['egress-learn', 'egress-audit', 'egress-enforce']) {
    const health = await service.managedEgressRunHealth({ mode });
    assert.equal(health.ok, false, mode);
    assert.match(health.error, /nosh-egress-loader status failed|ENOENT/);
  }
  assert.equal(
    (await service.managedEgressRunHealth({ mode: 'learn' })).ok,
    true,
  );
});

test('scoped learning reuses proven terminal namespaces before releasing a runner', async (t) => {
  const root = tempDir(t);
  const workdir = path.join(root, 'workspace');
  fs.mkdirSync(workdir);
  const operations = [];
  let mountVerification = null;
  let connected = false;
  const fakeDocker = {
    async inspectImage() {
      operations.push('inspect-image');
      return {
        Id: 'sha256:image',
        RepoDigests: ['nosh@sha256:image'],
        Config: {
          Labels: {
            'io.notty.guard.runner-abi': '1',
          },
        },
      };
    },
    async ensureInternalNetwork() {
      operations.push('ensure-network');
      return { Internal: true };
    },
    async createContainer(name, spec) {
      operations.push('create');
      assert.equal(spec.HostConfig.NetworkMode, 'none');
      assert.deepEqual(spec.NetworkingConfig.EndpointsConfig, {});
      return { Id: 'container-1', Warnings: [] };
    },
    async startContainer() {
      operations.push('start');
    },
    async inspectContainer() {
      operations.push('inspect-container');
      return {
        Id: 'container-1',
        Image: 'sha256:image',
        State: { Running: true, Pid: 4242 },
        Config: {
          Labels: {
            'io.notty.guard.run-id': 'run-attach-order',
            'io.notty.guard.image-digest': 'sha256:image',
          },
        },
        NetworkSettings: {
          Networks: connected
            ? {
                'nosh-guard-test': {
                  IPAddress: '10.240.0.3',
                  GlobalIPv6Address: 'fd42:6e6f:7368:1::3',
                },
              }
            : {},
        },
      };
    },
    async connectNetwork(networkName, containerId, endpoint) {
      operations.push('connect-network');
      assert.equal(networkName, 'nosh-guard-test');
      assert.equal(containerId, 'container-1');
      assert.deepEqual(endpoint, {
        ipv4Address: '10.240.0.3',
        ipv6Address: 'fd42:6e6f:7368:1::3',
      });
      connected = true;
    },
    async releaseGate() {
      operations.push('release');
    },
    async stopContainer() {
      operations.push('stop');
    },
    async removeContainer() {
      operations.push('remove');
    },
  };
  const fakeAdapters = {
    async health() {
      operations.push('adapter-health');
      return [{ name: 'tetragon-events', required: true, ok: true }];
    },
    async attach() {
      operations.push('adapter-attach');
      return [{ name: 'tetragon-events', pid: 1234, longRunning: true }];
    },
    async detach() {
      operations.push('adapter-detach');
      return [];
    },
  };
  const fakeEgress = {
    async initialize() {},
    async prepareNetwork() {
      operations.push('prepare-egress');
      return {
        networkName: 'nosh-guard-test',
        runnerIp: '10.240.0.3',
        runnerIpv6: 'fd42:6e6f:7368:1::3',
        egressGateway: '10.240.0.2',
        dockerGateway: '10.240.0.1',
        dockerGatewayIpv6: 'fd42:6e6f:7368:1::1',
        gatewayContainerId: 'gateway-1',
      };
    },
    async attachRun() {
      operations.push('attach-egress');
      return {
        networkName: 'nosh-guard-test',
        sourceIpv4: '10.240.0.3',
        gatewayIpv4: '10.240.0.2',
      };
    },
    async detachRun() {
      operations.push('detach-egress');
      return { ok: true };
    },
    async runtimeHealth() {
      return { ok: true };
    },
  };
  const { GuardStateStore } = await importModule('lib/guardd/state-store.js');
  const { GuardService } = await importModule('lib/guardd/service.js');
  const store = new GuardStateStore(path.join(root, 'state'));
  const service = new GuardService({
    docker: fakeDocker,
    adapters: fakeAdapters,
    egress: fakeEgress,
    scopedEgress: scopedBackendFromLegacy(fakeEgress),
    ebpfActivations: { async initialize() {} },
    store,
    healthProvider: healthyHost,
    namespaceProvider: () => ({
      cgroup: '200',
      mnt: '201',
      net: '202',
      pid: '203',
      user: '204',
    }),
    cgroupProvider: async () => ({
      path: '/sys/fs/cgroup/nosh-test-1',
      id: '200',
      membership: '/nosh-test-1',
    }),
    hostNamespaceProvider: () => '100',
    workspaceMountVerifier: async (options) => {
      mountVerification = options;
    },
  });
  await service.initialize();
  await store.writeRun({
    runId: 'historical-failed-removed',
    status: 'failed',
    containerRemoved: true,
    namespaces: { cgroup: '200' },
  });
  await store.writeRun({
    runId: 'historical-stopped',
    status: 'stopped',
    namespaces: { cgroup: '200' },
  });
  await store.writeRun({
    runId: 'historical-completed',
    status: 'completed',
    namespaces: { cgroup: '200' },
  });

  const run = await service.startRun({
    runId: 'run-attach-order',
    mode: 'egress-learn',
    image: 'nosh',
    name: 'guard-test',
    workdir,
  });

  assert.equal(run.status, 'running');
  assert.equal(run.imageDigest, 'sha256:image');
  assert.equal(run.egress.sourceIpv6, 'fd42:6e6f:7368:1::3');
  assert.deepEqual(run.egress.platformContainmentCidrs, [
    '10.240.0.1/32',
    'fd42:6e6f:7368:1::1/128',
  ]);
  assert.equal(run.egress.containmentCount, 2);
  assert.equal(
    run.egress.containmentDigest,
    platformContainmentIdentity(run.egress.platformContainmentCidrs).digest,
  );
  const workspaceStat = fs.statSync(workdir, { bigint: true });
  const expectedWorkspaceIdentity = {
    dev: String(workspaceStat.dev),
    ino: String(workspaceStat.ino),
  };
  assert.deepEqual(run.workspaceIdentity, expectedWorkspaceIdentity);
  assert.deepEqual(mountVerification, {
    workdir,
    initPid: 4242,
    expected: expectedWorkspaceIdentity,
  });
  assert.deepEqual(run.runnerImageAbi, {
    label: 'io.notty.guard.runner-abi',
    version: '1',
  });
  assert.ok(operations.indexOf('adapter-attach') < operations.indexOf('connect-network'));
  assert.ok(operations.indexOf('connect-network') < operations.indexOf('release'));
  assert.equal(
    operations.filter((operation) => operation === 'inspect-container').length,
    3,
  );
  assert.ok(
    operations.lastIndexOf('inspect-container') < operations.indexOf('release'),
  );
  assert.deepEqual(operations.slice(0, 8), [
    'inspect-image',
    'prepare-egress',
    'create',
    'start',
    'inspect-container',
    'adapter-health',
    'adapter-attach',
    'connect-network',
  ]);
  assert.ok(
    operations.indexOf('connect-network') < operations.indexOf('attach-egress'),
  );
});

test('quarantined and paused runs retain cgroup namespace ownership', async () => {
  const { runReservesCgroupNamespace } = await importModule(
    'lib/guardd/service.js',
  );
  for (const terminal of [
    { status: 'failed', containerRemoved: true },
    { status: 'removed' },
    { status: 'stopped' },
    { status: 'complete' },
    { status: 'completed' },
  ]) {
    assert.equal(runReservesCgroupNamespace(terminal), false);
  }
  for (const owner of [
    { status: 'failed', containerRemoved: false },
    { status: 'quarantined', containerRemoved: false },
    { status: 'failed', containerPaused: true },
    { status: 'running' },
    { status: 'identity-verified' },
    { status: 'future-unknown-status' },
    null,
  ]) {
    assert.equal(runReservesCgroupNamespace(owner), true);
  }
});

test('egress-enforce rejects legacy local approvals before touching Docker', async (t) => {
  const root = tempDir(t);
  const workdir = path.join(root, 'workspace');
  fs.mkdirSync(workdir);
  const operations = [];
  const imageDigest = `sha256:${'1'.repeat(64)}`;
  const approvalContentHash = `sha256:${'3'.repeat(64)}`;
  const workspaceKey = '4'.repeat(64);
  const { stableStringify } = await importModule('lib/guard/stable.js');
  const encode = (value) => `${stableStringify(value, 2)}\n`;
  const hash = (value) =>
    `sha256:${crypto.createHash('sha256').update(encode(value)).digest('hex')}`;
  const profile = { kind: 'NoshEgressProfile', revision: 'approved-1' };
  const policy = { kind: 'NoshEgressPolicy', egress: [] };
  const policyHash = hash(policy);
  const manifest = { kind: 'NoshEgressBundleManifest', revision: 'approved-1' };
  const approvedRules = [
    {
      destination: 'api.openai.com',
      protocol: 'tcp',
      ports: [443],
    },
  ];
  const approval = {
    kind: 'NoshEgressPolicyApproval',
    contentHash: approvalContentHash,
    rules: approvedRules,
  };
  const verification = {
    ok: true,
    revision: 'approved-1',
    workspace: workdir,
    workspaceIdentity: (() => {
      const stat = fs.statSync(workdir, { bigint: true });
      return { dev: String(stat.dev), ino: String(stat.ino) };
    })(),
    workspaceKey,
    imageDigest,
    rules: approvedRules,
    policyPath: path.join(root, 'profiles', 'egress-policy.json'),
    policyHash,
    artifacts: {
      'egress-profile.json': hash(profile),
      'egress-policy.json': hash(policy),
    },
    manifestHash: hash(manifest),
    approvalHash: approvalContentHash,
    approvalFileHash: hash(approval),
    profile,
    policy,
    manifest,
    approval,
  };
  let runnerSpec = null;
  let attachedProfile = null;
  const docker = {
    async inspectImage() {
      operations.push('inspect-image');
      return {
        Id: imageDigest,
        RepoDigests: [`nosh@${imageDigest}`],
        Config: {
          Labels: { 'io.notty.guard.runner-abi': '1' },
        },
      };
    },
    async createContainer(name, spec) {
      operations.push('create');
      runnerSpec = spec;
      return { Id: 'egress-enforce-container', Warnings: [] };
    },
    async startContainer() {
      operations.push('start');
    },
    async inspectContainer() {
      operations.push('inspect-container');
      return {
        Id: 'egress-enforce-container',
        Image: imageDigest,
        State: { Running: true, Pid: 5252 },
        Config: {
          Labels: {
            'io.notty.guard.run-id': 'run-egress-enforce',
            'io.notty.guard.image-digest': imageDigest,
          },
        },
        NetworkSettings: {
          Networks: {
            'nosh-guard-egress-enforce': { IPAddress: '10.240.10.3' },
          },
        },
      };
    },
    async releaseGate() {
      operations.push('release');
    },
  };
  const egress = {
    async initialize() {},
    async prepareNetwork() {
      operations.push('prepare-egress');
      return {
        networkName: 'nosh-guard-egress-enforce',
        runnerIp: '10.240.10.3',
        egressGateway: '10.240.10.2',
        gatewayContainerId: 'gateway-egress-enforce',
      };
    },
    async attachRun(run, inspected, allocation, policyPath, options) {
      operations.push('attach-egress');
      attachedProfile = { run, policyPath, options };
      return {
        networkName: allocation.networkName,
        sourceIpv4: allocation.runnerIp,
        gatewayIpv4: allocation.egressGateway,
        gatewayContainerId: allocation.gatewayContainerId,
        policyHash: `sha256:${'5'.repeat(64)}`,
      };
    },
    async runtimeHealth() {
      operations.push('egress-policy-health');
      return {
        ok: true,
        policyHash: `sha256:${'5'.repeat(64)}`,
        approvalHash: approvalContentHash,
        profilePolicyHash: policyHash,
      };
    },
  };
  const adapters = {
    async health(mode) {
      operations.push(`adapter-health:${mode}`);
      return [];
    },
    async attach(mode) {
      operations.push(`adapter-attach:${mode}`);
      return [];
    },
  };
  const { GuardStateStore } = await importModule('lib/guardd/state-store.js');
  const { GuardService } = await importModule('lib/guardd/service.js');
  const service = new GuardService({
    docker,
    adapters,
    egress,
    scopedEgress: scopedBackendFromLegacy(egress),
    ebpfActivations: {
      async initialize() {},
      async verifyActive() {
        throw new Error('legacy profile rejection must precede activation lookup');
      },
    },
    store: new GuardStateStore(path.join(root, 'state')),
    healthProvider: healthyHost,
    egressProfiles: {
      async verifyApproval() {
        operations.push('verify-approval');
        return verification;
      },
      async verifyCandidate() {
        throw new Error('must not accept a candidate for enforcement');
      },
    },
    hostProfiles: {
      load() {
        throw new Error('must not load scoped policy as AppArmor');
      },
      remove() {
        throw new Error('must not remove an unattached AppArmor profile');
      },
    },
    namespaceProvider: () => ({
      cgroup: '520',
      mnt: '521',
      net: '522',
      pid: '523',
      user: '524',
    }),
    cgroupProvider: async () => ({
      path: '/sys/fs/cgroup/nosh-egress-enforce',
      id: '520',
      membership: '/nosh-egress-enforce',
    }),
    hostNamespaceProvider: () => '100',
    workspaceMountVerifier: async () => {},
  });
  await service.initialize();

  await assert.rejects(
    service.startRun({
      runId: 'run-egress-enforce',
      mode: 'egress-enforce',
      image: 'nosh',
      name: 'egress-enforce-runner',
      workdir,
      profileDir: path.join(root, 'profiles', 'approved-1'),
    }),
    (error) => error.code === 'GUARD_EBPF_ACTIVATION_REQUIRED',
  );
  assert.equal(operations.includes('verify-approval'), false);
  assert.equal(operations.includes('inspect-image'), false);
});

test('guard service rejects an incompatible runner image before network creation', async (t) => {
  const root = tempDir(t);
  const workdir = path.join(root, 'workspace');
  fs.mkdirSync(workdir);
  const operations = [];
  const { GuardStateStore } = await importModule('lib/guardd/state-store.js');
  const { GuardService } = await importModule('lib/guardd/service.js');
  const store = new GuardStateStore(path.join(root, 'state'));
  const service = new GuardService({
    store,
    healthProvider: healthyHost,
    docker: {
      async inspectImage() {
        operations.push('inspect-image');
        return {
          Id: 'sha256:untrusted',
          Config: {
            Labels: {
              'io.notty.guard.runner-abi': '2',
            },
          },
        };
      },
      async createContainer() {
        operations.push('create-container');
        throw new Error('must not create an incompatible runner');
      },
    },
    adapters: {},
    egress: {
      async initialize() {},
      async prepareNetwork() {
        operations.push('prepare-network');
        throw new Error('must not create a network for an incompatible runner');
      },
    },
  });
  await service.initialize();

  await assert.rejects(
    service.startRun({
      runId: 'run-incompatible-image',
      mode: 'learn',
      image: 'untrusted',
      name: 'incompatible-image',
      workdir,
    }),
    (error) =>
      error.code === 'GUARD_RUNNER_IMAGE_ABI_MISMATCH' &&
      error.expected === '1' &&
      error.actual === '2',
  );
  assert.deepEqual(operations, ['inspect-image']);
  const failed = await store.readRun('run-incompatible-image');
  assert.equal(failed.status, 'failed');
  assert.equal(failed.containerId, null);
  assert.equal(failed.failure.cleanupVerified, true);
});

test('stopped runner state survives fail-closed container removal', async (t) => {
  const root = tempDir(t);
  const workdir = path.join(root, 'workspace');
  fs.mkdirSync(workdir);
  const operations = [];
  const runId = 'run-stopped-before-release';
  const containerId = 'c'.repeat(64);
  const imageDigest = `sha256:${'d'.repeat(64)}`;
  const dockerRuntimeState = {
    ExitCode: 127,
    Error: 'gate command\ncould not start\u001b[31m',
    OOMKilled: false,
    Dead: false,
    StartedAt: '2026-08-20T12:00:00.000000000Z',
    FinishedAt: '2026-08-20T12:00:00.125000000Z',
  };
  const runtimeState = {
    ...dockerRuntimeState,
    Error: 'gate command\ufffdcould not start\ufffd[31m',
  };
  const { GuardStateStore } = await importModule('lib/guardd/state-store.js');
  const { GuardService } = await importModule('lib/guardd/service.js');
  const store = new GuardStateStore(path.join(root, 'state'));
  const fakeEgress = {
    async initialize() {},
    async prepareNetwork() {
      operations.push('prepare-network');
      return {
        networkName: 'nosh-guard-stopped',
        runnerIp: '10.240.12.3',
        runnerIpv6: 'fd42:6e6f:7368:12::3',
        egressGateway: '10.240.12.2',
        dockerGateway: '10.240.12.1',
        dockerGatewayIpv6: 'fd42:6e6f:7368:12::1',
        gatewayContainerId: 'gateway-stopped',
      };
    },
    async snapshotRun() {
      operations.push('snapshot-egress');
      return { complete: false };
    },
    async detachRun() {
      operations.push('detach-egress');
    },
  };
  const service = new GuardService({
    store,
    healthProvider: healthyHost,
    docker: {
      async inspectImage() {
        return {
          Id: imageDigest,
          Config: {
            Labels: {
              'io.notty.guard.runner-abi': '1',
            },
          },
        };
      },
      async createContainer() {
        operations.push('create');
        return { Id: containerId };
      },
      async startContainer() {
        operations.push('start');
      },
      async inspectContainer() {
        operations.push('inspect');
        return {
          Id: containerId,
          Image: imageDigest,
          State: {
            Running: false,
            Pid: 0,
            ...dockerRuntimeState,
            Health: { Status: 'unhealthy' },
          },
        };
      },
      async containerLogs(id, options) {
        operations.push('logs');
        assert.equal(id, containerId);
        assert.deepEqual(options, {
          tailLines: 40,
          maxWireBytes: 32 * 1024,
          maxTextBytes: 8 * 1024,
          timeoutMs: 2_000,
        });
        return {
          text: 'gate boot\nTOKEN=do-not-retain\n/bin/sh: gate\u001b failed',
          truncated: false,
        };
      },
      async stopContainer() {
        operations.push('stop');
      },
      async removeContainer() {
        operations.push('remove');
      },
    },
    adapters: {
      async detach() {
        operations.push('detach-adapters');
        return [];
      },
    },
    egress: fakeEgress,
    scopedEgress: scopedBackendFromLegacy(fakeEgress),
    ebpfActivations: { async initialize() {} },
  });
  await service.initialize();

  let startError = null;
  await assert.rejects(
    service.startRun({
      runId,
      mode: 'egress-learn',
      image: imageDigest,
      name: 'stopped-before-release',
      workdir,
    }),
    (error) => {
      startError = error;
      return error.code === 'GUARD_RUNTIME_IDENTITY_MISMATCH';
    },
  );

  assert.equal(startError.runId, runId);
  assert.equal(startError.containerId, containerId);
  assert.equal(startError.containerRemoved, true);
  assert.deepEqual(startError.runtimeState, runtimeState);
  assert.deepEqual(startError.runtimeLogTail, {
    text: 'gate boot\nTOKEN=[redacted]\n/bin/sh: gate\ufffd failed',
    truncated: false,
  });
  assert.equal(
    startError.message,
    'runner runtime identity mismatch: container is not running '
      + '(exit code 127; OOMKilled=false; '
      + 'Docker error: "gate command\ufffdcould not start\ufffd[31m"); '
      + 'container log: "/bin/sh: gate\ufffd failed"',
  );
  assert.deepEqual(operations, [
    'prepare-network',
    'create',
    'start',
    'inspect',
    'logs',
    'stop',
    'detach-adapters',
    'snapshot-egress',
    'remove',
    'detach-egress',
  ]);

  const listed = await service.listRuns();
  assert.equal(listed.length, 1);
  const [failed] = listed;
  assert.equal(failed.runId, runId);
  assert.equal(failed.containerId, containerId);
  assert.equal(failed.status, 'failed');
  assert.equal(failed.containerRemoved, true);
  assert.equal(fs.statSync(store.runPath(runId)).mode & 0o7777, 0o600);
  assert.deepEqual(failed.failure.runtimeState, runtimeState);
  assert.deepEqual(failed.failure.runtimeLogTail, startError.runtimeLogTail);
  assert.equal('Running' in failed.failure.runtimeState, false);
  assert.equal('Pid' in failed.failure.runtimeState, false);
  assert.equal('Health' in failed.failure.runtimeState, false);
});

test('rm releases a failed run that never created a container', async (t) => {
  const root = tempDir(t);
  const workdir = path.join(root, 'workspace');
  fs.mkdirSync(workdir);
  const { GuardStateStore } = await importModule('lib/guardd/state-store.js');
  const { GuardService } = await importModule('lib/guardd/service.js');
  const store = new GuardStateStore(path.join(root, 'state'));
  const service = new GuardService({
    store,
    healthProvider: healthyHost,
    docker: {
      async inspectImage() {
        return {
          Id: 'sha256:untrusted',
          Config: {
            Labels: {
              'io.notty.guard.runner-abi': '2',
            },
          },
        };
      },
    },
    adapters: {},
    egress: {
      async initialize() {},
    },
  });
  await service.initialize();

  await assert.rejects(
    service.startRun({
      runId: 'run-before-container',
      mode: 'learn',
      image: 'untrusted',
      name: 'before-container',
      workdir,
    }),
    { code: 'GUARD_RUNNER_IMAGE_ABI_MISMATCH' },
  );

  const removed = await service.runAction('before-container', 'rm');
  assert.equal(removed.status, 'removed');
  assert.equal(removed.containerRemoved, true);
  assert.equal(await store.findRun('before-container'), null);
});

test('egress image ABI failure remains pre-network and safely removable', async (t) => {
  const root = tempDir(t);
  const workdir = path.join(root, 'workspace');
  const stateDir = path.join(root, 'state');
  fs.mkdirSync(workdir);
  const operations = [];
  const docker = {
    async inspectImage(image) {
      operations.push(['inspectImage', image]);
      if (image === 'runner:test') {
        return {
          Id: 'sha256:runner',
          Config: {
            Labels: { 'io.notty.guard.runner-abi': '1' },
          },
        };
      }
      return {
        Id: 'sha256:stale-egress',
        Config: {
          Labels: { 'io.notty.guard.egress-abi': '0' },
        },
      };
    },
    async inspectContainer(name) {
      operations.push(['inspectContainer', name]);
      throw new Error('gateway inspection must not precede ABI validation');
    },
    async createContainer(name) {
      operations.push(['createContainer', name]);
      throw new Error('container creation must not precede ABI validation');
    },
    async createNetwork(name) {
      operations.push(['createNetwork', name]);
      throw new Error('network creation must not precede ABI validation');
    },
  };
  const { EgressManager } = await importModule(
    'lib/guardd/egress-manager.js',
  );
  const { GuardStateStore } = await importModule('lib/guardd/state-store.js');
  const { GuardService } = await importModule('lib/guardd/service.js');
  const store = new GuardStateStore(stateDir);
  const service = new GuardService({
    store,
    docker,
    healthProvider: healthyHost,
    adapters: {},
    egress: new EgressManager({
      docker,
      stateDir,
      image: 'egress:test',
    }),
  });
  await service.initialize();

  await assert.rejects(
    service.startRun({
      runId: 'run-stale-egress-abi',
      mode: 'learn',
      image: 'runner:test',
      name: 'stale-egress-abi',
      workdir,
    }),
    { code: 'GUARD_EGRESS_IMAGE_ABI_MISMATCH' },
  );
  assert.deepEqual(operations, [
    ['inspectImage', 'runner:test'],
    ['inspectImage', 'egress:test'],
  ]);
  const failed = await store.findRun('stale-egress-abi');
  assert.equal(failed.status, 'failed');
  assert.equal(failed.containerId, null);
  assert.equal(failed.failure.code, 'GUARD_EGRESS_IMAGE_ABI_MISMATCH');

  const removed = await service.runAction('stale-egress-abi', 'rm');
  assert.equal(removed.status, 'removed');
  assert.equal(removed.containerRemoved, true);
  assert.equal(await store.findRun('stale-egress-abi'), null);
});

test('rm keeps a containerless run reserved when its cleanup phase is unknown', async (t) => {
  const root = tempDir(t);
  const operations = [];
  const { GuardStateStore } = await importModule('lib/guardd/state-store.js');
  const { GuardService } = await importModule('lib/guardd/service.js');
  const store = new GuardStateStore(path.join(root, 'state'));
  const service = new GuardService({
    store,
    healthProvider: healthyHost,
    docker: {},
    adapters: {},
    egress: {
      async initialize() {},
      async detachRun() {
        operations.push('detach-egress');
      },
    },
  });
  await service.initialize();
  await store.writeRun({
    runId: 'run-containerless-quarantine',
    name: 'containerless-quarantine',
    mode: 'egress-learn',
    status: 'failed',
    containerId: null,
    quarantineActive: false,
    cleanupFailures: [],
    failure: {
      code: 'GUARD_EGRESS_NETWORK_SETUP_FAILED',
      message: 'network setup failed after mutation',
    },
  });

  await assert.rejects(
    service.runAction('containerless-quarantine', 'rm'),
    (error) =>
      error.code === 'GUARD_CLEANUP_INCOMPLETE'
      && error.statusCode === 409,
  );
  assert.deepEqual(operations, []);
  assert.equal(
    (await store.findRun('containerless-quarantine')).status,
    'failed',
  );

  await store.writeRun({
    runId: 'run-containerless-verified',
    name: 'containerless-verified',
    mode: 'egress-enforce',
    status: 'failed',
    containerId: null,
    quarantineActive: false,
    cleanupFailures: [],
    failure: {
      code: 'GUARD_EBPF_ACTIVATION_REQUIRED',
      message: 'no signed activation is installed',
      cleanupVerified: true,
    },
  });
  const removed = await service.runAction('containerless-verified', 'rm');
  assert.equal(removed.status, 'removed');
  assert.equal(await store.findRun('containerless-verified'), null);

  await store.writeRun({
    runId: 'run-containerless-backend-preflight',
    name: 'containerless-backend-preflight',
    mode: 'egress-learn',
    status: 'failed',
    containerId: null,
    quarantineActive: false,
    cleanupFailures: [],
    failure: {
      code: 'GUARD_EBPF_EGRESS_BACKEND_UNHEALTHY',
      message: 'bpffs was not mounted before network preparation',
    },
  });
  const preflightRemoved = await service.runAction(
    'containerless-backend-preflight',
    'rm',
  );
  assert.equal(preflightRemoved.status, 'removed');
  assert.equal(
    await store.findRun('containerless-backend-preflight'),
    null,
  );
});

test('rm retries AppArmor cleanup for a verified pre-network failure', async (t) => {
  const root = tempDir(t);
  const workdir = path.join(root, 'workspace');
  const profileDir = path.join(root, 'candidate');
  fs.mkdirSync(workdir);
  const imageDigest = `sha256:${'a'.repeat(64)}`;
  const {
    compileGuardProfile,
    writeCompiledProfile,
  } = await importModule('lib/guard/index.js');
  writeCompiledProfile(
    profileDir,
    compileGuardProfile(
      [
        {
          schemaVersion: 1,
          source: { kind: 'tetragon', name: 'tetragon', version: '1.7.0' },
          runId: 'run-containerless-apparmor',
          event: { type: 'syscall', name: 'read' },
        },
      ],
      {
        name: 'containerless-apparmor',
        imageDigest,
      },
    ),
  );
  const operations = [];
  let removalAttempts = 0;
  const { GuardStateStore } = await importModule('lib/guardd/state-store.js');
  const { GuardService } = await importModule('lib/guardd/service.js');
  const store = new GuardStateStore(path.join(root, 'state'));
  const service = new GuardService({
    store,
    healthProvider: healthyHost,
    docker: {
      async inspectImage() {
        return {
          Id: imageDigest,
          Config: {
            Labels: {
              'io.notty.guard.runner-abi': '1',
            },
          },
        };
      },
    },
    adapters: {},
    egress: {
      async initialize() {},
      async prepareNetwork() {
        operations.push('prepare-network');
        const error = new Error('trusted egress image is missing');
        error.code = 'GUARD_EGRESS_IMAGE_MISSING';
        throw error;
      },
    },
    hostProfiles: {
      load(profilePath) {
        operations.push(`load-apparmor:${profilePath}`);
      },
      remove(profilePath) {
        removalAttempts += 1;
        operations.push(`remove-apparmor:${profilePath}`);
        return removalAttempts === 1
          ? { removed: false, error: 'transient unload failure' }
          : { removed: true };
      },
    },
  });
  await service.initialize();

  await assert.rejects(
    service.startRun({
      runId: 'run-containerless-apparmor',
      mode: 'audit',
      image: imageDigest,
      name: 'containerless-apparmor',
      workdir,
      profileDir,
    }),
    { code: 'GUARD_EGRESS_IMAGE_MISSING' },
  );
  const failed = await store.readRun('run-containerless-apparmor');
  assert.equal(failed.status, 'quarantined');
  assert.equal(failed.containerId, null);
  assert.equal(failed.failure.code, 'GUARD_EGRESS_IMAGE_MISSING');
  assert.equal(typeof failed.runtimeAppArmorProfile, 'string');
  assert.ok(failed.runtimeAppArmorProfile.endsWith('apparmor.profile'));
  assert.deepEqual(
    failed.cleanupFailures.map((failure) => failure.name),
    ['apparmor'],
  );

  const removed = await service.runAction('containerless-apparmor', 'rm');
  assert.equal(removed.status, 'removed');
  assert.deepEqual(removed.apparmorResult, { removed: true });
  assert.deepEqual(operations, [
    `load-apparmor:${failed.runtimeAppArmorProfile}`,
    'prepare-network',
    `remove-apparmor:${failed.runtimeAppArmorProfile}`,
    `remove-apparmor:${failed.runtimeAppArmorProfile}`,
  ]);
  assert.equal(await store.findRun('containerless-apparmor'), null);
});

test('scoped runner stays gated and is cleaned up when post-policy network attach fails', async (t) => {
  const root = tempDir(t);
  const workdir = path.join(root, 'workspace');
  fs.mkdirSync(workdir);
  const operations = [];
  const fakeDocker = {
    async inspectImage() {
      return {
        Id: 'sha256:image',
        Config: {
          Labels: {
            'io.notty.guard.runner-abi': '1',
          },
        },
      };
    },
    async ensureInternalNetwork() {},
    async createContainer() {
      return { Id: 'container-2' };
    },
    async startContainer() {},
    async inspectContainer() {
      return {
        Id: 'container-2',
        Image: 'sha256:image',
        State: { Running: true, Pid: 4243 },
        Config: {
          Labels: {
            'io.notty.guard.run-id': 'run-fail-closed',
            'io.notty.guard.image-digest': 'sha256:image',
          },
        },
        NetworkSettings: {
          Networks: {},
        },
      };
    },
    async connectNetwork() {
      operations.push('connect-network');
      throw new Error('network attach failed after policy attestation');
    },
    async releaseGate() {
      operations.push('release');
    },
    async stopContainer() {
      operations.push('stop');
    },
    async removeContainer() {
      operations.push('remove');
    },
  };
  const fakeAdapters = {
    async health() {
      return [];
    },
    async attach() {
      operations.push('adapter-attach');
      return [];
    },
    async detach() {
      operations.push('detach');
      return [];
    },
  };
  let policyHealthChecks = 0;
  const fakeEgress = {
    async initialize() {},
    async prepareNetwork() {
      return {
        networkName: 'nosh-guard-test',
        runnerIp: '10.240.0.3',
        runnerIpv6: 'fd42:6e6f:7368:2::3',
        egressGateway: '10.240.0.2',
        dockerGateway: '10.240.0.1',
        dockerGatewayIpv6: 'fd42:6e6f:7368:2::1',
        gatewayContainerId: 'gateway-1',
      };
    },
    async attachRun() {
      return {
        networkName: 'nosh-guard-test',
        sourceIpv4: '10.240.0.3',
        gatewayIpv4: '10.240.0.2',
      };
    },
    async runtimeHealth() {
      policyHealthChecks += 1;
      operations.push(`policy-health-${policyHealthChecks}`);
      return { ok: true };
    },
    async detachRun() {
      operations.push('detach-egress');
      return { ok: true };
    },
  };
  const { GuardStateStore } = await importModule('lib/guardd/state-store.js');
  const { GuardService } = await importModule('lib/guardd/service.js');
  const store = new GuardStateStore(path.join(root, 'state'));
  const service = new GuardService({
    docker: fakeDocker,
    adapters: fakeAdapters,
    egress: fakeEgress,
    scopedEgress: scopedBackendFromLegacy(fakeEgress, {
      attestRun(run) {
        operations.push('attest-policy');
        return {
          apiVersion: 'notty.dev/v1alpha1',
          kind: 'NoshEbpfEgressRuntimeAttestation',
          runId: run.runId,
          policyDigest: run.egress.policyDigest,
          containmentDigest: run.egress.containmentDigest,
          containmentCount: run.egress.containmentCount,
          policyGeneration: '1',
        };
      },
    }),
    ebpfActivations: { async initialize() {} },
    store,
    healthProvider: healthyHost,
    namespaceProvider: () => ({
      cgroup: '300',
      mnt: '301',
      net: '302',
      pid: '303',
      user: '304',
    }),
    cgroupProvider: async () => ({
      path: '/sys/fs/cgroup/nosh-test-2',
      id: '300',
      membership: '/nosh-test-2',
    }),
    hostNamespaceProvider: () => '100',
    workspaceMountVerifier: async () => {},
  });
  await service.initialize();

  await assert.rejects(
    service.startRun({
      runId: 'run-fail-closed',
      mode: 'egress-learn',
      image: 'nosh',
      name: 'guard-test',
      workdir,
    }),
    /network attach failed after policy attestation/,
  );
  assert.deepEqual(operations, [
    'adapter-attach',
    'attest-policy',
    'policy-health-1',
    'connect-network',
    'stop',
    'detach',
    'remove',
    'detach-egress',
  ]);
  assert.equal(operations.includes('release'), false);
  const failed = await store.readRun('run-fail-closed');
  assert.equal(failed.status, 'failed');
  assert.equal(failed.failure.cleanupVerified, true);
});

test('scoped startup failure retains BPF and network controls when only pause succeeds', async (t) => {
  const root = tempDir(t);
  const workdir = path.join(root, 'workspace');
  fs.mkdirSync(workdir);
  const operations = [];
  const docker = {
    async inspectImage() {
      return {
        Id: 'sha256:image',
        Config: {
          Labels: {
            'io.notty.guard.runner-abi': '1',
          },
        },
      };
    },
    async createContainer() {
      return { Id: 'container-pause-only' };
    },
    async startContainer() {},
    async inspectContainer() {
      return {
        Id: 'container-pause-only',
        Image: 'sha256:image',
        State: { Running: true, Pid: 4250 },
        Config: {
          Labels: {
            'io.notty.guard.run-id': 'run-pause-only',
            'io.notty.guard.image-digest': 'sha256:image',
          },
        },
        NetworkSettings: { Networks: {} },
      };
    },
    async connectNetwork() {
      operations.push('connect-network');
      throw new Error('network attach failed after policy attestation');
    },
    async stopContainer() {
      operations.push('stop');
      throw new Error('stop failed');
    },
    async pauseContainer() {
      operations.push('pause');
    },
    async removeContainer() {
      operations.push('remove');
      throw new Error('remove failed');
    },
  };
  const adapters = {
    async health() {
      return [];
    },
    async attach() {
      operations.push('adapter-attach');
      return [];
    },
    async detach() {
      operations.push('detach-adapters');
      return [];
    },
  };
  const scopedEgress = scopedBackendFromLegacy({
    async prepareNetwork() {
      return {
        networkName: 'nosh-guard-pause-only',
        runnerIp: '10.240.9.3',
        runnerIpv6: 'fd42:6e6f:7368:9::3',
        egressGateway: '10.240.9.1',
        dockerGateway: '10.240.9.1',
        dockerGatewayIpv6: 'fd42:6e6f:7368:9::1',
        gatewayContainerId: null,
      };
    },
    async attachRun() {
      return {};
    },
    async runtimeHealth() {
      operations.push('policy-health');
      return { ok: true };
    },
    async detachRun() {
      operations.push('detach-egress');
      return { ok: true };
    },
  }, {
    attestRun(run) {
      operations.push('attest-policy');
      return {
        apiVersion: 'notty.dev/v1alpha1',
        kind: 'NoshEbpfEgressRuntimeAttestation',
        runId: run.runId,
        policyDigest: run.egress.policyDigest,
        containmentDigest: run.egress.containmentDigest,
        containmentCount: run.egress.containmentCount,
        policyGeneration: '1',
      };
    },
  });
  const { GuardStateStore } = await importModule('lib/guardd/state-store.js');
  const { GuardService } = await importModule('lib/guardd/service.js');
  const store = new GuardStateStore(path.join(root, 'state'));
  const service = new GuardService({
    docker,
    adapters,
    egress: { async initialize() {} },
    scopedEgress,
    ebpfActivations: { async initialize() {} },
    store,
    healthProvider: healthyHost,
    namespaceProvider: () => ({
      cgroup: '310',
      mnt: '311',
      net: '312',
      pid: '313',
      user: '314',
    }),
    cgroupProvider: async () => ({
      path: '/sys/fs/cgroup/nosh-pause-only',
      id: '310',
      membership: '/nosh-pause-only',
    }),
    hostNamespaceProvider: () => '100',
    workspaceMountVerifier: async () => {},
  });
  await service.initialize();

  await assert.rejects(
    service.startRun({
      runId: 'run-pause-only',
      mode: 'egress-learn',
      image: 'nosh',
      name: 'pause-only',
      workdir,
    }),
    /network attach failed after policy attestation/,
  );

  assert.equal(operations.includes('detach-egress'), false);
  assert.deepEqual(operations, [
    'adapter-attach',
    'attest-policy',
    'policy-health',
    'connect-network',
    'stop',
    'pause',
    'detach-adapters',
    'remove',
  ]);
  const failed = await store.readRun('run-pause-only');
  assert.equal(failed.status, 'quarantined');
  assert.equal(failed.containerRemoved, false);
  assert.equal(failed.containerPaused, true);
  assert.equal(failed.failure.cleanupVerified, false);
  assert.deepEqual(
    failed.cleanupFailures.map((failure) => failure.name),
    ['docker-container'],
  );
});

test('start failure keeps every control attached when containment fails', async (t) => {
  const root = tempDir(t);
  const workdir = path.join(root, 'workspace');
  fs.mkdirSync(workdir);
  const operations = [];
  const { GuardStateStore } = await importModule('lib/guardd/state-store.js');
  const { GuardService } = await importModule('lib/guardd/service.js');
  const store = new GuardStateStore(path.join(root, 'state'));
  const service = new GuardService({
    store,
    healthProvider: healthyHost,
    namespaceProvider: () => ({
      cgroup: '700',
      mnt: '701',
      net: '702',
      pid: '703',
      user: '704',
    }),
    cgroupProvider: async () => ({
      path: '/sys/fs/cgroup/start-containment',
      id: '700',
      membership: '/start-containment',
    }),
    hostNamespaceProvider: () => '100',
    docker: {
      async inspectImage() {
        return {
          Id: 'sha256:image',
          Config: {
            Labels: {
              'io.notty.guard.runner-abi': '1',
            },
          },
        };
      },
      async createContainer() {
        return { Id: 'container-start-containment' };
      },
      async startContainer() {},
      async inspectContainer() {
        return {
          Id: 'container-start-containment',
          Image: 'sha256:image',
          State: { Running: true, Pid: 7000 },
          Config: {
            Labels: {
              'io.notty.guard.run-id': 'run-start-containment',
              'io.notty.guard.image-digest': 'sha256:image',
            },
          },
          NetworkSettings: {
            Networks: {
              'nosh-guard-start': { IPAddress: '10.240.7.3' },
            },
          },
        };
      },
      async stopContainer() {
        operations.push('stop');
        throw new Error('stop failed');
      },
      async pauseContainer() {
        operations.push('pause');
        throw new Error('pause failed');
      },
      async removeContainer() {
        operations.push('remove');
        throw new Error('remove failed');
      },
    },
    adapters: {
      async health() {
        return [{ name: 'required-monitor', required: true, ok: false }];
      },
      async detach() {
        operations.push('detach-adapters');
        return [];
      },
    },
    egress: {
      async initialize() {},
      async prepareNetwork() {
        return {
          networkName: 'nosh-guard-start',
          runnerIp: '10.240.7.3',
          egressGateway: '10.240.7.2',
          gatewayContainerId: 'gateway-start',
        };
      },
      async attachRun(run) {
        assert.equal(run.initPid, 7000);
        return {
          networkName: 'nosh-guard-start',
          sourceIpv4: '10.240.7.3',
          gatewayIpv4: '10.240.7.2',
          gatewayContainerId: 'gateway-start',
        };
      },
      async detachRun() {
        operations.push('detach-egress');
      },
    },
  });
  await service.initialize();

  await assert.rejects(
    service.startRun({
      runId: 'run-start-containment',
      mode: 'learn',
      image: 'nosh',
      name: 'start-containment',
      workdir,
    }),
    /required guard adapters are unhealthy/,
  );

  assert.deepEqual(operations, ['stop', 'pause', 'remove']);
  const failed = await store.readRun('run-start-containment');
  assert.equal(failed.status, 'quarantined');
  assert.equal(failed.containerRemoved, false);
  assert.equal(failed.containerPaused, false);
  assert.deepEqual(
    failed.cleanupFailures.map((failure) => failure.name),
    ['docker-containment'],
  );
});

test('rm recontains stale state and retains controls if containment fails', async (t) => {
  const root = tempDir(t);
  const operations = [];
  const { GuardStateStore } = await importModule('lib/guardd/state-store.js');
  const { GuardService } = await importModule('lib/guardd/service.js');
  const store = new GuardStateStore(path.join(root, 'state'));
  const service = new GuardService({
    store,
    healthProvider: healthyHost,
    docker: {
      async stopContainer() {
        operations.push('stop');
        throw new Error('stop failed');
      },
      async pauseContainer() {
        operations.push('pause');
        throw new Error('pause failed');
      },
      async removeContainer() {
        operations.push('remove');
        throw new Error('remove failed');
      },
    },
    adapters: {
      async detach() {
        operations.push('detach-adapters');
        return [];
      },
    },
    egress: {
      async initialize() {},
      async detachRun() {
        operations.push('detach-egress');
      },
    },
    hostProfiles: {
      remove() {
        operations.push('remove-apparmor');
        return { removed: true };
      },
    },
  });
  await service.initialize();
  await store.writeRun({
    runId: 'run-rm-containment',
    name: 'rm-containment',
    mode: 'enforce',
    status: 'stopped',
    containerId: 'container-rm-containment',
    runtimeAppArmorProfile: '/run/nosh-guard/apparmor.profile',
    adapters: [{ name: 'tetragon-policy', cleanupCritical: true }],
    detachResults: [],
    cleanupFailures: [],
    evidenceComplete: false,
  });

  await assert.rejects(
    service.runAction('run-rm-containment', 'rm'),
    (error) => error.code === 'GUARD_CONTAINER_CONTAINMENT_FAILED',
  );
  assert.deepEqual(operations, ['stop', 'pause', 'remove']);
  const quarantined = await store.readRun('run-rm-containment');
  assert.equal(quarantined.status, 'quarantined');
  assert.equal(quarantined.quarantineActive, true);
  assert.deepEqual(
    quarantined.cleanupFailures.map((failure) => failure.name),
    ['docker-containment'],
  );
});

test('watchdog quarantines runtime and managed-policy drift before detaching', async (t) => {
  const root = tempDir(t);
  const operations = [];
  const { GuardStateStore } = await importModule('lib/guardd/state-store.js');
  const { GuardService } = await importModule('lib/guardd/service.js');
  const store = new GuardStateStore(path.join(root, 'state'));
  const docker = {
    async inspectContainer() {
      operations.push('inspect');
      return {
        Id: 'container-watchdog',
        Image: 'sha256:drifted',
        State: { Running: true, Pid: 5000 },
        Config: {
          Labels: {
            'io.notty.guard.run-id': 'run-watchdog',
            'io.notty.guard.image-digest': 'sha256:expected',
          },
        },
        NetworkSettings: {
          Networks: {
            'nosh-guard-watchdog': { IPAddress: '10.240.1.3' },
          },
        },
      };
    },
    async pauseContainer() {
      operations.push('pause');
      throw new Error('pause failed');
    },
    async removeContainer() {
      operations.push('remove');
    },
  };
  const adapters = {
    async runtimeHealth() {
      operations.push('runtime-health');
      return [];
    },
    async detach() {
      operations.push('detach');
      return [];
    },
  };
  const egress = {
    async initialize() {},
    async health() {
      return { ok: true, containerId: 'gateway-watchdog' };
    },
    async runtimeHealth() {
      operations.push('egress-policy-health');
      return { ok: false, error: 'approval or policy hash changed' };
    },
    async snapshotRun(run) {
      operations.push('snapshot');
      return {
        source: 'managed_gateway',
        type: 'counter_snapshot_attestation',
        runId: run.runId,
        policyHash: run.egress.policyHash,
        nonce: 'snapshot-nonce',
        complete: true,
        evidenceRecordHash: `sha256:${'f'.repeat(64)}`,
      };
    },
  };
  const service = new GuardService({
    docker,
    adapters,
    egress,
    store,
    healthProvider: healthyHost,
  });
  await service.initialize();
  const evidenceDir = store.evidencePath('run-watchdog');
  fs.mkdirSync(evidenceDir, { recursive: true });
  await store.writeRun({
    runId: 'run-watchdog',
    name: 'watchdog-runner',
    mode: 'enforce',
    status: 'running',
    containerId: 'container-watchdog',
    imageDigest: 'sha256:expected',
    initPid: 4000,
    namespaces: {
      cgroup: '400',
      mnt: '401',
      net: '402',
      pid: '403',
      user: '404',
    },
    cgroup: {
      path: '/sys/fs/cgroup/watchdog',
      id: '400',
      membership: '/watchdog',
    },
    adapters: [],
    evidenceDir,
    evidenceComplete: true,
    egress: {
      networkName: 'nosh-guard-watchdog',
      sourceIpv4: '10.240.1.3',
      gatewayContainerId: 'gateway-watchdog',
      policyHash: `sha256:${'a'.repeat(64)}`,
      acknowledgement: {
        source: 'managed_gateway',
        type: 'policy_attestation',
        runId: 'run-watchdog',
        policyHash: `sha256:${'a'.repeat(64)}`,
      },
    },
  });

  const [quarantined] = await service.watchdogTick();
  assert.equal(quarantined.status, 'quarantined');
  assert.equal(quarantined.containerRemoved, true);
  assert.equal(quarantined.evidenceComplete, false);
  assert.ok(
    operations.indexOf('remove') < operations.indexOf('detach'),
    `expected removal before detach, got ${operations.join(', ')}`,
  );
  assert.deepEqual(
    quarantined.quarantine.failures.map((failure) => failure.name),
    ['runtime-identity', 'managed-egress-policy'],
  );
});

test('watchdog keeps enforcement attached when emergency containment fails', async (t) => {
  const root = tempDir(t);
  const operations = [];
  const { GuardStateStore } = await importModule('lib/guardd/state-store.js');
  const { GuardService } = await importModule('lib/guardd/service.js');
  const store = new GuardStateStore(path.join(root, 'state'));
  const service = new GuardService({
    store,
    healthProvider: healthyHost,
    docker: {
      async inspectContainer() {
        throw new Error('container identity unavailable');
      },
      async pauseContainer() {
        operations.push('pause');
        throw new Error('pause failed');
      },
      async removeContainer() {
        operations.push('remove');
        throw new Error('remove failed');
      },
    },
    adapters: {
      async runtimeHealth() {
        return [];
      },
      async detach() {
        operations.push('detach');
        return [];
      },
    },
    egress: {
      async initialize() {},
      async health() {
        return { ok: true, containerId: 'gateway-containment' };
      },
      async snapshotRun() {
        operations.push('snapshot');
        return {};
      },
    },
  });
  await service.initialize();
  const evidenceDir = store.evidencePath('run-containment');
  fs.mkdirSync(evidenceDir, { recursive: true });
  await store.writeRun({
    runId: 'run-containment',
    name: 'containment-runner',
    mode: 'enforce',
    status: 'running',
    containerId: 'container-containment',
    imageDigest: 'sha256:expected',
    initPid: 6000,
    namespaces: { cgroup: '600' },
    cgroup: {
      path: '/sys/fs/cgroup/containment',
      id: '600',
      membership: '/containment',
    },
    adapters: [{ name: 'tetragon-enforce-policy', cleanupCritical: true }],
    evidenceDir,
    evidenceComplete: true,
    egress: {
      gatewayContainerId: 'gateway-containment',
    },
  });

  const [quarantined] = await service.watchdogTick();
  assert.equal(quarantined.status, 'quarantined');
  assert.equal(quarantined.quarantineActive, true);
  assert.deepEqual(operations, ['pause', 'remove']);
  assert.deepEqual(
    quarantined.cleanupFailures.map((failure) => failure.name),
    ['docker-containment'],
  );
});

test('stop captures final gateway counters before evidence finalization', async (t) => {
  const root = tempDir(t);
  const stateDir = path.join(root, 'state');
  const operations = [];
  const policyHash = `sha256:${'b'.repeat(64)}`;
  const runId = 'run-final-snapshot';
  const dnsEvidenceKey = crypto.createHash('sha256').update(runId).digest('hex');
  const dnsEvidencePath = path.join(
    stateDir,
    'egress',
    'evidence',
    'managed-dns',
    `${dnsEvidenceKey}.log`,
  );
  const counter = {
    schemaVersion: 1,
    source: 'managed_gateway',
    type: 'counter_snapshot',
    runId,
    policyHash,
    complete: true,
    decision: 'observed',
    wouldDenyCount: 0,
    deniedCount: 0,
    counters: [],
    error: null,
  };
  const recordHash = `sha256:${require('node:crypto')
    .createHash('sha256')
    .update(JSON.stringify(counter))
    .digest('hex')}`;
  const { GuardStateStore } = await importModule('lib/guardd/state-store.js');
  const { GuardService } = await importModule('lib/guardd/service.js');
  const store = new GuardStateStore(stateDir);
  const egressEvidenceDir = path.join(stateDir, 'egress', 'evidence');
  const service = new GuardService({
    store,
    healthProvider: healthyHost,
    docker: {
      async stopContainer() {
        operations.push('stop');
      },
    },
    adapters: {
      async detach() {
        operations.push('detach');
        return [];
      },
    },
    egress: {
      async initialize() {
        fs.mkdirSync(egressEvidenceDir, { recursive: true });
        fs.mkdirSync(path.dirname(dnsEvidencePath), { recursive: true });
        fs.writeFileSync(
          dnsEvidencePath,
          '',
          { mode: 0o600 },
        );
        fs.writeFileSync(
          path.join(egressEvidenceDir, 'managed-gateway-counters.ndjson'),
          '',
        );
      },
      async snapshotRun() {
        operations.push('snapshot');
        fs.writeFileSync(
          path.join(egressEvidenceDir, 'managed-gateway-counters.ndjson'),
          `${JSON.stringify(counter)}\n`,
        );
        return {
          schemaVersion: 1,
          source: 'managed_gateway',
          type: 'counter_snapshot_attestation',
          runId,
          policyHash,
          nonce: 'final-snapshot-nonce',
          complete: true,
          evidenceRecordHash: recordHash,
        };
      },
    },
  });
  await service.initialize();
  const evidenceDir = store.evidencePath(runId);
  fs.mkdirSync(evidenceDir, { recursive: true });
  const dnsStat = fs.statSync(
    dnsEvidencePath,
    { bigint: true },
  );
  const gatewayStat = fs.statSync(
    path.join(egressEvidenceDir, 'managed-gateway-counters.ndjson'),
    { bigint: true },
  );
  await store.writeRun({
    runId,
    name: 'final-snapshot-runner',
    mode: 'enforce',
    status: 'running',
    containerId: 'container-final-snapshot',
    imageDigest: 'sha256:image',
    evidenceDir,
    evidenceComplete: true,
    adapters: [],
    egress: {
      sourceIpv4: '10.240.2.3',
      policyHash,
      evidenceOffsets: {
        dns: {
          offset: 0,
          dev: dnsStat.dev.toString(),
          ino: dnsStat.ino.toString(),
          evidenceKey: dnsEvidenceKey,
          maxBytes: 8 * 1024 * 1024,
        },
        gateway: {
          offset: 0,
          dev: gatewayStat.dev.toString(),
          ino: gatewayStat.ino.toString(),
        },
      },
      acknowledgement: {
        schemaVersion: 1,
        source: 'managed_gateway',
        type: 'policy_attestation',
        runId,
        policyHash,
      },
    },
  });

  const stopped = await service.runAction(runId, 'stop');
  assert.deepEqual(operations, ['stop', 'detach', 'snapshot']);
  assert.equal(stopped.egress.finalSnapshot.evidenceRecordHash, recordHash);
  const manifest = JSON.parse(
    fs.readFileSync(stopped.evidenceManifest, 'utf8'),
  );
  const gateway = manifest.sources.find(
    (source) => source.name === 'managed_gateway',
  );
  assert.equal(gateway.complete, true);
  assert.equal(
    gateway.completionMarker,
    'policy-and-final-counters-attested',
  );
});

test('allow-incomplete cannot bypass guarded admission', async () => {
  const { GuardService } = await importModule('lib/guardd/service.js');
  const service = new GuardService({
    allowIncomplete: true,
    docker: {},
    adapters: {},
    egress: {},
    store: {},
    healthProvider: () => ({ checks: {}, gates: { learn: false } }),
  });
  await assert.rejects(
    service.startRun({
      runId: 'run-incomplete-bypass',
      mode: 'learn',
      name: 'incomplete-bypass',
      image: 'nosh',
      workdir: process.cwd(),
      allowIncomplete: true,
    }),
    (error) => error.code === 'GUARD_INCOMPLETE_BYPASS_DISABLED',
  );
});

test('guard state rejects substituted directories and run-state symlinks', async (t) => {
  const root = tempDir(t);
  const target = path.join(root, 'state-target');
  const linkedState = path.join(root, 'state-link');
  fs.mkdirSync(target, { mode: 0o700 });
  fs.symlinkSync(target, linkedState);
  const { GuardStateStore } = await importModule('lib/guardd/state-store.js');
  await assert.rejects(
    new GuardStateStore(linkedState).initialize(),
    /must not contain symbolic links/,
  );

  const stateDir = path.join(root, 'state');
  fs.mkdirSync(stateDir, { mode: 0o755 });
  const store = new GuardStateStore(stateDir);
  await store.initialize();
  assert.equal(fs.statSync(stateDir).mode & 0o7777, 0o700);

  const external = path.join(root, 'external-run.json');
  fs.writeFileSync(
    external,
    `${JSON.stringify({ schemaVersion: 1, runId: 'linked-run' })}\n`,
    { mode: 0o600 },
  );
  fs.symlinkSync(external, store.runPath('linked-run'));
  await assert.rejects(store.readRun('linked-run'));
});

test('guard state binds file contents to the requested run identity', async (t) => {
  const root = tempDir(t);
  const { GuardStateStore } = await importModule('lib/guardd/state-store.js');
  const store = new GuardStateStore(path.join(root, 'state'));
  await store.initialize();
  await store.writeRun({ runId: 'expected-run', status: 'running' });
  const statePath = store.runPath('expected-run');
  const document = JSON.parse(fs.readFileSync(statePath, 'utf8'));
  document.runId = 'different-run';
  fs.writeFileSync(statePath, `${JSON.stringify(document)}\n`, { mode: 0o600 });

  await assert.rejects(
    store.readRun('expected-run'),
    /state identity does not match expected-run/,
  );
});

test('guard state writes always refresh updatedAt', async (t) => {
  const root = tempDir(t);
  const { GuardStateStore } = await importModule('lib/guardd/state-store.js');
  const store = new GuardStateStore(path.join(root, 'state'));
  await store.initialize();
  const staleUpdatedAt = '2000-01-01T00:00:00.000Z';

  const written = await store.writeRun({
    runId: 'updated-run',
    status: 'running',
    updatedAt: staleUpdatedAt,
  });
  const persisted = await store.readRun('updated-run');

  assert.notEqual(written.updatedAt, staleUpdatedAt);
  assert.equal(persisted.updatedAt, written.updatedAt);
});

test('adapter configuration rejects symlinks and writable trusted files', async (t) => {
  const root = tempDir(t);
  const config = path.join(root, 'adapters.json');
  const link = path.join(root, 'adapters-link.json');
  fs.writeFileSync(config, '{"schemaVersion":1,"adapters":[]}\n', {
    mode: 0o600,
  });
  fs.symlinkSync(config, link);
  const { AdapterController } = await importModule('lib/guardd/adapters.js');
  await assert.rejects(
    new AdapterController({ configPath: link }).loadConfig(),
    /symbolic links/,
  );

  fs.chmodSync(config, 0o666);
  const trusted = new AdapterController({
    configPath: config,
    trustedConfigUid: process.getuid(),
    trustedConfigRoot: root,
  });
  await assert.rejects(trusted.loadConfig(), /owned or writable safely/);
  fs.chmodSync(config, 0o600);
  assert.deepEqual(await trusted.loadConfig(), {
    schemaVersion: 1,
    adapters: [],
  });
});

test('required adapter modes cannot be narrowed by optional mode activation', async (t) => {
  const root = tempDir(t);
  const evidenceDir = path.join(root, 'evidence');
  const configPath = path.join(root, 'adapters.json');
  const commands = [];
  fs.writeFileSync(
    configPath,
    `${JSON.stringify({
      schemaVersion: 1,
      adapters: [
        {
          name: 'required-policy',
          requiredModes: ['enforce'],
          modes: ['learn'],
          health: { command: 'required-health', args: [] },
          attach: { command: 'required-attach', args: [] },
          detach: { command: 'true', args: [] },
          cleanupCritical: true,
          longRunning: false,
        },
        {
          name: 'nosh-url',
          requiredModes: [],
          modes: ['build-net-learn'],
          health: { command: 'url-health', args: [] },
          attach: { command: 'url-attach', args: [] },
          detach: { command: 'true', args: [] },
          evidenceRequired: false,
          cleanupCritical: true,
          longRunning: false,
        },
      ],
    })}\n`,
    { mode: 0o600 },
  );
  const { AdapterController } = await importModule('lib/guardd/adapters.js');
  const controller = new AdapterController({
    configPath,
    spawnSyncImpl(command, args) {
      commands.push([command, ...args]);
      if (command === 'url-health') {
        return { status: 0, stdout: 'healthy', stderr: '' };
      }
      return { status: 1, stdout: '', stderr: 'unavailable' };
    },
  });

  const requiredHealth = await controller.health('enforce');
  assert.equal(requiredHealth.length, 1);
  assert.equal(requiredHealth[0].name, 'required-policy');
  assert.equal(requiredHealth[0].required, true);
  assert.equal(requiredHealth[0].ok, false);

  const optionalHealth = await controller.health('build-net-learn');
  assert.equal(optionalHealth.length, 1);
  assert.equal(optionalHealth[0].name, 'nosh-url');
  assert.equal(optionalHealth[0].required, false);
  assert.equal(optionalHealth[0].ok, true);

  await assert.rejects(
    controller.attach('enforce', { evidenceDir }),
    /required adapter required-policy failed to attach/,
  );
  assert.deepEqual(commands, [
    ['required-health'],
    ['url-health'],
    ['required-attach'],
  ]);
});

test('adapter schema covers the trusted runtime and build configurations', () => {
  const schema = JSON.parse(fs.readFileSync(path.join(
    appRoot,
    'config',
    'nosh-guard',
    'schemas',
    'adapters.schema.json',
  ), 'utf8'));
  const topLevelProperties = new Set(Object.keys(schema.properties));
  const adapterProperties = new Set(
    Object.keys(schema.$defs.adapter.properties),
  );
  const commandProperties = new Set(
    Object.keys(schema.$defs.command.properties),
  );
  const readinessProperties = new Set(
    Object.keys(schema.$defs.readiness.properties),
  );
  const completionProperties = new Set(
    Object.keys(schema.$defs.completion.properties),
  );

  for (const relativePath of [
    ['nosh-guard', 'adapters.json'],
    ['nosh-build', 'adapters.json'],
  ]) {
    const document = JSON.parse(fs.readFileSync(path.join(
      appRoot,
      'config',
      ...relativePath,
    ), 'utf8'));
    for (const key of Object.keys(document)) {
      assert.ok(topLevelProperties.has(key), `schema omits top-level ${key}`);
    }
    for (const adapter of document.adapters) {
      for (const key of Object.keys(adapter)) {
        assert.ok(
          adapterProperties.has(key),
          `schema omits adapter ${adapter.name}.${key}`,
        );
      }
      for (const operation of ['health', 'attach', 'detach', 'verify']) {
        if (!adapter[operation]) continue;
        for (const key of Object.keys(adapter[operation])) {
          assert.ok(
            commandProperties.has(key),
            `schema omits ${adapter.name}.${operation}.${key}`,
          );
        }
      }
      for (const key of Object.keys(adapter.readiness || {})) {
        assert.ok(
          readinessProperties.has(key),
          `schema omits ${adapter.name}.readiness.${key}`,
        );
      }
      for (const key of Object.keys(adapter.completion || {})) {
        assert.ok(
          completionProperties.has(key),
          `schema omits ${adapter.name}.completion.${key}`,
        );
      }
    }
  }

  assert.deepEqual(
    schema.$defs.adapter.properties.detachSignal,
    { const: 'SIGTERM' },
  );
  assert.deepEqual(
    schema.$defs.adapter.properties.supportedDepths.items,
    { $ref: '#/$defs/depth' },
  );
  assert.deepEqual(
    schema.$defs.completion.required,
    ['stream', 'match', 'requireZero', 'diagnosticOnly'],
  );
});

test('adapter cleanup uses the detach command pinned at attachment time', async (t) => {
  const root = tempDir(t);
  const evidenceDir = path.join(root, 'evidence');
  const configPath = path.join(root, 'adapters.json');
  const commands = [];
  fs.writeFileSync(
    configPath,
    `${JSON.stringify({
      schemaVersion: 1,
      adapters: [
        {
          name: 'policy',
          requiredModes: ['learn'],
          health: { command: 'health', args: [] },
          attach: { command: 'attach-policy', args: ['{runId}'] },
          detach: { command: 'detach-original', args: ['{runId}'] },
          cleanupCritical: true,
          longRunning: false,
        },
      ],
    })}\n`,
    { mode: 0o600 },
  );
  const { AdapterController } = await importModule('lib/guardd/adapters.js');
  const controller = new AdapterController({
    configPath,
    spawnSyncImpl(command, args) {
      commands.push([command, ...args]);
      return { status: 0, stdout: '', stderr: '' };
    },
  });
  const context = {
    runId: 'pinned-run',
    evidenceDir,
  };
  const attached = await controller.attach('learn', context);
  fs.unlinkSync(configPath);

  const results = await controller.detach({ adapters: attached }, context);

  assert.deepEqual(commands, [
    ['attach-policy', 'pinned-run'],
    ['detach-original', 'pinned-run'],
  ]);
  assert.equal(results.length, 1);
  assert.equal(results[0].cleanupOk, true);
});

test('failed required attachment stays registered for post-containment cleanup', async (t) => {
  const root = tempDir(t);
  const evidenceDir = path.join(root, 'evidence');
  const configPath = path.join(root, 'adapters.json');
  const commands = [];
  fs.writeFileSync(
    configPath,
    `${JSON.stringify({
      schemaVersion: 1,
      adapters: [
        {
          name: 'policy',
          requiredModes: ['enforce'],
          health: { command: 'health', args: [] },
          attach: { command: 'attach-failing-policy', args: [] },
          detach: { command: 'detach-failing-policy', args: [] },
          cleanupCritical: true,
          longRunning: false,
        },
      ],
    })}\n`,
    { mode: 0o600 },
  );
  const { AdapterController } = await importModule('lib/guardd/adapters.js');
  const controller = new AdapterController({
    configPath,
    spawnSyncImpl(command, args) {
      commands.push([command, ...args]);
      return {
        status: command === 'attach-failing-policy' ? 1 : 0,
        stdout: '',
        stderr: command === 'attach-failing-policy' ? 'partial failure' : '',
      };
    },
  });
  const context = { runId: 'failed-policy-run', evidenceDir };
  let attachError;
  try {
    await controller.attach('enforce', context);
  } catch (error) {
    attachError = error;
  }

  assert.ok(attachError);
  assert.equal(attachError.attachedAdapters.length, 1);
  assert.equal(
    attachError.attachedAdapters[0].detachCommand.command,
    'detach-failing-policy',
  );
  assert.deepEqual(commands, [['attach-failing-policy']]);

  const cleanup = await controller.detach(
    { adapters: attachError.attachedAdapters },
    context,
  );
  assert.deepEqual(commands, [
    ['attach-failing-policy'],
    ['detach-failing-policy'],
  ]);
  assert.equal(cleanup[0].cleanupOk, true);
});

test('runtime health fails closed when a required adapter leaves config', async (t) => {
  const root = tempDir(t);
  const evidenceDir = path.join(root, 'evidence');
  const configPath = path.join(root, 'adapters.json');
  fs.writeFileSync(
    configPath,
    `${JSON.stringify({
      schemaVersion: 1,
      adapters: [
        {
          name: 'policy',
          requiredModes: ['enforce'],
          health: { command: 'health', args: [] },
          attach: { command: 'attach-policy', args: [] },
          detach: { command: 'detach-policy', args: [] },
          cleanupCritical: true,
          longRunning: false,
        },
      ],
    })}\n`,
    { mode: 0o600 },
  );
  const { AdapterController } = await importModule('lib/guardd/adapters.js');
  const controller = new AdapterController({
    configPath,
    spawnSyncImpl() {
      return { status: 0, stdout: '', stderr: '' };
    },
  });
  const context = { runId: 'runtime-config-run', evidenceDir };
  const adapters = await controller.attach('enforce', context);
  fs.writeFileSync(
    configPath,
    '{"schemaVersion":1,"adapters":[]}\n',
    { mode: 0o600 },
  );

  const [health] = await controller.runtimeHealth(
    { mode: 'enforce', adapters },
    context,
  );
  assert.equal(health.required, true);
  assert.equal(health.ok, false);
  assert.match(health.error, /missing from the trusted configuration/);
});

test('artifact approval detects post-approval tampering', async (t) => {
  const directory = tempDir(t);
  const {
    compileGuardProfile,
    writeCompiledProfile,
  } = await importModule('lib/guard/index.js');
  const compiled = compileGuardProfile(
    [
      {
        schemaVersion: 1,
        source: { kind: 'tetragon', name: 'tetragon', version: '1.7.0' },
        runId: 'approval-run',
        event: { type: 'syscall', name: 'read' },
      },
    ],
    {
      name: 'approval-test',
      imageDigest: `sha256:${'a'.repeat(64)}`,
      tetragon: {
        reviewedEnforcement: true,
        enforcementRules: {
          lsmhooks: [
            {
              hook: 'file_open',
              args: [{ index: 0, type: 'file' }],
              selectors: [
                {
                  matchNamespaces: [
                    {
                      namespace: 'Cgroup',
                      operator: 'In',
                      values: ['{cgroupNamespace}'],
                    },
                  ],
                  matchActions: [{ action: 'Override', argError: -13 }],
                },
              ],
            },
          ],
        },
      },
    },
  );
  writeCompiledProfile(directory, compiled);
  const profile = path.join(directory, 'profile.yaml');
  const { approveArtifactSet, verifyArtifactSet } = await importModule(
    'lib/guardd/approval.js',
  );

  const approval = await approveArtifactSet(directory, {
    revision: 'revision-1',
    reviewer: 'test-reviewer',
    promotionOverrideReason: 'unit fixture exercises artifact tamper detection',
  });
  assert.equal(approval.revision, 'revision-1');
  assert.equal(
    approval.promotionGate.override.reason,
    'unit fixture exercises artifact tamper detection',
  );
  assert.equal((await verifyArtifactSet(directory)).ok, true);

  fs.appendFileSync(profile, 'tampered\n');
  const verification = await verifyArtifactSet(directory);
  assert.equal(verification.ok, false);
  assert.deepEqual(
    verification.mismatches.map((entry) => entry.filename),
    ['profile.yaml'],
  );
});

test('public build CLI scopes and validates HTTP capture before delegation', (t) => {
  const root = tempDir(t);
  const context = path.join(root, 'context');
  const home = path.join(root, 'home');
  const launcher = path.join(appRoot, 'nosh.sh');
  fs.mkdirSync(context, { mode: 0o700 });
  fs.mkdirSync(home, { mode: 0o700 });
  fs.writeFileSync(path.join(context, 'Dockerfile'), 'FROM scratch\n', {
    mode: 0o600,
  });
  const run = (args) => childProcess.spawnSync('bash', [launcher, ...args], {
    cwd: context,
    encoding: 'utf8',
    env: {
      PATH: process.env.PATH,
      HOME: home,
    },
  });

  const learned = run([
    'build',
    'net',
    'learn',
    '--http-capture',
    'mitmproxy',
    '--dry-run',
    context,
  ]);
  assert.equal(learned.status, 0, `${learned.stdout}${learned.stderr}`);
  assert.match(
    learned.stdout,
    /nosh-guard build net learn --http-capture mitmproxy .* --dry-run\s*$/,
  );

  const direct = childProcess.spawnSync(
    path.join(appRoot, 'bin', 'nosh-guard'),
    [
      'build',
      'net',
      'learn',
      '--http-capture',
      'mitmproxy',
      '--dry-run',
      context,
    ],
    {
      cwd: context,
      encoding: 'utf8',
      env: {
        PATH: process.env.PATH,
        HOME: home,
      },
    },
  );
  assert.equal(direct.status, 0, `${direct.stdout}${direct.stderr}`);
  assert.equal(JSON.parse(direct.stdout).httpCapture, 'mitmproxy');

  const invalid = run([
    'build', 'net', 'learn', '--http-capture', 'burp', '--dry-run', context,
  ]);
  assert.notEqual(invalid.status, 0);
  assert.match(invalid.stderr, /invalid --http-capture: burp/);

  const directInvalid = childProcess.spawnSync(
    path.join(appRoot, 'bin', 'nosh-guard'),
    [
      'build', 'net', 'learn', '--http-capture', 'burp', '--dry-run', context,
    ],
    {
      cwd: context,
      encoding: 'utf8',
      env: { PATH: process.env.PATH, HOME: home },
    },
  );
  assert.notEqual(directInvalid.status, 0);
  assert.match(
    directInvalid.stderr,
    /--http-capture must be none or mitmproxy/,
  );

  const duplicate = run([
    'build',
    'net',
    'learn',
    '--http-capture',
    'none',
    '--http-capture=mitmproxy',
    '--dry-run',
    context,
  ]);
  assert.notEqual(duplicate.status, 0);
  assert.match(duplicate.stderr, /--http-capture may be specified only once/);

  const wrongMode = run([
    'build', 'profile', '--http-capture', 'mitmproxy', '--dry-run', context,
  ]);
  assert.notEqual(wrongMode.status, 0);
  assert.match(
    wrongMode.stderr,
    /--http-capture is supported only by nosh build net learn/,
  );

  const directWrongMode = childProcess.spawnSync(
    path.join(appRoot, 'bin', 'nosh-guard'),
    [
      'build', 'profile', '--http-capture', 'mitmproxy', '--dry-run', context,
    ],
    {
      cwd: context,
      encoding: 'utf8',
      env: { PATH: process.env.PATH, HOME: home },
    },
  );
  assert.notEqual(directWrongMode.status, 0);
  assert.match(
    directWrongMode.stderr,
    /build profile does not support --http-capture/,
  );

  const help = run(['build', 'net', 'learn', '--help']);
  assert.equal(help.status, 0, `${help.stdout}${help.stderr}`);
  assert.match(help.stdout, /--http-capture MODE\s+none \(default\) or mitmproxy/);

  const directHelp = childProcess.spawnSync(
    path.join(appRoot, 'bin', 'nosh-guard'),
    ['build', 'net', 'learn', '--help'],
    {
      cwd: context,
      encoding: 'utf8',
      env: { PATH: process.env.PATH, HOME: home },
    },
  );
  assert.equal(
    directHelp.status,
    0,
    `${directHelp.stdout}${directHelp.stderr}`,
  );
  assert.match(
    directHelp.stdout,
    /--http-capture MODE\s+With net learn: none \(default\) or mitmproxy/,
  );
});

test('nosh-guard dry-run never prints runner secrets', (t) => {
  const workdir = tempDir(t);
  const result = childProcess.spawnSync(
    path.join(appRoot, 'bin', 'nosh-guard'),
    [
      'run',
      '--mode',
      'learn',
      '--action',
      'start',
      '--image',
      'nosh',
      '--name',
      'secret-test',
      '--workdir',
      workdir,
      '--dry-run',
    ],
    {
      cwd: appRoot,
      encoding: 'utf8',
      env: {
        PATH: process.env.PATH,
        NOTTY_MCP_SPAWN_OTP: 'do-not-print-this-otp',
        NOTTY_BASIC_AUTH_PASSWORD: 'do-not-print-this-password',
      },
    },
  );

  assert.equal(result.status, 0, `${result.stdout}\n${result.stderr}`);
  assert.doesNotMatch(result.stdout, /do-not-print-this/);
  const document = JSON.parse(result.stdout);
  assert.equal(document.dryRun, true);
  assert.equal(document.runner.readOnlyRoot, true);
});

test('mTLS principals are short-lived and map to one runner identity', async (t) => {
  const root = tempDir(t);
  const { PrincipalStore } = await importModule('lib/guardd/principals.js');
  const store = new PrincipalStore({ stateDir: root });
  await store.initialize();
  const fingerprint = 'AA'.repeat(32);

  await store.add({
    id: 'agent-one',
    certificateFingerprint: fingerprint,
    agentId: 'agent-one',
    expiresAt: new Date(Date.now() + 60_000).toISOString(),
  });
  const principal = await store.findByFingerprint(
    fingerprint.match(/../g).join(':'),
  );
  assert.equal(principal.id, 'agent-one');
  assert.equal(principal.agentId, 'agent-one');
  assert.equal(principal.runId, null);
  assert.equal(await store.revoke('agent-one'), true);
  assert.equal(await store.findByFingerprint(fingerprint), null);
});

test('gateway permits only the reviewed Notty UI, agent, and transport routes', async () => {
  const { allowedPath } = await importModule('lib/guardd/gateway.js');
  const { DEFAULT_PREFIXES: prefixes } = await importModule(
    'lib/guardd/principals.js',
  );

  assert.equal(allowedPath('/', prefixes), true);
  assert.equal(allowedPath('/_next/static/app.js', prefixes), true);
  assert.equal(allowedPath('/mcp', prefixes), true);
  assert.equal(allowedPath('/mcp/sse', prefixes), true);
  assert.equal(allowedPath('/message', prefixes), true);
  assert.equal(allowedPath('/api/terminals/123/read', prefixes), true);
  assert.equal(allowedPath('/api/agents', prefixes), true);
  assert.equal(allowedPath('/api/copilots/agent-one/ask', prefixes), true);
  assert.equal(allowedPath('/api/collab/session', prefixes), true);
  assert.equal(allowedPath('/admin/v1/channels', prefixes), false);
  assert.equal(allowedPath('/api/admin', prefixes), false);
  assert.equal(allowedPath('/api/terminals-escape', prefixes), false);
});

test('dependency grants are scoped, audited, and capped at one hour', async (t) => {
  const root = tempDir(t);
  const { GrantStore } = await importModule('lib/guardd/grants.js');
  const store = new GrantStore({ stateDir: root });
  await store.initialize();

  const grant = await store.create({
    runId: 'run-1',
    destination: 'registry.npmjs.org',
    protocol: 'tcp',
    ports: '443',
    actor: 'reviewer',
    reason: 'install reviewed dependency',
    ttlSeconds: 300,
  });
  assert.deepEqual(grant.ports, [443]);
  assert.equal(grant.runId, 'run-1');
  assert.equal(Object.hasOwn(grant, 'profileRevision'), false);
  assert.equal((await store.list()).length, 1);
  const privateGrant = await store.create({
    runId: 'run-1',
    destination: '192.168.1.65/32',
    protocol: 'tcp',
    ports: '9001',
    actor: 'reviewer',
    reason: 'reviewed private collection canary',
    ttlSeconds: 300,
  });
  const dnsTransportGrant = await store.create({
    runId: 'run-1',
    destination: '1.1.1.1/32',
    protocol: 'udp',
    ports: '53,443,853',
    actor: 'reviewer',
    reason: 'reviewed DNS transport behavior',
    ttlSeconds: 300,
  });
  assert.deepEqual(privateGrant.ports, [9001]);
  assert.deepEqual(dnsTransportGrant.ports, [53, 443, 853]);
  assert.equal((await store.list()).length, 3);
  await assert.rejects(
    store.create({
      profileRevision: 'candidate-1',
      destination: 'example.com',
      protocol: 'tcp',
      ports: '443',
      actor: 'reviewer',
      reason: 'revision-wide access',
      ttlSeconds: 300,
    }),
    /runId is required/,
  );
  await assert.rejects(
    store.create({
      runId: 'run-1',
      destination: 'example.com',
      protocol: 'tcp',
      ports: '443',
      actor: 'reviewer',
      reason: 'too long',
      ttlSeconds: 3601,
    }),
    /ttlSeconds/,
  );
  for (const destination of [
    'localhost',
    'bad..example.com',
    '-bad.example.com',
    '999.999.999.999/999',
    '1.2.3.4/',
  ]) {
    await assert.rejects(
      store.create({
        runId: 'run-1',
        destination,
        protocol: 'tcp',
        ports: '443',
        actor: 'reviewer',
        reason: 'invalid destination',
        ttlSeconds: 300,
      }),
      /valid FQDN|invalid IPv4/,
    );
  }

  const revoked = await store.revoke(grant.id, 'reviewer', 'fetch complete');
  await store.revoke(privateGrant.id, 'reviewer', 'canary complete');
  await store.revoke(dnsTransportGrant.id, 'reviewer', 'review complete');
  assert.ok(revoked.revokedAt);
  assert.equal((await store.list()).length, 0);
  const auditLines = fs
    .readFileSync(path.join(root, 'grant-audit.ndjson'), 'utf8')
    .trim()
    .split('\n')
    .map(JSON.parse);
  assert.deepEqual(
    auditLines.map((entry) => entry.action),
    ['create', 'create', 'create', 'revoke', 'revoke', 'revoke'],
  );

  const concurrent = await Promise.all(
    Array.from({ length: 8 }, (_, index) => store.create({
      runId: `run-concurrent-${index}`,
      destination: `dependency-${index}.example.com`,
      protocol: 'tcp',
      ports: '443',
      actor: 'reviewer',
      reason: 'concurrency test',
      ttlSeconds: 300,
    })),
  );
  assert.equal(concurrent.length, 8);
  assert.equal((await store.list()).length, 8);
});

test('a second guard daemon cannot unlink a live guard socket', async (t) => {
  const root = trustedDaemonTempDir(t);
  const socketPath = path.join(root, 'guard.sock');
  const firstStateDir = path.join(root, 'state-one');
  const contenderStateDir = path.join(root, 'state-two');
  const service = {
    async initialize() {},
    async watchdogTick() {},
    health() {
      return { ok: true };
    },
    async listRuns() {
      return [];
    },
  };
  const { listenGuardServer } = await importModule('lib/guardd/server.js');
  const first = await listenGuardServer({
    socketPath,
    stateDir: firstStateDir,
    service,
    watchdogIntervalMs: 0,
  });
  try {
    let contenderInitialized = false;
    await assert.rejects(
      listenGuardServer({
        socketPath,
        stateDir: contenderStateDir,
        watchdogIntervalMs: 0,
        service: {
          ...service,
          async initialize() {
            contenderInitialized = true;
          },
        },
      }),
      (error) =>
        error.code === 'GUARD_ALREADY_RUNNING' &&
        /already listening|live socket/.test(error.message),
    );
    assert.equal(contenderInitialized, false);
    assert.equal(fs.lstatSync(socketPath).isSocket(), true);
    await new Promise((resolve, reject) => {
      const socket = net.createConnection({ path: socketPath });
      socket.once('connect', () => {
        socket.destroy();
        resolve();
      });
      socket.once('error', reject);
    });
  } finally {
    await new Promise((resolve, reject) => {
      first.server.close((error) => (error ? reject(error) : resolve()));
    });
  }
});

test('one state directory admits only one guard daemon across sockets', async (t) => {
  const root = trustedDaemonTempDir(t);
  const stateDir = path.join(root, 'state');
  const firstSocket = path.join(root, 'first.sock');
  const secondSocket = path.join(root, 'second.sock');
  let contenderInitialized = false;
  const service = {
    async initialize() {},
    async watchdogTick() {},
    health() {
      return { ok: true };
    },
    async listRuns() {
      return [];
    },
  };
  const { listenGuardServer } = await importModule('lib/guardd/server.js');
  const first = await listenGuardServer({
    socketPath: firstSocket,
    stateDir,
    service,
    watchdogIntervalMs: 0,
  });
  try {
    await assert.rejects(
      listenGuardServer({
        socketPath: secondSocket,
        stateDir,
        watchdogIntervalMs: 0,
        service: {
          ...service,
          async initialize() {
            contenderInitialized = true;
          },
        },
      }),
      (error) =>
        error.code === 'GUARD_ALREADY_RUNNING' &&
        /state directory.*live daemon/.test(error.message),
    );
    assert.equal(contenderInitialized, false);
    assert.equal(fs.existsSync(secondSocket), false);
  } finally {
    await new Promise((resolve, reject) => {
      first.server.close((error) => (error ? reject(error) : resolve()));
    });
  }
});

test('guard daemon safely reuses an unlocked stale lock anchor', async (t) => {
  const root = trustedDaemonTempDir(t);
  const stateDir = path.join(root, 'state');
  const lockPath = path.join(stateDir, 'guardd.lock');
  fs.mkdirSync(stateDir, { mode: 0o700 });
  fs.writeFileSync(lockPath, 'stale metadata\n', { mode: 0o600 });
  const staleIdentity = fs.statSync(lockPath);
  const service = {
    async initialize() {},
    async watchdogTick() {},
    health() {
      return { ok: true };
    },
    async listRuns() {
      return [];
    },
  };
  const { listenGuardServer } = await importModule('lib/guardd/server.js');
  const first = await listenGuardServer({
    socketPath: path.join(root, 'first.sock'),
    stateDir,
    service,
    watchdogIntervalMs: 0,
  });
  const activeIdentity = fs.statSync(lockPath);
  assert.equal(activeIdentity.dev, staleIdentity.dev);
  assert.equal(activeIdentity.ino, staleIdentity.ino);
  assert.equal(activeIdentity.mode & 0o7777, 0o600);
  assert.equal(JSON.parse(fs.readFileSync(lockPath, 'utf8')).pid, process.pid);
  await new Promise((resolve, reject) => {
    first.server.close((error) => (error ? reject(error) : resolve()));
  });

  const second = await listenGuardServer({
    socketPath: path.join(root, 'second.sock'),
    stateDir,
    service,
    watchdogIntervalMs: 0,
  });
  try {
    assert.equal(fs.statSync(lockPath).ino, staleIdentity.ino);
    assert.match(
      JSON.parse(fs.readFileSync(lockPath, 'utf8')).socketPath,
      /second\.sock$/,
    );
  } finally {
    await new Promise((resolve, reject) => {
      second.server.close((error) => (error ? reject(error) : resolve()));
    });
  }
});

test('guard daemon rejects writable state and socket ancestry', async (t) => {
  const root = trustedDaemonTempDir(t);
  const unsafe = path.join(root, 'unsafe');
  fs.mkdirSync(unsafe, { mode: 0o777 });
  fs.chmodSync(unsafe, 0o777);
  let initialized = false;
  const service = {
    async initialize() {
      initialized = true;
    },
    async watchdogTick() {},
    health() {
      return { ok: true };
    },
    async listRuns() {
      return [];
    },
  };
  const { listenGuardServer } = await importModule('lib/guardd/server.js');
  await assert.rejects(
    listenGuardServer({
      socketPath: path.join(root, 'state-rejected.sock'),
      stateDir: path.join(unsafe, 'state'),
      service,
      watchdogIntervalMs: 0,
    }),
    /must not be group- or other-writable/,
  );
  assert.equal(initialized, false);

  const stateDir = path.join(root, 'safe-state');
  await assert.rejects(
    listenGuardServer({
      socketPath: path.join(unsafe, 'socket-rejected.sock'),
      stateDir,
      service,
      watchdogIntervalMs: 0,
    }),
    /must not be group- or other-writable/,
  );
  assert.equal(initialized, false);

  fs.chmodSync(unsafe, 0o700);
  const recovered = await listenGuardServer({
    socketPath: path.join(unsafe, 'accepted.sock'),
    stateDir,
    service,
    watchdogIntervalMs: 0,
  });
  try {
    assert.equal(initialized, true);
  } finally {
    await new Promise((resolve, reject) => {
      recovered.server.close((error) => (error ? reject(error) : resolve()));
    });
  }
});

test('guard socket is owner-only even under a permissive ambient umask', async (t) => {
  const root = trustedDaemonTempDir(t);
  const socketPath = path.join(root, 'guard.sock');
  const service = {
    async initialize() {},
    async watchdogTick() {},
    health() {
      return { ok: true };
    },
    async listRuns() {
      return [];
    },
  };
  const { listenGuardServer } = await importModule('lib/guardd/server.js');
  const previousUmask = process.umask(0);
  let instance;
  try {
    instance = await listenGuardServer({
      socketPath,
      stateDir: path.join(root, 'state'),
      service,
      watchdogIntervalMs: 0,
    });
  } finally {
    process.umask(previousUmask);
  }
  try {
    assert.equal(fs.lstatSync(socketPath).mode & 0o7777, 0o600);
  } finally {
    await new Promise((resolve, reject) => {
      instance.server.close((error) => (error ? reject(error) : resolve()));
    });
  }
});

test('Docker requests time out across a wedged daemon connection', async () => {
  const { DockerClient } = await importModule('lib/guardd/docker-client.js');
  let requestHandle;
  const client = new DockerClient({
    requestTimeoutMs: 20,
    requestImpl() {
      requestHandle = new EventEmitter();
      requestHandle.write = () => {};
      requestHandle.end = () => {};
      requestHandle.destroy = () => {
        requestHandle.destroyed = true;
      };
      return requestHandle;
    },
  });

  await assert.rejects(
    client.ping(),
    (error) =>
      error.code === 'DOCKER_REQUEST_TIMEOUT' &&
      error.timeoutMs === 20 &&
      /GET .*_ping.*20ms/.test(error.message),
  );
  assert.equal(requestHandle.destroyed, true);
  assert.throws(
    () => new DockerClient({ requestTimeoutMs: 0 }),
    /requestTimeoutMs must be an integer/,
  );
});

test('Docker release gate waits for successful detached exec completion', async () => {
  const { DockerClient } = await importModule('lib/guardd/docker-client.js');
  const client = new DockerClient({
    execWaitTimeoutMs: 100,
    execPollIntervalMs: 1,
  });
  const operations = [];
  client.exec = async () => {
    operations.push('start-exec');
    return 'exec-release';
  };
  client.inspectExec = async () => {
    operations.push('inspect-exec');
    return operations.filter((entry) => entry === 'inspect-exec').length === 1
      ? { Running: true, ExitCode: 0 }
      : { Running: false, ExitCode: 0 };
  };

  assert.equal(await client.releaseGate('container-1'), 'exec-release');
  assert.deepEqual(operations, [
    'start-exec',
    'inspect-exec',
    'inspect-exec',
  ]);
});

test('Docker release gate fails closed on exec failure or timeout', async () => {
  const { DockerClient } = await importModule('lib/guardd/docker-client.js');
  const failed = new DockerClient({
    execWaitTimeoutMs: 100,
    execPollIntervalMs: 1,
  });
  failed.exec = async () => 'exec-failed';
  failed.inspectExec = async () => ({ Running: false, ExitCode: 23 });
  await assert.rejects(
    failed.releaseGate('container-failed'),
    (error) =>
      error.code === 'DOCKER_EXEC_FAILED' &&
      error.execId === 'exec-failed' &&
      error.exitCode === 23,
  );

  const wedged = new DockerClient({
    execWaitTimeoutMs: 20,
    execPollIntervalMs: 2,
  });
  wedged.exec = async () => 'exec-wedged';
  wedged.inspectExec = async () => ({ Running: true, ExitCode: 0 });
  await assert.rejects(
    wedged.releaseGate('container-wedged'),
    (error) =>
      error.code === 'DOCKER_EXEC_TIMEOUT' &&
      error.execId === 'exec-wedged' &&
      error.timeoutMs === 20,
  );
});
