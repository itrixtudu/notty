'use strict';

const assert = require('node:assert/strict');
const { EventEmitter } = require('node:events');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const test = require('node:test');
const { pathToFileURL } = require('node:url');

const appRoot = path.resolve(__dirname, '..');

async function cliModule() {
  return import(
    pathToFileURL(path.join(appRoot, 'scripts', 'nosh-guard.mjs')).href
  );
}

function fixture(t) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'notty-net-cli-'));
  const workdir = path.join(root, 'workspace');
  const evidenceDir = path.join(root, 'evidence', 'learn-run');
  fs.mkdirSync(workdir);
  fs.mkdirSync(evidenceDir, { recursive: true });
  const manifestPath = path.join(evidenceDir, 'evidence-manifest.json');
  fs.writeFileSync(manifestPath, JSON.stringify({
    apiVersion: 'notty.dev/v1alpha1',
    kind: 'NoshSecurityEvidenceManifest',
    runId: 'learn-run',
    mode: 'egress-learn',
    complete: true,
  }));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  return { root, workdir, manifestPath };
}

function fakeRegistry(initial = null) {
  let state = initial;
  return {
    async initialize() {},
    async readWorkspace() {
      return state;
    },
    async setLatestCandidate(workdir, reference) {
      state ||= {
        canonicalPath: workdir,
        workspaceKey: 'a'.repeat(64),
        latestCandidate: null,
        approved: null,
        audits: [],
        lastLaunch: null,
      };
      state.latestCandidate = reference;
    },
    async setApproved(workdir, reference) {
      state ||= {
        canonicalPath: workdir,
        workspaceKey: 'a'.repeat(64),
        latestCandidate: null,
        approved: null,
        audits: [],
        lastLaunch: null,
      };
      state.approved = reference;
    },
    async recordAudit(workdir, audit) {
      state.audits.push(audit);
    },
    async recordLastLaunch(workdir, launch) {
      state.lastLaunch = launch;
    },
    state() {
      return state;
    },
  };
}

function attachment(runId, workdir) {
  return {
    runId,
    name: 'nosh-workspace-deadbeef',
    status: 'running',
    containerId: 'a'.repeat(64),
    imageDigest: `sha256:${'b'.repeat(64)}`,
    imageReference: `sha256:${'b'.repeat(64)}`,
    workdir,
    attachment: {
      validated: true,
      containerId: 'a'.repeat(64),
      dockerSocket: '/run/docker-test.sock',
      adapters: [{ name: 'nosh-l4', required: true, ok: true }],
    },
  };
}

test('net learn owns shell finalization, compilation, registration, and removal', async (t) => {
  const { executeNetCommand } = await cliModule();
  const current = fixture(t);
  const registry = fakeRegistry();
  const calls = [];
  const started = attachment('learn-run', current.workdir);
  const client = {
    async startRun(request) {
      calls.push(['start', request.mode]);
      return started;
    },
    async action(identifier, action) {
      calls.push([action, identifier]);
      if (action === 'attach') return started;
      if (action === 'stop') {
        return {
          ...started,
          evidenceManifest: current.manifestPath,
        };
      }
      return { runId: identifier, status: 'removed' };
    },
  };

  const status = await executeNetCommand('learn', {
    workdir: current.workdir,
    image: 'nosh',
    'no-collab': true,
    'no-start-app': true,
  }, {
    client,
    registry,
    interactive: true,
    geteuid: () => 0,
    spawnSyncImpl: () => ({ status: 4, signal: null }),
    loadEvidenceInputs: async () => ({
      records: [],
      runProvenance: [],
      ingestion: {},
    }),
    compileNetworkArtifact: () => ({
      spec: {
        egress: [{ destination: 'registry.example', protocol: 'tcp', ports: [443] }],
        unresolvedObservations: [],
      },
    }),
    createCandidate: async (input) => ({
      revision: input.runId,
      directory: path.join(current.root, 'profiles', input.runId),
      workspaceKey: 'a'.repeat(64),
      profile: {
        metadata: { createdAt: '2026-08-08T00:00:00.000Z' },
        spec: { target: { imageDigest: input.imageDigest } },
      },
      artifacts: { 'egress-policy.json': `sha256:${'c'.repeat(64)}` },
    }),
    mirrorWriter: () => current.root,
  });

  assert.equal(status, 4);
  assert.deepEqual(calls.map((entry) => entry[0]), [
    'start',
    'attach',
    'stop',
    'rm',
  ]);
  assert.equal(registry.state().latestCandidate.revision, 'learn-run');
  assert.equal(registry.state().lastLaunch.mode, 'egress-learn');
  assert.equal(
    registry.state().lastLaunch.profileDirectory,
    registry.state().latestCandidate.directory,
  );
});

test('timed net learn observes headlessly and still compiles and removes the run', async (t) => {
  const { executeNetCommand } = await cliModule();
  const current = fixture(t);
  const registry = fakeRegistry();
  const calls = [];
  const started = attachment('learn-run', current.workdir);
  let compiled = false;
  let printed = null;
  let mirroredReviewCandidate = null;
  const client = {
    async startRun(request) {
      calls.push(['start', request.mode]);
      return started;
    },
    async action(identifier, action) {
      calls.push([action, identifier]);
      if (action === 'attach') return started;
      if (action === 'stop') {
        return { ...started, evidenceManifest: current.manifestPath };
      }
      return { runId: identifier, status: 'removed' };
    },
  };

  const status = await executeNetCommand('learn', {
    workdir: current.workdir,
    image: 'nosh',
    duration: '180',
    json: true,
    'no-collab': true,
    'no-start-app': true,
  }, {
    client,
    registry,
    interactive: false,
    geteuid: () => 0,
    spawnSyncImpl: () => assert.fail('timed learning must not run docker exec'),
    waitForDuration: async (durationSeconds, waitOptions) => {
      assert.equal(durationSeconds, 180);
      assert.equal(calls.at(-1)[0], 'attach');
      await waitOptions.revalidate();
      return {
        status: 0,
        signal: null,
        requestedDurationSeconds: 180,
        observedDurationMilliseconds: 180_250,
        observationComplete: true,
      };
    },
    loadEvidenceInputs: async () => ({
      records: [],
      runProvenance: [],
      ingestion: {},
    }),
    compileNetworkArtifact: () => {
      compiled = true;
      return {
        spec: {
          egress: [{ destination: 'registry.example', protocol: 'tcp', ports: [443] }],
          unresolvedObservations: [],
        },
      };
    },
    createCandidate: async (input) => ({
      revision: input.runId,
      directory: path.join(current.root, 'profiles', input.runId),
      workspaceKey: 'a'.repeat(64),
      profile: {
        metadata: { createdAt: '2026-08-08T00:00:00.000Z' },
        spec: { target: { imageDigest: input.imageDigest } },
      },
      manifestHash: `sha256:${'d'.repeat(64)}`,
      artifacts: {
        'egress-policy.json': `sha256:${'c'.repeat(64)}`,
        'egress-profile.json': `sha256:${'e'.repeat(64)}`,
      },
    }),
    reviewCandidateSources: async () => ({
      profileSource: '{"kind":"NoshEgressProfile"}\n',
      policySource: '{"kind":"NoshEgressPolicy"}\n',
      manifestSource: '{"kind":"NoshEgressBundleManifest"}\n',
      targetContextSource: '{"kind":"NoshGuardEbpfTargetContext"}\n',
    }),
    mirrorWriter(payload) {
      mirroredReviewCandidate = payload.reviewCandidate;
      return current.root;
    },
    print(value) {
      printed = value;
    },
  });

  assert.equal(status, 0);
  assert.equal(compiled, true);
  assert.equal(mirroredReviewCandidate.kind, undefined);
  assert.equal(
    JSON.parse(mirroredReviewCandidate.targetContextSource).kind,
    'NoshGuardEbpfTargetContext',
  );
  assert.deepEqual(calls.map((entry) => entry[0]), [
    'start',
    'attach',
    'attach',
    'stop',
    'rm',
  ]);
  assert.equal(registry.state().latestCandidate.revision, 'learn-run');
  assert.equal(
    registry.state().latestCandidate.launchConfig.observationDurationSeconds,
    180,
  );
  assert.deepEqual(printed, {
    apiVersion: 'notty.dev/v1alpha1',
    kind: 'NoshEgressLearnResult',
    runId: 'learn-run',
    revision: 'learn-run',
    imageDigest: `sha256:${'b'.repeat(64)}`,
    imageReference: `sha256:${'b'.repeat(64)}`,
    profileDirectory: path.join(current.root, 'profiles', 'learn-run'),
    mirrorDirectory: current.root,
    authoritativePolicy: path.join(
      current.root,
      'profiles',
      'learn-run',
      'egress-policy.json',
    ),
    mirrorPolicy: path.join(current.root, 'candidate-egress-policy.json'),
    candidatePolicy: path.join(current.root, 'candidate-egress-policy.json'),
    reviewCandidateDirectory: path.join(
      current.root,
      'review-candidates',
      'a'.repeat(64),
      'learn-run',
    ),
    reviewTargetContext: path.join(
      current.root,
      'review-candidates',
      'a'.repeat(64),
      'learn-run',
      'guard-ebpf-target-context.json',
    ),
    evidenceManifest: current.manifestPath,
    durationSeconds: 180,
    requestedDurationSeconds: 180,
    observedDurationMilliseconds: 180_250,
    observationComplete: true,
    policyHash: `sha256:${'c'.repeat(64)}`,
    profileHash: `sha256:${'e'.repeat(64)}`,
    manifestHash: `sha256:${'d'.repeat(64)}`,
  });
});

test('interrupted timed learning stops but never advances a candidate', async (t) => {
  const { executeNetCommand } = await cliModule();
  const current = fixture(t);
  const registry = fakeRegistry();
  const calls = [];
  const started = attachment('learn-run', current.workdir);
  const signalSource = new EventEmitter();
  const client = {
    async startRun() {
      calls.push('start');
      return started;
    },
    async action(identifier, action) {
      calls.push(action);
      if (action === 'attach') return started;
      assert.equal(signalSource.listenerCount('SIGINT'), 1);
      assert.equal(signalSource.listenerCount('SIGTERM'), 1);
      if (action === 'stop') {
        return { ...started, evidenceManifest: current.manifestPath };
      }
      return { runId: identifier, status: 'removed' };
    },
  };

  const status = await executeNetCommand('learn', {
    workdir: current.workdir,
    image: 'nosh',
    duration: '180',
    'no-collab': true,
    'no-start-app': true,
  }, {
    client,
    registry,
    interactive: false,
    geteuid: () => 0,
    signalSource,
    waitForDuration: async () => {
      signalSource.emit('SIGTERM');
      return {
        status: 143,
        signal: 'SIGTERM',
        requestedDurationSeconds: 180,
        observedDurationMilliseconds: 30_000,
        observationComplete: false,
      };
    },
    createCandidate: async () => assert.fail('interrupted learning must not advance'),
    mirrorWriter: () => current.root,
  });
  assert.equal(status, 143);
  assert.deepEqual(calls, ['start', 'attach', 'stop']);
  assert.equal(registry.state(), null);
  assert.equal(signalSource.listenerCount('SIGINT'), 0);
  assert.equal(signalSource.listenerCount('SIGTERM'), 0);
});

test('signal latched during stop prevents the timed candidate commit', async (t) => {
  const { executeNetCommand } = await cliModule();
  const current = fixture(t);
  const registry = fakeRegistry();
  const signalSource = new EventEmitter();
  const calls = [];
  const started = attachment('learn-run', current.workdir);
  const client = {
    async startRun() {
      calls.push('start');
      return started;
    },
    async action(identifier, action) {
      calls.push(action);
      if (action === 'attach') return started;
      if (action === 'stop') {
        signalSource.emit('SIGINT');
        return { ...started, evidenceManifest: current.manifestPath };
      }
      return { runId: identifier, status: 'removed' };
    },
  };

  const status = await executeNetCommand('learn', {
    workdir: current.workdir,
    duration: '180',
    'no-collab': true,
    'no-start-app': true,
  }, {
    client,
    registry,
    signalSource,
    interactive: false,
    geteuid: () => 0,
    waitForDuration: async () => ({
      status: 0,
      signal: null,
      requestedDurationSeconds: 180,
      observedDurationMilliseconds: 180_000,
      observationComplete: true,
    }),
    createCandidate: async () => assert.fail('a pre-commit signal must not advance'),
  });

  assert.equal(status, 130);
  assert.deepEqual(calls, ['start', 'attach', 'stop']);
  assert.equal(registry.state(), null);
  assert.equal(signalSource.listenerCount('SIGINT'), 0);
  assert.equal(signalSource.listenerCount('SIGTERM'), 0);
});

test('signal latched during admission skips attach and retains the stopped run', async (t) => {
  const { executeNetCommand } = await cliModule();
  const current = fixture(t);
  const registry = fakeRegistry();
  const signalSource = new EventEmitter();
  const calls = [];
  const started = attachment('learn-run', current.workdir);
  const client = {
    async startRun() {
      calls.push('start');
      signalSource.emit('SIGTERM');
      return started;
    },
    async action(identifier, action) {
      calls.push(action);
      assert.notEqual(action, 'attach');
      if (action === 'stop') {
        return { ...started, evidenceManifest: current.manifestPath };
      }
      return { runId: identifier, status: 'removed' };
    },
  };

  const status = await executeNetCommand('learn', {
    workdir: current.workdir,
    duration: '180',
    'no-collab': true,
    'no-start-app': true,
  }, {
    client,
    registry,
    signalSource,
    interactive: false,
    geteuid: () => 0,
    waitForDuration: async () => assert.fail('an admission signal must skip the window'),
    createCandidate: async () => assert.fail('an admission signal must not advance'),
  });

  assert.equal(status, 143);
  assert.deepEqual(calls, ['start', 'stop']);
  assert.equal(registry.state(), null);
  assert.equal(signalSource.listenerCount('SIGINT'), 0);
  assert.equal(signalSource.listenerCount('SIGTERM'), 0);
});

test('timed learning rejects a failed in-window attach health check', async (t) => {
  const { executeNetCommand } = await cliModule();
  const current = fixture(t);
  const registry = fakeRegistry();
  const calls = [];
  const started = attachment('learn-run', current.workdir);
  let attachCount = 0;
  const client = {
    async startRun() {
      calls.push('start');
      return started;
    },
    async action(identifier, action) {
      calls.push(action);
      if (action === 'attach') {
        attachCount += 1;
        if (attachCount > 1) {
          throw new Error('required adapter nosh-l4 exited');
        }
        return started;
      }
      if (action === 'stop') {
        return { ...started, evidenceManifest: current.manifestPath };
      }
      return { runId: identifier, status: 'removed' };
    },
  };

  await assert.rejects(
    executeNetCommand('learn', {
      workdir: current.workdir,
      duration: '180',
      'no-collab': true,
      'no-start-app': true,
    }, {
      client,
      registry,
      interactive: false,
      geteuid: () => 0,
      waitForDuration: async (durationSeconds, waitOptions) => {
        assert.equal(durationSeconds, 180);
        await waitOptions.revalidate();
        assert.fail('failed health revalidation must reject the wait');
      },
      createCandidate: async () => assert.fail('unhealthy learning must not advance'),
    }),
    /guarded shell failed: required adapter nosh-l4 exited.*retained for diagnostics/,
  );
  assert.deepEqual(calls, ['start', 'attach', 'attach', 'stop']);
  assert.equal(registry.state(), null);
});

test('observation wait converts a termination signal to a cleanup-safe status', async () => {
  const { waitForObservationWindow } = await cliModule();
  const signalSource = new EventEmitter();
  const timer = {};
  let cleared = null;
  let delay = null;
  let forcedExit = null;
  const waiting = waitForObservationWindow(180, {
    signalSource,
    setTimeoutImpl(callback, milliseconds) {
      assert.equal(typeof callback, 'function');
      delay = milliseconds;
      return timer;
    },
    clearTimeoutImpl(value) {
      cleared = value;
    },
    forceExitImpl(status, signal) {
      forcedExit = { status, signal };
    },
  });

  signalSource.emit('SIGINT');
  signalSource.emit('SIGTERM');

  assert.deepEqual(await waiting, {
    status: 130,
    signal: 'SIGINT',
    requestedDurationSeconds: 180,
    observedDurationMilliseconds: 0,
    observationComplete: false,
  });
  assert.equal(delay, 5_000);
  assert.equal(cleared, timer);
  assert.deepEqual(forcedExit, { status: 143, signal: 'SIGTERM' });
  assert.equal(signalSource.listenerCount('SIGINT'), 0);
  assert.equal(signalSource.listenerCount('SIGTERM'), 0);
});

test('observation wait coalesces a relayed duplicate but honors a later second signal', async () => {
  const { waitForObservationWindow } = await cliModule();
  const signalSource = new EventEmitter();
  let signalTime = 10_000;
  let forcedExit = null;
  const waiting = waitForObservationWindow(180, {
    signalSource,
    signalNow: () => signalTime,
    setTimeoutImpl: () => ({}),
    clearTimeoutImpl() {},
    forceExitImpl(status, signal) {
      forcedExit = { status, signal };
    },
  });

  signalSource.emit('SIGINT');
  signalSource.emit('SIGINT');
  assert.equal(forcedExit, null);
  signalTime += 1_001;
  signalSource.emit('SIGINT');

  assert.equal((await waiting).status, 130);
  assert.deepEqual(forcedExit, { status: 130, signal: 'SIGINT' });
  assert.equal(signalSource.listenerCount('SIGINT'), 0);
  assert.equal(signalSource.listenerCount('SIGTERM'), 0);
});

test('observation wait serializes runner health checks through its deadline', async () => {
  const { waitForObservationWindow } = await cliModule();
  const signalSource = new EventEmitter();
  let now = 0;
  let checks = 0;
  let activeChecks = 0;
  const result = await waitForObservationWindow(1, {
    signalSource,
    pollIntervalMilliseconds: 250,
    monotonicNow: () => now,
    setTimeoutImpl(callback, milliseconds) {
      const timer = { milliseconds };
      queueMicrotask(() => {
        now += milliseconds;
        callback();
      });
      return timer;
    },
    clearTimeoutImpl() {},
    async revalidate() {
      activeChecks += 1;
      assert.equal(activeChecks, 1);
      await Promise.resolve();
      checks += 1;
      activeChecks -= 1;
    },
  });

  assert.deepEqual(result, {
    status: 0,
    signal: null,
    requestedDurationSeconds: 1,
    observedDurationMilliseconds: 1_000,
    observationComplete: true,
  });
  assert.equal(checks, 4);
  assert.equal(activeChecks, 0);
  assert.equal(signalSource.listenerCount('SIGINT'), 0);
  assert.equal(signalSource.listenerCount('SIGTERM'), 0);
});

test('net learn duration is validated and represented numerically in dry-run output', async () => {
  const { executeNetCommand } = await cliModule();
  let printed = null;
  const status = await executeNetCommand('learn', {
    duration: '180',
    'dry-run': true,
  }, {
    interactive: false,
    print(value) {
      printed = value;
    },
  });
  assert.equal(status, 0);
  assert.equal(printed.durationSeconds, 180);

  for (const duration of ['', '0', '-1', '1.5', '86401', 'unbounded']) {
    await assert.rejects(
      executeNetCommand('learn', {
        duration,
        'dry-run': true,
      }, { print: () => {} }),
      /--duration must be an integer from 1 to 86400/,
    );
  }
});

test('duration is learn-only and learn without it remains interactive', async () => {
  const { executeNetCommand } = await cliModule();
  await assert.rejects(
    executeNetCommand('audit', {
      duration: '180',
      'dry-run': true,
    }),
    /--duration is supported only by nosh net learn/,
  );
  await assert.rejects(
    executeNetCommand('learn', {
      json: true,
      'dry-run': true,
    }),
    /nosh net learn --json requires --duration/,
  );
  await assert.rejects(
    executeNetCommand('learn', {}, {
      interactive: false,
      geteuid: () => 0,
    }),
    /nosh net learn requires an interactive terminal/,
  );
});

test('net learn retains a stopped run when finalized evidence is incomplete', async (t) => {
  const { executeNetCommand } = await cliModule();
  const current = fixture(t);
  const manifest = JSON.parse(fs.readFileSync(current.manifestPath, 'utf8'));
  manifest.complete = false;
  fs.writeFileSync(current.manifestPath, JSON.stringify(manifest));
  const calls = [];
  const started = attachment('learn-run', current.workdir);
  const client = {
    async startRun() {
      calls.push('start');
      return started;
    },
    async action(identifier, action) {
      calls.push(action);
      if (action === 'attach') return started;
      if (action === 'stop') {
        return { ...started, evidenceManifest: current.manifestPath };
      }
      return { runId: identifier };
    },
  };

  await assert.rejects(
    executeNetCommand('learn', {
      workdir: current.workdir,
      image: 'nosh',
      'no-collab': true,
      'no-start-app': true,
    }, {
      client,
      registry: fakeRegistry(),
      interactive: true,
      geteuid: () => 0,
      spawnSyncImpl: () => ({ status: 0, signal: null }),
      mirrorWriter: () => current.root,
    }),
    /evidence is incomplete/,
  );
  assert.deepEqual(calls, ['start', 'attach', 'stop']);
});

test('net learn never registers evidence when the guarded shell cannot launch', async (t) => {
  const { executeNetCommand } = await cliModule();
  const current = fixture(t);
  const registry = fakeRegistry();
  const calls = [];
  const started = attachment('learn-run', current.workdir);
  const client = {
    async startRun() {
      calls.push('start');
      return started;
    },
    async action(identifier, action) {
      calls.push(action);
      if (action === 'attach') return started;
      if (action === 'stop') {
        return { ...started, evidenceManifest: current.manifestPath };
      }
      return { runId: identifier };
    },
  };

  await assert.rejects(
    executeNetCommand('learn', {
      workdir: current.workdir,
      image: 'nosh',
      'no-collab': true,
      'no-start-app': true,
    }, {
      client,
      registry,
      interactive: true,
      geteuid: () => 0,
      spawnSyncImpl: () => { throw new Error('docker executable missing'); },
      createCandidate: async () => {
        assert.fail('a failed shell must not create a candidate');
      },
    }),
    /guarded shell failed: docker executable missing.*retained for diagnostics/,
  );
  assert.deepEqual(calls, ['start', 'attach', 'stop']);
  assert.equal(registry.state(), null);
});

test('net enforce ignores legacy approval and uses current learned launch settings', async (t) => {
  const { executeNetCommand } = await cliModule();
  const current = fixture(t);
  const launchConfig = {
    image: 'nosh',
    imageReference: `sha256:${'b'.repeat(64)}`,
    imageDigest: `sha256:${'b'.repeat(64)}`,
    name: 'nosh-workspace-deadbeef',
    agentId: 'nosh-workspace-deadbeef',
    roles: [],
    configPath: null,
    configHash: null,
    collab: false,
    startApp: false,
  };
  const approved = {
    runId: 'old-run',
    revision: 'old-run',
    directory: path.join(current.root, 'old-run'),
    imageDigest: launchConfig.imageDigest,
    launchConfig,
  };
  const registry = fakeRegistry({
    canonicalPath: current.workdir,
    workspaceKey: 'a'.repeat(64),
    latestCandidate: {
      ...approved,
      runId: 'new-run',
      revision: 'new-run',
      directory: path.join(current.root, 'new-run'),
    },
    approved,
    audits: [],
    lastLaunch: null,
  });
  let startedRequest;
  const running = attachment('enforce-run', current.workdir);
  const client = {
    async startRun(request) {
      startedRequest = request;
      return running;
    },
    async action(identifier, action) {
      if (action === 'attach') return running;
      if (action === 'stop') {
        return { ...running, evidenceManifest: current.manifestPath };
      }
      return { runId: identifier };
    },
  };

  const status = await executeNetCommand('enforce', {
    workdir: current.workdir,
  }, {
    client,
    registry,
    interactive: true,
    geteuid: () => 0,
    confirm: async () => {
      assert.fail('legacy approval must not prompt or authorize eBPF enforcement');
    },
    verifyCandidate: async () => ({ ok: true }),
    spawnSyncImpl: () => ({ status: 0, signal: null }),
    mirrorWriter: () => current.root,
  });
  assert.equal(status, 0);
  assert.equal(startedRequest.mode, 'egress-enforce');
  assert.equal(startedRequest.profileDir, null);
  assert.equal(registry.state().lastLaunch.revision, 'new-run');
  assert.equal(registry.state().lastLaunch.launchCandidateRevision, 'new-run');
  assert.equal(registry.state().lastLaunch.profileDirectory, null);
});

test('non-interactive net enforce launches current settings while Guard supplies signed policy', async (t) => {
  const { executeNetCommand } = await cliModule();
  const current = fixture(t);
  const launchConfig = {
    image: 'nosh',
    imageReference: `sha256:${'b'.repeat(64)}`,
    imageDigest: `sha256:${'b'.repeat(64)}`,
    name: 'nosh-workspace-deadbeef',
    agentId: 'nosh-workspace-deadbeef',
    roles: [],
    configPath: null,
    configHash: null,
    collab: false,
    startApp: false,
  };
  const candidate = {
    runId: 'candidate-run',
    revision: 'candidate-run',
    directory: path.join(current.root, 'candidate-run'),
    imageDigest: launchConfig.imageDigest,
    launchConfig,
  };
  const registry = fakeRegistry({
    canonicalPath: current.workdir,
    workspaceKey: 'a'.repeat(64),
    latestCandidate: candidate,
    approved: {
      ...candidate,
      runId: 'legacy-approved-run',
      revision: 'legacy-approved-run',
      directory: path.join(current.root, 'legacy-approved-run'),
    },
    audits: [],
    lastLaunch: null,
  });
  let startedRequest;
  let printed;
  const running = {
    ...attachment('noninteractive-enforce', current.workdir),
    profileRevision: 'signed-activation-001',
  };

  await assert.rejects(
    executeNetCommand('enforce', {
      workdir: current.workdir,
      revision: 'not-the-current-candidate',
    }, {
      registry,
      interactive: false,
      geteuid: () => 0,
    }),
    /is not the current learned launch-settings revision/,
  );
  const status = await executeNetCommand('enforce', {
    workdir: current.workdir,
  }, {
    client: {
      async startRun(request) {
        startedRequest = request;
        return running;
      },
    },
    registry,
    interactive: false,
    geteuid: () => 0,
    verifyCandidate: async () => ({ ok: true }),
    mirrorWriter: () => current.root,
    print: (value) => { printed = value; },
  });

  assert.equal(status, 0);
  assert.equal(startedRequest.mode, 'egress-enforce');
  assert.equal(startedRequest.profileDir, null);
  assert.equal(printed.runId, running.runId);
  assert.equal(registry.state().lastLaunch.status, 'running');
  assert.equal(registry.state().lastLaunch.revision, candidate.revision);
  assert.equal(
    registry.state().lastLaunch.activationRevision,
    'signed-activation-001',
  );
  assert.equal(registry.state().lastLaunch.profileDirectory, null);
});

test('explicit mirror repair propagates a writer failure', async (t) => {
  const { executeNetCommand } = await cliModule();
  const current = fixture(t);
  const candidate = {
    runId: 'candidate-run',
    revision: 'candidate-run',
    directory: path.join(current.root, 'candidate-run'),
    workspaceKey: 'a'.repeat(64),
    imageDigest: `sha256:${'b'.repeat(64)}`,
    launchConfig: { roles: [], collab: false, startApp: false },
  };
  const registry = fakeRegistry({
    canonicalPath: current.workdir,
    workspaceKey: candidate.workspaceKey,
    latestCandidate: candidate,
    approved: null,
    audits: [],
    lastLaunch: null,
  });

  await assert.rejects(
    executeNetCommand('status', {
      workdir: current.workdir,
      repair: true,
    }, {
      registry,
      geteuid: () => 0,
      verifyCandidate: async () => ({ ok: true }),
      mirrorWriter: () => { throw new Error('mirror write denied'); },
    }),
    /mirror write denied/,
  );
});

test('non-root net status reads only the user mirror', async (t) => {
  const { executeNetCommand } = await cliModule();
  const current = fixture(t);
  let read = false;
  const status = await executeNetCommand('status', {
    workdir: current.workdir,
    json: true,
  }, {
    geteuid: () => 1000,
    readMirror: async () => {
      read = true;
      return {
        receipt: {
          workspace: { path: current.workdir },
          enforcementScope: 'egress-only',
          latestCandidate: null,
          approved: null,
          lastLaunch: null,
        },
      };
    },
  });
  assert.equal(status, 0);
  assert.equal(read, true);
});
