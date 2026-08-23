'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const test = require('node:test');
const { pathToFileURL } = require('node:url');

const appRoot = path.resolve(__dirname, '..');
const builderId = 'a'.repeat(64);
const builderImage =
  'moby/buildkit:v0.30.0@sha256:' + 'b'.repeat(64);

async function sessionModule() {
  return import(
    pathToFileURL(path.join(appRoot, 'lib/guardd/build-session-service.js')).href
  );
}

function fixture(t, overrides = {}) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'nosh-build-session-'));
  const stateDir = path.join(root, 'state');
  const workdir = path.join(root, 'workspace');
  const cgroupPath = path.join(root, 'builder-cgroup');
  fs.mkdirSync(workdir, { mode: 0o700 });
  fs.mkdirSync(cgroupPath, { mode: 0o700 });
  fs.writeFileSync(path.join(cgroupPath, 'cpu.stat'), 'usage_usec 100\n');
  fs.writeFileSync(
    path.join(cgroupPath, 'cpu.pressure'),
    'some avg10=0.00 avg60=0.00 avg300=0.00 total=0\nfull avg10=0.00 avg60=0.00 avg300=0.00 total=0\n',
  );
  fs.writeFileSync(
    path.join(cgroupPath, 'io.stat'),
    '8:0 rbytes=0 wbytes=0 rios=0 wios=0 dbytes=0 dios=0\n',
  );
  fs.writeFileSync(
    path.join(cgroupPath, 'io.pressure'),
    'some avg10=0.00 avg60=0.00 avg300=0.00 total=0\nfull avg10=0.00 avg60=0.00 avg300=0.00 total=0\n',
  );
  fs.writeFileSync(path.join(cgroupPath, 'memory.current'), '0\n');
  fs.writeFileSync(path.join(cgroupPath, 'memory.events'), 'low 0\nhigh 0\nmax 0\noom 0\noom_kill 0\n');
  fs.writeFileSync(
    path.join(cgroupPath, 'memory.pressure'),
    'some avg10=0.00 avg60=0.00 avg300=0.00 total=0\nfull avg10=0.00 avg60=0.00 avg300=0.00 total=0\n',
  );
  fs.writeFileSync(path.join(cgroupPath, 'pids.current'), '1\n');
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));

  const calls = {
    attach: [],
    cgroup: [],
    detach: [],
    health: [],
    inspect: [],
    stop: [],
  };
  const docker = {
    async inspectContainer(containerId) {
      calls.inspect.push(containerId);
      return {
        Id: builderId,
        Name: '/buildx_buildkit_nosh-builder0',
        Image: 'sha256:' + 'c'.repeat(64),
        Config: { Image: builderImage },
        State: { Running: true, Pid: 4242 },
        HostConfig: { Privileged: true, CgroupnsMode: 'private' },
      };
    },
    async stopContainer(containerId, timeout) {
      calls.stop.push([containerId, timeout]);
      return {};
    },
    ...overrides.docker,
  };
  const adapters = {
    async health(mode, context) {
      calls.health.push([mode, context]);
      return [{ name: 'nosh-build', required: true, ok: true }];
    },
    async attach(mode, context, options = {}) {
      calls.attach.push([mode, context]);
      const logPath = path.join(context.evidenceDir, 'nosh-build.jsonl');
      fs.writeFileSync(
        logPath,
        [
          JSON.stringify({
            eventKind: 'process-exec',
            observedCgroupId: '901',
            process: { comm: 'build-step' },
          }),
          JSON.stringify({
            recordKind: 'stats',
            final: true,
            targetCgroupId: '900',
            lostEvents: 0,
          }),
          '',
        ].join('\n'),
        { mode: 0o600 },
      );
      const attached = [{ name: 'nosh-build', required: true, logPath }];
      await options.onAttached?.(attached);
      return attached;
    },
    async runtimeHealth(run, context) {
      return [{ name: 'nosh-build', required: true, ok: true }];
    },
    async detach(run, context) {
      calls.detach.push([run.runId, context]);
      return [{
        name: 'nosh-build',
        ok: true,
        cleanupCritical: true,
        cleanupOk: true,
      }];
    },
    ...overrides.adapters,
  };
  const processStartTimeProvider = overrides.processStartTimeProvider
    || (async (pid) => (pid === 4242 ? 'builder-start' : '12345'));
  const processOwnerProvider = overrides.processOwnerProvider || (async () => (
    typeof process.getuid === 'function' ? process.getuid() : 0
  ));
  const cgroupProvider = overrides.cgroupProvider || (async (pid, containerId) => {
    calls.cgroup.push([pid, containerId]);
    return {
      path: cgroupPath,
      id: '900',
      membership: `/docker/${builderId}`,
      processPath: path.join(cgroupPath, 'init'),
      processId: '901',
      processMembership: `/docker/${builderId}/init`,
    };
  });
  const cgroupNamespaceProvider = overrides.cgroupNamespaceProvider
    || (async (pid) => (pid === 4242 ? '4026533000' : '4026531835'));

  return {
    root,
    stateDir,
    workdir,
    cgroupPath,
    docker,
    adapters,
    processStartTimeProvider,
    processOwnerProvider,
    cgroupProvider,
    cgroupNamespaceProvider,
    calls,
  };
}

function beginRequest(selected, overrides = {}) {
  return {
    runId: 'profile-one-cold',
    mode: 'build-profile',
    pass: 'cold',
    depth: 'balanced',
    workdir: selected.workdir,
    builderContainerId: builderId,
    builderName: 'nosh-builder',
    builderNode: 'nosh-builder0',
    builderImage,
    clientPid: 9191,
    clientStartTime: '12345',
    clientUid: typeof process.getuid === 'function' ? process.getuid() : 0,
    clientGid: typeof process.getgid === 'function' ? process.getgid() : 0,
    ...overrides,
  };
}

async function serviceFor(selected) {
  const { BuildSessionService } = await sessionModule();
  const service = new BuildSessionService({
    stateDir: selected.stateDir,
    buildRetention: selected.buildRetention,
    docker: selected.docker,
    buildAdapters: selected.adapters,
    cgroupProvider: selected.cgroupProvider,
    cgroupNamespaceProvider: selected.cgroupNamespaceProvider,
    processStartTimeProvider: selected.processStartTimeProvider,
    processOwnerProvider: selected.processOwnerProvider,
  });
  await service.initialize();
  return service;
}

test('collector completion validates terminal and declared summary records', async (t) => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'nosh-completion-records-'));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const output = path.join(root, 'collector.jsonl');
  const { buildSessionInternals } = await sessionModule();
  const contract = {
    match: { recordKind: 'stats', final: true },
    requireZero: ['counters.fileMapFull'],
  };
  const fileSummary = {
    schemaVersion: 1,
    recordKind: 'file-summary',
    metadataOnly: true,
    timestampUnixNs: '100',
    targetCgroupId: '9',
    path: '/app/package.json',
    aggregationKey: 'resolved-path',
    firstObservedNs: '10',
    lastObservedNs: '90',
    opens: '3',
    accessCounts: { read: '3', write: '0', execute: '0', create: '0' },
  };
  const final = {
    schemaVersion: 1,
    recordKind: 'stats',
    final: true,
    timestampUnixNs: '101',
    targetCgroupId: '9',
    fileSummaryRecords: '1',
    counters: { fileMapFull: '0', fileOpenObservations: '3' },
  };

  fs.writeFileSync(output, `${JSON.stringify(fileSummary)}\n${JSON.stringify(final)}\n`);
  const valid = await buildSessionInternals.inspectJsonlCompletion(output, contract);
  assert.equal(valid.complete, true);
  assert.equal(valid.finalRecords, 1);
  assert.equal(valid.summaryCountsMatch, true);
  assert.deepEqual(valid.summaryRecords, {
    file: '1',
    flow: '0',
    fileOpenObservations: '3',
  });

  fs.writeFileSync(output, `${JSON.stringify(fileSummary)}\n${JSON.stringify({
    ...final,
    fileSummaryRecords: '2',
  })}\n`);
  const mismatched = await buildSessionInternals.inspectJsonlCompletion(output, contract);
  assert.equal(mismatched.complete, false);
  assert.equal(mismatched.summaryCountsMatch, false);

  fs.writeFileSync(output, `${JSON.stringify(final)}\n${JSON.stringify(final)}\n`);
  const duplicateFinal = await buildSessionInternals.inspectJsonlCompletion(output, contract);
  assert.equal(duplicateFinal.complete, false);
  assert.equal(duplicateFinal.finalRecords, 2);
});

test('builder cgroup resolution selects the exact Docker container boundary', async () => {
  const { buildSessionInternals } = await sessionModule();
  const select = buildSessionInternals.containerCgroupMembership;

  assert.equal(
    select(`/docker/buildx/${builderId}/init`, builderId),
    `/docker/buildx/${builderId}`,
  );
  assert.equal(
    select(`/system.slice/docker-${builderId}.scope/init`, builderId),
    `/system.slice/docker-${builderId}.scope`,
  );
  assert.equal(select(`/docker/${builderId}`, builderId), `/docker/${builderId}`);

  for (const membership of [
    '/',
    `/docker/buildx/prefix-${builderId}/init`,
    `/docker/buildx/${builderId}-suffix/init`,
    `/docker/buildx/${'b'.repeat(64)}/init`,
  ]) {
    assert.throws(
      () => select(membership, builderId),
      /exact Docker container boundary/,
    );
  }
  assert.throws(
    () => select(`/docker/${builderId}/init/${builderId}`, builderId),
    /duplicate Docker container boundaries/,
  );
});

test('build session admits an exact builder and seals complete evidence', async (t) => {
  const selected = fixture(t, {
    processStartTimeProvider: async (pid) => (
      pid === 4242 ? 'builder-start' : '12345'
    ),
  });
  const service = await serviceFor(selected);
  const started = await service.begin(beginRequest(selected, {
    clientStartTime: '12345',
  }));

  assert.equal(started.status, 'sensors-ready');
  assert.equal(started.builder.containerId, builderId);
  assert.equal(started.builder.containerName, 'buildx_buildkit_nosh-builder0');
  assert.equal(started.builder.cgroupNamespace, '4026533000');
  assert.equal(started.builder.cgroup.id, '900');
  assert.deepEqual(selected.calls.cgroup, [[4242, builderId]]);
  assert.equal(selected.calls.health.length, 1);
  assert.equal(selected.calls.attach.length, 1);
  assert.equal(selected.calls.health[0][1].cgroupPath, selected.cgroupPath);
  assert.equal(selected.calls.health[0][1].cgroupId, '900');
  assert.equal(selected.calls.attach[0][1].cgroupPath, selected.cgroupPath);
  assert.equal(selected.calls.attach[0][1].cgroupId, '900');
  assert.notEqual(selected.calls.attach[0][1].cgroupId, '901');

  const buildStartedAt = started.startedAt;
  const buildFinishedAt = new Date(
    Date.parse(buildStartedAt) + 1_000,
  ).toISOString();
  const finished = await service.finish(started.runId, {
    buildExitCode: 0,
    buildStartedAt,
    buildFinishedAt,
    metadata: { imageDigest: 'sha256:' + 'd'.repeat(64) },
  });

  assert.equal(finished.status, 'complete');
  assert.equal(finished.buildSucceeded, true);
  assert.equal(finished.evidenceComplete, true);
  assert.equal(finished.manifest.kind, 'NoshBuildEvidenceManifest');
  assert.equal(finished.manifest.identity.ok, true);
  assert.equal(finished.manifest.cleanup.ok, true);
  assert.equal(
    finished.manifest.sources.find((source) => source.name === 'nosh-build')
      .completion.descendantObserved,
    true,
  );
  assert.equal(selected.calls.detach.length, 1);
  assert.equal(selected.calls.inspect.length, 2);
  assert.deepEqual(selected.calls.cgroup, [
    [4242, builderId],
    [4242, builderId],
  ]);

  const stored = await service.listRuns();
  assert.equal(stored.length, 1);
  assert.equal(stored[0].status, 'complete');
  assert.equal(fs.statSync(stored[0].evidenceManifest).mode & 0o7777, 0o600);
  assert.equal(
    JSON.parse(fs.readFileSync(stored[0].evidenceManifest, 'utf8')).complete,
    true,
  );
});

test('optional collector completion is truthful without blocking required evidence', async (t) => {
  const selected = fixture(t);
  selected.adapters.attach = async (mode, context, options = {}) => {
    const requiredPath = path.join(context.evidenceDir, 'nosh-build.jsonl');
    const optionalPath = path.join(context.evidenceDir, 'nosh-url.jsonl');
    fs.writeFileSync(requiredPath, `${JSON.stringify({
      recordKind: 'stats',
      final: true,
      targetCgroupId: '900',
      lostEvents: 0,
    })}\n`, { mode: 0o600 });
    fs.writeFileSync(optionalPath, `${JSON.stringify({
      schemaVersion: 1,
      recordKind: 'stats',
      final: true,
      timestampUnixNs: '1',
      cgroupId: '900',
      provider: 'libcurl',
      providersAttached: ['libcurl'],
      observationOnly: true,
      coverageComplete: false,
      coverageLimitation: 'dynamic attachment is incomplete',
      counters: {},
    })}\n`, { mode: 0o600 });
    const attached = [{
      name: 'nosh-build',
      required: true,
      logPath: requiredPath,
    }, {
      name: 'nosh-url',
      required: true,
      evidenceRequired: false,
      logPath: optionalPath,
      completion: { match: { recordKind: 'stats', final: true } },
    }];
    await options.onAttached?.(attached);
    return attached;
  };
  selected.adapters.runtimeHealth = async () => [{
    name: 'nosh-build', required: true, ok: true,
  }, {
    name: 'nosh-url', required: false, ok: true,
  }];
  selected.adapters.detach = async () => [{
    name: 'nosh-build', ok: true, evidenceOk: true, cleanupCritical: true, cleanupOk: true,
  }, {
    name: 'nosh-url', ok: true, evidenceOk: true, cleanupCritical: true, cleanupOk: true,
  }];
  const service = await serviceFor(selected);
  const started = await service.begin(beginRequest(selected, {
    mode: 'build-net-learn',
  }));
  const buildStartedAt = started.startedAt;
  const buildFinishedAt = new Date(Date.parse(buildStartedAt) + 1_000).toISOString();
  const finished = await service.finish(started.runId, {
    buildExitCode: 0,
    buildStartedAt,
    buildFinishedAt,
  });

  assert.equal(finished.evidenceComplete, true);
  assert.equal(finished.manifest.complete, true);
  const optional = finished.manifest.sources.find(
    (source) => source.name === 'nosh-url',
  );
  assert.equal(optional.required, false);
  assert.equal(optional.complete, false);
  assert.equal(optional.completion.complete, true);
  assert.equal(optional.completion.coversBuildEnd, false);
  assert.match(optional.error, /did not cover build completion/);
});

test('build session rejects a builder without a private cgroup namespace', async (t) => {
  const selected = fixture(t);
  selected.docker.inspectContainer = async () => ({
    Id: builderId,
    Name: '/buildx_buildkit_nosh-builder0',
    Image: 'sha256:' + 'c'.repeat(64),
    Config: { Image: builderImage },
    State: { Running: true, Pid: 4242 },
    HostConfig: { Privileged: true, CgroupnsMode: 'host' },
  });
  const service = await serviceFor(selected);

  await assert.rejects(
    service.begin(beginRequest(selected)),
    /must use a private cgroup namespace/,
  );
  assert.equal(selected.calls.health.length, 0);
});

test('build session rejects a builder in the guard host cgroup namespace', async (t) => {
  const selected = fixture(t, {
    cgroupNamespaceProvider: async () => '4026531835',
  });
  const service = await serviceFor(selected);

  await assert.rejects(
    service.begin(beginRequest(selected)),
    /joined the host cgroup namespace/,
  );
  assert.equal(selected.calls.health.length, 0);
});

test('build session fails closed when the exact builder identity drifts', async (t) => {
  let cgroupCalls = 0;
  const selected = fixture(t, {
    processStartTimeProvider: async (pid) => (
      pid === 4242 ? 'builder-start' : '12345'
    ),
    cgroupProvider: async () => ({
      path: selected.cgroupPath,
      id: cgroupCalls++ === 0 ? '900' : 'changed-cgroup',
      membership: `/docker/${builderId}`,
      processPath: path.join(selected.cgroupPath, 'init'),
      processId: '901',
      processMembership: `/docker/${builderId}/init`,
    }),
  });
  const service = await serviceFor(selected);
  const started = await service.begin(beginRequest(selected, {
    clientStartTime: '12345',
  }));
  const finished = await service.finish(started.runId, { buildExitCode: 0 });

  assert.equal(finished.status, 'failed');
  assert.equal(finished.buildSucceeded, true);
  assert.equal(finished.evidenceComplete, false);
  assert.equal(finished.manifest.identity.ok, false);
  assert.match(finished.manifest.identity.error, /cgroup ID changed/);
  assert.equal(selected.calls.detach.length, 1);
});

test('build session fails closed when the builder init cgroup leaf drifts', async (t) => {
  let cgroupCalls = 0;
  const selected = fixture(t, {
    processStartTimeProvider: async (pid) => (
      pid === 4242 ? 'builder-start' : '12345'
    ),
    cgroupProvider: async () => ({
      path: selected.cgroupPath,
      id: '900',
      membership: `/docker/${builderId}`,
      processPath: path.join(selected.cgroupPath, 'init'),
      processId: cgroupCalls++ === 0 ? '901' : 'changed-init-cgroup',
      processMembership: `/docker/${builderId}/init`,
    }),
  });
  const service = await serviceFor(selected);
  const started = await service.begin(beginRequest(selected, {
    clientStartTime: '12345',
  }));
  const finished = await service.finish(started.runId, { buildExitCode: 0 });

  assert.equal(finished.status, 'failed');
  assert.equal(finished.manifest.identity.ok, false);
  assert.match(finished.manifest.identity.error, /init cgroup ID changed/);
  assert.equal(selected.calls.detach.length, 1);
});

test('build session fails closed when the builder cgroup namespace drifts', async (t) => {
  let builderNamespaceCalls = 0;
  const selected = fixture(t, {
    processStartTimeProvider: async (pid) => (
      pid === 4242 ? 'builder-start' : '12345'
    ),
    cgroupNamespaceProvider: async (pid) => {
      if (pid !== 4242) return '4026531835';
      builderNamespaceCalls += 1;
      return builderNamespaceCalls === 1 ? '4026533000' : '4026533001';
    },
  });
  const service = await serviceFor(selected);
  const started = await service.begin(beginRequest(selected, {
    clientStartTime: '12345',
  }));
  const finished = await service.finish(started.runId, { buildExitCode: 0 });

  assert.equal(finished.status, 'failed');
  assert.equal(finished.manifest.identity.ok, false);
  assert.match(finished.manifest.identity.error, /cgroup namespace changed/);
  assert.equal(selected.calls.detach.length, 1);
});

test('required collector health failure removes its inert admission reservation', async (t) => {
  let attached = false;
  const selected = fixture(t, {
    adapters: {
      async health() {
        return [{ name: 'nosh-build', required: true, ok: false }];
      },
      async attach() {
        attached = true;
        return [];
      },
      async detach() {
        return [];
      },
    },
  });
  selected.buildRetention = {
    maximumRetainedRuns: 1,
    maximumExportedRuns: 0,
    maximumExportedAgeMs: 0,
  };
  const service = await serviceFor(selected);

  await assert.rejects(
    service.begin(beginRequest(selected)),
    /required build collectors are unhealthy: nosh-build/,
  );
  assert.equal(attached, false);
  assert.deepEqual(await service.listRuns(), []);
  assert.equal(
    fs.existsSync(path.join(selected.stateDir, 'build-evidence', 'profile-one-cold')),
    false,
  );
  await assert.rejects(
    service.begin(beginRequest(selected, { runId: 'profile-two-cold' })),
    /required build collectors are unhealthy: nosh-build/,
  );
  assert.deepEqual(await service.listRuns(), []);
});

test('required collector health failure reports its structured diagnostic', async (t) => {
  const selected = fixture(t, {
    processStartTimeProvider: async (pid) => (
      pid === 4242 ? 'builder-start' : '12345'
    ),
    adapters: {
      async health() {
        return [
          {
            name: 'nosh-l4',
            required: true,
            ok: false,
            detail: JSON.stringify({
              recordKind: 'status',
              status: 'unhealthy',
              message: 'cgroup id mismatch: resolved 901 but expected 900',
            }),
          },
          {
            name: 'escape-json',
            required: true,
            ok: false,
            detail: JSON.stringify({
              message: 'unsafe terminal escape \u001b[2J',
            }),
          },
          {
            name: 'bell-text',
            required: true,
            ok: false,
            detail: 'unsafe terminal bell \u0007',
          },
        ];
      },
      async attach() {
        assert.fail('attach must not run after an unhealthy result');
      },
      async detach() {
        return [];
      },
    },
  });
  const service = await serviceFor(selected);

  await assert.rejects(
    service.begin(beginRequest(selected, { clientStartTime: '12345' })),
    (error) => {
      assert.equal(
        error.message,
        'required build collectors are unhealthy: nosh-l4 (cgroup id mismatch: resolved 901 but expected 900), escape-json, bell-text',
      );
      assert.doesNotMatch(error.message, /[\x00-\x1f\x7f-\x9f]/);
      return true;
    },
  );
  assert.deepEqual(await service.listRuns(), []);
});

test('missing critical cgroup metrics prevent collector admission', async (t) => {
  const selected = fixture(t);
  fs.unlinkSync(path.join(selected.cgroupPath, 'io.pressure'));
  const service = await serviceFor(selected);

  await assert.rejects(
    service.begin(beginRequest(selected)),
    /initial builder cgroup snapshot is missing required cgroup metrics: io.pressure/,
  );
  assert.equal(selected.calls.attach.length, 0);
  assert.deepEqual(await service.listRuns(), []);
});

test('build session admission binds the client PID to its claimed uid', async (t) => {
  const expectedUid = typeof process.getuid === 'function' ? process.getuid() : 0;
  const selected = fixture(t, {
    processOwnerProvider: async () => expectedUid + 1,
  });
  const service = await serviceFor(selected);

  await assert.rejects(
    service.begin(beginRequest(selected)),
    (error) =>
      error.code === 'GUARD_BUILD_IDENTITY_MISMATCH'
      && /process owner does not match/.test(error.message),
  );
  assert.equal(selected.calls.health.length, 0);
  assert.equal(selected.calls.attach.length, 0);
  assert.deepEqual(await service.listRuns(), []);
});

test('one BuildKit worker cannot be admitted to concurrent build sessions', async (t) => {
  const selected = fixture(t);
  const service = await serviceFor(selected);
  await service.begin(beginRequest(selected));

  await assert.rejects(
    service.begin(beginRequest(selected, { runId: 'profile-two-cold' })),
    (error) =>
      error.code === 'GUARD_BUILD_LEASE_CONFLICT'
      && error.statusCode === 409,
  );
  assert.equal(selected.calls.attach.length, 1);
});

test('builder lease matching normalizes the exact container ID', async (t) => {
  const selected = fixture(t);
  const service = await serviceFor(selected);
  await service.begin(beginRequest(selected));

  await assert.rejects(
    service.begin(beginRequest(selected, {
      runId: 'profile-two-cold',
      builderContainerId: builderId.toUpperCase(),
      builderName: 'misleading-builder-name',
    })),
    (error) =>
      error.code === 'GUARD_BUILD_LEASE_CONFLICT'
      && error.statusCode === 409,
  );
  assert.equal(selected.calls.inspect.length, 1);
  assert.equal(selected.calls.attach.length, 1);
});

test('build session IDs cannot escape or exhaust the evidence namespace', async (t) => {
  const selected = fixture(t);
  const service = await serviceFor(selected);

  for (const runId of ['.', '..', 'a'.repeat(129), '../escaped']) {
    await assert.rejects(
      service.begin(beginRequest(selected, { runId })),
      /runId contains unsupported characters/,
    );
  }
  assert.equal(selected.calls.inspect.length, 0);
  assert.deepEqual(await service.listRuns(), []);
});

test('watchdog aborts an orphaned build session and stops its builder', async (t) => {
  let clientAlive = true;
  const selected = fixture(t, {
    processStartTimeProvider: async (pid) => {
      if (pid === 4242) {
        return 'builder-start';
      }
      if (!clientAlive) {
        throw Object.assign(new Error('process is gone'), { code: 'ENOENT' });
      }
      return '12345';
    },
  });
  const service = await serviceFor(selected);
  await service.begin(beginRequest(selected));
  clientAlive = false;

  const results = await service.watchdogTick();
  assert.equal(results.length, 1);
  assert.equal(results[0].status, 'aborted');
  assert.equal(results[0].quarantineActive, false);
  assert.deepEqual(selected.calls.stop, [[builderId, 10]]);
  assert.match(results[0].manifest.limitations[0], /build client process exited/);
});

test('watchdog retries quarantined builder containment until it succeeds', async (t) => {
  let clientAlive = true;
  let stopAttempts = 0;
  const selected = fixture(t, {
    docker: {
      async stopContainer(containerId, timeout) {
        selected.calls.stop.push([containerId, timeout]);
        stopAttempts += 1;
        if (stopAttempts === 1) {
          throw Object.assign(new Error('temporary Docker failure'), {
            statusCode: 500,
          });
        }
        return {};
      },
    },
    processStartTimeProvider: async (pid) => {
      if (pid === 4242) return 'builder-start';
      if (!clientAlive) {
        throw Object.assign(new Error('process is gone'), { code: 'ENOENT' });
      }
      return '12345';
    },
  });
  const service = await serviceFor(selected);
  await service.begin(beginRequest(selected));
  clientAlive = false;

  const [quarantined] = await service.watchdogTick();
  assert.equal(quarantined.status, 'quarantined');
  assert.equal(quarantined.quarantineActive, true);
  assert.equal(quarantined.quarantineAttempts, 1);
  await assert.rejects(
    service.acknowledgeExport(quarantined.runId, {
      portableBundleHash: `sha256:${'9'.repeat(64)}`,
    }),
    /cannot acknowledge export from status quarantined/,
  );

  const [recovered] = await service.watchdogTick();
  assert.equal(recovered.status, 'aborted');
  assert.equal(recovered.quarantineActive, false);
  assert.equal(stopAttempts, 2);
});

test('daemon restart recovers and contains an active build session', async (t) => {
  const selected = fixture(t);
  const first = await serviceFor(selected);
  const started = await first.begin(beginRequest(selected));
  assert.equal(started.status, 'sensors-ready');

  const restarted = await serviceFor(selected);
  const [recovered] = await restarted.listRuns();
  assert.equal(recovered.status, 'aborted');
  assert.equal(recovered.evidenceComplete, false);
  const manifest = JSON.parse(
    fs.readFileSync(recovered.evidenceManifest, 'utf8'),
  );
  assert.match(
    manifest.limitations[0],
    /guard daemon restarted during build profiling/,
  );
  assert.deepEqual(selected.calls.stop, [[builderId, 10]]);
});

test('portable export acknowledgement is idempotent and hash-bound', async (t) => {
  const selected = fixture(t);
  const service = await serviceFor(selected);
  const started = await service.begin(beginRequest(selected));
  const buildFinishedAt = new Date(
    Date.parse(started.startedAt) + 1_000,
  ).toISOString();
  await service.finish(started.runId, {
    buildExitCode: 0,
    buildStartedAt: started.startedAt,
    buildFinishedAt,
  });
  const portableBundleHash = `sha256:${'e'.repeat(64)}`;

  const acknowledged = await service.acknowledgeExport(started.runId, {
    portableBundleHash,
  });
  assert.equal(acknowledged.portableExport.bundleHash, portableBundleHash);
  assert.equal(acknowledged.retention.pruned.length, 0);
  const repeated = await service.acknowledgeExport(started.runId, {
    portableBundleHash,
  });
  assert.equal(
    repeated.portableExport.acknowledgedAt,
    acknowledged.portableExport.acknowledgedAt,
  );
  await assert.rejects(
    service.acknowledgeExport(started.runId, {
      portableBundleHash: `sha256:${'f'.repeat(64)}`,
    }),
    /different portable bundle/,
  );
});

test('late collector persistence cannot overwrite terminal session state', async (t) => {
  let persistAttached;
  const selected = fixture(t, {
    adapters: {
      async attach(mode, context, options = {}) {
        const logPath = path.join(context.evidenceDir, 'late.jsonl');
        fs.writeFileSync(
          logPath,
          '{"recordKind":"stats","final":true,"lostEvents":0}\n',
          { mode: 0o600 },
        );
        persistAttached = options.onAttached;
        const attached = [{ name: 'nosh-build', required: true, logPath }];
        await persistAttached(attached);
        return attached;
      },
    },
  });
  const service = await serviceFor(selected);
  const started = await service.begin(beginRequest(selected));
  const buildFinishedAt = new Date(
    Date.parse(started.startedAt) + 1_000,
  ).toISOString();
  const finished = await service.finish(started.runId, {
    buildExitCode: 0,
    buildStartedAt: started.startedAt,
    buildFinishedAt,
  });
  assert.equal(finished.status, 'complete');

  await persistAttached([{
    name: 'nosh-build',
    required: true,
    exitStatusKnown: true,
    exitCode: 9,
  }]);
  const [persisted] = await service.listRuns();
  assert.equal(persisted.status, 'complete');
  assert.equal(persisted.adapters[0].exitStatusKnown, undefined);
});

test('cleanup-critical collector failure keeps the builder lease quarantined', async (t) => {
  let collectorContained = false;
  const selected = fixture(t, {
    adapters: {
      async detach() {
        return [{
          name: 'nosh-build',
          ok: collectorContained,
          cleanupCritical: true,
          cleanupOk: collectorContained,
          error: collectorContained ? null : 'collector still running',
        }];
      },
    },
  });
  const service = await serviceFor(selected);
  const started = await service.begin(beginRequest(selected));
  const finished = await service.finish(started.runId, {
    buildExitCode: 0,
    buildStartedAt: started.startedAt,
    buildFinishedAt: new Date(
      Date.parse(started.startedAt) + 1_000,
    ).toISOString(),
  });
  assert.equal(finished.status, 'quarantined');
  assert.equal(finished.quarantineActive, true);
  await assert.rejects(
    service.acknowledgeExport(started.runId, {
      portableBundleHash: `sha256:${'7'.repeat(64)}`,
    }),
    /cannot acknowledge export from status quarantined/,
  );
  const [stillQuarantined] = await service.watchdogTick();
  assert.equal(stillQuarantined.status, 'quarantined');
  assert.equal(stillQuarantined.builderContained, true);
  assert.equal(stillQuarantined.collectorContained, false);

  collectorContained = true;
  const [recovered] = await service.watchdogTick();
  assert.equal(recovered.status, 'aborted');
  assert.equal(recovered.quarantineActive, false);
});

test('late collector drain failure cannot produce a complete manifest', async (t) => {
  const selected = fixture(t, {
    adapters: {
      async detach() {
        return [{
          name: 'nosh-build',
          ok: false,
          cleanupCritical: true,
          cleanupOk: true,
          evidenceOk: false,
          exitStatusKnown: true,
          exitCode: 1,
          exitSignal: null,
          evidenceFailures: [{
            stream: 'stderr',
            error: 'collector diagnostics failed during drain',
          }],
          error: 'collector diagnostics failed during drain',
        }];
      },
    },
  });
  const service = await serviceFor(selected);
  const started = await service.begin(beginRequest(selected));
  const finished = await service.finish(started.runId, {
    buildExitCode: 0,
    buildStartedAt: started.startedAt,
    buildFinishedAt: new Date(
      Date.parse(started.startedAt) + 1_000,
    ).toISOString(),
  });

  assert.equal(finished.status, 'failed');
  assert.equal(finished.quarantineActive, false);
  assert.equal(finished.evidenceComplete, false);
  assert.equal(finished.manifest.cleanup.ok, true);
  assert.equal(finished.manifest.cleanup.evidenceOk, false);
  const source = finished.manifest.sources.find(
    (entry) => entry.name === 'nosh-build',
  );
  assert.equal(source.complete, false);
  assert.match(source.error, /diagnostics failed during drain/);
});

test('retention only prunes acknowledged terminal evidence', async (t) => {
  const { buildSessionInternals } = await sessionModule();
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'nosh-build-retention-'));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  let now = Date.parse('2026-08-10T00:00:00.000Z');
  const store = new buildSessionInternals.BuildSessionStateStore(root, {
    maximumRetainedRuns: 8,
    maximumExportedRuns: 1,
    maximumExportedAgeMs: 60_000,
    now: () => now,
  });
  await store.initialize();

  async function retainedRun(runId, status, quarantineActive = false) {
    const evidenceDir = store.evidencePath(runId);
    fs.mkdirSync(evidenceDir, { mode: 0o700 });
    const evidenceManifest = path.join(
      evidenceDir,
      'build-evidence-manifest.json',
    );
    fs.writeFileSync(evidenceManifest, '{"complete":true}\n', { mode: 0o600 });
    return store.writeRun({
      runId,
      status,
      quarantineActive,
      evidenceDir,
      evidenceManifest,
    });
  }

  await retainedRun('active-run', 'sensors-ready');
  await retainedRun('quarantined-run', 'quarantined', true);
  await retainedRun('unexported-run', 'complete');
  await retainedRun('old-export', 'complete');
  await store.acknowledgePortableExport('old-export', {
    portableBundleHash: `sha256:${'1'.repeat(64)}`,
  });
  now += 1_000;
  await retainedRun('new-export', 'failed');
  await store.acknowledgePortableExport('new-export', {
    portableBundleHash: `sha256:${'2'.repeat(64)}`,
  });

  const retention = await store.pruneRetainedRuns();
  assert.deepEqual(retention.pruned, ['old-export']);
  assert.equal(fs.existsSync(store.runPath('old-export')), false);
  assert.equal(fs.existsSync(store.evidencePath('old-export')), false);
  assert.deepEqual(
    (await store.listRuns()).map((run) => run.runId).sort(),
    ['active-run', 'new-export', 'quarantined-run', 'unexported-run'],
  );
  assert.equal(fs.existsSync(store.evidencePath('active-run')), true);
  assert.equal(fs.existsSync(store.evidencePath('quarantined-run')), true);
  assert.equal(fs.existsSync(store.evidencePath('unexported-run')), true);

  now += 60_000;
  const aged = await store.pruneRetainedRuns();
  assert.deepEqual(aged.pruned, ['new-export']);
  assert.deepEqual(
    (await store.listRuns()).map((run) => run.runId).sort(),
    ['active-run', 'quarantined-run', 'unexported-run'],
  );
});

test('retention capacity fails closed instead of deleting unexported runs', async (t) => {
  const selected = fixture(t);
  selected.buildRetention = {
    maximumRetainedRuns: 1,
    maximumExportedRuns: 0,
    maximumExportedAgeMs: 0,
  };
  const service = await serviceFor(selected);
  await service.begin(beginRequest(selected));

  await assert.rejects(
    service.begin(beginRequest(selected, {
      runId: 'profile-two-cold',
      builderName: 'different-builder',
      builderNode: 'different-builder0',
    })),
    (error) => error.code === 'GUARD_BUILD_RETENTION_FULL'
      && error.statusCode === 507,
  );
  const [retained] = await service.listRuns();
  assert.equal(retained.status, 'sensors-ready');
});

test('acknowledgement preserves the current run through its response GC', async (t) => {
  const { buildSessionInternals } = await sessionModule();
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'nosh-build-ack-gc-'));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const store = new buildSessionInternals.BuildSessionStateStore(root, {
    maximumRetainedRuns: 2,
    maximumExportedRuns: 0,
    maximumExportedAgeMs: 0,
    now: () => Date.parse('2026-08-10T00:00:00.000Z'),
  });
  await store.initialize();
  const runId = 'preserved-ack';
  const evidenceDir = store.evidencePath(runId);
  fs.mkdirSync(evidenceDir, { mode: 0o700 });
  const evidenceManifest = path.join(evidenceDir, 'build-evidence-manifest.json');
  fs.writeFileSync(evidenceManifest, '{"complete":true}\n', { mode: 0o600 });
  await store.writeRun({
    runId,
    status: 'complete',
    evidenceDir,
    evidenceManifest,
  });
  await store.acknowledgePortableExport(runId, {
    portableBundleHash: `sha256:${'6'.repeat(64)}`,
  });

  const responseGc = await store.pruneRetainedRuns({
    preserveRunIds: [runId],
  });
  assert.deepEqual(responseGc.pruned, []);
  assert.equal(fs.existsSync(store.runPath(runId)), true);
  const laterGc = await store.pruneRetainedRuns();
  assert.deepEqual(laterGc.pruned, [runId]);
  assert.equal(fs.existsSync(store.runPath(runId)), false);
});

test('concurrent admissions atomically reserve retention capacity', async (t) => {
  const selected = fixture(t);
  selected.buildRetention = {
    maximumRetainedRuns: 1,
    maximumExportedRuns: 0,
    maximumExportedAgeMs: 0,
  };
  const service = await serviceFor(selected);

  const results = await Promise.allSettled([
    service.begin(beginRequest(selected, { runId: 'concurrent-one' })),
    service.begin(beginRequest(selected, { runId: 'concurrent-two' })),
  ]);
  assert.equal(
    results.filter((result) => result.status === 'fulfilled').length,
    1,
  );
  const [rejected] = results.filter((result) => result.status === 'rejected');
  assert.equal(rejected.reason.code, 'GUARD_BUILD_RETENTION_FULL');
  assert.equal((await service.listRuns()).length, 1);
});

test('process identity parser handles command names containing spaces and parentheses', async () => {
  const { buildSessionInternals } = await sessionModule();
  const fields = [
    'S', '1', '2', '3', '4', '5', '6', '7', '8', '9', '10', '11', '12', '13',
    '14', '15', '16', '17', '18', '424242', '20', '21', '22', '23', '24',
  ];
  const stat = `99 (builder (worker) name) ${fields.join(' ')}`;
  assert.equal(
    buildSessionInternals.processStartTimeFromStat(stat),
    '424242',
  );
});
