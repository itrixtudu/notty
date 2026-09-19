'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const test = require('node:test');
const { pathToFileURL } = require('node:url');

const appRoot = path.resolve(__dirname, '..');

async function storeModule() {
  return import(pathToFileURL(
    path.join(appRoot, 'lib/guardd/build-profile-store.js'),
  ).href);
}

async function artifactsModule() {
  return import(pathToFileURL(
    path.join(appRoot, 'lib/guardd/build-profile-artifacts.js'),
  ).href);
}

async function mirrorModule() {
  return import(pathToFileURL(
    path.join(appRoot, 'lib/guardd/build-profile-mirror.js'),
  ).href);
}

function fixture(t) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'nosh-build-store-'));
  const home = path.join(root, 'home');
  const context = path.join(root, 'context');
  fs.mkdirSync(home);
  fs.mkdirSync(context);
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  return { root, home, context };
}

async function runInput(t, current, overrides = {}) {
  const artifacts = await artifactsModule();
  const mode = overrides.mode || 'build-profile';
  const required = artifacts.requiredBuildEvidenceSources(mode, 'balanced');
  const network = mode === 'build-net-learn';
  return {
    context: current.context,
    runId: overrides.runId || 'run-one',
    mode,
    generatedAt: overrides.generatedAt || '2026-08-10T00:00:02.000Z',
    startedAt: '2026-08-10T00:00:00.000Z',
    endedAt: '2026-08-10T00:00:02.000Z',
    builder: { imageDigest: `sha256:${'a'.repeat(64)}` },
    build: {
      success: true,
      exitCode: 0,
      platform: 'linux/amd64',
      cacheMode: network ? 'cold' : 'compare',
      depth: 'balanced',
      passes: network
        ? [{ name: 'cold', success: true, exitCode: 0, durationMs: 2_000 }]
        : [
            { name: 'cold', success: true, exitCode: 0, durationMs: 2_000 },
            { name: 'warm', success: true, exitCode: 0, durationMs: 500 },
          ],
    },
    coverage: {
      builderIdentityStable: true,
      exclusiveBuilderLease: true,
      parentObserved: true,
      cleanupComplete: true,
      freshBuilder: network,
      forcedSourcePulls: network,
      cacheImportsDisabled: network,
      allReachableStepsExecuted: network,
    },
    sources: required.map((name) => ({
      name,
      format: 'ndjson',
      content: `${JSON.stringify({ source: name, final: true })}\n`,
      required: true,
      complete: true,
      lostEvents: 0,
      parseErrors: 0,
      completionMarker: 'clean-supervised-stop',
    })),
    observations: network
      ? {
          network: {
            destinations: [
              {
                fqdn: null,
                ip: '203.0.113.8',
                protocol: 'tcp',
                port: 443,
                source: 'nosh-l4',
              },
            ],
            directIp: [],
            encryptedDns: [],
            privateDestinations: [],
            parseFailures: [],
            unresolved: [],
          },
        }
      : {},
    ...overrides,
  };
}

test('store writes immutable private and redacted portable build bundles', async (t) => {
  const { BuildProfileStore, BUILD_PROFILE_FILES } = await storeModule();
  const current = fixture(t);
  const store = new BuildProfileStore({ home: current.home });
  const result = await store.finalizeRun(await runInput(t, current));
  const roots = await store.initialize();
  assert.ok(result.directory.startsWith(roots.profileRoot));
  assert.equal(result.manifest.complete, true);
  assert.equal(result.candidate.kind, 'NoshBuildProfileCandidate');
  assert.equal(result.candidateAdvanced, true);
  assert.equal(fs.statSync(result.directory).mode & 0o777, 0o700);
  assert.equal(
    fs.statSync(path.join(result.directory, BUILD_PROFILE_FILES.evidence)).mode & 0o777,
    0o600,
  );
  const portableSource = fs.readFileSync(
    path.join(result.portableDirectory, 'report.json'),
    'utf8',
  );
  assert.doesNotMatch(portableSource, new RegExp(current.context.replaceAll('/', '\\/')));
  assert.doesNotMatch(portableSource, /dockerEndpoint|canonicalPath|raw\/|events/);
  assert.equal(result.portableBundle.kind, 'NoshBuildPortableBundle');
  const portableCandidate = JSON.parse(fs.readFileSync(
    path.join(result.portableDirectory, 'candidate.json'),
    'utf8',
  ));
  assert.equal(portableCandidate.kind, 'NoshBuildPortableCandidateProjection');
  assert.equal(
    portableCandidate.sourceCorrelation.privateCandidateContentHash,
    result.candidate.contentHash,
  );
  assert.notEqual(portableCandidate.contentHash, result.candidate.contentHash);

  const latest = await store.latestCandidate(current.context);
  assert.equal(latest.reference.runId, 'run-one');
  assert.equal(latest.candidate.contentHash, result.candidate.contentHash);
  assert.equal((await store.list(current.context)).length, 1);
  await assert.rejects(
    store.finalizeRun(await runInput(t, current)),
    /already exists/,
  );
});

test('failed, lossy, and warm-only runs retain diagnostics without advancing latest', async (t) => {
  const { BuildProfileStore } = await storeModule();
  const current = fixture(t);
  const store = new BuildProfileStore({ home: current.home });

  const warm = await runInput(t, current, { runId: 'warm-only' });
  warm.build.cacheMode = 'warm';
  warm.build.passes = [{ name: 'warm', success: true, exitCode: 0 }];
  const warmResult = await store.finalizeRun(warm);
  assert.equal(warmResult.manifest.complete, true);
  assert.equal(warmResult.candidate, null);
  assert.equal(warmResult.candidateAdvanced, false);
  assert.equal(await store.latestCandidate(current.context), null);

  const failed = await runInput(t, current, { runId: 'failed-one' });
  failed.build.success = false;
  failed.build.exitCode = 1;
  failed.sources[0].lostEvents = 1;
  const failedResult = await store.finalizeRun(failed);
  assert.equal(failedResult.manifest.complete, false);
  assert.equal(failedResult.candidate, null);
  assert.match(failedResult.manifest.incompleteReasons.join('\n'), /did not succeed/);
  assert.match(failedResult.manifest.incompleteReasons.join('\n'), /lost events/);
});

test('build network candidates use a physically separate store and latest pointer', async (t) => {
  const { BuildProfileStore, BUILD_PROFILE_FILES } = await storeModule();
  const current = fixture(t);
  const store = new BuildProfileStore({ home: current.home });
  const result = await store.finalizeRun(await runInput(t, current, {
    mode: 'build-net-learn',
    runId: 'net-one',
  }));
  const roots = await store.initialize();
  assert.ok(result.directory.startsWith(roots.networkRoot));
  assert.equal(result.candidate.kind, 'NoshBuildNetworkCandidate');
  assert.equal(result.manifestHash, result.candidate.evidence.manifestHash);
  assert.equal(result.policyDraft.kind, 'NoshBuildNetworkPolicyDraft');
  assert.deepEqual(result.policyDraft.source, {
    runId: 'net-one',
    candidateHash: result.candidate.contentHash,
    evidenceManifestHash: result.candidate.evidence.manifestHash,
  });
  assert.equal(
    fs.existsSync(path.join(
      result.portableDirectory,
      BUILD_PROFILE_FILES.networkPolicyDraft,
    )),
    false,
  );
  assert.equal(await store.latestCandidate(current.context), null);
  const latestNetwork = await store.latestCandidate(current.context, {
    mode: 'build-net-learn',
  });
  assert.equal(latestNetwork.reference.runId, 'net-one');
  assert.equal(fs.existsSync(path.join(current.home, '.nosh', 'net-profiles')), false);
});

test('network policy draft edits preserve immutable evidence and hash bindings', async (t) => {
  const { BuildProfileStore, BUILD_PROFILE_FILES } = await storeModule();
  const current = fixture(t);
  const store = new BuildProfileStore({ home: current.home });
  const result = await store.finalizeRun(await runInput(t, current, {
    mode: 'build-net-learn',
    runId: 'net-editable-draft',
  }));
  const evidencePath = path.join(result.directory, BUILD_PROFILE_FILES.evidence);
  const candidatePath = path.join(
    result.directory,
    BUILD_PROFILE_FILES.networkCandidate,
  );
  const draftPath = path.join(
    result.directory,
    BUILD_PROFILE_FILES.networkPolicyDraft,
  );
  const evidenceBefore = fs.readFileSync(evidencePath);
  const candidateBefore = fs.readFileSync(candidatePath);
  const edited = structuredClone(result.policyDraft);
  edited.rules[0].decision = 'deny';
  edited.notes.push('operator denied this observed build destination');
  fs.writeFileSync(draftPath, `${JSON.stringify(edited, null, 2)}\n`, {
    mode: 0o600,
  });

  const reread = await store.read(current.context, 'net-editable-draft', {
    mode: 'build-net-learn',
  });
  assert.equal(reread.policyDraft.rules[0].decision, 'deny');
  assert.deepEqual(reread.policyDraft.notes, [
    'operator denied this observed build destination',
  ]);
  assert.equal(reread.policyDraft.source.candidateHash, reread.candidate.contentHash);
  assert.equal(
    reread.policyDraft.source.evidenceManifestHash,
    reread.candidate.evidence.manifestHash,
  );
  assert.equal(reread.manifestHash, reread.candidate.evidence.manifestHash);
  assert.deepEqual(fs.readFileSync(evidencePath), evidenceBefore);
  assert.deepEqual(fs.readFileSync(candidatePath), candidateBefore);

  const rebound = structuredClone(edited);
  rebound.source.candidateHash = `sha256:${'0'.repeat(64)}`;
  fs.writeFileSync(draftPath, `${JSON.stringify(rebound, null, 2)}\n`, {
    mode: 0o600,
  });
  await assert.rejects(
    store.read(current.context, 'net-editable-draft', {
      mode: 'build-net-learn',
    }),
    /identity or evidence binding is invalid/,
  );
});

test('bundle reads detect source and portable artifact tampering', async (t) => {
  const { BuildProfileStore } = await storeModule();
  const current = fixture(t);
  const store = new BuildProfileStore({ home: current.home });
  const result = await store.finalizeRun(await runInput(t, current));
  const firstSource = result.manifest.sources.find((source) => source.present);
  fs.writeFileSync(path.join(result.directory, firstSource.file), 'tampered\n', {
    mode: 0o600,
  });
  await assert.rejects(
    store.read(current.context, 'run-one'),
    /does not match its manifest/,
  );
});

test('per-pass collector manifests combine into the final user-owned bundle input', async (t) => {
  const {
    BuildProfileStore,
    combineBuildPassManifests,
  } = await storeModule();
  const current = fixture(t);
  const passes = [];
  for (const pass of ['cold', 'warm']) {
    const passDir = path.join(current.root, pass);
    const evidenceDir = path.join(passDir, 'kernel-evidence');
    fs.mkdirSync(evidenceDir, { recursive: true, mode: 0o700 });
    fs.writeFileSync(
      path.join(passDir, 'buildx-progress.raw.jsonl'),
      `${JSON.stringify({
        vertexes: [{
          digest: `sha256:${(pass === 'cold' ? 'c' : 'd').repeat(64)}`,
          name: `[${pass}] test`,
          started: '2026-08-10T00:00:00.000Z',
          completed: '2026-08-10T00:00:01.000Z',
        }],
        pass,
      })}\n`,
      { mode: 0o600 },
    );
    fs.writeFileSync(
      path.join(passDir, 'buildx-history.json'),
      `${JSON.stringify({ name: pass })}\n`,
      { mode: 0o600 },
    );
    for (const name of ['cgroup-before.json', 'cgroup-after.json']) {
      fs.writeFileSync(path.join(evidenceDir, name), `${JSON.stringify({
        'cpu.stat': 'usage_usec 0\n',
        'cpu.pressure': 'some avg10=0.00 avg60=0.00 avg300=0.00 total=0\n',
        'io.stat': '',
        'io.pressure': 'some avg10=0.00 avg60=0.00 avg300=0.00 total=0\n',
        'memory.current': '0\n',
        'memory.events': 'low 0\n',
        'memory.pressure': 'some avg10=0.00 avg60=0.00 avg300=0.00 total=0\n',
        'pids.current': '1\n',
      })}\n`, { mode: 0o600 });
    }
    fs.writeFileSync(
      path.join(evidenceDir, 'nosh-build.jsonl'),
      `${JSON.stringify({ recordKind: 'final_stats', lostEvents: 0 })}\n`,
      { mode: 0o600 },
    );
    fs.writeFileSync(
      path.join(evidenceDir, 'nosh-l4.jsonl'),
      `${JSON.stringify({
        recordKind: 'stats',
        final: true,
        lostEvents: 0,
        padding: 'x'.repeat(600),
      })}\n`,
      { mode: 0o600 },
    );
    passes.push({
      pass,
      passDir,
      evidenceDir,
      history: {
        available: true,
        historyPath: path.join(passDir, 'buildx-history.json'),
      },
      manifest: {
        schemaVersion: 1,
        apiVersion: 'notty.dev/v1alpha1',
        kind: 'NoshBuildEvidenceManifest',
        runId: `profile-${pass}`,
        mode: 'build-profile',
        pass,
        complete: true,
        startedAt: `2026-08-10T00:00:0${pass === 'cold' ? 0 : 3}.000Z`,
        finishedAt: `2026-08-10T00:00:0${pass === 'cold' ? 2 : 4}.000Z`,
        build: {
          exitCode: 0,
          succeeded: true,
          startedAt: `2026-08-10T00:00:0${pass === 'cold' ? 0 : 3}.000Z`,
          finishedAt: `2026-08-10T00:00:0${pass === 'cold' ? 2 : 4}.000Z`,
          metadata: pass === 'warm'
            ? { imageDigest: `sha256:${'b'.repeat(64)}` }
            : {},
        },
        workspace: { path: current.context },
        builder: {
          builderName: 'nosh-builder',
          containerId: 'builder-one',
          imageDigest: `sha256:${'a'.repeat(64)}`,
          initPid: 123,
          cgroup: { path: '/sys/fs/cgroup/builder-one' },
        },
        identity: { ok: true },
        cleanup: { ok: true },
        sources: [
          {
            name: 'cgroup-before.json',
            complete: true,
            file: { path: 'cgroup-before.json' },
          },
          {
            name: 'cgroup-after.json',
            complete: true,
            file: { path: 'cgroup-after.json' },
          },
          {
            name: 'nosh-build',
            complete: true,
            file: { path: 'nosh-build.jsonl' },
            completion: { lostEvents: 0, parseErrors: 0 },
          },
          {
            name: 'nosh-l4',
            complete: true,
            file: { path: 'nosh-l4.jsonl' },
            completion: { lostEvents: 0, parseErrors: 0 },
          },
        ],
        limitations: [],
      },
    });
  }
  const combinedInput = (profileId, selectedPasses) => ({
    context: current.context,
    profileId,
    mode: 'build-profile',
    cacheMode: 'compare',
    depth: 'balanced',
    platform: 'linux/amd64',
    exclusiveBuilderLease: true,
    parentObserved: true,
    builderCleanupComplete: true,
    passes: selectedPasses,
  });
  await assert.rejects(
    combineBuildPassManifests(combinedInput(
      'combined-too-many-passes',
      [passes[0], passes[1], passes[0]],
    )),
    /combined build profile supports at most 2 passes/,
  );
  await assert.rejects(
    combineBuildPassManifests(combinedInput(
      'combined-duplicate-pass',
      [passes[0], passes[0]],
    )),
    /combined build profile pass names must be unique/,
  );

  const combined = await combineBuildPassManifests(
    combinedInput('combined-one', passes),
  );
  assert.deepEqual(combined.build.passes.map((entry) => entry.name), ['cold', 'warm']);
  assert.equal(combined.build.outputImageDigest, `sha256:${'b'.repeat(64)}`);
  assert.equal(combined.sources.every((source) => source.complete), true);

  const maxPassSourceBytes = 1024;
  const maxCombinedSourceBytes = 2 * (maxPassSourceBytes + 64);
  const networkSource = combined.sources.find((source) =>
    source.name === 'ebpf-network');
  assert.ok(networkSource.content.length > maxPassSourceBytes);
  assert.ok(networkSource.content.length <= maxCombinedSourceBytes);

  const store = new BuildProfileStore({
    home: current.home,
    maxPassSourceBytes,
  });
  const coldOnly = await combineBuildPassManifests(
    combinedInput('combined-cold-only', [passes[0]]),
  );
  const coldOnlyResult = await store.finalizeRun(coldOnly);
  assert.equal(coldOnlyResult.manifest.complete, false);
  assert.match(
    coldOnlyResult.manifest.incompleteReasons.join('\n'),
    /warm comparison pass failed or is missing/,
  );

  const result = await store.finalizeRun(combined);
  assert.equal(
    result.manifest.complete,
    true,
    result.manifest.incompleteReasons.join('\n'),
  );
  assert.equal(result.candidateAdvanced, true);

  await assert.rejects(
    store.finalizeRun({
      ...combined,
      runId: 'combined-source-too-large',
      sources: combined.sources.map((source) => source.name === 'ebpf-network'
        ? { ...source, content: Buffer.alloc(maxCombinedSourceBytes + 1, 0x78) }
        : source),
    }),
    /build evidence source exceeds the byte limit: ebpf-network/,
  );

  fs.unlinkSync(passes[0].history.historyPath);
  passes[0].history = {
    available: false,
    reason: `\u001b[31mno record found\u001b[0m\n${'x'.repeat(600)}`,
  };
  const missingHistory = await combineBuildPassManifests(
    combinedInput('combined-missing-history', passes),
  );
  const historyReason = missingHistory.incompleteReasons.find((reason) =>
    reason.startsWith('cold Buildx history is missing:'));
  assert.ok(historyReason);
  assert.equal(historyReason.includes('\u001b'), false);
  assert.equal(historyReason.includes('\n'), false);
  assert.equal(historyReason.split(': ', 2)[1].length, 512);

  const missingResult = await store.finalizeRun(missingHistory);
  assert.equal(missingResult.manifest.complete, false);
  assert.ok(missingResult.manifest.incompleteReasons.includes(historyReason));
  assert.match(
    fs.readFileSync(path.join(missingResult.directory, 'report.txt'), 'utf8'),
    /cold Buildx history is missing: no record found/,
  );

  const coldL4 = passes[0].manifest.sources.find((source) => source.name === 'nosh-l4');
  coldL4.complete = false;
  coldL4.error = '\u001b[31madapter output exceeded 134217728 bytes\u001b[0m\n';
  const incompleteL4 = await combineBuildPassManifests(
    combinedInput('combined-incomplete-l4', passes),
  );
  const l4Reason = incompleteL4.incompleteReasons.find((reason) =>
    reason.startsWith('cold nosh-l4 evidence is incomplete:'));
  assert.ok(l4Reason);
  assert.equal(l4Reason.includes('\u001b'), false);
  assert.equal(l4Reason.includes('\n'), false);
  assert.match(l4Reason, /adapter output exceeded 134217728 bytes/);
});

test('portable mirrors stay non-authoritative and outside runtime network state', async (t) => {
  const { BuildProfileStore } = await storeModule();
  const {
    readCurrentBuildProfileMirror,
    writeBuildProfileMirrorPayload,
  } = await mirrorModule();
  const current = fixture(t);
  const privateHome = path.join(current.root, 'private-home');
  const mirrorHome = path.join(current.root, 'mirror-home');
  fs.mkdirSync(privateHome);
  fs.mkdirSync(mirrorHome);
  const result = await new BuildProfileStore({ home: privateHome }).finalizeRun(
    await runInput(t, current),
  );
  const mirrored = await writeBuildProfileMirrorPayload({
    home: mirrorHome,
    workdir: current.context,
    manifest: result.manifest,
    candidate: result.candidate,
  });
  assert.equal(mirrored.receipt.authoritative, false);
  assert.equal(mirrored.receipt.attested, false);
  assert.ok(mirrored.directory.includes(`${path.sep}build-profiles${path.sep}`));
  assert.equal(fs.existsSync(path.join(mirrorHome, '.nosh', 'net-profiles')), false);
  const currentMirror = await readCurrentBuildProfileMirror(current.context, {
    mode: 'build-profile',
    user: {
      username: 'developer',
      uid: process.getuid?.() ?? 0,
      gid: process.getgid?.() ?? 0,
      home: mirrorHome,
    },
  });
  assert.equal(currentMirror.receipt.runId, 'run-one');
});

test('reading a bundle performs no directory writes and rejects unsafe modes', async (t) => {
  const { BuildProfileStore } = await storeModule();
  const current = fixture(t);
  const store = new BuildProfileStore({ home: current.home });
  const result = await store.finalizeRun(await runInput(t, current));
  const promises = require('node:fs/promises');
  const readOnlyError = () => { throw Object.assign(new Error('read-only filesystem'), { code: 'EROFS' }); };
  t.mock.method(promises, 'mkdir', readOnlyError);
  t.mock.method(promises, 'chmod', readOnlyError);
  const loaded = await store.read(current.context, 'run-one');
  assert.equal(loaded.manifest.runId, 'run-one');
  fs.chmodSync(result.directory, 0o755);
  await assert.rejects(store.read(current.context, 'run-one'), /mode 0700/);
  assert.equal(fs.statSync(result.directory).mode & 0o777, 0o755);
});
