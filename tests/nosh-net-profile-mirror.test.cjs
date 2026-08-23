'use strict';

const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const test = require('node:test');
const { pathToFileURL } = require('node:url');

const appRoot = path.resolve(__dirname, '..');

function stableJson(value) {
  if (Array.isArray(value)) {
    return `[${value.map((item) => stableJson(item)).join(',')}]`;
  }
  if (value && typeof value === 'object') {
    return `{${Object.keys(value).sort().map(
      (key) => `${JSON.stringify(key)}:${stableJson(value[key])}`,
    ).join(',')}}`;
  }
  return JSON.stringify(value);
}

function hash(value) {
  return `sha256:${crypto.createHash('sha256').update(value).digest('hex')}`;
}

function reviewCandidateFixture(workdir) {
  const workspaceKey = crypto.createHash('sha256').update(workdir).digest('hex');
  const revision = 'candidate-1';
  const imageDigest = `sha256:${'1'.repeat(64)}`;
  const profile = {
    kind: 'NoshEgressProfile',
    metadata: { revision, workspaceKey },
    spec: {
      workspace: { key: workspaceKey, dev: '1', ino: '2' },
      target: { imageDigest },
    },
  };
  const policy = {
    kind: 'NoshEgressPolicy',
    metadata: { revision, workspaceKey },
  };
  const profileSource = `${JSON.stringify(profile, null, 2)}\n`;
  const policySource = `${JSON.stringify(policy, null, 2)}\n`;
  const unsignedManifest = {
    kind: 'NoshEgressBundleManifest',
    generatedAt: '2026-08-21T00:00:00.000Z',
    workspaceKey,
    revision,
    imageDigest,
    files: {
      'egress-profile.json': {
        hash: hash(profileSource),
        bytes: Buffer.byteLength(profileSource),
      },
      'egress-policy.json': {
        hash: hash(policySource),
        bytes: Buffer.byteLength(policySource),
      },
    },
  };
  const manifest = {
    ...unsignedManifest,
    contentHash: hash(stableJson(unsignedManifest)),
  };
  const unsignedTarget = {
    apiVersion: 'notty.dev/v1alpha1',
    kind: 'NoshGuardEbpfTargetContext',
    schemaVersion: 2,
    createdAt: '2026-08-21T00:00:00.000Z',
    backendAbi: 'nosh-egress-v2',
    objectDigest: `sha256:${'2'.repeat(64)}`,
    subject: {
      workspaceKey,
      imageDigest,
      workspaceIdentity: { dev: '1', ino: '2' },
    },
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
    resolvers: ['1.1.1.1'],
    platformContainment: {
      strategy: 'per-run-docker-bridge-gateways',
      ipv4PrefixLength: 32,
      ipv6PrefixLength: 128,
    },
  };
  const targetContext = {
    ...unsignedTarget,
    contentHash: hash(stableJson(unsignedTarget)),
  };
  return {
    workspaceKey,
    revision,
    profileSource,
    policySource,
    manifestSource: `${JSON.stringify(manifest, null, 2)}\n`,
    targetContextSource: `${JSON.stringify(targetContext, null, 2)}\n`,
  };
}

async function mirrorModule() {
  return import(
    pathToFileURL(path.join(appRoot, 'lib', 'guardd', 'net-profile-mirror.js')).href
  );
}

function tempHome(t) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'notty-net-mirror-'));
  const home = path.join(root, 'home');
  const workdir = path.join(root, 'workspace');
  fs.mkdirSync(home);
  fs.mkdirSync(workdir);
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  return { root, home, workdir };
}

test('sudo invoking identity is resolved by numeric passwd identity', async () => {
  const { resolveInvokingUser } = await mirrorModule();
  const selected = resolveInvokingUser({
    env: { SUDO_UID: '1001', SUDO_GID: '1002' },
    getuid: () => 0,
    getgid: () => 0,
    passwdLookup: () => 'developer:x:1001:1002:Developer:/srv/developer:/bin/bash\n',
  });
  assert.deepEqual(selected, {
    username: 'developer',
    uid: 1001,
    gid: 1002,
    home: '/srv/developer',
  });
});

test('mirror writes policy snapshots before its non-authoritative receipt', async (t) => {
  const { mirrorDirectory, writeMirrorPayload } = await mirrorModule();
  const current = tempHome(t);
  const receipt = {
    apiVersion: 'notty.dev/v1alpha1',
    kind: 'NoshEgressProfileReceipt',
    authoritative: false,
    workspace: { path: current.workdir },
  };
  const directory = await writeMirrorPayload({
    home: current.home,
    workdir: current.workdir,
    receipt,
    candidatePolicy: '{"candidate":true}\n',
    approvedPolicy: '{"approved":true}\n',
  });
  assert.equal(directory, mirrorDirectory(current.workdir, current.home));
  assert.deepEqual(
    JSON.parse(fs.readFileSync(path.join(directory, 'current.json'), 'utf8')),
    receipt,
  );
  assert.equal(
    fs.readFileSync(path.join(directory, 'candidate-egress-policy.json'), 'utf8'),
    '{"candidate":true}\n',
  );
  assert.equal(fs.statSync(directory).mode & 0o777, 0o700);
  assert.equal(fs.statSync(path.join(directory, 'current.json')).mode & 0o777, 0o600);
});

test('mirror refuses a symlinked state directory', async (t) => {
  const { writeMirrorPayload } = await mirrorModule();
  const current = tempHome(t);
  const outside = path.join(current.root, 'outside');
  fs.mkdirSync(outside);
  fs.symlinkSync(outside, path.join(current.home, '.nosh'));
  await assert.rejects(
    writeMirrorPayload({
      home: current.home,
      workdir: current.workdir,
      receipt: {
        kind: 'NoshEgressProfileReceipt',
        authoritative: false,
      },
    }),
    /not a directory/,
  );
});

test('mirror reads reject a receipt copied from another workspace', async (t) => {
  const {
    readCurrentUserMirror,
    writeMirrorPayload,
  } = await mirrorModule();
  const current = tempHome(t);
  const other = path.join(current.root, 'other-workspace');
  fs.mkdirSync(other);
  await writeMirrorPayload({
    home: current.home,
    workdir: current.workdir,
    receipt: {
      apiVersion: 'notty.dev/v1alpha1',
      kind: 'NoshEgressProfileReceipt',
      authoritative: false,
      workspace: { path: other },
    },
  });

  await assert.rejects(
    readCurrentUserMirror(current.workdir, {
      user: {
        username: 'developer',
        uid: process.getuid?.() ?? 0,
        gid: process.getgid?.() ?? 0,
        home: current.home,
      },
    }),
    /does not match this workspace/,
  );
});

test('mirror exports one immutable user-owned eBPF review candidate bundle', async (t) => {
  const {
    mirrorDirectory,
    reviewCandidateDirectory,
    writeMirrorPayload,
  } = await mirrorModule();
  const current = tempHome(t);
  const candidate = reviewCandidateFixture(current.workdir);
  const receipt = {
    apiVersion: 'notty.dev/v1alpha1',
    kind: 'NoshEgressProfileReceipt',
    authoritative: false,
    workspace: { path: current.workdir },
  };
  const directory = await writeMirrorPayload({
    home: current.home,
    workdir: current.workdir,
    receipt,
    reviewCandidate: {
      profileSource: candidate.profileSource,
      policySource: candidate.policySource,
      manifestSource: candidate.manifestSource,
      targetContextSource: candidate.targetContextSource,
    },
  });
  const expected = reviewCandidateDirectory(
    mirrorDirectory(current.workdir, current.home),
    candidate.workspaceKey,
    candidate.revision,
  );
  assert.equal(directory, mirrorDirectory(current.workdir, current.home));
  assert.equal(fs.statSync(expected).mode & 0o777, 0o700);
  assert.equal(fs.statSync(expected).uid, process.getuid());
  assert.equal(fs.statSync(expected).gid, process.getgid());
  for (const name of [
    'egress-profile.json',
    'egress-policy.json',
    'manifest.json',
    'guard-ebpf-target-context.json',
    'review-export.json',
  ]) {
    const selected = path.join(expected, name);
    assert.equal(fs.statSync(selected).mode & 0o777, 0o600);
    assert.equal(fs.statSync(selected).nlink, 1);
    assert.equal(fs.statSync(selected).uid, process.getuid());
    assert.equal(fs.statSync(selected).gid, process.getgid());
  }
  const exported = JSON.parse(
    fs.readFileSync(path.join(expected, 'review-export.json'), 'utf8'),
  );
  assert.equal(exported.kind, 'NoshGuardEbpfReviewCandidateExport');
  assert.equal(exported.workspaceKey, candidate.workspaceKey);
  assert.equal(exported.revision, candidate.revision);
  assert.equal(
    exported.files['guard-ebpf-target-context.json'].sha256,
    hash(candidate.targetContextSource),
  );

  fs.chmodSync(path.join(expected, 'manifest.json'), 0o644);
  await assert.rejects(
    writeMirrorPayload({
      home: current.home,
      workdir: current.workdir,
      receipt,
      reviewCandidate: {
        profileSource: candidate.profileSource,
        policySource: candidate.policySource,
        manifestSource: candidate.manifestSource,
        targetContextSource: candidate.targetContextSource,
      },
    }),
    /immutable review candidate already differs/,
  );
});
