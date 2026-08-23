'use strict';

const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const test = require('node:test');
const { pathToFileURL } = require('node:url');

const appRoot = path.resolve(__dirname, '..');
const SHA_A = `sha256:${'a'.repeat(64)}`;
const SHA_B = `sha256:${'b'.repeat(64)}`;
const WORKSPACE_KEY = 'c'.repeat(64);
const EGRESS_CAPABILITIES = Object.freeze({
  atomicPolicyGeneration: true,
  cgroupConnect: true,
  cgroupSendmsg: true,
  cgroupSkb: true,
  dnsParser: true,
  exactPlatformContainment: true,
  ipv6: true,
  tcpDns: false,
  ttlGrants: true,
});
const PLATFORM_CONTAINMENT = Object.freeze({
  strategy: 'per-run-docker-bridge-gateways',
  ipv4PrefixLength: 32,
  ipv6PrefixLength: 128,
});

function digest(value) {
  return `sha256:${crypto.createHash('sha256').update(value).digest('hex')}`;
}

function privateTemporaryDirectory(t) {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'nosh-ebpf-activation-'));
  fs.chmodSync(directory, 0o700);
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  return directory;
}

async function cliModule() {
  return import(
    pathToFileURL(path.join(appRoot, 'scripts', 'nosh-guard.mjs')).href
  );
}

function stateFixture() {
  return {
    schemaVersion: 1,
    kind: 'NoshGuardEbpfActivationState',
    activeGrantSetDigest: SHA_A,
    current: null,
    usedGrants: [],
    updatedAt: '2026-08-21T00:00:00.000Z',
    stateDigest: SHA_B,
  };
}

function healthFixture(objectDigest = SHA_A) {
  return {
    schemaVersion: 2,
    recordKind: 'status',
    timestampUnixNs: '123',
    status: 'healthy',
    cgroupId: null,
    attachedPrograms: 0,
    objectDigest,
    mapAbi: 2,
    programAbi: 2,
    message: 'host prerequisites satisfied',
    checks: {
      effectiveRoot: true,
      kernelIdentity: true,
      kernelBtf: true,
      cgroupV2: true,
      bpffs: true,
      targetCgroup: true,
    },
  };
}

function contextFixture(objectDigest = SHA_A) {
  return {
    document: { contentHash: SHA_B },
    expected: {
      imageDigest: SHA_B,
      workspaceKey: WORKSPACE_KEY,
      workspaceIdentity: { dev: '20', ino: '30' },
      backendAbi: 'nosh-egress-v2',
      objectDigest,
      capabilities: { ...EGRESS_CAPABILITIES },
      resolvers: ['1.1.1.1', '8.8.8.8'],
      platformContainment: { ...PLATFORM_CONTAINMENT },
    },
  };
}

test('ebpf status exposes the current grant-set digest and installed object', async () => {
  const { commandEbpf } = await cliModule();
  const printed = [];
  const status = stateFixture();
  assert.equal(await commandEbpf(['status', '--json'], {
    geteuid: () => 0,
    store: { async initialize() { return status; } },
    readHealth: () => healthFixture(),
    print(value) { printed.push(value); },
  }), 0);
  assert.equal(printed.length, 1);
  assert.equal(printed[0].kind, 'NoshGuardEbpfActivationStatus');
  assert.equal(printed[0].activeGrantSetDigest, SHA_A);
  assert.equal(printed[0].backend.objectDigest, SHA_A);
  assert.equal(printed[0].activation, null);
});

test('ebpf activate reads the context as the sudo user and imports exact bindings', async () => {
  const { commandEbpf } = await cliModule();
  const context = contextFixture();
  const importedState = {
    ...stateFixture(),
    activeGrantSetDigest: digest('next-grant-set'),
    usedGrants: [{ nonce: 'one-time' }],
    current: {
      activatedAt: '2026-08-21T01:00:00.000Z',
      previousActiveGrantSetDigest: SHA_A,
      leafBundleDigest: digest('leaf'),
      approvalEnvelopeDigest: digest('approval'),
      grantEnvelopeDigest: digest('grant'),
      nonce: 'one-time',
      imageDigest: SHA_B,
      workspaceKey: WORKSPACE_KEY,
      workspaceIdentity: { dev: '20', ino: '30' },
      backendAbi: 'nosh-egress-v2',
      objectDigest: SHA_A,
    },
  };
  const observed = {};
  const printed = [];
  assert.equal(await commandEbpf([
    'activate',
    '--bundle', '/review/activation',
    '--target-context', '/review/context.json',
  ], {
    geteuid: () => 0,
    invokingUser: { uid: 1000, gid: 1000, username: 'reviewer' },
    async readTrustedJson(file, options) {
      observed.contextRead = { file, options };
      return { document: { fixture: true } };
    },
    validateTargetContext(document) {
      observed.contextDocument = document;
      return context;
    },
    readHealth: () => healthFixture(),
    store: {
      async importActivation(bundle, input) {
        observed.import = { bundle, input };
        return { state: importedState };
      },
    },
    print(value) { printed.push(value); },
    now: '2026-08-21T01:00:00.000Z',
  }), 0);
  assert.deepEqual(observed.contextRead, {
    file: '/review/context.json',
    options: { expectedUid: 1000, maximumBytes: 4 * 1024 * 1024 },
  });
  assert.deepEqual(observed.contextDocument, { fixture: true });
  assert.equal(observed.import.bundle, '/review/activation');
  assert.equal(observed.import.input.sourceUid, 1000);
  assert.deepEqual(observed.import.input.expected, context.expected);
  assert.equal(observed.import.input.now, '2026-08-21T01:00:00.000Z');
  assert.equal(printed[0].kind, 'NoshGuardEbpfActivationReceipt');
  assert.equal(printed[0].targetContextHash, SHA_B);
  assert.equal(printed[0].activeGrantSetDigest, importedState.activeGrantSetDigest);
  assert.equal(Object.hasOwn(printed[0], 'nextGrantSetDigest'), false);
});

test('ebpf activate fails before import when the installed object changed', async () => {
  const { commandEbpf } = await cliModule();
  let imported = false;
  await assert.rejects(
    commandEbpf([
      'activate',
      '--bundle', '/review/activation',
      '--target-context', '/review/context.json',
    ], {
      geteuid: () => 0,
      invokingUser: { uid: 1000 },
      readTrustedJson: async () => ({ document: {} }),
      validateTargetContext: () => contextFixture(SHA_A),
      readHealth: () => healthFixture(SHA_B),
      store: {
        async importActivation() { imported = true; },
      },
    }),
    (error) => error.code === 'GUARD_EBPF_OBJECT_DIGEST_MISMATCH',
  );
  assert.equal(imported, false);
});

test('ebpf activation management is root-only', async () => {
  const { commandEbpf } = await cliModule();
  await assert.rejects(
    commandEbpf(['status', '--json'], { geteuid: () => 1000 }),
    (error) => error.code === 'GUARD_ROOT_REQUIRED',
  );
});

async function storeModules() {
  const [activation, jcs] = await Promise.all([
    import('../lib/guardd/ebpf-activation-store.js'),
    import('../lib/guard/review/jcs.js'),
  ]);
  return { activation, jcs };
}

function writePrivateJson(file, value) {
  fs.writeFileSync(file, `${JSON.stringify(value)}\n`, { mode: 0o600 });
}

async function createActivationSource(root, nonce, jcs) {
  const directory = fs.mkdtempSync(path.join(root, `source-${nonce}-`));
  fs.chmodSync(directory, 0o700);
  const policy = path.join(directory, 'policy');
  fs.mkdirSync(policy, { mode: 0o700 });
  const leafPayload = {
    activationEligible: true,
    apiVersion: 'notty.dev/v1alpha1',
    artifacts: [],
    capabilityDigest: digest('capability'),
    createdAt: '2026-08-21T00:00:00.000Z',
    decisionSetDigest: digest('decision'),
    graphDigest: digest('graph'),
    kind: 'NoshPolicyLeafBundle',
    policyIrDigest: digest('policy-ir'),
    projectionDigest: digest('projection'),
    schemaVersion: 1,
    target: 'guard-ebpf',
    targetContextDigest: digest('target-context'),
  };
  const leaf = {
    ...leafPayload,
    bundleDigest: jcs.sha256Digest(jcs.jcsCanonicalize(leafPayload)),
  };
  writePrivateJson(path.join(policy, 'leaf-bundle.json'), leaf);
  writePrivateJson(path.join(directory, 'approval-envelope.dsse.json'), { nonce });
  writePrivateJson(path.join(directory, 'deployment-grant.dsse.json'), { nonce });
  return { directory, leaf };
}

test('activation imports serialize one-time grant-set transitions without lost state', async (t) => {
  const { activation, jcs } = await storeModules();
  const root = privateTemporaryDirectory(t);
  const trustPath = path.join(root, 'trust.json');
  writePrivateJson(trustPath, {
    schemaVersion: 1,
    kind: 'NoshGuardEbpfDeploymentTrust',
    backendAbi: 'nosh-egress-v2',
    reviewPublicKey: '/etc/nosh-guard/review.pub',
    deploymentPublicKey: '/etc/nosh-guard/deployment.pub',
    reviewAudience: 'review.test',
    deploymentAudience: 'deployment.test',
  });
  const first = await createActivationSource(root, 'first', jcs);
  const second = await createActivationSource(root, 'second', jcs);
  const observedGrantSets = [];
  const store = new activation.EbpfActivationStore({
    stateRoot: path.join(root, 'state'),
    trustPath,
    lockTimeoutMs: 5_000,
    enforceTrustPathChains: false,
    async verifyAuthority(input) {
      observedGrantSets.push(input.activeGrantSetDigest);
      const grant = JSON.parse(fs.readFileSync(input.grant, 'utf8'));
      await new Promise((resolve) => setTimeout(resolve, 20));
      return {
        policy: { leaf: { bundleDigest: first.leaf.bundleDigest } },
        approval: { envelopeDigest: digest(`approval-${grant.nonce}`) },
        grant: {
          envelopeDigest: digest(`grant-${grant.nonce}`),
          statement: { nonce: grant.nonce },
        },
      };
    },
  });
  const expected = {
    imageDigest: digest('image'),
    workspaceKey: WORKSPACE_KEY,
    workspaceIdentity: { dev: '20', ino: '30' },
    backendAbi: 'nosh-egress-v2',
    objectDigest: digest('object'),
    capabilities: { ...EGRESS_CAPABILITIES },
    resolvers: ['1.1.1.1', '8.8.8.8'],
    platformContainment: { ...PLATFORM_CONTAINMENT },
  };
  const sourceUid = typeof process.getuid === 'function' ? process.getuid() : null;
  await Promise.all([
    store.importActivation(first.directory, {
      sourceUid,
      expected,
      now: '2026-08-21T01:00:00.000Z',
    }),
    store.importActivation(second.directory, {
      sourceUid,
      expected,
      now: '2026-08-21T01:00:01.000Z',
    }),
  ]);
  const state = await store.readState();
  assert.equal(state.usedGrants.length, 2);
  assert.equal(new Set(state.usedGrants.map((entry) => entry.nonce)).size, 2);
  assert.equal(observedGrantSets.length, 2);
  assert.notEqual(observedGrantSets[0], observedGrantSets[1]);
  assert.equal(fs.existsSync(store.lockPath), false);
  assert.equal(
    fs.readdirSync(store.importsDir).filter((name) => name.startsWith('.staging-')).length,
    0,
  );
  assert.equal(fs.statSync(store.statePath).mode & 0o777, 0o600);
});

test('fresh activation stores use distinct grant-set roots', async (t) => {
  const { activation } = await storeModules();
  const root = privateTemporaryDirectory(t);
  const first = new activation.EbpfActivationStore({
    stateRoot: path.join(root, 'first'),
  });
  const second = new activation.EbpfActivationStore({
    stateRoot: path.join(root, 'second'),
  });
  const [firstState, secondState] = await Promise.all([
    first.initialize(),
    second.initialize(),
  ]);
  assert.match(firstState.activeGrantSetDigest, /^sha256:[a-f0-9]{64}$/);
  assert.match(secondState.activeGrantSetDigest, /^sha256:[a-f0-9]{64}$/);
  assert.notEqual(firstState.activeGrantSetDigest, secondState.activeGrantSetDigest);
});

test('activation lock contention fails closed with a stable busy code', async (t) => {
  const { activation } = await storeModules();
  const root = privateTemporaryDirectory(t);
  const store = new activation.EbpfActivationStore({
    stateRoot: path.join(root, 'state'),
    trustPath: path.join(root, 'unused-trust.json'),
    lockTimeoutMs: 10,
  });
  await store.ensureDirectories();
  fs.writeFileSync(store.lockPath, '{}\n', { mode: 0o600, flag: 'wx' });
  await assert.rejects(
    store.withActivationLock(async () => {}),
    (error) => error.code === 'GUARD_EBPF_ACTIVATION_BUSY',
  );
});
