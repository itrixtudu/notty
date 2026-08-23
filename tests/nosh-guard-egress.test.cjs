'use strict';

const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const test = require('node:test');
const { pathToFileURL } = require('node:url');

const appRoot = path.resolve(__dirname, '..');
const managedDnsMaxBytes = 8 * 1024 * 1024;

async function importModule(relativePath) {
  return import(pathToFileURL(path.join(appRoot, relativePath)).href);
}

function tempDir(t) {
  const directory = fs.mkdtempSync(
    path.join(os.tmpdir(), 'nosh-guard-egress-test-'),
  );
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  return directory;
}

function egressPolicy(mode, overrides = {}) {
  return {
    runId: `run-${mode}`,
    mode,
    profileRevision: 'candidate-1',
    networkName: `nosh-guard-${mode}`,
    sourceIpv4: '10.240.8.3',
    gatewayIpv4: '10.240.8.2',
    egress: [
      {
        destination: 'api.openai.com',
        protocol: 'tcp',
        ports: [443],
      },
    ],
    ...overrides,
  };
}

function gatewayAttestation(runId) {
  return {
    schemaVersion: 1,
    source: 'managed_gateway',
    type: 'policy_attestation',
    timestamp: '2026-07-25T12:00:00.000Z',
    runId,
    policyHash: `sha256:${runId}`,
  };
}

function evidenceFileIdentity(filePath, offset = 0) {
  try {
    const stat = fs.statSync(filePath, { bigint: true });
    return {
      offset,
      dev: stat.dev.toString(),
      ino: stat.ino.toString(),
    };
  } catch (error) {
    if (error.code !== 'ENOENT') {
      throw error;
    }
    return { offset, dev: '0', ino: '0' };
  }
}

function managedDnsEvidencePaths(sharedDir, runId) {
  const key = crypto.createHash('sha256').update(runId).digest('hex');
  const directory = path.join(sharedDir, 'managed-dns');
  return {
    directory,
    key,
    logPath: path.join(directory, `${key}.log`),
    overflowPath: path.join(directory, `${key}.overflow.json`),
  };
}

function managedDnsEvidenceIdentity(sharedDir, runId, offset = 0) {
  const paths = managedDnsEvidencePaths(sharedDir, runId);
  fs.mkdirSync(paths.directory, { recursive: true });
  if (!fs.existsSync(paths.logPath)) {
    fs.writeFileSync(paths.logPath, '', { mode: 0o600 });
  }
  return {
    ...evidenceFileIdentity(paths.logPath, offset),
    evidenceKey: paths.key,
    maxBytes: managedDnsMaxBytes,
  };
}

function managedDnsSnapshot(runId, bytesWritten = 0, overflowMarker = null) {
  const evidenceKey = crypto.createHash('sha256').update(runId).digest('hex');
  return {
    schemaVersion: 1,
    source: 'managed_dns',
    type: 'evidence_snapshot',
    runId,
    evidenceKey,
    observedAt: '2026-07-25T12:00:01.000Z',
    limitBytes: managedDnsMaxBytes,
    bytesWritten,
    overflowed: overflowMarker !== null,
    lostEvents: overflowMarker ? 1 : 0,
    overflowMarker,
  };
}

function makeRun(root, options = {}) {
  const runId = options.runId || 'run-evidence';
  const evidenceDir = path.join(root, 'runs', runId);
  const sharedDir = path.join(root, 'egress', 'evidence');
  fs.mkdirSync(evidenceDir, { recursive: true });
  const dnsIdentity = managedDnsEvidenceIdentity(sharedDir, runId);
  const dnsPaths = managedDnsEvidencePaths(sharedDir, runId);
  const dnsSnapshot = options.managedDnsSnapshot || managedDnsSnapshot(
    runId,
    fs.statSync(dnsPaths.logPath).size,
  );
  return {
    runId,
    mode: options.mode || 'enforce',
    profileRevision: 'candidate-1',
    workdir: options.workdir || null,
    workspaceIdentity: options.workspaceIdentity || null,
    evidenceDir,
    evidenceComplete: options.evidenceComplete ?? true,
    adapters: options.adapters || [],
    detachResults: options.detachResults || [],
    egress: {
      sourceIpv4: options.sourceIpv4 || '10.240.8.3',
      acknowledgement:
        options.acknowledgement || gatewayAttestation(runId),
      evidenceOffsets: Object.hasOwn(options, 'evidenceOffsets')
        ? options.evidenceOffsets
        : {
            dns: dnsIdentity,
            gateway: evidenceFileIdentity(
              path.join(sharedDir, 'managed-gateway-counters.ndjson'),
            ),
          },
      finalSnapshot: { managedDnsEvidence: dnsSnapshot },
    },
  };
}

function writeJsonl(filePath, records) {
  fs.writeFileSync(
    filePath,
    records.map((record) => JSON.stringify(record)).join('\n') +
      (records.length ? '\n' : ''),
  );
}

function sourceByName(manifest, name) {
  const source = manifest.sources.find((entry) => entry.name === name);
  assert.ok(source, `missing evidence source ${name}`);
  return source;
}

function endWritable(stream) {
  return new Promise((resolve, reject) => {
    stream.once('finish', resolve);
    stream.once('error', reject);
    stream.end();
  });
}

test('observe-only DNS correlation is bounded and refuses ambiguous evidence', async () => {
  const { correlateObservedDns } = await importModule(
    'lib/guardd/evidence-finalizer.js',
  );
  const identity = {
    schemaVersion: 1,
    source: 'nosh-dns',
    runId: 'run-observe',
    cgroupId: '42',
    timestampNs: '1000000',
    observedAt: '2026-07-25T12:00:00.000Z',
    recordKind: 'event',
    messageKind: 'response',
    transport: 'udp',
    transactionId: 7,
    qtype: 'A',
    truncated: false,
    encrypted: false,
  };
  const l4 = [{
    recordKind: 'event',
    observedAt: '2026-07-25T12:00:01.000Z',
    network: { destinationAddress: '203.0.113.8' },
  }];
  const stats = {
    ...identity,
    recordKind: 'stats',
    final: true,
    counters: {
      ringbufDrops: 0,
      parseErrors: 0,
      tcpReassemblyDrops: 0,
      transactionEvictions: 0,
    },
  };
  delete stats.messageKind;
  const answer = { name: 'edge.example', type: 'A', data: '203.0.113.8', ttl: 30 };
  const unique = correlateObservedDns([
    { ...identity, qname: 'api.example', answers: [answer] },
    stats,
  ], l4, { runId: 'run-observe' });
  assert.equal(unique.eligible, true);
  assert.equal(unique.correlations[0].qname, 'api.example');
  const deterministic = correlateObservedDns([
    {
      ...identity,
      observedAt: '2026-07-25T12:00:00.100Z',
      transactionId: 21,
      qname: 'api.example',
      answers: [answer],
    },
    {
      ...identity,
      observedAt: '2026-07-25T12:00:00.900Z',
      transactionId: 22,
      transport: 'tcp',
      qname: 'api.example',
      answers: [answer],
    },
    stats,
  ], l4, { runId: 'run-observe' });
  assert.equal(deterministic.eligible, true);
  assert.equal(deterministic.correlations[0].transactionId, 22);
  assert.equal(deterministic.correlations[0].transport, 'tcp');

  const ambiguous = correlateObservedDns([
    { ...identity, qname: 'api.example', answers: [answer] },
    { ...identity, transport: 'tcp', transactionId: 8, qname: 'cdn.example', answers: [answer] },
    stats,
  ], l4, { runId: 'run-observe' });
  assert.equal(ambiguous.eligible, false);
  assert.equal(ambiguous.unresolved[0].reason, 'ambiguous-address-correlation');

  const expired = correlateObservedDns([
    { ...identity, qname: 'old.example', answers: [{ ...answer, ttl: 0 }] },
    stats,
  ], l4, { runId: 'run-observe' });
  assert.equal(expired.unresolved[0].reason, 'uncorrelated-address');
});

async function finalizeEnforceEvidence(t, options = {}) {
  const root = tempDir(t);
  const tetragonPath = path.join(root, 'tetragon-events.jsonl');
  const noshL4Path = path.join(root, 'nosh-l4.jsonl');
  if (options.tetragonRaw == null) {
    writeJsonl(tetragonPath, options.tetragonRecords || [
      { schemaVersion: 1, recordKind: 'event', type: 'process_exec' },
    ]);
  } else {
    fs.writeFileSync(tetragonPath, options.tetragonRaw);
  }
  if (options.noshL4Raw == null) {
    writeJsonl(noshL4Path, options.noshL4Records || [
      {
        schemaVersion: 1,
        recordKind: 'stats',
        final: true,
        decoderErrors: '0',
        counters: {
          ringbufDrops: '0',
          parseErrors: '0',
          unsupportedProtocol: '0',
          flowMapFull: '0',
          configMissing: '0',
        },
      },
    ]);
  } else {
    fs.writeFileSync(noshL4Path, options.noshL4Raw);
  }
  const run = makeRun(root, {
    adapters: [
      {
        name: 'tetragon-events',
        logPath: tetragonPath,
        required: true,
      },
      {
        name: 'nosh-l4',
        logPath: noshL4Path,
        required: true,
      },
    ],
  });
  const { finalizeRunEvidence } = await importModule(
    'lib/guardd/evidence-finalizer.js',
  );
  return finalizeRunEvidence(run, { stateDir: root });
}

test('managed runner access stays on a root-only Unix control proxy', async (t) => {
  const root = tempDir(t);
  const controlDir = path.join(root, 'egress', 'control');
  fs.mkdirSync(controlDir, { recursive: true, mode: 0o777 });
  fs.chmodSync(controlDir, 0o777);
  let gatewayCreated = false;
  let gatewaySpec = null;
  const inspectedGateway = () => ({
    Id: 'gateway-container',
    Image: 'sha256:gateway-image',
    Config: {
      Labels: gatewaySpec.Labels,
      Healthcheck: {
        Test: [
          'CMD-SHELL',
          'test -e /run/nosh-guard/healthy ' +
            '&& nft list table inet nosh_guard',
        ],
      },
    },
    HostConfig: gatewaySpec.HostConfig,
    Mounts: gatewaySpec.HostConfig.Binds.map((bind) => {
      const [source, destination, access] = bind.split(':');
      return {
        Source: source,
        Destination: destination,
        RW: access === 'rw',
      };
    }),
    State: { Running: true, Health: { Status: 'healthy' } },
    NetworkSettings: { Networks: {} },
  });
  const docker = {
    async inspectContainer() {
      if (!gatewayCreated) {
        const error = new Error('not found');
        error.statusCode = 404;
        throw error;
      }
      return inspectedGateway();
    },
    async inspectImage() {
      return {
        Id: 'sha256:gateway-image',
        Config: {
          Labels: { 'io.notty.guard.egress-abi': '1' },
        },
      };
    },
    async createContainer(_name, spec) {
      gatewayCreated = true;
      gatewaySpec = spec;
      return { Id: 'gateway-container' };
    },
  };
  const { EgressManager } = await importModule(
    'lib/guardd/egress-manager.js',
  );
  const { runnerProxySocket } = await importModule('lib/guardd/gateway.js');
  const manager = new EgressManager({ docker, stateDir: root });

  await manager.ensureGateway();
  const controlStat = fs.statSync(controlDir);
  const controlMode = controlStat.mode & 0o7777;
  assert.equal(controlMode, 0o700);
  if (typeof process.geteuid === 'function' && process.geteuid() === 0) {
    assert.equal(controlStat.uid, 0);
  }
  assert.equal(
    manager.controlSocketPath,
    path.join(root, 'egress', 'control', 'runner-proxy.sock'),
  );
  assert.equal(
    runnerProxySocket({ egress: manager }),
    manager.controlSocketPath,
  );
  assert.deepEqual(gatewaySpec.HostConfig.PortBindings, {});
  assert.equal(gatewaySpec.HostConfig.PublishAllPorts, false);
  assert.equal(gatewaySpec.ExposedPorts, undefined);
  assert.ok(
    gatewaySpec.HostConfig.Binds.includes(
      `${path.join(root, 'egress', 'control')}:` +
        '/var/lib/nosh-guard/control:rw',
    ),
  );
  assert.ok(
    gatewaySpec.Env.includes(
      'NOSH_GUARD_CONTROL_SOCKET=' +
        '/var/lib/nosh-guard/control/runner-proxy.sock',
    ),
  );

  const hostGatewaySource = fs.readFileSync(
    path.join(appRoot, 'lib', 'guardd', 'gateway.js'),
    'utf8',
  );
  const managedGatewaySource = fs.readFileSync(
    path.join(appRoot, 'scripts', 'nosh-guard-egress-gateway.mjs'),
    'utf8',
  );
  assert.doesNotMatch(
    hostGatewaySource,
    /NetworkSettings|GlobalIPv6Address|runnerAddress/,
  );
  assert.match(hostGatewaySource, /http\.request\(\s*\{\s*socketPath,/);
  assert.match(
    hostGatewaySource,
    /net\.connect\(\{\s*path: socketPath\s*\}/,
  );
  assert.match(
    managedGatewaySource,
    /proxyServer\.listen\(controlSocketPath, resolve\)/,
  );
  assert.match(
    managedGatewaySource,
    /fs\.chmod\(controlSocketPath, 0o600\)/,
  );
  assert.match(managedGatewaySource, /if \(!stat\.isSocket\(\)\)/);
  assert.match(
    managedGatewaySource,
    /containsExactValue\(rule\.expr \|\| \[\], policy\.sourceIpv4\)/,
  );
  assert.doesNotMatch(
    managedGatewaySource,
    /JSON\.stringify\(rule\.expr[^;]*\.includes\(policy\.sourceIpv4\)/,
  );

  const drifted = structuredClone(inspectedGateway());
  drifted.HostConfig.PortBindings = { '3000/tcp': [{ HostPort: '3000' }] };
  assert.throws(
    () =>
      manager.validateGateway(drifted, {
        Id: 'sha256:gateway-image',
        Config: {
          Labels: { 'io.notty.guard.egress-abi': '1' },
        },
      }),
    /no published ports/,
  );
  const extraMount = structuredClone(inspectedGateway());
  extraMount.HostConfig.Binds.push(
    '/var/run/docker.sock:/var/run/docker.sock:rw',
  );
  extraMount.Mounts.push({
    Source: '/var/run/docker.sock',
    Destination: '/var/run/docker.sock',
    RW: true,
  });
  assert.throws(
    () =>
      manager.validateGateway(extraMount, {
        Id: 'sha256:gateway-image',
        Config: {
          Labels: { 'io.notty.guard.egress-abi': '1' },
        },
      }),
    /no additional mounts/,
  );
});

test('trusted egress image ABI is pinned and rejects stale images before Docker mutation', async (t) => {
  assert.match(
    fs.readFileSync(path.join(appRoot, 'Dockerfile.nosh-egress'), 'utf8'),
    /^LABEL io\.notty\.guard\.egress-abi="1"$/m,
  );
  const {
    EgressManager,
    assertEgressImageAbi,
  } = await importModule('lib/guardd/egress-manager.js');
  assert.deepEqual(
    assertEgressImageAbi({
      Config: {
        Labels: { 'io.notty.guard.egress-abi': '1' },
      },
    }),
    {
      label: 'io.notty.guard.egress-abi',
      version: '1',
    },
  );

  for (const [name, actual] of [
    ['missing', null],
    ['wrong', '0'],
  ]) {
    await t.test(name, async () => {
      const root = tempDir(t);
      const image = `nosh-guard-egress:${name}`;
      const calls = [];
      const labels = actual == null
        ? {}
        : { 'io.notty.guard.egress-abi': actual };
      const imageInfo = {
        Id: `sha256:${name}`,
        Config: { Labels: labels },
      };
      const docker = {
        async inspectImage(candidate) {
          calls.push(['inspectImage', candidate]);
          return imageInfo;
        },
        async inspectContainer(candidate) {
          calls.push(['inspectContainer', candidate]);
          throw new Error('gateway inspection must not precede ABI validation');
        },
        async createContainer(candidate) {
          calls.push(['createContainer', candidate]);
          throw new Error('gateway creation must not precede ABI validation');
        },
        async createNetwork(candidate) {
          calls.push(['createNetwork', candidate]);
          throw new Error('network creation must not precede ABI validation');
        },
      };
      const manager = new EgressManager({ docker, stateDir: root, image });

      assert.throws(
        () => manager.validateGateway({}, imageInfo),
        (error) => {
          assert.equal(error.code, 'GUARD_EGRESS_IMAGE_ABI_MISMATCH');
          assert.equal(error.actual, actual);
          return true;
        },
      );
      await assert.rejects(
        manager.prepareNetwork(`abi-${name}`),
        (error) => {
          assert.equal(error.code, 'GUARD_EGRESS_IMAGE_ABI_MISMATCH');
          assert.equal(error.image, image);
          assert.equal(error.label, 'io.notty.guard.egress-abi');
          assert.equal(error.expected, '1');
          assert.equal(error.actual, actual);
          assert.match(error.message, /Dockerfile\.nosh-egress/);
          assert.match(error.message, /NOSH_GUARD_EGRESS_IMAGE/);
          return true;
        },
      );
      assert.deepEqual(calls, [['inspectImage', image]]);
    });
  }
});

test('missing trusted egress image fails before Docker mutation', async (t) => {
  const root = tempDir(t);
  const image = 'registry.example/nosh-guard-egress:reviewed';
  const dockerFailure = new Error(
    `Docker GET /images/${encodeURIComponent(image)}/json failed (404)`,
  );
  dockerFailure.statusCode = 404;
  const calls = [];
  const docker = {
    async inspectImage(candidate) {
      calls.push(['inspectImage', candidate]);
      throw dockerFailure;
    },
    async inspectContainer(candidate) {
      calls.push(['inspectContainer', candidate]);
      throw new Error('inspectContainer must not run without the trusted image');
    },
    async createContainer(name) {
      calls.push(['createContainer', name]);
      throw new Error('createContainer must not run without the trusted image');
    },
    async createNetwork(name) {
      calls.push(['createNetwork', name]);
      throw new Error('createNetwork must not run without the trusted image');
    },
  };
  const { EgressManager } = await importModule(
    'lib/guardd/egress-manager.js',
  );
  const manager = new EgressManager({ docker, stateDir: root, image });

  await assert.rejects(
    manager.prepareNetwork('missing-image-run'),
    (error) => {
      assert.equal(error.code, 'GUARD_EGRESS_IMAGE_MISSING');
      assert.equal(error.image, image);
      assert.equal(error.cause, dockerFailure);
      assert.ok(error.message.includes(JSON.stringify(image)));
      assert.match(
        error.message,
        /docker build -f Dockerfile\.nosh-egress -t nosh-guard-egress:0\.1 \./,
      );
      assert.match(error.message, /NOSH_GUARD_EGRESS_IMAGE/);
      assert.match(
        error.message,
        /immutable image ID or digest-pinned reference/,
      );
      return true;
    },
  );
  assert.deepEqual(calls, [['inspectImage', image]]);
});

test('trusted egress image inspection preserves non-404 Docker failures', async (t) => {
  const root = tempDir(t);
  const dockerFailure = new Error('Docker daemon refused image inspection');
  dockerFailure.statusCode = 500;
  let mutations = 0;
  const docker = {
    async inspectImage() {
      throw dockerFailure;
    },
    async inspectContainer() {
      mutations += 1;
    },
    async createContainer() {
      mutations += 1;
    },
    async createNetwork() {
      mutations += 1;
    },
  };
  const { EgressManager } = await importModule(
    'lib/guardd/egress-manager.js',
  );
  const manager = new EgressManager({ docker, stateDir: root });

  await assert.rejects(
    manager.ensureGateway(),
    (error) => error === dockerFailure,
  );
  assert.equal(mutations, 0);
});

test('managed proxy state rejects unsafe control paths and owners', async (t) => {
  const { EgressManager, secureDirectory } = await importModule(
    'lib/guardd/egress-manager.js',
  );
  const docker = {};

  const symlinkRoot = tempDir(t);
  const symlinkTarget = path.join(symlinkRoot, 'redirected-control');
  const symlinkPath = path.join(symlinkRoot, 'egress', 'control');
  fs.mkdirSync(path.dirname(symlinkPath), { recursive: true });
  fs.mkdirSync(symlinkTarget);
  fs.symlinkSync(symlinkTarget, symlinkPath);
  await assert.rejects(
    new EgressManager({ docker, stateDir: symlinkRoot }).initialize(),
    /symbolic links|real directory/,
  );

  const fileRoot = tempDir(t);
  const filePath = path.join(fileRoot, 'egress', 'control');
  fs.mkdirSync(path.dirname(filePath), { recursive: true });
  fs.writeFileSync(filePath, 'not a directory\n');
  await assert.rejects(
    new EgressManager({ docker, stateDir: fileRoot }).initialize(),
    /EEXIST|directory/,
  );

  const ownerRoot = tempDir(t);
  const ownerPath = path.join(ownerRoot, 'owner-check');
  fs.mkdirSync(ownerPath);
  const actualUid = fs.statSync(ownerPath).uid;
  await assert.rejects(
    secureDirectory(ownerPath, { requiredUid: actualUid + 1 }),
    /must be owned by uid/,
  );
});

test('run admission captures inode-bound evidence cursors', async (t) => {
  const root = tempDir(t);
  const runId = 'cursor-run';
  const gatewayLog = path.join(
    root,
    'egress',
    'evidence',
    'managed-gateway-counters.ndjson',
  );
  const dnsPaths = managedDnsEvidencePaths(
    path.join(root, 'egress', 'evidence'),
    runId,
  );
  const dnsLog = dnsPaths.logPath;
  let manager;
  const docker = {
    async exec() {
      const policy = JSON.parse(
        fs.readFileSync(
          path.join(root, 'egress', 'policies', `${runId}.json`),
          'utf8',
        ),
      );
      const acknowledgementDir = path.join(
        root,
        'egress',
        'evidence',
        'acks',
      );
      fs.mkdirSync(acknowledgementDir, { recursive: true });
      fs.writeFileSync(
        path.join(acknowledgementDir, `${runId}.json`),
        `${JSON.stringify({
          source: 'managed_gateway',
          type: 'policy_attestation',
          runId: policy.runId,
          mode: policy.mode,
          profileRevision: policy.profileRevision,
          policyHash: policy.policyHash,
          approvalHash: policy.approvalHash,
          profilePolicyHash: policy.profilePolicyHash,
          imageDigest: policy.imageDigest,
          workspaceKey: policy.workspaceKey,
          networkName: policy.networkName,
          sourceIpv4: policy.sourceIpv4,
          gatewayIpv4: policy.gatewayIpv4,
        })}\n`,
        { mode: 0o600 },
      );
      fs.appendFileSync(dnsLog, 'dnsmasq: new run evidence\n');
      fs.appendFileSync(
        gatewayLog,
        `${JSON.stringify({ runId, type: 'policy_reload' })}\n`,
      );
      return { status: 0 };
    },
  };
  const { EgressManager } = await importModule(
    'lib/guardd/egress-manager.js',
  );
  manager = new EgressManager({
    docker,
    stateDir: root,
    publicOrigin: 'https://guard.example:3443',
    spawnSyncImpl() {
      return { status: 0, stderr: '' };
    },
  });
  await manager.initialize();
  fs.appendFileSync(
    gatewayLog,
    `${JSON.stringify({ runId: 'older-run', type: 'counter_snapshot' })}\n`,
  );
  const gatewayBefore = fs.statSync(gatewayLog, { bigint: true });
  const initPid = process.pid;
  const namespace = fs.statSync(`/proc/${initPid}/ns/net`, {
    bigint: true,
  });
  const allocation = {
    networkName: 'nosh-guard-cursor',
    runnerIp: '10.240.8.3',
    egressGateway: '10.240.8.2',
    gatewayContainerId: 'gateway-container',
  };
  const approvalHash = `sha256:${'a'.repeat(64)}`;
  const profilePolicyHash = `sha256:${'b'.repeat(64)}`;
  const imageDigest = `sha256:${'c'.repeat(64)}`;
  const workspaceKey = 'd'.repeat(64);
  const run = {
    runId,
    mode: 'egress-enforce',
    profileRevision: 'approved-1',
    initPid,
    namespaces: { net: namespace.ino.toString() },
    approvalHash,
    profilePolicyHash,
    imageDigest,
    workspaceKey,
  };
  const attached = await manager.attachRun(
    run,
    {
      State: { Pid: initPid },
      NetworkSettings: {
        Networks: {
          [allocation.networkName]: {
            IPAddress: allocation.runnerIp,
          },
        },
      },
    },
    allocation,
    null,
    {
      networkRules: [],
      approvalHash,
      profilePolicyHash,
      workspaceKey,
    },
  );
  const dnsAfter = fs.statSync(dnsLog, { bigint: true });

  assert.deepEqual(attached.evidenceOffsets, {
    dns: {
      offset: 0,
      dev: dnsAfter.dev.toString(),
      ino: dnsAfter.ino.toString(),
      evidenceKey: dnsPaths.key,
      maxBytes: managedDnsMaxBytes,
    },
    gateway: {
      offset: Number(gatewayBefore.size),
      dev: gatewayBefore.dev.toString(),
      ino: gatewayBefore.ino.toString(),
    },
  });
  assert.equal(fs.statSync(dnsLog).mode & 0o7777, 0o600);
  assert.equal(fs.statSync(gatewayLog).mode & 0o7777, 0o600);
  assert.equal(
    JSON.parse(
      fs.readFileSync(
        path.join(root, 'egress', 'policies', `${runId}.json`),
        'utf8',
      ),
    ).publicOrigin,
    'https://guard.example:3443',
  );
  manager.health = async () => ({
    ok: true,
    containerId: 'gateway-container',
  });
  assert.deepEqual(
    await manager.runtimeHealth({ ...run, egress: attached }),
    {
      ok: true,
      policyHash: attached.policyHash,
      approvalHash,
      profilePolicyHash,
    },
  );
  assert.equal(
    (
      await manager.runtimeHealth({
        ...run,
        approvalHash: `sha256:${'e'.repeat(64)}`,
        egress: attached,
      })
    ).ok,
    false,
  );
  assert.equal(
    (
      await manager.runtimeHealth({
        ...run,
        profilePolicyHash: `sha256:${'f'.repeat(64)}`,
        egress: attached,
      })
    ).ok,
    false,
  );
});

test('legacy gateway acknowledgement fails immediately with ABI guidance', async (t) => {
  const root = tempDir(t);
  const runId = 'legacy-ack';
  const acknowledgementPath = path.join(
    root,
    'egress',
    'evidence',
    'acks',
    `${runId}.json`,
  );
  let replacementTimer = null;
  const writeAcknowledgement = (policy, complete) => {
    const acknowledgement = {
      schemaVersion: 1,
      source: 'managed_gateway',
      type: 'policy_attestation',
      runId: policy.runId,
      mode: policy.mode,
      profileRevision: policy.profileRevision,
      policyHash: policy.policyHash,
      ...(complete
        ? {
            approvalHash: policy.approvalHash,
            profilePolicyHash: policy.profilePolicyHash,
            imageDigest: policy.imageDigest,
            workspaceKey: policy.workspaceKey,
            networkName: policy.networkName,
            sourceIpv4: policy.sourceIpv4,
            gatewayIpv4: policy.gatewayIpv4,
          }
        : {}),
    };
    fs.mkdirSync(path.dirname(acknowledgementPath), { recursive: true });
    fs.writeFileSync(
      acknowledgementPath,
      `${JSON.stringify(acknowledgement)}\n`,
      { mode: 0o600 },
    );
  };
  const docker = {
    async exec() {
      const policy = JSON.parse(
        fs.readFileSync(
          path.join(root, 'egress', 'policies', `${runId}.json`),
          'utf8',
        ),
      );
      writeAcknowledgement(policy, false);
      replacementTimer = setTimeout(
        () => writeAcknowledgement(policy, true),
        1_000,
      );
      return { status: 0 };
    },
  };
  const { EgressManager } = await importModule(
    'lib/guardd/egress-manager.js',
  );
  const manager = new EgressManager({
    docker,
    stateDir: root,
    spawnSyncImpl() {
      return { status: 0, stderr: '' };
    },
  });
  await manager.initialize();
  const initPid = process.pid;
  const namespace = fs.statSync(`/proc/${initPid}/ns/net`, {
    bigint: true,
  });
  const allocation = {
    networkName: 'nosh-guard-legacy',
    runnerIp: '10.240.9.3',
    egressGateway: '10.240.9.2',
    gatewayContainerId: 'gateway-container',
  };

  try {
    await assert.rejects(
      manager.attachRun(
        {
          runId,
          mode: 'learn',
          profileRevision: 'candidate-1',
          initPid,
          namespaces: { net: namespace.ino.toString() },
        },
        {
          State: { Pid: initPid },
          NetworkSettings: {
            Networks: {
              [allocation.networkName]: {
                IPAddress: allocation.runnerIp,
              },
            },
          },
        },
        allocation,
        null,
        { networkRules: [] },
      ),
      (error) => {
        assert.equal(error.code, 'GUARD_EGRESS_POLICY_ACK_MISMATCH');
        assert.equal(error.runId, runId);
        assert.deepEqual(error.mismatchedFields, [
          'approvalHash',
          'profilePolicyHash',
          'imageDigest',
          'workspaceKey',
          'networkName',
          'sourceIpv4',
          'gatewayIpv4',
        ]);
        assert.match(error.message, /incompatible or stale/);
        assert.match(error.message, /io\.notty\.guard\.egress-abi=1/);
        return true;
      },
    );
  } finally {
    clearTimeout(replacementTimer);
  }
});

test('agent-only gateway principals reject ambiguous live runners', async () => {
  const { resolveRun } = await importModule('lib/guardd/gateway.js');
  const runs = [
    {
      runId: 'run-one',
      agentId: 'agent-one',
      status: 'running',
      containerId: 'container-one',
    },
    {
      runId: 'run-two',
      agentId: 'agent-one',
      status: 'running',
      containerId: 'container-two',
    },
  ];
  const service = {
    store: {
      async findRun(runId) {
        return runs.find((run) => run.runId === runId) || null;
      },
      async listRuns() {
        return runs;
      },
    },
  };

  await assert.rejects(
    resolveRun({ agentId: 'agent-one', runId: null }, service),
    (error) =>
      error.statusCode === 409 &&
      /multiple live runners|exact runId/.test(error.message),
  );
  assert.equal(
    (await resolveRun(
      { agentId: 'agent-one', runId: 'run-two' },
      service,
    )).containerId,
    'container-two',
  );
  runs[0].status = 'stopped';
  assert.equal(
    (await resolveRun({ agentId: 'agent-one', runId: null }, service)).runId,
    'run-two',
  );
});

test('principal route prefixes can narrow but never widen the gateway ceiling', async (t) => {
  const root = tempDir(t);
  const { PrincipalStore } = await importModule('lib/guardd/principals.js');
  const store = new PrincipalStore({ stateDir: root });
  await store.initialize();
  const base = {
    id: 'scoped-agent',
    certificateFingerprint: 'AB'.repeat(32),
    runId: 'run-one',
    expiresAt: new Date(Date.now() + 60_000).toISOString(),
  };
  const principal = await store.add({
    ...base,
    allowedPrefixes: [
      '/mcp',
      '/api/terminals/run-one',
      '/mcp',
    ],
  });

  assert.deepEqual(principal.allowedPrefixes, [
    '/mcp',
    '/api/terminals/run-one',
  ]);
  for (const invalid of [
    '',
    'mcp',
    '//mcp',
    '/api/admin',
    '/mcp/',
    '/mcp/../api/agents',
    '/mcp?admin=true',
    '/mcp/%2e%2e/api/agents',
  ]) {
    await assert.rejects(
      store.add({
        ...base,
        id: `invalid-${Buffer.from(invalid).toString('hex') || 'empty'}`,
        allowedPrefixes: [invalid],
      }),
      /allowedPrefixes|allowed prefix|canonical absolute paths|route ceiling/,
    );
  }

  fs.writeFileSync(
    path.join(root, 'principals.json'),
    `${JSON.stringify({
      schemaVersion: 1,
      principals: [
        {
          ...base,
          allowedPrefixes: ['/api/admin'],
        },
      ],
    })}\n`,
  );
  await assert.rejects(
    store.read(),
    /allowed prefix exceeds the gateway route ceiling/,
  );
});

test('counter snapshots require a fresh nonce-bound gateway attestation', async (t) => {
  const root = tempDir(t);
  const policyHash = `sha256:${'a'.repeat(64)}`;
  let request = null;
  let execCall = null;
  const docker = {
    async exec(containerId, command, options) {
      execCall = { containerId, command, options };
      request = JSON.parse(
        fs.readFileSync(
          path.join(
            root,
            'egress',
            'evidence',
            'snapshot-requests',
            'snapshot-run.json',
          ),
          'utf8',
        ),
      );
      fs.writeFileSync(
        path.join(
          root,
          'egress',
          'evidence',
          'snapshots',
          'snapshot-run.json',
        ),
        `${JSON.stringify({
          schemaVersion: 1,
          source: 'managed_gateway',
          type: 'counter_snapshot_attestation',
          runId: request.runId,
          policyHash: request.policyHash,
          nonce: request.nonce,
          requestedAt: request.requestedAt,
          recordedAt: '2026-07-25T12:00:01.000Z',
          complete: true,
          evidenceRecordHash: `sha256:${'b'.repeat(64)}`,
          managedDnsEvidence: managedDnsSnapshot(request.runId),
          error: null,
        })}\n`,
      );
      return { status: 0 };
    },
  };
  const { EgressManager } = await importModule(
    'lib/guardd/egress-manager.js',
  );
  const manager = new EgressManager({ docker, stateDir: root });
  const attestation = await manager.snapshotRun({
    runId: 'snapshot-run',
    egress: {
      policyHash,
      gatewayContainerId: 'gateway-container',
    },
  });

  assert.deepEqual(execCall, {
    containerId: 'gateway-container',
    command: ['/bin/sh', '-c', 'kill -USR1 1'],
    options: { user: '0' },
  });
  assert.equal(request.type, 'counter_snapshot_request');
  assert.equal(request.runId, 'snapshot-run');
  assert.equal(request.policyHash, policyHash);
  assert.match(request.nonce, /^[a-f0-9-]{36}$/);
  assert.equal(attestation.nonce, request.nonce);
  assert.equal(attestation.complete, true);
  assert.equal(
    fs.existsSync(
      path.join(
        root,
        'egress',
        'evidence',
        'snapshot-requests',
        'snapshot-run.json',
      ),
    ),
    false,
  );
});

test('observe-only egress-learn does not emit a managed-gateway snapshot record', async (t) => {
  const root = tempDir(t);
  const { EgressManager } = await importModule(
    'lib/guardd/egress-manager.js',
  );
  const manager = new EgressManager({
    docker: { async exec() { throw new Error('must not execute in observe-only mode'); } },
    stateDir: root,
  });
  const snapshot = await manager.snapshotRun({
    runId: 'observe-only-run',
    mode: 'egress-learn',
    egress: { observeOnly: true },
  });
  assert.equal(snapshot, null);
});

test('counter snapshots reject stale nonces and incomplete collection', async (t) => {
  const root = tempDir(t);
  const policyHash = `sha256:${'c'.repeat(64)}`;
  let responseMode = 'stale';
  const docker = {
    async exec() {
      const requestPath = path.join(
        root,
        'egress',
        'evidence',
        'snapshot-requests',
        'snapshot-run.json',
      );
      const request = JSON.parse(fs.readFileSync(requestPath, 'utf8'));
      const snapshot = {
        schemaVersion: 1,
        source: 'managed_gateway',
        type: 'counter_snapshot_attestation',
        runId: request.runId,
        policyHash: request.policyHash,
        nonce: responseMode === 'stale' ? crypto.randomUUID() : request.nonce,
        complete: responseMode !== 'incomplete',
        managedDnsEvidence: managedDnsSnapshot(request.runId),
        error: responseMode === 'incomplete' ? 'nft snapshot failed' : null,
      };
      fs.writeFileSync(
        path.join(
          root,
          'egress',
          'evidence',
          'snapshots',
          'snapshot-run.json',
        ),
        `${JSON.stringify(snapshot)}\n`,
      );
    },
  };
  const { EgressManager } = await importModule(
    'lib/guardd/egress-manager.js',
  );
  const manager = new EgressManager({ docker, stateDir: root });
  const run = {
    runId: 'snapshot-run',
    egress: {
      policyHash,
      gatewayContainerId: 'gateway-container',
    },
  };

  await assert.rejects(
    manager.snapshotRun(run, { timeoutMs: 75 }),
    (error) => error.code === 'GUARD_EGRESS_SNAPSHOT_TIMEOUT',
  );
  responseMode = 'incomplete';
  await assert.rejects(
    manager.snapshotRun(run, { timeoutMs: 75 }),
    (error) =>
      error.code === 'GUARD_EGRESS_SNAPSHOT_INCOMPLETE' &&
      /nft snapshot failed/.test(error.message),
  );
});

test('egress policy keeps learn, audit, and enforce decisions distinct', async () => {
  const { generateNftRules } = await importModule(
    'lib/guardd/egress-policy.js',
  );
  const learn = generateNftRules([egressPolicy('learn')]);
  const audit = generateNftRules([egressPolicy('audit')]);
  const enforce = generateNftRules([egressPolicy('enforce')]);

  assert.match(learn, / learn allow "/);
  assert.match(learn, /ip saddr 10\.240\.8\.3 ct mark set [^ ]+ counter accept/);
  assert.doesNotMatch(learn, /counter accept comment "profile"/);
  assert.doesNotMatch(learn, /audit would-deny|enforce deny/);

  assert.match(audit, /counter accept comment "profile"/);
  assert.match(audit, / audit would-deny "/);
  assert.match(audit, /ip saddr 10\.240\.8\.3 ct mark set [^ ]+ counter accept/);
  assert.doesNotMatch(audit, /enforce deny/);

  assert.match(enforce, /counter accept comment "profile"/);
  assert.match(enforce, / enforce deny "/);
  assert.match(enforce, /ip saddr 10\.240\.8\.3 counter drop/);
  assert.doesNotMatch(enforce, /learn allow|audit would-deny/);
});

test('scoped egress modes map exhaustively to learn, audit, and enforce behavior', async () => {
  const {
    egressModeBehavior,
    generateNftRules,
    requiresStrictManagedDns,
  } = await importModule('lib/guardd/egress-policy.js');
  const scopedLearn = generateNftRules([egressPolicy('egress-learn')]);
  const scopedAudit = generateNftRules([egressPolicy('egress-audit')]);
  const scopedEnforce = generateNftRules([egressPolicy('egress-enforce')]);

  assert.equal(egressModeBehavior('egress-learn'), 'record-allow');
  assert.equal(egressModeBehavior('egress-audit'), 'would-deny-allow');
  assert.equal(egressModeBehavior('egress-enforce'), 'allowlist-drop');
  assert.throws(() => egressModeBehavior('future-mode'), /unsupported/);
  assert.throws(
    () => generateNftRules([egressPolicy('future-mode')]),
    /egress mode must be one of/,
  );
  assert.equal(requiresStrictManagedDns('egress-learn'), false);
  assert.equal(requiresStrictManagedDns('egress-audit'), false);
  assert.equal(requiresStrictManagedDns('egress-enforce'), true);

  assert.match(scopedLearn, / egress-learn allow "/);
  assert.match(scopedLearn, /counter accept comment "nosh:[a-f0-9]+:egress-learn-observed"/);
  assert.match(scopedAudit, / egress-audit would-deny "/);
  assert.match(scopedAudit, /counter accept comment "nosh:[a-f0-9]+:egress-audit-would-deny"/);
  assert.match(scopedEnforce, / egress-enforce deny "/);
  assert.match(
    scopedEnforce,
    /ip saddr 10\.240\.8\.3 ct state established,related ct mark 0x[a-f0-9]+ counter accept/,
  );
  assert.match(scopedEnforce, /counter drop comment "nosh:[a-f0-9]+:egress-enforce-deny"/);
  assert.ok(
    scopedEnforce.indexOf('egress-enforce-deny')
      < scopedEnforce.indexOf('    ct state established,related ct mark {'),
    'source-bound terminal policy must precede the global established return rule',
  );
  assert.ok(
    scopedEnforce.indexOf('ip saddr 10.240.0.0/16 counter drop')
      < scopedEnforce.indexOf('    ct state established,related ct mark {'),
    'a removed runner policy must drop before established return handling',
  );
});

test('egress flow authorization marks are stable only for an unchanged policy', async () => {
  const { egressPolicyFlowMark } = await importModule(
    'lib/guardd/egress-policy.js',
  );
  const policy = egressPolicy('egress-enforce');
  assert.equal(egressPolicyFlowMark(policy), egressPolicyFlowMark(policy));
  assert.notEqual(
    egressPolicyFlowMark(policy),
    egressPolicyFlowMark({
      ...policy,
      egress: [
        ...policy.egress,
        { destination: 'second.example.com', protocol: 'tcp', ports: [443] },
      ],
    }),
  );
});

test('managed gateway rejects a policy whose content no longer matches its hash', async () => {
  const { verifyPolicyDocumentHash } = await importModule(
    'scripts/nosh-guard-egress-gateway.mjs',
  );
  const policy = egressPolicy('egress-enforce', {
    approvalHash: `sha256:${'a'.repeat(64)}`,
  });
  policy.policyHash = `sha256:${crypto
    .createHash('sha256')
    .update(JSON.stringify(policy))
    .digest('hex')}`;

  assert.equal(verifyPolicyDocumentHash(policy), policy);
  assert.throws(
    () =>
      verifyPolicyDocumentHash({
        ...policy,
        egress: [
          ...policy.egress,
          { destination: 'attacker.invalid', protocol: 'tcp', ports: [443] },
        ],
      }),
    /policy hash mismatch/,
  );
  assert.throws(
    () => verifyPolicyDocumentHash({ ...policy, policyHash: null }),
    /no valid policyHash/,
  );
});

test('managed gateway treats zero-match conntrack purges as best effort', async () => {
  const { clearConnections } = await importModule(
    'scripts/nosh-guard-egress-gateway.mjs',
  );
  const calls = [];
  clearConnections(
    [{ sourceIpv4: '10.240.9.3' }],
    (command, args, options) => {
      calls.push({ command, args, options });
    },
  );
  assert.deepEqual(calls, [
    {
      command: 'conntrack',
      args: ['-D', '-s', '10.240.9.3'],
      options: { allowFailure: true },
    },
    {
      command: 'conntrack',
      args: ['-D', '-d', '10.240.9.3'],
      options: { allowFailure: true },
    },
  ]);
  assert.throws(
    () => clearConnections(
      [{ sourceIpv4: '10.240.9.3' }],
      () => { throw new Error('conntrack unavailable'); },
    ),
    /conntrack unavailable/,
  );
});

test('managed gateway acknowledgement binds every scoped enforcement identity', async () => {
  const { policyAcknowledgementMatches } = await importModule(
    'lib/guardd/egress-manager.js',
  );
  const policy = {
    runId: 'exact-ack',
    mode: 'egress-enforce',
    profileRevision: 'approved-1',
    policyHash: `sha256:${'1'.repeat(64)}`,
    approvalHash: `sha256:${'2'.repeat(64)}`,
    profilePolicyHash: `sha256:${'3'.repeat(64)}`,
    imageDigest: `sha256:${'4'.repeat(64)}`,
    workspaceKey: '5'.repeat(64),
    networkName: 'nosh-guard-exact-ack',
    sourceIpv4: '10.240.8.3',
    gatewayIpv4: '10.240.8.2',
  };
  const acknowledgement = {
    source: 'managed_gateway',
    type: 'policy_attestation',
    ...policy,
  };

  assert.equal(policyAcknowledgementMatches(acknowledgement, policy), true);
  for (const field of [
    'runId',
    'mode',
    'profileRevision',
    'policyHash',
    'approvalHash',
    'profilePolicyHash',
    'imageDigest',
    'workspaceKey',
    'networkName',
    'sourceIpv4',
    'gatewayIpv4',
  ]) {
    assert.equal(
      policyAcknowledgementMatches(
        { ...acknowledgement, [field]: `${acknowledgement[field]}-changed` },
        policy,
      ),
      false,
      field,
    );
  }
});

test('egress grants match only the exact runId', async () => {
  const { normalizeEgressPolicy } = await importModule(
    'lib/guardd/egress-policy.js',
  );
  const expiresAt = new Date(Date.now() + 60_000).toISOString();
  const grant = (overrides) => ({
    id: 'grant',
    runId: null,
    profileRevision: 'candidate-1',
    destination: 'registry.npmjs.org',
    protocol: 'tcp',
    ports: [443],
    expiresAt,
    revokedAt: null,
    ...overrides,
  });
  const normalized = normalizeEgressPolicy(egressPolicy('enforce'), [
    grant({ id: 'exact-run', runId: 'run-enforce' }),
    grant({ id: 'different-run', runId: 'run-other' }),
    grant({ id: 'legacy-revision-only' }),
  ]);

  assert.deepEqual(
    normalized.rules.map((rule) => rule.source),
    ['profile', 'grant:exact-run'],
  );
});

test('ICMP rules are valid and IPv6 candidates fail explicitly', async () => {
  const { generateNftRules } = await importModule(
    'lib/guardd/egress-policy.js',
  );
  const unconstrained = generateNftRules([
    egressPolicy('enforce', {
      egress: [{ destination: '1.1.1.1/32', protocol: 'icmp' }],
    }),
  ]);
  const typed = generateNftRules([
    egressPolicy('enforce', {
      egress: [
        {
          destination: '1.1.1.1/32',
          protocol: 'icmp',
          icmpType: 8,
        },
      ],
    }),
  ]);

  assert.match(unconstrained, /meta l4proto icmp ct mark set 0x[a-f0-9]+ counter accept/);
  assert.match(typed, /icmp type 8 ct mark set 0x[a-f0-9]+ counter accept/);
  assert.doesNotMatch(typed, /\bicmp icmp\b/);
  assert.throws(
    () => generateNftRules([
      egressPolicy('enforce', {
        egress: [{
          destination: '2606:4700:4700::1111/128',
          protocol: 'icmpv6',
          icmpType: 128,
        }],
      }),
    ]),
    /IPv6 egress rules are unsupported/,
  );
});

test('special-use and DNS transports are reviewable while explicit platform containment stays first', async () => {
  const { generateNftRules } = await importModule(
    'lib/guardd/egress-policy.js',
  );
  const rules = generateNftRules([egressPolicy('learn')]);
  assert.doesNotMatch(rules, /10\.0\.0\.0\/8|192\.168\.0\.0\/16/);
  assert.doesNotMatch(rules, /dport \{ 53, 443, 853 \} counter drop/);
  assert.doesNotMatch(rules, /dport \{ 53, 853 \} counter drop/);
  assert.match(
    rules,
    /ip saddr 10\.240\.8\.3 ip daddr 10\.240\.8\.2 udp dport 53 ct mark set 1 counter accept/,
  );
  assert.match(
    rules,
    /ip saddr 10\.240\.8\.3 ip daddr 10\.240\.8\.2 tcp dport 53 ct mark set 1 counter accept/,
  );

  const enforce = generateNftRules([egressPolicy('enforce', {
    invariantBlockedCidrs: ['10.240.8.2/32'],
    egress: [
      { destination: '192.168.1.65/32', protocol: 'tcp', ports: [9001] },
      { destination: '1.1.1.1/32', protocol: 'udp', ports: [53, 443] },
      { destination: '9.9.9.9/32', protocol: 'tcp', ports: [853] },
    ],
  })]);
  const containment =
    'ip saddr 10.240.8.3 ip daddr @invariant_blocked_v4 counter drop';
  assert.ok(enforce.indexOf(containment) < enforce.indexOf('tcp dport 9001'));
  assert.match(enforce, /tcp dport 9001 .* counter accept/);
  assert.match(enforce, /udp dport \{ 53, 443 \} .* counter accept/);
  assert.match(enforce, /tcp dport 853 .* counter accept/);
  assert.match(enforce, / enforce deny /);
});

test('managed DNS accepts only exact runner and gateway address pairs', async () => {
  const { generateNftRules } = await importModule(
    'lib/guardd/egress-policy.js',
  );
  const first = egressPolicy('enforce', {
    runId: 'dns-pair-one',
    sourceIpv4: '10.240.8.3',
    gatewayIpv4: '10.240.8.2',
  });
  const second = egressPolicy('enforce', {
    runId: 'dns-pair-two',
    networkName: 'nosh-guard-dns-pair-two',
    sourceIpv4: '10.240.9.3',
    gatewayIpv4: '10.240.9.2',
  });
  const rules = generateNftRules([first, second]);

  for (const protocol of ['udp', 'tcp']) {
    assert.match(
      rules,
      new RegExp(
        `ip saddr 10\\.240\\.8\\.3 ip daddr 10\\.240\\.8\\.2 ` +
          `${protocol} dport 53 ct mark set 1 counter accept`,
      ),
    );
    assert.match(
      rules,
      new RegExp(
        `ip saddr 10\\.240\\.9\\.3 ip daddr 10\\.240\\.9\\.2 ` +
          `${protocol} dport 53 ct mark set 1 counter accept`,
      ),
    );
    assert.doesNotMatch(
      rules,
      new RegExp(
        `ip saddr 10\\.240\\.8\\.3 ip daddr 10\\.240\\.9\\.2 ` +
          `${protocol} dport 53 ct mark set 1 counter accept`,
      ),
    );
    assert.doesNotMatch(
      rules,
      new RegExp(
        `ip saddr 10\\.240\\.9\\.3 ip daddr 10\\.240\\.8\\.2 ` +
          `${protocol} dport 53 ct mark set 1 counter accept`,
      ),
    );
  }
});

test('enforce DNS binds one gateway and filters exact and wildcard FQDNs', async () => {
  const { generateDnsmasqConfig } = await importModule(
    'lib/guardd/egress-policy.js',
  );
  const upstreamServers = ['1.1.1.1', '9.9.9.9'];
  const enforce = generateDnsmasqConfig(
    [
      egressPolicy('enforce', {
        egress: [
          {
            destination: 'api.openai.com',
            protocol: 'tcp',
            ports: [443],
          },
          {
            destination: 'registry.npmjs.org',
            protocol: 'tcp',
            ports: [443],
          },
          {
            destination: '*.githubusercontent.com',
            protocol: 'tcp',
            ports: [443],
          },
        ],
      }),
    ],
    [],
    {
      listenAddress: '10.240.8.2',
      pidFile: '/run/nosh-guard/dnsmasq-enforce.pid',
      strictDomains: true,
      upstreamServers,
      uplinkInterface: 'eth0',
    },
  );
  const serverLines = enforce
    .split('\n')
    .filter((line) => line.startsWith('server='));

  assert.match(enforce, /^bind-interfaces$/m);
  assert.deepEqual(
    enforce
      .split('\n')
      .filter((line) => line.startsWith('listen-address=')),
    ['listen-address=10.240.8.2'],
  );
  assert.deepEqual(serverLines, [
    'server=1.1.1.1',
    'server=9.9.9.9',
  ]);
  assert.match(enforce, /^connmark-allowlist-enable$/m);
  assert.match(
    enforce,
    /^connmark-allowlist=1,\*\.githubusercontent\.com\/api\.openai\.com\/registry\.npmjs\.org$/m,
  );
  assert.match(
    enforce,
    /^nftset=\/\*\.githubusercontent\.com\//m,
  );
  assert.match(enforce, /^nftset=\/api\.openai\.com\//m);
  assert.doesNotMatch(
    enforce,
    /^connmark-allowlist=1,(?:githubusercontent\.com(?:\/|$)|[^ \n]*\/githubusercontent\.com(?:\/|$))/m,
  );
});

test('DNS audit wildcard matching mirrors dnsmasq one-label semantics', async () => {
  const { dnsNameMatches } = await importModule(
    'lib/guardd/evidence-finalizer.js',
  );
  assert.equal(dnsNameMatches('api.example.com', 'api.example.com'), true);
  assert.equal(dnsNameMatches('api.example.com', 'other.example.com'), false);
  assert.equal(dnsNameMatches('*.example.com', 'api.example.com'), true);
  assert.equal(dnsNameMatches('*.example.com', 'example.com'), false);
  assert.equal(dnsNameMatches('*.example.com', 'api.us.example.com'), false);
});

test('learn and audit DNS modes remain observational through unrestricted upstreams', async () => {
  const { generateDnsmasqConfig } = await importModule(
    'lib/guardd/egress-policy.js',
  );

  for (const mode of ['learn', 'audit', 'egress-learn', 'egress-audit']) {
    const config = generateDnsmasqConfig(
      [egressPolicy(mode)],
      [],
      {
        listenAddress: '10.240.8.2',
        strictDomains: false,
        upstreamServers: ['1.1.1.1', '9.9.9.9'],
      },
    );
    assert.match(config, /^listen-address=10\.240\.8\.2$/m);
    assert.match(config, /^server=1\.1\.1\.1$/m);
    assert.match(config, /^server=9\.9\.9\.9$/m);
    assert.doesNotMatch(config, /^connmark-allowlist(?:-enable|=)/m);
    assert.match(config, /^nftset=\/api\.openai\.com\//m);
  }
});

test('managed DNS projection isolates colliding serials by dnsmasq PID', async () => {
  const { projectManagedDnsLines } = await importModule(
    'lib/guardd/evidence-finalizer.js',
  );
  const records = projectManagedDnsLines(
    [
      'dnsmasq[101]: 42 query[A] api.openai.com from 10.240.8.3',
      'dnsmasq[202]: 42 query[A] unrelated.example from 10.240.9.3',
      'dnsmasq[202]: 42 reply unrelated.example is 203.0.113.20',
      'dnsmasq[101]: 42 forwarded api.openai.com to 1.1.1.1',
      'dnsmasq[101]: 42 reply api.openai.com is 203.0.113.10',
      'dnsmasq: 42 query[A] legacy.example from 10.240.8.3',
      'dnsmasq: 42 reply unrelated.example is 203.0.113.30',
      'dnsmasq[303]: 43 query[A] near-match.example from 10.240.8.30',
      'dnsmasq[303]: 43 reply near-match.example is 203.0.113.40',
    ].join('\n'),
    '10.240.8.3',
  );

  assert.deepEqual(
    records.map((record) => [record.type, record.qname, record.upstream]),
    [
      ['query', 'api.openai.com', null],
      ['forward', null, '1.1.1.1'],
      ['answer', 'api.openai.com', null],
      ['query', 'legacy.example', null],
    ],
  );
  assert.ok(
    records.every(
      (record) =>
        !record.raw.includes('unrelated.example') &&
        !record.raw.includes('near-match.example'),
    ),
  );
});

test('managed DNS projection keeps the original query name across CNAME answers', async () => {
  const { projectManagedDnsLines } = await importModule(
    'lib/guardd/evidence-finalizer.js',
  );
  const records = projectManagedDnsLines(
    [
      'nosh-observed-at=2026-07-25T12:00:00.000Z dnsmasq[404]: 44 query[A] api.example.com from 10.240.8.3',
      'nosh-observed-at=2026-07-25T12:00:00.050Z dnsmasq[404]: 44 forwarded api.example.com to 1.1.1.1',
      'nosh-observed-at=2026-07-25T12:00:00.100Z dnsmasq[404]: 44 reply api.example.com is <CNAME>',
      'nosh-observed-at=2026-07-25T12:00:00.150Z dnsmasq[404]: 44 reply edge.example.net is 203.0.113.50',
    ].join('\n'),
    '10.240.8.3',
  );
  const addressAnswer = records.find(
    (record) => record.type === 'answer' && record.answer === '203.0.113.50',
  );

  assert.deepEqual(
    {
      qname: addressAnswer?.qname,
      responseName: addressAnswer?.responseName,
      observedAt: addressAnswer?.observedAt,
    },
    {
      qname: 'api.example.com',
      responseName: 'edge.example.net',
      observedAt: '2026-07-25T12:00:00.150Z',
    },
  );
});

test('managed DNS evidence enforces a persistent per-run byte ceiling', async (t) => {
  const root = tempDir(t);
  const evidenceDir = path.join(root, 'egress', 'evidence');
  const runId = 'dns-budget-run';
  const paths = managedDnsEvidencePaths(evidenceDir, runId);
  fs.mkdirSync(paths.directory, { recursive: true });
  fs.writeFileSync(paths.logPath, '', { mode: 0o600 });
  const { createManagedDnsEvidenceWriter } = await importModule(
    'scripts/nosh-guard-egress-gateway.mjs',
  );

  const first = await createManagedDnsEvidenceWriter(runId, {
    evidenceDir,
    maxBytes: 48,
  });
  first.stream.write(Buffer.alloc(24, 0x61));
  first.stream.write(Buffer.alloc(24, 0x62));
  first.stream.write(Buffer.alloc(24, 0x63));
  await endWritable(first.stream);

  assert.equal(fs.statSync(paths.logPath).size, 48);
  const marker = JSON.parse(fs.readFileSync(paths.overflowPath, 'utf8'));
  assert.deepEqual(
    {
      type: marker.type,
      runId: marker.runId,
      limitBytes: marker.limitBytes,
      bytesWritten: marker.bytesWritten,
      lostEvents: marker.lostEvents,
      lossReason: marker.lossReason,
    },
    {
      type: 'evidence_overflow',
      runId,
      limitBytes: 48,
      bytesWritten: 48,
      lostEvents: 1,
      lossReason: 'byte_budget_exceeded',
    },
  );

  const restarted = await createManagedDnsEvidenceWriter(runId, {
    evidenceDir,
    maxBytes: 48,
  });
  restarted.stream.write(Buffer.alloc(24, 0x64));
  await endWritable(restarted.stream);
  assert.equal(fs.statSync(paths.logPath).size, 48);
  assert.equal(restarted.overflowed, true);
});

test('managed DNS forced termination persists explicit evidence loss', async (t) => {
  const root = tempDir(t);
  const evidenceDir = path.join(root, 'egress', 'evidence');
  const runId = 'dns-forced-stop-run';
  const paths = managedDnsEvidencePaths(evidenceDir, runId);
  fs.mkdirSync(paths.directory, { recursive: true });
  fs.writeFileSync(paths.logPath, '', { mode: 0o600 });
  const { createManagedDnsEvidenceWriter } = await importModule(
    'scripts/nosh-guard-egress-gateway.mjs',
  );
  const writer = await createManagedDnsEvidenceWriter(runId, { evidenceDir });
  const failure = new Error('resolver required SIGKILL');
  failure.code = 'MANAGED_DNS_FORCED_TERMINATION';
  const emitted = new Promise((resolve) => writer.stream.once('error', resolve));
  writer.stream.destroy(failure);
  assert.equal(await emitted, failure);

  const marker = JSON.parse(fs.readFileSync(paths.overflowPath, 'utf8'));
  assert.equal(marker.lossReason, 'forced_termination');
  assert.equal(marker.lostEvents, 1);
  const restarted = await createManagedDnsEvidenceWriter(runId, { evidenceDir });
  assert.equal(restarted.overflowed, true);
  await endWritable(restarted.stream);
});

test('managed gateway evidence stops at a durable hard ceiling', async (t) => {
  const root = tempDir(t);
  const evidencePath = path.join(root, 'managed-gateway-counters.ndjson');
  const overflowPath = path.join(
    root,
    'managed-gateway-counters.overflow.json',
  );
  const { appendManagedGatewayEvidence } = await importModule(
    'scripts/nosh-guard-egress-gateway.mjs',
  );
  const options = { evidencePath, overflowPath, maxBytes: 48 };
  await appendManagedGatewayEvidence(Buffer.alloc(32, 0x61), options);
  await assert.rejects(
    appendManagedGatewayEvidence(Buffer.alloc(24, 0x62), options),
    (error) => error.code === 'GUARD_GATEWAY_EVIDENCE_EXHAUSTED',
  );

  assert.equal(fs.statSync(evidencePath).size, 32);
  const marker = JSON.parse(fs.readFileSync(overflowPath, 'utf8'));
  assert.deepEqual(
    {
      type: marker.type,
      limitBytes: marker.limitBytes,
      bytesWritten: marker.bytesWritten,
      lostEvents: marker.lostEvents,
    },
    {
      type: 'evidence_overflow',
      limitBytes: 48,
      bytesWritten: 32,
      lostEvents: 1,
    },
  );
  await assert.rejects(
    appendManagedGatewayEvidence(Buffer.alloc(1), options),
    (error) => error.code === 'GUARD_GATEWAY_EVIDENCE_EXHAUSTED',
  );
  assert.equal(fs.statSync(evidencePath).size, 32);
});

test('final snapshots drain managed DNS before publishing an attestation', async () => {
  const {
    drainManagedDnsBeforeSnapshot,
    managedDnsSnapshotsForStoppedProcesses,
  } = await importModule(
    'scripts/nosh-guard-egress-gateway.mjs',
  );
  const policies = [{ runId: 'snapshot-drain-run' }];
  const grants = { grants: [] };
  const layout = { uplinkInterface: 'eth0' };
  const operations = [];
  const stoppedSnapshots = managedDnsSnapshotsForStoppedProcesses([{
    runId: 'snapshot-drain-run',
    evidence: {
      maxBytes: managedDnsMaxBytes,
      bytesWritten: 42,
      overflowMarker: null,
    },
  }]);
  assert.equal(
    stoppedSnapshots.get('snapshot-drain-run').bytesWritten,
    42,
  );
  const managedDnsEvidenceSnapshots = stoppedSnapshots;
  const records = await drainManagedDnsBeforeSnapshot({
    policies,
    grants,
    layout,
    async stopResolver() {
      operations.push('drain');
      return managedDnsEvidenceSnapshots;
    },
    async startResolver(receivedPolicies, receivedGrants, receivedLayout) {
      assert.equal(receivedPolicies, policies);
      assert.equal(receivedGrants, grants);
      assert.equal(receivedLayout, layout);
      operations.push('restart');
    },
    async captureCounters(receivedPolicies, options) {
      assert.equal(receivedPolicies, policies);
      assert.deepEqual(options, {
        publishSnapshotAttestations: true,
        managedDnsEvidenceSnapshots,
      });
      operations.push('publish');
      return ['snapshot-record'];
    },
  });
  assert.deepEqual(operations, ['drain', 'restart', 'publish']);
  assert.deepEqual(records, ['snapshot-record']);

  operations.length = 0;
  await assert.rejects(
    drainManagedDnsBeforeSnapshot({
      policies,
      grants,
      layout,
      async stopResolver() {
        operations.push('drain');
      },
      async startResolver() {
        operations.push('restart');
        throw new Error('resolver restart failed');
      },
      async captureCounters() {
        operations.push('publish');
      },
    }),
    /resolver restart failed/,
  );
  assert.deepEqual(operations, ['drain', 'restart']);
});

test('managed DNS overflow is explicit incomplete evidence', async (t) => {
  const root = tempDir(t);
  const sharedDir = path.join(root, 'egress', 'evidence');
  const runId = 'dns-overflow-run';
  const run = makeRun(root, { runId, mode: 'enforce' });
  run.profilePolicyHash = `sha256:${'a'.repeat(64)}`;
  const paths = managedDnsEvidencePaths(sharedDir, runId);
  const raw =
    'nosh-observed-at=2026-07-25T12:00:00.000Z dnsmasq[77]: 1 query[A] api.example.com from 10.240.8.3\n';
  fs.writeFileSync(paths.logPath, raw, { mode: 0o600 });
  const overflowMarker = {
    schemaVersion: 1,
    source: 'managed_dns',
    type: 'evidence_overflow',
    runId,
    evidenceKey: paths.key,
    observedAt: '2026-07-25T12:00:01.000Z',
    lossReason: 'byte_budget_exceeded',
    limitBytes: managedDnsMaxBytes,
    bytesWritten: Buffer.byteLength(raw),
    lostEvents: 1,
  };
  fs.writeFileSync(
    paths.overflowPath,
    `${JSON.stringify(overflowMarker, null, 2)}\n`,
    { mode: 0o600 },
  );
  run.egress.finalSnapshot.managedDnsEvidence = managedDnsSnapshot(
    runId,
    Buffer.byteLength(raw),
    overflowMarker,
  );
  const { finalizeRunEvidence } = await importModule(
    'lib/guardd/evidence-finalizer.js',
  );

  const { manifest } = await finalizeRunEvidence(run, {
    stateDir: root,
    requiredSources: ['managed_dns'],
  });
  const source = sourceByName(manifest, 'managed_dns');
  assert.equal(source.complete, false);
  assert.equal(source.lostEvents, 1);
  assert.equal(source.completionMarker, 'managed-dns-byte-budget-exceeded');
  assert.equal(manifest.complete, false);
  assert.equal(manifest.trainingEligible, false);

  fs.rmSync(paths.overflowPath);
  const afterMarkerDeletion = await finalizeRunEvidence(run, {
    stateDir: root,
    requiredSources: ['managed_dns'],
  });
  const deletedMarkerSource = sourceByName(
    afterMarkerDeletion.manifest,
    'managed_dns',
  );
  assert.equal(deletedMarkerSource.complete, false);
  assert.equal(deletedMarkerSource.lostEvents, 1);
  assert.equal(
    deletedMarkerSource.adapterState.evidenceWindow.marker,
    'managed-dns-overflow-marker-invalid',
  );
});

test('finalization refuses an over-budget managed DNS file without reading it', async (t) => {
  const root = tempDir(t);
  const sharedDir = path.join(root, 'egress', 'evidence');
  const runId = 'dns-oversize-run';
  const run = makeRun(root, { runId, mode: 'enforce' });
  run.profilePolicyHash = `sha256:${'a'.repeat(64)}`;
  const paths = managedDnsEvidencePaths(sharedDir, runId);
  fs.truncateSync(paths.logPath, managedDnsMaxBytes + 1);
  const { finalizeRunEvidence } = await importModule(
    'lib/guardd/evidence-finalizer.js',
  );

  const { manifest } = await finalizeRunEvidence(run, {
    stateDir: root,
    requiredSources: ['managed_dns'],
  });
  const source = sourceByName(manifest, 'managed_dns');
  assert.equal(source.complete, false);
  assert.equal(source.lostEvents, 1);
  assert.equal(source.completionMarker, 'evidence-byte-budget-exceeded');
});

test('FQDN rules keep each domain paired only with its own ports', async () => {
  const {
    generateDnsmasqConfig,
    generateNftRules,
    policySetNames,
  } = await importModule('lib/guardd/egress-policy.js');
  const policy = egressPolicy('enforce', {
    egress: [
      {
        destination: 'api.openai.com',
        protocol: 'tcp',
        ports: [443],
      },
      {
        destination: 'github.com',
        protocol: 'tcp',
        ports: [22],
      },
    ],
  });
  const [openaiV4, githubV4] = policySetNames(policy);
  const nft = generateNftRules([policy]);
  const dnsmasq = generateDnsmasqConfig([policy]);
  const openaiDns = dnsmasq
    .split('\n')
    .find((line) => line.startsWith('nftset=/api.openai.com/'));
  const githubDns = dnsmasq
    .split('\n')
    .find((line) => line.startsWith('nftset=/github.com/'));

  assert.match(nft, new RegExp(`ip daddr @${openaiV4} tcp dport 443`));
  assert.match(nft, new RegExp(`ip daddr @${githubV4} tcp dport 22`));
  assert.doesNotMatch(nft, new RegExp(`@${openaiV4} tcp dport 22`));
  assert.doesNotMatch(nft, new RegExp(`@${githubV4} tcp dport 443`));

  assert.ok(openaiDns);
  assert.match(openaiDns, new RegExp(openaiV4));
  assert.doesNotMatch(openaiDns, new RegExp(githubV4));
  assert.ok(githubDns);
  assert.match(githubDns, new RegExp(githubV4));
  assert.doesNotMatch(githubDns, new RegExp(openaiV4));
});

test('dynamic destination sets and resolver answers expire within five minutes', async () => {
  const { generateDnsmasqConfig, generateNftRules, policySetNames } =
    await importModule('lib/guardd/egress-policy.js');
  const policy = egressPolicy('enforce');
  const nft = generateNftRules([policy]);
  const dnsmasq = generateDnsmasqConfig([policy]);

  for (const name of policySetNames(policy)) {
    const declaration = nft.match(
      new RegExp(`set ${name} \\{([\\s\\S]*?)\\n  \\}`),
    )?.[1];
    assert.ok(declaration, `missing set ${name}`);
    assert.match(declaration, /flags interval,timeout/);
    assert.match(declaration, /timeout 5m/);
  }
  assert.match(dnsmasq, /^max-cache-ttl=300$/m);
  assert.match(dnsmasq, /^min-cache-ttl=1$/m);
});

test('static CIDR sets remain permanent while FQDN sets retain timeouts', async () => {
  const { generateNftRules, normalizeEgressPolicy, policySetNames } =
    await importModule('lib/guardd/egress-policy.js');
  const policy = egressPolicy('enforce', {
    egress: [
      {
        destination: '203.0.113.0/24',
        protocol: 'tcp',
        ports: [443],
      },
      {
        destination: 'api.openai.com',
        protocol: 'tcp',
        ports: [443],
      },
    ],
  });
  const normalized = normalizeEgressPolicy(policy);
  const [cidrRule, fqdnRule] = normalized.rules;
  const [cidrSet] = policySetNames(policy).filter((name) =>
    name.includes(cidrRule.id),
  );
  const fqdnSets = policySetNames(policy).filter((name) =>
    name.includes(fqdnRule.id),
  );
  const nft = generateNftRules([policy]);
  const declaration = (name) =>
    nft.match(new RegExp(`set ${name} \\{([\\s\\S]*?)\\n  \\}`))?.[1];

  assert.ok(declaration(cidrSet), `missing set ${cidrSet}`);
  assert.match(declaration(cidrSet), /flags interval(?:\n|$)/);
  assert.doesNotMatch(declaration(cidrSet), /timeout/);
  assert.match(declaration(cidrSet), /elements = \{ 203\.0\.113\.0\/24 \}/);
  assert.equal(fqdnSets.length, 1);
  for (const name of fqdnSets) {
    assert.match(declaration(name), /flags interval,timeout/);
    assert.match(declaration(name), /timeout 5m/);
  }
  assert.doesNotMatch(nft, /ip saddr 10\.240\.8\.3 ip6 daddr/);
});

test('managed gateway evidence is isolated by run ID', async (t) => {
  const root = tempDir(t);
  const sharedDir = path.join(root, 'egress', 'evidence');
  fs.mkdirSync(sharedDir, { recursive: true });
  writeJsonl(path.join(sharedDir, 'managed-gateway-counters.ndjson'), [
    { type: 'policy_reload', runId: 'run-a', sequence: 1 },
    { type: 'counter_snapshot', runId: 'run-b', sequence: 2 },
    { type: 'counter_snapshot', runId: 'run-a', sequence: 3 },
  ]);
  const { finalizeRunEvidence } = await importModule(
    'lib/guardd/evidence-finalizer.js',
  );
  const runA = makeRun(root, { runId: 'run-a' });
  const runB = makeRun(root, { runId: 'run-b' });

  await finalizeRunEvidence(runA, {
    stateDir: root,
    requiredSources: ['managed_gateway'],
  });
  await finalizeRunEvidence(runB, {
    stateDir: root,
    requiredSources: ['managed_gateway'],
  });
  const recordsA = fs
    .readFileSync(path.join(runA.evidenceDir, 'managed_gateway.jsonl'), 'utf8')
    .trim()
    .split('\n')
    .map(JSON.parse);
  const recordsB = fs
    .readFileSync(path.join(runB.evidenceDir, 'managed_gateway.jsonl'), 'utf8')
    .trim()
    .split('\n')
    .map(JSON.parse);

  assert.deepEqual(recordsA.map((record) => record.runId), [
    'run-a',
    'run-a',
    'run-a',
  ]);
  assert.deepEqual(recordsA.map((record) => record.sequence), [1, 3, undefined]);
  assert.deepEqual(recordsB.map((record) => record.runId), ['run-b', 'run-b']);
  assert.deepEqual(recordsB.map((record) => record.sequence), [2, undefined]);
});

test('managed gateway counters sum reset epochs across process sessions', async (t) => {
  const root = tempDir(t);
  const evidencePath = path.join(root, 'gateway.ndjson');
  const policyHash = `sha256:${'9'.repeat(64)}`;
  const record = (counterSession, counterEpoch, wouldDenyCount) => ({
    source: 'managed_gateway',
    type: 'counter_snapshot',
    runId: 'counter-session-run',
    policyHash,
    counterSession,
    counterEpoch,
    wouldDenyCount,
    deniedCount: 0,
  });
  writeJsonl(evidencePath, [
    record('11111111-1111-4111-8111-111111111111', 1, 2),
    record('11111111-1111-4111-8111-111111111111', 1, 5),
    record('22222222-2222-4222-8222-222222222222', 1, 3),
  ]);
  const { managedGatewayDecisionCounts } = await importModule(
    'lib/guardd/evidence-finalizer.js',
  );

  assert.deepEqual(
    await managedGatewayDecisionCounts(evidencePath, {
      runId: 'counter-session-run',
      egress: { policyHash },
    }),
    { wouldDenyCount: 8, deniedCount: 0 },
  );
});

test('managed evidence starts at the captured file identity and byte offset', async (t) => {
  const root = tempDir(t);
  const sharedDir = path.join(root, 'egress', 'evidence');
  fs.mkdirSync(sharedDir, { recursive: true });
  const runId = 'run-window';
  const dnsPaths = managedDnsEvidencePaths(sharedDir, runId);
  fs.mkdirSync(dnsPaths.directory, { recursive: true });
  const dnsPath = dnsPaths.logPath;
  const gatewayPath = path.join(
    sharedDir,
    'managed-gateway-counters.ndjson',
  );
  const staleDns =
    'dnsmasq[10]: 100 query[A] stale.example from 10.240.8.3\n';
  const freshDns =
    'dnsmasq[10]: 101 query[A] fresh.example from 10.240.8.3\n';
  fs.writeFileSync(dnsPath, staleDns + freshDns);
  const staleGateway = `${JSON.stringify({
    source: 'managed_gateway',
    type: 'counter_snapshot',
    runId: 'run-window',
    sequence: 1,
  })}\n`;
  const freshGateway = `${JSON.stringify({
    source: 'managed_gateway',
    type: 'counter_snapshot',
    runId: 'run-window',
    sequence: 2,
  })}\n`;
  fs.writeFileSync(gatewayPath, staleGateway + freshGateway);
  const run = makeRun(root, {
    runId,
    evidenceOffsets: {
      dns: {
        ...evidenceFileIdentity(dnsPath, Buffer.byteLength(staleDns)),
        evidenceKey: dnsPaths.key,
        maxBytes: managedDnsMaxBytes,
      },
      gateway: evidenceFileIdentity(
        gatewayPath,
        Buffer.byteLength(staleGateway),
      ),
    },
  });
  fs.appendFileSync(
    dnsPath,
    'dnsmasq[11]: 1 query[A] restart-only.example from 10.240.8.3\n',
  );
  const { finalizeRunEvidence } = await importModule(
    'lib/guardd/evidence-finalizer.js',
  );

  const { manifest } = await finalizeRunEvidence(run, {
    stateDir: root,
    requiredSources: ['managed_dns', 'managed_gateway'],
  });
  const dnsRecords = fs
    .readFileSync(path.join(run.evidenceDir, 'managed_dns.jsonl'), 'utf8')
    .split(/\r?\n/)
    .filter(Boolean)
    .map(JSON.parse);
  const gatewayRecords = fs
    .readFileSync(
      path.join(run.evidenceDir, 'managed_gateway.jsonl'),
      'utf8',
    )
    .split(/\r?\n/)
    .filter(Boolean)
    .map(JSON.parse);

  assert.deepEqual(dnsRecords.map((record) => record.qname), ['fresh.example']);
  assert.deepEqual(
    gatewayRecords
      .map((record) => record.sequence)
      .filter((sequence) => sequence != null),
    [2],
  );
  for (const name of ['managed_dns', 'managed_gateway']) {
    const source = sourceByName(manifest, name);
    assert.equal(source.adapterState.evidenceWindow.ok, true);
    assert.equal(
      source.adapterState.evidenceWindow.marker,
      'run-scoped-byte-window',
    );
  }
  const dnsSource = sourceByName(manifest, 'managed_dns');
  assert.ok(
    Number(dnsSource.adapterState.evidenceWindow.bytesAtFinalization)
      > Number(dnsSource.adapterState.evidenceWindow.bytesAtSnapshot),
  );
});

test('managed evidence fails closed on invalid offsets or file identity', async (t) => {
  const root = tempDir(t);
  const sharedDir = path.join(root, 'egress', 'evidence');
  fs.mkdirSync(sharedDir, { recursive: true });
  const gatewayPath = path.join(
    sharedDir,
    'managed-gateway-counters.ndjson',
  );
  fs.writeFileSync(
    gatewayPath,
    `${JSON.stringify({
      source: 'managed_gateway',
      type: 'counter_snapshot',
      runId: 'sentinel',
      sentinel: true,
    })}\n`,
  );
  const sourceNames = { dns: 'managed_dns', gateway: 'managed_gateway' };
  const cases = [
    {
      name: 'missing',
      expected: 'evidence-offset-missing',
      value() {
        return undefined;
      },
    },
    {
      name: 'old-number-shape',
      expected: 'evidence-file-identity-invalid',
      value() {
        return 0;
      },
    },
    {
      name: 'fractional',
      expected: 'evidence-offset-not-integer',
      value(identity) {
        return { ...identity, offset: 0.5 };
      },
    },
    {
      name: 'past-eof',
      expected: 'evidence-offset-out-of-range',
      value(identity, filePath) {
        return {
          ...identity,
          offset: fs.statSync(filePath).size + 1,
        };
      },
    },
    {
      name: 'mid-record',
      expected: 'evidence-window-truncated',
      value(identity) {
        return { ...identity, offset: 1 };
      },
    },
    {
      name: 'wrong-inode',
      expected: 'evidence-file-identity-mismatch',
      value(identity) {
        return {
          ...identity,
          ino: (BigInt(identity.ino) + 1n).toString(),
        };
      },
    },
  ];
  const { finalizeRunEvidence } = await importModule(
    'lib/guardd/evidence-finalizer.js',
  );
  let sequence = 0;
  for (const key of ['dns', 'gateway']) {
    for (const scenario of cases) {
      sequence += 1;
      const runId = `invalid-window-${sequence}`;
      const dnsPaths = managedDnsEvidencePaths(sharedDir, runId);
      fs.mkdirSync(dnsPaths.directory, { recursive: true });
      fs.writeFileSync(
        dnsPaths.logPath,
        'dnsmasq[10]: 200 query[A] sentinel.example from 10.240.8.3\n',
        { mode: 0o600 },
      );
      const paths = { dns: dnsPaths.logPath, gateway: gatewayPath };
      const offsets = {
        dns: {
          ...evidenceFileIdentity(dnsPaths.logPath),
          evidenceKey: dnsPaths.key,
          maxBytes: managedDnsMaxBytes,
        },
        gateway: evidenceFileIdentity(gatewayPath),
      };
      const value = scenario.value(offsets[key], paths[key]);
      if (value === undefined) {
        delete offsets[key];
      } else {
        offsets[key] = value;
      }
      const run = makeRun(root, { runId, evidenceOffsets: offsets });
      const { manifest } = await finalizeRunEvidence(run, {
        stateDir: root,
        requiredSources: [sourceNames[key]],
      });
      const source = sourceByName(manifest, sourceNames[key]);
      const projected = fs.readFileSync(source.path, 'utf8');

      const expected = key === 'dns'
        && ['missing', 'old-number-shape'].includes(scenario.name)
        ? 'managed-dns-budget-identity-invalid'
        : scenario.expected;
      assert.equal(source.completionMarker, expected, `${key}/${scenario.name}`);
      assert.equal(source.complete, false, `${key}/${scenario.name}`);
      assert.equal(manifest.complete, false, `${key}/${scenario.name}`);
      assert.doesNotMatch(projected, /sentinel/, `${key}/${scenario.name}`);
    }
  }
});

test('managed gateway evidence never accepts a foreign-run acknowledgement', async (t) => {
  const root = tempDir(t);
  const { finalizeRunEvidence } = await importModule(
    'lib/guardd/evidence-finalizer.js',
  );
  const run = makeRun(root, {
    runId: 'run-current',
    acknowledgement: gatewayAttestation('run-foreign'),
  });
  let finalized;
  try {
    finalized = await finalizeRunEvidence(run, {
      stateDir: root,
      requiredSources: ['managed_gateway'],
    });
  } catch (error) {
    assert.match(error.message, /acknowledgement|run.?id|attestation/i);
    return;
  }
  const records = fs
    .readFileSync(path.join(run.evidenceDir, 'managed_gateway.jsonl'), 'utf8')
    .split(/\r?\n/)
    .filter(Boolean)
    .map(JSON.parse);
  const managedGateway = sourceByName(
    finalized.manifest,
    'managed_gateway',
  );

  assert.ok(
    records.every((record) => record.runId === run.runId),
    'foreign-run records must not enter a run evidence directory',
  );
  assert.equal(managedGateway.complete, false);
  assert.equal(finalized.manifest.complete, false);
});

test('managed gateway completion requires a hash-matched final counter snapshot', async (t) => {
  const root = tempDir(t);
  const sharedDir = path.join(root, 'egress', 'evidence');
  fs.mkdirSync(sharedDir, { recursive: true });
  const policyHash = `sha256:${'d'.repeat(64)}`;
  const counter = {
    schemaVersion: 1,
    source: 'managed_gateway',
    type: 'counter_snapshot',
    timestamp: '2026-07-25T12:00:01.000Z',
    runId: 'snapshot-complete',
    mode: 'enforce',
    profileRevision: 'candidate-1',
    policyHash,
    complete: true,
    decision: 'observed',
    wouldDenyCount: 0,
    deniedCount: 0,
    counters: [
      {
        handle: 42,
        comment: 'nosh:runhash:enforce-deny',
        packets: 0,
        bytes: 0,
      },
    ],
    error: null,
  };
  const evidenceRecordHash = `sha256:${crypto
    .createHash('sha256')
    .update(JSON.stringify(counter))
    .digest('hex')}`;
  writeJsonl(path.join(sharedDir, 'managed-gateway-counters.ndjson'), [
    counter,
  ]);
  const acknowledgement = {
    ...gatewayAttestation('snapshot-complete'),
    policyHash,
  };
  const finalSnapshot = {
    schemaVersion: 1,
    source: 'managed_gateway',
    type: 'counter_snapshot_attestation',
    runId: 'snapshot-complete',
    policyHash,
    nonce: crypto.randomUUID(),
    requestedAt: '2026-07-25T12:00:00.000Z',
    recordedAt: counter.timestamp,
    complete: true,
    evidenceRecordHash,
    managedDnsEvidence: managedDnsSnapshot('snapshot-complete'),
    error: null,
  };
  const run = makeRun(root, {
    runId: 'snapshot-complete',
    acknowledgement,
  });
  run.egress.policyHash = policyHash;
  run.egress.finalSnapshot = finalSnapshot;
  const { finalizeRunEvidence } = await importModule(
    'lib/guardd/evidence-finalizer.js',
  );
  const { manifest } = await finalizeRunEvidence(run, {
    stateDir: root,
    requiredSources: ['managed_gateway'],
  });
  const managedGateway = sourceByName(manifest, 'managed_gateway');

  assert.equal(managedGateway.complete, true);
  assert.equal(
    managedGateway.completionMarker,
    'policy-and-final-counters-attested',
  );
  assert.equal(manifest.complete, true);

  const tamperedRoot = tempDir(t);
  const tamperedShared = path.join(tamperedRoot, 'egress', 'evidence');
  fs.mkdirSync(tamperedShared, { recursive: true });
  const tamperedCounter = {
    ...counter,
    runId: 'snapshot-tampered',
    deniedCount: 1,
  };
  writeJsonl(
    path.join(tamperedShared, 'managed-gateway-counters.ndjson'),
    [tamperedCounter],
  );
  const tamperedRun = makeRun(tamperedRoot, {
    runId: 'snapshot-tampered',
    acknowledgement: {
      ...gatewayAttestation('snapshot-tampered'),
      policyHash,
    },
  });
  tamperedRun.egress.policyHash = policyHash;
  tamperedRun.egress.finalSnapshot = {
    ...finalSnapshot,
    runId: 'snapshot-tampered',
  };
  const tampered = await finalizeRunEvidence(tamperedRun, {
    stateDir: tamperedRoot,
    requiredSources: ['managed_gateway'],
  });
  const tamperedGateway = sourceByName(
    tampered.manifest,
    'managed_gateway',
  );

  assert.equal(tamperedGateway.complete, false);
  assert.equal(
    tamperedGateway.completionMarker,
    'counter-snapshot-record-missing',
  );
  assert.equal(tampered.manifest.complete, false);
});

test('required evidence sources change by security mode', async (t) => {
  const root = tempDir(t);
  const { finalizeRunEvidence } = await importModule(
    'lib/guardd/evidence-finalizer.js',
  );
  const expected = {
    learn: [
      'ig-dns',
      'ig-syscalls',
      'managed_dns',
      'managed_gateway',
      'nosh-l4',
      'tetragon-events',
    ],
    audit: [
      'ig-dns',
      'ig-syscalls',
      'managed_dns',
      'managed_gateway',
      'nosh-l4',
      'tetragon-events',
    ],
    enforce: [
      'managed_dns',
      'managed_gateway',
      'nosh-l4',
      'tetragon-events',
    ],
    'egress-learn': [
      'nosh-egress',
    ],
    'egress-audit': [
      'nosh-egress',
    ],
    'egress-enforce': [
      'nosh-egress',
    ],
  };

  for (const mode of [
    'learn',
    'audit',
    'enforce',
    'egress-learn',
    'egress-audit',
    'egress-enforce',
  ]) {
    const scoped = mode.startsWith('egress-');
    const workspaceIdentity = scoped
      ? { dev: '123', ino: '456' }
      : null;
    const run = makeRun(root, {
      runId: `required-${mode}`,
      mode,
      ...(scoped
        ? { workdir: root, workspaceIdentity }
        : {}),
    });
    const { manifest } = await finalizeRunEvidence(run, { stateDir: root });
    assert.deepEqual(
      manifest.sources
        .filter((source) => source.required)
        .map((source) => source.name),
      expected[mode],
    );
    assert.equal(manifest.complete, false);
    assert.deepEqual(
      manifest.subject.workspaceIdentity,
      workspaceIdentity,
    );
    assert.equal(
      manifest.trainingEligible,
      !['enforce', 'egress-audit', 'egress-enforce'].includes(mode),
    );
    assert.equal(
      manifest.evidenceUse,
      ['enforce', 'egress-audit', 'egress-enforce'].includes(mode)
        ? 'diagnostic-only'
        : 'training',
    );
    if (['egress-audit', 'egress-enforce'].includes(mode)) {
      assert.deepEqual(manifest.egressEvaluation, {
        schemaVersion: 1,
        policyHash: null,
        wouldDenyCount: 0,
        deniedCount: 0,
        dnsWouldDenyCount: 0,
        dnsDeniedCount: 0,
        dnsEvaluationComplete: false,
        dnsEvaluationError: 'required nosh-egress evidence is incomplete',
        complete: false,
        backend: 'nosh-egress',
      });
    }
  }
});

test('malformed JSONL marks required evidence incomplete', async (t) => {
  const { manifest } = await finalizeEnforceEvidence(t, {
    tetragonRaw:
      '{"schemaVersion":1,"recordKind":"event","type":"process_exec"}\n' +
      'not-json\n',
  });
  const tetragon = sourceByName(manifest, 'tetragon-events');

  assert.equal(tetragon.present, true);
  assert.equal(tetragon.records, 1);
  assert.equal(tetragon.parseErrors, 1);
  assert.equal(tetragon.complete, false);
  assert.equal(manifest.complete, false);
});

test('reported collector loss marks final stats and the manifest incomplete', async (t) => {
  const { manifest } = await finalizeEnforceEvidence(t, {
    noshL4Records: [
      {
        schemaVersion: 1,
        recordKind: 'stats',
        final: true,
        decoderErrors: '1',
        counters: {
          ringbufDrops: '2',
          parseErrors: '3',
          unsupportedProtocol: '0',
          flowMapFull: '0',
          configMissing: '0',
        },
      },
    ],
  });
  const noshL4 = sourceByName(manifest, 'nosh-l4');

  assert.equal(noshL4.lostEvents, 6);
  assert.equal(noshL4.completionMarker, 'final-stats-reported-loss');
  assert.equal(noshL4.complete, false);
  assert.equal(manifest.complete, false);
});

test('nosh-l4 evidence without final stats is incomplete', async (t) => {
  const { manifest } = await finalizeEnforceEvidence(t, {
    noshL4Records: [
      {
        schemaVersion: 1,
        recordKind: 'event',
        eventKind: 'attempt',
      },
      {
        schemaVersion: 1,
        recordKind: 'stats',
        final: false,
        decoderErrors: '0',
        counters: {
          ringbufDrops: '0',
          parseErrors: '0',
          unsupportedProtocol: '0',
          flowMapFull: '0',
          configMissing: '0',
        },
      },
    ],
  });
  const noshL4 = sourceByName(manifest, 'nosh-l4');

  assert.equal(noshL4.lostEvents, 0);
  assert.equal(noshL4.completionMarker, 'missing-final-stats');
  assert.equal(noshL4.complete, false);
  assert.equal(manifest.complete, false);
});
