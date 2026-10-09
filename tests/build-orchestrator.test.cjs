'use strict';

const assert = require('node:assert/strict');
const { EventEmitter } = require('node:events');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { PassThrough } = require('node:stream');
const test = require('node:test');
const { pathToFileURL } = require('node:url');

const appRoot = path.resolve(__dirname, '..');

async function orchestratorModule() {
  return import(
    pathToFileURL(path.join(appRoot, 'lib/guardd/build-orchestrator.js')).href
  );
}

async function httpEvidenceModule() {
  return import(
    pathToFileURL(path.join(appRoot, 'lib/guardd/http-evidence.js')).href
  );
}

async function httpContentStoreModule() {
  return import(
    pathToFileURL(path.join(appRoot, 'lib/guardd/http-content-store.js')).href
  );
}

async function httpCaptureManagerModule() {
  return import(
    pathToFileURL(path.join(appRoot, 'lib/guardd/http-capture-manager.js')).href
  );
}

function buildContext(t) {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'nosh-build-orchestrator-'));
  fs.writeFileSync(
    path.join(directory, 'Dockerfile'),
    'FROM scratch\nLABEL purpose="default"\n',
    { mode: 0o600 },
  );
  fs.writeFileSync(
    path.join(directory, 'Dockerfile.ci'),
    'FROM scratch\nLABEL purpose="ci"\n',
    { mode: 0o600 },
  );
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  return directory;
}

function flowSummaryAdapter() {
  return {
    name: 'nosh-l4',
    required: true,
    longRunning: true,
    command: [
      '/usr/local/libexec/nosh-guard/nosh-l4-loader',
      'run',
      '--cgroup',
      '/sys/fs/cgroup/fake',
      '--cgroup-id',
      '900',
      '--output-mode',
      'flow-summary',
    ],
    readiness: {
      schemaVersion: 1,
      recordKind: 'status',
      status: 'ready',
      outputMode: 'flow-summary',
    },
    completion: {
      match: {
        recordKind: 'stats',
        final: true,
        outputMode: 'flow-summary',
      },
    },
  };
}

test('build invocation resolves one context and redacts secret-bearing arguments', async (t) => {
  const context = buildContext(t);
  const { resolveBuildInvocation } = await orchestratorModule();
  const invocation = await resolveBuildInvocation({
    context,
    variant: 'ci',
    architecture: 'x64',
    tag: ['example:test'],
    buildArg: ['TOKEN=super-secret', 'PUBLIC_VALUE=visible'],
    passthrough: [
      '--secret',
      'id=npmrc,src=/private/npmrc',
      '--ssh=default=/private/agent.sock',
      '--build-arg=SECOND_SECRET=also-secret',
      '--label',
      'org.example.test=yes',
    ],
  });

  assert.equal(invocation.context, fs.realpathSync(context));
  assert.equal(invocation.platform, 'linux/amd64');
  assert.equal(invocation.dockerfile.path, fs.realpathSync(path.join(context, 'Dockerfile.ci')));
  assert.match(invocation.dockerfile.sha256, /^sha256:[a-f0-9]{64}$/);
  assert.deepEqual(invocation.sanitized.buildArgNames, ['TOKEN', 'PUBLIC_VALUE']);
  assert.deepEqual(invocation.sanitized.passthrough, [
    '--secret=id=npmrc,<redacted>',
    '--ssh=<redacted>',
    '--build-arg=SECOND_SECRET=<redacted>',
    '--label',
    'org.example.test=yes',
  ]);
  assert.doesNotMatch(
    JSON.stringify(invocation.sanitized),
    /super-secret|also-secret|\/private\/npmrc|\/private\/agent/,
  );
});

test('build invocation rejects identity-changing and unsafe Buildx passthrough', async (t) => {
  const context = buildContext(t);
  const { resolveBuildInvocation } = await orchestratorModule();

  await assert.rejects(
    resolveBuildInvocation({ context, platform: 'linux/amd64,linux/arm64' }),
    /exactly one platform/,
  );
  await assert.rejects(
    resolveBuildInvocation({ context, passthrough: ['--builder', 'other'] }),
    /--builder is owned by nosh build/,
  );
  await assert.rejects(
    resolveBuildInvocation({ context, passthrough: ['-fOtherfile'] }),
    /-fOtherfile is owned by nosh build/,
  );
  await assert.rejects(
    resolveBuildInvocation({ context, passthrough: ['-texample:other'] }),
    /-texample:other is owned by nosh build/,
  );
  await assert.rejects(
    resolveBuildInvocation({ context, passthrough: ['-qfOtherfile'] }),
    /owned by nosh build/,
  );
  await assert.rejects(
    resolveBuildInvocation({ context, passthrough: ['-qtother:tag'] }),
    /owned by nosh build/,
  );
  for (const argument of [
    '--pull=false',
    '--no-cache=false',
    '--call=check',
    '--check',
    '--output=type=registry',
    '-otype=registry',
    '--push',
    '--load',
  ]) {
    await assert.rejects(
      resolveBuildInvocation({ context, passthrough: [argument] }),
      /owned by nosh build/,
    );
  }
  await assert.rejects(
    resolveBuildInvocation({ context, passthrough: ['--network=host'] }),
    /host networking.*unsupported/,
  );
  await assert.rejects(
    resolveBuildInvocation({
      context,
      forceClean: true,
      passthrough: ['--cache-from=type=local,src=/tmp/cache'],
    }),
    /rejects cache imports/,
  );
  await assert.rejects(
    resolveBuildInvocation({ context, file: 'Dockerfile', variant: 'ci' }),
    /mutually exclusive/,
  );
  await assert.rejects(
    resolveBuildInvocation({ context, push: true, output: ['type=oci,dest=image.tar'] }),
    /--push and --output are mutually exclusive/,
  );
});

test('Buildx command ownership preserves clean cold and normal warm output semantics', async () => {
  const { buildOrchestratorInternals } = await orchestratorModule();
  const invocation = {
    context: '/workspace/project',
    platform: 'linux/amd64',
    dockerfile: { path: '/workspace/project/Dockerfile' },
    tags: ['example:test'],
    target: 'release',
    buildArgs: ['PUBLIC=one'],
    push: false,
    outputs: [],
    noLoad: false,
    hasOutput: false,
    passthrough: ['--label', 'org.example.test=yes'],
  };
  const builder = { builderName: 'nosh-build-test' };

  const cold = buildOrchestratorInternals.buildCommand(
    invocation,
    builder,
    'cold',
    { passDir: '/profiles/cold', compare: true, forceClean: true },
  );
  assert.deepEqual(cold.args.slice(0, 10), [
    'buildx',
    'build',
    '--builder',
    'nosh-build-test',
    '--progress',
    'rawjson',
    '--metadata-file',
    '/profiles/cold/buildx-metadata.json',
    '--platform',
    'linux/amd64',
  ]);
  assert.ok(cold.args.includes('--pull'));
  assert.ok(cold.args.includes('--no-cache'));
  assert.deepEqual(
    cold.args.slice(cold.args.indexOf('--output'), cold.args.indexOf('--output') + 2),
    ['--output', 'type=cacheonly'],
  );
  assert.equal(cold.args.includes('--load'), false);
  assert.equal(cold.args.at(-1), '/workspace/project');

  const warm = buildOrchestratorInternals.buildCommand(
    invocation,
    builder,
    'warm',
    { passDir: '/profiles/warm', compare: true, forceClean: false },
  );
  assert.equal(warm.args.includes('--pull'), false);
  assert.equal(warm.args.includes('--no-cache'), false);
  assert.ok(warm.args.includes('--load'));

  const managedHttp = buildOrchestratorInternals.buildCommand(
    invocation,
    builder,
    'cold',
    {
      passDir: '/profiles/http',
      compare: false,
      forceClean: true,
      httpBuild: {
        buildArgs: [
          'HTTP_PROXY=http://nosh-http-proxy:8080',
          'HTTPS_PROXY=http://nosh-http-proxy:8080',
          'NOSH_HTTP_CAPTURE=1',
        ],
        secret: {
          id: 'nosh-http-ca',
          source: '/profiles/http/mitmproxy-ca-cert.pem',
        },
      },
    },
  );
  for (const value of [
    'HTTP_PROXY=http://nosh-http-proxy:8080',
    'HTTPS_PROXY=http://nosh-http-proxy:8080',
    'NOSH_HTTP_CAPTURE=1',
  ]) {
    const index = managedHttp.args.indexOf(value);
    assert.ok(index > 0);
    assert.equal(managedHttp.args[index - 1], '--build-arg');
  }
  const secretIndex = managedHttp.args.indexOf('--secret');
  assert.deepEqual(managedHttp.args.slice(secretIndex, secretIndex + 2), [
    '--secret',
    'id=nosh-http-ca,src=/profiles/http/mitmproxy-ca-cert.pem',
  ]);
  assert.throws(
    () => buildOrchestratorInternals.buildCommand(
      invocation,
      builder,
      'cold',
      {
        passDir: '/profiles/http-invalid',
        httpBuild: {
          buildArgs: ['UNREVIEWED_PROXY=value'],
          secret: { id: 'nosh-http-ca', source: '/profiles/http/ca.pem' },
        },
      },
    ),
    /managed HTTP build argument is invalid/,
  );
});

test('builder topology rejects unprofiled extra nodes', async () => {
  const { buildOrchestratorInternals } = await orchestratorModule();
  const names = { builderName: 'nosh-build-test', builderNode: 'nosh-build-test0' };
  assert.doesNotThrow(() => buildOrchestratorInternals.assertSingleBuilderNode(
    'Name: nosh-build-test\nDriver: docker-container\nNodes:\nName: nosh-build-test0\n',
    names,
  ));
  assert.throws(
    () => buildOrchestratorInternals.assertSingleBuilderNode(
      'Name: nosh-build-test\nDriver: docker-container\nNodes:\nName: nosh-build-test0\nName: nosh-build-test1\n',
      names,
    ),
    /exactly the profiled node/,
  );
});

test('managed capture binds the BuildKit driver to its exact bridge', async () => {
  const { buildOrchestratorInternals } = await orchestratorModule();
  const names = { builderName: 'nosh-build-test', builderNode: 'nosh-build-test0' };
  const image = `moby/buildkit:test@sha256:${'a'.repeat(64)}`;
  const networkName = 'nosh-http-net-fixture';
  const calls = [];
  const spawnSyncImpl = (command, args) => {
    assert.equal(command, 'docker');
    calls.push([...args]);
    if (args[0] === 'buildx' && args[1] === 'inspect' && args[2] === names.builderName) {
      return { status: 1, stdout: '', stderr: 'not found' };
    }
    if (args[0] === 'buildx' && args[1] === 'inspect' && args[2] === '--bootstrap') {
      return {
        status: 0,
        stdout: `Name: ${names.builderName}\nDriver: docker-container\nNodes:\nName: ${names.builderNode}\n`,
        stderr: '',
      };
    }
    if (args[0] === 'inspect') {
      return {
        status: 0,
        stdout: JSON.stringify({
          Id: 'b'.repeat(64),
          HostConfig: { CgroupnsMode: 'private' },
          Config: { Image: image },
          NetworkSettings: { Networks: { [networkName]: {} } },
        }),
        stderr: '',
      };
    }
    return { status: 0, stdout: '', stderr: '' };
  };

  const builder = buildOrchestratorInternals.ensureBuilder(
    names,
    image,
    'cold',
    { spawnSyncImpl },
    { networkName },
  );
  assert.equal(builder.containerId, 'b'.repeat(64));
  const create = calls.find((args) => args[0] === 'buildx' && args[1] === 'create');
  assert.ok(create);
  assert.deepEqual(
    create.slice(create.indexOf(`image=${image}`) - 1),
    ['--driver-opt', `image=${image}`, '--driver-opt', `network=${networkName}`],
  );

  assert.throws(
    () => buildOrchestratorInternals.ensureBuilder(
      names,
      image,
      'cold',
      { spawnSyncImpl() { assert.fail('invalid network must fail before Docker'); } },
      { networkName: 'invalid/network' },
    ),
    /builder network name is invalid/,
  );
});

test('warm builders are stable per context while cold builders are invocation-scoped', async () => {
  const { buildOrchestratorInternals } = await orchestratorModule();
  const invocation = { context: '/workspace/project', platform: 'linux/amd64' };
  const endpoint = 'unix:///var/run/docker.sock';
  const warmOne = buildOrchestratorInternals.builderNames(
    invocation,
    'profile-one',
    'warm',
    endpoint,
    1000,
  );
  const warmTwo = buildOrchestratorInternals.builderNames(
    invocation,
    'profile-two',
    'warm',
    endpoint,
    1000,
  );
  const coldOne = buildOrchestratorInternals.builderNames(
    invocation,
    'profile-one',
    'cold',
    endpoint,
    1000,
  );
  const coldTwo = buildOrchestratorInternals.builderNames(
    invocation,
    'profile-two',
    'cold',
    endpoint,
    1000,
  );

  assert.equal(warmOne.builderName, warmTwo.builderName);
  assert.notEqual(coldOne.builderName, coldTwo.builderName);
  for (const selected of [warmOne, coldOne, coldTwo]) {
    assert.match(selected.builderName, /^nosh-build-[a-f0-9]{20}$/);
    assert.equal(selected.builderNode, `${selected.builderName}0`);
    assert.ok(selected.builderNode.length <= 49);
  }
});

test('Buildx history references are bound to the selected builder node', async () => {
  const { buildOrchestratorInternals } = await orchestratorModule();
  const builder = {
    builderName: 'nosh-build-0123456789abcdef0123',
    builderNode: 'nosh-build-0123456789abcdef01230',
  };
  const buildId = '0fjb6ubs52xx3vygf6fgdl611';

  assert.equal(
    buildOrchestratorInternals.buildHistoryId(builder, {
      'buildx.build.ref': `${builder.builderName}/${builder.builderNode}/${buildId}`,
    }),
    buildId,
  );
  assert.equal(buildOrchestratorInternals.buildHistoryId(builder, {}), null);
  for (const buildRef of [
    `other-builder/${builder.builderNode}/${buildId}`,
    `${builder.builderName}/other-node/${buildId}`,
    `${builder.builderName}/${builder.builderNode}/${buildId}/extra`,
    `${builder.builderName}/${builder.builderNode}/INVALID`,
  ]) {
    assert.throws(
      () => buildOrchestratorInternals.buildHistoryId(builder, {
        'buildx.build.ref': buildRef,
      }),
      /build metadata reference/,
    );
  }

  const reason = buildOrchestratorInternals.buildHistoryFailureReason(
    `\u001b[31mno record\u001b[0m\n${'x'.repeat(600)}`,
  );
  assert.equal(reason.includes('\u001b'), false);
  assert.equal(reason.includes('\n'), false);
  assert.equal(reason.length, 512);
  assert.match(reason, /^no record x+\.\.\.$/);
});

test('build preflight requires local Linux cgroup-v2 Docker and Buildx', async () => {
  const { buildOrchestratorInternals } = await orchestratorModule();
  const calls = [];
  const healthy = buildOrchestratorInternals.dockerInfo({
    spawnSyncImpl(command, args) {
      calls.push([command, args]);
      if (args[0] === 'context') {
        return {
          status: 0,
          stdout: '"unix:///var/run/docker.sock"\n',
          stderr: '',
        };
      }
      if (args[0] === 'info') {
        return {
          status: 0,
          stdout: JSON.stringify({
            OSType: 'linux',
            CgroupVersion: '2',
            SecurityOptions: [
              'name=seccomp,profile=builtin',
              'name=cgroupns',
            ],
          }),
          stderr: '',
        };
      }
      assert.ok(
        (args[0] === 'buildx' && args[1] === 'version')
        || (args[0] === 'buildx' && args[1] === 'history' && args[2] === '--help'),
      );
      return { status: 0, stdout: 'github.com/docker/buildx v0.test\n', stderr: '' };
    },
  });
  assert.equal(healthy.endpoint, 'unix:///var/run/docker.sock');
  assert.equal(calls.length, 4);

  assert.throws(
    () => buildOrchestratorInternals.dockerInfo({
      spawnSyncImpl(command, args) {
        assert.equal(args[0], 'context');
        return { status: 0, stdout: '"tcp://docker.example:2376"', stderr: '' };
      },
    }),
    /local Unix-socket Docker context/,
  );
  assert.throws(
    () => buildOrchestratorInternals.dockerInfo({
      spawnSyncImpl(command, args) {
        if (args[0] === 'context') {
          return { status: 0, stdout: '"unix:///run/user/1000/docker.sock"', stderr: '' };
        }
        return {
          status: 0,
          stdout: JSON.stringify({
            OSType: 'linux',
            CgroupVersion: '2',
            SecurityOptions: ['name=rootless'],
          }),
          stderr: '',
        };
      },
    }),
    /rootless Docker is not supported/,
  );

  const noPrivateCgroupNamespaceCalls = [];
  assert.throws(
    () => buildOrchestratorInternals.dockerInfo({
      spawnSyncImpl(command, args) {
        noPrivateCgroupNamespaceCalls.push([command, args]);
        if (args[0] === 'context') {
          return { status: 0, stdout: '"unix:///var/run/docker.sock"', stderr: '' };
        }
        if (args[0] === 'info') {
          return {
            status: 0,
            stdout: JSON.stringify({
              OSType: 'linux',
              CgroupVersion: '2',
              SecurityOptions: ['name=seccomp,profile=builtin'],
            }),
            stderr: '',
          };
        }
        assert.fail('Buildx must not run before the cgroup namespace preflight passes');
      },
    }),
    /private cgroup namespaces enabled by default/,
  );
  assert.equal(noPrivateCgroupNamespaceCalls.length, 2);
});

test('dry-run profiles need no Docker daemon and network learning is always cold', async (t) => {
  const context = buildContext(t);
  const { executeBuildProfile } = await orchestratorModule();

  const profile = await executeBuildProfile({
    context,
    platform: 'linux/amd64',
    dryRun: true,
    cacheMode: 'compare',
    buildArg: ['TOKEN=secret-value'],
  });
  assert.equal(profile.dryRun, true);
  assert.equal(profile.mode, 'build-profile');
  assert.equal(profile.cacheMode, 'compare');
  assert.deepEqual(profile.invocation.buildArgNames, ['TOKEN']);
  assert.doesNotMatch(JSON.stringify(profile), /secret-value/);

  const policy = await executeBuildProfile({
    context,
    platform: 'linux/amd64',
    dryRun: true,
    depth: 'policy',
  });
  assert.equal(policy.depth, 'policy');

  const network = await executeBuildProfile({
    context,
    mode: 'build-net-learn',
    platform: 'linux/amd64',
    cacheMode: 'warm',
    dryRun: true,
  });
  assert.equal(network.mode, 'build-net-learn');
  assert.equal(network.cacheMode, 'cold');
  assert.equal(network.httpCapture, 'none');

  const capturedNetwork = await executeBuildProfile({
    context,
    mode: 'build-net-learn',
    platform: 'linux/amd64',
    httpCapture: 'mitmproxy',
    dryRun: true,
  });
  assert.equal(capturedNetwork.mode, 'build-net-learn');
  assert.equal(capturedNetwork.httpCapture, 'mitmproxy');

  await assert.rejects(
    executeBuildProfile({ context, dryRun: true, depth: 'maximal' }),
    /--depth must be balanced, policy, or deep/,
  );
  await assert.rejects(
    executeBuildProfile({
      context,
      mode: 'build-net-learn',
      dryRun: true,
      httpCapture: 'burp',
    }),
    /--http-capture must be none or mitmproxy/,
  );
  await assert.rejects(
    executeBuildProfile({
      context,
      mode: 'build-profile',
      dryRun: true,
      httpCapture: 'mitmproxy',
    }),
    /--http-capture is supported only by build net learn/,
  );

  for (const [ownedInput, message] of [
    [{ buildArg: ['HTTP_PROXY=http://unreviewed-proxy:8080'] }, /owns the HTTP_PROXY build argument/],
    [{ buildArg: ['ALL_PROXY=socks5://unreviewed-proxy:1080'] }, /owns the ALL_PROXY build argument/],
    [{ passthrough: ['--build-arg=HTTPS_PROXY=http://unreviewed-proxy:8080'] }, /owns the HTTPS_PROXY build argument/],
    [{ passthrough: ['--build-arg', 'no_proxy=localhost'] }, /owns the no_proxy build argument/],
    [{ passthrough: ['--secret=id=nosh-http-ca,src=/tmp/unreviewed-ca'] }, /owns the nosh-http-ca BuildKit secret/],
    [{ passthrough: ['--network=unreviewed-network'] }, /owns the BuildKit network/],
  ]) {
    await assert.rejects(
      executeBuildProfile({
        context,
        mode: 'build-net-learn',
        dryRun: true,
        httpCapture: 'mitmproxy',
        ...ownedInput,
      }),
      message,
    );
  }
});

test('build network summary correlates optional sanitized URL evidence through DNS to L4', async (t) => {
  const { buildOrchestratorInternals } = await orchestratorModule();
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'nosh-build-url-summary-'));
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  const writeJsonl = (name, records) => {
    const file = path.join(directory, name);
    fs.writeFileSync(file, `${records.map((record) => JSON.stringify(record)).join('\n')}\n`);
    return file;
  };
  const progressPath = writeJsonl('progress.jsonl', []);
  const correlation = {
    keyVersion: 1,
    id: 'udp53:77:4660:53000:10.0.0.53:53',
    complete: true,
    socketCookie: '77',
    transactionId: 4660,
    clientPort: 53000,
    serverAddress: '10.0.0.53',
    serverPort: 53,
  };
  const unixNs = (offset) => (1_700_000_000_000_000_000n + BigInt(offset)).toString();
  const monotonicNs = (offset) => (5_000_000_000n + BigInt(offset)).toString();
  const buildRecords = [
    {
      schemaVersion: 2,
      recordKind: 'event',
      metadataOnly: true,
      eventKind: 'dns-query',
      timestampNs: unixNs(100),
      network: {
        protocol: 'udp',
        direction: 'query',
        serverAddress: '10.0.0.53',
        serverPort: 53,
        clientPort: 53000,
      },
      dns: {
        transport: 'udp',
        qname: 'repo.example.',
        queryType: 1,
        queryClass: 1,
        correlation,
      },
    },
    {
      schemaVersion: 2,
      recordKind: 'event',
      metadataOnly: true,
      eventKind: 'dns-response',
      timestampNs: unixNs(200),
      network: {
        protocol: 'udp',
        direction: 'response',
        serverAddress: '10.0.0.53',
        serverPort: 53,
        clientPort: 53000,
      },
      dns: {
        transport: 'udp',
        qname: 'repo.example.',
        queryType: 1,
        queryClass: 1,
        correlation,
        response: {
          responseCode: 0,
          truncated: false,
          parseComplete: true,
          answerLimitReached: false,
          answersDeclared: 1,
          answersCaptured: 1,
          answers: [{
            index: 0,
            ownerName: 'repo.example.',
            type: 1,
            class: 1,
            ttl: 60,
            data: { kind: 'ipv4', address: '198.51.100.7' },
          }],
        },
      },
    },
    {
      schemaVersion: 2,
      recordKind: 'stats',
      final: true,
      timestampUnixNs: unixNs(300),
      inflightSyscalls: '0',
      fileSummaryRecords: '0',
      counters: {
        dnsParseErrors: '0',
        dnsCompressedNames: '0',
        dnsTruncatedNames: '0',
        dnsTruncatedResponses: '0',
        dnsAnswerLimitReached: '0',
        dnsUnsupportedAnswers: '0',
        dnsCorrelationMissing: '0',
        dnsQueryObservations: '1',
        dnsResponseObservations: '1',
        dnsNamePointers: '0',
        fileMapFull: '0',
        filePathErrors: '0',
        fileOpenObservations: '0',
      },
    },
  ];
  writeJsonl('nosh-build.jsonl', buildRecords);
  const l4Records = [{
    eventKind: 'attempt',
    timestampNs: unixNs(100),
    socketCookie: '77',
    process: { pid: 42, comm: 'git-remote-http' },
    network: {
      direction: 'egress',
      protocol: 'udp',
      destinationAddress: '10.0.0.53',
      destinationPort: 53,
    },
  }, {
    eventKind: 'attempt',
    timestampNs: unixNs(250),
    socketCookie: '88',
    process: { pid: 42, comm: 'git-remote-http' },
    network: {
      direction: 'egress',
      protocol: 'tcp',
      destinationAddress: '198.51.100.7',
      destinationPort: 443,
    },
  }, {
    eventKind: 'attempt',
    timestampNs: unixNs(260),
    socketCookie: '99',
    process: { pid: 42, comm: 'git-remote-http' },
    network: {
      direction: 'egress',
      protocol: 'tcp',
      destinationAddress: '192.168.1.65',
      destinationPort: 9001,
    },
  }, {
    eventKind: 'attempt',
    timestampNs: unixNs(270),
    socketCookie: '100',
    process: { pid: 42, comm: 'git-remote-http' },
    network: {
      direction: 'egress',
      protocol: 'tcp',
      destinationAddress: '2001:db8::1',
      destinationPort: 9443,
    },
  }];
  writeJsonl('nosh-l4.jsonl', l4Records);
  const urlObservation = {
    schemaVersion: 1,
    recordKind: 'url-observation',
    timestampUnixNs: unixNs(50),
    timestampMonotonicNs: monotonicNs(50),
    targetCgroupId: '900',
    cgroupId: '901',
    pid: 42,
    tid: 42,
    process: 'git-remote-http',
    provider: 'libcurl',
    source: 'libcurl:CURLOPT_URL',
    scheme: 'https',
    host: 'repo.example',
    port: 443,
    path: '/private/repository.git/info/refs',
    pathTruncated: false,
    observationOnly: true,
  };
  const directUrlObservation = {
    ...urlObservation,
    timestampUnixNs: unixNs(55),
    timestampMonotonicNs: monotonicNs(55),
    host: '192.168.1.65',
    port: 9001,
    path: '/collection-canary',
  };
  const directIpv6UrlObservation = {
    ...urlObservation,
    timestampUnixNs: unixNs(56),
    timestampMonotonicNs: monotonicNs(56),
    host: '[2001:0db8::1]',
    port: 9443,
    path: '/ipv6-collection-canary',
  };
  const urlStats = {
    schemaVersion: 1,
    recordKind: 'stats',
    timestampUnixNs: unixNs(300),
    cgroupId: '900',
    provider: 'libcurl',
    providersAttached: ['libcurl'],
    final: true,
    observationOnly: true,
    coverageComplete: false,
    coverageLimitation: 'Dynamic uprobes miss calls before attachment and non-libcurl clients.',
    counters: {
      ...Object.fromEntries([
        'ringbufDrops',
        'configMissing',
        'cgroupFilterErrors',
        'readErrors',
        'discoveryScans',
        'processesInspected',
        'libraryMappingsSeen',
        'discoveryMisses',
        'sanitizerRejects',
        'pathTruncations',
        'decoderErrors',
        'outputLimitReached',
      ].map((name) => [name, '0'])),
      optionCalls: '3',
      rawObservations: '3',
      attachments: '1',
      observations: '3',
    },
  };
  const urlRecords = [
    urlObservation,
    directUrlObservation,
    directIpv6UrlObservation,
    urlStats,
  ];
  writeJsonl('nosh-url.jsonl', urlRecords);
  const cgroup = {
    'cpu.stat': 'usage_usec 1\nuser_usec 1\nsystem_usec 0\n',
    'cpu.pressure': 'some total=0\nfull total=0\n',
    'io.stat': '8:0 rbytes=0 wbytes=0\n',
    'io.pressure': 'some total=0\nfull total=0\n',
    'memory.current': '0\n',
    'memory.events': 'low 0\nhigh 0\nmax 0\noom 0\noom_kill 0\n',
    'memory.pressure': 'some total=0\nfull total=0\n',
    'pids.current': '1\n',
  };
  writeJsonl('cgroup-before.json', [cgroup]);
  writeJsonl('cgroup-after.json', [cgroup]);
  const fileSource = (name, complete = true) => ({
    name,
    complete,
    file: { path: name },
  });
  const passEvidence = [{
    pass: 'cold',
    progressPath,
    evidenceDir: directory,
    manifest: {
      builder: { cgroup: { id: '900' } },
      sources: [
        fileSource('nosh-build.jsonl'),
        fileSource('nosh-l4.jsonl'),
        fileSource('nosh-url.jsonl'),
        fileSource('cgroup-before.json'),
        fileSource('cgroup-after.json'),
      ].map((source) => ({
        ...source,
        name: source.name.replace(/\.jsonl$/, ''),
      })),
    },
  }];
  const summary = await buildOrchestratorInternals.summarizeBuildPasses(passEvidence);

  assert.equal(summary.incompleteReasons.length, 0);
  assert.equal(summary.observations.network.resources.length, 3);
  assert.equal(summary.observations.network.resources[0].pathTruncated, false);
  assert.equal(summary.observations.network.resources[0].targetCgroupId, '900');
  assert.equal(summary.observations.network.resources[0].cgroupId, '901');
  assert.ok(summary.observations.network.resources.every((resource) => (
    resource.id.startsWith('url:sha256:')
  )));
  assert.equal(
    summary.observations.network.dns.snapshots[0].correlationComplete,
    true,
  );
  assert.equal(
    summary.observations.network.dns.snapshots[0].queryTimestampNs,
    unixNs(100),
  );
  assert.equal(summary.observations.network.dns.snapshots[0].clientPort, 53000);
  const dnsQuery = summary.observations.network.dns.queries[0];
  const dnsSnapshot = summary.observations.network.dns.snapshots[0];
  const dnsAnswer = summary.observations.network.dns.answers[0];
  assert.notEqual(dnsSnapshot.id, dnsQuery.id);
  assert.equal(dnsSnapshot.queryId, dnsQuery.id);
  assert.equal(dnsAnswer.snapshotId, dnsSnapshot.id);
  assert.equal(dnsAnswer.queryId, dnsQuery.id);
  const dnsDestinationCorrelation = summary.observations.network.correlations.find(
    (entry) => entry.kind === 'dns-destination',
  );
  assert.equal(dnsDestinationCorrelation.snapshotId, dnsSnapshot.id);
  assert.equal(dnsDestinationCorrelation.queryId, dnsQuery.id);
  const dnsProcessCorrelation = summary.observations.network.correlations.find(
    (entry) => entry.kind === 'dns-query-process',
  );
  assert.equal(dnsProcessCorrelation.clientPort, 53000);
  assert.equal(dnsProcessCorrelation.attemptTimestampNs, unixNs(100));
  assert.equal(
    dnsProcessCorrelation.correlationConfidence,
    'heuristic-socket-resolver-bounded-time',
  );
  assert.equal(summary.observations.network.coverage.url.enabled, true);
  assert.equal(summary.observations.network.coverage.url.complete, false);
  assert.deepEqual(summary.observations.network.coverage.url.providers, ['libcurl']);
  assert.match(
    summary.observations.network.coverage.url.limitations.join('\n'),
    /Dynamic uprobes/,
  );
  assert.deepEqual(
    summary.observations.network.correlations
      .map((entry) => entry.kind)
      .filter((kind) => kind.startsWith('resource-'))
      .sort(),
    [
      'resource-destination',
      'resource-direct-destination',
      'resource-direct-destination',
      'resource-dns-query',
    ],
  );
  const directCorrelation = summary.observations.network.correlations.find(
    (entry) => entry.kind === 'resource-direct-destination'
      && entry.port === 9001,
  );
  assert.equal(directCorrelation.host, '192.168.1.65');
  assert.equal(directCorrelation.address, '192.168.1.65');
  assert.equal(directCorrelation.port, 9001);
  assert.equal(directCorrelation.queryId, undefined);
  assert.match(directCorrelation.correlationConfidence, /^heuristic-/);
  const directIpv6Resource = summary.observations.network.resources.find(
    (entry) => entry.port === 9443,
  );
  assert.equal(directIpv6Resource.host, '[2001:db8::1]');
  const directIpv6Correlation = summary.observations.network.correlations.find(
    (entry) => entry.kind === 'resource-direct-destination'
      && entry.port === 9443,
  );
  assert.equal(directIpv6Correlation.host, '[2001:db8::1]');
  assert.equal(directIpv6Correlation.address, '2001:db8::1');
  assert.equal(summary.metrics.network.urlObservations, 3);
  assert.equal(summary.metrics.network.urlCorrelations, 4);

  const resourceBeforePathChange = summary.observations.network.resources.find(
    (entry) => entry.host === 'repo.example',
  );
  writeJsonl('nosh-url.jsonl', [
    { ...urlObservation, path: '/different/private/path' },
    directUrlObservation,
    directIpv6UrlObservation,
    urlStats,
  ]);
  const changedPath = await buildOrchestratorInternals.summarizeBuildPasses(
    passEvidence,
  );
  assert.equal(
    changedPath.observations.network.resources.find(
      (entry) => entry.host === 'repo.example',
    ).id,
    resourceBeforePathChange.id,
  );

  writeJsonl('nosh-url.jsonl', [
    { ...urlObservation, targetCgroupId: '999' },
    directUrlObservation,
    directIpv6UrlObservation,
    urlStats,
  ]);
  const wrongCgroup = await buildOrchestratorInternals.summarizeBuildPasses(passEvidence);
  assert.equal(wrongCgroup.observations.network.resources.length, 0);
  assert.match(
    wrongCgroup.observations.network.coverage.url.limitations.join('\n'),
    /local parse or contract failures/,
  );

  writeJsonl('nosh-url.jsonl', [
    urlObservation,
    directUrlObservation,
    directIpv6UrlObservation,
    { ...urlStats, counters: { ...urlStats.counters, observations: '2' } },
  ]);
  const impossibleCounts = await buildOrchestratorInternals.summarizeBuildPasses(
    passEvidence,
  );
  assert.equal(impossibleCounts.observations.network.resources.length, 0);
  assert.match(
    impossibleCounts.observations.network.coverage.url.limitations.join('\n'),
    /declares 2 emitted observations but contains 3/,
  );

  writeJsonl('nosh-url.jsonl', urlRecords);
  const incompleteDnsRecords = buildRecords.map((record) => {
    if (['dns-query', 'dns-response'].includes(record.eventKind)) {
      return {
        ...record,
        dns: {
          ...record.dns,
          correlation: {
            ...record.dns.correlation,
            id: 'udp53:0:4660:53000:10.0.0.53:53',
            complete: false,
            socketCookie: '0',
          },
        },
      };
    }
    if (record.recordKind === 'stats') {
      return {
        ...record,
        counters: { ...record.counters, dnsCorrelationMissing: '2' },
      };
    }
    return record;
  });
  writeJsonl('nosh-build.jsonl', incompleteDnsRecords);
  const incompleteDns = await buildOrchestratorInternals.summarizeBuildPasses(
    passEvidence,
  );
  assert.equal(
    incompleteDns.observations.network.dns.snapshots[0].correlationComplete,
    false,
  );
  assert.equal(
    incompleteDns.observations.network.correlations.some((entry) => [
      'dns-destination',
      'resource-destination',
      'resource-dns-query',
    ].includes(entry.kind)),
    false,
  );

  const lateDnsRecords = buildRecords.map((record) => (
    record.eventKind === 'dns-response'
      ? { ...record, timestampNs: unixNs(300) }
      : record
  ));
  writeJsonl('nosh-build.jsonl', lateDnsRecords);
  const lateDns = await buildOrchestratorInternals.summarizeBuildPasses(passEvidence);
  assert.equal(
    lateDns.observations.network.correlations.some(
      (entry) => entry.kind === 'dns-destination'
        || entry.kind === 'resource-destination',
    ),
    false,
  );
  assert.equal(
    lateDns.observations.network.correlations.some(
      (entry) => entry.kind === 'resource-dns-query',
    ),
    true,
  );

  const cnameDnsRecords = buildRecords.map((record) => {
    if (record.eventKind !== 'dns-response') return record;
    return {
      ...record,
      dns: {
        ...record.dns,
        response: {
          ...record.dns.response,
          answersDeclared: 2,
          answersCaptured: 2,
          answers: [{
            index: 0,
            ownerName: 'repo.example.',
            type: 5,
            class: 1,
            ttl: 1,
            data: { kind: 'cname', name: 'target.example.' },
          }, {
            index: 1,
            ownerName: 'target.example.',
            type: 1,
            class: 1,
            ttl: 300,
            data: { kind: 'ipv4', address: '198.51.100.7' },
          }],
        },
      },
    };
  });
  const afterCnameExpiry = l4Records.map((record) => (
    record.network.destinationAddress === '198.51.100.7'
      ? { ...record, timestampNs: unixNs(1_000_000_201) }
      : record
  ));
  writeJsonl('nosh-build.jsonl', cnameDnsRecords);
  writeJsonl('nosh-l4.jsonl', afterCnameExpiry);
  const expiredCname = await buildOrchestratorInternals.summarizeBuildPasses(
    passEvidence,
  );
  assert.deepEqual(
    expiredCname.observations.network.dns.snapshots[0].cnameChain,
    ['repo.example', 'target.example'],
  );
  assert.equal(
    expiredCname.observations.network.dns.snapshots[0].addresses[0].ttl,
    300,
  );
  assert.equal(
    expiredCname.observations.network.correlations.some(
      (entry) => entry.kind === 'dns-destination'
        || entry.kind === 'resource-destination',
    ),
    false,
  );

  const nonterminalAddress = cnameDnsRecords.map((record) => {
    if (record.eventKind !== 'dns-response') return record;
    return {
      ...record,
      dns: {
        ...record.dns,
        response: {
          ...record.dns.response,
          answers: record.dns.response.answers.map((answer) => (
            answer.data.kind === 'ipv4'
              ? { ...answer, ownerName: 'repo.example.' }
              : answer
          )),
        },
      },
    };
  });
  writeJsonl('nosh-build.jsonl', nonterminalAddress);
  writeJsonl('nosh-l4.jsonl', l4Records);
  const addressAtCnameOwner =
    await buildOrchestratorInternals.summarizeBuildPasses(passEvidence);
  assert.equal(
    addressAtCnameOwner.observations.network.correlations.some(
      (entry) => entry.kind === 'dns-destination'
        || entry.kind === 'resource-destination',
    ),
    false,
  );

  const nonAddressQuery = buildRecords.map((record) => (
    ['dns-query', 'dns-response'].includes(record.eventKind)
      ? {
          ...record,
          dns: { ...record.dns, queryType: 16 },
        }
      : record
  ));
  writeJsonl('nosh-build.jsonl', nonAddressQuery);
  const addressFromTxtQuery =
    await buildOrchestratorInternals.summarizeBuildPasses(passEvidence);
  assert.equal(
    addressFromTxtQuery.observations.network.correlations.some(
      (entry) => entry.kind === 'dns-destination'
        || entry.kind === 'resource-destination',
    ),
    false,
  );

  writeJsonl(
    'nosh-build.jsonl',
    buildRecords.filter((record) => record.eventKind !== 'dns-query'),
  );
  const responseWithoutQuery = await buildOrchestratorInternals.summarizeBuildPasses(
    passEvidence,
  );
  assert.equal(
    responseWithoutQuery.observations.network.dns.snapshots[0].correlationComplete,
    false,
  );
  assert.equal(
    responseWithoutQuery.observations.network.dns.snapshots[0].queryId,
    null,
  );
  assert.equal(
    responseWithoutQuery.observations.network.dns.answers[0].queryId,
    null,
  );
  assert.equal(
    responseWithoutQuery.observations.network.correlations.some(
      (entry) => entry.kind === 'dns-destination'
        || entry.kind === 'resource-destination',
    ),
    false,
  );

  const responseBeforeQuery = buildRecords.map((record) => (
    record.eventKind === 'dns-response'
      ? { ...record, timestampNs: unixNs(99) }
      : record
  ));
  writeJsonl('nosh-build.jsonl', responseBeforeQuery);
  const nonchronologicalTransaction =
    await buildOrchestratorInternals.summarizeBuildPasses(passEvidence);
  assert.equal(
    nonchronologicalTransaction.observations.network.dns.snapshots[0]
      .correlationComplete,
    false,
  );

  const ambiguousCname = buildRecords.map((record) => {
    if (record.eventKind !== 'dns-response') return record;
    return {
      ...record,
      dns: {
        ...record.dns,
        response: {
          ...record.dns.response,
          answersDeclared: 3,
          answersCaptured: 3,
          answers: [{
            index: 0,
            ownerName: 'repo.example.',
            type: 5,
            class: 1,
            ttl: 60,
            data: { kind: 'cname', name: 'first.example.' },
          }, {
            index: 1,
            ownerName: 'repo.example.',
            type: 5,
            class: 1,
            ttl: 60,
            data: { kind: 'cname', name: 'second.example.' },
          }, {
            index: 2,
            ownerName: 'second.example.',
            type: 1,
            class: 1,
            ttl: 60,
            data: { kind: 'ipv4', address: '198.51.100.7' },
          }],
        },
      },
    };
  });
  writeJsonl('nosh-build.jsonl', ambiguousCname);
  const ambiguous = await buildOrchestratorInternals.summarizeBuildPasses(
    passEvidence,
  );
  assert.equal(
    ambiguous.observations.network.correlations.some(
      (entry) => entry.kind === 'dns-destination'
        || entry.kind === 'resource-destination',
    ),
    false,
  );

  const secondResponse = {
    ...buildRecords.find((record) => record.eventKind === 'dns-response'),
    timestampNs: unixNs(210),
    dns: {
      ...buildRecords.find((record) => record.eventKind === 'dns-response').dns,
      response: {
        ...buildRecords.find((record) => record.eventKind === 'dns-response').dns.response,
        answers: [{
          index: 0,
          ownerName: 'repo.example.',
          type: 1,
          class: 1,
          ttl: 30,
          data: { kind: 'ipv4', address: '198.51.100.8' },
        }],
      },
    },
  };
  const repeatedResponseRecords = [
    buildRecords.find((record) => record.eventKind === 'dns-query'),
    buildRecords.find((record) => record.eventKind === 'dns-response'),
    secondResponse,
    {
      ...buildRecords.find((record) => record.recordKind === 'stats'),
      counters: {
        ...buildRecords.find((record) => record.recordKind === 'stats').counters,
        dnsResponseObservations: '2',
      },
    },
  ];
  writeJsonl('nosh-build.jsonl', repeatedResponseRecords);
  const repeatedResponses = await buildOrchestratorInternals.summarizeBuildPasses(
    passEvidence,
  );
  assert.equal(repeatedResponses.observations.network.dns.snapshots.length, 2);
  assert.equal(
    new Set(repeatedResponses.observations.network.dns.snapshots.map(
      (snapshot) => snapshot.id,
    )).size,
    2,
  );
  assert.equal(
    new Set(repeatedResponses.observations.network.dns.snapshots.map(
      (snapshot) => snapshot.queryId,
    )).size,
    1,
  );
  for (const answer of repeatedResponses.observations.network.dns.answers) {
    const snapshot = repeatedResponses.observations.network.dns.snapshots.find(
      (entry) => entry.id === answer.snapshotId,
    );
    assert.ok(snapshot);
    assert.equal(answer.queryId, snapshot.queryId);
    assert.equal(snapshot.addresses[0].address, answer.value);
  }
});

test('streaming builds fail closed when BuildKit progress exceeds its byte cap', async (t) => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'nosh-build-progress-'));
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  const { buildOrchestratorInternals } = await orchestratorModule();
  const signals = [];
  const child = new EventEmitter();
  child.pid = 4242;
  child.stderr = new PassThrough();
  child.kill = (signal) => {
    signals.push(signal);
    setImmediate(() => {
      child.stderr.end();
      child.emit('close', null, signal);
    });
    return true;
  };
  setImmediate(() => child.stderr.write(Buffer.alloc(64, 0x78)));

  await assert.rejects(
    buildOrchestratorInternals.runStreamingBuild(
      ['buildx', 'build'],
      path.join(directory, 'progress.jsonl'),
      { progressMaxBytes: 32, spawnImpl: () => child },
    ),
    /BuildKit progress exceeded 32 bytes/,
  );
  assert.equal(signals[0], 'SIGTERM');
  assert.ok(fs.statSync(path.join(directory, 'progress.jsonl')).size <= 32);
});

test('streaming builds report BuildKit lifecycle through the injected progress sink', async (t) => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'nosh-build-progress-'));
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  const { buildOrchestratorInternals } = await orchestratorModule();
  const messages = [];
  const child = new EventEmitter();
  child.pid = 4242;
  child.stderr = new PassThrough();
  child.kill = () => true;
  const rawProgress = [
    JSON.stringify({
      vertexes: [{
        digest: 'sha256:copy',
        name: '[cold] COPY metadata-only',
      }, {
        digest: 'sha256:cold',
        name: '[cold] RUN build-step',
      }],
    }),
    JSON.stringify({
      vertexes: [{
        digest: 'sha256:cold',
        started: '2026-08-10T00:00:00.000Z',
      }],
    }),
    JSON.stringify({
      vertexes: [{
        digest: 'sha256:cold',
        completed: '2026-08-10T00:00:01.000Z',
      }],
    }),
  ].join('\n');
  setImmediate(() => {
    child.stderr.end(Buffer.from(rawProgress));
    child.emit('close', 0, null);
  });

  const progressPath = path.join(directory, 'progress.jsonl');
  const result = await buildOrchestratorInternals.runStreamingBuild(
    ['buildx', 'build'],
    progressPath,
    {
      spawnImpl: () => child,
      reportProgress(message) {
        messages.push(message);
      },
    },
  );

  assert.deepEqual(result, { status: 0, signal: null });
  assert.deepEqual(messages, [
    '[build] STARTED [cold] RUN build-step',
    '[build] DONE 1.0s [cold] RUN build-step',
  ]);
  assert.equal(fs.readFileSync(progressPath, 'utf8'), rawProgress);
});

test('BuildKit progress tracking distinguishes discovery from active work', async () => {
  const { buildOrchestratorInternals } = await orchestratorModule();
  const messages = [];
  const tracker = buildOrchestratorInternals.createBuildkitProgressTracker(
    (message) => messages.push(message),
    { now: () => Date.parse('2026-08-10T00:00:45.000Z') },
  );

  tracker.update({
    digest: 'sha256:copy',
    name: '[base 26/31] COPY --chown=user:user tmux.conf /home/user/.tmux.conf',
  });
  tracker.update({
    digest: 'sha256:build',
    name: '[base 28/31] RUN next build',
  });
  assert.deepEqual(messages, []);

  tracker.update({
    digest: 'sha256:build',
    started: '2026-08-10T00:00:00.000Z',
  });
  tracker.update({
    digest: 'sha256:build',
    name: '[base 28/31] RUN next build',
  });
  tracker.update({
    digest: 'sha256:build',
    started: '2026-08-10T00:00:00.000Z',
  });
  tracker.heartbeat();
  tracker.update({
    digest: 'sha256:copy',
    started: '2026-08-10T00:00:01.000Z',
    completed: '2026-08-10T00:00:01.000Z',
    cached: true,
  });
  tracker.update({
    digest: 'sha256:build',
    completed: '2026-08-10T00:01:00.000Z',
    cached: true,
    error: 'old generation failed',
  });
  tracker.update({
    digest: 'sha256:build',
    completed: '2026-08-10T00:01:00.000Z',
  });
  tracker.heartbeat();
  tracker.update({
    digest: 'sha256:build',
    started: '2026-08-10T00:02:00.000Z',
  });
  tracker.update({
    digest: 'sha256:build',
    completed: '2026-08-10T00:02:02.000Z',
  });
  tracker.update({ name: 'missing digest is ignored' });
  tracker.update({
    digest: 'sha256:late',
    name: '[internal] completion arrived first',
    completed: '2026-08-10T00:03:00.000Z',
  });
  tracker.update({
    digest: 'sha256:late',
    started: '2026-08-10T00:02:59.000Z',
  });

  assert.deepEqual(messages, [
    '[build] STARTED [base 28/31] RUN next build',
    '[build] RUNNING 45.0s [base 28/31] RUN next build',
    '[build] FAILED 1m 00s [base 28/31] RUN next build',
    '[build] STARTED [base 28/31] RUN next build',
    '[build] DONE 2.0s [base 28/31] RUN next build',
  ]);
});

test('BuildKit progress condenses duplicate structural and FROM generations', async () => {
  const { buildOrchestratorInternals } = await orchestratorModule();
  const messages = [];
  const tracker = buildOrchestratorInternals.createBuildkitProgressTracker(
    (message) => messages.push(message),
  );
  const epoch = Date.parse('2026-08-10T00:00:00.000Z');
  const timestamp = (milliseconds) => new Date(epoch + milliseconds).toISOString();
  const complete = (digest, name, startedMs, durationMs, extra = {}) => {
    tracker.update({
      digest,
      name,
      started: timestamp(startedMs),
      completed: timestamp(startedMs + durationMs),
      ...extra,
    });
  };
  const dockerfile = '[internal] load build definition from Dockerfile.nosh';
  const dockerignore = '[internal] load .dockerignore';
  const from = '[base 1/31] FROM docker.io/library/node:24-bookworm-slim@sha256:abc';

  complete('sha256:dockerfile', dockerfile, 0, 0);
  tracker.update({
    digest: 'sha256:dockerfile',
    name: dockerfile,
    started: timestamp(100),
  });
  tracker.update({
    digest: 'sha256:dockerfile',
    completed: timestamp(600),
  });
  complete('sha256:dockerignore', dockerignore, 700, 0);
  complete('sha256:dockerignore', dockerignore, 800, 500);
  complete('sha256:from', from, 1_400, 100);
  complete('sha256:from', from, 1_600, 0);
  complete('sha256:from', from, 1_700, 800);
  complete('sha256:context', '[internal] load build context', 2_600, 4_800);
  complete('sha256:from', from, 7_500, 11_500);
  complete('sha256:from', from, 19_100, 900);
  complete('sha256:from', from, 20_100, 100);
  complete('sha256:from', from, 20_300, 100);
  complete('sha256:same-from-name', from, 20_500, 3_000);
  complete('sha256:fast-export', 'exporting layers', 23_600, 500);
  complete('sha256:slow-export', 'exporting to docker image format', 24_200, 3_200);
  complete(
    'sha256:copy-failure',
    '[base 14/31] COPY missing-file /app/',
    27_500,
    100,
    { error: 'missing source file' },
  );
  complete('sha256:unnamed-failure', ' \n\t ', 27_650, 100, {
    error: 'unnamed vertex failed',
  });
  complete('sha256:workdir', '[local 1/1] WORKDIR /app', 27_700, 0);

  assert.deepEqual(messages, [
    '[build] DONE 4.8s [internal] load build context',
    `[build] DONE 11.5s ${from}`,
    '[build] DONE 3.2s exporting to docker image format',
    '[build] FAILED 0.1s [base 14/31] COPY missing-file /app/',
    '[build] FAILED 0.1s (unnamed BuildKit vertex)',
  ]);
});

test('BuildKit progress compacts long apt and Ollama RUN names', async () => {
  const { buildOrchestratorInternals } = await orchestratorModule();
  const messages = [];
  const tracker = buildOrchestratorInternals.createBuildkitProgressTracker(
    (message) => messages.push(message),
    { now: () => Date.parse('2026-08-10T00:00:30.000Z') },
  );
  const aptName = `[base 2/31] RUN apt-get update && apt-get install -y --no-install-recommends
    autoconf bash bison bubblewrap ca-certificates cmake curl flex gawk g++ git lftp
    libnspr4 libnss3 libsecret-1-0 libvte-2.91-common libsdl1.2-dev libsdl2-dev
    net-tools make ncat pkgconf procps python3 ripgrep tmux tree vim vlock zstd
    && command -v passwd >/dev/null && if [ -r /etc/profile.d/vte-2.91.sh ]; then
    ln -s /etc/profile.d/vte-2.91.sh /etc/profile.d/vte.sh; fi`;
  const ollamaName = `[base 3/31] RUN set -eux; arch="amd64"; case "$arch" in
    amd64) ollamaSha256="2c88f0f31a959bac5a3cad4cc5296ec5" ;; esac;
    archive="/tmp/ollama-linux-${'$'}{arch}.tar.zst";
    curl --proto '=https' --tlsv1.2 --fail --show-error --location --retry 5
    "https://github.com/ollama/ollama/releases/download/v0.31.2/ollama-linux-${'$'}{arch}.tar.zst"
    --output "$archive"; echo "${'$'}{ollamaSha256} ${'$'}{archive}" | sha256sum --check --strict -;
    tar --use-compress-program=unzstd --extract --file "$archive" --directory /usr/local;
    rm -f "$archive"; ollama --version`;

  tracker.update({
    digest: 'sha256:apt',
    name: aptName,
    started: '2026-08-10T00:00:00.000Z',
  });
  tracker.heartbeat();
  tracker.update({
    digest: 'sha256:apt',
    completed: '2026-08-10T00:02:41.000Z',
  });
  tracker.update({
    digest: 'sha256:ollama',
    name: ollamaName,
    started: '2026-08-10T00:03:00.000Z',
    completed: '2026-08-10T00:03:15.000Z',
  });

  assert.equal(messages.length, 4);
  assert.match(messages[0], /^\[build\] STARTED \[base 2\/31\] RUN apt-get update/);
  assert.match(messages[1], /^\[build\] RUNNING 30\.0s \[base 2\/31\] RUN apt-get update/);
  assert.match(messages[2], /^\[build\] DONE 2m 41s \[base 2\/31\] RUN apt-get update/);
  assert.match(messages[3], /^\[build\] DONE 15\.0s \[base 3\/31\] RUN set -eux/);
  for (const message of messages) {
    assert.ok(message.includes(' ... '));
    assert.ok(message.length <= 165);
    assert.doesNotMatch(message, /\s{2,}/);
  }
  assert.match(messages[0], /vte\.sh; fi$/);
  assert.match(messages[3], /rm -f "\$archive"; ollama --version$/);
});

test('BuildKit heartbeat prioritizes recent work and caps noisy active parents', async () => {
  const { buildOrchestratorInternals } = await orchestratorModule();
  const messages = [];
  const tracker = buildOrchestratorInternals.createBuildkitProgressTracker(
    (message) => messages.push(message),
    { now: () => Date.parse('2026-08-10T00:00:20.000Z') },
  );
  for (let index = 0; index < 10; index += 1) {
    tracker.update({
      digest: `sha256:active-${index}`,
      name: `[internal] active-${index}`,
      started: `2026-08-10T00:00:${String(index).padStart(2, '0')}.000Z`,
    });
  }
  messages.length = 0;

  tracker.heartbeat();

  assert.equal(messages.length, 9);
  assert.equal(messages[0], '[build] RUNNING 11.0s [internal] active-9');
  assert.ok(messages.some((message) => message.endsWith('[internal] active-2')));
  assert.ok(!messages.some((message) => message.endsWith('[internal] active-1')));
  assert.ok(!messages.some((message) => message.endsWith('[internal] active-0')));
  assert.equal(messages.at(-1), '[build] RUNNING 2 additional BuildKit vertices');
});

test('streaming builds heartbeat active work and stop the timer after exit', async (t) => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'nosh-build-progress-'));
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  const { buildOrchestratorInternals } = await orchestratorModule();
  const messages = [];
  const child = new EventEmitter();
  child.pid = 4242;
  child.stderr = new PassThrough();
  child.kill = () => true;
  setImmediate(() => {
    child.stderr.write(`${JSON.stringify({
      vertexes: [{
        digest: 'sha256:active',
        name: '[cold] RUN long-step',
        started: '2026-08-10T00:00:00.000Z',
      }],
    })}\n`);
  });
  const closeTimer = setTimeout(() => {
    child.stderr.end();
    child.emit('close', 0, null);
  }, 80);
  t.after(() => clearTimeout(closeTimer));

  const result = await buildOrchestratorInternals.runStreamingBuild(
    ['buildx', 'build'],
    path.join(directory, 'progress.jsonl'),
    {
      spawnImpl: () => child,
      progressHeartbeatMs: 5,
      now: () => Date.parse('2026-08-10T00:00:10.000Z'),
      reportProgress(message) {
        messages.push(message);
      },
    },
  );
  const countAfterExit = messages.length;
  await new Promise((resolve) => setTimeout(resolve, 20));

  assert.deepEqual(result, { status: 0, signal: null });
  assert.equal(messages[0], '[build] STARTED [cold] RUN long-step');
  assert.ok(messages.includes('[build] RUNNING 10.0s [cold] RUN long-step'));
  assert.equal(messages.length, countAfterExit);
});

test('build session compatibility requires the exact nosh-l4 flow-summary contract', async () => {
  const { buildOrchestratorInternals } = await orchestratorModule();
  const assertContract =
    buildOrchestratorInternals.assertBuildL4FlowSummaryContract;
  const valid = { adapters: [flowSummaryAdapter()] };

  assert.doesNotThrow(() => assertContract(valid));

  for (const mutate of [
    (adapter) => adapter.command.splice(-2),
    (adapter) => adapter.command.push('--output-mode', 'flow-summary'),
    (adapter) => { adapter.required = false; },
    (adapter) => { adapter.longRunning = false; },
    (adapter) => { delete adapter.readiness.recordKind; },
    (adapter) => { delete adapter.readiness.status; },
    (adapter) => { delete adapter.readiness.outputMode; },
    (adapter) => { delete adapter.completion.match.recordKind; },
    (adapter) => { adapter.completion.match.final = false; },
    (adapter) => { delete adapter.completion.match.outputMode; },
  ]) {
    const adapter = structuredClone(flowSummaryAdapter());
    mutate(adapter);
    assert.throws(
      () => assertContract({ adapters: [adapter] }),
      /incompatible nosh-l4 collector contract.*reset-nosh-guard\.sh --replace-config/,
    );
  }
  assert.throws(
    () => assertContract({ adapters: [] }),
    /incompatible nosh-l4 collector contract/,
  );
});

test('legacy build session is aborted before its Buildx pass starts', async (t) => {
  const context = buildContext(t);
  const home = fs.mkdtempSync(path.join(os.tmpdir(), 'nosh-build-legacy-'));
  t.after(() => fs.rmSync(home, { recursive: true, force: true }));
  const { buildOrchestratorInternals, resolveBuildInvocation } =
    await orchestratorModule();
  const invocation = await resolveBuildInvocation({
    context,
    platform: 'linux/amd64',
    tag: 'example:test',
  });
  const lifecycle = [];
  const progress = [];
  let buildStarted = false;

  await assert.rejects(
    buildOrchestratorInternals.runPass(
      {
        bundleDir: path.join(home, 'profile'),
        profileId: 'legacy-contract',
        mode: 'build-profile',
        depth: 'balanced',
        builderImage: 'moby/buildkit:test@sha256:' + 'b'.repeat(64),
      },
      invocation,
      {
        containerId: 'a'.repeat(64),
        builderName: 'fake-builder',
        builderNode: 'fake-builder0',
      },
      'cold',
      { cacheMode: 'cold', forceClean: false },
      {
        privilegedInvoker(action, payload) {
          lifecycle.push([action, payload]);
          if (action === 'begin') {
            const adapter = flowSummaryAdapter();
            adapter.command.splice(-2);
            delete adapter.readiness.outputMode;
            delete adapter.completion.match.outputMode;
            return { runId: payload.runId, adapters: [adapter] };
          }
          if (action === 'abort') return { runId: payload.runId };
          throw new Error(`unexpected lifecycle action: ${action}`);
        },
        spawnImpl() {
          buildStarted = true;
          throw new Error('Buildx must not start for a legacy collector');
        },
        reportProgress(message) {
          progress.push(message);
        },
      },
    ),
    /incompatible nosh-l4 collector contract/,
  );

  assert.equal(buildStarted, false);
  assert.deepEqual(lifecycle.map(([action]) => action), ['begin', 'abort']);
  assert.equal(lifecycle[1][1].runId, 'legacy-contract-cold');
  assert.deepEqual(progress, ['[build] preparing cold sensors']);
});

test('compare profiling brackets both Buildx passes with privileged sensor sessions', async (t) => {
  const context = buildContext(t);
  const home = fs.mkdtempSync(path.join(os.tmpdir(), 'nosh-build-home-'));
  t.after(() => fs.rmSync(home, { recursive: true, force: true }));
  const [
    { executeBuildProfile },
    httpEvidence,
    httpContentStore,
    httpCaptureManager,
  ] = await Promise.all([
    orchestratorModule(),
    httpEvidenceModule(),
    httpContentStoreModule(),
    httpCaptureManagerModule(),
  ]);
  const containerId = 'a'.repeat(64);
  const builderImage =
    'moby/buildkit:v0.30.0@sha256:0168606be2315b7c807a03b3d8aa79beefdb31c98740cebdffdfeebf31190c9f';
  const imageDigest = 'sha256:' + 'd'.repeat(64);
  const configDigest = 'sha256:' + 'e'.repeat(64);
  const syncCalls = [];
  const buildCalls = [];
  const lifecycle = [];
  const progress = [];
  const timeline = [];
  const runDetails = new Map();
  let managedRunActive = false;
  const managedNetworkName = 'nosh-http-net-managed-test';
  const managedLifecycle = [];

  function spawnSyncImpl(command, args) {
    syncCalls.push([command, [...args]]);
    if (command.endsWith('/flock')) {
      return { status: 0, stdout: '', stderr: '' };
    }
    assert.equal(command, 'docker');
    if (managedRunActive && args[0] === 'buildx' && args[1] === 'create') {
      managedLifecycle.push('builder-create');
    }
    if (managedRunActive && args[0] === 'buildx' && args[1] === 'rm') {
      managedLifecycle.push('builder-cleanup');
    }
    if (args[0] === 'buildx' && args[1] === 'inspect' && args[2] !== '--bootstrap') {
      return { status: 1, stdout: '', stderr: 'not found' };
    }
    if (args[0] === 'buildx' && args[1] === 'inspect' && args[2] === '--bootstrap') {
      const builderName = args[3];
      return {
        status: 0,
        stdout: `Name: ${builderName}\nDriver: docker-container\nNodes:\nName: ${builderName}0\nEndpoint: unix:///var/run/docker.sock\nStatus: running\n`,
        stderr: '',
      };
    }
    if (args[0] === 'inspect') {
      return {
        status: 0,
        stdout: `${JSON.stringify({
          Id: containerId,
          Config: { Image: builderImage },
          HostConfig: { CgroupnsMode: 'private' },
          NetworkSettings: {
            Networks: managedRunActive ? { [managedNetworkName]: {} } : {},
          },
        })}\n`,
        stderr: '',
      };
    }
    if (args[0] === 'buildx' && args[1] === 'history' && args[2] === 'inspect') {
      return { status: 0, stdout: '{"records":[]}\n', stderr: '' };
    }
    if (args[0] === 'buildx' && args[1] === 'history' && args[2] === 'export') {
      return {
        status: 0,
        stdout: Buffer.from('fake build record\n'),
        stderr: Buffer.alloc(0),
      };
    }
    return { status: 0, stdout: '', stderr: '' };
  }

  function spawnImpl(command, args) {
    assert.equal(command, 'docker');
    if (managedRunActive) managedLifecycle.push('build');
    buildCalls.push([...args]);
    const builderName = args[args.indexOf('--builder') + 1];
    const metadataPath = args[args.indexOf('--metadata-file') + 1];
    const pass = metadataPath.includes(`${path.sep}cold${path.sep}`) ? 'cold' : 'warm';
    const buildId = pass === 'cold'
      ? '0fjb6ubs52xx3vygf6fgdl611'
      : '1gkc7vct63yy4wzhg7ghem722';
    fs.writeFileSync(
      metadataPath,
      `${JSON.stringify({
        'buildx.build.ref': `${builderName}/${builderName}0/${buildId}`,
        'containerimage.digest': imageDigest,
        'containerimage.config.digest': configDigest,
      })}\n`,
      { mode: 0o600 },
    );
    const child = new EventEmitter();
    child.stderr = new PassThrough();
    child.kill = () => true;
    setImmediate(() => {
      child.stderr.end(Buffer.from(`${JSON.stringify({
        vertexes: [{
          digest: `sha256:${pass}`,
          name: `[${pass}] RUN build-step`,
          started: '2026-08-10T00:00:00.000Z',
          completed: '2026-08-10T00:00:01.000Z',
          cached: pass === 'warm',
        }],
      })}\n`));
      child.emit('exit', 0, null);
      child.emit('close', 0, null);
    });
    return child;
  }

  function writeEvidence(payload) {
    const evidenceDir = fs.mkdtempSync(
      path.join('/tmp', 'nosh-build-evidence-'),
    );
    fs.chmodSync(evidenceDir, 0o700);
    const behaviorPath = path.join(evidenceDir, 'nosh-build.jsonl');
    const networkPath = path.join(evidenceDir, 'nosh-l4.jsonl');
    const finalStats = {
      schemaVersion: 2,
      recordKind: 'stats',
      final: true,
      timestampUnixNs: '9999999999999999999',
      targetCgroupId: '900',
      lostEvents: 0,
      inflightSyscalls: payload.pass === 'cold' ? '1' : '0',
      fileSummaryRecords: '0',
      counters: {
        dnsParseErrors: '0',
        dnsCompressedNames: '0',
        dnsTruncatedNames: '0',
        dnsTruncatedResponses: '0',
        dnsAnswerLimitReached: '0',
        dnsUnsupportedAnswers: '0',
        dnsCorrelationMissing: '0',
        dnsQueryObservations: '1',
        dnsResponseObservations: '1',
        dnsNamePointers: '1',
        fileMapFull: '0',
        filePathErrors: '0',
        fileOpenObservations: '0',
      },
    };
    const dnsCorrelation = {
      keyVersion: 1,
      id: 'udp53:77:4660:53000:10.0.0.53:53',
      complete: true,
      socketCookie: '77',
      transactionId: 4660,
      clientPort: 53000,
      serverAddress: '10.0.0.53',
      serverPort: 53,
    };
    const dnsNetwork = {
      family: 'ipv4',
      protocol: 'udp',
      serverAddress: '10.0.0.53',
      serverPort: 53,
      clientPort: 53000,
    };
    fs.writeFileSync(
      behaviorPath,
      [
        JSON.stringify({
          eventKind: 'process-exec',
          observedCgroupId: '901',
          process: { comm: 'build-step' },
        }),
        JSON.stringify({
          recordKind: 'syscall-summary',
          syscallNumber: 1,
          calls: '1',
          completions: '1',
          errors: '0',
          totalDurationNs: '10',
          maxDurationNs: '10',
        }),
        JSON.stringify({
          schemaVersion: 2,
          recordKind: 'event',
          metadataOnly: true,
          eventKind: 'dns-query',
          timestampNs: '100',
          targetCgroupId: '900',
          observedCgroupId: '901',
          process: null,
          network: { ...dnsNetwork, direction: 'query' },
          dns: {
            transport: 'udp',
            qname: 'registry.example.',
            queryType: 1,
            queryClass: 1,
            correlation: dnsCorrelation,
          },
        }),
        JSON.stringify({
          schemaVersion: 2,
          recordKind: 'event',
          metadataOnly: true,
          eventKind: 'dns-response',
          timestampNs: '200',
          targetCgroupId: '900',
          observedCgroupId: '901',
          process: null,
          network: { ...dnsNetwork, direction: 'response' },
          dns: {
            transport: 'udp',
            qname: 'registry.example.',
            queryType: 1,
            queryClass: 1,
            correlation: dnsCorrelation,
            response: {
              flags: 0x8180,
              responseCode: 0,
              truncated: false,
              questionCount: 1,
              answersDeclared: 2,
              answersVisited: 2,
              answersCaptured: 2,
              parseComplete: true,
              answerLimitReached: false,
              answers: [
                {
                  index: 0,
                  ownerName: 'registry.example.',
                  type: 5,
                  class: 1,
                  ttl: 60,
                  data: { kind: 'cname', name: 'cdn.registry.example.' },
                },
                {
                  index: 1,
                  ownerName: 'cdn.registry.example.',
                  type: 1,
                  class: 1,
                  ttl: 45,
                  data: { kind: 'ipv4', address: '203.0.113.10' },
                },
              ],
            },
          },
        }),
        JSON.stringify(finalStats),
        '',
      ].join('\n'),
      { mode: 0o600 },
    );
    fs.writeFileSync(
      networkPath,
      [
        JSON.stringify({
          eventKind: 'attempt',
          timestampNs: '100',
          observedCgroupId: '901',
          socketCookie: '77',
          process: { pid: 50, comm: 'apt' },
          network: {
            direction: 'egress',
            protocol: 'udp',
            destinationAddress: '10.0.0.53',
            destinationPort: 53,
          },
        }),
        JSON.stringify({
          eventKind: 'attempt',
          timestampNs: '250',
          observedCgroupId: '901',
          socketCookie: '88',
          process: { pid: 51, comm: 'curl' },
          network: {
            direction: 'egress',
            protocol: 'tcp',
            destinationAddress: '203.0.113.10',
            destinationPort: 443,
          },
        }),
        JSON.stringify({
          recordKind: 'flow-summary',
          timestampNs: '300',
          accounting: { packets: '4', bytes: '512' },
          network: {
            direction: 'egress',
            protocol: 'tcp',
            destinationAddress: '203.0.113.11',
            destinationPort: 8443,
          },
        }),
        ...(payload.mode === 'build-net-learn' ? [JSON.stringify({
          recordKind: 'flow-summary',
          timestampUnixNs: '1787400060000000000',
          firstObservedNs: '1787399999000000000',
          lastObservedNs: '1787400001000000000',
          observedCgroupId: '901',
          socketCookie: '99',
          process: { pid: 52, comm: 'curl' },
          network: {
            direction: 'egress',
            protocol: 'tcp',
            sourceAddress: '172.30.0.3',
            sourcePort: 41_234,
            destinationAddress: '172.30.0.2',
            destinationPort: 8080,
          },
        })] : []),
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
    for (const name of ['cgroup-before.json', 'cgroup-after.json']) {
      fs.writeFileSync(
        path.join(evidenceDir, name),
        `${JSON.stringify({
          'cpu.stat': 'usage_usec 10\nuser_usec 5\nsystem_usec 5\n',
          'cpu.pressure': 'some avg10=0.00 avg60=0.00 avg300=0.00 total=0\nfull avg10=0.00 avg60=0.00 avg300=0.00 total=0\n',
          'io.stat': '8:0 rbytes=0 wbytes=0 rios=0 wios=0\n',
          'io.pressure': 'some avg10=0.00 avg60=0.00 avg300=0.00 total=0\nfull avg10=0.00 avg60=0.00 avg300=0.00 total=0\n',
          'memory.current': '0\n',
          'memory.events': 'low 0\nhigh 0\nmax 0\noom 0\noom_kill 0\n',
          'memory.pressure': 'some avg10=0.00 avg60=0.00 avg300=0.00 total=0\nfull avg10=0.00 avg60=0.00 avg300=0.00 total=0\n',
          'pids.current': '1\n',
        })}\n`,
        { mode: 0o600 },
      );
    }
    const completion = {
      complete: true,
      marker: 'final-stats',
      lostEvents: 0,
      parseErrors: 0,
      descendantObserved: true,
      final: finalStats,
    };
    const now = new Date().toISOString();
    const manifest = {
      apiVersion: 'notty.dev/v1alpha1',
      kind: 'NoshBuildEvidenceManifest',
      schemaVersion: 1,
      runId: payload.runId,
      mode: payload.mode,
      pass: payload.pass,
      startedAt: payload.result.buildStartedAt,
      finishedAt: payload.result.buildFinishedAt || now,
      complete: true,
      build: {
        exitCode: 0,
        succeeded: true,
        startedAt: payload.result.buildStartedAt,
        finishedAt: payload.result.buildFinishedAt || now,
        metadata: payload.result.metadata,
      },
      workspace: { path: context },
      builder: {
        builderName: 'fake-builder',
        containerId,
        imageReference: 'moby/buildkit:test@sha256:' + 'f'.repeat(64),
        imageDigest: 'sha256:' + 'f'.repeat(64),
        initPid: 4242,
        cgroup: { path: '/sys/fs/cgroup/fake', id: '900' },
      },
      identity: { ok: true, error: null },
      cleanup: { ok: true, results: [] },
      sources: [
        {
          name: 'nosh-build',
          required: true,
          complete: true,
          file: { path: path.basename(behaviorPath) },
          completion,
        },
        {
          name: 'nosh-l4',
          required: true,
          complete: true,
          file: { path: path.basename(networkPath) },
          completion,
        },
        ...['cgroup-before.json', 'cgroup-after.json'].map((name) => ({
          name,
          required: true,
          complete: true,
          file: { path: name },
        })),
      ],
      limitations: [],
    };
    const manifestPath = path.join(evidenceDir, 'build-evidence-manifest.json');
    fs.writeFileSync(manifestPath, `${JSON.stringify(manifest)}\n`, { mode: 0o600 });
    return { manifest, manifestPath };
  }

  function privilegedInvoker(action, payload) {
    lifecycle.push([action, payload]);
    if (action === 'begin') {
      runDetails.set(payload.runId, { mode: payload.mode, pass: payload.pass });
      return { runId: payload.runId, adapters: [flowSummaryAdapter()] };
    }
    if (action === 'finish') {
      const details = runDetails.get(payload.runId);
      const { manifest, manifestPath } = writeEvidence({
        ...payload,
        mode: details.mode,
        pass: details.pass,
      });
      return {
        runId: payload.runId,
        evidenceComplete: true,
        buildSucceeded: true,
        userEvidenceManifest: manifestPath,
        manifest,
      };
    }
    if (action === 'exported') {
      assert.match(payload.portableBundleHash, /^sha256:[a-f0-9]{64}$/);
      return {
        runId: payload.runId,
        portableExport: { bundleHash: payload.portableBundleHash },
      };
    }
    throw new Error(`unexpected lifecycle action: ${action}`);
  }

  const result = await executeBuildProfile({
    context,
    home,
    platform: 'linux/amd64',
    cacheMode: 'compare',
    tag: 'example:test',
  }, {
    dockerInfo() {
      timeline.push(['docker-info']);
      return {
        endpoint: 'unix:///var/run/docker.sock',
        info: { OSType: 'linux', CgroupVersion: '2' },
      };
    },
    spawnSyncImpl,
    spawnImpl,
    privilegedInvoker,
    reportProgress(message) {
      progress.push(message);
      timeline.push(['progress', message]);
    },
  });

  assert.equal(result.status, 0);
  assert.equal(result.mode, 'build-profile');
  assert.equal(result.cacheMode, 'compare');
  assert.deepEqual(result.passes.map((entry) => entry.pass), ['cold', 'warm']);
  assert.equal(result.manifest.complete, true);
  assert.equal(result.manifest.candidateEligible, true);
  assert.equal(result.candidate.kind, 'NoshBuildProfileCandidate');
  assert.equal(result.candidate.approved, false);
  assert.equal(result.candidate.authoritative, false);
  assert.equal(result.candidate.spec.outputImageDigestUse, 'informational-only');
  assert.equal(result.manifest.metrics.syscalls.durationTotalsComplete, false);
  assert.equal(
    result.manifest.metrics.collectorDiagnostics.noshBuild.totals.inflightSyscalls,
    '1',
  );
  assert.equal(result.manifest.metrics.cgroup.passes.length, 2);
  assert.deepEqual(
    result.manifest.observations.network.destinations.map((entry) => entry.port),
    [443, 53, 8443],
  );
  assert.equal(result.manifest.observations.network.dns.queries.length, 2);
  assert.equal(result.manifest.observations.network.dns.answers.length, 4);
  assert.equal(result.manifest.observations.network.dns.snapshots.length, 2);
  assert.deepEqual(
    result.manifest.observations.network.dns.snapshots[0].cnameChain,
    ['registry.example', 'cdn.registry.example'],
  );
  assert.deepEqual(
    result.manifest.observations.network.dns.snapshots[0].addresses,
    [{
      address: '203.0.113.10',
      family: 'ipv4',
      ownerName: 'cdn.registry.example',
      ttl: 45,
    }],
  );
  assert.deepEqual(
    [...new Set(result.manifest.observations.network.correlations.map(
      (entry) => entry.kind,
    ))].sort(),
    ['dns-destination', 'dns-query-process'],
  );
  assert.equal(result.manifest.observations.network.correlations.length, 4);
  assert.equal(result.manifest.observations.network.coverage.dns.complete, true);
  assert.equal(result.manifest.observations.network.coverage.dns.queries, 2);
  assert.equal(result.manifest.observations.network.coverage.dns.responses, 2);
  assert.equal(result.manifest.observations.network.coverage.dns.answers, 4);
  assert.equal(result.manifest.observations.network.coverage.url.enabled, false);
  assert.equal(result.manifest.observations.network.coverage.url.complete, false);
  assert.deepEqual(result.manifest.observations.network.unresolved, []);
  assert.deepEqual(
    result.manifest.observations.network.privateDestinations.map((entry) => entry.ip),
    ['10.0.0.53'],
  );
  assert.equal(result.manifest.metrics.network.dnsNameCoverageComplete, true);
  assert.equal(result.manifest.metrics.network.dnsCorrelations, 4);
  assert.equal(result.candidate.spec.observations.network.dns.snapshots.length, 2);
  assert.equal(result.manifest.build.passes[0].metrics.cgroup.pass, 'cold');
  assert.ok(result.candidate.spec.limitations.some((entry) =>
    /syscall duration totals are incomplete/.test(entry)));
  assert.ok(fs.existsSync(result.bundleDir));
  assert.ok(fs.existsSync(result.portableBundleDir));

  assert.deepEqual(lifecycle.map(([action]) => action), [
    'begin',
    'finish',
    'begin',
    'finish',
    'exported',
    'exported',
  ]);
  assert.equal(
    lifecycle.at(-1)[1].portableBundleHash,
    lifecycle.at(-2)[1].portableBundleHash,
  );
  assert.equal(buildCalls.length, 2);
  assert.ok(buildCalls[0].includes('--pull'));
  assert.ok(buildCalls[0].includes('--no-cache'));
  assert.deepEqual(
    buildCalls[0].slice(buildCalls[0].indexOf('--output'), buildCalls[0].indexOf('--output') + 2),
    ['--output', 'type=cacheonly'],
  );
  assert.equal(buildCalls[1].includes('--no-cache'), false);
  assert.ok(buildCalls[1].includes('--load'));
  assert.ok(syncCalls.some(([, args]) => args[0] === 'buildx' && args[1] === 'create'));
  assert.ok(syncCalls.some(([, args]) => args[0] === 'buildx' && args[1] === 'rm'));
  assert.deepEqual(
    syncCalls
      .filter(([, args]) => args[0] === 'buildx' && args[1] === 'history')
      .map(([, args]) => [args[2], args.at(-1)]),
    [
      ['inspect', '0fjb6ubs52xx3vygf6fgdl611'],
      ['export', '0fjb6ubs52xx3vygf6fgdl611'],
      ['inspect', '1gkc7vct63yy4wzhg7ghem722'],
      ['export', '1gkc7vct63yy4wzhg7ghem722'],
    ],
  );
  assert.deepEqual(timeline.slice(0, 3), [
    ['progress', '[build] starting build profile'],
    ['docker-info'],
    ['progress', '[build] Docker preflight complete'],
  ]);
  assert.deepEqual(progress, [
    '[build] starting build profile',
    '[build] Docker preflight complete',
    '[build] preparing BuildKit builder',
    '[build] BuildKit builder ready',
    '[build] preparing cold sensors',
    '[build] starting cold pass',
    '[build] DONE 1.0s [cold] RUN build-step',
    '[build] preparing warm sensors',
    '[build] starting warm pass',
    '[build] CACHED 1.0s [warm] RUN build-step',
    '[build] cleaning up BuildKit builder',
    '[build] finalizing build evidence',
    '[build] preserving build evidence',
    '[build] build profile complete',
  ]);

  fs.appendFileSync(
    path.join(context, 'Dockerfile'),
    '\n# nosh-http-capture-ca-secret=v1\n',
  );
  managedRunActive = true;
  let managedRecords = null;
  let managedSession = null;
  let managedContentManifest = null;
  let managedContentObject = null;
  const managedProgress = [];
  const managedResult = await executeBuildProfile({
    context,
    home,
    mode: 'build-net-learn',
    platform: 'linux/amd64',
    httpCapture: 'mitmproxy',
    tag: 'example:http',
  }, {
    dockerInfo() {
      return {
        endpoint: 'unix:///var/run/docker.sock',
        info: { OSType: 'linux', CgroupVersion: '2' },
      };
    },
    spawnSyncImpl,
    spawnImpl,
    privilegedInvoker,
    async startManagedHttpCapture(input) {
      managedLifecycle.push('capture-start');
      assert.equal(input.dockerfile, fs.realpathSync(path.join(context, 'Dockerfile')));
      assert.match(fs.readFileSync(input.dockerfile, 'utf8'), /nosh-http-capture-ca-secret=v1/);
      const managedRoot = path.join(input.bundleDir, 'http-capture');
      const managedCasRoot = path.join(managedRoot, 'cas');
      fs.mkdirSync(managedCasRoot, { recursive: true, mode: 0o700 });
      fs.chmodSync(managedRoot, 0o700);
      fs.chmodSync(managedCasRoot, 0o700);
      managedSession = {
        runId: input.runId,
        root: managedRoot,
        networkName: managedNetworkName,
        proxyAlias: 'nosh-http-proxy',
        proxyIpv4: '172.30.0.2',
        proxyPort: 8080,
        caPath: path.join(input.bundleDir, 'fake-ca.pem'),
        casRoot: managedCasRoot,
        collectorIdentity: {
          collectorImageDigest: `sha256:${'a'.repeat(64)}`,
          collectorAddonDigest: `sha256:${'b'.repeat(64)}`,
          collectorWrapperDigest: `sha256:${'c'.repeat(64)}`,
        },
        stopped: false,
        networkCreated: true,
      };
      const request = httpEvidence.createHttpRequestEvidence({
        runId: input.runId,
        observedAt: '2026-08-22T12:00:00.000Z',
        provider: 'mitmproxy',
        providerEventId: 'managed-build-request',
        method: 'GET',
        url: 'https://registry.example.test/package.tgz',
        headers: {
          Accept: 'application/octet-stream',
        },
        requestBody: Buffer.alloc(0),
        tlsInterception: 'intercepted',
        upstreamTlsVerified: true,
        clientAddress: '172.30.0.3',
        clientPort: 41_234,
        proxyAddress: managedSession.proxyIpv4,
        proxyPort: managedSession.proxyPort,
      });
      const response = httpEvidence.createHttpResponseEvidence({
        runId: input.runId,
        observedAt: '2026-08-22T12:00:00.000Z',
        provider: 'mitmproxy',
        exchangeId: request.exchangeId,
        status: 200,
        contentType: 'application/octet-stream',
        contentEncoding: null,
        headersDigest: null,
        body: 'package bytes',
        decodedBody: 'package bytes',
        bodyComplete: true,
        delivery: 'observed',
        rangeResponse: false,
      });
      const contentStore = new httpContentStore.HttpContentStore({
        root: managedSession.casRoot,
        containmentRoot: managedSession.root,
      });
      managedContentObject = await contentStore.put(Buffer.from('package bytes'));
      managedContentManifest = httpContentStore.createHttpContentManifest({
        runId: input.runId,
        generatedAt: '2026-08-22T12:00:01.000Z',
        mode: 'offline-replay',
        entries: [{
          request: httpEvidence.httpRequestIdentity(request),
          response: {
            status: response.status,
            bodyDigest: managedContentObject.digest,
            bodyBytes: managedContentObject.bytes,
            contentType: response.contentType,
            contentEncoding: response.contentEncoding,
            location: null,
            locationDigest: null,
          },
          sourceExchangeId: request.exchangeId,
          capturedAt: '2026-08-22T12:00:00.000Z',
        }],
      });
      await contentStore.writeManifest(managedContentManifest);
      managedRecords = [
        request,
        response,
        httpEvidence.createHttpCaptureStats({
          runId: input.runId,
          observedAt: '2026-08-22T12:00:00.000Z',
          provider: 'mitmproxy',
          complete: true,
          requests: 1,
          responses: 1,
          redirects: 0,
          errors: 0,
          opaqueConnects: 0,
          incompleteBodies: 0,
          droppedRecords: 0,
          reviewOnlyRecords: 0,
          coverageGaps: [],
          contentAssuranceGaps: [],
          contentManifestDigest: managedContentManifest.contentHash,
          ...managedSession.collectorIdentity,
        }),
      ];
      return managedSession;
    },
    managedHttpBuildOptions(session) {
      managedLifecycle.push('build-options');
      assert.equal(session, managedSession);
      const proxy = 'http://nosh-http-proxy:8080';
      return {
        networkName: managedNetworkName,
        buildArgs: [
          `HTTP_PROXY=${proxy}`,
          `HTTPS_PROXY=${proxy}`,
          `FTP_PROXY=${proxy}`,
          `ALL_PROXY=${proxy}`,
          'NO_PROXY=',
          `http_proxy=${proxy}`,
          `https_proxy=${proxy}`,
          `ftp_proxy=${proxy}`,
          `all_proxy=${proxy}`,
          'no_proxy=',
          'NOSH_HTTP_CAPTURE=1',
          'NOSH_HTTP_CAPTURE_CA_FILE=/usr/local/share/ca-certificates/nosh-http-capture.crt',
        ],
        secret: { id: 'nosh-http-ca', source: session.caPath },
      };
    },
    async stopManagedHttpCapture(session) {
      managedLifecycle.push('capture-stop');
      assert.equal(session, managedSession);
      session.stopped = true;
      const content = Buffer.from(
        `${managedRecords.map((record) => JSON.stringify(record)).join('\n')}\n`,
      );
      return {
        records: managedRecords,
        contentManifest: managedContentManifest,
        contentManifestPath: path.join(
          session.casRoot,
          'manifests',
          `${managedContentManifest.contentHash.slice('sha256:'.length)}.json`,
        ),
        source: httpEvidence.createHttpEvidenceSourceDescriptor({
          file: 'raw/http.ndjson',
          content,
          records: managedRecords,
          required: true,
          expectedCollectorIdentity: session.collectorIdentity,
        }),
      };
    },
    correlateManagedHttpEvidence(records, input) {
      const proxyAttempt = input.networkAttempts.find((attempt) => (
        attempt.ip === managedSession.proxyIpv4
        && attempt.port === managedSession.proxyPort
      ));
      assert.equal(proxyAttempt.firstTimestampNs, '1787399999000000000');
      assert.equal(proxyAttempt.lastTimestampNs, '1787400001000000000');
      assert.equal(input.contentManifest, managedContentManifest);
      return httpCaptureManager.correlateManagedHttpEvidence(records, input);
    },
    cleanupManagedHttpCaptureNetwork(session) {
      managedLifecycle.push('network-cleanup');
      assert.equal(session, managedSession);
      session.networkCreated = false;
    },
    reportProgress(message) {
      managedProgress.push(message);
    },
  });

  assert.equal(managedResult.status, 1);
  assert.equal(managedResult.mode, 'build-net-learn');
  assert.equal(managedResult.manifest.complete, false);
  assert.equal(managedResult.manifest.candidateEligible, false);
  assert.ok(managedResult.manifest.incompleteReasons.includes(
    'managed HTTP capture has unresolved routing or network-provenance gaps',
  ));
  const httpSource = managedResult.manifest.sources.find((source) => source.name === 'http');
  assert.equal(httpSource.required, true);
  assert.equal(httpSource.present, true);
  assert.equal(httpSource.complete, true);
  assert.equal(httpSource.records, 3);
  assert.equal(httpSource.completionMarker, 'all-passes-finalized');
  const finalHttpEvidencePath = path.join(
    managedResult.bundleDir,
    'raw',
    'http.ndjson',
  );
  assert.ok(fs.existsSync(finalHttpEvidencePath));
  const finalHttpStats = fs.readFileSync(finalHttpEvidencePath, 'utf8')
    .trim()
    .split('\n')
    .map((line) => JSON.parse(line))
    .at(-1);
  assert.equal(finalHttpStats.contentManifestDigest, managedContentManifest.contentHash);
  assert.deepEqual(
    {
      collectorImageDigest: finalHttpStats.collectorImageDigest,
      collectorAddonDigest: finalHttpStats.collectorAddonDigest,
      collectorWrapperDigest: finalHttpStats.collectorWrapperDigest,
    },
    managedSession.collectorIdentity,
  );
  assert.equal(managedResult.manifest.observations.http.complete, false);
  assert.ok(managedResult.manifest.observations.http.gaps.includes(
    'managed HTTP origin route lacks independent proxy-leg L4 provenance',
  ));
  assert.equal(managedResult.manifest.observations.http.exchanges.length, 1);
  assert.deepEqual(
    managedResult.manifest.observations.http.exchanges[0].destination,
    { ip: '172.30.0.2', protocol: 'tcp', port: 8080 },
  );
  assert.equal(
    managedResult.manifest.observations.http.exchanges[0].destinationRole,
    'workload-to-proxy',
  );
  assert.deepEqual(
    managedResult.manifest.observations.http.exchanges[0].cas,
    {
      objectSha256: managedContentObject.digest,
      manifestSha256: managedContentManifest.contentHash,
      available: true,
    },
  );
  assert.equal(
    managedResult.httpContentManifestDigest,
    managedContentManifest.contentHash,
  );
  const finalCasRoot = path.join(
    managedResult.bundleDir,
    'private',
    'http-capture',
    'cas',
  );
  const finalContentStore = new httpContentStore.HttpContentStore({
    root: finalCasRoot,
    containmentRoot: path.dirname(finalCasRoot),
  });
  assert.equal(
    managedResult.httpContentManifestPath,
    finalContentStore.manifestPath(managedContentManifest.contentHash),
  );
  assert.equal(
    fs.statSync(managedResult.httpContentManifestPath).mode & 0o777,
    0o400,
  );
  assert.equal(
    fs.statSync(finalContentStore.objectPath(managedContentObject.digest)).mode & 0o777,
    0o400,
  );
  assert.deepEqual(
    await finalContentStore.readManifest(managedResult.httpContentManifestDigest),
    managedContentManifest,
  );
  assert.equal(
    (await finalContentStore.read(managedContentObject.digest, {
      expectedBytes: managedContentObject.bytes,
    })).toString('utf8'),
    'package bytes',
  );
  assert.deepEqual(managedLifecycle, [
    'capture-start',
    'build-options',
    'builder-create',
    'build',
    'capture-stop',
    'builder-cleanup',
    'network-cleanup',
  ]);
  const managedCreate = syncCalls
    .map(([, args]) => args)
    .filter((args) => args[0] === 'buildx' && args[1] === 'create')
    .at(-1);
  assert.ok(managedCreate.includes(`network=${managedNetworkName}`));
  const managedBuild = buildCalls.at(-1);
  assert.ok(managedBuild.includes('HTTPS_PROXY=http://nosh-http-proxy:8080'));
  assert.ok(managedBuild.includes(
    `id=nosh-http-ca,src=${managedSession.caPath}`,
  ));
  assert.ok(managedProgress.indexOf('[build] stopping managed HTTP observation proxy')
    < managedProgress.indexOf('[build] cleaning up BuildKit builder'));
});

test('managed capture cleanup aggregates bootstrap, proxy stop, and network failures', async (t) => {
  const context = buildContext(t);
  fs.appendFileSync(
    path.join(context, 'Dockerfile'),
    '\n# nosh-http-capture-ca-secret=v1\n',
  );
  const home = fs.mkdtempSync(path.join(os.tmpdir(), 'nosh-http-cleanup-home-'));
  t.after(() => fs.rmSync(home, { recursive: true, force: true }));
  const { executeBuildProfile } = await orchestratorModule();
  const events = [];
  const networkName = 'nosh-http-net-cleanup-test';
  const session = {
    runId: 'set-by-start',
    networkName,
    proxyAlias: 'nosh-http-proxy',
    proxyIpv4: '172.31.0.2',
    proxyPort: 8080,
    caPath: path.join(home, 'managed-http-ca.pem'),
    stopped: false,
    networkCreated: true,
  };

  await assert.rejects(
    executeBuildProfile({
      context,
      home,
      mode: 'build-net-learn',
      platform: 'linux/amd64',
      httpCapture: 'mitmproxy',
    }, {
      dockerInfo() {
        return {
          endpoint: 'unix:///var/run/docker.sock',
          info: { OSType: 'linux', CgroupVersion: '2' },
        };
      },
      spawnSyncImpl(command, args) {
        if (command.endsWith('/flock')) {
          return { status: 0, stdout: '', stderr: '' };
        }
        assert.equal(command, 'docker');
        if (args[0] === 'buildx' && args[1] === 'inspect' && args[2] !== '--bootstrap') {
          return { status: 1, stdout: '', stderr: 'not found' };
        }
        if (args[0] === 'buildx' && args[1] === 'create') {
          events.push('builder-create');
          return { status: 0, stdout: '', stderr: '' };
        }
        if (args[0] === 'buildx' && args[1] === 'inspect' && args[2] === '--bootstrap') {
          events.push('builder-bootstrap');
          return { status: 125, stdout: '', stderr: 'builder bootstrap failed' };
        }
        if (args[0] === 'buildx' && args[1] === 'rm') {
          events.push('builder-cleanup');
          return { status: 125, stdout: '', stderr: 'builder cleanup failed' };
        }
        assert.fail(`unexpected Docker command: ${args.join(' ')}`);
      },
      privilegedInvoker() {
        assert.fail('collector session must not begin after builder bootstrap failure');
      },
      async startManagedHttpCapture(input) {
        events.push('capture-start');
        session.runId = input.runId;
        return session;
      },
      managedHttpBuildOptions(selected) {
        events.push('build-options');
        assert.equal(selected, session);
        return {
          networkName,
          buildArgs: [
            'HTTP_PROXY=http://nosh-http-proxy:8080',
            'HTTPS_PROXY=http://nosh-http-proxy:8080',
          ],
          secret: { id: 'nosh-http-ca', source: session.caPath },
        };
      },
      async stopManagedHttpCapture(selected) {
        events.push('capture-stop');
        assert.equal(selected, session);
        throw new Error('capture stop failed');
      },
      cleanupManagedHttpCaptureNetwork(selected) {
        events.push('network-cleanup');
        assert.equal(selected, session);
        throw new Error('capture network cleanup failed');
      },
      reportProgress() {},
    }),
    (error) => {
      const messages = [];
      const visit = (current) => {
        messages.push(current.message);
        for (const nested of current.errors || []) visit(nested);
      };
      visit(error);
      assert.ok(error instanceof AggregateError);
      assert.match(error.message, /managed HTTP network cleanup failed/);
      assert.ok(messages.some((message) => /builder bootstrap failed/.test(message)));
      assert.ok(messages.some((message) => /builder cleanup failed/.test(message)));
      assert.ok(messages.some((message) => /capture stop failed/.test(message)));
      assert.ok(messages.some((message) => /capture network cleanup failed/.test(message)));
      return true;
    },
  );
  assert.deepEqual(events, [
    'capture-start',
    'build-options',
    'builder-create',
    'builder-bootstrap',
    'builder-cleanup',
    'capture-stop',
    'network-cleanup',
  ]);
});

test('CI collector lifecycle elevation is noninteractive and still uses the trusted helper', async (t) => {
  const { defaultPrivilegedInvoker } = await orchestratorModule();
  const previous = process.env.NOSH_BUILD_NONINTERACTIVE;
  t.after(() => { if (previous === undefined) delete process.env.NOSH_BUILD_NONINTERACTIVE; else process.env.NOSH_BUILD_NONINTERACTIVE = previous; });
  // Intercept execution after trust checks; no sudo process is started.
  const helper = fs.realpathSync('/usr/bin/true');
  for (const enabled of [false, true]) {
    if (enabled) process.env.NOSH_BUILD_NONINTERACTIVE = '1'; else delete process.env.NOSH_BUILD_NONINTERACTIVE;
    const result = defaultPrivilegedInvoker('begin', { clientUid: process.getuid() }, {
      guardBin: helper,
      spawnSyncImpl(command, args, options) {
        if (process.geteuid() === 0) {
          assert.equal(command, helper);
          assert.deepEqual(args, ['build-session', 'begin']);
        } else {
          assert.equal(command, 'sudo');
          assert.deepEqual(args, [...(enabled ? ['-n'] : []), '--', helper, 'build-session', 'begin']);
        }
        assert.equal(JSON.parse(options.input).clientUid, process.getuid());
        return { status: 0, stdout: '{"ok":true}' };
      },
    });
    assert.deepEqual(result, { ok: true });
  }
});
