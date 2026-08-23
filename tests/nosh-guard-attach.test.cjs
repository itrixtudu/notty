'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const test = require('node:test');
const { pathToFileURL } = require('node:url');

const appRoot = path.resolve(__dirname, '..');

async function importModule(relativePath) {
  return import(pathToFileURL(path.join(appRoot, relativePath)).href);
}

function tempDir(t) {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'nosh-attach-test-'));
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  return directory;
}

test('attach revalidates exact runtime, egress, and adapter identities', async (t) => {
  const root = tempDir(t);
  const stateDir = path.join(root, 'state');
  const workdir = path.join(root, 'workspace');
  fs.mkdirSync(workdir);
  const containerId = 'b'.repeat(64);
  const operations = [];
  const namespaces = {
    cgroup: '401',
    mnt: '402',
    net: '403',
    pid: '404',
    user: '405',
  };
  const cgroup = {
    path: '/sys/fs/cgroup/nosh-attach',
    id: '9001',
    membership: '/nosh-attach',
  };
  const { GuardStateStore } = await importModule('lib/guardd/state-store.js');
  const { GuardService } = await importModule('lib/guardd/service.js');
  const store = new GuardStateStore(stateDir);
  const service = new GuardService({
    store,
    docker: {
      socketPath: '/run/docker-attach.sock',
      async inspectContainer(requestedId) {
        operations.push(['inspect', requestedId]);
        return {
          Id: containerId,
          Image: 'sha256:runner',
          State: { Running: true, Pid: 4242 },
          Config: {
            Labels: {
              'io.notty.guard.run-id': 'run-attach',
              'io.notty.guard.image-digest': 'sha256:runner',
            },
          },
          NetworkSettings: {
            Networks: {
              'nosh-guard-attach': { IPAddress: '10.240.9.3' },
            },
          },
        };
      },
    },
    adapters: {
      async runtimeHealth(run, context) {
        operations.push([
          'adapters',
          run.runId,
          context.cgroupId,
          context.networkNamespace,
        ]);
        return [{ name: 'tetragon-events', required: true, ok: true }];
      },
    },
    egress: {
      async initialize() {},
      async health() {
        operations.push(['egress']);
        return { ok: true, containerId: 'gateway-attach' };
      },
    },
    namespaceProvider() {
      operations.push(['namespaces']);
      return namespaces;
    },
    cgroupProvider() {
      operations.push(['cgroup']);
      return cgroup;
    },
    hostNamespaceProvider() {
      return 'host-cgroup';
    },
  });
  await service.initialize();
  await store.writeRun({
    runId: 'run-attach',
    name: 'attach-runner',
    mode: 'learn',
    status: 'running',
    containerId,
    imageDigest: 'sha256:runner',
    initPid: 4242,
    namespaces,
    cgroup,
    workdir,
    adapters: [{ name: 'tetragon-events', required: true }],
    egress: {
      networkName: 'nosh-guard-attach',
      sourceIpv4: '10.240.9.3',
      gatewayIpv4: '10.240.9.2',
      gatewayContainerId: 'gateway-attach',
    },
  });

  const attached = await service.runAction('attach-runner', 'attach');

  assert.equal(attached.containerId, containerId);
  assert.equal(attached.workdir, workdir);
  assert.equal(attached.attachment.validated, true);
  assert.equal(attached.attachment.containerId, containerId);
  assert.equal(attached.attachment.dockerSocket, '/run/docker-attach.sock');
  assert.equal(attached.attachment.gatewayContainerId, 'gateway-attach');
  assert.deepEqual(attached.attachment.namespaces, namespaces);
  assert.deepEqual(operations, [
    ['inspect', containerId],
    ['namespaces'],
    ['cgroup'],
    ['egress'],
    ['adapters', 'run-attach', '9001', '403'],
  ]);
});

test('attach refuses stopped guarded runs without Docker access', async (t) => {
  const root = tempDir(t);
  const { GuardStateStore } = await importModule('lib/guardd/state-store.js');
  const { GuardService } = await importModule('lib/guardd/service.js');
  const store = new GuardStateStore(path.join(root, 'state'));
  const service = new GuardService({
    store,
    docker: {
      async inspectContainer() {
        throw new Error('must not inspect a stopped run');
      },
    },
    adapters: {},
    egress: {
      async initialize() {},
    },
  });
  await service.initialize();
  await store.writeRun({
    runId: 'run-stopped',
    name: 'stopped',
    status: 'stopped',
    containerId: 'c'.repeat(64),
  });

  await assert.rejects(
    service.runAction('stopped', 'attach'),
    (error) =>
      error.code === 'GUARD_RUN_NOT_RUNNING'
      && error.statusCode === 409,
  );
});
