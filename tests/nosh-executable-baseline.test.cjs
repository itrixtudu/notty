'use strict';

const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const test = require('node:test');
const { pathToFileURL } = require('node:url');

const appRoot = path.resolve(__dirname, '..');

async function baselineModule() {
  return import(pathToFileURL(path.join(
    appRoot,
    'lib/guardd/executable-baseline.js',
  )).href);
}

async function cliModule() {
  return import(pathToFileURL(path.join(appRoot, 'scripts/nosh-guard.mjs')).href);
}

function tempDir(t) {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'nosh-exec-baseline-'));
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  return directory;
}

function event(executable, pid, timestampNs) {
  return {
    schemaVersion: 2,
    recordKind: 'event',
    metadataOnly: true,
    eventKind: 'process-exec',
    timestampNs,
    targetCgroupId: '42',
    observedCgroupId: '84',
    process: {
      pid,
      tid: pid,
      ppid: 1,
      uid: 1000,
      gid: 1000,
      comm: path.basename(executable),
    },
    executable,
    rawExitCode: null,
  };
}

test('executable inventory allows and alerts on paths absent from the reviewed baseline', async () => {
  const {
    createExecutableBaselineDraft,
    projectExecutableInventory,
    validateExecutableInventory,
  } = await baselineModule();
  const selector = {
    runId: 'run-one',
    workspaceKey: 'a'.repeat(64),
    imageDigest: `sha256:${'b'.repeat(64)}`,
    complete: true,
    generatedAt: '2026-10-07T00:00:00.000Z',
  };
  const first = projectExecutableInventory([
    event('/usr/bin/node', 10, '1000000'),
    event('/usr/bin/node', 11, '2000000'),
    event('/usr/bin/git', 12, '3000000'),
  ], selector);
  assert.equal(validateExecutableInventory(first).inventoryDigest, first.inventoryDigest);
  assert.equal(first.argumentsRecorded, false);
  assert.equal(first.unknownAction, 'allow-and-alert');
  assert.equal(first.unknownCount, 2);
  assert.deepEqual(
    first.executables.map(({ path: executable, classification, action, count }) => ({
      executable, classification, action, count,
    })),
    [
      { executable: '/usr/bin/git', classification: 'unknown', action: 'allow-and-alert', count: 1 },
      { executable: '/usr/bin/node', classification: 'unknown', action: 'allow-and-alert', count: 2 },
    ],
  );

  const baseline = createExecutableBaselineDraft(first, {
    createdAt: '2026-10-07T00:00:01.000Z',
    reviewedAt: '2026-10-07T00:00:02.000Z',
    reviewer: 'Operator',
    acknowledged: true,
  });
  baseline.executables = ['/usr/bin/node'];
  const second = projectExecutableInventory([
    event('/usr/bin/node', 20, '4000000'),
    event('/tmp/generated-tool', 21, '5000000'),
  ], { ...selector, runId: 'run-two', baseline });
  assert.equal(second.expectedCount, 1);
  assert.equal(second.unknownCount, 1);
  assert.equal(second.executables.find((entry) => entry.path === '/usr/bin/node').classification, 'expected');
  assert.equal(second.executables.find((entry) => entry.path === '/tmp/generated-tool').action, 'allow-and-alert');

  assert.throws(
    () => validateExecutableInventory({ ...second, unknownCount: 99 }),
    /digest does not match/,
  );

  const relative = projectExecutableInventory([
    event('./workspace-tool', 22, '6000000'),
  ], { ...selector, runId: 'run-relative' });
  assert.equal(relative.executables[0].path, './workspace-tool');
  assert.equal(relative.executables[0].classification, 'unknown');
});

test('active executable baselines are image/workspace-bound trusted files', async (t) => {
  const root = tempDir(t);
  const {
    ExecutableBaselineStore,
    createExecutableBaselineDraft,
    executableBaselineDigest,
    projectExecutableInventory,
    validateExecutableBaseline,
  } = await baselineModule();
  const trustedUid = typeof process.geteuid === 'function' ? process.geteuid() : 0;
  const selector = {
    runId: 'run-store',
    workspaceKey: 'c'.repeat(64),
    imageDigest: `sha256:${'d'.repeat(64)}`,
    complete: true,
    generatedAt: '2026-10-07T00:00:00.000Z',
  };
  const inventory = projectExecutableInventory([
    event('/usr/bin/node', 30, '1000000'),
  ], selector);
  const baseline = createExecutableBaselineDraft(inventory, {
    createdAt: '2026-10-07T00:00:01.000Z',
    reviewedAt: '2026-10-07T00:00:02.000Z',
    reviewer: 'Root reviewer',
    acknowledged: true,
  });
  const store = new ExecutableBaselineStore({ stateDir: root, trustedUid });
  const activated = await store.activate(baseline);
  assert.equal(fs.statSync(activated.filePath).mode & 0o777, 0o600);
  const loaded = await store.loadActive(selector);
  assert.deepEqual(loaded.document, validateExecutableBaseline(baseline, selector));
  assert.equal(executableBaselineDigest(loaded.document), executableBaselineDigest(baseline));
  assert.equal(await store.loadActive({
    ...selector,
    imageDigest: `sha256:${'e'.repeat(64)}`,
  }), null);
  assert.throws(
    () => validateExecutableBaseline(baseline, {
      ...selector,
      workspaceKey: 'f'.repeat(64),
    }),
    /another workspace/,
  );

  fs.chmodSync(activated.filePath, 0o644);
  await assert.rejects(
    store.loadActive(selector),
    /trusted regular file/,
  );
  fs.chmodSync(activated.filePath, 0o600);

  const replacement = path.join(root, 'replacement.json');
  fs.renameSync(activated.filePath, replacement);
  fs.symlinkSync(replacement, activated.filePath);
  await assert.rejects(store.loadActive(selector), /trusted regular file/);
});

test('executable baseline CLI pins reviewed bytes and reports advisory status', async (t) => {
  const root = tempDir(t);
  const {
    ExecutableBaselineStore,
    createExecutableBaselineDraft,
    projectExecutableInventory,
  } = await baselineModule();
  const { commandExecutables } = await cliModule();
  const trustedUid = typeof process.geteuid === 'function' ? process.geteuid() : 0;
  const selector = {
    runId: 'run-cli',
    workspaceKey: '1'.repeat(64),
    imageDigest: `sha256:${'2'.repeat(64)}`,
    complete: true,
    generatedAt: '2026-10-07T00:00:00.000Z',
  };
  const inventory = projectExecutableInventory([
    event('/usr/bin/node', 40, '1000000'),
  ], selector);
  const baseline = createExecutableBaselineDraft(inventory, {
    createdAt: '2026-10-07T00:00:01.000Z',
    reviewedAt: '2026-10-07T00:00:02.000Z',
    reviewer: 'CLI reviewer',
    acknowledged: true,
  });
  const source = Buffer.from(`${JSON.stringify(baseline, null, 2)}\n`);
  const sourceDigest = `sha256:${crypto.createHash('sha256').update(source).digest('hex')}`;
  const baselinePath = path.join(root, 'reviewed-baseline.json');
  fs.writeFileSync(baselinePath, source, { mode: 0o600 });
  const store = new ExecutableBaselineStore({ stateDir: root, trustedUid });
  const receipts = [];
  const dependencies = {
    geteuid: () => 0,
    invokingUser: { uid: trustedUid },
    workspaceKey: async () => selector.workspaceKey,
    store,
    print(value) { receipts.push(value); },
  };

  assert.equal(await commandExecutables([
    'activate',
    '--workdir', root,
    '--image-digest', selector.imageDigest,
    '--baseline', baselinePath,
    '--baseline-digest', sourceDigest,
  ], dependencies), 0);
  assert.equal(receipts[0].kind, 'NoshExecutableBaselineActivationReceipt');
  assert.equal(receipts[0].sourceDigest, sourceDigest);
  assert.equal(receipts[0].policyUse, 'observation-only');
  assert.equal(receipts[0].enforcing, false);

  assert.equal(await commandExecutables([
    'status',
    '--workdir', root,
    '--image-digest', selector.imageDigest,
    '--json',
  ], dependencies), 0);
  assert.equal(receipts[1].active, true);
  assert.deepEqual(receipts[1].baseline.executables, ['/usr/bin/node']);
  assert.equal(receipts[1].unknownAction, 'allow-and-alert');

  await assert.rejects(commandExecutables([
    'activate',
    '--workdir', root,
    '--image-digest', selector.imageDigest,
    '--baseline', baselinePath,
    '--baseline-digest', `sha256:${'f'.repeat(64)}`,
  ], dependencies), /digest changed before activation/);
});
