'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs/promises');
const os = require('node:os');
const path = require('node:path');
const crypto = require('node:crypto');
const { Readable } = require('node:stream');
const modules = Promise.all([
  import('../modules/tool-review/model.js'),
  import('../modules/tool-review/storage.js'),
  import('../pages/api/tool-review.js'),
]);

async function fixture(t, complete = true, historyScope = null) {
  const [, storage] = await modules;
  const root = await fs.mkdtemp(path.join(os.tmpdir(), 'nosh-tool-review-'));
  const output = path.join(root, 'review');
  await fs.mkdir(output, { mode: 0o700 });
  const totals = { raw_requests: 7, unique_requests: 5, duplicate_requests: 2, allow_requests: 3, 'not-yet_requests': 2 };
  const group = (form, count) => ({ tool: 'exec_command', form, reason: 'reason', count,
    examples: [{ source: 'sessions/rollout-example.jsonl', line: 1 }] });
  const inputs = {
    'allow.json': { schema_version: 1, category: 'allow', complete, totals, entries: [group('ls', 3)] },
    'not-yet.json': { schema_version: 1, category: 'not-yet', complete, totals, entries: [group('rm', 2)] },
    'rules-review.json': { entries: [{ source: 'user/rules/default.rules', line: 3, executable: 'sh', prefix_tokens: 1,
      decision: 'allow', needs_review: true, reason: 'sandbox-escape-allow' }], errors: {} },
    'planning.config.toml': 'sandbox_mode = "read-only"\n',
    'implementation.config.toml': 'sandbox_mode = "workspace-write"\n',
  };
  if (historyScope) {
    inputs['allow.json'].history_scope = historyScope;
    inputs['not-yet.json'].history_scope = historyScope;
  }
  const hashes = [];
  for (const name of storage.INPUT_FILES) {
    const bytes = typeof inputs[name] === 'string' ? inputs[name] : JSON.stringify(inputs[name]);
    await fs.writeFile(path.join(root, name), bytes, { mode: 0o600 });
    hashes.push(`${name}\0${crypto.createHash('sha256').update(bytes).digest('hex')}\n`);
  }
  const session = { kind: 'NoshToolReviewSession', schemaVersion: 1, origin: 'http://127.0.0.1:43123', token: 'a'.repeat(64),
    snapshotDigest: `sha256:${crypto.createHash('sha256').update(hashes.join('')).digest('hex')}` };
  const sessionFile = path.join(root, 'session.json');
  await fs.writeFile(sessionFile, JSON.stringify(session), { mode: 0o600 });
  const environment = { NOTTY_TOOL_REVIEW_SESSION_FILE: sessionFile,
    NOTTY_TOOL_REVIEW_INPUT_DIR: root, NOTTY_TOOL_REVIEW_OUTPUT_DIR: output };
  const old = Object.fromEntries(Object.keys(environment).map(key => [key, process.env[key]]));
  Object.assign(process.env, environment);
  t.after(async () => {
    for (const [key, value] of Object.entries(old)) {
      if (value === undefined) delete process.env[key]; else process.env[key] = value;
    }
    await fs.rm(root, { recursive: true, force: true });
  });
  return { root, output, session, snapshot: await storage.loadSnapshot(session) };
}

async function call(session, document, headers = {}, method = document ? 'POST' : 'GET') {
  const [, , { default: handler }] = await modules;
  const request = Readable.from(document ? [Buffer.from(JSON.stringify(document))] : []);
  request.method = method;
  request.headers = { host: '127.0.0.1:43123', authorization: `Bearer ${session.token}`, ...headers };
  const response = { headers: {}, statusCode: 200,
    setHeader(key, value) { this.headers[key] = value; },
    end(value) { this.document = JSON.parse(value); } };
  await handler(request, response);
  return response;
}

function completed(model, snapshot) {
  const draft = model.decideGroups(model.emptyDraft(snapshot), snapshot.groups.map(group => group.id), 'expected');
  return { ...draft, kind: 'NoshToolReviewProposal', reviewer: 'Test reviewer', acknowledged: true,
    completedAt: '2026-10-04T00:00:00.000Z' };
}

test('group suggestions remain unconfirmed; filter and bulk choices affect only selected forms', async t => {
  const [model] = await modules;
  const { snapshot } = await fixture(t);
  const draft = model.emptyDraft(snapshot);
  assert.ok(Object.values(draft.decisions).every(value => value.choice === 'unreviewed'));
  const selected = model.filteredGroups(snapshot.groups, draft, { query: 'ls', remaining: true });
  assert.equal(selected.length, 1);
  const changed = model.decideGroups({ ...draft, acknowledged: true }, selected.map(group => group.id), 'expected', 'Reviewed');
  assert.equal(changed.acknowledged, false);
  assert.equal(model.filteredGroups(snapshot.groups, changed, { remaining: true }).length, 1);
  assert.equal(model.filteredGroups(snapshot.groups, changed, { choice: 'expected', tool: 'exec_command' }).length, 1);
  assert.notEqual(model.fingerprint(draft), model.fingerprint(changed));
  assert.throws(() => model.decideGroups(draft, ['unknown'], 'investigate'), /Unknown group/);
});

test('same-snapshot imports, completed proposals, and invalid decisions are validated', async t => {
  const [model] = await modules;
  const { snapshot } = await fixture(t);
  const document = completed(model, snapshot);
  assert.equal(model.validateDocument(document, snapshot, true).enforcing, false);
  assert.equal(model.importDraft(document, snapshot).kind, 'NoshToolReviewDraft');
  assert.equal(model.fingerprint(model.importDraft(document, snapshot)), model.fingerprint(document));
  for (const invalid of [
    { ...document, snapshotDigest: 'foreign' }, { ...document, enforcing: true },
    { ...document, acknowledged: false }, { ...document, reviewer: '' },
    { ...document, decisions: {} }, { ...document, decisions: { ...document.decisions, extra: { choice: 'investigate', note: '' } } },
    { ...document, decisions: { ...document.decisions, [snapshot.groups[0].id]: { choice: 'allow', note: '' } } },
    { ...document, decisions: { ...document.decisions, [snapshot.groups[0].id]: {
      choice: 'expected', legacyChoice: 'exclude', note: '',
    } } },
  ]) assert.throws(() => model.validateDocument(invalid, snapshot, true));
  assert.throws(() => model.validateDocument(document, { ...snapshot, complete: false }, true), /Complete the audit/);
});

test('legacy permission reviews remain readable and retain their original choices', async t => {
  const [model, storage] = await modules;
  const { snapshot, root, output } = await fixture(t);
  const legacyChoices = ['read-only', 'exclude'];
  const legacy = {
    kind: 'NoshToolReviewProposal',
    schemaVersion: 1,
    enforcing: false,
    snapshotDigest: snapshot.digest,
    reviewer: 'Legacy reviewer',
    acknowledged: true,
    completedAt: '2026-10-04T00:00:00.000Z',
    decisions: Object.fromEntries(snapshot.groups.map((group, index) => [
      group.id,
      { choice: legacyChoices[index], note: '' },
    ])),
  };
  const migrated = model.validateDocument(legacy, snapshot, true);
  assert.equal(migrated.schemaVersion, 2);
  assert.deepEqual(
    Object.values(migrated.decisions).map(({ choice, legacyChoice }) => ({ choice, legacyChoice })),
    [
      { choice: 'expected', legacyChoice: 'read-only' },
      { choice: 'investigate', legacyChoice: 'exclude' },
    ],
  );
  const original = `${JSON.stringify(legacy)}\n`;
  await fs.writeFile(path.join(output, 'proposal.json'), original, { mode: 0o600 });
  assert.deepEqual(await storage.readSaved('proposal.json', snapshot), migrated);
  assert.equal(await fs.readFile(path.join(output, 'proposal.json'), 'utf8'), original);

  const { LIMITATIONS } = await import('../modules/tool-review/environment.js');
  const environment = {
    kind: 'NoshEnvironmentPolicy',
    schemaVersion: 1,
    snapshotDigest: snapshot.digest,
    proposalDigest: await storage.proposalDigest(snapshot),
    workspace: root,
    workload: 'dev',
    allowImplementation: false,
    defaultMode: 'read-only',
    policyReadOnly: true,
    toolSelectionsInformational: true,
    limitations: LIMITATIONS,
    reviewer: 'Legacy reviewer',
    acknowledged: true,
    approvedAt: '2026-10-04T00:01:00.000Z',
  };
  await storage.saveDocument('environment-policy.json', environment, snapshot);
  const policyPath = path.join(output, 'environment-policy.json');
  const policyBytes = await fs.readFile(policyPath);
  const policyDigest = `sha256:${crypto.createHash('sha256').update(policyBytes).digest('hex')}`;
  const helper = path.resolve(__dirname, '../../scripts/nosh-tool-policy.py');
  if (require('node:fs').existsSync(helper)) {
    const { spawnSync } = require('node:child_process');
    const checked = spawnSync('python3', [helper, 'check', '--review', root,
      '--workdir', root, '--policy-digest', policyDigest], { encoding: 'utf8' });
    assert.equal(checked.status, 0, checked.stderr);
  }
});

test('managed save and reload persist private drafts/proposals without changing audit inputs', async t => {
  const [model, storage] = await modules;
  const { snapshot, session, root, output } = await fixture(t);
  const before = await fs.readFile(path.join(root, 'allow.json'));
  const draft = model.emptyDraft(snapshot);
  assert.equal((await call(session, draft)).statusCode, 201);
  const proposal = completed(model, snapshot);
  assert.equal((await call(session, proposal)).statusCode, 201);
  const reloaded = await call(session);
  assert.equal(reloaded.statusCode, 200);
  assert.deepEqual(reloaded.document.draft, draft);
  assert.deepEqual(reloaded.document.proposal, proposal);
  assert.equal(reloaded.headers['Cache-Control'], 'no-store');
  assert.equal((await fs.stat(path.join(output, 'draft.json'))).mode & 0o777, 0o600);
  assert.deepEqual(before, await fs.readFile(path.join(root, 'allow.json')));
  assert.deepEqual((await fs.readdir(output)).sort(), ['draft.json', 'proposal.json']);
  await assert.rejects(storage.saveDocument('../outside', draft, snapshot), /Invalid save target/);
});

test('API rejects foreign/missing credentials, origins, methods, changed inputs and invalid imports', async t => {
  const [model] = await modules;
  const { snapshot, session, root } = await fixture(t);
  for (const headers of [{ authorization: '' }, { authorization: 'Bearer wrong' }, { host: 'evil.test' },
    { origin: 'http://evil.test' }, { 'sec-fetch-site': 'cross-site' }]) {
    assert.equal((await call(session, null, headers)).statusCode, 403);
  }
  assert.equal((await call(session, null, {}, 'DELETE')).statusCode, 405);
  const draft = model.emptyDraft(snapshot);
  assert.equal((await call(session, { ...draft, snapshotDigest: 'wrong' })).statusCode, 422);
  await fs.appendFile(path.join(root, 'allow.json'), ' ');
  const changed = await call(session);
  assert.equal(changed.statusCode, 422);
  assert.match(changed.document.error, /inputs changed/);
});

test('incomplete snapshots permit drafts but reject finalization', async t => {
  const [model] = await modules;
  const { snapshot, session } = await fixture(t, false);
  assert.equal((await call(session, model.emptyDraft(snapshot))).statusCode, 201);
  assert.equal((await call(session, completed(model, snapshot))).statusCode, 422);
});

test('storage rejects nonprivate files and symlinks; save failures preserve earlier choices', async t => {
  const [model, storage] = await modules;
  const { snapshot, session, root, output } = await fixture(t);
  const draft = model.emptyDraft(snapshot);
  await storage.saveDocument('draft.json', draft, snapshot);
  await fs.chmod(output, 0o755);
  await assert.rejects(storage.saveDocument('draft.json', model.decideGroups(draft, [snapshot.groups[0].id], 'investigate'), snapshot), /private/);
  await fs.chmod(output, 0o700);
  assert.deepEqual(await storage.readSaved('draft.json', snapshot), draft);
  await fs.chmod(path.join(root, 'allow.json'), 0o644);
  await assert.rejects(storage.loadSnapshot(session), /private/);
  await fs.chmod(path.join(root, 'allow.json'), 0o600);
  await fs.rename(path.join(root, 'allow.json'), path.join(root, 'original.json'));
  await fs.symlink(path.join(root, 'original.json'), path.join(root, 'allow.json'));
  await assert.rejects(storage.loadSnapshot(session));
});

test('large inventories filter and round-trip within the save limit', async () => {
  const [model] = await modules;
  const snapshot = { digest: `sha256:${'b'.repeat(64)}`, complete: true,
    groups: Array.from({ length: 10000 }, (_, index) => ({ id: `group-${index}`, tool: `tool-${index % 10}`, form: `command-${index}`, reason: 'test' })) };
  let draft = model.emptyDraft(snapshot);
  const selected = model.filteredGroups(snapshot.groups, draft, { tool: 'tool-0' });
  assert.equal(selected.length, 1000);
  draft = model.decideGroups(draft, selected.map(group => group.id), 'investigate');
  assert.equal(model.filteredGroups(snapshot.groups, draft, { remaining: true }).length, 9000);
  assert.deepEqual(model.importDraft(JSON.parse(JSON.stringify(draft)), snapshot), draft);
});

test('environment approval is bound to a completed proposal and produces the saved file digest', async t => {
  const [model, storage] = await modules;
  const { LIMITATIONS } = await import('../modules/tool-review/environment.js');
  const { root, snapshot, session } = await fixture(t, true, { kind: 'repo', root: '/selected/repo', dates: 'all', excluded_roots: [], excluded_requests: 2, unattributed_requests: 0 });
  const document = { kind: 'NoshEnvironmentPolicy', schemaVersion: 1, snapshotDigest: snapshot.digest,
    proposalDigest: `sha256:${'0'.repeat(64)}`, workspace: root, workload: 'dev', allowImplementation: false,
    defaultMode: 'read-only', policyReadOnly: true, toolSelectionsInformational: true, limitations: LIMITATIONS,
    reviewer: 'Operator', acknowledged: true, approvedAt: '2026-10-04T00:00:00.000Z' };
  assert.equal((await call(session, document)).statusCode, 422);
  await storage.saveDocument('proposal.json', completed(model, snapshot), snapshot);
  document.proposalDigest = (await call(session, { kind: 'NoshEnvironmentDigestRequest' })).document.proposalDigest;
  assert.equal((await call(session, { ...document, policyReadOnly: false })).statusCode, 422);
  const response = await call(session, document);
  assert.equal(response.statusCode, 201);
  const saved = await fs.readFile(path.join(root, 'review/environment-policy.json'));
  assert.equal(response.document.policyDigest, `sha256:${crypto.createHash('sha256').update(saved).digest('hex')}`);
  // The standalone UI Docker context contains neither Python nor the host authority.
  // Full-checkout runs additionally check interoperability with that authority.
  const helper = path.resolve(__dirname, '../../scripts/nosh-tool-policy.py');
  await t.test('host policy checker accepts the UI document', {
    skip: require('node:fs').existsSync(helper) ? false : 'host helper is outside the standalone UI build context',
  }, () => {
    const { spawnSync } = require('node:child_process');
    const checked = spawnSync('python3', [helper, 'check', '--review', root, '--workdir', root,
      '--policy-digest', response.document.policyDigest], { encoding: 'utf8' });
    assert.equal(checked.status, 0, checked.stderr);
    assert.equal(JSON.parse(checked.stdout).policyDigest, response.document.policyDigest);
  });
  await storage.saveDocument('proposal.json', { ...completed(model, snapshot), reviewer: 'Different reviewer' }, snapshot);
  assert.equal((await call(session, document)).statusCode, 422);
});

test('scope provenance reaches review, changes its digest, and incomplete attribution blocks proposals', async t => {
  const [model] = await modules;
  const scope = { kind: 'directory', root: '/selected/workspace', dates: 'all', excluded_roots: [],
    excluded_requests: 11, unattributed_requests: 0 };
  let original;
  await t.test('complete scoped evidence', async t => {
    const selected = await fixture(t, true, scope);
    assert.deepEqual(selected.snapshot.historyScope, scope);
    original = selected.snapshot.digest;
  });
  await t.test('missing scoped attribution', async t => {
    const incomplete = await fixture(t, true, { ...scope, unattributed_requests: 1 });
    assert.notEqual(incomplete.snapshot.digest, original);
    assert.equal(incomplete.snapshot.complete, false);
    assert.throws(() => model.validateDocument(completed(model, incomplete.snapshot), incomplete.snapshot, true));
  });
  await t.test('all-history retains unattributed requests', async t => {
    const all = await fixture(t, true, { ...scope, kind: 'all', root: null, excluded_requests: 0, unattributed_requests: 1 });
    assert.equal(all.snapshot.complete, true);
    assert.equal(all.snapshot.historyScope.unattributed_requests, 1);
  });
});
