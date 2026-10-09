'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs/promises');
const os = require('node:os');
const path = require('node:path');
const crypto = require('node:crypto');
const { DatabaseSync } = require('node:sqlite');
const hash = value => crypto.createHash('sha256').update(value).digest('hex');

async function fixture(t) {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), 'nosh-request-evidence-'));
  const filename = path.join(root, 'requests.sqlite3');
  const group = hash('group');
  const db = new DatabaseSync(filename);
  db.exec(`PRAGMA user_version=1; CREATE TABLE requests (id TEXT PRIMARY KEY, group_id TEXT, tool TEXT,
    input_json TEXT, cwd TEXT, occurrences INTEGER, source TEXT, line INTEGER);`);
  const insert = db.prepare('INSERT INTO requests VALUES (?,?,?,?,?,?,?,?)');
  for (let i = 0; i < 125; i++) insert.run(hash(String(i)), group, 'exec_command',
    JSON.stringify({ cmd: `sed --sandbox -n '${i}p' file` }), '/workspace', 2, 'source', i + 1);
  db.close();
  await fs.chmod(filename, 0o600);
  const bytes = await fs.readFile(filename);
  const snapshot = { digest: 'sha256:' + hash(bytes), groups: [{ id: group, count: 250 }], requestEvidence: {
    schemaVersion: 1, file: 'requests.sqlite3', digest: 'sha256:' + hash(bytes), bytes: bytes.length,
    uniqueRequests: 125, recordedRequests: 250, originalInputs: true,
  } };
  const old = process.env.NOTTY_TOOL_REVIEW_INPUT_DIR;
  process.env.NOTTY_TOOL_REVIEW_INPUT_DIR = root;
  t.after(async () => {
    if (old === undefined) delete process.env.NOTTY_TOOL_REVIEW_INPUT_DIR; else process.env.NOTTY_TOOL_REVIEW_INPUT_DIR = old;
    await fs.rm(root, { recursive: true, force: true });
  });
  return { root, filename, snapshot, group };
}

test('unique evidence paginates all inputs and searches beyond the first page', async t => {
  const { requestEvidence } = await import('../modules/tool-review/evidence.js');
  const { snapshot, group } = await fixture(t);
  const first = await requestEvidence(snapshot, { group });
  const last = await requestEvidence(snapshot, { group, page: '2' });
  assert.equal(first.total, 125);
  assert.equal(first.occurrences, 250);
  assert.equal(first.entries.length, 50);
  assert.equal(last.entries.length, 25);
  assert.equal(new Set([...first.entries, ...last.entries].map(row => row.id)).size, 75);
  const filtered = await requestEvidence(snapshot, { command: 'sed', switch: '-n', q: '124p', input: 'files' });
  assert.equal(filtered.total, 1);
  const full = await requestEvidence(snapshot, { id: filtered.entries[0].id });
  assert.match(full.input, /124p/);
  assert.equal(full.nextOffset, null);
  await assert.rejects(requestEvidence(snapshot, { group: "' OR 1=1" }), /Unknown group/);
});

test('evidence modifications, missing files, links and mismatched counts fail closed', async t => {
  const { requestEvidence } = await import('../modules/tool-review/evidence.js');
  const { filename, snapshot } = await fixture(t);
  await requestEvidence(snapshot, {});
  await fs.chmod(filename, 0o644);
  await assert.rejects(requestEvidence(snapshot, {}), /private/);
  await fs.chmod(filename, 0o600);
  await assert.rejects(requestEvidence({ ...snapshot, requestEvidence: { ...snapshot.requestEvidence, uniqueRequests: 2 }, digest: 'changed' }, {}), /counts/);
  await fs.appendFile(filename, 'modified');
  await assert.rejects(requestEvidence(snapshot, {}), /private/);
  await fs.unlink(filename);
  await assert.rejects(requestEvidence(snapshot, {}));
});
