'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { createResumeStore } = require('../lib/collab/resume-store.cjs');
const { terminalSnapshot } = require('../lib/terminalSnapshot.cjs');

function fixture(t) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'notty-resume-'));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  return { root, store: createResumeStore(root) };
}
test('task index is private, project-bound and retains independently named tasks', (t) => {
  const { root, store } = fixture(t);
  assert.equal(store.read().tasks.length, 0);
  const first = store.createTask('First');
  const second = store.createTask('Second');
  assert.equal(second.tasks.length, 2);
  assert.notEqual(first.lastTaskId, second.lastTaskId);
  assert.equal(second.autoResume, false);
  assert.equal(fs.statSync(store.filename).mode & 0o777, 0o600);
  assert.equal(fs.statSync(path.join(root, '.notty')).mode & 0o777, 0o700);
  assert.deepEqual(createResumeStore(root).read(), second);
  assert.throws(() => store.update((doc) => { doc.project = '/wrong'; }), /project/);
  assert.deepEqual(store.read(), second);
});
test('task index rejects symlinks, hardlinks, permissions and malformed state', (t) => {
  const { root, store } = fixture(t);
  store.createTask('Task');
  fs.chmodSync(store.filename, 0o644);
  assert.throws(() => store.read(), /unsafe/);
  fs.chmodSync(store.filename, 0o600);
  const alias = path.join(root, 'alias');
  fs.linkSync(store.filename, alias);
  assert.throws(() => store.read(), /unsafe/);
  fs.unlinkSync(alias);
  fs.renameSync(store.filename, alias);
  fs.symlinkSync(alias, store.filename);
  assert.throws(() => store.read(), /unsafe/);
  fs.unlinkSync(store.filename);
  fs.renameSync(alias, store.filename);
  fs.writeFileSync(store.filename, '{bad');
  assert.throws(() => store.read(), SyntaxError);
});
test('task writes reject contention without replacing state', (t) => {
  const { store } = fixture(t);
  const before = store.createTask('Task');
  fs.writeFileSync(`${store.filename}.lock`, '', { mode: 0o600 });
  assert.throws(() => store.createTask('Another'), /EEXIST/);
  assert.deepEqual(store.read(), before);
});
test('terminal snapshots preserve Unicode and bound newest scrollback by lines and bytes', () => {
  const values = ['old', 'αβ', '😀', 'new'];
  const buffer = { length: values.length, getLine: (index) => ({ translateToString: () => values[index] }) };
  assert.deepEqual(terminalSnapshot(buffer), { text: values.join('\n'), truncated: false });
  assert.deepEqual(terminalSnapshot(buffer, 2), { text: '😀\nnew', truncated: true });
  assert.deepEqual(terminalSnapshot(buffer, 100, 4), { text: 'new', truncated: true });
});
