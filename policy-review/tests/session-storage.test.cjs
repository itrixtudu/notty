const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs/promises');
const os = require('node:os');
const path = require('node:path');

test('managed draft writes are private, atomic, bounded and survive reload', async t => {
  const storage = await import('../modules/policy-review/sessionStorage.js');
  const directory = await fs.mkdtemp(path.join(os.tmpdir(), 'nosh-review-session-'));
  const previous = process.env.NOTTY_POLICY_REVIEW_DECISIONS_DIR;
  process.env.NOTTY_POLICY_REVIEW_DECISIONS_DIR = directory;
  t.after(async () => {
    if (previous === undefined) delete process.env.NOTTY_POLICY_REVIEW_DECISIONS_DIR;
    else process.env.NOTTY_POLICY_REVIEW_DECISIONS_DIR = previous;
    await fs.rm(directory, { recursive: true, force: true });
  });
  const draft = { kind: 'NoshPolicyReviewDraft', decisions: { endpoint: 'accept' } };
  const result = await storage.saveReviewFile('draft.json', draft, { directory: '/host/review' });
  assert.equal(result.path, '/host/review/decisions/draft.json');
  assert.deepEqual(await storage.readSavedReview('draft.json'), draft);
  assert.equal((await fs.stat(path.join(directory, 'draft.json'))).mode & 0o777, 0o600);
  await assert.rejects(storage.saveReviewFile('draft.json', { text: 'x'.repeat(storage.MAX_SAVED_REVIEW_BYTES) }, null), /8 MiB/);
  assert.deepEqual(await storage.readSavedReview('draft.json'), draft);
  assert.deepEqual(await fs.readdir(directory), ['draft.json']);
  await fs.symlink(path.join(directory, 'draft.json'), path.join(directory, 'link.json'));
  await assert.rejects(storage.readSavedReview('link.json'));
});
