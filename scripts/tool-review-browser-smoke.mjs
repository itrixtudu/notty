#!/usr/bin/env node
// Run inside a container, after building policy-review. Playwright is an optional
// external test dependency; NOSH_PLAYWRIGHT_MODULE can point to its index.mjs.
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import net from 'node:net';
import crypto from 'node:crypto';
import { spawn, spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const { chromium } = await import(process.env.NOSH_PLAYWRIGHT_MODULE || 'playwright');
const repository = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const app = path.join(repository, 'policy-review');
const root = await fs.mkdtemp(path.join(os.tmpdir(), 'tool-review-browser-'));
const screenshots = process.env.NOSH_TOOL_REVIEW_SCREENSHOTS || path.join(os.tmpdir(), 'nosh-tool-review-screenshots');
await fs.mkdir(screenshots, { recursive: true });
const output = path.join(root, 'review');
await fs.mkdir(output, { mode: 0o700 });
const token = crypto.randomBytes(32).toString('hex');
const entries = Array.from({ length: 125 }, (_, index) => ({
  tool: index < 65 ? 'exec_command' : 'shell_command', form: `command-${String(index).padStart(3, '0')}`,
  reason: index < 25 ? 'local-inspection-in-sandbox' : 'runtime-or-wrapper-needs-review', count: index + 1,
  examples: [{ source: 'sessions/2026/10/04/rollout-example.jsonl', line: index + 1 }],
}));
const count = rows => rows.reduce((sum, row) => sum + row.count, 0);
const totals = { raw_requests: count(entries), unique_requests: count(entries), duplicate_requests: 0,
  allow_requests: count(entries.slice(0, 25)), 'not-yet_requests': count(entries.slice(25)) };
const files = {
  'allow.json': JSON.stringify({ schema_version: 1, category: 'allow', complete: true, history_scope: { kind: 'directory', root, dates: 'all', excluded_roots: [], excluded_requests: 3, unattributed_requests: 0 }, totals, entries: entries.slice(0, 25) }),
  'not-yet.json': JSON.stringify({ schema_version: 1, category: 'not-yet', complete: true, history_scope: { kind: 'directory', root, dates: 'all', excluded_roots: [], excluded_requests: 3, unattributed_requests: 0 }, totals, entries: entries.slice(25) }),
  'rules-review.json': JSON.stringify({ entries: [{ source: 'user/rules/default.rules', line: 2,
    executable: 'python3', prefix_tokens: 1, decision: 'allow', needs_review: true, reason: 'sandbox-escape-allow' }], errors: {} }),
  'planning.config.toml': 'sandbox_mode = "read-only"\napproval_policy = "never"\n',
  'implementation.config.toml': 'sandbox_mode = "workspace-write"\napproval_policy = "on-request"\n',
};
for (const [name, content] of Object.entries(files)) await fs.writeFile(path.join(root, name), content, { mode: 0o600 });
const digestInput = Object.entries(files).map(([name, content]) => `${name}\0${crypto.createHash('sha256').update(content).digest('hex')}\n`).join('');
const snapshotDigest = `sha256:${crypto.createHash('sha256').update(digestInput).digest('hex')}`;
// Verify the Python launcher and JS reader agree on actual file bytes.
const python = spawnSync('python3', ['-B', '-c',
  'import importlib.util,sys; from pathlib import Path; s=importlib.util.spec_from_file_location("launcher",sys.argv[1]); m=importlib.util.module_from_spec(s); s.loader.exec_module(m); print(m.snapshot_digest(Path(sys.argv[2])))',
  path.join(repository, 'scripts/review-codex-tools.py'), root], { encoding: 'utf8' });
assert.equal(python.status, 0, python.stderr);
assert.equal(python.stdout.trim(), snapshotDigest);
const reservation = net.createServer();
await new Promise(resolve => reservation.listen(0, '127.0.0.1', resolve));
const port = reservation.address().port;
await new Promise(resolve => reservation.close(resolve));
const origin = `http://127.0.0.1:${port}`;
await fs.writeFile(path.join(root, 'session.json'), JSON.stringify({ kind: 'NoshToolReviewSession', schemaVersion: 1,
  origin, token, snapshotDigest }), { mode: 0o600 });
const server = spawn(process.execPath, [path.join(app, 'node_modules/next/dist/bin/next'), 'start', '--hostname', '127.0.0.1', '--port', String(port)], {
  cwd: app, env: { ...process.env, NODE_ENV: 'production', NOTTY_TOOL_REVIEW_SESSION_FILE: path.join(root, 'session.json'),
    NOTTY_TOOL_REVIEW_INPUT_DIR: root, NOTTY_TOOL_REVIEW_OUTPUT_DIR: output }, stdio: ['ignore', 'pipe', 'pipe'],
});
let serverLog = '';
server.stdout.on('data', data => { serverLog += data; });
server.stderr.on('data', data => { serverLog += data; });
let browser;
const sleep = milliseconds => new Promise(resolve => setTimeout(resolve, milliseconds));
async function eventually(check) {
  for (let i = 0; i < 100; i++) {
    try { if (await check()) return; } catch { /* Wait for async UI/save. */ }
    await sleep(100);
  }
  throw new Error('Timed out waiting for expected browser state.');
}
try {
  await eventually(async () => (await fetch(`${origin}/tool-review`)).ok);
  browser = await chromium.launch({ headless: true, args: ['--no-sandbox'] });
  const page = await browser.newPage({ viewport: { width: 1440, height: 1100 } });
  const errors = [];
  page.on('pageerror', error => errors.push(error.message));
  await page.goto(`${origin}/tool-review#token=${token}`);
  await page.getByRole('heading', { name: 'Observed activity' }).waitFor();
  await page.getByRole('region', { name: 'History scope' }).getByText(/Directory and subdirectories/).waitFor();
  assert.equal(new URL(page.url()).hash, '');
  assert.equal(await page.getByLabel(/^Activity classification for/).count(), 50);
  assert.equal(await page.getByLabel(/^Activity classification for/).first().inputValue(), 'unreviewed');
  await page.getByRole('button', { name: 'Review selections', exact: true }).click();
  assert.equal(await page.getByRole('button', { name: 'Save reviewed proposal' }).isEnabled(), false);
  await page.getByRole('button', { name: 'Review selections', exact: true }).click();
  await page.getByLabel('Filter by tool', { exact: true }).selectOption('exec_command');
  await page.getByLabel('Select all filtered forms across pages').check();
  await page.getByRole('button', { name: 'Next', exact: true }).click();
  assert.equal(await page.getByLabel(/^Select command-/).count(), 15);
  assert.equal(await page.getByLabel(/^Select command-/).first().isChecked(), true);
  await page.getByRole('button', { name: 'Apply choice to selected' }).click();
  await eventually(async () => {
    const draft = JSON.parse(await fs.readFile(path.join(output, 'draft.json'), 'utf8'));
    return Object.values(draft.decisions).filter(value => value.choice === 'expected').length === 65;
  });
  await page.reload();
  await page.getByRole('heading', { name: 'Observed activity' }).waitFor();
  assert.equal(await page.getByLabel(/^Activity classification for/).first().inputValue(), 'expected');
  await page.getByRole('button', { name: 'Show remaining', exact: true }).click();
  await page.getByLabel('Select all filtered forms across pages').check();
  await page.getByLabel('Bulk activity classification').selectOption('investigate');
  // Real API save failure; selections remain available for retry and download.
  await fs.chmod(output, 0o755);
  await page.getByRole('button', { name: 'Apply choice to selected' }).click();
  await page.getByRole('button', { name: 'Retry save' }).waitFor();
  await page.getByText('No forms match these filters.').waitFor();
  await fs.chmod(output, 0o700);
  await page.getByRole('button', { name: 'Retry save' }).click();
  await eventually(async () => {
    const draft = JSON.parse(await fs.readFile(path.join(output, 'draft.json'), 'utf8'));
    return Object.values(draft.decisions).filter(value => value.choice === 'investigate').length === 60;
  });
  await page.getByRole('button', { name: 'Show all forms', exact: true }).click();
  await page.getByRole('button', { name: 'Review selections', exact: true }).click();
  await page.getByRole('textbox', { name: 'Reviewer name' }).fill('Browser smoke reviewer');
  const acknowledgement = page.getByRole('checkbox', { name: /I reviewed these classifications/ });
  await acknowledgement.check();
  await page.getByRole('button', { name: 'Save reviewed proposal' }).click();
  await page.getByText('Reviewed activity proposal saved. Runtime capabilities are unchanged.').waitFor();
  const finalized = JSON.parse(await fs.readFile(path.join(output, 'proposal.json'), 'utf8'));
  assert.equal(finalized.enforcing, false);
  assert.equal(finalized.snapshotDigest, snapshotDigest);
  await page.getByLabel('Policy workspace').fill(root);
  await page.getByRole('checkbox', { name: /Allow implementation mode/ }).check();
  await page.getByRole('checkbox', { name: /I approve these environment permissions/ }).check();
  await page.getByRole('button', { name: 'Save environment policy' }).click();
  await page.getByText('Environment policy saved for host review and apply. Existing containers are unchanged.').waitFor();
  const environmentPolicy = JSON.parse(await fs.readFile(path.join(output, 'environment-policy.json'), 'utf8'));
  assert.equal(environmentPolicy.policyReadOnly, true);
  assert.equal(environmentPolicy.allowImplementation, true);
  assert.equal(environmentPolicy.toolSelectionsInformational, true);

  await page.getByRole('button', { name: 'Review selections', exact: true }).click();
  await page.evaluate(() => window.scrollTo(0, 0));
  await page.screenshot({ path: path.join(screenshots, 'tool-review-desktop.png') });
  await page.getByRole('button', { name: 'Review selections', exact: true }).click();
  await page.getByText('More options', { exact: true }).click();
  const downloading = page.waitForEvent('download');
  await page.getByRole('button', { name: 'Download reviewed proposal' }).click();
  const downloaded = await downloading;
  assert.equal(downloaded.suggestedFilename(), 'tool-review-proposal.json');
  await page.getByLabel(/^Activity classification for/).first().selectOption('investigate');
  await page.getByText('Selections changed — save a new proposal').waitFor();
  assert.equal(await page.getByRole('button', { name: 'Download reviewed proposal' }).isEnabled(), false);
  assert.equal(await acknowledgement.isChecked(), false);
  const invalidFile = path.join(root, 'wrong-snapshot.json');
  await fs.writeFile(invalidFile, JSON.stringify({ ...finalized, snapshotDigest: 'wrong' }));
  await page.locator('input[type=file]').setInputFiles(invalidFile);
  await page.getByText(/Import failed: Invalid review or different audit snapshot/).waitFor();
  await page.locator('input[type=file]').setInputFiles(path.join(output, 'proposal.json'));
  await page.getByText('Imported selections. Review and acknowledge before saving a proposal.').waitFor();
  assert.equal(await acknowledgement.isChecked(), false);
  // Keyboard access and responsive layout.
  await page.getByLabel('Search command forms').focus();
  await page.keyboard.press('Tab');
  assert.equal(await page.getByLabel('Filter by tool', { exact: true }).evaluate(element => element === document.activeElement), true);
  await page.setViewportSize({ width: 390, height: 844 });
  await page.evaluate(() => window.scrollTo(0, 0));
  await page.screenshot({ path: path.join(screenshots, 'tool-review-mobile.png') });
  assert.equal(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth), true);
  assert.deepEqual(errors, []);
  console.log(`PASS: selection, pagination, autosave/reload, save failure/retry, finalize, environment approval, download/import, keyboard, mobile. Screenshots: ${screenshots}`);
} catch (error) {
  console.error(serverLog);
  throw error;
} finally {
  await browser?.close();
  server.kill('SIGTERM');
  await new Promise(resolve => server.exitCode !== null ? resolve() : server.once('exit', resolve));
  await fs.rm(root, { recursive: true, force: true });
}
