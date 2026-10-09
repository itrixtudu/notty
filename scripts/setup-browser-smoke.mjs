#!/usr/bin/env node
// Run inside a container after building policy-review; uses synthetic private state.
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import net from 'node:net';
import crypto from 'node:crypto';
import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { defaults } from '../policy-review/modules/setup/model.js';

const { chromium } = await import(process.env.NOSH_PLAYWRIGHT_MODULE || 'playwright');
const repo = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const app = path.join(repo, 'policy-review');
const root = await fs.mkdtemp(path.join(os.tmpdir(), 'nosh-setup-browser-'));
const config = path.join(root, 'profile');
const state = path.join(root, 'state');
const screenshots = process.env.NOSH_SETUP_SCREENSHOTS || '/tmp/nosh-setup-screenshots';
await fs.mkdir(config, { mode: 0o700 }); await fs.mkdir(state, { mode: 0o700 }); await fs.mkdir(screenshots, { recursive: true });
const reservation = net.createServer();
await new Promise(resolve => reservation.listen(0, '127.0.0.1', resolve));
const port = reservation.address().port;
await new Promise(resolve => reservation.close(resolve));
const origin = `http://127.0.0.1:${port}`;
const token = crypto.randomBytes(32).toString('hex');
const profile = defaults();
profile.settings.label = 'Example repository';
const document = { kind: 'NoshRepositoryProfile', schemaVersion: 1, revision: 1, profile };
for (const [filename, value] of [
  [path.join(config, 'profile.json'), document],
  [path.join(state, 'binding.json'), { workspace: { path: '/work/example', dev: '1', ino: '2' }, launcher: '/opt/notty/scripts/nosh.sh', scripts: '/opt/notty/scripts' }],
  [path.join(state, 'snapshot.json'), { kind: 'NoshRepositoryStatus', schemaVersion: 1, revision: 1, checkedAt: '2026-10-04T00:00:00Z', authoritative: false, workloads: { dev: { steps: { 7: { state: 'unknown', detail: 'Requires a privileged host check.' } } } } }],
  [path.join(root, 'session.json'), { kind: 'NoshSetupSession', schemaVersion: 1, origin, token }],
]) await fs.writeFile(filename, JSON.stringify(value), { mode: 0o600 });
const server = spawn(process.execPath, [path.join(app, 'node_modules/next/dist/bin/next'), 'start', '--hostname', '127.0.0.1', '--port', String(port)], {
  cwd: app, env: { ...process.env, NODE_ENV: 'production', NOTTY_SETUP_SESSION_FILE: path.join(root, 'session.json'), NOTTY_SETUP_PROFILE_DIR: config, NOTTY_SETUP_STATE_DIR: state }, stdio: ['ignore', 'pipe', 'pipe'],
});
let logs = '';
server.stdout.on('data', data => { logs += data; }); server.stderr.on('data', data => { logs += data; });
let browser;
const pause = milliseconds => new Promise(resolve => setTimeout(resolve, milliseconds));
async function eventually(check) {
  for (let i = 0; i < 100; i++) { try { if (await check()) return; } catch {} await pause(100); }
  throw new Error('Expected browser state not reached');
}
try {
  await eventually(async () => (await fetch(`${origin}/setup`)).ok);
  assert.equal((await fetch(`${origin}/api/setup`)).status, 403);
  browser = await chromium.launch({ headless: true, args: ['--no-sandbox'] });
  const page = await browser.newPage({ viewport: { width: 1440, height: 1050 } });
  const errors = []; page.on('pageerror', error => errors.push(error.message));
  await page.goto(`${origin}/setup#token=${token}`);
  await page.getByRole('heading', { name: 'Example repository', exact: true }).waitFor();
  assert.equal(new URL(page.url()).hash, '');
  await page.getByLabel('Profile name', { exact: true }).fill('Saved repository');
  await page.getByRole('button', { name: 'Save profile', exact: true }).click();
  await eventually(async () => { const text = await page.getByRole('status').textContent(); return text.includes('Profile saved.') && !text.includes('Unsaved changes.'); });
  await page.reload();
  await page.getByRole('heading', { name: 'Saved repository', exact: true }).waitFor();
  await page.screenshot({ path: path.join(screenshots, 'setup-desktop.png'), fullPage: true });
  await page.getByRole('button', { name: 'Build / CI', exact: true }).click();
  await page.getByLabel('Non-secret build arguments').fill('DISPLAY=$(touch injected)');
  await page.route('**/api/setup', route => route.request().method() === 'POST' ? route.fulfill({ status: 503, contentType: 'application/json', body: '{"error":"Simulated save failure"}' }) : route.continue());
  await page.getByRole('button', { name: 'Save profile', exact: true }).click();
  await page.getByRole('alert').filter({ hasText: 'Simulated save failure' }).waitFor();
  assert.equal(await page.getByLabel('Non-secret build arguments').inputValue(), 'DISPLAY=$(touch injected)');
  await page.unroute('**/api/setup');
  await page.getByRole('button', { name: 'Save profile', exact: true }).click();
  await eventually(async () => { const text = await page.getByRole('status').textContent(); return text.includes('Profile saved.') && !text.includes('Unsaved changes.'); });
  assert.match(await page.getByLabel('Capture build evidence command').inputValue(), /DISPLAY=\$\(touch injected\)/);
  await page.getByRole('button', { name: 'Tools', exact: true }).click();
  await page.getByLabel('Mode', { exact: true }).selectOption('implementation');
  await page.getByRole('button', { name: 'Save profile', exact: true }).click();
  await eventually(async () => { const text = await page.getByRole('status').textContent(); return text.includes('Profile saved.') && !text.includes('Unsaved changes.'); });
  // A second session wins a save: the page must retain edits and report a conflict.
  const current = JSON.parse(await fs.readFile(path.join(config, 'profile.json'), 'utf8'));
  await fs.writeFile(path.join(config, 'profile.json'), JSON.stringify({ ...current, revision: current.revision + 1 }), { mode: 0o600 });
  await page.getByLabel('Mode', { exact: true }).selectOption('read-only');
  await page.getByRole('button', { name: 'Save profile', exact: true }).click();
  await page.getByRole('alert').filter({ hasText: 'another session' }).waitFor();
  assert.equal(await page.getByLabel('Mode', { exact: true }).inputValue(), 'read-only');
  page.on('dialog', dialog => dialog.accept());
  await page.getByRole('button', { name: 'Reload saved profile', exact: true }).click();
  await eventually(async () => await page.getByLabel('Mode', { exact: true }).inputValue() === 'implementation');
  await page.setViewportSize({ width: 390, height: 844 });
  for (const tab of ['Repository & host', 'Build / CI', 'Runtime', 'Tools', 'Review & activation', 'Launch & export']) {
    await page.getByRole('button', { name: tab, exact: true }).click();
    assert.equal(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth), true, tab);
  }
  await page.screenshot({ path: path.join(screenshots, 'setup-mobile.png'), fullPage: true });
  await page.keyboard.press('Tab');
  assert.equal(await page.evaluate(() => document.activeElement.tagName !== 'BODY'), true);
  assert.deepEqual(errors, []);
  console.log('Setup browser smoke passed: save/reload, failed-save recovery, stale revisions, literal commands, keyboard focus and mobile layout.');
  console.log('Screenshots: ' + screenshots);
} catch (error) {
  console.error(logs); throw error;
} finally {
  await browser?.close();
  server.kill('SIGTERM');
  await new Promise(resolve => { if (server.exitCode !== null) resolve(); else server.once('exit', resolve); });
  await fs.rm(root, { recursive: true, force: true });
}
