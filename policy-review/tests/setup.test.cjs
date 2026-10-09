const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs/promises');
const os = require('node:os');
const path = require('node:path');
const { Readable } = require('node:stream');
const { spawnSync } = require('node:child_process');
const modules = Promise.all([import('../modules/setup/model.js'), import('../modules/setup/storage.js'), import('../pages/api/setup.js')]);

async function fixture(t) {
  const [model] = await modules;
  const root = await fs.mkdtemp(path.join(os.tmpdir(), 'nosh-setup-'));
  const config = path.join(root, 'profile');
  const state = path.join(root, 'state');
  await fs.mkdir(config, { mode: 0o700 }); await fs.mkdir(state, { mode: 0o700 });
  const binding = { workspace: { path: "/work/repo ' $(touch injected)", dev: '1', ino: '2' }, launcher: '/opt/nosh/scripts/nosh.sh', scripts: '/opt/nosh/scripts' };
  const document = { kind: 'NoshRepositoryProfile', schemaVersion: 1, revision: 1, profile: model.defaults() };
  const session = { kind: 'NoshSetupSession', schemaVersion: 1, token: 'a'.repeat(64), origin: 'http://127.0.0.1:43123' };
  for (const [filename, value] of [[path.join(config, 'profile.json'), document], [path.join(state, 'binding.json'), binding], [path.join(root, 'session.json'), session]]) {
    await fs.writeFile(filename, JSON.stringify(value), { mode: 0o600 });
  }
  const env = { NOTTY_SETUP_SESSION_FILE: path.join(root, 'session.json'), NOTTY_SETUP_PROFILE_DIR: config, NOTTY_SETUP_STATE_DIR: state };
  const old = Object.fromEntries(Object.keys(env).map(key => [key, process.env[key]]));
  Object.assign(process.env, env);
  t.after(async () => {
    for (const [key, value] of Object.entries(old)) { if (value === undefined) delete process.env[key]; else process.env[key] = value; }
    await fs.rm(root, { recursive: true, force: true });
  });
  return { root, config, state, binding, document, session };
}
async function call(body, headers = {}) {
  const [, , { default: handler }] = await modules;
  const req = Readable.from(body ? [Buffer.from(JSON.stringify(body))] : []);
  req.method = body ? 'POST' : 'GET';
  req.headers = { host: '127.0.0.1:43123', authorization: `Bearer ${'a'.repeat(64)}`, ...headers };
  const res = { headers: {}, setHeader(key, value) { this.headers[key] = value; }, end(value) { this.body = JSON.parse(value); } };
  await handler(req, res);
  return res;
}

test('setup API loads binding and saves a private revision without changing status or authority', async t => {
  const f = await fixture(t);
  const response = await call();
  assert.equal(response.statusCode, 200);
  assert.equal(response.headers['Cache-Control'], 'no-store');
  assert.deepEqual(response.body.binding, f.binding);
  const profile = structuredClone(f.document.profile);
  profile.settings.tools.mode = 'implementation';
  const saved = await call({ revision: 1, profile });
  assert.equal(saved.statusCode, 200);
  assert.equal(saved.body.document.revision, 2);
  assert.equal((await fs.stat(path.join(f.config, 'profile.json'))).mode & 0o777, 0o600);
  assert.deepEqual(await fs.readdir(f.state), ['binding.json']);
  assert.equal((await call()).body.document.profile.settings.tools.mode, 'implementation');
});

test('setup rejects stale revisions and concurrent saves without losing edits', async t => {
  const { document } = await fixture(t);
  const request = { revision: 1, profile: document.profile };
  const results = await Promise.all([call(request), call(request)]);
  assert.deepEqual(results.map(result => result.statusCode).sort(), [200, 409]);
  assert.equal((await call(request)).statusCode, 409);
  assert.equal((await call()).body.document.revision, 2);
});

test('setup requires session token and exact origin, and rejects browser host-binding edits', async t => {
  const { document } = await fixture(t);
  for (const headers of [{ authorization: '' }, { host: 'evil.test' }, { origin: 'http://evil.test' }, { 'sec-fetch-site': 'cross-site' }]) {
    assert.equal((await call(null, headers)).statusCode, 403);
  }
  assert.equal((await call({ revision: 1, profile: document.profile, binding: {} })).statusCode, 422);
  assert.equal((await call()).body.document.revision, 1);
});

test('setup refuses unsafe links and retains existing profile after failed validation', async t => {
  const { config, document } = await fixture(t);
  const invalid = structuredClone(document.profile);
  invalid.settings.build.context = '../outside';
  assert.equal((await call({ revision: 1, profile: invalid })).statusCode, 422);
  const filename = path.join(config, 'profile.json');
  await fs.rename(filename, path.join(config, 'original.json'));
  await fs.symlink('original.json', filename);
  assert.equal((await call()).statusCode, 422);
});

test('commands use separate build, run, dev and tool policy workflows', async t => {
  const [model] = await modules;
  const { document, binding } = await fixture(t);
  const cards = model.commands(document.profile, binding);
  const get = id => cards.find(card => card.id === id);
  assert.match(get('build').command, /'build' 'net' 'learn'/);
  assert.doesNotMatch(get('build').command, /'sudo'|--cache-mode|--depth/);
  assert.match(get('start-dev').command, /'config' 'runtime' '--operation' 'enforce'.*'--workload' 'dev'.*'--revision' '1'/);
  assert.match(get('start-run').command, /'--workload' 'run'/);
  assert.equal(get('apply-dev').command, '');
  assert.match(get('recreate-dev').blocked, /no recreate command/);
  document.profile.host.reviews.dev = { directory: '/private/review', decisionDigest: 'sha256:' + 'a'.repeat(64) };
  assert.match(model.commands(document.profile, binding).find(card => card.id === 'apply-dev').command, /--decision-digest/);
  document.profile.settings.runtime.dev.launchMode = 'legacy';
  assert.match(model.commands(document.profile, binding).find(card => card.id === 'recreate-dev').command, /'recreate'.*'--security-mode' 'legacy'/);
});

test('copy commands preserve literal shell metacharacters as single arguments', async () => {
  const [model] = await modules;
  const values = ["/work/it's a repo", 'VALUE=$(touch /tmp/should-not-exist); `id`', 'spaces and "quotes"'];
  const source = model.shell([process.execPath, '-e', 'console.log(JSON.stringify(process.argv.slice(1)))', ...values]);
  const result = spawnSync('bash', ['-c', source], { encoding: 'utf8' });
  assert.equal(result.status, 0, result.stderr);
  assert.deepEqual(JSON.parse(result.stdout), values);
});

test('schema rejects unknown options, secrets and nonportable paths', async () => {
  const [model] = await modules;
  for (const change of [
    profile => { profile.settings.hook = 'shell'; },
    profile => { profile.settings.build.buildArgs = ['PASSWORD=bad']; },
    profile => { profile.settings.runtime.dev.baselines = ['/host/file@sha256:' + 'a'.repeat(64)]; },
    profile => { profile.host.guardPrefix = '/opt/../etc'; },
    profile => { profile.settings.runtime.run.agents = 'codex'; },
  ]) { const profile = model.defaults(); change(profile); assert.throws(() => model.validateProfile(profile)); }
});
