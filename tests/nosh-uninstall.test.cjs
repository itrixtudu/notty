const assert = require('node:assert/strict');
const { spawnSync } = require('node:child_process');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const test = require('node:test');

const repository = path.resolve(__dirname, '..');
const uninstaller = path.join(repository, 'scripts/uninstall-nosh.sh');

function fixture(t) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'nosh-uninstall-'));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const home = path.join(root, 'home');
  const bin = path.join(home, '.local/bin');
  const configDir = path.join(home, '.config/nosh');
  const tui = path.join(home, '.local/share/nosh/tui/venv-v1/bin');
  fs.mkdirSync(bin, { recursive: true });
  fs.mkdirSync(configDir, { recursive: true });
  fs.mkdirSync(tui, { recursive: true });
  const nosh = path.join(repository, 'scripts/nosh.sh');
  const guard = path.join(repository, 'bin/nosh-guard');
  fs.symlinkSync(nosh, path.join(bin, 'nosh'));
  fs.symlinkSync(guard, path.join(bin, 'nosh-guard'));
  const config = [
    'SCHEMA_VERSION=1', `BIN_DIR=${bin}`, `NOSH_BIN=${nosh}`,
    `NOSH_GUARD_BIN=${guard}`, 'NOSH_GUARD_PREFIX=/opt/notty',
    'NOSH_GUARD_PRIVILEGED_BIN=/opt/notty/bin/nosh-guard', '',
  ].join('\n');
  fs.writeFileSync(path.join(configDir, 'paths.conf'), config, { mode: 0o600 });
  fs.writeFileSync(path.join(configDir, 'policy-review-images.conf'), [
    'SCHEMA_VERSION=1', `NOSH_POLICY_TOOLING_IMAGE=sha256:${'1'.repeat(64)}`,
    `NOSH_POLICY_REVIEW_UI_IMAGE=sha256:${'2'.repeat(64)}`, '',
  ].join('\n'), { mode: 0o600 });
  fs.writeFileSync(path.join(tui, 'python'), '', { mode: 0o700 });
  return { root, home, bin, configDir };
}

function run(home, args) {
  return spawnSync('bash', [uninstaller, ...args], {
    encoding: 'utf8', env: { ...process.env, HOME: home, XDG_CONFIG_HOME: path.join(home, '.config'),
      XDG_DATA_HOME: path.join(home, '.local/share') },
  });
}

test('user-only uninstall removes only verified setup and preserves state', (t) => {
  const item = fixture(t);
  const state = path.join(item.home, '.local/state/nosh/evidence');
  fs.mkdirSync(state, { recursive: true });
  fs.writeFileSync(path.join(state, 'keep'), 'evidence');
  const result = run(item.home, ['--user-only', '--yes']);
  assert.equal(result.status, 0, result.stdout + result.stderr);
  assert.equal(fs.existsSync(path.join(item.bin, 'nosh')), false);
  assert.equal(fs.existsSync(path.join(item.configDir, 'paths.conf')), false);
  assert.equal(fs.existsSync(path.join(item.home, '.local/share/nosh/tui')), false);
  assert.equal(fs.readFileSync(path.join(state, 'keep'), 'utf8'), 'evidence');
});

test('uninstall refuses a foreign launcher before removing anything', (t) => {
  const item = fixture(t);
  fs.unlinkSync(path.join(item.bin, 'nosh'));
  fs.writeFileSync(path.join(item.bin, 'nosh'), 'foreign');
  const result = run(item.home, ['--user-only', '--yes']);
  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /foreign launcher/);
  assert.equal(fs.existsSync(path.join(item.configDir, 'paths.conf')), true);
  assert.equal(fs.readFileSync(path.join(item.bin, 'nosh'), 'utf8'), 'foreign');
});

test('dry-run reports but does not remove user setup', (t) => {
  const item = fixture(t);
  const result = run(item.home, ['--user-only', '--dry-run']);
  assert.equal(result.status, 0, result.stdout + result.stderr);
  assert.match(result.stdout, /User removal plan/);
  assert.equal(fs.lstatSync(path.join(item.bin, 'nosh')).isSymbolicLink(), true);
  assert.equal(fs.existsSync(path.join(item.configDir, 'paths.conf')), true);
});
