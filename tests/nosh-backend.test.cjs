'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawnSync } = require('node:child_process');

const root = path.resolve(__dirname, '..');
const launcher = path.join(root, 'scripts/nosh.sh');

function fixture(t) {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'nosh backend '));
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  const workspace = path.join(directory, 'workspace with spaces');
  const home = path.join(directory, 'home');
  fs.mkdirSync(workspace);
  fs.mkdirSync(home);
  return { directory, workspace, home };
}

function run(file, args, f) {
  return spawnSync('bash', [file, ...args], {
    cwd: f.workspace,
    encoding: 'utf8',
    env: { PATH: process.env.PATH, HOME: f.home, USER: 'fixture',
      NOTTY_MCP_SPAWN_OTP: 'fixture-otp' },
  });
}

test('default and explicit Docker preserve caller workspace through an installed symlink', (t) => {
  const f = fixture(t);
  const link = path.join(f.directory, 'nosh');
  fs.symlinkSync(launcher, link);
  const args = ['--dry-run', '--security-mode', 'legacy', '--no-start-app', '--no-collab', '--agents', 'none'];
  const ordinary = run(link, args, f);
  const explicit = run(link, ['--docker', ...args], f);
  assert.equal(ordinary.status, 0, ordinary.stderr);
  assert.equal(explicit.status, ordinary.status, explicit.stderr);
  assert.equal(explicit.stdout, ordinary.stdout);
  assert.ok(ordinary.stdout.includes(f.workspace));
  const completion = run(link, ['--docker', 'completion', 'bash'], f);
  assert.equal(completion.status, 0, completion.stderr);
  assert.equal(completion.stdout, fs.readFileSync(path.join(root, 'completions/nosh.bash'), 'utf8'));
});

test('QEMU dispatch forwards literal arguments and exit status without Docker setup', (t) => {
  const f = fixture(t);
  const scripts = path.join(f.directory, 'checkout/scripts');
  fs.mkdirSync(scripts, { recursive: true });
  fs.copyFileSync(launcher, path.join(scripts, 'nosh.sh'));
  fs.writeFileSync(path.join(scripts, 'nosh-qemu.sh'), '#!/bin/bash\nprintf "%s\\0" "$PWD" "$@"\nexit 37\n');
  const link = path.join(f.directory, 'nosh');
  fs.symlinkSync('checkout/scripts/nosh.sh', link);
  for (const args of [[], ['attach', '--name', 'fixture'], ['--workdir', 'space $(touch INJECTED)', '--detach']]) {
    const result = run(link, ['--qemu', ...args], f);
    assert.equal(result.status, 37, result.stderr);
    assert.deepEqual(result.stdout.split('\0').slice(0, -1), [f.workspace, ...args]);
  }
  assert.equal(fs.existsSync(path.join(f.workspace, 'INJECTED')), false);
});

test('conflicting backends and unavailable bwrap fail before starting a backend', (t) => {
  const f = fixture(t);
  for (const args of [['--docker', '--qemu'], ['--qemu', '--docker'], ['--bwrap', '--qemu']]) {
    const result = run(launcher, args, f);
    assert.equal(result.status, 2);
    assert.match(result.stderr, /conflicting backend selectors/);
    assert.equal(result.stdout, '');
  }
  const result = run(launcher, ['--bwrap'], f);
  assert.equal(result.status, 2);
  assert.match(result.stderr, /--bwrap is not implemented/);
  assert.equal(result.stdout, '');
});

test('QEMU help is available through the unified launcher without starting a VM', (t) => {
  const result = run(launcher, ['--qemu', '--help'], fixture(t));
  assert.equal(result.status, 0, result.stderr);
  assert.match(result.stdout, /--accel/);
  assert.match(result.stdout, /default: start/);
});
