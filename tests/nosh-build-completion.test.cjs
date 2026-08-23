'use strict';

const assert = require('node:assert/strict');
const childProcess = require('node:child_process');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const test = require('node:test');

const appRoot = path.resolve(__dirname, '..');
const completionPath = path.join(appRoot, 'completions', 'nosh.bash');

function complete(words, options = {}) {
  const result = childProcess.spawnSync('bash', [
    '-c',
    [
      'source "$0"',
      'COMP_WORDS=("$@")',
      'COMP_CWORD=$((${#COMP_WORDS[@]} - 1))',
      '_nosh_completion',
      'printf "%s\\0" "${COMPREPLY[@]}"',
    ].join('\n'),
    completionPath,
    ...words,
  ], {
    cwd: options.cwd || appRoot,
    encoding: 'buffer',
    env: {
      PATH: process.env.PATH,
      HOME: process.env.HOME,
      ...(options.env || {}),
    },
  });

  assert.equal(
    result.status,
    0,
    `${String(result.stdout)}${String(result.stderr)}`,
  );
  return result.stdout.toString('utf8').split('\0').filter(Boolean);
}

test('Nosh completes nested build profile and status commands', () => {
  assert.ok(complete(['nosh', '']).includes('build'));
  assert.deepEqual(
    complete(['nosh', 'build', '']),
    ['profile', 'status', 'net', '-h', '--help'],
  );

  const profile = complete(['nosh', 'build', 'profile', '--']);
  for (const option of [
    '--file',
    '--variant',
    '--tag',
    '--target',
    '--platform',
    '--build-arg',
    '--cache-mode',
    '--depth',
    '--push',
    '--output',
    '--no-load',
  ]) {
    assert.ok(profile.includes(option), `missing build profile option ${option}`);
  }

  assert.deepEqual(
    complete(['nosh', 'build', 'status', '--']),
    ['--run', '--json', '--dry-run', '--help'],
  );
});

test('Nosh completes build modes and Dockerfiles', (t) => {
  const fixture = fs.mkdtempSync(path.join(os.tmpdir(), 'notty-build-complete-'));
  t.after(() => fs.rmSync(fixture, { recursive: true, force: true }));
  fs.writeFileSync(path.join(fixture, 'Dockerfile.ci'), 'FROM scratch\n');
  fs.mkdirSync(path.join(fixture, 'context-dir'));

  assert.deepEqual(
    complete(['nosh', 'build', 'profile', '--cache-mode', 'c']),
    ['compare', 'cold'],
  );
  assert.deepEqual(
    complete(['nosh', 'build', 'profile', '--depth=d']),
    ['--depth=deep'],
  );
  assert.deepEqual(
    complete(['nosh', 'build', 'profile', '--depth=p']),
    ['--depth=policy'],
  );
  assert.deepEqual(
    complete(['nosh', 'build', 'profile', '--file', 'Dock'], {
      cwd: fixture,
    }),
    ['Dockerfile.ci'],
  );
  assert.deepEqual(
    complete(['nosh', 'build', 'profile', 'cont'], { cwd: fixture }),
    ['context-dir/'],
  );
});

test('Nosh scopes build-network completion and stops at Buildx passthrough', () => {
  assert.deepEqual(
    complete(['nosh', 'build', 'net', '']),
    ['learn', 'status', '-h', '--help'],
  );
  const learn = complete(['nosh', 'build', 'net', 'learn', '--']);
  assert.ok(learn.includes('--build-arg'));
  assert.ok(learn.includes('--platform'));
  assert.ok(learn.includes('--json'));
  assert.ok(!learn.includes('--cache-mode'));
  assert.ok(!learn.includes('--depth'));
  assert.deepEqual(
    complete(['nosh', 'build', 'net', 'status', '--']),
    ['--json', '--dry-run', '--help'],
  );
  assert.deepEqual(
    complete(['nosh', 'build', 'profile', '--', '--sec']),
    [],
  );
});
