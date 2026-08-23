'use strict';

const assert = require('node:assert/strict');
const childProcess = require('node:child_process');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const test = require('node:test');

const appRoot = path.resolve(__dirname, '..');
const buildPath = path.join(appRoot, 'build-nosh.sh');
const buildNoshcPath = path.join(appRoot, 'build-noshc.sh');

function createFixture(t) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'notty-build-nosh-'));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const bin = path.join(root, 'bin');
  const home = path.join(root, 'home');
  fs.mkdirSync(bin, { recursive: true });
  fs.mkdirSync(home, { recursive: true });
  return { root, bin, home };
}

function runBuild(fixture, args, env = {}) {
  return childProcess.spawnSync('bash', [buildPath, ...args], {
    cwd: appRoot,
    encoding: 'utf8',
    env: {
      PATH: `${fixture.bin}:${process.env.PATH}`,
      HOME: fixture.home,
      USER: 'fixture-user',
      USERNAME: 'fixture-user',
      USER_UID: '1234',
      USER_GID: '5678',
      IMAGE_NAME: 'example/nosh:test',
      TARGET: 'cdev',
      ...env,
    },
  });
}

function output(result) {
  return `${result.stdout || ''}${result.stderr || ''}`;
}

function installArgumentLogger(filePath, logPath) {
  fs.writeFileSync(filePath, [
    '#!/usr/bin/env bash',
    'set -euo pipefail',
    'printf "%s\\n" "$@" > "$ARGUMENT_LOG"',
    'if [[ -n "${DOCKER_BUILDKIT_LOG:-}" ]]; then',
    '  printf "%s\\n" "${DOCKER_BUILDKIT:-}" > "$DOCKER_BUILDKIT_LOG"',
    'fi',
    '',
  ].join('\n'), { mode: 0o755 });
  return { ARGUMENT_LOG: logPath };
}

test('ordinary build-nosh behavior still invokes docker build with existing arguments', (t) => {
  const fixture = createFixture(t);
  const argumentLog = path.join(fixture.root, 'docker-argv.log');
  const buildkitLog = path.join(fixture.root, 'docker-buildkit.log');
  const env = {
    ...installArgumentLogger(
      path.join(fixture.bin, 'docker'),
      argumentLog,
    ),
    DOCKER_BUILDKIT: '0',
    DOCKER_BUILDKIT_LOG: buildkitLog,
  };
  const result = runBuild(fixture, ['--no-cache'], env);

  assert.equal(result.status, 0, output(result));
  assert.match(
    result.stdout,
    /Building example\/nosh:test target=cdev with USERNAME=fixture-user USER_UID=1234 USER_GID=5678/,
  );
  assert.equal(
    fs.readFileSync(argumentLog, 'utf8'),
    [
      'build',
      '--build-arg',
      'USERNAME=fixture-user',
      '--build-arg',
      'USER_UID=1234',
      '--build-arg',
      'USER_GID=5678',
      '--target',
      'cdev',
      '-f',
      'Dockerfile.nosh',
      '-t',
      'example/nosh:test',
      '--no-cache',
      '.',
      '',
    ].join('\n'),
  );
  assert.equal(fs.readFileSync(buildkitLog, 'utf8'), '1\n');
});

test('build-nosh profile supplies the Notty build inputs to nosh-guard', (t) => {
  const fixture = createFixture(t);
  const argumentLog = path.join(fixture.root, 'guard-argv.log');
  const guardPath = path.join(fixture.bin, 'fake-nosh-guard');
  const env = {
    ...installArgumentLogger(guardPath, argumentLog),
    NOSH_GUARD_BIN: guardPath,
  };
  const result = runBuild(fixture, [
    'profile',
    '--cache-mode',
    'cold',
    '--',
    '--secret',
    'id=fixture',
  ], env);

  assert.equal(result.status, 0, output(result));
  assert.deepEqual(
    fs.readFileSync(argumentLog, 'utf8').trim().split('\n'),
    [
      'build',
      'profile',
      '--file',
      path.join(appRoot, 'Dockerfile.nosh'),
      '--tag',
      'example/nosh:test',
      '--target',
      'cdev',
      '--build-arg',
      'USERNAME=fixture-user',
      '--build-arg',
      'USER_UID=1234',
      '--build-arg',
      'USER_GID=5678',
      '--cache-mode',
      'cold',
      appRoot,
      '--',
      '--secret',
      'id=fixture',
    ],
  );
});

test('build-nosh net learn uses the independent build-network workflow', (t) => {
  const fixture = createFixture(t);
  const argumentLog = path.join(fixture.root, 'guard-argv.log');
  const guardPath = path.join(fixture.bin, 'fake-nosh-guard');
  const env = {
    ...installArgumentLogger(guardPath, argumentLog),
    NOSH_GUARD_BIN: guardPath,
  };
  const result = runBuild(fixture, [
    'net',
    'learn',
    '--platform',
    'linux/amd64',
  ], env);

  assert.equal(result.status, 0, output(result));
  assert.deepEqual(
    fs.readFileSync(argumentLog, 'utf8').trim().split('\n'),
    [
      'build',
      'net',
      'learn',
      '--file',
      path.join(appRoot, 'Dockerfile.nosh'),
      '--tag',
      'example/nosh:test',
      '--target',
      'cdev',
      '--build-arg',
      'USERNAME=fixture-user',
      '--build-arg',
      'USER_UID=1234',
      '--build-arg',
      'USER_GID=5678',
      '--platform',
      'linux/amd64',
      appRoot,
    ],
  );
});

test('build-nosh net learn launches Policy Review for the persisted private bundle', (t) => {
  const fixture = createFixture(t);
  const profileDir = path.join(fixture.root, 'profile-1');
  const reviewLog = path.join(fixture.root, 'review-argv.log');
  const guardPath = path.join(fixture.bin, 'fake-nosh-guard');
  const reviewPath = path.join(fixture.bin, 'fake-review-launcher');
  const dockerLog = path.join(fixture.root, 'unexpected-docker.log');
  fs.mkdirSync(profileDir, { recursive: true });
  fs.writeFileSync(guardPath, [
    '#!/usr/bin/env bash',
    'set -euo pipefail',
    'printf "Private bundle: %s\\n" "$TEST_PRIVATE_BUNDLE"',
  ].join('\n'), { mode: 0o755 });
  fs.writeFileSync(reviewPath, [
    '#!/usr/bin/env bash',
    'set -euo pipefail',
    'printf "%s\\n" "$@" > "$TEST_REVIEW_LOG"',
    'exit "${TEST_REVIEW_STATUS:-0}"',
  ].join('\n'), { mode: 0o755 });
  fs.writeFileSync(path.join(fixture.bin, 'docker'), [
    '#!/usr/bin/env bash',
    'set -euo pipefail',
    'printf "%s\\n" "$@" >"$TEST_DOCKER_LOG"',
    'exit 88',
  ].join('\n'), { mode: 0o755 });
  const env = {
    NOSH_GUARD_BIN: guardPath,
    NOSH_BUILD_REVIEW_LAUNCHER: reviewPath,
    TEST_PRIVATE_BUNDLE: profileDir,
    TEST_REVIEW_LOG: reviewLog,
    TEST_DOCKER_LOG: dockerLog,
  };

  const result = runBuild(fixture, ['net', 'learn'], env);
  assert.equal(result.status, 0, output(result));
  assert.deepEqual(fs.readFileSync(reviewLog, 'utf8').trim().split('\n'), [
    '--build-profile',
    profileDir,
    '--allow-missing-sbom',
  ]);
  assert.equal(fs.existsSync(dockerLog), false, 'net learn must not fall through to docker build');

  fs.rmSync(reviewLog);
  const optedOut = runBuild(fixture, ['net', 'learn', '--no-review'], env);
  assert.equal(optedOut.status, 0, output(optedOut));
  assert.equal(fs.existsSync(reviewLog), false);
  assert.equal(fs.existsSync(dockerLog), false);
});

test('build-nosh preserves a nonzero learn status after review success or failure', (t) => {
  const fixture = createFixture(t);
  const profileDir = path.join(fixture.root, 'profile-incomplete');
  const reviewLog = path.join(fixture.root, 'review-argv.log');
  const guardPath = path.join(fixture.bin, 'fake-nosh-guard');
  const reviewPath = path.join(fixture.bin, 'fake-review-launcher');
  fs.mkdirSync(profileDir, { recursive: true });
  fs.writeFileSync(guardPath, [
    '#!/usr/bin/env bash',
    'set -euo pipefail',
    'printf "Private bundle: %s\\n" "$TEST_PRIVATE_BUNDLE"',
    'printf "Private bundle: /tmp/stderr-spoof\\n" >&2',
    'exit 17',
  ].join('\n'), { mode: 0o755 });
  fs.writeFileSync(reviewPath, [
    '#!/usr/bin/env bash',
    'set -euo pipefail',
    'printf "%s\\n" "$@" >"$TEST_REVIEW_LOG"',
    'exit "${TEST_REVIEW_STATUS:-0}"',
  ].join('\n'), { mode: 0o755 });
  const env = {
    NOSH_GUARD_BIN: guardPath,
    NOSH_BUILD_REVIEW_LAUNCHER: reviewPath,
    TEST_PRIVATE_BUNDLE: profileDir,
    TEST_REVIEW_LOG: reviewLog,
  };

  for (const reviewStatus of ['0', '9']) {
    fs.rmSync(reviewLog, { force: true });
    const result = runBuild(fixture, ['net', 'learn'], {
      ...env,
      TEST_REVIEW_STATUS: reviewStatus,
    });
    assert.equal(result.status, 17, output(result));
    assert.deepEqual(fs.readFileSync(reviewLog, 'utf8').trim().split('\n'), [
      '--build-profile',
      profileDir,
      '--allow-missing-sbom',
    ]);
    if (reviewStatus !== '0') {
      assert.match(result.stderr, /review launch failed; the learned evidence was preserved/);
    }
  }
});

test('build-nosh derives tooling and UI image IDs for the automatic review handoff', (t) => {
  const fixture = createFixture(t);
  const profileDir = path.join(fixture.root, 'profile-auto-images');
  const reviewLog = path.join(fixture.root, 'review-env.log');
  const dockerLog = path.join(fixture.root, 'docker.log');
  const guardPath = path.join(fixture.bin, 'fake-nosh-guard');
  const reviewPath = path.join(fixture.bin, 'fake-review-launcher');
  const tooling = `sha256:${'a'.repeat(64)}`;
  const ui = `sha256:${'b'.repeat(64)}`;
  fs.mkdirSync(profileDir, { recursive: true });
  fs.writeFileSync(guardPath, [
    '#!/usr/bin/env bash',
    'set -euo pipefail',
    'printf "Private bundle: %s\\n" "$TEST_PRIVATE_BUNDLE"',
    `printf "Output image (informational): ${tooling}\\n"`,
  ].join('\n'), { mode: 0o755 });
  fs.writeFileSync(reviewPath, [
    '#!/usr/bin/env bash',
    'set -euo pipefail',
    'printf "tooling=%s\\nui=%s\\n" "$NOSH_POLICY_TOOLING_IMAGE" "$NOSH_POLICY_REVIEW_UI_IMAGE" >"$TEST_REVIEW_LOG"',
  ].join('\n'), { mode: 0o755 });
  fs.writeFileSync(path.join(fixture.bin, 'docker'), [
    '#!/usr/bin/env bash',
    'set -euo pipefail',
    'printf "%s\\n" "$@" >>"$TEST_DOCKER_LOG"',
    'if [[ "$1 $2" == "image inspect" ]]; then printf "%s\\n" "$TEST_UI_IMAGE"; fi',
  ].join('\n'), { mode: 0o755 });
  const result = runBuild(fixture, ['net', 'learn'], {
    NOSH_GUARD_BIN: guardPath,
    NOSH_BUILD_REVIEW_LAUNCHER: reviewPath,
    NOSH_POLICY_REVIEW_UI_IMAGE_TAG: 'nosh-policy-review:managed',
    TEST_PRIVATE_BUNDLE: profileDir,
    TEST_REVIEW_LOG: reviewLog,
    TEST_DOCKER_LOG: dockerLog,
    TEST_UI_IMAGE: ui,
  });
  assert.equal(result.status, 0, output(result));
  assert.ok(fs.existsSync(reviewLog), output(result));
  assert.equal(fs.readFileSync(reviewLog, 'utf8'), `tooling=${tooling}\nui=${ui}\n`);
  assert.match(fs.readFileSync(dockerLog, 'utf8'), /image/);
});

test('build-nosh suppresses automatic review for machine modes only before --', (t) => {
  const fixture = createFixture(t);
  const reviewLog = path.join(fixture.root, 'review-argv.log');
  const guardLog = path.join(fixture.root, 'guard-argv.log');
  const dockerLog = path.join(fixture.root, 'docker-argv.log');
  const guardPath = path.join(fixture.bin, 'fake-nosh-guard');
  const reviewPath = path.join(fixture.bin, 'fake-review-launcher');
  fs.writeFileSync(guardPath, [
    '#!/usr/bin/env bash',
    'set -euo pipefail',
    'printf "%s\\n" "$@" >"$TEST_GUARD_LOG"',
    'printf "{\\"status\\":\\"machine\\"}\\n"',
  ].join('\n'), { mode: 0o755 });
  fs.writeFileSync(reviewPath, [
    '#!/usr/bin/env bash',
    'set -euo pipefail',
    'printf "%s\\n" "$@" >"$TEST_REVIEW_LOG"',
  ].join('\n'), { mode: 0o755 });
  fs.writeFileSync(path.join(fixture.bin, 'docker'), [
    '#!/usr/bin/env bash',
    'set -euo pipefail',
    'printf "%s\\n" "$@" >"$TEST_DOCKER_LOG"',
    'exit 88',
  ].join('\n'), { mode: 0o755 });
  const env = {
    NOSH_GUARD_BIN: guardPath,
    NOSH_BUILD_REVIEW_LAUNCHER: reviewPath,
    TEST_GUARD_LOG: guardLog,
    TEST_REVIEW_LOG: reviewLog,
    TEST_DOCKER_LOG: dockerLog,
  };

  for (const mode of ['--no-review', '--json', '--private-json', '--dry-run']) {
    fs.rmSync(reviewLog, { force: true });
    const result = runBuild(fixture, ['net', 'learn', mode], env);
    assert.equal(result.status, 0, output(result));
    assert.equal(fs.existsSync(reviewLog), false, mode);
    assert.equal(fs.existsSync(dockerLog), false, mode);
    if (mode === '--dry-run') {
      assert.match(result.stdout, /build net learn .*--dry-run/);
    } else {
      assert.deepEqual(JSON.parse(result.stdout), { status: 'machine' });
    }
  }

  fs.rmSync(reviewLog, { force: true });
  const passthrough = runBuild(fixture, ['net', 'learn', '--', '--no-review'], env);
  assert.equal(passthrough.status, 0, output(passthrough));
  assert.match(fs.readFileSync(guardLog, 'utf8'), /--no-review/);
  assert.match(passthrough.stderr, /no persisted private bundle was reported/);
});

test('build-nosh rejects incomplete network workflow names', (t) => {
  const fixture = createFixture(t);
  const result = runBuild(fixture, ['net']);

  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /expected `net learn`/);
});

test('build-noshc retains its cdev and noshc compatibility defaults', (t) => {
  const fixture = createFixture(t);
  const argumentLog = path.join(fixture.root, 'docker-argv.log');
  const env = installArgumentLogger(
    path.join(fixture.bin, 'docker'),
    argumentLog,
  );
  const result = childProcess.spawnSync('bash', [buildNoshcPath, '--no-cache'], {
    cwd: appRoot,
    encoding: 'utf8',
    env: {
      PATH: `${fixture.bin}:${process.env.PATH}`,
      HOME: fixture.home,
      USER: 'fixture-user',
      USERNAME: 'fixture-user',
      USER_UID: '1234',
      USER_GID: '5678',
      ...env,
    },
  });

  assert.equal(result.status, 0, output(result));
  assert.match(result.stdout, /Building noshc target=cdev/);
  assert.match(fs.readFileSync(argumentLog, 'utf8'), /cdev\n-f\nDockerfile\.nosh\n-t\nnoshc\n/);
});
