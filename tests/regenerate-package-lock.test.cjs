const assert = require('node:assert/strict');
const childProcess = require('node:child_process');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const test = require('node:test');

const root = path.resolve(__dirname, '..');
const hostScript = path.join(root, 'scripts/regenerate-package-lock.sh');
const containerScript = path.join(root, 'scripts', 'regenerate-package-lock-container.sh');
const dockerfilePath = path.join(root, 'Dockerfile.package-lock');
const releaseAuditDockerfilePath = path.join(root, 'Dockerfile.release-audit');

function run(command, args, options = {}) {
  return childProcess.spawnSync(command, args, {
    cwd: root,
    encoding: 'utf8',
    ...options,
  });
}

function git(command, cwd, env) {
  const result = run('git', command, { cwd, env });
  assert.equal(result.status, 0, result.stderr);
}

function createFixture(tempRoot) {
  const fixture = path.join(tempRoot, 'checkout');
  fs.mkdirSync(path.join(fixture, 'scripts'), { recursive: true });
  for (const [source, destination] of [
    [hostScript, path.join(fixture, 'scripts/regenerate-package-lock.sh')],
    [containerScript, path.join(fixture, 'scripts', 'regenerate-package-lock-container.sh')],
    [dockerfilePath, path.join(fixture, 'Dockerfile.package-lock')],
    [path.join(root, 'package.json'), path.join(fixture, 'package.json')],
    [path.join(root, 'package-lock.json'), path.join(fixture, 'package-lock.json')],
  ]) {
    fs.copyFileSync(source, destination);
  }
  fs.chmodSync(path.join(fixture, 'scripts/regenerate-package-lock.sh'), 0o755);
  fs.chmodSync(
    path.join(fixture, 'scripts', 'regenerate-package-lock-container.sh'),
    0o755,
  );

  const gitEnv = {
    ...process.env,
    GIT_CONFIG_GLOBAL: '/dev/null',
    GIT_CONFIG_NOSYSTEM: '1',
    GIT_CONFIG_COUNT: '1',
    GIT_CONFIG_KEY_0: 'commit.gpgSign',
    GIT_CONFIG_VALUE_0: 'false',
  };
  git(['init', '-q'], fixture, gitEnv);
  git(['config', 'user.name', 'Package Lock Test'], fixture, gitEnv);
  git(['config', 'user.email', 'package-lock@example.invalid'], fixture, gitEnv);
  git(['add', '.'], fixture, gitEnv);
  git(['commit', '-qm', 'fixture'], fixture, gitEnv);
  return { fixture, gitEnv };
}

test('package-lock entrypoints are executable and syntactically valid', () => {
  for (const script of [hostScript, containerScript]) {
    assert.notEqual(fs.statSync(script).mode & 0o111, 0, `${script} must be executable`);
    const result = run('bash', ['-n', script]);
    assert.equal(result.status, 0, result.stderr);
  }

  const help = run('bash', [hostScript, '--help']);
  assert.equal(help.status, 0, help.stderr);
  assert.match(help.stdout, /never runs npm, npx, or node on the host/i);
  assert.match(help.stdout, /package\.json.*stdin/is);
  assert.match(help.stdout, /--network none/i);
  assert.match(help.stdout, /never.*creates\/moves a release tag/is);

  const invalid = run('bash', [hostScript, '--invalid']);
  assert.equal(invalid.status, 2);
});

test('host wrapper cannot directly invoke a host Node package manager', () => {
  const source = fs.readFileSync(hostScript, 'utf8');

  assert.doesNotMatch(source, /^\s*(?:command\s+)?(?:npm|npx|node)\b/m);
  assert.doesNotMatch(source, /\$\(\s*(?:npm|npx|node)\b/);
  assert.match(source, /readonly -f npm npx node/);
  assert.match(source, /refusing to fall back to host npm/);
  const containerArgs = source.match(/container_args\(\) \{[\s\S]*?\n\}/)?.[0];
  assert.ok(containerArgs, 'container_args function must exist');
  assert.doesNotMatch(containerArgs, /--mount|^\s*-v(?:\s|$)/m);
});

test('generator image and runtime retain the intended isolation controls', () => {
  const dockerfile = fs.readFileSync(dockerfilePath, 'utf8');
  const releaseAuditDockerfile = fs.readFileSync(releaseAuditDockerfilePath, 'utf8');
  const hostSource = fs.readFileSync(hostScript, 'utf8');
  const helperSource = fs.readFileSync(containerScript, 'utf8');
  const imagePattern = /^ARG NODE_IMAGE=(node:24\.18\.0-bookworm-slim@sha256:[a-f0-9]{64})$/m;

  assert.match(dockerfile, imagePattern);
  assert.match(releaseAuditDockerfile, imagePattern);
  assert.equal(dockerfile.match(imagePattern)[1], releaseAuditDockerfile.match(imagePattern)[1]);
  assert.match(dockerfile, /^USER node$/m);
  assert.doesNotMatch(dockerfile, /apt-get|curl|wget/);
  assert.match(helperSource, /EXPECTED_NODE_VERSION=v24\.18\.0/);
  assert.match(helperSource, /EXPECTED_NPM_VERSION=11\.16\.0/);
  assert.match(helperSource, /cd "\$WORK_ROOT"/);
  for (const pattern of [
    /--read-only/,
    /--user 1000:1000/,
    /--cap-drop ALL/,
    /no-new-privileges=true/,
    /--pids-limit 128/,
    /--memory 2g/,
    /--ipc none/,
    /--network "\$network_mode"/,
    /PACKAGE_LOCK_NETWORK_MODE=\$network_mode/,
  ]) {
    assert.match(hostSource, pattern);
  }
  assert.match(hostSource, /container_args "\$VALIDATE_CONTAINER" none/);
  assert.match(hostSource, /<"\$manifest_snapshot" >"\$candidate_path"/);
  assert.match(helperSource, /--package-lock-only/);
  assert.match(helperSource, /--ignore-scripts/);
  assert.match(helperSource, /--allow-directory=none/);
  assert.match(helperSource, /--allow-file=none/);
  assert.match(helperSource, /--allow-git=none/);
  assert.match(helperSource, /--allow-remote=none/);
  assert.match(helperSource, /hostname !== 'registry\.npmjs\.org'/);
  assert.match(helperSource, /npm audit --omit=dev --json/);
  assert.match(helperSource, /3<&0 <<'NODE'/);
  assert.match(helperSource, /const framed = fs\.readFileSync\(3\);/);
  assert.doesNotMatch(helperSource, /fs\.readFileSync\(0\)/);
});

test('missing Docker never calls a host npm executable or changes the lock', (t) => {
  const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'notty-lock-missing-docker-'));
  t.after(() => fs.rmSync(tempRoot, { recursive: true, force: true }));
  const { fixture } = createFixture(tempRoot);
  const fakeBin = path.join(tempRoot, 'bin');
  const npmMarker = path.join(tempRoot, 'host-npm-was-called');
  const fixtureScript = path.join(fixture, 'scripts/regenerate-package-lock.sh');
  const fixtureLock = path.join(fixture, 'package-lock.json');
  const lockBefore = fs.readFileSync(fixtureLock);
  fs.mkdirSync(fakeBin);
  fs.writeFileSync(
    path.join(fakeBin, 'docker'),
    '#!/bin/sh\n[ "$1" = info ] && exit 1\nexit 99\n',
    { mode: 0o755 },
  );
  for (const command of ['npm', 'npx', 'node']) {
    fs.writeFileSync(
      path.join(fakeBin, command),
      `#!/bin/sh\ntouch ${JSON.stringify(npmMarker)}\nexit 99\n`,
      { mode: 0o755 },
    );
  }

  const result = run(
    '/bin/bash',
    [fixtureScript],
    { cwd: fixture, env: { PATH: `${fakeBin}:/usr/bin:/bin` } },
  );

  assert.equal(result.status, 1, result.stdout + result.stderr);
  assert.match(result.stdout + result.stderr, /refusing to fall back to host npm/i);
  assert.equal(fs.existsSync(npmMarker), false);
  assert.deepEqual(fs.readFileSync(fixtureLock), lockBefore);
});

test('container helper refuses to generate a lock outside Docker', () => {
  const result = run('/bin/bash', [containerScript, 'generate'], {
    input: '{}\n',
    env: {
      PATH: '/usr/bin:/bin',
      DOCKER_CONTAINER: '0',
      HOME: '/lock/runtime/home',
      NPM_CONFIG_USERCONFIG: '/dev/null',
    },
  });

  assert.equal(result.status, 2);
  assert.match(result.stderr, /refusing to run npm/);
});

test('symlink lock target is rejected before Docker', (t) => {
  const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'notty-lock-symlink-'));
  t.after(() => fs.rmSync(tempRoot, { recursive: true, force: true }));
  const { fixture } = createFixture(tempRoot);
  const fakeBin = path.join(tempRoot, 'bin');
  const dockerMarker = path.join(tempRoot, 'docker-was-called');
  const sentinel = path.join(tempRoot, 'sentinel-lock.json');
  const lockPath = path.join(fixture, 'package-lock.json');
  fs.mkdirSync(fakeBin);
  fs.writeFileSync(sentinel, 'do not replace\n');
  fs.rmSync(lockPath);
  fs.symlinkSync(sentinel, lockPath);
  fs.writeFileSync(
    path.join(fakeBin, 'docker'),
    `#!/bin/sh\ntouch ${JSON.stringify(dockerMarker)}\nexit 99\n`,
    { mode: 0o755 },
  );

  const result = run('/bin/bash', [path.join(fixture, 'scripts/regenerate-package-lock.sh')], {
    cwd: fixture,
    env: { PATH: `${fakeBin}:/usr/bin:/bin` },
  });

  assert.equal(result.status, 1, result.stdout + result.stderr);
  assert.match(result.stderr, /regular, non-symlink file/);
  assert.equal(fs.existsSync(dockerMarker), false);
  assert.equal(fs.readFileSync(sentinel, 'utf8'), 'do not replace\n');
});

test('validated fake-Docker candidate replaces the lock atomically', (t) => {
  const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'notty-lock-atomic-'));
  t.after(() => fs.rmSync(tempRoot, { recursive: true, force: true }));
  const { fixture } = createFixture(tempRoot);
  const fakeBin = path.join(tempRoot, 'bin');
  const stateDir = path.join(tempRoot, 'docker-state');
  const candidatePath = path.join(tempRoot, 'candidate.json');
  const lockPath = path.join(fixture, 'package-lock.json');
  const manifest = JSON.parse(fs.readFileSync(path.join(fixture, 'package.json'), 'utf8'));
  const candidate = {
    name: manifest.name,
    version: manifest.version,
    lockfileVersion: 3,
    requires: true,
    packages: {
      '': {
        name: manifest.name,
        version: manifest.version,
        license: manifest.license,
        dependencies: manifest.dependencies,
        devDependencies: manifest.devDependencies,
        bin: manifest.bin,
      },
      'node_modules/example': {
        version: '1.0.0',
        resolved: 'https://registry.npmjs.org/example/-/example-1.0.0.tgz',
        integrity: `sha512-${'A'.repeat(86)}==`,
      },
    },
  };
  fs.mkdirSync(fakeBin);
  fs.mkdirSync(stateDir);
  fs.writeFileSync(candidatePath, `${JSON.stringify(candidate, null, 2)}\n`);
  fs.writeFileSync(
    path.join(fakeBin, 'docker'),
    `#!/bin/sh
set -eu
state=$FAKE_DOCKER_STATE
label_file=$state/label
image_file=$state/image
network_file=$state/network
case "\${1:-}" in
  info) exit 0 ;;
  build)
    shift
    for arg in "$@"; do
      case "$arg" in
        io.notty.package-lock.run=*) printf '%s\n' "\${arg#*=}" >"$label_file" ;;
      esac
    done
    : >"$image_file"
    exit 0
    ;;
  image)
    action=\${2:-}
    if [ "$action" = inspect ]; then
      [ -e "$image_file" ] || exit 1
      case "$*" in
        *'.Id'*) printf 'sha256:%064d\n' 1 ;;
        *'io.notty.package-lock.run'*) command cat "$label_file" ;;
      esac
      exit 0
    fi
    if [ "$action" = rm ]; then
      command rm -f "$image_file"
      exit 0
    fi
    ;;
  network)
    action=\${2:-}
    if [ "$action" = create ]; then
      : >"$network_file"
      exit 0
    fi
    if [ "$action" = inspect ]; then
      [ -e "$network_file" ] || exit 1
      case "$*" in
        *'io.notty.package-lock.run'*) command cat "$label_file" ;;
      esac
      exit 0
    fi
    if [ "$action" = rm ]; then
      command rm -f "$network_file"
      exit 0
    fi
    ;;
  container) exit 1 ;;
  run)
    last=
    for arg in "$@"; do last=$arg; done
    if [ "$last" = generate ]; then
      command cat >/dev/null
      command cat "$FAKE_LOCK_CANDIDATE"
      exit 0
    fi
    if [ "$last" = validate ]; then
      command cat >"$state/validation-frame"
      [ "\${FAKE_VALIDATE_FAIL:-0}" != 1 ] || exit 42
      exit 0
    fi
    ;;
esac
exit 99
`,
    { mode: 0o755 },
  );

  const result = run('/bin/bash', [path.join(fixture, 'scripts/regenerate-package-lock.sh')], {
    cwd: fixture,
    env: {
      PATH: `${fakeBin}:/usr/bin:/bin`,
      FAKE_DOCKER_STATE: stateDir,
      FAKE_LOCK_CANDIDATE: candidatePath,
      TMPDIR: tempRoot,
    },
  });

  assert.equal(result.status, 0, result.stdout + result.stderr);
  const validationFrame = fs.readFileSync(path.join(stateDir, 'validation-frame'));
  const frameNewline = validationFrame.indexOf(0x0a);
  assert.ok(frameNewline > 0 && frameNewline <= 20);
  const frameHeader = validationFrame.subarray(0, frameNewline).toString('ascii');
  assert.match(frameHeader, /^[1-9][0-9]*$/);
  const framedManifestLength = Number(frameHeader);
  const fixtureManifest = fs.readFileSync(path.join(fixture, 'package.json'));
  const framedManifestStart = frameNewline + 1;
  const framedLockStart = framedManifestStart + framedManifestLength;
  assert.equal(framedManifestLength, fixtureManifest.length);
  assert.deepEqual(
    validationFrame.subarray(framedManifestStart, framedLockStart),
    fixtureManifest,
  );
  assert.deepEqual(validationFrame.subarray(framedLockStart), fs.readFileSync(candidatePath));
  assert.deepEqual(fs.readFileSync(lockPath), fs.readFileSync(candidatePath));
  assert.equal(fs.statSync(lockPath).mode & 0o777, 0o644);
  assert.deepEqual(
    fs.readdirSync(fixture).filter((name) => name.startsWith('.package-lock.json.tmp.')),
    [],
  );
  assert.equal(fs.existsSync(path.join(stateDir, 'image')), false);
  assert.equal(fs.existsSync(path.join(stateDir, 'network')), false);
  assert.match(result.stdout, /package-lock\.json replaced atomically/);
  assert.match(result.stdout, /No commit, release audit, or tag was created automatically/);

  const lockBeforeFailedValidation = fs.readFileSync(lockPath);
  fs.writeFileSync(candidatePath, '{"invalid":"candidate"}\n');
  const failedValidation = run(
    '/bin/bash',
    [path.join(fixture, 'scripts/regenerate-package-lock.sh'), '--replace-dirty-lock'],
    {
      cwd: fixture,
      env: {
        PATH: `${fakeBin}:/usr/bin:/bin`,
        FAKE_DOCKER_STATE: stateDir,
        FAKE_LOCK_CANDIDATE: candidatePath,
        FAKE_VALIDATE_FAIL: '1',
        TMPDIR: tempRoot,
      },
    },
  );
  assert.equal(failedValidation.status, 1, failedValidation.stdout + failedValidation.stderr);
  assert.match(failedValidation.stderr, /offline candidate validation failed/);
  assert.deepEqual(fs.readFileSync(lockPath), lockBeforeFailedValidation);
  assert.deepEqual(
    fs.readdirSync(fixture).filter((name) => name.startsWith('.package-lock.json.tmp.')),
    [],
  );
  assert.equal(fs.existsSync(path.join(stateDir, 'image')), false);
  assert.equal(fs.existsSync(path.join(stateDir, 'network')), false);
});

test('manifest records reviewed fixed dependency constraints', () => {
  const manifest = JSON.parse(fs.readFileSync(path.join(root, 'package.json'), 'utf8'));

  assert.equal(manifest.private, true);
  assert.equal(manifest.dependencies['@modelcontextprotocol/sdk'], '^1.30.0');
  assert.equal(manifest.dependencies.next, '^16.2.12');
  assert.deepEqual(manifest.overrides, {
    '@hono/node-server': '2.0.12',
    'fast-uri': '3.1.6',
    hono: '4.12.34',
    postcss: '8.5.25',
    qs: '6.16.0',
    sharp: '0.35.3',
  });
});
