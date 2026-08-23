'use strict';

const assert = require('node:assert/strict');
const childProcess = require('node:child_process');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const test = require('node:test');

const appRoot = path.resolve(__dirname, '..');
const noshPath = path.join(appRoot, 'nosh.sh');

function createFixture(t) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'notty-nosh-vlock-'));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const home = path.join(root, 'home');
  const workspace = path.join(root, 'workspace');
  fs.mkdirSync(home);
  fs.mkdirSync(workspace);
  return { root, home, workspace };
}

function runNosh(fixture, args, env = {}) {
  return childProcess.spawnSync('bash', [noshPath, ...args], {
    cwd: fixture.workspace,
    encoding: 'utf8',
    env: {
      PATH: process.env.PATH,
      HOME: fixture.home,
      XDG_CONFIG_HOME: path.join(fixture.home, '.config'),
      ...env,
    },
  });
}

test('the common Nosh image installs vlock', () => {
  const dockerfile = fs.readFileSync(path.join(appRoot, 'Dockerfile.nosh'), 'utf8');
  assert.match(dockerfile, /^\s+vlock \\/m);
  assert.match(dockerfile, /\/etc\/notty\/container-user/);
  assert.match(
    dockerfile,
    /install -D -o root -g root -m 0555[\s\\]+\/app\/scripts\/set-vlock-password\.sh[\s\\]+\/usr\/local\/libexec\/notty-set-vlock-password/,
  );
  assert.match(dockerfile, /0:0:555/);
  assert.match(dockerfile, /0:0:444/);
});

test('set-login-password dry-run uses an interactive in-container passwd prompt', (t) => {
  const fixture = createFixture(t);
  const result = runNosh(fixture, [
    'set-login-password',
    '--dry-run',
    '--name',
    'nosh-password-test',
  ]);
  const output = `${result.stdout}${result.stderr}`;

  assert.equal(result.status, 0, output);
  assert.match(
    result.stdout,
    /docker exec --interactive --tty --user root --workdir \/ .*nosh-password-test \/usr\/local\/libexec\/notty-set-vlock-password/,
  );
  assert.match(result.stdout, /not Notty Basic Auth/);
  assert.doesNotMatch(result.stdout, /NOTTY_BASIC_AUTH_PASSWORD|chpasswd|--password/);
  assert.match(result.stdout, /--env LD_PRELOAD=/);
  assert.match(result.stdout, /--env BASH_ENV=/);
});

test('set-login-password rejects guarded runners', (t) => {
  const fixture = createFixture(t);
  const result = runNosh(fixture, [
    'set-login-password',
    '--dry-run',
    '--security-mode',
    'learn',
  ]);
  const output = `${result.stdout}${result.stderr}`;

  assert.notEqual(result.status, 0);
  assert.match(output, /only for legacy Nosh containers/);
  assert.doesNotMatch(output, /nosh-guard run|docker exec/);
});

test('set-login-password requires an existing running container', (t) => {
  const fixture = createFixture(t);
  const fakeBin = path.join(fixture.root, 'bin');
  const fakeDocker = path.join(fakeBin, 'docker');
  fs.mkdirSync(fakeBin);
  fs.writeFileSync(fakeDocker, [
    '#!/usr/bin/env bash',
    'if [[ "$1" == "container" ]]; then',
    '  [[ "$FAKE_DOCKER_STATE" != "missing" ]]',
    '  exit',
    'fi',
    'if [[ "$1" == "inspect" ]]; then',
    '  if [[ "$*" == *".State.Running"* ]]; then',
    '    [[ "$FAKE_DOCKER_STATE" == "running" ]] && printf "%s\\n" true || printf "%s\\n" false',
    '  elif [[ "$*" == *".Mounts"* ]]; then',
    '    :',
    '  else',
    '    printf "%s\\n" "<no value>|<no value>"',
    '  fi',
    'fi',
    '',
  ].join('\n'), { mode: 0o755 });
  const env = { PATH: `${fakeBin}:${process.env.PATH}` };

  const missing = runNosh(fixture, [
    'set-login-password', '--name', 'nosh-password-test',
  ], { ...env, FAKE_DOCKER_STATE: 'missing' });
  assert.notEqual(missing.status, 0);
  assert.match(`${missing.stdout}${missing.stderr}`, /container does not exist/);

  const stopped = runNosh(fixture, [
    'set-login-password', '--name', 'nosh-password-test',
  ], { ...env, FAKE_DOCKER_STATE: 'stopped' });
  assert.notEqual(stopped.status, 0);
  assert.match(`${stopped.stdout}${stopped.stderr}`, /container is not running/);
});

test('set-login-password passes no password value to Docker', (t) => {
  const fixture = createFixture(t);
  const fakeBin = path.join(fixture.root, 'bin');
  const dockerLog = path.join(fixture.root, 'docker.log');
  const fakeDocker = path.join(fakeBin, 'docker');
  fs.mkdirSync(fakeBin);
  fs.writeFileSync(fakeDocker, [
    '#!/usr/bin/env bash',
    'printf "%s\\n" "$*" >> "$FAKE_DOCKER_LOG"',
    'if [[ "$1" == "inspect" && "$*" == *".State.Running"* ]]; then',
    '  printf "%s\\n" true',
    'elif [[ "$1" == "inspect" && "$*" == *".Mounts"* ]]; then',
    '  :',
    'elif [[ "$1" == "inspect" ]]; then',
    '  printf "%s\\n" "<no value>|<no value>"',
    'fi',
    '',
  ].join('\n'), { mode: 0o755 });

  const result = runNosh(fixture, [
    'set-login-password',
    '--name',
    'nosh-password-test',
  ], {
    PATH: `${fakeBin}:${process.env.PATH}`,
    FAKE_DOCKER_LOG: dockerLog,
  });
  const output = `${result.stdout}${result.stderr}`;
  const dockerCalls = fs.readFileSync(dockerLog, 'utf8');

  assert.equal(result.status, 0, output);
  assert.match(dockerCalls, /^container inspect nosh-password-test$/m);
  assert.match(dockerCalls, /^inspect -f .*\.State\.Running.* nosh-password-test$/m);
  assert.match(dockerCalls, /^inspect -f .*io\.notty\.guard\.managed.*io\.notty\.guard\.component.* nosh-password-test$/m);
  assert.match(dockerCalls, /^inspect -f .*\.Mounts.* nosh-password-test$/m);
  assert.match(
    dockerCalls,
    /^exec --interactive --tty --user root --workdir \/ .*--env LD_PRELOAD= .*nosh-password-test \/usr\/local\/libexec\/notty-set-vlock-password$/m,
  );
  assert.doesNotMatch(dockerCalls, /NOTTY_|password=|chpasswd/);
});

test('set-login-password refuses bind mounts over privileged image paths', (t) => {
  const fixture = createFixture(t);
  const fakeBin = path.join(fixture.root, 'bin');
  const dockerLog = path.join(fixture.root, 'docker.log');
  const fakeDocker = path.join(fakeBin, 'docker');
  fs.mkdirSync(fakeBin);
  fs.writeFileSync(fakeDocker, [
    '#!/usr/bin/env bash',
    'printf "%s\\n" "$*" >> "$FAKE_DOCKER_LOG"',
    'if [[ "$1" == "inspect" && "$*" == *".State.Running"* ]]; then',
    '  printf "%s\\n" true',
    'elif [[ "$1" == "inspect" && "$*" == *".Mounts"* ]]; then',
    '  printf "%s\\n" "/usr/local/libexec/notty-set-vlock-password"',
    'elif [[ "$1" == "inspect" ]]; then',
    '  printf "%s\\n" "<no value>|<no value>"',
    'fi',
    '',
  ].join('\n'), { mode: 0o755 });

  const result = runNosh(fixture, [
    'set-login-password',
    '--name',
    'mounted-password-test',
  ], {
    PATH: `${fakeBin}:${process.env.PATH}`,
    FAKE_DOCKER_LOG: dockerLog,
  });
  const output = `${result.stdout}${result.stderr}`;
  const dockerCalls = fs.readFileSync(dockerLog, 'utf8');

  assert.notEqual(result.status, 0);
  assert.match(output, /refuses container mount over privileged path/);
  assert.doesNotMatch(dockerCalls, /^exec /m);
});

test('set-login-password refuses a Guard-managed target even in default legacy mode', (t) => {
  const fixture = createFixture(t);
  const fakeBin = path.join(fixture.root, 'bin');
  const dockerLog = path.join(fixture.root, 'docker.log');
  const fakeDocker = path.join(fakeBin, 'docker');
  fs.mkdirSync(fakeBin);
  fs.writeFileSync(fakeDocker, [
    '#!/usr/bin/env bash',
    'printf "%s\\n" "$*" >> "$FAKE_DOCKER_LOG"',
    'if [[ "$1" == "inspect" && "$*" == *".State.Running"* ]]; then',
    '  printf "%s\\n" true',
    'elif [[ "$1" == "inspect" ]]; then',
    '  printf "%s\\n" "true|runner"',
    'fi',
    '',
  ].join('\n'), { mode: 0o755 });

  const result = runNosh(fixture, [
    'set-login-password',
    '--name',
    'guarded-password-test',
  ], {
    PATH: `${fakeBin}:${process.env.PATH}`,
    FAKE_DOCKER_LOG: dockerLog,
  });
  const output = `${result.stdout}${result.stderr}`;
  const dockerCalls = fs.readFileSync(dockerLog, 'utf8');

  assert.notEqual(result.status, 0);
  assert.match(output, /refuses Nosh Guard-managed runner containers/);
  assert.doesNotMatch(dockerCalls, /^exec /m);
});

test('Nosh help advertises interactive vlock password setup', (t) => {
  const fixture = createFixture(t);
  const result = runNosh(fixture, ['--help']);
  assert.equal(result.status, 0, result.stderr);
  assert.match(result.stdout, /set-login-password/);
  assert.match(result.stdout, /interactively for vlock/);
});

test('the in-container helper resolves a root-owned identity and refuses root', () => {
  const helperPath = path.join(appRoot, 'scripts', 'set-vlock-password.sh');
  const helper = fs.readFileSync(helperPath, 'utf8');
  assert.ok((fs.statSync(helperPath).mode & 0o111) !== 0, 'helper must be executable');
  assert.match(helper, /^#!\/bin\/sh$/m);
  assert.match(helper, /identityFile='\/etc\/notty\/container-user'/);
  assert.match(helper, /\/usr\/bin\/stat -c/);
  assert.match(helper, /\/usr\/bin\/getent passwd/);
  assert.match(helper, /exec \/usr\/bin\/env -i/);
  assert.match(helper, /\/usr\/bin\/passwd/);
  assert.match(helper, /refusing to set the root password/);
  assert.doesNotMatch(helper, /NOTTY_CONTAINER_USER|passwd notty|chpasswd|password=/);
});
