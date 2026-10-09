'use strict';

const assert = require('node:assert/strict');
const childProcess = require('node:child_process');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const test = require('node:test');

const appRoot = path.resolve(__dirname, '..');
const completionPath = path.join(appRoot, 'completions', 'nosh.bash');
const noshPath = path.join(appRoot, 'scripts/nosh.sh');

function runNosh(args, options = {}) {
  return childProcess.spawnSync('bash', [noshPath, ...args], {
    cwd: options.cwd || appRoot,
    encoding: 'utf8',
    env: {
      PATH: process.env.PATH,
      HOME: process.env.HOME,
      ...(options.env || {}),
    },
  });
}

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

  return result.stdout
    .toString('utf8')
    .split('\0')
    .filter(Boolean);
}

test('backend completion offers selectors and delegates to backend-specific commands', () => {
  assert.deepEqual(complete(['nosh', '--q']), ['--qemu']);
  assert.ok(complete(['nosh', '']).includes('--docker'));
  assert.deepEqual(complete(['nosh', '--docker', 'build', '']), complete(['nosh', 'build', '']));
  const qemu = complete(['nosh', '--qemu', '']);
  assert.ok(qemu.includes('status'));
  assert.ok(qemu.includes('--accel'));
  assert.ok(!qemu.includes('--image'));
  assert.ok(!qemu.includes('_serve'));
  assert.deepEqual(complete(['nosh', '--qemu', '--accel', '']), ['kvm', 'tcg']);
  assert.deepEqual(complete(['nosh', '--qemu', '--agent-skills', '']), ['ro', 'rw']);
  assert.deepEqual(complete(['nosh', '--bwrap', '']), []);
  assert.deepEqual(complete(['nosh', '--docker', '--qemu', '']), []);
});

test('Nosh emits its sourceable Bash completion without runtime setup', () => {
  const result = runNosh(['completion', 'bash'], {
    env: {
      NOTTY_CONFIG: '/definitely/missing/notty-config.json',
      NOTTY_MCP_SPAWN_OTP: '',
    },
  });

  assert.equal(result.status, 0, result.stderr);
  assert.equal(result.stderr, '');
  assert.equal(result.stdout, fs.readFileSync(completionPath, 'utf8'));
  assert.match(result.stdout, /^_nosh_completion_add_words\(\)/m);
  assert.match(
    result.stdout,
    /^complete -F _nosh_completion nosh nosh\.sh$/m,
  );
});

test('Nosh reports unsupported or missing completion shells', () => {
  const missing = runNosh(['completion']);
  const unsupported = runNosh(['completion', 'zsh']);
  const extra = runNosh(['completion', 'bash', 'extra']);

  assert.notEqual(missing.status, 0);
  assert.match(missing.stderr, /requires a shell.*bash/i);
  assert.notEqual(unsupported.status, 0);
  assert.match(unsupported.stderr, /unsupported completion shell: zsh.*bash/i);
  assert.notEqual(extra.status, 0);
  assert.match(extra.stderr, /exactly one shell.*bash/i);
});

test('Nosh lists merged profile names without runtime setup', (t) => {
  const fixture = fs.mkdtempSync(path.join(os.tmpdir(), 'notty-profile-list-'));
  t.after(() => fs.rmSync(fixture, { recursive: true, force: true }));
  const home = path.join(fixture, 'home');
  const workspace = path.join(fixture, 'workspace');
  fs.mkdirSync(path.join(home, '.config', 'nosh'), { recursive: true });
  fs.mkdirSync(workspace);
  fs.writeFileSync(
    path.join(workspace, 'nosh.mounts.json'),
    '{"profiles":{"workspace-custom":{},"codex":{},"custom profile":{},"bad$(id)":{},"bad\\u001bname":{}}}\n',
    'utf8',
  );
  fs.writeFileSync(
    path.join(home, '.config', 'nosh', 'nosh.mounts.json'),
    '{"profiles":{"user-custom":{}}}\n',
    'utf8',
  );

  const result = runNosh(['--profile-list', '--workdir', workspace], {
    cwd: workspace,
    env: { HOME: home },
  });

  assert.equal(result.status, 0, `${result.stdout}${result.stderr}`);
  assert.equal(result.stderr, '');
  const listedProfiles = result.stdout.trim().split(/\r?\n/).filter(Boolean);
  const configuredProfiles = Object.keys(JSON.parse(
    fs.readFileSync(path.join(appRoot, 'config', 'nosh-profiles.json'), 'utf8'),
  ).profiles);
  const expectedProfiles = [...new Set([
    ...configuredProfiles,
    'workspace-custom',
    'user-custom',
  ])].sort();
  assert.deepEqual(listedProfiles, expectedProfiles);
  assert.doesNotMatch(result.stdout, /docker|ttyUSB/);
  assert.doesNotMatch(result.stdout, /custom profile|bad\$|\u001b/);
});

test('the bundled Nosh Bash completion has valid syntax and registrations', () => {
  const syntax = childProcess.spawnSync('bash', ['-n', completionPath], {
    encoding: 'utf8',
  });
  const registration = childProcess.spawnSync('bash', [
    '-c',
    'source "$0"; complete -p nosh; complete -p nosh.sh',
    completionPath,
  ], {
    encoding: 'utf8',
  });

  assert.equal(syntax.status, 0, syntax.stderr);
  assert.equal(registration.status, 0, registration.stderr);
  assert.match(
    registration.stdout,
    /complete -F _nosh_completion nosh(?:\n|$)/,
  );
  assert.match(
    registration.stdout,
    /complete -F _nosh_completion nosh\.sh(?:\n|$)/,
  );
});

test('Nosh completes commands, options, and the Bash completion shell', () => {
  const root = complete(['nosh', '']);
  const start = complete(['nosh', 'st']);
  const options = complete(['nosh', 'start', '--sec']);

  for (const command of [
    'start',
    'attach',
    'stop',
    'rm',
    'recreate',
    'net',
    'build',
    'review',
    'policy',
    'gateway',
    'auth',
    'set-login-password',
    'completion',
  ]) {
    assert.ok(root.includes(command), `missing root completion ${command}`);
  }
  assert.ok(root.includes('--profile'));
  assert.ok(root.includes('--profile-list'));
  assert.ok(root.includes('--no-oauth'));
  assert.ok(root.includes('--no-otp-auth'));
  assert.ok(root.includes('--no-otp'));
  assert.deepEqual(start, ['start', 'stop']);
  assert.deepEqual(options, ['--security-mode', '--security-profile-dir']);
  assert.deepEqual(complete(['nosh', 'completion', 'b']), ['bash']);
  assert.deepEqual(complete(['nosh', 'completion', 'bash', '']), []);
  assert.deepEqual(complete(['nosh', 'auth', '']), ['otp', 'reset', '-h', '--help']);
  assert.ok(complete(['nosh', 'auth', 'otp', '--']).includes('--workdir'));
  assert.ok(complete(['nosh', 'auth', 'reset', '--']).includes('--workdir'));
  assert.ok(complete(['nosh', 'auth', 'reset', '--']).includes('--secure'));
  assert.ok(!complete(['nosh', 'auth', 'otp', '--']).includes('--secure'));
});

test('Nosh completes semantic review and policy workflow commands', () => {
  assert.deepEqual(
    complete(['nosh', 'review', '']),
    ['bundle', 'inspect', 'serve', 'keygen', 'approve', 'sbom', '-h', '--help'],
  );
  const bundle = complete(['nosh', 'review', 'bundle', '--']);
  for (const option of [
    '--profile',
    '--output',
    '--baseline',
    '--base-policy',
    '--sbom-source',
    '--sbom-image',
    '--allow-missing-sbom',
  ]) assert.ok(bundle.includes(option), option);
  assert.ok(
    complete(['nosh', 'review', 'approve', '--']).includes('--audience'),
    'review approval audience',
  );
  assert.deepEqual(complete(['nosh', 'policy', '']), ['project', '-h', '--help']);
  assert.deepEqual(
    complete(['nosh', 'policy', 'project', '--target', 'g']),
    [
      'guard-ebpf',
      'guard-nftables',
      'gateway-iptables',
      'gateway-pf',
      'gateway-ipfw',
      'gateway-ipfilter',
      'gateway-l7-proxy',
    ],
  );
  assert.deepEqual(complete(['nosh', 'gateway', '']), ['grant', '-h', '--help']);
  const grant = complete(['nosh', 'gateway', 'grant', '--']);
  for (const option of [
    '--policy',
    '--approval',
    '--review-key',
    '--review-audience',
    '--deployment-key',
    '--audience',
    '--active-grant-set-digest',
  ]) assert.ok(grant.includes(option), option);
});

test('Nosh scopes init completion to configuration options', () => {
  assert.ok(complete(['nosh', 'in']).includes('init'));
  assert.ok(!complete(['nosh', 'start', '--']).includes('init'));
  const expected = ['--review', '--policy-digest', '--workload', '--agents', '--codex-home', '--agent-baseline', '--workdir', '--image', '--guard-prefix', '--dry-run', '--check', '--advanced', '--step', '--help'];
  assert.deepEqual(complete(['nosh', 'init', '']), expected);
  assert.deepEqual(complete(['nosh', 'init', '--image', 'nosh', '--']), expected);
  for (const prefix of ['--security', '--start-app']) {
    assert.deepEqual(complete(['nosh', 'init', prefix]), []);
  }
  assert.deepEqual(complete(['nosh', 'init', '--image', '']), []);
  assert.deepEqual(complete(['nosh', 'init', '--image=']), []);
});

test('Nosh completes init workspace and Guard directories', (t) => {
  const fixture = fs.mkdtempSync(path.join(os.tmpdir(), 'notty-init-completion-'));
  t.after(() => fs.rmSync(fixture, { recursive: true, force: true }));
  fs.mkdirSync(path.join(fixture, 'work space'));
  fs.mkdirSync(path.join(fixture, 'guard'));
  fs.writeFileSync(path.join(fixture, 'guard.json'), '{}\n');
  assert.deepEqual(
    complete(['nosh', 'init', '--workdir', 'work'], { cwd: fixture }),
    ['work space/'],
  );
  assert.deepEqual(
    complete(['nosh', 'init', '--workdir=work'], { cwd: fixture }),
    ['--workdir=work space/'],
  );
  assert.deepEqual(
    complete(['nosh', 'init', '--guard-prefix', `${fixture}/gua`], { cwd: fixture }),
    [`${fixture}/guard/`],
  );
  assert.deepEqual(
    complete(['nosh', 'init', `--guard-prefix=${fixture}/gua`], { cwd: fixture }),
    [`--guard-prefix=${fixture}/guard/`],
  );
  assert.deepEqual(
    complete(['nosh', 'init', '--guard-prefix', '=', `${fixture}/gua`], { cwd: fixture }),
    [`${fixture}/guard/`],
  );
  assert.deepEqual(complete(['nosh', 'init', '--guard-prefix', 'gua'], { cwd: fixture }), []);
});

test('Nosh completes nested network workflow commands and scoped options', () => {
  assert.deepEqual(
    complete(['nosh', 'net', '']),
    ['learn', 'audit', 'approve', 'enforce', 'status', '-h', '--help'],
  );
  assert.deepEqual(complete(['nosh', 'net', 'a']), ['audit', 'approve']);

  const learn = complete(['nosh', 'net', 'learn', '--']);
  assert.ok(learn.includes('--profile'));
  assert.ok(learn.includes('--collab'));
  assert.ok(learn.includes('--image'));
  assert.ok(learn.includes('--duration'));
  assert.ok(learn.includes('--json'));
  assert.ok(!learn.includes('--profile-list'));
  assert.ok(!learn.includes('--persist'));
  assert.ok(!learn.includes('--security-mode'));
  assert.ok(!learn.includes('--network'));
  assert.ok(!learn.includes('--publish'));
  assert.ok(!complete(['nosh', 'net', 'audit', '--']).includes('--duration'));
  assert.deepEqual(complete(['nosh', 'net', 'learn', '--duration=']), []);

  assert.deepEqual(
    complete(['nosh', 'net', 'approve', '--']),
    [
      '--workload',
      '--revision',
      '--reviewer',
      '--yes',
      '--workdir',
      '--dry-run',
      '--help',
    ],
  );
  assert.deepEqual(
    complete(['nosh', 'net', 'enforce', '--rev']),
    ['--revision'],
  );
  assert.deepEqual(
    complete(['nosh', 'net', 'status', '--']),
    ['--workload', '--json', '--repair', '--workdir', '--dry-run', '--help'],
  );
  assert.deepEqual(
    complete(['nosh', 'net', 'approve', '--revision=']),
    [],
  );
});

test('Nosh completes HTTP capture only for build network learning', () => {
  const learnOptions = complete(['nosh', 'build', 'net', 'learn', '--']);
  assert.ok(learnOptions.includes('--http-capture'));
  assert.equal(
    complete(['nosh', 'build', 'profile', '--']).includes('--http-capture'),
    false,
  );
  assert.equal(
    complete(['nosh', 'build', 'net', 'status', '--'])
      .includes('--http-capture'),
    false,
  );
  assert.equal(
    complete(['nosh', 'net', 'learn', '--']).includes('--http-capture'),
    false,
  );
  assert.deepEqual(
    complete([
      'nosh', 'build', 'net', 'learn', '--http-capture', '',
    ]),
    ['none', 'mitmproxy'],
  );
  assert.deepEqual(
    complete([
      'nosh', 'build', 'net', 'learn', '--http-capture=m',
    ]),
    ['--http-capture=mitmproxy'],
  );
});

test('Nosh completes security modes and comma-separated profiles', () => {
  assert.deepEqual(
    complete(['nosh', '--security-mode', 'l']),
    ['legacy', 'learn'],
  );
  assert.deepEqual(
    complete(['nosh', '--security-mode=l']),
    ['--security-mode=legacy', '--security-mode=learn'],
  );
  assert.deepEqual(
    complete(['nosh', '--security-mode', '=', 'l']),
    ['legacy', 'learn'],
  );
  assert.deepEqual(
    complete([
      'nosh',
      '--workdir',
      '/tmp',
      '--security-mode',
      '=',
      'l',
    ]),
    ['legacy', 'learn'],
  );
  assert.deepEqual(
    complete(['nosh', '-p', 'codex,du']),
    ['codex,durdraw'],
  );
  assert.deepEqual(
    complete(['nosh', '--profile=codex,ar']),
    ['--profile=codex,arduino'],
  );
  assert.deepEqual(
    complete(['nosh', '--config', 'foo', '--profile', '=', 'co']),
    ['codex'],
  );
  assert.deepEqual(complete(['nosh', '-p=co']), []);
  assert.deepEqual(complete(['nosh', '-p', '=', 'co']), []);

  const configuredProfiles = Object.keys(JSON.parse(
    fs.readFileSync(path.join(appRoot, 'config', 'nosh-profiles.json'), 'utf8'),
  ).profiles);
  const completedProfiles = complete(['nosh', '--profile', '']);
  assert.deepEqual(completedProfiles.sort(), configuredProfiles.sort());
});

test('Nosh completes profiles from workspace and user overrides', (t) => {
  const fixture = fs.mkdtempSync(path.join(os.tmpdir(), 'notty-profiles-'));
  t.after(() => fs.rmSync(fixture, { recursive: true, force: true }));
  const home = path.join(fixture, 'home');
  const workspace = path.join(fixture, 'workspace');
  fs.mkdirSync(path.join(home, '.config', 'nosh'), { recursive: true });
  fs.mkdirSync(workspace);
  fs.writeFileSync(
    path.join(workspace, 'nosh.mounts.json'),
    '{"profiles":{"workspace-custom":{},"custom profile":{},"bad$(id)":{}}}\n',
    'utf8',
  );
  fs.writeFileSync(
    path.join(home, '.config', 'nosh', 'nosh.mounts.json'),
    '{"profiles":{"user-custom":{}}}\n',
    'utf8',
  );

  const profiles = complete(['nosh', '--profile', ''], {
    cwd: workspace,
    env: { HOME: home },
  });
  assert.ok(profiles.includes('workspace-custom'));
  assert.ok(profiles.includes('user-custom'));
  assert.ok(!profiles.includes('custom profile'));
  assert.ok(!profiles.includes('bad$(id)'));
  assert.ok(profiles.every((profile) => /^[A-Za-z0-9_.-]+$/.test(profile)));
});

test('Nosh completes config files and directory-valued options', (t) => {
  const fixture = fs.mkdtempSync(path.join(os.tmpdir(), 'notty-completion-'));
  t.after(() => fs.rmSync(fixture, { recursive: true, force: true }));
  fs.writeFileSync(path.join(fixture, 'config one.json'), '{}\n', 'utf8');
  fs.mkdirSync(path.join(fixture, 'security profile'));
  fs.mkdirSync(path.join(fixture, '@scope', 'project'), { recursive: true });
  fs.mkdirSync(path.join(fixture, 'foo:bar', 'project'), { recursive: true });

  assert.deepEqual(
    complete(['nosh', '--config', 'con'], { cwd: fixture }),
    ['config one.json'],
  );
  assert.deepEqual(
    complete(['nosh', '--workdir=sec'], { cwd: fixture }),
    ['--workdir=security profile/'],
  );
  assert.deepEqual(
    complete(['nosh', '--security-profile-dir', 'sec'], { cwd: fixture }),
    ['security profile/'],
  );
  assert.deepEqual(
    complete(['nosh', '--workdir', '=@', 'scope/pro'], { cwd: fixture }),
    ['@scope/project/'],
  );
  assert.deepEqual(
    complete(
      ['nosh', '--workdir', '=', 'foo', ':', 'bar/pro'],
      { cwd: fixture },
    ),
    ['bar/project/'],
  );
});


test('init completes only configuration steps', () => {
  assert.deepEqual(complete(['nosh', 'init', '--step', '']),
    ['install', 'setup', 'build', 'preflight', 'network', 'learn', 'review', 'signing', 'apply', 'status', 'tools-review', 'tools-check', 'tools-apply', 'tools-status', 'tools-init']);
  assert.deepEqual(complete(['nosh', 'init', '--step', 'enforce']), []);
});

test('tool environment commands, modes, and wizard steps complete', () => {
  assert.ok(complete(['nosh', 'tools', '']).includes('apply'));
  assert.ok(complete(['nosh', '--tool-mode', '']).includes('read-only'));
  assert.ok(complete(['nosh', 'init', '--step', 'tools-']).includes('tools-apply'));
});

test('tool initialization offers scopes and output options', () => {
  assert.ok(complete(['nosh', 'tools', '']).includes('init'));
  assert.deepEqual(complete(['nosh', 'tools', 'init', '--scope', '']), ['repo', 'directory', 'all']);
  assert.ok(complete(['nosh', 'tools', 'init', '--']).includes('--no-prompt'));
});

test('tool review completes UI setup options only for review', () => {
  const review = complete(['nosh', 'tools', 'review', '--']);
  assert.ok(review.includes('--build-ui'));
  assert.ok(review.includes('--no-browser'));
  assert.ok(!complete(['nosh', 'tools', 'apply', '--']).includes('--build-ui'));
});
