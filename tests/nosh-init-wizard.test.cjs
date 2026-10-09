'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawnSync } = require('node:child_process');
const test = require('node:test');

const wizard = path.resolve(__dirname, '../scripts/nosh-init.sh');
test('policy manager rejects mismatched and unsafe report scopes', () => {
  const result = spawnSync('python3', ['-B', path.join(__dirname, 'nosh-policy-manager.test.py')], {
    encoding: 'utf8', timeout: 10000,
  });
  assert.equal(result.status, 0, result.stdout + result.stderr);
});
test('TUI state and queue model is deterministic', () => {
  const result = spawnSync('python3', ['-B', path.join(__dirname, 'nosh-init-tui-model.test.py')], {
    encoding: 'utf8', timeout: 10000,
  });
  assert.equal(result.status, 0, result.stdout + result.stderr);
});
test('preflight dry-run prints the read-only inspector without sudo or execution', () => {
  const result = run(['--dry-run', '--step', 'preflight']);
  assert.equal(result.status, 0, result.stdout + result.stderr);
  assert.match(result.stdout, /python3 -I -S .*scripts\/nosh-network-preflight\.py/);
  assert.doesNotMatch(result.stdout, /sudo|Docker network preflight \(read-only\)/);
});
function run(args, input = '') {
  return spawnSync('bash', [wizard, ...args], { input, encoding: 'utf8', timeout: 5000 });
}
function fixture(t) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'nosh-wizard-'));
  fs.chmodSync(root, 0o755);
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  fs.mkdirSync(path.join(root, 'scripts'));
  fs.copyFileSync(wizard, path.join(root, 'scripts/nosh-init.sh'));
  const calls = path.join(root, 'calls');
  fs.writeFileSync(calls, '');
  fs.chmodSync(calls, 0o666);
  const bin = path.join(root, 'bin');
  fs.mkdirSync(bin);
  fs.writeFileSync(path.join(bin, 'sudo'), '#!/bin/bash\nprintf "sudo\\n" >> "$WIZARD_CALLS"\nexec "$@"\n', { mode: 0o755 });
  const prefix = path.join(root, 'guard');
  fs.mkdirSync(path.join(prefix, 'bin'), { recursive: true });
  fs.writeFileSync(path.join(prefix, 'bin/nosh-guard'), '#!/bin/bash\nprintf "%s\\n" "$@" >> "$WIZARD_CALLS"\nexit "${WIZARD_EXIT:-0}"\n', { mode: 0o755 });
  for (const name of ['scripts/setup-nosh.sh', 'scripts/nosh.sh', 'scripts/build-nosh.sh']) {
    fs.writeFileSync(path.join(root, name), '#!/bin/bash\nprintf "%s\\n" "$@" >> "$WIZARD_CALLS"\nexit "${WIZARD_EXIT:-0}"\n', { mode: 0o755 });
  }
  return { root, calls, bin, prefix };
}
const quote = (value) => `'${value.replaceAll("'", "'\\''")}'`;
function terminal(f, args, input, extra = {}) {
  const command = ['bash', path.join(f.root, 'scripts/nosh-init.sh'), ...args].map(quote).join(' ');
  return spawnSync('script', ['-q', '-e', '-c', command, '/dev/null'], {
    input, encoding: 'utf8', timeout: 5000, cwd: f.root,
    env: { ...process.env, PATH: `${f.bin}:${process.env.PATH}`, WIZARD_CALLS: f.calls, ...f.env, ...extra },
    ...(process.getuid() === 0 ? { uid: 65534, gid: 65534 } : {}),
  });
}

function networkFixture(f) {
  fs.mkdirSync(path.join(f.root, 'scripts'), { recursive: true });
  const saved = path.join(f.root, 'network-fixture.json');
  fs.writeFileSync(saved, 'null', { mode: 0o666 });
  fs.chmodSync(saved, 0o666);
  fs.writeFileSync(path.join(f.root, 'scripts/nosh-review-network.py'), `
import json, os, sys
from pathlib import Path
saved = Path(${JSON.stringify(saved)})
arguments = sys.argv[1:]
with open(os.environ['WIZARD_CALLS'], 'a') as stream:
    stream.write('review-network\\n' + '\\n'.join(arguments) + '\\n')
mode = os.environ.get('REVIEW_NETWORK_MODE', 'configured')
if arguments[0] == 'suggest':
    if mode == 'incomplete':
        print('host inspection incomplete', file=sys.stderr)
        sys.exit(1)
    pools = [] if mode == 'exhausted' else [{'pool': '10.0.0.0/26', 'reviewNetworks': 8}]
    print(json.dumps({'schemaVersion': 1, 'status': 'checked', 'suggestions': pools}))
    sys.exit(0)
if arguments[0] == 'configure':
    if mode == 'invalid-pool':
        print('review network: invalid private pool', file=sys.stderr)
        sys.exit(1)
    if mode != 'not-saved':
        saved.write_text(json.dumps({'pool': arguments[arguments.index('--pool') + 1]}))
    print('{}')
    sys.exit(0)
if mode == 'invalid':
    print('review network: invalid configuration', file=sys.stderr)
    sys.exit(1)
record = json.loads(saved.read_text())
configured = mode == 'configured' or record is not None
if mode == 'malformed-status':
    print('{}')
    sys.exit(0)
print(json.dumps({'schemaVersion': 1, 'status': 'configured' if configured else 'missing',
    'pool': (record or {}).get('pool', '10.213.0.0/16') if configured else None,
    'excludedCidrs': [], 'configDigest': 'sha256:' + 'd' * 64 if configured else None}))
sys.exit(0 if configured else 3)
`);
}

test('wizard help, invalid options and noninteractive execution fail safely', () => {
  assert.equal(run(['--help']).status, 0);
  for (const args of [['--image'], ['--unknown'], ['--dry-run', '--step', 'unknown'],
    ['--dry-run', '--guard-prefix', '/opt/../etc']]) {
    assert.notEqual(run(args).status, 0);
  }
  const result = run(['--step', 'setup']);
  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /normal host user|interactive terminal/);
});

test('wizard previews every stage without invoking delegates or sudo', (t) => {
  const f = fixture(t);
  const inputs = {
    install: '', setup: '', build: 'preview-image\n', network: '', readiness: '', learn: '', review: '',
    signing: '', apply: `${f.root}\nsha256:${'a'.repeat(64)}\n`,
    status: '',
  };
  for (const [step, input] of Object.entries(inputs)) {
    const result = spawnSync('bash', [path.join(f.root, 'scripts/nosh-init.sh'), '--dry-run', '--step', step, '--image', 'local-image'], {
      input, encoding: 'utf8', timeout: 5000, cwd: f.root, env: { ...process.env, WIZARD_CALLS: f.calls },
    });
    assert.equal(result.status, 0, `${step}: ${result.stderr}`);
    assert.equal(fs.readFileSync(f.calls, 'utf8'), '');
    assert.equal(fs.readdirSync(f.root).some((name) => name.startsWith('.nosh-install')), false);
  }
});

test('wizard rejects pasted shell commands as an apply digest', (t) => {
  const f = fixture(t);
  const result = run(['--dry-run', '--step', 'apply'], `${f.root}\n$(touch ${f.root}/injected)\n`);
  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /invalid decision digest/);
  assert.equal(fs.existsSync(path.join(f.root, 'injected')), false);
});

const hasScript = spawnSync('script', ['--version'], { encoding: 'utf8' }).status === 0;
const hasPython = spawnSync('python3', ['--version'], { encoding: 'utf8' }).status === 0;
test('wizard status discovers saved stages without treating them as active policy', { skip: !hasPython }, () => {
  const result = spawnSync('python3', ['-B', path.join(__dirname, 'nosh-init-status.test.py')], {
    encoding: 'utf8', timeout: 10000,
  });
  assert.equal(result.status, 0, result.stderr);
});

test('wizard executes only confirmed commands and propagates failure', { skip: !hasScript }, (t) => {
  const f = fixture(t);
  let result = terminal(f, ['--step', 'setup'], 'n\n');
  assert.equal(result.status, 2, result.stderr);
  assert.equal(fs.readFileSync(f.calls, 'utf8'), '');
  result = terminal(f, ['--step', 'setup'], 'y\n', { WIZARD_EXIT: '7' });
  assert.equal(result.status, 7, result.stderr);
  assert.match(result.stdout, /Command exited with status 7/);
  assert.doesNotMatch(result.stdout, /Install the optional Bubble Bai/);
  assert.deepEqual(fs.readFileSync(f.calls, 'utf8').trim().split('\n'), ['--guard-prefix', '/opt/notty', '--require-guard']);
});

test('TUI-confirmed steps do not ask a second generic command question', { skip: !hasScript }, (t) => {
  const f = fixture(t);
  const result = terminal(f, ['--classic', '--tui-confirmed', '--step', 'setup'], 'n\n');
  assert.equal(result.status, 0, result.stdout + result.stderr);
  assert.doesNotMatch(result.stdout, /Run this command\?/);
  assert.deepEqual(fs.readFileSync(f.calls, 'utf8').trim().split('\n'),
    ['--guard-prefix', '/opt/notty', '--require-guard']);
});

test('install offers an explicit cross-prefix purge before building', { skip: !hasScript || process.getuid() !== 0 }, (t) => {
  const f = fixture(t);
  const oldPrefix = path.join(f.root, 'old-guard');
  const installer = path.join(oldPrefix, 'lib/notty/nosh-guard/current/install.sh');
  fs.mkdirSync(path.dirname(installer), { recursive: true });
  fs.writeFileSync(installer,
    '#!/bin/bash\nprintf "uninstaller\\n%s\\n" "$@" >> "$WIZARD_CALLS"\nexit 7\n',
    { mode: 0o755 });
  const receipt = path.join(f.root, 'install-layout.conf');
  fs.writeFileSync(receipt, [
    'SCHEMA_VERSION=1',
    `NOSH_GUARD_PREFIX=${oldPrefix}`,
    `MANIFEST_SHA256=${'a'.repeat(64)}`,
    '',
  ].join('\n'), { mode: 0o644 });
  const wizardCopy = path.join(f.root, 'scripts/nosh-init.sh');
  fs.writeFileSync(wizardCopy, fs.readFileSync(wizardCopy, 'utf8').replace(
    'GUARD_RECEIPT=/etc/nosh-guard-install-layout.conf',
    `GUARD_RECEIPT=${receipt}`,
  ));

  const result = terminal(f, ['--step', 'install', '--guard-prefix', f.prefix], 'y\ny\ny\ny\n');

  assert.equal(result.status, 7, result.stdout + result.stderr);
  assert.match(result.stdout, /Guard is installed under .*old-guard/);
  assert.match(result.stdout, /Purge bundle-managed Guard configuration/);
  assert.match(result.stdout, /Permanently purge all Guard evidence and state/);
  assert.equal(fs.readdirSync(f.root).some((name) => name.startsWith('.nosh-install')), false);
  assert.deepEqual(fs.readFileSync(f.calls, 'utf8').trim().split('\n'), [
    'sudo',
    'uninstaller',
    'uninstall',
    '--purge-config',
    '--purge-state',
    '--prefix',
    oldPrefix,
  ]);
});

function petFixture(t) {
  const f = fixture(t);
  const pet = path.join(f.root, 'bubble-bai-codex');
  fs.mkdirSync(pet);
  for (const name of ['install.sh', 'pet.json', 'spritesheet.png']) {
    fs.copyFileSync(path.resolve(__dirname, '../bubble-bai-codex', name), path.join(pet, name));
  }
  const home = path.join(f.root, 'home');
  fs.mkdirSync(home, { mode: 0o777 });
  fs.chmodSync(home, 0o777);
  f.env = { HOME: home, CODEX_HOME: '' };
  return f;
}

test('optional pet defaults to skipped and discloses Kitty testing before confirmation', { skip: !hasScript }, t => {
  const f = petFixture(t);
  const result = terminal(f, ['--step', 'setup'], 'y\n\n');
  assert.equal(result.status, 0, result.stdout + result.stderr);
  const notice = result.stdout.indexOf('Bubble Bai has only been tested in Kitty terminal. Support in other terminals is unverified.');
  assert.ok(notice >= 0);
  assert.ok(result.stdout.indexOf('Install the optional Bubble Bai Codex pet?') > notice);
  const disclaimer = result.stdout.indexOf('Disclaimer: using Codex with Kitty, pets, and voice is an escape hatch outside the coverage of the eBPF run profile.');
  assert.ok(disclaimer > notice);
  assert.ok(result.stdout.indexOf('Install the optional Bubble Bai Codex pet?') > disclaimer);
  assert.match(result.stdout, /installation skipped/);
  assert.equal(fs.existsSync(path.join(f.env.HOME, '.codex')), false);
});

test('optional pet installs once confirmed, respects CODEX_HOME, and safely reinstalls', { skip: !hasScript }, t => {
  for (const custom of [false, true]) {
    const f = petFixture(t);
    if (custom) f.env.CODEX_HOME = path.join(f.env.HOME, 'custom codex');
    const destination = path.join(f.env.CODEX_HOME || path.join(f.env.HOME, '.codex'), 'pets/bubble-bai');
    for (let attempt = 0; attempt < 2; attempt++) {
      const result = terminal(f, ['--step', 'setup'], 'y\ny\n');
      assert.equal(result.status, 0, result.stdout + result.stderr);
      assert.match(result.stdout, attempt ? /already installed/ : /Installed Bubble Bai/);
      for (const name of ['pet.json', 'spritesheet.png']) {
        assert.deepEqual(fs.readFileSync(path.join(destination, name)),
          fs.readFileSync(path.join(f.root, 'bubble-bai-codex', name)));
      }
    }
    if (custom) assert.equal(fs.existsSync(path.join(f.env.HOME, '.codex')), false);
  }
});

test('conflicting pet files are preserved and failure does not fail launcher setup', { skip: !hasScript }, t => {
  const f = petFixture(t);
  const destination = path.join(f.env.HOME, '.codex/pets/bubble-bai');
  fs.mkdirSync(destination, { recursive: true });
  fs.writeFileSync(path.join(destination, 'pet.json'), 'existing pet');
  const result = terminal(f, ['--step', 'setup'], 'y\ny\n');
  assert.equal(result.status, 0, result.stdout + result.stderr);
  assert.match(result.stdout, /Existing pet directory differs/);
  assert.match(result.stdout, /Nosh setup can continue/);
  assert.match(result.stdout, /Retry separately: sh .*bubble-bai-codex\/install\.sh/);
  assert.equal(fs.readFileSync(path.join(destination, 'pet.json'), 'utf8'), 'existing pet');
});

test('pet dry-run prints the optional command without installing', t => {
  const f = petFixture(t);
  const result = spawnSync('bash', [path.join(f.root, 'scripts/nosh-init.sh'), '--dry-run', '--step', 'setup'], {
    encoding: 'utf8', env: { ...process.env, ...f.env },
  });
  assert.equal(result.status, 0, result.stdout + result.stderr);
  assert.match(result.stdout, /Optional command: sh .*bubble-bai-codex\/install\.sh/);
  assert.equal(fs.existsSync(path.join(f.env.HOME, '.codex')), false);
  assert.equal(fs.readFileSync(f.calls, 'utf8'), '');
});

test('wizard passes workspace metacharacters literally to its delegate', { skip: !hasScript }, (t) => {
  const f = fixture(t);
  networkFixture(f);
  const workspace = path.join(f.root, 'workspace $(touch INJECTED)');
  fs.mkdirSync(workspace, { mode: 0o755 });
  const result = terminal(f, ['--step', 'review', '--workdir', workspace], 'y\n');
  assert.equal(result.status, 0, result.stderr);
  assert.deepEqual(fs.readFileSync(f.calls, 'utf8').trim().split('\n'), ['review-network', 'status', 'net', 'review', '--workdir', workspace, '--workload', 'dev']);
  assert.equal(fs.existsSync(path.join(f.root, 'INJECTED')), false);
});

test('configured review pool is reused without asking again', { skip: !hasScript || !hasPython }, t => {
  const f = fixture(t);
  networkFixture(f);
  const result = terminal(f, ['--step', 'network'], '');
  assert.equal(result.status, 0, result.stdout + result.stderr);
  assert.match(result.stdout, /Reserved review network pool: 10\.213\.0\.0\/16/);
  assert.doesNotMatch(result.stdout, /Run this command|Operator-reserved private IPv4 CIDR/);
  assert.deepEqual(fs.readFileSync(f.calls, 'utf8').trim().split('\n'), ['review-network', 'status']);
});

test('missing review pool is configured with explicit CIDR and separated exclusions before review', { skip: !hasScript || !hasPython }, t => {
  const f = fixture(t);
  networkFixture(f);
  const result = terminal(f, ['--step', 'review'], '10.214.1.0/24,10.214.2.0/24 10.214.3.0/24\nc\n10.213.0.0/16\ny\ny\n', {
    REVIEW_NETWORK_MODE: 'missing',
  });
  assert.equal(result.status, 0, result.stdout + result.stderr);
  assert.match(result.stdout, /Each review receives a \/29 subnet/);
  assert.match(result.stdout, /Docker daemon settings stay unchanged/);
  assert.match(result.stdout, /Custom private IPv4 CIDR/);
  assert.deepEqual(fs.readFileSync(f.calls, 'utf8').trim().split('\n'), [
    'review-network', 'status', 'review-network', 'suggest',
    '--exclude', '10.214.1.0/24', '--exclude', '10.214.2.0/24', '--exclude', '10.214.3.0/24',
    'review-network', 'configure', '--check-host', '--pool', '10.213.0.0/16',
    '--exclude', '10.214.1.0/24', '--exclude', '10.214.2.0/24', '--exclude', '10.214.3.0/24',
    'review-network', 'status', 'net', 'review', '--workdir', f.root, '--workload', 'dev',
  ]);
});

test('declining missing review network setup stops without choosing a pool', { skip: !hasScript || !hasPython }, async t => {
  for (const input of ['\n0\n', '\n\nn\n']) {
    await t.test(JSON.stringify(input), t => {
      const f = fixture(t);
      networkFixture(f);
      const result = terminal(f, ['--step', 'review'], input, { REVIEW_NETWORK_MODE: 'missing' });
      assert.equal(result.status, 2, result.stdout + result.stderr);
      assert.deepEqual(fs.readFileSync(f.calls, 'utf8').trim().split('\n'), ['review-network', 'status', 'review-network', 'suggest']);
    });
  }
});

test('invalid review network state or rejected CIDR stops before opening review', { skip: !hasScript || !hasPython }, async t => {
  for (const mode of ['invalid', 'malformed-status', 'invalid-pool', 'not-saved']) {
    await t.test(mode, t => {
      const f = fixture(t);
      networkFixture(f);
      const result = terminal(f, ['--step', 'review'], '\ninvalid-cidr\ny\n', { REVIEW_NETWORK_MODE: mode });
      assert.equal(result.status, 1, result.stdout + result.stderr);
      assert.doesNotMatch(fs.readFileSync(f.calls, 'utf8'), /net\nreview/);
      if (mode === 'not-saved') assert.match(result.stdout, /configuration was not saved/);
    });
  }
});

test('review network input is passed literally to its validating helper', { skip: !hasScript || !hasPython }, t => {
  const f = fixture(t);
  networkFixture(f);
  const pool = '$(touch INJECTED)';
  const exclude = '$(touch${IFS}EXCLUDED)';
  const result = terminal(f, ['--step', 'network'], `${exclude}\n${pool}\ny\n`, { REVIEW_NETWORK_MODE: 'invalid-pool' });
  assert.equal(result.status, 1, result.stdout + result.stderr);
  assert.deepEqual(fs.readFileSync(f.calls, 'utf8').trim().split('\n'), [
    'review-network', 'status', 'review-network', 'suggest', '--exclude', exclude,
    'review-network', 'configure', '--check-host', '--pool', pool, '--exclude', exclude,
  ]);
  assert.equal(fs.existsSync(path.join(f.root, 'INJECTED')), false);
  assert.equal(fs.existsSync(path.join(f.root, 'EXCLUDED')), false);
});

test('advanced review also checks the reserved network before launching', { skip: !hasScript || !hasPython }, t => {
  const f = fixture(t);
  networkFixture(f);
  const result = terminal(f, ['--advanced'], '5\n\n0\n0\n', { REVIEW_NETWORK_MODE: 'missing' });
  assert.equal(result.status, 0, result.stdout + result.stderr);
  assert.match(result.stdout, /no pool was saved/);
  assert.deepEqual(fs.readFileSync(f.calls, 'utf8').trim().split('\n'), ['review-network', 'status', 'review-network', 'suggest']);
});

test('Enter selects the first checked /26 and saves only after confirmation', { skip: !hasScript || !hasPython }, t => {
  const f = fixture(t);
  networkFixture(f);
  const result = terminal(f, ['--step', 'network'], '\n\ny\n', { REVIEW_NETWORK_MODE: 'missing' });
  assert.equal(result.status, 0, result.stdout + result.stderr);
  assert.match(result.stdout, /10\.0\.0\.0\/26.*eight/);
  assert.match(fs.readFileSync(f.calls, 'utf8'), /configure\n--check-host\n--pool\n10\.0\.0\.0\/26/);
});

test('incomplete suggestion inspection stops when retry is declined', { skip: !hasScript || !hasPython }, t => {
  const f = fixture(t);
  networkFixture(f);
  const result = terminal(f, ['--step', 'network'], '\nn\n', { REVIEW_NETWORK_MODE: 'incomplete' });
  assert.equal(result.status, 1, result.stdout + result.stderr);
  assert.doesNotMatch(fs.readFileSync(f.calls, 'utf8'), /configure/);
});

test('exhausted suggestions offer custom input without choosing an automatic pool', { skip: !hasScript || !hasPython }, t => {
  const f = fixture(t);
  networkFixture(f);
  const result = terminal(f, ['--step', 'network'], '\n0\n', { REVIEW_NETWORK_MODE: 'exhausted' });
  assert.equal(result.status, 2, result.stdout + result.stderr);
  assert.match(result.stdout, /No clear suggestions/);
  assert.doesNotMatch(fs.readFileSync(f.calls, 'utf8'), /configure/);
});

test('wizard stays on an incomplete step and lets the user quit', { skip: !hasScript }, (t) => {
  const f = fixture(t);
  const result = terminal(f, ['--advanced'], '2\ny\n0\n', { WIZARD_EXIT: '7' });
  assert.equal(result.status, 0, result.stderr);
  assert.match(result.stdout, /Step not completed/);
  assert.doesNotMatch(result.stdout, /Step returned successfully/);
});

test('learning automatically uses the discovered local image without asking for a tag', { skip: !hasScript || !hasPython }, (t) => {
  const f = fixture(t);
  fs.mkdirSync(path.join(f.root, 'scripts'), { recursive: true });
  fs.copyFileSync(path.resolve(__dirname, '../scripts/nosh-init-status.py'), path.join(f.root, 'scripts/nosh-init-status.py'));
  fs.copyFileSync(path.resolve(__dirname, '../scripts/nosh_policy_manager.py'), path.join(f.root, 'scripts/nosh_policy_manager.py'));
  const bin = path.join(f.root, 'bin');
  const image = `sha256:${'c'.repeat(64)}`;
  fs.writeFileSync(path.join(bin, 'docker'), `#!/bin/bash
case "$*" in
  'context inspect --format '{{.Endpoints.docker.Host}}) printf 'unix:///var/run/docker.sock\\n' ;;
  *'{{.Id}}|'*) printf '${image}|1\\n' ;;
  *'{{.Id}}'*) printf '${image}\\n' ;;
  *runner-abi*) printf '1\\n' ;;
  *) exit 2 ;;
esac
`, { mode: 0o755 });
  const result = terminal(f, ['--step', 'learn', '--guard-prefix', f.prefix], 'n\ny\n', {
    PATH: `${bin}:${process.env.PATH}`, HOME: f.root,
    DOCKER_HOST: 'unix:///var/run/docker.sock',
  });
  assert.equal(result.status, 0, result.stdout + result.stderr);
  assert.doesNotMatch(result.stdout, /Local workload image tag or sha256 ID/);
  assert.match(result.stdout, new RegExp(`Using local workload image: ${image}`));
  const args = fs.readFileSync(f.calls, 'utf8').trim().split('\n');
  assert.deepEqual(args.slice(0, 3), ['sudo', 'net', 'learn']);
  assert.equal(args[args.indexOf('--image') + 1], image);
  assert.ok(args.includes('--review-output'));
  assert.ok(args.includes('--no-start-app'));
});

for (const [workload, appOption] of [['dev', '--start-app'], ['run', '--no-start-app']]) {
  test(`guided ${workload} recording honors ${appOption} without another application prompt`, { skip: !hasScript }, t => {
    const f = fixture(t);
    const image = `sha256:${'c'.repeat(64)}`;
    fs.writeFileSync(path.join(f.bin, 'docker'), `#!/bin/bash
case "$*" in *runner-abi*) printf '1\\n';; *) printf '${image}\\n';; esac
`, { mode: 0o755 });
    const result = terminal(f, ['--step', 'learn', '--guard-prefix', f.prefix,
      '--image', image, '--workload', workload, appOption, '--tui-confirmed'], '');
    assert.equal(result.status, 0, result.stdout + result.stderr);
    assert.doesNotMatch(result.stdout, /Start the bundled|Run this command\?/);
    const args = fs.readFileSync(f.calls, 'utf8').trim().split('\n');
    assert.ok(args.includes(appOption));
    assert.equal(args[args.indexOf('--workload') + 1], workload);
  });
}

test('guided network selection performs host checks and rereads saved pool without asking again', { skip: !hasScript || !hasPython }, t => {
  const f = fixture(t);
  networkFixture(f);
  const result = terminal(f, ['--step', 'network', '--review-pool', '10.0.0.0/26',
    '--exclude', '192.168.0.0/16', '--tui-confirmed'], '', { REVIEW_NETWORK_MODE: 'missing' });
  assert.equal(result.status, 0, result.stdout + result.stderr);
  assert.doesNotMatch(result.stdout, /Review pool \[|Additional LAN\/VPN|Run this command\?/);
  assert.match(result.stdout, /Reserved review network pool: 10\.0\.0\.0\/26/);
  const calls = fs.readFileSync(f.calls, 'utf8');
  assert.match(calls, /configure\n--check-host\n--pool\n10\.0\.0\.0\/26\n--exclude\n192\.168\.0\.0\/16/);
  assert.match(calls, /status\n/);
});

test('guided network setup cannot advance when the selected pool is not saved', { skip: !hasScript || !hasPython }, t => {
  const f = fixture(t);
  networkFixture(f);
  const result = terminal(f, ['--step', 'network', '--review-pool', '10.0.0.0/26',
    '--tui-confirmed'], '', { REVIEW_NETWORK_MODE: 'not-saved' });
  assert.equal(result.status, 1, result.stdout + result.stderr);
  assert.match(result.stdout, /configuration was not saved/);
});

test('init rejects enforcement as a setup step', t => {
  const result = run(['--dry-run', '--step', 'enforce']);
  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /unknown step: enforce/);
});

test('interrupted learning retains failure status but follows detected next-step hints', { skip: !hasScript || !hasPython }, (t) => {
  const f = fixture(t);
  fs.mkdirSync(path.join(f.root, 'scripts'), { recursive: true });
  fs.writeFileSync(path.join(f.root, 'scripts/nosh-init-status.py'),
    "print('4\\tsaved\\tmatching export')\nprint('next\\t5')\n".replaceAll('\\t', '\t'));
  const image = `sha256:${'d'.repeat(64)}`;
  fs.writeFileSync(path.join(f.bin, 'docker'), `#!/bin/bash
case "$*" in
  *runner-abi*) printf '1\\n' ;;
  *) printf '${image}\\n' ;;
esac
`, { mode: 0o755 });
  const args = ['--advanced', '--image', image, '--guard-prefix', f.prefix];
  const result = terminal(f, args, '4\nn\ny\n0\n', { WIZARD_EXIT: '137' });
  assert.equal(result.status, 0, result.stdout + result.stderr);
  assert.match(result.stdout, /Command exited with status 137/);
  assert.match(result.stdout, /policy export may still have been saved/);
  assert.match(result.stdout, /Step \[5\]:/);
  assert.doesNotMatch(result.stdout, /Step returned successfully|This step is incomplete/);
  const single = terminal(f, ['--step', 'learn', ...args], 'n\ny\n', { WIZARD_EXIT: '137' });
  assert.equal(single.status, 137, single.stdout + single.stderr);
});

test('Apply discovers one saved review and requires confirmation without asking for its path', { skip: !hasScript || !hasPython }, t => {
  const f = fixture(t);
  const session = path.join(f.root, 'review with spaces');
  fs.mkdirSync(session);
  const digest = `sha256:${'e'.repeat(64)}`;
  fs.mkdirSync(path.join(f.root, 'scripts'), { recursive: true });
  fs.writeFileSync(path.join(f.root, 'scripts/nosh-init-status.py'),
    `print(${JSON.stringify(`review:0\t${session}\t${digest}`)})\n`);
  const declined = terminal(f, ['--step', 'apply'], 'n\n');
  assert.equal(declined.status, 2);
  assert.equal(fs.readFileSync(f.calls, 'utf8'), '');
  const result = terminal(f, ['--step', 'apply'], 'y\n');
  assert.equal(result.status, 0, result.stdout + result.stderr);
  assert.match(result.stdout, /Selected saved review:/);
  assert.doesNotMatch(result.stdout, /Review session directory:|Saved decision digest \(sha256/);
  assert.deepEqual(fs.readFileSync(f.calls, 'utf8').trim().split('\n'), [
    'net', 'apply', '--workload', 'dev', '--review', session, '--decision-digest', digest,
  ]);
});

test('Apply requires a choice among matching reviews and passes the chosen digest literally', { skip: !hasScript || !hasPython }, t => {
  const f = fixture(t);
  const sessions = ['first', "second $(touch INJECTED)"].map(name => path.join(f.root, name));
  sessions.forEach(dir => fs.mkdirSync(dir));
  const digests = ['a', 'b'].map(char => `sha256:${char.repeat(64)}`);
  fs.mkdirSync(path.join(f.root, 'scripts'), { recursive: true });
  fs.writeFileSync(path.join(f.root, 'scripts/nosh-init-status.py'), sessions.map((dir, i) =>
    `print(${JSON.stringify(`review:${i}\t${dir}\t${digests[i]}`)})`).join('\n'));
  assert.notEqual(terminal(f, ['--step', 'apply'], '3\n').status, 0);
  assert.equal(fs.readFileSync(f.calls, 'utf8'), '');
  const result = terminal(f, ['--step', 'apply'], '2\ny\n');
  assert.equal(result.status, 0, result.stdout + result.stderr);
  assert.deepEqual(fs.readFileSync(f.calls, 'utf8').trim().split('\n'), [
    'net', 'apply', '--workload', 'dev', '--review', sessions[1], '--decision-digest', digests[1],
  ]);
  assert.equal(fs.existsSync(path.join(f.root, 'INJECTED')), false);
});

function guidedFixture(t) {
  const f = fixture(t);
  // Routing prerequisites are fixture inputs, not requirements on the test host.
  fs.writeFileSync(path.join(f.bin, 'ip'), '#!/bin/bash\nprintf "default via fe80::1 dev eth0 proto static\\n"\n', { mode: 0o755 });
  fs.writeFileSync(path.join(f.bin, 'cat'), `#!/bin/bash
case "\${1:-}" in
  /proc/sys/net/ipv6/conf/all/disable_ipv6) printf '0\\n' ;;
  /proc/sys/net/ipv6/conf/all/forwarding) printf '1\\n' ;;
  /proc/sys/net/ipv6/conf/*/accept_ra) printf '2\\n' ;;
  *) exec /bin/cat "$@" ;;
esac
`, { mode: 0o755 });
  f.image = `sha256:${'a'.repeat(64)}`;
  f.tooling = `sha256:${'e'.repeat(64)}`;
  f.digest = `sha256:${'b'.repeat(64)}`;
  f.session = path.join(f.root, 'saved-review');
  fs.mkdirSync(f.session);
  fs.mkdirSync(path.join(f.root, 'scripts'), { recursive: true });
  networkFixture(f);
  f.state = path.join(f.root, 'state');
  fs.mkdirSync(f.state, { mode: 0o700 });
  f.imageConfig = path.join(f.state, 'images.conf');
  fs.writeFileSync(f.imageConfig, `SCHEMA_VERSION=1\n# Keep the reviewed UI selection\nNOSH_POLICY_REVIEW_UI_IMAGE=sha256:${'f'.repeat(64)}\nNOSH_POLICY_TOOLING_IMAGE=sha256:${'c'.repeat(64)}\n`, { mode: 0o600 });
  f.signingConfig = path.join(f.state, 'signing.json');
  fs.writeFileSync(f.signingConfig, 'signing configuration must remain unchanged', { mode: 0o600 });
  if (process.getuid() === 0) {
    for (const file of [f.state, f.imageConfig, f.signingConfig]) fs.chownSync(file, 65534, 65534);
  }
  f.env = { NOSH_PROFILE_REVIEW_IMAGE_CONFIG: f.imageConfig, NOSH_POLICY_TOOLING_IMAGE: '',
    NOSH_POLICY_APPLY_CONFIG: f.signingConfig };
  fs.copyFileSync(path.resolve(__dirname, '../scripts/nosh-save-tooling.py'), path.join(f.root, 'scripts/nosh-save-tooling.py'));
  const rows = ['1\tpresent\tfixture', '2\tconfigured\tfixture', '3\tavailable\tfixture',
    '4\tsaved\tfixture', '5\tsaved\tfixture', '6\tconfigured\tfixture',
    `image\t${f.image}\t1`, `revision\tlearn-guided\t${f.image}`, `review:0\t${f.session}\t${f.digest}`, 'next\t7'];
  fs.writeFileSync(path.join(f.root, 'scripts/nosh-init-status.py'), rows.map(row => `print(${JSON.stringify(row)})`).join('\n'));
  fs.writeFileSync(path.join(f.bin, 'docker'), `#!/bin/bash
case "$*" in *runner-abi*) printf '1\\n';; *nosh-policy-tooling:startup-*) printf '${f.tooling}\\n';; *) printf '${f.image}\\n';; esac
`, { mode: 0o755 });
  fs.writeFileSync(path.join(f.root, 'scripts/build-nosh.sh'), '#!/bin/bash\nprintf "build\\n%s\\n%s\\n" "$IMAGE_NAME" "$TARGET" >> "$WIZARD_CALLS"\nexit "${BUILD_EXIT:-0}"\n', { mode: 0o755 });
  fs.writeFileSync(path.join(f.root, 'scripts/nosh-net-review.sh'), `#!/bin/bash
printf '%s\\n' "$@" >> "$WIZARD_CALLS"
if [[ $1 == prepare ]]; then exit "\${PREPARE_EXIT:-0}"; fi
if [[ $1 == tooling-status ]]; then
  exec node "$PWD/probe-fixture.cjs" "$3"
fi
`, { mode: 0o755 });
  fs.writeFileSync(path.join(f.root, 'probe-fixture.cjs'), `
const fs = require('node:fs');
if (process.env.TOOLING_MODE === 'daemon-error') { console.error('Docker daemon unavailable'); process.exit(1); }
const filename = process.env.NOSH_PROFILE_REVIEW_IMAGE_CONFIG;
const config = fs.existsSync(filename) ? fs.readFileSync(filename, 'utf8') : '';
let image = process.env.NOSH_POLICY_TOOLING_IMAGE || config.match(/^NOSH_POLICY_TOOLING_IMAGE=(.+)$/m)?.[1] || 'sha256:${'c'.repeat(64)}';
let status = process.env.TOOLING_MODE === 'outdated' && image !== '${f.tooling}' ? 'needs-build' : 'ready';
if (image === '${f.tooling}' && process.env.REBUILT_MODE === 'incompatible') status = 'needs-build';
if (image === '${f.tooling}' && process.env.REBUILT_MODE === 'mismatch') image = 'sha256:${'d'.repeat(64)}';
fs.writeFileSync(process.argv[2], JSON.stringify({schemaVersion:1,status,toolingImage:image,reason:'Local tooling needs an update.'}), {mode:0o600,flag:'wx'});
process.exit(status === 'ready' ? 0 : 3);
`);
  fs.writeFileSync(path.join(f.root, 'result-fixture.json'), JSON.stringify({ schemaVersion: 1,
    workspace: f.root, revision: 'learn-guided', session: f.session, decisionDigest: f.digest,
    activation: { imageDigest: f.image, learnRevision: 'learn-guided', leafBundleDigest: `sha256:${'c'.repeat(64)}` } }), { mode: 0o644 });
  fs.writeFileSync(path.join(f.root, 'scripts/nosh.sh'), '#!/bin/bash\nprintf "%s\\n" "$@" >> "$WIZARD_CALLS"\nwhile (($#)); do\n if [[ $1 == --result-json ]]; then cp "$PWD/result-fixture.json" "$2"; chmod 600 "$2"; exit 0; fi\n shift\ndone\n', { mode: 0o755 });
  return f;
}

test('guided resume validates prerequisites then reports the applied revision without launching a container', { skip: !hasScript || !hasPython }, t => {
  const f = guidedFixture(t);
  const result = terminal(f, ['--guard-prefix', f.prefix], 'y\ny\ny\ny\ny\nn\n');
  assert.equal(result.status, 0, result.stdout + result.stderr);
  const calls = fs.readFileSync(f.calls, 'utf8');
  const ordered = ['doctor\n', 'review-network\nstatus\n', 'tooling-status\n', 'inventory\n', 'prepare\n', 'check\n', 'net\napply\n'];
  let previous = -1;
  for (const command of ordered) {
    const index = calls.indexOf(command);
    assert.ok(index > previous, calls);
    previous = index;
  }
  assert.doesNotMatch(calls, /net\nenforce\n/);
  assert.doesNotMatch(result.stdout, /Review session directory:|Approved workspace directory|Approved learning revision|Start the bundled/);
  assert.match(result.stdout, /Initialization complete/);
  assert.ok(result.stdout.includes(`nosh start --workdir ${f.root}`));
  assert.ok(result.stdout.includes(`Image: ${f.image}`));
  assert.match(result.stdout, /Revision: learn-guided/);
});

test('guided setup reserves review networking before tooling or inventories', { skip: !hasScript || !hasPython }, t => {
  const f = guidedFixture(t);
  const result = terminal(f, ['--guard-prefix', f.prefix], 'y\n\n\nn\n', { REVIEW_NETWORK_MODE: 'missing' });
  assert.equal(result.status, 2, result.stdout + result.stderr);
  assert.match(result.stdout, /Setup stopped at Reserve the review network pool/);
  const calls = fs.readFileSync(f.calls, 'utf8');
  assert.ok(calls.indexOf('doctor\n') < calls.indexOf('review-network\nstatus\n'));
  assert.doesNotMatch(calls, /tooling-status\n|inventory\n|net\napply|net\nreview/);
});

test('guided preparation stops before review and Apply when evidence is blocked', { skip: !hasScript || !hasPython }, t => {
  const f = guidedFixture(t);
  const result = terminal(f, ['--guard-prefix', f.prefix], 'y\ny\ny\n', { PREPARE_EXIT: '2' });
  assert.equal(result.status, 2, result.stdout + result.stderr);
  assert.match(result.stdout, /Setup stopped at Check evidence/);
  assert.doesNotMatch(fs.readFileSync(f.calls, 'utf8'), /net\napply|net\nenforce|net\nreview/);
});

test('guided setup rebuilds outdated tools, remembers the exact image and resumes with the saved workload', { skip: !hasScript || !hasPython }, t => {
  const f = guidedFixture(t);
  const result = terminal(f, ['--guard-prefix', f.prefix], 'y\ny\ny\ny\ny\ny\nn\n', { TOOLING_MODE: 'outdated' });
  assert.equal(result.status, 0, result.stdout + result.stderr);
  assert.match(result.stdout, /may download build dependencies/);
  assert.match(result.stdout, /Remembered verified tooling image/);
  const calls = fs.readFileSync(f.calls, 'utf8');
  assert.match(calls, /build\nnosh-policy-tooling:startup-[a-f0-9]{12}\nlocal/);
  assert.equal(calls.split('tooling-status\n').length - 1, 2);
  assert.ok(calls.indexOf('build\n') < calls.indexOf('inventory\n'), calls);
  assert.match(calls, new RegExp(`inventory\\n--workdir\\n${f.root}\\n--image\\n${f.image}`));
  assert.doesNotMatch(calls, /net\nenforce\n/);
  assert.equal(fs.readFileSync(f.imageConfig, 'utf8'), `SCHEMA_VERSION=1\n# Keep the reviewed UI selection\nNOSH_POLICY_REVIEW_UI_IMAGE=sha256:${'f'.repeat(64)}\nNOSH_POLICY_TOOLING_IMAGE=${f.tooling}\n`);
  assert.equal(fs.readFileSync(f.signingConfig, 'utf8'), 'signing configuration must remain unchanged');

  fs.writeFileSync(f.calls, '');
  const resumed = terminal(f, ['--guard-prefix', f.prefix], 'y\ny\ny\ny\ny\nn\n', { TOOLING_MODE: 'outdated' });
  assert.equal(resumed.status, 0, resumed.stdout + resumed.stderr);
  assert.match(resumed.stdout, /Local policy tooling is ready/);
  assert.doesNotMatch(fs.readFileSync(f.calls, 'utf8'), /build\n/);
});

test('declining a tooling build stops before inventories or policy changes', { skip: !hasScript || !hasPython }, t => {
  const f = guidedFixture(t);
  const before = fs.readFileSync(f.imageConfig, 'utf8');
  const result = terminal(f, ['--guard-prefix', f.prefix], 'y\nn\n', { TOOLING_MODE: 'outdated' });
  assert.equal(result.status, 2, result.stdout + result.stderr);
  assert.match(result.stdout, /Setup stopped at Prepare policy tools/);
  assert.doesNotMatch(fs.readFileSync(f.calls, 'utf8'), /build\n|inventory\n|net\napply/);
  assert.equal(fs.readFileSync(f.imageConfig, 'utf8'), before);
});

test('the first tooling rebuild creates private configuration without requiring a manually selected UI', { skip: !hasScript || !hasPython }, t => {
  const f = guidedFixture(t);
  fs.unlinkSync(f.imageConfig);
  const result = terminal(f, ['--guard-prefix', f.prefix], 'y\ny\ny\ny\ny\ny\nn\n', { TOOLING_MODE: 'outdated' });
  assert.equal(result.status, 0, result.stdout + result.stderr);
  const saved = fs.readFileSync(f.imageConfig, 'utf8');
  assert.match(saved, /^SCHEMA_VERSION=1$/m);
  assert.match(saved, new RegExp(`^NOSH_POLICY_TOOLING_IMAGE=${f.tooling}$`, 'm'));
  assert.match(saved, /^NOSH_POLICY_REVIEW_UI_IMAGE=$/m);
  assert.equal(fs.statSync(f.imageConfig).mode & 0o777, 0o600);
  assert.doesNotMatch(fs.readFileSync(f.calls, 'utf8'), /net\nenforce\n/);
});

test('failed or incompatible tooling builds leave the prior configuration intact', { skip: !hasScript || !hasPython }, async t => {
  for (const [extra, expected] of [[{ BUILD_EXIT: '8' }, 8], [{ REBUILT_MODE: 'incompatible' }, 3], [{ REBUILT_MODE: 'mismatch' }, 1]]) {
    await t.test(JSON.stringify(extra), t => {
      const f = guidedFixture(t);
      const before = fs.readFileSync(f.imageConfig, 'utf8');
      const result = terminal(f, ['--guard-prefix', f.prefix], 'y\ny\n', { TOOLING_MODE: 'outdated', ...extra });
      assert.equal(result.status, expected, result.stdout + result.stderr);
      assert.match(result.stdout, /Setup stopped at Prepare policy tools/);
      assert.doesNotMatch(fs.readFileSync(f.calls, 'utf8'), /inventory\n|net\napply/);
      assert.equal(fs.readFileSync(f.imageConfig, 'utf8'), before);
    });
  }
});

test('Docker readiness failure stops without proposing or running a tooling rebuild', { skip: !hasScript || !hasPython }, t => {
  const f = guidedFixture(t);
  const result = terminal(f, ['--guard-prefix', f.prefix], 'y\n', { TOOLING_MODE: 'daemon-error' });
  assert.equal(result.status, 1, result.stdout + result.stderr);
  assert.match(result.stdout, /Docker daemon unavailable/);
  assert.doesNotMatch(result.stdout, /may download build dependencies/);
  assert.doesNotMatch(fs.readFileSync(f.calls, 'utf8'), /build\n|inventory\n|net\napply/);
});


test('a mismatched Apply result cannot complete initialization or launch', { skip: !hasScript || !hasPython }, t => {
  const f = guidedFixture(t);
  const filename = path.join(f.root, 'result-fixture.json');
  const resultFixture = JSON.parse(fs.readFileSync(filename, 'utf8'));
  resultFixture.activation.imageDigest = `sha256:${'0'.repeat(64)}`;
  fs.writeFileSync(filename, JSON.stringify(resultFixture));
  const result = terminal(f, ['--guard-prefix', f.prefix], 'y\ny\ny\ny\ny\n');
  assert.notEqual(result.status, 0, result.stdout + result.stderr);
  assert.match(result.stdout, /Apply result does not match/);
  assert.doesNotMatch(result.stdout, /Initialization complete|Start or attach:/);
  assert.doesNotMatch(fs.readFileSync(f.calls, 'utf8'), /net\nenforce\n/);
});

test('tool environment wizard steps preserve report, digest, and workspace arguments', () => {
  for (const [step, action] of [['tools-review', 'review'], ['tools-check', 'check'], ['tools-apply', 'apply'], ['tools-status', 'status']]) {
    const result = run(['--dry-run', '--step', step, '--review', '/tmp/saved-audit', '--policy-digest', `sha256:${'c'.repeat(64)}`]);
    assert.equal(result.status, 0, result.stderr);
    assert.ok(result.stdout.includes(`tools ${action} --workdir`), result.stdout);
    if (action === 'apply') assert.ok(result.stdout.includes(`--policy-digest sha256:${'c'.repeat(64)}`));
  }
});

test('tool initialization wizard step starts a scoped audit without requesting an existing report', () => {
  const result = run(['--dry-run', '--step', 'tools-init', '--codex-home', '/tmp/custom-history']);
  assert.equal(result.status, 0, result.stderr);
  assert.match(result.stdout, /tools init --workdir/);
  assert.match(result.stdout, /--codex-home \/tmp\/custom-history/);
  assert.doesNotMatch(result.stdout, /--review|--policy-digest|sudo/);
});
