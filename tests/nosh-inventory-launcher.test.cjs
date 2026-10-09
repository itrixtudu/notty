'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawnSync } = require('node:child_process');
const test = require('node:test');

const launcher = path.resolve(__dirname, '../scripts/nosh-inventory.sh');
const TOOLING = `sha256:${'a'.repeat(64)}`;
const IMAGE = `sha256:${'b'.repeat(64)}`;
const OTHER = `sha256:${'c'.repeat(64)}`;

function fixture(t, config = {}) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'nosh-inventory-launcher-'));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const bin = path.join(root, 'bin');
  const workspace = path.join(root, 'workspace with spaces');
  const output = path.join(root, 'output');
  const calls = path.join(root, 'docker-calls.jsonl');
  fs.mkdirSync(bin);
  fs.mkdirSync(workspace);
  fs.writeFileSync(calls, '');
  if (config.runCollision || config.createCollision) fs.writeFileSync(path.join(root, 'foreign'), 'foreign container');
  fs.writeFileSync(path.join(bin, 'docker'), `#!${process.execPath}
const fs = require('node:fs');
const args = process.argv.slice(2);
const config = JSON.parse(process.env.INVENTORY_MOCK || '{}');
fs.appendFileSync(process.env.INVENTORY_CALLS, JSON.stringify(args) + '\\n');
const value = flag => args[args.indexOf(flag) + 1];
const fail = message => { process.stderr.write(message); process.exit(99); };
if (args[0] === 'image' && args[1] === 'inspect') {
  if (args.includes('--format')) {
    process.stdout.write(config.toolingMismatch ? '${OTHER}|1' : '${TOOLING}|1');
  } else process.stdout.write(JSON.stringify([{ Id: config.imageId || '${IMAGE}',
    Config: { Volumes: config.volumes ? { '/data': {} } : null } }]));
} else if (args[0] === 'run') {
  const command = args[args.indexOf('/app/scripts/nosh-inventory.py') + 1];
  if (!['--version', 'source', 'image'].includes(command)) fail('unexpected collector command');
  if (config.runCollision === command) process.exit(125);
  if (args.includes('--cidfile')) fs.writeFileSync(value('--cidfile'), 'e'.repeat(64));
  process.exit(config[command === '--version' ? 'versionExit' : command + 'Exit'] || 0);
} else if (args[0] === 'create') {
  if (config.createCollision) process.exit(125);
  const id = 'd'.repeat(64);
  fs.writeFileSync(process.env.INVENTORY_CLIENT, id);
  if (args.includes('--cidfile')) fs.writeFileSync(value('--cidfile'), id);
  process.stdout.write(id);
  process.exit(config.createExit || 0);
} else if (args[0] === 'container' && args[1] === 'inspect') {
  if (!args.includes('--format')) {
    if (args.at(-1) === 'd'.repeat(64)) process.exit(fs.existsSync(process.env.INVENTORY_CLIENT) ? 0 : 1);
    process.exit(config.collectorRemains ? 0 : 1);
  }
  process.stdout.write((config.containerImage || '${IMAGE}') + '|' +
    (config.containerState || 'created') + '|' + (config.containerMounts || '0'));
} else if (args[0] === 'export') {
  fs.writeFileSync(value('--output'), 'mock stopped filesystem archive');
  process.exit(config.exportExit || 0);
} else if (args[0] === 'rm') {
  if (args.at(-1) === 'd'.repeat(64)) fs.rmSync(process.env.INVENTORY_CLIENT, { force: true });
  if (args.at(-1).startsWith('nosh-inventory-')) fs.rmSync(process.env.INVENTORY_FOREIGN, { force: true });
} else fail('unexpected docker command: ' + args.join(' '));
`, { mode: 0o755 });
  fs.writeFileSync(path.join(bin, 'jq'), `#!${process.execPath}
const fs = require('node:fs');
const expression = process.argv.at(-1);
const document = JSON.parse(fs.readFileSync(0, 'utf8'));
if (expression === '.[0].Id') process.stdout.write(document[0].Id + '\\n');
else if (expression === '.[0].Config.Volumes // {} | length == 0') {
  process.exit(Object.keys(document[0].Config.Volumes || {}).length === 0 ? 0 : 1);
} else process.exit(99);
`, { mode: 0o755 });
  return {
    root, output, workspace, calls,
    run(args = []) {
      return spawnSync('bash', [launcher, '--workdir', workspace, '--image', IMAGE,
        '--tooling', TOOLING, '--output', output, ...args], {
        encoding: 'utf8', timeout: 10000,
        env: { ...process.env, PATH: `${bin}:${process.env.PATH}`,
          NOSH_NET_REVIEW_DOCKER_BIN: path.join(bin, 'docker'),
          INVENTORY_CALLS: calls, INVENTORY_CLIENT: path.join(root, 'client'),
          INVENTORY_FOREIGN: path.join(root, 'foreign'),
          INVENTORY_MOCK: JSON.stringify(config) },
      });
    },
    commands() { return fs.readFileSync(calls, 'utf8').trim().split('\n').filter(Boolean).map(JSON.parse); },
  };
}

const argument = (args, flag) => args[args.indexOf(flag) + 1];
function assertCleaned(f) {
  assert.equal(fs.existsSync(path.join(f.root, 'client')), false);
  assert.equal(fs.readdirSync(f.root).some(name => name.startsWith('.nosh-inventory-export.')), false);
  assert.equal(fs.readdirSync(f.root).some(name => name.startsWith('.nosh-inventory-run.')), false);
}

test('inventory runs only the local collector offline and exports an unstarted workload', t => {
  const f = fixture(t);
  const result = f.run();
  assert.equal(result.status, 0, result.stderr);
  const calls = f.commands();
  const runs = calls.filter(args => args[0] === 'run');
  assert.equal(runs.length, 3);
  for (const args of runs) {
    assert.equal(argument(args, '--pull'), 'never');
    assert.equal(argument(args, '--network'), 'none');
    assert.equal(argument(args, '--user'), `${process.getuid()}:${process.getgid()}`);
    assert.ok(args.includes('--read-only'));
    assert.equal(argument(args, '--cap-drop'), 'ALL');
    assert.equal(argument(args, '--security-opt'), 'no-new-privileges:true');
    assert.equal(argument(args, '--entrypoint'), '/usr/bin/python3');
    for (const flag of ['--pids-limit', '--memory', '--cpus']) assert.ok(args.includes(flag));
    assert.equal(args[args.indexOf('-I') - 1], TOOLING);
    assert.ok(!args.includes('--privileged'));
    assert.ok(!args.some(value => /docker\.sock|\/root\b/.test(value)));
  }
  assert.ok(runs[1].includes(`type=bind,src=${f.workspace},dst=/source,readonly`));
  assert.ok(runs[2].some(value => value.endsWith(',dst=/input/image.tar,readonly')));
  const create = calls.find(args => args[0] === 'create');
  assert.equal(create.at(-1), IMAGE);
  assert.equal(argument(create, '--entrypoint'), '/bin/false');
  assert.equal(argument(create, '--pull'), 'never');
  assert.equal(argument(create, '--network'), 'none');
  assert.ok(!create.includes('--mount') && !create.includes('-v'));
  assert.equal(calls.filter(args => ['start', 'exec', 'pull', 'build'].includes(args[0])).length, 0);
  assert.equal(fs.statSync(f.output).mode & 0o777, 0o700);
  assertCleaned(f);
});

test('source-only inventory never creates or exports a workload container', t => {
  const f = fixture(t);
  const result = f.run(['--source-only']);
  assert.equal(result.status, 0, result.stderr);
  assert.equal(f.commands().filter(args => args[0] === 'run').length, 2);
  assert.equal(f.commands().some(args => ['create', 'export'].includes(args[0])), false);
  assertCleaned(f);
});

test('local workload tags resolve once to an immutable image for the stopped export', t => {
  const f = fixture(t);
  const result = f.run(['--image', 'workload:local']);
  assert.equal(result.status, 0, result.stderr);
  assert.deepEqual(f.commands().find(args => args[0] === 'image' && !args.includes('--format')),
    ['image', 'inspect', 'workload:local']);
  assert.equal(f.commands().find(args => args[0] === 'create').at(-1), IMAGE);
  assertCleaned(f);
});

test('outdated or mismatched tooling fails before scanning or writing output', async t => {
  for (const config of [{ versionExit: 2 }, { toolingMismatch: true }]) await t.test(JSON.stringify(config), t => {
    const f = fixture(t, config);
    const result = f.run();
    assert.notEqual(result.status, 0);
    assert.match(result.stderr, /tooling image identity\/ABI mismatch|offline inventory collector is unavailable/);
    assert.equal(fs.existsSync(f.output), false);
    assert.equal(f.commands().some(args => args.includes('source') || args[0] === 'create'), false);
    assertCleaned(f);
  });
});

test('declared volumes and malformed image identity prevent container creation', async t => {
  for (const config of [{ volumes: true }, { imageId: 'untrusted:tag' }]) await t.test(JSON.stringify(config), t => {
    const f = fixture(t, config);
    const result = f.run();
    assert.notEqual(result.status, 0);
    assert.match(result.stderr, /image-declared volumes|invalid workload image ID/);
    assert.equal(f.commands().some(args => args[0] === 'create'), false);
    assertCleaned(f);
  });
});

test('an exact requested workload image cannot be replaced by inspect output', t => {
  const f = fixture(t, { imageId: OTHER, containerImage: OTHER });
  const result = f.run();
  assert.notEqual(result.status, 0, 'the exact requested image must match the inspected image');
  assert.equal(f.commands().some(args => args[0] === 'create'), false);
  assertCleaned(f);
});

test('export rejects changed workload identity, running state and unexpected mounts', async t => {
  for (const config of [{ containerImage: OTHER }, { containerState: 'running' }, { containerMounts: '1' }]) {
    await t.test(JSON.stringify(config), t => {
      const f = fixture(t, config);
      const result = f.run();
      assert.notEqual(result.status, 0);
      assert.match(result.stderr, /export container image, state or mounts changed/);
      assert.equal(f.commands().some(args => args[0] === 'export'), false);
      assertCleaned(f);
    });
  }
});

test('failures remove export containers, archives and any surviving collector', async t => {
  for (const config of [{ createExit: 9 }, { exportExit: 9 }, { imageExit: 9 }, { sourceExit: 9, collectorRemains: true }]) {
    await t.test(JSON.stringify(config), t => {
      const f = fixture(t, config);
      const result = f.run();
      assert.notEqual(result.status, 0);
      assertCleaned(f);
      if (config.collectorRemains) assert.ok(f.commands().some(args => args[0] === 'rm' && args[1] === '-f'));
      else assert.ok(f.commands().some(args => args[0] === 'rm' && /^-.*v/.test(args[1])));
      assert.ok(f.commands().filter(args => args[0] === 'rm').every(args => /^[a-f0-9]{64}$/.test(args.at(-1))));
    });
  }
});

test('failed create and run name collisions never remove foreign containers', async t => {
  for (const config of [{ createCollision: true }, { runCollision: '--version' }, { runCollision: 'source' }]) {
    await t.test(JSON.stringify(config), t => {
      const f = fixture(t, config);
      const result = f.run();
      assert.notEqual(result.status, 0);
      assert.equal(fs.existsSync(path.join(f.root, 'foreign')), true);
      assert.equal(f.commands().some(args => args[0] === 'rm'), false);
      assertCleaned(f);
    });
  }
});

test('incomplete inventory status is preserved without leaking export state', async t => {
  for (const config of [{ sourceExit: 2 }, { imageExit: 2 }]) await t.test(JSON.stringify(config), t => {
    const f = fixture(t, config);
    const result = f.run();
    assert.equal(result.status, 2, result.stderr);
    assertCleaned(f);
  });
});
