const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawnSync } = require('node:child_process');
const test = require('node:test');

const script = path.resolve(__dirname, '../scripts/nosh-net-review.sh');
const IMAGE = `sha256:${'a'.repeat(64)}`;
const OLD = `sha256:${'b'.repeat(64)}`;
const CID = 'c'.repeat(64);
const available = ['jq', 'python3', 'timeout'].every(command => spawnSync(command, ['--version']).status === 0);

function fixture(t, config = {}) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'nosh-tooling-status-'));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const write = (name, value, mode = 0o600) => {
    const file = path.join(root, name);
    fs.mkdirSync(path.dirname(file), { recursive: true, mode: 0o700 });
    fs.writeFileSync(file, value, { mode });
  };
  write('config.json', JSON.stringify(config));
  write('app/package.json', '{"type":"module"}');
  write('app/scripts/nosh-inventory.py', `print(${JSON.stringify(config.version || 'nosh-inventory 1')})\n`);
  write('app/scripts/nosh-policy-session.mjs', '');
  write('app/lib/guard/review/session.js', config.old
    ? 'export function snapshotReviewSelection() {}\n'
    : 'export function checkReviewSession() {}\nexport function snapshotReviewSelection() {}\nexport function migrateReviewDraft() {}\n');
  write('app/lib/guard/review/cli.js', config.missingBridgeResolver ? 'export {};\n' : `
export function resolveReviewGraphHosts(input, dependencies) {
  if (${Boolean(config.resolverFailure)}) throw new Error('unexpected resolver failure');
  const address = dependencies.networkInterfaces().eth0[0].address;
  const supported = ${JSON.stringify(config.supportedBridgeRanges || ['172.', '192.168.', '10.'])};
  if (!supported.some(prefix => address.startsWith(prefix))) {
    throw new TypeError('review graph advertised host auto requires exactly one Docker bridge address; found 0');
  }
  return { listenHost: input.host, advertiseHost: ${config.wrongAdvertiseHost ? "'172.20.0.2'" : 'address'} };
}
`);
  if (config.missingReviewCli) fs.unlinkSync(path.join(root, 'app/lib/guard/review/cli.js'));
  if (config.missingCollector) fs.unlinkSync(path.join(root, 'app/scripts/nosh-inventory.py'));
  write('docker', `#!/usr/bin/env node
const fs = require('node:fs'), path = require('node:path'), { spawnSync } = require('node:child_process');
const root = process.env.TOOLING_TEST_ROOT, args = process.argv.slice(2);
const config = JSON.parse(fs.readFileSync(path.join(root, 'config.json')));
const value = name => args[args.indexOf(name) + 1];
const fail = (message, code = 1) => { console.error(message); process.exit(code); };
fs.appendFileSync(path.join(root, 'commands.jsonl'), JSON.stringify(args) + '\\n');
if (args[0] === 'info') {
  if (config.daemonFailure) fail('Cannot connect to the Docker daemon');
  console.log('test-daemon'); process.exit(0);
}
if (args[0] === 'image' && args[1] === 'inspect') {
  if (config.inspectFailure) fail('unexpected image store failure');
  if (config.missingImage) fail('Error response from daemon: No such image: ' + args.at(-1));
  const image = args.at(-1) === 'nosh' ? '${IMAGE}' : args.at(-1);
  console.log((config.identityMismatch ? '${OLD}' : image) + '|' + (config.oldAbi ? '0' : '1'));
  process.exit(0);
}
if (args[0] === 'run') {
  for (const [flag, expected] of [['--pull','never'], ['--network','none'], ['--cap-drop','ALL'], ['--security-opt','no-new-privileges:true'], ['--entrypoint','/usr/local/bin/node']]) {
    if (value(flag) !== expected) fail('unsafe capability probe ' + flag, 99);
  }
  if (!args.includes('--read-only') || !args.includes('--rm') || !args.includes('--user') || !args.includes('--pids-limit') || !args.includes('--memory') || !args.includes('--cpus')) fail('unbounded probe', 99);
  if (args.includes('--mount') || args.includes('-v') || args.includes('--volume') || args.includes('--privileged')) fail('probe exposes host inputs', 99);
  if (config.collision) fail('Conflict. The container name is already in use.', 125);
  fs.writeFileSync(value('--cidfile'), '${CID}');
  if (config.probeExit) process.exit(config.probeExit);
  const code = value('-e').replaceAll('/app/', root + '/app/');
  const result = spawnSync(process.execPath, ['--input-type=module', '-e', code], { encoding: 'utf8' });
  process.stdout.write(result.stdout); process.stderr.write(result.stderr); process.exit(result.status ?? 1);
}
if (args[0] === 'container' && args[1] === 'inspect') {
  if (config.cleanupFailure) fail('Cannot connect to the Docker daemon');
  if (config.survives) { console.log('{}'); process.exit(0); }
  fail('Error: No such container: ' + args.at(-1));
}
if (args[0] === 'rm' && args[1] === '-f' && args[2] === '${CID}') process.exit(0);
fail('unexpected Docker command: ' + args.join(' '), 99);
`, 0o700);
  const env = { ...process.env, TOOLING_TEST_ROOT: root, NOSH_NET_REVIEW_DOCKER_BIN: path.join(root, 'docker'),
    NOSH_PROFILE_REVIEW_IMAGE_CONFIG: path.join(root, 'images.conf'), NOSH_POLICY_TOOLING_IMAGE: '' };
  return {
    root, write, env,
    run: (args = [], overrides = {}) => spawnSync('bash', [script, 'tooling-status', ...args], { env: { ...env, ...overrides }, encoding: 'utf8' }),
    commands: () => fs.existsSync(path.join(root, 'commands.jsonl'))
      ? fs.readFileSync(path.join(root, 'commands.jsonl'), 'utf8').trim().split('\n').map(JSON.parse) : [],
  };
}

test('current local nosh tooling is discovered and checked in an isolated bounded container', { skip: !available }, t => {
  const f = fixture(t);
  const result = f.run();
  assert.equal(result.status, 0, result.stderr);
  assert.deepEqual(JSON.parse(result.stdout), { schemaVersion: 1, status: 'ready', toolingImage: IMAGE,
    reason: 'The local policy tooling supports inventories and guided review.' });
  const commands = f.commands();
  assert.equal(commands.find(args => args[0] === 'image').at(-1), 'nosh');
  const probe = commands.find(args => args[0] === 'run');
  assert.ok(probe.includes(IMAGE));
  assert.equal(fs.existsSync(path.dirname(probe[probe.indexOf('--cidfile') + 1])), false);
  assert.ok(!commands.some(args => ['build', 'pull', 'create'].includes(args[0])));
});

test('missing local image and missing collector require a build rather than a download', { skip: !available }, async t => {
  for (const config of [{ missingImage: true }, { missingCollector: true }, { oldAbi: true }, { old: true }, { version: 'nosh-inventory 0' }]) {
    await t.test(JSON.stringify(config), t => {
      const f = fixture(t, config);
      const result = f.run();
      assert.equal(result.status, 3, result.stderr);
      const status = JSON.parse(result.stdout);
      assert.equal(status.status, 'needs-build');
      assert.equal(status.toolingImage, config.missingImage ? null : IMAGE);
      assert.ok(!f.commands().some(args => ['build', 'pull'].includes(args[0])));
    });
  }
});

test('configured exact image takes precedence over the local nosh tag', { skip: !available }, t => {
  const f = fixture(t, { old: true });
  f.write('images.conf', `NOSH_POLICY_TOOLING_IMAGE=${OLD}\n`);
  const result = f.run();
  assert.equal(result.status, 3, result.stderr);
  assert.equal(JSON.parse(result.stdout).toolingImage, OLD);
  assert.equal(f.commands().find(args => args[0] === 'image').at(-1), OLD);
});

test('older bridge discovery requires a tooling rebuild for both private subnet families', { skip: !available }, async t => {
  for (const config of [
    { supportedBridgeRanges: ['172.'] },
    { supportedBridgeRanges: ['172.', '10.'] },
    { supportedBridgeRanges: ['172.', '192.168.'] },
    { missingBridgeResolver: true },
    { missingReviewCli: true },
    { wrongAdvertiseHost: true },
  ]) {
    await t.test(JSON.stringify(config), t => {
      const f = fixture(t, config);
      const result = f.run();
      assert.equal(result.status, 3, result.stderr);
      const status = JSON.parse(result.stdout);
      assert.equal(status.status, 'needs-build');
      assert.equal(status.toolingImage, IMAGE);
      assert.ok(!f.commands().some(args => ['build', 'pull', 'network'].includes(args[0])));
    });
  }
});

test('explicit environment override takes precedence over saved configuration', { skip: !available }, t => {
  const f = fixture(t);
  f.write('images.conf', `NOSH_POLICY_TOOLING_IMAGE=${OLD}\n`);
  const result = f.run([], { NOSH_POLICY_TOOLING_IMAGE: IMAGE });
  assert.equal(result.status, 0, result.stderr);
  assert.equal(JSON.parse(result.stdout).toolingImage, IMAGE);
});

test('infrastructure and unexpected probe failures never request a rebuild', { skip: !available }, async t => {
  for (const config of [{ daemonFailure: true }, { inspectFailure: true }, { probeExit: 125 }, { probeExit: 124 }, { identityMismatch: true }, { cleanupFailure: true }, { resolverFailure: true }]) {
    await t.test(JSON.stringify(config), t => {
      const f = fixture(t, config);
      const result = f.run([], { NOSH_POLICY_TOOLING_IMAGE: IMAGE });
      assert.equal(result.status, 1, result.stderr);
      assert.equal(result.stdout, '');
      if (config.daemonFailure) assert.deepEqual(f.commands().map(args => args[0]), ['info']);
    });
  }
});

test('probe removes only its recorded container ID, never a colliding container name', { skip: !available }, async t => {
  for (const config of [{ survives: true }, { survives: true, probeExit: 124 }, { collision: true }]) {
    await t.test(JSON.stringify(config), t => {
      const f = fixture(t, config);
      const result = f.run();
      assert.equal(result.status, config.probeExit || config.collision ? 1 : 0, result.stderr);
      const removals = f.commands().filter(args => args[0] === 'rm');
      assert.deepEqual(removals, config.collision ? [] : [['rm', '-f', CID]]);
    });
  }
});

test('tooling status writes a new private result file and refuses to overwrite it', { skip: !available }, t => {
  const f = fixture(t);
  const file = path.join(f.root, 'status.json');
  const result = f.run(['--result-json', file]);
  assert.equal(result.status, 0, result.stderr);
  assert.deepEqual(JSON.parse(fs.readFileSync(file)), JSON.parse(result.stdout));
  assert.equal(fs.statSync(file).mode & 0o777, 0o600);
  assert.equal(fs.statSync(file).nlink, 1);
  const prior = fs.readFileSync(file, 'utf8');
  assert.equal(f.run(['--result-json', file]).status, 1);
  assert.equal(fs.readFileSync(file, 'utf8'), prior);
});

test('needs-build result is also saved and unsafe result parents are refused', { skip: !available }, t => {
  const f = fixture(t, { missingImage: true });
  const file = path.join(f.root, 'status.json');
  assert.equal(f.run(['--result-json', file]).status, 3);
  assert.equal(JSON.parse(fs.readFileSync(file)).status, 'needs-build');
  fs.mkdirSync(path.join(f.root, 'public'), { mode: 0o755 });
  assert.equal(f.run(['--result-json', path.join(f.root, 'public/status.json')]).status, 1);
  assert.equal(fs.existsSync(path.join(f.root, 'public/status.json')), false);
});
