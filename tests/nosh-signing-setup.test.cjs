'use strict';
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawnSync } = require('node:child_process');
const test = require('node:test');
const helper = path.resolve(__dirname, '../scripts/nosh-signing-setup.py');
const image = `sha256:${'a'.repeat(64)}`;
const quote = value => `'${value.replaceAll("'", "'\\''")}'`;
function fixture(t) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'signing-setup-'));
  fs.chmodSync(root, 0o755);
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const home = path.join(root, 'home'), bin = path.join(root, 'bin'), work = path.join(root, 'work');
  for (const dir of [home, bin, work]) fs.mkdirSync(dir, { mode: 0o755 });
  if (process.getuid() === 0) fs.chownSync(home, 65534, 65534);
  const log = path.join(home, 'calls.jsonl');
  fs.writeFileSync(path.join(bin, 'docker'), `#!/usr/bin/env python3
import os, sys, json
from pathlib import Path
args=sys.argv[1:]
with open(os.environ['CALLS'], 'a') as out: out.write(json.dumps(['docker']+args)+'\\n')
if 'inspect' in args:
 print('${image}|1')
elif 'keygen' in args:
 mount=args[args.index('--mount')+1]
 role=Path(mount.split('src=',1)[1].split(',dst=')[0])
 key=role/'key'; key.mkdir(mode=0o700)
 for name in ('private.pem','public.pem'):
  file=key/name; file.write_text('TEST ONLY '+role.name+' '+name); file.chmod(0o600)
`, { mode: 0o755 });
  fs.writeFileSync(path.join(bin, 'sudo'), `#!/usr/bin/env python3
import os,sys,json
with open(os.environ['CALLS'], 'a') as out: out.write(json.dumps(['sudo']+sys.argv[1:])+'\\n')
sys.exit(int(os.environ.get('SUDO_RESULT','0')))
`, { mode: 0o755 });
  const run = (input, args = [], extra = {}) => spawnSync('script', ['-q', '-e', '-c',
    ['python3', helper, '--workdir', work, ...args].map(quote).join(' '), '/dev/null'], {
    input, encoding: 'utf8', timeout: 10000,
    env: { ...process.env, HOME: home, XDG_CONFIG_HOME: path.join(home, '.config'),
      XDG_DATA_HOME: path.join(home, '.local/share'), NOSH_POLICY_APPLY_CONFIG: path.join(home, '.config/nosh/policy-apply.json'),
      NOSH_PROFILE_REVIEW_IMAGE_CONFIG: path.join(home, 'images.conf'), NOSH_POLICY_TOOLING_IMAGE: image,
      DOCKER_HOST: 'unix:///var/run/docker.sock', PATH: `${bin}:${process.env.PATH}`, CALLS: log, ...extra },
    ...(process.getuid() === 0 ? { uid: 65534, gid: 65534 } : {}),
  });
  const calls = () => fs.existsSync(log) ? fs.readFileSync(log, 'utf8').trim().split('\n').map(JSON.parse) : [];
  const stages = () => fs.readdirSync(path.join(home, '.local/share/nosh')).map(name => path.join(home, '.local/share/nosh', name));
  return { home, work, run, calls, stages, config: path.join(home, '.config/nosh/policy-apply.json') };
}
test('first-time setup separates offline key roles and installs only reviewed public trust', t => {
  const f = fixture(t);
  const result = f.run('y\ny\n');
  assert.equal(result.status, 0, result.stdout + result.stderr);
  const calls = f.calls(), containers = calls.filter(call => call.includes('run'));
  assert.equal(containers.length, 4);
  for (const call of containers) {
    assert.equal(call[call.indexOf('--network') + 1], 'none');
    assert.equal(call[call.indexOf('--pull') + 1], 'never');
    assert.equal(call.filter(arg => arg === '--mount').length, 1);
    assert.ok(call.includes(image));
    assert.ok(!call.includes('/var/run/docker.sock:/var/run/docker.sock'));
  }
  const config = JSON.parse(fs.readFileSync(f.config));
  assert.notEqual(path.dirname(config.reviewPrivateKey), path.dirname(config.deploymentPrivateKey));
  assert.equal(fs.statSync(f.config).mode & 0o777, 0o600);
  const privileged = calls.find(call => call[0] === 'sudo');
  assert.ok(privileged);
  assert.equal(privileged[4], 'nosh-signing-setup');
  assert.ok(privileged[5].endsWith('/public'));
  assert.match(result.stdout, /Public trust to install/);
  assert.match(result.stdout, /Signing setup complete/);
  const before = fs.readFileSync(f.config, 'utf8');
  assert.notEqual(f.run('y\ny\n').status, 0);
  assert.equal(fs.readFileSync(f.config, 'utf8'), before);
  assert.equal(f.calls().filter(call => call[0] === 'sudo').length, 1);
});
test('declining trust installation retains keys and resumes without generating replacements', t => {
  const f = fixture(t);
  assert.notEqual(f.run('y\nn\n').status, 0);
  assert.equal(f.calls().some(call => call[0] === 'sudo'), false);
  assert.equal(fs.existsSync(f.config), false);
  const stage = f.stages()[0];
  const prior = fs.readFileSync(path.join(stage, 'review/key/private.pem'), 'utf8');
  const resumed = f.run('y\n', ['--resume', stage]);
  assert.equal(resumed.status, 0, resumed.stdout + resumed.stderr);
  assert.equal(f.calls().filter(call => call.includes('keygen')).length, 2);
  assert.equal(fs.readFileSync(path.join(stage, 'review/key/private.pem'), 'utf8'), prior);
});
test('failed privileged installation does not publish user configuration', t => {
  const f = fixture(t);
  assert.notEqual(f.run('y\ny\n', [], { SUDO_RESULT: '1' }).status, 0);
  assert.equal(fs.existsSync(f.config), false);
  assert.equal(f.stages().length, 1);
});
test('declining generation and remote Docker never generate keys or elevate', t => {
  const f = fixture(t);
  assert.notEqual(f.run('n\n').status, 0);
  assert.equal(f.calls().some(call => call.includes('run') || call[0] === 'sudo'), false);
  assert.notEqual(f.run('y\ny\n', [], { DOCKER_HOST: 'tcp://example.invalid:2375' }).status, 0);
  assert.equal(f.calls().some(call => call.includes('run') || call[0] === 'sudo'), false);
});


test('public trust transaction rejects changed material and resumes without overwriting trust', () => {
  const result = spawnSync('python3', ['-B', path.join(__dirname, 'nosh-signing-trust.test.py')], {
    encoding: 'utf8', timeout: 10000,
  });
  assert.equal(result.status, 0, result.stdout + result.stderr);
});
