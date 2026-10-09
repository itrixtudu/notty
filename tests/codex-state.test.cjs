'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { spawnSync } = require('node:child_process');
const path = require('node:path');
test('Codex resource boundaries, lifetime locks and persistent QEMU layout', () => {
  const result = spawnSync('python3', ['-B', path.join(__dirname, 'codex-state.test.py')], { encoding: 'utf8' });
  assert.equal(result.status, 0, result.stdout + result.stderr);
});

const fs = require('node:fs');
const os = require('node:os');
function fixture(t) {
  const home = fs.mkdtempSync(path.join(os.tmpdir(), 'nosh-codex-policy-'));
  t.after(() => fs.rmSync(home, { recursive: true, force: true }));
  fs.mkdirSync(path.join(home, '.codex'), { mode: 0o700 });
  fs.mkdirSync(path.join(home, 'project'), { mode: 0o700 });
  return { user: { home, uid: process.getuid(), gid: process.getgid() }, workspace: path.join(home, 'project') };
}

test('Guard binds resource permissions and detects policy or identity changes', async (t) => {
  const { resolveAgentHomes, validateAgentMounts, sameAgentMounts } = await import('../lib/guardd/workload.js');
  const { buildRunnerSpec } = await import('../lib/guardd/runner-spec.js');
  const { user, workspace } = fixture(t);
  const protectedHomes = resolveAgentHomes({ user, workspace, modes: { skills: 'rw' } });
  const mount = protectedHomes.mounts[0];
  const auth = mount.policy.resources.find((resource) => resource.category === 'credentials');
  assert.equal(auth.mode, 'ro');
  assert.equal(auth.target, '/home/nosh-guard/.codex/auth.json');
  validateAgentMounts(protectedHomes.mounts, user, 'dev', workspace);
  const edited = structuredClone(protectedHomes.mounts);
  edited[0].policy.resources.find((resource) => resource.category === 'credentials').mode = 'rw';
  assert.throws(() => validateAgentMounts(edited, user, 'dev', workspace), /resources changed/);
  assert.throws(() => validateAgentMounts(protectedHomes.mounts, user, 'dev', user.home), /workspace/);
  const writableHomes = resolveAgentHomes({ user, workspace, modes: { skills: 'rw', settings: 'rw' } });
  assert.equal(sameAgentMounts(protectedHomes.mounts, writableHomes.mounts), false);
  if (process.getuid() !== 0) {
    const spec = buildRunnerSpec({ workdir: workspace, runId: 'codex-modes', name: 'codex-modes',
      image: 'nosh', mode: 'egress-learn', agentMounts: protectedHomes.mounts }).spec;
    assert.ok(spec.HostConfig.Binds.includes(`${auth.source}:${auth.target}:ro`));
    assert.ok(spec.HostConfig.Binds.includes(`${user.home}/.codex:/home/nosh-guard/.codex:rw`));
  }
  const skills = path.join(user.home, '.codex/skills');
  fs.renameSync(skills, skills + '-old');
  fs.mkdirSync(skills, { mode: 0o700 });
  assert.throws(() => validateAgentMounts(protectedHomes.mounts, user, 'dev', workspace), /resources changed/);
});

test('legacy dry run prints protected mounts without creating profile resources', (t) => {
  const { user, workspace } = fixture(t);
  const result = spawnSync('bash', [path.join(__dirname, '../scripts/nosh.sh'), '--dry-run', '--security-mode', 'legacy',
    '--workdir', workspace, '--agents', 'codex', '--agent-skills', 'rw', '--no-start-app'],
  { encoding: 'utf8', env: { PATH: process.env.PATH, USER: process.env.USER, HOME: user.home, CODEX_HOME: path.join(user.home, '.codex') } });
  assert.equal(result.status, 0, result.stdout + result.stderr);
  assert.match(result.stdout, /\.codex\/auth\.json:.*\.codex\/auth\.json:ro/);
  assert.match(result.stdout, /\.codex\/skills:.*\.codex\/skills:rw/);
  assert.deepEqual(fs.readdirSync(path.join(user.home, '.codex')), []);
});
