'use strict';

const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const test = require('node:test');

function fixture(t) {
  const home = fs.mkdtempSync(path.join(os.tmpdir(), 'nosh-workload-'));
  t.after(() => fs.rmSync(home, { recursive: true, force: true }));
  return { home, uid: process.getuid(), gid: process.getgid() };
}

test('dev reuses existing homes and Claude companion state; run has no homes', async (t) => {
  const { resolveAgentHomes, validateAgentMounts, sameAgentMounts } = await import('../lib/guardd/workload.js');
  const user = fixture(t);
  for (const agent of ['codex', 'claude', 'gemini']) fs.mkdirSync(path.join(user.home, `.${agent}`), { mode: 0o700 });
  fs.chmodSync(path.join(user.home, '.gemini'), 0o775);
  fs.writeFileSync(path.join(user.home, '.claude.json'), '{}', { mode: 0o600 });
  const homes = resolveAgentHomes({ user });
  assert.deepEqual(homes.agents, ['claude', 'codex', 'gemini']);
  assert.equal(homes.mounts.length, 4);
  assert.ok(homes.mounts.every((mount) => mount.mode === 'rw'));
  validateAgentMounts(homes.mounts, user, 'dev');
  assert.ok(sameAgentMounts(homes.mounts, resolveAgentHomes({ user, agents: 'gemini,claude,codex' }).mounts));
  fs.writeFileSync(path.join(user.home, '.claude-new.json'), '{}', { mode: 0o600 });
  fs.renameSync(path.join(user.home, '.claude-new.json'), path.join(user.home, '.claude.json'));
  assert.ok(sameAgentMounts(homes.mounts, resolveAgentHomes({ user }).mounts));
  assert.deepEqual(resolveAgentHomes({ user, workload: 'run' }), { agents: [], mounts: [] });
  assert.deepEqual(resolveAgentHomes({ user, agents: 'none' }), { agents: [], mounts: [] });
  assert.throws(() => validateAgentMounts(homes.mounts, user, 'run'), /require the dev/);
});

test('custom Codex home and refreshed credentials survive replay without reading secrets', async (t) => {
  const { resolveAgentHomes, validateAgentMounts } = await import('../lib/guardd/workload.js');
  const user = fixture(t);
  const codexHome = path.join(user.home, 'custom-codex');
  fs.mkdirSync(codexHome, { mode: 0o700 });
  fs.writeFileSync(path.join(codexHome, 'auth.json'), 'secret-before');
  const homes = resolveAgentHomes({ user, agents: 'codex', codexHome });
  fs.writeFileSync(path.join(codexHome, 'refreshed'), 'secret-after');
  fs.renameSync(path.join(codexHome, 'refreshed'), path.join(codexHome, 'auth.json'));
  validateAgentMounts(homes.mounts, user, 'dev');
  assert.equal(homes.mounts[0].source, codexHome);
  assert.equal(homes.mounts[0].target, '/home/nosh-guard/.codex');
  assert.doesNotMatch(JSON.stringify(homes), /secret-before|secret-after/);
  fs.renameSync(codexHome, `${codexHome}-old`);
  fs.mkdirSync(codexHome, { mode: 0o700 });
  assert.throws(() => validateAgentMounts(homes.mounts, user, 'dev'), /identity changed/);
});

test('missing, symlinked, duplicate and foreign-owned homes are rejected', async (t) => {
  const { resolveAgentHomes, validateAgentMounts } = await import('../lib/guardd/workload.js');
  const user = fixture(t);
  assert.deepEqual(resolveAgentHomes({ user }).mounts, []);
  assert.throws(() => resolveAgentHomes({ user, agents: 'codex' }), /missing codex home/);
  fs.mkdirSync(path.join(user.home, 'real'), { mode: 0o700 });
  fs.symlinkSync(path.join(user.home, 'real'), path.join(user.home, '.codex'));
  assert.throws(() => resolveAgentHomes({ user }), /canonical/);
  fs.unlinkSync(path.join(user.home, '.codex'));
  fs.mkdirSync(path.join(user.home, '.codex'), { mode: 0o700 });
  const homes = resolveAgentHomes({ user });
  assert.throws(() => validateAgentMounts([...homes.mounts, ...homes.mounts], user, 'dev'), /duplicate/);
  assert.throws(() => validateAgentMounts(homes.mounts, { uid: user.uid + 1 }, 'dev'), /owned/);
  assert.throws(() => validateAgentMounts([{ ...homes.mounts[0], target: '/etc' }], user, 'dev'), /destination/);
});

test('dev and run have independent registries, mirrors and activation slots', async (t) => {
  const { NetProfileRegistry } = await import('../lib/guardd/net-profile-store.js');
  const { EbpfActivationStore } = await import('../lib/guardd/ebpf-activation-store.js');
  const { mirrorDirectory } = await import('../lib/guardd/net-profile-mirror.js');
  const user = fixture(t);
  const workspaceKey = 'a'.repeat(64);
  const registries = ['dev', 'run'].map((workload) => new NetProfileRegistry({
    stateDir: user.home, workload, trustedUid: user.uid,
  }));
  for (const [index, registry] of registries.entries()) {
    await registry.mutateWorkspace(user.home, (entry) => { entry.lastLaunch = { runId: `run-${index}`, mode: 'egress-learn', marker: index }; });
  }
  for (const [index, registry] of registries.entries()) {
    assert.equal((await registry.readWorkspace(user.home)).lastLaunch.marker, index);
  }
  assert.equal(new Set(registries.map((entry) => entry.registryPath)).size, 2);
  assert.equal(new Set(['dev', 'run'].map((workload) => mirrorDirectory(user.home, user.home, workload))).size, 2);
  const slots = ['dev', 'run'].map((workload) => new EbpfActivationStore({ stateDir: user.home, workload, workspaceKey }).statePath);
  assert.equal(new Set(slots).size, 2);
  assert.notEqual(slots[0], new EbpfActivationStore({ stateDir: user.home, workload: 'dev', workspaceKey: 'b'.repeat(64) }).statePath);
  assert.throws(() => new EbpfActivationStore({ workload: 'dev' }), /workspace key/);
});

test('pinned baselines compose only as review inputs with provenance and exact image compatibility', async (t) => {
  const { readAgentBaselines, composeAgentBaselines } = await import('../lib/guardd/agent-baselines.js');
  const user = fixture(t);
  const imageDigest = `sha256:${'a'.repeat(64)}`;
  const rule = { destination: 'api.example.com', protocol: 'tcp', ports: [443] };
  const doc = { schemaVersion: 1, agent: 'codex', revision: 'v1', imageDigest, toolVersion: '1.2.3', rules: [rule] };
  const file = path.join(user.home, 'baseline.json');
  const source = JSON.stringify(doc);
  fs.writeFileSync(file, source, { mode: 0o600 });
  const selection = `${file}@sha256:${crypto.createHash('sha256').update(source).digest('hex')}`;
  const options = { workload: 'dev', agents: ['codex'], uid: user.uid };
  const baselines = await readAgentBaselines([selection], options);
  const rules = composeAgentBaselines([rule], baselines, imageDigest);
  assert.equal(rules.length, 1);
  assert.equal(rules[0].observations[0].source, 'agent-baseline');
  assert.equal(rules[0].observations[0].revision, 'v1');
  assert.throws(() => composeAgentBaselines([], baselines, `sha256:${'b'.repeat(64)}`), /another image/);
  await assert.rejects(readAgentBaselines([selection], { ...options, workload: 'run' }), /require the dev/);
  await assert.rejects(readAgentBaselines([selection, selection], options), /one baseline/);
  fs.writeFileSync(file, source + ' ');
  await assert.rejects(readAgentBaselines([selection], options), /digest changed/);
  assert.equal(baselines[0].revision, 'v1');
});

test('net defaults to dev and rejects cross-workload agent flags even during dry run', async () => {
  const { executeNetCommand } = await import('../scripts/nosh-guard.mjs');
  const { workloadName } = await import('../lib/guardd/workload.js');
  assert.throws(() => workloadName('legacy'), /must be dev or run/);
  let output;
  await executeNetCommand('learn', { 'dry-run': true }, { print: (value) => { output = value; } });
  assert.equal(output.workload, 'dev');
  await assert.rejects(executeNetCommand('learn', { 'dry-run': true, workload: 'run', agents: 'codex' }), /require the dev/);
});

test('guarded dev runner exposes persistent homes and run omits them', { skip: process.getuid() === 0 }, async (t) => {
  const { resolveAgentHomes } = await import('../lib/guardd/workload.js');
  const { buildRunnerSpec } = await import('../lib/guardd/runner-spec.js');
  const user = fixture(t);
  fs.mkdirSync(path.join(user.home, '.codex'), { mode: 0o700 });
  const homes = resolveAgentHomes({ user });
  const base = { workdir: user.home, runId: 'test-workload', name: 'workload-test', image: 'nosh', mode: 'egress-learn' };
  const dev = buildRunnerSpec({ ...base, workload: 'dev', agentMounts: homes.mounts }).spec;
  assert.ok(dev.HostConfig.Binds.includes(`${user.home}/.codex:/home/nosh-guard/.codex:rw`));
  assert.ok(dev.Env.includes('CODEX_HOME=/home/nosh-guard/.codex'));
  assert.ok(dev.Env.includes('HOME=/home/nosh-guard'));
  assert.equal(dev.User, `${user.uid}:${user.gid}`);
  const run = buildRunnerSpec({ ...base, workload: 'run' }).spec;
  assert.ok(run.HostConfig.Binds.every((entry) => !entry.includes('.codex')));
  assert.ok(!run.Env.some((entry) => entry.startsWith('CODEX_HOME=')));
});

test('enforcement replays recorded dev homes and rejects a run profile mismatch', async (t) => {
  const { resolveAgentHomes } = await import('../lib/guardd/workload.js');
  const { executeNetCommand } = await import('../scripts/nosh-guard.mjs');
  const user = fixture(t);
  fs.mkdirSync(path.join(user.home, '.codex'), { mode: 0o700 });
  const homes = resolveAgentHomes({ user });
  const reference = { directory: path.join(user.home, 'candidate'), revision: 'dev-one', launchConfig: {
    workload: 'dev', agentHomes: homes, image: 'nosh', imageDigest: `sha256:${'a'.repeat(64)}`,
    name: 'dev-test', agentId: 'dev-test', roles: [], startApp: false, collab: false,
  } };
  const state = { latestCandidate: reference };
  let request;
  const dependencies = {
    geteuid: () => 0, interactive: false, print() {},
    registry: { async initialize() {}, async readWorkspace() { return state; }, async recordLastLaunch() {} },
    readActiveDeployment: async () => null,
    verifyCandidate: async () => ({ ok: true }),
    mirrorWriter: () => user.home,
    client: { async startRun(input) { request = input; return { runId: 'dev-run' }; } },
  };
  assert.equal(await executeNetCommand('enforce', { workdir: user.home }, dependencies), 0);
  assert.equal(request.workload, 'dev');
  assert.deepEqual(request.agentMounts, homes.mounts);
  assert.equal(request.profileDir, null);
  request = null;
  await assert.rejects(executeNetCommand('enforce', { workdir: user.home, workload: 'run' }, dependencies), /another workload/);
  assert.equal(request, null);
});
