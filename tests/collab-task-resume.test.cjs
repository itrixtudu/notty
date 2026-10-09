'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const cp = require('node:child_process');
const crypto = require('node:crypto');
const { createSessionManager, buildAgentPrompt } = require('../lib/collab/session.cjs');

test('named task resumes exact role IDs across stop and model changes; missing history blocks all launches', async (t) => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'notty-task-launch-'));
  const original = cp.spawnSync;
  const tmux = new Set();
  const launches = [];
  cp.spawnSync = (command, args) => {
    if (command === 'tmux' && args[0] === 'new-session') {
      tmux.add(args[args.indexOf('-s') + 1]); launches.push(args);
    }
    return { status: 0, stdout: '', stderr: '' };
  };
  t.after(() => { cp.spawnSync = original; fs.rmSync(root, { recursive: true, force: true }); });
  const ids = new Map();
  let missing = false;
  const config = { resolved: { defaultTemplate: 'solo', layouts: { grid: { label: 'Grid', mode: 'grid' } },
    prompts: { qa: { role: 'qa', instructions: 'Review code and run tests.' } },
    templates: { solo: { layout: 'grid', requiredNoshProfiles: [], agents: ['qa_codex_gpt-5.3-codex-spark_low'] } } } };
  const manager = createSessionManager({ workspaceRoot: root, manifestPath: path.join(root, 'active.json'),
    configStore: { load: () => config }, environment: {},
    tmuxSessionExists: (target) => tmux.has(target), tmuxSessionOwnedBy: (target) => tmux.has(target),
    killTmuxSession: (target) => { tmux.delete(target); return true; },
    resolveCodexThreadId: async (options) => {
      if (missing) return '';
      if (!ids.has(options.marker)) ids.set(options.marker, crypto.randomUUID());
      if (options.threadId) assert.equal(options.threadId, ids.get(options.marker));
      return ids.get(options.marker);
    },
  });
  const tasks = manager.createTask('Feature A');
  const taskId = tasks.lastTaskId;
  const first = await manager.launchTask({ taskId });
  await new Promise((resolve) => setImmediate(resolve));
  const saved = manager.tasks().tasks[0].roles[0];
  assert.equal(saved.status, 'saved');
  assert.ok(launches[0].some((arg) => arg.startsWith(`Notty launch ${saved.marker}\n`)));
  manager.stop();
  for (let i = 0; i < 3; i += 1) {
    await manager.launchTask({ taskId, agentChoices: [{ harness: 'codex', backend: 'default', model: 'gpt-6-astra', think: 'low' }] });
    await new Promise((resolve) => setImmediate(resolve));
    const command = launches.at(-1);
    assert.equal(command[command.indexOf('resume') + 1], saved.threadId);
    assert.match(command.at(-1), /Do not continue an old assignment/);
    manager.stop();
  }
  assert.equal(manager.tasks().tasks[0].manualResumes, 3);
  manager.taskSettings({ autoResume: true });
  assert.equal(manager.tasks().autoResume, true);
  const autoLaunch = manager.launchTask({ autoResume: true });
  await assert.rejects(manager.launchTask({ autoResume: true }), /already in progress/);
  const autoSession = await autoLaunch;
  await new Promise((resolve) => setImmediate(resolve));
  assert.equal((await manager.launchTask({ autoResume: true })).id, autoSession.id);
  assert.equal(manager.tasks().tasks[0].manualResumes, 3);
  manager.stop();
  missing = true;
  const count = launches.length;
  await assert.rejects(manager.launchTask({ taskId }), /Cannot recover/);
  assert.equal(launches.length, count);
  assert.equal(manager.getSession(), null);
  assert.equal(manager.tasks().tasks[0].roles[0].threadId, saved.threadId);
  missing = false;
  const next = manager.createTask('Feature B');
  assert.equal(next.autoResume, false);
  await manager.launchTask({ taskId: next.lastTaskId });
  await new Promise((resolve) => setImmediate(resolve));
  assert.equal(launches.at(-1).includes('resume'), false);
  assert.notEqual(manager.getSession().id, first.id);
  assert.equal(manager.tasks().tasks.length, 2);
  manager.stop();
});

test('startup orchestration precedes role guidance and forbids idle exploration', () => {
  const prompt = buildAgentPrompt({ role: 'qa', identity: 'qa', prompt: 'qa' }, {
    prompts: { qa: { instructions: 'Review source files.' } }, workspaceRoot: '/work', channel: 'lobby', sessionId: 'session', mcpUrl: 'http://localhost/mcp',
  });
  assert.ok(prompt.indexOf('STARTUP CONTRACT') < prompt.indexOf('Review source files.'));
  assert.match(prompt, /end your turn silently/);
  assert.match(prompt, /Do not explore the repository/);
  assert.match(prompt, /report one clear connection failure and stop/);
});

test('dangerous bypass omits sandbox advice but keeps outcome guidance', () => {
  const options = {
    prompts: { qa: { instructions: 'Review assigned work.' } },
    workspaceRoot: '/work',
    channel: 'lobby',
    sessionId: 'session',
    mcpUrl: 'http://localhost/mcp',
  };
  const managed = buildAgentPrompt({
    role: 'qa', identity: 'qa', prompt: 'qa', permissionMode: 'workspace-write',
  }, options);
  const bypass = buildAgentPrompt({
    role: 'qa', identity: 'qa', prompt: 'qa', permissionMode: 'danger-full-access',
  }, options);

  assert.match(managed, /approval or sandbox barriers/);
  assert.doesNotMatch(bypass, /approval or sandbox barriers/);
  assert.match(bypass, /Task complete/);
  assert.match(bypass, /Human help needed/);
});
