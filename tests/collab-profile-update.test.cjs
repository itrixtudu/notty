'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const test = require('node:test');

const { createConfigStore } = require('../lib/collab/config.cjs');
const { resolveLaunchRoster } = require('../lib/collab/session.cjs');

function createBuiltinFixture(t) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'notty-collab-profile-update-'));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const store = createConfigStore({
    builtinPath: path.join(__dirname, '..', 'config', 'collab.templates.json'),
    userPath: path.join(root, 'user.json'),
    workspacePath: path.join(root, 'workspace.json'),
  });
  return store.load();
}

function launchContract(agent) {
  return {
    prompt: agent.prompt,
    harness: agent.harness,
    backend: agent.backend,
    model: agent.model,
    think: agent.think,
    identity: agent.identity,
    coordinatorCapable: agent.coordinatorCapable,
  };
}

test('Full Roster resolves to the same effective agents in the UI and server', async (t) => {
  const { resolveLaunchAgents } = await import('../components/collab/configModel.js');
  const loaded = createBuiltinFixture(t);
  const summaryTemplate = loaded.summary.templates.find((template) => template.id === 'full-roster');
  const resolvedTemplate = loaded.resolved.templates['full-roster'];

  for (const coordinatorMode of ['agent', 'human']) {
    const uiAgents = resolveLaunchAgents(
      summaryTemplate,
      coordinatorMode,
      loaded.summary.prompts,
    );
    const serverAgents = resolveLaunchRoster(
      resolvedTemplate,
      loaded.resolved.prompts,
      coordinatorMode,
    ).agents;

    assert.deepEqual(
      uiAgents.map(launchContract),
      serverAgents.map(launchContract),
      `${coordinatorMode} mode preview must match the launched roster`,
    );
  }

  assert.deepEqual(
    resolveLaunchAgents(summaryTemplate, 'human', loaded.summary.prompts)
      .map((agent) => agent.prompt),
    ['implementer', 'reviewer', 'qa', 'observer', 'bofh'],
  );
});

test('Full Roster always displays Agent + model and identifies Ollama as the backend', async (t) => {
  const {
    formatAgentModel,
    resolveLaunchAgents,
  } = await import('../components/collab/configModel.js');
  const loaded = createBuiltinFixture(t);
  const template = loaded.summary.templates.find((entry) => entry.id === 'full-roster');
  const agents = resolveLaunchAgents(template, 'agent', loaded.summary.prompts);

  assert.deepEqual(
    agents.map((agent) => ({
      role: agent.label,
      display: formatAgentModel(agent),
      backend: agent.backend,
      think: agent.think,
    })),
    [
      { role: 'Coordinator', display: 'Codex + gpt-5.6-sol', backend: 'default', think: 'high' },
      { role: 'Implementer', display: 'Codex + gpt-5.6-sol', backend: 'default', think: 'medium' },
      { role: 'Reviewer', display: 'Agy + 3.6-flash-medium', backend: 'default', think: 'high' },
      { role: 'QA', display: 'Codex + gpt-5.6-sol', backend: 'default', think: 'max' },
      { role: 'Observer', display: 'Codex + qwen3:4b', backend: 'ollama', think: 'low' },
      { role: 'BOFH', display: 'Claude + sonnet', backend: 'default', think: 'low' },
    ],
  );
  assert.equal(agents.some((agent) => formatAgentModel(agent).startsWith('Ollama +')), false);
});

test('Agy display aliases remove exactly the first provider prefix', async () => {
  const {
    displayModelName,
    formatAgentModel,
  } = await import('../components/collab/configModel.js');
  const aliases = [
    ['gemini-3.6-flash-medium', '3.6-flash-medium'],
    ['claude-sonnet-4-6-thinking', 'sonnet-4-6-thinking'],
    ['claude-opus-4-6-thinking', 'opus-4-6-thinking'],
    ['gpt-oss-120b', 'oss-120b'],
  ];

  for (const [model, display] of aliases) {
    const agent = {
      prompt: 'reviewer',
      harness: 'agy',
      backend: 'default',
      model,
      think: 'high',
    };
    assert.equal(displayModelName(agent), display);
    assert.equal(formatAgentModel(agent), `Agy + ${display}`);
    assert.equal(agent.model, model, 'display formatting must not mutate the launch model ID');
  }

  assert.equal(
    displayModelName({ harness: 'codex', backend: 'default', model: 'openai-gpt-5.4' }),
    'openai-gpt-5.4',
  );
  assert.equal(
    displayModelName({ harness: 'claude', backend: 'default', model: 'claude-sonnet' }),
    'claude-sonnet',
  );
});

test('only Codex can select the Ollama model runtime', async () => {
  const {
    AGENT_BACKENDS,
    AGENT_HARNESSES,
    isCompatibleAgentBackend,
  } = await import('../components/collab/configModel.js');

  assert.deepEqual(AGENT_HARNESSES.map((entry) => entry.id), ['codex', 'agy', 'claude']);
  assert.deepEqual(AGENT_BACKENDS.map((entry) => entry.id), ['default', 'ollama']);
  assert.deepEqual(
    AGENT_HARNESSES.flatMap(({ id: harness }) => (
      AGENT_BACKENDS.map(({ id: backend }) => [
        `${harness}:${backend}`,
        isCompatibleAgentBackend(harness, backend),
      ])
    )),
    [
      ['codex:default', true],
      ['codex:ollama', true],
      ['agy:default', true],
      ['agy:ollama', false],
      ['claude:default', true],
      ['claude:ollama', false],
    ],
  );
});
