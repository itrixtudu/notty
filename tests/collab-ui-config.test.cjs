'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');

test('UI template serialization preserves compact specs and omits an empty coordinator spec', async () => {
  const { createTemplateDocument } = await import('../components/collab/configModel.js');
  const document = createTemplateDocument({
    id: 'human-pair',
    layout: 'pair-review',
    defaultCoordinatorMode: 'human',
    coordinatorSpec: '',
    agents: ['dev_codex_gpt-5.4', 'qa_codex_gpt_5_4'],
  });

  assert.deepEqual(document.agents, ['dev_codex_gpt-5.4', 'qa_codex_gpt_5_4']);
  assert.equal(Object.hasOwn(document, 'coordinatorSpec'), false);
});

test('UI compact spec parsing preserves underscores in model names', async () => {
  const { parseAgentSpec } = await import('../components/collab/configModel.js');
  const parsed = parseAgentSpec('coder_codex_gpt_5_4');
  assert.equal(parsed.spec, 'coder_codex_gpt_5_4');
  assert.equal(parsed.prompt, 'coder');
  assert.equal(parsed.runtime, 'codex');
  assert.equal(parsed.harness, 'codex');
  assert.equal(parsed.backend, 'default');
  assert.equal(parsed.model, 'gpt_5_4');
  assert.equal(parsed.think, '');
  assert.equal(parsed.valid, true);
});

test('UI maps legacy runtimes to canonical agent and backend fields without inventing Think', async () => {
  const {
    normalizeAgentSpec,
    thinkOptionsFor,
  } = await import('../components/collab/configModel.js');

  assert.deepEqual(
    (({ prompt, harness, backend, model, think }) => ({ prompt, harness, backend, model, think }))(
      normalizeAgentSpec('observer_ollama_qwen3:4b'),
    ),
    {
      prompt: 'observer',
      harness: 'codex',
      backend: 'ollama',
      model: 'qwen3:4b',
      think: '',
    },
  );
  assert.equal(thinkOptionsFor('codex', 'default').includes('minimal'), true);
  assert.equal(thinkOptionsFor('agy', 'default')[0], '');
});

test('UI shortens only the visible Agy model while retaining the raw model ID', async () => {
  const {
    displayModelName,
    formatAgentModel,
    normalizeAgentSpec,
  } = await import('../components/collab/configModel.js');
  const agent = normalizeAgentSpec({
    prompt: 'reviewer',
    harness: 'agy',
    backend: 'default',
    model: 'gemini-3.6-flash-high',
    think: 'high',
  });

  assert.equal(displayModelName(agent), '3.6-flash-high');
  assert.equal(formatAgentModel(agent), 'Agy + 3.6-flash-high');
  assert.equal(agent.model, 'gemini-3.6-flash-high');
  assert.equal(
    displayModelName({ harness: 'codex', backend: 'default', model: 'openai-gpt-5.4' }),
    'openai-gpt-5.4',
  );
});

test('UI SAFE and FULL controls alternate Codex permission modes', async () => {
  const {
    CODEX_PERMISSION_MODES,
    nextCodexPermissionMode,
  } = await import('../components/collab/configModel.js');

  assert.deepEqual(CODEX_PERMISSION_MODES, {
    SANDBOXED: 'workspace-write',
    BYPASS: 'danger-full-access',
  });

  let permissionMode = CODEX_PERMISSION_MODES.SANDBOXED;
  permissionMode = nextCodexPermissionMode(permissionMode);
  assert.equal(permissionMode, CODEX_PERMISSION_MODES.BYPASS);

  permissionMode = nextCodexPermissionMode(permissionMode);
  assert.equal(permissionMode, CODEX_PERMISSION_MODES.SANDBOXED);
});

test('UI launch preview alternates between worker-only and full rosters', async () => {
  const { resolveLaunchAgents } = await import('../components/collab/configModel.js');
  const prompts = [
    {
      id: 'coordinator',
      identity: 'shared',
      label: 'Coordinator',
      role: 'coordinator',
      coordinatorCapable: true,
    },
    {
      id: 'qa',
      identity: 'shared',
      label: 'QA',
      role: 'qa',
      coordinatorCapable: false,
    },
  ];
  const template = {
    agents: [
      {
        spec: 'coordinator_codex_gpt-5.4',
        identity: 'shared',
        coordinatorCapable: true,
      },
      {
        spec: 'qa_codex_gpt-5.4',
        identity: 'shared-2',
        coordinatorCapable: false,
      },
    ],
  };

  const human = resolveLaunchAgents(template, 'human', prompts);
  assert.deepEqual(human.map((agent) => agent.prompt), ['qa']);
  assert.deepEqual(human.map((agent) => agent.identity), ['shared']);

  const agent = resolveLaunchAgents(template, 'agent', prompts);
  assert.deepEqual(agent.map((entry) => entry.prompt), ['coordinator', 'qa']);
  assert.deepEqual(agent.map((entry) => entry.identity), ['shared', 'shared-2']);
});

test('UI agent preview includes the coordinator fallback without adding it to human mode', async () => {
  const { resolveLaunchAgents } = await import('../components/collab/configModel.js');
  const prompts = [
    {
      id: 'coordinator',
      label: 'Coordinator',
      role: 'coordinator',
      coordinatorCapable: true,
    },
    {
      id: 'dev',
      label: 'Developer',
      role: 'dev',
      coordinatorCapable: false,
    },
  ];
  const template = {
    coordinatorSpec: 'coordinator_codex_gpt-5.4',
    agents: ['dev_codex_gpt-5.4'],
  };

  assert.deepEqual(
    resolveLaunchAgents(template, 'human', prompts).map((agent) => agent.prompt),
    ['dev'],
  );
  const agentMode = resolveLaunchAgents(template, 'agent', prompts);
  assert.deepEqual(
    agentMode.map((agent) => agent.prompt),
    ['coordinator', 'dev'],
  );
  assert.equal(
    agentMode.filter((agent) => agent.coordinatorCapable).length,
    1,
  );
});

test('UI template removal converts legacy arrays before deleting by id', async () => {
  const { removeScopedTemplate } = await import('../components/collab/configModel.js');
  const document = removeScopedTemplate({
    schemaVersion: 1,
    defaultTemplate: 'solo',
    templates: [
      {
        id: 'solo',
        label: 'Solo',
        layout: 'single',
        agents: ['coder_codex_gpt-5.4'],
      },
      {
        id: 'pair',
        label: 'Pair',
        layout: 'grid',
        agents: ['coder_codex_gpt-5.4', 'qa_codex_gpt-5.4'],
      },
    ],
  }, 'pair');

  assert.deepEqual(Object.keys(document.templates), ['solo']);
  assert.deepEqual(document.templates.solo.agents, ['coder_codex_gpt-5.4']);
  assert.equal(document.templates.pair, undefined);
  assert.equal(Array.isArray(document.templates), false);
});

test('UI edited templates upgrade schema-v1 documents and persist canonical rows', async () => {
  const { updateScopedTemplate } = await import('../components/collab/configModel.js');
  const document = updateScopedTemplate({
    schemaVersion: 1,
    prompts: {},
    templates: {},
  }, 'full-roster', {
    id: 'full-roster',
    label: 'Full Roster',
    layout: 'grid',
    agents: [{
      prompt: 'observer',
      harness: 'codex',
      backend: 'ollama',
      model: 'qwen3:4b',
      think: 'low',
    }],
  }, 1);

  assert.equal(document.schemaVersion, 2);
  assert.deepEqual(document.templates['full-roster'].agents, [{
    prompt: 'observer',
    harness: 'codex',
    backend: 'ollama',
    model: 'qwen3:4b',
    think: 'low',
  }]);
});

test('UI prompt updates share the scoped document and preserve template overrides', async () => {
  const {
    isPromptReferenced,
    updateScopedPrompt,
  } = await import('../components/collab/configModel.js');
  const document = updateScopedPrompt({
    schemaVersion: 1,
    templates: {
      pair: {
        label: 'Pair',
        layout: 'grid',
        agents: ['qa_codex_gpt-5.4'],
      },
    },
  }, 'qa', {
    label: 'QA',
    role: 'qa',
    identity: 'qa',
    coordinatorCapable: false,
    instructions: 'Verify behavior.',
  }, 1);

  assert.equal(document.schemaVersion, 2);
  assert.equal(document.templates.pair.label, 'Pair');
  assert.equal(document.prompts.qa.instructions, 'Verify behavior.');
  assert.equal(isPromptReferenced([
    { agents: [{ prompt: 'qa', harness: 'codex', backend: 'default', model: 'gpt-5.4' }] },
  ], 'qa'), true);
});
