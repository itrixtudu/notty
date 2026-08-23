'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const test = require('node:test');

const {
  SCHEMA_VERSION,
  createConfigStore,
  legacyRuntimeFor,
  normalizeAgentSpec,
  parseAgentSpec,
  parseTemplateAgents,
  validateDocument,
} = require('../lib/collab/config.cjs');

function writeJson(filePath, value) {
  fs.mkdirSync(path.dirname(filePath), { recursive: true });
  fs.writeFileSync(filePath, `${JSON.stringify(value, null, 2)}\n`, 'utf8');
}

function fixtureDocument(overrides = {}) {
  return {
    schemaVersion: 1,
    defaultTemplate: 'pair',
    prompts: {
      coder: { label: 'Coder', role: 'coder' },
      qa: { label: 'QA', role: 'qa' },
    },
    layouts: {
      grid: { label: 'Grid', mode: 'grid' },
    },
    templates: {
      pair: {
        label: 'Pair',
        layout: 'grid',
        channel: 'lobby',
        agents: ['coder_codex_gpt-5.6-sol', 'qa_codex_luna'],
      },
    },
    ...overrides,
  };
}

test('compact agent specs preserve the model remainder', () => {
  assert.deepEqual(parseAgentSpec('qa_codex_gpt_5.6-sol'), {
    spec: 'qa_codex_gpt_5.6-sol',
    legacySpec: 'qa_codex_gpt_5.6-sol',
    prompt: 'qa',
    harness: 'codex',
    backend: 'default',
    model: 'gpt_5.6-sol',
    think: '',
    runtime: 'codex',
  });
  assert.deepEqual(parseAgentSpec('qa_agy_Claude Opus 4.6 (Thinking)'), {
    spec: 'qa_agy_Claude Opus 4.6 (Thinking)',
    legacySpec: 'qa_agy_Claude Opus 4.6 (Thinking)',
    prompt: 'qa',
    harness: 'agy',
    backend: 'default',
    model: 'Claude Opus 4.6 (Thinking)',
    think: '',
    runtime: 'agy',
  });
  assert.deepEqual(parseAgentSpec('qa_ollama_ornith:9b'), {
    spec: 'qa_ollama_ornith:9b',
    legacySpec: 'qa_ollama_ornith:9b',
    prompt: 'qa',
    harness: 'codex',
    backend: 'ollama',
    model: 'ornith:9b',
    think: '',
    runtime: 'ollama',
  });
  assert.throws(
    () => parseAgentSpec('qa_ollama_'),
    /invalid agent spec/,
  );
  assert.throws(
    () => parseAgentSpec('qa_unknown_Claude Opus 4.6 (Thinking)'),
    /unsupported runtime "unknown"/,
  );
});

test('canonical agent specs separate the harness and backend without losing object fields', () => {
  const input = {
    prompt: 'qa',
    harness: 'Codex',
    backend: 'Ollama',
    model: 'qwen3:4b',
    think: 'Low',
  };
  const normalized = normalizeAgentSpec(input);

  assert.deepEqual(normalized, {
    spec: {
      prompt: 'qa',
      harness: 'codex',
      backend: 'ollama',
      model: 'qwen3:4b',
      think: 'low',
    },
    legacySpec: 'qa_ollama_qwen3:4b',
    prompt: 'qa',
    harness: 'codex',
    backend: 'ollama',
    model: 'qwen3:4b',
    think: 'low',
    runtime: 'ollama',
  });
  assert.notEqual(normalized.spec, input);
  assert.deepEqual(input, {
    prompt: 'qa',
    harness: 'Codex',
    backend: 'Ollama',
    model: 'qwen3:4b',
    think: 'Low',
  });
  assert.equal(legacyRuntimeFor('codex', 'default'), 'codex');
  assert.equal(legacyRuntimeFor('agy', 'default'), 'agy');
  assert.equal(legacyRuntimeFor('codex', 'ollama'), 'ollama');
  assert.equal(legacyRuntimeFor('claude', 'default'), 'claude');
  assert.throws(
    () => legacyRuntimeFor('claude', 'ollama'),
    /ollama backend currently requires the codex harness/,
  );
});

test('duplicate prompt identities receive deterministic suffixes', () => {
  const agents = parseTemplateAgents({
    agents: [
      'coder_codex_gpt-5.6-sol',
      'coder_codex_gpt-5.6-sol',
      'coder_codex_luna',
    ],
  }, {
    coder: { label: 'Coder', role: 'coder' },
  });

  assert.deepEqual(agents.map((agent) => agent.identity), ['coder', 'coder-2', 'coder-3']);
});

test('canonical specs survive coordinator filtering and identity reparsing', () => {
  const coordinator = {
    prompt: 'coordinator',
    harness: 'codex',
    backend: 'default',
    model: 'gpt-5.4',
    think: 'high',
  };
  const worker = {
    prompt: 'coder',
    harness: 'codex',
    backend: 'ollama',
    model: 'qwen3:4b',
    think: 'low',
  };
  const prompts = {
    coordinator: { role: 'coordinator', coordinatorCapable: true },
    coder: { role: 'coder', coordinatorCapable: false },
  };
  const full = parseTemplateAgents({ agents: [coordinator, worker, worker] }, prompts);
  const reparsedWorkers = parseTemplateAgents({
    agents: full
      .filter((agent) => !agent.coordinatorCapable)
      .map((agent) => agent.spec),
  }, prompts);

  assert.deepEqual(reparsedWorkers.map((agent) => agent.identity), ['coder', 'coder-2']);
  assert.deepEqual(reparsedWorkers.map((agent) => agent.think), ['low', 'low']);
  assert.deepEqual(reparsedWorkers.map((agent) => agent.runtime), ['ollama', 'ollama']);
  assert.notEqual(full[1].spec, worker);
});

test('agent prompt lookup ignores inherited object properties', () => {
  assert.throws(
    () => parseTemplateAgents({ agents: ['constructor_codex_model'] }, {}),
    /invalid|unknown prompt/,
  );
  assert.throws(
    () => parseTemplateAgents({ agents: ['toString_codex_model'] }, {}),
    /unknown prompt/,
  );
});

test('configuration maps require structured prompt and layout entries', () => {
  assert.throws(
    () => validateDocument(fixtureDocument({ prompts: { coder: 'coder' } })),
    /prompt coder must be an object/,
  );
  assert.throws(
    () => validateDocument(fixtureDocument({ layouts: { grid: 'grid' } })),
    /layout grid must be an object/,
  );
  assert.throws(
    () => validateDocument(fixtureDocument({ layouts: { grid: { label: 'Grid' } } })),
    /layout grid mode must be a non-empty string/,
  );
  assert.throws(
    () => validateDocument(fixtureDocument({
      prompts: { coder: { coordinatorCapable: 'yes' } },
    })),
    /coordinatorCapable must be a boolean/,
  );
});

test('template fields are validated before layered resolution', () => {
  const withTemplate = (template) => fixtureDocument({ templates: { pair: template } });
  const validTemplate = fixtureDocument().templates.pair;

  assert.throws(
    () => validateDocument(withTemplate({ ...validTemplate, layout: 42 })),
    /layout must be a non-empty string/,
  );
  assert.throws(
    () => validateDocument(withTemplate({ ...validTemplate, defaultCoordinatorMode: 'automatic' })),
    /defaultCoordinatorMode must be human or agent/,
  );
  assert.throws(
    () => validateDocument(withTemplate({ ...validTemplate, coordinatorSpec: 'coordinator' })),
    /invalid agent spec/,
  );
  assert.throws(
    () => validateDocument(withTemplate({ ...validTemplate, requiredNoshProfiles: ['agents', ''] })),
    /requiredNoshProfiles must be an array of non-empty strings/,
  );
  assert.throws(
    () => validateDocument(withTemplate({ ...validTemplate, startup: [] })),
    /startup must be an object/,
  );
});

test('schemaVersion 2 accepts mixed canonical and legacy rows while schemaVersion 1 stays strict', () => {
  const canonical = {
    prompt: 'qa',
    harness: 'claude',
    backend: 'default',
    model: 'sonnet',
    think: 'low',
  };
  const versionTwo = fixtureDocument({
    schemaVersion: 2,
    templates: {
      pair: {
        ...fixtureDocument().templates.pair,
        coordinatorSpec: canonical,
        agents: ['coder_codex_gpt-5.4', canonical],
      },
    },
  });

  assert.equal(validateDocument(versionTwo), versionTwo);
  assert.throws(
    () => validateDocument({ ...versionTwo, schemaVersion: 1 }),
    /agent specs must be strings in schemaVersion 1/,
  );
  assert.throws(
    () => validateDocument({ ...versionTwo, schemaVersion: 3 }),
    /schemaVersion must be 1 or 2/,
  );
  assert.throws(
    () => normalizeAgentSpec({ ...canonical, harness: 'unknown' }),
    /unsupported agent harness/,
  );
  assert.throws(
    () => normalizeAgentSpec({ ...canonical, backend: 'unknown' }),
    /unsupported model backend/,
  );
  assert.throws(
    () => normalizeAgentSpec({ ...canonical, think: undefined }),
    /think must be a string/,
  );
});

test('workspace entries override user and built-in entries', (t) => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'notty-collab-config-'));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));

  const builtinPath = path.join(root, 'builtin.json');
  const userPath = path.join(root, 'user.json');
  const workspacePath = path.join(root, 'workspace.json');
  writeJson(builtinPath, fixtureDocument());
  writeJson(userPath, {
    schemaVersion: 1,
    templates: {
      pair: {
        label: 'User Pair',
        layout: 'grid',
        channel: 'user',
        agents: ['coder_codex_user-model'],
      },
    },
  });
  writeJson(workspacePath, {
    schemaVersion: 1,
    templates: {
      pair: {
        label: 'Workspace Pair',
        layout: 'grid',
        channel: 'workspace',
        agents: ['qa_codex_workspace-model'],
      },
    },
  });
  const userSource = fs.readFileSync(userPath, 'utf8');
  const workspaceSource = fs.readFileSync(workspacePath, 'utf8');

  const store = createConfigStore({ builtinPath, userPath, workspacePath });
  const loaded = store.load();
  const pair = loaded.summary.templates.find((template) => template.id === 'pair');
  assert.equal(pair.label, 'Workspace Pair');
  assert.equal(pair.source, 'workspace');
  assert.equal(pair.agents[0].model, 'workspace-model');
  assert.equal(pair.agents[0].harness, 'codex');
  assert.equal(pair.agents[0].backend, 'default');
  assert.equal(pair.agents[0].think, '');
  assert.equal(loaded.summary.schemaVersion, SCHEMA_VERSION);
  assert.equal(loaded.documents.user.schemaVersion, 1);
  assert.equal(loaded.documents.workspace.schemaVersion, 1);
  assert.equal(fs.readFileSync(userPath, 'utf8'), userSource);
  assert.equal(fs.readFileSync(workspacePath, 'utf8'), workspaceSource);
});

test('configuration writes require the current revision', (t) => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'notty-collab-write-'));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));

  const builtinPath = path.join(root, 'builtin.json');
  const userPath = path.join(root, 'user.json');
  const workspacePath = path.join(root, 'workspace.json');
  writeJson(builtinPath, fixtureDocument());

  const store = createConfigStore({ builtinPath, userPath, workspacePath });
  const revision = store.load().summary.revisions.workspace;
  const updated = store.write('workspace', revision, {
    schemaVersion: 1,
    prompts: {},
    layouts: {},
    templates: {
      pair: {
        label: 'Local Pair',
        layout: 'grid',
        channel: 'lobby',
        agents: ['coder_codex_custom-model'],
      },
    },
  });

  assert.notEqual(updated.summary.revisions.workspace, revision);
  assert.equal(updated.documents.workspace.schemaVersion, SCHEMA_VERSION);
  assert.equal(JSON.parse(fs.readFileSync(workspacePath, 'utf8')).schemaVersion, SCHEMA_VERSION);
  assert.throws(
    () => store.write('workspace', revision, updated.documents.workspace),
    (error) => error.statusCode === 409,
  );
});

test('built-in Full Roster exposes the approved canonical choices', (t) => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'notty-collab-builtin-'));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const store = createConfigStore({
    builtinPath: path.join(__dirname, '..', 'config', 'collab.templates.json'),
    userPath: path.join(root, 'user.json'),
    workspacePath: path.join(root, 'workspace.json'),
  });
  const loaded = store.load();
  const fullRoster = loaded.summary.templates.find((template) => template.id === 'full-roster');

  assert.equal(loaded.documents.builtin.schemaVersion, 2);
  assert.equal(fullRoster.label, 'Full Roster');
  assert.deepEqual(
    fullRoster.agents.map(({ prompt, harness, backend, model, think, runtime }) => ({
      prompt,
      harness,
      backend,
      model,
      think,
      runtime,
    })),
    [
      { prompt: 'coordinator', harness: 'codex', backend: 'default', model: 'gpt-5.6-sol', think: 'high', runtime: 'codex' },
      { prompt: 'implementer', harness: 'codex', backend: 'default', model: 'gpt-5.6-sol', think: 'medium', runtime: 'codex' },
      { prompt: 'reviewer', harness: 'agy', backend: 'default', model: 'gemini-3.6-flash-medium', think: 'high', runtime: 'agy' },
      { prompt: 'qa', harness: 'codex', backend: 'default', model: 'gpt-5.6-sol', think: 'max', runtime: 'codex' },
      { prompt: 'observer', harness: 'codex', backend: 'ollama', model: 'qwen3:4b', think: 'low', runtime: 'ollama' },
      { prompt: 'bofh', harness: 'claude', backend: 'default', model: 'sonnet', think: 'low', runtime: 'claude' },
    ],
  );
  assert.deepEqual(
    fullRoster.agents.filter((agent) => !agent.coordinatorCapable).map((agent) => agent.prompt),
    ['implementer', 'reviewer', 'qa', 'observer', 'bofh'],
  );
});
