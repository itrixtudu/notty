'use strict';

const crypto = require('crypto');
const fs = require('fs');
const os = require('os');
const path = require('path');

const LEGACY_AGENT_RUNTIMES = new Set(['codex', 'agy', 'ollama']);
const SUPPORTED_AGENT_HARNESSES = new Set(['codex', 'agy', 'claude']);
const SUPPORTED_MODEL_BACKENDS = new Set(['default', 'ollama']);

const SCHEMA_VERSION = 2;
const SUPPORTED_SCHEMA_VERSIONS = new Set([1, SCHEMA_VERSION]);
const MAP_KEYS = ['prompts', 'layouts', 'templates'];
const CONFIG_ID_PATTERN = /^[A-Za-z0-9][A-Za-z0-9.-]*$/;
const RESERVED_CONFIG_IDS = new Set(['__proto__', 'prototype', 'constructor']);

function isPlainObject(value) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    return false;
  }
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function validateOptionalString(entry, key, source, options = {}) {
  if (entry[key] === undefined) {
    return;
  }
  if (typeof entry[key] !== 'string' || (options.nonEmpty && !entry[key].trim())) {
    throw new Error(`${source} ${key} must be ${options.nonEmpty ? 'a non-empty string' : 'a string'}`);
  }
}

function requireAgentString(entry, key, source, options = {}) {
  if (!Object.hasOwn(entry, key) || typeof entry[key] !== 'string') {
    throw new Error(`${source} ${key} must be a string`);
  }
  const value = entry[key].trim();
  if (options.nonEmpty && !value) {
    throw new Error(`${source} ${key} must be a non-empty string`);
  }
  return value;
}

function validateConfigId(value, label = 'configuration id') {
  const id = String(value || '');
  if (!CONFIG_ID_PATTERN.test(id) || RESERVED_CONFIG_IDS.has(id)) {
    throw new Error(`${label} ${JSON.stringify(id)} is invalid`);
  }
  return id;
}

function stableJson(value) {
  if (Array.isArray(value)) {
    return `[${value.map(stableJson).join(',')}]`;
  }
  if (value && typeof value === 'object') {
    return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${stableJson(value[key])}`).join(',')}}`;
  }
  return JSON.stringify(value);
}

function revisionFor(document) {
  return crypto.createHash('sha256').update(stableJson(document)).digest('hex').slice(0, 16);
}

function emptyDocument() {
  return {
    schemaVersion: SCHEMA_VERSION,
    prompts: {},
    layouts: {},
    templates: {},
  };
}

function readDocument(filePath, options = {}) {
  let source;
  try {
    source = fs.readFileSync(filePath, 'utf8');
  } catch (error) {
    if (error.code === 'ENOENT') {
      return emptyDocument();
    }
    throw new Error(`invalid collab configuration ${filePath}: ${error.message}`);
  }

  let parsed;
  try {
    parsed = JSON.parse(source);
  } catch (error) {
    throw new Error(`invalid collab configuration ${filePath}: ${error.message}`);
  }
  validateDocument(parsed, { filePath, allowEmpty: options.allowEmpty !== false });
  return parsed;
}

function validateDocument(document, options = {}) {
  const source = options.filePath || 'configuration';
  if (!document || typeof document !== 'object' || Array.isArray(document)) {
    throw new Error(`${source} must contain a JSON object`);
  }
  const schemaVersion = document.schemaVersion === undefined ? 1 : document.schemaVersion;
  if (!SUPPORTED_SCHEMA_VERSIONS.has(schemaVersion)) {
    throw new Error(`${source} schemaVersion must be 1 or ${SCHEMA_VERSION}`);
  }
  for (const key of MAP_KEYS) {
    if (document[key] !== undefined && (!document[key] || typeof document[key] !== 'object' || Array.isArray(document[key]))) {
      throw new Error(`${source} ${key} must be an object map`);
    }
    for (const id of Object.keys(document[key] || {})) {
      validateConfigId(id, `${source} ${key} id`);
    }
  }
  if (document.defaultTemplate !== undefined && typeof document.defaultTemplate !== 'string') {
    throw new Error(`${source} defaultTemplate must be a string`);
  }
  if (document.defaultTemplate !== undefined) {
    validateConfigId(document.defaultTemplate, `${source} defaultTemplate`);
  }
  for (const [id, prompt] of Object.entries(document.prompts || {})) {
    if (!isPlainObject(prompt)) {
      throw new Error(`${source} prompt ${id} must be an object`);
    }
    for (const key of ['label', 'role', 'identity', 'instructions']) {
      validateOptionalString(prompt, key, `${source} prompt ${id}`);
    }
    if (prompt.coordinatorCapable !== undefined && typeof prompt.coordinatorCapable !== 'boolean') {
      throw new Error(`${source} prompt ${id} coordinatorCapable must be a boolean`);
    }
  }
  for (const [id, layout] of Object.entries(document.layouts || {})) {
    if (!isPlainObject(layout)) {
      throw new Error(`${source} layout ${id} must be an object`);
    }
    for (const key of ['label', 'description']) {
      validateOptionalString(layout, key, `${source} layout ${id}`);
    }
    validateOptionalString(layout, 'mode', `${source} layout ${id}`, { nonEmpty: true });
    if (layout.mode === undefined) {
      throw new Error(`${source} layout ${id} mode must be a non-empty string`);
    }
  }
  for (const [id, template] of Object.entries(document.templates || {})) {
    if (!isPlainObject(template)) {
      throw new Error(`${source} template ${id} must be an object`);
    }
    for (const key of ['label', 'description', 'channel']) {
      validateOptionalString(template, key, `${source} template ${id}`);
    }
    validateOptionalString(template, 'layout', `${source} template ${id}`, { nonEmpty: true });
    if (template.layout === undefined) {
      throw new Error(`${source} template ${id} layout must be a non-empty string`);
    }
    validateConfigId(template.layout, `${source} template ${id} layout`);
    if (!Array.isArray(template.agents) || template.agents.length === 0) {
      throw new Error(`${source} template ${id} must define a non-empty agents array`);
    }
    template.agents.forEach((spec, index) => {
      if (schemaVersion === 1 && typeof spec !== 'string') {
        throw new Error(`${source} template ${id} agent specs must be strings in schemaVersion 1`);
      }
      normalizeAgentSpec(spec, `${source} template ${id} agent ${index + 1}`);
    });
    if (
      template.defaultCoordinatorMode !== undefined
      && template.defaultCoordinatorMode !== 'human'
      && template.defaultCoordinatorMode !== 'agent'
    ) {
      throw new Error(`${source} template ${id} defaultCoordinatorMode must be human or agent`);
    }
    if (template.coordinatorSpec !== undefined) {
      if (schemaVersion === 1 && typeof template.coordinatorSpec !== 'string') {
        throw new Error(`${source} template ${id} coordinatorSpec must be a string in schemaVersion 1`);
      }
      normalizeAgentSpec(template.coordinatorSpec, `${source} template ${id} coordinatorSpec`);
    }
    if (template.requiredNoshProfiles !== undefined) {
      if (
        !Array.isArray(template.requiredNoshProfiles)
        || template.requiredNoshProfiles.some((profile) => typeof profile !== 'string' || !profile.trim())
      ) {
        throw new Error(`${source} template ${id} requiredNoshProfiles must be an array of non-empty strings`);
      }
    }
    if (template.startup !== undefined && !isPlainObject(template.startup)) {
      throw new Error(`${source} template ${id} startup must be an object`);
    }
  }
  return document;
}

function legacyRuntimeFor(harness, backend) {
  const normalizedHarness = String(harness || '').trim().toLowerCase();
  const normalizedBackend = String(backend || '').trim().toLowerCase();
  if (!SUPPORTED_AGENT_HARNESSES.has(normalizedHarness)) {
    throw new Error(`unsupported agent harness ${JSON.stringify(normalizedHarness || String(harness || ''))}`);
  }
  if (!SUPPORTED_MODEL_BACKENDS.has(normalizedBackend)) {
    throw new Error(`unsupported model backend ${JSON.stringify(normalizedBackend || String(backend || ''))}`);
  }
  if (normalizedBackend === 'ollama') {
    if (normalizedHarness !== 'codex') {
      throw new Error('ollama backend currently requires the codex harness');
    }
    return 'ollama';
  }
  return normalizedHarness;
}

function parseLegacyAgentSpec(value) {
  const spec = String(value || '').trim();
  const first = spec.indexOf('_');
  const second = first === -1 ? -1 : spec.indexOf('_', first + 1);
  if (first <= 0 || second <= first + 1 || second === spec.length - 1) {
    throw new Error(`invalid agent spec ${JSON.stringify(spec)}; expected <prompt>_<runtime>_<model>`);
  }
  const prompt = spec.slice(0, first);
  const runtime = spec.slice(first + 1, second);
  const model = spec.slice(second + 1);
  if (!LEGACY_AGENT_RUNTIMES.has(runtime)) {
    throw new Error(`unsupported runtime ${JSON.stringify(runtime)} in ${JSON.stringify(spec)}`);
  }
  validateConfigId(prompt, 'agent prompt');
  const harness = runtime === 'ollama' ? 'codex' : runtime;
  const backend = runtime === 'ollama' ? 'ollama' : 'default';
  return {
    spec,
    legacySpec: spec,
    prompt,
    harness,
    backend,
    model,
    think: '',
    runtime,
  };
}

function normalizeAgentSpec(value, source = 'agent spec') {
  if (typeof value === 'string') {
    return parseLegacyAgentSpec(value);
  }
  if (!isPlainObject(value)) {
    throw new Error(`${source} must be a legacy string or canonical agent object`);
  }

  const prompt = requireAgentString(value, 'prompt', source, { nonEmpty: true });
  const harness = requireAgentString(value, 'harness', source, { nonEmpty: true }).toLowerCase();
  const backend = requireAgentString(value, 'backend', source, { nonEmpty: true }).toLowerCase();
  const model = requireAgentString(value, 'model', source, { nonEmpty: true });
  const think = requireAgentString(value, 'think', source).toLowerCase();
  validateConfigId(prompt, 'agent prompt');
  const runtime = legacyRuntimeFor(harness, backend);
  const canonical = { prompt, harness, backend, model, think };
  const legacySpec = LEGACY_AGENT_RUNTIMES.has(runtime)
    ? `${prompt}_${runtime}_${model}`
    : '';
  return {
    spec: structuredClone(canonical),
    legacySpec,
    ...canonical,
    runtime,
  };
}

function parseAgentSpec(value) {
  return normalizeAgentSpec(value);
}

function normalizeIdentity(value) {
  const clean = String(value || '').trim().replace(/[^A-Za-z0-9._-]/g, '-').replace(/-+/g, '-');
  return clean || 'agent';
}

function parseTemplateAgents(template, prompts = {}) {
  const counts = new Map();
  return (template.agents || []).map((value) => {
    const parsed = normalizeAgentSpec(value);
    const prompt = Object.hasOwn(prompts, parsed.prompt) ? prompts[parsed.prompt] : null;
    if (!prompt || typeof prompt !== 'object') {
      throw new Error(`template references unknown prompt ${JSON.stringify(parsed.prompt)}`);
    }
    const base = normalizeIdentity(prompt.identity || parsed.prompt);
    const count = (counts.get(base) || 0) + 1;
    counts.set(base, count);
    return {
      ...parsed,
      identity: count === 1 ? base : `${base}-${count}`,
      role: String(prompt.role || parsed.prompt),
      label: String(prompt.label || parsed.prompt),
      coordinatorCapable: Boolean(prompt.coordinatorCapable),
    };
  });
}

function mergeDocuments(layers) {
  const resolved = emptyDocument();
  const sources = {
    defaultTemplate: '',
    prompts: {},
    layouts: {},
    templates: {},
  };
  for (const layer of layers) {
    const document = layer.document;
    if (document.defaultTemplate !== undefined) {
      resolved.defaultTemplate = document.defaultTemplate;
      sources.defaultTemplate = layer.scope;
    }
    for (const key of MAP_KEYS) {
      for (const [id, entry] of Object.entries(document[key] || {})) {
        resolved[key][id] = structuredClone(entry);
        sources[key][id] = layer.scope;
      }
    }
  }
  return { resolved, sources };
}

function toSummary(merged, revisions) {
  const { resolved, sources } = merged;
  const prompts = Object.entries(resolved.prompts).map(([id, entry]) => ({
    ...structuredClone(entry),
    id,
    source: sources.prompts[id],
  }));
  const layouts = Object.entries(resolved.layouts).map(([id, entry]) => ({
    ...structuredClone(entry),
    id,
    source: sources.layouts[id],
  }));
  const templates = Object.entries(resolved.templates).map(([id, entry]) => ({
    ...structuredClone(entry),
    id,
    source: sources.templates[id],
    agents: parseTemplateAgents(entry, resolved.prompts),
  }));
  if (!resolved.defaultTemplate || !Object.hasOwn(resolved.templates, resolved.defaultTemplate)) {
    throw new Error(`defaultTemplate ${JSON.stringify(resolved.defaultTemplate || '')} does not name a resolved template`);
  }
  for (const template of templates) {
    if (!Object.hasOwn(resolved.layouts, template.layout)) {
      throw new Error(`template ${template.id} references unknown layout ${JSON.stringify(template.layout)}`);
    }
  }
  return {
    schemaVersion: SCHEMA_VERSION,
    defaultTemplate: resolved.defaultTemplate,
    revisions,
    prompts,
    layouts,
    templates,
  };
}

function atomicWriteJson(filePath, document) {
  fs.mkdirSync(path.dirname(filePath), { recursive: true });
  const temporary = `${filePath}.${process.pid}.${crypto.randomBytes(4).toString('hex')}.tmp`;
  try {
    fs.writeFileSync(temporary, `${JSON.stringify(document, null, 2)}\n`, { encoding: 'utf8', mode: 0o600 });
    fs.renameSync(temporary, filePath);
  } finally {
    if (fs.existsSync(temporary)) {
      fs.unlinkSync(temporary);
    }
  }
}

function createConfigStore(options = {}) {
  const appRoot = path.resolve(options.appRoot || path.join(__dirname, '..', '..'));
  const workspaceRoot = path.resolve(options.workspaceRoot || process.env.NOTTY_WORKDIR || process.cwd());
  const configHome = path.resolve(options.configHome || process.env.XDG_CONFIG_HOME || path.join(os.homedir(), '.config'));
  const paths = {
    builtin: path.resolve(options.builtinPath || path.join(appRoot, 'config', 'collab.templates.json')),
    user: path.resolve(options.userPath || path.join(configHome, 'notty', 'collab.templates.json')),
    workspace: path.resolve(options.workspacePath || path.join(workspaceRoot, '.notty', 'collab.json')),
  };

  function load() {
    const documents = {
      builtin: readDocument(paths.builtin, { allowEmpty: false }),
      user: readDocument(paths.user),
      workspace: readDocument(paths.workspace),
    };
    const revisions = {
      user: revisionFor(documents.user),
      workspace: revisionFor(documents.workspace),
    };
    const merged = mergeDocuments([
      { scope: 'builtin', document: documents.builtin },
      { scope: 'user', document: documents.user },
      { scope: 'workspace', document: documents.workspace },
    ]);
    return {
      paths: { ...paths },
      documents,
      resolved: merged.resolved,
      sources: merged.sources,
      summary: toSummary(merged, revisions),
    };
  }

  function write(scope, expectedRevision, document) {
    if (scope !== 'user' && scope !== 'workspace') {
      const error = new Error(`configuration scope ${JSON.stringify(scope)} is read-only`);
      error.statusCode = 403;
      throw error;
    }
    const current = load();
    if (typeof expectedRevision !== 'string' || expectedRevision !== current.summary.revisions[scope]) {
      const error = new Error(`stale ${scope} configuration revision`);
      error.statusCode = 409;
      error.currentRevision = current.summary.revisions[scope];
      throw error;
    }
    const normalized = {
      ...structuredClone(document),
      schemaVersion: SCHEMA_VERSION,
    };
    validateDocument(normalized, { filePath: `${scope} configuration` });
    const candidateDocuments = {
      ...current.documents,
      [scope]: normalized,
    };
    const candidateMerged = mergeDocuments([
      { scope: 'builtin', document: candidateDocuments.builtin },
      { scope: 'user', document: candidateDocuments.user },
      { scope: 'workspace', document: candidateDocuments.workspace },
    ]);
    toSummary(candidateMerged, {
      user: revisionFor(candidateDocuments.user),
      workspace: revisionFor(candidateDocuments.workspace),
    });
    atomicWriteJson(paths[scope], normalized);
    return load();
  }

  return { appRoot, workspaceRoot, paths, load, write };
}

module.exports = {
  SCHEMA_VERSION,
  atomicWriteJson,
  createConfigStore,
  emptyDocument,
  legacyRuntimeFor,
  normalizeAgentSpec,
  parseAgentSpec,
  parseTemplateAgents,
  revisionFor,
  validateDocument,
  validateConfigId,
};
