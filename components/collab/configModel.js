export const CODEX_PERMISSION_MODES = Object.freeze({
  SANDBOXED: 'workspace-write',
  BYPASS: 'danger-full-access'
});

export const AGENT_HARNESSES = Object.freeze([
  { id: 'codex', label: 'Codex' },
  { id: 'agy', label: 'Agy' },
  { id: 'claude', label: 'Claude' }
]);

export const AGENT_BACKENDS = Object.freeze([
  { id: 'default', label: 'Default' },
  { id: 'ollama', label: 'Ollama' }
]);

const THINK_LEVELS = Object.freeze({
  'codex:default': ['', 'none', 'minimal', 'low', 'medium', 'high', 'xhigh', 'max', 'ultra'],
  'codex:ollama': ['', 'none', 'low', 'medium', 'high', 'max'],
  'agy:default': ['', 'low', 'medium', 'high'],
  'claude:default': ['', 'low', 'medium', 'high', 'xhigh', 'max']
});

export function nextCodexPermissionMode(value) {
  return value === CODEX_PERMISSION_MODES.BYPASS
    ? CODEX_PERMISSION_MODES.SANDBOXED
    : CODEX_PERMISSION_MODES.BYPASS;
}

export function legacyRuntimeIdentity(runtime) {
  const value = String(runtime || '').trim().toLowerCase();
  if (value === 'ollama') return { harness: 'codex', backend: 'ollama' };
  if (value === 'agy') return { harness: 'agy', backend: 'default' };
  if (value === 'claude') return { harness: 'claude', backend: 'default' };
  if (value === 'codex') return { harness: 'codex', backend: 'default' };
  return { harness: value, backend: 'default' };
}

export function legacyRuntimeForAgent(agent = {}) {
  const harness = String(agent.harness || '').trim().toLowerCase();
  const backend = String(agent.backend || 'default').trim().toLowerCase();
  if (harness === 'codex' && backend === 'ollama') return 'ollama';
  return harness;
}

export function isCompatibleAgentBackend(harness, backend) {
  const agent = String(harness || '').trim().toLowerCase();
  const runtime = String(backend || 'default').trim().toLowerCase();
  return agent === 'codex'
    ? ['default', 'ollama'].includes(runtime)
    : ['agy', 'claude'].includes(agent) && runtime === 'default';
}

export function thinkOptionsFor(harness, backend) {
  return [...(THINK_LEVELS[`${harness}:${backend || 'default'}`] || [])];
}

function defaultThinkFor(harness, backend) {
  const options = thinkOptionsFor(harness, backend);
  return options[0] || '';
}

export function parseAgentSpec(spec = '') {
  const value = String(spec).trim();
  const firstSeparator = value.indexOf('_');
  const secondSeparator = firstSeparator >= 0
    ? value.indexOf('_', firstSeparator + 1)
    : -1;

  if (firstSeparator < 1 || secondSeparator <= firstSeparator + 1) {
    return {
      spec: value,
      prompt: '',
      runtime: '',
      harness: '',
      backend: 'default',
      model: '',
      think: '',
      valid: false
    };
  }

  const prompt = value.slice(0, firstSeparator);
  const runtime = value.slice(firstSeparator + 1, secondSeparator);
  const model = value.slice(secondSeparator + 1);
  const { harness, backend } = legacyRuntimeIdentity(runtime);
  return {
    spec: value,
    prompt,
    runtime,
    harness,
    backend,
    model,
    think: defaultThinkFor(harness, backend),
    valid: Boolean(model)
  };
}

export function normalizeAgentSpec(agent) {
  if (typeof agent === 'string') {
    return parseAgentSpec(agent);
  }
  const parsed = parseAgentSpec(agent?.spec || '');
  const runtimeIdentity = legacyRuntimeIdentity(agent?.runtime || parsed.runtime);
  const harness = String(
    agent?.harness || agent?.agent || runtimeIdentity.harness || parsed.harness || ''
  ).trim().toLowerCase();
  const backend = String(
    agent?.backend || runtimeIdentity.backend || parsed.backend || 'default'
  ).trim().toLowerCase() || 'default';
  const prompt = String(agent?.prompt || parsed.prompt || '').trim();
  const model = String(agent?.model || parsed.model || '').trim();
  const think = String(
    agent && Object.hasOwn(agent, 'think')
      ? agent.think ?? ''
      : parsed.think ?? defaultThinkFor(harness, backend)
  ).trim().toLowerCase();
  const runtime = legacyRuntimeForAgent({ harness, backend });

  return {
    ...parsed,
    ...agent,
    prompt,
    harness,
    backend,
    runtime,
    model,
    think,
    valid: Boolean(prompt && harness && backend && model)
  };
}

export function createAgentDocument(agent) {
  const normalized = normalizeAgentSpec(agent);
  return {
    prompt: normalized.prompt,
    harness: normalized.harness,
    backend: normalized.backend,
    model: normalized.model,
    think: normalized.think
  };
}

function normalizeAgentIdentity(value) {
  const identity = String(value || '')
    .trim()
    .replace(/[^A-Za-z0-9._-]/g, '-')
    .replace(/-+/g, '-');
  return identity || 'agent';
}

function promptMap(prompts) {
  if (Array.isArray(prompts)) {
    return new Map(prompts.map((prompt) => [prompt.id, prompt]));
  }
  return new Map(Object.entries(prompts || {}));
}

function hasAgentSpec(value) {
  if (typeof value === 'string') return Boolean(value.trim());
  return Boolean(value && typeof value === 'object' && normalizeAgentSpec(value).model);
}

export function resolveLaunchAgents(template, coordinatorMode, prompts = []) {
  const promptById = promptMap(prompts);
  const hydrate = (agent) => {
    const normalized = normalizeAgentSpec(agent);
    const prompt = promptById.get(normalized.prompt) || {};
    return {
      ...normalized,
      role: String(prompt.role || normalized.role || normalized.prompt),
      label: String(prompt.label || normalized.label || normalized.prompt),
      coordinatorCapable: Boolean(
        prompt.coordinatorCapable ?? normalized.coordinatorCapable
      )
    };
  };

  let agents = (template?.agents || []).map(hydrate);
  if (
    coordinatorMode === 'agent'
    && !agents.some((agent) => agent.coordinatorCapable)
    && hasAgentSpec(template?.coordinatorSpec)
  ) {
    agents.unshift(hydrate(template.coordinatorSpec));
  } else if (coordinatorMode === 'human') {
    agents = agents.filter((agent) => !agent.coordinatorCapable);
  }

  const identityCounts = new Map();
  return agents.map((agent) => {
    const prompt = promptById.get(agent.prompt) || {};
    const baseIdentity = normalizeAgentIdentity(prompt.identity || agent.prompt);
    const count = (identityCounts.get(baseIdentity) || 0) + 1;
    identityCounts.set(baseIdentity, count);
    return {
      ...agent,
      identity: count === 1 ? baseIdentity : `${baseIdentity}-${count}`
    };
  });
}

export function serializeAgentSpec(agent) {
  const normalized = normalizeAgentSpec(agent);
  const prompt = normalized.prompt;
  const runtime = legacyRuntimeForAgent(normalized);
  const model = normalized.model;
  return prompt && runtime && model ? `${prompt}_${runtime}_${model}` : '';
}

export function formatAgentName(harness) {
  return AGENT_HARNESSES.find((entry) => entry.id === harness)?.label
    || String(harness || 'Agent');
}

export function displayModelName(agent) {
  const normalized = normalizeAgentSpec(agent);
  if (normalized.harness !== 'agy') return normalized.model;
  return normalized.model.replace(/^[^-]+-/, '');
}

export function formatAgentModel(agent) {
  const normalized = normalizeAgentSpec(agent);
  return `${formatAgentName(normalized.harness)} + ${displayModelName(normalized)}`;
}

export function createTemplateDocument(template) {
  const coordinatorSpec = template?.coordinatorSpec;
  const normalizedCoordinator = typeof coordinatorSpec === 'string'
    ? coordinatorSpec.trim()
    : hasAgentSpec(coordinatorSpec)
      ? createAgentDocument(coordinatorSpec)
      : null;
  return {
    label: template.label || template.id,
    description: template.description || '',
    layout: template.layout || 'grid',
    channel: template.channel || 'lobby',
    defaultCoordinatorMode: template.defaultCoordinatorMode || 'human',
    ...(normalizedCoordinator ? { coordinatorSpec: normalizedCoordinator } : {}),
    requiredNoshProfiles: Array.isArray(template.requiredNoshProfiles)
      ? template.requiredNoshProfiles
      : [],
    startup: template.startup || {},
    agents: (template.agents || [])
      .map((agent) => (
        typeof agent === 'string' ? agent.trim() : createAgentDocument(agent)
      ))
      .filter((agent) => typeof agent === 'string' ? Boolean(agent) : Boolean(agent.model))
  };
}

function objectMap(value, createEntry) {
  return Array.isArray(value)
    ? Object.fromEntries(value.map((entry) => [entry.id, createEntry(entry)]))
    : { ...(value || {}) };
}

function writeSchemaVersion(current, requested) {
  return Math.max(2, Number(current?.schemaVersion) || 0, Number(requested) || 0);
}

export function updateScopedTemplate(document, templateId, template, schemaVersion = 2) {
  const current = document && typeof document === 'object' ? document : {};
  const templates = objectMap(current.templates, createTemplateDocument);
  templates[templateId] = createTemplateDocument(template);
  return {
    ...current,
    schemaVersion: writeSchemaVersion(current, schemaVersion),
    templates
  };
}

export function removeScopedTemplate(document, templateId, schemaVersion = 2) {
  const current = document && typeof document === 'object' ? document : {};
  const templates = objectMap(current.templates, createTemplateDocument);
  delete templates[templateId];
  return {
    ...current,
    schemaVersion: writeSchemaVersion(current, schemaVersion),
    templates
  };
}

export function createPromptDocument(prompt = {}) {
  return {
    label: String(prompt.label || prompt.id || '').trim(),
    role: String(prompt.role || prompt.id || '').trim(),
    identity: String(prompt.identity || prompt.id || '').trim(),
    coordinatorCapable: Boolean(prompt.coordinatorCapable),
    instructions: String(prompt.instructions || '').trim()
  };
}

export function updateScopedPrompt(document, promptId, prompt, schemaVersion = 2) {
  const current = document && typeof document === 'object' ? document : {};
  const prompts = objectMap(current.prompts, createPromptDocument);
  prompts[promptId] = createPromptDocument({ ...prompt, id: promptId });
  return {
    ...current,
    schemaVersion: writeSchemaVersion(current, schemaVersion),
    prompts
  };
}

export function removeScopedPrompt(document, promptId, schemaVersion = 2) {
  const current = document && typeof document === 'object' ? document : {};
  const prompts = objectMap(current.prompts, createPromptDocument);
  delete prompts[promptId];
  return {
    ...current,
    schemaVersion: writeSchemaVersion(current, schemaVersion),
    prompts
  };
}

export function scopeHasTemplate(document, templateId) {
  if (Array.isArray(document?.templates)) {
    return document.templates.some((entry) => entry.id === templateId);
  }
  return Boolean(
    document?.templates
    && Object.hasOwn(document.templates, templateId)
    && document.templates[templateId]
  );
}

export function scopeHasPrompt(document, promptId) {
  if (Array.isArray(document?.prompts)) {
    return document.prompts.some((entry) => entry.id === promptId);
  }
  return Boolean(
    document?.prompts
    && Object.hasOwn(document.prompts, promptId)
    && document.prompts[promptId]
  );
}

export function isPromptReferenced(templates, promptId) {
  return (templates || []).some((template) => {
    const specs = [...(template.agents || []), template.coordinatorSpec].filter(Boolean);
    return specs.some((spec) => normalizeAgentSpec(spec).prompt === promptId);
  });
}

export function resolveTerminalId(summary) {
  return summary?.id ?? summary?.terminal_uuid ?? null;
}
