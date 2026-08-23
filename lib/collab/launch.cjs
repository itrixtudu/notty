'use strict';

const { buildOllamaCodexRelayCommand } = require('./ollama-codex-relay.cjs');

const SUPPORTED_HARNESSES = new Set(['codex', 'agy', 'claude']);
const SUPPORTED_BACKENDS = new Set(['default', 'ollama']);
const CODEX_THINK_LEVELS = Object.freeze([
  'none', 'minimal', 'low', 'medium', 'high', 'xhigh', 'max', 'ultra',
]);
const OLLAMA_THINK_LEVELS = Object.freeze(['none', 'low', 'medium', 'high', 'max']);
const AGY_THINK_LEVELS = Object.freeze(['low', 'medium', 'high']);
const CLAUDE_THINK_LEVELS = Object.freeze(['low', 'medium', 'high', 'xhigh', 'max']);

function normalizeLegacyRuntime(value, fallback = 'codex') {
  const runtime = String(value || fallback).trim().toLowerCase();
  if (!['codex', 'agy', 'ollama', 'claude'].includes(runtime)) {
    throw new Error(`unsupported legacy agent runtime: ${runtime || '(empty)'}`);
  }
  return runtime;
}

function legacyRuntimeFor(harness, backend) {
  return harness === 'codex' && backend === 'ollama' ? 'ollama' : harness;
}

function normalizeLaunchTarget(value = {}, fallbackRuntime = 'codex') {
  const source = value && typeof value === 'object' ? value : {};
  const legacyRuntime = normalizeLegacyRuntime(source.runtime, fallbackRuntime);
  const inferredHarness = legacyRuntime === 'ollama' ? 'codex' : legacyRuntime;
  const inferredBackend = legacyRuntime === 'ollama' ? 'ollama' : 'default';
  const harness = String(source.harness || inferredHarness).trim().toLowerCase();
  const backend = String(source.backend || inferredBackend).trim().toLowerCase();

  if (!SUPPORTED_HARNESSES.has(harness)) {
    throw new Error(`unsupported agent harness: ${harness || '(empty)'}`);
  }
  if (!SUPPORTED_BACKENDS.has(backend)) {
    throw new Error(`unsupported model runtime: ${backend || '(empty)'}`);
  }
  if (backend === 'ollama' && harness !== 'codex') {
    throw new Error(`${harness} does not support the Ollama model runtime`);
  }

  return {
    harness,
    backend,
    runtime: legacyRuntimeFor(harness, backend),
  };
}

function thinkLevelsFor(value = {}) {
  const { harness, backend } = normalizeLaunchTarget(value);
  if (backend === 'ollama') return OLLAMA_THINK_LEVELS;
  if (harness === 'agy') return AGY_THINK_LEVELS;
  if (harness === 'claude') return CLAUDE_THINK_LEVELS;
  return CODEX_THINK_LEVELS;
}

function normalizeThink(value, target = {}) {
  if (value === undefined || value === null || value === '') return '';
  let think = typeof value === 'boolean'
    ? (value ? 'high' : 'none')
    : String(value).trim().toLowerCase();
  if (['1', 'true', 'yes', 'on'].includes(think)) think = 'high';
  if (['0', 'false', 'no', 'off'].includes(think)) think = 'none';
  const supported = thinkLevelsFor(target);
  if (!supported.includes(think)) {
    const { harness, backend } = normalizeLaunchTarget(target);
    throw new Error(
      `unsupported Think level for ${harness}/${backend}: ${think || '(empty)'}; expected ${supported.join(', ')}`,
    );
  }
  return think;
}

function modelReasoningConfig(think) {
  return think ? `model_reasoning_effort=${JSON.stringify(think)}` : '';
}

function defaultClaudeSafetyArgs(environment = process.env) {
  if (/^(1|true|yes|on)$/i.test(String(environment.NOTTY_COLLAB_UNSANDBOXED || ''))) {
    return ['--dangerously-skip-permissions'];
  }
  return ['--permission-mode', 'acceptEdits'];
}

function mcpTransportFor(target = {}) {
  return normalizeLaunchTarget(target).harness === 'agy' ? 'sse' : 'http';
}

function buildClaudeMcpConfig(mcpUrl, serverName) {
  return JSON.stringify({
    mcpServers: {
      [serverName]: {
        type: 'http',
        url: String(mcpUrl),
      },
    },
  });
}

function buildLaunchCommand(agent, options = {}) {
  const target = normalizeLaunchTarget(agent);
  const think = normalizeThink(agent.think, target);
  const model = String(agent.model || '').trim();
  const prompt = String(options.prompt || '');
  const resumeSessionId = String(options.resumeSessionId || '').trim();
  const newSessionId = String(options.newSessionId || '').trim();

  if (target.backend === 'ollama' && !model) {
    throw new Error('Ollama model runtime requires a model');
  }

  if (target.harness === 'agy') {
    return [
      options.agyBin || 'agy',
      ...(resumeSessionId ? ['--conversation', resumeSessionId] : []),
      ...(model ? ['--model', model] : []),
      ...(think ? ['--effort', think] : []),
      ...(options.agyArgs || []),
      '--prompt-interactive', prompt,
    ];
  }

  if (target.harness === 'claude') {
    return [
      options.claudeBin || 'claude',
      ...(model ? ['--model', model] : []),
      ...(think ? ['--effort', think] : []),
      '--mcp-config', buildClaudeMcpConfig(options.mcpUrl, options.mcpServerName),
      ...(options.claudeArgs || defaultClaudeSafetyArgs(options.environment)),
      ...(agent.identity ? ['--name', String(agent.identity)] : []),
      ...(resumeSessionId
        ? ['--resume', resumeSessionId]
        : newSessionId
          ? ['--session-id', newSessionId, prompt]
          : [prompt]),
    ];
  }

  const codexTail = [
    '-c', `mcp_servers.${options.mcpServerName}.url=${JSON.stringify(options.mcpUrl)}`,
    ...(think ? ['-c', modelReasoningConfig(think)] : []),
    ...(options.codexArgs || []),
    ...(resumeSessionId ? ['resume', resumeSessionId] : [prompt]),
  ];
  if (target.backend === 'ollama') {
    const providerArgs = Array.isArray(options.ollamaProviderArgs)
      ? options.ollamaProviderArgs.map(String)
      : [];
    if (!providerArgs.length) {
      throw new Error('Ollama model runtime requires prepared Codex provider arguments');
    }
    return buildOllamaCodexRelayCommand([
      options.codexBin || 'codex',
      ...providerArgs,
      ...codexTail,
    ], {
      nodeBin: options.nodeBin,
      relayPath: options.ollamaRelayPath,
    });
  }
  return [
    options.codexBin || 'codex',
    ...(model ? ['-m', model] : []),
    ...codexTail,
  ];
}

module.exports = {
  AGY_THINK_LEVELS,
  CLAUDE_THINK_LEVELS,
  CODEX_THINK_LEVELS,
  OLLAMA_THINK_LEVELS,
  SUPPORTED_BACKENDS,
  SUPPORTED_HARNESSES,
  buildClaudeMcpConfig,
  buildLaunchCommand,
  defaultClaudeSafetyArgs,
  legacyRuntimeFor,
  mcpTransportFor,
  modelReasoningConfig,
  normalizeLaunchTarget,
  normalizeLegacyRuntime,
  normalizeThink,
  thinkLevelsFor,
};
