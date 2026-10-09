'use strict';

const crypto = require('crypto');
const { timeoutPolicy, enforceAgentDeadline } = require('./timeout.cjs');
const childProcess = require('child_process');
const fs = require('fs');
const os = require('os');
const path = require('path');
const readline = require('readline');
const {
  childEnvironmentAssignments,
  sanitizeChildEnvironment,
} = require('../childEnvironment.cjs');

const { atomicWriteJson, parseTemplateAgents } = require('./config.cjs');
const { createResumeStore } = require('./resume-store.cjs');
const {
  buildLaunchCommand,
  defaultClaudeSafetyArgs,
  legacyRuntimeFor,
  mcpTransportFor,
  modelReasoningConfig,
  normalizeLaunchTarget,
  normalizeLegacyRuntime,
  normalizeThink,
} = require('./launch.cjs');
const { classifyAgentHealth, normalizeHealthOverride } = require('./health.cjs');
const {
  prepareOllamaCodexProvider,
  removeOllamaModelCatalog,
  requireInstalledOllamaModel,
} = require('./ollama.cjs');

const QUICK_COMMAND_TIMEOUT_MS = 5000;
const COLLAB_SESSION_MCP_SERVER = 'notty_collab_session';
const SUPPORTED_AGENT_RUNTIMES = new Set(['codex', 'agy', 'ollama', 'claude']);
const CODEX_PERMISSION_MODES = Object.freeze({
  SANDBOXED: 'workspace-write',
  BYPASS: 'danger-full-access',
});
const CODEX_WORKSPACE_SAFETY_ARGS = Object.freeze([
  '--sandbox',
  'workspace-write',
  '--ask-for-approval',
  'on-request',
]);
const CODEX_BYPASS_SAFETY_ARGS = Object.freeze([
  '--dangerously-bypass-approvals-and-sandbox',
]);

function isTruthy(value) {
  return /^(1|true|yes|on)$/i.test(String(value || ''));
}

function normalizeCodexPermissionMode(value, fallback = '') {
  const mode = String(value || fallback).trim().toLowerCase();
  if (mode === CODEX_PERMISSION_MODES.SANDBOXED || mode === 'sandboxed') {
    return CODEX_PERMISSION_MODES.SANDBOXED;
  }
  if (
    mode === CODEX_PERMISSION_MODES.BYPASS
    || mode === 'bypass'
    || mode === 'full-access'
    || mode === 'full'
  ) {
    return CODEX_PERMISSION_MODES.BYPASS;
  }
  throw new Error(
    `unsupported Codex permission mode: ${mode || '(empty)'}; expected workspace-write or danger-full-access`,
  );
}

function defaultCodexPermissionMode(environment = process.env) {
  if (Object.hasOwn(environment, 'NOTTY_COLLAB_UNSANDBOXED')) {
    return isTruthy(environment.NOTTY_COLLAB_UNSANDBOXED)
      ? CODEX_PERMISSION_MODES.BYPASS
      : CODEX_PERMISSION_MODES.SANDBOXED;
  }
  return isTruthy(environment.DOCKER_CONTAINER)
    ? CODEX_PERMISSION_MODES.BYPASS
    : CODEX_PERMISSION_MODES.SANDBOXED;
}

function codexSafetyArgsForPermissionMode(mode) {
  return normalizeCodexPermissionMode(mode) === CODEX_PERMISSION_MODES.BYPASS
    ? [...CODEX_BYPASS_SAFETY_ARGS]
    : [...CODEX_WORKSPACE_SAFETY_ARGS];
}

function codexPermissionModeFromArgs(args, fallback = '') {
  const values = Array.isArray(args) ? args.map(String) : [];
  if (values.includes('--dangerously-bypass-approvals-and-sandbox') || values.includes('--yolo')) {
    return CODEX_PERMISSION_MODES.BYPASS;
  }
  const inlineSandbox = values.find((value) => value.startsWith('--sandbox='));
  if (inlineSandbox) {
    return inlineSandbox.slice('--sandbox='.length) === CODEX_PERMISSION_MODES.BYPASS
      ? CODEX_PERMISSION_MODES.BYPASS
      : CODEX_PERMISSION_MODES.SANDBOXED;
  }
  const sandboxIndex = values.findIndex((value) => value === '--sandbox' || value === '-s');
  if (sandboxIndex !== -1 && values[sandboxIndex + 1] === CODEX_PERMISSION_MODES.BYPASS) {
    return CODEX_PERMISSION_MODES.BYPASS;
  }
  if (sandboxIndex !== -1) {
    return CODEX_PERMISSION_MODES.SANDBOXED;
  }
  return fallback ? normalizeCodexPermissionMode(fallback) : '';
}

function codexArgsWithPermissionMode(args, mode) {
  const source = Array.isArray(args) ? args.map(String) : [];
  const filtered = [];
  for (let index = 0; index < source.length; index += 1) {
    const value = source[index];
    if (value === '--dangerously-bypass-approvals-and-sandbox' || value === '--yolo') {
      continue;
    }
    if (value.startsWith('--sandbox=') || value.startsWith('--ask-for-approval=')) {
      continue;
    }
    if (
      value === '--sandbox'
      || value === '-s'
      || value === '--ask-for-approval'
      || value === '-a'
    ) {
      index += 1;
      continue;
    }
    filtered.push(value);
  }
  return [...filtered, ...codexSafetyArgsForPermissionMode(mode)];
}

function defaultCodexSafetyArgs(environment = process.env) {
  return codexSafetyArgsForPermissionMode(defaultCodexPermissionMode(environment));
}

function defaultAgySafetyArgs(environment = process.env) {
  if (isTruthy(environment.NOTTY_COLLAB_UNSANDBOXED)) {
    return ['--dangerously-skip-permissions'];
  }
  return ['--mode', 'accept-edits', '--sandbox'];
}

function normalizeAgentRuntime(value, fallback = 'codex') {
  return normalizeLegacyRuntime(value, fallback);
}

function normalizeAgentThink(value, runtime = 'codex') {
  const target = runtime && typeof runtime === 'object' ? runtime : { runtime };
  return normalizeThink(value, target);
}

function cleanToken(value, fallback = '') {
  const clean = String(value || '').trim().replace(/[^A-Za-z0-9._-]/g, '-').replace(/-+/g, '-');
  return clean || fallback;
}

function commandExists(command, args = ['--version'], environment = process.env) {
  const result = childProcess.spawnSync(command, args, {
    encoding: 'utf8',
    timeout: QUICK_COMMAND_TIMEOUT_MS,
    env: sanitizeChildEnvironment(environment),
  });
  if (result.error) {
    return { ok: false, error: result.error.message };
  }
  return {
    ok: result.status === 0,
    error: result.status === 0 ? '' : (result.stderr || result.stdout || `${command} exited ${result.status}`).trim(),
    stdout: String(result.stdout || ''),
    stderr: String(result.stderr || ''),
  };
}

function canonicalAgentLaunch(agent = {}) {
  return { ...agent, ...normalizeLaunchTarget(agent) };
}

function newPaneOutput(previousValue, currentValue) {
  const previous = String(previousValue || '');
  const current = String(currentValue || '');
  if (!previous) return current;
  if (current.startsWith(previous)) return current.slice(previous.length);
  const previousLines = previous.split('\n');
  const currentLines = current.split('\n');
  const maximum = Math.min(previousLines.length, currentLines.length);
  for (let overlap = maximum; overlap > 0; overlap -= 1) {
    if (
      previousLines.slice(-overlap).join('\n')
      === currentLines.slice(0, overlap).join('\n')
    ) {
      return currentLines.slice(overlap).join('\n');
    }
  }
  return current;
}

function selectCodexThreadId(threads, options = {}) {
  const cwd = path.resolve(String(options.cwd || process.cwd()));
  const prompt = String(options.prompt || '');
  const matches = (Array.isArray(threads) ? threads : []).filter((thread) => (
    thread
    && typeof thread.id === 'string'
    && path.resolve(String(thread.cwd || '.')) === cwd
    && String(thread.preview || '') === prompt
  ));
  matches.sort((left, right) => (
    Number(right.updatedAt || right.createdAt || 0) - Number(left.updatedAt || left.createdAt || 0)
  ));
  return matches[0]?.id || '';
}

function resolveCodexThreadId(options = {}) {
  const codexBin = String(options.codexBin || process.env.CODEX_BIN || 'codex');
  const cwd = path.resolve(String(options.cwd || process.cwd()));
  const prompt = String(options.prompt || '');
  const timeoutMs = Number(options.timeoutMs || QUICK_COMMAND_TIMEOUT_MS);
  const pageLimit = 100;
  const maxPages = 25;

  if (!prompt) {
    return Promise.reject(new Error('cannot resolve a Codex thread without its initial prompt'));
  }

  return new Promise((resolve, reject) => {
    const child = childProcess.spawn(codexBin, ['app-server'], {
      cwd,
      env: sanitizeChildEnvironment(options.environment || process.env),
      stdio: ['pipe', 'pipe', 'pipe'],
    });
    const output = readline.createInterface({ input: child.stdout });
    let settled = false;
    let initialized = false;
    let listRequestId = 10;
    let pageCount = 0;
    let stderr = '';
    let candidateId = '';
    let outputBytes = 0;

    const finish = (error, threadId = '') => {
      if (settled) {
        return;
      }
      settled = true;
      clearTimeout(timer);
      output.close();
      child.stdin.end();
      if (child.exitCode === null && !child.killed) {
        child.kill('SIGTERM');
        const killTimer = setTimeout(() => { if (child.exitCode === null) child.kill('SIGKILL'); }, 1000);
        killTimer.unref?.();
      }
      if (error) {
        reject(error);
      } else {
        resolve(threadId);
      }
    };

    const send = (message) => {
      if (!settled && child.stdin.writable) {
        child.stdin.write(`${JSON.stringify(message)}\n`);
      }
    };

    const requestPage = (cursor = null) => {
      listRequestId += 1;
      pageCount += 1;
      send({
        method: 'thread/list',
        id: listRequestId,
        params: {
          cwd,
          cursor,
          limit: pageLimit,
          sourceKinds: ['cli'],
          sortKey: 'updated_at',
          sortDirection: 'desc',
          useStateDbOnly: true,
        },
      });
    };

    const timer = setTimeout(() => {
      finish(new Error(`timed out resolving the Codex thread after ${timeoutMs}ms`));
    }, timeoutMs);

    child.stderr.on('data', (chunk) => {
      stderr = `${stderr}${chunk.toString('utf8')}`.slice(-4096);
    });
    child.stdout.on('data', (chunk) => {
      outputBytes += chunk.length;
      if (outputBytes > 16 * 1024 * 1024) finish(new Error('Codex thread lookup exceeded its response limit'));
    });
    child.stdin.on('error', () => {
      // The app-server may close stdin while finish() is terminating it.
    });
    child.once('error', (error) => finish(error));
    child.once('exit', (code, signal) => {
      if (!settled) {
        const detail = stderr.trim();
        finish(new Error(
          detail
          || `Codex app-server exited before listing threads (${signal ? `signal=${signal}` : `code=${code}`})`,
        ));
      }
    });
    output.on('line', (line) => {
      if (settled) return;
      let message;
      try {
        message = JSON.parse(line);
      } catch {
        return;
      }
      if (message.id === 1) {
        if (message.error) {
          finish(new Error(message.error.message || 'Codex app-server initialization failed'));
          return;
        }
        initialized = true;
        send({ method: 'initialized', params: {} });
        if (options.threadId) {
          candidateId = options.threadId;
          send({ method: 'thread/read', id: 2, params: { threadId: candidateId, includeTurns: true } });
        } else requestPage();
        return;
      }
      if (initialized && message.id === 2) {
        const thread = message.result?.thread;
        const firstUser = thread?.turns?.flatMap((turn) => turn.items || []).find((item) => item.type === 'userMessage');
        const firstText = firstUser?.content?.filter((part) => part.type === 'text').map((part) => part.text).join('\n') || '';
        if (message.error || !thread || thread.id !== candidateId || path.resolve(thread.cwd || '.') !== cwd
          || !(options.marker ? firstText.startsWith(`Notty launch ${options.marker}\n`) : firstText === prompt)) {
          finish(new Error('Saved Codex thread is missing or does not match this workspace and role launch'));
        } else finish(null, candidateId);
        return;
      }
      if (!initialized || message.id !== listRequestId) {
        return;
      }
      if (message.error) {
        finish(new Error(message.error.message || 'Codex thread listing failed'));
        return;
      }
      const threads = message.result?.data || [];
      const matches = options.marker ? threads.filter((thread) => path.resolve(thread.cwd || '.') === cwd
        && String(thread.preview || '').startsWith(`Notty launch ${options.marker}`)) : [];
      if (matches.length > 1) { finish(new Error('Ambiguous Codex launch correlation')); return; }
      const threadId = options.marker ? matches[0]?.id : selectCodexThreadId(threads, { cwd, prompt });
      if (threadId) {
        if (options.marker) {
          candidateId = threadId;
          send({ method: 'thread/read', id: 2, params: { threadId, includeTurns: true } });
        } else finish(null, threadId);
        return;
      }
      const nextCursor = message.result?.nextCursor;
      if (nextCursor && pageCount < maxPages) {
        requestPage(nextCursor);
        return;
      }
      finish(null, '');
    });

    send({
      method: 'initialize',
      id: 1,
      params: {
        clientInfo: {
          name: 'notty_collab',
          title: 'Notty Collab',
          version: '1.0.0',
        },
      },
    });
  });
}

function tmuxSessionExists(target) {
  return childProcess.spawnSync('tmux', ['has-session', '-t', target], {
    stdio: 'ignore',
    timeout: QUICK_COMMAND_TIMEOUT_MS,
  }).status === 0;
}

function setTmuxSessionOwner(target, sessionId) {
  const result = childProcess.spawnSync(
    'tmux',
    ['set-option', '-t', target, '@notty_collab_session', sessionId],
    { encoding: 'utf8', timeout: QUICK_COMMAND_TIMEOUT_MS },
  );
  if (result.error) {
    throw result.error;
  }
  if (result.status !== 0) {
    throw new Error((result.stderr || result.stdout || 'unable to mark tmux session ownership').trim());
  }
}

function tmuxSessionOwnedBy(target, sessionId) {
  const result = childProcess.spawnSync(
    'tmux',
    ['display-message', '-p', '-t', target, '#{@notty_collab_session}'],
    { encoding: 'utf8', timeout: QUICK_COMMAND_TIMEOUT_MS },
  );
  return result.status === 0 && result.stdout.trim() === sessionId;
}

function killTmuxSession(target) {
  return childProcess.spawnSync('tmux', ['kill-session', '-t', target], {
    encoding: 'utf8',
    timeout: QUICK_COMMAND_TIMEOUT_MS,
  });
}

function captureTmuxPane(target) {
  const result = childProcess.spawnSync(
    'tmux',
    ['capture-pane', '-p', '-t', target, '-S', '-80'],
    { encoding: 'utf8', timeout: QUICK_COMMAND_TIMEOUT_MS },
  );
  return result.status === 0 ? String(result.stdout || '') : '';
}

function createLayoutSnapshot(layoutId, layout) {
  return {
    ...(layout && typeof layout === 'object' ? structuredClone(layout) : {}),
    id: String(layoutId || 'grid'),
  };
}

function resolveSessionOperator(options = {}, environment = process.env) {
  return cleanToken(options.operator || environment.NOTTY_COLLAB_OPERATOR || 'operator', 'operator');
}

function validateNoshProfiles(requiredProfiles, environment = process.env) {
  const required = Array.isArray(requiredProfiles) ? requiredProfiles : [];
  if (!Object.hasOwn(environment, 'NOTTY_NOSH_PROFILES')) {
    return required.length > 0 ? ['Active Nosh profiles are unavailable; requirements were not verified.'] : [];
  }

  const activeText = String(environment.NOTTY_NOSH_PROFILES || '').trim();
  const active = new Set(activeText.split(/[,+\s]+/).filter(Boolean));
  const missing = required.filter((profile) => !active.has(profile));
  if (missing.length > 0) {
    const error = new Error(`missing required Nosh profiles: ${missing.join(', ')}`);
    error.statusCode = 422;
    throw error;
  }
  return [];
}

function resolveLaunchChoices(template, prompts, coordinatorMode, choices) {
  const roster = resolveLaunchRoster(template, prompts, coordinatorMode);
  if (choices === undefined) return { ...roster, agents: roster.agents.map((agent) => ({ ...agent, ...timeoutPolicy() })) };
  const fields = ['harness', 'backend', 'model', 'think'];
  if (!Array.isArray(choices) || choices.length !== roster.agents.length
    || choices.some((choice) => !choice || typeof choice !== 'object'
      || Array.isArray(choice) || Object.keys(choice).some((key) => ![...fields, 'timeoutSeconds', 'terminateOnExpire'].includes(key))
      || fields.some((key) => typeof choice[key] !== 'string')
      || !choice.model.trim())) {
    const error = new Error('agentChoices must contain one agent, backend, model, and Think selection per launch row');
    error.statusCode = 422;
    throw error;
  }
  const policies = choices.map(timeoutPolicy);
  const resolved = resolveLaunchRoster({
    ...template,
    coordinatorSpec: null,
    agents: roster.agents.map((agent, index) => ({ prompt: agent.prompt,
      ...Object.fromEntries(fields.map((field) => [field, choices[index][field]])) })),
  }, prompts, coordinatorMode);
  return { ...resolved, agents: resolved.agents.map((agent, index) => ({ ...agent, ...policies[index] })) };
}

function resolveLaunchRoster(template, prompts, coordinatorMode) {
  if (coordinatorMode !== 'human' && coordinatorMode !== 'agent') {
    const error = new Error('coordinatorMode must be human or agent');
    error.statusCode = 422;
    throw error;
  }

  let specs = template.agents.slice();
  let agents = parseTemplateAgents({ agents: specs }, prompts);

  if (coordinatorMode === 'human') {
    specs = agents
      .filter((agent) => !agent.coordinatorCapable)
      .map((agent) => agent.spec);
    if (specs.length === 0) {
      const error = new Error('human coordinator mode requires at least one worker agent');
      error.statusCode = 422;
      throw error;
    }
    agents = parseTemplateAgents({ agents: specs }, prompts);
  } else {
    const coordinators = agents.filter((agent) => agent.coordinatorCapable);
    if (coordinators.length === 0) {
      if (!template.coordinatorSpec) {
        const error = new Error('agent coordinator mode requires one coordinator-capable agent');
        error.statusCode = 422;
        throw error;
      }
      specs.unshift(template.coordinatorSpec);
      agents = parseTemplateAgents({ agents: specs }, prompts);
    }
    if (agents.filter((agent) => agent.coordinatorCapable).length !== 1) {
      const error = new Error('agent coordinator mode requires exactly one coordinator-capable agent');
      error.statusCode = 422;
      throw error;
    }
  }

  return { specs, agents };
}

function resolveAgentTmuxState(agent, options = {}) {
  const recovered = Boolean(options.recovered);
  const tmuxPresent = Boolean(options.tmuxPresent);
  const tmuxOwned = recovered ? null : tmuxPresent && Boolean(options.tmuxOwned);
  const tmuxAlive = recovered ? tmuxPresent : tmuxOwned;
  const ownershipLost = !recovered && tmuxPresent && !tmuxOwned;
  const launchFailed = agent.status === 'failed';
  const stopFailed = agent.status === 'stop-failed';

  return {
    ...agent,
    status: ownershipLost
      ? 'ownership-lost'
      : stopFailed && tmuxAlive
          ? 'stop-failed'
      : launchFailed && !tmuxAlive
          ? 'failed'
          : tmuxAlive
              ? 'running'
              : 'stopped',
    tmuxPresent,
    tmuxOwned,
    tmuxAlive,
    ownershipLost,
    error: ownershipLost
      ? `tmux target is owned by another session: ${agent.tmuxTarget}`
      : agent.error || '',
  };
}

function agentRuntimeSignature(agent) {
  return JSON.stringify({
    status: agent.status,
    permissionMode: agent.permissionMode || '',
    runtimeSessionId: agent.runtimeSessionId || '',
    tmuxPresent: agent.tmuxPresent,
    tmuxOwned: agent.tmuxOwned,
    tmuxAlive: agent.tmuxAlive,
    ownershipLost: agent.ownershipLost,
    registered: agent.registered,
    mcpStatus: agent.mcpStatus,
    pending: agent.pending || null,
    health: agent.health || null,
    error: agent.error || '',
  });
}

function buildAgentPrompt(agent, options) {
  const prompt = options.prompts[agent.prompt] || {};
  const bypass = agent.permissionMode === CODEX_PERMISSION_MODES.BYPASS
    || agent.permissionMode === 'danger-full-access'
    || (agent.harness !== 'codex' && isTruthy(process.env.NOTTY_COLLAB_UNSANDBOXED));
  const lines = [
    agent.resumeMarker ? `Notty launch ${agent.resumeMarker}` : '',
    'STARTUP CONTRACT: This is initialization, not a work assignment. Do one bounded startup check, then wait quietly.',
    `You are the ${agent.role} agent (${agent.identity}) for collaboration session ${options.sessionId}.`,
    `Use the ${COLLAB_SESSION_MCP_SERVER} MCP service at ${options.mcpUrl}.`,
    'Use native MCP tool discovery. If this service is unavailable, report one clear connection failure and stop. Do not invent endpoints, debug the service, inspect its source, or poll in a loop.',
    'Do not explore the repository, run tests, or perform your role’s work until an explicit assignment arrives. Role guidance below describes how to handle assignments, not work to start now.',
    'Read channel history with read_messages, not tmux_read. Channels are not tmux panes; tmux tools accept exact agent identities.',
    `Set your nickname to ${agent.identity}, coordinate in ${options.channel}, set_status(\"busy\") while working, set_status(\"idle\") when waiting or done, and call claim_pending() once before waiting.`,
    'If no assignment is pending, end your turn silently. Do not send ready/idle acknowledgements or repeatedly claim work. A later explicit nudge may request another single claim.',
    `Work only inside ${options.workspaceRoot} and follow its AGENTS.md instructions.`,
    'Treat a denied action as a boundary, not as the conclusion of the task. Check whether the requested outcome is already complete, then try safe in-scope alternatives that preserve the boundary.',
    'Conclude with either “Task complete — <one-sentence evidence>” or “Human help needed — <one-sentence reason>. Next: <one concrete human action>”. A raw status code may be supporting detail, never the conclusion.',
    bypass ? '' : 'For approval or sandbox barriers, do not repeat the rejected operation, weaken containment, or broaden your own authority.',
    String(prompt.instructions || '').trim(),
  ].filter(Boolean);
  if (agent.coordinatorCapable && options.coordinatorMode === 'agent' && options.task) {
    lines.push('', 'Request to coordinate:', options.task);
  }
  return lines.join('\n');
}

function launchTmuxAgent(agent, options) {
  const target = normalizeLaunchTarget(agent);
  const think = normalizeAgentThink(agent.think, target);
  if (options.spawnOtp !== undefined && options.spawnOtp !== null && options.spawnOtp !== '') {
    throw new Error(
      'Agent OTP delivery is not supported; enter a spawn OTP directly in each terminal-spawn request.',
    );
  }
  const resumeSessionId = String(options.resumeSessionId || '').trim();
  const envArgs = [
    `MYID=${agent.identity}`,
    `COLLAB_AGENT_ID=${agent.identity}`,
    `COLLAB_CHANNEL=${options.channel}`,
    `COLLAB_MCP_URL=${options.mcpUrl}`,
    `COLLAB_MCP_SERVER=${COLLAB_SESSION_MCP_SERVER}`,
    `COLLAB_ROLE=${agent.role}`,
    `COLLAB_HARNESS=${target.harness}`,
    `COLLAB_BACKEND=${target.backend}`,
    `COLLAB_RUNTIME=${target.runtime}`,
    `COLLAB_MODEL=${agent.model || ''}`,
    `COLLAB_THINK=${think}`,
    `COLLAB_SESSION_ID=${options.sessionId}`,
  ];
  const prompt = agent.initialPrompt || buildAgentPrompt(agent, options);
  if (target.backend === 'ollama' && !String(agent.model || '').trim()) {
    throw new Error('Ollama model runtime requires a model');
  }
  let ollamaProvider = null;
  let tmuxStarted = false;
  try {
    ollamaProvider = target.backend === 'ollama'
      ? options.ollamaProvider || prepareOllamaCodexProvider({
          model: agent.model,
          endpoint: options.ollamaEndpoint,
          environment: options.environment,
          spawnSync: options.ollamaSpawnSync,
          curlBin: options.curlBin,
          timeoutMs: options.ollamaTimeoutMs,
          runtimeDir: options.ollamaRuntimeDir,
          isolationKey: options.ollamaIsolationKey
            || `${options.sessionId || 'standalone'}:${agent.identity || agent.id || agent.model}`,
        })
      : null;
    const runtimeCommand = buildLaunchCommand({ ...agent, ...target, think }, {
      ...options,
      prompt,
      resumeSessionId,
      newSessionId: options.newSessionId,
      mcpServerName: COLLAB_SESSION_MCP_SERVER,
      codexArgs: options.codexArgs || defaultCodexSafetyArgs(options.environment),
      agyArgs: options.agyArgs || defaultAgySafetyArgs(options.environment),
      claudeArgs: options.claudeArgs || defaultClaudeSafetyArgs(options.environment),
      ollamaProviderArgs: ollamaProvider?.args,
    });
    const command = [
      'new-session',
      '-d',
      '-c', options.workspaceRoot,
      '-s', agent.tmuxTarget,
      '--',
      'env',
      '-i',
      ...childEnvironmentAssignments(options.environment),
      ...envArgs,
      ...runtimeCommand,
    ];
    const result = childProcess.spawnSync('tmux', command, {
      encoding: 'utf8',
      env: sanitizeChildEnvironment(options.environment),
    });
    if (result.error) {
      throw result.error;
    }
    if (result.status !== 0) {
      throw new Error((result.stderr || result.stdout || `tmux new-session failed (${result.status})`).trim());
    }
    tmuxStarted = true;
    if (!tmuxSessionExists(agent.tmuxTarget)) {
      throw new Error(`tmux session did not stay alive: ${agent.tmuxTarget}`);
    }
    try {
      setTmuxSessionOwner(agent.tmuxTarget, options.sessionId);
    } catch (error) {
      childProcess.spawnSync('tmux', ['kill-session', '-t', agent.tmuxTarget], {
        stdio: 'ignore',
        timeout: QUICK_COMMAND_TIMEOUT_MS,
      });
      throw error;
    }
  } catch (error) {
    let catalogPath = ollamaProvider?.catalogPath || '';
    if (catalogPath && !tmuxStarted && !tmuxSessionExists(agent.tmuxTarget)) {
      try {
        const removeCatalog = options.removeOllamaModelCatalog || removeOllamaModelCatalog;
        removeCatalog(catalogPath, {
          runtimeDir: options.ollamaRuntimeDir,
          environment: options.environment,
        });
        catalogPath = '';
      } catch (cleanupError) {
        error.ollamaCatalogCleanupError = cleanupError;
      }
    }
    if (catalogPath) error.ollamaCatalogPath = catalogPath;
    throw error;
  }
}

function statePathForWorkspace(options = {}) {
  const stateHome = path.resolve(options.stateHome || process.env.XDG_STATE_HOME || path.join(os.homedir(), '.local', 'state'));
  const workspaceRoot = path.resolve(options.workspaceRoot || process.cwd());
  const key = crypto.createHash('sha256').update(workspaceRoot).digest('hex').slice(0, 20);
  return path.join(stateHome, 'notty', 'collab', `${key}.json`);
}

function createSessionManager(options = {}) {
  const appRoot = path.resolve(options.appRoot || path.join(__dirname, '..', '..'));
  const workspaceRoot = fs.realpathSync(options.workspaceRoot || process.env.NOTTY_WORKDIR || process.cwd());
  const manifestPath = path.resolve(options.manifestPath || statePathForWorkspace({
    stateHome: options.stateHome,
    workspaceRoot,
  }));
  const configStore = options.configStore;
  const eventHub = options.eventHub;
  const environment = sanitizeChildEnvironment(options.environment || process.env);
  const mcpUrl = String(options.mcpUrl || 'http://127.0.0.1:1337/mcp');
  const sseUrl = String(options.sseUrl || 'http://127.0.0.1:1337/sse');
  const codexBin = String(options.codexBin || environment.CODEX_BIN || 'codex');
  const agyBin = String(options.agyBin || environment.AGY_BIN || 'agy');
  const claudeBin = String(options.claudeBin || environment.CLAUDE_BIN || 'claude');
  const curlBin = String(options.curlBin || environment.CURL_BIN || 'curl');
  const ollamaEndpoint = String(options.ollamaEndpoint || environment.OLLAMA_HOST || '');
  const ollamaSpawnSync = options.ollamaSpawnSync || childProcess.spawnSync;
  const ollamaRuntimeDir = String(options.ollamaRuntimeDir || environment.XDG_RUNTIME_DIR || '');
  const ollamaTimeoutMs = Number(options.ollamaTimeoutMs || QUICK_COMMAND_TIMEOUT_MS);
  const codexArgs = Array.isArray(options.codexArgs)
    ? options.codexArgs.map(String)
    : defaultCodexSafetyArgs(environment);
  const defaultPermissionMode = codexPermissionModeFromArgs(
    codexArgs,
    defaultCodexPermissionMode(environment),
  );
  const agyArgs = Array.isArray(options.agyArgs)
    ? options.agyArgs.map(String)
    : defaultAgySafetyArgs(environment);
  const claudeArgs = Array.isArray(options.claudeArgs)
    ? options.claudeArgs.map(String)
    : defaultClaudeSafetyArgs(environment);
  const operator = resolveSessionOperator(options, environment);
  const hasTmuxSession = typeof options.tmuxSessionExists === 'function'
    ? options.tmuxSessionExists
    : tmuxSessionExists;
  const ownsTmuxSession = typeof options.tmuxSessionOwnedBy === 'function'
    ? options.tmuxSessionOwnedBy
    : tmuxSessionOwnedBy;
  const stopTmuxSession = typeof options.killTmuxSession === 'function'
    ? options.killTmuxSession
    : killTmuxSession;
  const readAgentOutput = typeof options.readAgentOutput === 'function'
    ? options.readAgentOutput
    : captureTmuxPane;
  const healthScanIntervalMs = Number(options.healthScanIntervalMs || 10_000);
  const healthScanTimes = new Map();
  const healthOutput = new Map();
  const describeAgent = typeof options.describeAgent === 'function' ? options.describeAgent : () => null;
  const addManagedAgent = typeof options.addManagedAgent === 'function' ? options.addManagedAgent : () => {};
  const removeManagedAgent = typeof options.removeManagedAgent === 'function' ? options.removeManagedAgent : () => {};
  const removeCatalog = typeof options.removeOllamaModelCatalog === 'function'
    ? options.removeOllamaModelCatalog
    : removeOllamaModelCatalog;
  const clearAgentRuntime = typeof options.clearAgentRuntime === 'function' ? options.clearAgentRuntime : () => {};
  const listLegacyManagedAgents = typeof options.listLegacyManagedAgents === 'function' ? options.listLegacyManagedAgents : () => [];
  const postMessage = typeof options.postMessage === 'function' ? options.postMessage : () => null;
  const findCodexThreadId = typeof options.resolveCodexThreadId === 'function'
    ? options.resolveCodexThreadId
    : resolveCodexThreadId;
  const resumeStore = createResumeStore(workspaceRoot);
  let taskLaunchPending = false;

  function permissionModeForAgent(agent) {
    const { harness } = normalizeLaunchTarget(agent);
    if (harness !== 'codex') {
      return '';
    }
    return normalizeCodexPermissionMode(agent.permissionMode || defaultPermissionMode);
  }

  function codexArgsForAgent(agent) {
    return codexArgsWithPermissionMode(codexArgs, permissionModeForAgent(agent));
  }

  function mcpUrlForAgent(agent) {
    return mcpTransportFor(agent) === 'sse' ? sseUrl : mcpUrl;
  }

  function managedMetadataForAgent(agent, sessionId) {
    const target = normalizeLaunchTarget(agent);
    return {
      role: agent.role,
      harness: target.harness,
      backend: target.backend,
      runtime: target.runtime,
      model: agent.model,
      think: agent.think,
      sessionId,
      runtimeSessionId: agent.runtimeSessionId,
      permissionMode: agent.permissionMode,
    };
  }

  function healthAfterFailure(agent, error) {
    if (agent.health?.source === 'operator') return agent.health;
    return classifyAgentHealth(error?.message || String(error || ''), {
      source: 'automatic',
    }) || agent.health || null;
  }

  function emit(type, data) {
    if (eventHub) {
      eventHub.emit(type, data);
    }
  }

  function readManifest() {
    if (!fs.existsSync(manifestPath)) {
      return null;
    }
    try {
      const parsed = JSON.parse(fs.readFileSync(manifestPath, 'utf8'));
      if (!parsed || parsed.workspaceRoot !== workspaceRoot || !Array.isArray(parsed.agents)) {
        return null;
      }
      return {
        ...parsed,
        agents: parsed.agents.map(canonicalAgentLaunch),
      };
    } catch (_error) {
      return null;
    }
  }

  function saveManifest(session) {
    atomicWriteJson(manifestPath, session);
    return session;
  }

  function deleteManifest() {
    if (fs.existsSync(manifestPath)) {
      fs.unlinkSync(manifestPath);
    }
  }

  function refreshAgent(agent, session) {
    const tmuxPresent = hasTmuxSession(agent.tmuxTarget);
    const tmuxOwned = !session.recovered
      && tmuxPresent
      && ownsTmuxSession(agent.tmuxTarget, session.id);
    const live = describeAgent(agent.identity) || {};
    let health = agent.health || null;
    const now = Date.now();
    if (
      tmuxPresent
      && health?.source !== 'operator'
      && now - (healthScanTimes.get(agent.identity) || 0) >= healthScanIntervalMs
    ) {
      healthScanTimes.set(agent.identity, now);
      const output = String(readAgentOutput(agent.tmuxTarget) || '');
      if (output && output !== healthOutput.get(agent.identity)) {
        const recentOutput = newPaneOutput(healthOutput.get(agent.identity), output);
        healthOutput.set(agent.identity, output);
        const classified = classifyAgentHealth(recentOutput, { source: 'automatic', now });
        health = classified || (health?.source === 'automatic' ? null : health);
      }
    }
    return {
      ...resolveAgentTmuxState(agent, {
        recovered: session.recovered,
        tmuxPresent,
        tmuxOwned,
      }),
      permissionMode: permissionModeForAgent(agent),
      runtimeSessionId: String(agent.runtimeSessionId || ''),
      registered: Boolean(live.registered),
      mcpStatus: live.registered ? String(live.status || 'idle') : 'unregistered',
      pending: live.pending || { directCount: 0, channels: [], updatedAt: '' },
      health,
    };
  }

  function reconcile(session, persist = true) {
    if (!session) {
      return null;
    }
    const agents = session.agents.map((agent) => refreshAgent(enforceAgentDeadline(agent, session, {
      present: hasTmuxSession, owned: ownsTmuxSession, stop: stopTmuxSession,
      clear: (identity) => { removeManagedAgent(identity); clearAgentRuntime(identity); },
    }), session));
    const running = agents.filter((agent) => agent.tmuxAlive).length;
    const failed = agents.filter((agent) => ['failed', 'stopped', 'stop-failed', 'ownership-lost'].includes(agent.status)).length;
    let status = session.status;
    if (failed > 0 && running > 0) {
      status = 'degraded';
    } else if (running === agents.length && agents.length > 0) {
      status = session.recovered ? 'recovered' : 'running';
    } else if (running === 0 && agents.length > 0) {
      status = agents.every((agent) => ['failed', 'ownership-lost'].includes(agent.status))
        ? 'failed'
        : 'degraded';
    }
    const runtimeChanged = status !== session.status || agents.some((agent, index) => (
      agentRuntimeSignature(agent) !== agentRuntimeSignature(session.agents[index] || {})
    ));
    if (!runtimeChanged) {
      return session;
    }

    const next = {
      ...session,
      status,
      updatedAt: new Date().toISOString(),
      agents,
    };
    if (persist) {
      saveManifest(next);
      agents.forEach((agent, index) => {
        if (agentRuntimeSignature(agent) !== agentRuntimeSignature(session.agents[index] || {})) {
          emit('agent.status', agent);
        }
      });
      emit('session.changed', next);
    }
    return next;
  }

  function layoutSnapshot(layoutId, resolvedLayouts = null) {
    let layouts = resolvedLayouts;
    if (!layouts && configStore) {
      layouts = configStore.load().resolved.layouts;
    }
    return createLayoutSnapshot(layoutId, layouts && layouts[layoutId]);
  }

  function importLegacySession() {
    const legacy = listLegacyManagedAgents().filter((row) => row && row.agent && row.target && hasTmuxSession(row.target));
    if (legacy.length === 0) {
      return null;
    }
    const now = new Date().toISOString();
    const session = {
      id: `legacy-${crypto.createHash('sha1').update(workspaceRoot).digest('hex').slice(0, 8)}`,
      templateId: null,
      templateSnapshot: null,
      coordinatorMode: 'human',
      task: '',
      channel: 'lobby',
      layout: 'grid',
      layoutSnapshot: layoutSnapshot('grid'),
      status: 'recovered',
      createdAt: now,
      updatedAt: now,
      workspaceRoot,
      recovered: true,
      warnings: ['Imported live legacy managed agents.'],
      agents: legacy.map((row) => {
        const runtime = SUPPORTED_AGENT_RUNTIMES.has(String(row.runtime || '').toLowerCase())
          ? String(row.runtime).toLowerCase()
          : 'codex';
        const target = normalizeLaunchTarget({
          runtime,
          harness: row.harness,
          backend: row.backend,
        });
        return {
          id: row.agent,
          identity: row.agent,
          prompt: row.agent,
          role: row.role || row.agent,
          ...target,
          model: row.model || '',
          think: row.think || '',
          permissionMode: target.harness === 'codex'
            ? normalizeCodexPermissionMode(row.permission_mode || defaultPermissionMode)
            : '',
          runtimeSessionId: String(row.runtime_session_id || ''),
          spec: '',
          tmuxTarget: row.target,
          status: 'running',
          tmuxPresent: true,
          tmuxOwned: null,
          tmuxAlive: true,
          ownershipLost: false,
          registered: Boolean(row.registered),
          mcpStatus: row.registered ? row.status || 'idle' : 'unregistered',
          pending: row.pending || { directCount: 0, channels: [], updatedAt: '' },
          startedAt: row.timestamp || now,
          error: '',
        };
      }),
    };
    saveManifest(session);
    return session;
  }

  function getSession() {
    const current = readManifest();
    if (current) {
      return reconcile(current);
    }
    return importLegacySession();
  }

  function validatePreflight(template, agents) {
    const invalid = (message) => {
      const error = new Error(message);
      error.statusCode = 422;
      throw error;
    };
    if (!fs.existsSync(workspaceRoot) || !fs.statSync(workspaceRoot).isDirectory()) {
      invalid(`workspace does not exist: ${workspaceRoot}`);
    }
    const tmux = commandExists('tmux', ['-V'], environment);
    if (!tmux.ok) {
      invalid(`tmux is unavailable: ${tmux.error}`);
    }
    const probes = new Map();
    const probe = (key, executable, args) => {
      if (!probes.has(key)) probes.set(key, commandExists(executable, args, environment));
      return probes.get(key);
    };
    for (const inputAgent of agents || []) {
      let target;
      try {
        target = normalizeLaunchTarget(inputAgent);
        normalizeAgentThink(inputAgent.think, target);
      } catch (error) {
        invalid(error.message || String(error));
      }
      if (target.backend === 'ollama') {
        const model = String(inputAgent.model || '').trim();
        if (!model) invalid('Ollama model runtime requires a model');
        try {
          requireInstalledOllamaModel(model, {
            endpoint: ollamaEndpoint,
            environment,
            spawnSync: ollamaSpawnSync,
            curlBin,
            timeoutMs: ollamaTimeoutMs,
          });
        } catch (error) {
          invalid(error.message || String(error));
        }
        const codex = probe('codex', codexBin, ['--version']);
        if (!codex.ok) invalid(`codex is unavailable for ollama: ${codex.error}`);
        continue;
      }
      const executable = target.harness === 'agy'
        ? agyBin
        : target.harness === 'claude'
          ? claudeBin
          : codexBin;
      const available = probe(target.harness, executable, ['--version']);
      if (!available.ok) invalid(`${target.harness} is unavailable: ${available.error}`);
    }
    return validateNoshProfiles(template.requiredNoshProfiles, environment);
  }

  function create(input = {}, taskContext = null) {
    const current = getSession();
    if (current) {
      const error = new Error(`workspace already has an active collaboration session: ${current.id}`);
      error.statusCode = 409;
      throw error;
    }
    const config = configStore.load();
    const templateId = String(input.templateId || config.resolved.defaultTemplate || '').trim();
    if (!Object.hasOwn(config.resolved.templates, templateId)) {
      const error = new Error(`unknown collaboration template: ${templateId}`);
      error.statusCode = 404;
      throw error;
    }
    const template = config.resolved.templates[templateId];
    const coordinatorMode = String(input.coordinatorMode || template.defaultCoordinatorMode || 'human').trim();
    const {
      specs,
      agents: parsedAgents,
    } = resolveLaunchChoices(template, config.resolved.prompts, coordinatorMode, input.agentChoices);
    const warnings = validatePreflight(template, parsedAgents);
    const id = crypto.randomUUID();
    const shortId = id.slice(0, 8);
    const channel = cleanToken(input.channel || template.channel || 'lobby', 'lobby');
    const task = String(input.task || '').trim();
    const now = new Date().toISOString();
    const session = {
      id,
      templateId,
      templateSnapshot: {
        ...structuredClone(template),
        agents: specs.slice(),
        prompts: Object.fromEntries(Array.from(new Set(parsedAgents.map((agent) => agent.prompt))).map((promptId) => [
          promptId,
          structuredClone(config.resolved.prompts[promptId]),
        ])),
      },
      coordinatorMode,
      taskId: taskContext?.id || null,
      task,
      channel,
      layout: template.layout,
      layoutSnapshot: layoutSnapshot(template.layout, config.resolved.layouts),
      status: 'starting',
      createdAt: now,
      updatedAt: now,
      workspaceRoot,
      recovered: false,
      warnings,
      agents: parsedAgents.map((inputAgent) => {
        const target = normalizeLaunchTarget(inputAgent);
        const agent = {
          ...inputAgent,
          ...target,
          think: normalizeAgentThink(inputAgent.think, target),
          ...(target.harness === 'codex' && taskContext ? {
            resumeMarker: taskContext.roles.find((role) => role.identity === inputAgent.identity && role.backend === target.backend)?.marker,
          } : {}),
        };
        const launchMcpUrl = mcpUrlForAgent(agent);
        return {
          id: agent.identity,
          ...agent,
          permissionMode: target.harness === 'codex'
            ? defaultPermissionMode
            : '',
          runtimeSessionId: target.harness === 'claude' ? crypto.randomUUID()
            : taskContext?.roles.find((role) => role.identity === agent.identity && role.backend === target.backend)?.threadId || '',
          resumeStatus: agent.resumeMarker ? 'capturing' : '',
          initialPrompt: buildAgentPrompt(agent, {
            prompts: config.resolved.prompts,
            sessionId: id,
            mcpUrl: launchMcpUrl,
            channel,
            workspaceRoot,
            coordinatorMode,
            task,
          }),
          tmuxTarget: cleanToken(`collab-${shortId}-${agent.identity}`, `collab-${shortId}`),
          status: 'starting',
          tmuxPresent: false,
          tmuxOwned: false,
          tmuxAlive: false,
          ownershipLost: false,
          registered: false,
          mcpStatus: 'unregistered',
          pending: { directCount: 0, channels: [], updatedAt: '' },
          health: null,
          startedAt: '',
          error: '',
        };
      }),
    };
    saveManifest(session);
    emit('session.changed', session);

    for (let index = 0; index < session.agents.length; index += 1) {
      const agent = session.agents[index];
      try {
        if (hasTmuxSession(agent.tmuxTarget)) {
          throw new Error(`tmux session already exists: ${agent.tmuxTarget}`);
        }
        launchTmuxAgent(agent, {
          prompts: config.resolved.prompts,
          sessionId: session.id,
          mcpUrl: mcpUrlForAgent(agent),
          channel,
          workspaceRoot,
          coordinatorMode,
          task,
          codexBin,
          codexArgs: codexArgsForAgent(agent),
          agyBin,
          agyArgs,
          claudeBin,
          claudeArgs,
          curlBin,
          ollamaEndpoint,
          ollamaSpawnSync,
          ollamaRuntimeDir,
          ollamaTimeoutMs,
          removeOllamaModelCatalog: removeCatalog,
          environment,
          newSessionId: agent.harness === 'claude' ? agent.runtimeSessionId : '',
          resumeSessionId: agent.harness === 'codex' ? agent.runtimeSessionId : '',
          resumePrompt: agent.harness === 'codex' && agent.runtimeSessionId
            ? `Rejoin collaboration session ${session.id}, task ${taskContext.name}, role ${agent.identity}, channel ${channel}. Do not continue an old assignment. ${buildAgentPrompt(agent, { prompts: {}, sessionId: session.id, mcpUrl: mcpUrlForAgent(agent), channel, workspaceRoot })}` : '',
        });
        addManagedAgent(
          agent.identity,
          agent.tmuxTarget,
          managedMetadataForAgent(agent, session.id),
        );
        session.agents[index] = {
          ...agent,
          status: 'running',
          tmuxPresent: true,
          tmuxOwned: true,
          tmuxAlive: true,
          ownershipLost: false,
          health: agent.health?.source === 'operator' ? agent.health : null,
          startedAt: new Date().toISOString(),
          expiresAt: Date.now() + agent.timeoutSeconds * 1000,
        };
        healthScanTimes.set(agent.identity, Date.now());
      } catch (error) {
        const tmuxPresent = hasTmuxSession(agent.tmuxTarget);
        session.agents[index] = resolveAgentTmuxState({
          ...agent,
          status: 'failed',
          health: healthAfterFailure(agent, error),
          error: error.message || String(error),
        }, {
          recovered: false,
          tmuxPresent,
          tmuxOwned: tmuxPresent && ownsTmuxSession(agent.tmuxTarget, session.id),
        });
      }
      session.updatedAt = new Date().toISOString();
      saveManifest(session);
      emit('agent.status', session.agents[index]);
    }

    const failed = session.agents.filter((agent) => !agent.tmuxAlive).length;
    session.status = failed === 0 ? 'running' : failed === session.agents.length ? 'failed' : 'degraded';
    session.updatedAt = new Date().toISOString();
    saveManifest(session);
    if (coordinatorMode === 'human' && task) {
      postMessage({
        agent: operator,
        channel,
        to: 'all',
        body: task,
        kind: 'message',
        quiet: true,
      });
    }
    emit('session.changed', session);
    return reconcile(session);
  }

  function patch(input = {}) {
    const session = getSession();
    if (!session) {
      const error = new Error('no active collaboration session');
      error.statusCode = 404;
      throw error;
    }
    if (input.layout !== undefined) {
      const config = configStore.load();
      if (!Object.hasOwn(config.resolved.layouts, input.layout)) {
        const error = new Error(`unknown layout: ${input.layout}`);
        error.statusCode = 422;
        throw error;
      }
      session.layout = input.layout;
      session.layoutSnapshot = layoutSnapshot(input.layout, config.resolved.layouts);
    }
    session.updatedAt = new Date().toISOString();
    saveManifest(session);
    emit('session.changed', session);
    return session;
  }

  async function relaunchNow(agentId, input = {}) {
    let session = getSession();
    if (!session) {
      const error = new Error('no active collaboration session');
      error.statusCode = 404;
      throw error;
    }
    if (session.recovered) {
      const error = new Error('recovered legacy agents cannot be relaunched without a template');
      error.statusCode = 409;
      throw error;
    }
    let index = session.agents.findIndex((agent) => agent.id === agentId || agent.identity === agentId);
    if (index === -1) {
      const error = new Error(`unknown session agent: ${agentId}`);
      error.statusCode = 404;
      throw error;
    }
    let agent = session.agents[index];
    const target = normalizeLaunchTarget(agent);
    if (target.harness !== 'codex') {
      const error = new Error('permission-mode relaunch is supported only for Codex agents');
      error.statusCode = 422;
      throw error;
    }
    let permissionMode;
    try {
      permissionMode = normalizeCodexPermissionMode(input.permissionMode);
    } catch (error) {
      error.statusCode = 422;
      throw error;
    }
    if (permissionMode === permissionModeForAgent(agent)) {
      return session;
    }

    const tmuxPresent = hasTmuxSession(agent.tmuxTarget);
    const tmuxOwned = tmuxPresent && ownsTmuxSession(agent.tmuxTarget, session.id);
    if (!tmuxPresent || !tmuxOwned) {
      const error = new Error(tmuxPresent
        ? `agent tmux target is occupied by another session: ${agent.tmuxTarget}`
        : `agent tmux session is not running: ${agent.tmuxTarget}`);
      error.statusCode = 409;
      throw error;
    }

    const initialPrompt = String(agent.initialPrompt || buildAgentPrompt(agent, {
      prompts: session.templateSnapshot?.prompts || {},
      sessionId: session.id,
      mcpUrl: mcpUrlForAgent(agent),
      channel: session.channel,
      workspaceRoot,
      coordinatorMode: session.coordinatorMode,
      task: session.task,
    }));
    let runtimeSessionId = String(agent.runtimeSessionId || '').trim();
    if (!runtimeSessionId || agent.resumeMarker) {
      runtimeSessionId = String(await findCodexThreadId({
        codexBin,
        cwd: workspaceRoot,
        prompt: initialPrompt,
        marker: agent.resumeMarker,
        threadId: agent.resumeMarker ? runtimeSessionId || undefined : undefined,
        environment,
      }) || '').trim();
    }
    if (!runtimeSessionId) {
      const error = new Error(
        `Codex has not recorded a resumable thread for ${agent.identity}; wait for startup to finish and try again`,
      );
      error.statusCode = 409;
      throw error;
    }

    // Resolve the exact Codex thread before stopping anything, then reload the
    // manifest so an intervening patch/stop cannot be overwritten by this
    // request's pre-app-server snapshot.
    const latestSession = getSession();
    if (!latestSession || latestSession.id !== session.id) {
      const error = new Error('collaboration session changed during agent relaunch');
      error.statusCode = 409;
      throw error;
    }
    const latestIndex = latestSession.agents.findIndex(
      (entry) => entry.id === agentId || entry.identity === agentId,
    );
    if (latestIndex === -1) {
      const error = new Error(`session agent changed during relaunch: ${agentId}`);
      error.statusCode = 409;
      throw error;
    }
    const latestAgent = latestSession.agents[latestIndex];
    if (normalizeLaunchTarget(latestAgent).harness !== 'codex') {
      const error = new Error(`session agent runtime changed during relaunch: ${agentId}`);
      error.statusCode = 409;
      throw error;
    }
    if (permissionMode === permissionModeForAgent(latestAgent)) {
      return latestSession;
    }
    session = latestSession;
    index = latestIndex;
    agent = latestAgent;
    runtimeSessionId = String(agent.runtimeSessionId || runtimeSessionId).trim();

    // Re-check ownership in case the tmux target changed while app-server was
    // listing the exact thread.
    if (
      !hasTmuxSession(agent.tmuxTarget)
      || !ownsTmuxSession(agent.tmuxTarget, session.id)
    ) {
      const error = new Error(`agent tmux ownership changed during relaunch: ${agent.tmuxTarget}`);
      error.statusCode = 409;
      throw error;
    }

    stopTmuxSession(agent.tmuxTarget);
    if (hasTmuxSession(agent.tmuxTarget)) {
      const error = new Error(`agent tmux session did not stop: ${agent.tmuxTarget}`);
      error.statusCode = 500;
      throw error;
    }
    clearAgentRuntime(agent.identity);

    const restarting = {
      ...agent,
      permissionMode,
      runtimeSessionId,
      initialPrompt,
      status: 'starting',
      tmuxPresent: false,
      tmuxOwned: false,
      tmuxAlive: false,
      ownershipLost: false,
      registered: false,
      mcpStatus: 'unregistered',
      error: '',
    };
    session.agents[index] = restarting;
    session.status = 'degraded';
    session.updatedAt = new Date().toISOString();
    saveManifest(session);
    emit('agent.status', restarting);
    emit('session.changed', session);

    try {
      launchTmuxAgent(restarting, {
        prompts: session.templateSnapshot.prompts,
        sessionId: session.id,
        mcpUrl: mcpUrlForAgent(restarting),
        channel: session.channel,
        workspaceRoot,
        coordinatorMode: session.coordinatorMode,
        task: session.task,
        codexBin,
        codexArgs: codexArgsForAgent(restarting),
        agyBin,
        agyArgs,
        claudeBin,
        claudeArgs,
        curlBin,
        ollamaEndpoint,
        ollamaSpawnSync,
        ollamaRuntimeDir,
        ollamaTimeoutMs,
        removeOllamaModelCatalog: removeCatalog,
        environment,
        resumeSessionId: runtimeSessionId,
      });
      addManagedAgent(
        restarting.identity,
        restarting.tmuxTarget,
        managedMetadataForAgent({ ...restarting, runtimeSessionId }, session.id),
      );
      session.agents[index] = {
        ...restarting,
        status: 'running',
        tmuxPresent: true,
        tmuxOwned: true,
        tmuxAlive: true,
        ownershipLost: false,
        health: restarting.health?.source === 'operator' ? restarting.health : null,
        startedAt: new Date().toISOString(),
      };
      healthScanTimes.set(restarting.identity, Date.now());
    } catch (error) {
      const tmuxPresentAfterFailure = hasTmuxSession(restarting.tmuxTarget);
      const failed = resolveAgentTmuxState({
        ...restarting,
        status: 'failed',
        health: healthAfterFailure(restarting, error),
        error: error.message || String(error),
      }, {
        recovered: false,
        tmuxPresent: tmuxPresentAfterFailure,
        tmuxOwned: tmuxPresentAfterFailure
          && ownsTmuxSession(restarting.tmuxTarget, session.id),
      });
      session.agents[index] = failed;
    }

    session.status = session.agents.every((entry) => entry.status === 'running')
      ? 'running'
      : 'degraded';
    session.updatedAt = new Date().toISOString();
    saveManifest(session);
    emit('agent.status', session.agents[index]);
    emit('session.changed', session);
    return reconcile(session);
  }

  let relaunchTail = Promise.resolve();
  function relaunch(agentId, input = {}) {
    const operation = relaunchTail.then(() => relaunchNow(agentId, input));
    relaunchTail = operation.then(() => undefined, () => undefined);
    return operation;
  }

  function retry(agentId) {
    const session = getSession();
    if (!session) {
      const error = new Error('no active collaboration session');
      error.statusCode = 404;
      throw error;
    }
    if (session.recovered) {
      const error = new Error('recovered legacy agents cannot be relaunched without a template');
      error.statusCode = 409;
      throw error;
    }
    const index = session.agents.findIndex((agent) => agent.id === agentId || agent.identity === agentId);
    if (index === -1) {
      const error = new Error(`unknown session agent: ${agentId}`);
      error.statusCode = 404;
      throw error;
    }
    const agent = session.agents[index];
    if (agent.resumeMarker && !agent.runtimeSessionId) {
      throw Object.assign(new Error('Resume ID is not captured yet. Stop and relaunch this task to recover its conversation.'), { statusCode: 409 });
    }
    if (hasTmuxSession(agent.tmuxTarget)) {
      const owned = ownsTmuxSession(agent.tmuxTarget, session.id);
      const error = new Error(owned
        ? `agent tmux session is already running: ${agent.tmuxTarget}`
        : `agent tmux target is occupied by another session: ${agent.tmuxTarget}`);
      error.statusCode = 409;
      throw error;
    }
    try {
      launchTmuxAgent(agent, {
        prompts: session.templateSnapshot.prompts,
        sessionId: session.id,
        mcpUrl: mcpUrlForAgent(agent),
        channel: session.channel,
        workspaceRoot,
        coordinatorMode: session.coordinatorMode,
        task: session.task,
        codexBin,
        codexArgs: codexArgsForAgent(agent),
        agyBin,
        agyArgs,
        claudeBin,
        claudeArgs,
        curlBin,
        ollamaEndpoint,
        ollamaSpawnSync,
        ollamaRuntimeDir,
        ollamaTimeoutMs,
        removeOllamaModelCatalog: removeCatalog,
        environment,
        resumeSessionId: agent.runtimeSessionId,
        resumePrompt: agent.resumeMarker
          ? `Rejoin session ${session.id}, role ${agent.identity}, channel ${session.channel}. Do not continue an old assignment. Use the configured ${COLLAB_SESSION_MCP_SERVER} service, set_nickname to ${agent.identity}, set_status idle, claim_pending once, then wait silently unless explicitly assigned work.` : '',
      });
      addManagedAgent(
        agent.identity,
        agent.tmuxTarget,
        managedMetadataForAgent(agent, session.id),
      );
      session.agents[index] = {
        ...agent,
        status: 'running',
        tmuxPresent: true,
        tmuxOwned: true,
        tmuxAlive: true,
        ownershipLost: false,
        health: agent.health?.source === 'operator' ? agent.health : null,
        startedAt: new Date().toISOString(),
        expiresAt: Date.now() + timeoutPolicy(agent).timeoutSeconds * 1000,
        error: '',
      };
      healthScanTimes.set(agent.identity, Date.now());
    } catch (error) {
      const tmuxPresent = hasTmuxSession(agent.tmuxTarget);
      session.agents[index] = resolveAgentTmuxState({
        ...agent,
        status: 'failed',
        health: healthAfterFailure(agent, error),
        error: error.message || String(error),
      }, {
        recovered: false,
        tmuxPresent,
        tmuxOwned: tmuxPresent && ownsTmuxSession(agent.tmuxTarget, session.id),
      });
    }
    session.status = session.agents.every((entry) => entry.status === 'running') ? 'running' : 'degraded';
    session.updatedAt = new Date().toISOString();
    saveManifest(session);
    emit('agent.status', session.agents[index]);
    emit('session.changed', session);
    return reconcile(session);
  }

  function setAgentHealth(agentId, input = {}) {
    const session = getSession();
    if (!session) {
      const error = new Error('no active collaboration session');
      error.statusCode = 404;
      throw error;
    }
    const index = session.agents.findIndex(
      (agent) => agent.id === agentId || agent.identity === agentId,
    );
    if (index === -1) {
      const error = new Error(`unknown session agent: ${agentId}`);
      error.statusCode = 404;
      throw error;
    }
    let health;
    try {
      health = normalizeHealthOverride(input);
    } catch (error) {
      error.statusCode = 422;
      throw error;
    }
    const agent = session.agents[index];
    if (health?.cleared && agent.tmuxTarget) {
      healthOutput.set(agent.identity, String(readAgentOutput(agent.tmuxTarget) || ''));
      healthScanTimes.set(agent.identity, Date.now());
    }
    session.agents[index] = { ...agent, health };
    session.updatedAt = new Date().toISOString();
    saveManifest(session);
    emit('agent.status', session.agents[index]);
    emit('session.changed', session);
    return session;
  }

  function stop() {
    const session = readManifest();
    if (!session) {
      return null;
    }
    const agents = [];
    const stopFailures = [];
    for (const agent of session.agents) {
      if (session.recovered) {
        try {
          removeManagedAgent(agent.identity);
        } catch (error) {
          error.statusCode = error.statusCode || 500;
          throw error;
        }
        agents.push(agent);
        continue;
      }

      const tmuxPresent = hasTmuxSession(agent.tmuxTarget);
      const tmuxOwned = tmuxPresent && ownsTmuxSession(agent.tmuxTarget, session.id);
      let killResult = null;
      if (tmuxOwned) {
        killResult = stopTmuxSession(agent.tmuxTarget);
      }
      const remainsPresent = hasTmuxSession(agent.tmuxTarget);
      const remainsOwned = remainsPresent && ownsTmuxSession(agent.tmuxTarget, session.id);
      if (remainsOwned) {
        const detail = killResult && (
          killResult.error?.message
          || killResult.stderr
          || killResult.stdout
          || (killResult.status !== 0 ? `tmux kill-session exited ${killResult.status}` : '')
        );
        const failedAgent = {
          ...agent,
          status: 'stop-failed',
          tmuxPresent: true,
          tmuxOwned: true,
          tmuxAlive: true,
          ownershipLost: false,
          error: String(detail || `tmux target remained alive after termination: ${agent.tmuxTarget}`).trim(),
        };
        agents.push(failedAgent);
        stopFailures.push(failedAgent);
        continue;
      }
      try {
        removeManagedAgent(agent.identity);
      } catch (_error) {
        // A stale managed entry must not prevent the rest of the session from stopping.
      }
      clearAgentRuntime(agent.identity);
      agents.push(resolveAgentTmuxState({ ...agent, status: 'stopped', error: '' }, {
        recovered: false,
        tmuxPresent: remainsPresent,
        tmuxOwned: false,
      }));
    }

    if (stopFailures.length > 0) {
      const next = {
        ...session,
        status: 'degraded',
        updatedAt: new Date().toISOString(),
        agents,
      };
      saveManifest(next);
      stopFailures.forEach((agent) => emit('agent.status', agent));
      emit('session.changed', next);
      const error = new Error(`failed to stop owned tmux sessions: ${stopFailures.map((agent) => agent.tmuxTarget).join(', ')}`);
      error.statusCode = 500;
      throw error;
    }
    deleteManifest();
    emit('session.changed', null);
    return {
      id: session.id,
      stopped: true,
      stoppedAt: new Date().toISOString(),
    };
  }

  async function captureTaskRole(sessionId, taskId, agent) {
    let threadId = agent.runtimeSessionId;
    const deadline = Date.now() + (options.resumeCaptureTimeoutMs || 60000);
    do {
      try {
        threadId = threadId || await findCodexThreadId({ codexBin, cwd: workspaceRoot,
          environment, prompt: agent.initialPrompt, marker: agent.resumeMarker,
          timeoutMs: Math.max(1, Math.min(QUICK_COMMAND_TIMEOUT_MS, deadline - Date.now())) });
      } catch { /* Bounded retry while the CLI initializes. */ }
      if (threadId || Date.now() >= deadline) break;
      await new Promise((resolve) => { const timer = setTimeout(resolve, 2000); timer.unref?.(); });
    } while (Date.now() < deadline);
    const status = threadId ? 'saved' : 'failed';
    resumeStore.update((document) => {
      const role = document.tasks.find((entry) => entry.id === taskId)?.roles.find((entry) => entry.marker === agent.resumeMarker);
      if (!role) return;
      role.threadId = threadId || role.threadId;
      role.status = role.threadId ? 'saved' : status;
      role.updatedAt = new Date().toISOString();
    });
    const current = getSession();
    if (!current || current.id !== sessionId) return;
    const row = current.agents.find((entry) => entry.id === agent.id && entry.resumeMarker === agent.resumeMarker);
    if (!row) return;
    row.runtimeSessionId = threadId || '';
    row.resumeStatus = status;
    row.resumeError = threadId ? '' : 'Thread capture timed out. Relaunch the task to recover this exact conversation.';
    saveManifest(current);
    emit('session.changed', current);
  }

  async function launchTask(input = {}) {
    if (taskLaunchPending) throw Object.assign(new Error('A collaboration launch is already in progress'), { statusCode: 409 });
    if (getSession()) {
      if (input.autoResume === true) return getSession();
      throw Object.assign(new Error('A collaboration session is already active'), { statusCode: 409 });
    }
    taskLaunchPending = true;
    try {
      let document = resumeStore.read();
      if (input.autoResume === true && !document.autoResume) throw new Error('Automatic resume is disabled');
      if (!document.tasks.length) document = resumeStore.createTask('Default task');
      const task = document.tasks.find((entry) => entry.id === (input.taskId || document.lastTaskId));
      if (!task) throw new Error('Unknown collaboration task');
      const settings = input.autoResume === true ? task.launch : input;
      if (!settings) throw new Error('This task has no saved launch settings');
      const config = configStore.load();
      const templateId = settings.templateId || config.resolved.defaultTemplate;
      const template = config.resolved.templates[templateId];
      if (!template) throw new Error('Unknown collaboration template');
      const coordinatorMode = settings.coordinatorMode || template.defaultCoordinatorMode || 'human';
      const { agents } = resolveLaunchChoices(template, config.resolved.prompts, coordinatorMode, settings.agentChoices);
      validatePreflight(template, agents);
      let resumed = false;
      const roles = structuredClone(task.roles);
      for (const agent of agents) {
        const target = normalizeLaunchTarget(agent);
        if (target.harness !== 'codex') continue;
        let role = roles.find((entry) => entry.identity === agent.identity && entry.backend === target.backend);
        if (role) {
          const threadId = await findCodexThreadId({ codexBin, cwd: workspaceRoot, environment,
            prompt: `Notty launch ${role.marker}`, marker: role.marker, threadId: role.threadId || undefined });
          if (!threadId) throw new Error(`Cannot recover saved conversation for ${agent.identity}. No fresh conversation was started.`);
          role.threadId = threadId;
          role.status = 'saved';
          resumed = true;
        } else {
          role = { identity: agent.identity, backend: target.backend, marker: crypto.randomUUID(), threadId: '',
            model: '', think: '', status: 'capturing', updatedAt: new Date().toISOString() };
          roles.push(role);
        }
        role.model = String(agent.model || '');
        role.think = String(agent.think || '');
      }
      resumeStore.update((next) => {
        const entry = next.tasks.find((item) => item.id === task.id);
        entry.roles = roles;
        entry.updatedAt = new Date().toISOString();
        entry.launch = { templateId, coordinatorMode, channel: String(settings.channel || template.channel || 'lobby'),
          agentChoices: agents.map((agent) => ({ ...normalizeLaunchTarget(agent), model: String(agent.model || ''), think: String(agent.think || ''), ...timeoutPolicy(agent) }))
            .map(({ harness, backend, model, think, timeoutSeconds, terminateOnExpire }) => ({ harness, backend, model, think, timeoutSeconds, terminateOnExpire })) };
        next.lastTaskId = task.id;
      });
      const session = create({ ...settings, templateId, coordinatorMode }, { ...task, roles });
      if (resumed && input.autoResume !== true && session.status === 'running') {
        resumeStore.update((next) => { next.tasks.find((entry) => entry.id === task.id).manualResumes += 1; });
      }
      for (const agent of session.agents.filter((entry) => entry.resumeMarker)) {
        captureTaskRole(session.id, task.id, agent).catch((error) => {
          const current = getSession();
          const row = current?.id === session.id && current.agents.find((entry) => entry.id === agent.id);
          if (row) {
            row.resumeStatus = 'failed';
            row.resumeError = 'Could not persist the resume ID. Check the project resume index permissions and lock.';
            saveManifest(current);
            emit('session.changed', current);
          }
          emit('session.resume-error', { taskId: task.id, agentId: agent.id, error: error.message });
        });
      }
      return session;
    } finally { taskLaunchPending = false; }
  }

  async function retryTask(agentId) {
    const session = getSession();
    const agent = session?.agents.find((entry) => entry.id === agentId || entry.identity === agentId);
    if (agent?.resumeMarker) {
      const threadId = await findCodexThreadId({ codexBin, cwd: workspaceRoot, environment,
        prompt: agent.initialPrompt, marker: agent.resumeMarker, threadId: agent.runtimeSessionId || undefined });
      if (!threadId) throw new Error('Saved conversation is unavailable; retry did not start a new conversation');
      const current = getSession();
      if (!current || current.id !== session.id) throw new Error('Session changed during retry');
      const row = current.agents.find((entry) => entry.id === agent.id);
      row.runtimeSessionId = threadId;
      row.resumeStatus = 'saved';
      resumeStore.update((document) => {
        const role = document.tasks.find((entry) => entry.id === current.taskId)?.roles.find((entry) => entry.marker === agent.resumeMarker);
        if (role) { role.threadId = threadId; role.status = 'saved'; role.updatedAt = new Date().toISOString(); }
      });
      saveManifest(current);
    }
    return retry(agentId);
  }

  function taskSettings(input) {
    if (taskLaunchPending) throw Object.assign(new Error('A task launch is in progress'), { statusCode: 409 });
    return resumeStore.update((document) => {
      if (Object.keys(input).some((key) => !['taskId', 'autoResume'].includes(key))) throw new Error('Unknown task setting');
      if (input.taskId !== undefined) {
        if (!document.tasks.some((task) => task.id === input.taskId)) throw new Error('Unknown task');
        document.lastTaskId = input.taskId;
        if (document.tasks.find((task) => task.id === input.taskId).manualResumes < 3) document.autoResume = false;
      }
      if (input.autoResume !== undefined) {
        if (typeof input.autoResume !== 'boolean') throw new Error('autoResume must be boolean');
        const task = document.tasks.find((entry) => entry.id === document.lastTaskId);
        if (input.autoResume && (!task || task.manualResumes < 3)) throw new Error('Complete three manual resumes before enabling automatic resume');
        document.autoResume = input.autoResume;
      }
    });
  }

  return {
    appRoot,
    operator,
    workspaceRoot,
    manifestPath,
    create,
    launchTask,
    retryTask,
    tasks: () => resumeStore.read(),
    createTask: (name) => {
      if (taskLaunchPending) throw Object.assign(new Error('A task launch is in progress'), { statusCode: 409 });
      return resumeStore.createTask(name);
    },
    taskSettings,
    getSession,
    patch,
    relaunch,
    retry,
    setAgentHealth,
    stop,
    reconcile: () => getSession(),
  };
}

module.exports = {
  CODEX_PERMISSION_MODES,
  COLLAB_SESSION_MCP_SERVER,
  QUICK_COMMAND_TIMEOUT_MS,
  buildAgentPrompt,
  codexArgsWithPermissionMode,
  codexPermissionModeFromArgs,
  codexSafetyArgsForPermissionMode,
  commandExists,
  createSessionManager,
  createLayoutSnapshot,
  defaultAgySafetyArgs,
  defaultClaudeSafetyArgs,
  defaultCodexPermissionMode,
  defaultCodexSafetyArgs,
  killTmuxSession,
  captureTmuxPane,
  launchTmuxAgent,
  modelReasoningConfig,
  newPaneOutput,
  normalizeAgentRuntime,
  normalizeAgentThink,
  normalizeCodexPermissionMode,
  resolveCodexThreadId,
  resolveAgentTmuxState,
  resolveLaunchRoster,
  resolveLaunchChoices,
  resolveSessionOperator,
  selectCodexThreadId,
  setTmuxSessionOwner,
  statePathForWorkspace,
  tmuxSessionExists,
  tmuxSessionOwnedBy,
  validateNoshProfiles,
};
