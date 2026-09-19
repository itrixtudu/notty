import * as fs from 'node:fs';
import * as path from 'node:path';
import { spawn } from 'node:child_process';
import { randomUUID } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import childEnvironment from './childEnvironment.cjs';
import {
  createTerminalReader,
  getTerminalSummary,
  inspectTerminal
} from './terminalManager.js';

const { sanitizeChildEnvironment } = childEnvironment;

const ROOT_DIR = fileURLToPath(new URL('..', import.meta.url));
const DEFAULT_CONFIG_PATH = path.join(ROOT_DIR, 'config', 'notty-agents.json');
const COLLAB_CHANNELS_DIR = path.join(ROOT_DIR, 'collab', 'intragent', 'channels');
const DEFAULT_MAX_CONTEXT_CHARS = 20000;
const MAX_CONTEXT_CHARS = 200000;
const MAX_MESSAGES = 500;
const DEFAULT_COMMAND_TIMEOUT_MS = 120000;
const DEFAULT_AGENT = {
  id: 'collab',
  label: 'Collab',
  adapter: 'collab',
  enabled: true,
  channel: 'lobby',
  description: 'Posts terminal context to the collab/intragent JSONL bus.'
};

const state = globalThis.__nottyAgentState || {
  runs: new Map(),
  messages: [],
  lastRuns: new Map()
};

globalThis.__nottyAgentState = state;

function sanitizeId(value, fallback = 'agent') {
  const raw = String(value || fallback).trim();
  const clean = raw.replace(/[^A-Za-z0-9._-]/g, '_');
  return clean || fallback;
}

function sanitizeChannel(value, fallback = 'lobby') {
  return sanitizeId(value, fallback);
}

function toPositiveInt(value, fallback, max = Number.MAX_SAFE_INTEGER) {
  const parsed = Number.parseInt(String(value ?? ''), 10);
  if (!Number.isFinite(parsed) || parsed <= 0) {
    return fallback;
  }
  return Math.min(parsed, max);
}

function resolveConfigPath() {
  const configured = process.env.NOTTY_AGENTS_CONFIG;
  if (typeof configured === 'string' && configured.trim()) {
    return path.isAbsolute(configured)
      ? configured.trim()
      : path.resolve(ROOT_DIR, configured.trim());
  }
  return DEFAULT_CONFIG_PATH;
}

function normalizeAgents(rawAgents) {
  const candidates = Array.isArray(rawAgents)
    ? rawAgents
    : rawAgents && typeof rawAgents === 'object'
        ? Object.entries(rawAgents).map(([id, value]) => ({ id, ...value }))
        : [DEFAULT_AGENT];

  const seen = new Set();
  const agents = [];

  for (const candidate of candidates) {
    if (!candidate || typeof candidate !== 'object') {
      continue;
    }

    const id = sanitizeId(candidate.id || candidate.name, '');
    if (!id || seen.has(id)) {
      continue;
    }
    seen.add(id);

    const adapter = sanitizeId(candidate.adapter || candidate.type || 'command', 'command');
    agents.push({
      id,
      label: String(candidate.label || candidate.name || id),
      description: String(candidate.description || ''),
      adapter,
      enabled: candidate.enabled !== false,
      channel: sanitizeChannel(candidate.channel, getTerminalChannel()),
      command: typeof candidate.command === 'string' ? candidate.command : '',
      args: Array.isArray(candidate.args) ? candidate.args.map(String) : [],
      cwd: typeof candidate.cwd === 'string' && candidate.cwd.trim()
        ? path.resolve(ROOT_DIR, candidate.cwd)
        : ROOT_DIR,
      shell: candidate.shell === true,
      timeoutMs: toPositiveInt(
        candidate.timeoutMs ?? candidate.timeout_ms,
        DEFAULT_COMMAND_TIMEOUT_MS,
        15 * 60 * 1000
      ),
      maxOutputChars: toPositiveInt(
        candidate.maxOutputChars ?? candidate.max_output_chars,
        32000,
        200000
      )
    });
  }

  return agents.length ? agents : [{ ...DEFAULT_AGENT }];
}

function readAgentConfig() {
  const configPath = resolveConfigPath();
  let raw = {};
  let configError = null;

  try {
    if (fs.existsSync(/* turbopackIgnore: true */ configPath)) {
      raw = JSON.parse(fs.readFileSync(/* turbopackIgnore: true */ configPath, 'utf8'));
    }
  } catch (err) {
    raw = {};
    configError = err.message || String(err);
  }

  return {
    configPath,
    configError,
    maxContextChars: toPositiveInt(
      raw.maxContextChars ?? raw.max_context_chars,
      DEFAULT_MAX_CONTEXT_CHARS,
      MAX_CONTEXT_CHARS
    ),
    agents: normalizeAgents(raw.agents)
  };
}

function publicAgent(agent) {
  const lastRun = state.lastRuns.get(agent.id) || null;
  return {
    id: agent.id,
    label: agent.label,
    description: agent.description,
    adapter: agent.adapter,
    enabled: agent.enabled,
    channel: agent.channel,
    status: lastRun?.status || 'idle',
    lastRun
  };
}

export function listAgents() {
  const config = readAgentConfig();
  return {
    configPath: config.configPath,
    configError: config.configError,
    maxContextChars: config.maxContextChars,
    agents: config.agents.map(publicAgent)
  };
}

function resolveTerminalRef(input) {
  if (Number.isInteger(input) || typeof input === 'string') {
    return input;
  }

  if (!input || typeof input !== 'object') {
    throw new Error('terminal_uuid or terminal_id is required');
  }

  const terminalUuid =
    typeof input.terminal_uuid === 'string' && input.terminal_uuid.trim()
      ? input.terminal_uuid.trim()
      : typeof input.terminalUuid === 'string' && input.terminalUuid.trim()
          ? input.terminalUuid.trim()
          : null;
  if (terminalUuid) {
    return { terminal_uuid: terminalUuid };
  }

  if (Number.isInteger(input.terminal_id)) {
    return input.terminal_id;
  }
  if (Number.isInteger(input.terminalId)) {
    return input.terminalId;
  }
  if (typeof input.terminal_id === 'string' && input.terminal_id.trim()) {
    return input.terminal_id.trim();
  }
  if (typeof input.terminalId === 'string' && input.terminalId.trim()) {
    return input.terminalId.trim();
  }

  throw new Error('terminal_uuid or terminal_id is required');
}

function normalizeScope(value) {
  return value === 'history' ? 'history' : 'tail';
}

export function getTerminalChannel(terminalUuid = '') {
  if (!terminalUuid) {
    return 'lobby';
  }
  return `terminal-${sanitizeChannel(terminalUuid).slice(0, 18)}`;
}

export function redactTerminalSecrets(text) {
  if (!text) {
    return '';
  }

  return String(text)
    .replace(
      /(^|[\r\n\s])((?:export\s+)?(?:[A-Z0-9_]*(?:TOKEN|PASSWORD|PASSWD|SECRET|OTP|AUTH|API_KEY|ACCESS_KEY)[A-Z0-9_]*)\s*=\s*)([^\s\r\n]+)/gi,
      (_match, prefix, key) => `${prefix}${key}[redacted]`
    )
    .replace(
      /\b(authorization\s*:\s*(?:bearer|basic)\s+)[^\s\r\n]+/gi,
      '$1[redacted]'
    )
    .replace(
      /(\s--(?:access[-_]?key|api[-_]?key|auth|password|passwd|secret|token|otp)(?:\s+|=))['"]?[^\s'"`]+/gi,
      '$1[redacted]'
    );
}

function readTerminalBuffer(terminalRef) {
  const reader = createTerminalReader(terminalRef, { includeHistory: true });
  try {
    return reader.read();
  } finally {
    reader.dispose();
  }
}

export function captureTerminalContext(input = {}) {
  const config = readAgentConfig();
  const terminalRef = resolveTerminalRef(input);
  const summary = getTerminalSummary(terminalRef);
  const uuidRef = { terminal_uuid: summary.terminal_uuid };
  const inspection = inspectTerminal(uuidRef);
  const rawOutput = readTerminalBuffer(uuidRef);
  const redacted = redactTerminalSecrets(rawOutput);
  const maxContextChars = toPositiveInt(
    input.maxContextChars ?? input.max_context_chars,
    config.maxContextChars,
    MAX_CONTEXT_CHARS
  );
  const truncatedStart = redacted.length > maxContextChars;
  const text = truncatedStart ? redacted.slice(-maxContextChars) : redacted;

  return {
    terminal: {
      id: summary.id,
      terminal_uuid: summary.terminal_uuid,
      shell: summary.shell,
      cwd: summary.cwd,
      cols: summary.cols,
      rows: summary.rows,
      alive: summary.alive,
      createdAt: summary.createdAt,
      terminalType: summary.terminalType,
      bufferBytesUsed: inspection.bufferBytesUsed,
      maxBufferBytes: inspection.maxBufferBytes
    },
    scope: normalizeScope(input.scope),
    capturedAt: new Date().toISOString(),
    maxContextChars,
    truncatedStart,
    text
  };
}

function appendLocalMessage(message) {
  const next = {
    id: message.id || randomUUID(),
    timestamp: message.timestamp || new Date().toISOString(),
    role: message.role || 'agent',
    kind: message.kind || 'message',
    terminal_uuid: message.terminal_uuid || null,
    channel: message.channel || null,
    agentId: message.agentId || message.agent_id || 'agent',
    agentLabel: message.agentLabel || message.agentId || message.agent_id || 'Agent',
    body: String(message.body || ''),
    suggestions: Array.isArray(message.suggestions) ? message.suggestions : [],
    runId: message.runId || null,
    status: message.status || null
  };

  state.messages.push(next);
  if (state.messages.length > MAX_MESSAGES) {
    state.messages.splice(0, state.messages.length - MAX_MESSAGES);
  }
  return next;
}

function ensureCollabDir() {
  fs.mkdirSync(COLLAB_CHANNELS_DIR, { recursive: true });
}

function writeCollabRecord(record) {
  ensureCollabDir();
  const channel = sanitizeChannel(record.channel, 'lobby');
  const channelPath = path.join(COLLAB_CHANNELS_DIR, `${channel}.jsonl`);
  const next = {
    timestamp: new Date().toISOString(),
    kind: 'message',
    agent_id: 'notty',
    to: 'all',
    ...record,
    channel
  };
  fs.appendFileSync(channelPath, `${JSON.stringify(next)}\n`, 'utf8');
  return next;
}

function readCollabRecords(channel, limit) {
  const channelPath = path.join(COLLAB_CHANNELS_DIR, `${sanitizeChannel(channel)}.jsonl`);
  if (!fs.existsSync(channelPath)) {
    return [];
  }

  const lines = fs.readFileSync(channelPath, 'utf8').split('\n').filter(Boolean);
  return lines.slice(-limit).map((line) => {
    try {
      return JSON.parse(line);
    } catch {
      return null;
    }
  }).filter(Boolean);
}

function collabRecordToMessage(record) {
  return {
    id: record.message_id || `${record.channel}:${record.timestamp}:${record.agent_id}:${record.body}`,
    timestamp: record.timestamp || new Date().toISOString(),
    role: record.agent_id === 'notty' ? 'system' : 'agent',
    kind: record.kind || 'message',
    terminal_uuid: record.terminal_uuid || null,
    channel: record.channel || 'lobby',
    agentId: record.agent_id || 'agent',
    agentLabel: record.agent_label || record.agent_id || 'Agent',
    body: String(record.body || ''),
    suggestions: Array.isArray(record.suggestions)
      ? record.suggestions
      : extractCommandSuggestions(record.body || ''),
    runId: record.run_id || null,
    status: record.status || null
  };
}

function resolveMessageChannels(config, terminalUuid, requestedChannel) {
  const channels = new Set();
  if (requestedChannel) {
    channels.add(sanitizeChannel(requestedChannel));
  }
  if (terminalUuid) {
    channels.add(getTerminalChannel(terminalUuid));
  }
  for (const agent of config.agents) {
    if (agent.channel) {
      channels.add(agent.channel);
    }
  }
  if (channels.size === 0) {
    channels.add('lobby');
  }
  return Array.from(channels);
}

export function readAgentMessages(input = {}) {
  const config = readAgentConfig();
  const terminalUuid = typeof input.terminal_uuid === 'string' && input.terminal_uuid.trim()
    ? input.terminal_uuid.trim()
    : typeof input.terminalUuid === 'string' && input.terminalUuid.trim()
        ? input.terminalUuid.trim()
        : '';
  const limit = toPositiveInt(input.limit, 80, 300);
  const channels = resolveMessageChannels(config, terminalUuid, input.channel);
  const seen = new Set();
  const messages = [];

  const maybePush = (message) => {
    if (!message || message.kind === 'terminal_context') {
      return;
    }
    if (terminalUuid && message.terminal_uuid && message.terminal_uuid !== terminalUuid) {
      return;
    }
    const key = message.id;
    if (seen.has(key)) {
      return;
    }
    seen.add(key);
    messages.push(message);
  };

  for (const message of state.messages) {
    maybePush(message);
  }

  for (const channel of channels) {
    for (const record of readCollabRecords(channel, limit)) {
      if (record.kind === 'terminal_context') {
        continue;
      }
      maybePush(collabRecordToMessage(record));
    }
  }

  messages.sort((a, b) => String(a.timestamp).localeCompare(String(b.timestamp)));
  return {
    messages: messages.slice(-limit),
    channels
  };
}

function buildAgentPrompt({ prompt, context }) {
  const envelope = {
    terminal: context.terminal,
    scope: context.scope,
    capturedAt: context.capturedAt,
    truncatedStart: context.truncatedStart,
    maxContextChars: context.maxContextChars
  };

  return [
    'You are a Notty terminal copilot.',
    'Give concise, practical feedback about the current terminal state.',
    'If you suggest commands, put each command in a fenced bash block or on a line prefixed with "command:".',
    '',
    'User prompt:',
    prompt,
    '',
    'Terminal metadata:',
    JSON.stringify(envelope, null, 2),
    '',
    'Terminal output:',
    '```text',
    context.text || '[no terminal output captured]',
    '```',
    ''
  ].join('\n');
}

function extractCommandSuggestions(text) {
  const suggestions = [];
  const pushCommand = (value) => {
    const command = String(value || '').trim();
    if (!command || suggestions.includes(command) || suggestions.length >= 5) {
      return;
    }
    suggestions.push(command);
  };

  const fenced = String(text || '').matchAll(/```(?:bash|sh|shell|console)?\s*\n([\s\S]*?)```/gi);
  for (const match of fenced) {
    const block = match[1]
      .split('\n')
      .map((line) => line.replace(/^\s*\$\s*/, '').trim())
      .filter((line) => line && !line.startsWith('#'))
      .join('\n')
      .trim();
    pushCommand(block);
  }

  const commandLines = String(text || '').matchAll(/^\s*command:\s*(.+)$/gim);
  for (const match of commandLines) {
    pushCommand(match[1]);
  }

  return suggestions;
}

function updateLastRun(agent, patch) {
  const previous = state.lastRuns.get(agent.id) || {};
  const next = {
    agentId: agent.id,
    runId: patch.runId || previous.runId || null,
    startedAt: patch.startedAt || previous.startedAt || null,
    finishedAt: patch.finishedAt || previous.finishedAt || null,
    status: patch.status || previous.status || 'idle',
    error: patch.error || null
  };
  state.lastRuns.set(agent.id, next);
  return next;
}

async function runCommandAgent({ agent, run, promptText, context }) {
  if (!agent.command) {
    throw new Error(`Agent ${agent.id} is missing command`);
  }

  const child = spawn(agent.command, agent.args, {
    cwd: agent.cwd,
    shell: agent.shell,
    env: sanitizeChildEnvironment(process.env, {
      NOTTY_AGENT_ID: agent.id,
      NOTTY_TERMINAL_UUID: context.terminal.terminal_uuid,
      NOTTY_TERMINAL_ID: String(context.terminal.id),
      NOTTY_TERMINAL_CWD: context.terminal.cwd || ''
    }),
    stdio: ['pipe', 'pipe', 'pipe']
  });

  let stdout = '';
  let stderr = '';
  let finished = false;

  const trimOutput = (value) => {
    if (value.length <= agent.maxOutputChars) {
      return value;
    }
    return value.slice(value.length - agent.maxOutputChars);
  };

  const timer = setTimeout(() => {
    if (!finished) {
      child.kill('SIGTERM');
    }
  }, agent.timeoutMs);

  child.stdout.on('data', (chunk) => {
    stdout = trimOutput(stdout + chunk.toString('utf8'));
  });
  child.stderr.on('data', (chunk) => {
    stderr = trimOutput(stderr + chunk.toString('utf8'));
  });

  child.stdin.end(promptText);

  const exitCode = await new Promise((resolve, reject) => {
    child.on('error', reject);
    child.on('close', (code) => resolve(code));
  });

  finished = true;
  clearTimeout(timer);

  const body = stdout.trim() || stderr.trim() || `[agent exited ${exitCode ?? 'unknown'} with no output]`;
  const suggestions = extractCommandSuggestions(body);
  const status = exitCode === 0 ? 'complete' : 'error';
  const kind = suggestions.length ? 'suggestion' : 'message';
  const message = appendLocalMessage({
    role: 'agent',
    kind,
    terminal_uuid: context.terminal.terminal_uuid,
    channel: agent.channel,
    agentId: agent.id,
    agentLabel: agent.label,
    body,
    suggestions,
    runId: run.id,
    status
  });

  writeCollabRecord({
    message_id: message.id,
    kind: status === 'complete' ? kind : 'error',
    agent_id: agent.id,
    agent_label: agent.label,
    to: 'notty',
    channel: agent.channel || getTerminalChannel(context.terminal.terminal_uuid),
    terminal_uuid: context.terminal.terminal_uuid,
    run_id: run.id,
    body,
    suggestions,
    status
  });

  if (exitCode !== 0) {
    const error = new Error(stderr.trim() || `Agent ${agent.id} exited with code ${exitCode}`);
    error.messagePosted = true;
    throw error;
  }

  return message;
}

async function runCollabAgent({ agent, run, promptText, context }) {
  const channel = agent.channel || getTerminalChannel(context.terminal.terminal_uuid);
  writeCollabRecord({
    kind: 'terminal_context',
    agent_id: 'notty',
    to: agent.id,
    channel,
    terminal_uuid: context.terminal.terminal_uuid,
    run_id: run.id,
    body: promptText,
    status: 'posted'
  });

  return appendLocalMessage({
    role: 'system',
    kind: 'message',
    terminal_uuid: context.terminal.terminal_uuid,
    channel,
    agentId: agent.id,
    agentLabel: agent.label,
    body: `Posted terminal context to #${channel}.`,
    runId: run.id,
    status: 'posted'
  });
}

async function runAgent({ agent, run, promptText, context }) {
  updateLastRun(agent, {
    runId: run.id,
    startedAt: run.startedAt,
    status: 'running'
  });

  try {
    if (agent.adapter === 'collab') {
      await runCollabAgent({ agent, run, promptText, context });
    } else if (agent.adapter === 'command') {
      await runCommandAgent({ agent, run, promptText, context });
    } else {
      throw new Error(`Unknown agent adapter: ${agent.adapter}`);
    }

    updateLastRun(agent, {
      runId: run.id,
      startedAt: run.startedAt,
      finishedAt: new Date().toISOString(),
      status: 'complete'
    });
  } catch (err) {
    const message = err.message || String(err);
    if (!err.messagePosted) {
      appendLocalMessage({
        role: 'agent',
        kind: 'error',
        terminal_uuid: context.terminal.terminal_uuid,
        channel: agent.channel,
        agentId: agent.id,
        agentLabel: agent.label,
        body: message,
        runId: run.id,
        status: 'error'
      });
    }
    updateLastRun(agent, {
      runId: run.id,
      startedAt: run.startedAt,
      finishedAt: new Date().toISOString(),
      status: 'error',
      error: message
    });
  }
}

function selectAgents(config, requestedIds) {
  const ids = Array.isArray(requestedIds)
    ? requestedIds.map((id) => sanitizeId(id, '')).filter(Boolean)
    : [];
  const idSet = new Set(ids);
  return config.agents.filter((agent) => agent.enabled && (idSet.size === 0 || idSet.has(agent.id)));
}

export function askAgents(input = {}) {
  const config = readAgentConfig();
  const selectedAgents = selectAgents(config, input.agentIds || input.agent_ids);
  if (selectedAgents.length === 0) {
    throw new Error('No enabled agents selected');
  }

  const prompt = typeof input.prompt === 'string' && input.prompt.trim()
    ? input.prompt.trim()
    : 'Review the current terminal context.';
  const context = captureTerminalContext({
    ...input,
    maxContextChars: input.maxContextChars ?? input.max_context_chars
  });
  const run = {
    id: randomUUID(),
    terminal_uuid: context.terminal.terminal_uuid,
    prompt,
    scope: context.scope,
    agentIds: selectedAgents.map((agent) => agent.id),
    status: 'running',
    startedAt: new Date().toISOString()
  };
  state.runs.set(run.id, run);

  appendLocalMessage({
    role: 'user',
    kind: 'ask',
    terminal_uuid: context.terminal.terminal_uuid,
    channel: getTerminalChannel(context.terminal.terminal_uuid),
    agentId: 'you',
    agentLabel: 'You',
    body: prompt,
    runId: run.id,
    status: 'sent'
  });

  const promptText = buildAgentPrompt({ prompt, context });
  for (const agent of selectedAgents) {
    runAgent({ agent, run, promptText, context });
  }

  return {
    run,
    context: {
      terminal: context.terminal,
      scope: context.scope,
      capturedAt: context.capturedAt,
      maxContextChars: context.maxContextChars,
      truncatedStart: context.truncatedStart,
      chars: context.text.length
    },
    agents: selectedAgents.map(publicAgent)
  };
}

export function postCopilotMessage(input = {}) {
  const terminalRef = resolveTerminalRef(input);
  const summary = getTerminalSummary(terminalRef);
  const terminalUuid = summary.terminal_uuid;
  const agentId = sanitizeId(input.agent || input.agentId || input.agent_id, 'agent');
  const channel = sanitizeChannel(input.channel, getTerminalChannel(terminalUuid));
  const body = String(input.body || '');
  if (!body.trim()) {
    throw new Error('body is required');
  }
  const suggestions = Array.isArray(input.suggestions)
    ? input.suggestions.map(String).filter(Boolean).slice(0, 5)
    : extractCommandSuggestions(body);
  const message = appendLocalMessage({
    role: 'agent',
    kind: sanitizeId(input.kind, suggestions.length ? 'suggestion' : 'message'),
    terminal_uuid: terminalUuid,
    channel,
    agentId,
    agentLabel: input.agentLabel || input.agent_label || agentId,
    body,
    suggestions,
    runId: input.runId || input.run_id || null,
    status: 'posted'
  });

  writeCollabRecord({
    message_id: message.id,
    kind: message.kind,
    agent_id: agentId,
    agent_label: message.agentLabel,
    to: 'notty',
    channel,
    terminal_uuid: terminalUuid,
    run_id: message.runId,
    body,
    suggestions,
    status: 'posted'
  });

  return message;
}
