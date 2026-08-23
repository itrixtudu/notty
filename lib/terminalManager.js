import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';
import { randomBytes, randomUUID } from 'node:crypto';
import * as pty from 'node-pty';
import { EventEmitter } from 'node:events';
import { logTerminalEvent, shouldLogReads } from './terminalLogging.js';
import { createTerminalOutputParser } from './terminalCommandProtocol.js';

// Maximum buffer size per terminal session (10MB default)
// Prevents unbounded memory growth on long-running terminals
const MAX_BUFFER_SIZE = parseInt(process.env.TERMINAL_MAX_BUFFER_SIZE, 10) || 10 * 1024 * 1024;
export const TERMINAL_MAX_BUFFER_SIZE = MAX_BUFFER_SIZE;

const globalState = globalThis.__terminalManagerState || {
  sessions: new Map(),
  uuidIndex: new Map(),
  nextId: 1
};

globalThis.__terminalManagerState = globalState;

const sessions = globalState.sessions;
if (!globalState.uuidIndex) {
  globalState.uuidIndex = new Map();
}
const uuidIndex = globalState.uuidIndex;
if (sessions.size > 0) {
  for (const session of sessions.values()) {
    if (!session.terminalUuid) {
      session.terminalUuid = randomUUID();
    }
    if (!uuidIndex.has(session.terminalUuid)) {
      uuidIndex.set(session.terminalUuid, session);
    }
  }
}

function normalizeTerminalUuid(value) {
  if (typeof value !== 'string') {
    return null;
  }
  const trimmed = value.trim();
  return trimmed.length ? trimmed : null;
}

function isNumericIdString(value) {
  return /^\d+$/.test(value);
}

function generateId() {
  const id = globalState.nextId;
  globalState.nextId += 1;
  return id;
}

function defaultCwd() {
  const configured = process.env.NOTTY_WORKDIR;
  if (typeof configured === 'string' && configured.trim()) {
    try {
      if (fs.statSync(configured).isDirectory()) {
        return configured;
      }
    } catch {
      // ignore missing/invalid configured cwd and fall back
    }
  }
  return process.env.HOME || os.homedir();
}

function resolveCwd(value) {
  const fallback = defaultCwd();
  if (typeof value !== 'string') {
    return { cwd: fallback, usedFallback: false, requestedCwd: null };
  }
  const trimmed = value.trim();
  if (!trimmed) {
    return { cwd: fallback, usedFallback: false, requestedCwd: null };
  }
  try {
    if (fs.statSync(trimmed).isDirectory()) {
      return { cwd: trimmed, usedFallback: false, requestedCwd: trimmed };
    }
  } catch {
    // ignore missing/invalid paths and fall back
  }
  return { cwd: fallback, usedFallback: true, requestedCwd: trimmed };
}

const defaultShell = os.platform() === 'win32' ? 'powershell.exe' : 'bash';
const moduleDirectory = path.dirname(fileURLToPath(import.meta.url));
const shellIntegrationDirectory = path.resolve(moduleDirectory, '../scripts/shell-integration');
const HEURISTIC_PROMPT_IDLE_MS = 200;
const MAX_HEURISTIC_OUTPUT_CHARS = 20_000;

function environmentFlagEnabled(value, fallback = true) {
  if (value === undefined || value === null || value === '') {
    return fallback;
  }
  return !['0', 'false', 'off', 'no'].includes(String(value).trim().toLowerCase());
}

function configureShellIntegration({ shell, spawnArgs, command, spawnEnv, requested }) {
  const shellName = path.basename(shell).toLowerCase().replace(/\.exe$/, '');
  const enabledByEnvironment = environmentFlagEnabled(
    spawnEnv.NOTTY_SHELL_INTEGRATION,
    true
  );
  const eligible = !command && spawnArgs.length === 0 && requested !== false;
  if (!eligible || !enabledByEnvironment || !['bash', 'zsh'].includes(shellName)) {
    return {
      args: spawnArgs,
      env: spawnEnv,
      markerNonce: null,
      state: {
        enabled: false,
        mode: 'heuristic',
        shell: shellName,
        reason: eligible ? 'unsupported-shell' : 'custom-launch'
      }
    };
  }

  if (shellName === 'bash') {
    const rcfile = path.join(shellIntegrationDirectory, 'bashrc');
    if (fs.existsSync(rcfile)) {
      const markerNonce = randomBytes(16).toString('hex');
      return {
        args: ['--rcfile', rcfile],
        env: { ...spawnEnv, NOTTY_SHELL_MARKER_NONCE: markerNonce },
        markerNonce,
        state: { enabled: true, mode: 'exact', shell: shellName }
      };
    }
  }

  if (shellName === 'zsh') {
    const rcfile = path.join(shellIntegrationDirectory, '.zshrc');
    if (fs.existsSync(rcfile)) {
      const markerNonce = randomBytes(16).toString('hex');
      const originalZdotdirPresent = Object.hasOwn(spawnEnv, 'ZDOTDIR');
      const originalZdotdir = originalZdotdirPresent
        ? String(spawnEnv.ZDOTDIR ?? '')
        : '';
      const originalStartupDirectory = originalZdotdirPresent
        ? originalZdotdir
        : spawnEnv.HOME || os.homedir();
      return {
        args: spawnArgs,
        env: {
          ...spawnEnv,
          ZDOTDIR: shellIntegrationDirectory,
          NOTTY_ORIGINAL_ZDOTDIR: originalZdotdir,
          NOTTY_ORIGINAL_ZDOTDIR_PATH: originalStartupDirectory,
          NOTTY_ORIGINAL_ZDOTDIR_SET: originalZdotdirPresent ? '1' : '0',
          NOTTY_SHELL_MARKER_NONCE: markerNonce
        },
        markerNonce,
        state: { enabled: true, mode: 'exact', shell: shellName }
      };
    }
  }

  return {
    args: spawnArgs,
    env: spawnEnv,
    markerNonce: null,
    state: {
      enabled: false,
      mode: 'heuristic',
      shell: shellName,
      reason: 'integration-unavailable'
    }
  };
}

export function validateTerminalDimensions(cols, rows) {
  if (!Number.isInteger(cols) || !Number.isInteger(rows)) {
    throw new Error('cols and rows must be integers');
  }
  if (cols <= 0 || rows <= 0) {
    throw new Error('cols and rows must be positive');
  }
}

function buildSummary(session) {
  ensureInteractionState(session);
  const summary = {
    id: session.id,
    terminal_uuid: session.terminalUuid,
    shell: session.shell,
    cols: session.cols,
    rows: session.rows,
    cwd: session.cwd,
    alive: !session.proc.killed,
    createdAt: session.createdAt,
    terminalType: session.terminalType
  };

  if (session.interaction?.shellIntegration) {
    summary.shellIntegration = { ...session.interaction.shellIntegration };
  }

  if (session.metadata) {
    summary.metadata = { ...session.metadata };
  }

  return summary;
}

function normalizeTerminalMetadata(value) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    return null;
  }

  try {
    const cloned = JSON.parse(JSON.stringify(value));
    return cloned && typeof cloned === 'object' && !Array.isArray(cloned) ? cloned : null;
  } catch {
    return null;
  }
}

function buildSpawnEnv(overrides) {
  if (!overrides || typeof overrides !== 'object' || Array.isArray(overrides)) {
    return process.env;
  }
  const env = { ...process.env };
  for (const [key, value] of Object.entries(overrides)) {
    if (value === null || value === undefined) {
      delete env[key];
    } else {
      env[key] = String(value);
    }
  }
  return env;
}

function createInteractionState(session, shellIntegration) {
  return {
    shellIntegration,
    alternateScreen: false,
    promptReady: null,
    currentCwd: session.cwd,
    lastInputAt: null,
    lastOutputAt: null,
    lastCommand: null,
    pendingCommands: [],
    nextCommandId: 1,
    inputLine: '',
    inputActor: null,
    inputBindingId: null,
    inputEscapeSequence: '',
    lastInputWasCarriageReturn: false,
    heuristicOutput: '',
    heuristicTimer: null
  };
}

function ensureInteractionState(session) {
  if (!session.interaction) {
    const shellName = path.basename(session.shell || defaultShell)
      .toLowerCase()
      .replace(/\.exe$/, '');
    session.interaction = createInteractionState(session, {
      enabled: false,
      mode: 'heuristic',
      shell: shellName,
      reason: 'legacy-session'
    });
  } else {
    const interaction = session.interaction;
    interaction.shellIntegration ||= {
      enabled: false,
      mode: 'heuristic',
      shell: path.basename(session.shell || defaultShell).toLowerCase(),
      reason: 'legacy-session'
    };
    interaction.alternateScreen ??= false;
    interaction.promptReady ??= null;
    interaction.currentCwd ||= session.cwd;
    interaction.lastInputAt ??= null;
    interaction.lastOutputAt ??= null;
    interaction.lastCommand ??= null;
    if (!Array.isArray(interaction.pendingCommands)) {
      interaction.pendingCommands = [];
    }
    if (!Number.isInteger(interaction.nextCommandId) || interaction.nextCommandId < 1) {
      interaction.nextCommandId = 1;
    }
    interaction.inputLine ??= '';
    interaction.inputActor ??= null;
    interaction.inputBindingId ??= null;
    interaction.inputEscapeSequence ??= '';
    interaction.lastInputWasCarriageReturn ??= false;
    interaction.heuristicOutput ??= '';
    interaction.heuristicTimer ??= null;
  }

  if (!session.outputParser && !session.legacyInteractionObserverInstalled && session.emitter) {
    session.legacyInteractionObserverInstalled = true;
    session.emitter.on('data', (data) => observeHeuristicOutput(session, data));
    session.emitter.once('exit', () => clearHeuristicTimer(session));
  }
  return session.interaction;
}

function getSession(id) {
  const session = sessions.get(id);
  if (!session) {
    throw new Error(`Session ${id} not found`);
  }
  ensureInteractionState(session);
  return session;
}

function getSessionByUuid(uuid) {
  const session = uuidIndex.get(uuid);
  if (!session) {
    throw new Error(`Session ${uuid} not found`);
  }
  ensureInteractionState(session);
  return session;
}

function normalizeSessionRef(ref) {
  if (Number.isInteger(ref)) {
    return { id: ref, uuid: null };
  }

  if (typeof ref === 'string') {
    const trimmed = ref.trim();
    if (!trimmed) {
      return { id: null, uuid: null };
    }
    if (uuidIndex.has(trimmed)) {
      return { id: null, uuid: trimmed };
    }
    if (isNumericIdString(trimmed)) {
      const parsed = Number.parseInt(trimmed, 10);
      return Number.isNaN(parsed) ? { id: null, uuid: trimmed } : { id: parsed, uuid: null };
    }
    return { id: null, uuid: trimmed };
  }

  if (ref && typeof ref === 'object') {
    const providedUuid =
      normalizeTerminalUuid(ref.terminal_uuid)
      || normalizeTerminalUuid(ref.terminalUuid)
      || normalizeTerminalUuid(ref.terminalUUID);
    if (providedUuid) {
      return { id: null, uuid: providedUuid };
    }

    const possibleId =
      Number.isInteger(ref.terminal_id)
        ? ref.terminal_id
        : Number.isInteger(ref.terminalId)
            ? ref.terminalId
            : Number.isInteger(ref.id)
                ? ref.id
                : null;
    if (Number.isInteger(possibleId)) {
      return { id: possibleId, uuid: null };
    }

    if (typeof ref.terminal_id === 'string' && ref.terminal_id.trim()) {
      const trimmed = ref.terminal_id.trim();
      if (uuidIndex.has(trimmed)) {
        return { id: null, uuid: trimmed };
      }
      if (isNumericIdString(trimmed)) {
        const parsed = Number.parseInt(trimmed, 10);
        return Number.isNaN(parsed) ? { id: null, uuid: trimmed } : { id: parsed, uuid: null };
      }
      return { id: null, uuid: trimmed };
    }

    if (typeof ref.terminalId === 'string' && ref.terminalId.trim()) {
      const trimmed = ref.terminalId.trim();
      if (uuidIndex.has(trimmed)) {
        return { id: null, uuid: trimmed };
      }
      if (isNumericIdString(trimmed)) {
        const parsed = Number.parseInt(trimmed, 10);
        return Number.isNaN(parsed) ? { id: null, uuid: trimmed } : { id: parsed, uuid: null };
      }
      return { id: null, uuid: trimmed };
    }

    if (typeof ref.id === 'string' && ref.id.trim()) {
      const trimmed = ref.id.trim();
      if (uuidIndex.has(trimmed)) {
        return { id: null, uuid: trimmed };
      }
      if (isNumericIdString(trimmed)) {
        const parsed = Number.parseInt(trimmed, 10);
        return Number.isNaN(parsed) ? { id: null, uuid: trimmed } : { id: parsed, uuid: null };
      }
      return { id: null, uuid: trimmed };
    }
  }

  return { id: null, uuid: null };
}

function getSessionByRef(ref) {
  const { id, uuid } = normalizeSessionRef(ref);
  if (uuid) {
    return getSessionByUuid(uuid);
  }
  if (id !== null) {
    return getSession(id);
  }
  throw new Error('Session reference is required');
}

function mapTerminalTypeToPtyName(terminalType) {
  // Map terminal type to PTY terminal name (TERM environment variable)
  switch (terminalType) {
    case 'vt100':
      return 'vt100'; // VT100 terminal emulation (minimal features, good for most tasks)
    case 'xterm':
      return 'xterm'; // Xterm terminal emulation (more features, better compatibility)
    case 'ascii':
      return 'dumb'; // No ANSI escape codes (legacy support)
    case 'ansi':
      return 'ansi'; // ANSI escape codes (legacy support)
    default:
      return 'vt100'; // Default to vt100 for most tasks
  }
}

function trimBuffer(session) {
  // Trim buffer if it exceeds MAX_BUFFER_SIZE
  // Keep data that active readers still need
  if (session.buffer.length <= MAX_BUFFER_SIZE) {
    return;
  }

  // Find the minimum pointer position (oldest unread data)
  let minPointer = session.buffer.length;
  for (const pointer of session.readPointers.values()) {
    if (pointer < minPointer) {
      minPointer = pointer;
    }
  }

  // If no active readers or all readers are caught up, keep last 1MB
  const keepSize = 1 * 1024 * 1024;
  const trimPoint = session.readPointers.size === 0
    ? Math.max(0, session.buffer.length - keepSize)
    : minPointer;

  // Trim buffer and adjust all pointers
  if (trimPoint > 0) {
    session.buffer = session.buffer.slice(trimPoint);
    for (const [key, pointer] of session.readPointers.entries()) {
      session.readPointers.set(key, Math.max(0, pointer - trimPoint));
    }
  }
}

function normalizeWriteContext(options) {
  const normalized = options && typeof options === 'object' && !Array.isArray(options)
    ? options
    : {};
  const actor = typeof normalized.actor === 'string' && normalized.actor.trim()
    ? normalized.actor.trim()
    : 'unknown';
  const bindingId = typeof normalized.bindingId === 'string' && normalized.bindingId.trim()
    ? normalized.bindingId.trim()
    : null;
  return { actor, bindingId };
}

function serializeInteractionState(session) {
  const interaction = ensureInteractionState(session);
  return {
    terminal_id: session.id,
    terminal_uuid: session.terminalUuid,
    shellIntegration: { ...interaction.shellIntegration },
    alternateScreen: interaction.alternateScreen,
    promptReady: interaction.promptReady,
    currentCwd: interaction.currentCwd,
    lastInputAt: interaction.lastInputAt,
    lastOutputAt: interaction.lastOutputAt,
    lastCommand: interaction.lastCommand ? { ...interaction.lastCommand } : null,
    pendingCommandCount: interaction.pendingCommands.length
  };
}

function emitInteractionState(session, reason) {
  session.emitter.emit('interaction', {
    type: 'interaction',
    reason,
    timestamp: Date.now(),
    ...serializeInteractionState(session)
  });
}

function emitCommandEvent(session, details) {
  const event = {
    type: 'command',
    terminal_id: session.id,
    terminal_uuid: session.terminalUuid,
    commandId: details.commandId,
    inputCommandId: details.inputCommandId || null,
    command: details.command === null ? null : details.command ?? '',
    cwd: details.cwd || session.interaction.currentCwd || session.cwd,
    phase: details.phase,
    status: details.phase,
    exitCode: details.exitCode ?? null,
    likelyFailed: details.likelyFailed === true,
    exact: details.exact === true,
    detection: details.detection || 'heuristic',
    actor: details.actor || 'unknown',
    bindingId: details.bindingId || null,
    timestamp: Date.now()
  };
  session.interaction.lastCommand = event;
  session.emitter.emit('command', event);
  emitInteractionState(session, `command-${event.phase}`);
  return event;
}

function appendInputCharacter(session, character, context) {
  if (
    session.interaction.shellIntegration.mode === 'heuristic'
    && session.interaction.pendingCommands.length === 0
    && session.interaction.inputLine.length === 0
  ) {
    session.interaction.heuristicOutput = '';
  }
  session.interaction.inputLine += character;
  session.interaction.inputActor = context.actor;
  session.interaction.inputBindingId = context.bindingId;
  session.interaction.promptReady = false;
}

function submitInputLine(session, context) {
  const command = session.interaction.inputLine;
  const actor = context.actor !== 'unknown'
    ? context.actor
    : session.interaction.inputActor || 'unknown';
  const bindingId = context.bindingId || session.interaction.inputBindingId || null;
  session.interaction.inputLine = '';
  session.interaction.inputActor = null;
  session.interaction.inputBindingId = null;
  session.interaction.promptReady = false;

  if (!command.trim()) {
    return null;
  }

  const commandId = `input-${session.terminalUuid}-${session.interaction.nextCommandId}`;
  session.interaction.nextCommandId += 1;
  const pending = {
    commandId,
    command,
    cwd: session.interaction.currentCwd || session.cwd,
    actor,
    bindingId,
    shellCommandId: null
  };
  session.interaction.pendingCommands.push(pending);
  if (session.interaction.pendingCommands.length > 100) {
    session.interaction.pendingCommands.splice(
      0,
      session.interaction.pendingCommands.length - 100
    );
  }

  return emitCommandEvent(session, {
    ...pending,
    phase: 'submitted',
    exact: false,
    detection: 'input'
  });
}

function cancelInputLine(session, context) {
  const command = session.interaction.inputLine;
  const actor = context.actor !== 'unknown'
    ? context.actor
    : session.interaction.inputActor || 'unknown';
  const bindingId = context.bindingId || session.interaction.inputBindingId || null;
  session.interaction.inputLine = '';
  session.interaction.inputActor = null;
  session.interaction.inputBindingId = null;
  session.interaction.promptReady = null;
  if (!command.trim()) {
    return;
  }
  emitCommandEvent(session, {
    commandId: `input-${session.terminalUuid}-${session.interaction.nextCommandId}`,
    command,
    phase: 'cancelled',
    exact: false,
    detection: 'input',
    actor,
    bindingId
  });
  session.interaction.nextCommandId += 1;
}

function observeTerminalInput(session, data, context) {
  for (const character of String(data)) {
    if (session.interaction.inputEscapeSequence) {
      session.interaction.inputEscapeSequence += character;
      if (
        /[A-Za-z~]$/.test(session.interaction.inputEscapeSequence)
        || session.interaction.inputEscapeSequence.length > 32
      ) {
        session.interaction.inputEscapeSequence = '';
      }
      continue;
    }
    if (character === '\x1b') {
      session.interaction.inputEscapeSequence = character;
      continue;
    }
    if (character === '\r') {
      submitInputLine(session, context);
      session.interaction.lastInputWasCarriageReturn = true;
      continue;
    }
    if (character === '\n') {
      if (session.interaction.lastInputWasCarriageReturn) {
        session.interaction.lastInputWasCarriageReturn = false;
      } else {
        submitInputLine(session, context);
      }
      continue;
    }
    session.interaction.lastInputWasCarriageReturn = false;
    if (character === '\x03') {
      cancelInputLine(session, context);
      continue;
    }
    if (character === '\x15') {
      session.interaction.inputLine = '';
      continue;
    }
    if (character === '\x7f' || character === '\b') {
      session.interaction.inputLine = Array.from(session.interaction.inputLine)
        .slice(0, -1)
        .join('');
      continue;
    }
    if (character === '\t' || character < ' ') {
      continue;
    }
    appendInputCharacter(session, character, context);
  }
}

function normalizeCommandForMatch(value) {
  return String(value || '')
    .replace(/[;\r\n]+/g, ' ')
    .replace(/\s+/g, ' ')
    .trim();
}

function findPendingCommandGroup(session, marker) {
  const pendingCommands = session.interaction.pendingCommands;
  // A commandless completion cannot safely distinguish a multiline command from queued
  // typeahead. Clear the full queue rather than retaining stale actor attribution.
  if (marker.type === 'complete' && !marker.command) {
    return [...pendingCommands];
  }
  if (marker.commandId) {
    const byShellId = pendingCommands.filter(
      (pending) => pending.shellCommandId === marker.commandId
    );
    if (byShellId.length) {
      return byShellId;
    }
  }
  if (marker.command) {
    const normalizedCommand = marker.command.trim();
    const exactIndex = pendingCommands.findIndex(
      (pending) => pending.command.trim() === normalizedCommand
    );
    if (exactIndex !== -1) {
      return pendingCommands.slice(0, exactIndex + 1);
    }

    const normalizedMarker = normalizeCommandForMatch(marker.command);
    for (let count = 2; count <= pendingCommands.length; count += 1) {
      const combined = pendingCommands
        .slice(0, count)
        .map((pending) => pending.command)
        .join('\n');
      if (normalizeCommandForMatch(combined) === normalizedMarker) {
        return pendingCommands.slice(0, count);
      }
    }
  }
  return pendingCommands.length ? [pendingCommands[0]] : [];
}

function commonPendingValue(entries, key, fallback) {
  if (!entries.length) {
    return fallback;
  }
  const first = entries[0][key] ?? fallback;
  return entries.every((entry) => (entry[key] ?? fallback) === first) ? first : fallback;
}

function observeCommandMarker(session, marker) {
  if (marker.cwd) {
    session.interaction.currentCwd = marker.cwd;
  }
  if (marker.type === 'prompt') {
    session.interaction.promptReady = true;
    emitInteractionState(session, 'shell-prompt');
    return;
  }

  const pendingGroup = findPendingCommandGroup(session, marker);
  const pending = pendingGroup[0] || null;
  if (marker.commandId) {
    for (const entry of pendingGroup) {
      entry.shellCommandId = marker.commandId;
    }
  }
  const details = {
    commandId: marker.commandId || pending?.commandId || `shell-${randomUUID()}`,
    inputCommandId: pending?.commandId || null,
    // The authenticated marker makes lifecycle, cwd, and status exact. If the shell could not
    // provide command text (for example with history disabled), do not label one observed input
    // line as the exact command—especially for multiline input.
    command: marker.command || null,
    cwd: marker.cwd || pending?.cwd,
    phase: marker.type === 'start' ? 'started' : 'completed',
    exitCode: marker.type === 'complete' ? marker.exitCode : null,
    exact: true,
    detection: 'shell-marker',
    actor: commonPendingValue(pendingGroup, 'actor', 'unknown'),
    bindingId: commonPendingValue(pendingGroup, 'bindingId', null)
  };

  session.interaction.promptReady = marker.type === 'complete';
  if (marker.type === 'complete' && pendingGroup.length) {
    const consumed = new Set(pendingGroup);
    session.interaction.pendingCommands = session.interaction.pendingCommands.filter(
      (entry) => !consumed.has(entry)
    );
  }
  emitCommandEvent(session, details);
}

function clearHeuristicTimer(session) {
  const timer = session.interaction?.heuristicTimer;
  if (timer !== null && timer !== undefined) {
    clearTimeout(timer);
    session.interaction.heuristicTimer = null;
  }
}

function heuristicOutputLooksLikePrompt(value) {
  const plain = stripAnsiCodes(String(value || '')).replace(/\r/g, '');
  const lastLine = plain.split('\n').at(-1) || '';
  if (/\b(?:password|passphrase|token|otp|pin)\s*:\s*$/i.test(lastLine)) {
    return false;
  }
  return lastLine.length <= 500 && /(?:[$#%>]|❯|➜)\s*$/.test(lastLine);
}

function heuristicOutputLooksLikeFailure(value) {
  const plain = stripAnsiCodes(String(value || '')).replace(/\r/g, '');
  return (
    /(?:^|\n)[^\n]*(?:command not found|permission denied|no such file or directory)/i.test(plain)
    || /(?:^|\n)\s*(?:error|fatal|failed)\s*:/i.test(plain)
  );
}

function finalizeHeuristicPrompt(session) {
  const interaction = session.interaction;
  if (
    interaction.shellIntegration.mode !== 'heuristic'
    || !heuristicOutputLooksLikePrompt(interaction.heuristicOutput)
  ) {
    return false;
  }

  clearHeuristicTimer(session);
  // Heuristic prompt recognition is sufficient for feedback scheduling, but not strong enough
  // to authorize terminal control. `null` keeps Insert/Autonomous fail-closed.
  interaction.promptReady = null;
  const pendingGroup = [...interaction.pendingCommands];
  interaction.pendingCommands = [];
  if (!pendingGroup.length) {
    interaction.heuristicOutput = '';
    emitInteractionState(session, 'heuristic-shell-prompt');
    return true;
  }

  const command = pendingGroup.map((entry) => entry.command).join('\n');
  const failed = heuristicOutputLooksLikeFailure(interaction.heuristicOutput);
  interaction.heuristicOutput = '';
  emitCommandEvent(session, {
    commandId: pendingGroup[0].commandId,
    inputCommandId: pendingGroup[0].commandId,
    command,
    cwd: pendingGroup[0].cwd,
    phase: 'completed',
    exitCode: null,
    likelyFailed: failed,
    exact: false,
    detection: 'heuristic-prompt',
    actor: commonPendingValue(pendingGroup, 'actor', 'unknown'),
    bindingId: commonPendingValue(pendingGroup, 'bindingId', null)
  });
  return true;
}

function observeHeuristicOutput(session, data) {
  const interaction = ensureInteractionState(session);
  if (interaction.shellIntegration.mode !== 'heuristic') {
    return;
  }
  interaction.heuristicOutput = `${interaction.heuristicOutput}${String(data || '')}`
    .slice(-MAX_HEURISTIC_OUTPUT_CHARS);
  clearHeuristicTimer(session);
  interaction.heuristicTimer = setTimeout(() => {
    interaction.heuristicTimer = null;
    finalizeHeuristicPrompt(session);
  }, HEURISTIC_PROMPT_IDLE_MS);
  interaction.heuristicTimer.unref?.();
}

function prepareHeuristicForInput(session) {
  if (session.interaction.shellIntegration.mode !== 'heuristic') {
    return;
  }
  if (!finalizeHeuristicPrompt(session)) {
    clearHeuristicTimer(session);
  }
}

export function spawnTerminal(options = {}, internalOptions = {}) {
  const shell = options.shell || defaultShell;
  const args = Array.isArray(options.args) ? options.args : null;
  const command = typeof options.command === 'string' && options.command.length
    ? options.command
    : null;
  const cols = options.cols ?? 80;
  const rows = options.rows ?? 30;
  validateTerminalDimensions(cols, rows);
  const id = generateId();
  const cwdInfo = resolveCwd(options.cwd);
  const cwd = cwdInfo.cwd;
  const terminalType = options.terminalType || 'vt100'; // Default to 'vt100' for most tasks
  const metadata = normalizeTerminalMetadata(options.metadata);
  let spawnEnv = buildSpawnEnv(internalOptions.env);
  const requestedUuid =
    normalizeTerminalUuid(options.terminal_uuid)
    || normalizeTerminalUuid(options.terminalUuid);
  let terminalUuid = requestedUuid || randomUUID();
  if (uuidIndex.has(terminalUuid)) {
    if (requestedUuid) {
      throw new Error(`terminal_uuid ${terminalUuid} already exists`);
    }
    do {
      terminalUuid = randomUUID();
    } while (uuidIndex.has(terminalUuid));
  }
  const ptyName = mapTerminalTypeToPtyName(terminalType);

  let spawnArgs = args ?? (command ? ['-c', command] : []);
  const shellIntegration = configureShellIntegration({
    shell,
    spawnArgs,
    command,
    spawnEnv,
    requested: options.shellIntegration
  });
  spawnArgs = shellIntegration.args;
  spawnEnv = shellIntegration.env;

  const proc = pty.spawn(shell, spawnArgs, {
    name: ptyName, // This sets the TERM environment variable
    cols,
    rows,
    cwd,
    env: spawnEnv
  });

  const emitter = new EventEmitter();
  const session = {
    id,
    terminalUuid,
    proc,
    shell,
    cols,
    rows,
    cwd,
    terminalType,
    metadata,
    buffer: '',
    readPointers: new Map(),
    nextReaderId: 1,
    emitter,
    interaction: null,
    markerNonce: shellIntegration.markerNonce || randomBytes(16).toString('hex'),
    createdAt: new Date().toISOString()
  };
  session.interaction = createInteractionState(session, shellIntegration.state);

  session.outputParser = createTerminalOutputParser({
    markerNonce: session.markerNonce,
    onCommandMarker: (marker) => observeCommandMarker(session, marker),
    onAlternateScreen: (active) => {
      session.interaction.alternateScreen = active;
      emitInteractionState(session, 'alternate-screen');
    }
  });

  proc.onData((data) => {
    const visibleData = session.outputParser.push(data);
    if (!visibleData) {
      return;
    }
    session.interaction.lastOutputAt = Date.now();
    session.buffer += visibleData;
    trimBuffer(session);
    emitter.emit('data', visibleData);
    observeHeuristicOutput(session, visibleData);
  });

  proc.onExit((info) => {
    clearHeuristicTimer(session);
    const remainingOutput = session.outputParser.flush();
    if (remainingOutput) {
      session.interaction.lastOutputAt = Date.now();
      session.buffer += remainingOutput;
      trimBuffer(session);
      emitter.emit('data', remainingOutput);
    }
    emitter.emit('exit', info);
    emitter.removeAllListeners();
    sessions.delete(id);
    uuidIndex.delete(terminalUuid);
  });

  sessions.set(id, session);
  uuidIndex.set(terminalUuid, session);
  logTerminalEvent({
    op: 'spawnTerminal',
    terminal_id: id,
    terminal_uuid: terminalUuid,
    shell,
    cols,
    rows,
    cwd,
    terminalType,
    shell_integration: shellIntegration.state.mode,
    has_command: Boolean(command),
    args_count: spawnArgs.length
  });
  const summary = buildSummary(session);
  if (cwdInfo.usedFallback) {
    summary.cwd_fallback = true;
    summary.cwd_requested = cwdInfo.requestedCwd;
    summary.cwd_notice =
      'Requested cwd not found on the terminal host; falling back to the server home directory. MCP client and terminal host filesystems are different.';
  }
  return summary;
}

export function writeToTerminal(id, data, options = {}) {
  const session = getSessionByRef(id);
  const context = normalizeWriteContext(options);
  prepareHeuristicForInput(session);
  session.proc.write(data);
  session.interaction.lastInputAt = Date.now();
  const inputEvent = {
    type: 'input',
    terminal_id: session.id,
    terminal_uuid: session.terminalUuid,
    data,
    bytes: data.length,
    submitted: /[\r\n]/.test(data),
    actor: context.actor,
    bindingId: context.bindingId,
    timestamp: session.interaction.lastInputAt
  };
  session.emitter.emit('input', inputEvent);
  observeTerminalInput(session, data, context);
  logTerminalEvent({
    op: 'writeToTerminal',
    terminal_id: session.id,
    terminal_uuid: session.terminalUuid,
    bytes: data.length,
    actor: context.actor,
    binding_id: context.bindingId
  });
  return data.length;
}

const DEFAULT_READER_KEY = 'default';

function stripAnsiCodes(text) {
  // Remove ANSI escape sequences for ASCII-only terminals
  // This handles:
  // - CSI sequences: ESC [ ... (final byte @-~)
  // - OSC sequences: ESC ] ... (terminated by BEL or ESC \)
  // - Other escape sequences: ESC c, ESC 7, ESC 8, etc.
  // eslint-disable-next-line no-control-regex
  return text
    // Remove CSI sequences (ESC [ ... final_byte)
    // Final byte is in range 0x40-0x7E (@-~)
    .replace(/\x1b\[[0-9;?]*[@-~]/g, '')
    // Remove OSC sequences (ESC ] ... BEL or ESC \)
    .replace(/\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)/g, '')
    // Remove other common escape sequences
    .replace(/\x1b[=>c78DEHM]/g, '')
    // Remove 8-bit CSI (0x9B)
    .replace(/\x9b[0-9;?]*[@-~]/g, '');
}

function readFromPointer(session, key) {
  const pointer = session.readPointers.get(key);
  if (pointer === undefined) {
    throw new Error(`Reader ${String(key)} is not registered for session ${session.id}`);
  }
  let data = session.buffer.slice(pointer);

  // Strip ANSI codes if terminal type is ASCII (legacy plain text mode)
  if (session.terminalType === 'ascii') {
    data = stripAnsiCodes(data);
  }

  session.readPointers.set(key, session.buffer.length);
  return data;
}

function registerPointer(session, key, includeHistory) {
  if (!session.readPointers.has(key)) {
    const start = includeHistory ? 0 : session.buffer.length;
    session.readPointers.set(key, start);
  }
}

export function readTerminal(id) {
  const session = getSessionByRef(id);
  registerPointer(session, DEFAULT_READER_KEY, true);
  const data = readFromPointer(session, DEFAULT_READER_KEY);
  if (shouldLogReads()) {
    logTerminalEvent({
      op: 'readTerminal',
      terminal_id: session.id,
      terminal_uuid: session.terminalUuid,
      bytes: data.length,
      reader_key: DEFAULT_READER_KEY,
      include_history: true
    });
  }
  return data;
}

export function resizeTerminal(id, cols, rows) {
  validateTerminalDimensions(cols, rows);
  const session = getSessionByRef(id);
  session.proc.resize(cols, rows);
  session.cols = cols;
  session.rows = rows;
  logTerminalEvent({
    op: 'resizeTerminal',
    terminal_id: session.id,
    terminal_uuid: session.terminalUuid,
    cols,
    rows
  });
  return buildSummary(session);
}

export function killTerminal(id) {
  const session = getSessionByRef(id);

  // Send kill signal to the process
  session.proc.kill();
  logTerminalEvent({
    op: 'killTerminal',
    terminal_id: session.id,
    terminal_uuid: session.terminalUuid
  });

  // DON'T delete the session immediately - let the exit handler clean it up
  // This ensures we maintain a reference to the session until the process actually exits
  // If the process is stubborn and doesn't die, we can still interact with it or try again

  // The exit handler (set up in spawnTerminal) will delete the session when the process exits
  return true;
}

export function listTerminals() {
  const list = Array.from(sessions.values()).map(buildSummary);
  logTerminalEvent({
    op: 'listTerminals',
    count: list.length
  });
  return list;
}

export function listTerminalsByMetadata(criteria = {}) {
  const entries = Object.entries(criteria);
  return Array.from(sessions.values())
    .filter((session) => {
      if (!session.metadata) {
        return false;
      }
      return entries.every(([key, value]) => session.metadata[key] === value);
    })
    .map(buildSummary);
}

export function createTerminalReader(id, options = {}) {
  const session = getSessionByRef(id);
  const includeHistory = options.includeHistory ?? false;
  const persistent = options.persistent ?? false;

  // Use provided key for persistent readers, or generate unique key for temporary readers
  const readerKey = persistent && options.key
    ? `persistent:${options.key}`
    : `reader:${session.nextReaderId}`;

  if (!persistent) {
    session.nextReaderId += 1;
  }

  registerPointer(session, readerKey, includeHistory);

  logTerminalEvent({
    op: 'createTerminalReader',
    terminal_id: session.id,
    terminal_uuid: session.terminalUuid,
    include_history: includeHistory,
    persistent,
    reader_key: readerKey
  });

  const read = () => {
    const data = readFromPointer(session, readerKey);
    if (shouldLogReads()) {
      logTerminalEvent({
        op: 'readTerminal',
        terminal_id: session.id,
        terminal_uuid: session.terminalUuid,
        bytes: data.length,
        reader_key: readerKey,
        include_history: includeHistory
      });
    }
    return data;
  };

  const dispose = () => {
    session.readPointers.delete(readerKey);
    logTerminalEvent({
      op: 'disposeTerminalReader',
      terminal_id: session.id,
      terminal_uuid: session.terminalUuid,
      reader_key: readerKey
    });
  };

  const getPointer = () => session.readPointers.get(readerKey) ?? session.buffer.length;

  return {
    read,
    dispose,
    key: readerKey,
    getPointer,
    terminal_id: session.id,
    terminal_uuid: session.terminalUuid
  };
}

export function subscribeToTerminal(id, listener) {
  const session = getSessionByRef(id);
  session.emitter.on('data', listener);
  logTerminalEvent({
    op: 'subscribeToTerminal',
    terminal_id: session.id,
    terminal_uuid: session.terminalUuid
  });
  return () => {
    session.emitter.off('data', listener);
    logTerminalEvent({
      op: 'unsubscribeFromTerminal',
      terminal_id: session.id,
      terminal_uuid: session.terminalUuid
    });
  };
}

export function subscribeToTerminalInput(id, listener) {
  const session = getSessionByRef(id);
  session.emitter.on('input', listener);
  return () => {
    session.emitter.off('input', listener);
  };
}

export function subscribeToTerminalCommand(id, listener) {
  const session = getSessionByRef(id);
  session.emitter.on('command', listener);
  return () => {
    session.emitter.off('command', listener);
  };
}

export function subscribeToTerminalInteraction(id, listener) {
  const session = getSessionByRef(id);
  session.emitter.on('interaction', listener);
  return () => {
    session.emitter.off('interaction', listener);
  };
}

export function getTerminalInteractionState(id) {
  return serializeInteractionState(getSessionByRef(id));
}

export function onTerminalExit(id, listener) {
  const session = getSessionByRef(id);
  session.emitter.on('exit', listener);
  logTerminalEvent({
    op: 'subscribeToTerminalExit',
    terminal_id: session.id,
    terminal_uuid: session.terminalUuid
  });
  return () => {
    session.emitter.off('exit', listener);
    logTerminalEvent({
      op: 'unsubscribeFromTerminalExit',
      terminal_id: session.id,
      terminal_uuid: session.terminalUuid
    });
  };
}

export function getTerminalSummary(id) {
  const summary = buildSummary(getSessionByRef(id));
  logTerminalEvent({
    op: 'getTerminalSummary',
    terminal_id: summary.id,
    terminal_uuid: summary.terminal_uuid
  });
  return summary;
}

export function setTerminalType(id, terminalType, options = {}) {
  const validTypes = ['vt100', 'xterm', 'ansi', 'ascii'];
  if (!validTypes.includes(terminalType)) {
    throw new Error('terminalType must be one of: vt100, xterm, ansi, ascii');
  }
  const session = getSessionByRef(id);
  const termName = mapTerminalTypeToPtyName(terminalType);
  writeToTerminal(id, `export TERM='${termName}'\r`, options);
  session.terminalType = terminalType;
  logTerminalEvent({
    op: 'setTerminalType',
    terminal_id: session.id,
    terminal_uuid: session.terminalUuid,
    terminalType
  });
  return buildSummary(session);
}

export function inspectTerminal(id) {
  const session = getSessionByRef(id);
  const bufferBytesUsed = session.buffer.length;
  const inspection = {
    id: session.id,
    terminal_uuid: session.terminalUuid,
    terminalType: session.terminalType,
    shell: session.shell,
    cwd: session.cwd,
    interaction: serializeInteractionState(session),
    bufferBytesUsed,
    maxBufferBytes: MAX_BUFFER_SIZE,
    bufferUtilization: MAX_BUFFER_SIZE > 0
      ? Math.min(100, (bufferBytesUsed / MAX_BUFFER_SIZE) * 100)
      : null
  };
  if (session.metadata) {
    inspection.metadata = { ...session.metadata };
  }
  logTerminalEvent({
    op: 'inspectTerminal',
    terminal_id: session.id,
    terminal_uuid: session.terminalUuid,
    buffer_bytes_used: bufferBytesUsed
  });
  return inspection;
}
