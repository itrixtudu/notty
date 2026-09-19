import {
  spawnTerminal,
  writeToTerminal,
  createTerminalReader
} from './terminalManager.js';
import { withLogContext } from './terminalLogging.js';
import { getSpawnOtpConfig, isSpawnOtpProtected } from './mcpSpawnOtp.js';

const DEFAULT_IDLE_TIMEOUT_MS = 500;
const DEFAULT_MAX_WAIT_MS = 20000;
const DEFAULT_POLL_INTERVAL_MS = 100;

const ESC = '\u001b';

const KEY_SEQUENCES = new Map([
  ['enter', '\r'],
  ['return', '\r'],
  ['tab', '\t'],
  ['up', '\u001b[A'],
  ['down', '\u001b[B'],
  ['left', '\u001b[D'],
  ['right', '\u001b[C'],
  ['pageup', '\u001b[5~'],
  ['pagedown', '\u001b[6~'],
  ['home', '\u001b[H'],
  ['end', '\u001b[F'],
  ['esc', ESC],
  ['escape', ESC],
  ['ctrl+c', '\u0003'],
  ['ctrl+d', '\u0004'],
  ['backspace', '\u007f'],
  ['space', ' ']
]);

const FUNCTION_KEY_SEQUENCES = new Map([
  ['f1', '\u001bOP'],
  ['f2', '\u001bOQ'],
  ['f3', '\u001bOR'],
  ['f4', '\u001bOS'],
  ['f5', '\u001b[15~'],
  ['f6', '\u001b[17~'],
  ['f7', '\u001b[18~'],
  ['f8', '\u001b[19~'],
  ['f9', '\u001b[20~'],
  ['f10', '\u001b[21~']
]);

const DURDRAW_ACTIONS = new Map([
  ['menu', 'm'],
  ['help', escSequenceForKey('h')],
  ['quit', escSequenceForKey('q')],
  ['save', escSequenceForKey('s')],
  ['open', escSequenceForKey('o')],
  ['new', escSequenceForKey('C')],
  ['clear', escSequenceForKey('C')],
  ['colorpicker', '\t'],
  ['colorpickeresc', escSequenceForKey('c')],
  ['nextfgcolor', escSequenceForKey('up')],
  ['colorup', escSequenceForKey('up')],
  ['colordown', escSequenceForKey('down')],
  ['colorleft', escSequenceForKey('left')],
  ['colorright', escSequenceForKey('right')],
  ['frameprev', escSequenceForKey('j')],
  ['framenext', escSequenceForKey('k')],
  ['frameclone', escSequenceForKey('n')],
  ['frameappend', escSequenceForKey('N')],
  ['play', escSequenceForKey('p')],
  ['toggleplay', escSequenceForKey('p')],
  ['info', escSequenceForKey('i')],
  ['viewer', escSequenceForKey('V')],
  ['gotoframe', escSequenceForKey('g')],
  ['fpsup', escSequenceForKey('+')],
  ['fpsdown', escSequenceForKey('-')],
  ['setrange', escSequenceForKey('R')],
  ['chargroupprev', escSequenceForKey('[')],
  ['chargroupnext', escSequenceForKey(']')]
]);

for (let i = 1; i <= 9; i += 1) {
  DURDRAW_ACTIONS.set(`block${i}`, escSequenceForKey(String(i)));
}
DURDRAW_ACTIONS.set('block0', escSequenceForKey('0'));
DURDRAW_ACTIONS.set('block10', escSequenceForKey('0'));

export function getToolDefinitions() {
  const spawnOtpEnabled = isSpawnOtpProtected();

  return [
    {
      name: 'spawn_durdraw',
      description: [
        'Spawn a new terminal session and launch Durdraw (TUI).',
        'Options map to durdraw CLI (play, times, wait, colorMode, width, height, max, noMouse, cursor, theme, noTheme, blackBg, cp437, exportAnsi, undoSize).',
        spawnOtpEnabled
          ? 'A one-time OTP is required to spawn a terminal.'
          : 'No parameters are required.',
        'Returns terminal_uuid to be used for subsequent Durdraw calls.'
      ]
        .filter(Boolean)
        .join(' '),
      inputSchema: {
        type: 'object',
        properties: {
          cols: { type: 'number', default: 80 },
          rows: { type: 'number', default: 30 },
          cwd: { type: 'string', description: 'Working directory for new session.' },
          terminalType: {
            type: 'string',
            description: 'Terminal type for new sessions.',
            enum: ['vt100', 'xterm', 'ansi', 'ascii']
          },
          command: {
            type: 'string',
            description:
              'Optional raw command string to run instead of building durdraw args.'
          },
          filename: { type: 'string', description: 'File to open in edit mode.' },
          files: {
            type: 'array',
            items: { type: 'string' },
            description: 'Files to play in --play mode.'
          },
          play: { type: 'boolean', description: 'Use play-only mode (-p/--play).' },
          times: { type: 'number', description: 'Loop count for play mode (--times).' },
          wait: { type: 'boolean', description: 'Wait at end of playback (--wait).' },
          startup: { type: 'boolean', description: 'Start in playback mode (--startup).' },
          colorMode: {
            type: 'string',
            enum: ['256', '16'],
            description: 'Color mode: 256 or 16.'
          },
          blackBg: { type: 'boolean', description: 'Force black background (--blackbg).' },
          width: { type: 'number', description: 'Canvas width (--width).' },
          height: { type: 'number', description: 'Canvas height (--height).' },
          max: { type: 'boolean', description: 'Maximize canvas size (--max).' },
          noMouse: { type: 'boolean', description: 'Disable mouse (--nomouse).' },
          cursor: {
            type: 'string',
            enum: ['block', 'underscore', 'pipe'],
            description: 'Cursor style (--cursor).'
          },
          noTheme: { type: 'boolean', description: 'Disable theme (--notheme).' },
          theme: { type: 'string', description: 'Theme file (--theme).' },
          cp437: { type: 'boolean', description: 'Use CP437 encoding (--cp437).' },
          exportAnsi: { type: 'boolean', description: 'Export ANSI (--export-ansi).' },
          undoSize: { type: 'number', description: 'Undo buffer size (--undosize).' },
          extraArgs: {
            type: 'array',
            items: { type: 'string' },
            description: 'Additional CLI args appended to durdraw.'
          },
          ...(spawnOtpEnabled
            ? {
                otp: {
                  type: 'string',
                  description: 'One-time terminal spawn OTP.'
                }
              }
            : {})
        },
        required: []
      }
    },
    {
      name: 'durdraw_action',
      description: [
        'Send a named Durdraw action or key combo to a session.',
        'Actions map to the observed keymap: menu(m), help(esc-h), quit(esc-q), save(esc-s), open(esc-o), new/clear(esc-C),',
        'color_picker(tab or esc-c), next_fg_color(esc-up), frame_prev(esc-j), frame_next(esc-k), frame_clone(esc-n), frame_append(esc-N), play(esc-p),',
        'info(esc-i), viewer(esc-V), fps_up(esc-+), fps_down(esc--), set_range(esc-R), char_group_prev(esc-[), char_group_next(esc-]).',
        'You can also pass raw keys like "tab", "up", "esc-q", "f1".'
      ].join(' '),
      inputSchema: {
        type: 'object',
        properties: {
          terminal_id: { type: 'number' },
          terminal_uuid: { type: 'string' },
          action: { type: 'string', description: 'Action name or key combo.' },
          await_output: {
            type: 'boolean',
            description: 'Wait for output to become idle after sending the action.'
          },
          idle_timeout_ms: { type: 'number' },
          max_wait_ms: { type: 'number' },
          poll_interval_ms: { type: 'number' }
        },
        required: ['action']
      }
    },
    {
      name: 'durdraw_text',
      description:
        'Type literal text into the Durdraw session. Supports \\n, \\r, \\t escape sequences. Use append_enter to send Enter after the text.',
      inputSchema: {
        type: 'object',
        properties: {
          terminal_id: { type: 'number' },
          terminal_uuid: { type: 'string' },
          text: { type: 'string', description: 'Text to type.' },
          append_enter: {
            type: 'boolean',
            description: 'Append Enter (\\r) if the text does not already end with a newline.'
          },
          await_output: {
            type: 'boolean',
            description: 'Wait for output to become idle after typing the text.'
          },
          idle_timeout_ms: { type: 'number' },
          max_wait_ms: { type: 'number' },
          poll_interval_ms: { type: 'number' }
        },
        required: ['text']
      }
    },
    {
      name: 'read_terminal',
      description:
        'Read buffered output from a terminal session using a persistent reader scoped to Durdraw.',
      inputSchema: {
        type: 'object',
        properties: {
          terminal_id: { type: 'number' },
          terminal_uuid: { type: 'string' }
        },
        required: []
      }
    }
  ];
}

export const toolDefinitions = getToolDefinitions();

export async function callTool(name, args = {}) {
  return withLogContext({ source: 'mcpDurdraw', tool: name }, async () => {
    try {
      switch (name) {
        case 'spawn_durdraw': {
          const commandResult = buildDurdrawCommand(args);
          if (commandResult.error) {
            return wrapError(commandResult.error);
          }

          const session = spawnTerminal({
            cols: args.cols,
            rows: args.rows,
            cwd: args.cwd,
            terminalType: 'xterm',
            otp: args.otp
          });

          const commandPayload = normalizeCommandPayload(commandResult.command);
          const bytes = writeToTerminal(
            { terminal_uuid: session.terminal_uuid },
            commandPayload,
            { actor: 'agent-mcp' }
          );

          return wrapJson({
            terminal_uuid: session.terminal_uuid,
            command: commandResult.command,
            bytes_written: bytes,
            note: 'All subsequent tool calls require this terminal_uuid.'
          });
        }

        case 'durdraw_action': {
          const terminalRef = resolveTerminalRef(args);
          if (!terminalRef) {
            return wrapError('terminal reference is required');
          }
          const action = typeof args.action === 'string' ? args.action.trim() : '';
          if (!action) {
            return wrapError('action is required');
          }

          const sequence = resolveDurdrawSequence(action);
          if (!sequence) {
            return wrapError(`Unknown action or key: ${action}`);
          }

          const result = await writeAndMaybeWait(terminalRef, sequence, args);

          return wrapJson({
            terminal_id: Number.isInteger(args.terminal_id)
              ? args.terminal_id
              : Number.isInteger(args.terminalId)
                  ? args.terminalId
                  : undefined,
            terminal_uuid:
              typeof args.terminal_uuid === 'string'
                ? args.terminal_uuid
                : typeof args.terminalUuid === 'string'
                    ? args.terminalUuid
                    : undefined,
            action,
            ...result
          });
        }

        case 'durdraw_text': {
          const terminalRef = resolveTerminalRef(args);
          if (!terminalRef) {
            return wrapError('terminal reference is required');
          }
          const text = typeof args.text === 'string' ? args.text : null;
          if (text === null || text === undefined || text.length === 0) {
            return wrapError('text is required');
          }

          const payload = normalizeTextPayload(text, args.append_enter);
          const result = await writeAndMaybeWait(terminalRef, payload, args);

          return wrapJson({
            terminal_id: Number.isInteger(args.terminal_id)
              ? args.terminal_id
              : Number.isInteger(args.terminalId)
                  ? args.terminalId
                  : undefined,
            terminal_uuid:
              typeof args.terminal_uuid === 'string'
                ? args.terminal_uuid
                : typeof args.terminalUuid === 'string'
                    ? args.terminalUuid
                    : undefined,
            bytes_written: result.bytes_written,
            ...(result.output !== undefined
              ? {
                  output: result.output,
                  has_output: result.has_output,
                  idle_timeout_ms: result.idle_timeout_ms,
                  max_wait_ms: result.max_wait_ms,
                  poll_interval_ms: result.poll_interval_ms,
                  timed_out: result.timed_out,
                  elapsed_ms: result.elapsed_ms
                }
              : {})
          });
        }

        case 'read_terminal': {
          const terminalRef = resolveTerminalRef(args);
          if (!terminalRef) {
            return wrapError('terminal reference is required');
          }

          const reader = createTerminalReader(terminalRef, {
            includeHistory: true,
            persistent: true,
            key: 'durdraw_reader'
          });

          const output = reader.read();

          return wrapJson({
            terminal_id: reader.terminal_id,
            terminal_uuid: reader.terminal_uuid,
            output: output || '',
            has_output: output.length > 0,
            pointer_position: reader.getPointer()
          });
        }

        default:
          return wrapError(`Unknown tool: ${name}`);
      }
    } catch (err) {
      return err?.code
        ? wrapErrorJson(err.code, err.message || 'Unknown error')
        : wrapError(err.message || 'Unknown error');
    }
  });
}

function normalizeActionName(name) {
  return name
    .trim()
    .toLowerCase()
    .replace(/\s+/g, '')
    .replace(/[_-]+/g, '');
}

function resolveDurdrawActionSequence(name) {
  if (typeof name !== 'string') {
    return null;
  }
  const normalized = normalizeActionName(name);
  return DURDRAW_ACTIONS.get(normalized) || null;
}

function normalizeKeyName(name) {
  return name
    .trim()
    .toLowerCase()
    .replace(/\s+/g, '')
    .replace(/control/g, 'ctrl')
    .replace(/-/g, '+');
}

function resolveFunctionKeySequence(normalizedKey) {
  if (FUNCTION_KEY_SEQUENCES.has(normalizedKey)) {
    return FUNCTION_KEY_SEQUENCES.get(normalizedKey);
  }
  return null;
}

function resolveKeySequence(keyName) {
  if (typeof keyName !== 'string') {
    return null;
  }
  const trimmed = keyName.trim();
  if (!trimmed) {
    return null;
  }
  if (trimmed.length === 1) {
    return trimmed;
  }

  const normalized = normalizeKeyName(trimmed);
  if (KEY_SEQUENCES.has(normalized)) {
    return KEY_SEQUENCES.get(normalized);
  }

  return resolveFunctionKeySequence(normalized);
}

function extractEscRemainder(value) {
  if (typeof value !== 'string') {
    return null;
  }
  const trimmed = value.trim();
  if (!trimmed) {
    return null;
  }
  const lower = trimmed.toLowerCase();
  const prefixes = ['esc-', 'esc+', 'esc ', 'escape-', 'escape+', 'escape '];
  for (const prefix of prefixes) {
    if (lower.startsWith(prefix)) {
      return trimmed.slice(prefix.length);
    }
  }
  return null;
}

function resolveDurdrawSequence(value) {
  if (typeof value !== 'string') {
    return null;
  }
  const actionSequence = resolveDurdrawActionSequence(value);
  if (actionSequence) {
    return actionSequence;
  }

  const escRemainder = extractEscRemainder(value);
  if (escRemainder) {
    const sequence = resolveKeySequence(escRemainder);
    if (sequence) {
      return `${ESC}${sequence}`;
    }
  }

  return resolveKeySequence(value);
}

function escSequenceForKey(keyName) {
  const sequence = resolveKeySequence(keyName);
  if (!sequence) {
    return null;
  }
  return `${ESC}${sequence}`;
}

function resolveTerminalRef(args) {
  if (!args || typeof args !== 'object') {
    return null;
  }

  const spawnOtpConfig = getSpawnOtpConfig();
  if (spawnOtpConfig.otp) {
    if (typeof args.terminal_uuid === 'string' && args.terminal_uuid.trim()) {
      return { terminal_uuid: args.terminal_uuid.trim() };
    }
    if (typeof args.terminalUuid === 'string' && args.terminalUuid.trim()) {
      return { terminal_uuid: args.terminalUuid.trim() };
    }
    return null;
  }

  if (typeof args.terminal_uuid === 'string' && args.terminal_uuid.trim()) {
    return { terminal_uuid: args.terminal_uuid.trim() };
  }
  if (typeof args.terminalUuid === 'string' && args.terminalUuid.trim()) {
    return { terminal_uuid: args.terminalUuid.trim() };
  }

  if (Number.isInteger(args.terminal_id)) {
    return args.terminal_id;
  }
  if (Number.isInteger(args.terminalId)) {
    return args.terminalId;
  }

  if (typeof args.terminal_id === 'string' && args.terminal_id.trim()) {
    return args.terminal_id.trim();
  }
  if (typeof args.terminalId === 'string' && args.terminalId.trim()) {
    return args.terminalId.trim();
  }

  return null;
}

function normalizeCommandPayload(command) {
  const decoded = decodeEscapeSequences(command);
  if (decoded.endsWith('\n') || decoded.endsWith('\r')) {
    return decoded;
  }
  return `${decoded}\r`;
}

function normalizeTextPayload(text, appendEnter) {
  const decoded = decodeEscapeSequences(text);
  if (appendEnter && !decoded.endsWith('\n') && !decoded.endsWith('\r')) {
    return `${decoded}\r`;
  }
  return decoded;
}

function decodeEscapeSequences(data) {
  if (typeof data !== 'string' || !data.includes('\\')) {
    return data;
  }

  return data.replace(/\\(n|r|t|\\)/g, (_, ch) => {
    switch (ch) {
      case 'n':
        return '\n';
      case 'r':
        return '\r';
      case 't':
        return '\t';
      case '\\':
        return '\\';
      default:
        return ch;
    }
  });
}

function getNumberEnv(name, fallback) {
  const value = Number.parseInt(process.env[name], 10);
  if (Number.isFinite(value) && value >= 0) {
    return value;
  }
  return fallback;
}

function getNumberArg(value, fallback) {
  const parsed = Number.parseInt(value, 10);
  if (Number.isFinite(parsed) && parsed >= 0) {
    return parsed;
  }
  return fallback;
}

export function buildDurdrawCommand(args) {
  if (typeof args.command === 'string' && args.command.trim()) {
    return { command: args.command.trim() };
  }

  const parts = ['durdraw'];
  const play = args.play === true;
  const files = resolveDurdrawFiles(args);

  if (play) {
    if (files.length === 0) {
      return { error: 'play mode requires files or filename' };
    }
    parts.push('--play', ...files);
  }

  if (Number.isFinite(args.times)) {
    parts.push('--times', String(args.times));
  }
  if (args.wait) {
    parts.push('--wait');
  }
  if (args.startup) {
    parts.push('--startup');
  }
  if (args.colorMode === '256') {
    parts.push('--256color');
  }
  if (args.colorMode === '16') {
    parts.push('--16color');
  }
  if (args.blackBg) {
    parts.push('--blackbg');
  }
  if (Number.isFinite(args.width)) {
    parts.push('--width', String(args.width));
  }
  if (Number.isFinite(args.height)) {
    parts.push('--height', String(args.height));
  }
  if (args.max) {
    parts.push('--max');
  }
  if (args.noMouse) {
    parts.push('--nomouse');
  }
  if (args.cursor) {
    parts.push('--cursor', args.cursor);
  }
  if (args.noTheme) {
    parts.push('--notheme');
  }
  if (args.theme) {
    parts.push('--theme', args.theme);
  }
  if (args.cp437) {
    parts.push('--cp437');
  }
  if (args.exportAnsi) {
    parts.push('--export-ansi');
  }
  if (Number.isFinite(args.undoSize)) {
    parts.push('--undosize', String(args.undoSize));
  }

  if (!play && files.length > 0) {
    parts.push(files[0]);
  }

  if (Array.isArray(args.extraArgs)) {
    for (const extra of args.extraArgs) {
      if (typeof extra === 'string' && extra.trim()) {
        parts.push(extra.trim());
      }
    }
  }

  return { command: parts.map(quoteShellArg).join(' ') };
}

function resolveDurdrawFiles(args) {
  const files = [];
  if (Array.isArray(args.files)) {
    for (const file of args.files) {
      if (typeof file === 'string' && file.trim()) {
        files.push(file.trim());
      }
    }
  }

  if (files.length === 0 && typeof args.filename === 'string' && args.filename.trim()) {
    files.push(args.filename.trim());
  }

  return files;
}

async function writeAndMaybeWait(terminalRef, payload, args) {
  const awaitOutput = args.await_output === true;
  let reader = null;

  if (awaitOutput) {
    reader = createTerminalReader(terminalRef, {
      includeHistory: false,
      persistent: false
    });
  }

  const bytes = writeToTerminal(terminalRef, payload, { actor: 'agent-mcp' });

  if (!reader) {
    return { bytes_written: bytes };
  }

  const idleTimeoutMs = getNumberArg(
    args.idle_timeout_ms,
    getNumberEnv('NOTTY_DURDRAW_IDLE_TIMEOUT_MS', DEFAULT_IDLE_TIMEOUT_MS)
  );
  const maxWaitMs = getNumberArg(
    args.max_wait_ms,
    getNumberEnv('NOTTY_DURDRAW_MAX_WAIT_MS', DEFAULT_MAX_WAIT_MS)
  );
  const pollIntervalMs = getNumberArg(
    args.poll_interval_ms,
    getNumberEnv('NOTTY_DURDRAW_POLL_INTERVAL_MS', DEFAULT_POLL_INTERVAL_MS)
  );

  const result = await waitForIdleOutput(reader, {
    idleTimeoutMs,
    maxWaitMs,
    pollIntervalMs
  });

  reader.dispose();

  return {
    bytes_written: bytes,
    output: result.output,
    has_output: result.output.length > 0,
    idle_timeout_ms: idleTimeoutMs,
    max_wait_ms: maxWaitMs,
    poll_interval_ms: pollIntervalMs,
    timed_out: result.timedOut,
    elapsed_ms: result.elapsedMs
  };
}

async function waitForIdleOutput(reader, options) {
  const idleTimeoutMs = Math.max(0, options.idleTimeoutMs ?? DEFAULT_IDLE_TIMEOUT_MS);
  const maxWaitMs = Math.max(0, options.maxWaitMs ?? DEFAULT_MAX_WAIT_MS);
  const pollIntervalMs = Math.max(10, options.pollIntervalMs ?? DEFAULT_POLL_INTERVAL_MS);

  let output = '';
  let lastOutputAt = Date.now();
  const start = lastOutputAt;

  while (true) {
    const chunk = reader.read();
    if (chunk) {
      output += chunk;
      lastOutputAt = Date.now();
    }

    const now = Date.now();
    const idleFor = now - lastOutputAt;
    const elapsed = now - start;

    if (idleFor >= idleTimeoutMs) {
      return { output, timedOut: false, elapsedMs: elapsed };
    }

    if (elapsed >= maxWaitMs) {
      return { output, timedOut: true, elapsedMs: elapsed };
    }

    await sleep(pollIntervalMs);
  }
}

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function quoteShellArg(value) {
  const str = String(value);
  if (!str.length) {
    return "''";
  }
  if (/^[A-Za-z0-9_./:-]+$/.test(str)) {
    return str;
  }
  return `'${str.replace(/'/g, "'\"'\"'")}'`;
}

function wrapJson(data) {
  return {
    content: [{ type: 'text', text: JSON.stringify(data, null, 2) }]
  };
}

function wrapError(text) {
  return {
    content: [{ type: 'text', text }],
    isError: true
  };
}

function wrapErrorJson(code, message) {
  return {
    content: [{
      type: 'text',
      text: JSON.stringify({ error: { code, message } }, null, 2)
    }],
    isError: true
  };
}
