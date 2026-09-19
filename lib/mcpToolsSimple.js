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

const KEY_SEQUENCES = new Map([
  ['enter', '\r'],
  ['return', '\r'],
  ['tab', '\t'],
  ['up', '\u001b[A'],
  ['down', '\u001b[B'],
  ['left', '\u001b[D'],
  ['right', '\u001b[C'],
  ['esc', '\u001b'],
  ['escape', '\u001b'],
  ['ctrl+c', '\u0003'],
  ['ctrl+d', '\u0004'],
  ['backspace', '\u007f']
]);

export function getToolDefinitions() {
  const spawnOtpEnabled = isSpawnOtpProtected();

  return [
    {
      name: 'spawn_terminal',
      description: [
        'Spawn a new terminal session.',
        spawnOtpEnabled
          ? 'A one-time OTP is required to spawn a terminal.'
          : 'No parameters are required.',
        'Returns terminal_uuid to be used for subsequent terminal calls.'
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
      name: 'run_command',
      description:
        'Run a command in a terminal session, waiting for output to become idle before returning.',
      inputSchema: {
        type: 'object',
        properties: {
          command: { type: 'string', description: 'Command to run.' },
          terminal_id: {
            type: 'number',
            description: 'Existing terminal session id to reuse.'
          },
          terminal_uuid: {
            type: 'string',
            description: 'Existing terminal session uuid to reuse.'
          },
          cols: { type: 'number', default: 80 },
          rows: { type: 'number', default: 30 },
          cwd: { type: 'string', description: 'Working directory for new session.' },
          terminalType: {
            type: 'string',
            description: 'Terminal type for new sessions.',
            enum: ['vt100', 'xterm', 'ansi', 'ascii']
          },
          ...(spawnOtpEnabled
            ? {
                otp: {
                  type: 'string',
                  description: 'Single-use OTP required only when this call creates a terminal.'
                }
              }
            : {})
        },
        required: ['command']
      }
    },
    {
      name: 'read_terminal',
      description:
        'Read buffered output from a terminal session using a persistent reader scoped to simplified mode.',
      inputSchema: {
        type: 'object',
        properties: {
          terminal_id: { type: 'number' },
          terminal_uuid: { type: 'string' }
        },
        required: []
      }
    },
    {
      name: 'send_key',
      description:
        'Send a friendly key name (Enter, Ctrl+C, Tab, Up, Down, Esc) to a terminal session.',
      inputSchema: {
        type: 'object',
        properties: {
          terminal_id: { type: 'number' },
          terminal_uuid: { type: 'string' },
          key: { type: 'string', description: 'Key name or literal characters.' }
        },
        required: ['key']
      }
    }
  ];
}

export const toolDefinitions = getToolDefinitions();

export async function callTool(name, args = {}) {
  return withLogContext({ source: 'mcpToolsSimple', tool: name }, async () => {
    try {
      switch (name) {
        case 'spawn_terminal': {
          const session = spawnTerminal({
            cols: args.cols,
            rows: args.rows,
            cwd: args.cwd,
            terminalType: args.terminalType || 'vt100',
            otp: args.otp
          });
          return wrapJson({
            terminal_uuid: session.terminal_uuid,
            note: 'All subsequent tool calls require this terminal_uuid.'
          });
        }

        case 'run_command': {
          const command = typeof args.command === 'string' ? args.command : null;
          if (!command || !command.trim()) {
            return wrapError('command is required');
          }

          let terminalRef = resolveTerminalRef(args);
          let sessionInfo = null;

          if (!terminalRef) {
            const session = spawnTerminal({
              cols: args.cols,
              rows: args.rows,
              cwd: args.cwd,
              terminalType: args.terminalType || 'vt100',
              otp: args.otp
            });
            terminalRef = { terminal_uuid: session.terminal_uuid };
            sessionInfo = session;
          }

          const reader = createTerminalReader(terminalRef, {
            includeHistory: true,
            persistent: true,
            key: 'simple_reader'
          });

          const commandPayload = normalizeCommandPayload(command);
          const bytes = writeToTerminal(terminalRef, commandPayload, { actor: 'agent-mcp' });

          const idleTimeoutMs = getNumberEnv(
            'NOTTY_SIMPLE_IDLE_TIMEOUT_MS',
            DEFAULT_IDLE_TIMEOUT_MS
          );
          const maxWaitMs = getNumberEnv(
            'NOTTY_SIMPLE_MAX_WAIT_MS',
            DEFAULT_MAX_WAIT_MS
          );
          const pollIntervalMs = getNumberEnv(
            'NOTTY_SIMPLE_POLL_INTERVAL_MS',
            DEFAULT_POLL_INTERVAL_MS
          );

          const result = await waitForIdleOutput(reader, {
            idleTimeoutMs,
            maxWaitMs,
            pollIntervalMs
          });

          return wrapJson({
            terminal_id: reader.terminal_id,
            terminal_uuid: reader.terminal_uuid,
            bytes_written: bytes,
            output: result.output,
            has_output: result.output.length > 0,
            idle_timeout_ms: idleTimeoutMs,
            max_wait_ms: maxWaitMs,
            poll_interval_ms: pollIntervalMs,
            timed_out: result.timedOut,
            elapsed_ms: result.elapsedMs,
            ...(sessionInfo
              ? {
                  spawned: true,
                  shell: sessionInfo.shell,
                  cols: sessionInfo.cols,
                  rows: sessionInfo.rows,
                  cwd: sessionInfo.cwd,
                  terminalType: sessionInfo.terminalType,
                  alive: sessionInfo.alive,
                  createdAt: sessionInfo.createdAt
                }
              : { spawned: false })
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
            key: 'simple_reader'
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

        case 'send_key': {
          const terminalRef = resolveTerminalRef(args);
          if (!terminalRef) {
            return wrapError('terminal reference is required');
          }
          const keyName = typeof args.key === 'string' ? args.key : '';
          if (!keyName.trim()) {
            return wrapError('key is required');
          }

          const sequence = resolveKeySequence(keyName);
          if (!sequence) {
            return wrapError(`Unknown key: ${keyName}`);
          }

          const bytes = writeToTerminal(terminalRef, sequence, { actor: 'agent-mcp' });

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
            bytes_written: bytes,
            success: true
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

function normalizeKeyName(name) {
  return name
    .trim()
    .toLowerCase()
    .replace(/\s+/g, '')
    .replace(/control/g, 'ctrl')
    .replace(/-/g, '+');
}

function resolveKeySequence(keyName) {
  const normalized = normalizeKeyName(keyName);
  if (KEY_SEQUENCES.has(normalized)) {
    return KEY_SEQUENCES.get(normalized);
  }

  if (keyName.length === 1) {
    return keyName;
  }

  return null;
}

function getNumberEnv(name, fallback) {
  const value = Number.parseInt(process.env[name], 10);
  if (Number.isFinite(value) && value >= 0) {
    return value;
  }
  return fallback;
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
