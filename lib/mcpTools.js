import {
  spawnTerminal,
  writeToTerminal,
  createTerminalReader,
  resizeTerminal,
  killTerminal,
  listTerminals,
  setTerminalType,
  subscribeToTerminal,
  onTerminalExit
} from './terminalManager.js';
import {
  captureTerminalContext,
  postCopilotMessage
} from './agentManager.js';
import { withLogContext } from './terminalLogging.js';
import { getSpawnOtpConfig, isSpawnOtpProtected, validateSpawnOtp } from './mcpSpawnOtp.js';

// Global state for reader management across MCP sessions
const globalReaderState = globalThis.__mcpReaderState || {
  readers: new Map(), // readerHandle -> { terminalId, reader }
  nextHandle: 1
};
globalThis.__mcpReaderState = globalReaderState;

const OTP_TERMINAL_UUID_REQUIRED_ERROR =
  'terminal_uuid is required in OTP-protected MCP mode (terminal_id is not accepted).';
const TERMINAL_REF_REQUIRED_ERROR = 'terminal_uuid is required';

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

function resolveTerminalUuid(args) {
  if (!args || typeof args !== 'object') {
    return null;
  }

  if (typeof args.terminal_uuid === 'string' && args.terminal_uuid.trim()) {
    return args.terminal_uuid.trim();
  }
  if (typeof args.terminalUuid === 'string' && args.terminalUuid.trim()) {
    return args.terminalUuid.trim();
  }

  return null;
}

function resolveTerminalRef(args) {
  if (!args || typeof args !== 'object') {
    return null;
  }

  const terminalUuid = resolveTerminalUuid(args);
  if (terminalUuid) {
    return { terminal_uuid: terminalUuid };
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

function resolveTerminalRefForMcp(args) {
  if (getSpawnOtpConfig().otp) {
    const terminalUuid = resolveTerminalUuid(args);
    if (!terminalUuid) {
      return { error: OTP_TERMINAL_UUID_REQUIRED_ERROR };
    }
    return { terminalRef: { terminal_uuid: terminalUuid } };
  }

  const terminalRef = resolveTerminalRef(args);
  if (!terminalRef) {
    return { error: TERMINAL_REF_REQUIRED_ERROR };
  }
  return { terminalRef };
}

function getTerminalRefSchema() {
  if (isSpawnOtpProtected()) {
    return {
      terminal_uuid: {
        type: 'string',
        description:
          'Required when NOTTY_MCP_SPAWN_OTP is Enabled (OTP-protected MCP mode).'
      }
    };
  }

  return {
    terminal_id: {
      type: 'number',
      description:
        'Not accepted when NOTTY_MCP_SPAWN_OTP is Enabled (OTP-protected MCP mode); use terminal_uuid.'
    },
    terminal_uuid: {
      type: 'string',
      description:
        'Required when NOTTY_MCP_SPAWN_OTP is Enabled (OTP-protected MCP mode).'
    }
  };
}

function terminalRefToObject(terminalRef) {
  if (terminalRef && typeof terminalRef === 'object') {
    return terminalRef;
  }
  return { terminal_id: terminalRef };
}

export function getToolDefinitions() {
  const spawnOtpEnabled = isSpawnOtpProtected();
  const terminalRefSchema = getTerminalRefSchema();
  const spawnTerminalDescription = [
    'Spawn a new terminal session.',
    spawnOtpEnabled
      ? 'OTP value is required to spawn a terminal NOTTY_MCP_SPAWN_OTP is Enabled.'
      : 'No parameters are required.',
    'Returns terminal_uuid to be used for subsequent terminal calls.',
    'Do not submit UUID to spawn_terminal. There is no content field use data'
  ]
    .filter(Boolean)
    .join(' ');

  return [
    {
      name: 'spawn_terminal',
      description: spawnTerminalDescription,
      inputSchema: {
        type: 'object',
        properties: {
          cols: { type: 'number', default: 80 },
          rows: { type: 'number', default: 30 },
          cwd: { type: 'string', description: 'Working directory' },
          terminalType: {
            type: 'string',
            description: 'Terminal type: "vt100" (recommended for most tasks), "xterm" (more features), "ansi" (legacy), or "ascii" (plain text). Defaults to "vt100" for MCP.',
            enum: ['vt100', 'xterm', 'ansi', 'ascii']
          },
          ...(spawnOtpEnabled
            ? {
                otp: {
                  type: 'string',
                  description:
                    'Spawn OTP token. Required when NOTTY_MCP_SPAWN_OTP is Enabled in the environment.'
                }
              }
            : {})
        },
        required: []
      }
    },
    {
      name: 'write_terminal',
      description: 'Write `data` to terminal session by `terminal_uuid`. Returns structured data including bytes written. ',
      inputSchema: {
        type: 'object',
        properties: {
          ...terminalRefSchema,
          data: { type: 'string', description: 'Data to write (use \\r\\n for enter if running a linux command)' }
        },
        required: ['data']
      }
    },
    {
      name: 'read_terminal',
      description: 'Read buffered output from terminal by terminal_uuid. Uses a persistent reader to avoid replaying entire buffer. Returns structured data including output and session metadata.',
      inputSchema: {
        type: 'object',
        properties: {
          ...terminalRefSchema
        },
        required: []
      }
    },
    {
      name: 'open_reader',
      description: 'Open a streaming reader for a terminal session by terminal_uuid. Returns a reader handle that can be used with read_delta to get incremental output. This is more efficient than read_terminal for continuous monitoring.',
      inputSchema: {
        type: 'object',
        properties: {
          ...terminalRefSchema,
          include_history: {
            type: 'boolean',
            description: 'Include all buffered output from session start (true) or only new output (false). Defaults to false.',
            default: false
          }
        },
        required: []
      }
    },
    {
      name: 'read_delta',
      description: 'Read incremental output from a streaming reader. Returns only new data since the last read_delta call on this reader.',
      inputSchema: {
        type: 'object',
        properties: {
          reader_handle: { type: 'number', description: 'Reader handle from open_reader' }
        },
        required: ['reader_handle']
      }
    },
    {
      name: 'close_reader',
      description: 'Close a streaming reader and free its resources.',
      inputSchema: {
        type: 'object',
        properties: {
          reader_handle: { type: 'number', description: 'Reader handle from open_reader' }
        },
        required: ['reader_handle']
      }
    },
    {
      name: 'resize_terminal',
      description: 'Resize terminal dimensions by terminal_uuid. Returns updated session metadata.',
      inputSchema: {
        type: 'object',
        properties: {
          ...terminalRefSchema,
          cols: { type: 'number' },
          rows: { type: 'number' }
        },
        required: ['cols', 'rows']
      }
    },
    {
      name: 'kill_terminal',
      description: 'Kill a terminal session by terminal_uuid. Returns confirmation with terminal_uuid.',
      inputSchema: {
        type: 'object',
        properties: {
          ...terminalRefSchema
        },
        required: []
      }
    },
    {
      name: 'list_terminals',
      description: 'List all active terminal sessions with full metadata (id, shell, terminalType, alive, createdAt, etc).',
      inputSchema: { type: 'object', properties: {} }
    },
    {
      name: 'set_terminal_type',
      description: 'Set the terminal type for a terminal session by terminal_uuid. Switch to xterm if vt100 is insufficient. Returns updated session metadata.',
      inputSchema: {
        type: 'object',
        properties: {
          ...terminalRefSchema,
          terminal_type: {
            type: 'string',
            description: 'Terminal type: "vt100" (recommended for most tasks), "xterm" (more features), "ansi" (legacy), or "ascii" (plain text)',
            enum: ['vt100', 'xterm', 'ansi', 'ascii']
          }
        },
        required: ['terminal_type']
      }
    },
    {
      name: 'get_terminal_context',
      description: 'Get bounded, redacted terminal context for a copilot agent.',
      inputSchema: {
        type: 'object',
        properties: {
          ...terminalRefSchema,
          scope: {
            type: 'string',
            enum: ['tail', 'history'],
            default: 'tail'
          },
          max_context_chars: {
            type: 'number',
            default: 20000
          }
        },
        required: []
      }
    },
    {
      name: 'post_copilot_message',
      description: 'Post an agent message or command suggestion into the Notty copilot sidebar.',
      inputSchema: {
        type: 'object',
        properties: {
          ...terminalRefSchema,
          agent: { type: 'string', default: 'agent' },
          channel: { type: 'string' },
          kind: { type: 'string', default: 'message' },
          body: { type: 'string' },
          suggestions: {
            type: 'array',
            items: { type: 'string' }
          }
        },
        required: ['body']
      }
    }
  ];
}

export const toolDefinitions = getToolDefinitions();

export function callTool(name, args = {}) {
  return withLogContext({ source: 'mcpTools', tool: name }, () => {
    try {
      switch (name) {
        case 'spawn_terminal': {
          const otpResult = validateSpawnOtp(args);
          if (otpResult.error) {
            return wrapErrorJson(otpResult.error.code, otpResult.error.message);
          }
          const requestedUuid =
            typeof args.terminal_uuid === 'string'
              ? args.terminal_uuid
              : typeof args.terminalUuid === 'string'
                  ? args.terminalUuid
                  : null;
          if (requestedUuid && requestedUuid.trim()) {
            console.error(
              '[mcpTools] spawn_terminal received terminal_uuid; ignoring and generating UUID server-side.'
            );
          }
          const session = spawnTerminal({
            cols: args.cols,
            rows: args.rows,
            cwd: args.cwd,
            terminalType: args.terminalType || 'vt100' // Default to vt100 for MCP
          });
          return wrapJson({
            terminal_uuid: session.terminal_uuid,
            note: 'All subsequent tool calls require this terminal_uuid.'
          });
        }

        case 'write_terminal': {
          const terminalRefResult = resolveTerminalRefForMcp(args);
          if (terminalRefResult.error) {
            return wrapError(terminalRefResult.error);
          }
          const terminalRef = terminalRefResult.terminalRef;
          const normalizedData = decodeEscapeSequences(args.data);
          const bytes = writeToTerminal(terminalRef, normalizedData, { actor: 'agent-mcp' });
          const terminalUuid =
            typeof args.terminal_uuid === 'string'
              ? args.terminal_uuid
              : typeof args.terminalUuid === 'string'
                  ? args.terminalUuid
                  : undefined;
          return wrapJson({
            terminal_id: Number.isInteger(args.terminal_id)
              ? args.terminal_id
              : Number.isInteger(args.terminalId)
                  ? args.terminalId
                  : undefined,
            terminal_uuid: terminalUuid,
            bytes_written: bytes,
            success: true
          });
        }

        case 'read_terminal': {
          const terminalRefResult = resolveTerminalRefForMcp(args);
          if (terminalRefResult.error) {
            return wrapError(terminalRefResult.error);
          }
          const terminalRef = terminalRefResult.terminalRef;
          // Use persistent reader per session to avoid replaying entire buffer
          // Reader key is stored in the session and reused across calls
          const reader = createTerminalReader(terminalRef, {
            includeHistory: true,
            persistent: true,
            key: 'mcp_reader'
          });
          const output = reader.read();
          const pointer = reader.getPointer();
          return wrapJson({
            terminal_id: reader.terminal_id,
            terminal_uuid: reader.terminal_uuid,
            output: output || '',
            has_output: output.length > 0,
            pointer_position: pointer
          });
        }

        case 'open_reader': {
          const terminalRefResult = resolveTerminalRefForMcp(args);
          if (terminalRefResult.error) {
            return wrapError(terminalRefResult.error);
          }
          const terminalRef = terminalRefResult.terminalRef;
          const includeHistory = args.include_history ?? false;
          const reader = createTerminalReader(terminalRef, {
            includeHistory,
            persistent: false
          });

          // Generate unique handle for this reader and register cleanup
          const handle = globalReaderState.nextHandle++;
          let closed = false;
          let unsubscribe = null;

          const cleanup = () => {
            if (closed) {
              return;
            }
            closed = true;
            reader.dispose();
            globalReaderState.readers.delete(handle);
            if (unsubscribe) {
              unsubscribe();
              unsubscribe = null;
            }
          };

          const terminalSessionId = reader.terminal_id;
          const terminalUuid = reader.terminal_uuid;

          unsubscribe = onTerminalExit(terminalSessionId, () => {
            cleanup();
          });

          globalReaderState.readers.set(handle, {
            terminalId: terminalSessionId,
            terminalUuid,
            reader,
            cleanup
          });

          return wrapJson({
            reader_handle: handle,
            terminal_id: terminalSessionId,
            terminal_uuid: terminalUuid,
            include_history: includeHistory
          });
        }

        case 'read_delta': {
          const readerInfo = globalReaderState.readers.get(args.reader_handle);
          if (!readerInfo) {
            return wrapError(
              `Reader handle ${args.reader_handle} not found. It may have been closed or the session may have exited.`
            );
          }

          const output = readerInfo.reader.read();
          const pointer = readerInfo.reader.getPointer();

          return wrapJson({
            reader_handle: args.reader_handle,
            terminal_id: readerInfo.terminalId,
            terminal_uuid: readerInfo.terminalUuid,
            output: output || '',
            has_output: output.length > 0,
            pointer_position: pointer
          });
        }

        case 'close_reader': {
          const readerInfo = globalReaderState.readers.get(args.reader_handle);
          if (!readerInfo) {
            return wrapError(
              `Reader handle ${args.reader_handle} not found. It may have already been closed.`
            );
          }

          readerInfo.cleanup();

          return wrapJson({
            reader_handle: args.reader_handle,
            terminal_id: readerInfo.terminalId,
            terminal_uuid: readerInfo.terminalUuid,
            closed: true
          });
        }

        case 'resize_terminal': {
          const terminalRefResult = resolveTerminalRefForMcp(args);
          if (terminalRefResult.error) {
            return wrapError(terminalRefResult.error);
          }
          const terminalRef = terminalRefResult.terminalRef;
          const session = resizeTerminal(terminalRef, args.cols, args.rows);
          return wrapJson({
            terminal_id: session.id,
            terminal_uuid: session.terminal_uuid,
            cols: session.cols,
            rows: session.rows,
            shell: session.shell,
            terminalType: session.terminalType,
            alive: session.alive,
            createdAt: session.createdAt
          });
        }

        case 'kill_terminal': {
          const terminalRefResult = resolveTerminalRefForMcp(args);
          if (terminalRefResult.error) {
            return wrapError(terminalRefResult.error);
          }
          const terminalRef = terminalRefResult.terminalRef;
          killTerminal(terminalRef);
          const terminalUuid =
            typeof args.terminal_uuid === 'string'
              ? args.terminal_uuid
              : typeof args.terminalUuid === 'string'
                  ? args.terminalUuid
                  : undefined;
          return wrapJson({
            terminal_id: Number.isInteger(args.terminal_id)
              ? args.terminal_id
              : Number.isInteger(args.terminalId)
                  ? args.terminalId
                  : undefined,
            terminal_uuid: terminalUuid,
            killed: true
          });
        }

        case 'list_terminals': {
          const spawnOtpConfig = getSpawnOtpConfig();
          if (spawnOtpConfig.otp) {
            return wrapErrorJson(
              'list_terminals_disabled',
              'There can be only one.*highlander*. list_terminals is disabled in OTP-protected MCP mode.'
            );
          }
          const terminals = listTerminals();
          return wrapJson({
            terminals,
            count: terminals.length
          });
        }

        case 'set_terminal_type': {
          const terminalRefResult = resolveTerminalRefForMcp(args);
          if (terminalRefResult.error) {
            return wrapError(terminalRefResult.error);
          }
          const terminalRef = terminalRefResult.terminalRef;
          const session = setTerminalType(
            terminalRef,
            args.terminal_type,
            { actor: 'agent-mcp' }
          );
          return wrapJson({
            terminal_id: session.id,
            terminal_uuid: session.terminal_uuid,
            terminalType: session.terminalType,
            shell: session.shell,
            cols: session.cols,
            rows: session.rows,
            alive: session.alive,
            createdAt: session.createdAt
          });
        }

        case 'get_terminal_context': {
          const terminalRefResult = resolveTerminalRefForMcp(args);
          if (terminalRefResult.error) {
            return wrapError(terminalRefResult.error);
          }
          const context = captureTerminalContext({
            ...terminalRefToObject(terminalRefResult.terminalRef),
            scope: args.scope,
            max_context_chars: args.max_context_chars ?? args.maxContextChars
          });
          return wrapJson(context);
        }

        case 'post_copilot_message': {
          const terminalRefResult = resolveTerminalRefForMcp(args);
          if (terminalRefResult.error) {
            return wrapError(terminalRefResult.error);
          }
          const message = postCopilotMessage({
            ...terminalRefToObject(terminalRefResult.terminalRef),
            agent: args.agent,
            channel: args.channel,
            kind: args.kind,
            body: args.body,
            suggestions: args.suggestions
          });
          return wrapJson({ message });
        }

        default:
          return wrapError(`Unknown tool: ${name}`);
      }
    } catch (err) {
      return wrapError(err.message || 'Unknown error');
    }
  });
}

function wrapText(text) {
  return {
    content: [{ type: 'text', text }]
  };
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
    content: [
      {
        type: 'text',
        text: JSON.stringify(
          {
            error: {
              code,
              message
            }
          },
          null,
          2
        )
      }
    ],
    isError: true
  };
}
