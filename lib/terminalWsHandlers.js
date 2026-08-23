import { URL } from 'node:url';
import { getRequestIpInfo, getWsProtocol, withLogContext } from './terminalLogging.js';
import {
  getTerminalSummary,
  createTerminalReader,
  subscribeToTerminal,
  onTerminalExit,
  writeToTerminal,
  resizeTerminal
} from './terminalManager.js';

function defaultParseId(request) {
  const url = new URL(request.url || '/', 'ws://localhost');
  const raw = url.searchParams.get('id');
  if (!raw) {
    throw new Error('Missing session id');
  }
  const trimmed = raw.trim();
  if (!trimmed) {
    throw new Error('Missing session id');
  }
  return trimmed;
}

function safeClose(ws, code, reason) {
  try {
    ws.close(code, reason);
  } catch {
    // ignore
  }
}

function sendJson(ws, payload) {
  if (ws.readyState !== ws.OPEN) {
    return;
  }
  ws.send(JSON.stringify(payload));
}

export function createTerminalWebSocketHandler(options = {}) {
  const { parseId = defaultParseId } = options;

  return (ws, request) => {
    const { sourceIp, forwardedFor } = getRequestIpInfo(request);
    const baseContext = {
      protocol: getWsProtocol(request),
      transport: 'ws',
      source: 'terminalWs',
      route: 'WS /ws/terminals',
      source_ip: sourceIp,
      x_forwarded_for: forwardedFor
    };

    const withWsContext = (extra, fn) =>
      withLogContext({ ...baseContext, ...extra }, fn);

    let reader = null;
    let unsubData = null;
    let unsubExit = null;

    const cleanup = () => {
      if (unsubData) {
        try {
          unsubData();
        } catch {
          // ignore
        }
        unsubData = null;
      }
      if (unsubExit) {
        try {
          unsubExit();
        } catch {
          // ignore
        }
        unsubExit = null;
      }
      if (reader) {
        try {
          reader.dispose();
        } catch {
          // ignore
        }
        reader = null;
      }
    };

    try {
      const id = parseId(request);
      withWsContext({ messageType: 'connect' }, () => {
        const session = getTerminalSummary(id);
        sendJson(ws, { type: 'session', session });

        reader = createTerminalReader(id, { includeHistory: true });
        const buffered = reader.read();
        if (buffered) {
          sendJson(ws, { type: 'output', data: buffered });
        }
        reader.dispose();
        reader = null;

        unsubData = subscribeToTerminal(id, (data) => {
          sendJson(ws, { type: 'output', data });
        });

        unsubExit = onTerminalExit(id, (info) => {
          sendJson(ws, { type: 'exit', info });
          safeClose(ws, 1000, 'terminal exited');
        });
      });

      ws.on('message', (raw) => {
        let message = null;
        try {
          message = JSON.parse(raw.toString());
        } catch (err) {
          withWsContext({ messageType: 'parse_error' }, () => {
            sendJson(ws, { type: 'error', error: err.message });
          });
          return;
        }

        const messageType = typeof message?.type === 'string' ? message.type : 'unknown';
        withWsContext({ messageType }, () => {
          if (message.type === 'input') {
            writeToTerminal(id, message.data ?? '', { actor: 'human' });
          } else if (message.type === 'resize') {
            resizeTerminal(id, message.cols, message.rows);
          } else if (message.type === 'read') {
            const tempReader = createTerminalReader(id, { includeHistory: false });
            const data = tempReader.read();
            tempReader.dispose();
            sendJson(ws, { type: 'output', data });
          } else {
            sendJson(ws, { type: 'error', error: 'Unknown message type' });
          }
        });
      });

      ws.on('close', cleanup);
      ws.on('error', cleanup);
    } catch (err) {
      cleanup();
      sendJson(ws, { type: 'error', error: err.message || 'Unknown error' });
      safeClose(ws, 1011, err.message);
    }
  };
}

export function attachTerminalWebSocketHandlers(wss, options = {}) {
  const handler = createTerminalWebSocketHandler(options);
  wss.on('connection', handler);
  return handler;
}
