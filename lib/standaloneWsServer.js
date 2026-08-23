import { createTerminalWebSocketHandler } from './terminalWsHandlers.js';

const STATE_VERSION = 2;

const state = globalThis.__terminalStandaloneWsState || {
  started: false,
  version: STATE_VERSION
};

if (state.version !== STATE_VERSION) {
  try {
    state.wss?.clients?.forEach((client) => client.close());
    state.wss?.close();
  } catch {
    // ignore close errors
  }
  state.started = false;
  state.handlersAttached = false;
  state.version = STATE_VERSION;
}

function attachConnectionHandlers(wss) {
  if (state.handlersAttached) {
    return;
  }

  const handler = createTerminalWebSocketHandler();
  wss.on('connection', handler);

  state.handlersAttached = true;
  state.handler = handler;
}

export function registerExternalWsServer({ wss, port, path, host, url }) {
  if (!wss || typeof wss.on !== 'function') {
    throw new Error('A WebSocketServer instance is required');
  }

  const envPort = Number.parseInt(process.env.PORT ?? '', 10);
  const fallbackPort = Number.isNaN(envPort) ? 3000 : envPort;
  const resolvedPort =
    typeof port === 'number' && Number.isFinite(port) ? port : fallbackPort;

  const resolvedPathRaw =
    typeof path === 'string' && path.length ? path : '/ws/terminals';
  const resolvedPath = resolvedPathRaw.startsWith('/')
    ? resolvedPathRaw
    : `/${resolvedPathRaw}`;

  const resolvedHost = typeof host === 'string' && host.length ? host : 'localhost';
  const resolvedUrl =
    typeof url === 'string' && url.length
      ? url
      : `ws://${resolvedHost}:${resolvedPort}${resolvedPath}`;

  attachConnectionHandlers(wss);

  state.started = true;
  state.port = resolvedPort;
  state.path = resolvedPath;
  state.host = resolvedHost;
  state.url = resolvedUrl;
  state.wss = wss;
  state.version = STATE_VERSION;

  globalThis.__terminalStandaloneWsState = state;
  return state;
}

export function getStandaloneWsState() {
  if (!state.started) {
    throw new Error(
      'Terminal WebSocket server state is unavailable. Call registerExternalWsServer first.'
    );
  }

  return state;
}
