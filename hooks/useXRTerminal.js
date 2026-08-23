import { useCallback, useEffect, useRef, useState } from 'react';
import { resolveTerminalWsUrl } from '../lib/terminalWs.js';

const connectionRegistry = new Map();

function useLatest(value) {
  const ref = useRef(value);
  ref.current = value;
  return ref;
}

function ensureConnection(sessionId) {
  let entry = connectionRegistry.get(sessionId);

  if (!entry) {
    entry = createConnection(sessionId);
    connectionRegistry.set(sessionId, entry);
  }

  entry.refCount += 1;
  return entry;
}

function releaseConnection(sessionId) {
  const entry = connectionRegistry.get(sessionId);

  if (!entry) {
    return;
  }

  entry.refCount -= 1;

  if (entry.refCount <= 0) {
    entry.shutdown();
    connectionRegistry.delete(sessionId);
  }
}

function createConnection(sessionId) {
  let ws = null;
  let connectPromise = null;
  let status = 'idle';
  let statusNote = '';
  let dimensions = { cols: 80, rows: 24 };
  const subscribers = new Set();

  const notify = (event) => {
    subscribers.forEach((handler) => {
      try {
        handler(event);
      } catch (err) {
        console.error('[useXRTerminal] subscriber error', err);
      }
    });
  };

  const snapshotStatus = () => ({ status, note: statusNote });
  const snapshotDimensions = (source = 'local', session = null) => ({
    dimensions: { ...dimensions },
    source,
    session
  });

  const setStatus = (nextStatus, note = '') => {
    status = nextStatus;
    statusNote = note;
    notify({ type: 'status', ...snapshotStatus() });
  };

  const applyRemoteDimensions = (next, session) => {
    const cols = Number.isFinite(next?.cols) ? next.cols : dimensions.cols;
    const rows = Number.isFinite(next?.rows) ? next.rows : dimensions.rows;
    dimensions = { cols, rows };
    notify({ type: 'dimensions', ...snapshotDimensions('remote', session) });
  };

  const connect = async () => {
    if (typeof window === 'undefined') {
      return null;
    }

    if (ws && (ws.readyState === WebSocket.OPEN || ws.readyState === WebSocket.CONNECTING)) {
      return ws;
    }

    if (connectPromise) {
      return connectPromise;
    }

    connectPromise = (async () => {
      try {
        setStatus('connecting', '');
        const wsUrl = await resolveTerminalWsUrl(sessionId);
        const nextWs = new WebSocket(wsUrl);
        ws = nextWs;

        nextWs.onopen = () => {
          setStatus('connected', '');
          notify({ type: 'open' });
        };

        nextWs.onmessage = (event) => {
          let message;

          try {
            message = JSON.parse(event.data);
          } catch (err) {
            notify({ type: 'parse-error', error: err });
            return;
          }

          if (message.type === 'output') {
            notify({ type: 'output', data: message.data });
            return;
          }

          if (message.type === 'session') {
            applyRemoteDimensions(message.session, message.session);
            return;
          }

          if (message.type === 'exit') {
            setStatus('closed', `code=${message.info?.exitCode ?? '0'}`);
            notify({ type: 'exit', info: message.info ?? {} });
            return;
          }

          if (message.type === 'error') {
            notify({ type: 'server-error', error: message.error });
          }
        };

        nextWs.onerror = () => {
          setStatus('error', 'network error');
          notify({ type: 'error', error: new Error('network error') });
        };

        nextWs.onclose = (event) => {
          ws = null;
          const detail = `code=${event.code}${event.reason ? ` reason=${event.reason}` : ''}`;
          setStatus(event.wasClean ? 'closed' : 'error', detail);
          notify({ type: 'close', event });
        };

        return nextWs;
      } catch (err) {
        ws = null;
        setStatus('error', err.message ?? 'connection failed');
        notify({ type: 'error', error: err });
        throw err;
      } finally {
        connectPromise = null;
      }
    })();

    return connectPromise;
  };

  const send = (payload) => {
    if (!ws || ws.readyState !== WebSocket.OPEN) {
      return false;
    }

    ws.send(JSON.stringify(payload));
    return true;
  };

  const sendInput = (data) => send({ type: 'input', data });

  const sendResize = (cols, rows) => {
    const nextCols = Number.isFinite(cols) ? cols : dimensions.cols;
    const nextRows = Number.isFinite(rows) ? rows : dimensions.rows;
    dimensions = { cols: nextCols, rows: nextRows };
    notify({ type: 'dimensions', ...snapshotDimensions('local') });
    return send({ type: 'resize', cols: nextCols, rows: nextRows });
  };

  const subscribe = (handler) => {
    subscribers.add(handler);
    handler({ type: 'status', ...snapshotStatus() });
    handler({ type: 'dimensions', ...snapshotDimensions('initial') });

    return () => {
      subscribers.delete(handler);
    };
  };

  const shutdown = () => {
    subscribers.clear();

    if (ws) {
      ws.onopen = null;
      ws.onmessage = null;
      ws.onerror = null;
      ws.onclose = null;
      ws.close(1000);
      ws = null;
    }

    status = 'closed';
    statusNote = 'client-disconnect';
  };

  return {
    sessionId,
    refCount: 0,
    connect,
    send,
    sendInput,
    sendResize,
    subscribe,
    shutdown,
    get status() {
      return status;
    },
    get statusNote() {
      return statusNote;
    },
    get dimensions() {
      return { ...dimensions };
    }
  };
}

export default function useXRTerminal(options = {}) {
  const {
    sessionId,
    autoConnect = true,
    onOutput,
    onSession,
    onExit,
    onError,
    onStatusChange,
    onServerError
  } = options;

  const outputRef = useLatest(onOutput);
  const sessionRef = useLatest(onSession);
  const exitRef = useLatest(onExit);
  const errorRef = useLatest(onError);
  const serverErrorRef = useLatest(onServerError);
  const statusChangeRef = useLatest(onStatusChange);
  const connectionRef = useRef(null);

  const [status, setStatus] = useState('idle');
  const [statusNote, setStatusNote] = useState('');
  const [dimensions, setDimensions] = useState({ cols: 80, rows: 24 });

  useEffect(() => {
    if (!sessionId) {
      return () => {};
    }

    const connection = ensureConnection(sessionId);
    connectionRef.current = connection;

    setStatus(connection.status);
    setStatusNote(connection.statusNote);
    setDimensions(connection.dimensions);

    const unsubscribe = connection.subscribe((event) => {
      if (event.type === 'status') {
        setStatus(event.status);
        setStatusNote(event.note ?? '');
        if (statusChangeRef.current) {
          statusChangeRef.current({ status: event.status, note: event.note ?? '' });
        }
        return;
      }

      if (event.type === 'dimensions') {
        setDimensions(event.dimensions);
        if (event.source === 'remote' && sessionRef.current) {
          sessionRef.current(event.session ?? event.dimensions);
        }
        return;
      }

      if (event.type === 'output') {
        if (outputRef.current) {
          outputRef.current(event.data);
        }
        return;
      }

      if (event.type === 'exit') {
        if (exitRef.current) {
          exitRef.current(event.info);
        }
        return;
      }

      if (event.type === 'error') {
        if (errorRef.current) {
          errorRef.current(event.error);
        }
        return;
      }

      if (event.type === 'server-error') {
        if (serverErrorRef.current) {
          serverErrorRef.current(event.error);
        }
      }
    });

    if (autoConnect) {
      connection.connect().catch(() => {});
    }

    return () => {
      unsubscribe();
      if (connectionRef.current === connection) {
        connectionRef.current = null;
      }
      releaseConnection(sessionId);
    };
  }, [sessionId, autoConnect, statusChangeRef, sessionRef, outputRef, exitRef, errorRef, serverErrorRef]);

  const sendInput = useCallback((data) => {
    if (!connectionRef.current) {
      return false;
    }

    return connectionRef.current.sendInput(data);
  }, []);

  const sendResize = useCallback((cols, rows) => {
    if (!connectionRef.current) {
      return false;
    }

    return connectionRef.current.sendResize(cols, rows);
  }, []);

  const sendControl = useCallback((payload) => {
    if (!connectionRef.current) {
      return false;
    }

    return connectionRef.current.send(payload);
  }, []);

  const reconnect = useCallback(() => {
    if (!connectionRef.current) {
      return Promise.resolve(null);
    }

    return connectionRef.current.connect();
  }, []);

  return {
    status,
    statusNote,
    dimensions,
    isConnected: status === 'connected',
    sendInput,
    sendResize,
    sendControl,
    reconnect
  };
}
