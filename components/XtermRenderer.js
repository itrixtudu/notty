import { useCallback, useEffect, useRef, useState } from 'react';
import { Terminal } from '@xterm/xterm';
import { FitAddon } from '@xterm/addon-fit';
import { WebLinksAddon } from '@xterm/addon-web-links';
import { WebglAddon } from '@xterm/addon-webgl';
import { RefreshCw } from 'lucide-react';
import {
  primeCanvasReadback,
  shouldDeferCanvasReadback,
  waitForCanvasReadbackInput
} from '../lib/canvasReadbackGate.js';
import { resolveTerminalWsUrl } from '../lib/terminalWs.js';

export default function XtermRenderer({
  sessionId,
  fullViewport = false,
  showPlaceholder = true,
  showChrome = true,
  onNewTerminal,
  title,
  subtitle,
  compact = false,
  autoFocus = true,
  updateDocumentTitle = true,
  onConnectionStatus,
  onSelectionChange
}) {
  const [status, setStatus] = useState('idle');
  const [statusNote, setStatusNote] = useState('');
  const [dimensions, setDimensions] = useState({ cols: 80, rows: 24 });
  const [terminalTitle, setTerminalTitle] = useState('');
  const [connectionRevision, setConnectionRevision] = useState(0);
  const [canvasReadbackReady, setCanvasReadbackReady] = useState(() => (
    typeof window !== 'undefined' && !shouldDeferCanvasReadback(window)
  ));
  const terminalRef = useRef(null);
  const containerRef = useRef(null);
  const wsRef = useRef(null);
  const fitAddonRef = useRef(null);
  const onNewTerminalRef = useRef(onNewTerminal);
  const onConnectionStatusRef = useRef(onConnectionStatus);
  const onSelectionChangeRef = useRef(onSelectionChange);

  useEffect(() => {
    onNewTerminalRef.current = onNewTerminal;
  }, [onNewTerminal]);

  useEffect(() => {
    onConnectionStatusRef.current = onConnectionStatus;
  }, [onConnectionStatus]);

  useEffect(() => {
    onSelectionChangeRef.current = onSelectionChange;
  }, [onSelectionChange]);

  useEffect(() => {
    onConnectionStatusRef.current?.({ status, note: statusNote });
  }, [status, statusNote]);

  useEffect(() => {
    setTerminalTitle('');
  }, [sessionId]);

  useEffect(() => {
    if (typeof window === 'undefined') {
      setCanvasReadbackReady(false);
      return undefined;
    }
    if (!sessionId) {
      setCanvasReadbackReady(!shouldDeferCanvasReadback(window));
      return undefined;
    }

    if (!shouldDeferCanvasReadback(window)) {
      setCanvasReadbackReady(true);
      return undefined;
    }

    setCanvasReadbackReady(false);
    setStatus('waiting');
    setStatusNote('user input required');
    return waitForCanvasReadbackInput(() => {
      setCanvasReadbackReady(true);
      setStatus('idle');
      setStatusNote('');
    }, window);
  }, [sessionId]);

  // Initialize xterm.js terminal
  useEffect(() => {
    if (!sessionId || typeof window === 'undefined' || !canvasReadbackReady) return undefined;
    const container = containerRef.current;
    if (!container) return undefined;
    const initialPageTitle = typeof document !== 'undefined' ? document.title : '';

    // Create terminal instance
    const terminal = new Terminal({
      cursorBlink: true,
      fontSize: 14,
      fontFamily: 'JetBrains Mono, Fira Code, Consolas, Monaco, monospace',
      theme: {
        background: '#0a0e14',
        foreground: '#c5c8c6',
        cursor: '#c5c8c6',
        black: '#1d1f21',
        red: '#cc6666',
        green: '#b5bd68',
        yellow: '#f0c674',
        blue: '#81a2be',
        magenta: '#b294bb',
        cyan: '#8abeb7',
        white: '#c5c8c6',
        brightBlack: '#969896',
        brightRed: '#cc6666',
        brightGreen: '#b5bd68',
        brightYellow: '#f0c674',
        brightBlue: '#81a2be',
        brightMagenta: '#b294bb',
        brightCyan: '#8abeb7',
        brightWhite: '#ffffff',
      },
      scrollback: 10000,
      allowTransparency: false,
      convertEol: false,
    });

    // Load addons
    const fitAddon = new FitAddon();
    const webLinksAddon = new WebLinksAddon();

    terminal.loadAddon(fitAddon);
    terminal.loadAddon(webLinksAddon);

    // Open terminal in container
    terminal.open(container);

    // Try to load WebGL addon (fallback gracefully if not supported)
    try {
      const webglAddon = new WebglAddon();
      webglAddon.onContextLoss(() => {
        webglAddon.dispose();
      });
      terminal.loadAddon(webglAddon);
    } catch (err) {
      console.warn('WebGL addon failed to load:', err.message);
    }

    // Fit terminal to container
    fitAddon.fit();

    // Store refs
    terminalRef.current = terminal;
    fitAddonRef.current = fitAddon;

    const titleDisposable = terminal.onTitleChange((title) => {
      setTerminalTitle(title);
      if (updateDocumentTitle && typeof document !== 'undefined') {
        document.title = title;
      }
    });
    const selectionDisposable = terminal.onSelectionChange(() => {
      onSelectionChangeRef.current?.({
        sessionId,
        text: terminal.getSelection()
      });
    });

    terminal.attachCustomKeyEventHandler((event) => {
      if (!onNewTerminalRef.current) {
        return true;
      }
      if (
        event.ctrlKey
        && event.shiftKey
        && !event.altKey
        && !event.metaKey
        && event.key === 'ArrowRight'
      ) {
        if (!event.repeat) {
          onNewTerminalRef.current?.();
        }
        event.preventDefault();
        event.stopPropagation();
        return false;
      }
      return true;
    });

    let resizeFrame = 0;
    const fitToContainer = () => {
      if (resizeFrame) {
        window.cancelAnimationFrame(resizeFrame);
      }
      resizeFrame = window.requestAnimationFrame(() => {
        resizeFrame = 0;
        if (fitAddonRef.current) {
          fitAddonRef.current.fit();
        }
      });
    };

    // Handle window and pane resize
    const handleResize = () => {
      if (fitAddonRef.current) {
        fitAddonRef.current.fit();
      }
    };
    window.addEventListener('resize', handleResize);
    const resizeObserver = typeof ResizeObserver !== 'undefined'
      ? new ResizeObserver(fitToContainer)
      : null;
    resizeObserver?.observe(container);

    // Cleanup
    return () => {
      titleDisposable.dispose();
      selectionDisposable.dispose();
      if (updateDocumentTitle && typeof document !== 'undefined') {
        document.title = initialPageTitle;
      }
      window.removeEventListener('resize', handleResize);
      resizeObserver?.disconnect();
      if (resizeFrame) {
        window.cancelAnimationFrame(resizeFrame);
      }
      try {
        container.replaceChildren();
      } catch {
        container.innerHTML = '';
      }
      setTimeout(() => terminal.dispose(), 0);
      terminalRef.current = null;
      fitAddonRef.current = null;
    };
  }, [sessionId, canvasReadbackReady, updateDocumentTitle]);

  // WebSocket connection
  useEffect(() => {
    if (!sessionId || typeof window === 'undefined' || !canvasReadbackReady) return undefined;
    if (!terminalRef.current) return undefined;

    const terminal = terminalRef.current;
    let ws;
    let active = true;
    let reconnectTimer = null;
    let retryCount = 0;
    let processExited = false;
    const maxReconnectAttempts = 5;

    const scheduleReconnect = () => {
      if (!active || processExited || retryCount >= maxReconnectAttempts) {
        return;
      }

      retryCount += 1;
      const delay = Math.min(750 * (2 ** (retryCount - 1)), 8000);
      setStatus('reconnecting');
      setStatusNote(`retry ${retryCount}/${maxReconnectAttempts}`);
      reconnectTimer = window.setTimeout(connect, delay);
    };

    const connect = async () => {
      try {
        setStatus(retryCount ? 'reconnecting' : 'connecting');
        setStatusNote(retryCount ? `retry ${retryCount}/${maxReconnectAttempts}` : '');
        const wsUrl = await resolveTerminalWsUrl(sessionId);
        if (!active) {
          return;
        }
        ws = new WebSocket(wsUrl);
        wsRef.current = ws;

        ws.onopen = () => {
          if (!active) return;
          terminal.reset();
          terminal.clear();
          setStatus('connected');
          setStatusNote('');

          // Send initial resize based on terminal dimensions
          const cols = terminal.cols;
          const rows = terminal.rows;
          setDimensions({ cols, rows });
          ws.send(JSON.stringify({ type: 'resize', cols, rows }));
        };

        ws.onclose = (event) => {
          if (!active) return;
          setStatus(event.wasClean ? 'closed' : 'error');
          const detail = `code=${event.code}${event.reason ? ` reason=${event.reason}` : ''}`;
          setStatusNote(detail);
          if (!processExited) {
            terminal.writeln(`\r\n[connection closed ${detail}]`);
          }
          wsRef.current = null;
          scheduleReconnect();
        };

        ws.onerror = () => {
          if (!active) return;
          setStatus('error');
          setStatusNote('network error');
        };

        ws.onmessage = (event) => {
          if (!active) return;
          try {
            const message = JSON.parse(event.data);
            if (message.type === 'output') {
              terminal.write(message.data);
            } else if (message.type === 'session') {
              retryCount = 0;
              setDimensions({ cols: message.session.cols, rows: message.session.rows });
            } else if (message.type === 'exit') {
              terminal.writeln(`\r\n[process exited code=${message.info?.exitCode}]`);
              setStatus('closed');
              setStatusNote(`code=${message.info?.exitCode ?? '0'}`);
              processExited = true;
            } else if (message.type === 'error') {
              terminal.writeln(`\r\n[error] ${message.error}`);
            }
          } catch (err) {
            terminal.writeln(`\r\n[parse error] ${err.message}`);
          }
        };
      } catch (err) {
        if (!active) {
          return;
        }
        setStatus('error');
        setStatusNote(err.message ?? 'unknown error');
        if (terminal) {
          terminal.writeln(`\r\n[ws error] ${err.message}`);
        }
        scheduleReconnect();
      }
    };

    // Wire up terminal input to WebSocket
    const inputDisposable = terminal.onData((data) => {
      if (ws && ws.readyState === WebSocket.OPEN) {
        ws.send(JSON.stringify({ type: 'input', data }));
      }
    });

    // Wire up terminal resize to WebSocket
    const resizeDisposable = terminal.onResize(({ cols, rows }) => {
      setDimensions({ cols, rows });
      if (ws && ws.readyState === WebSocket.OPEN) {
        ws.send(JSON.stringify({ type: 'resize', cols, rows }));
      }
    });

    connect();

    return () => {
      active = false;
      inputDisposable.dispose();
      resizeDisposable.dispose();
      if (reconnectTimer) {
        window.clearTimeout(reconnectTimer);
      }
      if (ws) {
        ws.close(1000);
      }
      wsRef.current = null;
    };
  }, [sessionId, canvasReadbackReady, connectionRevision]);

  // Fit on layout changes
  useEffect(() => {
    if (fitAddonRef.current) {
      const timer = setTimeout(() => {
        fitAddonRef.current.fit();
      }, 100);
      return () => clearTimeout(timer);
    }
  }, [status]);

  const handleCtrlC = () => {
    if (terminalRef.current) {
      if (wsRef.current?.readyState === WebSocket.OPEN) {
        wsRef.current.send(JSON.stringify({ type: 'input', data: '\u0003' }));
      }
      terminalRef.current.focus();
    }
  };

  const reconnect = useCallback(() => {
    setConnectionRevision((revision) => revision + 1);
  }, []);

  const focusTerminal = () => {
    if (terminalRef.current) {
      terminalRef.current.focus();
    }
  };

  // Auto-focus on mount
  useEffect(() => {
    if (!sessionId || !canvasReadbackReady || !autoFocus) return;
    const timer = setTimeout(focusTerminal, 100);
    return () => clearTimeout(timer);
  }, [sessionId, canvasReadbackReady, autoFocus]);

  if (!sessionId && showPlaceholder) {
    return (
      <div className="terminal-shell terminal-shell-empty">
        <div className="terminal-placeholder">
          <h2>No session selected</h2>
          <p>Use the controls to create or pick a terminal session.</p>
        </div>
      </div>
    );
  }

  const shellClassNames = ['terminal-shell'];
  if (fullViewport) {
    shellClassNames.push('terminal-shell-full');
  }
  if (!showChrome) {
    shellClassNames.push('terminal-shell-chromeless');
  }
  if (compact) {
    shellClassNames.push('terminal-shell-compact');
  }

  const headerTitle = title || terminalTitle || (sessionId ? `Session #${sessionId}` : 'Session');

  if (sessionId && !canvasReadbackReady) {
    return (
      <div className={shellClassNames.concat('terminal-shell-empty').join(' ')}>
        <div className="terminal-placeholder">
          <h2>Start Terminal</h2>
          <p>Firefox needs one input event before terminal rendering starts.</p>
          <button
            type="button"
            onClick={() => {
              if (primeCanvasReadback(window)) {
                setCanvasReadbackReady(true);
              }
            }}
          >
            Start
          </button>
        </div>
      </div>
    );
  }

  return (
    <div className={shellClassNames.join(' ')}>
      {showChrome && (
        <header className="terminal-header">
          <div className="terminal-title">
            <h2>
              {headerTitle}
              {!compact && <span className="renderer-badge">xterm.js</span>}
            </h2>
            {subtitle && <span className="terminal-subtitle">{subtitle}</span>}
            <div className="status-line">
              <span className={`status status-${status}`}>{status}</span>
              {statusNote && <span className="status-note">{statusNote}</span>}
            </div>
          </div>
          <div className="terminal-meta">
            <span className="terminal-dimensions">
              {dimensions.cols}×{dimensions.rows}
            </span>
            <button
              type="button"
              className="terminal-reconnect"
              onClick={reconnect}
              aria-label={`Reconnect ${headerTitle}`}
              title="Reconnect terminal"
            >
              <RefreshCw size={14} aria-hidden="true" />
            </button>
          </div>
        </header>
      )}

      <div
        className="terminal-output xterm-wrapper"
        ref={containerRef}
        onClick={focusTerminal}
      />

      {showChrome && (
        <footer className="terminal-footer">
          <span className="hint">Click inside the terminal to type. Use Ctrl+C or the button to interrupt.</span>
          <button type="button" onClick={handleCtrlC}>
            Ctrl+C
          </button>
        </footer>
      )}
    </div>
  );
}
