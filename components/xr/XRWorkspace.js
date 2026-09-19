import { Component, Suspense, useCallback, useEffect, useMemo, useState } from 'react';
import dynamic from 'next/dynamic';
import { createXRStore } from '@react-three/xr';
import { useStore as useZustandStore } from 'zustand';
import useXrSessionQuery from '../../hooks/useXrSessionQuery.js';
import useXrSessions from '../../hooks/useXrSessions.js';
import useTerminalSpawnDialog from '../../hooks/useTerminalSpawnDialog.js';
import useXrSupport from '../../hooks/useXrSupport.js';
import useSpatialStore from '../../lib/stores/spatialStore.js';
import SpawnTerminalDialog from '../SpawnTerminalDialog.js';
import styles from './XRWorkspace.module.css';

const BaseXRCanvas = dynamic(() => import('./core/BaseXRCanvas'), {
  ssr: false
});

const SpatialTerminal = dynamic(() => import('./terminals/SpatialTerminal'), {
  ssr: false
});

const XR_SESSION_TARGETS = {
  vr: 'immersive-vr',
  ar: 'immersive-ar'
};

const TERMINAL_RING_RADIUS = 2.25;
const TERMINAL_RING_HEIGHT = 1.4;

const DEFAULT_SESSION_ENTRY = {
  id: null,
  shell: 'No session selected',
  cwd: ''
};

const cx = (...classes) => classes.filter(Boolean).join(' ');

const LoadingState = ({ message = 'Checking XR capabilities…' }) => (
  <div className={cx(styles['xr-status'], styles['xr-status--loading'])}>
    <div className={styles.spinner} aria-hidden />
    <p>{message}</p>
  </div>
);

const UnsupportedState = () => (
  <div className={cx(styles['xr-status'], styles['xr-status--unsupported'])}>
    <h2>WebXR Not Available</h2>
    <p>
      Your current browser or device does not support immersive experiences. Try updating your browser or using a
      WebXR-compatible device such as Meta Quest.
    </p>
    <ul>
      <li>Ensure HTTPS is enabled when deploying.</li>
      <li>Use Chrome, Edge, or Quest Browser for the best results.</li>
      <li>Desktop users can install the WebXR Emulator extension.</li>
    </ul>
  </div>
);

const XRModeSelector = ({ availableModes, currentMode, onChange }) => (
  <div className={styles['xr-mode-selector']} role="radiogroup" aria-label="XR session mode">
    {availableModes.map(mode => (
      <button
        key={mode}
        type="button"
        role="radio"
        aria-checked={currentMode === mode}
        className={currentMode === mode ? styles.active : ''}
        onClick={() => onChange(mode)}
      >
        {mode === 'vr' ? 'VR Mode' : 'AR Mode'}
      </button>
    ))}
  </div>
);

const XRSessionButtons = ({ supportedModes, store }) => {
  const [pendingMode, setPendingMode] = useState(null);
  const [error, setError] = useState(null);
  const activeMode = useZustandStore(store, state => state.mode);
  const activeSession = useZustandStore(store, state => state.session);

  const toggleSession = useCallback(
    async modeKey => {
      const targetMode = XR_SESSION_TARGETS[modeKey];

      if (!targetMode) {
        return;
      }

      setPendingMode(modeKey);
      setError(null);

      try {
        const { session, mode } = store.getState();

        if (session && mode === targetMode) {
          await session.end();
        } else {
          await store.enterXR(targetMode);
        }
      } catch (err) {
        console.error(`Failed to toggle ${modeKey.toUpperCase()} session`, err);
        setError(err instanceof Error ? err.message : 'Unable to start XR session');
      } finally {
        setPendingMode(null);
      }
    },
    [store]
  );

  const renderButton = modeKey => {
    const targetMode = XR_SESSION_TARGETS[modeKey];
    const isActive = activeSession != null && activeMode === targetMode;
    const isPending = pendingMode != null;
    const label = isActive ? `Exit ${modeKey.toUpperCase()}` : `Enter ${modeKey.toUpperCase()}`;

    return (
      <button
        key={modeKey}
        type="button"
        className={isActive ? styles.active : ''}
        disabled={isPending}
        onClick={() => toggleSession(modeKey)}
      >
        {isPending && pendingMode === modeKey ? 'Connecting…' : label}
      </button>
    );
  };

  return (
    <>
      <div className={styles['xr-session-buttons']}>
        {supportedModes.includes('vr') ? renderButton('vr') : null}
        {supportedModes.includes('ar') ? renderButton('ar') : null}
      </div>
      {error ? (
        <p className={styles['xr-session-error']} role="alert">
          {error}
        </p>
      ) : null}
    </>
  );
};

function resolveTerminalPlacement(index, total) {
  const count = Math.max(1, total);
  const step = (Math.PI * 2) / count;
  const baseAngle = index * step + Math.PI;
  const position = [
    Math.sin(baseAngle) * TERMINAL_RING_RADIUS,
    TERMINAL_RING_HEIGHT,
    Math.cos(baseAngle) * TERMINAL_RING_RADIUS
  ];
  const rotation = [0, baseAngle - Math.PI, 0];

  const isSolo = count === 1;

  return {
    position,
    rotation,
    size: isSolo ? [1.2, 0.75] : [1.05, 0.68],
    quality: isSolo ? 'high' : 'balanced'
  };
}

const SessionBrowser = ({ sessions, activeSessionId, loading, error, onRefresh, onSelect, onCreate, creating }) => {
  const hasSessions = sessions.length > 0;
  const entries = hasSessions ? sessions : [DEFAULT_SESSION_ENTRY];

  return (
    <section className={styles['xr-session-browser']} aria-labelledby="xr-session-browser-heading">
      <div className={styles['xr-session-browser__header']}>
        <div>
          <h2 id="xr-session-browser-heading">Choose a terminal</h2>
          <p>Select a session to preview before starting an immersive experience.</p>
        </div>
        <div className={styles['xr-session-browser__actions']}>
          {typeof onCreate === 'function' ? (
            <button type="button" onClick={onCreate} disabled={creating || loading}>
              {creating ? 'Spawning…' : 'New terminal'}
            </button>
          ) : null}
          <button type="button" onClick={onRefresh} disabled={loading}>
            {loading ? 'Refreshing…' : 'Refresh'}
          </button>
        </div>
      </div>
      {error ? (
        <p className={styles['xr-session-browser__error']} role="alert">
          {error}
        </p>
      ) : null}
      <div className={styles['xr-session-grid']}>
        {entries.map(session => {
          const isActive = session.id === activeSessionId;
          return (
            <button
              type="button"
              key={session.id ?? `placeholder-${session.shell}`}
              className={cx(styles['xr-session-card'], isActive ? styles.active : null)}
              onClick={() => (session.id ? onSelect(session.id) : null)}
              disabled={!session.id}
            >
              <span className={styles['xr-session-card__title']}>
                {session.id ? `Session #${session.id}` : 'No sessions available'}
              </span>
              <span className={styles['xr-session-card__meta']}>{session.shell ?? 'Unknown shell'}</span>
              {session.cwd ? <span className={styles['xr-session-card__cwd']}>{session.cwd}</span> : null}
            </button>
          );
        })}
        {!hasSessions && !loading ? (
          <div className={styles['xr-session-empty']} role="note">
            No terminals are running yet. Use the dashboard to start one.
          </div>
        ) : null}
      </div>
    </section>
  );
};

const DefaultXRScene = ({ sessions, activeSessionId, onSessionFocus }) => {
  const entries = sessions.length ? sessions : [DEFAULT_SESSION_ENTRY];
  const total = entries.length;

  return (
    <group>
      <ambientLight intensity={0.6} />
      <directionalLight position={[4, 6, 2]} intensity={1.1} castShadow />
      {entries.map((session, index) => {
        const placement = resolveTerminalPlacement(index, total);
        const terminalId = session.id ? `session-${session.id}` : `placeholder-${index}`;
        const isActive = session.id != null && session.id === activeSessionId;

        return (
          <SpatialTerminal
            key={terminalId}
            sessionId={session.id ?? undefined}
            terminalId={terminalId}
            title={session.id ? `Session ${session.id} · ${session.shell}` : session.shell}
            position={placement.position}
            rotation={placement.rotation}
            size={placement.size}
            quality={placement.quality}
            holographic={isActive}
            onFocus={() => {
              if (session.id && typeof onSessionFocus === 'function') {
                onSessionFocus(session.id);
              }
            }}
          />
        );
      })}
      <mesh rotation={[-Math.PI / 2, 0, 0]} position={[0, -0.02, 0]} receiveShadow>
        <planeGeometry args={[12, 12]} />
        <meshStandardMaterial color="#0b101f" roughness={0.8} metalness={0.05} />
      </mesh>
      <gridHelper args={[10, 20, '#263238', '#0d1b2a']} position={[0, -0.01, 0]} />
    </group>
  );
};

class XRPageErrorBoundary extends Component {
  constructor(props) {
    super(props);
    this.state = { hasError: false, error: null };
  }

  static getDerivedStateFromError(error) {
    return { hasError: true, error };
  }

  componentDidCatch(error, info) {
    console.error('XR page rendering error', error, info);
  }

  render() {
    if (this.state.hasError) {
      return (
        <div className={cx(styles['xr-status'], styles['xr-status--error'])}>
          <h2>Unable to Load XR Experience</h2>
          <p>Something went wrong while preparing the immersive workspace.</p>
          <pre>{this.state.error?.message}</pre>
        </div>
      );
    }

    return this.props.children;
  }
}

export default function XRWorkspace() {
  const xrSupport = useXrSupport();
  const [mode, setMode] = useState('vr');
  const { requestTerminalSpawn, spawnDialogProps } = useTerminalSpawnDialog();
  const {
    sessions,
    loading: sessionsLoading,
    error: sessionsError,
    refresh: loadSessions,
    create: createSession,
    creating: creatingSession
  } = useXrSessions({ spawnTerminal: requestTerminalSpawn });
  const { activeSessionId, setActiveSessionId } = useXrSessionQuery({ sessions });
  const xrStore = useMemo(
    () =>
      createXRStore({
        handTracking: 'preferred',
        domOverlay: true,
        layers: false,
        emulate: true
      }),
    []
  );

  const setActiveTerminal = useSpatialStore(state => state.setActiveTerminal);

  useEffect(
    () => () => {
      xrStore?.destroy?.();
    },
    [xrStore]
  );

  useEffect(() => {
    if (!xrSupport.modes.length) {
      return;
    }
    setMode(previous => (xrSupport.modes.includes(previous) ? previous : xrSupport.modes[0] ?? 'vr'));
  }, [xrSupport.modes]);

  useEffect(() => {
    const terminalId = activeSessionId ? `session-${activeSessionId}` : null;
    setActiveTerminal(terminalId);
  }, [activeSessionId, setActiveTerminal]);

  useEffect(() => {
    if (sessionsError) {
      return;
    }
    if (!sessionsLoading && !sessions.length) {
      setActiveTerminal(null);
    }
  }, [sessionsError, sessionsLoading, sessions.length, setActiveTerminal]);

  const handleSessionSelect = useCallback(
    sessionId => {
      if (sessionId === activeSessionId) {
        return;
      }
      setActiveSessionId(sessionId);
    },
    [activeSessionId, setActiveSessionId]
  );

  const handleSessionFocus = useCallback(
    sessionId => {
      if (sessionId === activeSessionId) {
        return;
      }
      setActiveSessionId(sessionId);
    },
    [activeSessionId, setActiveSessionId]
  );

  const handleCreateSession = useCallback(async () => {
    const newId = await createSession();
    if (newId != null) {
      setActiveSessionId(newId);
    }
  }, [createSession, setActiveSessionId]);

  const showFallback = !xrSupport.checking && xrSupport.modes.length === 0 && !xrSupport.error;
  const sessionsForBrowser = sessions.length ? sessions : [DEFAULT_SESSION_ENTRY];

  return (
    <>
      <main className={styles['xr-page']}>
        <header className={styles['xr-header']}>
          <h1>Spatial XR Workspace</h1>
          <p>Explore the immersive terminal environment in VR or AR.</p>
        </header>

        <SessionBrowser
          sessions={sessionsForBrowser}
          activeSessionId={activeSessionId}
          loading={sessionsLoading}
          error={sessionsError}
          onRefresh={() => loadSessions()}
          onSelect={handleSessionSelect}
          onCreate={handleCreateSession}
          creating={creatingSession}
        />

        {xrSupport.checking ? <LoadingState /> : null}
        {xrSupport.error ? (
          <div className={cx(styles['xr-status'], styles['xr-status--error'])}>
            <h2>XR Detection Failed</h2>
            <p>We could not determine if immersive sessions are supported.</p>
            <pre>{xrSupport.error.message}</pre>
          </div>
        ) : null}
        {showFallback ? <UnsupportedState /> : null}

        {!xrSupport.checking && xrSupport.modes.length > 0 ? (
          <section className={styles['xr-experience']} aria-live="polite">
            <XRModeSelector availableModes={xrSupport.modes} currentMode={mode} onChange={setMode} />
            <XRPageErrorBoundary>
              <Suspense fallback={<LoadingState message="Preparing immersive scene…" />}>
                <div className={styles['xr-canvas-container']}>
                  <BaseXRCanvas mode={mode} store={xrStore}>
                    <DefaultXRScene
                      sessions={sessions}
                      activeSessionId={activeSessionId}
                      onSessionFocus={handleSessionFocus}
                    />
                  </BaseXRCanvas>
                </div>
              </Suspense>
            </XRPageErrorBoundary>
            <XRSessionButtons supportedModes={xrSupport.modes} store={xrStore} />
          </section>
        ) : null}
      </main>
      <SpawnTerminalDialog {...spawnDialogProps} />
    </>
  );
}
