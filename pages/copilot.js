import Head from 'next/head';
import { useCallback, useEffect, useMemo, useState } from 'react';
import { useRouter } from 'next/router';
import { PanelRightOpen, RefreshCw } from 'lucide-react';
import CopilotPane from '../components/CopilotPane.js';
import {
  createCopilotWindowMessage,
  getCopilotPopoutInstance,
  getCopilotPopoutSource,
  isCopilotWindowMessage,
  resolveCopilotPopoutSession
} from '../components/copilotPaneModel.js';
import { browserFetch } from '../lib/browserRequest.js';
import { isTerminalLockdownEnabled } from '../lib/lockdown.js';
import styles from '../styles/Terminal.module.css';

async function fetchSourceSession(sourceTerminalUuid) {
  const response = await browserFetch('/api/terminals');
  const payload = await response.json().catch(() => ({}));
  if (!response.ok) {
    throw new Error(payload.error || response.statusText || 'Unable to load terminal sessions');
  }
  const sessions = Array.isArray(payload.sessions)
    ? payload.sessions.filter((session) => session?.metadata?.type !== 'copilot-view')
    : [];
  return resolveCopilotPopoutSession(sessions, sourceTerminalUuid);
}

export default function CopilotPopoutPage() {
  const router = useRouter();
  const sourceTerminalUuid = useMemo(
    () => getCopilotPopoutSource(router.query),
    [router.query]
  );
  const instanceId = useMemo(
    () => getCopilotPopoutInstance(router.query),
    [router.query]
  );
  const [session, setSession] = useState(null);
  const [selectedText, setSelectedText] = useState('');
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');

  const loadSession = useCallback(async () => {
    if (!router.isReady) {
      return;
    }
    if (!sourceTerminalUuid) {
      setSession(null);
      setLoading(false);
      setError('This Copilot window is missing its source terminal identity.');
      return;
    }

    setLoading(true);
    setError('');
    try {
      const nextSession = await fetchSourceSession(sourceTerminalUuid);
      setSession(nextSession);
      if (!nextSession) {
        setError('The source terminal has ended or is no longer available.');
      }
    } catch (err) {
      setSession(null);
      setError(err.message);
    } finally {
      setLoading(false);
    }
  }, [router.isReady, sourceTerminalUuid]);

  useEffect(() => {
    loadSession();
  }, [loadSession]);

  useEffect(() => {
    if (!router.isReady || typeof window === 'undefined' || !sourceTerminalUuid) {
      return undefined;
    }

    const opener = window.opener;
    const handleMessage = (event) => {
      if (
        !opener
        || event.origin !== window.location.origin
        || event.source !== opener
        || !isCopilotWindowMessage(event.data, 'selection')
        || event.data.sourceTerminalUuid !== sourceTerminalUuid
        || event.data.instanceId !== instanceId
      ) {
        return;
      }
      setSelectedText(
        typeof event.data.selectedText === 'string' ? event.data.selectedText : ''
      );
    };

    window.addEventListener('message', handleMessage);
    if (opener && !opener.closed) {
      opener.postMessage(createCopilotWindowMessage('ready', {
        sourceTerminalUuid,
        instanceId
      }), window.location.origin);
    }
    return () => window.removeEventListener('message', handleMessage);
  }, [instanceId, router.isReady, sourceTerminalUuid]);

  const dockCopilotPane = useCallback(() => {
    if (typeof window === 'undefined') {
      return;
    }
    const opener = window.opener;
    if (opener && !opener.closed) {
      opener.postMessage(createCopilotWindowMessage('dock', {
        sourceTerminalUuid,
        instanceId
      }), window.location.origin);
      window.close();
      return;
    }
    window.location.assign('/');
  }, [instanceId, sourceTerminalUuid]);

  const clearSelectedText = useCallback(() => {
    setSelectedText('');
    if (typeof window === 'undefined') {
      return;
    }
    const opener = window.opener;
    if (opener && !opener.closed) {
      opener.postMessage(createCopilotWindowMessage('clear-selection', {
        sourceTerminalUuid,
        instanceId
      }), window.location.origin);
    }
  }, [instanceId, sourceTerminalUuid]);

  const title = session ? `Copilot · Terminal #${session.id}` : 'Copilot · Notty';

  return (
    <main className={`${styles.page} copilot-popout-page`}>
      <Head>
        <title>{title}</title>
      </Head>
      {session ? (
        <CopilotPane
          session={session}
          selectedText={selectedText}
          onClearSelection={clearSelectedText}
          onDock={dockCopilotPane}
        />
      ) : (
        <section className="copilot-popout-state" aria-live="polite">
          <div>
            <h1>Copilot</h1>
            <p>{loading ? 'Connecting to the source terminal…' : error}</p>
            <div className="copilot-popout-state-actions">
              {!loading && sourceTerminalUuid && (
                <button type="button" onClick={loadSession}>
                  <RefreshCw size={14} aria-hidden="true" />
                  Retry
                </button>
              )}
              <button type="button" onClick={dockCopilotPane}>
                <PanelRightOpen size={14} aria-hidden="true" />
                Dock in terminal window
              </button>
            </div>
          </div>
        </section>
      )}
    </main>
  );
}

export async function getServerSideProps() {
  const lockdownEnabled = isTerminalLockdownEnabled()
    || isTerminalLockdownEnabled(process.env.NOTTY_LOCKDOWN_UI ?? '');

  if (lockdownEnabled) {
    return {
      redirect: {
        destination: '/lockdown',
        permanent: false
      }
    };
  }

  return { props: {} };
}
