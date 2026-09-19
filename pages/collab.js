import { useCallback, useEffect, useRef, useState } from 'react';
import Link from 'next/link';
import { useRouter } from 'next/router';
import CollabLaunchpad from '../components/collab/CollabLaunchpad.js';
import CollabWorkspace from '../components/collab/CollabWorkspace.js';
import {
  removeScopedTemplate,
  removeScopedPrompt,
  updateScopedPrompt,
  updateScopedTemplate
} from '../components/collab/configModel.js';
import { browserFetch, resolveBrowserUrl } from '../lib/browserRequest.js';
import { isTerminalLockdownEnabled } from '../lib/lockdown.js';
import { isCollabEnabled } from '../lib/runtimeFeatures.js';
import styles from '../styles/Collab.module.css';

async function jsonRequest(url, options = {}) {
  const response = await browserFetch(url, {
    ...options,
    headers: {
      'Content-Type': 'application/json',
      ...(options.headers || {})
    }
  });

  if (!response.ok) {
    const payload = await response.json().catch(() => ({}));
    throw new Error(
      payload.error?.message
      || (typeof payload.error === 'string' ? payload.error : '')
      || payload.message
      || response.statusText
      || `Request failed (${response.status})`
    );
  }
  if (response.status === 204) {
    return null;
  }
  return response.json();
}

function configFrom(payload) {
  return payload?.config || payload || {};
}

export default function CollabPage() {
  const router = useRouter();
  const chatsOnly = router.query.chats === '1';
  const [bootstrap, setBootstrap] = useState(null);
  const [config, setConfig] = useState(null);
  const [views, setViews] = useState(null);
  const [selectedTemplateId, setSelectedTemplateId] = useState('');
  const [loading, setLoading] = useState(true);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const [attachError, setAttachError] = useState('');
  const [eventStatus, setEventStatus] = useState('connecting');
  const [eventRevision, setEventRevision] = useState(0);
  const refreshTimerRef = useRef(null);
  const refreshViewsRef = useRef(false);
  const autoResumeAttempted = useRef(false);

  const loadData = useCallback(async ({ quiet = false } = {}) => {
    if (!quiet) setLoading(true);
    try {
      const [bootstrapPayload, configPayload] = await Promise.all([
        jsonRequest('/api/collab/bootstrap'),
        jsonRequest('/api/collab/config')
      ]);
      const detailedConfig = configFrom(configPayload);
      const nextConfig = {
        ...(bootstrapPayload.config || {}),
        ...detailedConfig,
        documents: detailedConfig.documents || bootstrapPayload.config?.documents || {}
      };
      setBootstrap(bootstrapPayload);
      setConfig(nextConfig);
      const savedTemplateId = bootstrapPayload.tasks?.tasks?.find((entry) => entry.id === bootstrapPayload.tasks.lastTaskId)?.launch?.templateId;
      setSelectedTemplateId((current) => (
        nextConfig.templates?.some((template) => template.id === current)
          ? current
          : nextConfig.templates?.some((template) => template.id === savedTemplateId)
            ? savedTemplateId : nextConfig.defaultTemplate || nextConfig.templates?.[0]?.id || ''
      ));
      setError('');
      return bootstrapPayload;
    } catch (requestError) {
      setError(requestError.message);
      return null;
    } finally {
      if (!quiet) setLoading(false);
    }
  }, []);

  useEffect(() => {
    loadData();
  }, [loadData]);

  const loadViewsForSession = useCallback(async (sessionId) => {
    if (!sessionId) return;
    try {
      const payload = await jsonRequest('/api/collab/session/views', {
        method: 'POST',
        body: JSON.stringify({})
      });
      setViews(payload);
      setAttachError('');
    } catch (requestError) {
      setAttachError(requestError.message);
    }
  }, []);

  useEffect(() => {
    if (typeof window === 'undefined') return undefined;
    const source = new EventSource(resolveBrowserUrl('/api/collab/events'));
    const scheduleRefresh = (event) => {
      setEventRevision((revision) => revision + 1);
      if (event?.type === 'agent.status') {
        refreshViewsRef.current = true;
      }
      if (refreshTimerRef.current) return;
      refreshTimerRef.current = window.setTimeout(async () => {
        refreshTimerRef.current = null;
        const shouldRefreshViews = refreshViewsRef.current;
        refreshViewsRef.current = false;
        const payload = await loadData({ quiet: true });
        if (shouldRefreshViews && payload?.session?.id) {
          await loadViewsForSession(payload.session.id);
        }
      }, 180);
    };
    const eventNames = [
      'session.changed',
      'session.resume-error',
      'agent.status',
      'agent.registration',
      'agent.pending',
      'config.changed',
      'channel.message',
      'message.feedback',
      'feedback.changed',
      'agent.health',
      'health.changed',
      'catalog.changed',
      'catalog.refreshed'
    ];

    source.onopen = () => setEventStatus('live');
    source.onerror = () => setEventStatus('reconnecting');
    eventNames.forEach((name) => source.addEventListener(name, scheduleRefresh));

    return () => {
      eventNames.forEach((name) => source.removeEventListener(name, scheduleRefresh));
      source.close();
      if (refreshTimerRef.current) {
        window.clearTimeout(refreshTimerRef.current);
        refreshTimerRef.current = null;
      }
    };
  }, [loadData, loadViewsForSession]);

  const session = bootstrap?.session || null;

  const loadViews = useCallback(
    () => loadViewsForSession(session?.id),
    [loadViewsForSession, session?.id]
  );

  useEffect(() => {
    setViews(null);
    setAttachError('');
    if (session?.id) {
      loadViews();
    }
  }, [session?.id, loadViews]);

  const runAction = async (action) => {
    setBusy(true);
    setError('');
    try {
      await action();
      return true;
    } catch (actionError) {
      setError(actionError.message);
      return false;
    } finally {
      setBusy(false);
    }
  };

  const launch = (payload) => runAction(async () => {
    await jsonRequest('/api/collab/session', {
      method: 'POST',
      body: JSON.stringify(payload)
    });
    await loadData({ quiet: true });
  });

  const saveTemplate = (scope, templateId, template) => runAction(async () => {
    const document = updateScopedTemplate(
      config.documents?.[scope],
      templateId,
      template,
      config.schemaVersion
    );
    await jsonRequest(`/api/collab/config/${scope}`, {
      method: 'PUT',
      body: JSON.stringify({
        revision: config.revisions?.[scope] || '',
        document
      })
    });
    await loadData({ quiet: true });
  });

  const removeOverride = (scope, templateId) => runAction(async () => {
    const document = removeScopedTemplate(
      config.documents?.[scope],
      templateId,
      config.schemaVersion
    );
    await jsonRequest(`/api/collab/config/${scope}`, {
      method: 'PUT',
      body: JSON.stringify({
        revision: config.revisions?.[scope] || '',
        document
      })
    });
    await loadData({ quiet: true });
  });

  const savePrompt = (scope, promptId, prompt) => runAction(async () => {
    const document = updateScopedPrompt(
      config.documents?.[scope],
      promptId,
      prompt,
      config.schemaVersion
    );
    await jsonRequest(`/api/collab/config/${scope}`, {
      method: 'PUT',
      body: JSON.stringify({
        revision: config.revisions?.[scope] || '',
        document
      })
    });
    await loadData({ quiet: true });
  });

  const removePrompt = (scope, promptId) => runAction(async () => {
    const document = removeScopedPrompt(
      config.documents?.[scope],
      promptId,
      config.schemaVersion
    );
    await jsonRequest(`/api/collab/config/${scope}`, {
      method: 'PUT',
      body: JSON.stringify({
        revision: config.revisions?.[scope] || '',
        document
      })
    });
    await loadData({ quiet: true });
  });

  const createTask = async (name) => {
    let created;
    const success = await runAction(async () => {
      created = await jsonRequest('/api/collab/tasks', { method: 'POST', body: JSON.stringify({ name }) });
      await loadData({ quiet: true });
    });
    return success ? created : false;
  };
  const taskSettings = (settings) => runAction(async () => {
    await jsonRequest('/api/collab/tasks', { method: 'PATCH', body: JSON.stringify(settings) });
    const saved = bootstrap?.tasks?.tasks?.find((entry) => entry.id === settings.taskId)?.launch;
    if (saved?.templateId) setSelectedTemplateId(saved.templateId);
    await loadData({ quiet: true });
  });
  useEffect(() => {
    if (!router.isReady || !bootstrap || autoResumeAttempted.current) return;
    autoResumeAttempted.current = true;
    if (chatsOnly || bootstrap.session || !bootstrap.tasks?.autoResume) return;
    runAction(async () => {
      await jsonRequest('/api/collab/session', { method: 'POST', body: JSON.stringify({ autoResume: true }) });
      await loadData({ quiet: true });
    });
  }, [router.isReady, bootstrap, chatsOnly]);

  const refreshCatalog = () => runAction(async () => {
    await jsonRequest('/api/collab/catalog/refresh', {
      method: 'POST',
      body: JSON.stringify({})
    });
    await loadData({ quiet: true });
  });

  const changeLayout = (layout) => runAction(async () => {
    await jsonRequest('/api/collab/session', {
      method: 'PATCH',
      body: JSON.stringify({ layout })
    });
    await loadData({ quiet: true });
  });

  const retryAgent = (agentId) => runAction(async () => {
    await jsonRequest(`/api/collab/session/agents/${encodeURIComponent(agentId)}/retry`, {
      method: 'POST',
      body: JSON.stringify({})
    });
    await loadData({ quiet: true });
    await loadViews();
  });

  const changeAgentPermissionMode = (agentId, permissionMode) => runAction(async () => {
    await jsonRequest(
      `/api/collab/session/agents/${encodeURIComponent(agentId)}/permission-mode`,
      {
        method: 'POST',
        body: JSON.stringify({ permissionMode })
      }
    );
    await loadData({ quiet: true });
    await loadViews();
  });

  const changeAgentHealth = (agentId, code) => runAction(async () => {
    await jsonRequest(
      `/api/collab/session/agents/${encodeURIComponent(agentId)}/health`,
      {
        method: 'PUT',
        body: JSON.stringify({ code })
      }
    );
    await loadData({ quiet: true });
  });

  const loadStats = useCallback((scope) => jsonRequest(
    `/api/collab/stats?scope=${encodeURIComponent(scope)}`
  ), []);

  const loadMessages = useCallback(() => {
    if (!session?.channel) return Promise.resolve({ messages: [] });
    return jsonRequest(
      `/api/collab/channels/${encodeURIComponent(session.channel)}/messages?limit=100`
    );
  }, [session?.channel]);

  const rateMessage = useCallback((messageId, rating) => {
    if (!session?.channel) return Promise.resolve(null);
    return jsonRequest(
      `/api/collab/channels/${encodeURIComponent(session.channel)}/messages/${
        encodeURIComponent(messageId)
      }/feedback`,
      {
        method: 'PUT',
        body: JSON.stringify({ rating })
      }
    );
  }, [session?.channel]);

  const stopSession = () => runAction(async () => {
    await jsonRequest('/api/collab/session/views', { method: 'DELETE' }).catch(() => null);
    await jsonRequest('/api/collab/session', { method: 'DELETE' });
    setViews(null);
    await loadData({ quiet: true });
  });

  return (
    <main className={styles.page}>
      <header className={styles.appHeader} hidden={chatsOnly}>
        <div className={styles.brandBlock}>
          <div className={styles.brandLine}>
            <h1>Collab Operations</h1>
            <span
              className={`${styles.serviceState} ${bootstrap?.service?.status === 'ready' || bootstrap?.daemon?.marker ? styles.serviceReady : ''}`}
              role="status"
            >
              {bootstrap?.service?.status || (bootstrap?.daemon?.marker ? 'ready' : loading ? 'starting' : 'offline')}
            </span>
          </div>
          <span className={styles.workspacePath}>
            {bootstrap?.paths?.workspaceRoot || bootstrap?.workspaceRoot || 'workspace unavailable'}
          </span>
        </div>
        <nav className={styles.primaryNav} aria-label="Primary">
          <Link href="/">Terminals</Link>
          <Link href="/collab" aria-current="page">Collab</Link>
        </nav>
      </header>

      {error && (
        <div className={styles.pageError} role="alert">
          <span>{error}</span>
          <button type="button" onClick={() => loadData()} disabled={loading}>Retry</button>
        </div>
      )}

      <div className={styles.pageBody}>
        {loading && !bootstrap ? (
          <div className={styles.loadingState}>Loading collab state…</div>
        ) : chatsOnly && (!session || router.query.session !== session.id) ? (
          <div className={styles.emptyState}>This collaboration session is no longer active. You can close this window.</div>
        ) : session && config ? (
          <CollabWorkspace
            key={`${session.id}-${chatsOnly}`}
            chatsOnly={chatsOnly}
            session={session}
            config={config}
            views={views}
            eventStatus={eventStatus}
            eventRevision={eventRevision}
            busy={busy}
            attachError={attachError}
            onRefreshViews={loadViews}
            onChangeLayout={changeLayout}
            onChangeAgentPermissionMode={changeAgentPermissionMode}
            onChangeAgentHealth={changeAgentHealth}
            onRetryAgent={retryAgent}
            onLoadStats={loadStats}
            onLoadMessages={loadMessages}
            onRateMessage={rateMessage}
            onStop={stopSession}
          />
        ) : config ? (
          <CollabLaunchpad
            tasks={bootstrap?.tasks}
            onCreateTask={createTask}
            onTaskSettings={taskSettings}
            config={config}
            selectedTemplateId={selectedTemplateId}
            onSelectTemplate={setSelectedTemplateId}
            onLaunch={launch}
            onSaveTemplate={saveTemplate}
            onRemoveOverride={removeOverride}
            onSavePrompt={savePrompt}
            onRemovePrompt={removePrompt}
            onRefreshCatalog={refreshCatalog}
            modelCatalog={
              bootstrap?.modelCatalog
              || bootstrap?.config?.modelCatalog
              || config.modelCatalog
              || []
            }
            launchCatalog={
              bootstrap?.launchCatalog
              || bootstrap?.config?.launchCatalog
              || config.launchCatalog
              || null
            }
            busy={busy}
          />
        ) : (
          <div className={styles.loadingState}>Collab service unavailable</div>
        )}
      </div>
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

  if (!isCollabEnabled()) {
    return { notFound: true };
  }

  return { props: {} };
}
