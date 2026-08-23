import { useCallback, useEffect, useRef, useState } from 'react';
import { browserFetch } from '../lib/browserRequest.js';

const DEFAULT_SESSIONS = [];

async function fetchSessions({ signal } = {}) {
  const response = await browserFetch('/api/terminals', { signal });
  if (!response.ok) {
    const payload = await response.json().catch(() => ({}));
    throw new Error(payload.error || response.statusText);
  }

  const data = await response.json();
  return Array.isArray(data.sessions) ? data.sessions : [];
}

async function createSession() {
  const response = await browserFetch('/api/terminals', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({})
  });
  const payload = await response.json().catch(() => ({}));
  if (!response.ok) {
    throw new Error(payload.error || response.statusText);
  }

  return payload?.session?.id ?? null;
}

export default function useXrSessions({ autoLoad = true } = {}) {
  const [sessions, setSessions] = useState(DEFAULT_SESSIONS);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const [creating, setCreating] = useState(false);
  const refreshAbortRef = useRef(null);

  const refresh = useCallback(async () => {
    if (refreshAbortRef.current) {
      refreshAbortRef.current.abort();
    }

    const controller = new AbortController();
    refreshAbortRef.current = controller;
    setLoading(true);
    setError(null);

    try {
      const nextSessions = await fetchSessions({ signal: controller.signal });
      if (!controller.signal.aborted) {
        setSessions(nextSessions);
      }
    } catch (fetchError) {
      if (controller.signal.aborted || fetchError?.name === 'AbortError') {
        return;
      }
      console.error('Failed to load terminal sessions', fetchError);
      setError(fetchError instanceof Error ? fetchError.message : 'Unable to load sessions');
    } finally {
      if (!controller.signal.aborted) {
        setLoading(false);
      }
    }
  }, []);

  const create = useCallback(async () => {
    setCreating(true);
    setError(null);
    try {
      const sessionId = await createSession();
      await refresh();
      return sessionId;
    } catch (createError) {
      console.error('Failed to create terminal session', createError);
      setError(createError instanceof Error ? createError.message : 'Unable to create session');
      return null;
    } finally {
      setCreating(false);
    }
  }, [refresh]);

  useEffect(() => {
    if (!autoLoad) {
      return () => {};
    }

    refresh();

    return () => {
      if (refreshAbortRef.current) {
        refreshAbortRef.current.abort();
      }
    };
  }, [autoLoad, refresh]);

  return {
    sessions,
    loading,
    error,
    refresh,
    create,
    creating
  };
}
