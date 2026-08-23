import { useCallback, useEffect, useMemo } from 'react';
import { useRouter } from 'next/router';

function parseSessionId(value) {
  if (value == null) {
    return null;
  }
  const raw = Array.isArray(value) ? value[0] : value;
  const parsed = Number.parseInt(String(raw), 10);
  return Number.isFinite(parsed) ? parsed : null;
}

export default function useXrSessionQuery({ sessions } = {}) {
  const router = useRouter();

  const activeSessionId = useMemo(() => {
    if (!router?.isReady) {
      return null;
    }
    return parseSessionId(router.query?.session);
  }, [router?.isReady, router?.query?.session]);

  const setActiveSessionId = useCallback(
    sessionId => {
      if (!router?.isReady) {
        return;
      }
      const nextQuery = { ...router.query };
      if (sessionId) {
        nextQuery.session = String(sessionId);
      } else {
        delete nextQuery.session;
      }
      router.replace({ pathname: router.pathname, query: nextQuery }, undefined, { shallow: true });
    },
    [router]
  );

  useEffect(() => {
    if (!router?.isReady) {
      return;
    }
    if (!sessions?.length) {
      if (router.query?.session) {
        const nextQuery = { ...router.query };
        delete nextQuery.session;
        router.replace({ pathname: router.pathname, query: nextQuery }, undefined, { shallow: true });
      }
      return;
    }
    const sessionIds = new Set(sessions.map(session => session.id));
    if (!activeSessionId || !sessionIds.has(activeSessionId)) {
      const fallback = sessions[0]?.id;
      if (!fallback || activeSessionId === fallback) {
        return;
      }
      const nextQuery = { ...router.query, session: String(fallback) };
      router.replace({ pathname: router.pathname, query: nextQuery }, undefined, { shallow: true });
    }
  }, [router, sessions, activeSessionId]);

  return {
    activeSessionId,
    setActiveSessionId
  };
}
