function normalizeBaseUrl(value) {
  const parsed = new URL(String(value || 'http://127.0.0.1:1337'));
  parsed.pathname = parsed.pathname.replace(/\/+$/, '');
  parsed.search = '';
  parsed.hash = '';
  return parsed.toString().replace(/\/+$/, '');
}

export function createCollabAdminClient(options = {}) {
  const baseUrl = normalizeBaseUrl(options.baseUrl);
  const fetchImpl = options.fetchImpl || globalThis.fetch;
  if (typeof fetchImpl !== 'function') {
    throw new Error('createCollabAdminClient requires fetch');
  }

  async function request(pathname, init = {}) {
    const response = await fetchImpl(`${baseUrl}${pathname}`, {
      ...init,
      headers: {
        Accept: 'application/json',
        ...(init.body === undefined ? {} : { 'Content-Type': 'application/json' }),
        ...(init.headers || {}),
      },
    });
    const payload = await response.json().catch(() => null);
    if (!response.ok) {
      const error = new Error(payload?.error?.message || `collab daemon request failed (${response.status})`);
      error.statusCode = response.status;
      error.payload = payload;
      throw error;
    }
    return payload;
  }

  return {
    baseUrl,
    eventsUrl: `${baseUrl}/admin/v1/events`,
    bootstrap: () => request('/admin/v1/bootstrap'),
    refreshCatalog: () => request('/admin/v1/catalog/refresh', {
      method: 'POST',
      body: JSON.stringify({}),
    }),
    getConfig: () => request('/admin/v1/config'),
    writeConfig: (scope, revision, document) => request(`/admin/v1/config/${encodeURIComponent(scope)}`, {
      method: 'PUT',
      body: JSON.stringify({ revision, document }),
    }),
    getSession: () => request('/admin/v1/session'),
    createSession: (input) => request('/admin/v1/session', {
      method: 'POST',
      body: JSON.stringify(input || {}),
    }),
    updateSession: (input) => request('/admin/v1/session', {
      method: 'PATCH',
      body: JSON.stringify(input || {}),
    }),
    stopSession: () => request('/admin/v1/session', { method: 'DELETE' }),
    retryAgent: (agentId) => request(`/admin/v1/session/agents/${encodeURIComponent(agentId)}/retry`, { method: 'POST' }),
    setAgentHealth: (agentId, input) => request(
      `/admin/v1/session/agents/${encodeURIComponent(agentId)}/health`,
      {
        method: 'PUT',
        body: JSON.stringify(input || {}),
      },
    ),
    setAgentPermissionMode: (agentId, permissionMode) => request(
      `/admin/v1/session/agents/${encodeURIComponent(agentId)}/permission-mode`,
      {
        method: 'POST',
        body: JSON.stringify({ permissionMode }),
      },
    ),
    getMessages: (channel, limit = 100, cursor = null) => {
      const params = new URLSearchParams({ limit: String(limit) });
      if (cursor !== null && cursor !== undefined) {
        params.set('cursor', String(cursor));
      }
      return request(
        `/admin/v1/channels/${encodeURIComponent(channel)}/messages?${params.toString()}`,
      );
    },
    sendMessage: (channel, input) => request(`/admin/v1/channels/${encodeURIComponent(channel)}/messages`, {
      method: 'POST',
      body: JSON.stringify(input || {}),
    }),
    setMessageFeedback: (channel, messageId, rating) => request(
      `/admin/v1/channels/${encodeURIComponent(channel)}`
        + `/messages/${encodeURIComponent(messageId)}/feedback`,
      {
        method: 'PUT',
        body: JSON.stringify({ rating }),
      },
    ),
    getStats: (scope = 'session') => request(
      `/admin/v1/stats?scope=${encodeURIComponent(scope)}`,
    ),
  };
}
