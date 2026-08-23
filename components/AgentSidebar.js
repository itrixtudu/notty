import { useCallback, useEffect, useMemo, useState } from 'react';
import { browserFetch } from '../lib/browserRequest.js';

async function jsonFetch(url, options) {
  const response = await browserFetch(url, {
    headers: { 'Content-Type': 'application/json' },
    ...options
  });
  if (!response.ok) {
    const payload = await response.json().catch(() => ({}));
    throw new Error(payload.error || response.statusText);
  }
  return response.json();
}

function normalizeTerminalInput(command) {
  const text = String(command || '').replace(/\n/g, '\r');
  return text.endsWith('\r') ? text : `${text}\r`;
}

function formatTime(value) {
  if (!value) {
    return '';
  }
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) {
    return '';
  }
  return date.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
}

export default function AgentSidebar({ session }) {
  const [agents, setAgents] = useState([]);
  const [selectedAgentIds, setSelectedAgentIds] = useState([]);
  const [messages, setMessages] = useState([]);
  const [channels, setChannels] = useState([]);
  const [scope, setScope] = useState('tail');
  const [prompt, setPrompt] = useState('');
  const [loadingAgents, setLoadingAgents] = useState(false);
  const [asking, setAsking] = useState(false);
  const [sendingCommand, setSendingCommand] = useState('');
  const [error, setError] = useState('');

  const terminalUuid = session?.terminal_uuid || '';
  const terminalId = session?.id || null;

  const selectedCount = selectedAgentIds.length;
  const enabledAgents = useMemo(
    () => agents.filter((agent) => agent.enabled),
    [agents]
  );

  const loadAgents = useCallback(async () => {
    setLoadingAgents(true);
    try {
      const data = await jsonFetch('/api/agents');
      const nextAgents = Array.isArray(data.agents) ? data.agents : [];
      setAgents(nextAgents);
      setSelectedAgentIds((previous) => {
        const enabledIds = nextAgents.filter((agent) => agent.enabled).map((agent) => agent.id);
        const kept = previous.filter((id) => enabledIds.includes(id));
        return kept.length ? kept : enabledIds;
      });
      setError(data.configError ? `Agent config: ${data.configError}` : '');
    } catch (err) {
      setError(err.message);
    } finally {
      setLoadingAgents(false);
    }
  }, []);

  const loadMessages = useCallback(async () => {
    if (!terminalUuid) {
      setMessages([]);
      setChannels([]);
      return;
    }

    try {
      const data = await jsonFetch(
        `/api/agents/messages?terminal_uuid=${encodeURIComponent(terminalUuid)}&limit=80`
      );
      setMessages(Array.isArray(data.messages) ? data.messages : []);
      setChannels(Array.isArray(data.channels) ? data.channels : []);
    } catch (err) {
      setError(err.message);
    }
  }, [terminalUuid]);

  useEffect(() => {
    loadAgents();
  }, [loadAgents]);

  useEffect(() => {
    loadMessages();
  }, [loadMessages]);

  useEffect(() => {
    if (!terminalUuid) {
      return undefined;
    }
    const timer = setInterval(() => {
      loadMessages();
      loadAgents();
    }, 2500);
    return () => clearInterval(timer);
  }, [loadAgents, loadMessages, terminalUuid]);

  const toggleAgent = (agentId) => {
    setSelectedAgentIds((previous) => {
      if (previous.includes(agentId)) {
        return previous.filter((id) => id !== agentId);
      }
      return [...previous, agentId];
    });
  };

  const handleAsk = async () => {
    if (!terminalUuid || !terminalId || asking) {
      return;
    }

    setAsking(true);
    setError('');
    try {
      await jsonFetch('/api/agents/ask', {
        method: 'POST',
        body: JSON.stringify({
          terminal_uuid: terminalUuid,
          terminal_id: terminalId,
          agent_ids: selectedAgentIds,
          scope,
          prompt
        })
      });
      setPrompt('');
      await loadMessages();
      await loadAgents();
    } catch (err) {
      setError(err.message);
    } finally {
      setAsking(false);
    }
  };

  const handleSendCommand = async (command) => {
    if (!terminalId || sendingCommand) {
      return;
    }

    setSendingCommand(command);
    setError('');
    try {
      await jsonFetch(`/api/terminals/${terminalId}/write`, {
        method: 'POST',
        body: JSON.stringify({ data: normalizeTerminalInput(command) })
      });
    } catch (err) {
      setError(err.message);
    } finally {
      setSendingCommand('');
    }
  };

  return (
    <aside className="agent-sidebar" aria-label="Copilot agents">
      <div className="agent-sidebar-header">
        <div>
          <h2>Agents</h2>
          <span>
            {terminalUuid
              ? `${selectedCount}/${enabledAgents.length} selected`
              : 'No terminal'}
          </span>
        </div>
        <button type="button" className="secondary" onClick={loadAgents} disabled={loadingAgents}>
          {loadingAgents ? '...' : 'Sync'}
        </button>
      </div>

      <div className="agent-list" role="list">
        {agents.map((agent) => (
          <label key={agent.id} className="agent-toggle">
            <input
              type="checkbox"
              checked={selectedAgentIds.includes(agent.id)}
              disabled={!agent.enabled}
              onChange={() => toggleAgent(agent.id)}
            />
            <span className="agent-toggle-body">
              <span className="agent-toggle-title">
                {agent.label}
                <span className={`agent-status agent-status-${agent.status || 'idle'}`}>
                  {agent.status || 'idle'}
                </span>
              </span>
              <span className="agent-toggle-meta">
                {agent.adapter}
                {agent.channel ? ` #${agent.channel}` : ''}
              </span>
            </span>
          </label>
        ))}
        {!agents.length && (
          <div className="agent-empty">No agents configured</div>
        )}
      </div>

      <div className="agent-ask">
        <div className="agent-ask-row">
          <label>
            <span>Context</span>
            <select value={scope} onChange={(event) => setScope(event.target.value)}>
              <option value="tail">Tail</option>
              <option value="history">History</option>
            </select>
          </label>
          <button
            type="button"
            onClick={handleAsk}
            disabled={!terminalUuid || !selectedCount || asking}
          >
            {asking ? 'Asking...' : 'Ask'}
          </button>
        </div>
        <textarea
          value={prompt}
          onChange={(event) => setPrompt(event.target.value)}
          placeholder="Ask for a read on the current terminal..."
          rows={3}
          disabled={!terminalUuid}
        />
      </div>

      {error && (
        <div className="agent-error" role="alert">
          {error}
        </div>
      )}

      <div className="agent-messages" aria-live="polite">
        {messages.map((message) => (
          <article
            key={message.id}
            className={`agent-message agent-message-${message.role || 'agent'} agent-message-${message.kind || 'message'}`}
          >
            <header>
              <strong>{message.agentLabel || message.agentId || 'Agent'}</strong>
              <span>{formatTime(message.timestamp)}</span>
            </header>
            <pre>{message.body}</pre>
            {Array.isArray(message.suggestions) && message.suggestions.length > 0 && (
              <div className="agent-suggestions">
                {message.suggestions.map((suggestion) => (
                  <button
                    key={suggestion}
                    type="button"
                    className="secondary"
                    onClick={() => handleSendCommand(suggestion)}
                    disabled={!terminalId || sendingCommand === suggestion}
                  >
                    {sendingCommand === suggestion ? 'Sending...' : 'Run'}
                    <code>{suggestion}</code>
                  </button>
                ))}
              </div>
            )}
          </article>
        ))}
        {!messages.length && (
          <div className="agent-empty">
            {terminalUuid ? 'No agent messages yet' : 'Select or create a terminal'}
          </div>
        )}
      </div>

      {channels.length > 0 && (
        <div className="agent-channel-list">
          {channels.map((channel) => `#${channel}`).join(' ')}
        </div>
      )}
    </aside>
  );
}
