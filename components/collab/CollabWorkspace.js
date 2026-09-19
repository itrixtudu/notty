import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import {
  ChevronDown,
  ChevronUp,
  MessageSquare,
  ExternalLink,
  Maximize2,
  Minimize2,
  RefreshCw,
  Square,
  ThumbsDown,
  ThumbsUp
} from 'lucide-react';
import TerminalConsole from '../TerminalConsole.js';
import TerminalPaneLayout from '../terminal/TerminalPaneLayout.js';
import { buildChatLayout } from './chatLayout.js';
import {
  CODEX_PERMISSION_MODES,
  collabChatsPath,
  formatAgentModel,
  nextCodexPermissionMode,
  normalizeAgentSpec,
  resolveTerminalId
} from './configModel.js';
import styles from '../../styles/Collab.module.css';

const EMPTY_AGENT_TERMINALS = Object.freeze({});

function healthCode(agent) {
  return agent.health?.code
    || agent.healthCode
    || agent.rateLimit?.code
    || agent.rateLimitCode
    || '';
}

function agentState(agent) {
  if (healthCode(agent) === 'rate-limited') return 'rateLimited';
  if (agent.error || ['error', 'failed'].includes(agent.status)) return 'error';
  if (['complete', 'completed', 'done'].includes(agent.status)) return 'complete';
  if (agent.registered || agent.tmuxAlive || ['running', 'active', 'starting'].includes(agent.status)) {
    return 'running';
  }
  return 'idle';
}

function sessionLayoutMode(session, layouts) {
  const snapshot = session.layoutSnapshot;
  if (snapshot && typeof snapshot === 'object' && snapshot.mode) {
    return snapshot.mode;
  }
  if (typeof snapshot === 'string' && ['grid', 'pair', 'lead-grid'].includes(snapshot)) {
    return snapshot;
  }
  const layoutId = typeof snapshot === 'string'
    ? snapshot
    : snapshot?.id || session.layout;
  return (layouts || []).find((layout) => layout.id === layoutId)?.mode;
}

function rowsFromStats(payload) {
  if (Array.isArray(payload)) return payload;
  if (Array.isArray(payload?.rows)) return payload.rows;
  if (Array.isArray(payload?.stats?.rows)) return payload.stats.rows;
  return [];
}

function messagesFromPayload(payload) {
  if (Array.isArray(payload)) return payload;
  if (Array.isArray(payload?.messages)) return payload.messages;
  if (Array.isArray(payload?.result?.messages)) return payload.result.messages;
  return [];
}

function helpfulText(row) {
  const rated = Number(row?.rated ?? ((row?.helpful || 0) + (row?.unhelpful || 0)));
  if (!rated) return '—';
  const value = row?.helpfulPercentage != null
    ? Number(row.helpfulPercentage)
    : Number(row?.helpfulRatio || 0) * 100;
  return `${Math.round(value)}%`;
}

function messageFeedback(message) {
  return message.feedback || {};
}

function viewerRating(message) {
  const feedback = messageFeedback(message);
  return feedback.viewerRating ?? feedback.operatorVote ?? message.viewerRating ?? null;
}

function messageBody(message) {
  return String(message.body ?? message.content ?? message.text ?? message.message ?? '');
}

function messageAuthor(message) {
  const snapshot = message.author_snapshot || message.authorSnapshot || {};
  return snapshot.role
    || snapshot.label
    || message.author
    || message.identity
    || message.agent
    || 'system';
}

function messageIdentity(message) {
  return String(
    message.session_agent_id
    || message.sessionAgentId
    || message.identity
    || message.agent_id
    || message.agent
    || ''
  );
}

function messageAgentSnapshot(message) {
  const snapshot = message.author_snapshot || message.authorSnapshot;
  return snapshot && snapshot.model ? normalizeAgentSpec(snapshot) : null;
}

function messageTimestamp(message) {
  const raw = message.createdAt || message.created_at || message.timestamp;
  if (!raw) return '';
  const date = new Date(raw);
  return Number.isNaN(date.getTime()) ? String(raw) : date.toLocaleTimeString([], {
    hour: '2-digit',
    minute: '2-digit'
  });
}

function canRateMessage(message) {
  if (message.author_type || message.authorType) {
    return (message.author_type || message.authorType) === 'agent';
  }
  return Boolean(message.author_snapshot || message.authorSnapshot || message.session_agent_id);
}

function metricForAgent(rows, agent) {
  return rows.find((row) => (
    row.sessionAgentId === agent.id
    || row.session_agent_id === agent.id
    || row.agentId === agent.id
    || row.sessionAgentIds?.includes(agent.id)
    || row.identity === agent.identity
  )) || null;
}

function AgentModel({ agent }) {
  const normalized = normalizeAgentSpec(agent);
  return (
    <span className={styles.agentModelCell} title={normalized.model || undefined}>
      <strong>{formatAgentModel(normalized)}</strong>
      {normalized.backend === 'ollama' && <small>via Ollama</small>}
    </span>
  );
}

export default function CollabWorkspace({
  chatsOnly = false,
  session,
  config,
  views,
  eventStatus,
  eventRevision,
  busy,
  attachError,
  onRefreshViews,
  onChangeLayout,
  onChangeAgentPermissionMode,
  onChangeAgentHealth,
  onRetryAgent,
  onLoadStats,
  onLoadMessages,
  onRateMessage,
  onStop
}) {
  const [focusedPane, setFocusedPane] = useState('channel');
  const [statsScope, setStatsScope] = useState('session');
  const [statsByScope, setStatsByScope] = useState({ session: [], lifetime: [] });
  const [statsLoadingByScope, setStatsLoadingByScope] = useState({
    session: false,
    lifetime: false
  });
  const [statsErrorByScope, setStatsErrorByScope] = useState({ session: '', lifetime: '' });
  const [activityOpen, setActivityOpen] = useState(false);
  const [messages, setMessages] = useState([]);
  const [messagesLoading, setMessagesLoading] = useState(false);
  const [messagesError, setMessagesError] = useState('');
  const [ratingMessageId, setRatingMessageId] = useState('');
  const [splitRatios, setSplitRatios] = useState({});
  const [rosterHidden, setRosterHidden] = useState(chatsOnly);
  const [chatColumns, setChatColumns] = useState(chatsOnly ? 2 : 0);
  const [chatHeight, setChatHeight] = useState(360);
  const [poppedOut, setPoppedOut] = useState(false);
  const [popoutError, setPopoutError] = useState('');
  const popoutRef = useRef(null);

  useEffect(() => {
    if (!poppedOut) return undefined;
    const timer = window.setInterval(() => {
      if (!popoutRef.current || popoutRef.current.closed) {
        popoutRef.current = null;
        setPoppedOut(false);
      }
    }, 500);
    return () => window.clearInterval(timer);
  }, [poppedOut]);

  const popOutChats = () => {
    if (popoutRef.current && !popoutRef.current.closed) {
      popoutRef.current.focus();
      return;
    }
    const url = new URL(collabChatsPath(session.id), window.location.origin);
    const popup = window.open(url.href, `collab-chats-${session.id}`, 'popup,width=1400,height=900');
    if (!popup) {
      setPopoutError('Pop-up blocked. Allow pop-ups for this site and try again.');
      return;
    }
    popoutRef.current = popup;
    setPopoutError('');
    setPoppedOut(true);
  };
  const [maximizedPane, setMaximizedPane] = useState(null);
  useEffect(() => {
    if (!maximizedPane) return undefined;
    const restore = (event) => {
      if (event.key === 'Escape' && !event.target.closest?.('[data-terminal-selection]')) {
        event.preventDefault();
        event.stopPropagation();
        setMaximizedPane(null);
      }
    };
    window.addEventListener('keydown', restore, true);
    return () => window.removeEventListener('keydown', restore, true);
  }, [maximizedPane]);
  const agentTerminals = views?.terminals?.agents || EMPTY_AGENT_TERMINALS;
  const channelTerminal = views?.terminals?.channel || null;
  const layoutMode = sessionLayoutMode(session, config.layouts);
  const snapshotLayout = session.layoutSnapshot && typeof session.layoutSnapshot === 'object'
    && session.layoutSnapshot.id === session.layout
    ? session.layoutSnapshot
    : null;
  const layoutOptions = snapshotLayout
    ? [snapshotLayout, ...(config.layouts || []).filter((layout) => layout.id !== snapshotLayout.id)]
    : config.layouts || [];
  const stats = statsByScope[statsScope] || [];
  const statsLoading = Boolean(statsLoadingByScope[statsScope]);
  const statsError = statsErrorByScope[statsScope] || '';

  const panes = useMemo(() => ([
    {
      id: 'channel',
      kind: 'channel',
      label: `#${session.channel || 'lobby'}`,
      subtitle: 'group IRC',
      terminal: channelTerminal
    },
    ...(session.agents || []).map((agent) => ({
      id: agent.id,
      kind: 'agent',
      label: agent.identity || agent.id,
      subtitle: `${agent.role || agent.prompt} · ${formatAgentModel(agent)}${agent.resumeStatus ? ` · Resume: ${agent.resumeStatus}` : ''}${agent.resumeError ? ` · ${agent.resumeError}` : ''}${
        normalizeAgentSpec(agent).backend === 'ollama' ? ' · via Ollama' : ''
      }`,
      terminal: agentTerminals[agent.id] || agentTerminals[agent.identity],
      agent
    }))
  ]), [session, channelTerminal, agentTerminals]);

  useEffect(() => {
    if (!panes.some((pane) => pane.id === focusedPane)) {
      setFocusedPane('channel');
    }
  }, [focusedPane, panes]);

  useEffect(() => {
    if (maximizedPane && !panes.some((pane) => pane.id === maximizedPane)) setMaximizedPane(null);
  }, [maximizedPane, panes]);

  const chatLayout = buildChatLayout(panes.map((pane) => pane.id), chatColumns, layoutMode, splitRatios);

  const loadStats = useCallback(async () => {
    if (!onLoadStats) return;
    const requestedScope = statsScope;
    setStatsLoadingByScope((current) => ({ ...current, [requestedScope]: true }));
    try {
      const payload = await onLoadStats(requestedScope);
      setStatsByScope((current) => ({
        ...current,
        [requestedScope]: rowsFromStats(payload)
      }));
      setStatsErrorByScope((current) => ({ ...current, [requestedScope]: '' }));
    } catch (error) {
      setStatsErrorByScope((current) => ({
        ...current,
        [requestedScope]: error.message
      }));
    } finally {
      setStatsLoadingByScope((current) => ({ ...current, [requestedScope]: false }));
    }
  }, [onLoadStats, statsScope]);

  useEffect(() => {
    setStatsByScope({ session: [], lifetime: [] });
    setStatsErrorByScope({ session: '', lifetime: '' });
  }, [session.id]);

  useEffect(() => {
    loadStats();
  }, [loadStats, eventRevision, session.id]);

  const loadMessages = useCallback(async () => {
    if (!onLoadMessages || !activityOpen) return;
    setMessagesLoading(true);
    try {
      const payload = await onLoadMessages();
      setMessages(messagesFromPayload(payload));
      setMessagesError('');
    } catch (error) {
      setMessagesError(error.message);
    } finally {
      setMessagesLoading(false);
    }
  }, [activityOpen, onLoadMessages]);

  useEffect(() => {
    loadMessages();
  }, [loadMessages, eventRevision, session.id]);

  const rateMessage = async (message, rating) => {
    const id = message.id || message.messageId || message.message_id;
    if (!id || !onRateMessage) return;
    const nextRating = viewerRating(message) === rating ? null : rating;
    setRatingMessageId(String(id));
    try {
      await onRateMessage(id, nextRating);
      await Promise.all([loadMessages(), loadStats()]);
      setMessagesError('');
    } catch (error) {
      setMessagesError(error.message);
    } finally {
      setRatingMessageId('');
    }
  };

  return (
    <div className={styles.workspace}>
      <header className={styles.workspaceToolbar}>
        <div className={styles.sessionIdentity}>
          <span className={`${styles.healthDot} ${styles[`health_${session.status || 'active'}`]}`} />
          <div>
            <strong>{session.templateId || 'Collab session'}</strong>
            <span>{session.status || 'active'} · #{session.channel || 'lobby'}</span>
          </div>
        </div>

        <div className={styles.toolbarControls}>
          <button type="button" onClick={() => setRosterHidden((hidden) => !hidden)}
            aria-expanded={!rosterHidden}>{rosterHidden ? 'Show roster' : 'Hide roster'}</button>
          <label className={styles.layoutPicker}>Columns
            <select value={chatColumns} onChange={(event) => { setChatColumns(Number(event.target.value)); setSplitRatios({}); }}>
              <option value={0}>Auto</option>
              {[1, 2, 3, 4].map((count) => <option key={count} value={count}>{count}</option>)}
            </select>
          </label>
          <label className={styles.layoutPicker}>Chat height
            <input aria-label="Chat row height" type="range" min="200" max="900" step="20"
              value={chatHeight} onChange={(event) => { setChatHeight(Number(event.target.value)); if (!chatColumns) setChatColumns(2); }} />
          </label>
          {!chatsOnly && <button type="button" onClick={popOutChats}>
            <ExternalLink size={14} aria-hidden="true" /> {poppedOut ? 'Focus chats' : 'Pop out chats'}
          </button>}
          {poppedOut && <button type="button" onClick={() => { popoutRef.current?.close(); setPoppedOut(false); }}>Dock chats</button>}
          <span className={`${styles.eventStatus} ${styles[`event_${eventStatus}`]}`}>
            {eventStatus === 'live' ? 'events live' : eventStatus}
          </span>
          <button
            type="button"
            className={`${styles.activityToggle}${activityOpen ? ` ${styles.activityToggleActive}` : ''}`}
            onClick={() => setActivityOpen((open) => !open)}
            aria-expanded={activityOpen}
          >
            <MessageSquare size={14} aria-hidden="true" />
            Activity
            {activityOpen ? <ChevronDown size={13} aria-hidden="true" /> : <ChevronUp size={13} aria-hidden="true" />}
          </button>
          <label className={styles.layoutPicker}>
            <span>Layout</span>
            <select
              value={session.layout || 'grid'}
              onChange={(event) => onChangeLayout(event.target.value)}
              disabled={busy}
            >
              {layoutOptions.map((layout) => (
                <option value={layout.id} key={layout.id}>{layout.label || layout.id}</option>
              ))}
            </select>
          </label>
          <button
            type="button"
            className={styles.toolbarIcon}
            onClick={onRefreshViews}
            disabled={busy}
            aria-label="Reconnect terminal viewers"
            title="Reconnect terminal viewers"
          >
            <RefreshCw size={15} aria-hidden="true" />
          </button>
          <button
            type="button"
            className={`${styles.toolbarIcon} ${styles.stopButton}`}
            onClick={onStop}
            disabled={busy}
            aria-label="Stop collaboration session"
            title="Stop collaboration session"
          >
            <Square size={13} fill="currentColor" aria-hidden="true" />
          </button>
        </div>
      </header>

      <section className={styles.rosterPanel} aria-label="Collaboration roster" hidden={rosterHidden}>
        <div className={styles.rosterToolbar}>
          <button
            type="button"
            className={focusedPane === 'channel' ? styles.channelFocusActive : ''}
            onClick={() => setFocusedPane('channel')}
            aria-pressed={focusedPane === 'channel'}
          >
            <span className={`${styles.agentDot} ${styles.state_running}`} />
            #{session.channel || 'lobby'}
          </button>
          <div className={styles.segmented} aria-label="Metrics scope">
            {['session', 'lifetime'].map((scope) => (
              <button
                type="button"
                className={statsScope === scope ? styles.segmentActive : ''}
                aria-pressed={statsScope === scope}
                onClick={() => setStatsScope(scope)}
                key={scope}
              >
                {scope === 'session' ? 'Session' : 'Lifetime'}
              </button>
            ))}
          </div>
          <button
            type="button"
            className={styles.rosterRefresh}
            onClick={loadStats}
            disabled={statsLoading}
          >
            <RefreshCw size={12} aria-hidden="true" />
            {statsLoading ? 'Loading…' : 'Refresh metrics'}
          </button>
        </div>

        <div className={styles.rosterTable}>
          <div className={styles.rosterHeader}>
            <span>Role</span>
            <span>Agent + Model</span>
            <span>Think</span>
            <span>Msgs</span>
            <span>Helpful</span>
            <span>Status</span>
            <span>Controls</span>
          </div>
          {statsScope === 'session' ? (session.agents || []).map((agent) => {
            const state = agentState(agent);
            const metric = metricForAgent(stats, agent);
            const normalized = normalizeAgentSpec(agent);
            const canRetry = !session.recovered
              && agent.tmuxAlive === false
              && !['starting'].includes(agent.status);
            const isCodex = normalized.harness === 'codex';
            const fullAccess = agent.permissionMode === CODEX_PERMISSION_MODES.BYPASS;
            const canChangePermissionMode = isCodex
              && !session.recovered
              && agent.tmuxAlive === true
              && agent.tmuxOwned === true
              && !['starting'].includes(agent.status);
            const rateLimited = healthCode(agent) === 'rate-limited';
            const manuallyCleared = agent.health?.source === 'operator'
              && agent.health?.cleared === true;
            return (
              <div
                className={`${styles.rosterRow}${focusedPane === agent.id ? ` ${styles.rosterRowActive}` : ''}`}
                key={agent.id}
              >
                <button type="button" onClick={() => setFocusedPane(agent.id)}>
                  <span className={`${styles.agentDot} ${styles[`state_${state}`]}`} />
                  <strong>{agent.role || agent.prompt}</strong>
                  <small>{agent.identity || agent.id}</small>
                </button>
                <button type="button" onClick={() => setFocusedPane(agent.id)}>
                  <AgentModel agent={agent} />
                </button>
                <span>{normalized.think || 'Default'}</span>
                <span>{metric ? metric.messages ?? 0 : '—'}</span>
                <span title={metric ? `${metric.helpful || 0} helpful / ${metric.rated || 0} rated` : ''}>
                  {helpfulText(metric)}
                </span>
                <span
                  className={rateLimited ? styles.rateLimitedStatus : ''}
                  title={agent.health?.message || undefined}
                >
                  {rateLimited ? 'rate limited' : agent.mcpStatus || agent.status || state}
                </span>
                <span className={styles.rosterControls}>
                  {canRetry && (
                    <button
                      type="button"
                      className={styles.retryAgent}
                      onClick={() => onRetryAgent(agent.id)}
                      disabled={busy}
                      aria-label={`Retry ${agent.identity || agent.id}`}
                      title="Retry agent"
                    >
                      <RefreshCw size={13} aria-hidden="true" />
                    </button>
                  )}
                  {onChangeAgentHealth && (
                    <button
                      type="button"
                      className={`${styles.healthOverride}${rateLimited ? ` ${styles.healthOverrideActive}` : ''}`}
                      onClick={() => onChangeAgentHealth(
                        agent.id,
                        rateLimited ? null : 'rate-limited'
                      )}
                      disabled={busy}
                      aria-label={`${rateLimited ? 'Clear' : 'Mark'} rate limited for ${agent.identity || agent.id}`}
                      title={rateLimited
                        ? 'Clear the rate-limit status for this session'
                        : manuallyCleared
                          ? 'Rate-limit status is manually clear for this session; mark it limited'
                          : 'Mark rate limited for this session'}
                    >
                      {rateLimited ? 'CLEAR' : 'LIMIT'}
                    </button>
                  )}
                  {isCodex && (
                    <button
                      type="button"
                      role="switch"
                      aria-checked={fullAccess}
                      className={`${styles.permissionSwitch}${fullAccess ? ` ${styles.permissionSwitchFull}` : ''}`}
                      onClick={() => onChangeAgentPermissionMode(
                        agent.id,
                        nextCodexPermissionMode(agent.permissionMode)
                      )}
                      disabled={busy || !canChangePermissionMode}
                      aria-label={`${fullAccess ? 'Disable' : 'Enable'} full access for ${
                        agent.identity || agent.id
                      } and relaunch the agent`}
                      title={fullAccess
                        ? 'Full access; relaunch with workspace sandbox'
                        : 'Workspace sandbox; relaunch with full access'}
                    >
                      {fullAccess ? 'FULL' : 'SAFE'}
                    </button>
                  )}
                </span>
              </div>
            );
          }) : stats.map((row) => (
            <div className={`${styles.rosterRow} ${styles.lifetimeRow}`} key={row.key || [
              row.role,
              row.harness || row.agent,
              row.backend || row.runtime,
              row.model,
              row.think
            ].join(':')}>
              <span><strong>{row.role || 'unknown'}</strong></span>
              <AgentModel agent={{
                harness: row.harness || row.agent,
                ...(row.backend ? { backend: row.backend } : { runtime: row.runtime }),
                model: row.model,
                think: row.think
              }} />
              <span>{row.think || 'Default'}</span>
              <span>{row.messages || 0}</span>
              <span title={`${row.helpful || 0} helpful / ${row.rated || 0} rated`}>
                {helpfulText(row)}
              </span>
              <span>lifetime</span>
              <span />
            </div>
          ))}
          {statsScope === 'lifetime' && !stats.length && !statsLoading && (
            <div className={styles.rosterEmpty}>No attributed lifetime messages yet.</div>
          )}
        </div>
        {statsError && <div className={styles.compactError} role="alert">{statsError}</div>}
      </section>

      {attachError && (
        <div className={styles.attachError} role="alert">
          <span>{attachError}</span>
          <button type="button" onClick={onRefreshViews}>Retry</button>
        </div>
      )}

      {Array.isArray(session.warnings) && session.warnings.length > 0 && (
        <div className={styles.sessionWarnings} role="status">
          {session.warnings.map((warning) => <span key={warning}>{warning}</span>)}
        </div>
      )}

      {popoutError && <div role="alert" className={styles.inlineNotice}>{popoutError}</div>}
      {poppedOut && <div className={styles.emptyState}>Chats are open in a separate window. Close it or choose Dock chats to return them here.</div>}
      {!poppedOut && <section
        className={styles.chatSplitLayout}
        style={{ minHeight: Math.min(900, chatHeight) }}
        data-count={panes.length}
        aria-label="Collaboration terminals"
      >
        {chatLayout && <TerminalPaneLayout layout={chatLayout} activePaneId={focusedPane}
          onActivatePane={setFocusedPane}
          onResizeSplit={(id, ratios) => setSplitRatios((current) => ({ ...current, [id]: ratios }))}
          renderPane={(leaf) => {
          const pane = panes.find((entry) => entry.id === leaf.id);
          const terminalId = resolveTerminalId(pane.terminal);
          return (
            <div
              className={`${styles.terminalTile}${focusedPane === pane.id ? ` ${styles.focusedTile}` : ''}${maximizedPane === pane.id ? ` ${styles.maximizedTile}` : ''}`}
              data-kind={pane.kind}
              inert={maximizedPane && maximizedPane !== pane.id ? true : undefined}
              key={pane.id}
              onPointerDown={() => setFocusedPane(pane.id)}
            >
              {terminalId ? (
                <TerminalConsole
                  sessionId={terminalId}
                  title={pane.label}
                  subtitle={pane.subtitle}
                  compact
                  autoFocus={false}
                  updateDocumentTitle={false}
                  copyControls
                  transcriptControl={pane.agent && normalizeAgentSpec(pane.agent).harness === 'codex'}
                  headerActions={
                    <button type="button" className="terminal-reconnect" aria-label={`${maximizedPane === pane.id ? 'Restore' : 'Maximize'} ${pane.label}`}
                      title={maximizedPane === pane.id ? 'Restore pane (Escape)' : 'Maximize pane'}
                      aria-pressed={maximizedPane === pane.id}
                      onClick={() => setMaximizedPane((current) => current === pane.id ? null : pane.id)}>
                      {maximizedPane === pane.id ? <Minimize2 size={14} aria-hidden="true" /> : <Maximize2 size={14} aria-hidden="true" />}
                    </button>
                  }
                />
              ) : (
                <div className={styles.pendingTerminal}>
                  <div>
                    <strong>{pane.label}</strong>
                    <span>{pane.agent?.error || 'Viewer pending'}</span>
                  </div>
                </div>
              )}
            </div>
          );
        }} />}
      </section>}

      {activityOpen && (
        <aside className={styles.activityDrawer} aria-label="Session activity">
          <header>
            <div>
              <strong>Activity</strong>
              <span>#{session.channel || 'lobby'} · {messages.length} recent</span>
            </div>
            <button type="button" onClick={loadMessages} disabled={messagesLoading}>
              <RefreshCw size={12} aria-hidden="true" />
              {messagesLoading ? 'Loading…' : 'Refresh'}
            </button>
          </header>
          {messagesError && <div className={styles.compactError} role="alert">{messagesError}</div>}
          <div className={styles.activityList}>
            {messages.map((message, index) => {
              const id = String(message.id || message.messageId || message.message_id || index);
              const feedback = messageFeedback(message);
              const rating = viewerRating(message);
              const rateable = canRateMessage(message);
              const identity = messageIdentity(message);
              const agentSnapshot = messageAgentSnapshot(message);
              return (
                <article className={styles.activityMessage} key={id}>
                  <div className={styles.messageMeta}>
                    <strong>{messageAuthor(message)}</strong>
                    {identity && <span>{identity}</span>}
                    {agentSnapshot && (
                      <span>
                        {formatAgentModel(agentSnapshot)}
                        {agentSnapshot.backend === 'ollama' ? ' · via Ollama' : ''}
                      </span>
                    )}
                    <span>{messageTimestamp(message)}</span>
                  </div>
                  <p>{messageBody(message)}</p>
                  {rateable && (
                    <div className={styles.feedbackControls}>
                      <button
                        type="button"
                        className={rating === 'helpful' ? styles.ratingActiveHelpful : ''}
                        aria-pressed={rating === 'helpful'}
                        aria-label={`Mark message from ${messageAuthor(message)} helpful`}
                        onClick={() => rateMessage(message, 'helpful')}
                        disabled={ratingMessageId === id}
                      >
                        <ThumbsUp size={12} aria-hidden="true" />
                        {feedback.helpful || 0}
                      </button>
                      <button
                        type="button"
                        className={rating === 'unhelpful' ? styles.ratingActiveUnhelpful : ''}
                        aria-pressed={rating === 'unhelpful'}
                        aria-label={`Mark message from ${messageAuthor(message)} unhelpful`}
                        onClick={() => rateMessage(message, 'unhelpful')}
                        disabled={ratingMessageId === id}
                      >
                        <ThumbsDown size={12} aria-hidden="true" />
                        {feedback.unhelpful || 0}
                      </button>
                    </div>
                  )}
                </article>
              );
            })}
            {!messages.length && !messagesLoading && (
              <div className={styles.activityEmpty}>No channel messages yet.</div>
            )}
          </div>
        </aside>
      )}
    </div>
  );
}
