import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import {
  Activity,
  Bot,
  ChevronDown,
  ChevronUp,
  ExternalLink,
  PanelRightClose,
  PanelRightOpen,
  Play,
  RefreshCw,
  RotateCcw,
  Send,
  ShieldAlert,
  Square,
  X
} from 'lucide-react';
import TerminalConsole from './TerminalConsole.js';
import { deriveCopilotPaneViewState } from './copilotPaneModel.js';
import { browserFetch, resolveBrowserUrl } from '../lib/browserRequest.js';

const SELECTION_LIMIT = 20_000;
const MODEL_STORAGE_KEY = 'notty.copilot.models';
const POLL_INTERVAL_MS = 15_000;
const COPILOT_SSE_EVENT_TYPES = [
  'copilot',
  'copilot.created',
  'copilot.updated',
  'copilot.stopped',
  'copilot.question',
  'copilot.lease-renewed',
  'copilot.feedback',
  'copilot.proposal',
  'copilot.proposal-approved'
];

const DEFAULT_RUNTIMES = [
  {
    id: 'ollama',
    label: 'Ollama',
    defaultModel: 'qwen3:4b',
    available: true
  },
  {
    id: 'codex',
    label: 'Codex',
    defaultModel: 'gpt-5.3-codex-spark',
    available: true
  },
  {
    id: 'agy',
    label: 'Agy',
    defaultModel: 'gemini-3.6-flash-medium',
    available: true
  }
];

const OBSERVATION_MODES = [
  { value: 'passive', label: 'Passive' },
  { value: 'active', label: 'Active' }
];

const CONTROL_MODES = [
  { value: 'off', label: 'Off' },
  { value: 'insert', label: 'Insert' },
  { value: 'approve', label: 'Approve' },
  { value: 'autonomous', label: 'Autonomous' }
];

const TIP_INTERVALS = [
  { value: 0, label: 'Off' },
  { value: 15, label: '15 sec' },
  { value: 30, label: '30 sec' },
  { value: 60, label: '60 sec' },
  { value: 300, label: '5 min' }
];

async function jsonFetch(url, options = {}) {
  const response = await browserFetch(url, {
    headers: { 'Content-Type': 'application/json' },
    ...options
  });
  const text = await response.text();
  let payload = null;
  if (text) {
    try {
      payload = JSON.parse(text);
    } catch {
      payload = null;
    }
  }
  if (!response.ok) {
    const structuredError = payload?.error && typeof payload.error === 'object'
      ? payload.error
      : null;
    const message = typeof payload?.error === 'string'
      ? payload.error
      : structuredError?.message
        || payload?.message
        || (text && !payload ? text : '')
        || response.statusText
        || `Request failed with HTTP ${response.status}`;
    const error = new Error(message);
    error.code = payload?.code || structuredError?.code || '';
    error.status = response.status;
    throw error;
  }
  return payload;
}

function errorDetails(error) {
  if (!error) {
    return null;
  }
  if (typeof error === 'string') {
    return { message: error, code: '', status: null };
  }
  return {
    message: error.message || 'Unknown copilot error',
    code: typeof error.code === 'string' ? error.code : '',
    status: Number.isInteger(error.status) ? error.status : null
  };
}

function readRememberedModels() {
  if (typeof window === 'undefined') {
    return {};
  }
  try {
    const parsed = JSON.parse(window.localStorage.getItem(MODEL_STORAGE_KEY) || '{}');
    return parsed && typeof parsed === 'object' && !Array.isArray(parsed) ? parsed : {};
  } catch {
    return {};
  }
}

function rememberModel(runtime, model) {
  if (typeof window === 'undefined' || !runtime || !String(model || '').trim()) {
    return;
  }
  try {
    const models = readRememberedModels();
    models[runtime] = String(model).trim();
    window.localStorage.setItem(MODEL_STORAGE_KEY, JSON.stringify(models));
  } catch {
    // Local storage is optional in restricted browser contexts.
  }
}

function mergeRuntimeCatalog(catalog) {
  const supplied = Array.isArray(catalog?.runtimes) ? catalog.runtimes : [];
  const suppliedById = new Map(supplied.map((entry) => [entry.id, entry]));
  const defaults = DEFAULT_RUNTIMES.map((entry) => ({
    ...entry,
    ...(suppliedById.get(entry.id) || {})
  }));
  const extra = supplied.filter((entry) => (
    entry?.id && !DEFAULT_RUNTIMES.some((candidate) => candidate.id === entry.id)
  ));
  return [...defaults, ...extra];
}

function getViewerTerminalId(binding) {
  return binding?.viewerTerminal?.id
    ?? binding?.viewer_terminal?.id
    ?? binding?.viewerTerminalId
    ?? binding?.agentTerminal?.id
    ?? null;
}

function normalizeFeed(binding) {
  const source = binding?.feedback || binding?.analysis || binding?.messages || [];
  return Array.isArray(source) ? source : [];
}

function normalizeProposals(binding) {
  return Array.isArray(binding?.proposals) ? binding.proposals : [];
}

function normalizeLeases(binding) {
  const asLease = (rawTarget, lease, fallbackLabel = rawTarget) => {
    const target = String(rawTarget || 'visible').trim().toLowerCase();
    return {
      ...lease,
      key: lease.id || `${target}-lease`,
      target,
      label: lease.label || fallbackLabel
    };
  };
  const normalized = [];
  const leases = binding?.leases;
  if (Array.isArray(leases)) {
    normalized.push(...leases
      .filter((lease) => lease && typeof lease === 'object')
      .map((lease, index) => {
        const target = lease.target
          || lease.purpose
          || lease.role
          || lease.kind
          || (index === 0 ? 'visible' : 'analyzer');
        return asLease(target, lease, target);
      }));
  } else if (leases && typeof leases === 'object') {
    normalized.push(...Object.entries(leases)
      .filter(([, lease]) => lease && typeof lease === 'object')
      .map(([target, lease]) => asLease(target, lease, target)));
  } else if (binding?.lease && typeof binding.lease === 'object') {
    normalized.push(asLease('visible', binding.lease));
  }
  if (
    !normalized.some((lease) => lease.target === 'visible')
    && binding?.visibleLease
    && typeof binding.visibleLease === 'object'
  ) {
    normalized.push(asLease('visible', binding.visibleLease));
  }
  const analyzerLease = binding?.analyzerLease || binding?.analyzer?.lease;
  if (
    !normalized.some((lease) => lease.target === 'analyzer')
    && analyzerLease
    && typeof analyzerLease === 'object'
  ) {
    normalized.push(asLease('analyzer', analyzerLease));
  }
  return normalized;
}

function formatCountdown(lease, now) {
  if (lease?.status === 'revoked') {
    return 'revoked';
  }
  if (lease?.status === 'expired') {
    return 'expired';
  }
  const expiresAt = lease?.expiresAt || lease?.expires_at;
  if (!expiresAt) {
    return lease?.status || 'pending';
  }
  const remainingMs = new Date(expiresAt).getTime() - now;
  if (!Number.isFinite(remainingMs) || remainingMs <= 0) {
    return 'expired';
  }
  const totalSeconds = Math.ceil(remainingMs / 1000);
  const hours = Math.floor(totalSeconds / 3600);
  const minutes = Math.floor((totalSeconds % 3600) / 60);
  const seconds = totalSeconds % 60;
  if (hours) {
    return `${hours}h ${String(minutes).padStart(2, '0')}m`;
  }
  return `${minutes}:${String(seconds).padStart(2, '0')}`;
}

function formatTime(value) {
  if (!value) {
    return '';
  }
  const date = new Date(value);
  return Number.isNaN(date.getTime())
    ? ''
    : date.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
}

function feedbackBody(item) {
  if (typeof item === 'string') {
    return item;
  }
  return item?.body || item?.message || item?.text || item?.summary || item?.question || '';
}

function proposalCommand(proposal) {
  return proposal?.command || proposal?.data || proposal?.text || '';
}

export default function CopilotPane({
  session,
  selectedText = '',
  onClearSelection,
  onCollapse,
  onPopOut,
  onDock,
  popoutOpening = false,
  focusToken = 0,
  compact = false
}) {
  const [copilots, setCopilots] = useState([]);
  const [catalog, setCatalog] = useState({});
  const [loading, setLoading] = useState(true);
  const [busyAction, setBusyAction] = useState('');
  const [error, setError] = useState(null);
  const [runtime, setRuntime] = useState('ollama');
  const [model, setModel] = useState('qwen3:4b');
  const [observationMode, setObservationMode] = useState('passive');
  const [controlMode, setControlMode] = useState('off');
  const [tipIntervalSeconds, setTipIntervalSeconds] = useState(30);
  const [question, setQuestion] = useState('');
  const [expandedConfigurationBindingId, setExpandedConfigurationBindingId] = useState('');
  const [now, setNow] = useState(() => Date.now());
  const mountedRef = useRef(true);
  const paneRef = useRef(null);
  const loadRequestRef = useRef(0);
  const configurationToggleRef = useRef(null);
  const launchButtonRef = useRef(null);
  const focusConfigurationToggleRef = useRef(false);
  const focusLaunchButtonRef = useRef(false);

  useEffect(() => {
    if (!focusToken || typeof window === 'undefined') {
      return undefined;
    }
    const frame = window.requestAnimationFrame(() => paneRef.current?.focus());
    return () => window.cancelAnimationFrame(frame);
  }, [focusToken]);

  const runtimeOptions = useMemo(() => mergeRuntimeCatalog(catalog), [catalog]);
  const {
    sourceTerminalUuid,
    binding,
    configurationVisible,
    agentTerminalExpanded
  } = useMemo(() => deriveCopilotPaneViewState({
    session,
    copilots,
    expandedConfigurationBindingId
  }), [session, copilots, expandedConfigurationBindingId]);
  const activeBindingIdRef = useRef(null);
  activeBindingIdRef.current = binding?.id || null;

  const replaceCopilot = useCallback((nextBinding) => {
    if (!nextBinding?.id) {
      return;
    }
    // A direct mutation/SSE snapshot is newer than any list request already in flight.
    loadRequestRef.current += 1;
    setLoading(false);
    setCopilots((current) => [
      ...current.filter((candidate) => candidate.id !== nextBinding.id),
      nextBinding
    ]);
  }, []);

  const loadCopilots = useCallback(async ({ quiet = false } = {}) => {
    const requestId = loadRequestRef.current + 1;
    loadRequestRef.current = requestId;
    if (!quiet) {
      setLoading(true);
    }
    try {
      const data = await jsonFetch('/api/copilots');
      if (!mountedRef.current || requestId !== loadRequestRef.current) {
        return;
      }
      setCopilots(Array.isArray(data?.copilots) ? data.copilots : []);
      setCatalog(data?.catalog && typeof data.catalog === 'object' ? data.catalog : {});
      if (!quiet) {
        setError(null);
      }
    } catch (err) {
      if (mountedRef.current && requestId === loadRequestRef.current) {
        setError(err);
      }
    } finally {
      if (mountedRef.current && requestId === loadRequestRef.current) {
        setLoading(false);
      }
    }
  }, []);

  useEffect(() => {
    mountedRef.current = true;
    loadCopilots();
    const poll = window.setInterval(() => loadCopilots({ quiet: true }), POLL_INTERVAL_MS);
    return () => {
      mountedRef.current = false;
      window.clearInterval(poll);
    };
  }, [loadCopilots]);

  useEffect(() => {
    if (typeof window === 'undefined' || typeof EventSource === 'undefined') {
      return undefined;
    }
    const events = new EventSource(resolveBrowserUrl('/api/copilots/events'));
    const handleEvent = (event) => {
      try {
        const payload = JSON.parse(event.data);
        if (payload?.copilot) {
          replaceCopilot(payload.copilot);
        } else if (payload?.binding) {
          replaceCopilot(payload.binding);
        } else if (payload?.type !== 'heartbeat') {
          loadCopilots({ quiet: true });
        }
      } catch {
        loadCopilots({ quiet: true });
      }
    };
    events.onmessage = handleEvent;
    COPILOT_SSE_EVENT_TYPES.forEach((eventName) => {
      events.addEventListener(eventName, handleEvent);
    });
    return () => {
      events.close();
    };
  }, [loadCopilots, replaceCopilot]);

  useEffect(() => {
    const timer = window.setInterval(() => setNow(Date.now()), 1_000);
    return () => window.clearInterval(timer);
  }, []);

  const catalogSignature = runtimeOptions.map((entry) => (
    `${entry.id}:${entry.available !== false}:${entry.defaultModel || ''}:${(
      Array.isArray(entry.models) ? entry.models : []
    ).join(',')}`
  )).join('|');

  useEffect(() => {
    setQuestion('');
    setError(null);
    if (binding) {
      setRuntime(binding.runtime || 'ollama');
      setModel(binding.model || runtimeOptions.find((entry) => entry.id === binding.runtime)?.defaultModel || '');
    }
  }, [sourceTerminalUuid, binding?.id]);

  useEffect(() => {
    if (binding && focusConfigurationToggleRef.current) {
      focusConfigurationToggleRef.current = false;
      configurationToggleRef.current?.focus();
    } else if (!binding && focusLaunchButtonRef.current) {
      focusLaunchButtonRef.current = false;
      launchButtonRef.current?.focus();
    }
  }, [binding?.id]);

  useEffect(() => {
    if (!binding) {
      return;
    }
    setObservationMode(binding.observationMode || 'passive');
    setControlMode(binding.controlMode || 'off');
    setTipIntervalSeconds(Number(binding.tipIntervalSeconds ?? 30));
  }, [binding?.id, binding?.updatedAt]);

  useEffect(() => {
    if (binding || !sourceTerminalUuid) {
      return;
    }
    const defaultRuntime = runtimeOptions.find((entry) => (
      entry.id === catalog?.defaults?.runtime && entry.available !== false
    ));
    const availableOllama = runtimeOptions.find((entry) => (
      entry.id === 'ollama' && entry.available !== false
    ));
    const nextRuntime = defaultRuntime
      || availableOllama
      || runtimeOptions.find((entry) => entry.available !== false)
      || runtimeOptions[0];
    const remembered = readRememberedModels();
    setRuntime(nextRuntime?.id || 'ollama');
    setModel(remembered[nextRuntime?.id] || nextRuntime?.defaultModel || '');
    setObservationMode(catalog?.defaults?.observationMode || 'passive');
    setControlMode(catalog?.defaults?.controlMode || 'off');
    setTipIntervalSeconds(Number(catalog?.defaults?.tipIntervalSeconds ?? 30));
  }, [
    sourceTerminalUuid,
    binding?.id,
    catalogSignature,
    catalog?.defaults?.runtime,
    catalog?.defaults?.observationMode,
    catalog?.defaults?.controlMode,
    catalog?.defaults?.tipIntervalSeconds
  ]);

  const selectedRuntime = runtimeOptions.find((entry) => entry.id === runtime) || null;
  const modelOptions = Array.isArray(selectedRuntime?.models)
    ? selectedRuntime.models.filter((entry) => typeof entry === 'string' && entry.trim())
    : [];
  const selectedModelIsAvailable = modelOptions.includes(model);
  const runtimeChanged = Boolean(binding && (
    runtime !== binding.runtime || String(model).trim() !== String(binding.model || '').trim()
  ));
  const selectionLength = selectedText.length;
  const selectionTooLarge = selectionLength > SELECTION_LIMIT;
  const viewerTerminalId = getViewerTerminalId(binding);
  const feedback = normalizeFeed(binding);
  const pendingProposals = normalizeProposals(binding).filter((proposal) => (
    !proposal.status || proposal.status === 'pending'
  ));
  const leases = normalizeLeases(binding);
  const renderedError = errorDetails(error);
  const latestProposal = pendingProposals.at(-1) || null;
  const latestFeedback = feedback.at(-1) || null;
  const latestProposalAt = Date.parse(latestProposal?.createdAt || latestProposal?.timestamp || '') || 0;
  const latestFeedbackAt = Date.parse(latestFeedback?.createdAt || latestFeedback?.timestamp || '') || 0;
  const liveAnnouncement = latestProposal && latestProposalAt > latestFeedbackAt
    ? `Command proposal: ${proposalCommand(latestProposal)}`
    : latestFeedback
        ? feedbackBody(latestFeedback)
        : latestProposal
            ? `Command proposal: ${proposalCommand(latestProposal)}`
            : '';

  const autonomousConfirmation = useCallback(() => {
    if (typeof window === 'undefined') {
      return false;
    }
    return window.confirm(
      'Autonomous control lets this agent type commands and press Enter in this terminal until its lease expires. Continue?'
    );
  }, []);

  const buildCreatePayload = useCallback((autonomousConfirmed = false) => ({
    sourceTerminalUuid,
    runtime,
    model: String(model).trim(),
    observationMode,
    controlMode,
    tipIntervalSeconds: Number(tipIntervalSeconds),
    autonomousConfirmed
  }), [
    sourceTerminalUuid,
    runtime,
    model,
    observationMode,
    controlMode,
    tipIntervalSeconds
  ]);

  const launchCopilot = async () => {
    if (!sourceTerminalUuid || busyAction || !String(model).trim()) {
      return;
    }
    const autonomousConfirmed = controlMode === 'autonomous'
      ? autonomousConfirmation()
      : false;
    if (controlMode === 'autonomous' && !autonomousConfirmed) {
      return;
    }

    setBusyAction('launch');
    setError(null);
    try {
      const data = await jsonFetch('/api/copilots', {
        method: 'POST',
        body: JSON.stringify(buildCreatePayload(autonomousConfirmed))
      });
      rememberModel(runtime, model);
      focusConfigurationToggleRef.current = true;
      replaceCopilot(data?.copilot);
      await loadCopilots({ quiet: true });
    } catch (err) {
      setError(err);
    } finally {
      setBusyAction('');
    }
  };

  const relaunchCopilot = async () => {
    if (!binding || busyAction || typeof window === 'undefined') {
      return;
    }
    if (!window.confirm('Relaunch this copilot with the selected runtime and model? Its current agent terminal will close.')) {
      return;
    }
    const autonomousConfirmed = controlMode === 'autonomous'
      ? autonomousConfirmation()
      : false;
    if (controlMode === 'autonomous' && !autonomousConfirmed) {
      return;
    }
    setBusyAction('relaunch');
    setError(null);
    try {
      await jsonFetch(`/api/copilots/${encodeURIComponent(binding.id)}`, { method: 'DELETE' });
      const data = await jsonFetch('/api/copilots', {
        method: 'POST',
        body: JSON.stringify(buildCreatePayload(autonomousConfirmed))
      });
      rememberModel(runtime, model);
      focusConfigurationToggleRef.current = true;
      replaceCopilot(data?.copilot);
      await loadCopilots({ quiet: true });
    } catch (err) {
      setError(err);
      await loadCopilots({ quiet: true });
    } finally {
      setBusyAction('');
    }
  };

  const stopCopilot = async () => {
    if (!binding || busyAction) {
      return;
    }
    setBusyAction('stop');
    setError(null);
    try {
      await jsonFetch(`/api/copilots/${encodeURIComponent(binding.id)}`, { method: 'DELETE' });
      focusLaunchButtonRef.current = true;
      setCopilots((current) => current.filter((candidate) => candidate.id !== binding.id));
    } catch (err) {
      setError(err);
    } finally {
      setBusyAction('');
    }
  };

  const patchSetting = async (field, value, setter, previousValue, options = {}) => {
    if (!binding || busyAction) {
      setter(value);
      return;
    }
    let autonomousConfirmed = false;
    if (field === 'controlMode' && value === 'autonomous') {
      autonomousConfirmed = autonomousConfirmation();
      if (!autonomousConfirmed) {
        return;
      }
    }
    const originBindingId = binding.id;
    setter(value);
    setBusyAction(`patch-${field}`);
    setError(null);
    try {
      const data = await jsonFetch(`/api/copilots/${encodeURIComponent(binding.id)}`, {
        method: 'PATCH',
        body: JSON.stringify({
          [field]: options.number ? Number(value) : value,
          autonomousConfirmed
        })
      });
      replaceCopilot(data?.copilot);
    } catch (err) {
      if (activeBindingIdRef.current === originBindingId) {
        setter(previousValue);
        setError(err);
      }
    } finally {
      setBusyAction('');
    }
  };

  const askCopilot = async () => {
    const cleanQuestion = question.trim();
    if (!binding || !cleanQuestion || selectionTooLarge || busyAction) {
      return;
    }
    setBusyAction('ask');
    setError(null);
    try {
      const data = await jsonFetch(`/api/copilots/${encodeURIComponent(binding.id)}/ask`, {
        method: 'POST',
        body: JSON.stringify({
          question: cleanQuestion,
          selectedText: selectedText || undefined
        })
      });
      setQuestion('');
      replaceCopilot(data?.copilot);
    } catch (err) {
      setError(err);
    } finally {
      setBusyAction('');
    }
  };

  const renewLease = async (lease) => {
    if (!binding || busyAction) {
      return;
    }
    const target = lease?.target || lease?.purpose || lease?.role || lease?.kind || 'visible';
    const autonomousConfirmed = target === 'visible' && controlMode === 'autonomous'
      ? autonomousConfirmation()
      : false;
    if (target === 'visible' && controlMode === 'autonomous' && !autonomousConfirmed) {
      return;
    }
    setBusyAction(`renew-${target}`);
    setError(null);
    try {
      const data = await jsonFetch(`/api/copilots/${encodeURIComponent(binding.id)}/renew`, {
        method: 'POST',
        body: JSON.stringify({ target, autonomousConfirmed })
      });
      replaceCopilot(data?.copilot);
    } catch (err) {
      setError(err);
    } finally {
      setBusyAction('');
    }
  };

  const approveProposal = async (proposal) => {
    if (!binding || !proposal?.id || busyAction) {
      return;
    }
    setBusyAction(`proposal-${proposal.id}`);
    setError(null);
    try {
      const data = await jsonFetch(
        `/api/copilots/${encodeURIComponent(binding.id)}/proposals/${encodeURIComponent(proposal.id)}/approve`,
        { method: 'POST', body: '{}' }
      );
      replaceCopilot(data?.copilot);
    } catch (err) {
      setError(err);
    } finally {
      setBusyAction('');
    }
  };

  const handleRuntimeChange = (nextRuntime) => {
    rememberModel(runtime, model);
    const next = runtimeOptions.find((entry) => entry.id === nextRuntime);
    const remembered = readRememberedModels();
    setRuntime(nextRuntime);
    setModel(remembered[nextRuntime] || next?.defaultModel || '');
  };

  if (compact) {
    return <aside id="terminal-copilot-pane" ref={paneRef} hidden />;
  }

  return (
    <aside
      id="terminal-copilot-pane"
      ref={paneRef}
      className="agent-sidebar copilot-pane"
      aria-label="Terminal copilot"
      tabIndex={-1}
    >
      <div className="agent-sidebar-header copilot-header">
        <div>
          <h2><Bot size={15} aria-hidden="true" /> Copilot</h2>
          <span>
            {session
              ? binding
                ? `${binding.runtime} · ${binding.status || 'running'} · terminal #${session.id}`
                : `Ready for terminal #${session.id}`
              : 'Select a terminal'}
          </span>
        </div>
        <div className="copilot-header-actions">
          <button
            type="button"
            className="secondary copilot-icon-button"
            onClick={() => loadCopilots()}
            disabled={loading || Boolean(busyAction)}
            aria-label="Refresh copilots"
            title="Refresh copilots"
          >
            <RefreshCw size={13} aria-hidden="true" />
          </button>
          {onPopOut && (
            <button
              type="button"
              className="secondary copilot-icon-button"
              onClick={onPopOut}
              disabled={!session || popoutOpening}
              aria-label={popoutOpening ? 'Opening Copilot window' : 'Pop out Copilot pane'}
              title={popoutOpening ? 'Opening Copilot window…' : 'Pop out to a separate window'}
            >
              <ExternalLink size={13} aria-hidden="true" />
            </button>
          )}
          {onDock && (
            <button
              type="button"
              className="secondary copilot-icon-button"
              onClick={onDock}
              aria-label="Dock Copilot pane in terminal window"
              title="Dock Copilot pane"
            >
              <PanelRightOpen size={13} aria-hidden="true" />
            </button>
          )}
          {onCollapse && (
            <button
              type="button"
              className="secondary copilot-icon-button"
              onClick={onCollapse}
              aria-controls="terminal-copilot-pane"
              aria-expanded={true}
              aria-label="Collapse Copilot pane to the right"
              title="Collapse Copilot pane"
            >
              <PanelRightClose size={13} aria-hidden="true" />
            </button>
          )}
          {binding && (
            <button
              ref={configurationToggleRef}
              type="button"
              className="secondary copilot-icon-button"
              onClick={() => setExpandedConfigurationBindingId(
                configurationVisible ? '' : binding.id
              )}
              disabled={Boolean(busyAction)}
              aria-controls="copilot-configuration"
              aria-expanded={configurationVisible}
              aria-label={configurationVisible
                ? 'Collapse copilot configuration'
                : 'Expand copilot configuration'}
              title={configurationVisible
                ? 'Collapse copilot configuration'
                : 'Expand copilot configuration'}
            >
              {configurationVisible
                ? <ChevronUp size={13} aria-hidden="true" />
                : <ChevronDown size={13} aria-hidden="true" />}
            </button>
          )}
          {binding && (
            <button
              type="button"
              className="secondary copilot-icon-button copilot-stop-button"
              onClick={stopCopilot}
              disabled={Boolean(busyAction)}
              aria-label="Stop this copilot"
              title="Stop copilot (source terminal stays open)"
            >
              <Square size={12} aria-hidden="true" />
            </button>
          )}
        </div>
      </div>

      <div className={`copilot-scroll-region${agentTerminalExpanded
        ? ' copilot-scroll-region-agent-expanded'
        : ''}`}>
        {!session && (
          <div className="agent-empty copilot-empty">
            Select or create a terminal, then launch its copilot.
          </div>
        )}

        {session && (
          <section
            id="copilot-configuration"
            className="copilot-controls"
            aria-label="Copilot configuration"
            hidden={!configurationVisible}
          >
            <div className="copilot-field-grid">
              <label>
                <span>Agent</span>
                <select
                  value={runtime}
                  onChange={(event) => handleRuntimeChange(event.target.value)}
                  disabled={Boolean(busyAction)}
                >
                  {runtimeOptions.map((entry) => (
                    <option key={entry.id} value={entry.id} disabled={entry.available === false}>
                      {entry.label || entry.id}{entry.available === false ? ' · unavailable' : ''}
                    </option>
                  ))}
                </select>
              </label>
              <label>
                <span>Model</span>
                {runtime === 'ollama' && modelOptions.length ? (
                  <select
                    value={model}
                    onChange={(event) => {
                      setModel(event.target.value);
                      rememberModel(runtime, event.target.value);
                    }}
                    disabled={Boolean(busyAction)}
                  >
                    {model && !selectedModelIsAvailable && (
                      <option value={model}>{model} · unavailable</option>
                    )}
                    {modelOptions.map((option) => (
                      <option key={option} value={option}>{option}</option>
                    ))}
                  </select>
                ) : (
                  <input
                    value={model}
                    onChange={(event) => {
                      setModel(event.target.value);
                      rememberModel(runtime, event.target.value);
                    }}
                    placeholder={selectedRuntime?.defaultModel || 'model name'}
                    disabled={Boolean(busyAction)}
                    spellCheck="false"
                  />
                )}
              </label>
            </div>

            <div className="copilot-field-grid copilot-mode-grid">
              <label>
                <span>Observe</span>
                <select
                  value={observationMode}
                  onChange={(event) => patchSetting(
                    'observationMode',
                    event.target.value,
                    setObservationMode,
                    observationMode
                  )}
                  disabled={Boolean(busyAction)}
                >
                  {OBSERVATION_MODES.map((option) => (
                    <option key={option.value} value={option.value}>{option.label}</option>
                  ))}
                </select>
              </label>
              <label>
                <span>Terminal control</span>
                <select
                  value={controlMode}
                  onChange={(event) => patchSetting(
                    'controlMode',
                    event.target.value,
                    setControlMode,
                    controlMode
                  )}
                  disabled={Boolean(busyAction)}
                >
                  {CONTROL_MODES.map((option) => (
                    <option key={option.value} value={option.value}>{option.label}</option>
                  ))}
                </select>
              </label>
              <label>
                <span>Tips</span>
                <select
                  value={tipIntervalSeconds}
                  onChange={(event) => patchSetting(
                    'tipIntervalSeconds',
                    Number(event.target.value),
                    setTipIntervalSeconds,
                    tipIntervalSeconds,
                    { number: true }
                  )}
                  disabled={Boolean(busyAction) || observationMode !== 'active'}
                >
                  {TIP_INTERVALS.map((option) => (
                    <option key={option.value} value={option.value}>{option.label}</option>
                  ))}
                </select>
              </label>
            </div>

            {selectedRuntime?.defaultModelError && (
              <div className="copilot-warning" role="status">
                <ShieldAlert size={13} aria-hidden="true" />
                {selectedRuntime.defaultModelError}
              </div>
            )}

            {!binding && (
              <button
                ref={launchButtonRef}
                type="button"
                className="copilot-primary-button"
                onClick={launchCopilot}
                disabled={
                  loading
                  || Boolean(busyAction)
                  || !String(model).trim()
                  || selectedRuntime?.available === false
                }
              >
                <Play size={13} aria-hidden="true" />
                {busyAction === 'launch' ? 'Launching…' : 'Launch copilot'}
              </button>
            )}
            {binding && runtimeChanged && (
              <button
                type="button"
                className="copilot-primary-button copilot-relaunch-button"
                onClick={relaunchCopilot}
                disabled={
                  Boolean(busyAction)
                  || !String(model).trim()
                  || selectedRuntime?.available === false
                }
              >
                <RotateCcw size={13} aria-hidden="true" />
                {busyAction === 'relaunch' ? 'Relaunching…' : 'Relaunch with changes'}
              </button>
            )}

            {controlMode === 'autonomous' && (
              <div className="copilot-warning">
                <ShieldAlert size={13} aria-hidden="true" />
                This copilot can press Enter until its access lease expires.
              </div>
            )}

            {binding && leases.length > 0 && (
              <div className="copilot-leases" aria-label="Copilot access leases">
                {leases.map((lease) => {
                  const countdown = formatCountdown(lease, now);
                  const inactive = ['expired', 'revoked'].includes(countdown);
                  return (
                    <div key={lease.key} className={`copilot-lease${inactive ? ' copilot-lease-expired' : ''}`}>
                      <span>
                        <strong>{lease.label}</strong>
                        <code>{countdown}</code>
                      </span>
                      <button
                        type="button"
                        className="secondary"
                        onClick={() => renewLease(lease)}
                        disabled={Boolean(busyAction)}
                      >
                        {busyAction === `renew-${lease.target}` ? 'Renewing…' : 'Renew'}
                      </button>
                    </div>
                  );
                })}
              </div>
            )}
            {binding?.analyzer && (
              <div className={`copilot-analyzer-state copilot-analyzer-${binding.analyzer.status || 'unknown'}`}>
                <Activity size={12} aria-hidden="true" />
                <span>
                  Local analyzer: {binding.analyzer.model || binding.analyzer.runtime || 'configured'}
                  {binding.analyzer.status ? ` · ${binding.analyzer.status}` : ''}
                  {binding.analyzer.reason ? ` · ${binding.analyzer.reason}` : ''}
                </span>
              </div>
            )}
          </section>
        )}

        {renderedError && (
          <div className="agent-error copilot-error" role="alert">
            <div>{renderedError.message}</div>
            {(renderedError.code || renderedError.status) && (
              <small>
                {renderedError.code && <code>{renderedError.code}</code>}
                {renderedError.code && renderedError.status ? ' · ' : ''}
                {renderedError.status ? `HTTP ${renderedError.status}` : ''}
              </small>
            )}
          </div>
        )}

        {binding && (
          <div className="copilot-live-status" aria-live="polite" aria-atomic="true">
            {liveAnnouncement}
          </div>
        )}

        {binding && (feedback.length > 0 || pendingProposals.length > 0) && (
          <section className="copilot-feed" aria-label="Live copilot analysis">
            <div className="copilot-section-heading">
              <strong><Activity size={12} aria-hidden="true" /> Live analysis</strong>
              <span>{feedback.length}</span>
            </div>
            <div className="copilot-feed-items">
              {pendingProposals.map((proposal) => (
                <article key={proposal.id || proposalCommand(proposal)} className="copilot-feed-item copilot-proposal">
                  <header>
                    <strong>Command proposal</strong>
                    <span>{formatTime(proposal.createdAt || proposal.timestamp)}</span>
                  </header>
                  <code>{proposalCommand(proposal)}</code>
                  {proposal.reason && (
                    <span className="copilot-proposal-reason">
                      Waiting: {proposal.reason.replaceAll('-', ' ')}
                    </span>
                  )}
                  <button
                    type="button"
                    onClick={() => approveProposal(proposal)}
                    disabled={Boolean(busyAction)}
                  >
                    {busyAction === `proposal-${proposal.id}` ? 'Running…' : 'Approve & run'}
                  </button>
                </article>
              ))}
              {feedback.slice(-30).reverse().map((item, index) => (
                <article key={item?.id || `${item?.timestamp || 'feedback'}-${index}`} className="copilot-feed-item">
                  <header>
                    <strong>{item?.title || item?.kind || item?.type || 'Copilot'}</strong>
                    <span>{formatTime(item?.createdAt || item?.timestamp)}</span>
                  </header>
                  <pre>{feedbackBody(item)}</pre>
                  {item?.confidence != null && (
                    <span className="copilot-confidence">confidence {item.confidence}</span>
                  )}
                </article>
              ))}
            </div>
          </section>
        )}

        {binding && (
          <section className="copilot-viewer" aria-label="Copilot agent terminal">
            <div className="copilot-section-heading">
              <strong>Agent terminal</strong>
              <span>{binding.model}</span>
            </div>
            <div className="copilot-viewer-terminal">
              {viewerTerminalId ? (
                <TerminalConsole
                  sessionId={viewerTerminalId}
                  showChrome={false}
                  compact
                  autoFocus={false}
                  updateDocumentTitle={false}
                />
              ) : (
                <div className="agent-empty">
                  {binding.status === 'error'
                    ? 'The agent terminal could not be started.'
                    : 'Starting the agent terminal…'}
                </div>
              )}
            </div>
          </section>
        )}

        {session && (
          <section className="copilot-ask" aria-label="Ask copilot">
            <div className="copilot-section-heading">
              <strong>Ask about this terminal</strong>
              <span className={selectionTooLarge ? 'copilot-count-error' : ''}>
                {selectionLength.toLocaleString()} / {SELECTION_LIMIT.toLocaleString()}
              </span>
            </div>
            {selectedText ? (
              <div className={`copilot-selection${selectionTooLarge ? ' copilot-selection-error' : ''}`}>
                <pre>{selectedText}</pre>
                <button
                  type="button"
                  className="copilot-clear-selection"
                  onClick={onClearSelection}
                  aria-label="Clear highlighted terminal text"
                  title="Clear highlighted text"
                >
                  <X size={12} aria-hidden="true" />
                </button>
              </div>
            ) : (
              <div className="copilot-selection-placeholder">
                Highlight terminal output to attach it to your question.
              </div>
            )}
            <div className="copilot-question-row">
              <textarea
                value={question}
                onChange={(event) => setQuestion(event.target.value)}
                onKeyDown={(event) => {
                  if ((event.ctrlKey || event.metaKey) && event.key === 'Enter') {
                    event.preventDefault();
                    askCopilot();
                  }
                }}
                rows={2}
                placeholder={binding ? 'What does this mean? (Ctrl+Enter)' : 'Launch a copilot to ask a question'}
                disabled={!binding || Boolean(busyAction)}
              />
              <button
                type="button"
                onClick={askCopilot}
                disabled={
                  !binding
                  || !question.trim()
                  || selectionTooLarge
                  || Boolean(busyAction)
                }
                aria-label="Ask copilot"
                title="Ask copilot"
              >
                <Send size={14} aria-hidden="true" />
              </button>
            </div>
            {selectionTooLarge && (
              <div className="copilot-inline-error" role="alert">
                Highlight no more than {SELECTION_LIMIT.toLocaleString()} characters. The selection was not truncated.
              </div>
            )}
          </section>
        )}
      </div>
    </aside>
  );
}
