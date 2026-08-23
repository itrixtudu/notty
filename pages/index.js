import { useCallback, useEffect, useRef, useState } from 'react';
import Link from 'next/link';
import {
  Bot,
  Columns2,
  ExternalLink,
  Maximize2,
  Minimize2,
  PanelRightOpen,
  Plus,
  RefreshCw,
  Rows2,
  Settings2,
  SquareTerminal,
  Trash2
} from 'lucide-react';
import TerminalCreator from '../components/TerminalCreator.js';
import TerminalList from '../components/TerminalList.js';
import ConfigPanel from '../components/ConfigPanel.js';
import SpawnOtpManager from '../components/SpawnOtpManager.js';
import CopilotPane from '../components/CopilotPane.js';
import TerminalConsole from '../components/TerminalConsole.js';
import SessionTabs from '../components/SessionTabs.js';
import TerminalPaneLayout from '../components/terminal/TerminalPaneLayout.js';
import {
  buildCopilotPopoutPath,
  COPILOT_PANE_MODE_COLLAPSED,
  COPILOT_PANE_MODE_DOCKED,
  COPILOT_PANE_MODE_OPENING,
  COPILOT_PANE_MODE_POPOUT,
  createCopilotWindowMessage,
  deriveCopilotPanePresentation,
  isCopilotWindowMessage,
  normalizeCopilotPaneMode
} from '../components/copilotPaneModel.js';
import { browserFetch, resolveBrowserUrl } from '../lib/browserRequest.js';
import { isTerminalLockdownEnabled } from '../lib/lockdown.js';
import { isCollabEnabled } from '../lib/runtimeFeatures.js';
import styles from '../styles/Terminal.module.css';
import {
  createInitialLayout,
  getFirstPane,
  getPane,
  hasPane,
  pruneSessionFromLayout,
  splitPane,
  updatePane,
  updateSplitRatios
} from '../lib/terminalLayout.js';

const AGENT_SIDEBAR_DEFAULT_WIDTH = 380;
const AGENT_SIDEBAR_MIN_WIDTH = 320;
const AGENT_SIDEBAR_MAX_WIDTH = 720;
const AGENT_SIDEBAR_MIN_TERMINAL_WIDTH = 420;
const AGENT_DIVIDER_WIDTH = 14;
const AGENT_SIDEBAR_WIDTH_STORAGE_KEY = 'notty.agentSidebarWidth';
const COPILOT_PANE_MODE_STORAGE_KEY = 'notty.copilotPaneMode';
const COPILOT_POPOUT_WINDOW_NAME = 'notty-copilot';
const COPILOT_POPOUT_READY_TIMEOUT_MS = 6_000;
const COPILOT_POPOUT_CLOSED_POLL_MS = 500;

function clampAgentSidebarWidth(width, workspaceWidth = 0) {
  const maxWidth = workspaceWidth
    ? Math.min(
        AGENT_SIDEBAR_MAX_WIDTH,
        Math.max(
          AGENT_SIDEBAR_MIN_WIDTH,
          workspaceWidth - AGENT_SIDEBAR_MIN_TERMINAL_WIDTH - AGENT_DIVIDER_WIDTH
        )
      )
    : AGENT_SIDEBAR_MAX_WIDTH;

  return Math.min(
    Math.max(Math.round(width), AGENT_SIDEBAR_MIN_WIDTH),
    maxWidth
  );
}

function readStoredAgentSidebarWidth() {
  if (typeof window === 'undefined') {
    return null;
  }

  try {
    const storedValue = window.localStorage.getItem(AGENT_SIDEBAR_WIDTH_STORAGE_KEY);
    if (!storedValue) {
      return null;
    }
    const width = Number(storedValue);
    return Number.isFinite(width) ? width : null;
  } catch {
    return null;
  }
}

function storeAgentSidebarWidth(width) {
  if (typeof window === 'undefined') {
    return;
  }

  try {
    window.localStorage.setItem(AGENT_SIDEBAR_WIDTH_STORAGE_KEY, String(Math.round(width)));
  } catch {
    // Browser storage can be unavailable in restricted modes.
  }
}

function createCopilotPopoutInstanceId() {
  if (typeof window !== 'undefined' && typeof window.crypto?.randomUUID === 'function') {
    return window.crypto.randomUUID();
  }
  return `copilot-${Date.now()}-${Math.random().toString(36).slice(2)}`;
}

function readStoredCopilotPaneMode() {
  if (typeof window === 'undefined') {
    return COPILOT_PANE_MODE_DOCKED;
  }
  try {
    return normalizeCopilotPaneMode(
      window.localStorage.getItem(COPILOT_PANE_MODE_STORAGE_KEY)
    );
  } catch {
    return COPILOT_PANE_MODE_DOCKED;
  }
}

function storeCopilotPaneMode(mode) {
  if (
    typeof window === 'undefined'
    || (mode !== COPILOT_PANE_MODE_DOCKED && mode !== COPILOT_PANE_MODE_COLLAPSED)
  ) {
    return;
  }
  try {
    window.localStorage.setItem(COPILOT_PANE_MODE_STORAGE_KEY, mode);
  } catch {
    // Browser storage can be unavailable in restricted modes.
  }
}


function isEditableTarget(target) {
  if (!target || typeof target !== 'object') {
    return false;
  }
  if (typeof HTMLElement === 'undefined' || !(target instanceof HTMLElement)) {
    return false;
  }
  if (target.isContentEditable) {
    return true;
  }
  const tagName = target.tagName?.toLowerCase();
  return tagName === 'input' || tagName === 'textarea' || tagName === 'select';
}

function isWithinXterm(target) {
  if (!target || typeof target !== 'object') {
    return false;
  }
  if (typeof target.closest !== 'function') {
    return false;
  }
  return Boolean(target.closest('.xterm-wrapper'));
}

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

export default function HomePage({ collabEnabled = false }) {
  const [sessions, setSessions] = useState([]);
  const [selectedId, setSelectedId] = useState(null);
  const [terminalLayout, setTerminalLayout] = useState(() => createInitialLayout());
  const [activePaneId, setActivePaneId] = useState('pane-1');
  const nextPaneIdRef = useRef(2);
  const [loading, setLoading] = useState(true);
  const [creating, setCreating] = useState(false);
  const [error, setError] = useState('');
  const [settingsOpen, setSettingsOpen] = useState(false);
  const [consoleExpanded, setConsoleExpanded] = useState(false);
  const [terminalSelections, setTerminalSelections] = useState({});
  const [agentSidebarWidth, setAgentSidebarWidth] = useState(AGENT_SIDEBAR_DEFAULT_WIDTH);
  const [agentSidebarWidthLoaded, setAgentSidebarWidthLoaded] = useState(false);
  const [resizingAgentSidebar, setResizingAgentSidebar] = useState(false);
  const [copilotPaneMode, setCopilotPaneMode] = useState(COPILOT_PANE_MODE_DOCKED);
  const [copilotPaneModeLoaded, setCopilotPaneModeLoaded] = useState(false);
  const [copilotPaneError, setCopilotPaneError] = useState('');
  const [copilotPaneFocusToken, setCopilotPaneFocusToken] = useState(0);
  const overlayRef = useRef(null);
  const workspaceRef = useRef(null);
  const copilotPaneRailRef = useRef(null);
  const copilotPopupRef = useRef(null);
  const copilotPopupContextRef = useRef(null);
  const focusCopilotRailRef = useRef(false);
  const terminalSelectionsRef = useRef(terminalSelections);
  terminalSelectionsRef.current = terminalSelections;
  const copilotPanePresentation = deriveCopilotPanePresentation(copilotPaneMode);

  const loadSessions = useCallback(async () => {
    setLoading(true);
    try {
      const data = await jsonFetch('/api/terminals');
      const workspaceSessions = data.sessions.filter((session) => (
        session?.metadata?.type !== 'copilot-view'
      ));
      setSessions(workspaceSessions);
      setError('');
      if (!selectedId && workspaceSessions.length) {
        const nextSelectedId = workspaceSessions[0].id;
        setSelectedId(nextSelectedId);
        setTerminalLayout((layout) => updatePane(layout, activePaneId, (pane) => (
          pane.sessionId ? pane : { ...pane, sessionId: nextSelectedId }
        )));
      }
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  }, [activePaneId, selectedId]);

  useEffect(() => {
    loadSessions();
  }, [loadSessions]);

  useEffect(() => {
    if (!settingsOpen || typeof window === 'undefined') {
      return undefined;
    }

    const dialog = overlayRef.current;
    const previouslyFocused = document.activeElement;
    dialog?.focus();

    const handleKeydown = (event) => {
      if (event.key === 'Escape') {
        event.preventDefault();
        setSettingsOpen(false);
        return;
      }

      if (event.key !== 'Tab' || !dialog) {
        return;
      }

      const focusable = Array.from(dialog.querySelectorAll(
        'a[href], button:not([disabled]), input:not([disabled]), select:not([disabled]), textarea:not([disabled]), [tabindex]:not([tabindex="-1"])'
      )).filter((element) => element.getClientRects().length > 0);
      const first = focusable[0];
      const last = focusable[focusable.length - 1];
      const activeElement = document.activeElement;

      if (!first || !last) {
        event.preventDefault();
        dialog.focus();
      } else if (event.shiftKey && (activeElement === first || activeElement === dialog)) {
        event.preventDefault();
        last.focus();
      } else if (!event.shiftKey && (activeElement === last || !dialog.contains(activeElement))) {
        event.preventDefault();
        first.focus();
      }
    };

    window.addEventListener('keydown', handleKeydown);
    return () => {
      window.removeEventListener('keydown', handleKeydown);
      if (previouslyFocused instanceof HTMLElement && previouslyFocused.isConnected) {
        window.requestAnimationFrame(() => previouslyFocused.focus());
      }
    };
  }, [settingsOpen]);

  const toggleConsoleExpanded = useCallback(() => {
    setConsoleExpanded((prev) => !prev);
  }, []);

  const collapseConsole = useCallback(() => {
    setConsoleExpanded(false);
  }, []);

  useEffect(() => {
    if (typeof window === 'undefined') {
      return undefined;
    }
    const handleShortcut = (event) => {
      if (event.ctrlKey && event.altKey && event.key.toLowerCase() === 'f') {
        event.preventDefault();
        setConsoleExpanded((prev) => !prev);
      }
    };
    window.addEventListener('keydown', handleShortcut);
    return () => window.removeEventListener('keydown', handleShortcut);
  }, []);

  const handleCreate = useCallback(async (payload) => {
    setCreating(true);
    try {
      const data = await jsonFetch('/api/terminals', {
        method: 'POST',
        body: JSON.stringify(payload)
      });
      setSelectedId(data.session.id);
      setTerminalLayout((layout) => updatePane(layout, activePaneId, (pane) => ({
        ...pane,
        sessionId: data.session.id
      })));
      await loadSessions();
    } catch (err) {
      setError(err.message);
    } finally {
      setCreating(false);
    }
  }, [activePaneId, loadSessions]);

  const handleKill = async () => {
    if (!selectedId) return;
    try {
      await browserFetch(`/api/terminals/${selectedId}`, { method: 'DELETE' });
      setSelectedId(null);
      setTerminalLayout((layout) => pruneSessionFromLayout(layout, selectedId));
      await loadSessions();
    } catch (err) {
      setError(err.message);
    }
  };

  const selectSession = (sessionId) => {
    const nextSelectedId = sessionId === '' || sessionId == null
      ? null
      : Number(sessionId);
    setSelectedId(nextSelectedId);
    setTerminalLayout((layout) => updatePane(layout, activePaneId, (pane) => ({
      ...pane,
      sessionId: nextSelectedId
    })));
  };

  const handleQuickCreate = useCallback(() => {
    handleCreate({});
  }, [handleCreate]);

  const getWorkspaceWidth = useCallback(() => (
    workspaceRef.current?.getBoundingClientRect().width || 0
  ), []);

  const resizeAgentSidebar = useCallback((nextWidth) => {
    setAgentSidebarWidth(
      clampAgentSidebarWidth(nextWidth, getWorkspaceWidth())
    );
  }, [getWorkspaceWidth]);

  const resizeAgentSidebarBy = useCallback((delta) => {
    setAgentSidebarWidth((previous) => (
      clampAgentSidebarWidth(previous + delta, getWorkspaceWidth())
    ));
  }, [getWorkspaceWidth]);

  const handleAgentDividerPointerDown = useCallback((event) => {
    if (event.button !== 0) {
      return;
    }

    const workspace = workspaceRef.current;
    if (!workspace || typeof window === 'undefined') {
      return;
    }

    event.preventDefault();
    setResizingAgentSidebar(true);
    event.currentTarget.setPointerCapture?.(event.pointerId);

    const rect = workspace.getBoundingClientRect();
    const previousBodyCursor = document.body.style.cursor;
    const previousBodyUserSelect = document.body.style.userSelect;
    document.body.style.cursor = 'col-resize';
    document.body.style.userSelect = 'none';
    const updateFromPointer = (clientX) => {
      resizeAgentSidebar(rect.right - clientX - (AGENT_DIVIDER_WIDTH / 2));
    };
    const handlePointerMove = (moveEvent) => {
      moveEvent.preventDefault();
      updateFromPointer(moveEvent.clientX);
    };
    const stopResize = () => {
      setResizingAgentSidebar(false);
      document.body.style.cursor = previousBodyCursor;
      document.body.style.userSelect = previousBodyUserSelect;
      window.removeEventListener('pointermove', handlePointerMove);
      window.removeEventListener('pointerup', stopResize);
      window.removeEventListener('pointercancel', stopResize);
    };

    updateFromPointer(event.clientX);
    window.addEventListener('pointermove', handlePointerMove);
    window.addEventListener('pointerup', stopResize);
    window.addEventListener('pointercancel', stopResize);
  }, [resizeAgentSidebar]);

  const handleAgentDividerKeyDown = useCallback((event) => {
    const largeStep = event.shiftKey ? 80 : 24;

    if (event.key === 'ArrowLeft') {
      event.preventDefault();
      resizeAgentSidebarBy(largeStep);
    } else if (event.key === 'ArrowRight') {
      event.preventDefault();
      resizeAgentSidebarBy(-largeStep);
    } else if (event.key === 'Home') {
      event.preventDefault();
      resizeAgentSidebar(AGENT_SIDEBAR_MAX_WIDTH);
    } else if (event.key === 'End') {
      event.preventDefault();
      resizeAgentSidebar(AGENT_SIDEBAR_MIN_WIDTH);
    }
  }, [resizeAgentSidebar, resizeAgentSidebarBy]);

  useEffect(() => {
    const storedWidth = readStoredAgentSidebarWidth();
    if (storedWidth !== null) {
      setAgentSidebarWidth(
        clampAgentSidebarWidth(storedWidth, getWorkspaceWidth())
      );
    }
    setAgentSidebarWidthLoaded(true);
  }, [getWorkspaceWidth]);

  useEffect(() => {
    if (!agentSidebarWidthLoaded) {
      return;
    }
    storeAgentSidebarWidth(agentSidebarWidth);
  }, [agentSidebarWidth, agentSidebarWidthLoaded]);

  useEffect(() => {
    setCopilotPaneMode(readStoredCopilotPaneMode());
    setCopilotPaneModeLoaded(true);
  }, []);

  useEffect(() => {
    if (copilotPaneModeLoaded) {
      storeCopilotPaneMode(copilotPaneMode);
    }
  }, [copilotPaneMode, copilotPaneModeLoaded]);

  useEffect(() => {
    if (!focusCopilotRailRef.current || copilotPaneMode === COPILOT_PANE_MODE_DOCKED) {
      return undefined;
    }
    focusCopilotRailRef.current = false;
    const frame = window.requestAnimationFrame(() => copilotPaneRailRef.current?.focus());
    return () => window.cancelAnimationFrame(frame);
  }, [copilotPaneMode]);

  useEffect(() => {
    if (typeof window === 'undefined') {
      return undefined;
    }

    const handleShortcut = (event) => {
      if (event.defaultPrevented) {
        return;
      }
      if (
        event.ctrlKey
        && event.shiftKey
        && !event.altKey
        && !event.metaKey
        && event.key === 'ArrowRight'
      ) {
        if (event.repeat) {
          return;
        }
        if (isEditableTarget(event.target) && !isWithinXterm(event.target)) {
          return;
        }
        event.preventDefault();
        handleQuickCreate();
      }
    };

    window.addEventListener('keydown', handleShortcut);
    return () => window.removeEventListener('keydown', handleShortcut);
  }, [handleQuickCreate]);

  useEffect(() => {
    if (typeof window === 'undefined') {
      return undefined;
    }

    const handleResize = () => {
      setAgentSidebarWidth((previous) => (
        clampAgentSidebarWidth(previous, getWorkspaceWidth())
      ));
    };

    window.addEventListener('resize', handleResize);
    handleResize();
    return () => window.removeEventListener('resize', handleResize);
  }, [getWorkspaceWidth]);

  useEffect(() => {
    setTerminalLayout((layout) => (
      hasPane(layout, activePaneId) ? layout : createInitialLayout(selectedId)
    ));
  }, [activePaneId, selectedId]);

  const activePane = getPane(terminalLayout, activePaneId) || getFirstPane(terminalLayout);
  const activeSessionId = activePane?.sessionId ?? null;

  useEffect(() => {
    setSelectedId(activeSessionId);
  }, [activeSessionId]);

  const splitTerminalPane = useCallback(async (direction) => {
    if (!activePaneId || creating) {
      return;
    }

    const targetPaneId = activePaneId;
    setCreating(true);
    try {
      const data = await jsonFetch('/api/terminals', {
        method: 'POST',
        body: JSON.stringify({})
      });
      const newSession = data?.session;
      if (newSession?.id == null) {
        throw new Error('Terminal creation did not return a session id');
      }

      const newPaneId = `pane-${nextPaneIdRef.current}`;
      nextPaneIdRef.current += 1;
      setSessions((currentSessions) => [
        ...currentSessions.filter((session) => session.id !== newSession.id),
        newSession
      ]);
      setTerminalLayout((layout) => (
        splitPane(layout, targetPaneId, newPaneId, direction, newSession.id)
      ));
      setActivePaneId(newPaneId);
      setSelectedId(newSession.id);
      setError('');
    } catch (err) {
      setError(err.message);
    } finally {
      setCreating(false);
    }
  }, [activePaneId, creating]);

  const resizeTerminalSplit = useCallback((splitId, ratios) => {
    setTerminalLayout((layout) => updateSplitRatios(layout, splitId, ratios));
  }, []);

  const selectedSession = sessions.find((session) => session.id === activeSessionId) || null;
  const selectedTerminalKey = selectedSession?.terminal_uuid
    || (activeSessionId == null ? '' : `terminal-id:${activeSessionId}`);
  const selectedTerminalText = selectedTerminalKey
    ? terminalSelections[selectedTerminalKey] || ''
    : '';

  const handleTerminalSelection = useCallback((terminalKey, text) => {
    if (!terminalKey) {
      return;
    }
    setTerminalSelections((current) => {
      if (!text) {
        if (!(terminalKey in current)) {
          return current;
        }
        const next = { ...current };
        delete next[terminalKey];
        return next;
      }
      if (current[terminalKey] === text) {
        return current;
      }
      return { ...current, [terminalKey]: text };
    });
  }, []);

  const clearSelectedTerminalText = useCallback(() => {
    if (selectedTerminalKey) {
      handleTerminalSelection(selectedTerminalKey, '');
    }
  }, [handleTerminalSelection, selectedTerminalKey]);

  const restoreCopilotPaneAfterPopup = useCallback(() => {
    copilotPopupRef.current = null;
    copilotPopupContextRef.current = null;
    setCopilotPaneMode(COPILOT_PANE_MODE_DOCKED);
    setCopilotPaneError('');
    setCopilotPaneFocusToken((token) => token + 1);
  }, []);

  const dockCopilotPane = useCallback(() => {
    const popup = copilotPopupRef.current;
    copilotPopupRef.current = null;
    copilotPopupContextRef.current = null;
    if (popup && !popup.closed) {
      try {
        popup.close();
      } catch {
        // The closed-window poll remains the fallback for unusual browser policies.
      }
    }
    setCopilotPaneMode(COPILOT_PANE_MODE_DOCKED);
    setCopilotPaneError('');
    setCopilotPaneFocusToken((token) => token + 1);
  }, []);

  const collapseCopilotPane = useCallback(() => {
    focusCopilotRailRef.current = true;
    setCopilotPaneError('');
    setCopilotPaneMode(COPILOT_PANE_MODE_COLLAPSED);
  }, []);

  const expandCopilotPane = useCallback(() => {
    setCopilotPaneMode(COPILOT_PANE_MODE_DOCKED);
    setCopilotPaneError('');
    setCopilotPaneFocusToken((token) => token + 1);
  }, []);

  const toggleCopilotPane = useCallback(() => {
    if (copilotPaneMode === COPILOT_PANE_MODE_DOCKED) {
      collapseCopilotPane();
    } else if (copilotPaneMode === COPILOT_PANE_MODE_COLLAPSED) {
      expandCopilotPane();
    } else {
      dockCopilotPane();
    }
  }, [
    collapseCopilotPane,
    copilotPaneMode,
    dockCopilotPane,
    expandCopilotPane
  ]);

  const focusCopilotPopout = useCallback(() => {
    const popup = copilotPopupRef.current;
    if (!popup || popup.closed) {
      restoreCopilotPaneAfterPopup();
      return;
    }
    try {
      popup.focus();
    } catch {
      setCopilotPaneError('The Copilot window could not be focused. Dock it to continue here.');
    }
  }, [restoreCopilotPaneAfterPopup]);

  const popOutCopilotPane = useCallback(() => {
    if (typeof window === 'undefined' || !selectedSession?.terminal_uuid) {
      return;
    }

    const existingPopup = copilotPopupRef.current;
    if (existingPopup && !existingPopup.closed) {
      existingPopup.focus();
      return;
    }

    const instanceId = createCopilotPopoutInstanceId();
    const path = buildCopilotPopoutPath(selectedSession, { instanceId });
    if (!path) {
      return;
    }

    let popup = null;
    try {
      popup = window.open(
        resolveBrowserUrl(path),
        COPILOT_POPOUT_WINDOW_NAME,
        'popup=yes,width=520,height=860,resizable=yes,scrollbars=yes'
      );
    } catch {
      popup = null;
    }

    if (!popup) {
      setCopilotPaneError(
        'The browser blocked the Copilot window. Allow pop-ups for this site and try again.'
      );
      return;
    }

    copilotPopupRef.current = popup;
    copilotPopupContextRef.current = {
      sourceTerminalUuid: selectedSession.terminal_uuid,
      instanceId
    };
    setCopilotPaneError('');
    setCopilotPaneMode(COPILOT_PANE_MODE_OPENING);
    popup.focus();
  }, [selectedSession]);

  useEffect(() => {
    if (typeof window === 'undefined') {
      return undefined;
    }

    const handleCopilotWindowMessage = (event) => {
      const popup = copilotPopupRef.current;
      const context = copilotPopupContextRef.current;
      if (
        !popup
        || !context
        || event.origin !== window.location.origin
        || event.source !== popup
        || !isCopilotWindowMessage(event.data)
        || event.data.sourceTerminalUuid !== context.sourceTerminalUuid
        || event.data.instanceId !== context.instanceId
      ) {
        return;
      }

      if (event.data.action === 'ready') {
        setCopilotPaneMode(COPILOT_PANE_MODE_POPOUT);
        setCopilotPaneError('');
        popup.postMessage(createCopilotWindowMessage('selection', {
          sourceTerminalUuid: context.sourceTerminalUuid,
          instanceId: context.instanceId,
          selectedText: terminalSelectionsRef.current[context.sourceTerminalUuid] || ''
        }), window.location.origin);
      } else if (event.data.action === 'clear-selection') {
        handleTerminalSelection(context.sourceTerminalUuid, '');
      } else if (event.data.action === 'dock') {
        dockCopilotPane();
      }
    };

    window.addEventListener('message', handleCopilotWindowMessage);
    return () => window.removeEventListener('message', handleCopilotWindowMessage);
  }, [dockCopilotPane, handleTerminalSelection]);

  useEffect(() => {
    if (copilotPaneMode !== COPILOT_PANE_MODE_OPENING) {
      return undefined;
    }
    const expectedPopup = copilotPopupRef.current;
    const timer = window.setTimeout(() => {
      if (!expectedPopup || copilotPopupRef.current !== expectedPopup) {
        return;
      }
      copilotPopupRef.current = null;
      copilotPopupContextRef.current = null;
      try {
        expectedPopup.close();
      } catch {
        // Restore the docked pane even if browser policy prevents closing the window.
      }
      setCopilotPaneMode(COPILOT_PANE_MODE_DOCKED);
      setCopilotPaneError(
        'The Copilot window did not finish loading, so the pane was restored here.'
      );
      setCopilotPaneFocusToken((token) => token + 1);
    }, COPILOT_POPOUT_READY_TIMEOUT_MS);
    return () => window.clearTimeout(timer);
  }, [copilotPaneMode]);

  useEffect(() => {
    if (
      copilotPaneMode !== COPILOT_PANE_MODE_OPENING
      && copilotPaneMode !== COPILOT_PANE_MODE_POPOUT
    ) {
      return undefined;
    }
    const interval = window.setInterval(() => {
      const popup = copilotPopupRef.current;
      if (popup && !popup.closed) {
        return;
      }
      restoreCopilotPaneAfterPopup();
    }, COPILOT_POPOUT_CLOSED_POLL_MS);
    return () => window.clearInterval(interval);
  }, [copilotPaneMode, restoreCopilotPaneAfterPopup]);

  useEffect(() => {
    if (copilotPaneMode !== COPILOT_PANE_MODE_POPOUT) {
      return;
    }
    const popup = copilotPopupRef.current;
    const context = copilotPopupContextRef.current;
    if (!popup || popup.closed || !context) {
      return;
    }
    popup.postMessage(createCopilotWindowMessage('selection', {
      sourceTerminalUuid: context.sourceTerminalUuid,
      instanceId: context.instanceId,
      selectedText: terminalSelections[context.sourceTerminalUuid] || ''
    }), window.location.origin);
  }, [copilotPaneMode, terminalSelections]);

  const renderTerminalPane = useCallback((pane, isActive) => {
    const paneSession = sessions.find((session) => session.id === pane.sessionId) || null;
    const terminalKey = paneSession?.terminal_uuid
      || (pane.sessionId == null ? '' : `terminal-id:${pane.sessionId}`);
    return (
      <TerminalConsole
        sessionId={pane.sessionId}
        onNewTerminal={handleQuickCreate}
        autoFocus={isActive}
        updateDocumentTitle={false}
        onSelectionChange={({ text }) => handleTerminalSelection(terminalKey, text)}
      />
    );
  }, [handleQuickCreate, handleTerminalSelection, sessions]);

  const openSettings = () => setSettingsOpen(true);
  const closeSettings = () => setSettingsOpen(false);

  const serviceStatus = error ? 'attention' : loading ? 'syncing' : 'ready';
  const copilotPaneToggleLabel = copilotPaneMode === COPILOT_PANE_MODE_DOCKED
    ? 'Hide Copilot pane'
    : copilotPaneMode === COPILOT_PANE_MODE_COLLAPSED
      ? 'Show Copilot pane'
      : 'Dock Copilot pane';
  const pageClassNames = ['terminal-page', styles.page];
  const workspaceClassNames = ['terminal-workspace'];
  if (consoleExpanded) {
    pageClassNames.push('console-expanded');
  }
  if (resizingAgentSidebar) {
    workspaceClassNames.push('resizing-agent-sidebar');
  }
  if (!copilotPanePresentation.paneVisible) {
    workspaceClassNames.push('copilot-pane-compact');
  }

  return (
    <main className={pageClassNames.join(' ')}>
      <header className={styles.appHeader}>
        <div className={styles.brandBlock}>
          <div className={styles.brandLine}>
            <SquareTerminal size={17} strokeWidth={1.8} aria-hidden="true" />
            <h1>Notty Terminals</h1>
            <span
              className={`${styles.serviceState} ${
                serviceStatus === 'ready'
                  ? styles.serviceReady
                  : serviceStatus === 'attention'
                    ? styles.serviceAttention
                    : styles.serviceSyncing
              }`}
            >
              {serviceStatus}
            </span>
          </div>
          <span className={styles.workspacePath}>
            {selectedSession?.cwd || (loading ? 'Discovering terminal sessions…' : 'Ready for a terminal session')}
          </span>
        </div>
        <nav className={styles.primaryNav} aria-label="Primary">
          <Link href="/" aria-current="page">Terminals</Link>
          {collabEnabled && (
            <Link href="/collab">Collab</Link>
          )}
        </nav>
      </header>

      <div className={styles.workspaceToolbar}>
        <SessionTabs
          sessions={sessions}
          activeSessionId={activeSessionId}
          onSelect={selectSession}
        />

        <div className={styles.toolbarControls}>
          <button
            type="button"
            className={styles.toolbarIcon}
            onClick={loadSessions}
            disabled={loading}
            aria-label="Refresh terminal sessions"
            title="Refresh sessions"
          >
            <RefreshCw size={15} aria-hidden="true" />
          </button>

          <button
            type="button"
            className={styles.newTerminalButton}
            onClick={handleQuickCreate}
            disabled={creating}
            title="New terminal (Ctrl+Shift+→)"
            aria-label={creating ? 'Spawning terminal' : 'New terminal'}
            aria-keyshortcuts="Control+Shift+ArrowRight"
          >
            <Plus size={15} aria-hidden="true" />
            <span>{creating ? 'Spawning…' : 'New terminal'}</span>
          </button>

          <button
            type="button"
            className={`${styles.copilotToggleButton}${copilotPanePresentation.paneVisible
              ? ` ${styles.copilotToggleButtonActive}`
              : ''}`}
            onClick={toggleCopilotPane}
            aria-controls="terminal-copilot-pane"
            aria-pressed={copilotPanePresentation.paneVisible}
            aria-label={copilotPaneToggleLabel}
            title={copilotPaneToggleLabel}
          >
            <Bot size={15} aria-hidden="true" />
            <span>Copilot</span>
          </button>

          <button
            type="button"
            className={styles.toolbarIcon}
            aria-label="Open settings"
            title="Settings and sessions"
            onClick={openSettings}
          >
            <Settings2 size={15} aria-hidden="true" />
          </button>

          <span className={styles.toolbarDivider} aria-hidden="true" />

          <button
            type="button"
            className={styles.toolbarIcon}
            onClick={() => splitTerminalPane('vertical')}
            disabled={!activePaneId || creating}
            aria-label="Split terminal into columns"
            title="Split into columns"
          >
            <Columns2 size={15} aria-hidden="true" />
          </button>
          <button
            type="button"
            className={styles.toolbarIcon}
            onClick={() => splitTerminalPane('horizontal')}
            disabled={!activePaneId || creating}
            aria-label="Split terminal into rows"
            title="Split into rows"
          >
            <Rows2 size={15} aria-hidden="true" />
          </button>
          <button
            type="button"
            className={styles.toolbarIcon}
            aria-label={consoleExpanded ? 'Exit terminal maximized view (Ctrl+Alt+F)' : 'Maximize terminal (Ctrl+Alt+F)'}
            title={consoleExpanded ? 'Exit maximized view' : 'Maximize terminal'}
            onClick={toggleConsoleExpanded}
          >
            {consoleExpanded
              ? <Minimize2 size={15} aria-hidden="true" />
              : <Maximize2 size={15} aria-hidden="true" />}
          </button>
          <button
            type="button"
            className={`${styles.toolbarIcon} ${styles.dangerAction}`}
            onClick={handleKill}
            disabled={!selectedId}
            aria-label="Kill selected terminal"
            title="Kill selected terminal"
          >
            <Trash2 size={15} aria-hidden="true" />
          </button>
        </div>
      </div>
      {error && (
        <div className="inline-error" role="alert">
          {error}
        </div>
      )}
      {copilotPaneError && (
        <div className="inline-error" role="alert">
          {copilotPaneError}
        </div>
      )}

      <div className="terminal-stage">
        <div
          className={workspaceClassNames.join(' ')}
          ref={workspaceRef}
          style={{ '--agent-sidebar-width': `${agentSidebarWidth}px` }}
        >
          <section className="terminal-main-pane" aria-label="Terminal panes">
            <TerminalPaneLayout
              layout={terminalLayout}
              activePaneId={activePaneId}
              onActivatePane={setActivePaneId}
              onNewTerminal={handleQuickCreate}
              onResizeSplit={resizeTerminalSplit}
              renderPane={renderTerminalPane}
            />
          </section>
          {copilotPanePresentation.resizerVisible && (
            <button
              type="button"
              className="terminal-pane-resizer"
              aria-label="Resize Copilot pane"
              aria-orientation="vertical"
              aria-valuemin={AGENT_SIDEBAR_MIN_WIDTH}
              aria-valuemax={AGENT_SIDEBAR_MAX_WIDTH}
              aria-valuenow={agentSidebarWidth}
              onPointerDown={handleAgentDividerPointerDown}
              onKeyDown={handleAgentDividerKeyDown}
              role="separator"
            />
          )}
          <CopilotPane
            session={selectedSession}
            selectedText={selectedTerminalText}
            onClearSelection={clearSelectedTerminalText}
            onCollapse={collapseCopilotPane}
            onPopOut={popOutCopilotPane}
            popoutOpening={copilotPaneMode === COPILOT_PANE_MODE_OPENING}
            focusToken={copilotPaneFocusToken}
            compact={!copilotPanePresentation.paneVisible}
          />
          {copilotPanePresentation.restoreControlVisible && (
            <aside
              className={`copilot-pane-rail copilot-pane-rail-${copilotPaneMode}`}
              aria-label={copilotPanePresentation.popupOpen
                ? 'Copilot separate-window controls'
                : 'Collapsed Copilot pane'}
            >
              {copilotPaneMode === COPILOT_PANE_MODE_COLLAPSED ? (
                <button
                  ref={copilotPaneRailRef}
                  type="button"
                  className="copilot-pane-rail-expand"
                  onClick={expandCopilotPane}
                  aria-controls="terminal-copilot-pane"
                  aria-expanded={false}
                  aria-label="Expand Copilot pane"
                  title="Expand Copilot pane"
                >
                  <PanelRightOpen size={15} aria-hidden="true" />
                  <span>Copilot</span>
                </button>
              ) : (
                <>
                  <button
                    ref={copilotPaneRailRef}
                    type="button"
                    onClick={focusCopilotPopout}
                    aria-label="Focus Copilot window"
                    title="Focus Copilot window"
                  >
                    <ExternalLink size={14} aria-hidden="true" />
                  </button>
                  <span className="copilot-pane-rail-status" aria-live="polite">
                    {copilotPaneMode === COPILOT_PANE_MODE_OPENING ? 'Opening' : 'Popped out'}
                  </span>
                  <button
                    type="button"
                    onClick={dockCopilotPane}
                    aria-controls="terminal-copilot-pane"
                    aria-expanded={false}
                    aria-label="Dock Copilot pane"
                    title="Dock Copilot pane"
                  >
                    <PanelRightOpen size={14} aria-hidden="true" />
                  </button>
                </>
              )}
            </aside>
          )}
        </div>
      </div>

      {consoleExpanded && (
        <button
          type="button"
          className="terminal-collapse-button"
          onClick={collapseConsole}
          aria-label="Exit terminal maximized view"
        >
          <Minimize2 size={18} aria-hidden="true" />
        </button>
      )}

      {settingsOpen && (
        <div className="control-overlay" onClick={closeSettings}>
          <div
            className="control-panel"
            role="dialog"
            aria-modal="true"
            aria-label="Terminal settings"
            ref={overlayRef}
            tabIndex={-1}
            onClick={(event) => event.stopPropagation()}
          >
            <div className="control-panel-header">
              <h2>Settings &amp; Sessions</h2>
              <button
                type="button"
                className="icon-button"
                onClick={closeSettings}
                aria-label="Close settings"
              >
                <span aria-hidden="true">×</span>
              </button>
            </div>
            <div className="control-panel-body">
              <TerminalCreator onCreate={handleCreate} busy={creating} />
              <TerminalList
                sessions={sessions}
                selectedId={selectedId}
                onSelect={selectSession}
                onRefresh={loadSessions}
              />
              <ConfigPanel />
              <SpawnOtpManager />
            </div>
          </div>
        </div>
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

  return { props: { collabEnabled: isCollabEnabled() } };
}
