export function getCopilotBindingSourceUuid(binding) {
  return binding?.sourceTerminalUuid
    || binding?.source_terminal_uuid
    || binding?.sourceTerminal?.terminal_uuid
    || binding?.terminal_uuid
    || '';
}

export const COPILOT_PANE_MODE_DOCKED = 'docked';
export const COPILOT_PANE_MODE_COLLAPSED = 'collapsed';
export const COPILOT_PANE_MODE_OPENING = 'opening';
export const COPILOT_PANE_MODE_POPOUT = 'popped-out';
export const COPILOT_WINDOW_MESSAGE_TYPE = 'notty:copilot-window';

const COPILOT_PANE_MODES = new Set([
  COPILOT_PANE_MODE_DOCKED,
  COPILOT_PANE_MODE_COLLAPSED,
  COPILOT_PANE_MODE_OPENING,
  COPILOT_PANE_MODE_POPOUT
]);

export function normalizeCopilotPaneMode(mode, { popupOpen = false } = {}) {
  if (!COPILOT_PANE_MODES.has(mode)) {
    return COPILOT_PANE_MODE_DOCKED;
  }
  if (
    (mode === COPILOT_PANE_MODE_OPENING || mode === COPILOT_PANE_MODE_POPOUT)
    && !popupOpen
  ) {
    return COPILOT_PANE_MODE_DOCKED;
  }
  return mode;
}

export function deriveCopilotPanePresentation(mode) {
  const normalizedMode = COPILOT_PANE_MODES.has(mode)
    ? mode
    : COPILOT_PANE_MODE_DOCKED;
  const docked = normalizedMode === COPILOT_PANE_MODE_DOCKED;

  return {
    mode: normalizedMode,
    paneVisible: docked,
    resizerVisible: docked,
    restoreControlVisible: !docked,
    popupOpen: normalizedMode === COPILOT_PANE_MODE_OPENING
      || normalizedMode === COPILOT_PANE_MODE_POPOUT,
    popupReady: normalizedMode === COPILOT_PANE_MODE_POPOUT
  };
}

function firstQueryValue(value) {
  return Array.isArray(value) ? value[0] : value;
}

export function getCopilotPopoutSource(query = {}) {
  const source = firstQueryValue(query?.source);
  return typeof source === 'string' ? source : '';
}

export function getCopilotPopoutInstance(query = {}) {
  const instanceId = firstQueryValue(query?.instance);
  return typeof instanceId === 'string' ? instanceId : '';
}

export function buildCopilotPopoutPath(session, { instanceId = '' } = {}) {
  const sourceTerminalUuid = session?.terminal_uuid;
  if (typeof sourceTerminalUuid !== 'string' || !sourceTerminalUuid) {
    return '';
  }

  const search = new URLSearchParams({ source: sourceTerminalUuid });
  if (instanceId) {
    search.set('instance', instanceId);
  }
  return `/copilot?${search.toString()}`;
}

export function resolveCopilotPopoutSession(sessions, sourceOrQuery) {
  const sourceTerminalUuid = typeof sourceOrQuery === 'string'
    ? sourceOrQuery
    : getCopilotPopoutSource(sourceOrQuery);
  if (!sourceTerminalUuid || !Array.isArray(sessions)) {
    return null;
  }

  return sessions.find((session) => (
    session?.terminal_uuid === sourceTerminalUuid
  )) || null;
}

export function createCopilotWindowMessage(action, payload = {}) {
  return {
    ...payload,
    type: COPILOT_WINDOW_MESSAGE_TYPE,
    action
  };
}

export function isCopilotWindowMessage(data, action = '') {
  return Boolean(
    data
    && typeof data === 'object'
    && data.type === COPILOT_WINDOW_MESSAGE_TYPE
    && typeof data.action === 'string'
    && (!action || data.action === action)
  );
}

export function deriveCopilotPaneViewState({
  session,
  copilots = [],
  expandedConfigurationBindingId = ''
} = {}) {
  const sourceTerminalUuid = session?.terminal_uuid || '';
  const binding = sourceTerminalUuid
    ? copilots.find((candidate) => (
      getCopilotBindingSourceUuid(candidate) === sourceTerminalUuid
    )) || null
    : null;
  const hasSession = Boolean(session);
  const configurationVisible = hasSession && (
    !binding || expandedConfigurationBindingId === binding.id
  );
  const agentTerminalExpanded = Boolean(binding && !configurationVisible);

  return {
    sourceTerminalUuid,
    binding,
    configurationVisible,
    agentTerminalExpanded
  };
}
