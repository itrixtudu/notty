'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');

test('Copilot pane collapses configuration for its running binding and restores it after Stop', async () => {
  const { deriveCopilotPaneViewState } = await import('../components/copilotPaneModel.js');
  const session = { id: 1, terminal_uuid: 'source-one' };
  const unrelated = { id: 'binding-other', sourceTerminalUuid: 'source-other' };
  const running = { id: 'binding-one', sourceTerminalUuid: 'source-one', status: 'running' };

  const ready = deriveCopilotPaneViewState({ session, copilots: [unrelated] });
  assert.equal(ready.binding, null);
  assert.equal(ready.configurationVisible, true);
  assert.equal(ready.agentTerminalExpanded, false);

  const active = deriveCopilotPaneViewState({ session, copilots: [unrelated, running] });
  assert.equal(active.binding, running);
  assert.equal(active.configurationVisible, false);
  assert.equal(active.agentTerminalExpanded, true);

  const manuallyExpanded = deriveCopilotPaneViewState({
    session,
    copilots: [unrelated, running],
    expandedConfigurationBindingId: running.id
  });
  assert.equal(manuallyExpanded.configurationVisible, true);
  assert.equal(manuallyExpanded.agentTerminalExpanded, false);

  const afterStop = deriveCopilotPaneViewState({
    session,
    copilots: [unrelated],
    expandedConfigurationBindingId: running.id
  });
  assert.equal(afterStop.binding, null);
  assert.equal(afterStop.configurationVisible, true);
  assert.equal(afterStop.agentTerminalExpanded, false);
});

test('Copilot pane presentation distinguishes docked, collapsed, and popped-out modes', async () => {
  const {
    COPILOT_PANE_MODE_COLLAPSED,
    COPILOT_PANE_MODE_DOCKED,
    COPILOT_PANE_MODE_OPENING,
    COPILOT_PANE_MODE_POPOUT,
    deriveCopilotPanePresentation,
    normalizeCopilotPaneMode
  } = await import('../components/copilotPaneModel.js');

  assert.deepEqual(deriveCopilotPanePresentation(COPILOT_PANE_MODE_DOCKED), {
    mode: COPILOT_PANE_MODE_DOCKED,
    paneVisible: true,
    resizerVisible: true,
    restoreControlVisible: false,
    popupOpen: false,
    popupReady: false
  });
  assert.deepEqual(deriveCopilotPanePresentation(COPILOT_PANE_MODE_COLLAPSED), {
    mode: COPILOT_PANE_MODE_COLLAPSED,
    paneVisible: false,
    resizerVisible: false,
    restoreControlVisible: true,
    popupOpen: false,
    popupReady: false
  });
  assert.deepEqual(deriveCopilotPanePresentation(COPILOT_PANE_MODE_OPENING), {
    mode: COPILOT_PANE_MODE_OPENING,
    paneVisible: false,
    resizerVisible: false,
    restoreControlVisible: true,
    popupOpen: true,
    popupReady: false
  });
  assert.deepEqual(deriveCopilotPanePresentation(COPILOT_PANE_MODE_POPOUT), {
    mode: COPILOT_PANE_MODE_POPOUT,
    paneVisible: false,
    resizerVisible: false,
    restoreControlVisible: true,
    popupOpen: true,
    popupReady: true
  });

  assert.equal(normalizeCopilotPaneMode('unknown'), COPILOT_PANE_MODE_DOCKED);
  assert.equal(normalizeCopilotPaneMode(COPILOT_PANE_MODE_COLLAPSED), COPILOT_PANE_MODE_COLLAPSED);
  assert.equal(normalizeCopilotPaneMode(COPILOT_PANE_MODE_OPENING), COPILOT_PANE_MODE_DOCKED);
  assert.equal(
    normalizeCopilotPaneMode(COPILOT_PANE_MODE_OPENING, { popupOpen: true }),
    COPILOT_PANE_MODE_OPENING
  );
  assert.equal(normalizeCopilotPaneMode(COPILOT_PANE_MODE_POPOUT), COPILOT_PANE_MODE_DOCKED);
  assert.equal(
    normalizeCopilotPaneMode(COPILOT_PANE_MODE_POPOUT, { popupOpen: true }),
    COPILOT_PANE_MODE_POPOUT
  );
});

test('Copilot popout path requires terminal_uuid and round-trips the exact source identity', async () => {
  const {
    buildCopilotPopoutPath,
    getCopilotPopoutInstance,
    getCopilotPopoutSource
  } = await import('../components/copilotPaneModel.js');
  const sourceTerminalUuid = 'source/one + two?\u2713';
  const instanceId = 'window/one + two';
  const path = buildCopilotPopoutPath(
    { id: 17, terminal_uuid: sourceTerminalUuid },
    { instanceId }
  );
  const parsed = new URL(path, 'https://notty.test');

  assert.equal(parsed.pathname, '/copilot');
  assert.equal(parsed.searchParams.get('source'), sourceTerminalUuid);
  assert.equal(parsed.searchParams.get('instance'), instanceId);
  assert.equal(getCopilotPopoutSource({ source: parsed.searchParams.get('source') }), sourceTerminalUuid);
  assert.equal(getCopilotPopoutSource({ source: [sourceTerminalUuid, 'source-other'] }), sourceTerminalUuid);
  assert.equal(getCopilotPopoutInstance({ instance: parsed.searchParams.get('instance') }), instanceId);
  assert.equal(getCopilotPopoutInstance({ instance: [instanceId, 'window-other'] }), instanceId);

  assert.equal(buildCopilotPopoutPath(), '');
  assert.equal(buildCopilotPopoutPath({ id: 17 }), '');
  assert.equal(buildCopilotPopoutPath({ id: 17, terminalUuid: sourceTerminalUuid }), '');
  assert.equal(buildCopilotPopoutPath({ id: 17, terminal_uuid: 17 }), '');
  assert.equal(getCopilotPopoutSource({}), '');
  assert.equal(getCopilotPopoutInstance({}), '');
});

test('Copilot popout session resolution uses only an exact terminal UUID', async () => {
  const { resolveCopilotPopoutSession } = await import('../components/copilotPaneModel.js');
  const first = { id: 17, terminal_uuid: 'source-one' };
  const second = { id: 18, terminal_uuid: 'source-two' };
  const sessions = [first, second];

  assert.equal(resolveCopilotPopoutSession(sessions, 'source-two'), second);
  assert.equal(resolveCopilotPopoutSession(sessions, { source: 'source-one' }), first);
  assert.equal(resolveCopilotPopoutSession(sessions, { source: ['source-two', 'source-one'] }), second);
  assert.equal(resolveCopilotPopoutSession(sessions, '17'), null);
  assert.equal(resolveCopilotPopoutSession(sessions, { source: 'missing-source' }), null);
  assert.equal(resolveCopilotPopoutSession(sessions, {}), null);
  assert.equal(resolveCopilotPopoutSession(null, 'source-one'), null);
});

test('Copilot window messages guard dock, ready, and selection actions', async () => {
  const {
    COPILOT_WINDOW_MESSAGE_TYPE,
    createCopilotWindowMessage,
    isCopilotWindowMessage
  } = await import('../components/copilotPaneModel.js');

  for (const action of ['dock', 'ready', 'selection']) {
    const message = createCopilotWindowMessage(action, {
      sourceTerminalUuid: 'source-one',
      selectedText: action === 'selection' ? 'selected output' : ''
    });

    assert.equal(message.type, COPILOT_WINDOW_MESSAGE_TYPE);
    assert.equal(message.action, action);
    assert.equal(message.sourceTerminalUuid, 'source-one');
    assert.equal(isCopilotWindowMessage(message), true);
    assert.equal(isCopilotWindowMessage(message, action), true);
    assert.equal(isCopilotWindowMessage(message, `${action}-other`), false);
  }

  assert.equal(isCopilotWindowMessage(null), false);
  assert.equal(isCopilotWindowMessage('ready'), false);
  assert.equal(isCopilotWindowMessage({ type: 'other-window', action: 'ready' }), false);
  assert.equal(isCopilotWindowMessage({ type: COPILOT_WINDOW_MESSAGE_TYPE }), false);
  assert.equal(isCopilotWindowMessage({
    type: COPILOT_WINDOW_MESSAGE_TYPE,
    action: 1
  }), false);
});
