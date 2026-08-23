'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');

test('private command markers survive chunk boundaries and are stripped from output', async () => {
  const {
    createTerminalOutputParser,
    encodeTerminalCommandMarker,
  } = await import('../lib/terminalCommandProtocol.js');
  const nonce = 'session-nonce-a';
  const markers = [];
  const alternateStates = [];
  const parser = createTerminalOutputParser({
    markerNonce: nonce,
    onCommandMarker: (marker) => markers.push(marker),
    onAlternateScreen: (active) => alternateStates.push(active),
  });
  const marker = encodeTerminalCommandMarker({
    type: 'complete',
    commandId: 'bash-42-7',
    command: 'kubectl get pods --all-namespaces',
    cwd: '/tmp/work tree',
    exitCode: 1,
  }, { nonce });

  const chunks = [
    `before${marker.slice(0, 4)}`,
    marker.slice(4, 25),
    marker.slice(25, -1),
    `${marker.slice(-1)}after\x1b[?10`,
    '49hfull-screen',
    '\x1b[?1049lback',
  ];
  const visible = chunks.map((chunk) => parser.push(chunk)).join('');

  assert.equal(
    visible,
    'beforeafter\x1b[?1049hfull-screen\x1b[?1049lback',
  );
  assert.deepEqual(markers, [{
    version: 2,
    type: 'complete',
    commandId: 'bash-42-7',
    exitCode: 1,
    cwd: '/tmp/work tree',
    command: 'kubectl get pods --all-namespaces',
  }]);
  assert.deepEqual(alternateStates, [true, false]);
  assert.equal(parser.getState().alternateScreen, false);
  assert.equal(parser.getState().pendingMarkerBytes, 0);
});

test('command protocol accepts ST termination and flushes ordinary partial output', async () => {
  const {
    createTerminalOutputParser,
    encodeTerminalCommandMarker,
  } = await import('../lib/terminalCommandProtocol.js');
  const nonce = 'session-nonce-b';
  const markers = [];
  const parser = createTerminalOutputParser({
    markerNonce: nonce,
    onCommandMarker: (marker) => markers.push(marker),
  });

  const marker = encodeTerminalCommandMarker({
    type: 'start',
    commandId: 'zsh-1-1',
    command: 'echo hello',
    cwd: '/workspace',
  }, { terminator: 'st', nonce });
  assert.equal(parser.push(`${marker}tail\x1b]69`), 'tail');
  assert.equal(parser.flush(), '\x1b]69');
  assert.equal(markers.length, 1);
  assert.equal(markers[0].type, 'start');
  assert.equal(markers[0].exitCode, null);
});

test('wrong-nonce, legacy, and malformed private markers are stripped without callbacks', async () => {
  const {
    TERMINAL_COMMAND_OSC_PREFIX,
    createTerminalOutputParser,
    encodeTerminalCommandMarker,
  } = await import('../lib/terminalCommandProtocol.js');
  const nonce = 'trusted-session-nonce';
  const markers = [];
  const parser = createTerminalOutputParser({
    markerNonce: nonce,
    onCommandMarker: (marker) => markers.push(marker),
  });
  const forged = encodeTerminalCommandMarker({
    type: 'prompt',
    cwd: '/forged',
  }, { nonce: 'wrong-session-nonce' });
  const legacy = `${TERMINAL_COMMAND_OSC_PREFIX}1;prompt;;;2f;\x07`;
  const malformed = `${TERMINAL_COMMAND_OSC_PREFIX}2;${nonce};complete;cmd;;2f;6563686f\x07`;
  const overlong = `${TERMINAL_COMMAND_OSC_PREFIX}${'x'.repeat((64 * 1024) + 1)}\x07`;
  const trusted = encodeTerminalCommandMarker({
    type: 'complete',
    commandId: 'bash-7-1',
    exitCode: 0,
    cwd: '/trusted',
    command: 'true',
  }, { nonce });

  assert.equal(
    parser.push(`before${forged}${legacy}${malformed}${overlong}${trusted}after`),
    'beforeafter'
  );
  assert.deepEqual(markers, [{
    version: 2,
    type: 'complete',
    commandId: 'bash-7-1',
    exitCode: 0,
    cwd: '/trusted',
    command: 'true',
  }]);
});

test('state-mutating output parsers fail closed without a valid scoped nonce', async () => {
  const {
    createTerminalOutputParser,
    encodeTerminalCommandMarker,
  } = await import('../lib/terminalCommandProtocol.js');
  const marker = encodeTerminalCommandMarker({
    type: 'prompt',
    cwd: '/trusted',
  }, { nonce: 'valid-but-unscoped' });
  for (const markerNonce of [undefined, '', 'contains spaces']) {
    const markers = [];
    const parser = createTerminalOutputParser({
      markerNonce,
      onCommandMarker: (event) => markers.push(event),
    });
    assert.equal(parser.push(`before${marker}after`), 'beforeafter');
    assert.deepEqual(markers, []);
  }
});
