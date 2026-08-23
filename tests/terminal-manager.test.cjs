'use strict';

const assert = require('node:assert/strict');
const { EventEmitter } = require('node:events');
const fs = require('node:fs');
const test = require('node:test');

async function waitFor(predicate, timeoutMs = 2000) {
  const deadline = Date.now() + timeoutMs;
  while (!predicate()) {
    if (Date.now() >= deadline) {
      return false;
    }
    await new Promise((resolve) => setTimeout(resolve, 20));
  }
  return true;
}

test('Zsh integration restores startup state and replays zshenv before zshrc', () => {
  const script = fs.readFileSync(
    `${__dirname}/../scripts/shell-integration/.zshrc`,
    'utf8',
  );
  const restoreZdotdir = script.indexOf('export ZDOTDIR="$_notty_original_zdotdir"');
  const clearPrivateEnvironment = script.indexOf('unset NOTTY_ORIGINAL_ZDOTDIR');
  const sourceZshenv = script.indexOf('source "$_notty_original_startup_dir/.zshenv"');
  const selectEffectiveZdotdir = script.indexOf('if (( ${+ZDOTDIR} )); then');
  const sourceZshrc = script.indexOf('source "$_notty_effective_zdotdir/.zshrc"');

  for (const offset of [
    restoreZdotdir,
    clearPrivateEnvironment,
    sourceZshenv,
    selectEffectiveZdotdir,
    sourceZshrc,
  ]) {
    assert.notEqual(offset, -1);
  }
  assert.ok(restoreZdotdir < clearPrivateEnvironment);
  assert.ok(clearPrivateEnvironment < sourceZshenv);
  assert.ok(sourceZshenv < selectEffectiveZdotdir);
  assert.ok(selectEffectiveZdotdir < sourceZshrc);
});

test('terminal dimensions use nullish defaults and reject non-positive values', async () => {
  const {
    getTerminalSummary,
    killTerminal,
    onTerminalExit,
    resizeTerminal,
    spawnTerminal,
  } = await import('../lib/terminalManager.js');

  assert.throws(
    () => spawnTerminal({ cols: 0, rows: 30 }),
    /cols and rows must be positive/,
  );
  assert.throws(
    () => spawnTerminal({ cols: 80, rows: -1 }),
    /cols and rows must be positive/,
  );
  assert.throws(
    () => spawnTerminal({ cols: 80.5, rows: 30 }),
    /cols and rows must be integers/,
  );

  const session = spawnTerminal({ shell: 'bash', cols: null, rows: undefined });
  assert.equal(session.cols, 80);
  assert.equal(session.rows, 30);

  assert.throws(
    () => resizeTerminal(session.id, 0, 24),
    /cols and rows must be positive/,
  );
  assert.deepEqual(
    { cols: getTerminalSummary(session.id).cols, rows: getTerminalSummary(session.id).rows },
    { cols: 80, rows: 30 },
  );

  const resized = resizeTerminal(session.id, 100, 40);
  assert.equal(resized.cols, 100);
  assert.equal(resized.rows, 40);

  await new Promise((resolve, reject) => {
    const timeout = setTimeout(() => reject(new Error('terminal did not exit')), 2000);
    onTerminalExit(session.id, () => {
      clearTimeout(timeout);
      resolve();
    });
    killTerminal(session.id);
  });
});

test('terminal input and heuristic command events preserve actor and binding isolation', async () => {
  const {
    getTerminalInteractionState,
    killTerminal,
    onTerminalExit,
    spawnTerminal,
    subscribeToTerminalCommand,
    subscribeToTerminalInput,
    writeToTerminal,
  } = await import('../lib/terminalManager.js');
  const session = spawnTerminal({
    shell: 'bash',
    shellIntegration: false,
    cols: 80,
    rows: 30,
  });
  const inputs = [];
  const commands = [];
  subscribeToTerminalInput(session.id, (event) => inputs.push(event));
  subscribeToTerminalCommand(session.terminal_uuid, (event) => commands.push(event));

  writeToTerminal(session.id, 'kubectl get pods', {
    actor: 'staged',
    bindingId: 'binding-a',
  });
  writeToTerminal(session.id, '\r', {
    actor: 'approved',
    bindingId: 'binding-a',
  });
  writeToTerminal(session.id, 'rm -rf typo', {
    actor: 'autonomous',
    bindingId: 'binding-b',
  });
  writeToTerminal(session.id, '\x03', {
    actor: 'autonomous',
    bindingId: 'binding-b',
  });

  assert.equal(inputs.length, 4);
  assert.deepEqual(
    inputs.map(({ actor, bindingId }) => ({ actor, bindingId })),
    [
      { actor: 'staged', bindingId: 'binding-a' },
      { actor: 'approved', bindingId: 'binding-a' },
      { actor: 'autonomous', bindingId: 'binding-b' },
      { actor: 'autonomous', bindingId: 'binding-b' },
    ],
  );
  assert.equal(commands.length, 2);
  assert.deepEqual(
    commands.map(({ command, phase, actor, bindingId, exact }) => ({
      command,
      phase,
      actor,
      bindingId,
      exact,
    })),
    [
      {
        command: 'kubectl get pods',
        phase: 'submitted',
        actor: 'approved',
        bindingId: 'binding-a',
        exact: false,
      },
      {
        command: 'rm -rf typo',
        phase: 'cancelled',
        actor: 'autonomous',
        bindingId: 'binding-b',
        exact: false,
      },
    ],
  );
  assert.deepEqual(
    getTerminalInteractionState(session.id).shellIntegration,
    {
      enabled: false,
      mode: 'heuristic',
      shell: 'bash',
      reason: 'custom-launch',
    },
  );

  // Let Bash process the submitted line and Ctrl+C before closing its PTY.
  await new Promise((resolve) => setTimeout(resolve, 100));

  await new Promise((resolve, reject) => {
    const timeout = setTimeout(() => reject(new Error('terminal did not exit')), 2000);
    onTerminalExit(session.id, () => {
      clearTimeout(timeout);
      resolve();
    });
    killTerminal(session.id);
  });
});

test('live Bash integration strips private markers and reports exact compound completions', async (t) => {
  const {
    getTerminalInteractionState,
    killTerminal,
    onTerminalExit,
    spawnTerminal,
    subscribeToTerminal,
    subscribeToTerminalCommand,
    writeToTerminal,
  } = await import('../lib/terminalManager.js');
  const session = spawnTerminal({ shell: 'bash', terminalType: 'xterm' });
  assert.doesNotMatch(JSON.stringify(session), /nonce/i);
  const output = [];
  const commands = [];
  subscribeToTerminal(session.id, (data) => output.push(data));
  subscribeToTerminalCommand(session.id, (event) => commands.push(event));
  let stopped = false;
  t.after(async () => {
    if (stopped) {
      return;
    }
    try {
      await new Promise((resolve) => {
        onTerminalExit(session.id, resolve);
        killTerminal(session.id);
      });
    } catch {
      // Best-effort cleanup after an assertion failure.
    }
  });

  assert.equal(
    await waitFor(() => getTerminalInteractionState(session.id).promptReady === true),
    true,
    'the authenticated initial prompt marker should arrive',
  );
  writeToTerminal(session.id, 'printf live-ok; false\r', {
    actor: 'human',
    bindingId: 'binding-live',
  });
  assert.equal(
    await waitFor(() => commands.some((event) => event.phase === 'completed')),
    true,
    'the exact completion marker should arrive',
  );
  const failure = commands.find((event) => event.phase === 'completed');
  assert.equal(failure.command, 'printf live-ok; false');
  assert.equal(failure.exitCode, 1);
  assert.equal(failure.exact, true);
  assert.equal(failure.actor, 'human');
  assert.equal(failure.bindingId, 'binding-live');

  writeToTerminal(session.id, 'if true; then\r', { actor: 'human' });
  writeToTerminal(session.id, 'echo compound-ok\r', { actor: 'human' });
  writeToTerminal(session.id, 'fi\r', { actor: 'human' });
  assert.equal(
    await waitFor(() => commands.filter((event) => event.phase === 'completed').length === 2),
    true,
    'the compound command should produce one exact completion',
  );
  const compound = commands.filter((event) => event.phase === 'completed').at(-1);
  assert.match(compound.command, /if true; then.*echo compound-ok.*fi/);
  assert.equal(compound.exitCode, 0);
  assert.equal(getTerminalInteractionState(session.id).pendingCommandCount, 0);
  assert.doesNotMatch(output.join(''), /6973;notty-command/);

  writeToTerminal(
    session.id,
    "if env | grep -Eq '^(NOTTY_SHELL_MARKER_NONCE|_notty_marker_nonce)='; then false; else true; fi\r",
    { actor: 'human' },
  );
  assert.equal(
    await waitFor(() => commands.filter((event) => event.phase === 'completed').length === 3),
    true,
    'the nonce inheritance check should complete',
  );
  assert.equal(commands.filter((event) => event.phase === 'completed').at(-1).exitCode, 0);

  writeToTerminal(session.id, 'set +o history\r', { actor: 'human' });
  assert.equal(
    await waitFor(() => commands.filter((event) => event.phase === 'completed').length === 4),
    true,
    'disabling Bash history should complete',
  );
  writeToTerminal(session.id, 'if true; then\r', { actor: 'human' });
  writeToTerminal(session.id, 'echo no-history-compound\r', { actor: 'human' });
  writeToTerminal(session.id, 'fi\r', { actor: 'human' });
  assert.equal(
    await waitFor(() => commands.filter((event) => event.phase === 'completed').length === 5),
    true,
    'a commandless exact marker should reconcile the full pending compound command',
  );
  const noHistoryCompound = commands.filter((event) => event.phase === 'completed').at(-1);
  assert.equal(noHistoryCompound.command, null);
  assert.equal(noHistoryCompound.exact, true);
  assert.equal(noHistoryCompound.exitCode, 0);
  assert.equal(getTerminalInteractionState(session.id).pendingCommandCount, 0);

  await new Promise((resolve) => {
    onTerminalExit(session.id, resolve);
    killTerminal(session.id);
  });
  stopped = true;
});

test('heuristic shells recover completion feedback without authorizing terminal control', async (t) => {
  const {
    getTerminalInteractionState,
    killTerminal,
    onTerminalExit,
    spawnTerminal,
    subscribeToTerminalCommand,
    writeToTerminal,
  } = await import('../lib/terminalManager.js');
  const session = spawnTerminal({
    shell: 'bash',
    args: ['--norc'],
    terminalType: 'xterm',
  }, { env: { PS1: 'nosh ❯ ' } });
  const commands = [];
  subscribeToTerminalCommand(session.id, (event) => commands.push(event));
  let stopped = false;
  t.after(async () => {
    if (stopped) {
      return;
    }
    try {
      await new Promise((resolve) => {
        onTerminalExit(session.id, resolve);
        killTerminal(session.id);
      });
    } catch {
      // Best-effort cleanup after an assertion failure.
    }
  });

  await new Promise((resolve) => setTimeout(resolve, 250));
  assert.equal(getTerminalInteractionState(session.id).promptReady, null);
  writeToTerminal(session.id, 'definitely-not-a-notty-command\r', { actor: 'human' });
  assert.equal(
    await waitFor(() => commands.some((event) => event.phase === 'completed')),
    true,
    'the heuristic prompt should close the submitted command',
  );
  const completion = commands.find((event) => event.phase === 'completed');
  assert.equal(completion.exact, false);
  assert.equal(completion.detection, 'heuristic-prompt');
  assert.equal(completion.exitCode, null);
  assert.equal(completion.likelyFailed, true);
  assert.equal(completion.actor, 'human');
  assert.equal(getTerminalInteractionState(session.id).pendingCommandCount, 0);
  assert.equal(
    getTerminalInteractionState(session.id).promptReady,
    null,
    'heuristic recognition must remain unsafe for Insert and Autonomous control',
  );

  await new Promise((resolve) => {
    onTerminalExit(session.id, resolve);
    killTerminal(session.id);
  });
  stopped = true;
});

test('retained legacy sessions hydrate interaction state before writing', async (t) => {
  const {
    getTerminalInteractionState,
    subscribeToTerminalInput,
    writeToTerminal,
  } = await import('../lib/terminalManager.js');
  const state = globalThis.__terminalManagerState;
  const id = 987654321;
  const terminalUuid = 'legacy-terminal-for-interaction-test';
  const writes = [];
  const legacy = {
    id,
    terminalUuid,
    shell: 'fish',
    cols: 80,
    rows: 30,
    cwd: process.cwd(),
    terminalType: 'xterm',
    metadata: null,
    proc: {
      killed: false,
      write: (data) => writes.push(data),
    },
    buffer: '',
    readPointers: new Map(),
    nextReaderId: 1,
    emitter: new EventEmitter(),
    createdAt: new Date().toISOString(),
  };
  state.sessions.set(id, legacy);
  state.uuidIndex.set(terminalUuid, legacy);
  t.after(() => {
    legacy.emitter.emit('exit', { exitCode: 0 });
    legacy.emitter.removeAllListeners();
    state.sessions.delete(id);
    state.uuidIndex.delete(terminalUuid);
  });
  const actors = [];
  subscribeToTerminalInput(terminalUuid, (event) => actors.push(event.actor));

  assert.equal(writeToTerminal(terminalUuid, 'echo hydrated\r', { actor: 'api' }), 14);
  assert.deepEqual(writes, ['echo hydrated\r']);
  assert.deepEqual(actors, ['api']);
  assert.equal(getTerminalInteractionState(terminalUuid).shellIntegration.reason, 'legacy-session');
});
