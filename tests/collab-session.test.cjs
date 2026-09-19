'use strict';

const assert = require('node:assert/strict');
const childProcess = require('node:child_process');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const test = require('node:test');

const {
  CODEX_PERMISSION_MODES,
  COLLAB_SESSION_MCP_SERVER,
  QUICK_COMMAND_TIMEOUT_MS,
  codexArgsWithPermissionMode,
  codexPermissionModeFromArgs,
  commandExists,
  createLayoutSnapshot,
  createSessionManager,
  defaultAgySafetyArgs,
  defaultClaudeSafetyArgs,
  defaultCodexPermissionMode,
  defaultCodexSafetyArgs,
  killTmuxSession,
  launchTmuxAgent,
  newPaneOutput,
  normalizeCodexPermissionMode,
  normalizeAgentThink,
  resolveAgentTmuxState,
  resolveLaunchRoster,
  resolveSessionOperator,
  selectCodexThreadId,
  setTmuxSessionOwner,
  tmuxSessionExists,
  tmuxSessionOwnedBy,
  validateNoshProfiles,
} = require('../lib/collab/session.cjs');

test('pane health scans classify only output added after the previous snapshot', () => {
  const previous = 'ready\nHTTP 429 rate limited\nwaiting';
  assert.equal(
    newPaneOutput(previous, `${previous}\ncommand completed`),
    '\ncommand completed',
  );
  assert.equal(
    newPaneOutput(previous, 'HTTP 429 rate limited\nwaiting\ncommand completed'),
    'command completed',
  );
});

function writeManifest(filePath, value) {
  fs.writeFileSync(filePath, `${JSON.stringify(value, null, 2)}\n`, 'utf8');
}

function runtimeAgent(overrides = {}) {
  return {
    id: 'coder',
    identity: 'coder',
    tmuxTarget: 'collab-test-coder',
    status: 'running',
    tmuxPresent: true,
    tmuxOwned: true,
    tmuxAlive: true,
    ownershipLost: false,
    registered: false,
    mcpStatus: 'unregistered',
    permissionMode: CODEX_PERMISSION_MODES.SANDBOXED,
    runtimeSessionId: '',
    pending: { directCount: 0, channels: [], updatedAt: '' },
    error: '',
    ...overrides,
  };
}

test('quick command probes and tmux ownership operations have bounded runtimes', (t) => {
  const originalSpawnSync = childProcess.spawnSync;
  const calls = [];
  childProcess.spawnSync = (command, args, options) => {
    calls.push({ command, args, options });
    return { status: 0, stdout: 'session-test\n', stderr: '' };
  };
  t.after(() => {
    childProcess.spawnSync = originalSpawnSync;
  });

  assert.equal(commandExists('codex').ok, true);
  assert.equal(tmuxSessionExists('agent-test'), true);
  setTmuxSessionOwner('agent-test', 'session-test');
  assert.equal(tmuxSessionOwnedBy('agent-test', 'session-test'), true);
  assert.equal(killTmuxSession('agent-test').status, 0);

  assert.equal(calls.length, 5);
  for (const call of calls) {
    assert.equal(call.options.timeout, QUICK_COMMAND_TIMEOUT_MS);
  }
});

test('agent launch does not apply the probe timeout to the detached launch command', (t) => {
  const originalSpawnSync = childProcess.spawnSync;
  const calls = [];
  childProcess.spawnSync = (command, args, options) => {
    calls.push({ command, args, options });
    return { status: 0, stdout: '', stderr: '' };
  };
  t.after(() => {
    childProcess.spawnSync = originalSpawnSync;
  });

  launchTmuxAgent({
    identity: 'coder',
    role: 'coder',
    prompt: 'coder',
    model: 'gpt-5',
    tmuxTarget: 'collab-test-coder',
  }, {
    channel: 'lobby',
    environment: {},
    mcpUrl: 'http://127.0.0.1:1337/mcp',
    prompts: { coder: { instructions: 'Implement the task.' } },
    sessionId: 'session-test',
    workspaceRoot: '/workspace',
  });

  assert.equal(calls[0].args[0], 'new-session');
  assert.equal(Object.hasOwn(calls[0].options, 'timeout'), false);
  assert.ok(calls[0].args.includes(`COLLAB_MCP_SERVER=${COLLAB_SESSION_MCP_SERVER}`));
  assert.ok(calls[0].args.includes(
    `mcp_servers.${COLLAB_SESSION_MCP_SERVER}.url="http://127.0.0.1:1337/mcp"`,
  ));
  assert.equal(calls[0].args.some((arg) => arg.startsWith('mcp_servers.collab.url=')), false);
  assert.deepEqual(defaultCodexSafetyArgs({}), [
    '--sandbox',
    'workspace-write',
    '--ask-for-approval',
    'on-request',
  ]);
  assert.deepEqual(defaultCodexSafetyArgs({ NOTTY_COLLAB_UNSANDBOXED: 'true' }), [
    '--dangerously-bypass-approvals-and-sandbox',
  ]);
  assert.equal(calls[0].args.includes('--full-auto'), false);
  assert.ok(calls[0].args.includes('--sandbox'));
  assert.ok(calls[0].args.includes('workspace-write'));
  assert.ok(calls[0].args.includes('--ask-for-approval'));
  assert.ok(calls[0].args.includes('on-request'));
  assert.equal(calls[1].options.timeout, QUICK_COMMAND_TIMEOUT_MS);
  assert.equal(calls[2].options.timeout, QUICK_COMMAND_TIMEOUT_MS);
});

test('Codex permission defaults use full access only for containers or an explicit opt-in', () => {
  assert.equal(
    defaultCodexPermissionMode({}),
    CODEX_PERMISSION_MODES.SANDBOXED,
  );
  assert.equal(
    defaultCodexPermissionMode({ DOCKER_CONTAINER: '1' }),
    CODEX_PERMISSION_MODES.BYPASS,
  );
  assert.equal(
    defaultCodexPermissionMode({
      DOCKER_CONTAINER: '1',
      NOTTY_COLLAB_UNSANDBOXED: 'false',
    }),
    CODEX_PERMISSION_MODES.SANDBOXED,
  );
  assert.equal(
    defaultCodexPermissionMode({ NOTTY_COLLAB_UNSANDBOXED: 'true' }),
    CODEX_PERMISSION_MODES.BYPASS,
  );
  assert.deepEqual(defaultCodexSafetyArgs({ DOCKER_CONTAINER: '1' }), [
    '--dangerously-bypass-approvals-and-sandbox',
  ]);
  assert.deepEqual(defaultCodexSafetyArgs({
    DOCKER_CONTAINER: '1',
    NOTTY_COLLAB_UNSANDBOXED: 'false',
  }), [
    '--sandbox',
    'workspace-write',
    '--ask-for-approval',
    'on-request',
  ]);
});

test('Codex permission-mode argv replacement is normalized and mutually exclusive', () => {
  assert.equal(
    normalizeCodexPermissionMode('sandboxed'),
    CODEX_PERMISSION_MODES.SANDBOXED,
  );
  assert.equal(
    normalizeCodexPermissionMode('full-access'),
    CODEX_PERMISSION_MODES.BYPASS,
  );
  assert.throws(
    () => normalizeCodexPermissionMode('host-write'),
    /unsupported Codex permission mode/i,
  );

  const bypassArgs = codexArgsWithPermissionMode([
    '-c', 'model_reasoning_effort="high"',
    '--sandbox', 'workspace-write',
    '--ask-for-approval', 'on-request',
  ], CODEX_PERMISSION_MODES.BYPASS);
  assert.deepEqual(bypassArgs, [
    '-c', 'model_reasoning_effort="high"',
    '--dangerously-bypass-approvals-and-sandbox',
  ]);
  assert.equal(
    codexPermissionModeFromArgs(bypassArgs),
    CODEX_PERMISSION_MODES.BYPASS,
  );

  const sandboxedArgs = codexArgsWithPermissionMode([
    '-c', 'model_reasoning_effort="high"',
    '--yolo',
  ], CODEX_PERMISSION_MODES.SANDBOXED);
  assert.deepEqual(sandboxedArgs, [
    '-c', 'model_reasoning_effort="high"',
    '--sandbox', 'workspace-write',
    '--ask-for-approval', 'on-request',
  ]);
  assert.equal(
    codexPermissionModeFromArgs(sandboxedArgs),
    CODEX_PERMISSION_MODES.SANDBOXED,
  );
});

test('Codex thread selection requires an exact prompt and workspace match', () => {
  const cwd = path.resolve('/workspace/project');
  const prompt = 'Exact initial collaboration prompt';
  const threads = [
    {
      id: 'wrong-workspace',
      cwd: path.resolve('/workspace/other'),
      preview: prompt,
      updatedAt: 500,
    },
    {
      id: 'prompt-prefix-only',
      cwd,
      preview: `${prompt}\nAdditional text`,
      updatedAt: 600,
    },
    {
      id: 'older-exact',
      cwd,
      preview: prompt,
      updatedAt: 100,
    },
    {
      id: 'newer-exact',
      cwd: path.join(cwd, '.'),
      preview: prompt,
      updatedAt: 200,
    },
    {
      id: 123,
      cwd,
      preview: prompt,
      updatedAt: 700,
    },
  ];

  assert.equal(
    selectCodexThreadId(threads, { cwd, prompt }),
    'newer-exact',
  );
  assert.equal(
    selectCodexThreadId(threads, { cwd, prompt: `${prompt} ` }),
    '',
  );
});

test('Codex resume launch places permission flags before resume and the thread id', (t) => {
  const originalSpawnSync = childProcess.spawnSync;
  const calls = [];
  childProcess.spawnSync = (command, args, options) => {
    calls.push({ command, args, options });
    return { status: 0, stdout: '', stderr: '' };
  };
  t.after(() => {
    childProcess.spawnSync = originalSpawnSync;
  });

  const codexBin = '/opt/codex';
  const mcpUrl = 'http://127.0.0.1:1337/mcp';
  const threadId = '019f0000-0000-7000-8000-000000000001';
  launchTmuxAgent({
    identity: 'coder',
    role: 'coder',
    runtime: 'codex',
    prompt: 'coder',
    model: 'gpt-5.4',
    think: 'high',
    tmuxTarget: 'collab-test-coder',
  }, {
    channel: 'lobby',
    codexBin,
    codexArgs: ['--dangerously-bypass-approvals-and-sandbox'],
    environment: {},
    mcpUrl,
    prompts: { coder: { instructions: 'Implement the task.' } },
    resumeSessionId: threadId,
    sessionId: 'session-test',
    workspaceRoot: '/workspace',
  });

  const launchArgs = calls[0].args;
  const codexIndex = launchArgs.indexOf(codexBin);
  assert.notEqual(codexIndex, -1);
  assert.deepEqual(launchArgs.slice(codexIndex), [
    codexBin,
    '-m', 'gpt-5.4',
    '-c', `mcp_servers.${COLLAB_SESSION_MCP_SERVER}.url=${JSON.stringify(mcpUrl)}`,
    '-c', 'model_reasoning_effort="high"',
    '--dangerously-bypass-approvals-and-sandbox',
    'resume', threadId,
  ]);
  assert.equal(launchArgs.includes('--sandbox'), false);
  assert.equal(launchArgs.some((arg) => /Implement the task\./.test(arg)), false);
});

test('Agy launch preserves a spaced model and uses its SSE-safe argv and environment', (t) => {
  const originalSpawnSync = childProcess.spawnSync;
  const calls = [];
  childProcess.spawnSync = (command, args, options) => {
    calls.push({ command, args, options });
    return { status: 0, stdout: '', stderr: '' };
  };
  t.after(() => {
    childProcess.spawnSync = originalSpawnSync;
  });

  const model = 'Claude Opus 4.6 (Thinking)';
  const sseUrl = 'http://127.0.0.1:1337/sse';
  launchTmuxAgent({
    identity: 'agy-coder',
    role: 'coder',
    runtime: 'agy',
    prompt: 'coder',
    model,
    think: 'high',
    tmuxTarget: 'collab-test-agy-coder',
  }, {
    agyBin: '/opt/agy/bin/agy',
    channel: 'lobby',
    environment: {},
    mcpUrl: sseUrl,
    prompts: { coder: { instructions: 'Implement the task.' } },
    sessionId: 'session-test',
    workspaceRoot: '/workspace',
  });

  const launchArgs = calls[0].args;
  assert.equal(calls[0].command, 'tmux');
  assert.equal(launchArgs[0], 'new-session');
  assert.ok(launchArgs.includes('COLLAB_RUNTIME=agy'));
  assert.ok(launchArgs.includes(`COLLAB_MODEL=${model}`));
  assert.ok(launchArgs.includes('COLLAB_THINK=high'));
  assert.ok(launchArgs.includes(`COLLAB_MCP_URL=${sseUrl}`));

  const agyIndex = launchArgs.indexOf('/opt/agy/bin/agy');
  assert.notEqual(agyIndex, -1);
  const agyArgs = launchArgs.slice(agyIndex + 1);
  assert.equal(agyArgs[agyArgs.indexOf('--model') + 1], model);
  assert.equal(agyArgs.filter((arg) => arg === model).length, 1);
  assert.equal(agyArgs[agyArgs.indexOf('--effort') + 1], 'high');
  assert.deepEqual(defaultAgySafetyArgs({}), ['--mode', 'accept-edits', '--sandbox']);
  assert.ok(agyArgs.includes('--mode'));
  assert.ok(agyArgs.includes('accept-edits'));
  assert.ok(agyArgs.includes('--sandbox'));
  assert.ok(agyArgs.includes('--prompt-interactive'));
  assert.match(agyArgs[agyArgs.indexOf('--prompt-interactive') + 1], /http:\/\/127\.0\.0\.1:1337\/sse/);
  assert.equal(agyArgs.includes('-c'), false);
  assert.equal(agyArgs.some((arg) => arg.startsWith('mcp_servers.')), false);
  assert.equal(calls[1].options.timeout, QUICK_COMMAND_TIMEOUT_MS);
  assert.equal(calls[2].options.timeout, QUICK_COMMAND_TIMEOUT_MS);
});

test('Claude launch uses the hosted agent with process-scoped MCP and effort settings', (t) => {
  const originalSpawnSync = childProcess.spawnSync;
  const calls = [];
  childProcess.spawnSync = (command, args, options) => {
    calls.push({ command, args, options });
    return { status: 0, stdout: '', stderr: '' };
  };
  t.after(() => {
    childProcess.spawnSync = originalSpawnSync;
  });

  const mcpUrl = 'http://127.0.0.1:1337/mcp';
  const sessionId = '019f0000-0000-7000-8000-000000000099';
  launchTmuxAgent({
    identity: 'bofh',
    role: 'bofh',
    prompt: 'bofh',
    harness: 'claude',
    backend: 'default',
    model: 'sonnet',
    think: 'low',
    tmuxTarget: 'collab-test-bofh',
  }, {
    channel: 'lobby',
    claudeBin: '/opt/claude',
    environment: {},
    mcpUrl,
    newSessionId: sessionId,
    prompts: { bofh: { instructions: 'Challenge fragile assumptions.' } },
    sessionId: 'session-test',
    workspaceRoot: '/workspace',
  });

  const launchArgs = calls[0].args;
  assert.ok(launchArgs.includes('COLLAB_HARNESS=claude'));
  assert.ok(launchArgs.includes('COLLAB_BACKEND=default'));
  assert.ok(launchArgs.includes('COLLAB_RUNTIME=claude'));
  const claudeIndex = launchArgs.indexOf('/opt/claude');
  assert.notEqual(claudeIndex, -1);
  const claudeArgs = launchArgs.slice(claudeIndex);
  assert.deepEqual(claudeArgs.slice(0, 5), [
    '/opt/claude', '--model', 'sonnet', '--effort', 'low',
  ]);
  const mcpConfig = JSON.parse(claudeArgs[claudeArgs.indexOf('--mcp-config') + 1]);
  assert.equal(mcpConfig.mcpServers[COLLAB_SESSION_MCP_SERVER].type, 'http');
  assert.equal(mcpConfig.mcpServers[COLLAB_SESSION_MCP_SERVER].url, mcpUrl);
  assert.deepEqual(defaultClaudeSafetyArgs({}), ['--permission-mode', 'acceptEdits']);
  assert.deepEqual(
    defaultClaudeSafetyArgs({ NOTTY_COLLAB_UNSANDBOXED: 'true' }),
    ['--dangerously-skip-permissions'],
  );
  assert.equal(claudeArgs[claudeArgs.indexOf('--session-id') + 1], sessionId);
  assert.match(claudeArgs.at(-1), /Challenge fragile assumptions/);
});

test('only Codex can use the Ollama model runtime', (t) => {
  const originalSpawnSync = childProcess.spawnSync;
  const calls = [];
  childProcess.spawnSync = (...args) => {
    calls.push(args);
    return { status: 0, stdout: '', stderr: '' };
  };
  t.after(() => {
    childProcess.spawnSync = originalSpawnSync;
  });

  for (const harness of ['agy', 'claude']) {
    assert.throws(
      () => launchTmuxAgent({
        identity: `bad-local-${harness}`,
        role: 'test',
        prompt: 'test',
        harness,
        backend: 'ollama',
        model: 'qwen3:4b',
        think: 'low',
        tmuxTarget: `collab-test-bad-local-${harness}`,
      }, {
        channel: 'lobby',
        mcpUrl: 'http://127.0.0.1:1337/mcp',
        prompts: { test: { instructions: 'test' } },
        sessionId: 'session-test',
        workspaceRoot: '/workspace',
      }),
      new RegExp(`${harness} does not support the Ollama model runtime`, 'i'),
    );
  }
  assert.deepEqual(calls, [], 'invalid agent/backend pairs must fail before tmux launch');
});

test('Ollama launch invokes Codex directly with its provider, reasoning, MCP, and safety args', (t) => {
  const originalSpawnSync = childProcess.spawnSync;
  const calls = [];
  childProcess.spawnSync = (command, args, options) => {
    calls.push({ command, args, options });
    return { status: 0, stdout: '', stderr: '' };
  };
  t.after(() => {
    childProcess.spawnSync = originalSpawnSync;
  });

  const model = 'ornith:9b';
  const mcpUrl = 'http://127.0.0.1:1337/mcp';
  const codexBin = '/opt/codex/bin/codex';
  const providerId = 'notty_ollama_0123456789abcdef0123456789abcdef';
  const providerArgs = [
    '-m', model,
    '-c', `model_provider=${JSON.stringify(providerId)}`,
    '-c', `model_providers.${providerId}.base_url="http://host.docker.internal:11434/v1"`,
    '-c', `model_providers.${providerId}.wire_api="responses"`,
    '-c', `model_providers.${providerId}.requires_openai_auth=false`,
    '-c', 'model_catalog_json="/run/user/1000/notty-ollama/catalog.json"',
  ];
  launchTmuxAgent({
    identity: 'ollama-coder',
    role: 'coder',
    runtime: 'ollama',
    prompt: 'coder',
    model,
    think: ' HIGH ',
    tmuxTarget: 'collab-test-ollama-coder',
  }, {
    channel: 'lobby',
    codexBin,
    environment: {},
    mcpUrl,
    ollamaProvider: { args: providerArgs },
    prompts: { coder: { instructions: 'Implement the task.' } },
    sessionId: 'session-test',
    workspaceRoot: '/workspace',
  });

  const launchArgs = calls[0].args;
  assert.equal(calls[0].command, 'tmux');
  assert.equal(launchArgs[0], 'new-session');
  assert.ok(launchArgs.includes('COLLAB_RUNTIME=ollama'));
  assert.ok(launchArgs.includes(`COLLAB_MODEL=${model}`));
  assert.ok(launchArgs.includes('COLLAB_THINK=high'));
  assert.ok(launchArgs.includes(`COLLAB_MCP_URL=${mcpUrl}`));
  assert.equal(launchArgs.some((value) => value.startsWith('MCP_SPAWN_OTP=')), false);
  assert.deepEqual(
    launchArgs.slice(launchArgs.indexOf('env') + 1, launchArgs.indexOf('MYID=ollama-coder')),
    ['-i'],
  );
  assert.doesNotMatch(launchArgs.at(-1), /spawn OTP|MCP_SPAWN_OTP/i);

  const codexIndex = launchArgs.indexOf(codexBin);
  assert.notEqual(codexIndex, -1);
  const runtimeArgs = launchArgs.slice(codexIndex);
  assert.deepEqual(runtimeArgs.slice(0, providerArgs.length + 1), [codexBin, ...providerArgs]);
  assert.equal(runtimeArgs.includes('--oss'), false);
  assert.equal(runtimeArgs.includes('launch'), false);

  const processMcpOverride = `mcp_servers.${COLLAB_SESSION_MCP_SERVER}.url=${JSON.stringify(mcpUrl)}`;
  const codexTail = runtimeArgs.slice(providerArgs.length + 1);
  assert.deepEqual(codexTail.slice(0, 4), [
    '-c', processMcpOverride,
    '-c', 'model_reasoning_effort="high"',
  ]);
  assert.deepEqual(codexTail.slice(4, 8), [
    '--sandbox',
    'workspace-write',
    '--ask-for-approval',
    'on-request',
  ]);
  assert.match(codexTail[8], /Implement the task\./);
  assert.match(codexTail[8], /http:\/\/127\.0\.0\.1:1337\/mcp/);
  assert.doesNotMatch(codexTail[8], /spawn OTP|MCP_SPAWN_OTP/i);
  assert.equal(codexTail.length, 9);
  assert.equal(calls[1].options.timeout, QUICK_COMMAND_TIMEOUT_MS);
  assert.equal(calls[2].options.timeout, QUICK_COMMAND_TIMEOUT_MS);
});

test('Ollama launch rolls back only when tmux never starts the relay', (t) => {
  const originalSpawnSync = childProcess.spawnSync;
  let targetPresent = false;
  childProcess.spawnSync = (command, args) => {
    if (command === 'tmux' && args[0] === 'has-session') {
      return { status: targetPresent ? 0 : 1, stdout: '', stderr: '' };
    }
    if (command === 'tmux' && args[0] === 'new-session') {
      return { status: 1, stdout: '', stderr: 'forced launch failure' };
    }
    return { status: 0, stdout: '', stderr: '' };
  };
  t.after(() => {
    childProcess.spawnSync = originalSpawnSync;
  });

  const catalogPath = '/run/user/1000/notty-ollama/catalog-aaaaaaaaaaaaaaaaaaaaaaaa-bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb.json';
  const removed = [];
  const launch = () => launchTmuxAgent({
    identity: 'ollama-coder',
    role: 'coder',
    runtime: 'ollama',
    prompt: 'coder',
    model: 'qwen3:4b',
    tmuxTarget: 'collab-test-ollama-rollback',
  }, {
    channel: 'lobby',
    codexBin: '/opt/codex',
    environment: {},
    mcpUrl: 'http://127.0.0.1:1337/mcp',
    ollamaProvider: {
      catalogPath,
      args: ['-m', 'qwen3:4b', '-c', `model_catalog_json=${JSON.stringify(catalogPath)}`],
    },
    ollamaRuntimeDir: '/run/user/1000',
    prompts: { coder: { instructions: 'Implement the task.' } },
    removeOllamaModelCatalog: (value, options) => removed.push({ value, options }),
    sessionId: 'session-test',
    workspaceRoot: '/workspace',
  });

  assert.throws(launch, /forced launch failure/i);
  assert.deepEqual(removed, [{
    value: catalogPath,
    options: { runtimeDir: '/run/user/1000', environment: {} },
  }]);

  removed.length = 0;
  targetPresent = true;
  assert.throws(
    launch,
    (error) => error.ollamaCatalogPath === catalogPath && /forced launch failure/i.test(error.message),
  );
  assert.deepEqual(removed, [], 'an occupied or ambiguous tmux target must preserve the catalog');
});

test('Ollama launch requires a model before invoking tmux', () => {
  assert.throws(
    () => launchTmuxAgent({
      identity: 'ollama-coder',
      role: 'coder',
      runtime: 'ollama',
      prompt: 'coder',
      model: '',
      tmuxTarget: 'collab-test-ollama-coder',
    }, {
      channel: 'lobby',
      environment: {},
      mcpUrl: 'http://127.0.0.1:1337/mcp',
      prompts: { coder: { instructions: 'Implement the task.' } },
      sessionId: 'session-test',
      workspaceRoot: '/workspace',
    }),
    /ollama.*require.*model/i,
  );
});

test('exported Ollama think normalization accepts canonical levels and boolean aliases', {
  skip: typeof normalizeAgentThink === 'function'
    ? false
    : 'normalizeAgentThink is not exported',
}, () => {
  for (const level of ['none', 'low', 'medium', 'high', 'max']) {
    assert.equal(normalizeAgentThink(level, 'ollama'), level);
    assert.equal(normalizeAgentThink(` ${level.toUpperCase()} `, 'ollama'), level);
  }
  assert.equal(normalizeAgentThink(true, 'ollama'), 'high');
  assert.equal(normalizeAgentThink('true', 'ollama'), 'high');
  assert.equal(normalizeAgentThink(false, 'ollama'), 'none');
  assert.equal(normalizeAgentThink('false', 'ollama'), 'none');
  assert.throws(() => normalizeAgentThink('xhigh', 'ollama'), /think|reasoning/i);
});

test('Think normalization follows each agent and model runtime capability', () => {
  for (const level of ['none', 'minimal', 'low', 'medium', 'high', 'xhigh', 'max', 'ultra']) {
    assert.equal(normalizeAgentThink(level, 'codex'), level);
  }
  assert.equal(normalizeAgentThink(true, 'codex'), 'high');
  assert.equal(normalizeAgentThink(false, 'codex'), 'none');
  for (const level of ['low', 'medium', 'high']) {
    assert.equal(normalizeAgentThink(level, 'agy'), level);
  }
  assert.throws(() => normalizeAgentThink('max', 'agy'), /unsupported Think level/i);
  for (const level of ['low', 'medium', 'high', 'xhigh', 'max']) {
    assert.equal(normalizeAgentThink(level, 'claude'), level);
  }
});

test('Ollama session preflight checks HTTP model availability and the Codex binary', (t) => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'notty-collab-ollama-preflight-'));
  const workspaceRoot = path.join(root, 'workspace');
  const manifestPath = path.join(root, 'session.json');
  fs.mkdirSync(workspaceRoot, { recursive: true });
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));

  const originalSpawnSync = childProcess.spawnSync;
  const calls = [];
  let ollamaAvailable = false;
  let codexAvailable = false;
  childProcess.spawnSync = (command, args, options) => {
    calls.push({ command, args, options });
    if (command === '/opt/curl') {
      if (!ollamaAvailable) {
        return { status: 7, stdout: '', stderr: 'unable to connect to Ollama' };
      }
      if (args.at(-1).endsWith('/api/tags')) {
        return {
          status: 0,
          stdout: JSON.stringify({ models: [{ name: 'ornith:9b' }] }),
          stderr: '',
        };
      }
      return {
        status: 0,
        stdout: JSON.stringify({
          capabilities: ['completion', 'tools'],
          model_info: { 'ornith.context_length': 32_768 },
        }),
        stderr: '',
      };
    }
    if (command === '/opt/codex') {
      return codexAvailable
        ? { status: 0, stdout: 'codex-cli 0.151.0\n', stderr: '' }
        : { status: 1, stdout: '', stderr: 'codex unavailable' };
    }
    return { status: 0, stdout: '', stderr: '' };
  };
  t.after(() => {
    childProcess.spawnSync = originalSpawnSync;
  });

  const configStore = {
    load: () => ({
      resolved: {
        defaultTemplate: 'ollama',
        layouts: { grid: { label: 'Grid', mode: 'grid' } },
        prompts: {
          coder: {
            identity: 'coder',
            role: 'coder',
            label: 'Coder',
            instructions: 'Implement the task.',
          },
        },
        templates: {
          ollama: {
            label: 'Ollama',
            layout: 'grid',
            channel: 'lobby',
            defaultCoordinatorMode: 'human',
            requiredNoshProfiles: [],
            agents: ['coder_ollama_ornith:9b'],
          },
        },
      },
    }),
  };
  const createManager = () => createSessionManager({
    codexBin: '/opt/codex',
    curlBin: '/opt/curl',
    environment: {
      PATH: '/safe/bin',
      SAFE_PREFLIGHT_VALUE: 'preserved',
      NOTTY_MCP_SPAWN_OTP: 'spawn-canary',
      NOTTY_BASIC_AUTH_PASSWORD: 'basic-canary',
      NOTTY_OAUTH_ACCESS_TOKEN: 'oauth-canary',
      AUTHORIZATION: 'Bearer header-canary',
    },
    ollamaEndpoint: '127.0.0.1:11434',
    workspaceRoot,
    manifestPath,
    configStore,
  });

  assert.throws(
    () => createManager().create({}),
    /unable to query Ollama.*unable to connect to Ollama/i,
  );
  assert.ok(calls.some((call) => (
    call.command === '/opt/curl' && call.args.at(-1).endsWith('/api/tags')
  )));
  assert.equal(calls.some((call) => call.command === '/opt/codex'), false);

  calls.length = 0;
  ollamaAvailable = true;
  assert.throws(
    () => createManager().create({}),
    /codex is unavailable for ollama: codex unavailable/i,
  );
  assert.ok(calls.some((call) => (
    call.command === '/opt/curl' && call.args.at(-1).endsWith('/api/tags')
  )));
  assert.ok(calls.some((call) => (
    call.command === '/opt/curl' && call.args.at(-1).endsWith('/api/show')
  )));
  assert.ok(calls.some((call) => call.command === '/opt/codex' && call.args[0] === '--version'));
  const codexProbe = calls.find((call) => call.command === '/opt/codex');
  assert.equal(codexProbe.options.env.PATH, '/safe/bin');
  assert.equal(codexProbe.options.env.SAFE_PREFLIGHT_VALUE, 'preserved');
  assert.equal(codexProbe.options.env.NOTTY_MCP_SPAWN_OTP, undefined);
  assert.equal(codexProbe.options.env.NOTTY_BASIC_AUTH_PASSWORD, undefined);
  assert.equal(codexProbe.options.env.NOTTY_OAUTH_ACCESS_TOKEN, undefined);
  assert.equal(codexProbe.options.env.AUTHORIZATION, undefined);
  assert.equal(calls.some((call) => call.command.includes('ollama')), false);
  assert.equal(fs.existsSync(manifestPath), false);
});

test('owned sessions distinguish a live agent from an occupied tmux target', () => {
  const agent = {
    id: 'coder',
    identity: 'coder',
    tmuxTarget: 'collab-test-coder',
    status: 'running',
    error: '',
  };

  assert.deepEqual(
    resolveAgentTmuxState(agent, { tmuxPresent: true, tmuxOwned: true }),
    {
      ...agent,
      status: 'running',
      tmuxPresent: true,
      tmuxOwned: true,
      tmuxAlive: true,
      ownershipLost: false,
      error: '',
    },
  );

  const occupied = resolveAgentTmuxState(agent, { tmuxPresent: true, tmuxOwned: false });
  assert.equal(occupied.status, 'ownership-lost');
  assert.equal(occupied.tmuxPresent, true);
  assert.equal(occupied.tmuxOwned, false);
  assert.equal(occupied.tmuxAlive, false);
  assert.equal(occupied.ownershipLost, true);
  assert.match(occupied.error, /owned by another session/);
});

test('recovered agents remain viewable without claiming tmux ownership', () => {
  const state = resolveAgentTmuxState({
    id: 'manual',
    tmuxTarget: 'manual',
    status: 'running',
  }, {
    recovered: true,
    tmuxPresent: true,
    tmuxOwned: false,
  });

  assert.equal(state.status, 'running');
  assert.equal(state.tmuxOwned, null);
  assert.equal(state.tmuxAlive, true);
  assert.equal(state.ownershipLost, false);
});

test('layout snapshots and operator identity are manager-owned values', () => {
  assert.deepEqual(createLayoutSnapshot('monitor', {
    id: 'spoofed',
    label: 'Monitor',
    mode: 'lead-grid',
  }), {
    id: 'monitor',
    label: 'Monitor',
    mode: 'lead-grid',
  });
  assert.equal(resolveSessionOperator({}, { NOTTY_COLLAB_OPERATOR: 'Team Lead' }), 'Team-Lead');
  assert.equal(resolveSessionOperator({ operator: 'release-coordinator' }, {
    NOTTY_COLLAB_OPERATOR: 'ignored',
  }), 'release-coordinator');
});

test('Nosh preflight distinguishes unavailable profiles from an explicitly empty selection', () => {
  assert.deepEqual(validateNoshProfiles(['agents'], {}), [
    'Active Nosh profiles are unavailable; requirements were not verified.',
  ]);
  assert.throws(
    () => validateNoshProfiles(['agents'], { NOTTY_NOSH_PROFILES: '' }),
    (error) => error.statusCode === 422 && /missing required Nosh profiles: agents/.test(error.message),
  );
  assert.deepEqual(
    validateNoshProfiles(['agents'], { NOTTY_NOSH_PROFILES: 'python,agents' }),
    [],
  );
});

test('human launch rosters omit coordinator-capable agents from built-in teams', () => {
  const config = JSON.parse(fs.readFileSync(
    path.join(__dirname, '..', 'config', 'collab.templates.json'),
    'utf8',
  ));

  const pair = resolveLaunchRoster(
    config.templates['pair-review'],
    config.prompts,
    'human',
  );
  assert.deepEqual(pair.specs, [{ prompt: 'qa', harness: 'codex', backend: 'default', model: 'gpt-5.3-codex-spark', think: 'low' }]);
  assert.deepEqual(pair.agents.map((agent) => agent.identity), ['qa']);
  assert.equal(pair.agents.some((agent) => agent.coordinatorCapable), false);

  const delivery = resolveLaunchRoster(
    config.templates['delivery-team'],
    config.prompts,
    'human',
  );
  assert.deepEqual(delivery.specs, [
    { prompt: 'dev', harness: 'codex', backend: 'default', model: 'gpt-5.3-codex-spark', think: 'low' },
    { prompt: 'coder', harness: 'codex', backend: 'default', model: 'gpt-5.3-codex-spark', think: 'low' },
    { prompt: 'qa', harness: 'codex', backend: 'default', model: 'gpt-5.3-codex-spark', think: 'low' },
  ]);
  assert.deepEqual(
    delivery.agents.map((agent) => agent.identity),
    ['dev', 'coder', 'qa'],
  );
  assert.equal(delivery.agents.some((agent) => agent.coordinatorCapable), false);
});

test('agent launch rosters retain exactly one coordinator and preserve fallback behavior', () => {
  const prompts = {
    coordinator: {
      label: 'Coordinator',
      role: 'coordinator',
      coordinatorCapable: true,
    },
    dev: {
      label: 'Developer',
      role: 'dev',
      coordinatorCapable: false,
    },
  };
  const full = resolveLaunchRoster({
    agents: [
      'coordinator_codex_gpt-5.4',
      'dev_codex_gpt-5.4',
    ],
    coordinatorSpec: 'coordinator_codex_gpt-5.4',
  }, prompts, 'agent');
  assert.deepEqual(full.specs, [
    'coordinator_codex_gpt-5.4',
    'dev_codex_gpt-5.4',
  ]);
  assert.equal(full.agents.filter((agent) => agent.coordinatorCapable).length, 1);

  const fallback = resolveLaunchRoster({
    agents: ['dev_codex_gpt-5.4'],
    coordinatorSpec: 'coordinator_codex_gpt-5.4',
  }, prompts, 'agent');
  assert.deepEqual(fallback.specs, [
    'coordinator_codex_gpt-5.4',
    'dev_codex_gpt-5.4',
  ]);
  assert.equal(fallback.agents.filter((agent) => agent.coordinatorCapable).length, 1);
});

test('human launch rosters reject coordinator-only teams and recalculate duplicate identities', () => {
  const prompts = {
    coordinator: {
      identity: 'shared',
      role: 'coordinator',
      coordinatorCapable: true,
    },
    dev: {
      identity: 'shared',
      role: 'dev',
      coordinatorCapable: false,
    },
    qa: {
      identity: 'shared',
      role: 'qa',
      coordinatorCapable: false,
    },
  };

  assert.throws(
    () => resolveLaunchRoster({
      agents: ['coordinator_codex_gpt-5.4'],
    }, prompts, 'human'),
    (error) => (
      error.statusCode === 422
      && /at least one worker agent/i.test(error.message)
    ),
  );

  const roster = resolveLaunchRoster({
    agents: [
      'dev_codex_gpt-5.4',
      'coordinator_codex_gpt-5.4',
      'qa_codex_gpt-5.4',
    ],
  }, prompts, 'human');
  assert.deepEqual(roster.specs, [
    'dev_codex_gpt-5.4',
    'qa_codex_gpt-5.4',
  ]);
  assert.deepEqual(
    roster.agents.map((agent) => agent.identity),
    ['shared', 'shared-2'],
  );
});

test('human mode filters coordinator runtimes before preflight and launch', (t) => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'notty-collab-human-preflight-'));
  const workspaceRoot = path.join(root, 'workspace');
  const manifestPath = path.join(root, 'session.json');
  fs.mkdirSync(workspaceRoot, { recursive: true });
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));

  const originalSpawnSync = childProcess.spawnSync;
  const calls = [];
  const tmuxSessions = new Set();
  childProcess.spawnSync = (command, args) => {
    calls.push({ command, args });
    if (command === '/opt/agy') {
      return { status: 1, stdout: '', stderr: 'agy unavailable' };
    }
    if (command === '/opt/codex') {
      return { status: 0, stdout: 'codex-cli\n', stderr: '' };
    }
    if (command !== 'tmux') {
      return { status: 0, stdout: '', stderr: '' };
    }
    if (args[0] === 'new-session') {
      tmuxSessions.add(args[args.indexOf('-s') + 1]);
      return { status: 0, stdout: '', stderr: '' };
    }
    if (args[0] === 'has-session') {
      return {
        status: tmuxSessions.has(args[args.indexOf('-t') + 1]) ? 0 : 1,
        stdout: '',
        stderr: '',
      };
    }
    return { status: 0, stdout: '', stderr: '' };
  };
  t.after(() => {
    childProcess.spawnSync = originalSpawnSync;
  });

  const manager = createSessionManager({
    codexBin: '/opt/codex',
    agyBin: '/opt/agy',
    environment: { NOTTY_NOSH_PROFILES: '' },
    workspaceRoot,
    manifestPath,
    configStore: {
      load: () => ({
        resolved: {
          defaultTemplate: 'mixed',
          layouts: {
            grid: { label: 'Grid', mode: 'grid' },
          },
          prompts: {
            coordinator: {
              role: 'coordinator',
              coordinatorCapable: true,
            },
            dev: {
              role: 'dev',
              coordinatorCapable: false,
            },
          },
          templates: {
            mixed: {
              layout: 'grid',
              defaultCoordinatorMode: 'human',
              requiredNoshProfiles: [],
              agents: [
                'coordinator_agy_Claude Coordinator',
                'dev_codex_gpt-5.4',
              ],
            },
          },
        },
      }),
    },
    tmuxSessionExists: (target) => tmuxSessions.has(target),
    tmuxSessionOwnedBy: (target) => tmuxSessions.has(target),
  });

  const session = manager.create({ coordinatorMode: 'human' });
  assert.deepEqual(session.agents.map((agent) => agent.id), ['dev']);
  assert.deepEqual(session.templateSnapshot.agents, ['dev_codex_gpt-5.4']);
  assert.deepEqual(Object.keys(session.templateSnapshot.prompts), ['dev']);
  assert.equal(calls.some((call) => call.command === '/opt/agy'), false);
  assert.equal(
    calls.filter((call) => call.command === 'tmux' && call.args[0] === 'new-session').length,
    1,
  );
});

test('permission relaunch resolves the exact thread before stopping and resumes with the new mode', async (t) => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'notty-collab-relaunch-'));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));

  const workspaceRoot = path.join(root, 'workspace');
  const manifestPath = path.join(root, 'session.json');
  const initialPrompt = 'Exact initial collaboration prompt';
  const runtimeSessionId = '019f0000-0000-7000-8000-000000000002';
  fs.mkdirSync(workspaceRoot, { recursive: true });
  writeManifest(manifestPath, {
    id: 'session-test',
    templateId: 'solo',
    templateSnapshot: {
      prompts: {
        coder: {
          instructions: 'Implement the task.',
        },
      },
    },
    coordinatorMode: 'human',
    task: '',
    channel: 'lobby',
    workspaceRoot,
    recovered: false,
    status: 'running',
    createdAt: '2026-01-01T00:00:00.000Z',
    updatedAt: '2026-01-01T00:00:00.000Z',
    agents: [runtimeAgent({
      role: 'coder',
      harness: 'codex',
      backend: 'default',
      runtime: 'codex',
      prompt: 'coder',
      model: 'gpt-5.4',
      think: 'high',
      initialPrompt,
    })],
  });

  const originalSpawnSync = childProcess.spawnSync;
  const spawnCalls = [];
  const lifecycle = [];
  const managedEntries = [];
  let tmuxAlive = true;
  childProcess.spawnSync = (command, args, options) => {
    spawnCalls.push({ command, args, options });
    if (command !== 'tmux') {
      return { status: 0, stdout: '', stderr: '' };
    }
    if (args[0] === 'new-session') {
      lifecycle.push('launch');
      tmuxAlive = true;
      return { status: 0, stdout: '', stderr: '' };
    }
    if (args[0] === 'has-session') {
      return { status: tmuxAlive ? 0 : 1, stdout: '', stderr: '' };
    }
    return { status: 0, stdout: '', stderr: '' };
  };
  t.after(() => {
    childProcess.spawnSync = originalSpawnSync;
  });

  const manager = createSessionManager({
    codexBin: '/opt/codex',
    environment: {},
    workspaceRoot,
    manifestPath,
    configStore: { load: () => { throw new Error('not used'); } },
    tmuxSessionExists: () => tmuxAlive,
    tmuxSessionOwnedBy: () => tmuxAlive,
    killTmuxSession: (target) => {
      lifecycle.push(`stop:${target}`);
      tmuxAlive = false;
      return { status: 0, stdout: '', stderr: '' };
    },
    clearAgentRuntime: (agent) => lifecycle.push(`clear:${agent}`),
    resolveCodexThreadId: async (options) => {
      lifecycle.push(`resolve:${tmuxAlive ? 'running' : 'stopped'}`);
      assert.equal(options.codexBin, '/opt/codex');
      assert.equal(options.cwd, workspaceRoot);
      assert.equal(options.prompt, initialPrompt);
      const concurrentManifest = JSON.parse(fs.readFileSync(manifestPath, 'utf8'));
      concurrentManifest.layout = 'concurrent-layout';
      writeManifest(manifestPath, concurrentManifest);
      return runtimeSessionId;
    },
    addManagedAgent: (agent, target, metadata) => {
      managedEntries.push({ agent, target, metadata });
    },
  });

  const [relaunched, concurrentDuplicate] = await Promise.all([
    manager.relaunch('coder', {
      permissionMode: CODEX_PERMISSION_MODES.BYPASS,
    }),
    manager.relaunch('coder', {
      permissionMode: CODEX_PERMISSION_MODES.BYPASS,
    }),
  ]);
  assert.deepEqual(lifecycle, [
    'resolve:running',
    'stop:collab-test-coder',
    'clear:coder',
    'launch',
  ]);
  assert.equal(relaunched.status, 'running');
  assert.equal(relaunched.layout, 'concurrent-layout');
  assert.equal(
    relaunched.agents[0].permissionMode,
    CODEX_PERMISSION_MODES.BYPASS,
  );
  assert.equal(relaunched.agents[0].runtimeSessionId, runtimeSessionId);
  assert.equal(
    concurrentDuplicate.agents[0].permissionMode,
    CODEX_PERMISSION_MODES.BYPASS,
  );

  const launch = spawnCalls.find((call) => (
    call.command === 'tmux' && call.args[0] === 'new-session'
  ));
  assert.ok(launch);
  const codexIndex = launch.args.indexOf('/opt/codex');
  assert.notEqual(codexIndex, -1);
  assert.deepEqual(launch.args.slice(codexIndex), [
    '/opt/codex',
    '-m', 'gpt-5.4',
    '-c', `mcp_servers.${COLLAB_SESSION_MCP_SERVER}.url="http://127.0.0.1:1337/mcp"`,
    '-c', 'model_reasoning_effort="high"',
    '--dangerously-bypass-approvals-and-sandbox',
    'resume', runtimeSessionId,
  ]);
  assert.equal(launch.args.includes('--sandbox'), false);
  assert.equal(launch.args.includes(initialPrompt), false);

  assert.deepEqual(managedEntries, [{
    agent: 'coder',
    target: 'collab-test-coder',
    metadata: {
      role: 'coder',
      harness: 'codex',
      backend: 'default',
      runtime: 'codex',
      model: 'gpt-5.4',
      think: 'high',
      sessionId: 'session-test',
      runtimeSessionId,
      permissionMode: CODEX_PERMISSION_MODES.BYPASS,
    },
  }]);
  const persisted = JSON.parse(fs.readFileSync(manifestPath, 'utf8'));
  assert.equal(persisted.id, 'session-test');
  assert.equal(persisted.agents[0].runtimeSessionId, runtimeSessionId);
  assert.equal(
    persisted.agents[0].permissionMode,
    CODEX_PERMISSION_MODES.BYPASS,
  );

  const launchCount = spawnCalls.filter((call) => (
    call.command === 'tmux' && call.args[0] === 'new-session'
  )).length;
  const lifecycleCount = lifecycle.length;
  const unchanged = await manager.relaunch('coder', {
    permissionMode: CODEX_PERMISSION_MODES.BYPASS,
  });
  assert.equal(unchanged.agents[0].runtimeSessionId, runtimeSessionId);
  assert.equal(lifecycle.length, lifecycleCount);
  assert.equal(
    spawnCalls.filter((call) => call.command === 'tmux' && call.args[0] === 'new-session').length,
    launchCount,
  );
});

test('reconcile persists and emits only when derived runtime state changes', (t) => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'notty-collab-reconcile-'));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));

  const workspaceRoot = path.join(root, 'workspace');
  const manifestPath = path.join(root, 'session.json');
  fs.mkdirSync(workspaceRoot, { recursive: true });
  const session = {
    id: 'session-test',
    workspaceRoot,
    recovered: false,
    status: 'running',
    updatedAt: '2026-01-01T00:00:00.000Z',
    agents: [runtimeAgent()],
  };
  writeManifest(manifestPath, session);

  let tmuxAlive = true;
  const events = [];
  const manager = createSessionManager({
    workspaceRoot,
    manifestPath,
    configStore: { load: () => { throw new Error('not used'); } },
    eventHub: { emit: (type, data) => events.push({ type, data }) },
    tmuxSessionExists: () => tmuxAlive,
    tmuxSessionOwnedBy: () => tmuxAlive,
  });

  const before = fs.readFileSync(manifestPath, 'utf8');
  assert.equal(manager.getSession().updatedAt, session.updatedAt);
  assert.equal(fs.readFileSync(manifestPath, 'utf8'), before);
  assert.deepEqual(events, []);

  tmuxAlive = false;
  const reconciled = manager.reconcile();
  assert.equal(reconciled.status, 'degraded');
  assert.equal(reconciled.agents[0].status, 'stopped');
  assert.notEqual(reconciled.updatedAt, session.updatedAt);
  assert.deepEqual(events.map((event) => event.type), ['agent.status', 'session.changed']);

  events.length = 0;
  const after = fs.readFileSync(manifestPath, 'utf8');
  manager.reconcile();
  assert.equal(fs.readFileSync(manifestPath, 'utf8'), after);
  assert.deepEqual(events, []);
});

test('persisted agent deadlines enforce after manager recreation without a browser', (t) => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'notty-collab-expiry-'));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const manifestPath = path.join(root, 'session.json');
  writeManifest(manifestPath, { id: 'deadline-session', workspaceRoot: root,
    status: 'running', recovered: false, agents: [runtimeAgent({
      timeoutSeconds: 3600, terminateOnExpire: true, expiresAt: Date.now() - 1,
    })] });
  let alive = true;
  let kills = 0;
  const manager = createSessionManager({ workspaceRoot: root, manifestPath,
    configStore: { load: () => { throw new Error('not used'); } },
    tmuxSessionExists: () => alive, tmuxSessionOwnedBy: () => alive,
    killTmuxSession: () => { alive = false; kills++; return { status: 0 }; },
  });
  assert.equal(manager.reconcile().agents[0].status, 'stopped');
  assert.equal(kills, 1);
  manager.reconcile();
  assert.equal(kills, 1);
  assert.equal(JSON.parse(fs.readFileSync(manifestPath)).agents[0].error, 'Terminated on expiry.');
});

test('layout patch refreshes the session layout snapshot', (t) => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'notty-collab-layout-'));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));

  const workspaceRoot = path.join(root, 'workspace');
  const manifestPath = path.join(root, 'session.json');
  fs.mkdirSync(workspaceRoot, { recursive: true });
  writeManifest(manifestPath, {
    id: 'layout-test',
    workspaceRoot,
    recovered: false,
    status: 'running',
    layout: 'grid',
    layoutSnapshot: { id: 'grid', label: 'Grid', mode: 'grid' },
    agents: [],
  });

  const manager = createSessionManager({
    workspaceRoot,
    manifestPath,
    configStore: {
      load: () => ({
        resolved: {
          layouts: {
            grid: { label: 'Grid', mode: 'grid' },
            monitor: { label: 'Monitor', mode: 'lead-grid' },
          },
        },
      }),
    },
  });
  const session = manager.patch({ layout: 'monitor' });
  assert.equal(session.layout, 'monitor');
  assert.deepEqual(session.layoutSnapshot, {
    id: 'monitor',
    label: 'Monitor',
    mode: 'lead-grid',
  });
});

test('legacy import snapshots its resolved layout', (t) => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'notty-collab-legacy-layout-'));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));

  const workspaceRoot = path.join(root, 'workspace');
  const manifestPath = path.join(root, 'session.json');
  fs.mkdirSync(workspaceRoot, { recursive: true });
  const manager = createSessionManager({
    workspaceRoot,
    manifestPath,
    configStore: {
      load: () => ({ resolved: { layouts: { grid: { label: 'Grid', mode: 'grid' } } } }),
    },
    listLegacyManagedAgents: () => [{ agent: 'manual', target: 'manual' }],
    tmuxSessionExists: () => true,
  });

  const session = manager.getSession();
  assert.equal(session.recovered, true);
  assert.deepEqual(session.layoutSnapshot, { id: 'grid', label: 'Grid', mode: 'grid' });
});

test('stop retains a degraded manifest until every owned tmux session exits', (t) => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'notty-collab-stop-failure-'));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));

  const workspaceRoot = path.join(root, 'workspace');
  const manifestPath = path.join(root, 'session.json');
  fs.mkdirSync(workspaceRoot, { recursive: true });
  writeManifest(manifestPath, {
    id: 'stop-test',
    workspaceRoot,
    recovered: false,
    status: 'running',
    agents: [runtimeAgent()],
  });

  let tmuxAlive = true;
  let killFails = true;
  const removed = [];
  const manager = createSessionManager({
    workspaceRoot,
    manifestPath,
    configStore: { load: () => { throw new Error('not used'); } },
    tmuxSessionExists: () => tmuxAlive,
    tmuxSessionOwnedBy: () => tmuxAlive,
    killTmuxSession: () => {
      if (killFails) {
        return { status: 1, stderr: 'permission denied' };
      }
      tmuxAlive = false;
      return { status: 0, stderr: '' };
    },
    removeManagedAgent: (agent) => removed.push(agent),
  });

  assert.throws(
    () => manager.stop(),
    (error) => error.statusCode === 500 && /failed to stop owned tmux sessions/.test(error.message),
  );
  assert.equal(fs.existsSync(manifestPath), true);
  const degraded = manager.getSession();
  assert.equal(degraded.status, 'degraded');
  assert.equal(degraded.agents[0].status, 'stop-failed');
  assert.match(degraded.agents[0].error, /permission denied/);
  assert.deepEqual(removed, []);

  killFails = false;
  assert.equal(manager.stop().stopped, true);
  assert.equal(fs.existsSync(manifestPath), false);
  assert.deepEqual(removed, ['coder']);
});

test('stopping a recovered session dismisses managed entries without killing tmux', (t) => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'notty-collab-recovered-'));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));

  const workspaceRoot = path.join(root, 'workspace');
  const manifestPath = path.join(root, 'session.json');
  fs.mkdirSync(workspaceRoot, { recursive: true });
  fs.writeFileSync(manifestPath, `${JSON.stringify({
    id: 'legacy-test',
    workspaceRoot,
    recovered: true,
    status: 'recovered',
    agents: [
      { id: 'coder', identity: 'coder', tmuxTarget: 'manual-coder' },
      { id: 'qa', identity: 'qa', tmuxTarget: 'manual-qa' },
    ],
  })}\n`, 'utf8');

  const managed = new Set(['coder', 'qa']);
  const removed = [];
  const manager = createSessionManager({
    workspaceRoot,
    manifestPath,
    configStore: { load: () => { throw new Error('not used'); } },
    listLegacyManagedAgents: () => [],
    removeManagedAgent(agent) {
      removed.push(agent);
      managed.delete(agent);
      return true;
    },
  });

  const result = manager.stop();
  assert.equal(result.stopped, true);
  assert.deepEqual(removed, ['coder', 'qa']);
  assert.deepEqual(Array.from(managed), []);
  assert.equal(fs.existsSync(manifestPath), false);
  assert.equal(manager.getSession(), null);
});
