'use strict';

const assert = require('node:assert/strict');
const childProcess = require('node:child_process');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const test = require('node:test');

const appRoot = path.resolve(__dirname, '..');
const createAgentPath = path.join(appRoot, 'agents', 'bin', 'create_agent.sh');
const resumeAgentPath = path.join(appRoot, 'agents', 'bin', 'resume_agent.sh');
const swarmLibPath = path.join(appRoot, 'agents', 'bin', 'swarm.lib.sh');

function readJsonLines(filePath) {
  return fs.readFileSync(filePath, 'utf8')
    .split('\n')
    .filter(Boolean)
    .map((line) => JSON.parse(line));
}

function ollamaProviderIdFromArgs(args) {
  const assignment = args.find((arg) => arg.startsWith('model_provider='));
  assert.ok(assignment, 'missing model_provider config');
  const providerId = JSON.parse(assignment.slice('model_provider='.length));
  assert.match(providerId, /^notty_ollama_[0-9a-f]{32}$/);
  return providerId;
}

function ollamaCatalogPathFromArgs(args) {
  const assignment = args.find((arg) => arg.startsWith('model_catalog_json='));
  assert.ok(assignment, 'missing model_catalog_json config');
  return JSON.parse(assignment.slice('model_catalog_json='.length));
}

function ollamaBaseUrlFromArgs(args, providerId) {
  const prefix = `model_providers.${providerId}.base_url=`;
  const assignment = args.find((arg) => arg.startsWith(prefix));
  assert.ok(assignment, 'missing Ollama provider base_url config');
  return JSON.parse(assignment.slice(prefix.length));
}

function createHarness(t) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'notty-create-agent-shell-'));
  const workspace = path.join(root, 'workspace');
  const binDir = path.join(root, 'bin');
  const tmuxState = path.join(root, 'tmux-state');
  const runtimeLog = path.join(root, 'runtime.log');
  const tmuxLog = path.join(root, 'tmux.log');
  const ollamaRuntimeDir = path.join(root, 'runtime');
  fs.mkdirSync(workspace, { recursive: true });
  fs.mkdirSync(binDir, { recursive: true });
  fs.mkdirSync(tmuxState, { recursive: true });
  fs.writeFileSync(runtimeLog, '', 'utf8');
  fs.writeFileSync(tmuxLog, '', 'utf8');
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));

  const fakeTmux = path.join(binDir, 'tmux');
  fs.writeFileSync(fakeTmux, [
    `#!${process.execPath}`,
    "'use strict';",
    "const childProcess = require('node:child_process');",
    "const fs = require('node:fs');",
    "const path = require('node:path');",
    'const args = process.argv.slice(2);',
    "fs.appendFileSync(process.env.TMUX_LOG, `${JSON.stringify(args)}\\n`);",
    "if (args.includes('has-session')) {",
    "  const index = args.indexOf('-t');",
    "  const state = path.join(process.env.TMUX_STATE, args[index + 1]);",
    '  process.exit(fs.existsSync(state) ? 0 : 1);',
    '}',
    "if (!args.includes('new-session')) process.exit(0);",
    "if (process.env.FAKE_TMUX_NEW_SESSION_FAIL === '1') {",
    "  process.stderr.write('forced tmux launch failure\\n');",
    '  process.exit(42);',
    '}',
    "const sessionIndex = args.indexOf('-s');",
    'const session = args[sessionIndex + 1];',
    'const launch = args[args.length - 1];',
    "const result = childProcess.spawnSync('/bin/bash', ['-lc', launch], {",
    '  env: process.env,',
    "  encoding: 'utf8',",
    '});',
    'if (result.error || result.status !== 0) {',
    "  process.stderr.write(result.error ? result.error.message : (result.stderr || result.stdout || 'launch failed'));",
    '  process.exit(result.status || 1);',
    '}',
    "fs.writeFileSync(path.join(process.env.TMUX_STATE, session), 'running\\n', 'utf8');",
    '',
  ].join('\n'), { mode: 0o755 });

  const runtimePaths = {};
  for (const runtime of ['codex', 'agy', 'claude']) {
    const runtimePath = path.join(binDir, runtime);
    runtimePaths[runtime] = runtimePath;
    fs.writeFileSync(runtimePath, [
      `#!${process.execPath}`,
      "'use strict';",
      "const fs = require('node:fs');",
      'const argv = process.argv.slice(2);',
      `if (${JSON.stringify(runtime)} === 'codex' && argv[0] === '--version') {`,
      "  if (process.env.FAKE_CODEX_UNAVAILABLE === '1') {",
      "    process.stderr.write('codex unavailable\\n');",
      '    process.exit(1);',
      '  }',
      "  process.stdout.write('codex test\\n');",
      '  process.exit(0);',
      '}',
      'fs.appendFileSync(process.env.RUNTIME_LOG, `${JSON.stringify({',
      `  executable: ${JSON.stringify(runtime)},`,
      '  argv,',
      '  env: {',
      '    COLLAB_AGENT_ID: process.env.COLLAB_AGENT_ID,',
      '    COLLAB_BACKEND: process.env.COLLAB_BACKEND,',
      '    COLLAB_HARNESS: process.env.COLLAB_HARNESS,',
      '    COLLAB_MCP_URL: process.env.COLLAB_MCP_URL,',
      '    COLLAB_MODEL: process.env.COLLAB_MODEL,',
      '    COLLAB_RUNTIME: process.env.COLLAB_RUNTIME,',
      '    COLLAB_THINK: process.env.COLLAB_THINK,',
      '    OLLAMA_HOST: process.env.OLLAMA_HOST,',
      '  },',
      '})}\\n`);',
      '',
    ].join('\n'), { mode: 0o755 });
  }

  const fakeCurl = path.join(binDir, 'curl');
  fs.writeFileSync(fakeCurl, [
    `#!${process.execPath}`,
    "'use strict';",
    'const args = process.argv.slice(2);',
    "if (process.env.FAKE_OLLAMA_UNAVAILABLE === '1') {",
    "  process.stderr.write('connection refused\\n');",
    '  process.exit(7);',
    '}',
    "const models = JSON.parse(process.env.FAKE_OLLAMA_MODELS || '[\"qwen3:4b\"]');",
    "const url = String(args.at(-1) || '');",
    "if (url.endsWith('/api/tags')) {",
    '  process.stdout.write(JSON.stringify({',
    '    models: models.map((model) => ({ name: model, model })),',
    '  }));',
    "} else if (url.endsWith('/api/show')) {",
    '  process.stdout.write(JSON.stringify({',
    "    capabilities: ['tools'],",
    "    model_info: { context_length: 32768 },",
    '  }));',
    '} else {',
    "  process.stderr.write(`unexpected Ollama URL: ${url}\\n`);",
    '  process.exit(2);',
    '}',
    '',
  ].join('\n'), { mode: 0o755 });

  const env = { ...process.env };
  for (const name of [
    'COLLAB_AGENT_SPAWN_OTP',
    'COLLAB_BACKEND',
    'COLLAB_HARNESS',
    'COLLAB_MODEL',
    'COLLAB_RUNTIME',
    'COLLAB_THINK',
  ]) {
    delete env[name];
  }
  Object.assign(env, {
    PATH: `${binDir}:${env.PATH}`,
    COLLAB_MCP_URL: 'http://127.0.0.1:18888/mcp',
    NOTTY_COLLAB_UNSANDBOXED: 'false',
    NOTTY_WORKDIR: workspace,
    OLLAMA_BIN: '/definitely/not-used/ollama',
    OLLAMA_HOST: 'http://ollama.test:11434',
    RUNTIME_LOG: runtimeLog,
    SWARM_AGY_BIN: runtimePaths.agy,
    SWARM_CLAUDE_BIN: runtimePaths.claude,
    SWARM_CODEX_BIN: runtimePaths.codex,
    SWARM_CURL_BIN: fakeCurl,
    SWARM_NODE_BIN: process.execPath,
    SWARM_OLLAMA_BIN: '/also/not-used/ollama',
    SWARM_OLLAMA_RUNTIME_DIR: ollamaRuntimeDir,
    SWARM_STARTUP_PROBE_DELAY: '0',
    TMUX_LOG: tmuxLog,
    TMUX_STATE: tmuxState,
  });

  return {
    env,
    root,
    runtimeLog,
    tmuxLog,
    tmuxState,
    ollamaRuntimeDir,
    workspace,
    run(args, options = {}) {
      return childProcess.spawnSync(createAgentPath, args, {
        cwd: options.cwd || workspace,
        encoding: 'utf8',
        env: { ...env, ...(options.env || {}) },
      });
    },
    resume(args, options = {}) {
      return childProcess.spawnSync(resumeAgentPath, args, {
        cwd: workspace,
        encoding: 'utf8',
        env: { ...env, ...(options.env || {}) },
      });
    },
  };
}

test('canonical Codex/Ollama launch exports canonical and legacy identity', (t) => {
  const harness = createHarness(t);
  const result = harness.run([
    '--agent', 'local-observer',
    '--role', 'observer',
    '--harness', 'codex',
    '--backend', 'ollama',
    '--model', 'qwen3:4b',
    '--think', 'max',
  ]);

  assert.equal(result.status, 0, `${result.stdout}\n${result.stderr}`);
  const [launch] = readJsonLines(harness.runtimeLog);
  assert.equal(launch.executable, 'codex');
  assert.deepEqual(launch.argv.slice(0, 2), ['-m', 'qwen3:4b']);
  const providerId = ollamaProviderIdFromArgs(launch.argv);
  assert.match(ollamaBaseUrlFromArgs(launch.argv, providerId), /^http:\/\/127\.0\.0\.1:\d+\/v1$/);
  assert.ok(launch.argv.includes(
    `model_providers.${providerId}.wire_api="responses"`,
  ));
  assert.ok(launch.argv.includes('model_reasoning_effort="max"'));
  assert.ok(launch.argv.includes(
    'mcp_servers.notty_collab_session.url="http://127.0.0.1:18888/mcp"',
  ));
  assert.ok(launch.argv.includes('--sandbox'));
  assert.ok(launch.argv.includes('workspace-write'));
  assert.ok(launch.argv.includes('--ask-for-approval'));
  assert.ok(launch.argv.includes('on-request'));
  assert.equal(launch.argv.includes('launch'), false);
  assert.equal(launch.argv.includes('--oss'), false);
  const catalogPath = ollamaCatalogPathFromArgs(launch.argv);
  assert.equal(fs.existsSync(catalogPath), false, 'relay removes its catalog when Codex exits');
  assert.equal(launch.env.COLLAB_HARNESS, 'codex');
  assert.equal(launch.env.COLLAB_BACKEND, 'ollama');
  assert.equal(launch.env.COLLAB_RUNTIME, 'ollama');
  assert.equal(launch.env.COLLAB_THINK, 'max');
  assert.equal(launch.env.OLLAMA_HOST, 'http://ollama.test:11434');
  assert.match(result.stdout, /harness=codex\tbackend=ollama\truntime=ollama/);
});

test('legacy --runtime ollama alias uses the same direct Codex provider path', (t) => {
  const harness = createHarness(t);
  const result = harness.run([
    '--agent', 'legacy-local',
    '--runtime', 'ollama',
    '--model', 'qwen3:4b',
  ]);

  assert.equal(result.status, 0, `${result.stdout}\n${result.stderr}`);
  const [launch] = readJsonLines(harness.runtimeLog);
  assert.equal(launch.executable, 'codex');
  assert.deepEqual(launch.argv.slice(0, 2), ['-m', 'qwen3:4b']);
  const providerId = ollamaProviderIdFromArgs(launch.argv);
  assert.match(ollamaBaseUrlFromArgs(launch.argv, providerId), /^http:\/\/127\.0\.0\.1:\d+\/v1$/);
  assert.equal(launch.argv.includes('launch'), false);
  assert.equal(launch.env.COLLAB_HARNESS, 'codex');
  assert.equal(launch.env.COLLAB_BACKEND, 'ollama');
  assert.equal(launch.env.COLLAB_RUNTIME, 'ollama');
});

test('Ollama model catalogs are isolated by workspace as well as agent name', (t) => {
  const harness = createHarness(t);
  const launchArgs = [
    '--agent', 'workspace-local',
    '--runtime', 'ollama',
    '--model', 'qwen3:4b',
  ];
  const first = harness.run(launchArgs);
  assert.equal(first.status, 0, `${first.stdout}\n${first.stderr}`);

  fs.rmSync(path.join(harness.tmuxState, 'workspace-local'), { force: true });
  const secondWorkspace = path.join(harness.root, 'workspace-two');
  fs.mkdirSync(secondWorkspace, { recursive: true });
  const second = harness.run(launchArgs, { cwd: secondWorkspace });
  assert.equal(second.status, 0, `${second.stdout}\n${second.stderr}`);

  const launches = readJsonLines(harness.runtimeLog);
  assert.equal(launches.length, 2);
  assert.notEqual(
    ollamaProviderIdFromArgs(launches[0].argv),
    ollamaProviderIdFromArgs(launches[1].argv),
  );
  assert.notEqual(
    ollamaCatalogPathFromArgs(launches[0].argv),
    ollamaCatalogPathFromArgs(launches[1].argv),
  );
});

test('Agy receives raw model id, SSE transport, and --effort', (t) => {
  const harness = createHarness(t);
  const model = 'gemini-3.6-flash-medium';
  const result = harness.run([
    '--agent', 'reviewer',
    '--harness', 'agy',
    '--backend', 'default',
    '--model', model,
    '--think', 'high',
  ]);

  assert.equal(result.status, 0, `${result.stdout}\n${result.stderr}`);
  const [launch] = readJsonLines(harness.runtimeLog);
  assert.equal(launch.executable, 'agy');
  assert.deepEqual(launch.argv.slice(0, 7), [
    '--model', model,
    '--effort', 'high',
    '--mode', 'accept-edits', '--sandbox',
  ]);
  assert.equal(launch.env.COLLAB_MCP_URL, 'http://127.0.0.1:18888/sse');
  assert.equal(launch.env.COLLAB_HARNESS, 'agy');
  assert.equal(launch.env.COLLAB_BACKEND, 'default');
  assert.equal(launch.env.COLLAB_RUNTIME, 'agy');
});

test('Claude launch uses process-scoped MCP config, effort, and safety args', (t) => {
  const harness = createHarness(t);
  const result = harness.run([
    '--agent', 'bofh',
    '--role', 'bofh',
    '--harness', 'claude',
    '--backend', 'default',
    '--model', 'sonnet',
    '--think', 'low',
  ]);

  assert.equal(result.status, 0, `${result.stdout}\n${result.stderr}`);
  const [launch] = readJsonLines(harness.runtimeLog);
  assert.equal(launch.executable, 'claude');
  assert.deepEqual(launch.argv.slice(0, 4), [
    '--model', 'sonnet', '--effort', 'low',
  ]);
  const mcpIndex = launch.argv.indexOf('--mcp-config');
  assert.notEqual(mcpIndex, -1);
  assert.deepEqual(JSON.parse(launch.argv[mcpIndex + 1]), {
    mcpServers: {
      notty_collab_session: {
        type: 'http',
        url: 'http://127.0.0.1:18888/mcp',
      },
    },
  });
  assert.deepEqual(
    launch.argv.slice(mcpIndex + 2, mcpIndex + 6),
    ['--permission-mode', 'acceptEdits', '--name', 'bofh'],
  );
  assert.match(launch.argv.at(-1), /You are the bofh agent/);
  assert.equal(launch.env.COLLAB_HARNESS, 'claude');
  assert.equal(launch.env.COLLAB_BACKEND, 'default');
  assert.equal(launch.env.COLLAB_RUNTIME, 'claude');

  const unsandboxed = harness.run([
    '--agent', 'bofh-full',
    '--harness', 'claude',
    '--model', 'sonnet',
  ], { env: { NOTTY_COLLAB_UNSANDBOXED: 'true' } });
  assert.equal(unsandboxed.status, 0, `${unsandboxed.stdout}\n${unsandboxed.stderr}`);
  const bypassLaunch = readJsonLines(harness.runtimeLog).at(-1);
  assert.ok(bypassLaunch.argv.includes('--dangerously-skip-permissions'));
  assert.equal(bypassLaunch.argv.includes('--permission-mode'), false);
});

test('canonical launcher resumes Claude without appending a new prompt', (t) => {
  const harness = createHarness(t);
  const script = [
    'source "$1"',
    'swarm_launch_canonical_agent "$2" claude-resume reviewer claude default sonnet high "$3" lobby http://127.0.0.1:18888/mcp resume session-123',
  ].join('\n');
  const result = childProcess.spawnSync('/bin/bash', ['-c', script, '_', swarmLibPath, appRoot, harness.workspace], {
    cwd: harness.workspace,
    encoding: 'utf8',
    env: harness.env,
  });

  assert.equal(result.status, 0, `${result.stdout}\n${result.stderr}`);
  const [launch] = readJsonLines(harness.runtimeLog);
  assert.equal(launch.executable, 'claude');
  assert.deepEqual(launch.argv.slice(-4), ['--name', 'claude-resume', '--resume', 'session-123']);
  assert.equal(launch.argv.some((arg) => /You are the reviewer agent/.test(arg)), false);
});

test('resume script preserves canonical Agy, Claude, and Codex/Ollama targets', (t) => {
  const harness = createHarness(t);
  const agy = harness.resume([
    '--agent', 'agy-resume',
    '--session-id', 'agy-conversation-1',
    '--harness', 'agy',
    '--model', 'gemini-3.6-flash-medium',
    '--think', 'high',
  ]);
  assert.equal(agy.status, 0, `${agy.stdout}\n${agy.stderr}`);

  const claude = harness.resume([
    '--agent', 'claude-resume-script',
    '--session-id', 'claude-session-1',
    '--harness', 'claude',
    '--model', 'sonnet',
    '--think', 'low',
  ]);
  assert.equal(claude.status, 0, `${claude.stdout}\n${claude.stderr}`);

  const ollama = harness.resume([
    '--agent', 'ollama-resume',
    '--session-id', 'codex-thread-1',
    '--harness', 'codex',
    '--backend', 'ollama',
    '--model', 'qwen3:4b',
    '--think', 'medium',
  ]);
  assert.equal(ollama.status, 0, `${ollama.stdout}\n${ollama.stderr}`);

  const launches = readJsonLines(harness.runtimeLog);
  assert.deepEqual(launches[0].argv.slice(0, 6), [
    '--conversation', 'agy-conversation-1',
    '--model', 'gemini-3.6-flash-medium',
    '--effort', 'high',
  ]);
  assert.equal(launches[0].env.COLLAB_MCP_URL, 'http://127.0.0.1:18888/sse');
  assert.deepEqual(launches[1].argv.slice(-4), [
    '--name', 'claude-resume-script', '--resume', 'claude-session-1',
  ]);
  assert.equal(launches[2].executable, 'codex');
  assert.deepEqual(launches[2].argv.slice(0, 2), ['-m', 'qwen3:4b']);
  const providerId = ollamaProviderIdFromArgs(launches[2].argv);
  assert.match(
    ollamaBaseUrlFromArgs(launches[2].argv, providerId),
    /^http:\/\/127\.0\.0\.1:\d+\/v1$/,
  );
  const resumeIndex = launches[2].argv.indexOf('resume');
  assert.notEqual(resumeIndex, -1);
  assert.equal(launches[2].argv[resumeIndex + 1], 'codex-thread-1');
  assert.equal(launches[2].env.COLLAB_HARNESS, 'codex');
  assert.equal(launches[2].env.COLLAB_BACKEND, 'ollama');
});

test('Codex/Ollama launch rejects a missing model before creating a tmux session', (t) => {
  const harness = createHarness(t);
  const result = harness.run([
    '--agent', 'missing-model',
    '--harness', 'codex',
    '--backend', 'ollama',
    '--model', 'missing:latest',
  ], { env: { FAKE_OLLAMA_MODELS: '["qwen3:4b"]' } });

  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /Ollama model is not installed: missing:latest/);
  assert.deepEqual(readJsonLines(harness.runtimeLog), []);
  assert.equal(
    readJsonLines(harness.tmuxLog).some((args) => args.includes('new-session')),
    false,
  );
});

test('Codex/Ollama launch requires a working Codex executable before Ollama preflight', (t) => {
  const harness = createHarness(t);
  const result = harness.run([
    '--agent', 'missing-codex',
    '--harness', 'codex',
    '--backend', 'ollama',
    '--model', 'qwen3:4b',
  ], { env: { FAKE_CODEX_UNAVAILABLE: '1' } });

  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /codex is unavailable for Ollama backend: codex unavailable/);
  assert.deepEqual(readJsonLines(harness.runtimeLog), []);
  assert.deepEqual(readJsonLines(harness.tmuxLog), []);
});

test('Codex/Ollama launch removes its catalog when tmux fails before the relay starts', (t) => {
  const harness = createHarness(t);
  const result = harness.run([
    '--agent', 'tmux-failure',
    '--runtime', 'ollama',
    '--model', 'qwen3:4b',
  ], { env: { FAKE_TMUX_NEW_SESSION_FAIL: '1' } });

  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /forced tmux launch failure/i);
  assert.deepEqual(readJsonLines(harness.runtimeLog), []);
  const catalogRoot = path.join(harness.ollamaRuntimeDir, 'notty-ollama');
  assert.equal(fs.existsSync(catalogRoot), true);
  assert.deepEqual(
    fs.readdirSync(catalogRoot).filter((name) => name.endsWith('.json')),
    [],
  );
});

test('canonical Ollama resume validates its session id before catalog preparation', (t) => {
  const harness = createHarness(t);
  const script = [
    'source "$1"',
    'swarm_launch_canonical_agent "$2" missing-thread coder codex ollama qwen3:4b low "$3" lobby http://127.0.0.1:18888/mcp resume ""',
  ].join('\n');
  const result = childProcess.spawnSync(
    '/bin/bash',
    ['-c', script, '_', swarmLibPath, appRoot, harness.workspace],
    { cwd: harness.workspace, encoding: 'utf8', env: harness.env },
  );

  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /resume mode requires a session id/i);
  assert.equal(fs.existsSync(path.join(harness.ollamaRuntimeDir, 'notty-ollama')), false);
  assert.deepEqual(readJsonLines(harness.tmuxLog), []);
});

test('legacy aliases map cleanly and conflicting targets fail before tmux', (t) => {
  const harness = createHarness(t);
  const legacy = harness.run([
    '--agent', 'legacy-claude',
    '--runtime', 'claude',
    '--model', 'sonnet',
    '--think', 'medium',
  ]);
  assert.equal(legacy.status, 0, `${legacy.stdout}\n${legacy.stderr}`);
  const [launch] = readJsonLines(harness.runtimeLog);
  assert.equal(launch.env.COLLAB_HARNESS, 'claude');
  assert.equal(launch.env.COLLAB_BACKEND, 'default');
  assert.equal(launch.env.COLLAB_RUNTIME, 'claude');

  fs.writeFileSync(harness.runtimeLog, '', 'utf8');
  fs.writeFileSync(harness.tmuxLog, '', 'utf8');
  const conflict = harness.run([
    '--agent', 'conflict',
    '--runtime', 'agy',
    '--harness', 'codex',
  ]);
  assert.notEqual(conflict.status, 0);
  assert.match(conflict.stderr, /--runtime agy conflicts with --harness codex/);

  const unsupported = harness.run([
    '--agent', 'unsupported',
    '--harness', 'claude',
    '--backend', 'ollama',
    '--model', 'qwen3:4b',
  ]);
  assert.notEqual(unsupported.status, 0);
  assert.match(unsupported.stderr, /claude does not support the Ollama model backend/);
  assert.deepEqual(readJsonLines(harness.runtimeLog), []);
  assert.deepEqual(readJsonLines(harness.tmuxLog), []);
});
