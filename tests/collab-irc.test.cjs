'use strict';

const assert = require('node:assert/strict');
const childProcess = require('node:child_process');
const fs = require('node:fs');
const net = require('node:net');
const os = require('node:os');
const path = require('node:path');
const test = require('node:test');

const appRoot = path.resolve(__dirname, '..');

async function reservePort() {
  const server = net.createServer();
  await new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', resolve);
  });
  const port = server.address().port;
  await new Promise((resolve) => server.close(resolve));
  return port;
}

function readJsonLines(filePath) {
  return fs.readFileSync(filePath, 'utf8')
    .split('\n')
    .filter(Boolean)
    .map((line) => JSON.parse(line));
}

function ollamaProviderId(args) {
  const providerArg = args.find((arg) => String(arg).startsWith('model_provider='));
  assert.ok(providerArg, 'missing model_provider override');
  const providerId = JSON.parse(providerArg.slice('model_provider='.length));
  assert.match(providerId, /^notty_ollama_[0-9a-f]{32}$/);
  return providerId;
}

function createIrcHarness(t, options = {}) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'notty-collab-irc-'));
  const workspace = path.join(root, 'workspace');
  const fakeBin = path.join(root, 'bin');
  const tmuxState = path.join(root, 'tmux-state');
  const tmuxLog = path.join(root, 'tmux.log');
  const runtimeLog = path.join(root, 'runtime.log');
  const fakeTmux = path.join(fakeBin, 'tmux');
  const fakeCodex = path.join(fakeBin, 'codex');
  const fakeAgy = path.join(fakeBin, 'agy');
  const fakeCurl = path.join(fakeBin, 'curl');

  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  fs.mkdirSync(workspace, { recursive: true });
  fs.mkdirSync(fakeBin, { recursive: true });
  fs.mkdirSync(tmuxState, { recursive: true });
  fs.writeFileSync(tmuxLog, '', 'utf8');
  fs.writeFileSync(runtimeLog, '', 'utf8');

  fs.writeFileSync(fakeTmux, [
    `#!${process.execPath}`,
    "'use strict';",
    "const childProcess = require('node:child_process');",
    "const fs = require('node:fs');",
    "const path = require('node:path');",
    'const args = process.argv.slice(2);',
    "fs.appendFileSync(process.env.TMUX_LOG, `${JSON.stringify(args)}\\n`);",
    "const command = args.includes('has-session') ? 'has-session'",
    "  : args.includes('new-session') ? 'new-session'",
    "    : args.includes('kill-session') ? 'kill-session' : '';",
    "const targetFlag = command === 'has-session' || command === 'kill-session' ? '-t' : '-s';",
    'const targetIndex = args.indexOf(targetFlag);',
    "const target = targetIndex === -1 ? '' : args[targetIndex + 1];",
    "const statePath = path.join(process.env.TMUX_STATE_DIR, target.replace(/[^A-Za-z0-9._-]/g, '-'));",
    "if (command === 'has-session') process.exit(fs.existsSync(statePath) ? 0 : 1);",
    "if (command === 'kill-session') { fs.rmSync(statePath, { force: true }); process.exit(0); }",
    "if (command !== 'new-session') process.exit(0);",
    'const launch = args[args.length - 1];',
    "const result = childProcess.spawnSync('/bin/bash', ['-lc', launch], {",
    '  env: process.env,',
    "  encoding: 'utf8',",
    '});',
    'if (result.error || result.status !== 0) {',
    "  process.stderr.write(result.error ? result.error.message : (result.stderr || result.stdout || 'launch failed'));",
    '  process.exit(result.status || 1);',
    '}',
    "fs.writeFileSync(statePath, 'running\\n', 'utf8');",
    '',
  ].join('\n'), { mode: 0o755 });

  const writeFakeRuntime = (filePath, runtime) => {
    fs.writeFileSync(filePath, [
      `#!${process.execPath}`,
      "'use strict';",
      "const fs = require('node:fs');",
      'fs.appendFileSync(process.env.RUNTIME_LOG, `${JSON.stringify({',
      `  runtime: ${JSON.stringify(runtime)},`,
      '  argv: process.argv.slice(2),',
      '  env: {',
      '    COLLAB_AGENT_ID: process.env.COLLAB_AGENT_ID,',
      '    COLLAB_CHANNEL: process.env.COLLAB_CHANNEL,',
      '    COLLAB_MCP_URL: process.env.COLLAB_MCP_URL,',
      '    COLLAB_MODEL: process.env.COLLAB_MODEL,',
      '    COLLAB_ROLE: process.env.COLLAB_ROLE,',
      '    COLLAB_RUNTIME: process.env.COLLAB_RUNTIME,',
      '    COLLAB_THINK: process.env.COLLAB_THINK,',
      '    MCP_SPAWN_OTP: process.env.MCP_SPAWN_OTP,',
      '    NOTTY_MCP_SPAWN_OTP: process.env.NOTTY_MCP_SPAWN_OTP,',
      '    COLLAB_AGENT_SPAWN_OTP: process.env.COLLAB_AGENT_SPAWN_OTP,',
      '  },',
      '})}\\n`);',
      '',
    ].join('\n'), { mode: 0o755 });
  };
  writeFakeRuntime(fakeCodex, 'codex');
  writeFakeRuntime(fakeAgy, 'agy');
  fs.writeFileSync(fakeCurl, [
    `#!${process.execPath}`,
    "'use strict';",
    'const url = process.argv.at(-1);',
    "if (url.endsWith('/api/tags')) {",
    "  process.stdout.write(JSON.stringify({ models: [{ name: 'ornith:9b' }] }));",
    "} else if (url.endsWith('/api/show')) {",
    "  process.stdout.write(JSON.stringify({ capabilities: ['completion', 'tools'], model_info: { 'ornith.context_length': 32768 } }));",
    '} else {',
    "  process.stderr.write(`unexpected Ollama URL: ${url}`);",
    '  process.exitCode = 22;',
    '}',
    '',
  ].join('\n'), { mode: 0o755 });

  const environment = {
    ...process.env,
    AGY_BIN: fakeAgy,
    CODEX_BIN: fakeCodex,
    CURL_BIN: fakeCurl,
    OLLAMA_BIN: '/definitely/not-used/ollama',
    OLLAMA_HOST: '127.0.0.1:11434',
    PATH: `${fakeBin}:${process.env.PATH}`,
    NOTTY_WORKDIR: workspace,
    SWARM_AGY_BIN: fakeAgy,
    SWARM_CODEX_BIN: fakeCodex,
    SWARM_OLLAMA_BIN: '/definitely/not-used/ollama',
    SWARM_STARTUP_PROBE_DELAY: '0',
    NOTTY_COLLAB_UNSANDBOXED: 'false',
    MCP_SPAWN_OTP: 'parent-client-otp-must-not-leak',
    NOTTY_MCP_SPAWN_OTP: 'parent-server-otp-must-not-leak',
    TMUX_LOG: tmuxLog,
    TMUX_STATE_DIR: tmuxState,
    RUNTIME_LOG: runtimeLog,
    XDG_RUNTIME_DIR: path.join(root, 'runtime'),
  };
  if (options.containerDefault) {
    delete environment.NOTTY_COLLAB_UNSANDBOXED;
    environment.DOCKER_CONTAINER = '1';
  }

  return {
    root,
    workspace,
    tmuxLog,
    runtimeLog,
    env: environment,
  };
}

async function runStandaloneIrc(harness, input) {
  const port = await reservePort();
  const result = childProcess.spawnSync(process.execPath, [
    path.join(appRoot, 'collab.cjs'),
    'irc',
    '--standalone',
    '--fresh',
    '--follow', 'false',
    '--channel', 'lobby',
    '--ip', '127.0.0.1',
    '--port', String(port),
    '--workdir', harness.workspace,
  ], {
    cwd: appRoot,
    encoding: 'utf8',
    input: `${input}\n/quit\n`,
    timeout: 10_000,
    env: harness.env,
  });
  return { port, result };
}

test('standalone IRC accepts a role-only create-agent command', { timeout: 15_000 }, async (t) => {
  const harness = createIrcHarness(t);
  const staleFeedbackPath = path.join(
    harness.workspace,
    'collab',
    'intragent',
    'message_feedback.jsonl',
  );
  fs.mkdirSync(path.dirname(staleFeedbackPath), { recursive: true });
  fs.writeFileSync(staleFeedbackPath, '{"rating":"helpful"}\n', 'utf8');
  const { port, result } = await runStandaloneIrc(
    harness,
    '/create_agent --role irc-coder',
  );

  assert.equal(result.status, 0, `${result.stdout}\n${result.stderr}`);
  assert.equal(fs.existsSync(staleFeedbackPath), false);
  assert.match(result.stdout, /feedback=1/);
  const calls = readJsonLines(harness.tmuxLog);
  assert.ok(
    calls.some((args) => args.includes('has-session') && args.includes('irc-coder')),
    `missing irc-coder has-session call in ${JSON.stringify(calls)}`,
  );
  assert.ok(
    calls.some((args) => args.includes('new-session') && args.includes('irc-coder')),
    `missing irc-coder new-session call in ${JSON.stringify(calls)}`,
  );
  assert.ok(!calls.some((args) => args.includes('-s') && args.includes('--role')));

  const [launch] = readJsonLines(harness.runtimeLog);
  assert.equal(launch.runtime, 'codex');
  assert.deepEqual(
    launch.argv.slice(0, 4),
    ['--sandbox', 'workspace-write', '--ask-for-approval', 'on-request'],
  );
  assert.ok(!launch.argv.includes('--full-auto'));
  assert.equal(launch.env.COLLAB_AGENT_ID, 'irc-coder');
  assert.equal(launch.env.COLLAB_ROLE, 'irc-coder');
  assert.equal(launch.env.COLLAB_RUNTIME, 'codex');
  assert.equal(launch.env.COLLAB_MCP_URL, `http://127.0.0.1:${port}/mcp`);
  assert.equal(launch.env.MCP_SPAWN_OTP, undefined);
  assert.equal(launch.env.NOTTY_MCP_SPAWN_OTP, undefined);

  fs.writeFileSync(harness.runtimeLog, '', 'utf8');
  const legacyParserResult = childProcess.spawnSync(
    path.join(appRoot, 'agents', 'bin', 'create_agent.sh'),
    ['--role', 'legacy-coder'],
    {
      cwd: harness.workspace,
      encoding: 'utf8',
      env: harness.env,
    },
  );
  assert.equal(
    legacyParserResult.status,
    0,
    `${legacyParserResult.stdout}\n${legacyParserResult.stderr}`,
  );
  const [legacyLaunch] = readJsonLines(harness.runtimeLog);
  assert.equal(legacyLaunch.runtime, 'codex');
  assert.equal(legacyLaunch.env.COLLAB_AGENT_ID, 'legacy-coder');
  assert.equal(legacyLaunch.env.COLLAB_ROLE, 'legacy-coder');
  assert.equal(legacyLaunch.env.MCP_SPAWN_OTP, undefined);
  assert.equal(legacyLaunch.env.NOTTY_MCP_SPAWN_OTP, undefined);
  assert.equal(legacyLaunch.env.COLLAB_AGENT_SPAWN_OTP, undefined);
});

test('standalone IRC preserves a quoted Agy model and uses the SSE endpoint', { timeout: 15_000 }, async (t) => {
  const harness = createIrcHarness(t);
  const model = 'Claude Opus 4.6 (Thinking)';
  const { port, result } = await runStandaloneIrc(
    harness,
    `/create_agent --agent agy-coder --role coder --runtime agy --model "${model}"`,
  );

  assert.equal(result.status, 0, `${result.stdout}\n${result.stderr}`);
  const [launch] = readJsonLines(harness.runtimeLog);
  assert.equal(launch.runtime, 'agy');
  assert.deepEqual(
    launch.argv.slice(0, 5),
    ['--model', model, '--mode', 'accept-edits', '--sandbox'],
  );
  const promptIndex = launch.argv.indexOf('--prompt-interactive');
  assert.ok(promptIndex >= 0, `missing --prompt-interactive in ${JSON.stringify(launch.argv)}`);
  assert.match(launch.argv[promptIndex + 1], /You are the coder agent/);
  assert.ok(!launch.argv.includes('--ask-for-approval'));
  assert.ok(!launch.argv.includes('--full-auto'));
  assert.equal(launch.env.COLLAB_AGENT_ID, 'agy-coder');
  assert.equal(launch.env.COLLAB_ROLE, 'coder');
  assert.equal(launch.env.COLLAB_RUNTIME, 'agy');
  assert.equal(launch.env.COLLAB_MODEL, model);
  assert.equal(launch.env.COLLAB_MCP_URL, `http://127.0.0.1:${port}/sse`);
});

test('standalone IRC launches Ollama Codex with MCP, thinking, and safety overrides', { timeout: 15_000 }, async (t) => {
  const harness = createIrcHarness(t);
  const model = 'ornith:9b';
  const { port, result } = await runStandaloneIrc(
    harness,
    `/create_agent --agent ollama-coder --role coder --runtime ollama --model ${model} --think high`,
  );

  assert.equal(result.status, 0, `${result.stdout}\n${result.stderr}`);
  const launch = readJsonLines(harness.runtimeLog)
    .find((entry) => (
      entry.env.COLLAB_RUNTIME === 'ollama'
      && entry.env.COLLAB_AGENT_ID === 'ollama-coder'
      && !entry.argv.includes('--version')
    ));
  assert.ok(launch, 'missing direct Codex/Ollama runtime launch');
  assert.equal(launch.runtime, 'codex');
  assert.deepEqual(launch.argv.slice(0, 2), ['-m', model]);
  const providerId = ollamaProviderId(launch.argv);
  assert.ok(launch.argv.includes(`model_provider=${JSON.stringify(providerId)}`));
  const baseUrlPrefix = `model_providers.${providerId}.base_url=`;
  const baseUrlArg = launch.argv.find((arg) => String(arg).startsWith(baseUrlPrefix));
  assert.ok(baseUrlArg, 'missing relayed Ollama provider URL');
  const baseUrl = new URL(JSON.parse(baseUrlArg.slice(baseUrlPrefix.length)));
  assert.equal(baseUrl.hostname, '127.0.0.1');
  assert.match(baseUrl.port, /^\d+$/);
  assert.equal(baseUrl.pathname, '/v1');
  assert.ok(launch.argv.includes(`model_providers.${providerId}.wire_api="responses"`));
  assert.ok(launch.argv.includes(
    `model_providers.${providerId}.requires_openai_auth=false`,
  ));
  assert.ok(launch.argv.some((arg) => arg.startsWith('model_catalog_json=')));
  assert.equal(launch.argv.includes('--oss'), false);
  assert.equal(launch.argv.includes('launch'), false);

  const mcpUrl = `http://127.0.0.1:${port}/mcp`;
  const mcpIndex = launch.argv.indexOf(
    `mcp_servers.notty_collab_session.url=${JSON.stringify(mcpUrl)}`,
  );
  assert.notEqual(mcpIndex, -1);
  assert.deepEqual(
    launch.argv.slice(mcpIndex - 1, mcpIndex + 3),
    [
      '-c', `mcp_servers.notty_collab_session.url=${JSON.stringify(mcpUrl)}`,
      '-c', 'model_reasoning_effort="high"',
    ],
  );
  assert.deepEqual(
    launch.argv.slice(mcpIndex + 3, mcpIndex + 7),
    ['--sandbox', 'workspace-write', '--ask-for-approval', 'on-request'],
  );
  assert.match(launch.argv.at(-1), /You are the coder agent/);
  assert.match(launch.argv.at(-1), /configured collab MCP service/);

  assert.equal(launch.env.COLLAB_AGENT_ID, 'ollama-coder');
  assert.equal(launch.env.COLLAB_ROLE, 'coder');
  assert.equal(launch.env.COLLAB_RUNTIME, 'ollama');
  assert.equal(launch.env.COLLAB_MODEL, model);
  assert.equal(launch.env.COLLAB_THINK, 'high');
  assert.equal(launch.env.COLLAB_MCP_URL, mcpUrl);
  assert.equal(launch.env.MCP_SPAWN_OTP, undefined);
  assert.equal(launch.env.NOTTY_MCP_SPAWN_OTP, undefined);
  assert.equal(launch.env.COLLAB_AGENT_SPAWN_OTP, undefined);
  assert.doesNotMatch(launch.argv.at(-1), /spawn OTP|MCP_SPAWN_OTP/i);
});

test('standalone IRC rejects attempts to deliver a spawn OTP to an agent', { timeout: 15_000 }, async (t) => {
  const harness = createIrcHarness(t);
  const { result } = await runStandaloneIrc(
    harness,
    '/create_agent --agent otp-agent --spawn-otp must-not-enter-agent-env',
  );

  assert.equal(result.status, 0, `${result.stdout}\n${result.stderr}`);
  assert.match(`${result.stdout}\n${result.stderr}`, /Agent OTP delivery is not supported/i);
  assert.deepEqual(readJsonLines(harness.runtimeLog), []);
  assert.equal(
    readJsonLines(harness.tmuxLog).some((args) => args.includes('new-session')),
    false,
  );
});

test('standalone IRC rejects invalid Ollama launch inputs before tmux launch', { timeout: 15_000 }, async (t) => {
  const harness = createIrcHarness(t);
  const { result } = await runStandaloneIrc(
    harness,
    [
      '/create_agent --agent ollama-no-model --runtime ollama --think high',
      '/create_agent --agent ollama-bad-think --runtime ollama --model ornith:9b --think extreme',
    ].join('\n'),
  );

  assert.equal(result.status, 0, `${result.stdout}\n${result.stderr}`);
  assert.match(`${result.stdout}\n${result.stderr}`, /runtime ollama requires --model/i);
  assert.match(`${result.stdout}\n${result.stderr}`, /unsupported Think level for codex\/ollama: extreme/i);
  assert.deepEqual(readJsonLines(harness.runtimeLog), []);
  const calls = readJsonLines(harness.tmuxLog);
  assert.ok(!calls.some((args) => args.includes('new-session')));
});

test('standalone IRC rejects an unknown create-agent runtime before launch', { timeout: 15_000 }, async (t) => {
  const harness = createIrcHarness(t);
  const { result } = await runStandaloneIrc(
    harness,
    '/create_agent --agent bad-coder --runtime gemini',
  );

  assert.equal(result.status, 0, `${result.stdout}\n${result.stderr}`);
  assert.match(`${result.stdout}\n${result.stderr}`, /unsupported legacy agent runtime: gemini/i);
  assert.deepEqual(readJsonLines(harness.runtimeLog), []);
  const calls = readJsonLines(harness.tmuxLog);
  assert.ok(!calls.some((args) => args.includes('new-session')));
});

test('standalone container defaults bypass Codex and Ollama but keep Agy sandboxed', {
  timeout: 15_000,
}, async (t) => {
  const harness = createIrcHarness(t, { containerDefault: true });
  const { result } = await runStandaloneIrc(
    harness,
    [
      '/create_agent --agent container-codex --role coder --runtime codex',
      '/create_agent --agent container-ollama --role coder --runtime ollama --model ornith:9b',
      '/create_agent --agent container-agy --role coder --runtime agy',
    ].join('\n'),
  );

  assert.equal(result.status, 0, `${result.stdout}\n${result.stderr}`);
  const launches = Object.fromEntries(
    readJsonLines(harness.runtimeLog).map((entry) => [entry.env.COLLAB_AGENT_ID, entry]),
  );
  for (const agent of ['container-codex', 'container-ollama']) {
    assert.ok(launches[agent], `missing ${agent} launch`);
    assert.ok(launches[agent].argv.includes('--dangerously-bypass-approvals-and-sandbox'));
    assert.equal(launches[agent].argv.includes('--sandbox'), false);
    assert.equal(launches[agent].argv.includes('--ask-for-approval'), false);
  }
  assert.ok(launches['container-agy']);
  assert.deepEqual(
    launches['container-agy'].argv.slice(0, 3),
    ['--mode', 'accept-edits', '--sandbox'],
  );
  assert.equal(
    launches['container-agy'].argv.includes('--dangerously-skip-permissions'),
    false,
  );
});
