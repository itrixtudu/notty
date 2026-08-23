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

async function waitForBootstrap(baseUrl, child, output) {
  const deadline = Date.now() + 8_000;
  while (Date.now() < deadline) {
    if (child.exitCode !== null) {
      throw new Error(`collab daemon exited early (${child.exitCode}): ${output()}`);
    }
    try {
      const response = await fetch(`${baseUrl}/admin/v1/bootstrap`);
      if (response.ok) return await response.json();
    } catch {
      // Listener startup is asynchronous.
    }
    await new Promise((resolve) => setTimeout(resolve, 75));
  }
  throw new Error(`collab daemon did not become ready: ${output()}`);
}

async function waitForChannelBody(baseUrl, channel, pattern) {
  const deadline = Date.now() + 4_000;
  while (Date.now() < deadline) {
    const response = await fetch(`${baseUrl}/admin/v1/channels/${channel}/messages?limit=50`);
    if (response.ok) {
      const page = await response.json();
      const match = page.messages.find((message) => pattern.test(message.body));
      if (match) return match;
    }
    await new Promise((resolve) => setTimeout(resolve, 75));
  }
  throw new Error(`message did not reach #${channel}`);
}

async function stopChild(child) {
  if (child.exitCode !== null) return;
  const exited = new Promise((resolve) => child.once('exit', resolve));
  child.kill('SIGTERM');
  let timeout;
  await Promise.race([
    exited,
    new Promise((resolve) => {
      timeout = setTimeout(resolve, 2_000);
      timeout.unref();
    }),
  ]);
  clearTimeout(timeout);
  if (child.exitCode === null) {
    child.kill('SIGKILL');
    await exited;
  }
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

function createFakeTmux(root) {
  const fakeBin = path.join(root, 'bin');
  const stateDir = path.join(root, 'tmux-state');
  const logPath = path.join(root, 'tmux.log');
  const fakeTmux = path.join(fakeBin, 'tmux');
  const fakeCodex = path.join(fakeBin, 'codex');
  const fakeAgy = path.join(fakeBin, 'agy');
  const fakeClaude = path.join(fakeBin, 'claude');
  const fakeCurl = path.join(fakeBin, 'curl');
  fs.mkdirSync(fakeBin, { recursive: true });
  fs.mkdirSync(stateDir, { recursive: true });
  fs.writeFileSync(logPath, '', 'utf8');
  fs.writeFileSync(fakeTmux, [
    `#!${process.execPath}`,
    "'use strict';",
    "const fs = require('node:fs');",
    "const path = require('node:path');",
    'const args = process.argv.slice(2);',
    "fs.appendFileSync(process.env.TMUX_LOG, `${JSON.stringify(args)}\\n`);",
    "const command = args[0] || '';",
    "const targetFlag = command === 'new-session' ? '-s' : '-t';",
    'const targetIndex = args.indexOf(targetFlag);',
    "const target = targetIndex === -1 ? '' : args[targetIndex + 1];",
    "const statePath = path.join(process.env.TMUX_STATE_DIR, target.replace(/[^A-Za-z0-9._-]/g, '-'));",
    "if (command === 'has-session') process.exit(fs.existsSync(statePath) ? 0 : 1);",
    "if (command === 'kill-session') { fs.rmSync(statePath, { force: true }); process.exit(0); }",
    "if (command === 'set-option') {",
    "  if (!fs.existsSync(statePath)) process.exit(1);",
    "  const ownerIndex = args.indexOf('@notty_collab_session');",
    "  fs.writeFileSync(statePath, JSON.stringify({ owner: ownerIndex === -1 ? '' : args[ownerIndex + 1] || '' }));",
    "  process.exit(0);",
    "}",
    "if (command === 'display-message') {",
    "  if (!fs.existsSync(statePath)) process.exit(1);",
    "  const state = JSON.parse(fs.readFileSync(statePath, 'utf8'));",
    "  process.stdout.write(`${state.owner || ''}\\n`);",
    "  process.exit(0);",
    "}",
    "if (command !== 'new-session') process.exit(0);",
    "if (target.includes('forced-launch-failure')) { process.stderr.write('forced launch failure'); process.exit(42); }",
    "if (args.includes('/bin/false')) { process.stderr.write('launch failed'); process.exit(1); }",
    "fs.writeFileSync(statePath, JSON.stringify({ owner: '' }), 'utf8');",
    '',
  ].join('\n'), { mode: 0o755 });
  fs.writeFileSync(fakeCodex, [
    `#!${process.execPath}`,
    "'use strict';",
    "const fs = require('node:fs');",
    "const readline = require('node:readline');",
    "if (process.argv[2] === '--version') { process.stdout.write('codex-test 1.0.0\\n'); process.exit(0); }",
    "if (process.argv[2] !== 'app-server') process.exit(0);",
    "const ids = [",
    "  '019f0000-0000-7000-8000-000000000001',",
    "  '019f0000-0000-7000-8000-000000000002',",
    "];",
    "const input = readline.createInterface({ input: process.stdin });",
    "input.on('line', (line) => {",
    "  const message = JSON.parse(line);",
    "  if (message.method === 'initialize') {",
    "    process.stdout.write(`${JSON.stringify({ id: message.id, result: {} })}\\n`);",
    "    return;",
    "  }",
    "  if (message.method !== 'thread/list') return;",
    "  const launches = fs.readFileSync(process.env.TMUX_LOG, 'utf8')",
    "    .split('\\n')",
    "    .filter(Boolean)",
    "    .map((entry) => JSON.parse(entry))",
    "    .filter((args) => args[0] === 'new-session' && args.includes(process.argv[1]) && !args.includes('resume'));",
    "  const data = launches.map((args, index) => ({",
    "    id: ids[index] || `019f0000-0000-7000-8000-${String(index + 1).padStart(12, '0')}`,",
    "    cwd: process.cwd(),",
    "    preview: args[args.length - 1],",
    "    updatedAt: index + 1,",
    "  }));",
    "  process.stdout.write(`${JSON.stringify({ id: message.id, result: { data, nextCursor: null } })}\\n`);",
    "});",
    '',
  ].join('\n'), { mode: 0o755 });
  fs.writeFileSync(fakeAgy, `#!${process.execPath}\n`, { mode: 0o755 });
  fs.writeFileSync(fakeClaude, `#!${process.execPath}\n`, { mode: 0o755 });
  fs.writeFileSync(fakeCurl, [
    `#!${process.execPath}`,
    "'use strict';",
    'const url = process.argv.at(-1);',
    "if (url.endsWith('/api/tags')) {",
    "  process.stdout.write(JSON.stringify({ models: [{ name: 'ornith:9b', details: { parameter_size: '9B' } }] }));",
    "} else if (url.endsWith('/api/show')) {",
    "  process.stdout.write(JSON.stringify({ capabilities: ['completion', 'tools'], model_info: { 'ornith.context_length': 32768 } }));",
    '} else {',
    "  process.stderr.write(`unexpected Ollama URL: ${url}`);",
    '  process.exitCode = 22;',
    '}',
    '',
  ].join('\n'), { mode: 0o755 });
  return { fakeAgy, fakeBin, fakeClaude, fakeCodex, fakeCurl, logPath, stateDir };
}

test('daemon-backed CLI mutations publish through the admin authority', { timeout: 15_000 }, async () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'notty-collab-daemon-'));
  const workspace = path.join(root, 'workspace');
  const configHome = path.join(root, 'config');
  const stateHome = path.join(root, 'state');
  fs.mkdirSync(workspace, { recursive: true });
  const fakeTmux = createFakeTmux(root);
  const port = await reservePort();
  const baseUrl = `http://127.0.0.1:${port}`;
  let output = '';
  const daemon = childProcess.spawn(process.execPath, [
    path.join(appRoot, 'collab.cjs'),
    'daemon',
    '--workdir', workspace,
    '--ip', '127.0.0.1',
    '--port', String(port),
  ], {
    cwd: appRoot,
    env: {
      ...process.env,
      AGY_BIN: fakeTmux.fakeAgy,
      CLAUDE_BIN: fakeTmux.fakeClaude,
      CODEX_BIN: fakeTmux.fakeCodex,
      CURL_BIN: fakeTmux.fakeCurl,
      OLLAMA_BIN: '/definitely/not-used/ollama',
      OLLAMA_HOST: '127.0.0.1:11434',
      NOTTY_COLLAB_UNSANDBOXED: 'false',
      PATH: `${fakeTmux.fakeBin}:${process.env.PATH}`,
      TMUX_LOG: fakeTmux.logPath,
      TMUX_STATE_DIR: fakeTmux.stateDir,
      XDG_CONFIG_HOME: configHome,
      XDG_RUNTIME_DIR: path.join(root, 'runtime'),
      XDG_STATE_HOME: stateHome,
    },
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  daemon.stdout.on('data', (chunk) => { output += chunk; });
  daemon.stderr.on('data', (chunk) => { output += chunk; });

  try {
    const bootstrap = await waitForBootstrap(baseUrl, daemon, () => output);
    assert.equal(bootstrap.daemon.marker, 'notty-collab-daemon');
    assert.ok(bootstrap.modelCatalog.codex.some((model) => model.id === 'gpt-5.6-sol'));
    assert.ok(Array.isArray(bootstrap.modelCatalog.agy));
    assert.ok(Array.isArray(bootstrap.modelCatalog.ollama));
    assert.ok(bootstrap.modelCatalog.ollama.some((model) => model.id === 'ornith:9b'));

    const runCli = (...args) => childProcess.spawnSync(process.execPath, [
      path.join(appRoot, 'collab.cjs'),
      ...args,
      '--server', baseUrl,
      '--workdir', workspace,
    ], { cwd: appRoot, encoding: 'utf8' });

    const sent = runCli('send', '--agent', 'operator', '--channel', 'lobby', '--body', 'first');
    assert.equal(sent.status, 0, sent.stderr);
    assert.match(sent.stdout, /first/);

    const firstPage = await fetch(`${baseUrl}/admin/v1/channels/lobby/messages?limit=10`).then((res) => res.json());
    assert.equal(firstPage.messages.length, 1);
    assert.equal(firstPage.messages[0].body, 'first');
    assert.ok(Number.isInteger(firstPage.cursor));

    const second = runCli('send', '--agent', 'qa', '--channel', 'lobby', '--body', 'second');
    assert.equal(second.status, 0, second.stderr);
    assert.equal(runCli('send', '--agent', 'dev', '--channel', 'lobby', '--body', 'third').status, 0);
    assert.equal(runCli('send', '--agent', 'coder', '--channel', 'lobby', '--body', 'fourth').status, 0);
    const delta = await fetch(
      `${baseUrl}/admin/v1/channels/lobby/messages?limit=2&cursor=${firstPage.cursor}`,
    ).then((res) => res.json());
    assert.deepEqual(delta.messages.map((message) => message.body), ['second', 'third']);
    const nextDelta = await fetch(
      `${baseUrl}/admin/v1/channels/lobby/messages?limit=2&cursor=${delta.cursor}`,
    ).then((res) => res.json());
    assert.deepEqual(nextDelta.messages.map((message) => message.body), ['fourth']);

    const boundedChannelPath = path.join(workspace, 'collab', 'intragent', 'channels', 'bounded.jsonl');
    const largeRecord = (id, marker) => JSON.stringify({
      id,
      timestamp: new Date().toISOString(),
      kind: 'message',
      agent_id: 'load-test',
      channel: 'bounded',
      to: 'all',
      body: `${marker}:${'x'.repeat(600 * 1024)}`,
    });
    fs.appendFileSync(
      boundedChannelPath,
      `${largeRecord('bounded-1', 'first-large')}\n${largeRecord('bounded-2', 'second-large')}\n`,
      'utf8',
    );

    const boundedRecent = await fetch(
      `${baseUrl}/admin/v1/channels/bounded/messages?limit=2`,
    ).then((res) => res.json());
    assert.equal(boundedRecent.messages.length, 1);
    assert.equal(boundedRecent.messages[0].body.startsWith('second-large:'), true);

    const boundedFirst = await fetch(
      `${baseUrl}/admin/v1/channels/bounded/messages?limit=2&cursor=0`,
    ).then((res) => res.json());
    assert.equal(boundedFirst.messages.length, 1);
    assert.equal(boundedFirst.messages[0].body.startsWith('first-large:'), true);
    assert.ok(boundedFirst.cursor > 0 && boundedFirst.cursor <= 1024 * 1024);
    const boundedSecond = await fetch(
      `${baseUrl}/admin/v1/channels/bounded/messages?limit=2&cursor=${boundedFirst.cursor}`,
    ).then((res) => res.json());
    assert.equal(boundedSecond.messages.length, 1);
    assert.equal(boundedSecond.messages[0].body.startsWith('second-large:'), true);
    assert.equal(boundedSecond.cursor, fs.statSync(boundedChannelPath).size);

    const nearLimitStart = fs.statSync(boundedChannelPath).size;
    const nearLimitBody = `near-limit:${'y'.repeat((1024 * 1024) - 1024)}`;
    const nearLimitPost = await fetch(
      `${baseUrl}/admin/v1/channels/bounded/messages`,
      {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ body: nearLimitBody }),
      },
    );
    assert.equal(nearLimitPost.status, 201);
    const nearLimitPage = await fetch(
      `${baseUrl}/admin/v1/channels/bounded/messages?limit=1&cursor=${nearLimitStart}`,
    ).then((res) => res.json());
    assert.equal(nearLimitPage.messages.length, 1);
    assert.equal(nearLimitPage.messages[0].body, nearLimitBody);
    assert.equal(nearLimitPage.cursor, fs.statSync(boundedChannelPath).size);

    const exactChannelPath = path.join(workspace, 'collab', 'intragent', 'channels', 'exact-boundary.jsonl');
    const exactRecord = {
      id: 'exact-boundary',
      timestamp: new Date().toISOString(),
      kind: 'message',
      agent_id: 'load-test',
      channel: 'exact-boundary',
      to: 'all',
      body: '',
    };
    const exactReadBoundary = (1024 * 1024) + (64 * 1024);
    const exactOverhead = Buffer.byteLength(`${JSON.stringify(exactRecord)}\n`, 'utf8');
    exactRecord.body = 'z'.repeat(exactReadBoundary - exactOverhead);
    const exactSerialized = `${JSON.stringify(exactRecord)}\n`;
    assert.equal(Buffer.byteLength(exactSerialized, 'utf8'), exactReadBoundary);
    fs.writeFileSync(exactChannelPath, exactSerialized, 'utf8');
    const exactRecent = await fetch(
      `${baseUrl}/admin/v1/channels/exact-boundary/messages?limit=1`,
    ).then((res) => res.json());
    assert.equal(exactRecent.messages.length, 1);
    assert.equal(exactRecent.messages[0].id, exactRecord.id);

    const mirrored = runCli(
      'mirror',
      '--follow', 'false',
      '--replay-lines', '1',
      '--source-channel', 'lobby',
      '--target-channel', 'review',
      '--to', 'qa',
    );
    assert.equal(mirrored.status, 0, mirrored.stderr);
    const review = await fetch(`${baseUrl}/admin/v1/channels/review/messages?limit=10`).then((res) => res.json());
    assert.equal(review.messages.length, 1);
    assert.match(review.messages[0].body, /fourth/);
    assert.match(runCli('channels').stdout, /review/);
    assert.match(runCli('who', '--channel', 'lobby').stdout, /qa/);

    const mirrorFollower = childProcess.spawn(process.execPath, [
      path.join(appRoot, 'collab.cjs'),
      'mirror',
      '--all-channels',
      '--follow', 'true',
      '--target-channel', 'audit',
      '--to', 'qa',
      '--server', baseUrl,
      '--workdir', workspace,
    ], { cwd: appRoot, stdio: ['ignore', 'pipe', 'pipe'] });
    let mirrorOutput = '';
    mirrorFollower.stdout.on('data', (chunk) => { mirrorOutput += chunk; });
    mirrorFollower.stderr.on('data', (chunk) => { mirrorOutput += chunk; });
    try {
      const mirrorDeadline = Date.now() + 4_000;
      while (!mirrorOutput.includes('mirror:') && Date.now() < mirrorDeadline) {
        await new Promise((resolve) => setTimeout(resolve, 25));
      }
      assert.match(mirrorOutput, /mirror:/);
      assert.equal(runCli('send', '--agent', 'dev', '--channel', 'new-channel', '--body', 'new source').status, 0);
      const relayed = await waitForChannelBody(baseUrl, 'audit', /new source/);
      assert.match(relayed.body, /src #new-channel/);
    } finally {
      await stopChild(mirrorFollower);
    }

    const rejectedFresh = runCli('send', '--fresh', '--agent', 'qa', '--body', 'discarded');
    assert.equal(rejectedFresh.status, 1);
    assert.match(rejectedFresh.stderr, /--fresh is not valid/);

    const malformed = await fetch(`${baseUrl}/admin/v1/session`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: '{',
    });
    assert.equal(malformed.status, 400);

    const simpleCrossSite = await fetch(`${baseUrl}/admin/v1/commands/tmux-send`, {
      method: 'POST',
      headers: {
        'Content-Type': 'text/plain',
        Origin: 'https://attacker.example',
      },
      body: JSON.stringify({ target: 'anything', body: 'echo unsafe', enter: true }),
    });
    assert.equal(simpleCrossSite.status, 415);
    const jsonCrossSite = await fetch(`${baseUrl}/admin/v1/session`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Origin: 'https://attacker.example',
        'Sec-Fetch-Site': 'cross-site',
      },
      body: '{}',
    });
    assert.equal(jsonCrossSite.status, 403);

    const agyModel = 'Claude Opus 4.6 (Thinking)';
    const agyAgent = runCli(
      'create-agent',
      '--agent', 'agy-daemon',
      '--role', 'coder',
      '--runtime', 'agy',
      '--model', agyModel,
      '--think', 'high',
    );
    assert.equal(agyAgent.status, 0, `${agyAgent.stdout}\n${agyAgent.stderr}`);
    const agyLaunch = readJsonLines(fakeTmux.logPath)
      .find((args) => args.includes('new-session') && args.includes('agy-daemon'));
    assert.ok(agyLaunch, 'missing Agy tmux new-session call');
    assert.ok(agyLaunch.includes(`COLLAB_MCP_URL=${baseUrl}/sse`));
    assert.ok(agyLaunch.includes('COLLAB_RUNTIME=agy'));
    assert.ok(agyLaunch.includes(`COLLAB_MODEL=${agyModel}`));
    const executableIndex = agyLaunch.indexOf(fakeTmux.fakeAgy);
    assert.notEqual(executableIndex, -1);
    assert.deepEqual(
      agyLaunch.slice(executableIndex, executableIndex + 9),
      [
        fakeTmux.fakeAgy,
        '--model', agyModel,
        '--effort', 'high',
        '--mode', 'accept-edits',
        '--sandbox',
        '--prompt-interactive',
      ],
    );
    const promptIndex = agyLaunch.indexOf('--prompt-interactive');
    const bootstrapPrompt = agyLaunch[promptIndex + 1];
    assert.match(bootstrapPrompt, new RegExp(`${baseUrl}/sse`));
    assert.match(bootstrapPrompt, /Your coordination channel is lobby\./);
    assert.match(bootstrapPrompt, /Use set_nickname\(\) to set your nickname to agy-daemon/);
    assert.match(
      bootstrapPrompt,
      /call set_status\("idle"\) and wait for explicit instructions or a Notty pending-work nudge/,
    );
    assert.match(
      bootstrapPrompt,
      /Do not call claim_pending\(\), read_messages\(\), or send_message\(\) during startup\./,
    );
    assert.match(bootstrapPrompt, /Do not poll, announce readiness, or invent work\./);
    assert.doesNotMatch(bootstrapPrompt, /claim_pending\(\) whenever you become idle/);
    assert.doesNotMatch(bootstrapPrompt, /report status in lobby/);

    const claudeAgent = runCli(
      'create-agent',
      '--agent', 'claude-daemon',
      '--role', 'bofh',
      '--harness', 'claude',
      '--backend', 'default',
      '--model', 'sonnet',
      '--think', 'low',
    );
    assert.equal(claudeAgent.status, 0, `${claudeAgent.stdout}\n${claudeAgent.stderr}`);
    const claudeLaunch = readJsonLines(fakeTmux.logPath)
      .find((args) => args.includes('new-session') && args.includes('claude-daemon'));
    assert.ok(claudeLaunch, 'missing Claude tmux new-session call');
    const claudeIndex = claudeLaunch.indexOf(fakeTmux.fakeClaude);
    assert.notEqual(claudeIndex, -1);
    assert.deepEqual(claudeLaunch.slice(claudeIndex, claudeIndex + 5), [
      fakeTmux.fakeClaude,
      '--model', 'sonnet',
      '--effort', 'low',
    ]);
    assert.ok(claudeLaunch.includes('--mcp-config'));
    assert.ok(claudeLaunch.includes('--session-id'));
    assert.ok(claudeLaunch.includes('COLLAB_HARNESS=claude'));
    assert.ok(claudeLaunch.includes('COLLAB_BACKEND=default'));

    const ollamaModel = 'ornith:9b';
    const ollamaAgent = runCli(
      'create-agent',
      '--agent', 'ollama-daemon',
      '--role', 'coder',
      '--runtime', 'ollama',
      '--model', ollamaModel,
      '--think', 'high',
    );
    assert.equal(ollamaAgent.status, 0, `${ollamaAgent.stdout}\n${ollamaAgent.stderr}`);
    const ollamaLaunch = readJsonLines(fakeTmux.logPath)
      .find((args) => args.includes('new-session') && args.includes('ollama-daemon'));
    assert.ok(ollamaLaunch, 'missing Ollama tmux new-session call');
    assert.ok(ollamaLaunch.includes(`COLLAB_MCP_URL=${baseUrl}/mcp`));
    assert.ok(ollamaLaunch.includes('COLLAB_RUNTIME=ollama'));
    assert.ok(ollamaLaunch.includes(`COLLAB_MODEL=${ollamaModel}`));
    assert.ok(ollamaLaunch.includes('COLLAB_THINK=high'));

    const ollamaIndex = ollamaLaunch.indexOf(fakeTmux.fakeCodex);
    assert.notEqual(ollamaIndex, -1);
    const ollamaArgs = ollamaLaunch.slice(ollamaIndex + 1);
    assert.deepEqual(ollamaArgs.slice(0, 2), ['-m', ollamaModel]);
    const providerId = ollamaProviderId(ollamaArgs);
    assert.ok(ollamaArgs.includes(`model_provider=${JSON.stringify(providerId)}`));
    assert.ok(ollamaArgs.includes(
      `model_providers.${providerId}.base_url="http://127.0.0.1:11434/v1"`,
    ));
    assert.ok(ollamaArgs.includes(`model_providers.${providerId}.wire_api="responses"`));
    assert.ok(ollamaArgs.includes(
      `model_providers.${providerId}.requires_openai_auth=false`,
    ));
    const catalogArg = ollamaArgs.find((arg) => arg.startsWith('model_catalog_json='));
    assert.ok(catalogArg);
    const catalogPath = JSON.parse(catalogArg.slice('model_catalog_json='.length));
    assert.equal(fs.existsSync(catalogPath), true);
    assert.equal(fs.statSync(catalogPath).mode & 0o777, 0o600);
    assert.equal(ollamaArgs.includes('--oss'), false);
    assert.equal(ollamaArgs.includes('launch'), false);
    const mcpConfigIndex = ollamaArgs.indexOf(
      `mcp_servers.notty_collab_session.url=${JSON.stringify(`${baseUrl}/mcp`)}`,
    );
    assert.notEqual(mcpConfigIndex, -1);
    assert.deepEqual(ollamaArgs.slice(mcpConfigIndex - 1, mcpConfigIndex + 7), [
      '-c', `mcp_servers.notty_collab_session.url=${JSON.stringify(`${baseUrl}/mcp`)}`,
      '-c', 'model_reasoning_effort="high"',
      '--sandbox', 'workspace-write',
      '--ask-for-approval', 'on-request',
    ]);
    assert.match(ollamaArgs.at(-1), /You are the coder agent/);
    assert.match(ollamaArgs.at(-1), new RegExp(`${baseUrl}/mcp`));

    const duplicateOllama = runCli(
      'create-agent',
      '--agent', 'ollama-daemon',
      '--runtime', 'ollama',
      '--model', ollamaModel,
      '--ollama-endpoint', 'http://0.0.0.0:11434',
    );
    assert.equal(duplicateOllama.status, 1);
    assert.match(duplicateOllama.stderr, /managed agent already exists: ollama-daemon/i);
    assert.doesNotMatch(duplicateOllama.stderr, /wildcard bind address/i);

    const catalogRoot = path.join(root, 'runtime', 'notty-ollama');
    const catalogsBeforeFailedLaunch = new Set(
      fs.readdirSync(catalogRoot).filter((name) => name.endsWith('.json')),
    );
    const failedOllamaLaunch = runCli(
      'create-agent',
      '--agent', 'ollama-forced-launch-failure',
      '--runtime', 'ollama',
      '--model', ollamaModel,
    );
    assert.equal(failedOllamaLaunch.status, 1);
    assert.match(failedOllamaLaunch.stderr, /forced launch failure/i);
    assert.deepEqual(
      new Set(fs.readdirSync(catalogRoot).filter((name) => name.endsWith('.json'))),
      catalogsBeforeFailedLaunch,
    );

    const ollamaResumeId = '019f0000-0000-7000-8000-000000000098';
    const resumedOllama = runCli(
      'resume-agent',
      '--agent', 'ollama-resumed-daemon',
      '--session-id', ollamaResumeId,
      '--runtime', 'ollama',
      '--model', ollamaModel,
      '--think', 'low',
    );
    assert.equal(resumedOllama.status, 0, `${resumedOllama.stdout}\n${resumedOllama.stderr}`);
    const ollamaResumeLaunch = readJsonLines(fakeTmux.logPath)
      .find((args) => args.includes('new-session') && args.includes('ollama-resumed-daemon'));
    const ollamaResumeIndex = ollamaResumeLaunch.indexOf(fakeTmux.fakeCodex);
    assert.notEqual(ollamaResumeIndex, -1);
    const ollamaResumeArgs = ollamaResumeLaunch.slice(ollamaResumeIndex + 1);
    assert.deepEqual(ollamaResumeArgs.slice(0, 2), ['-m', ollamaModel]);
    const resumeProviderId = ollamaProviderId(ollamaResumeArgs);
    assert.notEqual(resumeProviderId, providerId);
    assert.deepEqual(ollamaResumeArgs.slice(-2), ['resume', ollamaResumeId]);
    assert.ok(
      ollamaResumeArgs.indexOf('model_reasoning_effort="low"')
        < ollamaResumeArgs.indexOf('resume'),
    );
    assert.equal(ollamaResumeArgs.includes('--oss'), false);

    const disableThink = await fetch(`${baseUrl}/admin/v1/commands/add-agent`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        agent: 'ollama-daemon',
        target: 'ollama-daemon',
        runtime: 'ollama',
        model: ollamaModel,
        think: false,
      }),
    });
    assert.equal(disableThink.status, 200);
    assert.equal((await disableThink.json()).result.think, 'none');

    const missingOllamaModel = runCli(
      'create-agent',
      '--agent', 'ollama-no-model',
      '--runtime', 'ollama',
      '--think', 'high',
    );
    assert.equal(missingOllamaModel.status, 1);
    assert.match(missingOllamaModel.stderr, /runtime ollama requires --model/i);
    const invalidOllamaThink = runCli(
      'create-agent',
      '--agent', 'ollama-bad-think',
      '--runtime', 'ollama',
      '--model', ollamaModel,
      '--think', 'extreme',
    );
    assert.equal(invalidOllamaThink.status, 1);
    assert.match(invalidOllamaThink.stderr, /unsupported Think level for codex\/ollama: extreme/i);
    const rejectedLaunches = readJsonLines(fakeTmux.logPath);
    assert.ok(!rejectedLaunches.some((args) => args.includes('ollama-no-model')));
    assert.ok(!rejectedLaunches.some((args) => args.includes('ollama-bad-think')));

    const resumedThreadId = '019f0000-0000-7000-8000-000000000099';
    const resumedAgent = runCli(
      'resume-agent',
      '--agent', 'resumed-daemon',
      '--session-id', resumedThreadId,
      '--codex-bin', '/bin/true',
    );
    assert.equal(resumedAgent.status, 0, `${resumedAgent.stdout}\n${resumedAgent.stderr}`);
    const managedDocument = JSON.parse(fs.readFileSync(
      path.join(workspace, 'collab', 'intragent', 'managed_agents.json'),
      'utf8',
    ));
    assert.equal(
      managedDocument['resumed-daemon'].runtime_session_id,
      resumedThreadId,
    );
    assert.equal(
      managedDocument['resumed-daemon'].permission_mode,
      'workspace-write',
    );

    const claudeResumeId = '11111111-2222-4333-8444-555555555555';
    const resumedClaude = runCli(
      'resume-agent',
      '--agent', 'claude-resumed-daemon',
      '--session-id', claudeResumeId,
      '--harness', 'claude',
      '--model', 'opus',
      '--think', 'high',
    );
    assert.equal(resumedClaude.status, 0, `${resumedClaude.stdout}\n${resumedClaude.stderr}`);
    const claudeResumeLaunch = readJsonLines(fakeTmux.logPath)
      .find((args) => args.includes('new-session') && args.includes('claude-resumed-daemon'));
    const resumedClaudeIndex = claudeResumeLaunch.indexOf(fakeTmux.fakeClaude);
    assert.notEqual(resumedClaudeIndex, -1);
    assert.deepEqual(claudeResumeLaunch.slice(-4), [
      '--name', 'claude-resumed-daemon', '--resume', claudeResumeId,
    ]);
    assert.equal(claudeResumeLaunch.includes('--session-id'), false);

    const failedAgent = runCli(
      'create-agent',
      '--agent', 'doomed',
      '--codex-bin', '/bin/false',
    );
    assert.equal(failedAgent.status, 1);
    const managed = runCli('managed-agents');
    assert.equal(managed.status, 0, managed.stderr);
    assert.doesNotMatch(managed.stdout, /doomed/);
    assert.equal((await fetch(`${baseUrl}/admin/v1/bootstrap`)).status, 200);
  } finally {
    await stopChild(daemon);
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test('HTTP session launches honor human and agent coordinator rosters', {
  timeout: 15_000,
}, async () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'notty-collab-container-http-'));
  const workspace = path.join(root, 'workspace');
  const configHome = path.join(root, 'config');
  const stateHome = path.join(root, 'state');
  fs.mkdirSync(workspace, { recursive: true });
  const fakeTmux = createFakeTmux(root);
  const port = await reservePort();
  const baseUrl = `http://127.0.0.1:${port}`;
  let output = '';
  const environment = {
    ...process.env,
    CODEX_BIN: fakeTmux.fakeCodex,
    DOCKER_CONTAINER: '1',
    NOTTY_NOSH_PROFILES: 'agents',
    PATH: `${fakeTmux.fakeBin}:${process.env.PATH}`,
    TMUX_LOG: fakeTmux.logPath,
    TMUX_STATE_DIR: fakeTmux.stateDir,
    XDG_CONFIG_HOME: configHome,
    XDG_STATE_HOME: stateHome,
  };
  delete environment.NOTTY_COLLAB_UNSANDBOXED;
  const daemon = childProcess.spawn(process.execPath, [
    path.join(appRoot, 'collab.cjs'),
    'daemon',
    '--workdir', workspace,
    '--ip', '127.0.0.1',
    '--port', String(port),
  ], {
    cwd: appRoot,
    env: environment,
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  daemon.stdout.on('data', (chunk) => { output += chunk; });
  daemon.stderr.on('data', (chunk) => { output += chunk; });

  try {
    await waitForBootstrap(baseUrl, daemon, () => output);
    const configResponse = await fetch(`${baseUrl}/admin/v1/config`);
    const configPayload = await configResponse.json();
    assert.equal(configResponse.status, 200, JSON.stringify(configPayload));
    const workspaceDocument = {
      ...configPayload.documents.workspace,
      templates: {
        ...(configPayload.documents.workspace.templates || {}),
        'coordinator-only': {
          label: 'Coordinator Only',
          layout: 'grid',
          channel: 'lobby',
          defaultCoordinatorMode: 'human',
          requiredNoshProfiles: [],
          agents: ['coordinator_codex_gpt-5.4'],
        },
      },
    };
    const configWrite = await fetch(`${baseUrl}/admin/v1/config/workspace`, {
      method: 'PUT',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        revision: configPayload.revisions.workspace,
        document: workspaceDocument,
      }),
    });
    assert.equal(configWrite.status, 200, await configWrite.text());

    const launchesBeforeRejection = fs.existsSync(fakeTmux.logPath)
      ? readJsonLines(fakeTmux.logPath).filter((args) => args.includes('new-session')).length
      : 0;
    const rejectedResponse = await fetch(`${baseUrl}/admin/v1/session`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        templateId: 'coordinator-only',
        coordinatorMode: 'human',
      }),
    });
    const rejectedPayload = await rejectedResponse.json();
    assert.equal(rejectedResponse.status, 422, JSON.stringify(rejectedPayload));
    assert.equal(rejectedPayload.error.code, 422);
    assert.match(rejectedPayload.error.message, /human coordinator mode.*worker agent/i);
    const launchesAfterRejection = fs.existsSync(fakeTmux.logPath)
      ? readJsonLines(fakeTmux.logPath).filter((args) => args.includes('new-session')).length
      : 0;
    assert.equal(launchesAfterRejection, launchesBeforeRejection);

    const response = await fetch(`${baseUrl}/admin/v1/session`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        templateId: 'pair-review',
        coordinatorMode: 'human',
      }),
    });
    const payload = await response.json();
    assert.equal(response.status, 201, JSON.stringify(payload));
    assert.deepEqual(payload.session.agents.map((agent) => agent.id), ['qa']);
    assert.deepEqual(payload.session.templateSnapshot.agents, ['qa_codex_gpt-5.6-sol']);
    assert.equal(payload.session.agents.some((agent) => agent.coordinatorCapable), false);
    assert.ok(payload.session.agents.every(
      (agent) => agent.permissionMode === 'danger-full-access',
    ));

    const agentMessageResponse = await fetch(`${baseUrl}/admin/v1/commands/send`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        agent: 'qa',
        channel: 'metrics',
        to: 'coordinator',
        body: 'agent telemetry message',
      }),
    });
    const agentMessagePayload = await agentMessageResponse.json();
    assert.equal(agentMessageResponse.status, 200, JSON.stringify(agentMessagePayload));
    const agentMessage = agentMessagePayload.result;
    assert.equal(agentMessage.schema_version, 2);
    assert.equal(agentMessage.session_id, payload.session.id);
    assert.equal(agentMessage.session_agent_id, 'qa');
    assert.equal(agentMessage.author_type, 'agent');
    assert.equal(agentMessage.author_snapshot.role, 'qa');

    const humanMessageResponse = await fetch(`${baseUrl}/admin/v1/channels/metrics/messages`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ agent: 'qa', body: 'human telemetry message' }),
    });
    const humanMessagePayload = await humanMessageResponse.json();
    assert.equal(humanMessageResponse.status, 201, JSON.stringify(humanMessagePayload));
    assert.equal(humanMessagePayload.message.author_type, 'human');
    assert.equal(humanMessagePayload.message.session_id, null);

    const feedbackResponse = await fetch(
      `${baseUrl}/admin/v1/channels/metrics/messages/${agentMessage.id}/feedback`,
      {
        method: 'PUT',
        headers: {
          'content-type': 'application/json',
          'x-notty-collab-operator': 'alice',
        },
        body: JSON.stringify({ rating: 'helpful' }),
      },
    );
    const feedbackPayload = await feedbackResponse.json();
    assert.equal(feedbackResponse.status, 200, JSON.stringify(feedbackPayload));
    assert.equal(feedbackPayload.feedback.viewerRating, 'helpful');
    assert.equal(feedbackPayload.feedback.helpfulPercentage, 100);

    const metricsPage = await fetch(
      `${baseUrl}/admin/v1/channels/metrics/messages?limit=10`,
      { headers: { 'x-notty-collab-operator': 'alice' } },
    ).then((entry) => entry.json());
    const enrichedAgentMessage = metricsPage.messages.find(
      (entry) => entry.id === agentMessage.id,
    );
    assert.equal(enrichedAgentMessage.feedback.viewerRating, 'helpful');
    assert.equal(enrichedAgentMessage.feedback.rated, 1);
    assert.ok(Number.isInteger(metricsPage.cursor));

    const statsResponse = await fetch(`${baseUrl}/admin/v1/stats?scope=session`);
    const statsPayload = await statsResponse.json();
    assert.equal(statsResponse.status, 200, JSON.stringify(statsPayload));
    assert.equal(statsPayload.scope, 'session');
    assert.equal(statsPayload.sessionId, payload.session.id);
    assert.equal(statsPayload.totals.messages, 1);
    assert.equal(statsPayload.totals.helpful, 1);
    assert.equal(statsPayload.rows[0].sessionAgentId, 'qa');

    const launches = readJsonLines(fakeTmux.logPath)
      .filter((args) => args.includes('new-session'));
    assert.equal(launches.length, 1);
    assert.ok(launches[0].includes('MYID=qa'));
    assert.equal(launches[0].includes('MYID=coordinator'), false);
    for (const launch of launches) {
      const codexIndex = launch.indexOf(fakeTmux.fakeCodex);
      assert.notEqual(codexIndex, -1);
      assert.ok(launch.includes('--dangerously-bypass-approvals-and-sandbox'));
      assert.equal(launch.includes('--sandbox'), false);
      assert.equal(launch.includes('--ask-for-approval'), false);
    }

    const agent = payload.session.agents[0];
    const safeResponse = await fetch(
      `${baseUrl}/admin/v1/session/agents/${encodeURIComponent(agent.id)}/permission-mode`,
      {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ permissionMode: 'workspace-write' }),
      },
    );
    const safePayload = await safeResponse.json();
    assert.equal(safeResponse.status, 200, JSON.stringify(safePayload));
    const safeAgent = safePayload.session.agents.find((entry) => entry.id === agent.id);
    assert.equal(safeAgent.permissionMode, 'workspace-write');
    assert.equal(
      safeAgent.runtimeSessionId,
      '019f0000-0000-7000-8000-000000000001',
    );

    const resumedLaunch = readJsonLines(fakeTmux.logPath)
      .filter((args) => args.includes('new-session') && args.includes(agent.tmuxTarget))
      .at(-1);
    const codexIndex = resumedLaunch.indexOf(fakeTmux.fakeCodex);
    assert.notEqual(codexIndex, -1);
    assert.deepEqual(resumedLaunch.slice(-6), [
      '--sandbox',
      'workspace-write',
      '--ask-for-approval',
      'on-request',
      'resume',
      safeAgent.runtimeSessionId,
    ]);
    assert.equal(
      resumedLaunch.includes('--dangerously-bypass-approvals-and-sandbox'),
      false,
    );

    const persistedResponse = await fetch(`${baseUrl}/admin/v1/session`);
    const persistedPayload = await persistedResponse.json();
    assert.equal(persistedResponse.status, 200, JSON.stringify(persistedPayload));
    assert.deepEqual(persistedPayload.session.agents.map((entry) => entry.id), ['qa']);
    assert.deepEqual(
      persistedPayload.session.templateSnapshot.agents,
      ['qa_codex_gpt-5.6-sol'],
    );

    const stopPair = await fetch(`${baseUrl}/admin/v1/session`, {
      method: 'DELETE',
      headers: { 'content-type': 'application/json' },
    });
    assert.equal(stopPair.status, 200, await stopPair.text());
    const deliveryLaunchBaseline = readJsonLines(fakeTmux.logPath)
      .filter((args) => args.includes('new-session')).length;
    const deliveryResponse = await fetch(`${baseUrl}/admin/v1/session`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        templateId: 'delivery-team',
        coordinatorMode: 'human',
      }),
    });
    const deliveryPayload = await deliveryResponse.json();
    assert.equal(deliveryResponse.status, 201, JSON.stringify(deliveryPayload));
    assert.deepEqual(
      deliveryPayload.session.agents.map((entry) => entry.id),
      ['dev', 'coder', 'qa'],
    );
    assert.deepEqual(deliveryPayload.session.templateSnapshot.agents, [
      'dev_codex_gpt-5.6-sol',
      'coder_codex_gpt-5.6-sol',
      'qa_codex_gpt-5.6-sol',
    ]);
    assert.equal(
      deliveryPayload.session.agents.some((entry) => entry.coordinatorCapable),
      false,
    );
    const deliveryLaunches = readJsonLines(fakeTmux.logPath)
      .filter((args) => args.includes('new-session'))
      .slice(deliveryLaunchBaseline);
    assert.deepEqual(
      deliveryLaunches.map((args) => args.find((arg) => arg.startsWith('MYID='))),
      ['MYID=dev', 'MYID=coder', 'MYID=qa'],
    );

    const stopDelivery = await fetch(`${baseUrl}/admin/v1/session`, {
      method: 'DELETE',
      headers: { 'content-type': 'application/json' },
    });
    assert.equal(stopDelivery.status, 200, await stopDelivery.text());
    const agentLaunchBaseline = readJsonLines(fakeTmux.logPath)
      .filter((args) => args.includes('new-session')).length;
    const agentResponse = await fetch(`${baseUrl}/admin/v1/session`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        templateId: 'pair-review',
        coordinatorMode: 'agent',
      }),
    });
    const agentPayload = await agentResponse.json();
    assert.equal(agentResponse.status, 201, JSON.stringify(agentPayload));
    assert.deepEqual(
      agentPayload.session.agents.map((entry) => entry.id),
      ['coordinator', 'qa'],
    );
    assert.equal(
      agentPayload.session.agents.filter((entry) => entry.coordinatorCapable).length,
      1,
    );
    assert.deepEqual(agentPayload.session.templateSnapshot.agents, [
      'coordinator_codex_gpt-5.6-sol',
      'qa_codex_gpt-5.6-sol',
    ]);
    const agentLaunches = readJsonLines(fakeTmux.logPath)
      .filter((args) => args.includes('new-session'))
      .slice(agentLaunchBaseline);
    assert.deepEqual(
      agentLaunches.map((args) => args.find((arg) => arg.startsWith('MYID='))),
      ['MYID=coordinator', 'MYID=qa'],
    );
  } finally {
    await stopChild(daemon);
    fs.rmSync(root, { recursive: true, force: true });
  }
});
