'use strict';

const assert = require('node:assert/strict');
const childProcess = require('node:child_process');
const crypto = require('node:crypto');
const fs = require('node:fs');
const net = require('node:net');
const os = require('node:os');
const path = require('node:path');
const test = require('node:test');

const appRoot = path.resolve(__dirname, '..');
const collabPath = path.join(appRoot, 'collab.cjs');
const tmuxLookup = childProcess.spawnSync(
  '/bin/sh',
  ['-c', 'command -v tmux'],
  { encoding: 'utf8' },
);
const realTmux = tmuxLookup.status === 0 ? tmuxLookup.stdout.trim() : '';

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

async function waitForBootstrap(baseUrl, daemon, output) {
  const deadline = Date.now() + 10_000;
  while (Date.now() < deadline) {
    if (daemon.exitCode !== null) {
      throw new Error(`collab daemon exited early (${daemon.exitCode}): ${output()}`);
    }
    try {
      const response = await fetch(`${baseUrl}/admin/v1/bootstrap`);
      if (response.ok) return await response.json();
    } catch {
      // The listener starts asynchronously.
    }
    await new Promise((resolve) => setTimeout(resolve, 75));
  }
  throw new Error(`collab daemon did not become ready: ${output()}`);
}

async function postCommand(baseUrl, name, body) {
  const response = await fetch(`${baseUrl}/admin/v1/commands/${name}`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(body),
  });
  const text = await response.text();
  assert.equal(response.status, 200, `${name} failed: ${text}`);
  return JSON.parse(text);
}

async function waitForPane(baseUrl, session, predicate) {
  const deadline = Date.now() + 8_000;
  let pane = '';
  while (Date.now() < deadline) {
    const response = await postCommand(baseUrl, 'tmux-read', {
      session,
      lines: 80,
    });
    pane = String(response.result || '');
    if (predicate(pane)) return pane;
    await new Promise((resolve) => setTimeout(resolve, 75));
  }
  throw new Error(`timed out waiting for ${session} pane:\n${pane}`);
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

function writeFakeRuntime(filePath, runtime) {
  fs.writeFileSync(filePath, [
    `#!${process.execPath}`,
    "'use strict';",
    "const fs = require('node:fs');",
    "const readline = require('node:readline');",
    `const runtime = ${JSON.stringify(runtime)};`,
    'const args = process.argv.slice(2);',
    "if (runtime === 'agy' && args.length === 1 && args[0] === 'models') {",
    "  process.stdout.write('Available models:\\nAgy Test Model\\n');",
    '  process.exit(0);',
    '}',
    'const sensitiveEnvironmentKeys = [',
    "  'AUTHORIZATION',",
    "  'HTTP_AUTHORIZATION',",
    "  'MCP_BEARER_TOKEN',",
    "  'MCP_TOKEN',",
    "  'MCP_SPAWN_OTP',",
    "  'COLLAB_AGENT_SPAWN_OTP',",
    "  'NOTTY_MCP_SPAWN_OTP',",
    "  'NOTTY_MCP_SPAWN_OTP_ENABLED',",
    "  'NOTTY_MCP_SPAWN_OTP_TTL_SECONDS',",
    "  'NOTTY_BASIC_AUTH_PASSWORD',",
    "  'NOTTY_OAUTH_CLIENT_SECRET',",
    "  'NOTTY_GUARD_MTLS',",
    "  'NOTTY_GUARD_GATEWAY_PEER_IP',",
    "  'NOTTY_GUARD_GATEWAY_TOKEN',",
    "  'NOTTY_GUARD_OTP_MINT_TOKEN',",
    "  'NOTTY_LOOPBACK_PUBLICATION',",
    '];',
    'const inheritedSensitiveKeys = sensitiveEnvironmentKeys.filter((key) => Object.hasOwn(process.env, key));',
    'fs.appendFileSync(process.env.FAKE_RUNTIME_LOG, `${JSON.stringify({',
    '  runtime,',
    '  collabRuntime: process.env.COLLAB_RUNTIME,',
    '  argv: args,',
    '  inheritedSensitiveKeys,',
    '})}\\n`);',
    'process.stdout.write(`READY:${runtime}\\n`);',
    'const input = readline.createInterface({',
    '  input: process.stdin,',
    '  crlfDelay: Infinity,',
    '  terminal: false,',
    '});',
    "input.on('line', (line) => {",
    "  if (line === 'just respond with hello') process.stdout.write('hello\\n');",
    '});',
    '',
  ].join('\n'), { mode: 0o755 });
}

function createHarness(root, socketName) {
  const workspace = path.join(root, 'workspace');
  const fakeBin = path.join(root, 'bin');
  const runtimeLog = path.join(root, 'runtime.jsonl');
  const configHome = path.join(root, 'config');
  const stateHome = path.join(root, 'state');
  const fakeTmux = path.join(fakeBin, 'tmux');
  const fakeCodex = path.join(fakeBin, 'codex');
  const fakeAgy = path.join(fakeBin, 'agy');
  const fakeCurl = path.join(fakeBin, 'curl');

  for (const dir of [workspace, fakeBin, configHome, stateHome]) {
    fs.mkdirSync(dir, { recursive: true });
  }
  fs.writeFileSync(runtimeLog, '', 'utf8');
  fs.writeFileSync(fakeTmux, [
    `#!${process.execPath}`,
    "'use strict';",
    "const childProcess = require('node:child_process');",
    "const result = childProcess.spawnSync(process.env.COLLAB_TEST_REAL_TMUX, [",
    "  '-L',",
    '  process.env.COLLAB_TEST_TMUX_SOCKET,',
    '  ...process.argv.slice(2),',
    "], { stdio: 'inherit' });",
    'if (result.error) throw result.error;',
    'process.exit(result.status === null ? 1 : result.status);',
    '',
  ].join('\n'), { mode: 0o755 });
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

  const env = {
    ...process.env,
    AGY_BIN: fakeAgy,
    CODEX_BIN: fakeCodex,
    CURL_BIN: fakeCurl,
    OLLAMA_BIN: '/definitely/not-used/ollama',
    OLLAMA_HOST: '127.0.0.1:11434',
    COLLAB_AGENT_SPAWN_OTP: 'inherited-internal-token-must-not-leak',
    COLLAB_TEST_REAL_TMUX: realTmux,
    COLLAB_TEST_TMUX_SOCKET: socketName,
    FAKE_RUNTIME_LOG: runtimeLog,
    MCP_SPAWN_OTP: 'inherited-client-otp-must-not-leak',
    MCP_BEARER_TOKEN: 'inherited-mcp-bearer-must-not-leak',
    MCP_TOKEN: 'inherited-mcp-token-must-not-leak',
    NOTTY_BASIC_AUTH_PASSWORD: 'inherited-basic-secret-must-not-leak',
    NOTTY_COLLAB_UNSANDBOXED: 'false',
    NOTTY_GUARD_MTLS: 'true',
    NOTTY_GUARD_GATEWAY_PEER_IP: '10.240.9.2',
    NOTTY_GUARD_GATEWAY_TOKEN: 'inherited-guard-gateway-must-not-leak',
    NOTTY_GUARD_OTP_MINT_TOKEN: 'inherited-guard-mint-must-not-leak',
    NOTTY_LOOPBACK_PUBLICATION: 'true',
    NOTTY_MCP_SPAWN_OTP: 'inherited-server-otp-must-not-leak',
    NOTTY_MCP_SPAWN_OTP_ENABLED: 'true',
    NOTTY_MCP_SPAWN_OTP_TTL_SECONDS: '3600',
    NOTTY_OAUTH_CLIENT_SECRET: 'inherited-oauth-secret-must-not-leak',
    PATH: `${fakeBin}:${process.env.PATH}`,
    XDG_CONFIG_HOME: configHome,
    XDG_RUNTIME_DIR: path.join(root, 'runtime'),
    XDG_STATE_HOME: stateHome,
  };
  delete env.TMUX;
  delete env.TMUX_PANE;

  return {
    env,
    runtimeLog,
    workspace,
  };
}

test(
  'HTTP-created codex, agy, and ollama agents receive no server auth or OTP secrets',
  {
    skip: realTmux ? false : 'tmux is not installed',
    timeout: 45_000,
  },
  async () => {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), 'notty-collab-runtime-'));
    const socketName = `notty-test-${process.pid}-${crypto.randomUUID().slice(0, 8)}`;
    const harness = createHarness(root, socketName);
    const port = await reservePort();
    const baseUrl = `http://127.0.0.1:${port}`;
    let daemonOutput = '';
    const daemon = childProcess.spawn(process.execPath, [
      collabPath,
      'daemon',
      '--workdir', harness.workspace,
      '--ip', '127.0.0.1',
      '--port', String(port),
    ], {
      cwd: appRoot,
      env: harness.env,
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    daemon.stdout.on('data', (chunk) => { daemonOutput += chunk; });
    daemon.stderr.on('data', (chunk) => { daemonOutput += chunk; });

    const cleanupEnv = { ...process.env };
    delete cleanupEnv.TMUX;
    delete cleanupEnv.TMUX_PANE;

    try {
      const bootstrap = await waitForBootstrap(baseUrl, daemon, () => daemonOutput);
      assert.ok(
        bootstrap.modelCatalog.agy.some((entry) => entry.id === 'Agy Test Model'),
      );
      assert.ok(
        bootstrap.modelCatalog.ollama.some((entry) => entry.id === 'ornith:9b'),
      );

      const cases = [
        {
          agent: 'hello-codex',
          runtime: 'codex',
          model: 'fake-codex',
        },
        {
          agent: 'hello-agy',
          runtime: 'agy',
          model: 'Agy Test Model',
        },
        {
          agent: 'hello-ollama',
          runtime: 'ollama',
          model: 'ornith:9b',
          think: 'high',
        },
      ];

      const createResponses = [];
      const panes = [];
      for (const entry of cases) {
        const created = await postCommand(baseUrl, 'create-agent', {
          agent: entry.agent,
          role: 'coder',
          runtime: entry.runtime,
          model: entry.model,
          think: entry.think,
        });
        createResponses.push(created);
        assert.equal(created.result.agent, entry.agent);
        assert.equal(created.result.runtime, entry.runtime);
        assert.equal(created.result.model, entry.model);
        assert.equal(Object.hasOwn(created.result, 'spawn_otp_configured'), false);

        await waitForPane(
          baseUrl,
          entry.agent,
          (pane) => pane.split(/\r?\n/).map((line) => line.trim()).includes(
            `READY:${entry.runtime === 'ollama' ? 'codex' : entry.runtime}`,
          ),
        );
        const sent = await postCommand(baseUrl, 'tmux-send', {
          session: entry.agent,
          body: 'just respond with hello',
          enter: true,
          'delay-ms': 1,
        });
        assert.equal(sent.result, entry.agent);
        const pane = await waitForPane(
          baseUrl,
          entry.agent,
          (text) => text.split(/\r?\n/).map((line) => line.trim()).includes('hello'),
        );
        const lines = pane.split(/\r?\n/).map((line) => line.trim());
        assert.equal(
          lines.filter((line) => line === 'hello').length,
          1,
          `expected one exact hello line from ${entry.runtime}:\n${pane}`,
        );
        panes.push(pane);
      }

      const launches = readJsonLines(harness.runtimeLog);
      assert.equal(launches.length, cases.length);
      for (const entry of cases) {
        const launch = launches.find((candidate) => candidate.collabRuntime === entry.runtime);
        assert.ok(launch, `missing ${entry.runtime} runtime launch`);
        assert.equal(launch.runtime, entry.runtime === 'ollama' ? 'codex' : entry.runtime);
        assert.deepEqual(launch.inheritedSensitiveKeys, []);
      }
      const ollamaLaunch = launches.find((launch) => launch.collabRuntime === 'ollama');
      assert.deepEqual(ollamaLaunch.argv.slice(0, 2), ['-m', 'ornith:9b']);
      const providerId = ollamaProviderId(ollamaLaunch.argv);
      const baseUrlPrefix = `model_providers.${providerId}.base_url=`;
      const baseUrlArg = ollamaLaunch.argv.find(
        (arg) => String(arg).startsWith(baseUrlPrefix),
      );
      assert.ok(baseUrlArg, 'missing relayed Ollama provider URL');
      const relayBaseUrl = new URL(JSON.parse(baseUrlArg.slice(baseUrlPrefix.length)));
      assert.equal(relayBaseUrl.hostname, '127.0.0.1');
      assert.match(relayBaseUrl.port, /^\d+$/);
      assert.equal(relayBaseUrl.pathname, '/v1');
      assert.ok(ollamaLaunch.argv.some((arg) => arg.startsWith('model_catalog_json=')));
      assert.equal(ollamaLaunch.argv.includes('--oss'), false);
      assert.equal(ollamaLaunch.argv.includes('launch'), false);
      const managedResponse = await postCommand(baseUrl, 'managed-agents', {});
      assert.deepEqual(
        managedResponse.result.map((entry) => entry.agent).sort(),
        cases.map((entry) => entry.agent).sort(),
      );
      const managedPath = path.join(
        harness.workspace,
        'collab',
        'intragent',
        'managed_agents.json',
      );
      const managedMetadata = fs.readFileSync(managedPath, 'utf8');
      assert.doesNotMatch(managedMetadata, /spawn[_-]?otp|MCP_SPAWN_OTP/i);

      const observableOutput = [
        JSON.stringify(createResponses),
        JSON.stringify(managedResponse),
        managedMetadata,
        fs.readFileSync(harness.runtimeLog, 'utf8'),
        panes.join('\n'),
        daemonOutput,
      ].join('\n');
      for (const secret of [
        'inherited-internal-token-must-not-leak',
        'inherited-client-otp-must-not-leak',
        'inherited-mcp-bearer-must-not-leak',
        'inherited-mcp-token-must-not-leak',
        'inherited-server-otp-must-not-leak',
        'inherited-basic-secret-must-not-leak',
        'inherited-oauth-secret-must-not-leak',
        'inherited-guard-gateway-must-not-leak',
        'inherited-guard-mint-must-not-leak',
      ]) {
        assert.equal(observableOutput.includes(secret), false, `${secret} leaked to an agent or output`);
      }
    } finally {
      await stopChild(daemon);
      childProcess.spawnSync(
        realTmux,
        ['-L', socketName, 'kill-server'],
        { env: cleanupEnv, stdio: 'ignore' },
      );
      fs.rmSync(root, { recursive: true, force: true });
    }
  },
);
