'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const test = require('node:test');

async function loadSmokeModule() {
  return import('../scripts/durdraw-agent-art-smoke.mjs');
}

function completedMcpEvent(server, tool, overrides = {}) {
  return JSON.stringify({
    type: 'item.completed',
    item: {
      type: 'mcp_tool_call',
      server,
      tool,
      status: 'completed',
      ...overrides,
    },
  });
}

function requiredMcpTrace(extraLines = []) {
  return [
    JSON.stringify({ type: 'thread.started', thread_id: 'thread-test' }),
    completedMcpEvent('notty_durdraw', 'durdraw_text'),
    completedMcpEvent('notty_durdraw', 'durdraw_action'),
    completedMcpEvent('collab_art', 'send_message'),
    ...extraLines,
  ].join('\n');
}

test('Durdraw agent smoke parses explicit options and normalizes MCP URLs', async () => {
  const { normalizeMcpUrl, parseArgs, siblingUrl } = await loadSmokeModule();
  const outputDir = path.resolve('tmp/durdraw-art-output');
  const options = parseArgs([
    '--notty-url', 'https://notty.example.test/root/mcp/',
    '--collab-url', 'http://collab.example.test:1337/mcp/',
    '--codex-bin', '/opt/codex/bin/codex',
    '--model', 'gpt-test',
    '--think', 'HIGH',
    '--sandbox', 'DANGER-FULL-ACCESS',
    '--timeout-ms', '120000',
    '--otp-ttl-seconds', '900',
    '--output-dir', 'tmp/durdraw-art-output',
  ]);

  assert.deepEqual(options, {
    nottyUrl: 'https://notty.example.test/root/mcp',
    collabUrl: 'http://collab.example.test:1337/mcp',
    codexBin: '/opt/codex/bin/codex',
    model: 'gpt-test',
    think: 'high',
    sandbox: 'danger-full-access',
    timeoutMs: 120000,
    otpTtlSeconds: 900,
    outputDir,
    help: false,
  });
  assert.equal(
    normalizeMcpUrl('http://127.0.0.1:3000/mcp/#ignored', '--notty-url'),
    'http://127.0.0.1:3000/mcp',
  );
  assert.equal(
    siblingUrl('https://notty.example.test/root/mcp', '/api/spawn-otps'),
    'https://notty.example.test/root/api/spawn-otps',
  );
});

test('Durdraw agent smoke rejects unsafe URLs and invalid arguments', async () => {
  const { normalizeMcpUrl, parseArgs } = await loadSmokeModule();

  for (const [value, message] of [
    ['not a URL', /must be a valid URL/],
    ['file:///tmp/mcp', /must use http or https/],
    ['http://user:password@localhost:3000/mcp', /must not contain credentials/],
    ['http://localhost:3000/mcp?token=secret', /must not contain query/],
    ['http://localhost:3000/tools', /must end in \/mcp/],
  ]) {
    assert.throws(
      () => normalizeMcpUrl(value, '--notty-url'),
      message,
      value,
    );
  }

  assert.throws(() => parseArgs(['--notty-url']), /--notty-url requires a value/);
  assert.throws(() => parseArgs(['--timeout-ms', '0']), /must be a positive integer/);
  assert.throws(() => parseArgs(['--timeout-ms', '12junk']), /must be a positive integer/);
  assert.throws(() => parseArgs(['--timeout-ms', '1.5']), /must be a positive integer/);
  assert.throws(() => parseArgs(['--otp-ttl-seconds', '-1']), /must be a positive integer/);
  assert.throws(
    () => parseArgs(['--think', 'extreme']),
    /--think must be one of: minimal, low, medium, high, xhigh/,
  );
  assert.throws(
    () => parseArgs(['--sandbox', 'read-only']),
    /--sandbox must be workspace-write or danger-full-access/,
  );
  assert.throws(() => parseArgs(['--surprise']), /unknown option: --surprise/);
});

test('Durdraw agent smoke validates mutually exclusive Notty authorization modes', async () => {
  const { resolveNottyAuth } = await loadSmokeModule();

  assert.deepEqual(resolveNottyAuth({}), { header: '', secrets: [] });
  assert.deepEqual(
    resolveNottyAuth({ NOTTY_MCP_AUTHORIZATION: 'Bearer direct-token' }),
    {
      header: 'Bearer direct-token',
      secrets: ['Bearer direct-token'],
    },
  );
  assert.deepEqual(
    resolveNottyAuth({ NOTTY_MCP_BEARER_TOKEN: 'bearer-token' }),
    {
      header: 'Bearer bearer-token',
      secrets: ['bearer-token', 'Bearer bearer-token'],
    },
  );

  const basic = resolveNottyAuth({
    NOTTY_BASIC_AUTH_USERNAME: 'artist',
    NOTTY_BASIC_AUTH_PASSWORD: 'paint-secret',
  });
  const encoded = Buffer.from('artist:paint-secret').toString('base64');
  assert.equal(basic.header, `Basic ${encoded}`);
  assert.deepEqual(
    new Set(basic.secrets),
    new Set(['paint-secret', encoded, `Basic ${encoded}`]),
  );

  assert.throws(
    () => resolveNottyAuth({ NOTTY_MCP_AUTHORIZATION: 'Digest unsupported' }),
    /must be a Basic or Bearer Authorization value/,
  );
  assert.throws(
    () => resolveNottyAuth({
      NOTTY_MCP_BEARER_TOKEN: 'bearer-token',
      NOTTY_BASIC_AUTH_PASSWORD: 'basic-password',
    }),
    /configure only one Notty Authorization mode/,
  );
});

test('artist child environments scrub inherited spawn OTPs and raw Notty credentials', async () => {
  const { scrubbedCodexEnvironment } = await loadSmokeModule();
  const inherited = Object.freeze({
    PATH: '/test/bin',
    OPENAI_API_KEY: 'provider-key-needed-by-codex',
    SPAWN_OTP: 'generic-launcher-otp',
    SPAWN_OTP: 'generic-launcher-otp',
    MCP_SPAWN_OTP: 'client-otp',
    NOTTY_MCP_SPAWN_OTP: 'server-otp',
    COLLAB_AGENT_SPAWN_OTP: 'launcher-otp',
    NOTTY_MCP_AUTHORIZATION: 'Bearer raw-header',
    NOTTY_MCP_BEARER_TOKEN: 'raw-bearer',
    NOTTY_BASIC_AUTH_USERNAME: 'notty-user',
    NOTTY_BASIC_AUTH_PASSWORD: 'notty-password',
  });

  const scrubbed = scrubbedCodexEnvironment(inherited);

  assert.equal(scrubbed.PATH, inherited.PATH);
  assert.equal(scrubbed.OPENAI_API_KEY, inherited.OPENAI_API_KEY);
  for (const key of [
    'SPAWN_OTP',
    'MCP_SPAWN_OTP',
    'SPAWN_OTP',
    'NOTTY_MCP_SPAWN_OTP',
    'COLLAB_AGENT_SPAWN_OTP',
    'NOTTY_MCP_AUTHORIZATION',
    'NOTTY_MCP_BEARER_TOKEN',
    'NOTTY_BASIC_AUTH_USERNAME',
    'NOTTY_BASIC_AUTH_PASSWORD',
  ]) {
    assert.equal(Object.hasOwn(scrubbed, key), false, key);
    assert.equal(Object.hasOwn(inherited, key), true, `input was mutated: ${key}`);
  }
});

test('artist prompts contain the assigned UUID and lock protocol but no OTP value', async () => {
  const { agentPrompt } = await loadSmokeModule();
  const terminalUuid = '11111111-2222-4333-8444-555555555555';
  const otpValue = 'otp-must-never-enter-the-prompt';
  const otpUuid = 'aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee';
  const prompt = agentPrompt(
    {
      id: 'artist-a',
      terminalUuid,
      otp: { value: otpValue, uuid: otpUuid },
    },
    {
      channel: 'durdraw-test-channel',
      timeoutMs: 45678,
    },
  );

  assert.match(prompt, new RegExp(terminalUuid));
  assert.match(prompt, /Never call\s+`spawn_durdraw`/);
  assert.match(prompt, /terminal_uuid `11111111-2222-4333-8444-555555555555`/);
  assert.match(prompt, /node \.notty-art\/art-lock\.mjs acquire artist-a artist-a\.ans/);
  assert.match(prompt, /node \.notty-art\/art-lock\.mjs verify artist-a artist-a\.ans/);
  assert.match(prompt, /node \.notty-art\/art-lock\.mjs release artist-a artist-a\.ans/);
  assert.match(prompt, /node \.notty-art\/art-lock\.mjs ready artist-a/);
  assert.match(
    prompt,
    /node \.notty-art\/art-lock\.mjs begin-shared artist-a collaboration\.ans 45678/,
  );
  assert.match(prompt, /node \.notty-art\/art-lock\.mjs finish artist-a/);
  assert.match(prompt, /channel `durdraw-test-channel`/);
  assert.match(prompt, /literal ASCII signature `\[artist-a\]`/);
  assert.match(prompt, /file picker directly/);
  assert.match(prompt, /do not type a format letter/);
  assert.doesNotMatch(prompt, /type `i` for ASCII\/ANSI input/);
  assert.doesNotMatch(prompt, new RegExp(otpValue));
  assert.doesNotMatch(prompt, new RegExp(otpUuid));
  assert.doesNotMatch(prompt, /MCP_SPAWN_OTP|NOTTY_MCP_SPAWN_OTP/);
});

test('workspace instructions make filesystem locks authoritative for ANSI writes', async () => {
  const { workspaceInstructions } = await loadSmokeModule();
  const instructions = workspaceInstructions();

  assert.match(instructions, /Every target must be locked before the first editing tool call/);
  assert.match(instructions, /lock is authoritative at `agents\/locks\/<target>`/);
  assert.match(instructions, /Never edit a target when acquisition reports busy/);
  assert.match(instructions, /Hold only one lock at a time/);
  assert.match(instructions, /Do not delete, replace, or take over another agent's lock/);
  assert.match(instructions, /Use only `\.notty-art\/art-lock\.mjs`/);
  assert.match(instructions, /Use Durdraw MCP tools for art edits/);
  assert.match(
    instructions,
    /Never create or modify an `\.ans` file with shell,\s+JavaScript, Python, redirection, apply_patch, base64/,
  );
  assert.match(instructions, /parent creates `coordination\/go` only after both personal pieces/);
  assert.match(instructions, /requires\s+one denied acquisition before a verified handoff/);
});

test('Codex JSONL evidence accepts only completed exact MCP calls', async () => {
  const { assertAgentToolEvidence, completedMcpCalls } = await loadSmokeModule();
  const ignoredCalls = [
    JSON.stringify({
      type: 'item.started',
      item: {
        type: 'mcp_tool_call',
        server: 'notty_durdraw',
        tool: 'read_terminal',
        status: 'in_progress',
      },
    }),
    completedMcpEvent('notty_durdraw', 'read_terminal', {
      status: 'failed',
      error: { message: 'test failure' },
    }),
  ];
  const trace = requiredMcpTrace(ignoredCalls);

  assert.deepEqual(completedMcpCalls(trace, 'artist-a'), [
    { server: 'notty_durdraw', tool: 'durdraw_text' },
    { server: 'notty_durdraw', tool: 'durdraw_action' },
    { server: 'collab_art', tool: 'send_message' },
  ]);
  assert.doesNotThrow(() => {
    assertAgentToolEvidence([{ id: 'artist-a', stdout: trace }]);
  });

  assert.throws(
    () => assertAgentToolEvidence([{
      id: 'artist-a',
      stdout: [
        completedMcpEvent('notty_durdraw', 'durdraw_text'),
        completedMcpEvent('notty_durdraw', 'durdraw_action'),
        completedMcpEvent('wrong_collab', 'send_message'),
      ].join('\n'),
    }]),
    /artist-a trace has no Collab message MCP call evidence/,
  );
  assert.throws(
    () => completedMcpCalls('not-json', 'artist-a'),
    /artist-a emitted invalid Codex JSONL at line 1/,
  );
});

test('Codex JSONL evidence rejects spawn_durdraw even when other evidence passes', async () => {
  const { assertAgentToolEvidence } = await loadSmokeModule();
  const trace = requiredMcpTrace([
    completedMcpEvent('notty_durdraw', 'spawn_durdraw'),
  ]);

  assert.throws(
    () => assertAgentToolEvidence([{ id: 'artist-b', stdout: trace }]),
    /artist-b attempted spawn_durdraw instead of reusing its assigned OTP session/,
  );

  const failedAttempt = requiredMcpTrace([
    completedMcpEvent('notty_durdraw', 'spawn_durdraw', {
      status: 'failed',
      error: { message: 'OTP unavailable' },
    }),
  ]);
  assert.throws(
    () => assertAgentToolEvidence([{ id: 'artist-b', stdout: failedAttempt }]),
    /artist-b attempted spawn_durdraw/,
  );
});

test('ANSI validation recognizes signatures separated by per-character SGR codes', async (t) => {
  const { validateArt } = await loadSmokeModule();
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'notty-ansi-signatures-'));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));

  const encoded = (text, color) => Buffer.from(
    [...text].map((character) => `\u001b[${color}m${character}`).join('')
      + `\u001b[0m\r\n${'x'.repeat(100)}`,
    'latin1',
  );
  fs.writeFileSync(path.join(root, 'artist-a.ans'), encoded('[artist-a]', '36'));
  fs.writeFileSync(path.join(root, 'artist-b.ans'), encoded('[artist-b]', '35'));
  fs.writeFileSync(
    path.join(root, 'collaboration.ans'),
    encoded('[artist-a] SIGNAL BRIDGE [artist-b]', '33'),
  );

  const result = await validateArt(root);
  assert.ok(result['artist-a.ans'].bytes > 80);
  assert.ok(result['artist-b.ans'].bytes > 80);
  assert.ok(result['collaboration.ans'].bytes > 80);
});
