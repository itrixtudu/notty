'use strict';

const assert = require('node:assert/strict');
const { PassThrough } = require('node:stream');
const test = require('node:test');

const { createIrcTerminalUi } = require('../lib/collab/terminal-ui.cjs');

function createStream(isTTY) {
  const stream = new PassThrough();
  stream.isTTY = isTTY;
  stream.columns = 80;
  stream.rows = 24;
  return stream;
}

function createInput(isTTY) {
  const stream = createStream(isTTY);
  stream.setRawMode = (enabled) => {
    stream.isRaw = enabled;
    return stream;
  };
  return stream;
}

function captureOutput(stream) {
  let output = '';
  stream.setEncoding('utf8');
  stream.on('data', (chunk) => { output += chunk; });
  return () => output;
}

function jsonResponse(payload, options = {}) {
  return {
    ok: options.ok !== false,
    status: options.status || 200,
    async json() {
      if (options.invalidJson) throw new Error('invalid json');
      return payload;
    },
  };
}

test('collab client normalizes URLs, headers, bodies, and encoded identifiers', async () => {
  const { createCollabAdminClient } = await import('../lib/collab/client.js');
  const requests = [];
  const client = createCollabAdminClient({
    baseUrl: 'http://127.0.0.1:1337/root/?token=discarded#hash',
    fetchImpl: async (url, init) => {
      requests.push({ url, init });
      return jsonResponse({ ok: true });
    },
  });

  assert.equal(client.baseUrl, 'http://127.0.0.1:1337/root');
  assert.equal(client.eventsUrl, 'http://127.0.0.1:1337/root/admin/v1/events');

  await client.writeConfig('work space', 'rev-1', { templates: {} });
  await client.retryAgent('agent/one');
  await client.sendMessage('release notes', { body: 'ship it' });

  assert.equal(requests[0].url, 'http://127.0.0.1:1337/root/admin/v1/config/work%20space');
  assert.equal(requests[0].init.method, 'PUT');
  assert.equal(requests[0].init.headers.Accept, 'application/json');
  assert.equal(requests[0].init.headers['Content-Type'], 'application/json');
  assert.deepEqual(JSON.parse(requests[0].init.body), {
    revision: 'rev-1',
    document: { templates: {} },
  });
  assert.match(requests[1].url, /agents\/agent%2Fone\/retry$/);
  assert.match(requests[2].url, /channels\/release%20notes\/messages$/);
});

test('collab client sets an encoded agent permission mode with JSON', async () => {
  const { createCollabAdminClient } = await import('../lib/collab/client.js');
  const requests = [];
  const client = createCollabAdminClient({
    baseUrl: 'http://127.0.0.1:1337',
    fetchImpl: async (url, init) => {
      requests.push({ url, init });
      return jsonResponse({ session: { id: 'session-test' } });
    },
  });

  await client.setAgentPermissionMode('agent/one', 'danger-full-access');

  assert.equal(requests.length, 1);
  assert.equal(
    requests[0].url,
    'http://127.0.0.1:1337/admin/v1/session/agents/agent%2Fone/permission-mode',
  );
  assert.equal(requests[0].init.method, 'POST');
  assert.equal(requests[0].init.headers.Accept, 'application/json');
  assert.equal(requests[0].init.headers['Content-Type'], 'application/json');
  assert.deepEqual(JSON.parse(requests[0].init.body), {
    permissionMode: 'danger-full-access',
  });
});

test('collab client preserves message cursors and exposes feedback and stats endpoints', async () => {
  const { createCollabAdminClient } = await import('../lib/collab/client.js');
  const requests = [];
  const client = createCollabAdminClient({
    baseUrl: 'http://127.0.0.1:1337',
    fetchImpl: async (url, init) => {
      requests.push({ url, init });
      return jsonResponse({ ok: true });
    },
  });

  await client.getMessages('release notes', 25, 1234);
  await client.setMessageFeedback('release notes', 'message/one', 'helpful');
  await client.getStats('lifetime');

  assert.equal(
    requests[0].url,
    'http://127.0.0.1:1337/admin/v1/channels/release%20notes/messages?limit=25&cursor=1234',
  );
  assert.equal(
    requests[1].url,
    'http://127.0.0.1:1337/admin/v1/channels/release%20notes/messages/message%2Fone/feedback',
  );
  assert.equal(requests[1].init.method, 'PUT');
  assert.deepEqual(JSON.parse(requests[1].init.body), { rating: 'helpful' });
  assert.equal(
    requests[2].url,
    'http://127.0.0.1:1337/admin/v1/stats?scope=lifetime',
  );
});

test('collab client refreshes launch catalogs and sets canonical agent health', async () => {
  const { createCollabAdminClient } = await import('../lib/collab/client.js');
  const requests = [];
  const client = createCollabAdminClient({
    baseUrl: 'http://127.0.0.1:1337',
    fetchImpl: async (url, init) => {
      requests.push({ url, init });
      return jsonResponse({ ok: true });
    },
  });

  await client.refreshCatalog();
  await client.setAgentHealth('observer/one', {
    code: 'rate-limited',
    message: 'Local runtime is cooling down.',
  });

  assert.equal(requests[0].url, 'http://127.0.0.1:1337/admin/v1/catalog/refresh');
  assert.equal(requests[0].init.method, 'POST');
  assert.deepEqual(JSON.parse(requests[0].init.body), {});
  assert.equal(
    requests[1].url,
    'http://127.0.0.1:1337/admin/v1/session/agents/observer%2Fone/health',
  );
  assert.equal(requests[1].init.method, 'PUT');
  assert.deepEqual(JSON.parse(requests[1].init.body), {
    code: 'rate-limited',
    message: 'Local runtime is cooling down.',
  });
});

test('collab client propagates structured and fallback HTTP errors', async () => {
  const { createCollabAdminClient } = await import('../lib/collab/client.js');
  const structured = createCollabAdminClient({
    fetchImpl: async () => jsonResponse(
      { error: { message: 'revision conflict', code: 'CONFLICT' } },
      { ok: false, status: 409 },
    ),
  });

  await assert.rejects(
    structured.getConfig(),
    (error) => {
      assert.equal(error.message, 'revision conflict');
      assert.equal(error.statusCode, 409);
      assert.equal(error.payload.error.code, 'CONFLICT');
      return true;
    },
  );

  const fallback = createCollabAdminClient({
    fetchImpl: async () => jsonResponse(null, {
      ok: false,
      status: 503,
      invalidJson: true,
    }),
  });
  await assert.rejects(fallback.bootstrap(), /collab daemon request failed \(503\)/);
});

test('shared IRC terminal UI restores the active input and cursor after output', async (t) => {
  const input = createInput(true);
  const output = createStream(true);
  const rendered = captureOutput(output);
  let prompt = 'tester@#lobby> ';
  const ui = createIrcTerminalUi({ input, output, prompt: () => prompt });
  t.after(() => ui.readline.close());

  ui.setPromptVisible(true);
  ui.prompt();
  input.write('draft\x1b[D\x1b[D');
  await new Promise((resolve) => setImmediate(resolve));

  prompt = 'tester@#ops> ';
  ui.write('incoming message');

  const line = new Promise((resolve) => ui.readline.once('line', resolve));
  input.write('X');
  input.write('\r');

  assert.equal(await line, 'draXft');
  assert.match(rendered(), /incoming message\r?\n/);
  assert.match(rendered(), /tester@#ops> /);
});

test('shared IRC terminal UI does not force terminal mode for non-TTY streams', (t) => {
  const cases = [
    { inputIsTTY: true, outputIsTTY: true, expected: true },
    { inputIsTTY: true, outputIsTTY: false, expected: false },
    { inputIsTTY: false, outputIsTTY: true, expected: false },
    { inputIsTTY: false, outputIsTTY: false, expected: false },
  ];

  for (const entry of cases) {
    const input = createInput(entry.inputIsTTY);
    const output = createStream(entry.outputIsTTY);
    const rendered = captureOutput(output);
    const ui = createIrcTerminalUi({ input, output, prompt: 'plain> ' });
    t.after(() => ui.readline.close());

    assert.equal(ui.isTerminal, entry.expected);
    assert.equal(ui.readline.terminal, entry.expected);

    if (!entry.expected) {
      ui.setPromptVisible(true);
      ui.prompt();
      ui.write('plain output');
      assert.doesNotMatch(rendered(), /\x1b\[[0-9;?]*[A-HJ-KSTf]/);
    }
  }
});
