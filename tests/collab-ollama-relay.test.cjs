'use strict';

const assert = require('node:assert/strict');
const { EventEmitter } = require('node:events');
const http = require('node:http');
const path = require('node:path');
const { Readable, Writable } = require('node:stream');
const { pipeline } = require('node:stream/promises');
const test = require('node:test');

const {
  FUNCTION_NAME_LIMIT,
  NamespaceAliasRegistry,
  NamespaceSseTransform,
  buildOllamaCodexRelayCommand,
  inspectCodexProviderCommand,
  removeOwnedCatalog,
  restoreNamespaceCalls,
  rewriteCodexProviderCommand,
  runOllamaCodexRelayCommand,
  startOllamaCodexRelay,
  transformCodexRequest,
} = require('../lib/collab/ollama-codex-relay.cjs');

function listen(server) {
  return new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', () => {
      server.off('error', reject);
      resolve(server.address());
    });
  });
}

function close(server) {
  return new Promise((resolve) => server.close(resolve));
}

function sampleCommand(catalogPath = '/runtime/notty-ollama/catalog-example.json') {
  return [
    '/usr/local/bin/codex',
    '-m', 'qwen3:4b',
    '-c', 'model_provider="notty_ollama_0123abcd"',
    '-c', 'model_providers.notty_ollama_0123abcd.name="Ollama via Notty"',
    '-c', 'model_providers.notty_ollama_0123abcd.base_url="http://ollama.test:11434/v1"',
    '-c', `model_catalog_json=${JSON.stringify(catalogPath)}`,
    'prompt',
  ];
}

test('Responses requests flatten namespace members and remove hosted web search', () => {
  const registry = new NamespaceAliasRegistry();
  const transformed = transformCodexRequest({
    model: 'qwen3:4b',
    tools: [
      {
        type: 'function',
        name: 'exec_command',
        description: 'Run a command.',
        parameters: { type: 'object' },
      },
      { type: 'web_search', name: '' },
      {
        type: 'namespace',
        name: 'mcp__notty_collab_session',
        description: 'Notty collaboration tools.',
        tools: [{
          type: 'function',
          name: 'claim_pending',
          description: 'Claim queued work.',
          strict: true,
          parameters: {
            type: 'object',
            properties: { limit: { type: 'integer' } },
          },
        }],
      },
    ],
    input: [{
      type: 'function_call',
      namespace: 'mcp__notty_collab_session',
      name: 'claim_pending',
      call_id: 'call-1',
      arguments: '{"limit":1}',
    }],
  }, registry);

  assert.equal(transformed.tools.length, 2);
  assert.equal(transformed.tools[0].name, 'exec_command');
  const flattened = transformed.tools[1];
  assert.equal(flattened.type, 'function');
  assert.match(flattened.name, /^notty_ns_[0-9a-f]{24}_claim_pending$/);
  assert.ok(flattened.name.length <= FUNCTION_NAME_LIMIT);
  assert.equal(flattened.strict, true);
  assert.deepEqual(flattened.parameters.properties.limit, { type: 'integer' });
  assert.match(flattened.description, /mcp__notty_collab_session/);
  assert.match(flattened.description, /Claim queued work/);
  assert.equal(transformed.input[0].name, flattened.name);
  assert.equal('namespace' in transformed.input[0], false);

  assert.deepEqual(restoreNamespaceCalls({
    type: 'function_call',
    name: flattened.name,
    arguments: '{}',
    call_id: 'call-2',
  }, registry), {
    type: 'function_call',
    name: 'claim_pending',
    namespace: 'mcp__notty_collab_session',
    arguments: '{}',
    call_id: 'call-2',
  });
});

test('namespace aliases are deterministic, readable, and collision checked', () => {
  const first = new NamespaceAliasRegistry();
  const second = new NamespaceAliasRegistry();
  assert.equal(
    first.aliasFor('mcp__alpha', 'list-terminals'),
    second.aliasFor('mcp__alpha', 'list-terminals'),
  );
  assert.match(first.aliasFor('mcp__alpha', 'list-terminals'), /_list-terminals$/);

  const colliding = new NamespaceAliasRegistry({ hash: () => 'a'.repeat(64) });
  colliding.aliasFor('mcp__alpha', 'one');
  assert.throws(
    () => colliding.aliasFor('mcp__beta', 'one'),
    /namespace alias collision/,
  );
});

test('unsupported namespace member types fail closed', () => {
  assert.throws(
    () => transformCodexRequest({
      tools: [{
        type: 'namespace',
        name: 'mcp__unsafe',
        tools: [{ type: 'custom', name: 'freeform' }],
      }],
    }),
    /unsupported member type custom/,
  );
});

test('relay accepts only the Ollama Responses API base path', async () => {
  await assert.rejects(
    startOllamaCodexRelay({ upstreamBaseUrl: 'http://127.0.0.1:11434/api' }),
    /must use the \/v1 API base path/,
  );
});

test('SSE transformer bounds an unterminated event across chunks', async () => {
  const source = Readable.from([Buffer.alloc(9, 'a'), Buffer.alloc(9, 'b')]);
  const sink = new Writable({ write(_chunk, _encoding, callback) { callback(); } });
  await assert.rejects(
    pipeline(source, new NamespaceSseTransform(new NamespaceAliasRegistry(), 16), sink),
    /SSE event exceeds 16 bytes/,
  );
});

test('loopback relay rewrites streamed calls and subsequent request history', async (t) => {
  const received = [];
  const upstream = http.createServer(async (request, response) => {
    const chunks = [];
    for await (const chunk of request) chunks.push(chunk);
    const body = JSON.parse(Buffer.concat(chunks).toString('utf8'));
    received.push(body);
    const alias = body.tools.find((tool) => tool.name?.startsWith('notty_ns_')).name;
    const events = [
      {
        type: 'response.output_item.added',
        item: {
          type: 'function_call',
          id: 'fc-1',
          call_id: 'call-1',
          name: alias,
          arguments: '',
        },
      },
      {
        type: 'response.output_item.done',
        item: {
          type: 'function_call',
          id: 'fc-1',
          call_id: 'call-1',
          name: alias,
          arguments: '{}',
        },
      },
      {
        type: 'response.completed',
        response: {
          output: [{
            type: 'function_call',
            id: 'fc-1',
            call_id: 'call-1',
            name: alias,
            arguments: '{}',
          }],
        },
      },
    ];
    const stream = `${events.map((event) => `data: ${JSON.stringify(event)}\n\n`).join('')}data: [DONE]\n\n`;
    response.writeHead(200, { 'content-type': 'text/event-stream' });
    response.write(stream.slice(0, 17));
    response.write(stream.slice(17, 83));
    response.end(stream.slice(83));
  });
  const address = await listen(upstream);
  t.after(() => close(upstream));
  const relay = await startOllamaCodexRelay({
    upstreamBaseUrl: `http://127.0.0.1:${address.port}/v1`,
  });
  t.after(() => relay.close());

  const response = await fetch(`${relay.baseUrl}/responses`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({
      model: 'qwen3:4b',
      stream: true,
      tools: [
        { type: 'web_search', name: '' },
        {
          type: 'namespace',
          name: 'mcp__notty_probe',
          tools: [{
            type: 'function',
            name: 'list_terminals',
            parameters: { type: 'object', properties: {} },
          }],
        },
      ],
      input: [{
        type: 'function_call',
        namespace: 'mcp__notty_probe',
        name: 'list_terminals',
        call_id: 'old-call',
        arguments: '{}',
      }],
    }),
  });
  assert.equal(response.status, 200);
  const text = await response.text();
  assert.equal(received.length, 1);
  assert.equal(received[0].tools.length, 1);
  assert.match(received[0].tools[0].name, /^notty_ns_[0-9a-f]{24}_list_terminals$/);
  assert.equal(received[0].input[0].name, received[0].tools[0].name);
  assert.equal('namespace' in received[0].input[0], false);

  const data = text
    .split(/\r?\n/)
    .filter((line) => line.startsWith('data: {'))
    .map((line) => JSON.parse(line.slice(6)));
  assert.equal(data.length, 3);
  for (const event of data) {
    const call = event.item || event.response.output[0];
    assert.equal(call.namespace, 'mcp__notty_probe');
    assert.equal(call.name, 'list_terminals');
    assert.equal(call.call_id, 'call-1');
  }
  assert.match(text, /data: \[DONE\]/);
});

test('loopback relay restores namespaced calls in non-streaming JSON responses', async (t) => {
  const upstream = http.createServer(async (request, response) => {
    const chunks = [];
    for await (const chunk of request) chunks.push(chunk);
    const body = JSON.parse(Buffer.concat(chunks).toString('utf8'));
    const alias = body.tools.find((tool) => tool.name?.startsWith('notty_ns_')).name;
    const responseBody = JSON.stringify({
      id: 'response-1',
      output: [{
        type: 'function_call',
        id: 'fc-1',
        call_id: 'call-1',
        name: alias,
        arguments: '{}',
      }],
    });
    response.writeHead(200, {
      'content-type': 'application/json',
      'content-length': Buffer.byteLength(responseBody),
    });
    response.end(responseBody);
  });
  const address = await listen(upstream);
  t.after(() => close(upstream));
  const relay = await startOllamaCodexRelay({
    upstreamBaseUrl: `http://127.0.0.1:${address.port}/v1`,
  });
  t.after(() => relay.close());

  const response = await fetch(`${relay.baseUrl}/responses`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({
      model: 'qwen3:4b',
      stream: false,
      tools: [{
        type: 'namespace',
        name: 'mcp__notty_probe',
        tools: [{
          type: 'function',
          name: 'return_hello',
          parameters: { type: 'object', properties: {} },
        }],
      }],
    }),
  });
  assert.equal(response.status, 200);
  const body = await response.json();
  assert.equal(body.output[0].namespace, 'mcp__notty_probe');
  assert.equal(body.output[0].name, 'return_hello');
  assert.equal(body.output[0].call_id, 'call-1');
});

test('relay rejects encoded Responses bodies before transforming them', async (t) => {
  const upstream = http.createServer((_request, response) => {
    response.writeHead(200, {
      'content-type': 'text/event-stream',
      'content-encoding': 'gzip',
    });
    response.end('encoded bytes are not safe to transform');
  });
  const address = await listen(upstream);
  t.after(() => close(upstream));
  const relay = await startOllamaCodexRelay({
    upstreamBaseUrl: `http://127.0.0.1:${address.port}/v1`,
  });
  t.after(() => relay.close());

  const response = await fetch(`${relay.baseUrl}/responses`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ model: 'qwen3:4b', stream: true, tools: [] }),
  });
  assert.equal(response.status, 502);
  assert.match(await response.text(), /unsupported Responses response content encoding: gzip/);
});

test('relay wrapper rewrites only its Notty provider and owns catalog cleanup', async () => {
  const command = sampleCommand('/run/user/1000/notty-ollama/catalog-deadbeef.json');
  const inspected = inspectCodexProviderCommand(command);
  assert.equal(inspected.providerId, 'notty_ollama_0123abcd');
  assert.equal(inspected.upstreamBaseUrl, 'http://ollama.test:11434/v1');
  const rewritten = rewriteCodexProviderCommand(inspected, 'http://127.0.0.1:23456/v1');
  assert.ok(rewritten.includes(
    'model_providers.notty_ollama_0123abcd.base_url="http://127.0.0.1:23456/v1"',
  ));
  assert.deepEqual(buildOllamaCodexRelayCommand(command, {
    nodeBin: '/node',
    relayPath: '/relay.cjs',
  }).slice(0, 3), ['/node', '/relay.cjs', '--']);

  const child = new EventEmitter();
  child.kill = () => true;
  let spawned;
  let closed = 0;
  const removed = [];
  const processObject = new EventEmitter();
  const resultPromise = runOllamaCodexRelayCommand(command, {
    processObject,
    environment: {},
    startRelay: async () => ({
      baseUrl: 'http://127.0.0.1:23456/v1',
      close: async () => { closed += 1; },
    }),
    spawn: (file, args, options) => {
      spawned = { file, args, options };
      queueMicrotask(() => child.emit('exit', 7, null));
      return child;
    },
    removeCatalog: (catalogPath, options) => {
      removed.push({ catalogPath, options });
      return true;
    },
  });
  const result = await resultPromise;
  assert.deepEqual(result, { code: 7, signal: null });
  assert.equal(spawned.file, '/usr/local/bin/codex');
  assert.ok(spawned.args.includes(
    'model_providers.notty_ollama_0123abcd.base_url="http://127.0.0.1:23456/v1"',
  ));
  assert.equal(closed, 1);
  assert.equal(removed.length, 1);
  assert.equal(
    removed[0].catalogPath,
    '/run/user/1000/notty-ollama/catalog-deadbeef.json',
  );
  assert.equal(removed[0].options.runtimeDir, '/run/user/1000');
  assert.equal(processObject.listenerCount('SIGTERM'), 0);
});

test('relay wrapper closes and removes its catalog when Codex spawn fails', async () => {
  let closed = 0;
  let removed = 0;
  await assert.rejects(
    runOllamaCodexRelayCommand(sampleCommand(), {
      processObject: new EventEmitter(),
      startRelay: async () => ({
        baseUrl: 'http://127.0.0.1:23456/v1',
        close: async () => { closed += 1; },
      }),
      spawn: () => { throw new Error('spawn failed'); },
      removeCatalog: () => { removed += 1; },
    }),
    /spawn failed/,
  );
  assert.equal(closed, 1);
  assert.equal(removed, 1);
});

test('catalog cleanup preserves fallback runtime-root semantics', async () => {
  const uid = typeof process.getuid === 'function' ? process.getuid() : 'unknown';
  const catalogPath = path.join(
    '/tmp',
    `notty-ollama-${uid}`,
    `catalog-${'a'.repeat(24)}-${'b'.repeat(32)}.json`,
  );
  let received;
  await removeOwnedCatalog(catalogPath, {
    environment: { XDG_RUNTIME_DIR: '/run/user/1000' },
    removeCatalog: (value, options) => {
      received = { value, options };
      return true;
    },
  });
  assert.equal(received.value, catalogPath);
  assert.equal(received.options.runtimeDir, '');
  assert.equal(received.options.environment.XDG_RUNTIME_DIR, '');
});

test('relay wrapper rejects commands for non-Notty providers', () => {
  const command = sampleCommand().map((part) => (
    part.replaceAll('notty_ollama_0123abcd', 'ollama')
  ));
  assert.throws(() => inspectCodexProviderCommand(command), /non-Notty model provider/);
});
