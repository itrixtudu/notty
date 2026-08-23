'use strict';

const assert = require('node:assert/strict');
const childProcess = require('node:child_process');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const test = require('node:test');

const {
  DEFAULT_OLLAMA_CONTEXT_WINDOW,
  MAX_OLLAMA_CONTEXT_WINDOW,
  MIN_OLLAMA_CONTEXT_WINDOW,
  OLLAMA_CODEX_PROVIDER_PREFIX,
  buildCodexOllamaProviderArgs,
  modelContextWindow,
  normalizeOllamaEndpoint,
  prepareOllamaCodexProvider,
  removeOllamaModelCatalog,
  requireInstalledOllamaModel,
  runtimeCatalogRoot,
  writeOllamaModelCatalog,
} = require('../lib/collab/ollama.cjs');
const { parseArgs: parseOllamaCliArgs } = require('../lib/collab/ollama-cli.cjs');

function fakeOllamaCurl(models, shown = {}) {
  const calls = [];
  const spawnSync = (command, args, options) => {
    calls.push({ command, args, options });
    const url = args.at(-1);
    if (url.endsWith('/api/tags')) {
      return { status: 0, stdout: JSON.stringify({ models }), stderr: '' };
    }
    if (url.endsWith('/api/show')) {
      return { status: 0, stdout: JSON.stringify(shown), stderr: '' };
    }
    return { status: 22, stdout: '', stderr: `unexpected URL: ${url}` };
  };
  return { calls, spawnSync };
}

test('Ollama endpoints normalize client origins without accepting bind addresses or paths', () => {
  assert.equal(normalizeOllamaEndpoint(undefined, {}), 'http://127.0.0.1:11434');
  assert.equal(normalizeOllamaEndpoint('ollama.internal', {}), 'http://ollama.internal:11434');
  assert.equal(normalizeOllamaEndpoint('172.17.0.1:11500', {}), 'http://172.17.0.1:11500');
  assert.equal(normalizeOllamaEndpoint('https://ollama.internal/', {}), 'https://ollama.internal');
  assert.equal(normalizeOllamaEndpoint('ollama.com', {}), 'http://ollama.com:11434');
  assert.equal(
    normalizeOllamaEndpoint(undefined, { OLLAMA_HOST: 'http://host.docker.internal:11434' }),
    'http://host.docker.internal:11434',
  );

  assert.throws(
    () => normalizeOllamaEndpoint('http://0.0.0.0:11434', {}),
    /client endpoint.*wildcard bind address 0\.0\.0\.0/i,
  );
  assert.throws(
    () => normalizeOllamaEndpoint('http://[::]:11434', {}),
    /client endpoint.*wildcard bind address ::/i,
  );
  assert.throws(
    () => normalizeOllamaEndpoint('http://ollama.internal:11434/api', {}),
    /server origin without a path/i,
  );
  assert.throws(
    () => normalizeOllamaEndpoint('ssh://ollama.internal', {}),
    /unsupported Ollama URL protocol/i,
  );
  assert.throws(
    () => normalizeOllamaEndpoint('http://user:secret@ollama.internal', {}),
    /must not include credentials/i,
  );
});

test('installed model preflight uses tags and show without invoking Ollama or pulling', () => {
  const curl = fakeOllamaCurl([
    { name: 'Qwen3:4B', model: 'Qwen3:4B', details: { parameter_size: '4.0B' } },
  ], {
    capabilities: ['completion', 'tools', 'thinking'],
    model_info: { 'qwen3.context_length': 40_960 },
  });

  const selected = requireInstalledOllamaModel('qwen3:4b', {
    endpoint: '127.0.0.1:11434',
    environment: {},
    spawnSync: curl.spawnSync,
    curlBin: '/usr/bin/curl',
  });

  assert.equal(selected.endpoint, 'http://127.0.0.1:11434');
  assert.equal(selected.requestedModel, 'qwen3:4b');
  assert.equal(selected.model, 'Qwen3:4B');
  assert.equal(selected.installedModel.name, 'Qwen3:4B');
  assert.equal(curl.calls.length, 2);
  assert.deepEqual(curl.calls.map((call) => call.command), ['/usr/bin/curl', '/usr/bin/curl']);
  assert.equal(curl.calls.every((call) => call.args[0] === '--disable'), true);
  assert.deepEqual(curl.calls.map((call) => call.args.at(-1)), [
    'http://127.0.0.1:11434/api/tags',
    'http://127.0.0.1:11434/api/show',
  ]);
  const showCall = curl.calls[1];
  const bodyIndex = showCall.args.indexOf('--data-binary');
  assert.deepEqual(JSON.parse(showCall.args[bodyIndex + 1]), { model: 'Qwen3:4B' });
  assert.equal(curl.calls.some((call) => call.args.some((arg) => /pull/i.test(arg))), false);
});

test('installed model preflight accepts an implicit latest tag and rejects absent models', () => {
  const available = fakeOllamaCurl([{ name: 'mistral:latest' }], {
    capabilities: ['completion', 'tools'],
    model_info: {},
  });
  assert.equal(requireInstalledOllamaModel('MISTRAL', {
    environment: {},
    spawnSync: available.spawnSync,
  }).model, 'mistral:latest');

  const missing = fakeOllamaCurl([{ name: 'mistral:latest' }]);
  assert.throws(
    () => requireInstalledOllamaModel('qwen3:4b', {
      environment: {},
      spawnSync: missing.spawnSync,
    }),
    /model is not installed.*qwen3:4b/i,
  );
  assert.equal(missing.calls.length, 1);
});

test('installed model preflight rejects models that do not advertise tool support', () => {
  for (const shown of [
    { capabilities: ['completion'], model_info: {} },
    { model_info: { 'text.context_length': 32_768 } },
  ]) {
    const curl = fakeOllamaCurl([{ name: 'text-only:latest' }], shown);
    assert.throws(
      () => requireInstalledOllamaModel('text-only:latest', {
        environment: {},
        spawnSync: curl.spawnSync,
      }),
      /model does not support tools.*text-only:latest.*\/api\/show/i,
    );
    assert.equal(curl.calls.length, 2);
  }
});

test('provider preparation writes a private atomic catalog and complete direct Codex argv', (t) => {
  const runtimeDir = fs.mkdtempSync(path.join(os.tmpdir(), 'notty-ollama-runtime-'));
  t.after(() => fs.rmSync(runtimeDir, { recursive: true, force: true }));
  const curl = fakeOllamaCurl([{ name: 'qwen3:4b' }], {
    capabilities: ['completion', 'tools', 'thinking'],
    model_info: {
      'qwen3.context_length': 40_960,
      'qwen3.embedding_length': 2_560,
      context_length: 32_768,
      'string.context_length': '999999',
    },
  });

  const prepared = prepareOllamaCodexProvider({
    model: 'qwen3:4b',
    endpoint: 'http://host.docker.internal:11434',
    environment: {},
    spawnSync: curl.spawnSync,
    runtimeDir,
    isolationKey: 'session:coder',
    providerId: 'notty_ollama',
  });

  assert.match(
    prepared.providerId,
    new RegExp(`^${OLLAMA_CODEX_PROVIDER_PREFIX}_[0-9a-f]{32}$`),
  );
  assert.notEqual(prepared.providerId, 'notty_ollama');
  assert.equal(prepared.baseUrl, 'http://host.docker.internal:11434/v1');
  assert.equal(path.dirname(prepared.catalogPath), path.join(runtimeDir, 'notty-ollama'));
  assert.equal(fs.statSync(path.dirname(prepared.catalogPath)).mode & 0o777, 0o700);
  assert.equal(fs.statSync(prepared.catalogPath).mode & 0o777, 0o600);
  assert.deepEqual(JSON.parse(fs.readFileSync(prepared.catalogPath, 'utf8')), prepared.catalog);
  assert.equal(prepared.catalog.models[0].slug, 'qwen3:4b');
  assert.equal(prepared.catalog.models[0].context_window, 40_960);
  assert.deepEqual(prepared.catalog.models[0].input_modalities, ['text']);
  assert.equal(prepared.catalog.models[0].support_verbosity, false);
  assert.equal(prepared.catalog.models[0].default_verbosity, null);
  assert.match(prepared.catalog.models[0].base_instructions, /coding agent/i);
  assert.doesNotMatch(prepared.catalog.models[0].base_instructions, /apply_patch/i);
  assert.equal(prepared.catalog.models[0].supports_reasoning_summaries, false);
  assert.deepEqual(prepared.catalog.models[0].supported_reasoning_levels, []);

  assert.deepEqual(prepared.args.slice(0, 2), ['-m', 'qwen3:4b']);
  assert.ok(prepared.args.includes(`model_provider=${JSON.stringify(prepared.providerId)}`));
  assert.ok(prepared.args.includes(
    `model_providers.${prepared.providerId}.base_url="http://host.docker.internal:11434/v1"`,
  ));
  assert.ok(prepared.args.includes(`model_providers.${prepared.providerId}.wire_api="responses"`));
  assert.ok(prepared.args.includes(
    `model_providers.${prepared.providerId}.requires_openai_auth=false`,
  ));
  assert.ok(prepared.args.includes(`model_catalog_json=${JSON.stringify(prepared.catalogPath)}`));
  assert.ok(prepared.args.includes(`web_search=${JSON.stringify('disabled')}`));
  assert.equal(prepared.args.some((arg) => arg === '--oss' || /\bollama\s+launch\b/.test(arg)), false);
  assert.deepEqual(
    fs.readdirSync(path.dirname(prepared.catalogPath)).filter((name) => name.endsWith('.tmp')),
    [],
  );

  const other = prepareOllamaCodexProvider({
    model: 'qwen3:4b',
    endpoint: 'http://host.docker.internal:11434',
    environment: {},
    spawnSync: curl.spawnSync,
    runtimeDir,
    isolationKey: 'session:reviewer',
  });
  assert.notEqual(other.catalogPath, prepared.catalogPath);
  assert.notEqual(other.providerId, prepared.providerId);
});

test('catalog paths include the model identity and remain unique for every launch', (t) => {
  const runtimeDir = fs.mkdtempSync(path.join(os.tmpdir(), 'notty-ollama-isolation-'));
  t.after(() => fs.rmSync(runtimeDir, { recursive: true, force: true }));
  const common = { runtimeDir, environment: {}, isolationKey: 'workspace:agent' };

  const first = writeOllamaModelCatalog({ ...common, model: 'qwen3:4b' });
  const second = writeOllamaModelCatalog({ ...common, model: 'qwen3:4b' });
  const differentModel = writeOllamaModelCatalog({ ...common, model: 'mistral:latest' });
  const prefix = (catalogPath) => path.basename(catalogPath).match(
    /^catalog-([a-f0-9]{24})-[a-f0-9]{32}\.json$/,
  )?.[1];

  assert.ok(prefix(first.catalogPath));
  assert.equal(prefix(second.catalogPath), prefix(first.catalogPath));
  assert.notEqual(prefix(differentModel.catalogPath), prefix(first.catalogPath));
  assert.notEqual(second.catalogPath, first.catalogPath);
  assert.equal(new Set([
    first.catalogPath,
    second.catalogPath,
    differentModel.catalogPath,
  ]).size, 3);
});

test('catalog cleanup is scoped, symlink-safe, and idempotent', (t) => {
  const runtimeDir = fs.mkdtempSync(path.join(os.tmpdir(), 'notty-ollama-cleanup-'));
  t.after(() => fs.rmSync(runtimeDir, { recursive: true, force: true }));
  const written = writeOllamaModelCatalog({
    model: 'qwen3:4b',
    runtimeDir,
    environment: {},
    isolationKey: 'cleanup',
  });

  assert.equal(removeOllamaModelCatalog(written.catalogPath, { runtimeDir, environment: {} }), true);
  assert.equal(fs.existsSync(written.catalogPath), false);
  assert.equal(removeOllamaModelCatalog(written.catalogPath, { runtimeDir, environment: {} }), false);
  assert.throws(
    () => removeOllamaModelCatalog(path.join(runtimeDir, 'unrelated.json'), {
      runtimeDir,
      environment: {},
    }),
    /refusing to remove unrecognized/i,
  );

  const symlinkPath = written.catalogPath;
  const targetPath = path.join(runtimeDir, 'must-remain.txt');
  fs.writeFileSync(targetPath, 'keep', 'utf8');
  fs.symlinkSync(targetPath, symlinkPath);
  assert.throws(
    () => removeOllamaModelCatalog(symlinkPath, { runtimeDir, environment: {} }),
    /refusing to remove non-file/i,
  );
  assert.equal(fs.readFileSync(targetPath, 'utf8'), 'keep');
});

test('model context metadata is numeric, bounded, and always a safe integer', () => {
  assert.equal(modelContextWindow({ model_info: { 'tiny.context_length': 1 } }), MIN_OLLAMA_CONTEXT_WINDOW);
  assert.equal(
    modelContextWindow({ model_info: { 'huge.context_length': Number.MAX_VALUE } }),
    MAX_OLLAMA_CONTEXT_WINDOW,
  );
  assert.equal(modelContextWindow({ model_info: { 'fraction.context_length': 40960.9 } }), 40_960);
  assert.equal(modelContextWindow({ model_info: { context_length: 32_768 } }), 32_768);
  assert.equal(
    modelContextWindow({ model_info: { 'string.context_length': '40960' } }),
    DEFAULT_OLLAMA_CONTEXT_WINDOW,
  );
  assert.equal(modelContextWindow({ model_info: {} }), 32_768);
  assert.equal(Number.isSafeInteger(MAX_OLLAMA_CONTEXT_WINDOW), true);
});

test('catalog root rejects a pre-created symlink without chmodding its target', (t) => {
  const base = fs.mkdtempSync(path.join(os.tmpdir(), 'notty-ollama-root-'));
  const runtimeDir = path.join(base, 'runtime');
  const symlinkTarget = path.join(base, 'target');
  fs.mkdirSync(runtimeDir, { mode: 0o700 });
  fs.mkdirSync(symlinkTarget, { mode: 0o755 });
  fs.symlinkSync(symlinkTarget, path.join(runtimeDir, 'notty-ollama'), 'dir');
  t.after(() => fs.rmSync(base, { recursive: true, force: true }));

  const originalMode = fs.statSync(symlinkTarget).mode & 0o777;
  assert.throws(
    () => runtimeCatalogRoot({ runtimeDir, environment: {} }),
    /catalog root must be a real directory/i,
  );
  assert.equal(fs.statSync(symlinkTarget).mode & 0o777, originalMode);
});

test('provider arg builder requires an isolated catalog path', () => {
  assert.throws(
    () => buildCodexOllamaProviderArgs({ model: 'qwen3:4b', endpoint: 'localhost:11434' }),
    /catalog path is required/i,
  );
});

test('prepare-codex CLI does not expose a provider-id override', () => {
  assert.throws(
    () => parseOllamaCliArgs([
      'prepare-codex', '--model', 'qwen3:4b', '--provider-id', 'notty_ollama',
    ]),
    /unknown option: --provider-id/i,
  );
});

test('prepare-codex CLI emits only NUL-terminated Codex argv tokens', (t) => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'notty-ollama-cli-'));
  const curlBin = path.join(root, 'fake-curl');
  fs.writeFileSync(curlBin, `#!/usr/bin/env node
const url = process.argv.at(-1);
if (url.endsWith('/api/tags')) {
  process.stdout.write(JSON.stringify({ models: [{ name: 'qwen3:4b' }] }));
} else if (url.endsWith('/api/show')) {
  process.stdout.write(JSON.stringify({
    capabilities: ['completion', 'tools'],
    model_info: { 'qwen3.context_length': 40960 },
  }));
} else {
  process.stderr.write('unexpected URL');
  process.exitCode = 22;
}
`, { encoding: 'utf8', mode: 0o700 });
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));

  const cliPath = path.resolve(__dirname, '..', 'lib', 'collab', 'ollama-cli.cjs');
  const result = childProcess.spawnSync(process.execPath, [
    cliPath,
    'prepare-codex',
    '--format', 'nul',
    '--endpoint', '127.0.0.1:11434',
    '--model', 'qwen3:4b',
    '--runtime-dir', root,
    '--isolation-key', 'shell-agent',
    '--curl-bin', curlBin,
  ], { encoding: 'buffer' });

  assert.equal(result.status, 0, result.stderr.toString('utf8'));
  assert.equal(result.stderr.length, 0);
  assert.equal(result.stdout.at(-1), 0, 'the final argv token must be NUL-terminated');
  const args = result.stdout.toString('utf8').split('\0').slice(0, -1);
  assert.deepEqual(args.slice(0, 2), ['-m', 'qwen3:4b']);
  const providerArg = args.find((arg) => arg.startsWith('model_provider='));
  const providerId = JSON.parse(providerArg.slice('model_provider='.length));
  assert.match(providerId, /^notty_ollama_[0-9a-f]{32}$/);
  assert.ok(args.includes(`model_providers.${providerId}.wire_api="responses"`));
  const catalogConfig = args.find((arg) => arg.startsWith('model_catalog_json='));
  assert.ok(catalogConfig);
  const catalogPath = JSON.parse(catalogConfig.slice('model_catalog_json='.length));
  assert.equal(fs.existsSync(catalogPath), true);
  assert.equal(args.includes('--oss'), false);

  for (let attempt = 0; attempt < 2; attempt += 1) {
    const removed = childProcess.spawnSync(process.execPath, [
      cliPath,
      'remove-catalog',
      '--runtime-dir', root,
      '--catalog-config', catalogConfig,
    ], { encoding: 'utf8' });
    assert.equal(removed.status, 0, removed.stderr);
    assert.equal(removed.stdout, '');
    assert.equal(removed.stderr, '');
  }
  assert.equal(fs.existsSync(catalogPath), false);
});
