'use strict';

const assert = require('node:assert/strict');
const childProcess = require('node:child_process');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const test = require('node:test');

const examplePath = path.resolve(__dirname, '../examples/codex-ollama/run.cjs');

function writeExecutable(filePath, source) {
  fs.writeFileSync(filePath, source, { mode: 0o755 });
}

test('Codex Ollama example preflights, relays, preserves argv, and cleans its catalog', (t) => {
  const temporaryRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'notty-codex-ollama-example-'));
  t.after(() => fs.rmSync(temporaryRoot, { recursive: true, force: true }));
  const runtimeDir = path.join(temporaryRoot, 'runtime');
  const curlLog = path.join(temporaryRoot, 'curl.jsonl');
  const codexLog = path.join(temporaryRoot, 'codex.json');
  const fakeCurl = path.join(temporaryRoot, 'curl');
  const fakeCodex = path.join(temporaryRoot, 'codex');

  writeExecutable(fakeCurl, `#!${process.execPath}\n`
    + `'use strict';\n`
    + `const fs = require('node:fs');\n`
    + `const url = process.argv.at(-1);\n`
    + `fs.appendFileSync(process.env.EXAMPLE_CURL_LOG, JSON.stringify({ url, argv: process.argv.slice(2) }) + '\\n');\n`
    + `if (url.endsWith('/api/tags')) {\n`
    + `  process.stdout.write(JSON.stringify({ models: [{ name: 'qwen3:4b', model: 'qwen3:4b' }] }));\n`
    + `} else if (url.endsWith('/api/show')) {\n`
    + `  process.stdout.write(JSON.stringify({ capabilities: ['completion', 'tools'], model_info: { 'qwen3.context_length': 40960 } }));\n`
    + `} else {\n`
    + `  process.stderr.write('unexpected URL: ' + url);\n`
    + `  process.exitCode = 2;\n`
    + `}\n`);

  writeExecutable(fakeCodex, `#!${process.execPath}\n`
    + `'use strict';\n`
    + `const fs = require('node:fs');\n`
    + `const argv = process.argv.slice(2);\n`
    + `const providerConfig = argv.find((value) => value.startsWith('model_provider='));\n`
    + `const providerId = JSON.parse(providerConfig.slice('model_provider='.length));\n`
    + `const basePrefix = 'model_providers.' + providerId + '.base_url=';\n`
    + `const baseConfig = argv.find((value) => value.startsWith(basePrefix));\n`
    + `const catalogConfig = argv.find((value) => value.startsWith('model_catalog_json='));\n`
    + `const catalogPath = JSON.parse(catalogConfig.slice('model_catalog_json='.length));\n`
    + `fs.writeFileSync(process.env.EXAMPLE_CODEX_LOG, JSON.stringify({\n`
    + `  argv,\n`
    + `  providerId,\n`
    + `  baseUrl: JSON.parse(baseConfig.slice(basePrefix.length)),\n`
    + `  catalogPath,\n`
    + `  catalogExists: fs.existsSync(catalogPath),\n`
    + `}));\n`
    + `process.exitCode = 7;\n`);

  const result = childProcess.spawnSync(process.execPath, [
    examplePath,
    '--model', 'qwen3:4b',
    '--endpoint', 'http://ollama.example:11434',
    '--curl-bin', fakeCurl,
    '--codex-bin', fakeCodex,
    '--runtime-dir', runtimeDir,
    '--',
    'exec', '--sandbox', 'read-only', 'hello world',
  ], {
    cwd: path.resolve(__dirname, '..'),
    encoding: 'utf8',
    env: {
      ...process.env,
      EXAMPLE_CURL_LOG: curlLog,
      EXAMPLE_CODEX_LOG: codexLog,
    },
  });

  assert.equal(result.status, 7, result.stderr || result.stdout);
  const curlCalls = fs.readFileSync(curlLog, 'utf8').trim().split('\n').map(JSON.parse);
  assert.deepEqual(
    curlCalls.map((call) => call.url),
    [
      'http://ollama.example:11434/api/tags',
      'http://ollama.example:11434/api/show',
    ],
  );
  assert.equal(curlCalls.some((call) => call.url.includes('/api/pull')), false);

  const launched = JSON.parse(fs.readFileSync(codexLog, 'utf8'));
  assert.match(launched.providerId, /^notty_ollama_[0-9a-f]{32}$/);
  assert.match(launched.baseUrl, /^http:\/\/127\.0\.0\.1:\d+\/v1$/);
  assert.equal(launched.catalogExists, true);
  assert.deepEqual(launched.argv.slice(0, 2), ['-m', 'qwen3:4b']);
  assert.deepEqual(
    launched.argv.slice(-4),
    ['exec', '--sandbox', 'read-only', 'hello world'],
  );
  assert.equal(launched.argv.includes('launch'), false);
  assert.equal(fs.existsSync(launched.catalogPath), false);

});

test('Codex Ollama example defaults to a read-only interactive launch', async () => {
  const { DEFAULT_CODEX_ARGS, parseArgs, runExample } = require(examplePath);
  const parsed = parseArgs(['--model', 'qwen3:4b'], {});
  let command;
  const result = await runExample(parsed, {
    cwd: '/workspace/example',
    environment: {},
    prepareOllamaCodexProvider: () => ({
      catalogPath: '/tmp/example-catalog.json',
      args: ['-m', 'qwen3:4b', '-c', 'model_provider="notty_ollama_deadbeef"'],
    }),
    runOllamaCodexRelayCommand: async (value) => {
      command = value;
      return { code: 0, signal: null };
    },
    removeOllamaModelCatalog: () => true,
  });

  assert.deepEqual(command.slice(-DEFAULT_CODEX_ARGS.length), DEFAULT_CODEX_ARGS);
  assert.deepEqual(result, { code: 0, signal: null });
});
