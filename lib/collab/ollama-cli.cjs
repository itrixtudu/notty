#!/usr/bin/env node
'use strict';

const {
  prepareOllamaCodexProvider,
  removeOllamaModelCatalog,
} = require('./ollama.cjs');

function usage() {
  return [
    'Usage:',
    '  ollama-cli.cjs prepare-codex --model MODEL [options]',
    '  ollama-cli.cjs remove-catalog --catalog-config CONFIG [options]',
    '',
    'Options:',
    '  --endpoint URL        Ollama endpoint (default: OLLAMA_HOST)',
    '  --runtime-dir PATH    Parent for the isolated model catalog',
    '  --isolation-key KEY   Stable per-agent catalog identity',
    '  --curl-bin PATH       curl executable',
    '  --timeout-ms MS       Ollama query timeout',
    '  --format json|nul     Output format (default: json)',
    '  --catalog-config ARG  model_catalog_json=JSON assignment to remove',
  ].join('\n');
}

function parseArgs(argv) {
  const command = String(argv[0] || '');
  if (command === '-h' || command === '--help') return { help: true };
  if (!['prepare-codex', 'remove-catalog'].includes(command)) {
    throw new Error(`unsupported command: ${command || '(empty)'}`);
  }
  const values = { command, format: 'json' };
  for (let index = 1; index < argv.length; index += 1) {
    const option = argv[index];
    if (option === '-h' || option === '--help') return { help: true };
    if (!option.startsWith('--')) throw new Error(`unexpected argument: ${option}`);
    const key = option.slice(2).replace(/-([a-z])/g, (_match, letter) => letter.toUpperCase());
    const value = argv[index + 1];
    const allowed = command === 'prepare-codex'
      ? ['endpoint', 'runtimeDir', 'isolationKey', 'curlBin', 'timeoutMs', 'format', 'model']
      : ['runtimeDir', 'catalogConfig'];
    if (!allowed.includes(key)) {
      throw new Error(`unknown option: ${option}`);
    }
    if (value === undefined) throw new Error(`${option} requires a value`);
    values[key] = value;
    index += 1;
  }
  if (command === 'prepare-codex' && !values.model) throw new Error('--model is required');
  if (command === 'remove-catalog' && !values.catalogConfig) {
    throw new Error('--catalog-config is required');
  }
  if (command === 'prepare-codex' && !['json', 'nul'].includes(values.format)) {
    throw new Error('--format must be json or nul');
  }
  if (command === 'prepare-codex' && values.timeoutMs !== undefined) {
    values.timeoutMs = Number(values.timeoutMs);
    if (!Number.isSafeInteger(values.timeoutMs) || values.timeoutMs <= 0) {
      throw new Error('--timeout-ms must be a positive integer');
    }
  }
  return values;
}

function catalogPathFromConfig(value) {
  const config = String(value || '');
  const prefix = 'model_catalog_json=';
  if (!config.startsWith(prefix)) {
    throw new Error('--catalog-config must be a model_catalog_json assignment');
  }
  let catalogPath;
  try {
    catalogPath = JSON.parse(config.slice(prefix.length));
  } catch (error) {
    throw new Error(`invalid model_catalog_json assignment: ${error.message}`);
  }
  if (typeof catalogPath !== 'string' || !catalogPath) {
    throw new Error('model_catalog_json must contain a non-empty string');
  }
  return catalogPath;
}

function main(argv = process.argv.slice(2)) {
  const options = parseArgs(argv);
  if (options.help) {
    process.stdout.write(`${usage()}\n`);
    return;
  }
  if (options.command === 'remove-catalog') {
    removeOllamaModelCatalog(catalogPathFromConfig(options.catalogConfig), {
      runtimeDir: options.runtimeDir,
    });
    return;
  }
  const prepared = prepareOllamaCodexProvider(options);
  if (options.format === 'nul') {
    process.stdout.write(Buffer.from(`${prepared.args.join('\0')}\0`, 'utf8'));
    return;
  }
  process.stdout.write(`${JSON.stringify({
    endpoint: prepared.endpoint,
    baseUrl: prepared.baseUrl,
    model: prepared.model,
    providerId: prepared.providerId,
    catalogPath: prepared.catalogPath,
    installedModel: prepared.installedModel,
    args: prepared.args,
  })}\n`);
}

if (require.main === module) {
  try {
    main();
  } catch (error) {
    process.stderr.write(`ollama-cli: ${error?.message || error}\n`);
    process.exitCode = 1;
  }
}

module.exports = { catalogPathFromConfig, main, parseArgs, usage };
