#!/usr/bin/env node
'use strict';

const crypto = require('node:crypto');
const path = require('node:path');

const {
  prepareOllamaCodexProvider,
  removeOllamaModelCatalog,
} = require('../../lib/collab/ollama.cjs');
const {
  runOllamaCodexRelayCommand,
} = require('../../lib/collab/ollama-codex-relay.cjs');

const DEFAULT_CODEX_ARGS = [
  '--sandbox', 'read-only',
  '--ask-for-approval', 'never',
];

function usage() {
  return [
    'Usage:',
    '  run.cjs --model MODEL [options] [-- CODEX_ARGS...]',
    '',
    'Options:',
    '  --model MODEL       Installed Ollama model (or OLLAMA_MODEL)',
    '  --endpoint URL      Ollama client origin (or OLLAMA_HOST)',
    '  --codex-bin PATH    Codex executable (default: CODEX_BIN or codex)',
    '  --curl-bin PATH     curl executable (default: CURL_BIN or curl)',
    '  --runtime-dir PATH  Parent for the private model catalog',
    '  --timeout-ms MS     Ollama preflight timeout (default: 5000)',
    '  -h, --help          Show this help',
    '',
    'Without CODEX_ARGS, Codex opens interactively in read-only mode with approvals disabled.',
    'Arguments after -- replace those safe defaults and are passed directly to Codex.',
  ].join('\n');
}

function requiredValue(argv, index, option) {
  const value = argv[index + 1];
  if (value === undefined || value === '--') throw new Error(`${option} requires a value`);
  return value;
}

function parseArgs(argv = process.argv.slice(2), environment = process.env) {
  const options = {
    model: String(environment.OLLAMA_MODEL || '').trim(),
    endpoint: String(environment.OLLAMA_HOST || '').trim() || undefined,
    codexBin: String(environment.CODEX_BIN || 'codex').trim(),
    curlBin: String(environment.CURL_BIN || 'curl').trim(),
    runtimeDir: String(environment.XDG_RUNTIME_DIR || '').trim() || undefined,
    timeoutMs: undefined,
    codexArgs: [],
  };

  for (let index = 0; index < argv.length; index += 1) {
    const argument = argv[index];
    if (argument === '-h' || argument === '--help') return { help: true };
    if (argument === '--') {
      options.codexArgs = argv.slice(index + 1);
      break;
    }
    const value = requiredValue(argv, index, argument);
    if (argument === '--model') options.model = value.trim();
    else if (argument === '--endpoint') options.endpoint = value.trim();
    else if (argument === '--codex-bin') options.codexBin = value.trim();
    else if (argument === '--curl-bin') options.curlBin = value.trim();
    else if (argument === '--runtime-dir') options.runtimeDir = value.trim();
    else if (argument === '--timeout-ms') {
      options.timeoutMs = Number(value);
      if (!Number.isSafeInteger(options.timeoutMs) || options.timeoutMs <= 0) {
        throw new Error('--timeout-ms must be a positive integer');
      }
    } else {
      throw new Error(`unknown option: ${argument}`);
    }
    index += 1;
  }

  if (!options.model) throw new Error('--model or OLLAMA_MODEL is required');
  if (!options.codexBin) throw new Error('--codex-bin or CODEX_BIN must not be empty');
  if (!options.curlBin) throw new Error('--curl-bin or CURL_BIN must not be empty');
  if (options.endpoint !== undefined && !options.endpoint) {
    throw new Error('--endpoint must not be empty');
  }
  if (options.runtimeDir !== undefined && !options.runtimeDir) {
    throw new Error('--runtime-dir must not be empty');
  }
  return options;
}

async function runExample(options, dependencies = {}) {
  const environment = dependencies.environment || process.env;
  const cwd = path.resolve(dependencies.cwd || process.cwd());
  const prepareProvider = dependencies.prepareOllamaCodexProvider
    || prepareOllamaCodexProvider;
  const runRelay = dependencies.runOllamaCodexRelayCommand
    || runOllamaCodexRelayCommand;
  const removeCatalog = dependencies.removeOllamaModelCatalog
    || removeOllamaModelCatalog;
  const log = dependencies.log || ((message) => process.stderr.write(`${message}\n`));
  const prepared = prepareProvider({
    endpoint: options.endpoint,
    model: options.model,
    curlBin: options.curlBin,
    runtimeDir: options.runtimeDir,
    timeoutMs: options.timeoutMs,
    environment,
    isolationKey: `codex-ollama-example:${cwd}:${process.pid}:${crypto.randomUUID()}`,
  });
  const codexArgs = options.codexArgs.length > 0
    ? options.codexArgs
    : DEFAULT_CODEX_ARGS;
  const command = [options.codexBin, ...prepared.args, ...codexArgs];

  try {
    return await runRelay(command, { cwd, environment, log });
  } finally {
    try {
      removeCatalog(prepared.catalogPath, {
        runtimeDir: options.runtimeDir,
        environment,
      });
    } catch (error) {
      log(`codex-ollama example: unable to remove model catalog: ${error.message}`);
    }
  }
}

async function main(argv = process.argv.slice(2), dependencies = {}) {
  const options = parseArgs(argv, dependencies.environment || process.env);
  if (options.help) {
    process.stdout.write(`${usage()}\n`);
    return;
  }
  const result = await runExample(options, dependencies);
  if (result.signal) {
    process.kill(process.pid, result.signal);
    return;
  }
  process.exitCode = result.code === null ? 1 : result.code;
}

if (require.main === module) {
  main().catch((error) => {
    process.stderr.write(`codex-ollama example: ${error?.message || error}\n`);
    process.exitCode = 1;
  });
}

module.exports = {
  DEFAULT_CODEX_ARGS,
  main,
  parseArgs,
  runExample,
  usage,
};
