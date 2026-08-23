import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { parseBooleanSwitch } from './runtimeFeatures.js';

const SCHEMA_VERSION = 1;
const MODES = new Set(['next', 'sse', 'stdio']);
const SWITCH_NAMES = new Set(['collab']);

function isPlainObject(value) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    return false;
  }
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

export function parseRuntimeArgs(argv = []) {
  const parsed = {
    collab: undefined,
    configPath: '',
    help: false,
    mode: '',
  };

  for (let index = 0; index < argv.length; index += 1) {
    const argument = String(argv[index]);
    if (argument === '--collab') {
      parsed.collab = true;
      continue;
    }
    if (argument === '--no-collab') {
      parsed.collab = false;
      continue;
    }
    if (argument === '--help' || argument === '-h') {
      parsed.help = true;
      continue;
    }
    if (argument === '--config' || argument === '--mode') {
      const value = argv[index + 1];
      if (
        value === undefined
        || !String(value).trim()
        || String(value).startsWith('-')
      ) {
        throw new Error(`${argument} requires a value`);
      }
      if (argument === '--config') {
        parsed.configPath = String(value);
      } else {
        parsed.mode = String(value).trim().toLowerCase();
      }
      index += 1;
      continue;
    }
    if (argument.startsWith('--config=')) {
      const value = argument.slice('--config='.length);
      if (!value.trim()) {
        throw new Error('--config requires a value');
      }
      parsed.configPath = value;
      continue;
    }
    if (argument.startsWith('--mode=')) {
      const value = argument.slice('--mode='.length).trim().toLowerCase();
      if (!value) {
        throw new Error('--mode requires a value');
      }
      parsed.mode = value;
      continue;
    }
    if (!argument.startsWith('-') && MODES.has(argument.toLowerCase()) && !parsed.mode) {
      parsed.mode = argument.toLowerCase();
      continue;
    }
    throw new Error(`unknown Notty option: ${argument}`);
  }

  return parsed;
}

function readConfigDocument(filePath, options = {}) {
  let source;
  try {
    source = fs.readFileSync(filePath, 'utf8');
  } catch (error) {
    if (error.code === 'ENOENT') {
      if (options.required) {
        throw new Error(`Notty config does not exist: ${filePath}`);
      }
      return null;
    }
    throw new Error(`invalid Notty config ${filePath}: ${error.message}`);
  }

  let document;
  try {
    document = JSON.parse(source);
  } catch (error) {
    throw new Error(`invalid Notty config ${filePath}: ${error.message}`);
  }
  if (!isPlainObject(document)) {
    throw new Error(`Notty config ${filePath} must contain a JSON object`);
  }
  if (document.schemaVersion !== undefined && document.schemaVersion !== SCHEMA_VERSION) {
    throw new Error(`Notty config ${filePath} schemaVersion must be ${SCHEMA_VERSION}`);
  }
  if (document.switches !== undefined && !isPlainObject(document.switches)) {
    throw new Error(`Notty config ${filePath} switches must be an object`);
  }
  for (const name of Object.keys(document.switches || {})) {
    if (!SWITCH_NAMES.has(name)) {
      throw new Error(`Notty config ${filePath} contains unknown switch ${JSON.stringify(name)}`);
    }
  }
  if (
    document.switches
    && Object.hasOwn(document.switches, 'collab')
    && typeof document.switches.collab !== 'boolean'
  ) {
    throw new Error(`Notty config ${filePath} switches.collab must be a boolean`);
  }
  return document;
}

export function resolveRuntimeConfig(options = {}) {
  const env = options.env || process.env;
  const argv = options.argv || [];
  const appRoot = path.resolve(options.appRoot || process.cwd());
  const workspaceRoot = path.resolve(options.workspaceRoot || env.NOTTY_WORKDIR || process.cwd());
  const configHome = path.resolve(
    options.configHome
    || env.XDG_CONFIG_HOME
    || path.join(env.HOME || os.homedir(), '.config'),
  );
  const cli = parseRuntimeArgs(argv);
  if (cli.help) {
    return {
      schemaVersion: SCHEMA_VERSION,
      mode: cli.mode || 'next',
      help: true,
      switches: { collab: false },
      sources: { collab: 'default' },
      paths: {
        builtin: path.resolve(options.builtinPath || path.join(appRoot, 'config', 'config.json')),
        user: path.resolve(options.userPath || path.join(configHome, 'notty', 'config.json')),
        workspace: path.resolve(options.workspacePath || path.join(workspaceRoot, '.notty', 'config.json')),
        explicit: '',
        loaded: [],
      },
    };
  }
  const explicitConfig = cli.configPath || env.NOTTY_CONFIG || '';
  const layers = [
    { source: 'builtin', path: path.resolve(options.builtinPath || path.join(appRoot, 'config', 'config.json')), required: true },
    { source: 'user', path: path.resolve(options.userPath || path.join(configHome, 'notty', 'config.json')), required: false },
    { source: 'workspace', path: path.resolve(options.workspacePath || path.join(workspaceRoot, '.notty', 'config.json')), required: false },
  ];
  if (explicitConfig) {
    layers.push({
      source: 'explicit',
      path: path.resolve(options.cwd || process.cwd(), explicitConfig),
      required: true,
    });
  }

  let collab = false;
  let collabSource = 'default';
  const loadedPaths = [];
  for (const layer of layers) {
    const document = readConfigDocument(layer.path, { required: layer.required });
    if (!document) {
      continue;
    }
    loadedPaths.push(layer.path);
    if (document.switches && Object.hasOwn(document.switches, 'collab')) {
      collab = document.switches.collab;
      collabSource = layer.source;
    }
  }

  if (Object.hasOwn(env, 'NOTTY_COLLAB_ENABLED')) {
    collab = parseBooleanSwitch(env.NOTTY_COLLAB_ENABLED, 'NOTTY_COLLAB_ENABLED');
    collabSource = 'environment';
  }
  if (cli.collab !== undefined) {
    collab = cli.collab;
    collabSource = 'cli';
  }

  const environmentMode = String(env.NOTTY_MODE || '').trim().toLowerCase();
  const mode = cli.mode || environmentMode || 'next';
  if (!MODES.has(mode)) {
    throw new Error(`Notty mode must be one of: ${Array.from(MODES).join(', ')}`);
  }
  if (collab && mode !== 'next') {
    throw new Error(`Collab requires next mode; received ${mode}`);
  }

  return {
    schemaVersion: SCHEMA_VERSION,
    mode,
    help: cli.help,
    switches: { collab },
    sources: { collab: collabSource },
    paths: {
      builtin: layers[0].path,
      user: layers[1].path,
      workspace: layers[2].path,
      explicit: explicitConfig ? layers.at(-1).path : '',
      loaded: loadedPaths,
    },
  };
}

export function applyRuntimeConfigToEnv(config, env = process.env) {
  env.NOTTY_COLLAB_ENABLED = config.switches.collab ? 'true' : 'false';
  return env;
}

export function runtimeHelp() {
  return [
    'Usage: node server.js [next|sse|stdio] [options]',
    '',
    'Options:',
    '  --collab            Enable Collab UI, APIs, supervisor, and daemon',
    '  --no-collab         Disable Collab even when enabled by config or environment',
    '  --config PATH       Load an additional config.json layer',
    '  --mode MODE         Select next, sse, or stdio mode',
    '  -h, --help          Show this help',
  ].join('\n');
}

export { parseBooleanSwitch } from './runtimeFeatures.js';
