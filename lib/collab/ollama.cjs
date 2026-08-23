'use strict';

const childProcess = require('node:child_process');
const crypto = require('node:crypto');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

const DEFAULT_OLLAMA_HOST = '127.0.0.1:11434';
const DEFAULT_OLLAMA_TIMEOUT_MS = 5000;
const DEFAULT_OLLAMA_CONTEXT_WINDOW = 32_768;
const MIN_OLLAMA_CONTEXT_WINDOW = 1_024;
const MAX_OLLAMA_CONTEXT_WINDOW = 1_048_576;
const OLLAMA_CODEX_PROVIDER_PREFIX = 'notty_ollama';
const OLLAMA_CODEX_BASE_INSTRUCTIONS = [
  'You are Codex, a coding agent working in the current repository.',
  'Follow the repository instructions, inspect relevant files, make careful changes with the available tools, and verify the result when practical.',
  'Keep responses concise and state blockers clearly.',
].join(' ');

function normalizeOllamaEndpoint(value, environment = process.env) {
  const inputValue = value ?? environment.OLLAMA_HOST ?? '';
  let input = String(inputValue).trim();
  if (!input) input = DEFAULT_OLLAMA_HOST;

  const hasScheme = /^[A-Za-z][A-Za-z0-9+.-]*:\/\//.test(input);

  let endpoint;
  try {
    endpoint = new URL(hasScheme ? input : `http://${input}`);
  } catch (error) {
    throw new Error(`invalid OLLAMA_HOST ${JSON.stringify(input)}: ${error.message}`);
  }

  if (!['http:', 'https:'].includes(endpoint.protocol)) {
    throw new Error(`unsupported Ollama URL protocol: ${endpoint.protocol}`);
  }
  if (!endpoint.hostname) throw new Error('OLLAMA_HOST must include a host');
  if (endpoint.username || endpoint.password) {
    throw new Error('OLLAMA_HOST must not include credentials');
  }
  if (endpoint.search || endpoint.hash) {
    throw new Error('OLLAMA_HOST must not include a query string or fragment');
  }
  if (endpoint.pathname !== '/') {
    throw new Error('OLLAMA_HOST must be an Ollama server origin without a path');
  }

  if (!hasScheme && !endpoint.port) endpoint.port = '11434';
  const hostname = endpoint.hostname.replace(/^\[|\]$/g, '');
  if (hostname === '0.0.0.0' || hostname === '::') {
    throw new Error(
      `OLLAMA_HOST is a client endpoint and cannot use wildcard bind address ${hostname}; `
      + 'use a reachable host address instead',
    );
  }

  return endpoint.origin;
}

function ollamaUrl(endpoint, suffix) {
  const normalized = normalizeOllamaEndpoint(endpoint, {});
  return `${normalized}${String(suffix).startsWith('/') ? suffix : `/${suffix}`}`;
}

function ollamaCodexBaseUrl(endpoint) {
  return ollamaUrl(endpoint, '/v1');
}

function curlJson(url, options = {}) {
  const spawnSync = options.spawnSync || childProcess.spawnSync;
  const timeoutMs = Number.isFinite(options.timeoutMs) && options.timeoutMs > 0
    ? Math.floor(options.timeoutMs)
    : DEFAULT_OLLAMA_TIMEOUT_MS;
  const args = [
    '--disable',
    '--fail',
    '--silent',
    '--show-error',
    '--max-time', String(Math.max(1, Math.ceil(timeoutMs / 1000))),
    '--header', 'accept: application/json',
  ];
  if (options.body !== undefined) {
    args.push(
      '--request', options.method || 'POST',
      '--header', 'content-type: application/json',
      '--data-binary', JSON.stringify(options.body),
    );
  } else if (options.method && options.method !== 'GET') {
    args.push('--request', options.method);
  }
  args.push(url);

  const command = String(options.curlBin || options.environment?.CURL_BIN || 'curl');
  const result = spawnSync(command, args, {
    encoding: 'utf8',
    timeout: timeoutMs + 1000,
    maxBuffer: 4 * 1024 * 1024,
    env: options.environment || process.env,
  });
  if (result.error) {
    throw new Error(`unable to query Ollama at ${url}: ${result.error.message}`);
  }
  if (result.status !== 0) {
    const detail = String(result.stderr || result.stdout || `${command} exited ${result.status}`).trim();
    throw new Error(`unable to query Ollama at ${url}: ${detail}`);
  }
  try {
    const parsed = JSON.parse(String(result.stdout || ''));
    if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
      throw new Error('expected a JSON object');
    }
    return parsed;
  } catch (error) {
    throw new Error(`invalid JSON from Ollama at ${url}: ${error.message}`);
  }
}

function queryOllamaTags(options = {}) {
  const endpoint = normalizeOllamaEndpoint(options.endpoint, options.environment);
  const response = curlJson(ollamaUrl(endpoint, '/api/tags'), options);
  if (!Array.isArray(response.models)) {
    throw new Error(`invalid Ollama tags response from ${endpoint}: models must be an array`);
  }
  return { endpoint, models: response.models, response };
}

function normalizeOllamaModel(value) {
  const model = String(value || '').trim();
  if (!model) throw new Error('Ollama model is required');
  if (model.length > 200 || /[\0\r\n]/.test(model)) {
    throw new Error('Ollama model must be a single-line value under 200 characters');
  }
  return model;
}

function queryOllamaShow(modelValue, options = {}) {
  const model = normalizeOllamaModel(modelValue);
  const endpoint = normalizeOllamaEndpoint(options.endpoint, options.environment);
  const modelInfo = curlJson(ollamaUrl(endpoint, '/api/show'), {
    ...options,
    method: 'POST',
    body: { model },
  });
  return { endpoint, model, modelInfo };
}

function ollamaModelNames(entry) {
  if (!entry || typeof entry !== 'object') return [];
  return [entry.name, entry.model]
    .map((value) => String(value || '').trim())
    .filter(Boolean);
}

function implicitLatestName(model) {
  const finalSegment = model.slice(model.lastIndexOf('/') + 1);
  return finalSegment.includes(':') ? '' : `${model}:latest`;
}

function ollamaModelCapabilities(modelInfo) {
  if (!Array.isArray(modelInfo?.capabilities)) return [];
  return modelInfo.capabilities
    .map((value) => String(value).trim().toLowerCase())
    .filter(Boolean);
}

function requireInstalledOllamaModel(modelValue, options = {}) {
  const requestedModel = normalizeOllamaModel(modelValue);
  const tags = queryOllamaTags(options);
  const acceptableNames = new Set(
    [requestedModel, implicitLatestName(requestedModel)]
      .filter(Boolean)
      .map((name) => name.toLowerCase()),
  );
  const installedModel = tags.models.find((entry) => (
    ollamaModelNames(entry).some((name) => acceptableNames.has(name.toLowerCase()))
  ));
  if (!installedModel) {
    throw new Error(
      `Ollama model is not installed: ${requestedModel}; install it explicitly before launching Codex`,
    );
  }
  const canonicalModel = ollamaModelNames(installedModel)
    .find((name) => acceptableNames.has(name.toLowerCase())) || requestedModel;
  const shown = queryOllamaShow(canonicalModel, { ...options, endpoint: tags.endpoint });
  if (!ollamaModelCapabilities(shown.modelInfo).includes('tools')) {
    throw new Error(
      `Ollama model does not support tools: ${canonicalModel}; `
      + 'choose a model whose /api/show capabilities include tools',
    );
  }
  return {
    endpoint: tags.endpoint,
    model: canonicalModel,
    requestedModel,
    installedModel,
    modelInfo: shown.modelInfo,
  };
}

function modelContextWindow(modelInfo) {
  const values = Object.entries(modelInfo?.model_info || {})
    .filter(([key, value]) => (
      (key === 'context_length' || key.endsWith('.context_length'))
      && typeof value === 'number'
      && Number.isFinite(value)
      && value > 0
    ))
    .map(([, value]) => value);
  if (!values.length) return DEFAULT_OLLAMA_CONTEXT_WINDOW;
  const reported = values.reduce((maximum, value) => Math.max(maximum, value), 0);
  return Math.trunc(Math.min(
    MAX_OLLAMA_CONTEXT_WINDOW,
    Math.max(MIN_OLLAMA_CONTEXT_WINDOW, reported),
  ));
}

function buildOllamaModelCatalog(modelValue, modelInfo = {}) {
  const model = normalizeOllamaModel(modelValue);
  const capabilities = ollamaModelCapabilities(modelInfo);
  return {
    models: [{
      slug: model,
      display_name: model,
      context_window: modelContextWindow(modelInfo),
      shell_type: 'default',
      visibility: 'list',
      supported_in_api: true,
      priority: 0,
      truncation_policy: { mode: 'bytes', limit: 10_000 },
      input_modalities: capabilities.includes('vision') ? ['text', 'image'] : ['text'],
      base_instructions: OLLAMA_CODEX_BASE_INSTRUCTIONS,
      support_verbosity: false,
      default_verbosity: null,
      supports_parallel_tool_calls: false,
      supports_reasoning_summaries: false,
      supported_reasoning_levels: [],
      experimental_supported_tools: [],
    }],
  };
}

function createOllamaCodexProviderId() {
  return `${OLLAMA_CODEX_PROVIDER_PREFIX}_${crypto.randomBytes(16).toString('hex')}`;
}

function runtimeCatalogRootPath(options = {}) {
  const environment = options.environment || process.env;
  const uid = typeof process.getuid === 'function' ? process.getuid() : null;
  const configuredRoot = String(options.runtimeDir || environment.XDG_RUNTIME_DIR || '').trim();
  const parent = configuredRoot ? path.resolve(configuredRoot) : os.tmpdir();
  return path.join(parent, configuredRoot ? 'notty-ollama' : `notty-ollama-${uid ?? 'unknown'}`);
}

function runtimeCatalogRoot(options = {}) {
  const fileSystem = options.fileSystem || fs;
  const uid = typeof process.getuid === 'function' ? process.getuid() : null;
  const root = runtimeCatalogRootPath(options);
  const parent = path.dirname(root);
  fileSystem.mkdirSync(parent, { recursive: true, mode: 0o700 });
  try {
    fileSystem.mkdirSync(root, { mode: 0o700 });
  } catch (error) {
    if (error?.code !== 'EEXIST') throw error;
  }
  const rootStats = fileSystem.lstatSync(root);
  if (rootStats.isSymbolicLink() || !rootStats.isDirectory()) {
    throw new Error(`Ollama model catalog root must be a real directory: ${root}`);
  }
  if (uid !== null && rootStats.uid !== uid) {
    throw new Error(`Ollama model catalog root is not owned by the current user: ${root}`);
  }
  fileSystem.chmodSync(root, 0o700);
  return root;
}

function writeOllamaModelCatalog(options = {}) {
  const fileSystem = options.fileSystem || fs;
  const model = normalizeOllamaModel(options.model);
  const catalog = buildOllamaModelCatalog(model, options.modelInfo);
  const isolationKey = String(options.isolationKey || `${process.pid}-${crypto.randomUUID()}`);
  const digest = crypto.createHash('sha256')
    .update(isolationKey)
    .update('\0')
    .update(model)
    .digest('hex')
    .slice(0, 24);
  const root = runtimeCatalogRoot(options);
  const uniqueSuffix = crypto.randomBytes(16).toString('hex');
  const catalogPath = path.join(root, `catalog-${digest}-${uniqueSuffix}.json`);
  const temporaryPath = path.join(
    root,
    `.catalog-${digest}-${uniqueSuffix}.${process.pid}.${crypto.randomUUID()}.tmp`,
  );
  try {
    fileSystem.writeFileSync(
      temporaryPath,
      `${JSON.stringify(catalog, null, 2)}\n`,
      { encoding: 'utf8', mode: 0o600, flag: 'wx' },
    );
    fileSystem.renameSync(temporaryPath, catalogPath);
    fileSystem.chmodSync(catalogPath, 0o600);
  } catch (error) {
    try {
      fileSystem.unlinkSync(temporaryPath);
    } catch {
      // Preserve the original atomic-write error.
    }
    throw error;
  }
  return { catalogPath, catalog };
}

function removeOllamaModelCatalog(catalogPathValue, options = {}) {
  const fileSystem = options.fileSystem || fs;
  const uid = typeof process.getuid === 'function' ? process.getuid() : null;
  const catalogPathText = String(catalogPathValue || '');
  if (!catalogPathText || /[\0\r\n]/.test(catalogPathText)) {
    throw new Error('Ollama model catalog path is required');
  }

  const catalogPath = path.resolve(catalogPathText);
  const root = runtimeCatalogRootPath(options);
  if (
    path.dirname(catalogPath) !== root
    || !/^catalog-[a-f0-9]{24}-[a-f0-9]{32}\.json$/.test(path.basename(catalogPath))
  ) {
    throw new Error(`refusing to remove unrecognized Ollama model catalog: ${catalogPath}`);
  }

  let rootStats;
  try {
    rootStats = fileSystem.lstatSync(root);
  } catch (error) {
    if (error?.code === 'ENOENT') return false;
    throw error;
  }
  if (rootStats.isSymbolicLink() || !rootStats.isDirectory()) {
    throw new Error(`Ollama model catalog root must be a real directory: ${root}`);
  }
  if (uid !== null && rootStats.uid !== uid) {
    throw new Error(`Ollama model catalog root is not owned by the current user: ${root}`);
  }

  let catalogStats;
  try {
    catalogStats = fileSystem.lstatSync(catalogPath);
  } catch (error) {
    if (error?.code === 'ENOENT') return false;
    throw error;
  }
  if (catalogStats.isSymbolicLink() || !catalogStats.isFile()) {
    throw new Error(`refusing to remove non-file Ollama model catalog: ${catalogPath}`);
  }
  if (uid !== null && catalogStats.uid !== uid) {
    throw new Error(`Ollama model catalog is not owned by the current user: ${catalogPath}`);
  }
  fileSystem.unlinkSync(catalogPath);
  return true;
}

function buildCodexOllamaProviderArgs(options = {}) {
  const endpoint = normalizeOllamaEndpoint(options.endpoint, options.environment);
  const model = normalizeOllamaModel(options.model);
  const providerId = String(options.providerId || createOllamaCodexProviderId()).trim();
  const catalogPath = path.resolve(String(options.catalogPath || ''));
  if (!/^[A-Za-z0-9_-]+$/.test(providerId)) {
    throw new Error(`invalid Codex Ollama provider id: ${providerId || '(empty)'}`);
  }
  if (!options.catalogPath || /[\0\r\n]/.test(String(options.catalogPath))) {
    throw new Error('Codex Ollama model catalog path is required');
  }
  const providerPrefix = `model_providers.${providerId}`;
  return [
    '-m', model,
    '-c', `model_provider=${JSON.stringify(providerId)}`,
    '-c', `${providerPrefix}.name=${JSON.stringify('Ollama via Notty')}`,
    '-c', `${providerPrefix}.base_url=${JSON.stringify(ollamaCodexBaseUrl(endpoint))}`,
    '-c', `${providerPrefix}.wire_api=${JSON.stringify('responses')}`,
    '-c', `${providerPrefix}.requires_openai_auth=false`,
    '-c', `model_catalog_json=${JSON.stringify(catalogPath)}`,
    '-c', `web_search=${JSON.stringify('disabled')}`,
  ];
}

function prepareOllamaCodexProvider(options = {}) {
  const preparedModel = requireInstalledOllamaModel(options.model, options);
  const written = writeOllamaModelCatalog({
    ...options,
    model: preparedModel.model,
    modelInfo: preparedModel.modelInfo,
  });
  const providerId = createOllamaCodexProviderId();
  let args;
  try {
    args = buildCodexOllamaProviderArgs({
      ...options,
      endpoint: preparedModel.endpoint,
      model: preparedModel.model,
      providerId,
      catalogPath: written.catalogPath,
    });
  } catch (error) {
    try {
      removeOllamaModelCatalog(written.catalogPath, options);
    } catch (cleanupError) {
      error.ollamaCatalogPath = written.catalogPath;
      error.ollamaCatalogCleanupError = cleanupError;
    }
    throw error;
  }
  return {
    ...preparedModel,
    baseUrl: ollamaCodexBaseUrl(preparedModel.endpoint),
    providerId,
    catalogPath: written.catalogPath,
    catalog: written.catalog,
    args,
  };
}

module.exports = {
  DEFAULT_OLLAMA_CONTEXT_WINDOW,
  DEFAULT_OLLAMA_HOST,
  DEFAULT_OLLAMA_TIMEOUT_MS,
  MAX_OLLAMA_CONTEXT_WINDOW,
  MIN_OLLAMA_CONTEXT_WINDOW,
  OLLAMA_CODEX_BASE_INSTRUCTIONS,
  OLLAMA_CODEX_PROVIDER_PREFIX,
  buildCodexOllamaProviderArgs,
  buildOllamaModelCatalog,
  createOllamaCodexProviderId,
  modelContextWindow,
  normalizeOllamaEndpoint,
  normalizeOllamaModel,
  ollamaCodexBaseUrl,
  prepareOllamaCodexProvider,
  queryOllamaShow,
  queryOllamaTags,
  removeOllamaModelCatalog,
  requireInstalledOllamaModel,
  runtimeCatalogRoot,
  runtimeCatalogRootPath,
  writeOllamaModelCatalog,
};
