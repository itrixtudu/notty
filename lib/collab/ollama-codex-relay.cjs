#!/usr/bin/env node
'use strict';

const childProcess = require('node:child_process');
const crypto = require('node:crypto');
const http = require('node:http');
const https = require('node:https');
const path = require('node:path');
const { StringDecoder } = require('node:string_decoder');
const { Transform, pipeline } = require('node:stream');

const RELAY_HOST = '127.0.0.1';
const MAX_RELAY_BODY_BYTES = 64 * 1024 * 1024;
const MAX_SSE_EVENT_BYTES = 4 * 1024 * 1024;
const FUNCTION_NAME_LIMIT = 64;
const ALIAS_PREFIX = 'notty_ns_';
const ALIAS_HASH_LENGTH = 24;
const HOSTED_WEB_SEARCH_TYPES = new Set(['web_search', 'web_search_preview']);
const FORWARDED_SIGNALS = Object.freeze(['SIGINT', 'SIGTERM', 'SIGHUP']);

function isPlainObject(value) {
  return Boolean(value) && typeof value === 'object' && !Array.isArray(value);
}

function parseConfigString(value, label) {
  try {
    const parsed = JSON.parse(String(value));
    if (typeof parsed !== 'string' || !parsed.trim()) {
      throw new Error('expected a non-empty string');
    }
    return parsed;
  } catch (error) {
    throw new Error(`invalid ${label} Codex config value: ${error.message}`);
  }
}

function sanitizeFunctionName(value) {
  const sanitized = String(value || '')
    .replace(/[^A-Za-z0-9_-]+/g, '_')
    .replace(/^_+|_+$/g, '');
  return sanitized || 'tool';
}

class NamespaceAliasRegistry {
  constructor(options = {}) {
    this.hash = options.hash || ((value) => (
      crypto.createHash('sha256').update(value).digest('hex')
    ));
    this.aliases = new Map();
    this.identities = new Map();
  }

  aliasFor(namespaceValue, memberValue) {
    const namespace = String(namespaceValue || '').trim();
    const member = String(memberValue || '').trim();
    if (!namespace || !member) {
      throw new Error('namespace tools require non-empty namespace and member names');
    }
    const identity = `${namespace}\0${member}`;
    const existing = this.identities.get(identity);
    if (existing) return existing;

    const digest = String(this.hash(identity)).toLowerCase();
    if (!/^[0-9a-f]{24,}$/.test(digest)) {
      throw new Error('namespace alias hash must contain at least 24 hexadecimal characters');
    }
    const suffixLimit = FUNCTION_NAME_LIMIT
      - ALIAS_PREFIX.length
      - ALIAS_HASH_LENGTH
      - 1;
    const suffix = sanitizeFunctionName(member).slice(0, suffixLimit);
    const alias = `${ALIAS_PREFIX}${digest.slice(0, ALIAS_HASH_LENGTH)}_${suffix}`;
    const collision = this.aliases.get(alias);
    if (collision && (collision.namespace !== namespace || collision.member !== member)) {
      throw new Error(
        `namespace alias collision between ${collision.namespace}.${collision.member} `
        + `and ${namespace}.${member}`,
      );
    }
    this.aliases.set(alias, { namespace, member });
    this.identities.set(identity, alias);
    return alias;
  }

  identityFor(aliasValue) {
    return this.aliases.get(String(aliasValue || '')) || null;
  }
}

function namespaceToolDescription(namespace, member, namespaceDescription, memberDescription) {
  return [
    `Compatibility alias for Codex namespace ${namespace}, tool ${member}.`,
    String(namespaceDescription || '').trim(),
    String(memberDescription || '').trim(),
  ].filter(Boolean).join(' ');
}

function flattenNamespaceTools(toolsValue, registry) {
  if (!Array.isArray(toolsValue)) return toolsValue;
  const flattened = [];
  const aliases = new Map();
  for (const tool of toolsValue) {
    if (!isPlainObject(tool)) {
      flattened.push(tool);
      continue;
    }
    if (HOSTED_WEB_SEARCH_TYPES.has(String(tool.type || ''))) {
      continue;
    }
    if (tool.type !== 'namespace') {
      flattened.push(tool);
      continue;
    }

    const namespace = String(tool.name || '').trim();
    if (!namespace) throw new Error('namespace tool is missing its name');
    if (!Array.isArray(tool.tools)) {
      throw new Error(`namespace tool ${namespace} is missing its member list`);
    }
    for (const memberTool of tool.tools) {
      if (!isPlainObject(memberTool) || memberTool.type !== 'function') {
        const memberType = isPlainObject(memberTool) ? memberTool.type : typeof memberTool;
        throw new Error(
          `namespace tool ${namespace} contains unsupported member type ${memberType || '(empty)'}`,
        );
      }
      const member = String(memberTool.name || '').trim();
      const alias = registry.aliasFor(namespace, member);
      const converted = {
        ...memberTool,
        type: 'function',
        name: alias,
        description: namespaceToolDescription(
          namespace,
          member,
          tool.description,
          memberTool.description,
        ),
      };
      const signature = JSON.stringify(converted);
      const priorSignature = aliases.get(alias);
      if (priorSignature && priorSignature !== signature) {
        throw new Error(`namespace tool ${namespace}.${member} has conflicting definitions`);
      }
      if (!priorSignature) {
        aliases.set(alias, signature);
        flattened.push(converted);
      }
    }
  }
  return flattened;
}

function rewriteNamespacedHistory(value, registry) {
  if (Array.isArray(value)) {
    return value.map((entry) => rewriteNamespacedHistory(entry, registry));
  }
  if (!isPlainObject(value)) return value;
  const rewritten = {};
  for (const [key, entry] of Object.entries(value)) {
    rewritten[key] = rewriteNamespacedHistory(entry, registry);
  }
  if (
    (rewritten.type === 'function_call' || rewritten.type === 'function')
    && typeof rewritten.namespace === 'string'
    && typeof rewritten.name === 'string'
  ) {
    rewritten.name = registry.aliasFor(rewritten.namespace, rewritten.name);
    delete rewritten.namespace;
  }
  return rewritten;
}

function transformCodexRequest(body, registry = new NamespaceAliasRegistry()) {
  if (!isPlainObject(body)) throw new Error('Responses request body must be a JSON object');
  const transformed = {};
  for (const [key, value] of Object.entries(body)) {
    transformed[key] = key === 'tools'
      ? flattenNamespaceTools(value, registry)
      : rewriteNamespacedHistory(value, registry);
  }
  return transformed;
}

function restoreNamespaceCalls(value, registry) {
  if (Array.isArray(value)) {
    return value.map((entry) => restoreNamespaceCalls(entry, registry));
  }
  if (!isPlainObject(value)) return value;
  const restored = {};
  for (const [key, entry] of Object.entries(value)) {
    restored[key] = restoreNamespaceCalls(entry, registry);
  }
  if (restored.type === 'function_call' && typeof restored.name === 'string') {
    const identity = registry.identityFor(restored.name);
    if (identity) {
      restored.namespace = identity.namespace;
      restored.name = identity.member;
    }
  }
  return restored;
}

function transformSseBlock(block, registry) {
  const newline = block.includes('\r\n') ? '\r\n' : '\n';
  const lines = block.split(/\r?\n/);
  const dataIndexes = [];
  const dataParts = [];
  lines.forEach((line, index) => {
    if (!line.startsWith('data:')) return;
    dataIndexes.push(index);
    dataParts.push(line.slice(5).replace(/^ /, ''));
  });
  if (!dataIndexes.length) return block;
  const data = dataParts.join('\n');
  if (!data || data === '[DONE]') return block;
  let parsed;
  try {
    parsed = JSON.parse(data);
  } catch {
    return block;
  }
  const replacement = `data: ${JSON.stringify(restoreNamespaceCalls(parsed, registry))}`;
  const firstDataIndex = dataIndexes[0];
  const dataIndexSet = new Set(dataIndexes);
  return lines
    .filter((_line, index) => !dataIndexSet.has(index) || index === firstDataIndex)
    .map((line, index) => (index === firstDataIndex ? replacement : line))
    .join(newline);
}

class NamespaceSseTransform extends Transform {
  constructor(registry, maxEventBytes = MAX_SSE_EVENT_BYTES) {
    super();
    this.registry = registry;
    this.maxEventBytes = maxEventBytes;
    this.decoder = new StringDecoder('utf8');
    this.buffer = '';
    this.bufferBytes = 0;
  }

  drainCompleteBlocks() {
    while (true) {
      const match = /\r?\n\r?\n/.exec(this.buffer);
      if (!match) return;
      const block = this.buffer.slice(0, match.index);
      const delimiter = match[0];
      const consumed = this.buffer.slice(0, match.index + delimiter.length);
      if (Buffer.byteLength(block) > this.maxEventBytes) {
        throw new Error(`Responses SSE event exceeds ${this.maxEventBytes} bytes`);
      }
      this.buffer = this.buffer.slice(consumed.length);
      this.bufferBytes -= Buffer.byteLength(consumed);
      this.push(`${transformSseBlock(block, this.registry)}${delimiter}`);
    }
  }

  _transform(chunk, _encoding, callback) {
    try {
      this.bufferBytes += chunk.length;
      this.buffer += this.decoder.write(chunk);
      this.drainCompleteBlocks();
      if (this.bufferBytes > this.maxEventBytes) {
        throw new Error(`Responses SSE event exceeds ${this.maxEventBytes} bytes`);
      }
      callback();
    } catch (error) {
      callback(error);
    }
  }

  _flush(callback) {
    try {
      this.buffer += this.decoder.end();
      this.drainCompleteBlocks();
      if (this.bufferBytes > this.maxEventBytes) {
        throw new Error(`Responses SSE event exceeds ${this.maxEventBytes} bytes`);
      }
      if (this.buffer) this.push(transformSseBlock(this.buffer, this.registry));
      callback();
    } catch (error) {
      callback(error);
    }
  }
}

function normalizedUpstreamBaseUrl(value) {
  let upstream;
  try {
    upstream = new URL(String(value || ''));
  } catch (error) {
    throw new Error(`invalid Ollama relay upstream URL: ${error.message}`);
  }
  if (!['http:', 'https:'].includes(upstream.protocol)) {
    throw new Error(`unsupported Ollama relay protocol: ${upstream.protocol}`);
  }
  if (!upstream.hostname || upstream.username || upstream.password) {
    throw new Error('Ollama relay upstream must be an origin without credentials');
  }
  if (upstream.search || upstream.hash) {
    throw new Error('Ollama relay upstream must not include a query or fragment');
  }
  upstream.pathname = upstream.pathname.replace(/\/+$/, '') || '/';
  if (upstream.pathname !== '/v1') {
    throw new Error('Ollama relay upstream must use the /v1 API base path');
  }
  return upstream;
}

function responsesPathFor(upstream) {
  const prefix = upstream.pathname === '/' ? '' : upstream.pathname;
  return `${prefix}/responses`;
}

async function readBody(stream, limit = MAX_RELAY_BODY_BYTES) {
  const chunks = [];
  let size = 0;
  for await (const chunk of stream) {
    size += chunk.length;
    if (size > limit) throw new Error(`relay body exceeds ${limit} bytes`);
    chunks.push(chunk);
  }
  return Buffer.concat(chunks);
}

function outgoingRequestHeaders(headers, upstream, body) {
  const outgoing = { ...headers };
  delete outgoing.connection;
  delete outgoing['proxy-connection'];
  delete outgoing['transfer-encoding'];
  delete outgoing['accept-encoding'];
  outgoing.host = upstream.host;
  if (body) outgoing['content-length'] = String(body.length);
  else delete outgoing['content-length'];
  return outgoing;
}

function outgoingResponseHeaders(headers, transformed = false) {
  const outgoing = { ...headers };
  delete outgoing.connection;
  delete outgoing['proxy-connection'];
  if (transformed) {
    delete outgoing['content-length'];
    delete outgoing['transfer-encoding'];
    delete outgoing['content-encoding'];
  }
  return outgoing;
}

function writeRelayError(response, statusCode, error) {
  if (response.headersSent || response.destroyed) {
    response.destroy(error);
    return;
  }
  const body = Buffer.from(JSON.stringify({
    error: {
      message: error?.message || String(error),
      type: 'notty_ollama_relay_error',
    },
  }));
  response.writeHead(statusCode, {
    'content-type': 'application/json',
    'content-length': String(body.length),
  });
  response.end(body);
}

function pipeStreams(source, destination, transform = null) {
  return new Promise((resolve, reject) => {
    const streams = transform
      ? [source, transform, destination]
      : [source, destination];
    pipeline(...streams, (error) => (error ? reject(error) : resolve()));
  });
}

async function handleRelayRequest(request, response, state) {
  const requestUrl = new URL(request.url || '/', 'http://relay.invalid');
  const isResponsesRequest = requestUrl.pathname === state.responsesPath;
  let body = null;
  try {
    if (!['GET', 'HEAD'].includes(request.method || 'GET')) {
      body = await readBody(request, state.maxBodyBytes);
    }
    if (isResponsesRequest && body?.length) {
      const encoding = String(request.headers['content-encoding'] || 'identity').toLowerCase();
      if (encoding !== 'identity') {
        throw new Error(`unsupported Responses request content encoding: ${encoding}`);
      }
      let parsed;
      try {
        parsed = JSON.parse(body.toString('utf8'));
      } catch (error) {
        throw new Error(`invalid Responses request JSON: ${error.message}`);
      }
      body = Buffer.from(JSON.stringify(transformCodexRequest(parsed, state.registry)));
    }
  } catch (error) {
    writeRelayError(response, 400, error);
    return;
  }

  const transport = state.upstream.protocol === 'https:' ? https : http;
  const upstreamRequest = transport.request({
    protocol: state.upstream.protocol,
    hostname: state.upstream.hostname,
    port: state.upstream.port || undefined,
    method: request.method,
    path: request.url,
    headers: outgoingRequestHeaders(request.headers, state.upstream, body),
  });
  const cancelUpstream = () => upstreamRequest.destroy();
  request.once('aborted', cancelUpstream);
  response.once('close', () => {
    if (!response.writableEnded) cancelUpstream();
  });
  upstreamRequest.once('error', (error) => writeRelayError(response, 502, error));
  upstreamRequest.once('response', async (upstreamResponse) => {
    try {
      const contentType = String(upstreamResponse.headers['content-type'] || '').toLowerCase();
      const isSse = isResponsesRequest && contentType.includes('text/event-stream');
      const isJson = isResponsesRequest && contentType.includes('application/json');
      const contentEncoding = String(
        upstreamResponse.headers['content-encoding'] || 'identity',
      ).toLowerCase();
      if ((isSse || isJson) && contentEncoding !== 'identity') {
        upstreamResponse.destroy();
        throw new Error(`unsupported Responses response content encoding: ${contentEncoding}`);
      }
      if (isSse) {
        response.writeHead(
          upstreamResponse.statusCode || 502,
          outgoingResponseHeaders(upstreamResponse.headers, true),
        );
        await pipeStreams(
          upstreamResponse,
          response,
          new NamespaceSseTransform(state.registry, state.maxSseEventBytes),
        );
        return;
      }
      if (isJson) {
        const upstreamBody = await readBody(upstreamResponse, state.maxBodyBytes);
        let transformedBody = upstreamBody;
        try {
          transformedBody = Buffer.from(JSON.stringify(
            restoreNamespaceCalls(JSON.parse(upstreamBody.toString('utf8')), state.registry),
          ));
        } catch {
          // Preserve non-JSON error bodies even when the content type is inaccurate.
        }
        const headers = outgoingResponseHeaders(upstreamResponse.headers, true);
        headers['content-length'] = String(transformedBody.length);
        response.writeHead(upstreamResponse.statusCode || 502, headers);
        response.end(transformedBody);
        return;
      }
      response.writeHead(
        upstreamResponse.statusCode || 502,
        outgoingResponseHeaders(upstreamResponse.headers),
      );
      await pipeStreams(upstreamResponse, response);
    } catch (error) {
      writeRelayError(response, 502, error);
    }
  });
  upstreamRequest.end(body || undefined);
}

async function startOllamaCodexRelay(options = {}) {
  const upstream = normalizedUpstreamBaseUrl(options.upstreamBaseUrl);
  const registry = options.registry || new NamespaceAliasRegistry();
  const host = options.host || RELAY_HOST;
  if (host !== RELAY_HOST) throw new Error(`Ollama Codex relay must bind ${RELAY_HOST}`);
  const state = {
    upstream,
    registry,
    responsesPath: responsesPathFor(upstream),
    maxBodyBytes: options.maxBodyBytes || MAX_RELAY_BODY_BYTES,
    maxSseEventBytes: options.maxSseEventBytes || MAX_SSE_EVENT_BYTES,
  };
  const server = (options.createServer || http.createServer)((request, response) => {
    handleRelayRequest(request, response, state).catch((error) => {
      writeRelayError(response, 502, error);
    });
  });
  await new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, host, () => {
      server.off('error', reject);
      resolve();
    });
  });
  const address = server.address();
  if (!address || typeof address === 'string') {
    server.close();
    throw new Error('unable to resolve Ollama Codex relay address');
  }
  const basePath = upstream.pathname === '/' ? '' : upstream.pathname;
  const close = () => new Promise((resolve) => {
    if (!server.listening) {
      resolve();
      return;
    }
    server.close(() => resolve());
    server.closeAllConnections?.();
  });
  return {
    server,
    registry,
    upstreamBaseUrl: upstream.toString().replace(/\/$/, ''),
    baseUrl: `http://${RELAY_HOST}:${address.port}${basePath}`,
    close,
  };
}

function inspectCodexProviderCommand(commandValue) {
  const command = Array.from(commandValue || [], String);
  if (!command.length) throw new Error('relay wrapper requires a Codex command');
  const configs = [];
  for (let index = 1; index < command.length - 1; index += 1) {
    if (command[index] === '-c' || command[index] === '--config') {
      configs.push({ index: index + 1, value: command[index + 1] });
      index += 1;
    }
  }
  const providerConfig = configs.find(({ value }) => /^model_provider=/.test(value));
  if (!providerConfig) throw new Error('Codex command is missing model_provider config');
  const providerId = parseConfigString(
    providerConfig.value.slice(providerConfig.value.indexOf('=') + 1),
    'model_provider',
  );
  if (!/^notty_ollama_[A-Za-z0-9]+$/.test(providerId)) {
    throw new Error(`refusing to relay non-Notty model provider ${providerId}`);
  }
  const baseKey = `model_providers.${providerId}.base_url=`;
  const baseConfig = configs.find(({ value }) => value.startsWith(baseKey));
  if (!baseConfig) throw new Error(`Codex command is missing ${baseKey.slice(0, -1)}`);
  const upstreamBaseUrl = parseConfigString(
    baseConfig.value.slice(baseKey.length),
    `${baseKey.slice(0, -1)}`,
  );
  const catalogConfig = configs.find(({ value }) => value.startsWith('model_catalog_json='));
  const catalogPath = catalogConfig
    ? parseConfigString(
        catalogConfig.value.slice('model_catalog_json='.length),
        'model_catalog_json',
      )
    : '';
  return {
    command,
    providerId,
    baseConfigIndex: baseConfig.index,
    upstreamBaseUrl,
    catalogPath,
  };
}

function rewriteCodexProviderCommand(inspected, relayBaseUrl) {
  const command = inspected.command.slice();
  const key = `model_providers.${inspected.providerId}.base_url`;
  command[inspected.baseConfigIndex] = `${key}=${JSON.stringify(relayBaseUrl)}`;
  return command;
}

function buildOllamaCodexRelayCommand(command, options = {}) {
  return [
    String(options.nodeBin || process.execPath),
    String(options.relayPath || __filename),
    '--',
    ...Array.from(command || [], String),
  ];
}

async function removeOwnedCatalog(catalogPath, options = {}) {
  if (!catalogPath) return false;
  const removeCatalog = options.removeCatalog
    || require('./ollama.cjs').removeOllamaModelCatalog;
  if (typeof removeCatalog !== 'function') {
    throw new Error('Ollama model catalog remover is unavailable');
  }
  const resolvedCatalogPath = path.resolve(catalogPath);
  const catalogRoot = path.dirname(resolvedCatalogPath);
  const uid = typeof process.getuid === 'function' ? process.getuid() : null;
  const fallbackRootName = `notty-ollama-${uid ?? 'unknown'}`;
  const usesFallbackRoot = path.basename(catalogRoot) === fallbackRootName;
  const environment = usesFallbackRoot
    ? { ...(options.environment || process.env), XDG_RUNTIME_DIR: '' }
    : options.environment || process.env;
  return removeCatalog(resolvedCatalogPath, {
    runtimeDir: usesFallbackRoot ? '' : path.dirname(catalogRoot),
    environment,
    fileSystem: options.fileSystem,
  });
}

async function runOllamaCodexRelayCommand(command, options = {}) {
  const inspected = inspectCodexProviderCommand(command);
  let relay;
  let child;
  const processObject = options.processObject || process;
  const spawn = options.spawn || childProcess.spawn;
  const log = options.log || ((message) => process.stderr.write(`${message}\n`));
  let catalogCleaned = false;
  const cleanupCatalog = async () => {
    if (catalogCleaned) return;
    catalogCleaned = true;
    try {
      await removeOwnedCatalog(inspected.catalogPath, options);
    } catch (error) {
      log(`ollama-codex-relay: unable to remove model catalog: ${error.message}`);
    }
  };
  try {
    relay = await (options.startRelay || startOllamaCodexRelay)({
      upstreamBaseUrl: inspected.upstreamBaseUrl,
    });
    const rewritten = rewriteCodexProviderCommand(inspected, relay.baseUrl);
    child = spawn(rewritten[0], rewritten.slice(1), {
      cwd: options.cwd || process.cwd(),
      env: options.environment || process.env,
      stdio: 'inherit',
    });
  } catch (error) {
    await relay?.close?.();
    await cleanupCatalog();
    throw error;
  }

  const handlers = new Map();
  for (const signal of FORWARDED_SIGNALS) {
    const handler = () => {
      try {
        child.kill(signal);
      } catch {
        // The child may have exited between signal delivery and forwarding.
      }
    };
    handlers.set(signal, handler);
    processObject.on(signal, handler);
  }
  let result;
  try {
    result = await new Promise((resolve, reject) => {
      child.once('error', reject);
      child.once('exit', (code, signal) => resolve({ code, signal }));
    });
  } finally {
    for (const [signal, handler] of handlers) processObject.off(signal, handler);
    await relay.close();
    await cleanupCatalog();
  }
  return result;
}

function usage() {
  return 'Usage: ollama-codex-relay.cjs -- codex [ARGS...]';
}

async function main(argv = process.argv.slice(2)) {
  if (argv[0] === '-h' || argv[0] === '--help') {
    process.stdout.write(`${usage()}\n`);
    return;
  }
  if (argv[0] !== '--' || argv.length < 2) throw new Error(usage());
  const result = await runOllamaCodexRelayCommand(argv.slice(1));
  if (result.signal) {
    process.kill(process.pid, result.signal);
    return;
  }
  process.exitCode = result.code === null ? 1 : result.code;
}

if (require.main === module) {
  main().catch((error) => {
    process.stderr.write(`ollama-codex-relay: ${error?.message || error}\n`);
    process.exitCode = 1;
  });
}

module.exports = {
  ALIAS_PREFIX,
  FUNCTION_NAME_LIMIT,
  HOSTED_WEB_SEARCH_TYPES,
  MAX_RELAY_BODY_BYTES,
  MAX_SSE_EVENT_BYTES,
  NamespaceAliasRegistry,
  NamespaceSseTransform,
  buildOllamaCodexRelayCommand,
  flattenNamespaceTools,
  inspectCodexProviderCommand,
  main,
  removeOwnedCatalog,
  restoreNamespaceCalls,
  rewriteCodexProviderCommand,
  rewriteNamespacedHistory,
  runOllamaCodexRelayCommand,
  startOllamaCodexRelay,
  transformCodexRequest,
  transformSseBlock,
  usage,
};
