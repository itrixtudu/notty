import crypto from 'node:crypto';
import fs from 'node:fs/promises';
import { constants as fsConstants } from 'node:fs';
import path from 'node:path';

import { sha256, stableStringify } from '../guard/stable.js';
import {
  HTTP_EVIDENCE_API_VERSION,
  httpRequestIdentity,
  httpRequestIdentityKey,
} from './http-evidence.js';

export const HTTP_CONTENT_MANIFEST_SCHEMA_VERSION = 1;
export const HTTP_CONTENT_MANIFEST_KIND = 'NoshHttpContentManifest';
export const HTTP_CONTENT_GATE_MODES = Object.freeze([
  'observe',
  'offline-replay',
  'live-buffer-verify',
]);
export const HTTP_CONTENT_DEFAULT_MAX_BYTES = 512 * 1024 * 1024;
export const HTTP_CONTENT_MANIFEST_MAX_ENTRIES = 100_000;
export const HTTP_CONTENT_DEFAULT_MAX_TOTAL_BYTES = 8 * 1024 * 1024 * 1024;
export const HTTP_CONTENT_DEFAULT_MAX_OBJECTS = 10_000;

const DIGEST_PATTERN = /^sha256:[a-f0-9]{64}$/;
const RUN_ID_PATTERN = /^[A-Za-z0-9_.-]{1,128}$/;
const MANIFEST_MODES = new Set(['offline-replay', 'live-buffer-verify']);
const MANIFEST_MAX_BYTES = 16 * 1024 * 1024;

function plainObject(value, label) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    throw new TypeError(`${label} must be an object`);
  }
  return value;
}

function exactKeys(value, expected, label) {
  plainObject(value, label);
  const actual = Object.keys(value).sort();
  const selected = [...expected].sort();
  if (
    actual.length !== selected.length
    || actual.some((key, index) => key !== selected[index])
  ) {
    throw new TypeError(`${label} contains missing or unrecognized fields`);
  }
}

function exactDigest(value, label) {
  if (!DIGEST_PATTERN.test(value || '')) {
    throw new TypeError(`${label} must be an exact sha256 digest`);
  }
  return value;
}

function optionalDigest(value, label) {
  if (value == null) return null;
  return exactDigest(value, label);
}

function timestamp(value, label) {
  if (typeof value !== 'string' || Number.isNaN(Date.parse(value))) {
    throw new TypeError(`${label} must be an ISO-compatible timestamp`);
  }
  return new Date(Date.parse(value)).toISOString();
}

function nonNegativeInteger(value, label) {
  const selected = Number(value);
  if (!Number.isSafeInteger(selected) || selected < 0) {
    throw new TypeError(`${label} must be a non-negative safe integer`);
  }
  return selected;
}

function positiveInteger(value, label, maximum = Number.MAX_SAFE_INTEGER) {
  const selected = Number(value);
  if (!Number.isSafeInteger(selected) || selected < 1 || selected > maximum) {
    throw new TypeError(`${label} must be a positive safe integer no greater than ${maximum}`);
  }
  return selected;
}

function optionalMetadata(value, label, maximum = 1024) {
  if (value == null || value === '') return null;
  if (
    typeof value !== 'string'
    || value.length > maximum
    || /[\r\n]/.test(value)
  ) {
    throw new TypeError(`${label} is invalid or too large`);
  }
  return value;
}

function responseStatus(value) {
  const status = Number(value);
  if (!Number.isSafeInteger(status) || status < 200 || status > 599) {
    throw new TypeError('HTTP content response status must be a terminal status from 200 to 599');
  }
  return status;
}

function serializeHttpContentManifest(value) {
  return `${stableStringify(value)}\n`;
}

function contentManifestEntry(input) {
  plainObject(input, 'HTTP content manifest entry');
  const request = httpRequestIdentity(input.request);
  if (request.credentialed) {
    throw new TypeError('credentialed HTTP requests cannot enter a replay manifest');
  }
  if (request.method === 'HEAD') {
    throw new TypeError('HEAD responses cannot enter a replay manifest');
  }
  const requestKey = httpRequestIdentityKey(request);
  if (input.requestKey != null && input.requestKey !== requestKey) {
    throw new TypeError('HTTP content manifest requestKey does not match its request identity');
  }
  const response = plainObject(input.response, 'HTTP content manifest response');
  const status = responseStatus(response.status);
  if (status === 206 || status === 304) {
    throw new TypeError(`HTTP ${status} responses cannot enter a replay manifest`);
  }
  const bodyDigest = exactDigest(response.bodyDigest, 'HTTP content response bodyDigest');
  const bodyBytes = nonNegativeInteger(response.bodyBytes, 'HTTP content response bodyBytes');
  const location = optionalMetadata(response.location, 'HTTP content redirect location', 64 * 1024);
  const locationDigest = optionalDigest(
    response.locationDigest,
    'HTTP content redirect locationDigest',
  );
  const hasLocation = location !== null || locationDigest !== null;
  if (
    (location === null) !== (locationDigest === null)
    || (hasLocation && (status < 300 || status > 399 || status === 304))
  ) {
    throw new TypeError('HTTP redirect locations require a 3xx response and an exact digest');
  }
  if (location !== null && sha256(location) !== locationDigest) {
    throw new TypeError('HTTP content redirect location digest does not match');
  }
  return {
    requestKey,
    request,
    response: {
      status,
      bodyDigest,
      bodyBytes,
      contentType: optionalMetadata(response.contentType, 'HTTP contentType'),
      contentEncoding: optionalMetadata(response.contentEncoding, 'HTTP contentEncoding', 128),
      location,
      locationDigest,
    },
    sourceExchangeId: exactDigest(
      input.sourceExchangeId,
      'HTTP content sourceExchangeId',
    ),
    capturedAt: timestamp(input.capturedAt, 'HTTP content capturedAt'),
  };
}

export function createHttpContentManifest(input) {
  plainObject(input, 'HTTP content manifest input');
  if (!RUN_ID_PATTERN.test(input.runId || '')) {
    throw new TypeError('HTTP content manifest runId contains unsupported characters');
  }
  if (!MANIFEST_MODES.has(input.mode)) {
    throw new TypeError(`unsupported HTTP content manifest mode: ${input.mode}`);
  }
  if (
    !Array.isArray(input.entries)
    || input.entries.length < 1
    || input.entries.length > HTTP_CONTENT_MANIFEST_MAX_ENTRIES
  ) {
    throw new TypeError(
      `HTTP content manifest requires 1-${HTTP_CONTENT_MANIFEST_MAX_ENTRIES} response entries`,
    );
  }
  const byRequest = new Map();
  for (const candidate of input.entries) {
    const entry = contentManifestEntry(candidate);
    if (byRequest.has(entry.requestKey)) {
      throw new TypeError(`duplicate HTTP content request identity: ${entry.requestKey}`);
    }
    byRequest.set(entry.requestKey, entry);
  }
  const base = {
    schemaVersion: HTTP_CONTENT_MANIFEST_SCHEMA_VERSION,
    apiVersion: HTTP_EVIDENCE_API_VERSION,
    kind: HTTP_CONTENT_MANIFEST_KIND,
    generatedAt: timestamp(
      input.generatedAt || new Date().toISOString(),
      'HTTP content manifest generatedAt',
    ),
    runId: input.runId,
    mode: input.mode,
    entries: [...byRequest.values()].sort((left, right) => (
      left.requestKey.localeCompare(right.requestKey)
    )),
  };
  const manifest = {
    ...base,
    contentHash: sha256(stableStringify(base)),
  };
  if (Buffer.byteLength(serializeHttpContentManifest(manifest), 'utf8') > MANIFEST_MAX_BYTES) {
    throw new TypeError(`HTTP content manifest exceeds its ${MANIFEST_MAX_BYTES} byte limit`);
  }
  return manifest;
}

const MANIFEST_KEYS = [
  'schemaVersion',
  'apiVersion',
  'kind',
  'generatedAt',
  'runId',
  'mode',
  'entries',
  'contentHash',
];
const ENTRY_KEYS = [
  'requestKey',
  'request',
  'response',
  'sourceExchangeId',
  'capturedAt',
];
const REQUEST_KEYS = [
  'method',
  'scheme',
  'hostname',
  'port',
  'requestTargetDigest',
  'requestBodyDigest',
  'representationHeadersDigest',
  'credentialed',
];
const RESPONSE_KEYS = [
  'status',
  'bodyDigest',
  'bodyBytes',
  'contentType',
  'contentEncoding',
  'location',
  'locationDigest',
];

export function verifyHttpContentManifest(input) {
  exactKeys(input, MANIFEST_KEYS, 'HTTP content manifest');
  if (
    input.schemaVersion !== HTTP_CONTENT_MANIFEST_SCHEMA_VERSION
    || input.apiVersion !== HTTP_EVIDENCE_API_VERSION
    || input.kind !== HTTP_CONTENT_MANIFEST_KIND
  ) {
    throw new TypeError('HTTP content manifest uses an unsupported contract version');
  }
  if (!Array.isArray(input.entries)) {
    throw new TypeError('HTTP content manifest entries must be an array');
  }
  for (const entry of input.entries) {
    exactKeys(entry, ENTRY_KEYS, 'HTTP content manifest entry');
    exactKeys(entry.request, REQUEST_KEYS, 'HTTP content manifest request');
    exactKeys(entry.response, RESPONSE_KEYS, 'HTTP content manifest response');
  }
  const normalized = createHttpContentManifest(input);
  if (stableStringify(normalized) !== stableStringify(input)) {
    throw new TypeError('HTTP content manifest is not normalized or its hash is invalid');
  }
  return normalized;
}

function currentUid() {
  return typeof process.geteuid === 'function' ? process.geteuid() : null;
}

async function syncDirectory(directory) {
  const handle = await fs.open(
    directory,
    fsConstants.O_RDONLY | (fsConstants.O_DIRECTORY || 0) | (fsConstants.O_NOFOLLOW || 0),
  );
  try {
    await handle.sync();
  } finally {
    await handle.close();
  }
}

async function secureDirectory(directory, trustedUid, options = {}) {
  const resolved = path.resolve(directory);
  if (options.mustExist !== true) {
    await fs.mkdir(resolved, { recursive: true, mode: 0o700 });
  }
  const canonical = await fs.realpath(resolved);
  if (canonical !== resolved) {
    throw new Error(`HTTP content store path contains a symlink: ${resolved}`);
  }
  const stat = await fs.lstat(resolved);
  if (!stat.isDirectory() || stat.isSymbolicLink()) {
    throw new Error(`HTTP content store path is not a directory: ${resolved}`);
  }
  if (trustedUid != null && stat.uid !== trustedUid) {
    throw new Error(`HTTP content store path has an unexpected owner: ${resolved}`);
  }
  if (options.requirePrivate === true && (stat.mode & 0o7777) !== 0o700) {
    throw new Error(`HTTP content store root mode must already be 700: ${resolved}`);
  }
  await fs.chmod(resolved, 0o700);
  return resolved;
}

async function openTrustedFile(file, trustedUid, maximumBytes, expectedMode = 0o400) {
  const handle = await fs.open(
    file,
    fsConstants.O_RDONLY | (fsConstants.O_NOFOLLOW || 0),
  );
  try {
    const stat = await handle.stat();
    if (!stat.isFile() || stat.nlink !== 1) {
      throw new Error(`HTTP content artifact is not a singly-linked regular file: ${file}`);
    }
    if (trustedUid != null && stat.uid !== trustedUid) {
      throw new Error(`HTTP content artifact has an unexpected owner: ${file}`);
    }
    if ((stat.mode & 0o7777) !== expectedMode) {
      throw new Error(`HTTP content artifact mode must be ${expectedMode.toString(8)}: ${file}`);
    }
    if (stat.size > maximumBytes) {
      throw new Error(`HTTP content artifact exceeds its byte limit: ${file}`);
    }
    return { handle, stat };
  } catch (error) {
    await handle.close().catch(() => {});
    throw error;
  }
}

function bodyChunk(value) {
  if (Buffer.isBuffer(value)) return value;
  if (value instanceof Uint8Array) {
    return Buffer.from(value.buffer, value.byteOffset, value.byteLength);
  }
  if (typeof value === 'string') return Buffer.from(value, 'utf8');
  throw new TypeError('HTTP response body chunks must be bytes or strings');
}

async function *bodyChunks(source) {
  if (
    Buffer.isBuffer(source)
    || source instanceof Uint8Array
    || typeof source === 'string'
  ) {
    yield bodyChunk(source);
    return;
  }
  if (!source || typeof source[Symbol.asyncIterator] !== 'function') {
    throw new TypeError('HTTP response body must be bytes, a string, or an async iterable');
  }
  for await (const chunk of source) {
    yield bodyChunk(chunk);
  }
}

export async function bufferHttpResponseBody(source, options = {}) {
  const maximumBytes = positiveInteger(
    options.maximumBytes ?? HTTP_CONTENT_DEFAULT_MAX_BYTES,
    'HTTP response maximumBytes',
    HTTP_CONTENT_DEFAULT_MAX_BYTES,
  );
  const chunks = [];
  let bytes = 0;
  const hash = crypto.createHash('sha256');
  for await (const chunk of bodyChunks(source)) {
    if (bytes + chunk.length > maximumBytes) {
      const error = new Error(`HTTP response exceeds the ${maximumBytes} byte buffer limit`);
      error.code = 'NOSH_HTTP_RESPONSE_TOO_LARGE';
      throw error;
    }
    bytes += chunk.length;
    hash.update(chunk);
    chunks.push(chunk);
  }
  return {
    body: Buffer.concat(chunks, bytes),
    bytes,
    digest: `sha256:${hash.digest('hex')}`,
  };
}

export class HttpContentStore {
  constructor(options = {}) {
    plainObject(options, 'HTTP content store options');
    if (typeof options.root !== 'string' || !path.isAbsolute(options.root)) {
      throw new TypeError('HTTP content store root must be absolute');
    }
    if (
      typeof options.containmentRoot !== 'string'
      || !path.isAbsolute(options.containmentRoot)
    ) {
      throw new TypeError('HTTP content store containmentRoot must be absolute');
    }
    this.root = path.resolve(options.root);
    this.containmentRoot = path.resolve(options.containmentRoot);
    const relativeRoot = path.relative(this.containmentRoot, this.root);
    if (
      relativeRoot === ''
      || relativeRoot === '..'
      || relativeRoot.startsWith(`..${path.sep}`)
      || path.isAbsolute(relativeRoot)
    ) {
      throw new TypeError('HTTP content store root must be a child of containmentRoot');
    }
    this.trustedUid = options.trustedUid === undefined
      ? currentUid()
      : (options.trustedUid == null ? null : nonNegativeInteger(options.trustedUid, 'trustedUid'));
    this.maxObjectBytes = positiveInteger(
      options.maxObjectBytes ?? HTTP_CONTENT_DEFAULT_MAX_BYTES,
      'HTTP content store maxObjectBytes',
      HTTP_CONTENT_DEFAULT_MAX_BYTES,
    );
    this.maxTotalBytes = positiveInteger(
      options.maxTotalBytes ?? HTTP_CONTENT_DEFAULT_MAX_TOTAL_BYTES,
      'HTTP content store maxTotalBytes',
    );
    this.maxObjects = positiveInteger(
      options.maxObjects ?? HTTP_CONTENT_DEFAULT_MAX_OBJECTS,
      'HTTP content store maxObjects',
      HTTP_CONTENT_MANIFEST_MAX_ENTRIES,
    );
    this.objectsRoot = path.join(this.root, 'objects', 'sha256');
    this.manifestsRoot = path.join(this.root, 'manifests');
    this.temporaryRoot = path.join(this.root, 'tmp');
    this.totalObjectBytes = 0;
    this.objectCount = 0;
    this.initialized = false;
    this.initializationPromise = null;
    this.quotaTail = Promise.resolve();
  }

  async measureUsage() {
    let totalObjectBytes = 0;
    let objectCount = 0;
    const shards = await fs.readdir(this.objectsRoot, { withFileTypes: true });
    for (const shard of shards) {
      if (!shard.isDirectory() || !/^[a-f0-9]{2}$/.test(shard.name)) {
        throw new Error('HTTP content store contains an invalid object shard');
      }
      const shardPath = path.join(this.objectsRoot, shard.name);
      const canonical = await fs.realpath(shardPath);
      const shardStat = await fs.lstat(shardPath);
      if (
        canonical !== shardPath
        || !shardStat.isDirectory()
        || shardStat.isSymbolicLink()
        || (this.trustedUid != null && shardStat.uid !== this.trustedUid)
      ) {
        throw new Error('HTTP content store contains an unsafe object shard');
      }
      const objects = await fs.readdir(shardPath, { withFileTypes: true });
      for (const object of objects) {
        if (!object.isFile() || !/^[a-f0-9]{64}$/.test(object.name)) {
          throw new Error('HTTP content store contains an invalid object');
        }
        const objectStat = await fs.lstat(path.join(shardPath, object.name));
        if (
          !objectStat.isFile()
          || objectStat.isSymbolicLink()
          || objectStat.nlink !== 1
          || (objectStat.mode & 0o7777) !== 0o400
          || (this.trustedUid != null && objectStat.uid !== this.trustedUid)
        ) {
          throw new Error('HTTP content store contains an unsafe object');
        }
        objectCount += 1;
        totalObjectBytes += objectStat.size;
        if (objectCount > this.maxObjects || totalObjectBytes > this.maxTotalBytes) {
          const error = new Error('HTTP content store exceeds its configured run quota');
          error.code = 'NOSH_HTTP_CONTENT_QUOTA';
          throw error;
        }
      }
    }
    this.objectCount = objectCount;
    this.totalObjectBytes = totalObjectBytes;
  }

  async initialize() {
    const canonicalContainment = await fs.realpath(this.containmentRoot);
    if (canonicalContainment !== this.containmentRoot) {
      throw new Error('HTTP content store containmentRoot contains a symlink');
    }
    await secureDirectory(this.root, this.trustedUid, {
      mustExist: true,
      requirePrivate: true,
    });
    await secureDirectory(path.join(this.root, 'objects'), this.trustedUid);
    await secureDirectory(this.objectsRoot, this.trustedUid);
    await secureDirectory(this.manifestsRoot, this.trustedUid);
    await secureDirectory(this.temporaryRoot, this.trustedUid);
    await this.measureUsage();
    this.initialized = true;
    return {
      root: this.root,
      objectsRoot: this.objectsRoot,
      manifestsRoot: this.manifestsRoot,
    };
  }

  async ensureInitialized() {
    if (!this.initialized) {
      this.initializationPromise ||= this.initialize();
      try {
        await this.initializationPromise;
      } catch (error) {
        this.initializationPromise = null;
        throw error;
      }
    }
  }

  async withQuotaLock(operation) {
    const previous = this.quotaTail;
    let release;
    this.quotaTail = new Promise((resolve) => {
      release = resolve;
    });
    await previous;
    try {
      return await operation();
    } finally {
      release();
    }
  }

  objectPath(value) {
    const selected = exactDigest(value, 'HTTP content object digest').slice('sha256:'.length);
    return path.join(this.objectsRoot, selected.slice(0, 2), selected);
  }

  manifestPath(value) {
    const selected = exactDigest(value, 'HTTP content manifest hash').slice('sha256:'.length);
    return path.join(this.manifestsRoot, `${selected}.json`);
  }

  async put(source, options = {}) {
    await this.ensureInitialized();
    const maximumBytes = positiveInteger(
      options.maximumBytes ?? this.maxObjectBytes,
      'HTTP content object maximumBytes',
      this.maxObjectBytes,
    );
    const expectedDigest = options.expectedDigest == null
      ? null
      : exactDigest(options.expectedDigest, 'expected HTTP content digest');
    const temporary = path.join(
      this.temporaryRoot,
      `${process.pid}.${crypto.randomUUID()}.part`,
    );
    const handle = await fs.open(
      temporary,
      fsConstants.O_WRONLY
        | fsConstants.O_CREAT
        | fsConstants.O_EXCL
        | (fsConstants.O_NOFOLLOW || 0),
      0o600,
    );
    let bytes = 0;
    const hash = crypto.createHash('sha256');
    try {
      for await (const chunk of bodyChunks(source)) {
        if (bytes + chunk.length > maximumBytes) {
          const error = new Error(`HTTP content object exceeds the ${maximumBytes} byte limit`);
          error.code = 'NOSH_HTTP_RESPONSE_TOO_LARGE';
          throw error;
        }
        let offset = 0;
        while (offset < chunk.length) {
          const { bytesWritten } = await handle.write(
            chunk,
            offset,
            chunk.length - offset,
          );
          if (!Number.isSafeInteger(bytesWritten) || bytesWritten < 1) {
            throw new Error('HTTP content object write made no forward progress');
          }
          offset += bytesWritten;
        }
        hash.update(chunk);
        bytes += chunk.length;
      }
      await handle.sync();
    } catch (error) {
      await handle.close().catch(() => {});
      await fs.unlink(temporary).catch(() => {});
      throw error;
    }
    await handle.close();
    const objectDigest = `sha256:${hash.digest('hex')}`;
    if (expectedDigest != null && expectedDigest !== objectDigest) {
      await fs.unlink(temporary).catch(() => {});
      const error = new Error(
        `HTTP content digest mismatch: expected ${expectedDigest}, observed ${objectDigest}`,
      );
      error.code = 'NOSH_HTTP_CONTENT_MISMATCH';
      throw error;
    }
    const destination = this.objectPath(objectDigest);
    const shard = path.dirname(destination);
    await secureDirectory(shard, this.trustedUid);
    await fs.chmod(temporary, 0o400);
    let created = false;
    try {
      created = await this.withQuotaLock(async () => {
        try {
          await this.read(objectDigest, { expectedBytes: bytes });
          return false;
        } catch (error) {
          if (error.code !== 'ENOENT') throw error;
        }
        if (
          this.objectCount >= this.maxObjects
          || this.totalObjectBytes + bytes > this.maxTotalBytes
        ) {
          const error = new Error('HTTP content store exceeds its configured run quota');
          error.code = 'NOSH_HTTP_CONTENT_QUOTA';
          throw error;
        }
        try {
          await fs.link(temporary, destination);
        } catch (error) {
          if (error.code !== 'EEXIST') throw error;
          await this.read(objectDigest, { expectedBytes: bytes });
          return false;
        }
        this.objectCount += 1;
        this.totalObjectBytes += bytes;
        await syncDirectory(shard);
        return true;
      });
    } finally {
      await fs.unlink(temporary).catch(() => {});
      await syncDirectory(this.temporaryRoot).catch(() => {});
    }
    await this.read(objectDigest, { expectedBytes: bytes });
    return {
      digest: objectDigest,
      bytes,
      created,
    };
  }

  async read(value, options = {}) {
    await this.ensureInitialized();
    const selectedDigest = exactDigest(value, 'HTTP content object digest');
    const { handle, stat } = await openTrustedFile(
      this.objectPath(selectedDigest),
      this.trustedUid,
      this.maxObjectBytes,
    );
    try {
      if (
        options.expectedBytes != null
        && nonNegativeInteger(options.expectedBytes, 'expected HTTP content bytes') !== stat.size
      ) {
        throw new Error('HTTP content object size does not match its manifest');
      }
      const body = await handle.readFile();
      if (sha256(body) !== selectedDigest) {
        throw new Error('HTTP content object digest does not match its address');
      }
      return body;
    } finally {
      await handle.close();
    }
  }

  async verify(value, options = {}) {
    const body = await this.read(value, options);
    return {
      digest: exactDigest(value, 'HTTP content object digest'),
      bytes: body.length,
    };
  }

  async writeManifest(input) {
    await this.ensureInitialized();
    const manifest = verifyHttpContentManifest(input);
    for (const entry of manifest.entries) {
      await this.verify(entry.response.bodyDigest, {
        expectedBytes: entry.response.bodyBytes,
      });
    }
    const destination = this.manifestPath(manifest.contentHash);
    const content = Buffer.from(serializeHttpContentManifest(manifest), 'utf8');
    if (content.length > MANIFEST_MAX_BYTES) {
      throw new Error(`HTTP content manifest exceeds its ${MANIFEST_MAX_BYTES} byte limit`);
    }
    const temporary = path.join(
      this.temporaryRoot,
      `${process.pid}.${crypto.randomUUID()}.manifest`,
    );
    let created = false;
    try {
      const handle = await fs.open(
        temporary,
        fsConstants.O_WRONLY
          | fsConstants.O_CREAT
          | fsConstants.O_EXCL
          | (fsConstants.O_NOFOLLOW || 0),
        0o600,
      );
      try {
        await handle.writeFile(content);
        await handle.sync();
      } finally {
        await handle.close();
      }
      await fs.chmod(temporary, 0o400);
      await fs.link(temporary, destination);
      await syncDirectory(this.manifestsRoot);
      created = true;
    } catch (error) {
      if (error.code !== 'EEXIST') throw error;
      const current = await this.readManifest(manifest.contentHash);
      if (stableStringify(current) !== stableStringify(manifest)) {
        throw new Error('immutable HTTP content manifest already differs');
      }
    } finally {
      await fs.unlink(temporary).catch(() => {});
      await syncDirectory(this.temporaryRoot).catch(() => {});
    }
    return {
      manifest,
      created,
    };
  }

  async readManifest(value) {
    await this.ensureInitialized();
    const selectedHash = exactDigest(value, 'HTTP content manifest hash');
    const { handle } = await openTrustedFile(
      this.manifestPath(selectedHash),
      this.trustedUid,
      MANIFEST_MAX_BYTES,
    );
    try {
      let document;
      try {
        document = JSON.parse((await handle.readFile()).toString('utf8'));
      } catch (error) {
        throw new Error('HTTP content manifest is not valid JSON', { cause: error });
      }
      const manifest = verifyHttpContentManifest(document);
      if (manifest.contentHash !== selectedHash) {
        throw new Error('HTTP content manifest does not match its content address');
      }
      return manifest;
    } finally {
      await handle.close();
    }
  }
}

function gateError(code, message) {
  const error = new Error(message);
  error.code = code;
  return error;
}

export class HttpContentGate {
  constructor(options = {}) {
    plainObject(options, 'HTTP content gate options');
    if (!HTTP_CONTENT_GATE_MODES.includes(options.mode)) {
      throw new TypeError(`unsupported HTTP content gate mode: ${options.mode}`);
    }
    if (options.store != null && !(options.store instanceof HttpContentStore)) {
      throw new TypeError('HTTP content gate store must be an HttpContentStore');
    }
    this.mode = options.mode;
    this.store = options.store || null;
    this.maximumBytes = positiveInteger(
      options.maximumBytes ?? this.store?.maxObjectBytes ?? HTTP_CONTENT_DEFAULT_MAX_BYTES,
      'HTTP content gate maximumBytes',
      this.store?.maxObjectBytes ?? HTTP_CONTENT_DEFAULT_MAX_BYTES,
    );
    this.persistObserved = options.persistObserved === true;
    if (this.persistObserved && !this.store) {
      throw new TypeError('persistObserved requires an HTTP content store');
    }
    this.manifest = options.manifest == null
      ? null
      : verifyHttpContentManifest(options.manifest);
    if (this.mode === 'observe' && this.manifest != null) {
      throw new TypeError('observe mode must not apply a reviewed HTTP content manifest');
    }
    if (this.mode !== 'observe') {
      if (!this.store || !this.manifest) {
        throw new TypeError(`${this.mode} requires an HTTP content store and manifest`);
      }
      if (this.manifest.mode !== this.mode) {
        throw new TypeError('HTTP content gate mode does not match its reviewed manifest');
      }
    }
    this.entries = new Map(
      (this.manifest?.entries || []).map((entry) => [entry.requestKey, entry]),
    );
  }

  reviewedEntry(request) {
    const requestKey = httpRequestIdentityKey(request);
    const entry = this.entries.get(requestKey);
    if (!entry) {
      throw gateError(
        'NOSH_HTTP_POLICY_MISS',
        `HTTP request is absent from the reviewed content manifest: ${requestKey}`,
      );
    }
    return entry;
  }

  async process(input) {
    plainObject(input, 'HTTP content gate input');
    const request = httpRequestIdentity(input.request);
    if (request.credentialed) {
      throw gateError(
        'NOSH_HTTP_CREDENTIAL_UNSUPPORTED',
        'credentialed HTTP requests cannot use content replay or digest gates',
      );
    }
    if (this.mode === 'observe') {
      if (input.responseBody == null) {
        throw new TypeError('observe mode requires a response body');
      }
      const buffered = await bufferHttpResponseBody(input.responseBody, {
        maximumBytes: this.maximumBytes,
      });
      if (this.persistObserved) {
        await this.store.put(buffered.body, {
          expectedDigest: buffered.digest,
          maximumBytes: this.maximumBytes,
        });
      }
      return {
        action: 'observed',
        requestKey: httpRequestIdentityKey(request),
        body: buffered.body,
        bodyDigest: buffered.digest,
        bodyBytes: buffered.bytes,
        persisted: this.persistObserved,
      };
    }
    const entry = this.reviewedEntry(request);
    if (this.mode === 'offline-replay') {
      if (input.responseBody != null) {
        throw gateError(
          'NOSH_HTTP_OFFLINE_ORIGIN_CONTACT',
          'offline replay refuses an upstream response body',
        );
      }
      const body = await this.store.read(entry.response.bodyDigest, {
        expectedBytes: entry.response.bodyBytes,
      });
      return {
        action: 'replayed',
        requestKey: entry.requestKey,
        status: entry.response.status,
        contentType: entry.response.contentType,
        contentEncoding: entry.response.contentEncoding,
        location: entry.response.location,
        body,
        bodyDigest: entry.response.bodyDigest,
        bodyBytes: entry.response.bodyBytes,
      };
    }
    if (input.responseBody == null) {
      throw new TypeError('live buffer verification requires an upstream response body');
    }
    const buffered = await bufferHttpResponseBody(input.responseBody, {
      maximumBytes: this.maximumBytes,
    });
    if (
      buffered.digest !== entry.response.bodyDigest
      || buffered.bytes !== entry.response.bodyBytes
    ) {
      throw gateError(
        'NOSH_HTTP_CONTENT_MISMATCH',
        `HTTP response content differs from reviewed digest ${entry.response.bodyDigest}`,
      );
    }
    if (
      input.status == null
      || responseStatus(input.status) !== entry.response.status
      || optionalMetadata(input.contentType, 'live HTTP contentType') !== entry.response.contentType
      || optionalMetadata(
        input.contentEncoding,
        'live HTTP contentEncoding',
        128,
      ) !== entry.response.contentEncoding
      || optionalMetadata(
        input.location,
        'live HTTP redirect location',
        64 * 1024,
      ) !== entry.response.location
    ) {
      throw gateError(
        'NOSH_HTTP_RESPONSE_METADATA_MISMATCH',
        'HTTP response metadata differs from the reviewed response',
      );
    }
    return {
      action: 'verified',
      requestKey: entry.requestKey,
      status: entry.response.status,
      contentType: entry.response.contentType,
      contentEncoding: entry.response.contentEncoding,
      location: entry.response.location,
      body: buffered.body,
      bodyDigest: buffered.digest,
      bodyBytes: buffered.bytes,
    };
  }
}
