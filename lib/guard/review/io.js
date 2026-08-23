import crypto from 'node:crypto';
import { constants as fsConstants } from 'node:fs';
import fs from 'node:fs/promises';
import path from 'node:path';

import { jcsCanonicalize, sha256Digest } from './jcs.js';

const DEFAULT_MAX_DOCUMENT_BYTES = 16 * 1024 * 1024;
const DEFAULT_MAX_ARTIFACT_BYTES = 256 * 1024 * 1024;
const SAFE_ARTIFACT_NAME = /^[A-Za-z0-9][A-Za-z0-9._/-]{0,511}$/;

function decodeUtf8(content, label) {
  try {
    return new TextDecoder('utf-8', { fatal: true }).decode(content);
  } catch (error) {
    throw new Error(`${label} is not valid UTF-8`, { cause: error });
  }
}

function expectedUserId(options = {}) {
  if (options.expectedUid === null) return null;
  if (Number.isSafeInteger(options.expectedUid) && options.expectedUid >= 0) {
    return options.expectedUid;
  }
  return typeof process.geteuid === 'function' ? process.geteuid() : null;
}

function safeRelativePath(value, label = 'artifact path') {
  if (
    typeof value !== 'string'
    || !SAFE_ARTIFACT_NAME.test(value)
    || path.isAbsolute(value)
    || value.includes('\\')
  ) {
    throw new TypeError(`${label} must be a safe relative POSIX path`);
  }
  const normalized = path.posix.normalize(value);
  if (
    normalized !== value
    || normalized === '..'
    || normalized.startsWith('../')
    || normalized.includes('/../')
  ) {
    throw new TypeError(`${label} escapes its bundle`);
  }
  return normalized;
}

async function syncDirectory(directory) {
  const handle = await fs.open(
    directory,
    fsConstants.O_RDONLY
      | (fsConstants.O_DIRECTORY || 0)
      | (fsConstants.O_NOFOLLOW || 0),
  );
  try {
    await handle.sync();
  } finally {
    await handle.close();
  }
}

function sameFileSnapshot(before, after) {
  return before.dev === after.dev
    && before.ino === after.ino
    && before.size === after.size
    && before.mtimeMs === after.mtimeMs
    && before.ctimeMs === after.ctimeMs;
}

async function readBoundedSnapshot(handle, before, maximumBytes, resolved) {
  if (!Number.isSafeInteger(before.size) || before.size > maximumBytes) {
    throw new Error(`trusted input exceeds its byte limit: ${resolved}`);
  }
  const content = Buffer.allocUnsafe(before.size);
  let offset = 0;
  while (offset < content.length) {
    const result = await handle.read(content, offset, content.length - offset, offset);
    if (result.bytesRead === 0) {
      throw new Error(`trusted input changed while it was read: ${resolved}`);
    }
    offset += result.bytesRead;
  }
  const extra = Buffer.allocUnsafe(1);
  const trailing = await handle.read(extra, 0, 1, content.length);
  const after = await handle.stat();
  if (trailing.bytesRead !== 0 || !sameFileSnapshot(before, after)) {
    throw new Error(`trusted input changed while it was read: ${resolved}`);
  }
  return content;
}

export async function readTrustedFile(file, options = {}) {
  const resolved = path.resolve(file);
  const maximumBytes = options.maximumBytes ?? DEFAULT_MAX_DOCUMENT_BYTES;
  if (!Number.isSafeInteger(maximumBytes) || maximumBytes < 1) {
    throw new TypeError('trusted file byte limit must be positive');
  }
  const handle = await fs.open(
    resolved,
    fsConstants.O_RDONLY | (fsConstants.O_NOFOLLOW || 0),
  );
  try {
    const stat = await handle.stat();
    const uid = expectedUserId(options);
    if (!stat.isFile() || stat.nlink !== 1) {
      throw new Error(`trusted input is not a singly-linked file: ${resolved}`);
    }
    if (uid != null && stat.uid !== uid) {
      throw new Error(`trusted input has an unexpected owner: ${resolved}`);
    }
    if ((stat.mode & (options.allowGroupRead ? 0o022 : 0o077)) !== 0) {
      throw new Error(`trusted input has unsafe permissions: ${resolved}`);
    }
    return await readBoundedSnapshot(handle, stat, maximumBytes, resolved);
  } finally {
    await handle.close();
  }
}

export async function readTrustedJson(file, options = {}) {
  const content = await readTrustedFile(file, options);
  const text = decodeUtf8(content, `trusted input ${path.resolve(file)}`);
  let document;
  try {
    document = JSON.parse(text);
  } catch (error) {
    throw new Error(`trusted input is not valid JSON: ${path.resolve(file)}`, {
      cause: error,
    });
  }
  if (options.requireJcs === true && jcsCanonicalize(document) !== text) {
    throw new Error(`trusted input is not JCS canonical: ${path.resolve(file)}`);
  }
  return { content, document, digest: sha256Digest(content) };
}

export async function readTrustedNdjson(file, options = {}) {
  const resolved = path.resolve(file);
  const maximumBytes = options.maximumBytes ?? DEFAULT_MAX_ARTIFACT_BYTES;
  const maximumLineBytes = options.maximumLineBytes ?? 1024 * 1024;
  const maximumRecords = options.maximumRecords ?? 1_000_000;
  if (
    !Number.isSafeInteger(maximumBytes)
    || maximumBytes < 1
    || !Number.isSafeInteger(maximumLineBytes)
    || maximumLineBytes < 1
    || !Number.isSafeInteger(maximumRecords)
    || maximumRecords < 1
  ) {
    throw new TypeError('NDJSON limits must be positive safe integers');
  }
  const handle = await fs.open(
    resolved,
    fsConstants.O_RDONLY | (fsConstants.O_NOFOLLOW || 0),
  );
  try {
    const stat = await handle.stat();
    const uid = expectedUserId(options);
    if (
      !stat.isFile()
      || stat.nlink !== 1
      || (uid != null && stat.uid !== uid)
      || (stat.mode & 0o077) !== 0
      || stat.size > maximumBytes
    ) {
      throw new Error(`NDJSON input is not a trusted bounded file: ${resolved}`);
    }
    if (options.expectedBytes != null && Number(options.expectedBytes) !== stat.size) {
      throw new Error(`NDJSON input byte count does not match its manifest: ${resolved}`);
    }
    const stream = handle.createReadStream({ autoClose: false });
    const hash = crypto.createHash('sha256');
    const decoder = new TextDecoder('utf-8', { fatal: true });
    let bytesRead = 0;
    let pending = '';
    let ordinal = 0;
    let parsed = 0;
    let parseErrors = 0;
    const consumeLine = async (inputLine) => {
      const line = inputLine.endsWith('\r') ? inputLine.slice(0, -1) : inputLine;
      ordinal += 1;
      if (ordinal > maximumRecords) {
        throw new Error(`NDJSON input exceeds its record limit: ${resolved}`);
      }
      if (Buffer.byteLength(line, 'utf8') > maximumLineBytes) {
        throw new Error(`NDJSON line exceeds its byte limit: ${resolved}:${ordinal}`);
      }
      if (!line.trim()) {
        parseErrors += 1;
        await options.onParseError?.({ ordinal, line, error: new Error('blank NDJSON line') });
        return;
      }
      let record;
      try {
        record = JSON.parse(line);
      } catch (error) {
        parseErrors += 1;
        await options.onParseError?.({ ordinal, line, error });
        return;
      }
      parsed += 1;
      await options.onRecord?.(record, { ordinal });
    };
    try {
      for await (const chunk of stream) {
        bytesRead += chunk.length;
        if (bytesRead > maximumBytes) {
          throw new Error(`NDJSON input exceeds its byte limit: ${resolved}`);
        }
        hash.update(chunk);
        pending += decoder.decode(chunk, { stream: true });
        let newline;
        while ((newline = pending.indexOf('\n')) !== -1) {
          const line = pending.slice(0, newline);
          pending = pending.slice(newline + 1);
          await consumeLine(line);
        }
        if (Buffer.byteLength(pending, 'utf8') > maximumLineBytes) {
          throw new Error(`NDJSON line exceeds its byte limit: ${resolved}:${ordinal + 1}`);
        }
      }
      pending += decoder.decode();
    } catch (error) {
      if (error instanceof TypeError && /encoded data was not valid/.test(error.message)) {
        throw new Error(`NDJSON input is not valid UTF-8: ${resolved}`, { cause: error });
      }
      throw error;
    }
    if (pending.length > 0) {
      await consumeLine(pending);
    }
    const finalStat = await handle.stat();
    if (bytesRead !== stat.size || !sameFileSnapshot(stat, finalStat)) {
      throw new Error(`NDJSON input changed while it was read: ${resolved}`);
    }
    const selectedDigest = `sha256:${hash.digest('hex')}`;
    if (options.expectedDigest && options.expectedDigest !== selectedDigest) {
      throw new Error(`NDJSON input digest does not match its manifest: ${resolved}`);
    }
    return {
      bytes: stat.size,
      digest: selectedDigest,
      records: parsed,
      lines: ordinal,
      parseErrors,
    };
  } finally {
    await handle.close();
  }
}

async function writeExclusiveFile(file, content, mode = 0o600) {
  const handle = await fs.open(
    file,
    fsConstants.O_WRONLY
      | fsConstants.O_CREAT
      | fsConstants.O_EXCL
      | (fsConstants.O_NOFOLLOW || 0),
    mode,
  );
  try {
    await handle.writeFile(content);
    await handle.sync();
  } finally {
    await handle.close();
  }
}

async function createPrivateDirectory(directory) {
  await fs.mkdir(directory, { mode: 0o700 });
  const stat = await fs.lstat(directory);
  const uid = expectedUserId();
  if (
    !stat.isDirectory()
    || stat.isSymbolicLink()
    || stat.nlink < 2
    || (uid != null && stat.uid !== uid)
    || (stat.mode & 0o7777) !== 0o700
  ) {
    throw new Error(`output directory is not private: ${directory}`);
  }
}

export async function writeArtifactDirectory(directory, artifacts, options = {}) {
  const destination = path.resolve(directory);
  if (!artifacts || typeof artifacts !== 'object' || Array.isArray(artifacts)) {
    throw new TypeError('artifacts must be an object');
  }
  const parent = path.dirname(destination);
  const maximumBytes = options.maximumBytes ?? DEFAULT_MAX_ARTIFACT_BYTES;
  if (!Number.isSafeInteger(maximumBytes) || maximumBytes < 1) {
    throw new TypeError('artifact directory byte limit must be a positive safe integer');
  }
  const resolvedParent = await fs.realpath(parent);
  if (resolvedParent !== parent) {
    throw new Error(`artifact parent directory must not traverse a symlink: ${parent}`);
  }
  const parentStat = await fs.lstat(parent);
  const uid = expectedUserId(options);
  if (
    !parentStat.isDirectory()
    || parentStat.isSymbolicLink()
    || (uid != null && parentStat.uid !== uid)
    || (parentStat.mode & 0o022) !== 0
  ) {
    throw new Error(`artifact parent directory is not trusted: ${parent}`);
  }
  // Reserve the final pathname with mkdir(2), whose EEXIST behavior gives the
  // writer a race-free no-clobber guarantee. Readers treat the manifest as the
  // completion marker, so a concurrently observed partial directory fails
  // closed instead of exposing a previous artifact under a reused pathname.
  await createPrivateDirectory(destination);
  try {
    let totalBytes = 0;
    const inventory = [];
    for (const [name, input] of Object.entries(artifacts).sort(
      ([left], [right]) => left.localeCompare(right),
    )) {
      const relative = safeRelativePath(name);
      if (!Buffer.isBuffer(input) && typeof input !== 'string') {
        throw new TypeError(`artifact ${relative} must be a string or Buffer`);
      }
      const content = Buffer.isBuffer(input) ? input : Buffer.from(input, 'utf8');
      totalBytes += content.length;
      if (totalBytes > maximumBytes) {
        throw new Error('artifact directory exceeds its byte limit');
      }
      const target = path.join(destination, ...relative.split('/'));
      const targetParent = path.dirname(target);
      if (targetParent !== destination) {
        await fs.mkdir(targetParent, { recursive: true, mode: 0o700 });
      }
      await writeExclusiveFile(target, content);
      inventory.push({
        path: relative,
        bytes: String(content.length),
        sha256: sha256Digest(content),
      });
    }
    await syncDirectory(destination);
    await syncDirectory(parent);
    return { directory: destination, inventory, totalBytes: String(totalBytes) };
  } catch (error) {
    await fs.rm(destination, { recursive: true, force: true }).catch(() => {});
    throw error;
  }
}

export async function writeEd25519KeyPair(directory, pair) {
  const destination = path.resolve(directory);
  const parent = path.dirname(destination);
  const resolvedParent = await fs.realpath(parent);
  if (resolvedParent !== parent) {
    throw new Error(`key parent directory must not traverse a symlink: ${parent}`);
  }
  const parentStat = await fs.lstat(parent);
  const uid = expectedUserId();
  if (
    !parentStat.isDirectory()
    || parentStat.isSymbolicLink()
    || (uid != null && parentStat.uid !== uid)
    || (parentStat.mode & 0o022) !== 0
  ) {
    throw new Error(`key parent directory is not trusted: ${parent}`);
  }
  await createPrivateDirectory(destination);
  try {
    await writeExclusiveFile(
      path.join(destination, 'private.pem'),
      pair.privateKeyPem,
      0o600,
    );
    await writeExclusiveFile(
      path.join(destination, 'public.pem'),
      pair.publicKeyPem,
      0o600,
    );
    await writeExclusiveFile(
      path.join(destination, 'key-id'),
      `${pair.keyId}\n`,
      0o600,
    );
    await syncDirectory(destination);
    await syncDirectory(parent);
  } catch (error) {
    await fs.rm(destination, { recursive: true, force: true }).catch(() => {});
    throw error;
  }
  return {
    directory: destination,
    privateKey: path.join(destination, 'private.pem'),
    publicKey: path.join(destination, 'public.pem'),
    keyId: pair.keyId,
  };
}

export async function readPrivateSigningKey(file) {
  return (await readTrustedFile(file, { maximumBytes: 64 * 1024 })).toString('utf8');
}

export async function readPublicVerificationKey(file, options = {}) {
  return (await readTrustedFile(file, {
    maximumBytes: 64 * 1024,
    allowGroupRead: true,
    ...options,
  })).toString('utf8');
}

export function createLeafManifest(input) {
  const artifacts = Object.entries(input.artifacts || {})
    .map(([name, content]) => {
      const relative = safeRelativePath(name);
      const bytes = Buffer.isBuffer(content) ? content : Buffer.from(String(content), 'utf8');
      return {
        path: relative,
        mediaType: relative.endsWith('.json')
          ? 'application/json'
          : relative.endsWith('.yaml') || relative.endsWith('.yml')
            ? 'application/yaml'
          : 'text/plain',
        bytes: String(bytes.length),
        sha256: sha256Digest(bytes),
      };
    })
    .sort((left, right) => left.path.localeCompare(right.path));
  const manifest = {
    apiVersion: 'notty.dev/v1alpha1',
    kind: 'NoshPolicyLeafBundle',
    schemaVersion: 1,
    createdAt: input.createdAt || new Date().toISOString(),
    target: input.target,
    activationEligible: input.activationEligible === true,
    graphDigest: input.graphDigest,
    decisionSetDigest: input.decisionSetDigest,
    policyIrDigest: input.policyIrDigest,
    targetContextDigest: input.targetContextDigest,
    capabilityDigest: input.capabilityDigest,
    projectionDigest: input.projectionDigest,
    artifacts,
  };
  return {
    ...manifest,
    bundleDigest: sha256Digest(jcsCanonicalize(manifest)),
  };
}
