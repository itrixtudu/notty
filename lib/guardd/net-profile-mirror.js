import crypto from 'node:crypto';
import fs from 'node:fs/promises';
import { constants as fsConstants } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import process from 'node:process';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

import { validateEbpfTargetContextDocument } from './enforcement-backend.js';

const MIRROR_KIND = 'NoshEgressProfileReceipt';
const REVIEW_EXPORT_KIND = 'NoshGuardEbpfReviewCandidateExport';
const HASH = /^sha256:[a-f0-9]{64}$/;
const SAFE_SEGMENT = /^[A-Za-z0-9_.-]{1,128}$/;

function sha256(value) {
  return `sha256:${crypto.createHash('sha256').update(value).digest('hex')}`;
}

function stableJson(value) {
  if (Array.isArray(value)) {
    return `[${value.map((item) => stableJson(item)).join(',')}]`;
  }
  if (value && typeof value === 'object') {
    return `{${Object.keys(value).sort().map(
      (key) => `${JSON.stringify(key)}:${stableJson(value[key])}`,
    ).join(',')}}`;
  }
  return JSON.stringify(value);
}

function safeSegment(value, label) {
  if (
    typeof value !== 'string'
    || !SAFE_SEGMENT.test(value)
    || value === '.'
    || value === '..'
  ) {
    throw new TypeError(`${label} contains unsupported characters`);
  }
  return value;
}

function numericId(value, label) {
  if (!/^\d+$/.test(String(value || ''))) {
    throw new Error(`${label} must be a numeric ID`);
  }
  const parsed = Number(value);
  if (!Number.isSafeInteger(parsed) || parsed < 0) {
    throw new Error(`${label} is outside the supported range`);
  }
  return parsed;
}

function passwdRecord(raw, expectedUid, expectedGid) {
  const fields = String(raw || '').trim().split(':');
  if (fields.length < 7) {
    throw new Error(`cannot resolve invoking uid ${expectedUid}`);
  }
  const uid = numericId(fields[2], 'passwd uid');
  const gid = numericId(fields[3], 'passwd gid');
  if (!path.isAbsolute(fields[5] || '')) {
    throw new Error('invoking user home from passwd must be absolute');
  }
  const home = path.resolve(fields[5]);
  if (uid !== expectedUid || gid !== expectedGid) {
    throw new Error('invoking user identity does not match passwd data');
  }
  return { username: fields[0], uid, gid, home };
}

export function resolveInvokingUser(options = {}) {
  const env = options.env || process.env;
  const getuid = options.getuid || process.getuid;
  const getgid = options.getgid || process.getgid;
  const currentUid = typeof getuid === 'function' ? getuid() : 0;
  const currentGid = typeof getgid === 'function' ? getgid() : 0;
  if (
    currentUid === 0
    && ((env.SUDO_UID == null) !== (env.SUDO_GID == null))
  ) {
    throw new Error('SUDO_UID and SUDO_GID must be supplied together');
  }
  if (currentUid === 0 && env.SUDO_UID != null && env.SUDO_GID != null) {
    const uid = numericId(env.SUDO_UID, 'SUDO_UID');
    const gid = numericId(env.SUDO_GID, 'SUDO_GID');
    const lookup = options.passwdLookup || ((selectedUid) => {
      const result = spawnSync('getent', ['passwd', String(selectedUid)], {
        encoding: 'utf8',
        timeout: 5_000,
        stdio: ['ignore', 'pipe', 'pipe'],
      });
      if (result.status !== 0) {
        throw new Error(
          `getent passwd ${selectedUid} failed: ${
            result.error?.message || result.stderr || `status ${result.status}`
          }`,
        );
      }
      return result.stdout;
    });
    return passwdRecord(lookup(uid), uid, gid);
  }
  const selected = options.userInfo ? options.userInfo() : os.userInfo();
  return {
    username: selected.username,
    uid: Number.isSafeInteger(selected.uid) ? selected.uid : currentUid,
    gid: Number.isSafeInteger(selected.gid) ? selected.gid : currentGid,
    home: path.resolve(selected.homedir),
  };
}

function workspaceSlug(workdir) {
  return path.basename(workdir)
    .toLowerCase()
    .replace(/[^a-z0-9._-]+/g, '-')
    .replace(/^-+|-+$/g, '')
    .slice(0, 48) || 'workspace';
}

export function mirrorDirectory(workdir, home) {
  const canonical = path.resolve(workdir);
  const key = crypto.createHash('sha256').update(canonical).digest('hex');
  return path.join(
    path.resolve(home),
    '.nosh',
    'net-profiles',
    `${workspaceSlug(canonical)}-${key}`,
  );
}

export function reviewCandidateDirectory(mirrorRoot, workspaceKey, revision) {
  if (!/^[a-f0-9]{64}$/.test(workspaceKey || '')) {
    throw new TypeError('review candidate workspaceKey is invalid');
  }
  return path.join(
    path.resolve(mirrorRoot),
    'review-candidates',
    workspaceKey,
    safeSegment(revision, 'review candidate revision'),
  );
}

async function secureMirrorDirectory(directory) {
  const expectedUid = process.getuid();
  const expectedGid = process.getgid();
  const parts = [
    path.dirname(path.dirname(directory)),
    path.dirname(directory),
    directory,
  ];
  for (const selected of parts) {
    try {
      const stat = await fs.lstat(selected);
      if (!stat.isDirectory() || stat.isSymbolicLink()) {
        throw new Error(`network profile mirror path is not a directory: ${selected}`);
      }
      if (stat.uid !== expectedUid || stat.gid !== expectedGid) {
        throw new Error(
          `network profile mirror path is not owned by the invoking user: ${selected}`,
        );
      }
      await fs.chmod(selected, 0o700);
    } catch (error) {
      if (error.code !== 'ENOENT') {
        throw error;
      }
      await fs.mkdir(selected, { mode: 0o700 });
      await fs.chmod(selected, 0o700);
    }
  }
}

async function atomicWrite(destination, content) {
  const temporary = `${destination}.${process.pid}.${crypto.randomUUID()}.tmp`;
  let handle;
  try {
    handle = await fs.open(
      temporary,
      fsConstants.O_WRONLY |
        fsConstants.O_CREAT |
        fsConstants.O_EXCL |
        (fsConstants.O_NOFOLLOW || 0),
      0o600,
    );
    await handle.writeFile(content);
    await handle.chmod(0o600);
    await handle.sync();
    await handle.close();
    handle = null;
    await fs.rename(temporary, destination);
  } catch (error) {
    await handle?.close().catch(() => {});
    await fs.unlink(temporary).catch(() => {});
    throw error;
  }
}

async function syncDirectory(directory) {
  const handle = await fs.open(
    directory,
    fsConstants.O_RDONLY | (fsConstants.O_DIRECTORY || 0),
  );
  try {
    await handle.sync();
  } finally {
    await handle.close();
  }
}

function parseCandidateFile(source, label) {
  if (typeof source !== 'string' || Buffer.byteLength(source) > 16 * 1024 * 1024) {
    throw new TypeError(`${label} must be a bounded JSON string`);
  }
  try {
    return JSON.parse(source);
  } catch (error) {
    throw new TypeError(`${label} is not valid JSON`, { cause: error });
  }
}

function validateReviewCandidate(candidate) {
  if (!candidate || typeof candidate !== 'object' || Array.isArray(candidate)) {
    throw new TypeError('reviewCandidate must be an object');
  }
  const permitted = [
    'profileSource',
    'policySource',
    'manifestSource',
    'targetContextSource',
  ];
  if (
    Object.keys(candidate).sort().join(',') !== permitted.sort().join(',')
  ) {
    throw new TypeError('reviewCandidate has an invalid field inventory');
  }
  const profile = parseCandidateFile(candidate.profileSource, 'candidate profile');
  const policy = parseCandidateFile(candidate.policySource, 'candidate policy');
  const manifest = parseCandidateFile(candidate.manifestSource, 'candidate manifest');
  const targetContext = parseCandidateFile(
    candidate.targetContextSource,
    'guard-ebpf target context',
  );
  const verifiedTarget = validateEbpfTargetContextDocument(targetContext);
  const workspaceKey = profile?.spec?.workspace?.key;
  const revision = profile?.metadata?.revision;
  const expectedFiles = manifest?.files;
  if (
    profile?.kind !== 'NoshEgressProfile'
    || policy?.kind !== 'NoshEgressPolicy'
    || manifest?.kind !== 'NoshEgressBundleManifest'
    || targetContext?.kind !== 'NoshGuardEbpfTargetContext'
    || !/^[a-f0-9]{64}$/.test(workspaceKey || '')
    || !SAFE_SEGMENT.test(revision || '')
    || profile.metadata?.workspaceKey !== workspaceKey
    || policy.metadata?.workspaceKey !== workspaceKey
    || manifest.workspaceKey !== workspaceKey
    || policy.metadata?.revision !== revision
    || manifest.revision !== revision
    || profile.spec?.target?.imageDigest !== manifest.imageDigest
    || verifiedTarget.expected.workspaceKey !== workspaceKey
    || verifiedTarget.expected.imageDigest !== manifest.imageDigest
    || verifiedTarget.expected.workspaceIdentity.dev
      !== String(profile.spec?.workspace?.dev || '')
    || verifiedTarget.expected.workspaceIdentity.ino
      !== String(profile.spec?.workspace?.ino || '')
    || !HASH.test(targetContext.contentHash || '')
  ) {
    throw new Error('review candidate artifacts do not share one exact subject');
  }
  const unsignedTarget = { ...targetContext };
  delete unsignedTarget.contentHash;
  if (targetContext.contentHash !== sha256(stableJson(unsignedTarget))) {
    throw new Error('guard-ebpf target context content hash mismatch');
  }
  const sources = {
    'egress-profile.json': candidate.profileSource,
    'egress-policy.json': candidate.policySource,
    'manifest.json': candidate.manifestSource,
    'guard-ebpf-target-context.json': candidate.targetContextSource,
  };
  for (const name of ['egress-profile.json', 'egress-policy.json']) {
    if (
      expectedFiles?.[name]?.hash !== sha256(sources[name])
      || expectedFiles?.[name]?.bytes !== Buffer.byteLength(sources[name])
    ) {
      throw new Error(`review candidate ${name} does not match its manifest`);
    }
  }
  const unsignedManifest = { ...manifest };
  delete unsignedManifest.contentHash;
  if (
    manifest.contentHash !== sha256(stableJson(unsignedManifest))
    || !HASH.test(manifest.contentHash || '')
  ) {
    throw new Error('review candidate manifest content hash mismatch');
  }
  return { workspaceKey, revision, manifest, targetContext, sources };
}

async function secureChildDirectory(directory) {
  try {
    const stat = await fs.lstat(directory);
    if (
      !stat.isDirectory()
      || stat.isSymbolicLink()
      || stat.uid !== process.getuid()
      || stat.gid !== process.getgid()
    ) {
      throw new Error(`review export path is not a directory: ${directory}`);
    }
    await fs.chmod(directory, 0o700);
  } catch (error) {
    if (error.code !== 'ENOENT') throw error;
    await fs.mkdir(directory, { mode: 0o700 });
    await fs.chmod(directory, 0o700);
    const created = await fs.lstat(directory);
    if (
      !created.isDirectory()
      || created.isSymbolicLink()
      || created.uid !== process.getuid()
      || created.gid !== process.getgid()
    ) {
      throw new Error(`review export path is not user-owned: ${directory}`);
    }
  }
}

async function readImmutableExportFile(destination, name) {
  const selected = path.join(destination, name);
  const handle = await fs.open(
    selected,
    fsConstants.O_RDONLY | (fsConstants.O_NOFOLLOW || 0),
  );
  try {
    const stat = await handle.stat();
    if (
      !stat.isFile()
      || stat.isSymbolicLink()
      || stat.nlink !== 1
      || stat.uid !== process.getuid()
      || stat.gid !== process.getgid()
      || (stat.mode & 0o777) !== 0o600
    ) {
      throw new Error(`review export artifact is not a secure regular file: ${selected}`);
    }
    return await handle.readFile('utf8');
  } finally {
    await handle.close();
  }
}

async function matchingImmutableExport(destination, sources) {
  try {
    const stat = await fs.lstat(destination);
    if (
      !stat.isDirectory()
      || stat.isSymbolicLink()
      || stat.uid !== process.getuid()
      || stat.gid !== process.getgid()
      || (stat.mode & 0o777) !== 0o700
    ) {
      return false;
    }
    for (const [name, source] of Object.entries(sources)) {
      if (await readImmutableExportFile(destination, name) !== source) {
        return false;
      }
    }
    return true;
  } catch {
    return false;
  }
}

async function writeReviewCandidateExport(mirrorRoot, candidate) {
  const verified = validateReviewCandidate(candidate);
  const reviewRoot = path.join(mirrorRoot, 'review-candidates');
  const workspaceRoot = path.join(reviewRoot, verified.workspaceKey);
  await secureChildDirectory(reviewRoot);
  await secureChildDirectory(workspaceRoot);
  const destination = reviewCandidateDirectory(
    mirrorRoot,
    verified.workspaceKey,
    verified.revision,
  );
  const unsignedExport = {
    apiVersion: 'notty.dev/v1alpha1',
    kind: REVIEW_EXPORT_KIND,
    schemaVersion: 1,
    createdAt: verified.manifest.generatedAt,
    workspaceKey: verified.workspaceKey,
    revision: verified.revision,
    candidateManifestHash: sha256(candidate.manifestSource),
    targetContextHash: verified.targetContext.contentHash,
    files: Object.fromEntries(Object.entries(verified.sources).map(
      ([name, source]) => [name, {
        sha256: sha256(source),
        bytes: Buffer.byteLength(source),
      }],
    )),
  };
  const exportDocument = {
    ...unsignedExport,
    contentHash: sha256(stableJson(unsignedExport)),
  };
  const exportSource = `${JSON.stringify(exportDocument, null, 2)}\n`;
  const allSources = {
    ...verified.sources,
    'review-export.json': exportSource,
  };
  if (await matchingImmutableExport(destination, allSources)) {
    return {
      directory: destination,
      targetContext: path.join(destination, 'guard-ebpf-target-context.json'),
    };
  }
  try {
    await fs.lstat(destination);
    throw new Error(`immutable review candidate already differs: ${destination}`);
  } catch (error) {
    if (error.code !== 'ENOENT') throw error;
  }
  const temporary = path.join(
    workspaceRoot,
    `.${verified.revision}.${process.pid}.${crypto.randomUUID()}.tmp`,
  );
  await fs.mkdir(temporary, { mode: 0o700 });
  try {
    for (const [name, source] of Object.entries(allSources)) {
      await atomicWrite(path.join(temporary, name), source);
    }
    await syncDirectory(temporary);
    await fs.rename(temporary, destination);
    await syncDirectory(workspaceRoot);
  } catch (error) {
    await fs.rm(temporary, { recursive: true, force: true }).catch(() => {});
    throw error;
  }
  return {
    directory: destination,
    targetContext: path.join(destination, 'guard-ebpf-target-context.json'),
  };
}

export async function writeMirrorPayload(payload) {
  if (
    payload?.receipt?.kind !== MIRROR_KIND ||
    payload.receipt?.authoritative !== false ||
    typeof payload.workdir !== 'string' ||
    typeof payload.home !== 'string'
  ) {
    throw new TypeError('invalid network profile mirror payload');
  }
  const directory = mirrorDirectory(payload.workdir, payload.home);
  const home = path.resolve(payload.home);
  const relative = path.relative(home, directory);
  if (
    relative.startsWith('..') ||
    path.isAbsolute(relative) ||
    relative === ''
  ) {
    throw new Error('network profile mirror escaped the invoking user home');
  }
  await secureMirrorDirectory(directory);
  if (typeof payload.candidatePolicy === 'string') {
    await atomicWrite(
      path.join(directory, 'candidate-egress-policy.json'),
      payload.candidatePolicy,
    );
  }
  if (typeof payload.approvedPolicy === 'string') {
    await atomicWrite(
      path.join(directory, 'approved-egress-policy.json'),
      payload.approvedPolicy,
    );
  }
  if (payload.reviewCandidate != null) {
    await writeReviewCandidateExport(directory, payload.reviewCandidate);
  }
  await atomicWrite(
    path.join(directory, 'current.json'),
    `${JSON.stringify(payload.receipt, null, 2)}\n`,
  );
  await syncDirectory(directory);
  return directory;
}

export function writeInvokingUserMirror(payload, options = {}) {
  const invokingUser = options.invokingUser || resolveInvokingUser(options);
  const helperPath = fileURLToPath(import.meta.url);
  const result = (options.spawnSyncImpl || spawnSync)(
    process.execPath,
    [helperPath, '--write-payload'],
    {
      encoding: 'utf8',
      input: JSON.stringify({
        ...payload,
        home: invokingUser.home,
      }),
      timeout: 10_000,
      uid: invokingUser.uid,
      gid: invokingUser.gid,
      env: {
        HOME: invokingUser.home,
        PATH: process.env.PATH || '/usr/bin:/bin',
      },
      stdio: ['pipe', 'pipe', 'pipe'],
    },
  );
  if (result.status !== 0) {
    throw new Error(
      `network profile mirror update failed: ${
        result.error?.message || result.stderr || `status ${result.status}`
      }`,
    );
  }
  return String(result.stdout || '').trim();
}

export async function readCurrentUserMirror(workdir, options = {}) {
  const canonical = await fs.realpath(path.resolve(workdir));
  const selected = options.user || resolveInvokingUser(options);
  const directory = mirrorDirectory(canonical, selected.home);
  const receipt = JSON.parse(
    await fs.readFile(path.join(directory, 'current.json'), 'utf8'),
  );
  if (
    receipt?.kind !== MIRROR_KIND
    || receipt?.authoritative !== false
    || receipt?.workspace?.path !== canonical
  ) {
    throw new Error('network profile mirror does not match this workspace');
  }
  return { directory, receipt };
}

async function readStdin() {
  const chunks = [];
  for await (const chunk of process.stdin) {
    chunks.push(chunk);
  }
  return Buffer.concat(chunks).toString('utf8');
}

if (
  process.argv[1] &&
  path.resolve(process.argv[1]) === fileURLToPath(import.meta.url) &&
  process.argv[2] === '--write-payload'
) {
  readStdin()
    .then((raw) => writeMirrorPayload(JSON.parse(raw)))
    .then((directory) => process.stdout.write(`${directory}\n`))
    .catch((error) => {
      process.stderr.write(`${error.message}\n`);
      process.exitCode = 1;
    });
}
