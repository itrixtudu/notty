import { workloadName } from './workload.js';
import crypto from 'node:crypto';
import fs from 'node:fs/promises';
import { constants as fsConstants } from 'node:fs';
import net from 'node:net';
import path from 'node:path';

import { stableStringify } from '../guard/stable.js';
import { DEFAULT_GUARD_STATE_DIR } from './constants.js';
import { normalizeEbpfCidr } from './enforcement-backend.js';

const API_VERSION = 'notty.dev/v1alpha1';
const PROFILE_FILE = 'egress-profile.json';
const POLICY_FILE = 'egress-policy.json';
const MANIFEST_FILE = 'manifest.json';
const APPROVAL_FILE = 'egress-approval.json';
const MAX_ARTIFACT_BYTES = 16 * 1024 * 1024;
const REGISTRY_LOCK_STALE_MS = 30_000;
const REGISTRY_LOCK_TIMEOUT_MS = 35_000;
const EGRESS_CONTRACT_VERSION = 1;
const EGRESS_SCOPE = 'egress-only';
const EGRESS_LIMITATIONS = Object.freeze([
  'ingress policy is not enforced',
  'Tetragon policy is not applied',
  'seccomp policy is not applied',
  'AppArmor policy is not applied',
  'stored launch settings are replay guidance, not an egress authorization boundary',
]);
const REQUIRED_EGRESS_LEARN_SOURCES = Object.freeze([
  'nosh-egress',
  'nosh-exec',
]);
const BUNDLE_FILES = Object.freeze([PROFILE_FILE, POLICY_FILE]);
const registryQueues = new Map();

function sha256(value) {
  const content = Buffer.isBuffer(value)
    ? value
    : Buffer.from(String(value), 'utf8');
  return `sha256:${crypto.createHash('sha256').update(content).digest('hex')}`;
}

function hashKey(value) {
  return crypto.createHash('sha256').update(value).digest('hex');
}

function serialized(value) {
  return `${stableStringify(value, 2)}\n`;
}

function jsonClone(value, label) {
  try {
    const source = stableStringify(value);
    if (source === undefined) {
      throw new TypeError(`${label} must be JSON serializable`);
    }
    return JSON.parse(source);
  } catch (error) {
    if (error instanceof TypeError && error.message.startsWith(label)) {
      throw error;
    }
    throw new TypeError(`${label} must be JSON serializable`, { cause: error });
  }
}

function safeSegment(value, label) {
  if (
    typeof value !== 'string'
    || value.length > 128
    || value === '.'
    || value === '..'
    || !/^[A-Za-z0-9_.-]+$/.test(value)
  ) {
    throw new TypeError(`${label} contains unsupported characters`);
  }
  return value;
}

function exactDigest(value, label = 'imageDigest') {
  if (!/^sha256:[a-f0-9]{64}$/.test(value || '')) {
    throw new TypeError(`${label} must be an exact sha256 digest`);
  }
  return value;
}

function exactHash(value, label) {
  if (!/^sha256:[a-f0-9]{64}$/.test(value || '')) {
    throw new Error(`${label} must be a sha256 hash`);
  }
  return value;
}

function isWithin(parent, candidate) {
  const relative = path.relative(parent, candidate);
  return relative === '' || (
    relative !== '..'
    && !relative.startsWith(`..${path.sep}`)
    && !path.isAbsolute(relative)
  );
}

function defaultTrustedUid(value) {
  return value == null ? 0 : Number(value);
}

function currentUid() {
  return typeof process.geteuid === 'function' ? process.geteuid() : null;
}

async function canonicalExistingPath(input, kind, label) {
  const resolved = path.resolve(input);
  const canonical = await fs.realpath(resolved);
  const stat = await fs.stat(canonical);
  if (
    (kind === 'directory' && !stat.isDirectory())
    || (kind === 'file' && !stat.isFile())
  ) {
    throw new Error(`${label} must be a ${kind}: ${resolved}`);
  }
  return canonical;
}

export async function canonicalWorkspace(workdir) {
  if (typeof workdir !== 'string' || !workdir.trim()) {
    throw new TypeError('workdir is required');
  }
  return canonicalExistingPath(workdir, 'directory', 'workspace');
}

async function canonicalWorkspaceBinding(workdir) {
  const canonicalPath = await canonicalWorkspace(workdir);
  const handle = await fs.open(
    canonicalPath,
    fsConstants.O_RDONLY
      | (fsConstants.O_DIRECTORY || 0)
      | (fsConstants.O_NOFOLLOW || 0),
  );
  try {
    const stat = await handle.stat({ bigint: true });
    if (!stat.isDirectory()) {
      throw new Error(`workspace must be a directory: ${canonicalPath}`);
    }
    const currentPath = await canonicalWorkspace(workdir);
    const currentStat = await fs.stat(currentPath, { bigint: true });
    if (
      currentPath !== canonicalPath
      || currentStat.dev !== stat.dev
      || currentStat.ino !== stat.ino
    ) {
      const error = new Error(
        'workspace identity changed while its egress profile was being bound',
      );
      error.code = 'GUARD_EGRESS_WORKSPACE_IDENTITY_CHANGED';
      throw error;
    }
    return {
      canonicalPath,
      dev: String(stat.dev),
      ino: String(stat.ino),
    };
  } finally {
    await handle.close();
  }
}

export async function workspaceKey(workdir) {
  return hashKey(await canonicalWorkspace(workdir));
}

function validDomainName(domain) {
  return domain.length <= 253
    && domain.includes('.')
    && domain.split('.').every(
      (label) =>
        label.length >= 1
        && label.length <= 63
        && /^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/.test(label),
    );
}

function normalizeDestination(value) {
  const destination = String(value || '').toLowerCase().trim();
  if (!destination) {
    throw new TypeError('egress destination is required');
  }
  const slash = destination.indexOf('/');
  const address = slash < 0 ? destination : destination.slice(0, slash);
  const prefix = slash < 0 ? null : destination.slice(slash + 1);
  const family = net.isIP(address);
  if (family) {
    const maximum = family === 4 ? 32 : 128;
    if (prefix === '') {
      throw new TypeError(`invalid CIDR prefix: ${destination}`);
    }
    const normalizedPrefix = prefix == null ? maximum : Number(prefix);
    if (
      !Number.isSafeInteger(normalizedPrefix)
      || normalizedPrefix < 0
      || normalizedPrefix > maximum
    ) {
      throw new TypeError(`invalid CIDR prefix: ${destination}`);
    }
    return normalizeEbpfCidr(`${address}/${normalizedPrefix}`);
  }
  const wildcard = destination.startsWith('*.');
  const domain = wildcard ? destination.slice(2) : destination;
  if (
    prefix != null
    || !validDomainName(domain)
  ) {
    throw new TypeError(`invalid egress destination: ${destination}`);
  }
  return wildcard ? `*.${domain}` : domain;
}

function normalizeIcmpField(value, label) {
  if (value == null || value === '') {
    return null;
  }
  const normalized = Number(value);
  if (!Number.isSafeInteger(normalized) || normalized < 0 || normalized > 255) {
    throw new TypeError(`${label} must be an integer from 0 to 255`);
  }
  return normalized;
}

function normalizeRule(input) {
  if (!input || typeof input !== 'object' || Array.isArray(input)) {
    throw new TypeError('egress rules must be objects');
  }
  const protocol = String(input.protocol || '').toLowerCase();
  if (!['tcp', 'udp', 'icmp', 'icmpv6'].includes(protocol)) {
    throw new TypeError(`unsupported egress protocol: ${input.protocol}`);
  }
  const destination = normalizeDestination(
    input.destination || input.fqdn || input.cidr,
  );
  const rule = { destination, protocol };
  if (protocol === 'tcp' || protocol === 'udp') {
    const values = Array.isArray(input.ports) ? input.ports : [input.ports];
    const ports = values
      .flatMap((value) => String(value == null ? '' : value).split(','))
      .filter(Boolean)
      .map(Number);
    if (
      !ports.length
      || ports.some(
        (port) => !Number.isSafeInteger(port) || port < 1 || port > 65535,
      )
    ) {
      throw new TypeError(`${protocol} egress rules require valid ports`);
    }
    rule.ports = [...new Set(ports)].sort((left, right) => left - right);
  } else if (
    input.ports != null
    && (!Array.isArray(input.ports) || input.ports.length)
  ) {
    throw new TypeError('ICMP egress rules must not contain ports');
  }
  const icmpType = normalizeIcmpField(input.icmpType, 'icmpType');
  const icmpCode = normalizeIcmpField(input.icmpCode, 'icmpCode');
  if ((icmpType != null || icmpCode != null) && !protocol.startsWith('icmp')) {
    throw new TypeError('icmpType and icmpCode require an ICMP protocol');
  }
  if (icmpType != null) {
    rule.icmpType = icmpType;
  }
  if (icmpCode != null) {
    rule.icmpCode = icmpCode;
  }
  if (input.observations != null) {
    if (!Array.isArray(input.observations)) {
      throw new TypeError('egress rule observations must be an array');
    }
    const observations = new Map();
    for (const inputObservation of input.observations) {
      if (
        !inputObservation
        || typeof inputObservation !== 'object'
        || Array.isArray(inputObservation)
      ) {
        throw new TypeError('egress rule observations must be objects');
      }
      const observation = jsonClone(inputObservation, 'egress rule observation');
      observations.set(stableStringify(observation), observation);
    }
    if (observations.size) {
      rule.observations = [...observations.entries()]
        .sort(([left], [right]) => left.localeCompare(right))
        .map(([, observation]) => observation);
    }
  }
  return rule;
}

export function normalizeEgressRules(rules) {
  if (!Array.isArray(rules)) {
    throw new TypeError('egress rules must be an array');
  }
  const byValue = new Map();
  for (const input of rules) {
    const rule = normalizeRule(input);
    const { observations = [], ...match } = rule;
    const key = stableStringify(match);
    const current = byValue.get(key);
    if (!current) {
      byValue.set(key, rule);
      continue;
    }
    const merged = new Map(
      [...(current.observations || []), ...observations]
        .map((observation) => [stableStringify(observation), observation]),
    );
    if (merged.size) {
      current.observations = [...merged.entries()]
        .sort(([left], [right]) => left.localeCompare(right))
        .map(([, observation]) => observation);
    }
  }
  return [...byValue.entries()]
    .sort(([left], [right]) => left === right ? 0 : left < right ? -1 : 1)
    .map(([, rule]) => rule);
}

function projectEnforceableRules(inputRules, inputUnresolved) {
  const unresolved = [...inputUnresolved];
  const rules = normalizeEgressRules(inputRules);
  const uniqueUnresolved = new Map(
    unresolved.map((entry) => [stableStringify(entry), entry]),
  );
  return {
    rules,
    unresolvedObservations: [...uniqueUnresolved.entries()]
      .sort(([left], [right]) => left.localeCompare(right))
      .map(([, entry]) => entry),
  };
}

async function statTrustedPath(target, options) {
  const stat = await fs.lstat(target);
  const expectedKind = options.kind;
  if (
    stat.isSymbolicLink()
    || (expectedKind === 'directory' && !stat.isDirectory())
    || (expectedKind === 'file' && (!stat.isFile() || stat.nlink !== 1))
  ) {
    throw new Error(`trusted egress path has wrong type: ${target}`);
  }
  if (stat.uid !== options.trustedUid || (stat.mode & 0o022) !== 0) {
    throw new Error(
      `trusted egress path must be owned by uid ${options.trustedUid} `
      + `and not group/other-writable: ${target}`,
    );
  }
  if (expectedKind === 'file' && stat.size > MAX_ARTIFACT_BYTES) {
    throw new Error(`trusted egress artifact exceeds size limit: ${target}`);
  }
  return stat;
}

async function assertTrustedDirectory(directory, options = {}) {
  const resolved = path.resolve(directory);
  const trustedRoot = path.resolve(options.trustedRoot || resolved);
  const trustedUid = defaultTrustedUid(options.trustedUid);
  const [canonical, canonicalRoot] = await Promise.all([
    fs.realpath(resolved),
    fs.realpath(trustedRoot),
  ]);
  if (canonical !== resolved || canonicalRoot !== trustedRoot) {
    throw new Error('trusted egress paths must not contain symbolic links');
  }
  if (!isWithin(canonicalRoot, canonical)) {
    throw new Error(`egress bundle must be beneath trusted root ${canonicalRoot}`);
  }
  const profilesDir = path.dirname(canonicalRoot);
  const trustBoundary = trustedUid === 0
    ? path.parse(canonicalRoot).root
    : path.basename(canonicalRoot) === 'net'
      && path.basename(profilesDir) === 'profiles'
      ? path.dirname(profilesDir)
      : canonicalRoot;
  if ((await fs.realpath(trustBoundary)) !== trustBoundary) {
    throw new Error('trusted egress paths must not contain symbolic links');
  }
  let cursor = trustBoundary;
  await statTrustedPath(cursor, { kind: 'directory', trustedUid });
  for (const segment of path.relative(trustBoundary, canonicalRoot).split(path.sep)) {
    if (!segment) {
      continue;
    }
    cursor = path.join(cursor, segment);
    await statTrustedPath(cursor, { kind: 'directory', trustedUid });
  }
  const relative = path.relative(canonicalRoot, canonical);
  for (const segment of relative ? relative.split(path.sep) : []) {
    cursor = path.join(cursor, segment);
    await statTrustedPath(cursor, { kind: 'directory', trustedUid });
  }
  return { directory: canonical, trustedRoot: canonicalRoot, trustedUid };
}

function normalizeTrustedNetRoot(input) {
  const resolved = path.resolve(input);
  return path.basename(resolved) === 'profiles'
    ? path.join(resolved, 'net')
    : resolved;
}

async function readTrustedFile(filePath, options = {}) {
  await statTrustedPath(filePath, {
    kind: 'file',
    trustedUid: defaultTrustedUid(options.trustedUid),
  });
  const handle = await fs.open(
    filePath,
    fsConstants.O_RDONLY | (fsConstants.O_NOFOLLOW || 0),
  );
  try {
    const stat = await handle.stat();
    if (
      !stat.isFile()
      || stat.nlink !== 1
      || stat.uid !== defaultTrustedUid(options.trustedUid)
      || (stat.mode & 0o022) !== 0
      || stat.size > MAX_ARTIFACT_BYTES
    ) {
      throw new Error(`trusted egress artifact changed during validation: ${filePath}`);
    }
    return handle.readFile();
  } finally {
    await handle.close();
  }
}

async function ensureDirectory(directory, trustedUid) {
  await fs.mkdir(directory, { recursive: true, mode: 0o700 });
  const resolved = path.resolve(directory);
  if ((await fs.realpath(resolved)) !== resolved) {
    throw new Error(`authoritative egress path must not contain symlinks: ${resolved}`);
  }
  const uid = currentUid();
  if (uid != null && uid !== trustedUid) {
    throw new Error(
      `authoritative egress state must be written by uid ${trustedUid}; current uid is ${uid}`,
    );
  }
  await statTrustedPath(resolved, { kind: 'directory', trustedUid });
  await fs.chmod(resolved, 0o700);
}

async function writeExclusive(filePath, content) {
  const handle = await fs.open(
    filePath,
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

function delay(milliseconds) {
  return new Promise((resolve) => setTimeout(resolve, milliseconds));
}

async function processStartIdentity(pid) {
  try {
    const source = await fs.readFile(`/proc/${pid}/stat`, 'utf8');
    const close = source.lastIndexOf(')');
    if (close < 0) {
      return null;
    }
    const fields = source.slice(close + 2).trim().split(/\s+/);
    return /^\d+$/.test(fields[19] || '') ? fields[19] : null;
  } catch (error) {
    if (error.code === 'ENOENT' || error.code === 'ESRCH') {
      return null;
    }
    throw error;
  }
}

async function lockOwnerIsActive(owner) {
  if (!Number.isSafeInteger(owner?.pid) || owner.pid <= 0) {
    return false;
  }
  try {
    process.kill(owner.pid, 0);
  } catch (error) {
    if (error.code === 'ESRCH') {
      return false;
    }
    if (error.code !== 'EPERM') {
      throw error;
    }
  }
  if (!owner.processStartIdentity) {
    return true;
  }
  return await processStartIdentity(owner.pid) === owner.processStartIdentity;
}

async function readRegistryLockOwner(lockDir, trustedUid) {
  try {
    const raw = await readTrustedFile(path.join(lockDir, 'owner.json'), {
      trustedUid,
    });
    return JSON.parse(raw.toString('utf8'));
  } catch (error) {
    if (error.code === 'ENOENT' || error instanceof SyntaxError) {
      return null;
    }
    throw error;
  }
}

async function tryReapRegistryLock(lockDir, trustedUid) {
  let stat;
  try {
    stat = await statTrustedPath(lockDir, {
      kind: 'directory',
      trustedUid,
    });
  } catch (error) {
    if (error.code === 'ENOENT') {
      return true;
    }
    throw error;
  }
  if (Date.now() - stat.mtimeMs < REGISTRY_LOCK_STALE_MS) {
    return false;
  }
  const owner = await readRegistryLockOwner(lockDir, trustedUid);
  if (owner && await lockOwnerIsActive(owner)) {
    return false;
  }
  try {
    await writeExclusive(
      path.join(lockDir, 'reap'),
      `${process.pid}:${crypto.randomUUID()}\n`,
    );
  } catch (error) {
    if (error.code === 'EEXIST' || error.code === 'ENOENT') {
      return false;
    }
    throw error;
  }
  const stale = `${lockDir}.stale.${process.pid}.${crypto.randomUUID()}`;
  try {
    await fs.rename(lockDir, stale);
  } catch (error) {
    if (error.code === 'ENOENT') {
      return false;
    }
    throw error;
  }
  await fs.rm(stale, { recursive: true, force: true });
  return true;
}

async function acquireRegistryLock(lockDir, trustedUid) {
  const deadline = Date.now() + REGISTRY_LOCK_TIMEOUT_MS;
  for (;;) {
    const token = crypto.randomUUID();
    try {
      await fs.mkdir(lockDir, { mode: 0o700 });
      const owner = {
        pid: process.pid,
        processStartIdentity: await processStartIdentity(process.pid),
        token,
        acquiredAt: new Date().toISOString(),
      };
      try {
        await writeExclusive(path.join(lockDir, 'owner.json'), serialized(owner));
        await syncDirectory(lockDir);
      } catch (error) {
        await fs.rm(lockDir, { recursive: true, force: true }).catch(() => {});
        throw error;
      }
      return { lockDir, token };
    } catch (error) {
      if (error.code !== 'EEXIST') {
        throw error;
      }
    }
    if (await tryReapRegistryLock(lockDir, trustedUid)) {
      continue;
    }
    if (Date.now() >= deadline) {
      throw new Error('authoritative egress workspace registry is busy');
    }
    await delay(25);
  }
}

async function releaseRegistryLock(lock, trustedUid) {
  const owner = await readRegistryLockOwner(lock.lockDir, trustedUid);
  if (owner?.token !== lock.token || owner?.pid !== process.pid) {
    throw new Error('authoritative egress workspace registry lock identity changed');
  }
  await fs.rm(lock.lockDir, { recursive: true });
  await syncDirectory(path.dirname(lock.lockDir));
}

async function readEvidenceFile(filePath, trustedUid) {
  const resolved = path.resolve(filePath);
  const canonical = await fs.realpath(resolved);
  if (canonical !== resolved) {
    throw new Error(`evidence path must not contain symbolic links: ${resolved}`);
  }
  return readTrustedFile(canonical, { trustedUid });
}

async function verifyEvidenceManifest(input) {
  const manifestPath = path.resolve(input.manifestPath);
  const expectedPath = path.join(
    path.resolve(input.stateDir),
    'evidence',
    safeSegment(input.runId, 'runId'),
    'evidence-manifest.json',
  );
  if (manifestPath !== expectedPath) {
    throw new Error(`learning evidence manifest must be ${expectedPath}`);
  }
  await assertTrustedDirectory(path.dirname(manifestPath), {
    trustedRoot: path.resolve(input.stateDir),
    trustedUid: input.trustedUid,
  });
  const raw = await readEvidenceFile(manifestPath, input.trustedUid);
  let manifest;
  try {
    manifest = JSON.parse(raw.toString('utf8'));
  } catch (error) {
    throw new Error('learning evidence manifest is not valid JSON', { cause: error });
  }
  if (
    manifest.schemaVersion !== 1
    || typeof manifest.generatedAt !== 'string'
    || Number.isNaN(Date.parse(manifest.generatedAt))
    || manifest.apiVersion !== API_VERSION
    || manifest.kind !== 'NoshSecurityEvidenceManifest'
    || manifest.mode !== 'egress-learn'
    || manifest.complete !== true
    || manifest.trainingEligible !== true
    || manifest.evidenceUse !== 'training'
  ) {
    throw new Error('candidate requires a complete learn evidence manifest');
  }
  if (manifest.runId !== input.runId) {
    throw new Error('learning evidence run ID does not match the candidate');
  }
  if (manifest.subject?.imageDigest !== input.imageDigest) {
    throw new Error('learning evidence image digest does not match the candidate');
  }
  if (
    !manifest.subject
    || typeof manifest.subject !== 'object'
    || Array.isArray(manifest.subject)
    || typeof manifest.subject.containerId !== 'string'
    || !manifest.subject.containerId.trim()
    || typeof manifest.subject.containerName !== 'string'
    || !manifest.subject.containerName.trim()
    || typeof manifest.subject.image !== 'string'
    || !manifest.subject.image.trim()
    || typeof manifest.subject.workspace !== 'string'
    || !manifest.subject.workspace.trim()
  ) {
    throw new Error('complete learning evidence requires a finalized subject');
  }
  if (
    input.workspace
    && manifest.subject?.workspace !== input.workspace
  ) {
    throw new Error('learning evidence workspace does not match the candidate');
  }
  const evidenceWorkspaceIdentity = manifest.subject?.workspaceIdentity;
  if (
    !evidenceWorkspaceIdentity
    || typeof evidenceWorkspaceIdentity !== 'object'
    || Array.isArray(evidenceWorkspaceIdentity)
    || !/^\d+$/.test(evidenceWorkspaceIdentity.dev || '')
    || !/^\d+$/.test(evidenceWorkspaceIdentity.ino || '')
    || Object.keys(evidenceWorkspaceIdentity).sort().join(',') !== 'dev,ino'
  ) {
    throw new Error(
      'complete learning evidence requires a bound workspace identity',
    );
  }
  if (
    input.workspaceIdentity
    && (
      evidenceWorkspaceIdentity.dev !== input.workspaceIdentity.dev
      || evidenceWorkspaceIdentity.ino !== input.workspaceIdentity.ino
    )
  ) {
    const error = new Error(
      'learning evidence workspace identity changed before candidate creation',
    );
    error.code = 'GUARD_EGRESS_WORKSPACE_IDENTITY_CHANGED';
    throw error;
  }
  if (
    typeof manifest.startedAt !== 'string'
    || Number.isNaN(Date.parse(manifest.startedAt))
    || typeof manifest.endedAt !== 'string'
    || Number.isNaN(Date.parse(manifest.endedAt))
    || Date.parse(manifest.endedAt) < Date.parse(manifest.startedAt)
    || Date.parse(manifest.generatedAt) < Date.parse(manifest.startedAt)
  ) {
    throw new Error('complete learning evidence requires valid finalized timestamps');
  }
  if (
    !Object.hasOwn(manifest, 'profileRevision')
    || !(
      manifest.profileRevision === null
      || (
        typeof manifest.profileRevision === 'string'
        && manifest.profileRevision.trim()
        && manifest.profileRevision.length <= 256
      )
    )
  ) {
    throw new Error('learning evidence profileRevision must be null or a non-empty string');
  }
  if (!Array.isArray(manifest.sources)) {
    throw new Error('learning evidence manifest requires source descriptors');
  }
  const required = manifest.sources.filter((source) => source?.required === true);
  const requiredNames = new Set(required.map((source) => source?.name));
  if (
    requiredNames.size !== REQUIRED_EGRESS_LEARN_SOURCES.length
    || REQUIRED_EGRESS_LEARN_SOURCES.some((name) => !requiredNames.has(name))
  ) {
    throw new Error(
      'learning evidence must require nosh-egress and nosh-exec sources',
    );
  }
  if (
    manifest.ebpfEgressEvaluation?.schemaVersion !== 2
    || manifest.ebpfEgressEvaluation?.backend !== 'nosh-egress'
    || manifest.ebpfEgressEvaluation?.backendAbi !== 'nosh-egress-v2'
    || manifest.ebpfEgressEvaluation?.eligible !== true
    || !Array.isArray(manifest.ebpfEgressEvaluation?.unresolved)
    || manifest.ebpfEgressEvaluation.unresolved.length !== 0
  ) {
    throw new Error(
      'candidate requires complete, resolved nosh-egress-v2 evidence',
    );
  }
  const sourceNames = new Set();
  const sourceHashes = {};
  const evidenceDirectory = path.dirname(manifestPath);
  for (const source of manifest.sources) {
    if (
      !source
      || typeof source !== 'object'
      || Array.isArray(source)
      || typeof source.name !== 'string'
      || !source.name
      || sourceNames.has(source.name)
    ) {
      throw new Error('learning evidence source names must be non-empty and unique');
    }
    sourceNames.add(source.name);
    if (
      typeof source.required !== 'boolean'
      || typeof source.present !== 'boolean'
      || typeof source.complete !== 'boolean'
      || !Number.isSafeInteger(source.bytes)
      || source.bytes < 0
      || !Number.isSafeInteger(source.records)
      || source.records < 0
      || (
        source.present
        && !['ndjson', 'ig-seccomp-advice'].includes(source.format)
      )
      || !Number.isFinite(source.lostEvents)
      || source.lostEvents < 0
      || !Number.isSafeInteger(source.parseErrors)
      || source.parseErrors < 0
      || typeof source.completionMarker !== 'string'
      || !source.completionMarker.trim()
    ) {
      throw new Error(`learning evidence source metadata is invalid: ${source.name}`);
    }
    if (source.required && source.lostEvents !== 0) {
      throw new Error(`required learning evidence reports lost events: ${source.name}`);
    }
    if (source.required && source.parseErrors !== 0) {
      throw new Error(`required learning evidence reports parse errors: ${source.name}`);
    }
    if (!source.present) {
      if (source.required) {
        throw new Error(`required learning evidence is absent: ${source.name}`);
      }
      continue;
    }
    if (
      typeof source.path !== 'string'
      || !path.isAbsolute(source.path)
      || !isWithin(evidenceDirectory, path.resolve(source.path))
    ) {
      throw new Error(`learning evidence source escaped its run directory: ${source.name}`);
    }
    if (source.required && source.complete !== true) {
      throw new Error(`required learning evidence is incomplete: ${source.name}`);
    }
    const expectedHash = exactHash(
      source.hash,
      `learning evidence source ${source.name}`,
    );
    const sourceRaw = await readEvidenceFile(source.path, input.trustedUid);
    const actualHash = sha256(sourceRaw);
    if (actualHash !== expectedHash || sourceRaw.length !== source.bytes) {
      throw new Error(`learning evidence source hash mismatch: ${source.name}`);
    }
    sourceHashes[source.name] = actualHash;
  }
  return {
    manifest,
    manifestPath,
    manifestHash: sha256(raw),
    sourceHashes: Object.fromEntries(Object.entries(sourceHashes).sort()),
  };
}

function candidateReference(verification) {
  return {
    runId: verification.profile.metadata.revision,
    revision: verification.profile.metadata.revision,
    directory: verification.directory,
    workspaceKey: verification.workspaceKey,
    manifestHash: verification.manifestHash,
    profileHash: verification.artifacts[PROFILE_FILE],
    policyHash: verification.artifacts[POLICY_FILE],
    rulesHash: verification.rulesHash,
    imageDigest: verification.imageDigest,
    evidenceManifestHash: verification.profile.spec.evidence.manifestHash,
    launchConfig: verification.profile.spec.launch.config,
    createdAt: verification.profile.metadata.createdAt,
  };
}

function validateCandidateDocuments(documents, directory) {
  const {
    profile,
    policy,
    manifest,
    artifacts,
    artifactBytes,
    manifestHash,
  } = documents;
  if (profile.apiVersion !== API_VERSION || profile.kind !== 'NoshEgressProfile') {
    throw new Error('egress profile has an unsupported apiVersion or kind');
  }
  if (policy.apiVersion !== API_VERSION || policy.kind !== 'NoshEgressPolicy') {
    throw new Error('egress policy has an unsupported apiVersion or kind');
  }
  if (
    manifest.apiVersion !== API_VERSION
    || manifest.kind !== 'NoshEgressBundleManifest'
  ) {
    throw new Error('egress bundle manifest has an unsupported apiVersion or kind');
  }
  if (
    profile.contractVersion !== EGRESS_CONTRACT_VERSION
    || profile.scope !== EGRESS_SCOPE
    || policy.contractVersion !== EGRESS_CONTRACT_VERSION
    || policy.scope !== EGRESS_SCOPE
    || manifest.contractVersion !== EGRESS_CONTRACT_VERSION
    || manifest.scope !== EGRESS_SCOPE
  ) {
    throw new Error('egress bundle is not an egress-only contract');
  }
  const workspace = profile.spec?.workspace;
  if (
    typeof workspace?.canonicalPath !== 'string'
    || !/^[a-f0-9]{64}$/.test(workspace?.key || '')
    || !/^\d+$/.test(workspace?.dev || '')
    || !/^\d+$/.test(workspace?.ino || '')
    || hashKey(workspace.canonicalPath) !== workspace.key
    || profile.metadata?.workspaceKey !== workspace.key
  ) {
    throw new Error('egress profile workspace binding is invalid');
  }
  exactDigest(profile.spec?.target?.imageDigest);
  exactHash(profile.spec?.evidence?.manifestHash, 'evidence manifest hash');
  if (
    typeof profile.metadata?.createdAt !== 'string'
    || Number.isNaN(Date.parse(profile.metadata.createdAt))
    || policy.metadata?.createdAt !== profile.metadata.createdAt
    || manifest.generatedAt !== profile.metadata.createdAt
  ) {
    throw new Error('egress bundle creation timestamp binding is invalid');
  }
  const revision = safeSegment(profile.metadata?.revision, 'profile revision');
  if (
    path.basename(directory) !== revision
    || path.basename(path.dirname(directory)) !== workspace.key
  ) {
    throw new Error('egress bundle path does not match its workspace and revision');
  }
  const normalizedRules = normalizeEgressRules(policy.spec?.egress);
  if (stableStringify(normalizedRules) !== stableStringify(policy.spec?.egress)) {
    throw new Error('egress policy rules are not normalized');
  }
  if (!Array.isArray(policy.spec?.unresolvedObservations)) {
    throw new Error('egress policy unresolved observations must be an array');
  }
  const projected = projectEnforceableRules(
    normalizedRules,
    policy.spec.unresolvedObservations,
  );
  if (
    stableStringify(projected.rules) !== stableStringify(normalizedRules)
    || stableStringify(projected.unresolvedObservations)
      !== stableStringify(policy.spec.unresolvedObservations)
  ) {
    throw new Error(
      'egress policy contains rules that are not enforceable by this runtime',
    );
  }
  const rulesHash = sha256(stableStringify(normalizedRules));
  if (
    profile.spec?.launch?.launchHash
      !== sha256(stableStringify(profile.spec?.launch?.config))
    || profile.spec?.launch?.configHash
      !== (profile.spec?.launch?.config?.configHash || null)
    || profile.spec?.launch?.config?.imageDigest
      !== profile.spec.target.imageDigest
  ) {
    throw new Error('egress profile launch configuration hash mismatch');
  }
  if (
    policy.spec?.defaultDeny?.egress !== true
    || policy.spec?.workspaceKey !== workspace.key
    || policy.spec?.targetImageDigest !== profile.spec.target.imageDigest
    || policy.metadata?.revision !== revision
    || policy.metadata?.workspaceKey !== workspace.key
    || policy.spec?.rulesHash !== rulesHash
  ) {
    throw new Error('egress policy scope or rules hash does not match its profile');
  }
  if (
    !Array.isArray(policy.spec?.platformContainment)
    || policy.spec.platformContainment.length !== 0
  ) {
    throw new Error('egress candidate must not claim platform containment authority');
  }
  const unsignedManifest = { ...manifest };
  delete unsignedManifest.contentHash;
  if (manifest.contentHash !== sha256(stableStringify(unsignedManifest))) {
    throw new Error('egress bundle manifest content hash mismatch');
  }
  const expectedFiles = Object.fromEntries(
    BUNDLE_FILES.map((filename) => [filename, artifacts[filename]]),
  );
  const recordedFiles = Object.fromEntries(
    Object.entries(manifest.files || {}).map(([filename, descriptor]) => [
      filename,
      descriptor?.hash,
    ]),
  );
  if (stableStringify(recordedFiles) !== stableStringify(expectedFiles)) {
    throw new Error('egress bundle manifest artifact hash mismatch');
  }
  for (const filename of BUNDLE_FILES) {
    if (
      !Number.isSafeInteger(manifest.files?.[filename]?.bytes)
      || manifest.files[filename].bytes !== artifactBytes[filename]
    ) {
      throw new Error(`egress bundle manifest artifact size mismatch: ${filename}`);
    }
  }
  if (
    manifest.workspaceKey !== workspace.key
    || manifest.workspace !== workspace.canonicalPath
    || manifest.runId !== revision
    || manifest.revision !== revision
    || manifest.imageDigest !== profile.spec.target.imageDigest
    || manifest.evidenceManifestHash !== profile.spec.evidence.manifestHash
    || manifest.rulesHash !== rulesHash
    || profile.spec?.artifacts?.policy?.fileName !== POLICY_FILE
    || profile.spec?.artifacts?.policy?.hash !== artifacts[POLICY_FILE]
    || profile.spec?.artifacts?.evidenceManifest?.hash
      !== profile.spec.evidence.manifestHash
  ) {
    throw new Error('egress bundle cross-artifact binding mismatch');
  }
  return {
    directory,
    revision,
    workspace: workspace.canonicalPath,
    workspaceIdentity: {
      dev: workspace.dev,
      ino: workspace.ino,
    },
    workspaceKey: workspace.key,
    imageDigest: profile.spec.target.imageDigest,
    rules: normalizedRules,
    rulesHash,
    policyPath: path.join(directory, POLICY_FILE),
    policyHash: artifacts[POLICY_FILE],
    artifacts,
    hashes: artifacts,
    manifestHash,
    profile,
    policy,
    manifest,
  };
}

export async function verifyEgressCandidateBundle(profileDir, options = {}) {
  const trustedRoot = normalizeTrustedNetRoot(
    options.trustedRoot
      || path.join(DEFAULT_GUARD_STATE_DIR, 'profiles', 'net'),
  );
  const trust = await assertTrustedDirectory(profileDir, {
    trustedRoot,
    trustedUid: options.trustedUid,
  });
  const buffers = {};
  for (const filename of [...BUNDLE_FILES, MANIFEST_FILE]) {
    buffers[filename] = await readTrustedFile(
      path.join(trust.directory, filename),
      { trustedUid: trust.trustedUid },
    );
  }
  const artifacts = Object.fromEntries(
    BUNDLE_FILES.map((filename) => [filename, sha256(buffers[filename])]),
  );
  const parse = (filename) => {
    try {
      const document = JSON.parse(buffers[filename].toString('utf8'));
      if (!buffers[filename].equals(Buffer.from(serialized(document)))) {
        throw new Error(`egress bundle artifact is not canonical: ${filename}`);
      }
      return document;
    } catch (error) {
      if (error.message.includes('is not canonical')) {
        throw error;
      }
      throw new Error(`egress bundle artifact is not valid JSON: ${filename}`, {
        cause: error,
      });
    }
  };
  const verification = validateCandidateDocuments({
    profile: parse(PROFILE_FILE),
    policy: parse(POLICY_FILE),
    manifest: parse(MANIFEST_FILE),
    artifacts,
    artifactBytes: Object.fromEntries(
      BUNDLE_FILES.map((filename) => [filename, buffers[filename].length]),
    ),
    manifestHash: sha256(buffers[MANIFEST_FILE]),
  }, trust.directory);
  if (options.workdir) {
    const currentWorkspace = await canonicalWorkspaceBinding(options.workdir);
    if (
      verification.workspace !== currentWorkspace.canonicalPath
      || verification.workspaceKey !== hashKey(currentWorkspace.canonicalPath)
    ) {
      throw new Error('egress bundle is approved for a different workspace');
    }
    if (
      verification.workspaceIdentity.dev !== currentWorkspace.dev
      || verification.workspaceIdentity.ino !== currentWorkspace.ino
    ) {
      const error = new Error(
        'egress bundle workspace identity changed since the candidate was created',
      );
      error.code = 'GUARD_EGRESS_WORKSPACE_IDENTITY_CHANGED';
      throw error;
    }
  }
  return { ok: true, ...verification };
}

function stateDirFromTrustedRoot(trustedRoot) {
  const resolved = path.resolve(trustedRoot);
  if (path.basename(resolved) === 'profiles') {
    return path.dirname(resolved);
  }
  if (
    path.basename(resolved) !== 'net'
    || path.basename(path.dirname(resolved)) !== 'profiles'
  ) {
    throw new Error(
      'trustedRoot must be a profiles or profiles/net directory when stateDir is omitted',
    );
  }
  return path.dirname(path.dirname(resolved));
}

export async function createEgressCandidateBundle(input) {
  if (!input || typeof input !== 'object') {
    throw new TypeError('candidate options are required');
  }
  const stateDir = path.resolve(input.stateDir || DEFAULT_GUARD_STATE_DIR);
  const trustedUid = defaultTrustedUid(input.trustedUid);
  const runId = safeSegment(input.runId, 'runId');
  const imageDigest = exactDigest(input.imageDigest);
  const workspaceBinding = await canonicalWorkspaceBinding(input.workdir);
  const workspace = workspaceBinding.canonicalPath;
  const key = hashKey(workspace);
  const evidence = await verifyEvidenceManifest({
    manifestPath: input.evidenceManifestPath,
    stateDir,
    runId,
    imageDigest,
    trustedUid,
    workspace,
    workspaceIdentity: {
      dev: workspaceBinding.dev,
      ino: workspaceBinding.ino,
    },
  });
  const suppliedUnresolved = jsonClone(
    input.unresolvedObservations || [],
    'unresolvedObservations',
  );
  if (!Array.isArray(suppliedUnresolved)) {
    throw new TypeError('unresolvedObservations must be an array');
  }
  const { rules, unresolvedObservations } = projectEnforceableRules(
    input.rules,
    suppliedUnresolved,
  );
  const launchConfig = jsonClone(input.launchConfig || {}, 'launchConfig');
  if (
    !launchConfig
    || typeof launchConfig !== 'object'
    || Array.isArray(launchConfig)
  ) {
    throw new TypeError('launchConfig must be an object');
  }
  launchConfig.workload = workloadName(launchConfig.workload);
  if (launchConfig.imageDigest !== imageDigest) {
    throw new Error('launch configuration image digest does not match the candidate');
  }
  const launchHash = sha256(stableStringify(launchConfig));
  const configHash = launchConfig.configHash || null;
  if (configHash) {
    exactHash(configHash, 'configHash');
  }
  const createdAt = input.createdAt || new Date().toISOString();
  if (typeof createdAt !== 'string' || Number.isNaN(Date.parse(createdAt))) {
    throw new TypeError('createdAt must be an ISO-compatible timestamp');
  }
  const rulesHash = sha256(stableStringify(rules));
  const policy = {
    apiVersion: API_VERSION,
    kind: 'NoshEgressPolicy',
    contractVersion: EGRESS_CONTRACT_VERSION,
    scope: EGRESS_SCOPE,
    metadata: {
      revision: runId,
      workspaceKey: key,
      createdAt,
    },
    spec: {
      workspaceKey: key,
      targetImageDigest: imageDigest,
      defaultDeny: { egress: true },
      egress: rules,
      platformContainment: [],
      unresolvedObservations,
      rulesHash,
    },
  };
  const policySource = serialized(policy);
  const policyHash = sha256(policySource);
  const profile = {
    apiVersion: API_VERSION,
    kind: 'NoshEgressProfile',
    contractVersion: EGRESS_CONTRACT_VERSION,
    scope: EGRESS_SCOPE,
    metadata: {
      revision: runId,
      workspaceKey: key,
      createdAt,
    },
    spec: {
      workspace: {
        canonicalPath: workspace,
        key,
        dev: workspaceBinding.dev,
        ino: workspaceBinding.ino,
      },
      target: {
        image: input.imageReference || evidence.manifest.subject?.image || null,
        imageDigest,
      },
      evidence: {
        runId,
        mode: evidence.manifest.mode,
        manifestPath: evidence.manifestPath,
        manifestHash: evidence.manifestHash,
        generatedAt: evidence.manifest.generatedAt || null,
        sourceHashes: evidence.sourceHashes,
      },
      launch: {
        config: launchConfig,
        launchHash,
        configHash,
      },
      artifacts: {
        policy: {
          fileName: POLICY_FILE,
          hash: policyHash,
        },
        evidenceManifest: {
          path: evidence.manifestPath,
          hash: evidence.manifestHash,
        },
      },
    },
  };
  const profileSource = serialized(profile);
  const profileHash = sha256(profileSource);
  const unsignedManifest = {
    apiVersion: API_VERSION,
    kind: 'NoshEgressBundleManifest',
    contractVersion: EGRESS_CONTRACT_VERSION,
    scope: EGRESS_SCOPE,
    generatedAt: createdAt,
    workspace,
    workspaceKey: key,
    runId,
    revision: runId,
    imageDigest,
    evidenceManifestHash: evidence.manifestHash,
    rulesHash,
    files: {
      [PROFILE_FILE]: {
        hash: profileHash,
        bytes: Buffer.byteLength(profileSource),
      },
      [POLICY_FILE]: {
        hash: policyHash,
        bytes: Buffer.byteLength(policySource),
      },
    },
  };
  const manifest = {
    ...unsignedManifest,
    contentHash: sha256(stableStringify(unsignedManifest)),
  };
  const manifestSource = serialized(manifest);
  const netRoot = path.join(stateDir, 'profiles', 'net');
  const workspaceDir = path.join(netRoot, key);
  const destination = path.join(workspaceDir, runId);
  await ensureDirectory(stateDir, trustedUid);
  await ensureDirectory(path.join(stateDir, 'profiles'), trustedUid);
  await ensureDirectory(netRoot, trustedUid);
  await ensureDirectory(workspaceDir, trustedUid);
  const temporary = path.join(
    workspaceDir,
    `.${runId}.${process.pid}.${crypto.randomUUID()}.tmp`,
  );
  await fs.mkdir(temporary, { mode: 0o700 });
  try {
    await writeExclusive(path.join(temporary, PROFILE_FILE), profileSource);
    await writeExclusive(path.join(temporary, POLICY_FILE), policySource);
    await writeExclusive(path.join(temporary, MANIFEST_FILE), manifestSource);
    await syncDirectory(temporary);
    try {
      await fs.rename(temporary, destination);
    } catch (error) {
      if (error.code === 'EEXIST' || error.code === 'ENOTEMPTY') {
        throw new Error(`egress candidate revision already exists: ${runId}`, {
          cause: error,
        });
      }
      throw error;
    }
    await syncDirectory(workspaceDir);
  } catch (error) {
    await fs.rm(temporary, { recursive: true, force: true }).catch(() => {});
    throw error;
  }
  const verification = await verifyEgressCandidateBundle(destination, {
    trustedRoot: netRoot,
    trustedUid,
    workdir: workspace,
  });
  const registry = new NetProfileRegistry({ stateDir, trustedUid, workload: launchConfig.workload });
  await registry.setLatestCandidate(workspace, candidateReference(verification));
  return { ...verification, registryRegistered: true };
}

function approvalReference(verification) {
  return {
    ...candidateReference(verification),
    revision: verification.approval.revision,
    approvalHash: verification.approval.contentHash,
    approvedAt: verification.approval.approvedAt,
    reviewer: verification.approval.reviewer,
  };
}

export async function approveEgressCandidateBundle(profileDir, options = {}) {
  const reviewer = typeof options.reviewer === 'string'
    ? options.reviewer.trim()
    : '';
  if (!reviewer) {
    throw new TypeError('egress approval requires an explicit reviewer');
  }
  const configuredTrustedRoot = path.resolve(
    options.trustedRoot
      || path.join(options.stateDir || DEFAULT_GUARD_STATE_DIR, 'profiles', 'net'),
  );
  const trustedRoot = normalizeTrustedNetRoot(configuredTrustedRoot);
  const trustedUid = defaultTrustedUid(options.trustedUid);
  if (currentUid() != null && currentUid() !== trustedUid) {
    throw new Error(
      `egress approval must be written by uid ${trustedUid}; current uid is ${currentUid()}`,
    );
  }
  const candidate = await verifyEgressCandidateBundle(profileDir, {
    trustedRoot,
    trustedUid,
    workdir: options.workdir,
  });
  await verifyEvidenceManifest({
    manifestPath: candidate.profile.spec.evidence.manifestPath,
    stateDir: options.stateDir || stateDirFromTrustedRoot(configuredTrustedRoot),
    runId: candidate.profile.spec.evidence.runId,
    imageDigest: candidate.imageDigest,
    trustedUid,
    workspace: candidate.workspace,
  }).then((evidence) => {
    if (
      evidence.manifestHash !== candidate.profile.spec.evidence.manifestHash
      || stableStringify(evidence.sourceHashes)
        !== stableStringify(candidate.profile.spec.evidence.sourceHashes)
    ) {
      throw new Error('approved learning evidence no longer matches the candidate');
    }
  });
  const revision = safeSegment(
    options.revision || candidate.revision,
    'approval revision',
  );
  const approvedAt = options.approvedAt || new Date().toISOString();
  if (typeof approvedAt !== 'string' || Number.isNaN(Date.parse(approvedAt))) {
    throw new TypeError('approvedAt must be an ISO-compatible timestamp');
  }
  const unsigned = {
    apiVersion: API_VERSION,
    kind: 'NoshEgressPolicyApproval',
    contractVersion: EGRESS_CONTRACT_VERSION,
    scope: EGRESS_SCOPE,
    approvedAt,
    reviewer,
    revision,
    candidateRevision: candidate.revision,
    candidate: candidate.directory,
    workspace: candidate.workspace,
    workspaceKey: candidate.workspaceKey,
    imageDigest: candidate.imageDigest,
    evidence: {
      runId: candidate.profile.spec.evidence.runId,
      manifestHash: candidate.profile.spec.evidence.manifestHash,
    },
    artifacts: {
      ...candidate.artifacts,
      [MANIFEST_FILE]: candidate.manifestHash,
    },
    rulesHash: candidate.rulesHash,
    rules: candidate.rules,
    defaultDeny: true,
    limitations: [...EGRESS_LIMITATIONS],
    policyHash: candidate.policyHash,
  };
  const approval = {
    ...unsigned,
    contentHash: sha256(stableStringify(unsigned)),
  };
  await writeExclusive(
    path.join(candidate.directory, APPROVAL_FILE),
    serialized(approval),
  );
  await syncDirectory(candidate.directory);
  const verification = await verifyEgressApprovalBundle(candidate.directory, {
    trustedRoot,
    trustedUid,
    workdir: options.workdir || candidate.workspace,
  });
  const stateDir = options.stateDir || stateDirFromTrustedRoot(configuredTrustedRoot);
  const registry = new NetProfileRegistry({ stateDir, trustedUid, workload: candidate.profile.spec.launch.config.workload });
  await registry.setApproved(candidate.workspace, approvalReference(verification));
  return {
    ...verification,
    registryRegistered: true,
    contentHash: verification.approval.contentHash,
    approvedAt: verification.approval.approvedAt,
    reviewer: verification.approval.reviewer,
  };
}

export async function verifyEgressApprovalBundle(profileDir, options = {}) {
  const candidate = await verifyEgressCandidateBundle(profileDir, options);
  const approvalRaw = await readTrustedFile(
    path.join(candidate.directory, APPROVAL_FILE),
    { trustedUid: options.trustedUid },
  );
  let approval;
  try {
    approval = JSON.parse(approvalRaw.toString('utf8'));
  } catch (error) {
    throw new Error('egress approval is not valid JSON', { cause: error });
  }
  if (!approvalRaw.equals(Buffer.from(serialized(approval)))) {
    throw new Error('egress approval is not canonical');
  }
  if (
    approval.apiVersion !== API_VERSION
    || approval.kind !== 'NoshEgressPolicyApproval'
    || approval.contractVersion !== EGRESS_CONTRACT_VERSION
    || approval.scope !== EGRESS_SCOPE
    || typeof approval.approvedAt !== 'string'
    || Number.isNaN(Date.parse(approval.approvedAt))
    || typeof approval.reviewer !== 'string'
    || !approval.reviewer.trim()
  ) {
    throw new Error('egress approval identity or reviewer is invalid');
  }
  const unsigned = { ...approval };
  delete unsigned.contentHash;
  if (approval.contentHash !== sha256(stableStringify(unsigned))) {
    throw new Error('egress approval content hash mismatch');
  }
  const expectedArtifacts = {
    ...candidate.artifacts,
    [MANIFEST_FILE]: candidate.manifestHash,
  };
  if (
    stableStringify(approval.artifacts) !== stableStringify(expectedArtifacts)
    || approval.candidate !== candidate.directory
    || approval.candidateRevision !== candidate.revision
    || approval.workspace !== candidate.workspace
    || approval.workspaceKey !== candidate.workspaceKey
    || approval.imageDigest !== candidate.imageDigest
    || approval.evidence?.runId !== candidate.profile.spec.evidence.runId
    || approval.evidence?.manifestHash
      !== candidate.profile.spec.evidence.manifestHash
    || approval.rulesHash !== candidate.rulesHash
    || stableStringify(approval.rules) !== stableStringify(candidate.rules)
    || approval.defaultDeny !== true
    || stableStringify(approval.limitations)
      !== stableStringify([...EGRESS_LIMITATIONS])
    || approval.policyHash !== candidate.policyHash
  ) {
    throw new Error('egress approval does not match the exact candidate artifacts');
  }
  safeSegment(approval.revision, 'approval revision');
  return {
    ...candidate,
    revision: approval.revision,
    approval,
    approvalHash: approval.contentHash,
    approvalFileHash: sha256(approvalRaw),
    contentHash: approval.contentHash,
    approvedAt: approval.approvedAt,
    reviewer: approval.reviewer,
  };
}

function emptyRegistry() {
  return {
    apiVersion: API_VERSION,
    kind: 'NoshEgressWorkspaceRegistry',
    schemaVersion: 1,
    updatedAt: null,
    workspaces: {},
  };
}

function validateRegistry(registry) {
  if (
    registry.apiVersion !== API_VERSION
    || registry.kind !== 'NoshEgressWorkspaceRegistry'
    || registry.schemaVersion !== 1
    || !registry.workspaces
    || typeof registry.workspaces !== 'object'
    || Array.isArray(registry.workspaces)
  ) {
    throw new Error('authoritative egress workspace registry is invalid');
  }
  for (const [key, value] of Object.entries(registry.workspaces)) {
    if (
      !/^[a-f0-9]{64}$/.test(key)
      || value?.workspaceKey !== key
      || hashKey(value?.canonicalPath || '') !== key
      || !Array.isArray(value.audits)
      || !Object.hasOwn(value, 'latestCandidate')
      || !Object.hasOwn(value, 'approved')
      || !Object.hasOwn(value, 'lastLaunch')
    ) {
      throw new Error(`authoritative egress workspace registry entry is invalid: ${key}`);
    }
    for (const [label, reference] of [
      ['candidate', value.latestCandidate],
      ['approval', value.approved],
    ]) {
      if (reference == null) {
        continue;
      }
      const normalized = normalizedReference(reference, label);
      if (
        normalized.workspaceKey !== key
        || stableStringify(normalized) !== stableStringify(reference)
      ) {
        throw new Error(
          `authoritative egress workspace ${label} reference is invalid: ${key}`,
        );
      }
      if (label === 'approval') {
        exactHash(normalized.approvalHash, 'approval content hash');
      }
    }
    const auditIds = new Set();
    for (const audit of value.audits) {
      safeSegment(audit?.runId, 'audit runId');
      if (auditIds.has(audit.runId)) {
        throw new Error(`authoritative egress workspace audit is duplicated: ${key}`);
      }
      auditIds.add(audit.runId);
      for (const field of [
        'wouldDenyCount',
        'dnsWouldDenyCount',
        'deniedCount',
      ]) {
        if (
          audit[field] != null
          && (!Number.isSafeInteger(audit[field]) || audit[field] < 0)
        ) {
          throw new Error(
            `authoritative egress workspace audit ${field} is invalid: ${key}`,
          );
        }
      }
    }
    if (
      value.lastLaunch != null
      && (
        typeof value.lastLaunch !== 'object'
        || Array.isArray(value.lastLaunch)
      )
    ) {
      throw new Error(`authoritative egress workspace last launch is invalid: ${key}`);
    }
    if (value.lastLaunch) {
      safeSegment(value.lastLaunch.runId, 'lastLaunch runId');
      if (
        value.lastLaunch.profileDirectory != null
        && !path.isAbsolute(value.lastLaunch.profileDirectory)
      ) {
        throw new Error(
          `authoritative egress workspace last launch profile directory is invalid: ${key}`,
        );
      }
      if (
        !['egress-learn', 'egress-audit', 'egress-enforce'].includes(
          value.lastLaunch.mode,
        )
      ) {
        throw new Error(`authoritative egress workspace last launch is invalid: ${key}`);
      }
    }
  }
  return registry;
}

async function atomicWrite(filePath, value, trustedUid) {
  const temporary = `${filePath}.${process.pid}.${crypto.randomUUID()}.tmp`;
  try {
    await writeExclusive(temporary, serialized(value));
    await fs.rename(temporary, filePath);
    await syncDirectory(path.dirname(filePath));
  } catch (error) {
    await fs.unlink(temporary).catch(() => {});
    throw error;
  }
  await statTrustedPath(filePath, { kind: 'file', trustedUid });
}

function queueRegistryMutation(registryPath, operation) {
  const previous = registryQueues.get(registryPath) || Promise.resolve();
  const current = previous.then(operation, operation);
  registryQueues.set(registryPath, current.catch(() => {}));
  return current;
}

function normalizedReference(reference, label) {
  if (!reference || typeof reference !== 'object' || Array.isArray(reference)) {
    throw new TypeError(`${label} reference is required`);
  }
  const copy = jsonClone(reference, `${label} reference`);
  copy.runId ||= copy.revision;
  safeSegment(copy.runId, `${label} runId`);
  safeSegment(copy.revision, `${label} revision`);
  exactDigest(copy.imageDigest, `${label} imageDigest`);
  exactHash(copy.policyHash, `${label} policyHash`);
  if (
    typeof copy.directory !== 'string'
    || !path.isAbsolute(copy.directory)
    || !/^[a-f0-9]{64}$/.test(copy.workspaceKey || '')
    || !copy.launchConfig
    || typeof copy.launchConfig !== 'object'
    || Array.isArray(copy.launchConfig)
  ) {
    throw new TypeError(`${label} reference scope is invalid`);
  }
  return copy;
}

function assertCandidateReference(reference, verification) {
  if (
    reference.revision !== verification.revision
    || path.resolve(reference.directory || '') !== verification.directory
    || reference.workspaceKey !== verification.workspaceKey
    || reference.imageDigest !== verification.imageDigest
    || reference.policyHash !== verification.policyHash
    || stableStringify(reference.launchConfig)
      !== stableStringify(verification.profile.spec.launch.config)
  ) {
    throw new Error('candidate registry reference does not match its bundle');
  }
}

function assertApprovalReference(reference, verification) {
  assertCandidateReference({
    ...reference,
    revision: verification.profile.metadata.revision,
  }, {
    ...verification,
    revision: verification.profile.metadata.revision,
  });
  if (
    reference.revision !== verification.revision
    || reference.approvalHash !== verification.approval.contentHash
  ) {
    throw new Error('approval registry reference does not match its bundle');
  }
}

export class NetProfileRegistry {
  constructor(options = {}) {
    if (typeof options === 'string') {
      options = { stateDir: options };
    }
    this.stateDir = path.resolve(options.stateDir || DEFAULT_GUARD_STATE_DIR);
    this.trustedUid = defaultTrustedUid(options.trustedUid);
    this.netRoot = path.join(this.stateDir, 'profiles', 'net');
    this.workload = workloadName(options.workload);
    const suffix = `-${this.workload}`;
    this.registryPath = path.join(this.netRoot, `workspaces${suffix}.json`);
    this.lockDir = path.join(this.netRoot, `.workspaces${suffix}.lock`);
  }

  async initialize() {
    await ensureDirectory(this.stateDir, this.trustedUid);
    await ensureDirectory(path.join(this.stateDir, 'profiles'), this.trustedUid);
    await ensureDirectory(this.netRoot, this.trustedUid);
  }

  async readRegistry() {
    await this.initialize();
    let raw;
    try {
      raw = await readTrustedFile(this.registryPath, {
        trustedUid: this.trustedUid,
      });
    } catch (error) {
      if (error.code === 'ENOENT') {
        return emptyRegistry();
      }
      throw error;
    }
    let registry;
    try {
      registry = JSON.parse(raw.toString('utf8'));
    } catch (error) {
      throw new Error('authoritative egress workspace registry is not valid JSON', {
        cause: error,
      });
    }
    if (!raw.equals(Buffer.from(serialized(registry)))) {
      throw new Error('authoritative egress workspace registry is not canonical');
    }
    return validateRegistry(registry);
  }

  async readWorkspace(workdir) {
    const workspace = await canonicalWorkspace(workdir);
    const key = hashKey(workspace);
    const registry = await this.readRegistry();
    const entry = registry.workspaces[key];
    if (entry && entry.canonicalPath !== workspace) {
      throw new Error('egress workspace hash collision detected');
    }
    return entry ? { ...jsonClone(entry, 'workspace registry entry'), workload: this.workload } : null;
  }

  async mutateWorkspace(workdir, mutate) {
    const workspace = await canonicalWorkspace(workdir);
    const key = hashKey(workspace);
    return queueRegistryMutation(this.registryPath, async () => {
      await this.initialize();
      const lock = await acquireRegistryLock(this.lockDir, this.trustedUid);
      let mutationError = null;
      try {
        const registry = await this.readRegistry();
        const existing = registry.workspaces[key];
        if (existing && existing.canonicalPath !== workspace) {
          throw new Error('egress workspace hash collision detected');
        }
        const now = new Date().toISOString();
        const entry = existing || {
          canonicalPath: workspace,
          workspaceKey: key,
          latestCandidate: null,
          approved: null,
          audits: [],
          lastLaunch: null,
          createdAt: now,
          updatedAt: now,
        };
        await mutate(entry);
        entry.updatedAt = now;
        registry.workspaces[key] = entry;
        registry.updatedAt = now;
        validateRegistry(registry);
        await atomicWrite(this.registryPath, registry, this.trustedUid);
        return jsonClone(entry, 'workspace registry entry');
      } catch (error) {
        mutationError = error;
        throw error;
      } finally {
        try {
          await releaseRegistryLock(lock, this.trustedUid);
        } catch (releaseError) {
          if (!mutationError) {
            throw releaseError;
          }
        }
      }
    });
  }

  async setLatestCandidate(workdir, reference) {
    const normalized = normalizedReference(reference, 'candidate');
    const verification = await verifyEgressCandidateBundle(normalized.directory, {
      trustedRoot: this.netRoot,
      trustedUid: this.trustedUid,
      workdir,
    });
    assertCandidateReference(normalized, verification);
    if (workloadName(verification.profile.spec.launch.config.workload) !== this.workload) throw new Error('candidate belongs to another workload');
    return this.mutateWorkspace(workdir, async (entry) => {
      entry.latestCandidate = normalized;
    });
  }

  async setApproved(workdir, reference) {
    const normalized = normalizedReference(reference, 'approval');
    exactHash(normalized.approvalHash, 'approval content hash');
    const verification = await verifyEgressApprovalBundle(normalized.directory, {
      trustedRoot: this.netRoot,
      trustedUid: this.trustedUid,
      workdir,
    });
    assertApprovalReference(normalized, verification);
    if (workloadName(verification.profile.spec.launch.config.workload) !== this.workload) throw new Error('approval belongs to another workload');
    return this.mutateWorkspace(workdir, async (entry) => {
      entry.approved = normalized;
    });
  }

  async recordAudit(workdir, audit) {
    const normalized = jsonClone(audit, 'audit');
    safeSegment(normalized?.runId, 'audit runId');
    return this.mutateWorkspace(workdir, async (entry) => {
      if (entry.audits.some((item) => item.runId === normalized.runId)) {
        throw new Error(`egress audit is already recorded: ${normalized.runId}`);
      }
      entry.audits.push(normalized);
    });
  }

  async recordLastLaunch(workdir, launch) {
    const normalized = jsonClone(launch, 'lastLaunch');
    if (!normalized || typeof normalized !== 'object' || Array.isArray(normalized)) {
      throw new TypeError('lastLaunch must be an object');
    }
    safeSegment(normalized.runId, 'lastLaunch runId');
    if (
      !['egress-learn', 'egress-audit', 'egress-enforce'].includes(
        normalized.mode,
      )
    ) {
      throw new TypeError('lastLaunch mode must be a scoped egress mode');
    }
    if (normalized.revision != null) {
      safeSegment(normalized.revision, 'lastLaunch revision');
    }
    if (
      normalized.profileDirectory != null
      && !path.isAbsolute(normalized.profileDirectory)
    ) {
      throw new TypeError('lastLaunch profileDirectory must be absolute');
    }
    return this.mutateWorkspace(workdir, async (entry) => {
      entry.lastLaunch = normalized;
    });
  }
}

export const EGRESS_BUNDLE_FILES = Object.freeze({
  profile: PROFILE_FILE,
  policy: POLICY_FILE,
  manifest: MANIFEST_FILE,
  approval: APPROVAL_FILE,
});

export const EGRESS_PROFILE_CONTRACT = Object.freeze({
  contractVersion: EGRESS_CONTRACT_VERSION,
  scope: EGRESS_SCOPE,
  limitations: EGRESS_LIMITATIONS,
});
