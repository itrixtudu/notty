import crypto from 'node:crypto';
import fs from 'node:fs/promises';
import { constants as fsConstants } from 'node:fs';
import path from 'node:path';

import { AdapterController } from './adapters.js';
import {
  DEFAULT_BUILD_ADAPTER_CONFIG,
  DEFAULT_GUARD_STATE_DIR,
} from './constants.js';
import { DockerClient } from './docker-client.js';

const ACTIVE_STATUSES = new Set(['preparing', 'sensors-ready', 'building']);
const LEASE_STATUSES = new Set([...ACTIVE_STATUSES, 'quarantined']);
const TERMINAL_STATUSES = new Set(['complete', 'failed', 'aborted']);
const BUILD_MODES = new Set(['build-profile', 'build-net-learn']);
const CGROUP_FILES = Object.freeze([
  'cgroup.events',
  'cpu.pressure',
  'cpu.stat',
  'io.pressure',
  'io.stat',
  'memory.current',
  'memory.events',
  'memory.peak',
  'memory.pressure',
  'pids.current',
  'pids.events',
]);
const REQUIRED_CGROUP_METRICS = Object.freeze([
  'cpu.stat',
  'cpu.pressure',
  'io.stat',
  'io.pressure',
  'memory.current',
  'memory.events',
  'memory.pressure',
  'pids.current',
]);
const MAX_STATE_BYTES = 16 * 1024 * 1024;
const MAX_EVIDENCE_FILE_BYTES = 128 * 1024 * 1024;
const DEFAULT_MAX_RETAINED_RUNS = 32;
const DEFAULT_MAX_EXPORTED_RUNS = 8;
const DEFAULT_MAX_EXPORTED_AGE_MS = 24 * 60 * 60 * 1_000;

function retentionLimit(value, fallback, label, minimum = 0) {
  const selected = value == null ? fallback : Number(value);
  if (!Number.isSafeInteger(selected) || selected < minimum) {
    throw new TypeError(`${label} must be an integer of at least ${minimum}`);
  }
  return selected;
}

function portableBundleHash(value) {
  if (typeof value !== 'string' || !/^sha256:[a-f0-9]{64}$/i.test(value)) {
    throw new TypeError('portableBundleHash must be an exact sha256 digest');
  }
  return value.toLowerCase();
}

function exportAcknowledged(run) {
  return TERMINAL_STATUSES.has(run?.status)
    && run?.quarantineActive !== true
    && typeof run?.portableExport?.acknowledgedAt === 'string'
    && Number.isFinite(Date.parse(run.portableExport.acknowledgedAt))
    && /^sha256:[a-f0-9]{64}$/.test(run.portableExport.bundleHash || '');
}

function safeSegment(value, label) {
  if (
    typeof value !== 'string'
    || value.length < 1
    || value.length > 128
    || value === '.'
    || value === '..'
    || !/^[A-Za-z0-9_.-]+$/.test(value)
  ) {
    throw new TypeError(`${label} contains unsupported characters`);
  }
  return value;
}

function exactContainerId(value) {
  if (typeof value !== 'string' || !/^[a-f0-9]{64}$/i.test(value)) {
    throw new TypeError('builderContainerId must be an exact Docker container ID');
  }
  return value.toLowerCase();
}

function numericId(value, label) {
  const parsed = Number(value);
  if (!Number.isSafeInteger(parsed) || parsed < 0) {
    throw new TypeError(`${label} must be a non-negative integer`);
  }
  return parsed;
}

function processStartTimeFromStat(source) {
  const close = String(source).lastIndexOf(')');
  if (close < 0) {
    throw new Error('cannot parse process identity');
  }
  const fields = String(source).slice(close + 2).trim().split(/\s+/);
  if (!/^\d+$/.test(fields[19] || '')) {
    throw new Error('process start time is unavailable');
  }
  return fields[19];
}

async function processStartTime(pid) {
  return processStartTimeFromStat(
    await fs.readFile(`/proc/${numericId(pid, 'pid')}/stat`, 'utf8'),
  );
}

async function processOwner(pid) {
  return (await fs.stat(`/proc/${numericId(pid, 'pid')}`)).uid;
}

async function cgroupNamespaceIdentity(pid) {
  const identity = path.basename(
    await fs.readlink(`/proc/${numericId(pid, 'pid')}/ns/cgroup`),
  );
  const inode = identity.match(/\[(\d+)\]/)?.[1];
  if (!inode) {
    throw new Error('cgroup namespace identity is unavailable');
  }
  return inode;
}

async function directoryIdentity(directory) {
  const canonicalPath = await fs.realpath(path.resolve(directory));
  const stat = await fs.stat(canonicalPath, { bigint: true });
  if (!stat.isDirectory()) {
    throw new Error(`build context is not a directory: ${canonicalPath}`);
  }
  return {
    path: canonicalPath,
    dev: String(stat.dev),
    ino: String(stat.ino),
  };
}

function containerCgroupMembership(membership, containerId) {
  const selectedContainerId = exactContainerId(containerId);
  if (
    typeof membership !== 'string'
    || !membership.startsWith('/')
    || /[\0\r\n]/.test(membership)
  ) {
    throw new Error('builder cgroup-v2 membership is invalid');
  }
  const components = membership.split('/').filter(Boolean);
  if (components.some((component) => component === '.' || component === '..')) {
    throw new Error('builder cgroup-v2 membership is invalid');
  }
  const accepted = new Set([
    selectedContainerId,
    `docker-${selectedContainerId}.scope`,
  ]);
  let boundary = -1;
  for (let index = 0; index < components.length; index += 1) {
    if (!accepted.has(components[index])) continue;
    if (boundary >= 0) {
      throw new Error('builder cgroup contains duplicate Docker container boundaries');
    }
    boundary = index;
  }
  if (boundary < 0) {
    throw new Error('builder cgroup does not contain its exact Docker container boundary');
  }
  return `/${components.slice(0, boundary + 1).join('/')}`;
}

async function resolveCgroupTarget(pid, containerId) {
  const membership = await fs.readFile(`/proc/${numericId(pid, 'pid')}/cgroup`, 'utf8');
  const unified = membership
    .split(/\r?\n/)
    .map((line) => line.split(':'))
    .find((parts) => (
      parts.length === 3
      && parts[0] === '0'
      && parts[1] === ''
      && parts[2].startsWith('/')
    ));
  if (!unified) {
    throw new Error('builder does not have a cgroup-v2 membership');
  }
  const processMembership = unified[2];
  const targetMembership = containerCgroupMembership(
    processMembership,
    containerId,
  );
  const root = await fs.realpath('/sys/fs/cgroup');
  const selected = await fs.realpath(path.resolve(root, `.${targetMembership}`));
  const processPath = await fs.realpath(path.resolve(root, `.${processMembership}`));
  const relative = path.relative(root, selected);
  const processRelative = path.relative(selected, processPath);
  if (
    !relative
    || relative.startsWith('..')
    || path.isAbsolute(relative)
    || processRelative.startsWith('..')
    || path.isAbsolute(processRelative)
  ) {
    throw new Error('refusing the cgroup-v2 root or an escaped builder cgroup');
  }
  const stat = await fs.stat(selected, { bigint: true });
  const processStat = await fs.stat(processPath, { bigint: true });
  if (!stat.isDirectory() || !processStat.isDirectory()) {
    throw new Error('resolved builder cgroup is not a directory');
  }
  return {
    path: selected,
    id: String(stat.ino),
    membership: targetMembership,
    processPath,
    processId: String(processStat.ino),
    processMembership,
  };
}

async function secureDirectory(directory, mode = 0o700) {
  const resolved = path.resolve(directory);
  await fs.mkdir(resolved, { recursive: true, mode });
  if (await fs.realpath(resolved) !== resolved) {
    throw new Error(`build session path must not contain symbolic links: ${resolved}`);
  }
  const stat = await fs.lstat(resolved);
  const uid = typeof process.geteuid === 'function' ? process.geteuid() : null;
  if (!stat.isDirectory() || stat.isSymbolicLink()) {
    throw new Error(`build session path is not a real directory: ${resolved}`);
  }
  if (uid != null && stat.uid !== uid) {
    throw new Error(`build session path must be owned by uid ${uid}: ${resolved}`);
  }
  await fs.chmod(resolved, mode);
  return resolved;
}

async function atomicJson(destination, value) {
  const temporary = `${destination}.${process.pid}.${crypto.randomUUID()}.tmp`;
  let handle;
  try {
    handle = await fs.open(
      temporary,
      fsConstants.O_WRONLY
        | fsConstants.O_CREAT
        | fsConstants.O_EXCL
        | (fsConstants.O_NOFOLLOW || 0),
      0o600,
    );
    await handle.writeFile(`${JSON.stringify(value, null, 2)}\n`, 'utf8');
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

async function readJsonFile(filePath) {
  const handle = await fs.open(
    filePath,
    fsConstants.O_RDONLY | (fsConstants.O_NOFOLLOW || 0),
  );
  try {
    const stat = await handle.stat();
    const uid = typeof process.geteuid === 'function' ? process.geteuid() : null;
    if (
      !stat.isFile()
      || stat.nlink !== 1
      || stat.size > MAX_STATE_BYTES
      || (uid != null && stat.uid !== uid)
    ) {
      throw new Error(`invalid build session state file: ${filePath}`);
    }
    if ((stat.mode & 0o7777) !== 0o600) {
      throw new Error(`build session state file mode must be 600: ${filePath}`);
    }
    return JSON.parse(await handle.readFile('utf8'));
  } finally {
    await handle.close();
  }
}

class BuildSessionStateStore {
  constructor(root = DEFAULT_GUARD_STATE_DIR, options = {}) {
    this.root = path.resolve(root);
    this.runsDir = path.join(this.root, 'build-runs');
    this.evidenceDir = path.join(this.root, 'build-evidence');
    this.maximumRetainedRuns = retentionLimit(
      options.maximumRetainedRuns,
      DEFAULT_MAX_RETAINED_RUNS,
      'maximum retained build runs',
      1,
    );
    this.maximumExportedRuns = retentionLimit(
      options.maximumExportedRuns,
      DEFAULT_MAX_EXPORTED_RUNS,
      'maximum exported build runs',
    );
    this.maximumExportedAgeMs = retentionLimit(
      options.maximumExportedAgeMs,
      DEFAULT_MAX_EXPORTED_AGE_MS,
      'maximum exported build age',
    );
    this.now = options.now || (() => Date.now());
    this.gcTail = Promise.resolve();
    this.runTails = new Map();
  }

  async initialize() {
    await secureDirectory(this.root);
    await secureDirectory(this.runsDir);
    await secureDirectory(this.evidenceDir);
    await this.pruneRetainedRuns();
  }

  runPath(runId) {
    return path.join(this.runsDir, `${safeSegment(runId, 'runId')}.json`);
  }

  evidencePath(runId) {
    return path.join(this.evidenceDir, safeSegment(runId, 'runId'));
  }

  enqueueRun(runId, operation) {
    const selected = safeSegment(runId, 'runId');
    const previous = this.runTails.get(selected) || Promise.resolve();
    const current = previous.then(operation, operation);
    const settled = current.then(() => undefined, () => undefined);
    this.runTails.set(selected, settled);
    void settled.finally(() => {
      if (this.runTails.get(selected) === settled) {
        this.runTails.delete(selected);
      }
    });
    return current;
  }

  async writeRunDocument(run) {
    const now = new Date().toISOString();
    const document = {
      schemaVersion: 1,
      createdAt: run.createdAt || now,
      ...run,
      runId: safeSegment(run.runId, 'runId'),
      updatedAt: now,
    };
    await atomicJson(this.runPath(document.runId), document);
    return document;
  }

  writeRun(run) {
    const runId = safeSegment(run?.runId, 'runId');
    return this.enqueueRun(runId, () => this.writeRunDocument(run));
  }

  updateRun(runId, updater) {
    if (typeof updater !== 'function') {
      throw new TypeError('build session updater must be a function');
    }
    const selected = safeSegment(runId, 'runId');
    return this.enqueueRun(selected, async () => {
      const current = await this.readRun(selected);
      const next = await updater(current);
      if (next == null || next === current) return current;
      return this.writeRunDocument({ ...next, runId: selected });
    });
  }

  async readRun(runId) {
    const selected = safeSegment(runId, 'runId');
    const run = await readJsonFile(this.runPath(selected));
    if (run.runId !== selected) {
      throw new Error(`build session state identity does not match ${selected}`);
    }
    return run;
  }

  async listRuns() {
    const entries = await fs.readdir(this.runsDir);
    const runs = [];
    for (const entry of entries.sort()) {
      if (entry.endsWith('.json')) {
        runs.push(await this.readRun(entry.slice(0, -5)));
      }
    }
    return runs;
  }

  async assertCapacity(additionalRuns = 1) {
    const additional = retentionLimit(
      additionalRuns,
      1,
      'additional build runs',
    );
    await this.pruneRetainedRuns();
    const retained = (await this.listRuns()).length;
    if (retained + additional > this.maximumRetainedRuns) {
      const error = new Error(
        `build session retention is full (${retained}/${this.maximumRetainedRuns}); `
        + 'export retained terminal profiles before starting another build',
      );
      error.code = 'GUARD_BUILD_RETENTION_FULL';
      error.statusCode = 507;
      throw error;
    }
    return {
      retained,
      maximumRetainedRuns: this.maximumRetainedRuns,
      available: this.maximumRetainedRuns - retained,
    };
  }

  acknowledgePortableExport(runId, input = {}) {
    const selected = safeSegment(runId, 'runId');
    const bundleHash = portableBundleHash(input.portableBundleHash);
    return this.updateRun(selected, async (run) => {
      if (!TERMINAL_STATUSES.has(run.status) || run.quarantineActive === true) {
        const error = new Error(
          `build session cannot acknowledge export from status ${run.status}`,
        );
        error.statusCode = 409;
        throw error;
      }
      const expectedEvidenceDir = this.evidencePath(selected);
      const expectedManifest = path.join(
        expectedEvidenceDir,
        'build-evidence-manifest.json',
      );
      if (
        path.resolve(run.evidenceDir || '') !== expectedEvidenceDir
        || path.resolve(run.evidenceManifest || '') !== expectedManifest
      ) {
        throw new Error('build session evidence identity is invalid for export acknowledgement');
      }
      await readJsonFile(expectedManifest);
      if (run.portableExport) {
        if (!exportAcknowledged(run)) {
          throw new Error('build session has an invalid portable export acknowledgement');
        }
        if (run.portableExport.bundleHash === bundleHash) return run;
        const error = new Error('build session already acknowledges a different portable bundle');
        error.statusCode = 409;
        throw error;
      }
      return {
        ...run,
        portableExport: {
          acknowledgedAt: new Date(this.now()).toISOString(),
          bundleHash,
        },
      };
    });
  }

  async removeRunFiles(run) {
    const selected = safeSegment(run.runId, 'runId');
    const expectedEvidenceDir = this.evidencePath(selected);
    if (path.resolve(run.evidenceDir || '') !== expectedEvidenceDir) {
      throw new Error(`build session evidence identity does not match ${selected}`);
    }
    try {
      const stat = await fs.lstat(expectedEvidenceDir);
      const uid = typeof process.geteuid === 'function' ? process.geteuid() : null;
      if (
        !stat.isDirectory()
        || stat.isSymbolicLink()
        || (uid != null && stat.uid !== uid)
        || await fs.realpath(expectedEvidenceDir) !== expectedEvidenceDir
      ) {
        throw new Error(`refusing to prune untrusted build evidence: ${selected}`);
      }
      await fs.rm(expectedEvidenceDir, { recursive: true });
    } catch (error) {
      if (error.code !== 'ENOENT') throw error;
    }
    await fs.unlink(this.runPath(selected));
  }

  removeExportedRun(run) {
    const selected = safeSegment(run.runId, 'runId');
    return this.enqueueRun(selected, async () => {
      const current = await this.readRun(selected);
      if (!exportAcknowledged(current)) {
        return false;
      }
      await this.removeRunFiles(current);
      return true;
    });
  }

  discardAdmissionFailure(runId) {
    const selected = safeSegment(runId, 'runId');
    return this.enqueueRun(selected, async () => {
      const current = await this.readRun(selected);
      const cleanupContained = (current.detachResults || []).every(
        (entry) => !entry.cleanupCritical || entry.cleanupOk === true,
      );
      const hasCleanupProof = !(current.adapters || []).length
        || (current.detachResults || []).length > 0;
      if (
        current.admissionFailed !== true
        || !['failed', 'aborted'].includes(current.status)
        || current.quarantineActive === true
        || !cleanupContained
        || !hasCleanupProof
      ) {
        throw new Error(
          `refusing to discard unresolved build admission failure: ${selected}`,
        );
      }
      await this.removeRunFiles(current);
      return { ...current, discarded: true };
    });
  }

  async pruneRetainedRuns(options = {}) {
    const preserved = new Set(
      (options.preserveRunIds || []).map((runId) => safeSegment(runId, 'runId')),
    );
    const prune = async () => {
      const now = Number(this.now());
      if (!Number.isFinite(now)) {
        throw new Error('build retention clock returned an invalid time');
      }
      const eligible = (await this.listRuns())
        .filter(exportAcknowledged)
        .sort((left, right) => (
          Date.parse(left.portableExport.acknowledgedAt)
          - Date.parse(right.portableExport.acknowledgedAt)
          || String(left.runId).localeCompare(String(right.runId))
        ));
      let excess = Math.max(0, eligible.length - this.maximumExportedRuns);
      const prunedByCount = new Set();
      for (const run of eligible) {
        if (excess === 0) break;
        if (preserved.has(run.runId)) continue;
        prunedByCount.add(run.runId);
        excess -= 1;
      }
      const candidates = eligible.filter((run) => (
        !preserved.has(run.runId)
        && (
          now - Date.parse(run.portableExport.acknowledgedAt)
            >= this.maximumExportedAgeMs
          || prunedByCount.has(run.runId)
        )
      ));
      const pruned = [];
      for (const run of candidates) {
        if (await this.removeExportedRun(run)) pruned.push(run.runId);
      }
      return {
        pruned,
        retainedExported: eligible.length - pruned.length,
        maximumRetainedRuns: this.maximumRetainedRuns,
        maximumExportedRuns: this.maximumExportedRuns,
        maximumExportedAgeMs: this.maximumExportedAgeMs,
      };
    };
    const operation = this.gcTail.then(prune, prune);
    this.gcTail = operation.then(() => undefined, () => undefined);
    return operation;
  }
}

async function readCgroupSnapshot(cgroupPath) {
  const snapshot = {};
  for (const name of CGROUP_FILES) {
    try {
      snapshot[name] = await fs.readFile(path.join(cgroupPath, name), 'utf8');
    } catch (error) {
      if (error.code !== 'ENOENT' && error.code !== 'EACCES') {
        throw error;
      }
      snapshot[name] = null;
    }
  }
  return snapshot;
}

function assertCgroupSnapshotCoverage(snapshot, label) {
  const missing = REQUIRED_CGROUP_METRICS.filter((name) => (
    typeof snapshot?.[name] !== 'string'
    || (name !== 'io.stat' && !snapshot[name].trim())
  ));
  if (missing.length) {
    throw new Error(
      `${label} is missing required cgroup metrics: ${missing.join(', ')}`,
    );
  }
}

async function hashEvidenceFile(filePath, evidenceDir) {
  const resolved = path.resolve(filePath);
  const relative = path.relative(evidenceDir, resolved);
  if (!relative || relative.startsWith('..') || path.isAbsolute(relative)) {
    throw new Error('collector evidence escaped the build evidence directory');
  }
  const handle = await fs.open(
    resolved,
    fsConstants.O_RDONLY | (fsConstants.O_NOFOLLOW || 0),
  );
  try {
    const stat = await handle.stat();
    if (!stat.isFile() || stat.nlink !== 1 || stat.size > MAX_EVIDENCE_FILE_BYTES) {
      throw new Error(`invalid build evidence file: ${relative}`);
    }
    const digest = crypto.createHash('sha256');
    for await (const chunk of handle.createReadStream({ autoClose: false })) {
      digest.update(chunk);
    }
    return {
      path: relative,
      bytes: stat.size,
      sha256: `sha256:${digest.digest('hex')}`,
    };
  } finally {
    await handle.close();
  }
}

function statsRecord(record) {
  return record?.recordKind === 'stats'
    || record?.kind === 'stats'
    || record?.type === 'collector_stats'
    || record?.recordKind === 'final_stats';
}

function nestedValue(record, selector) {
  if (typeof selector !== 'string' || !/^[A-Za-z][A-Za-z0-9]*(?:\.[A-Za-z][A-Za-z0-9]*)*$/.test(selector)) {
    return undefined;
  }
  return selector.split('.').reduce((value, key) => value?.[key], record);
}

function finalRecordCovers(record, buildFinishedAt) {
  if (!record || typeof buildFinishedAt !== 'string') {
    return false;
  }
  const finishedMilliseconds = Date.parse(buildFinishedAt);
  if (!Number.isFinite(finishedMilliseconds)) {
    return false;
  }
  try {
    const observedNanoseconds = BigInt(record.timestampUnixNs);
    return observedNanoseconds >= BigInt(finishedMilliseconds) * 1_000_000n;
  } catch {
    return false;
  }
}

async function inspectJsonlCompletion(filePath, contract = null) {
  let source;
  try {
    source = await fs.readFile(filePath, 'utf8');
  } catch (error) {
    if (error.code === 'ENOENT') {
      return { complete: false, marker: 'missing-output', lostEvents: null };
    }
    throw error;
  }
  let final = null;
  let finalRecords = 0;
  let parseErrors = 0;
  let summaryRecordErrors = 0;
  let fileSummaryRecords = 0n;
  let fileOpenObservations = 0n;
  let flowSummaryRecords = 0n;
  const observedCgroupIds = new Set();
  for (const line of source.split(/\r?\n/).filter(Boolean)) {
    try {
      const record = JSON.parse(line);
      const expected = contract?.match;
      const matchesContract = expected
        && typeof expected === 'object'
        && !Array.isArray(expected)
        && Object.entries(expected).every(([key, value]) => record?.[key] === value);
      if (matchesContract || (!expected && statsRecord(record) && record.final === true)) {
        final = record;
        finalRecords += 1;
      }
      if (record?.recordKind === 'file-summary') {
        fileSummaryRecords += 1n;
        if (
          record.schemaVersion !== 1
          || record.metadataOnly !== true
          || record.aggregationKey !== 'resolved-path'
          || typeof record.path !== 'string'
          || !record.path.startsWith('/')
          || !/^(0|[1-9][0-9]*)$/.test(String(record.opens ?? ''))
          || !/^(0|[1-9][0-9]*)$/.test(String(record.firstObservedNs ?? ''))
          || !/^(0|[1-9][0-9]*)$/.test(String(record.lastObservedNs ?? ''))
          || !['read', 'write', 'execute', 'create'].every(
            (key) => /^(0|[1-9][0-9]*)$/.test(
              String(record.accessCounts?.[key] ?? ''),
            ),
          )
        ) {
          summaryRecordErrors += 1;
        } else {
          fileOpenObservations += BigInt(record.opens);
        }
      }
      if (record?.recordKind === 'flow-summary') {
        flowSummaryRecords += 1n;
        if (
          record.schemaVersion !== 1
          || record.metadataOnly !== true
          || !/^(0|[1-9][0-9]*)$/.test(String(record.firstObservedNs ?? ''))
          || !/^(0|[1-9][0-9]*)$/.test(String(record.lastObservedNs ?? ''))
          || !['ingress', 'egress'].includes(record.network?.direction)
          || !['ipv4', 'ipv6'].includes(record.network?.family)
          || !['tcp', 'udp', 'icmp', 'icmpv6'].includes(record.network?.protocol)
          || typeof record.network?.destinationAddress !== 'string'
          || !record.network.destinationAddress
          || record.accounting?.scope !== 'capture-flow-total'
          || !/^(0|[1-9][0-9]*)$/.test(String(record.accounting?.packets ?? ''))
          || !/^(0|[1-9][0-9]*)$/.test(String(record.accounting?.bytes ?? ''))
        ) {
          summaryRecordErrors += 1;
        }
      }
      if (record?.observedCgroupId != null) {
        observedCgroupIds.add(String(record.observedCgroupId));
      }
    } catch {
      parseErrors += 1;
    }
  }
  const fallbackLossFields = [
    final?.lostEvents,
    final?.lostSamples,
    final?.ringBufferLost,
    final?.mapUpdateFailures,
    final?.mapFull,
    final?.decoderErrors,
    final?.counters?.ringbufDrops,
    final?.counters?.syscallMapFull,
    final?.counters?.inflightMapFull,
    final?.counters?.configMissing,
    final?.counters?.ancestryLimit,
    final?.counters?.cgroupFilterErrors,
    final?.counters?.parseErrors,
    final?.counters?.flowMapFull,
  ];
  const configuredLossFields = Array.isArray(contract?.requireZero)
    ? contract.requireZero.map((selector) => nestedValue(final, selector))
    : [];
  const configuredDiagnosticFields = Array.isArray(contract?.diagnosticOnly)
    ? contract.diagnosticOnly.map((selector) => [selector, nestedValue(final, selector)])
    : [];
  const missingRequiredCounters = configuredLossFields.some(
    (value) => !Number.isFinite(Number(value)),
  );
  const missingDiagnosticCounters = configuredDiagnosticFields.some(
    ([, value]) => !Number.isFinite(Number(value)),
  );
  const lossFields = (configuredLossFields.length
    ? configuredLossFields
    : fallbackLossFields)
    .filter((value) => Number.isFinite(Number(value)));
  const lostEvents = lossFields.reduce((sum, value) => sum + Number(value), 0);
  const declaredFileSummaryRecords = final?.fileSummaryRecords;
  const declaredFileOpenObservations = final?.counters?.fileOpenObservations;
  const declaredFlowSummaryRecords = final?.flowSummaryRecords;
  const summaryCountsMatch = [
    [declaredFileSummaryRecords, fileSummaryRecords],
    [declaredFileOpenObservations, fileOpenObservations],
    [declaredFlowSummaryRecords, flowSummaryRecords],
  ].every(([declared, observed]) => (
    declared == null
      || (typeof declared === 'string'
        && /^(0|[1-9][0-9]*)$/.test(declared)
        && BigInt(declared) === observed)
  ));
  const targetCgroupId = final?.targetCgroupId == null
    ? null
    : String(final.targetCgroupId);
  return {
    complete:
      Boolean(final)
      && finalRecords === 1
      && parseErrors === 0
      && summaryRecordErrors === 0
      && summaryCountsMatch
      && !missingRequiredCounters
      && !missingDiagnosticCounters
      && lostEvents === 0,
    marker: finalRecords > 1
      ? 'multiple-final-stats'
      : final
        ? 'final-stats'
        : 'missing-final-stats',
    lostEvents,
    parseErrors,
    finalRecords,
    summaryRecordErrors,
    summaryCountsMatch,
    summaryRecords: {
      file: fileSummaryRecords.toString(),
      flow: flowSummaryRecords.toString(),
      fileOpenObservations: fileOpenObservations.toString(),
    },
    descendantObserved:
      targetCgroupId != null
      && [...observedCgroupIds].some((value) => value !== targetCgroupId),
    observedCgroupIds: [...observedCgroupIds].sort(),
    missingRequiredCounters,
    missingDiagnosticCounters,
    diagnosticCounters: Object.fromEntries(configuredDiagnosticFields),
    final,
  };
}

function identityError(message) {
  const error = new Error(message);
  error.code = 'GUARD_BUILD_IDENTITY_MISMATCH';
  error.statusCode = 409;
  return error;
}

function healthFailureSummary(entry) {
  const raw = String(entry.error || entry.detail || '').trim();
  if (!raw) return entry.name;

  let detail = raw.split(/\r?\n/, 1)[0];
  try {
    const record = JSON.parse(detail);
    if (typeof record?.message === 'string' && record.message.trim()) {
      detail = record.message.trim();
    }
  } catch {
    // Third-party health commands may report a plain-text first line.
  }
  detail = detail
    .replace(/[\r\n\t]+/g, ' ')
    .replace(/ {2,}/g, ' ')
    .trim();
  if (/[\x00-\x1f\x7f-\x9f]/.test(detail)) return entry.name;
  if (detail.length > 512) detail = `${detail.slice(0, 509)}...`;
  return detail ? `${entry.name} (${detail})` : entry.name;
}

export class BuildSessionService {
  constructor(options = {}) {
    this.docker = options.docker || new DockerClient(options.dockerOptions);
    this.store = options.buildSessionStore
      || new BuildSessionStateStore(options.stateDir, options.buildRetention);
    this.adapters = options.buildAdapters || new AdapterController({
      configPath: options.buildAdapterConfig || DEFAULT_BUILD_ADAPTER_CONFIG,
    });
    this.cgroupProvider = options.cgroupProvider || resolveCgroupTarget;
    this.cgroupNamespaceProvider = options.cgroupNamespaceProvider
      || cgroupNamespaceIdentity;
    this.processStartTimeProvider = options.processStartTimeProvider || processStartTime;
    this.processOwnerProvider = options.processOwnerProvider || processOwner;
    this.pending = new Set();
    this.admissionTail = Promise.resolve();
  }

  serializeAdmission(operation) {
    const current = this.admissionTail.then(operation, operation);
    this.admissionTail = current.then(() => undefined, () => undefined);
    return current;
  }

  async initialize() {
    await this.store.initialize();
    for (const run of await this.store.listRuns()) {
      if (LEASE_STATUSES.has(run.status)) {
        await this.abort(run.runId, {
          reason: run.status === 'quarantined'
            ? 'retry quarantined builder stop after daemon restart'
            : 'guard daemon restarted during build profiling',
        });
      }
    }
    await this.store.pruneRetainedRuns?.();
  }

  async inspectBuilder(request, baseline = null) {
    const containerId = exactContainerId(request.builderContainerId);
    const inspected = await this.docker.inspectContainer(containerId);
    if (String(inspected?.Id || '').toLowerCase() !== containerId) {
      throw identityError('Docker returned a different builder container identity');
    }
    if (inspected?.State?.Running !== true || !Number.isSafeInteger(inspected.State.Pid)) {
      throw identityError('BuildKit builder container is not running');
    }
    const expectedName = `/buildx_buildkit_${safeSegment(request.builderNode, 'builderNode')}`;
    if (inspected.Name !== expectedName) {
      throw identityError(`unexpected BuildKit container name: ${inspected.Name || 'missing'}`);
    }
    if (inspected.HostConfig?.Privileged !== true) {
      throw identityError('docker-container BuildKit worker is not privileged as expected');
    }
    if (inspected.HostConfig?.CgroupnsMode !== 'private') {
      throw identityError('docker-container BuildKit worker must use a private cgroup namespace');
    }
    if (request.builderImage) {
      const expectedDigest = String(request.builderImage).match(
        /@((?:sha256:)[a-f0-9]{64})$/i,
      )?.[1]?.toLowerCase();
      const configuredImage = String(inspected.Config?.Image || '');
      const configuredDigest = configuredImage.match(
        /@((?:sha256:)[a-f0-9]{64})$/i,
      )?.[1]?.toLowerCase();
      if (
        !expectedDigest
        || (request.builderImage !== configuredImage
          && expectedDigest !== configuredDigest)
      ) {
        throw identityError('BuildKit builder image does not match the requested pin');
      }
    }
    const initPid = inspected.State.Pid;
    let cgroupNamespace;
    let hostCgroupNamespace;
    try {
      [cgroupNamespace, hostCgroupNamespace] = await Promise.all([
        this.cgroupNamespaceProvider(initPid),
        this.cgroupNamespaceProvider(process.pid),
      ]);
    } catch {
      throw identityError('BuildKit cgroup namespace identity is unavailable');
    }
    if (!cgroupNamespace || cgroupNamespace === hostCgroupNamespace) {
      throw identityError('docker-container BuildKit worker joined the host cgroup namespace');
    }
    const cgroup = await this.cgroupProvider(initPid, containerId);
    if (
      !cgroup?.path
      || !cgroup?.id
      || !cgroup?.membership
      || !cgroup?.processPath
      || !cgroup?.processId
      || !cgroup?.processMembership
    ) {
      throw identityError('BuildKit cgroup target identity is incomplete');
    }
    const pidStartTime = await this.processStartTimeProvider(initPid);
    const identity = {
      containerId,
      containerName: inspected.Name.slice(1),
      builderName: safeSegment(request.builderName, 'builderName'),
      builderNode: request.builderNode,
      imageReference: inspected.Config?.Image || null,
      imageDigest: inspected.Image || null,
      initPid,
      pidStartTime,
      cgroupNamespace,
      cgroup,
    };
    if (baseline) {
      for (const [label, current, expected] of [
        ['container ID', identity.containerId, baseline.containerId],
        ['init PID', identity.initPid, baseline.initPid],
        ['PID start time', identity.pidStartTime, baseline.pidStartTime],
        ['cgroup namespace', identity.cgroupNamespace, baseline.cgroupNamespace],
        ['cgroup path', identity.cgroup.path, baseline.cgroup?.path],
        ['cgroup ID', identity.cgroup.id, baseline.cgroup?.id],
        ['init cgroup path', identity.cgroup.processPath, baseline.cgroup?.processPath],
        ['init cgroup ID', identity.cgroup.processId, baseline.cgroup?.processId],
        [
          'init cgroup membership',
          identity.cgroup.processMembership,
          baseline.cgroup?.processMembership,
        ],
      ]) {
        if (String(current) !== String(expected)) {
          throw identityError(`BuildKit builder ${label} changed during profiling`);
        }
      }
    }
    return identity;
  }

  async begin(request) {
    if (!BUILD_MODES.has(request?.mode)) {
      throw new TypeError('build mode must be build-profile or build-net-learn');
    }
    const depth = request.depth || 'balanced';
    if (!['balanced', 'policy', 'deep'].includes(depth)) {
      throw new TypeError('build collector depth must be balanced, policy, or deep');
    }
    const requestedContainerId = exactContainerId(request.builderContainerId);
    const runId = safeSegment(request.runId || crypto.randomUUID(), 'runId');
    if (this.pending.has(runId)) {
      const error = new Error(`build session ${runId} is already being prepared`);
      error.statusCode = 409;
      throw error;
    }
    this.pending.add(runId);
    try {
      const admission = await this.serializeAdmission(async () => {
        try {
          await this.store.readRun(runId);
          const error = new Error(`build session ${runId} already exists`);
          error.statusCode = 409;
          throw error;
        } catch (error) {
          if (error.code !== 'ENOENT') throw error;
        }
        await this.store.assertCapacity?.(1);
        const workspace = await directoryIdentity(request.workdir);
        if (
          request.workspaceDev != null
          && (String(request.workspaceDev) !== workspace.dev
            || String(request.workspaceIno) !== workspace.ino)
        ) {
          throw identityError('build context changed before collector admission');
        }
        const active = (await this.store.listRuns()).find((run) => (
          LEASE_STATUSES.has(run.status)
          && (run.builder?.containerId === requestedContainerId
            || run.builder?.builderName === request.builderName)
        ));
        if (active) {
          const error = new Error(`BuildKit builder is already profiled by ${active.runId}`);
          error.code = 'GUARD_BUILD_LEASE_CONFLICT';
          error.statusCode = 409;
          throw error;
        }
        const builder = await this.inspectBuilder(request);
        const client = {
          pid: numericId(request.clientPid, 'clientPid'),
          startTime: String(request.clientStartTime || ''),
          uid: numericId(request.clientUid, 'clientUid'),
          gid: numericId(request.clientGid, 'clientGid'),
        };
        if (!/^\d+$/.test(client.startTime)) {
          throw new TypeError('clientStartTime must be a procfs start-time value');
        }
        if (await this.processStartTimeProvider(client.pid) !== client.startTime) {
          throw identityError('build client process identity is not live');
        }
        if (await this.processOwnerProvider(client.pid) !== client.uid) {
          throw identityError('build client process owner does not match the request');
        }
        const evidenceDir = this.store.evidencePath(runId);
        const run = await this.store.writeRun({
          runId,
          mode: request.mode,
          pass: request.pass || 'single',
          depth,
          status: 'preparing',
          workspace,
          builder,
          client,
          evidenceDir,
          evidenceComplete: false,
        });
        await secureDirectory(evidenceDir);
        return { builder, client, evidenceDir, run, workspace };
      });
      const { builder, evidenceDir } = admission;
      let { run } = admission;
      const before = await readCgroupSnapshot(builder.cgroup.path);
      assertCgroupSnapshotCoverage(before, 'initial builder cgroup snapshot');
      await atomicJson(path.join(evidenceDir, 'cgroup-before.json'), before);
      const context = {
        runId,
        mode: request.mode,
        pass: run.pass,
        evidenceDir,
        containerId: builder.containerId,
        containerName: builder.containerName,
        imageDigest: builder.imageDigest || '',
        initPid: builder.initPid,
        cgroupPath: builder.cgroup.path,
        cgroupId: builder.cgroup.id,
        cgroupNamespace: builder.cgroupNamespace,
        mountNamespace: '',
        networkNamespace: '',
        depth,
      };
      const health = await this.adapters.health(request.mode, context);
      const failures = health.filter((entry) => entry.required && !entry.ok);
      if (failures.length) {
        throw new Error(
          `required build collectors are unhealthy: ${failures.map(healthFailureSummary).join(', ')}`,
        );
      }
      let adapters;
      try {
        adapters = await this.adapters.attach(request.mode, context, {
          onAttached: async (current) => {
            const updated = await this.store.updateRun(
              runId,
              (persisted) => ACTIVE_STATUSES.has(persisted.status)
                ? { ...persisted, adapters: current }
                : persisted,
            );
            if (ACTIVE_STATUSES.has(updated.status)) run = updated;
          },
        });
      } catch (error) {
        const attachedAdapters = Array.isArray(error.attachedAdapters)
          ? error.attachedAdapters
          : [];
        let cleanupError = null;
        let cleanup = [];
        if (attachedAdapters.length) {
          try {
            cleanup = await this.adapters.detach(
              { ...run, adapters: attachedAdapters },
              context,
            );
            if (cleanup.some((entry) => entry.cleanupCritical && !entry.cleanupOk)) {
              cleanupError = new Error('admission collector cleanup was incomplete');
            }
          } catch (detachError) {
            cleanupError = detachError;
          }
        }
        try {
          await this.store.writeRun({
            ...run,
            status: cleanupError ? 'quarantined' : 'failed',
            admissionFailed: true,
            quarantineActive: Boolean(cleanupError),
            quarantineError: cleanupError?.message || null,
            adapters: attachedAdapters,
            detachResults: cleanup,
            evidenceComplete: false,
            failure: error.message,
          });
        } catch {
          // In-process cleanup above does not depend on the state commit.
        }
        if (cleanupError) {
          throw new AggregateError(
            [error, cleanupError],
            'collector admission and cleanup failed',
          );
        }
        throw error;
      }
      run = await this.store.writeRun({
        ...run,
        status: 'sensors-ready',
        startedAt: new Date().toISOString(),
        adapterHealth: health,
        adapters,
      });
      return run;
    } catch (error) {
      try {
        let partial = await this.store.readRun(runId);
        if (
          partial.status === 'quarantined'
          || (partial.adapters?.length && partial.admissionFailed !== true)
        ) {
          if (partial.admissionFailed !== true) {
            partial = await this.store.writeRun({
              ...partial,
              admissionFailed: true,
            });
          }
          this.pending.delete(runId);
          const contained = await this.abort(runId, {
            reason: `admission failed: ${error.message}`,
          });
          if (
            contained.status === 'aborted'
            && contained.quarantineActive !== true
            && contained.discarded !== true
          ) {
            await this.store.discardAdmissionFailure(runId);
          }
        } else {
          if (partial.admissionFailed !== true) {
            partial = await this.store.writeRun({
              ...partial,
              status: 'failed',
              admissionFailed: true,
              evidenceComplete: false,
              failure: error.message,
            });
          }
          await this.store.discardAdmissionFailure(runId);
        }
      } catch {
        // Preserve the original admission failure.
      }
      throw error;
    } finally {
      this.pending.delete(runId);
    }
  }

  async finish(runId, result = {}) {
    const selected = safeSegment(runId, 'runId');
    if (this.pending.has(selected)) {
      const error = new Error(`build session ${selected} already has an active lifecycle action`);
      error.statusCode = 409;
      throw error;
    }
    this.pending.add(selected);
    try {
      let run = await this.store.readRun(selected);
      if (!ACTIVE_STATUSES.has(run.status)) {
        if (['complete', 'failed', 'aborted'].includes(run.status)) {
          let manifest = null;
          if (run.evidenceManifest) {
            try {
              manifest = await readJsonFile(run.evidenceManifest);
            } catch {
              // Preserve idempotent lifecycle state even if evidence is damaged.
            }
          }
          return manifest ? { ...run, manifest } : run;
        }
        throw new Error(`build session cannot finish from status ${run.status}`);
      }
      const buildExitCode = result.buildExitCode == null
        ? null
        : Number(result.buildExitCode);
      if (
        buildExitCode != null
        && (!Number.isSafeInteger(buildExitCode)
          || buildExitCode < 0
          || buildExitCode > 255)
      ) {
        throw new TypeError('buildExitCode must be an integer from 0 to 255');
      }
      const buildStartedMilliseconds = Date.parse(result.buildStartedAt || '');
      const buildFinishedMilliseconds = Date.parse(result.buildFinishedAt || '');
      const sensorReadyMilliseconds = Date.parse(run.startedAt || '');
      const buildWindowOk = buildExitCode != null
        && Number.isFinite(buildStartedMilliseconds)
        && Number.isFinite(buildFinishedMilliseconds)
        && Number.isFinite(sensorReadyMilliseconds)
        && buildStartedMilliseconds >= sensorReadyMilliseconds
        && buildFinishedMilliseconds >= buildStartedMilliseconds;
      let identityOk = true;
      let identityErrorMessage = null;
      try {
        await this.inspectBuilder({
          builderContainerId: run.builder.containerId,
          builderName: run.builder.builderName,
          builderNode: run.builder.builderNode,
          builderImage: run.builder.imageReference || run.builder.imageDigest,
        }, run.builder);
      } catch (error) {
        identityOk = false;
        identityErrorMessage = error.message;
      }
      const context = {
        runId: run.runId,
        mode: run.mode,
        pass: run.pass,
        evidenceDir: run.evidenceDir,
        containerId: run.builder.containerId,
        containerName: run.builder.containerName,
        imageDigest: run.builder.imageDigest || '',
        initPid: run.builder.initPid,
        cgroupPath: run.builder.cgroup.path,
        cgroupId: run.builder.cgroup.id,
        cgroupNamespace: run.builder.cgroupNamespace,
        mountNamespace: '',
        networkNamespace: '',
        depth: run.depth || 'balanced',
      };
      let runtimeHealth;
      try {
        runtimeHealth = await this.adapters.runtimeHealth(run, context);
      } catch (error) {
        runtimeHealth = [{
          name: 'adapter-controller',
          required: true,
          ok: false,
          error: error.message,
        }];
      }
      const runtimeHealthy = runtimeHealth.every(
        (entry) => !entry.required || entry.ok === true,
      );
      let detachResults;
      try {
        detachResults = await this.adapters.detach(run, context);
      } catch (error) {
        detachResults = [{
          name: 'adapter-controller',
          ok: false,
          cleanupCritical: true,
          cleanupOk: false,
          error: error.message,
        }];
      }
      try {
        const postDetach = await this.store.readRun(selected);
        if (ACTIVE_STATUSES.has(postDetach.status)) {
          run = {
            ...run,
            adapters: postDetach.adapters || run.adapters,
          };
        }
      } catch {
        // Detach results below still fail evidence closed if state refresh failed.
      }
      let after = null;
      try {
        after = await readCgroupSnapshot(run.builder.cgroup.path);
        assertCgroupSnapshotCoverage(after, 'final builder cgroup snapshot');
        await atomicJson(path.join(run.evidenceDir, 'cgroup-after.json'), after);
      } catch (error) {
        identityOk = false;
        identityErrorMessage ||= error.message;
      }
      const sources = [];
      for (const adapter of run.adapters || []) {
        const adapterRuntimeHealth = runtimeHealth.find(
          (entry) => entry.name === adapter.name,
        );
        const source = {
          name: adapter.name,
          required: adapter.evidenceRequired == null
            ? adapter.required !== false
            : adapter.evidenceRequired === true,
          complete: !adapter.error,
          error: adapter.error || null,
        };
        if (adapterRuntimeHealth?.ok !== true) {
          source.complete = false;
          source.error ||= adapterRuntimeHealth?.error
            || 'collector runtime health was not established';
        }
        const adapterDetachResults = detachResults.filter(
          (entry) => entry.name === adapter.name,
        );
        const adapterDetachFailures = adapterDetachResults
          .flatMap((entry) => entry.evidenceFailures || []);
        if (
          adapterDetachFailures.length
            || adapterDetachResults.some((entry) => (
              entry.ok !== true || entry.evidenceOk === false
            ))
        ) {
          source.complete = false;
          source.error ||= adapterDetachFailures[0]?.error
            || adapterDetachResults.find((entry) => entry.ok !== true)?.error
            || 'collector evidence failed during shutdown';
        }
        if (adapter.logPath) {
          try {
            source.file = await hashEvidenceFile(adapter.logPath, run.evidenceDir);
            const completion = await inspectJsonlCompletion(
              adapter.logPath,
              adapter.completion,
            );
            source.completion = completion;
            if (adapter.completion) {
              source.completion.coversBuildEnd = buildWindowOk
                && finalRecordCovers(
                  completion.final,
                  result.buildFinishedAt,
                );
            }
            const completionOk = completion.complete
              && (!adapter.completion || source.completion.coversBuildEnd);
            source.complete = source.complete && completionOk;
            if (!completionOk) {
              source.error ||= adapter.completion
                && source.completion.coversBuildEnd !== true
                ? 'collector final evidence did not cover build completion'
                : 'collector evidence did not complete cleanly';
            }
          } catch (error) {
            source.complete = false;
            source.error = error.message;
          }
        }
        if (adapter.diagnosticsPath) {
          try {
            source.diagnostics = await hashEvidenceFile(
              adapter.diagnosticsPath,
              run.evidenceDir,
            );
          } catch (error) {
            source.complete = false;
            source.error ||= error.message;
          }
        }
        sources.push(source);
      }
      for (const name of ['cgroup-before.json', 'cgroup-after.json']) {
        try {
          sources.push({
            name,
            required: true,
            complete: true,
            file: await hashEvidenceFile(path.join(run.evidenceDir, name), run.evidenceDir),
          });
        } catch (error) {
          sources.push({ name, required: true, complete: false, error: error.message });
        }
      }
      const cleanupOk = detachResults.every(
        (entry) => !entry.cleanupCritical || entry.cleanupOk === true,
      );
      const evidenceRequiredAdapters = new Set(
        (run.adapters || [])
          .filter((entry) => (
            entry.evidenceRequired == null
              ? entry.required !== false
              : entry.evidenceRequired === true
          ))
          .map((entry) => entry.name),
      );
      const shutdownEvidenceOk = detachResults.every(
        (entry) => !evidenceRequiredAdapters.has(entry.name)
          || (entry.ok === true && entry.evidenceOk !== false),
      );
      const evidenceComplete = identityOk
        && buildWindowOk
        && runtimeHealthy
        && cleanupOk
        && shutdownEvidenceOk
        && sources.every((source) => !source.required || source.complete);
      const buildSucceeded = buildExitCode === 0;
      const finishedAt = new Date().toISOString();
      const manifest = {
        apiVersion: 'notty.dev/v1alpha1',
        kind: 'NoshBuildEvidenceManifest',
        schemaVersion: 1,
        runId: run.runId,
        mode: run.mode,
        pass: run.pass,
        startedAt: run.startedAt,
        finishedAt,
        complete: evidenceComplete,
        build: {
          exitCode: buildExitCode,
          succeeded: buildSucceeded,
          startedAt: result.buildStartedAt || null,
          finishedAt: result.buildFinishedAt || null,
          metadata: result.metadata && typeof result.metadata === 'object'
            ? result.metadata
            : {},
          windowValid: buildWindowOk,
        },
        workspace: run.workspace,
        builder: run.builder,
        identity: { ok: identityOk, error: identityErrorMessage },
        cleanup: {
          ok: cleanupOk,
          evidenceOk: shutdownEvidenceOk,
          results: detachResults,
        },
        runtimeHealth: { ok: runtimeHealthy, results: runtimeHealth },
        sources,
        limitations: Array.isArray(result.limitations) ? result.limitations : [],
      };
      const manifestPath = path.join(run.evidenceDir, 'build-evidence-manifest.json');
      await atomicJson(manifestPath, manifest);
      run = await this.store.writeRun({
        ...run,
        status: !cleanupOk
          ? 'quarantined'
          : buildSucceeded && evidenceComplete
            ? 'complete'
            : 'failed',
        quarantineActive: !cleanupOk,
        quarantineError: cleanupOk
          ? null
          : 'one or more cleanup-critical collectors did not stop cleanly',
        finishedAt,
        buildExitCode,
        buildSucceeded,
        evidenceComplete,
        detachResults,
        runtimeHealth,
        identityError: identityErrorMessage,
        evidenceManifest: manifestPath,
        sources,
      });
      return { ...run, manifest };
    } finally {
      this.pending.delete(selected);
    }
  }

  async acknowledgeExport(runId, input = {}) {
    const selected = safeSegment(runId, 'runId');
    if (this.pending.has(selected)) {
      const error = new Error(
        `build session ${selected} already has an active lifecycle action`,
      );
      error.statusCode = 409;
      throw error;
    }
    this.pending.add(selected);
    try {
      const acknowledged = await this.store.acknowledgePortableExport(
        selected,
        input,
      );
      const retention = await this.store.pruneRetainedRuns({
        preserveRunIds: [selected],
      });
      return { ...acknowledged, retention };
    } finally {
      this.pending.delete(selected);
    }
  }

  async abort(runId, options = {}) {
    const run = await this.store.readRun(safeSegment(runId, 'runId'));
    if (!LEASE_STATUSES.has(run.status)) {
      return run;
    }
    let finished = run.status === 'quarantined'
      ? run
      : await this.finish(run.runId, {
          buildExitCode: null,
          limitations: [`aborted: ${options.reason || 'build client ended'}`],
        });
    let collectorContained = (finished.detachResults || []).every(
      (entry) => !entry.cleanupCritical || entry.cleanupOk === true,
    );
    if (finished.status === 'quarantined' && !collectorContained) {
      const context = {
        runId: finished.runId,
        mode: finished.mode,
        pass: finished.pass,
        evidenceDir: finished.evidenceDir,
        containerId: finished.builder.containerId,
        containerName: finished.builder.containerName,
        imageDigest: finished.builder.imageDigest || '',
        initPid: finished.builder.initPid,
        cgroupPath: finished.builder.cgroup.path,
        cgroupId: finished.builder.cgroup.id,
        cgroupNamespace: finished.builder.cgroupNamespace,
        mountNamespace: '',
        networkNamespace: '',
        depth: finished.depth || 'balanced',
      };
      let retryResults;
      try {
        retryResults = await this.adapters.detach(finished, context);
      } catch (error) {
        retryResults = [{
          name: 'adapter-controller',
          ok: false,
          cleanupCritical: true,
          cleanupOk: false,
          error: error.message,
        }];
      }
      collectorContained = retryResults.every(
        (entry) => !entry.cleanupCritical || entry.cleanupOk === true,
      );
      finished = await this.store.writeRun({
        ...finished,
        detachResults: retryResults,
        quarantineLastCollectorAttemptAt: new Date().toISOString(),
      });
    }
    let builderContained = true;
    let builderError = null;
    try {
      await this.docker.stopContainer(run.builder.containerId, 10);
    } catch (error) {
      if (error.statusCode !== 304 && error.statusCode !== 404) {
        builderContained = false;
        builderError = error.message;
      }
    }
    if (!collectorContained || !builderContained) {
      return this.store.writeRun({
        ...finished,
        status: 'quarantined',
        quarantineActive: true,
        quarantineError: [
          !collectorContained ? 'cleanup-critical collectors remain active' : null,
          !builderContained ? builderError : null,
        ].filter(Boolean).join('; '),
        builderContained,
        collectorContained,
        quarantineAttempts: Number(finished.quarantineAttempts || 0) + 1,
        quarantineLastAttemptAt: new Date().toISOString(),
      });
    }
    const aborted = await this.store.writeRun({
      ...finished,
      status: 'aborted',
      quarantineActive: false,
      quarantineError: null,
      builderContained: true,
      collectorContained: true,
    });
    if (aborted.admissionFailed === true) {
      return this.store.discardAdmissionFailure(aborted.runId);
    }
    return aborted;
  }

  async watchdogTick() {
    const results = [];
    for (const run of await this.store.listRuns()) {
      if (!LEASE_STATUSES.has(run.status) || this.pending.has(run.runId)) {
        continue;
      }
      if (run.status === 'quarantined') {
        results.push(await this.abort(run.runId, { reason: 'retry quarantined builder stop' }));
        continue;
      }
      let live = false;
      try {
        live = await this.processStartTimeProvider(run.client.pid) === run.client.startTime;
      } catch {
        live = false;
      }
      if (!live) {
        results.push(await this.abort(run.runId, { reason: 'build client process exited' }));
      }
    }
    return results;
  }

  async shutdown() {
    const results = [];
    for (const run of await this.store.listRuns()) {
      if (LEASE_STATUSES.has(run.status)) {
        results.push(await this.abort(run.runId, { reason: 'guard daemon is shutting down' }));
      }
    }
    return results;
  }

  listRuns() {
    return this.store.listRuns();
  }
}

export const buildSessionInternals = Object.freeze({
  BuildSessionStateStore,
  cgroupNamespaceIdentity,
  containerCgroupMembership,
  inspectJsonlCompletion,
  processStartTimeFromStat,
  processOwner,
  readCgroupSnapshot,
  assertCgroupSnapshotCoverage,
  resolveCgroupTarget,
});
