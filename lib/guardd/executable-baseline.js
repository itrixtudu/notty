import crypto from 'node:crypto';
import fs from 'node:fs/promises';
import { constants as fsConstants } from 'node:fs';
import path from 'node:path';

import { DEFAULT_GUARD_STATE_DIR } from './constants.js';
import { canonicalize, stableStringify } from '../guard/stable.js';

const API_VERSION = 'notty.dev/v1alpha1';
const MAX_BASELINE_BYTES = 4 * 1024 * 1024;
const SHA256 = /^sha256:[a-f0-9]{64}$/;
const WORKSPACE_KEY = /^[a-f0-9]{64}$/;

function sha256(value) {
  return `sha256:${crypto.createHash('sha256').update(value).digest('hex')}`;
}

function exactKeys(value, required) {
  return value
    && typeof value === 'object'
    && !Array.isArray(value)
    && Object.keys(value).sort().join(',') === [...required].sort().join(',');
}

function validDate(value) {
  return typeof value === 'string' && Number.isFinite(Date.parse(value));
}

function executableReference(value) {
  return typeof value === 'string'
    && value.length > 0
    && value.length <= 4096
    && !value.includes('\0');
}

function sortedUnique(values) {
  return [...new Set(values)].sort((left, right) => left.localeCompare(right));
}

function sortedUniqueStrings(values, predicate = () => true) {
  return Array.isArray(values)
    && values.every((value) => typeof value === 'string' && predicate(value))
    && JSON.stringify(values) === JSON.stringify(sortedUnique(values));
}

function decimalIdentity(value) {
  return /^(0|[1-9][0-9]{0,19})$/.test(value);
}

function validInventoryEntry(entry) {
  const required = [
    'path',
    'classification',
    'action',
    'count',
    'pids',
    'ppids',
    'uids',
    'gids',
    'cgroupIds',
    'comms',
  ];
  const optional = ['firstObservedAt', 'lastObservedAt'];
  const keys = Object.keys(entry || {});
  if (
    !entry
    || typeof entry !== 'object'
    || Array.isArray(entry)
    || required.some((key) => !Object.hasOwn(entry, key))
    || keys.some((key) => !required.includes(key) && !optional.includes(key))
    || !executableReference(entry.path)
    || !['expected', 'unknown'].includes(entry.classification)
    || entry.action !== (
      entry.classification === 'expected' ? 'allow' : 'allow-and-alert'
    )
    || !Number.isSafeInteger(entry.count)
    || entry.count < 1
    || !sortedUniqueStrings(entry.pids, decimalIdentity)
    || !sortedUniqueStrings(entry.ppids, decimalIdentity)
    || !sortedUniqueStrings(entry.uids, decimalIdentity)
    || !sortedUniqueStrings(entry.gids, decimalIdentity)
    || !sortedUniqueStrings(entry.cgroupIds, decimalIdentity)
    || !sortedUniqueStrings(
      entry.comms,
      (value) => value.length <= 64 && !value.includes('\0'),
    )
    || (
      Object.hasOwn(entry, 'firstObservedAt')
      && !validDate(entry.firstObservedAt)
    )
    || (
      Object.hasOwn(entry, 'lastObservedAt')
      && !validDate(entry.lastObservedAt)
    )
    || (
      entry.firstObservedAt
      && entry.lastObservedAt
      && Date.parse(entry.lastObservedAt) < Date.parse(entry.firstObservedAt)
    )
  ) {
    return false;
  }
  return true;
}

export function executableBaselineDigest(document) {
  return sha256(stableStringify(validateExecutableBaseline(document)));
}

export function validateExecutableBaseline(document, expected = {}) {
  const keys = [
    'schemaVersion',
    'apiVersion',
    'kind',
    'createdAt',
    'reviewedAt',
    'reviewer',
    'acknowledged',
    'workspaceKey',
    'imageDigest',
    'sourceInventoryDigest',
    'mode',
    'enforcing',
    'executables',
  ];
  if (
    !exactKeys(document, keys)
    || document.schemaVersion !== 1
    || document.apiVersion !== API_VERSION
    || document.kind !== 'NoshExecutableBaseline'
    || !validDate(document.createdAt)
    || !validDate(document.reviewedAt)
    || Date.parse(document.reviewedAt) < Date.parse(document.createdAt)
    || typeof document.reviewer !== 'string'
    || !document.reviewer.trim()
    || document.reviewer.length > 200
    || document.acknowledged !== true
    || !WORKSPACE_KEY.test(document.workspaceKey || '')
    || !SHA256.test(document.imageDigest || '')
    || !SHA256.test(document.sourceInventoryDigest || '')
    || document.mode !== 'observe-and-alert'
    || document.enforcing !== false
    || !Array.isArray(document.executables)
    || document.executables.length > 50_000
    || document.executables.some((entry) => !executableReference(entry))
    || JSON.stringify(document.executables)
      !== JSON.stringify(sortedUnique(document.executables))
  ) {
    throw new Error('invalid executable baseline');
  }
  if (
    expected.workspaceKey
    && document.workspaceKey !== expected.workspaceKey
  ) {
    throw new Error('executable baseline belongs to another workspace');
  }
  if (
    expected.imageDigest
    && document.imageDigest !== expected.imageDigest
  ) {
    throw new Error('executable baseline belongs to another image');
  }
  return canonicalize(document);
}

export function createExecutableBaselineDraft(inventory, options = {}) {
  const validated = validateExecutableInventory(inventory);
  return canonicalize({
    schemaVersion: 1,
    apiVersion: API_VERSION,
    kind: 'NoshExecutableBaseline',
    createdAt: options.createdAt || new Date().toISOString(),
    reviewedAt: options.reviewedAt || new Date().toISOString(),
    reviewer: String(options.reviewer || ''),
    acknowledged: options.acknowledged === true,
    workspaceKey: validated.workspaceKey,
    imageDigest: validated.imageDigest,
    sourceInventoryDigest: validated.inventoryDigest,
    mode: 'observe-and-alert',
    enforcing: false,
    executables: sortedUnique(validated.executables.map((entry) => entry.path)),
  });
}

function aggregateSet(values) {
  return sortedUnique(values.map((value) => String(value)));
}

function observedAt(value) {
  if (!/^\d+$/.test(String(value || ''))) return null;
  try {
    const milliseconds = BigInt(value) / 1_000_000n;
    if (milliseconds > BigInt(Number.MAX_SAFE_INTEGER)) return null;
    return new Date(Number(milliseconds)).toISOString();
  } catch {
    return null;
  }
}

export function projectExecutableInventory(records, input) {
  if (
    !input
    || typeof input !== 'object'
    || typeof input.runId !== 'string'
    || !input.runId
    || !WORKSPACE_KEY.test(input.workspaceKey || '')
    || !SHA256.test(input.imageDigest || '')
    || typeof input.complete !== 'boolean'
  ) {
    throw new Error('executable inventory requires a run, workspace, image, and completion state');
  }
  const baseline = input.baseline == null
    ? null
    : validateExecutableBaseline(input.baseline, input);
  const expected = new Set(baseline?.executables || []);
  const aggregates = new Map();
  for (const record of records || []) {
    if (
      record?.recordKind !== 'event'
      || record?.eventKind !== 'process-exec'
      || !executableReference(record.executable)
    ) {
      continue;
    }
    const current = aggregates.get(record.executable) || {
      path: record.executable,
      count: 0,
      timestamps: [],
      pids: [],
      ppids: [],
      uids: [],
      gids: [],
      cgroupIds: [],
      comms: [],
    };
    current.count += 1;
    if (record.timestampNs) current.timestamps.push(record.timestampNs);
    if (record.process?.pid != null) current.pids.push(record.process.pid);
    if (record.process?.ppid != null) current.ppids.push(record.process.ppid);
    if (record.process?.uid != null) current.uids.push(record.process.uid);
    if (record.process?.gid != null) current.gids.push(record.process.gid);
    if (record.observedCgroupId) current.cgroupIds.push(record.observedCgroupId);
    if (record.process?.comm) current.comms.push(record.process.comm);
    aggregates.set(record.executable, current);
  }
  const executables = [...aggregates.values()]
    .sort((left, right) => left.path.localeCompare(right.path))
    .map((entry) => {
      const timestamps = entry.timestamps
        .filter((value) => /^\d+$/.test(String(value)))
        .map((value) => BigInt(value))
        .sort((left, right) => left < right ? -1 : left > right ? 1 : 0);
      const first = timestamps.length ? observedAt(timestamps[0]) : null;
      const last = timestamps.length ? observedAt(timestamps.at(-1)) : null;
      return canonicalize({
        path: entry.path,
        classification: expected.has(entry.path) ? 'expected' : 'unknown',
        action: expected.has(entry.path) ? 'allow' : 'allow-and-alert',
        count: entry.count,
        ...(first ? { firstObservedAt: first } : {}),
        ...(last ? { lastObservedAt: last } : {}),
        pids: aggregateSet(entry.pids),
        ppids: aggregateSet(entry.ppids),
        uids: aggregateSet(entry.uids),
        gids: aggregateSet(entry.gids),
        cgroupIds: aggregateSet(entry.cgroupIds),
        comms: aggregateSet(entry.comms),
      });
    });
  const body = canonicalize({
    schemaVersion: 1,
    apiVersion: API_VERSION,
    kind: 'NoshExecutableInventory',
    generatedAt: input.generatedAt || new Date().toISOString(),
    runId: input.runId,
    workspaceKey: input.workspaceKey,
    imageDigest: input.imageDigest,
    complete: input.complete,
    policyUse: 'observation-only',
    enforcing: false,
    argumentsRecorded: false,
    unknownAction: 'allow-and-alert',
    baseline: baseline ? {
      digest: executableBaselineDigest(baseline),
      sourceInventoryDigest: baseline.sourceInventoryDigest,
      reviewedAt: baseline.reviewedAt,
      reviewer: baseline.reviewer,
    } : null,
    eventCount: executables.reduce((sum, entry) => sum + entry.count, 0),
    expectedCount: executables.filter((entry) => entry.classification === 'expected').length,
    unknownCount: executables.filter((entry) => entry.classification === 'unknown').length,
    executables,
  });
  return Object.freeze({
    ...body,
    inventoryDigest: sha256(stableStringify(body)),
  });
}

export function validateExecutableInventory(document) {
  const keys = [
    'schemaVersion',
    'apiVersion',
    'kind',
    'generatedAt',
    'runId',
    'workspaceKey',
    'imageDigest',
    'complete',
    'policyUse',
    'enforcing',
    'argumentsRecorded',
    'unknownAction',
    'baseline',
    'eventCount',
    'expectedCount',
    'unknownCount',
    'executables',
    'inventoryDigest',
  ];
  if (
    !exactKeys(document, keys)
    || document.schemaVersion !== 1
    || document.apiVersion !== API_VERSION
    || document.kind !== 'NoshExecutableInventory'
    || !validDate(document.generatedAt)
    || typeof document.runId !== 'string'
    || !document.runId
    || !WORKSPACE_KEY.test(document.workspaceKey || '')
    || !SHA256.test(document.imageDigest || '')
    || !SHA256.test(document.inventoryDigest || '')
    || typeof document.complete !== 'boolean'
    || document.policyUse !== 'observation-only'
    || document.enforcing !== false
    || document.argumentsRecorded !== false
    || document.unknownAction !== 'allow-and-alert'
    || !Array.isArray(document.executables)
    || document.executables.length > 50_000
    || !Number.isSafeInteger(document.eventCount)
    || document.eventCount < 0
    || !Number.isSafeInteger(document.expectedCount)
    || document.expectedCount < 0
    || !Number.isSafeInteger(document.unknownCount)
    || document.unknownCount < 0
    || (
      document.baseline !== null
      && (
        !exactKeys(document.baseline, [
          'digest',
          'sourceInventoryDigest',
          'reviewedAt',
          'reviewer',
        ])
        || !SHA256.test(document.baseline.digest || '')
        || !SHA256.test(document.baseline.sourceInventoryDigest || '')
        || !validDate(document.baseline.reviewedAt)
        || typeof document.baseline.reviewer !== 'string'
        || !document.baseline.reviewer.trim()
        || document.baseline.reviewer.length > 200
      )
    )
  ) {
    throw new Error('invalid executable inventory');
  }
  const { inventoryDigest, ...body } = document;
  if (inventoryDigest !== sha256(stableStringify(canonicalize(body)))) {
    throw new Error('executable inventory digest does not match its contents');
  }
  if (
    document.executables.some((entry) => !validInventoryEntry(entry))
    || JSON.stringify(document.executables.map((entry) => entry.path))
      !== JSON.stringify(sortedUnique(document.executables.map((entry) => entry.path)))
    || document.eventCount
      !== document.executables.reduce((sum, entry) => sum + entry.count, 0)
    || document.expectedCount
      !== document.executables.filter(
        (entry) => entry.classification === 'expected',
      ).length
    || document.unknownCount
      !== document.executables.filter(
        (entry) => entry.classification === 'unknown',
      ).length
    || document.expectedCount + document.unknownCount
      !== document.executables.length
  ) {
    throw new Error('executable inventory counts or entries are invalid');
  }
  return canonicalize(document);
}

async function readTrustedBaseline(filePath, trustedUid, expected) {
  const lstat = await fs.lstat(filePath);
  if (
    !lstat.isFile()
    || lstat.isSymbolicLink()
    || lstat.nlink !== 1
    || lstat.uid !== trustedUid
    || (lstat.mode & 0o777) !== 0o600
    || lstat.size > MAX_BASELINE_BYTES
  ) {
    throw new Error('active executable baseline is not a trusted regular file');
  }
  const handle = await fs.open(
    filePath,
    fsConstants.O_RDONLY | (fsConstants.O_NOFOLLOW || 0),
  );
  try {
    const stat = await handle.stat();
    if (
      !stat.isFile()
      || stat.dev !== lstat.dev
      || stat.ino !== lstat.ino
      || stat.size !== lstat.size
    ) {
      throw new Error('active executable baseline changed while opening');
    }
    const source = await handle.readFile();
    return {
      document: validateExecutableBaseline(JSON.parse(source), expected),
      digest: sha256(source),
      source,
    };
  } finally {
    await handle.close();
  }
}

export class ExecutableBaselineStore {
  constructor(options = {}) {
    this.root = path.join(
      path.resolve(options.stateDir || DEFAULT_GUARD_STATE_DIR),
      'executable-baselines',
    );
    this.trustedUid = options.trustedUid ?? (
      typeof process.geteuid === 'function' ? process.geteuid() : 0
    );
  }

  baselinePath(workspaceKey, imageDigest) {
    if (!WORKSPACE_KEY.test(workspaceKey || '') || !SHA256.test(imageDigest || '')) {
      throw new Error('executable baseline selector is invalid');
    }
    return path.join(this.root, workspaceKey, `${imageDigest.slice('sha256:'.length)}.json`);
  }

  async loadActive(expected) {
    const filePath = this.baselinePath(expected.workspaceKey, expected.imageDigest);
    try {
      return { filePath, ...await readTrustedBaseline(filePath, this.trustedUid, expected) };
    } catch (error) {
      if (error.code === 'ENOENT') return null;
      throw error;
    }
  }

  async activate(document, options = {}) {
    const validated = validateExecutableBaseline(document, options.expected || {});
    const serialized = Buffer.from(`${stableStringify(validated, 2)}\n`, 'utf8');
    const digest = sha256(serialized);
    if (options.expectedDigest && options.expectedDigest !== digest) {
      throw new Error('executable baseline digest changed before activation');
    }
    const filePath = this.baselinePath(validated.workspaceKey, validated.imageDigest);
    const directory = path.dirname(filePath);
    await fs.mkdir(directory, { recursive: true, mode: 0o700 });
    const rootStat = await fs.lstat(this.root);
    const directoryStat = await fs.lstat(directory);
    for (const [label, stat] of [['baseline root', rootStat], ['baseline workspace', directoryStat]]) {
      if (
        !stat.isDirectory()
        || stat.isSymbolicLink()
        || stat.uid !== this.trustedUid
        || (stat.mode & 0o777) !== 0o700
      ) {
        throw new Error(`${label} is not trusted`);
      }
    }
    const temporary = path.join(directory, `.${crypto.randomUUID()}.tmp`);
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
      await handle.writeFile(serialized);
      await handle.sync();
      await handle.close();
      handle = null;
      await fs.rename(temporary, filePath);
      const directoryHandle = await fs.open(
        directory,
        fsConstants.O_RDONLY
          | (fsConstants.O_DIRECTORY || 0)
          | (fsConstants.O_NOFOLLOW || 0),
      );
      try {
        await directoryHandle.sync();
      } finally {
        await directoryHandle.close();
      }
    } finally {
      await handle?.close();
      await fs.rm(temporary, { force: true });
    }
    return { filePath, digest, document: validated };
  }
}
