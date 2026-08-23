import crypto from 'node:crypto';
import path from 'node:path';

export const MANAGED_DNS_EVIDENCE_MAX_BYTES = 8 * 1024 * 1024;
const MANAGED_DNS_LOSS_REASONS = new Set([
  'byte_budget_exceeded',
  'collector_failure',
  'forced_termination',
]);

function requiredRunId(runId) {
  if (typeof runId !== 'string' || !runId || runId.length > 256) {
    throw new TypeError('managed DNS evidence requires a bounded run ID');
  }
  return runId;
}

export function managedDnsEvidenceKey(runId) {
  return crypto
    .createHash('sha256')
    .update(requiredRunId(runId))
    .digest('hex');
}

export function managedDnsEvidencePaths(evidenceDir, runId) {
  const key = managedDnsEvidenceKey(runId);
  const directory = path.join(path.resolve(evidenceDir), 'managed-dns');
  return {
    directory,
    key,
    logPath: path.join(directory, `${key}.log`),
    overflowPath: path.join(directory, `${key}.overflow.json`),
  };
}

export function managedDnsOverflowMarker(input) {
  const runId = requiredRunId(input?.runId);
  const limitBytes = Number(input?.limitBytes);
  const bytesWritten = Number(input?.bytesWritten);
  if (
    !Number.isSafeInteger(limitBytes)
    || limitBytes <= 0
    || !Number.isSafeInteger(bytesWritten)
    || bytesWritten < 0
    || bytesWritten > limitBytes
  ) {
    throw new TypeError('managed DNS overflow marker has invalid byte counters');
  }
  const observedAt = input.observedAt || new Date().toISOString();
  if (typeof observedAt !== 'string' || Number.isNaN(Date.parse(observedAt))) {
    throw new TypeError('managed DNS overflow marker has an invalid timestamp');
  }
  const lossReason = input.lossReason || 'byte_budget_exceeded';
  if (!MANAGED_DNS_LOSS_REASONS.has(lossReason)) {
    throw new TypeError('managed DNS overflow marker has an invalid loss reason');
  }
  return {
    schemaVersion: 1,
    source: 'managed_dns',
    type: 'evidence_overflow',
    runId,
    evidenceKey: managedDnsEvidenceKey(runId),
    observedAt,
    lossReason,
    limitBytes,
    bytesWritten,
    lostEvents: 1,
  };
}

export function validateManagedDnsOverflowMarker(document, options = {}) {
  const expected = managedDnsOverflowMarker({
    runId: options.runId,
    limitBytes: options.limitBytes ?? MANAGED_DNS_EVIDENCE_MAX_BYTES,
    bytesWritten: document?.bytesWritten,
    observedAt: document?.observedAt,
    lossReason: document?.lossReason,
  });
  if (
    document?.schemaVersion !== expected.schemaVersion
    || document?.source !== expected.source
    || document?.type !== expected.type
    || document?.runId !== expected.runId
    || document?.evidenceKey !== expected.evidenceKey
    || document?.lossReason !== expected.lossReason
    || document?.limitBytes !== expected.limitBytes
    || document?.lostEvents !== 1
  ) {
    throw new Error('managed DNS overflow marker does not match its run and budget');
  }
  return expected;
}

export function managedDnsEvidenceSnapshot(input) {
  const runId = requiredRunId(input?.runId);
  const limitBytes = Number(input?.limitBytes);
  const bytesWritten = Number(input?.bytesWritten);
  if (
    !Number.isSafeInteger(limitBytes)
    || limitBytes <= 0
    || !Number.isSafeInteger(bytesWritten)
    || bytesWritten < 0
    || bytesWritten > limitBytes
  ) {
    throw new TypeError('managed DNS evidence snapshot has invalid byte counters');
  }
  const observedAt = input.observedAt || new Date().toISOString();
  if (typeof observedAt !== 'string' || Number.isNaN(Date.parse(observedAt))) {
    throw new TypeError('managed DNS evidence snapshot has an invalid timestamp');
  }
  const overflowMarker = input.overflowMarker == null
    ? null
    : validateManagedDnsOverflowMarker(input.overflowMarker, {
        runId,
        limitBytes,
      });
  if (overflowMarker && overflowMarker.bytesWritten !== bytesWritten) {
    throw new Error('managed DNS evidence snapshot does not match its overflow marker');
  }
  return {
    schemaVersion: 1,
    source: 'managed_dns',
    type: 'evidence_snapshot',
    runId,
    evidenceKey: managedDnsEvidenceKey(runId),
    observedAt,
    limitBytes,
    bytesWritten,
    overflowed: overflowMarker !== null,
    lostEvents: overflowMarker ? overflowMarker.lostEvents : 0,
    overflowMarker,
  };
}

export function validateManagedDnsEvidenceSnapshot(document, options = {}) {
  const expected = managedDnsEvidenceSnapshot({
    runId: options.runId,
    limitBytes: options.limitBytes ?? MANAGED_DNS_EVIDENCE_MAX_BYTES,
    bytesWritten: document?.bytesWritten,
    observedAt: document?.observedAt,
    overflowMarker: document?.overflowMarker,
  });
  if (
    document?.schemaVersion !== expected.schemaVersion
    || document?.source !== expected.source
    || document?.type !== expected.type
    || document?.runId !== expected.runId
    || document?.evidenceKey !== expected.evidenceKey
    || document?.limitBytes !== expected.limitBytes
    || document?.overflowed !== expected.overflowed
    || document?.lostEvents !== expected.lostEvents
  ) {
    throw new Error('managed DNS evidence snapshot does not match its run and budget');
  }
  return expected;
}
