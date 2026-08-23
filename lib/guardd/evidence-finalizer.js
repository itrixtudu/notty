import crypto from 'node:crypto';
import fs from 'node:fs/promises';
import { constants as fsConstants } from 'node:fs';
import net from 'node:net';
import path from 'node:path';

import { AUDIT_ARTIFACT_FILES } from '../guard/audit-evaluation.js';
import { stableStringify } from '../guard/stable.js';
import { MANAGED_GATEWAY_EVIDENCE_MAX_BYTES } from './constants.js';
import {
  MANAGED_DNS_EVIDENCE_MAX_BYTES,
  managedDnsEvidencePaths,
  validateManagedDnsEvidenceSnapshot,
  validateManagedDnsOverflowMarker,
} from './managed-dns-evidence.js';

function hashBuffer(buffer) {
  return `sha256:${crypto.createHash('sha256').update(buffer).digest('hex')}`;
}

const REQUIRED_SOURCES_BY_MODE = Object.freeze({
  learn: Object.freeze([
    'tetragon-events',
    'ig-dns',
    'ig-syscalls',
    'nosh-l4',
    'managed_dns',
    'managed_gateway',
  ]),
  audit: Object.freeze([
    'tetragon-events',
    'ig-dns',
    'ig-syscalls',
    'nosh-l4',
    'managed_dns',
    'managed_gateway',
  ]),
  enforce: Object.freeze([
    'tetragon-events',
    'nosh-l4',
    'managed_dns',
    'managed_gateway',
  ]),
  'egress-learn': Object.freeze([
    'nosh-egress',
  ]),
  'egress-audit': Object.freeze([
    'nosh-egress',
  ]),
  'egress-enforce': Object.freeze([
    'nosh-egress',
  ]),
});

function dnsSerial(line) {
  return (
    line.match(/dnsmasq(?:\[\d+\])?:\s+(\d+)\s+/)?.[1] ||
    line.match(/^\s*(\d+)\s+/)?.[1] ||
    null
  );
}

function dnsProcessId(line) {
  return line.match(/dnsmasq\[(\d+)\]:/i)?.[1] || null;
}

function dnsRequester(line) {
  return (
    line.match(
      /query\[[A-Z0-9]+\]\s+\S+\s+from\s+([0-9a-f:.]+)/i,
    )?.[1] || null
  );
}

// The gateway stamps each complete dnsmasq line when it receives it. Native
// dnsmasq text has no timezone-qualified event time and is not safe for a
// bounded cross-source join on its own.
function dnsObservedAt(line) {
  const value = line.match(
    /^nosh-observed-at=(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?(?:Z|[+-]\d{2}:\d{2}))\s+/,
  )?.[1];
  if (!value) {
    return null;
  }
  const milliseconds = Date.parse(value);
  return Number.isFinite(milliseconds)
    ? new Date(milliseconds).toISOString()
    : null;
}

function dnsQueryName(line) {
  return line.match(
    /query\[[A-Z0-9]+\]\s+(\S+)\s+from\s+[0-9a-f:.]+/i,
  )?.[1]?.replace(/\.$/, '').toLowerCase() || null;
}

function parseDnsLine(line, sourceIpv4, transaction = {}) {
  const query = line.match(
    /query\[([A-Z0-9]+)\]\s+(\S+)\s+from\s+([0-9a-f:.]+)/i,
  );
  const reply = line.match(/(?:reply|cached)\s+(\S+)\s+is\s+(\S+)/i);
  const forwarded = line.match(/forwarded\s+(\S+)\s+to\s+(\S+)/i);
  const responseName = reply?.[1]?.replace(/\.$/, '').toLowerCase() || null;
  const qname = query?.[2]?.replace(/\.$/, '').toLowerCase() ||
    (reply ? transaction.queryName || null : null);
  return {
    schemaVersion: 1,
    source: 'managed_dns',
    type: query
      ? 'query'
      : reply
        ? 'answer'
        : forwarded
          ? 'forward'
          : 'resolver',
    transactionId: dnsSerial(line),
    requester: query?.[3] || null,
    qtype: query?.[1]?.toUpperCase() || null,
    qname,
    responseName,
    answer: reply?.[2] || null,
    upstream: forwarded?.[2] || null,
    attributedRunner: sourceIpv4,
    observedAt: dnsObservedAt(line),
    raw: line,
  };
}

export function projectManagedDnsLines(raw, sourceIpv4) {
  const lines = String(raw || '')
    .split(/\r?\n/)
    .filter(Boolean);
  const groups = new Map();
  const ungrouped = [];
  for (const line of lines) {
    const serial = dnsSerial(line);
    const processId = dnsProcessId(line);
    if (!serial || !processId) {
      ungrouped.push(line);
      continue;
    }
    const key = `${processId}:${serial}`;
    const group = groups.get(key) || [];
    group.push(line);
    groups.set(key, group);
  }
  const selected = [];
  for (const group of groups.values()) {
    if (group.some((line) => dnsRequester(line) === sourceIpv4)) {
      const queryNames = new Set(
        group
          .filter((line) => dnsRequester(line) === sourceIpv4)
          .map(dnsQueryName)
          .filter(Boolean),
      );
      const queryName = queryNames.size === 1 ? [...queryNames][0] : null;
      selected.push(
        ...group.map((line) => ({
          line,
          transaction: { queryName },
        })),
      );
    }
  }
  // PID-less log lines cannot be safely joined by serial: concurrent
  // dnsmasq processes each start their own serial sequence. Preserve only
  // lines that attribute the requester directly.
  selected.push(
    ...ungrouped
      .filter((line) => dnsRequester(line) === sourceIpv4)
      .map((line) => ({
        line,
        transaction: { queryName: dnsQueryName(line) },
      })),
  );
  return selected.map(({ line, transaction }) =>
    parseDnsLine(line, sourceIpv4, transaction));
}

async function readManagedDnsOverflowMarker(filePath, runId) {
  let handle;
  try {
    handle = await fs.open(
      filePath,
      fsConstants.O_RDONLY | (fsConstants.O_NOFOLLOW || 0),
    );
  } catch (error) {
    if (error.code === 'ENOENT') {
      return null;
    }
    throw error;
  }
  try {
    const stat = await handle.stat({ bigint: true });
    const expectedUid = typeof process.geteuid === 'function'
      ? BigInt(process.geteuid())
      : null;
    if (
      !stat.isFile()
      || stat.nlink !== 1n
      || (stat.mode & 0o7777n) !== 0o600n
      || stat.size > 64n * 1024n
      || (expectedUid !== null && stat.uid !== expectedUid)
    ) {
      throw new Error('managed DNS overflow marker is not a trusted 0600 file');
    }
    const source = await handle.readFile('utf8');
    const current = await fs.lstat(filePath, { bigint: true });
    if (
      !current.isFile()
      || current.isSymbolicLink()
      || current.dev !== stat.dev
      || current.ino !== stat.ino
    ) {
      throw new Error('managed DNS overflow marker changed during finalization');
    }
    return validateManagedDnsOverflowMarker(JSON.parse(source), {
      runId,
      limitBytes: MANAGED_DNS_EVIDENCE_MAX_BYTES,
    });
  } finally {
    await handle.close();
  }
}

async function copyManagedDns(run, sharedDir) {
  const destination = path.join(run.evidenceDir, 'managed_dns.jsonl');
  const paths = managedDnsEvidencePaths(sharedDir, run.runId);
  const identity = run.egress?.evidenceOffsets?.dns;
  let snapshot = null;
  let snapshotError = null;
  try {
    snapshot = validateManagedDnsEvidenceSnapshot(
      run.egress?.finalSnapshot?.managedDnsEvidence,
      {
        runId: run.runId,
        limitBytes: MANAGED_DNS_EVIDENCE_MAX_BYTES,
      },
    );
  } catch (error) {
    snapshotError = error.message;
  }
  let evidenceWindow;
  if (snapshotError) {
    evidenceWindow = invalidEvidenceWindow(
      'managed-dns-final-snapshot-invalid',
      snapshotError,
    );
  } else if (
    identity?.evidenceKey !== paths.key
    || identity?.maxBytes !== MANAGED_DNS_EVIDENCE_MAX_BYTES
  ) {
    evidenceWindow = invalidEvidenceWindow(
      'managed-dns-budget-identity-invalid',
      'run state does not bind the managed DNS evidence file and byte budget',
    );
  } else {
    evidenceWindow = await readEvidenceWindow(paths.logPath, identity, {
      endOffset: snapshot.bytesWritten,
      maxBytesAtFinalization: MANAGED_DNS_EVIDENCE_MAX_BYTES,
    });
  }
  let overflow = null;
  let overflowError = null;
  try {
    const persistedOverflow = await readManagedDnsOverflowMarker(
      paths.overflowPath,
      run.runId,
    );
    if (snapshot?.overflowed) {
      overflow = snapshot.overflowMarker;
      if (!persistedOverflow) {
        throw new Error('attested managed DNS overflow marker is missing');
      }
      if (
        JSON.stringify(persistedOverflow)
        !== JSON.stringify(snapshot.overflowMarker)
      ) {
        throw new Error('managed DNS overflow marker changed after snapshot');
      }
    } else if (
      snapshot
      && persistedOverflow
      && Date.parse(persistedOverflow.observedAt) <= Date.parse(snapshot.observedAt)
    ) {
      overflow = persistedOverflow;
      throw new Error('managed DNS overflow state contradicts its final snapshot');
    } else if (!snapshot) {
      overflow = persistedOverflow;
    }
  } catch (error) {
    overflowError = error.message;
  }
  if (overflowError) {
    evidenceWindow = invalidEvidenceWindow(
      'managed-dns-overflow-marker-invalid',
      overflowError,
    );
  }
  const raw = evidenceWindow.content.toString('utf8');
  const records = projectManagedDnsLines(raw, run.egress?.sourceIpv4);
  await fs.writeFile(
    destination,
    records.map((record) => JSON.stringify(record)).join('\n') +
      (records.length ? '\n' : ''),
    { mode: 0o600 },
  );
  return {
    path: destination,
    evidenceWindow: evidenceWindow.state,
    finalSnapshot: snapshot,
    overflow,
    lostEvents: Math.max(
      snapshot?.lostEvents || 0,
      overflow?.lostEvents || 0,
      evidenceWindow.state.marker === 'evidence-byte-budget-exceeded' ? 1 : 0,
    ),
  };
}

async function copyManagedGateway(run, sharedDir) {
  const destination = path.join(run.evidenceDir, 'managed_gateway.jsonl');
  const records = [];
  const window = await readEvidenceWindow(
    path.join(sharedDir, 'managed-gateway-counters.ndjson'),
    run.egress?.evidenceOffsets?.gateway,
    { maxBytesAtFinalization: MANAGED_GATEWAY_EVIDENCE_MAX_BYTES },
  );
  let evidenceWindow = window.state;
  for (const line of window.content.toString('utf8').split(/\r?\n/).filter(Boolean)) {
    try {
      const record = JSON.parse(line);
      if (record.runId === run.runId) {
        records.push(record);
      }
    } catch {
      evidenceWindow = {
        ...evidenceWindow,
        ok: false,
        marker: 'evidence-window-truncated',
        error: 'shared gateway evidence contains an invalid NDJSON record',
      };
    }
  }
  if (run.egress?.acknowledgement?.runId === run.runId) {
    records.push(run.egress.acknowledgement);
  }
  if (run.egress?.finalSnapshot?.runId === run.runId) {
    records.push(run.egress.finalSnapshot);
  }
  await fs.writeFile(
    destination,
    records.map((record) => JSON.stringify(record)).join('\n') +
      (records.length ? '\n' : ''),
    { mode: 0o600 },
  );
  return {
    path: destination,
    evidenceWindow,
  };
}

function invalidEvidenceWindow(marker, error, details = {}) {
  return {
    content: Buffer.alloc(0),
    state: {
      ok: false,
      marker,
      error,
      ...details,
    },
  };
}

async function readEvidenceWindow(filePath, identity, options = {}) {
  if (identity == null) {
    return invalidEvidenceWindow(
      'evidence-offset-missing',
      'run state does not contain shared evidence file identity',
    );
  }
  if (
    typeof identity !== 'object' ||
    Array.isArray(identity) ||
    !Object.hasOwn(identity, 'offset') ||
    !Object.hasOwn(identity, 'dev') ||
    !Object.hasOwn(identity, 'ino')
  ) {
    return invalidEvidenceWindow(
      'evidence-file-identity-invalid',
      'shared evidence identity requires offset, dev, and ino',
    );
  }
  const { offset, dev, ino } = identity;
  if (!Number.isSafeInteger(offset)) {
    return invalidEvidenceWindow(
      'evidence-offset-not-integer',
      'shared evidence byte offset must be a safe integer',
      { offset },
    );
  }
  if (offset < 0) {
    return invalidEvidenceWindow(
      'evidence-offset-out-of-range',
      'shared evidence byte offset must not be negative',
      { offset },
    );
  }
  if (
    typeof dev !== 'string' ||
    !/^\d+$/.test(dev) ||
    typeof ino !== 'string' ||
    !/^\d+$/.test(ino)
  ) {
    return invalidEvidenceWindow(
      'evidence-file-identity-invalid',
      'shared evidence dev and ino must be decimal strings',
      { offset },
    );
  }
  let handle;
  try {
    const lstat = await fs.lstat(filePath, { bigint: true });
    if (!lstat.isFile() || lstat.isSymbolicLink()) {
      return invalidEvidenceWindow(
        'evidence-file-identity-mismatch',
        'shared evidence path is not a regular non-symlink file',
        { offset, expectedDev: dev, expectedIno: ino },
      );
    }
    if (lstat.dev.toString() !== dev || lstat.ino.toString() !== ino) {
      return invalidEvidenceWindow(
        'evidence-file-identity-mismatch',
        'shared evidence file was replaced after run admission',
        {
          offset,
          expectedDev: dev,
          expectedIno: ino,
          actualDev: lstat.dev.toString(),
          actualIno: lstat.ino.toString(),
        },
      );
    }
    handle = await fs.open(
      filePath,
      fsConstants.O_RDONLY | (fsConstants.O_NOFOLLOW || 0),
    );
  } catch (error) {
    if (error.code === 'ENOENT') {
      return invalidEvidenceWindow(
        'shared-evidence-log-missing',
        'shared evidence log is missing',
        { offset },
      );
    }
    return invalidEvidenceWindow(
      'shared-evidence-log-unreadable',
      error.message,
      { offset },
    );
  }
  try {
    const stat = await handle.stat({ bigint: true });
    if (
      !stat.isFile() ||
      stat.dev.toString() !== dev ||
      stat.ino.toString() !== ino
    ) {
      return invalidEvidenceWindow(
        'evidence-file-identity-mismatch',
        'shared evidence file identity changed while it was opened',
        {
          offset,
          expectedDev: dev,
          expectedIno: ino,
          actualDev: stat.dev.toString(),
          actualIno: stat.ino.toString(),
        },
      );
    }
    if (
      Number.isSafeInteger(options.maxBytesAtFinalization)
      && options.maxBytesAtFinalization >= 0
      && stat.size > BigInt(options.maxBytesAtFinalization)
    ) {
      return invalidEvidenceWindow(
        'evidence-byte-budget-exceeded',
        'shared evidence log exceeds its hard byte budget',
        {
          offset,
          bytesAtFinalization: stat.size.toString(),
          maxBytesAtFinalization: options.maxBytesAtFinalization,
        },
      );
    }
    const offsetBigInt = BigInt(offset);
    if (offsetBigInt > stat.size) {
      return invalidEvidenceWindow(
        'evidence-offset-out-of-range',
        'shared evidence log was truncated below the captured byte offset',
        {
          offset,
          bytesAtFinalization: stat.size.toString(),
          logTruncated: true,
        },
      );
    }
    let endOffset = stat.size;
    if (Object.hasOwn(options, 'endOffset')) {
      if (!Number.isSafeInteger(options.endOffset) || options.endOffset < 0) {
        return invalidEvidenceWindow(
          'evidence-snapshot-endpoint-invalid',
          'attested evidence endpoint must be a nonnegative safe integer',
          { offset, endOffset: options.endOffset },
        );
      }
      endOffset = BigInt(options.endOffset);
      if (endOffset < offsetBigInt || endOffset > stat.size) {
        return invalidEvidenceWindow(
          'evidence-snapshot-endpoint-invalid',
          'attested evidence endpoint is outside the captured file',
          {
            offset,
            endOffset: options.endOffset,
            bytesAtFinalization: stat.size.toString(),
          },
        );
      }
    }
    const contentLength = endOffset - offsetBigInt;
    if (contentLength > BigInt(Number.MAX_SAFE_INTEGER)) {
      return invalidEvidenceWindow(
        'shared-evidence-log-unreadable',
        'shared evidence byte window exceeds the supported size',
        {
          offset,
          endOffset: endOffset.toString(),
          bytesAtFinalization: stat.size.toString(),
        },
      );
    }
    if (offset > 0) {
      const boundary = Buffer.alloc(1);
      const boundaryRead = await handle.read(
        boundary,
        0,
        boundary.length,
        offset - 1,
      );
      if (boundaryRead.bytesRead !== 1 || boundary[0] !== 0x0a) {
        return invalidEvidenceWindow(
          'evidence-window-truncated',
          'shared evidence byte offset is not aligned to a complete line',
          { offset, bytesAtFinalization: stat.size.toString() },
        );
      }
    }
    const content = Buffer.alloc(Number(contentLength));
    let bytesRead = 0;
    while (bytesRead < content.length) {
      const result = await handle.read(
        content,
        bytesRead,
        content.length - bytesRead,
        offset + bytesRead,
      );
      if (result.bytesRead === 0) {
        break;
      }
      bytesRead += result.bytesRead;
    }
    if (bytesRead !== content.length) {
      return invalidEvidenceWindow(
        'evidence-window-truncated',
        'shared evidence log changed during finalization',
        {
          offset,
          bytesAtFinalization: stat.size.toString(),
          bytesRead,
          logTruncated: true,
        },
      );
    }
    if (content.length > 0 && content[content.length - 1] !== 0x0a) {
      return invalidEvidenceWindow(
        'evidence-window-truncated',
        'shared evidence window ends with an incomplete line',
        { offset, bytesAtFinalization: stat.size.toString() },
      );
    }
    return {
      content,
      state: {
        ok: true,
        marker: 'run-scoped-byte-window',
        error: null,
        offset,
        dev,
        ino,
        bytesAtFinalization: stat.size.toString(),
        bytesAtSnapshot: endOffset.toString(),
        bytesRead: content.length,
      },
    };
  } catch (error) {
    return invalidEvidenceWindow(
      'shared-evidence-log-unreadable',
      error.message,
      { offset },
    );
  } finally {
    await handle.close().catch(() => {});
  }
}

function balancedJsonObjects(source) {
  const objects = [];
  let start = -1;
  let depth = 0;
  let inString = false;
  let escaped = false;
  for (let index = 0; index < source.length; index += 1) {
    const character = source[index];
    if (inString) {
      if (escaped) {
        escaped = false;
      } else if (character === '\\') {
        escaped = true;
      } else if (character === '"') {
        inString = false;
      }
      continue;
    }
    if (character === '"') {
      inString = true;
      continue;
    }
    if (character === '{') {
      if (depth === 0) {
        start = index;
      }
      depth += 1;
    } else if (character === '}' && depth > 0) {
      depth -= 1;
      if (depth === 0 && start >= 0) {
        objects.push(source.slice(start, index + 1));
        start = -1;
      }
    }
  }
  return objects;
}

function recordsFromJson(content, name) {
  const source = content.toString('utf8').trim();
  if (!source) {
    return { records: [], parseErrors: 0 };
  }
  try {
    const parsed = JSON.parse(source);
    if (Array.isArray(parsed)) {
      return { records: parsed, parseErrors: 0 };
    }
    if (Array.isArray(parsed?.records)) {
      return { records: parsed.records, parseErrors: 0 };
    }
    return { records: [parsed], parseErrors: 0 };
  } catch {
    // Normal collectors use JSONL. The seccomp advisor may print a pretty
    // JSON profile after a short human prefix, so it is handled separately.
  }
  if (name === 'ig-syscalls') {
    const records = [];
    for (const candidate of balancedJsonObjects(source)) {
      try {
        const record = JSON.parse(candidate);
        if (
          typeof record?.defaultAction === 'string' &&
          Array.isArray(record.syscalls)
        ) {
          records.push(record);
        }
      } catch {
        // Count failure below if no complete advisor document was recovered.
      }
    }
    return { records, parseErrors: records.length ? 0 : 1 };
  }
  const records = [];
  let parseErrors = 0;
  for (const line of source.split(/\r?\n/).filter(Boolean)) {
    try {
      records.push(JSON.parse(line));
    } catch {
      parseErrors += 1;
    }
  }
  return { records, parseErrors };
}

function nonnegativeCounter(value) {
  if (typeof value === 'number') {
    return Number.isSafeInteger(value) && value >= 0
      ? value
      : Number.MAX_SAFE_INTEGER;
  }
  const text = String(value ?? '0');
  if (!/^(0|[1-9][0-9]*)$/.test(text)) return Number.MAX_SAFE_INTEGER;
  const parsed = BigInt(text);
  return parsed > BigInt(Number.MAX_SAFE_INTEGER)
    ? Number.MAX_SAFE_INTEGER
    : Number(parsed);
}

function decimalCounter(value) {
  const text = String(value);
  return /^(0|[1-9][0-9]*)$/.test(text) ? text : null;
}

function nonzeroCounter(value) {
  const selected = decimalCounter(value);
  return selected == null || selected !== '0';
}

const NOSH_EGRESS_DECISION_FIELDS = Object.freeze([
  'schemaVersion',
  'recordKind',
  'timestampMonotonicNs',
  'cgroupId',
  'policyGeneration',
  'hook',
  'family',
  'protocol',
  'sourceAddress',
  'destinationAddress',
  'sourcePort',
  'destinationPort',
  'verdict',
  'decisionClass',
  'reason',
  'reasonCode',
  'enforcementApplied',
  'containmentId',
  'ruleId',
  'packetBytes',
  'transactionId',
  'domain',
  'expiresMonotonicNs',
]);

const NOSH_EGRESS_DNS_ANSWER_FIELDS = Object.freeze([
  'schemaVersion',
  'recordKind',
  'timestampMonotonicNs',
  'cgroupId',
  'policyGeneration',
  'hook',
  'transportFamily',
  'transportProtocol',
  'resolverAddress',
  'resolverPort',
  'clientPort',
  'domain',
  'dnsRecordType',
  'answerAddress',
  'decisionClass',
  'reason',
  'reasonCode',
  'enforcementApplied',
  'transactionId',
  'expiresMonotonicNs',
]);

const NOSH_EGRESS_STATS_FIELDS = Object.freeze([
  'schemaVersion',
  'recordKind',
  'timestampUnixNs',
  'cgroupId',
  'policyGeneration',
  'mode',
  'final',
  'eventsSeen',
  'decoderErrors',
  'counters',
]);

const NOSH_EGRESS_COUNTER_FIELDS = Object.freeze([
  'allowed',
  'wouldDeny',
  'denied',
  'ringbufDrops',
  'parseErrors',
  'fragments',
  'configInvalid',
  'policyMisses',
  'dnsQueries',
  'dnsResponses',
  'dnsTransactionMisses',
  'dnsGrantUpdates',
  'dnsGrantFailures',
  'dnsUnsupported',
  'unsupportedProtocol',
  'coverageAllowed',
  'coverageWouldDeny',
  'coverageDenied',
  'containmentDenied',
  'backendDenied',
  'dnsAnswers',
]);

const NOSH_EGRESS_REASON_NAMES = Object.freeze({
  1: 'static-policy',
  2: 'configured-resolver',
  3: 'dns-grant',
  4: 'learn-observed',
  5: 'default-deny',
  6: 'backend-invalid',
  7: 'parse-gap',
  8: 'fragment-gap',
  9: 'dns-domain-deny',
  10: 'dns-response-unmatched',
  11: 'unsupported-gap',
  12: 'ipv6-control',
  13: 'platform-containment',
  14: 'hidden-destination',
  15: 'unknown-destination',
  16: 'dns-answer',
  17: 'dns-query-observed',
  18: 'dns-response',
});

const NOSH_EGRESS_DECISION_CLASSES = new Set([
  'policy-allow',
  'observed',
  'would-deny',
  'policy-deny',
  'containment-deny',
  'coverage-gap',
  'backend-deny',
  'infrastructure-allow',
  'dns-observation',
]);

const NOSH_EGRESS_DECISION_MATRIX = Object.freeze({
  learn: Object.freeze({
    2: Object.freeze(['allow', 'infrastructure-allow', false]),
    4: Object.freeze(['allow', 'observed', false]),
    6: Object.freeze(['deny', 'backend-deny', true]),
    7: Object.freeze(['allow', 'coverage-gap', false]),
    8: Object.freeze(['allow', 'coverage-gap', false]),
    10: Object.freeze(['allow', 'coverage-gap', false]),
    11: Object.freeze(['allow', 'coverage-gap', false]),
    12: Object.freeze(['allow', 'infrastructure-allow', false]),
    13: Object.freeze(['deny', 'containment-deny', true]),
    14: Object.freeze(['deny', 'backend-deny', true]),
    15: Object.freeze(['deny', 'backend-deny', true]),
    17: Object.freeze(['allow', 'dns-observation', false]),
    18: Object.freeze(['allow', 'infrastructure-allow', false]),
  }),
  audit: Object.freeze({
    1: Object.freeze(['allow', 'policy-allow', false]),
    2: Object.freeze(['allow', 'infrastructure-allow', false]),
    3: Object.freeze(['allow', 'policy-allow', false]),
    5: Object.freeze(['would-deny', 'would-deny', false]),
    6: Object.freeze(['deny', 'backend-deny', true]),
    7: Object.freeze(['would-deny', 'coverage-gap', false]),
    8: Object.freeze(['would-deny', 'coverage-gap', false]),
    9: Object.freeze(['would-deny', 'would-deny', false]),
    10: Object.freeze(['would-deny', 'coverage-gap', false]),
    11: Object.freeze(['would-deny', 'coverage-gap', false]),
    12: Object.freeze(['allow', 'infrastructure-allow', false]),
    13: Object.freeze(['deny', 'containment-deny', true]),
    14: Object.freeze(['deny', 'backend-deny', true]),
    15: Object.freeze(['deny', 'backend-deny', true]),
    18: Object.freeze(['allow', 'infrastructure-allow', false]),
  }),
  enforce: Object.freeze({
    1: Object.freeze(['allow', 'policy-allow', true]),
    2: Object.freeze(['allow', 'infrastructure-allow', false]),
    3: Object.freeze(['allow', 'policy-allow', true]),
    5: Object.freeze(['deny', 'policy-deny', true]),
    6: Object.freeze(['deny', 'backend-deny', true]),
    7: Object.freeze(['deny', 'coverage-gap', true]),
    8: Object.freeze(['deny', 'coverage-gap', true]),
    9: Object.freeze(['deny', 'policy-deny', true]),
    10: Object.freeze(['deny', 'coverage-gap', true]),
    11: Object.freeze(['deny', 'coverage-gap', true]),
    12: Object.freeze(['allow', 'infrastructure-allow', false]),
    13: Object.freeze(['deny', 'containment-deny', true]),
    14: Object.freeze(['deny', 'backend-deny', true]),
    15: Object.freeze(['deny', 'backend-deny', true]),
    18: Object.freeze(['allow', 'infrastructure-allow', false]),
  }),
});

function exactFieldInventory(record, fields) {
  return record
    && typeof record === 'object'
    && !Array.isArray(record)
    && Object.keys(record).sort().join(',') === [...fields].sort().join(',');
}

function unsignedInteger(value, maximum = Number.MAX_SAFE_INTEGER) {
  return Number.isSafeInteger(value) && value >= 0 && value <= maximum;
}

function validObservedDomain(value) {
  if (value === '') return true;
  return typeof value === 'string'
    && value === value.toLowerCase()
    && value.length <= 253
    && value.split('.').every((label) => (
      label.length >= 1
      && label.length <= 63
      && /^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/.test(label)
    ));
}

function validNoshEgressAddressPair(record) {
  if (record.family === 0) {
    return record.sourceAddress === '' && record.destinationAddress === '';
  }
  return net.isIP(record.sourceAddress) === record.family
    && net.isIP(record.destinationAddress) === record.family;
}

function validNoshEgressReason(record) {
  return Number.isInteger(record.reasonCode)
    && record.reasonCode >= 1
    && record.reasonCode <= 18
    && record.reason === NOSH_EGRESS_REASON_NAMES[record.reasonCode];
}

function validNoshEgressDecisionSemantics(record, mode) {
  if (!NOSH_EGRESS_DECISION_CLASSES.has(record.decisionClass)) return false;
  if (typeof record.enforcementApplied !== 'boolean') return false;
  const expected = NOSH_EGRESS_DECISION_MATRIX[mode]?.[record.reasonCode];
  if (
    !expected
    || record.verdict !== expected[0]
    || record.decisionClass !== expected[1]
    || record.enforcementApplied !== expected[2]
  ) {
    return false;
  }
  if (
    [1, 3].includes(record.reasonCode)
    && (!unsignedInteger(record.ruleId, 0xffffffff) || record.ruleId === 0)
  ) return false;
  if (record.reasonCode === 13) {
    const containedAddress = record.hook === 5
      ? record.sourceAddress
      : record.destinationAddress;
    return [4, 6].includes(record.family)
      && net.isIP(containedAddress) === record.family
      && record.containmentId === `platform-endpoint:${containedAddress}`;
  }
  return record.containmentId === '';
}

function validNoshEgressDnsAnswer(record) {
  const answerFamily = record.dnsRecordType === 'A'
    ? 4
    : record.dnsRecordType === 'AAAA'
      ? 6
      : 0;
  return exactFieldInventory(record, NOSH_EGRESS_DNS_ANSWER_FIELDS)
    && record.hook === 5
    && [4, 6].includes(record.transportFamily)
    && [6, 17].includes(record.transportProtocol)
    && net.isIP(record.resolverAddress) === record.transportFamily
    && record.resolverPort === 53
    && unsignedInteger(record.clientPort, 65_535)
    && record.clientPort > 0
    && validObservedDomain(record.domain)
    && record.domain !== ''
    && net.isIP(record.answerAddress) === answerFamily
    && record.decisionClass === 'dns-observation'
    && record.reason === 'dns-answer'
    && record.reasonCode === 16
    && record.enforcementApplied === false
    && unsignedInteger(record.transactionId, 65_535)
    && decimalCounter(record.timestampMonotonicNs)
    && decimalCounter(record.cgroupId)
    && decimalCounter(record.policyGeneration)
    && decimalCounter(record.expiresMonotonicNs)
    && BigInt(record.expiresMonotonicNs) > BigInt(record.timestampMonotonicNs);
}

const NOSH_EGRESS_RECONCILED_COUNTERS = Object.freeze([
  'allowed',
  'wouldDeny',
  'denied',
  'coverageAllowed',
  'coverageWouldDeny',
  'coverageDenied',
  'containmentDenied',
  'backendDenied',
  'dnsAnswers',
]);

function isDnsGrantMaterialization(record) {
  return record.reasonCode === 3
    && record.hook === 5
    && record.sourcePort === 53
    && record.packetBytes === 0
    && record.ruleId > 0
    && record.domain !== ''
    && BigInt(record.expiresMonotonicNs)
      > BigInt(record.timestampMonotonicNs);
}

function reconciledNoshEgressCounters(records) {
  const counters = Object.fromEntries(
    NOSH_EGRESS_RECONCILED_COUNTERS.map((name) => [name, 0n]),
  );
  for (const record of records) {
    if (record.recordKind === 'dns-answer') {
      counters.dnsAnswers += 1n;
      continue;
    }
    if (record.recordKind !== 'decision') continue;

    /*
     * DNS grant materialization records describe authority installed from a
     * validated answer. The BPF program emits them for correlation, but the
     * one allowed packet counter belongs to the enclosing DNS response.
     */
    if (record.verdict === 'allow' && !isDnsGrantMaterialization(record)) {
      counters.allowed += 1n;
    } else if (record.verdict === 'would-deny') {
      counters.wouldDeny += 1n;
    } else if (record.verdict === 'deny') {
      counters.denied += 1n;
    }
    if (record.decisionClass === 'coverage-gap') {
      if (record.verdict === 'allow') counters.coverageAllowed += 1n;
      if (record.verdict === 'would-deny') counters.coverageWouldDeny += 1n;
      if (record.verdict === 'deny') counters.coverageDenied += 1n;
    }
    if (record.decisionClass === 'containment-deny') {
      counters.containmentDenied += 1n;
    }
    if (record.decisionClass === 'backend-deny') {
      counters.backendDenied += 1n;
    }
  }
  return counters;
}

function cleanNoshEgressCountersMatch(records, finalStats) {
  if (
    decimalCounter(finalStats.decoderErrors) !== '0'
    || decimalCounter(finalStats.counters.ringbufDrops) !== '0'
  ) {
    /* Lost/undecodable records are already incomplete and cannot reconcile. */
    return true;
  }
  const expected = reconciledNoshEgressCounters(records);
  return NOSH_EGRESS_RECONCILED_COUNTERS.every((name) => (
    BigInt(finalStats.counters[name]) === expected[name]
  ));
}

function evidenceLoss(records) {
  let lostEvents = 0;
  for (const record of records) {
    if (record?.recordKind === 'stats') {
      const counters = record.counters || {};
      if (
        record.schemaVersion === 2
        && Object.hasOwn(counters, 'coverageAllowed')
      ) {
        lostEvents = Math.max(
          lostEvents,
          nonnegativeCounter(record.decoderErrors)
            + nonnegativeCounter(counters.ringbufDrops)
            + nonnegativeCounter(counters.configInvalid)
            + nonnegativeCounter(counters.dnsGrantFailures),
        );
        continue;
      }
      lostEvents = Math.max(
        lostEvents,
        nonnegativeCounter(record.decoderErrors) +
          nonnegativeCounter(counters.ringbufDrops) +
          nonnegativeCounter(counters.parseErrors) +
          nonnegativeCounter(counters.fragments) +
          nonnegativeCounter(counters.configInvalid) +
          nonnegativeCounter(counters.dnsTransactionMisses) +
          nonnegativeCounter(counters.dnsGrantFailures) +
          nonnegativeCounter(counters.dnsUnsupported) +
          nonnegativeCounter(counters.unsupportedProtocol) +
          nonnegativeCounter(counters.flowMapFull) +
          nonnegativeCounter(counters.configMissing) +
          nonnegativeCounter(counters.tcpReassemblyDrops) +
          nonnegativeCounter(counters.transactionEvictions),
      );
      continue;
    }
    if (
      record?.recordKind === 'loss' ||
      record?.type === 'loss' ||
      record?.type === 'collector_stats'
    ) {
      lostEvents = Math.max(
        lostEvents,
        nonnegativeCounter(
          record.lostEvents ??
            record.lost_events ??
            record.eventsLost ??
            record.stats?.lostEvents ??
            record.stats?.lost,
        ),
      );
    }
  }
  return lostEvents;
}

function eventMilliseconds(record) {
  const value = Date.parse(record?.observedAt || '');
  return Number.isFinite(value) ? value : null;
}

/**
 * Conservatively correlate observe-only DNS responses with L4 attempts.
 * An address is promotable only when one complete, unexpired transaction is
 * the sole DNS name that could explain the attempt inside the bounded window.
 */
export function correlateObservedDns(records, l4Records, options = {}) {
  const runId = options.runId;
  const maximumWindowMs = options.maximumWindowMs ?? 5000;
  const responses = records.filter((record) => (
    record?.recordKind === 'event'
    && record.messageKind === 'response'
    && record.runId === runId
  ));
  const loss = evidenceLoss(records);
  const correlations = [];
  const unresolved = [];
  for (const attempt of l4Records.filter((record) => record?.recordKind === 'event')) {
    const address = attempt.network?.destinationAddress
      || attempt.destinationAddress;
    const attemptedAt = eventMilliseconds(attempt);
    if (!address || attemptedAt === null) continue;
    const candidates = [];
    for (const response of responses) {
      const responseAt = eventMilliseconds(response);
      if (responseAt === null || responseAt > attemptedAt) continue;
      for (const answer of response.answers || []) {
        if (answer?.data !== address) continue;
        const ageMs = attemptedAt - responseAt;
        const ttlMs = Number(answer.ttl) * 1000;
        if (ageMs <= maximumWindowMs && ageMs <= ttlMs) {
          candidates.push({ response, answer, ageMs, responseAt });
        }
      }
    }
    const names = new Set(candidates.map(({ response }) =>
      String(response.qname).replace(/\.$/, '').toLowerCase()));
    const unsafe = loss > 0
      || candidates.some(({ response }) => response.truncated || response.encrypted)
      || names.size !== 1;
    if (unsafe) {
      unresolved.push({
        destinationAddress: address,
        observedAt: attempt.observedAt || null,
        reason: loss > 0
          ? 'dns-evidence-loss'
          : candidates.some(({ response }) => response.truncated)
            ? 'truncated-dns-response'
            : candidates.some(({ response }) => response.encrypted)
              ? 'encrypted-dns'
              : names.size > 1
                ? 'ambiguous-address-correlation'
                : 'uncorrelated-address',
      });
      continue;
    }
    const candidate = candidates.reduce((best, entry) => {
      if (!best) return entry;
      if (entry.ageMs < best.ageMs) return entry;
      if (entry.ageMs > best.ageMs) return best;
      if (entry.responseAt > best.responseAt) return entry;
      if (entry.responseAt < best.responseAt) return best;
      if ((entry.response.transactionId ?? 0) > (best.response.transactionId ?? 0)) {
        return entry;
      }
      if ((entry.response.transactionId ?? 0) < (best.response.transactionId ?? 0)) {
        return best;
      }
      return String(entry.response.transport || '')
        < String(best.response.transport || '')
        ? entry
        : best;
    }, null);
    correlations.push({
      destinationAddress: address,
      qname: [...names][0],
      qtype: candidate.response.qtype,
      transport: candidate.response.transport,
      transactionId: candidate.response.transactionId,
      ageMs: candidate.ageMs,
      observedAt: attempt.observedAt || null,
    });
  }
  return {
    schemaVersion: 1,
    maximumWindowMs,
    eligible: loss === 0 && unresolved.length === 0,
    correlations,
    unresolved,
  };
}

function hasSeccompRecommendation(records) {
  return records.some((record) => {
    const profile = record?.profile || record?.event?.value || record;
    return (
      typeof profile?.defaultAction === 'string' &&
      Array.isArray(profile.syscalls) &&
      profile.syscalls.some(
        (entry) => Array.isArray(entry?.names) && entry.names.length > 0,
      )
    );
  });
}

function managedGatewayCompletion(records, adapterState) {
  const runId = adapterState?.runId;
  const policyHash = adapterState?.policyHash;
  const expectedSnapshot = adapterState?.finalSnapshot;
  const policyAttested = records.some(
    (record) =>
      record?.source === 'managed_gateway'
      && record?.type === 'policy_attestation'
      && record?.runId === runId
      && record?.policyHash === policyHash,
  );
  if (!policyAttested) {
    return { complete: false, marker: 'policy-attestation-missing' };
  }
  if (
    expectedSnapshot?.source !== 'managed_gateway'
    || expectedSnapshot?.type !== 'counter_snapshot_attestation'
    || expectedSnapshot?.runId !== runId
    || expectedSnapshot?.policyHash !== policyHash
    || expectedSnapshot?.complete !== true
    || !/^sha256:[a-f0-9]{64}$/.test(
      expectedSnapshot?.evidenceRecordHash || '',
    )
  ) {
    return { complete: false, marker: 'counter-snapshot-attestation-missing' };
  }
  const attestationPresent = records.some(
    (record) =>
      record?.source === expectedSnapshot.source
      && record?.type === expectedSnapshot.type
      && record?.runId === runId
      && record?.policyHash === policyHash
      && record?.nonce === expectedSnapshot.nonce
      && record?.evidenceRecordHash === expectedSnapshot.evidenceRecordHash
      && record?.complete === true,
  );
  if (!attestationPresent) {
    return { complete: false, marker: 'counter-snapshot-attestation-missing' };
  }
  const counterPresent = records.some((record) => (
    record?.source === 'managed_gateway'
    && record?.type === 'counter_snapshot'
    && record?.runId === runId
    && record?.policyHash === policyHash
    && record?.complete === true
    && !record?.error
    && hashBuffer(Buffer.from(JSON.stringify(record), 'utf8'))
      === expectedSnapshot.evidenceRecordHash
  ));
  return {
    complete: counterPresent,
    marker: counterPresent
      ? 'policy-and-final-counters-attested'
      : 'counter-snapshot-record-missing',
  };
}

function completionForSource(
  name,
  records,
  stateOk,
  lostEvents,
  adapterState = null,
) {
  if (name === 'managed_dns' && adapterState?.overflow) {
    return {
      complete: false,
      marker:
        adapterState.overflow.lossReason === 'byte_budget_exceeded'
          ? 'managed-dns-byte-budget-exceeded'
          : 'managed-dns-evidence-lost',
    };
  }
  if (adapterState?.evidenceWindow?.ok === false) {
    return {
      complete: false,
      marker:
        adapterState.evidenceWindow.marker || 'evidence-window-invalid',
    };
  }
  if (name === 'managed_gateway') {
    return managedGatewayCompletion(records, adapterState);
  }
  if (!stateOk) {
    return { complete: false, marker: 'collector-shutdown-failed' };
  }
  if (name === 'nosh-l4') {
    const finalStats = records.find(
      (record) => record?.recordKind === 'stats' && record.final === true,
    );
    if (!finalStats) {
      return { complete: false, marker: 'missing-final-stats' };
    }
    return {
      complete: lostEvents === 0,
      marker: lostEvents === 0 ? 'final-stats-clean' : 'final-stats-reported-loss',
    };
  }
  if (name === 'nosh-egress') {
    const expected = adapterState?.readiness?.attestation;
    const finalStatsRecords = records.filter(
      (record) => record?.recordKind === 'stats' && record.final === true,
    );
    if (!finalStatsRecords.length) {
      return { complete: false, marker: 'missing-final-stats' };
    }
    if (finalStatsRecords.length !== 1) {
      return { complete: false, marker: 'duplicate-final-stats' };
    }
    const finalStats = finalStatsRecords[0];
    if (records.at(-1) !== finalStats) {
      return { complete: false, marker: 'final-stats-not-last' };
    }
    const invalid = records.some((record) => {
      if (record?.schemaVersion !== 2) return true;
      if (record.recordKind === 'decision') {
        return !exactFieldInventory(record, NOSH_EGRESS_DECISION_FIELDS)
          || !['allow', 'would-deny', 'deny'].includes(record.verdict)
          || !validNoshEgressReason(record)
          || !validNoshEgressDecisionSemantics(record, expected?.mode)
          || !Number.isInteger(record.hook)
          || ![1, 2, 3, 4, 5, 6].includes(record.hook)
          || !Number.isInteger(record.family)
          || ![0, 4, 6].includes(record.family)
          || !Number.isInteger(record.protocol)
          || ![0, 1, 6, 17, 58].includes(record.protocol)
          || !validNoshEgressAddressPair(record)
          || !unsignedInteger(record.sourcePort, 65535)
          || !unsignedInteger(record.destinationPort, 65535)
          || !unsignedInteger(record.ruleId, 0xffffffff)
          || !unsignedInteger(record.packetBytes, 0xffffffff)
          || !unsignedInteger(record.transactionId, 65_535)
          || !validObservedDomain(record.domain)
          || !decimalCounter(record.timestampMonotonicNs)
          || !decimalCounter(record.cgroupId)
          || !decimalCounter(record.policyGeneration)
          || !decimalCounter(record.expiresMonotonicNs);
      }
      if (record.recordKind === 'dns-answer') {
        return !validNoshEgressDnsAnswer(record);
      }
      if (record.recordKind === 'stats') {
        const names = Object.keys(record.counters || {}).sort();
        return !exactFieldInventory(record, NOSH_EGRESS_STATS_FIELDS)
          || typeof record.final !== 'boolean'
          || !['learn', 'audit', 'enforce'].includes(record.mode)
          || !decimalCounter(record.timestampUnixNs)
          || !decimalCounter(record.cgroupId)
          || !decimalCounter(record.policyGeneration)
          || !decimalCounter(record.eventsSeen)
          || !decimalCounter(record.decoderErrors)
          || !record.counters
          || typeof record.counters !== 'object'
          || Array.isArray(record.counters)
          || names.join(',')
            !== [...NOSH_EGRESS_COUNTER_FIELDS].sort().join(',')
          || NOSH_EGRESS_COUNTER_FIELDS.some(
            (counter) => !decimalCounter(record.counters[counter]),
          );
      }
      return true;
    });
    if (invalid) {
      return { complete: false, marker: 'invalid-nosh-egress-v2-record' };
    }
    let eventsSeen = 0n;
    let priorStats = null;
    for (const record of records) {
      if (['decision', 'dns-answer'].includes(record.recordKind)) {
        eventsSeen += 1n;
        continue;
      }
      const monotonicFields = [
        ['eventsSeen', record.eventsSeen],
        ['decoderErrors', record.decoderErrors],
        ...NOSH_EGRESS_COUNTER_FIELDS.map((counter) => [
          `counters.${counter}`,
          record.counters[counter],
        ]),
      ];
      if (
        BigInt(record.eventsSeen) !== eventsSeen
        || (
          priorStats
          && monotonicFields.some(([field, value]) => (
            BigInt(value) < BigInt(
              field.startsWith('counters.')
                ? priorStats.counters[field.slice('counters.'.length)]
                : priorStats[field]
            )
          ))
        )
      ) {
        return { complete: false, marker: 'nonmonotonic-nosh-egress-stats' };
      }
      priorStats = record;
    }
    const snapshotStats = adapterState?.finalSnapshot?.stats;
    if (
      !expected
      || records.some((record) => (
        String(record.cgroupId) !== String(expected.targetCgroupId)
        || String(record.policyGeneration) !== String(expected.policyGeneration)
        || (
          record.recordKind === 'stats'
          && record.mode !== expected.mode
        )
      ))
      || BigInt(finalStats.eventsSeen) !== BigInt(
        records.filter((record) => (
          record.recordKind === 'decision' || record.recordKind === 'dns-answer'
        )).length,
      )
      || String(finalStats.cgroupId) !== String(expected.targetCgroupId)
      || String(finalStats.policyGeneration) !== String(expected.policyGeneration)
      || finalStats.mode !== expected.mode
      || adapterState?.finalSnapshot?.policyDigest !== expected.policyDigest
      || adapterState?.finalSnapshot?.objectDigest !== expected.objectDigest
      || adapterState?.finalSnapshot?.containmentDigest
        !== expected.containmentDigest
      || adapterState?.finalSnapshot?.containmentCount
        !== expected.containmentCount
      || !exactFieldInventory(snapshotStats, NOSH_EGRESS_STATS_FIELDS)
      || snapshotStats.final !== true
      || snapshotStats.mode !== expected.mode
      || String(snapshotStats.cgroupId) !== String(expected.targetCgroupId)
      || String(snapshotStats.policyGeneration)
        !== String(expected.policyGeneration)
      || decimalCounter(snapshotStats.eventsSeen) !== '0'
      || decimalCounter(snapshotStats.decoderErrors) !== '0'
      || Object.keys(snapshotStats.counters || {}).sort().join(',')
        !== [...NOSH_EGRESS_COUNTER_FIELDS].sort().join(',')
      || NOSH_EGRESS_COUNTER_FIELDS.some(
        (counter) => !decimalCounter(snapshotStats.counters[counter]),
      )
      || stableStringify(snapshotStats.counters)
        !== stableStringify(finalStats.counters)
    ) {
      return { complete: false, marker: 'final-stats-attestation-mismatch' };
    }
    if (!cleanNoshEgressCountersMatch(records, finalStats)) {
      return {
        complete: false,
        marker: 'nosh-egress-counter-evidence-mismatch',
      };
    }
    if (nonzeroCounter(finalStats.counters.backendDenied)) {
      return { complete: false, marker: 'backend-deny-observed' };
    }
    if (EBPF_COVERAGE_COUNTERS.some(
      (counter) => nonzeroCounter(finalStats.counters[counter]),
    )) {
      return { complete: false, marker: 'coverage-gap-observed' };
    }
    return {
      complete: lostEvents === 0,
      marker: lostEvents === 0
        ? 'final-stats-clean'
        : 'final-stats-reported-loss',
    };
  }
  if (name === 'nosh-dns') {
    const finalStats = records.find(
      (record) => record?.recordKind === 'stats' && record.final === true,
    );
    if (!finalStats) {
      return { complete: false, marker: 'missing-final-stats' };
    }
    const invalid = records.some((record) => (
      record?.schemaVersion !== 1
      || record?.source !== 'nosh-dns'
      || typeof record?.runId !== 'string'
      || !/^\d+$/.test(String(record?.cgroupId || ''))
      || !/^\d+$/.test(String(record?.timestampNs || ''))
      || Number.isNaN(Date.parse(record?.observedAt))
      || (record.recordKind === 'event' && (
        !['query', 'response'].includes(record.messageKind)
        || !['udp', 'tcp'].includes(record.transport)
        || !Number.isInteger(record.transactionId)
        || typeof record.qname !== 'string'
        || !record.qname
        || typeof record.qtype !== 'string'
        || !Array.isArray(record.answers)
        || typeof record.truncated !== 'boolean'
        || typeof record.encrypted !== 'boolean'
      ))
      || (record.recordKind === 'stats' && (
        typeof record.final !== 'boolean'
        || !record.counters
        || typeof record.counters !== 'object'
        || Array.isArray(record.counters)
        || !['ringbufDrops', 'parseErrors', 'tcpReassemblyDrops', 'transactionEvictions']
          .every((counter) => Number.isInteger(record.counters[counter]) && record.counters[counter] >= 0)
      ))
    ));
    if (invalid) {
      return { complete: false, marker: 'invalid-nosh-dns-v1-record' };
    }
    return {
      complete: lostEvents === 0,
      marker: lostEvents === 0 ? 'clean-final-stats' : 'collector-reported-loss',
    };
  }
  if (name === 'ig-syscalls') {
    const valid = hasSeccompRecommendation(records);
    return {
      complete: valid,
      marker: valid ? 'advisor-profile-flushed' : 'advisor-profile-missing',
    };
  }
  if (name === 'tetragon-events') {
    return {
      complete: records.length > 0 && lostEvents === 0,
      marker:
        records.length === 0
          ? 'event-stream-empty'
          : lostEvents
            ? 'collector-reported-loss'
            : 'clean-supervised-stop',
    };
  }
  return { complete: lostEvents === 0, marker: 'clean-supervised-stop' };
}

function auditCandidateArtifacts(run) {
  const snapshots = (run.runtimeAttestations || []).filter(
    (entry) =>
      entry?.kind === 'NoshRuntimeArtifactSnapshot'
      && entry?.runId === run.runId,
  );
  const artifacts = snapshots.length === 1 ? snapshots[0].artifacts : {};
  return Object.fromEntries(
    AUDIT_ARTIFACT_FILES.map((filename) => {
      const hash = artifacts?.[filename];
      return [
        filename,
        /^sha256:[a-f0-9]{64}$/.test(hash || '') ? hash : null,
      ];
    }),
  );
}

const EBPF_FATAL_COUNTERS = Object.freeze([
  'ringbufDrops',
  'configInvalid',
  'dnsGrantFailures',
  'backendDenied',
]);

const EBPF_COVERAGE_COUNTERS = Object.freeze([
  'parseErrors',
  'fragments',
  'dnsTransactionMisses',
  'dnsUnsupported',
  'unsupportedProtocol',
  'coverageAllowed',
  'coverageWouldDeny',
  'coverageDenied',
]);

function evaluateEbpfEvidence(records, descriptor, run) {
  const decisions = records.filter((record) => record?.recordKind === 'decision');
  const finalStats = records.findLast(
    (record) => record?.recordKind === 'stats' && record.final === true,
  );
  const counts = Object.fromEntries(
    ['allow', 'would-deny', 'deny'].map((verdict) => [
      verdict,
      decisions.filter((record) => record.verdict === verdict).length,
    ]),
  );
  const decisionClasses = Object.fromEntries(
    [...NOSH_EGRESS_DECISION_CLASSES].sort().map((decisionClass) => [
      decisionClass,
      decisions.filter((record) => record.decisionClass === decisionClass).length,
    ]),
  );
  const fatalCounters = Object.fromEntries([
    ['decoderErrors', decimalCounter(finalStats?.decoderErrors)],
    ...EBPF_FATAL_COUNTERS.map((name) => [
      name,
      decimalCounter(finalStats?.counters?.[name]),
    ]),
  ]);
  const unresolved = [];
  for (const [name, value] of Object.entries(fatalCounters)) {
    if (value == null || value !== '0') {
      unresolved.push({
        kind: 'fatal-counter',
        name,
        value,
      });
    }
  }
  const coverageCounters = Object.fromEntries(
    EBPF_COVERAGE_COUNTERS.map((name) => [
      name,
      decimalCounter(finalStats?.counters?.[name]),
    ]),
  );
  for (const [name, value] of Object.entries(coverageCounters)) {
    if (value == null || value !== '0') {
      unresolved.push({
        kind: 'coverage-gap',
        name,
        value,
      });
    }
  }
  const containmentDenied = decimalCounter(
    finalStats?.counters?.containmentDenied,
  );
  if (containmentDenied == null || containmentDenied !== '0') {
    unresolved.push({
      kind: 'platform-containment',
      name: 'containmentDenied',
      value: containmentDenied,
    });
  }
  const reasonCounts = new Map();
  for (const decision of decisions) {
    if ([6, 7, 8, 10, 11, 14, 15].includes(decision.reasonCode)) {
      reasonCounts.set(
        decision.reasonCode,
        (reasonCounts.get(decision.reasonCode) || 0) + 1,
      );
    }
    if (
      decision.ruleId !== 0
      && !Object.hasOwn(run.egress?.ruleIdMap || {}, String(decision.ruleId))
    ) {
      unresolved.push({
        kind: 'unknown-rule-id',
        ruleId: decision.ruleId,
      });
    }
  }
  for (const [reasonCode, count] of [...reasonCounts.entries()]
    .sort(([left], [right]) => left - right)) {
    unresolved.push({
      kind: 'unsupported-decision',
      reasonCode,
      count,
    });
  }
  const uniqueUnresolved = [...new Map(
    unresolved.map((entry) => [stableStringify(entry), entry]),
  ).values()];
  return {
    schemaVersion: 2,
    backend: 'nosh-egress',
    backendAbi: run.egress?.backendAbi || null,
    objectDigest: run.egress?.objectDigest || null,
    policyDigest: run.egress?.policyDigest || null,
    targetContextHash: run.egress?.targetContextHash || null,
    ruleIdMap: { ...(run.egress?.ruleIdMap || {}) },
    counts,
    decisionClasses,
    fatalCounters,
    coverageCounters,
    containmentDenied,
    unresolved: uniqueUnresolved,
    eligible: descriptor?.complete === true && uniqueUnresolved.length === 0,
  };
}

export async function managedGatewayDecisionCounts(filePath, run) {
  try {
    const content = await fs.readFile(filePath, 'utf8');
    const epochs = new Map();
    for (const line of content.split(/\r?\n/).filter(Boolean)) {
      const record = JSON.parse(line);
      if (
        record?.source !== 'managed_gateway'
        || record?.type !== 'counter_snapshot'
        || record?.runId !== run.runId
        || record?.policyHash !== run.egress?.policyHash
      ) {
        continue;
      }
      const candidateWouldDeny = Number(record.wouldDenyCount || 0);
      const candidateDenied = Number(record.deniedCount || 0);
      if (
        Number.isSafeInteger(candidateWouldDeny)
        && candidateWouldDeny >= 0
        && Number.isSafeInteger(candidateDenied)
        && candidateDenied >= 0
      ) {
        const session = typeof record.counterSession === 'string'
          && /^[a-f0-9-]{16,64}$/i.test(record.counterSession)
          ? record.counterSession
          : 'legacy';
        const epoch = Number.isSafeInteger(record.counterEpoch)
          && record.counterEpoch >= 0
          ? `${session}:epoch:${record.counterEpoch}`
          : `${session}:legacy`;
        const counts = epochs.get(epoch) || {
          wouldDenyCount: 0,
          deniedCount: 0,
        };
        counts.wouldDenyCount = Math.max(
          counts.wouldDenyCount,
          candidateWouldDeny,
        );
        counts.deniedCount = Math.max(counts.deniedCount, candidateDenied);
        epochs.set(epoch, counts);
      }
    }
    return [...epochs.values()].reduce(
      (total, counts) => ({
        wouldDenyCount: total.wouldDenyCount + counts.wouldDenyCount,
        deniedCount: total.deniedCount + counts.deniedCount,
      }),
      { wouldDenyCount: 0, deniedCount: 0 },
    );
  } catch {
    return { wouldDenyCount: 0, deniedCount: 0 };
  }
}

async function currentAuditEvaluation(run, managedGatewayPath) {
  const { wouldDenyCount: networkWouldDenyCount } =
    await managedGatewayDecisionCounts(managedGatewayPath, run);
  return {
    schemaVersion: 1,
    candidateArtifacts: auditCandidateArtifacts(run),
    backends: {
      tetragon: {
        evaluator: 'tetragon-shadow-policy-unavailable',
        complete: false,
        wouldDenyCount: 0,
        reason:
          'the candidate Tetragon policy is not evaluated in audit mode',
      },
      seccomp: {
        evaluator: 'seccomp-log-collector-unavailable',
        complete: false,
        wouldDenyCount: 0,
        reason:
          'SCMP_ACT_LOG decisions are not collected and attributed to the run',
      },
      apparmor: {
        evaluator: 'apparmor-complain-collector-unavailable',
        complete: false,
        wouldDenyCount: 0,
        reason:
          'AppArmor complain decisions are not collected and attributed to the run',
      },
      docker: {
        evaluator: 'docker-runtime-conformance-unattested',
        complete: false,
        wouldDenyCount: 0,
        reason:
          'runtime conformance is checked at admission but lacks a final audit attestation',
      },
      network: {
        evaluator: 'managed-gateway-egress-only',
        complete: false,
        wouldDenyCount: networkWouldDenyCount,
        reason:
          'managed gateway counters evaluate egress but not the artifact ingress policy',
      },
    },
  };
}

export function dnsNameMatches(pattern, name) {
  if (pattern.startsWith('*.')) {
    const suffix = pattern.slice(2);
    if (!name.endsWith(`.${suffix}`)) return false;
    const prefix = name.slice(0, -(suffix.length + 1));
    return Boolean(prefix) && !prefix.includes('.');
  }
  return name === pattern;
}

async function managedDnsPolicyDecisionCount(run, managedDnsPath) {
  try {
    const [policySource, dnsSource] = await Promise.all([
      fs.readFile(
        path.join(
          run.evidenceDir,
          'egress-profile-snapshot',
          'egress-policy.json',
        ),
        'utf8',
      ),
      fs.readFile(managedDnsPath, 'utf8'),
    ]);
    const policy = JSON.parse(policySource);
    const patterns = (policy.spec?.egress || [])
      .map((rule) => String(rule.destination || '').toLowerCase())
      .filter((destination) => destination && !destination.includes('/'));
    let count = 0;
    for (const line of dnsSource.split(/\r?\n/).filter(Boolean)) {
      const record = JSON.parse(line);
      const name = String(record.qname || '').toLowerCase().replace(/\.$/, '');
      if (
        record.source === 'managed_dns'
        && record.type === 'query'
        && name
        && !patterns.some((pattern) => dnsNameMatches(pattern, name))
      ) {
        count += 1;
      }
    }
    return { ok: true, count, error: null };
  } catch (error) {
    return {
      ok: false,
      count: 0,
      error: `DNS policy evaluation failed: ${error.code || 'invalid evidence'}`,
    };
  }
}

async function currentEgressEvaluation(
  run,
  managedGatewayPath,
  managedDnsPath,
  complete,
) {
  const { wouldDenyCount, deniedCount } =
    await managedGatewayDecisionCounts(managedGatewayPath, run);
  const dnsEvaluation = await managedDnsPolicyDecisionCount(
    run,
    managedDnsPath,
  );
  const policyHashValid = /^sha256:[a-f0-9]{64}$/.test(
    run.profilePolicyHash || '',
  );
  return {
    schemaVersion: 1,
    policyHash: run.profilePolicyHash || null,
    wouldDenyCount,
    deniedCount,
    dnsWouldDenyCount:
      run.mode === 'egress-audit' ? dnsEvaluation.count : 0,
    dnsDeniedCount:
      run.mode === 'egress-enforce' ? dnsEvaluation.count : 0,
    dnsEvaluationComplete: complete && dnsEvaluation.ok,
    dnsEvaluationError: complete
      ? dnsEvaluation.error
      : 'required managed DNS evidence is incomplete',
    complete: complete && dnsEvaluation.ok && policyHashValid,
  };
}

async function sourceDescriptor(name, filePath, required, adapterState = null) {
  if (!filePath) {
    return {
      name,
      path: null,
      format: name === 'ig-syscalls' ? 'ig-seccomp-advice' : 'ndjson',
      required,
      present: false,
      bytes: 0,
      records: 0,
      hash: null,
      lostEvents: 0,
      parseErrors: 0,
      completionMarker: 'evidence-path-missing',
      adapterState,
      complete: !required,
      error: 'evidence path is missing',
    };
  }
  try {
    const content = await fs.readFile(filePath);
    const parsed = recordsFromJson(content, name);
    const lostEvents = Math.max(
      evidenceLoss(parsed.records),
      nonnegativeCounter(adapterState?.lostEvents),
    );
    const stateOk =
      adapterState?.ok !== false &&
      !adapterState?.error &&
      adapterState?.verification?.ok !== false;
    const completion = completionForSource(
      name,
      parsed.records,
      stateOk,
      lostEvents,
      adapterState,
    );
    let diagnostics = null;
    if (adapterState?.diagnosticsPath) {
      try {
        const diagnosticContent = await fs.readFile(adapterState.diagnosticsPath);
        diagnostics = {
          path: adapterState.diagnosticsPath,
          bytes: diagnosticContent.length,
          hash: hashBuffer(diagnosticContent),
        };
      } catch (error) {
        if (error.code !== 'ENOENT') {
          throw error;
        }
      }
    }
    return {
      name,
      path: filePath,
      format: name === 'ig-syscalls' ? 'ig-seccomp-advice' : 'ndjson',
      required,
      present: true,
      bytes: content.length,
      records: parsed.records.length,
      hash: hashBuffer(content),
      lostEvents,
      parseErrors: parsed.parseErrors,
      completionMarker: completion.marker,
      diagnostics,
      adapterState,
      complete:
        parsed.parseErrors === 0 &&
        completion.complete,
    };
  } catch (error) {
    if (error.code !== 'ENOENT') {
      throw error;
    }
    return {
      name,
      path: filePath,
      format: name === 'ig-syscalls' ? 'ig-seccomp-advice' : 'ndjson',
      required,
      present: false,
      bytes: 0,
      records: 0,
      hash: null,
      lostEvents: 0,
      parseErrors: 0,
      completionMarker: 'evidence-file-missing',
      adapterState,
      complete: !required,
      error: 'evidence file is missing',
    };
  }
}

export async function finalizeRunEvidence(run, options = {}) {
  const sharedDir = path.join(options.stateDir, 'egress', 'evidence');
  const scopedEgress = ['egress-learn', 'egress-audit', 'egress-enforce']
    .includes(run.mode);
  const [managedDns, managedGateway] = scopedEgress
    ? [{ path: null }, { path: null }]
    : await Promise.all([
        copyManagedDns(run, sharedDir),
        copyManagedGateway(run, sharedDir),
      ]);
  const detachByName = new Map(
    (run.detachResults || []).map((entry) => [entry.name, entry]),
  );
  const descriptors = [];
  for (const adapter of run.adapters || []) {
    if (adapter.evidence === false) {
      continue;
    }
    const detachState = detachByName.get(adapter.name);
    const adapterState = detachState ? { ...adapter, ...detachState } : adapter;
    descriptors.push(
      await sourceDescriptor(
        adapter.name,
        adapter.logPath,
        adapter.required !== false,
        adapter.name === 'nosh-egress'
          ? {
              ...adapterState,
              finalSnapshot: run.egress?.finalSnapshot || null,
              finalSnapshotError: run.egress?.finalSnapshotError || null,
            }
          : adapterState,
      ),
    );
  }
  if (!scopedEgress) {
    descriptors.push(
      await sourceDescriptor('managed_dns', managedDns.path, true, {
      ok: run.egress?.acknowledgement?.runId === run.runId,
      evidenceWindow: managedDns.evidenceWindow,
      finalSnapshot: managedDns.finalSnapshot,
      overflow: managedDns.overflow,
      lostEvents: managedDns.lostEvents,
      }),
    );
    descriptors.push(
      await sourceDescriptor('managed_gateway', managedGateway.path, true, {
      ok:
        run.egress?.acknowledgement?.runId === run.runId
        && run.egress?.acknowledgement?.policyHash === run.egress?.policyHash
        && run.egress?.finalSnapshot?.runId === run.runId
        && run.egress?.finalSnapshot?.policyHash === run.egress?.policyHash
        && run.egress?.finalSnapshot?.complete === true,
      runId: run.runId,
      policyHash: run.egress?.policyHash,
      finalSnapshot: run.egress?.finalSnapshot || null,
      snapshotError: run.egress?.finalSnapshotError || null,
      evidenceWindow: managedGateway.evidenceWindow,
      }),
    );
  }
  const modeRequiredSources = REQUIRED_SOURCES_BY_MODE[run.mode];
  if (!options.requiredSources && !modeRequiredSources) {
    throw new TypeError(`unsupported evidence mode: ${run.mode}`);
  }
  const requiredNames = new Set(
    options.requiredSources || modeRequiredSources,
  );
  for (const descriptor of descriptors) {
    descriptor.required = requiredNames.has(descriptor.name);
    if (descriptor.required && !descriptor.present) {
      descriptor.complete = false;
    }
  }
  for (const name of requiredNames) {
    if (!descriptors.some((descriptor) => descriptor.name === name)) {
      descriptors.push({
        name,
        path: null,
        required: true,
        present: false,
        bytes: 0,
        records: 0,
        hash: null,
        lostEvents: 0,
        parseErrors: 0,
        completionMarker: 'adapter-did-not-run',
        complete: false,
        error: 'required evidence adapter did not run',
      });
    }
  }
  descriptors.sort((left, right) => left.name.localeCompare(right.name));
  const auditEvaluation =
    run.mode === 'audit'
      ? await currentAuditEvaluation(run, managedGateway.path)
      : null;
  let egressEvaluation =
    !scopedEgress && ['egress-audit', 'egress-enforce'].includes(run.mode)
      ? await currentEgressEvaluation(
          run,
          managedGateway.path,
          managedDns.path,
          descriptors
            .filter((descriptor) => descriptor.required)
            .every((descriptor) => descriptor.complete),
        )
      : null;
  const diagnosticOnly = [
    'enforce',
    'egress-audit',
    'egress-enforce',
  ].includes(run.mode);
  const requiredSourcesComplete = descriptors
    .filter((descriptor) => descriptor.required)
    .every((descriptor) => descriptor.complete);
  let ebpfEgressEvaluation = null;
  if (scopedEgress) {
    const descriptor = descriptors.find((entry) => entry.name === 'nosh-egress');
    const records = descriptor?.present
      ? recordsFromJson(await fs.readFile(descriptor.path), 'nosh-egress').records
      : [];
    ebpfEgressEvaluation = evaluateEbpfEvidence(records, descriptor, run);
    const counts = ebpfEgressEvaluation.counts;
    egressEvaluation = {
      schemaVersion: 1,
      policyHash: run.profilePolicyHash || run.egress?.policyDigest || null,
      wouldDenyCount: counts['would-deny'],
      deniedCount: counts.deny,
      dnsWouldDenyCount: 0,
      dnsDeniedCount: 0,
      dnsEvaluationComplete: descriptor?.complete === true,
      dnsEvaluationError: descriptor?.complete === true
        ? null
        : 'required nosh-egress evidence is incomplete',
      complete: descriptor?.complete === true,
      backend: 'nosh-egress',
    };
  }
  const manifest = {
    schemaVersion: 1,
    apiVersion: 'notty.dev/v1alpha1',
    kind: 'NoshSecurityEvidenceManifest',
    generatedAt: new Date().toISOString(),
    runId: run.runId,
    mode: run.mode,
    subject: {
      containerId: run.containerId || null,
      containerName: run.name || null,
      image: run.imageReference || run.imageRequested || null,
      imageDigest: run.imageDigest || null,
      workspace: run.workdir || null,
      workspaceIdentity: run.workspaceIdentity || null,
    },
    startedAt: run.releasedAt || run.createdAt || null,
    endedAt: new Date().toISOString(),
    profileRevision: run.profileRevision,
    ...(auditEvaluation ? { auditEvaluation } : {}),
    ...(egressEvaluation ? { egressEvaluation } : {}),
    ...(ebpfEgressEvaluation ? { ebpfEgressEvaluation } : {}),
    trainingEligible: !diagnosticOnly,
    evidenceUse: diagnosticOnly ? 'diagnostic-only' : 'training',
    complete:
      run.evidenceComplete !== false &&
      requiredSourcesComplete &&
      (!ebpfEgressEvaluation || ebpfEgressEvaluation.eligible === true) &&
      (!egressEvaluation || egressEvaluation.complete === true),
    sources: descriptors,
  };
  const manifestPath = path.join(run.evidenceDir, 'evidence-manifest.json');
  await fs.writeFile(manifestPath, `${JSON.stringify(manifest, null, 2)}\n`, {
    mode: 0o600,
  });
  return { manifestPath, manifest };
}
