import crypto from 'node:crypto';
import fs from 'node:fs/promises';
import { constants as fsConstants } from 'node:fs';
import os from 'node:os';
import path from 'node:path';

import { serializeJson, sha256, stableStringify } from '../guard/stable.js';
import {
  BUILD_ARTIFACT_KINDS,
  BUILD_PROFILE_API_VERSION,
  BUILD_PROFILE_SCHEMA_VERSION,
  buildProjectKey,
  createBuildEvidenceManifest,
  createBuildNetworkCandidate,
  createBuildNetworkPolicyDraft,
  createBuildProfileCandidate,
  createPortableBundleManifest,
  normalizeBuildMode,
  redactBuildValue,
  requiredBuildEvidenceSources,
  safeBuildSegment,
  validateBuildEvidenceManifest,
  validateBuildNetworkPolicyDraft,
  verifyBuildCandidate,
} from './build-profile-artifacts.js';
import {
  createBuildProfileReport,
  createPortableBuildReport,
  renderPortableBuildReport,
  renderBuildProfileReport,
} from './build-profile-report.js';

export const BUILD_PROFILE_FILES = Object.freeze({
  evidence: 'evidence-manifest.json',
  profileCandidate: 'build-profile-candidate.json',
  networkCandidate: 'build-network-candidate.json',
  networkPolicyDraft: 'build-network-policy-draft.json',
  report: 'report.json',
  reportText: 'report.txt',
  portableDirectory: 'portable',
  portableManifest: 'portable-bundle.json',
  runState: 'run.json',
  latestCandidate: 'latest-candidate.json',
});

const MAX_DOCUMENT_BYTES = 64 * 1024 * 1024;
const MAX_PASS_SOURCE_BYTES = 128 * 1024 * 1024;
const MAX_BUILD_PASSES = 2;
const MAX_PASS_BOUNDARY_BYTES = Math.max(
  ...['cold', 'warm'].map((pass) => Buffer.byteLength(
    `${JSON.stringify({ schemaVersion: 1, recordKind: 'pass_boundary', pass })}\n`,
    'utf8',
  )),
);
// collectorRecords() canonicalizes a final unterminated JSONL record by adding
// one newline in addition to the pass boundary.
const MAX_PASS_FRAMING_BYTES = MAX_PASS_BOUNDARY_BYTES + 1;
const MAX_COMBINED_SOURCE_BYTES = MAX_BUILD_PASSES
  * (MAX_PASS_SOURCE_BYTES + MAX_PASS_FRAMING_BYTES);
const MAX_BUILDX_HISTORY_REASON_CHARS = 512;
const mutationQueues = new Map();

function passSourceByteLimit(value = MAX_PASS_SOURCE_BYTES) {
  const selected = Number(value);
  if (
    !Number.isSafeInteger(selected)
    || selected < 1
    || selected > MAX_PASS_SOURCE_BYTES
  ) {
    throw new TypeError(
      `maxPassSourceBytes must be from 1 to ${MAX_PASS_SOURCE_BYTES}`,
    );
  }
  return selected;
}

function combinedSourceByteLimit(passCount, maximumPassBytes = MAX_PASS_SOURCE_BYTES) {
  const selectedPassCount = Number(passCount);
  if (
    !Number.isSafeInteger(selectedPassCount)
    || selectedPassCount < 1
    || selectedPassCount > MAX_BUILD_PASSES
  ) {
    throw new TypeError(`combined build profile supports 1 to ${MAX_BUILD_PASSES} passes`);
  }
  return selectedPassCount * (
    passSourceByteLimit(maximumPassBytes) + MAX_PASS_FRAMING_BYTES
  );
}

function aggregatePassCount(input) {
  const passes = input?.build?.passes || input?.passes;
  if (!Array.isArray(passes) || passes.length === 0) return 1;
  if (passes.length > MAX_BUILD_PASSES) {
    throw new TypeError(`combined build profile supports at most ${MAX_BUILD_PASSES} passes`);
  }
  return passes.length;
}

export function defaultBuildProfileRoots(home = os.homedir()) {
  const base = path.join(path.resolve(home), '.nosh');
  return {
    profile: path.join(base, 'build-profiles'),
    network: path.join(base, 'build-net-profiles'),
  };
}

function rootOptions(input = {}) {
  if (typeof input === 'string') return { profileRoot: input };
  if (!input || typeof input !== 'object' || Array.isArray(input)) {
    throw new TypeError('build profile store options must be an object');
  }
  return input;
}

async function secureDirectory(directory) {
  const resolved = path.resolve(directory);
  await fs.mkdir(resolved, { recursive: true, mode: 0o700 });
  const stat = await fs.lstat(resolved);
  if (!stat.isDirectory() || stat.isSymbolicLink()) {
    throw new Error(`build profile path is not a directory: ${resolved}`);
  }
  const expectedUid = typeof process.geteuid === 'function'
    ? process.geteuid()
    : null;
  if (expectedUid != null && stat.uid !== expectedUid) {
    throw new Error(`build profile directory must be owned by uid ${expectedUid}: ${resolved}`);
  }
  await fs.chmod(resolved, 0o700);
  return resolved;
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

async function writeExclusive(file, content) {
  const handle = await fs.open(
    file,
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

async function atomicWrite(file, content) {
  const temporary = `${file}.${process.pid}.${crypto.randomUUID()}.tmp`;
  try {
    await writeExclusive(temporary, content);
    await fs.rename(temporary, file);
    await syncDirectory(path.dirname(file));
  } catch (error) {
    await fs.unlink(temporary).catch(() => {});
    throw error;
  }
}

async function trustedFile(file, maximumBytes = MAX_DOCUMENT_BYTES) {
  const handle = await fs.open(file, fsConstants.O_RDONLY | (fsConstants.O_NOFOLLOW || 0));
  try {
    const stat = await handle.stat();
    const expectedUid = typeof process.geteuid === 'function'
      ? process.geteuid()
      : null;
    if (!stat.isFile() || stat.nlink !== 1) {
      throw new Error(`build profile artifact is not a singly-linked file: ${file}`);
    }
    if (expectedUid != null && stat.uid !== expectedUid) {
      throw new Error(`build profile artifact has an unexpected owner: ${file}`);
    }
    if ((stat.mode & 0o7777) !== 0o600) {
      throw new Error(`build profile artifact mode must be 600: ${file}`);
    }
    if (stat.size > maximumBytes) {
      throw new Error(`build profile artifact is too large: ${file}`);
    }
    return handle.readFile();
  } finally {
    await handle.close();
  }
}

async function trustedJson(file) {
  const content = await trustedFile(file);
  try {
    return { content, document: JSON.parse(content.toString('utf8')) };
  } catch (error) {
    throw new Error(`build profile artifact is not valid JSON: ${file}`, { cause: error });
  }
}

function safeRelativeFile(value, label) {
  if (typeof value !== 'string' || !value.trim() || path.isAbsolute(value)) {
    throw new TypeError(`${label} must be a relative filename`);
  }
  const normalized = path.posix.normalize(value.replaceAll('\\', '/'));
  if (normalized === '..' || normalized.startsWith('../')) {
    throw new TypeError(`${label} escapes its bundle`);
  }
  return normalized;
}

async function canonicalProjectBinding(context) {
  if (typeof context !== 'string' || !context.trim()) {
    throw new TypeError('build context is required');
  }
  const canonicalPath = await fs.realpath(path.resolve(context));
  const stat = await fs.stat(canonicalPath, { bigint: true });
  if (!stat.isDirectory()) throw new Error(`build context must be a directory: ${canonicalPath}`);
  return {
    canonicalPath,
    key: buildProjectKey(canonicalPath),
    dev: String(stat.dev),
    ino: String(stat.ino),
  };
}

async function hashFile(file, maximumBytes = MAX_COMBINED_SOURCE_BYTES) {
  const handle = await fs.open(file, fsConstants.O_RDONLY | (fsConstants.O_NOFOLLOW || 0));
  try {
    const stat = await handle.stat();
    if (!stat.isFile() || stat.nlink !== 1 || stat.size > maximumBytes) {
      throw new Error(`build evidence source is not a supported regular file: ${file}`);
    }
    const hash = crypto.createHash('sha256');
    let records = 0;
    let lastByte = null;
    for await (const chunk of handle.createReadStream({ autoClose: false })) {
      hash.update(chunk);
      for (const byte of chunk) {
        if (byte === 0x0a) records += 1;
        lastByte = byte;
      }
    }
    if (stat.size > 0 && lastByte !== 0x0a) records += 1;
    return {
      bytes: stat.size,
      hash: `sha256:${hash.digest('hex')}`,
      records,
    };
  } finally {
    await handle.close();
  }
}

function extensionForFormat(format) {
  if (format === 'json') return 'json';
  if (format === 'text' || format === 'rawjson') return 'txt';
  if (format === 'collapsed') return 'collapsed';
  return 'ndjson';
}

async function sourceContent(source, maximumBytes = MAX_COMBINED_SOURCE_BYTES) {
  if (source.content != null) {
    if (Buffer.isBuffer(source.content)) return source.content;
    if (typeof source.content === 'string') return Buffer.from(source.content, 'utf8');
    return Buffer.from(serializeJson(source.content), 'utf8');
  }
  if (source.sourcePath) {
    const sourcePath = path.resolve(source.sourcePath);
    return trustedFile(sourcePath, maximumBytes);
  }
  return null;
}

async function optionalPiece(
  file,
  pass,
  label,
  transform = null,
  expectedFile = null,
) {
  if (!file) {
    return { content: null, error: `${label} is missing` };
  }
  try {
    const content = await trustedFile(path.resolve(file), MAX_PASS_SOURCE_BYTES);
    if (
      expectedFile?.bytes != null
      && Number(expectedFile.bytes) !== content.length
    ) {
      throw new Error(`${label} size does not match its privileged manifest`);
    }
    if (
      expectedFile?.sha256
      && expectedFile.sha256 !== sha256(content)
    ) {
      throw new Error(`${label} hash does not match its privileged manifest`);
    }
    if (transform) return { content: transform(content, pass), error: null };
    const boundary = Buffer.from(
      `${JSON.stringify({ schemaVersion: 1, recordKind: 'pass_boundary', pass })}\n`,
      'utf8',
    );
    return { content: Buffer.concat([boundary, content]), error: null };
  } catch {
    return { content: null, error: `${label} is unavailable or untrusted` };
  }
}

function boundedEvidenceFailureReason(value) {
  if (typeof value !== 'string' || !value) return null;
  const sanitized = value
    .replace(/\x1b\[[0-?]*[ -/]*[@-~]/g, '')
    .replace(/[\x00-\x1f\x7f-\x9f]+/g, ' ')
    .replace(/\s+/g, ' ')
    .trim();
  if (!sanitized) return null;
  return sanitized.length <= MAX_BUILDX_HISTORY_REASON_CHARS
    ? sanitized
    : `${sanitized.slice(0, MAX_BUILDX_HISTORY_REASON_CHARS - 3)}...`;
}

function passName(value, cacheMode, mode) {
  if (value === 'cold' || value === 'warm') return value;
  if (mode === 'build-net-learn') return 'cold';
  return cacheMode === 'warm' ? 'warm' : 'cold';
}

function sourcePathFromManifest(entry, source) {
  const selected = source?.file?.path || source?.file || null;
  if (!selected) return null;
  if (path.isAbsolute(selected)) return selected;
  const evidenceDirectory = entry.evidenceDir
    || (entry.manifestPath ? path.dirname(entry.manifestPath) : null);
  return evidenceDirectory ? path.resolve(evidenceDirectory, selected) : null;
}

function jsonRecord(content, pass, field) {
  const document = JSON.parse(content.toString('utf8'));
  return Buffer.from(`${JSON.stringify({ pass, [field]: document })}\n`, 'utf8');
}

function cgroupSnapshotRecord(content, pass, field) {
  const document = JSON.parse(content.toString('utf8'));
  const required = [
    'cpu.stat',
    'cpu.pressure',
    'io.stat',
    'io.pressure',
    'memory.current',
    'memory.events',
    'memory.pressure',
    'pids.current',
  ];
  const missing = required.filter((name) => (
    typeof document?.[name] !== 'string'
    || (name !== 'io.stat' && !document[name].trim())
  ));
  if (missing.length) {
    throw new Error(`cgroup snapshot is missing required metrics: ${missing.join(', ')}`);
  }
  return Buffer.from(`${JSON.stringify({ pass, [field]: document })}\n`, 'utf8');
}

function ndjsonRecords(content, pass) {
  const lines = content.toString('utf8').split(/\r?\n/).filter(Boolean);
  for (const line of lines) JSON.parse(line);
  const boundary = Buffer.from(
    `${JSON.stringify({ schemaVersion: 1, recordKind: 'pass_boundary', pass })}\n`,
    'utf8',
  );
  return Buffer.concat([boundary, content]);
}

function buildkitProgressRecords(content, pass) {
  const lines = content.toString('utf8').split(/\r?\n/).filter(Boolean);
  const records = lines.map((line) => JSON.parse(line));
  const vertices = new Map();
  for (const record of records) {
    for (const vertex of record.vertexes || []) {
      if (vertex?.digest) {
        vertices.set(vertex.digest, { ...vertices.get(vertex.digest), ...vertex });
      }
    }
  }
  if (!records.length || !vertices.size) {
    throw new Error('BuildKit progress has no vertex records');
  }
  if ([...vertices.values()].some((vertex) => !vertex.completed)) {
    throw new Error('BuildKit progress ended before every observed vertex completed');
  }
  return ndjsonRecords(content, pass);
}

function collectorRecords(content, pass, sourceName) {
  const selected = [];
  for (const line of content.toString('utf8').split(/\r?\n/).filter(Boolean)) {
    const record = JSON.parse(line);
    const shared = ['capabilities', 'stats', 'final_stats'].includes(
      record.recordKind,
    );
    const matches = sourceName === 'ebpf-process'
      ? ['process-exec', 'process-exit'].includes(record.eventKind)
      : sourceName === 'ebpf-syscall'
        ? record.recordKind === 'syscall-summary'
        : sourceName === 'dns'
          ? ['dns-query', 'dns-response'].includes(record.eventKind)
          : sourceName === 'ebpf-file'
            ? record.recordKind === 'file-summary'
            : false;
    if (shared || matches) {
      selected.push(`${JSON.stringify(record)}\n`);
    }
  }
  return Buffer.concat([
    Buffer.from(
      `${JSON.stringify({ schemaVersion: 1, recordKind: 'pass_boundary', pass })}\n`,
      'utf8',
    ),
    Buffer.from(selected.join(''), 'utf8'),
  ]);
}

function decimalCounter(value) {
  const normalized = String(value ?? '');
  return /^(0|[1-9][0-9]*)$/.test(normalized) ? normalized : null;
}

function noshBuildDiagnostics(pass, completion) {
  const final = completion?.final;
  if (!final || typeof final !== 'object' || Array.isArray(final)) return null;
  return {
    pass,
    finalTimestampUnixNs: decimalCounter(final.timestampUnixNs),
    inflightSyscalls: decimalCounter(final.inflightSyscalls),
    dnsParseErrors: decimalCounter(final.counters?.dnsParseErrors),
    dnsCompressedNames: decimalCounter(final.counters?.dnsCompressedNames),
    dnsTruncatedNames: decimalCounter(final.counters?.dnsTruncatedNames),
    dnsTruncatedResponses: decimalCounter(final.counters?.dnsTruncatedResponses),
    dnsAnswerLimitReached: decimalCounter(final.counters?.dnsAnswerLimitReached),
    dnsUnsupportedAnswers: decimalCounter(final.counters?.dnsUnsupportedAnswers),
    dnsCorrelationMissing: decimalCounter(final.counters?.dnsCorrelationMissing),
    dnsQueryObservations: decimalCounter(final.counters?.dnsQueryObservations),
    dnsResponseObservations: decimalCounter(final.counters?.dnsResponseObservations),
    dnsNamePointers: decimalCounter(final.counters?.dnsNamePointers),
    fileMapFull: decimalCounter(final.counters?.fileMapFull),
    filePathErrors: decimalCounter(final.counters?.filePathErrors),
    fileOpenObservations: decimalCounter(final.counters?.fileOpenObservations),
    fileSummaryRecords: decimalCounter(final.fileSummaryRecords),
  };
}

function sumDiagnosticField(records, field) {
  let total = 0n;
  for (const record of records) {
    if (record[field] == null) return null;
    total += BigInt(record[field]);
  }
  return total.toString();
}

function combinedCollectorDiagnostics(records, expectedPasses) {
  const totals = {
    inflightSyscalls: sumDiagnosticField(records, 'inflightSyscalls'),
    dnsParseErrors: sumDiagnosticField(records, 'dnsParseErrors'),
    dnsCompressedNames: sumDiagnosticField(records, 'dnsCompressedNames'),
    dnsTruncatedNames: sumDiagnosticField(records, 'dnsTruncatedNames'),
    dnsTruncatedResponses: sumDiagnosticField(records, 'dnsTruncatedResponses'),
    dnsAnswerLimitReached: sumDiagnosticField(records, 'dnsAnswerLimitReached'),
    dnsUnsupportedAnswers: sumDiagnosticField(records, 'dnsUnsupportedAnswers'),
    dnsCorrelationMissing: sumDiagnosticField(records, 'dnsCorrelationMissing'),
    dnsQueryObservations: sumDiagnosticField(records, 'dnsQueryObservations'),
    dnsResponseObservations: sumDiagnosticField(records, 'dnsResponseObservations'),
    dnsNamePointers: sumDiagnosticField(records, 'dnsNamePointers'),
    fileMapFull: sumDiagnosticField(records, 'fileMapFull'),
    filePathErrors: sumDiagnosticField(records, 'filePathErrors'),
    fileOpenObservations: sumDiagnosticField(records, 'fileOpenObservations'),
    fileSummaryRecords: sumDiagnosticField(records, 'fileSummaryRecords'),
  };
  const allFinalStatsPresent = records.length === expectedPasses
    && records.every((record) => record.finalTimestampUnixNs != null);
  return {
    passes: records,
    totals,
    allFinalStatsPresent,
    syscallDurationTotalsComplete:
      allFinalStatsPresent && totals.inflightSyscalls === '0',
    dnsNameCoverageComplete:
      allFinalStatsPresent
      && totals.dnsParseErrors === '0'
      && totals.dnsCompressedNames === '0'
      && totals.dnsTruncatedNames === '0'
      && totals.dnsTruncatedResponses === '0'
      && totals.dnsAnswerLimitReached === '0'
      && totals.dnsUnsupportedAnswers === '0'
      && totals.dnsCorrelationMissing === '0',
  };
}

function collectorDiagnosticLimitations(diagnostics) {
  const limitations = [];
  const { totals } = diagnostics;
  if (totals.inflightSyscalls != null && totals.inflightSyscalls !== '0') {
    limitations.push(
      `${totals.inflightSyscalls} syscalls were still active at collector shutdown; syscall duration totals are incomplete.`,
    );
  }
  if (totals.dnsParseErrors != null && totals.dnsParseErrors !== '0') {
    limitations.push(
      `${totals.dnsParseErrors} DNS query names could not be parsed by the build collector.`,
    );
  }
  if (totals.dnsCompressedNames != null && totals.dnsCompressedNames !== '0') {
    limitations.push(
      `${totals.dnsCompressedNames} compressed DNS query names were not decoded by the build collector.`,
    );
  }
  if (totals.dnsTruncatedNames != null && totals.dnsTruncatedNames !== '0') {
    limitations.push(
      `${totals.dnsTruncatedNames} DNS query names were truncated by the build collector.`,
    );
  }
  if (
    totals.dnsTruncatedResponses != null
    && totals.dnsTruncatedResponses !== '0'
  ) {
    limitations.push(
      `${totals.dnsTruncatedResponses} truncated DNS responses could not supply complete answer snapshots.`,
    );
  }
  if (
    totals.dnsAnswerLimitReached != null
    && totals.dnsAnswerLimitReached !== '0'
  ) {
    limitations.push(
      `${totals.dnsAnswerLimitReached} DNS responses exceeded the bounded answer capture limit.`,
    );
  }
  if (
    totals.dnsUnsupportedAnswers != null
    && totals.dnsUnsupportedAnswers !== '0'
  ) {
    limitations.push(
      `${totals.dnsUnsupportedAnswers} DNS answer records were outside the bounded A, AAAA, and CNAME evidence contract.`,
    );
  }
  if (
    totals.dnsCorrelationMissing != null
    && totals.dnsCorrelationMissing !== '0'
  ) {
    limitations.push(
      `${totals.dnsCorrelationMissing} DNS responses could not be joined to an exact observed query transaction.`,
    );
  }
  if (totals.fileMapFull != null && totals.fileMapFull !== '0') {
    limitations.push(
      `${totals.fileMapFull} file paths could not be retained because the bounded aggregate was full.`,
    );
  }
  if (totals.filePathErrors != null && totals.filePathErrors !== '0') {
    limitations.push(
      `${totals.filePathErrors} file-open paths could not be resolved by the build collector.`,
    );
  }
  return limitations;
}

/**
 * Convert the privileged collector's per-pass manifests into one user-owned
 * profile input. Raw command arguments and environments are intentionally not
 * accepted by this adapter.
 */
export async function combineBuildPassManifests(input) {
  if (!input || typeof input !== 'object' || Array.isArray(input)) {
    throw new TypeError('combined build pass input is required');
  }
  if (!Array.isArray(input.passes) || input.passes.length < 1) {
    throw new TypeError('combined build profile requires at least one pass');
  }
  const mode = normalizeBuildMode(input.mode || 'build-profile');
  const cacheMode = mode === 'build-net-learn' ? 'cold' : input.cacheMode || 'compare';
  const passEntries = input.passes.map((entry) => {
    const manifest = entry?.manifest || entry;
    if (
      !manifest
      || manifest.kind !== BUILD_ARTIFACT_KINDS.evidence
      || manifest.schemaVersion !== BUILD_PROFILE_SCHEMA_VERSION
      || manifest.mode !== mode
    ) {
      throw new Error('per-pass build evidence manifest identity is invalid');
    }
    return {
      ...entry,
      manifest,
      selectedPass: passName(entry.pass || manifest.pass, cacheMode, mode),
    };
  });
  if (passEntries.length > MAX_BUILD_PASSES) {
    throw new TypeError(`combined build profile supports at most ${MAX_BUILD_PASSES} passes`);
  }
  if (
    new Set(passEntries.map((entry) => entry.selectedPass)).size
    !== passEntries.length
  ) {
    throw new TypeError('combined build profile pass names must be unique');
  }
  const maximumCombinedSourceBytes = combinedSourceByteLimit(passEntries.length);
  const requiredNames = new Set(requiredBuildEvidenceSources(
    mode,
    input.depth || 'balanced',
  ));
  const managedHttpCapture = mode === 'build-net-learn'
    && input.httpCapture === 'mitmproxy';
  if (managedHttpCapture) requiredNames.add('http');
  const optionalNames = new Set(
    mode === 'build-net-learn'
      && passEntries.some((entry) => (
        entry.manifest.sources?.some((source) => source.name === 'nosh-url')
      ))
      ? ['url']
      : [],
  );
  const groups = Object.fromEntries(
    [...new Set([...requiredNames, ...optionalNames])]
      .map((name) => [name, []]),
  );
  const errors = Object.fromEntries(Object.keys(groups).map((name) => [name, []]));
  const collectorStats = {
    'ebpf-process': [],
    'ebpf-syscall': [],
    'ebpf-file': [],
    'ebpf-network': [],
    dns: [],
  };
  const buildCollectorDiagnostics = [];
  for (const entry of passEntries) {
    const pass = entry.selectedPass;
    const passDirectory = entry.passDir || null;
    const progress = await optionalPiece(
      entry.progressPath || (passDirectory && path.join(passDirectory, 'buildx-progress.raw.jsonl')),
      pass,
      `${pass} BuildKit progress`,
      buildkitProgressRecords,
    );
    if (progress.content) groups['buildkit-progress']?.push(progress.content);
    if (progress.error) errors['buildkit-progress'].push(progress.error);

    const history = await optionalPiece(
      entry.historyPath || entry.history?.historyPath,
      pass,
      `${pass} Buildx history`,
      (content) => jsonRecord(content, pass, 'history'),
    );
    if (history.content) groups['buildx-history']?.push(history.content);
    if (history.error || entry.history?.available === false) {
      const failure = history.error || `${pass} Buildx history is unavailable`;
      const reason = entry.history?.available === false
        ? boundedEvidenceFailureReason(entry.history.reason)
        : null;
      errors['buildx-history'].push(reason ? `${failure}: ${reason}` : failure);
    }

    const cgroupSources = (entry.manifest.sources || []).filter((source) =>
      ['cgroup-before.json', 'cgroup-after.json'].includes(source.name));
    if (groups['cgroup-metrics'] && cgroupSources.length !== 2) {
      errors['cgroup-metrics'].push(`${pass} cgroup snapshots are incomplete`);
    }
    for (const source of cgroupSources) {
      const piece = await optionalPiece(
        sourcePathFromManifest(entry, source),
        pass,
        `${pass} ${source.name}`,
        (content) => cgroupSnapshotRecord(
          content,
          pass,
          source.name.replace('.json', ''),
        ),
        source.file,
      );
      if (piece.content) groups['cgroup-metrics']?.push(piece.content);
      if (groups['cgroup-metrics'] && piece.error) {
        errors['cgroup-metrics'].push(piece.error);
      }
    }

    const collector = (entry.manifest.sources || []).find((source) =>
      source.name === 'nosh-build');
    const diagnostics = noshBuildDiagnostics(pass, collector?.completion);
    if (diagnostics) buildCollectorDiagnostics.push(diagnostics);
    const collectorPiece = await optionalPiece(
      sourcePathFromManifest(entry, collector),
      pass,
      `${pass} nosh-build evidence`,
      null,
      collector?.file,
    );
    const noshBuildNames = ['ebpf-process', 'ebpf-syscall', 'ebpf-file', 'dns'];
    for (const name of noshBuildNames.filter((selected) => groups[selected])) {
      let selectedPiece = collectorPiece;
      if (collectorPiece.content) {
        try {
          selectedPiece = {
            content: collectorRecords(collectorPiece.content, pass, name),
            error: null,
          };
        } catch {
          selectedPiece = {
            content: null,
            error: `${pass} nosh-build evidence is not valid JSONL`,
          };
        }
      }
      if (selectedPiece.content) groups[name].push(selectedPiece.content);
      if (selectedPiece.error || collector?.complete !== true) {
        errors[name].push(
          selectedPiece.error || `${pass} nosh-build evidence is incomplete`,
        );
      }
      collectorStats[name].push({
        lostEvents: Number(collector?.completion?.lostEvents || 0),
        parseErrors: Number(collector?.completion?.parseErrors || 0),
      });
    }

    const l4 = (entry.manifest.sources || []).find((source) =>
      source.name === 'nosh-l4');
    const l4Piece = await optionalPiece(
      sourcePathFromManifest(entry, l4),
      pass,
      `${pass} nosh-l4 evidence`,
      null,
      l4?.file,
    );
    if (l4Piece.content) groups['ebpf-network']?.push(l4Piece.content);
    if (groups['ebpf-network']) {
      const reason = boundedEvidenceFailureReason(l4?.error);
      if (l4Piece.error) {
        errors['ebpf-network'].push(
          `${l4Piece.error}${reason ? `: ${reason}` : ''}`,
        );
      } else if (l4?.complete !== true) {
        errors['ebpf-network'].push(
          `${pass} nosh-l4 evidence is incomplete${reason ? `: ${reason}` : ''}`,
        );
      }
    }
    collectorStats['ebpf-network'].push({
      lostEvents: Number(l4?.completion?.lostEvents || 0),
      parseErrors: Number(l4?.completion?.parseErrors || 0),
    });

    if (groups.url) {
      const url = (entry.manifest.sources || []).find((source) =>
        source.name === 'nosh-url');
      const urlPiece = await optionalPiece(
        sourcePathFromManifest(entry, url),
        pass,
        `${pass} optional nosh-url evidence`,
        null,
        url?.file,
      );
      if (urlPiece.content) groups.url.push(urlPiece.content);
      if (urlPiece.error || url?.complete !== true) {
        const reason = boundedEvidenceFailureReason(url?.error);
        errors.url.push(
          `${urlPiece.error || `${pass} nosh-url evidence is incomplete`}${
            reason ? `: ${reason}` : ''
          }`,
        );
      }
      collectorStats.url ||= [];
      collectorStats.url.push({
        lostEvents: Number(url?.completion?.lostEvents || 0),
        parseErrors: Number(url?.completion?.parseErrors || 0),
      });
    }
  }
  if (input.httpEvidenceSource && !managedHttpCapture) {
    throw new TypeError('HTTP evidence source requires managed build network capture');
  }
  if (managedHttpCapture) {
    const http = input.httpEvidenceSource;
    if (!http || http.name !== 'http') {
      errors.http.push('managed HTTP evidence is missing');
    } else {
      const content = Buffer.isBuffer(http.content)
        ? http.content
        : http.content == null
          ? null
          : Buffer.from(String(http.content), 'utf8');
      if (!content?.length) {
        errors.http.push('managed HTTP evidence has no private NDJSON content');
      } else {
        groups.http.push(content);
      }
      if (http.complete !== true) {
        errors.http.push('managed HTTP evidence is incomplete');
      }
      collectorStats.http ||= [];
      collectorStats.http.push({
        lostEvents: Number(http.lostEvents || 0),
        parseErrors: Number(http.parseErrors || 0),
      });
    }
  }
  const sources = Object.entries(groups).map(([name, pieces]) => {
    const combinedBytes = pieces.reduce((sum, piece) => sum + piece.length, 0);
    if (combinedBytes > maximumCombinedSourceBytes) {
      throw new Error(`build evidence source exceeds the byte limit: ${name}`);
    }
    return {
      name,
      format: 'ndjson',
      content: pieces.length ? Buffer.concat(pieces, combinedBytes) : null,
      required: requiredNames.has(name),
      complete: errors[name].length === 0,
      lostEvents: (collectorStats[name] || [])
        .reduce((sum, value) => sum + value.lostEvents, 0),
      parseErrors: (collectorStats[name] || [])
        .reduce((sum, value) => sum + value.parseErrors, 0),
      completionMarker: errors[name].length === 0
        ? 'all-passes-finalized'
        : 'incomplete-pass-evidence',
    };
  });
  const diagnostics = combinedCollectorDiagnostics(
    buildCollectorDiagnostics,
    passEntries.length,
  );
  const startedAt = passEntries
    .map((entry) => entry.manifest.startedAt || entry.manifest.build?.startedAt)
    .filter(Boolean)
    .sort()[0];
  const endedAt = passEntries
    .map((entry) => entry.manifest.finishedAt || entry.manifest.endedAt)
    .filter(Boolean)
    .sort()
    .at(-1);
  const passes = passEntries.map((entry) => {
    const exitCode = Number(entry.manifest.build?.exitCode);
    const buildStartedAt = entry.manifest.build?.startedAt;
    const buildFinishedAt = entry.manifest.build?.finishedAt;
    return {
      name: entry.selectedPass,
      success: entry.manifest.build?.succeeded === true,
      exitCode: Number.isSafeInteger(exitCode) && exitCode >= 0 ? exitCode : 1,
      durationMs: buildStartedAt && buildFinishedAt
        ? Math.max(0, Date.parse(buildFinishedAt) - Date.parse(buildStartedAt))
        : null,
      cache: entry.cache || {},
      metrics: entry.metrics || {},
    };
  });
  const buildSucceeded = passEntries.every((entry) =>
    entry.manifest.build?.succeeded === true
    && Number(entry.manifest.build?.exitCode) === 0);
  const outputPass = [...passEntries].reverse().find((entry) =>
    entry.manifest.build?.metadata?.imageDigest
    || entry.manifest.build?.metadata?.configDigest);
  const output = input.output || outputPass?.manifest.build?.metadata || {};
  const builder = passEntries[0].manifest.builder || {};
  return {
    context: input.context || passEntries[0].manifest.workspace?.path,
    runId: input.runId || input.profileId,
    mode,
    generatedAt: input.generatedAt || endedAt,
    startedAt,
    endedAt,
    builder: {
      id: builder.builderName || null,
      containerId: builder.containerId || null,
      image: builder.imageReference || input.builderImage || null,
      imageDigest: builder.imageDigest || null,
      pid: builder.initPid || null,
      cgroup: builder.cgroup?.path || null,
      dockerEndpoint: input.dockerEndpoint || null,
    },
    build: {
      success: buildSucceeded,
      exitCode: buildSucceeded ? 0 : Number(
        passEntries.find((entry) => Number(entry.manifest.build?.exitCode) !== 0)
          ?.manifest.build?.exitCode ?? 1,
      ),
      platform: input.platform,
      cacheMode,
      depth: input.depth || 'balanced',
      target: input.target || null,
      outputImageDigest: output.imageDigest || null,
      configDigest: output.configDigest || null,
      passes,
    },
    coverage: {
      builderIdentityStable: passEntries.every((entry) => entry.manifest.identity?.ok === true),
      exclusiveBuilderLease: input.exclusiveBuilderLease === true,
      parentObserved: input.parentObserved === true,
      cleanupComplete: input.builderCleanupComplete === true
        && passEntries.every((entry) => entry.manifest.cleanup?.ok === true),
      freshBuilder: input.freshBuilder === true,
      forcedSourcePulls: input.forcedSourcePulls === true,
      cacheImportsDisabled: input.cacheImportsDisabled === true,
      allReachableStepsExecuted: input.allReachableStepsExecuted === true,
    },
    sources,
    metrics: {
      ...(input.metrics && typeof input.metrics === 'object' && !Array.isArray(input.metrics)
        ? input.metrics
        : {}),
      collectorDiagnostics: {
        ...(input.metrics?.collectorDiagnostics
          && typeof input.metrics.collectorDiagnostics === 'object'
          && !Array.isArray(input.metrics.collectorDiagnostics)
          ? input.metrics.collectorDiagnostics
          : {}),
        noshBuild: diagnostics,
      },
    },
    observations: input.observations || {},
    incompleteReasons: [
      ...[...requiredNames].flatMap((name) => errors[name] || []),
      ...passEntries
        .filter((entry) => entry.manifest.complete !== true)
        .map((entry) => `${entry.selectedPass} privileged evidence manifest is incomplete`),
      ...(Array.isArray(input.incompleteReasons) ? input.incompleteReasons : []),
    ],
    limitations: [
      ...passEntries.flatMap((entry) => entry.manifest.limitations || []),
      ...collectorDiagnosticLimitations(diagnostics),
      ...[...optionalNames].flatMap((name) => (
        errors[name] || []
      ).map((error) => `Optional ${name} evidence gap: ${error}`)),
      ...(input.limitations || []),
    ],
  };
}

async function materializeSources(
  directory,
  inputs,
  maximumBytes = MAX_COMBINED_SOURCE_BYTES,
) {
  const rawDirectory = path.join(directory, 'raw');
  await secureDirectory(rawDirectory);
  const results = [];
  for (const source of inputs) {
    if (!source || typeof source !== 'object' || Array.isArray(source)) {
      throw new TypeError('build evidence sources must be objects');
    }
    const name = safeBuildSegment(source.name, 'build evidence source name');
    const format = typeof source.format === 'string' && source.format.trim()
      ? source.format.trim()
      : 'ndjson';
    const relative = safeRelativeFile(
      source.file || `raw/${name}.${extensionForFormat(format)}`,
      `${name} artifact file`,
    );
    if (!relative.startsWith('raw/')) {
      throw new TypeError(`${name} artifact must be stored below raw/`);
    }
    const destination = path.join(directory, ...relative.split('/'));
    if (path.dirname(destination) !== rawDirectory) {
      await secureDirectory(path.dirname(destination));
    }
    const content = await sourceContent(source, maximumBytes);
    if (source.present === true && content == null) {
      throw new Error(`present build evidence source ${name} has no content`);
    }
    if (content != null) {
      if (content.length > maximumBytes) {
        throw new Error(`build evidence source exceeds the byte limit: ${name}`);
      }
      await writeExclusive(destination, content);
      const actual = await hashFile(destination, maximumBytes);
      if (source.hash && source.hash !== actual.hash) {
        throw new Error(`build evidence source hash changed: ${name}`);
      }
      if (source.bytes != null && Number(source.bytes) !== actual.bytes) {
        throw new Error(`build evidence source size changed: ${name}`);
      }
      results.push({
        ...source,
        content: undefined,
        sourcePath: undefined,
        name,
        format,
        file: relative,
        present: true,
        bytes: actual.bytes,
        records: source.records == null ? actual.records : source.records,
        hash: actual.hash,
      });
    } else {
      results.push({
        ...source,
        content: undefined,
        sourcePath: undefined,
        name,
        format,
        file: null,
        present: false,
        bytes: 0,
        records: 0,
        hash: null,
      });
    }
  }
  return results;
}

function queueMutation(key, operation) {
  const previous = mutationQueues.get(key) || Promise.resolve();
  const current = previous.then(operation, operation);
  mutationQueues.set(key, current);
  return current.finally(() => {
    if (mutationQueues.get(key) === current) mutationQueues.delete(key);
  });
}

async function portableFile(directory, name, value, mediaType) {
  const content = Buffer.from(
    typeof value === 'string' ? value : serializeJson(value),
    'utf8',
  );
  await writeExclusive(path.join(directory, name), content);
  return { hash: sha256(content), bytes: content.length, mediaType };
}

function portableCandidateProjection(candidate) {
  const unsigned = {
    schemaVersion: BUILD_PROFILE_SCHEMA_VERSION,
    apiVersion: BUILD_PROFILE_API_VERSION,
    kind: 'NoshBuildPortableCandidateProjection',
    generatedAt: candidate.generatedAt,
    sourceCorrelation: {
      privateCandidateKind: candidate.kind,
      privateCandidateContentHash: candidate.contentHash,
      privateEvidenceManifestHash: candidate.evidence?.manifestHash || null,
    },
    candidate: redactBuildValue({
      authoritative: candidate.authoritative,
      attested: candidate.attested,
      project: candidate.project,
      evidence: {
        runId: candidate.evidence?.runId || null,
        complete: candidate.evidence?.complete === true,
      },
      spec: candidate.spec,
    }),
  };
  return {
    ...unsigned,
    contentHash: sha256(stableStringify(unsigned)),
  };
}

export async function writePortableBuildBundle(input) {
  if (!input || typeof input !== 'object' || Array.isArray(input)) {
    throw new TypeError('portable build bundle input is required');
  }
  const manifest = validateBuildEvidenceManifest(input.manifest);
  const candidate = input.candidate || null;
  if (candidate) verifyBuildCandidate(candidate, manifest);
  const destination = path.resolve(input.directory);
  await secureDirectory(destination);
  const report = createPortableBuildReport(manifest, candidate);
  const files = {};
  files['report.json'] = await portableFile(
    destination,
    'report.json',
    report,
    'application/json',
  );
  files['report.txt'] = await portableFile(
    destination,
    'report.txt',
    renderPortableBuildReport(manifest, candidate),
    'text/plain',
  );
  files['metrics.json'] = await portableFile(
    destination,
    'metrics.json',
    redactBuildValue(manifest.metrics),
    'application/json',
  );
  files['provenance.json'] = await portableFile(
    destination,
    'provenance.json',
    redactBuildValue(manifest.observations?.provenance || {}),
    'application/json',
  );
  files['limitations.json'] = await portableFile(
    destination,
    'limitations.json',
    redactBuildValue(manifest.limitations),
    'application/json',
  );
  if (candidate) {
    files['candidate.json'] = await portableFile(
      destination,
      'candidate.json',
      portableCandidateProjection(candidate),
      'application/json',
    );
  }
  const bundle = createPortableBundleManifest({
    runId: manifest.runId,
    mode: manifest.mode,
    generatedAt: manifest.generatedAt,
    projectKey: manifest.project.key,
    files,
  });
  await writeExclusive(
    path.join(destination, BUILD_PROFILE_FILES.portableManifest),
    serializeJson(bundle),
  );
  await syncDirectory(destination);
  return { directory: destination, bundle, report };
}

async function verifyPortableBundle(directory, manifest) {
  const { document: bundle } = await trustedJson(
    path.join(directory, BUILD_PROFILE_FILES.portableManifest),
  );
  if (
    bundle.schemaVersion !== BUILD_PROFILE_SCHEMA_VERSION
    || bundle.apiVersion !== BUILD_PROFILE_API_VERSION
    || bundle.kind !== BUILD_ARTIFACT_KINDS.portableBundle
    || bundle.runId !== manifest.runId
    || bundle.mode !== manifest.mode
    || bundle.projectKey !== manifest.project.key
    || bundle.redacted !== true
    || bundle.authoritative !== false
    || bundle.attested !== false
  ) {
    throw new Error('portable build bundle identity is invalid');
  }
  const unsigned = { ...bundle };
  delete unsigned.contentHash;
  if (bundle.contentHash !== sha256(stableStringify(unsigned))) {
    throw new Error('portable build bundle content hash mismatch');
  }
  for (const [name, descriptor] of Object.entries(bundle.files || {})) {
    const selected = safeRelativeFile(name, 'portable bundle file');
    const content = await trustedFile(path.join(directory, selected));
    if (sha256(content) !== descriptor.hash || content.length !== descriptor.bytes) {
      throw new Error(`portable build bundle artifact mismatch: ${selected}`);
    }
  }
  const expectedFiles = new Set([
    ...Object.keys(bundle.files || {}),
    BUILD_PROFILE_FILES.portableManifest,
  ]);
  const actualFiles = await fs.readdir(directory);
  if (
    actualFiles.length !== expectedFiles.size
    || actualFiles.some((name) => !expectedFiles.has(name))
  ) {
    throw new Error('portable build bundle contains an unmanifested artifact');
  }
  return bundle;
}

export class BuildProfileStore {
  constructor(input = {}) {
    const options = rootOptions(input);
    const defaults = defaultBuildProfileRoots(options.home || os.homedir());
    this.profileRoot = path.resolve(options.profileRoot || options.root || defaults.profile);
    this.networkRoot = path.resolve(options.networkRoot || (
      options.profileRoot || options.root
        ? path.join(path.dirname(this.profileRoot), 'build-net-profiles')
        : defaults.network
    ));
    this.maxPassSourceBytes = passSourceByteLimit(options.maxPassSourceBytes);
  }

  rootForMode(mode) {
    return normalizeBuildMode(mode) === 'build-net-learn'
      ? this.networkRoot
      : this.profileRoot;
  }

  async initialize() {
    if (this.profileRoot === this.networkRoot) {
      throw new Error('build and build-network profile roots must be separate');
    }
    const sharedParent = path.dirname(this.profileRoot) === path.dirname(this.networkRoot)
      ? path.dirname(this.profileRoot)
      : null;
    if (sharedParent && path.basename(sharedParent) === '.nosh') {
      await secureDirectory(sharedParent);
    }
    await secureDirectory(this.profileRoot);
    await secureDirectory(this.networkRoot);
    return { profileRoot: this.profileRoot, networkRoot: this.networkRoot };
  }

  async projectDirectory(context, mode, create = false) {
    const project = await canonicalProjectBinding(context);
    const directory = path.join(this.rootForMode(mode), project.key);
    if (create) await secureDirectory(directory);
    return { directory, project };
  }

  async writeRun(input) {
    if (!input || typeof input !== 'object' || Array.isArray(input)) {
      throw new TypeError('build run state input is required');
    }
    await this.initialize();
    const mode = normalizeBuildMode(input.mode || 'build-profile');
    const runId = safeBuildSegment(input.runId, 'runId');
    const context = input.context || input.workdir || input.project?.canonicalPath;
    const { directory, project } = await this.projectDirectory(context, mode, true);
    const stateDirectory = path.join(directory, '.runs');
    await secureDirectory(stateDirectory);
    const now = new Date().toISOString();
    const state = {
      schemaVersion: BUILD_PROFILE_SCHEMA_VERSION,
      apiVersion: BUILD_PROFILE_API_VERSION,
      kind: 'NoshBuildProfileRunState',
      runId,
      mode,
      project,
      createdAt: input.createdAt || now,
      updatedAt: now,
      finalized: input.finalized === true,
      status: input.status || 'running',
      state: input.state && typeof input.state === 'object' ? input.state : {},
    };
    await atomicWrite(path.join(stateDirectory, `${runId}.json`), serializeJson(state));
    return state;
  }

  async finalizeRun(input) {
    if (!input || typeof input !== 'object' || Array.isArray(input)) {
      throw new TypeError('build run finalization input is required');
    }
    await this.initialize();
    const suppliedManifest = input.manifest || null;
    const mode = normalizeBuildMode(input.mode || suppliedManifest?.mode || 'build-profile');
    const runId = safeBuildSegment(input.runId || suppliedManifest?.runId, 'runId');
    const context = input.context
      || input.workdir
      || input.project?.canonicalPath
      || suppliedManifest?.project?.canonicalPath;
    const { directory: projectDirectory, project } = await this.projectDirectory(
      context,
      mode,
      true,
    );
    const destination = path.join(projectDirectory, runId);
    const temporary = path.join(
      projectDirectory,
      `.${runId}.${process.pid}.${crypto.randomUUID()}.tmp`,
    );
    await fs.mkdir(temporary, { mode: 0o700 });
    let manifest;
    let candidate = null;
    let policyDraft = null;
    try {
      const sourceInputs = input.sources || suppliedManifest?.sources || [];
      const maximumSourceBytes = combinedSourceByteLimit(
        aggregatePassCount(suppliedManifest || input),
        this.maxPassSourceBytes,
      );
      const sources = await materializeSources(
        temporary,
        sourceInputs,
        maximumSourceBytes,
      );
      if (suppliedManifest) {
        validateBuildEvidenceManifest(suppliedManifest);
        const suppliedInput = { ...suppliedManifest };
        const explicitlyDisabled = suppliedManifest.candidateIneligibleReasons?.includes(
          'candidate advancement was explicitly disabled',
        );
        delete suppliedInput.complete;
        delete suppliedInput.candidateEligible;
        delete suppliedInput.evidenceUse;
        delete suppliedInput.candidateIneligibleReasons;
        delete suppliedInput.attestation;
        manifest = createBuildEvidenceManifest({
          ...suppliedInput,
          project,
          sources,
          candidateEligible: explicitlyDisabled ? false : undefined,
        });
        if (stableStringify(manifest) !== stableStringify(suppliedManifest)) {
          throw new Error('materialized build evidence does not match the supplied manifest');
        }
      } else {
        manifest = createBuildEvidenceManifest({
          ...input,
          runId,
          mode,
          project,
          sources,
        });
      }
      if (manifest.candidateEligible) {
        candidate = mode === 'build-profile'
          ? createBuildProfileCandidate(manifest)
          : createBuildNetworkCandidate(manifest);
        if (mode === 'build-net-learn') {
          policyDraft = createBuildNetworkPolicyDraft(candidate);
        }
      }
      await writeExclusive(
        path.join(temporary, BUILD_PROFILE_FILES.evidence),
        serializeJson(manifest),
      );
      if (candidate) {
        const candidateFile = mode === 'build-profile'
          ? BUILD_PROFILE_FILES.profileCandidate
          : BUILD_PROFILE_FILES.networkCandidate;
        await writeExclusive(path.join(temporary, candidateFile), serializeJson(candidate));
      }
      if (policyDraft) {
        await writeExclusive(
          path.join(temporary, BUILD_PROFILE_FILES.networkPolicyDraft),
          serializeJson(policyDraft),
        );
      }
      const report = createBuildProfileReport(manifest, candidate);
      await writeExclusive(
        path.join(temporary, BUILD_PROFILE_FILES.report),
        serializeJson(report),
      );
      await writeExclusive(
        path.join(temporary, BUILD_PROFILE_FILES.reportText),
        renderBuildProfileReport(manifest, candidate),
      );
      await writePortableBuildBundle({
        directory: path.join(temporary, BUILD_PROFILE_FILES.portableDirectory),
        manifest,
        candidate,
      });
      await syncDirectory(temporary);
      try {
        await fs.rename(temporary, destination);
      } catch (error) {
        if (error.code === 'EEXIST' || error.code === 'ENOTEMPTY') {
          throw new Error(`build profile run already exists: ${runId}`, { cause: error });
        }
        throw error;
      }
      await syncDirectory(projectDirectory);
    } catch (error) {
      await fs.rm(temporary, { recursive: true, force: true }).catch(() => {});
      throw error;
    }
    const verified = await this.read(context, runId, { mode });
    const candidateAdvanced = candidate
      ? await this.#advanceLatest(projectDirectory, manifest, candidate)
      : false;
    await this.writeRun({
      runId,
      mode,
      context,
      finalized: true,
      status: manifest.complete ? 'complete' : 'incomplete',
      state: {
        bundleDirectory: destination,
        candidateAdvanced,
      },
    });
    return { ...verified, candidateAdvanced };
  }

  async #advanceLatest(projectDirectory, manifest, candidate) {
    const selected = path.join(projectDirectory, BUILD_PROFILE_FILES.latestCandidate);
    return queueMutation(selected, async () => {
      let previous = null;
      try {
        previous = (await trustedJson(selected)).document;
      } catch (error) {
        if (error.code !== 'ENOENT') throw error;
      }
      if (previous && Date.parse(previous.generatedAt) > Date.parse(manifest.generatedAt)) {
        return false;
      }
      const reference = {
        schemaVersion: BUILD_PROFILE_SCHEMA_VERSION,
        apiVersion: BUILD_PROFILE_API_VERSION,
        kind: 'NoshBuildCandidateReference',
        generatedAt: manifest.generatedAt,
        runId: manifest.runId,
        mode: manifest.mode,
        projectKey: manifest.project.key,
        candidateKind: candidate.kind,
        candidateHash: candidate.contentHash,
        authoritative: false,
        approved: false,
      };
      await atomicWrite(selected, serializeJson(reference));
      return true;
    });
  }

  async read(context, runId, options = {}) {
    await this.initialize();
    const mode = normalizeBuildMode(options.mode || 'build-profile');
    const selectedRunId = safeBuildSegment(runId, 'runId');
    const { directory: projectDirectory, project } = await this.projectDirectory(
      context,
      mode,
      false,
    );
    const directory = path.join(projectDirectory, selectedRunId);
    const { content, document: manifest } = await trustedJson(
      path.join(directory, BUILD_PROFILE_FILES.evidence),
    );
    validateBuildEvidenceManifest(manifest);
    if (
      manifest.mode !== mode
      || manifest.runId !== selectedRunId
      || stableStringify(manifest.project) !== stableStringify(project)
      || !content.equals(Buffer.from(serializeJson(manifest)))
    ) {
      throw new Error('build profile bundle identity is invalid');
    }
    const maximumSourceBytes = combinedSourceByteLimit(
      aggregatePassCount(manifest),
      this.maxPassSourceBytes,
    );
    for (const source of manifest.sources.filter((entry) => entry.present)) {
      if (!source.file) throw new Error(`build evidence source has no file: ${source.name}`);
      const relative = safeRelativeFile(source.file, `${source.name} source file`);
      const sourceFile = path.join(directory, ...relative.split('/'));
      const sourceContent = await trustedFile(sourceFile, maximumSourceBytes);
      if (sourceContent.length !== source.bytes || sha256(sourceContent) !== source.hash) {
        throw new Error(`build evidence source does not match its manifest: ${source.name}`);
      }
    }
    let candidate = null;
    const candidateFile = mode === 'build-profile'
      ? BUILD_PROFILE_FILES.profileCandidate
      : BUILD_PROFILE_FILES.networkCandidate;
    try {
      const candidateArtifact = await trustedJson(path.join(directory, candidateFile));
      candidate = candidateArtifact.document;
      if (!candidateArtifact.content.equals(Buffer.from(serializeJson(candidate)))) {
        throw new Error('build candidate artifact is not canonical');
      }
    } catch (error) {
      if (error.code !== 'ENOENT') throw error;
    }
    if (manifest.candidateEligible !== Boolean(candidate)) {
      throw new Error('build candidate presence does not match evidence eligibility');
    }
    if (candidate) verifyBuildCandidate(candidate, manifest);
    let policyDraft = null;
    if (mode === 'build-net-learn' && candidate) {
      const draftArtifact = await trustedJson(
        path.join(directory, BUILD_PROFILE_FILES.networkPolicyDraft),
      );
      policyDraft = validateBuildNetworkPolicyDraft(
        draftArtifact.document,
        candidate,
      );
    }
    const { content: reportContent, document: report } = await trustedJson(
      path.join(directory, BUILD_PROFILE_FILES.report),
    );
    if (
      stableStringify(report)
      !== stableStringify(createBuildProfileReport(manifest, candidate))
    ) {
      throw new Error('build profile report does not match its evidence');
    }
    if (!reportContent.equals(Buffer.from(serializeJson(report)))) {
      throw new Error('build profile report is not canonical');
    }
    const reportText = await trustedFile(
      path.join(directory, BUILD_PROFILE_FILES.reportText),
    );
    if (!reportText.equals(Buffer.from(renderBuildProfileReport(manifest, candidate)))) {
      throw new Error('build profile text report does not match its evidence');
    }
    const portableBundle = await verifyPortableBundle(
      path.join(directory, BUILD_PROFILE_FILES.portableDirectory),
      manifest,
    );
    return {
      directory,
      manifest,
      manifestHash: sha256(content),
      candidate,
      policyDraft,
      report,
      portableDirectory: path.join(directory, BUILD_PROFILE_FILES.portableDirectory),
      portableBundle,
    };
  }

  readRun(context, runId, options = {}) {
    return this.read(context, runId, options);
  }

  async list(context, options = {}) {
    await this.initialize();
    const mode = normalizeBuildMode(options.mode || 'build-profile');
    const { directory } = await this.projectDirectory(context, mode, false);
    let entries;
    try {
      entries = await fs.readdir(directory, { withFileTypes: true });
    } catch (error) {
      if (error.code === 'ENOENT') return [];
      throw error;
    }
    const runs = [];
    for (const entry of entries) {
      if (!entry.isDirectory() || entry.name.startsWith('.')) continue;
      try {
        const verified = await this.read(context, entry.name, { mode });
        runs.push({
          runId: verified.manifest.runId,
          mode,
          generatedAt: verified.manifest.generatedAt,
          complete: verified.manifest.complete,
          candidateEligible: verified.manifest.candidateEligible,
          directory: verified.directory,
        });
      } catch (error) {
        error.message = `cannot read build profile run ${entry.name}: ${error.message}`;
        throw error;
      }
    }
    return runs.sort((left, right) =>
      Date.parse(right.generatedAt) - Date.parse(left.generatedAt));
  }

  listRuns(context, options = {}) {
    return this.list(context, options);
  }

  async latestCandidate(context, options = {}) {
    await this.initialize();
    const mode = normalizeBuildMode(options.mode || 'build-profile');
    const { directory, project } = await this.projectDirectory(context, mode, false);
    let reference;
    try {
      reference = (await trustedJson(
        path.join(directory, BUILD_PROFILE_FILES.latestCandidate),
      )).document;
    } catch (error) {
      if (error.code === 'ENOENT') return null;
      throw error;
    }
    if (
      reference.kind !== 'NoshBuildCandidateReference'
      || reference.mode !== mode
      || reference.projectKey !== project.key
      || reference.authoritative !== false
      || reference.approved !== false
    ) {
      throw new Error('latest build candidate reference is invalid');
    }
    const bundle = await this.read(context, reference.runId, { mode });
    if (
      !bundle.candidate
      || bundle.candidate.kind !== reference.candidateKind
      || bundle.candidate.contentHash !== reference.candidateHash
    ) {
      throw new Error('latest build candidate reference does not match its bundle');
    }
    return { reference, ...bundle };
  }
}

export async function writeBuildProfileBundle(input, options = {}) {
  const store = options.store || new BuildProfileStore(options);
  return store.finalizeRun(input);
}

export async function finalizeBuildPassManifests(input, options = {}) {
  const combined = await combineBuildPassManifests(input);
  return writeBuildProfileBundle(combined, options);
}
