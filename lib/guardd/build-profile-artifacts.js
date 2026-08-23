import net from 'node:net';
import path from 'node:path';

import { serializeJson, sha256, stableStringify } from '../guard/stable.js';

export const BUILD_PROFILE_API_VERSION = 'notty.dev/v1alpha1';
export const BUILD_PROFILE_SCHEMA_VERSION = 1;
export const BUILD_NETWORK_EVIDENCE_VERSION = 2;

export const BUILD_ARTIFACT_KINDS = Object.freeze({
  evidence: 'NoshBuildEvidenceManifest',
  profileCandidate: 'NoshBuildProfileCandidate',
  networkCandidate: 'NoshBuildNetworkCandidate',
  networkPolicyDraft: 'NoshBuildNetworkPolicyDraft',
  portableBundle: 'NoshBuildPortableBundle',
});

export const BUILD_PROFILE_MODES = Object.freeze([
  'build-profile',
  'build-net-learn',
]);

const HASH_PATTERN = /^sha256:[a-f0-9]{64}$/;
const PROJECT_KEY_PATTERN = /^[a-f0-9]{64}$/;
const SAFE_SEGMENT_PATTERN = /^[A-Za-z0-9_.-]+$/;
const PROFILE_SOURCES = Object.freeze([
  'buildkit-progress',
  'buildx-history',
  'cgroup-metrics',
  'ebpf-process',
  'ebpf-syscall',
  'ebpf-network',
  'dns',
]);
const DEEP_SOURCES = Object.freeze([
  'ebpf-offcpu',
  'ebpf-file',
  'ebpf-block',
]);
const POLICY_SOURCES = Object.freeze([
  'ebpf-file',
]);
const NETWORK_SOURCES = Object.freeze([
  'buildkit-progress',
  'buildx-history',
  'ebpf-network',
  'dns',
]);
const PARENT_OBSERVATION_REASON =
  'collector did not observe activity below the builder cgroup';
const LEGACY_PARENT_OBSERVATION_REASON =
  'collector did not observe its parent';
const NETWORK_CORRELATION_WINDOW_NS = 30_000_000_000n;
const DNS_ADDRESS_BINDING_MAX_TTL_SECONDS = 300n;

export const BUILD_PROFILE_LIMITATIONS = Object.freeze([
  'This candidate is observational and is not an approved or enforced policy.',
  'A Docker-authorized user can influence the observed builder and its evidence.',
  'The exclusive lease covers cooperating Nosh sessions, not out-of-band Buildx use.',
  'Kernel evidence covers the BuildKit cgroup subtree, not Docker CLI or external Docker-daemon work.',
  'The Dockerfile is identity-checked before and after each pass, but the broader build context is not snapshotted.',
  'Artifact hashes provide integrity checking, not trusted attestation.',
  'The output image digest is informational and does not bind a runtime profile.',
]);

function cloneJson(value, label) {
  try {
    const serialized = stableStringify(value);
    if (serialized === undefined) {
      throw new TypeError(`${label} must be JSON serializable`);
    }
    return JSON.parse(serialized);
  } catch (error) {
    if (error instanceof TypeError && error.message.startsWith(label)) {
      throw error;
    }
    throw new TypeError(`${label} must be JSON serializable`, { cause: error });
  }
}

function plainObject(value, label) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    throw new TypeError(`${label} must be an object`);
  }
  return value;
}

function timestamp(value, label, nullable = false) {
  if (nullable && value == null) {
    return null;
  }
  if (typeof value !== 'string' || Number.isNaN(Date.parse(value))) {
    throw new TypeError(`${label} must be an ISO-compatible timestamp`);
  }
  return new Date(Date.parse(value)).toISOString();
}

export function safeBuildSegment(value, label = 'value') {
  if (
    typeof value !== 'string'
    || value.length < 1
    || value.length > 128
    || value === '.'
    || value === '..'
    || !SAFE_SEGMENT_PATTERN.test(value)
  ) {
    throw new TypeError(`${label} contains unsupported characters`);
  }
  return value;
}

export function normalizeBuildMode(value) {
  if (value === 'profile') return 'build-profile';
  if (value === 'net-learn' || value === 'network') return 'build-net-learn';
  if (!BUILD_PROFILE_MODES.includes(value)) {
    throw new TypeError(`unsupported build profile mode: ${value}`);
  }
  return value;
}

export function buildProjectKey(canonicalPath) {
  if (typeof canonicalPath !== 'string' || !path.isAbsolute(canonicalPath)) {
    throw new TypeError('project canonicalPath must be absolute');
  }
  return sha256(path.resolve(canonicalPath)).slice('sha256:'.length);
}

function normalizedProject(input) {
  const project = plainObject(input, 'project');
  const canonicalPath = path.resolve(project.canonicalPath || '');
  if (!project.canonicalPath || !path.isAbsolute(project.canonicalPath)) {
    throw new TypeError('project canonicalPath must be absolute');
  }
  const key = project.key || buildProjectKey(canonicalPath);
  if (!PROJECT_KEY_PATTERN.test(key) || key !== buildProjectKey(canonicalPath)) {
    throw new TypeError('project key must match the canonical project path');
  }
  if (!/^\d+$/.test(String(project.dev || ''))) {
    throw new TypeError('project dev must be a decimal filesystem ID');
  }
  if (!/^\d+$/.test(String(project.ino || ''))) {
    throw new TypeError('project ino must be a decimal inode ID');
  }
  return {
    canonicalPath,
    key,
    dev: String(project.dev),
    ino: String(project.ino),
  };
}

function optionalDigest(value, label) {
  if (value == null || value === '') return null;
  if (!HASH_PATTERN.test(value)) {
    throw new TypeError(`${label} must be an exact sha256 digest`);
  }
  return value;
}

function nonNegativeInteger(value, label, fallback = 0) {
  const normalized = value == null ? fallback : Number(value);
  if (!Number.isSafeInteger(normalized) || normalized < 0) {
    throw new TypeError(`${label} must be a non-negative integer`);
  }
  return normalized;
}

function optionalDecimalString(value, label) {
  if (value == null) return null;
  const normalized = String(value);
  if (!/^(0|[1-9][0-9]*)$/.test(normalized)) {
    throw new TypeError(`${label} must be an unsigned decimal string`);
  }
  return normalized;
}

function relativeArtifactName(value, label) {
  if (value == null) return null;
  if (typeof value !== 'string' || !value.trim() || path.isAbsolute(value)) {
    throw new TypeError(`${label} must be a relative artifact name`);
  }
  const normalized = path.posix.normalize(value.replaceAll('\\', '/'));
  if (normalized === '..' || normalized.startsWith('../')) {
    throw new TypeError(`${label} escapes the build evidence bundle`);
  }
  return normalized;
}

function normalizedSource(source) {
  plainObject(source, 'build evidence source');
  const name = safeBuildSegment(source.name, 'build evidence source name');
  const present = source.present === true;
  const complete = source.complete === true;
  const hash = optionalDigest(source.hash, `${name} source hash`);
  if (present && !hash) {
    throw new TypeError(`present build evidence source ${name} requires a hash`);
  }
  return {
    name,
    format: typeof source.format === 'string' && source.format.trim()
      ? source.format.trim()
      : 'ndjson',
    file: relativeArtifactName(source.file || source.fileName, `${name} source file`),
    required: source.required === true,
    present,
    complete,
    bytes: nonNegativeInteger(source.bytes, `${name} source bytes`),
    records: nonNegativeInteger(source.records, `${name} source records`),
    hash,
    lostEvents: nonNegativeInteger(source.lostEvents, `${name} lostEvents`),
    parseErrors: nonNegativeInteger(source.parseErrors, `${name} parseErrors`),
    completionMarker: typeof source.completionMarker === 'string'
      ? source.completionMarker
      : null,
  };
}

export function requiredBuildEvidenceSources(mode, depth = 'balanced') {
  const selectedMode = normalizeBuildMode(mode);
  if (!['balanced', 'policy', 'deep'].includes(depth)) {
    throw new TypeError(`unsupported build profile depth: ${depth}`);
  }
  if (selectedMode === 'build-net-learn') {
    return [...NETWORK_SOURCES];
  }
  if (depth === 'deep') return [...PROFILE_SOURCES, ...DEEP_SOURCES];
  if (depth === 'policy') return [...PROFILE_SOURCES, ...POLICY_SOURCES];
  return [...PROFILE_SOURCES];
}

function normalizeSources(input, mode, depth) {
  if (!Array.isArray(input)) {
    throw new TypeError('build evidence sources must be an array');
  }
  const required = new Set(requiredBuildEvidenceSources(mode, depth));
  const byName = new Map();
  for (const source of input) {
    const normalized = normalizedSource(source);
    if (byName.has(normalized.name)) {
      throw new TypeError(`duplicate build evidence source: ${normalized.name}`);
    }
    normalized.required = normalized.required || required.has(normalized.name);
    byName.set(normalized.name, normalized);
  }
  for (const name of required) {
    if (!byName.has(name)) {
      byName.set(name, normalizedSource({
        name,
        required: true,
        present: false,
        complete: false,
      }));
    }
  }
  return [...byName.values()].sort((left, right) =>
    left.name.localeCompare(right.name));
}

function normalizedPass(pass) {
  plainObject(pass, 'build pass');
  const name = safeBuildSegment(pass.name, 'build pass name');
  if (!['cold', 'warm'].includes(name)) {
    throw new TypeError(`unsupported build pass: ${name}`);
  }
  const exitCode = pass.exitCode == null ? null : Number(pass.exitCode);
  if (exitCode != null && (!Number.isSafeInteger(exitCode) || exitCode < 0)) {
    throw new TypeError(`${name} build pass exitCode is invalid`);
  }
  const durationMs = pass.durationMs == null
    ? null
    : nonNegativeInteger(pass.durationMs, `${name} durationMs`);
  return {
    name,
    success: pass.success === true,
    exitCode,
    durationMs,
    cache: cloneJson(pass.cache || {}, `${name} cache metrics`),
    metrics: cloneJson(pass.metrics || {}, `${name} build metrics`),
  };
}

function normalizePasses(input) {
  if (!Array.isArray(input)) {
    throw new TypeError('build passes must be an array');
  }
  const passes = input.map(normalizedPass);
  if (new Set(passes.map((entry) => entry.name)).size !== passes.length) {
    throw new TypeError('build pass names must be unique');
  }
  return passes;
}

function normalizedCoverage(input = {}) {
  plainObject(input, 'build evidence coverage');
  return {
    builderIdentityStable: input.builderIdentityStable === true,
    exclusiveBuilderLease: input.exclusiveBuilderLease === true,
    parentObserved: input.parentObserved === true,
    cleanupComplete: input.cleanupComplete === true,
    freshBuilder: input.freshBuilder === true,
    forcedSourcePulls: input.forcedSourcePulls === true,
    cacheImportsDisabled: input.cacheImportsDisabled === true,
    allReachableStepsExecuted: input.allReachableStepsExecuted === true,
  };
}

function sourceIncompleteReasons(sources) {
  const reasons = [];
  for (const source of sources.filter((entry) => entry.required)) {
    if (!source.present) reasons.push(`required source ${source.name} is missing`);
    if (source.present && !source.complete) {
      reasons.push(`required source ${source.name} is incomplete`);
    }
    if (source.lostEvents > 0) {
      reasons.push(`required source ${source.name} lost events`);
    }
    if (source.parseErrors > 0) {
      reasons.push(`required source ${source.name} has parse errors`);
    }
    if (source.present && source.complete && !source.completionMarker) {
      reasons.push(`required source ${source.name} has no completion marker`);
    }
  }
  return reasons;
}

function uniqueSortedStrings(values, label) {
  if (!Array.isArray(values)) throw new TypeError(`${label} must be an array`);
  return [...new Set(values.map((value) => {
    if (typeof value !== 'string' || !value.trim()) {
      throw new TypeError(`${label} entries must be non-empty strings`);
    }
    return value.trim();
  }))].sort();
}

function normalizedBuilder(input = {}) {
  plainObject(input, 'builder identity');
  const pid = input.pid == null ? null : Number(input.pid);
  if (pid != null && (!Number.isSafeInteger(pid) || pid < 1)) {
    throw new TypeError('builder pid must be a positive integer');
  }
  return {
    id: typeof input.id === 'string' ? input.id : null,
    containerId: typeof input.containerId === 'string' ? input.containerId : null,
    image: typeof input.image === 'string' ? input.image : null,
    imageDigest: optionalDigest(input.imageDigest, 'BuildKit image digest'),
    pid,
    cgroup: typeof input.cgroup === 'string' ? input.cgroup : null,
    dockerEndpoint: typeof input.dockerEndpoint === 'string'
      ? input.dockerEndpoint
      : null,
  };
}

function buildIncompleteReasons(input) {
  const {
    build,
    cacheMode,
    coverage,
    mode,
    passes,
    sources,
  } = input;
  const reasons = sourceIncompleteReasons(sources);
  if (!build.success || build.exitCode !== 0) reasons.push('build did not succeed');
  if (!coverage.builderIdentityStable) reasons.push('builder identity was not stable');
  if (!coverage.exclusiveBuilderLease) reasons.push('builder lease was not exclusive');
  if (!coverage.parentObserved) {
    reasons.push(PARENT_OBSERVATION_REASON);
  }
  if (!coverage.cleanupComplete) reasons.push('collector or builder cleanup was incomplete');
  const successfulPasses = new Set(
    passes
      .filter((pass) => pass.success && pass.exitCode === 0)
      .map((pass) => pass.name),
  );
  if (cacheMode === 'compare') {
    if (!successfulPasses.has('cold')) reasons.push('cold comparison pass failed or is missing');
    if (!successfulPasses.has('warm')) reasons.push('warm comparison pass failed or is missing');
  } else if (!successfulPasses.has(cacheMode)) {
    reasons.push(`${cacheMode} build pass failed or is missing`);
  }
  if (mode === 'build-net-learn') {
    if (cacheMode !== 'cold') reasons.push('network learning requires a cold build');
    if (!coverage.freshBuilder) reasons.push('network learning did not use a fresh builder');
    if (!coverage.forcedSourcePulls) reasons.push('network learning did not force source pulls');
    if (!coverage.cacheImportsDisabled) reasons.push('network learning allowed cache imports');
    if (!coverage.allReachableStepsExecuted) {
      reasons.push('network learning did not execute every reachable step');
    }
  }
  return reasons;
}

export function createBuildEvidenceManifest(input) {
  plainObject(input, 'build evidence input');
  const mode = normalizeBuildMode(input.mode || 'build-profile');
  const runId = safeBuildSegment(input.runId, 'runId');
  const generatedAt = timestamp(input.generatedAt || new Date().toISOString(), 'generatedAt');
  const startedAt = timestamp(input.startedAt, 'startedAt');
  const endedAt = timestamp(input.endedAt, 'endedAt');
  if (Date.parse(endedAt) < Date.parse(startedAt)) {
    throw new TypeError('endedAt must not precede startedAt');
  }
  const buildInput = plainObject(input.build, 'build result');
  const cacheMode = buildInput.cacheMode || input.cacheMode || (
    mode === 'build-net-learn' ? 'cold' : 'compare'
  );
  if (!['compare', 'cold', 'warm'].includes(cacheMode)) {
    throw new TypeError(`unsupported build cache mode: ${cacheMode}`);
  }
  const depth = buildInput.depth || input.depth || 'balanced';
  if (!['balanced', 'policy', 'deep'].includes(depth)) {
    throw new TypeError(`unsupported build profile depth: ${depth}`);
  }
  const platform = String(buildInput.platform || '').trim();
  if (!platform || platform.includes(',')) {
    throw new TypeError('build platform must select exactly one platform');
  }
  const exitCode = Number(buildInput.exitCode);
  if (!Number.isSafeInteger(exitCode) || exitCode < 0) {
    throw new TypeError('build exitCode must be a non-negative integer');
  }
  const passes = normalizePasses(buildInput.passes || input.passes || []);
  const coverage = normalizedCoverage(input.coverage || {});
  const sources = normalizeSources(input.sources || [], mode, depth);
  const build = {
    success: buildInput.success === true,
    exitCode,
    platform,
    cacheMode,
    depth,
    target: typeof buildInput.target === 'string' ? buildInput.target : null,
    outputImageDigest: optionalDigest(
      buildInput.outputImageDigest || buildInput.imageDigest,
      'output image digest',
    ),
    configDigest: optionalDigest(buildInput.configDigest, 'build config digest'),
    durationMs: buildInput.durationMs == null
      ? Math.max(0, Date.parse(endedAt) - Date.parse(startedAt))
      : nonNegativeInteger(buildInput.durationMs, 'build durationMs'),
    passes,
  };
  const suppliedReasons = uniqueSortedStrings(
    input.incompleteReasons || [],
    'incompleteReasons',
  );
  const incompleteReasons = [...new Set([
    ...buildIncompleteReasons({
      build,
      cacheMode,
      coverage,
      mode,
      passes,
      sources,
    }),
    ...suppliedReasons,
    ...(input.complete === false ? ['run was explicitly marked incomplete'] : []),
  ])].sort();
  const complete = incompleteReasons.length === 0;
  const eligibilityReasons = [...incompleteReasons];
  if (mode === 'build-profile' && cacheMode === 'warm') {
    eligibilityReasons.push('warm-only evidence cannot advance a behavioral candidate');
  }
  if (input.candidateEligible === false) {
    eligibilityReasons.push('candidate advancement was explicitly disabled');
  }
  const candidateEligible = complete && eligibilityReasons.length === 0;
  const observations = cloneJson(input.observations || {}, 'build observations');
  if (mode === 'build-net-learn') {
    observations.network = normalizedNetworkObservations(
      observations.network || {},
    );
  }
  return {
    schemaVersion: BUILD_PROFILE_SCHEMA_VERSION,
    apiVersion: BUILD_PROFILE_API_VERSION,
    kind: BUILD_ARTIFACT_KINDS.evidence,
    generatedAt,
    runId,
    mode,
    project: normalizedProject(input.project),
    builder: normalizedBuilder(input.builder || {}),
    startedAt,
    endedAt,
    build,
    coverage,
    sources,
    metrics: cloneJson(input.metrics || {}, 'build metrics'),
    observations,
    complete,
    candidateEligible,
    evidenceUse: candidateEligible ? 'candidate' : 'diagnostic-only',
    incompleteReasons,
    candidateIneligibleReasons: [...new Set(eligibilityReasons)].sort(),
    attestation: {
      authoritative: false,
      attested: false,
      integrityOnly: true,
    },
    limitations: uniqueSortedStrings(
      [...BUILD_PROFILE_LIMITATIONS, ...(input.limitations || [])],
      'limitations',
    ),
  };
}

export function validateBuildEvidenceManifest(manifest) {
  plainObject(manifest, 'build evidence manifest');
  if (
    manifest.schemaVersion !== BUILD_PROFILE_SCHEMA_VERSION
    || manifest.apiVersion !== BUILD_PROFILE_API_VERSION
    || manifest.kind !== BUILD_ARTIFACT_KINDS.evidence
  ) {
    throw new Error('unsupported build evidence manifest identity');
  }
  const source = cloneJson(manifest, 'build evidence manifest');
  const explicitlyDisabled = manifest.candidateIneligibleReasons?.includes(
    'candidate advancement was explicitly disabled',
  );
  delete source.complete;
  delete source.candidateEligible;
  delete source.evidenceUse;
  delete source.candidateIneligibleReasons;
  delete source.attestation;
  const rebuilt = createBuildEvidenceManifest({
    ...source,
    candidateEligible: explicitlyDisabled ? false : undefined,
  });
  if (stableStringify(rebuilt) === stableStringify(manifest)) {
    return manifest;
  }
  if (
    manifest.coverage?.parentObserved === false
    && manifest.incompleteReasons?.includes(LEGACY_PARENT_OBSERVATION_REASON)
  ) {
    const compatible = cloneJson(rebuilt, 'rebuilt build evidence manifest');
    for (const field of ['incompleteReasons', 'candidateIneligibleReasons']) {
      compatible[field] = [...new Set(compatible[field].map((reason) =>
        reason === PARENT_OBSERVATION_REASON
          ? LEGACY_PARENT_OBSERVATION_REASON
          : reason))].sort();
    }
    if (stableStringify(compatible) === stableStringify(manifest)) {
      return manifest;
    }
  }
  throw new Error('build evidence manifest fields or derived state are invalid');
}

function candidateEnvelope(manifest, kind) {
  validateBuildEvidenceManifest(manifest);
  if (!manifest.candidateEligible || !manifest.complete) {
    throw new Error('candidate requires successful complete eligible build evidence');
  }
  const evidenceManifestHash = sha256(serializeJson(manifest));
  return {
    schemaVersion: BUILD_PROFILE_SCHEMA_VERSION,
    apiVersion: BUILD_PROFILE_API_VERSION,
    kind,
    generatedAt: manifest.generatedAt,
    runId: manifest.runId,
    approved: false,
    authoritative: false,
    attested: false,
    project: cloneJson(manifest.project, 'candidate project'),
    evidence: {
      runId: manifest.runId,
      manifestHash: evidenceManifestHash,
      complete: true,
    },
  };
}

function withContentHash(unsigned) {
  return {
    ...unsigned,
    contentHash: sha256(stableStringify(unsigned)),
  };
}

export function createBuildProfileCandidate(manifest) {
  if (manifest?.mode !== 'build-profile') {
    throw new Error('build profile candidate requires build-profile evidence');
  }
  const envelope = candidateEnvelope(manifest, BUILD_ARTIFACT_KINDS.profileCandidate);
  return withContentHash({
    ...envelope,
    spec: {
      platform: manifest.build.platform,
      cacheMode: manifest.build.cacheMode,
      depth: manifest.build.depth,
      outputImageDigest: manifest.build.outputImageDigest,
      outputImageDigestUse: 'informational-only',
      passes: cloneJson(manifest.build.passes, 'candidate passes'),
      metrics: cloneJson(manifest.metrics, 'candidate metrics'),
      observations: cloneJson(manifest.observations, 'candidate observations'),
      limitations: [...manifest.limitations],
    },
  });
}

function normalizeProtocol(value) {
  const normalized = String(value || '').toLowerCase();
  if (!['tcp', 'udp'].includes(normalized)) {
    throw new TypeError(`unsupported observed network protocol: ${value}`);
  }
  return normalized;
}

function normalizeDestination(entry) {
  plainObject(entry, 'network destination');
  const port = Number(entry.port);
  if (!Number.isSafeInteger(port) || port < 1 || port > 65535) {
    throw new TypeError('network destination port must be from 1 to 65535');
  }
  const fqdn = entry.fqdn == null
    ? null
    : String(entry.fqdn).trim().toLowerCase().replace(/\.$/, '');
  const ip = entry.ip == null
    ? null
    : observationIp(entry.ip, 'network destination IP address');
  if (!fqdn && !ip) {
    throw new TypeError('network destination requires an fqdn or IP address');
  }
  return {
    fqdn: fqdn || null,
    ip: ip || null,
    protocol: normalizeProtocol(entry.protocol),
    port,
    source: typeof entry.source === 'string' ? entry.source : null,
  };
}

function normalizeDestinationList(values) {
  if (!Array.isArray(values)) {
    throw new TypeError('network destinations must be an array');
  }
  const destinations = values.map(normalizeDestination);
  const byKey = new Map(destinations.map((entry) => [stableStringify(entry), entry]));
  return [...byKey.values()].sort((left, right) =>
    stableStringify(left).localeCompare(stableStringify(right)));
}

function exactObservationFields(input, required, optional, label) {
  plainObject(input, label);
  const requiredSet = new Set(required);
  const allowed = new Set([...required, ...optional]);
  const missing = [...requiredSet].filter((key) => !Object.hasOwn(input, key));
  if (missing.length > 0) {
    throw new TypeError(`${label} requires fields: ${missing.sort().join(', ')}`);
  }
  const unsupported = Object.keys(input).filter((key) => !allowed.has(key));
  if (unsupported.length > 0) {
    throw new TypeError(
      `${label} has unsupported fields: ${unsupported.sort().join(', ')}`,
    );
  }
  return input;
}

function observationString(value, label, { allowEmpty = false, max = 512 } = {}) {
  if (
    typeof value !== 'string'
    || (!allowEmpty && value.length === 0)
    || value.length > max
    || /[\x00-\x1f\x7f]/.test(value)
  ) {
    throw new TypeError(`${label} must be a bounded text value`);
  }
  return value;
}

function observationInteger(value, label, minimum, maximum) {
  if (
    !Number.isSafeInteger(value)
    || value < minimum
    || value > maximum
  ) {
    throw new TypeError(
      `${label} must be an integer from ${minimum} to ${maximum}`,
    );
  }
  return value;
}

function observationDecimal(value, label) {
  if (typeof value !== 'string' || !/^(0|[1-9][0-9]*)$/.test(value)) {
    throw new TypeError(`${label} must be an unsigned decimal string`);
  }
  return value;
}

function observationPass(value, label) {
  if (!['cold', 'warm'].includes(value)) {
    throw new TypeError(`${label} must identify a cold or warm build pass`);
  }
  return value;
}

function observationDnsName(value, label) {
  const normalized = observationString(value, label, { max: 253 })
    .trim()
    .toLowerCase();
  const name = normalized === '.' ? '.' : normalized.replace(/\.$/, '');
  if (
    !name
    || /[\s\/@?#\\]/.test(name)
    || name.includes('..')
    || (name !== '.' && name.split('.').some((part) => part.length > 63))
  ) {
    throw new TypeError(`${label} is not a bounded DNS name`);
  }
  return name;
}

function observationIp(value, label, expectedFamily = null) {
  const normalized = observationString(value, label, { max: 45 }).toLowerCase();
  const family = net.isIP(normalized);
  if (family === 0 || (expectedFamily != null && family !== expectedFamily)) {
    throw new TypeError(`${label} must be a valid IP address`);
  }
  return normalized;
}

function normalizedResolver(input, label) {
  exactObservationFields(input, ['address', 'port'], [], label);
  return {
    address: observationIp(input.address, `${label} address`),
    port: observationInteger(input.port, `${label} port`, 0, 65_535),
  };
}

function normalizedProcess(input, label, nullable = true) {
  if (nullable && input == null) return null;
  exactObservationFields(input, ['pid', 'comm'], [], label);
  return {
    pid: observationInteger(input.pid, `${label} pid`, 1, Number.MAX_SAFE_INTEGER),
    comm: observationString(input.comm, `${label} comm`, {
      allowEmpty: true,
      max: 256,
    }),
  };
}

function normalizedDnsQuery(input) {
  const label = 'DNS query';
  exactObservationFields(input, [
    'id',
    'pass',
    'timestampNs',
    'transport',
    'qname',
    'queryType',
    'queryClass',
    'resolver',
    'clientPort',
    'socketCookie',
    'transactionId',
    'correlationComplete',
  ], [], label);
  if (input.transport !== 'udp') {
    throw new TypeError('DNS query transport must be udp');
  }
  if (typeof input.correlationComplete !== 'boolean') {
    throw new TypeError('DNS query correlationComplete must be a boolean');
  }
  const query = {
    id: observationString(input.id, 'DNS query id'),
    pass: observationPass(input.pass, 'DNS query pass'),
    timestampNs: observationDecimal(input.timestampNs, 'DNS query timestampNs'),
    transport: 'udp',
    qname: observationDnsName(input.qname, 'DNS query qname'),
    queryType: observationInteger(input.queryType, 'DNS query type', 0, 65_535),
    queryClass: observationInteger(input.queryClass, 'DNS query class', 0, 65_535),
    resolver: normalizedResolver(input.resolver, 'DNS query resolver'),
    clientPort: observationInteger(input.clientPort, 'DNS query clientPort', 1, 65_535),
    socketCookie: observationDecimal(input.socketCookie, 'DNS query socketCookie'),
    transactionId: observationInteger(
      input.transactionId,
      'DNS query transactionId',
      0,
      65_535,
    ),
    correlationComplete: input.correlationComplete,
  };
  if (query.resolver.port !== 53) {
    throw new TypeError('DNS query resolver port must be 53');
  }
  if (query.correlationComplete !== (query.socketCookie !== '0')) {
    throw new TypeError(
      'DNS query correlationComplete must exactly match its socket identity',
    );
  }
  const expectedId = [
    query.pass,
    'udp53',
    query.socketCookie,
    query.transactionId,
    query.clientPort,
    query.resolver.address,
    query.resolver.port,
    'dns-query',
    query.timestampNs,
  ].join(':');
  if (query.id !== expectedId) {
    throw new TypeError('DNS query id must match its deterministic event identity');
  }
  return query;
}

function normalizedDnsAnswer(input) {
  const label = 'DNS answer';
  exactObservationFields(input, [
    'snapshotId',
    'queryId',
    'pass',
    'index',
    'ownerName',
    'type',
    'class',
    'ttl',
    'valueKind',
    'value',
  ], [], label);
  if (!['cname', 'ipv4', 'ipv6'].includes(input.valueKind)) {
    throw new TypeError('DNS answer valueKind is unsupported');
  }
  const value = input.valueKind === 'cname'
    ? observationDnsName(input.value, 'DNS answer CNAME value')
    : observationIp(
        input.value,
        'DNS answer address value',
        input.valueKind === 'ipv4' ? 4 : 6,
      );
  const type = observationInteger(input.type, 'DNS answer type', 0, 65_535);
  const answerClass = observationInteger(
    input.class,
    'DNS answer class',
    0,
    65_535,
  );
  const expectedType = {
    cname: 5,
    ipv4: 1,
    ipv6: 28,
  }[input.valueKind];
  if (type !== expectedType || answerClass !== 1) {
    throw new TypeError(
      'DNS answer type, valueKind, and class must match the IN producer contract',
    );
  }
  return {
    snapshotId: observationString(input.snapshotId, 'DNS answer snapshotId'),
    queryId: input.queryId == null
      ? null
      : observationString(input.queryId, 'DNS answer queryId'),
    pass: observationPass(input.pass, 'DNS answer pass'),
    index: observationInteger(input.index, 'DNS answer index', 0, 65_535),
    ownerName: observationDnsName(input.ownerName, 'DNS answer ownerName'),
    type,
    class: answerClass,
    ttl: observationInteger(input.ttl, 'DNS answer ttl', 0, 4_294_967_295),
    valueKind: input.valueKind,
    value,
  };
}

function normalizedDnsAddress(input) {
  const label = 'DNS snapshot address';
  exactObservationFields(
    input,
    ['address', 'family', 'ownerName', 'ttl'],
    [],
    label,
  );
  if (!['ipv4', 'ipv6'].includes(input.family)) {
    throw new TypeError('DNS snapshot address family is unsupported');
  }
  return {
    address: observationIp(
      input.address,
      'DNS snapshot address',
      input.family === 'ipv4' ? 4 : 6,
    ),
    family: input.family,
    ownerName: observationDnsName(
      input.ownerName,
      'DNS snapshot address ownerName',
    ),
    ttl: observationInteger(
      input.ttl,
      'DNS snapshot address ttl',
      0,
      4_294_967_295,
    ),
  };
}

function normalizedDnsSnapshot(input) {
  const label = 'DNS answer snapshot';
  exactObservationFields(input, [
    'id',
    'queryId',
    'pass',
    'timestampNs',
    'socketCookie',
    'transactionId',
    'clientPort',
    'queryTimestampNs',
    'qname',
    'queryType',
    'queryClass',
    'resolver',
    'correlationComplete',
    'responseCode',
    'truncated',
    'parseComplete',
    'answerLimitReached',
    'answersDeclared',
    'answersCaptured',
    'cnameChain',
    'addresses',
  ], [], label);
  if (!Array.isArray(input.cnameChain) || !Array.isArray(input.addresses)) {
    throw new TypeError('DNS answer snapshot names and addresses must be arrays');
  }
  for (const field of [
    'correlationComplete',
    'truncated',
    'parseComplete',
    'answerLimitReached',
  ]) {
    if (typeof input[field] !== 'boolean') {
      throw new TypeError(`DNS answer snapshot ${field} must be a boolean`);
    }
  }
  if (
    (input.correlationComplete === true
      && (input.queryId == null || input.queryTimestampNs == null))
    || (input.correlationComplete === false
      && (input.queryId != null || input.queryTimestampNs != null))
  ) {
    throw new TypeError(
      'DNS answer snapshot query identity must match correlationComplete',
    );
  }
  const cnameChain = input.cnameChain.map((name) =>
    observationDnsName(name, 'DNS answer snapshot CNAME'));
  if (new Set(cnameChain).size !== cnameChain.length) {
    throw new TypeError('DNS answer snapshot CNAME chain must not contain duplicates');
  }
  const snapshot = {
    id: observationString(input.id, 'DNS answer snapshot id'),
    queryId: input.queryId == null
      ? null
      : observationString(input.queryId, 'DNS answer snapshot queryId'),
    pass: observationPass(input.pass, 'DNS answer snapshot pass'),
    timestampNs: observationDecimal(
      input.timestampNs,
      'DNS answer snapshot timestampNs',
    ),
    socketCookie: observationDecimal(
      input.socketCookie,
      'DNS answer snapshot socketCookie',
    ),
    transactionId: observationInteger(
      input.transactionId,
      'DNS answer snapshot transactionId',
      0,
      65_535,
    ),
    clientPort: observationInteger(
      input.clientPort,
      'DNS answer snapshot clientPort',
      1,
      65_535,
    ),
    queryTimestampNs: input.queryTimestampNs == null
      ? null
      : observationDecimal(
          input.queryTimestampNs,
          'DNS answer snapshot queryTimestampNs',
        ),
    qname: observationDnsName(input.qname, 'DNS answer snapshot qname'),
    queryType: observationInteger(
      input.queryType,
      'DNS answer snapshot queryType',
      0,
      65_535,
    ),
    queryClass: observationInteger(
      input.queryClass,
      'DNS answer snapshot queryClass',
      0,
      65_535,
    ),
    resolver: normalizedResolver(input.resolver, 'DNS answer snapshot resolver'),
    correlationComplete: input.correlationComplete,
    responseCode: observationInteger(
      input.responseCode,
      'DNS answer snapshot responseCode',
      0,
      15,
    ),
    truncated: input.truncated,
    parseComplete: input.parseComplete,
    answerLimitReached: input.answerLimitReached,
    answersDeclared: observationInteger(
      input.answersDeclared,
      'DNS answer snapshot answersDeclared',
      0,
      65_535,
    ),
    answersCaptured: observationInteger(
      input.answersCaptured,
      'DNS answer snapshot answersCaptured',
      0,
      65_535,
    ),
    cnameChain,
    addresses: input.addresses.map(normalizedDnsAddress),
  };
  if (snapshot.resolver.port !== 53) {
    throw new TypeError('DNS answer snapshot resolver port must be 53');
  }
  if (snapshot.correlationComplete === true && snapshot.socketCookie === '0') {
    throw new TypeError(
      'complete DNS answer snapshot must have a nonzero socket identity',
    );
  }
  const expectedId = [
    snapshot.pass,
    'udp53',
    snapshot.socketCookie,
    snapshot.transactionId,
    snapshot.clientPort,
    snapshot.resolver.address,
    snapshot.resolver.port,
    'dns-response',
    snapshot.timestampNs,
  ].join(':');
  if (snapshot.id !== expectedId) {
    throw new TypeError(
      'DNS answer snapshot id must match its deterministic event identity',
    );
  }
  return snapshot;
}

function normalizedDestinationKey(value, label) {
  const serialized = observationString(value, label, { max: 2_048 });
  let parsed;
  try {
    parsed = JSON.parse(serialized);
  } catch (error) {
    throw new TypeError(`${label} must be canonical destination JSON`, {
      cause: error,
    });
  }
  exactObservationFields(
    parsed,
    ['fqdn', 'ip', 'protocol', 'port', 'source'],
    [],
    `${label} value`,
  );
  const normalized = normalizeDestination(parsed);
  if (JSON.stringify(normalized) !== serialized) {
    throw new TypeError(`${label} must be canonical destination JSON`);
  }
  return serialized;
}

function normalizedDnsDestinationCorrelation(input) {
  const label = 'dns-destination correlation';
  exactObservationFields(input, [
    'kind',
    'pass',
    'snapshotId',
    'queryId',
    'qname',
    'ownerName',
    'address',
    'protocol',
    'port',
    'destinationKey',
    'process',
    'timestampNs',
  ], [], label);
  return {
    kind: 'dns-destination',
    pass: observationPass(input.pass, `${label} pass`),
    snapshotId: observationString(input.snapshotId, `${label} snapshotId`),
    queryId: observationString(input.queryId, `${label} queryId`),
    qname: observationDnsName(input.qname, `${label} qname`),
    ownerName: observationDnsName(input.ownerName, `${label} ownerName`),
    address: observationIp(input.address, `${label} address`),
    protocol: normalizeProtocol(input.protocol),
    port: observationInteger(input.port, `${label} port`, 1, 65_535),
    destinationKey: normalizedDestinationKey(
      input.destinationKey,
      `${label} destinationKey`,
    ),
    process: normalizedProcess(input.process, `${label} process`),
    timestampNs: observationDecimal(input.timestampNs, `${label} timestampNs`),
  };
}

function normalizedDnsQueryProcessCorrelation(input) {
  const label = 'dns-query-process correlation';
  exactObservationFields(input, [
    'kind',
    'correlationConfidence',
    'pass',
    'queryId',
    'socketCookie',
    'clientPort',
    'qname',
    'resolver',
    'process',
    'timestampNs',
    'attemptTimestampNs',
  ], [], label);
  if (input.correlationConfidence !== 'heuristic-socket-resolver-bounded-time') {
    throw new TypeError(`${label} confidence is invalid`);
  }
  return {
    kind: 'dns-query-process',
    correlationConfidence: input.correlationConfidence,
    pass: observationPass(input.pass, `${label} pass`),
    queryId: observationString(input.queryId, `${label} queryId`),
    socketCookie: observationDecimal(
      input.socketCookie,
      `${label} socketCookie`,
    ),
    clientPort: observationInteger(
      input.clientPort,
      `${label} clientPort`,
      1,
      65_535,
    ),
    qname: observationDnsName(input.qname, `${label} qname`),
    resolver: normalizedResolver(input.resolver, `${label} resolver`),
    process: normalizedProcess(input.process, `${label} process`),
    timestampNs: observationDecimal(input.timestampNs, `${label} timestampNs`),
    attemptTimestampNs: observationDecimal(
      input.attemptTimestampNs,
      `${label} attemptTimestampNs`,
    ),
  };
}

function normalizedResourceDnsQueryCorrelation(input) {
  const label = 'resource-dns-query correlation';
  exactObservationFields(input, [
    'kind',
    'correlationConfidence',
    'pass',
    'resourceId',
    'provider',
    'host',
    'queryId',
    'qname',
    'resolver',
    'resourceTimestampUnixNs',
    'queryTimestampNs',
    'resourceProcess',
    'dnsProcess',
  ], [], label);
  if (input.correlationConfidence !== 'heuristic-same-pid-host-bounded-time') {
    throw new TypeError(`${label} confidence is invalid`);
  }
  return {
    kind: 'resource-dns-query',
    correlationConfidence: input.correlationConfidence,
    pass: observationPass(input.pass, `${label} pass`),
    resourceId: observationString(input.resourceId, `${label} resourceId`),
    provider: observationString(input.provider, `${label} provider`, { max: 64 }),
    host: normalizeResourceHost(input.host),
    queryId: observationString(input.queryId, `${label} queryId`),
    qname: observationDnsName(input.qname, `${label} qname`),
    resolver: normalizedResolver(input.resolver, `${label} resolver`),
    resourceTimestampUnixNs: observationDecimal(
      input.resourceTimestampUnixNs,
      `${label} resourceTimestampUnixNs`,
    ),
    queryTimestampNs: observationDecimal(
      input.queryTimestampNs,
      `${label} queryTimestampNs`,
    ),
    resourceProcess: normalizedProcess(
      input.resourceProcess,
      `${label} resourceProcess`,
      false,
    ),
    dnsProcess: normalizedProcess(input.dnsProcess, `${label} dnsProcess`, false),
  };
}

function normalizedResourceDestinationCorrelation(input, direct = false) {
  const kind = direct ? 'resource-direct-destination' : 'resource-destination';
  const label = `${kind} correlation`;
  const dnsFields = direct
    ? []
    : ['snapshotId', 'queryId', 'qname', 'ownerName'];
  exactObservationFields(input, [
    'kind',
    'correlationConfidence',
    'pass',
    'resourceId',
    'provider',
    'host',
    ...dnsFields,
    'address',
    'protocol',
    'port',
    'destinationKey',
    'resourceTimestampUnixNs',
    'destinationTimestampNs',
    'resourceProcess',
    'networkProcess',
  ], [], label);
  const expectedConfidence = direct
    ? 'heuristic-direct-ip-same-pid-port-bounded-time'
    : 'heuristic-same-pid-host-port-bounded-time';
  if (input.correlationConfidence !== expectedConfidence) {
    throw new TypeError(`${label} confidence is invalid`);
  }
  return {
    kind,
    correlationConfidence: input.correlationConfidence,
    pass: observationPass(input.pass, `${label} pass`),
    resourceId: observationString(input.resourceId, `${label} resourceId`),
    provider: observationString(input.provider, `${label} provider`, { max: 64 }),
    host: normalizeResourceHost(input.host),
    ...(direct
      ? {}
      : {
          snapshotId: observationString(input.snapshotId, `${label} snapshotId`),
          queryId: observationString(input.queryId, `${label} queryId`),
          qname: observationDnsName(input.qname, `${label} qname`),
          ownerName: observationDnsName(input.ownerName, `${label} ownerName`),
        }),
    address: observationIp(input.address, `${label} address`),
    protocol: normalizeProtocol(input.protocol),
    port: observationInteger(input.port, `${label} port`, 1, 65_535),
    destinationKey: normalizedDestinationKey(
      input.destinationKey,
      `${label} destinationKey`,
    ),
    resourceTimestampUnixNs: observationDecimal(
      input.resourceTimestampUnixNs,
      `${label} resourceTimestampUnixNs`,
    ),
    destinationTimestampNs: observationDecimal(
      input.destinationTimestampNs,
      `${label} destinationTimestampNs`,
    ),
    resourceProcess: normalizedProcess(
      input.resourceProcess,
      `${label} resourceProcess`,
      false,
    ),
    networkProcess: normalizedProcess(
      input.networkProcess,
      `${label} networkProcess`,
      false,
    ),
  };
}

function normalizedNetworkCorrelation(input) {
  plainObject(input, 'network observation correlation');
  switch (input.kind) {
    case 'dns-destination':
      return normalizedDnsDestinationCorrelation(input);
    case 'dns-query-process':
      return normalizedDnsQueryProcessCorrelation(input);
    case 'resource-dns-query':
      return normalizedResourceDnsQueryCorrelation(input);
    case 'resource-destination':
      return normalizedResourceDestinationCorrelation(input);
    case 'resource-direct-destination':
      return normalizedResourceDestinationCorrelation(input, true);
    default:
      throw new TypeError(
        `unsupported network observation correlation kind: ${input.kind}`,
      );
  }
}

function normalizedTypedList(values, label, normalizer) {
  if (!Array.isArray(values)) {
    throw new TypeError(`${label} must be an array`);
  }
  const entries = values.map(normalizer);
  return [...new Map(entries.map((entry) => [stableStringify(entry), entry]))
    .values()]
    .sort((left, right) => stableStringify(left).localeCompare(stableStringify(right)));
}

function normalizedUniqueRecordList(values, label, normalizer, keyFor) {
  if (!Array.isArray(values)) {
    throw new TypeError(`${label} must be an array`);
  }
  const entries = values.map(normalizer);
  const keys = new Set();
  for (const entry of entries) {
    const key = keyFor(entry);
    if (keys.has(key)) {
      throw new TypeError(`${label} contain a duplicate record identity`);
    }
    keys.add(key);
  }
  return entries.sort((left, right) =>
    stableStringify(left).localeCompare(stableStringify(right)));
}

function sameObservation(left, right) {
  return stableStringify(left) === stableStringify(right);
}

function boundedObservationChronology(earlier, later) {
  const start = BigInt(earlier);
  const end = BigInt(later);
  return end >= start && end - start <= NETWORK_CORRELATION_WINDOW_NS;
}

function recordsBy(values, field) {
  const records = new Map();
  for (const value of values) {
    if (value[field] == null) continue;
    const key = String(value[field]);
    const current = records.get(key) || [];
    current.push(value);
    records.set(key, current);
  }
  return records;
}

function queryMatchesSnapshot(query, snapshot) {
  return query.id === snapshot.queryId
    && query.pass === snapshot.pass
    && query.timestampNs === snapshot.queryTimestampNs
    && query.correlationComplete === true
    && query.qname === snapshot.qname
    && query.queryType === snapshot.queryType
    && query.queryClass === snapshot.queryClass
    && sameObservation(query.resolver, snapshot.resolver)
    && query.clientPort === snapshot.clientPort
    && query.socketCookie === snapshot.socketCookie
    && query.transactionId === snapshot.transactionId
    && boundedObservationChronology(query.timestampNs, snapshot.timestampNs);
}

function reconstructedSnapshotCnameChain(snapshot, answers) {
  const cnameEdges = new Map();
  for (const answer of answers) {
    if (
      answer.snapshotId !== snapshot.id
      || answer.queryId !== snapshot.queryId
      || answer.pass !== snapshot.pass
      || answer.valueKind !== 'cname'
    ) {
      continue;
    }
    if (cnameEdges.has(answer.ownerName)) return null;
    cnameEdges.set(answer.ownerName, answer.value);
  }
  const chain = [snapshot.qname];
  const seen = new Set(chain);
  let current = snapshot.qname;
  for (let depth = 0; depth < 16; depth += 1) {
    const next = cnameEdges.get(current);
    if (next == null) break;
    if (seen.has(next)) return null;
    chain.push(next);
    seen.add(next);
    current = next;
  }
  if (cnameEdges.has(current)) return null;
  return chain;
}

function snapshotEffectiveTtl(snapshot, answers, correlation) {
  const exactCnameChain = reconstructedSnapshotCnameChain(snapshot, answers);
  if (
    exactCnameChain == null
    || !sameObservation(exactCnameChain, snapshot.cnameChain)
    || snapshot.correlationComplete !== true
    || snapshot.responseCode !== 0
    || snapshot.truncated !== false
    || snapshot.parseComplete !== true
    || snapshot.answerLimitReached !== false
    || snapshot.answersDeclared !== snapshot.answersCaptured
    || snapshot.cnameChain[0] !== snapshot.qname
  ) {
    return null;
  }
  const familyNumber = net.isIP(correlation.address);
  const family = familyNumber === 4 ? 'ipv4' : 'ipv6';
  if (
    snapshot.queryClass !== 1
    || snapshot.queryType !== (familyNumber === 4 ? 1 : 28)
  ) {
    return null;
  }
  const ownerIndex = snapshot.cnameChain.indexOf(correlation.ownerName);
  if (
    ownerIndex < 0
    || ownerIndex !== snapshot.cnameChain.length - 1
  ) {
    return null;
  }
  const ttls = [];
  for (let index = 0; index < ownerIndex; index += 1) {
    const ownerName = snapshot.cnameChain[index];
    const value = snapshot.cnameChain[index + 1];
    const matches = answers.filter((answer) => (
      answer.snapshotId === snapshot.id
      && answer.queryId === snapshot.queryId
      && answer.pass === snapshot.pass
      && answer.ownerName === ownerName
      && answer.type === 5
      && answer.class === snapshot.queryClass
      && answer.valueKind === 'cname'
      && answer.value === value
    ));
    if (matches.length === 0) return null;
    ttls.push(...matches.map((answer) => answer.ttl));
  }
  const address = snapshot.addresses.find((entry) => (
    entry.address === correlation.address
    && entry.family === family
    && entry.ownerName === correlation.ownerName
  ));
  if (!address) return null;
  const addressType = family === 'ipv4' ? 1 : 28;
  const addressAnswers = answers.filter((answer) => (
    answer.snapshotId === snapshot.id
    && answer.queryId === snapshot.queryId
    && answer.pass === snapshot.pass
    && answer.ownerName === correlation.ownerName
    && answer.type === addressType
    && answer.class === snapshot.queryClass
    && answer.valueKind === family
    && answer.value === correlation.address
    && answer.ttl === address.ttl
  ));
  if (addressAnswers.length === 0) return null;
  ttls.push(address.ttl);
  const effectiveTtl = Math.min(...ttls);
  return effectiveTtl < 1 ? null : BigInt(effectiveTtl);
}

function destinationMatchesCorrelation(destinationKeys, correlation) {
  if (!destinationKeys.has(correlation.destinationKey)) return false;
  const destination = JSON.parse(correlation.destinationKey);
  return destination.ip === correlation.address
    && destination.protocol === correlation.protocol
    && destination.port === correlation.port;
}

function matchingCompleteSnapshots({ answers, queriesById, snapshotsById }, correlation) {
  const attemptTimestamp = BigInt(correlation.timestampNs);
  return (snapshotsById.get(correlation.snapshotId) || []).filter((snapshot) => {
    if (
      snapshot.pass !== correlation.pass
      || snapshot.id !== correlation.snapshotId
      || snapshot.queryId !== correlation.queryId
      || snapshot.qname !== correlation.qname
      || BigInt(snapshot.timestampNs) > attemptTimestamp
    ) {
      return false;
    }
    const exactQuery = (queriesById.get(snapshot.queryId) || []).some((query) =>
      queryMatchesSnapshot(query, snapshot));
    if (!exactQuery) return false;
    const effectiveTtl = snapshotEffectiveTtl(snapshot, answers, correlation);
    if (effectiveTtl == null) return false;
    const expiresTimestamp = BigInt(snapshot.timestampNs)
      + (effectiveTtl < DNS_ADDRESS_BINDING_MAX_TTL_SECONDS
        ? effectiveTtl
        : DNS_ADDRESS_BINDING_MAX_TTL_SECONDS) * 1_000_000_000n;
    return attemptTimestamp >= BigInt(snapshot.timestampNs)
      && attemptTimestamp <= expiresTimestamp;
  });
}

function matchingCompleteQueries(queriesById, correlation) {
  return (queriesById.get(correlation.queryId) || []).filter((query) => (
    query.correlationComplete === true
    && query.pass === correlation.pass
    && query.id === correlation.queryId
    && query.socketCookie !== '0'
    && query.socketCookie === correlation.socketCookie
    && query.clientPort === correlation.clientPort
    && query.qname === correlation.qname
    && sameObservation(query.resolver, correlation.resolver)
    && query.resolver.port === 53
    && query.timestampNs === correlation.timestampNs
    && boundedObservationChronology(
      correlation.attemptTimestampNs,
      query.timestampNs,
    )
  ));
}

function resourceProcess(resource) {
  if (resource.pid == null || resource.process == null) return null;
  return { pid: resource.pid, comm: resource.process };
}

function matchingResources(resourcesById, correlation) {
  return (resourcesById.get(correlation.resourceId) || []).filter((resource) => (
    resource.id === correlation.resourceId
    && resource.source === 'nosh-url'
    && resource.provider === correlation.provider
    && resource.host === correlation.host
    && resource.pass === correlation.pass
    && resource.timestampUnixNs === correlation.resourceTimestampUnixNs
    && sameObservation(resourceProcess(resource), correlation.resourceProcess)
  ));
}

function validateNetworkObservationRelations(network) {
  const queriesById = recordsBy(network.dns.queries, 'id');
  const snapshotsById = recordsBy(network.dns.snapshots, 'id');
  const resourcesById = recordsBy(network.resources, 'id');
  const destinationKeys = new Set(
    network.destinations.map((destination) => JSON.stringify(destination)),
  );
  const queryProcessCorrelations = network.correlations.filter((entry) =>
    entry.kind === 'dns-query-process');
  const dnsDestinationCorrelations = network.correlations.filter((entry) =>
    entry.kind === 'dns-destination');
  const authoritySnapshotIds = new Set(network.correlations
    .filter((entry) => [
      'dns-destination',
      'resource-destination',
    ].includes(entry.kind))
    .map((entry) => entry.snapshotId));

  if ([...queriesById.values()].some((entries) => entries.length !== 1)) {
    throw new TypeError('DNS query event IDs must be unique');
  }
  if ([...snapshotsById.values()].some((entries) => entries.length !== 1)) {
    throw new TypeError('DNS snapshot event IDs must be unique');
  }

  for (const answer of network.dns.answers) {
    const exactSnapshot = (snapshotsById.get(answer.snapshotId) || []).some(
      (snapshot) => (
        snapshot.id === answer.snapshotId
        && snapshot.pass === answer.pass
        && snapshot.queryId === answer.queryId
      ),
    );
    if (!exactSnapshot) {
      throw new TypeError(
        'DNS answer does not reference an exact snapshot and query identity',
      );
    }
  }

  for (const snapshot of network.dns.snapshots) {
    const answers = network.dns.answers.filter((answer) => (
      answer.snapshotId === snapshot.id
      && answer.queryId === snapshot.queryId
      && answer.pass === snapshot.pass
    ));
    const exactCnameChain = reconstructedSnapshotCnameChain(
      snapshot,
      network.dns.answers,
    );
    const indices = answers.map((answer) => answer.index).sort((left, right) =>
      left - right);
    const contiguousIndices = indices.every((index, position) => index === position);
    const projectedAddresses = answers
      .filter((answer) => ['ipv4', 'ipv6'].includes(answer.valueKind))
      .map((answer) => ({
        address: answer.value,
        family: answer.valueKind,
        ownerName: answer.ownerName,
        ttl: answer.ttl,
      }));
    const addressKeys = projectedAddresses.map((address) => stableStringify(address));
    const snapshotAddressKeys = snapshot.addresses.map((address) =>
      stableStringify(address));
    if (
      (
        authoritySnapshotIds.has(snapshot.id)
        && (
          exactCnameChain == null
          || !sameObservation(exactCnameChain, snapshot.cnameChain)
        )
      )
      || answers.length !== snapshot.answersCaptured
      || !contiguousIndices
      || new Set(addressKeys).size !== addressKeys.length
      || new Set(snapshotAddressKeys).size !== snapshotAddressKeys.length
      || stableStringify([...addressKeys].sort())
        !== stableStringify([...snapshotAddressKeys].sort())
    ) {
      throw new TypeError(
        'DNS snapshot answers must exactly match its CNAME chain, captured indices, and addresses',
      );
    }
    if (
      snapshot.correlationComplete === true
      && (
        snapshot.queryTimestampNs == null
        || !(queriesById.get(snapshot.queryId) || []).some((query) =>
          queryMatchesSnapshot(query, snapshot))
      )
    ) {
      throw new TypeError(
        'complete DNS answer snapshot does not reference an exact prior query tuple',
      );
    }
  }

  for (const correlation of queryProcessCorrelations) {
    if (matchingCompleteQueries(queriesById, correlation).length === 0) {
      throw new TypeError(
        'dns-query-process correlation does not reference a compatible complete query',
      );
    }
    const resolverAttempt = network.destinations.some((destination) => (
      destination.ip === correlation.resolver.address
      && destination.protocol === 'udp'
      && destination.port === correlation.resolver.port
    ));
    if (!resolverAttempt) {
      throw new TypeError(
        'dns-query-process correlation does not reference an observed resolver destination',
      );
    }
  }

  for (const correlation of dnsDestinationCorrelations) {
    if (!destinationMatchesCorrelation(destinationKeys, correlation)) {
      throw new TypeError(
        'dns-destination correlation does not reference an exact destination',
      );
    }
    if (matchingCompleteSnapshots({
      answers: network.dns.answers,
      queriesById,
      snapshotsById,
    }, correlation).length === 0) {
      throw new TypeError(
        'dns-destination correlation does not reference a complete TTL-valid DNS snapshot',
      );
    }
  }

  for (const destination of network.destinations) {
    if (destination.ip == null) {
      throw new TypeError(
        'network destination must retain its exact observed L4 IP address',
      );
    }
    const expectedSource = destination.fqdn == null
      ? 'nosh-l4'
      : 'nosh-build-dns+nosh-l4';
    if (destination.source !== expectedSource) {
      throw new TypeError(
        'network destination source does not match its producer-derived identity',
      );
    }
    if (destination.fqdn != null) {
      const destinationKey = JSON.stringify(destination);
      const backedByDns = dnsDestinationCorrelations.some((correlation) => (
        correlation.destinationKey === destinationKey
        && correlation.qname === destination.fqdn
      ));
      if (!backedByDns) {
        throw new TypeError(
          'network destination FQDN is not backed by exact DNS-to-L4 evidence',
        );
      }
    }
  }

  for (const correlation of network.correlations) {
    if (!correlation.kind.startsWith('resource-')) continue;
    const resources = matchingResources(resourcesById, correlation);
    if (resources.length === 0) {
      throw new TypeError(
        `${correlation.kind} correlation does not reference a compatible URL resource`,
      );
    }
    if (correlation.kind === 'resource-dns-query') {
      const queries = (queriesById.get(correlation.queryId) || []).filter((query) => (
        query.correlationComplete === true
        && query.pass === correlation.pass
        && query.qname === correlation.qname
        && sameObservation(query.resolver, correlation.resolver)
        && query.timestampNs === correlation.queryTimestampNs
      ));
      const processCorrelation = queryProcessCorrelations.some((entry) => (
        entry.queryId === correlation.queryId
        && entry.pass === correlation.pass
        && entry.timestampNs === correlation.queryTimestampNs
        && sameObservation(entry.process, correlation.dnsProcess)
      ));
      if (
        queries.length === 0
        || !processCorrelation
        || resources.every((resource) => (
          resource.host !== correlation.qname
          || resource.pid !== correlation.dnsProcess.pid
          || !boundedObservationChronology(
            resource.timestampUnixNs,
            correlation.queryTimestampNs,
          )
        ))
      ) {
        throw new TypeError(
          'resource-dns-query correlation does not reference compatible DNS evidence',
        );
      }
      continue;
    }
    if (!destinationMatchesCorrelation(destinationKeys, correlation)) {
      throw new TypeError(
        `${correlation.kind} correlation does not reference an exact destination`,
      );
    }
    if (correlation.kind === 'resource-destination') {
      const dnsDestination = dnsDestinationCorrelations.some((entry) => (
        entry.pass === correlation.pass
        && entry.snapshotId === correlation.snapshotId
        && entry.queryId === correlation.queryId
        && entry.qname === correlation.qname
        && entry.ownerName === correlation.ownerName
        && entry.address === correlation.address
        && entry.protocol === correlation.protocol
        && entry.port === correlation.port
        && entry.destinationKey === correlation.destinationKey
        && entry.timestampNs === correlation.destinationTimestampNs
        && sameObservation(entry.process, correlation.networkProcess)
      ));
      if (
        !dnsDestination
        || resources.every((resource) => (
          resource.host !== correlation.qname
          || resource.port !== correlation.port
          || resource.pid !== correlation.networkProcess.pid
          || !boundedObservationChronology(
            resource.timestampUnixNs,
            correlation.destinationTimestampNs,
          )
        ))
      ) {
        throw new TypeError(
          'resource-destination correlation does not reference compatible DNS and URL evidence',
        );
      }
      continue;
    }
    const literalHost = correlation.host.startsWith('[')
      ? correlation.host.slice(1, -1)
      : correlation.host;
    if (
      literalHost !== correlation.address
      || resources.every((resource) => (
        resource.port !== correlation.port
        || resource.pid !== correlation.networkProcess.pid
        || !boundedObservationChronology(
          resource.timestampUnixNs,
          correlation.destinationTimestampNs,
        )
      ))
    ) {
      throw new TypeError(
        'resource-direct-destination correlation does not reference compatible direct-IP evidence',
      );
    }
  }

  if (
    network.coverage.dns.queries !== network.dns.queries.length
    || network.coverage.dns.responses !== network.dns.snapshots.length
    || network.coverage.dns.answers !== network.dns.answers.length
  ) {
    throw new TypeError(
      'DNS coverage counts must exactly match the immutable DNS records',
    );
  }
  const urlObservationCount = network.resources.filter((resource) =>
    resource.source === 'nosh-url').length;
  if (network.coverage.url.observations !== urlObservationCount) {
    throw new TypeError(
      'URL coverage observations must exactly match nosh-url resources',
    );
  }
  if (
    network.coverage.dns.complete === true
    && (
      network.coverage.dns.transactionMisses !== 0
      || network.coverage.dns.parseFailures !== 0
    )
  ) {
    throw new TypeError(
      'complete DNS coverage cannot contain transaction or parse gaps',
    );
  }
}

function normalizedNetworkObservations(input = {}) {
  plainObject(input, 'network observations');
  const cloneList = (field) => {
    const value = input[field] || [];
    if (!Array.isArray(value)) {
      throw new TypeError(`network observations ${field} must be an array`);
    }
    return cloneJson(value, `network observations ${field}`);
  };
  const network = {
    evidenceContractVersion: BUILD_NETWORK_EVIDENCE_VERSION,
    destinations: normalizeDestinationList(input.destinations || []),
    dns: normalizedDnsObservations(input.dns || {}),
    resources: normalizedResourceObservations(input.resources || []),
    correlations: normalizedTypedList(
      input.correlations || [],
      'network observation correlations',
      normalizedNetworkCorrelation,
    ),
    coverage: normalizedNetworkCoverage(input.coverage || {}),
    directIp: cloneList('directIp'),
    encryptedDns: cloneList('encryptedDns'),
    privateDestinations: cloneList('privateDestinations'),
    parseFailures: cloneList('parseFailures'),
    unresolved: cloneList('unresolved'),
  };
  validateNetworkObservationRelations(network);
  return network;
}

function normalizedDnsObservations(input) {
  exactObservationFields(
    input,
    [],
    ['queries', 'answers', 'snapshots'],
    'network DNS observations',
  );
  const queries = normalizedUniqueRecordList(
    input.queries || [],
    'DNS queries',
    normalizedDnsQuery,
    (query) => query.id,
  );
  const answerEntries = normalizedUniqueRecordList(
    input.answers || [],
    'DNS answers',
    normalizedDnsAnswer,
    (answer) => stableStringify([answer.snapshotId, answer.index]),
  );
  const snapshots = normalizedUniqueRecordList(
    input.snapshots || [],
    'DNS answer snapshots',
    normalizedDnsSnapshot,
    (snapshot) => snapshot.id,
  );
  return {
    queries,
    answers: answerEntries,
    snapshots,
  };
}

function normalizeResourceHost(value) {
  const raw = observationString(value, 'network resource host', { max: 253 })
    .trim();
  const lower = raw.toLowerCase();
  if (lower.includes('[') || lower.includes(']') || lower.includes(':')) {
    if (
      raw !== lower
      || !/^\[[^\[\]]+\]$/.test(lower)
      || lower.includes('%')
      || net.isIP(lower.slice(1, -1)) !== 6
    ) {
      throw new TypeError('network resource host is invalid');
    }
    let canonical;
    try {
      canonical = new URL(`http://${lower}/`).hostname;
    } catch {
      throw new TypeError('network resource host is invalid');
    }
    if (canonical !== lower) {
      throw new TypeError('network resource host must use canonical bracketed IPv6');
    }
    return lower;
  }
  const host = lower.replace(/\.$/, '');
  if (
    !host
    || /[\s\x00-\x1f\x7f\/@?#\\%]/.test(host)
    || host.includes('..')
  ) {
    throw new TypeError('network resource host is invalid');
  }
  return host;
}

function normalizedResourceObservation(input) {
  plainObject(input, 'network resource observation');
  const scheme = String(input.scheme || '').trim().toLowerCase();
  const host = normalizeResourceHost(input.host);
  const port = Number(input.port);
  const resourcePath = input.path == null ? '/' : String(input.path);
  if (!/^[a-z][a-z0-9+.-]{0,31}$/.test(scheme)) {
    throw new TypeError('network resource scheme is invalid');
  }
  if (!Number.isSafeInteger(port) || port < 1 || port > 65_535) {
    throw new TypeError('network resource port must be from 1 to 65535');
  }
  if (
    !resourcePath.startsWith('/')
    || resourcePath.length > 512
    || /[\x00-\x1f\x7f?#]/.test(resourcePath)
  ) {
    throw new TypeError(
      'network resource path must be a bounded path without query or fragment',
    );
  }
  if (typeof input.pathTruncated !== 'boolean') {
    throw new TypeError('network resource pathTruncated must be a boolean');
  }
  const resource = {
    id: typeof input.id === 'string' && input.id ? input.id : null,
    provider: typeof input.provider === 'string' && input.provider
      ? input.provider
      : 'unknown',
    scheme,
    host,
    port,
    path: resourcePath,
    pathTruncated: input.pathTruncated,
    process: typeof input.process === 'string' && input.process
      ? input.process
      : null,
    pid: input.pid == null
      ? null
      : nonNegativeInteger(input.pid, 'network resource pid'),
    tid: input.tid == null
      ? null
      : nonNegativeInteger(input.tid, 'network resource tid'),
    timestampUnixNs: optionalDecimalString(
      input.timestampUnixNs,
      'network resource Unix timestamp',
    ),
    timestampMonotonicNs: optionalDecimalString(
      input.timestampMonotonicNs,
      'network resource monotonic timestamp',
    ),
    targetCgroupId: optionalDecimalString(
      input.targetCgroupId,
      'network resource target cgroup ID',
    ),
    cgroupId: optionalDecimalString(
      input.cgroupId,
      'network resource observed cgroup ID',
    ),
    pass: typeof input.pass === 'string' && input.pass ? input.pass : null,
    source: typeof input.source === 'string' && input.source
      ? input.source
      : null,
  };
  if (resource.source === 'nosh-url') {
    if (
      resource.process == null
      || resource.pid == null
      || resource.pid < 1
      || resource.tid == null
      || resource.tid < 1
      || resource.timestampUnixNs == null
      || resource.timestampMonotonicNs == null
      || resource.targetCgroupId == null
      || resource.targetCgroupId === '0'
      || resource.cgroupId == null
      || resource.cgroupId === '0'
      || !['cold', 'warm'].includes(resource.pass)
    ) {
      throw new TypeError(
        'nosh-url resource identity fields must be complete and nonzero',
      );
    }
    const identity = JSON.stringify([
      resource.pass,
      resource.timestampMonotonicNs,
      resource.targetCgroupId,
      resource.cgroupId,
      resource.pid,
      resource.tid,
      resource.scheme,
      resource.host,
      resource.port,
    ]);
    const identityDigest = sha256(identity);
    const canonicalId = `url:${identityDigest}`;
    // Older bundles used url:<hex> before the sha256: prefix became part of
    // the stable digest representation. Accept that form only for this exact
    // path-independent identity; never accept a caller/path-derived ID.
    const legacyId = identityDigest.startsWith('sha256:')
      ? `url:${identityDigest.slice('sha256:'.length)}`
      : null;
    if (resource.id !== canonicalId && resource.id !== legacyId) {
      throw new TypeError(
        `nosh-url resource id must bind the path-independent observation identity (actual=${resource.id}; expected=${canonicalId})`,
      );
    }
  }
  return resource;
}

function normalizedResourceObservations(values) {
  if (!Array.isArray(values)) {
    throw new TypeError('network resource observations must be an array');
  }
  const entries = values.map(normalizedResourceObservation);
  const noshUrlIds = new Set();
  for (const entry of entries) {
    if (entry.source !== 'nosh-url') continue;
    if (noshUrlIds.has(entry.id)) {
      throw new TypeError(
        'network resource observations contain a duplicate nosh-url event ID',
      );
    }
    noshUrlIds.add(entry.id);
  }
  return [...new Map(entries.map((entry) => [stableStringify(entry), entry]))
    .values()]
    .sort((left, right) => stableStringify(left).localeCompare(stableStringify(right)));
}

function normalizedNetworkCoverage(input) {
  exactObservationFields(
    input,
    [],
    ['dns', 'url'],
    'network observation coverage',
  );
  const dns = exactObservationFields(
    input.dns || {},
    [],
    [
      'queries',
      'responses',
      'answers',
      'transactionMisses',
      'parseFailures',
      'complete',
    ],
    'DNS observation coverage',
  );
  const url = exactObservationFields(
    input.url || {},
    [],
    [
      'enabled',
      'providers',
      'observations',
      'discoveryMisses',
      'readErrors',
      'complete',
      'limitations',
    ],
    'URL observation coverage',
  );
  if (Object.hasOwn(url, 'complete') && url.complete !== false) {
    throw new TypeError(
      'URL coverage complete must be false because enrichment is non-authoritative',
    );
  }
  return {
    dns: {
      queries: nonNegativeInteger(dns.queries, 'DNS coverage queries'),
      responses: nonNegativeInteger(dns.responses, 'DNS coverage responses'),
      answers: nonNegativeInteger(dns.answers, 'DNS coverage answers'),
      transactionMisses: nonNegativeInteger(
        dns.transactionMisses,
        'DNS coverage transactionMisses',
      ),
      parseFailures: nonNegativeInteger(
        dns.parseFailures,
        'DNS coverage parseFailures',
      ),
      complete: dns.complete === true,
    },
    url: {
      enabled: url.enabled === true,
      providers: uniqueSortedStrings(url.providers || [], 'URL coverage providers'),
      observations: nonNegativeInteger(
        url.observations,
        'URL coverage observations',
      ),
      discoveryMisses: nonNegativeInteger(
        url.discoveryMisses,
        'URL coverage discoveryMisses',
      ),
      readErrors: nonNegativeInteger(url.readErrors, 'URL coverage readErrors'),
      complete: false,
      limitations: uniqueSortedStrings(
        url.limitations || [],
        'URL coverage limitations',
      ),
    },
  };
}

export function createBuildNetworkCandidate(manifest) {
  if (manifest?.mode !== 'build-net-learn') {
    throw new Error('build network candidate requires build-net-learn evidence');
  }
  const envelope = candidateEnvelope(manifest, BUILD_ARTIFACT_KINDS.networkCandidate);
  const network = normalizedNetworkObservations(manifest.observations?.network || {});
  return withContentHash({
    ...envelope,
    spec: {
      platform: manifest.build.platform,
      outputImageDigest: manifest.build.outputImageDigest,
      outputImageDigestUse: 'informational-only',
      observations: network,
      provenance: cloneJson(
        manifest.observations?.provenance || {},
        'network build provenance',
      ),
      limitations: [...manifest.limitations],
    },
  });
}

export function createBuildNetworkPolicyDraft(candidate) {
  plainObject(candidate, 'build network candidate');
  if (candidate.kind !== BUILD_ARTIFACT_KINDS.networkCandidate) {
    throw new Error('build network policy draft requires a network candidate');
  }
  const rules = candidate.spec.observations.destinations.map((destination) => {
    const identity = {
      fqdn: destination.fqdn,
      ip: destination.ip,
      protocol: destination.protocol,
      port: destination.port,
    };
    return {
      id: `draft:${sha256(stableStringify(identity)).slice('sha256:'.length)}`,
      decision: 'review',
      direction: 'egress',
      peer: {
        fqdn: destination.fqdn,
        ip: destination.ip,
      },
      transport: {
        protocol: destination.protocol,
        ports: [destination.port],
      },
      evidence: {
        source: destination.source,
      },
    };
  });
  return {
    schemaVersion: 1,
    apiVersion: BUILD_PROFILE_API_VERSION,
    kind: BUILD_ARTIFACT_KINDS.networkPolicyDraft,
    generatedAt: candidate.generatedAt,
    editable: true,
    authoritative: false,
    source: {
      runId: candidate.runId,
      candidateHash: candidate.contentHash,
      evidenceManifestHash: candidate.evidence.manifestHash,
    },
    defaults: { egress: 'deny-after-approval' },
    rules,
    notes: [],
  };
}

export function validateBuildNetworkPolicyDraft(draft, candidate) {
  plainObject(draft, 'build network policy draft');
  const exactKeys = (value, keys) => (
    value
    && typeof value === 'object'
    && !Array.isArray(value)
    && Object.keys(value).sort().join(',') === [...keys].sort().join(',')
  );
  if (
    !exactKeys(draft, [
      'schemaVersion',
      'apiVersion',
      'kind',
      'generatedAt',
      'editable',
      'authoritative',
      'source',
      'defaults',
      'rules',
      'notes',
    ])
    || draft.schemaVersion !== 1
    || draft.apiVersion !== BUILD_PROFILE_API_VERSION
    || draft.kind !== BUILD_ARTIFACT_KINDS.networkPolicyDraft
    || draft.editable !== true
    || draft.authoritative !== false
    || !exactKeys(draft.source, [
      'runId', 'candidateHash', 'evidenceManifestHash',
    ])
    || draft.source?.runId !== candidate.runId
    || draft.source?.candidateHash !== candidate.contentHash
    || draft.source?.evidenceManifestHash !== candidate.evidence.manifestHash
    || !exactKeys(draft.defaults, ['egress'])
    || draft.defaults?.egress !== 'deny-after-approval'
    || !Array.isArray(draft.rules)
    || !Array.isArray(draft.notes)
    || draft.notes.some((note) => typeof note !== 'string')
  ) {
    throw new Error('build network policy draft identity or evidence binding is invalid');
  }
  for (const rule of draft.rules) {
    if (
      !rule
      || typeof rule !== 'object'
      || Array.isArray(rule)
      || !exactKeys(rule, [
        'id', 'decision', 'direction', 'peer', 'transport', 'evidence',
      ])
      || typeof rule.id !== 'string'
      || !rule.id
      || !['review', 'allow', 'deny'].includes(rule.decision)
      || rule.direction !== 'egress'
      || !exactKeys(rule.peer, ['fqdn', 'ip'])
      || !exactKeys(rule.transport, ['protocol', 'ports'])
      || !exactKeys(rule.evidence, ['source'])
      || !['tcp', 'udp'].includes(rule.transport?.protocol)
      || !Array.isArray(rule.transport?.ports)
      || !rule.transport.ports.length
      || rule.transport.ports.some((port) => (
        !Number.isSafeInteger(port) || port < 1 || port > 65_535
      ))
      || (!rule.peer?.fqdn && !rule.peer?.ip)
      || (rule.evidence.source != null && typeof rule.evidence.source !== 'string')
    ) {
      throw new Error('build network policy draft contains an invalid editable rule');
    }
  }
  return draft;
}

export function verifyBuildCandidate(candidate, manifest) {
  plainObject(candidate, 'build candidate');
  const expected = manifest.mode === 'build-profile'
    ? createBuildProfileCandidate(manifest)
    : createBuildNetworkCandidate(manifest);
  if (stableStringify(candidate) !== stableStringify(expected)) {
    throw new Error('build candidate does not match its evidence manifest');
  }
  return candidate;
}

const PORTABLE_SENSITIVE_KEYS = new Set([
  'argv',
  'authorization',
  'body',
  'canonicalPath',
  'cgroup',
  'command',
  'cgroupId',
  'commands',
  'dockerEndpoint',
  'displayUrl',
  'environment',
  'event',
  'events',
  'fragment',
  'file',
  'fileName',
  'log',
  'logs',
  'headers',
  'path',
  'paths',
  'password',
  'raw',
  'query',
  'sourcePath',
  'stackSamples',
  'stderr',
  'stdout',
  'targetCgroupId',
  'timestampMonotonicNs',
  'tid',
  'userinfo',
]);

function sensitivePortableKey(key) {
  return PORTABLE_SENSITIVE_KEYS.has(key)
    || /(?:authorization|password)/i.test(key)
    || /(?:^|_)(?:argv|cmd|command|context|credential|dockerfile|env|events?|logs?|path|raw|secret|stderr|stdout|token)(?:$|_)/i.test(key);
}

function redactPortableString(value) {
  if (value.includes('\n') || value.includes('\r') || value.includes('\0')) {
    return '[redacted-text]';
  }
  if (
    value.startsWith('/')
    || /^[A-Za-z]:[\\/]/.test(value)
    || /(?:^|[\s"'=:(])\/(?!\/)[^\s"']+/.test(value)
    || /(?:^|[\s"'=:(])[A-Za-z]:[\\/][^\s"']+/.test(value)
  ) {
    return '[redacted-path]';
  }
  return value;
}

export function redactBuildValue(value) {
  if (Array.isArray(value)) return value.map(redactBuildValue);
  if (typeof value === 'string') return redactPortableString(value);
  if (!value || typeof value !== 'object') return value;
  const redacted = Object.fromEntries(
    Object.entries(value)
      .filter(([key]) => !sensitivePortableKey(key))
      .map(([key, entry]) => [key, redactBuildValue(entry)]),
  );
  return redacted;
}

export function portableBuildProjection(manifest, candidate = null) {
  validateBuildEvidenceManifest(manifest);
  if (candidate) verifyBuildCandidate(candidate, manifest);
  return {
    schemaVersion: BUILD_PROFILE_SCHEMA_VERSION,
    apiVersion: BUILD_PROFILE_API_VERSION,
    kind: 'NoshBuildPortableReport',
    generatedAt: manifest.generatedAt,
    runId: manifest.runId,
    mode: manifest.mode,
    project: { key: manifest.project.key },
    build: {
      success: manifest.build.success,
      exitCode: manifest.build.exitCode,
      platform: manifest.build.platform,
      cacheMode: manifest.build.cacheMode,
      depth: manifest.build.depth,
      outputImageDigest: manifest.build.outputImageDigest,
      outputImageDigestUse: 'informational-only',
      durationMs: manifest.build.durationMs,
      passes: redactBuildValue(manifest.build.passes),
    },
    evidence: {
      complete: manifest.complete,
      candidateEligible: manifest.candidateEligible,
      evidenceUse: manifest.evidenceUse,
      incompleteReasons: redactBuildValue(manifest.incompleteReasons),
      candidateIneligibleReasons: redactBuildValue(manifest.candidateIneligibleReasons),
      sources: manifest.sources.map((source) => ({
        name: source.name,
        required: source.required,
        present: source.present,
        complete: source.complete,
        bytes: source.bytes,
        records: source.records,
        hash: source.hash,
        lostEvents: source.lostEvents,
        parseErrors: source.parseErrors,
        completionMarker: source.completionMarker,
      })),
    },
    metrics: redactBuildValue(manifest.metrics),
    observations: redactBuildValue(manifest.observations),
    candidate: candidate ? redactBuildValue(candidate) : null,
    attestation: {
      authoritative: false,
      attested: false,
      integrityOnly: true,
    },
    limitations: redactBuildValue(manifest.limitations),
  };
}

export function createPortableBundleManifest(input) {
  plainObject(input, 'portable bundle input');
  const runId = safeBuildSegment(input.runId, 'runId');
  const mode = normalizeBuildMode(input.mode);
  plainObject(input.files, 'portable bundle files');
  const files = {};
  for (const [name, descriptor] of Object.entries(input.files)) {
    const file = relativeArtifactName(name, 'portable bundle filename');
    plainObject(descriptor, `portable file ${file}`);
    const hash = optionalDigest(descriptor.hash, `${file} hash`);
    if (!hash) throw new TypeError(`${file} requires a hash`);
    files[file] = {
      hash,
      bytes: nonNegativeInteger(descriptor.bytes, `${file} bytes`),
      mediaType: String(descriptor.mediaType || 'application/octet-stream'),
    };
  }
  const unsigned = {
    schemaVersion: BUILD_PROFILE_SCHEMA_VERSION,
    apiVersion: BUILD_PROFILE_API_VERSION,
    kind: BUILD_ARTIFACT_KINDS.portableBundle,
    generatedAt: timestamp(input.generatedAt || new Date().toISOString(), 'generatedAt'),
    runId,
    mode,
    projectKey: String(input.projectKey || ''),
    authoritative: false,
    attested: false,
    integrityOnly: true,
    redacted: true,
    files,
  };
  if (!PROJECT_KEY_PATTERN.test(unsigned.projectKey)) {
    throw new TypeError('portable bundle projectKey is invalid');
  }
  return withContentHash(unsigned);
}
