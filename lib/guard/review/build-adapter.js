import fs from 'node:fs/promises';
import net from 'node:net';
import path from 'node:path';

import {
  BUILD_PROFILE_FILES,
  BuildProfileStore,
} from '../../guardd/build-profile-store.js';
import { validateBuildEvidenceManifest } from '../../guardd/build-profile-artifacts.js';
import {
  createScope,
  createStableId,
} from './ids.js';
import { jcsCanonicalize, sha256Digest } from './jcs.js';
import { readTrustedJson, readTrustedNdjson } from './io.js';
import {
  createCoverageMarker,
  createFinding,
  createGraphDiff,
  createGraphNode,
  createObservation,
  createPolicyProposal,
} from './records.js';

const SOURCE_DOMAIN = Object.freeze({
  'buildkit-progress': 'buildkit-progress',
  'buildx-history': 'buildx-history',
  'cgroup-metrics': 'cgroup-metrics',
  'ebpf-process': 'process',
  'ebpf-syscall': 'syscall',
  'ebpf-network': 'network',
  dns: 'dns',
  'ebpf-file': 'file',
  'sbom-source': 'sbom-source',
  'sbom-image': 'sbom-image',
});

const PORTABLE = Object.freeze({ classification: 'portable', fields: [] });
const PORTABLE_SENSITIVE = Object.freeze({
  classification: 'portable-sensitive',
  fields: [],
});
const PRIVATE = Object.freeze({ classification: 'private', fields: [] });
const HTTP_PORTABLE = Object.freeze({
  classification: 'portable-sensitive',
  fields: Object.freeze([
    Object.freeze({ path: '/properties/displayUrl', class: 'private' }),
  ]),
});

function clonePrivacy(value) {
  return {
    classification: value.classification,
    fields: (value.fields || []).map((field) => ({ ...field })),
  };
}

function boundedLabel(value, fallback = 'unknown') {
  const selected = String(value ?? fallback)
    .replace(/[\u0000-\u001f\u007f]+/g, ' ')
    .replace(/\s+/g, ' ')
    .trim();
  if (!selected) return fallback;
  if (Buffer.byteLength(selected, 'utf8') <= 512) return selected;
  let truncated = '';
  for (const character of selected) {
    if (Buffer.byteLength(`${truncated}${character}...`, 'utf8') > 512) break;
    truncated += character;
  }
  return `${truncated}...`;
}

function decimal(value, fallback = '0') {
  const selected = String(value ?? fallback);
  return /^(0|[1-9][0-9]*)$/.test(selected) ? selected : fallback;
}

function addDecimal(left, right) {
  return (BigInt(decimal(left)) + BigInt(decimal(right))).toString();
}

function maximumDecimal(left, right) {
  return (BigInt(decimal(left)) > BigInt(decimal(right))
    ? BigInt(decimal(left))
    : BigInt(decimal(right))).toString();
}

function networkProposalKey(tuple) {
  return JSON.stringify({
    family: tuple.family,
    address: tuple.address,
    protocol: tuple.protocol === 'icmpv6' ? 'icmp' : tuple.protocol,
    port: tuple.port,
    icmpType: tuple.icmpType ?? null,
    icmpCode: tuple.icmpCode ?? null,
  });
}

function timestampFromNanoseconds(value) {
  try {
    const selected = String(value ?? '');
    if (!/^(0|[1-9][0-9]*)$/.test(selected)) return null;
    const milliseconds = BigInt(selected) / 1_000_000n;
    if (milliseconds > BigInt(Number.MAX_SAFE_INTEGER)) return null;
    const date = new Date(Number(milliseconds));
    return Number.isFinite(date.getTime()) ? date.toISOString() : null;
  } catch {
    return null;
  }
}

function safeDomain(value) {
  const domain = String(value || '').trim().toLowerCase().replace(/\.$/, '');
  if (
    !domain
    || domain === '.'
    || domain.length > 253
    || !domain.includes('.')
    || !domain.split('.').every(
      (label) => /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(label),
    )
  ) {
    return null;
  }
  return domain;
}

function safeHttpHost(value) {
  const host = String(value || '').trim().toLowerCase();
  const selected = host.startsWith('[') && host.endsWith(']')
    ? host.slice(1, -1)
    : host;
  if (net.isIP(selected)) return selected;
  if (
    host.length <= 253
    && !host.endsWith('.')
    && host.split('.').every(
      (label) => /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(label),
    )
  ) {
    return host;
  }
  return null;
}

function assertExactKeys(value, required, optional, label) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    throw new TypeError(`${label} must be an object`);
  }
  const allowed = new Set([...required, ...optional]);
  for (const key of Object.keys(value)) {
    if (!allowed.has(key)) throw new TypeError(`${label}.${key} is not allowed`);
  }
  for (const key of required) {
    if (!Object.hasOwn(value, key)) throw new TypeError(`${label}.${key} is required`);
  }
}

function assertReviewDigest(value, label) {
  if (!/^sha256:[a-f0-9]{64}$/.test(String(value || ''))) {
    throw new TypeError(`${label} must be a sha256 digest`);
  }
}

function normalizedHttpResponse(value, label) {
  if (value === null) return null;
  assertExactKeys(value, ['status', 'complete'], [
    'contentSha256',
    'decodedContentSha256',
    'length',
    'redirectLocationSha256',
  ], label);
  if (!Number.isInteger(value.status) || value.status < 100 || value.status > 599) {
    throw new TypeError(`${label}.status must be an HTTP status`);
  }
  if (typeof value.complete !== 'boolean') {
    throw new TypeError(`${label}.complete must be boolean`);
  }
  for (const key of [
    'contentSha256',
    'decodedContentSha256',
    'redirectLocationSha256',
  ]) {
    if (Object.hasOwn(value, key)) assertReviewDigest(value[key], `${label}.${key}`);
  }
  if (Object.hasOwn(value, 'length') && !/^(0|[1-9][0-9]*)$/.test(value.length)) {
    throw new TypeError(`${label}.length must be a decimal string`);
  }
  if (value.complete && !value.contentSha256) {
    throw new TypeError(`${label}.contentSha256 is required for a complete response`);
  }
  return { ...value };
}

function normalizedHttpIntegrity(value, label) {
  if (value === null || value === undefined) return null;
  assertExactKeys(value, [
    'kind',
    'contentSha256',
    'verificationEvidenceSha256',
    'verified',
  ], [], label);
  if (![
    'npm-sri',
    'apt-signed-metadata',
    'publisher-signature',
    'reviewed-digest',
  ].includes(value.kind)) {
    throw new TypeError(`${label}.kind is unsupported`);
  }
  assertReviewDigest(value.contentSha256, `${label}.contentSha256`);
  assertReviewDigest(
    value.verificationEvidenceSha256,
    `${label}.verificationEvidenceSha256`,
  );
  if (value.verified !== true) throw new TypeError(`${label}.verified must be true`);
  return { ...value };
}

function normalizedHttpCas(value, label) {
  if (value === null || value === undefined) return null;
  assertExactKeys(value, [
    'objectSha256',
    'manifestSha256',
    'available',
  ], [], label);
  assertReviewDigest(value.objectSha256, `${label}.objectSha256`);
  assertReviewDigest(value.manifestSha256, `${label}.manifestSha256`);
  if (value.available !== true) throw new TypeError(`${label}.available must be true`);
  return { ...value };
}

function normalizedHttpDestination(value, label) {
  if (value === null) return null;
  assertExactKeys(value, ['ip', 'protocol', 'port'], [], label);
  const family = net.isIP(value.ip);
  if (!family) throw new TypeError(`${label}.ip must be an IP address`);
  if (value.protocol !== 'tcp') throw new TypeError(`${label}.protocol must be tcp`);
  if (!Number.isInteger(value.port) || value.port < 1 || value.port > 65535) {
    throw new TypeError(`${label}.port is invalid`);
  }
  return { ip: value.ip.toLowerCase(), protocol: 'tcp', port: value.port };
}

function normalizedHttpExchange(value, index) {
  const label = `HTTP exchange[${index}]`;
  assertExactKeys(value, [
    'id',
    'pass',
    'timestampUnixNs',
    'method',
    'scheme',
    'host',
    'port',
    'displayUrl',
    'requestTargetSha256',
    'representationHeadersSha256',
    'destination',
    'destinationRole',
    'response',
  ], [
    'requestBodySha256',
    'upstreamDestination',
    'integrity',
    'cas',
  ], label);
  if (typeof value.id !== 'string' || value.id.length < 1 || value.id.length > 512) {
    throw new TypeError(`${label}.id is invalid`);
  }
  if (!['cold', 'warm'].includes(value.pass)) throw new TypeError(`${label}.pass is invalid`);
  if (!/^(0|[1-9][0-9]*)$/.test(value.timestampUnixNs)) {
    throw new TypeError(`${label}.timestampUnixNs must be decimal`);
  }
  if (!/^[A-Z][A-Z0-9-]{0,31}$/.test(value.method)) {
    throw new TypeError(`${label}.method is invalid`);
  }
  if (value.method === 'CONNECT') {
    throw new TypeError(`${label}.method cannot represent an opaque CONNECT tunnel`);
  }
  if (!['http', 'https'].includes(value.scheme)) throw new TypeError(`${label}.scheme is invalid`);
  const host = safeHttpHost(value.host);
  if (!host || host !== value.host) throw new TypeError(`${label}.host must be canonical`);
  if (!Number.isInteger(value.port) || value.port < 1 || value.port > 65535) {
    throw new TypeError(`${label}.port is invalid`);
  }
  assertReviewDigest(value.requestTargetSha256, `${label}.requestTargetSha256`);
  if (value.requestBodySha256) {
    assertReviewDigest(value.requestBodySha256, `${label}.requestBodySha256`);
  }
  assertReviewDigest(
    value.representationHeadersSha256,
    `${label}.representationHeadersSha256`,
  );
  if (
    typeof value.displayUrl !== 'string'
    || value.displayUrl.length < 1
    || value.displayUrl.length > 8192
  ) {
    throw new TypeError(`${label}.displayUrl must be bounded to 8192 characters`);
  }
  let display;
  try {
    display = new URL(value.displayUrl);
  } catch {
    throw new TypeError(`${label}.displayUrl must be an absolute URL`);
  }
  if (
    display.protocol !== `${value.scheme}:`
    || display.hostname.toLowerCase().replace(/^\[|\]$/g, '')
      !== host.replace(/^\[|\]$/g, '')
    || Number(display.port || (value.scheme === 'https' ? 443 : 80)) !== value.port
    || display.username
    || display.password
    || display.search
    || display.hash
  ) {
    throw new TypeError(`${label}.displayUrl does not match its sanitized origin`);
  }
  const response = normalizedHttpResponse(value.response, `${label}.response`);
  const integrity = normalizedHttpIntegrity(value.integrity, `${label}.integrity`);
  const cas = normalizedHttpCas(value.cas, `${label}.cas`);
  const destination = normalizedHttpDestination(value.destination, `${label}.destination`);
  if (
    (destination === null && value.destinationRole !== null)
    || (
      destination !== null
      && !['workload-to-origin', 'workload-to-proxy'].includes(value.destinationRole)
    )
  ) {
    throw new TypeError(`${label}.destinationRole must describe the exact L4 join`);
  }
  const upstreamDestination = Object.hasOwn(value, 'upstreamDestination')
    ? normalizedHttpDestination(
      value.upstreamDestination,
      `${label}.upstreamDestination`,
    )
    : null;
  if (integrity && response?.contentSha256 !== integrity.contentSha256) {
    throw new TypeError(`${label}.integrity does not match the response content`);
  }
  if (cas && response?.contentSha256 !== cas.objectSha256) {
    throw new TypeError(`${label}.cas object does not match the response content`);
  }
  return {
    ...value,
    host,
    destination,
    ...(Object.hasOwn(value, 'upstreamDestination') ? { upstreamDestination } : {}),
    response,
    ...(integrity ? { integrity } : {}),
    ...(cas ? { cas } : {}),
  };
}

export function validateBuildHttpEvidence(value, pathLabel = 'build HTTP evidence') {
  assertExactKeys(value, [
    'contractVersion',
    'provider',
    'captureMode',
    'required',
    'complete',
    'gaps',
    'contentAssuranceGaps',
    'exchanges',
  ], [], pathLabel);
  if (value.contractVersion !== 2) {
    throw new TypeError(`${pathLabel}.contractVersion must be 2`);
  }
  if (!['mitmproxy', 'burp'].includes(value.provider)) {
    throw new TypeError(`${pathLabel}.provider is unsupported`);
  }
  if (!['managed', 'manual-import'].includes(value.captureMode)) {
    throw new TypeError(`${pathLabel}.captureMode is unsupported`);
  }
  if (value.captureMode === 'managed' && value.provider !== 'mitmproxy') {
    throw new TypeError(`${pathLabel} only managed mitmproxy capture may create authority`);
  }
  if (typeof value.required !== 'boolean' || typeof value.complete !== 'boolean') {
    throw new TypeError(`${pathLabel} coverage flags must be boolean`);
  }
  if (!Array.isArray(value.gaps) || !value.gaps.every((gap) => (
    typeof gap === 'string' && gap.length > 0 && Buffer.byteLength(gap) <= 8192
  ))) {
    throw new TypeError(`${pathLabel}.gaps must contain bounded strings`);
  }
  const contentAssuranceGaps = value.contentAssuranceGaps;
  if (!Array.isArray(contentAssuranceGaps) || !contentAssuranceGaps.every((gap) => (
    typeof gap === 'string' && gap.length > 0 && Buffer.byteLength(gap) <= 8192
  ))) {
    throw new TypeError(`${pathLabel}.contentAssuranceGaps must contain bounded strings`);
  }
  if (!Array.isArray(value.exchanges) || value.exchanges.length > 100_000) {
    throw new TypeError(`${pathLabel}.exchanges is invalid`);
  }
  if (value.complete !== (value.gaps.length === 0)) {
    throw new TypeError(`${pathLabel}.complete must agree with coverage gaps`);
  }
  if (value.captureMode === 'manual-import' && value.complete) {
    throw new TypeError(`${pathLabel} manual imports cannot claim complete capture`);
  }
  const exchanges = value.exchanges.map(normalizedHttpExchange);
  const ids = new Set(exchanges.map((exchange) => exchange.id));
  if (ids.size !== exchanges.length) throw new TypeError(`${pathLabel} exchange IDs must be unique`);
  return {
    ...value,
    gaps: [...new Set([
      ...value.gaps,
      ...(value.captureMode === 'manual-import'
        ? ['manual import does not attest capture completeness']
        : []),
    ])].sort(),
    contentAssuranceGaps: [...new Set(contentAssuranceGaps)].sort(),
    exchanges: exchanges.sort((left, right) => left.id.localeCompare(right.id)),
  };
}

function recordPass(record, currentPass, passes) {
  if (['cold', 'warm'].includes(record?.pass)) return record.pass;
  if (['cold', 'warm'].includes(currentPass)) return currentPass;
  return passes.length === 1 ? passes[0] : 'cold';
}

function sourcePrivacy(sourceName) {
  return ['ebpf-process', 'ebpf-file', 'buildkit-progress', 'buildx-history']
    .includes(sourceName)
    ? PRIVATE
    : PORTABLE_SENSITIVE;
}

export function buildTargetFeasibility(domain, peerKind = null, network = null) {
  if (domain === 'http') {
    return [
      ...[
        'cilium',
        'guard-ebpf',
        'guard-nftables',
        'gateway-iptables',
        'gateway-pf',
        'gateway-ipfw',
        'gateway-ipfilter',
      ].map((target) => ({
        target,
        status: target === 'guard-ebpf' ? 'outsideScope' : 'permissive',
        reasons: target === 'guard-ebpf'
          ? ['build-time HTTP authority cannot authorize the runtime eBPF subject']
          : ['layer-3/4 policy cannot express an exact HTTP request target or response identity'],
      })),
      {
        target: 'gateway-l7-proxy',
        status: 'exact',
        reasons: [],
      },
    ];
  }
  if (domain !== 'network') {
    return [
      'cilium',
      'guard-ebpf',
      'guard-nftables',
      'gateway-iptables',
      'gateway-pf',
      'gateway-ipfw',
      'gateway-ipfilter',
      'gateway-l7-proxy',
    ].map((target) => ({
      target,
      status: 'outsideScope',
      reasons: [`${target} v1 does not compile ${domain} build policy`],
    }));
  }
  if (peerKind === 'ipv4-cidr') {
    return [
      {
        target: 'cilium',
        status: 'conditional',
        reasons: ['requires an exact workload subject and exclusive selecting-policy ownership'],
      },
      {
        target: 'guard-ebpf',
        status: 'outsideScope',
        reasons: ['build-time behavior cannot authorize the runtime eBPF subject'],
      },
      {
        target: 'guard-nftables',
        status: 'exact',
        reasons: [],
      },
      {
        target: 'gateway-iptables',
        status: 'exact',
        reasons: [],
      },
      ...['gateway-pf', 'gateway-ipfw', 'gateway-ipfilter'].map((target) => ({
        target,
        status: 'exact',
        reasons: ['render-only export requires native syntax and live-state validation before activation'],
      })),
      {
        target: 'gateway-l7-proxy',
        status: 'exact',
        reasons: ['composite proxy target must select and verify an underlying network backend'],
      },
    ];
  }
  if (peerKind === 'fqdn') {
    return [
      ...['cilium', 'guard-nftables', 'gateway-iptables'].map((target) => ({
        target,
        status: 'conditional',
        reasons: ['requires managed DNS enforcement'],
      })),
      {
        target: 'guard-ebpf',
        status: 'outsideScope',
        reasons: ['build-time behavior cannot authorize the runtime eBPF subject'],
      },
      ...['gateway-pf', 'gateway-ipfw', 'gateway-ipfilter'].map((target) => ({
        target,
        status: 'conditional',
        reasons: [
          'requires a fail-closed TTL-aware managed DNS table updater',
          'render-only export requires native validation before activation',
        ],
      })),
      {
        target: 'gateway-l7-proxy',
        status: 'conditional',
        reasons: [
          'requires a fail-closed TTL-aware managed DNS table updater',
          'composite proxy target must select and verify an underlying network backend',
        ],
      },
    ];
  }
  return [
    'cilium',
    'guard-ebpf',
    'guard-nftables',
    'gateway-iptables',
    'gateway-pf',
    'gateway-ipfw',
    'gateway-ipfilter',
    'gateway-l7-proxy',
  ].map((target) => ({
    target,
    status: target === 'guard-ebpf' ? 'outsideScope' : 'unsupported',
    reasons: target === 'guard-ebpf'
      ? ['build-time behavior cannot authorize the runtime eBPF subject']
      : ['deployable policy v1 is IPv4-only'],
  }));
}

function sourceGaps(source) {
  const gaps = [];
  if (!source.present) gaps.push('source is missing');
  if (source.present && !source.complete) gaps.push('source is incomplete');
  if (Number(source.lostEvents || 0) > 0) {
    gaps.push(`${source.lostEvents} events were lost`);
  }
  if (Number(source.parseErrors || 0) > 0) {
    gaps.push(`${source.parseErrors} records failed to parse`);
  }
  if (source.present && source.complete && !source.completionMarker) {
    gaps.push('source has no completion marker');
  }
  return gaps;
}

async function readBuildSourceNdjson(directory, source, options = {}) {
  const result = await readTrustedNdjson(
    path.join(directory, ...source.file.split('/')),
    {
      ...options,
      expectedBytes: source.bytes,
      expectedDigest: source.hash,
    },
  );
  if (result.lines !== source.records) {
    throw new Error(
      `NDJSON record count does not match the build manifest for ${source.name}`,
    );
  }
  if (result.parseErrors !== source.parseErrors) {
    throw new Error(
      `NDJSON parse-error count does not match the build manifest for ${source.name}`,
    );
  }
  return result;
}

function graphAccumulator() {
  const roles = {
    nodes: new Map(),
    observations: new Map(),
    coverage: new Map(),
    findings: new Map(),
    proposals: new Map(),
    diff: new Map(),
  };
  const add = (role, record) => {
    const previous = roles[role].get(record.id);
    if (previous && jcsCanonicalize(previous) !== jcsCanonicalize(record)) {
      throw new Error(`semantic graph record collision for ${record.id}`);
    }
    roles[role].set(record.id, record);
    return record;
  };
  const replace = (role, record) => {
    if (!roles[role].has(record.id)) {
      throw new Error(`cannot replace missing semantic graph record ${record.id}`);
    }
    roles[role].set(record.id, record);
    return record;
  };
  return {
    add,
    replace,
    get(role, id) {
      return roles[role].get(id) || null;
    },
    result() {
      return Object.fromEntries(Object.entries(roles).map(([role, entries]) => [
        role,
        [...entries.values()].sort((left, right) => left.id.localeCompare(right.id)),
      ]));
    },
  };
}

async function resolveVerifiedBuildProfile(input) {
  const requested = await fs.realpath(path.resolve(input));
  const stat = await fs.lstat(requested);
  const directory = stat.isDirectory() ? requested : path.dirname(requested);
  const manifestPath = path.join(directory, BUILD_PROFILE_FILES.evidence);
  const { document: manifest } = await readTrustedJson(manifestPath, {
    maximumBytes: 64 * 1024 * 1024,
  });
  validateBuildEvidenceManifest(manifest);
  const inferredRoot = path.dirname(path.dirname(directory));
  const store = new BuildProfileStore({
    [manifest.mode === 'build-net-learn' ? 'networkRoot' : 'profileRoot']: inferredRoot,
  });
  const verified = await store.read(
    manifest.project.canonicalPath,
    manifest.runId,
    { mode: manifest.mode },
  );
  if (await fs.realpath(verified.directory) !== directory) {
    throw new Error('requested build profile does not match its verified store entry');
  }
  return verified;
}

function createBuildScope(manifest, runtimeBinding = null) {
  const dockerfileDigest = manifest.observations?.provenance?.dockerfileDigest || null;
  if (runtimeBinding) {
    const imageDigest = runtimeBinding.imageDigest;
    const workspaceDigest = sha256Digest({
      workspaceKey: runtimeBinding.workspaceKey,
      workspaceIdentity: runtimeBinding.workspaceIdentity,
    });
    const identity = {
      class: 'runtime',
      subjectId: createStableId('subject', {
        projectKey: manifest.project.key,
        platform: manifest.build.platform,
        target: manifest.build.target,
        dockerfileDigest,
        imageDigest,
        workspaceDigest,
      }),
      projectKey: manifest.project.key,
      platform: manifest.build.platform,
      target: manifest.build.target,
      dockerfileDigest,
      imageDigest,
      workspaceDigest,
    };
    return createScope(identity);
  }
  const identity = {
    class: 'build',
    subjectId: createStableId('subject', {
      projectKey: manifest.project.key,
      platform: manifest.build.platform,
      target: manifest.build.target,
      dockerfileDigest,
    }),
    projectKey: manifest.project.key,
    platform: manifest.build.platform,
    target: manifest.build.target,
    dockerfileDigest,
    imageDigest: null,
    workspaceDigest: null,
  };
  return createScope(identity);
}

function structuralGraph(accumulator, manifest, manifestHash, scope) {
  const manifestSource = accumulator.add('nodes', createGraphNode({
    semanticKey: { manifestHash },
    scopeDigest: scope.scopeDigest,
    nodeType: 'evidenceSource',
    label: 'Build evidence manifest',
    identity: { name: BUILD_PROFILE_FILES.evidence, digest: manifestHash },
    properties: {
      complete: manifest.complete,
      candidateEligible: manifest.candidateEligible,
      evidenceUse: manifest.evidenceUse,
    },
    evidenceRefs: [],
    privacy: clonePrivacy(PORTABLE),
  }));
  const project = accumulator.add('nodes', createGraphNode({
    id: scope.subjectId,
    semanticKey: { projectKey: manifest.project.key },
    scopeDigest: scope.scopeDigest,
    nodeType: 'project',
    label: `Project ${manifest.project.key.slice(0, 12)}`,
    identity: { projectKey: manifest.project.key },
    properties: {},
    evidenceRefs: [manifestSource.id],
    privacy: clonePrivacy(PORTABLE),
  }));
  const run = accumulator.add('nodes', createGraphNode({
    semanticKey: { runId: manifest.runId },
    scopeDigest: scope.scopeDigest,
    nodeType: 'buildRun',
    label: `Build ${manifest.runId}`,
    identity: { runId: manifest.runId },
    properties: {
      mode: manifest.mode,
      cacheMode: manifest.build.cacheMode,
      depth: manifest.build.depth,
      complete: manifest.complete,
      candidateEligible: manifest.candidateEligible,
      startedAt: manifest.startedAt,
      endedAt: manifest.endedAt,
    },
    evidenceRefs: [manifestSource.id],
    privacy: clonePrivacy(PORTABLE),
  }));
  accumulator.add('observations', createObservation({
    scopeDigest: scope.scopeDigest,
    observationType: 'contains',
    subjectId: project.id,
    objectId: run.id,
    basis: 'observed',
    confidence: 100,
    count: '1',
    evidenceRefs: [manifestSource.id],
    properties: {},
    privacy: clonePrivacy(PORTABLE),
  }));
  const passes = new Map();
  for (const pass of manifest.build.passes) {
    const passNode = accumulator.add('nodes', createGraphNode({
      semanticKey: { runId: manifest.runId, pass: pass.name },
      scopeDigest: scope.scopeDigest,
      nodeType: 'buildPass',
      label: `${pass.name} pass`,
      identity: { runId: manifest.runId, pass: pass.name },
      properties: {
        success: pass.success,
        exitCode: pass.exitCode,
        durationMs: String(pass.durationMs ?? 0),
        cache: pass.cache,
      },
      evidenceRefs: [manifestSource.id],
      privacy: clonePrivacy(PORTABLE),
    }));
    passes.set(pass.name, passNode);
    accumulator.add('observations', createObservation({
      scopeDigest: scope.scopeDigest,
      observationType: 'contains',
      subjectId: run.id,
      objectId: passNode.id,
      basis: 'observed',
      confidence: 100,
      count: '1',
      evidenceRefs: [manifestSource.id],
      properties: {},
      privacy: clonePrivacy(PORTABLE),
    }));
  }
  return { manifestSource, project, run, passes };
}

function sourceGraph(accumulator, manifest, scope, manifestSource) {
  const sources = new Map();
  for (const source of manifest.sources) {
    const node = accumulator.add('nodes', createGraphNode({
      semanticKey: {
        runId: manifest.runId,
        sourceName: source.name,
        sourceHash: source.hash,
      },
      scopeDigest: scope.scopeDigest,
      nodeType: 'evidenceSource',
      label: source.name,
      identity: {
        runId: manifest.runId,
        sourceName: source.name,
        sourceHash: source.hash,
      },
      properties: {
        required: source.required,
        present: source.present,
        complete: source.complete,
        bytes: String(source.bytes),
        records: String(source.records),
        lostEvents: String(source.lostEvents),
        parseErrors: String(source.parseErrors),
        completionMarker: source.completionMarker,
      },
      evidenceRefs: [manifestSource.id],
      privacy: clonePrivacy(sourcePrivacy(source.name)),
    }));
    sources.set(source.name, node);
    const gaps = sourceGaps(source);
    const domain = SOURCE_DOMAIN[source.name];
    if (domain) {
      accumulator.add('coverage', createCoverageMarker({
        scopeDigest: scope.scopeDigest,
        domain,
        status: gaps.length ? (source.present ? 'incomplete' : 'unavailable') : 'complete',
        sourceIds: [node.id],
        counters: {
          bytes: String(source.bytes),
          records: String(source.records),
          lostEvents: String(source.lostEvents),
          parseErrors: String(source.parseErrors),
        },
        gaps,
        blocking: source.required && gaps.length > 0,
        privacy: clonePrivacy(PORTABLE),
      }));
    }
  }
  return sources;
}

function createBuildFinding(accumulator, scope, runId, sourceId, message, index) {
  return accumulator.add('findings', createFinding({
    semanticKey: { runId, message, index },
    scopeDigest: scope.scopeDigest,
    findingType: /coverage|source|evidence|collector|parse/i.test(message)
      ? 'coverage-degraded'
      : 'unresolved-evidence',
    severity: 'high',
    blocking: true,
    message: boundedLabel(message),
    semanticRefs: [],
    evidenceRefs: [sourceId],
    properties: {},
    privacy: clonePrivacy(PORTABLE),
  }));
}

function ensureNode(accumulator, nodes, key, factory) {
  if (!nodes.has(key)) nodes.set(key, accumulator.add('nodes', factory()));
  return nodes.get(key);
}

async function ingestBuildkit(input) {
  const {
    accumulator,
    directory,
    source,
    sourceNode,
    scope,
    passes,
  } = input;
  let currentPass = null;
  const vertexNodes = new Map();
  await readBuildSourceNdjson(directory, source, {
    onRecord(record) {
      if (record.recordKind === 'pass_boundary') {
        currentPass = record.pass;
        return;
      }
      const passName = recordPass(record, currentPass, [...passes.keys()]);
      const pass = passes.get(passName);
      if (!pass) return;
      for (const vertex of record.vertexes || []) {
        if (!vertex?.digest) continue;
        const vertexNode = ensureNode(
          accumulator,
          vertexNodes,
          String(vertex.digest),
          () => createGraphNode({
            semanticKey: { scopeDigest: scope.scopeDigest, digest: vertex.digest },
            scopeDigest: scope.scopeDigest,
            nodeType: 'buildkitVertex',
            label: boundedLabel(vertex.name || vertex.digest),
            identity: { digest: String(vertex.digest) },
            properties: {
              cached: vertex.cached === true,
              error: Boolean(vertex.error),
              startedAt: vertex.started || null,
              completedAt: vertex.completed || null,
            },
            evidenceRefs: [sourceNode.id],
            privacy: clonePrivacy(PRIVATE),
          }),
        );
        accumulator.add('observations', createObservation({
          semanticKey: {
            passId: pass.id,
            vertexId: vertexNode.id,
            sourceId: sourceNode.id,
          },
          scopeDigest: scope.scopeDigest,
          observationType: 'contains',
          subjectId: pass.id,
          objectId: vertexNode.id,
          basis: 'observed',
          confidence: 100,
          count: '1',
          evidenceRefs: [sourceNode.id],
          properties: { pass: passName },
          privacy: clonePrivacy(PRIVATE),
        }));
      }
    },
  });
}

async function ingestProcessAndDns(input) {
  const {
    accumulator,
    directory,
    source,
    sourceNode,
    scope,
    passes,
    proposalAggregates,
  } = input;
  let currentPass = null;
  const nodes = new Map();
  const observations = new Map();
  await readBuildSourceNdjson(directory, source, {
    onRecord(record) {
      if (record.recordKind === 'pass_boundary') {
        currentPass = record.pass;
        return;
      }
      const passName = recordPass(record, currentPass, [...passes.keys()]);
      const pass = passes.get(passName);
      if (!pass) return;
      if (record.eventKind === 'process-exec' && record.process) {
        const executable = String(record.executable || record.process.comm || 'unknown');
        const executableNode = ensureNode(
          accumulator,
          nodes,
          `executable:${executable}`,
          () => createGraphNode({
            semanticKey: { scopeDigest: scope.scopeDigest, executable },
            scopeDigest: scope.scopeDigest,
            nodeType: 'executable',
            label: boundedLabel(executable),
            identity: { executable },
            properties: {},
            evidenceRefs: [sourceNode.id],
            privacy: clonePrivacy(PRIVATE),
          }),
        );
        const processNode = accumulator.add('nodes', createGraphNode({
          semanticKey: {
            runId: input.runId,
            pass: passName,
            cgroupId: record.observedCgroupId,
            pid: record.process.pid,
            timestampNs: record.timestampNs,
          },
          scopeDigest: scope.scopeDigest,
          nodeType: 'process',
          label: boundedLabel(record.process.comm || `pid ${record.process.pid}`),
          identity: {
            runId: input.runId,
            pass: passName,
            pid: String(record.process.pid),
            timestampNs: decimal(record.timestampNs),
          },
          properties: {
            tid: String(record.process.tid),
            ppid: String(record.process.ppid),
            uid: String(record.process.uid),
            gid: String(record.process.gid),
            comm: record.process.comm,
          },
          evidenceRefs: [sourceNode.id],
          privacy: clonePrivacy(PRIVATE),
        }));
        const timestamp = timestampFromNanoseconds(record.timestampNs);
        accumulator.add('observations', createObservation({
          scopeDigest: scope.scopeDigest,
          observationType: 'executes',
          subjectId: processNode.id,
          objectId: executableNode.id,
          basis: 'observed',
          confidence: 100,
          count: '1',
          evidenceRefs: [sourceNode.id],
          properties: { pass: passName },
          ...(timestamp ? { firstObservedAt: timestamp, lastObservedAt: timestamp } : {}),
          privacy: clonePrivacy(PRIVATE),
        }));
        accumulator.add('observations', createObservation({
          scopeDigest: scope.scopeDigest,
          observationType: 'contains',
          subjectId: pass.id,
          objectId: processNode.id,
          basis: 'observed',
          confidence: 100,
          count: '1',
          evidenceRefs: [sourceNode.id],
          properties: {},
          privacy: clonePrivacy(PRIVATE),
        }));
        if (executable.startsWith('/') && !/[\r\n]/.test(executable)) {
          proposalAggregates.process.set(executable, {
            peer: { kind: 'executable', value: executable },
            evidenceRef: sourceNode.id,
            objectId: executableNode.id,
          });
        } else {
          accumulator.add('findings', createFinding({
            semanticKey: { type: 'relative-executable', executable },
            scopeDigest: scope.scopeDigest,
            findingType: 'unresolved-evidence',
            severity: 'medium',
            blocking: false,
            message: 'An executed program was captured without an absolute executable path.',
            semanticRefs: [executableNode.id],
            evidenceRefs: [sourceNode.id],
            properties: { executable },
            privacy: clonePrivacy(PRIVATE),
          }));
        }
      } else if (record.eventKind === 'dns-query' && record.dns?.qname) {
        const domain = safeDomain(record.dns.qname);
        if (!domain) {
          const capturedName = boundedLabel(record.dns.qname, 'unresolved DNS name');
          const unresolvedNode = ensureNode(
            accumulator,
            nodes,
            `unresolved-domain:${capturedName}`,
            () => createGraphNode({
              semanticKey: { unresolvedDnsName: capturedName },
              scopeDigest: scope.scopeDigest,
              nodeType: 'domain',
              label: capturedName,
              identity: { capturedName },
              properties: { policyRepresentable: false },
              evidenceRefs: [sourceNode.id],
              privacy: clonePrivacy(PORTABLE_SENSITIVE),
            }),
          );
          accumulator.add('findings', createFinding({
            semanticKey: { type: 'unsupported-dns-name', capturedName },
            scopeDigest: scope.scopeDigest,
            findingType: 'unsupported-target',
            severity: 'high',
            blocking: true,
            message: 'A captured DNS name cannot be represented by the exact-FQDN policy v1 contract.',
            semanticRefs: [unresolvedNode.id],
            evidenceRefs: [sourceNode.id],
            properties: { capturedName },
            privacy: clonePrivacy(PORTABLE_SENSITIVE),
          }));
          return;
        }
        const domainNode = ensureNode(
          accumulator,
          nodes,
          `domain:${domain}`,
          () => createGraphNode({
            semanticKey: { domain },
            scopeDigest: scope.scopeDigest,
            nodeType: 'domain',
            label: domain,
            identity: { fqdn: domain },
            properties: {},
            evidenceRefs: [sourceNode.id],
            privacy: clonePrivacy(PORTABLE_SENSITIVE),
          }),
        );
        const key = `${pass.id}:${domainNode.id}`;
        const existing = observations.get(key) || {
          count: '0',
          first: null,
          last: null,
          pass,
          domainNode,
        };
        existing.count = addDecimal(existing.count, '1');
        const timestamp = timestampFromNanoseconds(record.timestampNs);
        if (timestamp) {
          existing.first = existing.first && existing.first < timestamp
            ? existing.first
            : timestamp;
          existing.last = existing.last && existing.last > timestamp
            ? existing.last
            : timestamp;
        }
        observations.set(key, existing);
      }
    },
  });
  for (const entry of observations.values()) {
    accumulator.add('observations', createObservation({
      scopeDigest: scope.scopeDigest,
      observationType: 'queries',
      subjectId: entry.pass.id,
      objectId: entry.domainNode.id,
      basis: 'observed',
      confidence: 100,
      count: entry.count,
      evidenceRefs: [sourceNode.id],
      properties: {
        processAttribution: null,
        attributionScope: 'build-pass-cgroup',
      },
      ...(entry.first ? {
        firstObservedAt: entry.first,
        lastObservedAt: entry.last,
      } : {}),
      privacy: clonePrivacy(PORTABLE_SENSITIVE),
    }));
  }
}

async function ingestSyscalls(input) {
  const {
    accumulator,
    directory,
    source,
    sourceNode,
    scope,
    passes,
    proposalAggregates,
  } = input;
  let currentPass = null;
  const totals = new Map();
  await readBuildSourceNdjson(directory, source, {
    onRecord(record) {
      if (record.recordKind === 'pass_boundary') {
        currentPass = record.pass;
        return;
      }
      if (record.recordKind !== 'syscall-summary') return;
      const passName = recordPass(record, currentPass, [...passes.keys()]);
      const pass = passes.get(passName);
      if (!pass || decimal(record.calls) === '0') return;
      const key = `${passName}:${record.targetCgroupId}:${record.syscallNumber}`;
      const total = totals.get(key) || {
        pass,
        passName,
        targetCgroupId: decimal(record.targetCgroupId),
        syscallNumber: String(record.syscallNumber),
        calls: '0',
        completions: '0',
        errors: '0',
        totalDurationNs: '0',
        maxDurationNs: '0',
      };
      total.calls = addDecimal(total.calls, record.calls);
      total.completions = addDecimal(total.completions, record.completions);
      total.errors = addDecimal(total.errors, record.errors);
      total.totalDurationNs = addDecimal(total.totalDurationNs, record.totalDurationNs);
      total.maxDurationNs = maximumDecimal(total.maxDurationNs, record.maxDurationNs);
      totals.set(key, total);
    },
  });
  for (const total of totals.values()) {
    const syscallNode = accumulator.add('nodes', createGraphNode({
      semanticKey: {
        scopeDigest: scope.scopeDigest,
        pass: total.passName,
        cgroupId: total.targetCgroupId,
        syscallNumber: total.syscallNumber,
      },
      scopeDigest: scope.scopeDigest,
      nodeType: 'syscall',
      label: `syscall ${total.syscallNumber}`,
      identity: {
        number: total.syscallNumber,
        auditArchitecture: null,
      },
      properties: {},
      evidenceRefs: [sourceNode.id],
      privacy: clonePrivacy(PORTABLE),
    }));
    accumulator.add('observations', createObservation({
      scopeDigest: scope.scopeDigest,
      observationType: 'invokes',
      subjectId: total.pass.id,
      objectId: syscallNode.id,
      basis: 'observed',
      confidence: 100,
      count: total.calls,
      evidenceRefs: [sourceNode.id],
      properties: {
        attributionScope: 'build-pass-cgroup',
        completions: total.completions,
        errors: total.errors,
        totalDurationNs: total.totalDurationNs,
        maxDurationNs: total.maxDurationNs,
        auditArchitecture: null,
      },
      privacy: clonePrivacy(PORTABLE),
    }));
    proposalAggregates.syscall.set(total.syscallNumber, {
      peer: { kind: 'syscall', value: total.syscallNumber },
      evidenceRef: sourceNode.id,
      objectId: syscallNode.id,
    });
  }
}

async function ingestNetwork(input) {
  const {
    accumulator,
    directory,
    source,
    sourceNode,
    scope,
    passes,
    proposalAggregates,
  } = input;
  let currentPass = null;
  const totals = new Map();
  const flowTotals = new Map();
  const endpointNodes = new Map();
  await readBuildSourceNdjson(directory, source, {
    onRecord(record) {
      if (record.recordKind === 'pass_boundary') {
        currentPass = record.pass;
        return;
      }
      const eventKind = record.recordKind === 'flow-summary'
        ? 'flow-summary'
        : record.eventKind;
      if (!['attempt', 'flow-summary', 'packet'].includes(eventKind)) return;
      const network = record.network;
      if (
        network?.direction !== 'egress'
        || !['tcp', 'udp', 'icmp', 'icmpv6'].includes(network.protocol)
        || !network.destinationAddress
      ) return;
      const passName = recordPass(record, currentPass, [...passes.keys()]);
      const pass = passes.get(passName);
      if (!pass) return;
      const port = network.protocol === 'tcp' || network.protocol === 'udp'
        ? Number(network.destinationPort)
        : null;
      if (port != null && (!Number.isSafeInteger(port) || port < 1 || port > 65535)) {
        return;
      }
      const tuple = {
        family: network.family,
        address: String(network.destinationAddress).toLowerCase(),
        protocol: network.protocol,
        port,
        icmpType: network.icmpType ?? null,
        icmpCode: network.icmpCode ?? null,
      };
      const key = JSON.stringify({ passName, ...tuple });
      const total = totals.get(key) || {
        pass,
        passName,
        tuple,
        attempts: '0',
        packets: '0',
        ownerMissing: false,
        first: null,
        last: null,
      };
      if (eventKind === 'attempt') {
        total.attempts = addDecimal(total.attempts, '1');
      } else {
        if (eventKind === 'flow-summary' && record.process == null) {
          total.ownerMissing = true;
        }
        const flowKey = JSON.stringify({
          passName,
          cgroupId: decimal(record.cgroupId),
          socketCookie: decimal(record.socketCookie),
          direction: network.direction,
          family: network.family,
          protocol: network.protocol,
          sourceAddress: network.sourceAddress || null,
          destinationAddress: network.destinationAddress,
          sourcePort: network.sourcePort ?? null,
          destinationPort: network.destinationPort ?? null,
          icmpType: network.icmpType ?? null,
          icmpCode: network.icmpCode ?? null,
          ifindex: network.ifindex ?? null,
        });
        const flow = flowTotals.get(flowKey) || {
          endpointKey: key,
          packets: '0',
        };
        flow.packets = maximumDecimal(
          flow.packets,
          decimal(record.accounting?.packets || '1', '1'),
        );
        flowTotals.set(flowKey, flow);
      }
      const first = timestampFromNanoseconds(
        eventKind === 'flow-summary' ? record.firstObservedNs : record.timestampNs,
      );
      const last = timestampFromNanoseconds(
        eventKind === 'flow-summary' ? record.lastObservedNs : record.timestampNs,
      );
      if (first) {
        total.first = total.first && total.first < first ? total.first : first;
      }
      if (last) {
        total.last = total.last && total.last > last ? total.last : last;
      }
      totals.set(key, total);
    },
  });
  for (const flow of flowTotals.values()) {
    const total = totals.get(flow.endpointKey);
    if (total) total.packets = addDecimal(total.packets, flow.packets);
  }
  for (const total of totals.values()) {
    const observedCount = total.packets !== '0' ? total.packets : total.attempts;
    if (observedCount === '0') continue;
    const tupleKey = JSON.stringify(total.tuple);
    const endpoint = ensureNode(
      accumulator,
      endpointNodes,
      tupleKey,
      () => createGraphNode({
        semanticKey: total.tuple,
        scopeDigest: scope.scopeDigest,
        nodeType: 'networkEndpoint',
        label: `${total.tuple.address}${total.tuple.port ? `:${total.tuple.port}` : ''}/${total.tuple.protocol}`,
        identity: total.tuple,
        properties: {},
        evidenceRefs: [sourceNode.id],
        privacy: clonePrivacy(PORTABLE_SENSITIVE),
      }),
    );
    const observation = accumulator.add('observations', createObservation({
      scopeDigest: scope.scopeDigest,
      observationType: 'connects',
      subjectId: total.pass.id,
      objectId: endpoint.id,
      basis: 'observed',
      confidence: 100,
      count: observedCount,
      evidenceRefs: [sourceNode.id],
      properties: {
        attributionScope: 'build-pass-cgroup',
        completion: 'unknown',
        attempts: total.attempts,
        packets: total.packets,
      },
      ...(total.first ? {
        firstObservedAt: total.first,
        lastObservedAt: total.last,
      } : {}),
      privacy: clonePrivacy(PORTABLE_SENSITIVE),
    }));
    if (total.ownerMissing) {
      accumulator.add('findings', createFinding({
        semanticKey: {
          type: 'missing-flow-owner',
          pass: total.passName,
          tuple: total.tuple,
        },
        scopeDigest: scope.scopeDigest,
        findingType: 'coverage-degraded',
        severity: 'medium',
        blocking: false,
        message: 'A final network flow had no surviving socket-owner attribution.',
        semanticRefs: [endpoint.id],
        evidenceRefs: [sourceNode.id],
        properties: { attribution: 'socket-cookie-cache-miss' },
        privacy: clonePrivacy(PORTABLE_SENSITIVE),
      }));
    }
    const protocol = total.tuple.protocol === 'icmpv6'
      ? 'icmp'
      : total.tuple.protocol;
    const proposalKey = networkProposalKey({
      ...total.tuple,
      protocol,
    });
    const proposalAggregate = proposalAggregates.network.get(proposalKey) || {
      tuple: total.tuple,
      evidenceRef: sourceNode.id,
      objectId: endpoint.id,
      observationRefs: new Set(),
      observationRefsByPass: new Map(),
      authorityGroups: new Map(),
    };
    proposalAggregate.observationRefs.add(observation.id);
    const passObservationRefs = proposalAggregate.observationRefsByPass.get(total.passName)
      || new Set();
    passObservationRefs.add(observation.id);
    proposalAggregate.observationRefsByPass.set(total.passName, passObservationRefs);
    proposalAggregates.network.set(proposalKey, proposalAggregate);
  }
}

function matchingNetworkAggregate(proposalAggregates, destination, passName) {
  if (!destination) return null;
  const ipVersion = net.isIP(destination.ip);
  if (!ipVersion) return null;
  const aggregate = proposalAggregates.network.get(networkProposalKey({
    family: ipVersion === 4 ? 'ipv4' : 'ipv6',
    address: destination.ip.toLowerCase(),
    protocol: destination.protocol,
    port: destination.port,
    icmpType: null,
    icmpCode: null,
  })) || null;
  if (!aggregate) return null;
  const observationRefs = aggregate.observationRefsByPass.get(passName);
  if (!observationRefs || observationRefs.size === 0) return null;
  return {
    ...aggregate,
    observationRefs,
  };
}

function addHttpRequestEvidence(input) {
  const {
    accumulator,
    scope,
    pass,
    evidenceRef,
    semanticIdentity,
    identity,
    properties,
    timestampNs,
  } = input;
  const requestNode = accumulator.add('nodes', createGraphNode({
    semanticKey: {
      scopeDigest: scope.scopeDigest,
      httpRequest: semanticIdentity,
    },
    scopeDigest: scope.scopeDigest,
    nodeType: 'httpRequest',
    label: boundedLabel(`${identity.scheme}://${identity.host}:${identity.port}`),
    identity,
    properties,
    evidenceRefs: [evidenceRef],
    privacy: clonePrivacy(HTTP_PORTABLE),
  }));
  const timestamp = timestampFromNanoseconds(timestampNs);
  const requestObservation = accumulator.add('observations', createObservation({
    scopeDigest: scope.scopeDigest,
    observationType: 'requests',
    subjectId: pass.id,
    objectId: requestNode.id,
    basis: 'observed',
    confidence: 100,
    count: '1',
    evidenceRefs: [evidenceRef],
    properties: {
      provider: properties.provider,
      captureMode: properties.captureMode,
      authoritativeReachability: false,
    },
    ...(timestamp ? { firstObservedAt: timestamp, lastObservedAt: timestamp } : {}),
    privacy: clonePrivacy(PORTABLE_SENSITIVE),
  }));
  return { requestNode, requestObservation };
}

function addHttpResponseEvidence(input) {
  const {
    accumulator,
    scope,
    requestNode,
    evidenceRef,
    exchangeId,
    response,
    integrity,
    cas,
    timestampNs,
  } = input;
  if (!response) return { responseNode: null, responseObservation: null };
  const responseNode = accumulator.add('nodes', createGraphNode({
    semanticKey: {
      scopeDigest: scope.scopeDigest,
      httpResponse: exchangeId,
      status: response.status,
      contentSha256: response.contentSha256 || null,
    },
    scopeDigest: scope.scopeDigest,
    nodeType: 'httpResponse',
    label: `HTTP ${response.status}`,
    identity: {
      exchangeId: sha256Digest(exchangeId),
      status: response.status,
      contentSha256: response.contentSha256 || null,
      decodedContentSha256: response.decodedContentSha256 || null,
      redirectLocationSha256: response.redirectLocationSha256 || null,
      length: response.length || null,
    },
    properties: {
      complete: response.complete,
      redirectLocationSha256: response.redirectLocationSha256 || null,
      integrity: integrity || null,
      cas: cas || null,
    },
    evidenceRefs: [evidenceRef],
    privacy: clonePrivacy(PORTABLE_SENSITIVE),
  }));
  const timestamp = timestampFromNanoseconds(timestampNs);
  const responseObservation = accumulator.add('observations', createObservation({
    scopeDigest: scope.scopeDigest,
    observationType: 'respondsWith',
    subjectId: requestNode.id,
    objectId: responseNode.id,
    basis: 'observed',
    confidence: 100,
    count: '1',
    evidenceRefs: [evidenceRef],
    properties: { complete: response.complete },
    ...(timestamp ? { firstObservedAt: timestamp, lastObservedAt: timestamp } : {}),
    privacy: clonePrivacy(PORTABLE_SENSITIVE),
  }));
  return { responseNode, responseObservation };
}

function correlateHttpRequestToNetwork(input) {
  const {
    accumulator,
    scope,
    requestNode,
    requestObservation,
    evidenceRef,
    networkEntry,
    confidence,
    authorityGroupId,
  } = input;
  if (!networkEntry) return null;
  const correlation = accumulator.add('observations', createObservation({
    semanticKey: {
      scopeDigest: scope.scopeDigest,
      requestId: requestNode.id,
      endpointId: networkEntry.objectId,
      authorityGroupId,
    },
    scopeDigest: scope.scopeDigest,
    observationType: 'correlatesWith',
    subjectId: requestNode.id,
    objectId: networkEntry.objectId,
    basis: 'correlated',
    confidence,
    algorithm: 'bounded-http-l4-correlation-v1',
    count: '1',
    evidenceRefs: [evidenceRef, networkEntry.evidenceRef],
    properties: {
      authoritativeReachability: false,
      independentNetworkEvidenceRequired: true,
    },
    privacy: clonePrivacy(PORTABLE_SENSITIVE),
  }));
  networkEntry.authorityGroups.set(authorityGroupId, {
    authorityGroupId,
    requestNode,
    evidenceRefs: [...new Set([evidenceRef, networkEntry.evidenceRef])].sort(),
    observationRefs: [...new Set([
      requestObservation.id,
      correlation.id,
      ...networkEntry.observationRefs,
    ])].sort(),
  });
  return correlation;
}

function addHttpCoverage(accumulator, scope, evidenceRef, input) {
  const gaps = [...new Set(input.gaps || [])].sort();
  accumulator.add('coverage', createCoverageMarker({
    scopeDigest: scope.scopeDigest,
    domain: 'http-capture',
    status: input.complete ? 'complete' : (input.exchanges > 0 ? 'incomplete' : 'unavailable'),
    sourceIds: [],
    counters: {
      exchanges: String(input.exchanges),
      correlated: String(input.correlated),
      uncorrelated: String(input.uncorrelated),
    },
    gaps,
    blocking: input.required && !input.complete,
    semanticKey: {
      scopeDigest: scope.scopeDigest,
      domain: 'http-capture',
      evidenceRef,
      producer: input.producer,
    },
    privacy: clonePrivacy(PORTABLE),
  }));
}

function addArtifactIntegrityCoverage(accumulator, scope, evidenceRef, input) {
  const gaps = [...new Set(input.gaps || [])];
  if (input.completeResponses < input.exchanges) {
    gaps.push('some HTTP exchanges lack a complete response identity');
  }
  if (input.nativeIntegrity === 0 && input.casObjects === 0) {
    gaps.push('no native integrity proof or immutable CAS object was observed');
  }
  const complete = gaps.length === 0;
  accumulator.add('coverage', createCoverageMarker({
    semanticKey: {
      scopeDigest: scope.scopeDigest,
      domain: 'artifact-integrity',
      evidenceRef,
    },
    scopeDigest: scope.scopeDigest,
    domain: 'artifact-integrity',
    status: complete ? 'complete' : (input.exchanges > 0 ? 'incomplete' : 'unavailable'),
    sourceIds: [],
    counters: {
      exchanges: String(input.exchanges),
      completeResponses: String(input.completeResponses),
      nativeIntegrity: String(input.nativeIntegrity),
      casObjects: String(input.casObjects),
    },
    gaps: gaps.length > 0 ? gaps.sort() : [],
    blocking: false,
    privacy: clonePrivacy(PORTABLE),
  }));
}

function ingestObservedUrlResources(input) {
  const {
    accumulator,
    manifest,
    scope,
    passes,
    proposalAggregates,
    evidenceRef,
  } = input;
  const network = manifest.observations?.network;
  if (network?.evidenceContractVersion !== 2 || !Array.isArray(network.resources)) return;
  const resourcesById = new Map(network.resources.map((resource) => [resource.id, resource]));
  let correlated = 0;
  let uncorrelated = 0;
  const additionalGaps = [];
  for (const resource of network.resources) {
    if (resource.source !== 'nosh-url' || !resource.id) continue;
    const pass = passes.get(resource.pass);
    if (!pass) continue;
    const resourcePathDigest = sha256Digest(resource.path);
    const origin = `${resource.scheme}://${resource.host}${
      (resource.scheme === 'https' && resource.port === 443)
      || (resource.scheme === 'http' && resource.port === 80)
        ? ''
        : `:${resource.port}`
    }`;
    const { requestNode, requestObservation } = addHttpRequestEvidence({
      accumulator,
      scope,
      pass,
      evidenceRef,
      semanticIdentity: {
        producer: 'nosh-url',
        resourceId: resource.id,
        resourcePathDigest,
      },
      identity: {
        producer: 'nosh-url',
        resourceId: sha256Digest(resource.id),
        scheme: resource.scheme,
        host: resource.host,
        port: resource.port,
        resourcePathDigest,
      },
      properties: {
        provider: resource.provider,
        captureMode: 'userspace-uprobe',
        displayUrl: `${origin}${resource.path}`,
        method: null,
        pathTruncated: resource.pathTruncated,
        process: resource.process,
        pid: resource.pid == null ? null : String(resource.pid),
      },
      timestampNs: resource.timestampUnixNs,
    });
    if (resource.pathTruncated) {
      additionalGaps.push('at least one userspace URL observation was truncated');
    }
    const correlations = network.correlations.filter((entry) => (
      ['resource-destination', 'resource-direct-destination'].includes(entry.kind)
      && entry.resourceId === resource.id
    ));
    let resourceCorrelated = false;
    for (const relation of correlations) {
      const destination = {
        ip: relation.address,
        protocol: relation.protocol,
        port: relation.port,
      };
      const networkEntry = matchingNetworkAggregate(
        proposalAggregates,
        destination,
        resource.pass,
      );
      if (!networkEntry) continue;
      const authorityGroupId = createStableId('authority', {
        scopeDigest: scope.scopeDigest,
        requestNodeId: requestNode.id,
        destination,
      });
      correlateHttpRequestToNetwork({
        accumulator,
        scope,
        requestNode,
        requestObservation,
        evidenceRef,
        networkEntry,
        confidence: 70,
        authorityGroupId,
      });
      resourceCorrelated = true;
    }
    if (resourceCorrelated) {
      correlated += 1;
    } else {
      uncorrelated += 1;
      accumulator.add('findings', createFinding({
        semanticKey: { type: 'uncorrelated-url-resource', requestNodeId: requestNode.id },
        scopeDigest: scope.scopeDigest,
        findingType: 'coverage-degraded',
        severity: 'medium',
        blocking: false,
        message: 'A userspace URL observation has no corresponding authoritative L4 observation.',
        semanticRefs: [requestNode.id],
        evidenceRefs: [evidenceRef],
        properties: { authorityCreated: false },
        privacy: clonePrivacy(PORTABLE_SENSITIVE),
      }));
    }
  }
  const urlCoverage = network.coverage?.url;
  const observations = [...resourcesById.values()].filter((resource) => (
    resource.source === 'nosh-url'
  )).length;
  if (observations === 0 && !urlCoverage?.enabled) return;
  const limitations = [
    ...(urlCoverage?.limitations || []),
    ...additionalGaps,
    ...(uncorrelated > 0 ? ['some URL observations have no matching L4 evidence'] : []),
    'libcurl uprobes do not cover arbitrary HTTP clients or response content',
  ];
  addHttpCoverage(accumulator, scope, evidenceRef, {
    producer: 'nosh-url',
    complete: false,
    required: false,
    exchanges: observations,
    correlated,
    uncorrelated,
    gaps: limitations,
  });
}

function assuranceFor(level, requestNode, responseNode, options = {}) {
  const contentLocked = [
    'native-integrity',
    'cas-replay',
    'live-digest-gate',
  ].includes(level);
  return {
    contractVersion: 2,
    level,
    mutableContent: !contentLocked,
    evidenceBacked: true,
    requestEvidenceRefs: [requestNode.id],
    responseEvidenceRefs: responseNode ? [responseNode.id] : [],
    integrityKind: options.integrityKind || 'none',
    ...(options.contentDigest ? { contentDigest: options.contentDigest } : {}),
    ...(options.proofDigest ? { proofDigest: options.proofDigest } : {}),
  };
}

function ingestNormalizedHttpEvidence(input) {
  const {
    accumulator,
    manifest,
    scope,
    passes,
    proposalAggregates,
    evidenceRef,
  } = input;
  if (!manifest.observations?.http) return;
  const http = validateBuildHttpEvidence(manifest.observations.http);
  let correlated = 0;
  let uncorrelated = 0;
  let completeResponses = 0;
  let nativeIntegrity = 0;
  let casObjects = 0;
  const coverageGaps = [...http.gaps];
  const liveDigestCaptureEligible = http.contentAssuranceGaps.length === 0;
  for (const exchange of http.exchanges) {
    const pass = passes.get(exchange.pass);
    if (!pass) {
      throw new TypeError(`HTTP exchange ${exchange.id} references an unavailable build pass`);
    }
    const { requestNode, requestObservation } = addHttpRequestEvidence({
      accumulator,
      scope,
      pass,
      evidenceRef,
      semanticIdentity: {
        producer: http.provider,
        exchangeId: exchange.id,
        requestTargetSha256: exchange.requestTargetSha256,
        requestBodySha256: exchange.requestBodySha256 || null,
        representationHeadersSha256: exchange.representationHeadersSha256,
      },
      identity: {
        producer: http.provider,
        exchangeId: sha256Digest(exchange.id),
        scheme: exchange.scheme,
        host: exchange.host,
        port: exchange.port,
        method: exchange.method,
        requestTargetSha256: exchange.requestTargetSha256,
        representationHeadersSha256: exchange.representationHeadersSha256,
        requestBodySha256: exchange.requestBodySha256 || null,
      },
      properties: {
        provider: http.provider,
        captureMode: http.captureMode,
        displayUrl: exchange.displayUrl,
        requestBodySha256: exchange.requestBodySha256 || null,
        representationHeadersSha256: exchange.representationHeadersSha256 || null,
        l4DestinationRole: exchange.destinationRole,
        upstreamDestination: exchange.upstreamDestination || null,
      },
      timestampNs: exchange.timestampUnixNs,
    });
    const { responseNode, responseObservation } = addHttpResponseEvidence({
      accumulator,
      scope,
      requestNode,
      evidenceRef,
      exchangeId: exchange.id,
      response: exchange.response,
      integrity: exchange.integrity || null,
      cas: exchange.cas || null,
      timestampNs: exchange.timestampUnixNs,
    });
    if (exchange.response?.complete && exchange.response.contentSha256) {
      completeResponses += 1;
    }
    if (exchange.integrity) nativeIntegrity += 1;
    if (exchange.cas) casObjects += 1;
    const networkEntry = http.captureMode === 'managed'
      ? matchingNetworkAggregate(
        proposalAggregates,
        exchange.destination,
        exchange.pass,
      )
      : null;
    if (networkEntry && exchange.destinationRole === 'workload-to-proxy') {
      accumulator.add('observations', createObservation({
        semanticKey: {
          scopeDigest: scope.scopeDigest,
          requestId: requestNode.id,
          proxyEndpointId: networkEntry.objectId,
        },
        scopeDigest: scope.scopeDigest,
        observationType: 'correlatesWith',
        subjectId: requestNode.id,
        objectId: networkEntry.objectId,
        basis: 'correlated',
        confidence: 100,
        algorithm: 'bounded-http-downstream-proxy-l4-correlation-v1',
        count: '1',
        evidenceRefs: [evidenceRef, networkEntry.evidenceRef],
        properties: {
          authoritativeReachability: false,
          originLegVerified: false,
        },
        privacy: clonePrivacy(PORTABLE_SENSITIVE),
      }));
      uncorrelated += 1;
      coverageGaps.push(
        'managed HTTP origin route lacks independent proxy-leg L4 provenance',
      );
      accumulator.add('findings', createFinding({
        semanticKey: {
          type: 'proxy-origin-leg-unverified',
          requestNodeId: requestNode.id,
        },
        scopeDigest: scope.scopeDigest,
        findingType: 'coverage-degraded',
        severity: 'high',
        blocking: http.required,
        message: 'The workload-to-proxy flow is verified, but the separate proxy-to-origin flow has no independently scoped L4 evidence.',
        semanticRefs: [requestNode.id, networkEntry.objectId],
        evidenceRefs: [evidenceRef, networkEntry.evidenceRef],
        properties: { authorityCreated: false },
        privacy: clonePrivacy(PORTABLE_SENSITIVE),
      }));
      continue;
    }
    if (!networkEntry || exchange.destinationRole !== 'workload-to-origin') {
      uncorrelated += 1;
      coverageGaps.push('at least one HTTP exchange has no matching L4 evidence');
      accumulator.add('findings', createFinding({
        semanticKey: { type: 'uncorrelated-http-exchange', requestNodeId: requestNode.id },
        scopeDigest: scope.scopeDigest,
        findingType: 'coverage-degraded',
        severity: 'high',
        blocking: http.required,
        message: http.captureMode === 'manual-import'
          ? 'A manually imported HTTP exchange is review-only and cannot create authority.'
          : 'An HTTP exchange has no corresponding authoritative L4 observation.',
        semanticRefs: [requestNode.id],
        evidenceRefs: [evidenceRef],
        properties: { authorityCreated: false },
        privacy: clonePrivacy(PORTABLE_SENSITIVE),
      }));
      continue;
    }
    if (exchange.response && exchange.response.status < 200) {
      correlated += 1;
      coverageGaps.push('an interim or upgraded HTTP exchange cannot create authority');
      accumulator.add('findings', createFinding({
        semanticKey: {
          type: 'http-upgrade-unbound',
          requestNodeId: requestNode.id,
        },
        scopeDigest: scope.scopeDigest,
        findingType: 'coverage-degraded',
        severity: 'high',
        blocking: true,
        message: 'An interim or upgraded HTTP exchange is outside the bounded HTTP request/response policy model.',
        semanticRefs: [requestNode.id, networkEntry.objectId],
        evidenceRefs: [evidenceRef, networkEntry.evidenceRef],
        properties: { authorityCreated: false },
        privacy: clonePrivacy(PORTABLE_SENSITIVE),
      }));
      continue;
    }
    correlated += 1;
    const authorityGroupId = createStableId('authority', {
      scopeDigest: scope.scopeDigest,
      requestNodeId: requestNode.id,
      destination: exchange.destination,
      destinationRole: exchange.destinationRole,
    });
    const correlation = correlateHttpRequestToNetwork({
      accumulator,
      scope,
      requestNode,
      requestObservation,
      evidenceRef,
      networkEntry,
      confidence: 100,
      authorityGroupId,
    });
    const observationRefs = [
      requestObservation.id,
      correlation.id,
      ...(responseObservation ? [responseObservation.id] : []),
    ].sort();
    const common = {
      authorityGroupId,
      requestNode,
      responseNode,
      evidenceRefs: [...new Set([evidenceRef, networkEntry.evidenceRef])].sort(),
      observationRefs,
      http: {
        contractVersion: 2,
        method: exchange.method,
        scheme: exchange.scheme,
        host: exchange.host,
        port: exchange.port,
        requestTargetSha256: exchange.requestTargetSha256,
        ...(exchange.requestBodySha256
          ? { requestBodySha256: exchange.requestBodySha256 }
          : {}),
        representationHeadersSha256: exchange.representationHeadersSha256,
      },
    };
    const variants = [{
      level: 'url-restricted',
      assurance: assuranceFor('url-restricted', requestNode, null),
      intentHttp: common.http,
      rationale: 'Observed exact HTTP method and request target; response bytes remain mutable.',
    }];
    if (
      liveDigestCaptureEligible
      && exchange.method !== 'HEAD'
      && exchange.response?.complete
      && exchange.response.contentSha256
      && exchange.response.status >= 200
      && exchange.response.status !== 206
      && exchange.response.status !== 304
    ) {
      variants.push({
        level: 'live-digest-gate',
        assurance: assuranceFor('live-digest-gate', requestNode, responseNode, {
          integrityKind: 'live-response-digest',
          contentDigest: exchange.response.contentSha256,
          proofDigest: exchange.response.contentSha256,
        }),
        intentHttp: {
          ...common.http,
          response: {
            kind: 'live-digest',
            contentSha256: exchange.response.contentSha256,
            ...(exchange.response.decodedContentSha256 ? {
              decodedContentSha256: exchange.response.decodedContentSha256,
            } : {}),
            ...(exchange.response.redirectLocationSha256 ? {
              redirectLocationSha256: exchange.response.redirectLocationSha256,
            } : {}),
            status: exchange.response.status,
            ...(exchange.response.length ? { length: exchange.response.length } : {}),
          },
        },
        rationale: 'Observed complete response bytes can be fully buffered and digest-gated before release.',
      });
    }
    if (exchange.integrity) {
      variants.push({
        level: 'native-integrity',
        assurance: assuranceFor('native-integrity', requestNode, responseNode, {
          integrityKind: exchange.integrity.kind,
          contentDigest: exchange.integrity.contentSha256,
          proofDigest: exchange.integrity.verificationEvidenceSha256,
        }),
        intentHttp: {
          ...common.http,
          response: {
            kind: 'native-integrity',
            contentSha256: exchange.integrity.contentSha256,
            ...(exchange.response.redirectLocationSha256 ? {
              redirectLocationSha256: exchange.response.redirectLocationSha256,
            } : {}),
            status: exchange.response.status,
          },
        },
        rationale: 'Observed response identity is backed by a frozen native integrity verification.',
      });
    }
    if (exchange.cas) {
      variants.push({
        level: 'cas-replay',
        assurance: assuranceFor('cas-replay', requestNode, responseNode, {
          integrityKind: 'cas-object',
          contentDigest: exchange.cas.objectSha256,
          proofDigest: exchange.cas.manifestSha256,
        }),
        intentHttp: {
          ...common.http,
          response: {
            kind: 'cas',
            contentSha256: exchange.cas.objectSha256,
            ...(exchange.response.redirectLocationSha256 ? {
              redirectLocationSha256: exchange.response.redirectLocationSha256,
            } : {}),
            status: exchange.response.status,
          },
        },
        rationale: 'Observed response bytes are present in an immutable content-addressed store.',
      });
    }
    proposalAggregates.http.push({ ...common, variants });
  }
  const gaps = [...new Set(coverageGaps)].sort();
  addHttpCoverage(accumulator, scope, evidenceRef, {
    producer: http.provider,
    complete: http.complete && uncorrelated === 0,
    required: http.required,
    exchanges: http.exchanges.length,
    correlated,
    uncorrelated,
    gaps: gaps.length > 0
      ? gaps
      : (uncorrelated > 0 ? ['some HTTP exchanges have no matching L4 evidence'] : []),
  });
  addArtifactIntegrityCoverage(accumulator, scope, evidenceRef, {
    exchanges: http.exchanges.length,
    completeResponses,
    nativeIntegrity,
    casObjects,
    gaps: http.contentAssuranceGaps,
  });
}

async function ingestFile(input) {
  const {
    accumulator,
    directory,
    source,
    sourceNode,
    scope,
    passes,
    proposalAggregates,
  } = input;
  let currentPass = null;
  const totals = new Map();
  await readBuildSourceNdjson(directory, source, {
    onRecord(record) {
      if (record.recordKind === 'pass_boundary') {
        currentPass = record.pass;
        return;
      }
      const recordKind = record.eventKind || record.recordKind;
      if (!['file-operation', 'file-summary', 'file-access'].includes(recordKind)) return;
      const selectedPath = record.path || record.file?.path;
      if (typeof selectedPath !== 'string' || !selectedPath) return;
      const passName = recordPass(record, currentPass, [...passes.keys()]);
      const pass = passes.get(passName);
      if (!pass) return;
      const operations = recordKind === 'file-summary'
        ? Object.entries(record.accessCounts || {})
        : [[record.operation || record.file?.operation, record.count || '1']];
      for (const [operation, count] of operations) {
        if (!operation || decimal(count) === '0') continue;
        const key = JSON.stringify({ passName, path: selectedPath, operation });
        const total = totals.get(key) || {
          pass,
          passName,
          path: selectedPath,
          operation: String(operation),
          count: '0',
          first: null,
          last: null,
        };
        total.count = addDecimal(total.count, count);
        const first = timestampFromNanoseconds(record.firstObservedNs || record.timestampNs);
        const last = timestampFromNanoseconds(record.lastObservedNs || record.timestampNs);
        if (first) total.first = total.first && total.first < first ? total.first : first;
        if (last) total.last = total.last && total.last > last ? total.last : last;
        totals.set(key, total);
      }
    },
  });
  for (const total of totals.values()) {
    const fileNode = accumulator.add('nodes', createGraphNode({
      semanticKey: { path: total.path },
      scopeDigest: scope.scopeDigest,
      nodeType: 'file',
      label: boundedLabel(total.path),
      identity: { path: total.path },
      properties: {},
      evidenceRefs: [sourceNode.id],
      privacy: clonePrivacy(PRIVATE),
    }));
    accumulator.add('observations', createObservation({
      scopeDigest: scope.scopeDigest,
      observationType: 'accesses',
      subjectId: total.pass.id,
      objectId: fileNode.id,
      basis: 'observed',
      confidence: 100,
      count: total.count,
      evidenceRefs: [sourceNode.id],
      properties: {
        operation: total.operation,
        attributionScope: 'build-pass-cgroup',
      },
      ...(total.first ? {
        firstObservedAt: total.first,
        lastObservedAt: total.last,
      } : {}),
      privacy: clonePrivacy(PRIVATE),
    }));
    const portablePath = /^[\x20-\x7e]+$/.test(total.path);
    if (total.path.startsWith('/') && portablePath) {
      proposalAggregates.file.set(`${total.path}:${total.operation}`, {
        peer: { kind: 'path', value: total.path },
        operation: total.operation,
        evidenceRef: sourceNode.id,
        objectId: fileNode.id,
      });
    } else {
      const encodingLoss = total.path.startsWith('/') && !portablePath;
      accumulator.add('findings', createFinding({
        semanticKey: {
          type: encodingLoss ? 'lossy-file-path-encoding' : 'relative-file-path',
          path: total.path,
        },
        scopeDigest: scope.scopeDigest,
        findingType: 'unresolved-evidence',
        severity: encodingLoss ? 'high' : 'medium',
        blocking: encodingLoss,
        message: encodingLoss
          ? 'A file path contains bytes that policy v1 cannot represent losslessly.'
          : 'A file operation was captured without an absolute resolved path.',
        semanticRefs: [fileNode.id],
        evidenceRefs: [sourceNode.id],
        properties: { path: total.path },
        privacy: clonePrivacy(PRIVATE),
      }));
    }
  }
}

function proposals(accumulator, scope, proposalAggregates) {
  for (const entry of proposalAggregates.network.values()) {
    const isIpv4 = entry.tuple.family === 'ipv4'
      && net.isIP(entry.tuple.address) === 4;
    if (!isIpv4) {
      accumulator.add('findings', createFinding({
        semanticKey: { type: 'unsupported-ipv6', tuple: entry.tuple },
        scopeDigest: scope.scopeDigest,
        findingType: 'unsupported-target',
        severity: 'high',
        blocking: true,
        message: 'Observed IPv6 behavior is reviewable but cannot be deployed by policy v1.',
        semanticRefs: [entry.objectId],
        evidenceRefs: [entry.evidenceRef],
        properties: {
          family: entry.tuple.family,
          targetApplicability: {
            kind: 'build-network-ipv6-v1',
            scopeClass: 'build',
            targets: buildTargetFeasibility('network', 'ipv6-cidr')
              .map(({ target, status }) => ({ target, status })),
          },
        },
        privacy: clonePrivacy(PORTABLE_SENSITIVE),
      }));
      continue;
    }
    if (
      ['tcp', 'udp'].includes(entry.tuple.protocol)
      && entry.tuple.port == null
    ) {
      accumulator.add('findings', createFinding({
        semanticKey: { type: 'missing-l4-port', tuple: entry.tuple },
        scopeDigest: scope.scopeDigest,
        findingType: 'unsupported-target',
        severity: 'high',
        blocking: true,
        message: 'Observed TCP/UDP traffic has no deployable destination port.',
        semanticRefs: [entry.objectId],
        evidenceRefs: [entry.evidenceRef],
        properties: { protocol: entry.tuple.protocol },
        privacy: clonePrivacy(PORTABLE_SENSITIVE),
      }));
      continue;
    }
    const peer = {
      kind: 'ipv4-cidr',
      value: `${entry.tuple.address}/32`,
    };
    const networkIntent = {
      domain: 'network',
      subjectId: scope.subjectId,
      effect: 'allow',
      direction: 'egress',
      peer,
      transport: {
        protocol: entry.tuple.protocol === 'icmpv6' ? 'icmp' : entry.tuple.protocol,
        ports: entry.tuple.port == null ? [] : [entry.tuple.port],
        ...(entry.tuple.icmpType == null ? {} : { icmpType: entry.tuple.icmpType }),
        ...(entry.tuple.icmpCode == null ? {} : { icmpCode: entry.tuple.icmpCode }),
      },
    };
    if (entry.authorityGroups.size === 0) {
      accumulator.add('proposals', createPolicyProposal({
        scopeDigest: scope.scopeDigest,
        scopeClass: 'build',
        proposalType: 'observed-network-egress',
        intent: networkIntent,
        baselineState: 'new',
        rationale: 'Observed build-cgroup egress attempt; completion is not proven.',
        evidenceRefs: [entry.evidenceRef],
        observationRefs: [...entry.observationRefs],
        targetFeasibility: buildTargetFeasibility(
          'network',
          'ipv4-cidr',
          { protocol: entry.tuple.protocol, port: entry.tuple.port },
        ),
        privacy: clonePrivacy(PORTABLE_SENSITIVE),
      }));
    } else {
      for (const group of entry.authorityGroups.values()) {
        accumulator.add('proposals', createPolicyProposal({
          scopeDigest: scope.scopeDigest,
          scopeClass: 'build',
          proposalType: 'observed-network-egress-endpoint-only',
          intent: networkIntent,
          authorityGroupId: group.authorityGroupId,
          assurance: assuranceFor('endpoint-only', group.requestNode, null),
          baselineState: 'new',
          rationale: 'Observed L4 endpoint correlated with a resource request; resource and response bytes remain mutable.',
          evidenceRefs: group.evidenceRefs,
          observationRefs: group.observationRefs,
          targetFeasibility: buildTargetFeasibility(
            'network',
            'ipv4-cidr',
            { protocol: entry.tuple.protocol, port: entry.tuple.port },
          ),
          privacy: clonePrivacy(PORTABLE_SENSITIVE),
        }));
      }
    }
  }
  for (const entry of proposalAggregates.http) {
    for (const variant of entry.variants) {
      accumulator.add('proposals', createPolicyProposal({
        scopeDigest: scope.scopeDigest,
        scopeClass: 'build',
        proposalType: `observed-http-${variant.level}`,
        intent: {
          domain: 'http',
          subjectId: scope.subjectId,
          effect: 'allow',
          direction: 'egress',
          peer: { kind: 'http-resource', value: entry.requestNode.id },
          http: variant.intentHttp,
        },
        authorityGroupId: entry.authorityGroupId,
        assurance: variant.assurance,
        baselineState: 'new',
        rationale: variant.rationale,
        evidenceRefs: entry.evidenceRefs,
        observationRefs: entry.observationRefs,
        targetFeasibility: buildTargetFeasibility('http', 'http-resource'),
        privacy: clonePrivacy(PORTABLE_SENSITIVE),
      }));
    }
  }
  for (const entry of proposalAggregates.process.values()) {
    accumulator.add('proposals', createPolicyProposal({
      scopeDigest: scope.scopeDigest,
      scopeClass: 'build',
      proposalType: 'observed-process-exec',
      intent: {
        domain: 'process',
        subjectId: scope.subjectId,
        effect: 'monitor',
        peer: entry.peer,
        operation: 'execute',
      },
      baselineState: 'new',
      rationale: 'Observed executable metadata; build v1 has no process enforcement backend.',
      evidenceRefs: [entry.evidenceRef],
      targetFeasibility: buildTargetFeasibility('process'),
      privacy: clonePrivacy(PRIVATE),
    }));
  }
  for (const entry of proposalAggregates.syscall.values()) {
    accumulator.add('proposals', createPolicyProposal({
      scopeDigest: scope.scopeDigest,
      scopeClass: 'build',
      proposalType: 'observed-syscall',
      intent: {
        domain: 'syscall',
        subjectId: scope.subjectId,
        effect: 'monitor',
        peer: entry.peer,
        operation: 'invoke',
      },
      baselineState: 'new',
      rationale: 'Observed cgroup-wide syscall number without a trusted audit architecture.',
      evidenceRefs: [entry.evidenceRef],
      targetFeasibility: buildTargetFeasibility('syscall'),
      privacy: clonePrivacy(PORTABLE),
    }));
  }
  for (const entry of proposalAggregates.file.values()) {
    accumulator.add('proposals', createPolicyProposal({
      scopeDigest: scope.scopeDigest,
      scopeClass: 'build',
      proposalType: 'observed-file-operation',
      intent: {
        domain: 'filesystem',
        subjectId: scope.subjectId,
        effect: 'monitor',
        peer: entry.peer,
        operation: entry.operation,
      },
      baselineState: 'new',
      rationale: 'Observed metadata-only file operation; build v1 treats it as a release-review preview.',
      evidenceRefs: [entry.evidenceRef],
      targetFeasibility: buildTargetFeasibility('filesystem'),
      privacy: clonePrivacy(PRIVATE),
    }));
  }
}

function proposalComparisonKey(proposal) {
  return sha256Digest({
    scopeClass: proposal.scopeClass,
    proposalType: proposal.proposalType,
    authorityGroupId: proposal.authorityGroupId || null,
    assurance: proposal.assurance || null,
    intent: {
      ...proposal.intent,
      subjectId: 'current-scope-subject',
    },
  });
}

function applyBaseline(accumulator, records, baseline, scope, evidenceRef) {
  if (!baseline) return;
  const baselineById = new Map((baseline.proposals || []).map((entry) => [entry.id, entry]));
  const baselineByMeaning = new Map(
    (baseline.proposals || []).map((entry) => [proposalComparisonKey(entry), entry]),
  );
  const currentById = new Map(records.proposals.map((entry) => [entry.id, entry]));
  const matchedBaselineIds = new Set();
  for (const proposal of records.proposals) {
    const before = baselineById.get(proposal.id)
      || baselineByMeaning.get(proposalComparisonKey(proposal));
    if (before) matchedBaselineIds.add(before.id);
    const afterDigest = sha256Digest(proposal.intent);
    const beforeDigest = before ? sha256Digest(before.intent) : null;
    accumulator.replace('proposals', createPolicyProposal({
      ...proposal,
      baselineState: before
        ? (beforeDigest === afterDigest ? 'unchanged' : 'broadened')
        : 'new',
    }));
    accumulator.add('diff', createGraphDiff({
      scopeDigest: proposal.scopeDigest,
      entityId: proposal.id,
      changeType: before ? (beforeDigest === afterDigest ? 'unchanged' : 'broadened') : 'added',
      beforeDigest,
      afterDigest,
      policyRelevant: !before || beforeDigest !== afterDigest,
      summary: before
        ? (beforeDigest === afterDigest ? 'Observed policy proposal is unchanged.' : 'Observed policy proposal changed.')
        : 'Observed policy proposal is new.',
      evidenceRefs: proposal.evidenceRefs,
      privacy: clonePrivacy(proposal.privacy),
    }));
  }
  for (const proposal of baseline.proposals || []) {
    if (currentById.has(proposal.id) || matchedBaselineIds.has(proposal.id)) continue;
    accumulator.add('diff', createGraphDiff({
      scopeDigest: scope.scopeDigest,
      entityId: proposal.id,
      changeType: 'removed',
      beforeDigest: sha256Digest(proposal.intent),
      afterDigest: null,
      policyRelevant: false,
      summary: 'Previously observed policy proposal was not observed in this run.',
      evidenceRefs: [evidenceRef],
      privacy: clonePrivacy(proposal.privacy),
    }));
  }
  if (baseline.scope?.scopeDigest && baseline.scope.scopeDigest !== scope.scopeDigest) {
    accumulator.add('findings', createFinding({
      semanticKey: {
        type: 'provenance-change',
        beforeScope: baseline.scope.scopeDigest,
        afterScope: scope.scopeDigest,
      },
      scopeDigest: scope.scopeDigest,
      findingType: 'provenance-change',
      severity: 'high',
      blocking: false,
      message: 'The build review scope changed from the selected baseline.',
      semanticRefs: [],
      evidenceRefs: [evidenceRef],
      properties: {
        beforeScopeDigest: baseline.scope.scopeDigest,
        afterScopeDigest: scope.scopeDigest,
      },
      privacy: clonePrivacy(PORTABLE),
    }));
  }
}

export async function createBuildReviewGraph(profilePath, options = {}) {
  const verified = await resolveVerifiedBuildProfile(profilePath);
  const { directory, manifest, manifestHash } = verified;
  const scope = createBuildScope(manifest, options.runtimeBinding || null);
  const accumulator = graphAccumulator();
  const structural = structuralGraph(
    accumulator,
    manifest,
    manifestHash,
    scope,
  );
  const sourceNodes = sourceGraph(
    accumulator,
    manifest,
    scope,
    structural.manifestSource,
  );
  manifest.incompleteReasons.forEach((reason, index) => createBuildFinding(
    accumulator,
    scope,
    manifest.runId,
    structural.manifestSource.id,
    reason,
    index,
  ));
  (manifest.limitations || []).forEach((message, index) => {
    accumulator.add('findings', createFinding({
      semanticKey: { runId: manifest.runId, limitation: message, index },
      scopeDigest: scope.scopeDigest,
      findingType: 'coverage-degraded',
      severity: 'medium',
      blocking: false,
      message: boundedLabel(message),
      semanticRefs: [],
      evidenceRefs: [structural.manifestSource.id],
      properties: { declaredLimitation: true },
      privacy: clonePrivacy(PORTABLE),
    }));
  });
  const proposalAggregates = {
    network: new Map(),
    http: [],
    process: new Map(),
    syscall: new Map(),
    file: new Map(),
  };
  for (const source of manifest.sources.filter((entry) => entry.present && entry.file)) {
    const common = {
      accumulator,
      directory,
      source,
      sourceNode: sourceNodes.get(source.name),
      scope,
      runId: manifest.runId,
      passes: structural.passes,
      proposalAggregates,
    };
    if (source.name === 'buildkit-progress') await ingestBuildkit(common);
    if (source.name === 'ebpf-process' || source.name === 'dns') {
      await ingestProcessAndDns(common);
    }
    if (source.name === 'ebpf-syscall') await ingestSyscalls(common);
    if (source.name === 'ebpf-network') await ingestNetwork(common);
    if (source.name === 'ebpf-file') await ingestFile(common);
  }
  const httpCommon = {
    accumulator,
    manifest,
    scope,
    passes: structural.passes,
    proposalAggregates,
    evidenceRef: structural.manifestSource.id,
  };
  ingestObservedUrlResources(httpCommon);
  ingestNormalizedHttpEvidence(httpCommon);
  proposals(accumulator, scope, proposalAggregates);
  let records = accumulator.result();
  applyBaseline(
    accumulator,
    records,
    options.baseline || null,
    scope,
    structural.manifestSource.id,
  );
  records = accumulator.result();
  return {
    scope,
    sources: manifest.sources.map((source) => {
      const gaps = sourceGaps(source).sort();
      return {
        id: sourceNodes.get(source.name).id,
        sourceType: 'nosh.build.evidence',
        artifactKind: manifest.kind,
        artifactDigest: manifestHash,
        runId: manifest.runId,
        sourceName: source.name,
        ...(source.hash ? { sourceDigest: source.hash } : {}),
        coverage: {
          status: gaps.length
            ? (source.present ? 'incomplete' : 'unavailable')
            : 'complete',
          lostEvents: String(source.lostEvents),
          parseErrors: String(source.parseErrors),
          gaps,
        },
        observedFrom: manifest.startedAt,
        observedTo: manifest.endedAt,
      };
    }),
    ...records,
    frozen: true,
    profile: {
      directory,
      runId: manifest.runId,
      manifestDigest: manifestHash,
      complete: manifest.complete,
      candidateEligible: manifest.candidateEligible,
    },
  };
}
