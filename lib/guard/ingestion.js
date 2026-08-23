import crypto from 'node:crypto';
import fs from 'node:fs/promises';
import { constants as fsConstants } from 'node:fs';
import net from 'node:net';
import path from 'node:path';

import { evaluateAuditEvaluation } from './audit-evaluation.js';
import { parseEvidenceInput } from './evidence.js';
import {
  canonicalize,
  compareCanonical,
  isPlainObject,
  sha256,
  sortedUniqueStrings,
  stableStringify,
} from './stable.js';

const DEFAULT_MAX_FILE_BYTES = 64 * 1024 * 1024;
const DEFAULT_MAX_TOTAL_BYTES = 512 * 1024 * 1024;
const DEFAULT_MAX_INPUTS = 64;
const DEFAULT_MAX_SOURCES_PER_MANIFEST = 32;
const MANIFEST_KIND = 'NoshSecurityEvidenceManifest';
const REQUIRED_SOURCES = Object.freeze({
  learn: ['tetragon', 'ig_dns', 'ig_syscalls', 'nosh_l4', 'managed_dns', 'managed_gateway'],
  audit: ['tetragon', 'ig_dns', 'ig_syscalls', 'nosh_l4', 'managed_dns', 'managed_gateway'],
  'egress-learn': ['nosh_egress'],
  'egress-audit': ['nosh_egress'],
  'egress-enforce': ['nosh_egress'],
});
const SOURCE_ALIASES = Object.freeze({
  tetragon: 'tetragon',
  'tetragon-events': 'tetragon',
  ig_dns: 'ig_dns',
  'ig-dns': 'ig_dns',
  ig_syscalls: 'ig_syscalls',
  'ig-syscalls': 'ig_syscalls',
  nosh_l4: 'nosh_l4',
  'nosh-l4': 'nosh_l4',
  nosh_egress: 'nosh_egress',
  'nosh-egress': 'nosh_egress',
  managed_dns: 'managed_dns',
  'managed-dns': 'managed_dns',
  managed_gateway: 'managed_gateway',
  'managed-gateway': 'managed_gateway',
});
const LIVE_SOURCE_NAMES = new Set([
  'tetragon-events',
  'tetragon-enforce-policy',
  'ig-dns',
  'ig-syscalls',
  'nosh-l4',
  'nosh-egress',
  'managed_dns',
  'managed_gateway',
]);
const TETRAGON_EVENT_FIELDS = Object.freeze([
  'process_exec',
  'process_exit',
  'process_kprobe',
  'process_lsm',
  'process_tracepoint',
]);

function rawSha256(buffer) {
  return crypto.createHash('sha256').update(buffer).digest('hex');
}

function normalizedExpectedHash(value) {
  const hash = String(value || '').trim().toLowerCase();
  return hash.startsWith('sha256:') ? hash.slice('sha256:'.length) : hash;
}

function isInside(root, target) {
  const relative = path.relative(root, target);
  return relative === '' || (!relative.startsWith('..') && !path.isAbsolute(relative));
}

async function readSafeFile(filePath, options = {}) {
  const resolved = path.resolve(filePath);
  if (options.root && !isInside(options.root, resolved)) {
    throw new Error(`evidence source escapes its manifest directory: ${filePath}`);
  }
  const lstat = await fs.lstat(resolved);
  if (lstat.isSymbolicLink()) {
    throw new Error(`refusing symbolic-link evidence input: ${filePath}`);
  }
  if (!lstat.isFile()) {
    throw new Error(`evidence input is not a regular file: ${filePath}`);
  }
  const realPath = await fs.realpath(resolved);
  if (options.root && !isInside(options.root, realPath)) {
    throw new Error(`evidence source resolves outside its manifest directory: ${filePath}`);
  }
  const maximum = options.maxFileBytes || DEFAULT_MAX_FILE_BYTES;
  if (lstat.size > maximum) {
    throw new Error(`evidence input exceeds ${maximum} bytes: ${filePath}`);
  }
  const handle = await fs.open(
    resolved,
    fsConstants.O_RDONLY | (fsConstants.O_NOFOLLOW || 0),
  );
  try {
    const stat = await handle.stat();
    if (
      !stat.isFile()
      || stat.size !== lstat.size
      || stat.dev !== lstat.dev
      || stat.ino !== lstat.ino
    ) {
      throw new Error(`evidence input changed while opening: ${filePath}`);
    }
    const buffer = await handle.readFile();
    if (buffer.length > maximum) {
      throw new Error(`evidence input exceeds ${maximum} bytes: ${filePath}`);
    }
    return { buffer, realPath, stat };
  } finally {
    await handle.close();
  }
}

function parseJsonLines(source, label) {
  return source
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter(Boolean)
    .map((line, index) => {
      try {
        return JSON.parse(line);
      } catch (error) {
        throw new Error(`invalid evidence JSON in ${label} line ${index + 1}: ${error.message}`);
      }
    });
}

function parseSource(buffer, format, label) {
  const source = buffer.toString('utf8');
  if (format === 'ndjson' || format === 'jsonl') {
    return parseJsonLines(source, label);
  }
  if (format === 'ig-seccomp-advice') {
    return parseEvidenceInput(source);
  }
  try {
    return JSON.parse(source);
  } catch (error) {
    throw new Error(`invalid evidence JSON in ${label}: ${error.message}`);
  }
}

function rawRecords(document) {
  if (Array.isArray(document)) {
    return document;
  }
  if (!isPlainObject(document)) {
    return [];
  }
  if (
    typeof document.$schema === 'string'
    && document.$schema.endsWith('raw-fixture.schema.json')
    && Array.isArray(document.expectedEvents)
  ) {
    return document.expectedEvents;
  }
  if (Array.isArray(document.events)) {
    return document.events;
  }
  if (Array.isArray(document.records)) {
    return document.records;
  }
  return [document];
}

function declaredRecordCount(document) {
  if (isPlainObject(document) && Array.isArray(document.records)) {
    return document.records.length;
  }
  return rawRecords(document).length;
}

function sourceVersion(document) {
  return isPlainObject(document) && typeof document.producerVersion === 'string'
    ? document.producerVersion
    : '';
}

function sourceIdentity(sourceName, version = '') {
  const normalized = SOURCE_ALIASES[sourceName] || sourceName;
  const identities = {
    tetragon: { kind: 'tetragon', name: 'tetragon' },
    ig_dns: { kind: 'ig', name: 'trace_dns' },
    ig_syscalls: { kind: 'ig', name: 'advise_seccomp' },
    nosh_l4: { kind: 'nosh_l4', name: 'docker-network' },
    nosh_egress: { kind: 'nosh_egress', name: 'cgroup-egress' },
    managed_dns: { kind: 'managed_dns', name: 'managed-resolver' },
    managed_gateway: { kind: 'managed_gateway', name: 'egress-gateway' },
  };
  return canonicalize({
    ...(identities[normalized] || { kind: normalized }),
    ...(version ? { version } : {}),
  });
}

function scalar(value) {
  return typeof value === 'string' || typeof value === 'number'
    ? String(value).trim()
    : '';
}

function compareRunProvenance(left, right) {
  const byRunId = scalar(left?.runId).localeCompare(scalar(right?.runId));
  return byRunId || compareCanonical(left, right);
}

function mergeContainer(recordContainer, manifestContainer) {
  const record = isPlainObject(recordContainer) ? recordContainer : {};
  const manifest = isPlainObject(manifestContainer) ? manifestContainer : {};
  const aliases = {
    id: record.id || record.containerId,
    name: record.name || record.containerName,
    image: record.image,
    imageDigest: record.imageDigest || record.digest,
  };
  for (const [field, manifestValue] of Object.entries(manifest)) {
    if (aliases[field] && manifestValue && aliases[field] !== manifestValue) {
      throw new Error(`evidence container ${field} does not match its manifest`);
    }
  }
  return canonicalize({
    ...manifest,
    ...Object.fromEntries(
      Object.entries(aliases).filter(([, value]) => scalar(value)),
    ),
  });
}

function containerIdValues(container) {
  if (!isPlainObject(container)) {
    return [];
  }
  return sortedUniqueStrings([
    scalar(container.id),
    scalar(container.containerId),
  ]);
}

function nativeTetragonContainerIds(record) {
  if (!isPlainObject(record)) {
    return {
      envelopePresent: false,
      ids: [],
    };
  }
  const ids = [];
  let envelopePresent = false;
  for (const field of TETRAGON_EVENT_FIELDS) {
    if (!Object.hasOwn(record, field)) {
      continue;
    }
    envelopePresent = true;
    const payload = record[field];
    if (!isPlainObject(payload)) {
      continue;
    }
    ids.push(
      scalar(payload.docker),
      ...containerIdValues(payload.container),
      ...containerIdValues(payload.pod?.container),
    );
    for (const process of [payload.process, payload.current]) {
      if (!isPlainObject(process)) {
        continue;
      }
      ids.push(
        scalar(process.docker),
        ...containerIdValues(process.container),
        ...containerIdValues(process.pod?.container),
      );
    }
  }
  return {
    envelopePresent,
    ids: sortedUniqueStrings(ids),
  };
}

function assertManifestTetragonContainer(record, manifestContainer, label) {
  const expectedId = scalar(manifestContainer?.id);
  if (!expectedId) {
    throw new Error(
      `${label} cannot be attributed because its manifest has no exact container id`,
    );
  }

  const native = nativeTetragonContainerIds(record);
  const canonicalPresent = isPlainObject(record?.event);
  const canonicalIds = canonicalPresent
    ? containerIdValues(record.container)
    : [];
  if (native.envelopePresent && !native.ids.length) {
    throw new Error(
      `${label} native event is missing an attributable container id`,
    );
  }
  if (canonicalPresent && !canonicalIds.length) {
    throw new Error(
      `${label} canonical event is missing an attributable container id`,
    );
  }
  if (!native.envelopePresent && !canonicalPresent) {
    throw new Error(
      `${label} is missing a native or canonical Tetragon event identity`,
    );
  }

  const observedIds = sortedUniqueStrings([...native.ids, ...canonicalIds]);
  for (const observedId of observedIds) {
    if (observedId !== expectedId) {
      throw new Error(
        `${label} container id ${observedId} does not match manifest ${expectedId}`,
      );
    }
  }
}

function canonicalRecord(record, context, source) {
  if (!isPlainObject(record) || !isPlainObject(record.event)) {
    return null;
  }
  if (record.runId && record.runId !== context.runId) {
    throw new Error(
      `evidence record runId ${record.runId} does not match manifest ${context.runId}`,
    );
  }
  const recordKind = scalar(record.source?.kind || record.source);
  if (
    recordKind
    && recordKind !== source.kind
    && !(source.kind === 'ig' && (recordKind === 'ig_dns' || recordKind === 'ig_syscalls'))
  ) {
    throw new Error(`evidence record source ${recordKind} does not match ${source.kind}`);
  }
  return canonicalize({
    schemaVersion: 1,
    source: isPlainObject(record.source) ? record.source : source,
    runId: context.runId,
    ...(record.observedAt ? { observedAt: record.observedAt } : {}),
    container: mergeContainer(record.container, context.container),
    event: record.event,
  });
}

function timestampFromNanoseconds(value) {
  if (!/^\d+$/.test(String(value || ''))) {
    return '';
  }
  try {
    const milliseconds = BigInt(value) / 1_000_000n;
    if (milliseconds > BigInt(Number.MAX_SAFE_INTEGER)) {
      return '';
    }
    return new Date(Number(milliseconds)).toISOString();
  } catch {
    return '';
  }
}

function networkRecord(source, context, event, observedAt = '') {
  return canonicalize({
    schemaVersion: 1,
    source,
    runId: context.runId,
    ...(observedAt ? { observedAt } : {}),
    container: context.container,
    event: {
      type: 'network',
      ...event,
    },
  });
}

function advisoryRecord(source, context, value, domain = 'collection') {
  return canonicalize({
    schemaVersion: 1,
    source,
    runId: context.runId,
    container: context.container,
    event: {
      type: 'recommendation',
      domain,
      action: 'record',
      value: canonicalize(value),
      generator: source.name || source.kind,
    },
  });
}

function projectIgDns(record, source, context) {
  const protocolNumber = Number(record.src?.proto || record.dst?.proto);
  const protocol = protocolNumber === 6
    ? 'tcp'
    : protocolNumber === 17
      ? 'udp'
      : 'any';
  const port = Number(record.dst?.port);
  const dnsName = scalar(record.name || record.qname).replace(/\.$/, '').toLowerCase();
  const address = scalar(record.dst?.addr || record.destinationAddress);
  if (!dnsName && !address) {
    return [advisoryRecord(source, context, record, 'dns')];
  }
  return [networkRecord(source, context, {
    direction: 'egress',
    protocol,
    ...(address ? { address } : {}),
    ...(dnsName ? { dnsName } : {}),
    ...(Number.isInteger(port) && port > 0 && port <= 65535 ? { port } : {}),
  }, scalar(record.timestamp || record.observedAt))];
}

function projectNoshL4(record, source, context) {
  const network = record.network || {};
  const protocol = scalar(network.protocol || record.protocol).toLowerCase();
  const port = Number(network.destinationPort || record.destinationPort);
  const address = scalar(network.destinationAddress || record.destinationAddress);
  if (!['tcp', 'udp', 'icmp'].includes(protocol) || !address) {
    return [advisoryRecord(source, context, record, 'l4')];
  }
  return [networkRecord(source, context, {
    direction: scalar(network.direction || record.direction || 'egress').toLowerCase(),
    protocol,
    address,
    ...(Number.isInteger(port) && port > 0 && port <= 65535 ? { port } : {}),
  }, scalar(record.observedAt) || timestampFromNanoseconds(record.timestampNs))];
}

function ebpfProtocol(value) {
  return ({
    1: 'icmp',
    6: 'tcp',
    17: 'udp',
    58: 'icmpv6',
  })[Number(value)] || '';
}

function monotonicCounter(value) {
  if (!/^\d+$/.test(String(value || ''))) return null;
  try {
    return BigInt(value);
  } catch {
    return null;
  }
}

function relativeMonotonicTimestamp(value, baseline, startedAt) {
  if (value == null || baseline == null || value < baseline) return '';
  const started = Date.parse(startedAt || '');
  const milliseconds = (value - baseline) / 1_000_000n;
  if (
    !Number.isFinite(started)
    || milliseconds > BigInt(Number.MAX_SAFE_INTEGER)
  ) {
    return '';
  }
  const timestamp = started + Number(milliseconds);
  return Number.isFinite(timestamp) ? new Date(timestamp).toISOString() : '';
}

function projectedDecision(record) {
  return canonicalize({
    schemaVersion: Number(record.schemaVersion),
    recordKind: 'decision',
    verdict: scalar(record.verdict).toLowerCase(),
    decisionClass: scalar(record.decisionClass).toLowerCase(),
    reason: scalar(record.reason).toLowerCase(),
    reasonCode: Number(record.reasonCode),
    hook: Number(record.hook),
    ruleId: Number(record.ruleId),
    family: Number(record.family),
    protocol: Number(record.protocol),
    sourceAddress: scalar(record.sourceAddress),
    destinationAddress: scalar(record.destinationAddress),
    sourcePort: Number(record.sourcePort),
    destinationPort: Number(record.destinationPort),
    packetBytes: Number(record.packetBytes),
    transactionId: Number(record.transactionId),
    domain: scalar(record.domain).replace(/\.$/, '').toLowerCase(),
    enforcementApplied: record.enforcementApplied === true,
    containmentId: scalar(record.containmentId),
    timestampMonotonicNs: scalar(record.timestampMonotonicNs),
    cgroupId: scalar(record.cgroupId),
    policyGeneration: scalar(record.policyGeneration),
    expiresMonotonicNs: scalar(record.expiresMonotonicNs),
  });
}

function projectNoshEgressRecords(records, source, context) {
  const decisions = records.filter((record) => record?.recordKind === 'decision');
  const dnsAnswers = records.filter((record) => record?.recordKind === 'dns-answer');
  const monotonicValues = decisions
    .map((record) => monotonicCounter(record.timestampMonotonicNs))
    .filter((value) => value != null);
  const baseline = monotonicValues.length
    ? monotonicValues.reduce((left, right) => left < right ? left : right)
    : null;
  const grantsByAddress = new Map();
  for (const record of dnsAnswers) {
    const address = scalar(record.answerAddress);
    const dnsName = scalar(record.domain).replace(/\.$/, '').toLowerCase();
    const observed = monotonicCounter(record.timestampMonotonicNs);
    const expires = monotonicCounter(record.expiresMonotonicNs);
    if (
      !net.isIP(address)
      || !dnsName
      || observed == null
      || expires == null
      || expires <= observed
      || !['A', 'AAAA'].includes(scalar(record.dnsRecordType).toUpperCase())
    ) {
      continue;
    }
    const grants = grantsByAddress.get(address) || [];
    grants.push({
      schemaVersion: Number(record.schemaVersion),
      recordKind: 'dns-answer',
      dnsName,
      address,
      observed,
      expires,
      protocol: 0,
      port: 0,
      transactionId: Number(record.transactionId),
      dnsRecordType: scalar(record.dnsRecordType).toUpperCase(),
      transportProtocol: Number(record.transportProtocol),
      transportFamily: Number(record.transportFamily),
      hook: Number(record.hook),
      resolverAddress: scalar(record.resolverAddress),
      resolverPort: Number(record.resolverPort),
      clientPort: Number(record.clientPort),
      decisionClass: scalar(record.decisionClass).toLowerCase(),
      reason: scalar(record.reason).toLowerCase(),
      reasonCode: Number(record.reasonCode),
      enforcementApplied: record.enforcementApplied === true,
      timestampMonotonicNs: scalar(record.timestampMonotonicNs),
      cgroupId: scalar(record.cgroupId),
      policyGeneration: scalar(record.policyGeneration),
    });
    grantsByAddress.set(address, grants);
  }
  for (const record of decisions) {
    const address = scalar(record.destinationAddress);
    const dnsName = scalar(record.domain).replace(/\.$/, '').toLowerCase();
    const observed = monotonicCounter(record.timestampMonotonicNs);
    const expires = monotonicCounter(record.expiresMonotonicNs);
    const protocol = Number(record.protocol);
    const port = Number(record.destinationPort);
    if (
      record.reasonCode !== 3
      || Number(record.hook) !== 5
      || Number(record.packetBytes) !== 0
      || !net.isIP(address)
      || !dnsName
      || observed == null
      || expires == null
      || expires <= observed
      || ![0, 6, 17].includes(protocol)
      || !Number.isInteger(port)
      || port < 0
      || port > 65535
    ) {
      continue;
    }
    const grants = grantsByAddress.get(address) || [];
    grants.push({
      dnsName,
      address,
      observed,
      expires,
      protocol,
      port,
      transactionId: Number(record.transactionId),
    });
    grantsByAddress.set(address, grants);
  }
  const projected = [];
  for (const record of decisions) {
    const hook = Number(record.hook);
    const protocol = ebpfProtocol(record.protocol);
    const address = scalar(record.destinationAddress);
    const port = Number(record.destinationPort);
    const observed = monotonicCounter(record.timestampMonotonicNs);
    const decision = projectedDecision(record);
    const nonCandidateReason = ![1, 2, 3, 4, 6].includes(hook)
      ? `hook ${hook} is evidence-only`
      : Number(record.reasonCode) === 12
        ? 'IPv6 control traffic is platform infrastructure'
        : Number(record.reasonCode) === 2
          ? 'configured resolver traffic is platform infrastructure'
          : Number(record.reasonCode) === 3 && port === 0
            ? 'synthetic DNS grant is correlation evidence'
            : !protocol
              ? 'record has no reviewable transport protocol'
              : !net.isIP(address)
                ? 'record has no reviewable destination address'
                : observed == null
                  ? 'record has no valid monotonic timestamp'
                  : ['tcp', 'udp'].includes(protocol)
                    && (!Number.isInteger(port) || port < 1 || port > 65535)
                    ? 'record has no reviewable destination port'
                    : '';
    if (nonCandidateReason) {
      projected.push(advisoryRecord(
        { ...source, name: 'decision' },
        context,
        {
          classification: 'runtime-decision-evidence',
          reason: nonCandidateReason,
          decision,
        },
        'nosh-egress',
      ));
      continue;
    }
    const dnsChain = (grantsByAddress.get(address) || [])
      .filter((grant) => (
        grant.observed <= observed
        && observed <= grant.expires
        && (grant.protocol === 0 || grant.protocol === Number(record.protocol))
        && (grant.port === 0 || grant.port === port)
      ))
      .map((grant) => canonicalize({
        dnsName: grant.dnsName,
        address: grant.address,
        protocol: ebpfProtocol(grant.protocol) || 'any',
        port: grant.port,
        transactionId: grant.transactionId,
        ...(grant.dnsRecordType ? { dnsRecordType: grant.dnsRecordType } : {}),
        ...(grant.recordKind ? {
          schemaVersion: grant.schemaVersion,
          recordKind: grant.recordKind,
          hook: grant.hook,
          transportFamily: grant.transportFamily,
          timestampMonotonicNs: grant.timestampMonotonicNs,
          cgroupId: grant.cgroupId,
          policyGeneration: grant.policyGeneration,
        } : {}),
        ...(grant.transportProtocol
          ? { transportProtocol: ebpfProtocol(grant.transportProtocol) }
          : {}),
        ...(grant.resolverAddress
          ? { resolverAddress: grant.resolverAddress }
          : {}),
        ...(grant.resolverPort ? { resolverPort: grant.resolverPort } : {}),
        ...(grant.clientPort ? { clientPort: grant.clientPort } : {}),
        ...(grant.decisionClass ? { decisionClass: grant.decisionClass } : {}),
        ...(grant.reason ? { reason: grant.reason } : {}),
        ...(Number.isInteger(grant.reasonCode)
          ? { reasonCode: grant.reasonCode }
          : {}),
        ...(grant.dnsRecordType
          ? { enforcementApplied: grant.enforcementApplied }
          : {}),
        observedMonotonicNs: grant.observed.toString(),
        expiresMonotonicNs: grant.expires.toString(),
      }))
      .sort(compareCanonical);
    const names = new Set(dnsChain.map((grant) => grant.dnsName));
    const peer = {
      address,
      ...(names.size ? { dnsNames: [...names].sort() } : {}),
      ...(dnsChain.length ? { dnsChain } : {}),
    };
    if (names.size === 1) {
      peer.dnsName = [...names][0];
    } else if (names.size > 1) {
      const sorted = [...names].sort();
      peer.unresolvedReason =
        `destination IP was shared by multiple DNS names: ${sorted.join(', ')}`;
    }
    if (
      Number(record.reasonCode) === 13
      || scalar(record.decisionClass) === 'containment-deny'
    ) {
      const containmentId = scalar(record.containmentId) || 'unnamed-platform-containment';
      peer.unresolvedReason =
        `platform containment ${containmentId} cannot be authorized by reviewed policy`;
    } else if (
      scalar(record.decisionClass) === 'coverage-gap'
      || scalar(record.decisionClass) === 'backend-deny'
    ) {
      peer.unresolvedReason =
        `${scalar(record.decisionClass)} ${scalar(record.reason)} must be resolved before policy authorization`;
    }
    projected.push(networkRecord(
      { ...source, name: 'decision' },
      context,
      {
        direction: 'egress',
        protocol,
        ...peer,
        decision,
        ...(['tcp', 'udp'].includes(protocol) ? { port } : {}),
      },
      relativeMonotonicTimestamp(observed, baseline, context.startedAt),
    ));
  }
  return projected;
}

function projectManagedDns(record, source, context) {
  const dnsName = scalar(record.name || record.qname).replace(/\.$/, '').toLowerCase();
  const answers = Array.isArray(record.answers)
    ? record.answers.map((answer) => scalar(answer?.address)).filter(Boolean)
    : [scalar(record.answer)].filter((answer) => net.isIP(answer));
  if (!answers.length) {
    return [advisoryRecord(source, context, {
      type: record.type || 'query',
      ...(dnsName ? { dnsName } : {}),
      ...(record.rcode ? { rcode: record.rcode } : {}),
    }, 'dns')];
  }
  return answers.map((address) => networkRecord(source, context, {
    direction: 'egress',
    protocol: 'any',
    address,
    ...(dnsName ? { dnsName } : {}),
  }, scalar(record.observedAt)));
}

function projectManagedGateway(record, source, context) {
  const protocol = scalar(record.protocol).toLowerCase();
  const address = scalar(record.destinationAddress || record.address);
  const port = Number(record.destinationPort || record.port);
  if (!['tcp', 'udp', 'icmp'].includes(protocol) || !address) {
    return [advisoryRecord(source, context, record, 'gateway')];
  }
  return [networkRecord(source, context, {
    direction: scalar(record.direction || 'egress').toLowerCase(),
    protocol,
    address,
    ...(scalar(record.dnsName)
      ? { dnsName: scalar(record.dnsName).replace(/\.$/, '').toLowerCase() }
      : {}),
    ...(Number.isInteger(port) && port > 0 && port <= 65535 ? { port } : {}),
  }, scalar(record.observedAt))];
}

function projectIgSyscalls(record, source, context) {
  const profile = isPlainObject(record.profile) ? record.profile : record;
  if (
    !isPlainObject(profile)
    || typeof profile.defaultAction !== 'string'
    || !Array.isArray(profile.syscalls)
  ) {
    return [advisoryRecord(source, context, record, 'seccomp')];
  }
  const syscalls = sortedUniqueStrings(
    (profile.syscalls || []).flatMap((group) => group.names || []),
  );
  return [canonicalize({
    schemaVersion: 1,
    source,
    runId: context.runId,
    container: context.container,
    event: {
      type: 'recommendation',
      domain: 'seccomp',
      action: 'allow-syscalls',
      value: syscalls,
      generator: source.version
        ? `advise_seccomp:${source.version}`
        : 'advise_seccomp',
    },
  })];
}

function projectRecord(record, sourceName, source, context) {
  const canonical = canonicalRecord(record, context, source);
  if (canonical) {
    return [canonical];
  }
  const normalizedSource = SOURCE_ALIASES[sourceName] || sourceName;
  if (normalizedSource === 'tetragon') {
    return [{
      ...record,
      source,
      runId: context.runId,
      container: mergeContainer(record.container, context.container),
      observedAt: record.observedAt || record.time || record.timestamp,
    }];
  }
  if (normalizedSource === 'ig_dns') {
    return projectIgDns(record, source, context);
  }
  if (normalizedSource === 'ig_syscalls') {
    return projectIgSyscalls(record, source, context);
  }
  if (normalizedSource === 'nosh_l4') {
    return projectNoshL4(record, source, context);
  }
  if (normalizedSource === 'managed_dns') {
    return projectManagedDns(record, source, context);
  }
  if (normalizedSource === 'managed_gateway') {
    return projectManagedGateway(record, source, context);
  }
  return [advisoryRecord(source, context, record)];
}

function containsWouldDeny(record) {
  if (!isPlainObject(record)) {
    return false;
  }
  const decisions = [
    record.decision,
    record.verdict,
    record.action,
    record.event?.decision,
    record.event?.verdict,
    record.event?.action,
    record.sensorDecision?.verdict,
    record.network?.decision,
  ].map((value) => scalar(value).toLowerCase().replace(/_/g, '-'));
  if (decisions.some((value) => ['block', 'blocked', 'deny', 'denied', 'would-deny'].includes(value))) {
    return true;
  }
  if (record.denied === true || record.wouldDeny === true || record.would_deny === true) {
    return true;
  }
  return Array.isArray(record.flags)
    && record.flags.some(
      (flag) => scalar(flag).toLowerCase().replace(/_/g, '-') === 'would-deny',
    );
}

function inferFormat(descriptor) {
  if (descriptor.format) {
    return descriptor.format;
  }
  const source = SOURCE_ALIASES[descriptor.name] || descriptor.name;
  if (source === 'ig_syscalls') {
    return 'ig-seccomp-advice';
  }
  const extension = path.extname(descriptor.path || '').toLowerCase();
  return extension === '.json' ? 'json' : 'ndjson';
}

function normalizeManifest(document, manifestHash, options = {}) {
  if (!isPlainObject(document) || document.schemaVersion !== undefined && document.schemaVersion !== 1) {
    throw new Error('evidence manifest schemaVersion must be 1');
  }
  const live = document.kind === MANIFEST_KIND;
  if (live && document.apiVersion !== 'notty.dev/v1alpha1') {
    throw new Error('evidence manifest apiVersion must be notty.dev/v1alpha1');
  }
  const legacy = Array.isArray(document.inputs) && Object.hasOwn(document, 'promotionEligible');
  if (!live && !legacy) {
    throw new Error('unsupported evidence manifest document');
  }
  const runId = scalar(document.runId);
  const mode = scalar(document.mode).toLowerCase();
  if (
    !runId ||
    ![
      'learn',
      'audit',
      'enforce',
      'egress-learn',
      'egress-audit',
      'egress-enforce',
    ].includes(mode)
  ) {
    throw new Error('evidence manifest requires a runId and valid mode');
  }
  if (
    mode === 'enforce' ||
    mode === 'egress-audit' ||
    mode === 'egress-enforce'
  ) {
    throw new Error(
      `${mode}-mode evidence is diagnostic-only and cannot train or promote a replacement profile`,
    );
  }
  if (mode === 'egress-learn' && document.trainingEligible !== true) {
    throw new Error(
      'egress-learn evidence must be explicitly training eligible',
    );
  }
  const subject = isPlainObject(document.subject) ? document.subject : {};
  const container = canonicalize({
    ...(isPlainObject(document.container) ? document.container : {}),
    ...(subject.containerId ? { id: subject.containerId } : {}),
    ...(subject.containerName ? { name: subject.containerName } : {}),
    ...(subject.image ? { image: subject.image } : {}),
    ...(subject.imageDigest ? { imageDigest: subject.imageDigest } : {}),
    ...(document.imageDigest ? { imageDigest: document.imageDigest } : {}),
  });
  if (!/^sha256:[a-f0-9]{64}$/.test(container.imageDigest || '')) {
    throw new Error(`evidence manifest ${runId} requires an immutable image digest`);
  }
  const sources = live
    ? document.sources
    : document.inputs?.map((input) => ({
      name: input.source,
      path: input.path,
      format: input.format,
      required: true,
      present: true,
      complete: input.complete,
      records: input.records,
      hash: input.sha256 || null,
      lostEvents: 0,
    }));
  if (!Array.isArray(sources) || !sources.length) {
    throw new Error(`evidence manifest ${runId} has no sources`);
  }
  const maximumSources =
    options.maxSourcesPerManifest || DEFAULT_MAX_SOURCES_PER_MANIFEST;
  if (sources.length > maximumSources) {
    throw new Error(
      `evidence manifest ${runId} has more than ${maximumSources} sources`,
    );
  }
  const sourceNames = new Set();
  const sourceDescriptors = new Map();
  for (const source of sources) {
    if (!isPlainObject(source) || !scalar(source.name)) {
      throw new Error(`evidence manifest ${runId} contains an invalid source descriptor`);
    }
    if (live && !LIVE_SOURCE_NAMES.has(source.name)) {
      throw new Error(`evidence manifest ${runId} contains unknown source ${source.name}`);
    }
    const sourceName = SOURCE_ALIASES[source.name] || source.name;
    if (sourceNames.has(sourceName)) {
      throw new Error(`evidence manifest ${runId} contains duplicate source ${source.name}`);
    }
    sourceNames.add(sourceName);
    sourceDescriptors.set(sourceName, source);
  }
  const missingSources = (REQUIRED_SOURCES[mode] || []).filter(
    (name) => !sourceNames.has(name),
  );
  if (missingSources.length) {
    throw new Error(
      `evidence manifest ${runId} is missing required sources: ${missingSources.join(', ')}`,
    );
  }
  for (const sourceName of REQUIRED_SOURCES[mode] || []) {
    const source = sourceDescriptors.get(sourceName);
    if (
      live
      && (
        source.required !== true
        || source.present !== true
        || source.complete !== true
      )
    ) {
      throw new Error(
        `evidence manifest ${runId} required source ${source.name} is not complete`,
      );
    }
  }
  const gaps = legacy ? document.gaps || [] : sources
    .filter((source) => source.error || source.complete === false)
    .map((source) => `${source.name || 'unknown'}: ${source.error || 'incomplete'}`);
  const complete = live ? document.complete === true : document.promotionEligible === true;
  if (!complete) {
    throw new Error(`evidence manifest ${runId} is incomplete or not promotion eligible`);
  }
  if (gaps.length) {
    throw new Error(`evidence manifest ${runId} contains collection gaps`);
  }
  for (const source of sources) {
    const lostEvents = Number(source.lostEvents || 0);
    const parseErrors = Number(source.parseErrors || 0);
    if (!Number.isFinite(lostEvents) || lostEvents < 0 || lostEvents !== 0) {
      throw new Error(`evidence manifest ${runId} reports lost events for ${source.name}`);
    }
    if (!Number.isSafeInteger(parseErrors) || parseErrors !== 0) {
      throw new Error(`evidence manifest ${runId} reports parse errors for ${source.name}`);
    }
    if (source.complete !== true) {
      throw new Error(`evidence manifest ${runId} has incomplete source ${source.name}`);
    }
    if (source.required !== false && source.present === false) {
      throw new Error(`evidence manifest ${runId} is missing required source ${source.name}`);
    }
    if (
      live
      && (
        typeof source.required !== 'boolean'
        || typeof source.present !== 'boolean'
        || !Number.isFinite(source.lostEvents)
        || source.lostEvents < 0
        || !Number.isSafeInteger(source.parseErrors)
        || source.parseErrors < 0
        || !Number.isSafeInteger(source.bytes)
        || source.bytes < 0
        || !Number.isSafeInteger(source.records)
        || source.records < 0
        || typeof source.completionMarker !== 'string'
        || !source.completionMarker.trim()
      )
    ) {
      throw new Error(`evidence manifest ${runId} has invalid metadata for ${source.name}`);
    }
  }
  return {
    live,
    runId,
    mode,
    container,
    startedAt: document.startedAt || null,
    endedAt: document.endedAt || document.generatedAt || null,
    profileRevision: document.profileRevision || null,
    auditEvaluation:
      mode === 'audit' && isPlainObject(document.auditEvaluation)
        ? canonicalize(document.auditEvaluation)
        : null,
    manifestHash,
    sources,
  };
}

async function loadManifest(manifestPath, options, budget, preloaded = {}) {
  const manifestFile = preloaded.file || await readSafeFile(manifestPath, options);
  if (!preloaded.file) {
    budget.bytes += manifestFile.buffer.length;
    if (budget.bytes > options.maxTotalBytes) {
      throw new Error(`evidence inputs exceed ${options.maxTotalBytes} total bytes`);
    }
  }
  let document = preloaded.document;
  if (!document) {
    try {
      document = JSON.parse(manifestFile.buffer.toString('utf8'));
    } catch (error) {
      throw new Error(`invalid evidence manifest ${manifestPath}: ${error.message}`);
    }
  }
  const manifest = normalizeManifest(document, sha256(manifestFile.buffer), options);
  const root = await fs.realpath(path.dirname(manifestFile.realPath));
  const records = [];
  const inputProvenance = [];
  let integrityVerified = true;
  let wouldDenyCount = 0;
  const seenPaths = new Set();
  const sources = [...manifest.sources].sort(compareCanonical);
  for (const descriptor of sources) {
    if (descriptor.present === false && descriptor.required === false) {
      continue;
    }
    if (typeof descriptor.path !== 'string' || !descriptor.path) {
      throw new Error(
        `evidence manifest ${manifest.runId} source ${descriptor.name} has no path`,
      );
    }
    const sourcePath = path.resolve(root, descriptor.path);
    if (seenPaths.has(sourcePath)) {
      throw new Error(`evidence manifest ${manifest.runId} references a source twice`);
    }
    seenPaths.add(sourcePath);
    const sourceFile = await readSafeFile(sourcePath, { ...options, root });
    budget.bytes += sourceFile.buffer.length;
    if (budget.bytes > options.maxTotalBytes) {
      throw new Error(`evidence inputs exceed ${options.maxTotalBytes} total bytes`);
    }
    if (descriptor.bytes !== undefined && descriptor.bytes !== sourceFile.buffer.length) {
      throw new Error(
        `evidence source byte count mismatch for ${descriptor.name} in ${manifest.runId}`,
      );
    }
    const actualHash = rawSha256(sourceFile.buffer);
    const expectedHash = normalizedExpectedHash(descriptor.hash || descriptor.sha256);
    if (!/^[a-f0-9]{64}$/.test(expectedHash)) {
      throw new Error(
        `evidence source ${descriptor.name} in ${manifest.runId} has no valid SHA-256 hash`,
      );
    }
    if (expectedHash && actualHash !== expectedHash) {
      throw new Error(`evidence source hash mismatch for ${descriptor.name} in ${manifest.runId}`);
    }
    const format = inferFormat(descriptor);
    const parsed = parseSource(sourceFile.buffer, format, sourceFile.realPath);
    const sourceRecords = rawRecords(parsed);
    const recordCount = declaredRecordCount(parsed);
    if (descriptor.records !== undefined && descriptor.records !== recordCount) {
      throw new Error(
        `evidence source record count mismatch for ${descriptor.name} in ${manifest.runId}`,
      );
    }
    wouldDenyCount += sourceRecords.filter(containsWouldDeny).length;
    const version = sourceVersion(parsed);
    const source = sourceIdentity(descriptor.name, version);
    const context = {
      runId: manifest.runId,
      container: manifest.container,
      startedAt: manifest.startedAt,
    };
    const normalizedSource = SOURCE_ALIASES[descriptor.name] || descriptor.name;
    if (normalizedSource === 'nosh_egress') {
      records.push(...projectNoshEgressRecords(sourceRecords, source, context));
    }
    for (const [recordIndex, record] of sourceRecords.entries()) {
      if (normalizedSource === 'nosh_egress') {
        continue;
      }
      if ((SOURCE_ALIASES[descriptor.name] || descriptor.name) === 'tetragon') {
        assertManifestTetragonContainer(
          record,
          manifest.container,
          `evidence source ${descriptor.name} record ${recordIndex + 1} in ${manifest.runId}`,
        );
      }
      records.push(...projectRecord(record, descriptor.name, source, context));
    }
    inputProvenance.push(canonicalize({
      source: descriptor.name,
      path: path.relative(root, sourceFile.realPath),
      format,
      bytes: sourceFile.buffer.length,
      records: recordCount,
      hash: `sha256:${actualHash}`,
      complete: true,
      lostEvents: 0,
      integrityVerified: true,
    }));
  }
  const auditEvaluation =
    manifest.mode === 'audit'
      ? evaluateAuditEvaluation(manifest.auditEvaluation)
      : null;
  const evaluatedWouldDenyCount =
    manifest.mode === 'audit'
      ? Math.max(wouldDenyCount, auditEvaluation.wouldDenyCount)
      : wouldDenyCount;
  const evaluationComplete =
    manifest.mode !== 'audit' || auditEvaluation.complete;
  const cleanAudit = manifest.mode === 'audit'
    && integrityVerified
    && evaluationComplete
    && evaluatedWouldDenyCount === 0;
  return {
    records: records.sort(compareCanonical),
    run: canonicalize({
      runId: manifest.runId,
      mode: manifest.mode,
      imageDigest: manifest.container.imageDigest,
      ...(manifest.startedAt ? { startedAt: manifest.startedAt } : {}),
      ...(manifest.endedAt ? { endedAt: manifest.endedAt } : {}),
      ...(manifest.profileRevision
        ? { profileRevision: manifest.profileRevision }
        : {}),
      manifestHash: manifest.manifestHash,
      manifestVerified: integrityVerified,
      complete: true,
      // Scoped learning is valid input for the dedicated egress bundle
      // compiler, but it can never authorize promotion of a full five-
      // artifact security profile.
      promotionEligible:
        evaluationComplete && manifest.mode !== 'egress-learn',
      ...(manifest.mode === 'egress-learn'
        ? { profileScope: 'egress-only' }
        : {}),
      gaps: [],
      lostEvents: 0,
      wouldDenyCount: evaluatedWouldDenyCount,
      cleanAudit,
      ...(manifest.mode === 'audit'
        ? {
            auditEvaluation: manifest.auditEvaluation,
            auditEvaluationComplete: auditEvaluation.complete,
            auditEvaluationErrors: auditEvaluation.errors,
          }
        : {}),
      inputs: inputProvenance.sort(compareCanonical),
    }),
  };
}

function isManifestDocument(filePath, document) {
  return path.basename(filePath) === 'evidence-manifest.json'
    || document?.kind === MANIFEST_KIND
    || (
      Array.isArray(document?.inputs)
      && Object.hasOwn(document, 'promotionEligible')
    );
}

function directRunProvenance(records, inputProvenance) {
  const runs = new Map();
  for (const record of records) {
    const runId = scalar(record?.runId);
    if (!runId) {
      continue;
    }
    if (!runs.has(runId)) {
      runs.set(runId, {
        runId,
        mode: 'direct',
        manifestVerified: false,
        complete: false,
        promotionEligible: false,
        cleanAudit: false,
        gaps: ['direct evidence input has no completed run manifest'],
        lostEvents: null,
        wouldDenyCount: 0,
        inputs: inputProvenance,
      });
    }
  }
  return Array.from(runs.values()).sort(compareRunProvenance);
}

export async function loadEvidenceInputs(inputPaths, inputOptions = {}) {
  const paths = (Array.isArray(inputPaths) ? inputPaths : [inputPaths])
    .map((entry) => String(entry || '').trim())
    .filter(Boolean);
  if (!paths.length) {
    throw new TypeError('at least one evidence path is required');
  }
  const maxInputs = inputOptions.maxInputs || DEFAULT_MAX_INPUTS;
  if (paths.length > maxInputs) {
    throw new Error(`no more than ${maxInputs} evidence inputs may be compiled`);
  }
  const options = {
    maxFileBytes: inputOptions.maxFileBytes || DEFAULT_MAX_FILE_BYTES,
    maxTotalBytes: inputOptions.maxTotalBytes || DEFAULT_MAX_TOTAL_BYTES,
    maxSourcesPerManifest:
      inputOptions.maxSourcesPerManifest || DEFAULT_MAX_SOURCES_PER_MANIFEST,
  };
  const budget = { bytes: 0 };
  const resolvedPaths = [];
  for (const inputPath of paths) {
    const resolved = path.resolve(inputOptions.cwd || process.cwd(), inputPath);
    if (resolvedPaths.includes(resolved)) {
      throw new Error(`duplicate evidence input: ${inputPath}`);
    }
    resolvedPaths.push(resolved);
  }
  resolvedPaths.sort();

  const classified = [];
  for (const inputPath of resolvedPaths) {
    const file = await readSafeFile(inputPath, options);
    budget.bytes += file.buffer.length;
    if (budget.bytes > options.maxTotalBytes) {
      throw new Error(`evidence inputs exceed ${options.maxTotalBytes} total bytes`);
    }
    let document = null;
    if (path.extname(inputPath).toLowerCase() === '.json') {
      try {
        document = JSON.parse(file.buffer.toString('utf8'));
      } catch {
        // Direct invalid JSON receives the more precise parser error below.
      }
    }
    classified.push({
      inputPath,
      file,
      manifest: isManifestDocument(inputPath, document),
      document,
    });
  }
  const manifestCount = classified.filter((entry) => entry.manifest).length;
  if (manifestCount && manifestCount !== classified.length) {
    throw new Error('completed manifest inputs cannot be mixed with direct raw evidence');
  }

  const records = [];
  const runProvenance = [];
  const directInputs = [];
  if (manifestCount) {
    const seenRunIds = new Set();
    let imageDigest = '';
    for (const entry of classified) {
      const loaded = await loadManifest(entry.inputPath, options, budget, entry);
      if (seenRunIds.has(loaded.run.runId)) {
        throw new Error(`duplicate evidence runId: ${loaded.run.runId}`);
      }
      seenRunIds.add(loaded.run.runId);
      if (imageDigest && loaded.run.imageDigest !== imageDigest) {
        throw new Error('evidence manifests must describe the same immutable image digest');
      }
      imageDigest = loaded.run.imageDigest;
      records.push(...loaded.records);
      runProvenance.push(loaded.run);
    }
  } else {
    for (const entry of classified) {
      const extension = path.extname(entry.inputPath).toLowerCase();
      const format = extension === '.jsonl' || extension === '.ndjson'
        ? 'ndjson'
        : 'json';
      const parsed = parseSource(entry.file.buffer, format, entry.inputPath);
      const sourceRecords = rawRecords(parsed);
      const sourceName = scalar(parsed?.source);
      const source = sourceIdentity(sourceName || 'direct', sourceVersion(parsed));
      const context = {
        runId: scalar(sourceRecords.find((record) => record?.runId)?.runId),
        container: {},
      };
      if (sourceName && SOURCE_ALIASES[sourceName]) {
        for (const record of sourceRecords) {
          records.push(...projectRecord(record, sourceName, source, {
            ...context,
            runId: scalar(record?.runId) || context.runId || 'direct-fixture',
          }));
        }
      } else {
        records.push(...sourceRecords);
      }
      directInputs.push(canonicalize({
        path: path.basename(entry.inputPath),
        format,
        bytes: entry.file.buffer.length,
        records: declaredRecordCount(parsed),
        hash: sha256(entry.file.buffer),
        manifestVerified: false,
      }));
    }
    runProvenance.push(...directRunProvenance(records, directInputs));
  }
  return canonicalize({
    records: records.sort(compareCanonical),
    runProvenance: runProvenance.sort(compareRunProvenance),
    ingestion: {
      mode: manifestCount ? 'completed-manifests' : 'direct',
      manifestCount,
      directInputCount: manifestCount ? 0 : classified.length,
      totalBytes: budget.bytes,
      inputCount: classified.length,
      promotionInputEligible: manifestCount > 0
        && runProvenance.every((run) => run.manifestVerified && run.promotionEligible),
      inputHashes: manifestCount
        ? runProvenance.map((run) => run.manifestHash).sort()
        : directInputs.map((entry) => entry.hash).sort(),
    },
  });
}
