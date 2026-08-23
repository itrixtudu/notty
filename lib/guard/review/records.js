import net from 'node:net';

import {
  COVERAGE_DOMAINS,
  DEPLOYMENT_TARGETS,
  FINDING_TYPES,
  HTTP_ASSURANCE_LEVELS,
  HTTP_INTEGRITY_KINDS,
  NODE_TYPES,
  OBSERVATION_TYPES,
  POLICY_DOMAINS,
  POLICY_TARGET_KINDS,
  REVIEW_API_VERSION,
  REVIEW_KINDS,
  REVIEW_LIMITS,
  REVIEW_SCHEMA_VERSION,
  STREAM_ROLES,
  TARGET_PARITY,
} from './constants.js';
import { cloneCanonicalJson } from './jcs.js';
import { assertSha256, assertStableId, createStableId } from './ids.js';
import {
  assertArray,
  assertBoolean,
  assertDateTime,
  assertDecimal,
  assertEnum,
  assertJsonBounds,
  assertPlainObject,
  assertPrivacy,
  assertSafeToken,
  assertStableIdArray,
  assertStrictObject,
  assertString,
  assertUniqueStrings,
} from './validation.js';

const RECORD_KINDS_BY_ROLE = Object.freeze({
  nodes: REVIEW_KINDS.node,
  observations: REVIEW_KINDS.observation,
  coverage: REVIEW_KINDS.coverage,
  findings: REVIEW_KINDS.finding,
  proposals: REVIEW_KINDS.proposal,
  diff: REVIEW_KINDS.diff,
});

function assertRecordHeader(record, kind, path) {
  if (record.apiVersion !== REVIEW_API_VERSION) {
    throw new TypeError(`${path}.apiVersion must be ${REVIEW_API_VERSION}`);
  }
  if (record.kind !== kind) {
    throw new TypeError(`${path}.kind must be ${kind}`);
  }
  if (record.schemaVersion !== REVIEW_SCHEMA_VERSION) {
    throw new TypeError(`${path}.schemaVersion must be ${REVIEW_SCHEMA_VERSION}`);
  }
  assertStableId(record.id, `${path}.id`);
  assertSha256(record.scopeDigest, `${path}.scopeDigest`);
  assertPrivacy(record.privacy, record, `${path}.privacy`);
}

function assertRecordProperties(value, path) {
  assertPlainObject(value, path);
  assertJsonBounds(value, path);
}

function assertTimeRange(record, path) {
  if (Object.hasOwn(record, 'firstObservedAt')) {
    assertDateTime(record.firstObservedAt, `${path}.firstObservedAt`);
  }
  if (Object.hasOwn(record, 'lastObservedAt')) {
    assertDateTime(record.lastObservedAt, `${path}.lastObservedAt`);
  }
  if (
    record.firstObservedAt
    && record.lastObservedAt
    && Date.parse(record.firstObservedAt) > Date.parse(record.lastObservedAt)
  ) {
    throw new TypeError(`${path} observation time range is reversed`);
  }
}

export function validateGraphNode(record, path = '$') {
  assertStrictObject(record, {
    required: [
      'apiVersion',
      'kind',
      'schemaVersion',
      'id',
      'scopeDigest',
      'nodeType',
      'label',
      'identity',
      'properties',
      'evidenceRefs',
      'privacy',
    ],
  }, path);
  assertRecordHeader(record, REVIEW_KINDS.node, path);
  assertEnum(record.nodeType, NODE_TYPES, `${path}.nodeType`);
  assertString(record.label, `${path}.label`, {
    maxBytes: REVIEW_LIMITS.maxLabelBytes,
  });
  assertRecordProperties(record.identity, `${path}.identity`);
  if (Object.keys(record.identity).length === 0) {
    throw new TypeError(`${path}.identity must not be empty`);
  }
  assertRecordProperties(record.properties, `${path}.properties`);
  assertStableIdArray(record.evidenceRefs, `${path}.evidenceRefs`, { sorted: true });
  return record;
}

export function validateObservation(record, path = '$') {
  assertStrictObject(record, {
    required: [
      'apiVersion',
      'kind',
      'schemaVersion',
      'id',
      'scopeDigest',
      'observationType',
      'subjectId',
      'objectId',
      'basis',
      'confidence',
      'count',
      'evidenceRefs',
      'properties',
      'privacy',
    ],
    optional: ['algorithm', 'firstObservedAt', 'lastObservedAt'],
  }, path);
  assertRecordHeader(record, REVIEW_KINDS.observation, path);
  assertEnum(record.observationType, OBSERVATION_TYPES, `${path}.observationType`);
  assertStableId(record.subjectId, `${path}.subjectId`);
  assertStableId(record.objectId, `${path}.objectId`);
  assertEnum(record.basis, ['observed', 'correlated', 'inferred'], `${path}.basis`);
  if (!Number.isInteger(record.confidence) || record.confidence < 0 || record.confidence > 100) {
    throw new TypeError(`${path}.confidence must be an integer from 0 through 100`);
  }
  if (record.basis === 'observed' && record.confidence !== 100) {
    throw new TypeError(`${path}.confidence must be 100 for observed evidence`);
  }
  if (Object.hasOwn(record, 'algorithm')) {
    assertSafeToken(record.algorithm, `${path}.algorithm`);
  }
  assertDecimal(record.count, `${path}.count`);
  if (record.count === '0') {
    throw new TypeError(`${path}.count must be greater than zero`);
  }
  assertStableIdArray(record.evidenceRefs, `${path}.evidenceRefs`, { minItems: 1, sorted: true });
  assertRecordProperties(record.properties, `${path}.properties`);
  assertTimeRange(record, path);
  return record;
}

export function validateCoverageMarker(record, path = '$') {
  assertStrictObject(record, {
    required: [
      'apiVersion',
      'kind',
      'schemaVersion',
      'id',
      'scopeDigest',
      'domain',
      'status',
      'sourceIds',
      'counters',
      'gaps',
      'blocking',
      'privacy',
    ],
  }, path);
  assertRecordHeader(record, REVIEW_KINDS.coverage, path);
  assertEnum(record.domain, COVERAGE_DOMAINS, `${path}.domain`);
  assertEnum(record.status, ['complete', 'incomplete', 'unavailable', 'degraded'], `${path}.status`);
  assertStableIdArray(record.sourceIds, `${path}.sourceIds`, { sorted: true });
  assertPlainObject(record.counters, `${path}.counters`);
  const counterKeys = Object.keys(record.counters);
  if (counterKeys.length > 64) {
    throw new TypeError(`${path}.counters has too many entries`);
  }
  for (const key of counterKeys) {
    assertSafeToken(key, `${path}.counters key`);
    assertDecimal(record.counters[key], `${path}.counters.${key}`);
  }
  assertUniqueStrings(record.gaps, `${path}.gaps`, {
    maxItems: 256,
    sorted: true,
    string: { maxBytes: REVIEW_LIMITS.maxMessageBytes },
  });
  assertBoolean(record.blocking, `${path}.blocking`);
  if (record.status === 'complete' && record.gaps.length > 0) {
    throw new TypeError(`${path}.gaps must be empty when coverage is complete`);
  }
  if (record.status !== 'complete' && record.gaps.length === 0) {
    throw new TypeError(`${path}.gaps must explain incomplete coverage`);
  }
  return record;
}

export function validateFinding(record, path = '$') {
  assertStrictObject(record, {
    required: [
      'apiVersion',
      'kind',
      'schemaVersion',
      'id',
      'scopeDigest',
      'findingType',
      'severity',
      'blocking',
      'message',
      'semanticRefs',
      'evidenceRefs',
      'properties',
      'privacy',
    ],
  }, path);
  assertRecordHeader(record, REVIEW_KINDS.finding, path);
  assertEnum(record.findingType, FINDING_TYPES, `${path}.findingType`);
  assertEnum(record.severity, ['info', 'low', 'medium', 'high', 'critical'], `${path}.severity`);
  assertBoolean(record.blocking, `${path}.blocking`);
  assertString(record.message, `${path}.message`, { maxBytes: REVIEW_LIMITS.maxMessageBytes });
  assertStableIdArray(record.semanticRefs, `${path}.semanticRefs`, { sorted: true });
  assertStableIdArray(record.evidenceRefs, `${path}.evidenceRefs`, { sorted: true });
  assertRecordProperties(record.properties, `${path}.properties`);
  return record;
}

function validatePeer(peer, path) {
  assertStrictObject(peer, {
    required: ['kind'],
    optional: ['value', 'selector'],
  }, path);
  assertEnum(peer.kind, POLICY_TARGET_KINDS, `${path}.kind`);
  if (!Object.hasOwn(peer, 'value') && !Object.hasOwn(peer, 'selector')) {
    throw new TypeError(`${path} requires value or selector`);
  }
  if (Object.hasOwn(peer, 'value')) {
    assertString(peer.value, `${path}.value`, { maxBytes: 4096 });
  }
  if (Object.hasOwn(peer, 'selector')) {
    assertRecordProperties(peer.selector, `${path}.selector`);
  }
  if (peer.kind !== 'workload' && Object.hasOwn(peer, 'selector')) {
    throw new TypeError(`${path}.selector is only valid for workload peers`);
  }
  if (Object.hasOwn(peer, 'value')) {
    if (peer.kind === 'fqdn') {
      const fqdn = peer.value;
      const selected = fqdn.startsWith('*.') ? fqdn.slice(2) : fqdn;
      if (
        fqdn.length > 253
        || fqdn !== fqdn.toLowerCase()
        || (fqdn.includes('*') && !fqdn.startsWith('*.'))
        || fqdn.endsWith('.')
        || !/^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(selected)
      ) {
        throw new TypeError(`${path}.value must be an exact or leading-wildcard lowercase FQDN`);
      }
    } else if (peer.kind === 'ipv4' && net.isIP(peer.value) !== 4) {
      throw new TypeError(`${path}.value must be an IPv4 address`);
    } else if (peer.kind === 'ipv4-cidr') {
      const [address, prefix, extra] = peer.value.split('/');
      if (
        extra !== undefined
        || net.isIP(address) !== 4
        || !/^(?:0|[1-9]|[12][0-9]|3[0-2])$/.test(prefix || '')
      ) {
        throw new TypeError(`${path}.value must be an IPv4 CIDR`);
      }
    } else if (peer.kind === 'ipv6' && net.isIP(peer.value) !== 6) {
      throw new TypeError(`${path}.value must be an IPv6 address`);
    } else if (peer.kind === 'ipv6-cidr') {
      const separator = peer.value.lastIndexOf('/');
      const address = separator === -1 ? '' : peer.value.slice(0, separator);
      const prefix = separator === -1 ? '' : peer.value.slice(separator + 1);
      if (
        net.isIP(address) !== 6
        || !/^(?:0|[1-9]|[1-9][0-9]|1[01][0-9]|12[0-8])$/.test(prefix)
      ) {
        throw new TypeError(`${path}.value must be an IPv6 CIDR`);
      }
    } else if (
      ['executable', 'path'].includes(peer.kind)
      && (!peer.value.startsWith('/') || peer.value.includes('\n') || peer.value.includes('\r'))
    ) {
      throw new TypeError(`${path}.value must be a safe absolute path`);
    } else if (
      peer.kind === 'syscall'
      && !/^[A-Za-z0-9_]+$/.test(peer.value)
    ) {
      throw new TypeError(`${path}.value must be a syscall name`);
    } else if (peer.kind === 'http-resource') {
      assertStableId(peer.value, `${path}.value`);
    }
  }
}

function validateHttpResponseIdentity(response, path) {
  assertStrictObject(response, {
    required: ['kind', 'contentSha256'],
    optional: [
      'decodedContentSha256',
      'redirectLocationSha256',
      'status',
      'length',
    ],
  }, path);
  assertEnum(
    response.kind,
    ['native-integrity', 'cas', 'live-digest'],
    `${path}.kind`,
  );
  assertSha256(response.contentSha256, `${path}.contentSha256`);
  if (Object.hasOwn(response, 'decodedContentSha256')) {
    assertSha256(response.decodedContentSha256, `${path}.decodedContentSha256`);
  }
  if (Object.hasOwn(response, 'redirectLocationSha256')) {
    assertSha256(
      response.redirectLocationSha256,
      `${path}.redirectLocationSha256`,
    );
  }
  if (Object.hasOwn(response, 'status')) {
    if (!Number.isInteger(response.status) || response.status < 100 || response.status > 599) {
      throw new TypeError(`${path}.status must be an HTTP status from 100 through 599`);
    }
  }
  if (Object.hasOwn(response, 'length')) {
    assertDecimal(response.length, `${path}.length`);
  }
}

function validateHttpIntent(http, path) {
  assertStrictObject(http, {
    required: [
      'contractVersion',
      'method',
      'scheme',
      'host',
      'port',
      'requestTargetSha256',
      'representationHeadersSha256',
    ],
    optional: ['requestBodySha256', 'response'],
  }, path);
  if (http.contractVersion !== 2) {
    throw new TypeError(`${path}.contractVersion must be 2`);
  }
  assertString(http.method, `${path}.method`, {
    maxBytes: 32,
    pattern: /^[A-Z][A-Z0-9-]{0,31}$/,
  });
  if (http.method === 'CONNECT') {
    throw new TypeError(`${path}.method cannot authorize an opaque CONNECT tunnel`);
  }
  assertEnum(http.scheme, ['http', 'https'], `${path}.scheme`);
  assertString(http.host, `${path}.host`, { maxBytes: 253 });
  const bracketedIpv6 = http.host.startsWith('[') && http.host.endsWith(']');
  const ipVersion = net.isIP(http.host);
  const domainValid = ipVersion === 0
    && http.host === http.host.toLowerCase()
    && !http.host.endsWith('.')
    && http.host.split('.').every((label) => (
      /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(label)
    ));
  if (
    http.host !== http.host.toLowerCase()
    || bracketedIpv6
    || (ipVersion === 0 && !domainValid)
  ) {
    throw new TypeError(`${path}.host must be a canonical unbracketed hostname or IP literal`);
  }
  if (!Number.isInteger(http.port) || http.port < 1 || http.port > 65535) {
    throw new TypeError(`${path}.port must be an integer from 1 through 65535`);
  }
  assertSha256(http.requestTargetSha256, `${path}.requestTargetSha256`);
  if (Object.hasOwn(http, 'requestBodySha256')) {
    assertSha256(http.requestBodySha256, `${path}.requestBodySha256`);
  }
  assertSha256(
    http.representationHeadersSha256,
    `${path}.representationHeadersSha256`,
  );
  if (Object.hasOwn(http, 'response')) {
    validateHttpResponseIdentity(http.response, `${path}.response`);
  }
}

function validateTransport(transport, path) {
  assertStrictObject(transport, {
    required: ['protocol', 'ports'],
    optional: ['icmpType', 'icmpCode'],
  }, path);
  assertEnum(transport.protocol, ['tcp', 'udp', 'icmp', 'icmpv6'], `${path}.protocol`);
  assertArray(transport.ports, `${path}.ports`, { maxItems: 64 });
  const seen = new Set();
  let previousPort = null;
  for (let index = 0; index < transport.ports.length; index += 1) {
    const port = transport.ports[index];
    if (!Number.isInteger(port) || port < 1 || port > 65535) {
      throw new TypeError(`${path}.ports[${index}] must be an integer from 1 through 65535`);
    }
    if (seen.has(port)) {
      throw new TypeError(`${path}.ports contains a duplicate port`);
    }
    if (previousPort !== null && previousPort > port) {
      throw new TypeError(`${path}.ports must be sorted`);
    }
    seen.add(port);
    previousPort = port;
  }
  for (const key of ['icmpType', 'icmpCode']) {
    if (Object.hasOwn(transport, key)) {
      if (!Number.isInteger(transport[key]) || transport[key] < 0 || transport[key] > 255) {
        throw new TypeError(`${path}.${key} must be an integer from 0 through 255`);
      }
    }
  }
  if (transport.protocol === 'icmp' || transport.protocol === 'icmpv6') {
    if (transport.ports.length !== 0) {
      throw new TypeError(`${path}.ports must be empty for ICMP`);
    }
  } else if (
    Object.hasOwn(transport, 'icmpType')
    || Object.hasOwn(transport, 'icmpCode')
  ) {
      throw new TypeError(`${path} ICMP fields require an ICMP protocol`);
  }
}

export function validatePolicyIntent(intent, path = '$.intent') {
  assertStrictObject(intent, {
    required: ['domain', 'subjectId', 'effect'],
    optional: ['direction', 'peer', 'transport', 'operation', 'constraints', 'http'],
  }, path);
  assertEnum(intent.domain, POLICY_DOMAINS, `${path}.domain`);
  assertStableId(intent.subjectId, `${path}.subjectId`);
  assertEnum(intent.effect, ['allow', 'deny', 'monitor'], `${path}.effect`);
  if (Object.hasOwn(intent, 'direction')) {
    assertEnum(intent.direction, ['ingress', 'egress'], `${path}.direction`);
  }
  if (Object.hasOwn(intent, 'peer')) {
    validatePeer(intent.peer, `${path}.peer`);
  }
  if (Object.hasOwn(intent, 'transport')) {
    validateTransport(intent.transport, `${path}.transport`);
  }
  if (Object.hasOwn(intent, 'operation')) {
    assertSafeToken(intent.operation, `${path}.operation`);
  }
  if (Object.hasOwn(intent, 'constraints')) {
    assertRecordProperties(intent.constraints, `${path}.constraints`);
  }
  if (Object.hasOwn(intent, 'http')) {
    validateHttpIntent(intent.http, `${path}.http`);
  }
  if (intent.domain === 'network') {
    if (Object.hasOwn(intent, 'http')) {
      throw new TypeError(`${path}.http is only valid for HTTP policy`);
    }
    for (const key of ['direction', 'peer', 'transport']) {
      if (!Object.hasOwn(intent, key)) {
        throw new TypeError(`${path}.${key} is required for network policy`);
      }
    }
    if (![
      'fqdn',
      'ipv4',
      'ipv4-cidr',
      'ipv6',
      'ipv6-cidr',
      'workload',
    ].includes(intent.peer.kind)) {
      throw new TypeError(`${path}.peer kind is not valid for network policy`);
    }
    if (
      ['tcp', 'udp'].includes(intent.transport.protocol)
      && intent.transport.ports.length === 0
    ) {
      throw new TypeError(`${path}.transport.ports requires at least one TCP or UDP port`);
    }
  } else if (intent.domain === 'http') {
    if (intent.direction !== 'egress') {
      throw new TypeError(`${path}.direction must be egress for HTTP policy`);
    }
    if (!intent.peer || intent.peer.kind !== 'http-resource') {
      throw new TypeError(`${path}.peer must identify an http-resource`);
    }
    if (!intent.http) {
      throw new TypeError(`${path}.http is required for HTTP policy`);
    }
    if (
      Object.hasOwn(intent, 'transport')
      || Object.hasOwn(intent, 'operation')
      || Object.hasOwn(intent, 'constraints')
    ) {
      throw new TypeError(`${path} transport, operation, and generic constraints are not valid for HTTP policy`);
    }
  } else {
    if (Object.hasOwn(intent, 'http')) {
      throw new TypeError(`${path}.http is only valid for HTTP policy`);
    }
    if (Object.hasOwn(intent, 'direction') || Object.hasOwn(intent, 'transport')) {
      throw new TypeError(`${path} direction and transport are only valid for network policy`);
    }
    if (!Object.hasOwn(intent, 'peer') && !Object.hasOwn(intent, 'operation')) {
      throw new TypeError(`${path} requires a peer or operation`);
    }
    const domainPeerKinds = {
      process: ['executable', 'workload', 'container'],
      filesystem: ['path'],
      syscall: ['syscall'],
    };
    if (intent.peer && !domainPeerKinds[intent.domain].includes(intent.peer.kind)) {
      throw new TypeError(`${path}.peer kind is not valid for ${intent.domain} policy`);
    }
  }
  return intent;
}

export function validateHttpAssurance(assurance, path = '$.assurance') {
  assertStrictObject(assurance, {
    required: [
      'contractVersion',
      'level',
      'mutableContent',
      'evidenceBacked',
      'requestEvidenceRefs',
      'responseEvidenceRefs',
      'integrityKind',
    ],
    optional: ['contentDigest', 'proofDigest'],
  }, path);
  if (assurance.contractVersion !== 2) {
    throw new TypeError(`${path}.contractVersion must be 2`);
  }
  assertEnum(assurance.level, HTTP_ASSURANCE_LEVELS, `${path}.level`);
  assertBoolean(assurance.mutableContent, `${path}.mutableContent`);
  if (assurance.evidenceBacked !== true) {
    throw new TypeError(`${path}.evidenceBacked must be true`);
  }
  assertStableIdArray(assurance.requestEvidenceRefs, `${path}.requestEvidenceRefs`, {
    minItems: 1,
    sorted: true,
  });
  assertStableIdArray(assurance.responseEvidenceRefs, `${path}.responseEvidenceRefs`, {
    sorted: true,
  });
  assertEnum(assurance.integrityKind, HTTP_INTEGRITY_KINDS, `${path}.integrityKind`);
  const contentLocked = [
    'native-integrity',
    'cas-replay',
    'live-digest-gate',
  ].includes(assurance.level);
  if (contentLocked) {
    if (
      assurance.mutableContent
      || !Object.hasOwn(assurance, 'contentDigest')
      || !Object.hasOwn(assurance, 'proofDigest')
    ) {
      throw new TypeError(`${path} content-locked assurance requires content and proof digests`);
    }
    assertSha256(assurance.contentDigest, `${path}.contentDigest`);
    assertSha256(assurance.proofDigest, `${path}.proofDigest`);
    if (assurance.responseEvidenceRefs.length === 0) {
      throw new TypeError(`${path}.responseEvidenceRefs requires frozen response evidence`);
    }
    if (assurance.integrityKind === 'none') {
      throw new TypeError(`${path}.integrityKind must identify the content proof`);
    }
    const compatibleKinds = {
      'native-integrity': [
        'npm-sri',
        'apt-signed-metadata',
        'publisher-signature',
        'reviewed-digest',
      ],
      'cas-replay': ['cas-object'],
      'live-digest-gate': ['live-response-digest'],
    };
    if (!compatibleKinds[assurance.level].includes(assurance.integrityKind)) {
      throw new TypeError(`${path}.integrityKind does not match its assurance level`);
    }
  } else {
    if (
      !assurance.mutableContent
      || Object.hasOwn(assurance, 'contentDigest')
      || Object.hasOwn(assurance, 'proofDigest')
    ) {
      throw new TypeError(`${path} mutable assurance must not claim a content digest`);
    }
    if (assurance.integrityKind !== 'none') {
      throw new TypeError(`${path}.integrityKind must be none for mutable assurance`);
    }
  }
}

function validateTargetFeasibility(value, path) {
  assertArray(value, path, { maxItems: DEPLOYMENT_TARGETS.length });
  const targets = new Set();
  let previousTarget = null;
  for (let index = 0; index < value.length; index += 1) {
    const entry = value[index];
    const entryPath = `${path}[${index}]`;
    assertStrictObject(entry, {
      required: ['target', 'status', 'reasons'],
    }, entryPath);
    assertEnum(entry.target, DEPLOYMENT_TARGETS, `${entryPath}.target`);
    assertEnum(entry.status, TARGET_PARITY, `${entryPath}.status`);
    assertUniqueStrings(entry.reasons, `${entryPath}.reasons`, {
      maxItems: 64,
      sorted: true,
      string: { maxBytes: REVIEW_LIMITS.maxMessageBytes },
    });
    if (targets.has(entry.target)) {
      throw new TypeError(`${path} contains duplicate target feasibility`);
    }
    if (previousTarget !== null && previousTarget > entry.target) {
      throw new TypeError(`${path} must be sorted by target`);
    }
    targets.add(entry.target);
    previousTarget = entry.target;
  }
}

export function validatePolicyProposal(record, path = '$') {
  assertStrictObject(record, {
    required: [
      'apiVersion',
      'kind',
      'schemaVersion',
      'id',
      'scopeDigest',
      'scopeClass',
      'proposalType',
      'intent',
      'baselineState',
      'rationale',
      'evidenceRefs',
      'targetFeasibility',
      'privacy',
    ],
    optional: ['observationRefs', 'authorityGroupId', 'assurance'],
  }, path);
  assertRecordHeader(record, REVIEW_KINDS.proposal, path);
  assertEnum(record.scopeClass, ['build', 'runtime'], `${path}.scopeClass`);
  assertSafeToken(record.proposalType, `${path}.proposalType`);
  validatePolicyIntent(record.intent, `${path}.intent`);
  assertEnum(record.baselineState, ['new', 'broadened', 'unchanged', 'removed'], `${path}.baselineState`);
  assertString(record.rationale, `${path}.rationale`, { maxBytes: REVIEW_LIMITS.maxMessageBytes });
  assertStableIdArray(record.evidenceRefs, `${path}.evidenceRefs`, { minItems: 1, sorted: true });
  if (Object.hasOwn(record, 'observationRefs')) {
    assertStableIdArray(record.observationRefs, `${path}.observationRefs`, {
      minItems: 1,
      sorted: true,
    });
  }
  validateTargetFeasibility(record.targetFeasibility, `${path}.targetFeasibility`);
  const hasAuthorityGroup = Object.hasOwn(record, 'authorityGroupId');
  const hasAssurance = Object.hasOwn(record, 'assurance');
  if (hasAuthorityGroup !== hasAssurance) {
    throw new TypeError(`${path} authorityGroupId and assurance must be supplied together`);
  }
  if (hasAuthorityGroup) {
    assertStableId(record.authorityGroupId, `${path}.authorityGroupId`);
    validateHttpAssurance(record.assurance, `${path}.assurance`);
    if (
      record.assurance.level === 'endpoint-only'
      && record.intent.domain !== 'network'
    ) {
      throw new TypeError(`${path} endpoint-only assurance must retain network policy intent`);
    }
    if (
      record.assurance.level !== 'endpoint-only'
      && record.intent.domain !== 'http'
    ) {
      throw new TypeError(`${path} URL/content assurance requires HTTP policy intent`);
    }
    if (
      record.intent.domain === 'http'
      && !record.assurance.requestEvidenceRefs.includes(record.intent.peer.value)
    ) {
      throw new TypeError(`${path}.intent.peer must identify request evidence in its authority group`);
    }
    const responseDigest = record.intent.http?.response?.contentSha256;
    if (
      Object.hasOwn(record.assurance, 'contentDigest')
      && responseDigest !== record.assurance.contentDigest
    ) {
      throw new TypeError(`${path} assurance digest must match the HTTP response identity`);
    }
    const responseKinds = {
      'native-integrity': 'native-integrity',
      'cas-replay': 'cas',
      'live-digest-gate': 'live-digest',
    };
    if (
      responseKinds[record.assurance.level]
      && record.intent.http?.response?.kind !== responseKinds[record.assurance.level]
    ) {
      throw new TypeError(`${path} HTTP response identity does not match its assurance level`);
    }
  }
  return record;
}

export function validateGraphDiff(record, path = '$') {
  assertStrictObject(record, {
    required: [
      'apiVersion',
      'kind',
      'schemaVersion',
      'id',
      'scopeDigest',
      'entityId',
      'changeType',
      'beforeDigest',
      'afterDigest',
      'policyRelevant',
      'summary',
      'evidenceRefs',
      'privacy',
    ],
  }, path);
  assertRecordHeader(record, REVIEW_KINDS.diff, path);
  assertStableId(record.entityId, `${path}.entityId`);
  assertEnum(
    record.changeType,
    ['unchanged', 'added', 'broadened', 'removed', 'coverage-degraded', 'metric-only'],
    `${path}.changeType`,
  );
  for (const key of ['beforeDigest', 'afterDigest']) {
    if (record[key] !== null) {
      assertSha256(record[key], `${path}.${key}`);
    }
  }
  if (record.changeType === 'added' && record.beforeDigest !== null) {
    throw new TypeError(`${path}.beforeDigest must be null for an added entity`);
  }
  if (record.changeType === 'removed' && record.afterDigest !== null) {
    throw new TypeError(`${path}.afterDigest must be null for a removed entity`);
  }
  assertBoolean(record.policyRelevant, `${path}.policyRelevant`);
  assertString(record.summary, `${path}.summary`, { maxBytes: REVIEW_LIMITS.maxMessageBytes });
  assertStableIdArray(record.evidenceRefs, `${path}.evidenceRefs`, { sorted: true });
  return record;
}

export function validateGraphRecord(role, record, path = '$') {
  assertEnum(role, STREAM_ROLES, 'stream role');
  const validators = {
    nodes: validateGraphNode,
    observations: validateObservation,
    coverage: validateCoverageMarker,
    findings: validateFinding,
    proposals: validatePolicyProposal,
    diff: validateGraphDiff,
  };
  return validators[role](record, path);
}

function defaultPrivacy() {
  return { classification: 'portable', fields: [] };
}

function createRecord(role, input, semanticKey) {
  assertPlainObject(input, 'record input');
  const kind = RECORD_KINDS_BY_ROLE[role];
  const normalizedInput = {
    ...input,
    ...(Array.isArray(input.evidenceRefs)
      ? { evidenceRefs: [...input.evidenceRefs].sort() }
      : {}),
    ...(input.privacy
      ? {
          privacy: {
            ...input.privacy,
            fields: [...(input.privacy.fields || [])]
              .sort((left, right) => left.path.localeCompare(right.path)),
          },
        }
      : {}),
  };
  const body = {
    ...normalizedInput,
    apiVersion: REVIEW_API_VERSION,
    kind,
    schemaVersion: REVIEW_SCHEMA_VERSION,
    privacy: normalizedInput.privacy || defaultPrivacy(),
  };
  delete body.semanticKey;
  if (!body.id) {
    body.id = createStableId(
      role === 'observations' ? 'observation' : role.replace(/s$/, ''),
      semanticKey,
    );
  }
  const record = cloneCanonicalJson(body);
  validateGraphRecord(role, record);
  return Object.freeze(record);
}

export function createGraphNode(input) {
  return createRecord('nodes', input, input.semanticKey || {
    scopeDigest: input.scopeDigest,
    nodeType: input.nodeType,
    identity: input.identity,
  });
}

export function createObservation(input) {
  return createRecord('observations', input, input.semanticKey || {
    scopeDigest: input.scopeDigest,
    observationType: input.observationType,
    subjectId: input.subjectId,
    objectId: input.objectId,
    properties: input.properties,
  });
}

export function createCoverageMarker(input) {
  const normalized = {
    ...input,
    sourceIds: [...(input.sourceIds || [])].sort(),
    gaps: [...(input.gaps || [])].sort(),
  };
  return createRecord('coverage', normalized, input.semanticKey || {
    scopeDigest: input.scopeDigest,
    domain: input.domain,
    sourceIds: normalized.sourceIds,
  });
}

export function createFinding(input) {
  const normalized = {
    ...input,
    semanticRefs: [...(input.semanticRefs || [])].sort(),
  };
  return createRecord('findings', normalized, input.semanticKey || {
    scopeDigest: input.scopeDigest,
    findingType: input.findingType,
    semanticRefs: normalized.semanticRefs,
    message: input.message,
  });
}

export function createPolicyProposal(input) {
  const intent = {
    ...input.intent,
    ...(input.intent?.transport
      ? {
          transport: {
            ...input.intent.transport,
            ports: [...(input.intent.transport.ports || [])].sort((left, right) => left - right),
          },
        }
      : {}),
  };
  const normalized = {
    ...input,
    intent,
    ...(input.observationRefs
      ? { observationRefs: [...input.observationRefs].sort() }
      : {}),
    targetFeasibility: [...(input.targetFeasibility || [])]
      .map((entry) => ({ ...entry, reasons: [...(entry.reasons || [])].sort() }))
      .sort((left, right) => left.target.localeCompare(right.target)),
  };
  return createRecord('proposals', normalized, input.semanticKey || {
    scopeDigest: input.scopeDigest,
    scopeClass: input.scopeClass,
    intent,
    ...(input.authorityGroupId ? {
      authorityGroupId: input.authorityGroupId,
      assurance: input.assurance,
    } : {}),
  });
}

export function createGraphDiff(input) {
  return createRecord('diff', input, input.semanticKey || {
    scopeDigest: input.scopeDigest,
    entityId: input.entityId,
    changeType: input.changeType,
    beforeDigest: input.beforeDigest,
    afterDigest: input.afterDigest,
  });
}
