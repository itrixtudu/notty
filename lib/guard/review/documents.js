import {
  DEPLOYMENT_TARGETS,
  REQUIRED_STREAM_ROLES,
  REVIEW_API_VERSION,
  REVIEW_KINDS,
  REVIEW_LIMITS,
  REVIEW_SCHEMA_VERSION,
  STREAM_ROLES,
  TARGET_PARITY,
} from './constants.js';
import { cloneCanonicalJson, sha256Digest } from './jcs.js';
import {
  assertSha256,
  assertStableId,
  createStableId,
} from './ids.js';
import {
  validateGraphRecord,
  validateHttpAssurance,
  validatePolicyIntent,
  validatePolicyProposal,
} from './records.js';
import {
  parseHashAddressedStream,
  validateStreamDescriptor,
} from './streams.js';
import {
  assertArray,
  assertBoolean,
  assertDateTime,
  assertDecimal,
  assertEnum,
  assertJsonBounds,
  assertNullableSha256,
  assertPlainObject,
  assertSafeToken,
  assertScope,
  assertStableIdArray,
  assertStrictObject,
  assertString,
  assertUniqueStrings,
} from './validation.js';

function assertDocumentHeader(document, kind, path = '$') {
  if (document.apiVersion !== REVIEW_API_VERSION) {
    throw new TypeError(`${path}.apiVersion must be ${REVIEW_API_VERSION}`);
  }
  if (document.kind !== kind) {
    throw new TypeError(`${path}.kind must be ${kind}`);
  }
  if (document.schemaVersion !== REVIEW_SCHEMA_VERSION) {
    throw new TypeError(`${path}.schemaVersion must be ${REVIEW_SCHEMA_VERSION}`);
  }
}

function sortById(values) {
  return [...values].sort((left, right) => (
    left.id < right.id ? -1 : left.id > right.id ? 1 : 0
  ));
}

function sortStreams(streams) {
  const order = new Map(STREAM_ROLES.map((role, index) => [role, index]));
  return [...streams].sort((left, right) => order.get(left.role) - order.get(right.role));
}

function validateSourceCoverage(coverage, path) {
  assertStrictObject(coverage, {
    required: ['status', 'lostEvents', 'parseErrors', 'gaps'],
  }, path);
  assertEnum(coverage.status, ['complete', 'incomplete', 'unavailable', 'degraded'], `${path}.status`);
  assertDecimal(coverage.lostEvents, `${path}.lostEvents`);
  assertDecimal(coverage.parseErrors, `${path}.parseErrors`);
  assertUniqueStrings(coverage.gaps, `${path}.gaps`, {
    maxItems: 256,
    sorted: true,
    string: { maxBytes: REVIEW_LIMITS.maxMessageBytes },
  });
  if (
    coverage.status === 'complete'
    && (coverage.lostEvents !== '0' || coverage.parseErrors !== '0' || coverage.gaps.length > 0)
  ) {
    throw new TypeError(`${path} complete coverage cannot contain loss, parse errors, or gaps`);
  }
  if (coverage.status !== 'complete' && coverage.gaps.length === 0) {
    throw new TypeError(`${path}.gaps must explain non-complete coverage`);
  }
}

function validateSource(source, path) {
  assertStrictObject(source, {
    required: ['id', 'artifactKind', 'artifactDigest', 'coverage'],
    optional: [
      'sourceType',
      'runId',
      'sourceName',
      'sourceDigest',
      'observedFrom',
      'observedTo',
    ],
  }, path);
  assertStableId(source.id, `${path}.id`);
  assertSafeToken(source.artifactKind, `${path}.artifactKind`);
  assertSha256(source.artifactDigest, `${path}.artifactDigest`);
  if (Object.hasOwn(source, 'sourceType')) {
    assertSafeToken(source.sourceType, `${path}.sourceType`);
  }
  if (Object.hasOwn(source, 'runId')) {
    assertString(source.runId, `${path}.runId`, {
      maxBytes: 256,
      pattern: /^[A-Za-z0-9][A-Za-z0-9_.:-]{0,255}$/,
    });
  }
  if (Object.hasOwn(source, 'sourceName')) {
    assertString(source.sourceName, `${path}.sourceName`, {
      maxBytes: 256,
      pattern: /^[A-Za-z0-9][A-Za-z0-9_.:-]{0,255}$/,
    });
  }
  if (Object.hasOwn(source, 'sourceDigest')) {
    assertSha256(source.sourceDigest, `${path}.sourceDigest`);
  }
  const hasObservedFrom = Object.hasOwn(source, 'observedFrom');
  const hasObservedTo = Object.hasOwn(source, 'observedTo');
  if (hasObservedFrom !== hasObservedTo) {
    throw new TypeError(`${path}.observedFrom and observedTo must be supplied together`);
  }
  if (hasObservedFrom) {
    assertDateTime(source.observedFrom, `${path}.observedFrom`);
    assertDateTime(source.observedTo, `${path}.observedTo`);
    if (Date.parse(source.observedFrom) > Date.parse(source.observedTo)) {
      throw new TypeError(`${path} observation time range is reversed`);
    }
  }
  validateSourceCoverage(source.coverage, `${path}.coverage`);
}

function validateBaseline(baseline, path = '$.baseline') {
  assertStrictObject(baseline, {
    required: ['selection', 'bundleDigest', 'reason'],
  }, path);
  assertEnum(baseline.selection, ['automatic', 'override', 'none'], `${path}.selection`);
  assertNullableSha256(baseline.bundleDigest, `${path}.bundleDigest`);
  if (baseline.reason !== null) {
    assertString(baseline.reason, `${path}.reason`, { maxBytes: REVIEW_LIMITS.maxMessageBytes });
  }
  if (baseline.selection === 'none' && baseline.bundleDigest !== null) {
    throw new TypeError(`${path}.bundleDigest must be null when no baseline is selected`);
  }
  if (baseline.selection !== 'none' && baseline.bundleDigest === null) {
    throw new TypeError(`${path}.bundleDigest is required for a selected baseline`);
  }
  if (baseline.selection === 'override' && baseline.reason === null) {
    throw new TypeError(`${path}.reason is required for a baseline override`);
  }
}

function validateSources(sources, path = '$.sources') {
  assertArray(sources, path, { maxItems: 1024 });
  const seen = new Set();
  let previous = null;
  for (let index = 0; index < sources.length; index += 1) {
    const source = sources[index];
    validateSource(source, `${path}[${index}]`);
    if (seen.has(source.id)) {
      throw new TypeError(`${path} contains a duplicate source ID`);
    }
    if (previous !== null && previous > source.id) {
      throw new TypeError(`${path} must be sorted by source ID`);
    }
    seen.add(source.id);
    previous = source.id;
  }
}

function validateStreams(streams, path = '$.streams') {
  assertArray(streams, path, {
    minItems: REQUIRED_STREAM_ROLES.length,
    maxItems: REQUIRED_STREAM_ROLES.length,
  });
  const roles = new Set();
  let previousIndex = -1;
  for (let index = 0; index < streams.length; index += 1) {
    const descriptor = streams[index];
    validateStreamDescriptor(descriptor, `${path}[${index}]`);
    if (roles.has(descriptor.role)) {
      throw new TypeError(`${path} contains duplicate stream role ${descriptor.role}`);
    }
    roles.add(descriptor.role);
    const roleIndex = STREAM_ROLES.indexOf(descriptor.role);
    if (roleIndex < previousIndex) {
      throw new TypeError(`${path} must use canonical role order`);
    }
    previousIndex = roleIndex;
  }
  for (const role of REQUIRED_STREAM_ROLES) {
    if (!roles.has(role)) {
      throw new TypeError(`${path} is missing required stream role ${role}`);
    }
  }
}

function graphDigestPayload(scope, sources, streams) {
  const graphRoles = new Set(['nodes', 'observations', 'coverage', 'findings']);
  return {
    apiVersion: REVIEW_API_VERSION,
    schemaVersion: REVIEW_SCHEMA_VERSION,
    scope,
    sources,
    streams: streams
      .filter((descriptor) => graphRoles.has(descriptor.role))
      .map(({ role, schema, sha256, bytes, records }) => ({
        role,
        schema,
        sha256,
        bytes,
        records,
      })),
  };
}

export function computeGraphDigest({ scope, sources, streams }) {
  assertScope(scope);
  validateSources(sources);
  validateStreams(streams);
  return sha256Digest(graphDigestPayload(scope, sources, streams));
}

export function computeProposalSetDigest({
  scopeDigest,
  graphDigest,
  basePolicyDigest,
  baseline,
  streams,
}) {
  assertSha256(scopeDigest, 'scopeDigest');
  assertSha256(graphDigest, 'graphDigest');
  assertSha256(basePolicyDigest, 'basePolicyDigest');
  validateBaseline(baseline);
  validateStreams(streams);
  const proposalStream = streams.find((descriptor) => descriptor.role === 'proposals');
  return sha256Digest({
    apiVersion: REVIEW_API_VERSION,
    schemaVersion: REVIEW_SCHEMA_VERSION,
    scopeDigest,
    graphDigest,
    basePolicyDigest,
    baseline,
    proposalStream: {
      schema: proposalStream.schema,
      sha256: proposalStream.sha256,
      bytes: proposalStream.bytes,
      records: proposalStream.records,
    },
  });
}

function bundleDigestPayload(bundle) {
  return {
    apiVersion: bundle.apiVersion,
    kind: bundle.kind,
    schemaVersion: bundle.schemaVersion,
    createdAt: bundle.createdAt,
    scope: bundle.scope,
    sources: bundle.sources,
    baseline: bundle.baseline,
    streams: bundle.streams,
    graphDigest: bundle.graphDigest,
    proposalSetDigest: bundle.proposalSetDigest,
    basePolicyDigest: bundle.basePolicyDigest,
    privacyProfile: bundle.privacyProfile,
  };
}

export function computeReviewBundleDigest(bundle) {
  return sha256Digest(bundleDigestPayload(bundle));
}

export function createReviewBundle(input) {
  assertPlainObject(input, 'review bundle input');
  const streams = sortStreams((input.streams || []).map((stream) => (
    stream?.descriptor || stream
  )));
  const sources = sortById((input.sources || []).map((source) => ({
    ...source,
    coverage: {
      ...source.coverage,
      gaps: [...(source.coverage?.gaps || [])].sort(),
    },
  })));
  const scope = cloneCanonicalJson(input.scope);
  const baseline = cloneCanonicalJson(input.baseline || {
    selection: 'none',
    bundleDigest: null,
    reason: null,
  });
  assertScope(scope);
  validateSources(sources);
  validateBaseline(baseline);
  validateStreams(streams);
  const graphDigest = computeGraphDigest({ scope, sources, streams });
  const proposalSetDigest = computeProposalSetDigest({
    scopeDigest: scope.scopeDigest,
    graphDigest,
    basePolicyDigest: input.basePolicyDigest || sha256Digest(null),
    baseline,
    streams,
  });
  const document = {
    apiVersion: REVIEW_API_VERSION,
    kind: REVIEW_KINDS.bundle,
    schemaVersion: REVIEW_SCHEMA_VERSION,
    bundleId: '',
    createdAt: input.createdAt || new Date().toISOString(),
    scope,
    sources,
    baseline,
    streams,
    graphDigest,
    proposalSetDigest,
    basePolicyDigest: input.basePolicyDigest || sha256Digest(null),
    privacyProfile: input.privacyProfile || 'private-review',
    bundleDigest: '',
  };
  document.bundleDigest = computeReviewBundleDigest(document);
  document.bundleId = createStableId('review', document.bundleDigest);
  const result = cloneCanonicalJson(document);
  validateReviewBundle(result);
  return Object.freeze(result);
}

export function validateReviewBundle(bundle, path = '$') {
  assertStrictObject(bundle, {
    required: [
      'apiVersion',
      'kind',
      'schemaVersion',
      'bundleId',
      'createdAt',
      'scope',
      'sources',
      'baseline',
      'streams',
      'graphDigest',
      'proposalSetDigest',
      'basePolicyDigest',
      'privacyProfile',
      'bundleDigest',
    ],
  }, path);
  assertDocumentHeader(bundle, REVIEW_KINDS.bundle, path);
  assertStableId(bundle.bundleId, `${path}.bundleId`);
  assertDateTime(bundle.createdAt, `${path}.createdAt`);
  assertScope(bundle.scope, `${path}.scope`);
  validateSources(bundle.sources, `${path}.sources`);
  validateBaseline(bundle.baseline, `${path}.baseline`);
  validateStreams(bundle.streams, `${path}.streams`);
  assertSha256(bundle.graphDigest, `${path}.graphDigest`);
  assertSha256(bundle.proposalSetDigest, `${path}.proposalSetDigest`);
  assertSha256(bundle.basePolicyDigest, `${path}.basePolicyDigest`);
  assertEnum(bundle.privacyProfile, ['private-review', 'portable-sensitive'], `${path}.privacyProfile`);
  assertSha256(bundle.bundleDigest, `${path}.bundleDigest`);
  const graphDigest = computeGraphDigest(bundle);
  if (bundle.graphDigest !== graphDigest) {
    throw new TypeError(`${path}.graphDigest does not match the graph streams`);
  }
  const proposalSetDigest = computeProposalSetDigest({
    scopeDigest: bundle.scope.scopeDigest,
    graphDigest,
    basePolicyDigest: bundle.basePolicyDigest,
    baseline: bundle.baseline,
    streams: bundle.streams,
  });
  if (bundle.proposalSetDigest !== proposalSetDigest) {
    throw new TypeError(`${path}.proposalSetDigest does not match the proposal stream`);
  }
  if (bundle.bundleDigest !== computeReviewBundleDigest(bundle)) {
    throw new TypeError(`${path}.bundleDigest does not match bundle content`);
  }
  if (bundle.bundleId !== createStableId('review', bundle.bundleDigest)) {
    throw new TypeError(`${path}.bundleId does not match bundle content`);
  }
  return bundle;
}

function resolveStreamContent(contents, descriptor) {
  let value;
  if (contents instanceof Map) {
    value = contents.get(descriptor.role) ?? contents.get(descriptor.path);
  } else if (contents && typeof contents === 'object') {
    value = contents[descriptor.role] ?? contents[descriptor.path];
  }
  if (value && typeof value === 'object' && !Buffer.isBuffer(value)) {
    value = value.content;
  }
  if (value === undefined) {
    throw new TypeError(`missing stream content for ${descriptor.role}`);
  }
  return value;
}

function validateHttpAssuranceEvidence(proposal, nodesById, path) {
  if (!proposal.assurance) return;
  const requestNodes = proposal.assurance.requestEvidenceRefs.map((requestId) => {
    const requestNode = nodesById.get(requestId);
    if (requestNode?.nodeType !== 'httpRequest') {
      throw new TypeError(`${path} HTTP request assurance references the wrong node type`);
    }
    return requestNode;
  });
  const responseNodes = proposal.assurance.responseEvidenceRefs.map((responseId) => {
    const responseNode = nodesById.get(responseId);
    if (responseNode?.nodeType !== 'httpResponse') {
      throw new TypeError(`${path} HTTP response assurance references the wrong node type`);
    }
    return responseNode;
  });
  for (const node of [...requestNodes, ...responseNodes]) {
    if (!node.evidenceRefs.every((evidenceRef) => proposal.evidenceRefs.includes(evidenceRef))) {
      throw new TypeError(`${path} HTTP assurance omits source evidence used by its frozen node`);
    }
  }
  if (proposal.intent.domain !== 'http') return;
  const requestNode = nodesById.get(proposal.intent.peer.value);
  const http = proposal.intent.http;
  const requestIdentity = requestNode?.identity || {};
  for (const field of [
    'method',
    'scheme',
    'host',
    'port',
    'requestTargetSha256',
    'representationHeadersSha256',
  ]) {
    if (requestIdentity[field] !== http[field]) {
      throw new TypeError(`${path} HTTP intent ${field} is not backed by its frozen request node`);
    }
  }
  if (
    (requestIdentity.requestBodySha256 ?? null)
    !== (http.requestBodySha256 ?? null)
  ) {
    throw new TypeError(`${path} HTTP intent request body is not backed by its frozen request node`);
  }
  if (!http.response) return;
  const matchingResponse = responseNodes.find((responseNode) => {
    const identity = responseNode.identity || {};
    return identity.contentSha256 === http.response.contentSha256
      && (!Object.hasOwn(http.response, 'status') || identity.status === http.response.status)
      && (
        !Object.hasOwn(http.response, 'decodedContentSha256')
        || identity.decodedContentSha256 === http.response.decodedContentSha256
      )
      && (
        !Object.hasOwn(http.response, 'redirectLocationSha256')
        || identity.redirectLocationSha256 === http.response.redirectLocationSha256
      )
      && (!Object.hasOwn(http.response, 'length') || identity.length === http.response.length);
  });
  if (!matchingResponse) {
    throw new TypeError(`${path} HTTP response identity is not backed by frozen response evidence`);
  }
  if (proposal.assurance.level === 'native-integrity') {
    const integrity = matchingResponse.properties?.integrity;
    if (
      integrity?.verified !== true
      || integrity.kind !== proposal.assurance.integrityKind
      || integrity.contentSha256 !== proposal.assurance.contentDigest
      || integrity.verificationEvidenceSha256 !== proposal.assurance.proofDigest
    ) {
      throw new TypeError(`${path} native integrity assurance is not backed by frozen verification evidence`);
    }
  }
  if (proposal.assurance.level === 'cas-replay') {
    const cas = matchingResponse.properties?.cas;
    if (
      cas?.available !== true
      || cas.objectSha256 !== proposal.assurance.contentDigest
      || cas.manifestSha256 !== proposal.assurance.proofDigest
    ) {
      throw new TypeError(`${path} CAS assurance is not backed by frozen content-store evidence`);
    }
  }
}

function validateMaterializedReferences(bundle, records) {
  const nodeIds = new Set(records.nodes.map((node) => node.id));
  const nodesById = new Map(records.nodes.map((node) => [node.id, node]));
  const observationIds = new Set(records.observations.map((observation) => observation.id));
  const assuranceEvidenceIds = new Set([...nodeIds, ...observationIds]);
  const sourceIds = new Set(bundle.sources.map((source) => source.id));
  for (const observation of records.observations) {
    if (!nodeIds.has(observation.subjectId) || !nodeIds.has(observation.objectId)) {
      throw new TypeError(`observation ${observation.id} references a missing graph node`);
    }
  }
  for (const marker of records.coverage) {
    for (const sourceId of marker.sourceIds) {
      if (!sourceIds.has(sourceId)) {
        throw new TypeError(`coverage marker ${marker.id} references a missing bundle source`);
      }
    }
  }
  for (const proposal of records.proposals) {
    if (!nodeIds.has(proposal.intent.subjectId)) {
      throw new TypeError(`proposal ${proposal.id} references a missing subject node`);
    }
    for (const observationId of proposal.observationRefs || []) {
      if (!observationIds.has(observationId)) {
        throw new TypeError(
          `proposal ${proposal.id} references a missing observation ${observationId}`,
        );
      }
    }
    for (const evidenceId of [
      ...(proposal.assurance?.requestEvidenceRefs || []),
      ...(proposal.assurance?.responseEvidenceRefs || []),
    ]) {
      if (!assuranceEvidenceIds.has(evidenceId)) {
        throw new TypeError(
          `proposal ${proposal.id} references missing HTTP assurance evidence ${evidenceId}`,
        );
      }
    }
    validateHttpAssuranceEvidence(proposal, nodesById, `proposal ${proposal.id}`);
  }
  for (const role of STREAM_ROLES) {
    for (const record of records[role]) {
      if (record.scopeDigest !== bundle.scope.scopeDigest) {
        throw new TypeError(`${role} record ${record.id} belongs to a different scope`);
      }
    }
  }
}

export function materializeSemanticGraph(bundle, streamContents) {
  validateReviewBundle(bundle);
  const records = {};
  for (const descriptor of bundle.streams) {
    records[descriptor.role] = parseHashAddressedStream(
      descriptor.role,
      resolveStreamContent(streamContents, descriptor),
      descriptor,
    );
  }
  validateMaterializedReferences(bundle, records);
  const graph = {
    apiVersion: REVIEW_API_VERSION,
    kind: REVIEW_KINDS.semanticGraph,
    schemaVersion: REVIEW_SCHEMA_VERSION,
    graphId: createStableId('graph', bundle.graphDigest),
    revision: bundle.bundleDigest,
    graphDigest: bundle.graphDigest,
    proposalSetDigest: bundle.proposalSetDigest,
    basePolicyDigest: bundle.basePolicyDigest,
    scope: bundle.scope,
    sources: bundle.sources,
    nodes: records.nodes,
    observations: records.observations,
    coverage: records.coverage,
    findings: records.findings,
    proposals: records.proposals,
    diff: records.diff,
    frozen: true,
    contentDigest: '',
  };
  graph.contentDigest = computeSemanticGraphContentDigest(graph);
  const result = cloneCanonicalJson(graph);
  validateSemanticGraph(result);
  return Object.freeze(result);
}

function semanticGraphDigestPayload(graph) {
  const { contentDigest, ...payload } = graph;
  return payload;
}

export function computeSemanticGraphContentDigest(graph) {
  assertPlainObject(graph, 'semantic graph');
  return sha256Digest(semanticGraphDigestPayload(graph));
}

export function validateSemanticGraph(graph, path = '$') {
  assertStrictObject(graph, {
    required: [
      'apiVersion',
      'kind',
      'schemaVersion',
      'graphId',
      'revision',
      'graphDigest',
      'proposalSetDigest',
      'basePolicyDigest',
      'scope',
      'sources',
      ...STREAM_ROLES,
      'frozen',
      'contentDigest',
    ],
  }, path);
  assertDocumentHeader(graph, REVIEW_KINDS.semanticGraph, path);
  assertStableId(graph.graphId, `${path}.graphId`);
  assertSha256(graph.revision, `${path}.revision`);
  assertSha256(graph.graphDigest, `${path}.graphDigest`);
  assertSha256(graph.proposalSetDigest, `${path}.proposalSetDigest`);
  assertSha256(graph.basePolicyDigest, `${path}.basePolicyDigest`);
  assertScope(graph.scope, `${path}.scope`);
  validateSources(graph.sources, `${path}.sources`);
  assertBoolean(graph.frozen, `${path}.frozen`);
  assertSha256(graph.contentDigest, `${path}.contentDigest`);
  if (!graph.frozen) {
    throw new TypeError(`${path}.frozen must be true for a materialized review snapshot`);
  }
  for (const role of STREAM_ROLES) {
    assertArray(graph[role], `${path}.${role}`, {
      maxItems: REVIEW_LIMITS.maxRecordsPerStream,
    });
    graph[role].forEach((record, index) => (
      validateGraphRecord(role, record, `${path}.${role}[${index}]`)
    ));
  }
  const nodeIds = new Set(graph.nodes.map((node) => node.id));
  const nodesById = new Map(graph.nodes.map((node) => [node.id, node]));
  const observationIds = new Set(graph.observations.map((observation) => observation.id));
  const assuranceEvidenceIds = new Set([...nodeIds, ...observationIds]);
  for (const observation of graph.observations) {
    if (!nodeIds.has(observation.subjectId) || !nodeIds.has(observation.objectId)) {
      throw new TypeError(`${path}.observations contains a missing graph-node reference`);
    }
  }
  for (const proposal of graph.proposals) {
    if (!nodeIds.has(proposal.intent.subjectId)) {
      throw new TypeError(`${path}.proposals contains a missing subject-node reference`);
    }
    for (const observationId of proposal.observationRefs || []) {
      if (!observationIds.has(observationId)) {
        throw new TypeError(`${path}.proposals contains a missing observation reference`);
      }
    }
    for (const evidenceId of [
      ...(proposal.assurance?.requestEvidenceRefs || []),
      ...(proposal.assurance?.responseEvidenceRefs || []),
    ]) {
      if (!assuranceEvidenceIds.has(evidenceId)) {
        throw new TypeError(`${path}.proposals contains a missing HTTP assurance reference`);
      }
    }
    validateHttpAssuranceEvidence(proposal, nodesById, `${path}.proposals`);
  }
  if (graph.graphId !== createStableId('graph', graph.graphDigest)) {
    throw new TypeError(`${path}.graphId does not match graphDigest`);
  }
  if (graph.contentDigest !== computeSemanticGraphContentDigest(graph)) {
    throw new TypeError(`${path}.contentDigest does not match the materialized graph`);
  }
  return graph;
}

function validateDecision(decision, path) {
  assertStrictObject(decision, {
    required: ['id', 'proposalId', 'disposition', 'rationale', 'targetAcknowledgements'],
  }, path);
  assertStableId(decision.id, `${path}.id`);
  assertStableId(decision.proposalId, `${path}.proposalId`);
  assertEnum(decision.disposition, ['accept', 'reject', 'needs-review'], `${path}.disposition`);
  assertString(decision.rationale, `${path}.rationale`, { maxBytes: REVIEW_LIMITS.maxMessageBytes });
  assertArray(decision.targetAcknowledgements, `${path}.targetAcknowledgements`, {
    maxItems: DEPLOYMENT_TARGETS.length,
  });
  const targets = new Set();
  let previousTarget = null;
  for (let index = 0; index < decision.targetAcknowledgements.length; index += 1) {
    const acknowledgement = decision.targetAcknowledgements[index];
    const acknowledgementPath = `${path}.targetAcknowledgements[${index}]`;
    assertStrictObject(acknowledgement, {
      required: ['target', 'status', 'rationale'],
    }, acknowledgementPath);
    assertEnum(acknowledgement.target, DEPLOYMENT_TARGETS, `${acknowledgementPath}.target`);
    assertEnum(acknowledgement.status, ['restrictive', 'conditional'], `${acknowledgementPath}.status`);
    assertString(acknowledgement.rationale, `${acknowledgementPath}.rationale`, {
      maxBytes: REVIEW_LIMITS.maxMessageBytes,
    });
    if (targets.has(acknowledgement.target)) {
      throw new TypeError(`${path}.targetAcknowledgements contains a duplicate target`);
    }
    if (previousTarget !== null && previousTarget > acknowledgement.target) {
      throw new TypeError(`${path}.targetAcknowledgements must be sorted by target`);
    }
    targets.add(acknowledgement.target);
    previousTarget = acknowledgement.target;
  }
}

function decisionSetDigestPayload(document) {
  const {
    decisionSetId,
    contentDigest,
    ...payload
  } = document;
  return payload;
}

export function createDecisionSet(input) {
  assertPlainObject(input, 'decision set input');
  validateSemanticGraph(input.graph, 'graph');
  const proposalIds = new Set(input.graph.proposals.map((proposal, index) => {
    validatePolicyProposal(proposal, `proposals[${index}]`);
    if (proposal.scopeDigest !== input.graph.scope.scopeDigest) {
      throw new TypeError(`proposal ${proposal.id} belongs to a different decision scope`);
    }
    return proposal.id;
  }));
  const decisions = (input.decisions || []).map((decision) => {
    const normalized = {
      ...decision,
      id: decision.id || createStableId('decision', {
        scopeDigest: input.graph.scope.scopeDigest,
        proposalId: decision.proposalId,
      }),
      targetAcknowledgements: [...(decision.targetAcknowledgements || [])]
        .sort((left, right) => left.target.localeCompare(right.target)),
    };
    return normalized;
  }).sort((left, right) => (
    left.proposalId < right.proposalId ? -1 : left.proposalId > right.proposalId ? 1 : 0
  ));
  if (proposalIds.size > 0) {
    if (decisions.length !== proposalIds.size) {
      throw new TypeError('decision set must decide every proposal exactly once');
    }
    for (const decision of decisions) {
      if (!proposalIds.has(decision.proposalId)) {
        throw new TypeError(`decision references unknown proposal ${decision.proposalId}`);
      }
    }
  }
  const proposalById = new Map(input.graph.proposals.map((proposal) => [proposal.id, proposal]));
  const acceptedAuthorityGroups = new Set();
  for (const decision of decisions) {
    if (decision.disposition !== 'accept') continue;
    const authorityGroupId = proposalById.get(decision.proposalId)?.authorityGroupId;
    if (!authorityGroupId) continue;
    if (acceptedAuthorityGroups.has(authorityGroupId)) {
      throw new TypeError(
        `decision set accepts more than one assurance variant for ${authorityGroupId}`,
      );
    }
    acceptedAuthorityGroups.add(authorityGroupId);
  }
  const document = {
    apiVersion: REVIEW_API_VERSION,
    kind: REVIEW_KINDS.decisionSet,
    schemaVersion: REVIEW_SCHEMA_VERSION,
    decisionSetId: '',
    createdAt: input.createdAt || new Date().toISOString(),
    reviewer: input.reviewer,
    scopeDigest: input.graph.scope.scopeDigest,
    graphDigest: input.graph.graphDigest,
    graphContentDigest: input.graph.contentDigest,
    proposalSetDigest: input.graph.proposalSetDigest,
    basePolicyDigest: input.graph.basePolicyDigest,
    decisions,
    contentDigest: '',
  };
  document.contentDigest = sha256Digest(decisionSetDigestPayload(document));
  document.decisionSetId = createStableId('decision-set', document.contentDigest);
  const result = cloneCanonicalJson(document);
  validateDecisionSet(result);
  return Object.freeze(result);
}

export function validateDecisionSet(document, path = '$') {
  assertStrictObject(document, {
    required: [
      'apiVersion',
      'kind',
      'schemaVersion',
      'decisionSetId',
      'createdAt',
      'reviewer',
      'scopeDigest',
      'graphDigest',
      'graphContentDigest',
      'proposalSetDigest',
      'basePolicyDigest',
      'decisions',
      'contentDigest',
    ],
  }, path);
  assertDocumentHeader(document, REVIEW_KINDS.decisionSet, path);
  assertStableId(document.decisionSetId, `${path}.decisionSetId`);
  assertDateTime(document.createdAt, `${path}.createdAt`);
  assertString(document.reviewer, `${path}.reviewer`, { maxBytes: 256 });
  for (const key of [
    'scopeDigest',
    'graphDigest',
    'graphContentDigest',
    'proposalSetDigest',
    'basePolicyDigest',
    'contentDigest',
  ]) {
    assertSha256(document[key], `${path}.${key}`);
  }
  assertArray(document.decisions, `${path}.decisions`, { maxItems: REVIEW_LIMITS.maxRules });
  const seen = new Set();
  let previous = null;
  for (let index = 0; index < document.decisions.length; index += 1) {
    const decision = document.decisions[index];
    validateDecision(decision, `${path}.decisions[${index}]`);
    if (decision.id !== createStableId('decision', {
      scopeDigest: document.scopeDigest,
      proposalId: decision.proposalId,
    })) {
      throw new TypeError(`${path}.decisions[${index}].id is not derived from its proposal and scope`);
    }
    if (seen.has(decision.proposalId)) {
      throw new TypeError(`${path}.decisions contains a duplicate proposal`);
    }
    if (previous !== null && previous > decision.proposalId) {
      throw new TypeError(`${path}.decisions must be sorted by proposal ID`);
    }
    seen.add(decision.proposalId);
    previous = decision.proposalId;
  }
  const expectedDigest = sha256Digest(decisionSetDigestPayload(document));
  if (document.contentDigest !== expectedDigest) {
    throw new TypeError(`${path}.contentDigest does not match the decisions`);
  }
  if (document.decisionSetId !== createStableId('decision-set', document.contentDigest)) {
    throw new TypeError(`${path}.decisionSetId does not match contentDigest`);
  }
  return document;
}

function validatePolicyRule(rule, path) {
  assertStrictObject(rule, {
    required: [
      'id',
      'proposalId',
      'scopeClass',
      'domain',
      'subjectId',
      'effect',
      'evidenceRefs',
      'decisionRefs',
    ],
    optional: [
      'direction',
      'peer',
      'transport',
      'operation',
      'constraints',
      'http',
      'authorityGroupId',
      'assurance',
    ],
  }, path);
  assertStableId(rule.id, `${path}.id`);
  assertStableId(rule.proposalId, `${path}.proposalId`);
  assertStableIdArray(rule.evidenceRefs, `${path}.evidenceRefs`, { minItems: 1, sorted: true });
  assertStableIdArray(rule.decisionRefs, `${path}.decisionRefs`, { minItems: 1, sorted: true });
  assertEnum(rule.scopeClass, ['build', 'runtime'], `${path}.scopeClass`);
  if (Object.hasOwn(rule, 'authorityGroupId')) {
    assertStableId(rule.authorityGroupId, `${path}.authorityGroupId`);
  }
  const {
    id,
    proposalId,
    scopeClass,
    evidenceRefs,
    decisionRefs,
    authorityGroupId,
    assurance,
    ...intent
  } = rule;
  validatePolicyIntent(intent, path);
  if (Object.hasOwn(rule, 'authorityGroupId') !== Object.hasOwn(rule, 'assurance')) {
    throw new TypeError(`${path} authorityGroupId and assurance must be supplied together`);
  }
  if (assurance) {
    validateHttpAssurance(assurance, `${path}.assurance`);
    if (assurance.level === 'endpoint-only' && intent.domain !== 'network') {
      throw new TypeError(`${path} endpoint-only assurance must retain network intent`);
    }
    if (assurance.level !== 'endpoint-only' && intent.domain !== 'http') {
      throw new TypeError(`${path} URL/content assurance requires HTTP intent`);
    }
    if (
      intent.domain === 'http'
      && !assurance.requestEvidenceRefs.includes(intent.peer.value)
    ) {
      throw new TypeError(`${path}.peer is not bound to its request assurance evidence`);
    }
    if (
      assurance.contentDigest
      && assurance.contentDigest !== intent.http?.response?.contentSha256
    ) {
      throw new TypeError(`${path} assurance digest does not match its HTTP response identity`);
    }
    const responseKinds = {
      'native-integrity': 'native-integrity',
      'cas-replay': 'cas',
      'live-digest-gate': 'live-digest',
    };
    if (
      responseKinds[assurance.level]
      && intent.http?.response?.kind !== responseKinds[assurance.level]
    ) {
      throw new TypeError(`${path} HTTP response identity does not match its assurance level`);
    }
  }
}

function policyIrDigestPayload(document) {
  const { policyIrId, contentDigest, ...payload } = document;
  return payload;
}

export function createPolicyIR(input) {
  assertPlainObject(input, 'policy IR input');
  validateDecisionSet(input.decisionSet, 'decisionSet');
  validateSemanticGraph(input.graph, 'graph');
  const scope = input.graph.scope;
  if (scope.scopeDigest !== input.decisionSet.scopeDigest) {
    throw new TypeError('policy IR scope does not match the decision set');
  }
  for (const key of [
    'graphDigest',
    'graphContentDigest',
    'proposalSetDigest',
    'basePolicyDigest',
  ]) {
    if (input.decisionSet[key] !== input.graph[
      key === 'graphContentDigest' ? 'contentDigest' : key
    ]) {
      throw new TypeError(`policy IR graph ${key} does not match the decision set`);
    }
  }
  const proposals = new Map();
  for (let index = 0; index < input.graph.proposals.length; index += 1) {
    const proposal = input.graph.proposals[index];
    validatePolicyProposal(proposal, `proposals[${index}]`);
    if (proposal.scopeDigest !== scope.scopeDigest) {
      throw new TypeError(`proposal ${proposal.id} belongs to a different scope`);
    }
    if (
      proposal.scopeClass !== scope.class
      && !(scope.class === 'runtime' && proposal.scopeClass === 'build')
    ) {
      throw new TypeError(`proposal ${proposal.id} has a different scope class`);
    }
    if (proposals.has(proposal.id)) {
      throw new TypeError(`duplicate proposal ${proposal.id}`);
    }
    proposals.set(proposal.id, proposal);
  }
  if (proposals.size !== input.decisionSet.decisions.length) {
    throw new TypeError('policy IR requires exactly one decision for every supplied proposal');
  }
  const rules = [];
  const acceptedAuthorityGroups = new Set();
  for (const decision of input.decisionSet.decisions) {
    const proposal = proposals.get(decision.proposalId);
    if (!proposal) {
      throw new TypeError(`decision references unavailable proposal ${decision.proposalId}`);
    }
    if (decision.disposition === 'needs-review') {
      throw new TypeError(`proposal ${proposal.id} still needs review`);
    }
    if (decision.disposition !== 'accept') {
      continue;
    }
    if (proposal.authorityGroupId) {
      if (acceptedAuthorityGroups.has(proposal.authorityGroupId)) {
        throw new TypeError(
          `policy IR accepts more than one assurance variant for ${proposal.authorityGroupId}`,
        );
      }
      acceptedAuthorityGroups.add(proposal.authorityGroupId);
    }
    const ruleBody = {
      proposalId: proposal.id,
      scopeClass: proposal.scopeClass,
      ...proposal.intent,
      ...(proposal.authorityGroupId ? {
        authorityGroupId: proposal.authorityGroupId,
        assurance: proposal.assurance,
      } : {}),
      evidenceRefs: proposal.evidenceRefs,
      decisionRefs: [decision.id],
    };
    rules.push({
      id: createStableId('rule', {
        scopeDigest: scope.scopeDigest,
        proposalId: proposal.id,
        scopeClass: proposal.scopeClass,
        intent: proposal.intent,
        ...(proposal.authorityGroupId ? {
          authorityGroupId: proposal.authorityGroupId,
          assurance: proposal.assurance,
        } : {}),
      }),
      ...ruleBody,
    });
  }
  rules.sort((left, right) => (left.id < right.id ? -1 : left.id > right.id ? 1 : 0));
  const document = {
    apiVersion: REVIEW_API_VERSION,
    kind: REVIEW_KINDS.policyIr,
    schemaVersion: REVIEW_SCHEMA_VERSION,
    policyIrId: '',
    createdAt: input.createdAt || new Date().toISOString(),
    graphDigest: input.decisionSet.graphDigest,
    graphContentDigest: input.decisionSet.graphContentDigest,
    proposalSetDigest: input.decisionSet.proposalSetDigest,
    decisionSetDigest: input.decisionSet.contentDigest,
    basePolicyDigest: input.decisionSet.basePolicyDigest,
    scope,
    defaults: { ingress: 'deny', egress: 'deny' },
    rules,
    contentDigest: '',
  };
  document.contentDigest = sha256Digest(policyIrDigestPayload(document));
  document.policyIrId = createStableId('policy-ir', document.contentDigest);
  const result = cloneCanonicalJson(document);
  validatePolicyIR(result);
  return Object.freeze(result);
}

export function validatePolicyIR(document, path = '$') {
  assertStrictObject(document, {
    required: [
      'apiVersion',
      'kind',
      'schemaVersion',
      'policyIrId',
      'createdAt',
      'graphDigest',
      'graphContentDigest',
      'proposalSetDigest',
      'decisionSetDigest',
      'basePolicyDigest',
      'scope',
      'defaults',
      'rules',
      'contentDigest',
    ],
  }, path);
  assertDocumentHeader(document, REVIEW_KINDS.policyIr, path);
  assertStableId(document.policyIrId, `${path}.policyIrId`);
  assertDateTime(document.createdAt, `${path}.createdAt`);
  for (const key of [
    'graphDigest',
    'graphContentDigest',
    'proposalSetDigest',
    'decisionSetDigest',
    'basePolicyDigest',
    'contentDigest',
  ]) {
    assertSha256(document[key], `${path}.${key}`);
  }
  assertScope(document.scope, `${path}.scope`);
  assertStrictObject(document.defaults, { required: ['ingress', 'egress'] }, `${path}.defaults`);
  if (document.defaults.ingress !== 'deny' || document.defaults.egress !== 'deny') {
    throw new TypeError(`${path}.defaults must be default deny`);
  }
  assertArray(document.rules, `${path}.rules`, { maxItems: REVIEW_LIMITS.maxRules });
  const seen = new Set();
  let previous = null;
  for (let index = 0; index < document.rules.length; index += 1) {
    const rule = document.rules[index];
    validatePolicyRule(rule, `${path}.rules[${index}]`);
    if (seen.has(rule.id)) {
      throw new TypeError(`${path}.rules contains a duplicate rule`);
    }
    if (previous !== null && previous > rule.id) {
      throw new TypeError(`${path}.rules must be sorted by rule ID`);
    }
    seen.add(rule.id);
    previous = rule.id;
    const {
      id,
      proposalId,
      scopeClass,
      evidenceRefs,
      decisionRefs,
      authorityGroupId,
      assurance,
      ...intent
    } = rule;
    const expectedRuleId = createStableId('rule', {
      scopeDigest: document.scope.scopeDigest,
      proposalId,
      scopeClass,
      intent,
      ...(authorityGroupId ? { authorityGroupId, assurance } : {}),
    });
    if (id !== expectedRuleId) {
      throw new TypeError(`${path}.rules[${index}].id is not derived from its proposal and intent`);
    }
  }
  const expectedDigest = sha256Digest(policyIrDigestPayload(document));
  if (document.contentDigest !== expectedDigest) {
    throw new TypeError(`${path}.contentDigest does not match policy IR`);
  }
  if (document.policyIrId !== createStableId('policy-ir', document.contentDigest)) {
    throw new TypeError(`${path}.policyIrId does not match contentDigest`);
  }
  return document;
}

function validateCompiler(compiler, path) {
  assertStrictObject(compiler, {
    required: ['id', 'version', 'digest'],
  }, path);
  assertSafeToken(compiler.id, `${path}.id`);
  assertString(compiler.version, `${path}.version`, { maxBytes: 128 });
  assertSha256(compiler.digest, `${path}.digest`);
}

function validateArtifactRef(artifact, path) {
  assertStrictObject(artifact, {
    required: ['name', 'mediaType', 'sha256', 'bytes'],
  }, path);
  assertString(artifact.name, `${path}.name`, {
    maxBytes: 256,
    pattern: /^[A-Za-z0-9][A-Za-z0-9_.-]{0,255}$/,
  });
  assertString(artifact.mediaType, `${path}.mediaType`, { maxBytes: 256 });
  assertSha256(artifact.sha256, `${path}.sha256`);
  assertDecimal(artifact.bytes, `${path}.bytes`);
}

function validateRuleMapping(mapping, path) {
  assertStrictObject(mapping, {
    required: ['ruleId', 'proposalId', 'pointer', 'parity', 'reasons'],
  }, path);
  assertStableId(mapping.ruleId, `${path}.ruleId`);
  assertStableId(mapping.proposalId, `${path}.proposalId`);
  assertString(mapping.pointer, `${path}.pointer`, { maxBytes: 2048 });
  assertEnum(mapping.parity, TARGET_PARITY, `${path}.parity`);
  assertUniqueStrings(mapping.reasons, `${path}.reasons`, {
    maxItems: 64,
    sorted: true,
    string: { maxBytes: REVIEW_LIMITS.maxMessageBytes },
  });
}

function validateTargetProjection(projection, path, policyRules = null) {
  assertStrictObject(projection, {
    required: [
      'target',
      'targetContextDigest',
      'compiler',
      'status',
      'activationEligible',
      'requiresAcknowledgement',
      'artifacts',
      'ruleMappings',
      'diagnostics',
    ],
  }, path);
  assertEnum(projection.target, DEPLOYMENT_TARGETS, `${path}.target`);
  assertSha256(projection.targetContextDigest, `${path}.targetContextDigest`);
  validateCompiler(projection.compiler, `${path}.compiler`);
  assertEnum(projection.status, TARGET_PARITY, `${path}.status`);
  assertBoolean(projection.activationEligible, `${path}.activationEligible`);
  assertBoolean(projection.requiresAcknowledgement, `${path}.requiresAcknowledgement`);
  const statusCanActivate = ['exact', 'restrictive', 'conditional'].includes(
    projection.status,
  );
  if (projection.activationEligible && !statusCanActivate) {
    throw new TypeError(`${path}.activationEligible disagrees with projection status`);
  }
  const expectedAcknowledgement = ['restrictive', 'conditional'].includes(projection.status);
  if (projection.requiresAcknowledgement !== expectedAcknowledgement) {
    throw new TypeError(`${path}.requiresAcknowledgement disagrees with projection status`);
  }
  assertArray(projection.artifacts, `${path}.artifacts`, { maxItems: 128 });
  const artifactNames = new Set();
  let previousArtifact = null;
  for (let index = 0; index < projection.artifacts.length; index += 1) {
    const artifact = projection.artifacts[index];
    validateArtifactRef(artifact, `${path}.artifacts[${index}]`);
    if (artifactNames.has(artifact.name)) {
      throw new TypeError(`${path}.artifacts contains a duplicate name`);
    }
    if (previousArtifact !== null && previousArtifact > artifact.name) {
      throw new TypeError(`${path}.artifacts must be sorted by name`);
    }
    artifactNames.add(artifact.name);
    previousArtifact = artifact.name;
  }
  assertArray(projection.ruleMappings, `${path}.ruleMappings`, {
    maxItems: REVIEW_LIMITS.maxRules,
  });
  const mappedRules = new Set();
  let previousRule = null;
  let worstParity = 0;
  let inScopeMappings = 0;
  const parityRank = new Map(TARGET_PARITY.map((value, index) => [value, index]));
  for (let index = 0; index < projection.ruleMappings.length; index += 1) {
    const mapping = projection.ruleMappings[index];
    validateRuleMapping(mapping, `${path}.ruleMappings[${index}]`);
    if (mappedRules.has(mapping.ruleId)) {
      throw new TypeError(`${path}.ruleMappings contains a duplicate rule`);
    }
    if (policyRules && !policyRules.has(mapping.ruleId)) {
      throw new TypeError(`${path}.ruleMappings references an unknown policy rule`);
    }
    if (
      policyRules
      && policyRules.get(mapping.ruleId).proposalId !== mapping.proposalId
    ) {
      throw new TypeError(`${path}.ruleMappings proposal does not match its policy rule`);
    }
    if (previousRule !== null && previousRule > mapping.ruleId) {
      throw new TypeError(`${path}.ruleMappings must be sorted by rule ID`);
    }
    mappedRules.add(mapping.ruleId);
    previousRule = mapping.ruleId;
    if (mapping.parity !== 'outsideScope') {
      inScopeMappings += 1;
      worstParity = Math.max(worstParity, parityRank.get(mapping.parity));
    }
  }
  if (
    policyRules
    && !['unsupported', 'outsideScope'].includes(projection.status)
    && mappedRules.size !== policyRules.size
  ) {
    throw new TypeError(`${path}.ruleMappings must classify every policy rule`);
  }
  if (parityRank.get(projection.status) < worstParity) {
    throw new TypeError(`${path}.status is more permissive than an individual rule mapping`);
  }
  if (
    (projection.status === 'outsideScope')
    !== (inScopeMappings === 0)
  ) {
    throw new TypeError(`${path}.outsideScope status disagrees with its rule mappings`);
  }
  if (
    policyRules
    && policyRules.size > 0
    && projection.activationEligible
    && projection.artifacts.length === 0
  ) {
    throw new TypeError(`${path}.artifacts is required for an activatable projection`);
  }
  assertUniqueStrings(projection.diagnostics, `${path}.diagnostics`, {
    maxItems: 256,
    sorted: true,
    string: { maxBytes: REVIEW_LIMITS.maxMessageBytes },
  });
}

function targetReviewSetDigestPayload(document) {
  const { targetReviewSetId, contentDigest, ...payload } = document;
  return payload;
}

export function createTargetReviewSet(input) {
  assertPlainObject(input, 'target review set input');
  validatePolicyIR(input.policyIR, 'policyIR');
  const policyRules = new Map(input.policyIR.rules.map((rule) => [rule.id, rule]));
  const projections = (input.projections || []).map((projection) => ({
    ...projection,
    activationEligible: projection.activationEligible === true
      && ['exact', 'restrictive', 'conditional'].includes(projection.status),
    requiresAcknowledgement: ['restrictive', 'conditional'].includes(projection.status),
    artifacts: [...(projection.artifacts || [])]
      .sort((left, right) => left.name.localeCompare(right.name)),
    ruleMappings: [...(projection.ruleMappings || [])]
      .map((mapping) => ({
        ...mapping,
        reasons: [...(mapping.reasons || [])].sort(),
      }))
      .sort((left, right) => left.ruleId.localeCompare(right.ruleId)),
    diagnostics: [...(projection.diagnostics || [])].sort(),
  })).sort((left, right) => left.target.localeCompare(right.target));
  projections.forEach((projection, index) => (
    validateTargetProjection(projection, `projections[${index}]`, policyRules)
  ));
  const document = {
    apiVersion: REVIEW_API_VERSION,
    kind: REVIEW_KINDS.targetReviewSet,
    schemaVersion: REVIEW_SCHEMA_VERSION,
    targetReviewSetId: '',
    createdAt: input.createdAt || new Date().toISOString(),
    graphDigest: input.policyIR.graphDigest,
    proposalSetDigest: input.policyIR.proposalSetDigest,
    decisionSetDigest: input.policyIR.decisionSetDigest,
    basePolicyDigest: input.policyIR.basePolicyDigest,
    policyIrDigest: input.policyIR.contentDigest,
    scopeDigest: input.policyIR.scope.scopeDigest,
    projections,
    contentDigest: '',
  };
  document.contentDigest = sha256Digest(targetReviewSetDigestPayload(document));
  document.targetReviewSetId = createStableId('target-review', document.contentDigest);
  const result = cloneCanonicalJson(document);
  validateTargetReviewSet(result, { policyIR: input.policyIR });
  return Object.freeze(result);
}

export function validateTargetReviewSet(document, options = {}, path = '$') {
  assertStrictObject(document, {
    required: [
      'apiVersion',
      'kind',
      'schemaVersion',
      'targetReviewSetId',
      'createdAt',
      'graphDigest',
      'proposalSetDigest',
      'decisionSetDigest',
      'basePolicyDigest',
      'policyIrDigest',
      'scopeDigest',
      'projections',
      'contentDigest',
    ],
  }, path);
  assertDocumentHeader(document, REVIEW_KINDS.targetReviewSet, path);
  assertStableId(document.targetReviewSetId, `${path}.targetReviewSetId`);
  assertDateTime(document.createdAt, `${path}.createdAt`);
  for (const key of [
    'graphDigest',
    'proposalSetDigest',
    'decisionSetDigest',
    'basePolicyDigest',
    'policyIrDigest',
    'scopeDigest',
    'contentDigest',
  ]) {
    assertSha256(document[key], `${path}.${key}`);
  }
  const policyIR = options.policyIR || null;
  if (policyIR) {
    validatePolicyIR(policyIR, 'policyIR');
    const bindings = {
      graphDigest: policyIR.graphDigest,
      proposalSetDigest: policyIR.proposalSetDigest,
      decisionSetDigest: policyIR.decisionSetDigest,
      basePolicyDigest: policyIR.basePolicyDigest,
      policyIrDigest: policyIR.contentDigest,
      scopeDigest: policyIR.scope.scopeDigest,
    };
    for (const [key, value] of Object.entries(bindings)) {
      if (document[key] !== value) {
        throw new TypeError(`${path}.${key} does not bind the supplied policy IR`);
      }
    }
  }
  assertArray(document.projections, `${path}.projections`, {
    maxItems: DEPLOYMENT_TARGETS.length,
  });
  const targets = new Set();
  const policyRules = policyIR
    ? new Map(policyIR.rules.map((rule) => [rule.id, rule]))
    : null;
  let previous = null;
  for (let index = 0; index < document.projections.length; index += 1) {
    const projection = document.projections[index];
    validateTargetProjection(projection, `${path}.projections[${index}]`, policyRules);
    if (targets.has(projection.target)) {
      throw new TypeError(`${path}.projections contains a duplicate target`);
    }
    if (previous !== null && previous > projection.target) {
      throw new TypeError(`${path}.projections must be sorted by target`);
    }
    targets.add(projection.target);
    previous = projection.target;
  }
  const expectedDigest = sha256Digest(targetReviewSetDigestPayload(document));
  if (document.contentDigest !== expectedDigest) {
    throw new TypeError(`${path}.contentDigest does not match target projections`);
  }
  if (document.targetReviewSetId !== createStableId('target-review', document.contentDigest)) {
    throw new TypeError(`${path}.targetReviewSetId does not match contentDigest`);
  }
  return document;
}

function validateFiniteCoordinate(value, path) {
  if (!Number.isFinite(value) || Math.abs(value) > 10_000_000) {
    throw new TypeError(`${path} must be a finite coordinate within bounds`);
  }
}

function validatePosition(position, path) {
  assertStrictObject(position, {
    required: ['nodeId', 'x', 'y', 'z', 'pinned'],
  }, path);
  assertStableId(position.nodeId, `${path}.nodeId`);
  validateFiniteCoordinate(position.x, `${path}.x`);
  validateFiniteCoordinate(position.y, `${path}.y`);
  if (position.z !== null) {
    validateFiniteCoordinate(position.z, `${path}.z`);
  }
  assertBoolean(position.pinned, `${path}.pinned`);
}

function validateVector(vector, path) {
  assertStrictObject(vector, { required: ['x', 'y', 'z'] }, path);
  validateFiniteCoordinate(vector.x, `${path}.x`);
  validateFiniteCoordinate(vector.y, `${path}.y`);
  validateFiniteCoordinate(vector.z, `${path}.z`);
}

function validateCamera(camera, path) {
  if (camera === null) {
    return;
  }
  assertStrictObject(camera, {
    required: ['position', 'target', 'zoom'],
  }, path);
  validateVector(camera.position, `${path}.position`);
  validateVector(camera.target, `${path}.target`);
  if (!Number.isFinite(camera.zoom) || camera.zoom <= 0 || camera.zoom > 1000) {
    throw new TypeError(`${path}.zoom must be a positive finite number no greater than 1000`);
  }
}

export function createGraphViewState(input) {
  assertPlainObject(input, 'graph view state input');
  const positions = [...(input.positions || [])].sort((left, right) => (
    left.nodeId < right.nodeId ? -1 : left.nodeId > right.nodeId ? 1 : 0
  ));
  const document = {
    apiVersion: REVIEW_API_VERSION,
    kind: REVIEW_KINDS.viewState,
    schemaVersion: REVIEW_SCHEMA_VERSION,
    viewStateId: input.viewStateId || createStableId('graph-view', {
      graphDigest: input.graphDigest,
      renderer: input.renderer,
    }),
    graphDigest: input.graphDigest,
    updatedAt: input.updatedAt || new Date().toISOString(),
    renderer: input.renderer,
    projection: input.projection || 'baseline-drift',
    positions,
    collapsedNodeIds: [...(input.collapsedNodeIds || [])].sort(),
    filters: input.filters || {},
    camera: input.camera ?? null,
    authoritative: false,
  };
  const result = cloneCanonicalJson(document);
  validateGraphViewState(result);
  return Object.freeze(result);
}

export function validateGraphViewState(document, path = '$') {
  assertStrictObject(document, {
    required: [
      'apiVersion',
      'kind',
      'schemaVersion',
      'viewStateId',
      'graphDigest',
      'updatedAt',
      'renderer',
      'projection',
      'positions',
      'collapsedNodeIds',
      'filters',
      'camera',
      'authoritative',
    ],
  }, path);
  assertDocumentHeader(document, REVIEW_KINDS.viewState, path);
  assertStableId(document.viewStateId, `${path}.viewStateId`);
  assertSha256(document.graphDigest, `${path}.graphDigest`);
  assertDateTime(document.updatedAt, `${path}.updatedAt`);
  assertStrictObject(document.renderer, { required: ['name', 'version'] }, `${path}.renderer`);
  assertSafeToken(document.renderer.name, `${path}.renderer.name`);
  assertString(document.renderer.version, `${path}.renderer.version`, { maxBytes: 128 });
  assertEnum(
    document.projection,
    ['baseline-drift', 'build', 'behavior', 'network', 'evidence', 'policy', 'runtime'],
    `${path}.projection`,
  );
  assertArray(document.positions, `${path}.positions`, {
    maxItems: REVIEW_LIMITS.maxViewNodes,
  });
  const seen = new Set();
  let previous = null;
  for (let index = 0; index < document.positions.length; index += 1) {
    const position = document.positions[index];
    validatePosition(position, `${path}.positions[${index}]`);
    if (seen.has(position.nodeId)) {
      throw new TypeError(`${path}.positions contains a duplicate node`);
    }
    if (previous !== null && previous > position.nodeId) {
      throw new TypeError(`${path}.positions must be sorted by node ID`);
    }
    seen.add(position.nodeId);
    previous = position.nodeId;
  }
  assertStableIdArray(document.collapsedNodeIds, `${path}.collapsedNodeIds`, {
    maxItems: REVIEW_LIMITS.maxViewNodes,
    sorted: true,
  });
  assertPlainObject(document.filters, `${path}.filters`);
  assertJsonBounds(document.filters, `${path}.filters`);
  validateCamera(document.camera, `${path}.camera`);
  if (document.authoritative !== false) {
    throw new TypeError(`${path}.authoritative must be false`);
  }
  if (document.viewStateId !== createStableId('graph-view', {
    graphDigest: document.graphDigest,
    renderer: document.renderer,
  })) {
    throw new TypeError(`${path}.viewStateId does not match graph and renderer identity`);
  }
  return document;
}

function validateWatermark(watermark, path) {
  assertStrictObject(watermark, {
    required: ['sourceId', 'sequence', 'observedAt'],
  }, path);
  assertStableId(watermark.sourceId, `${path}.sourceId`);
  assertDecimal(watermark.sequence, `${path}.sequence`);
  if (watermark.observedAt !== null) {
    assertDateTime(watermark.observedAt, `${path}.observedAt`);
  }
}

function validateDeltaOperation(operation, path) {
  assertStrictObject(operation, {
    required: ['op', 'role', 'recordId', 'recordDigest'],
    optional: ['record'],
  }, path);
  assertEnum(operation.op, ['upsert', 'remove'], `${path}.op`);
  assertEnum(operation.role, STREAM_ROLES, `${path}.role`);
  assertStableId(operation.recordId, `${path}.recordId`);
  assertSha256(operation.recordDigest, `${path}.recordDigest`);
  if (operation.op === 'upsert') {
    if (!Object.hasOwn(operation, 'record')) {
      throw new TypeError(`${path}.record is required for an upsert`);
    }
    validateGraphRecord(operation.role, operation.record, `${path}.record`);
    if (operation.record.id !== operation.recordId) {
      throw new TypeError(`${path}.recordId does not match the upsert record`);
    }
    if (sha256Digest(operation.record) !== operation.recordDigest) {
      throw new TypeError(`${path}.recordDigest does not match the upsert record`);
    }
  } else if (Object.hasOwn(operation, 'record')) {
    throw new TypeError(`${path}.record is not allowed for a remove operation`);
  }
}

function deltaDigestPayload(document) {
  const { deltaDigest, ...payload } = document;
  return payload;
}

export function createGraphDelta(input) {
  assertPlainObject(input, 'graph delta input');
  const operations = (input.operations || []).map((operation) => {
    if (operation.op !== 'upsert') {
      return operation;
    }
    return {
      ...operation,
      recordId: operation.recordId || operation.record?.id,
      recordDigest: operation.recordDigest || sha256Digest(operation.record),
    };
  });
  const document = {
    apiVersion: REVIEW_API_VERSION,
    kind: REVIEW_KINDS.delta,
    schemaVersion: REVIEW_SCHEMA_VERSION,
    graphId: input.graphId,
    baseRevision: input.baseRevision,
    scopeDigest: input.scopeDigest,
    sequence: input.sequence,
    previousDeltaDigest: input.previousDeltaDigest ?? null,
    createdAt: input.createdAt || new Date().toISOString(),
    sourceWatermarks: [...(input.sourceWatermarks || [])].sort((left, right) => (
      left.sourceId < right.sourceId ? -1 : left.sourceId > right.sourceId ? 1 : 0
    )),
    operations,
    frozen: false,
    deltaDigest: '',
  };
  document.deltaDigest = sha256Digest(deltaDigestPayload(document));
  const result = cloneCanonicalJson(document);
  validateGraphDelta(result);
  return Object.freeze(result);
}

export function validateGraphDelta(document, path = '$') {
  assertStrictObject(document, {
    required: [
      'apiVersion',
      'kind',
      'schemaVersion',
      'graphId',
      'baseRevision',
      'scopeDigest',
      'sequence',
      'previousDeltaDigest',
      'createdAt',
      'sourceWatermarks',
      'operations',
      'frozen',
      'deltaDigest',
    ],
  }, path);
  assertDocumentHeader(document, REVIEW_KINDS.delta, path);
  assertStableId(document.graphId, `${path}.graphId`);
  assertSha256(document.baseRevision, `${path}.baseRevision`);
  assertSha256(document.scopeDigest, `${path}.scopeDigest`);
  assertDecimal(document.sequence, `${path}.sequence`);
  if (document.sequence === '0') {
    throw new TypeError(`${path}.sequence must be greater than zero`);
  }
  assertNullableSha256(document.previousDeltaDigest, `${path}.previousDeltaDigest`);
  assertDateTime(document.createdAt, `${path}.createdAt`);
  assertArray(document.sourceWatermarks, `${path}.sourceWatermarks`, { maxItems: 1024 });
  const sources = new Set();
  let previous = null;
  for (let index = 0; index < document.sourceWatermarks.length; index += 1) {
    const watermark = document.sourceWatermarks[index];
    validateWatermark(watermark, `${path}.sourceWatermarks[${index}]`);
    if (sources.has(watermark.sourceId)) {
      throw new TypeError(`${path}.sourceWatermarks contains a duplicate source`);
    }
    if (previous !== null && previous > watermark.sourceId) {
      throw new TypeError(`${path}.sourceWatermarks must be sorted by source ID`);
    }
    sources.add(watermark.sourceId);
    previous = watermark.sourceId;
  }
  assertArray(document.operations, `${path}.operations`, {
    maxItems: REVIEW_LIMITS.maxDeltaOperations,
  });
  document.operations.forEach((operation, index) => (
    validateDeltaOperation(operation, `${path}.operations[${index}]`)
  ));
  for (let index = 0; index < document.operations.length; index += 1) {
    const operation = document.operations[index];
    if (operation.op === 'upsert' && operation.record.scopeDigest !== document.scopeDigest) {
      throw new TypeError(`${path}.operations[${index}].record belongs to a different scope`);
    }
  }
  if (document.sequence === '1' && document.previousDeltaDigest !== null) {
    throw new TypeError(`${path}.previousDeltaDigest must be null for the first delta`);
  }
  if (document.sequence !== '1' && document.previousDeltaDigest === null) {
    throw new TypeError(`${path}.previousDeltaDigest is required after the first delta`);
  }
  if (document.frozen !== false) {
    throw new TypeError(`${path}.frozen must be false for a live delta`);
  }
  assertSha256(document.deltaDigest, `${path}.deltaDigest`);
  if (document.deltaDigest !== sha256Digest(deltaDigestPayload(document))) {
    throw new TypeError(`${path}.deltaDigest does not match delta content`);
  }
  return document;
}
