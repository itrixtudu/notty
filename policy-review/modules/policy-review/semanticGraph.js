import { parseRfc3339Timestamp } from './timelineProjection.js';
import { normalizeManagedReviewGraphUrl } from './runtimeAttestation.js';

const API_VERSION = 'notty.dev/v1alpha1';
const GRAPH_KIND = 'NoshSemanticGraph';
const DELTA_KIND = 'NoshSemanticGraphDelta';
const DECISION_SET_KIND = 'NoshPolicyDecisionSet';

export const MAX_REVIEW_FILE_BYTES = 25 * 1024 * 1024;
export const MAX_GRAPH_NODES = 5000;
export const MAX_GRAPH_OBSERVATIONS = 20000;
export const MAX_GRAPH_PROPOSALS = 5000;

const FORBIDDEN_KEYS = new Set(['__proto__', 'prototype', 'constructor']);
const SHA256_PATTERN = /^sha256:[a-f0-9]{64}$/;
const STABLE_ID_PATTERN = /^[a-z][a-z0-9-]{0,31}:[a-f0-9]{64}$/;
const DECIMAL_PATTERN = /^(0|[1-9][0-9]*)$/;
const SAFE_TOKEN_PATTERN = /^[A-Za-z][A-Za-z0-9_.:/-]{0,255}$/;
const SOURCE_NAME_PATTERN = /^[A-Za-z0-9][A-Za-z0-9_.:-]{0,255}$/;
const DATE_TIME_PATTERN = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?(?:Z|[+-]\d{2}:\d{2})$/;
const COVERAGE_STATUSES = new Set(['complete', 'incomplete', 'unavailable', 'degraded']);
export const POLICY_REVIEW_TARGETS = Object.freeze([
    'guard-ebpf',
    'cilium',
    'gateway-iptables',
    'gateway-pf',
    'gateway-ipfw',
    'gateway-ipfilter',
    'gateway-l7-proxy',
    'guard-nftables',
]);
const DEPLOYMENT_TARGETS = new Set(POLICY_REVIEW_TARGETS);
const DIFF_STATUSES = new Set([
    'unchanged',
    'added',
    'broadened',
    'removed',
    'coverage-degraded',
    'metric-only',
]);
const DISPOSITIONS = new Set(['accept', 'reject', 'needs-review']);
const TARGET_STATUSES = new Set([
    'exact',
    'restrictive',
    'conditional',
    'permissive',
    'unsupported',
    'outsideScope',
]);
const RECORD_ROLES = ['nodes', 'observations', 'coverage', 'findings', 'proposals', 'diff'];
const RECORD_KINDS = {
    nodes: 'NoshGraphNode',
    observations: 'NoshObservation',
    coverage: 'NoshCoverageMarker',
    findings: 'NoshFinding',
    proposals: 'NoshPolicyProposal',
    diff: 'NoshGraphDiff',
};

const isPlainObject = value => (
    value !== null
    && typeof value === 'object'
    && !Array.isArray(value)
    && (Object.getPrototypeOf(value) === Object.prototype || Object.getPrototypeOf(value) === null)
);

const assertPlainObject = (value, path) => {
    if (!isPlainObject(value)) {
        throw new Error(`${path} must be a JSON object`);
    }
};

const assertExactKeys = (value, path, required, optional = []) => {
    assertPlainObject(value, path);
    const allowed = new Set([...required, ...optional]);
    Object.keys(value).forEach(key => {
        if (!allowed.has(key)) {
            throw new Error(`${path}.${key} is not allowed`);
        }
    });
    required.forEach(key => {
        if (!Object.hasOwn(value, key)) {
            throw new Error(`${path}.${key} is required`);
        }
    });
};

const assertArray = (value, path, maximum) => {
    if (!Array.isArray(value)) {
        throw new Error(`${path} must be an array`);
    }
    if (value.length > maximum) {
        throw new Error(`${path} exceeds the ${maximum} record limit`);
    }
};

const utf8ByteLength = value => new TextEncoder().encode(value).byteLength;

const assertUnicodeScalarString = (value, path) => {
    for (let index = 0; index < value.length; index += 1) {
        const codeUnit = value.charCodeAt(index);
        if (codeUnit >= 0xd800 && codeUnit <= 0xdbff) {
            const next = value.charCodeAt(index + 1);
            if (next < 0xdc00 || next > 0xdfff) {
                throw new Error(`${path} contains an unpaired high surrogate`);
            }
            index += 1;
        } else if (codeUnit >= 0xdc00 && codeUnit <= 0xdfff) {
            throw new Error(`${path} contains an unpaired low surrogate`);
        }
    }
};

const assertString = (value, path, {
    allowEmpty = false,
    maximum = 16 * 1024,
    pattern,
} = {}) => {
    if (typeof value !== 'string' || (!allowEmpty && !value.trim())) {
        throw new Error(`${path} must be a ${allowEmpty ? '' : 'non-empty '}string`);
    }
    assertUnicodeScalarString(value, path);
    if (utf8ByteLength(value) > maximum || value.includes('\0')) {
        throw new Error(`${path} exceeds its safe string bounds`);
    }
    if (pattern && !pattern.test(value)) {
        throw new Error(`${path} has an invalid format`);
    }
};

const assertSafeToken = (value, path) => {
    assertString(value, path, { maximum: 256, pattern: SAFE_TOKEN_PATTERN });
};

const assertDateTime = (value, path) => {
    assertString(value, path, { maximum: 64, pattern: DATE_TIME_PATTERN });
    parseRfc3339Timestamp(value, path);
};

const assertDigest = (value, path) => {
    if (typeof value !== 'string' || !SHA256_PATTERN.test(value)) {
        throw new Error(`${path} must be a sha256 digest`);
    }
};

const assertStableId = (value, path) => {
    if (typeof value !== 'string' || !STABLE_ID_PATTERN.test(value)) {
        throw new Error(`${path} must be a namespaced stable ID`);
    }
};

const assertDecimal = (value, path) => {
    if (typeof value !== 'string' || !DECIMAL_PATTERN.test(value)) {
        throw new Error(`${path} must be an unsigned decimal string`);
    }
};

const assertSafeJsonValue = (value, path = '$', depth = 0, budget = { records: 0 }) => {
    if (depth > 16) {
        throw new Error(`${path} exceeds the maximum nesting depth`);
    }
    if (value === null || typeof value === 'boolean') {
        return;
    }
    if (typeof value === 'string') {
        assertString(value, path, { allowEmpty: true });
        return;
    }
    if (typeof value === 'number') {
        if (!Number.isFinite(value) || (Number.isInteger(value) && !Number.isSafeInteger(value))) {
            throw new Error(`${path} contains an unsafe JSON number`);
        }
        return;
    }
    if (Array.isArray(value)) {
        if (value.length > 50000) {
            throw new Error(`${path} contains too many array entries`);
        }
        value.forEach((entry, index) => assertSafeJsonValue(entry, `${path}[${index}]`, depth + 1, budget));
        return;
    }
    assertPlainObject(value, path);
    budget.records += 1;
    if (budget.records > 250000 || Object.keys(value).length > 256) {
        throw new Error(`${path} exceeds the JSON object budget`);
    }
    Object.entries(value).forEach(([key, entry]) => {
        if (FORBIDDEN_KEYS.has(key)) {
            throw new Error(`${path} contains forbidden key ${key}`);
        }
        assertSafeJsonValue(entry, `${path}.${key}`, depth + 1, budget);
    });
};

const assertIdArray = (value, path, maximum = 256) => {
    assertArray(value, path, maximum);
    const seen = new Set();
    value.forEach((id, index) => {
        assertStableId(id, `${path}[${index}]`);
        if (seen.has(id)) {
            throw new Error(`${path} contains a duplicate ID`);
        }
        seen.add(id);
    });
};

const assertSortedUniqueStrings = (value, path, maximum = 256) => {
    assertArray(value, path, maximum);
    const seen = new Set();
    let previous = null;
    value.forEach((entry, index) => {
        assertString(entry, `${path}[${index}]`, { maximum: 8192 });
        if (seen.has(entry)) {
            throw new Error(`${path} contains a duplicate value`);
        }
        if (previous !== null && previous > entry) {
            throw new Error(`${path} must be sorted`);
        }
        seen.add(entry);
        previous = entry;
    });
};

const assertPrivacy = (privacy, path) => {
    assertExactKeys(privacy, path, ['classification', 'fields']);
    if (!['portable', 'portable-sensitive', 'private'].includes(privacy.classification)) {
        throw new Error(`${path}.classification is not supported`);
    }
    assertArray(privacy.fields, `${path}.fields`, 256);
};

const validateRecordHeader = (record, kind, path) => {
    if (record.apiVersion !== API_VERSION || record.kind !== kind || record.schemaVersion !== 1) {
        throw new Error(`${path} has an invalid semantic record header`);
    }
    assertStableId(record.id, `${path}.id`);
    assertDigest(record.scopeDigest, `${path}.scopeDigest`);
    assertPrivacy(record.privacy, `${path}.privacy`);
};

const validateNode = (record, index) => {
    const path = `$.nodes[${index}]`;
    assertExactKeys(record, path, [
        'apiVersion', 'kind', 'schemaVersion', 'id', 'scopeDigest', 'nodeType', 'label',
        'identity', 'properties', 'evidenceRefs', 'privacy',
    ]);
    validateRecordHeader(record, RECORD_KINDS.nodes, path);
    assertString(record.nodeType, `${path}.nodeType`, { maximum: 128 });
    assertString(record.label, `${path}.label`, { maximum: 512 });
    assertPlainObject(record.identity, `${path}.identity`);
    if (!Object.keys(record.identity).length) {
        throw new Error(`${path}.identity must not be empty`);
    }
    assertPlainObject(record.properties, `${path}.properties`);
    assertIdArray(record.evidenceRefs, `${path}.evidenceRefs`);
};

const validateObservation = (record, index) => {
    const path = `$.observations[${index}]`;
    assertExactKeys(record, path, [
        'apiVersion', 'kind', 'schemaVersion', 'id', 'scopeDigest', 'observationType',
        'subjectId', 'objectId', 'basis', 'confidence', 'count', 'evidenceRefs',
        'properties', 'privacy',
    ], ['algorithm', 'firstObservedAt', 'lastObservedAt']);
    validateRecordHeader(record, RECORD_KINDS.observations, path);
    assertString(record.observationType, `${path}.observationType`, { maximum: 128 });
    assertStableId(record.subjectId, `${path}.subjectId`);
    assertStableId(record.objectId, `${path}.objectId`);
    if (!['observed', 'correlated', 'inferred'].includes(record.basis)) {
        throw new Error(`${path}.basis is not supported`);
    }
    if (!Number.isInteger(record.confidence) || record.confidence < 0 || record.confidence > 100) {
        throw new Error(`${path}.confidence must be an integer from 0 through 100`);
    }
    assertDecimal(record.count, `${path}.count`);
    assertIdArray(record.evidenceRefs, `${path}.evidenceRefs`);
    assertPlainObject(record.properties, `${path}.properties`);
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
        throw new Error(`${path} observation time range is reversed`);
    }
};

const validateCoverage = (record, index) => {
    const path = `$.coverage[${index}]`;
    assertExactKeys(record, path, [
        'apiVersion', 'kind', 'schemaVersion', 'id', 'scopeDigest', 'domain', 'status',
        'sourceIds', 'counters', 'gaps', 'blocking', 'privacy',
    ]);
    validateRecordHeader(record, RECORD_KINDS.coverage, path);
    assertString(record.domain, `${path}.domain`, { maximum: 128 });
    if (!COVERAGE_STATUSES.has(record.status)) {
        throw new Error(`${path}.status is not supported`);
    }
    assertIdArray(record.sourceIds, `${path}.sourceIds`);
    assertPlainObject(record.counters, `${path}.counters`);
    Object.entries(record.counters).forEach(([key, value]) => assertDecimal(value, `${path}.counters.${key}`));
    assertArray(record.gaps, `${path}.gaps`, 256);
    record.gaps.forEach((gap, gapIndex) => assertString(gap, `${path}.gaps[${gapIndex}]`, { maximum: 8192 }));
    if (typeof record.blocking !== 'boolean') {
        throw new Error(`${path}.blocking must be a boolean`);
    }
};

const validateFinding = (record, index) => {
    const path = `$.findings[${index}]`;
    assertExactKeys(record, path, [
        'apiVersion', 'kind', 'schemaVersion', 'id', 'scopeDigest', 'findingType',
        'severity', 'blocking', 'message', 'semanticRefs', 'evidenceRefs', 'properties', 'privacy',
    ]);
    validateRecordHeader(record, RECORD_KINDS.findings, path);
    assertString(record.findingType, `${path}.findingType`, { maximum: 128 });
    if (!['info', 'low', 'medium', 'high', 'critical'].includes(record.severity)) {
        throw new Error(`${path}.severity is not supported`);
    }
    if (typeof record.blocking !== 'boolean') {
        throw new Error(`${path}.blocking must be a boolean`);
    }
    assertString(record.message, `${path}.message`, { maximum: 8192 });
    assertIdArray(record.semanticRefs, `${path}.semanticRefs`);
    assertIdArray(record.evidenceRefs, `${path}.evidenceRefs`);
    assertPlainObject(record.properties, `${path}.properties`);
};

const validateProposal = (record, index) => {
    const path = `$.proposals[${index}]`;
    assertExactKeys(record, path, [
        'apiVersion', 'kind', 'schemaVersion', 'id', 'scopeDigest', 'scopeClass',
        'proposalType', 'intent', 'baselineState', 'rationale', 'evidenceRefs',
        'targetFeasibility', 'privacy',
    ], ['observationRefs']);
    validateRecordHeader(record, RECORD_KINDS.proposals, path);
    if (!['build', 'runtime'].includes(record.scopeClass)) {
        throw new Error(`${path}.scopeClass is not supported`);
    }
    assertString(record.proposalType, `${path}.proposalType`, { maximum: 128 });
    assertPlainObject(record.intent, `${path}.intent`);
    if (!['new', 'broadened', 'unchanged', 'removed'].includes(record.baselineState)) {
        throw new Error(`${path}.baselineState is not supported`);
    }
    assertString(record.rationale, `${path}.rationale`, { maximum: 8192 });
    assertIdArray(record.evidenceRefs, `${path}.evidenceRefs`);
    if (Object.hasOwn(record, 'observationRefs')) {
        assertIdArray(record.observationRefs, `${path}.observationRefs`);
    }
    assertArray(record.targetFeasibility, `${path}.targetFeasibility`, POLICY_REVIEW_TARGETS.length);
    const feasibilityTargets = new Set();
    let previousFeasibilityTarget = null;
    record.targetFeasibility.forEach((target, targetIndex) => {
        const targetPath = `${path}.targetFeasibility[${targetIndex}]`;
        assertExactKeys(target, targetPath, ['target', 'status', 'reasons']);
        if (!POLICY_REVIEW_TARGETS.includes(target.target)) {
            throw new Error(`${targetPath}.target is not supported`);
        }
        if (!TARGET_STATUSES.has(target.status)) {
            throw new Error(`${targetPath}.status is not supported`);
        }
        assertSortedUniqueStrings(target.reasons, `${targetPath}.reasons`, 64);
        target.reasons.forEach((reason, reasonIndex) => {
            assertString(reason, `${targetPath}.reasons[${reasonIndex}]`, { maximum: 8192 });
        });
        if (feasibilityTargets.has(target.target)) {
            throw new Error(`${path}.targetFeasibility contains duplicate targets`);
        }
        if (previousFeasibilityTarget !== null && previousFeasibilityTarget > target.target) {
            throw new Error(`${path}.targetFeasibility must be sorted by target`);
        }
        feasibilityTargets.add(target.target);
        previousFeasibilityTarget = target.target;
    });
};

const validateDiff = (record, index) => {
    const path = `$.diff[${index}]`;
    assertExactKeys(record, path, [
        'apiVersion', 'kind', 'schemaVersion', 'id', 'scopeDigest', 'entityId',
        'changeType', 'beforeDigest', 'afterDigest', 'policyRelevant', 'summary',
        'evidenceRefs', 'privacy',
    ]);
    validateRecordHeader(record, RECORD_KINDS.diff, path);
    assertStableId(record.entityId, `${path}.entityId`);
    if (!DIFF_STATUSES.has(record.changeType)) {
        throw new Error(`${path}.changeType is not supported`);
    }
    ['beforeDigest', 'afterDigest'].forEach(key => {
        if (record[key] !== null) {
            assertDigest(record[key], `${path}.${key}`);
        }
    });
    if (typeof record.policyRelevant !== 'boolean') {
        throw new Error(`${path}.policyRelevant must be a boolean`);
    }
    assertString(record.summary, `${path}.summary`, { maximum: 8192 });
    assertIdArray(record.evidenceRefs, `${path}.evidenceRefs`);
};

const recordValidators = {
    nodes: validateNode,
    observations: validateObservation,
    coverage: validateCoverage,
    findings: validateFinding,
    proposals: validateProposal,
    diff: validateDiff,
};

const validateSource = (source, index) => {
    const path = `$.sources[${index}]`;
    assertExactKeys(source, path, ['id', 'artifactKind', 'artifactDigest', 'coverage'], [
        'sourceType',
        'runId',
        'sourceName',
        'sourceDigest',
        'observedFrom',
        'observedTo',
    ]);
    assertStableId(source.id, `${path}.id`);
    assertSafeToken(source.artifactKind, `${path}.artifactKind`);
    assertDigest(source.artifactDigest, `${path}.artifactDigest`);
    if (Object.hasOwn(source, 'sourceType')) {
        assertSafeToken(source.sourceType, `${path}.sourceType`);
    }
    ['runId', 'sourceName'].forEach(key => {
        if (Object.hasOwn(source, key)) {
            assertString(source[key], `${path}.${key}`, {
                maximum: 256,
                pattern: SOURCE_NAME_PATTERN,
            });
        }
    });
    if (Object.hasOwn(source, 'sourceDigest')) {
        assertDigest(source.sourceDigest, `${path}.sourceDigest`);
    }
    const hasObservedFrom = Object.hasOwn(source, 'observedFrom');
    const hasObservedTo = Object.hasOwn(source, 'observedTo');
    if (hasObservedFrom !== hasObservedTo) {
        throw new Error(`${path}.observedFrom and observedTo must be supplied together`);
    }
    if (hasObservedFrom) {
        assertDateTime(source.observedFrom, `${path}.observedFrom`);
        assertDateTime(source.observedTo, `${path}.observedTo`);
        if (Date.parse(source.observedFrom) > Date.parse(source.observedTo)) {
            throw new Error(`${path} observation time range is reversed`);
        }
    }
    assertExactKeys(source.coverage, `${path}.coverage`, ['status', 'lostEvents', 'parseErrors', 'gaps']);
    if (!COVERAGE_STATUSES.has(source.coverage.status)) {
        throw new Error(`${path}.coverage.status is not supported`);
    }
    assertDecimal(source.coverage.lostEvents, `${path}.coverage.lostEvents`);
    assertDecimal(source.coverage.parseErrors, `${path}.coverage.parseErrors`);
    assertSortedUniqueStrings(source.coverage.gaps, `${path}.coverage.gaps`);
    if (
        source.coverage.status === 'complete'
        && (
            source.coverage.lostEvents !== '0'
            || source.coverage.parseErrors !== '0'
            || source.coverage.gaps.length > 0
        )
    ) {
        throw new Error(`${path}.coverage complete status cannot contain loss, parse errors, or gaps`);
    }
    if (source.coverage.status !== 'complete' && source.coverage.gaps.length === 0) {
        throw new Error(`${path}.coverage.gaps must explain non-complete coverage`);
    }
};

const assertUniqueIds = (records, path) => {
    const ids = new Set();
    records.forEach(record => {
        if (ids.has(record.id)) {
            throw new Error(`${path} contains duplicate id ${record.id}`);
        }
        ids.add(record.id);
    });
    return ids;
};

const validateLiveDeltaState = (state, sourceIds) => {
    assertExactKeys(state, '$.liveDeltaState', [
        'sequence', 'lastDeltaDigest', 'sourceWatermarks',
    ]);
    assertDecimal(state.sequence, '$.liveDeltaState.sequence');
    if (state.lastDeltaDigest !== null) {
        assertDigest(state.lastDeltaDigest, '$.liveDeltaState.lastDeltaDigest');
    }
    if ((state.sequence === '0') !== (state.lastDeltaDigest === null)) {
        throw new Error('$.liveDeltaState sequence and lastDeltaDigest are inconsistent');
    }
    assertArray(state.sourceWatermarks, '$.liveDeltaState.sourceWatermarks', 1024);
    let previousSourceId = null;
    const seen = new Set();
    state.sourceWatermarks.forEach((watermark, index) => {
        const path = `$.liveDeltaState.sourceWatermarks[${index}]`;
        assertExactKeys(watermark, path, ['sourceId', 'sequence', 'observedAt']);
        assertStableId(watermark.sourceId, `${path}.sourceId`);
        assertDecimal(watermark.sequence, `${path}.sequence`);
        if (watermark.observedAt !== null) {
            assertDateTime(watermark.observedAt, `${path}.observedAt`);
        }
        if (!sourceIds.has(watermark.sourceId)) {
            throw new Error(`${path}.sourceId is not present in the live graph`);
        }
        if (seen.has(watermark.sourceId) || (previousSourceId && previousSourceId > watermark.sourceId)) {
            throw new Error('$.liveDeltaState.sourceWatermarks must be sorted and unique');
        }
        seen.add(watermark.sourceId);
        previousSourceId = watermark.sourceId;
    });
};

const validateViewerGraph = (value, { allowLive = false } = {}) => {
    assertSafeJsonValue(value);
    assertExactKeys(value, '$', [
        'apiVersion', 'kind', 'schemaVersion', 'graphId', 'revision', 'graphDigest',
        'proposalSetDigest', 'basePolicyDigest', 'scope', 'sources', ...RECORD_ROLES, 'frozen',
    ], allowLive ? ['importAdapter', 'contentDigest', 'liveDeltaState'] : ['contentDigest']);
    if (value.apiVersion !== API_VERSION || value.kind !== GRAPH_KIND || value.schemaVersion !== 1) {
        throw new Error(`Graph must be ${API_VERSION} ${GRAPH_KIND} schemaVersion 1`);
    }
    assertStableId(value.graphId, '$.graphId');
    assertDigest(value.revision, '$.revision');
    assertDigest(value.graphDigest, '$.graphDigest');
    assertDigest(value.proposalSetDigest, '$.proposalSetDigest');
    assertDigest(value.basePolicyDigest, '$.basePolicyDigest');
    assertPlainObject(value.scope, '$.scope');
    if (!['build', 'runtime'].includes(value.scope.class)) {
        throw new Error('$.scope.class must be build or runtime');
    }
    assertStableId(value.scope.subjectId, '$.scope.subjectId');
    assertDigest(value.scope.scopeDigest, '$.scope.scopeDigest');
    if (typeof value.frozen !== 'boolean' || (!allowLive && !value.frozen)) {
        throw new Error('$.frozen must be true for a canonical materialized graph');
    }
    if (value.frozen && !Object.hasOwn(value, 'contentDigest')) {
        throw new Error('$.contentDigest is required for a frozen materialized graph');
    }
    if (Object.hasOwn(value, 'contentDigest')) {
        assertDigest(value.contentDigest, '$.contentDigest');
    }
    assertArray(value.sources, '$.sources', 1024);
    value.sources.forEach(validateSource);
    assertUniqueIds(value.sources, '$.sources');
    value.sources.forEach((source, index) => {
        if (index > 0 && value.sources[index - 1].id > source.id) {
            throw new Error('$.sources must be sorted by source ID');
        }
    });
    if (!value.frozen) {
        if (!Object.hasOwn(value, 'liveDeltaState')) {
            throw new Error('$.liveDeltaState is required for a live graph');
        }
        validateLiveDeltaState(value.liveDeltaState, new Set(value.sources.map(source => source.id)));
    } else if (Object.hasOwn(value, 'liveDeltaState')) {
        throw new Error('$.liveDeltaState is not allowed on a frozen graph');
    }

    RECORD_ROLES.forEach(role => {
        const maximum = role === 'observations' ? MAX_GRAPH_OBSERVATIONS
            : role === 'proposals' ? MAX_GRAPH_PROPOSALS : MAX_GRAPH_NODES;
        assertArray(value[role], `$.${role}`, maximum);
        value[role].forEach(recordValidators[role]);
        assertUniqueIds(value[role], `$.${role}`);
        value[role].forEach(record => {
            if (record.scopeDigest !== value.scope.scopeDigest) {
                throw new Error(`${role} record ${record.id} belongs to another scope`);
            }
        });
    });
    const nodeIds = new Set(value.nodes.map(node => node.id));
    value.observations.forEach(observation => {
        if (!nodeIds.has(observation.subjectId) || !nodeIds.has(observation.objectId)) {
            throw new Error(`observation ${observation.id} references a missing node`);
        }
    });
    value.proposals.forEach(proposal => {
        if (!nodeIds.has(proposal.intent.subjectId)) {
            throw new Error(`proposal ${proposal.id} references a missing subject node`);
        }
    });
    const observationIds = new Set(value.observations.map(observation => observation.id));
    value.proposals.forEach(proposal => {
        (proposal.observationRefs || []).forEach(observationId => {
            if (!observationIds.has(observationId)) {
                throw new Error(
                    `proposal ${proposal.id} references a missing observation ${observationId}`,
                );
            }
        });
    });
    return value;
};

export const validateSemanticGraph = value => validateViewerGraph(value);

export const computeSemanticGraphContentDigest = async graph => {
    const { contentDigest, ...payload } = graph;
    return browserSha256Digest(payload);
};

export const verifySemanticGraphContentDigest = async value => {
    const graph = validateSemanticGraph(value);
    const expected = await computeSemanticGraphContentDigest(graph);
    if (graph.contentDigest !== expected) {
        throw new Error('$.contentDigest does not match the materialized graph');
    }
    return graph;
};

export const parseSemanticGraphJson = async text => {
    if (typeof text !== 'string' || !text.trim() || utf8ByteLength(text) > MAX_REVIEW_FILE_BYTES) {
        throw new Error('Graph JSON is empty or exceeds the review limit');
    }
    let value;
    try {
        value = JSON.parse(text);
    } catch (error) {
        throw new Error(`Graph JSON could not be parsed: ${error.message}`);
    }
    return verifySemanticGraphContentDigest(value);
};

export const fetchSemanticGraphUrl = async (input, {
    fetchImpl = globalThis.fetch,
    attestedGraphOrigin = null,
} = {}) => {
    const url = new URL(normalizeManagedReviewGraphUrl(input, { attestedGraphOrigin }));
    if (typeof fetchImpl !== 'function') {
        throw new Error('This browser does not provide fetch');
    }
    const response = await fetchImpl(url.href, {
        method: 'GET',
        credentials: 'omit',
        cache: 'no-store',
        redirect: 'error',
        referrerPolicy: 'no-referrer',
        headers: { Accept: 'application/json' },
    });
    if (!response?.ok) {
        throw new Error(`Graph URL returned HTTP ${response?.status || 'error'}`);
    }
    const advertisedBytes = Number(response.headers?.get?.('content-length'));
    if (Number.isFinite(advertisedBytes) && advertisedBytes > MAX_REVIEW_FILE_BYTES) {
        throw new Error('Graph URL response exceeds the review limit');
    }
    if (typeof response.text !== 'function') {
        throw new Error('Graph URL response does not contain text');
    }
    return parseSemanticGraphJson(await response.text());
};

export const normalizeLoopbackReviewGraphUrl = normalizeManagedReviewGraphUrl;

const stableToken = value => {
    const input = String(value);
    let hash = 2166136261;
    for (let index = 0; index < input.length; index += 1) {
        hash ^= input.charCodeAt(index);
        hash = Math.imul(hash, 16777619);
    }
    return (hash >>> 0).toString(16).padStart(8, '0');
};

const localHex = value => Array.from({ length: 8 }, (_, index) => stableToken(`${index}|${value}`)).join('');
const localDigest = value => `sha256:${localHex(value)}`;
const localId = (namespace, value) => `${namespace}:${localHex(value)}`;
const portableSensitive = () => ({ classification: 'portable-sensitive', fields: [] });

const getHubbleEndpoint = (endpoint, ip, role, scopeDigest, sourceId) => {
    const namespace = String(endpoint?.namespace || '').trim();
    const workloads = Array.isArray(endpoint?.workloads) ? endpoint.workloads : [];
    const workload = String(workloads[0]?.name || endpoint?.pod_name || '').trim();
    const address = String(ip || '').trim();
    const identityLabel = workload || address || `${role}-unknown`;
    const identityKey = `${namespace}|${identityLabel}`;
    return {
        apiVersion: API_VERSION,
        kind: RECORD_KINDS.nodes,
        schemaVersion: 1,
        id: localId(workload ? 'workload' : 'endpoint', identityKey),
        scopeDigest,
        nodeType: workload ? 'workload' : 'networkEndpoint',
        label: namespace ? `${namespace}/${identityLabel}` : identityLabel,
        identity: { namespace, workload, address },
        properties: {
            labels: Array.isArray(endpoint?.labels) ? endpoint.labels.slice(0, 100) : [],
            importRole: role,
        },
        evidenceRefs: [sourceId],
        privacy: portableSensitive(),
    };
};

const resolveHubbleTransport = flow => {
    const tcp = flow?.l4?.TCP || flow?.l4?.tcp;
    const udp = flow?.l4?.UDP || flow?.l4?.udp;
    if (tcp) {
        return { protocol: 'tcp', port: Number(tcp.destination_port || tcp.destinationPort || 0) };
    }
    if (udp) {
        return { protocol: 'udp', port: Number(udp.destination_port || udp.destinationPort || 0) };
    }
    if (flow?.l4?.ICMPv4 || flow?.l4?.icmpv4) {
        return { protocol: 'icmp', port: 0 };
    }
    return { protocol: null, port: 0 };
};

const isIpv4 = value => {
    const parts = String(value).split('.');
    return parts.length === 4 && parts.every(part => /^\d{1,3}$/.test(part) && Number(part) <= 255);
};

export const parseHubbleJsonLines = text => {
    if (typeof text !== 'string' || !text.trim() || text.length > MAX_REVIEW_FILE_BYTES) {
        throw new Error('Hubble JSONL is empty or exceeds the review limit');
    }
    const lines = text.split(/\r?\n/).filter(line => line.trim());
    if (lines.length > 50000) {
        throw new Error('Hubble JSONL exceeds the 50000 record limit');
    }

    const graphKey = stableToken(text);
    const scopeDigest = localDigest(`scope:${graphKey}`);
    const sourceId = localId('source', graphKey);
    const nodes = new Map();
    const observations = new Map();
    const proposals = new Map();
    let observedFrom = null;
    let observedTo = null;
    let untimedRecords = 0;
    lines.forEach((line, lineIndex) => {
        let record;
        try {
            record = JSON.parse(line);
        } catch (error) {
            throw new Error(`Hubble line ${lineIndex + 1} is invalid JSON: ${error.message}`);
        }
        assertSafeJsonValue(record, `$hubble[${lineIndex}]`);
        const flow = record?.flow || record;
        assertPlainObject(flow, `$hubble[${lineIndex}].flow`);
        const observedAt = flow.time ?? record?.time ?? null;
        if (observedAt !== null && observedAt !== '') {
            assertDateTime(observedAt, `$hubble[${lineIndex}].time`);
            observedFrom = observedFrom === null || Date.parse(observedAt) < Date.parse(observedFrom)
                ? observedAt
                : observedFrom;
            observedTo = observedTo === null || Date.parse(observedAt) > Date.parse(observedTo)
                ? observedAt
                : observedTo;
        } else {
            untimedRecords += 1;
        }
        const sourceIp = flow?.IP?.source || flow?.ip?.source || '';
        const destinationIp = flow?.IP?.destination || flow?.ip?.destination || '';
        const source = getHubbleEndpoint(flow.source, sourceIp, 'source', scopeDigest, sourceId);
        const destination = getHubbleEndpoint(flow.destination, destinationIp, 'destination', scopeDigest, sourceId);
        nodes.set(source.id, source);
        nodes.set(destination.id, destination);

        const { protocol, port } = resolveHubbleTransport(flow);
        const verdict = String(flow.verdict || 'UNKNOWN').toUpperCase();
        const direction = String(flow.traffic_direction || 'EGRESS').toLowerCase() === 'ingress'
            ? 'ingress'
            : 'egress';
        const subject = direction === 'ingress' ? destination : source;
        const peer = direction === 'ingress' ? source : destination;
        const peerIp = direction === 'ingress' ? sourceIp : destinationIp;
        const relationKey = `${direction}|${subject.id}|${peer.id}|${protocol}|${port}|${verdict}`;
        const observationId = localId('observation', relationKey);
        const prior = observations.get(observationId);
        const timedRecords = Number(prior?.properties?.timedRecords || 0) + (observedAt ? 1 : 0);
        const relationUntimedRecords = Number(prior?.properties?.untimedRecords || 0) + (observedAt ? 0 : 1);
        const firstObservedAt = observedAt && (
            !prior?.firstObservedAt || Date.parse(observedAt) < Date.parse(prior.firstObservedAt)
        )
            ? observedAt
            : prior?.firstObservedAt;
        const lastObservedAt = observedAt && (
            !prior?.lastObservedAt || Date.parse(observedAt) > Date.parse(prior.lastObservedAt)
        )
            ? observedAt
            : prior?.lastObservedAt;
        observations.set(observationId, {
            apiVersion: API_VERSION,
            kind: RECORD_KINDS.observations,
            schemaVersion: 1,
            id: observationId,
            scopeDigest,
            observationType: 'connects',
            subjectId: subject.id,
            objectId: peer.id,
            basis: 'observed',
            confidence: 100,
            count: String(Number(prior?.count || 0) + 1),
            evidenceRefs: [sourceId],
            properties: {
                protocol: protocol || 'unknown',
                destinationPort: String(port),
                verdict,
                trafficDirection: direction,
                timedRecords: String(timedRecords),
                untimedRecords: String(relationUntimedRecords),
            },
            ...(firstObservedAt ? { firstObservedAt, lastObservedAt } : {}),
            privacy: portableSensitive(),
        });

        const canPropose = ['FORWARDED', 'DROPPED'].includes(verdict)
            && protocol
            && isIpv4(peerIp)
            && (['icmp', 'icmpv6'].includes(protocol)
                || (Number.isInteger(port) && port > 0 && port <= 65535));
        if (canPropose) {
            const proposalId = localId('proposal', `${direction}|${subject.id}|${peer.id}|${protocol}|${port}`);
            const priorProposal = proposals.get(proposalId);
            const observationRefs = [...new Set([
                ...(priorProposal?.observationRefs || []),
                observationId,
            ])].sort();
            proposals.set(proposalId, {
                apiVersion: API_VERSION,
                kind: RECORD_KINDS.proposals,
                schemaVersion: 1,
                id: proposalId,
                scopeDigest,
                scopeClass: 'runtime',
                proposalType: `network-${direction}`,
                intent: {
                    domain: 'network',
                    subjectId: subject.id,
                    effect: 'allow',
                    direction,
                    peer: { kind: 'ipv4', value: String(peerIp) },
                    transport: {
                        protocol,
                        ports: ['icmp', 'icmpv6'].includes(protocol) ? [] : [port],
                    },
                    constraints: { observedVerdict: verdict },
                },
                baselineState: 'new',
                rationale: `${protocol.toUpperCase()}${port ? `/${port}` : ''} ${verdict.toLowerCase()} flow imported from live Hubble data`,
                evidenceRefs: observationRefs,
                observationRefs,
                targetFeasibility: [
                    { target: 'cilium', status: 'conditional', reasons: ['live import is not a frozen Guard snapshot'] },
                    { target: 'gateway-iptables', status: 'conditional', reasons: ['live import is not a frozen Guard snapshot'] },
                    { target: 'guard-ebpf', status: 'conditional', reasons: ['live import is not a frozen Guard snapshot'] },
                    { target: 'guard-nftables', status: 'conditional', reasons: ['live import is not a frozen Guard snapshot'] },
                ],
                privacy: portableSensitive(),
            });
        }
    });

    const coverageId = localId('coverage', graphKey);
    const findingId = localId('finding', graphKey);
    const diff = [
        ...[...nodes.values()].map(node => ({
            apiVersion: API_VERSION,
            kind: RECORD_KINDS.diff,
            schemaVersion: 1,
            id: localId('diff', node.id),
            scopeDigest,
            entityId: node.id,
            changeType: 'added',
            beforeDigest: null,
            afterDigest: localDigest(node.id),
            policyRelevant: node.nodeType === 'networkEndpoint' || node.nodeType === 'workload',
            summary: `${node.label} was observed in the live import`,
            evidenceRefs: [sourceId],
            privacy: portableSensitive(),
        })),
        ...[...proposals.values()].map(proposal => ({
            apiVersion: API_VERSION,
            kind: RECORD_KINDS.diff,
            schemaVersion: 1,
            id: localId('diff', proposal.id),
            scopeDigest,
            entityId: proposal.id,
            changeType: 'added',
            beforeDigest: null,
            afterDigest: localDigest(proposal.id),
            policyRelevant: true,
            summary: 'Live traffic produced a preview-only policy proposal',
            evidenceRefs: proposal.evidenceRefs,
            privacy: portableSensitive(),
        })),
    ];
    const graphDigest = localDigest(`graph:${graphKey}`);
    const sourceGaps = [
        'browser import is not a finalized, Guard-verified capture',
        ...(untimedRecords ? [`${untimedRecords} imported record(s) had no flow timestamp`] : []),
    ].sort();
    return validateViewerGraph({
        apiVersion: API_VERSION,
        kind: GRAPH_KIND,
        schemaVersion: 1,
        graphId: localId('graph', graphDigest),
        revision: localDigest(`revision:${graphKey}`),
        graphDigest,
        proposalSetDigest: localDigest(`proposals:${graphKey}`),
        basePolicyDigest: localDigest('unbound-live-base-policy'),
        scope: {
            class: 'runtime',
            subjectId: localId('subject', 'hubble-import'),
            scopeDigest,
            projectKey: localHex('hubble-import'),
            platform: 'linux/amd64',
            target: null,
        },
        sources: [{
            id: sourceId,
            artifactKind: 'HubbleJsonLinesImport',
            artifactDigest: localDigest(text),
            ...(observedFrom ? { observedFrom, observedTo } : {}),
            coverage: {
                status: 'degraded',
                lostEvents: '0',
                parseErrors: '0',
                gaps: sourceGaps,
            },
        }],
        nodes: [...nodes.values()],
        observations: [...observations.values()],
        coverage: [{
            apiVersion: API_VERSION,
            kind: RECORD_KINDS.coverage,
            schemaVersion: 1,
            id: coverageId,
            scopeDigest,
            domain: 'hubble',
            status: 'degraded',
            sourceIds: [sourceId],
            counters: {
                importedRecords: String(lines.length),
                untimedRecords: String(untimedRecords),
            },
            gaps: [
                'browser import is live and lacks a signed completion manifest',
                ...(untimedRecords ? [`${untimedRecords} imported record(s) had no flow timestamp`] : []),
            ].sort(),
            blocking: true,
            privacy: portableSensitive(),
        }],
        findings: [{
            apiVersion: API_VERSION,
            kind: RECORD_KINDS.findings,
            schemaVersion: 1,
            id: findingId,
            scopeDigest,
            findingType: 'unresolved-evidence',
            severity: 'info',
            blocking: true,
            message: 'Freeze and verify this capture with Nosh Guard before approval.',
            semanticRefs: [],
            evidenceRefs: [sourceId],
            properties: { importAdapter: 'hubble-jsonl/v1' },
            privacy: portableSensitive(),
        }],
        proposals: [...proposals.values()],
        diff,
        frozen: false,
        importAdapter: 'hubble-jsonl/v1',
        liveDeltaState: {
            sequence: '0',
            lastDeltaDigest: null,
            sourceWatermarks: [],
        },
    }, { allowLive: true });
};

const validateDeltaRecord = (role, record, path) => {
    const originalPath = `$.$delta.${role}`;
    try {
        recordValidators[role](record, 0);
    } catch (error) {
        throw new Error(error.message.replace(`$.${role}[0]`, path).replace(originalPath, path));
    }
};

export const computeSemanticRecordDigest = async record => browserSha256Digest(record);

export const computeSemanticGraphDeltaDigest = async delta => {
    const { deltaDigest, ...payload } = delta;
    return browserSha256Digest(payload);
};

const compareDecimal = (left, right) => (
    left.length !== right.length
        ? left.length - right.length
        : left.localeCompare(right)
);

const incrementDecimal = value => {
    const digits = value.split('');
    for (let index = digits.length - 1; index >= 0; index -= 1) {
        if (digits[index] !== '9') {
            digits[index] = String(Number(digits[index]) + 1);
            return digits.join('');
        }
        digits[index] = '0';
    }
    return `1${digits.join('')}`;
};

export const parseSemanticGraphDelta = async text => {
    if (typeof text !== 'string' || !text.trim() || utf8ByteLength(text) > MAX_REVIEW_FILE_BYTES) {
        throw new Error('Graph delta JSON is empty or exceeds the review limit');
    }
    let value;
    try {
        value = JSON.parse(text);
    } catch (error) {
        throw new Error(`Graph delta JSON could not be parsed: ${error.message}`);
    }
    assertSafeJsonValue(value);
    assertExactKeys(value, '$', [
        'apiVersion', 'kind', 'schemaVersion', 'graphId', 'baseRevision', 'scopeDigest',
        'sequence', 'previousDeltaDigest', 'createdAt', 'sourceWatermarks', 'operations',
        'frozen', 'deltaDigest',
    ]);
    if (value.apiVersion !== API_VERSION || value.kind !== DELTA_KIND || value.schemaVersion !== 1) {
        throw new Error(`Delta must be ${API_VERSION} ${DELTA_KIND} schemaVersion 1`);
    }
    assertStableId(value.graphId, '$.graphId');
    assertDigest(value.baseRevision, '$.baseRevision');
    assertDigest(value.scopeDigest, '$.scopeDigest');
    assertDecimal(value.sequence, '$.sequence');
    if (value.sequence === '0') {
        throw new Error('$.sequence must be greater than zero');
    }
    if (value.previousDeltaDigest !== null) {
        assertDigest(value.previousDeltaDigest, '$.previousDeltaDigest');
    }
    if ((value.sequence === '1') !== (value.previousDeltaDigest === null)) {
        throw new Error('$.previousDeltaDigest must be null only for the first delta');
    }
    assertDateTime(value.createdAt, '$.createdAt');
    assertArray(value.sourceWatermarks, '$.sourceWatermarks', 1024);
    const watermarkIds = new Set();
    let previousSourceId = null;
    value.sourceWatermarks.forEach((watermark, index) => {
        const path = `$.sourceWatermarks[${index}]`;
        assertExactKeys(watermark, path, ['sourceId', 'sequence', 'observedAt']);
        assertStableId(watermark.sourceId, `${path}.sourceId`);
        assertDecimal(watermark.sequence, `${path}.sequence`);
        if (watermark.observedAt !== null) {
            assertDateTime(watermark.observedAt, `${path}.observedAt`);
        }
        if (watermarkIds.has(watermark.sourceId) || (previousSourceId && previousSourceId > watermark.sourceId)) {
            throw new Error('$.sourceWatermarks must be sorted and unique');
        }
        watermarkIds.add(watermark.sourceId);
        previousSourceId = watermark.sourceId;
    });
    assertArray(value.operations, '$.operations', 100000);
    const operationIds = new Set();
    for (let index = 0; index < value.operations.length; index += 1) {
        const operation = value.operations[index];
        const path = `$.operations[${index}]`;
        assertExactKeys(operation, path, ['op', 'role', 'recordId', 'recordDigest'], ['record']);
        if (!['upsert', 'remove'].includes(operation.op) || !RECORD_ROLES.includes(operation.role)) {
            throw new Error(`${path} has an unsupported operation`);
        }
        assertStableId(operation.recordId, `${path}.recordId`);
        assertDigest(operation.recordDigest, `${path}.recordDigest`);
        const operationId = `${operation.role}:${operation.recordId}`;
        if (operationIds.has(operationId)) {
            throw new Error(`$.operations contains duplicate target ${operationId}`);
        }
        operationIds.add(operationId);
        if (operation.op === 'upsert') {
            if (!operation.record || operation.record.id !== operation.recordId) {
                throw new Error(`${path}.record must match recordId`);
            }
            validateDeltaRecord(operation.role, operation.record, `${path}.record`);
            if (operation.record.scopeDigest !== value.scopeDigest) {
                throw new Error(`${path}.record belongs to another scope`);
            }
            if (operation.recordDigest !== await computeSemanticRecordDigest(operation.record)) {
                throw new Error(`${path}.recordDigest does not match the upsert record`);
            }
        } else if (Object.hasOwn(operation, 'record')) {
            throw new Error(`${path}.record is not allowed for removal`);
        }
    }
    if (value.frozen !== false) {
        throw new Error('$.frozen must be false for a live delta');
    }
    assertDigest(value.deltaDigest, '$.deltaDigest');
    if (value.deltaDigest !== await computeSemanticGraphDeltaDigest(value)) {
        throw new Error('$.deltaDigest does not match delta content');
    }
    return value;
};

export const applySemanticGraphDelta = async (graph, deltaInput) => {
    validateViewerGraph(graph, { allowLive: true });
    if (graph.frozen) {
        throw new Error('Frozen graphs do not accept live deltas');
    }
    const delta = await parseSemanticGraphDelta(JSON.stringify(deltaInput));
    if (delta.graphId !== graph.graphId || delta.scopeDigest !== graph.scope.scopeDigest) {
        throw new Error('Delta graph or scope does not match the live view');
    }
    if (delta.baseRevision !== graph.revision) {
        throw new Error('Delta baseRevision does not match the live view revision');
    }
    const expectedSequence = incrementDecimal(graph.liveDeltaState.sequence);
    if (delta.sequence !== expectedSequence) {
        throw new Error(`Delta sequence must be ${expectedSequence}`);
    }
    if (delta.previousDeltaDigest !== graph.liveDeltaState.lastDeltaDigest) {
        throw new Error('Delta previousDeltaDigest does not match the live chain');
    }
    const sourceIds = new Set(graph.sources.map(source => source.id));
    const previousWatermarks = new Map(graph.liveDeltaState.sourceWatermarks.map(watermark => [
        watermark.sourceId,
        watermark,
    ]));
    delta.sourceWatermarks.forEach(watermark => {
        if (!sourceIds.has(watermark.sourceId)) {
            throw new Error(`Delta watermark source is not present in the live graph: ${watermark.sourceId}`);
        }
        const previous = previousWatermarks.get(watermark.sourceId);
        if (previous && compareDecimal(watermark.sequence, previous.sequence) <= 0) {
            throw new Error(`Delta watermark did not advance for source ${watermark.sourceId}`);
        }
        if (
            previous?.observedAt
            && watermark.observedAt
            && Date.parse(watermark.observedAt) < Date.parse(previous.observedAt)
        ) {
            throw new Error(`Delta watermark time regressed for source ${watermark.sourceId}`);
        }
        previousWatermarks.set(watermark.sourceId, watermark);
    });
    const nextRoles = Object.fromEntries(RECORD_ROLES.map(role => [
        role,
        new Map(graph[role].map(record => [record.id, record])),
    ]));
    for (const operation of delta.operations) {
        if (operation.op === 'remove') {
            const current = nextRoles[operation.role].get(operation.recordId);
            if (!current) {
                throw new Error(`Delta cannot remove missing ${operation.role} record ${operation.recordId}`);
            }
            if (operation.recordDigest !== await computeSemanticRecordDigest(current)) {
                throw new Error(`Delta remove digest does not match ${operation.role} record ${operation.recordId}`);
            }
            nextRoles[operation.role].delete(operation.recordId);
        } else {
            nextRoles[operation.role].set(operation.recordId, operation.record);
        }
    }
    return validateViewerGraph({
        ...graph,
        revision: delta.deltaDigest,
        graphDigest: delta.deltaDigest,
        ...Object.fromEntries(RECORD_ROLES.map(role => [role, [...nextRoles[role].values()]])),
        liveDeltaState: {
            sequence: delta.sequence,
            lastDeltaDigest: delta.deltaDigest,
            sourceWatermarks: [...previousWatermarks.values()]
                .sort((left, right) => left.sourceId.localeCompare(right.sourceId)),
        },
    }, { allowLive: true });
};

const normalizeDecisionEntries = (graph, decisions) => {
    const proposalIds = new Set(graph.proposals.map(proposal => proposal.id));
    const normalized = graph.proposals.map(proposal => {
        const decision = decisions?.[proposal.id] || {};
        const targetAcknowledgements = Object.entries(decision.targetAcknowledgements || {})
            .filter(([, acknowledgement]) => acknowledgement?.acknowledged)
            .map(([target, acknowledgement]) => ({
                target,
                status: acknowledgement.status,
                rationale: String(acknowledgement.rationale || '').trim(),
            }))
            .sort((left, right) => left.target.localeCompare(right.target));
        return {
            proposalId: proposal.id,
            disposition: DISPOSITIONS.has(decision.disposition) ? decision.disposition : 'needs-review',
            rationale: typeof decision.rationale === 'string' ? decision.rationale.trim() : '',
            targetAcknowledgements,
        };
    }).sort((left, right) => left.proposalId.localeCompare(right.proposalId));
    Object.keys(decisions || {}).forEach(proposalId => {
        if (!proposalIds.has(proposalId)) {
            throw new Error(`Decision references unknown proposal ${proposalId}`);
        }
    });
    return normalized;
};

const isBoundedNonEmptyString = (value, maximum) => {
    try {
        assertString(value, 'value', { maximum });
        return true;
    } catch {
        return false;
    }
};

const addDecimalStrings = values => values.reduce(
    (total, value) => total + BigInt(value),
    0n,
).toString();

const sourceLooksLikeDns = source => (
    /(?:^|[^a-z])dns(?:[^a-z]|$)/i.test([
        source?.sourceName,
        source?.sourceType,
        source?.artifactKind,
    ].filter(Boolean).join(' '))
);

export const createReviewRunStatus = graph => {
    const buildRuns = (graph?.nodes || []).filter(node => node.nodeType === 'buildRun');
    const run = buildRuns.length === 1 ? buildRuns[0] : null;
    const runComplete = typeof run?.properties?.complete === 'boolean'
        ? run.properties.complete
        : null;
    const candidateGenerated = typeof run?.properties?.candidateEligible === 'boolean'
        ? run.properties.candidateEligible
        : null;
    const sources = Array.isArray(graph?.sources) ? graph.sources : [];
    const incompleteSources = sources.filter(source => source.coverage?.status !== 'complete');
    const dnsSources = sources.filter(sourceLooksLikeDns);
    const dnsLostEvents = addDecimalStrings(
        dnsSources.map(source => source.coverage?.lostEvents || '0'),
    );
    const coverage = Array.isArray(graph?.coverage) ? graph.coverage : [];
    const incompleteCoverage = coverage.filter(marker => marker.status !== 'complete');
    const blockingCoverage = incompleteCoverage.filter(marker => marker.blocking);
    const findings = Array.isArray(graph?.findings) ? graph.findings : [];
    const blockingFindings = findings.filter(finding => finding.blocking);
    const missingSbomCoverage = ['sbom-source', 'sbom-image'].filter(domain => {
        const markers = coverage.filter(marker => marker.domain === domain);
        return markers.length > 0 && (
            markers.length !== 1 || markers[0].status !== 'complete'
        );
    });
    const evidenceIneligible = runComplete === false
        || candidateGenerated === false
        || blockingCoverage.length > 0
        || blockingFindings.length > 0
        || missingSbomCoverage.length > 0;
    return Object.freeze({
        runId: run?.identity?.runId || null,
        runState: runComplete === true ? 'complete' : runComplete === false ? 'incomplete' : 'not-declared',
        candidateState: candidateGenerated === true
            ? 'generated'
            : candidateGenerated === false ? 'not-generated' : 'not-declared',
        sourceCoverage: Object.freeze({
            complete: sources.length - incompleteSources.length,
            total: sources.length,
            incomplete: Object.freeze(incompleteSources.map(source => Object.freeze({
                id: source.id,
                name: source.sourceName || source.artifactKind || source.id,
                status: source.coverage?.status || 'unavailable',
            }))),
        }),
        dns: Object.freeze({
            status: dnsSources.length === 0
                ? 'not-declared'
                : dnsLostEvents === '0' ? 'no-loss' : 'loss',
            lostEvents: dnsLostEvents,
        }),
        incompleteCoverage: Object.freeze(incompleteCoverage.map(marker => Object.freeze({
            id: marker.id,
            domain: marker.domain,
            status: marker.status,
            blocking: marker.blocking,
        }))),
        blockingCoverage: blockingCoverage.length,
        blockingFindings: Object.freeze(blockingFindings.map(finding => Object.freeze({
            id: finding.id,
            message: finding.message,
            severity: finding.severity,
        }))),
        activationState: evidenceIneligible ? 'ineligible' : run ? 'pending-review' : 'not-declared',
    });
};

export const createDecisionSetPreview = ({
    graph,
    decisions,
    intendedTarget = POLICY_REVIEW_TARGETS[0],
    reviewerAcknowledged = false,
    reviewer = '',
}) => {
    validateViewerGraph(graph, { allowLive: !graph.frozen });
    const runStatus = createReviewRunStatus(graph);
    const normalizedDecisions = normalizeDecisionEntries(graph, decisions);
    const intendedTargetValid = DEPLOYMENT_TARGETS.has(intendedTarget);
    const blockingCoverage = graph.coverage.filter(marker => marker.blocking && marker.status !== 'complete');
    const blockingFindings = graph.findings.filter(finding => finding.blocking);
    const unresolved = normalizedDecisions.filter(decision => (
        decision.disposition === 'needs-review'
        || !isBoundedNonEmptyString(decision.rationale, 8192)
    ));
    const acknowledgementBlockers = [];
    normalizedDecisions.forEach(decision => {
        decision.targetAcknowledgements.forEach(acknowledgement => {
            if (
                !DEPLOYMENT_TARGETS.has(acknowledgement.target)
                || !['restrictive', 'conditional'].includes(acknowledgement.status)
                || !isBoundedNonEmptyString(acknowledgement.rationale, 8192)
            ) {
                acknowledgementBlockers.push(
                    `target:${decision.proposalId}:${acknowledgement.target || 'unknown'}:invalid`,
                );
            }
        });
    });
    graph.proposals.forEach(proposal => {
        const decision = normalizedDecisions.find(entry => entry.proposalId === proposal.id);
        if (decision?.disposition !== 'accept') {
            return;
        }
        proposal.targetFeasibility
            .filter(target => (
                target.target === intendedTarget
                && ['restrictive', 'conditional'].includes(target.status)
            ))
            .forEach(target => {
                const acknowledgement = decision.targetAcknowledgements.find(entry => entry.target === target.target);
                if (!acknowledgement || acknowledgement.status !== target.status || !acknowledgement.rationale) {
                    acknowledgementBlockers.push(`target:${proposal.id}:${target.target}:${target.status}`);
                }
            });
    });
    const reviewerValid = typeof reviewer === 'string'
        && isBoundedNonEmptyString(reviewer.trim(), 256);
    const readyForCliApproval = Boolean(
        graph.frozen
        && reviewerAcknowledged
        && reviewerValid
        && intendedTargetValid
        && !blockingCoverage.length
        && !blockingFindings.length
        && runStatus.runState !== 'incomplete'
        && runStatus.candidateState !== 'not-generated'
        && !unresolved.length
        && !acknowledgementBlockers.length
    );
    return {
        graphDigest: graph.graphDigest,
        graphContentDigest: graph.contentDigest || null,
        proposalSetDigest: graph.proposalSetDigest,
        basePolicyDigest: graph.basePolicyDigest,
        scopeDigest: graph.scope.scopeDigest,
        intendedTarget,
        decisionsComplete: Boolean(graph.frozen && reviewerAcknowledged && reviewerValid
            && intendedTargetValid && !unresolved.length && !acknowledgementBlockers.length),
        reviewState: readyForCliApproval ? 'complete' : 'draft',
        reviewerAcknowledged: Boolean(reviewerAcknowledged),
        decisions: normalizedDecisions,
        blockers: [
            ...blockingCoverage.map(marker => `coverage:${marker.domain}:${marker.status}`),
            ...blockingFindings.map(finding => `finding:${finding.id}`),
            ...(runStatus.runState === 'incomplete' ? ['profile:run-incomplete'] : []),
            ...(runStatus.candidateState === 'not-generated'
                ? ['profile:candidate-not-generated']
                : []),
            ...unresolved.map(decision => `decision:${decision.proposalId}`),
            ...acknowledgementBlockers,
            ...(!intendedTargetValid ? ['target:selection-required'] : []),
            ...(!graph.frozen ? ['graph:not-frozen'] : []),
            ...(!reviewerValid ? ['reviewer:identity-required'] : []),
            ...(!reviewerAcknowledged ? ['reviewer:not-acknowledged'] : []),
        ],
    };
};

const canonicalize = value => {
    if (value === null || typeof value === 'boolean' || typeof value === 'number' || typeof value === 'string') {
        return JSON.stringify(value);
    }
    if (Array.isArray(value)) {
        return `[${value.map(canonicalize).join(',')}]`;
    }
    const keys = Object.keys(value).sort();
    return `{${keys.map(key => `${JSON.stringify(key)}:${canonicalize(value[key])}`).join(',')}}`;
};

const SHA256_ROUND_CONSTANTS = new Uint32Array([
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
]);

const rotateRight = (value, bits) => (value >>> bits) | (value << (32 - bits));

const softwareSha256 = bytes => {
    const bitLength = bytes.length * 8;
    const paddedLength = Math.ceil((bytes.length + 9) / 64) * 64;
    const message = new Uint8Array(paddedLength);
    message.set(bytes);
    message[bytes.length] = 0x80;
    const messageView = new DataView(message.buffer);
    messageView.setUint32(paddedLength - 8, Math.floor(bitLength / 0x100000000), false);
    messageView.setUint32(paddedLength - 4, bitLength >>> 0, false);
    const state = new Uint32Array([
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
    ]);
    const words = new Uint32Array(64);
    for (let offset = 0; offset < paddedLength; offset += 64) {
        for (let index = 0; index < 16; index += 1) {
            words[index] = messageView.getUint32(offset + (index * 4), false);
        }
        for (let index = 16; index < 64; index += 1) {
            const left = words[index - 15];
            const right = words[index - 2];
            const sigma0 = rotateRight(left, 7) ^ rotateRight(left, 18) ^ (left >>> 3);
            const sigma1 = rotateRight(right, 17) ^ rotateRight(right, 19) ^ (right >>> 10);
            words[index] = (words[index - 16] + sigma0 + words[index - 7] + sigma1) >>> 0;
        }
        let [a, b, c, d, e, f, g, h] = state;
        for (let index = 0; index < 64; index += 1) {
            const sum1 = rotateRight(e, 6) ^ rotateRight(e, 11) ^ rotateRight(e, 25);
            const choice = (e & f) ^ (~e & g);
            const temporary1 = (h + sum1 + choice + SHA256_ROUND_CONSTANTS[index] + words[index]) >>> 0;
            const sum0 = rotateRight(a, 2) ^ rotateRight(a, 13) ^ rotateRight(a, 22);
            const majority = (a & b) ^ (a & c) ^ (b & c);
            const temporary2 = (sum0 + majority) >>> 0;
            h = g; g = f; f = e; e = (d + temporary1) >>> 0;
            d = c; c = b; b = a; a = (temporary1 + temporary2) >>> 0;
        }
        state[0] = (state[0] + a) >>> 0; state[1] = (state[1] + b) >>> 0;
        state[2] = (state[2] + c) >>> 0; state[3] = (state[3] + d) >>> 0;
        state[4] = (state[4] + e) >>> 0; state[5] = (state[5] + f) >>> 0;
        state[6] = (state[6] + g) >>> 0; state[7] = (state[7] + h) >>> 0;
    }
    const digest = new Uint8Array(32);
    const digestView = new DataView(digest.buffer);
    state.forEach((word, index) => digestView.setUint32(index * 4, word, false));
    return digest;
};

export const browserSha256Digest = async (value, { rawString = false, subtle = globalThis.crypto?.subtle } = {}) => {
    const source = rawString ? String(value) : canonicalize(value);
    const bytes = new TextEncoder().encode(source);
    const digest = subtle
        ? new Uint8Array(await subtle.digest('SHA-256', bytes))
        : softwareSha256(bytes);
    return `sha256:${[...digest].map(byte => byte.toString(16).padStart(2, '0')).join('')}`;
};

const browserStableId = async (namespace, semanticKey) => {
    // Core createStableId hashes JCS(semanticKey). String keys therefore include
    // their JSON quotes; hashing the raw digest string produces a different ID.
    const digest = await browserSha256Digest(semanticKey);
    return `${namespace}:${digest.slice('sha256:'.length)}`;
};

export const materializeDecisionSet = async ({
    graph,
    decisions,
    intendedTarget = POLICY_REVIEW_TARGETS[0],
    reviewer,
    reviewerAcknowledged = false,
    createdAt = new Date().toISOString(),
    allowBlockedReview = false,
}) => {
    await verifySemanticGraphContentDigest(graph);
    const preview = createDecisionSetPreview({
        graph,
        decisions,
        intendedTarget,
        reviewer,
        reviewerAcknowledged,
    });
    if (preview.reviewState !== 'complete' && !(allowBlockedReview && preview.decisionsComplete)) {
        throw new Error(`DecisionSet is still a draft: ${preview.blockers.join(', ')}`);
    }
    assertDateTime(createdAt, 'createdAt');
    const normalizedDecisions = await Promise.all(preview.decisions.map(async decision => ({
        id: await browserStableId('decision', {
            scopeDigest: graph.scope.scopeDigest,
            proposalId: decision.proposalId,
        }),
        ...decision,
    })));
    const payload = {
        apiVersion: API_VERSION,
        kind: DECISION_SET_KIND,
        schemaVersion: 1,
        createdAt,
        reviewer: reviewer.trim(),
        scopeDigest: graph.scope.scopeDigest,
        graphDigest: graph.graphDigest,
        graphContentDigest: graph.contentDigest,
        proposalSetDigest: graph.proposalSetDigest,
        basePolicyDigest: graph.basePolicyDigest,
        decisions: normalizedDecisions,
    };
    const contentDigest = await browserSha256Digest(payload);
    const decisionSetId = await browserStableId('decision-set', contentDigest);
    return {
        ...payload,
        decisionSetId,
        contentDigest,
    };
};

const demoDigest = character => `sha256:${character.repeat(64)}`;
const demoId = (namespace, character) => `${namespace}:${character.repeat(64)}`;
const demoPrivacy = () => ({ classification: 'portable-sensitive', fields: [] });

export const createSampleSemanticGraph = () => {
    const scopeDigest = 'sha256:e5a68f9f97c8f2c0e511f076bfcf05466ccc61e466a2e7e0e4f52e8e18bb4616';
    const sampleStartedAt = '2026-08-16T12:00:00.000Z';
    const sampleEndedAt = '2026-08-16T12:00:08.000Z';
    const sourceBuildkit = demoId('source', '1');
    const sourceNetwork = demoId('source', '2');
    const node = (id, nodeType, label, properties = {}) => ({
        apiVersion: API_VERSION,
        kind: RECORD_KINDS.nodes,
        schemaVersion: 1,
        id,
        scopeDigest,
        nodeType,
        label,
        identity: { key: id },
        properties,
        evidenceRefs: [sourceBuildkit],
        privacy: demoPrivacy(),
    });
    const ids = {
        run: demoId('build', '1'),
        stage: demoId('vertex', '2'),
        node: demoId('process', '3'),
        curl: demoId('process', '4'),
        lock: demoId('file', '5'),
        profile: demoId('file', '6'),
        syscall: demoId('syscall', '7'),
        registryDomain: demoId('domain', '8'),
        telemetryDomain: demoId('domain', '9'),
        registryEndpoint: demoId('endpoint', 'b'),
        telemetryEndpoint: demoId('endpoint', 'c'),
        pkg: demoId('package', 'd'),
    };
    const observations = [
        [demoId('observation', '1'), 'mayHaveOccurredDuring', ids.stage, ids.node, 'correlated', '2026-08-16T12:00:00.500Z', '2026-08-16T12:00:04.000Z'],
        [demoId('observation', '2'), 'mayHaveOccurredDuring', ids.stage, ids.curl, 'correlated', '2026-08-16T12:00:01.000Z', '2026-08-16T12:00:06.000Z'],
        [demoId('observation', '3'), 'accesses', ids.node, ids.lock, 'observed', '2026-08-16T12:00:02.000Z', '2026-08-16T12:00:03.000Z'],
        [demoId('observation', '4'), 'accesses', ids.curl, ids.profile, 'observed', '2026-08-16T12:00:04.000Z', '2026-08-16T12:00:04.500Z'],
        [demoId('observation', '5'), 'invokes', ids.node, ids.syscall, 'correlated', '2026-08-16T12:00:02.500Z', '2026-08-16T12:00:05.000Z'],
        [demoId('observation', '6'), 'queries', ids.node, ids.registryDomain, 'inferred', '2026-08-16T12:00:02.750Z', '2026-08-16T12:00:02.750Z'],
        [demoId('observation', '7'), 'queries', ids.curl, ids.telemetryDomain, 'inferred', '2026-08-16T12:00:04.750Z', '2026-08-16T12:00:04.750Z'],
        [demoId('observation', '8'), 'connects', ids.node, ids.registryEndpoint, 'inferred', '2026-08-16T12:00:03.000Z', '2026-08-16T12:00:05.000Z'],
        [demoId('observation', '9'), 'connects', ids.curl, ids.telemetryEndpoint, 'inferred', '2026-08-16T12:00:05.000Z', '2026-08-16T12:00:07.000Z'],
    ].map(([
        id,
        observationType,
        subjectId,
        objectId,
        basis,
        firstObservedAt,
        lastObservedAt,
    ]) => ({
        apiVersion: API_VERSION,
        kind: RECORD_KINDS.observations,
        schemaVersion: 1,
        id,
        scopeDigest,
        observationType,
        subjectId,
        objectId,
        basis,
        confidence: basis === 'observed' ? 100 : basis === 'correlated' ? 75 : 45,
        count: '1',
        firstObservedAt,
        lastObservedAt,
        evidenceRefs: [sourceBuildkit],
        properties: {},
        privacy: demoPrivacy(),
    }));
    const proposals = [
        {
            id: demoId('proposal', '1'),
            subjectId: ids.node,
            endpoint: '104.16.0.1',
            baselineState: 'unchanged',
            rationale: 'Package installation contacted the approved registry endpoint over TCP/443.',
            evidenceRefs: [demoId('observation', '8')],
        },
        {
            id: demoId('proposal', '2'),
            subjectId: ids.curl,
            endpoint: '203.0.113.24',
            baselineState: 'broadened',
            rationale: 'A destination absent from the signed baseline was contacted over TCP/443.',
            evidenceRefs: [demoId('observation', '9')],
        },
    ].map(proposal => ({
        apiVersion: API_VERSION,
        kind: RECORD_KINDS.proposals,
        schemaVersion: 1,
        id: proposal.id,
        scopeDigest,
        scopeClass: 'build',
        proposalType: 'network-egress',
        intent: {
            domain: 'network',
            subjectId: proposal.subjectId,
            effect: 'allow',
            direction: 'egress',
            peer: { kind: 'ipv4', value: proposal.endpoint },
            transport: { protocol: 'tcp', ports: [443] },
        },
        baselineState: proposal.baselineState,
        rationale: proposal.rationale,
        evidenceRefs: proposal.evidenceRefs,
        observationRefs: proposal.evidenceRefs,
        targetFeasibility: [
            { target: 'cilium', status: 'exact', reasons: [] },
            { target: 'gateway-iptables', status: 'exact', reasons: [] },
            { target: 'guard-ebpf', status: 'outsideScope', reasons: ['build-time behavior cannot authorize the runtime eBPF subject'] },
            { target: 'guard-nftables', status: 'exact', reasons: [] },
        ],
        privacy: demoPrivacy(),
    }));
    const diffEntry = (id, entityId, changeType, summary, evidenceRefs = []) => ({
        apiVersion: API_VERSION,
        kind: RECORD_KINDS.diff,
        schemaVersion: 1,
        id,
        scopeDigest,
        entityId,
        changeType,
        beforeDigest: changeType === 'added' ? null : demoDigest('1'),
        afterDigest: changeType === 'removed' ? null : demoDigest('2'),
        policyRelevant: !['metric-only', 'removed'].includes(changeType),
        summary,
        evidenceRefs,
        privacy: demoPrivacy(),
    });
    return validateSemanticGraph({
        apiVersion: API_VERSION,
        kind: GRAPH_KIND,
        schemaVersion: 1,
        graphId: 'graph:15e2ecf3c7c02602d46b3d6f37a0741e0f62386ce58436e119ad93db8d81ca5e',
        revision: demoDigest('3'),
        graphDigest: demoDigest('4'),
        proposalSetDigest: demoDigest('5'),
        basePolicyDigest: demoDigest('6'),
        contentDigest: 'sha256:34f24bf8e57b8b012eb93c7d4893f09747363ee784049d81c453e9997765502a',
        scope: {
            class: 'build',
            subjectId: demoId('subject', 'e'),
            scopeDigest,
            projectKey: '7'.repeat(64),
            platform: 'linux/amd64',
            target: 'release',
            dockerfileDigest: demoDigest('8'),
            imageDigest: null,
            workspaceDigest: null,
        },
        sources: [
            {
                id: sourceBuildkit,
                artifactKind: 'NoshBuildKitProgress',
                artifactDigest: demoDigest('9'),
                observedFrom: sampleStartedAt,
                observedTo: sampleEndedAt,
                coverage: { status: 'complete', lostEvents: '0', parseErrors: '0', gaps: [] },
            },
            {
                id: sourceNetwork,
                artifactKind: 'NoshL4FlowSummary',
                artifactDigest: demoDigest('b'),
                observedFrom: '2026-08-16T12:00:02.000Z',
                observedTo: '2026-08-16T12:00:07.000Z',
                coverage: { status: 'complete', lostEvents: '0', parseErrors: '0', gaps: [] },
            },
        ],
        nodes: [
            node(ids.run, 'buildRun', 'release profile', {
                summary: 'cold + warm passes',
                startedAt: sampleStartedAt,
                endedAt: sampleEndedAt,
            }),
            node(ids.stage, 'buildkitVertex', 'RUN npm ci', {
                summary: 'dependency install',
                startedAt: '2026-08-16T12:00:00.500Z',
                completedAt: '2026-08-16T12:00:07.500Z',
            }),
            node(ids.node, 'process', 'node', { executable: '/usr/local/bin/node' }),
            node(ids.curl, 'process', 'curl', { summary: 'new executable in build' }),
            node(ids.lock, 'file', '/app/package-lock.json', { operation: 'read' }),
            node(ids.profile, 'file', '/root/.npmrc', { operation: 'read' }),
            node(ids.syscall, 'syscall', 'connect(2)', { calls: '12' }),
            node(ids.registryDomain, 'domain', 'registry.npmjs.org', { recordType: 'A' }),
            node(ids.telemetryDomain, 'domain', 'telemetry.example.net', { recordType: 'A' }),
            {
                ...node(ids.registryEndpoint, 'networkEndpoint', '104.16.0.1:443', { protocol: 'tcp', port: 443 }),
                identity: {
                    family: 'ipv4',
                    address: '104.16.0.1',
                    protocol: 'tcp',
                    port: 443,
                    icmpType: null,
                    icmpCode: null,
                },
                evidenceRefs: [sourceNetwork],
            },
            {
                ...node(ids.telemetryEndpoint, 'networkEndpoint', '203.0.113.24:443', { protocol: 'tcp', port: 443 }),
                identity: {
                    family: 'ipv4',
                    address: '203.0.113.24',
                    protocol: 'tcp',
                    port: 443,
                    icmpType: null,
                    icmpCode: null,
                },
                evidenceRefs: [sourceNetwork],
            },
            node(ids.pkg, 'package', 'next@16.2.6', { format: 'CycloneDX' }),
        ],
        observations,
        coverage: [
            ['process', demoId('coverage', '1')],
            ['file', demoId('coverage', '2')],
            ['network', demoId('coverage', '3')],
        ].map(([domain, id]) => ({
            apiVersion: API_VERSION,
            kind: RECORD_KINDS.coverage,
            schemaVersion: 1,
            id,
            scopeDigest,
            domain,
            status: 'complete',
            sourceIds: [domain === 'network' ? sourceNetwork : sourceBuildkit],
            counters: { records: '1' },
            gaps: [],
            blocking: true,
            privacy: demoPrivacy(),
        })),
        findings: [{
            apiVersion: API_VERSION,
            kind: RECORD_KINDS.findings,
            schemaVersion: 1,
            id: demoId('finding', '1'),
            scopeDigest,
            findingType: 'drift-broadened',
            severity: 'high',
            blocking: false,
            message: 'New telemetry destination requires disposition.',
            semanticRefs: [ids.telemetryEndpoint],
            evidenceRefs: [sourceNetwork],
            properties: {},
            privacy: demoPrivacy(),
        }],
        proposals,
        diff: [
            diffEntry(demoId('diff', '1'), ids.curl, 'added', 'curl was not present in the baseline', [sourceBuildkit]),
            diffEntry(demoId('diff', '2'), ids.profile, 'added', 'a new credential-adjacent path was read', [sourceBuildkit]),
            diffEntry(demoId('diff', '3'), ids.telemetryEndpoint, 'broadened', 'new network destination', [sourceNetwork]),
            diffEntry(demoId('diff', '4'), ids.pkg, 'added', 'package version changed', [sourceBuildkit]),
            diffEntry(demoId('diff', '5'), ids.syscall, 'metric-only', 'connect call count changed', [sourceBuildkit]),
            diffEntry(demoId('diff', '6'), proposals[0].id, 'unchanged', 'registry policy matches baseline', proposals[0].evidenceRefs),
            diffEntry(demoId('diff', '7'), proposals[1].id, 'broadened', 'new egress proposal', proposals[1].evidenceRefs),
        ],
        frozen: true,
    });
};

export const POLICY_REVIEW_API_VERSION = API_VERSION;
