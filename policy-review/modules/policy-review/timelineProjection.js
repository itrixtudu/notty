export const TIMELINE_DOMAINS = Object.freeze([
    'build',
    'process',
    'filesystem',
    'syscall',
    'dns',
    'network',
    'package',
    'other',
]);

const RFC3339_PATTERN = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.(\d{1,9}))?(Z|([+-])(\d{2}):(\d{2}))$/;

const OBSERVATION_DOMAINS = Object.freeze({
    accesses: 'filesystem',
    communicatesWith: 'network',
    connects: 'network',
    executes: 'process',
    exits: 'process',
    installs: 'package',
    invokes: 'syscall',
    parentPidObserved: 'process',
    queries: 'dns',
    resolvesTo: 'dns',
});

const NODE_DOMAINS = Object.freeze({
    buildPass: 'build',
    buildRun: 'build',
    buildkitVertex: 'build',
    cgroup: 'process',
    collector: 'build',
    coverageSource: 'build',
    domain: 'dns',
    evidenceSource: 'other',
    executable: 'process',
    file: 'filesystem',
    image: 'package',
    networkEndpoint: 'network',
    package: 'package',
    process: 'process',
    project: 'build',
    sourceRecord: 'build',
    syscall: 'syscall',
    workload: 'process',
});

const STRUCTURAL_NODE_BOUNDS = Object.freeze({
    buildRun: Object.freeze({ start: 'startedAt', end: 'endedAt' }),
    buildkitVertex: Object.freeze({ start: 'startedAt', end: 'completedAt' }),
});

const RECORD_TYPE_ORDER = Object.freeze({
    source: 0,
    observation: 1,
    node: 2,
});

const freezeArray = values => Object.freeze([...values]);

const compareStrings = (left, right) => left < right ? -1 : left > right ? 1 : 0;

const freezeMetadata = metadata => Object.freeze({
    ...metadata,
    fields: freezeArray(metadata.fields || []),
    diagnostics: freezeArray(metadata.diagnostics || []),
});

const invalidTimestamp = (path, reason = '') => {
    throw new TypeError(`${path} must be a strict RFC 3339 timestamp${reason ? ` (${reason})` : ''}`);
};

export const parseRfc3339Timestamp = (value, path = 'timestamp') => {
    if (typeof value !== 'string') {
        return invalidTimestamp(path);
    }
    const match = RFC3339_PATTERN.exec(value);
    if (!match) {
        return invalidTimestamp(path);
    }
    const [
        , yearText, monthText, dayText, hourText, minuteText, secondText,
        fractionText = '', zoneText, offsetSign, offsetHourText = '0', offsetMinuteText = '0',
    ] = match;
    const year = Number(yearText);
    const month = Number(monthText);
    const day = Number(dayText);
    const hour = Number(hourText);
    const minute = Number(minuteText);
    const second = Number(secondText);
    const millisecond = Number(`${fractionText}000`.slice(0, 3));
    const offsetHour = Number(offsetHourText);
    const offsetMinute = Number(offsetMinuteText);

    if (
        year === 0
        || month < 1 || month > 12
        || day < 1 || day > 31
        || hour > 23
        || minute > 59
        || second > 59
        || offsetHour > 23
        || offsetMinute > 59
    ) {
        return invalidTimestamp(path);
    }

    const local = new Date(0);
    local.setUTCHours(hour, minute, second, millisecond);
    local.setUTCFullYear(year, month - 1, day);
    if (
        local.getUTCFullYear() !== year
        || local.getUTCMonth() !== month - 1
        || local.getUTCDate() !== day
        || local.getUTCHours() !== hour
        || local.getUTCMinutes() !== minute
        || local.getUTCSeconds() !== second
    ) {
        return invalidTimestamp(path, 'invalid calendar date');
    }

    const offsetDirection = zoneText === 'Z' ? 0 : offsetSign === '+' ? 1 : -1;
    const offsetMs = offsetDirection * ((offsetHour * 60) + offsetMinute) * 60 * 1000;
    const timestamp = local.getTime() - offsetMs;
    if (!Number.isFinite(timestamp)) {
        return invalidTimestamp(path, 'outside the supported date range');
    }
    return timestamp;
};

const timestamp = (value, path) => ({
    at: value,
    ms: parseRfc3339Timestamp(value, path),
});

const compareTimestamp = (left, right) => (
    left.ms - right.ms
    || compareStrings(left.at, right.at)
);

const minTimestamp = values => values.reduce(
    (minimum, value) => !minimum || compareTimestamp(value, minimum) < 0 ? value : minimum,
    null,
);

const maxTimestamp = values => values.reduce(
    (maximum, value) => !maximum || compareTimestamp(value, maximum) > 0 ? value : maximum,
    null,
);

const createBounds = ({ start, end, path }) => {
    if (!start && !end) {
        return null;
    }
    const resolvedStart = start || end;
    const resolvedEnd = end || start;
    if (compareTimestamp(resolvedStart, resolvedEnd) > 0) {
        throw new TypeError(`${path} time range is reversed`);
    }
    return Object.freeze({
        startAt: resolvedStart.at,
        endAt: resolvedEnd.at,
        startMs: resolvedStart.ms,
        endMs: resolvedEnd.ms,
        temporalKind: resolvedStart.ms === resolvedEnd.ms ? 'point' : 'interval',
    });
};

const boundsFromFields = (record, startField, endField, path) => {
    const hasStart = record[startField] !== undefined && record[startField] !== null;
    const hasEnd = record[endField] !== undefined && record[endField] !== null;
    return createBounds({
        start: hasStart ? timestamp(record[startField], `${path}.${startField}`) : null,
        end: hasEnd ? timestamp(record[endField], `${path}.${endField}`) : null,
        path,
    });
};

const safeBoundsFromFields = (record, startField, endField, path, { requirePair = false } = {}) => {
    const presentFields = [startField, endField].filter(field => record[field] != null);
    if (!presentFields.length) {
        return { status: 'absent', bounds: null, fields: [], diagnostics: [] };
    }
    if (requirePair && presentFields.length !== 2) {
        return {
            status: 'invalid',
            bounds: null,
            fields: presentFields,
            diagnostics: [`${path} must provide ${startField} and ${endField} together`],
        };
    }
    try {
        return {
            status: 'valid',
            bounds: boundsFromFields(record, startField, endField, path),
            fields: presentFields,
            diagnostics: [],
        };
    } catch (error) {
        return {
            status: 'invalid',
            bounds: null,
            fields: presentFields,
            diagnostics: [error.message],
        };
    }
};

const unionItemBounds = items => {
    const timed = items.filter(item => item.temporalKind !== 'untimed');
    if (!timed.length) {
        return null;
    }
    return createBounds({
        start: minTimestamp(timed.map(item => ({ at: item.startAt, ms: item.startMs }))),
        end: maxTimestamp(timed.map(item => ({ at: item.endAt, ms: item.endMs }))),
        path: 'derived timeline envelope',
    });
};

const sourceText = source => [
    source.sourceName,
    source.sourceType,
    source.artifactKind,
].filter(Boolean).join(' ');

const domainFromText = value => {
    const text = String(value || '').toLowerCase();
    if (/(?:dns|domain)/.test(text)) return 'dns';
    if (/(?:l4|network|flow|socket|hubble)/.test(text)) return 'network';
    if (/(?:file|filesystem)/.test(text)) return 'filesystem';
    if (/syscall/.test(text)) return 'syscall';
    if (/(?:process|exec)/.test(text)) return 'process';
    if (/(?:sbom|package)/.test(text)) return 'package';
    if (/(?:build|buildkit|buildx|cgroup)/.test(text)) return 'build';
    return 'other';
};

const sourceDomain = (source, coverageDomains) => {
    const explicit = coverageDomains.get(source.id);
    const classified = new Set();
    (explicit || []).forEach(domain => {
        if (domain === 'dns') classified.add('dns');
        else if (['network', 'runtime-network', 'hubble'].includes(domain)) classified.add('network');
        else if (['file', 'runtime-file'].includes(domain)) classified.add('filesystem');
        else if (domain === 'syscall') classified.add('syscall');
        else if (['process', 'runtime-process'].includes(domain)) classified.add('process');
        else if (['sbom-source', 'sbom-image'].includes(domain)) classified.add('package');
        else classified.add('build');
    });
    if (classified.size === 1) return [...classified][0];
    const namedDomain = domainFromText(sourceText(source));
    if (namedDomain !== 'other') return namedDomain;
    return classified.size ? 'other' : namedDomain;
};

const nodeDomain = node => NODE_DOMAINS[node.nodeType] || domainFromText(node.nodeType);

const observationDomain = (observation, nodesById, sourceItemsById) => {
    if (OBSERVATION_DOMAINS[observation.observationType]) {
        return OBSERVATION_DOMAINS[observation.observationType];
    }
    const candidates = [
        nodesById.get(observation.objectId),
        nodesById.get(observation.subjectId),
    ].filter(Boolean).map(nodeDomain);
    const evidenceDomains = (observation.evidenceRefs || [])
        .map(id => sourceItemsById.get(id)?.domain)
        .filter(Boolean);
    return [...candidates, ...evidenceDomains].find(domain => domain !== 'other') || 'other';
};

const untimedBounds = Object.freeze({
    startAt: null,
    endAt: null,
    startMs: null,
    endMs: null,
    temporalKind: 'untimed',
});

const makeItem = ({
    recordType,
    recordId,
    domain,
    label,
    bounds,
    relatedNodeIds = [],
    precision,
    aggregation,
}) => Object.freeze({
    id: `timeline:${recordType}:${recordId}`,
    recordType,
    recordId,
    domain,
    label,
    ...(bounds || untimedBounds),
    relatedNodeIds: freezeArray([...new Set(relatedNodeIds)].sort()),
    precision: freezeMetadata(precision),
    aggregation: Object.freeze({ ...aggregation }),
});

const sourceItem = (source, index, coverageDomains, nodeIds) => {
    const timing = safeBoundsFromFields(
        source,
        'observedFrom',
        'observedTo',
        `$.sources[${index}]`,
        { requirePair: true },
    );
    const bounds = timing.bounds;
    return makeItem({
        recordType: 'source',
        recordId: source.id,
        domain: sourceDomain(source, coverageDomains),
        label: source.sourceName || source.artifactKind || source.id,
        bounds,
        relatedNodeIds: nodeIds.has(source.id) ? [source.id] : [],
        precision: timing.status === 'valid' ? {
            kind: 'capture-window',
            basis: 'source-bounds',
            resolution: 'millisecond',
            fields: ['observedFrom', 'observedTo'],
            diagnostics: [],
        } : timing.status === 'invalid' ? {
            kind: 'invalid-source-bounds',
            basis: 'source-bounds',
            resolution: null,
            fields: timing.fields,
            diagnostics: timing.diagnostics,
        } : {
            kind: 'untimed',
            basis: 'none',
            resolution: null,
            fields: [],
            diagnostics: [],
        },
        aggregation: {
            aggregated: false,
            count: null,
            semantics: timing.status === 'valid'
                ? 'capture-window-not-event-activity'
                : timing.status === 'invalid'
                    ? 'invalid-source-bounds-untimed'
                    : 'untimed-context',
            representsContinuousActivity: false,
        },
    });
};

const observationItem = (observation, index, nodesById, sourceItemsById) => {
    const timing = safeBoundsFromFields(
        observation,
        'firstObservedAt',
        'lastObservedAt',
        `$.observations[${index}]`,
    );
    const recordBounds = timing.bounds;
    const bounds = recordBounds;
    const count = typeof observation.count === 'string' ? observation.count : null;
    const isEnvelope = Boolean(recordBounds && recordBounds.temporalKind === 'interval');
    const isAggregated = count !== null && count !== '1';
    const hasFirst = timing.fields.includes('firstObservedAt');
    const hasLast = timing.fields.includes('lastObservedAt');
    const partialBoundary = timing.status === 'valid' && hasFirst !== hasLast;
    const subject = nodesById.get(observation.subjectId);
    const object = nodesById.get(observation.objectId);
    return makeItem({
        recordType: 'observation',
        recordId: observation.id,
        domain: observationDomain(observation, nodesById, sourceItemsById),
        label: [
            subject?.label || observation.subjectId,
            observation.observationType,
            object?.label || observation.objectId,
        ].join(' '),
        bounds,
        relatedNodeIds: [observation.subjectId, observation.objectId],
        precision: timing.status === 'valid' ? {
            kind: partialBoundary
                ? (hasFirst ? 'recorded-start-boundary' : 'recorded-end-boundary')
                : recordBounds.temporalKind === 'point' ? 'recorded-point' : 'recorded-range',
            basis: 'observation-bounds',
            resolution: 'millisecond',
            fields: timing.fields,
            diagnostics: [],
            boundary: partialBoundary ? (hasFirst ? 'start' : 'end') : 'complete',
        } : timing.status === 'invalid' ? {
            kind: 'invalid-observation-bounds',
            basis: 'observation-bounds',
            resolution: null,
            fields: timing.fields,
            diagnostics: timing.diagnostics,
        } : {
            kind: 'untimed',
            basis: 'none',
            resolution: null,
            fields: [],
            diagnostics: [],
        },
        aggregation: {
            aggregated: isAggregated || isEnvelope,
            count,
            semantics: timing.status === 'valid'
                ? partialBoundary
                    ? 'partial-occurrence-bound-not-complete-range'
                    : isEnvelope
                        ? 'occurrence-envelope-not-continuous-activity'
                        : 'recorded-occurrence'
                : timing.status === 'invalid'
                    ? 'invalid-observation-bounds-untimed'
                    : 'untimed-context',
            representsContinuousActivity: false,
        },
    });
};

const structuralNodeTiming = (node, index) => {
    const fields = STRUCTURAL_NODE_BOUNDS[node.nodeType];
    if (!fields) {
        return Object.freeze({ status: 'absent', bounds: null, fields: [], diagnostics: [] });
    }
    return safeBoundsFromFields(
        node.properties || {},
        fields.start,
        fields.end,
        `$.nodes[${index}].properties`,
    );
};

const nodeItem = (node, index, relatedObservations, sourceItemsById) => {
    const structural = structuralNodeTiming(node, index);
    const structuralBounds = structural.bounds;
    const timedRelatedObservations = relatedObservations.filter(item => item.temporalKind !== 'untimed');
    const observationBounds = structural.status === 'invalid'
        ? null
        : unionItemBounds(timedRelatedObservations);
    const bounds = structuralBounds || observationBounds;
    const structuralBoundaryOnly = structuralBounds && structural.fields.length === 1;
    const derivation = structuralBounds
        ? 'structural-metadata'
        : observationBounds
            ? 'related-observation-envelope'
            : structural.status === 'invalid'
                ? 'invalid-structural-metadata'
                : 'untimed';
    return makeItem({
        recordType: 'node',
        recordId: node.id,
        domain: sourceItemsById.get(node.id)?.domain || nodeDomain(node),
        label: node.label || node.id,
        bounds,
        relatedNodeIds: [node.id],
        precision: bounds ? {
            kind: derivation,
            basis: derivation,
            resolution: 'millisecond',
            fields: structuralBounds
                ? structural.fields
                : observationBounds
                    ? ['firstObservedAt', 'lastObservedAt']
                    : [],
            diagnostics: structural.diagnostics,
            boundary: structuralBoundaryOnly
                ? (structural.fields[0] === STRUCTURAL_NODE_BOUNDS[node.nodeType]?.start ? 'start' : 'end')
                : 'complete',
        } : {
            kind: derivation,
            basis: structural.status === 'invalid' ? 'structural-metadata' : 'none',
            resolution: null,
            fields: structural.fields,
            diagnostics: structural.diagnostics,
        },
        aggregation: {
            aggregated: timedRelatedObservations.length > 1,
            count: observationBounds ? String(timedRelatedObservations.length) : null,
            semantics: structuralBounds
                ? structuralBoundaryOnly
                    ? 'structural-boundary-not-complete-activity-range'
                    : 'structural-activity-range'
                : observationBounds
                    ? 'related-observation-envelope-not-continuous-activity'
                    : structural.status === 'invalid'
                        ? 'invalid-structural-metadata-untimed'
                        : 'untimed-context',
            representsContinuousActivity: Boolean(structuralBounds && structuralBounds.temporalKind === 'interval'),
        },
    });
};

const compareItems = (left, right) => {
    if (left.startMs === null && right.startMs !== null) return 1;
    if (left.startMs !== null && right.startMs === null) return -1;
    if (left.startMs !== null && right.startMs !== null) {
        const timeOrder = left.startMs - right.startMs || left.endMs - right.endMs;
        if (timeOrder) return timeOrder;
    }
    const recordTypeOrder = RECORD_TYPE_ORDER[left.recordType] - RECORD_TYPE_ORDER[right.recordType];
    return recordTypeOrder || compareStrings(left.id, right.id);
};

const coverageDomainsBySource = graph => {
    const result = new Map();
    (graph.coverage || []).forEach(marker => {
        (marker.sourceIds || []).forEach(sourceId => {
            if (!result.has(sourceId)) result.set(sourceId, new Set());
            result.get(sourceId).add(marker.domain);
        });
    });
    return result;
};

const requireGraphArrays = graph => {
    if (!graph || typeof graph !== 'object') {
        throw new TypeError('graph must be a NoshSemanticGraph object');
    }
    ['sources', 'nodes', 'observations'].forEach(role => {
        if (!Array.isArray(graph[role])) {
            throw new TypeError(`graph.${role} must be an array`);
        }
    });
};

export const createTimelineProjection = graph => {
    requireGraphArrays(graph);
    const nodesById = new Map(graph.nodes.map(node => [node.id, node]));
    const nodeIds = new Set(nodesById.keys());
    const coverageDomains = coverageDomainsBySource(graph);
    const sourceItems = graph.sources.map((source, index) => (
        sourceItem(source, index, coverageDomains, nodeIds)
    ));
    const sourceItemsById = new Map(sourceItems.map(item => [item.recordId, item]));
    const observationItems = graph.observations.map((observation, index) => (
        observationItem(observation, index, nodesById, sourceItemsById)
    ));
    const observationsByNodeId = new Map();
    observationItems.forEach(item => {
        item.relatedNodeIds.forEach(nodeId => {
            if (!observationsByNodeId.has(nodeId)) observationsByNodeId.set(nodeId, []);
            observationsByNodeId.get(nodeId).push(item);
        });
    });
    const nodeItems = graph.nodes.map((node, index) => (
        nodeItem(node, index, observationsByNodeId.get(node.id) || [], sourceItemsById)
    ));
    const items = [...sourceItems, ...observationItems, ...nodeItems].sort(compareItems);
    const timedItems = items.filter(item => item.temporalKind !== 'untimed');
    const minimum = timedItems.length
        ? minTimestamp(timedItems.map(item => ({ at: item.startAt, ms: item.startMs })))
        : null;
    const maximum = timedItems.length
        ? maxTimestamp(timedItems.map(item => ({ at: item.endAt, ms: item.endMs })))
        : null;
    const extent = minimum && maximum ? Object.freeze({
        startMs: minimum.ms,
        endMs: maximum.ms,
        startAt: new Date(minimum.ms).toISOString(),
        endAt: new Date(maximum.ms).toISOString(),
        durationMs: maximum.ms - minimum.ms,
    }) : null;
    const representedDomains = new Set(items.map(item => item.domain));
    const domains = TIMELINE_DOMAINS.filter(domain => representedDomains.has(domain));
    const stats = Object.freeze({
        total: items.length,
        timed: timedItems.length,
        point: items.filter(item => item.temporalKind === 'point').length,
        interval: items.filter(item => item.temporalKind === 'interval').length,
        untimed: items.filter(item => item.temporalKind === 'untimed').length,
        aggregated: items.filter(item => item.aggregation.aggregated).length,
    });
    return Object.freeze({
        items: freezeArray(items),
        extent,
        domains: freezeArray(domains),
        stats,
    });
};

const includeTimedItem = (item, cursorMs, mode, windowMs) => {
    if (mode === 'cumulative') {
        return item.startMs <= cursorMs;
    }
    if (mode === 'window') {
        return item.startMs <= cursorMs && item.endMs >= cursorMs - windowMs;
    }
    return item.startMs <= cursorMs && item.endMs >= cursorMs;
};

const sortedIds = values => freezeArray([...values].sort());

export const selectTimelineActivity = (projection, {
    cursorMs,
    mode = 'cumulative',
    windowMs = 0,
    domains = null,
    includeUntimed = false,
} = {}) => {
    if (!projection || !Array.isArray(projection.items)) {
        throw new TypeError('projection.items must be an array');
    }
    if (!Number.isFinite(cursorMs)) {
        throw new TypeError('cursorMs must be a finite epoch millisecond value');
    }
    if (!['overlap', 'cumulative', 'window'].includes(mode)) {
        throw new TypeError('mode must be overlap, cumulative, or window');
    }
    if (!Number.isFinite(windowMs) || windowMs < 0) {
        throw new TypeError('windowMs must be a non-negative finite number');
    }
    let domainSet = null;
    if (domains !== null) {
        if (!Array.isArray(domains) && !(domains instanceof Set)) {
            throw new TypeError('domains must be an array, Set, or null');
        }
        domainSet = new Set(domains);
    }
    const selected = projection.items.filter(item => {
        if (domainSet && !domainSet.has(item.domain)) return false;
        if (item.temporalKind === 'untimed') return includeUntimed;
        return includeTimedItem(item, cursorMs, mode, windowMs);
    });
    const observationIds = new Set();
    const nodeIds = new Set();
    const sourceIds = new Set();
    selected.forEach(item => {
        if (item.recordType === 'observation') observationIds.add(item.recordId);
        if (item.recordType === 'node') nodeIds.add(item.recordId);
        if (item.recordType === 'source') sourceIds.add(item.recordId);
        item.relatedNodeIds.forEach(id => nodeIds.add(id));
    });
    const bounds = Object.freeze({
        startMs: mode === 'cumulative' ? null : mode === 'window' ? cursorMs - windowMs : cursorMs,
        endMs: cursorMs,
    });
    return Object.freeze({
        items: freezeArray(selected),
        itemIds: sortedIds(selected.map(item => item.id)),
        observationIds: sortedIds(observationIds),
        nodeIds: sortedIds(nodeIds),
        sourceIds: sortedIds(sourceIds),
        mode,
        cursorMs,
        windowMs,
        bounds,
    });
};
