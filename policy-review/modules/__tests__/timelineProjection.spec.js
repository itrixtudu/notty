import { describe, expect, it } from 'vitest';

import {
    TIMELINE_DOMAINS,
    createTimelineProjection,
    parseRfc3339Timestamp,
    selectTimelineActivity,
} from '../policy-review/timelineProjection';

const clone = value => JSON.parse(JSON.stringify(value));
const at = seconds => `2026-08-16T12:00:${String(seconds).padStart(2, '0')}.000Z`;

const createFixture = () => ({
    sources: [
        {
            id: 'source:network',
            sourceName: 'ebpf-network',
            artifactKind: 'NoshBuildEvidence',
            observedFrom: at(0),
            observedTo: at(10),
        },
        {
            id: 'source:build',
            sourceName: 'buildx-history',
            artifactKind: 'NoshBuildEvidence',
        },
    ],
    nodes: [
        {
            id: 'node:run',
            nodeType: 'buildRun',
            label: 'build run',
            properties: { startedAt: at(1), endedAt: at(9) },
            evidenceRefs: ['source:build'],
        },
        {
            id: 'node:vertex',
            nodeType: 'buildkitVertex',
            label: 'RUN npm ci',
            properties: { startedAt: at(2), completedAt: at(2) },
            evidenceRefs: ['source:build'],
        },
        {
            id: 'node:process',
            nodeType: 'process',
            label: 'node',
            properties: {},
            evidenceRefs: ['source:network'],
        },
        {
            id: 'node:endpoint',
            nodeType: 'networkEndpoint',
            label: '192.0.2.1:443',
            properties: {},
            evidenceRefs: ['source:network'],
        },
        {
            id: 'node:executable',
            nodeType: 'executable',
            label: '/usr/local/bin/node',
            properties: {},
            evidenceRefs: ['source:network'],
        },
        {
            id: 'node:file',
            nodeType: 'file',
            label: '/app/package-lock.json',
            properties: { firstSeenAt: '1970-01-01T00:00:00Z' },
            evidenceRefs: ['source:network'],
        },
        {
            id: 'node:orphan',
            nodeType: 'policySet',
            label: 'untimed policy context',
            properties: {},
            evidenceRefs: ['source:build'],
        },
    ],
    observations: [
        {
            id: 'observation:flow',
            observationType: 'connects',
            subjectId: 'node:process',
            objectId: 'node:endpoint',
            count: '4',
            firstObservedAt: at(3),
            lastObservedAt: at(5),
            evidenceRefs: ['source:network'],
        },
        {
            id: 'observation:exec',
            observationType: 'executes',
            subjectId: 'node:process',
            objectId: 'node:executable',
            count: '1',
            firstObservedAt: at(4),
            lastObservedAt: at(4),
            evidenceRefs: ['source:network'],
        },
        {
            id: 'observation:file',
            observationType: 'accesses',
            subjectId: 'node:process',
            objectId: 'node:file',
            count: '12',
            evidenceRefs: ['source:network'],
        },
        {
            id: 'observation:contains',
            observationType: 'contains',
            subjectId: 'node:run',
            objectId: 'node:orphan',
            count: '1',
            evidenceRefs: ['source:build'],
        },
    ],
    coverage: [
        { domain: 'network', sourceIds: ['source:network'] },
        { domain: 'buildkit-progress', sourceIds: ['source:build'] },
    ],
});

const findItem = (projection, recordType, recordId) => projection.items.find(item => (
    item.recordType === recordType && item.recordId === recordId
));

describe('timeline projection', () => {
    it('strictly parses RFC 3339 instants without normalizing invalid dates', () => {
        expect(parseRfc3339Timestamp('2026-08-16T12:00:00.123456789Z')).toBe(
            Date.parse('2026-08-16T12:00:00.123Z'),
        );
        expect(parseRfc3339Timestamp('2026-08-16T14:30:00+02:30')).toBe(
            Date.parse('2026-08-16T12:00:00Z'),
        );
        expect(parseRfc3339Timestamp('2024-02-29T00:00:00Z')).toBe(
            Date.parse('2024-02-29T00:00:00Z'),
        );

        [
            '2026-02-29T00:00:00Z',
            '2026-02-30T00:00:00Z',
            '2026-08-16 12:00:00Z',
            '2026-08-16T12:00:00',
            '2026-08-16T24:00:00Z',
            '2026-08-16T12:00:60Z',
            '2026-08-16T12:00:00z',
        ].forEach(value => {
            expect(() => parseRfc3339Timestamp(value)).toThrow('strict RFC 3339');
        });
    });

    it('projects source coverage, observations, structural nodes, and explicit untimed context', () => {
        const graph = createFixture();
        const before = clone(graph);
        const projection = createTimelineProjection(graph);

        expect(graph).toEqual(before);
        expect(TIMELINE_DOMAINS).toEqual([
            'build', 'process', 'filesystem', 'syscall', 'dns', 'network', 'package', 'other',
        ]);
        expect(projection.domains).toEqual(['build', 'process', 'filesystem', 'network', 'other']);
        expect(projection.extent).toEqual({
            startMs: Date.parse(at(0)),
            endMs: Date.parse(at(10)),
            startAt: at(0),
            endAt: at(10),
            durationMs: 10000,
        });
        expect(projection.stats).toEqual({
            total: 13,
            timed: 8,
            point: 3,
            interval: 5,
            untimed: 5,
            aggregated: 3,
        });

        expect(findItem(projection, 'source', 'source:network')).toMatchObject({
            domain: 'network',
            temporalKind: 'interval',
            precision: { kind: 'capture-window', basis: 'source-bounds' },
            aggregation: {
                semantics: 'capture-window-not-event-activity',
                representsContinuousActivity: false,
            },
        });
        expect(findItem(projection, 'observation', 'observation:flow')).toMatchObject({
            domain: 'network',
            temporalKind: 'interval',
            precision: { kind: 'recorded-range', basis: 'observation-bounds' },
            aggregation: {
                aggregated: true,
                count: '4',
                semantics: 'occurrence-envelope-not-continuous-activity',
                representsContinuousActivity: false,
            },
        });
        expect(findItem(projection, 'observation', 'observation:file')).toMatchObject({
            domain: 'filesystem',
            temporalKind: 'untimed',
            startMs: null,
            precision: { kind: 'untimed', basis: 'none' },
            aggregation: { count: '12', semantics: 'untimed-context' },
        });
        expect(findItem(projection, 'node', 'node:run')).toMatchObject({
            domain: 'build',
            temporalKind: 'interval',
            precision: { kind: 'structural-metadata' },
            aggregation: { representsContinuousActivity: true },
        });
        expect(findItem(projection, 'node', 'node:process')).toMatchObject({
            temporalKind: 'interval',
            precision: { kind: 'related-observation-envelope' },
            aggregation: {
                aggregated: true,
                count: '2',
                representsContinuousActivity: false,
            },
        });
        expect(findItem(projection, 'node', 'node:file')).toMatchObject({
            temporalKind: 'untimed',
            precision: { kind: 'untimed' },
        });
    });

    it('is deterministic regardless of source record ordering', () => {
        const graph = createFixture();
        const reversed = {
            ...clone(graph),
            sources: clone(graph.sources).reverse(),
            nodes: clone(graph.nodes).reverse(),
            observations: clone(graph.observations).reverse(),
            coverage: clone(graph.coverage).reverse(),
        };

        expect(createTimelineProjection(reversed)).toEqual(createTimelineProjection(graph));
    });

    it('labels one-sided observation timestamps as partial boundaries', () => {
        const graph = createFixture();
        delete graph.observations[1].lastObservedAt;
        const item = findItem(
            createTimelineProjection(graph),
            'observation',
            'observation:exec',
        );

        expect(item).toMatchObject({
            temporalKind: 'point',
            precision: {
                kind: 'recorded-start-boundary',
                boundary: 'start',
                fields: ['firstObservedAt'],
            },
            aggregation: {
                semantics: 'partial-occurrence-bound-not-complete-range',
                representsContinuousActivity: false,
            },
        });
    });

    it('selects inclusive overlap, cumulative, and trailing-window activity', () => {
        const projection = createTimelineProjection(createFixture());
        const cumulative = selectTimelineActivity(projection, {
            cursorMs: Date.parse(at(4)),
            mode: 'cumulative',
        });
        const overlap = selectTimelineActivity(projection, {
            cursorMs: Date.parse(at(6)),
            mode: 'overlap',
        });
        const windowed = selectTimelineActivity(projection, {
            cursorMs: Date.parse(at(6)),
            mode: 'window',
            windowMs: 2000,
        });

        expect(cumulative.observationIds).toEqual(['observation:exec', 'observation:flow']);
        expect(cumulative.nodeIds).not.toContain('node:file');
        expect(cumulative.bounds).toEqual({ startMs: null, endMs: Date.parse(at(4)) });
        expect(overlap.observationIds).toEqual([]);
        expect(overlap.nodeIds).toEqual(['node:run']);
        expect(windowed.observationIds).toEqual(['observation:exec', 'observation:flow']);
        expect(windowed.bounds).toEqual({
            startMs: Date.parse(at(4)),
            endMs: Date.parse(at(6)),
        });
    });

    it('filters domains and only includes untimed context when explicitly requested', () => {
        const projection = createTimelineProjection(createFixture());
        const network = selectTimelineActivity(projection, {
            cursorMs: Date.parse(at(6)),
            mode: 'window',
            windowMs: 2000,
            domains: new Set(['network']),
        });
        const filesystem = selectTimelineActivity(projection, {
            cursorMs: Date.parse(at(6)),
            mode: 'overlap',
            domains: ['filesystem'],
            includeUntimed: true,
        });

        expect(network.items.every(item => item.domain === 'network')).toBe(true);
        expect(network.observationIds).toEqual(['observation:flow']);
        expect(network.nodeIds).toEqual(['node:endpoint', 'node:process']);
        expect(filesystem.observationIds).toEqual(['observation:file']);
        expect(filesystem.nodeIds).toEqual(['node:file', 'node:process']);
        expect(filesystem.items.every(item => item.domain === 'filesystem')).toBe(true);
    });

    it('degrades invalid optional timing metadata to honest untimed records', () => {
        const graph = createFixture();
        graph.sources[0].observedFrom = '2026-02-30T00:00:00Z';
        graph.observations[0].lastObservedAt = '2026-08-16T12:00:99Z';
        graph.nodes[0].properties.startedAt = 'not-a-timestamp';
        const projection = createTimelineProjection(graph);

        expect(findItem(projection, 'source', 'source:network')).toMatchObject({
            temporalKind: 'untimed',
            precision: {
                kind: 'invalid-source-bounds',
                basis: 'source-bounds',
                diagnostics: [expect.stringContaining('strict RFC 3339')],
            },
        });
        expect(findItem(projection, 'observation', 'observation:flow')).toMatchObject({
            temporalKind: 'untimed',
            precision: {
                kind: 'invalid-observation-bounds',
                diagnostics: [expect.stringContaining('strict RFC 3339')],
            },
        });
        expect(findItem(projection, 'node', 'node:run')).toMatchObject({
            temporalKind: 'untimed',
            precision: {
                kind: 'invalid-structural-metadata',
                diagnostics: [expect.stringContaining('strict RFC 3339')],
            },
        });
        expect(findItem(projection, 'node', 'node:endpoint').temporalKind).toBe('untimed');
    });

    it('never substitutes epoch time for records with no canonical bounds', () => {
        const graph = {
            sources: [{ id: 'source:untimed', artifactKind: 'UnknownCapture' }],
            nodes: [{
                id: 'node:untimed',
                nodeType: 'file',
                label: 'context',
                properties: { timestamp: '1970-01-01T00:00:00Z' },
                evidenceRefs: ['source:untimed'],
            }],
            observations: [],
            coverage: [],
        };
        const projection = createTimelineProjection(graph);

        expect(projection.extent).toBeNull();
        expect(projection.stats).toMatchObject({ timed: 0, untimed: 2 });
        expect(projection.items.every(item => (
            item.temporalKind === 'untimed' && item.startMs === null && item.endMs === null
        ))).toBe(true);
    });

    it('indexes related observations for high-cardinality profiles', () => {
        const count = 5000;
        const nodes = Array.from({ length: count }, (_, index) => ({
            id: `node:${index}`,
            nodeType: 'process',
            label: `process ${index}`,
            properties: {},
            evidenceRefs: [],
        }));
        const observations = Array.from({ length: count }, (_, index) => ({
            id: `observation:${index}`,
            observationType: 'executes',
            subjectId: `node:${index}`,
            objectId: `node:${index}`,
            count: '1',
            firstObservedAt: at(1),
            lastObservedAt: at(1),
            evidenceRefs: [],
        }));

        const projection = createTimelineProjection({
            sources: [],
            nodes,
            observations,
            coverage: [],
        });

        expect(projection.stats).toEqual({
            total: count * 2,
            timed: count * 2,
            point: count * 2,
            interval: 0,
            untimed: 0,
            aggregated: 0,
        });
        expect(projection.extent.durationMs).toBe(0);
    });
});
