import { describe, expect, it } from 'vitest';

import { createSampleSemanticGraph } from '../policy-review/semanticGraph';
import {
    createPolicyReviewState,
    createTimelineViewState,
    policyReviewReducer,
} from '../policy-review/reviewStore';

const START_MS = Date.parse('2026-08-16T12:00:00.000Z');
const END_MS = Date.parse('2026-08-16T12:00:10.000Z');

const graphWithoutExtent = () => {
    const graph = createSampleSemanticGraph();
    graph.sources = graph.sources.map(({ observedFrom, observedTo, ...source }) => source);
    graph.nodes = graph.nodes.map(node => {
        const { startedAt, endedAt, completedAt, ...properties } = node.properties;
        return { ...node, properties };
    });
    graph.observations = graph.observations.map(({
        firstObservedAt,
        lastObservedAt,
        ...observation
    }) => observation);
    return graph;
};

const graphWithExtent = (startMs = START_MS, endMs = END_MS) => {
    const graph = graphWithoutExtent();
    graph.observations = graph.observations.map((observation, index) => (
        index === 0
            ? {
                ...observation,
                firstObservedAt: new Date(startMs).toISOString(),
                lastObservedAt: new Date(endMs).toISOString(),
            }
            : observation
    ));
    return graph;
};

const reduce = (state, action) => policyReviewReducer(state, action);

describe('policy review timeline state', () => {
    it('ships a timestamped example that demonstrates the timeline immediately', () => {
        const timeline = createTimelineViewState(createSampleSemanticGraph());

        expect(timeline).toMatchObject({
            startMs: START_MS,
            endMs: START_MS + 8000,
            cursorMs: START_MS + 8000,
            playing: false,
        });
    });

    it('initializes a timestamped graph at the end of its review extent', () => {
        const timeline = createTimelineViewState(graphWithExtent());

        expect(timeline).toMatchObject({
            startMs: START_MS,
            endMs: END_MS,
            cursorMs: END_MS,
            playing: false,
            speed: 1,
            mode: 'cumulative',
            domains: null,
        });
        expect(timeline.windowMs).toBe(1000);
    });

    it('starts from the beginning at the end and otherwise resumes in place', () => {
        const initial = createPolicyReviewState(graphWithExtent());
        const restarted = reduce(initial, { type: 'SET_TIMELINE_PLAYING', playing: true });

        expect(restarted.timeline).toMatchObject({
            cursorMs: START_MS,
            playing: true,
        });

        const pausedMidway = {
            ...restarted,
            timeline: {
                ...restarted.timeline,
                cursorMs: START_MS + 2500,
                playing: false,
            },
        };
        const resumed = reduce(pausedMidway, { type: 'SET_TIMELINE_PLAYING', playing: true });
        expect(resumed.timeline).toMatchObject({
            cursorMs: START_MS + 2500,
            playing: true,
        });
    });

    it('scrubbing clamps to the extent and always pauses playback', () => {
        const initial = createPolicyReviewState(graphWithExtent());
        const playing = {
            ...initial,
            timeline: { ...initial.timeline, cursorMs: START_MS + 5000, playing: true },
        };

        const beforeStart = reduce(playing, {
            type: 'SET_TIMELINE_CURSOR',
            cursorMs: START_MS - 1,
        });
        expect(beforeStart.timeline).toMatchObject({ cursorMs: START_MS, playing: false });

        const afterEnd = reduce(playing, {
            type: 'SET_TIMELINE_CURSOR',
            cursorMs: END_MS + 1,
        });
        expect(afterEnd.timeline).toMatchObject({ cursorMs: END_MS, playing: false });

        const invalid = reduce(playing, {
            type: 'SET_TIMELINE_CURSOR',
            cursorMs: Number.NaN,
        });
        expect(invalid.timeline).toMatchObject({ cursorMs: START_MS + 5000, playing: false });
    });

    it('rewinds to the start and pauses', () => {
        const initial = createPolicyReviewState(graphWithExtent());
        const playing = {
            ...initial,
            timeline: { ...initial.timeline, cursorMs: START_MS + 7000, playing: true },
        };

        const rewound = reduce(playing, { type: 'REWIND_TIMELINE' });
        expect(rewound.timeline).toMatchObject({ cursorMs: START_MS, playing: false });
    });

    it('ignores invalid playback, mode, window, domain, and elapsed-time actions', () => {
        const initial = createPolicyReviewState(graphWithExtent());
        const playing = {
            ...initial,
            timeline: { ...initial.timeline, cursorMs: START_MS, playing: true },
        };

        expect(reduce(initial, { type: 'SET_TIMELINE_SPEED', speed: 4 })).toBe(initial);
        expect(reduce(initial, { type: 'SET_TIMELINE_SPEED', speed: '1' })).toBe(initial);
        expect(reduce(initial, { type: 'SET_TIMELINE_MODE', mode: 'future' })).toBe(initial);
        expect(reduce(initial, { type: 'SET_TIMELINE_WINDOW_MS', windowMs: 0 })).toBe(initial);
        expect(reduce(initial, {
            type: 'TOGGLE_TIMELINE_DOMAIN',
            domain: 'unknown',
            availableDomains: ['unknown'],
        })).toBe(initial);
        expect(reduce(playing, { type: 'ADVANCE_TIMELINE', elapsedMs: 0 })).toBe(playing);
        expect(reduce(playing, { type: 'ADVANCE_TIMELINE', elapsedMs: Number.NaN })).toBe(playing);
    });

    it('advances by playback speed, then clamps and stops at the end', () => {
        const initial = createPolicyReviewState(graphWithExtent());
        const playing = {
            ...initial,
            timeline: {
                ...initial.timeline,
                cursorMs: START_MS,
                playing: true,
                speed: 2,
            },
        };

        const advanced = reduce(playing, { type: 'ADVANCE_TIMELINE', elapsedMs: 1250 });
        expect(advanced.timeline).toMatchObject({
            cursorMs: START_MS + 2500,
            playing: true,
        });

        const completed = reduce(advanced, { type: 'ADVANCE_TIMELINE', elapsedMs: 60_000 });
        expect(completed.timeline).toMatchObject({ cursorMs: END_MS, playing: false });
    });

    it('reconciles a live delta without resetting review controls', () => {
        const initial = createPolicyReviewState(graphWithExtent());
        const configured = {
            ...initial,
            timeline: {
                ...initial.timeline,
                cursorMs: START_MS + 2000,
                playing: true,
                speed: 0.5,
                mode: 'window',
                windowMs: 8000,
                domains: ['network'],
            },
        };
        const narrowedGraph = graphWithExtent(START_MS + 5000, START_MS + 7000);

        const reconciled = reduce(configured, { type: 'APPLY_DELTA', graph: narrowedGraph });
        expect(reconciled.timeline).toEqual({
            startMs: START_MS + 5000,
            endMs: START_MS + 7000,
            cursorMs: START_MS + 5000,
            playing: false,
            speed: 0.5,
            mode: 'window',
            windowMs: 2000,
            domains: ['network'],
        });

        const withoutTimedEvidence = reduce(configured, {
            type: 'APPLY_DELTA',
            graph: graphWithoutExtent(),
        });
        expect(withoutTimedEvidence.timeline).toEqual({
            startMs: null,
            endMs: null,
            cursorMs: null,
            playing: false,
            speed: 0.5,
            mode: 'window',
            windowMs: 8000,
            domains: ['network'],
        });
    });

    it('keeps a playhead pinned to the end when a live delta extends the graph', () => {
        const initial = createPolicyReviewState(graphWithExtent());
        const extendedEnd = END_MS + 5000;

        const reconciled = reduce(initial, {
            type: 'APPLY_DELTA',
            graph: graphWithExtent(START_MS, extendedEnd),
        });

        expect(reconciled.timeline).toMatchObject({
            startMs: START_MS,
            endMs: extendedEnd,
            cursorMs: extendedEnd,
            playing: false,
        });
    });
});
