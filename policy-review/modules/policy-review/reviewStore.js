import { createContext, createElement, useContext, useMemo, useReducer } from 'react';

import { createSampleSemanticGraph, POLICY_REVIEW_TARGETS } from './semanticGraph';
import { createTimelineProjection, TIMELINE_DOMAINS } from './timelineProjection';
import { validateReviewDraft } from './savedReview';

const PolicyReviewContext = createContext(null);

const createProposalDecisions = graph => Object.fromEntries(
    graph.proposals.map(proposal => [proposal.id, {
        disposition: 'needs-review',
        rationale: '',
        targetAcknowledgements: Object.fromEntries(
            proposal.targetFeasibility
                .filter(target => ['restrictive', 'conditional'].includes(target.status))
                .map(target => [target.target, {
                    acknowledged: false,
                    status: target.status,
                    rationale: '',
                }]),
        ),
    }]),
);

const TIMELINE_SPEEDS = new Set([0.25, 0.5, 1, 2]);
const TIMELINE_MODES = new Set(['cumulative', 'window']);
const PROPOSAL_DISPOSITIONS = new Set(['accept', 'reject', 'needs-review']);
const MAX_REVIEW_RATIONALE_LENGTH = 4096;
const SELECTABLE_RECORD_COLLECTIONS = [
    ['node', 'nodes'],
    ['observation', 'observations'],
    ['proposal', 'proposals'],
    ['coverage', 'coverage'],
    ['finding', 'findings'],
];

const selectionKey = record => `${record.type}:${record.id}`;

const orderedSelectedRecords = (state, records) => {
    const requested = new Set(
        (Array.isArray(records) ? records : [])
            .filter(record => record && typeof record.type === 'string' && typeof record.id === 'string')
            .map(selectionKey),
    );
    return SELECTABLE_RECORD_COLLECTIONS.flatMap(([type, collection]) => (
        (state.graph[collection] || [])
            .filter(record => requested.has(selectionKey({ type, id: record.id })))
            .map(record => ({ type, id: record.id }))
    ));
};

const withSelection = (state, selectedRecords, primary = null, proposalSelectionAnchor = null) => {
    const ordered = orderedSelectedRecords(state, selectedRecords);
    const selectedKeys = new Set(ordered.map(selectionKey));
    const resolvedPrimary = primary && selectedKeys.has(selectionKey(primary))
        ? primary
        : state.selected && selectedKeys.has(selectionKey(state.selected))
            ? state.selected
            : ordered.at(-1) || null;
    const selectedProposalIds = ordered
        .filter(record => record.type === 'proposal')
        .map(record => record.id);
    return {
        ...state,
        selected: resolvedPrimary,
        selectedRecords: ordered,
        selectedProposalIds,
        proposalSelectionAnchor: selectedProposalIds.length ? proposalSelectionAnchor : null,
    };
};

const orderedProposalIds = (state, proposalIds) => {
    const selected = new Set(proposalIds);
    return state.graph.proposals
        .map(proposal => proposal.id)
        .filter(proposalId => selected.has(proposalId));
};

const authorityGroupProposals = (state, authorityGroupId) => (
    typeof authorityGroupId === 'string' && authorityGroupId
        ? state.graph.proposals.filter(proposal => proposal.authorityGroupId === authorityGroupId)
        : []
);

const selectAuthorityVariant = (state, proposalId, rationale = '') => {
    const proposal = state.graph.proposals.find(candidate => candidate.id === proposalId);
    const group = authorityGroupProposals(state, proposal?.authorityGroupId);
    if (!proposal || !group.length || !state.decisions[proposalId]) {
        return state;
    }
    const selectedRationale = String(rationale || '').trim()
        || `Selected ${proposal.assurance?.level || 'reviewed'} authority for this observed web resource.`;
    const decisions = { ...state.decisions };
    for (const candidate of group) {
        const selected = candidate.id === proposalId;
        decisions[candidate.id] = {
            ...decisions[candidate.id],
            disposition: selected ? 'accept' : 'reject',
            rationale: selected
                ? selectedRationale
                : `Rejected as an alternative to selected proposal ${proposalId}.`,
        };
    }
    return { ...state, decisions };
};

const rejectAuthorityGroup = (state, authorityGroupId) => {
    const group = authorityGroupProposals(state, authorityGroupId);
    if (!group.length) return state;
    const decisions = { ...state.decisions };
    for (const proposal of group) {
        decisions[proposal.id] = {
            ...decisions[proposal.id],
            disposition: 'reject',
            rationale: 'Denied all observed authority variants for this web resource.',
        };
    }
    return { ...state, decisions };
};

const selectRecord = (state, action) => {
    const record = action.record || (
        action.proposalId ? { type: 'proposal', id: action.proposalId } : null
    );
    if (!record || orderedSelectedRecords(state, [record]).length !== 1) {
        return state;
    }

    const currentRecords = orderedSelectedRecords(state, state.selectedRecords || []);
    const currentKeys = new Set(currentRecords.map(selectionKey));
    const recordKey = selectionKey(record);
    if (record.type !== 'proposal' || !action.range) {
        let nextRecords;
        if (action.toggle) {
            nextRecords = currentKeys.has(recordKey)
                ? currentRecords.filter(selectedRecord => selectionKey(selectedRecord) !== recordKey)
                : [...currentRecords, record];
        } else {
            nextRecords = [record];
        }
        const nextPrimary = action.toggle && currentKeys.has(recordKey) ? null : record;
        return withSelection(
            state,
            nextRecords,
            nextPrimary,
            record.type === 'proposal' && nextRecords.length
                ? record.id
                : state.proposalSelectionAnchor,
        );
    }

    const proposalIds = state.graph.proposals.map(proposal => proposal.id);
    const proposalIdSet = new Set(proposalIds);
    const proposalId = record.id;
    if (!proposalIdSet.has(proposalId)) {
        return state;
    }

    const anchor = proposalIdSet.has(state.proposalSelectionAnchor)
        ? state.proposalSelectionAnchor
        : state.selected?.type === 'proposal' && proposalIdSet.has(state.selected.id)
            ? state.selected.id
            : proposalId;
    const anchorIndex = proposalIds.indexOf(anchor);
    const proposalIndex = proposalIds.indexOf(proposalId);
    const start = Math.min(anchorIndex, proposalIndex);
    const end = Math.max(anchorIndex, proposalIndex);
    const rangeRecords = proposalIds.slice(start, end + 1)
        .map(id => ({ type: 'proposal', id }));
    const nextRecords = action.toggle ? [...currentRecords, ...rangeRecords] : rangeRecords;
    return withSelection(
        state,
        nextRecords,
        { type: 'proposal', id: proposalId },
        anchor,
    );
};

const resolveTimelineExtent = graph => {
    const extent = createTimelineProjection(graph).extent;
    if (!Number.isFinite(extent?.startMs) || !Number.isFinite(extent?.endMs)) {
        return { startMs: null, endMs: null };
    }
    return {
        startMs: extent.startMs,
        endMs: Math.max(extent.startMs, extent.endMs),
    };
};

const defaultTimelineWindowMs = ({ startMs, endMs }) => {
    if (!Number.isFinite(startMs) || !Number.isFinite(endMs)) {
        return 1000;
    }
    const durationMs = Math.max(1, endMs - startMs);
    return Math.min(durationMs, Math.max(1000, Math.round(durationMs / 10)));
};

export const createTimelineViewState = graph => {
    const extent = resolveTimelineExtent(graph);
    return {
        ...extent,
        cursorMs: extent.endMs,
        playing: false,
        speed: 1,
        mode: 'cumulative',
        windowMs: defaultTimelineWindowMs(extent),
        domains: null,
    };
};

const clampTimelineCursor = (timeline, value) => {
    if (
        !Number.isFinite(value)
        || !Number.isFinite(timeline.startMs)
        || !Number.isFinite(timeline.endMs)
    ) {
        return timeline.cursorMs;
    }
    return Math.min(timeline.endMs, Math.max(timeline.startMs, value));
};

const reconcileTimelineViewState = (timeline, graph) => {
    const next = createTimelineViewState(graph);
    if (!Number.isFinite(next.startMs)) {
        return {
            ...timeline,
            startMs: null,
            endMs: null,
            cursorMs: null,
            playing: false,
        };
    }
    if (!Number.isFinite(timeline.cursorMs)) {
        return {
            ...timeline,
            startMs: next.startMs,
            endMs: next.endMs,
            cursorMs: next.endMs,
            playing: false,
            windowMs: next.windowMs,
        };
    }
    const wasAtEnd = timeline.cursorMs >= timeline.endMs;
    return {
        ...timeline,
        startMs: next.startMs,
        endMs: next.endMs,
        cursorMs: wasAtEnd
            ? next.endMs
            : clampTimelineCursor(next, timeline.cursorMs),
        playing: false,
        windowMs: Math.min(
            Math.max(1, next.endMs - next.startMs),
            Math.max(1, timeline.windowMs),
        ),
    };
};

export const createPolicyReviewState = graph => ({
    graph,
    decisions: createProposalDecisions(graph),
    intendedTarget: graph.scope.class === 'runtime' ? 'guard-ebpf' : POLICY_REVIEW_TARGETS[0],
    profileName: '',
    reviewer: '',
    reviewerAcknowledged: false,
    selected: null,
    // Selection is browser-only review state. The primary `selected` record
    // drives the inspector while the ordered set supports evidence and proposal
    // bulk review without becoming part of an exported decision document.
    selectedRecords: [],
    selectedProposalIds: [],
    proposalSelectionAnchor: null,
    laneFilter: 'All',
    streamPaused: false,
    appliedDeltaCount: 0,
    sourceLabel: 'Built-in signed-baseline example',
    // Timeline controls only affect the browser projection. They are deliberately
    // excluded from policy decisions, decision-set materialization, and digests.
    timeline: createTimelineViewState(graph),
});

export const policyReviewReducer = (state, action) => {
    switch (action.type) {
        case 'SET_PROFILE_NAME':
            return { ...state, profileName: String(action.value).slice(0, 128) };
        case 'RESTORE_REVIEW': {
            const draft = validateReviewDraft(action.document, state.graph);
            return { ...state, profileName: draft.profileName, decisions: draft.decisions,
                reviewer: draft.reviewer, reviewerAcknowledged: draft.reviewerAcknowledged,
                intendedTarget: draft.intendedTarget };
        }
        case 'LOAD_GRAPH':
            return {
                ...createPolicyReviewState(action.graph),
                sourceLabel: action.sourceLabel || 'Imported semantic graph',
            };
        case 'SELECT':
            if (!action.selected) {
                return withSelection(state, []);
            }
            return selectRecord(state, { record: action.selected });
        case 'SELECT_RECORD':
            return selectRecord(state, action);
        case 'SELECT_PROPOSAL':
            return selectRecord(state, action);
        case 'SELECT_ALL_NETWORK_PROPOSALS':
        case 'SELECT_ALL_PROPOSALS': {
            const selectedProposalIds = state.graph.proposals
                .filter(proposal => action.type !== 'SELECT_ALL_NETWORK_PROPOSALS' || proposal.intent?.domain === 'network')
                .map(proposal => proposal.id);
            if (!selectedProposalIds.length) {
                return state;
            }
            const primaryProposalId = (
                state.selected?.type === 'proposal'
                && selectedProposalIds.includes(state.selected.id)
            ) ? state.selected.id : selectedProposalIds[0];
            return withSelection(
                state,
                selectedProposalIds.map(id => ({ type: 'proposal', id })),
                { type: 'proposal', id: primaryProposalId },
                primaryProposalId,
            );
        }
        case 'SET_LANE_FILTER':
            return {
                ...state,
                selected: null,
                selectedRecords: [],
                selectedProposalIds: [],
                proposalSelectionAnchor: null,
                laneFilter: action.laneFilter,
            };
        case 'SET_DISPOSITION':
            if (
                !state.decisions[action.proposalId]
                || !PROPOSAL_DISPOSITIONS.has(action.disposition)
            ) {
                return state;
            }
            if (action.disposition === 'accept') {
                const proposal = state.graph.proposals.find(
                    candidate => candidate.id === action.proposalId,
                );
                if (proposal?.authorityGroupId) {
                    return selectAuthorityVariant(
                        state,
                        action.proposalId,
                        state.decisions[action.proposalId].rationale,
                    );
                }
            }
            return {
                ...state,
                decisions: {
                    ...state.decisions,
                    [action.proposalId]: {
                        ...state.decisions[action.proposalId],
                        disposition: action.disposition,
                    },
                },
            };
        case 'SELECT_AUTHORITY_VARIANT':
            return selectAuthorityVariant(state, action.proposalId, action.rationale);
        case 'REJECT_AUTHORITY_GROUP':
            return rejectAuthorityGroup(state, action.authorityGroupId);
        case 'SET_BULK_PROPOSAL_DECISION': {
            if (!PROPOSAL_DISPOSITIONS.has(action.disposition)) {
                return state;
            }
            const rationale = typeof action.rationale === 'string'
                ? action.rationale.trim()
                : '';
            if (!rationale || rationale.length > MAX_REVIEW_RATIONALE_LENGTH) {
                return state;
            }
            const proposalIds = orderedProposalIds(
                state,
                Array.isArray(action.proposalIds) ? action.proposalIds : [],
            ).filter(proposalId => state.decisions[proposalId]);
            if (!proposalIds.length) {
                return state;
            }
            if (
                action.disposition === 'accept'
                && proposalIds.some(proposalId => state.graph.proposals.find(
                    proposal => proposal.id === proposalId && proposal.authorityGroupId,
                ))
            ) {
                // Web authority alternatives require an explicit per-group choice so a
                // bulk action cannot accidentally accept endpoint, URL, and content
                // variants together.
                return state;
            }
            const decisions = { ...state.decisions };
            proposalIds.forEach(proposalId => {
                decisions[proposalId] = {
                    ...decisions[proposalId],
                    disposition: action.disposition,
                    rationale,
                };
            });
            return {
                ...state,
                decisions,
            };
        }
        case 'SET_RATIONALE':
            if (!state.decisions[action.proposalId]) {
                return state;
            }
            return {
                ...state,
                decisions: {
                    ...state.decisions,
                    [action.proposalId]: {
                        ...state.decisions[action.proposalId],
                        rationale: action.rationale,
                    },
                },
            };
        case 'SET_ACKNOWLEDGED':
            return {
                ...state,
                reviewerAcknowledged: Boolean(action.acknowledged),
            };
        case 'SET_REVIEWER':
            return {
                ...state,
                reviewer: action.reviewer,
            };
        case 'SET_INTENDED_TARGET':
            if (!POLICY_REVIEW_TARGETS.includes(action.intendedTarget)) {
                return state;
            }
            return {
                ...state,
                intendedTarget: action.intendedTarget,
                reviewerAcknowledged: false,
            };
        case 'SET_TARGET_ACKNOWLEDGEMENT':
            if (!state.decisions[action.proposalId]?.targetAcknowledgements?.[action.target]) {
                return state;
            }
            return {
                ...state,
                decisions: {
                    ...state.decisions,
                    [action.proposalId]: {
                        ...state.decisions[action.proposalId],
                        targetAcknowledgements: {
                            ...state.decisions[action.proposalId].targetAcknowledgements,
                            [action.target]: {
                                ...state.decisions[action.proposalId].targetAcknowledgements[action.target],
                                ...action.update,
                            },
                        },
                    },
                },
            };
        case 'SET_STREAM_PAUSED':
            if (state.graph.frozen) {
                return state;
            }
            return {
                ...state,
                streamPaused: Boolean(action.paused),
            };
        case 'SET_TIMELINE_PLAYING': {
            const canPlay = (
                Number.isFinite(state.timeline.startMs)
                && Number.isFinite(state.timeline.endMs)
                && state.timeline.endMs > state.timeline.startMs
            );
            if (!action.playing || !canPlay) {
                return {
                    ...state,
                    timeline: { ...state.timeline, playing: false },
                };
            }
            return {
                ...state,
                timeline: {
                    ...state.timeline,
                    cursorMs: state.timeline.cursorMs >= state.timeline.endMs
                        ? state.timeline.startMs
                        : state.timeline.cursorMs,
                    playing: true,
                },
            };
        }
        case 'ADVANCE_TIMELINE': {
            if (!state.timeline.playing || !Number.isFinite(action.elapsedMs) || action.elapsedMs <= 0) {
                return state;
            }
            const cursorMs = clampTimelineCursor(
                state.timeline,
                state.timeline.cursorMs + action.elapsedMs * state.timeline.speed,
            );
            return {
                ...state,
                timeline: {
                    ...state.timeline,
                    cursorMs,
                    playing: cursorMs < state.timeline.endMs,
                },
            };
        }
        case 'REWIND_TIMELINE':
            return {
                ...state,
                timeline: {
                    ...state.timeline,
                    cursorMs: state.timeline.startMs,
                    playing: false,
                },
            };
        case 'SET_TIMELINE_CURSOR':
            return {
                ...state,
                timeline: {
                    ...state.timeline,
                    cursorMs: clampTimelineCursor(state.timeline, action.cursorMs),
                    playing: false,
                },
            };
        case 'SET_TIMELINE_SPEED':
            if (!TIMELINE_SPEEDS.has(action.speed)) {
                return state;
            }
            return {
                ...state,
                timeline: { ...state.timeline, speed: action.speed },
            };
        case 'SET_TIMELINE_MODE':
            if (!TIMELINE_MODES.has(action.mode)) {
                return state;
            }
            return {
                ...state,
                timeline: { ...state.timeline, mode: action.mode },
            };
        case 'SET_TIMELINE_WINDOW_MS': {
            if (!Number.isFinite(action.windowMs) || action.windowMs <= 0) {
                return state;
            }
            const maximum = Math.max(1, state.timeline.endMs - state.timeline.startMs);
            return {
                ...state,
                timeline: {
                    ...state.timeline,
                    windowMs: Math.min(maximum, Math.max(1, action.windowMs)),
                },
            };
        }
        case 'TOGGLE_TIMELINE_DOMAIN': {
            if (!TIMELINE_DOMAINS.includes(action.domain)) {
                return state;
            }
            const availableDomains = [...new Set(
                Array.isArray(action.availableDomains) ? action.availableDomains : [],
            )]
                .filter(domain => TIMELINE_DOMAINS.includes(domain))
                .sort();
            if (!availableDomains.includes(action.domain)) {
                return state;
            }
            const selectedDomains = state.timeline.domains === null
                ? availableDomains
                : state.timeline.domains;
            const nextDomains = selectedDomains.includes(action.domain)
                ? selectedDomains.filter(domain => domain !== action.domain)
                : [...selectedDomains, action.domain].sort();
            return {
                ...state,
                timeline: {
                    ...state.timeline,
                    domains: nextDomains.length === availableDomains.length ? null : nextDomains,
                },
            };
        }
        case 'RESET_TIMELINE_DOMAINS':
            return {
                ...state,
                timeline: { ...state.timeline, domains: null },
            };
        case 'APPLY_DELTA': {
            const graph = action.graph;
            const nextDecisions = createProposalDecisions(graph);
            Object.keys(nextDecisions).forEach(proposalId => {
                if (state.decisions[proposalId]) {
                    nextDecisions[proposalId] = state.decisions[proposalId];
                }
            });
            return {
                ...state,
                graph,
                decisions: nextDecisions,
                selected: null,
                selectedRecords: [],
                selectedProposalIds: [],
                proposalSelectionAnchor: null,
                reviewerAcknowledged: false,
                appliedDeltaCount: state.appliedDeltaCount + 1,
                timeline: reconcileTimelineViewState(state.timeline, graph),
            };
        }
        default:
            return state;
    }
};

export function PolicyReviewProvider({ children, initialGraph }) {
    const [state, dispatch] = useReducer(
        policyReviewReducer,
        initialGraph,
        graph => createPolicyReviewState(graph || createSampleSemanticGraph()),
    );
    const value = useMemo(() => ({ state, dispatch }), [state]);
    return createElement(PolicyReviewContext.Provider, { value }, children);
}

export const usePolicyReviewStore = () => {
    const store = useContext(PolicyReviewContext);
    if (!store) {
        throw new Error('usePolicyReviewStore must be used inside PolicyReviewProvider');
    }
    return store;
};

export const findRecord = (state, selection) => {
    if (!selection) {
        return null;
    }
    const { type, id } = selection;
    if (type === 'node') {
        return state.graph.nodes.find(record => record.id === id) || null;
    }
    if (type === 'observation') {
        return state.graph.observations.find(record => record.id === id) || null;
    }
    if (type === 'proposal') {
        return state.graph.proposals.find(record => record.id === id) || null;
    }
    if (type === 'coverage') {
        return state.graph.coverage.find(record => record.id === id) || null;
    }
    if (type === 'finding') {
        return state.graph.findings.find(record => record.id === id) || null;
    }
    return null;
};

export const findSelectedRecord = state => findRecord(state, state.selected);

export const findSelectedRecords = state => (state.selectedRecords || [])
    .map(selection => ({ selection, record: findRecord(state, selection) }))
    .filter(entry => entry.record);
