import { describe, expect, it } from 'vitest';

import { createSampleSemanticGraph } from '../policy-review/semanticGraph';
import { resolveAllowProposalSelection } from '../policy-review/proposalDerivation';
import {
    createPolicyReviewState,
    findSelectedRecords,
    policyReviewReducer,
} from '../policy-review/reviewStore';

const reduce = (state, action) => policyReviewReducer(state, action);

describe('policy review record selection', () => {
    it('tracks a primary inspector record and an ordered generic selection', () => {
        const graph = createSampleSemanticGraph();
        const node = graph.nodes[0];
        const observation = graph.observations[0];
        let state = createPolicyReviewState(graph);

        state = reduce(state, {
            type: 'SELECT_RECORD',
            record: { type: 'observation', id: observation.id },
        });
        state = reduce(state, {
            type: 'SELECT_RECORD',
            record: { type: 'node', id: node.id },
            toggle: true,
        });

        expect(state.selected).toEqual({ type: 'node', id: node.id });
        expect(state.selectedRecords).toEqual([
            { type: 'node', id: node.id },
            { type: 'observation', id: observation.id },
        ]);
        expect(findSelectedRecords(state).map(entry => entry.record.id)).toEqual([
            node.id,
            observation.id,
        ]);

        state = reduce(state, {
            type: 'SELECT_RECORD',
            record: { type: 'node', id: node.id },
            toggle: true,
        });
        expect(state.selected).toEqual({ type: 'observation', id: observation.id });
        expect(state.selectedRecords).toEqual([
            { type: 'observation', id: observation.id },
        ]);
    });

    it('supports proposal toggle and anchored range selection', () => {
        const graph = createSampleSemanticGraph();
        const [first, second] = graph.proposals;
        let state = createPolicyReviewState(graph);

        state = reduce(state, { type: 'SELECT_PROPOSAL', proposalId: first.id });
        state = reduce(state, {
            type: 'SELECT_PROPOSAL',
            proposalId: second.id,
            range: true,
        });

        expect(state.selected).toEqual({ type: 'proposal', id: second.id });
        expect(state.selectedProposalIds).toEqual([first.id, second.id]);
        expect(state.selectedRecords).toEqual([
            { type: 'proposal', id: first.id },
            { type: 'proposal', id: second.id },
        ]);
        expect(state.proposalSelectionAnchor).toBe(first.id);

        state = reduce(state, {
            type: 'SELECT_PROPOSAL',
            proposalId: first.id,
            toggle: true,
        });
        expect(state.selectedProposalIds).toEqual([second.id]);
    });

    it('select-all, clear, and graph replacement keep selection view-only', () => {
        const graph = createSampleSemanticGraph();
        const initial = createPolicyReviewState(graph);
        const selected = reduce(initial, { type: 'SELECT_ALL_PROPOSALS' });

        expect(selected.graph).toBe(graph);
        expect(selected.decisions).toBe(initial.decisions);
        expect(selected.timeline).toBe(initial.timeline);
        expect(selected.selectedProposalIds).toEqual(graph.proposals.map(proposal => proposal.id));

        const cleared = reduce(selected, { type: 'SELECT', selected: null });
        expect(cleared).toMatchObject({
            selected: null,
            selectedRecords: [],
            selectedProposalIds: [],
            proposalSelectionAnchor: null,
        });

        const unknown = reduce(cleared, {
            type: 'SELECT_RECORD',
            record: { type: 'observation', id: 'observation:missing' },
            toggle: true,
        });
        expect(unknown).toBe(cleared);

        const replaced = reduce(selected, {
            type: 'LOAD_GRAPH',
            graph: createSampleSemanticGraph(),
            sourceLabel: 'replacement',
        });
        expect(replaced.selectedRecords).toEqual([]);
        expect(replaced.selectedProposalIds).toEqual([]);
    });
});

describe('bulk proposal disposition', () => {
    it('accepts an exact allow proposal selected through its telemetry edge', () => {
        const graph = createSampleSemanticGraph();
        const proposal = graph.proposals[0];
        let state = createPolicyReviewState(graph);

        state = reduce(state, {
            type: 'SELECT_RECORD',
            record: { type: 'observation', id: proposal.observationRefs[0] },
        });
        const resolution = resolveAllowProposalSelection(graph, state.selectedRecords);
        expect(resolution.allowProposalIds).toEqual([proposal.id]);
        expect(resolution.unsupportedSelections).toEqual([]);

        const reviewed = reduce(state, {
            type: 'SET_BULK_PROPOSAL_DECISION',
            proposalIds: resolution.allowProposalIds,
            disposition: 'accept',
            rationale: 'The exact observed endpoint and transport are required.',
        });
        expect(reviewed.graph).toBe(graph);
        expect(reviewed.decisions[proposal.id]).toMatchObject({
            disposition: 'accept',
            rationale: 'The exact observed endpoint and transport are required.',
        });
    });

    it('requires a bounded rationale and applies one decision without changing the graph', () => {
        const graph = createSampleSemanticGraph();
        const initial = createPolicyReviewState(graph);
        const proposalIds = graph.proposals.map(proposal => proposal.id);

        expect(reduce(initial, {
            type: 'SET_BULK_PROPOSAL_DECISION',
            proposalIds,
            disposition: 'accept',
            rationale: '   ',
        })).toBe(initial);
        expect(reduce(initial, {
            type: 'SET_BULK_PROPOSAL_DECISION',
            proposalIds,
            disposition: 'invented',
            rationale: 'reviewed',
        })).toBe(initial);

        const reviewed = reduce(initial, {
            type: 'SET_BULK_PROPOSAL_DECISION',
            proposalIds: [...proposalIds].reverse(),
            disposition: 'accept',
            rationale: '  Exact captured behavior is approved.  ',
        });

        expect(reviewed.graph).toBe(graph);
        proposalIds.forEach(proposalId => {
            expect(reviewed.decisions[proposalId]).toMatchObject({
                disposition: 'accept',
                rationale: 'Exact captured behavior is approved.',
            });
        });
    });

    it('can bulk reject or return selected proposals to needs-review', () => {
        const graph = createSampleSemanticGraph();
        const proposalIds = graph.proposals.map(proposal => proposal.id);
        let state = createPolicyReviewState(graph);

        state = reduce(state, {
            type: 'SET_BULK_PROPOSAL_DECISION',
            proposalIds,
            disposition: 'reject',
            rationale: 'Not required by this workload.',
        });
        expect(Object.values(state.decisions).every(decision => decision.disposition === 'reject')).toBe(true);

        state = reduce(state, {
            type: 'SET_BULK_PROPOSAL_DECISION',
            proposalIds,
            disposition: 'needs-review',
            rationale: 'Escalate to the network owner.',
        });
        expect(Object.values(state.decisions).every(decision => (
            decision.disposition === 'needs-review'
            && decision.rationale === 'Escalate to the network owner.'
        ))).toBe(true);
    });
});
