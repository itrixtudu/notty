import { describe, expect, it } from 'vitest';
import { createSampleSemanticGraph, materializeDecisionSet } from '../policy-review/semanticGraph';
import { createPolicyReviewState, policyReviewReducer } from '../policy-review/reviewStore';
import { reviewSnapshot, reviewFingerprint, validateReviewDraft, validateSavedDecisionSet, applyReviewCommand } from '../policy-review/savedReview';

describe('saved review workflow', () => {
    it('restores graph-bound drafts and rejects foreign or malformed decisions', () => {
        const state = createPolicyReviewState(createSampleSemanticGraph());
        const draft = reviewSnapshot(state);
        expect(validateReviewDraft(draft, state.graph)).toEqual(draft);
        const restored = policyReviewReducer(state, { type: 'RESTORE_REVIEW', document: { ...draft, profileName: 'Selected endpoints' } });
        expect(restored.profileName).toBe('Selected endpoints');
        expect(reviewFingerprint(restored)).not.toBe(reviewFingerprint(state));
        expect(() => validateReviewDraft({ ...draft, graphContentDigest: 'other' }, state.graph)).toThrow();
        expect(() => validateReviewDraft({ ...draft, decisions: {} }, state.graph)).toThrow();
    });
    it('validates exported selections by digest and detects edited JSON', async () => {
        const state = createPolicyReviewState(createSampleSemanticGraph());
        state.reviewer = 'Operator'; state.reviewerAcknowledged = true;
        for (const decision of Object.values(state.decisions)) {
            decision.disposition = 'reject'; decision.rationale = 'Not needed by this workspace';
        }
        const document = await materializeDecisionSet({ ...state, allowBlockedReview: true });
        await expect(validateSavedDecisionSet(document, state.graph)).resolves.toEqual(document);
        await expect(validateSavedDecisionSet({ ...document, reviewer: 'Changed' }, state.graph)).rejects.toThrow(/digest/);
    });
    it('quotes host paths and binds Apply to the exact saved digest', () => {
        const digest = `sha256:${'a'.repeat(64)}`;
        expect(applyReviewCommand({ runtimeCandidate: '/candidate', launcher: "/home/it's/scripts/nosh.sh", directory: '/review session' }, digest))
            .toBe(`'/home/it'"'"'s/scripts/nosh.sh' net apply --review '/review session' --decision-digest '${digest}'`);
        expect(applyReviewCommand({ runtimeCandidate: null }, digest)).toBe('');
    });
});
