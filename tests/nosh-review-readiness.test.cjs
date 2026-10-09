'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');

test('new graph drafts retain only identical proposals and require fresh acknowledgement', async () => {
  const { rebaseReviewDraft } = await import('../lib/guard/review/session.js');
  const same = { id: 'same', intent: { peer: '203.0.113.1', port: 443 } };
  const changed = { id: 'changed', intent: { peer: '203.0.113.2', port: 443 } };
  const oldGraph = { contentDigest: 'old', proposals: [same, changed] };
  const graph = { contentDigest: 'new', proposals: [same,
    { ...changed, intent: { peer: '203.0.113.2', port: 80 } }, { id: 'new' }] };
  const prior = { kind: 'NoshPolicyReviewDraft', schemaVersion: 1, graphContentDigest: 'old',
    reviewer: 'Operator', reviewerAcknowledged: true, decisions: {
      same: { disposition: 'accept', rationale: 'Expected', targetAcknowledgements: { 'guard-ebpf': { acknowledged: true } } },
      changed: { disposition: 'reject', rationale: 'Unexpected', targetAcknowledgements: {} },
    } };
  const { draft, retained } = rebaseReviewDraft(prior, oldGraph, graph);
  assert.equal(retained, 1);
  assert.equal(draft.graphContentDigest, 'new');
  assert.equal(draft.decisions.same.disposition, 'accept');
  assert.equal(draft.decisions.changed.disposition, 'needs-review');
  assert.equal(draft.decisions.new.disposition, 'needs-review');
  assert.equal(draft.reviewerAcknowledged, false);
  assert.deepEqual(draft.decisions.same.targetAcknowledgements, {});
  assert.equal(prior.reviewerAcknowledged, true);
  assert.throws(() => rebaseReviewDraft({ ...prior, graphContentDigest: 'another' }, oldGraph, graph), /does not match/);
});

test('readiness includes evidence failures even with both inventories present', async () => {
  const { reviewApprovalBlockers } = await import('../lib/guard/review/approval-service.js');
  const review = { graph: { coverage: ['sbom-source', 'sbom-image'].map(domain => ({ domain, status: 'complete' })),
    findings: [{ id: 'lost-evidence', blocking: true }] } };
  assert.deepEqual(reviewApprovalBlockers(review).map(blocker => blocker.code), ['findings']);
  review.graph.findings = [];
  review.graph.coverage.push({ id: 'network', domain: 'network', status: 'incomplete', blocking: true });
  assert.deepEqual(reviewApprovalBlockers(review).map(blocker => blocker.code), ['coverage']);
});

test('Apply source freshness rejects changed, missing, ambiguous or incomplete inventories', async () => {
  const { assertCurrentSourceInventory } = await import('../lib/guard/review/session.js');
  const source = { nodeType: 'evidenceSource', identity: { role: 'source' },
    properties: { collection: { input: { metadataDigest: 'sha256:original' } } } };
  const graph = { nodes: [source] };
  const current = { role: 'source', status: 'complete', input: { metadataDigest: 'sha256:original' } };
  assert.doesNotThrow(() => assertCurrentSourceInventory(graph, current));
  for (const altered of [null, { ...current, status: 'incomplete' }, { ...current, input: { metadataDigest: 'sha256:changed' } }]) {
    assert.throws(() => assertCurrentSourceInventory(graph, altered), /changed or is incomplete/);
  }
  assert.throws(() => assertCurrentSourceInventory({ nodes: [source, source] }, current), /changed or is incomplete/);
});
