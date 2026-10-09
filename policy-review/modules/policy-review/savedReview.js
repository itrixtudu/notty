import { browserSha256Digest, POLICY_REVIEW_TARGETS } from './semanticGraph.js';

export const reviewSnapshot = state => ({
    kind: 'NoshPolicyReviewDraft',
    schemaVersion: 1,
    graphContentDigest: state.graph.contentDigest,
    profileName: state.profileName || '',
    reviewer: state.reviewer,
    reviewerAcknowledged: state.reviewerAcknowledged,
    intendedTarget: state.intendedTarget,
    decisions: state.decisions,
});

export const reviewFingerprint = state => JSON.stringify(reviewSnapshot(state));

export function validateReviewDraft(document, graph) {
    if (!graph.frozen || !graph.contentDigest
        || document?.kind !== 'NoshPolicyReviewDraft' || document.schemaVersion !== 1
        || document.graphContentDigest !== graph.contentDigest
        || !POLICY_REVIEW_TARGETS.includes(document.intendedTarget)
        || typeof document.reviewer !== 'string' || document.reviewer.length > 256
        || typeof document.profileName !== 'string' || document.profileName.length > 128
        || typeof document.reviewerAcknowledged !== 'boolean'
        || !document.decisions || Array.isArray(document.decisions)
        || Object.keys(document.decisions).length !== graph.proposals.length) {
        throw new Error('Saved review does not match this frozen graph');
    }
    for (const proposal of graph.proposals) {
        const decision = document.decisions[proposal.id];
        if (!decision || !['accept', 'reject', 'needs-review'].includes(decision.disposition)
            || typeof decision.rationale !== 'string' || decision.rationale.length > 4096
            || !decision.targetAcknowledgements || Array.isArray(decision.targetAcknowledgements)) {
            throw new Error(`Invalid saved decision for ${proposal.id}`);
        }
        const targets = new Map(proposal.targetFeasibility.map(target => [target.target, target]));
        for (const [target, acknowledgement] of Object.entries(decision.targetAcknowledgements)) {
            if (!targets.has(target) || acknowledgement?.status !== targets.get(target).status
                || typeof acknowledgement.acknowledged !== 'boolean'
                || typeof acknowledgement.rationale !== 'string'
                || acknowledgement.rationale.length > 4096) {
                throw new Error(`Invalid saved acknowledgement for ${proposal.id}`);
            }
        }
    }
    return document;
}

export async function validateSavedDecisionSet(document, graph) {
    if (document?.kind !== 'NoshPolicyDecisionSet' || document.schemaVersion !== 1
        || document.graphContentDigest !== graph.contentDigest
        || document.graphDigest !== graph.graphDigest
        || document.scopeDigest !== graph.scope.scopeDigest
        || document.proposalSetDigest !== graph.proposalSetDigest
        || document.basePolicyDigest !== graph.basePolicyDigest
        || typeof document.reviewer !== 'string' || !document.reviewer.trim()
        || document.reviewer.length > 256 || !Array.isArray(document.decisions)
        || document.decisions.length !== graph.proposals.length) {
        throw new Error('DecisionSet does not match this frozen graph');
    }
    const ids = new Set(graph.proposals.map(proposal => proposal.id));
    for (const decision of document.decisions) {
        if (!ids.delete(decision.proposalId)
            || !['accept', 'reject'].includes(decision.disposition)
            || typeof decision.rationale !== 'string' || !decision.rationale.trim()
            || decision.rationale.length > 8192) {
            throw new Error('DecisionSet contains unfinished, duplicate, or foreign decisions');
        }
    }
    const { contentDigest, decisionSetId, ...payload } = document;
    if (contentDigest !== await browserSha256Digest(payload)
        || decisionSetId !== `decision-set:${(await browserSha256Digest(contentDigest)).slice(7)}`) {
        throw new Error('DecisionSet digest does not match its contents');
    }
    return document;
}

export const shellQuote = value => `'${String(value).replace(/'/g, `'"'"'`)}'`;

export function applyReviewCommand(session, digest) {
    if (!session?.runtimeCandidate || !/^sha256:[a-f0-9]{64}$/.test(digest || '')) return '';
    return `${shellQuote(session.launcher)} net apply --review ${shellQuote(session.directory)} --decision-digest ${shellQuote(digest)}`;
}

export function endpointRows(graph) {
    const observations = new Map(graph.observations.map(record => [record.id, record]));
    const nodes = new Map(graph.nodes.map(record => [record.id, record]));
    return graph.proposals.filter(proposal => proposal.intent?.domain === 'network').map(proposal => {
        const evidence = (proposal.observationRefs || []).flatMap(id => {
            const observation = observations.get(id);
            return observation?.properties?.runtimeEvidence
                || nodes.get(observation?.objectId)?.properties?.runtimeEvidence || [];
        });
        const names = [...new Set(evidence.flatMap(record => [
            ...(record.dnsNames || []), ...(record.dnsName ? [record.dnsName] : []),
            ...(record.dnsChain || []).map(answer => answer.dnsName),
        ]).filter(Boolean))].sort();
        const peer = proposal.intent.peer;
        return {
            proposal, id: proposal.id, names,
            address: peer.value,
            protocol: proposal.intent.transport?.protocol || 'any',
            ports: proposal.intent.transport?.ports || [],
            count: evidence.reduce((sum, record) => sum + (Number(record.count) || 1), 0),
            dnsEvidence: evidence.flatMap(record => record.dnsChain || []),
            scope: proposal.scopeClass,
            ipBased: ['ipv4', 'ipv6', 'ipv4-cidr', 'ipv6-cidr'].includes(peer.kind),
        };
    }).sort((left, right) => (left.names[0] || left.address).localeCompare(right.names[0] || right.address)
        || left.id.localeCompare(right.id));
}
