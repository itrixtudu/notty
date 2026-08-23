const matchNetworkTransport = (identity, transport) => {
    if (!transport || identity.protocol !== transport.protocol) {
        return false;
    }
    if (transport.protocol === 'tcp' || transport.protocol === 'udp') {
        return transport.ports?.length === 1 && identity.port === transport.ports[0];
    }
    if (!['icmp', 'icmpv6'].includes(transport.protocol) || transport.ports?.length !== 0 || identity.port !== null) {
        return false;
    }
    return identity.icmpType === (transport.icmpType ?? null)
        && identity.icmpCode === (transport.icmpCode ?? null);
};

const matchesPeer = (node, intent) => {
    const peer = intent?.peer;
    if (!peer || typeof peer.value !== 'string') {
        return false;
    }
    if (peer.kind === 'fqdn') {
        return node.nodeType === 'domain' && node.identity?.fqdn === peer.value;
    }
    if (peer.kind === 'path') {
        return node.nodeType === 'file' && node.identity?.path === peer.value;
    }
    if (peer.kind === 'executable') {
        return node.nodeType === 'executable' && node.identity?.executable === peer.value;
    }
    if (peer.kind === 'syscall') {
        return node.nodeType === 'syscall' && node.identity?.number === peer.value;
    }
    if (!['ipv4', 'ipv4-cidr', 'ipv6', 'ipv6-cidr'].includes(peer.kind)) {
        return false;
    }
    const separator = peer.value.lastIndexOf('/');
    const address = separator === -1 ? peer.value : peer.value.slice(0, separator);
    const prefix = separator === -1 ? undefined : peer.value.slice(separator + 1);
    const exactPrefix = peer.kind.startsWith('ipv6') ? '128' : '32';
    if (
        (!peer.kind.endsWith('-cidr') && prefix !== undefined)
        || (peer.kind.endsWith('-cidr') && prefix !== exactPrefix)
    ) {
        return false;
    }
    return node.nodeType === 'networkEndpoint'
        && node.identity?.address === address
        && matchNetworkTransport(node.identity, intent.transport);
};

const deriveExactPeerNodeId = (graph, proposal) => {
    const matches = graph.nodes.filter(node => matchesPeer(node, proposal.intent));
    return matches.length === 1 ? matches[0].id : null;
};

export const deriveProposalNodeLinks = (graph, proposal) => {
    const nodeIds = new Set(graph.nodes.map(node => node.id));
    const links = [];
    const add = (nodeId, relation) => {
        if (nodeIds.has(nodeId) && !links.some(link => link.nodeId === nodeId)) {
            links.push({ nodeId, relation });
        }
    };
    add(proposal.intent?.subjectId, 'subject');
    add(deriveExactPeerNodeId(graph, proposal), 'peer');
    (proposal.evidenceRefs || []).forEach(nodeId => add(nodeId, 'evidence'));
    return links;
};

const selectionKey = selection => `${selection.type}:${selection.id}`;

const compareSelections = (left, right) => selectionKey(left).localeCompare(selectionKey(right));

export const resolveAllowProposalSelection = (graph, selections = []) => {
    const proposalsById = new Map(graph.proposals.map(proposal => [proposal.id, proposal]));
    const proposalsByObservationId = new Map();
    const proposalsByPeerNodeId = new Map();
    graph.proposals.forEach(proposal => {
        (proposal.observationRefs || []).forEach(observationId => {
            if (!proposalsByObservationId.has(observationId)) {
                proposalsByObservationId.set(observationId, []);
            }
            proposalsByObservationId.get(observationId).push(proposal);
        });
        deriveProposalNodeLinks(graph, proposal)
            .filter(link => link.relation === 'peer')
            .forEach(link => {
                if (!proposalsByPeerNodeId.has(link.nodeId)) {
                    proposalsByPeerNodeId.set(link.nodeId, []);
                }
                proposalsByPeerNodeId.get(link.nodeId).push(proposal);
            });
    });

    const uniqueSelections = new Map();
    selections.forEach(selection => {
        if (
            selection
            && ['proposal', 'observation', 'node'].includes(selection.type)
            && typeof selection.id === 'string'
        ) {
            uniqueSelections.set(selectionKey(selection), {
                type: selection.type,
                id: selection.id,
            });
        }
    });

    const allowProposalIds = new Set();
    const resolvedSelections = [];
    const unsupportedSelections = [];
    [...uniqueSelections.values()].sort(compareSelections).forEach(selection => {
        const candidates = selection.type === 'proposal'
            ? [proposalsById.get(selection.id)].filter(Boolean)
            : selection.type === 'observation'
                ? (proposalsByObservationId.get(selection.id) || [])
                : (proposalsByPeerNodeId.get(selection.id) || []);
        const allowed = candidates
            .filter(proposal => proposal.intent?.effect === 'allow')
            .map(proposal => proposal.id)
            .sort();
        if (allowed.length === 0) {
            unsupportedSelections.push({
                ...selection,
                reason: candidates.length
                    ? 'linked proposal is not an allow intent'
                    : 'selection has no exact digest-bound allow proposal',
            });
            return;
        }
        allowed.forEach(proposalId => allowProposalIds.add(proposalId));
        resolvedSelections.push({ ...selection, proposalIds: allowed });
    });

    return Object.freeze({
        allowProposalIds: Object.freeze([...allowProposalIds].sort()),
        resolvedSelections: Object.freeze(resolvedSelections.map(entry => Object.freeze({
            ...entry,
            proposalIds: Object.freeze([...entry.proposalIds]),
        }))),
        unsupportedSelections: Object.freeze(unsupportedSelections.map(Object.freeze)),
    });
};
