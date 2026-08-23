import { browserSha256Digest, verifySemanticGraphContentDigest } from './semanticGraph.js';

const MAX_SELECTED_PROPOSALS = 1000;
const MAX_SELECTED_SCRIPT_BYTES = 8 * 1024 * 1024;

const EXPORT_CONTEXT_KEYS = new Set([
    'includeMasquerade',
    'sourceIpv4',
    'uplinkInterface',
]);

const assertPlainObject = (value, label) => {
    if (!value || typeof value !== 'object' || Array.isArray(value)) {
        throw new Error(`${label} must be an object`);
    }
};

const freezeJsonValue = value => {
    if (!value || typeof value !== 'object' || Object.isFrozen(value)) {
        return value;
    }
    Object.values(value).forEach(freezeJsonValue);
    return Object.freeze(value);
};

const canonicalize = value => {
    if (value === null || typeof value === 'boolean' || typeof value === 'number' || typeof value === 'string') {
        return JSON.stringify(value);
    }
    if (Array.isArray(value)) {
        return `[${value.map(canonicalize).join(',')}]`;
    }
    return `{${Object.keys(value).sort().map(key => (
        `${JSON.stringify(key)}:${canonicalize(value[key])}`
    )).join(',')}}`;
};

const sha256Digest = browserSha256Digest;

const parseIpv4 = (value, label) => {
    if (typeof value !== 'string' || value.length > 15) {
        throw new Error(`${label} must be an IPv4 address`);
    }
    const pieces = value.split('.');
    if (
        pieces.length !== 4
        || pieces.some(piece => !/^(?:0|[1-9][0-9]{0,2})$/.test(piece))
    ) {
        throw new Error(`${label} must be an IPv4 address`);
    }
    const octets = pieces.map(Number);
    if (octets.some(octet => octet > 255)) {
        throw new Error(`${label} must be an IPv4 address`);
    }
    return {
        address: octets.join('.'),
        integer: octets.reduce(
            (result, octet) => ((result << 8) | octet) >>> 0,
            0,
        ),
    };
};

const cidrRange = (value, label) => {
    if (typeof value !== 'string' || value.length > 32) {
        throw new Error(`${label} must be a canonical IPv4 CIDR`);
    }
    const pieces = value.split('/');
    if (pieces.length !== 2 || !/^(?:0|[1-9][0-9]?)$/.test(pieces[1])) {
        throw new Error(`${label} must be a canonical IPv4 CIDR`);
    }
    const prefix = Number(pieces[1]);
    if (prefix > 32) {
        throw new Error(`${label} must be a canonical IPv4 CIDR`);
    }
    const address = parseIpv4(pieces[0], label);
    const mask = prefix === 0 ? 0 : (0xffffffff << (32 - prefix)) >>> 0;
    const start = (address.integer & mask) >>> 0;
    if (start !== address.integer) {
        throw new Error(`${label} must use its canonical network address`);
    }
    const end = (start | (~mask >>> 0)) >>> 0;
    return {
        value: `${address.address}/${prefix}`,
        start,
        end,
    };
};

const normalizePeerCidr = peer => {
    assertPlainObject(peer, 'proposal peer');
    if (peer.kind === 'ipv4') {
        const address = parseIpv4(peer.value, 'proposal IPv4 peer');
        return cidrRange(`${address.address}/32`, 'proposal IPv4 peer');
    }
    if (peer.kind === 'ipv4-cidr') {
        return cidrRange(peer.value, 'proposal IPv4 CIDR peer');
    }
    throw new Error(
        peer.kind === 'fqdn'
            ? 'legacy browser sketch cannot enforce FQDNs without managed DNS and address tables'
            : `legacy browser sketch does not support peer kind ${String(peer.kind || 'missing')}`,
    );
};

const normalizeTransport = transport => {
    assertPlainObject(transport, 'proposal transport');
    const protocol = String(transport.protocol || '').toLowerCase();
    if (!['tcp', 'udp', 'icmp'].includes(protocol)) {
        throw new Error(`legacy browser sketch does not support protocol ${protocol || 'missing'}`);
    }
    if (protocol === 'icmp') {
        if (!Array.isArray(transport.ports) || transport.ports.length !== 0) {
            throw new Error('ICMP proposal must not contain ports');
        }
        const normalizeByte = (value, label) => {
            if (value == null) return null;
            if (!Number.isSafeInteger(value) || value < 0 || value > 255) {
                throw new Error(`${label} must be an integer from 0 to 255`);
            }
            return value;
        };
        const icmpType = normalizeByte(transport.icmpType, 'ICMP type');
        const icmpCode = normalizeByte(transport.icmpCode, 'ICMP code');
        if (icmpCode != null && icmpType == null) {
            throw new Error('iptables cannot express an ICMP code without an ICMP type');
        }
        return { protocol, ports: [], icmpType, icmpCode };
    }
    if (!Array.isArray(transport.ports) || transport.ports.length === 0) {
        throw new Error(`${protocol.toUpperCase()} proposal requires at least one port`);
    }
    if (transport.ports.length > 64) {
        throw new Error(`${protocol.toUpperCase()} proposal exceeds the 64-port review limit`);
    }
    const ports = [...new Set(transport.ports)].sort((left, right) => left - right);
    if (ports.some(port => !Number.isSafeInteger(port) || port < 1 || port > 65535)) {
        throw new Error(`${protocol.toUpperCase()} proposal contains an invalid port`);
    }
    return { protocol, ports, icmpType: null, icmpCode: null };
};

const validateContext = input => {
    assertPlainObject(input, 'iptables sketch context');
    Object.keys(input).forEach(key => {
        if (!EXPORT_CONTEXT_KEYS.has(key)) {
            throw new Error(`iptables sketch context field ${key} is not supported`);
        }
    });
    const sourceIpv4 = parseIpv4(input.sourceIpv4, 'sourceIpv4').address;
    if (
        typeof input.uplinkInterface !== 'string'
        || !/^[A-Za-z0-9_.:-]{1,15}$/.test(input.uplinkInterface)
    ) {
        throw new Error('uplinkInterface contains unsupported characters');
    }
    if (input.includeMasquerade != null && typeof input.includeMasquerade !== 'boolean') {
        throw new Error('includeMasquerade must be a boolean');
    }
    return Object.freeze({
        sourceIpv4,
        uplinkInterface: input.uplinkInterface,
        includeMasquerade: input.includeMasquerade === true,
    });
};

const mapping = (proposalId, status, reasons = []) => Object.freeze({
    proposalId,
    status,
    reasons: Object.freeze([...reasons]),
});

const classifyProposal = (proposal, decision) => {
    if (
        decision?.disposition !== 'accept'
        || typeof decision.rationale !== 'string'
        || !decision.rationale.trim()
        || decision.rationale.trim().length > 4096
    ) {
        return {
            mapping: mapping(proposal.id, 'not-accepted', [
                'selected proposal requires an accepted decision with a bounded rationale',
            ]),
        };
    }
    const feasibilityEntries = proposal.targetFeasibility?.filter(entry => (
        entry.target === 'gateway-iptables'
    )) || [];
    if (feasibilityEntries.length !== 1) {
        return {
            mapping: mapping(proposal.id, 'unsupported', [
                feasibilityEntries.length
                    ? 'proposal has duplicate gateway-iptables feasibility entries'
                    : 'proposal has no gateway-iptables feasibility entry',
            ]),
        };
    }
    const [feasibility] = feasibilityEntries;
    if (!feasibility || feasibility.status !== 'exact') {
        return {
            mapping: mapping(proposal.id, feasibility?.status || 'unsupported', [
                ...(feasibility?.reasons || []),
                'legacy sketch requires an exact gateway-iptables projection',
            ]),
        };
    }
    const intent = proposal.intent;
    if (
        intent?.domain !== 'network'
        || intent.effect !== 'allow'
        || intent.direction !== 'egress'
    ) {
        return {
            mapping: mapping(proposal.id, 'unsupported', [
                'legacy sketch supports egress network allow proposals only',
            ]),
        };
    }
    try {
        const peer = normalizePeerCidr(intent.peer);
        const transport = normalizeTransport(intent.transport);
        return {
            mapping: mapping(proposal.id, 'exact'),
            rule: Object.freeze({
                proposalId: proposal.id,
                subjectId: intent.subjectId,
                peer: peer.value,
                transport,
            }),
        };
    } catch (error) {
        return {
            mapping: mapping(
                proposal.id,
                'unsupported',
                [error.message],
            ),
        };
    }
};

const chunk = (values, size) => Array.from(
    { length: Math.ceil(values.length / size) },
    (_, index) => values.slice(index * size, index * size + size),
);

const base64EncodeUtf8 = value => {
    const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
    const bytes = new TextEncoder().encode(value);
    let result = '';
    for (let index = 0; index < bytes.length; index += 3) {
        const first = bytes[index];
        const second = bytes[index + 1];
        const third = bytes[index + 2];
        const combined = (first << 16) | ((second || 0) << 8) | (third || 0);
        result += alphabet[(combined >>> 18) & 63];
        result += alphabet[(combined >>> 12) & 63];
        result += second == null ? '=' : alphabet[(combined >>> 6) & 63];
        result += third == null ? '=' : alphabet[combined & 63];
    }
    return result;
};

const renderRuleLines = (chain, rule, commentPrefix, index) => {
    const comment = `${commentPrefix}:r${index + 1}`;
    const common = `-A ${chain} -d ${rule.peer} -p ${rule.transport.protocol}`;
    if (rule.transport.protocol === 'icmp') {
        const type = rule.transport.icmpType == null
            ? ''
            : ` --icmp-type ${rule.transport.icmpType}${
                rule.transport.icmpCode == null ? '' : `/${rule.transport.icmpCode}`
            }`;
        return [`${common}${type} -m comment --comment "${comment}" -j ACCEPT`];
    }
    return chunk(rule.transport.ports, 15).map(ports => (
        `${common}${ports.length === 1
            ? ` --dport ${ports[0]}`
            : ` -m multiport --dports ${ports.join(',')}`
        } -m comment --comment "${comment}" -j ACCEPT`
    ));
};

const renderRestorePayload = ({
    chain,
    commentPrefix,
    context,
    flowMark,
    rules,
    selectionDigest,
}) => {
    const filterLines = [
        '*filter',
        `:${chain} - [0:0]`,
        `-I FORWARD 1 -s ${context.sourceIpv4}/32 -m comment --comment "${commentPrefix}:hook" -j ${chain}`,
        `-I FORWARD 1 -d ${context.sourceIpv4}/32 -m conntrack --ctstate ESTABLISHED,RELATED -m connmark --mark ${flowMark} -m comment --comment "${commentPrefix}:return" -j ACCEPT`,
    ];
    rules.forEach((rule, index) => {
        const matchLines = renderRuleLines(chain, rule, commentPrefix, index);
        matchLines.forEach(line => {
            filterLines.push(
                line.replace(/ -j ACCEPT$/, ` -j CONNMARK --set-mark ${flowMark}`),
                line.replace(/ -j ACCEPT$/, ` -m connmark --mark ${flowMark} -j ACCEPT`),
            );
        });
    });
    filterLines.push(
        `-A ${chain} -m comment --comment "${commentPrefix}:default-deny" -j DROP`,
        'COMMIT',
    );
    const natLines = context.includeMasquerade ? [
        '*nat',
        `-A POSTROUTING -s ${context.sourceIpv4}/32 -o ${context.uplinkInterface} -m comment --comment "${commentPrefix}:masquerade" -j MASQUERADE`,
        'COMMIT',
    ] : [];
    return [
        `# Nosh selected review ${selectionDigest}`,
        '# Validate with: iptables-restore --test --noflush < payload.v4',
        '# Applying this payload is intentionally outside this unsigned browser sketch.',
        ...filterLines,
        ...natLines,
        '',
    ].join('\n');
};

const renderShellScript = ({ payload, metadata }) => [
    '#!/bin/sh',
    'set -eu',
    '',
    '# Nosh unsigned browser iptables sketch v2',
    `# Graph digest: ${metadata.graphDigest}`,
    `# Graph content digest: ${metadata.graphContentDigest}`,
    `# Selection digest: ${metadata.selectionDigest}`,
    `# Rendered proposals: ${metadata.exportedProposalIds.length}`,
    '#',
    '# This unsigned script only prints iptables-restore input. It never invokes',
    '# iptables, iptables-restore, ipset, dnsmasq, conntrack, or sudo. Review the',
    '# output and use the signed Nosh policy/approval/grant/gateway path to apply.',
    '# It has no quarantine, rollback, cleanup, capability, or live-state checks.',
    '# Selection manifest: concatenate and base64-decode the NSH-MANIFEST-B64 chunks.',
    ...chunk(base64EncodeUtf8(canonicalize(metadata.selectionManifest)).split(''), 76)
        .map(part => `# NSH-MANIFEST-B64:${part.join('')}`),
    "cat <<'NOSH_SELECTED_IPTABLES_EOF'",
    payload.trimEnd(),
    'NOSH_SELECTED_IPTABLES_EOF',
    '',
].join('\n');

export const createSelectedIptablesExport = async ({
    graph,
    proposalIds,
    decisions,
    context,
}) => {
    const verifiedGraph = await verifySemanticGraphContentDigest(graph);
    if (!verifiedGraph.frozen) {
        throw new Error('selected iptables sketch requires a frozen semantic graph');
    }
    if (!Array.isArray(proposalIds) || proposalIds.length === 0) {
        throw new Error('select at least one proposal for the iptables sketch');
    }
    if (proposalIds.length > MAX_SELECTED_PROPOSALS) {
        throw new Error(`selected iptables sketch is limited to ${MAX_SELECTED_PROPOSALS} proposals`);
    }
    assertPlainObject(decisions, 'proposal decisions');
    const normalizedContext = validateContext(context);
    const proposalsById = new Map(verifiedGraph.proposals.map(proposal => [proposal.id, proposal]));
    const selectedProposalIds = [...new Set(proposalIds)].sort();
    if (selectedProposalIds.length !== proposalIds.length) {
        throw new Error('selected proposal IDs must not contain duplicates');
    }
    selectedProposalIds.forEach(proposalId => {
        if (!proposalsById.has(proposalId)) {
            throw new Error(`selected proposal ${proposalId} is not in the frozen graph`);
        }
    });
    const classified = selectedProposalIds.map(proposalId => (
        classifyProposal(proposalsById.get(proposalId), decisions[proposalId])
    ));
    let mappings = classified.map(entry => entry.mapping);
    let rules = classified.filter(entry => entry.rule).map(entry => entry.rule);
    const networkCoverage = verifiedGraph.coverage.filter(marker => marker.domain === 'network');
    const networkCoverageFailures = networkCoverage.filter(marker => (
        marker.status !== 'complete' || (marker.blocking && marker.gaps.length > 0)
    ));
    const networkCoverageReason = !networkCoverage.length
        ? 'frozen graph has no network coverage marker'
        : networkCoverageFailures.length
            ? `network coverage is incomplete: ${networkCoverageFailures.map(marker => (
                `${marker.id}:${marker.status}`
            )).join(',')}`
            : null;
    const subjectIds = [...new Set(rules.map(rule => rule.subjectId))].sort();
    const subjectReason = subjectIds.length > 1
        ? 'selected proposals span multiple policy subjects and cannot bind one source IPv4'
        : null;
    const selectionBlockReason = networkCoverageReason || subjectReason;
    if (selectionBlockReason) {
        const exactProposalIds = new Set(rules.map(rule => rule.proposalId));
        mappings = mappings.map(entry => (
            exactProposalIds.has(entry.proposalId)
                ? mapping(entry.proposalId, 'unsupported', [selectionBlockReason])
                : entry
        ));
        rules = [];
    }
    const exportedProposalIds = Object.freeze(rules.map(rule => rule.proposalId));
    const subjectId = subjectIds.length === 1 ? subjectIds[0] : null;
    const decisionBindings = await Promise.all(selectedProposalIds.map(async proposalId => {
        const rationale = typeof decisions[proposalId]?.rationale === 'string'
            ? decisions[proposalId].rationale.trim()
            : null;
        return {
            proposalId,
            disposition: decisions[proposalId]?.disposition || null,
            rationaleDigest: rationale ? await sha256Digest(rationale, { rawString: true }) : null,
        };
    }));
    const selectionManifestPayload = {
        apiVersion: 'notty.dev/v1alpha1',
        kind: 'NoshSelectedIptablesReviewExport',
        schemaVersion: 2,
        artifactClass: 'unsigned-browser-sketch',
        signed: false,
        renderOnly: true,
        activationEligible: false,
        digestAlgorithms: {
            selectionDigest: 'sha256-jcs',
            rationaleDigest: 'sha256-utf8',
        },
        graphDigest: verifiedGraph.graphDigest,
        graphContentDigest: verifiedGraph.contentDigest,
        proposalSetDigest: verifiedGraph.proposalSetDigest,
        selectedProposalIds,
        exportedProposalIds,
        subjectId,
        decisionBindings,
        mappings,
        reviewBlockers: {
            networkCoverageMissing: networkCoverage.length === 0,
            networkCoverage: networkCoverageFailures.map(marker => ({
                id: marker.id,
                status: marker.status,
                gaps: [...marker.gaps],
            })),
            blockingFindingIds: verifiedGraph.findings
                .filter(finding => finding.blocking)
                .map(finding => finding.id)
                .sort(),
        },
        context: normalizedContext,
    };
    const selectionDigest = await sha256Digest(selectionManifestPayload);
    const selectionManifest = freezeJsonValue({
        ...selectionManifestPayload,
        selectionDigest,
    });
    const warnings = [
        'This is an unsigned browser sketch, not a NoshPolicyDecisionSet, PolicyIR, target projection, approval, grant, or gateway activation.',
        'The script prints iptables-restore input and never applies firewall changes.',
        'This sketch adds no implicit CIDR or DNS-port policy; it renders selected reviewed rules followed by default deny.',
        'Non-reviewable containment invariants and managed DNS authority belong to an explicit server-side target context.',
        'FQDN policy requires a server-side Nosh gateway projection with managed DNS and address tables.',
        'This sketch has no quarantine, rollback, cleanup, capability, or live-state verification.',
        subjectId
            ? `Mapping policy subject ${subjectId} to source IPv4 ${normalizedContext.sourceIpv4} is an operator assertion.`
            : 'No single policy subject was eligible for source IPv4 mapping.',
        'Use nosh policy project, nosh review approve, nosh gateway grant, and nosh-gateway apply for enforcement.',
        normalizedContext.includeMasquerade
            ? 'The rendered payload includes source-specific IPv4 masquerading.'
            : 'The rendered payload does not include source NAT.',
    ];
    const skipped = mappings.length - exportedProposalIds.length;
    if (skipped) {
        warnings.push(`${skipped} selected proposal${skipped === 1 ? ' was' : 's were'} not rendered; inspect the mapping reasons.`);
    }
    const blockingFindings = verifiedGraph.findings.filter(finding => finding.blocking);
    if (blockingFindings.length) {
        warnings.push(`${blockingFindings.length} blocking graph finding${blockingFindings.length === 1 ? ' remains' : 's remain'} unresolved.`);
    }
    if (!rules.length) {
        return Object.freeze({
            script: null,
            filename: null,
            scriptDigest: null,
            selectionDigest,
            selectionManifest,
            exportedProposalIds: Object.freeze([]),
            mappings: Object.freeze(mappings),
            warnings: Object.freeze(warnings),
        });
    }
    const digestHex = selectionDigest.slice('sha256:'.length);
    const chain = `NSR_${digestHex.slice(0, 20).toUpperCase()}`;
    const commentPrefix = `nosh-review:${digestHex.slice(0, 12)}`;
    const flowMarkValue = (Number.parseInt(digestHex.slice(0, 8), 16) | 0x100) >>> 0;
    const flowMark = `0x${flowMarkValue.toString(16).padStart(8, '0')}`;
    const payload = renderRestorePayload({
        chain,
        commentPrefix,
        context: normalizedContext,
        flowMark,
        rules,
        selectionDigest,
    });
    const script = renderShellScript({
        payload,
        metadata: {
            graphDigest: verifiedGraph.graphDigest,
            graphContentDigest: verifiedGraph.contentDigest,
            selectionDigest,
            exportedProposalIds,
            selectionManifest,
        },
    });
    if (new TextEncoder().encode(script).byteLength > MAX_SELECTED_SCRIPT_BYTES) {
        throw new Error('selected iptables sketch exceeds the 8 MiB script limit');
    }
    const scriptDigest = await sha256Digest(script, { rawString: true });
    return Object.freeze({
        script,
        filename: `nosh-selected-${digestHex.slice(0, 16)}.iptables-sketch.sh`,
        scriptDigest,
        selectionDigest,
        selectionManifest,
        exportedProposalIds: Object.freeze([...exportedProposalIds]),
        mappings: Object.freeze(mappings),
        warnings: Object.freeze(warnings),
    });
};
