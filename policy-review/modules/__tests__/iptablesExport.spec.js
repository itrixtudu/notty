import { describe, expect, it } from 'vitest';

import { createSelectedIptablesExport } from '../policy-review/iptablesExport';
import {
    computeSemanticGraphContentDigest,
    createSampleSemanticGraph,
} from '../policy-review/semanticGraph';

const clone = value => JSON.parse(JSON.stringify(value));

const exportContext = Object.freeze({
    sourceIpv4: '198.51.100.10',
    uplinkInterface: 'eth0',
});

const acceptedDecision = rationale => ({
    disposition: 'accept',
    rationale,
});

const recomputeContentDigest = async graph => {
    graph.contentDigest = await computeSemanticGraphContentDigest(graph);
    return graph;
};

const mutateSample = async mutation => {
    const graph = clone(createSampleSemanticGraph());
    mutation(graph);
    return recomputeContentDigest(graph);
};

const exportOne = async ({
    graph = createSampleSemanticGraph(),
    proposal = graph.proposals[0],
    decision = acceptedDecision('Reviewer approved this exact observed flow.'),
    context = exportContext,
} = {}) => createSelectedIptablesExport({
    graph,
    proposalIds: [proposal.id],
    decisions: { [proposal.id]: decision },
    context,
});

const payloadLinesFor = (script, destination) => script
    .split('\n')
    .filter(line => line.startsWith('-A NSR_') && line.includes(` -d ${destination} `));

describe('unsigned selected-network iptables browser sketch', () => {
    it('renders a deterministic, content-bound TCP review script from an exact accepted selection', async () => {
        const graph = createSampleSemanticGraph();
        const proposal = graph.proposals[0];
        const input = {
            graph,
            proposalIds: [proposal.id],
            decisions: {
                [proposal.id]: acceptedDecision('Reviewer approved this exact observed flow.'),
            },
            context: exportContext,
        };

        const first = await createSelectedIptablesExport(input);
        const second = await createSelectedIptablesExport(input);

        expect(second).toEqual(first);
        expect(first.exportedProposalIds).toEqual([proposal.id]);
        expect(first.mappings).toEqual([{
            proposalId: proposal.id,
            status: 'exact',
            reasons: [],
        }]);
        expect(first.selectionDigest).toMatch(/^sha256:[0-9a-f]{64}$/);
        expect(first.scriptDigest).toMatch(/^sha256:[0-9a-f]{64}$/);
        expect(first.filename).toBe(
            `nosh-selected-${first.selectionDigest.slice('sha256:'.length, 'sha256:'.length + 16)}.iptables-sketch.sh`,
        );
        expect(first.script).toContain(`# Graph digest: ${graph.graphDigest}`);
        expect(first.script).toContain(`# Graph content digest: ${graph.contentDigest}`);
        expect(first.script).toContain(`# Selection digest: ${first.selectionDigest}`);
        expect(first.script).toContain(`-d 104.16.0.1/32 -p tcp --dport 443`);
        expect(first.script).toContain(`-s ${exportContext.sourceIpv4}/32 -m comment`);
        expect(first.script).not.toContain(`-s ${exportContext.sourceIpv4}/32 -o `);
        expect(first.script).toMatch(/^#!\/bin\/sh\nset -eu\n/);
        expect(first.script.endsWith('\n')).toBe(true);

        const encodedManifest = first.script
            .split('\n')
            .filter(line => line.startsWith('# NSH-MANIFEST-B64:'))
            .map(line => line.slice('# NSH-MANIFEST-B64:'.length))
            .join('');
        expect(JSON.parse(Buffer.from(encodedManifest, 'base64').toString('utf8'))).toEqual(
            first.selectionManifest,
        );
        expect(first.selectionManifest).toMatchObject({
            schemaVersion: 2,
            artifactClass: 'unsigned-browser-sketch',
            signed: false,
            renderOnly: true,
            activationEligible: false,
            graphDigest: graph.graphDigest,
            graphContentDigest: graph.contentDigest,
            selectionDigest: first.selectionDigest,
            selectedProposalIds: [proposal.id],
            exportedProposalIds: [proposal.id],
            subjectId: proposal.intent.subjectId,
            context: exportContext,
        });
        expect(first.selectionManifest.decisionBindings[0].rationaleDigest).toMatch(
            /^sha256:[0-9a-f]{64}$/,
        );
    });

    it('is render-only: the shell body invokes no firewall, privilege, or network command', async () => {
        const result = await exportOne();
        const heredocStart = result.script.indexOf("cat <<'NOSH_SELECTED_IPTABLES_EOF'");
        const shellBody = result.script.slice(0, heredocStart);
        const executableLines = shellBody
            .split('\n')
            .map(line => line.trim())
            .filter(line => line && !line.startsWith('#'));

        expect(executableLines).toEqual(['set -eu']);
        expect(result.script.slice(heredocStart)).toMatch(
            /^cat <<'NOSH_SELECTED_IPTABLES_EOF'\n/,
        );
        const executableText = executableLines.join('\n');
        expect(executableText).not.toMatch(/\b(?:iptables|iptables-restore|ipset|dnsmasq|conntrack|sudo|nft|eval|exec)\b/);
        expect(executableText).not.toMatch(/\$\(|`/);
    });

    it('binds the artifact identity to the exact selected proposals and review decisions', async () => {
        const graph = createSampleSemanticGraph();
        const firstProposal = graph.proposals[0];
        const secondProposal = graph.proposals[1];
        const first = await exportOne({ graph, proposal: firstProposal });
        const second = await exportOne({ graph, proposal: secondProposal });
        const changedRationale = await exportOne({
            graph,
            proposal: firstProposal,
            decision: acceptedDecision('A different bounded review rationale.'),
        });

        expect(first.selectionDigest).not.toBe(second.selectionDigest);
        expect(first.selectionDigest).not.toBe(changedRationale.selectionDigest);
        expect(first.scriptDigest).not.toBe(second.scriptDigest);
        expect(first.filename).not.toBe(second.filename);
        expect(first.filename).not.toBe(changedRationale.filename);
    });

    it('rejects an empty, unknown, or duplicate proposal selection', async () => {
        const graph = createSampleSemanticGraph();
        const proposal = graph.proposals[0];
        const decisions = {
            [proposal.id]: acceptedDecision('Approved.'),
        };

        await expect(createSelectedIptablesExport({
            graph,
            proposalIds: [],
            decisions,
            context: exportContext,
        })).rejects.toThrow('select at least one proposal');
        await expect(createSelectedIptablesExport({
            graph,
            proposalIds: [`proposal:${'f'.repeat(64)}`],
            decisions,
            context: exportContext,
        })).rejects.toThrow('is not in the frozen graph');
        await expect(createSelectedIptablesExport({
            graph,
            proposalIds: [proposal.id, proposal.id],
            decisions,
            context: exportContext,
        })).rejects.toThrow('must not contain duplicates');
        await expect(createSelectedIptablesExport({
            graph,
            proposalIds: Array.from({ length: 1001 }, () => proposal.id),
            decisions,
            context: exportContext,
        })).rejects.toThrow('limited to 1000 proposals');
    });

    it('fails closed on duplicate target feasibility declarations', async () => {
        const graph = await mutateSample(sample => {
            const proposal = sample.proposals[0];
            proposal.targetFeasibility[2] = {
                target: 'gateway-iptables',
                status: 'unsupported',
                reasons: ['duplicate target declaration'],
            };
        });

        await expect(exportOne({ graph })).rejects.toThrow(/duplicate targets|must be sorted by target/);
    });

    it('does not collapse different policy subjects into one source IPv4', async () => {
        const graph = createSampleSemanticGraph();
        const decisions = Object.fromEntries(graph.proposals.map(proposal => [
            proposal.id,
            acceptedDecision('Approved only for the proposal subject.'),
        ]));
        const result = await createSelectedIptablesExport({
            graph,
            proposalIds: graph.proposals.map(proposal => proposal.id),
            decisions,
            context: exportContext,
        });

        expect(result.script).toBeNull();
        expect(result.exportedProposalIds).toEqual([]);
        expect(result.mappings.every(entry => (
            entry.status === 'unsupported'
            && entry.reasons.includes(
                'selected proposals span multiple policy subjects and cannot bind one source IPv4',
            )
        ))).toBe(true);
        expect(result.selectionManifest.subjectId).toBeNull();
    });

    it('does not render exact rules when frozen network coverage is incomplete', async () => {
        const graph = await mutateSample(sample => {
            const marker = sample.coverage.find(entry => entry.domain === 'network');
            marker.status = 'incomplete';
            marker.gaps = ['collector output was truncated'];
        });
        const result = await exportOne({ graph });

        expect(result.script).toBeNull();
        expect(result.mappings[0].status).toBe('unsupported');
        expect(result.mappings[0].reasons[0]).toContain('network coverage is incomplete');
        expect(result.selectionManifest.reviewBlockers.networkCoverage).toEqual([{
            id: graph.coverage.find(entry => entry.domain === 'network').id,
            status: 'incomplete',
            gaps: ['collector output was truncated'],
        }]);
    });

    it.each([
        [
            'source command injection',
            { ...exportContext, sourceIpv4: '198.51.100.10; reboot' },
            'sourceIpv4 must be an IPv4 address',
        ],
        [
            'interface command injection',
            { ...exportContext, uplinkInterface: 'eth0;reboot' },
            'uplinkInterface contains unsupported characters',
        ],
        [
            'unsupported context field',
            { ...exportContext, gatewayIpv4: '198.51.100.1' },
            'field gatewayIpv4 is not supported',
        ],
        [
            'non-boolean masquerade switch',
            { ...exportContext, includeMasquerade: 'yes' },
            'includeMasquerade must be a boolean',
        ],
    ])('rejects invalid context: %s', async (_label, context, message) => {
        await expect(exportOne({ context })).rejects.toThrow(message);
    });

    it('skips selected proposals that have not been accepted with a rationale', async () => {
        const graph = createSampleSemanticGraph();
        const [accepted, rejected] = graph.proposals;
        const result = await createSelectedIptablesExport({
            graph,
            proposalIds: [rejected.id, accepted.id],
            decisions: {
                [accepted.id]: acceptedDecision('Approved exact flow.'),
                [rejected.id]: {
                    disposition: 'reject',
                    rationale: 'The capture does not justify this destination.',
                },
            },
            context: exportContext,
        });

        expect(result.script).not.toBeNull();
        expect(result.exportedProposalIds).toEqual([accepted.id]);
        expect(result.mappings.find(mapping => mapping.proposalId === rejected.id)).toEqual({
            proposalId: rejected.id,
            status: 'not-accepted',
            reasons: ['selected proposal requires an accepted decision with a bounded rationale'],
        });
        expect(result.warnings).toContain('1 selected proposal was not rendered; inspect the mapping reasons.');
        expect(result.script).not.toContain('203.0.113.24/32');
    });

    it.each([
        [
            'FQDN peers',
            proposal => {
                proposal.intent.peer = { kind: 'fqdn', value: 'registry.npmjs.org' };
            },
            'unsupported',
            'cannot enforce FQDNs',
        ],
        [
            'ingress intents',
            proposal => {
                proposal.intent.direction = 'ingress';
            },
            'unsupported',
            'egress network allow proposals only',
        ],
        [
            'non-network intents',
            proposal => {
                proposal.intent.domain = 'filesystem';
            },
            'unsupported',
            'egress network allow proposals only',
        ],
        [
            'restrictive target feasibility',
            proposal => {
                const feasibility = proposal.targetFeasibility.find(target => (
                    target.target === 'gateway-iptables'
                ));
                feasibility.status = 'restrictive';
                feasibility.reasons = ['Gateway projection narrows the requested policy.'];
            },
            'restrictive',
            'requires an exact gateway-iptables projection',
        ],
        [
            'ICMP code without type',
            proposal => {
                proposal.intent.transport = {
                    protocol: 'icmp',
                    ports: [],
                    icmpCode: 3,
                };
            },
            'unsupported',
            'cannot express an ICMP code without an ICMP type',
        ],
        [
            'more than 64 transport ports',
            proposal => {
                proposal.intent.transport = {
                    protocol: 'tcp',
                    ports: Array.from({ length: 65 }, (_, index) => index + 1000),
                };
            },
            'unsupported',
            'exceeds the 64-port review limit',
        ],
    ])('reports %s as selected-but-not-rendered', async (_label, mutation, status, reason) => {
        const graph = await mutateSample(sample => mutation(sample.proposals[0]));
        const result = await exportOne({ graph });

        expect(result.script).toBeNull();
        expect(result.filename).toBeNull();
        expect(result.scriptDigest).toBeNull();
        expect(result.exportedProposalIds).toEqual([]);
        expect(result.mappings).toHaveLength(1);
        expect(result.mappings[0]).toMatchObject({ status });
        expect(result.mappings[0].reasons.join(' ')).toContain(reason);
        expect(result.warnings.at(-1)).toBe(
            '1 selected proposal was not rendered; inspect the mapping reasons.',
        );
    });

    it.each([
        [
            'reviewed RFC1918 destination',
            { kind: 'ipv4', value: '192.168.1.65' },
            { protocol: 'tcp', ports: [9001] },
            '-d 192.168.1.65/32 -p tcp --dport 9001',
        ],
        [
            'reviewed UDP DNS resolver',
            { kind: 'ipv4', value: '10.10.0.53' },
            { protocol: 'udp', ports: [53] },
            '-d 10.10.0.53/32 -p udp --dport 53',
        ],
        [
            'reviewed TCP DNS-over-TLS endpoint',
            { kind: 'ipv4', value: '172.16.0.53' },
            { protocol: 'tcp', ports: [853] },
            '-d 172.16.0.53/32 -p tcp --dport 853',
        ],
        [
            'reviewed UDP 443 endpoint',
            { kind: 'ipv4', value: '10.20.30.40' },
            { protocol: 'udp', ports: [443] },
            '-d 10.20.30.40/32 -p udp --dport 443',
        ],
    ])('renders %s without inventing CIDR or DNS-port invariants', async (
        _label,
        peer,
        transport,
        expectedRule,
    ) => {
        const graph = await mutateSample(sample => {
            sample.proposals[0].intent.peer = peer;
            sample.proposals[0].intent.transport = transport;
        });
        const result = await exportOne({ graph });

        expect(result.mappings[0]).toMatchObject({ status: 'exact' });
        expect(result.script).toContain(expectedRule);
        expect(result.script).not.toContain(':invariant');
        expect(result.script).not.toContain(':dns-guard');
        expect(result.script).toContain(':default-deny');
        expect(result.warnings).toContain(
            'This sketch adds no implicit CIDR or DNS-port policy; it renders selected reviewed rules followed by default deny.',
        );
    });

    it('chunks TCP port lists at the iptables multiport limit of fifteen', async () => {
        const fifteenPorts = Array.from({ length: 15 }, (_, index) => 1000 + index);
        const sixteenPorts = [...fifteenPorts, 1015];
        const graphWithFifteen = await mutateSample(graph => {
            graph.proposals[0].intent.transport.ports = fifteenPorts;
        });
        const graphWithSixteen = await mutateSample(graph => {
            graph.proposals[0].intent.transport.ports = sixteenPorts;
        });
        const fifteen = await exportOne({ graph: graphWithFifteen });
        const sixteen = await exportOne({ graph: graphWithSixteen });
        const fifteenLines = payloadLinesFor(fifteen.script, '104.16.0.1/32');
        const sixteenLines = payloadLinesFor(sixteen.script, '104.16.0.1/32');

        expect(fifteenLines).toHaveLength(2);
        fifteenLines.forEach(line => {
            expect(line).toContain(`-m multiport --dports ${fifteenPorts.join(',')}`);
            expect(line).not.toMatch(/ --dport /);
        });
        expect(sixteenLines).toHaveLength(4);
        expect(sixteenLines.slice(0, 2).every(line => (
            line.includes(`-m multiport --dports ${fifteenPorts.join(',')}`)
        ))).toBe(true);
        expect(sixteenLines.slice(2).every(line => line.includes(' --dport 1015 '))).toBe(true);
    });

    it('only renders source-specific masquerading when explicitly requested', async () => {
        const withoutMasquerade = await exportOne();
        const withMasquerade = await exportOne({
            context: { ...exportContext, includeMasquerade: true },
        });

        expect(withoutMasquerade.script).not.toContain('*nat\n');
        expect(withoutMasquerade.script).not.toContain(' -j MASQUERADE');
        expect(withoutMasquerade.warnings).toContain(
            'The rendered payload does not include source NAT.',
        );
        expect(withMasquerade.script).toContain('*nat\n');
        expect(withMasquerade.script).toContain(
            `-A POSTROUTING -s ${exportContext.sourceIpv4}/32 -o ${exportContext.uplinkInterface}`
            + ' -m comment --comment "nosh-review:',
        );
        expect(withMasquerade.script).toContain(' -j MASQUERADE');
        expect(withMasquerade.warnings).toContain(
            'The rendered payload includes source-specific IPv4 masquerading.',
        );
        expect(withMasquerade.selectionDigest).not.toBe(withoutMasquerade.selectionDigest);
        expect(withMasquerade.filename).not.toBe(withoutMasquerade.filename);
    });
});
