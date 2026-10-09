import { describe, expect, it } from 'vitest';

import {
    applySemanticGraphDelta,
    browserSha256Digest,
    computeSemanticGraphContentDigest,
    computeSemanticGraphDeltaDigest,
    createDecisionSetPreview,
    createReviewRunStatus,
    createSampleSemanticGraph,
    fetchSemanticGraphUrl,
    materializeDecisionSet,
    normalizeLoopbackReviewGraphUrl,
    parseHubbleJsonLines,
    parseSemanticGraphDelta,
    parseSemanticGraphJson,
    validateSemanticGraph,
    verifySemanticGraphContentDigest,
} from '../policy-review/semanticGraph';
import {
    deriveProposalNodeLinks,
    resolveAllowProposalSelection,
} from '../policy-review/proposalDerivation';

const clone = value => JSON.parse(JSON.stringify(value));

describe('semantic policy graph', () => {
    it('verifies the managed-bridge SHA-256 fallback against a known vector', async () => {
        await expect(
            browserSha256Digest('abc', { rawString: true, subtle: null }),
        ).resolves.toBe(
            'sha256:ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad',
        );
    });
    it('cryptographically validates the signed-baseline example without changing canonical records', async () => {
        const graph = createSampleSemanticGraph();

        expect(validateSemanticGraph(graph)).toBe(graph);
        await expect(verifySemanticGraphContentDigest(graph)).resolves.toBe(graph);
        await expect(computeSemanticGraphContentDigest(graph)).resolves.toBe(graph.contentDigest);
        expect(graph.kind).toBe('NoshSemanticGraph');
        expect(graph.frozen).toBe(true);
        expect(graph.diff.some(record => record.changeType === 'broadened')).toBe(true);
    });

    it('rejects malformed canonical records instead of normalizing them', () => {
        const graph = createSampleSemanticGraph();
        delete graph.nodes[0].nodeType;

        expect(() => validateSemanticGraph(graph)).toThrow('$.nodes[0].nodeType');
    });

    it('rejects dangling observation endpoints', () => {
        const graph = createSampleSemanticGraph();
        graph.observations[0].subjectId = `missing:${'0'.repeat(64)}`;

        expect(() => validateSemanticGraph(graph)).toThrow('references a missing node');
    });

    it('rejects prototype-bearing input keys before rendering', async () => {
        const text = JSON.stringify(createSampleSemanticGraph()).replace(
            '"graphId":',
            '"__proto__":{"polluted":true},"graphId":',
        );

        await expect(parseSemanticGraphJson(text)).rejects.toThrow('forbidden key __proto__');
        expect({}.polluted).toBeUndefined();
    });

    it('accepts Guard source provenance fields and enforces paired observation bounds', () => {
        const graph = createSampleSemanticGraph();
        Object.assign(graph.sources[0], {
            sourceType: 'guard-adapter',
            runId: 'cold:1',
            sourceName: 'ebpf-network',
            sourceDigest: `sha256:${'c'.repeat(64)}`,
            observedFrom: '2026-08-16T12:00:00Z',
            observedTo: '2026-08-16T12:00:02Z',
        });

        expect(validateSemanticGraph(graph)).toBe(graph);

        const incompleteRange = clone(graph);
        delete incompleteRange.sources[0].observedTo;
        expect(() => validateSemanticGraph(incompleteRange)).toThrow(
            'observedFrom and observedTo must be supplied together',
        );
    });

    it('loads an explicit review URL without credentials, cache, redirects, or referrer', async () => {
        const sourceGraph = createSampleSemanticGraph();
        let request;
        const token = 'a'.repeat(64);
        const graph = await fetchSemanticGraphUrl(
            `http://127.0.0.1:43117/v1/graph/${token}`,
            {
                fetchImpl: async (url, options) => {
                    request = { url, options };
                    return {
                        ok: true,
                        status: 200,
                        headers: { get: () => null },
                        text: async () => JSON.stringify(sourceGraph),
                    };
                },
            },
        );

        expect(graph.graphId).toBe(sourceGraph.graphId);
        expect(request).toEqual({
            url: `http://127.0.0.1:43117/v1/graph/${token}`,
            options: {
                method: 'GET',
                credentials: 'omit',
                cache: 'no-store',
                redirect: 'error',
                referrerPolicy: 'no-referrer',
                headers: { Accept: 'application/json' },
            },
        });
        await expect(fetchSemanticGraphUrl('file:///tmp/graph.json')).rejects.toThrow(
            'exact tokenized',
        );
    });

    it('accepts loopback diagnostics and only the exact launcher-attested bridge origin', () => {
        const valid = `http://127.0.0.1:8765/v1/graph/${'a'.repeat(64)}`;
        const bridgeOrigin = 'http://172.23.4.9:8765';
        const bridge = `${bridgeOrigin}/v1/graph/${'b'.repeat(64)}`;
        expect(normalizeLoopbackReviewGraphUrl(valid)).toBe(valid);
        expect(normalizeLoopbackReviewGraphUrl(bridge, {
            attestedGraphOrigin: bridgeOrigin,
        })).toBe(bridge);
        expect(() => normalizeLoopbackReviewGraphUrl(bridge)).toThrow('requires launcher');
        expect(() => normalizeLoopbackReviewGraphUrl(bridge, {
            attestedGraphOrigin: 'http://172.23.4.10:8765',
        })).toThrow('does not match');
        for (const invalid of [
            `https://127.0.0.1:8765/v1/graph/${'a'.repeat(64)}`,
            `http://localhost:8765/v1/graph/${'a'.repeat(64)}`,
            `http://127.0.0.1:8765/v1/graph/${'a'.repeat(64)}?extra=1`,
            `http://172.32.0.1:8765/v1/graph/${'a'.repeat(64)}`,
            `http://172.17.999.1:8765/v1/graph/${'a'.repeat(64)}`,
            `http://example.test:8765/v1/graph/${'a'.repeat(64)}`,
            'http://127.0.0.1:8765/v1/graph/short',
        ]) {
            expect(() => normalizeLoopbackReviewGraphUrl(invalid)).toThrow('exact tokenized');
        }
        for (const origin of ['http://10.0.0.2:8765', 'http://192.168.16.3:8765']) {
            const url = `${origin}/v1/graph/${'a'.repeat(64)}`;
            expect(() => normalizeLoopbackReviewGraphUrl(url)).toThrow('requires launcher');
            expect(normalizeLoopbackReviewGraphUrl(url, {
                attestedGraphOrigin: origin,
            })).toBe(url);
        }
    });

    it('shows incomplete run, source, DNS, candidate, finding, and activation state', () => {
        const graph = createSampleSemanticGraph();
        const run = graph.nodes[0];
        run.nodeType = 'buildRun';
        run.identity = { runId: 'incomplete-run' };
        run.properties = {
            complete: false,
            candidateEligible: false,
        };
        Object.assign(graph.sources[0], {
            sourceName: 'dns',
            coverage: {
                status: 'incomplete',
                lostEvents: '7',
                parseErrors: '0',
                gaps: ['collector reported DNS loss'],
            },
        });
        graph.coverage[0].status = 'incomplete';
        graph.coverage[0].gaps = ['collector reported DNS loss'];
        graph.coverage[0].blocking = true;
        graph.findings[0].blocking = true;

        expect(createReviewRunStatus(graph)).toMatchObject({
            runId: 'incomplete-run',
            runState: 'incomplete',
            candidateState: 'not-generated',
            sourceCoverage: { complete: 1, total: 2 },
            dns: { status: 'loss', lostEvents: '7' },
            blockingCoverage: 1,
            activationState: 'ineligible',
        });
        expect(createReviewRunStatus(graph).blockingFindings).toHaveLength(1);
        expect(createDecisionSetPreview({
            graph,
            decisions: {},
            reviewer: 'reviewer',
            reviewerAcknowledged: true,
        }).blockers).toEqual(expect.arrayContaining([
            'profile:run-incomplete',
            'profile:candidate-not-generated',
        ]));
    });

    it('maps Hubble egress and ingress from the protected workload perspective', () => {
        const hubble = JSON.stringify({
            flow: {
                time: '2026-08-16T12:00:00Z',
                verdict: 'FORWARDED',
                IP: { source: '10.0.0.2', destination: '1.1.1.1' },
                l4: { TCP: { destination_port: 443 } },
                source: {
                    namespace: 'build',
                    workloads: [{ name: 'builder' }],
                    labels: ['app=builder'],
                },
                destination: {},
            },
        });

        const graph = parseHubbleJsonLines(hubble);

        expect(graph.frozen).toBe(false);
        expect(graph.importAdapter).toBe('hubble-jsonl/v1');
        expect(graph.coverage[0].status).toBe('degraded');
        expect(graph.observations[0]).toMatchObject({
            observationType: 'connects',
            properties: {
                protocol: 'tcp',
                destinationPort: '443',
            },
        });
        expect(graph.proposals[0].kind).toBe('NoshPolicyProposal');
        expect(graph.proposals[0].intent).toMatchObject({
            direction: 'egress',
            subjectId: graph.nodes.find(node => node.identity.address === '10.0.0.2').id,
            peer: { kind: 'ipv4', value: '1.1.1.1' },
        });

        const ingress = parseHubbleJsonLines(JSON.stringify({
            flow: {
                time: '2026-08-16T12:00:01Z',
                verdict: 'FORWARDED',
                traffic_direction: 'INGRESS',
                IP: { source: '198.51.100.8', destination: '10.0.0.2' },
                l4: { TCP: { destination_port: 8443 } },
                source: {},
                destination: {
                    namespace: 'build',
                    workloads: [{ name: 'builder' }],
                },
            },
        }));
        const ingressSubject = ingress.nodes.find(node => node.identity.address === '10.0.0.2');
        const ingressPeer = ingress.nodes.find(node => node.identity.address === '198.51.100.8');
        expect(ingress.proposals[0]).toMatchObject({
            proposalType: 'network-ingress',
            intent: {
                direction: 'ingress',
                subjectId: ingressSubject.id,
                peer: { kind: 'ipv4', value: '198.51.100.8' },
                transport: { protocol: 'tcp', ports: [8443] },
            },
        });
        expect(ingress.observations[0]).toMatchObject({
            subjectId: ingressSubject.id,
            objectId: ingressPeer.id,
        });
    });

    it('normalizes unsorted Hubble time bounds and marks untimed records', () => {
        const flow = time => ({
            flow: {
                ...(time ? { time } : {}),
                verdict: 'FORWARDED',
                IP: { source: '10.0.0.2', destination: '1.1.1.1' },
                l4: { TCP: { destination_port: 443 } },
                source: { workloads: [{ name: 'builder' }] },
                destination: {},
            },
        });
        const graph = parseHubbleJsonLines([
            flow('2026-08-16T12:00:02Z'),
            flow('2026-08-16T12:00:00Z'),
            flow(null),
        ].map(JSON.stringify).join('\n'));

        expect(graph.sources[0]).toMatchObject({
            observedFrom: '2026-08-16T12:00:00Z',
            observedTo: '2026-08-16T12:00:02Z',
        });
        expect(graph.observations[0]).toMatchObject({
            count: '3',
            firstObservedAt: '2026-08-16T12:00:00Z',
            lastObservedAt: '2026-08-16T12:00:02Z',
            properties: { timedRecords: '2', untimedRecords: '1' },
        });
        expect(graph.coverage[0].counters.untimedRecords).toBe('1');
        expect(graph.coverage[0].gaps).toContain('1 imported record(s) had no flow timestamp');
    });

    it('rejects invalid or reversed observation timestamps before rendering', () => {
        expect(() => parseHubbleJsonLines(JSON.stringify({
            flow: {
                time: 'not-a-time',
                verdict: 'FORWARDED',
                IP: { source: '10.0.0.2', destination: '1.1.1.1' },
                l4: { TCP: { destination_port: 443 } },
                source: {},
                destination: {},
            },
        }))).toThrow('$hubble[0].time');

        expect(() => parseHubbleJsonLines(JSON.stringify({
            flow: {
                time: '2026-02-30T12:00:00Z',
                verdict: 'FORWARDED',
                IP: { source: '10.0.0.2', destination: '1.1.1.1' },
                l4: { TCP: { destination_port: 443 } },
                source: {},
                destination: {},
            },
        }))).toThrow('invalid calendar date');

        const graph = createSampleSemanticGraph();
        graph.observations[0].firstObservedAt = '2026-08-16T12:00:02Z';
        graph.observations[0].lastObservedAt = '2026-08-16T12:00:00Z';
        expect(() => validateSemanticGraph(graph)).toThrow('observation time range is reversed');
    });

    it('binds all policy digests and stays draft until every decision is resolved', async () => {
        const graph = createSampleSemanticGraph();
        const incomplete = createDecisionSetPreview({ graph, decisions: {}, reviewerAcknowledged: false });
        const decisions = Object.fromEntries(graph.proposals.map(proposal => [proposal.id, {
            disposition: proposal.id.includes('telemetry') ? 'reject' : 'accept',
            rationale: proposal.id.includes('telemetry')
                ? 'Unexpected destination is denied by default.'
                : 'Required for the pinned package installation step.',
        }]));
        const complete = createDecisionSetPreview({
            graph,
            decisions,
            reviewer: 'test-reviewer',
            reviewerAcknowledged: true,
        });
        const document = await materializeDecisionSet({
            graph,
            decisions,
            reviewer: 'test-reviewer',
            reviewerAcknowledged: true,
            createdAt: '2026-08-16T12:00:00Z',
        });

        expect(incomplete.reviewState).toBe('draft');
        expect(complete.reviewState).toBe('complete');
        expect(complete).toMatchObject({
            graphDigest: graph.graphDigest,
            graphContentDigest: graph.contentDigest,
            proposalSetDigest: graph.proposalSetDigest,
            basePolicyDigest: graph.basePolicyDigest,
            scopeDigest: graph.scope.scopeDigest,
        });
        expect(document.kind).toBe('NoshPolicyDecisionSet');
        expect(document.graphContentDigest).toBe(graph.contentDigest);
        expect(document.contentDigest).toMatch(/^sha256:[a-f0-9]{64}$/);
        expect(document.decisionSetId).toMatch(/^decision-set:[a-f0-9]{64}$/);
    });

    it('gates projection acknowledgements only for the intended target', () => {
        const graph = createSampleSemanticGraph();
        graph.proposals[0].targetFeasibility[0] = {
            target: 'cilium',
            status: 'restrictive',
            reasons: ['selector inventory narrows the captured subject'],
        };
        const decisions = Object.fromEntries(graph.proposals.map(proposal => [proposal.id, {
            disposition: 'accept',
            rationale: 'This captured behavior is required.',
        }]));
        const review = intendedTarget => createDecisionSetPreview({
            graph,
            decisions,
            intendedTarget,
            reviewer: 'test-reviewer',
            reviewerAcknowledged: true,
        });

        expect(review('gateway-iptables').reviewState).toBe('complete');
        expect(review('cilium')).toMatchObject({
            reviewState: 'draft',
            blockers: [expect.stringContaining(':cilium:restrictive')],
        });
    });

    it('cryptographically verifies ordered live deltas and rejects replay', async () => {
        const hubbleGraph = parseHubbleJsonLines(JSON.stringify({
            flow: {
                verdict: 'DROPPED',
                IP: { source: '10.0.0.2', destination: '10.0.0.3' },
                l4: { UDP: { destination_port: 53 } },
                source: {},
                destination: {},
            },
        }));
        const delta = {
            apiVersion: 'notty.dev/v1alpha1',
            kind: 'NoshSemanticGraphDelta',
            schemaVersion: 1,
            graphId: hubbleGraph.graphId,
            baseRevision: hubbleGraph.revision,
            scopeDigest: hubbleGraph.scope.scopeDigest,
            sequence: '1',
            previousDeltaDigest: null,
            createdAt: '2026-08-16T12:00:00Z',
            sourceWatermarks: [{
                sourceId: hubbleGraph.sources[0].id,
                sequence: '1',
                observedAt: '2026-08-16T12:00:00Z',
            }],
            operations: [],
            frozen: false,
            deltaDigest: '',
        };
        delta.deltaDigest = await computeSemanticGraphDeltaDigest(delta);

        const parsedDelta = await parseSemanticGraphDelta(JSON.stringify(delta));
        const applied = await applySemanticGraphDelta(hubbleGraph, parsedDelta);
        expect(applied).toMatchObject({
            revision: delta.deltaDigest,
            liveDeltaState: {
                sequence: '1',
                lastDeltaDigest: delta.deltaDigest,
            },
        });
        await expect(applySemanticGraphDelta(applied, parsedDelta)).rejects.toThrow(
            /baseRevision|sequence|live chain/,
        );
        await expect(applySemanticGraphDelta(createSampleSemanticGraph(), parsedDelta)).rejects.toThrow(
            'Frozen graphs',
        );

        const contentTampered = clone(delta);
        contentTampered.createdAt = '2026-08-16T12:00:01Z';
        await expect(parseSemanticGraphDelta(JSON.stringify(contentTampered))).rejects.toThrow(
            'deltaDigest does not match delta content',
        );

        const recordTampered = clone(delta);
        recordTampered.operations = [{
            op: 'upsert',
            role: 'nodes',
            recordId: hubbleGraph.nodes[0].id,
            recordDigest: `sha256:${'f'.repeat(64)}`,
            record: hubbleGraph.nodes[0],
        }];
        recordTampered.deltaDigest = await computeSemanticGraphDeltaDigest(recordTampered);
        await expect(parseSemanticGraphDelta(JSON.stringify(recordTampered))).rejects.toThrow(
            'recordDigest does not match the upsert record',
        );

        const removeTampered = clone(delta);
        removeTampered.operations = [{
            op: 'remove',
            role: 'nodes',
            recordId: hubbleGraph.nodes[0].id,
            recordDigest: `sha256:${'e'.repeat(64)}`,
        }];
        removeTampered.deltaDigest = await computeSemanticGraphDeltaDigest(removeTampered);
        await expect(applySemanticGraphDelta(hubbleGraph, removeTampered)).rejects.toThrow(
            'remove digest does not match',
        );
    });

    it('rejects semantically altered graph content before review or export', async () => {
        const graph = createSampleSemanticGraph();
        const tampered = clone(graph);
        tampered.proposals[0].intent.peer.value = 'attacker.example';

        await expect(parseSemanticGraphJson(JSON.stringify(tampered))).rejects.toThrow(
            'contentDigest does not match the materialized graph',
        );

        const decisions = Object.fromEntries(tampered.proposals.map(proposal => [proposal.id, {
            disposition: 'accept',
            rationale: 'Required by the build.',
        }]));
        await expect(materializeDecisionSet({
            graph: tampered,
            decisions,
            reviewer: 'test-reviewer',
            reviewerAcknowledged: true,
        })).rejects.toThrow('contentDigest does not match the materialized graph');
    });

    it('connects Guard proposals only to their subject, exact peer, and explicit source node', () => {
        const graph = createSampleSemanticGraph();
        const proposal = graph.proposals[0];
        const sourceNode = graph.nodes.find(node => node.id !== proposal.intent.subjectId);
        const unrelatedObservation = graph.observations.find(record => (
            record.subjectId !== proposal.intent.subjectId
            && record.objectId !== proposal.intent.subjectId
            && record.objectId !== sourceNode.id
        ));
        proposal.evidenceRefs = [sourceNode.id];
        unrelatedObservation.evidenceRefs = [sourceNode.id];

        expect(deriveProposalNodeLinks(graph, proposal)).toEqual([
            { nodeId: proposal.intent.subjectId, relation: 'subject' },
            {
                nodeId: graph.nodes.find(node => (
                    node.nodeType === 'networkEndpoint'
                    && node.identity.address === proposal.intent.peer.value
                )).id,
                relation: 'peer',
            },
            { nodeId: sourceNode.id, relation: 'evidence' },
        ]);
        expect(deriveProposalNodeLinks(graph, proposal).map(link => link.nodeId))
            .not.toContain(unrelatedObservation.objectId);
    });

    it('connects Guard policy peers only by exact, unambiguous typed identity', () => {
        const stableId = (namespace, character) => `${namespace}:${character.repeat(64)}`;
        const subjectId = stableId('subject', '1');
        const sourceId = stableId('source', '2');
        const nodes = [
            { id: subjectId, nodeType: 'project', identity: { projectKey: 'fixture' } },
            { id: sourceId, nodeType: 'evidenceSource', identity: { sourceName: 'guard' } },
            {
                id: stableId('endpoint', '3'),
                nodeType: 'networkEndpoint',
                identity: {
                    family: 'ipv4',
                    address: '104.16.0.1',
                    protocol: 'tcp',
                    port: 443,
                    icmpType: null,
                    icmpCode: null,
                },
            },
            {
                id: stableId('file', '4'),
                nodeType: 'file',
                identity: { path: '/app/package-lock.json' },
            },
            {
                id: stableId('executable', '5'),
                nodeType: 'executable',
                identity: { executable: '/usr/local/bin/node' },
            },
            {
                id: stableId('syscall', '6'),
                nodeType: 'syscall',
                identity: { number: '59', auditArchitecture: null },
            },
        ];
        const proposal = (peer, domain, extra = {}) => ({
            intent: {
                domain,
                subjectId,
                effect: domain === 'network' ? 'allow' : 'monitor',
                peer,
                ...extra,
            },
            evidenceRefs: [sourceId],
        });
        const fixtures = [
            [
                proposal(
                    { kind: 'ipv4-cidr', value: '104.16.0.1/32' },
                    'network',
                    {
                        direction: 'egress',
                        transport: { protocol: 'tcp', ports: [443] },
                    },
                ),
                nodes[2].id,
            ],
            [proposal({ kind: 'path', value: '/app/package-lock.json' }, 'filesystem'), nodes[3].id],
            [proposal({ kind: 'executable', value: '/usr/local/bin/node' }, 'process'), nodes[4].id],
            [proposal({ kind: 'syscall', value: '59' }, 'syscall'), nodes[5].id],
        ];

        fixtures.forEach(([record, peerNodeId]) => {
            expect(deriveProposalNodeLinks({ nodes }, record)).toEqual([
                { nodeId: subjectId, relation: 'subject' },
                { nodeId: peerNodeId, relation: 'peer' },
                { nodeId: sourceId, relation: 'evidence' },
            ]);
        });

        const ambiguousNodes = [
            ...nodes,
            { ...nodes[2], id: stableId('endpoint', '7') },
        ];
        expect(deriveProposalNodeLinks({ nodes: ambiguousNodes }, fixtures[0][0])).toEqual([
            { nodeId: subjectId, relation: 'subject' },
            { nodeId: sourceId, relation: 'evidence' },
        ]);
    });

    it('resolves selected telemetry only to exact digest-bound allow proposals', () => {
        const graph = createSampleSemanticGraph();
        const firstProposal = graph.proposals[0];
        const secondProposal = graph.proposals[1];
        const firstObservationId = firstProposal.observationRefs[0];
        const peerNodeId = graph.nodes.find(node => (
            node.nodeType === 'networkEndpoint'
            && node.identity.address === firstProposal.intent.peer.value
        )).id;
        const unsupportedObservation = graph.observations.find(observation => (
            observation.observationType === 'accesses'
        ));

        expect(resolveAllowProposalSelection(graph, [
            { type: 'observation', id: firstObservationId },
            { type: 'node', id: peerNodeId },
            { type: 'proposal', id: secondProposal.id },
            { type: 'observation', id: unsupportedObservation.id },
            { type: 'observation', id: firstObservationId },
        ])).toEqual({
            allowProposalIds: [firstProposal.id, secondProposal.id].sort(),
            resolvedSelections: [
                {
                    type: 'node',
                    id: peerNodeId,
                    proposalIds: [firstProposal.id],
                },
                {
                    type: 'observation',
                    id: firstObservationId,
                    proposalIds: [firstProposal.id],
                },
                {
                    type: 'proposal',
                    id: secondProposal.id,
                    proposalIds: [secondProposal.id],
                },
            ].sort((left, right) => `${left.type}:${left.id}`.localeCompare(`${right.type}:${right.id}`)),
            unsupportedSelections: [{
                type: 'observation',
                id: unsupportedObservation.id,
                reason: 'selection has no exact digest-bound allow proposal',
            }],
        });
    });

    it('does not let an imported graph mutate the sample fixture', async () => {
        const graph = createSampleSemanticGraph();
        const imported = await parseSemanticGraphJson(JSON.stringify(graph));
        imported.nodes[0].label = 'changed';

        expect(clone(createSampleSemanticGraph()).nodes[0].label).toBe('release profile');
    });
});
