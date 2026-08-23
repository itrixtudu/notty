import { useMemo } from 'react';
import ReactFlow, {
    Background,
    Controls,
    Handle,
    MarkerType,
    MiniMap,
    Position,
} from 'reactflow';

import { usePolicyReviewStore } from '../../modules/policy-review/reviewStore';
import { deriveProposalNodeLinks } from '../../modules/policy-review/proposalDerivation';
import {
    createTimelineProjection,
    selectTimelineActivity,
} from '../../modules/policy-review/timelineProjection';

import styles from './PolicyReview.module.css';

export const POLICY_REVIEW_LANES = [
    'Build',
    'Processes',
    'Filesystem',
    'Syscalls',
    'Network / DNS',
    'Packages',
    'Policy',
    'Coverage',
];

const LANE_WIDTH = 300;
const LANE_GAP = 24;
const NODE_WIDTH = 252;
const NODE_HEIGHT = 116;
const NODE_GAP = 34;
const HEADER_HEIGHT = 70;

const laneMatchers = [
    ['Build', /project|build|stage|vertex|image|pass/i],
    ['Processes', /process|exec|executable|capabilit|mount/i],
    ['Filesystem', /file|path|directory/i],
    ['Syscalls', /syscall/i],
    ['Network / DNS', /network|endpoint|domain|dns|flow|socket/i],
    ['Packages', /package|component|sbom|provenance/i],
    ['Policy', /policy|rule|proposal/i],
    ['Coverage', /coverage|finding|source|collector/i],
];

export const resolvePolicyReviewLane = node => {
    if (POLICY_REVIEW_LANES.includes(node?.lane)) {
        return node.lane;
    }
    const kind = String(node?.nodeType || node?.kind || '');
    return laneMatchers.find(([, matcher]) => matcher.test(kind))?.[0] || 'Coverage';
};

const StatusPill = ({ status }) => (
    <span className={styles.statusPill} data-status={status || 'unchanged'}>
        {status || 'unchanged'}
    </span>
);

function LaneNode({ data }) {
    return (
        <section className={styles.laneNode} aria-label={`${data.label} lane`}>
            <header>
                <span>{data.label}</span>
                <small>{data.count}</small>
            </header>
        </section>
    );
}

function SemanticNode({ data, selected }) {
    return (
        <article
            className={`${styles.semanticNode} ${selected ? styles.semanticNodeSelected : ''}`}
            data-status={data.diffStatus || 'unchanged'}
            data-temporal={data.temporalState || 'all'}
        >
            <Handle className={styles.nodeHandle} type="target" position={Position.Left} />
            <header>
                <span className={styles.nodeKind}>{data.kind}</span>
                <StatusPill status={data.diffStatus} />
            </header>
            <strong>{data.label}</strong>
            {data.summary ? <p>{data.summary}</p> : null}
            <footer>
                <span>{data.evidenceCount} evidence ref{data.evidenceCount === 1 ? '' : 's'}</span>
                {data.temporalLabel ? <span>{data.temporalLabel}</span> : null}
            </footer>
            <Handle className={styles.nodeHandle} type="source" position={Position.Right} />
        </article>
    );
}

function ProposalNode({ data, selected }) {
    return (
        <article
            className={`${styles.semanticNode} ${styles.proposalNode} ${selected ? styles.semanticNodeSelected : ''}`}
            data-status={data.diffStatus || 'unchanged'}
            data-disposition={data.disposition}
        >
            <Handle className={styles.nodeHandle} type="target" position={Position.Left} />
            <header>
                <span className={styles.nodeKind}>Policy proposal</span>
                <StatusPill status={data.diffStatus} />
            </header>
            <strong>{data.label}</strong>
            <p>{data.summary}</p>
            <footer>
                <span>{data.disposition}</span>
                <span>{data.evidenceCount} refs</span>
            </footer>
            <Handle className={styles.nodeHandle} type="source" position={Position.Right} />
        </article>
    );
}

const nodeTypes = {
    lane: LaneNode,
    semantic: SemanticNode,
    proposal: ProposalNode,
};

const getEdgeColor = status => {
    if (status === 'added' || status === 'broadened') {
        return '#fb7185';
    }
    if (status === 'removed') {
        return '#94a3b8';
    }
    if (status === 'coverage-degraded') {
        return '#f59e0b';
    }
    if (status === 'metric-only') {
        return '#38bdf8';
    }
    return '#64748b';
};

const proposalTitle = proposal => {
    const intent = proposal.intent || {};
    const peer = intent.peer?.value || intent.peer?.kind || intent.operation || intent.domain;
    return `${intent.effect || 'review'} ${intent.direction || intent.domain || 'policy'} ${peer || ''}`.trim();
};

const temporalState = (timelineContext, recordType, recordId) => {
    if (!timelineContext) {
        return { state: 'all', label: null };
    }
    const item = timelineContext.itemsByRecord.get(`${recordType}:${recordId}`);
    const activeIds = recordType === 'observation'
        ? timelineContext.activeObservationIds
        : timelineContext.activeNodeIds;
    if (!activeIds.has(recordId)) {
        return { state: 'inactive', label: 'outside view' };
    }
    if (!item || item.temporalKind === 'untimed') {
        return { state: 'untimed', label: 'untimed context' };
    }
    return {
        state: 'active',
        label: item.aggregation?.aggregated ? 'aggregate in view' : 'in view',
    };
};

export const buildPolicyReviewFlowElements = (
    graph,
    decisions,
    laneFilter,
    timelineContext = null,
    selectionContext = null,
) => {
    const diffByEntity = new Map(graph.diff.map(record => [record.entityId, record.changeType]));
    const statusFor = record => diffByEntity.get(record.id) || record.baselineState || 'unchanged';
    const visibleLanes = laneFilter === 'All' ? POLICY_REVIEW_LANES : [laneFilter];
    const semanticByLane = new Map(visibleLanes.map(lane => [lane, []]));
    graph.nodes.forEach(node => {
        const lane = resolvePolicyReviewLane(node);
        if (semanticByLane.has(lane)) {
            semanticByLane.get(lane).push({ record: node, type: 'semantic' });
        }
    });
    if (semanticByLane.has('Policy')) {
        graph.proposals.forEach(proposal => {
            semanticByLane.get('Policy').push({ record: proposal, type: 'proposal' });
        });
    }

    semanticByLane.forEach(records => records.sort((left, right) => {
        const statusWeight = status => (
            status === 'broadened' ? 0 : status === 'added' ? 1 : status === 'coverage-degraded' ? 2 : 3
        );
        const weight = statusWeight(statusFor(left.record)) - statusWeight(statusFor(right.record));
        return weight || String(left.record.label || proposalTitle(left.record))
            .localeCompare(String(right.record.label || proposalTitle(right.record)));
    }));

    const maximumLaneRecords = Math.max(1, ...[...semanticByLane.values()].map(records => records.length));
    const laneHeight = HEADER_HEIGHT + maximumLaneRecords * (NODE_HEIGHT + NODE_GAP) + 42;
    const nodes = [];
    const visibleNodeIds = new Set();
    visibleLanes.forEach((lane, laneIndex) => {
        const x = laneIndex * (LANE_WIDTH + LANE_GAP);
        const records = semanticByLane.get(lane) || [];
        nodes.push({
            id: `lane:${lane}`,
            type: 'lane',
            position: { x, y: 0 },
            data: { label: lane, count: records.length },
            draggable: false,
            selectable: false,
            connectable: false,
            focusable: false,
            zIndex: -1,
            style: { width: LANE_WIDTH, height: laneHeight },
        });
        records.forEach(({ record, type }, recordIndex) => {
            const id = type === 'proposal' ? `proposal:${record.id}` : record.id;
            const temporal = type === 'proposal'
                ? { state: 'all', label: null }
                : temporalState(timelineContext, 'node', record.id);
            visibleNodeIds.add(id);
            nodes.push({
                id,
                type,
                selected: Boolean(selectionContext?.selectedKeys?.has(
                    `${type === 'proposal' ? 'proposal' : 'node'}:${record.id}`,
                )),
                position: {
                    x: x + (LANE_WIDTH - NODE_WIDTH) / 2,
                    y: HEADER_HEIGHT + 20 + recordIndex * (NODE_HEIGHT + NODE_GAP),
                },
                draggable: false,
                connectable: false,
                data: {
                    recordId: record.id,
                    recordType: type === 'proposal' ? 'proposal' : 'node',
                    kind: record.nodeType || record.proposalType || record.kind,
                    label: record.label || proposalTitle(record),
                    summary: record.properties?.summary || record.rationale || '',
                    diffStatus: statusFor(record),
                    evidenceCount: Array.isArray(record.evidenceRefs) ? record.evidenceRefs.length : 0,
                    disposition: type === 'proposal'
                        ? (decisions[record.id]?.disposition || 'needs-review')
                        : undefined,
                    temporalState: temporal.state,
                    temporalLabel: temporal.label,
                },
                style: { width: NODE_WIDTH, height: NODE_HEIGHT },
            });
        });
    });

    const edges = graph.observations
        .filter(observation => visibleNodeIds.has(observation.subjectId) && visibleNodeIds.has(observation.objectId))
        .map(observation => {
            const temporal = temporalState(timelineContext, 'observation', observation.id);
            const baseColor = getEdgeColor(statusFor(observation));
            return {
            id: observation.id,
            source: observation.subjectId,
            target: observation.objectId,
            selected: Boolean(selectionContext?.selectedKeys?.has(`observation:${observation.id}`)),
            label: `«${observation.observationType}»${temporal.state === 'untimed' ? ' · untimed' : ''}`,
            type: 'smoothstep',
            data: {
                recordId: observation.id,
                recordType: 'observation',
                temporalState: temporal.state,
            },
            markerEnd: {
                type: MarkerType.ArrowClosed,
                color: temporal.state === 'inactive' ? '#334155' : baseColor,
            },
            style: {
                stroke: temporal.state === 'inactive' ? '#334155' : baseColor,
                strokeWidth: statusFor(observation) === 'broadened' ? 2.5 : 1.5,
                strokeDasharray: temporal.state === 'untimed'
                    ? '2 6'
                    : observation.basis === 'inferred' ? '6 5' : undefined,
                opacity: temporal.state === 'inactive' ? 0.18 : 1,
            },
            labelStyle: {
                fill: temporal.state === 'inactive' ? '#475569' : '#cbd5e1',
                fontSize: 10,
                fontWeight: 700,
            },
            labelBgStyle: {
                fill: '#111827',
                fillOpacity: 0.92,
            },
        };
        });

    if (semanticByLane.has('Policy')) {
        graph.proposals.forEach(proposal => {
            const proposalNodeId = `proposal:${proposal.id}`;
            if (!visibleNodeIds.has(proposalNodeId)) {
                return;
            }
            deriveProposalNodeLinks(graph, proposal)
                .filter(link => visibleNodeIds.has(link.nodeId))
                .forEach(link => {
                    const targetsPeer = link.relation === 'peer';
                    edges.push({
                        id: `derivation:${proposal.id}:${link.relation}:${link.nodeId}`,
                        source: targetsPeer ? proposalNodeId : link.nodeId,
                        target: targetsPeer ? link.nodeId : proposalNodeId,
                        label: `«${link.relation === 'subject' ? 'proposes' : link.relation}»`,
                        type: 'smoothstep',
                        animated: decisions[proposal.id]?.disposition === 'needs-review',
                        selectable: false,
                        markerEnd: { type: MarkerType.ArrowClosed, color: '#a78bfa' },
                        style: { stroke: '#a78bfa', strokeWidth: 2, strokeDasharray: '4 4' },
                        labelStyle: { fill: '#ddd6fe', fontSize: 10, fontWeight: 700 },
                        labelBgStyle: { fill: '#111827', fillOpacity: 0.92 },
                    });
                });
        });
    }

    return { nodes, edges };
};

export default function PolicyReviewCanvas() {
    const { state, dispatch } = usePolicyReviewStore();
    const timelineProjection = useMemo(
        () => createTimelineProjection(state.graph),
        [state.graph],
    );
    const timelineActivity = useMemo(() => selectTimelineActivity(timelineProjection, {
        cursorMs: Number.isFinite(state.timeline.cursorMs) ? state.timeline.cursorMs : 0,
        mode: state.timeline.mode,
        windowMs: state.timeline.windowMs,
        domains: state.timeline.domains,
        includeUntimed: true,
    }), [
        state.timeline.cursorMs,
        state.timeline.domains,
        state.timeline.mode,
        state.timeline.windowMs,
        timelineProjection,
    ]);
    const timelineItemsByRecord = useMemo(
        () => new Map(timelineProjection.items.map(item => [
            `${item.recordType}:${item.recordId}`,
            item,
        ])),
        [timelineProjection.items],
    );
    const timelineContext = useMemo(() => ({
        activeNodeIds: new Set(timelineActivity.nodeIds),
        activeObservationIds: new Set(timelineActivity.observationIds),
        itemsByRecord: timelineItemsByRecord,
    }), [timelineActivity, timelineItemsByRecord]);
    const selectionContext = useMemo(() => ({
        selectedKeys: new Set((state.selectedRecords || []).map(record => (
            `${record.type}:${record.id}`
        ))),
    }), [state.selectedRecords]);
    const elements = useMemo(
        () => buildPolicyReviewFlowElements(
            state.graph,
            state.decisions,
            state.laneFilter,
            timelineContext,
            selectionContext,
        ),
        [selectionContext, state.decisions, state.graph, state.laneFilter, timelineContext],
    );

    return (
        <div className={styles.canvas} aria-label="Semantic policy graph">
            <p className={styles.canvasSelectionHint}>
                Ctrl/Cmd-click nodes or evidence edges to multi-select. Shift-click policy proposals for a range.
            </p>
            <ReactFlow
                nodes={elements.nodes}
                edges={elements.edges}
                nodeTypes={nodeTypes}
                nodesDraggable={false}
                nodesConnectable={false}
                elementsSelectable
                fitView
                fitViewOptions={{ padding: 0.08, maxZoom: 1 }}
                minZoom={0.15}
                maxZoom={1.8}
                onNodeClick={(event, node) => {
                    if (node.data?.recordId) {
                        dispatch({
                            type: 'SELECT_RECORD',
                            record: { type: node.data.recordType, id: node.data.recordId },
                            toggle: event.ctrlKey || event.metaKey,
                            range: event.shiftKey && node.data.recordType === 'proposal',
                        });
                    }
                }}
                onEdgeClick={(event, edge) => {
                    if (edge.data?.recordId) {
                        dispatch({
                            type: 'SELECT_RECORD',
                            record: { type: edge.data.recordType, id: edge.data.recordId },
                            toggle: event.ctrlKey || event.metaKey,
                        });
                    }
                }}
                onPaneClick={() => dispatch({ type: 'SELECT', selected: null })}
                proOptions={{ hideAttribution: false }}
            >
                <Background color="#334155" gap={24} size={1} />
                <MiniMap
                    pannable
                    zoomable
                    nodeColor={node => {
                        if (node.type === 'lane') return '#111827';
                        if (node.data?.temporalState === 'inactive') return '#334155';
                        return getEdgeColor(node.data?.diffStatus);
                    }}
                    maskColor="rgba(2, 6, 23, 0.75)"
                />
                <Controls showInteractive={false} />
            </ReactFlow>
        </div>
    );
}
