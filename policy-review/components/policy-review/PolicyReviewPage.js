import Head from 'next/head';
import Link from 'next/link';
import { useEffect, useMemo, useRef, useState } from 'react';

import { createSelectedIptablesExport } from '../../modules/policy-review/iptablesExport';
import {
    applySemanticGraphDelta,
    createReviewRunStatus,
    createDecisionSetPreview,
    createSampleSemanticGraph,
    fetchSemanticGraphUrl,
    MAX_REVIEW_FILE_BYTES,
    parseHubbleJsonLines,
    parseSemanticGraphDelta,
    parseSemanticGraphJson,
} from '../../modules/policy-review/semanticGraph';
import { fetchPolicyReviewRuntimeAttestation } from '../../modules/policy-review/runtimeAttestation';
import { resolveAllowProposalSelection } from '../../modules/policy-review/proposalDerivation';
import {
    findSelectedRecord,
    findSelectedRecords,
    PolicyReviewProvider,
    usePolicyReviewStore,
} from '../../modules/policy-review/reviewStore';

import PolicyReviewCanvas, { POLICY_REVIEW_LANES } from './PolicyReviewCanvas';
import PolicyReviewTimeline from './PolicyReviewTimeline';
import ReviewWorkflow from './ReviewWorkflow';
import EndpointTable from './EndpointTable';
import styles from './PolicyReview.module.css';

const dispositions = [
    { id: 'accept', label: 'Accept' },
    { id: 'reject', label: 'Reject' },
    { id: 'needs-review', label: 'Needs review' },
];

const assuranceLabels = Object.freeze({
    'endpoint-only': {
        label: 'Endpoint only',
        detail: 'IP/FQDN, protocol, and port only. Every resource and future response at that authority remains mutable.',
        tone: 'danger',
    },
    'url-restricted': {
        label: 'URL restricted',
        detail: 'Force the exact HTTP method and request target through the reviewed proxy. The response bytes remain mutable.',
        tone: 'warning',
    },
    'native-integrity': {
        label: 'Native integrity',
        detail: 'Require the observed package-manager signature or lockfile integrity proof before content is consumed.',
        tone: 'strong',
    },
    'cas-replay': {
        label: 'Reviewed replay / CAS',
        detail: 'Serve only the reviewed content-addressed response bytes with upstream networking disabled.',
        tone: 'recommended',
    },
    'live-digest-gate': {
        label: 'Live digest gate',
        detail: 'Buffer the complete live response and release it only after it matches the reviewed digest.',
        tone: 'strong',
    },
});

const readReviewFile = async file => {
    if (!file) {
        throw new Error('No file selected');
    }
    if (file.size > MAX_REVIEW_FILE_BYTES) {
        throw new Error(`File exceeds the ${Math.round(MAX_REVIEW_FILE_BYTES / 1024 / 1024)} MiB review limit`);
    }
    return file.text();
};

const downloadText = (filename, value, type) => {
    const blob = new Blob([value], { type });
    const url = URL.createObjectURL(blob);
    const anchor = document.createElement('a');
    anchor.href = url;
    anchor.download = filename;
    anchor.click();
    URL.revokeObjectURL(url);
};

const safeDownloadFilename = (filename, fallback) => {
    const basename = String(filename || '').split(/[\\/]/).at(-1);
    const safe = basename.replace(/[^A-Za-z0-9._-]+/g, '-').slice(0, 160);
    return safe && !['.', '..'].includes(safe) ? safe : fallback;
};

const shortDigest = digest => {
    const value = String(digest || 'unbound');
    if (value.length <= 24) {
        return value;
    }
    return `${value.slice(0, 15)}…${value.slice(-8)}`;
};

const proposalTitle = proposal => {
    const intent = proposal.intent || {};
    const peer = intent.peer?.value || intent.peer?.kind || intent.operation || intent.domain;
    return `${intent.effect || 'review'} ${intent.direction || intent.domain || 'policy'} ${peer || ''}`.trim();
};

function ReviewHeader({ decisionSet, onOpenGraph, onOpenUrl, onOpenHubble, onOpenDelta }) {
    const { state, dispatch } = usePolicyReviewStore();
    return (
        <header className={styles.header}>
            <div className={styles.brand}>
                <Link href="/" aria-label="Back to launch pad">N</Link>
                <div>
                    <p>Nosh Guard</p>
                    <h1>Policy Review</h1>
                </div>
            </div>
            <div className={styles.graphIdentity}>
                <span className={styles.modeBadge} data-mode={state.graph.frozen ? 'frozen' : 'live'}>
                    {state.graph.frozen ? 'Frozen evidence' : state.streamPaused ? 'Live · paused' : 'Live evidence'}
                </span>
                <div>
                    <strong>{state.graph.graphId}</strong>
                    <small>rev {shortDigest(state.graph.revision)} · {shortDigest(state.graph.graphDigest)}</small>
                </div>
            </div>
            <details><summary>Evidence tools</summary><nav className={styles.headerActions} aria-label="Review actions">
                <button type="button" onClick={() => dispatch({
                    type: 'LOAD_GRAPH',
                    graph: createSampleSemanticGraph(),
                    sourceLabel: 'Built-in signed-baseline example',
                })}>
                    Example
                </button>
                <button type="button" onClick={onOpenGraph}>Open graph</button>
                <button type="button" onClick={onOpenUrl}>Open URL</button>
                <button type="button" onClick={onOpenHubble}>Import Hubble</button>
                {!state.graph.frozen ? (
                    <>
                        <button type="button" onClick={onOpenDelta} disabled={state.streamPaused}>Apply delta</button>
                        <button
                            type="button"
                            onClick={() => dispatch({ type: 'SET_STREAM_PAUSED', paused: !state.streamPaused })}
                        >
                            {state.streamPaused ? 'Resume' : 'Pause'}
                        </button>
                    </>
                ) : null}

            </nav></details>
        </header>
    );
}

function CoverageList() {
    const { state, dispatch } = usePolicyReviewStore();
    return (
        <section className={styles.sidebarSection}>
            <div className={styles.sectionHeading}>
                <h2>Coverage</h2>
                <span>{state.graph.coverage.filter(item => item.status === 'complete').length}/{state.graph.coverage.length}</span>
            </div>
            <div className={styles.coverageGrid}>
                {state.graph.coverage.map(marker => (
                    <button
                        key={marker.id}
                        type="button"
                        data-status={marker.status}
                        onClick={() => dispatch({ type: 'SELECT', selected: { type: 'coverage', id: marker.id } })}
                    >
                        <span>{marker.domain}</span>
                        <strong>{marker.status}</strong>
                    </button>
                ))}
            </div>
        </section>
    );
}

function DiffSummary() {
    const { state } = usePolicyReviewStore();
    const summary = state.graph.diff.reduce((result, record) => ({
        ...result,
        [record.changeType]: (result[record.changeType] || 0) + 1,
    }), {});
    return (
        <section className={styles.sidebarSection}>
            <div className={styles.sectionHeading}>
                <h2>Baseline drift</h2>
                <span>{state.graph.diff.length}</span>
            </div>
            <div className={styles.diffSummary}>
                {['broadened', 'added', 'coverage-degraded', 'removed', 'metric-only', 'unchanged'].map(status => (
                    <div key={status} data-status={status}>
                        <span />
                        <strong>{summary[status] || 0}</strong>
                        <small>{status}</small>
                    </div>
                ))}
            </div>
        </section>
    );
}

const displayStatus = value => String(value || 'not-declared').replaceAll('-', ' ');

function RunStatusSummary() {
    const { state } = usePolicyReviewStore();
    const summary = useMemo(() => createReviewRunStatus(state.graph), [state.graph]);
    const dnsStatus = summary.dns.status === 'loss'
        ? `${summary.dns.lostEvents} lost event${summary.dns.lostEvents === '1' ? '' : 's'}`
        : displayStatus(summary.dns.status);
    return (
        <section className={`${styles.sidebarSection} ${styles.runStatusSection}`}>
            <div className={styles.sectionHeading}>
                <h2>Run status</h2>
                <span>{summary.runId || 'graph snapshot'}</span>
            </div>
            <dl className={styles.runStatusGrid}>
                <div data-status={summary.runState}>
                    <dt>Evidence run</dt>
                    <dd>{displayStatus(summary.runState)}</dd>
                </div>
                <div data-status={summary.candidateState}>
                    <dt>Candidate</dt>
                    <dd>{displayStatus(summary.candidateState)}</dd>
                </div>
                <div data-status={summary.sourceCoverage.incomplete.length ? 'incomplete' : 'complete'}>
                    <dt>Source coverage</dt>
                    <dd>{summary.sourceCoverage.complete}/{summary.sourceCoverage.total} complete</dd>
                </div>
                <div data-status={summary.dns.status}>
                    <dt>DNS loss</dt>
                    <dd>{dnsStatus}</dd>
                </div>
                <div data-status={summary.blockingFindings.length ? 'blocking' : 'complete'}>
                    <dt>Blocking findings</dt>
                    <dd>{summary.blockingFindings.length}</dd>
                </div>
                <div data-status={summary.activationState}>
                    <dt>Activation</dt>
                    <dd>{displayStatus(summary.activationState)}</dd>
                </div>
            </dl>
            {summary.sourceCoverage.incomplete.length ? (
                <p className={styles.runStatusDetail}>
                    <strong>Incomplete source coverage:</strong>{' '}
                    {summary.sourceCoverage.incomplete
                        .map(source => `${source.name} (${source.status})`)
                        .join(', ')}
                </p>
            ) : null}
            {summary.incompleteCoverage.length ? (
                <p className={styles.runStatusDetail}>
                    <strong>Coverage gaps:</strong>{' '}
                    {summary.incompleteCoverage
                        .map(marker => `${marker.domain} (${marker.status})`)
                        .join(', ')}
                </p>
            ) : null}
            {summary.blockingFindings.length ? (
                <ul className={styles.runFindingList} aria-label="Blocking findings">
                    {summary.blockingFindings.slice(0, 4).map(finding => (
                        <li key={finding.id}>{finding.message}</li>
                    ))}
                    {summary.blockingFindings.length > 4 ? (
                        <li>+{summary.blockingFindings.length - 4} more blocking findings</li>
                    ) : null}
                </ul>
            ) : null}
        </section>
    );
}

function LaneFilter() {
    const { state, dispatch } = usePolicyReviewStore();
    return (
        <section className={styles.sidebarSection}>
            <div className={styles.sectionHeading}>
                <h2>Projection</h2>
                <span>UML lanes</span>
            </div>
            <div className={styles.laneFilters}>
                {['All', ...POLICY_REVIEW_LANES].map(lane => (
                    <button
                        key={lane}
                        type="button"
                        aria-pressed={state.laneFilter === lane}
                        onClick={() => dispatch({ type: 'SET_LANE_FILTER', laneFilter: lane })}
                    >
                        {lane}
                    </button>
                ))}
            </div>
        </section>
    );
}

function ProposalList() {
    const { state, dispatch } = usePolicyReviewStore();
    const counts = Object.values(state.decisions).reduce((result, decision) => ({
        ...result,
        [decision.disposition]: (result[decision.disposition] || 0) + 1,
    }), {});
    return (
        <section className={`${styles.sidebarSection} ${styles.proposalListSection}`}>
            <div className={styles.sectionHeading}>
                <h2>Proposals</h2>
                <span>{counts.accept || 0} accepted · {counts.reject || 0} rejected</span>
            </div>
            {state.graph.proposals.length ? (
                <div className={styles.selectionActions}>
                    <span>{state.selectedProposalIds.length} selected</span>
                    <button
                        type="button"
                        onClick={() => dispatch({ type: 'SELECT_ALL_PROPOSALS' })}
                    >
                        Select all
                    </button>
                    <button
                        type="button"
                        disabled={!state.selectedRecords.length}
                        onClick={() => dispatch({ type: 'SELECT', selected: null })}
                    >
                        Clear
                    </button>
                </div>
            ) : null}
            <div className={styles.proposalList}>
                {state.graph.proposals.length ? state.graph.proposals.map(proposal => (
                    <button
                        key={proposal.id}
                        type="button"
                        data-disposition={state.decisions[proposal.id]?.disposition}
                        aria-pressed={state.selectedProposalIds.includes(proposal.id)}
                        onClick={event => dispatch({
                            type: 'SELECT_PROPOSAL',
                            proposalId: proposal.id,
                            toggle: event.ctrlKey || event.metaKey,
                            range: event.shiftKey,
                        })}
                    >
                        <span>{proposal.kind}</span>
                        <strong>{proposalTitle(proposal)}</strong>
                        <small>{state.decisions[proposal.id]?.disposition || 'needs-review'}</small>
                    </button>
                )) : <p className={styles.emptyState}>No proposals in this graph.</p>}
            </div>
            {state.graph.proposals.length ? (
                <p className={styles.selectionHint}>
                    Ctrl/Cmd-click toggles proposals. Shift-click selects a range.
                </p>
            ) : null}
        </section>
    );
}

function ReviewSidebar() {
    const { state } = usePolicyReviewStore();
    return (
        <aside className={styles.sidebar}>
            <section className={styles.scopeCard}>
                <span>{state.graph.scope.class} policy</span>
                <strong>{state.graph.scope.projectKey || state.graph.graphId}</strong>
                <small>{state.sourceLabel}</small>
            </section>
            <RunStatusSummary />
            <DiffSummary />
            <CoverageList />
            <LaneFilter />
            <ProposalList />
        </aside>
    );
}

const RecordDetails = ({ record }) => {
    const entries = Object.entries(record).filter(([, value]) => (
        ['string', 'number', 'boolean'].includes(typeof value)
    ));
    return (
        <dl className={styles.recordDetails}>
            {entries.map(([key, value]) => (
                <div key={key}>
                    <dt>{key}</dt>
                    <dd>{String(value)}</dd>
                </div>
            ))}
        </dl>
    );
};

function WebAssuranceReview({ proposal }) {
    const { state, dispatch } = usePolicyReviewStore();
    if (!proposal.authorityGroupId) return null;
    const alternatives = state.graph.proposals.filter(candidate => (
        candidate.authorityGroupId === proposal.authorityGroupId
    ));
    if (!alternatives.length) return null;
    const selected = alternatives.find(candidate => (
        state.decisions[candidate.id]?.disposition === 'accept'
    ));
    return (
        <section className={styles.assuranceReview}>
            <h3>Web download assurance</h3>
            <p>
                Choose one frozen, evidence-derived authority. This control cannot invent a URL,
                response digest, or package proof.
            </p>
            <div className={styles.assuranceChoices} role="radiogroup" aria-label="Web download assurance">
                {alternatives.map(candidate => {
                    const assurance = candidate.assurance || {};
                    const presentation = assuranceLabels[assurance.level] || {
                        label: assurance.level || 'Observed authority',
                        detail: candidate.rationale,
                        tone: 'warning',
                    };
                    return (
                        <button
                            key={candidate.id}
                            type="button"
                            role="radio"
                            aria-checked={selected?.id === candidate.id}
                            data-tone={presentation.tone}
                            onClick={() => dispatch({
                                type: 'SELECT_AUTHORITY_VARIANT',
                                proposalId: candidate.id,
                            })}
                        >
                            <span>
                                <strong>{presentation.label}</strong>
                                {presentation.tone === 'recommended' ? <em>Recommended</em> : null}
                            </span>
                            <small>{presentation.detail}</small>
                            {assurance.contentDigest ? (
                                <code>{shortDigest(assurance.contentDigest)}</code>
                            ) : null}
                        </button>
                    );
                })}
            </div>
            <button
                className={styles.denyAuthorityButton}
                type="button"
                onClick={() => dispatch({
                    type: 'REJECT_AUTHORITY_GROUP',
                    authorityGroupId: proposal.authorityGroupId,
                })}
            >
                Deny every authority variant
            </button>
            {selected?.assurance?.mutableContent ? (
                <p className={styles.mutableContentWarning} role="status">
                    The selected authority does not bind response bytes. The same URL may return
                    different content later.
                </p>
            ) : null}
        </section>
    );
}

function ProposalReview({ proposal }) {
    const { state, dispatch } = usePolicyReviewStore();
    const decision = state.decisions[proposal.id];
    return (
        <section className={styles.proposalReview}>
            <WebAssuranceReview proposal={proposal} />
            <h3>Disposition</h3>
            <div className={styles.dispositionButtons}>
                {dispositions.map(disposition => (
                    <button
                        key={disposition.id}
                        type="button"
                        data-disposition={disposition.id}
                        aria-pressed={decision?.disposition === disposition.id}
                        onClick={() => dispatch({
                            type: 'SET_DISPOSITION',
                            proposalId: proposal.id,
                            disposition: disposition.id,
                        })}
                    >
                        {disposition.label}
                    </button>
                ))}
            </div>
            <label className={styles.rationaleField}>
                <span>Reviewer rationale</span>
                <textarea
                    value={decision?.rationale || ''}
                    maxLength={4096}
                    placeholder="Explain why this observed behavior should be allowed or denied."
                    onChange={event => dispatch({
                        type: 'SET_RATIONALE',
                        proposalId: proposal.id,
                        rationale: event.target.value,
                    })}
                />
            </label>
            <h3>Target projection</h3>
            <div className={styles.targetMatrix}>
                {proposal.targetFeasibility.map(target => (
                    <div key={target.target} className={styles.targetEntry}>
                        <span>{target.target}</span>
                        <strong data-status={target.status}>{target.status}</strong>
                        {['restrictive', 'conditional'].includes(target.status) ? (
                            <label className={styles.targetAcknowledgement}>
                                <input
                                    type="checkbox"
                                    checked={Boolean(decision?.targetAcknowledgements?.[target.target]?.acknowledged)}
                                    onChange={event => dispatch({
                                        type: 'SET_TARGET_ACKNOWLEDGEMENT',
                                        proposalId: proposal.id,
                                        target: target.target,
                                        update: { acknowledged: event.target.checked },
                                    })}
                                />
                                <span>Acknowledge projection tradeoff</span>
                                <input
                                    type="text"
                                    maxLength={4096}
                                    value={decision?.targetAcknowledgements?.[target.target]?.rationale || ''}
                                    placeholder="Why is this projection acceptable?"
                                    onChange={event => dispatch({
                                        type: 'SET_TARGET_ACKNOWLEDGEMENT',
                                        proposalId: proposal.id,
                                        target: target.target,
                                        update: { rationale: event.target.value },
                                    })}
                                />
                            </label>
                        ) : null}
                    </div>
                ))}
                {!proposal.targetFeasibility.length ? <p>No target projections materialized.</p> : null}
            </div>
            <h3>Typed rule</h3>
            <pre className={styles.jsonPreview}>{JSON.stringify(proposal.intent, null, 2)}</pre>
        </section>
    );
}

function BulkProposalReview({ proposals }) {
    const { state, dispatch } = usePolicyReviewStore();
    const [rationale, setRationale] = useState('');
    const [appliedDisposition, setAppliedDisposition] = useState(null);
    const proposalIds = proposals.map(proposal => proposal.id);
    const selectedDecisions = proposalIds.map(proposalId => state.decisions[proposalId]);
    const currentDispositions = new Set(selectedDecisions.map(decision => decision?.disposition));
    const sharedDisposition = currentDispositions.size === 1
        ? selectedDecisions[0]?.disposition
        : null;
    const rationaleValid = Boolean(rationale.trim()) && rationale.trim().length <= 4096;
    const acknowledgementCount = proposals.filter(proposal => (
        proposal.targetFeasibility.some(target => (
            target.target === state.intendedTarget
            && ['restrictive', 'conditional'].includes(target.status)
        ))
    )).length;

    const applyDisposition = disposition => {
        if (!rationaleValid) {
            return;
        }
        dispatch({
            type: 'SET_BULK_PROPOSAL_DECISION',
            proposalIds,
            disposition,
            rationale,
        });
        setAppliedDisposition(disposition);
    };

    return (
        <section className={styles.bulkProposalReview}>
            <h3>Bulk disposition</h3>
            <p>
                Apply one review decision to {proposals.length} selected proposals. Each proposal remains
                a separate digest-bound decision entry.
            </p>
            <label className={styles.rationaleField}>
                <span>Required shared rationale</span>
                <textarea
                    value={rationale}
                    maxLength={4096}
                    aria-invalid={!rationaleValid}
                    aria-describedby="bulk-rationale-help"
                    placeholder="Explain why every selected proposal should receive this disposition."
                    onChange={event => {
                        setRationale(event.target.value);
                        setAppliedDisposition(null);
                    }}
                />
            </label>
            <p id="bulk-rationale-help" className={styles.bulkRationaleHelp}>
                A non-empty rationale is required before a bulk decision can be applied.
            </p>
            <div className={styles.dispositionButtons}>
                {dispositions.map(disposition => (
                    <button
                        key={disposition.id}
                        type="button"
                        data-disposition={disposition.id}
                        aria-pressed={sharedDisposition === disposition.id}
                        disabled={!rationaleValid}
                        onClick={() => applyDisposition(disposition.id)}
                    >
                        {disposition.label} all
                    </button>
                ))}
            </div>
            {appliedDisposition ? (
                <p className={styles.bulkApplyStatus} role="status">
                    Applied {appliedDisposition} to {proposals.length} proposals.
                </p>
            ) : null}
            {acknowledgementCount ? (
                <p className={styles.bulkProjectionWarning}>
                    {acknowledgementCount} accepted proposal{acknowledgementCount === 1 ? '' : 's'} will still
                    require individual {state.intendedTarget} projection acknowledgement.
                </p>
            ) : null}
        </section>
    );
}

function SelectedIptablesExport({ proposalIds }) {
    const { state } = usePolicyReviewStore();
    const [sourceIpv4, setSourceIpv4] = useState('');
    const [uplinkInterface, setUplinkInterface] = useState('');
    const [includeMasquerade, setIncludeMasquerade] = useState(false);
    const [preview, setPreview] = useState(null);
    const [error, setError] = useState(null);
    const [generating, setGenerating] = useState(false);
    const selectionSignature = JSON.stringify([...proposalIds].sort());
    const decisionSignature = JSON.stringify(proposalIds.map(proposalId => {
        const decision = state.decisions[proposalId];
        return [proposalId, decision?.disposition || '', decision?.rationale || ''];
    }));
    const exportBinding = JSON.stringify([
        state.graph.contentDigest,
        selectionSignature,
        decisionSignature,
        sourceIpv4.trim(),
        uplinkInterface.trim(),
        includeMasquerade,
    ]);
    const generatedExport = preview?.binding === exportBinding ? preview.result : null;
    const exportError = error?.binding === exportBinding ? error.message : null;

    const updateContext = setter => event => {
        setter(event.target.type === 'checkbox' ? event.target.checked : event.target.value);
        setPreview(null);
        setError(null);
    };

    const generatePreview = async event => {
        event.preventDefault();
        if (generating || !state.graph.frozen || !proposalIds.length) {
            return;
        }
        setGenerating(true);
        setPreview(null);
        setError(null);
        try {
            const result = await createSelectedIptablesExport({
                graph: state.graph,
                proposalIds,
                decisions: state.decisions,
                context: {
                    sourceIpv4: sourceIpv4.trim(),
                    uplinkInterface: uplinkInterface.trim(),
                    includeMasquerade,
                },
            });
            setPreview({ binding: exportBinding, result });
        } catch (caught) {
            setError({
                binding: exportBinding,
                message: caught instanceof Error
                    ? caught.message
                    : 'Could not create the unsigned iptables sketch',
            });
        } finally {
            setGenerating(false);
        }
    };

    const downloadPreview = () => {
        if (!generatedExport?.script || !generatedExport.exportedProposalIds.length) {
            return;
        }
        downloadText(
            safeDownloadFilename(generatedExport.filename, 'nosh-selected-rules.iptables-sketch.sh'),
            generatedExport.script,
            'text/x-shellscript;charset=utf-8',
        );
    };

    const nonProposalSelectionCount = Math.max(
        0,
        state.selectedRecords.length - proposalIds.length,
    );

    return (
        <section className={styles.iptablesExport} aria-busy={generating}>
            <h3>Unsigned selected-rule iptables sketch</h3>
            <p>
                Evaluate {proposalIds.length} explicitly selected proposal
                {proposalIds.length === 1 ? '' : 's'} for a legacy static syntax sketch.
                {nonProposalSelectionCount ? (
                    <> {nonProposalSelectionCount} selected evidence record
                        {nonProposalSelectionCount === 1 ? ' is' : 's are'} not implicitly promoted.</>
                ) : null}
            </p>
            <p>
                Only accepted, rationale-backed, static egress IPv4/CIDR allow proposals with an exact
                gateway-iptables projection are sketched. This helper adds no implicit RFC1918 or DNS-port
                policy; all other mappings remain visible and are skipped.
            </p>
            <div className={styles.iptablesSafetyNotice}>
                <strong>Unsigned browser sketch only</strong>
                <span>
                    The downloaded shell script only prints deterministic `iptables-restore --noflush`
                    input. It is not a DecisionSet, PolicyIR, target projection, signed Guard artifact,
                    or deployment authority.
                </span>
            </div>
            {!state.graph.frozen ? (
                <p className={styles.iptablesExportBlocked} role="status">
                    Freeze and digest-bind the graph before generating this sketch.
                </p>
            ) : null}
            <form className={styles.iptablesExportForm} onSubmit={generatePreview}>
                <fieldset disabled={generating}>
                    <label>
                        <span>Routed source IPv4</span>
                        <input
                            type="text"
                            inputMode="decimal"
                            autoComplete="off"
                            spellCheck="false"
                            required
                            maxLength={15}
                            value={sourceIpv4}
                            placeholder="10.20.0.15"
                            onChange={updateContext(setSourceIpv4)}
                        />
                    </label>
                    <label>
                        <span>Gateway uplink</span>
                        <input
                            type="text"
                            autoComplete="off"
                            spellCheck="false"
                            required
                            maxLength={15}
                            pattern="[A-Za-z0-9_.:-]{1,15}"
                            value={uplinkInterface}
                            placeholder="eth0"
                            onChange={updateContext(setUplinkInterface)}
                        />
                    </label>
                    <label className={styles.iptablesMasquerade}>
                        <input
                            type="checkbox"
                            checked={includeMasquerade}
                            onChange={updateContext(setIncludeMasquerade)}
                        />
                        <span>Include selected-source masquerade in printed restore input</span>
                    </label>
                </fieldset>
                <button
                    type="submit"
                    disabled={generating || !state.graph.frozen || !proposalIds.length}
                >
                    {generating ? 'Generating…' : 'Generate unsigned sketch'}
                </button>
            </form>
            {exportError ? <p className={styles.iptablesExportError} role="alert">{exportError}</p> : null}
            {generatedExport ? (
                <div className={styles.iptablesExportPreview}>
                    <div className={styles.iptablesExportSummary}>
                        <span>
                            <strong>{generatedExport.exportedProposalIds.length}</strong>
                            rules rendered
                        </span>
                        <span>
                            <strong>{generatedExport.mappings.length - generatedExport.exportedProposalIds.length}</strong>
                            skipped
                        </span>
                    </div>
                    <ul className={styles.iptablesMappings}>
                        {generatedExport.mappings.map(mapping => (
                            <li key={mapping.proposalId} data-status={mapping.status}>
                                <span>{mapping.proposalId}</span>
                                <strong>{mapping.status}</strong>
                                {mapping.reasons.length ? <small>{mapping.reasons.join(' · ')}</small> : null}
                            </li>
                        ))}
                    </ul>
                    {generatedExport.warnings.length ? (
                        <div className={styles.iptablesWarnings}>
                            <strong>Sketch warnings</strong>
                            <ul>
                                {generatedExport.warnings.map(warning => <li key={warning}>{warning}</li>)}
                            </ul>
                        </div>
                    ) : null}
                    <dl className={styles.iptablesExportDigests}>
                        <div>
                            <dt>File</dt>
                            <dd>
                                {generatedExport.filename
                                    ? safeDownloadFilename(
                                        generatedExport.filename,
                                        'nosh-selected-rules.iptables-sketch.sh',
                                    )
                                    : 'not generated'}
                            </dd>
                        </div>
                        <div><dt>Selection</dt><dd title={generatedExport.selectionDigest}>{shortDigest(generatedExport.selectionDigest)}</dd></div>
                        <div>
                            <dt>Script</dt>
                            <dd title={generatedExport.scriptDigest || undefined}>
                                {generatedExport.scriptDigest ? shortDigest(generatedExport.scriptDigest) : 'not generated'}
                            </dd>
                        </div>
                    </dl>
                    {generatedExport.script ? (
                        <details className={styles.iptablesScriptPreview}>
                            <summary>Review generated unsigned sketch</summary>
                            <pre className={styles.jsonPreview}>{generatedExport.script}</pre>
                        </details>
                    ) : null}
                    <button
                        className={styles.iptablesDownloadButton}
                        type="button"
                        disabled={!generatedExport.exportedProposalIds.length}
                        onClick={downloadPreview}
                    >
                        Download unsigned print-only sketch
                    </button>
                    {!generatedExport.exportedProposalIds.length ? (
                        <p className={styles.iptablesExportBlocked} role="status">
                            Nothing was downloadable: every selected proposal was skipped. Review each mapping above.
                        </p>
                    ) : null}
                </div>
            ) : null}
        </section>
    );
}

function MultiSelectionSummary({ entries }) {
    return (
        <section className={styles.multiSelectionSummary}>
            <h3>Selected records</h3>
            <ul>
                {entries.map(({ selection, record }) => (
                    <li key={`${selection.type}:${selection.id}`}>
                        <span>{selection.type}</span>
                        <strong>
                            {record.label
                                || record.message
                                || (selection.type === 'proposal' ? proposalTitle(record) : '')
                                || record.domain
                                || record.id}
                        </strong>
                    </li>
                ))}
            </ul>
        </section>
    );
}

function AllowSelectedTelemetry({ selections }) {
    const { state, dispatch } = usePolicyReviewStore();
    const [rationale, setRationale] = useState('');
    const [applied, setApplied] = useState(false);
    const telemetrySelections = selections.filter(selection => (
        selection.type === 'node' || selection.type === 'observation'
    ));
    const telemetrySelectionKey = telemetrySelections
        .map(selection => `${selection.type}:${selection.id}`)
        .join('|');
    const resolution = useMemo(
        () => resolveAllowProposalSelection(state.graph, telemetrySelections),
        [state.graph, telemetrySelectionKey],
    );
    if (!telemetrySelections.length) {
        return null;
    }

    const rationaleValid = Boolean(rationale.trim()) && rationale.trim().length <= 4096;
    const canApply = rationaleValid && resolution.allowProposalIds.length > 0;
    const targetAcknowledgementCount = resolution.allowProposalIds.filter(proposalId => (
        state.graph.proposals.find(proposal => proposal.id === proposalId)
            ?.targetFeasibility.some(target => (
                target.target === state.intendedTarget
                && ['restrictive', 'conditional'].includes(target.status)
            ))
    )).length;
    const projectionAcknowledgementCount = state.graph.proposals.filter(proposal => (
        resolution.allowProposalIds.includes(proposal.id)
        && proposal.targetFeasibility.some(target => (
            target.target === state.intendedTarget
            && ['restrictive', 'conditional'].includes(target.status)
        ))
    )).length;
    const applyAllow = () => {
        if (!canApply) {
            return;
        }
        dispatch({
            type: 'SET_BULK_PROPOSAL_DECISION',
            proposalIds: resolution.allowProposalIds,
            disposition: 'accept',
            rationale,
        });
        setApplied(true);
    };

    return (
        <section className={styles.allowSelectionReview}>
            <h3>Allow selected telemetry</h3>
            <p>
                {resolution.resolvedSelections.length}/{telemetrySelections.length} selected telemetry
                records resolve to {resolution.allowProposalIds.length} existing allow proposal
                {resolution.allowProposalIds.length === 1 ? '' : 's'}.
            </p>
            <label className={styles.rationaleField}>
                <span>Required allow rationale</span>
                <textarea
                    value={rationale}
                    maxLength={4096}
                    aria-invalid={!rationaleValid}
                    placeholder="Explain why every exactly linked allow proposal should be accepted."
                    onChange={event => {
                        setRationale(event.target.value);
                        setApplied(false);
                    }}
                />
            </label>
            <button
                className={styles.allowSelectionButton}
                type="button"
                disabled={!canApply}
                onClick={applyAllow}
            >
                Accept {resolution.allowProposalIds.length} linked allow proposal
                {resolution.allowProposalIds.length === 1 ? '' : 's'}
            </button>
            {applied ? (
                <p className={styles.bulkApplyStatus} role="status">
                    Accepted {resolution.allowProposalIds.length} digest-bound allow proposal
                    {resolution.allowProposalIds.length === 1 ? '' : 's'}.
                </p>
            ) : null}
            {targetAcknowledgementCount ? (
                <p className={styles.selectionIntegrityNote}>
                    {targetAcknowledgementCount} linked proposal
                    {targetAcknowledgementCount === 1 ? '' : 's'} still require individual
                    {' '}{state.intendedTarget} projection acknowledgement before export.
                </p>
            ) : null}
            {resolution.unsupportedSelections.length ? (
                <div className={styles.unsupportedSelections} role="status">
                    <strong>{resolution.unsupportedSelections.length} selection{resolution.unsupportedSelections.length === 1 ? '' : 's'} not applied</strong>
                    <ul>
                        {resolution.unsupportedSelections.map(selection => (
                            <li key={`${selection.type}:${selection.id}`}>
                                <span>{selection.type}:{selection.id}</span>
                                <small>{selection.reason}</small>
                            </li>
                        ))}
                    </ul>
                </div>
            ) : null}
            {projectionAcknowledgementCount ? (
                <p className={styles.bulkProjectionWarning}>
                    {projectionAcknowledgementCount} linked proposal
                    {projectionAcknowledgementCount === 1 ? '' : 's'} will require individual
                    {' '}{state.intendedTarget} projection acknowledgement after acceptance.
                </p>
            ) : null}
            <p className={styles.selectionIntegrityNote}>
                This action only updates reviews for exact, digest-bound proposals. It never creates or
                changes records in the frozen evidence graph.
            </p>
        </section>
    );
}

function EvidenceReferences({ record }) {
    const references = Array.isArray(record?.evidenceRefs) ? record.evidenceRefs : [];
    return (
        <section className={styles.evidenceRefs}>
            <h3>Evidence references</h3>
            {references.length ? (
                <ul>
                    {references.map(reference => <li key={reference}>{reference}</li>)}
                </ul>
            ) : <p>No direct references on this record.</p>}
        </section>
    );
}

function ReviewChecklist({ decisionSet }) {
    const { state, dispatch } = usePolicyReviewStore();
    const assuranceSummary = state.graph.proposals.reduce((summary, proposal) => {
        if (
            !proposal.authorityGroupId
            || state.decisions[proposal.id]?.disposition !== 'accept'
        ) {
            return summary;
        }
        const level = proposal.assurance?.level || 'unknown';
        return { ...summary, [level]: (summary[level] || 0) + 1 };
    }, {});
    return (
        <section className={styles.checklist}>
            <div className={styles.reviewState} data-ready={decisionSet.reviewState === 'complete'}>
                <span>{decisionSet.reviewState === 'complete' ? 'Review decisions complete' : 'Draft review'}</span>
                <strong>{decisionSet.blockers.length} blocker{decisionSet.blockers.length === 1 ? '' : 's'}</strong>
            </div>
            <p>
                This browser only records decisions. Nosh Guard verifies the digests and performs signing outside the UI.
            </p>
            {decisionSet.reviewState === 'complete' ? (
                <section className={styles.activationHandoff} data-testid="signed-activation-handoff">
                    <h3>Apply the saved profile</h3>
                    <p>
                        Open Review selections above, save the reviewed policy, then copy its apply command. The host verifies
                        the saved digest, projects the rules, signs approval, and activates the policy.
                        Saving or downloading JSON alone does not apply it.
                    </p>
                </section>
            ) : null}
            {Object.keys(assuranceSummary).length ? (
                <section className={styles.assuranceSummary}>
                    <h3>Selected web assurance</h3>
                    <dl>
                        {Object.entries(assuranceSummary).sort(([left], [right]) => (
                            left.localeCompare(right)
                        )).map(([level, count]) => (
                            <div key={level}>
                                <dt>{assuranceLabels[level]?.label || level}</dt>
                                <dd>{count}</dd>
                            </div>
                        ))}
                    </dl>
                </section>
            ) : null}

            <details><summary>Technical details: blockers and integrity</summary>
            <h3>Current blockers</h3>
            {decisionSet.blockers.length ? (
                <ul className={styles.blockerList}>
                    {decisionSet.blockers.map(blocker => <li key={blocker}>{blocker}</li>)}
                </ul>
            ) : <p className={styles.noBlockers}>All review gates represented in this bundle are satisfied.</p>}
            <h3>Integrity bindings</h3>
            <dl className={styles.digestList}>
                <div><dt>Graph</dt><dd>{state.graph.graphDigest}</dd></div>
                <div><dt>Graph content</dt><dd>{state.graph.contentDigest || 'live / unbound'}</dd></div>
                <div><dt>Proposal set</dt><dd>{state.graph.proposalSetDigest || 'missing'}</dd></div>
                <div><dt>Base policy</dt><dd>{state.graph.basePolicyDigest || 'missing'}</dd></div>
                <div><dt>Scope</dt><dd>{state.graph.scope.scopeDigest}</dd></div>
            </dl></details>
        </section>
    );
}

function EvidenceInspector({ decisionSet }) {
    const { state, dispatch } = usePolicyReviewStore();
    const record = findSelectedRecord(state);
    const selectedEntries = findSelectedRecords(state);
    const selectedProposals = selectedEntries
        .filter(entry => entry.selection.type === 'proposal')
        .map(entry => entry.record);
    if (!record) {
        return (
            <aside id="review-inspector" tabIndex={-1} className={styles.inspector}>
                <header>
                    <div><span>Review gate</span><h2>Approval readiness</h2></div>
                </header>
                <ReviewChecklist decisionSet={decisionSet} />
            </aside>
        );
    }
    if (selectedEntries.length > 1) {
        const selectionKey = selectedEntries
            .map(entry => `${entry.selection.type}:${entry.selection.id}`)
            .join('|');
        return (
            <aside id="review-inspector" tabIndex={-1} className={styles.inspector}>
                <header>
                    <div>
                        <span>Multi-selection</span>
                        <h2>{selectedEntries.length} records · {selectedProposals.length} proposals</h2>
                    </div>
                    <button type="button" onClick={() => dispatch({ type: 'SELECT', selected: null })}>×</button>
                </header>
                <div className={styles.inspectorBody}>
                    <MultiSelectionSummary entries={selectedEntries} />
                    <AllowSelectedTelemetry
                        key={`allow:${selectionKey}`}
                        selections={selectedEntries.map(entry => entry.selection)}
                    />
                    {selectedProposals.length > 1 ? (
                        <BulkProposalReview key={selectionKey} proposals={selectedProposals} />
                    ) : null}
                    {selectedProposals.length === 1 ? (
                        <ProposalReview proposal={selectedProposals[0]} />
                    ) : null}
                    {selectedProposals.length ? (
                        <SelectedIptablesExport
                            key={`iptables:${selectionKey}`}
                            proposalIds={selectedProposals.map(proposal => proposal.id)}
                        />
                    ) : null}
                </div>
            </aside>
        );
    }
    return (
        <aside id="review-inspector" tabIndex={-1} className={styles.inspector}>
            <header>
                <div>
                    <span>{state.selected.type}</span>
                    <h2>{record.label || record.message || (state.selected.type === 'proposal' ? proposalTitle(record) : '') || record.domain || record.id}</h2>
                </div>
                <button type="button" onClick={() => dispatch({ type: 'SELECT', selected: null })}>×</button>
            </header>
            <div className={styles.inspectorBody}>
                {record.message ? <p className={styles.recordDescription}>{record.message}</p> : null}
                <RecordDetails record={record} />
                <AllowSelectedTelemetry
                    key={`allow:${state.selected.type}:${state.selected.id}`}
                    selections={selectedEntries.map(entry => entry.selection)}
                />
                {state.selected.type === 'proposal' ? <ProposalReview proposal={record} /> : null}
                {state.selected.type === 'proposal' ? (
                    <SelectedIptablesExport
                        key={`iptables:${record.id}`}
                        proposalIds={[record.id]}
                    />
                ) : null}
                <EvidenceReferences record={record} />
                <details className={styles.rawRecord}>
                    <summary>Raw safe JSON record</summary>
                    <pre className={styles.jsonPreview}>{JSON.stringify(record, null, 2)}</pre>
                </details>
            </div>
        </aside>
    );
}

function PolicyReviewWorkspace() {
    const { state, dispatch } = usePolicyReviewStore();
    const graphInputRef = useRef(null);
    const hubbleInputRef = useRef(null);
    const deltaInputRef = useRef(null);
    const [message, setMessage] = useState(null);
    const [showUrlLoader, setShowUrlLoader] = useState(false);
    const [graphUrl, setGraphUrl] = useState('');
    const [urlLoading, setUrlLoading] = useState(false);
    const [view, setView] = useState('endpoints');
    const queryGraphLoadedRef = useRef(false);
    const decisionSet = useMemo(() => createDecisionSetPreview({
        graph: state.graph,
        decisions: state.decisions,
        intendedTarget: state.intendedTarget,
        reviewer: state.reviewer,
        reviewerAcknowledged: state.reviewerAcknowledged,
    }), [
        state.decisions,
        state.graph,
        state.intendedTarget,
        state.reviewer,
        state.reviewerAcknowledged,
    ]);

    const loadFile = async (event, parser, sourceLabel) => {
        const input = event.currentTarget;
        try {
            const file = input.files?.[0];
            const text = await readReviewFile(file);
            const graph = await parser(text);
            dispatch({ type: 'LOAD_GRAPH', graph, sourceLabel: `${sourceLabel}: ${file.name}` });
            setMessage({ type: 'success', text: `Loaded ${file.name}` });
        } catch (error) {
            setMessage({ type: 'error', text: error.message });
        } finally {
            input.value = '';
        }
    };

    const loadGraphFromUrl = async selectedUrl => {
        if (urlLoading) {
            return;
        }
        setUrlLoading(true);
        try {
            const attestation = await fetchPolicyReviewRuntimeAttestation();
            const graph = await fetchSemanticGraphUrl(selectedUrl, {
                attestedGraphOrigin: attestation.graphOrigin,
            });
            dispatch({
                type: 'LOAD_GRAPH',
                graph,
                sourceLabel: 'Nosh review server graph',
            });
            setGraphUrl('');
            setShowUrlLoader(false);
            setMessage({ type: 'success', text: 'Loaded the semantic graph from the supplied review URL.' });
        } catch (error) {
            setMessage({ type: 'error', text: error.message });
        } finally {
            setUrlLoading(false);
        }
    };

    const loadGraphUrl = async event => {
        event.preventDefault();
        await loadGraphFromUrl(graphUrl.trim());
    };

    useEffect(() => {
        if (queryGraphLoadedRef.current || typeof window === 'undefined') return;
        queryGraphLoadedRef.current = true;
        const current = new URL(window.location.href);
        const supplied = current.searchParams.get('graph');
        if (!supplied) return;
        current.searchParams.delete('graph');
        window.history.replaceState(null, '', `${current.pathname}${current.search}${current.hash}`);
        setGraphUrl(supplied);
        setShowUrlLoader(true);
        void loadGraphFromUrl(supplied);
    }, []);

    const applyDeltaFile = async event => {
        const input = event.currentTarget;
        try {
            const file = input.files?.[0];
            const text = await readReviewFile(file);
            const delta = await parseSemanticGraphDelta(text);
            if (state.streamPaused) {
                throw new Error('Resume live updates before applying a delta');
            }
            const graph = await applySemanticGraphDelta(state.graph, delta);
            dispatch({ type: 'APPLY_DELTA', graph });
            setMessage({ type: 'success', text: `Applied revision ${delta.deltaDigest} from ${file.name}` });
        } catch (error) {
            setMessage({ type: 'error', text: error.message });
        } finally {
            input.value = '';
        }
    };


    return (
        <div className={styles.appShell}>
            <ReviewHeader
                decisionSet={decisionSet}
                onOpenGraph={() => graphInputRef.current?.click()}
                onOpenUrl={() => setShowUrlLoader(value => !value)}
                onOpenHubble={() => hubbleInputRef.current?.click()}
                onOpenDelta={() => deltaInputRef.current?.click()}
            />
            <input
                ref={graphInputRef}
                className={styles.hiddenInput}
                type="file"
                accept="application/json,.json"
                onChange={event => loadFile(event, parseSemanticGraphJson, 'Semantic graph')}
            />
            <input
                ref={hubbleInputRef}
                className={styles.hiddenInput}
                type="file"
                accept="application/x-ndjson,.jsonl,.ndjson,.log"
                onChange={event => loadFile(event, parseHubbleJsonLines, 'Live Hubble adapter')}
            />
            <input
                ref={deltaInputRef}
                className={styles.hiddenInput}
                type="file"
                accept="application/json,.json"
                onChange={applyDeltaFile}
            />
            {showUrlLoader ? (
                <form className={styles.urlLoader} onSubmit={loadGraphUrl}>
                    <label htmlFor="policy-review-graph-url">Review server URL</label>
                    <input
                        id="policy-review-graph-url"
                        type="url"
                        inputMode="url"
                        autoComplete="off"
                        spellCheck="false"
                        value={graphUrl}
                        placeholder="http://127.0.0.1:PORT/v1/graph/TOKEN"
                        onChange={event => setGraphUrl(event.target.value)}
                        autoFocus
                        required
                    />
                    <button type="submit" disabled={urlLoading}>
                        {urlLoading ? 'Loading…' : 'Load graph'}
                    </button>
                    <button
                        type="button"
                        disabled={urlLoading}
                        onClick={() => {
                            setGraphUrl('');
                            setShowUrlLoader(false);
                        }}
                    >
                        Cancel
                    </button>
                    <small>
                        Paste the exact URL printed by `nosh review serve`; Docker bridge origins must match launcher attestation.
                    </small>
                </form>
            ) : null}
            <div className={styles.reviewNotices}>
                {message ? (
                    <div className={styles.message} data-type={message.type} role="status">
                        <span>{message.text}</span>
                        <button type="button" onClick={() => setMessage(null)}>×</button>
                    </div>
                ) : null}
                {!state.graph.frozen ? (
                    <div className={styles.liveWarning}>
                        <strong>{state.streamPaused ? 'Live view paused.' : 'Live observations may change.'}</strong>
                        <span>
                            Pausing only stops local deltas; it does not create a Guard-verified frozen snapshot or approval input.
                        </span>
                    </div>
                ) : null}
            </div>
            <ReviewWorkflow decisionSet={decisionSet} />
            <div className={styles.viewTabs} role="group" aria-label="Review view">
                <button aria-pressed={view === 'endpoints'} onClick={() => setView('endpoints')}>Endpoints</button>
                <button aria-pressed={view === 'graph'} onClick={() => setView('graph')}>Graph and timeline</button>
            </div>
            {view === 'graph' && <PolicyReviewTimeline />}
            <main className={styles.workspace}>
                <ReviewSidebar />
                {view === 'graph' ? <PolicyReviewCanvas /> : <EndpointTable />}
                <EvidenceInspector decisionSet={decisionSet} />
            </main>
            <footer className={styles.footer}>
                <span>{state.graph.nodes.length} nodes · {state.graph.observations.length} observations · {state.graph.proposals.length} proposals</span>
                <span>{state.appliedDeltaCount} live deltas · schema v{state.graph.schemaVersion}</span>
            </footer>
        </div>
    );
}

export default function PolicyReviewPage() {
    return (
        <>
            <Head>
                <title>Nosh Guard · Policy Review</title>
                <meta
                    name="description"
                    content="Review digest-bound Nosh Guard build and runtime evidence as a semantic policy graph."
                />
            </Head>
            <PolicyReviewProvider>
                <PolicyReviewWorkspace />
            </PolicyReviewProvider>
        </>
    );
}
