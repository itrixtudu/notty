import { useEffect, useMemo, useRef, useState } from 'react';
import { usePolicyReviewStore } from '../../modules/policy-review/reviewStore';
import { materializeDecisionSet, POLICY_REVIEW_TARGETS } from '../../modules/policy-review/semanticGraph';
import { applyReviewCommand, reviewFingerprint, reviewSnapshot, validateReviewDraft,
    validateSavedDecisionSet } from '../../modules/policy-review/savedReview';
import { createDraftAutosaver, explainReviewBlocker } from '../../modules/policy-review/draftAutosave';
import styles from './PolicyReview.module.css';

async function sessionRequest(url, document) {
    const response = await fetch(url, { method: document ? 'POST' : 'GET',
        credentials: 'same-origin', cache: 'no-store',
        ...(document ? { headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(document) } : {}) });
    const result = await response.json();
    if (!response.ok) throw new Error(result.error || 'Review could not be saved');
    return result;
}

function download(document, filename) {
    const url = URL.createObjectURL(new Blob([`${JSON.stringify(document, null, 2)}\n`], { type: 'application/json' }));
    const anchor = documentElement(filename, url);
    anchor.click();
    anchor.remove();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
}

function documentElement(filename, url) {
    const anchor = window.document.createElement('a');
    anchor.href = url;
    anchor.download = filename;
    window.document.body.appendChild(anchor);
    return anchor;
}

export default function ReviewWorkflow({ decisionSet }) {
    const { state, dispatch } = usePolicyReviewStore();
    const [session, setSession] = useState(null);
    const [saved, setSaved] = useState(null);
    const [savedFingerprint, setSavedFingerprint] = useState(null);
    const [draftFingerprint, setDraftFingerprint] = useState(null);
    const [notice, setNotice] = useState('');
    const [busy, setBusy] = useState(false);
    const [lastApplied, setLastApplied] = useState(null);
    const importInput = useRef(null);
    const writer = useRef(null);
    const generation = useRef(0);
    const [ready, setReady] = useState(false);
    const [saveError, setSaveError] = useState('');
    const [summaryOpen, setSummaryOpen] = useState(false);
    const fingerprint = reviewFingerprint(state);
    const changed = fingerprint !== savedFingerprint;
    const blockers = useMemo(() => [
        ...decisionSet.blockers.filter(blocker => !/^(decision:|reviewer:|target:|graph:)/.test(blocker)),
        ...(session?.preflight || []),
        ...(!session?.runtimeCandidate ? ['Runtime learning is required before applying a workspace policy.'] : []),
    ], [decisionSet.blockers, session]);
    const inventoryLimitations = useMemo(() => [...new Set(state.graph.nodes
        .filter(node => node.nodeType === 'evidenceSource')
        .flatMap(node => node.properties?.collection?.limitations || []))], [state.graph]);
    const command = !changed && blockers.length === 0
        ? applyReviewCommand(session, saved?.contentDigest) : '';
    const blockerMessages = [...new Set(blockers.map(blocker => explainReviewBlocker(blocker, state.graph)))];

    useEffect(() => {
        const current = ++generation.current;
        let cancelled = false;
        setReady(false); setSession(null); setSaved(null); setSavedFingerprint(null);
        setDraftFingerprint(null); setLastApplied(null); setNotice(''); setSaveError('');
        setSummaryOpen(false); setBusy(false);
        sessionRequest('/api/policy-review-session').then(async result => {
            if (cancelled) return;
            if (result.session.graphContentDigest !== state.graph.contentDigest) {
                throw new Error('Managed session belongs to a different graph; open its original review URL.');
            }
            let restored = state;
            let restoredSaved = null;
            if (result.draft) {
                const draft = validateReviewDraft(result.draft, state.graph);
                restored = { ...state, ...draft };
                if (result.decisions) {
                    await validateSavedDecisionSet(result.decisions, state.graph);
                    try {
                        const document = await materializeDecisionSet({ ...restored,
                            graph: state.graph, allowBlockedReview: true, createdAt: result.decisions.createdAt });
                        if (document.contentDigest === result.decisions.contentDigest) {
                            restoredSaved = { ...result.decisions,
                                path: `${result.session.directory}/decisions/decisions.json`,
                                savedAt: result.decisions.createdAt };
                        }
                    } catch { /* An unfinished draft is not a finalized review. */ }
                }
            }
            if (cancelled) return;
            if (result.draft) {
                dispatch({ type: 'RESTORE_REVIEW', document: result.draft });
                setDraftFingerprint(reviewFingerprint(restored));
            }
            if (restoredSaved) {
                setSaved(restoredSaved); setSavedFingerprint(reviewFingerprint(restored));
                setSummaryOpen(true);
            }
            setSession(result.session); setLastApplied(result.lastApplied);
            writer.current = createDraftAutosaver({
                save: snapshot => sessionRequest('/api/policy-review-session', snapshot),
                onSaved: snapshot => {
                    if (generation.current !== current) return;
                    setDraftFingerprint(JSON.stringify(snapshot)); setSaveError('');
                },
                onError: error => {
                    if (generation.current === current) setSaveError(error.message);
                },
            });
            setReady(true);
        }).catch(error => { if (!cancelled) setNotice(`Automatic saving unavailable: ${error.message}. Use More options to download your work.`); });
        return () => {
            cancelled = true; ++generation.current;
            writer.current?.dispose(); writer.current = null;
        };
    }, [state.graph.contentDigest]);

    useEffect(() => {
        if (ready && state.graph.frozen && fingerprint !== draftFingerprint) {
            writer.current?.schedule(reviewSnapshot(state));
        }
    }, [fingerprint, ready]);

    useEffect(() => {
        if (fingerprint === draftFingerprint) return;
        const warn = event => { event.preventDefault(); event.returnValue = ''; };
        window.addEventListener('beforeunload', warn);
        return () => window.removeEventListener('beforeunload', warn);
    }, [fingerprint, draftFingerprint]);

    const save = async () => {
        const snapshot = reviewSnapshot(state);
        const currentFingerprint = fingerprint;
        const current = generation.current;
        setBusy(true); setNotice('');
        try {
            await writer.current.flush(snapshot);
            if (current !== generation.current) return;
            const document = await materializeDecisionSet({ ...state, allowBlockedReview: true });
            if (current !== generation.current) return;
            const result = await sessionRequest('/api/policy-review-decision-set', document);
            if (current !== generation.current) return;
            setSaved({ ...document, ...result });
            setSavedFingerprint(currentFingerprint);
            setNotice('');
        } catch (error) {
            if (current === generation.current) setNotice(`Could not finalize review: ${error.message}. Your choices are retained; retry or download them.`);
        } finally { if (current === generation.current) setBusy(false); }
    };

    const retry = async () => {
        setSaveError('');
        try { await writer.current?.flush(reviewSnapshot(state)); }
        catch { /* The writer reports the failure without discarding edits. */ }
    };

    const exportJson = async () => {
        try {
            const complete = decisionSet.decisionsComplete;
            const document = complete
                ? await materializeDecisionSet({ ...state, allowBlockedReview: true })
                : reviewSnapshot(state);
            const name = (state.profileName || state.graph.graphId).replace(/[^a-zA-Z0-9._-]/g, '-').slice(0, 80);
            const filename = `${name}.${complete ? 'decisions' : 'draft'}.json`;
            download(document, filename);
            setNotice(`Downloaded ${filename} to your browser's download location. This does not apply the policy.`);
        } catch (error) { setNotice(error.message); }
    };

    const importJson = async event => {
        try {
            const file = event.target.files?.[0];
            if (!file) return;
            if (file.size > 8 * 1024 * 1024) throw new Error('Saved review exceeds 8 MiB');
            const document = JSON.parse(await file.text());
            let draft = document;
            if (document.kind === 'NoshPolicyDecisionSet') {
                await validateSavedDecisionSet(document, state.graph);
                const decisions = structuredClone(state.decisions);
                for (const entry of document.decisions) {
                    decisions[entry.proposalId] = { disposition: entry.disposition, rationale: entry.rationale,
                        targetAcknowledgements: { ...decisions[entry.proposalId].targetAcknowledgements } };
                    for (const acknowledgement of entry.targetAcknowledgements || []) {
                        decisions[entry.proposalId].targetAcknowledgements[acknowledgement.target] = {
                            ...acknowledgement, acknowledged: true,
                        };
                    }
                }
                draft = { ...reviewSnapshot(state), decisions, reviewer: document.reviewer, reviewerAcknowledged: false };
            }
            validateReviewDraft(draft, state.graph);
            dispatch({ type: 'RESTORE_REVIEW', document: draft });
            setNotice('Imported choices. Progress saves automatically; review the selections before finalizing.');
        } catch (error) { setNotice(`Import failed: ${error.message}`); }
        finally { event.target.value = ''; }
    };

    const unfinished = decisionSet.blockers.filter(blocker =>
        /^(decision:|reviewer:|target:|graph:)/.test(blocker));
    const progress = !state.graph.frozen ? 'Automatic saving unavailable for live evidence'
        : !ready ? (notice ? 'Automatic saving unavailable' : 'Loading saved progress…')
        : saveError ? 'Could not save progress'
        : fingerprint === draftFingerprint ? 'Progress saved' : 'Saving progress…';
    const counts = decisionSet.decisions.reduce((result, entry) => {
        result[entry.disposition] = (result[entry.disposition] || 0) + 1;
        return result;
    }, {});
    const reveal = blocker => {
        if (blocker.startsWith('reviewer:')) {
            document.getElementById(blocker.endsWith('identity-required') ? 'reviewer-name' : 'reviewer-confirm')?.focus();
        } else if (blocker.startsWith('decision:') || blocker.startsWith('target:')) {
            const proposal = state.graph.proposals.find(entry => blocker === `decision:${entry.id}`
                || blocker.startsWith(`target:${entry.id}:`));
            if (proposal) dispatch({ type: 'SELECT_PROPOSAL', proposalId: proposal.id });
            const destination = document.getElementById(proposal ? 'review-inspector' : 'review-target');
            destination?.scrollIntoView({ behavior: 'smooth' });
            destination?.focus();
        }
    };

    return <section id="save-review" className={styles.workflow} aria-label="Network policy review progress">
        <div className={styles.workflowIdentity}>
            <strong>1. Choose connections → 2. Review and save → 3. Apply on host</strong>
            <span>{state.graph.scope.class === 'runtime' ? 'Runtime policy · exact IP/port selection' : 'Build traffic · runtime learning required for workspace enforcement'}</span>
            {session && <span>Workspace: {session.workdir} · Image: {session.imageDigest || 'build evidence'}</span>}
        </div>
        {inventoryLimitations.length > 0 && <details>
            <summary>What the software inventory covers</summary>
            <p>These inventories describe package metadata. This network policy does not approve executable files.</p>
            <ul>{inventoryLimitations.map(message => <li key={message}>{message}</li>)}</ul>
        </details>}
        {session?.runtimeCandidate && <p>Rules allow exact IP and port connections. DNS names are supporting evidence; hostname resolution is not automatically allowed.</p>}
        <div className={styles.workflowActions}>
            <span>{counts.accept || 0} allowed · {counts.reject || 0} denied · {counts['needs-review'] || 0} need review</span>
            <strong role="status" aria-live="polite">{progress}</strong>
            {saveError && <button onClick={retry}>Retry saving</button>}
            {!summaryOpen && <button className={saved && !changed ? undefined : styles.exportButton} onClick={() => setSummaryOpen(true)}>Review selections</button>}
            {summaryOpen && <button onClick={() => setSummaryOpen(false)}>Back to connections</button>}
        </div>
        {saveError && <p role="alert">{saveError}. Your edits remain here. Retry or download a copy under More options before leaving.</p>}
        {summaryOpen && <div className={styles.reviewSummary}>
            <h2>Review your network policy</h2>
            <p>Only allowed connections are included in the allowlist. Verify your choices and the evidence before saving this review.</p>
            <div className={styles.workflowActions}>
                <label>Profile name <input aria-label="Profile name" value={state.profileName} maxLength={128}
                    placeholder={session?.profileName || 'Workspace network policy'}
                    onChange={event => dispatch({ type: 'SET_PROFILE_NAME', value: event.target.value })} /></label>
                <label>Enforcement target <select id="review-target" value={state.intendedTarget}
                    onChange={event => dispatch({ type: 'SET_INTENDED_TARGET', intendedTarget: event.target.value })}>
                    {POLICY_REVIEW_TARGETS.map(target => <option key={target} value={target}>{target}</option>)}
                </select></label>
                <label>Reviewer <input id="reviewer-name" aria-label="Reviewer" value={state.reviewer} maxLength={256}
                    onChange={event => dispatch({ type: 'SET_REVIEWER', reviewer: event.target.value })} /></label>
                <label><input id="reviewer-confirm" type="checkbox" checked={state.reviewerAcknowledged}
                    onChange={event => dispatch({ type: 'SET_ACKNOWLEDGED', acknowledged: event.target.checked })} /> I reviewed the connections, evidence, and decisions</label>
            </div>
            {unfinished.length > 0 && <div id="review-incomplete"><strong>Before you can save this review:</strong>
                <ul>{unfinished.map(blocker => <li key={blocker}>
                    {explainReviewBlocker(blocker, state.graph)}{' '}
                    {!blocker.startsWith('graph:') && <button onClick={() => reveal(blocker)}>Go to requirement</button>}
                </li>)}</ul></div>}
            {(!saved || changed) && <button className={styles.exportButton}
                aria-describedby={unfinished.length ? 'review-incomplete' : undefined}
                disabled={busy || !ready || !decisionSet.decisionsComplete} onClick={save}>
                {busy ? 'Saving reviewed policy…' : 'Save reviewed policy'}
            </button>}
            {saved && !changed && <strong role="status">{blockers.length ? 'Saved — application blocked' : 'Policy saved. Apply it on the host next.'}</strong>}
            {saved && changed && <p>Choices changed after the last finalized review. Save reviewed policy again to get an updated apply command.</p>}
        </div>}
        {notice && <p role="status">{notice}</p>}
        {(summaryOpen || Boolean(saved)) && <section className={styles.applyDetails} aria-label="Apply on host">
            <h3>{blockers.length ? 'Before application' : 'Apply on host'}</h3>
            <p>Saving records your review. The host checks prerequisites, signs approval, and activates policy for future guarded runs.</p>
            {blockers.length > 0 && <ul>{blockerMessages.map(message => <li key={message}>{message}</li>)}</ul>}
            {command && <><p>{blockers.length ? 'Resolve the prerequisites above before running this command. The host will validate them again.' : 'Run this exact command on the host:'}</p>
                <pre>{command}</pre><button className={styles.exportButton} onClick={async () => {
                    try { await navigator.clipboard.writeText(command); setNotice('Apply command copied. Run it in your host terminal.'); }
                    catch { setNotice('Clipboard unavailable. Select and copy the command shown above.'); }
                }}>Copy apply command</button></>}
            {!command && <p>{blockers.length
                ? 'Application is blocked. Your review is retained; resolve the requirements above and reopen review before applying.'
                : 'Finish and save your runtime review to get its apply command.'}</p>}
            {lastApplied && <p>Historical application receipt: {lastApplied.activatedAt}. Run <code>nosh net status</code> on the host to check current enforcement.</p>}
        </section>}
        <details><summary>More options</summary><div className={styles.workflowActions}>
            <button disabled={!state.graph.frozen} onClick={exportJson}>Download JSON</button>
            <button onClick={() => importInput.current.click()}>Import saved JSON</button>
            <input ref={importInput} className={styles.hiddenInput} type="file" accept="application/json,.json" onChange={importJson} />
            <span>Downloading a copy does not apply a policy. Imported choices are saved as draft progress; review them before finalizing.</span>
        </div></details>
        <details><summary>Technical details</summary>
            {session && <p className={styles.savedPath}>Host files: <code>{session.directory}/decisions/draft.json</code> · <code>{session.directory}/decisions/decisions.json</code> · Revision: {session.revision}</p>}
            {saved && <p>Last finalized review: {saved.savedAt} · {saved.path}</p>}
            <ul>{[...new Set([...decisionSet.blockers, ...blockers])].map(blocker => <li key={blocker}><code>{blocker}</code></li>)}</ul>
        </details>
    </section>;
}
