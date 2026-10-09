import { LIMITATIONS } from '../../modules/tool-review/environment';
import { Fragment, useEffect, useMemo, useRef, useState } from 'react';
import { createDraftAutosaver } from '../../modules/policy-review/draftAutosave';
import { CHOICES, MAX_DOCUMENT_BYTES, emptyDraft, validateDocument, importDraft, fingerprint,
    filteredGroups, decideGroups } from '../../modules/tool-review/model';
import shared from '../policy-review/PolicyReview.module.css';
import styles from './ToolReview.module.css';
import CommandRuleReview, { RequestBrowser } from './RequestReview';

const PAGE_SIZE = 50;
const number = value => value.toLocaleString();

function download(value, filename) {
    const url = URL.createObjectURL(new Blob([`${JSON.stringify(value, null, 2)}\n`], { type: 'application/json' }));
    const anchor = document.createElement('a');
    anchor.href = url; anchor.download = filename;
    document.body.appendChild(anchor); anchor.click(); anchor.remove();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
}

async function request(token, document) {
    const response = await fetch('/api/tool-review', { method: document ? 'POST' : 'GET', cache: 'no-store',
        credentials: 'same-origin', headers: { Authorization: `Bearer ${token}`, ...(document ? { 'Content-Type': 'application/json' } : {}) },
        ...(document ? { body: JSON.stringify(document) } : {}) });
    const result = await response.json();
    if (!response.ok) throw new Error(result.error || 'Review request failed.');
    return result;
}

export default function ToolReviewPage() {
    const [workspace, setWorkspace] = useState('');
    const [allowImplementation, setAllowImplementation] = useState(false);
    const [environmentAcknowledged, setEnvironmentAcknowledged] = useState(false);
    const [policyDigest, setPolicyDigest] = useState('');
    const [snapshot, setSnapshot] = useState(null);
    const [commandPolicy, setCommandPolicy] = useState(null);
    const [expandedGroups, setExpandedGroups] = useState(new Set());
    const [draft, setDraft] = useState(null);
    const [savedFingerprint, setSavedFingerprint] = useState('');
    const [proposal, setProposal] = useState(null);
    const [error, setError] = useState('');
    const [saveError, setSaveError] = useState('');
    const [notice, setNotice] = useState('');
    const [busy, setBusy] = useState(false);
    const [summary, setSummary] = useState(false);
    const [query, setQuery] = useState('');
    const [tool, setTool] = useState('');
    const [choice, setChoice] = useState('');
    const [remaining, setRemaining] = useState(false);
    const [selected, setSelected] = useState(new Set());
    const [bulkChoice, setBulkChoice] = useState('expected');
    const [bulkNote, setBulkNote] = useState('');
    const [page, setPage] = useState(0);
    const writer = useRef(null);
    const token = useRef('');
    const importInput = useRef(null);

    useEffect(() => {
        let cancelled = false;
        const fragment = new URLSearchParams(window.location.hash.slice(1));
        const incoming = fragment.get('token');
        try {
            if (incoming) {
                sessionStorage.setItem('nosh-tool-review-token', incoming);
                window.history.replaceState(null, '', window.location.pathname);
            }
            token.current = incoming || sessionStorage.getItem('nosh-tool-review-token') || '';
        } catch { token.current = incoming || ''; }
        request(token.current).then(result => {
            if (cancelled) return;
            const restored = result.draft ? validateDocument(result.draft, result.snapshot)
                : result.proposal ? importDraft(result.proposal, result.snapshot) : emptyDraft(result.snapshot);
            setSnapshot(result.snapshot); setDraft(restored); setSavedFingerprint(fingerprint(restored));
            setProposal(result.proposal); setError('');
            setCommandPolicy(result.commandPolicy || null);
            writer.current = createDraftAutosaver({
                save: document => request(token.current, document),
                onSaved: document => { if (!cancelled) { setSavedFingerprint(fingerprint(document)); setSaveError(''); } },
                onError: failure => { if (!cancelled) setSaveError(failure.message); },
            });
        }).catch(failure => { if (!cancelled) setError(failure.message); });
        return () => { cancelled = true; writer.current?.dispose(); writer.current = null; };
    }, []);

    const currentFingerprint = draft ? fingerprint(draft) : '';
    useEffect(() => {
        if (draft && currentFingerprint !== savedFingerprint) writer.current?.schedule(draft);
    }, [draft, currentFingerprint, savedFingerprint]);
    useEffect(() => { setPage(0); }, [query, tool, choice, remaining]);
    useEffect(() => {
        const warn = event => {
            if (currentFingerprint !== savedFingerprint) { event.preventDefault(); event.returnValue = ''; }
        };
        window.addEventListener('beforeunload', warn);
        return () => window.removeEventListener('beforeunload', warn);
    }, [currentFingerprint, savedFingerprint]);

    const groups = snapshot?.groups || [];
    const tools = useMemo(() => [...new Set(groups.map(group => group.tool))], [snapshot]);
    const filtered = useMemo(() => draft ? filteredGroups(groups, draft, { query, tool, choice, remaining }) : [],
        [snapshot, draft, query, tool, choice, remaining]);
    const counts = useMemo(() => {
        const result = Object.fromEntries(Object.keys(CHOICES).map(key => [key, { groups: 0, requests: 0 }]));
        for (const group of groups) {
            const count = result[draft.decisions[group.id].choice];
            count.groups++; count.requests += group.count;
        }
        return result;
    }, [snapshot, draft]);
    const selectedGroups = groups.filter(group => selected.has(group.id));
    const selectedRequests = selectedGroups.reduce((sum, group) => sum + group.count, 0);
    const selectedFiltered = filtered.filter(group => selected.has(group.id)).length;
    const pageCount = Math.max(1, Math.ceil(filtered.length / PAGE_SIZE));
    const currentPage = Math.min(page, pageCount - 1);
    const visible = filtered.slice(currentPage * PAGE_SIZE, (currentPage + 1) * PAGE_SIZE);
    const finalized = proposal && draft && fingerprint(proposal) === currentFingerprint;

    const decide = (ids, value, note) => {
        setDraft(current => decideGroups(current, ids, value, note));
        setNotice('');
    };
    const retry = async () => {
        setBusy(true);
        try { await writer.current.flush(draft); } catch (failure) { setSaveError(failure.message); }
        finally { setBusy(false); }
    };
    const finalize = async () => {
        setBusy(true); setNotice('');
        try {
            const document = validateDocument({ ...draft, kind: 'NoshToolReviewProposal', completedAt: new Date().toISOString() }, snapshot, true);
            await writer.current.flush(draft);
            await request(token.current, document);
            setProposal(document); setNotice('Reviewed activity proposal saved. Runtime capabilities are unchanged.');
        } catch (failure) { setSaveError(failure.message); }
        finally { setBusy(false); }
    };
    const saveEnvironment = async () => {
        setBusy(true); setSaveError(''); setPolicyDigest('');
        try {
            const evidence = await request(token.current, { kind: 'NoshEnvironmentDigestRequest' });
            const result = await request(token.current, { kind: 'NoshEnvironmentPolicy', schemaVersion: 1,
                snapshotDigest: snapshot.digest, proposalDigest: evidence.proposalDigest, workspace, workload: 'dev',
                allowImplementation, defaultMode: 'read-only', policyReadOnly: true, toolSelectionsInformational: true,
                limitations: LIMITATIONS, reviewer: draft.reviewer, acknowledged: environmentAcknowledged,
                approvedAt: new Date().toISOString() });
            setPolicyDigest(result.policyDigest);
            setNotice('Environment policy saved for host review and apply. Existing containers are unchanged.');
        } catch (failure) { setSaveError(failure.message); }
        finally { setBusy(false); }
    };
    const importFile = async event => {
        const file = event.target.files?.[0]; event.target.value = '';
        if (!file) return;
        setBusy(true);
        try {
            if (file.size > MAX_DOCUMENT_BYTES) throw new Error('Import exceeds the 8 MiB limit.');
            const imported = importDraft(JSON.parse(await file.text()), snapshot);
            setDraft({ ...imported, acknowledged: false });
            setSelected(new Set()); setNotice('Imported selections. Review and acknowledge before saving a proposal.');
        } catch (failure) { setNotice(`Import failed: ${failure.message}`); }
        finally { setBusy(false); }
    };

    return <main className={`${shared.appShell} ${styles.shell}`}>
        <header className={`${shared.header} ${styles.toolbar}`}>
            <div className={shared.brand}><a href="/tool-review" aria-label="Tool activity review home">N</a><div><p>Nosh policy review</p><h1>Tool activity review</h1></div></div>
            <div className={shared.graphIdentity}><div><strong>Classify recorded tool activity</strong><small>Review and export · capabilities are enforced elsewhere</small></div></div>
            <span className={styles.badge}>Informational</span>
        </header>
        <div className={styles.content}>
            {!snapshot ? <section className={shared.workflow}><h2>{error ? 'Review unavailable' : 'Loading audit…'}</h2>
                {error && <><p role="alert" className={styles.error}>{error}</p><p>Reopen using the URL printed by the audit launcher.</p></>}
            </section> : <>
                <section className={`${shared.workflow} ${styles.panel}`} aria-label="History scope">
                    <h2>History scope</h2>
                    <p>{snapshot.historyScope ? `${{ repo: 'This Git checkout', directory: 'Directory and subdirectories', all: 'All recorded history' }[snapshot.historyScope.kind]}${snapshot.historyScope.root ? `: ${snapshot.historyScope.root}` : ''}` : 'Legacy audit: all recorded history'} · All recorded dates</p>
                    <p>Scope follows recorded working directories, not every file a command touched.</p>
                    {snapshot.historyScope && <p>{number(snapshot.historyScope.excluded_requests)} requests outside scope; {number(snapshot.historyScope.unattributed_requests)} requests without a usable working directory ({snapshot.historyScope.kind === 'all' ? 'included' : 'excluded'}).</p>}
                    {snapshot.groups.length === 0 && <p>No matching tool requests were found. Choose another scope with nosh tools init.</p>}
                </section>
                <div className={styles.stats} aria-label="Review progress">
                    <div className={styles.stat}><strong>{number(groups.length)}</strong><span>Command forms</span></div>
                    <div className={styles.stat}><strong>{number(snapshot.totals.uniqueRequests)}</strong><span>Recorded requests</span></div>
                    <div className={styles.stat}><strong>{number(counts.unreviewed.groups)}</strong><span>Forms unreviewed</span></div>
                    <div className={styles.stat}><strong>{snapshot.rules.filter(rule => rule.needs_review).length}</strong><span>Existing escape allows</span></div>
                </div>
                <section className={`${shared.workflow} ${styles.panel}`} aria-label="Save review">
                    <div role="status" aria-live="polite">{saveError ? <span className={styles.error}>Save failed: {saveError}</span>
                        : currentFingerprint !== savedFingerprint ? 'Saving progress…' : 'Progress saved'}
                        {saveError && <button disabled={busy} onClick={retry}>Retry save</button>}</div>
                    {!snapshot.complete && <p role="alert" className={styles.error}>This audit snapshot is incomplete. You can save a draft, but must resolve audit input issues and run a fresh audit before finalizing.</p>}
                    <p>Mark each recorded form as expected or worth investigating. These labels support review and correlation; they never authorize or block a command.</p>
                    <fieldset disabled={busy} className={styles.controls}>
                        <div className={shared.workflowActions}><button onClick={() => setSummary(!summary)} aria-expanded={summary}>Review selections</button>
                            <span>{finalized ? 'Reviewed proposal saved' : proposal ? 'Selections changed — save a new proposal' : 'Draft review'}</span></div>
                        {summary && <section className={shared.reviewSummary} aria-label="Review selections">
                            <h2>Review activity classifications</h2>
                            <div className={shared.endpointTableScroll}><table className={shared.endpointTable}><thead><tr><th>Classification</th><th>Forms</th><th>Requests</th></tr></thead><tbody>
                                {Object.entries(CHOICES).map(([key, label]) => <tr key={key}><td>{label}</td><td>{number(counts[key].groups)}</td><td>{number(counts[key].requests)}</td></tr>)}
                            </tbody></table></div>
                            <label className={shared.reviewerField}>Reviewer name <input value={draft.reviewer} maxLength={200} onChange={event => setDraft({ ...draft, reviewer: event.target.value, acknowledged: false })} /></label>
                            <label><input type="checkbox" checked={draft.acknowledged} onChange={event => setDraft({ ...draft, acknowledged: event.target.checked })} />I reviewed these classifications and understand they do not grant capabilities.</label>
                            <div className={shared.workflowActions}><button disabled={!snapshot.complete || counts.unreviewed.groups > 0 || !draft.reviewer.trim() || !draft.acknowledged}
                                onClick={finalize}>Save reviewed proposal</button></div>
                            {counts.unreviewed.groups > 0 && <p>Classify {number(counts.unreviewed.groups)} remaining forms before saving a reviewed proposal.</p>}
                        </section>}
                        <details><summary>More options</summary><div className={shared.workflowActions}>
                            <button onClick={() => download(draft, 'tool-review-draft.json')}>Download draft JSON</button>
                            <button disabled={!finalized} onClick={() => download(proposal, 'tool-review-proposal.json')}>Download reviewed proposal</button>
                            <button onClick={() => importInput.current.click()}>Import saved JSON</button>
                            <input ref={importInput} type="file" accept="application/json,.json" hidden onChange={importFile} />
                        </div></details>
                    </fieldset>
                    {notice && <p role="status">{notice}</p>}
                </section>
                <section className={`${shared.workflow} ${styles.panel}`} aria-label="Environment policy">
                    <h2>Enforced capabilities</h2>
                    <p>Enforced: read-only root filesystem, policy and mounted agent settings; workspace read-only by default. Scratch and isolated agent state remain writable. Implementation mode allows workspace writes by any process.</p>
                    <p>Observed activity classifications are informational. Individual tool allow/deny rules and universal executable blocking are not claimed. Network access keeps its separate Nosh network policy; remote writes are not blocked by filesystem permissions.</p>
                    {commandPolicy?.rules.length > 0 && <p className={styles.error}>Command rules are saved as drafts. Environment-only approval cannot activate them; strict runner enforcement is not available.</p>}
                    <fieldset disabled={busy || !finalized || commandPolicy?.rules.length > 0} className={styles.controls}>
                        <label>Host workspace (absolute canonical path) <input aria-label="Policy workspace" value={workspace} onChange={event => { setWorkspace(event.target.value); setEnvironmentAcknowledged(false); setPolicyDigest(''); }} /></label>
                        <label><input type="checkbox" checked={allowImplementation} onChange={event => { setAllowImplementation(event.target.checked); setEnvironmentAcknowledged(false); setPolicyDigest(''); }} />Allow implementation mode to write the workspace</label>
                        <label><input type="checkbox" checked={environmentAcknowledged} onChange={event => setEnvironmentAcknowledged(event.target.checked)} />I approve these environment permissions and understand all the limitations above.</label>
                        <button disabled={!workspace || !environmentAcknowledged} onClick={saveEnvironment}>Save environment policy</button>
                    </fieldset>
                    {!finalized && <p>Save the reviewed tool proposal first.</p>}
                    {policyDigest && <p>Saved digest: <code>{policyDigest}</code>. On the host, run <code>nosh tools check --review REPORT --workdir WORKSPACE</code>, then <code>nosh tools apply --review REPORT --workdir WORKSPACE --policy-digest {policyDigest}</code>. Apply affects future containers; explicitly recreate an existing container to adopt it.</p>}
                </section>
                <section className={`${shared.endpointPanel} ${styles.panel}`} aria-label="Command forms">
                    <h2>Observed activity</h2>
                    <p><strong>Expected</strong> means the recorded form is familiar for this workspace. <strong>Investigate</strong> flags it for follow-up. <strong>Unreviewed</strong> leaves it unresolved. None of these choices changes runtime access.</p>
                    <fieldset disabled={busy} className={styles.controls}>
                        <div className={shared.workflowActions}>
                            <input aria-label="Search command forms" placeholder="Search tool, command, or reason…" value={query} onChange={event => setQuery(event.target.value)} />
                            <select aria-label="Filter by tool" value={tool} onChange={event => setTool(event.target.value)}><option value="">All tools</option>{tools.map(name => <option key={name}>{name}</option>)}</select>
                            <select aria-label="Filter by activity classification" value={choice} onChange={event => setChoice(event.target.value)}><option value="">All choices</option>{Object.entries(CHOICES).map(([key, label]) => <option key={key} value={key}>{label}</option>)}</select>
                            <button aria-pressed={remaining} onClick={() => setRemaining(!remaining)}>{remaining ? 'Show all forms' : 'Show remaining'}</button>
                        </div>
                        <div className={shared.workflowActions}>
                            <span role="status">{number(selectedGroups.length)} forms / {number(selectedRequests)} requests selected across all filters</span>
                            <select aria-label="Bulk activity classification" value={bulkChoice} onChange={event => setBulkChoice(event.target.value)}>{Object.entries(CHOICES).map(([key, label]) => <option key={key} value={key}>{label}</option>)}</select>
                            <input aria-label="Shared decision note" placeholder="Optional shared note" value={bulkNote} maxLength={4096} onChange={event => setBulkNote(event.target.value)} />
                            <button disabled={!selected.size} onClick={() => { decide([...selected], bulkChoice, bulkNote); setSelected(new Set()); }}>Apply choice to selected</button>
                            <button disabled={!selected.size} onClick={() => setSelected(new Set())}>Clear selection</button>
                        </div>
                        <div className={shared.endpointTableScroll}><table className={shared.endpointTable}><thead><tr>
                            <th><label><input type="checkbox" aria-label="Select all filtered forms across pages" disabled={!filtered.length}
                                checked={filtered.length > 0 && selectedFiltered === filtered.length}
                                ref={element => { if (element) element.indeterminate = selectedFiltered > 0 && selectedFiltered < filtered.length; }}
                                onChange={event => { const next = new Set(selected); filtered.forEach(group => event.target.checked ? next.add(group.id) : next.delete(group.id)); setSelected(next); }} /> Select all filtered</label></th>
                            <th>Command / tool form</th><th>Requests</th><th>Evidence</th><th>Classification</th>
                        </tr></thead><tbody>{visible.map((group, index) => <Fragment key={group.id}>
                            {(index === 0 || visible[index - 1].tool !== group.tool) && <tr className={styles.toolName}><th colSpan={5} scope="rowgroup">{group.tool}</th></tr>}
                            <tr><td><input type="checkbox" aria-label={`Select ${group.form} (${group.reason})`} checked={selected.has(group.id)} onChange={() => { const next = new Set(selected); next.has(group.id) ? next.delete(group.id) : next.add(group.id); setSelected(next); }} /></td>
                                <td><code>{group.form}</code><small>{group.reason}</small></td><td>{number(group.count)}</td>
                                <td>{group.category === 'allow' ? <span className={styles.success}>Expected candidate</span> : 'Investigate candidate'}
                                    <details className={styles.evidence}><summary>Evidence and note</summary>
                                        <p>{group.category === 'allow' ? 'Scanner-reviewed inspection candidate inside a sandbox.' : 'This group may include writes, network effects, or opaque payloads. Review its source references before classifying.'}</p>
                                        {(group.tool === 'exec' || group.tool === 'exec_command') && <p className={styles.toolDifference}><strong>Tool distinction:</strong> <code>exec</code> is the orchestration tool used by this interface; it runs JavaScript that can call other tools. <code>exec_command</code> is the underlying command runner; it executes the supplied shell command in the working directory.</p>}
                                        <p>Counts describe recorded requests, not successful executions.</p>
                                        {group.examples.map(example => <p key={`${example.source}:${example.line}`}><code>{example.source}:{example.line}</code></p>)}
                                        <input className={styles.note} aria-label={`Note for ${group.form}`} placeholder="Optional review note" maxLength={4096} value={draft.decisions[group.id].note}
                                            onChange={event => decide([group.id], draft.decisions[group.id].choice, event.target.value)} />
                                    </details>
                                </td><td><select aria-label={`Activity classification for ${group.form} (${group.reason})`} value={draft.decisions[group.id].choice} onChange={event => decide([group.id], event.target.value)}>
                                    {Object.entries(CHOICES).map(([key, label]) => <option key={key} value={key}>{label}</option>)}
                                </select></td></tr>
                            <tr><td colSpan={5}><button aria-expanded={expandedGroups.has(group.id)} onClick={() => setExpandedGroups(current => {
                                const next = new Set(current); next.has(group.id) ? next.delete(group.id) : next.add(group.id); return next;
                            })}>{expandedGroups.has(group.id) ? 'Hide unique requests' : 'View unique requests'}</button>
                                {expandedGroups.has(group.id) && <RequestBrowser token={token.current} snapshot={snapshot} group={group.id} />}
                            </td></tr>
                        </Fragment>)}</tbody></table></div>
                        {!filtered.length && <p>No forms match these filters.</p>}
                        <div className={shared.workflowActions}><button disabled={currentPage === 0} onClick={() => setPage(currentPage - 1)}>Previous</button>
                            <span>{number(filtered.length)} forms · page {currentPage + 1} of {pageCount}</span>
                            <button disabled={currentPage + 1 >= pageCount} onClick={() => setPage(currentPage + 1)}>Next</button></div>
                    </fieldset>
                </section>
                <CommandRuleReview token={token.current} snapshot={snapshot} initial={commandPolicy} onSaved={setCommandPolicy} />
                <section className={`${shared.workflow} ${styles.panel}`}>
                    <details><summary>Existing escape rules ({snapshot.rules.length})</summary>
                        <p>Review original rules at these source and line references. Decide whether to keep, narrow, remove, prompt, or forbid each rule outside this UI. Existing allows can bypass the sandbox; a saved proposal does not change them.</p>
                        <div className={shared.endpointTableScroll}><table className={shared.endpointTable}><thead><tr><th>Source</th><th>Executable</th><th>Prefix tokens</th><th>Existing decision</th></tr></thead><tbody>
                            {snapshot.rules.map((rule, index) => <tr key={index}><td>{rule.source}:{rule.line}</td><td>{rule.executable}</td><td>{rule.prefix_tokens}</td><td>{rule.decision}{rule.needs_review ? ' — review required' : ''}</td></tr>)}
                        </tbody></table></div>
                    </details>
                    <details><summary>Profile comparison and technical details</summary>
                        <p>Snapshot: <code>{snapshot.digest}</code></p>
                        <h3>Read-only profile</h3><pre>{snapshot.profiles.planning}</pre>
                        <h3>Implementation profile</h3><pre>{snapshot.profiles.implementation}</pre>
                        <p>Shell sandbox profiles apply to the environment, not individual command forms. MCP and remote effects need separate enforcement. Activity labels and command-rule drafts do not generate executable allow rules.</p>
                        <p>Drafts and proposals are stored in the audit report’s review directory. Downloading or saving does not install either profile.</p>
                    </details>
                </section>
            </>}
        </div>
    </main>;
}
