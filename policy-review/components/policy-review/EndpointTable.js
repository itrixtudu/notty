import { useMemo, useState } from 'react';
import { endpointRows } from '../../modules/policy-review/savedReview';
import { usePolicyReviewStore } from '../../modules/policy-review/reviewStore';
import styles from './PolicyReview.module.css';

const PAGE_SIZE = 100;

export default function EndpointTable() {
    const { state, dispatch } = usePolicyReviewStore();
    const [query, setQuery] = useState('');
    const [remainingOnly, setRemainingOnly] = useState(false);
    const [page, setPage] = useState(0);
    const [rationale, setRationale] = useState('');
    const rows = useMemo(() => endpointRows(state.graph), [state.graph]);
    const filtered = rows.filter(row => (!remainingOnly || state.decisions[row.id]?.disposition === 'needs-review' || !state.decisions[row.id]?.rationale?.trim()) && `${row.names.join(' ')} ${row.address} ${row.protocol} ${row.ports.join(' ')} ${row.scope}`.toLowerCase().includes(query.toLowerCase()));
    const selected = new Set(state.selectedProposalIds);
    const selectedCount = rows.filter(row => selected.has(row.id)).length;
    const currentPage = Math.min(page, Math.max(0, Math.ceil(filtered.length / PAGE_SIZE) - 1));
    const decide = (ids, disposition) => dispatch({ type: 'SET_BULK_PROPOSAL_DECISION', proposalIds: ids,
        disposition, rationale: rationale.trim() || (disposition === 'accept'
            ? 'Allow this observed endpoint for the reviewed workload.' : 'Exclude this endpoint from the default-deny allow list.') });
    return <section className={styles.endpointPanel} aria-label="Network endpoints">
        <h2>Choose the endpoints this workload may reach</h2>
        <p>DNS names describe captured evidence. An IP rule permits the displayed address and port; it does not follow future DNS changes. Unreviewed endpoints are not approved.</p>
        <div className={styles.workflowActions}>
            <button aria-pressed={remainingOnly} onClick={() => { setRemainingOnly(!remainingOnly); setPage(0); }}>{remainingOnly ? 'Show all connections' : 'Show remaining'}</button>
            <input aria-label="Search endpoints" placeholder="Search DNS name, IP, port…" value={query} onChange={event => { setQuery(event.target.value); setPage(0); }} />
            <span role="status">{selectedCount} of {rows.length} endpoints selected across all pages and filters</span>
            <input aria-label="Bulk decision rationale" placeholder="Optional shared rationale" value={rationale} maxLength={4096} onChange={event => setRationale(event.target.value)} />
            <button disabled={!selectedCount} onClick={() => decide(rows.filter(row => selected.has(row.id)).map(row => row.id), 'accept')}>Allow selected</button>
            <button disabled={!selectedCount} onClick={() => decide(rows.filter(row => selected.has(row.id)).map(row => row.id), 'reject')}>Deny selected</button>
            <button onClick={() => decide(rows.filter(row => state.decisions[row.id].disposition === 'needs-review').map(row => row.id), 'reject')}>Deny remaining</button>
        </div>
        <p>Use the Select header checkbox to select all, uncheck exceptions, then Allow selected. Use Deny remaining for connections still marked Needs review. Selection alone does not change decisions.</p>
        <div className={styles.endpointTableScroll}><table className={styles.endpointTable}><thead><tr>
            <th scope="col"><label title="Select or clear all network endpoints across all pages and filters">
                <input type="checkbox" aria-label="Select all network endpoints"
                    disabled={!rows.length} checked={rows.length > 0 && selectedCount === rows.length}
                    aria-checked={selectedCount > 0 && selectedCount < rows.length ? 'mixed' : rows.length > 0 && selectedCount === rows.length}
                    ref={element => { if (element) element.indeterminate = selectedCount > 0 && selectedCount < rows.length; }}
                    onChange={event => dispatch(event.target.checked
                        ? { type: 'SELECT_ALL_NETWORK_PROPOSALS' } : { type: 'SELECT', selected: null })} />{' '}Select
            </label></th><th>Observed DNS names</th><th>IP / peer</th><th>Protocol / ports</th><th>Observations</th><th>Decision</th>
        </tr></thead><tbody>{filtered.slice(currentPage * PAGE_SIZE, (currentPage + 1) * PAGE_SIZE).map(row => <tr key={row.id}>
            <td><input type="checkbox" aria-label={`Select ${row.address}`} checked={selected.has(row.id)} onChange={() => dispatch({ type: 'SELECT_PROPOSAL', proposalId: row.id, toggle: true })} /></td>
            <td>{row.names.length ? row.names.join(', ') : 'No observed DNS mapping'}
                {row.names.length > 1 && <small>Multiple possible names</small>}
                {row.dnsEvidence.length > 0 && <details><summary>DNS evidence</summary><ul>{row.dnsEvidence.map((answer, index) => <li key={index}>
                    {answer.dnsName} → {answer.address} · resolver {answer.resolverAddress || 'not recorded'} · {answer.dnsRecordType || 'address'} · observed {answer.observedMonotonicNs || 'unknown'} ns · expires {answer.expiresMonotonicNs || 'unknown'} ns
                </li>)}</ul></details>}
            </td>
            <td><button onClick={() => dispatch({ type: 'SELECT_PROPOSAL', proposalId: row.id })}>{row.address}</button><small>{row.scope} · {row.ipBased ? 'IP based' : 'Domain rule — check target support'}</small></td>
            <td>{row.protocol} / {row.ports.join(', ') || 'any'}</td><td>{row.count || 'Recorded'}</td>
            <td><select aria-label={`Decision for ${row.address}`} value={state.decisions[row.id].disposition} onChange={event => decide([row.id], event.target.value)}>
                <option value="needs-review">Needs review</option><option value="accept">Allow</option><option value="reject">Deny</option>
            </select></td>
        </tr>)}</tbody></table></div>
        {!rows.length && <p>No network proposals in this graph. Use the proposal list to review other evidence.</p>}
        <div className={styles.workflowActions}><button disabled={currentPage === 0} onClick={() => setPage(currentPage - 1)}>Previous</button>
            <span>{filtered.length} endpoints · page {currentPage + 1} of {Math.max(1, Math.ceil(filtered.length / PAGE_SIZE))}</span>
            <button disabled={(currentPage + 1) * PAGE_SIZE >= filtered.length} onClick={() => setPage(currentPage + 1)}>Next</button></div>
    </section>;
}
