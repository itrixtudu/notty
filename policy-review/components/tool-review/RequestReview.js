import { useEffect, useState } from 'react';
import { COMMANDS, ENFORCEMENT, emptyRules, validateRules } from '../../modules/command-policy/model.js';
import shared from '../policy-review/PolicyReview.module.css';
import styles from './ToolReview.module.css';

function formatRequest(value) {
  if (typeof value !== 'string') return String(value ?? '');
  try {
    return JSON.stringify(JSON.parse(value), null, 2);
  } catch {
    return value;
  }
}

async function api(token, query, document, signal) {
  const response = await fetch('/api/tool-review' + (query ? '?' + new URLSearchParams(query) : ''), {
    method: document ? 'POST' : 'GET', cache: 'no-store', signal,
    headers: { Authorization: `Bearer ${token}`, ...(document ? { 'Content-Type': 'application/json' } : {}) },
    ...(document ? { body: JSON.stringify(document) } : {}),
  });
  const result = await response.json();
  if (!response.ok) throw new Error(result.error || 'Request failed');
  return result;
}

function RequestInput({ token, id }) {
  const [result, setResult] = useState(null);
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);
  const load = async () => {
    setBusy(true); setError('');
    try {
      const next = await api(token, { view: 'requests', id, offset: result?.nextOffset || 0 });
      setResult(old => ({ ...next, input: (old?.input || '') + next.input }));
    } catch (failure) { setError(failure.message); }
    finally { setBusy(false); }
  };
  return <div>
    {result && <><pre className={styles.requestCode}>{result.nextOffset === null ? formatRequest(result.input) : result.input}</pre>
      <small>{result.nextOffset === null ? 'Complete original input' : 'Partial input; load more to continue'}</small></>}
    {(!result || result.nextOffset !== null) && <button disabled={busy} onClick={load}>
      {busy ? 'Loading…' : result ? 'Load next input chunk' : 'Show complete original input'}</button>}
    {error && <p role="alert">{error}</p>}
  </div>;
}

export function RequestBrowser({ token, snapshot, group = '', rules = [] }) {
  const [query, setQuery] = useState('');
  const [command, setCommand] = useState('');
  const [flag, setFlag] = useState('');
  const [input, setInput] = useState('');
  const [rule, setRule] = useState('');
  const [page, setPage] = useState(0);
  const [result, setResult] = useState(null);
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);
  useEffect(() => { setPage(0); }, [query, command, flag, input, rule, group]);
  useEffect(() => {
    if (!snapshot.requestEvidence) return;
    const controller = new AbortController();
    const timer = setTimeout(() => {
      setBusy(true); setError('');
      api(token, { view: 'requests', group, q: query, command, switch: flag, input, rule, page }, null, controller.signal)
        .then(setResult).catch(failure => { if (!controller.signal.aborted) setError(failure.message); })
        .finally(() => { if (!controller.signal.aborted) setBusy(false); });
    }, 250);
    return () => { clearTimeout(timer); controller.abort(); };
  }, [token, snapshot.digest, group, query, command, flag, input, rule, page]);
  if (!snapshot.requestEvidence) return <p>Request details were not captured. Run <code>nosh tools init</code> for a fresh scoped audit.</p>;
  return <div className={styles.requestBrowser}>
    <div className={shared.workflowActions}>
      <input aria-label="Search original requests" placeholder="Search input or working directory…" value={query} onChange={e => setQuery(e.target.value)} />
      <input aria-label="Filter executable" placeholder="Command, e.g. sed" value={command} onChange={e => setCommand(e.target.value)} />
      <input aria-label="Filter switch" placeholder="Switch, e.g. --* or -n" value={flag} onChange={e => setFlag(e.target.value)} />
      <select aria-label="Filter input source" value={input} onChange={e => setInput(e.target.value)}>
        <option value="">All input sources</option><option value="stdin">Stdin / pipeline</option><option value="files">File operands</option>
      </select>
      {rules.length > 0 && <select aria-label="Preview saved command rule" value={rule} onChange={e => setRule(e.target.value)}>
        <option value="">All rule matches</option>{rules.map(item => <option key={item.id} value={item.id}>{item.command}: {item.anySwitches ? 'Any switches' : item.allowedSwitches.join(' ') || 'No optional switches'}</option>)}
      </select>}
    </div>
    <p>Filters inspect literal command candidates. Dynamic code stays unresolved; inputs are never executed. Original inputs may contain secrets.</p>
    {busy && <p role="status">Searching unique requests…</p>}
    {error && <p role="alert" className={styles.error}>{error}</p>}
    {result && <><p role="status">{result.total.toLocaleString()} unique requests · {result.occurrences.toLocaleString()} recorded calls</p>
      {result.entries.map(entry => <details key={entry.id} className={styles.requestEntry}>
        <summary><strong>{entry.analysis.commands.map(item => item.command).join(' | ') || entry.tool}</strong>
          {' · '}{entry.occurrences.toLocaleString()} calls</summary>
        <p>Tool: <code>{entry.tool}</code> · Working directory: <code>{entry.cwd || 'Unknown'}</code></p>
        <p>First source: <code>{entry.source}:{entry.line}</code></p>
        <pre className={styles.requestCode}>{formatRequest(entry.preview)}</pre>
        {entry.analysis.unresolved && <p>Some or all command details require manual review.</p>}
        {entry.analysis.commands.map((item, index) => <div key={index}>
          <p>Extracted command argv preview (long arguments are capped here; use the complete original input below):</p>
          <pre className={styles.requestCode}>{JSON.stringify(item.argv || [], null, 2)}</pre>
          <p>{item.nested ? 'Literal candidate in orchestration code. ' : ''}
            {item.supported ? `Switches: ${item.switches.join(' ') || '(none)'}. Input: ${item.input}.` : item.reason}</p>
        </div>)}
        <RequestInput token={token} id={entry.id} />
      </details>)}
      <div className={shared.workflowActions}>
        <button disabled={busy || page === 0} onClick={() => setPage(page - 1)}>Previous requests</button>
        <span>Page {page + 1} of {Math.max(1, Math.ceil(result.total / result.pageSize))}</span>
        <button disabled={busy || (page + 1) * result.pageSize >= result.total} onClick={() => setPage(page + 1)}>Next requests</button>
      </div></>}
  </div>;
}

const split = value => value.trim() ? value.trim().split(/\s+/) : [];
const newRule = () => ({ id: crypto.randomUUID(), command: 'sed', mode: 'read-only', anySwitches: false,
  allowedSwitches: ['-n', '-E', '-e'], requiredSwitches: ['--sandbox'], optionValues: {} });

export default function CommandRuleReview({ token, snapshot, initial, onSaved }) {
  const [document, setDocument] = useState(initial || emptyRules(snapshot.digest));
  const [saved, setSaved] = useState(initial || emptyRules(snapshot.digest));
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);
  const [notice, setNotice] = useState('');
  const [invalidValues, setInvalidValues] = useState({});
  const update = (index, values) => setDocument(current => ({ ...current,
    rules: current.rules.map((rule, position) => position === index ? { ...rule, ...values } : rule) }));
  const save = async () => {
    if (Object.values(invalidValues).some(Boolean)) {
      setError('Correct option value patterns before saving.');
      return;
    }
    setBusy(true); setError(''); setNotice('');
    try {
      const clean = validateRules(document, snapshot.digest);
      await api(token, null, clean);
      setDocument(clean); setSaved(clean); onSaved(clean);
      setNotice('Command-rule draft saved. Enforcement is not active.');
    } catch (failure) { setError(failure.message); }
    finally { setBusy(false); }
  };
  return <section className={`${shared.workflow} ${styles.panel}`} aria-label="Experimental command-rule simulation">
    <details>
      <summary><strong>Experimental strict-worker simulation</strong> · command-rule drafts</summary>
      <div className={styles.experimentalRules}>
    <p className={styles.error}>{ENFORCEMENT.reason} These rules model a possible strict worker; they are not active permissions.</p>
    <p>Match one command and its permitted switches. * matches any sequence and ? matches one character within a switch or value.
      Any switches keeps required switches, value conditions, and filesystem restrictions. xargs is rejected by the simulation.</p>
    <fieldset disabled={busy || !snapshot.requestEvidence} className={styles.controls}>
      {document.rules.map((rule, index) => <div key={rule.id} className={styles.ruleEditor}>
        <label>Command <select aria-label={`Rule ${index + 1} command`} value={rule.command} onChange={e => update(index, {
          command: e.target.value, allowedSwitches: [], requiredSwitches: e.target.value === 'sed' ? ['--sandbox'] : [], optionValues: {},
        })}>{COMMANDS.map(name => <option key={name}>{name}</option>)}</select></label>
        <label>Workspace mode <select value={rule.mode} onChange={e => update(index, { mode: e.target.value })}>
          <option value="read-only">Read-only</option><option value="implementation">Implementation</option></select></label>
        <label><input type="checkbox" checked={rule.anySwitches} onChange={e => update(index, { anySwitches: e.target.checked })} />Any switches</label>
        <label>Allowed switches / patterns <input disabled={rule.anySwitches} defaultValue={rule.allowedSwitches.join(' ')} key={rule.command + ':allowed'}
          onBlur={e => update(index, { allowedSwitches: split(e.target.value) })} placeholder="-n -E --color*" /></label>
        <label>Required switches <input defaultValue={rule.requiredSwitches.join(' ')} key={rule.command + ':required'}
          onBlur={e => update(index, { requiredSwitches: split(e.target.value) })} /></label>
        <label>Option value patterns (JSON map) <textarea defaultValue={JSON.stringify(rule.optionValues, null, 2)} key={rule.command + ':values'}
          onChange={e => {
            try {
              const values = JSON.parse(e.target.value);
              if (!values || Array.isArray(values) || typeof values !== 'object') throw new Error();
              update(index, { optionValues: values });
              setInvalidValues(current => ({ ...current, [rule.id]: false }));
              setError('');
            } catch {
              setInvalidValues(current => ({ ...current, [rule.id]: true }));
              setError('Option value patterns must be a JSON object, e.g. {"--color":["always","never"]}.');
            }
          }} /></label>
        {rule.command === 'sed' && <p>GNU sed requires --sandbox. In-place editing also requires an implementation rule and writable workspace.</p>}
        <p>File and directory authorization is not available yet; workspace permissions remain the filesystem boundary.</p>
        <button onClick={() => {
          setDocument(current => ({ ...current, rules: current.rules.filter((_, position) => position !== index) }));
          setInvalidValues(current => ({ ...current, [rule.id]: false }));
        }}>Remove rule</button>
      </div>)}
      <div className={shared.workflowActions}><button onClick={() => setDocument(current => ({ ...current, rules: [...current.rules, newRule()] }))}>Add command rule</button>
        <button onClick={save}>Save command-rule draft</button><button disabled title={ENFORCEMENT.reason}>Activate command policy (unavailable)</button></div>
    </fieldset>
    {error && <p role="alert" className={styles.error}>{error}</p>}{notice && <p role="status">{notice}</p>}
    <h3>Unique request evidence</h3>
    <RequestBrowser key={JSON.stringify(saved)} token={token} snapshot={snapshot} rules={saved.rules} />
      </div>
    </details>
  </section>;
}
