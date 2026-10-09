import Head from 'next/head';
import { useEffect, useRef, useState } from 'react';
import { schema, commands, validateProfile } from '../modules/setup/model.js';
import styles from '../styles/setup.module.css';

const titles = {
  label: 'Profile name', context: 'Build context (relative to repository)', dockerfile: 'Dockerfile (relative to repository)',
  buildArgs: 'Non-secret build arguments (KEY=value, one per line)', tags: 'Image tags (one per line)',
  outputDirectory: 'Local output directory (relative to repository)', duration: 'Learning duration in seconds (0 = interactive)',
  presets: 'Development mount presets (one per line)', baselines: 'Pinned baseline files (relative path@sha256:digest, one per line)',
  reviewImage: 'Exact setup / review UI image ID', toolingImage: 'Exact policy tooling image ID',
  guardPrefix: 'Installed Guard prefix', reviewPool: 'Reserved review pool CIDR', excludedCidrs: 'LAN / VPN exclusions (one per line)',
  codexHome: 'Custom host Codex home', toolReport: 'Saved tool audit directory', toolPolicyDigest: 'Reviewed environment-policy digest',
  decisionDigest: 'Saved network decision digest', directory: 'Saved network review directory',
  httpCapture: 'HTTP capture (mitmproxy currently diagnostic only)', launchMode: 'Network launch mode',
  mode: 'Mode', image: 'Runtime image (prefer an exact local image ID)', startApp: 'Start application',
};
const title = key => titles[key] || key.replace(/([A-Z])/g, ' $1').replace(/^./, c => c.toUpperCase());

function Fields({ definition, value, onChange, prefix }) {
  return <div className={styles.fields}>{Object.entries(definition.properties).map(([key, field]) => {
    const id = `${prefix}-${key}`;
    const change = next => onChange({ ...value, [key]: next });
    if (field.type === 'object') return <fieldset key={key}><legend>{title(key)}</legend><Fields definition={field} value={value[key]} onChange={change} prefix={id} /></fieldset>;
    return <label key={key} htmlFor={id} className={field.type === 'boolean' ? styles.checkbox : undefined}>
      <span id={`${id}-label`}>{title(key)}</span>
      {field.type === 'boolean' ? <input id={id} aria-labelledby={`${id}-label`} type="checkbox" checked={value[key]} onChange={event => change(event.target.checked)} />
        : field.enum ? <select id={id} aria-labelledby={`${id}-label`} value={value[key]} onChange={event => change(event.target.value)}>{field.enum.map(option => <option key={option}>{option}</option>)}</select>
          : field.type === 'array' ? <textarea id={id} aria-labelledby={`${id}-label`} rows={3} value={value[key].join('\n')} onChange={event => change(event.target.value ? event.target.value.split('\n') : [])} onBlur={() => change(value[key].filter(item => item.trim()))} />
            : <input id={id} aria-labelledby={`${id}-label`} type={field.type === 'integer' ? 'number' : 'text'} min={field.minimum} max={field.maximum} value={value[key]} onChange={event => change(field.type === 'integer' ? Number(event.target.value) : event.target.value)} autoComplete="off" spellCheck={false} />}
    </label>;
  })}</div>;
}

function Command({ card }) {
  const [copied, setCopied] = useState(false);
  const ref = useRef(null);
  const copy = async () => {
    try { await navigator.clipboard.writeText(card.command); setCopied(true); }
    catch { ref.current?.focus(); ref.current?.select(); }
  };
  return <article className={styles.command}>
    <h3>{card.title}</h3><p>{card.note}</p>
    {card.blocked ? <p className={styles.blocked}>{card.blocked}</p> : <>
      <textarea ref={ref} readOnly aria-label={`${card.title} command`} value={card.command} rows={3} />
      <button type="button" onClick={copy}>{copied ? 'Copied' : 'Copy command'}</button>
    </>}
  </article>;
}

const stepLabels = { 1: 'Guard', 2: 'Launchers', 3: 'Image', 4: 'Runtime capture', 5: 'Network review', 6: 'Signing', 7: 'Activation', 8: 'Privileged check' };
export default function Setup() {
  const token = useRef('');
  const [loaded, setLoaded] = useState(null);
  const [profile, setProfile] = useState(null);
  const [message, setMessage] = useState('Opening repository setup…');
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);
  const [tab, setTab] = useState('repository');
  const dirty = loaded && JSON.stringify(loaded.document.profile) !== JSON.stringify(profile);
  async function api(body) {
    const response = await fetch('/api/setup', { method: body ? 'POST' : 'GET', headers: { Authorization: `Bearer ${token.current}`, ...(body ? { 'Content-Type': 'application/json' } : {}) }, ...(body ? { body: JSON.stringify(body) } : {}) });
    const data = await response.json();
    if (!response.ok) throw new Error(data.error || 'Setup request failed.');
    return data;
  }
  async function reload(reset = false) {
    setBusy(true); setError('');
    try {
      const data = await api();
      if (reset || !profile) { setLoaded(data); setProfile(data.document.profile); }
      else if (data.document.revision !== loaded.document.revision) throw new Error('Profile changed in another session. Reload saved profile to use it; your unsaved edits remain here.');
      else setLoaded(data);
      setMessage('Loaded saved configuration and the latest host snapshot.');
    } catch (err) { setError(err.message); }
    finally { setBusy(false); }
  }
  useEffect(() => {
    const fragment = new URLSearchParams(window.location.hash.slice(1)).get('token');
    try {
      if (fragment) sessionStorage.setItem('nosh-setup-token', fragment);
      token.current = fragment || sessionStorage.getItem('nosh-setup-token') || '';
    } catch { token.current = fragment || token.current; }
    if (fragment) window.history.replaceState(null, '', window.location.pathname);
    reload(true);
  }, []);
  useEffect(() => {
    const warn = event => { if (dirty) { event.preventDefault(); event.returnValue = ''; } };
    window.addEventListener('beforeunload', warn);
    return () => window.removeEventListener('beforeunload', warn);
  }, [dirty]);
  async function save() {
    setBusy(true); setError('');
    try {
      validateProfile(profile);
      const { document } = await api({ revision: loaded.document.revision, profile });
      setLoaded({ ...loaded, document }); setProfile(document.profile);
      setMessage('Profile saved. No host settings or active policies changed. Copy a command below to continue.');
    } catch (err) { setError(err.message); }
    finally { setBusy(false); }
  }
  const cards = loaded ? commands(loaded.document.profile, loaded.binding, loaded.document.revision) : [];
  const hostField = keys => {
    const properties = Object.fromEntries(keys.map(key => [key, schema.properties.host.properties[key]]));
    return <Fields definition={{ properties }} value={profile.host} onChange={host => setProfile({ ...profile, host })} prefix="host" />;
  };
  const settingsField = key => <Fields definition={schema.properties.settings.properties[key]} value={profile.settings[key]} onChange={value => setProfile({ ...profile, settings: { ...profile.settings, [key]: value } })} prefix={key} />;
  const show = ids => <div className={styles.commands}>{cards.filter(card => ids.includes(card.id)).map(card => <Command key={`${loaded.document.revision}-${card.id}`} card={card} />)}</div>;
  return <><Head><title>Repository setup · Nosh</title><meta name="referrer" content="no-referrer" /></Head>
    <main className={styles.page}>
      <header><p className={styles.eyebrow}>NOSH / REPOSITORY SETUP</p><h1>{profile?.settings.label || 'Repository setup'}</h1>
        <p>Save settings here. Run the generated commands in your host terminal. Review and activation remain separate steps.</p>
        {loaded && <code className={styles.workspace}>{loaded.binding.workspace.path}</code>}
      </header>
      <div role="status" className={styles.message}>{message}{dirty && ' Unsaved changes.'}</div>
      {error && <div role="alert" className={styles.error}>{error} <button onClick={() => reload(!profile)} disabled={busy}>Retry loading</button></div>}
      {profile && <>
        <div className={styles.toolbar}>
          <button className={styles.primary} onClick={save} disabled={busy || !dirty}>Save profile</button>
          <button onClick={() => reload()} disabled={busy}>Reload status</button>
          <button onClick={() => { if (!dirty || window.confirm('Discard unsaved edits and reload the saved profile?')) reload(true); }} disabled={busy}>Reload saved profile</button>
          <span>Revision {loaded.document.revision} · {dirty ? 'Commands use the last saved revision' : 'Saved'}</span>
        </div>
        <nav aria-label="Setup sections" className={styles.tabs}>{[['repository','Repository & host'],['build','Build / CI'],['runtime','Runtime'],['tools','Tools'],['review','Review & activation'],['launch','Launch & export']].map(([id, label]) => <button key={id} aria-current={tab === id ? 'page' : undefined} onClick={() => setTab(id)}>{label}</button>)}</nav>
        <fieldset className={styles.panel} disabled={busy}>
          <legend className={styles.visuallyHidden}>Repository configuration</legend>
          {tab === 'repository' && <><h2>Repository and host</h2><label className={styles.name}>Profile name<input value={profile.settings.label} onChange={event => setProfile({ ...profile, settings: { ...profile.settings, label: event.target.value } })} /></label>
            {hostField(['guardPrefix','toolingImage','reviewImage','reviewPool','excludedCidrs'])}
            <p>The review pool is shared host configuration. Saving it here does not reserve a network or change Docker.</p>
            {show(['install','setup','preflight','network','refresh','privileged-refresh','advanced'])}</>}
          {tab === 'build' && <><h2>Build capture and CI/CD</h2><p>Network capture always performs a clean build; cache mode and depth apply only to performance/profile capture. Build evidence does not authorize runtime traffic. Build arguments must contain no secrets.</p>
            {settingsField('build')}{show(['build'])}
            <details><summary>Saved build evidence (informational)</summary><pre>{JSON.stringify(loaded.snapshot?.build || { state: 'unknown' }, null, 2)}</pre></details>
            <h3>Use on a provisioned CI runner</h3><p>Export settings below, then run as a normal Docker-authorized user on a Linux runner with Guard and eBPF installed. Only upload the generated <code>portable/</code> directory and <code>result.json</code>. Private diagnostics remain in host state.</p>
            <pre>nosh config ci --profile nosh-config.json --workdir "$PWD" --output-dir "$PWD/ci-evidence"</pre>
            <p>The output directory must be new. CI never approves policy or deploys an image automatically.</p>{show(['export'])}</>}
          {tab === 'runtime' && <><h2>Development and application runtimes</h2><p>Each workload has independent capture and policy. Select a Guard-compatible image. Changing an image, workspace, agent homes, or baselines can require new learning and review.</p>
            {settingsField('runtime')}{hostField(['codexHome'])}{show(['learn-dev','learn-run','inventory-dev','inventory-run'])}</>}
          {tab === 'tools' && <><h2>Tool environment</h2><p>Read-only is the default. Implementation mode must be approved in Tool Review before launch. Tool activity classifications are informational; filesystem policy controls workspace writes for the entire dev container.</p>
            {settingsField('tools')}{hostField(['toolReport','toolPolicyDigest'])}{show(['audit-tools','tools-review','tools-check','tools-apply','tools-status'])}</>}
          {tab === 'review' && <><h2>Review and activation</h2><p>Use the managed reviewers to make decisions. Copy their saved directory and digest here to prepare the matching apply command. These references do not establish approval.</p>
            {hostField(['reviews'])}{show(['signing','prepare-dev','prepare-run','review-dev','review-run','apply-dev','apply-run'])}
            <h3>Last host snapshot</h3><p>{loaded.snapshot ? `Checked ${loaded.snapshot.checkedAt}. ${loaded.snapshot.revision !== loaded.document.revision ? 'Settings changed since this check; refresh from the host.' : ''}` : 'No host snapshot yet.'} Snapshots are informational; apply and launch verify current authority again.</p>
            {loaded.snapshot?.errors?.map(item => <p key={item} className={styles.error}>{item}</p>)}
            {Object.entries(loaded.snapshot?.workloads || {}).map(([workload, result]) => <div key={workload}><h3>{workload}</h3><dl className={styles.status}>{Object.entries(result.steps).filter(([key]) => stepLabels[key]).map(([key, row]) => <div key={key}><dt>{stepLabels[key]} · {row.state}</dt><dd>{row.detail}</dd></div>)}</dl>
              <details><summary>Saved evidence references</summary><pre>{JSON.stringify(Object.fromEntries(Object.entries(result.steps).filter(([key]) => !stepLabels[key])), null, 2)}</pre></details></div>)}
            <details><summary>Tool policy status (local mirror)</summary><pre>{JSON.stringify(loaded.snapshot?.tools || { state: 'unknown' }, null, 2)}</pre></details>
            {show(['refresh','privileged-refresh'])}</>}
          {tab === 'launch' && <><h2>Launch and portable export</h2><p>Applying a tool policy affects future containers. Recreate explicitly to change a running container’s pinned mode or policy. Enforced launch failures never fall back to legacy mode.</p>
            {show(['start-dev','recreate-dev','start-run','recreate-run','export'])}
            <p>Redirect export output to a file, then import it on another checkout with <code>nosh config import --profile nosh-config.json --workdir /path/to/repo</code>. Imports reset host references and require fresh checks.</p></>}
        </fieldset>
      </>}
    </main>
  </>;
}
