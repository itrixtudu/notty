import { canonicalJson, validateEnvironment } from './environment.js';
import fs, { constants } from 'node:fs/promises';
import path from 'node:path';
import crypto from 'node:crypto';
import { readPrivateJson } from '../policy-review/sessionStorage.js';
import { MAX_DOCUMENT_BYTES, validateDocument } from './model.js';
import { validateDescriptor, openEvidence } from './evidence.js';
import { validateRules } from '../command-policy/model.js';

export const INPUT_FILES = ['allow.json', 'not-yet.json', 'rules-review.json', 'planning.config.toml', 'implementation.config.toml'];
export const MAX_INPUT_BYTES = 25 * 1024 * 1024;
const hash = value => crypto.createHash('sha256').update(value).digest('hex');
const text = value => typeof value === 'string' && value.length <= 16384;
const natural = value => Number.isSafeInteger(value) && value >= 0;

export async function readSession() {
    const filename = process.env.NOTTY_TOOL_REVIEW_SESSION_FILE;
    if (!filename) throw new Error('Open this page with audit-codex-tools.py --review-ui REPORT_DIR.');
    const session = await readPrivateJson(filename);
    if (session.kind !== 'NoshToolReviewSession' || session.schemaVersion !== 1
        || !/^[a-f0-9]{64}$/.test(session.token) || !/^sha256:[a-f0-9]{64}$/.test(session.snapshotDigest)
        || !/^http:\/\/127\.0\.0\.1:\d+$/.test(session.origin)) throw new Error('Invalid review session.');
    return session;
}

export function authorize(request, session) {
    const expected = Buffer.from(`Bearer ${session.token}`);
    const received = Buffer.from(String(request.headers.authorization || ''));
    return received.length === expected.length && crypto.timingSafeEqual(received, expected)
        && `http://${request.headers.host}` === session.origin
        && (!request.headers.origin || request.headers.origin === session.origin)
        && (!request.headers['sec-fetch-site'] || request.headers['sec-fetch-site'] === 'same-origin');
}

export async function loadSnapshot(session) {
    const directory = process.env.NOTTY_TOOL_REVIEW_INPUT_DIR;
    if (!directory || !path.isAbsolute(directory)) throw new Error('Audit inputs are unavailable.');
    const inputs = {};
    const hashes = [];
    let size = 0;
    for (const name of INPUT_FILES) {
        // Inputs are private runtime mounts, never build-time dependencies.
        const file = path.join(/* turbopackIgnore: true */ directory, name);
        const handle = await fs.open(/* turbopackIgnore: true */ file, constants.O_RDONLY | constants.O_NOFOLLOW);
        try {
            const stat = await handle.stat();
            size += stat.size;
            if (!stat.isFile() || stat.nlink !== 1 || (stat.mode & 0o077) || stat.uid !== process.geteuid()
                || size > MAX_INPUT_BYTES) throw new Error('Audit inputs must be bounded private owned files.');
            const bytes = await handle.readFile();
            if (bytes.length !== stat.size) throw new Error('Audit input changed during reading.');
            hashes.push(`${name}\0${hash(bytes)}\n`);
            inputs[name] = name.endsWith('.json') ? JSON.parse(bytes.toString('utf8')) : bytes.toString('utf8');
        } finally { await handle.close(); }
    }
    const digest = `sha256:${hash(hashes.join(''))}`;
    if (digest !== session.snapshotDigest) throw new Error('Audit inputs changed. Reopen the review for this snapshot.');
    const groups = [];
    const ids = new Set();
    for (const category of ['allow', 'not-yet']) {
        const report = inputs[`${category}.json`];
        if (![1, 2].includes(report.schema_version) || report.category !== category || typeof report.complete !== 'boolean'
            || !Array.isArray(report.entries) || !report.totals) throw new Error('Unsupported audit report.');
        for (const entry of report.entries) {
            if (![entry.tool, entry.form, entry.reason].every(text) || !natural(entry.count)
                || !Array.isArray(entry.examples) || entry.examples.length > 3
                || entry.examples.some(example => !text(example.source) || !natural(example.line) || example.line < 1)) {
                throw new Error('Invalid audit group.');
            }
            const id = hash(JSON.stringify([category, entry.tool, entry.form, entry.reason]));
            if (ids.has(id)) throw new Error('Duplicate audit group.');
            ids.add(id);
            groups.push({ id, category, tool: entry.tool, form: entry.form, reason: entry.reason,
                count: entry.count, examples: entry.examples.map(({ source, line }) => ({ source, line })) });
        }
        const count = report.entries.reduce((total, entry) => total + entry.count, 0);
        if (count !== report.totals[`${category}_requests`]) throw new Error('Audit counts do not reconcile.');
    }
    const allowed = inputs['allow.json'];
    const pending = inputs['not-yet.json'];
    const requestEvidence = allowed.request_evidence ?? null;
    if (allowed.schema_version !== pending.schema_version
        || canonicalJson(requestEvidence) !== canonicalJson(pending.request_evidence ?? null)
        || (allowed.schema_version === 2 && !requestEvidence)) throw new Error('Mismatched request evidence.');
    if (requestEvidence) validateDescriptor(requestEvidence);
    const historyScope = allowed.history_scope ?? null;
    if (canonicalJson(historyScope) !== canonicalJson(pending.history_scope ?? null)
        || (historyScope !== null && (typeof historyScope !== 'object' || Array.isArray(historyScope)
            || !['repo', 'directory', 'all'].includes(historyScope.kind)
            || historyScope.dates !== 'all'
            || !Array.isArray(historyScope.excluded_roots)
            || historyScope.excluded_roots.some(root => typeof root !== 'string' || !root.startsWith('/'))
            || (historyScope.kind === 'all' ? historyScope.root !== null
                : typeof historyScope.root !== 'string' || !historyScope.root.startsWith('/'))
            || !natural(historyScope.excluded_requests) || !natural(historyScope.unattributed_requests)))) {
        throw new Error('Invalid or mismatched history scope.');
    }
    const totals = allowed.totals;
    for (const key of ['unique_requests', 'raw_requests', 'duplicate_requests', 'allow_requests', 'not-yet_requests']) {
        if (!natural(totals[key]) || totals[key] !== pending.totals[key]) throw new Error('Mismatched audit totals.');
    }
    if (totals.unique_requests !== totals.allow_requests + totals['not-yet_requests']
        || totals.raw_requests !== totals.unique_requests + totals.duplicate_requests
        || allowed.complete !== pending.complete) throw new Error('Mismatched audit snapshot.');
    const rules = inputs['rules-review.json'];
    if (!Array.isArray(rules.entries) || !rules.errors || typeof rules.errors !== 'object') throw new Error('Invalid rules report.');
    const ruleEntries = rules.entries.map(entry => {
        if (![entry.source, entry.executable, entry.reason].every(text) || !natural(entry.line) || entry.line < 1
            || !natural(entry.prefix_tokens) || !['allow', 'prompt', 'forbidden'].includes(entry.decision)
            || typeof entry.needs_review !== 'boolean') throw new Error('Invalid rule reference.');
        return { source: entry.source, line: entry.line, executable: entry.executable,
            prefix_tokens: entry.prefix_tokens, decision: entry.decision, needs_review: entry.needs_review };
    });
    groups.sort((a, b) => a.tool.localeCompare(b.tool) || b.count - a.count || a.id.localeCompare(b.id));
    return { digest, historyScope, complete: allowed.complete && (!historyScope || historyScope.kind === 'all' || historyScope.unattributed_requests === 0) && Object.keys(rules.errors).length === 0,
        groups, requestEvidence, rules: ruleEntries, totals: { uniqueRequests: totals.unique_requests },
        profiles: { planning: inputs['planning.config.toml'], implementation: inputs['implementation.config.toml'] } };
}

function outputDirectory() {
    const directory = process.env.NOTTY_TOOL_REVIEW_OUTPUT_DIR;
    if (!directory || !path.isAbsolute(directory)) throw new Error('Review output is unavailable.');
    return directory;
}

export async function readSaved(name, snapshot) {
    try {
        return validateDocument(await readPrivateJson(path.join(outputDirectory(), name)), snapshot, name === 'proposal.json');
    } catch (error) { if (error.code === 'ENOENT') return null; throw error; }
}

export async function saveDocument(name, document, snapshot) {
    if (!['draft.json', 'proposal.json', 'environment-policy.json', 'command-policy-draft.json'].includes(name)) throw new Error('Invalid save target.');
    if (snapshot.requestEvidence && name !== 'draft.json') await openEvidence(snapshot);
    if (name === 'environment-policy.json' && (await readCommandRules(snapshot))?.rules.length) {
        throw new Error('Command rules are not active: strict runner host enforcement has not been verified. Environment-only approval cannot activate them.');
    }
    const validated = name === 'command-policy-draft.json' ? validateRules(document, snapshot.digest)
        : name === 'environment-policy.json'
        ? validateEnvironment(document, snapshot, await proposalDigest(snapshot))
        : validateDocument(document, snapshot, name === 'proposal.json');
    const directory = outputDirectory();
    const stat = await fs.lstat(directory);
    if (!stat.isDirectory() || stat.isSymbolicLink() || (stat.mode & 0o077) || stat.uid !== process.geteuid()) {
        throw new Error('Review output directory must be private and owned.');
    }
    const serialized = `${JSON.stringify(validated)}\n`;
    if (Buffer.byteLength(serialized) > MAX_DOCUMENT_BYTES) throw new Error('Review exceeds the 8 MiB save limit.');
    const temporary = path.join(directory, `.${crypto.randomUUID()}.tmp`);
    try {
        await fs.writeFile(temporary, serialized, { flag: 'wx', mode: 0o600 });
        await fs.rename(temporary, path.join(directory, name));
    } finally { await fs.rm(temporary, { force: true }); }
    return { saved: true, file: name, ...(name === 'environment-policy.json' ? { policyDigest: `sha256:${hash(serialized)}` } : {}) };
}

export async function readCommandRules(snapshot) {
    try {
        return validateRules(await readPrivateJson(path.join(outputDirectory(), 'command-policy-draft.json')), snapshot.digest);
    } catch (error) { if (error.code === 'ENOENT') return null; throw error; }
}

export async function proposalDigest(snapshot) {
    const proposal = await readSaved('proposal.json', snapshot);
    if (!proposal) throw new Error('Save a completed tool proposal first.');
    return `sha256:${hash(canonicalJson(proposal))}`;
}
