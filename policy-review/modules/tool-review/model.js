export const CHOICES = Object.freeze({
    unreviewed: 'Unreviewed',
    expected: 'Expected',
    investigate: 'Investigate',
});
export const MAX_DOCUMENT_BYTES = 8 * 1024 * 1024;

const LEGACY_CHOICES = Object.freeze({
    'needs-review': 'unreviewed',
    'read-only': 'expected',
    implementation: 'investigate',
    exclude: 'investigate',
});

const object = value => value && typeof value === 'object' && !Array.isArray(value);
const shortText = (value, maximum) => typeof value === 'string' && value.length <= maximum;

export function emptyDraft(snapshot) {
    return { kind: 'NoshToolReviewDraft', schemaVersion: 2, enforcing: false,
        snapshotDigest: snapshot.digest, reviewer: '', acknowledged: false,
        decisions: Object.fromEntries(snapshot.groups.map(group => [group.id, { choice: 'unreviewed', note: '' }])) };
}

export function validateDocument(document, snapshot, finalized = false) {
    const kind = finalized ? 'NoshToolReviewProposal' : 'NoshToolReviewDraft';
    if (!object(document) || document.kind !== kind || ![1, 2].includes(document.schemaVersion)
        || document.enforcing !== false || document.snapshotDigest !== snapshot.digest
        || !shortText(document.reviewer, 200) || typeof document.acknowledged !== 'boolean'
        || !object(document.decisions)) throw new Error('Invalid review or different audit snapshot.');
    if (Object.keys(document.decisions).length !== snapshot.groups.length) throw new Error('Review must contain every audit group exactly once.');
    const decisions = {};
    for (const group of snapshot.groups) {
        const decision = document.decisions[group.id];
        const legacyChoice = document.schemaVersion === 1 ? decision?.choice : decision?.legacyChoice;
        const choice = document.schemaVersion === 1 ? LEGACY_CHOICES[decision?.choice] : decision?.choice;
        if (!object(decision) || !Object.hasOwn(CHOICES, choice) || !shortText(decision.note, 4096)
            || (legacyChoice !== undefined && (!Object.hasOwn(LEGACY_CHOICES, legacyChoice)
                || LEGACY_CHOICES[legacyChoice] !== choice))) {
            throw new Error('Unknown group, decision, or invalid note.');
        }
        decisions[group.id] = { choice, note: decision.note,
            ...(legacyChoice === undefined ? {} : { legacyChoice }) };
    }
    const clean = { kind, schemaVersion: 2, enforcing: false, snapshotDigest: snapshot.digest,
        reviewer: document.reviewer, acknowledged: document.acknowledged, decisions };
    if (finalized) {
        if (!snapshot.complete || !clean.reviewer.trim() || !clean.acknowledged
            || Object.values(decisions).some(decision => decision.choice === 'unreviewed')) {
            throw new Error('Complete the audit, all choices, reviewer name, and acknowledgement before saving a proposal.');
        }
        if (!shortText(document.completedAt, 40) || !Number.isFinite(Date.parse(document.completedAt))) {
            throw new Error('Invalid completion time.');
        }
        clean.completedAt = document.completedAt;
    }
    if (JSON.stringify(clean).length > MAX_DOCUMENT_BYTES) throw new Error('Review exceeds the save limit.');
    return clean;
}

export function importDraft(document, snapshot) {
    const finalized = document?.kind === 'NoshToolReviewProposal';
    const validated = validateDocument(document, snapshot, finalized);
    const { completedAt, ...draft } = validated;
    return { ...draft, kind: 'NoshToolReviewDraft' };
}

export function fingerprint(document) {
    return JSON.stringify([document.snapshotDigest, document.reviewer, document.acknowledged,
        Object.entries(document.decisions).sort(([a], [b]) => a.localeCompare(b))]);
}

export function filteredGroups(groups, draft, { query = '', tool = '', choice = '', remaining = false }) {
    const text = query.trim().toLowerCase();
    return groups.filter(group => (!tool || group.tool === tool)
        && (!choice || draft.decisions[group.id].choice === choice)
        && (!remaining || draft.decisions[group.id].choice === 'unreviewed')
        && (!text || `${group.tool} ${group.form} ${group.reason}`.toLowerCase().includes(text)));
}

export function decideGroups(draft, ids, choice, note) {
    if (!Object.hasOwn(CHOICES, choice)) throw new Error('Unknown decision.');
    const decisions = { ...draft.decisions };
    for (const id of ids) {
        if (!Object.hasOwn(decisions, id)) throw new Error('Unknown group.');
        decisions[id] = { choice, note: note === undefined ? decisions[id].note : note };
    }
    return { ...draft, acknowledged: false, decisions };
}
