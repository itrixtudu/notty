import fs, { constants } from 'node:fs/promises';
import crypto from 'node:crypto';
import path from 'node:path';

export const MAX_SAVED_REVIEW_BYTES = 8 * 1024 * 1024;

export async function readPrivateJson(file, maximum = MAX_SAVED_REVIEW_BYTES) {
    const handle = await fs.open(file, constants.O_RDONLY | constants.O_NOFOLLOW);
    try {
        const stat = await handle.stat();
        if (!stat.isFile() || stat.nlink !== 1 || (stat.mode & 0o077)
            || stat.uid !== process.geteuid() || stat.size > maximum) {
            throw new Error('Review file is not a bounded private owned file');
        }
        return JSON.parse(await handle.readFile('utf8'));
    } finally {
        await handle.close();
    }
}

export async function readSession() {
    const file = process.env.NOTTY_POLICY_REVIEW_SESSION_FILE;
    if (!file) return null;
    const session = await readPrivateJson(file);
    if (session.kind !== 'NoshPolicyReviewSession' || session.schemaVersion !== 1
        || !path.isAbsolute(session.directory) || !path.isAbsolute(session.launcher)
        || !/^sha256:[a-f0-9]{64}$/.test(session.graphContentDigest)) {
        throw new Error('Invalid launcher review session');
    }
    return session;
}

export async function readSessionGraph(session) {
    const file = process.env.NOTTY_POLICY_REVIEW_GRAPH_FILE;
    if (!session || !file) throw new Error('Managed review graph is unavailable');
    const graph = await readPrivateJson(file, 25 * 1024 * 1024);
    if (graph.contentDigest !== session.graphContentDigest) throw new Error('Session graph changed');
    return graph;
}

export async function saveReviewFile(filename, document, session) {
    const directory = process.env.NOTTY_POLICY_REVIEW_DECISIONS_DIR;
    if (!directory || !path.isAbsolute(directory)) throw new Error('Managed review saving is unavailable');
    const stat = await fs.lstat(directory);
    if (!stat.isDirectory() || stat.isSymbolicLink() || (stat.mode & 0o077)
        || stat.uid !== process.geteuid()) throw new Error('Review output directory is not private');
    const serialized = `${JSON.stringify(document, null, 2)}\n`;
    if (Buffer.byteLength(serialized) > MAX_SAVED_REVIEW_BYTES) throw new Error('Review exceeds the 8 MiB save limit');
    const temporary = path.join(directory, `.${filename}.${crypto.randomUUID()}.tmp`);
    try {
        await fs.writeFile(temporary, serialized, { flag: 'wx', mode: 0o600 });
        await fs.rename(temporary, path.join(directory, filename));
    } finally {
        await fs.rm(temporary, { force: true });
    }
    return { saved: true, file: filename,
        path: session ? path.join(session.directory, 'decisions', filename) : null,
        savedAt: new Date().toISOString(), contentDigest: document.contentDigest || null };
}

export async function readSavedReview(filename) {
    const directory = process.env.NOTTY_POLICY_REVIEW_DECISIONS_DIR;
    if (!directory) return null;
    try { return await readPrivateJson(path.join(directory, filename)); }
    catch (error) { if (error.code === 'ENOENT') return null; throw error; }
}
