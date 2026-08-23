import fs from 'node:fs/promises';
import path from 'node:path';

import { readPolicyReviewRuntimeAttestation } from './policy-review-attestation.js';

const MAX_DECISION_SET_BYTES = 8 * 1024 * 1024;

const responseHeaders = response => {
    response.setHeader('Cache-Control', 'no-store');
    response.setHeader('Content-Type', 'application/json; charset=utf-8');
    response.setHeader('Referrer-Policy', 'no-referrer');
    response.setHeader('X-Content-Type-Options', 'nosniff');
};

const sendJson = (response, statusCode, document) => {
    response.statusCode = statusCode;
    response.end(`${JSON.stringify(document)}\n`);
};

const requestOrigin = request => {
    const host = request.headers?.host;
    if (typeof host !== 'string' || !host || /[\s/\\]/.test(host)) return null;
    try {
        return new URL(`${request.socket?.encrypted ? 'https' : 'http'}://${host}`).origin;
    } catch {
        return null;
    }
};

const readBody = request => new Promise((resolve, reject) => {
    const chunks = [];
    let bytes = 0;
    request.on('data', chunk => {
        bytes += chunk.length;
        if (bytes > MAX_DECISION_SET_BYTES) {
            reject(new Error('DecisionSet exceeds the upload limit'));
            request.destroy();
            return;
        }
        chunks.push(chunk);
    });
    request.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')));
    request.on('error', reject);
});

const trustedDecisionSet = document => (
    document
    && typeof document === 'object'
    && !Array.isArray(document)
    && document.kind === 'NoshPolicyDecisionSet'
    && document.schemaVersion === 1
    && typeof document.graphContentDigest === 'string'
    && /^sha256:[a-f0-9]{64}$/.test(document.graphContentDigest)
    && Array.isArray(document.decisions)
);

const decisionsDirectory = environment => {
    const selected = String(environment.NOTTY_POLICY_REVIEW_DECISIONS_DIR || '');
    if (!selected || !path.isAbsolute(selected)) {
        throw new Error('managed DecisionSet output is unavailable');
    }
    return selected;
};

export default async function policyReviewDecisionSet(request, response) {
    responseHeaders(response);
    if (request.method !== 'POST') {
        response.setHeader('Allow', 'POST');
        sendJson(response, 405, { error: 'method not allowed' });
        return;
    }

    let attestation;
    try {
        attestation = await readPolicyReviewRuntimeAttestation();
    } catch {
        sendJson(response, 503, { error: 'launcher attestation unavailable' });
        return;
    }
    if (!attestation || requestOrigin(request) !== attestation.uiOrigin) {
        sendJson(response, 403, { error: 'UI origin does not match launcher attestation' });
        return;
    }

    let document;
    try {
        document = JSON.parse(await readBody(request));
    } catch (error) {
        sendJson(response, 400, { error: error.message || 'invalid DecisionSet JSON' });
        return;
    }
    if (!trustedDecisionSet(document)) {
        sendJson(response, 422, { error: 'incomplete or invalid DecisionSet' });
        return;
    }

    let directory;
    try {
        directory = decisionsDirectory(process.env);
        const stat = await fs.lstat(directory);
        if (
            !stat.isDirectory()
            || stat.isSymbolicLink()
            || (stat.mode & 0o077) !== 0
            || (typeof process.geteuid === 'function' && stat.uid !== process.geteuid())
        ) {
            throw new Error('managed DecisionSet output directory is not private');
        }
        const destination = path.join(directory, 'decisions.json');
        const temporary = path.join(directory, `.decisions.json.${process.pid}.tmp`);
        const serialized = `${JSON.stringify(document, null, 2)}\n`;
        await fs.writeFile(temporary, serialized, { flag: 'wx', mode: 0o600 });
        await fs.rename(temporary, destination);
        const destinationStat = await fs.lstat(destination);
        if (!destinationStat.isFile() || destinationStat.isSymbolicLink() || destinationStat.nlink !== 1) {
            throw new Error('managed DecisionSet output is not a regular file');
        }
        sendJson(response, 201, { saved: true, file: 'decisions.json' });
    } catch (error) {
        sendJson(response, 503, { error: error.message || 'could not save DecisionSet' });
    }
};
