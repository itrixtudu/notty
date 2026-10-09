import { readPolicyReviewRuntimeAttestation } from './policy-review-attestation.js';
import { readSession, readSessionGraph, saveReviewFile } from '../../modules/policy-review/sessionStorage.js';
import { validateSavedDecisionSet } from '../../modules/policy-review/savedReview.js';

export const config = { api: { bodyParser: false } };

const MAX_DECISION_SET_BYTES = 8 * 1024 * 1024;

export const responseHeaders = response => {
    response.setHeader('Cache-Control', 'no-store');
    response.setHeader('Content-Type', 'application/json; charset=utf-8');
    response.setHeader('Referrer-Policy', 'no-referrer');
    response.setHeader('X-Content-Type-Options', 'nosniff');
};

export const sendJson = (response, statusCode, document) => {
    response.statusCode = statusCode;
    response.end(`${JSON.stringify(document)}\n`);
};

export const requestOrigin = request => {
    const host = request.headers?.host;
    if (typeof host !== 'string' || !host || /[\s/\\]/.test(host)) return null;
    try {
        return new URL(`${request.socket?.encrypted ? 'https' : 'http'}://${host}`).origin;
    } catch {
        return null;
    }
};

export const readBody = request => new Promise((resolve, reject) => {
    const chunks = [];
    let bytes = 0;
    request.on('data', chunk => {
        bytes += chunk.length;
        if (bytes > MAX_DECISION_SET_BYTES) {
            reject(new Error('DecisionSet exceeds the upload limit'));
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
    if (!attestation || requestOrigin(request) !== attestation.uiOrigin
        || (request.headers.origin && request.headers.origin !== attestation.uiOrigin)) {
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

    try {
        const session = await readSession();
        if (session) await validateSavedDecisionSet(document, await readSessionGraph(session));
        sendJson(response, 201, await saveReviewFile('decisions.json', document, session));
    } catch (error) {
        sendJson(response, 503, { error: error.message || 'could not save DecisionSet' });
    }
};
