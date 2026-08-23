import { constants as fsConstants } from 'node:fs';
import fs from 'node:fs/promises';
import path from 'node:path';

import { parsePolicyReviewRuntimeAttestation } from '../../modules/policy-review/runtimeAttestation.js';

const MAX_ATTESTATION_BYTES = 4096;

const responseHeaders = response => {
    response.setHeader('Cache-Control', 'no-store');
    response.setHeader('Content-Type', 'application/json; charset=utf-8');
    response.setHeader('Referrer-Policy', 'no-referrer');
    response.setHeader('X-Content-Type-Options', 'nosniff');
    response.setHeader('Content-Security-Policy', "default-src 'none'; frame-ancestors 'none'");
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

export async function readPolicyReviewRuntimeAttestation(environment = process.env) {
    const configuredPath = String(environment.NOTTY_POLICY_REVIEW_ATTESTATION_FILE || '');
    if (!configuredPath) return null;
    if (!path.isAbsolute(configuredPath)) {
        throw new Error('Policy Review runtime attestation path must be absolute');
    }

    let handle;
    try {
        handle = await fs.open(
            configuredPath,
            fsConstants.O_RDONLY | (fsConstants.O_NOFOLLOW || 0),
        );
        const stat = await handle.stat();
        const effectiveUid = typeof process.geteuid === 'function' ? process.geteuid() : null;
        if (
            !stat.isFile()
            || stat.nlink !== 1
            || stat.size < 2
            || stat.size > MAX_ATTESTATION_BYTES
            || (stat.mode & 0o077) !== 0
            || (effectiveUid !== null && stat.uid !== effectiveUid)
        ) {
            throw new Error('Policy Review runtime attestation file is not a private owned regular file');
        }
        const content = await handle.readFile({ encoding: 'utf8' });
        return parsePolicyReviewRuntimeAttestation(JSON.parse(content));
    } finally {
        await handle?.close();
    }
}

export default async function policyReviewAttestation(request, response) {
    responseHeaders(response);
    if (request.method !== 'GET') {
        response.setHeader('Allow', 'GET');
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
    if (attestation === null) {
        sendJson(response, 200, { schemaVersion: 1, graphOrigin: null });
        return;
    }
    if (requestOrigin(request) !== attestation.uiOrigin) {
        sendJson(response, 403, { error: 'UI origin does not match launcher attestation' });
        return;
    }
    sendJson(response, 200, {
        schemaVersion: 1,
        graphOrigin: attestation.graphOrigin,
    });
}
