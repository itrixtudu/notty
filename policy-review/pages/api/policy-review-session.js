import { readPolicyReviewRuntimeAttestation } from './policy-review-attestation.js';
import { responseHeaders, requestOrigin, readBody, sendJson } from './policy-review-decision-set.js';
import { readSession, readSessionGraph, readSavedReview, saveReviewFile } from '../../modules/policy-review/sessionStorage.js';
import { validateReviewDraft } from '../../modules/policy-review/savedReview.js';

export const config = { api: { bodyParser: false } };

export default async function policyReviewSession(request, response) {
    responseHeaders(response);
    if (!['GET', 'POST'].includes(request.method)) {
        response.setHeader('Allow', 'GET, POST');
        return sendJson(response, 405, { error: 'method not allowed' });
    }
    try {
        const attestation = await readPolicyReviewRuntimeAttestation();
        if (!attestation || requestOrigin(request) !== attestation.uiOrigin
            || (request.headers.origin && request.headers.origin !== attestation.uiOrigin)) {
            return sendJson(response, 403, { error: 'UI origin does not match launcher attestation' });
        }
        const session = await readSession();
        if (!session) return sendJson(response, 503, { error: 'Reopen review with the updated launcher to enable managed saving' });
        if (request.method === 'GET') {
            return sendJson(response, 200, { session,
                draft: await readSavedReview('draft.json'),
                decisions: await readSavedReview('decisions.json'),
                lastApplied: await readSavedReview('applied.json') });
        }
        const document = JSON.parse(await readBody(request));
        validateReviewDraft(document, await readSessionGraph(session));
        return sendJson(response, 201, await saveReviewFile('draft.json', document, session));
    } catch (error) {
        return sendJson(response, 422, { error: error.message });
    }
}
