import { responseHeaders, readBody, sendJson } from './policy-review-decision-set.js';
import { authorize, readSession, loadSnapshot, readSaved, saveDocument, proposalDigest, readCommandRules } from '../../modules/tool-review/storage.js';
import { requestEvidence } from '../../modules/tool-review/evidence.js';
import { ENFORCEMENT } from '../../modules/command-policy/model.js';

export const config = { api: { bodyParser: false } };

export default async function toolReview(request, response) {
    responseHeaders(response);
    if (!['GET', 'POST'].includes(request.method)) {
        response.setHeader('Allow', 'GET, POST');
        return sendJson(response, 405, { error: 'Method not allowed.' });
    }
    try {
        const session = await readSession();
        if (!authorize(request, session)) return sendJson(response, 403, { error: 'Open the review using its launcher URL.' });
        const snapshot = await loadSnapshot(session);
        if (request.method === 'GET') {
            const commandPolicy = await readCommandRules(snapshot);
            if (request.query?.view === 'requests') return sendJson(response, 200,
                await requestEvidence(snapshot, request.query, commandPolicy));
            return sendJson(response, 200, { snapshot, commandPolicy, enforcement: ENFORCEMENT,
                draft: await readSaved('draft.json', snapshot), proposal: await readSaved('proposal.json', snapshot) });
        }
        const document = JSON.parse(await readBody(request));
        if (document?.kind === 'NoshEnvironmentDigestRequest') return sendJson(response, 200, { proposalDigest: await proposalDigest(snapshot) });
        const filename = document?.kind === 'NoshCommandPolicyDraft' ? 'command-policy-draft.json'
            : document?.kind === 'NoshEnvironmentPolicy' ? 'environment-policy.json'
            : document?.kind === 'NoshToolReviewProposal' ? 'proposal.json' : 'draft.json';
        return sendJson(response, 201, await saveDocument(filename, document, snapshot));
    } catch (error) {
        // Filesystem errors may include private host paths; do not return them.
        return sendJson(response, 422, { error: error.code ? 'Review storage is unavailable. Check the launcher and file permissions.' : error.message });
    }
}
