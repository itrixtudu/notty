import { responseHeaders, readBody, sendJson } from './policy-review-decision-set.js';
import { authorize } from '../../modules/tool-review/storage.js';
import { readSession, load, save } from '../../modules/setup/storage.js';

export const config = { api: { bodyParser: false } };
export default async function setup(request, response) {
  responseHeaders(response);
  if (!['GET', 'POST'].includes(request.method)) {
    response.setHeader('Allow', 'GET, POST');
    return sendJson(response, 405, { error: 'Method not allowed.' });
  }
  try {
    if (!authorize(request, await readSession())) return sendJson(response, 403, { error: 'Open setup using the private launcher URL.' });
    if (request.method === 'GET') return sendJson(response, 200, await load());
    const body = await readBody(request);
    if (Buffer.byteLength(body) > 1024 * 1024) return sendJson(response, 413, { error: 'Profile exceeds 1 MiB.' });
    return sendJson(response, 200, { document: await save(JSON.parse(body)) });
  } catch (error) {
    return sendJson(response, error.status || 422, { error: error.code ? 'Setup storage is unavailable. Check the launcher and private file permissions.' : error.message });
  }
}
