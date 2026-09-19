import { renewTerminalInputAccess } from '../../../../lib/terminalManager.js';
import { isJsonRequest } from '../../../../lib/httpContentType.js';
import { isTerminalLockdownEnabled, sendTerminalLockdownResponse } from '../../../../lib/lockdown.js';

export default function handler(req, res) {
  res.setHeader('Cache-Control', 'no-store');
  if (isTerminalLockdownEnabled()) return sendTerminalLockdownResponse(res);
  if (req.method !== 'POST') {
    res.setHeader('Allow', 'POST');
    return res.status(405).end();
  }
  if (!isJsonRequest(req)) {
    return res.status(415).json({ error: 'Access renewal requires a JSON body.' });
  }
  try {
    res.json({ session: renewTerminalInputAccess(req.query.id, req.body || {}) });
  } catch (error) {
    res.status(error.statusCode || 400).json({ error: { code: error.code, message: error.message } });
  }
}
