import { resizeTerminal } from '../../../../lib/terminalManager.js';
import { getHttpProtocol, getRequestIpInfo, withLogContext } from '../../../../lib/terminalLogging.js';
import {
  isTerminalLockdownEnabled,
  sendTerminalLockdownResponse
} from '../../../../lib/lockdown.js';

function parseTerminalRef(value) {
  if (typeof value === 'number' && Number.isInteger(value)) {
    return value;
  }

  const raw = typeof value === 'string' ? value.trim() : '';
  if (!raw) {
    throw new Error('Invalid session reference');
  }
  return raw;
}

function withHttpContext(req, route, fn) {
  const protocol = getHttpProtocol(req);
  const { sourceIp, forwardedFor } = getRequestIpInfo(req);
  return withLogContext(
    {
      protocol,
      transport: 'http',
      source: 'nextApiTerminal',
      route,
      source_ip: sourceIp,
      x_forwarded_for: forwardedFor
    },
    fn
  );
}

export default function handler(req, res) {
  if (isTerminalLockdownEnabled()) {
    sendTerminalLockdownResponse(res);
    return;
  }

  if (req.method !== 'POST') {
    res.setHeader('Allow', ['POST']);
    res.status(405).end();
    return;
  }

  let id;
  try {
    id = parseTerminalRef(req.query.id);
  } catch (err) {
    res.status(400).json({ error: err.message });
    return;
  }

  const cols = req.body?.cols;
  const rows = req.body?.rows;

  try {
    withHttpContext(req, 'POST /api/terminals/:id/resize', () => {
      const session = resizeTerminal(id, cols, rows);
      res.status(200).json({ session });
    });
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
}
