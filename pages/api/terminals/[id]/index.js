import {
  getTerminalSummary,
  killTerminal
} from '../../../../lib/terminalManager.js';
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

  let id;
  try {
    id = parseTerminalRef(req.query.id);
  } catch (err) {
    res.status(400).json({ error: err.message });
    return;
  }

  if (req.method === 'GET') {
    try {
      withHttpContext(req, 'GET /api/terminals/:id', () => {
        const session = getTerminalSummary(id);
        res.status(200).json({ session });
      });
    } catch (err) {
      res.status(404).json({ error: err.message });
    }
    return;
  }

  if (req.method === 'DELETE') {
    try {
      withHttpContext(req, 'DELETE /api/terminals/:id', () => {
        killTerminal(id);
        res.status(204).end();
      });
    } catch (err) {
      res.status(404).json({ error: err.message });
    }
    return;
  }

  res.setHeader('Allow', ['GET', 'DELETE']);
  res.status(405).end();
}
