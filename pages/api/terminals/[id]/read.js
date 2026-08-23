import { createTerminalReader } from '../../../../lib/terminalManager.js';
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

  try {
    withHttpContext(req, 'POST /api/terminals/:id/read', () => {
      // Create temporary isolated reader for this HTTP request
      const reader = createTerminalReader(id, { includeHistory: true });
      const data = reader.read();
      reader.dispose();
      res.status(200).json({ data });
    });
  } catch (err) {
    res.status(404).json({ error: err.message });
  }
}
