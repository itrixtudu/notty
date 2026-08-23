import { writeToTerminal } from '../../../../lib/terminalManager.js';
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

  const data = req.body?.data ?? '';
  if (typeof data !== 'string') {
    res.status(400).json({ error: 'data must be a string' });
    return;
  }

  try {
    withHttpContext(req, 'POST /api/terminals/:id/write', () => {
      const bytesWritten = writeToTerminal(id, data, { actor: 'human' });
      res.status(200).json({ bytesWritten });
    });
  } catch (err) {
    res.status(404).json({ error: err.message });
  }
}
