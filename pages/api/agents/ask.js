import { askAgents } from '../../../lib/agentManager.js';
import { getHttpProtocol, getRequestIpInfo, withLogContext } from '../../../lib/terminalLogging.js';
import {
  isTerminalLockdownEnabled,
  sendTerminalLockdownResponse
} from '../../../lib/lockdown.js';

function withHttpContext(req, route, fn) {
  const protocol = getHttpProtocol(req);
  const { sourceIp, forwardedFor } = getRequestIpInfo(req);
  return withLogContext(
    {
      protocol,
      transport: 'http',
      source: 'nextApiAgents',
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

  try {
    withHttpContext(req, 'POST /api/agents/ask', () => {
      const result = askAgents(req.body || {});
      res.status(202).json(result);
    });
  } catch (err) {
    res.status(400).json({ error: err.message || 'Unknown error' });
  }
}
