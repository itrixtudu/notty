import {
  postCopilotMessage,
  readAgentMessages
} from '../../../lib/agentManager.js';
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

  if (req.method === 'GET') {
    withHttpContext(req, 'GET /api/agents/messages', () => {
      res.status(200).json(readAgentMessages(req.query || {}));
    });
    return;
  }

  if (req.method === 'POST') {
    try {
      withHttpContext(req, 'POST /api/agents/messages', () => {
        const message = postCopilotMessage(req.body || {});
        res.status(201).json({ message });
      });
    } catch (err) {
      res.status(400).json({ error: err.message || 'Unknown error' });
    }
    return;
  }

  res.setHeader('Allow', ['GET', 'POST']);
  res.status(405).end();
}
