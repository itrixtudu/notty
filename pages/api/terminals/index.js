import {
  listTerminals,
  spawnTerminal
} from '../../../lib/terminalManager.js';
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
      source: 'nextApiTerminals',
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
    withHttpContext(req, 'GET /api/terminals', () => {
      res.status(200).json({ sessions: listTerminals() });
    });
    return;
  }

  if (req.method === 'POST') {
    withHttpContext(req, 'POST /api/terminals', () => {
      const options = req.body || {};
      // Default to 'xterm' for web/websocket connections
      if (!options.terminalType) {
        options.terminalType = 'xterm';
      }
      const session = spawnTerminal(options);
      res.status(201).json({ session });
    });
    return;
  }

  res.setHeader('Allow', ['GET', 'POST']);
  res.status(405).end();
}
