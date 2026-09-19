import {
  listTerminals,
  spawnTerminal
} from '../../../lib/terminalManager.js';
import { getHttpProtocol, getRequestIpInfo, withLogContext } from '../../../lib/terminalLogging.js';
import {
  isTerminalLockdownEnabled,
  sendTerminalLockdownResponse
} from '../../../lib/lockdown.js';
import { isJsonRequest } from '../../../lib/httpContentType.js';

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
    if (!isJsonRequest(req)) {
      res.status(415).json({
        error: {
          code: 'terminal_spawn_json_required',
          message: 'Terminal spawn requests require a JSON body.'
        }
      });
      return;
    }
    try {
      withHttpContext(req, 'POST /api/terminals', () => {
        const options = { ...(req.body || {}) };
        // Default to 'xterm' for web/websocket connections
        if (!options.terminalType) {
          options.terminalType = 'xterm';
        }
        const session = spawnTerminal(options);
        res.status(201).json({ session });
      });
    } catch (error) {
      const status = Number.isInteger(error?.statusCode) ? error.statusCode : 400;
      res.status(status).json({
        error: {
          code: error?.code || 'terminal_spawn_invalid',
          message: error?.message || 'Unknown error'
        }
      });
    }
    return;
  }

  res.setHeader('Allow', ['GET', 'POST']);
  res.status(405).end();
}
