import { createSpawnOtp, getSpawnOtpDashboard } from '../../lib/mcpSpawnOtp.js';
import { getHttpProtocol, getRequestIpInfo, withLogContext } from '../../lib/terminalLogging.js';
import {
  isTerminalLockdownEnabled,
  sendTerminalLockdownResponse
} from '../../lib/lockdown.js';

function withHttpContext(req, route, fn) {
  const protocol = getHttpProtocol(req);
  const { sourceIp, forwardedFor } = getRequestIpInfo(req);
  return withLogContext(
    {
      protocol,
      transport: 'http',
      source: 'nextApiSpawnOtps',
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
    withHttpContext(req, 'GET /api/spawn-otps', () => {
      res.status(200).json(getSpawnOtpDashboard());
    });
    return;
  }

  if (req.method === 'POST') {
    try {
      withHttpContext(req, 'POST /api/spawn-otps', () => {
        const otp = createSpawnOtp(req.body || {});
        res.status(201).json({
          otp,
          dashboard: getSpawnOtpDashboard()
        });
      });
    } catch (err) {
      const message = err instanceof Error ? err.message : 'Failed to create spawn OTP.';
      const status = message === 'Spawn OTP value already exists.' ? 409 : 400;
      res.status(status).json({ error: message });
    }
    return;
  }

  res.setHeader('Allow', ['GET', 'POST']);
  res.status(405).end();
}
