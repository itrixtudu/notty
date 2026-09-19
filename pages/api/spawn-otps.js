import { createSpawnOtp, getSpawnOtpDashboard } from '../../lib/mcpSpawnOtp.js';
import { resolveAuthMode } from '../../lib/authMode.js';
import { isGuardOtpMintRequestAuthorized } from '../../lib/guardGatewayAuth.js';
import { isJsonRequest } from '../../lib/httpContentType.js';
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
      const authMode = resolveAuthMode();
      const dashboard = getSpawnOtpDashboard();
      res.setHeader('Cache-Control', 'no-store');
      res.status(200).json({
        ...dashboard,
        mintingEnabled: dashboard.enabled && !authMode.otpOnly
      });
    });
    return;
  }

  if (req.method === 'POST') {
    res.setHeader('Cache-Control', 'no-store');
    if (!isJsonRequest(req)) {
      res.status(415).json({
        error: {
          code: 'spawn_otp_json_required',
          message: 'Spawn OTP creation requires a JSON body.'
        }
      });
      return;
    }
    try {
      withHttpContext(req, 'POST /api/spawn-otps', () => {
        if (!isGuardOtpMintRequestAuthorized(req)) {
          res.status(403).json({
            error: {
              code: 'spawn_otp_guard_operator_required',
              message: 'Guard spawn OTPs may be minted only through the mTLS gateway.'
            }
          });
          return;
        }
        if (resolveAuthMode().otpOnly) {
          res.status(403).json({
            error: {
              code: 'spawn_otp_http_mint_disabled',
              message: 'HTTP spawn OTP minting is disabled in OTP-only authentication mode.'
            }
          });
          return;
        }
        const otp = createSpawnOtp({
          value: req.body?.value,
          ttlSeconds: req.body?.ttlSeconds,
          // Source labels are server-owned so dashboard metadata can never be
          // abused to reflect an OTP or another request secret.
          source: req.nottyAuthPrincipal?.kind === 'guard-mtls'
            ? 'guard-operator'
            : 'ui'
        });
        res.status(201).json({
          otp,
          dashboard: {
            ...getSpawnOtpDashboard(),
            mintingEnabled: true
          }
        });
      });
    } catch (err) {
      const message = err instanceof Error ? err.message : 'Failed to create spawn OTP.';
      const duplicate = message === 'Spawn OTP value already exists.';
      const invalidRequest = message.startsWith('TTL ');
      const status = Number.isInteger(err?.statusCode)
        ? err.statusCode
        : duplicate
          ? 409
          : invalidRequest
            ? 400
            : 500;
      res.status(status).json({
        error: {
          code: err?.code
            || (duplicate
              ? 'spawn_otp_duplicate'
              : invalidRequest
                ? 'spawn_otp_invalid_request'
                : 'spawn_otp_create_failed'),
          message
        }
      });
    }
    return;
  }

  res.setHeader('Allow', ['GET', 'POST']);
  res.status(405).end();
}
