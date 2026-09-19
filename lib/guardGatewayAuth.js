import { timingSafeEqual } from 'node:crypto';
import { isIP } from 'node:net';

export const GUARD_GATEWAY_TOKEN_ENV = 'NOTTY_GUARD_GATEWAY_TOKEN';
export const GUARD_GATEWAY_TOKEN_HEADER = 'x-nosh-guard-gateway-token';
export const GUARD_GATEWAY_PEER_IP_ENV = 'NOTTY_GUARD_GATEWAY_PEER_IP';

const ID_PATTERN = /^[A-Za-z0-9_.:-]{1,200}$/;
const TOKEN_PATTERN = /^[A-Za-z0-9_-]{43}$/;

function enabled(value) {
  return ['1', 'true', 'yes', 'on'].includes(String(value || '').trim().toLowerCase());
}

function scalarHeader(req, name, required = false) {
  const value = req?.headers?.[name];
  if (value === undefined || value === null || value === '') {
    return required ? null : '';
  }
  if (Array.isArray(value) || typeof value !== 'string' || !ID_PATTERN.test(value)) {
    return null;
  }
  return value;
}

function safeEqual(left, right) {
  const expected = Buffer.from(String(left || ''), 'utf8');
  const actual = Buffer.from(String(right || ''), 'utf8');
  return expected.length > 0
    && expected.length === actual.length
    && timingSafeEqual(expected, actual);
}

export function normalizeGuardGatewayPeerIp(value) {
  if (typeof value !== 'string' || !value || value !== value.trim()) {
    return null;
  }
  const version = isIP(value);
  if (version === 4) {
    return value;
  }
  if (version !== 6) {
    return null;
  }

  const dottedMapped = value.match(/^::ffff:(\d{1,3}(?:\.\d{1,3}){3})$/i);
  if (dottedMapped && isIP(dottedMapped[1]) === 4) {
    return dottedMapped[1];
  }

  let normalized;
  try {
    const hostname = new URL(`http://[${value}]/`).hostname;
    normalized = hostname.replace(/^\[|\]$/g, '').toLowerCase();
  } catch {
    return null;
  }

  // Node can report IPv4 connections accepted by an IPv6 socket as an
  // IPv4-mapped address. Compare those requests to the exact IPv4 topology
  // address injected by Guard rather than treating the representation as a
  // distinct peer.
  const mapped = normalized.match(/^::ffff:([0-9a-f]{1,4}):([0-9a-f]{1,4})$/);
  if (mapped) {
    const high = Number.parseInt(mapped[1], 16);
    const low = Number.parseInt(mapped[2], 16);
    return [high >>> 8, high & 0xff, low >>> 8, low & 0xff].join('.');
  }
  return normalized;
}

export function authenticateGuardGatewayRequest(req, env = process.env) {
  if (!enabled(env.NOTTY_GUARD_MTLS)) {
    return { ok: true, guard: false, principal: null };
  }

  const configuredToken = env[GUARD_GATEWAY_TOKEN_ENV];
  const configuredPeer = env[GUARD_GATEWAY_PEER_IP_ENV];
  const expectedPeer = normalizeGuardGatewayPeerIp(configuredPeer);
  if (
    typeof configuredToken !== 'string'
    || !TOKEN_PATTERN.test(configuredToken)
    || expectedPeer === null
    || configuredPeer !== expectedPeer
  ) {
    return { ok: false, guard: true, code: 'guard_gateway_configuration_invalid' };
  }

  const provided = req?.headers?.[GUARD_GATEWAY_TOKEN_HEADER];
  const remotePeer = normalizeGuardGatewayPeerIp(req?.socket?.remoteAddress);
  if (
    Array.isArray(provided)
    || typeof provided !== 'string'
    || !safeEqual(configuredToken, provided)
    || remotePeer === null
    || remotePeer !== expectedPeer
  ) {
    return { ok: false, guard: true, code: 'guard_gateway_auth_required' };
  }

  const principalId = scalarHeader(req, 'x-nosh-guard-principal', true);
  const runId = scalarHeader(req, 'x-nosh-guard-upstream-run', true);
  const agentId = scalarHeader(req, 'x-nosh-guard-agent');
  if (principalId === null || runId === null || agentId === null) {
    return { ok: false, guard: true, code: 'guard_gateway_principal_invalid' };
  }

  return {
    ok: true,
    guard: true,
    principal: Object.freeze({
      kind: 'guard-mtls',
      clientId: runId,
      subject: principalId,
      scope: '',
      resource: '',
      runId,
      agentId: agentId || null
    })
  };
}

export function guardGatewayMiddleware(env = process.env) {
  return (req, res, next) => {
    const result = authenticateGuardGatewayRequest(req, env);
    if (result.ok) {
      if (result.principal) {
        req.nottyAuthPrincipal = result.principal;
      }
      next();
      return;
    }
    const configurationInvalid = result.code === 'guard_gateway_configuration_invalid';
    res.status(configurationInvalid ? 503 : 401).json({
      error: {
        code: result.code,
        message: configurationInvalid
          ? 'Guard gateway authentication is not configured securely.'
          : 'Guard requests must arrive through the authenticated mTLS gateway.'
      }
    });
  };
}

export function isGuardOtpMintRequestAuthorized(req, env = process.env) {
  if (!enabled(env.NOTTY_GUARD_MTLS)) {
    return true;
  }
  const principal = req?.nottyAuthPrincipal;
  if (principal?.kind === 'guard-mtls') {
    return !principal.agentId;
  }
  const result = authenticateGuardGatewayRequest(req, env);
  return result.ok && result.guard && !result.principal.agentId;
}
