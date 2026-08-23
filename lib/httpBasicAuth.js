import { timingSafeEqual } from 'node:crypto';

const AUTH_ENABLED = parseBoolean(process.env.NOTTY_BASIC_AUTH_ENABLED);
const USERNAME = process.env.NOTTY_BASIC_AUTH_USERNAME || '';
const PASSWORD = process.env.NOTTY_BASIC_AUTH_PASSWORD || '';
const REALM = process.env.NOTTY_BASIC_AUTH_REALM || 'notty';

function parseBoolean(value) {
  if (typeof value !== 'string') {
    return false;
  }
  return ['1', 'true', 'yes', 'on'].includes(value.trim().toLowerCase());
}

function isConfigured() {
  return AUTH_ENABLED && Boolean(USERNAME) && Boolean(PASSWORD);
}

function safeEquals(expected, provided) {
  if (typeof expected !== 'string' || typeof provided !== 'string') {
    return false;
  }

  const expectedBuf = Buffer.from(expected);
  const providedBuf = Buffer.from(provided);
  if (expectedBuf.length !== providedBuf.length) {
    return false;
  }

  try {
    return timingSafeEqual(expectedBuf, providedBuf);
  } catch {
    return false;
  }
}

function parseBasicHeader(header) {
  if (typeof header !== 'string' || !header.startsWith('Basic ')) {
    return null;
  }

  try {
    const decoded = Buffer.from(header.slice(6), 'base64').toString('utf8');
    const separatorIndex = decoded.indexOf(':');
    if (separatorIndex === -1) {
      return null;
    }

    return {
      username: decoded.slice(0, separatorIndex),
      password: decoded.slice(separatorIndex + 1)
    };
  } catch {
    return null;
  }
}

export function getHttpBasicAuthInfo() {
  return {
    enabled: AUTH_ENABLED,
    configured: isConfigured(),
    username: AUTH_ENABLED && USERNAME ? USERNAME : null,
    realm: REALM
  };
}

export function validateHttpBasicAuthRequest(req) {
  if (!AUTH_ENABLED) {
    return { ok: true, code: 'disabled' };
  }

  if (!isConfigured()) {
    return { ok: false, code: 'misconfigured' };
  }

  const credentials = parseBasicHeader(req.headers.authorization);
  if (!credentials) {
    return { ok: false, code: 'missing' };
  }

  if (!safeEquals(USERNAME, credentials.username) || !safeEquals(PASSWORD, credentials.password)) {
    return { ok: false, code: 'invalid' };
  }

  return { ok: true, code: 'valid' };
}

export function writeHttpBasicAuthChallenge(res, { socket = false } = {}) {
  const escapedRealm = String(REALM).replaceAll('"', '\\"');
  const headers = [
    `WWW-Authenticate: Basic realm="${escapedRealm}", charset="UTF-8"`,
    'Content-Type: text/plain; charset=utf-8'
  ];

  if (socket) {
    res.end(`HTTP/1.1 401 Unauthorized\r\n${headers.join('\r\n')}\r\n\r\nUnauthorized`);
    return;
  }

  res.setHeader('WWW-Authenticate', `Basic realm="${escapedRealm}", charset="UTF-8"`);
  res.status(401).type('text/plain').send('Unauthorized');
}

export function getHttpBasicAuthMiddleware() {
  return function httpBasicAuthMiddleware(req, res, next) {
    if (!AUTH_ENABLED || req.method === 'OPTIONS') {
      next();
      return;
    }

    const result = validateHttpBasicAuthRequest(req);
    if (result.ok) {
      next();
      return;
    }

    if (result.code === 'misconfigured') {
      res.status(503).type('text/plain').send('HTTP basic auth is enabled but not configured');
      return;
    }

    writeHttpBasicAuthChallenge(res);
  };
}
