import { timingSafeEqual, scryptSync } from 'node:crypto';

const VERIFIER_PATTERN = /^scrypt-v1:([a-f0-9]{32}):([a-f0-9]{64})$/;

function verifyPassword(verifier, password) {
  const match = typeof verifier === 'string' && verifier.match(VERIFIER_PATTERN);
  if (!match || typeof password !== 'string' || !password || Buffer.byteLength(password) > 65536) return false;
  const digest = scryptSync(password, Buffer.from(match[1], 'hex'), 32, { N: 16384, r: 8, p: 1 });
  return timingSafeEqual(digest, Buffer.from(match[2], 'hex'));
}

function parseBoolean(value) {
  if (typeof value !== 'string') {
    return false;
  }
  return ['1', 'true', 'yes', 'on'].includes(value.trim().toLowerCase());
}

function resolveConfig(options = {}) {
  const env = options.env || process.env;
  const enabled = options.enabled === undefined
    ? parseBoolean(env.NOTTY_BASIC_AUTH_ENABLED)
    : Boolean(options.enabled);
  return {
    enabled,
    username: options.username ?? env.NOTTY_BASIC_AUTH_USERNAME ?? '',
    password: options.password ?? env.NOTTY_BASIC_AUTH_PASSWORD ?? '',
    verifier: options.verifier ?? env.NOTTY_BASIC_AUTH_VERIFIER ?? '',
    realm: options.realm ?? env.NOTTY_BASIC_AUTH_REALM ?? 'notty'
  };
}

function isConfigured(config) {
  return config.enabled && Boolean(config.username)
    && (config.verifier ? VERIFIER_PATTERN.test(config.verifier) : Boolean(config.password));
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
  if (typeof header !== 'string') {
    return null;
  }

  const match = header.match(/^Basic\s+([^\s]+)$/i);
  if (!match) {
    return null;
  }

  try {
    const decoded = Buffer.from(match[1], 'base64').toString('utf8');
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

export function getHttpBasicAuthInfo(options = {}) {
  const config = resolveConfig(options);
  return {
    enabled: config.enabled,
    configured: isConfigured(config),
    username: config.enabled && config.username ? config.username : null,
    realm: config.realm
  };
}

export function validateHttpBasicAuthRequest(req, options = {}) {
  const config = resolveConfig(options);
  if (!config.enabled) {
    return { ok: true, code: 'disabled' };
  }

  if (!isConfigured(config)) {
    return { ok: false, code: 'misconfigured' };
  }

  const credentials = parseBasicHeader(req.headers.authorization);
  if (!credentials) {
    return { ok: false, code: 'missing' };
  }

  if (
    !safeEquals(config.username, credentials.username)
    || !(config.verifier
      ? verifyPassword(config.verifier, credentials.password)
      : safeEquals(config.password, credentials.password))
  ) {
    return { ok: false, code: 'invalid' };
  }

  return { ok: true, code: 'valid', subject: credentials.username };
}

export function writeHttpBasicAuthChallenge(res, { socket = false, realm } = {}) {
  const resolvedRealm = realm ?? process.env.NOTTY_BASIC_AUTH_REALM ?? 'notty';
  const escapedRealm = String(resolvedRealm).replaceAll('"', '\\"');
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

export function getHttpBasicAuthMiddleware(options = {}) {
  return function httpBasicAuthMiddleware(req, res, next) {
    const config = resolveConfig(options);
    if (!config.enabled || req.method === 'OPTIONS') {
      next();
      return;
    }

    const result = validateHttpBasicAuthRequest(req, config);
    if (result.ok) {
      req.nottyBasicAuth = {
        subject: result.subject || config.username,
        realm: config.realm
      };
      next();
      return;
    }

    if (result.code === 'misconfigured') {
      res.status(503).type('text/plain').send('HTTP basic auth is enabled but not configured');
      return;
    }

    writeHttpBasicAuthChallenge(res, { realm: config.realm });
  };
}

export { resolveConfig as resolveHttpBasicAuthConfig };
