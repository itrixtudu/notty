import fs from 'node:fs';
import path from 'node:path';
import { randomBytes, timingSafeEqual } from 'node:crypto';

const OAUTH_ENABLED = (process.env.NOTTY_OAUTH_ENABLED || '').toLowerCase() === 'true';
const CLIENT_ID = process.env.NOTTY_OAUTH_CLIENT_ID || '';
const CLIENT_SECRET = process.env.NOTTY_OAUTH_CLIENT_SECRET || '';
const BOOT_TOKEN = process.env.NOTTY_OAUTH_BOOT_TOKEN || '';
const TOKEN_PATH = process.env.NOTTY_OAUTH_TOKEN_PATH || '';

const ttlSeconds = Number.parseInt(process.env.NOTTY_OAUTH_TTL_SECONDS ?? '', 10);
const TTL_MS = Number.isFinite(ttlSeconds) && ttlSeconds > 0 ? ttlSeconds * 1000 : null;

let tokenState = null;
let tokenLogged = false;

function isConfigured() {
  return OAUTH_ENABLED && Boolean(CLIENT_ID) && Boolean(CLIENT_SECRET);
}

function generateTokenValue() {
  return BOOT_TOKEN || randomBytes(32).toString('base64url');
}

function persistToken(token) {
  if (!TOKEN_PATH) {
    return;
  }

  try {
    fs.mkdirSync(path.dirname(TOKEN_PATH), { recursive: true });
    fs.writeFileSync(TOKEN_PATH, `${token}\n`, { mode: 0o600, encoding: 'utf8' });
  } catch (err) {
    console.error('[auth] Failed to write token to disk:', err);
  }
}

function logToken(state) {
  if (tokenLogged) {
    return;
  }

  tokenLogged = true;
  const expiresIn = state.expiresAt ? Math.max(0, state.expiresAt - Date.now()) : null;
  const expiresMsg = expiresIn ? ` (expires in ${Math.round(expiresIn / 1000)}s)` : '';
  console.error('[auth] OAuth bearer token issued:', state.token, expiresMsg);
  if (TOKEN_PATH) {
    console.error('[auth] Token also written to:', TOKEN_PATH);
  }
}

function ensureTokenState() {
  if (!isConfigured()) {
    return null;
  }

  if (tokenState) {
    return tokenState;
  }

  const createdAt = Date.now();
  const token = generateTokenValue();
  const expiresAt = TTL_MS ? createdAt + TTL_MS : null;

  tokenState = { token, createdAt, expiresAt };
  persistToken(token);
  logToken(tokenState);

  return tokenState;
}

function tokensMatch(expected, provided) {
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

function validateAccessToken(token) {
  if (!isConfigured()) {
    return { ok: false, code: 'misconfigured' };
  }

  const state = ensureTokenState();
  if (!state) {
    return { ok: false, code: 'misconfigured' };
  }

  if (!token) {
    return { ok: false, code: 'missing' };
  }

  if (state.expiresAt && Date.now() > state.expiresAt) {
    return { ok: false, code: 'expired' };
  }

  if (!tokensMatch(state.token, token)) {
    return { ok: false, code: 'invalid' };
  }

  return { ok: true, state };
}

function parseBearerFromHeader(req) {
  const header = req.headers.authorization;
  if (typeof header !== 'string') {
    return null;
  }

  const [scheme, token] = header.split(' ');
  if (!scheme || !token) {
    return null;
  }

  if (scheme.toLowerCase() !== 'bearer') {
    return null;
  }

  return token.trim();
}

function extractBearerToken(req, { allowQueryToken = false } = {}) {
  const headerToken = parseBearerFromHeader(req);
  if (headerToken) {
    return headerToken;
  }

  if (allowQueryToken) {
    const queryTokenParam = req.query?.access_token;
    if (typeof queryTokenParam === 'string' && queryTokenParam) {
      return queryTokenParam;
    }
  }

  return null;
}

function parseBasicCredentials(req) {
  const header = req.headers.authorization;
  if (typeof header === 'string' && header.startsWith('Basic ')) {
    try {
      const decoded = Buffer.from(header.slice(6), 'base64').toString('utf8');
      const separatorIndex = decoded.indexOf(':');
      if (separatorIndex === -1) {
        return null;
      }

      const clientId = decoded.slice(0, separatorIndex);
      const clientSecret = decoded.slice(separatorIndex + 1);
      return { clientId, clientSecret };
    } catch {
      return null;
    }
  }

  const body = req.body || {};
  const clientId = body.client_id || body.clientId;
  const clientSecret = body.client_secret || body.clientSecret;
  if (typeof clientId === 'string' && typeof clientSecret === 'string') {
    return { clientId, clientSecret };
  }

  return null;
}

export function isAuthEnabled() {
  return OAUTH_ENABLED;
}

export function getCurrentToken() {
  return ensureTokenState()?.token || null;
}

export function getPublicTokenInfo({ eager = true } = {}) {
  const state = eager ? ensureTokenState() : tokenState;
  return {
    enabled: OAUTH_ENABLED,
    configured: isConfigured(),
    createdAt: state?.createdAt || null,
    expiresAt: state?.expiresAt || null,
    ttlSeconds: TTL_MS ? TTL_MS / 1000 : null
  };
}

export function getAuthMiddleware(options = {}) {
  const allowQueryToken = Boolean(options.allowQueryToken);

  return function authMiddleware(req, res, next) {
    if (!OAUTH_ENABLED) {
      next();
      return;
    }

    if (req.method === 'OPTIONS') {
      next();
      return;
    }

    const result = validateAccessToken(extractBearerToken(req, { allowQueryToken }));
    if (result.ok) {
      next();
      return;
    }

    const status = result.code === 'misconfigured' ? 503 : 401;
    const detail =
      result.code === 'misconfigured'
        ? 'OAuth shim enabled but credentials are not configured'
        : result.code === 'expired'
          ? 'Bearer token expired; restart the service to mint a new one'
          : 'Bearer token is missing or invalid';

    res.setHeader('WWW-Authenticate', 'Bearer realm="notty"');
    res.status(status).json({ error: 'invalid_token', detail });
  };
}

export function createTokenHandler() {
  return function tokenHandler(req, res) {
    if (!OAUTH_ENABLED) {
      res.status(404).json({ error: 'unsupported', detail: 'OAuth shim is disabled' });
      return;
    }

    if (!isConfigured()) {
      res
        .status(503)
        .json({ error: 'server_error', detail: 'Provide NOTTY_OAUTH_CLIENT_ID/SECRET' });
      return;
    }

    const grantType = req.body?.grant_type || req.query?.grant_type || 'client_credentials';
    if (grantType !== 'client_credentials') {
      res
        .status(400)
        .json({ error: 'unsupported_grant_type', detail: 'Only client_credentials is supported' });
      return;
    }

    const credentials = parseBasicCredentials(req);
    if (!credentials) {
      res.setHeader('WWW-Authenticate', 'Basic realm="notty"');
      res
        .status(401)
        .json({ error: 'invalid_client', detail: 'Client credentials are required' });
      return;
    }

    if (credentials.clientId !== CLIENT_ID || credentials.clientSecret !== CLIENT_SECRET) {
      res.setHeader('WWW-Authenticate', 'Basic realm="notty"');
      res
        .status(401)
        .json({ error: 'invalid_client', detail: 'Client credentials rejected' });
      return;
    }

    const state = ensureTokenState();
    if (!state) {
      res
        .status(503)
        .json({ error: 'server_error', detail: 'Token is unavailable; check configuration' });
      return;
    }

    const response = {
      access_token: state.token,
      token_type: 'Bearer',
      issued_at: Math.floor(state.createdAt / 1000)
    };

    if (state.expiresAt) {
      response.expires_in = Math.max(0, Math.floor((state.expiresAt - Date.now()) / 1000));
    }

    res.setHeader('Cache-Control', 'no-store');
    res.setHeader('Pragma', 'no-cache');
    res.json(response);
  };
}
