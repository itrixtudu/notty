import { createHash, randomBytes, randomUUID } from 'node:crypto';
import net from 'node:net';
import express from 'express';
import { closeAuthState, getAuthState, hashAuthSecret } from './authState.js';

export const MCP_OAUTH_SCOPE = 'mcp:tools';
export const AUTHORIZATION_CODE_TTL_SECONDS = 5 * 60;
export const ACCESS_TOKEN_TTL_SECONDS = 60 * 60;
export const REFRESH_TOKEN_TTL_SECONDS = 30 * 24 * 60 * 60;

const AUTHORIZATION_CODE_TTL_MS = AUTHORIZATION_CODE_TTL_SECONDS * 1000;
const ACCESS_TOKEN_TTL_MS = ACCESS_TOKEN_TTL_SECONDS * 1000;
const REFRESH_TOKEN_TTL_MS = REFRESH_TOKEN_TTL_SECONDS * 1000;
const PKCE_VALUE_PATTERN = /^[A-Za-z0-9._~-]{43,128}$/;
const PKCE_CHALLENGE_PATTERN = /^[A-Za-z0-9_-]{43}$/;
const MAX_PARAMETER_LENGTH = 4096;
const RESERVED_REDIRECT_QUERY_PARAMETERS = new Set([
  'code',
  'state',
  'iss',
  'error',
  'error_description',
  'error_uri'
]);

const DEFAULT_PATHS = Object.freeze({
  authorizationServerMetadata: '/.well-known/oauth-authorization-server',
  protectedResourceMetadata: '/.well-known/oauth-protected-resource',
  register: '/register',
  authorize: '/authorize',
  token: '/token',
  revoke: '/revoke',
  legacyToken: '/oauth/token'
});

class OAuthRequestError extends Error {
  constructor(error, description, options = {}) {
    super(description);
    this.name = 'OAuthRequestError';
    this.oauthError = error;
    this.statusCode = options.statusCode || 400;
  }
}

function stripIpv6Brackets(hostname) {
  return String(hostname || '').replace(/^\[|\]$/g, '');
}

export function isLoopbackHostname(hostname) {
  const normalized = stripIpv6Brackets(hostname).replace(/\.$/, '').toLowerCase();
  if (normalized === 'localhost' || normalized.endsWith('.localhost')) {
    return true;
  }
  const family = net.isIP(normalized);
  if (family === 4) {
    const firstOctet = Number.parseInt(normalized.split('.')[0], 10);
    return firstOctet === 127;
  }
  return family === 6 && normalized === '::1';
}

export function normalizeOAuthPublicOrigin(value) {
  if (typeof value !== 'string' || !value.trim()) {
    throw new TypeError('NOTTY_PUBLIC_ORIGIN is required for OAuth');
  }

  const raw = value.trim();
  if (raw !== value) {
    throw new TypeError('NOTTY_PUBLIC_ORIGIN must be an exact HTTP(S) origin');
  }
  let parsed;
  try {
    parsed = new URL(raw);
  } catch {
    throw new TypeError('NOTTY_PUBLIC_ORIGIN must be an exact HTTP(S) origin');
  }

  if (
    !['http:', 'https:'].includes(parsed.protocol)
    || !parsed.hostname
    || parsed.username
    || parsed.password
    || parsed.pathname !== '/'
    || parsed.search
    || parsed.hash
  ) {
    throw new TypeError(
      'NOTTY_PUBLIC_ORIGIN must be an exact origin without credentials, path, query, or fragment'
    );
  }

  if (raw !== parsed.origin) {
    throw new TypeError(`NOTTY_PUBLIC_ORIGIN must be the exact origin ${parsed.origin}`);
  }

  const loopback = isLoopbackHostname(parsed.hostname);
  if (parsed.protocol === 'http:' && !loopback) {
    throw new TypeError('NOTTY_PUBLIC_ORIGIN may use HTTP only for a loopback hostname');
  }

  return Object.freeze({
    origin: parsed.origin,
    protocol: parsed.protocol,
    host: parsed.host,
    hostname: parsed.hostname,
    loopback
  });
}

function normalizeRoutePath(value, label) {
  if (
    typeof value !== 'string'
    || !value.startsWith('/')
    || value.startsWith('//')
    || /[?#\\\u0000-\u0020\u007f]/.test(value)
  ) {
    throw new TypeError(`${label} must be a canonical absolute path`);
  }
  return value;
}

function normalizePaths(value = {}) {
  const paths = {};
  for (const [name, defaultValue] of Object.entries(DEFAULT_PATHS)) {
    paths[name] = normalizeRoutePath(value[name] || defaultValue, `OAuth route ${name}`);
  }
  return Object.freeze(paths);
}

function endpoint(origin, routePath) {
  return new URL(routePath, `${origin}/`).href;
}

function generatedSecret(bytes = 32) {
  return randomBytes(bytes).toString('base64url');
}

function noStore(res) {
  res.setHeader('Cache-Control', 'no-store');
  res.setHeader('Pragma', 'no-cache');
}

export function mountLegacyOAuthTombstone(app, publicOrigin, options = {}) {
  if (!app || typeof app.all !== 'function') {
    throw new TypeError('The legacy OAuth tombstone requires an Express-compatible application');
  }
  const origin = normalizeOAuthPublicOrigin(publicOrigin);
  const routePath = normalizeRoutePath(
    options.path || DEFAULT_PATHS.legacyToken,
    'Legacy OAuth token route'
  );
  const expectedAuthority = origin.host.toLowerCase();
  const authority = options.authorityMiddleware || ((req, res, next) => {
    const requestAuthority = req?.headers?.host;
    if (
      typeof requestAuthority !== 'string'
      || requestAuthority.toLowerCase() !== expectedAuthority
    ) {
      noStore(res);
      res.status(421).type('text/plain').send(
        'Request authority does not match NOTTY_PUBLIC_ORIGIN'
      );
      return;
    }
    next();
  });

  app.all(routePath, authority, (_req, res) => {
    noStore(res);
    res.status(410).json({
      error: 'gone',
      error_description: 'The legacy OAuth token endpoint has been removed'
    });
  });
  return app;
}

function sendOAuthError(res, error, description, statusCode = 400) {
  noStore(res);
  res.status(statusCode).json({
    error,
    ...(description ? { error_description: description } : {})
  });
}

function scalarParameter(source, name, options = {}) {
  const value = source?.[name];
  if (value === undefined || value === null || value === '') {
    if (options.required) {
      throw new OAuthRequestError('invalid_request', `${name} is required`);
    }
    return null;
  }
  if (Array.isArray(value) || typeof value !== 'string') {
    throw new OAuthRequestError('invalid_request', `${name} must occur exactly once`);
  }
  if (value.length > (options.maximumLength || MAX_PARAMETER_LENGTH)) {
    throw new OAuthRequestError('invalid_request', `${name} is too long`);
  }
  return value;
}

function resourceParameter(source) {
  let resource;
  try {
    resource = scalarParameter(source, 'resource');
  } catch (error) {
    if (error instanceof OAuthRequestError) {
      throw new OAuthRequestError('invalid_target', error.message);
    }
    throw error;
  }
  if (resource === null) {
    throw new OAuthRequestError('invalid_target', 'resource is required');
  }
  return resource;
}

function exactStringArray(value, expected, label) {
  if (
    !Array.isArray(value)
    || value.some((entry) => typeof entry !== 'string')
    || new Set(value).size !== value.length
  ) {
    throw new OAuthRequestError('invalid_client_metadata', `${label} must be an array of strings`);
  }
  const actual = [...value].sort();
  const wanted = [...expected].sort();
  if (actual.length !== wanted.length || actual.some((entry, index) => entry !== wanted[index])) {
    throw new OAuthRequestError(
      'invalid_client_metadata',
      `${label} must contain exactly ${expected.join(', ')}`
    );
  }
  return [...value];
}

function validateRedirectUri(value) {
  if (typeof value !== 'string' || !value || value.length > MAX_PARAMETER_LENGTH) {
    throw new OAuthRequestError('invalid_redirect_uri', 'redirect_uris contains an invalid URI');
  }
  let parsed;
  try {
    parsed = new URL(value);
  } catch {
    throw new OAuthRequestError('invalid_redirect_uri', 'redirect_uris must contain absolute URLs');
  }
  const loopback = isLoopbackHostname(parsed.hostname);
  if (
    !parsed.hostname
    || parsed.username
    || parsed.password
    || parsed.hash
    || (parsed.protocol !== 'https:' && !(parsed.protocol === 'http:' && loopback))
  ) {
    throw new OAuthRequestError(
      'invalid_redirect_uri',
      'redirect URIs must use HTTPS or loopback HTTP and must not contain credentials or fragments'
    );
  }
  if ([...parsed.searchParams.keys()].some((name) => (
    RESERVED_REDIRECT_QUERY_PARAMETERS.has(name)
  ))) {
    throw new OAuthRequestError(
      'invalid_redirect_uri',
      'redirect URIs must not contain OAuth response parameters in their query'
    );
  }
  // Redirect URIs are OAuth identifiers, so preserve the client's exact
  // registered string after validating its syntax and transport security.
  return value;
}

function parseStoredJson(value, label) {
  try {
    const parsed = JSON.parse(value);
    if (!Array.isArray(parsed) || parsed.some((entry) => typeof entry !== 'string')) {
      throw new Error('not a string array');
    }
    return parsed;
  } catch (error) {
    throw new Error(`Stored OAuth ${label} is corrupt: ${error.message}`);
  }
}

function clientFromRow(row) {
  if (!row) {
    return null;
  }
  return {
    clientId: row.client_id,
    clientName: row.client_name,
    redirectUris: parseStoredJson(row.redirect_uris_json, 'redirect URIs'),
    grantTypes: parseStoredJson(row.grant_types_json, 'grant types'),
    responseTypes: parseStoredJson(row.response_types_json, 'response types'),
    tokenEndpointAuthMethod: row.token_endpoint_auth_method,
    createdAt: row.created_at,
    revokedAt: row.revoked_at
  };
}

function escapeHtml(value) {
  return String(value)
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;')
    .replaceAll("'", '&#39;');
}

function consentDocument(request, client, actionPath, consentToken) {
  const hidden = [
    ['response_type', request.responseType],
    ['client_id', request.clientId],
    ['redirect_uri', request.redirectUri],
    ['scope', request.scope],
    ['resource', request.resource],
    ['code_challenge', request.codeChallenge],
    ['code_challenge_method', request.codeChallengeMethod],
    ['consent_token', consentToken],
    ...(request.state === null ? [] : [['state', request.state]])
  ].map(([name, value]) => (
    `<input type="hidden" name="${escapeHtml(name)}" value="${escapeHtml(value)}">`
  )).join('\n');

  return `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Authorize ${escapeHtml(client.clientName)}</title>
  <style>
    :root { color-scheme: light dark; font-family: system-ui, sans-serif; }
    body { margin: 0; min-height: 100vh; display: grid; place-items: center; background: #111827; color: #f9fafb; }
    main { width: min(34rem, calc(100% - 2rem)); padding: 2rem; border: 1px solid #374151; border-radius: 1rem; background: #1f2937; }
    code { overflow-wrap: anywhere; }
    .actions { display: flex; gap: .75rem; margin-top: 1.5rem; }
    button { border: 0; border-radius: .5rem; padding: .7rem 1.1rem; cursor: pointer; }
    .allow { background: #16a34a; color: white; }
    .deny { background: #4b5563; color: white; }
  </style>
</head>
<body>
  <main>
    <h1>Authorize MCP access?</h1>
    <p><strong>${escapeHtml(client.clientName)}</strong> is requesting the
      <code>${escapeHtml(request.scope)}</code> scope for:</p>
    <p><code>${escapeHtml(request.resource)}</code></p>
    <form method="post" action="${escapeHtml(actionPath)}">
      ${hidden}
      <div class="actions">
        <button class="allow" type="submit" name="decision" value="allow">Allow</button>
        <button class="deny" type="submit" name="decision" value="deny">Deny</button>
      </div>
    </form>
  </main>
</body>
</html>`;
}

function redirectWithParameters(res, redirectUri, parameters) {
  const destination = new URL(redirectUri);
  for (const [name, value] of Object.entries(parameters)) {
    if (value !== null && value !== undefined) {
      destination.searchParams.set(name, String(value));
    }
  }
  noStore(res);
  res.redirect(302, destination.href);
}

function challengeValue(value) {
  return String(value).replaceAll('\\', '\\\\').replaceAll('"', '\\"');
}

function parseBearerHeader(req) {
  const header = req?.headers?.authorization;
  if (typeof header !== 'string') {
    return null;
  }
  const match = header.match(/^Bearer[ \t]+([^\s,]+)[ \t]*$/i);
  return match ? match[1] : null;
}

function pkceChallenge(verifier) {
  return createHash('sha256').update(verifier, 'ascii').digest('base64url');
}

function normalizeBasicAuth(input = {}) {
  const enabled = Boolean(input.enabled);
  const validate = input.validate || input.validator || input.validateRequest;
  if (enabled && typeof validate !== 'function') {
    throw new TypeError('OAuth Basic consent protection requires a validator');
  }
  return Object.freeze({
    enabled,
    validate,
    challenge: input.challenge || input.writeChallenge || null,
    subject: input.subject || null,
    localSubject: String(input.localSubject || 'local-operator')
  });
}

function asyncRoute(operation, logError) {
  return function oauthAsyncRoute(req, res, next) {
    Promise.resolve(operation(req, res, next)).catch((error) => {
      logError('[oauth] request failed:', error);
      if (!res.headersSent) {
        sendOAuthError(res, 'server_error', 'The authorization server could not complete the request', 500);
      }
    });
  };
}

export class OAuthService {
  constructor(options = {}) {
    this.publicOrigin = normalizeOAuthPublicOrigin(
      options.publicOrigin || process.env.NOTTY_PUBLIC_ORIGIN || ''
    );
    this.paths = normalizePaths(options.paths);
    this.authStateOptions = options.authStateOptions || {};
    this.state = options.state || getAuthState(this.authStateOptions);
    this.ownsState = !options.state;
    this.basicAuth = normalizeBasicAuth(options.basicAuth);
    this.now = typeof options.now === 'function' ? options.now : Date.now;
    this.randomSecret = typeof options.randomSecret === 'function'
      ? options.randomSecret
      : generatedSecret;
    this.logError = typeof options.logError === 'function'
      ? options.logError
      : (...parts) => console.error(...parts);
    this.consentChallenges = new Map();

    if (!this.basicAuth.enabled && !this.publicOrigin.loopback) {
      throw new Error('Basic-free OAuth consent is allowed only for a loopback public origin');
    }

    this.resources = Object.freeze({
      mcp: endpoint(this.publicOrigin.origin, '/mcp'),
      sse: endpoint(this.publicOrigin.origin, '/sse')
    });
    this.resourceSet = new Set(Object.values(this.resources));
  }

  authorizationServerMetadata() {
    return {
      issuer: this.publicOrigin.origin,
      authorization_endpoint: endpoint(this.publicOrigin.origin, this.paths.authorize),
      token_endpoint: endpoint(this.publicOrigin.origin, this.paths.token),
      registration_endpoint: endpoint(this.publicOrigin.origin, this.paths.register),
      revocation_endpoint: endpoint(this.publicOrigin.origin, this.paths.revoke),
      revocation_endpoint_auth_methods_supported: ['none'],
      response_types_supported: ['code'],
      grant_types_supported: ['authorization_code', 'refresh_token'],
      token_endpoint_auth_methods_supported: ['none'],
      code_challenge_methods_supported: ['S256'],
      scopes_supported: [MCP_OAUTH_SCOPE],
      authorization_response_iss_parameter_supported: true
    };
  }

  canonicalResource(resource) {
    if (resource === 'mcp' || resource === '/mcp') {
      return this.resources.mcp;
    }
    if (resource === 'sse' || resource === '/sse') {
      return this.resources.sse;
    }
    if (typeof resource === 'string' && this.resourceSet.has(resource)) {
      return resource;
    }
    throw new TypeError('OAuth resource must identify the configured /mcp or /sse endpoint');
  }

  protectedResourceMetadata(resource) {
    const canonical = this.canonicalResource(resource);
    return {
      resource: canonical,
      authorization_servers: [this.publicOrigin.origin],
      scopes_supported: [MCP_OAUTH_SCOPE],
      bearer_methods_supported: ['header']
    };
  }

  protectedResourceMetadataUrl(resource) {
    const canonical = this.canonicalResource(resource);
    const suffix = canonical === this.resources.mcp ? '/mcp' : '/sse';
    return endpoint(
      this.publicOrigin.origin,
      `${this.paths.protectedResourceMetadata}${suffix}`
    );
  }

  authorityMiddleware() {
    const expectedAuthority = this.publicOrigin.host.toLowerCase();
    return (req, res, next) => {
      const authority = req?.headers?.host;
      if (typeof authority !== 'string' || authority.toLowerCase() !== expectedAuthority) {
        noStore(res);
        res.status(421).type('text/plain').send('Request authority does not match NOTTY_PUBLIC_ORIGIN');
        return;
      }
      next();
    };
  }

  mountPublicRoutes(app, options = {}) {
    if (!app || typeof app.get !== 'function' || typeof app.post !== 'function') {
      throw new TypeError('OAuth routes require an Express-compatible application');
    }
    const jsonParser = options.jsonParser || express.json({ limit: '64kb', type: 'application/json' });
    const formParser = options.formParser || express.urlencoded({ extended: false, limit: '32kb' });
    const authority = options.authorityMiddleware || this.authorityMiddleware();

    if (options.discovery !== false) {
      app.get(this.paths.authorizationServerMetadata, authority, (_req, res) => {
        res.json(this.authorizationServerMetadata());
      });
      app.get(this.paths.protectedResourceMetadata, authority, (_req, res) => {
        res.json(this.protectedResourceMetadata('/mcp'));
      });
      app.get(`${this.paths.protectedResourceMetadata}/mcp`, authority, (_req, res) => {
        res.json(this.protectedResourceMetadata('/mcp'));
      });
      app.get(`${this.paths.protectedResourceMetadata}/sse`, authority, (_req, res) => {
        res.json(this.protectedResourceMetadata('/sse'));
      });
    }

    if (options.protocol !== false) {
      app.post(
        this.paths.register,
        authority,
        jsonParser,
        asyncRoute((req, res) => this.handleRegister(req, res), this.logError)
      );
      app.post(
        this.paths.token,
        authority,
        formParser,
        asyncRoute((req, res) => this.handleToken(req, res), this.logError)
      );
      app.post(
        this.paths.revoke,
        authority,
        formParser,
        asyncRoute((req, res) => this.handleRevoke(req, res), this.logError)
      );
    }

    if (options.legacy !== false) {
      mountLegacyOAuthTombstone(app, this.publicOrigin.origin, {
        path: this.paths.legacyToken,
        authorityMiddleware: authority
      });
    }
    return this;
  }

  authorizeMiddleware() {
    return asyncRoute(async (req, res, next) => {
      if (!this.basicAuth.enabled) {
        req.oauthOperator = { subject: this.basicAuth.localSubject, authentication: 'local' };
        next();
        return;
      }

      const result = await this.basicAuth.validate(req);
      if (result?.ok) {
        let subject = result.subject;
        if (!subject && typeof this.basicAuth.subject === 'function') {
          subject = await this.basicAuth.subject(req, result);
        } else if (!subject && typeof this.basicAuth.subject === 'string') {
          subject = this.basicAuth.subject;
        }
        req.oauthOperator = {
          subject: String(subject || 'basic-operator'),
          authentication: 'basic'
        };
        next();
        return;
      }

      if (result?.code === 'misconfigured') {
        res.status(503).type('text/plain').send('HTTP basic auth is enabled but not configured');
        return;
      }
      if (typeof this.basicAuth.challenge === 'function') {
        await this.basicAuth.challenge(res, req, result);
        return;
      }
      res.setHeader('WWW-Authenticate', 'Basic realm="notty", charset="UTF-8"');
      res.status(401).type('text/plain').send('Unauthorized');
    }, this.logError);
  }

  mountAuthorizeRoute(app, options = {}) {
    const formParser = options.formParser || express.urlencoded({ extended: false, limit: '32kb' });
    const middleware = options.middleware || this.authorizeMiddleware();
    const authority = options.authorityMiddleware || this.authorityMiddleware();
    app.get(
      this.paths.authorize,
      authority,
      middleware,
      asyncRoute((req, res) => this.handleAuthorizeGet(req, res), this.logError)
    );
    app.post(
      this.paths.authorize,
      authority,
      middleware,
      formParser,
      asyncRoute((req, res) => this.handleAuthorizePost(req, res), this.logError)
    );
    return this;
  }

  mount(app, options = {}) {
    this.mountPublicRoutes(app, options.publicRoutes || options);
    this.mountAuthorizeRoute(app, options.authorizeRoute || options);
    return this;
  }

  _activeClient(database, clientId) {
    const row = database.prepare(`
      SELECT client_id, client_name, redirect_uris_json, grant_types_json,
             response_types_json, token_endpoint_auth_method, created_at, revoked_at
      FROM oauth_clients
      WHERE client_id = ? AND revoked_at IS NULL
    `).get(clientId);
    return clientFromRow(row);
  }

  handleRegister(req, res) {
    try {
      const body = req.body;
      if (!body || typeof body !== 'object' || Array.isArray(body)) {
        throw new OAuthRequestError('invalid_client_metadata', 'Registration body must be JSON');
      }
      if (!Array.isArray(body.redirect_uris) || body.redirect_uris.length === 0) {
        throw new OAuthRequestError('invalid_redirect_uri', 'redirect_uris is required');
      }
      if (body.redirect_uris.length > 20) {
        throw new OAuthRequestError('invalid_redirect_uri', 'Too many redirect URIs');
      }
      const redirectUris = body.redirect_uris.map(validateRedirectUri);
      if (new Set(redirectUris).size !== redirectUris.length) {
        throw new OAuthRequestError('invalid_redirect_uri', 'redirect_uris contains duplicates');
      }
      const grantTypes = exactStringArray(
        body.grant_types,
        ['authorization_code', 'refresh_token'],
        'grant_types'
      );
      const responseTypes = exactStringArray(body.response_types, ['code'], 'response_types');
      if (body.token_endpoint_auth_method !== 'none') {
        throw new OAuthRequestError(
          'invalid_client_metadata',
          'token_endpoint_auth_method must be none'
        );
      }
      if (body.client_name !== undefined && typeof body.client_name !== 'string') {
        throw new OAuthRequestError('invalid_client_metadata', 'client_name must be a string');
      }
      const clientName = body.client_name === undefined
        ? 'Dynamic MCP Client'
        : body.client_name.trim();
      if (!clientName || clientName.length > 200) {
        throw new OAuthRequestError('invalid_client_metadata', 'client_name is invalid');
      }

      const clientId = this.randomSecret(24);
      const createdAt = this.now();
      this.state.transaction((database) => {
        database.prepare(`
          INSERT INTO oauth_clients(
            client_id, client_name, redirect_uris_json, grant_types_json,
            response_types_json, token_endpoint_auth_method, created_at, revoked_at
          ) VALUES (?, ?, ?, ?, ?, 'none', ?, NULL)
        `).run(
          clientId,
          clientName,
          JSON.stringify(redirectUris),
          JSON.stringify(grantTypes),
          JSON.stringify(responseTypes),
          createdAt
        );
      });

      noStore(res);
      res.status(201).json({
        client_id: clientId,
        client_id_issued_at: Math.floor(createdAt / 1000),
        client_name: clientName,
        redirect_uris: redirectUris,
        grant_types: grantTypes,
        response_types: responseTypes,
        token_endpoint_auth_method: 'none'
      });
    } catch (error) {
      if (error instanceof OAuthRequestError) {
        sendOAuthError(res, error.oauthError, error.message, error.statusCode);
        return;
      }
      throw error;
    }
  }

  _authorizationRequest(parameters) {
    const clientId = scalarParameter(parameters, 'client_id', { required: true });
    const client = this._activeClient(this.state.database, clientId);
    if (!client) {
      throw new OAuthRequestError('invalid_request', 'client_id is invalid');
    }
    let redirectUri = scalarParameter(parameters, 'redirect_uri');
    if (redirectUri === null) {
      if (client.redirectUris.length !== 1) {
        throw new OAuthRequestError(
          'invalid_request',
          'redirect_uri is required when multiple redirect URIs are registered'
        );
      }
      [redirectUri] = client.redirectUris;
    } else if (!client.redirectUris.includes(redirectUri)) {
      throw new OAuthRequestError('invalid_request', 'client_id or redirect_uri is invalid');
    }

    let state = null;
    try {
      state = scalarParameter(parameters, 'state');
      const responseType = scalarParameter(parameters, 'response_type', { required: true });
      if (responseType !== 'code') {
        throw new OAuthRequestError('unsupported_response_type', 'response_type must be code');
      }
      const scope = scalarParameter(parameters, 'scope');
      if (scope !== MCP_OAUTH_SCOPE) {
        throw new OAuthRequestError('invalid_scope', `scope must be ${MCP_OAUTH_SCOPE}`);
      }
      const resource = resourceParameter(parameters);
      if (!this.resourceSet.has(resource)) {
        throw new OAuthRequestError('invalid_target', 'resource is not an exact protected resource');
      }
      const codeChallenge = scalarParameter(parameters, 'code_challenge', { required: true });
      if (!PKCE_CHALLENGE_PATTERN.test(codeChallenge)) {
        throw new OAuthRequestError('invalid_request', 'code_challenge must be an S256 challenge');
      }
      const codeChallengeMethod = scalarParameter(
        parameters,
        'code_challenge_method',
        { required: true }
      );
      if (codeChallengeMethod !== 'S256') {
        throw new OAuthRequestError('invalid_request', 'code_challenge_method must be S256');
      }
      return {
        client,
        request: {
          responseType,
          clientId,
          redirectUri,
          scope,
          resource,
          codeChallenge,
          codeChallengeMethod,
          state
        }
      };
    } catch (error) {
      if (error instanceof OAuthRequestError) {
        error.redirectUri = redirectUri;
        error.state = state;
      }
      throw error;
    }
  }

  _consentBinding(request, subject) {
    return JSON.stringify([
      request.responseType,
      request.clientId,
      request.redirectUri,
      request.scope,
      request.resource,
      request.codeChallenge,
      request.codeChallengeMethod,
      request.state,
      String(subject || '')
    ]);
  }

  _issueConsentChallenge(request, subject) {
    const now = this.now();
    for (const [hash, challenge] of this.consentChallenges) {
      if (challenge.expiresAt <= now) {
        this.consentChallenges.delete(hash);
      }
    }
    while (this.consentChallenges.size >= 1024) {
      this.consentChallenges.delete(this.consentChallenges.keys().next().value);
    }
    const token = this.randomSecret(24);
    this.consentChallenges.set(hashAuthSecret(token), {
      binding: this._consentBinding(request, subject),
      expiresAt: now + AUTHORIZATION_CODE_TTL_MS
    });
    return token;
  }

  _consumeConsentChallenge(parameters, request, subject) {
    const token = scalarParameter(parameters, 'consent_token', { required: true });
    const tokenHash = hashAuthSecret(token);
    const challenge = this.consentChallenges.get(tokenHash);
    this.consentChallenges.delete(tokenHash);
    if (
      !challenge
      || challenge.expiresAt <= this.now()
      || challenge.binding !== this._consentBinding(request, subject)
    ) {
      throw new OAuthRequestError('invalid_request', 'Consent form is invalid or expired');
    }
  }

  _sendAuthorizationError(res, error) {
    if (error instanceof OAuthRequestError && error.redirectUri) {
      redirectWithParameters(res, error.redirectUri, {
        error: error.oauthError,
        error_description: error.message,
        state: error.state,
        iss: this.publicOrigin.origin
      });
      return;
    }
    if (error instanceof OAuthRequestError) {
      sendOAuthError(res, error.oauthError, error.message, error.statusCode);
      return;
    }
    throw error;
  }

  _authorizationError(error, request) {
    if (error instanceof OAuthRequestError) {
      if (request && !error.redirectUri) {
        error.redirectUri = request.redirectUri;
        error.state = request.state;
      }
      return error;
    }
    if (!request) {
      return error;
    }
    this.logError('[oauth] authorization request failed:', error);
    const wrapped = new OAuthRequestError(
      'server_error',
      'The authorization server could not complete the request'
    );
    wrapped.redirectUri = request.redirectUri;
    wrapped.state = request.state;
    return wrapped;
  }

  handleAuthorizeGet(req, res) {
    let request = null;
    try {
      let client;
      ({ client, request } = this._authorizationRequest(req.query || {}));
      const consentToken = this._issueConsentChallenge(request, req.oauthOperator?.subject);
      noStore(res);
      res.setHeader('Content-Security-Policy', "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'");
      res.setHeader('X-Frame-Options', 'DENY');
      res.status(200).type('html').send(
        consentDocument(request, client, this.paths.authorize, consentToken)
      );
    } catch (error) {
      this._sendAuthorizationError(res, this._authorizationError(error, request));
    }
  }

  handleAuthorizePost(req, res) {
    let request = null;
    try {
      ({ request } = this._authorizationRequest(req.body || {}));
      const fetchSite = String(req.headers?.['sec-fetch-site'] || '').toLowerCase();
      if (fetchSite === 'cross-site' || fetchSite === 'same-site') {
        throw new OAuthRequestError('invalid_request', 'Cross-site consent submission is forbidden');
      }
      this._consumeConsentChallenge(
        req.body || {},
        request,
        req.oauthOperator?.subject
      );
      const decision = scalarParameter(req.body || {}, 'decision', { required: true });
      if (decision === 'deny') {
        redirectWithParameters(res, request.redirectUri, {
          error: 'access_denied',
          error_description: 'The operator denied this authorization request',
          state: request.state,
          iss: this.publicOrigin.origin
        });
        return;
      }
      if (decision !== 'allow') {
        throw new OAuthRequestError('invalid_request', 'decision must be allow or deny');
      }

      const subject = String(req.oauthOperator?.subject || '').trim();
      if (!subject) {
        throw new Error('OAuth consent subject is unavailable');
      }
      const grantId = randomUUID();
      const code = this.randomSecret(32);
      const codeHash = hashAuthSecret(code);
      const createdAt = this.now();
      const expiresAt = createdAt + AUTHORIZATION_CODE_TTL_MS;
      this.state.transaction((database) => {
        if (!this._activeClient(database, request.clientId)) {
          throw new OAuthRequestError('invalid_request', 'OAuth client is no longer active');
        }
        database.prepare(`
          INSERT INTO oauth_grants(
            grant_id, client_id, subject, scope, resource, created_at, revoked_at
          ) VALUES (?, ?, ?, ?, ?, ?, NULL)
        `).run(
          grantId,
          request.clientId,
          subject,
          request.scope,
          request.resource,
          createdAt
        );
        database.prepare(`
          INSERT INTO oauth_authorization_codes(
            code_hash, grant_id, client_id, subject, scope, resource,
            redirect_uri, code_challenge, created_at, expires_at, consumed_at
          ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL)
        `).run(
          codeHash,
          grantId,
          request.clientId,
          subject,
          request.scope,
          request.resource,
          request.redirectUri,
          request.codeChallenge,
          createdAt,
          expiresAt
        );
      });
      redirectWithParameters(res, request.redirectUri, {
        code,
        state: request.state,
        iss: this.publicOrigin.origin
      });
    } catch (error) {
      this._sendAuthorizationError(res, this._authorizationError(error, request));
    }
  }

  _assertPublicClientRequest(req) {
    if (req.headers?.authorization) {
      throw new OAuthRequestError('invalid_client', 'Public clients must not authenticate', {
        statusCode: 401
      });
    }
    if (req.body?.client_secret !== undefined) {
      throw new OAuthRequestError('invalid_client', 'client_secret is not accepted', {
        statusCode: 401
      });
    }
  }

  _issueFamilyTokens(database, principal, now, familyId = randomUUID()) {
    if (!principal.grantId) {
      throw new Error('OAuth refresh family requires an authorization grant');
    }
    const accessToken = this.randomSecret(32);
    const refreshToken = this.randomSecret(32);
    const accessHash = hashAuthSecret(accessToken);
    const refreshHash = hashAuthSecret(refreshToken);
    const familyExpiresAt = now + REFRESH_TOKEN_TTL_MS;

    database.prepare(`
      INSERT INTO oauth_refresh_families(
        family_id, client_id, subject, scope, resource,
        created_at, expires_at, revoked_at, replayed_at, grant_id
      ) VALUES (?, ?, ?, ?, ?, ?, ?, NULL, NULL, ?)
    `).run(
      familyId,
      principal.clientId,
      principal.subject,
      principal.scope,
      principal.resource,
      now,
      familyExpiresAt,
      principal.grantId
    );
    database.prepare(`
      INSERT INTO oauth_refresh_tokens(
        token_hash, family_id, created_at, expires_at,
        consumed_at, revoked_at, replaced_by_hash
      ) VALUES (?, ?, ?, ?, NULL, NULL, NULL)
    `).run(refreshHash, familyId, now, familyExpiresAt);
    database.prepare(`
      INSERT INTO oauth_access_tokens(
        token_hash, family_id, client_id, subject, scope, resource,
        created_at, expires_at, revoked_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, NULL)
    `).run(
      accessHash,
      familyId,
      principal.clientId,
      principal.subject,
      principal.scope,
      principal.resource,
      now,
      now + ACCESS_TOKEN_TTL_MS
    );
    return { accessToken, refreshToken, refreshHash, familyId };
  }

  _tokenResponse(res, tokens, principal) {
    noStore(res);
    res.json({
      access_token: tokens.accessToken,
      token_type: 'Bearer',
      expires_in: ACCESS_TOKEN_TTL_SECONDS,
      refresh_token: tokens.refreshToken,
      scope: principal.scope,
      resource: principal.resource
    });
  }

  handleToken(req, res) {
    try {
      this._assertPublicClientRequest(req);
      const grantType = scalarParameter(req.body || {}, 'grant_type', { required: true });
      if (grantType === 'authorization_code') {
        this._exchangeAuthorizationCode(req, res);
        return;
      }
      if (grantType === 'refresh_token') {
        this._exchangeRefreshToken(req, res);
        return;
      }
      throw new OAuthRequestError(
        'unsupported_grant_type',
        'grant_type must be authorization_code or refresh_token'
      );
    } catch (error) {
      if (error instanceof OAuthRequestError) {
        sendOAuthError(res, error.oauthError, error.message, error.statusCode);
        return;
      }
      throw error;
    }
  }

  _exchangeAuthorizationCode(req, res) {
    const body = req.body || {};
    const code = scalarParameter(body, 'code', { required: true });
    const clientId = scalarParameter(body, 'client_id', { required: true });
    const redirectUri = scalarParameter(body, 'redirect_uri');
    const verifier = scalarParameter(body, 'code_verifier', { required: true });
    const resource = resourceParameter(body);
    const requestedScope = scalarParameter(body, 'scope');
    if (!PKCE_VALUE_PATTERN.test(verifier)) {
      throw new OAuthRequestError('invalid_grant', 'code_verifier is invalid');
    }
    if (!this.resourceSet.has(resource)) {
      throw new OAuthRequestError('invalid_target', 'resource is not an exact protected resource');
    }
    const now = this.now();
    const codeHash = hashAuthSecret(code);
    const result = this.state.transaction((database) => {
      const row = database.prepare(`
        SELECT c.code_hash, c.grant_id, c.client_id, c.subject, c.scope, c.resource,
               c.redirect_uri, c.code_challenge, c.expires_at, c.consumed_at,
               g.revoked_at AS grant_revoked_at, o.revoked_at AS client_revoked_at
        FROM oauth_authorization_codes c
        JOIN oauth_grants g ON g.grant_id = c.grant_id
        JOIN oauth_clients o ON o.client_id = c.client_id
        WHERE c.code_hash = ?
      `).get(codeHash);
      if (
        !row
        || row.expires_at <= now
        || row.grant_revoked_at !== null
        || row.client_revoked_at !== null
        || row.client_id !== clientId
        || (redirectUri !== null && row.redirect_uri !== redirectUri)
        || pkceChallenge(verifier) !== row.code_challenge
      ) {
        return { error: new OAuthRequestError('invalid_grant', 'Authorization code is invalid') };
      }
      if (row.resource !== resource) {
        return {
          error: new OAuthRequestError('invalid_target', 'resource does not match the grant')
        };
      }
      if (requestedScope !== null && requestedScope !== row.scope) {
        return {
          error: new OAuthRequestError('invalid_scope', 'scope does not match the grant')
        };
      }
      if (row.consumed_at !== null) {
        this._revokeGrantFamily(
          database,
          row.grant_id,
          now,
          'authorization_code_replay',
          true
        );
        return {
          error: new OAuthRequestError('invalid_grant', 'Authorization code replay detected')
        };
      }
      const consumed = database.prepare(`
        UPDATE oauth_authorization_codes
        SET consumed_at = ?
        WHERE code_hash = ? AND consumed_at IS NULL
      `).run(now, codeHash);
      if (Number(consumed.changes) !== 1) {
        this._revokeGrantFamily(
          database,
          row.grant_id,
          now,
          'authorization_code_replay',
          true
        );
        return {
          error: new OAuthRequestError('invalid_grant', 'Authorization code replay detected')
        };
      }
      const principal = {
        grantId: row.grant_id,
        clientId: row.client_id,
        subject: row.subject,
        scope: row.scope,
        resource: row.resource
      };
      return {
        principal,
        tokens: this._issueFamilyTokens(database, principal, now)
      };
    });
    if (result.error) {
      throw result.error;
    }
    this._tokenResponse(res, result.tokens, result.principal);
  }

  _revokeGrantFamily(database, grantId, now, reason, replay = false) {
    const family = database.prepare(`
      SELECT family_id
      FROM oauth_refresh_families
      WHERE grant_id = ?
    `).get(grantId);
    if (!family) {
      return false;
    }
    return this._revokeRefreshFamily(database, family.family_id, now, reason, replay);
  }

  _revokeRefreshFamily(database, familyId, now, reason, replay = false) {
    const revoked = database.prepare(`
      UPDATE oauth_refresh_families
      SET revoked_at = ?,
          replayed_at = CASE WHEN ? THEN ? ELSE replayed_at END
      WHERE family_id = ? AND revoked_at IS NULL
    `).run(now, replay ? 1 : 0, now, familyId);
    if (Number(revoked.changes) !== 1) {
      return false;
    }
    database.prepare(`
      UPDATE oauth_grants
      SET revoked_at = COALESCE(revoked_at, ?)
      WHERE grant_id = (
        SELECT grant_id
        FROM oauth_refresh_families
        WHERE family_id = ?
      )
    `).run(now, familyId);
    database.prepare(`
      UPDATE oauth_refresh_tokens
      SET revoked_at = COALESCE(revoked_at, ?)
      WHERE family_id = ?
    `).run(now, familyId);
    database.prepare(`
      UPDATE oauth_access_tokens
      SET revoked_at = COALESCE(revoked_at, ?)
      WHERE family_id = ?
    `).run(now, familyId);
    database.prepare(`
      INSERT INTO auth_revocations(kind, target_id, reason, created_at)
      VALUES ('refresh_family', ?, ?, ?)
    `).run(familyId, reason, now);
    return true;
  }

  _exchangeRefreshToken(req, res) {
    const body = req.body || {};
    const refreshToken = scalarParameter(body, 'refresh_token', { required: true });
    const clientId = scalarParameter(body, 'client_id', { required: true });
    const resource = resourceParameter(body);
    const requestedScope = scalarParameter(body, 'scope');
    if (!this.resourceSet.has(resource)) {
      throw new OAuthRequestError('invalid_target', 'resource is not an exact protected resource');
    }
    const tokenHash = hashAuthSecret(refreshToken);
    const now = this.now();

    const result = this.state.transaction((database) => {
      const row = database.prepare(`
        SELECT t.token_hash, t.family_id, t.expires_at AS token_expires_at,
               t.consumed_at, t.revoked_at AS token_revoked_at,
               f.client_id, f.subject, f.scope, f.resource,
               f.expires_at AS family_expires_at, f.revoked_at AS family_revoked_at,
               f.replayed_at, c.revoked_at AS client_revoked_at,
               g.revoked_at AS grant_revoked_at
        FROM oauth_refresh_tokens t
        JOIN oauth_refresh_families f ON f.family_id = t.family_id
        JOIN oauth_clients c ON c.client_id = f.client_id
        JOIN oauth_grants g ON g.grant_id = f.grant_id
        WHERE t.token_hash = ?
      `).get(tokenHash);

      if (!row || row.client_id !== clientId) {
        return { error: new OAuthRequestError('invalid_grant', 'Refresh token is invalid') };
      }
      if (
        row.family_revoked_at !== null
        || row.replayed_at !== null
        || row.client_revoked_at !== null
        || row.grant_revoked_at !== null
      ) {
        return { error: new OAuthRequestError('invalid_grant', 'Refresh token is expired or revoked') };
      }
      if (row.consumed_at !== null) {
        this._revokeRefreshFamily(database, row.family_id, now, 'refresh_token_replay', true);
        return { error: new OAuthRequestError('invalid_grant', 'Refresh token replay detected') };
      }
      if (
        row.token_revoked_at !== null
        || row.token_expires_at <= now
        || row.family_expires_at <= now
      ) {
        return { error: new OAuthRequestError('invalid_grant', 'Refresh token is expired or revoked') };
      }
      if (row.resource !== resource) {
        return { error: new OAuthRequestError('invalid_target', 'resource does not match the grant') };
      }
      if (requestedScope !== null && requestedScope !== row.scope) {
        return { error: new OAuthRequestError('invalid_scope', 'scope does not match the grant') };
      }

      const principal = {
        clientId: row.client_id,
        subject: row.subject,
        scope: row.scope,
        resource: row.resource
      };
      const accessToken = this.randomSecret(32);
      const nextRefreshToken = this.randomSecret(32);
      const accessHash = hashAuthSecret(accessToken);
      const nextRefreshHash = hashAuthSecret(nextRefreshToken);
      const nextRefreshExpiresAt = now + REFRESH_TOKEN_TTL_MS;
      const consumed = database.prepare(`
        UPDATE oauth_refresh_tokens
        SET consumed_at = ?, replaced_by_hash = ?
        WHERE token_hash = ? AND consumed_at IS NULL AND revoked_at IS NULL
      `).run(now, nextRefreshHash, tokenHash);
      if (Number(consumed.changes) !== 1) {
        this._revokeRefreshFamily(database, row.family_id, now, 'refresh_token_replay', true);
        return { error: new OAuthRequestError('invalid_grant', 'Refresh token replay detected') };
      }
      const extendedFamily = database.prepare(`
        UPDATE oauth_refresh_families
        SET expires_at = ?
        WHERE family_id = ? AND revoked_at IS NULL AND replayed_at IS NULL
      `).run(nextRefreshExpiresAt, row.family_id);
      if (Number(extendedFamily.changes) !== 1) {
        return {
          error: new OAuthRequestError('invalid_grant', 'Refresh token is expired or revoked')
        };
      }
      database.prepare(`
        INSERT INTO oauth_refresh_tokens(
          token_hash, family_id, created_at, expires_at,
          consumed_at, revoked_at, replaced_by_hash
        ) VALUES (?, ?, ?, ?, NULL, NULL, NULL)
      `).run(nextRefreshHash, row.family_id, now, nextRefreshExpiresAt);
      database.prepare(`
        INSERT INTO oauth_access_tokens(
          token_hash, family_id, client_id, subject, scope, resource,
          created_at, expires_at, revoked_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, NULL)
      `).run(
        accessHash,
        row.family_id,
        principal.clientId,
        principal.subject,
        principal.scope,
        principal.resource,
        now,
        now + ACCESS_TOKEN_TTL_MS
      );
      return {
        principal,
        tokens: {
          accessToken,
          refreshToken: nextRefreshToken,
          refreshHash: nextRefreshHash,
          familyId: row.family_id
        }
      };
    });

    if (result.error) {
      throw result.error;
    }
    this._tokenResponse(res, result.tokens, result.principal);
  }

  _validateBearer(req, resource) {
    let canonical;
    try {
      canonical = this.canonicalResource(resource);
    } catch (error) {
      return { ok: false, error: 'invalid_token', description: error.message, resource: null };
    }
    if (req?.query?.access_token !== undefined) {
      return {
        ok: false,
        error: 'invalid_token',
        description: 'Bearer tokens are accepted only in the Authorization header',
        resource: canonical
      };
    }
    const token = parseBearerHeader(req);
    if (!token) {
      return {
        ok: false,
        error: 'invalid_token',
        description: 'Bearer token is missing or malformed',
        resource: canonical
      };
    }
    const tokenHash = hashAuthSecret(token);
    const now = this.now();
    const row = this.state.database.prepare(`
      SELECT a.client_id, a.subject, a.scope, a.resource, a.expires_at,
             a.revoked_at, c.revoked_at AS client_revoked_at,
             f.revoked_at AS family_revoked_at, f.replayed_at,
             g.revoked_at AS grant_revoked_at
      FROM oauth_access_tokens a
      JOIN oauth_clients c ON c.client_id = a.client_id
      JOIN oauth_refresh_families f ON f.family_id = a.family_id
      JOIN oauth_grants g ON g.grant_id = f.grant_id
      WHERE a.token_hash = ?
    `).get(tokenHash);
    if (
      !row
      || row.revoked_at !== null
      || row.client_revoked_at !== null
      || row.family_revoked_at !== null
      || row.replayed_at !== null
      || row.grant_revoked_at !== null
      || row.expires_at <= now
      || row.resource !== canonical
    ) {
      return {
        ok: false,
        error: 'invalid_token',
        description: 'Bearer token is expired, revoked, or has the wrong resource',
        resource: canonical
      };
    }
    if (row.scope !== MCP_OAUTH_SCOPE) {
      return {
        ok: false,
        error: 'insufficient_scope',
        description: `Bearer token does not grant ${MCP_OAUTH_SCOPE}`,
        resource: canonical
      };
    }
    return {
      ok: true,
      principal: {
        clientId: row.client_id,
        subject: row.subject,
        scope: row.scope,
        resource: row.resource
      },
      resource: canonical
    };
  }

  authenticateBearer(req, resource) {
    const result = this._validateBearer(req, resource);
    return result.ok ? result.principal : null;
  }

  bearerMiddleware(resource) {
    const canonical = this.canonicalResource(resource);
    return (req, res, next) => {
      if (req.method === 'OPTIONS') {
        next();
        return;
      }
      const result = this._validateBearer(req, canonical);
      if (result.ok) {
        req.auth = result.principal;
        req.oauthPrincipal = result.principal;
        next();
        return;
      }
      const challenge = [
        'Bearer realm="notty"',
        `resource_metadata="${challengeValue(this.protectedResourceMetadataUrl(canonical))}"`,
        `scope="${MCP_OAUTH_SCOPE}"`,
        `error="${challengeValue(result.error)}"`,
        `error_description="${challengeValue(result.description)}"`
      ].join(', ');
      res.setHeader('WWW-Authenticate', challenge);
      sendOAuthError(
        res,
        result.error,
        result.description,
        result.error === 'insufficient_scope' ? 403 : 401
      );
    };
  }

  handleRevoke(req, res) {
    try {
      this._assertPublicClientRequest(req);
      const token = scalarParameter(req.body || {}, 'token', { required: true });
      const clientId = scalarParameter(req.body || {}, 'client_id');
      if (clientId === null) {
        throw new OAuthRequestError('invalid_client', 'client_id is required', {
          statusCode: 401
        });
      }
      const tokenHash = hashAuthSecret(token);
      const now = this.now();
      const result = this.state.transaction((database) => {
        if (!this._activeClient(database, clientId)) {
          return {
            error: new OAuthRequestError('invalid_client', 'client_id is invalid or revoked', {
              statusCode: 401
            })
          };
        }
        const refresh = database.prepare(`
          SELECT t.family_id, f.client_id
          FROM oauth_refresh_tokens t
          JOIN oauth_refresh_families f ON f.family_id = t.family_id
          WHERE t.token_hash = ?
        `).get(tokenHash);
        if (refresh && clientId === refresh.client_id) {
          this._revokeRefreshFamily(database, refresh.family_id, now, 'token_revocation', false);
          return {};
        }
        const access = database.prepare(`
          SELECT client_id FROM oauth_access_tokens WHERE token_hash = ?
        `).get(tokenHash);
        if (access && clientId === access.client_id) {
          const revoked = database.prepare(`
            UPDATE oauth_access_tokens
            SET revoked_at = ?
            WHERE token_hash = ? AND revoked_at IS NULL
          `).run(now, tokenHash);
          if (Number(revoked.changes) === 1) {
            database.prepare(`
              INSERT INTO auth_revocations(kind, target_id, reason, created_at)
              VALUES ('access_token', ?, 'token_revocation', ?)
            `).run(tokenHash, now);
          }
        }
        return {};
      });
      if (result.error) {
        throw result.error;
      }
      noStore(res);
      res.status(200).end();
    } catch (error) {
      if (error instanceof OAuthRequestError) {
        sendOAuthError(res, error.oauthError, error.message, error.statusCode);
        return;
      }
      throw error;
    }
  }

  close() {
    if (!this.ownsState) {
      return false;
    }
    const closed = closeAuthState(this.authStateOptions);
    this.ownsState = false;
    return closed;
  }
}

export function createOAuthService(options = {}) {
  return new OAuthService(options);
}

export function mountOAuthRoutes(app, options = {}) {
  const service = options.service || createOAuthService(options);
  service.mount(app, options.mount || {});
  return service;
}

export { DEFAULT_PATHS as OAUTH_DEFAULT_PATHS };
