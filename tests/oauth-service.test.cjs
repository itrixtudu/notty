'use strict';

const assert = require('node:assert/strict');
const { createHash } = require('node:crypto');
const fs = require('node:fs');
const http = require('node:http');
const os = require('node:os');
const path = require('node:path');
const test = require('node:test');

const BASIC_AUTHORIZATION = `Basic ${Buffer.from('alice:consent-secret').toString('base64')}`;
const CODE_VERIFIER = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._~'.slice(0, 64);

function challengeFor(verifier) {
  return createHash('sha256').update(verifier, 'ascii').digest('base64url');
}

function listen(server) {
  return new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', () => {
      server.off('error', reject);
      resolve(server.address());
    });
  });
}

function close(server) {
  return new Promise((resolve) => server.close(() => resolve()));
}

function requestWithAuthority(url, authority) {
  return new Promise((resolve, reject) => {
    const request = http.request(url, {
      headers: { Host: authority }
    }, (response) => {
      const chunks = [];
      response.on('data', (chunk) => chunks.push(chunk));
      response.on('end', () => {
        const body = Buffer.concat(chunks).toString('utf8');
        resolve({
          status: response.statusCode,
          text: async () => body
        });
      });
    });
    request.once('error', reject);
    request.end();
  });
}

function form(values) {
  return new URLSearchParams(
    Object.entries(values).filter(([, value]) => value !== null && value !== undefined)
  );
}

async function json(response) {
  return response.json().catch(() => ({}));
}

async function createFixture(t, options = {}) {
  const express = (await import('express')).default;
  const { AuthStateDatabase } = await import('../lib/authState.js');
  const { createOAuthService } = await import('../lib/oauthService.js');
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'notty-oauth-service-'));
  const workspaceRoot = path.join(root, 'workspace');
  fs.mkdirSync(workspaceRoot, { mode: 0o700 });
  const state = new AuthStateDatabase({
    env: {
      HOME: root,
      XDG_STATE_HOME: root,
      NOTTY_WORKDIR: workspaceRoot
    },
    workspaceRoot
  });
  const app = express();
  const server = http.createServer(app);
  const address = await listen(server);
  const origin = `http://127.0.0.1:${address.port}`;
  let now = options.now ?? Date.UTC(2026, 7, 31, 6, 0, 0);
  const basicEnabled = options.basicEnabled !== false;
  const service = createOAuthService({
    publicOrigin: origin,
    state,
    now: () => now,
    basicAuth: basicEnabled
      ? {
          enabled: true,
          validate(req) {
            return req.headers.authorization === BASIC_AUTHORIZATION
              ? { ok: true, code: 'valid', subject: 'alice' }
              : { ok: false, code: 'missing' };
          },
          challenge(res) {
            res.setHeader('WWW-Authenticate', 'Basic realm="notty", charset="UTF-8"');
            res.status(401).type('text/plain').send('Unauthorized');
          }
        }
      : {
          enabled: false,
          localSubject: 'loopback-operator'
        },
    logError(...parts) {
      if (options.errors) options.errors.push(parts);
    }
  });
  service.mountPublicRoutes(app);
  service.mountAuthorizeRoute(app);
  app.get('/protected/mcp', service.bearerMiddleware('/mcp'), (req, res) => {
    res.json({ principal: req.auth });
  });
  app.get('/protected/sse', service.bearerMiddleware('/sse'), (req, res) => {
    res.json({ principal: req.auth });
  });

  t.after(async () => {
    await close(server);
    state.close();
    fs.rmSync(root, { recursive: true, force: true });
  });

  return {
    origin,
    service,
    state,
    request(target, requestOptions) {
      return fetch(`${origin}${target}`, requestOptions);
    },
    advance(milliseconds) {
      now += milliseconds;
    },
    now() {
      return now;
    }
  };
}

async function registerClient(fixture, overrides = {}) {
  const metadata = {
    client_name: 'Codex test client',
    redirect_uris: [`${fixture.origin}/callback`],
    grant_types: ['authorization_code', 'refresh_token'],
    response_types: ['code'],
    token_endpoint_auth_method: 'none',
    ...overrides
  };
  const response = await fixture.request('/register', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(metadata)
  });
  return { response, body: await json(response), metadata };
}

function authorizationParameters(fixture, client, overrides = {}) {
  return {
    response_type: 'code',
    client_id: client.client_id,
    redirect_uri: client.redirect_uris[0],
    scope: 'mcp:tools',
    resource: `${fixture.origin}/mcp`,
    code_challenge: challengeFor(CODE_VERIFIER),
    code_challenge_method: 'S256',
    state: 'state-from-client',
    ...overrides
  };
}

async function authorize(fixture, client, options = {}) {
  const parameters = authorizationParameters(fixture, client, options.parameters);
  const headers = options.withoutBasic ? {} : { Authorization: BASIC_AUTHORIZATION };
  const consent = await fixture.request(`/authorize?${form(parameters)}`, {
    headers,
    redirect: 'manual'
  });
  const consentText = await consent.text();
  const consentToken = consentText.match(
    /name="consent_token" value="([A-Za-z0-9_-]+)"/
  )?.[1];
  if (options.decision === undefined) {
    assert.equal(consent.status, 200, consentText);
    assert.match(consentText, /Authorize MCP access/);
    assert.match(consentText, /name="decision" value="allow"/);
    assert.match(consentText, /name="decision" value="deny"/);
    assert.ok(consentToken, 'consent form must contain a one-time challenge');
  }

  const decision = await fixture.request('/authorize', {
    method: 'POST',
    headers: {
      ...headers,
      'Content-Type': 'application/x-www-form-urlencoded'
    },
    body: form({
      ...parameters,
      consent_token: consentToken,
      decision: options.decision || 'allow'
    }),
    redirect: 'manual'
  });
  const location = new URL(decision.headers.get('location'));
  return {
    consent,
    consentText,
    decision,
    location,
    code: location.searchParams.get('code'),
    parameters
  };
}

async function exchangeCode(fixture, client, authorization, overrides = {}) {
  const response = await fixture.request('/token', {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: form({
      grant_type: 'authorization_code',
      client_id: client.client_id,
      code: authorization.code,
      redirect_uri: client.redirect_uris[0],
      code_verifier: CODE_VERIFIER,
      resource: authorization.parameters.resource,
      ...overrides
    })
  });
  return { response, body: await json(response) };
}

async function issueTokens(fixture) {
  const registration = await registerClient(fixture);
  assert.equal(registration.response.status, 201, JSON.stringify(registration.body));
  const authorization = await authorize(fixture, registration.body);
  assert.equal(authorization.decision.status, 302);
  assert.ok(authorization.code);
  const exchange = await exchangeCode(fixture, registration.body, authorization);
  assert.equal(exchange.response.status, 200, JSON.stringify(exchange.body));
  return {
    client: registration.body,
    authorization,
    tokens: exchange.body
  };
}

async function refresh(fixture, client, refreshToken, resource, overrides = {}) {
  const response = await fixture.request('/token', {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: form({
      grant_type: 'refresh_token',
      client_id: client.client_id,
      refresh_token: refreshToken,
      resource,
      ...overrides
    })
  });
  return { response, body: await json(response) };
}

test('public origin, metadata, protected resources, and DCR are exact and public', async (t) => {
  const {
    createOAuthService,
    normalizeOAuthPublicOrigin
  } = await import('../lib/oauthService.js');

  assert.equal(normalizeOAuthPublicOrigin('http://localhost:3111').origin, 'http://localhost:3111');
  assert.equal(normalizeOAuthPublicOrigin('https://notty.example').origin, 'https://notty.example');
  for (const invalid of [
    '',
    'http://notty.example',
    ' https://notty.example',
    'https://notty.example/',
    'https://user@notty.example',
    'https://notty.example/path',
    'https://notty.example?query=1',
    'https://notty.example#fragment'
  ]) {
    assert.throws(() => normalizeOAuthPublicOrigin(invalid), /PUBLIC_ORIGIN|exact origin|loopback/);
  }
  assert.throws(
    () => createOAuthService({
      publicOrigin: 'https://notty.example',
      state: {},
      basicAuth: { enabled: false }
    }),
    /loopback public origin/
  );

  const fixture = await createFixture(t);
  const asResponse = await fixture.request('/.well-known/oauth-authorization-server');
  assert.equal(asResponse.status, 200);
  assert.deepEqual(await asResponse.json(), {
    issuer: fixture.origin,
    authorization_endpoint: `${fixture.origin}/authorize`,
    token_endpoint: `${fixture.origin}/token`,
    registration_endpoint: `${fixture.origin}/register`,
    revocation_endpoint: `${fixture.origin}/revoke`,
    revocation_endpoint_auth_methods_supported: ['none'],
    response_types_supported: ['code'],
    grant_types_supported: ['authorization_code', 'refresh_token'],
    token_endpoint_auth_methods_supported: ['none'],
    code_challenge_methods_supported: ['S256'],
    scopes_supported: ['mcp:tools'],
    authorization_response_iss_parameter_supported: true
  });

  const rebound = await requestWithAuthority(
    `${fixture.origin}/.well-known/oauth-authorization-server`,
    'attacker.example'
  );
  assert.equal(rebound.status, 421);
  assert.match(await rebound.text(), /authority/i);

  for (const [suffix, resource] of [
    ['/mcp', `${fixture.origin}/mcp`],
    ['/sse', `${fixture.origin}/sse`]
  ]) {
    const response = await fixture.request(`/.well-known/oauth-protected-resource${suffix}`);
    assert.equal(response.status, 200);
    assert.deepEqual(await response.json(), {
      resource,
      authorization_servers: [fixture.origin],
      scopes_supported: ['mcp:tools'],
      bearer_methods_supported: ['header']
    });
  }

  const legacy = await fixture.request('/oauth/token', { redirect: 'manual' });
  assert.equal(legacy.status, 410);

  const registration = await registerClient(fixture, {
    redirect_uris: [
      `${fixture.origin}/callback`,
      'https://client.example/oauth/callback?channel=codex'
    ]
  });
  assert.equal(registration.response.status, 201, JSON.stringify(registration.body));
  assert.match(registration.body.client_id, /^[A-Za-z0-9_-]{32}$/);
  assert.equal(registration.body.client_secret, undefined);
  assert.deepEqual(registration.body.grant_types, ['authorization_code', 'refresh_token']);
  assert.equal(registration.body.token_endpoint_auth_method, 'none');

  const exactRedirect = await registerClient(fixture, {
    redirect_uris: [fixture.origin]
  });
  assert.equal(exactRedirect.response.status, 201, JSON.stringify(exactRedirect.body));
  assert.deepEqual(exactRedirect.body.redirect_uris, [fixture.origin]);
  const exactAuthorization = await authorize(fixture, exactRedirect.body);
  const exactExchange = await exchangeCode(fixture, exactRedirect.body, exactAuthorization);
  assert.equal(exactExchange.response.status, 200, JSON.stringify(exactExchange.body));

  const omittedAuthorization = await authorize(fixture, exactRedirect.body, {
    parameters: { redirect_uri: null }
  });
  assert.equal(omittedAuthorization.decision.status, 302);
  const omittedTokenRedirect = await exchangeCode(
    fixture,
    exactRedirect.body,
    omittedAuthorization,
    { redirect_uri: null }
  );
  assert.equal(
    omittedTokenRedirect.response.status,
    200,
    JSON.stringify(omittedTokenRedirect.body)
  );

  const missingMultiRedirect = await fixture.request(
    `/authorize?${form(authorizationParameters(fixture, registration.body, {
      redirect_uri: null
    }))}`,
    { headers: { Authorization: BASIC_AUTHORIZATION }, redirect: 'manual' }
  );
  assert.equal(missingMultiRedirect.status, 400);
  assert.equal((await missingMultiRedirect.json()).error, 'invalid_request');

  for (const overrides of [
    { redirect_uris: ['http://client.example/callback'] },
    { redirect_uris: ['custom-scheme://callback'] },
    { redirect_uris: [`${fixture.origin}/callback#fragment`] },
    { grant_types: ['authorization_code'] },
    { response_types: ['token'] },
    { token_endpoint_auth_method: 'client_secret_basic' },
    { redirect_uris: ['https://client.example/callback?state=registered'] },
    { client_name: { nested: 'not accepted' } }
  ]) {
    const invalid = await registerClient(fixture, overrides);
    assert.equal(invalid.response.status, 400, JSON.stringify(overrides));
    assert.match(invalid.body.error, /invalid_client_metadata|invalid_redirect_uri/);
  }
});

test('legacy token tombstone remains public when the OAuth service is not mounted', async (t) => {
  const express = (await import('express')).default;
  const { mountLegacyOAuthTombstone } = await import('../lib/oauthService.js');
  const app = express();
  const server = http.createServer(app);
  const address = await listen(server);
  const origin = `http://127.0.0.1:${address.port}`;
  mountLegacyOAuthTombstone(app, origin);
  t.after(() => close(server));

  const response = await fetch(`${origin}/oauth/token`, {
    method: 'POST',
    headers: { Authorization: 'Basic deliberately-not-authenticated' },
    redirect: 'manual'
  });
  assert.equal(response.status, 410);
  assert.deepEqual(await response.json(), {
    error: 'gone',
    error_description: 'The legacy OAuth token endpoint has been removed'
  });

  const rebound = await requestWithAuthority(
    `${origin}/oauth/token`,
    'attacker.example'
  );
  assert.equal(rebound.status, 421);
});

test('Basic consent, PKCE S256, exact scope/resource, hashed tokens, and bearer challenges work', async (t) => {
  const fixture = await createFixture(t);
  const registration = await registerClient(fixture);
  assert.equal(registration.response.status, 201);
  const client = registration.body;

  const unauthenticated = await fixture.request(
    `/authorize?${form(authorizationParameters(fixture, client))}`,
    { redirect: 'manual' }
  );
  assert.equal(unauthenticated.status, 401);
  assert.match(unauthenticated.headers.get('www-authenticate'), /^Basic /);

  const unauthenticatedOversizedPost = await fixture.request('/authorize', {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: `padding=${'x'.repeat(40 * 1024)}`,
    redirect: 'manual'
  });
  assert.equal(unauthenticatedOversizedPost.status, 401);
  assert.match(unauthenticatedOversizedPost.headers.get('www-authenticate'), /^Basic /);

  const wrongResource = await fixture.request(
    `/authorize?${form(authorizationParameters(fixture, client, {
      resource: `${fixture.origin}/mcp/`
    }))}`,
    { headers: { Authorization: BASIC_AUTHORIZATION }, redirect: 'manual' }
  );
  assert.equal(wrongResource.status, 302);
  assert.equal(
    new URL(wrongResource.headers.get('location')).searchParams.get('error'),
    'invalid_target'
  );
  assert.equal(
    new URL(wrongResource.headers.get('location')).searchParams.get('iss'),
    fixture.origin
  );

  for (const [parameters, expectedError] of [
    [{ resource: null }, 'invalid_target'],
    [{ scope: null }, 'invalid_scope']
  ]) {
    const missingParameter = await fixture.request(
      `/authorize?${form(authorizationParameters(fixture, client, parameters))}`,
      { headers: { Authorization: BASIC_AUTHORIZATION }, redirect: 'manual' }
    );
    assert.equal(missingParameter.status, 302);
    assert.equal(
      new URL(missingParameter.headers.get('location')).searchParams.get('error'),
      expectedError
    );
  }

  const denied = await authorize(fixture, client, { decision: 'deny' });
  assert.equal(denied.decision.status, 302);
  assert.equal(denied.location.searchParams.get('error'), 'access_denied');
  assert.equal(denied.location.searchParams.get('state'), 'state-from-client');
  assert.equal(denied.location.searchParams.get('iss'), fixture.origin);
  assert.equal(denied.code, null);

  const authorization = await authorize(fixture, client);
  assert.equal(authorization.decision.status, 302);
  assert.ok(authorization.code);
  assert.equal(authorization.location.searchParams.get('state'), 'state-from-client');
  assert.equal(authorization.location.searchParams.get('iss'), fixture.origin);

  const wrongVerifier = await exchangeCode(fixture, client, authorization, {
    code_verifier: 'Z'.repeat(64)
  });
  assert.equal(wrongVerifier.response.status, 400);
  assert.equal(wrongVerifier.body.error, 'invalid_grant');

  const wrongTokenResource = await exchangeCode(fixture, client, authorization, {
    resource: `${fixture.origin}/sse`
  });
  assert.equal(wrongTokenResource.response.status, 400);
  assert.equal(wrongTokenResource.body.error, 'invalid_target');

  const missingTokenResource = await exchangeCode(fixture, client, authorization, {
    resource: null
  });
  assert.equal(missingTokenResource.response.status, 400);
  assert.equal(missingTokenResource.body.error, 'invalid_target');

  const exchange = await exchangeCode(fixture, client, authorization);
  assert.equal(exchange.response.status, 200, JSON.stringify(exchange.body));
  assert.equal(exchange.body.token_type, 'Bearer');
  assert.equal(exchange.body.expires_in, 3600);
  assert.equal(exchange.body.scope, 'mcp:tools');
  assert.equal(exchange.body.resource, `${fixture.origin}/mcp`);
  assert.ok(exchange.body.access_token);
  assert.ok(exchange.body.refresh_token);

  const storedCode = fixture.state.database.prepare(`
    SELECT code_hash, created_at, expires_at, consumed_at
    FROM oauth_authorization_codes
  `).get();
  assert.notEqual(storedCode.code_hash, authorization.code);
  assert.equal(storedCode.expires_at - storedCode.created_at, 5 * 60 * 1000);
  assert.equal(typeof storedCode.consumed_at, 'number');
  const storedAccess = fixture.state.database.prepare(`
    SELECT token_hash, created_at, expires_at FROM oauth_access_tokens
  `).get();
  assert.notEqual(storedAccess.token_hash, exchange.body.access_token);
  assert.equal(storedAccess.expires_at - storedAccess.created_at, 60 * 60 * 1000);
  const storedRefresh = fixture.state.database.prepare(`
    SELECT token_hash, created_at, expires_at FROM oauth_refresh_tokens
  `).get();
  assert.notEqual(storedRefresh.token_hash, exchange.body.refresh_token);
  assert.equal(storedRefresh.expires_at - storedRefresh.created_at, 30 * 24 * 60 * 60 * 1000);

  const queryOnly = await fixture.request(
    `/protected/mcp?access_token=${encodeURIComponent(exchange.body.access_token)}`
  );
  assert.equal(queryOnly.status, 401);

  const protectedResponse = await fixture.request('/protected/mcp', {
    headers: { Authorization: `Bearer ${exchange.body.access_token}` }
  });
  assert.equal(protectedResponse.status, 200);
  assert.deepEqual(await protectedResponse.json(), {
    principal: {
      clientId: client.client_id,
      subject: 'alice',
      scope: 'mcp:tools',
      resource: `${fixture.origin}/mcp`
    }
  });

  assert.deepEqual(
    fixture.service.authenticateBearer(
      { headers: { authorization: `Bearer ${exchange.body.access_token}` } },
      '/mcp'
    ),
    {
      clientId: client.client_id,
      subject: 'alice',
      scope: 'mcp:tools',
      resource: `${fixture.origin}/mcp`
    }
  );

  const wrongAudience = await fixture.request('/protected/sse', {
    headers: { Authorization: `Bearer ${exchange.body.access_token}` }
  });
  assert.equal(wrongAudience.status, 401);
  assert.match(
    wrongAudience.headers.get('www-authenticate'),
    new RegExp(`resource_metadata="${fixture.origin.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}/\\.well-known/oauth-protected-resource/sse"`)
  );
});

test('authorization-code replay revokes tokens only when every binding is valid', async (t) => {
  const fixture = await createFixture(t);
  const issued = await issueTokens(fixture);
  const assertAccessStatus = async (expectedStatus) => {
    const response = await fixture.request('/protected/mcp', {
      headers: { Authorization: `Bearer ${issued.tokens.access_token}` }
    });
    assert.equal(response.status, expectedStatus);
  };

  const wrongVerifier = await exchangeCode(
    fixture,
    issued.client,
    issued.authorization,
    { code_verifier: 'Z'.repeat(64) }
  );
  assert.equal(wrongVerifier.response.status, 400);
  assert.equal(wrongVerifier.body.error, 'invalid_grant');
  await assertAccessStatus(200);

  const otherRegistration = await registerClient(fixture);
  assert.equal(otherRegistration.response.status, 201);
  const wrongClient = await exchangeCode(
    fixture,
    otherRegistration.body,
    issued.authorization
  );
  assert.equal(wrongClient.response.status, 400);
  assert.equal(wrongClient.body.error, 'invalid_grant');
  await assertAccessStatus(200);

  const wrongResource = await exchangeCode(
    fixture,
    issued.client,
    issued.authorization,
    { resource: `${fixture.origin}/sse` }
  );
  assert.equal(wrongResource.response.status, 400);
  assert.equal(wrongResource.body.error, 'invalid_target');
  await assertAccessStatus(200);

  const validReplay = await exchangeCode(fixture, issued.client, issued.authorization);
  assert.equal(validReplay.response.status, 400);
  assert.equal(validReplay.body.error, 'invalid_grant');
  assert.match(validReplay.body.error_description, /replay/i);
  await assertAccessStatus(401);

  const revokedRefresh = await refresh(
    fixture,
    issued.client,
    issued.tokens.refresh_token,
    issued.tokens.resource
  );
  assert.equal(revokedRefresh.response.status, 400);
  assert.equal(revokedRefresh.body.error, 'invalid_grant');

  const family = fixture.state.database.prepare(`
    SELECT grant_id, revoked_at, replayed_at
    FROM oauth_refresh_families
  `).get();
  assert.ok(family.grant_id);
  assert.equal(typeof family.revoked_at, 'number');
  assert.equal(typeof family.replayed_at, 'number');
  assert.equal(
    typeof fixture.state.database.prepare(`
      SELECT revoked_at
      FROM oauth_grants
      WHERE grant_id = ?
    `).get(family.grant_id).revoked_at,
    'number'
  );
  assert.equal(
    fixture.state.database.prepare(`
      SELECT COUNT(*) AS count
      FROM auth_revocations
      WHERE kind = 'refresh_family' AND reason = 'authorization_code_replay'
    `).get().count,
    1
  );
});

test('an expired consumed code is invalid without becoming a revocation oracle', async (t) => {
  const fixture = await createFixture(t);
  const issued = await issueTokens(fixture);
  fixture.advance(5 * 60 * 1000 + 1);

  const expiredReplay = await exchangeCode(fixture, issued.client, issued.authorization);
  assert.equal(expiredReplay.response.status, 400);
  assert.equal(expiredReplay.body.error, 'invalid_grant');

  const access = await fixture.request('/protected/mcp', {
    headers: { Authorization: `Bearer ${issued.tokens.access_token}` }
  });
  assert.equal(access.status, 200);
  const family = fixture.state.database.prepare(`
    SELECT revoked_at, replayed_at
    FROM oauth_refresh_families
  `).get();
  assert.equal(family.revoked_at, null);
  assert.equal(family.replayed_at, null);
});

test('refresh rotation detects replay and transactionally revokes the whole family', async (t) => {
  const fixture = await createFixture(t);
  const issued = await issueTokens(fixture);
  const missingResource = await refresh(
    fixture,
    issued.client,
    issued.tokens.refresh_token,
    null
  );
  assert.equal(missingResource.response.status, 400);
  assert.equal(missingResource.body.error, 'invalid_target');
  const rotated = await refresh(
    fixture,
    issued.client,
    issued.tokens.refresh_token,
    issued.tokens.resource
  );
  assert.equal(rotated.response.status, 200, JSON.stringify(rotated.body));
  assert.notEqual(rotated.body.refresh_token, issued.tokens.refresh_token);
  assert.notEqual(rotated.body.access_token, issued.tokens.access_token);

  const beforeReplay = await fixture.request('/protected/mcp', {
    headers: { Authorization: `Bearer ${rotated.body.access_token}` }
  });
  assert.equal(beforeReplay.status, 200);

  const replay = await refresh(
    fixture,
    issued.client,
    issued.tokens.refresh_token,
    issued.tokens.resource
  );
  assert.equal(replay.response.status, 400);
  assert.equal(replay.body.error, 'invalid_grant');
  assert.match(replay.body.error_description, /replay/i);

  for (const accessToken of [issued.tokens.access_token, rotated.body.access_token]) {
    const response = await fixture.request('/protected/mcp', {
      headers: { Authorization: `Bearer ${accessToken}` }
    });
    assert.equal(response.status, 401);
  }
  const successor = await refresh(
    fixture,
    issued.client,
    rotated.body.refresh_token,
    issued.tokens.resource
  );
  assert.equal(successor.response.status, 400);
  assert.equal(successor.body.error, 'invalid_grant');

  const family = fixture.state.database.prepare(`
    SELECT revoked_at, replayed_at FROM oauth_refresh_families
  `).get();
  assert.equal(typeof family.revoked_at, 'number');
  assert.equal(typeof family.replayed_at, 'number');
  const accessRows = fixture.state.database.prepare(`
    SELECT revoked_at FROM oauth_access_tokens
  `).all();
  assert.equal(accessRows.length, 2);
  assert.ok(accessRows.every((row) => typeof row.revoked_at === 'number'));
  assert.equal(
    fixture.state.database.prepare(`
      SELECT COUNT(*) AS count FROM auth_revocations
      WHERE kind = 'refresh_family' AND reason = 'refresh_token_replay'
    `).get().count,
    1
  );
});

test('rotated refresh tokens receive a new 30-day lifetime and expired access fails closed', async (t) => {
  const fixture = await createFixture(t);
  const issued = await issueTokens(fixture);

  fixture.advance(60 * 60 * 1000 + 1);
  const expiredAccess = await fixture.request('/protected/mcp', {
    headers: { Authorization: `Bearer ${issued.tokens.access_token}` }
  });
  assert.equal(expiredAccess.status, 401);

  const rotated = await refresh(
    fixture,
    issued.client,
    issued.tokens.refresh_token,
    issued.tokens.resource
  );
  assert.equal(rotated.response.status, 200, JSON.stringify(rotated.body));
  const successor = fixture.state.database.prepare(`
    SELECT created_at, expires_at
    FROM oauth_refresh_tokens
    WHERE consumed_at IS NULL
  `).get();
  const family = fixture.state.database.prepare(`
    SELECT expires_at FROM oauth_refresh_families
  `).get();
  assert.equal(successor.expires_at - successor.created_at, 30 * 24 * 60 * 60 * 1000);
  assert.equal(family.expires_at, successor.expires_at);

  fixture.advance(30 * 24 * 60 * 60 * 1000 + 1);
  const expiredRefresh = await refresh(
    fixture,
    issued.client,
    rotated.body.refresh_token,
    issued.tokens.resource
  );
  assert.equal(expiredRefresh.response.status, 400);
  assert.equal(expiredRefresh.body.error, 'invalid_grant');
});

test('concurrent refresh replay allows one rotation then revokes the family', async (t) => {
  const fixture = await createFixture(t);
  const issued = await issueTokens(fixture);
  const attempts = await Promise.all([
    refresh(fixture, issued.client, issued.tokens.refresh_token, issued.tokens.resource),
    refresh(fixture, issued.client, issued.tokens.refresh_token, issued.tokens.resource)
  ]);
  assert.deepEqual(attempts.map(({ response }) => response.status).sort(), [200, 400]);
  const successful = attempts.find(({ response }) => response.status === 200);
  const replay = attempts.find(({ response }) => response.status === 400);
  assert.equal(replay.body.error, 'invalid_grant');
  assert.match(replay.body.error_description, /replay/i);

  const revokedSuccessor = await fixture.request('/protected/mcp', {
    headers: { Authorization: `Bearer ${successful.body.access_token}` }
  });
  assert.equal(revokedSuccessor.status, 401);
});

test('revocation is idempotent and access-code/refresh expirations fail closed', async (t) => {
  const fixture = await createFixture(t);
  const issued = await issueTokens(fixture);

  const missingRevokeClient = await fixture.request('/revoke', {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: form({ token: issued.tokens.access_token })
  });
  assert.equal(missingRevokeClient.status, 401);
  assert.equal((await missingRevokeClient.json()).error, 'invalid_client');

  const unknownRevokeClient = await fixture.request('/revoke', {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: form({ token: issued.tokens.access_token, client_id: 'unknown-client' })
  });
  assert.equal(unknownRevokeClient.status, 401);
  assert.equal((await unknownRevokeClient.json()).error, 'invalid_client');

  const otherRegistration = await registerClient(fixture);
  assert.equal(otherRegistration.response.status, 201);
  const mismatchedRevokeClient = await fixture.request('/revoke', {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: form({
      token: issued.tokens.access_token,
      client_id: otherRegistration.body.client_id
    })
  });
  assert.equal(mismatchedRevokeClient.status, 200);
  const stillActive = await fixture.request('/protected/mcp', {
    headers: { Authorization: `Bearer ${issued.tokens.access_token}` }
  });
  assert.equal(stillActive.status, 200);

  fixture.state.database.prepare(`
    UPDATE oauth_clients
    SET revoked_at = ?
    WHERE client_id = ?
  `).run(fixture.now(), otherRegistration.body.client_id);
  const revokedRevokeClient = await fixture.request('/revoke', {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: form({ token: 'unknown-token', client_id: otherRegistration.body.client_id })
  });
  assert.equal(revokedRevokeClient.status, 401);
  assert.equal((await revokedRevokeClient.json()).error, 'invalid_client');

  const revokeAccess = await fixture.request('/revoke', {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: form({
      token: issued.tokens.access_token,
      token_type_hint: 'access_token',
      client_id: issued.client.client_id
    })
  });
  assert.equal(revokeAccess.status, 200);
  const revokeAccessAgain = await fixture.request('/revoke', {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: form({
      token: issued.tokens.access_token,
      token_type_hint: 'access_token',
      client_id: issued.client.client_id
    })
  });
  assert.equal(revokeAccessAgain.status, 200);
  assert.equal(
    fixture.state.database.prepare(`
      SELECT COUNT(*) AS count FROM auth_revocations
      WHERE kind = 'access_token' AND reason = 'token_revocation'
    `).get().count,
    1
  );
  const revokedAccess = await fixture.request('/protected/mcp', {
    headers: { Authorization: `Bearer ${issued.tokens.access_token}` }
  });
  assert.equal(revokedAccess.status, 401);

  const rotated = await refresh(
    fixture,
    issued.client,
    issued.tokens.refresh_token,
    issued.tokens.resource
  );
  assert.equal(rotated.response.status, 200);
  const revokeFamily = await fixture.request('/revoke', {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: form({
      token: rotated.body.refresh_token,
      token_type_hint: 'refresh_token',
      client_id: issued.client.client_id
    })
  });
  assert.equal(revokeFamily.status, 200);
  const revokeFamilyAgain = await fixture.request('/revoke', {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: form({
      token: rotated.body.refresh_token,
      token_type_hint: 'refresh_token',
      client_id: issued.client.client_id
    })
  });
  assert.equal(revokeFamilyAgain.status, 200);
  assert.equal(
    fixture.state.database.prepare(`
      SELECT COUNT(*) AS count FROM auth_revocations
      WHERE kind = 'refresh_family' AND reason = 'token_revocation'
    `).get().count,
    1
  );
  const familyAccess = await fixture.request('/protected/mcp', {
    headers: { Authorization: `Bearer ${rotated.body.access_token}` }
  });
  assert.equal(familyAccess.status, 401);

  const unknown = await fixture.request('/revoke', {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: form({ token: 'unknown-token', client_id: issued.client.client_id })
  });
  assert.equal(unknown.status, 200);

  const registration = await registerClient(fixture);
  const authorization = await authorize(fixture, registration.body);
  fixture.advance(5 * 60 * 1000 + 1);
  const expiredCode = await exchangeCode(fixture, registration.body, authorization);
  assert.equal(expiredCode.response.status, 400);
  assert.equal(expiredCode.body.error, 'invalid_grant');

  const authenticatedTokenRequest = await fixture.request('/token', {
    method: 'POST',
    headers: {
      Authorization: BASIC_AUTHORIZATION,
      'Content-Type': 'application/x-www-form-urlencoded'
    },
    body: form({ grant_type: 'authorization_code' })
  });
  assert.equal(authenticatedTokenRequest.status, 401);
  assert.equal((await authenticatedTokenRequest.json()).error, 'invalid_client');
});

test('consent POST requires a bound one-time challenge and same-origin fetch metadata', async (t) => {
  const fixture = await createFixture(t);
  const registration = await registerClient(fixture);
  const parameters = authorizationParameters(fixture, registration.body);
  const headers = {
    Authorization: BASIC_AUTHORIZATION,
    'Content-Type': 'application/x-www-form-urlencoded'
  };

  const missing = await fixture.request('/authorize', {
    method: 'POST',
    headers,
    body: form({ ...parameters, decision: 'allow' }),
    redirect: 'manual'
  });
  assert.equal(new URL(missing.headers.get('location')).searchParams.get('error'), 'invalid_request');

  const consent = await fixture.request(`/authorize?${form(parameters)}`, {
    headers: { Authorization: BASIC_AUTHORIZATION }
  });
  const consentToken = (await consent.text()).match(
    /name="consent_token" value="([A-Za-z0-9_-]+)"/
  )?.[1];
  assert.ok(consentToken);
  const body = form({ ...parameters, consent_token: consentToken, decision: 'allow' });

  const crossSite = await fixture.request('/authorize', {
    method: 'POST',
    headers: { ...headers, 'Sec-Fetch-Site': 'cross-site' },
    body,
    redirect: 'manual'
  });
  assert.equal(
    new URL(crossSite.headers.get('location')).searchParams.get('error'),
    'invalid_request'
  );

  const allowed = await fixture.request('/authorize', {
    method: 'POST',
    headers,
    body,
    redirect: 'manual'
  });
  assert.ok(new URL(allowed.headers.get('location')).searchParams.get('code'));

  const replay = await fixture.request('/authorize', {
    method: 'POST',
    headers,
    body,
    redirect: 'manual'
  });
  assert.equal(new URL(replay.headers.get('location')).searchParams.get('error'), 'invalid_request');
});

test('unexpected consent failures redirect with server_error, state, and issuer', async (t) => {
  const errors = [];
  const fixture = await createFixture(t, { errors });
  const registration = await registerClient(fixture);
  assert.equal(registration.response.status, 201);
  const parameters = authorizationParameters(fixture, registration.body);
  const consent = await fixture.request(`/authorize?${form(parameters)}`, {
    headers: { Authorization: BASIC_AUTHORIZATION }
  });
  const consentToken = (await consent.text()).match(
    /name="consent_token" value="([A-Za-z0-9_-]+)"/
  )?.[1];
  assert.ok(consentToken);

  const originalTransaction = fixture.state.transaction;
  fixture.state.transaction = () => {
    throw new Error('simulated auth database failure');
  };
  let failed;
  try {
    failed = await fixture.request('/authorize', {
      method: 'POST',
      headers: {
        Authorization: BASIC_AUTHORIZATION,
        'Content-Type': 'application/x-www-form-urlencoded'
      },
      body: form({ ...parameters, consent_token: consentToken, decision: 'allow' }),
      redirect: 'manual'
    });
  } finally {
    fixture.state.transaction = originalTransaction;
  }

  assert.equal(failed.status, 302);
  const location = new URL(failed.headers.get('location'));
  assert.equal(location.searchParams.get('error'), 'server_error');
  assert.equal(location.searchParams.get('state'), parameters.state);
  assert.equal(location.searchParams.get('iss'), fixture.origin);
  assert.equal(errors.length, 1);
});

test('Basic-disabled consent is an explicit loopback click-through', async (t) => {
  const fixture = await createFixture(t, { basicEnabled: false });
  const registration = await registerClient(fixture);
  const client = registration.body;
  const consent = await fixture.request(
    `/authorize?${form(authorizationParameters(fixture, client))}`,
    { redirect: 'manual' }
  );
  assert.equal(consent.status, 200);
  assert.match(await consent.text(), /Authorize MCP access/);

  const authorization = await authorize(fixture, client, { withoutBasic: true });
  const exchange = await exchangeCode(fixture, client, authorization);
  assert.equal(exchange.response.status, 200);
  const principal = fixture.service.authenticateBearer(
    { headers: { authorization: `Bearer ${exchange.body.access_token}` } },
    '/mcp'
  );
  assert.equal(principal.subject, 'loopback-operator');
});
