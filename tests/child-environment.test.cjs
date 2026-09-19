'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');

const {
  childEnvironmentAssignments,
  isSensitiveChildEnvironmentKey,
  sanitizeChildEnvironment,
} = require('../lib/childEnvironment.cjs');

test('child environments remove server auth and every inherited OTP capability', () => {
  const source = {
    PATH: '/usr/bin',
    HOME: '/tmp/test-home',
    SAFE_VALUE: 'kept',
    AUTHORIZATION: 'Bearer header-secret',
    HTTP_AUTHORIZATION: 'Basic header-secret',
    MCP_BEARER_TOKEN: 'mcp-bearer-secret',
    MCP_TOKEN: 'mcp-token-secret',
    SPAWN_OTP: 'generic-otp',
    NOTTY_BASIC_AUTH_USERNAME: 'operator',
    NOTTY_BASIC_AUTH_PASSWORD: 'basic-secret',
    NOTTY_OAUTH_CLIENT_SECRET: 'oauth-secret',
    NOTTY_OAUTH_BOOT_TOKEN: 'legacy-oauth-secret',
    NOTTY_MCP_AUTHORIZATION: 'Bearer mcp-secret',
    NOTTY_MCP_BEARER_TOKEN: 'mcp-secret',
    NOTTY_AUTHORIZATION: 'Bearer server-secret',
    NOTTY_AUTH_STATE_DIR: '/run/private/notty-auth',
    NOTTY_WORKSPACE_ID: 'private-workspace-id',
    NOTTY_MCP_SPAWN_OTP: 'launcher-otp',
    NOTTY_MCP_SPAWN_OTP_ENABLED: 'true',
    NOTTY_MCP_SPAWN_OTP_TTL_SECONDS: '3600',
    NOTTY_GUARD_MTLS: 'true',
    NOTTY_GUARD_GATEWAY_PEER_IP: '10.240.9.2',
    NOTTY_GUARD_GATEWAY_TOKEN: 'guard-gateway-secret',
    NOTTY_GUARD_OTP_MINT_TOKEN: 'guard-mint-secret',
    NOTTY_LOOPBACK_PUBLICATION: 'true',
    NOTTY_NOAUTH: 'true',
    NOTTY_NO_OAUTH: 'true',
    NOTTY_NO_OTP_AUTH: 'true',
    NOTTY_COPILOT_ACCESS_TOKEN: 'copilot-token',
    NOTTY_COPILOT_MCP_URL: 'http://127.0.0.1/private-mcp',
    MCP_SPAWN_OTP: 'client-otp',
    COLLAB_AGENT_SPAWN_OTP: 'collab-otp',
  };

  const child = sanitizeChildEnvironment(source, {
    SAFE_OVERRIDE: 42,
    NOTTY_BASIC_AUTH_PASSWORD: 'cannot-readd',
    MCP_SPAWN_OTP: 'cannot-readd',
  });

  assert.deepEqual(child, {
    PATH: '/usr/bin',
    HOME: '/tmp/test-home',
    SAFE_VALUE: 'kept',
    SAFE_OVERRIDE: '42',
  });
  assert.equal(isSensitiveChildEnvironmentKey('notty_oauth_access_token'), true);
  assert.equal(isSensitiveChildEnvironmentKey('SAFE_VALUE'), false);

  const assignments = childEnvironmentAssignments(source);
  assert.deepEqual(assignments, [
    'HOME=/tmp/test-home',
    'PATH=/usr/bin',
    'SAFE_VALUE=kept',
  ]);
  assert.doesNotMatch(assignments.join('\n'), /secret|SPAWN_OTP|AUTHORIZATION/);
});
