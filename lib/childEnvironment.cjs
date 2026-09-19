'use strict';

const BLOCKED_EXACT_KEYS = new Set([
  'AUTHORIZATION',
  'HTTP_AUTHORIZATION',
  'MCP_BEARER_TOKEN',
  'MCP_TOKEN',
  'MCP_SPAWN_OTP',
  'SPAWN_OTP',
  'COLLAB_AGENT_SPAWN_OTP',
  'NOTTY_AUTHORIZATION',
  'NOTTY_AUTH_STATE_DIR',
  'NOTTY_WORKSPACE_ID',
  'NOTTY_MCP_AUTHORIZATION',
  'NOTTY_MCP_BEARER_TOKEN',
  'NOTTY_MCP_SPAWN_OTP',
  'NOTTY_MCP_SPAWN_OTP_ENABLED',
  'NOTTY_MCP_SPAWN_OTP_TTL_SECONDS',
  'NOTTY_GUARD_MTLS',
  'NOTTY_GUARD_GATEWAY_PEER_IP',
  'NOTTY_GUARD_GATEWAY_TOKEN',
  'NOTTY_GUARD_OTP_MINT_TOKEN',
  'NOTTY_LOOPBACK_PUBLICATION',
  'NOTTY_NOAUTH',
  'NOTTY_NO_OAUTH',
  'NOTTY_NO_OTP_AUTH',
  'NOTTY_COPILOT_ACCESS_TOKEN',
  'NOTTY_COPILOT_MCP_URL'
]);

const BLOCKED_PREFIXES = Object.freeze([
  'NOTTY_BASIC_AUTH_',
  'NOTTY_OAUTH_'
]);

function isSensitiveChildEnvironmentKey(key) {
  const normalized = String(key || '').trim().toUpperCase();
  if (!normalized) {
    return false;
  }
  return BLOCKED_EXACT_KEYS.has(normalized)
    || BLOCKED_PREFIXES.some((prefix) => normalized.startsWith(prefix));
}

function sanitizeChildEnvironment(environment = process.env, overrides = {}) {
  const sanitized = {};
  for (const [key, value] of Object.entries(environment || {})) {
    if (value === undefined || value === null || isSensitiveChildEnvironmentKey(key)) {
      continue;
    }
    sanitized[key] = String(value);
  }

  for (const [key, value] of Object.entries(overrides || {})) {
    if (isSensitiveChildEnvironmentKey(key) || value === undefined || value === null) {
      delete sanitized[key];
      continue;
    }
    sanitized[key] = String(value);
  }
  return sanitized;
}

function childEnvironmentAssignments(environment) {
  return Object.entries(sanitizeChildEnvironment(environment))
    .map(([key, value]) => `${key}=${value}`)
    .sort();
}

module.exports = {
  BLOCKED_EXACT_KEYS,
  BLOCKED_PREFIXES,
  childEnvironmentAssignments,
  isSensitiveChildEnvironmentKey,
  sanitizeChildEnvironment
};
