import os from 'node:os';

export const DEFAULT_PORT = 3000;

const BIND_HOST_ENV_KEYS = ['NOTTY_BIND_HOST', 'NOTTY_HOST', 'BIND_HOST', 'HOST'];
const PUBLIC_HOST_ENV_KEYS = ['NOTTY_PUBLIC_HOST', 'PUBLIC_HOST'];

function normalizeHost(value) {
  if (typeof value !== 'string') {
    return null;
  }

  const trimmed = value.trim();
  if (!trimmed) {
    return null;
  }

  if (/^[a-z][a-z0-9+.-]*:\/\//i.test(trimmed)) {
    try {
      return new URL(trimmed).hostname;
    } catch {
      return null;
    }
  }

  return trimmed.replace(/^\[(.+)\]$/, '$1');
}

function firstConfiguredHost(env, keys) {
  for (const key of keys) {
    const host = normalizeHost(env[key]);
    if (host) {
      return host;
    }
  }

  return null;
}

function isIpLikeHost(host) {
  const normalized = normalizeHost(host);
  return (
    isWildcardHost(normalized)
    || /^\d{1,3}(?:\.\d{1,3}){3}$/.test(normalized || '')
    || (normalized || '').includes(':')
  );
}

function getConfiguredBindHost(env) {
  const bindHost = firstConfiguredHost(env, BIND_HOST_ENV_KEYS);
  if (bindHost) {
    return bindHost;
  }

  const hostname = normalizeHost(env.HOSTNAME);
  return hostname && isIpLikeHost(hostname) ? hostname : null;
}

export function parsePort(env = process.env, fallback = DEFAULT_PORT) {
  const parsed = Number.parseInt(env.PORT ?? '', 10);
  return Number.isInteger(parsed) && parsed > 0 && parsed <= 65535 ? parsed : fallback;
}

export function isWildcardHost(host) {
  const normalized = normalizeHost(host);
  return (
    !normalized
    || normalized === '*'
    || normalized === '0.0.0.0'
    || normalized === '::'
  );
}

export function getNetworkHost() {
  const interfaces = os.networkInterfaces();

  for (const addresses of Object.values(interfaces)) {
    for (const address of addresses || []) {
      if (address.family === 'IPv4' && !address.internal && address.address) {
        return address.address;
      }
    }
  }

  for (const addresses of Object.values(interfaces)) {
    for (const address of addresses || []) {
      if (address.family === 'IPv6' && !address.internal && address.address) {
        return address.address;
      }
    }
  }

  return null;
}

export function formatHostForUrl(host) {
  const normalized = normalizeHost(host) || 'localhost';
  return normalized.includes(':') ? `[${normalized}]` : normalized;
}

export function buildHttpUrl({ host, port, path = '' }) {
  const normalizedPath = path && path.startsWith('/') ? path : `/${path || ''}`;
  return `http://${formatHostForUrl(host)}:${port}${normalizedPath === '/' ? '' : normalizedPath}`;
}

export function buildWsUrl({ host, port, path }) {
  const normalizedPath = path && path.startsWith('/') ? path : `/${path || ''}`;
  return `ws://${formatHostForUrl(host)}:${port}${normalizedPath}`;
}

export function resolveServerAddress(env = process.env) {
  const port = parsePort(env);
  const bindHost = getConfiguredBindHost(env);
  const explicitPublicHost = firstConfiguredHost(env, PUBLIC_HOST_ENV_KEYS);
  const publicHost =
    explicitPublicHost
    || (!isWildcardHost(bindHost) ? bindHost : null)
    || getNetworkHost()
    || 'localhost';

  return {
    port,
    bindHost,
    publicHost
  };
}
