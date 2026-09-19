import net from 'node:net';

function normalizeHostname(value) {
  return String(value || '').trim().replace(/^\[(.*)\]$/, '$1').toLowerCase();
}

export function isLoopbackHost(value) {
  const hostname = normalizeHostname(value);
  if (!hostname) {
    return false;
  }
  if (hostname === 'localhost' || hostname.endsWith('.localhost') || hostname === '::1') {
    return true;
  }
  if (net.isIP(hostname) === 4) {
    const firstOctet = Number.parseInt(hostname.split('.')[0], 10);
    return firstOctet === 127;
  }
  return false;
}

export function parsePublicOrigin(value) {
  const raw = String(value || '');
  if (!raw) {
    throw new Error('NOTTY_PUBLIC_ORIGIN is required for HTTP OAuth transports');
  }
  if (raw !== raw.trim()) {
    throw new Error('NOTTY_PUBLIC_ORIGIN must not contain surrounding whitespace');
  }

  let url;
  try {
    url = new URL(raw);
  } catch {
    throw new Error('NOTTY_PUBLIC_ORIGIN must be an absolute http or https origin');
  }
  if (!['http:', 'https:'].includes(url.protocol)) {
    throw new Error('NOTTY_PUBLIC_ORIGIN must use http or https');
  }
  if (url.username || url.password) {
    throw new Error('NOTTY_PUBLIC_ORIGIN must not contain credentials');
  }
  if (url.pathname !== '/' || url.search || url.hash) {
    throw new Error('NOTTY_PUBLIC_ORIGIN must not contain a path, query, or fragment');
  }
  if (raw !== url.origin) {
    throw new Error(`NOTTY_PUBLIC_ORIGIN must be the exact origin ${url.origin}`);
  }
  if (url.protocol === 'http:' && !isLoopbackHost(url.hostname)) {
    throw new Error('NOTTY_PUBLIC_ORIGIN may use HTTP only for a loopback host');
  }
  return url.origin;
}

export function resolvePublicOrigin({ env = process.env, port = 3000, publicHost = 'localhost' } = {}) {
  const configured = String(env.NOTTY_PUBLIC_ORIGIN || '');
  if (configured) {
    return parsePublicOrigin(configured);
  }
  const hostname = normalizeHostname(publicHost);
  const formattedHost = hostname.includes(':') ? `[${hostname}]` : hostname;
  return parsePublicOrigin(`http://${formattedHost}:${port}`);
}

export function validateOAuthRedirectUri(value) {
  const raw = String(value || '').trim();
  let url;
  try {
    url = new URL(raw);
  } catch {
    return false;
  }
  if (url.username || url.password || url.hash) {
    return false;
  }
  if (url.protocol === 'https:') {
    return true;
  }
  return url.protocol === 'http:' && isLoopbackHost(url.hostname);
}

export function assertLoopbackExposure({ bindHost, publicOrigin, allowContainerLoopback = false } = {}) {
  const origin = new URL(parsePublicOrigin(publicOrigin));
  const listenerIsLoopback = isLoopbackHost(bindHost);
  if (!listenerIsLoopback && !allowContainerLoopback) {
    throw new Error('This authentication mode requires an explicit loopback listener');
  }
  if (!isLoopbackHost(origin.hostname)) {
    throw new Error('This authentication mode requires a loopback NOTTY_PUBLIC_ORIGIN');
  }
}
