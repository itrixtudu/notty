function normalizeConfiguredOrigin(value) {
  if (typeof value !== 'string' || !value.trim()) {
    return null;
  }

  const trimmed = value.trim();
  if (trimmed === '*') {
    return '*';
  }

  let parsed;
  try {
    parsed = new URL(trimmed);
  } catch {
    throw new Error('ALLOWED_ORIGIN must be an absolute URL or *');
  }
  if (!['http:', 'https:'].includes(parsed.protocol) || parsed.origin === 'null') {
    throw new Error('ALLOWED_ORIGIN must use an HTTP(S) origin or *');
  }
  return parsed.origin;
}

function normalizePublicOrigin(value) {
  if (typeof value !== 'string' || !value.trim()) {
    return null;
  }
  const trimmed = value.trim();
  let parsed;
  try {
    parsed = new URL(trimmed);
  } catch {
    throw new Error('publicOrigin must be an exact HTTP(S) origin');
  }
  if (
    !['http:', 'https:'].includes(parsed.protocol)
    || parsed.origin === 'null'
    || trimmed !== parsed.origin
  ) {
    throw new Error('publicOrigin must be an exact HTTP(S) origin');
  }
  return parsed.origin;
}

function normalizeHostname(value) {
  if (typeof value !== 'string' || !value.trim()) {
    return '';
  }
  const trimmed = value.trim();
  if (/^[a-z][a-z0-9+.-]*:\/\//i.test(trimmed)) {
    try {
      return new URL(trimmed).hostname.replace(/^\[|\]$/g, '').replace(/\.$/, '').toLowerCase();
    } catch {
      return '';
    }
  }
  if (trimmed.startsWith('[')) {
    const closingBracket = trimmed.indexOf(']');
    return closingBracket > 0
      ? trimmed.slice(1, closingBracket).toLowerCase()
      : '';
  }
  if ((trimmed.match(/:/g) || []).length > 1) {
    return trimmed.replace(/\.$/, '').toLowerCase();
  }
  return trimmed.split(':', 1)[0].replace(/\.$/, '').toLowerCase();
}

function isIpLiteral(hostname) {
  if (hostname.includes(':')) {
    return true;
  }
  const octets = hostname.split('.');
  return octets.length === 4 && octets.every((octet) => (
    /^\d{1,3}$/.test(octet) && Number(octet) >= 0 && Number(octet) <= 255
  ));
}

function isLoopbackHostname(hostname) {
  const normalized = normalizeHostname(hostname);
  if (normalized === 'localhost' || normalized.endsWith('.localhost') || normalized === '::1') {
    return true;
  }
  const octets = normalized.split('.');
  return octets.length === 4
    && octets[0] === '127'
    && octets.every((octet) => /^\d{1,3}$/.test(octet) && Number(octet) <= 255);
}

function isPrivateNetworkHostname(hostname) {
  const normalized = normalizeHostname(hostname);
  if (normalized.startsWith('fc') || normalized.startsWith('fd') || normalized.startsWith('fe8')
    || normalized.startsWith('fe9') || normalized.startsWith('fea') || normalized.startsWith('feb')) {
    return normalized.includes(':');
  }
  const octets = normalized.split('.').map(Number);
  if (octets.length !== 4 || octets.some((octet) => !Number.isInteger(octet) || octet < 0 || octet > 255)) {
    return false;
  }
  return octets[0] === 10
    || (octets[0] === 172 && octets[1] >= 16 && octets[1] <= 31)
    || (octets[0] === 192 && octets[1] === 168)
    || (octets[0] === 169 && octets[1] === 254);
}

function isEquivalentLocalHttpOrigin(requestOrigin, effectiveOrigin, publicOrigin) {
  if (!effectiveOrigin || !publicOrigin || requestOrigin.origin !== effectiveOrigin) {
    return false;
  }
  const effective = new URL(effectiveOrigin);
  const canonical = new URL(publicOrigin);
  return requestOrigin.protocol === 'http:'
    && effective.protocol === 'http:'
    && canonical.protocol === 'http:'
    && requestOrigin.port === canonical.port
    && (isLoopbackHostname(requestOrigin.hostname) || isPrivateNetworkHostname(requestOrigin.hostname))
    && isLoopbackHostname(canonical.hostname);
}

function isTrustedRequestHost(host, trustedHosts, configuredOrigin) {
  const hostname = normalizeHostname(host);
  if (!hostname) {
    return false;
  }
  if (hostname === 'localhost' || hostname.endsWith('.localhost') || isIpLiteral(hostname)) {
    return true;
  }

  const trusted = new Set((Array.isArray(trustedHosts) ? trustedHosts : [trustedHosts])
    .flatMap((entry) => typeof entry === 'string' ? entry.split(',') : [])
    .map(normalizeHostname)
    .filter((entry) => entry && entry !== '0.0.0.0' && entry !== '::'));
  if (configuredOrigin && configuredOrigin !== '*') {
    trusted.add(normalizeHostname(configuredOrigin));
  }
  return trusted.has(hostname);
}

function normalizeProtocol(value) {
  if (typeof value !== 'string' || !value.trim()) {
    return '';
  }
  const normalized = value.trim().toLowerCase();
  return normalized.endsWith(':') ? normalized : `${normalized}:`;
}

function resolveEffectiveOrigin(protocol, host) {
  const normalizedProtocol = normalizeProtocol(protocol);
  if (!['http:', 'https:'].includes(normalizedProtocol) || typeof host !== 'string' || !host.trim()) {
    return '';
  }
  try {
    return new URL(`${normalizedProtocol}//${host.trim()}`).origin;
  } catch {
    return '';
  }
}

export function resolveOriginPolicy({
  origin,
  host,
  protocol,
  allowedOrigin,
  publicOrigin,
  fetchSite,
  trustedHosts
} = {}) {
  const configuredOrigin = normalizeConfiguredOrigin(allowedOrigin);
  const canonicalPublicOrigin = normalizePublicOrigin(publicOrigin);
  const requestOrigin = typeof origin === 'string' ? origin.trim() : '';
  const requestFetchSite = typeof fetchSite === 'string' ? fetchSite.trim().toLowerCase() : '';

  if ((requestOrigin || requestFetchSite)
    && !isTrustedRequestHost(
      host,
      trustedHosts,
      canonicalPublicOrigin || configuredOrigin
    )) {
    return { allowed: false, responseOrigin: null, reason: 'untrusted-host' };
  }

  if (!requestOrigin) {
    if (requestFetchSite === 'cross-site' || requestFetchSite === 'same-site') {
      return { allowed: false, responseOrigin: null, reason: 'cross-site' };
    }
    return {
      allowed: true,
      responseOrigin: configuredOrigin === '*' ? '*' : null,
      reason: 'non-browser'
    };
  }

  let parsedOrigin;
  try {
    parsedOrigin = new URL(requestOrigin);
  } catch {
    return { allowed: false, responseOrigin: null, reason: 'invalid-origin' };
  }

  const effectiveOrigin = resolveEffectiveOrigin(protocol, host);
  const sameOrigin = parsedOrigin.origin === (canonicalPublicOrigin || effectiveOrigin)
    || isEquivalentLocalHttpOrigin(parsedOrigin, effectiveOrigin, canonicalPublicOrigin);
  const explicitlyAllowed = configuredOrigin === '*' || configuredOrigin === parsedOrigin.origin;
  if (!sameOrigin && !explicitlyAllowed) {
    return { allowed: false, responseOrigin: null, reason: 'cross-origin' };
  }

  return {
    allowed: true,
    responseOrigin: configuredOrigin === '*' ? '*' : parsedOrigin.origin,
    reason: sameOrigin ? 'same-origin' : 'configured-origin'
  };
}

export function createCorsMiddleware(options = {}) {
  const allowedOrigin = options.allowedOrigin;
  const allowedHeaders = options.allowedHeaders || 'Content-Type, Authorization';
  const allowedMethods = options.allowedMethods || 'GET,POST,OPTIONS';
  const exposedHeaders = options.exposedHeaders || '';
  const trustedHosts = options.trustedHosts;
  const publicOrigin = options.publicOrigin;

  // Validate configuration during startup instead of failing only after a request arrives.
  normalizeConfiguredOrigin(allowedOrigin);
  normalizePublicOrigin(publicOrigin);

  return function corsMiddleware(req, res, next) {
    const decision = resolveOriginPolicy({
      origin: req.get('origin'),
      host: req.get('host'),
      protocol: req.protocol,
      allowedOrigin,
      publicOrigin,
      fetchSite: req.get('sec-fetch-site'),
      trustedHosts
    });

    if (!decision.allowed) {
      res.status(403).json({
        error: {
          code: 'ORIGIN_REJECTED',
          message: 'Cross-origin requests are not allowed'
        }
      });
      return;
    }

    if (decision.responseOrigin) {
      res.setHeader('Access-Control-Allow-Origin', decision.responseOrigin);
      if (decision.responseOrigin !== '*') {
        res.vary('Origin');
      }
      res.setHeader('Access-Control-Allow-Headers', allowedHeaders);
      res.setHeader('Access-Control-Allow-Methods', allowedMethods);
      if (exposedHeaders) {
        res.setHeader('Access-Control-Expose-Headers', exposedHeaders);
      }
    }

    if (req.method === 'OPTIONS') {
      res.sendStatus(204);
      return;
    }
    next();
  };
}
