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
  fetchSite,
  trustedHosts
} = {}) {
  const configuredOrigin = normalizeConfiguredOrigin(allowedOrigin);
  const requestOrigin = typeof origin === 'string' ? origin.trim() : '';
  const requestFetchSite = typeof fetchSite === 'string' ? fetchSite.trim().toLowerCase() : '';

  if ((requestOrigin || requestFetchSite)
    && !isTrustedRequestHost(host, trustedHosts, configuredOrigin)) {
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

  const sameOrigin = parsedOrigin.origin === resolveEffectiveOrigin(protocol, host);
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

  // Validate configuration during startup instead of failing only after a request arrives.
  normalizeConfiguredOrigin(allowedOrigin);

  return function corsMiddleware(req, res, next) {
    const decision = resolveOriginPolicy({
      origin: req.get('origin'),
      host: req.get('host'),
      protocol: req.protocol,
      allowedOrigin,
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
