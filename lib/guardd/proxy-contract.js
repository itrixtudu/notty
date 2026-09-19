const FIXED_HOP_BY_HOP_HEADERS = new Set([
  'connection',
  'keep-alive',
  'proxy-authenticate',
  'proxy-authorization',
  'proxy-connection',
  'te',
  'trailer',
  'transfer-encoding',
  'upgrade',
]);

const CALLER_CONTROLLED_HEADERS = new Set([
  'cf-connecting-ip',
  'forwarded',
  'true-client-ip',
  'via',
  'x-client-ip',
  'x-invoke-path',
  'x-invoke-query',
  'x-middleware-subrequest',
  'x-middleware-subrequest-id',
  'x-now-route-matches',
  'x-original-url',
  'x-prerender-revalidate',
  'x-prerender-revalidate-if-generated',
  'x-real-ip',
  'x-rewrite-url',
]);

function scalarHeader(headers, name, options = {}) {
  const value = headers?.[name];
  if (value == null || value === '') {
    if (options.required) {
      throw new TypeError(`${name} header is required`);
    }
    return null;
  }
  if (Array.isArray(value) || typeof value !== 'string') {
    throw new TypeError(`${name} header must occur exactly once`);
  }
  if (/[\r\n\u0000]/.test(value)) {
    throw new TypeError(`${name} header contains invalid characters`);
  }
  return value.trim();
}

export function normalizeGatewayPublicOrigin(value) {
  if (typeof value !== 'string' || !value.trim()) {
    throw new TypeError('gateway public origin is required');
  }
  let parsed;
  try {
    parsed = new URL(value.trim());
  } catch {
    throw new TypeError('gateway public origin must be an absolute HTTPS URL');
  }
  if (
    parsed.protocol !== 'https:' ||
    parsed.username ||
    parsed.password ||
    parsed.pathname !== '/' ||
    parsed.search ||
    parsed.hash ||
    !parsed.hostname
  ) {
    throw new TypeError(
      'gateway public origin must be an HTTPS origin without credentials, path, query, or fragment',
    );
  }
  return Object.freeze({
    origin: parsed.origin,
    protocol: 'https',
    host: parsed.host,
    hostname: parsed.hostname,
    port: parsed.port || '443',
    websocketOrigin: `wss://${parsed.host}`,
  });
}

export function validatePublicRequestHeaders(
  headers,
  publicOrigin,
  options = {},
) {
  const contract =
    typeof publicOrigin === 'string'
      ? normalizeGatewayPublicOrigin(publicOrigin)
      : publicOrigin;
  const host = scalarHeader(headers, 'host', { required: true });
  if (host.toLowerCase() !== contract.host.toLowerCase()) {
    throw new TypeError(
      `request Host does not match configured gateway authority ${contract.host}`,
    );
  }
  const origin = scalarHeader(headers, 'origin');
  if (origin !== null && origin !== contract.origin) {
    throw new TypeError(
      `request Origin does not match configured gateway origin ${contract.origin}`,
    );
  }
  const fetchSite = scalarHeader(headers, 'sec-fetch-site');
  if (
    (origin !== null &&
      fetchSite !== null &&
      fetchSite.toLowerCase() !== 'same-origin') ||
    (origin === null &&
      ['same-site', 'cross-site'].includes(fetchSite?.toLowerCase()))
  ) {
    throw new TypeError('request fetch metadata does not match the public origin');
  }
  if (options.requireForwarded) {
    const forwardedHost = scalarHeader(headers, 'x-forwarded-host', {
      required: true,
    });
    const forwardedProto = scalarHeader(headers, 'x-forwarded-proto', {
      required: true,
    });
    const forwardedPort = scalarHeader(headers, 'x-forwarded-port', {
      required: true,
    });
    if (forwardedHost.toLowerCase() !== contract.host.toLowerCase()) {
      throw new TypeError('forwarded Host does not match the run policy');
    }
    if (forwardedProto !== contract.protocol) {
      throw new TypeError('forwarded protocol does not match the run policy');
    }
    if (forwardedPort !== contract.port) {
      throw new TypeError('forwarded port does not match the run policy');
    }
  }
  return {
    contract,
    hasOrigin: origin !== null,
  };
}

function connectionHeaders(headers) {
  const names = new Set(FIXED_HOP_BY_HOP_HEADERS);
  const connection = headers?.connection;
  const values = Array.isArray(connection) ? connection : [connection];
  for (const value of values) {
    if (typeof value !== 'string') {
      continue;
    }
    for (const token of value.split(',')) {
      const normalized = token.trim().toLowerCase();
      if (/^[!#$%&'*+\-.^_`|~0-9a-z]+$/.test(normalized)) {
        names.add(normalized);
      }
    }
  }
  return names;
}

function daemonControlledHeader(name) {
  return (
    name === 'host' ||
    name === 'origin' ||
    name === 'sec-fetch-site' ||
    CALLER_CONTROLLED_HEADERS.has(name) ||
    name.startsWith('x-forwarded-') ||
    name.startsWith('x-nosh-guard-')
  );
}

export function canonicalProxyHeaders(
  headers,
  publicOrigin,
  additions = {},
) {
  const contract =
    typeof publicOrigin === 'string'
      ? normalizeGatewayPublicOrigin(publicOrigin)
      : publicOrigin;
  const hasOrigin = scalarHeader(headers, 'origin') !== null;
  const hopByHop = connectionHeaders(headers);
  const output = {};
  for (const [rawName, value] of Object.entries(headers || {})) {
    const name = rawName.toLowerCase();
    if (
      value != null &&
      !hopByHop.has(name) &&
      !daemonControlledHeader(name)
    ) {
      output[name] = value;
    }
  }
  output.host = contract.host;
  output['x-forwarded-host'] = contract.host;
  output['x-forwarded-proto'] = contract.protocol;
  output['x-forwarded-port'] = contract.port;
  if (hasOrigin) {
    output.origin = contract.origin;
    output['sec-fetch-site'] = 'same-origin';
  }
  for (const [rawName, value] of Object.entries(additions)) {
    const name = rawName.toLowerCase();
    if (
      !name.startsWith('x-nosh-guard-') ||
      value == null ||
      /[\r\n\u0000]/.test(String(value))
    ) {
      throw new TypeError(`invalid daemon-controlled proxy header: ${rawName}`);
    }
    output[name] = String(value);
  }
  return output;
}

export function runnerPublicEnvironment(publicOrigin) {
  const contract =
    typeof publicOrigin === 'string'
      ? normalizeGatewayPublicOrigin(publicOrigin)
      : publicOrigin;
  return {
    ALLOWED_ORIGIN: contract.origin,
    NOTTY_PUBLIC_ORIGIN: contract.origin,
    NOTTY_PUBLIC_HOST: contract.hostname,
    NOTTY_PUBLIC_WS_URL: `${contract.websocketOrigin}/ws/terminals`,
    NOTTY_TRUSTED_HOSTS: contract.hostname,
  };
}

export { daemonControlledHeader };
