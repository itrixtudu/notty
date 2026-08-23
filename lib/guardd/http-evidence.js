import net from 'node:net';

import { sha256, stableStringify } from '../guard/stable.js';

export const HTTP_EVIDENCE_API_VERSION = 'notty.dev/v1alpha1';
export const HTTP_EVIDENCE_SCHEMA_VERSION = 1;
export const HTTP_EVIDENCE_MAX_LINE_BYTES = 1024 * 1024;
export const HTTP_EVIDENCE_MAX_RECORDS = 1_000_000;
export const HTTP_HAR_MAX_ENTRIES = 100_000;
export const HTTP_HAR_MAX_BODY_BYTES = 64 * 1024 * 1024;

export const HTTP_EVIDENCE_RECORD_KINDS = Object.freeze({
  request: 'http-request',
  response: 'http-response',
  redirect: 'http-redirect',
  stats: 'http-capture-stats',
});

const DIGEST_PATTERN = /^sha256:[a-f0-9]{64}$/;
const RUN_ID_PATTERN = /^[A-Za-z0-9_.-]{1,128}$/;
const PROVIDERS = new Set(['mitmproxy', 'burp-har', 'generic']);
const CAPTURE_AUTHORITIES = new Set(['managed', 'review-only']);
const CAPTURE_MODES = new Set(['managed-proxy', 'manual-import']);
const TLS_INTERCEPTION = new Set(['plaintext', 'intercepted', 'opaque']);
const RESPONSE_DELIVERIES = new Set(['observed', 'buffered', 'cas', 'manual-import']);
const NATIVE_INTEGRITY_KINDS = new Set([
  'npm-sri',
  'apt-signed-metadata',
  'publisher-signature',
  'reviewed-digest',
]);
const COVERAGE_GAPS = new Set([
  'capture-error',
  'dropped-records',
  'incomplete-request-body',
  'incomplete-response-body',
  'interim-response',
  'manual-import',
  'missing-response',
  'opaque-connect',
  'oversized-body',
  'provider-loss',
  'range-response',
  'streaming-response',
  'tls-passthrough',
  'unmatched-dns',
  'unmatched-network',
]);
const CONTENT_ASSURANCE_GAPS = new Set([
  'ambiguous-request-identity',
  'cas-quota-exceeded',
  'credentialed-request',
  'head-response',
  'incomplete-response',
  'interim-response',
  'manifest-too-large',
  'manual-import',
  'no-replayable-responses',
  'not-modified-response',
  'oversized-body',
  'range-response',
]);
const SAFE_REPRESENTATION_HEADERS = new Set([
  'accept',
  'accept-encoding',
  'accept-language',
  'if-match',
  'if-modified-since',
  'if-none-match',
  'if-range',
  'if-unmodified-since',
  'range',
]);
const CREDENTIAL_HEADERS = new Set([
  'authorization',
  'cookie',
  'proxy-authorization',
]);
const CREDENTIAL_HEADER_NAME = /(?:^|[-_])(?:api[-_]?key|auth(?:orization)?|credential|cookie|pass(?:word)?|private[-_]?token|secret|session|signature|token)(?:$|[-_])/i;
const SECRET_QUERY_KEY = /(?:auth|code|credential|key|pass|password|secret|session|signature|sig|token)/i;
const SECRET_PATH_SEGMENT = /^(?:[A-Fa-f0-9]{32,}|[A-Za-z0-9_-]{48,}|eyJ[A-Za-z0-9_-]{16,})$/;

function plainObject(value, label) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    throw new TypeError(`${label} must be an object`);
  }
  return value;
}

function exactKeys(value, expected, label) {
  plainObject(value, label);
  const actual = Object.keys(value).sort();
  const selected = [...expected].sort();
  if (
    actual.length !== selected.length
    || actual.some((key, index) => key !== selected[index])
  ) {
    throw new TypeError(`${label} contains missing or unrecognized fields`);
  }
}

function enumValue(value, allowed, label) {
  if (!allowed.has(value)) {
    throw new TypeError(`${label} is unsupported: ${value}`);
  }
  return value;
}

function boundedString(value, label, maximum, { nullable = false } = {}) {
  if (nullable && value == null) return null;
  if (typeof value !== 'string' || value.length < 1 || value.length > maximum) {
    throw new TypeError(`${label} must be a non-empty string no longer than ${maximum}`);
  }
  return value;
}

function timestamp(value, label) {
  const milliseconds = typeof value === 'string' ? Date.parse(value) : Number.NaN;
  if (!Number.isFinite(milliseconds) || milliseconds < 0) {
    throw new TypeError(`${label} must be an ISO-compatible timestamp at or after the Unix epoch`);
  }
  return new Date(milliseconds).toISOString();
}

function digest(value, label, { nullable = false } = {}) {
  if (nullable && value == null) return null;
  if (!DIGEST_PATTERN.test(value || '')) {
    throw new TypeError(`${label} must be an exact sha256 digest`);
  }
  return value;
}

function nonNegativeInteger(value, label, { nullable = false } = {}) {
  if (nullable && value == null) return null;
  const selected = Number(value);
  if (!Number.isSafeInteger(selected) || selected < 0) {
    throw new TypeError(`${label} must be a non-negative safe integer`);
  }
  return selected;
}

function portNumber(value, label = 'HTTP port') {
  const selected = Number(value);
  if (!Number.isSafeInteger(selected) || selected < 1 || selected > 65535) {
    throw new TypeError(`${label} must be an integer from 1 to 65535`);
  }
  return selected;
}

function nullableIpAddress(value, label) {
  if (value == null) return null;
  const selected = String(value).toLowerCase().replace(/^\[|\]$/g, '');
  if (!net.isIP(selected)) {
    throw new TypeError(`${label} must be an IP address or null`);
  }
  return selected;
}

function normalizeRunId(value) {
  if (!RUN_ID_PATTERN.test(value || '')) {
    throw new TypeError('HTTP evidence runId contains unsupported characters');
  }
  return value;
}

function normalizeMethod(value) {
  const method = String(value || '').toUpperCase();
  if (!/^[A-Z][A-Z0-9!#$%&'*+.^_`|~-]{0,31}$/.test(method)) {
    throw new TypeError('HTTP method is invalid or too long');
  }
  return method;
}

function normalizeScheme(value) {
  const scheme = String(value || '').toLowerCase();
  if (scheme !== 'http' && scheme !== 'https') {
    throw new TypeError(`unsupported HTTP scheme: ${value}`);
  }
  return scheme;
}

function normalizeHostname(value) {
  let hostname = String(value || '').toLowerCase();
  if (hostname.startsWith('[') && hostname.endsWith(']')) {
    hostname = hostname.slice(1, -1);
  }
  if (net.isIP(hostname)) return hostname;
  if (
    hostname.length < 1
    || hostname.length > 253
    || !hostname.split('.').every((label) => (
      label.length >= 1
      && label.length <= 63
      && /^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/.test(label)
    ))
  ) {
    throw new TypeError(`invalid HTTP hostname: ${value}`);
  }
  return hostname;
}

function normalizedHeaderEntries(input) {
  if (input == null) return [];
  const entries = Array.isArray(input)
    ? input.map((entry) => {
        plainObject(entry, 'HTTP header');
        return [entry.name, entry.value];
      })
    : Object.entries(plainObject(input, 'HTTP headers'));
  return entries.map(([name, value]) => {
    const normalizedName = String(name || '').trim().toLowerCase();
    if (!/^[!#$%&'*+.^_`|~0-9a-z-]{1,128}$/.test(normalizedName)) {
      throw new TypeError(`invalid HTTP header name: ${name}`);
    }
    const normalizedValue = Array.isArray(value)
      ? value.map((entry) => String(entry)).join(', ')
      : String(value ?? '');
    if (normalizedValue.length > 64 * 1024 || /[\r\n]/.test(normalizedValue)) {
      throw new TypeError(`HTTP header ${normalizedName} is invalid or too large`);
    }
    return [normalizedName, normalizedValue];
  });
}

function representationHeadersDigest(headers) {
  const selected = normalizedHeaderEntries(headers)
    .filter(([name]) => SAFE_REPRESENTATION_HEADERS.has(name))
    .sort(([leftName, leftValue], [rightName, rightValue]) => (
      leftName.localeCompare(rightName) || leftValue.localeCompare(rightValue)
    ));
  return sha256(stableStringify(selected));
}

function containsCredentials(headers) {
  return normalizedHeaderEntries(headers)
    .some(([name, value]) => (
      (CREDENTIAL_HEADERS.has(name) || CREDENTIAL_HEADER_NAME.test(name))
      && value.length > 0
    ));
}

function normalizeBody(value, label) {
  if (value == null) return null;
  if (Buffer.isBuffer(value)) return value;
  if (value instanceof Uint8Array) {
    return Buffer.from(value.buffer, value.byteOffset, value.byteLength);
  }
  if (typeof value === 'string') return Buffer.from(value, 'utf8');
  throw new TypeError(`${label} must be bytes or a string`);
}

function displayPathname(pathname) {
  return pathname
    .split('/')
    .map((segment) => (SECRET_PATH_SEGMENT.test(segment) ? '<redacted>' : segment))
    .join('/');
}

function displaySearch(params) {
  const entries = [];
  for (const [key] of params) {
    const displayKey = key.length > 128 || SECRET_QUERY_KEY.test(key)
      ? '<redacted-key>'
      : key;
    entries.push(`${encodeURIComponent(displayKey)}=<redacted>`);
    if (entries.length >= 128) {
      entries.push('truncated=<redacted>');
      break;
    }
  }
  return entries.length ? `?${entries.join('&')}` : '';
}

function hostForUrl(hostname) {
  return net.isIP(hostname) === 6 ? `[${hostname}]` : hostname;
}

function validateSanitizedDisplayUrl(value, expected = {}) {
  const selected = boundedString(value, 'HTTP display URL', 8192);
  let parsed;
  try {
    parsed = new URL(selected);
  } catch (error) {
    throw new TypeError('HTTP display URL is invalid', { cause: error });
  }
  const scheme = normalizeScheme(parsed.protocol.slice(0, -1));
  const hostname = normalizeHostname(parsed.hostname);
  const port = parsed.port
    ? portNumber(parsed.port)
    : (scheme === 'https' ? 443 : 80);
  if (
    parsed.username
    || parsed.password
    || parsed.hash
    || (expected.scheme && expected.scheme !== scheme)
    || (expected.hostname && expected.hostname !== hostname)
    || (expected.port && expected.port !== port)
  ) {
    throw new TypeError('HTTP display URL contains private data or mismatches its origin');
  }
  for (const [key, queryValue] of parsed.searchParams) {
    if (
      queryValue !== '<redacted>'
      || key.length < 1
      || key.length > 128
    ) {
      throw new TypeError('HTTP display URL query values must be redacted');
    }
  }
  return selected;
}

export function normalizeObservedUrl(value) {
  const raw = boundedString(value, 'observed HTTP URL', 64 * 1024);
  let parsed;
  try {
    parsed = new URL(raw);
  } catch (error) {
    throw new TypeError('observed HTTP URL is invalid', { cause: error });
  }
  const scheme = normalizeScheme(parsed.protocol.slice(0, -1));
  const hostname = normalizeHostname(parsed.hostname);
  const port = parsed.port
    ? portNumber(parsed.port)
    : (scheme === 'https' ? 443 : 80);
  const requestTarget = `${parsed.pathname || '/'}${parsed.search}`;
  const defaultPort = (scheme === 'https' && port === 443)
    || (scheme === 'http' && port === 80);
  const authority = `${hostForUrl(hostname)}${defaultPort ? '' : `:${port}`}`;
  const displayUrl = `${scheme}://${authority}${displayPathname(parsed.pathname || '/')}${displaySearch(parsed.searchParams)}`;
  if (displayUrl.length > 8192) {
    throw new TypeError('sanitized HTTP URL exceeds the evidence display limit');
  }
  return {
    scheme,
    hostname,
    port,
    displayUrl,
    requestTargetDigest: sha256(requestTarget),
    hadUserInfo: parsed.username !== '' || parsed.password !== '',
    hadQuery: parsed.search !== '',
  };
}

function commonRecord(input, recordKind) {
  const provider = enumValue(input.provider || 'generic', PROVIDERS, 'HTTP evidence provider');
  const captureAuthority = enumValue(
    input.captureAuthority || (provider === 'burp-har' ? 'review-only' : 'managed'),
    CAPTURE_AUTHORITIES,
    'HTTP capture authority',
  );
  const captureMode = enumValue(
    input.captureMode || (captureAuthority === 'review-only' ? 'manual-import' : 'managed-proxy'),
    CAPTURE_MODES,
    'HTTP capture mode',
  );
  if (
    (captureAuthority === 'review-only') !== (captureMode === 'manual-import')
  ) {
    throw new TypeError('manual HTTP imports must remain review-only');
  }
  if (provider === 'burp-har' && captureAuthority !== 'review-only') {
    throw new TypeError('Burp HAR evidence is always a review-only manual import');
  }
  if (captureAuthority === 'managed' && provider !== 'mitmproxy') {
    throw new TypeError('managed HTTP evidence requires the pinned mitmproxy provider');
  }
  return {
    schemaVersion: HTTP_EVIDENCE_SCHEMA_VERSION,
    apiVersion: HTTP_EVIDENCE_API_VERSION,
    recordKind,
    runId: normalizeRunId(input.runId),
    observedAt: timestamp(input.observedAt || new Date().toISOString(), 'HTTP evidence observedAt'),
    provider,
    captureAuthority,
    captureMode,
  };
}

function exchangeDigest(value, fallback) {
  if (value != null) return digest(value, 'HTTP exchangeId');
  return sha256(stableStringify(fallback));
}

export function createHttpRequestEvidence(input) {
  plainObject(input, 'HTTP request evidence input');
  const common = commonRecord(input, HTTP_EVIDENCE_RECORD_KINDS.request);
  const url = input.url == null ? null : normalizeObservedUrl(input.url);
  const scheme = normalizeScheme(input.scheme || url?.scheme);
  const hostname = normalizeHostname(input.hostname || url?.hostname);
  const port = portNumber(input.port ?? url?.port);
  const method = normalizeMethod(input.method);
  const displayUrl = validateSanitizedDisplayUrl(
    input.displayUrl || url?.displayUrl,
    { scheme, hostname, port },
  );
  const requestTargetDigest = digest(
    input.requestTargetDigest || url?.requestTargetDigest,
    'HTTP requestTargetDigest',
  );
  const requestBody = normalizeBody(input.requestBody, 'HTTP request body');
  const requestBodyDigest = requestBody == null
    ? digest(input.requestBodyDigest, 'HTTP requestBodyDigest', { nullable: true })
    : sha256(requestBody);
  const requestBodyBytes = requestBody == null
    ? nonNegativeInteger(input.requestBodyBytes, 'HTTP requestBodyBytes', { nullable: true })
    : requestBody.length;
  if ((requestBodyDigest == null) !== (requestBodyBytes == null)) {
    throw new TypeError('HTTP request body digest and byte count must be present together');
  }
  const selectedHeadersDigest = input.representationHeadersDigest
    ? digest(input.representationHeadersDigest, 'HTTP representationHeadersDigest')
    : representationHeadersDigest(input.headers);
  if (input.credentialed != null && typeof input.credentialed !== 'boolean') {
    throw new TypeError('HTTP credentialed must be boolean');
  }
  const derivedCredentialed = url?.hadUserInfo === true || containsCredentials(input.headers);
  if (input.credentialed === false && derivedCredentialed) {
    throw new TypeError('HTTP credentialed cannot contradict observed credentials');
  }
  const credentialed = input.credentialed === true || derivedCredentialed;
  const tlsInterception = enumValue(
    input.tlsInterception || (scheme === 'https' ? 'intercepted' : 'plaintext'),
    TLS_INTERCEPTION,
    'HTTP TLS interception',
  );
  if (scheme === 'http' && tlsInterception !== 'plaintext') {
    throw new TypeError('plaintext HTTP cannot claim TLS interception');
  }
  const upstreamTlsVerified = input.upstreamTlsVerified == null
    ? null
    : input.upstreamTlsVerified;
  if (upstreamTlsVerified !== null && typeof upstreamTlsVerified !== 'boolean') {
    throw new TypeError('upstreamTlsVerified must be boolean or null');
  }
  if (scheme === 'http' && upstreamTlsVerified !== null) {
    throw new TypeError('plaintext HTTP cannot claim upstream TLS verification');
  }
  const clientAddress = nullableIpAddress(input.clientAddress, 'HTTP clientAddress');
  const clientPort = input.clientPort == null
    ? null
    : portNumber(input.clientPort, 'HTTP clientPort');
  const proxyAddress = nullableIpAddress(input.proxyAddress, 'HTTP proxyAddress');
  const proxyPort = input.proxyPort == null
    ? null
    : portNumber(input.proxyPort, 'HTTP proxyPort');
  const connectionValues = [clientAddress, clientPort, proxyAddress, proxyPort];
  if (
    connectionValues.some((value) => value == null)
    && connectionValues.some((value) => value != null)
  ) {
    throw new TypeError('HTTP downstream connection tuple must be wholly present or null');
  }
  if (common.captureAuthority === 'managed' && clientAddress === null) {
    throw new TypeError('managed HTTP evidence requires its exact downstream connection tuple');
  }
  const exchangeId = exchangeDigest(input.exchangeId, [
    common.runId,
    input.providerEventId || null,
    common.observedAt,
    method,
    scheme,
    hostname,
    port,
    requestTargetDigest,
    requestBodyDigest,
    clientAddress,
    clientPort,
    proxyAddress,
    proxyPort,
  ]);
  return {
    ...common,
    exchangeId,
    method,
    scheme,
    hostname,
    port,
    displayUrl,
    requestTargetDigest,
    requestBodyDigest,
    requestBodyBytes,
    representationHeadersDigest: selectedHeadersDigest,
    credentialed,
    tlsInterception,
    upstreamTlsVerified,
    clientAddress,
    clientPort,
    proxyAddress,
    proxyPort,
  };
}

function normalizeStatus(value, label = 'HTTP response status') {
  const status = Number(value);
  if (!Number.isSafeInteger(status) || status < 100 || status > 599) {
    throw new TypeError(`${label} must be an integer from 100 to 599`);
  }
  return status;
}

function optionalMetadata(value, label, maximum = 1024) {
  if (value == null || value === '') return null;
  const normalized = boundedString(String(value).trim(), label, maximum);
  if (/[\r\n]/.test(normalized)) {
    throw new TypeError(`${label} must not contain control line breaks`);
  }
  return normalized;
}

export function createHttpResponseEvidence(input) {
  plainObject(input, 'HTTP response evidence input');
  const common = commonRecord(input, HTTP_EVIDENCE_RECORD_KINDS.response);
  const exchangeId = digest(input.exchangeId, 'HTTP exchangeId');
  const body = normalizeBody(input.body, 'HTTP response body');
  const decodedBody = normalizeBody(input.decodedBody, 'decoded HTTP response body');
  const bodyDigest = body == null
    ? digest(input.bodyDigest, 'HTTP response bodyDigest', { nullable: true })
    : sha256(body);
  const bodyBytes = body == null
    ? nonNegativeInteger(input.bodyBytes, 'HTTP response bodyBytes', { nullable: true })
    : body.length;
  const decodedBodyDigest = decodedBody == null
    ? digest(input.decodedBodyDigest, 'decoded HTTP response bodyDigest', { nullable: true })
    : sha256(decodedBody);
  const decodedBodyBytes = decodedBody == null
    ? nonNegativeInteger(input.decodedBodyBytes, 'decoded HTTP response bodyBytes', { nullable: true })
    : decodedBody.length;
  if ((bodyDigest == null) !== (bodyBytes == null)) {
    throw new TypeError('HTTP response body digest and byte count must be present together');
  }
  if ((decodedBodyDigest == null) !== (decodedBodyBytes == null)) {
    throw new TypeError('decoded HTTP response body digest and byte count must be present together');
  }
  const bodyComplete = input.bodyComplete === true;
  if (bodyComplete && bodyDigest == null) {
    throw new TypeError('complete HTTP response bodies require a digest and byte count');
  }
  const status = normalizeStatus(input.status);
  const rangeResponse = input.rangeResponse == null
    ? status === 206
    : input.rangeResponse;
  if (typeof rangeResponse !== 'boolean') {
    throw new TypeError('HTTP rangeResponse must be boolean');
  }
  if (status === 206 && !rangeResponse) {
    throw new TypeError('HTTP 206 responses must be marked as range responses');
  }
  const upstreamAddress = nullableIpAddress(input.upstreamAddress, 'HTTP upstreamAddress');
  const upstreamPort = input.upstreamPort == null
    ? null
    : portNumber(input.upstreamPort, 'HTTP upstreamPort');
  if ((upstreamAddress === null) !== (upstreamPort === null)) {
    throw new TypeError('HTTP upstream connection address and port must be present together');
  }
  return {
    ...common,
    exchangeId,
    status,
    contentType: optionalMetadata(input.contentType, 'HTTP contentType'),
    contentEncoding: optionalMetadata(input.contentEncoding, 'HTTP contentEncoding', 128),
    headersDigest: digest(input.headersDigest, 'HTTP response headersDigest', { nullable: true }),
    bodyDigest,
    bodyBytes,
    decodedBodyDigest,
    decodedBodyBytes,
    bodyComplete,
    delivery: enumValue(input.delivery || 'observed', RESPONSE_DELIVERIES, 'HTTP response delivery'),
    rangeResponse,
    upstreamAddress,
    upstreamPort,
  };
}

export function createHttpRedirectEvidence(input) {
  plainObject(input, 'HTTP redirect evidence input');
  const common = commonRecord(input, HTTP_EVIDENCE_RECORD_KINDS.redirect);
  const status = normalizeStatus(input.status, 'HTTP redirect status');
  if (status < 300 || status > 399) {
    throw new TypeError('HTTP redirect evidence requires a 3xx status');
  }
  let locationDisplayUrl = input.locationDisplayUrl;
  let locationDigest = input.locationDigest;
  if (input.location != null) {
    const rawLocation = boundedString(
      String(input.location),
      'HTTP redirect Location',
      64 * 1024,
    );
    if (/[\r\n]/.test(rawLocation)) {
      throw new TypeError('HTTP redirect Location contains a line break');
    }
    locationDigest = sha256(rawLocation);
    try {
      const resolved = input.baseUrl
        ? new URL(rawLocation, input.baseUrl).href
        : new URL(rawLocation).href;
      locationDisplayUrl = normalizeObservedUrl(resolved).displayUrl;
    } catch {
      locationDisplayUrl = null;
    }
  }
  return {
    ...common,
    exchangeId: digest(input.exchangeId, 'HTTP exchangeId'),
    status,
    locationDisplayUrl: locationDisplayUrl == null
      ? null
      : validateSanitizedDisplayUrl(locationDisplayUrl),
    locationDigest: digest(locationDigest, 'HTTP redirect locationDigest'),
  };
}

export function createHttpCaptureStats(input) {
  plainObject(input, 'HTTP capture stats input');
  const common = commonRecord(input, HTTP_EVIDENCE_RECORD_KINDS.stats);
  const coverageGaps = [...new Set(input.coverageGaps || [])]
    .map((gap) => enumValue(gap, COVERAGE_GAPS, 'HTTP coverage gap'))
    .sort();
  const contentAssuranceGaps = [...new Set(input.contentAssuranceGaps || [])]
    .map((gap) => enumValue(
      gap,
      CONTENT_ASSURANCE_GAPS,
      'HTTP content-assurance gap',
    ))
    .sort();
  const counters = {};
  for (const name of [
    'requests',
    'responses',
    'redirects',
    'errors',
    'opaqueConnects',
    'incompleteBodies',
    'droppedRecords',
    'reviewOnlyRecords',
  ]) {
    counters[name] = nonNegativeInteger(input[name], `HTTP stats ${name}`);
  }
  const complete = input.complete === true;
  if (!complete && coverageGaps.length === 0) {
    throw new TypeError('incomplete HTTP capture stats require an explicit coverage gap');
  }
  if (complete && (
    coverageGaps.length
    || counters.errors
    || counters.opaqueConnects
    || counters.droppedRecords
    || counters.incompleteBodies
    || counters.requests !== counters.responses
  )) {
    throw new TypeError('complete HTTP capture stats cannot contain evidence loss or coverage gaps');
  }
  if (counters.redirects > counters.responses) {
    throw new TypeError('HTTP capture redirect count cannot exceed response count');
  }
  if (common.captureAuthority === 'managed' && counters.reviewOnlyRecords !== 0) {
    throw new TypeError('managed HTTP capture cannot count review-only records');
  }
  if (common.captureAuthority === 'review-only' && counters.reviewOnlyRecords < 1) {
    throw new TypeError('manual HTTP imports must count their review-only records');
  }
  const collectorImageDigest = digest(
    input.collectorImageDigest,
    'HTTP collector image digest',
    { nullable: true },
  );
  const collectorAddonDigest = digest(
    input.collectorAddonDigest,
    'HTTP collector addon digest',
    { nullable: true },
  );
  const collectorWrapperDigest = digest(
    input.collectorWrapperDigest,
    'HTTP collector wrapper digest',
    { nullable: true },
  );
  const collectorDigests = [
    collectorImageDigest,
    collectorAddonDigest,
    collectorWrapperDigest,
  ];
  if (
    common.captureAuthority === 'managed'
      ? collectorDigests.some((value) => value == null)
      : collectorDigests.some((value) => value != null)
  ) {
    throw new TypeError('managed HTTP stats require exact collector identity digests');
  }
  const contentManifestDigest = digest(
    input.contentManifestDigest,
    'HTTP content manifest digest',
    { nullable: true },
  );
  if (
    common.captureAuthority === 'review-only'
    && contentManifestDigest !== null
  ) {
    throw new TypeError('review-only HTTP evidence cannot attest managed CAS content');
  }
  return {
    ...common,
    complete,
    ...counters,
    coverageGaps,
    contentAssuranceGaps,
    contentManifestDigest,
    collectorImageDigest,
    collectorAddonDigest,
    collectorWrapperDigest,
  };
}

const COMMON_KEYS = [
  'schemaVersion',
  'apiVersion',
  'recordKind',
  'runId',
  'observedAt',
  'provider',
  'captureAuthority',
  'captureMode',
];
const RECORD_KEYS = Object.freeze({
  [HTTP_EVIDENCE_RECORD_KINDS.request]: [
    ...COMMON_KEYS,
    'exchangeId',
    'method',
    'scheme',
    'hostname',
    'port',
    'displayUrl',
    'requestTargetDigest',
    'requestBodyDigest',
    'requestBodyBytes',
    'representationHeadersDigest',
    'credentialed',
    'tlsInterception',
    'upstreamTlsVerified',
    'clientAddress',
    'clientPort',
    'proxyAddress',
    'proxyPort',
  ],
  [HTTP_EVIDENCE_RECORD_KINDS.response]: [
    ...COMMON_KEYS,
    'exchangeId',
    'status',
    'contentType',
    'contentEncoding',
    'headersDigest',
    'bodyDigest',
    'bodyBytes',
    'decodedBodyDigest',
    'decodedBodyBytes',
    'bodyComplete',
    'delivery',
    'rangeResponse',
    'upstreamAddress',
    'upstreamPort',
  ],
  [HTTP_EVIDENCE_RECORD_KINDS.redirect]: [
    ...COMMON_KEYS,
    'exchangeId',
    'status',
    'locationDisplayUrl',
    'locationDigest',
  ],
  [HTTP_EVIDENCE_RECORD_KINDS.stats]: [
    ...COMMON_KEYS,
    'complete',
    'requests',
    'responses',
    'redirects',
    'errors',
    'opaqueConnects',
    'incompleteBodies',
    'droppedRecords',
    'reviewOnlyRecords',
    'coverageGaps',
    'contentAssuranceGaps',
    'contentManifestDigest',
    'collectorImageDigest',
    'collectorAddonDigest',
    'collectorWrapperDigest',
  ],
});

export function validateHttpEvidenceRecord(input) {
  plainObject(input, 'HTTP evidence record');
  const expected = RECORD_KEYS[input.recordKind];
  if (!expected) {
    throw new TypeError(`unsupported HTTP evidence record kind: ${input.recordKind}`);
  }
  exactKeys(input, expected, 'HTTP evidence record');
  if (
    input.schemaVersion !== HTTP_EVIDENCE_SCHEMA_VERSION
    || input.apiVersion !== HTTP_EVIDENCE_API_VERSION
  ) {
    throw new TypeError('HTTP evidence record uses an unsupported contract version');
  }
  if (input.recordKind === HTTP_EVIDENCE_RECORD_KINDS.request) {
    const normalized = createHttpRequestEvidence(input);
    if (stableStringify(normalized) !== stableStringify(input)) {
      throw new TypeError('HTTP request evidence is not normalized');
    }
    return normalized;
  }
  if (input.recordKind === HTTP_EVIDENCE_RECORD_KINDS.response) {
    const normalized = createHttpResponseEvidence(input);
    if (stableStringify(normalized) !== stableStringify(input)) {
      throw new TypeError('HTTP response evidence is not normalized');
    }
    return normalized;
  }
  if (input.recordKind === HTTP_EVIDENCE_RECORD_KINDS.redirect) {
    const normalized = createHttpRedirectEvidence(input);
    if (stableStringify(normalized) !== stableStringify(input)) {
      throw new TypeError('HTTP redirect evidence is not normalized');
    }
    return normalized;
  }
  const normalized = createHttpCaptureStats(input);
  if (stableStringify(normalized) !== stableStringify(input)) {
    throw new TypeError('HTTP capture stats are not normalized');
  }
  return normalized;
}

export function parseHttpEvidenceNdjson(value, options = {}) {
  const maximumLineBytes = nonNegativeInteger(
    options.maximumLineBytes ?? HTTP_EVIDENCE_MAX_LINE_BYTES,
    'HTTP evidence maximumLineBytes',
  );
  const maximumRecords = nonNegativeInteger(
    options.maximumRecords ?? HTTP_EVIDENCE_MAX_RECORDS,
    'HTTP evidence maximumRecords',
  );
  if (maximumLineBytes < 1 || maximumRecords < 1) {
    throw new TypeError('HTTP evidence parser limits must be positive');
  }
  const text = Buffer.isBuffer(value) ? value.toString('utf8') : String(value);
  const records = [];
  for (const [index, line] of text.split('\n').entries()) {
    if (!line.trim()) continue;
    if (Buffer.byteLength(line, 'utf8') > maximumLineBytes) {
      throw new Error(`HTTP evidence line ${index + 1} exceeds its byte limit`);
    }
    if (records.length >= maximumRecords) {
      throw new Error('HTTP evidence record count exceeds its limit');
    }
    let record;
    try {
      record = JSON.parse(line);
    } catch (error) {
      throw new Error(`HTTP evidence line ${index + 1} is not valid JSON`, { cause: error });
    }
    records.push(validateHttpEvidenceRecord(record));
  }
  return records;
}

function relativeEvidenceFile(value) {
  if (typeof value !== 'string' || !value.trim() || value.startsWith('/')) {
    throw new TypeError('HTTP evidence source file must be relative');
  }
  const normalized = value.replaceAll('\\', '/').split('/');
  if (normalized.some((segment) => segment === '' || segment === '.' || segment === '..')) {
    throw new TypeError('HTTP evidence source file escapes or ambiguously names its bundle');
  }
  return normalized.join('/');
}

function verifyHttpStatsCounts(records, stats) {
  const expected = {
    requests: records.filter(
      (record) => record.recordKind === HTTP_EVIDENCE_RECORD_KINDS.request,
    ).length,
    responses: records.filter(
      (record) => record.recordKind === HTTP_EVIDENCE_RECORD_KINDS.response,
    ).length,
    redirects: records.filter(
      (record) => record.recordKind === HTTP_EVIDENCE_RECORD_KINDS.redirect,
    ).length,
  };
  if (
    stats.requests !== expected.requests
    || stats.responses !== expected.responses
    || stats.redirects !== expected.redirects
  ) {
    throw new Error('HTTP terminal stats do not match the normalized evidence records');
  }
  const expectedReviewOnly = stats.captureAuthority === 'review-only' ? records.length : 0;
  if (stats.reviewOnlyRecords !== expectedReviewOnly) {
    throw new Error('HTTP terminal stats review-only count does not match its evidence');
  }
}

function verifyHttpRecordSet(records, stats) {
  if (records.some((record) => (
    record.runId !== stats.runId
    || record.provider !== stats.provider
    || record.captureAuthority !== stats.captureAuthority
    || record.captureMode !== stats.captureMode
  ))) {
    throw new Error('HTTP evidence source mixes capture identities or authorities');
  }
  if (stats.captureAuthority === 'managed' && stats.provider !== 'mitmproxy') {
    throw new Error('complete managed HTTP evidence requires the managed mitmproxy provider');
  }
  const requests = new Map();
  const responses = new Map();
  const redirects = new Map();
  for (const record of records) {
    if (record.recordKind === HTTP_EVIDENCE_RECORD_KINDS.request) {
      if (requests.has(record.exchangeId)) {
        throw new Error(`duplicate HTTP request evidence: ${record.exchangeId}`);
      }
      requests.set(record.exchangeId, record);
    } else if (record.recordKind === HTTP_EVIDENCE_RECORD_KINDS.response) {
      if (responses.has(record.exchangeId)) {
        throw new Error(`duplicate HTTP response evidence: ${record.exchangeId}`);
      }
      responses.set(record.exchangeId, record);
    } else if (record.recordKind === HTTP_EVIDENCE_RECORD_KINDS.redirect) {
      if (redirects.has(record.exchangeId)) {
        throw new Error(`duplicate HTTP redirect evidence: ${record.exchangeId}`);
      }
      redirects.set(record.exchangeId, record);
    }
  }
  for (const [exchangeId, response] of responses) {
    if (!requests.has(exchangeId)) {
      throw new Error(`HTTP response evidence has no matching request: ${exchangeId}`);
    }
    const redirect = redirects.get(exchangeId);
    if (redirect && redirect.status !== response.status) {
      throw new Error(`HTTP redirect status mismatches its response: ${exchangeId}`);
    }
  }
  for (const exchangeId of redirects.keys()) {
    if (!requests.has(exchangeId) || !responses.has(exchangeId)) {
      throw new Error(`HTTP redirect evidence has no matching exchange: ${exchangeId}`);
    }
  }
  const missingResponses = [...requests.keys()]
    .filter((exchangeId) => !responses.has(exchangeId)).length;
  const incompleteResponses = [...responses.values()]
    .filter((response) => !response.bodyComplete).length;
  if (stats.incompleteBodies !== missingResponses + incompleteResponses) {
    throw new Error('HTTP incomplete-body stats do not match exchange evidence');
  }
  if (missingResponses > 0 && !stats.coverageGaps.includes('missing-response')) {
    throw new Error('HTTP evidence omits its missing-response coverage gap');
  }
  if (
    incompleteResponses > 0
    && !stats.coverageGaps.some((gap) => (
      gap === 'incomplete-response-body' || gap === 'streaming-response'
    ))
  ) {
    throw new Error('HTTP evidence omits its incomplete-response coverage gap');
  }
  if (
    [...responses.values()].some((response) => response.rangeResponse)
    && !stats.coverageGaps.includes('range-response')
  ) {
    throw new Error('HTTP evidence omits its range-response coverage gap');
  }
  if (stats.errors > 0 && !stats.coverageGaps.includes('capture-error')) {
    throw new Error('HTTP evidence omits its capture-error coverage gap');
  }
  if (stats.opaqueConnects > 0 && !stats.coverageGaps.includes('opaque-connect')) {
    throw new Error('HTTP evidence omits its opaque-connect coverage gap');
  }
  if (stats.droppedRecords > 0 && !stats.coverageGaps.includes('dropped-records')) {
    throw new Error('HTTP evidence omits its dropped-records coverage gap');
  }
  if (
    stats.complete
    && [...requests.keys()].some((exchangeId) => !responses.has(exchangeId))
  ) {
    throw new Error('complete HTTP evidence contains a request without a response');
  }
}

function verifyExpectedCollectorIdentity(stats, input) {
  if (stats.captureAuthority !== 'managed') return;
  const expected = plainObject(input.expectedCollectorIdentity, 'expected HTTP collector identity');
  exactKeys(expected, [
    'collectorImageDigest',
    'collectorAddonDigest',
    'collectorWrapperDigest',
  ], 'expected HTTP collector identity');
  for (const name of [
    'collectorImageDigest',
    'collectorAddonDigest',
    'collectorWrapperDigest',
  ]) {
    if (digest(expected[name], `expected HTTP ${name}`) !== stats[name]) {
      throw new Error(`managed HTTP collector identity mismatch: ${name}`);
    }
  }
}

export function createHttpEvidenceSourceDescriptor(input) {
  plainObject(input, 'HTTP evidence source descriptor input');
  const content = input.content == null
    ? null
    : (Buffer.isBuffer(input.content)
        ? input.content
        : Buffer.from(String(input.content), 'utf8'));
  const parsedContent = content == null ? null : parseHttpEvidenceNdjson(content);
  const records = input.records || parsedContent;
  if (!Array.isArray(records) || records.length < 1) {
    throw new TypeError('HTTP evidence source requires normalized records or NDJSON content');
  }
  const normalized = records.map((record) => validateHttpEvidenceRecord(record));
  if (
    parsedContent
    && input.records
    && stableStringify(normalized) !== stableStringify(parsedContent)
  ) {
    throw new Error('HTTP evidence source records do not match its NDJSON content');
  }
  const stats = normalized.filter(
    (record) => record.recordKind === HTTP_EVIDENCE_RECORD_KINDS.stats,
  );
  if (stats.length !== 1 || normalized.at(-1).recordKind !== HTTP_EVIDENCE_RECORD_KINDS.stats) {
    throw new Error('HTTP evidence source requires exactly one terminal capture stats record');
  }
  if (normalized.some((record) => record.runId !== stats[0].runId)) {
    throw new Error('HTTP evidence source mixes run identities');
  }
  verifyHttpStatsCounts(normalized, stats[0]);
  verifyHttpRecordSet(normalized, stats[0]);
  verifyExpectedCollectorIdentity(stats[0], input);
  const materializedContent = content || Buffer.from(
    `${normalized.map((record) => stableStringify(record)).join('\n')}\n`,
    'utf8',
  );
  const bytes = materializedContent.length;
  const contentHash = sha256(materializedContent);
  if (input.bytes != null && nonNegativeInteger(
    input.bytes,
    'HTTP evidence source bytes',
  ) !== bytes) {
    throw new Error('HTTP evidence source byte count does not match its content');
  }
  if (input.hash != null && digest(
    input.hash,
    'HTTP evidence source hash',
  ) !== contentHash) {
    throw new Error('HTTP evidence source hash does not match its content');
  }
  const complete = stats[0].complete === true
    && stats[0].captureAuthority === 'managed'
    && stats[0].captureMode === 'managed-proxy';
  return {
    name: 'http',
    format: 'ndjson',
    file: relativeEvidenceFile(input.file),
    required: input.required !== false,
    present: true,
    complete,
    bytes,
    records: normalized.length,
    hash: contentHash,
    lostEvents: stats[0].droppedRecords,
    parseErrors: stats[0].errors,
    completionMarker: complete
      ? 'nosh-http-capture-complete'
      : 'nosh-http-capture-incomplete',
    content: materializedContent,
  };
}

export function httpDownstreamCorrelationHint(input, options = {}) {
  const request = validateHttpEvidenceRecord(input);
  if (request.recordKind !== HTTP_EVIDENCE_RECORD_KINDS.request) {
    throw new TypeError('HTTP downstream correlation hints require request evidence');
  }
  if (
    request.clientAddress == null
    || request.clientPort == null
    || request.proxyAddress == null
    || request.proxyPort == null
  ) {
    return null;
  }
  const pass = options.pass || 'cold';
  if (!['cold', 'warm'].includes(pass)) {
    throw new TypeError('HTTP downstream correlation pass must be cold or warm');
  }
  return {
    exchangeId: request.exchangeId,
    pass,
    timestampUnixNs: String(BigInt(Date.parse(request.observedAt)) * 1_000_000n),
    source: {
      address: request.clientAddress,
      port: request.clientPort,
    },
    destination: {
      ip: request.proxyAddress,
      protocol: 'tcp',
      port: request.proxyPort,
    },
  };
}

function selectedExchangeValue(source, exchangeId) {
  if (typeof source === 'function') return source(exchangeId);
  if (source instanceof Map) return source.get(exchangeId);
  if (source && typeof source === 'object') return source[exchangeId];
  return undefined;
}

function reviewDisplayUrl(value) {
  const display = new URL(value);
  display.username = '';
  display.password = '';
  display.search = '';
  display.hash = '';
  const serialized = display.href;
  if (serialized.length < 1 || serialized.length > 8192) {
    throw new TypeError('canonical HTTP review display URL exceeds the 8192-character limit');
  }
  return serialized;
}

function reviewDestination(value) {
  if (value == null) return null;
  plainObject(value, 'HTTP authoritative destination');
  const ip = normalizeHostname(value.ip);
  if (!net.isIP(ip) || value.protocol !== 'tcp') {
    throw new TypeError('HTTP authoritative destination must be a TCP IP observation');
  }
  return {
    ip,
    protocol: 'tcp',
    port: portNumber(value.port, 'HTTP authoritative destination port'),
  };
}

function reviewIntegrity(value, contentDigest) {
  if (value == null) return null;
  plainObject(value, 'HTTP native integrity evidence');
  const selected = {
    kind: enumValue(
      value.kind,
      NATIVE_INTEGRITY_KINDS,
      'HTTP native integrity kind',
    ),
    contentSha256: digest(value.contentSha256, 'HTTP native integrity content digest'),
    verificationEvidenceSha256: digest(
      value.verificationEvidenceSha256,
      'HTTP native integrity verification evidence digest',
    ),
    verified: value.verified === true,
  };
  if (!selected.verified || selected.contentSha256 !== contentDigest) {
    throw new TypeError('HTTP native integrity must verify the observed response content');
  }
  return selected;
}

function reviewCas(value, contentDigest) {
  if (value == null) return null;
  plainObject(value, 'HTTP CAS evidence');
  const selected = {
    objectSha256: digest(value.objectSha256, 'HTTP CAS object digest'),
    manifestSha256: digest(value.manifestSha256, 'HTTP CAS manifest digest'),
    available: value.available === true,
  };
  if (!selected.available || selected.objectSha256 !== contentDigest) {
    throw new TypeError('HTTP CAS evidence must bind available observed response content');
  }
  return selected;
}

export function createBuildHttpObservations(records, options = {}) {
  if (!Array.isArray(records) || records.length < 1) {
    throw new TypeError('build HTTP observations require normalized records');
  }
  const normalized = records.map((record) => validateHttpEvidenceRecord(record));
  const statsRecords = normalized.filter(
    (record) => record.recordKind === HTTP_EVIDENCE_RECORD_KINDS.stats,
  );
  if (statsRecords.length !== 1 || normalized.at(-1).recordKind !== HTTP_EVIDENCE_RECORD_KINDS.stats) {
    throw new Error('build HTTP observations require exactly one terminal capture stats record');
  }
  const stats = statsRecords[0];
  if (!['mitmproxy', 'burp-har'].includes(stats.provider)) {
    throw new TypeError('build HTTP observations require mitmproxy or Burp HAR evidence');
  }
  verifyHttpStatsCounts(normalized, stats);
  verifyHttpRecordSet(normalized, stats);
  const passFor = (exchangeId) => (
    selectedExchangeValue(options.passByExchangeId, exchangeId)
    || options.pass
    || 'cold'
  );
  const responses = new Map();
  const redirects = new Map();
  for (const record of normalized) {
    if (record.recordKind === HTTP_EVIDENCE_RECORD_KINDS.response) {
      if (responses.has(record.exchangeId)) {
        throw new Error(`duplicate HTTP response evidence: ${record.exchangeId}`);
      }
      responses.set(record.exchangeId, record);
    } else if (record.recordKind === HTTP_EVIDENCE_RECORD_KINDS.redirect) {
      if (redirects.has(record.exchangeId)) {
        throw new Error(`duplicate HTTP redirect evidence: ${record.exchangeId}`);
      }
      redirects.set(record.exchangeId, record);
    }
  }
  const exchanges = [];
  const requestIds = new Set();
  for (const request of normalized) {
    if (request.recordKind !== HTTP_EVIDENCE_RECORD_KINDS.request) continue;
    if (requestIds.has(request.exchangeId)) {
      throw new Error(`duplicate HTTP request evidence: ${request.exchangeId}`);
    }
    requestIds.add(request.exchangeId);
    const pass = passFor(request.exchangeId);
    if (!['cold', 'warm'].includes(pass)) {
      throw new TypeError('HTTP build pass must be cold or warm');
    }
    if (
      request.method === 'CONNECT'
      || !/^[A-Z][A-Z0-9-]{0,31}$/.test(request.method)
    ) {
      throw new TypeError(`HTTP method cannot enter the build review contract: ${request.method}`);
    }
    const responseRecord = responses.get(request.exchangeId) || null;
    const redirectRecord = redirects.get(request.exchangeId) || null;
    let response = null;
    if (responseRecord) {
      response = {
        status: responseRecord.status,
        complete: responseRecord.bodyComplete,
        ...(responseRecord.bodyDigest ? { contentSha256: responseRecord.bodyDigest } : {}),
        ...(responseRecord.decodedBodyDigest
          ? { decodedContentSha256: responseRecord.decodedBodyDigest }
          : {}),
        ...(responseRecord.bodyBytes != null
          ? { length: String(responseRecord.bodyBytes) }
          : {}),
        ...(redirectRecord
          ? { redirectLocationSha256: redirectRecord.locationDigest }
          : {}),
      };
    }
    const observedMilliseconds = Date.parse(request.observedAt);
    const destination = reviewDestination(
      selectedExchangeValue(options.destinationByExchangeId, request.exchangeId),
    );
    const destinationRole = selectedExchangeValue(
      options.destinationRoleByExchangeId,
      request.exchangeId,
    ) ?? null;
    if (
      (destination === null && destinationRole !== null)
      || (
        destination !== null
        && !['workload-to-origin', 'workload-to-proxy'].includes(destinationRole)
      )
    ) {
      throw new TypeError('HTTP destination role must describe the authoritative L4 join');
    }
    const upstreamDestination = reviewDestination(
      selectedExchangeValue(options.upstreamDestinationByExchangeId, request.exchangeId)
      || (
        responseRecord?.upstreamAddress
          ? {
              ip: responseRecord.upstreamAddress,
              protocol: 'tcp',
              port: responseRecord.upstreamPort,
            }
          : null
      ),
    );
    const exchange = {
      id: request.exchangeId,
      pass,
      timestampUnixNs: String(BigInt(observedMilliseconds) * 1_000_000n),
      method: request.method,
      scheme: request.scheme,
      host: request.hostname,
      port: request.port,
      displayUrl: reviewDisplayUrl(request.displayUrl),
      requestTargetSha256: request.requestTargetDigest,
      representationHeadersSha256: request.representationHeadersDigest,
      ...(request.requestBodyDigest
        ? { requestBodySha256: request.requestBodyDigest }
        : {}),
      destination,
      destinationRole,
      ...(upstreamDestination ? { upstreamDestination } : {}),
      response,
    };
    const integrity = reviewIntegrity(
      selectedExchangeValue(options.integrityByExchangeId, request.exchangeId),
      response?.contentSha256,
    );
    const cas = reviewCas(
      selectedExchangeValue(options.casByExchangeId, request.exchangeId),
      response?.contentSha256,
    );
    if (integrity) exchange.integrity = integrity;
    if (cas) exchange.cas = cas;
    exchanges.push(exchange);
    if (exchanges.length > 100_000) {
      throw new Error('build HTTP observations exceed the 100000 exchange limit');
    }
  }
  const gaps = [...new Set(stats.coverageGaps)].sort();
  return {
    contractVersion: 2,
    provider: stats.provider === 'burp-har' ? 'burp' : 'mitmproxy',
    captureMode: stats.captureAuthority === 'managed' ? 'managed' : 'manual-import',
    required: options.required !== false,
    complete: stats.complete && gaps.length === 0,
    gaps,
    contentAssuranceGaps: [...stats.contentAssuranceGaps],
    exchanges: exchanges.sort((left, right) => left.id.localeCompare(right.id)),
  };
}

function headerValue(headers, name) {
  const selected = normalizedHeaderEntries(headers)
    .find(([headerName]) => headerName === name);
  return selected?.[1] || null;
}

function harBody(content, maximumBytes, label) {
  if (!content || typeof content !== 'object' || typeof content.text !== 'string') {
    return null;
  }
  let body;
  if (content.encoding == null) {
    body = Buffer.from(content.text, 'utf8');
  } else if (content.encoding === 'base64') {
    const compact = content.text.replace(/[\t\n\r ]+/g, '');
    if (!/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(compact)) {
      throw new TypeError(`${label} is not canonical base64`);
    }
    body = Buffer.from(compact, 'base64');
  } else {
    throw new TypeError(`unsupported HAR content encoding: ${content.encoding}`);
  }
  if (body.length > maximumBytes) {
    throw new TypeError(`${label} exceeds the ${maximumBytes} byte import limit`);
  }
  return body;
}

export function normalizeBurpHarImport(input, options = {}) {
  const har = plainObject(input, 'Burp HAR import');
  const log = plainObject(har.log, 'Burp HAR log');
  if (!Array.isArray(log.entries)) {
    throw new TypeError('Burp HAR log entries must be an array');
  }
  const maximumEntries = nonNegativeInteger(
    options.maximumEntries ?? HTTP_HAR_MAX_ENTRIES,
    'Burp HAR maximumEntries',
  );
  const maximumBodyBytes = nonNegativeInteger(
    options.maximumBodyBytes ?? HTTP_HAR_MAX_BODY_BYTES,
    'Burp HAR maximumBodyBytes',
  );
  if (
    maximumEntries < 1
    || maximumEntries > HTTP_HAR_MAX_ENTRIES
    || maximumBodyBytes < 1
    || maximumBodyBytes > HTTP_HAR_MAX_BODY_BYTES
  ) {
    throw new TypeError('Burp HAR import limits are outside the supported bounds');
  }
  if (log.entries.length > maximumEntries) {
    throw new TypeError(`Burp HAR exceeds the ${maximumEntries} entry import limit`);
  }
  const runId = normalizeRunId(options.runId);
  const importedAt = timestamp(
    options.importedAt || new Date().toISOString(),
    'Burp HAR import timestamp',
  );
  const records = [];
  let requests = 0;
  let responses = 0;
  let redirects = 0;
  let errors = 0;
  let incompleteBodies = 0;
  for (const [index, entry] of log.entries.entries()) {
    const recordCheckpoint = records.length;
    const counterCheckpoint = { requests, responses, redirects, incompleteBodies };
    try {
      plainObject(entry, `Burp HAR entry ${index}`);
      const request = plainObject(entry.request, `Burp HAR request ${index}`);
      const observedAt = timestamp(
        entry.startedDateTime || importedAt,
        `Burp HAR entry ${index} timestamp`,
      );
      const rawRequestBody = request.postData?.text == null
        ? null
        : harBody({
            text: String(request.postData.text),
            encoding: request.postData.encoding,
          }, maximumBodyBytes, `Burp HAR request body ${index}`);
      const normalizedUrl = normalizeObservedUrl(request.url);
      const exchangeId = sha256(stableStringify([
        runId,
        index,
        observedAt,
        request.method,
        normalizedUrl.scheme,
        normalizedUrl.hostname,
        normalizedUrl.port,
        normalizedUrl.requestTargetDigest,
      ]));
      records.push(createHttpRequestEvidence({
        runId,
        observedAt,
        provider: 'burp-har',
        captureAuthority: 'review-only',
        captureMode: 'manual-import',
        exchangeId,
        url: request.url,
        method: request.method,
        headers: request.headers || [],
        requestBody: rawRequestBody,
        requestBodyDigest: rawRequestBody == null ? null : undefined,
        requestBodyBytes: rawRequestBody == null ? null : undefined,
        tlsInterception: normalizedUrl.scheme === 'https' ? 'intercepted' : 'plaintext',
        upstreamTlsVerified: null,
      }));
      requests += 1;
      if (!entry.response || typeof entry.response !== 'object') {
        incompleteBodies += 1;
        continue;
      }
      const response = entry.response;
      const decodedBody = harBody(
        response.content,
        maximumBodyBytes,
        `Burp HAR response body ${index}`,
      );
      const contentType = response.content?.mimeType || headerValue(response.headers, 'content-type');
      const contentEncoding = headerValue(response.headers, 'content-encoding');
      records.push(createHttpResponseEvidence({
        runId,
        observedAt,
        provider: 'burp-har',
        captureAuthority: 'review-only',
        captureMode: 'manual-import',
        exchangeId,
        status: response.status,
        contentType,
        contentEncoding,
        headersDigest: null,
        bodyDigest: null,
        bodyBytes: null,
        decodedBody,
        bodyComplete: false,
        delivery: 'manual-import',
        rangeResponse: Number(response.status) === 206,
      }));
      responses += 1;
      incompleteBodies += 1;
      const location = response.redirectURL || headerValue(response.headers, 'location');
      if (location) {
        records.push(createHttpRedirectEvidence({
          runId,
          observedAt,
          provider: 'burp-har',
          captureAuthority: 'review-only',
          captureMode: 'manual-import',
          exchangeId,
          status: response.status,
          location,
          baseUrl: request.url,
        }));
        redirects += 1;
      }
    } catch {
      records.length = recordCheckpoint;
      ({ requests, responses, redirects, incompleteBodies } = counterCheckpoint);
      errors += 1;
    }
  }
  const coverageGaps = new Set(['manual-import']);
  if (errors) coverageGaps.add('capture-error');
  if (incompleteBodies) coverageGaps.add('incomplete-response-body');
  if (responses < requests) coverageGaps.add('missing-response');
  if (records.some((record) => (
    record.recordKind === HTTP_EVIDENCE_RECORD_KINDS.response
    && record.rangeResponse
  ))) coverageGaps.add('range-response');
  records.push(createHttpCaptureStats({
    runId,
    observedAt: importedAt,
    provider: 'burp-har',
    captureAuthority: 'review-only',
    captureMode: 'manual-import',
    complete: false,
    requests,
    responses,
    redirects,
    errors,
    opaqueConnects: 0,
    incompleteBodies,
    droppedRecords: 0,
    reviewOnlyRecords: records.length + 1,
    coverageGaps: [...coverageGaps],
    contentAssuranceGaps: ['manual-import'],
    contentManifestDigest: null,
  }));
  return records;
}

export function httpRequestIdentity(input) {
  plainObject(input, 'HTTP request identity input');
  const record = input.recordKind === HTTP_EVIDENCE_RECORD_KINDS.request
    ? validateHttpEvidenceRecord(input)
    : input;
  if (typeof record.credentialed !== 'boolean') {
    throw new TypeError('HTTP request identity requires an explicit credentialed classification');
  }
  const identity = {
    method: normalizeMethod(record.method),
    scheme: normalizeScheme(record.scheme),
    hostname: normalizeHostname(record.hostname),
    port: portNumber(record.port),
    requestTargetDigest: digest(record.requestTargetDigest, 'HTTP requestTargetDigest'),
    requestBodyDigest: digest(record.requestBodyDigest, 'HTTP requestBodyDigest', { nullable: true }),
    representationHeadersDigest: digest(
      record.representationHeadersDigest,
      'HTTP representationHeadersDigest',
    ),
    credentialed: record.credentialed,
  };
  return identity;
}

export function httpRequestIdentityKey(input) {
  return sha256(stableStringify(httpRequestIdentity(input)));
}
