import crypto from 'node:crypto';

import { jcsCanonicalize, sha256Digest } from './jcs.js';

export const REVIEW_APPROVAL_PAYLOAD_TYPE =
  'application/vnd.notty.review-approval.v1+json';
export const GATEWAY_GRANT_PAYLOAD_TYPE =
  'application/vnd.notty.gateway-grant.v1+json';
export const DEPLOYMENT_GRANT_PAYLOAD_TYPE =
  'application/vnd.notty.deployment-grant.v1+json';
export const MAX_GATEWAY_GRANT_SECONDS = 24 * 60 * 60;
export const MAX_DEPLOYMENT_GRANT_SECONDS = MAX_GATEWAY_GRANT_SECONDS;

const DIGEST_PATTERN = /^sha256:[a-f0-9]{64}$/;
const MAX_DSSE_PAYLOAD_BYTES = 8 * 1024 * 1024;
const MAX_DSSE_SIGNATURES = 16;

function exactKeys(value, allowed, label) {
  for (const key of Object.keys(value)) {
    if (!allowed.has(key)) {
      throw new TypeError(`${label} contains unsupported field ${key}`);
    }
  }
}

function plainObject(value, label) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    throw new TypeError(`${label} must be an object`);
  }
  return value;
}

function nonEmptyString(value, label, maximum = 1024) {
  if (
    typeof value !== 'string'
    || !value.trim()
    || value.length > maximum
    || /[\u0000-\u001f\u007f]/.test(value)
  ) {
    throw new TypeError(`${label} must be a bounded non-empty string`);
  }
  return value;
}

function digest(value, label, nullable = false) {
  if (nullable && value == null) return null;
  if (typeof value !== 'string' || !DIGEST_PATTERN.test(value)) {
    throw new TypeError(`${label} must be an exact sha256 digest`);
  }
  return value;
}

function timestamp(value, label) {
  const milliseconds = Date.parse(value);
  if (typeof value !== 'string' || !Number.isFinite(milliseconds)) {
    throw new TypeError(`${label} must be an ISO-compatible timestamp`);
  }
  return new Date(milliseconds).toISOString();
}

function normalizedKeyObject(input, kind) {
  let key;
  try {
    if (input instanceof crypto.KeyObject) {
      if (kind === 'private') {
        if (input.type !== 'private') {
          throw new TypeError('expected a private KeyObject');
        }
        key = input;
      } else {
        key = input.type === 'public' ? input : crypto.createPublicKey(input);
      }
    } else {
      key = kind === 'private'
        ? crypto.createPrivateKey(input)
        : crypto.createPublicKey(input);
    }
  } catch (error) {
    throw new TypeError(`invalid Ed25519 ${kind} key`, { cause: error });
  }
  if (key.asymmetricKeyType !== 'ed25519') {
    throw new TypeError(`${kind} key must be Ed25519`);
  }
  return key;
}

function encodedLength(value) {
  return Buffer.byteLength(String(value), 'utf8');
}

export function dssePreAuthEncoding(payloadType, payload) {
  const selectedType = nonEmptyString(payloadType, 'DSSE payload type', 255);
  const selectedPayload = Buffer.isBuffer(payload)
    ? payload
    : Buffer.from(payload);
  if (selectedPayload.length > MAX_DSSE_PAYLOAD_BYTES) {
    throw new TypeError('DSSE payload exceeds the byte limit');
  }
  return Buffer.concat([
    Buffer.from(
      `DSSEv1 ${encodedLength(selectedType)} ${selectedType} ${selectedPayload.length} `,
      'utf8',
    ),
    selectedPayload,
  ]);
}

export function ed25519KeyId(keyInput) {
  const publicKey = normalizedKeyObject(keyInput, 'public');
  const der = publicKey.export({ type: 'spki', format: 'der' });
  return sha256Digest(der);
}

export function generateEd25519KeyPair() {
  const { privateKey, publicKey } = crypto.generateKeyPairSync('ed25519');
  const privateKeyPem = privateKey.export({ type: 'pkcs8', format: 'pem' });
  const publicKeyPem = publicKey.export({ type: 'spki', format: 'pem' });
  return {
    keyId: ed25519KeyId(publicKey),
    privateKeyPem,
    publicKeyPem,
  };
}

export function createDsseEnvelope(payloadType, statement, privateKeyInput) {
  plainObject(statement, 'DSSE statement');
  const privateKey = normalizedKeyObject(privateKeyInput, 'private');
  const publicKey = crypto.createPublicKey(privateKey);
  const payload = Buffer.from(jcsCanonicalize(statement), 'utf8');
  const signature = crypto.sign(
    null,
    dssePreAuthEncoding(payloadType, payload),
    privateKey,
  );
  return {
    payloadType: nonEmptyString(payloadType, 'DSSE payload type', 255),
    payload: payload.toString('base64'),
    signatures: [{
      keyid: ed25519KeyId(publicKey),
      sig: signature.toString('base64'),
    }],
  };
}

function decodeBase64(value, label, maximumBytes) {
  if (
    typeof value !== 'string'
    || !value
    || value.length > Math.ceil(maximumBytes * 4 / 3) + 8
    || !/^[A-Za-z0-9+/]+={0,2}$/.test(value)
  ) {
    throw new TypeError(`${label} must be bounded canonical base64`);
  }
  const decoded = Buffer.from(value, 'base64');
  if (
    decoded.length > maximumBytes
    || decoded.toString('base64') !== value
  ) {
    throw new TypeError(`${label} must be bounded canonical base64`);
  }
  return decoded;
}

function normalizeTrustedKey(entry) {
  plainObject(entry, 'trusted key');
  exactKeys(
    entry,
    new Set(['publicKey', 'publicKeyPem', 'keyId', 'roles', 'audiences']),
    'trusted key',
  );
  if (entry.publicKey != null && entry.publicKeyPem != null) {
    throw new TypeError('trusted key must use exactly one public key field');
  }
  const publicKey = normalizedKeyObject(
    entry.publicKey || entry.publicKeyPem,
    'public',
  );
  const keyId = ed25519KeyId(publicKey);
  if (entry.keyId != null && entry.keyId !== keyId) {
    throw new TypeError('trusted key ID does not match its public key');
  }
  if (entry.roles != null && !Array.isArray(entry.roles)) {
    throw new TypeError('trusted key roles must be an array');
  }
  if (entry.audiences != null && !Array.isArray(entry.audiences)) {
    throw new TypeError('trusted key audiences must be an array');
  }
  const selectedRoles = (entry.roles || []).map(
    (role) => nonEmptyString(role, 'key role', 64),
  );
  const selectedAudiences = (entry.audiences || []).map(
    (audience) => nonEmptyString(audience, 'key audience', 255),
  );
  if (new Set(selectedRoles).size !== selectedRoles.length) {
    throw new TypeError('trusted key roles must be unique');
  }
  if (new Set(selectedAudiences).size !== selectedAudiences.length) {
    throw new TypeError('trusted key audiences must be unique');
  }
  const roles = selectedRoles.sort();
  const audiences = selectedAudiences.sort();
  return { keyId, publicKey, roles, audiences };
}

export function verifyDsseEnvelope(envelope, options = {}) {
  plainObject(envelope, 'DSSE envelope');
  exactKeys(
    envelope,
    new Set(['payloadType', 'payload', 'signatures']),
    'DSSE envelope',
  );
  const payloadType = nonEmptyString(
    envelope.payloadType,
    'DSSE payload type',
    255,
  );
  if (options.payloadType && payloadType !== options.payloadType) {
    throw new Error(`unexpected DSSE payload type: ${payloadType}`);
  }
  const payload = decodeBase64(
    envelope.payload,
    'DSSE payload',
    MAX_DSSE_PAYLOAD_BYTES,
  );
  if (
    !Array.isArray(envelope.signatures)
    || envelope.signatures.length < 1
    || envelope.signatures.length > MAX_DSSE_SIGNATURES
  ) {
    throw new TypeError('DSSE envelope must contain bounded signatures');
  }
  let statement;
  try {
    statement = JSON.parse(payload.toString('utf8'));
  } catch (error) {
    throw new TypeError('DSSE payload is not JSON', { cause: error });
  }
  if (jcsCanonicalize(statement) !== payload.toString('utf8')) {
    throw new Error('DSSE payload is not JCS canonical');
  }
  plainObject(statement, 'DSSE statement');
  const trustedKeys = (options.trustedKeys || []).map(normalizeTrustedKey);
  if (!trustedKeys.length) {
    throw new TypeError('at least one trusted Ed25519 key is required');
  }
  if (new Set(trustedKeys.map((key) => key.keyId)).size !== trustedKeys.length) {
    throw new TypeError('trusted Ed25519 key IDs must be unique');
  }
  const signatures = new Map();
  for (const entry of envelope.signatures) {
    plainObject(entry, 'DSSE signature');
    exactKeys(entry, new Set(['keyid', 'sig']), 'DSSE signature');
    const keyId = digest(entry.keyid, 'DSSE signature key ID');
    if (signatures.has(keyId)) {
      throw new TypeError(`duplicate DSSE signature key ID: ${keyId}`);
    }
    signatures.set(
      keyId,
      decodeBase64(entry.sig, 'DSSE signature', 256),
    );
  }
  const pae = dssePreAuthEncoding(payloadType, payload);
  const verifiedKeys = [];
  for (const key of trustedKeys) {
    const signature = signatures.get(key.keyId);
    if (!signature || !crypto.verify(null, pae, key.publicKey, signature)) {
      continue;
    }
    if (options.role && !key.roles.includes(options.role)) {
      continue;
    }
    if (
      options.audience
      && !key.audiences.includes(options.audience)
    ) {
      continue;
    }
    verifiedKeys.push({
      keyId: key.keyId,
      roles: key.roles,
      audiences: key.audiences,
    });
  }
  if (!verifiedKeys.length) {
    throw new Error('DSSE envelope has no valid trusted signature');
  }
  return {
    payloadType,
    payloadDigest: sha256Digest(payload),
    envelopeDigest: sha256Digest(jcsCanonicalize(envelope)),
    statement,
    verifiedKeys,
  };
}

export function validateReviewApprovalStatement(statement, options = {}) {
  plainObject(statement, 'review approval statement');
  const normalized = createReviewApprovalStatement(statement);
  if (jcsCanonicalize(normalized) !== jcsCanonicalize(statement)) {
    throw new Error('review approval statement is not normalized');
  }
  if (options.audience && normalized.audience !== options.audience) {
    throw new Error('review approval audience does not match this deployment');
  }
  return normalized;
}

export function createReviewApprovalStatement(input) {
  plainObject(input, 'review approval input');
  return {
    apiVersion: 'notty.dev/v1alpha1',
    kind: 'NoshReviewApprovalStatement',
    schemaVersion: 1,
    issuedAt: timestamp(input.issuedAt || new Date().toISOString(), 'issuedAt'),
    reviewer: nonEmptyString(input.reviewer, 'reviewer', 255),
    audience: nonEmptyString(input.audience, 'audience', 255),
    bundleDigest: digest(input.bundleDigest, 'bundleDigest'),
    graphDigest: digest(input.graphDigest, 'graphDigest'),
    proposalSetDigest: digest(input.proposalSetDigest, 'proposalSetDigest'),
    decisionSetDigest: digest(input.decisionSetDigest, 'decisionSetDigest'),
    policyIrDigest: digest(input.policyIrDigest, 'policyIrDigest'),
    targetReviewSetDigest: digest(
      input.targetReviewSetDigest,
      'targetReviewSetDigest',
    ),
    baselineDigest: digest(input.baselineDigest, 'baselineDigest', true),
    scopeDigest: digest(input.scopeDigest, 'scopeDigest'),
    confirmationDigest: digest(input.confirmationDigest, 'confirmationDigest'),
  };
}

export function createGatewayGrantStatement(input, options = {}) {
  plainObject(input, 'gateway grant input');
  const now = options.now instanceof Date
    ? new Date(options.now.getTime())
    : new Date(options.now ?? input.issuedAt ?? Date.now());
  if (Number.isNaN(now.getTime())) {
    throw new TypeError('gateway grant clock is invalid');
  }
  if (
    input.issuedAt != null
    && timestamp(input.issuedAt, 'issuedAt') !== now.toISOString()
  ) {
    throw new TypeError('gateway grant issuedAt does not match its signing clock');
  }
  const notBefore = new Date(
    Date.parse(input.notBefore || now.toISOString()),
  );
  const expiresAt = new Date(
    Date.parse(input.expiresAt || new Date(
      notBefore.getTime() + MAX_GATEWAY_GRANT_SECONDS * 1000,
    ).toISOString()),
  );
  const lifetime = (expiresAt.getTime() - notBefore.getTime()) / 1000;
  const issuanceLifetime = (expiresAt.getTime() - now.getTime()) / 1000;
  if (
    !Number.isFinite(lifetime)
    || lifetime <= 0
    || lifetime > MAX_GATEWAY_GRANT_SECONDS
    || issuanceLifetime > MAX_GATEWAY_GRANT_SECONDS
    || notBefore.getTime() < now.getTime()
  ) {
    throw new TypeError(
      `gateway grant must not predate issuance or expire more than ${MAX_GATEWAY_GRANT_SECONDS} seconds after issuance`,
    );
  }
  return {
    apiVersion: 'notty.dev/v1alpha1',
    kind: 'NoshGatewayGrantStatement',
    schemaVersion: 1,
    issuedAt: now.toISOString(),
    notBefore: notBefore.toISOString(),
    expiresAt: expiresAt.toISOString(),
    nonce: nonEmptyString(input.nonce || crypto.randomUUID(), 'nonce', 128),
    audience: nonEmptyString(input.audience, 'audience', 255),
    target: nonEmptyString(input.target, 'target', 64),
    leafBundleDigest: digest(input.leafBundleDigest, 'leafBundleDigest'),
    approvalEnvelopeDigest: digest(
      input.approvalEnvelopeDigest,
      'approvalEnvelopeDigest',
    ),
    targetBindingDigest: digest(input.targetBindingDigest, 'targetBindingDigest'),
    capabilityDigest: digest(input.capabilityDigest, 'capabilityDigest'),
    activeGrantSetDigest: digest(input.activeGrantSetDigest, 'activeGrantSetDigest'),
    renderedArtifactsDigest: digest(
      input.renderedArtifactsDigest,
      'renderedArtifactsDigest',
    ),
  };
}

export function validateGatewayGrantStatement(statement, options = {}) {
  plainObject(statement, 'gateway grant statement');
  const normalized = createGatewayGrantStatement(statement, {
    now: new Date(statement.issuedAt),
  });
  if (jcsCanonicalize(normalized) !== jcsCanonicalize(statement)) {
    throw new Error('gateway grant statement is not normalized');
  }
  const now = options.now instanceof Date
    ? options.now.getTime()
    : Number(options.now ?? Date.now());
  if (!Number.isFinite(now)) {
    throw new TypeError('gateway grant verification clock is invalid');
  }
  if (Date.parse(normalized.notBefore) > now) {
    throw new Error('gateway grant is not active yet');
  }
  if (Date.parse(normalized.expiresAt) <= now) {
    throw new Error('gateway grant expired');
  }
  if (options.audience && normalized.audience !== options.audience) {
    throw new Error('gateway grant audience does not match this gateway');
  }
  if (options.target && normalized.target !== options.target) {
    throw new Error('gateway grant target does not match this backend');
  }
  return normalized;
}

export function createDeploymentGrantStatement(input, options = {}) {
  plainObject(input, 'deployment grant input');
  const gatewayShape = createGatewayGrantStatement(input, options);
  return {
    ...gatewayShape,
    kind: 'NoshDeploymentGrantStatement',
    subjectBindingDigest: digest(
      input.subjectBindingDigest,
      'subjectBindingDigest',
    ),
    backendAbi: nonEmptyString(input.backendAbi, 'backendAbi', 64),
  };
}

export function validateDeploymentGrantStatement(statement, options = {}) {
  plainObject(statement, 'deployment grant statement');
  const normalized = createDeploymentGrantStatement(statement, {
    now: new Date(statement.issuedAt),
  });
  if (jcsCanonicalize(normalized) !== jcsCanonicalize(statement)) {
    throw new Error('deployment grant statement is not normalized');
  }
  const now = options.now instanceof Date
    ? options.now.getTime()
    : Number(options.now ?? Date.now());
  if (!Number.isFinite(now)) throw new TypeError('deployment grant verification clock is invalid');
  if (Date.parse(normalized.notBefore) > now) throw new Error('deployment grant is not active yet');
  if (Date.parse(normalized.expiresAt) <= now) throw new Error('deployment grant expired');
  if (options.audience && normalized.audience !== options.audience) {
    throw new Error('deployment grant audience does not match this backend');
  }
  if (options.target && normalized.target !== options.target) {
    throw new Error('deployment grant target does not match this backend');
  }
  if (options.backendAbi && normalized.backendAbi !== options.backendAbi) {
    throw new Error('deployment grant ABI does not match this backend');
  }
  if (
    options.subjectBindingDigest
    && normalized.subjectBindingDigest !== options.subjectBindingDigest
  ) {
    throw new Error('deployment grant subject does not match this workload');
  }
  return normalized;
}
