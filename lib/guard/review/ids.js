import {
  SHA256_PATTERN,
  STABLE_ID_PATTERN,
} from './constants.js';
import { jcsCanonicalize, sha256Digest } from './jcs.js';

const NAMESPACE_PATTERN = /^[a-z][a-z0-9-]{0,31}$/;

export function createStableId(namespace, semanticKey) {
  if (!NAMESPACE_PATTERN.test(namespace)) {
    throw new TypeError('stable ID namespace must be a lowercase token of at most 32 characters');
  }
  return `${namespace}:${sha256Digest(jcsCanonicalize(semanticKey)).slice('sha256:'.length)}`;
}

export function assertStableId(value, label = 'ID') {
  if (typeof value !== 'string' || !STABLE_ID_PATTERN.test(value)) {
    throw new TypeError(`${label} must be a namespaced SHA-256 stable ID`);
  }
  return value;
}

export function assertSha256(value, label = 'digest') {
  if (typeof value !== 'string' || !SHA256_PATTERN.test(value)) {
    throw new TypeError(`${label} must be a sha256:<hex> digest`);
  }
  return value;
}

export function createScope(input) {
  if (!input || typeof input !== 'object' || Array.isArray(input)) {
    throw new TypeError('scope must be an object');
  }
  const { scopeDigest: ignored, ...identity } = input;
  return Object.freeze({
    ...identity,
    scopeDigest: sha256Digest(identity),
  });
}

export function createSourceId(passId, sourceName, sourceDigest) {
  return createStableId('source', { passId, sourceName, sourceDigest });
}

export function createSourceRecordId(sourceId, ordinal) {
  return createStableId('record', { sourceId, ordinal: String(ordinal) });
}
