import { cloneCanonicalJson, sha256Digest } from './jcs.js';
import { validateGraphRecord } from './records.js';
import { decodeJsonPointer, jsonPointerExists } from './validation.js';

function pointerParent(value, pointer) {
  const tokens = decodeJsonPointer(pointer);
  const leaf = tokens.pop();
  let cursor = value;
  for (const token of tokens) {
    if (!cursor || typeof cursor !== 'object' || !Object.hasOwn(cursor, token)) {
      return null;
    }
    cursor = cursor[token];
  }
  if (!cursor || typeof cursor !== 'object' || !Object.hasOwn(cursor, leaf)) {
    return null;
  }
  return { parent: cursor, leaf };
}

function assertPortableSalt(salt) {
  if (typeof salt !== 'string' || Buffer.byteLength(salt, 'utf8') < 16) {
    throw new TypeError('portable hashing requires a salt of at least 16 UTF-8 bytes');
  }
}

export function projectPortableRecord(role, record, options = {}) {
  validateGraphRecord(role, record);
  if (record.privacy.classification === 'private') {
    return null;
  }
  const projected = cloneCanonicalJson(record);
  for (const field of projected.privacy.fields) {
    if (field.class === 'never-store') {
      if (jsonPointerExists(projected, field.path)) {
        throw new TypeError(`never-store field is present at ${field.path}`);
      }
      continue;
    }
    if (field.class !== 'private' && field.class !== 'portable-hashed') {
      continue;
    }
    const location = pointerParent(projected, field.path);
    if (!location) {
      continue;
    }
    if (field.class === 'private') {
      location.parent[location.leaf] = '[redacted]';
      continue;
    }
    assertPortableSalt(options.salt);
    location.parent[location.leaf] = sha256Digest({
      salt: options.salt,
      value: location.parent[location.leaf],
    });
  }
  projected.privacy.classification = 'portable-sensitive';
  validateGraphRecord(role, projected);
  return Object.freeze(projected);
}

export function projectPortableRecords(role, records, options = {}) {
  if (!Array.isArray(records)) {
    throw new TypeError('records must be an array');
  }
  return Object.freeze(records
    .map((record) => projectPortableRecord(role, record, options))
    .filter(Boolean)
    .sort((left, right) => (left.id < right.id ? -1 : left.id > right.id ? 1 : 0)));
}
