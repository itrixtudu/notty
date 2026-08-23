import crypto from 'node:crypto';

import { REVIEW_LIMITS } from './constants.js';

function assertUnicodeScalarString(value, path) {
  for (let index = 0; index < value.length; index += 1) {
    const codeUnit = value.charCodeAt(index);
    if (codeUnit >= 0xd800 && codeUnit <= 0xdbff) {
      const next = value.charCodeAt(index + 1);
      if (!Number.isInteger(next) || next < 0xdc00 || next > 0xdfff) {
        throw new TypeError(`${path} contains an unpaired high surrogate`);
      }
      index += 1;
    } else if (codeUnit >= 0xdc00 && codeUnit <= 0xdfff) {
      throw new TypeError(`${path} contains an unpaired low surrogate`);
    }
  }
}

function canonicalizeValue(value, path, ancestors) {
  if (value === null || typeof value === 'boolean') {
    return JSON.stringify(value);
  }
  if (typeof value === 'string') {
    assertUnicodeScalarString(value, path);
    if (Buffer.byteLength(value, 'utf8') > REVIEW_LIMITS.maxStringBytes) {
      throw new TypeError(`${path} exceeds the maximum string byte length`);
    }
    return JSON.stringify(value);
  }
  if (typeof value === 'number') {
    if (!Number.isFinite(value)) {
      throw new TypeError(`${path} must be a finite JSON number`);
    }
    return JSON.stringify(value);
  }
  if (typeof value !== 'object' || ArrayBuffer.isView(value)) {
    throw new TypeError(`${path} is not an I-JSON value`);
  }
  if (ancestors.has(value)) {
    throw new TypeError(`${path} contains a circular reference`);
  }
  const prototype = Object.getPrototypeOf(value);
  if (prototype !== Object.prototype && prototype !== null && !Array.isArray(value)) {
    throw new TypeError(`${path} must contain only plain JSON objects`);
  }
  ancestors.add(value);
  let result;
  if (Array.isArray(value)) {
    result = `[${value.map((entry, index) => (
      canonicalizeValue(entry, `${path}[${index}]`, ancestors)
    )).join(',')}]`;
  } else {
    const keys = Object.keys(value).sort();
    result = `{${keys.map((key) => {
      assertUnicodeScalarString(key, `${path} key`);
      if (Buffer.byteLength(key, 'utf8') > 256) {
        throw new TypeError(`${path} contains an object key longer than 256 UTF-8 bytes`);
      }
      if (value[key] === undefined) {
        throw new TypeError(`${path}.${key} must not be undefined`);
      }
      return `${JSON.stringify(key)}:${canonicalizeValue(
        value[key],
        `${path}.${key}`,
        ancestors,
      )}`;
    }).join(',')}}`;
  }
  ancestors.delete(value);
  return result;
}

// RFC 8785 JSON Canonicalization Scheme for I-JSON-compatible JavaScript values.
export function jcsCanonicalize(value) {
  return canonicalizeValue(value, '$', new Set());
}

export function sha256Digest(value) {
  const bytes = Buffer.isBuffer(value)
    ? value
    : Buffer.from(typeof value === 'string' ? value : jcsCanonicalize(value), 'utf8');
  return `sha256:${crypto.createHash('sha256').update(bytes).digest('hex')}`;
}

export function cloneCanonicalJson(value) {
  return JSON.parse(jcsCanonicalize(value));
}

export function digestWithoutFields(value, fields = ['contentDigest']) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    throw new TypeError('digest input must be an object');
  }
  const omitted = new Set(fields);
  return sha256Digest(Object.fromEntries(
    Object.entries(value).filter(([key]) => !omitted.has(key)),
  ));
}
