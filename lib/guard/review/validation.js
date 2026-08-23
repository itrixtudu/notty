import {
  DECIMAL_PATTERN,
  PRIVACY_CLASSES,
  RECORD_PRIVACY_CLASSES,
  REVIEW_LIMITS,
  SAFE_TOKEN_PATTERN,
} from './constants.js';
import { sha256Digest } from './jcs.js';
import { assertSha256, assertStableId } from './ids.js';

const DATE_TIME_PATTERN = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?(?:Z|[+-]\d{2}:\d{2})$/;
const JSON_POINTER_PATTERN = /^(?:\/(?:[^~/]|~[01])*)+$/;
const FORBIDDEN_KEYS = new Set(['__proto__', 'prototype', 'constructor']);
const PROTECTED_PRIVACY_PATHS = new Set([
  '/apiVersion',
  '/kind',
  '/schemaVersion',
  '/id',
  '/scopeDigest',
  '/subjectId',
  '/objectId',
  '/privacy',
]);
const PORTABLE_FIELD_ROOTS = new Set([
  'identity',
  'properties',
  'label',
  'message',
  'rationale',
]);

export function assertPlainObject(value, path = '$') {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    throw new TypeError(`${path} must be an object`);
  }
  const prototype = Object.getPrototypeOf(value);
  if (prototype !== Object.prototype && prototype !== null) {
    throw new TypeError(`${path} must be a plain object`);
  }
  return value;
}

export function assertStrictObject(
  value,
  { required = [], optional = [] } = {},
  path = '$',
) {
  assertPlainObject(value, path);
  const allowed = new Set([...required, ...optional]);
  for (const key of Object.keys(value)) {
    if (!allowed.has(key)) {
      throw new TypeError(`${path}.${key} is not allowed`);
    }
  }
  for (const key of required) {
    if (!Object.hasOwn(value, key)) {
      throw new TypeError(`${path}.${key} is required`);
    }
  }
  return value;
}

export function assertString(value, path, options = {}) {
  const {
    minBytes = 1,
    maxBytes = REVIEW_LIMITS.maxStringBytes,
    pattern,
  } = options;
  if (typeof value !== 'string') {
    throw new TypeError(`${path} must be a string`);
  }
  const bytes = Buffer.byteLength(value, 'utf8');
  if (bytes < minBytes || bytes > maxBytes) {
    throw new TypeError(`${path} must be between ${minBytes} and ${maxBytes} UTF-8 bytes`);
  }
  if (value.includes('\0')) {
    throw new TypeError(`${path} must not contain NUL`);
  }
  if (pattern && !pattern.test(value)) {
    throw new TypeError(`${path} has an invalid format`);
  }
  return value;
}

export function assertNullableString(value, path, options = {}) {
  if (value === null) {
    return value;
  }
  return assertString(value, path, options);
}

export function assertEnum(value, allowed, path) {
  if (!allowed.includes(value)) {
    throw new TypeError(`${path} must be one of: ${allowed.join(', ')}`);
  }
  return value;
}

export function assertBoolean(value, path) {
  if (typeof value !== 'boolean') {
    throw new TypeError(`${path} must be a boolean`);
  }
  return value;
}

export function assertDecimal(value, path) {
  if (typeof value !== 'string' || !DECIMAL_PATTERN.test(value)) {
    throw new TypeError(`${path} must be an unsigned decimal string`);
  }
  return value;
}

export function assertDateTime(value, path) {
  assertString(value, path, { maxBytes: 64, pattern: DATE_TIME_PATTERN });
  if (!Number.isFinite(Date.parse(value))) {
    throw new TypeError(`${path} must be an RFC 3339 timestamp`);
  }
  return value;
}

export function assertArray(value, path, options = {}) {
  const {
    minItems = 0,
    maxItems = REVIEW_LIMITS.maxArrayItems,
  } = options;
  if (!Array.isArray(value)) {
    throw new TypeError(`${path} must be an array`);
  }
  if (value.length < minItems || value.length > maxItems) {
    throw new TypeError(`${path} must contain between ${minItems} and ${maxItems} items`);
  }
  return value;
}

export function assertUniqueStrings(value, path, options = {}) {
  assertArray(value, path, options);
  const seen = new Set();
  let previous = null;
  for (let index = 0; index < value.length; index += 1) {
    assertString(value[index], `${path}[${index}]`, options.string || {});
    if (seen.has(value[index])) {
      throw new TypeError(`${path} contains a duplicate value`);
    }
    if (options.sorted && previous !== null && previous > value[index]) {
      throw new TypeError(`${path} must be sorted`);
    }
    seen.add(value[index]);
    previous = value[index];
  }
  return value;
}

export function assertStableIdArray(value, path, options = {}) {
  assertArray(value, path, {
    maxItems: REVIEW_LIMITS.maxEvidenceRefs,
    ...options,
  });
  const seen = new Set();
  let previous = null;
  for (let index = 0; index < value.length; index += 1) {
    assertStableId(value[index], `${path}[${index}]`);
    if (seen.has(value[index])) {
      throw new TypeError(`${path} contains a duplicate ID`);
    }
    if (options.sorted && previous !== null && previous > value[index]) {
      throw new TypeError(`${path} must be sorted by ID`);
    }
    seen.add(value[index]);
    previous = value[index];
  }
  return value;
}

export function assertJsonBounds(value, path = '$', depth = 0) {
  if (depth > REVIEW_LIMITS.maxJsonDepth) {
    throw new TypeError(`${path} exceeds maximum JSON depth`);
  }
  if (value === null || typeof value === 'boolean') {
    return value;
  }
  if (typeof value === 'string') {
    return assertString(value, path, { minBytes: 0 });
  }
  if (typeof value === 'number') {
    if (!Number.isFinite(value)) {
      throw new TypeError(`${path} must be finite`);
    }
    if (Number.isInteger(value) && !Number.isSafeInteger(value)) {
      throw new TypeError(`${path} unsafe integers must be decimal strings`);
    }
    return value;
  }
  if (Array.isArray(value)) {
    assertArray(value, path);
    value.forEach((entry, index) => assertJsonBounds(entry, `${path}[${index}]`, depth + 1));
    return value;
  }
  assertPlainObject(value, path);
  const keys = Object.keys(value);
  if (keys.length > REVIEW_LIMITS.maxObjectProperties) {
    throw new TypeError(`${path} has too many properties`);
  }
  for (const key of keys) {
    assertString(key, `${path} key`, { minBytes: 1, maxBytes: 256 });
    if (FORBIDDEN_KEYS.has(key)) {
      throw new TypeError(`${path}.${key} uses a forbidden property name`);
    }
    assertJsonBounds(value[key], `${path}.${key}`, depth + 1);
  }
  return value;
}

export function assertScope(scope, path = '$.scope') {
  assertStrictObject(scope, {
    required: ['class', 'subjectId', 'scopeDigest'],
    optional: [
      'projectKey',
      'platform',
      'target',
      'dockerfileDigest',
      'imageDigest',
      'workspaceDigest',
    ],
  }, path);
  assertEnum(scope.class, ['build', 'runtime'], `${path}.class`);
  assertStableId(scope.subjectId, `${path}.subjectId`);
  assertSha256(scope.scopeDigest, `${path}.scopeDigest`);
  if (Object.hasOwn(scope, 'projectKey')) {
    assertString(scope.projectKey, `${path}.projectKey`, {
      maxBytes: 128,
      pattern: /^(?:[a-f0-9]{64}|sha256:[a-f0-9]{64})$/,
    });
  }
  if (Object.hasOwn(scope, 'platform')) {
    assertString(scope.platform, `${path}.platform`, { maxBytes: 128 });
  }
  if (Object.hasOwn(scope, 'target')) {
    assertNullableString(scope.target, `${path}.target`, { maxBytes: 256 });
  }
  for (const key of ['dockerfileDigest', 'imageDigest', 'workspaceDigest']) {
    if (Object.hasOwn(scope, key) && scope[key] !== null) {
      assertSha256(scope[key], `${path}.${key}`);
    }
  }
  const { scopeDigest, ...identity } = scope;
  if (sha256Digest(identity) !== scopeDigest) {
    throw new TypeError(`${path}.scopeDigest does not match the scope identity`);
  }
  return scope;
}

export function assertPrivacy(privacy, owner, path = '$.privacy') {
  assertStrictObject(privacy, {
    required: ['classification', 'fields'],
  }, path);
  assertEnum(
    privacy.classification,
    RECORD_PRIVACY_CLASSES,
    `${path}.classification`,
  );
  assertArray(privacy.fields, `${path}.fields`, { maxItems: 256 });
  const seen = new Set();
  let previous = null;
  for (let index = 0; index < privacy.fields.length; index += 1) {
    const field = privacy.fields[index];
    const fieldPath = `${path}.fields[${index}]`;
    assertStrictObject(field, { required: ['path', 'class'] }, fieldPath);
    assertString(field.path, `${fieldPath}.path`, {
      maxBytes: 512,
      pattern: JSON_POINTER_PATTERN,
    });
    assertEnum(field.class, PRIVACY_CLASSES, `${fieldPath}.class`);
    if (PROTECTED_PRIVACY_PATHS.has(field.path)) {
      throw new TypeError(`${fieldPath}.path targets an identity or integrity field`);
    }
    const pointerTokens = decodeJsonPointer(field.path);
    if (!PORTABLE_FIELD_ROOTS.has(pointerTokens[0])) {
      throw new TypeError(`${fieldPath}.path must target a display or payload field`);
    }
    if (
      ['identity', 'properties'].includes(pointerTokens[0])
      && pointerTokens.length < 2
    ) {
      throw new TypeError(`${fieldPath}.path must target a field within its payload object`);
    }
    if (seen.has(field.path)) {
      throw new TypeError(`${path}.fields contains a duplicate path`);
    }
    if (previous !== null && previous > field.path) {
      throw new TypeError(`${path}.fields must be sorted by JSON pointer`);
    }
    seen.add(field.path);
    previous = field.path;
    if (field.class === 'never-store' && jsonPointerExists(owner, field.path)) {
      throw new TypeError(`${fieldPath}.path marks a value that must never be stored`);
    }
  }
  return privacy;
}

export function decodeJsonPointer(pointer) {
  if (!JSON_POINTER_PATTERN.test(pointer)) {
    throw new TypeError('invalid JSON pointer');
  }
  return pointer.slice(1).split('/').map((token) => (
    token.replace(/~1/g, '/').replace(/~0/g, '~')
  ));
}

export function jsonPointerExists(value, pointer) {
  let cursor = value;
  for (const token of decodeJsonPointer(pointer)) {
    if (!cursor || typeof cursor !== 'object' || !Object.hasOwn(cursor, token)) {
      return false;
    }
    cursor = cursor[token];
  }
  return true;
}

export function assertSafeToken(value, path) {
  return assertString(value, path, { maxBytes: 256, pattern: SAFE_TOKEN_PATTERN });
}

export function assertNullableSha256(value, path) {
  if (value !== null) {
    assertSha256(value, path);
  }
  return value;
}
