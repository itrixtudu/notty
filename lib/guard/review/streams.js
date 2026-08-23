import path from 'node:path';

import {
  REVIEW_LIMITS,
  STREAM_ROLES,
  STREAM_SCHEMAS,
} from './constants.js';
import { jcsCanonicalize, sha256Digest } from './jcs.js';
import { assertSha256 } from './ids.js';
import { validateGraphRecord } from './records.js';
import {
  assertDecimal,
  assertEnum,
  assertStrictObject,
  assertString,
} from './validation.js';

function decimalToSafeNumber(value, pathLabel) {
  assertDecimal(value, pathLabel);
  const number = Number(value);
  if (!Number.isSafeInteger(number)) {
    throw new TypeError(`${pathLabel} exceeds the supported local stream size`);
  }
  return number;
}

export function validateStreamDescriptor(descriptor, pathLabel = '$') {
  assertStrictObject(descriptor, {
    required: ['role', 'path', 'schema', 'sha256', 'bytes', 'records'],
  }, pathLabel);
  assertEnum(descriptor.role, STREAM_ROLES, `${pathLabel}.role`);
  assertString(descriptor.path, `${pathLabel}.path`, {
    maxBytes: 512,
    pattern: /^streams\/[a-z]+\.[a-f0-9]{64}\.ndjson$/,
  });
  if (
    path.posix.isAbsolute(descriptor.path)
    || descriptor.path.split('/').includes('..')
  ) {
    throw new TypeError(`${pathLabel}.path must stay beneath the bundle`);
  }
  if (descriptor.schema !== STREAM_SCHEMAS[descriptor.role]) {
    throw new TypeError(`${pathLabel}.schema does not match its stream role`);
  }
  assertSha256(descriptor.sha256, `${pathLabel}.sha256`);
  const bytes = decimalToSafeNumber(descriptor.bytes, `${pathLabel}.bytes`);
  const records = decimalToSafeNumber(descriptor.records, `${pathLabel}.records`);
  if (bytes > REVIEW_LIMITS.maxStreamBytes) {
    throw new TypeError(`${pathLabel}.bytes exceeds the stream limit`);
  }
  if (records > REVIEW_LIMITS.maxRecordsPerStream) {
    throw new TypeError(`${pathLabel}.records exceeds the record limit`);
  }
  const expectedPath = `streams/${descriptor.role}.${descriptor.sha256.slice('sha256:'.length)}.ndjson`;
  if (descriptor.path !== expectedPath) {
    throw new TypeError(`${pathLabel}.path is not hash-addressed by its content`);
  }
  return descriptor;
}

export function createHashAddressedStream(role, records) {
  assertEnum(role, STREAM_ROLES, 'stream role');
  if (!Array.isArray(records)) {
    throw new TypeError('stream records must be an array');
  }
  if (records.length > REVIEW_LIMITS.maxRecordsPerStream) {
    throw new TypeError('stream exceeds the record limit');
  }
  const sorted = [...records].sort((left, right) => left.id.localeCompare(right.id));
  const seen = new Set();
  const lines = sorted.map((record, index) => {
    validateGraphRecord(role, record, `$[${index}]`);
    if (seen.has(record.id)) {
      throw new TypeError(`stream contains duplicate record ID ${record.id}`);
    }
    seen.add(record.id);
    const line = jcsCanonicalize(record);
    if (Buffer.byteLength(line, 'utf8') > REVIEW_LIMITS.maxLineBytes) {
      throw new TypeError(`stream record ${record.id} exceeds the line byte limit`);
    }
    return line;
  });
  const content = lines.length > 0 ? `${lines.join('\n')}\n` : '';
  const contentBytes = Buffer.from(content, 'utf8');
  if (contentBytes.length > REVIEW_LIMITS.maxStreamBytes) {
    throw new TypeError('stream exceeds the byte limit');
  }
  const digest = sha256Digest(contentBytes);
  const descriptor = {
    role,
    path: `streams/${role}.${digest.slice('sha256:'.length)}.ndjson`,
    schema: STREAM_SCHEMAS[role],
    sha256: digest,
    bytes: String(contentBytes.length),
    records: String(sorted.length),
  };
  validateStreamDescriptor(descriptor);
  return Object.freeze({
    descriptor: Object.freeze(descriptor),
    content,
    records: Object.freeze(sorted),
  });
}

export function parseHashAddressedStream(role, content, descriptor) {
  assertEnum(role, STREAM_ROLES, 'stream role');
  validateStreamDescriptor(descriptor, 'descriptor');
  if (descriptor.role !== role) {
    throw new TypeError('stream role does not match its descriptor');
  }
  const bytes = Buffer.isBuffer(content) ? content : Buffer.from(String(content), 'utf8');
  if (bytes.length > REVIEW_LIMITS.maxStreamBytes) {
    throw new TypeError('stream exceeds the byte limit');
  }
  if (String(bytes.length) !== descriptor.bytes) {
    throw new TypeError('stream byte count does not match its descriptor');
  }
  if (sha256Digest(bytes) !== descriptor.sha256) {
    throw new TypeError('stream digest does not match its descriptor');
  }
  if (bytes.length === 0) {
    if (descriptor.records !== '0') {
      throw new TypeError('empty stream has a non-zero record count');
    }
    return Object.freeze([]);
  }
  const text = bytes.toString('utf8');
  if (text.charCodeAt(0) === 0xfeff) {
    throw new TypeError('stream must not contain a byte-order mark');
  }
  if (!text.endsWith('\n')) {
    throw new TypeError('non-empty NDJSON stream must end with one newline');
  }
  const lines = text.slice(0, -1).split('\n');
  if (lines.length > REVIEW_LIMITS.maxRecordsPerStream) {
    throw new TypeError('stream exceeds the record limit');
  }
  if (String(lines.length) !== descriptor.records) {
    throw new TypeError('stream record count does not match its descriptor');
  }
  const records = [];
  let previousId = null;
  for (let index = 0; index < lines.length; index += 1) {
    const line = lines[index];
    if (!line) {
      throw new TypeError(`stream line ${index + 1} is empty`);
    }
    if (Buffer.byteLength(line, 'utf8') > REVIEW_LIMITS.maxLineBytes) {
      throw new TypeError(`stream line ${index + 1} exceeds the byte limit`);
    }
    let record;
    try {
      record = JSON.parse(line);
    } catch (error) {
      throw new TypeError(`stream line ${index + 1} is not valid JSON: ${error.message}`);
    }
    validateGraphRecord(role, record, `$[${index}]`);
    if (jcsCanonicalize(record) !== line) {
      throw new TypeError(`stream line ${index + 1} is not JCS canonical JSON`);
    }
    if (previousId !== null && previousId >= record.id) {
      throw new TypeError('stream record IDs must be unique and sorted');
    }
    previousId = record.id;
    records.push(Object.freeze(record));
  }
  return Object.freeze(records);
}
