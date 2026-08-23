import crypto from 'node:crypto';

export function isPlainObject(value) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    return false;
  }
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

export function canonicalize(value) {
  if (Array.isArray(value)) {
    return value.map((entry) => canonicalize(entry));
  }
  if (!isPlainObject(value)) {
    return value;
  }
  return Object.fromEntries(
    Object.keys(value)
      .sort()
      .map((key) => [key, canonicalize(value[key])]),
  );
}

export function stableStringify(value, space = 0) {
  return JSON.stringify(canonicalize(value), null, space);
}

export function sha256(value) {
  const input = Buffer.isBuffer(value) ? value : Buffer.from(String(value), 'utf8');
  return `sha256:${crypto.createHash('sha256').update(input).digest('hex')}`;
}

export function compareCanonical(left, right) {
  const leftText = stableStringify(left);
  const rightText = stableStringify(right);
  if (leftText === rightText) {
    return 0;
  }
  return leftText < rightText ? -1 : 1;
}

export function sortedUniqueStrings(values) {
  return Array.from(new Set(
    values
      .filter((value) => typeof value === 'string')
      .map((value) => value.trim())
      .filter(Boolean),
  )).sort();
}

export function sanitizeDnsLabel(value, fallback = 'profile') {
  const sanitized = String(value || '')
    .toLowerCase()
    .replace(/[^a-z0-9-]+/g, '-')
    .replace(/-+/g, '-')
    .replace(/^-|-$/g, '')
    .slice(0, 63)
    .replace(/-$/g, '');
  return sanitized || fallback;
}

export function serializeJson(value) {
  return `${stableStringify(value, 2)}\n`;
}

export function ensureTrailingNewline(value) {
  const text = String(value);
  return text.endsWith('\n') ? text : `${text}\n`;
}

export function escapeHtml(value) {
  return String(value)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}
