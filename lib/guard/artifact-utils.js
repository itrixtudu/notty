import { normalizeEvidence, isNormalizedEvidence } from './evidence.js';
import {
  sanitizeDnsLabel,
  sortedUniqueStrings,
} from './stable.js';

export function asEvidence(value, options = {}) {
  return isNormalizedEvidence(value) ? value : normalizeEvidence(value, options);
}

export function profileName(evidence, options = {}) {
  const base = sanitizeDnsLabel(
    options.name || evidence?.metadata?.name || evidence?.subject?.name || 'nosh',
    'nosh',
  );
  return sanitizeDnsLabel(`nosh-guard-${base}`, 'nosh-guard-profile');
}

export function validationResult(errors = [], warnings = [], extra = {}) {
  const normalizedErrors = sortedUniqueStrings(errors);
  const normalizedWarnings = sortedUniqueStrings(warnings);
  return {
    valid: normalizedErrors.length === 0,
    errors: normalizedErrors,
    warnings: normalizedWarnings,
    ...extra,
  };
}

export function isSafeAbsolutePath(value) {
  return typeof value === 'string'
    && value.startsWith('/')
    && !value.includes('\0')
    && !value.includes('\n')
    && !value.includes('\r');
}

export function cloneJson(value) {
  return value === undefined ? undefined : JSON.parse(JSON.stringify(value));
}
