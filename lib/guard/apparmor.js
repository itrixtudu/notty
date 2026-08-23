import {
  asEvidence,
  isSafeAbsolutePath,
  profileName,
  validationResult,
} from './artifact-utils.js';
import { sortedUniqueStrings } from './stable.js';

function quoteAppArmorPath(value) {
  return JSON.stringify(String(value));
}

function capabilityName(value) {
  return String(value)
    .toLowerCase()
    .replace(/^cap_/, '');
}

function fileRules(evidence) {
  const rules = new Set();
  for (const executable of evidence.observations.executables || []) {
    if (!isSafeAbsolutePath(executable.path)) {
      continue;
    }
    const path = quoteAppArmorPath(executable.path);
    rules.add(`  ${path} mr,`);
    rules.add(`  ${path} ix,`);
  }
  for (const file of evidence.observations.files || []) {
    if (!isSafeAbsolutePath(file.path)) {
      continue;
    }
    const path = quoteAppArmorPath(file.path);
    const operations = new Set(file.operations || []);
    if (operations.has('read')) {
      rules.add(`  ${path} r,`);
    }
    if (
      operations.has('write')
      || operations.has('create')
      || operations.has('delete')
      || operations.has('rename')
    ) {
      rules.add(`  ${path} rwlk,`);
    }
    if (operations.has('execute')) {
      rules.add(`  ${path} mr,`);
      rules.add(`  ${path} ix,`);
    }
  }
  return Array.from(rules).sort();
}

function networkRules(evidence) {
  const rules = new Set();
  for (const entry of evidence.observations.network || []) {
    if (entry.protocol === 'tcp' || entry.protocol === 'any') {
      rules.add('  network inet stream,');
      rules.add('  network inet6 stream,');
    }
    if (entry.protocol === 'udp' || entry.protocol === 'any') {
      rules.add('  network inet dgram,');
      rules.add('  network inet6 dgram,');
    }
    if (entry.protocol === 'icmp' || entry.protocol === 'any') {
      rules.add('  network inet raw,');
      rules.add('  network inet6 raw,');
    }
  }
  return Array.from(rules).sort();
}

export function compileAppArmorArtifact(evidenceInput, options = {}) {
  const evidence = asEvidence(evidenceInput, options);
  const name = profileName(evidence, options);
  const capabilities = sortedUniqueStrings(
    (evidence.observations.capabilities || []).map(
      (entry) => capabilityName(typeof entry === 'string' ? entry : entry.name),
    ),
  ).filter((entry) => /^[a-z0-9_]+$/.test(entry));
  const rules = [
    ...fileRules(evidence),
    ...networkRules(evidence),
    ...capabilities.map((capability) => `  capability ${capability},`),
  ].sort();
  return [
    '#include <tunables/global>',
    '',
    `profile ${name} flags=(attach_disconnected,mediate_deleted) {`,
    '  # This is a generated candidate. Parse, exercise, and approve it before loading.',
    '  #include <abstractions/base>',
    ...(rules.length ? ['', ...rules] : []),
    '}',
    '',
  ].join('\n');
}

export function validateAppArmorArtifact(artifact) {
  const errors = [];
  const warnings = [];
  if (typeof artifact !== 'string') {
    return validationResult(
      ['AppArmor artifact must be text'],
      [],
      { enforceable: false, runtimeValidationRequired: true },
    );
  }
  if (artifact.includes('\0')) {
    errors.push('AppArmor artifact contains a NUL byte');
  }
  const profiles = [
    ...artifact.matchAll(
      /^profile ([a-z0-9]([-a-z0-9]*[a-z0-9])?) flags=\(([^)]*)\) \{$/gm,
    ),
  ];
  const profile = profiles[0];
  if (profiles.length !== 1) {
    errors.push('AppArmor artifact must contain exactly one named profile');
  }
  const supportedLines = [
    /^\s*$/,
    /^\s*#(?!include\b)/,
    /^#include <tunables\/global>$/,
    /^  #include <abstractions\/base>$/,
    /^profile [a-z0-9](?:[-a-z0-9]*[a-z0-9])? flags=\(attach_disconnected,mediate_deleted\) \{$/,
    /^  "(?:[^"\\]|\\.)+" [rwmilkx]+,$/,
    /^  network (?:inet|inet6) (?:stream|dgram|raw),$/,
    /^  capability [a-z0-9_]+,$/,
    /^}$/,
  ];
  const unsupported = artifact
    .split(/\r?\n/)
    .filter((line) => !supportedLines.some((pattern) => pattern.test(line)));
  if (unsupported.length) {
    errors.push(
      'AppArmor artifact contains syntax outside the generated profile subset',
    );
  }
  const legacyProfile = artifact.match(
    /^profile ([a-z0-9]([-a-z0-9]*[a-z0-9])?) flags=\(([^)]*)\) \{$/m,
  );
  if (!legacyProfile) {
    errors.push('AppArmor artifact must contain one supported profile header');
  }
  if (/\bcomplain\b/.test(legacyProfile?.[3] || '')) {
    errors.push('AppArmor candidate must not use complain mode');
  }
  if (/^\s*\/\*\*\s+.*(?:w|x|m)/m.test(artifact)) {
    errors.push('AppArmor artifact must not grant a global write or execute wildcard');
  }
  if (!artifact.trimEnd().endsWith('}')) {
    errors.push('AppArmor profile is not closed');
  }
  const ruleLines = artifact
    .split('\n')
    .filter((line) => /^\s+(?:".*"|network |capability )/.test(line));
  if (!ruleLines.length) {
    warnings.push('AppArmor profile has no evidence-derived rules');
  }
  if (artifact.includes('#include <abstractions/base>')) {
    warnings.push('review permissions inherited from the AppArmor base abstraction');
  }
  warnings.push('validate the profile with aa-parser on the target host before approval');
  return validationResult(errors, warnings, {
    enforceable: errors.length === 0 && profiles.length === 1,
    runtimeValidationRequired: true,
  });
}
