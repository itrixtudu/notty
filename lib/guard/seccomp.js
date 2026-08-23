import { asEvidence, validationResult } from './artifact-utils.js';
import { canonicalize, isPlainObject, sortedUniqueStrings } from './stable.js';

const VALID_ACTIONS = new Set([
  'SCMP_ACT_ALLOW',
  'SCMP_ACT_ERRNO',
  'SCMP_ACT_KILL',
  'SCMP_ACT_KILL_PROCESS',
  'SCMP_ACT_KILL_THREAD',
  'SCMP_ACT_LOG',
  'SCMP_ACT_NOTIFY',
  'SCMP_ACT_TRACE',
  'SCMP_ACT_TRAP',
]);
const DANGEROUS_SYSCALLS = new Set([
  'bpf',
  'delete_module',
  'finit_module',
  'init_module',
  'kexec_file_load',
  'kexec_load',
  'mount',
  'open_by_handle_at',
  'perf_event_open',
  'ptrace',
  'setns',
  'swapon',
  'swapoff',
  'umount',
  'umount2',
  'unshare',
  'userfaultfd',
]);

function validSyscallName(name) {
  return /^[a-zA-Z0-9_]+$/.test(name);
}

function normalizeArchitecture(value) {
  const raw = String(value || '').trim();
  const architecture = raw.toLowerCase();
  const aliases = {
    x64: 'SCMP_ARCH_X86_64',
    x86_64: 'SCMP_ARCH_X86_64',
    amd64: 'SCMP_ARCH_X86_64',
    ia32: 'SCMP_ARCH_X86',
    x86: 'SCMP_ARCH_X86',
    arm64: 'SCMP_ARCH_AARCH64',
    aarch64: 'SCMP_ARCH_AARCH64',
    arm: 'SCMP_ARCH_ARM',
  };
  if (aliases[architecture]) {
    return aliases[architecture];
  }
  return /^SCMP_ARCH_[A-Z0-9_]+$/.test(raw) ? raw : '';
}

function advisedSeccompProfiles(evidence) {
  return (evidence.advisoryEvidence || [])
    .filter((entry) => entry?.domain === 'seccomp')
    .map((entry) => entry.value?.profile || entry.value)
    .filter(
      (profile) =>
        isPlainObject(profile) &&
        typeof profile.defaultAction === 'string' &&
        Array.isArray(profile.syscalls),
    );
}

export function compileSeccompArtifact(evidenceInput, options = {}) {
  const evidence = asEvidence(evidenceInput, options);
  const advisedProfiles = advisedSeccompProfiles(evidence);
  const names = sortedUniqueStrings([
    ...(evidence.observations.syscalls || []).map((entry) => entry.name),
    ...advisedProfiles.flatMap((profile) =>
      profile.syscalls
        .filter((group) => group?.action === 'SCMP_ACT_ALLOW')
        .flatMap((group) => group.names || []),
    ),
    ...(options.baselineSyscalls || []),
  ]).filter(validSyscallName);
  const architectures = sortedUniqueStrings([
    ...(evidence.observations.syscalls || []).flatMap(
      (entry) => entry.architectures || [],
    ),
    ...advisedProfiles.flatMap((profile) => profile.architectures || []),
    ...(options.seccompArchitectures || []),
    ...(options.architecture ? [options.architecture] : []),
  ].map(normalizeArchitecture));
  return canonicalize({
    defaultAction: 'SCMP_ACT_ERRNO',
    defaultErrnoRet: 1,
    ...(architectures.length ? { architectures } : {}),
    syscalls: names.length
      ? [{
        names,
        action: 'SCMP_ACT_ALLOW',
      }]
      : [],
  });
}

export function validateSeccompArtifact(artifact) {
  const errors = [];
  const warnings = [];
  if (!isPlainObject(artifact)) {
    return validationResult(
      ['seccomp artifact must be an object'],
      [],
      { enforceable: false, runtimeValidationRequired: true },
    );
  }
  if (!VALID_ACTIONS.has(artifact.defaultAction)) {
    errors.push('seccomp defaultAction is missing or unsupported');
  }
  if (artifact.defaultAction === 'SCMP_ACT_ALLOW') {
    errors.push('seccomp candidate must use a deny-by-default action');
  }
  if (!Array.isArray(artifact.syscalls)) {
    errors.push('seccomp syscalls must be an array');
  }
  const seen = new Set();
  const allowed = [];
  for (const group of artifact.syscalls || []) {
    if (!isPlainObject(group) || !VALID_ACTIONS.has(group.action)) {
      errors.push('each seccomp syscall group must have a supported action');
      continue;
    }
    if (!Array.isArray(group.names) || !group.names.length) {
      errors.push('each seccomp syscall group must contain names');
      continue;
    }
    for (const name of group.names) {
      if (typeof name !== 'string' || !validSyscallName(name)) {
        errors.push('seccomp syscall names must contain only letters, digits, and underscores');
        continue;
      }
      if (seen.has(name)) {
        errors.push(`seccomp syscall ${name} appears more than once`);
      }
      seen.add(name);
      if (group.action === 'SCMP_ACT_ALLOW') {
        allowed.push(name);
      }
    }
  }
  const dangerous = sortedUniqueStrings(
    allowed.filter((name) => DANGEROUS_SYSCALLS.has(name)),
  );
  if (dangerous.length) {
    warnings.push(`review dangerous allowed syscalls: ${dangerous.join(', ')}`);
  }
  if (!allowed.length) {
    warnings.push('seccomp allowlist is empty; the container will not start successfully');
  }
  if (!Array.isArray(artifact.architectures) || !artifact.architectures.length) {
    warnings.push('seccomp architecture is implicit; validate on every target architecture');
  }
  warnings.push('validate the seccomp profile with Docker on a disposable container before approval');
  const enforceable = errors.length === 0
    && artifact.defaultAction !== 'SCMP_ACT_ALLOW'
    && allowed.length > 0;
  return validationResult(errors, warnings, {
    enforceable,
    runtimeValidationRequired: true,
  });
}
