import { asEvidence, cloneJson, profileName, validationResult } from './artifact-utils.js';
import {
  canonicalize,
  isPlainObject,
  sortedUniqueStrings,
} from './stable.js';

const ENFORCEMENT_ACTIONS = new Set([
  'Override',
  'Sigkill',
  'Signal',
]);
const LOW_LEVEL_SCOPE_FIELDS = new Set([
  'matchBinaries',
  'matchNamespaces',
  'matchPIDs',
]);

function monitorSelector(binaries) {
  const selector = {
    matchActions: [{ action: 'Post' }],
  };
  if (binaries.length) {
    selector.matchBinaries = [{
      operator: 'In',
      values: binaries,
    }];
  }
  return selector;
}

function explicitEnforcementRules(options) {
  const tetragonOptions = isPlainObject(options.tetragon) ? options.tetragon : {};
  const rules = tetragonOptions.enforcementRules || options.tetragonEnforcementRules;
  const reviewed = tetragonOptions.reviewedEnforcement === true
    || options.reviewedTetragonEnforcement === true;
  if (!reviewed || !isPlainObject(rules)) {
    return {};
  }
  const supported = ['kprobes', 'lsmhooks', 'tracepoints', 'uprobes'];
  return Object.fromEntries(
    supported
      .filter((key) => Array.isArray(rules[key]) && rules[key].length)
      .map((key) => [key, cloneJson(rules[key])]),
  );
}

export function compileTetragonArtifact(evidenceInput, options = {}) {
  const evidence = asEvidence(evidenceInput, options);
  const binaries = sortedUniqueStrings(
    (evidence.observations.executables || []).map((entry) => entry.path),
  );
  const syscalls = sortedUniqueStrings([
    ...(evidence.observations.syscalls || []).map((entry) => entry.name),
    ...((evidence.observations.executables || []).length ? ['execve'] : []),
    ...((evidence.observations.files || []).length ? ['openat'] : []),
    ...((evidence.observations.network || []).some((entry) => entry.direction === 'egress')
      ? ['connect']
      : []),
    ...((evidence.observations.network || []).some((entry) => entry.direction === 'ingress')
      ? ['accept4']
      : []),
    ...(options.baselineSyscalls || []),
  ]);
  const maxSyscalls = Number.isInteger(options.maxTetragonSyscalls)
    && options.maxTetragonSyscalls > 0
    ? options.maxTetragonSyscalls
    : 256;
  const selectors = [monitorSelector(binaries)];
  const observedKprobes = syscalls
    .slice(0, maxSyscalls)
    .map((call) => ({
      call: call.startsWith('sys_') ? call : `sys_${call}`,
      syscall: true,
      selectors,
    }));
  const enforcementRules = explicitEnforcementRules(options);
  const kprobes = [
    ...observedKprobes,
    ...(enforcementRules.kprobes || []),
  ];

  return canonicalize({
    apiVersion: 'cilium.io/v1alpha1',
    kind: 'TracingPolicy',
    metadata: {
      name: profileName(evidence, options),
      annotations: {
        'notty.dev/candidate': 'true',
        'notty.dev/enforcement-source': Object.keys(enforcementRules).length
          ? 'operator-provided'
          : 'none',
        'notty.dev/review-required': 'true',
      },
    },
    spec: {
      options: [{
        name: 'policy-mode',
        value: 'monitor',
      }],
      ...(kprobes.length ? { kprobes } : {}),
      ...(enforcementRules.lsmhooks ? { lsmhooks: enforcementRules.lsmhooks } : {}),
      ...(enforcementRules.tracepoints ? { tracepoints: enforcementRules.tracepoints } : {}),
      ...(enforcementRules.uprobes ? { uprobes: enforcementRules.uprobes } : {}),
    },
  });
}

function policyMode(artifact) {
  const option = artifact?.spec?.options?.find((entry) => entry?.name === 'policy-mode');
  return option?.value;
}

function hooks(artifact) {
  return [
    ...(Array.isArray(artifact?.spec?.kprobes) ? artifact.spec.kprobes : []),
    ...(Array.isArray(artifact?.spec?.lsmhooks) ? artifact.spec.lsmhooks : []),
    ...(Array.isArray(artifact?.spec?.tracepoints) ? artifact.spec.tracepoints : []),
    ...(Array.isArray(artifact?.spec?.uprobes) ? artifact.spec.uprobes : []),
  ];
}

function selectorScope(selector) {
  return Array.from(LOW_LEVEL_SCOPE_FIELDS).some(
    (field) => Array.isArray(selector?.[field]) && selector[field].length,
  );
}

function exactRuntimeCgroupScope(selector) {
  return (selector?.matchNamespaces || []).some(
    (entry) =>
      entry?.namespace === 'Cgroup' &&
      entry?.operator === 'In' &&
      Array.isArray(entry.values) &&
      entry.values.length === 1 &&
      entry.values[0] === '{cgroupNamespace}',
  );
}

function enforcementDetails(artifact) {
  const enforcement = [];
  for (const hook of hooks(artifact)) {
    for (const selector of hook?.selectors || []) {
      for (const action of selector?.matchActions || []) {
        if (ENFORCEMENT_ACTIONS.has(action?.action)) {
          enforcement.push({
            action: action.action,
            scoped: selectorScope(selector),
            runtimeCgroupScoped: exactRuntimeCgroupScope(selector),
          });
        }
      }
    }
  }
  return enforcement;
}

export function validateTetragonArtifact(artifact) {
  const errors = [];
  const warnings = [];
  if (!isPlainObject(artifact)) {
    return validationResult(
      ['Tetragon artifact must be an object'],
      [],
      { enforceable: false, runtimeValidationRequired: true },
    );
  }
  if (artifact.apiVersion !== 'cilium.io/v1alpha1') {
    errors.push('Tetragon apiVersion must be cilium.io/v1alpha1');
  }
  if (artifact.kind !== 'TracingPolicy') {
    errors.push('Tetragon kind must be TracingPolicy');
  }
  if (!/^[a-z0-9]([-a-z0-9]*[a-z0-9])?$/.test(artifact.metadata?.name || '')) {
    errors.push('Tetragon metadata.name must be a DNS label');
  }
  if (policyMode(artifact) !== 'monitor') {
    errors.push('candidate Tetragon policy mode must be monitor');
  }
  const policyHooks = hooks(artifact);
  if (!policyHooks.length) {
    errors.push('Tetragon policy must contain at least one hook');
  }
  for (const hook of artifact.spec?.kprobes || []) {
    if (typeof hook.call !== 'string' || !hook.call.trim()) {
      errors.push('each Tetragon kprobe must name a call');
    }
    if (hook.syscall !== undefined && typeof hook.syscall !== 'boolean') {
      errors.push('Tetragon kprobe syscall must be a boolean');
    }
  }

  const enforcement = enforcementDetails(artifact);
  const unscoped = enforcement.filter((entry) => !entry.scoped);
  if (unscoped.length) {
    errors.push('Tetragon enforcement actions require an explicit low-level process scope');
  }
  const runtimeUnscoped = enforcement.filter(
    (entry) => !entry.runtimeCgroupScoped,
  );
  if (runtimeUnscoped.length) {
    errors.push(
      'every Tetragon enforcement selector requires the exact {cgroupNamespace} runtime scope',
    );
  }
  if (enforcement.some((entry) => entry.action === 'Sigkill' || entry.action === 'Signal')) {
    warnings.push('Tetragon signal actions can occur after an operation; prefer supported Override or BPF LSM denial');
  }
  const enforceable =
    enforcement.length > 0 &&
    unscoped.length === 0 &&
    runtimeUnscoped.length === 0;
  if (!enforceable) {
    warnings.push('Tetragon artifact is monitor-only and cannot satisfy an enforce-mode approval');
  }
  warnings.push(
    'validate this policy with pinned tetra/Tetragon v1.7 against the target kernel before approval',
  );
  warnings.push(
    'container IDs are provenance only; standalone Tetragon requires explicit binary, PID, or namespace scope',
  );
  return validationResult(errors, warnings, {
    enforceable,
    runtimeValidationRequired: true,
  });
}
