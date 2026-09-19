import { API_VERSION } from './constants.js';
import {
  asEvidence,
  profileName,
  validationResult,
} from './artifact-utils.js';
import {
  canonicalize,
  isPlainObject,
  sanitizeDnsLabel,
  sortedUniqueStrings,
} from './stable.js';

export function compileDockerArtifact(evidenceInput, options = {}) {
  const evidence = asEvidence(evidenceInput, options);
  const name = profileName(evidence, options);
  const dockerOptions = isPlainObject(options.docker) ? options.docker : {};
  const pidsLimit = Number.isInteger(dockerOptions.pidsLimit) && dockerOptions.pidsLimit > 0
    ? dockerOptions.pidsLimit
    : 512;
  const network = dockerOptions.network === 'none'
    ? 'none'
    : sanitizeDnsLabel(dockerOptions.network || 'nosh-guard', 'nosh-guard');
  const tmpfs = sortedUniqueStrings(
    dockerOptions.tmpfs || ['/tmp:rw,noexec,nosuid,nodev,size=512m'],
  );
  const runArgs = [
    '--cap-drop=ALL',
    '--security-opt=no-new-privileges=true',
    '--security-opt=seccomp=seccomp.json',
    `--security-opt=apparmor=${name}`,
    '--read-only',
    `--pids-limit=${pidsLimit}`,
    `--network=${network}`,
    ...tmpfs.map((entry) => `--tmpfs=${entry}`),
  ].sort();
  return canonicalize({
    apiVersion: API_VERSION,
    kind: 'NoshDockerRunPolicy',
    metadata: {
      name,
      annotations: {
        'notty.dev/candidate': 'true',
        'notty.dev/review-required': 'true',
      },
    },
    spec: {
      engine: 'docker',
      runArgs,
      readOnlyRootfs: true,
      pidsLimit,
      network,
      capabilities: {
        drop: ['ALL'],
        add: [],
      },
      securityProfiles: {
        apparmor: name,
        seccomp: 'seccomp.json',
      },
      tmpfs,
      writableMounts: [
        {
          source: '{workdir}',
          target: '{workdir}',
          mode: 'rw',
          purpose: 'coding-agent-workspace',
        },
        {
          source: '{auth_state}',
          target: '/var/lib/notty-auth',
          mode: 'rw',
          purpose: 'notty-auth-state',
        },
      ],
      policyNotes: [
        'the runtime renderer substitutes one operator-selected workspace for {workdir}',
        'the runtime renderer substitutes one owner-only workspace auth directory for {auth_state}',
        'credential mounts require a separate operator-reviewed grant',
        'the runtime creates only the declared workspace and auth-state bind mounts automatically',
      ],
    },
  });
}

export function validateDockerArtifact(artifact) {
  const errors = [];
  const warnings = [];
  if (!isPlainObject(artifact)) {
    return validationResult(
      ['Docker artifact must be an object'],
      [],
      { enforceable: false, runtimeValidationRequired: true },
    );
  }
  if (artifact.apiVersion !== API_VERSION || artifact.kind !== 'NoshDockerRunPolicy') {
    errors.push('Docker artifact must be a notty.dev/v1alpha1 NoshDockerRunPolicy');
  }
  const spec = artifact.spec;
  if (!isPlainObject(spec) || spec.engine !== 'docker') {
    errors.push('Docker policy spec.engine must be docker');
  }
  if (spec?.readOnlyRootfs !== true) {
    errors.push('Docker candidate must use a read-only root filesystem');
  }
  if (!Number.isInteger(spec?.pidsLimit) || spec.pidsLimit <= 0) {
    errors.push('Docker candidate must set a positive PID limit');
  }
  if (!Array.isArray(spec?.capabilities?.drop) || !spec.capabilities.drop.includes('ALL')) {
    errors.push('Docker candidate must drop all capabilities by default');
  }
  if (Array.isArray(spec?.capabilities?.add) && spec.capabilities.add.length) {
    warnings.push(`review added Docker capabilities: ${spec.capabilities.add.join(', ')}`);
  }
  const runArgs = Array.isArray(spec?.runArgs) ? spec.runArgs : [];
  if (!runArgs.includes('--security-opt=no-new-privileges=true')) {
    errors.push('Docker candidate must enable no-new-privileges');
  }
  if (!runArgs.some((entry) => entry === '--security-opt=seccomp=seccomp.json')) {
    errors.push('Docker candidate must reference the compiled seccomp profile');
  }
  if (!runArgs.some((entry) => entry.startsWith('--security-opt=apparmor='))) {
    errors.push('Docker candidate must reference the compiled AppArmor profile');
  }
  if (!runArgs.includes('--cap-drop=ALL')) {
    errors.push('Docker candidate run arguments must drop all capabilities');
  }
  if (!runArgs.includes('--read-only')) {
    errors.push('Docker candidate run arguments must make the root filesystem read-only');
  }
  if (!runArgs.some((entry) => entry.startsWith('--network='))) {
    errors.push('Docker candidate must select an explicit network');
  }
  const writableMounts = spec?.writableMounts;
  if (
    !Array.isArray(writableMounts) ||
    writableMounts.length !== 2 ||
    writableMounts[0]?.source !== '{workdir}' ||
    writableMounts[0]?.target !== '{workdir}' ||
    writableMounts[0]?.mode !== 'rw' ||
    writableMounts[0]?.purpose !== 'coding-agent-workspace' ||
    writableMounts[1]?.source !== '{auth_state}' ||
    writableMounts[1]?.target !== '/var/lib/notty-auth' ||
    writableMounts[1]?.mode !== 'rw' ||
    writableMounts[1]?.purpose !== 'notty-auth-state'
  ) {
    errors.push(
      'Docker candidate must declare the exact workspace and auth-state writable mounts',
    );
  }
  if (spec?.network !== 'none') {
    warnings.push('Docker network selection does not enforce egress by itself; attach the network policy backend');
  }
  warnings.push('run the Docker artifact against a disposable image before approval');
  return validationResult(errors, warnings, {
    enforceable: errors.length === 0,
    runtimeValidationRequired: true,
  });
}
