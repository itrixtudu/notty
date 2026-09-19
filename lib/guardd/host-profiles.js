import crypto from 'node:crypto';
import fs from 'node:fs/promises';
import path from 'node:path';
import { spawnSync } from 'node:child_process';

function sha256(content) {
  return `sha256:${crypto.createHash('sha256').update(content).digest('hex')}`;
}

function runtimeName(name, runId) {
  const suffix = crypto.createHash('sha256').update(runId).digest('hex').slice(0, 10);
  return `${String(name).slice(0, Math.max(1, 63 - suffix.length - 1))}-${suffix}`;
}

const RUNTIME_ARTIFACTS = Object.freeze({
  tetragonPolicy: 'tetragon.yaml',
  seccompProfile: 'seccomp.json',
  apparmorProfile: 'apparmor.profile',
  dockerProfile: 'docker.json',
  networkPolicy: 'network-policy.yaml',
});

export async function snapshotRuntimeArtifacts(options) {
  const expected = options.artifactHashes || {};
  const outputDir = path.join(options.outputDir, 'profile-snapshot');
  await fs.mkdir(outputDir, { recursive: true, mode: 0o700 });
  const snapshot = { profileDir: outputDir };
  const artifacts = {};
  for (const [key, filename] of Object.entries(RUNTIME_ARTIFACTS)) {
    const sourcePath = path.join(options.profileDir, filename);
    const content = await fs.readFile(sourcePath);
    const actual = sha256(content);
    const expectedHash = expected[filename]
      ? `sha256:${String(expected[filename]).replace(/^sha256:/, '')}`
      : null;
    if (!expectedHash || actual !== expectedHash) {
      throw new Error(`runtime artifact changed after verification: ${filename}`);
    }
    const destination = path.join(outputDir, filename);
    await fs.writeFile(destination, content, { mode: 0o600, flag: 'wx' });
    snapshot[key] = destination;
    artifacts[filename] = actual;
  }
  const attestation = {
    apiVersion: 'notty.dev/v1alpha1',
    kind: 'NoshRuntimeArtifactSnapshot',
    generatedAt: new Date().toISOString(),
    runId: options.runId,
    sourceProfileDir: path.resolve(options.profileDir),
    snapshotDir: outputDir,
    artifacts,
  };
  const attestationPath = path.join(outputDir, 'attestation.json');
  await fs.writeFile(attestationPath, `${JSON.stringify(attestation, null, 2)}\n`, {
    mode: 0o600,
    flag: 'wx',
  });
  return { ...snapshot, attestation, attestationPath };
}

export async function renderAppArmorProfile(options) {
  const source = await fs.readFile(options.templatePath, 'utf8');
  const templateHash = sha256(source);
  if (
    options.approvedTemplateHash &&
    templateHash !== options.approvedTemplateHash
  ) {
    throw new Error('AppArmor template no longer matches its approval hash');
  }
  const match = source.match(
    /^profile ([a-z0-9](?:[-a-z0-9]*[a-z0-9])?) flags=\(([^)]*)\) \{$/m,
  );
  if (!match) {
    throw new Error('AppArmor candidate does not contain one supported profile header');
  }
  const profileName = runtimeName(match[1], options.runId);
  const renderedSource = source.replace(
    match[0],
    `profile ${profileName} flags=(${match[2]}) {`,
  );
  const renderedHash = sha256(renderedSource);
  await fs.mkdir(options.outputDir, { recursive: true, mode: 0o700 });
  const profilePath = path.join(options.outputDir, 'rendered-apparmor.profile');
  const attestationPath = path.join(
    options.outputDir,
    'rendered-apparmor-attestation.json',
  );
  await fs.writeFile(profilePath, renderedSource, { mode: 0o600 });
  const attestation = {
    apiVersion: 'notty.dev/v1alpha1',
    kind: 'NoshRuntimePolicyAttestation',
    generatedAt: new Date().toISOString(),
    renderer: 'nosh-guard/v1',
    backend: 'apparmor',
    runId: options.runId,
    templatePath: path.resolve(options.templatePath),
    templateHash,
    renderedPath: profilePath,
    renderedHash,
    profileName,
  };
  await fs.writeFile(attestationPath, `${JSON.stringify(attestation, null, 2)}\n`, {
    mode: 0o600,
  });
  return { profilePath, profileName, attestationPath, attestation };
}

export function seccompForMode(document, mode) {
  const profile = structuredClone(document);
  if (mode === 'audit') {
    profile.defaultAction = 'SCMP_ACT_LOG';
    delete profile.defaultErrnoRet;
  }
  return profile;
}

export class HostProfileLoader {
  constructor(options = {}) {
    this.spawnSyncImpl = options.spawnSyncImpl || spawnSync;
  }

  command(args) {
    const result = this.spawnSyncImpl('apparmor_parser', args, {
      encoding: 'utf8',
      timeout: 10_000,
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    if (result.status !== 0) {
      throw new Error(
        `apparmor_parser ${args.join(' ')} failed: ${
          result.error?.message || result.stderr || `status ${result.status}`
        }`,
      );
    }
    return result;
  }

  load(profilePath, mode) {
    const args = ['--replace'];
    if (mode === 'audit') {
      args.push('--Complain');
    }
    args.push(profilePath);
    this.command(args);
    return { profilePath, mode, loaded: true };
  }

  remove(profilePath) {
    try {
      this.command(['--remove', profilePath]);
      return { profilePath, removed: true };
    } catch (error) {
      return { profilePath, removed: false, error: error.message };
    }
  }
}

export async function loadRuntimeProfileDocuments(profile, mode) {
  if (!profile?.profileDir || mode === 'learn') {
    return {
      seccomp: null,
      docker: null,
    };
  }
  const [seccomp, docker] = await Promise.all([
    fs.readFile(profile.seccompProfile, 'utf8').then(JSON.parse),
    fs.readFile(profile.dockerProfile, 'utf8').then(JSON.parse),
  ]);
  return {
    seccomp: seccompForMode(seccomp, mode),
    docker,
  };
}

export function assertDockerArtifactConformance(runnerSpec, dockerArtifact) {
  if (!dockerArtifact) {
    return;
  }
  const policy = dockerArtifact.spec;
  const host = runnerSpec.HostConfig;
  const errors = [];
  if (policy?.readOnlyRootfs !== host.ReadonlyRootfs) {
    errors.push('read-only root filesystem');
  }
  if (policy?.pidsLimit !== host.PidsLimit) {
    errors.push('PID limit');
  }
  if (
    !Array.isArray(host.CapDrop) ||
    !host.CapDrop.includes('ALL') ||
    (policy?.capabilities?.add || []).length ||
    (host.CapAdd || []).length
  ) {
    errors.push('capability set');
  }
  if (!host.SecurityOpt.includes('no-new-privileges:true')) {
    errors.push('no-new-privileges');
  }
  if (!host.SecurityOpt.some((entry) => entry.startsWith('seccomp='))) {
    errors.push('seccomp attachment');
  }
  if (!host.SecurityOpt.some((entry) => entry.startsWith('apparmor='))) {
    errors.push('AppArmor attachment');
  }
  if (
    typeof host.NetworkMode !== 'string' ||
    !host.NetworkMode.startsWith('nosh-guard-') ||
    dockerArtifact.spec?.network === 'none' ||
    !String(dockerArtifact.spec?.network || '').startsWith('nosh-guard')
  ) {
    errors.push('managed per-run network');
  }
  const expectedWorkspaceBind =
    `${runnerSpec.WorkingDir}:${runnerSpec.WorkingDir}:rw`;
  const binds = Array.isArray(host.Binds) ? host.Binds : [];
  const authBind = typeof binds[1] === 'string'
    ? binds[1].match(/^([^:]+):\/var\/lib\/notty-auth:rw$/)
    : null;
  const resolverBind = typeof binds[2] === 'string'
    ? binds[2].match(/^([^:]+):\/etc\/resolv\.conf:ro$/)
    : null;
  const resolverBindValid = binds.length === 2 || (
    binds.length === 3
    && resolverBind
    && resolverBind[1].startsWith('/')
  );
  const writableMounts = dockerArtifact.spec?.writableMounts;
  if (
    binds[0] !== expectedWorkspaceBind ||
    !authBind ||
    !authBind[1].startsWith('/') ||
    !resolverBindValid ||
    writableMounts?.length !== 2 ||
    writableMounts[0]?.source !== '{workdir}' ||
    writableMounts[0]?.target !== '{workdir}' ||
    writableMounts[0]?.mode !== 'rw' ||
    writableMounts[0]?.purpose !== 'coding-agent-workspace' ||
    writableMounts[1]?.source !== '{auth_state}' ||
    writableMounts[1]?.target !== '/var/lib/notty-auth' ||
    writableMounts[1]?.mode !== 'rw' ||
    writableMounts[1]?.purpose !== 'notty-auth-state'
  ) {
    errors.push('exact writable workspace and auth-state mounts');
  }
  if (errors.length) {
    throw new Error(
      `runtime Docker request does not conform to approved artifact: ${errors.join(
        ', ',
      )}`,
    );
  }
}
