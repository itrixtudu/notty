import crypto from 'node:crypto';
import fs from 'node:fs/promises';
import path from 'node:path';
import { readlinkSync } from 'node:fs';

import { AdapterController } from './adapters.js';
import {
  verifyArtifactSet,
  verifyCandidateArtifactSet,
} from './approval.js';
import {
  DEFAULT_DOCKER_SOCKET,
  EGRESS_SECURITY_MODES,
  GUARD_LABEL_PREFIX,
  SECURITY_MODES,
} from './constants.js';
import {
  DockerClient,
  sanitizeDockerRuntimeLogTail,
} from './docker-client.js';
import { EgressManager } from './egress-manager.js';
import { EbpfActivationStore } from './ebpf-activation-store.js';
import {
  EBPF_EGRESS_CAPABILITIES,
  EBPF_EGRESS_BACKEND_ABI,
  EBPF_PLATFORM_CONTAINMENT,
  EbpfEgressBackend,
} from './enforcement-backend.js';
import { finalizeRunEvidence } from './evidence-finalizer.js';
import { assertHealthForMode, collectGuardHealth } from './health.js';
import {
  assertDockerArtifactConformance,
  HostProfileLoader,
  loadRuntimeProfileDocuments,
  renderAppArmorProfile,
  snapshotRuntimeArtifacts,
} from './host-profiles.js';
import {
  assertRunnerImageAbi,
  buildRunnerSpec,
  summarizeRunnerSpec,
} from './runner-spec.js';
import { renderApprovedTetragonPolicy } from './runtime-artifacts.js';
import { GuardStateStore } from './state-store.js';
import { normalizeGatewayPublicOrigin } from './proxy-contract.js';
import {
  EGRESS_BUNDLE_FILES,
  verifyEgressApprovalBundle,
  verifyEgressCandidateBundle,
} from './net-profile-store.js';
import { stableStringify } from '../guard/stable.js';

const FULL_RUNTIME_PROFILE_MODES = new Set(['audit', 'enforce']);
const PRE_NETWORK_FAILURE_CODES = new Set([
  'GUARD_EBPF_ACTIVATION_BUSY',
  'GUARD_EBPF_ACTIVATION_REQUIRED',
  'GUARD_EBPF_EGRESS_BACKEND_FAILED',
  'GUARD_EBPF_EGRESS_BACKEND_UNHEALTHY',
  'GUARD_EGRESS_IMAGE_ABI_MISMATCH',
  'GUARD_EGRESS_IMAGE_MISSING',
  'GUARD_RUNNER_IMAGE_ABI_MISMATCH',
]);
const SCOPED_EGRESS_MODES = new Set(EGRESS_SECURITY_MODES);
const NON_LIVE_RUNTIME_STATUSES = new Set([
  'removed',
  'stopped',
  // Older retained runtime records used these terminal spellings.
  'complete',
  'completed',
]);

function platformContainmentCidrs(allocation) {
  if (!allocation?.dockerGateway || !allocation?.dockerGatewayIpv6) {
    throw new Error(
      'scoped egress network is missing its exact Docker bridge gateways',
    );
  }
  return [
    `${allocation.dockerGateway}/32`,
    `${allocation.dockerGatewayIpv6}/128`,
  ];
}

export function runReservesCgroupNamespace(run) {
  if (!run || typeof run !== 'object' || Array.isArray(run)) return true;
  // An explicit removal attestation is stronger than the historical status;
  // failed/quarantined records can remain for evidence after Docker removal.
  if (run.containerRemoved === true || run.status === 'removed') return false;
  // A paused or quarantined container may still own every recorded namespace.
  // Unknown and non-terminal states also reserve by default below.
  if (
    run.containerPaused === true
    || run.quarantineActive === true
    || run.status === 'quarantined'
  ) {
    return true;
  }
  return !NON_LIVE_RUNTIME_STATUSES.has(run.status);
}

function egressApprovalHash(verification) {
  return (
    verification?.approval?.contentHash ||
    verification?.approvalHash ||
    null
  );
}

function serializedDocument(document) {
  return `${stableStringify(document, 2)}\n`;
}

function hashDocument(source) {
  return `sha256:${crypto.createHash('sha256').update(source).digest('hex')}`;
}

function scopedWorkspaceKey(workspace) {
  return crypto.createHash('sha256').update(workspace.canonicalPath).digest('hex');
}

async function directoryIdentity(directory) {
  const stat = await fs.stat(directory, { bigint: true });
  if (!stat.isDirectory()) {
    throw new Error(`workspace is not a directory: ${directory}`);
  }
  return { dev: String(stat.dev), ino: String(stat.ino) };
}

async function canonicalWorkspaceIdentity(directory) {
  const canonicalPath = await fs.realpath(path.resolve(directory));
  return {
    canonicalPath,
    ...await directoryIdentity(canonicalPath),
  };
}

export async function assertWorkspaceMountIdentity(options) {
  if (!Number.isSafeInteger(options?.initPid) || options.initPid <= 0) {
    throw new Error('runner init PID is unavailable for workspace verification');
  }
  const expected = options.expected;
  const host = await directoryIdentity(options.workdir);
  const mountedPath = path.join(
    '/proc',
    String(options.initPid),
    'root',
    options.workdir.replace(/^\/+/, ''),
  );
  const mounted = await directoryIdentity(mountedPath);
  if (
    !expected
    || host.dev !== expected.dev
    || host.ino !== expected.ino
    || mounted.dev !== expected.dev
    || mounted.ino !== expected.ino
  ) {
    const error = new Error(
      'runner workspace changed between identity capture and bind-mount admission',
    );
    error.code = 'GUARD_EGRESS_WORKSPACE_IDENTITY_CHANGED';
    throw error;
  }
  return { host, mounted };
}

export async function snapshotEgressProfile(options) {
  const { verification } = options;
  if (!verification?.ok) {
    throw new Error('cannot snapshot an unverified egress profile');
  }
  if (
    verification.policyHash !==
      verification.artifacts?.[EGRESS_BUNDLE_FILES.policy] ||
    (verification.approval &&
      verification.approvalHash !== verification.approval.contentHash)
  ) {
    const error = new Error(
      'verified egress bundle exposes inconsistent policy or approval hashes',
    );
    error.code = 'GUARD_EGRESS_SNAPSHOT_HASH_MISMATCH';
    throw error;
  }
  const documents = [
    {
      name: EGRESS_BUNDLE_FILES.profile,
      document: verification.profile,
      expectedHash: verification.artifacts?.[EGRESS_BUNDLE_FILES.profile],
    },
    {
      name: EGRESS_BUNDLE_FILES.policy,
      document: verification.policy,
      expectedHash: verification.artifacts?.[EGRESS_BUNDLE_FILES.policy],
    },
    {
      name: EGRESS_BUNDLE_FILES.manifest,
      document: verification.manifest,
      expectedHash: verification.manifestHash,
    },
  ];
  if (verification.approval) {
    documents.push({
      name: EGRESS_BUNDLE_FILES.approval,
      document: verification.approval,
      expectedHash: verification.approvalFileHash,
    });
  }
  if (options.mode === 'egress-enforce' && !verification.approval) {
    throw new Error('egress-enforce snapshot requires an approval document');
  }
  const files = {};
  const sources = new Map();
  for (const entry of documents) {
    const source = serializedDocument(entry.document);
    const hash = hashDocument(source);
    if (hash !== entry.expectedHash) {
      const error = new Error(
        `verified egress artifact changed before snapshot: ${entry.name}`,
      );
      error.code = 'GUARD_EGRESS_SNAPSHOT_HASH_MISMATCH';
      throw error;
    }
    sources.set(entry.name, source);
    files[entry.name] = {
      hash,
      bytes: Buffer.byteLength(source),
    };
  }
  const snapshotDir = path.join(options.evidenceDir, 'egress-profile-snapshot');
  await fs.mkdir(snapshotDir, { mode: 0o700 });
  for (const [name, source] of sources) {
    await fs.writeFile(path.join(snapshotDir, name), source, {
      flag: 'wx',
      mode: 0o600,
    });
  }
  const attestation = {
    apiVersion: 'notty.dev/v1alpha1',
    kind: 'NoshEgressRuntimeProfileSnapshot',
    capturedAt: new Date().toISOString(),
    runId: options.runId,
    mode: options.mode,
    revision: verification.revision,
    workspace: verification.workspace,
    workspaceKey: verification.workspaceKey,
    imageDigest: verification.imageDigest,
    profilePolicyHash: verification.policyHash,
    approvalHash: egressApprovalHash(verification),
    files,
  };
  const attestationPath = path.join(snapshotDir, 'attestation.json');
  await fs.writeFile(attestationPath, serializedDocument(attestation), {
    flag: 'wx',
    mode: 0o600,
  });
  return { snapshotDir, attestationPath, attestation };
}

function readNamespaceIdentities(pid) {
  if (!Number.isSafeInteger(pid) || pid <= 0) {
    return {};
  }
  const identities = {};
  for (const namespace of ['cgroup', 'mnt', 'net', 'pid', 'user']) {
    try {
      const identity = path.basename(
        // This is an intentionally synchronous read of five procfs symlinks during
        // the gated lifecycle. It keeps the identity snapshot internally coherent.
        readlinkSync(`/proc/${pid}/ns/${namespace}`),
      );
      identities[namespace] = identity.match(/\[(\d+)\]/)?.[1] || identity;
    } catch {
      identities[namespace] = null;
    }
  }
  return identities;
}

async function resolveCgroupTarget(pid) {
  if (!Number.isSafeInteger(pid) || pid <= 0) {
    throw new Error('runner init PID is unavailable for cgroup resolution');
  }
  const membership = await fs.readFile(`/proc/${pid}/cgroup`, 'utf8');
  const unified = membership
    .split(/\r?\n/)
    .map((line) => line.split(':'))
    .find(
      (parts) =>
        parts.length === 3 &&
        parts[0] === '0' &&
        parts[1] === '' &&
        parts[2].startsWith('/'),
    );
  if (!unified) {
    throw new Error('runner does not have a cgroup-v2 membership');
  }
  const cgroupRoot = await fs.realpath('/sys/fs/cgroup');
  const candidate = path.resolve(cgroupRoot, `.${unified[2]}`);
  const cgroupPath = await fs.realpath(candidate);
  const relative = path.relative(cgroupRoot, cgroupPath);
  if (!relative || relative.startsWith('..') || path.isAbsolute(relative)) {
    throw new Error('refusing the cgroup-v2 mount root or an escaped cgroup path');
  }
  const stat = await fs.stat(cgroupPath, { bigint: true });
  if (!stat.isDirectory()) {
    throw new Error('resolved runner cgroup is not a directory');
  }
  return {
    path: cgroupPath,
    id: stat.ino.toString(),
    membership: unified[2],
  };
}

function preferredImageReference(image, imageInfo) {
  if (image.includes('@sha256:')) {
    return image;
  }
  const repoDigest = (imageInfo?.RepoDigests || [])[0];
  return repoDigest || imageInfo?.Id || image;
}

function artifactContext(profileDir) {
  if (!profileDir) {
    return {
      profileDir: '',
      tetragonPolicy: '',
      seccompProfile: '',
      apparmorProfile: '',
      dockerProfile: '',
      networkPolicy: '',
    };
  }
  const resolved = path.resolve(profileDir);
  return {
    profileDir: resolved,
    tetragonPolicy: path.join(resolved, 'tetragon.yaml'),
    seccompProfile: path.join(resolved, 'seccomp.json'),
    apparmorProfile: path.join(resolved, 'apparmor.profile'),
    dockerProfile: path.join(resolved, 'docker.json'),
    networkPolicy: path.join(resolved, 'network-policy.yaml'),
  };
}

async function existingPath(filePath) {
  if (!filePath) {
    return '';
  }
  try {
    await fs.access(filePath);
    return filePath;
  } catch {
    return '';
  }
}

function requiredAdapterFailures(results) {
  return results.filter((result) => result.required && !result.ok);
}

function criticalCleanupFailures(results) {
  return results.filter(
    (result) =>
      result.cleanupCritical === true &&
      result.cleanupOk === false,
  );
}

function currentNamespaceIdentity(namespace) {
  const identity = path.basename(readlinkSync(`/proc/self/ns/${namespace}`));
  return identity.match(/\[(\d+)\]/)?.[1] || identity;
}

function identityMismatch(detail) {
  const error = new Error(`runner runtime identity mismatch: ${detail}`);
  error.code = 'GUARD_RUNTIME_IDENTITY_MISMATCH';
  return error;
}

function boundedRuntimeStateString(value, maxLength) {
  if (typeof value !== 'string') {
    return null;
  }
  return value
    .replace(/[\p{Cc}\p{Cf}\p{Zl}\p{Zp}]/gu, '\ufffd')
    .slice(0, maxLength);
}

export function sanitizeStoppedRuntimeState(state) {
  if (!state || typeof state !== 'object' || Array.isArray(state)) {
    return null;
  }
  return {
    ExitCode: Number.isSafeInteger(state.ExitCode) ? state.ExitCode : null,
    Error: boundedRuntimeStateString(state.Error, 4096),
    OOMKilled: typeof state.OOMKilled === 'boolean' ? state.OOMKilled : null,
    Dead: typeof state.Dead === 'boolean' ? state.Dead : null,
    StartedAt: boundedRuntimeStateString(state.StartedAt, 128),
    FinishedAt: boundedRuntimeStateString(state.FinishedAt, 128),
  };
}

function stoppedRuntimeStateSummary(state) {
  const details = [];
  if (Number.isSafeInteger(state?.ExitCode)) {
    details.push(`exit code ${state.ExitCode}`);
  }
  if (typeof state?.OOMKilled === 'boolean') {
    details.push(`OOMKilled=${state.OOMKilled}`);
  }
  if (typeof state?.Error === 'string' && state.Error.length > 0) {
    const dockerError = state.Error.length > 512
      ? `${state.Error.slice(0, 511)}\u2026`
      : state.Error;
    details.push(`Docker error: ${JSON.stringify(dockerError)}`);
  }
  return details.length ? ` (${details.join('; ')})` : '';
}

function stoppedRuntimeLogSummary(runtimeLogTail) {
  const line = runtimeLogTail?.text
    ?.split('\n')
    .findLast((entry) => entry.trim().length > 0);
  if (!line) {
    return '';
  }
  const concise = line.length > 256
    ? `${line.slice(0, 255)}\u2026`
    : line;
  return `; container log: ${JSON.stringify(concise)}`;
}

function assertSameIdentity(expected, actual, label) {
  if (!expected || !actual || expected !== actual) {
    throw identityMismatch(
      `${label} changed from ${expected || 'unavailable'} to ${
        actual || 'unavailable'
      }`,
    );
  }
}

function cleanupFailure(name, error) {
  return {
    name,
    cleanupCritical: true,
    cleanupOk: false,
    error: error?.message || String(error),
  };
}

export class GuardService {
  constructor(options = {}) {
    this.gatewayPublicOrigin = options.gatewayPublicOrigin
      ? normalizeGatewayPublicOrigin(options.gatewayPublicOrigin).origin
      : null;
    this.docker = options.docker || new DockerClient(options.dockerOptions);
    this.store = options.store || new GuardStateStore(options.stateDir);
    const stateDir = options.stateDir || this.store.root;
    this.adapters =
      options.adapters ||
      new AdapterController({ configPath: options.adapterConfig });
    this.egress =
      options.egress ||
      new EgressManager({
        docker: this.docker,
        stateDir,
        image: options.egressImage,
        publicOrigin: this.gatewayPublicOrigin,
        ipv6RoutingProvider: options.ipv6RoutingProvider,
      });
    this.scopedEgress =
      options.scopedEgress ||
      new EbpfEgressBackend({
        networkManager: this.egress,
        stateDir,
        loaderPath: options.egressLoader,
        pinRoot: options.egressPinRoot,
        resolvers: options.egressResolvers,
      });
    this.resolveScopedEgressLoader =
      !options.scopedEgress
      && !options.egressLoader
      && this.adapters instanceof AdapterController;
    this.ebpfActivations =
      options.ebpfActivations
      || new EbpfActivationStore({
        stateDir,
        trustPath: options.ebpfDeploymentTrust,
      });
    this.healthProvider = options.healthProvider || collectGuardHealth;
    this.namespaceProvider = options.namespaceProvider || readNamespaceIdentities;
    this.cgroupProvider = options.cgroupProvider || resolveCgroupTarget;
    this.hostNamespaceProvider =
      options.hostNamespaceProvider || currentNamespaceIdentity;
    this.hostProfiles = options.hostProfiles || new HostProfileLoader();
    this.egressProfiles = options.egressProfiles || {
      verifyApproval: verifyEgressApprovalBundle,
      verifyCandidate: verifyEgressCandidateBundle,
    };
    this.workspaceMountVerifier =
      options.workspaceMountVerifier || assertWorkspaceMountIdentity;
    this.allowIncomplete = Boolean(options.allowIncomplete);
    this.pendingRunIdentities = new Set();
    this.pendingRunActions = new Set();
    this.pendingRunStarts = new Set();
    this.requiredAdapterExitFailures = new Map();
  }

  async initialize() {
    await this.store.initialize();
    if (this.resolveScopedEgressLoader) {
      const [healthLoader, attachLoader] = await Promise.all([
        this.adapters.configuredExecutable('nosh-egress', 'health'),
        this.adapters.configuredExecutable('nosh-egress', 'attach'),
      ]);
      if (healthLoader !== attachLoader) {
        throw new Error(
          'nosh-egress health and attach must use the same installed loader',
        );
      }
      this.scopedEgress.configureLoaderPath(healthLoader);
    }
    await Promise.all([
      this.egress.initialize(),
      this.scopedEgress.initialize(),
      this.ebpfActivations.initialize(),
    ]);
  }

  health() {
    return this.healthProvider();
  }

  async managedEgressRunHealth(run) {
    const backend = SCOPED_EGRESS_MODES.has(run?.mode)
      ? this.scopedEgress
      : this.egress;
    if (typeof backend.runtimeHealth !== 'function') {
      if (SCOPED_EGRESS_MODES.has(run?.mode)) {
        return {
          ok: false,
          error: 'managed egress runtime policy health is not implemented',
        };
      }
      return { ok: true, detail: 'runtime policy health is not implemented' };
    }
    try {
      return await backend.runtimeHealth(run);
    } catch (error) {
      return { ok: false, error: error.message };
    }
  }

  async inspectRuntimeIdentity(expected, baseline = null) {
    const inspected = await this.docker.inspectContainer(expected.containerId);
    if (!inspected || inspected.Id !== expected.containerId) {
      throw identityMismatch('Docker returned a different container ID');
    }
    if (inspected.State?.Running !== true) {
      const runtimeState = sanitizeStoppedRuntimeState(inspected.State);
      const error = identityMismatch(
        `container is not running${stoppedRuntimeStateSummary(runtimeState)}`,
      );
      error.runtimeState = runtimeState;
      throw error;
    }
    const initPid = inspected.State?.Pid;
    if (!Number.isSafeInteger(initPid) || initPid <= 0) {
      throw identityMismatch('container init PID is unavailable');
    }
    if (inspected.Image !== expected.imageDigest) {
      throw identityMismatch(
        `image changed from ${expected.imageDigest || 'unavailable'} to ${
          inspected.Image || 'unavailable'
        }`,
      );
    }
    const labels = inspected.Config?.Labels || {};
    if (labels[`${GUARD_LABEL_PREFIX}.run-id`] !== expected.runId) {
      throw identityMismatch('container run-ID label is missing or changed');
    }
    if (
      labels[`${GUARD_LABEL_PREFIX}.image-digest`] !== expected.imageDigest
    ) {
      throw identityMismatch('container image-digest label is missing or changed');
    }
    const networks = inspected.NetworkSettings?.Networks || {};
    const attached = Object.keys(networks);
    if (expected.requireNoNetwork === true) {
      if (attached.length !== 0) {
        throw identityMismatch(
          `runner must remain networkless before policy attachment; found ${attached.join(', ')}`,
        );
      }
    } else if (expected.networkName) {
      if (
        attached.length !== 1
        || attached[0] !== expected.networkName
        || networks[expected.networkName]?.IPAddress !== expected.sourceIpv4
        || (
          expected.sourceIpv6
          && networks[expected.networkName]?.GlobalIPv6Address !== expected.sourceIpv6
        )
      ) {
        throw identityMismatch(
          `network attachment must be exactly ${expected.networkName} at ${
            expected.sourceIpv4 || 'the assigned address'
          }`,
        );
      }
    }
    const namespaces = await this.namespaceProvider(initPid);
    const cgroup = await this.cgroupProvider(initPid);
    if (!namespaces?.cgroup) {
      throw identityMismatch('runner cgroup namespace identity is unavailable');
    }
    if (namespaces.cgroup === this.hostNamespaceProvider('cgroup')) {
      throw identityMismatch('runner joined the host cgroup namespace');
    }
    if (!cgroup?.path || !cgroup?.id || !cgroup?.membership) {
      throw identityMismatch('runner cgroup target is incomplete');
    }
    if (baseline) {
      assertSameIdentity(String(baseline.initPid), String(initPid), 'init PID');
      for (const namespace of ['cgroup', 'mnt', 'net', 'pid', 'user']) {
        assertSameIdentity(
          baseline.namespaces?.[namespace],
          namespaces?.[namespace],
          `${namespace} namespace`,
        );
      }
      for (const field of ['path', 'id', 'membership']) {
        assertSameIdentity(
          String(baseline.cgroup?.[field] || ''),
          String(cgroup?.[field] || ''),
          `cgroup ${field}`,
        );
      }
    }
    return {
      inspected,
      initPid,
      namespaces,
      cgroup,
    };
  }

  async captureStoppedRuntimeLogTail(containerId, error) {
    if (
      !containerId
      || !error?.runtimeState
      || typeof this.docker.containerLogs !== 'function'
    ) {
      return null;
    }
    try {
      const captured = await this.docker.containerLogs(containerId, {
        tailLines: 40,
        maxWireBytes: 32 * 1024,
        maxTextBytes: 8 * 1024,
        timeoutMs: 2_000,
      });
      return sanitizeDockerRuntimeLogTail(captured)
        || { text: '', truncated: false };
    } catch {
      return null;
    }
  }

  async captureFinalEgressSnapshot(run) {
    try {
      const backend = SCOPED_EGRESS_MODES.has(run?.mode)
        ? this.scopedEgress
        : this.egress;
      const finalSnapshot = await backend.snapshotRun(run);
      return {
        ...run,
        egress: {
          ...(run.egress || {}),
          finalSnapshot,
          finalSnapshotError: null,
        },
      };
    } catch (error) {
      return {
        ...run,
        evidenceComplete: false,
        egress: {
          ...(run.egress || {}),
          finalSnapshot: error.attestation || null,
          finalSnapshotError: {
            code: error.code || null,
            message: error.message,
            at: new Date().toISOString(),
          },
        },
      };
    }
  }

  async containForCleanup(containerId, timeoutSeconds = 5) {
    try {
      await this.docker.stopContainer(containerId, timeoutSeconds);
      return {
        contained: true,
        containment: 'stopped',
        containerPaused: false,
        containerRemoved: false,
      };
    } catch (stopError) {
      if (stopError.statusCode === 404) {
        return {
          contained: true,
          containment: 'absent',
          containerPaused: false,
          containerRemoved: true,
        };
      }
      try {
        await this.docker.pauseContainer(containerId);
        return {
          contained: true,
          containment: 'paused',
          containerPaused: true,
          containerRemoved: false,
          stopError: stopError.message,
        };
      } catch (pauseError) {
        if (pauseError.statusCode === 404) {
          return {
            contained: true,
            containment: 'absent',
            containerPaused: false,
            containerRemoved: true,
            stopError: stopError.message,
          };
        }
        try {
          await this.docker.removeContainer(containerId, true);
          return {
            contained: true,
            containment: 'removed',
            containerPaused: false,
            containerRemoved: true,
            stopError: stopError.message,
            pauseError: pauseError.message,
          };
        } catch (removalError) {
          if (removalError.statusCode === 404) {
            return {
              contained: true,
              containment: 'absent',
              containerPaused: false,
              containerRemoved: true,
              stopError: stopError.message,
              pauseError: pauseError.message,
            };
          }
          const error = new Error(
            `could not stop, pause, or force-remove runner before policy cleanup: ${
              stopError.message
            }; ${pauseError.message}; ${removalError.message}`,
          );
          error.code = 'GUARD_CONTAINER_CONTAINMENT_FAILED';
          error.stopError = stopError;
          error.pauseError = pauseError;
          error.removalError = removalError;
          throw error;
        }
      }
    }
  }

  async startRun(request) {
    const runId = request.runId || crypto.randomUUID();
    const identities = [`run:${runId}`, `name:${request.name}`];
    if (
      this.pendingRunActions.has(runId) ||
      identities.some((identity) => this.pendingRunIdentities.has(identity))
    ) {
      const error = new Error('guard run identity is already being prepared');
      error.code = 'GUARD_RUN_IDENTITY_CONFLICT';
      error.statusCode = 409;
      throw error;
    }
    identities.forEach((identity) => this.pendingRunIdentities.add(identity));
    this.pendingRunActions.add(runId);
    this.pendingRunStarts.add(runId);
    try {
      const result = await this.startRunExclusive({ ...request, runId });
      this.assertRequiredAdaptersStillRunning(runId);
      return result;
    } finally {
      identities.forEach((identity) => this.pendingRunIdentities.delete(identity));
      this.pendingRunStarts.delete(runId);
      this.pendingRunActions.delete(runId);
      const deferredFailure = this.requiredAdapterExitFailures.get(runId);
      if (deferredFailure) {
        await this.handleRequiredAdapterExit(runId, deferredFailure);
      }
    }
  }

  assertRequiredAdaptersStillRunning(runId) {
    const failure = this.requiredAdapterExitFailures.get(runId);
    if (!failure) return;
    const error = new Error(
      `required guard adapter ${failure.name || 'unknown'} exited unexpectedly: ${
        failure.error || failure.exitSignal || `status ${failure.exitCode}`
      }`,
    );
    error.code = 'GUARD_REQUIRED_ADAPTER_EXITED';
    error.adapterFailure = structuredClone(failure);
    throw error;
  }

  async startRunExclusive(request) {
    if (this.allowIncomplete || request.allowIncomplete) {
      const error = new Error(
        'allow-incomplete is disabled for guarded runner admission',
      );
      error.code = 'GUARD_INCOMPLETE_BYPASS_DISABLED';
      throw error;
    }
    if (!SECURITY_MODES.includes(request.mode)) {
      throw new TypeError(`mode must be one of: ${SECURITY_MODES.join(', ')}`);
    }
    if (request.mode === 'enforce') {
      const error = new Error(
        'standalone enforcement is unavailable until an ingress backend can enforce the compiled network policy',
      );
      error.code = 'GUARD_STANDALONE_INGRESS_UNAVAILABLE';
      throw error;
    }
    const health = this.health();
    assertHealthForMode(health, request.mode);

    const scopedWorkspace = SCOPED_EGRESS_MODES.has(request.mode)
      ? await canonicalWorkspaceIdentity(request.workdir)
      : null;
    if (scopedWorkspace) {
      request = {
        ...request,
        workdir: scopedWorkspace.canonicalPath,
      };
    }

    const profile = artifactContext(request.profileDir);
    if (request.mode === 'audit' && !request.profileDir) {
      throw new Error('audit mode requires --profile-dir with a candidate artifact set');
    }
    let verification = null;
    let egressVerification = null;
    if (request.mode === 'audit') {
      verification = await verifyCandidateArtifactSet(request.profileDir);
    }
    if (request.mode === 'enforce') {
      if (!request.profileDir) {
        throw new Error('enforce mode requires --profile-dir with an approved artifact set');
      }
      verification = await verifyArtifactSet(request.profileDir, {
        requireTrustedOwnership: true,
        trustedRoot: this.store.profilesDir,
      });
      if (!verification.ok) {
        const error = new Error('profile artifact hashes do not match approval');
        error.code = 'GUARD_PROFILE_TAMPERED';
        error.verification = verification;
        throw error;
      }
    }
    if (request.mode === 'egress-learn' && request.profileDir) {
      throw new Error('egress-learn mode does not accept a profile directory');
    }
    if (request.mode === 'egress-audit') {
      if (!request.profileDir) {
        throw new Error(
          'egress-audit mode requires --profile-dir with a scoped candidate bundle',
        );
      }
      egressVerification = await this.egressProfiles.verifyCandidate(
        request.profileDir,
        {
          trustedRoot: path.join(this.store.profilesDir, 'net'),
          workdir: request.workdir,
        },
      );
      if (!egressVerification?.ok) {
        const error = new Error(
          'scoped egress candidate artifact hashes do not match its manifest',
        );
        error.code = 'GUARD_EGRESS_CANDIDATE_TAMPERED';
        error.verification = egressVerification;
        throw error;
      }
    }
    if (request.mode === 'egress-enforce') {
      if (request.profileDir) {
        const error = new Error(
          'egress-enforce does not accept caller-selected or legacy approved profiles; '
            + 'activate a signed guard-ebpf deployment in the root-owned activation store',
        );
        error.code = 'GUARD_EBPF_ACTIVATION_REQUIRED';
        throw error;
      }
    }

    let workspaceIdentity = null;
    if (scopedWorkspace) {
      workspaceIdentity = egressVerification?.workspaceIdentity || {
        dev: scopedWorkspace.dev,
        ino: scopedWorkspace.ino,
      };
      if (
        egressVerification
        && (
          egressVerification.workspace !== scopedWorkspace.canonicalPath
          || workspaceIdentity.dev !== scopedWorkspace.dev
          || workspaceIdentity.ino !== scopedWorkspace.ino
        )
      ) {
        const error = new Error(
          'scoped egress workspace changed during profile verification',
        );
        error.code = 'GUARD_EGRESS_WORKSPACE_IDENTITY_CHANGED';
        throw error;
      }
      if (
        !/^\d+$/.test(workspaceIdentity?.dev || '')
        || !/^\d+$/.test(workspaceIdentity?.ino || '')
      ) {
        const error = new Error(
          'scoped egress verification did not bind the workspace identity',
        );
        error.code = 'GUARD_EGRESS_WORKSPACE_IDENTITY_MISSING';
        throw error;
      }
    }

    const runId = request.runId;
    const conflictingRun = (await this.store.listRuns()).find(
      (entry) =>
        entry.runId === runId ||
        (request.name && entry.name === request.name),
    );
    if (conflictingRun) {
      const error = new Error(
        `guard run identity is already reserved by ${conflictingRun.runId}; remove it before reuse`,
      );
      error.code = 'GUARD_RUN_IDENTITY_CONFLICT';
      error.statusCode = 409;
      throw error;
    }
    const evidenceDir = this.store.evidencePath(runId);
    try {
      await fs.mkdir(evidenceDir, { mode: 0o700 });
    } catch (error) {
      if (error.code !== 'EEXIST') {
        throw error;
      }
      const reused = new Error(
        `guard run ID ${runId} was already used; retained evidence makes run IDs immutable`,
      );
      reused.code = 'GUARD_RUN_ID_REUSED';
      reused.statusCode = 409;
      throw reused;
    }
    let containerId = null;
    let adapters = [];
    let networkAllocation = null;
    let networkPreparationStarted = false;
    let scopedPreparation = null;
    let runtimeAppArmor = null;
    let runtimeProfile = profile;
    let runtimeAttestations = [];
    let ebpfAuthority = null;
    let runner = null;
    let run = {
      runId,
      name: request.name,
      mode: request.mode,
      agentId: request.agentId || request.name,
      profileDir: profile.profileDir || null,
      status: 'preparing',
      evidenceDir,
      evidenceComplete: false,
      health,
      approvalHash:
        egressApprovalHash(egressVerification) ||
        verification?.approval?.contentHash ||
        null,
      profilePolicyHash: egressVerification?.policyHash || null,
      workspaceKey:
        egressVerification?.workspaceKey ||
        (scopedWorkspace ? scopedWorkspaceKey(scopedWorkspace) : null),
      workspaceIdentity,
      requestedNetwork: request.requestedNetwork || null,
    };
    await this.store.writeRun(run);
    try {
      const imageInfo = await this.docker.inspectImage(request.image);
      const runnerImageAbi = assertRunnerImageAbi(imageInfo);
      const imageReference = preferredImageReference(request.image, imageInfo);
      const imageDigest = imageInfo?.Id || imageReference;
      const scopedBackendHealth = SCOPED_EGRESS_MODES.has(request.mode)
        ? this.scopedEgress.preflight()
        : null;
      const scopedResolvers = SCOPED_EGRESS_MODES.has(request.mode)
        ? typeof this.scopedEgress.resolversFor === 'function'
          ? this.scopedEgress.resolversFor(request.resolvers)
          : [...(request.resolvers || this.scopedEgress.resolvers || [])]
        : null;
      if (request.mode === 'egress-enforce') {
        ebpfAuthority = await this.ebpfActivations.verifyActive({
          imageDigest,
          workspaceKey: run.workspaceKey,
          workspaceIdentity,
          backendAbi: EBPF_EGRESS_BACKEND_ABI,
          objectDigest: scopedBackendHealth.objectDigest,
          capabilities: { ...EBPF_EGRESS_CAPABILITIES },
          resolvers: [...scopedResolvers],
          platformContainment: { ...EBPF_PLATFORM_CONTAINMENT },
        });
        const verifiedSubject = ebpfAuthority.verification.ebpfPolicy.subject;
        if (
          verifiedSubject.workspaceKey !== run.workspaceKey
          || verifiedSubject.workspaceIdentity.dev !== workspaceIdentity.dev
          || verifiedSubject.workspaceIdentity.ino !== workspaceIdentity.ino
          || verifiedSubject.imageDigest !== imageDigest
        ) {
          throw new Error(
            'active guard-ebpf deployment does not bind the exact runtime subject',
          );
        }
        runtimeAttestations.push({
          apiVersion: 'notty.dev/v1alpha1',
          kind: 'NoshGuardEbpfActivationSnapshot',
          schemaVersion: 1,
          capturedAt: new Date().toISOString(),
          runId,
          activeGrantSetDigest: ebpfAuthority.state.activeGrantSetDigest,
          leafBundleDigest: ebpfAuthority.current.leafBundleDigest,
          approvalEnvelopeDigest: ebpfAuthority.current.approvalEnvelopeDigest,
          grantEnvelopeDigest: ebpfAuthority.current.grantEnvelopeDigest,
          activatedAt: ebpfAuthority.current.activatedAt,
          backendAbi: EBPF_EGRESS_BACKEND_ABI,
          objectDigest: scopedBackendHealth.objectDigest,
          subject: structuredClone(verifiedSubject),
        });
        run = await this.store.writeRun({
          ...run,
          approvalHash: ebpfAuthority.current.approvalEnvelopeDigest,
          profilePolicyHash: ebpfAuthority.verification.policyDigest,
          ebpfActivation: {
            activeGrantSetDigest: ebpfAuthority.state.activeGrantSetDigest,
            leafBundleDigest: ebpfAuthority.current.leafBundleDigest,
            approvalEnvelopeDigest: ebpfAuthority.current.approvalEnvelopeDigest,
            grantEnvelopeDigest: ebpfAuthority.current.grantEnvelopeDigest,
          },
          runtimeAttestations,
        });
      }
      if (
        FULL_RUNTIME_PROFILE_MODES.has(request.mode) ||
        request.mode === 'egress-audit'
      ) {
        const expectedImageDigest =
          egressVerification?.imageDigest ||
          verification?.profile?.spec?.target?.imageDigest;
        if (!expectedImageDigest || expectedImageDigest !== imageDigest) {
          throw new Error(
            `profile image digest mismatch: expected ${
              expectedImageDigest || 'an immutable digest'
            }, got ${imageDigest}`,
          );
        }
      }
      if (egressVerification && request.mode !== 'egress-enforce') {
        const egressSnapshot = await snapshotEgressProfile({
          verification: egressVerification,
          evidenceDir,
          runId,
          mode: request.mode,
        });
        runtimeAttestations.push(egressSnapshot.attestation);
      }
      const profileRevision =
        ebpfAuthority?.current?.leafBundleDigest ||
        egressVerification?.revision ||
        verification?.approval?.revision ||
        request.profileRevision ||
        'candidate';
      if (FULL_RUNTIME_PROFILE_MODES.has(request.mode)) {
        const snapshot = await snapshotRuntimeArtifacts({
          profileDir: profile.profileDir,
          outputDir: evidenceDir,
          runId,
          artifactHashes:
            verification?.approval?.artifacts || verification?.artifacts,
        });
        runtimeProfile = snapshot;
        runtimeAttestations.push(snapshot.attestation);
        runtimeAppArmor = await renderAppArmorProfile({
          templatePath: runtimeProfile.apparmorProfile,
          approvedTemplateHash: `sha256:${
            (
              verification?.approval?.artifacts ||
              verification?.artifacts
            )['apparmor.profile']
          }`,
          outputDir: evidenceDir,
          runId,
        });
        this.hostProfiles.load(runtimeAppArmor.profilePath, request.mode);
        runtimeAttestations.push(runtimeAppArmor.attestation);
        runtimeProfile = {
          ...runtimeProfile,
          apparmorProfile: runtimeAppArmor.profilePath,
          apparmorProfileName: runtimeAppArmor.profileName,
        };
      }
      const runtimeDocuments = FULL_RUNTIME_PROFILE_MODES.has(request.mode)
        ? await loadRuntimeProfileDocuments(runtimeProfile, request.mode)
        : { seccomp: null, docker: null };
      const scopedEgress = SCOPED_EGRESS_MODES.has(request.mode);
      networkPreparationStarted = true;
      networkAllocation = scopedEgress
        ? await this.scopedEgress.prepareNetwork(runId)
        : await this.egress.prepareNetwork(runId);
      scopedPreparation = scopedEgress
        ? await this.scopedEgress.prepareRun({
            runId,
            mode: request.mode,
            imageDigest,
            workspaceKey: run.workspaceKey,
            workspaceIdentity,
            evidenceDir,
            objectDigest: scopedBackendHealth.objectDigest,
            resolvers: scopedResolvers,
            platformContainmentCidrs: platformContainmentCidrs(networkAllocation),
            rules: request.mode === 'egress-enforce'
              ? ebpfAuthority?.verification?.ebpfPolicy?.rules || []
              : egressVerification?.rules || [],
          })
        : null;
      run = await this.store.writeRun({
        ...run,
        status: 'network-prepared',
        egress: {
          networkName: networkAllocation.networkName,
          gatewayIpv4: networkAllocation.egressGateway,
          sourceIpv4: networkAllocation.runnerIp,
          sourceIpv6: networkAllocation.runnerIpv6,
          gatewayContainerId: networkAllocation.gatewayContainerId,
          ...(scopedPreparation || {}),
        },
      });
      runner = buildRunnerSpec({
        ...request,
        runId,
        image: imageReference,
        imageDigest,
        network: scopedEgress ? 'none' : networkAllocation.networkName,
        runnerIp: scopedEgress ? null : networkAllocation.runnerIp,
        runnerIpv6: scopedEgress ? null : networkAllocation.runnerIpv6,
        managedDns: scopedEgress ? null : networkAllocation.egressGateway,
        resolverConfigPath: scopedPreparation?.resolverConfigPath || null,
        gatewayPublicOrigin: this.gatewayPublicOrigin,
        profileRevision,
        seccompDocument: runtimeDocuments.seccomp,
        apparmorProfileName: runtimeAppArmor?.profileName,
        resources: runtimeDocuments.docker
          ? { pids: runtimeDocuments.docker.spec.pidsLimit }
          : undefined,
      });
      if (scopedWorkspace) {
        if (runner.workdir !== scopedWorkspace.canonicalPath) {
          const error = new Error(
            'runner workspace changed after scoped identity capture',
          );
          error.code = 'GUARD_EGRESS_WORKSPACE_CHANGED';
          throw error;
        }
      }
      assertDockerArtifactConformance(runner.spec, runtimeDocuments.docker);
      run = await this.store.writeRun({
        ...run,
        name: runner.name,
        mode: runner.mode,
        agentId: runner.agentId,
        profileRevision: runner.profileRevision,
        imageRequested: request.image,
        imageReference,
        imageDigest,
        runnerImageAbi,
        workdir: runner.workdir,
        status: 'creating',
        summary: summarizeRunnerSpec(runner),
        runtimeAppArmorProfile: runtimeAppArmor?.profilePath || null,
        apparmorProfileName: runtimeAppArmor?.profileName || null,
        runtimeAttestations,
      });
      const created = await this.docker.createContainer(runner.name, runner.spec);
      containerId = created?.Id;
      if (!containerId) {
        throw new Error('Docker did not return a container ID');
      }
      run = await this.store.writeRun({
        ...run,
        containerId,
        warnings: created.Warnings || [],
        status: 'created',
      });
      await this.docker.startContainer(containerId);
      let runtimeIdentity = await this.inspectRuntimeIdentity({
        containerId,
        runId: runner.runId,
        imageDigest,
        networkName: scopedEgress ? null : networkAllocation.networkName,
        sourceIpv4: scopedEgress ? null : networkAllocation.runnerIp,
        sourceIpv6: scopedEgress ? null : networkAllocation.runnerIpv6,
        requireNoNetwork: scopedEgress,
      });
      let {
        inspected,
        initPid,
        namespaces,
        cgroup,
      } = runtimeIdentity;
      if (scopedWorkspace) {
        await this.workspaceMountVerifier({
          workdir: runner.workdir,
          initPid,
          expected: workspaceIdentity,
        });
      }
      const duplicateNamespace = (await this.store.listRuns()).find(
        (entry) =>
          entry.runId !== runner.runId &&
          runReservesCgroupNamespace(entry) &&
          entry.namespaces?.cgroup === namespaces.cgroup,
      );
      if (duplicateNamespace) {
        throw new Error(
          `runner cgroup namespace is already assigned to ${duplicateNamespace.runId}`,
        );
      }
      run = await this.store.writeRun({
        ...run,
        status: 'identity-verified',
        initPid,
        namespaces,
        cgroup,
      });
      if (!scopedEgress) {
        const egress = await this.egress.attachRun(
          run,
          inspected,
          networkAllocation,
          egressVerification?.policyPath ||
            await existingPath(runtimeProfile.networkPolicy),
          {
            networkRules: request.mode === 'egress-enforce'
              ? egressVerification?.approval?.rules
              : egressVerification?.rules,
            workspaceKey: egressVerification?.workspaceKey || null,
            approvalHash: egressApprovalHash(egressVerification),
            profilePolicyHash: egressVerification?.policyHash || null,
          },
        );
        run = await this.store.writeRun({
          ...run,
          egress,
          status: 'network-gated',
        });
        const egressPolicyHealth = await this.managedEgressRunHealth(run);
        if (egressPolicyHealth.ok !== true) {
          const error = new Error(
            `managed egress policy failed post-attach verification: ${
              egressPolicyHealth.error || 'unknown policy drift'
            }`,
          );
          error.code = 'GUARD_EGRESS_POLICY_UNVERIFIED';
          error.health = egressPolicyHealth;
          throw error;
        }
        run = await this.store.writeRun({
          ...run,
          egressPolicyHealth,
        });
      }
      if (runner.mode === 'enforce') {
        const rendered = await renderApprovedTetragonPolicy({
          templatePath: runtimeProfile.tetragonPolicy,
          approvedTemplateHash: verification?.approval?.artifacts?.['tetragon.yaml']
            ? `sha256:${verification.approval.artifacts['tetragon.yaml']}`
            : null,
          outputDir: evidenceDir,
          runId: runner.runId,
          containerId,
          imageDigest,
          initPid,
          namespaces,
        });
        runtimeProfile = {
          ...runtimeProfile,
          tetragonPolicy: rendered.policyPath,
          tetragonPolicyName: rendered.policyName,
        };
        runtimeAttestations.push(rendered.attestation);
        run = await this.store.writeRun({
          ...run,
          runtimeAttestations,
          runtimeTetragonPolicy: rendered.policyPath,
          tetragonPolicyName: rendered.policyName,
          status: 'policy-rendered',
        });
      }

      const context = {
        runId: runner.runId,
        containerId,
        containerName: runner.name,
        mode: runner.mode,
        imageDigest,
        initPid: initPid || '',
        cgroupNamespace: namespaces.cgroup || '',
        cgroupPath: cgroup.path,
        cgroupId: cgroup.id,
        mountNamespace: namespaces.mnt || '',
        networkNamespace: namespaces.net || '',
        evidenceDir,
        managedDns: scopedEgress ? '' : networkAllocation.egressGateway,
        runnerIp: networkAllocation.runnerIp,
        networkName: networkAllocation.networkName,
        workspaceKey: run.workspaceKey || '',
        egressBackend: run.egress?.backend || '',
        egressBackendMode: run.egress?.backendMode || '',
        egressPolicyPath: run.egress?.policyPath || '',
        egressPolicyDigest: run.egress?.policyDigest || '',
        egressPinRoot: run.egress?.pinRoot || '',
        grantsPath: path.join(this.store.root, 'grants', 'current.json'),
        ...runtimeProfile,
      };
      const adapterHealth = await this.adapters.health(runner.mode, context);
      const failures = requiredAdapterFailures(adapterHealth);
      if (failures.length) {
        throw new Error(
          `required guard adapters are unhealthy: ${failures
            .map((failure) => failure.name)
            .join(', ')}`,
        );
      }
      adapters = await this.adapters.attach(runner.mode, context, {
        onRequiredAdapterExit: (failure) =>
          this.handleRequiredAdapterExit(runner.runId, failure),
      });
      const optionalFailures = adapters.filter((adapter) => adapter.error);
      const evidenceComplete =
        failures.length === 0 && optionalFailures.length === 0;
      const scopedBackendAttestation = scopedEgress
        ? this.scopedEgress.attestRun(
            { ...run, adapters },
            adapters,
          )
        : null;
      if (scopedBackendAttestation) {
        runtimeAttestations.push(scopedBackendAttestation);
      }
      if (scopedEgress) {
        run = await this.store.writeRun({
          ...run,
          status: 'policy-attached',
          initPid,
          namespaces,
          cgroup,
          evidenceDir,
          adapterHealth,
          adapters,
          evidenceComplete,
          runtimeAttestations,
          egress: {
            ...run.egress,
            attestation: scopedBackendAttestation,
          },
        });
        const networkAdmissionPolicyHealth =
          await this.managedEgressRunHealth(run);
        if (networkAdmissionPolicyHealth.ok !== true) {
          const error = new Error(
            `nosh-egress policy failed pre-network verification: ${
              networkAdmissionPolicyHealth.error || 'unknown policy drift'
            }`,
          );
          error.code = 'GUARD_EBPF_EGRESS_POLICY_UNVERIFIED';
          error.health = networkAdmissionPolicyHealth;
          throw error;
        }
        run = await this.store.writeRun({
          ...run,
          networkAdmissionPolicyHealth,
        });
        this.assertRequiredAdaptersStillRunning(runner.runId);
        await this.docker.connectNetwork(
          networkAllocation.networkName,
          containerId,
          {
            ipv4Address: networkAllocation.runnerIp,
            ipv6Address: networkAllocation.runnerIpv6,
          },
        );
        this.assertRequiredAdaptersStillRunning(runner.runId);
        runtimeIdentity = await this.inspectRuntimeIdentity(
          {
            containerId,
            runId: runner.runId,
            imageDigest,
            networkName: networkAllocation.networkName,
            sourceIpv4: networkAllocation.runnerIp,
            sourceIpv6: networkAllocation.runnerIpv6,
          },
          runtimeIdentity,
        );
        ({ inspected, initPid, namespaces, cgroup } = runtimeIdentity);
        const egress = await this.scopedEgress.bindRun(
          run,
          inspected,
          networkAllocation,
          run.egress,
        );
        run = await this.store.writeRun({
          ...run,
          status: 'gated',
          egress,
          summary: {
            ...run.summary,
            network: networkAllocation.networkName,
          },
        });
      } else {
        run = await this.store.writeRun({
          ...run,
          status: 'gated',
          initPid,
          namespaces,
          cgroup,
          evidenceDir,
          adapterHealth,
          adapters,
          evidenceComplete,
          runtimeAttestations,
        });
      }
      await this.inspectRuntimeIdentity(
        {
          containerId,
          runId: runner.runId,
          imageDigest,
          networkName: networkAllocation.networkName,
          sourceIpv4: networkAllocation.runnerIp,
          sourceIpv6: networkAllocation.runnerIpv6,
        },
        runtimeIdentity,
      );
      const releaseEgressPolicyHealth =
        await this.managedEgressRunHealth(run);
      if (releaseEgressPolicyHealth.ok !== true) {
        const error = new Error(
          `managed egress policy failed release verification: ${
            releaseEgressPolicyHealth.error || 'unknown policy drift'
          }`,
        );
        error.code = scopedEgress
          ? 'GUARD_EBPF_EGRESS_POLICY_UNVERIFIED'
          : 'GUARD_EGRESS_POLICY_UNVERIFIED';
        error.health = releaseEgressPolicyHealth;
        throw error;
      }
      run = await this.store.writeRun({
        ...run,
        releaseEgressPolicyHealth,
      });
      if (typeof this.adapters.runtimeHealth === 'function') {
        const releaseAdapterHealth = await this.adapters.runtimeHealth(
          run,
          context,
        );
        const releaseAdapterFailures = releaseAdapterHealth.filter(
          (entry) => entry.required && entry.ok !== true,
        );
        if (releaseAdapterFailures.length) {
          const error = new Error(
            `required guard adapters failed before runner release: ${
              releaseAdapterFailures.map((failure) => failure.name).join(', ')
            }`,
          );
          error.code = 'GUARD_REQUIRED_ADAPTER_EXITED';
          error.health = releaseAdapterFailures;
          throw error;
        }
        run = await this.store.writeRun({
          ...run,
          releaseAdapterHealth,
        });
      }
      this.assertRequiredAdaptersStillRunning(runner.runId);
      await this.docker.releaseGate(containerId);
      this.assertRequiredAdaptersStillRunning(runner.runId);
      run = await this.store.writeRun({
        ...run,
        status: 'running',
        releasedAt: new Date().toISOString(),
      });
      return run;
    } catch (error) {
      error.runId = run.runId;
      let networkCleanupVerified =
        networkPreparationStarted === false
        || error.networkCleanupVerified === true;
      if (containerId) {
        error.containerId = containerId;
      }
      const runtimeLogTail = await this.captureStoppedRuntimeLogTail(
        containerId,
        error,
      );
      if (runtimeLogTail) {
        error.runtimeLogTail = runtimeLogTail;
        error.message += stoppedRuntimeLogSummary(runtimeLogTail);
      }
      if (!adapters.length && Array.isArray(error.attachedAdapters)) {
        adapters = error.attachedAdapters;
      }
      const failedRun = {
        ...run,
        containerId,
        adapters,
        runtimeAppArmorProfile:
          run.runtimeAppArmorProfile || runtimeAppArmor?.profilePath || null,
        apparmorProfileName:
          run.apparmorProfileName || runtimeAppArmor?.profileName || null,
        status: 'failed',
        failure: {
          message: error.message,
          code: error.code || null,
          cleanupVerified: networkCleanupVerified,
          at: new Date().toISOString(),
          ...(error.runtimeState
            ? { runtimeState: error.runtimeState }
            : {}),
          ...(error.runtimeLogTail
            ? { runtimeLogTail: error.runtimeLogTail }
            : {}),
        },
      };
      let statePersistenceError = null;
      try {
        run = await this.store.writeRun(failedRun);
      } catch (writeError) {
        run = failedRun;
        statePersistenceError = writeError.message;
      }
      let detachResults = [];
      const cleanupFailures = [];
      let containerContained = !containerId;
      let containerRemoved = false;
      let containerPaused = false;
      if (containerId && runner) {
        try {
          const containment = await this.containForCleanup(containerId, 2);
          containerContained = true;
          containerRemoved = containment.containerRemoved === true;
          containerPaused = containment.containerPaused === true;
        } catch (cleanupError) {
          cleanupFailures.push(
            cleanupFailure('docker-containment', cleanupError),
          );
        }
        if (containerContained) {
          try {
            detachResults = await this.adapters.detach(run, {
              runId: runner.runId,
              containerId,
              containerName: runner.name,
              mode: runner.mode,
              evidenceDir: this.store.evidencePath(runner.runId),
              ...artifactContext(run.profileDir),
              tetragonPolicy:
                run.runtimeTetragonPolicy ||
                artifactContext(run.profileDir).tetragonPolicy,
              tetragonPolicyName: run.tetragonPolicyName || '',
            });
            cleanupFailures.push(...criticalCleanupFailures(detachResults));
          } catch (cleanupError) {
            cleanupFailures.push(cleanupFailure('adapters', cleanupError));
          }
        }
      }
      let evidenceManifest = null;
      let evidenceFinalizationError = null;
      if (containerContained) {
        run = await this.captureFinalEgressSnapshot({
          ...run,
          detachResults,
          evidenceComplete: false,
        });
        try {
          const evidence = await finalizeRunEvidence(run, {
            stateDir: this.store.root,
          });
          evidenceManifest = evidence.manifestPath;
        } catch (finalizationError) {
          evidenceFinalizationError = finalizationError.message;
        }
        if (containerId && !containerRemoved) {
          try {
            await this.docker.removeContainer(containerId, true);
            containerRemoved = true;
          } catch (cleanupError) {
            if (cleanupError.statusCode === 404) {
              containerRemoved = true;
            } else {
              cleanupFailures.push(
                cleanupFailure('docker-container', cleanupError),
              );
            }
          }
        }
      }
      if (
        networkAllocation
        && containerContained
        && (
          !SCOPED_EGRESS_MODES.has(run.mode)
          || containerRemoved
          || !containerPaused
        )
      ) {
        try {
          const scopedCleanup = SCOPED_EGRESS_MODES.has(run.mode);
          const backend = scopedCleanup
            ? this.scopedEgress
            : this.egress;
          const cleanupRun = {
            ...run,
            egress: {
              ...(scopedCleanup ? scopedPreparation || {} : {}),
              ...(run.egress || {}),
              networkName:
                run.egress?.networkName || networkAllocation.networkName,
              gatewayContainerId:
                run.egress?.gatewayContainerId
                || networkAllocation.gatewayContainerId
                || null,
              sourceIpv4:
                run.egress?.sourceIpv4 || networkAllocation.runnerIp,
              sourceIpv6:
                run.egress?.sourceIpv6 || networkAllocation.runnerIpv6 || null,
            },
          };
          await backend.detachRun(cleanupRun);
          networkCleanupVerified = true;
        } catch (cleanupError) {
          cleanupFailures.push({
            name: 'managed-egress',
            cleanupCritical: true,
            cleanupOk: false,
            error: cleanupError.message,
          });
        }
      }
      let apparmorResult = null;
      if (runtimeAppArmor && (containerRemoved || !containerId)) {
        apparmorResult = this.hostProfiles.remove(runtimeAppArmor.profilePath);
        if (apparmorResult.removed === false) {
          cleanupFailures.push(cleanupFailure('apparmor', apparmorResult.error));
        }
      }
      try {
        await this.store.writeRun({
          ...run,
          failure: {
            ...(run.failure || failedRun.failure),
            cleanupVerified: networkCleanupVerified,
          },
          status: cleanupFailures.length ? 'quarantined' : 'failed',
          detachResults,
          cleanupFailures,
          apparmorResult,
          evidenceManifest,
          evidenceFinalizationError,
          evidenceComplete: false,
          containerRemoved,
          containerPaused: containerPaused && !containerRemoved,
          statePersistenceError,
        });
      } catch (writeError) {
        error.statePersistenceError = writeError.message;
      }
      error.containerRemoved = containerRemoved;
      throw error;
    }
  }

  async runAction(identifier, action, options = {}) {
    const run = await this.store.findRun(identifier);
    if (!run) {
      const error = new Error(`guard run not found: ${identifier}`);
      error.statusCode = 404;
      throw error;
    }
    if (this.pendingRunActions.has(run.runId)) {
      const error = new Error(`guard run action is already in progress: ${run.runId}`);
      error.code = 'GUARD_RUN_ACTION_CONFLICT';
      error.statusCode = 409;
      throw error;
    }
    this.pendingRunActions.add(run.runId);
    try {
      return await this.runActionExclusive(run, identifier, action, options);
    } finally {
      this.pendingRunActions.delete(run.runId);
    }
  }

  async runActionExclusive(run, identifier, action, options = {}) {
    if (action === 'attach') {
      if (run.status !== 'running') {
        const error = new Error(
          `guard run is not attachable in status ${run.status || 'unknown'}: ${identifier}`,
        );
        error.code = 'GUARD_RUN_NOT_RUNNING';
        error.statusCode = 409;
        throw error;
      }
      const failures = [];
      let runtimeIdentity = null;
      try {
        runtimeIdentity = await this.inspectRuntimeIdentity(
          {
            containerId: run.containerId,
            runId: run.runId,
            imageDigest: run.imageDigest,
            networkName: run.egress?.networkName,
            sourceIpv4: run.egress?.sourceIpv4,
            sourceIpv6: run.egress?.sourceIpv6,
          },
          {
            initPid: run.initPid,
            namespaces: run.namespaces,
            cgroup: run.cgroup,
          },
        );
      } catch (error) {
        failures.push({
          name: 'runtime-identity',
          required: true,
          ok: false,
          code: error.code || null,
          error: error.message,
        });
      }
      const scopedEgress = SCOPED_EGRESS_MODES.has(run.mode);
      let egressHealth = { ok: true };
      if (!scopedEgress) {
        try {
          egressHealth = await this.egress.health();
        } catch (error) {
          egressHealth = {
            name: 'managed-egress',
            required: true,
            ok: false,
            error: error.message,
          };
        }
        if (egressHealth.ok !== true) {
          failures.push({
            name: 'managed-egress',
            required: true,
            ...egressHealth,
            ok: false,
          });
        } else if (
          !run.egress?.gatewayContainerId
          || egressHealth.containerId !== run.egress.gatewayContainerId
        ) {
          failures.push({
            name: 'managed-egress-identity',
            required: true,
            ok: false,
            error: 'managed egress gateway container identity changed',
          });
        }
      }
      const egressPolicyHealth = await this.managedEgressRunHealth(run);
      if (egressPolicyHealth.ok !== true) {
        failures.push({
          name: 'managed-egress-policy',
          required: true,
          ...egressPolicyHealth,
          ok: false,
        });
      }
      const context = {
        runId: run.runId,
        containerId: run.containerId,
        containerName: run.name,
        mode: run.mode,
        imageDigest: run.imageDigest || '',
        initPid: run.initPid || '',
        cgroupNamespace: run.namespaces?.cgroup || '',
        cgroupPath: run.cgroup?.path || '',
        cgroupId: run.cgroup?.id || '',
        mountNamespace: run.namespaces?.mnt || '',
        networkNamespace: run.namespaces?.net || '',
        evidenceDir: run.evidenceDir || this.store.evidencePath(run.runId),
        managedDns: run.egress?.gatewayIpv4 || '',
        runnerIp: run.egress?.sourceIpv4 || '',
        networkName: run.egress?.networkName || '',
        grantsPath: path.join(this.store.root, 'grants', 'current.json'),
        ...artifactContext(run.profileDir),
        tetragonPolicy:
          run.runtimeTetragonPolicy ||
          artifactContext(run.profileDir).tetragonPolicy,
        tetragonPolicyName: run.tetragonPolicyName || '',
      };
      let adapterHealth;
      try {
        adapterHealth = await this.adapters.runtimeHealth(run, context);
      } catch (error) {
        adapterHealth = [
          {
            name: 'adapter-controller',
            required: true,
            ok: false,
            error: error.message,
          },
        ];
      }
      failures.push(
        ...adapterHealth.filter((entry) => entry.required && !entry.ok),
      );
      if (failures.length) {
        let quarantine = null;
        let quarantineError = null;
        try {
          quarantine = await this.quarantineRun(run, failures);
        } catch (error) {
          quarantineError = error.message;
        }
        const error = new Error(
          `guard run failed attach revalidation: ${failures
            .map((failure) => failure.name)
            .join(', ')}`,
        );
        error.code = 'GUARD_ATTACH_REVALIDATION_FAILED';
        error.statusCode = 409;
        error.health = {
          failures,
          quarantineStatus: quarantine?.status || null,
          quarantineError,
        };
        throw error;
      }
      return {
        ...run,
        attachment: {
          validated: true,
          validatedAt: new Date().toISOString(),
          containerId: run.containerId,
          dockerSocket: this.docker.socketPath || DEFAULT_DOCKER_SOCKET,
          initPid: runtimeIdentity.initPid,
          namespaces: runtimeIdentity.namespaces,
          cgroup: runtimeIdentity.cgroup,
          networkName: run.egress?.networkName || null,
          sourceIpv4: run.egress?.sourceIpv4 || null,
          sourceIpv6: run.egress?.sourceIpv6 || null,
          gatewayContainerId: run.egress?.gatewayContainerId || null,
          adapters: adapterHealth.map((entry) => ({
            name: entry.name,
            required: entry.required,
            ok: entry.ok,
          })),
        },
      };
    }
    if (!run.containerId) {
      if (action !== 'rm') {
        throw new Error(`guard run has no container: ${identifier}`);
      }
      if (
        run.failure?.cleanupVerified !== true
        && !PRE_NETWORK_FAILURE_CODES.has(run.failure?.code)
      ) {
        const error = new Error(
          `refusing removal because pre-container cleanup is unverified: ${identifier}`,
        );
        error.code = 'GUARD_CLEANUP_INCOMPLETE';
        error.statusCode = 409;
        throw error;
      }
      const cleanupFailures = (run.cleanupFailures || []).filter(
        (failure) => failure.cleanupCritical === true,
      );
      const nonRetryableCleanupFailures = cleanupFailures.filter(
        (failure) =>
          failure.name !== 'apparmor' || !run.runtimeAppArmorProfile,
      );
      if (
        run.quarantineActive === true
        || nonRetryableCleanupFailures.length
      ) {
        const error = new Error(
          `refusing removal while critical cleanup is incomplete${
            nonRetryableCleanupFailures.length
              ? `: ${nonRetryableCleanupFailures
                  .map((failure) => failure.name)
                  .join(', ')}`
              : ''
          }`,
        );
        error.code = 'GUARD_CLEANUP_INCOMPLETE';
        error.statusCode = 409;
        throw error;
      }
      const apparmorResult = run.apparmorResult?.removed
        ? run.apparmorResult
        : run.runtimeAppArmorProfile
          ? this.hostProfiles.remove(run.runtimeAppArmorProfile)
          : null;
      if (apparmorResult?.removed === false) {
        await this.store.writeRun({
          ...run,
          status: 'quarantined',
          quarantineActive: false,
          evidenceComplete: false,
          cleanupFailures: [cleanupFailure('apparmor', apparmorResult.error)],
          apparmorResult,
        });
        const error = new Error(
          'refusing removal while AppArmor cleanup is incomplete',
        );
        error.code = 'GUARD_CLEANUP_INCOMPLETE';
        error.statusCode = 409;
        throw error;
      }
      await this.store.removeRun(run.runId);
      return {
        ...run,
        status: 'removed',
        apparmorResult,
        containerRemoved: true,
        containerPaused: false,
      };
    }
    const context = {
      runId: run.runId,
      containerId: run.containerId,
      containerName: run.name,
      mode: run.mode,
      evidenceDir: run.evidenceDir || this.store.evidencePath(run.runId),
      ...artifactContext(run.profileDir),
      tetragonPolicy:
        run.runtimeTetragonPolicy || artifactContext(run.profileDir).tetragonPolicy,
      tetragonPolicyName: run.tetragonPolicyName || '',
    };
    if (action === 'stop') {
      await this.docker.stopContainer(run.containerId, options.timeoutSeconds || 10);
      const detachResults = await this.adapters.detach(run, context);
      const apparmorResult = run.runtimeAppArmorProfile
        ? this.hostProfiles.remove(run.runtimeAppArmorProfile)
        : null;
      const cleanupFailures = criticalCleanupFailures(detachResults);
      if (apparmorResult?.removed === false) {
        cleanupFailures.push({
          name: 'apparmor',
          cleanupCritical: true,
          cleanupOk: false,
          error: apparmorResult.error,
        });
      }
      const finalRun = await this.captureFinalEgressSnapshot({
        ...run,
        detachResults,
        evidenceComplete:
          run.evidenceComplete &&
          detachResults.every((result) => result.ok !== false),
      });
      let evidence;
      try {
        evidence = await finalizeRunEvidence(
          finalRun,
          { stateDir: this.store.root },
        );
      } catch (error) {
        await this.store.writeRun({
          ...finalRun,
          status: 'quarantined',
          quarantineActive: false,
          stoppedAt: new Date().toISOString(),
          detachResults,
          cleanupFailures,
          apparmorResult,
          evidenceComplete: false,
          evidenceFinalizationError: error.message,
        });
        throw error;
      }
      return this.store.writeRun({
        ...finalRun,
        status: cleanupFailures.length ? 'quarantined' : 'stopped',
        stoppedAt: new Date().toISOString(),
        detachResults,
        cleanupFailures,
        apparmorResult,
        evidenceManifest: evidence.manifestPath,
        evidenceComplete: evidence.manifest.complete,
      });
    }
    if (action === 'rm') {
      let detachResults = run.detachResults || [];
      let evidenceManifest = run.evidenceManifest || null;
      let evidenceComplete = run.evidenceComplete;
      let cleanupAttemptResults = [];
      let currentRun = run;
      let containerRemoved = run.containerRemoved === true;
      let containerPaused = run.containerPaused === true && !containerRemoved;
      const retryCriticalCleanup =
        run.quarantineActive === true ||
        (run.cleanupFailures || []).some(
          (failure) => failure.cleanupCritical === true,
        );
      if (!containerRemoved) {
        try {
          const containment = await this.containForCleanup(run.containerId, 5);
          containerRemoved =
            containerRemoved || containment.containerRemoved === true;
          containerPaused =
            !containerRemoved && containment.containerPaused === true;
        } catch (error) {
          await this.store.writeRun({
            ...run,
            status: 'quarantined',
            quarantineActive: true,
            evidenceComplete: false,
            cleanupFailures: [
              ...(run.cleanupFailures || []).filter(
                (failure) => failure.name !== 'docker-containment',
              ),
              cleanupFailure('docker-containment', error),
            ],
          });
          throw error;
        }
      }
      const needsAdapterCleanup =
        run.status === 'running' ||
        retryCriticalCleanup ||
        ((run.adapters || []).length > 0 && detachResults.length === 0);
      if (run.status === 'running') {
        detachResults = await this.adapters.detach(run, context);
        cleanupAttemptResults = detachResults;
        currentRun = await this.captureFinalEgressSnapshot({
          ...run,
          detachResults,
          evidenceComplete:
            run.evidenceComplete &&
            detachResults.every((result) => result.ok !== false),
        });
        let evidence;
        try {
          evidence = await finalizeRunEvidence(
            currentRun,
            { stateDir: this.store.root },
          );
        } catch (error) {
          await this.store.writeRun({
            ...currentRun,
            status: 'quarantined',
            quarantineActive: !containerRemoved,
            stoppedAt: new Date().toISOString(),
            detachResults,
            evidenceComplete: false,
            evidenceFinalizationError: error.message,
            containerRemoved,
            containerPaused,
          });
          throw error;
        }
        evidenceManifest = evidence.manifestPath;
        evidenceComplete = evidence.manifest.complete;
      } else if (needsAdapterCleanup) {
        const retryRun = {
          ...run,
          adapters: retryCriticalCleanup
            ? (run.adapters || []).filter(
                (adapter) => adapter.cleanupCritical === true,
              )
            : run.adapters || [],
        };
        cleanupAttemptResults = await this.adapters.detach(retryRun, context);
        detachResults = [
          ...(run.detachResults || []).filter(
            (result) => result.cleanupCritical !== true,
          ),
          ...cleanupAttemptResults,
        ];
      }
      const cleanupFailures = criticalCleanupFailures(cleanupAttemptResults);
      if (cleanupFailures.length) {
        await this.store.writeRun({
          ...currentRun,
          status: 'quarantined',
          quarantineActive: !containerRemoved,
          detachResults,
          cleanupFailures,
          evidenceManifest,
          evidenceComplete,
          containerRemoved,
          containerPaused,
        });
        const error = new Error(
          `refusing removal while critical cleanup is incomplete: ${cleanupFailures
            .map((failure) => failure.name)
            .join(', ')}`,
        );
        error.code = 'GUARD_CLEANUP_INCOMPLETE';
        error.statusCode = 409;
        throw error;
      }
      if (!containerRemoved) {
        try {
          await this.docker.removeContainer(run.containerId, true);
          containerRemoved = true;
          containerPaused = false;
        } catch (error) {
          if (error.statusCode === 404) {
            containerRemoved = true;
            containerPaused = false;
          } else {
            const containerFailure = cleanupFailure('docker-container', error);
            await this.store.writeRun({
              ...currentRun,
              status: 'quarantined',
              quarantineActive: true,
              detachResults,
              cleanupFailures: [containerFailure],
              evidenceManifest,
              evidenceComplete: false,
              containerRemoved: false,
              containerPaused,
            });
            throw error;
          }
        }
      }
      const apparmorResult = run.apparmorResult?.removed
        ? run.apparmorResult
        : run.runtimeAppArmorProfile
          ? this.hostProfiles.remove(run.runtimeAppArmorProfile)
          : null;
      if (apparmorResult?.removed === false) {
        const apparmorFailure = cleanupFailure(
          'apparmor',
          apparmorResult.error,
        );
        await this.store.writeRun({
          ...currentRun,
          status: 'quarantined',
          quarantineActive: false,
          detachResults,
          cleanupFailures: [apparmorFailure],
          apparmorResult,
          evidenceManifest,
          evidenceComplete,
          containerRemoved,
          containerPaused: false,
        });
        const error = new Error(
          'refusing removal while AppArmor cleanup is incomplete',
        );
        error.code = 'GUARD_CLEANUP_INCOMPLETE';
        error.statusCode = 409;
        throw error;
      }
      let egressResult;
      try {
        const backend = SCOPED_EGRESS_MODES.has(currentRun.mode)
          ? this.scopedEgress
          : this.egress;
        egressResult = await backend.detachRun(currentRun);
      } catch (error) {
        await this.store.writeRun({
          ...currentRun,
          status: 'quarantined',
          detachResults,
          cleanupFailures: [
            {
              name: 'managed-egress',
              cleanupCritical: true,
              cleanupOk: false,
              error: error.message,
            },
          ],
          apparmorResult,
          evidenceManifest,
          evidenceComplete,
          containerRemoved,
          containerPaused: false,
        });
        throw error;
      }
      await this.store.removeRun(run.runId);
      return {
        ...currentRun,
        status: 'removed',
        detachResults,
        evidenceManifest,
        evidenceComplete,
        egressResult,
        apparmorResult,
        containerRemoved,
        containerPaused: false,
      };
    }
    throw new TypeError(`unsupported action: ${action}`);
  }

  async quarantineRun(run, failures) {
    const quarantinedAt = new Date().toISOString();
    let pauseError = null;
    let emergencyRemovalError = null;
    let containerRemoved = false;
    let contained = false;
    try {
      await this.docker.pauseContainer(run.containerId);
      contained = true;
    } catch (error) {
      pauseError = error.message;
      try {
        await this.docker.removeContainer(run.containerId, true);
        containerRemoved = true;
        contained = true;
      } catch (removalError) {
        if (removalError.statusCode === 404) {
          containerRemoved = true;
          contained = true;
        } else {
          emergencyRemovalError = removalError.message;
        }
      }
    }
    const containmentFailures = contained
      ? []
      : [cleanupFailure(
        'docker-containment',
        new Error(
          emergencyRemovalError
            ? `${pauseError}; force removal failed: ${emergencyRemovalError}`
            : pauseError || 'runner could not be contained',
        ),
      )];
    let current = await this.store.writeRun({
      ...run,
      status: 'quarantined',
      quarantineActive: !containerRemoved,
      quarantinedAt,
      quarantine: {
        reason: 'runtime guard health failure',
        failures,
        pauseError,
        emergencyRemovalError,
      },
      evidenceComplete: false,
      cleanupFailures: containmentFailures,
      containerRemoved,
    });
    if (!contained) {
      return current;
    }
    const context = {
      runId: run.runId,
      containerId: run.containerId,
      containerName: run.name,
      mode: run.mode,
      evidenceDir: run.evidenceDir || this.store.evidencePath(run.runId),
      cgroupPath: run.cgroup?.path || '',
      cgroupId: run.cgroup?.id || '',
      ...artifactContext(run.profileDir),
      tetragonPolicy:
        run.runtimeTetragonPolicy || artifactContext(run.profileDir).tetragonPolicy,
      tetragonPolicyName: run.tetragonPolicyName || '',
    };
    let detachResults = [];
    try {
      detachResults = await this.adapters.detach(run, context);
    } catch (error) {
      detachResults = [
        {
          name: 'adapters',
          ok: false,
          cleanupCritical: true,
          cleanupOk: false,
          error: error.message,
        },
      ];
    }
    const cleanupFailures = [
      ...containmentFailures,
      ...criticalCleanupFailures(detachResults),
    ];
    let apparmorResult = null;
    let evidenceManifest = null;
    current = await this.captureFinalEgressSnapshot({
      ...current,
      detachResults,
      evidenceComplete: false,
    });
    try {
      const evidence = await finalizeRunEvidence(
        {
          ...current,
          detachResults,
          evidenceComplete: false,
        },
        { stateDir: this.store.root },
      );
      evidenceManifest = evidence.manifestPath;
    } catch (error) {
      cleanupFailures.push({
        name: 'evidence-finalizer',
        cleanupCritical: false,
        cleanupOk: false,
        error: error.message,
      });
    }
    if (!containerRemoved) {
      try {
        await this.docker.removeContainer(run.containerId, true);
        containerRemoved = true;
      } catch (error) {
        if (error.statusCode === 404) {
          containerRemoved = true;
        } else {
          cleanupFailures.push(cleanupFailure('docker-container', error));
        }
      }
    }
    let egressResult = null;
    if (containerRemoved && SCOPED_EGRESS_MODES.has(run.mode)) {
      try {
        egressResult = await this.scopedEgress.detachRun({
          ...current,
          containerRemoved: true,
          containerPaused: false,
        });
        if (egressResult?.ok !== true) {
          throw new Error('nosh-egress backend detach returned no success attestation');
        }
      } catch (error) {
        cleanupFailures.push({
          name: 'nosh-egress-backend',
          cleanupCritical: true,
          cleanupOk: false,
          error: error.message,
        });
      }
    }
    if (containerRemoved && run.runtimeAppArmorProfile) {
      apparmorResult = this.hostProfiles.remove(run.runtimeAppArmorProfile);
      if (apparmorResult.removed === false) {
        cleanupFailures.push(cleanupFailure('apparmor', apparmorResult.error));
      }
    }
    const quarantineActive = !containerRemoved || cleanupFailures.some(
      (failure) => failure.cleanupCritical === true,
    );
    current = await this.store.writeRun({
      ...current,
      status: 'quarantined',
      quarantineActive,
      stoppedAt: containerRemoved ? new Date().toISOString() : null,
      detachResults,
      cleanupFailures,
      apparmorResult,
      evidenceManifest,
      evidenceComplete: false,
      containerRemoved,
      egressResult,
    });
    return current;
  }

  async handleRequiredAdapterExit(runId, failure) {
    const retainedFailure = {
      name: failure?.name || 'required-adapter',
      required: true,
      ok: false,
      code: 'GUARD_REQUIRED_ADAPTER_EXITED',
      error: failure?.error || 'required adapter exited unexpectedly',
      ...(Number.isInteger(failure?.exitCode)
        ? { exitCode: failure.exitCode }
        : {}),
      ...(failure?.exitSignal ? { exitSignal: failure.exitSignal } : {}),
      ...(failure?.exitedAt ? { exitedAt: failure.exitedAt } : {}),
    };
    this.requiredAdapterExitFailures.set(runId, retainedFailure);
    if (this.pendingRunStarts.has(runId)) {
      let startupRun;
      try {
        startupRun = await this.store.readRun(runId);
      } catch {
        return { runId, status: 'startup-run-not-found' };
      }
      if (!startupRun.containerId || startupRun.containerRemoved === true) {
        return { runId, status: 'startup-exit-recorded' };
      }
      try {
        await this.docker.pauseContainer(startupRun.containerId);
        return { runId, status: 'startup-run-paused' };
      } catch (pauseError) {
        try {
          await this.docker.removeContainer(startupRun.containerId, true);
          return {
            runId,
            status: 'startup-run-removed',
            pauseError: pauseError.message,
          };
        } catch (removalError) {
          if (removalError.statusCode === 404) {
            return {
              runId,
              status: 'startup-run-absent',
              pauseError: pauseError.message,
            };
          }
          return {
            runId,
            status: 'startup-containment-failed',
            pauseError: pauseError.message,
            removalError: removalError.message,
          };
        }
      }
    }
    if (this.pendingRunActions.has(runId)) {
      if (this.requiredAdapterExitFailures.get(runId) === retainedFailure) {
        this.requiredAdapterExitFailures.delete(runId);
      }
      return { runId, status: 'lifecycle-action-in-progress' };
    }
    let run;
    try {
      run = await this.store.readRun(runId);
    } catch {
      return { runId, status: 'run-not-found' };
    }
    if (run.status !== 'running') {
      if (this.requiredAdapterExitFailures.get(runId) === retainedFailure) {
        this.requiredAdapterExitFailures.delete(runId);
      }
      return { runId, status: 'run-not-running' };
    }
    this.pendingRunActions.add(runId);
    try {
      const current = await this.store.readRun(runId);
      if (current.status !== 'running') {
        return { runId, status: 'run-not-running' };
      }
      return await this.quarantineRun(current, [retainedFailure]);
    } catch (error) {
      return {
        runId,
        status: 'quarantine-error',
        error: error.message,
      };
    } finally {
      this.pendingRunActions.delete(runId);
      if (this.requiredAdapterExitFailures.get(runId) === retainedFailure) {
        this.requiredAdapterExitFailures.delete(runId);
      }
    }
  }

  async watchdogTick() {
    if (this.watchdogRunning) {
      return [];
    }
    this.watchdogRunning = true;
    try {
      const runs = (await this.store.listRuns()).filter(
        (run) => run.status === 'running',
      );
      if (!runs.length) {
        return [];
      }
      let egressHealth;
      try {
        egressHealth = await this.egress.health();
      } catch (error) {
        egressHealth = { ok: false, error: error.message };
      }
      const results = [];
      for (const run of runs) {
        if (this.pendingRunActions.has(run.runId)) {
          continue;
        }
        const runtimeFailures = [];
        try {
          await this.inspectRuntimeIdentity(
            {
              containerId: run.containerId,
              runId: run.runId,
              imageDigest: run.imageDigest,
              networkName: run.egress?.networkName,
              sourceIpv4: run.egress?.sourceIpv4,
              sourceIpv6: run.egress?.sourceIpv6,
            },
            {
              initPid: run.initPid,
              namespaces: run.namespaces,
              cgroup: run.cgroup,
            },
          );
        } catch (error) {
          runtimeFailures.push({
            name: 'runtime-identity',
            required: true,
            ok: false,
            code: error.code || null,
            error: error.message,
          });
        }
        const scopedEgress = SCOPED_EGRESS_MODES.has(run.mode);
        if (
          !scopedEgress
          && egressHealth.ok
          && (
            !run.egress?.gatewayContainerId
            || egressHealth.containerId !== run.egress.gatewayContainerId
          )
        ) {
          runtimeFailures.push({
            name: 'managed-egress-identity',
            required: true,
            ok: false,
            error: 'managed egress gateway container identity changed',
          });
        }
        const egressPolicyHealth = await this.managedEgressRunHealth(run);
        if (egressPolicyHealth.ok !== true) {
          runtimeFailures.push({
            name: 'managed-egress-policy',
            required: true,
            ...egressPolicyHealth,
            ok: false,
          });
        }
        const context = {
          runId: run.runId,
          containerId: run.containerId,
          containerName: run.name,
          mode: run.mode,
          evidenceDir: run.evidenceDir || this.store.evidencePath(run.runId),
          cgroupPath: run.cgroup?.path || '',
          cgroupId: run.cgroup?.id || '',
          ...artifactContext(run.profileDir),
          tetragonPolicy:
            run.runtimeTetragonPolicy ||
            artifactContext(run.profileDir).tetragonPolicy,
          tetragonPolicyName: run.tetragonPolicyName || '',
        };
        let adapterHealth;
        try {
          adapterHealth = await this.adapters.runtimeHealth(run, context);
        } catch (error) {
          adapterHealth = [
            {
              name: 'adapter-controller',
              required: true,
              ok: false,
              error: error.message,
            },
          ];
        }
        const failures = [
          ...runtimeFailures,
          ...(!scopedEgress && !egressHealth.ok
            ? [{ name: 'managed-egress', ...egressHealth }]
            : []),
          ...adapterHealth.filter((entry) => entry.required && !entry.ok),
        ];
        if (failures.length) {
          if (this.pendingRunActions.has(run.runId)) {
            continue;
          }
          let currentRun;
          try {
            currentRun = await this.store.readRun(run.runId);
          } catch {
            continue;
          }
          if (
            currentRun.status !== 'running'
            || currentRun.updatedAt !== run.updatedAt
            || this.pendingRunActions.has(run.runId)
          ) {
            continue;
          }
          this.pendingRunActions.add(run.runId);
          try {
            results.push(await this.quarantineRun(currentRun, failures));
          } catch (error) {
            results.push({
              runId: run.runId,
              status: 'quarantine-error',
              error: error.message,
            });
          } finally {
            this.pendingRunActions.delete(run.runId);
          }
        }
      }
      return results;
    } finally {
      this.watchdogRunning = false;
    }
  }

  async shutdown() {
    const runs = (await this.store.listRuns()).filter(
      (run) => run.status === 'running',
    );
    const results = [];
    for (const run of runs) {
      if (this.pendingRunActions.has(run.runId)) {
        results.push({
          runId: run.runId,
          status: 'quarantine-error',
          error: 'another lifecycle action is already in progress',
        });
        continue;
      }
      this.pendingRunActions.add(run.runId);
      try {
        let currentRun;
        try {
          currentRun = await this.store.readRun(run.runId);
        } catch {
          continue;
        }
        if (
          currentRun.status !== 'running' ||
          currentRun.updatedAt !== run.updatedAt
        ) {
          continue;
        }
        results.push(
          await this.quarantineRun(currentRun, [
            {
              name: 'guard-daemon',
              required: true,
              ok: false,
              error: 'guard daemon is shutting down',
            },
          ]),
        );
      } catch (error) {
        results.push({
          runId: run.runId,
          status: 'quarantine-error',
          error: error.message,
          failures: [
          {
            name: 'guard-daemon',
            required: true,
            ok: false,
            error: 'guard daemon is shutting down',
          },
          ],
        });
      } finally {
        this.pendingRunActions.delete(run.runId);
      }
    }
    return results;
  }

  listRuns() {
    return this.store.listRuns();
  }
}
