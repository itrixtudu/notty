import crypto from 'node:crypto';
import { constants as fsConstants } from 'node:fs';
import fs from 'node:fs/promises';
import net from 'node:net';
import path from 'node:path';
import { spawnSync } from 'node:child_process';

import {
  DEFAULT_GUARD_STATE_DIR,
  EGRESS_IMAGE_ABI_LABEL,
  EGRESS_IMAGE_ABI_VERSION,
  GUARD_LABEL_PREFIX,
} from './constants.js';
import { GrantStore } from './grants.js';
import {
  MANAGED_DNS_EVIDENCE_MAX_BYTES,
  managedDnsEvidencePaths,
  validateManagedDnsEvidenceSnapshot,
} from './managed-dns-evidence.js';
import { normalizeGatewayPublicOrigin } from './proxy-contract.js';

const DEFAULT_EGRESS_IMAGE =
  process.env.NOSH_GUARD_EGRESS_IMAGE || 'nosh-guard-egress:0.1';
const DEFAULT_EGRESS_NAME =
  process.env.NOSH_GUARD_EGRESS_NAME || 'nosh-guard-egress';

async function hostIpv6RoutingStatus() {
  try {
    const [disabled, forwarding, routeTable] = await Promise.all([
      fs.readFile('/proc/sys/net/ipv6/conf/all/disable_ipv6', 'utf8'),
      fs.readFile('/proc/sys/net/ipv6/conf/all/forwarding', 'utf8'),
      fs.readFile('/proc/net/ipv6_route', 'utf8'),
    ]);
    const defaultRoute = routeTable.split(/\r?\n/).some((line) => {
      const fields = line.trim().split(/\s+/);
      return fields.length >= 10
        && fields[0] === '00000000000000000000000000000000'
        && fields[1] === '00'
        && fields.at(-1) !== 'lo'
        && fields[5] !== 'ffffffff';
    });
    return {
      ok: disabled.trim() === '0'
        && forwarding.trim() === '1'
        && defaultRoute,
      ipv6Enabled: disabled.trim() === '0',
      forwarding: forwarding.trim() === '1',
      defaultRoute,
    };
  } catch (error) {
    return { ok: false, error: error.message };
  }
}

function missingTrustedEgressImageError(image, cause) {
  const error = new Error(
    `trusted egress image ${JSON.stringify(image)} is not installed locally; ` +
      'to use the default development image, remove any ' +
      'NOSH_GUARD_EGRESS_IMAGE override and from a reviewed Nosh checkout run ' +
      '`docker build -f Dockerfile.nosh-egress ' +
      '-t nosh-guard-egress:0.1 .`; for a custom deployment, install the ' +
      'exact configured image locally and set NOSH_GUARD_EGRESS_IMAGE in ' +
      '/etc/nosh-guard/nosh-guard.env to its reviewed immutable image ID or ' +
      'digest-pinned reference, then restart nosh-guardd',
    { cause },
  );
  error.code = 'GUARD_EGRESS_IMAGE_MISSING';
  error.image = image;
  return error;
}

export function assertEgressImageAbi(imageInfo, image = DEFAULT_EGRESS_IMAGE) {
  const actual = imageInfo?.Config?.Labels?.[EGRESS_IMAGE_ABI_LABEL];
  if (actual !== EGRESS_IMAGE_ABI_VERSION) {
    const error = new Error(
      `trusted egress image ABI mismatch for ${JSON.stringify(image)}: ` +
        `expected ${EGRESS_IMAGE_ABI_LABEL}=${EGRESS_IMAGE_ABI_VERSION}, ` +
        `got ${actual == null ? 'missing' : actual}; from a reviewed Nosh ` +
        'checkout rebuild the default image with `docker build -f ' +
        'Dockerfile.nosh-egress -t nosh-guard-egress:0.1 .`, or install a ' +
        'compatible custom image and set NOSH_GUARD_EGRESS_IMAGE to its ' +
        'reviewed immutable image ID or digest-pinned reference, then restart ' +
        'nosh-guardd',
    );
    error.code = 'GUARD_EGRESS_IMAGE_ABI_MISMATCH';
    error.image = image;
    error.label = EGRESS_IMAGE_ABI_LABEL;
    error.expected = EGRESS_IMAGE_ABI_VERSION;
    error.actual = actual ?? null;
    throw error;
  }
  return {
    label: EGRESS_IMAGE_ABI_LABEL,
    version: EGRESS_IMAGE_ABI_VERSION,
  };
}

function shortId(value) {
  return crypto.createHash('sha256').update(value).digest('hex').slice(0, 12);
}

function normalizedCapabilities(values) {
  return new Set(
    (values || []).map((value) =>
      String(value).toUpperCase().replace(/^CAP_/, ''),
    ),
  );
}

function subnetCandidate(runId, attempt) {
  const digest = crypto
    .createHash('sha256')
    .update(`${runId}:${attempt}`)
    .digest();
  const index = digest.readUInt16BE(0) % 8192;
  const third = Math.floor(index / 32);
  const fourth = (index % 32) * 8;
  const prefix = `10.240.${third}.${fourth}`;
  return {
    subnet: `${prefix}/29`,
    dockerGateway: `10.240.${third}.${fourth + 1}`,
    egressGateway: `10.240.${third}.${fourth + 2}`,
    runnerIp: `10.240.${third}.${fourth + 3}`,
    ipv6Subnet: `fd42:6e6f:7368:${index.toString(16)}::/64`,
    dockerGatewayIpv6: `fd42:6e6f:7368:${index.toString(16)}::1`,
    runnerIpv6: `fd42:6e6f:7368:${index.toString(16)}::3`,
  };
}

function networkFromInspect(network) {
  const configs = network?.IPAM?.Config || [];
  const config = configs.find((entry) => !String(entry?.Subnet || '').includes(':')) || {};
  const subnet = String(config.Subnet || '');
  const [base] = subnet.split('/');
  const parts = base.split('.').map(Number);
  if (
    parts.length !== 4 ||
    parts.some((part) => !Number.isInteger(part) || part < 0 || part > 255)
  ) {
    throw new Error(`guard network has unsupported subnet: ${subnet}`);
  }
  const result = {
    subnet,
    dockerGateway: config.Gateway,
    egressGateway: `${parts[0]}.${parts[1]}.${parts[2]}.${parts[3] + 2}`,
    runnerIp: `${parts[0]}.${parts[1]}.${parts[2]}.${parts[3] + 3}`,
  };
  const ipv6 = configs.find((entry) => String(entry?.Subnet || '').includes(':'));
  if (ipv6) {
    const prefix = String(ipv6.Subnet || '').replace(/::\/64$/, '');
    if (!prefix || !String(ipv6.Subnet || '').endsWith('::/64')) {
      throw new Error(`guard network has unsupported IPv6 subnet: ${ipv6.Subnet}`);
    }
    result.ipv6Subnet = ipv6.Subnet;
    result.dockerGatewayIpv6 = ipv6.Gateway;
    result.runnerIpv6 = `${prefix}::3`;
  }
  return result;
}

async function readNetworkRules(filePath) {
  if (!filePath) {
    return [];
  }
  try {
    const document = JSON.parse(await fs.readFile(filePath, 'utf8'));
    const rules =
      document?.spec?.egress ||
      document?.policy?.egress ||
      document?.egress ||
      document?.rules ||
      [];
    if (!Array.isArray(rules)) {
      throw new TypeError('network policy egress rules must be an array');
    }
    return rules.flatMap((rule) => {
      if (!Array.isArray(rule.peers)) {
        return [rule];
      }
      const protocols =
        String(rule.protocol || 'ANY').toUpperCase() === 'ANY'
          ? ['tcp', 'udp', 'icmp', 'icmpv6']
          : [String(rule.protocol).toLowerCase()];
      return rule.peers.flatMap((peer) =>
        protocols.map((protocol) => ({
          destination: peer.dnsName || peer.cidr || peer.address,
          protocol,
          ports: rule.ports || [],
          icmpType: rule.icmpType,
          icmpCode: rule.icmpCode,
        })),
      );
    });
  } catch (error) {
    if (error.code === 'ENOENT') {
      return [];
    }
    throw error;
  }
}

function requiredStateUid() {
  return typeof process.geteuid === 'function' && process.geteuid() === 0
    ? 0
    : null;
}

async function secureDirectory(
  directoryPath,
  { mode = 0o700, requiredUid = requiredStateUid() } = {},
) {
  const resolved = path.resolve(directoryPath);
  await fs.mkdir(resolved, { recursive: true, mode });
  if ((await fs.realpath(resolved)) !== resolved) {
    throw new Error(
      `guard state directory path must not contain symbolic links: ${resolved}`,
    );
  }
  let handle;
  try {
    handle = await fs.open(
      resolved,
      fsConstants.O_RDONLY |
        (fsConstants.O_DIRECTORY || 0) |
        (fsConstants.O_NOFOLLOW || 0),
    );
  } catch (error) {
    throw new Error(
      `guard state path must be a real directory: ${resolved}: ${error.message}`,
      { cause: error },
    );
  }
  try {
    const before = await handle.stat();
    if (!before.isDirectory()) {
      throw new Error(`guard state path is not a directory: ${resolved}`);
    }
    if (requiredUid != null && before.uid !== requiredUid) {
      throw new Error(
        `guard state directory must be owned by uid ${requiredUid}: ${resolved}`,
      );
    }
    await handle.chmod(mode);
    const after = await handle.stat();
    const current = await fs.lstat(resolved);
    if (
      !current.isDirectory() ||
      current.isSymbolicLink() ||
      current.dev !== after.dev ||
      current.ino !== after.ino
    ) {
      throw new Error(`guard state directory changed during validation: ${resolved}`);
    }
    if ((after.mode & 0o7777) !== mode) {
      throw new Error(
        `guard state directory mode must be ${mode.toString(8)}: ${resolved}`,
      );
    }
    return {
      dev: String(after.dev),
      ino: String(after.ino),
      mode: after.mode & 0o7777,
      uid: after.uid,
    };
  } finally {
    await handle.close();
  }
}

async function secureEvidenceFile(
  filePath,
  { requiredUid = requiredStateUid() } = {},
) {
  const flags =
    fsConstants.O_RDWR |
    fsConstants.O_CREAT |
    (fsConstants.O_NOFOLLOW || 0) |
    (fsConstants.O_NONBLOCK || 0);
  let handle;
  try {
    handle = await fs.open(filePath, flags, 0o600);
  } catch (error) {
    throw new Error(
      `managed egress evidence path must be a regular non-symlink file: ${filePath}: ${error.message}`,
      { cause: error },
    );
  }
  try {
    const before = await handle.stat();
    if (!before.isFile() || before.nlink !== 1) {
      throw new Error(
        `managed egress evidence path must be a singly-linked regular file: ${filePath}`,
      );
    }
    if (requiredUid != null && before.uid !== requiredUid) {
      throw new Error(
        `managed egress evidence file must be owned by uid ${requiredUid}: ${filePath}`,
      );
    }
    await handle.chmod(0o600);
    const after = await handle.stat();
    const current = await fs.lstat(filePath);
    if (
      !current.isFile() ||
      current.isSymbolicLink() ||
      current.dev !== after.dev ||
      current.ino !== after.ino
    ) {
      throw new Error(
        `managed egress evidence file changed during validation: ${filePath}`,
      );
    }
    if ((after.mode & 0o7777) !== 0o600) {
      throw new Error(
        `managed egress evidence file mode must be 600: ${filePath}`,
      );
    }
  } finally {
    await handle.close();
  }
}

async function captureFileCursor(filePath) {
  let handle;
  try {
    handle = await fs.open(
      filePath,
      fsConstants.O_RDONLY |
        (fsConstants.O_NOFOLLOW || 0) |
        (fsConstants.O_NONBLOCK || 0),
    );
  } catch (error) {
    throw new Error(
      `managed egress evidence cursor path is unavailable: ${filePath}: ${error.message}`,
      { cause: error },
    );
  }
  try {
    const stat = await handle.stat({ bigint: true });
    if (
      !stat.isFile() ||
      stat.nlink !== 1n ||
      stat.size > BigInt(Number.MAX_SAFE_INTEGER)
    ) {
      throw new Error(
        `managed egress evidence cursor requires a safe regular file: ${filePath}`,
      );
    }
    const current = await fs.lstat(filePath, { bigint: true });
    if (
      !current.isFile() ||
      current.isSymbolicLink() ||
      current.dev !== stat.dev ||
      current.ino !== stat.ino
    ) {
      throw new Error(
        `managed egress evidence file changed while capturing cursor: ${filePath}`,
      );
    }
    return {
      offset: Number(stat.size),
      dev: stat.dev.toString(),
      ino: stat.ino.toString(),
    };
  } finally {
    await handle.close();
  }
}

async function readManagedJson(filePath) {
  const handle = await fs.open(
    filePath,
    fsConstants.O_RDONLY | (fsConstants.O_NOFOLLOW || 0),
  );
  try {
    const before = await handle.stat();
    const requiredUid = requiredStateUid();
    if (
      !before.isFile() ||
      before.nlink !== 1 ||
      before.size > 1024 * 1024 ||
      (requiredUid != null && before.uid !== requiredUid) ||
      (before.mode & 0o7777) !== 0o600
    ) {
      throw new Error(`managed JSON state is not a trusted 0600 file: ${filePath}`);
    }
    const source = await handle.readFile('utf8');
    const current = await fs.lstat(filePath);
    if (
      !current.isFile() ||
      current.isSymbolicLink() ||
      current.dev !== before.dev ||
      current.ino !== before.ino
    ) {
      throw new Error(`managed JSON state changed during read: ${filePath}`);
    }
    return JSON.parse(source);
  } finally {
    await handle.close();
  }
}

const POLICY_ACKNOWLEDGEMENT_FIELDS = Object.freeze([
  'source',
  'type',
  'runId',
  'mode',
  'profileRevision',
  'policyHash',
  'approvalHash',
  'profilePolicyHash',
  'imageDigest',
  'workspaceKey',
  'networkName',
  'sourceIpv4',
  'gatewayIpv4',
]);

export function policyAcknowledgementMismatches(candidate, policy) {
  const expected = {
    source: 'managed_gateway',
    type: 'policy_attestation',
    ...policy,
  };
  return POLICY_ACKNOWLEDGEMENT_FIELDS.filter(
    (field) => candidate?.[field] !== expected[field],
  );
}

export function policyAcknowledgementMatches(candidate, policy) {
  return policyAcknowledgementMismatches(candidate, policy).length === 0;
}

function policyAcknowledgementMismatchError(candidate, policy) {
  const mismatchedFields = policyAcknowledgementMismatches(candidate, policy);
  const error = new Error(
    `managed egress policy acknowledgement is incompatible or stale for run ` +
      `${JSON.stringify(policy.runId)} (missing or mismatched fields: ` +
      `${mismatchedFields.join(', ')}); expected gateway image ABI ` +
      `${EGRESS_IMAGE_ABI_LABEL}=${EGRESS_IMAGE_ABI_VERSION}; verify the ` +
      'installed trusted egress image and replace a stale gateway only after ' +
      'confirming no active guarded runs',
  );
  error.code = 'GUARD_EGRESS_POLICY_ACK_MISMATCH';
  error.runId = policy.runId;
  error.mismatchedFields = mismatchedFields;
  error.label = EGRESS_IMAGE_ABI_LABEL;
  error.expected = EGRESS_IMAGE_ABI_VERSION;
  return error;
}

export class EgressManager {
  constructor(options = {}) {
    if (!options.docker) {
      throw new TypeError('EgressManager requires a Docker client');
    }
    this.docker = options.docker;
    this.stateDir = path.resolve(options.stateDir || DEFAULT_GUARD_STATE_DIR);
    this.image = options.image || DEFAULT_EGRESS_IMAGE;
    this.containerName = options.containerName || DEFAULT_EGRESS_NAME;
    this.publicOrigin = options.publicOrigin
      ? normalizeGatewayPublicOrigin(options.publicOrigin).origin
      : null;
    this.spawnSyncImpl = options.spawnSyncImpl || spawnSync;
    this.ipv6RoutingProvider = options.ipv6RoutingProvider
      || hostIpv6RoutingStatus;
    this.policiesDir = path.join(this.stateDir, 'egress', 'policies');
    this.evidenceDir = path.join(this.stateDir, 'egress', 'evidence');
    this.dnsEvidenceDir = path.join(this.evidenceDir, 'managed-dns');
    this.controlDir = path.join(this.stateDir, 'egress', 'control');
    this.controlSocketPath = path.join(this.controlDir, 'runner-proxy.sock');
    this.snapshotRequestDir = path.join(
      this.evidenceDir,
      'snapshot-requests',
    );
    this.snapshotDir = path.join(this.evidenceDir, 'snapshots');
    this.grants = new GrantStore({ stateDir: this.stateDir });
  }

  async initialize() {
    await Promise.all([
      secureDirectory(this.policiesDir),
      secureDirectory(this.evidenceDir),
      secureDirectory(this.dnsEvidenceDir),
      secureDirectory(this.controlDir),
      secureDirectory(this.snapshotRequestDir),
      secureDirectory(this.snapshotDir),
      this.grants.initialize(),
    ]);
    await Promise.all([
      secureEvidenceFile(
        path.join(this.evidenceDir, 'managed-gateway-counters.ndjson'),
      ),
    ]);
  }

  async prepareManagedDnsEvidence(runId) {
    const paths = managedDnsEvidencePaths(this.evidenceDir, runId);
    await secureDirectory(paths.directory);
    const flags =
      fsConstants.O_WRONLY |
      fsConstants.O_CREAT |
      fsConstants.O_EXCL |
      (fsConstants.O_NOFOLLOW || 0);
    let handle;
    try {
      handle = await fs.open(paths.logPath, flags, 0o600);
      await handle.sync();
    } catch (error) {
      if (error.code === 'EEXIST') {
        const conflict = new Error(
          `managed DNS evidence already exists for immutable run ${runId}`,
        );
        conflict.code = 'GUARD_EGRESS_DNS_EVIDENCE_REUSED';
        throw conflict;
      }
      throw error;
    } finally {
      await handle?.close();
    }
    try {
      await fs.lstat(paths.overflowPath);
      throw new Error(
        `managed DNS overflow marker already exists for immutable run ${runId}`,
      );
    } catch (error) {
      if (error.code !== 'ENOENT') {
        throw error;
      }
    }
    await secureEvidenceFile(paths.logPath);
    return {
      ...(await captureFileCursor(paths.logPath)),
      evidenceKey: paths.key,
      maxBytes: MANAGED_DNS_EVIDENCE_MAX_BYTES,
    };
  }

  async inspectGateway() {
    try {
      return await this.docker.inspectContainer(this.containerName);
    } catch (error) {
      if (error.statusCode === 404) {
        return null;
      }
      throw error;
    }
  }

  async health() {
    const gateway = await this.inspectGateway();
    if (!gateway) {
      return { ok: false, error: 'managed egress gateway is missing' };
    }
    try {
      const imageInfo = await this.docker.inspectImage(this.image);
      this.validateGateway(gateway, imageInfo);
    } catch (error) {
      return {
        ok: false,
        containerId: gateway.Id,
        running: gateway.State?.Running === true,
        health: gateway.State?.Health?.Status || null,
        error: error.message,
      };
    }
    const health = gateway.State?.Health?.Status || null;
    return {
      ok:
        gateway.State?.Running === true &&
        health === 'healthy',
      containerId: gateway.Id,
      running: gateway.State?.Running === true,
      health,
      error:
        gateway.State?.Running !== true
          ? 'managed egress gateway is not running'
          : health === 'healthy'
            ? null
            : `managed egress gateway health is ${health || 'unavailable'}`,
    };
  }

  async runtimeHealth(run) {
    try {
      const gatewayHealth = await this.health();
      if (!gatewayHealth.ok) {
        throw new Error(gatewayHealth.error || 'managed egress gateway is unhealthy');
      }
      if (
        run?.egress?.gatewayContainerId
        && gatewayHealth.containerId !== run.egress.gatewayContainerId
      ) {
        throw new Error('managed egress gateway identity changed');
      }
      const runId = String(run?.runId || '');
      if (!/^[A-Za-z0-9_.-]+$/.test(runId)) {
        throw new Error('managed egress run ID is invalid');
      }
      const policy = await readManagedJson(
        path.join(this.policiesDir, `${runId}.json`),
      );
      const recordedPolicyHash = policy.policyHash;
      const unsignedPolicy = { ...policy };
      delete unsignedPolicy.policyHash;
      const computedPolicyHash = `sha256:${crypto
        .createHash('sha256')
        .update(JSON.stringify(unsignedPolicy))
        .digest('hex')}`;
      const expected = {
        runId,
        mode: run.mode,
        profileRevision: run.profileRevision,
        policyHash: run.egress?.policyHash,
        approvalHash: run.approvalHash || null,
        profilePolicyHash: run.profilePolicyHash || null,
        imageDigest: run.imageDigest || null,
        workspaceKey: run.workspaceKey || null,
        networkName: run.egress?.networkName,
        sourceIpv4: run.egress?.sourceIpv4,
        gatewayIpv4: run.egress?.gatewayIpv4,
      };
      if (
        recordedPolicyHash !== computedPolicyHash ||
        !policyAcknowledgementMatches(
          {
            source: 'managed_gateway',
            type: 'policy_attestation',
            ...policy,
          },
          expected,
        )
      ) {
        throw new Error('managed egress policy no longer matches run state');
      }
      const acknowledgement = await readManagedJson(
        path.join(this.evidenceDir, 'acks', `${runId}.json`),
      );
      if (!policyAcknowledgementMatches(acknowledgement, expected)) {
        throw new Error('managed egress acknowledgement no longer matches run state');
      }
      return {
        ok: true,
        policyHash: recordedPolicyHash,
        approvalHash: expected.approvalHash,
        profilePolicyHash: expected.profilePolicyHash,
      };
    } catch (error) {
      return { ok: false, error: error.message };
    }
  }

  validateGateway(gateway, imageInfo) {
    assertEgressImageAbi(imageInfo, this.image);
    const errors = [];
    const labels = gateway?.Config?.Labels || {};
    if (
      labels[`${GUARD_LABEL_PREFIX}.managed`] !== 'true' ||
      labels[`${GUARD_LABEL_PREFIX}.component`] !== 'egress'
    ) {
      errors.push('managed labels');
    }
    if (!imageInfo?.Id || gateway?.Image !== imageInfo.Id) {
      errors.push('exact configured image ID');
    }
    const host = gateway?.HostConfig || {};
    if (host.Privileged !== false) {
      errors.push('unprivileged runtime');
    }
    if (host.ReadonlyRootfs !== true) {
      errors.push('read-only root filesystem');
    }
    if (host.Init !== true) {
      errors.push('container init');
    }
    if (!['bridge', 'default'].includes(host.NetworkMode)) {
      errors.push('default bridge network');
    }
    if (host.PublishAllPorts === true || Object.keys(host.PortBindings || {}).length) {
      errors.push('no published ports');
    }
    const capDrop = normalizedCapabilities(host.CapDrop);
    const capAdd = normalizedCapabilities(host.CapAdd);
    if (
      !capDrop.has('ALL') ||
      capAdd.size !== 2 ||
      !capAdd.has('NET_ADMIN') ||
      !capAdd.has('NET_RAW')
    ) {
      errors.push('minimal gateway capabilities');
    }
    if (
      !(host.SecurityOpt || []).some((entry) =>
        String(entry).startsWith('no-new-privileges'),
      )
    ) {
      errors.push('no-new-privileges');
    }
    if (
      (host.SecurityOpt || []).some((entry) =>
        /(?:seccomp|apparmor)=unconfined/i.test(String(entry)),
      )
    ) {
      errors.push('confined LSM and seccomp settings');
    }
    if (
      !['', 'private'].includes(host.PidMode || '') ||
      !['', 'private'].includes(host.IpcMode || '') ||
      (host.UTSMode || '') !== '' ||
      !['', 'private'].includes(host.CgroupnsMode || '') ||
      (host.Devices || []).length ||
      (host.DeviceRequests || []).length
    ) {
      errors.push('private namespaces and no devices');
    }
    if (
      host.Memory !== 256 * 1024 * 1024 ||
      host.MemorySwap !== 256 * 1024 * 1024 ||
      host.NanoCpus !== 500_000_000 ||
      host.PidsLimit !== 128
    ) {
      errors.push('exact resource limits');
    }
    if (
      host.Sysctls?.['net.ipv4.ip_forward'] !== '1' ||
      Object.keys(host.Sysctls || {}).length !== 1
    ) {
      errors.push('exact forwarding sysctl');
    }
    const expectedMounts = new Map([
      ['/var/lib/nosh-guard/policies', {
        source: this.policiesDir,
        rw: false,
      }],
      ['/var/lib/nosh-guard/grants', {
        source: path.dirname(this.grants.filePath),
        rw: false,
      }],
      ['/var/lib/nosh-guard/evidence', {
        source: this.evidenceDir,
        rw: true,
      }],
      ['/var/lib/nosh-guard/control', {
        source: this.controlDir,
        rw: true,
      }],
    ]);
    for (const [destination, expected] of expectedMounts) {
      const mount = (gateway?.Mounts || []).find(
        (entry) => entry.Destination === destination,
      );
      if (
        !mount ||
        path.resolve(mount.Source || '') !== path.resolve(expected.source) ||
        mount.RW !== expected.rw
      ) {
        errors.push(`trusted ${destination} mount`);
      }
    }
    if (
      (gateway?.Mounts || []).length !== expectedMounts.size ||
      (host.Binds || []).length !== expectedMounts.size
    ) {
      errors.push('no additional mounts');
    }
    const healthcheck = (gateway?.Config?.Healthcheck?.Test || []).join(' ');
    if (
      !healthcheck.includes('/run/nosh-guard/healthy') ||
      !healthcheck.includes('nft list table inet nosh_guard')
    ) {
      errors.push('exact Docker healthcheck');
    }
    if (errors.length) {
      throw new Error(
        `refusing unmanaged or drifted egress gateway: ${errors.join(', ')}`,
      );
    }
    return true;
  }

  async waitForGatewayHealthy(containerId, timeoutMs = 30_000) {
    const deadline = Date.now() + timeoutMs;
    while (Date.now() < deadline) {
      const inspected = await this.docker.inspectContainer(containerId);
      if (inspected?.State?.Running !== true) {
        throw new Error('managed egress gateway exited during startup');
      }
      const status = inspected.State?.Health?.Status;
      if (status === 'healthy') {
        return inspected;
      }
      if (status === 'unhealthy') {
        throw new Error('managed egress gateway reported unhealthy during startup');
      }
      await new Promise((resolve) => setTimeout(resolve, 100));
    }
    throw new Error(
      `managed egress gateway did not become healthy within ${timeoutMs}ms`,
    );
  }

  async ensureGateway() {
    if (!this.gatewayPromise) {
      this.gatewayPromise = this.ensureGatewayExclusive().finally(() => {
        this.gatewayPromise = null;
      });
    }
    return this.gatewayPromise;
  }

  async ensureGatewayExclusive() {
    await this.initialize();
    let imageInfo;
    try {
      imageInfo = await this.docker.inspectImage(this.image);
    } catch (error) {
      if (error.statusCode === 404) {
        throw missingTrustedEgressImageError(this.image, error);
      }
      throw error;
    }
    assertEgressImageAbi(imageInfo, this.image);
    let gateway = await this.inspectGateway();
    if (!gateway) {
      const imageReference = imageInfo?.RepoDigests?.[0] || imageInfo?.Id || this.image;
      const created = await this.docker.createContainer(this.containerName, {
        Image: imageReference,
        Hostname: this.containerName,
        Env: [
          'NOSH_GUARD_POLICY_DIR=/var/lib/nosh-guard/policies',
          'NOSH_GUARD_GRANTS=/var/lib/nosh-guard/grants/current.json',
          'NOSH_GUARD_EVIDENCE_DIR=/var/lib/nosh-guard/evidence',
          'NOSH_GUARD_CONTROL_SOCKET=/var/lib/nosh-guard/control/runner-proxy.sock',
        ],
        Labels: {
          [`${GUARD_LABEL_PREFIX}.managed`]: 'true',
          [`${GUARD_LABEL_PREFIX}.component`]: 'egress',
        },
        HostConfig: {
          AutoRemove: false,
          Binds: [
            `${this.policiesDir}:/var/lib/nosh-guard/policies:ro`,
            `${path.dirname(this.grants.filePath)}:/var/lib/nosh-guard/grants:ro`,
            `${this.evidenceDir}:/var/lib/nosh-guard/evidence:rw`,
            `${this.controlDir}:/var/lib/nosh-guard/control:rw`,
          ],
          CapDrop: ['ALL'],
          CapAdd: ['NET_ADMIN', 'NET_RAW'],
          Init: true,
          Memory: 256 * 1024 * 1024,
          MemorySwap: 256 * 1024 * 1024,
          NanoCpus: 500_000_000,
          NetworkMode: 'bridge',
          PidsLimit: 128,
          PortBindings: {},
          Privileged: false,
          PublishAllPorts: false,
          ReadonlyRootfs: true,
          SecurityOpt: ['no-new-privileges:true'],
          Sysctls: {
            'net.ipv4.ip_forward': '1',
          },
          Tmpfs: {
            '/run': 'rw,nosuid,nodev,noexec,size=16777216',
            '/tmp': 'rw,nosuid,nodev,noexec,size=16777216',
          },
        },
      });
      if (!created?.Id) {
        throw new Error('Docker did not return an egress gateway container ID');
      }
      gateway = await this.docker.inspectContainer(created.Id);
    }
    this.validateGateway(gateway, imageInfo);
    if (gateway?.State?.Running !== true) {
      await this.docker.startContainer(gateway.Id);
    }
    gateway = await this.waitForGatewayHealthy(gateway.Id);
    this.validateGateway(gateway, imageInfo);
    return gateway;
  }

  async prepareNetwork(runId) {
    const gateway = await this.ensureGateway();
    const networkName = `nosh-guard-${shortId(runId)}`;
    let network;
    try {
      network = await this.docker.inspectNetwork(networkName);
    } catch (error) {
      if (error.statusCode !== 404) {
        throw error;
      }
    }
    if (!network) {
      let lastError = null;
      for (let attempt = 0; attempt < 64; attempt += 1) {
        const allocation = subnetCandidate(runId, attempt);
        try {
          await this.docker.createNetwork(networkName, {
            internal: true,
            options: {
              'com.docker.network.bridge.inhibit_ipv4': 'true',
              'com.docker.network.bridge.enable_ip_masquerade': 'false',
            },
            labels: {
              [`${GUARD_LABEL_PREFIX}.managed`]: 'true',
              [`${GUARD_LABEL_PREFIX}.run-id`]: runId,
            },
            ipam: {
              subnet: allocation.subnet,
              gateway: allocation.dockerGateway,
            },
          });
          network = await this.docker.inspectNetwork(networkName);
          break;
        } catch (error) {
          lastError = error;
          if (error.statusCode !== 409 && !/overlap|pool/i.test(error.message)) {
            throw error;
          }
        }
      }
      if (!network) {
        throw new Error(
          `unable to allocate an isolated runner subnet: ${lastError?.message || 'no free candidate'}`,
        );
      }
    }
    if (
      network.Labels?.[`${GUARD_LABEL_PREFIX}.run-id`] !== runId ||
      network.Internal !== true ||
      network.Options?.['com.docker.network.bridge.inhibit_ipv4'] !== 'true' ||
      network.Options?.['com.docker.network.bridge.enable_ip_masquerade'] !==
        'false'
    ) {
      throw new Error(`refusing unmanaged or reused guard network: ${networkName}`);
    }
    const allocation = networkFromInspect(network);
    const gatewayNetworks = gateway.NetworkSettings?.Networks || {};
    if (!gatewayNetworks[networkName]) {
      await this.docker.connectNetwork(networkName, gateway.Id, {
        ipv4Address: allocation.egressGateway,
        aliases: ['nosh-egress'],
      });
    } else if (
      gatewayNetworks[networkName].IPAddress !== allocation.egressGateway
    ) {
      throw new Error(`egress gateway has unexpected address on ${networkName}`);
    }
    return {
      networkName,
      gatewayContainerId: gateway.Id,
      ...allocation,
    };
  }

  async prepareObserveNetwork(runId) {
    const networkName = `nosh-guard-${shortId(runId)}`;
    let network;
    try {
      network = await this.docker.inspectNetwork(networkName);
    } catch (error) {
      if (error.statusCode !== 404) throw error;
    }
    if (!network) {
      for (let attempt = 0; attempt < 64 && !network; attempt += 1) {
        const allocation = subnetCandidate(runId, attempt);
        try {
          await this.docker.createNetwork(networkName, {
            internal: false,
            options: {
              'com.docker.network.bridge.enable_ip_masquerade': 'true',
            },
            labels: {
              [`${GUARD_LABEL_PREFIX}.managed`]: 'true',
              [`${GUARD_LABEL_PREFIX}.run-id`]: runId,
              [`${GUARD_LABEL_PREFIX}.dns-mode`]: 'observe-only',
            },
            ipam: { subnet: allocation.subnet, gateway: allocation.dockerGateway },
          });
          network = await this.docker.inspectNetwork(networkName);
        } catch (error) {
          if (error.statusCode !== 409 && !/overlap|pool/i.test(error.message)) {
            throw error;
          }
        }
      }
    }
    if (
      !network
      || network.Internal === true
      || network.Labels?.[`${GUARD_LABEL_PREFIX}.run-id`] !== runId
      || network.Labels?.[`${GUARD_LABEL_PREFIX}.dns-mode`] !== 'observe-only'
    ) {
      throw new Error(`refusing invalid observe-only runner network: ${networkName}`);
    }
    return {
      networkName,
      gatewayContainerId: null,
      ...networkFromInspect(network),
      egressGateway: null,
      observeOnly: true,
    };
  }

  async prepareDirectNetwork(runId) {
    const ipv6Routing = await this.ipv6RoutingProvider();
    if (ipv6Routing?.ok !== true) {
      const error = new Error(
        'eBPF egress requires host IPv6 forwarding and a non-loopback IPv6 '
          + `default route: ${JSON.stringify(ipv6Routing || {})}`,
      );
      error.code = 'GUARD_EBPF_IPV6_NETWORK_UNAVAILABLE';
      error.ipv6Routing = ipv6Routing || null;
      error.networkCleanupVerified = true;
      throw error;
    }
    const networkName = `nosh-guard-${shortId(runId)}`;
    let network;
    let createdByThisCall = false;
    try {
      network = await this.docker.inspectNetwork(networkName);
    } catch (error) {
      if (error.statusCode !== 404) {
        error.networkCleanupVerified = true;
        throw error;
      }
    }
    try {
      if (!network) {
        for (let attempt = 0; attempt < 64 && !network; attempt += 1) {
          const allocation = subnetCandidate(runId, attempt);
          try {
            await this.docker.createNetwork(networkName, {
              internal: false,
              enableIPv6: true,
              options: {
                'com.docker.network.bridge.enable_ip_masquerade': 'true',
              },
              labels: {
                [`${GUARD_LABEL_PREFIX}.managed`]: 'true',
                [`${GUARD_LABEL_PREFIX}.run-id`]: runId,
                [`${GUARD_LABEL_PREFIX}.egress-backend`]: 'nosh-egress',
              },
              ipam: {
                config: [
                  { subnet: allocation.subnet, gateway: allocation.dockerGateway },
                  {
                    subnet: allocation.ipv6Subnet,
                    gateway: allocation.dockerGatewayIpv6,
                  },
                ],
              },
            });
            createdByThisCall = true;
          } catch (error) {
            if (/ipv6|address family|no available addresses/i.test(error.message)) {
              const unavailable = new Error(
                `Docker could not create the required dual-stack eBPF egress network: ${error.message}`,
                { cause: error },
              );
              unavailable.code = 'GUARD_EBPF_IPV6_NETWORK_UNAVAILABLE';
              throw unavailable;
            }
            if (error.statusCode === 409 || /overlap|pool/i.test(error.message)) {
              continue;
            }
            throw error;
          }
          network = await this.docker.inspectNetwork(networkName);
        }
      }
      if (
        !network
        || network.Internal === true
        || network.EnableIPv6 !== true
        || network.Labels?.[`${GUARD_LABEL_PREFIX}.managed`] !== 'true'
        || network.Labels?.[`${GUARD_LABEL_PREFIX}.run-id`] !== runId
        || network.Labels?.[`${GUARD_LABEL_PREFIX}.egress-backend`] !== 'nosh-egress'
        || network.Options?.['com.docker.network.bridge.enable_ip_masquerade'] !== 'true'
      ) {
        throw new Error(`refusing invalid eBPF egress runner network: ${networkName}`);
      }
      const allocation = networkFromInspect(network);
      const deterministic = Array.from({ length: 64 }, (_, attempt) =>
        subnetCandidate(runId, attempt)).some((expected) => (
        allocation.subnet === expected.subnet
        && allocation.dockerGateway === expected.dockerGateway
        && allocation.egressGateway === expected.egressGateway
        && allocation.runnerIp === expected.runnerIp
        && allocation.ipv6Subnet === expected.ipv6Subnet
        && allocation.dockerGatewayIpv6 === expected.dockerGatewayIpv6
        && allocation.runnerIpv6 === expected.runnerIpv6
      ));
      if (!allocation.ipv6Subnet || !allocation.runnerIpv6 || !deterministic) {
        const error = new Error(
          'eBPF egress requires an exact deterministic dual-stack Docker bridge',
        );
        error.code = !allocation.ipv6Subnet || !allocation.runnerIpv6
          ? 'GUARD_EBPF_IPV6_NETWORK_UNAVAILABLE'
          : 'GUARD_EBPF_NETWORK_DRIFT';
        throw error;
      }
      return {
        networkName,
        gatewayContainerId: null,
        ...allocation,
        egressGateway: null,
        backend: 'nosh-egress',
        ipv6Routing,
      };
    } catch (error) {
      if (!createdByThisCall) throw error;
      try {
        await this.detachDirectRun({
          runId,
          egress: { networkName },
        });
      } catch (rollbackError) {
        const cleanupError = new Error(
          `eBPF egress network admission failed and rollback is unproven: ${
            error.message
          }; rollback failed: ${rollbackError.message}`,
          { cause: error },
        );
        cleanupError.code = 'GUARD_EBPF_NETWORK_ROLLBACK_FAILED';
        cleanupError.rollbackError = rollbackError.message;
        throw cleanupError;
      }
      const rolledBack = new Error(
        `eBPF egress network admission failed after an exact rollback: ${error.message}`,
        { cause: error },
      );
      rolledBack.code = 'GUARD_EBPF_NETWORK_ROLLED_BACK';
      rolledBack.networkCleanupVerified = true;
      rolledBack.originalCode = error.code || null;
      throw rolledBack;
    }
  }

  async detachDirectRun(run) {
    const networkName = run?.egress?.networkName;
    if (!networkName) {
      return { ok: true, networkName: null };
    }
    try {
      const network = await this.docker.inspectNetwork(networkName);
      if (
        network.Labels?.[`${GUARD_LABEL_PREFIX}.managed`] !== 'true'
        || network.Labels?.[`${GUARD_LABEL_PREFIX}.run-id`] !== run.runId
        || network.Labels?.[`${GUARD_LABEL_PREFIX}.egress-backend`] !== 'nosh-egress'
      ) {
        throw new Error(`refusing to remove an unmanaged eBPF egress network: ${networkName}`);
      }
    } catch (error) {
      if (error.statusCode === 404) {
        return { ok: true, networkName };
      }
      throw error;
    }
    try {
      await this.docker.removeNetwork(networkName);
    } catch (error) {
      if (error.statusCode !== 404) throw error;
    }
    try {
      await this.docker.inspectNetwork(networkName);
    } catch (error) {
      if (error.statusCode === 404) {
        return { ok: true, networkName };
      }
      throw error;
    }
    const error = new Error(
      `eBPF egress network remains after removal: ${networkName}`,
    );
    error.code = 'GUARD_EBPF_NETWORK_REMOVE_INCOMPLETE';
    throw error;
  }

  async attachObservedRun(run, inspected, allocation) {
    const runnerAddress = inspected?.NetworkSettings?.Networks
      ?.[allocation.networkName]?.IPAddress;
    if (runnerAddress !== allocation.runnerIp) {
      throw new Error(
        `runner address mismatch: expected ${allocation.runnerIp}, got ${runnerAddress || 'none'}`,
      );
    }
    return {
      networkName: allocation.networkName,
      sourceIpv4: allocation.runnerIp,
      gatewayIpv4: null,
      gatewayContainerId: null,
      routeInstalled: false,
      observeOnly: true,
      dnsAuthority: 'observational',
    };
  }

  async attachRun(
    run,
    inspected,
    allocation,
    networkPolicyPath,
    options = {},
  ) {
    const initPid = inspected?.State?.Pid;
    if (!Number.isSafeInteger(initPid) || initPid <= 0) {
      throw new Error('runner init PID is unavailable for route configuration');
    }
    if (
      run?.initPid !== initPid ||
      !/^\d+$/.test(String(run?.namespaces?.net || ''))
    ) {
      throw new Error(
        'runner network namespace identity was not persisted before route configuration',
      );
    }
    const runnerAddress =
      inspected?.NetworkSettings?.Networks?.[allocation.networkName]?.IPAddress;
    if (runnerAddress !== allocation.runnerIp) {
      throw new Error(
        `runner address mismatch: expected ${allocation.runnerIp}, got ${
          runnerAddress || 'none'
        }`,
      );
    }
    const networkNamespace = await fs.open(`/proc/${initPid}/ns/net`, 'r');
    let route;
    try {
      const namespaceStat = await networkNamespace.stat({ bigint: true });
      if (namespaceStat.ino.toString() !== String(run.namespaces.net)) {
        throw new Error(
          'runner network namespace changed before route configuration',
        );
      }
      route = this.spawnSyncImpl(
        'nsenter',
        [
          '--net=/proc/self/fd/3',
          'ip',
          'route',
          'replace',
          'default',
          'via',
          allocation.egressGateway,
        ],
        {
          encoding: 'utf8',
          timeout: 5_000,
          stdio: ['ignore', 'pipe', 'pipe', networkNamespace.fd],
        },
      );
    } finally {
      await networkNamespace.close();
    }
    if (route.status !== 0) {
      throw new Error(
        `failed to install guarded default route: ${
          route.error?.message || route.stderr || `status ${route.status}`
        }`,
      );
    }
    const [dnsOffset, gatewayOffset] = await Promise.all([
      this.prepareManagedDnsEvidence(run.runId),
      captureFileCursor(
        path.join(this.evidenceDir, 'managed-gateway-counters.ndjson'),
      ),
    ]);
    const egress = options.networkRules == null
      ? await readNetworkRules(networkPolicyPath)
      : structuredClone(options.networkRules);
    if (!Array.isArray(egress)) {
      throw new TypeError('verified egress network rules must be an array');
    }
    if (['egress-audit', 'egress-enforce'].includes(run.mode)) {
      const requiredHashes = [
        ['profile policy hash', options.profilePolicyHash],
        ...(run.mode === 'egress-enforce'
          ? [['approval hash', options.approvalHash]]
          : []),
      ];
      for (const [label, value] of requiredHashes) {
        if (!/^sha256:[a-f0-9]{64}$/.test(value || '')) {
          throw new Error(`${run.mode} requires a verified ${label}`);
        }
      }
      if (typeof options.workspaceKey !== 'string' || !options.workspaceKey) {
        throw new Error(`${run.mode} requires a verified workspace key`);
      }
    }
    const policy = {
      schemaVersion: 1,
      runId: run.runId,
      mode: run.mode,
      profileRevision: run.profileRevision,
      networkName: allocation.networkName,
      sourceIpv4: allocation.runnerIp,
      gatewayIpv4: allocation.egressGateway,
      publicOrigin: this.publicOrigin,
      imageDigest: run.imageDigest || null,
      workspaceKey: options.workspaceKey || null,
      approvalHash: options.approvalHash || null,
      profilePolicyHash: options.profilePolicyHash || null,
      egress,
      updatedAt: new Date().toISOString(),
    };
    policy.policyHash = `sha256:${crypto
      .createHash('sha256')
      .update(JSON.stringify(policy))
      .digest('hex')}`;
    const destination = path.join(this.policiesDir, `${run.runId}.json`);
    const temporary = `${destination}.${process.pid}.tmp`;
    await fs.writeFile(temporary, `${JSON.stringify(policy, null, 2)}\n`, {
      mode: 0o600,
    });
    await fs.rename(temporary, destination);
    const acknowledgementPath = path.join(
      this.evidenceDir,
      'acks',
      `${run.runId}.json`,
    );
    await fs.rm(acknowledgementPath, { force: true });
    await this.docker.exec(
      allocation.gatewayContainerId,
      ['/bin/sh', '-c', 'kill -HUP 1'],
      { user: '0' },
    );
    const deadline = Date.now() + 10_000;
    let acknowledgement = null;
    while (Date.now() < deadline) {
      try {
        const candidate = JSON.parse(
          await fs.readFile(acknowledgementPath, 'utf8'),
        );
        if (policyAcknowledgementMatches(candidate, policy)) {
          acknowledgement = candidate;
          break;
        }
        throw policyAcknowledgementMismatchError(candidate, policy);
      } catch (error) {
        if (error.code !== 'ENOENT' && !(error instanceof SyntaxError)) {
          throw error;
        }
      }
      await new Promise((resolve) => setTimeout(resolve, 50));
    }
    if (!acknowledgement) {
      throw new Error(
        `managed egress did not attest policy ${policy.policyHash} within 10 seconds`,
      );
    }
    return {
      policyPath: destination,
      networkName: allocation.networkName,
      sourceIpv4: allocation.runnerIp,
      gatewayIpv4: allocation.egressGateway,
      gatewayContainerId: allocation.gatewayContainerId,
      routeInstalled: true,
      policyHash: policy.policyHash,
      approvalHash: policy.approvalHash,
      profilePolicyHash: policy.profilePolicyHash,
      acknowledgement,
      evidenceOffsets: {
        dns: dnsOffset,
        gateway: gatewayOffset,
      },
    };
  }

  async snapshotRun(run, options = {}) {
    if (run?.mode === 'egress-learn' && run?.egress?.observeOnly === true) {
      return null;
    }
    const runId = String(run?.runId || '');
    if (!/^[A-Za-z0-9_.-]+$/.test(runId)) {
      throw new TypeError('snapshot runId contains unsupported characters');
    }
    const policyHash = run?.egress?.policyHash;
    if (
      typeof policyHash !== 'string' ||
      !/^sha256:[a-f0-9]{64}$/.test(policyHash)
    ) {
      throw new Error('managed egress policy hash is unavailable for snapshot');
    }
    const gatewayContainerId =
      run?.egress?.gatewayContainerId || (await this.inspectGateway())?.Id;
    if (!gatewayContainerId) {
      throw new Error('managed egress gateway is unavailable for snapshot');
    }
    await this.initialize();
    const nonce = crypto.randomUUID();
    const request = {
      schemaVersion: 1,
      type: 'counter_snapshot_request',
      runId,
      policyHash,
      nonce,
      requestedAt: new Date().toISOString(),
    };
    const requestPath = path.join(this.snapshotRequestDir, `${runId}.json`);
    const requestTemporary = `${requestPath}.${process.pid}.tmp`;
    const snapshotPath = path.join(this.snapshotDir, `${runId}.json`);
    await fs.rm(snapshotPath, { force: true });
    await fs.writeFile(
      requestTemporary,
      `${JSON.stringify(request, null, 2)}\n`,
      { mode: 0o600 },
    );
    await fs.rename(requestTemporary, requestPath);
    try {
      await this.docker.exec(
        gatewayContainerId,
        ['/bin/sh', '-c', 'kill -USR1 1'],
        { user: '0' },
      );
      const deadline = Date.now() + (options.timeoutMs || 10_000);
      while (Date.now() < deadline) {
        try {
          const attestation = JSON.parse(
            await fs.readFile(snapshotPath, 'utf8'),
          );
          if (
            attestation.source === 'managed_gateway' &&
            attestation.type === 'counter_snapshot_attestation' &&
            attestation.runId === runId &&
            attestation.policyHash === policyHash &&
            attestation.nonce === nonce
          ) {
            try {
              validateManagedDnsEvidenceSnapshot(
                attestation.managedDnsEvidence,
                {
                  runId,
                  limitBytes: MANAGED_DNS_EVIDENCE_MAX_BYTES,
                },
              );
            } catch (dnsError) {
              const error = new Error(
                `managed egress DNS evidence snapshot is incomplete: ${dnsError.message}`,
                { cause: dnsError },
              );
              error.code = 'GUARD_EGRESS_SNAPSHOT_INCOMPLETE';
              error.attestation = attestation;
              throw error;
            }
            if (attestation.complete !== true) {
              const error = new Error(
                `managed egress counter snapshot is incomplete: ${
                  attestation.error || 'unknown counter collection error'
                }`,
              );
              error.code = 'GUARD_EGRESS_SNAPSHOT_INCOMPLETE';
              error.attestation = attestation;
              throw error;
            }
            return attestation;
          }
        } catch (error) {
          if (
            error.code !== 'ENOENT' &&
            !(error instanceof SyntaxError)
          ) {
            throw error;
          }
        }
        await new Promise((resolve) => setTimeout(resolve, 50));
      }
      const error = new Error(
        'managed egress did not attest a final counter snapshot within 10 seconds',
      );
      error.code = 'GUARD_EGRESS_SNAPSHOT_TIMEOUT';
      throw error;
    } finally {
      await fs.rm(requestPath, { force: true });
    }
  }

  async detachRun(run) {
    const networkName = run.egress?.networkName;
    const dnsEvidence = managedDnsEvidencePaths(this.evidenceDir, run.runId);
    if (!networkName) {
      await Promise.all([
        fs.rm(dnsEvidence.logPath, { force: true }),
        fs.rm(dnsEvidence.overflowPath, { force: true }),
      ]);
      return { ok: true, detail: 'no managed egress network recorded' };
    }
    await fs.rm(path.join(this.policiesDir, `${run.runId}.json`), { force: true });
    const gateway = await this.inspectGateway();
    if (gateway) {
      try {
        await this.docker.exec(gateway.Id, ['/bin/sh', '-c', 'kill -HUP 1'], {
          user: '0',
        });
      } catch {
        // The gateway may be restarting; removing the internal network remains
        // fail closed for this runner.
      }
      try {
        await this.docker.disconnectNetwork(networkName, gateway.Id, true);
      } catch (error) {
        // Stale-run cleanup is idempotent: Docker can report a 500 when the
        // endpoint was already disconnected, and a 404 when the network was
        // already removed. Both states mean there is nothing left to detach.
        const alreadyDetached =
          /not connected to the network|network .* not found/i.test(
            String(error.message || ''),
          );
        if (error.statusCode !== 404 && !alreadyDetached) {
          throw error;
        }
      }
    }
    await fs.rm(path.join(this.evidenceDir, 'acks', `${run.runId}.json`), {
      force: true,
    });
    try {
      await this.docker.removeNetwork(networkName);
    } catch (error) {
      if (error.statusCode !== 404) {
        throw error;
      }
    }
    await Promise.all([
      fs.rm(dnsEvidence.logPath, { force: true }),
      fs.rm(dnsEvidence.overflowPath, { force: true }),
    ]);
    return { ok: true, networkName };
  }
}

export {
  captureFileCursor,
  networkFromInspect,
  readNetworkRules,
  secureDirectory,
  subnetCandidate,
};
