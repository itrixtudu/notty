import { workloadName } from './workload.js';
import crypto from 'node:crypto';
import fs from 'node:fs/promises';
import { constants as fsConstants } from 'node:fs';
import path from 'node:path';

import { verifyEbpfDeploymentAuthority } from '../guard/review/grant-service.js';
import { validateLeafManifest } from '../guard/review/leaf-store.js';
import { stableStringify } from '../guard/stable.js';
import {
  DEFAULT_GUARD_CONFIG_DIR,
  DEFAULT_GUARD_STATE_DIR,
} from './constants.js';
import { EBPF_EGRESS_BACKEND_ABI } from './enforcement-backend.js';

export const DEFAULT_EBPF_DEPLOYMENT_TRUST = path.join(
  DEFAULT_GUARD_CONFIG_DIR,
  'ebpf-deployment-trust.json',
);
export const EBPF_ACTIVATION_LAYOUT = Object.freeze({
  policy: 'policy',
  approval: 'approval-envelope.dsse.json',
  grant: 'deployment-grant.dsse.json',
});

const HASH = /^sha256:[a-f0-9]{64}$/;
function hash(value) {
  return `sha256:${crypto.createHash('sha256')
    .update(
      Buffer.isBuffer(value)
        ? value
        : typeof value === 'string'
          ? value
          : stableStringify(value),
    )
    .digest('hex')}`;
}

function createGenesisGrantSetDigest() {
  return hash({
    kind: 'NoshGuardEbpfGrantSetGenesis',
    schemaVersion: 1,
    nonce: crypto.randomBytes(32).toString('hex'),
  });
}

function expectedUid() {
  return typeof process.geteuid === 'function' && process.geteuid() === 0
    ? 0
    : null;
}

function exactKeys(value, required, optional, label) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    throw new TypeError(`${label} must be an object`);
  }
  const permitted = new Set([...required, ...optional]);
  if (
    required.some((name) => !Object.hasOwn(value, name))
    || Object.keys(value).some((name) => !permitted.has(name))
  ) {
    throw new TypeError(`${label} has an invalid field inventory`);
  }
  return value;
}

async function assertRootOwnedPathChain(target, { type = 'file' } = {}) {
  const resolved = path.resolve(target);
  const real = await fs.realpath(resolved);
  if (real !== resolved) {
    throw new Error(`trusted eBPF activation path contains a symlink: ${resolved}`);
  }
  const uid = expectedUid();
  for (let selected = resolved; ; selected = path.dirname(selected)) {
    const stat = await fs.lstat(selected);
    const leaf = selected === resolved;
    if (
      stat.isSymbolicLink()
      || (uid != null && stat.uid !== uid)
      || (!leaf && (!stat.isDirectory() || (stat.mode & 0o022) !== 0))
      || (leaf && type === 'file' && !stat.isFile())
      || (leaf && type === 'directory' && !stat.isDirectory())
    ) {
      throw new Error(`trusted eBPF activation path chain is unsafe: ${resolved}`);
    }
    if (selected === path.parse(selected).root) break;
  }
  return resolved;
}

async function privateDirectory(directory, { create = false } = {}) {
  const resolved = path.resolve(directory);
  if (create) await fs.mkdir(resolved, { recursive: true, mode: 0o700 });
  const real = await fs.realpath(resolved);
  const stat = await fs.lstat(real);
  const uid = expectedUid();
  if (
    real !== resolved
    || !stat.isDirectory()
    || stat.isSymbolicLink()
    || (stat.mode & 0o7777) !== 0o700
    || (uid != null && stat.uid !== uid)
  ) {
    throw new Error(`eBPF activation directory is not root-owned mode 0700: ${resolved}`);
  }
  return resolved;
}

async function trustedRootFile(filePath, maximumBytes = 16 * 1024 * 1024) {
  const resolved = path.resolve(filePath);
  const real = await fs.realpath(resolved);
  if (real !== resolved) throw new Error(`trusted file contains a symlink: ${resolved}`);
  const handle = await fs.open(
    resolved,
    fsConstants.O_RDONLY | (fsConstants.O_NOFOLLOW || 0),
  );
  try {
    const stat = await handle.stat();
    const uid = expectedUid();
    if (
      !stat.isFile()
      || stat.nlink !== 1
      || stat.size > maximumBytes
      || (stat.mode & 0o022) !== 0
      || (uid != null && stat.uid !== uid)
    ) {
      throw new Error(`trusted file is not a safe root-owned file: ${resolved}`);
    }
    const content = await handle.readFile();
    const current = await fs.lstat(resolved);
    if (
      !current.isFile()
      || current.isSymbolicLink()
      || current.dev !== stat.dev
      || current.ino !== stat.ino
    ) {
      throw new Error(`trusted file changed during read: ${resolved}`);
    }
    return content;
  } finally {
    await handle.close();
  }
}

async function sourceFile(sourceRoot, relative, sourceUid, maximumBytes) {
  const root = path.resolve(sourceRoot);
  const selected = path.resolve(root, relative);
  const between = path.relative(root, selected);
  if (!between || between.startsWith('..') || path.isAbsolute(between)) {
    throw new Error(`activation import path escapes its source: ${relative}`);
  }
  const real = await fs.realpath(selected);
  if (real !== selected) throw new Error(`activation import contains a symlink: ${relative}`);
  const handle = await fs.open(
    selected,
    fsConstants.O_RDONLY | (fsConstants.O_NOFOLLOW || 0),
  );
  try {
    const stat = await handle.stat();
    if (
      !stat.isFile()
      || stat.nlink !== 1
      || !Number.isSafeInteger(stat.size)
      || stat.size > maximumBytes
      || (stat.mode & 0o022) !== 0
      || (sourceUid != null && stat.uid !== sourceUid)
    ) {
      throw new Error(`activation import file is unsafe: ${relative}`);
    }
    const content = Buffer.allocUnsafe(stat.size);
    let offset = 0;
    while (offset < content.length) {
      const { bytesRead } = await handle.read(
        content,
        offset,
        content.length - offset,
        offset,
      );
      if (bytesRead === 0) {
        throw new Error(`activation import changed during read: ${relative}`);
      }
      offset += bytesRead;
    }
    const trailing = Buffer.allocUnsafe(1);
    const extra = await handle.read(trailing, 0, 1, content.length);
    const after = await handle.stat();
    const current = await fs.lstat(selected);
    if (
      extra.bytesRead !== 0
      || after.dev !== stat.dev
      || after.ino !== stat.ino
      || after.size !== stat.size
      || after.mtimeMs !== stat.mtimeMs
      || after.ctimeMs !== stat.ctimeMs
      || !current.isFile()
      || current.isSymbolicLink()
      || current.dev !== stat.dev
      || current.ino !== stat.ino
      || current.size !== stat.size
      || current.mtimeMs !== stat.mtimeMs
      || current.ctimeMs !== stat.ctimeMs
    ) {
      throw new Error(`activation import changed during read: ${relative}`);
    }
    return content;
  } finally {
    await handle.close();
  }
}

async function writeExclusive(filePath, content) {
  await fs.mkdir(path.dirname(filePath), { recursive: true, mode: 0o700 });
  const handle = await fs.open(
    filePath,
    fsConstants.O_WRONLY
      | fsConstants.O_CREAT
      | fsConstants.O_EXCL
      | (fsConstants.O_NOFOLLOW || 0),
    0o600,
  );
  try {
    await handle.writeFile(content);
    await handle.sync();
  } finally {
    await handle.close();
  }
  await syncDirectory(path.dirname(filePath));
}

async function atomicJson(filePath, value) {
  const temporary = `${filePath}.tmp-${process.pid}-${crypto.randomUUID()}`;
  let handle;
  try {
    handle = await fs.open(
      temporary,
      fsConstants.O_WRONLY
        | fsConstants.O_CREAT
        | fsConstants.O_EXCL
        | (fsConstants.O_NOFOLLOW || 0),
      0o600,
    );
    await handle.writeFile(`${stableStringify(value, 2)}\n`);
    await handle.sync();
    await handle.close();
    handle = null;
    await fs.rename(temporary, filePath);
    await syncDirectory(path.dirname(filePath));
  } catch (error) {
    await handle?.close().catch(() => {});
    await fs.unlink(temporary).catch(() => {});
    throw error;
  }
}

async function createJson(filePath, value) {
  const temporary = `${filePath}.init-${process.pid}-${crypto.randomUUID()}`;
  let handle;
  try {
    handle = await fs.open(
      temporary,
      fsConstants.O_WRONLY
        | fsConstants.O_CREAT
        | fsConstants.O_EXCL
        | (fsConstants.O_NOFOLLOW || 0),
      0o600,
    );
    await handle.writeFile(`${stableStringify(value, 2)}\n`);
    await handle.sync();
    await handle.close();
    handle = null;
    // link(2) supplies the no-replace atomicity that rename(2) lacks. A
    // concurrent initializer either installs this complete inode or observes
    // the already installed state; it can never replace it.
    await fs.link(temporary, filePath);
    await syncDirectory(path.dirname(filePath));
  } catch (error) {
    if (error.code !== 'EEXIST') throw error;
  } finally {
    await handle?.close().catch(() => {});
    await fs.unlink(temporary).catch(() => {});
    await syncDirectory(path.dirname(filePath)).catch(() => {});
  }
}

async function syncDirectory(directory) {
  const handle = await fs.open(
    directory,
    fsConstants.O_RDONLY | (fsConstants.O_DIRECTORY || 0),
  );
  try {
    await handle.sync();
  } finally {
    await handle.close();
  }
}

async function syncDirectoryTree(directory) {
  const entries = await fs.readdir(directory, { withFileTypes: true });
  for (const entry of entries) {
    const selected = path.join(directory, entry.name);
    if (entry.isSymbolicLink()) {
      throw new Error(`eBPF activation staging contains a symlink: ${selected}`);
    }
    if (entry.isDirectory()) {
      await syncDirectoryTree(selected);
    } else if (!entry.isFile()) {
      throw new Error(`eBPF activation staging contains an unsupported entry: ${selected}`);
    }
  }
  await syncDirectory(directory);
}

function delay(milliseconds) {
  return new Promise((resolve) => setTimeout(resolve, milliseconds));
}

function stateWithDigest(state) {
  const { stateDigest: ignored, ...unsigned } = state;
  return { ...unsigned, stateDigest: hash(unsigned) };
}

function validateState(input) {
  const state = exactKeys(
    input,
    [
      'schemaVersion',
      'kind',
      'activeGrantSetDigest',
      'current',
      'usedGrants',
      'updatedAt',
      'stateDigest',
    ],
    [],
    'eBPF activation state',
  );
  if (
    state.schemaVersion !== 1
    || state.kind !== 'NoshGuardEbpfActivationState'
    || !HASH.test(state.activeGrantSetDigest || '')
    || !Array.isArray(state.usedGrants)
    || !Number.isFinite(Date.parse(state.updatedAt))
  ) {
    throw new TypeError('eBPF activation state header is invalid');
  }
  const { stateDigest, ...unsigned } = state;
  if (stateDigest !== hash(unsigned)) {
    throw new Error('eBPF activation state digest mismatch');
  }
  return state;
}

function validateTrust(input) {
  const trust = exactKeys(
    input,
    [
      'schemaVersion',
      'kind',
      'backendAbi',
      'reviewPublicKey',
      'deploymentPublicKey',
      'reviewAudience',
      'deploymentAudience',
    ],
    [],
    'eBPF deployment trust',
  );
  if (
    trust.schemaVersion !== 1
    || trust.kind !== 'NoshGuardEbpfDeploymentTrust'
    || trust.backendAbi !== EBPF_EGRESS_BACKEND_ABI
    || !path.isAbsolute(trust.reviewPublicKey || '')
    || !path.isAbsolute(trust.deploymentPublicKey || '')
    || typeof trust.reviewAudience !== 'string'
    || !trust.reviewAudience
    || trust.reviewAudience.length > 255
    || /[\u0000-\u001f\u007f]/.test(trust.reviewAudience)
    || typeof trust.deploymentAudience !== 'string'
    || !trust.deploymentAudience
    || trust.deploymentAudience.length > 255
    || /[\u0000-\u001f\u007f]/.test(trust.deploymentAudience)
    || path.resolve(trust.reviewPublicKey) === path.resolve(trust.deploymentPublicKey)
  ) {
    throw new TypeError('eBPF deployment trust is invalid');
  }
  return trust;
}

function nextGrantSetDigest(previous, verification) {
  return hash({
    previousActiveGrantSetDigest: previous,
    grantEnvelopeDigest: verification.grant.envelopeDigest,
    leafBundleDigest: verification.policy.leaf.bundleDigest,
    nonce: verification.grant.statement.nonce,
  });
}

async function snapshotActivation(sourceDirectory, staging, sourceUid) {
  const source = path.resolve(sourceDirectory);
  const real = await fs.realpath(source);
  const stat = await fs.lstat(real);
  if (
    source !== real
    || !stat.isDirectory()
    || stat.isSymbolicLink()
    || (stat.mode & 0o077) !== 0
    || (sourceUid != null && stat.uid !== sourceUid)
  ) {
    throw new Error('activation import directory is not private or trusted');
  }
  const leafContent = await sourceFile(
    source,
    `${EBPF_ACTIVATION_LAYOUT.policy}/leaf-bundle.json`,
    sourceUid,
    4 * 1024 * 1024,
  );
  const leaf = validateLeafManifest(JSON.parse(leafContent.toString('utf8')));
  await writeExclusive(
    path.join(staging, EBPF_ACTIVATION_LAYOUT.policy, 'leaf-bundle.json'),
    leafContent,
  );
  for (const artifact of leaf.artifacts) {
    const relative = `${EBPF_ACTIVATION_LAYOUT.policy}/${artifact.path}`;
    const content = await sourceFile(source, relative, sourceUid, 128 * 1024 * 1024);
    if (String(content.length) !== artifact.bytes || hash(content) !== artifact.sha256) {
      throw new Error(`activation leaf artifact digest changed: ${artifact.path}`);
    }
    await writeExclusive(path.join(staging, relative), content);
  }
  for (const relative of [
    EBPF_ACTIVATION_LAYOUT.approval,
    EBPF_ACTIVATION_LAYOUT.grant,
  ]) {
    await writeExclusive(
      path.join(staging, relative),
      await sourceFile(source, relative, sourceUid, 16 * 1024 * 1024),
    );
  }
}

export class EbpfActivationStore {
  constructor(options = {}) {
    const workload = workloadName(options.workload);
    this.workspaceKey = options.workspaceKey;
    if (!/^[a-f0-9]{64}$/.test(this.workspaceKey || '')) {
      throw new TypeError('dev/run activation storage requires a workspace key');
    }
    this.stateRoot = path.resolve(
      options.stateRoot
        || path.join(options.stateDir || DEFAULT_GUARD_STATE_DIR, 'activations', `guard-ebpf-${workload}-${this.workspaceKey}`),
    );
    this.importsDir = path.join(this.stateRoot, 'imports');
    this.statePath = path.join(this.stateRoot, 'current.json');
    this.lockPath = path.join(this.stateRoot, 'activation.lock');
    this.trustPath = path.resolve(
      options.trustPath || DEFAULT_EBPF_DEPLOYMENT_TRUST,
    );
    this.lockTimeoutMs = options.lockTimeoutMs ?? 30_000;
    this.verifyAuthority = options.verifyAuthority || verifyEbpfDeploymentAuthority;
    this.enforceTrustPathChains = options.enforceTrustPathChains !== false;
  }

  async ensureDirectories() {
    await privateDirectory(this.stateRoot, { create: true });
    await privateDirectory(this.importsDir, { create: true });
  }

  async initializeUnlocked() {
    await this.ensureDirectories();
    try {
      await fs.access(this.statePath);
    } catch (error) {
      if (error.code !== 'ENOENT') throw error;
      const now = new Date().toISOString();
      await createJson(this.statePath, stateWithDigest({
        schemaVersion: 1,
        kind: 'NoshGuardEbpfActivationState',
        // A per-install random root prevents a grant minted for one fresh
        // Guard state from replaying against another installation that uses
        // the same trust keys and audience.
        activeGrantSetDigest: createGenesisGrantSetDigest(),
        current: null,
        usedGrants: [],
        updatedAt: now,
      }));
    }
    return this.readState();
  }

  async withActivationLock(operation, options = {}) {
    await this.ensureDirectories();
    const timeoutMs = options.timeoutMs ?? this.lockTimeoutMs;
    if (!Number.isSafeInteger(timeoutMs) || timeoutMs < 1 || timeoutMs > 300_000) {
      throw new TypeError('eBPF activation lock timeout must be 1..300000 milliseconds');
    }
    const deadline = Date.now() + timeoutMs;
    let handle;
    while (!handle) {
      try {
        handle = await fs.open(
          this.lockPath,
          fsConstants.O_WRONLY
            | fsConstants.O_CREAT
            | fsConstants.O_EXCL
            | (fsConstants.O_NOFOLLOW || 0),
          0o600,
        );
      } catch (error) {
        if (error.code !== 'EEXIST') throw error;
        // A crashed writer intentionally leaves a fail-closed sentinel. PID
        // probing cannot safely reclaim it because host PIDs may be reused;
        // recovery therefore requires an operator to establish that no
        // activation process still owns this exact root-only path.
        if (Date.now() >= deadline) {
          const lockError = new Error(
            'timed out waiting for the guard-ebpf activation transition lock '
              + `${this.lockPath}; confirm no activation process owns it before recovery`,
          );
          lockError.code = 'GUARD_EBPF_ACTIVATION_BUSY';
          throw lockError;
        }
        await delay(25);
      }
    }
    try {
      await handle.writeFile(`${stableStringify({
        schemaVersion: 1,
        pid: process.pid,
        acquiredAt: new Date().toISOString(),
      })}\n`);
      await handle.sync();
      await syncDirectory(this.stateRoot);
      return await operation();
    } finally {
      await handle.close().catch(() => {});
      await fs.unlink(this.lockPath).catch(() => {});
      await syncDirectory(this.stateRoot).catch(() => {});
    }
  }

  async initialize() {
    return this.withActivationLock(() => this.initializeUnlocked());
  }

  async readState() {
    return validateState(JSON.parse((await trustedRootFile(this.statePath)).toString('utf8')));
  }

  async readTrust() {
    if (this.enforceTrustPathChains) {
      await assertRootOwnedPathChain(this.trustPath);
    }
    const trust = validateTrust(
      JSON.parse((await trustedRootFile(this.trustPath)).toString('utf8')),
    );
    if (this.enforceTrustPathChains) {
      await Promise.all([
        assertRootOwnedPathChain(trust.reviewPublicKey),
        assertRootOwnedPathChain(trust.deploymentPublicKey),
      ]);
    }
    return trust;
  }

  async importActivation(sourceDirectory, input = {}) {
    if (input.expected?.workspaceKey !== this.workspaceKey) throw new Error('activation belongs to another workspace');
    await this.ensureDirectories();
    return this.withActivationLock(async () => {
      await this.initializeUnlocked();
      const state = await this.readState();
      const trust = await this.readTrust();
      const transitionClock = input.now instanceof Date
        ? new Date(input.now.getTime())
        : new Date(input.now ?? Date.now());
      if (!Number.isFinite(transitionClock.getTime())) {
        throw new TypeError('eBPF activation transition clock is invalid');
      }
      const staging = path.join(this.importsDir, `.staging-${crypto.randomUUID()}`);
      await fs.mkdir(staging, { mode: 0o700 });
      await syncDirectory(this.importsDir);
      try {
        await snapshotActivation(sourceDirectory, staging, input.sourceUid);
        await syncDirectoryTree(staging);
        const verification = await this.verifyAuthority({
          policy: path.join(staging, EBPF_ACTIVATION_LAYOUT.policy),
          approval: path.join(staging, EBPF_ACTIVATION_LAYOUT.approval),
          grant: path.join(staging, EBPF_ACTIVATION_LAYOUT.grant),
          reviewPublicKey: trust.reviewPublicKey,
          deploymentPublicKey: trust.deploymentPublicKey,
          reviewAudience: trust.reviewAudience,
          deploymentAudience: trust.deploymentAudience,
          activeGrantSetDigest: state.activeGrantSetDigest,
          expected: input.expected,
          now: transitionClock,
        });
        if (state.usedGrants.some((entry) => (
          entry.nonce === verification.grant.statement.nonce
          || entry.grantEnvelopeDigest === verification.grant.envelopeDigest
        ))) {
          throw new Error('deployment grant was already consumed');
        }
        const importId = verification.grant.envelopeDigest.slice(7);
        const directory = path.join(this.importsDir, importId);
        const activatedAt = transitionClock.toISOString();
        await fs.rename(staging, directory);
        await syncDirectory(this.importsDir);
        const current = {
          directory,
          activatedAt,
          previousActiveGrantSetDigest: state.activeGrantSetDigest,
          leafBundleDigest: verification.policy.leaf.bundleDigest,
          ...(verification.policy.policyIR?.decisionSetDigest
            ? { decisionSetDigest: verification.policy.policyIR.decisionSetDigest } : {}),
          approvalEnvelopeDigest: verification.approval.envelopeDigest,
          grantEnvelopeDigest: verification.grant.envelopeDigest,
          nonce: verification.grant.statement.nonce,
          imageDigest: input.expected.imageDigest,
          workspaceKey: input.expected.workspaceKey,
          workspaceIdentity: input.expected.workspaceIdentity,
          backendAbi: input.expected.backendAbi,
          objectDigest: input.expected.objectDigest,
          ...(input.launchReference ? { launchReference: structuredClone(input.launchReference) } : {}),
        };
        const next = stateWithDigest({
          ...state,
          activeGrantSetDigest: nextGrantSetDigest(state.activeGrantSetDigest, verification),
          current,
          usedGrants: [
            ...state.usedGrants,
            {
              nonce: current.nonce,
              grantEnvelopeDigest: current.grantEnvelopeDigest,
              leafBundleDigest: current.leafBundleDigest,
              activatedAt,
            },
          ],
          updatedAt: activatedAt,
        });
        await atomicJson(this.statePath, next);
        return { state: next, current, verification };
      } catch (error) {
        await fs.rm(staging, { recursive: true, force: true }).catch(() => {});
        await syncDirectory(this.importsDir).catch(() => {});
        throw error;
      }
    });
  }

  async verifyActive(expected, { leafBundleDigest } = {}) {
    if (expected.workspaceKey !== this.workspaceKey) throw new Error('activation belongs to another workspace');
    await this.ensureDirectories();
    return this.withActivationLock(async () => {
      await this.initializeUnlocked();
      const state = await this.readState();
      const trust = await this.readTrust();
      const current = state.current;
      if (!current) {
        const error = new Error('no signed guard-ebpf deployment is active');
        error.code = 'GUARD_EBPF_ACTIVATION_REQUIRED';
        throw error;
      }
      for (const field of ['imageDigest', 'workspaceKey', 'backendAbi', 'objectDigest']) {
        if (current[field] !== expected[field]) {
          throw new Error(`active guard-ebpf deployment ${field} does not match the run`);
        }
      }
      if (leafBundleDigest != null && current.leafBundleDigest !== leafBundleDigest) {
        throw new Error('active guard-ebpf deployment changed after launch selection; confirm the policy again');
      }
      if (
        String(current.workspaceIdentity?.dev) !== String(expected.workspaceIdentity?.dev)
        || String(current.workspaceIdentity?.ino) !== String(expected.workspaceIdentity?.ino)
      ) {
        throw new Error('active guard-ebpf deployment workspace identity does not match the run');
      }
      const activationClock = new Date(current.activatedAt);
      if (!Number.isFinite(activationClock.getTime())) {
        throw new Error('active guard-ebpf deployment has an invalid activation time');
      }
      const verification = await this.verifyAuthority({
        policy: path.join(current.directory, EBPF_ACTIVATION_LAYOUT.policy),
        approval: path.join(current.directory, EBPF_ACTIVATION_LAYOUT.approval),
        grant: path.join(current.directory, EBPF_ACTIVATION_LAYOUT.grant),
        reviewPublicKey: trust.reviewPublicKey,
        deploymentPublicKey: trust.deploymentPublicKey,
        reviewAudience: trust.reviewAudience,
        deploymentAudience: trust.deploymentAudience,
        activeGrantSetDigest: current.previousActiveGrantSetDigest,
        expected,
        // A consumed grant authorizes the activation transition. Re-verification
        // proves it was valid at that transition; expiry does not silently tear
        // down the active root-owned policy.
        now: activationClock,
      });
      if (
        verification.policy.leaf.bundleDigest !== current.leafBundleDigest
        || verification.approval.envelopeDigest !== current.approvalEnvelopeDigest
        || verification.grant.envelopeDigest !== current.grantEnvelopeDigest
        || verification.grant.statement.nonce !== current.nonce
      ) {
        throw new Error('active guard-ebpf deployment state does not bind its artifacts');
      }
      return { state, current, verification };
    });
  }
}
