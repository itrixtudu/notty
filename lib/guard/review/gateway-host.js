import { spawn } from 'node:child_process';
import { constants as fsConstants } from 'node:fs';
import fs from 'node:fs/promises';
import net from 'node:net';
import path from 'node:path';

import { readTrustedFile, readTrustedJson } from './io.js';
import { jcsCanonicalize, sha256Digest } from './jcs.js';
import { readPolicyLeafArtifact } from './leaf-store.js';
import {
  ed25519KeyId,
  GATEWAY_GRANT_PAYLOAD_TYPE,
  REVIEW_APPROVAL_PAYLOAD_TYPE,
  validateGatewayGrantStatement,
  validateReviewApprovalStatement,
  verifyDsseEnvelope,
} from './signing.js';

export const DEFAULT_GATEWAY_TRUST_PATH = '/etc/nosh-gateway/trust.json';
export const GATEWAY_STATE_NAME = 'state.json';

const API_VERSION = 'notty.dev/v1alpha1';
const SCHEMA_VERSION = 1;
const DIGEST_PATTERN = /^sha256:[a-f0-9]{64}$/;
const SAFE_COMMAND_ARGUMENT = /^[^\u0000]*$/;
const SAFE_SYSTEMD_UNIT = /^[A-Za-z0-9][A-Za-z0-9@_.:-]{0,254}\.service$/;
const ACTIVE_STATE_STATUSES = new Set(['bootstrap', 'active']);
const MAX_COMMAND_OUTPUT_BYTES = 4 * 1024 * 1024;
const MAX_USED_GRANTS = 4096;
const COMMAND_BASENAMES = Object.freeze({
  conntrack: /^conntrack$/,
  dnsmasq: /^dnsmasq$/,
  ipset: /^ipset$/,
  iptables: /^iptables(?:-legacy|-nft)?$/,
  iptablesRestore: /^iptables(?:-legacy|-nft)?-restore$|^iptables-restore(?:-legacy|-nft)?$/,
  iptablesSave: /^iptables(?:-legacy|-nft)?-save$|^iptables-save(?:-legacy|-nft)?$/,
  nft: /^nft$/,
  systemctl: /^systemctl$/,
});

const BACKENDS = Object.freeze({
  'guard-nftables': Object.freeze({
    commands: Object.freeze(['conntrack', 'dnsmasq', 'nft', 'systemctl']),
    paths: Object.freeze(['dnsmasqConfig', 'nftablesConfig', 'stateDirectory']),
    rendered: Object.freeze([
      'apply-plan.json',
      'dnsmasq.conf',
      'gateway-policy.json',
      'nftables.nft',
    ]),
    compiler: 'nosh-guard-nftables-policy-v1',
  }),
  'gateway-iptables': Object.freeze({
    commands: Object.freeze([
      'conntrack',
      'dnsmasq',
      'ipset',
      'iptables',
      'iptablesRestore',
      'iptablesSave',
      'systemctl',
    ]),
    paths: Object.freeze([
      'dnsmasqConfig',
      'ipsetRestoreConfig',
      'iptablesRestoreConfig',
      'stateDirectory',
    ]),
    rendered: Object.freeze([
      'apply-plan.json',
      'dnsmasq.conf',
      'ipset.restore',
      'iptables-restore.v4',
      'verify-plan.json',
    ]),
    compiler: 'nosh-gateway-iptables-policy-v1',
  }),
});

function plainObject(value, label) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    throw new TypeError(`${label} must be an object`);
  }
  return value;
}

function exactKeys(value, expected, label) {
  plainObject(value, label);
  const actual = Object.keys(value).sort();
  const selected = [...expected].sort();
  if (
    actual.length !== selected.length
    || actual.some((key, index) => key !== selected[index])
  ) {
    throw new TypeError(`${label} contains missing or unsupported fields`);
  }
}

function boundedString(value, label, maximum = 1024) {
  if (
    typeof value !== 'string'
    || !value
    || value.length > maximum
    || /[\u0000-\u001f\u007f]/.test(value)
  ) {
    throw new TypeError(`${label} must be a bounded non-empty string`);
  }
  return value;
}

function digest(value, label) {
  if (typeof value !== 'string' || !DIGEST_PATTERN.test(value)) {
    throw new TypeError(`${label} must be a SHA-256 digest`);
  }
  return value;
}

function absolutePath(value, label, options = {}) {
  const selected = boundedString(value, label, 4096);
  if (
    !path.isAbsolute(selected)
    || path.normalize(selected) !== selected
    || selected === '/'
    || selected.endsWith('/')
  ) {
    throw new TypeError(`${label} must be a canonical absolute path below /`);
  }
  if (options.executable && path.dirname(selected) === '/') {
    throw new TypeError(`${label} must name an executable below a system directory`);
  }
  return selected;
}

function normalizedTrustedKey(entry, label) {
  exactKeys(entry, ['keyId', 'publicKeyPem'], label);
  const publicKeyPem = entry.publicKeyPem;
  if (
    typeof publicKeyPem !== 'string'
    || publicKeyPem.length < 1
    || publicKeyPem.length > 64 * 1024
    || /[\u0000-\u0009\u000b-\u001f\u007f]/.test(publicKeyPem)
    || !publicKeyPem.startsWith('-----BEGIN PUBLIC KEY-----\n')
    || !publicKeyPem.endsWith('-----END PUBLIC KEY-----\n')
  ) throw new TypeError(`${label}.publicKeyPem must be a bounded public-key PEM`);
  const keyId = ed25519KeyId(publicKeyPem);
  if (entry.keyId !== keyId) {
    throw new TypeError(`${label}.keyId does not match its Ed25519 public key`);
  }
  return { keyId, publicKeyPem };
}

function normalizedKeys(entries, label) {
  if (!Array.isArray(entries) || entries.length < 1 || entries.length > 64) {
    throw new TypeError(`${label} must contain from 1 through 64 keys`);
  }
  const result = entries.map((entry, index) => (
    normalizedTrustedKey(entry, `${label}[${index}]`)
  )).sort((left, right) => left.keyId.localeCompare(right.keyId));
  if (new Set(result.map((entry) => entry.keyId)).size !== result.length) {
    throw new TypeError(`${label} contains duplicate keys`);
  }
  return result;
}

function normalizedNamedPaths(input, names, label, options = {}) {
  exactKeys(input, names, label);
  return Object.fromEntries(names.map((name) => [
    name,
    absolutePath(input[name], `${label}.${name}`, options),
  ]));
}

export function validateGatewayTrustConfig(input) {
  exactKeys(input, [
    'activeGrantSetDigest',
    'apiVersion',
    'audience',
    'capabilityDigest',
    'commands',
    'deploymentKeys',
    'kind',
    'paths',
    'reviewKeys',
    'schemaVersion',
    'services',
    'target',
    'targetBindingDigest',
    'targetContextDigest',
  ], 'gateway trust config');
  if (
    input.apiVersion !== API_VERSION
    || input.kind !== 'NoshGatewayTrustConfig'
    || input.schemaVersion !== SCHEMA_VERSION
  ) {
    throw new TypeError('gateway trust config header is unsupported');
  }
  const backend = BACKENDS[input.target];
  if (!backend) throw new TypeError('gateway trust config target is unsupported');
  exactKeys(input.services, ['dnsmasq'], 'gateway trust config services');
  const dnsmasqService = boundedString(
    input.services.dnsmasq,
    'gateway trust config services.dnsmasq',
    255,
  );
  if (!SAFE_SYSTEMD_UNIT.test(dnsmasqService)) {
    throw new TypeError('gateway dnsmasq service must be an exact systemd service unit');
  }
  const normalized = {
    apiVersion: API_VERSION,
    kind: 'NoshGatewayTrustConfig',
    schemaVersion: SCHEMA_VERSION,
    audience: boundedString(input.audience, 'gateway trust config audience', 255),
    target: input.target,
    targetBindingDigest: digest(input.targetBindingDigest, 'targetBindingDigest'),
    targetContextDigest: digest(input.targetContextDigest, 'targetContextDigest'),
    capabilityDigest: digest(input.capabilityDigest, 'capabilityDigest'),
    activeGrantSetDigest: digest(input.activeGrantSetDigest, 'activeGrantSetDigest'),
    reviewKeys: normalizedKeys(input.reviewKeys, 'gateway trust config reviewKeys'),
    deploymentKeys: normalizedKeys(
      input.deploymentKeys,
      'gateway trust config deploymentKeys',
    ),
    commands: normalizedNamedPaths(
      input.commands,
      backend.commands,
      'gateway trust config commands',
      { executable: true },
    ),
    paths: normalizedNamedPaths(
      input.paths,
      backend.paths,
      'gateway trust config paths',
    ),
    services: { dnsmasq: dnsmasqService },
  };
  for (const [name, command] of Object.entries(normalized.commands)) {
    if (!COMMAND_BASENAMES[name].test(path.basename(command))) {
      throw new TypeError(`gateway command ${name} has an unexpected executable name`);
    }
  }
  if (new Set(Object.values(normalized.commands)).size !== Object.keys(normalized.commands).length) {
    throw new TypeError('gateway commands must use distinct executable paths');
  }
  if (new Set(Object.values(normalized.paths)).size !== Object.keys(normalized.paths).length) {
    throw new TypeError('gateway managed paths must be distinct');
  }
  const deploymentKeyIds = new Set(normalized.deploymentKeys.map((entry) => entry.keyId));
  if (normalized.reviewKeys.some((entry) => deploymentKeyIds.has(entry.keyId))) {
    throw new TypeError('review and deployment signing roles must use separate keys');
  }
  return Object.freeze(normalized);
}

async function assertRootOwnedPathChain(target, options = {}) {
  const resolved = path.resolve(target);
  if (await fs.realpath(resolved) !== resolved) {
    throw new Error(`trusted gateway path is not canonical: ${resolved}`);
  }
  const pieces = resolved.split(path.sep).filter(Boolean);
  let current = '/';
  for (let index = 0; index < pieces.length; index += 1) {
    current = path.join(current, pieces[index]);
    const stat = await fs.lstat(current);
    const leaf = index === pieces.length - 1;
    if (stat.isSymbolicLink() || stat.uid !== (options.expectedUid ?? 0)) {
      throw new Error(`trusted gateway path has unsafe ownership or links: ${current}`);
    }
    if (!leaf || options.type === 'directory') {
      if (!stat.isDirectory() || (stat.mode & 0o022) !== 0) {
        throw new Error(`trusted gateway directory is writable by another user: ${current}`);
      }
    } else {
      const selectedMode = stat.mode & 0o777;
      if (
        !stat.isFile()
        || stat.nlink !== 1
        || (options.mode != null
          ? selectedMode !== options.mode
          : (selectedMode & 0o022) !== 0)
        || (options.executable === true && (selectedMode & 0o111) === 0)
      ) {
        throw new Error(`trusted gateway file has unsafe type, links, or mode: ${current}`);
      }
    }
  }
  return resolved;
}

async function assertTrustedExecutable(file, expectedUid = 0) {
  const requested = path.resolve(file);
  await assertRootOwnedPathChain(path.dirname(requested), {
    expectedUid,
    type: 'directory',
  });
  const requestedStat = await fs.lstat(requested);
  if (requestedStat.uid !== expectedUid) {
    throw new Error(`configured command is not root-owned: ${requested}`);
  }
  if (!requestedStat.isFile() && !requestedStat.isSymbolicLink()) {
    throw new Error(`configured command has an unsupported file type: ${requested}`);
  }
  const resolved = await fs.realpath(requested);
  await assertRootOwnedPathChain(resolved, {
    expectedUid,
    type: 'file',
    executable: true,
  });
  return requested;
}

export async function assertTrustedPolicyLeafTree(directory, options = {}) {
  const root = path.resolve(directory);
  const expectedUid = options.expectedUid ?? 0;
  if (options.checkPathChain !== false) {
    await assertRootOwnedPathChain(root, { expectedUid, type: 'directory' });
  }
  let entries = 0;
  let bytes = 0;
  async function visit(current, depth) {
    if (depth > 16) throw new Error('policy leaf tree exceeds its depth limit');
    const stat = await fs.lstat(current);
    if (
      stat.isSymbolicLink()
      || stat.uid !== expectedUid
      || (stat.mode & 0o077) !== 0
    ) throw new Error(`policy leaf tree has unsafe ownership, mode, or symlink: ${current}`);
    if (stat.isFile()) {
      if (stat.nlink !== 1) throw new Error(`policy leaf tree contains a hard link: ${current}`);
      bytes += stat.size;
      if (bytes > 512 * 1024 * 1024) {
        throw new Error('policy leaf tree exceeds its byte limit');
      }
      return;
    }
    if (!stat.isDirectory()) {
      throw new Error(`policy leaf tree contains a special file: ${current}`);
    }
    const children = await fs.readdir(current);
    for (const name of children) {
      entries += 1;
      if (entries > 4096) throw new Error('policy leaf tree exceeds its entry limit');
      await visit(path.join(current, name), depth + 1);
    }
  }
  await visit(root, 0);
  return Object.freeze({ directory: root, entries, bytes: String(bytes) });
}

export async function loadGatewayTrustConfig(file = DEFAULT_GATEWAY_TRUST_PATH, options = {}) {
  const resolved = await assertRootOwnedPathChain(file, {
    expectedUid: options.expectedUid ?? 0,
    mode: 0o600,
    type: 'file',
  });
  const loaded = await readTrustedJson(resolved, {
    expectedUid: options.expectedUid ?? 0,
    maximumBytes: 1024 * 1024,
  });
  const config = validateGatewayTrustConfig(loaded.document);
  return Object.freeze({ config, path: resolved, trustDigest: sha256Digest(config) });
}

function stateDigestPayload(state) {
  const { stateDigest, ...payload } = state;
  return payload;
}

function stateDigest(state) {
  return sha256Digest(stateDigestPayload(state));
}

function newGatewayState(trust) {
  const state = {
    apiVersion: API_VERSION,
    kind: 'NoshGatewayState',
    schemaVersion: SCHEMA_VERSION,
    audience: trust.audience,
    target: trust.target,
    targetBindingDigest: trust.targetBindingDigest,
    targetContextDigest: trust.targetContextDigest,
    capabilityDigest: trust.capabilityDigest,
    activeGrantSetDigest: trust.activeGrantSetDigest,
    status: 'bootstrap',
    currentLeafBundleDigest: null,
    currentGrantEnvelopeDigest: null,
    lastAppliedAt: null,
    liveStateDigest: null,
    liveVerification: null,
    quarantine: null,
    usedGrants: [],
    stateDigest: '',
  };
  state.stateDigest = stateDigest(state);
  return state;
}

export function validateGatewayState(input, trust) {
  exactKeys(input, [
    'activeGrantSetDigest',
    'apiVersion',
    'audience',
    'capabilityDigest',
    'currentGrantEnvelopeDigest',
    'currentLeafBundleDigest',
    'kind',
    'lastAppliedAt',
    'liveStateDigest',
    'liveVerification',
    'quarantine',
    'schemaVersion',
    'stateDigest',
    'status',
    'target',
    'targetBindingDigest',
    'targetContextDigest',
    'usedGrants',
  ], 'gateway state');
  if (
    input.apiVersion !== API_VERSION
    || input.kind !== 'NoshGatewayState'
    || input.schemaVersion !== SCHEMA_VERSION
  ) throw new TypeError('gateway state header is unsupported');
  for (const [field, expected] of Object.entries({
    audience: trust.audience,
    target: trust.target,
    targetBindingDigest: trust.targetBindingDigest,
    targetContextDigest: trust.targetContextDigest,
    capabilityDigest: trust.capabilityDigest,
  })) {
    if (input[field] !== expected) throw new Error(`gateway state ${field} does not match trust`);
  }
  digest(input.activeGrantSetDigest, 'gateway state activeGrantSetDigest');
  if (!['bootstrap', 'active', 'quarantine-retained'].includes(input.status)) {
    throw new TypeError('gateway state status is unsupported');
  }
  for (const field of ['currentLeafBundleDigest', 'currentGrantEnvelopeDigest']) {
    if (input[field] !== null) digest(input[field], `gateway state ${field}`);
  }
  if (input.lastAppliedAt !== null && !Number.isFinite(Date.parse(input.lastAppliedAt))) {
    throw new TypeError('gateway state lastAppliedAt is invalid');
  }
  if (input.liveStateDigest !== null) {
    digest(input.liveStateDigest, 'gateway state liveStateDigest');
  }
  if (input.liveVerification !== null) {
    if (input.target === 'guard-nftables') {
      exactKeys(
        input.liveVerification,
        ['backend', 'dnsmasqConfigDigest'],
        'gateway state liveVerification',
      );
      if (input.liveVerification.backend !== 'guard-nftables') {
        throw new TypeError('gateway state liveVerification backend is invalid');
      }
    } else {
      exactKeys(
        input.liveVerification,
        ['backend', 'dnsmasqConfigDigest', 'verifyPlan'],
        'gateway state liveVerification',
      );
      if (input.liveVerification.backend !== 'gateway-iptables') {
        throw new TypeError('gateway state liveVerification backend is invalid');
      }
      validateIptablesVerifyPlan(input.liveVerification.verifyPlan);
    }
    digest(
      input.liveVerification.dnsmasqConfigDigest,
      'gateway state liveVerification dnsmasqConfigDigest',
    );
  }
  if (input.quarantine !== null) {
    exactKeys(input.quarantine, [
      'backend', 'id', 'installedAt', 'sourceIpv4',
    ], 'gateway state quarantine');
    if (input.quarantine.backend !== input.target) {
      throw new TypeError('gateway state quarantine backend is invalid');
    }
    boundedString(input.quarantine.id, 'gateway state quarantine ID', 64);
    if (net.isIP(input.quarantine.sourceIpv4) !== 4) {
      throw new TypeError('gateway state quarantine source must be IPv4');
    }
    if (!Number.isFinite(Date.parse(input.quarantine.installedAt))) {
      throw new TypeError('gateway state quarantine timestamp is invalid');
    }
  }
  if ((input.status === 'quarantine-retained') !== (input.quarantine !== null)) {
    throw new TypeError('gateway state quarantine marker disagrees with status');
  }
  if (input.status === 'bootstrap' && (
    input.activeGrantSetDigest !== trust.activeGrantSetDigest
    || input.currentLeafBundleDigest !== null
    || input.currentGrantEnvelopeDigest !== null
    || input.lastAppliedAt !== null
    || input.liveStateDigest !== null
    || input.liveVerification !== null
  )) throw new TypeError('gateway bootstrap state contains activated policy state');
  if (input.status === 'active' && (
    input.currentLeafBundleDigest === null
    || input.currentGrantEnvelopeDigest === null
    || input.lastAppliedAt === null
    || input.liveStateDigest === null
    || input.liveVerification === null
  )) throw new TypeError('active gateway state is missing its activation identity');
  if (!Array.isArray(input.usedGrants) || input.usedGrants.length > MAX_USED_GRANTS) {
    throw new TypeError('gateway state used grant log is invalid');
  }
  const nonces = new Set();
  for (const [index, entry] of input.usedGrants.entries()) {
    exactKeys(entry, [
      'expiresAt', 'grantEnvelopeDigest', 'nonce',
    ], `gateway state usedGrants[${index}]`);
    boundedString(entry.nonce, 'used grant nonce', 128);
    digest(entry.grantEnvelopeDigest, 'used grant envelope digest');
    if (!Number.isFinite(Date.parse(entry.expiresAt))) {
      throw new TypeError('used grant expiry is invalid');
    }
    if (nonces.has(entry.nonce)) throw new TypeError('gateway state contains a duplicate nonce');
    nonces.add(entry.nonce);
  }
  digest(input.stateDigest, 'gateway state digest');
  if (input.stateDigest !== stateDigest(input)) {
    throw new Error('gateway state digest does not match its content');
  }
  return input;
}

export async function readGatewayState(trust, options = {}) {
  const statePath = path.join(trust.paths.stateDirectory, GATEWAY_STATE_NAME);
  try {
    await assertRootOwnedPathChain(trust.paths.stateDirectory, {
      expectedUid: options.expectedUid ?? 0,
      type: 'directory',
    });
    const loaded = await readTrustedJson(statePath, {
      expectedUid: options.expectedUid ?? 0,
      maximumBytes: 4 * 1024 * 1024,
    });
    validateGatewayState(loaded.document, trust);
    return loaded.document;
  } catch (error) {
    if (error.code !== 'ENOENT') throw error;
    return newGatewayState(trust);
  }
}

function trustedKeys(entries, role, audience) {
  return entries.map((entry) => ({
    keyId: entry.keyId,
    publicKeyPem: entry.publicKeyPem,
    roles: [role],
    audiences: [audience],
  }));
}

function assertReviewBindings(statement, policy) {
  const bindings = {
    graphDigest: policy.policyIR.graphDigest,
    proposalSetDigest: policy.policyIR.proposalSetDigest,
    decisionSetDigest: policy.policyIR.decisionSetDigest,
    policyIrDigest: policy.policyIR.contentDigest,
    targetReviewSetDigest: policy.targetReviewSet.contentDigest,
    scopeDigest: policy.policyIR.scope.scopeDigest,
    confirmationDigest: sha256Digest(policy.targetReviewSet.contentDigest),
  };
  for (const [name, expected] of Object.entries(bindings)) {
    if (statement[name] !== expected) {
      throw new Error(`review approval ${name} does not bind the policy leaf`);
    }
  }
}

function assertKnownProjection(policy, trust) {
  const backend = BACKENDS[trust.target];
  const projection = policy.targetReviewSet.projections[0];
  const compiler = projection?.compiler;
  if (
    policy.targetReviewSet.projections.length !== 1
    || !policy.leaf.activationEligible
    || !projection?.activationEligible
    || !policy.projection.activationEligible
  ) throw new Error('policy leaf is not activation eligible');
  if (
    policy.leaf.target !== trust.target
    || projection.target !== trust.target
    || policy.projection.target !== trust.target
  ) throw new Error('policy leaf target does not match gateway trust');
  if (
    policy.leaf.targetContextDigest !== trust.targetContextDigest
    || projection.targetContextDigest !== trust.targetContextDigest
    || policy.projection.targetContextDigest !== trust.targetContextDigest
  ) throw new Error('policy leaf target context does not match gateway trust');
  if (
    policy.leaf.capabilityDigest !== trust.capabilityDigest
    || policy.projection.capabilityDigest !== trust.capabilityDigest
  ) throw new Error('policy leaf capability set does not match gateway trust');
  if (
    compiler?.id !== backend.compiler
    || compiler.version !== '1'
    || compiler.digest !== sha256Digest({ id: backend.compiler, version: '1' })
  ) throw new Error('policy leaf compiler identity is unsupported');
  const rendered = policy.leaf.artifacts
    .filter((entry) => entry.path.startsWith('rendered/'))
    .map((entry) => entry.path.slice('rendered/'.length))
    .sort();
  if (
    rendered.length !== backend.rendered.length
    || rendered.some((name, index) => name !== backend.rendered[index])
  ) throw new Error('policy leaf rendered artifact inventory is unsupported');
}

export function verifyGatewayActivation(input) {
  const trust = validateGatewayTrustConfig(input.trust);
  const state = input.state || newGatewayState(trust);
  validateGatewayState(state, trust);
  if (!ACTIVE_STATE_STATUSES.has(state.status)) {
    throw new Error('gateway retains a quarantine from a failed apply');
  }
  const policy = plainObject(input.policy, 'verified policy leaf');
  assertKnownProjection(policy, trust);
  const approval = verifyDsseEnvelope(input.approvalEnvelope, {
    payloadType: REVIEW_APPROVAL_PAYLOAD_TYPE,
    trustedKeys: trustedKeys(trust.reviewKeys, 'review-approval', trust.audience),
    role: 'review-approval',
    audience: trust.audience,
  });
  validateReviewApprovalStatement(approval.statement, {
    audience: trust.audience,
  });
  assertReviewBindings(approval.statement, policy);
  const grant = verifyDsseEnvelope(input.grantEnvelope, {
    payloadType: GATEWAY_GRANT_PAYLOAD_TYPE,
    trustedKeys: trustedKeys(trust.deploymentKeys, 'gateway-deployment', trust.audience),
    role: 'gateway-deployment',
    audience: trust.audience,
  });
  validateGatewayGrantStatement(grant.statement, {
    now: input.now,
    audience: trust.audience,
    target: trust.target,
  });
  const verificationTime = input.now instanceof Date
    ? input.now.getTime()
    : Number(input.now ?? Date.now());
  if (Date.parse(approval.statement.issuedAt) > verificationTime) {
    throw new Error('review approval is future-dated');
  }
  if (Date.parse(grant.statement.issuedAt) < Date.parse(approval.statement.issuedAt)) {
    throw new Error('gateway grant predates its review approval');
  }
  const grantBindings = {
    leafBundleDigest: policy.leaf.bundleDigest,
    approvalEnvelopeDigest: approval.envelopeDigest,
    targetBindingDigest: trust.targetBindingDigest,
    capabilityDigest: trust.capabilityDigest,
    activeGrantSetDigest: state.activeGrantSetDigest,
    renderedArtifactsDigest: policy.projection.artifactsDigest,
  };
  for (const [name, expected] of Object.entries(grantBindings)) {
    if (grant.statement[name] !== expected) {
      throw new Error(`gateway grant ${name} does not bind the active policy and gateway`);
    }
  }
  if (state.usedGrants.some((entry) => entry.nonce === grant.statement.nonce)) {
    throw new Error('gateway grant nonce was already applied');
  }
  return Object.freeze({ policy, trust, state, approval, grant });
}

export function createCommandRunner(options = {}) {
  const spawnImpl = options.spawnImpl || spawn;
  const maximumOutputBytes = options.maximumOutputBytes || MAX_COMMAND_OUTPUT_BYTES;
  const defaultTimeoutMs = options.timeoutMs || 30_000;
  return async function runCommand(file, args = [], commandOptions = {}) {
    absolutePath(file, 'command path', { executable: true });
    if (options.checkExecutable !== false) {
      await assertTrustedExecutable(file, options.expectedUid ?? 0);
    }
    if (
      !Array.isArray(args)
      || args.some((entry) => typeof entry !== 'string' || !SAFE_COMMAND_ARGUMENT.test(entry))
    ) throw new TypeError('command arguments must be NUL-free strings');
    const input = commandOptions.input == null
      ? null
      : Buffer.from(commandOptions.input);
    if (input && input.length > 128 * 1024 * 1024) {
      throw new TypeError('command input exceeds the byte limit');
    }
    const timeoutMs = commandOptions.timeoutMs || defaultTimeoutMs;
    const allowedExitCodes = commandOptions.allowedExitCodes || [0];
    return await new Promise((resolve, reject) => {
      const child = spawnImpl(file, args, {
        shell: false,
        windowsHide: true,
        stdio: ['pipe', 'pipe', 'pipe'],
        env: {
          LANG: 'C',
          LC_ALL: 'C',
          PATH: '/usr/sbin:/usr/bin:/sbin:/bin',
        },
      });
      const stdout = [];
      const stderr = [];
      let bytes = 0;
      let settled = false;
      let timer;
      const finish = (error, result) => {
        if (settled) return;
        settled = true;
        if (timer) clearTimeout(timer);
        if (error) reject(error);
        else resolve(result);
      };
      const collect = (target) => (chunk) => {
        bytes += chunk.length;
        if (bytes > maximumOutputBytes) {
          child.kill('SIGKILL');
          finish(new Error(`command output exceeds the byte limit: ${file}`));
          return;
        }
        target.push(chunk);
      };
      child.stdout.on('data', collect(stdout));
      child.stderr.on('data', collect(stderr));
      child.on('error', (error) => finish(error));
      child.on('close', (code, signal) => {
        const result = {
          file,
          args: [...args],
          code,
          signal,
          stdout: Buffer.concat(stdout).toString('utf8'),
          stderr: Buffer.concat(stderr).toString('utf8'),
        };
        if (!allowedExitCodes.includes(code)) {
          finish(new Error(
            `command failed (${code ?? signal}): ${file} ${args.join(' ')}`,
            { cause: result },
          ));
        } else {
          finish(null, result);
        }
      });
      timer = setTimeout(() => {
        child.kill('SIGKILL');
        finish(new Error(`command timed out: ${file}`));
      }, timeoutMs);
      if (input) child.stdin.end(input);
      else child.stdin.end();
    });
  };
}

async function readJsonArtifact(policy, name) {
  const loaded = await readTrustedJson(path.join(policy.directory, 'rendered', name), {
    maximumBytes: 16 * 1024 * 1024,
  });
  return loaded.document;
}

async function readTextArtifact(policy, name) {
  return await readTrustedFile(path.join(policy.directory, 'rendered', name), {
    maximumBytes: 128 * 1024 * 1024,
  });
}

function validateApplyPlan(plan, target) {
  exactKeys(
    plan,
    target === 'guard-nftables'
      ? [
          'backend',
          'failureState',
          'phases',
          'requiresExclusiveFirewallOwnership',
          'schemaVersion',
        ]
      : [
          'backend',
          'failureState',
          'globallyAtomic',
          'phases',
          'requiresExclusiveFirewallOwnership',
          'schemaVersion',
        ],
    'gateway apply plan',
  );
  const expectedBackend = target === 'guard-nftables'
    ? 'nftables-dnsmasq'
    : null;
  if (
    plan.schemaVersion !== 1
    || plan.failureState !== 'retain-source-quarantine'
    || (expectedBackend && plan.backend !== expectedBackend)
    || plan.requiresExclusiveFirewallOwnership !== true
    || (target === 'gateway-iptables' && (
      !/^iptables-(legacy|nft)-ipset-dnsmasq$/.test(plan.backend)
      || plan.globallyAtomic !== false
      || plan.requiresExclusiveFirewallOwnership !== true
    ))
    || !Array.isArray(plan.phases)
    || plan.phases.length < 5
    || plan.phases.length > 16
    || !plan.phases.every((entry) => typeof entry === 'string')
  ) throw new Error('gateway apply plan is unsupported');
}

function validateIptablesVerifyPlan(verifyPlan, expectedBackend = null) {
  exactKeys(verifyPlan, [
    'backend',
    'expectedChain',
    'expectedFlowMark',
    'expectedHookComment',
    'expectedSets',
    'expectedSourceIpv4',
    'infrastructureCommentPrefix',
    'requireManagedDns',
    'schemaVersion',
  ], 'iptables verify plan');
  if (
    verifyPlan.schemaVersion !== 1
    || (expectedBackend !== null && verifyPlan.backend !== expectedBackend)
    || !/^iptables-(legacy|nft)-ipset-dnsmasq$/.test(verifyPlan.backend)
    || net.isIP(verifyPlan.expectedSourceIpv4) !== 4
    || !/^[A-Z0-9_]{1,28}$/.test(verifyPlan.expectedChain)
    || !/^0x[a-f0-9]{8}$/.test(verifyPlan.expectedFlowMark)
    || !/^nosh-gateway:[a-f0-9]{12}:hook$/.test(verifyPlan.expectedHookComment)
    || !/^nosh-gateway:[a-f0-9]{12}:infra$/.test(
      verifyPlan.infrastructureCommentPrefix,
    )
    || !Array.isArray(verifyPlan.expectedSets)
    || verifyPlan.expectedSets.length > 100_000
    || verifyPlan.expectedSets.some((name) => !/^[A-Za-z0-9_.:-]{1,31}$/.test(name))
    || new Set(verifyPlan.expectedSets).size !== verifyPlan.expectedSets.length
    || verifyPlan.expectedSets.some((name, index, values) => (
      index > 0 && values[index - 1].localeCompare(name) >= 0
    ))
    || typeof verifyPlan.requireManagedDns !== 'boolean'
  ) throw new Error('iptables verification plan is unsupported');
  return verifyPlan;
}

function validateIpSetRestore(content) {
  const names = new Set();
  for (const [index, rawLine] of content.toString('utf8').split('\n').entries()) {
    const line = rawLine.trim();
    if (!line) continue;
    const create = /^create ([A-Za-z0-9_.:-]{1,31}) hash:(ip|net) family inet(?: timeout [1-9][0-9]{0,8})? maxelem [1-9][0-9]{0,8} -exist$/.exec(line);
    const flush = /^flush ([A-Za-z0-9_.:-]{1,31})$/.exec(line);
    const add = /^add ([A-Za-z0-9_.:-]{1,31}) ([0-9.]+(?:\/[0-9]{1,2})?) -exist$/.exec(line);
    if (!create && !flush && !add) {
      throw new Error(`ipset restore contains an unsupported instruction on line ${index + 1}`);
    }
    if (create) names.add(create[1]);
    if (flush && !names.has(flush[1])) throw new Error('ipset restore flushes an undeclared set');
    if (add) {
      if (!names.has(add[1]) || net.isIP(add[2].split('/')[0]) !== 4) {
        throw new Error('ipset restore adds an invalid member or undeclared set');
      }
    }
  }
  return [...names].sort();
}

export function createNftReplacementTransaction(content, tableExists) {
  const rules = Buffer.isBuffer(content) ? content : Buffer.from(content);
  const text = rules.toString('utf8');
  if (!Buffer.from(text, 'utf8').equals(rules)) {
    throw new Error('nft artifact is not valid UTF-8');
  }
  const lines = text.split('\n');
  if (lines[0] !== 'table inet nosh_guard {') {
    throw new Error('nft artifact does not exclusively declare inet/nosh_guard');
  }
  let depth = 0;
  let closed = false;
  for (const [index, line] of lines.entries()) {
    if (/[^\t\x20-\x7e]/.test(line)) {
      throw new Error(`nft artifact contains unsupported text on line ${index + 1}`);
    }
    if (closed) {
      if (line !== '') {
        throw new Error('nft artifact contains content after inet/nosh_guard');
      }
      continue;
    }
    const structural = line.replace(/"(?:\\.|[^"\\])*"/g, '""');
    if (/\b(?:add|create|define|delete|destroy|flush|include|insert|redefine|rename|replace|reset|undefine)\b/.test(
      structural,
    )) {
      throw new Error(`nft artifact contains an unsupported operation on line ${index + 1}`);
    }
    depth += (structural.match(/\{/g) || []).length;
    depth -= (structural.match(/\}/g) || []).length;
    if (depth < 0) throw new Error('nft artifact has unbalanced braces');
    if (depth === 0) {
      if (line.trim() !== '}') {
        throw new Error('nft artifact does not end at the nosh_guard table boundary');
      }
      closed = true;
    }
  }
  if (!closed || depth !== 0) throw new Error('nft artifact has an incomplete table declaration');
  return tableExists
    ? Buffer.concat([Buffer.from('delete table inet nosh_guard\n'), rules])
    : rules;
}

async function loadBackendArtifacts(activation) {
  const { policy, trust } = activation;
  const applyPlan = await readJsonArtifact(policy, 'apply-plan.json');
  validateApplyPlan(applyPlan, trust.target);
  const dnsmasq = await readTextArtifact(policy, 'dnsmasq.conf');
  if (trust.target === 'guard-nftables') {
    const gatewayPolicy = await readJsonArtifact(policy, 'gateway-policy.json');
    if (net.isIP(gatewayPolicy.sourceIpv4) !== 4) {
      throw new Error('gateway policy does not bind a valid source IPv4 address');
    }
    return {
      applyPlan,
      sourceIpv4: gatewayPolicy.sourceIpv4,
      dnsmasq,
      nftables: await readTextArtifact(policy, 'nftables.nft'),
    };
  }
  const verifyPlan = await readJsonArtifact(policy, 'verify-plan.json');
  validateIptablesVerifyPlan(verifyPlan, applyPlan.backend);
  const ipset = await readTextArtifact(policy, 'ipset.restore');
  const parsedSets = validateIpSetRestore(ipset);
  if (jcsCanonicalize(parsedSets) !== jcsCanonicalize([...verifyPlan.expectedSets].sort())) {
    throw new Error('iptables verification plan does not bind the rendered ipsets');
  }
  return {
    applyPlan,
    verifyPlan,
    sourceIpv4: verifyPlan.expectedSourceIpv4,
    dnsmasq,
    ipset,
    iptables: await readTextArtifact(policy, 'iptables-restore.v4'),
  };
}

async function runSyntaxChecks(activation, artifacts, runner) {
  const { commands, services, target } = activation.trust;
  const results = [];
  results.push(await runner(commands.dnsmasq, [
    '--test',
    `--conf-file=${path.join(activation.policy.directory, 'rendered', 'dnsmasq.conf')}`,
  ]));
  if (target === 'guard-nftables') {
    const existing = await runner(commands.nft, [
      'list', 'table', 'inet', 'nosh_guard',
    ], { allowedExitCodes: [0, 1] });
    const transaction = createNftReplacementTransaction(
      artifacts.nftables,
      existing.code === 0,
    );
    results.push(existing);
    results.push(await runner(commands.nft, ['--check', '-f', '-'], { input: transaction }));
  } else {
    results.push(await runner(commands.iptablesRestore, ['--test', '--noflush'], {
      input: createIsolationSafeIptablesRestore(artifacts.iptables, artifacts.verifyPlan),
    }));
    validateIpSetRestore(artifacts.ipset);
  }
  const service = await runner(commands.systemctl, [
    'show',
    '--property=LoadState',
    '--value',
    services.dnsmasq,
  ]);
  if (service.stdout.trim() !== 'loaded') {
    throw new Error('configured managed DNS service is not loaded');
  }
  results.push(service);
  return results;
}

async function optionalConfiguredDigest(file, expectedUid = 0) {
  try {
    const content = await readTrustedFile(file, {
      expectedUid,
      allowGroupRead: true,
      maximumBytes: 128 * 1024 * 1024,
    });
    return { exists: true, digest: sha256Digest(content), bytes: String(content.length) };
  } catch (error) {
    if (error.code === 'ENOENT') return { exists: false, digest: null, bytes: '0' };
    throw error;
  }
}

function removeDynamicNftElements(text) {
  const lines = text.split('\n');
  const output = [];
  for (let index = 0; index < lines.length; index += 1) {
    const match = /^(\s*)set [A-Za-z0-9_]+ \{$/.exec(lines[index]);
    if (!match) {
      output.push(lines[index]);
      continue;
    }
    const indentation = match[1].length;
    const block = [lines[index]];
    for (index += 1; index < lines.length; index += 1) {
      block.push(lines[index]);
      if (
        lines[index].trim() === '}'
        && lines[index].match(/^\s*/)[0].length === indentation
      ) break;
    }
    const dynamic = block.some((line) => (
      /flags\s+[^;]*timeout/.test(line)
    ));
    if (!dynamic) {
      output.push(...block);
      continue;
    }
    let skipping = false;
    let depth = 0;
    for (const line of block) {
      if (!skipping && /^\s*elements\s*=\s*\{/.test(line)) {
        skipping = true;
      }
      if (skipping) {
        depth += (line.match(/\{/g) || []).length;
        depth -= (line.match(/\}/g) || []).length;
        if (depth <= 0) skipping = false;
        continue;
      }
      output.push(line);
    }
  }
  return output.join('\n');
}

export function normalizeNftManagedRuleset(input) {
  return removeDynamicNftElements(String(input))
    .split('\n')
    .map((line) => line
      .replace(/\bcounter\s+packets\s+[0-9]+\s+bytes\s+[0-9]+\b/g, 'counter')
      .replace(/;/g, '')
      .trim()
      .replace(/\s+/g, ' '))
    .filter(Boolean)
    .join('\n');
}

function commandTokens(line) {
  const result = [];
  const expression = /"((?:\\.|[^"\\])*)"|'((?:\\.|[^'\\])*)'|\S+/g;
  for (const match of line.matchAll(expression)) {
    result.push((match[1] ?? match[2] ?? match[0]).replace(/\\([\\"])/g, '$1'));
  }
  return result;
}

function normalizeIptablesRule(line) {
  const tokens = commandTokens(line);
  const canonicalMark = (value) => {
    const [rawValue, rawMask = '0xffffffff'] = String(value || '').split('/');
    const normalizePart = (part) => {
      if (!/^0x[a-f0-9]+$/i.test(part)) return part.toLowerCase();
      return `0x${BigInt(part).toString(16)}`;
    };
    return `${normalizePart(rawValue)}/${normalizePart(rawMask)}`;
  };
  if (tokens[0] === '-I') {
    tokens[0] = '-A';
    if (/^[1-9][0-9]*$/.test(tokens[2] || '')) tokens.splice(2, 1);
  }
  for (let index = 0; index < tokens.length; index += 1) {
    if (['-s', '-d'].includes(tokens[index]) && /\/32$/.test(tokens[index + 1] || '')) {
      tokens[index + 1] = tokens[index + 1].slice(0, -3);
    }
    if (tokens[index] === '--set-xmark') tokens[index] = '--set-mark';
    if (['--set-mark', '--mark'].includes(tokens[index])) {
      tokens[index + 1] = canonicalMark(tokens[index + 1]);
    }
    if (['--ctstate', '--state'].includes(tokens[index])) {
      tokens[index + 1] = (tokens[index + 1] || '')
        .split(',')
        .map((entry) => entry.toUpperCase())
        .sort()
        .join(',');
    }
    if (tokens[index] === '--limit') {
      tokens[index + 1] = (tokens[index + 1] || '')
        .replace(/\/(?:second|sec)$/i, '/s')
        .replace(/\/(?:minute|min)$/i, '/m')
        .replace(/\/(?:hour|hr)$/i, '/h')
        .replace(/\/day$/i, '/d');
    }
    if (tokens[index] === '--limit-burst' && tokens[index + 1] === '5') {
      tokens.splice(index, 2);
      index -= 1;
    }
  }
  const protocolIndex = tokens.indexOf('-p');
  const protocol = protocolIndex >= 0 ? tokens[protocolIndex + 1] : null;
  for (let index = 0; index < tokens.length - 1; index += 1) {
    if (tokens[index] === '-m' && tokens[index + 1] === protocol) {
      tokens.splice(index, 2);
      index -= 1;
    }
  }
  return tokens.join(' ');
}

export function projectManagedIptables(input, verifyPlan) {
  const projection = {
    chainDeclared: false,
    chainRules: [],
    infrastructureRules: [],
    hookPosition: null,
    hookRules: [],
    returnRules: [],
    unexpectedOwnedRules: [],
  };
  const returnComment = verifyPlan.expectedHookComment.replace(/:hook$/, ':return');
  let table = null;
  let forwardPosition = 0;
  for (const line of String(input).split('\n')) {
    if (/^\*[A-Za-z0-9_]+$/.test(line)) {
      table = line.slice(1);
      continue;
    }
    if (line === 'COMMIT') {
      table = null;
      continue;
    }
    if (table === 'filter' && line.startsWith(`:${verifyPlan.expectedChain} `)) {
      projection.chainDeclared = true;
      continue;
    }
    if (!line.startsWith('-A ') && !line.startsWith('-I ')) continue;
    const normalized = normalizeIptablesRule(line);
    const tokens = commandTokens(normalized);
    const chain = tokens[1];
    const commentIndex = tokens.indexOf('--comment');
    const comment = commentIndex >= 0 ? tokens[commentIndex + 1] : null;
    if (table === 'filter' && chain === 'FORWARD') {
      if (comment === verifyPlan.expectedHookComment) {
        projection.hookPosition = forwardPosition;
        projection.hookRules.push(normalized);
      }
      if (comment === returnComment) projection.returnRules.push(normalized);
      forwardPosition += 1;
    }
    if (table === 'filter' && chain === verifyPlan.expectedChain) {
      projection.chainRules.push(normalized);
    }
    if (comment?.startsWith(`${verifyPlan.infrastructureCommentPrefix}:`)) {
      projection.infrastructureRules.push(`${table}:${normalized}`);
    } else if (
      comment?.startsWith('nosh-gateway:')
      && comment !== verifyPlan.expectedHookComment
      && comment !== returnComment
    ) {
      projection.unexpectedOwnedRules.push(`${table}:${normalized}`);
    }
  }
  projection.hookRules.sort();
  projection.returnRules.sort();
  projection.infrastructureRules.sort();
  projection.unexpectedOwnedRules.sort();
  return projection;
}

function ipsetDefinitions(input) {
  const definitions = new Map();
  for (const rawLine of String(input).split('\n')) {
    const tokens = commandTokens(rawLine);
    if (tokens[0] === 'create') {
      const name = tokens[1];
      const value = (option) => {
        const index = tokens.indexOf(option);
        return index < 0 ? null : tokens[index + 1];
      };
      definitions.set(name, {
        name,
        type: tokens[2],
        family: value('family'),
        timeout: value('timeout'),
        maxelem: value('maxelem'),
        members: [],
      });
    } else if (tokens[0] === 'add' && definitions.has(tokens[1])) {
      definitions.get(tokens[1]).members.push(tokens[2]);
    }
  }
  for (const definition of definitions.values()) definition.members.sort();
  return definitions;
}

export function verifyManagedIptablesLive(artifacts, iptablesSave, ipsetSave) {
  const expectedRules = projectManagedIptables(
    createIsolationSafeIptablesRestore(artifacts.iptables, artifacts.verifyPlan)
      .toString('utf8'),
    artifacts.verifyPlan,
  );
  // The source hook is inserted at the head of FORWARD. This position is an
  // enforcement property, not presentation metadata.
  expectedRules.hookPosition = 0;
  const liveRules = projectManagedIptables(iptablesSave, artifacts.verifyPlan);
  if (jcsCanonicalize(liveRules) !== jcsCanonicalize(expectedRules)) {
    throw new Error('live iptables managed projection differs from the signed artifact');
  }
  const expectedSets = ipsetDefinitions(artifacts.ipset);
  const liveSets = ipsetDefinitions(ipsetSave);
  const setProjection = [];
  for (const name of artifacts.verifyPlan.expectedSets) {
    const expected = expectedSets.get(name);
    const live = liveSets.get(name);
    if (!expected || !live) throw new Error(`live ipset is missing: ${name}`);
    for (const field of ['type', 'family', 'timeout', 'maxelem']) {
      if (expected[field] !== live[field]) {
        throw new Error(`live ipset ${name} ${field} differs from the signed artifact`);
      }
    }
    if (expected.type === 'hash:net') {
      if (jcsCanonicalize(expected.members) !== jcsCanonicalize(live.members)) {
        throw new Error(`live static ipset ${name} members differ from the signed artifact`);
      }
    } else if (live.members.some((entry) => net.isIP(entry.split('/')[0]) !== 4)) {
      throw new Error(`live dynamic ipset ${name} contains a non-IPv4 member`);
    }
    setProjection.push({
      name,
      type: live.type,
      family: live.family,
      timeout: live.timeout,
      maxelem: live.maxelem,
      members: expected.type === 'hash:net' ? live.members : [],
    });
  }
  return {
    projection: { rules: liveRules, sets: setProjection },
    digest: sha256Digest({ rules: liveRules, sets: setProjection }),
  };
}

function projectCurrentManagedIptables(
  verifyPlan,
  iptablesSave,
  ipsetSave,
  expectedSetDefinitions = null,
) {
  const rules = projectManagedIptables(iptablesSave, verifyPlan);
  const liveSets = ipsetDefinitions(ipsetSave);
  const sets = verifyPlan.expectedSets.map((name) => {
    const expected = expectedSetDefinitions?.get(name);
    const live = liveSets.get(name);
    if (!live) return { name, missing: true };
    return {
      name,
      type: live.type,
      family: live.family,
      timeout: live.timeout,
      maxelem: live.maxelem,
      members: (expected?.type || live.type) === 'hash:net' ? live.members : [],
    };
  });
  return { rules, sets };
}

function quarantineIdsFromIptablesSave(input) {
  const ids = new Set();
  for (const match of String(input).matchAll(
    /--comment\s+"?(ngq_[a-f0-9]{12})-(?:src|dst)"?/g,
  )) ids.add(match[1]);
  return [...ids].sort();
}

function untrackedQuarantines(ids, state) {
  const tracked = state.quarantine?.id || null;
  return ids.filter((id) => id !== tracked);
}

export async function readGatewayLiveState(
  subject,
  runner,
  artifacts = null,
  options = {},
) {
  const { trust, state } = subject;
  if (trust.target === 'guard-nftables') {
    const [table, tables] = await Promise.all([
      runner(trust.commands.nft, [
        '--stateless', 'list', 'table', 'inet', 'nosh_guard',
      ], { allowedExitCodes: [0, 1] }),
      runner(trust.commands.nft, ['list', 'tables']),
    ]);
    const quarantines = [...tables.stdout.matchAll(
      /^table inet (ngq_[a-f0-9]{12})$/gm,
    )].map((match) => match[1]).sort();
    const normalized = table.code === 0
      ? normalizeNftManagedRuleset(table.stdout)
      : null;
    const matchesExpected = artifacts
      ? normalized === normalizeNftManagedRuleset(artifacts.nftables)
      : null;
    if (artifacts && !matchesExpected && options.requireMatch === true) {
      throw new Error('live nftables managed table differs from the signed artifact');
    }
    const liveDigest = sha256Digest({ present: table.code === 0, ruleset: normalized });
    const matchesRecorded = state.liveStateDigest === null
      ? null
      : state.liveStateDigest === liveDigest;
    return {
      digest: liveDigest,
      present: table.code === 0,
      matchesExpected: artifacts ? matchesExpected : matchesRecorded,
      quarantines,
      untrackedQuarantines: untrackedQuarantines(quarantines, state),
      trackedQuarantineMissing: state.quarantine !== null
        && !quarantines.includes(state.quarantine.id),
      matchesRecorded,
    };
  }
  const [iptables, ipset] = await Promise.all([
    runner(trust.commands.iptablesSave, []),
    runner(trust.commands.ipset, ['save']),
  ]);
  const quarantines = quarantineIdsFromIptablesSave(iptables.stdout);
  let verified;
  let matchesExpected = null;
  let verificationError = null;
  if (artifacts) {
    try {
      verified = verifyManagedIptablesLive(artifacts, iptables.stdout, ipset.stdout);
      matchesExpected = true;
    } catch (error) {
      if (options.requireMatch === true) throw error;
      const projection = projectCurrentManagedIptables(
        artifacts.verifyPlan,
        iptables.stdout,
        ipset.stdout,
        ipsetDefinitions(artifacts.ipset),
      );
      verified = { digest: sha256Digest(projection), projection };
      matchesExpected = false;
      verificationError = error.message;
    }
  } else if (options.verifyPlan) {
    validateIptablesVerifyPlan(options.verifyPlan);
    const projection = projectCurrentManagedIptables(
      options.verifyPlan,
      iptables.stdout,
      ipset.stdout,
    );
    verified = { digest: sha256Digest(projection), projection };
  } else {
    verified = { digest: sha256Digest({
        iptables: iptables.stdout.split('\n').filter((line) => !line.startsWith('#')).join('\n'),
        setNames: [...ipsetDefinitions(ipset.stdout).keys()].sort(),
      }) };
  }
  const selectedVerifyPlan = artifacts?.verifyPlan || options.verifyPlan || null;
  const projectedRules = selectedVerifyPlan
    ? projectManagedIptables(iptables.stdout, selectedVerifyPlan)
    : null;
  const matchesRecorded = state.liveStateDigest === null
    ? null
    : state.liveStateDigest === verified.digest;
  return {
    digest: verified.digest,
    present: projectedRules
      ? projectedRules.chainDeclared || projectedRules.hookRules.length > 0
      : true,
    matchesExpected: artifacts ? matchesExpected : matchesRecorded,
    ...(verificationError ? { verificationError } : {}),
    quarantines,
    untrackedQuarantines: untrackedQuarantines(quarantines, state),
    trackedQuarantineMissing: state.quarantine !== null
      && !quarantines.includes(state.quarantine.id),
    matchesRecorded,
  };
}

export function evaluateGatewayRuntimeStatus(
  state,
  firewallLive,
  dnsmasqConfig,
  dnsmasqService,
) {
  const expectedDnsmasqDigest = state.liveVerification?.dnsmasqConfigDigest || null;
  const dnsmasqMatchesExpected = expectedDnsmasqDigest === null
    ? null
    : dnsmasqConfig.exists === true
      && dnsmasqConfig.digest === expectedDnsmasqDigest;
  const serviceActive = dnsmasqService.code === 0;
  const firewallMatchesExpected = firewallLive.matchesExpected;
  return Object.freeze({
    ...firewallLive,
    firewallMatchesExpected,
    dnsmasqConfig: Object.freeze({
      path: dnsmasqConfig.path,
      exists: dnsmasqConfig.exists,
      expectedDigest: expectedDnsmasqDigest,
      currentDigest: dnsmasqConfig.digest,
      matchesExpected: dnsmasqMatchesExpected,
    }),
    dnsmasqService: Object.freeze({
      unit: dnsmasqService.unit,
      active: serviceActive,
      exitCode: dnsmasqService.code,
    }),
    matchesExpected: state.status === 'active'
      ? firewallMatchesExpected === true
        && dnsmasqMatchesExpected === true
        && serviceActive
      : firewallMatchesExpected,
  });
}

export async function createGatewayDiff(activation, options = {}) {
  const runner = options.runner || createCommandRunner();
  const artifacts = await loadBackendArtifacts(activation);
  const syntax = await runSyntaxChecks(activation, artifacts, runner);
  const expected = activation.trust.target === 'guard-nftables'
    ? {
        dnsmasqConfig: artifacts.dnsmasq,
        nftablesConfig: artifacts.nftables,
      }
    : {
        dnsmasqConfig: artifacts.dnsmasq,
        ipsetRestoreConfig: artifacts.ipset,
        iptablesRestoreConfig: artifacts.iptables,
      };
  const configs = [];
  for (const [name, content] of Object.entries(expected)) {
    const current = await optionalConfiguredDigest(
      activation.trust.paths[name],
      options.expectedUid ?? 0,
    );
    const expectedDigest = sha256Digest(content);
    configs.push({
      name,
      path: activation.trust.paths[name],
      expectedDigest,
      currentDigest: current.digest,
      changed: current.digest !== expectedDigest,
    });
  }
  const live = await readGatewayLiveState(activation, runner, artifacts);
  const liveChanged = live.matchesExpected !== true
    || activation.state.liveStateDigest !== live.digest;
  return Object.freeze({
    apiVersion: API_VERSION,
    kind: 'NoshGatewayDiff',
    schemaVersion: SCHEMA_VERSION,
    audience: activation.trust.audience,
    target: activation.trust.target,
    leafBundleDigest: activation.policy.leaf.bundleDigest,
    grantEnvelopeDigest: activation.grant.envelopeDigest,
    activeGrantSetDigest: activation.state.activeGrantSetDigest,
    sourceIpv4: artifacts.sourceIpv4,
    syntaxChecks: syntax.map((entry) => ({
      command: entry.file,
      args: entry.args,
      exitCode: entry.code,
    })),
    configs,
    live,
    blocking: live.untrackedQuarantines.length > 0,
    blockingReasons: live.untrackedQuarantines.map(
      (id) => `untracked managed source quarantine ${id}`,
    ),
    changed: configs.some((entry) => entry.changed)
      || activation.state.currentLeafBundleDigest !== activation.policy.leaf.bundleDigest
      || liveChanged
      || live.untrackedQuarantines.length > 0,
  });
}

async function syncDirectory(directory) {
  const handle = await fs.open(
    directory,
    fsConstants.O_RDONLY | (fsConstants.O_DIRECTORY || 0) | (fsConstants.O_NOFOLLOW || 0),
  );
  try {
    await handle.sync();
  } finally {
    await handle.close();
  }
}

async function ensureRootDirectory(directory, mode = 0o700, expectedUid = 0) {
  await assertRootOwnedPathChain(path.dirname(directory), {
    expectedUid,
    type: 'directory',
  });
  try {
    await fs.mkdir(directory, { mode });
  } catch (error) {
    if (error.code !== 'EEXIST') throw error;
  }
  const stat = await fs.lstat(directory);
  if (
    !stat.isDirectory()
    || stat.isSymbolicLink()
    || stat.uid !== expectedUid
    || (stat.mode & 0o777) !== mode
  ) throw new Error(`gateway directory is not root-owned with mode ${mode.toString(8)}: ${directory}`);
}

async function atomicWrite(file, content, options = {}) {
  const target = path.resolve(file);
  const parent = path.dirname(target);
  const expectedUid = options.expectedUid ?? 0;
  await assertRootOwnedPathChain(parent, { expectedUid, type: 'directory' });
  const parentStat = await fs.lstat(parent);
  if (
    !parentStat.isDirectory()
    || parentStat.isSymbolicLink()
    || parentStat.uid !== expectedUid
    || (parentStat.mode & 0o022) !== 0
  ) throw new Error(`gateway output parent is unsafe: ${parent}`);
  try {
    const existing = await fs.lstat(target);
    if (
      !existing.isFile()
      || existing.isSymbolicLink()
      || existing.uid !== expectedUid
      || existing.nlink !== 1
      || (existing.mode & 0o022) !== 0
    ) throw new Error(`gateway output target is unsafe: ${target}`);
  } catch (error) {
    if (error.code !== 'ENOENT') throw error;
  }
  const temporary = path.join(
    parent,
    `.${path.basename(target)}.${process.pid}.${Date.now().toString(36)}.tmp`,
  );
  const handle = await fs.open(
    temporary,
    fsConstants.O_WRONLY
      | fsConstants.O_CREAT
      | fsConstants.O_EXCL
      | (fsConstants.O_NOFOLLOW || 0),
    options.mode ?? 0o600,
  );
  try {
    await handle.writeFile(content);
    await handle.sync();
    await handle.chmod(options.mode ?? 0o600);
  } catch (error) {
    await handle.close().catch(() => {});
    await fs.unlink(temporary).catch(() => {});
    throw error;
  }
  await handle.close();
  try {
    await fs.rename(temporary, target);
    await syncDirectory(parent);
  } catch (error) {
    await fs.unlink(temporary).catch(() => {});
    throw error;
  }
}

async function writeState(trust, state, options = {}) {
  const next = { ...state, stateDigest: '' };
  next.stateDigest = stateDigest(next);
  validateGatewayState(next, trust);
  await atomicWrite(
    path.join(trust.paths.stateDirectory, GATEWAY_STATE_NAME),
    `${jcsCanonicalize(next)}\n`,
    { mode: 0o600, expectedUid: options.expectedUid ?? 0 },
  );
  return next;
}

function quarantineId(activation) {
  return `ngq_${activation.policy.leaf.bundleDigest.slice(7, 19)}`;
}

function nftQuarantine(id, sourceIpv4) {
  return [
    `table inet ${id} {`,
    '  chain forward {',
    '    type filter hook forward priority -310; policy accept;',
    `    ip saddr ${sourceIpv4} counter drop`,
    `    ip daddr ${sourceIpv4} counter drop`,
    '  }',
    '}',
    '',
  ].join('\n');
}

function iptablesQuarantine(id, sourceIpv4, remove = false) {
  const operation = remove ? '-D' : '-I';
  return [
    '*raw',
    `${operation} PREROUTING -s ${sourceIpv4} -m comment --comment ${id}-src -j DROP`,
    `${operation} PREROUTING -d ${sourceIpv4} -m comment --comment ${id}-dst -j DROP`,
    'COMMIT',
    '',
  ].join('\n');
}

async function installQuarantine(activation, artifacts, runner) {
  const id = quarantineId(activation);
  if (activation.trust.target === 'guard-nftables') {
    const content = nftQuarantine(id, artifacts.sourceIpv4);
    await runner(activation.trust.commands.nft, ['--check', '-f', '-'], { input: content });
    await runner(activation.trust.commands.nft, ['-f', '-'], { input: content });
  } else {
    const content = iptablesQuarantine(id, artifacts.sourceIpv4);
    await runner(activation.trust.commands.iptablesRestore, ['--test', '--noflush'], {
      input: content,
    });
    await runner(activation.trust.commands.iptablesRestore, ['--noflush'], { input: content });
  }
  return {
    backend: activation.trust.target,
    id,
    sourceIpv4: artifacts.sourceIpv4,
    installedAt: new Date().toISOString(),
  };
}

async function removeQuarantine(activation, quarantine, runner) {
  if (activation.trust.target === 'guard-nftables') {
    await runner(activation.trust.commands.nft, [
      'delete', 'table', 'inet', quarantine.id,
    ]);
  } else {
    const content = iptablesQuarantine(quarantine.id, quarantine.sourceIpv4, true);
    await runner(activation.trust.commands.iptablesRestore, ['--test', '--noflush'], {
      input: content,
    });
    await runner(activation.trust.commands.iptablesRestore, ['--noflush'], { input: content });
  }
}

async function purgeConntrack(activation, sourceIpv4, runner) {
  for (const direction of ['-s', '-d']) {
    await runner(activation.trust.commands.conntrack, [
      '-D', '-f', 'ipv4', direction, sourceIpv4,
    ], { allowedExitCodes: [0, 1] });
  }
}

function validateIsolationSafeIptablesArtifact(text, verifyPlan) {
  const tables = [];
  const infrastructure = new Map();
  let table = null;
  let chainDeclarations = 0;
  let hookRules = 0;
  let returnRules = 0;
  const returnComment = verifyPlan.expectedHookComment.replace(/:hook$/, ':return');
  for (const [index, line] of text.split('\n').entries()) {
    if (/[^\t\x20-\x7e]/.test(line)) {
      throw new Error(`iptables artifact contains unsupported text on line ${index + 1}`);
    }
    if (!line) continue;
    const tableMatch = /^\*(mangle|filter|nat)$/.exec(line);
    if (tableMatch) {
      if (table !== null) throw new Error('iptables artifact nests table declarations');
      table = tableMatch[1];
      tables.push(table);
      continue;
    }
    if (line === 'COMMIT') {
      if (table === null) throw new Error('iptables artifact has COMMIT outside a table');
      table = null;
      continue;
    }
    if (table === null) throw new Error('iptables artifact has content outside a table');
    if (line.startsWith(':')) {
      if (table !== 'filter' || line !== `:${verifyPlan.expectedChain} - [0:0]`) {
        throw new Error('iptables artifact declares an unsupported chain');
      }
      chainDeclarations += 1;
      continue;
    }
    if (!line.startsWith('-A ')) {
      throw new Error('iptables artifact contains a non-append operation');
    }
    const normalized = normalizeIptablesRule(line);
    const tokens = commandTokens(normalized);
    const chain = tokens[1];
    const commentIndex = tokens.indexOf('--comment');
    const comment = commentIndex >= 0 ? tokens[commentIndex + 1] : null;
    if (table === 'filter' && chain === verifyPlan.expectedChain) continue;
    if (table === 'filter' && chain === 'FORWARD') {
      if (comment === verifyPlan.expectedHookComment) {
        const expected = normalizeIptablesRule(
          `-A FORWARD -s ${verifyPlan.expectedSourceIpv4} -m comment --comment "${comment}" -j ${verifyPlan.expectedChain}`,
        );
        if (normalized !== expected) throw new Error('iptables source hook shape is unsupported');
        hookRules += 1;
        continue;
      }
      if (comment === returnComment) {
        const expected = normalizeIptablesRule(
          `-A FORWARD -d ${verifyPlan.expectedSourceIpv4} -m conntrack --ctstate ESTABLISHED,RELATED -m connmark --mark ${verifyPlan.expectedFlowMark} -m comment --comment "${comment}" -j ACCEPT`,
        );
        if (normalized !== expected) throw new Error('iptables return rule shape is unsupported');
        returnRules += 1;
        continue;
      }
      throw new Error('iptables artifact contains an unmanaged FORWARD rule');
    }
    if (!comment?.startsWith(`${verifyPlan.infrastructureCommentPrefix}:`)) {
      throw new Error('iptables artifact contains a rule outside managed chains');
    }
    const suffix = comment.slice(verifyPlan.infrastructureCommentPrefix.length + 1);
    if (infrastructure.has(suffix)) {
      throw new Error(`iptables artifact duplicates managed infrastructure: ${suffix}`);
    }
    const destinationIndex = tokens.indexOf('-d');
    const protocolIndex = tokens.indexOf('-p');
    const outputIndex = tokens.indexOf('-o');
    let expected;
    if (/^dns-mark-(udp|tcp)$/.test(suffix)) {
      const protocol = suffix.endsWith('udp') ? 'udp' : 'tcp';
      const gateway = tokens[destinationIndex + 1];
      if (table !== 'mangle' || chain !== 'PREROUTING' || net.isIP(gateway) !== 4) {
        throw new Error('iptables DNS mark infrastructure shape is unsupported');
      }
      expected = `-A PREROUTING -s ${verifyPlan.expectedSourceIpv4} -d ${gateway} -p ${protocol} --dport 53 -m comment --comment "${comment}" -j CONNMARK --set-mark 0x1`;
    } else if (/^dns-input-(udp|tcp)$/.test(suffix)) {
      const protocol = suffix.endsWith('udp') ? 'udp' : 'tcp';
      const gateway = tokens[destinationIndex + 1];
      if (table !== 'filter' || chain !== 'INPUT' || net.isIP(gateway) !== 4) {
        throw new Error('iptables DNS input infrastructure shape is unsupported');
      }
      expected = `-A INPUT -s ${verifyPlan.expectedSourceIpv4} -d ${gateway} -p ${protocol} --dport 53 -m comment --comment "${comment}" -j ACCEPT`;
    } else if (suffix === 'masquerade') {
      const uplink = tokens[outputIndex + 1];
      if (
        table !== 'nat'
        || chain !== 'POSTROUTING'
        || !/^[A-Za-z0-9_.:-]{1,15}$/.test(uplink || '')
      ) throw new Error('iptables masquerade infrastructure shape is unsupported');
      expected = `-A POSTROUTING -s ${verifyPlan.expectedSourceIpv4} -o ${uplink} -m comment --comment "${comment}" -j MASQUERADE`;
    } else {
      throw new Error(`iptables artifact has unknown managed infrastructure: ${suffix}`);
    }
    if (normalized !== normalizeIptablesRule(expected)) {
      throw new Error(`iptables managed infrastructure differs from its required shape: ${suffix}`);
    }
    if (protocolIndex >= 0 && !['udp', 'tcp'].includes(tokens[protocolIndex + 1])) {
      throw new Error('iptables managed infrastructure uses an unsupported protocol');
    }
    infrastructure.set(suffix, tokens[destinationIndex + 1] || null);
  }
  if (table !== null) throw new Error('iptables artifact has an unterminated table');
  if (tables.join(',') !== 'mangle,filter,nat') {
    throw new Error('iptables artifact does not declare exactly the managed tables');
  }
  if (chainDeclarations !== 1 || hookRules !== 1 || returnRules !== 1) {
    throw new Error('iptables artifact has an incomplete managed chain boundary');
  }
  const requiredInfrastructure = [
    'dns-input-tcp',
    'dns-input-udp',
    'dns-mark-tcp',
    'dns-mark-udp',
    'masquerade',
  ];
  if (
    requiredInfrastructure.some((name) => !infrastructure.has(name))
    || new Set([
      infrastructure.get('dns-input-tcp'),
      infrastructure.get('dns-input-udp'),
      infrastructure.get('dns-mark-tcp'),
      infrastructure.get('dns-mark-udp'),
    ]).size !== 1
  ) throw new Error('iptables artifact has incomplete or inconsistent managed infrastructure');
}

export function createIsolationSafeIptablesRestore(content, verifyPlan) {
  const text = content.toString('utf8');
  if (!Buffer.from(text, 'utf8').equals(Buffer.from(content))) {
    throw new Error('iptables artifact is not valid UTF-8');
  }
  validateIsolationSafeIptablesArtifact(text, verifyPlan);
  if (
    /^(?:-F|-X|:INPUT |:OUTPUT |:FORWARD |:PREROUTING |:POSTROUTING )/m.test(text)
    || /^\*raw$/m.test(text)
  ) throw new Error('iptables artifact attempts to flush or replace host-owned firewall state');
  const hookPattern = new RegExp(
    `^-A FORWARD -s ${verifyPlan.expectedSourceIpv4.replaceAll('.', '\\.')} `
      + '-m comment --comment "nosh-gateway:[a-f0-9]{12}:hook" '
      + `-j ${verifyPlan.expectedChain}$`,
  );
  const hookLines = text.split('\n').filter((line) => hookPattern.test(line));
  if (hookLines.length !== 1) {
    throw new Error('iptables artifact does not contain exactly one managed source hook');
  }
  return Buffer.from(text.replace(
    hookLines[0],
    hookLines[0].replace(/^-A FORWARD /, '-I FORWARD 1 '),
  ), 'utf8');
}

function sourceTokenMatches(value, sourceIpv4) {
  return value === sourceIpv4 || value === `${sourceIpv4}/32`;
}

export function createIptablesGenerationCleanup(saveOutput, verifyPlan) {
  const lines = saveOutput.split('\n');
  const declared = new Set(lines.flatMap((line) => {
    const match = /^:(NG_[A-F0-9_]{1,25}) - /.exec(line);
    return match ? [match[1]] : [];
  }));
  const sourceChains = new Set();
  const deletions = new Map([
    ['filter', []],
    ['mangle', []],
    ['nat', []],
  ]);
  let table = null;
  for (const line of lines) {
    if (/^\*(filter|mangle|nat)$/.test(line)) {
      table = line.slice(1);
      continue;
    }
    if (line === 'COMMIT') {
      table = null;
      continue;
    }
    if (
      table
      && line.startsWith('-A ')
      && line.includes(
        `--comment "${verifyPlan.infrastructureCommentPrefix}:`,
      )
    ) {
      deletions.get(table).push(line.replace(/^-A /, '-D '));
      continue;
    }
    if (table !== 'filter' || !line.startsWith('-A FORWARD ')) continue;
    const tokens = line.split(' ');
    const sourceIndex = tokens.indexOf('-s');
    const destinationIndex = tokens.indexOf('-d');
    const jumpIndex = tokens.lastIndexOf('-j');
    const jump = jumpIndex >= 0 ? tokens[jumpIndex + 1] : null;
    if (
      sourceIndex >= 0
      && sourceTokenMatches(tokens[sourceIndex + 1], verifyPlan.expectedSourceIpv4)
      && typeof jump === 'string'
      && /^NG_[A-F0-9_]{1,25}$/.test(jump)
      && declared.has(jump)
      && /--comment "nosh-gateway:[a-f0-9]{12}:hook"/.test(line)
    ) {
      sourceChains.add(jump);
      deletions.get('filter').push(line.replace(/^-A /, '-D '));
      continue;
    }
    if (
      destinationIndex >= 0
      && sourceTokenMatches(tokens[destinationIndex + 1], verifyPlan.expectedSourceIpv4)
      && tokens.includes('--ctstate')
      && tokens.includes('--mark')
      && jump === 'ACCEPT'
      && /--comment "nosh-gateway:[a-f0-9]{12}:return"/.test(line)
    ) deletions.get('filter').push(line.replace(/^-A /, '-D '));
  }
  if (declared.has(verifyPlan.expectedChain)) sourceChains.add(verifyPlan.expectedChain);
  const chains = [...sourceChains].sort();
  if (![...deletions.values()].some((entries) => entries.length) && !chains.length) {
    return { transaction: null, obsoleteSetPrefixes: [] };
  }
  const transaction = ['mangle', 'filter', 'nat'].flatMap((name) => {
    const entries = deletions.get(name);
    const chainEntries = name === 'filter'
      ? chains.flatMap((chain) => [`-F ${chain}`, `-X ${chain}`])
      : [];
    return entries.length || chainEntries.length
      ? [`*${name}`, ...entries, ...chainEntries, 'COMMIT']
      : [];
  }).concat('').join('\n');
  const currentPrefix = verifyPlan.expectedChain.slice(3, 11).toLowerCase();
  return {
    transaction,
    obsoleteSetPrefixes: chains
      .map((chain) => chain.slice(3, 11).toLowerCase())
      .filter((prefix) => prefix !== currentPrefix),
  };
}

async function prepareIptablesGeneration(activation, artifacts, runner) {
  const saved = await runner(activation.trust.commands.iptablesSave, []);
  const cleanup = createIptablesGenerationCleanup(saved.stdout, artifacts.verifyPlan);
  if (cleanup.transaction) {
    await runner(activation.trust.commands.iptablesRestore, ['--test', '--noflush'], {
      input: cleanup.transaction,
    });
    await runner(activation.trust.commands.iptablesRestore, ['--noflush'], {
      input: cleanup.transaction,
    });
  }
  const savedSets = await runner(activation.trust.commands.ipset, ['save']);
  const obsoleteSets = savedSets.stdout.split('\n').flatMap((line) => {
    const match = /^create (ng_[a-f0-9]{8}_[a-f0-9]{12}) /.exec(line);
    if (!match) return [];
    return cleanup.obsoleteSetPrefixes.some((prefix) => match[1].startsWith(`ng_${prefix}_`))
      ? [match[1]]
      : [];
  });
  return [...new Set(obsoleteSets)].sort();
}

async function applyBackend(activation, artifacts, runner, options = {}) {
  const trust = activation.trust;
  await atomicWrite(trust.paths.dnsmasqConfig, artifacts.dnsmasq, {
    mode: 0o600,
    expectedUid: options.expectedUid ?? 0,
  });
  if (trust.target === 'guard-nftables') {
    await atomicWrite(trust.paths.nftablesConfig, artifacts.nftables, {
      mode: 0o600,
      expectedUid: options.expectedUid ?? 0,
    });
    const existing = await runner(trust.commands.nft, [
      'list', 'table', 'inet', 'nosh_guard',
    ], { allowedExitCodes: [0, 1] });
    const transaction = createNftReplacementTransaction(
      artifacts.nftables,
      existing.code === 0,
    );
    await runner(trust.commands.nft, ['--check', '-f', '-'], { input: transaction });
    await runner(trust.commands.nft, ['-f', '-'], { input: transaction });
  } else {
    await atomicWrite(trust.paths.ipsetRestoreConfig, artifacts.ipset, {
      mode: 0o600,
      expectedUid: options.expectedUid ?? 0,
    });
    await atomicWrite(trust.paths.iptablesRestoreConfig, artifacts.iptables, {
      mode: 0o600,
      expectedUid: options.expectedUid ?? 0,
    });
    const obsoleteSets = await prepareIptablesGeneration(activation, artifacts, runner);
    await runner(trust.commands.ipset, ['restore', '-exist'], { input: artifacts.ipset });
    const transaction = createIsolationSafeIptablesRestore(
      artifacts.iptables,
      artifacts.verifyPlan,
    );
    await runner(trust.commands.iptablesRestore, ['--test', '--noflush'], {
      input: transaction,
    });
    await runner(trust.commands.iptablesRestore, ['--noflush'], { input: transaction });
    artifacts.obsoleteSets = obsoleteSets;
  }
  await runner(trust.commands.systemctl, ['restart', trust.services.dnsmasq]);
  await purgeConntrack(activation, artifacts.sourceIpv4, runner);
  if (trust.target === 'guard-nftables') {
    await runner(trust.commands.nft, ['list', 'table', 'inet', 'nosh_guard']);
  } else {
    await runner(trust.commands.iptables, [
      '-C', 'FORWARD', '-s', artifacts.sourceIpv4,
      '-m', 'comment', '--comment', artifacts.verifyPlan.expectedHookComment,
      '-j', artifacts.verifyPlan.expectedChain,
    ]);
    for (const name of artifacts.verifyPlan.expectedSets) {
      await runner(trust.commands.ipset, ['list', name]);
    }
    for (const name of artifacts.obsoleteSets || []) {
      await runner(trust.commands.ipset, ['destroy', name]);
    }
  }
  await runner(trust.commands.systemctl, [
    'is-active', '--quiet', trust.services.dnsmasq,
  ]);
}

export function computeNextActiveGrantSetDigest(input) {
  return sha256Digest({
    previousActiveGrantSetDigest: digest(
      input.previousActiveGrantSetDigest,
      'previousActiveGrantSetDigest',
    ),
    grantEnvelopeDigest: digest(input.grantEnvelopeDigest, 'grantEnvelopeDigest'),
    leafBundleDigest: digest(input.leafBundleDigest, 'leafBundleDigest'),
    nonce: boundedString(input.nonce, 'gateway grant nonce', 128),
  });
}

function nextGrantSetDigest(activation) {
  return computeNextActiveGrantSetDigest({
    previousActiveGrantSetDigest: activation.state.activeGrantSetDigest,
    grantEnvelopeDigest: activation.grant.envelopeDigest,
    leafBundleDigest: activation.policy.leaf.bundleDigest,
    nonce: activation.grant.statement.nonce,
  });
}

function usedGrantLog(activation, now) {
  const current = activation.state.usedGrants.filter(
    (entry) => Date.parse(entry.expiresAt) > now,
  );
  current.push({
    nonce: activation.grant.statement.nonce,
    expiresAt: activation.grant.statement.expiresAt,
    grantEnvelopeDigest: activation.grant.envelopeDigest,
  });
  return current.slice(-MAX_USED_GRANTS);
}

async function writeReceipt(activation, state, diff, options = {}) {
  const receipt = {
    apiVersion: API_VERSION,
    kind: 'NoshGatewayApplyReceipt',
    schemaVersion: SCHEMA_VERSION,
    appliedAt: state.lastAppliedAt,
    audience: activation.trust.audience,
    target: activation.trust.target,
    targetBindingDigest: activation.trust.targetBindingDigest,
    targetContextDigest: activation.trust.targetContextDigest,
    capabilityDigest: activation.trust.capabilityDigest,
    leafBundleDigest: activation.policy.leaf.bundleDigest,
    approvalEnvelopeDigest: activation.approval.envelopeDigest,
    grantEnvelopeDigest: activation.grant.envelopeDigest,
    previousActiveGrantSetDigest: activation.state.activeGrantSetDigest,
    activeGrantSetDigest: state.activeGrantSetDigest,
    liveStateDigest: state.liveStateDigest,
    liveVerificationDigest: sha256Digest(state.liveVerification),
    stateDigest: state.stateDigest,
    configDigests: Object.fromEntries(diff.configs.map((entry) => [
      entry.name,
      entry.expectedDigest,
    ])),
  };
  const receiptDigest = sha256Digest(receipt);
  const receipts = path.join(activation.trust.paths.stateDirectory, 'receipts');
  await ensureRootDirectory(receipts, 0o700, options.expectedUid ?? 0);
  const file = path.join(receipts, `${receiptDigest.slice(7)}.json`);
  const handle = await fs.open(
    file,
    fsConstants.O_WRONLY
      | fsConstants.O_CREAT
      | fsConstants.O_EXCL
      | (fsConstants.O_NOFOLLOW || 0),
    0o600,
  );
  try {
    await handle.writeFile(`${jcsCanonicalize({ ...receipt, receiptDigest })}\n`);
    await handle.sync();
  } finally {
    await handle.close();
  }
  await syncDirectory(receipts);
  return { file, receipt: { ...receipt, receiptDigest } };
}

export async function applyGatewayActivation(activation, options = {}) {
  if (options.confirmed !== true) throw new Error('gateway apply requires explicit confirmation');
  const effectiveUid = options.effectiveUid
    ?? (typeof process.geteuid === 'function' ? process.geteuid() : null);
  if (effectiveUid !== 0) throw new Error('gateway apply must run as root');
  const expectedUid = options.expectedUid ?? 0;
  const runner = options.runner || createCommandRunner();
  const clock = () => (options.now instanceof Date
    ? options.now.getTime()
    : options.now == null
      ? Date.now()
      : Number(options.now));
  await ensureRootDirectory(activation.trust.paths.stateDirectory, 0o700, expectedUid);
  const lockPath = path.join(activation.trust.paths.stateDirectory, 'apply.lock');
  let lock;
  try {
    lock = await fs.open(
      lockPath,
      fsConstants.O_WRONLY
        | fsConstants.O_CREAT
        | fsConstants.O_EXCL
        | (fsConstants.O_NOFOLLOW || 0),
      0o600,
    );
    await lock.writeFile(`${process.pid}\n`);
    await lock.sync();
    const currentState = await readGatewayState(activation.trust, { expectedUid });
    if (currentState.stateDigest !== activation.state.stateDigest) {
      throw new Error('gateway state changed after grant verification');
    }
    validateGatewayGrantStatement(activation.grant.statement, {
      now: clock(),
      audience: activation.trust.audience,
      target: activation.trust.target,
    });
    const diff = await createGatewayDiff(activation, { runner, expectedUid });
    if (diff.blocking) {
      throw new Error(`gateway apply is blocked: ${diff.blockingReasons.join('; ')}`);
    }
    const artifacts = await loadBackendArtifacts(activation);
    const quarantine = await installQuarantine(activation, artifacts, runner);
    let quarantinePresent = true;
    let retainedState = {
      ...activation.state,
      status: 'quarantine-retained',
      quarantine,
      stateDigest: '',
    };
    try {
      retainedState = await writeState(activation.trust, retainedState, { expectedUid });
      await applyBackend(activation, artifacts, runner, { expectedUid });
      const now = clock();
      validateGatewayGrantStatement(activation.grant.statement, {
        now,
        audience: activation.trust.audience,
        target: activation.trust.target,
      });
      const verifiedLive = await readGatewayLiveState(
        { trust: activation.trust, state: retainedState },
        runner,
        artifacts,
        { requireMatch: true },
      );
      if (!verifiedLive.present || verifiedLive.untrackedQuarantines.length > 0) {
        throw new Error('gateway live verification found missing policy or an untracked quarantine');
      }
      const pending = await writeState(activation.trust, {
        ...retainedState,
        activeGrantSetDigest: nextGrantSetDigest(activation),
        currentLeafBundleDigest: activation.policy.leaf.bundleDigest,
        currentGrantEnvelopeDigest: activation.grant.envelopeDigest,
        lastAppliedAt: new Date(now).toISOString(),
        liveStateDigest: verifiedLive.digest,
        liveVerification: activation.trust.target === 'guard-nftables'
          ? {
              backend: 'guard-nftables',
              dnsmasqConfigDigest: sha256Digest(artifacts.dnsmasq),
            }
          : {
              backend: 'gateway-iptables',
              dnsmasqConfigDigest: sha256Digest(artifacts.dnsmasq),
              verifyPlan: artifacts.verifyPlan,
            },
        usedGrants: usedGrantLog(activation, now),
        stateDigest: '',
      }, { expectedUid });
      const activeCandidate = {
        ...pending,
        status: 'active',
        quarantine: null,
        stateDigest: '',
      };
      activeCandidate.stateDigest = stateDigest(activeCandidate);
      validateGatewayState(activeCandidate, activation.trust);
      await removeQuarantine(activation, quarantine, runner);
      quarantinePresent = false;
      const finalLive = await readGatewayLiveState(
        { trust: activation.trust, state: activeCandidate },
        runner,
        artifacts,
        { requireMatch: true },
      );
      if (
        !finalLive.present
        || finalLive.untrackedQuarantines.length > 0
        || finalLive.digest !== activeCandidate.liveStateDigest
      ) throw new Error('gateway quarantine removal or final live verification failed');
      const active = await writeState(
        activation.trust,
        activeCandidate,
        { expectedUid },
      );
      const receipt = await writeReceipt(
        activation,
        active,
        diff,
        { expectedUid },
      );
      return Object.freeze({ diff, state: active, ...receipt });
    } catch (error) {
      // The source quarantine is deliberately not removed on any error. A
      // best-effort state write makes the fail-closed condition discoverable;
      // failure to record it does not weaken the installed packet filter.
      let retainedQuarantine = quarantine;
      if (!quarantinePresent) {
        retainedQuarantine = await installQuarantine(activation, artifacts, runner)
          .catch(() => quarantine);
      }
      await writeState(activation.trust, {
        ...retainedState,
        status: 'quarantine-retained',
        quarantine: retainedQuarantine,
        stateDigest: '',
      }, { expectedUid }).catch(() => {});
      throw new Error('gateway apply failed with source quarantine retained', { cause: error });
    }
  } finally {
    if (lock) {
      await lock.close().catch(() => {});
      await fs.unlink(lockPath).catch(() => {});
      await syncDirectory(activation.trust.paths.stateDirectory).catch(() => {});
    }
  }
}

export async function loadGatewayActivation(input, options = {}) {
  const trustArtifact = await loadGatewayTrustConfig(
    input.trust || DEFAULT_GATEWAY_TRUST_PATH,
    { expectedUid: options.expectedUid ?? 0 },
  );
  const [policyPath, approvalPath, grantPath] = await Promise.all([
    assertRootOwnedPathChain(input.policy, {
      expectedUid: options.expectedUid ?? 0,
      type: 'directory',
    }),
    assertRootOwnedPathChain(input.approval, {
      expectedUid: options.expectedUid ?? 0,
      type: 'file',
      mode: 0o600,
    }),
    assertRootOwnedPathChain(input.grant, {
      expectedUid: options.expectedUid ?? 0,
      type: 'file',
      mode: 0o600,
    }),
  ]);
  await assertTrustedPolicyLeafTree(policyPath, {
    expectedUid: options.expectedUid ?? 0,
  });
  const [policy, approval, grant, state] = await Promise.all([
    readPolicyLeafArtifact(policyPath),
    readTrustedJson(approvalPath, {
      expectedUid: options.expectedUid ?? 0,
      allowGroupRead: true,
      maximumBytes: 16 * 1024 * 1024,
    }),
    readTrustedJson(grantPath, {
      expectedUid: options.expectedUid ?? 0,
      allowGroupRead: true,
      maximumBytes: 16 * 1024 * 1024,
    }),
    readGatewayState(trustArtifact.config, { expectedUid: options.expectedUid ?? 0 }),
  ]);
  return verifyGatewayActivation({
    policy,
    approvalEnvelope: approval.document,
    grantEnvelope: grant.document,
    trust: trustArtifact.config,
    state,
    now: options.now,
  });
}

export async function gatewayStatus(input = {}, options = {}) {
  const trustArtifact = await loadGatewayTrustConfig(
    input.trust || DEFAULT_GATEWAY_TRUST_PATH,
    { expectedUid: options.expectedUid ?? 0 },
  );
  const state = await readGatewayState(trustArtifact.config, {
    expectedUid: options.expectedUid ?? 0,
  });
  const runner = options.runner || createCommandRunner();
  const [firewallLive, currentDnsmasq, dnsmasqService] = await Promise.all([
    readGatewayLiveState({
      trust: trustArtifact.config,
      state,
    }, runner, null, {
      verifyPlan: state.liveVerification?.verifyPlan,
    }),
    optionalConfiguredDigest(
      trustArtifact.config.paths.dnsmasqConfig,
      options.expectedUid ?? 0,
    ),
    runner(trustArtifact.config.commands.systemctl, [
      'is-active', '--quiet', trustArtifact.config.services.dnsmasq,
    ], { allowedExitCodes: [0, 1, 2, 3, 4] }),
  ]);
  const live = evaluateGatewayRuntimeStatus(
    state,
    firewallLive,
    {
      ...currentDnsmasq,
      path: trustArtifact.config.paths.dnsmasqConfig,
    },
    {
      ...dnsmasqService,
      unit: trustArtifact.config.services.dnsmasq,
    },
  );
  let applyLocked = false;
  try {
    const lock = await fs.lstat(path.join(
      trustArtifact.config.paths.stateDirectory,
      'apply.lock',
    ));
    if (
      !lock.isFile()
      || lock.isSymbolicLink()
      || lock.uid !== (options.expectedUid ?? 0)
      || lock.nlink !== 1
      || (lock.mode & 0o777) !== 0o600
    ) throw new Error('gateway apply lock has unsafe ownership, type, or mode');
    applyLocked = true;
  } catch (error) {
    if (error.code !== 'ENOENT') throw error;
  }
  return Object.freeze({
    apiVersion: API_VERSION,
    kind: 'NoshGatewayStatus',
    schemaVersion: SCHEMA_VERSION,
    trustDigest: trustArtifact.trustDigest,
    audience: trustArtifact.config.audience,
    target: trustArtifact.config.target,
    targetBindingDigest: trustArtifact.config.targetBindingDigest,
    targetContextDigest: trustArtifact.config.targetContextDigest,
    capabilityDigest: trustArtifact.config.capabilityDigest,
    activeGrantSetDigest: state.activeGrantSetDigest,
    applyLocked,
    status: state.status,
    currentLeafBundleDigest: state.currentLeafBundleDigest,
    currentGrantEnvelopeDigest: state.currentGrantEnvelopeDigest,
    lastAppliedAt: state.lastAppliedAt,
    liveStateDigest: state.liveStateDigest,
    liveVerificationDigest: state.liveVerification === null
      ? null
      : sha256Digest(state.liveVerification),
    live,
    quarantine: state.quarantine,
    stateDigest: state.stateDigest,
  });
}

export { newGatewayState as createInitialGatewayState };
