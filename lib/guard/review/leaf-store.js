import fs from 'node:fs/promises';
import path from 'node:path';

import {
  validatePolicyIR,
  validateTargetReviewSet,
} from './documents.js';
import { readTrustedFile, readTrustedJson } from './io.js';
import { jcsCanonicalize, sha256Digest } from './jcs.js';

const DIGEST_PATTERN = /^sha256:[a-f0-9]{64}$/;
const SAFE_PATH = /^[A-Za-z0-9][A-Za-z0-9._/-]{0,511}$/;

function assertDigest(value, name) {
  if (typeof value !== 'string' || !DIGEST_PATTERN.test(value)) {
    throw new TypeError(`${name} must be a SHA-256 digest`);
  }
}

function safeArtifactPath(value) {
  if (
    typeof value !== 'string'
    || !SAFE_PATH.test(value)
    || value.includes('\\')
    || path.posix.normalize(value) !== value
    || value.split('/').includes('..')
  ) {
    throw new TypeError('leaf artifact path is unsafe');
  }
  return value;
}

function validateLeafManifest(leaf) {
  if (!leaf || typeof leaf !== 'object' || Array.isArray(leaf)) {
    throw new TypeError('leaf bundle manifest must be an object');
  }
  const expectedKeys = [
    'activationEligible',
    'apiVersion',
    'artifacts',
    'bundleDigest',
    'capabilityDigest',
    'createdAt',
    'decisionSetDigest',
    'graphDigest',
    'kind',
    'policyIrDigest',
    'projectionDigest',
    'schemaVersion',
    'target',
    'targetContextDigest',
  ];
  const keys = Object.keys(leaf).sort();
  if (keys.length !== expectedKeys.length || keys.some((key, index) => key !== expectedKeys[index])) {
    throw new TypeError('leaf bundle manifest contains unsupported fields');
  }
  if (
    leaf.apiVersion !== 'notty.dev/v1alpha1'
    || leaf.kind !== 'NoshPolicyLeafBundle'
    || leaf.schemaVersion !== 1
    || typeof leaf.activationEligible !== 'boolean'
    || ![
      'cilium',
      'guard-ebpf',
      'guard-nftables',
      'gateway-iptables',
      'gateway-pf',
      'gateway-ipfw',
      'gateway-ipfilter',
      'gateway-l7-proxy',
    ].includes(leaf.target)
    || !Number.isFinite(Date.parse(leaf.createdAt))
  ) {
    throw new TypeError('leaf bundle manifest header is invalid');
  }
  for (const field of [
    'bundleDigest',
    'capabilityDigest',
    'decisionSetDigest',
    'graphDigest',
    'policyIrDigest',
    'projectionDigest',
    'targetContextDigest',
  ]) assertDigest(leaf[field], field);
  if (!Array.isArray(leaf.artifacts) || leaf.artifacts.length > 256) {
    throw new TypeError('leaf bundle artifact inventory is invalid');
  }
  let previous = null;
  const seen = new Set();
  for (const artifact of leaf.artifacts) {
    if (!artifact || typeof artifact !== 'object' || Array.isArray(artifact)) {
      throw new TypeError('leaf artifact entry must be an object');
    }
    const artifactKeys = Object.keys(artifact).sort();
    if (artifactKeys.join(',') !== 'bytes,mediaType,path,sha256') {
      throw new TypeError('leaf artifact entry contains unsupported fields');
    }
    safeArtifactPath(artifact.path);
    assertDigest(artifact.sha256, 'leaf artifact digest');
    if (!/^(0|[1-9][0-9]*)$/.test(artifact.bytes)) {
      throw new TypeError('leaf artifact bytes must be a decimal string');
    }
    if (typeof artifact.mediaType !== 'string' || !artifact.mediaType) {
      throw new TypeError('leaf artifact media type is required');
    }
    if (seen.has(artifact.path) || (previous != null && previous > artifact.path)) {
      throw new TypeError('leaf artifacts must be uniquely sorted');
    }
    seen.add(artifact.path);
    previous = artifact.path;
  }
  const { bundleDigest, ...payload } = leaf;
  if (bundleDigest !== sha256Digest(jcsCanonicalize(payload))) {
    throw new Error('leaf bundle digest does not match its manifest');
  }
  return leaf;
}

async function trustedDirectory(directory) {
  const requested = path.resolve(directory);
  const resolved = await fs.realpath(requested);
  const stat = await fs.lstat(resolved);
  const uid = typeof process.geteuid === 'function' ? process.geteuid() : null;
  if (
    requested !== resolved
    || !stat.isDirectory()
    || stat.isSymbolicLink()
    || (uid != null && stat.uid !== uid)
    || (stat.mode & 0o077) !== 0
  ) throw new Error('policy leaf directory is not private and trusted');
  return resolved;
}

function assertBindings(leaf, policyIR, targetReviewSet, projection) {
  const targetProjection = targetReviewSet.projections.find(
    (entry) => entry.target === leaf.target,
  );
  if (!targetProjection || targetReviewSet.projections.length !== 1) {
    throw new Error('leaf bundle must contain exactly one bound target projection');
  }
  const bindings = {
    graphDigest: policyIR.graphDigest,
    decisionSetDigest: policyIR.decisionSetDigest,
    policyIrDigest: policyIR.contentDigest,
    projectionDigest: targetReviewSet.contentDigest,
    targetContextDigest: targetProjection.targetContextDigest,
    capabilityDigest: projection.capabilityDigest,
  };
  for (const [name, expected] of Object.entries(bindings)) {
    if (leaf[name] !== expected) throw new Error(`leaf ${name} binding is invalid`);
  }
  if (
    projection.target !== leaf.target
    || projection.targetContextDigest !== leaf.targetContextDigest
    || leaf.activationEligible !== targetProjection.activationEligible
  ) {
    throw new Error('leaf target projection binding is invalid');
  }
  const artifacts = new Map(leaf.artifacts.map((entry) => [entry.path, entry]));
  for (const artifact of targetProjection.artifacts) {
    const leafArtifact = artifacts.get(`rendered/${artifact.name}`);
    if (
      !leafArtifact
      || leafArtifact.sha256 !== artifact.sha256
      || leafArtifact.bytes !== artifact.bytes
    ) {
      throw new Error(`leaf rendered artifact does not match target review: ${artifact.name}`);
    }
  }
}

export async function readPolicyLeafArtifact(directory) {
  const resolved = await trustedDirectory(directory);
  const leaf = (await readTrustedJson(path.join(resolved, 'leaf-bundle.json'), {
    maximumBytes: 4 * 1024 * 1024,
  })).document;
  validateLeafManifest(leaf);
  const expectedFiles = new Set(['leaf-bundle.json']);
  for (const artifact of leaf.artifacts) {
    const file = path.join(resolved, ...artifact.path.split('/'));
    const content = await readTrustedFile(file, { maximumBytes: 128 * 1024 * 1024 });
    if (String(content.length) !== artifact.bytes || sha256Digest(content) !== artifact.sha256) {
      throw new Error(`leaf artifact changed: ${artifact.path}`);
    }
    expectedFiles.add(artifact.path);
  }
  const discovered = [];
  async function walk(relative = '') {
    const entries = await fs.readdir(path.join(resolved, relative), { withFileTypes: true });
    for (const entry of entries) {
      const child = relative ? `${relative}/${entry.name}` : entry.name;
      if (entry.isSymbolicLink()) throw new Error(`leaf bundle contains a symlink: ${child}`);
      if (entry.isDirectory()) await walk(child);
      else if (entry.isFile()) discovered.push(child);
      else throw new Error(`leaf bundle contains an unsupported entry: ${child}`);
    }
  }
  await walk();
  if (
    discovered.length !== expectedFiles.size
    || discovered.some((file) => !expectedFiles.has(file))
  ) {
    throw new Error('leaf bundle contains unbound files');
  }
  const policyIR = (await readTrustedJson(path.join(resolved, 'policy-ir.json'))).document;
  const targetReviewSet = (
    await readTrustedJson(path.join(resolved, 'target-review-set.json'))
  ).document;
  const projection = (await readTrustedJson(path.join(resolved, 'projection.json'))).document;
  validatePolicyIR(policyIR);
  validateTargetReviewSet(targetReviewSet, { policyIR });
  assertBindings(leaf, policyIR, targetReviewSet, projection);
  return Object.freeze({
    directory: resolved,
    leaf,
    policyIR,
    targetReviewSet,
    projection,
  });
}

export { validateLeafManifest };
