import fs from 'node:fs/promises';
import path from 'node:path';

import {
  REVIEW_LIMITS,
  STREAM_ROLES,
} from './constants.js';
import {
  createReviewBundle,
  materializeSemanticGraph,
  validateReviewBundle,
} from './documents.js';
import { writeArtifactDirectory, readTrustedFile, readTrustedJson } from './io.js';
import { jcsCanonicalize } from './jcs.js';
import { createHashAddressedStream } from './streams.js';

export const REVIEW_BUNDLE_MANIFEST = 'review-bundle.json';
const MAX_REVIEW_BUNDLE_BYTES = REVIEW_LIMITS.maxStreamBytes * 2 + 4 * 1024 * 1024;
export const REVIEW_VIEW_LIMITS = Object.freeze({
  bytes: 25 * 1024 * 1024,
  nodes: 5_000,
  observations: 20_000,
  coverage: 5_000,
  findings: 5_000,
  proposals: 5_000,
  diff: 5_000,
});

export function assertReviewableSemanticGraph(graph) {
  for (const role of STREAM_ROLES) {
    const records = graph?.[role];
    if (!Array.isArray(records)) {
      throw new TypeError(`materialized graph ${role} must be an array`);
    }
    if (records.length > REVIEW_VIEW_LIMITS[role]) {
      throw new Error(
        `materialized graph has ${records.length} ${role} records; `
        + `the review limit is ${REVIEW_VIEW_LIMITS[role]}`,
      );
    }
  }
  const bytes = Buffer.byteLength(jcsCanonicalize(graph), 'utf8');
  if (bytes > REVIEW_VIEW_LIMITS.bytes) {
    throw new Error(
      `materialized graph is ${bytes} bytes; the review limit is ${REVIEW_VIEW_LIMITS.bytes}`,
    );
  }
  return graph;
}

function currentUid() {
  return typeof process.geteuid === 'function' ? process.geteuid() : null;
}

async function resolvePrivateBundleDirectory(directory) {
  const requested = path.resolve(directory);
  const resolved = await fs.realpath(requested);
  if (requested !== resolved) {
    throw new Error('review bundle directory must not be reached through a symlink');
  }
  const stat = await fs.lstat(resolved);
  const uid = currentUid();
  if (
    !stat.isDirectory()
    || stat.isSymbolicLink()
    || (uid != null && stat.uid !== uid)
    || (stat.mode & 0o077) !== 0
  ) {
    throw new Error('review bundle directory is not a private trusted directory');
  }
  return resolved;
}

async function resolvePrivateBundleFile(directory, relativePath) {
  const requested = path.join(directory, ...relativePath.split('/'));
  const resolved = await fs.realpath(requested);
  if (resolved !== requested || !resolved.startsWith(`${directory}${path.sep}`)) {
    throw new Error(`review bundle artifact must not traverse a symlink: ${relativePath}`);
  }
  const parent = path.dirname(resolved);
  const parentStat = await fs.lstat(parent);
  const uid = currentUid();
  if (
    !parentStat.isDirectory()
    || parentStat.isSymbolicLink()
    || (uid != null && parentStat.uid !== uid)
    || (parentStat.mode & 0o077) !== 0
  ) {
    throw new Error(`review bundle artifact parent is not trusted: ${relativePath}`);
  }
  return resolved;
}

function normalizeRecordSets(input) {
  const records = {};
  for (const role of STREAM_ROLES) {
    const selected = input?.[role] || [];
    if (!Array.isArray(selected)) {
      throw new TypeError(`review records.${role} must be an array`);
    }
    records[role] = selected;
  }
  return records;
}

export function createReviewBundleArtifact(input) {
  if (!input || typeof input !== 'object' || Array.isArray(input)) {
    throw new TypeError('review artifact input must be an object');
  }
  const records = normalizeRecordSets(input.records);
  const streams = Object.fromEntries(STREAM_ROLES.map((role) => [
    role,
    createHashAddressedStream(role, records[role]),
  ]));
  const bundle = createReviewBundle({
    scope: input.scope,
    sources: input.sources,
    baseline: input.baseline,
    basePolicyDigest: input.basePolicyDigest,
    privacyProfile: input.privacyProfile,
    createdAt: input.createdAt,
    streams: STREAM_ROLES.map((role) => streams[role]),
  });
  const contents = Object.fromEntries(STREAM_ROLES.map((role) => [
    role,
    streams[role].content,
  ]));
  const graph = materializeSemanticGraph(bundle, contents);
  assertReviewableSemanticGraph(graph);
  const artifacts = {
    [REVIEW_BUNDLE_MANIFEST]: jcsCanonicalize(bundle),
    ...Object.fromEntries(STREAM_ROLES.map((role) => [
      streams[role].descriptor.path,
      streams[role].content,
    ])),
  };
  return Object.freeze({
    bundle,
    graph,
    records: Object.freeze(records),
    streams: Object.freeze(streams),
    artifacts: Object.freeze(artifacts),
  });
}

export async function writeReviewBundleArtifact(directory, artifact, options = {}) {
  if (!artifact?.bundle || !artifact?.artifacts) {
    throw new TypeError('a composed review bundle artifact is required');
  }
  validateReviewBundle(artifact.bundle);
  const result = await writeArtifactDirectory(directory, artifact.artifacts, {
    maximumBytes: options.maximumBytes ?? MAX_REVIEW_BUNDLE_BYTES,
  });
  const verified = await readReviewBundleArtifact(result.directory);
  if (verified.bundle.bundleDigest !== artifact.bundle.bundleDigest) {
    throw new Error('persisted review bundle digest changed during verification');
  }
  return { ...result, ...verified };
}

export async function readReviewBundleArtifact(directory) {
  const resolved = await resolvePrivateBundleDirectory(directory);
  const { content: manifestContent, document: bundle } = await readTrustedJson(
    path.join(resolved, REVIEW_BUNDLE_MANIFEST),
    { maximumBytes: 4 * 1024 * 1024, requireJcs: true },
  );
  validateReviewBundle(bundle);
  const contents = {};
  let totalBytes = manifestContent.length;
  const expectedFiles = new Set([REVIEW_BUNDLE_MANIFEST]);
  for (const descriptor of bundle.streams) {
    const file = await resolvePrivateBundleFile(resolved, descriptor.path);
    const content = await readTrustedFile(file, {
      maximumBytes: REVIEW_LIMITS.maxStreamBytes,
    });
    try {
      new TextDecoder('utf-8', { fatal: true }).decode(content);
    } catch (error) {
      throw new Error(`review stream is not valid UTF-8: ${descriptor.role}`, {
        cause: error,
      });
    }
    if (String(content.length) !== descriptor.bytes) {
      throw new Error(`review stream byte count changed: ${descriptor.role}`);
    }
    totalBytes += content.length;
    if (totalBytes > MAX_REVIEW_BUNDLE_BYTES) {
      throw new Error('review bundle exceeds the aggregate byte limit');
    }
    contents[descriptor.role] = content;
    expectedFiles.add(descriptor.path);
  }
  const discovered = [];
  async function walk(relative = '') {
    const entries = await fs.readdir(path.join(resolved, relative), { withFileTypes: true });
    for (const entry of entries) {
      const child = relative ? `${relative}/${entry.name}` : entry.name;
      if (entry.isSymbolicLink()) throw new Error(`review bundle contains a symlink: ${child}`);
      if (entry.isDirectory()) await walk(child);
      else if (entry.isFile()) discovered.push(child);
      else throw new Error(`review bundle contains an unsupported entry: ${child}`);
    }
  }
  await walk();
  if (
    discovered.length !== expectedFiles.size
    || discovered.some((file) => !expectedFiles.has(file))
  ) {
    throw new Error('review bundle contains unbound files');
  }
  const graph = materializeSemanticGraph(bundle, contents);
  assertReviewableSemanticGraph(graph);
  return Object.freeze({ directory: resolved, bundle, graph, contents });
}
