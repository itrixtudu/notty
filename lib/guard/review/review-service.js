import path from 'node:path';

import { createBuildReviewGraph } from './build-adapter.js';
import {
  createReviewBundleArtifact,
  readReviewBundleArtifact,
  writeReviewBundleArtifact,
} from './bundle-store.js';
import { sha256Digest, jcsCanonicalize } from './jcs.js';
import { readPolicyLeafArtifact } from './leaf-store.js';
import { createCoverageMarker, createFinding, createGraphDiff } from './records.js';
import { loadSbom, sbomGraphRecords } from './sbom.js';
import {
  createRuntimeCandidateGraphRecords,
  loadRuntimeEgressCandidate,
  runtimeCandidateBinding,
  runtimeReviewScope,
} from './runtime-adapter.js';

const PORTABLE = Object.freeze({ classification: 'portable', fields: [] });

function canonicalEqual(left, right) {
  return jcsCanonicalize(left) === jcsCanonicalize(right);
}

function recordMaps(records) {
  return Object.fromEntries(
    ['nodes', 'observations', 'coverage', 'findings', 'proposals', 'diff']
      .map((role) => [role, new Map(records[role].map((record) => [record.id, record]))]),
  );
}

function addRecord(maps, role, record) {
  const previous = maps[role].get(record.id);
  if (previous && !canonicalEqual(previous, record)) {
    throw new Error(`semantic graph record collision for ${record.id}`);
  }
  maps[role].set(record.id, record);
}

function recordsFromMaps(maps) {
  return Object.fromEntries(Object.entries(maps).map(([role, entries]) => [
    role,
    [...entries.values()].sort((left, right) => left.id.localeCompare(right.id)),
  ]));
}

function validateBaselineScope(current, baseline) {
  if (!baseline) return;
  for (const key of ['class', 'projectKey', 'platform', 'target']) {
    if (current[key] !== baseline.scope?.[key]) {
      throw new Error(`selected baseline has a different build ${key}`);
    }
  }
}

function missingSbomCoverage(scope, role, blocking) {
  return createCoverageMarker({
    scopeDigest: scope.scopeDigest,
    domain: role === 'source' ? 'sbom-source' : 'sbom-image',
    status: 'unavailable',
    sourceIds: [],
    counters: { packages: '0' },
    gaps: [`${role} SBOM was not supplied or generated`],
    blocking,
    privacy: { ...PORTABLE, fields: [] },
  });
}

function packageKey(node) {
  return JSON.stringify({
    role: node.properties?.sourceRole || null,
    purl: node.identity?.purl || null,
    name: node.identity?.name || null,
  });
}

function addPackageDiffs(maps, scope, baseline, fallbackEvidenceRef) {
  if (!baseline) return;
  const current = [...maps.nodes.values()].filter((node) => node.nodeType === 'package');
  const previous = (baseline.nodes || []).filter((node) => node.nodeType === 'package');
  const beforeByKey = new Map(previous.map((node) => [packageKey(node), node]));
  const currentKeys = new Set();
  for (const node of current) {
    const key = packageKey(node);
    currentKeys.add(key);
    const before = beforeByKey.get(key);
    const beforeDigest = before ? sha256Digest(before.identity) : null;
    const afterDigest = sha256Digest(node.identity);
    const changed = !before || beforeDigest !== afterDigest;
    addRecord(maps, 'diff', createGraphDiff({
      scopeDigest: scope.scopeDigest,
      entityId: node.id,
      changeType: before ? (changed ? 'broadened' : 'unchanged') : 'added',
      beforeDigest,
      afterDigest,
      policyRelevant: changed,
      summary: before
        ? (changed ? 'Package identity or version changed.' : 'Package is unchanged.')
        : 'Package is newly present.',
      evidenceRefs: node.evidenceRefs,
      privacy: node.privacy,
    }));
    if (changed) {
      addRecord(maps, 'findings', createFinding({
        semanticKey: {
          type: 'package-change',
          packageKey: key,
          beforeDigest,
          afterDigest,
        },
        scopeDigest: scope.scopeDigest,
        findingType: 'package-change',
        severity: 'high',
        blocking: false,
        message: before
          ? `Package changed: ${node.label}`
          : `New package observed: ${node.label}`,
        semanticRefs: [node.id],
        evidenceRefs: node.evidenceRefs,
        properties: { beforeDigest, afterDigest },
        privacy: node.privacy,
      }));
    }
  }
  for (const node of previous) {
    if (currentKeys.has(packageKey(node))) continue;
    addRecord(maps, 'diff', createGraphDiff({
      scopeDigest: scope.scopeDigest,
      entityId: node.id,
      changeType: 'removed',
      beforeDigest: sha256Digest(node.identity),
      afterDigest: null,
      policyRelevant: false,
      summary: 'Previously observed package is absent.',
      evidenceRefs: [fallbackEvidenceRef],
      privacy: node.privacy,
    }));
  }
}

async function appendSbom(maps, sources, scope, input) {
  if (!['source', 'image'].includes(input.role)) {
    throw new TypeError('SBOM role must be source or image');
  }
  const loaded = await loadSbom(input.file);
  const generated = sbomGraphRecords({
    scope,
    role: input.role,
    digest: loaded.digest,
    sbom: loaded.normalized,
  });
  generated.nodes.forEach((record) => addRecord(maps, 'nodes', record));
  generated.observations.forEach((record) => addRecord(maps, 'observations', record));
  addRecord(maps, 'coverage', generated.coverage);
  sources.push({
    id: generated.sourceNode.id,
    sourceType: 'software-bill-of-materials',
    artifactKind: loaded.normalized.format === 'spdx-json'
      ? 'SPDXDocument'
      : 'CycloneDXDocument',
    artifactDigest: loaded.digest,
    sourceName: `${input.role}-sbom`,
    sourceDigest: loaded.digest,
    coverage: {
      status: 'complete',
      lostEvents: '0',
      parseErrors: '0',
      gaps: [],
    },
  });
}

export async function createBuildReviewArtifact(input) {
  if (!input?.profile && !input?.runtimeCandidate) throw new TypeError('build review profile or runtime candidate path is required');
  if (input.baselineOverrideReason && !input.baseline) {
    throw new TypeError('a baseline override reason requires an explicit baseline');
  }
  const baselineArtifact = input.baseline
    ? await readReviewBundleArtifact(input.baseline)
    : null;
  if (input.basePolicy && !baselineArtifact) {
    throw new TypeError('a base policy requires the review bundle that produced it as --baseline');
  }
  const basePolicyArtifact = input.basePolicy
    ? await readPolicyLeafArtifact(input.basePolicy)
    : null;
  if (
    basePolicyArtifact
    && (
      basePolicyArtifact.policyIR.graphDigest !== baselineArtifact.bundle.graphDigest
      || basePolicyArtifact.policyIR.proposalSetDigest
        !== baselineArtifact.bundle.proposalSetDigest
    )
  ) {
    throw new Error('base policy does not descend from the selected baseline review');
  }
  const runtimeCandidate = input.runtimeCandidate
    ? await loadRuntimeEgressCandidate(input.runtimeCandidate, {
        ...(input.runtimeTrustedRoot
          ? { trustedRoot: input.runtimeTrustedRoot }
          : {}),
        ...(input.runtimeTrustedUid == null
          ? {}
          : { trustedUid: input.runtimeTrustedUid }),
      })
    : null;
  const build = input.profile ? await createBuildReviewGraph(input.profile, {
    baseline: baselineArtifact?.graph || null,
    ...(runtimeCandidate
      ? { runtimeBinding: runtimeCandidateBinding(runtimeCandidate) }
      : {}),
  }) : { scope: runtimeReviewScope(runtimeCandidate), sources: [], nodes: [],
    observations: [], coverage: [], findings: [], proposals: [], diff: [] };
  validateBaselineScope(build.scope, baselineArtifact?.graph || null);
  const maps = recordMaps(build);
  const sources = [...build.sources];
  if (runtimeCandidate) {
    const runtime = createRuntimeCandidateGraphRecords(build.scope, runtimeCandidate, {
      includeSubject: !input.profile,
      literalEndpoints: input.literalEndpoints === true || !input.profile,
    });
    for (const [role, records] of Object.entries(runtime.records)) {
      records.forEach((record) => addRecord(maps, role, record));
    }
    sources.push(runtime.source);
  }
  const roles = new Set();
  for (const sbom of input.sboms || []) {
    if (roles.has(sbom.role)) throw new TypeError(`duplicate ${sbom.role} SBOM`);
    roles.add(sbom.role);
    await appendSbom(maps, sources, build.scope, sbom);
  }
  for (const role of ['source', 'image']) {
    if (!roles.has(role)) {
      addRecord(
        maps,
        'coverage',
        missingSbomCoverage(build.scope, role, input.requireSbom !== false),
      );
    }
  }
  addPackageDiffs(
    maps,
    build.scope,
    baselineArtifact?.graph || null,
    sources[0].id,
  );
  const records = recordsFromMaps(maps);
  const baseline = baselineArtifact
    ? {
        selection: input.baselineOverrideReason ? 'override' : 'automatic',
        bundleDigest: baselineArtifact.bundle.bundleDigest,
        reason: input.baselineOverrideReason || null,
      }
    : { selection: 'none', bundleDigest: null, reason: null };
  return createReviewBundleArtifact({
    scope: build.scope,
    sources,
    records,
    baseline,
    basePolicyDigest: basePolicyArtifact?.policyIR.contentDigest || sha256Digest(null),
    privacyProfile: input.privacyProfile || 'private-review',
    createdAt: input.createdAt,
  });
}

export async function buildAndWriteReviewBundle(input) {
  const artifact = await createBuildReviewArtifact(input);
  const written = await writeReviewBundleArtifact(path.resolve(input.output), artifact);
  return { artifact, written };
}
