import crypto from 'node:crypto';
import fs from 'node:fs/promises';
import path from 'node:path';

import {
  artifactHashesFromProfile,
  evaluateAuditEvaluation,
} from '../guard/audit-evaluation.js';
import { DEFAULT_CLEAN_AUDIT_THRESHOLD } from '../guard/compiler.js';
import { DEFAULT_GUARD_PROFILE_DIR } from './constants.js';

const ARTIFACT_FILES = Object.freeze([
  'profile.yaml',
  'tetragon.yaml',
  'seccomp.json',
  'apparmor.profile',
  'docker.json',
  'network-policy.yaml',
  'report.json',
  'report.html',
  'manifest.json',
]);

async function sha256File(filePath) {
  const content = await fs.readFile(filePath);
  return crypto.createHash('sha256').update(content).digest('hex');
}

function canonicalJson(value) {
  if (Array.isArray(value)) {
    return `[${value.map(canonicalJson).join(',')}]`;
  }
  if (value && typeof value === 'object') {
    return `{${Object.keys(value)
      .sort()
      .map((key) => `${JSON.stringify(key)}:${canonicalJson(value[key])}`)
      .join(',')}}`;
  }
  return JSON.stringify(value);
}

export async function hashArtifactSet(directory) {
  const resolved = path.resolve(directory);
  const artifacts = {};
  for (const filename of ARTIFACT_FILES) {
    const filePath = path.join(resolved, filename);
    try {
      artifacts[filename] = await sha256File(filePath);
    } catch (error) {
      if (error.code === 'ENOENT') {
        throw new Error(`candidate is missing required artifact: ${filename}`);
      }
      throw error;
    }
  }
  return artifacts;
}

async function assertTrustedPaths(checks) {
  for (const check of checks) {
    const stat = await fs.lstat(check.path);
    if (
      (check.kind === 'directory' && !stat.isDirectory()) ||
      (check.kind === 'file' && !stat.isFile())
    ) {
      throw new Error(`trusted profile path has wrong type: ${check.path}`);
    }
    if (stat.uid !== 0 || (stat.mode & 0o022) !== 0) {
      throw new Error(
        `enforce profile must be root-owned and not group/other-writable: ${check.path}`,
      );
    }
  }
}

function isWithinDirectory(parent, candidate) {
  const relative = path.relative(parent, candidate);
  return relative === '' || (
    relative !== '..' &&
    !relative.startsWith(`..${path.sep}`) &&
    !path.isAbsolute(relative)
  );
}

async function assertTrustedDirectoryAncestry(directory, trustedRoot) {
  const resolved = path.resolve(directory);
  const resolvedRoot = path.resolve(trustedRoot);
  let canonical;
  let canonicalRoot;
  try {
    [canonical, canonicalRoot] = await Promise.all([
      fs.realpath(resolved),
      fs.realpath(resolvedRoot),
    ]);
  } catch (error) {
    throw new Error(
      `trusted profile root and candidate must already exist: ${error.message}`,
      { cause: error },
    );
  }
  if (canonical !== resolved || canonicalRoot !== resolvedRoot) {
    throw new Error(
      'trusted profile root and candidate must not contain symbolic links',
    );
  }
  if (!isWithinDirectory(canonicalRoot, canonical)) {
    throw new Error(
      `enforce profile must be beneath the trusted profile root ${canonicalRoot}`,
    );
  }
  let cursor = canonical;
  for (;;) {
    await assertTrustedPaths([{ path: cursor, kind: 'directory' }]);
    if (cursor === path.parse(cursor).root) {
      break;
    }
    cursor = path.dirname(cursor);
  }
}

async function assertTrustedCandidateDirectory(directory, options = {}) {
  const resolved = path.resolve(directory);
  await assertTrustedDirectoryAncestry(
    resolved,
    options.trustedRoot || DEFAULT_GUARD_PROFILE_DIR,
  );
  const checks = [
    { path: resolved, kind: 'directory' },
    ...ARTIFACT_FILES.map((filename) => ({
      path: path.join(resolved, filename),
      kind: 'file',
    })),
  ];
  await assertTrustedPaths(checks);
  return true;
}

async function assertTrustedArtifactDirectory(directory, options = {}) {
  await assertTrustedCandidateDirectory(directory, options);
  await assertTrustedPaths([
    { path: path.join(directory, 'approval.json'), kind: 'file' },
  ]);
  return true;
}

function prefixedHash(value) {
  return `sha256:${value}`;
}

export function evaluatePromotionGate(profile) {
  const evidence = profile?.spec?.evidence || {};
  const runs = Array.isArray(evidence.runProvenance)
    ? evidence.runProvenance
    : [];
  const targetDigest = profile?.spec?.target?.imageDigest
    || evidence.subject?.imageDigest
    || '';
  const seenRunIds = new Set();
  const seenManifestHashes = new Set();
  const cleanAuditRuns = [];
  const errors = [];
  const hardErrors = [];
  const candidateArtifactHashes = artifactHashesFromProfile(profile);
  if (!/^sha256:[a-f0-9]{64}$/.test(targetDigest)) {
    hardErrors.push('promotion requires an exact immutable target image digest');
  }
  for (const run of runs) {
    if (!run?.runId || seenRunIds.has(run.runId)) {
      hardErrors.push('promotion evidence run IDs must be non-empty and distinct');
      continue;
    }
    seenRunIds.add(run.runId);
    if (
      run.profileScope === 'egress-only'
      || String(run.mode || '').startsWith('egress-')
    ) {
      hardErrors.push(
        `promotion run ${run.runId} is scoped to egress-only evidence`,
      );
    }
    if (run.manifestVerified === true && (
      typeof run.manifestHash !== 'string'
      || !/^sha256:[a-f0-9]{64}$/.test(run.manifestHash)
      || seenManifestHashes.has(run.manifestHash)
    )) {
      hardErrors.push(`promotion run ${run.runId} requires a distinct manifest hash`);
      continue;
    }
    if (run.manifestVerified === true) {
      seenManifestHashes.add(run.manifestHash);
    }
    if (
      run.manifestVerified === true
      && targetDigest
      && run.imageDigest !== targetDigest
    ) {
      hardErrors.push(`promotion run ${run.runId} image digest does not match the profile`);
      continue;
    }
    const auditEvaluation = run.mode === 'audit'
      ? evaluateAuditEvaluation(
          run.auditEvaluation,
          candidateArtifactHashes,
        )
      : null;
    for (const evaluationError of auditEvaluation?.errors || []) {
      hardErrors.push(
        `promotion run ${run.runId} ${evaluationError}`,
      );
    }
    const clean = run.mode === 'audit'
      && run.cleanAudit === true
      && run.complete === true
      && run.promotionEligible === true
      && run.manifestVerified === true
      && Number(run.lostEvents || 0) === 0
      && Number(run.wouldDenyCount || 0) === 0
      && Array.isArray(run.gaps)
      && run.gaps.length === 0
      && auditEvaluation?.clean === true;
    if (clean) {
      cleanAuditRuns.push(run.runId);
    }
  }
  cleanAuditRuns.sort();
  const declared = profile?.spec?.promotion || {};
  const declaredThreshold = Number(declared.cleanAuditThreshold);
  const threshold = Number.isSafeInteger(declaredThreshold)
    && declaredThreshold >= DEFAULT_CLEAN_AUDIT_THRESHOLD
    ? declaredThreshold
    : DEFAULT_CLEAN_AUDIT_THRESHOLD;
  if (
    !Number.isSafeInteger(declaredThreshold)
    || declaredThreshold < DEFAULT_CLEAN_AUDIT_THRESHOLD
  ) {
    hardErrors.push(
      `candidate clean audit threshold must be at least ${DEFAULT_CLEAN_AUDIT_THRESHOLD}`,
    );
  }
  const allInputsManifested = evidence.ingestion?.manifestCount > 0
    && evidence.ingestion?.directInputCount === 0
    && evidence.ingestion?.promotionInputEligible === true
    && Number.isSafeInteger(evidence.ingestion.manifestCount)
    && runs.length === evidence.ingestion.manifestCount
    && runs.every((run) => run?.manifestVerified === true);
  if (!allInputsManifested) {
    errors.push('promotion requires only completed, integrity-verified manifest inputs');
  }
  const computedThresholdSatisfied = hardErrors.length === 0
    && allInputsManifested
    && cleanAuditRuns.length >= threshold;
  if (
    declared.cleanAuditRunCount !== cleanAuditRuns.length
    || JSON.stringify(declared.cleanAuditRuns || []) !== JSON.stringify(cleanAuditRuns)
    || declared.allInputsManifested !== allInputsManifested
    || declared.thresholdSatisfied !== computedThresholdSatisfied
  ) {
    hardErrors.push('candidate promotion summary does not match evidence provenance');
  }
  errors.push(...hardErrors);
  return {
    threshold,
    cleanAuditRuns,
    cleanAuditRunCount: cleanAuditRuns.length,
    allInputsManifested,
    satisfied: errors.length === 0 && computedThresholdSatisfied,
    overrideEligible: hardErrors.length === 0,
    errors: [...new Set(errors)].sort(),
  };
}

function validateRecordedPromotionGate(approval, profile) {
  const computed = evaluatePromotionGate(profile);
  const recorded = approval?.promotionGate;
  if (!recorded || typeof recorded !== 'object') {
    return 'approval is missing its promotion gate decision';
  }
  const { override = null, ...recordedDecision } = recorded;
  if (canonicalJson(recordedDecision) !== canonicalJson(computed)) {
    return 'approval promotion gate does not match the candidate provenance';
  }
  if (computed.satisfied) {
    return override === null
      ? null
      : 'a threshold-satisfied approval must not contain a promotion override';
  }
  if (!computed.overrideEligible) {
    return 'candidate promotion provenance is not override eligible';
  }
  if (
    !override
    || typeof override.reviewer !== 'string'
    || !override.reviewer.trim()
    || typeof override.reason !== 'string'
    || !override.reason.trim()
    || override.reviewer !== approval.reviewer
  ) {
    return 'below-threshold approval requires a matching explicit reviewer and override reason';
  }
  return null;
}

async function validateCandidate(directory, artifactHashes, options = {}) {
  const requireEnforceable = options.requireEnforceable !== false;
  const [
    profile,
    manifest,
    tetragon,
    seccomp,
    docker,
    network,
    apparmor,
    validators,
  ] = await Promise.all([
    fs.readFile(path.join(directory, 'profile.yaml'), 'utf8').then(JSON.parse),
    fs.readFile(path.join(directory, 'manifest.json'), 'utf8').then(JSON.parse),
    fs.readFile(path.join(directory, 'tetragon.yaml'), 'utf8').then(JSON.parse),
    fs.readFile(path.join(directory, 'seccomp.json'), 'utf8').then(JSON.parse),
    fs.readFile(path.join(directory, 'docker.json'), 'utf8').then(JSON.parse),
    fs
      .readFile(path.join(directory, 'network-policy.yaml'), 'utf8')
      .then(JSON.parse),
    fs.readFile(path.join(directory, 'apparmor.profile'), 'utf8'),
    import('../guard/index.js'),
  ]);
  if (
    profile.apiVersion !== 'notty.dev/v1alpha1' ||
    profile.kind !== 'NoshSecurityProfile'
  ) {
    throw new Error('candidate profile has an unsupported apiVersion or kind');
  }
  if (profile.spec?.lifecycle?.structurallyValid !== true) {
    throw new Error('candidate profile is not structurally valid');
  }
  if (
    requireEnforceable &&
    profile.spec?.lifecycle?.enforcementReady !== true
  ) {
    throw new Error(
      'candidate is not enforcement ready; every independent artifact must be enforceable',
    );
  }
  for (const [name, descriptor] of Object.entries(profile.spec?.artifacts || {})) {
    if (
      descriptor.status !== 'candidate' ||
      (requireEnforceable && descriptor.enforceable !== true)
    ) {
      throw new Error(`candidate artifact is not enforceable: ${name}`);
    }
    const filename = descriptor.fileName;
    if (
      !filename ||
      prefixedHash(artifactHashes[filename]) !== descriptor.hash
    ) {
      throw new Error(`candidate artifact hash mismatch: ${name}`);
    }
  }
  const validations = {
    tetragon: validators.validateTetragonArtifact(tetragon),
    seccomp: validators.validateSeccompArtifact(seccomp),
    apparmor: validators.validateAppArmorArtifact(apparmor),
    docker: validators.validateDockerArtifact(docker),
    network: validators.validateNetworkArtifact(network),
  };
  for (const [name, validation] of Object.entries(validations)) {
    if (
      !validation.valid ||
      (requireEnforceable && validation.enforceable !== true)
    ) {
      throw new Error(
        `candidate ${name} artifact failed independent validation: ${[
          ...(validation.errors || []),
          ...(validation.enforceable ? [] : ['not enforceable']),
        ].join('; ')}`,
      );
    }
  }
  if (requireEnforceable) {
    const tetragonSource = await fs.readFile(
      path.join(directory, 'tetragon.yaml'),
      'utf8',
    );
    if (
      !tetragonSource.includes('{cgroupNamespace}') &&
      !tetragonSource.includes('{initPid}')
    ) {
      throw new Error(
        'standalone Docker Tetragon enforcement requires a reviewed {cgroupNamespace} or {initPid} runtime scope placeholder',
      );
    }
  }
  for (const [filename, entry] of Object.entries(manifest.files || {})) {
    const actual = artifactHashes[filename];
    if (!actual || entry.hash !== prefixedHash(actual)) {
      throw new Error(`candidate bundle manifest hash mismatch: ${filename}`);
    }
  }
  return { profile, manifest, validations };
}

export async function approveArtifactSet(directory, options = {}) {
  const resolved = path.resolve(directory);
  const artifacts = await hashArtifactSet(resolved);
  const validation = await validateCandidate(resolved, artifacts, {
    requireEnforceable: true,
  });
  const promotionGate = evaluatePromotionGate(validation.profile);
  const explicitReviewer = typeof options.reviewer === 'string'
    ? options.reviewer.trim()
    : '';
  const overrideReason = typeof options.promotionOverrideReason === 'string'
    ? options.promotionOverrideReason.trim()
    : '';
  let promotionOverride = null;
  if (!promotionGate.satisfied) {
    if (!promotionGate.overrideEligible) {
      throw new Error(
        `candidate promotion provenance is invalid: ${promotionGate.errors.join('; ')}`,
      );
    }
    if (!explicitReviewer || !overrideReason) {
      throw new Error(
        `candidate requires ${promotionGate.threshold} distinct clean audit runs; `
        + 'an override requires explicit reviewer and promotionOverrideReason',
      );
    }
    promotionOverride = {
      reviewer: explicitReviewer,
      reason: overrideReason,
    };
  }
  const reviewer =
    explicitReviewer
    || process.env.SUDO_USER
    || process.env.USER
    || `uid:${typeof process.getuid === 'function' ? process.getuid() : 'unknown'}`;
  const unsigned = {
    apiVersion: 'notty.dev/v1alpha1',
    kind: 'NoshSecurityProfileApproval',
    candidate: resolved,
    revision: options.revision || path.basename(resolved),
    reviewer,
    approvedAt: new Date().toISOString(),
    artifacts,
    profileName: validation.profile.metadata?.name || null,
    evidenceHash: validation.profile.spec?.evidenceHash || null,
    compilerManifestHash: prefixedHash(artifacts['manifest.json']),
    promotionGate: {
      ...promotionGate,
      override: promotionOverride,
    },
  };
  const approval = {
    ...unsigned,
    contentHash: crypto
      .createHash('sha256')
      .update(canonicalJson(unsigned))
      .digest('hex'),
  };
  const destination = path.join(resolved, 'approval.json');
  await fs.writeFile(destination, `${JSON.stringify(approval, null, 2)}\n`, {
    mode: 0o600,
    flag: options.replace ? 'w' : 'wx',
  });
  return approval;
}

export async function verifyCandidateArtifactSet(directory) {
  const resolved = path.resolve(directory);
  const artifacts = await hashArtifactSet(resolved);
  const validation = await validateCandidate(resolved, artifacts, {
    requireEnforceable: false,
  });
  return {
    ok: true,
    artifacts,
    profile: validation.profile,
    manifest: validation.manifest,
    validations: validation.validations,
  };
}

export async function verifyArtifactSet(directory, options = {}) {
  const resolved = path.resolve(directory);
  if (options.requireTrustedOwnership) {
    await assertTrustedArtifactDirectory(resolved, {
      trustedRoot: options.trustedRoot,
    });
  }
  const approval = JSON.parse(
    await fs.readFile(path.join(resolved, 'approval.json'), 'utf8'),
  );
  const current = await hashArtifactSet(resolved);
  const mismatches = [];
  const { contentHash, ...unsigned } = approval;
  const approvalHash = crypto
    .createHash('sha256')
    .update(canonicalJson(unsigned))
    .digest('hex');
  if (contentHash !== approvalHash) {
    mismatches.push({
      filename: 'approval.json',
      expected: contentHash || null,
      actual: approvalHash,
    });
  }
  for (const [filename, expected] of Object.entries(approval.artifacts || {})) {
    if (current[filename] !== expected) {
      mismatches.push({
        filename,
        expected,
        actual: current[filename] || null,
      });
    }
  }
  for (const filename of Object.keys(current)) {
    if (!approval.artifacts?.[filename]) {
      mismatches.push({ filename, expected: null, actual: current[filename] });
    }
  }
  let candidate = null;
  if (!mismatches.length) {
    try {
      candidate = await validateCandidate(resolved, current, {
        requireEnforceable: true,
      });
    } catch (error) {
      mismatches.push({
        filename: 'candidate-validation',
        expected: 'valid enforceable artifact set',
        actual: error.message,
      });
    }
  }
  if (!mismatches.length && candidate) {
    const promotionError = validateRecordedPromotionGate(
      approval,
      candidate.profile,
    );
    if (promotionError) {
      mismatches.push({
        filename: 'approval-promotion-gate',
        expected: 'a current satisfied gate or an explicit eligible override',
        actual: promotionError,
      });
    }
  }
  return {
    ok: mismatches.length === 0,
    approval,
    artifacts: current,
    profile: candidate?.profile || null,
    manifest: candidate?.manifest || null,
    validations: candidate?.validations || null,
    mismatches,
  };
}

export {
  ARTIFACT_FILES,
  assertTrustedArtifactDirectory,
  assertTrustedCandidateDirectory,
};
