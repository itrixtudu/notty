import { API_VERSION, ARTIFACT_FILES, ARTIFACT_KEYS, PROFILE_KIND } from './constants.js';
import { compileAppArmorArtifact, validateAppArmorArtifact } from './apparmor.js';
import { compileDockerArtifact, validateDockerArtifact } from './docker.js';
import { isNormalizedEvidence, normalizeEvidence } from './evidence.js';
import { compileNetworkArtifact, validateNetworkArtifact } from './network.js';
import { compileSeccompArtifact, validateSeccompArtifact } from './seccomp.js';
import { compileTetragonArtifact, validateTetragonArtifact } from './tetragon.js';
import { profileName } from './artifact-utils.js';
import {
  artifactHashesFromCompiledArtifacts,
  evaluateAuditEvaluation,
} from './audit-evaluation.js';
import {
  canonicalize,
  ensureTrailingNewline,
  serializeJson,
  sha256,
} from './stable.js';

const ARTIFACT_HANDLERS = Object.freeze({
  tetragon: {
    compile: compileTetragonArtifact,
    validate: validateTetragonArtifact,
    mediaType: 'application/yaml',
  },
  seccomp: {
    compile: compileSeccompArtifact,
    validate: validateSeccompArtifact,
    mediaType: 'application/json',
  },
  apparmor: {
    compile: compileAppArmorArtifact,
    validate: validateAppArmorArtifact,
    mediaType: 'text/plain',
  },
  docker: {
    compile: compileDockerArtifact,
    validate: validateDockerArtifact,
    mediaType: 'application/json',
  },
  network: {
    compile: compileNetworkArtifact,
    validate: validateNetworkArtifact,
    mediaType: 'application/yaml',
  },
});

export const DEFAULT_CLEAN_AUDIT_THRESHOLD = 3;

export function serializeArtifact(name, content) {
  if (name === 'apparmor') {
    return ensureTrailingNewline(content ?? '');
  }
  return serializeJson(content ?? null);
}

function compileArtifact(name, evidence, options) {
  const handler = ARTIFACT_HANDLERS[name];
  let content = null;
  let validation;
  try {
    content = handler.compile(evidence, options);
    validation = handler.validate(content);
  } catch (error) {
    validation = {
      valid: false,
      enforceable: false,
      runtimeValidationRequired: true,
      errors: [`${name} compiler failed: ${error.message}`],
      warnings: [],
    };
  }
  const serialized = serializeArtifact(name, content);
  return canonicalize({
    status: validation.valid ? 'candidate' : 'invalid',
    enforceable: validation.enforceable === true,
    runtimeValidationRequired: validation.runtimeValidationRequired !== false,
    errors: validation.errors || [],
    warnings: validation.warnings || [],
    hash: sha256(serialized),
    mediaType: handler.mediaType,
    fileName: ARTIFACT_FILES[name],
    content,
  });
}

function artifactDescriptor(entry) {
  return canonicalize({
    status: entry.status,
    enforceable: entry.enforceable,
    runtimeValidationRequired: entry.runtimeValidationRequired,
    errors: entry.errors,
    warnings: entry.warnings,
    hash: entry.hash,
    mediaType: entry.mediaType,
    fileName: entry.fileName,
  });
}

export function compileGuardProfile(evidenceInput, options = {}) {
  const evidence = isNormalizedEvidence(evidenceInput)
    ? canonicalize(evidenceInput)
    : normalizeEvidence(evidenceInput, options);
  const artifacts = Object.fromEntries(
    ARTIFACT_KEYS.map((name) => [
      name,
      compileArtifact(name, evidence, options),
    ]),
  );
  const allStructurallyValid = ARTIFACT_KEYS.every(
    (name) => artifacts[name].status === 'candidate',
  );
  const allEnforceable = ARTIFACT_KEYS.every(
    (name) => artifacts[name].enforceable === true,
  );
  const compiledArtifactHashes =
    artifactHashesFromCompiledArtifacts(artifacts);
  const cleanAuditRuns = Array.from(new Set(
    (evidence.runProvenance || [])
      .filter((run) => {
        const auditEvaluation = evaluateAuditEvaluation(
          run.auditEvaluation,
          compiledArtifactHashes,
        );
        return (
          run.mode === 'audit'
          && run.cleanAudit === true
          && run.complete === true
          && run.promotionEligible === true
          && run.manifestVerified === true
          && Number(run.lostEvents || 0) === 0
          && Number(run.wouldDenyCount || 0) === 0
          && (!Array.isArray(run.gaps) || run.gaps.length === 0)
          && auditEvaluation.clean
        );
      })
      .map((run) => run.runId),
  )).sort();
  const cleanAuditThreshold = Math.max(
    DEFAULT_CLEAN_AUDIT_THRESHOLD,
    Number.isSafeInteger(options.cleanAuditThreshold)
      ? options.cleanAuditThreshold
      : DEFAULT_CLEAN_AUDIT_THRESHOLD,
  );
  const allInputsManifested = evidence.ingestion?.manifestCount > 0
    && evidence.ingestion?.directInputCount === 0
    && evidence.ingestion?.promotionInputEligible === true
    && (evidence.runProvenance || []).every((run) => run.manifestVerified === true);
  const profile = canonicalize({
    apiVersion: API_VERSION,
    kind: PROFILE_KIND,
    metadata: {
      name: profileName(evidence, options),
      annotations: {
        'notty.dev/candidate': 'true',
        'notty.dev/review-required': 'true',
      },
    },
    spec: {
      target: {
        ...(evidence.subject?.containerId
          ? { containerId: evidence.subject.containerId }
          : {}),
        ...(evidence.subject?.name ? { containerName: evidence.subject.name } : {}),
        ...(evidence.subject?.image ? { image: evidence.subject.image } : {}),
        ...(options.imageDigest || evidence.subject?.imageDigest
          ? { imageDigest: String(options.imageDigest || evidence.subject.imageDigest) }
          : {}),
        ...(options.role ? { role: String(options.role) } : {}),
        ...(options.architecture ? { architecture: String(options.architecture) } : {}),
        ...(options.kernel ? { kernel: String(options.kernel) } : {}),
        identityUse: 'provenance-only',
      },
      lifecycle: {
        phase: 'candidate',
        reviewRequired: true,
        automaticApply: false,
        sensorOutputAuthoritative: false,
        structurallyValid: allStructurallyValid,
        enforcementReady: allStructurallyValid && allEnforceable,
      },
      promotion: {
        automatic: false,
        requiresHumanApproval: true,
        cleanAuditThreshold,
        cleanAuditRuns,
        cleanAuditRunCount: cleanAuditRuns.length,
        allInputsManifested,
        thresholdSatisfied:
          allInputsManifested && cleanAuditRuns.length >= cleanAuditThreshold,
      },
      evidenceHash: sha256(serializeJson(evidence)),
      evidence,
      artifacts: Object.fromEntries(
        ARTIFACT_KEYS.map((name) => [name, artifactDescriptor(artifacts[name])]),
      ),
    },
  });
  return {
    status: 'candidate',
    profile,
    artifacts,
  };
}
