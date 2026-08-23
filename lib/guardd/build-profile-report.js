import {
  BUILD_ARTIFACT_KINDS,
  BUILD_PROFILE_API_VERSION,
  BUILD_PROFILE_SCHEMA_VERSION,
  portableBuildProjection,
  redactBuildValue,
  validateBuildEvidenceManifest,
  verifyBuildCandidate,
} from './build-profile-artifacts.js';

function formatDuration(milliseconds) {
  if (!Number.isFinite(milliseconds)) return 'unknown';
  if (milliseconds < 1_000) return `${milliseconds} ms`;
  return `${(milliseconds / 1_000).toFixed(2)} s`;
}

function passSummary(pass) {
  return {
    name: pass.name,
    success: pass.success,
    exitCode: pass.exitCode,
    durationMs: pass.durationMs,
    cache: pass.cache,
  };
}

export function createBuildProfileReport(manifest, candidate = null) {
  validateBuildEvidenceManifest(manifest);
  if (candidate) verifyBuildCandidate(candidate, manifest);
  const required = manifest.sources.filter((source) => source.required);
  const cold = manifest.build.passes.find((pass) => pass.name === 'cold');
  const warm = manifest.build.passes.find((pass) => pass.name === 'warm');
  const comparison = cold && warm
    ? {
        coldDurationMs: cold.durationMs,
        warmDurationMs: warm.durationMs,
        speedupRatio: cold.durationMs != null
          && warm.durationMs != null
          && warm.durationMs > 0
          ? Number((cold.durationMs / warm.durationMs).toFixed(4))
          : null,
      }
    : null;
  return {
    schemaVersion: BUILD_PROFILE_SCHEMA_VERSION,
    apiVersion: BUILD_PROFILE_API_VERSION,
    kind: 'NoshBuildProfileReport',
    generatedAt: manifest.generatedAt,
    runId: manifest.runId,
    mode: manifest.mode,
    projectKey: manifest.project.key,
    status: manifest.complete ? 'complete' : 'incomplete',
    candidate: candidate
      ? {
          kind: candidate.kind,
          generated: true,
          advanced: manifest.candidateEligible,
          contentHash: candidate.contentHash,
        }
      : {
          kind: manifest.mode === 'build-profile'
            ? BUILD_ARTIFACT_KINDS.profileCandidate
            : BUILD_ARTIFACT_KINDS.networkCandidate,
          generated: false,
          advanced: false,
          contentHash: null,
        },
    build: {
      success: manifest.build.success,
      exitCode: manifest.build.exitCode,
      platform: manifest.build.platform,
      cacheMode: manifest.build.cacheMode,
      depth: manifest.build.depth,
      durationMs: manifest.build.durationMs,
      outputImageDigest: manifest.build.outputImageDigest,
      outputImageDigestUse: 'informational-only',
      passes: manifest.build.passes.map(passSummary),
      comparison,
    },
    evidence: {
      complete: manifest.complete,
      candidateEligible: manifest.candidateEligible,
      requiredSources: required.length,
      completeRequiredSources: required.filter(
        (source) =>
          source.present
          && source.complete
          && source.lostEvents === 0
          && source.parseErrors === 0,
      ).length,
      lostEvents: required.reduce((sum, source) => sum + source.lostEvents, 0),
      parseErrors: required.reduce((sum, source) => sum + source.parseErrors, 0),
      incompleteReasons: [...manifest.incompleteReasons],
      candidateIneligibleReasons: [...manifest.candidateIneligibleReasons],
    },
    metrics: manifest.metrics,
    limitations: [...manifest.limitations],
    authoritative: false,
    attested: false,
  };
}

export function renderBuildProfileReport(manifest, candidate = null) {
  const report = createBuildProfileReport(manifest, candidate);
  const lines = [
    `Nosh build ${report.mode === 'build-profile' ? 'profile' : 'network learning'}: ${report.runId}`,
    `Status: ${report.status}`,
    `Candidate: ${report.candidate.generated ? 'generated (unapproved)' : 'not generated'}`,
    `Platform: ${report.build.platform}`,
    `Build: ${report.build.success ? 'succeeded' : 'failed'} (exit ${report.build.exitCode})`,
    `Duration: ${formatDuration(report.build.durationMs)}`,
    `Evidence: ${report.evidence.completeRequiredSources}/${report.evidence.requiredSources} required sources complete`,
  ];
  if (report.build.comparison) {
    lines.push(
      `Cold/warm: ${formatDuration(report.build.comparison.coldDurationMs)} / ${formatDuration(report.build.comparison.warmDurationMs)}`,
    );
    if (report.build.comparison.speedupRatio != null) {
      lines.push(`Warm-cache speedup: ${report.build.comparison.speedupRatio}x`);
    }
  }
  if (report.build.outputImageDigest) {
    lines.push(`Output image (informational): ${report.build.outputImageDigest}`);
  }
  if (report.evidence.candidateIneligibleReasons.length) {
    lines.push('Candidate not advanced:');
    for (const reason of report.evidence.candidateIneligibleReasons) {
      lines.push(`  - ${reason}`);
    }
  }
  lines.push('Attestation: none (integrity hashes only)');
  return `${lines.join('\n')}\n`;
}

export function createPortableBuildReport(manifest, candidate = null) {
  const portable = portableBuildProjection(manifest, candidate);
  const report = createBuildProfileReport(manifest, candidate);
  return {
    ...portable,
    summary: {
      status: report.status,
      candidate: report.candidate,
      comparison: report.build.comparison,
      requiredSources: report.evidence.requiredSources,
      completeRequiredSources: report.evidence.completeRequiredSources,
      lostEvents: report.evidence.lostEvents,
      parseErrors: report.evidence.parseErrors,
    },
  };
}

export function renderPortableBuildReport(manifest, candidate = null) {
  const report = createBuildProfileReport(manifest, candidate);
  const reasons = redactBuildValue(report.evidence.candidateIneligibleReasons);
  const lines = [
    `Nosh build ${report.mode === 'build-profile' ? 'profile' : 'network learning'}: ${report.runId}`,
    `Status: ${report.status}`,
    `Candidate: ${report.candidate.generated ? 'generated (unapproved)' : 'not generated'}`,
    `Platform: ${report.build.platform}`,
    `Build: ${report.build.success ? 'succeeded' : 'failed'} (exit ${report.build.exitCode})`,
    `Duration: ${formatDuration(report.build.durationMs)}`,
    `Evidence: ${report.evidence.completeRequiredSources}/${report.evidence.requiredSources} required sources complete`,
  ];
  if (report.build.comparison) {
    lines.push(
      `Cold/warm: ${formatDuration(report.build.comparison.coldDurationMs)} / ${formatDuration(report.build.comparison.warmDurationMs)}`,
    );
  }
  if (reasons.length) {
    lines.push('Candidate not advanced:');
    for (const reason of reasons) lines.push(`  - ${reason}`);
  }
  lines.push('Attestation: none (integrity hashes only)');
  return `${lines.join('\n')}\n`;
}
