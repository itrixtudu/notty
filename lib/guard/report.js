import { REPORT_KIND, API_VERSION } from './constants.js';
import {
  canonicalize,
  escapeHtml,
  serializeJson,
  sortedUniqueStrings,
} from './stable.js';

function unpack(value) {
  if (value?.profile && value?.artifacts) {
    return value;
  }
  if (value?.kind === 'NoshSecurityProfile') {
    return {
      profile: value,
      artifacts: value.spec?.artifacts || {},
    };
  }
  throw new TypeError('report input must be a compiled guard result or NoshSecurityProfile');
}

function observationCounts(evidence) {
  const observations = evidence?.observations || {};
  return {
    executables: (observations.executables || []).length,
    syscalls: (observations.syscalls || []).length,
    files: (observations.files || []).length,
    network: (observations.network || []).length,
    capabilities: (observations.capabilities || []).length,
    mounts: (observations.mounts || []).length,
    advisoryEvidence: (evidence?.advisoryEvidence || []).length,
  };
}

export function createProfileReport(value) {
  const { profile, artifacts } = unpack(value);
  const artifactEntries = Object.entries(artifacts)
    .sort(([left], [right]) => (left === right ? 0 : left < right ? -1 : 1))
    .map(([name, entry]) => ({
      name,
      status: entry.status,
      enforceable: entry.enforceable === true,
      hash: entry.hash,
      fileName: entry.fileName,
      errors: sortedUniqueStrings(entry.errors || []),
      warnings: sortedUniqueStrings(entry.warnings || []),
    }));
  const evidence = profile.spec?.evidence || {};
  const findings = [
    ...(evidence.warnings || []).map((message) => ({
      severity: 'warning',
      artifact: 'evidence',
      message,
    })),
    ...artifactEntries.flatMap((entry) => [
      ...entry.errors.map((message) => ({
        severity: 'error',
        artifact: entry.name,
        message,
      })),
      ...entry.warnings.map((message) => ({
        severity: 'warning',
        artifact: entry.name,
        message,
      })),
    ]),
  ].sort((left, right) => (
    (left.severity === right.severity ? 0 : left.severity < right.severity ? -1 : 1)
    || (left.artifact === right.artifact ? 0 : left.artifact < right.artifact ? -1 : 1)
    || (left.message === right.message ? 0 : left.message < right.message ? -1 : 1)
  ));
  return canonicalize({
    apiVersion: API_VERSION,
    kind: REPORT_KIND,
    metadata: {
      name: profile.metadata?.name || 'nosh-guard-profile',
    },
    summary: {
      phase: profile.spec?.lifecycle?.phase || 'candidate',
      reviewRequired: profile.spec?.lifecycle?.reviewRequired !== false,
      enforcementReady: profile.spec?.lifecycle?.enforcementReady === true,
      sensorOutputAuthoritative: false,
      artifactCount: artifactEntries.length,
      validArtifactCount: artifactEntries.filter((entry) => entry.status === 'candidate').length,
      enforceableArtifactCount: artifactEntries.filter((entry) => entry.enforceable).length,
      observationCounts: observationCounts(evidence),
      promotion: {
        cleanAuditThreshold: profile.spec?.promotion?.cleanAuditThreshold || 3,
        cleanAuditRunCount: profile.spec?.promotion?.cleanAuditRunCount || 0,
        allInputsManifested: profile.spec?.promotion?.allInputsManifested === true,
        thresholdSatisfied: profile.spec?.promotion?.thresholdSatisfied === true,
      },
    },
    artifacts: artifactEntries,
    findings,
    safety: {
      automaticApply: false,
      statement: 'Observed sensor output is evidence, not approval. Review and independently validate every artifact before enforcement.',
    },
  });
}

export function generateJsonReport(value) {
  return serializeJson(createProfileReport(value));
}

function renderFindings(findings) {
  if (!findings.length) {
    return '<p>No structural findings.</p>';
  }
  return [
    '<ul class="findings">',
    ...findings.map((finding) => (
      `<li class="${escapeHtml(finding.severity)}"><strong>${escapeHtml(finding.artifact)}</strong>: ${escapeHtml(finding.message)}</li>`
    )),
    '</ul>',
  ].join('\n');
}

export function generateHtmlReport(value) {
  const report = createProfileReport(value);
  const rows = report.artifacts.map((artifact) => [
    '<tr>',
    `<td>${escapeHtml(artifact.name)}</td>`,
    `<td>${escapeHtml(artifact.status)}</td>`,
    `<td>${artifact.enforceable ? 'yes' : 'no'}</td>`,
    `<td><code>${escapeHtml(artifact.hash || '')}</code></td>`,
    `<td>${escapeHtml(artifact.fileName || '')}</td>`,
    '</tr>',
  ].join('')).join('\n');
  const counts = report.summary.observationCounts;
  return [
    '<!doctype html>',
    '<html lang="en">',
    '<head>',
    '<meta charset="utf-8">',
    '<meta name="viewport" content="width=device-width, initial-scale=1">',
    '<meta http-equiv="Content-Security-Policy" content="default-src \'none\'; style-src \'unsafe-inline\'; base-uri \'none\'; form-action \'none\'">',
    `<title>${escapeHtml(report.metadata.name)} security profile report</title>`,
    '<style>',
    'body{font-family:system-ui,sans-serif;max-width:1100px;margin:2rem auto;padding:0 1rem;color:#171717;background:#fff}',
    'h1,h2{line-height:1.2}table{border-collapse:collapse;width:100%}th,td{border:1px solid #bbb;padding:.5rem;text-align:left;vertical-align:top}',
    'th{background:#eee}code{font-size:.8rem;overflow-wrap:anywhere}.notice{border-left:4px solid #a35b00;background:#fff6df;padding:.8rem}',
    '.error{color:#9b1c1c}.warning{color:#6f4700}.facts{display:flex;flex-wrap:wrap;gap:1rem}.facts span{background:#eee;padding:.35rem .6rem}',
    '</style>',
    '</head>',
    '<body>',
    `<h1>${escapeHtml(report.metadata.name)} security profile</h1>`,
    `<p class="notice">${escapeHtml(report.safety.statement)}</p>`,
    '<div class="facts">',
    `<span>Phase: ${escapeHtml(report.summary.phase)}</span>`,
    `<span>Review required: ${report.summary.reviewRequired ? 'yes' : 'no'}</span>`,
    `<span>Enforcement ready: ${report.summary.enforcementReady ? 'yes' : 'no'}</span>`,
    `<span>Clean audits: ${report.summary.promotion.cleanAuditRunCount}/${report.summary.promotion.cleanAuditThreshold}</span>`,
    '</div>',
    '<h2>Observed surface</h2>',
    `<p>${counts.executables} executables, ${counts.syscalls} syscalls, ${counts.files} file paths, ${counts.network} network peers, ${counts.capabilities} capabilities, ${counts.mounts} mounts, and ${counts.advisoryEvidence} advisory-only records.</p>`,
    '<h2>Artifacts</h2>',
    '<table><thead><tr><th>Artifact</th><th>Status</th><th>Enforceable</th><th>Hash</th><th>File</th></tr></thead>',
    `<tbody>${rows}</tbody></table>`,
    '<h2>Findings</h2>',
    renderFindings(report.findings),
    '</body>',
    '</html>',
    '',
  ].join('\n');
}
