import fs from 'node:fs/promises';
import path from 'node:path';
import crypto from 'node:crypto';
import { readReviewBundleArtifact } from './bundle-store.js';
import { loadRuntimeEgressCandidate } from './runtime-adapter.js';
import { readTrustedJson } from './io.js';
import { validateDecisionSet } from './documents.js';
import { nonApprovableSbomDomains } from './approval-service.js';

export async function atomicSessionJson(file, document) {
  const temporary = `${file}.${crypto.randomUUID()}.tmp`;
  try {
    await fs.writeFile(temporary, `${JSON.stringify(document, null, 2)}\n`, { flag: 'wx', mode: 0o600 });
    await fs.rename(temporary, file);
  } finally { await fs.rm(temporary, { force: true }); }
}

export async function privateSessionDirectory(directory) {
  const resolved = path.resolve(directory);
  if (await fs.realpath(resolved) !== resolved) throw new Error('Review session path contains a symlink');
  const stat = await fs.lstat(resolved);
  if (!stat.isDirectory() || stat.uid !== process.geteuid() || (stat.mode & 0o077)) {
    throw new Error('Review session directory must be caller-owned mode 0700');
  }
  return resolved;
}

export async function prepareReviewSession(input) {
  const directory = await privateSessionDirectory(input.session);
  const review = await readReviewBundleArtifact(input.bundle);
  const candidate = input.candidate ? await loadRuntimeEgressCandidate(input.candidate) : null;
  if (candidate && (candidate.workspace !== input.workdir
    || candidate.imageDigest !== review.graph.scope.imageDigest)) {
    throw new Error('Review session does not bind the learned workspace and image');
  }
  const preflight = nonApprovableSbomDomains(review.graph).map(role =>
    `${role} is missing. Supply source and exact-image SBOMs when opening review; signing remains blocked.`);
  if (input.configAvailable !== 'yes') preflight.push(
    `Signing configuration is missing: ${input.applyConfig}. See docs/nosh-policy-review.md (Saved runtime profiles).`);
  const session = {
    kind: 'NoshPolicyReviewSession', schemaVersion: 1, directory,
    bundle: path.resolve(input.bundle), workdir: input.workdir,
    profileName: path.basename(input.workdir), revision: candidate?.revision || review.bundle.bundleId,
    runtimeCandidate: candidate?.directory || null, targetContext: input.context || null,
    imageDigest: candidate?.imageDigest || review.graph.scope.imageDigest || null,
    graphContentDigest: review.graph.contentDigest, graphDigest: review.graph.graphDigest,
    launcher: input.launcher, toolingImage: input.tooling, applyConfig: input.applyConfig,
    sbomSource: input.sbomSource || null, sbomImage: input.sbomImage || null,
    preflight,
  };
  await atomicSessionJson(path.join(directory, 'runtime', 'review.graph.json'), review.graph);
  await atomicSessionJson(path.join(directory, 'runtime', 'review-session.json'), session);
  return session;
}

export async function loadReviewSession(directory) {
  directory = await privateSessionDirectory(directory);
  const { document: session } = await readTrustedJson(path.join(directory, 'runtime', 'review-session.json'));
  if (session.kind !== 'NoshPolicyReviewSession' || session.schemaVersion !== 1
      || session.directory !== directory || session.bundle !== path.join(directory, 'bundle')
      || !session.runtimeCandidate || !session.targetContext
      || !/^sha256:[a-f0-9]{64}$/.test(session.toolingImage || '')) {
    throw new Error('A valid runtime review session is required');
  }
  return session;
}

export async function snapshotReviewSelection(directory, expectedDigest, output) {
  const session = await loadReviewSession(directory);
  const review = await readReviewBundleArtifact(session.bundle);
  const { document: decisions } = await readTrustedJson(path.join(directory, 'decisions', 'decisions.json'), {
    maximumBytes: 8 * 1024 * 1024,
  });
  validateDecisionSet(decisions);
  if (!/^sha256:[a-f0-9]{64}$/.test(expectedDigest || '') || decisions.contentDigest !== expectedDigest) {
    throw new Error('Saved decisions changed. Save the profile and copy its new Apply command.');
  }
  for (const [key, value] of Object.entries({ graphDigest: review.graph.graphDigest,
    graphContentDigest: review.graph.contentDigest, proposalSetDigest: review.graph.proposalSetDigest,
    basePolicyDigest: review.graph.basePolicyDigest, scopeDigest: review.graph.scope.scopeDigest })) {
    if (decisions[key] !== value) throw new Error(`Saved decisions have a stale ${key}`);
  }
  if (session.graphContentDigest !== review.graph.contentDigest) throw new Error('Session graph changed');
  const proposals = new Set(review.graph.proposals.map(proposal => proposal.id));
  if (decisions.decisions.length !== proposals.size || decisions.decisions.some(decision =>
    !proposals.delete(decision.proposalId) || decision.disposition === 'needs-review')) {
    throw new Error('Every proposal must have exactly one completed decision');
  }
  const candidate = await loadRuntimeEgressCandidate(session.runtimeCandidate);
  if (candidate.imageDigest !== session.imageDigest || candidate.workspace !== session.workdir
    || candidate.revision !== session.revision) throw new Error('Learned runtime identity changed');
  const sboms = nonApprovableSbomDomains(review.graph);
  if (sboms.length) throw new Error(`Cannot apply: missing ${sboms.join(', ')}. Reopen review with source and image SBOMs.`);
  const { document: context } = await readTrustedJson(session.targetContext);
  await privateSessionDirectory(output);
  // All downstream phases operate on this snapshot, never on browser-writable files.
  await fs.cp(session.bundle, path.join(output, 'bundle'), { recursive: true, errorOnExist: true, force: false });
  await atomicSessionJson(path.join(output, 'decisions.json'), decisions);
  await atomicSessionJson(path.join(output, 'target-context.json'), context);
  await atomicSessionJson(path.join(output, 'session.json'), session);
  // Reverify the copied bundle, including every hash-addressed stream.
  await readReviewBundleArtifact(path.join(output, 'bundle'));
  return { session, reviewer: decisions.reviewer, decisionDigest: decisions.contentDigest };
}
