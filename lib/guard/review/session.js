import fs from 'node:fs/promises';
import path from 'node:path';
import crypto from 'node:crypto';
import { readReviewBundleArtifact } from './bundle-store.js';
import { loadRuntimeEgressCandidate } from './runtime-adapter.js';
import { readTrustedJson } from './io.js';
import { validateDecisionSet } from './documents.js';
import { nonApprovableSbomDomains, reviewApprovalBlockers } from './approval-service.js';
import { createPolicyProjectionArtifact } from './projection-service.js';
import { jcsCanonicalize } from './jcs.js';
import { loadSbom } from './sbom.js';

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
  const readiness = { readyForReview: true, blockers: reviewApprovalBlockers(review) };
  readiness.readyForReview = readiness.blockers.length === 0;
  const preflight = readiness.blockers.map(blocker => `${blocker.message}. ${blocker.action}`);
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
    preflight, readiness,
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

async function readReviewSelection(directory, expectedDigest) {
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
  return { session, review, decisions, candidate, context };
}

export async function checkReviewSession(directory, expectedDigest = null, currentSourceFile = null) {
  const session = await loadReviewSession(directory);
  const review = await readReviewBundleArtifact(session.bundle);
  const candidate = await loadRuntimeEgressCandidate(session.runtimeCandidate);
  if (candidate.imageDigest !== session.imageDigest || candidate.workspace !== session.workdir
      || candidate.revision !== session.revision || review.graph.contentDigest !== session.graphContentDigest) {
    throw new Error('Review readiness identity changed');
  }
  let blockers = reviewApprovalBlockers(review);
  let readyForReview = blockers.length === 0;
  if (expectedDigest) {
    // Reject incomplete inventories as actionable prerequisites, then reuse the
    // exact snapshot and compiler validation without writing or signing anything.
    if (!nonApprovableSbomDomains(review.graph).length) {
      const { decisions, context } = await readReviewSelection(directory, expectedDigest);
      try {
        const projection = await createPolicyProjectionArtifact({ bundle: session.bundle,
          decisions: path.join(directory, 'decisions', 'decisions.json'), target: 'guard-ebpf', context });
        blockers = reviewApprovalBlockers(review, decisions, projection);
      } catch (error) {
        blockers.push({ code: 'projection', message: error.message, action: 'Reopen review and resolve target requirements before Apply.' });
      }
    }
  }
  if (currentSourceFile) {
    try {
      const current = await loadSbom(currentSourceFile);
      assertCurrentSourceInventory(review.graph, current.normalized.collection);
    } catch (error) {
      readyForReview = false;
      blockers.push({ code: 'source-inventory', message: error.message,
        action: 'Reopen review to collect current inventories and review the restored draft.' });
    }
  }
  return { schemaVersion: 1, session: directory, workspace: session.workdir,
    revision: session.revision, imageDigest: session.imageDigest,
    graphContentDigest: review.graph.contentDigest, decisionDigest: expectedDigest,
    readyForReview, readyForApply: Boolean(expectedDigest) && blockers.length === 0, blockers };
}

export async function snapshotReviewSelection(directory, expectedDigest, output) {
  const { session, review, decisions, context } = await readReviewSelection(directory, expectedDigest);
  const currentSource = await loadSbom(path.join(output, 'current-source', 'source.spdx.json'));
  assertCurrentSourceInventory(review.graph, currentSource.normalized.collection);
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

export function assertCurrentSourceInventory(graph, current) {
  const sources = graph.nodes.filter(node => node.nodeType === 'evidenceSource' && node.identity?.role === 'source');
  const reviewed = sources.length === 1 ? sources[0].properties?.collection : null;
  if (!reviewed || !current || current.role !== 'source' || current.status !== 'complete'
      || !reviewed.input?.metadataDigest || reviewed.input.metadataDigest !== current.input?.metadataDigest) {
    throw new Error('Source inventory changed or is incomplete. Reopen review to collect current inventories and review the updated draft.');
  }
}

export function rebaseReviewDraft(previous, oldGraph, graph) {
  if (previous?.kind !== 'NoshPolicyReviewDraft' || previous.schemaVersion !== 1
      || previous.graphContentDigest !== oldGraph.contentDigest
      || !previous.decisions || Array.isArray(previous.decisions)) throw new Error('Prior draft does not match its verified graph');
  const old = new Map(oldGraph.proposals.map(proposal => [proposal.id, proposal]));
  let retained = 0;
  const decisions = Object.fromEntries(graph.proposals.map(proposal => {
    const before = old.get(proposal.id);
    const choice = previous.decisions[proposal.id];
    const unchanged = before && jcsCanonicalize(before) === jcsCanonicalize(proposal)
      && ['accept', 'reject'].includes(choice?.disposition)
      && typeof choice.rationale === 'string' && choice.rationale.length <= 4096;
    if (unchanged) retained += 1;
    return [proposal.id, { disposition: unchanged ? choice.disposition : 'needs-review',
      rationale: unchanged ? choice.rationale : '', targetAcknowledgements: {} }];
  }));
  const bounded = (value, maximum) => typeof value === 'string' && value.length <= maximum ? value : '';
  return { retained, draft: { kind: 'NoshPolicyReviewDraft', schemaVersion: 1,
    graphContentDigest: graph.contentDigest, profileName: bounded(previous.profileName, 128),
    reviewer: bounded(previous.reviewer, 256), reviewerAcknowledged: false,
    intendedTarget: 'guard-ebpf', decisions } };
}

export async function migrateReviewDraft(directory, source = null) {
  const session = await loadReviewSession(directory);
  const review = await readReviewBundleArtifact(session.bundle);
  for (const name of ['draft.json', 'decisions.json']) {
    try { await fs.lstat(path.join(directory, 'decisions', name)); return { status: 'existing', session: directory }; }
    catch (error) { if (error.code !== 'ENOENT') throw error; }
  }
  const candidates = [];
  const entries = source ? [path.basename(source)] : (await fs.readdir(path.dirname(directory))).slice(0, 256);
  if (source && path.dirname(source) !== path.dirname(directory)) throw new Error('Prior session must be in the same review store');
  for (const name of entries) {
    const prior = path.join(path.dirname(directory), name);
    if (prior === directory) continue;
    try {
      const previousSession = await loadReviewSession(prior);
      if (['runtimeCandidate', 'workdir', 'imageDigest', 'revision'].some(key => previousSession[key] !== session[key])) continue;
      const previousReview = await readReviewBundleArtifact(previousSession.bundle);
      // UI-only rebuilds reuse the exact session through the launcher. Updated
      // policy tooling must restore choices as a draft even if its graph is
      // byte-for-byte identical, so the operator reviews under the new tooling.
      if (previousReview.graph.contentDigest === review.graph.contentDigest
          && previousSession.toolingImage === session.toolingImage) continue;
      let previous;
      try { previous = (await readTrustedJson(path.join(prior, 'decisions', 'draft.json'), { maximumBytes: 8 * 1024 * 1024 })).document; }
      catch (error) {
        if (error.code !== 'ENOENT') throw error;
        const { document } = await readTrustedJson(path.join(prior, 'decisions', 'decisions.json'), { maximumBytes: 8 * 1024 * 1024 });
        validateDecisionSet(document);
        if (document.graphContentDigest !== previousReview.graph.contentDigest) continue;
        previous = { kind: 'NoshPolicyReviewDraft', schemaVersion: 1,
          graphContentDigest: document.graphContentDigest, reviewer: document.reviewer,
          decisions: Object.fromEntries(document.decisions.map(choice => [choice.proposalId, choice])) };
      }
      const migrated = rebaseReviewDraft(previous, previousReview.graph, review.graph);
      if (migrated.retained) candidates.push({ source: prior, ...migrated });
    } catch (error) { if (source) throw error; }
  }
  if (candidates.length !== 1) return { status: candidates.length ? 'choose-source' : 'none',
    candidates: candidates.map(candidate => candidate.source), session: directory };
  const chosen = candidates[0];
  await fs.writeFile(path.join(directory, 'decisions', 'draft.json'), `${JSON.stringify(chosen.draft, null, 2)}\n`, { flag: 'wx', mode: 0o600 });
  return { status: 'migrated', source: chosen.source, retained: chosen.retained, session: directory,
    message: 'Unchanged selections restored as a draft. Review and acknowledge again before saving.' };
}
