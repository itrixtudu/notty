import path from 'node:path';

import { readReviewBundleArtifact } from './bundle-store.js';
import { validateDecisionSet } from './documents.js';
import {
  readPrivateSigningKey,
  readTrustedJson,
  writeArtifactDirectory,
} from './io.js';
import { jcsCanonicalize, sha256Digest } from './jcs.js';
import { readPolicyLeafArtifact } from './leaf-store.js';
import {
  createDsseEnvelope,
  createReviewApprovalStatement,
  ed25519KeyId,
  REVIEW_APPROVAL_PAYLOAD_TYPE,
  validateReviewApprovalStatement,
  verifyDsseEnvelope,
} from './signing.js';

const REQUIRED_SBOM_COVERAGE = Object.freeze(['sbom-source', 'sbom-image']);

export function nonApprovableSbomDomains(graph) {
  const coverage = Array.isArray(graph?.coverage) ? graph.coverage : [];
  return REQUIRED_SBOM_COVERAGE.filter((domain) => {
    const markers = coverage.filter((entry) => entry.domain === domain);
    return markers.length !== 1 || markers[0].status !== 'complete';
  });
}

function assertApprovalBindings(review, decisions, policy) {
  validateDecisionSet(decisions);
  const bindings = {
    graphDigest: review.bundle.graphDigest,
    graphContentDigest: review.graph.contentDigest,
    proposalSetDigest: review.bundle.proposalSetDigest,
    basePolicyDigest: review.bundle.basePolicyDigest,
    scopeDigest: review.bundle.scope.scopeDigest,
  };
  for (const [name, expected] of Object.entries(bindings)) {
    if (decisions[name] !== expected) {
      throw new Error(`decision set ${name} does not bind the review bundle`);
    }
  }
  if (
    policy.policyIR.graphDigest !== review.bundle.graphDigest
    || policy.policyIR.graphContentDigest !== review.graph.contentDigest
    || policy.policyIR.proposalSetDigest !== review.bundle.proposalSetDigest
    || policy.policyIR.basePolicyDigest !== review.bundle.basePolicyDigest
    || policy.policyIR.scope.scopeDigest !== review.bundle.scope.scopeDigest
    || policy.policyIR.decisionSetDigest !== decisions.contentDigest
  ) {
    throw new Error('policy leaf does not bind the review bundle and decision set');
  }
}

function assertApprovalGate(review, decisions, policy) {
  const coverage = review.graph.coverage.filter(
    (entry) => entry.blocking && entry.status !== 'complete',
  );
  const missingSboms = nonApprovableSbomDomains(review.graph);
  const findings = review.graph.findings.filter((entry) => entry.blocking);
  const pending = decisions.decisions.filter((entry) => entry.disposition === 'needs-review');
  if (coverage.length) throw new Error(`review has ${coverage.length} blocking coverage gaps`);
  if (missingSboms.length) {
    throw new Error(
      `review has ${missingSboms.length} non-approvable missing SBOM coverage gaps`,
    );
  }
  if (findings.length) throw new Error(`review has ${findings.length} blocking findings`);
  if (pending.length) throw new Error(`review has ${pending.length} pending decisions`);
  if (!policy.leaf.activationEligible) {
    throw new Error('target projection is not activation eligible');
  }
}

export async function createReviewApprovalArtifact(input) {
  const review = await readReviewBundleArtifact(input.bundle);
  const decisions = (await readTrustedJson(path.resolve(input.decisions), {
    maximumBytes: 16 * 1024 * 1024,
    allowGroupRead: true,
  })).document;
  const policy = await readPolicyLeafArtifact(input.policy);
  assertApprovalBindings(review, decisions, policy);
  assertApprovalGate(review, decisions, policy);
  if (input.reviewer !== decisions.reviewer) {
    throw new Error('approval reviewer must match the decision-set reviewer');
  }
  if (input.confirmation !== policy.targetReviewSet.contentDigest) {
    throw new Error('confirmation must exactly match the target review set digest');
  }
  const privateKey = await readPrivateSigningKey(path.resolve(input.privateKey));
  const statement = createReviewApprovalStatement({
    issuedAt: input.createdAt,
    reviewer: input.reviewer,
    audience: input.audience,
    bundleDigest: review.bundle.bundleDigest,
    graphDigest: review.bundle.graphDigest,
    proposalSetDigest: review.bundle.proposalSetDigest,
    decisionSetDigest: decisions.contentDigest,
    policyIrDigest: policy.policyIR.contentDigest,
    targetReviewSetDigest: policy.targetReviewSet.contentDigest,
    baselineDigest: review.bundle.baseline.bundleDigest,
    scopeDigest: review.bundle.scope.scopeDigest,
    confirmationDigest: sha256Digest(input.confirmation),
  });
  const envelope = createDsseEnvelope(
    REVIEW_APPROVAL_PAYLOAD_TYPE,
    statement,
    privateKey,
  );
  const receipt = {
    apiVersion: 'notty.dev/v1alpha1',
    kind: 'NoshReviewApprovalReceipt',
    schemaVersion: 1,
    createdAt: statement.issuedAt,
    reviewer: statement.reviewer,
    audience: statement.audience,
    keyId: ed25519KeyId(privateKey),
    approvalEnvelopeDigest: sha256Digest(jcsCanonicalize(envelope)),
    leafBundleDigest: policy.leaf.bundleDigest,
    ...Object.fromEntries([
      'bundleDigest',
      'graphDigest',
      'proposalSetDigest',
      'decisionSetDigest',
      'policyIrDigest',
      'targetReviewSetDigest',
      'baselineDigest',
      'scopeDigest',
      'confirmationDigest',
    ].map((key) => [key, statement[key]])),
  };
  return Object.freeze({
    review,
    decisions,
    policy,
    statement,
    envelope,
    receipt,
    artifacts: Object.freeze({
      'approval-envelope.dsse.json': `${jcsCanonicalize(envelope)}\n`,
      'approval-receipt.json': `${jcsCanonicalize(receipt)}\n`,
    }),
  });
}

export async function writeReviewApprovalArtifact(directory, artifact) {
  const written = await writeArtifactDirectory(path.resolve(directory), artifact.artifacts, {
    maximumBytes: 16 * 1024 * 1024,
  });
  return { ...written, receipt: artifact.receipt };
}

export async function verifyReviewApproval(input) {
  if (
    typeof input.audience !== 'string'
    || !input.audience.trim()
    || input.audience.length > 255
    || /[\u0000-\u001f\u007f]/.test(input.audience)
  ) {
    throw new TypeError('review approval verification requires an exact audience');
  }
  const envelope = (await readTrustedJson(path.resolve(input.envelope), {
    maximumBytes: 16 * 1024 * 1024,
    allowGroupRead: true,
  })).document;
  const verified = verifyDsseEnvelope(envelope, {
    payloadType: REVIEW_APPROVAL_PAYLOAD_TYPE,
    trustedKeys: input.trustedKeys,
    role: 'review-approval',
    audience: input.audience,
  });
  if (
    verified.statement.kind !== 'NoshReviewApprovalStatement'
    || verified.statement.apiVersion !== 'notty.dev/v1alpha1'
    || verified.statement.schemaVersion !== 1
  ) {
    throw new Error('review approval statement has an unsupported type');
  }
  validateReviewApprovalStatement(verified.statement, {
    audience: input.audience,
  });
  return verified;
}
