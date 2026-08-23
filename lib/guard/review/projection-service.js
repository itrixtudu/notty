import path from 'node:path';

import {
  createPolicyIR,
  createTargetReviewSet,
  validateDecisionSet,
  validateTargetReviewSet,
} from './documents.js';
import { readReviewBundleArtifact } from './bundle-store.js';
import { createLeafManifest, readTrustedJson, writeArtifactDirectory } from './io.js';
import { jcsCanonicalize, sha256Digest } from './jcs.js';
import { compilePolicyTarget } from './policy-compilers.js';

const PARITY_ORDER = new Map([
  'exact',
  'restrictive',
  'conditional',
  'permissive',
  'unsupported',
  'outsideScope',
].map((value, index) => [value, index]));

function mediaType(name) {
  if (name.endsWith('.json')) return 'application/json';
  if (name.endsWith('.yaml') || name.endsWith('.yml')) return 'application/yaml';
  return 'text/plain';
}

function artifactRefs(artifacts) {
  return Object.entries(artifacts).map(([name, content]) => {
    const bytes = Buffer.from(content, 'utf8');
    return {
      name,
      mediaType: mediaType(name),
      sha256: sha256Digest(bytes),
      bytes: String(bytes.length),
    };
  }).sort((left, right) => left.name.localeCompare(right.name));
}

function compilerIdentity(target) {
  const compiler = {
    cilium: { id: 'nosh-cilium-policy-v1', version: '1' },
    'guard-ebpf': { id: 'nosh-guard-ebpf-policy-v2', version: '2' },
    'guard-nftables': { id: 'nosh-guard-nftables-policy-v1', version: '1' },
    'gateway-iptables': { id: 'nosh-gateway-iptables-policy-v1', version: '1' },
    'gateway-pf': { id: 'nosh-gateway-pf-openbsd-policy-v1', version: '1' },
    'gateway-ipfw': { id: 'nosh-gateway-ipfw-freebsd-policy-v1', version: '1' },
    'gateway-ipfilter': { id: 'nosh-gateway-ipfilter-policy-v1', version: '1' },
    'gateway-l7-proxy': { id: 'nosh-gateway-l7-proxy-policy-v1', version: '1' },
  }[target];
  if (!compiler) {
    throw new TypeError(`unsupported policy projection target: ${target}`);
  }
  const { id, version } = compiler;
  return { id, version, digest: sha256Digest({ id, version }) };
}

function projectionStatus(mappings) {
  if (!mappings.length) return 'outsideScope';
  const inScope = mappings.filter((mapping) => mapping.parity !== 'outsideScope');
  if (!inScope.length) return 'outsideScope';
  return inScope.reduce((worst, mapping) => (
    PARITY_ORDER.get(mapping.parity) > PARITY_ORDER.get(worst)
      ? mapping.parity
      : worst
  ), 'exact');
}

export function deriveTargetProjection(policyIR, compilerResult) {
  const policyRules = new Map(policyIR.rules.map((rule) => [rule.id, rule]));
  const mappings = compilerResult.projections.map((entry) => {
    const rule = policyRules.get(entry.ruleId);
    if (!rule) throw new Error(`compiler classified unknown rule ${entry.ruleId}`);
    return {
      ruleId: entry.ruleId,
      proposalId: rule.proposalId,
      pointer: entry.targetIds?.length
        ? entry.targetIds.join(' ; ')
        : `${compilerResult.target}:unrendered:${entry.ruleId}`,
      parity: entry.parity,
      reasons: [...new Set([
        ...(entry.reasons || []),
        ...(entry.preconditions || []),
      ])].sort(),
    };
  }).sort((left, right) => left.ruleId.localeCompare(right.ruleId));
  if (mappings.length !== policyIR.rules.length) {
    throw new Error('compiler did not classify every PolicyIR rule');
  }
  const status = projectionStatus(mappings);
  return {
    target: compilerResult.target,
    targetContextDigest: compilerResult.targetContextDigest,
    compiler: compilerIdentity(compilerResult.target),
    status,
    activationEligible: compilerResult.activationEligible === true,
    artifacts: artifactRefs(compilerResult.artifacts),
    ruleMappings: mappings,
    diagnostics: [...new Set(compilerResult.limitations || [])].sort(),
  };
}

function validateDecisionBindings(graph, decisions) {
  validateDecisionSet(decisions);
  const bindings = {
    scopeDigest: graph.scope.scopeDigest,
    graphDigest: graph.graphDigest,
    graphContentDigest: graph.contentDigest,
    proposalSetDigest: graph.proposalSetDigest,
    basePolicyDigest: graph.basePolicyDigest,
  };
  for (const [name, expected] of Object.entries(bindings)) {
    if (decisions[name] !== expected) {
      throw new Error(`decision set ${name} does not match the frozen review graph`);
    }
  }
  const proposals = new Set(graph.proposals.map((proposal) => proposal.id));
  if (decisions.decisions.length !== proposals.size) {
    throw new Error('decision set must decide every frozen proposal');
  }
  for (const decision of decisions.decisions) {
    if (!proposals.has(decision.proposalId)) {
      throw new Error(`decision references unknown proposal ${decision.proposalId}`);
    }
  }
}

function assertTargetAcknowledgements(decisions, projection) {
  const byProposal = new Map(decisions.decisions.map((decision) => [
    decision.proposalId,
    decision,
  ]));
  for (const mapping of projection.ruleMappings) {
    if (!['restrictive', 'conditional'].includes(mapping.parity)) continue;
    const decision = byProposal.get(mapping.proposalId);
    const acknowledgement = decision?.targetAcknowledgements?.find(
      (entry) => entry.target === projection.target && entry.status === mapping.parity,
    );
    if (!acknowledgement?.rationale) {
      throw new Error(
        `proposal ${mapping.proposalId} requires an explicit ${mapping.parity} acknowledgement for ${projection.target}`,
      );
    }
  }
}

export async function createPolicyProjectionArtifact(input) {
  const review = await readReviewBundleArtifact(input.bundle);
  const loadedDecisions = await readTrustedJson(path.resolve(input.decisions), {
    maximumBytes: 16 * 1024 * 1024,
    allowGroupRead: true,
  });
  validateDecisionBindings(review.graph, loadedDecisions.document);
  const policyIR = createPolicyIR({
    decisionSet: loadedDecisions.document,
    graph: review.graph,
    createdAt: input.createdAt,
  });
  const compilerResult = compilePolicyTarget(input.target, policyIR, input.context);
  const projection = deriveTargetProjection(policyIR, compilerResult);
  assertTargetAcknowledgements(loadedDecisions.document, projection);
  const targetReviewSet = createTargetReviewSet({
    policyIR,
    projections: [projection],
    createdAt: input.createdAt,
  });
  validateTargetReviewSet(targetReviewSet, { policyIR });
  const controlArtifacts = {
    'policy-ir.json': `${jcsCanonicalize(policyIR)}\n`,
    'projection.json': `${jcsCanonicalize(compilerResult)}\n`,
    'target-review-set.json': `${jcsCanonicalize(targetReviewSet)}\n`,
  };
  const renderedArtifacts = Object.fromEntries(Object.entries(compilerResult.artifacts).map(
    ([name, content]) => [`rendered/${name}`, content],
  ));
  const leaf = createLeafManifest({
    target: compilerResult.target,
    activationEligible: targetReviewSet.projections[0].activationEligible,
    graphDigest: policyIR.graphDigest,
    decisionSetDigest: policyIR.decisionSetDigest,
    policyIrDigest: policyIR.contentDigest,
    targetContextDigest: compilerResult.targetContextDigest,
    capabilityDigest: compilerResult.capabilityDigest,
    projectionDigest: targetReviewSet.contentDigest,
    artifacts: { ...controlArtifacts, ...renderedArtifacts },
    createdAt: input.createdAt,
  });
  return Object.freeze({
    review,
    decisions: loadedDecisions.document,
    policyIR,
    compilerResult,
    projection,
    targetReviewSet,
    leaf,
    artifacts: Object.freeze({
      ...controlArtifacts,
      ...renderedArtifacts,
      'leaf-bundle.json': `${jcsCanonicalize(leaf)}\n`,
    }),
  });
}

export async function writePolicyProjectionArtifact(directory, artifact) {
  const written = await writeArtifactDirectory(path.resolve(directory), artifact.artifacts, {
    maximumBytes: 256 * 1024 * 1024,
  });
  return { ...written, leaf: artifact.leaf, targetReviewSet: artifact.targetReviewSet };
}
