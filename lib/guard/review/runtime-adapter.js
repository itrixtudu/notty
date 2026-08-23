import net from 'node:net';
import path from 'node:path';

import { verifyEgressCandidateBundle } from '../../guardd/net-profile-store.js';
import {
  createCoverageMarker,
  createFinding,
  createGraphNode,
  createObservation,
  createPolicyProposal,
} from './records.js';
import { createStableId } from './ids.js';
import { sha256Digest } from './jcs.js';

const PORTABLE = Object.freeze({ classification: 'portable', fields: [] });
const PORTABLE_SENSITIVE = Object.freeze({
  classification: 'portable-sensitive',
  fields: [],
});

function clone(value) {
  return structuredClone(value);
}

function runtimeFeasibility(rule) {
  let ebpf = { target: 'guard-ebpf', status: 'exact', reasons: [] };
  if (
    rule.protocol.startsWith('icmp')
    && (rule.icmpType != null || rule.icmpCode != null)
  ) {
    ebpf = {
      target: 'guard-ebpf',
      status: 'unsupported',
      reasons: ['guard-ebpf v2 cannot enforce ICMP type/code selectors'],
    };
  }
  const address = String(rule.destination || '').split('/')[0];
  const family = net.isIP(address);
  const portable = ['gateway-pf', 'gateway-ipfw', 'gateway-ipfilter'].map((target) => ({
    target,
    status: family === 4 ? 'exact' : family === 0 ? 'conditional' : 'unsupported',
    reasons: family === 4
      ? ['render-only export requires native validation before activation']
      : family === 0
        ? [
            'requires a fail-closed TTL-aware managed DNS table updater',
            'render-only export requires native validation before activation',
          ]
        : [`${target} render-only v1 is IPv4-only`],
  }));
  return [
    {
      target: 'cilium',
      status: 'outsideScope',
      reasons: ['runtime candidate is bound to the local Guard cgroup subject'],
    },
    ebpf,
    {
      target: 'guard-nftables',
      status: 'outsideScope',
      reasons: ['eBPF is the selected runtime enforcement backend'],
    },
    {
      target: 'gateway-iptables',
      status: 'outsideScope',
      reasons: ['eBPF is the selected runtime enforcement backend'],
    },
    ...portable,
  ];
}

function peerFor(destination) {
  const separator = destination.lastIndexOf('/');
  const address = separator === -1 ? destination : destination.slice(0, separator);
  const family = net.isIP(address);
  if (family === 4) {
    return {
      kind: separator === -1 ? 'ipv4' : 'ipv4-cidr',
      value: destination,
    };
  }
  if (family === 6) {
    return {
      kind: separator === -1 ? 'ipv6' : 'ipv6-cidr',
      value: destination.toLowerCase(),
    };
  }
  return { kind: 'fqdn', value: destination.toLowerCase() };
}

function endpointNode(scope, sourceId, rule, port) {
  const peer = peerFor(rule.destination);
  const identity = peer.kind === 'fqdn'
    ? { fqdn: peer.value, protocol: rule.protocol, port }
    : {
        family: peer.kind.startsWith('ipv6') ? 'ipv6' : 'ipv4',
        address: peer.value.split('/')[0],
        protocol: rule.protocol,
        port,
        icmpType: rule.icmpType ?? null,
        icmpCode: rule.icmpCode ?? null,
      };
  const semanticKey = {
    identity,
    protocol: rule.protocol,
    port,
  };
  return createGraphNode({
    semanticKey,
    scopeDigest: scope.scopeDigest,
    nodeType: peer.kind === 'fqdn' ? 'domain' : 'networkEndpoint',
    label: `${rule.destination}${port == null ? '' : `:${port}`}/${rule.protocol}`,
    identity,
    properties: {
      runtimeCandidate: true,
      ...(rule.observations?.length
        ? { runtimeEvidence: clone(rule.observations) }
        : {}),
    },
    evidenceRefs: [sourceId],
    privacy: clone(PORTABLE_SENSITIVE),
  });
}

export async function loadRuntimeEgressCandidate(candidatePath, options = {}) {
  const candidateDirectory = path.resolve(candidatePath);
  const trustedRoot = options.trustedRoot
    || path.dirname(path.dirname(candidateDirectory));
  const trustedUid = options.trustedUid == null
    ? (typeof process.geteuid === 'function' ? process.geteuid() : 0)
    : options.trustedUid;
  const verified = await verifyEgressCandidateBundle(candidateDirectory, {
    trustedRoot,
    trustedUid,
    ...(options.workdir ? { workdir: options.workdir } : {}),
  });
  return Object.freeze({
    directory: verified.directory,
    workspaceKey: verified.workspaceKey,
    workspaceIdentity: clone(verified.workspaceIdentity),
    imageDigest: verified.imageDigest,
    manifestHash: verified.manifestHash,
    policyHash: verified.policyHash,
    rulesHash: verified.rulesHash,
    rules: clone(verified.rules),
    unresolvedObservations: clone(
      verified.policy.spec.unresolvedObservations || [],
    ),
    revision: verified.revision,
    createdAt: verified.profile.metadata.createdAt,
    evidenceRunId: verified.profile.spec.evidence.runId,
    evidenceManifestHash: verified.profile.spec.evidence.manifestHash,
  });
}

export function runtimeCandidateBinding(candidate) {
  return Object.freeze({
    workspaceKey: candidate.workspaceKey,
    workspaceIdentity: clone(candidate.workspaceIdentity),
    imageDigest: candidate.imageDigest,
  });
}

export function createRuntimeCandidateGraphRecords(scope, candidate) {
  if (scope.class !== 'runtime') {
    throw new TypeError('runtime candidate composition requires a runtime review scope');
  }
  const expectedWorkspaceDigest = sha256Digest({
    workspaceKey: candidate.workspaceKey,
    workspaceIdentity: candidate.workspaceIdentity,
  });
  if (
    scope.imageDigest !== candidate.imageDigest
    || scope.workspaceDigest !== expectedWorkspaceDigest
  ) {
    throw new Error('runtime candidate does not bind the review scope');
  }
  const sourceId = createStableId('source', {
    artifactKind: 'NoshEgressBundleManifest',
    manifestHash: candidate.manifestHash,
  });
  const sourceNode = createGraphNode({
    id: sourceId,
    scopeDigest: scope.scopeDigest,
    nodeType: 'evidenceSource',
    label: `Runtime egress candidate ${candidate.revision}`,
    identity: {
      kind: 'NoshEgressBundleManifest',
      manifestHash: candidate.manifestHash,
    },
    properties: {
      evidenceRunId: candidate.evidenceRunId,
      evidenceManifestHash: candidate.evidenceManifestHash,
      policyHash: candidate.policyHash,
      rulesHash: candidate.rulesHash,
      imageDigest: candidate.imageDigest,
      workspaceKey: candidate.workspaceKey,
      workspaceIdentity: candidate.workspaceIdentity,
    },
    evidenceRefs: [],
    privacy: clone(PORTABLE),
  });
  const policyNode = createGraphNode({
    semanticKey: {
      revision: candidate.revision,
      policyHash: candidate.policyHash,
    },
    scopeDigest: scope.scopeDigest,
    nodeType: 'policySet',
    label: `Learned runtime egress ${candidate.revision}`,
    identity: {
      revision: candidate.revision,
      policyHash: candidate.policyHash,
    },
    properties: {
      candidate: true,
      defaultDeny: true,
    },
    evidenceRefs: [sourceId],
    privacy: clone(PORTABLE),
  });
  const observations = [createObservation({
    scopeDigest: scope.scopeDigest,
    observationType: 'derivedFrom',
    subjectId: policyNode.id,
    objectId: sourceId,
    basis: 'correlated',
    confidence: 100,
    count: '1',
    evidenceRefs: [sourceId],
    properties: {},
    privacy: clone(PORTABLE),
  })];
  const nodes = [sourceNode, policyNode];
  const proposals = [];
  for (const rule of candidate.rules) {
    const ports = Array.isArray(rule.ports) && rule.ports.length
      ? rule.ports
      : [null];
    for (const port of ports) {
      const endpoint = endpointNode(scope, sourceId, rule, port);
      nodes.push(endpoint);
      const observation = createObservation({
        scopeDigest: scope.scopeDigest,
        observationType: 'connects',
        subjectId: scope.subjectId,
        objectId: endpoint.id,
        basis: 'observed',
        confidence: 100,
        count: '1',
        evidenceRefs: [sourceId],
        properties: {
          runtimeCandidate: true,
          completion: 'observed-by-egress-learn',
          ...(rule.observations?.length
            ? { runtimeEvidence: clone(rule.observations) }
            : {}),
        },
        privacy: clone(PORTABLE_SENSITIVE),
      });
      observations.push(observation);
      proposals.push(createPolicyProposal({
        scopeDigest: scope.scopeDigest,
        scopeClass: 'runtime',
        proposalType: 'learned-runtime-egress',
        intent: {
          domain: 'network',
          subjectId: scope.subjectId,
          effect: 'allow',
          direction: 'egress',
          peer: peerFor(rule.destination),
          transport: {
            protocol: rule.protocol,
            ports: port == null ? [] : [port],
            ...(rule.icmpType == null ? {} : { icmpType: rule.icmpType }),
            ...(rule.icmpCode == null ? {} : { icmpCode: rule.icmpCode }),
          },
        },
        baselineState: 'new',
        rationale: 'Observed by the exact image- and workspace-bound runtime learning pass.',
        evidenceRefs: [sourceId],
        observationRefs: [observation.id],
        targetFeasibility: runtimeFeasibility(rule),
        privacy: clone(PORTABLE_SENSITIVE),
      }));
    }
  }
  const unresolved = candidate.unresolvedObservations;
  const unresolvedGaps = [...new Set(unresolved.map(
    (entry) => String(entry.reason || 'unresolved runtime observation'),
  ))].sort();
  const coverage = [createCoverageMarker({
    scopeDigest: scope.scopeDigest,
    domain: 'runtime-network',
    status: unresolved.length ? 'degraded' : 'complete',
    sourceIds: [sourceId],
    counters: {
      rules: String(proposals.length),
      unresolved: String(unresolved.length),
    },
    gaps: unresolvedGaps,
    blocking: unresolved.length > 0,
    privacy: clone(PORTABLE),
  })];
  const findings = unresolved.map((entry, index) => createFinding({
    semanticKey: {
      candidate: candidate.manifestHash,
      unresolved: entry,
      index,
    },
    scopeDigest: scope.scopeDigest,
    findingType: 'unresolved-evidence',
    severity: 'high',
    blocking: true,
    message: String(entry.reason || 'Runtime egress observation could not be represented.'),
    semanticRefs: [policyNode.id],
    evidenceRefs: [sourceId],
    properties: { observation: entry },
    privacy: clone(PORTABLE_SENSITIVE),
  }));
  return Object.freeze({
    source: {
      id: sourceId,
      sourceType: 'nosh.runtime.egress-candidate',
      artifactKind: 'NoshEgressBundleManifest',
      artifactDigest: candidate.manifestHash,
      runId: candidate.evidenceRunId,
      sourceName: 'runtime-egress-candidate',
      sourceDigest: candidate.policyHash,
      observedFrom: candidate.createdAt,
      observedTo: candidate.createdAt,
      coverage: {
        status: unresolved.length ? 'degraded' : 'complete',
        lostEvents: '0',
        parseErrors: '0',
        gaps: unresolvedGaps,
      },
    },
    records: {
      nodes,
      observations,
      coverage,
      findings,
      proposals,
      diff: [],
    },
  });
}
