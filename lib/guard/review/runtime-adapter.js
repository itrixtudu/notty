import net from 'node:net';
import path from 'node:path';

import { verifyEgressCandidateBundle } from '../../guardd/net-profile-store.js';
import { isLegacyLearningDnsQueryObservation } from '../dns-query-evidence.js';
import {
  createCoverageMarker,
  createFinding,
  createGraphNode,
  createObservation,
  createPolicyProposal,
} from './records.js';
import { createStableId } from './ids.js';
import { sha256Digest } from './jcs.js';
import { createScope } from './ids.js';

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
    workspace: verified.workspace,
    launchConfig: clone(verified.profile.spec.launch.config),
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

export function runtimeReviewScope(candidate) {
  const workspaceDigest = sha256Digest({ workspaceKey: candidate.workspaceKey,
    workspaceIdentity: candidate.workspaceIdentity });
  const identity = { class: 'runtime', projectKey: candidate.workspaceKey,
    ...(candidate.launchConfig?.platform ? { platform: candidate.launchConfig.platform } : {}), target: null,
    imageDigest: candidate.imageDigest, workspaceDigest };
  return createScope({ ...identity, subjectId: createStableId('subject', identity) });
}

// Derive literal alternatives before graph hashing. DNS is evidence, never a
// browser-side rewrite of an approved FQDN into an IP or a broad CIDR.
export function literalRuntimeRules(rules) {
  const result = new Map();
  const add = rule => {
    const { observations = [], ...match } = rule;
    const key = JSON.stringify(match);
    const prior = result.get(key);
    result.set(key, { ...match, observations: [...(prior?.observations || []), ...observations] });
  };
  for (const rule of rules) {
    if (peerFor(rule.destination).kind !== 'fqdn') { add(rule); continue; }
    let derived = 0;
    for (const observation of rule.observations || []) {
      const address = observation.address;
      const decision = observation.decision;
      if (!net.isIP(address) || !decision || decision.destinationAddress !== address
          || ![1, 2, 3, 4, 6].includes(Number(decision.hook))
          || ['backend-deny', 'containment-deny', 'coverage-gap', 'infrastructure-allow', 'dns-observation'].includes(decision.decisionClass)) continue;
      const protocol = { 6: 'tcp', 17: 'udp', 1: 'icmp', 58: 'icmpv6' }[decision.protocol];
      if (protocol !== rule.protocol) continue;
      const ports = ['tcp', 'udp'].includes(protocol) ? [Number(decision.destinationPort)] : [];
      if (ports.length && (!rule.ports?.includes(ports[0]) || ports[0] < 1)) continue;
      add({ destination: `${address}/${net.isIP(address) === 4 ? 32 : 128}`, protocol,
        ...(ports.length ? { ports } : {}), observations: [observation] });
      derived += 1;
    }
    // Retain an unconvertible proposal so missing evidence is never silently
    // removed or replaced with a freshly resolved address.
    if (!derived || derived !== (rule.observations || []).length) add(rule);
  }
  return [...result.values()];
}

export function createRuntimeCandidateGraphRecords(scope, candidate, options = {}) {
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
  if (options.includeSubject) nodes.push(createGraphNode({
    id: scope.subjectId, scopeDigest: scope.scopeDigest, nodeType: 'project',
    label: `Workspace ${candidate.workspaceKey.slice(0, 12)}`,
    identity: { projectKey: candidate.workspaceKey }, properties: {},
    evidenceRefs: [sourceId], privacy: clone(PORTABLE),
  }));
  const proposals = [];
  for (const rule of options.literalEndpoints ? literalRuntimeRules(candidate.rules) : candidate.rules) {
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
  const informationalQueries = new Set(candidate.unresolvedObservations
    .filter(isLegacyLearningDnsQueryObservation));
  const unresolved = candidate.unresolvedObservations
    .filter((entry) => !informationalQueries.has(entry));
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
      ...(informationalQueries.size
        ? { dnsQueries: String(informationalQueries.size) }
        : {}),
    },
    gaps: unresolvedGaps,
    blocking: unresolved.length > 0,
    privacy: clone(PORTABLE),
  })];
  const findings = candidate.unresolvedObservations.map((entry, index) => createFinding({
    semanticKey: {
      candidate: candidate.manifestHash,
      unresolved: entry,
      index,
    },
    scopeDigest: scope.scopeDigest,
    findingType: 'unresolved-evidence',
    severity: informationalQueries.has(entry) ? 'info' : 'high',
    blocking: !informationalQueries.has(entry),
    message: informationalQueries.has(entry)
      ? 'Successful learning DNS query retained as evidence; it grants no endpoint access.'
      : String(entry.reason || 'Runtime egress observation could not be represented.'),
    semanticRefs: [policyNode.id],
    evidenceRefs: [sourceId],
    properties: { observation: entry,
      ...(informationalQueries.has(entry) ? { classification: 'dns-query-evidence' } : {}) },
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
