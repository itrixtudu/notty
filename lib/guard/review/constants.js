export const REVIEW_API_VERSION = 'notty.dev/v1alpha1';
export const REVIEW_SCHEMA_VERSION = 1;

export const REVIEW_KINDS = Object.freeze({
  bundle: 'NoshReviewBundle',
  node: 'NoshGraphNode',
  observation: 'NoshObservation',
  coverage: 'NoshCoverageMarker',
  finding: 'NoshFinding',
  proposal: 'NoshPolicyProposal',
  diff: 'NoshGraphDiff',
  semanticGraph: 'NoshSemanticGraph',
  decisionSet: 'NoshPolicyDecisionSet',
  policyIr: 'NoshPolicyIR',
  targetReviewSet: 'NoshTargetReviewSet',
  viewState: 'NoshGraphViewState',
  delta: 'NoshSemanticGraphDelta',
});

export const STREAM_ROLES = Object.freeze([
  'nodes',
  'observations',
  'coverage',
  'findings',
  'proposals',
  'diff',
]);

export const REQUIRED_STREAM_ROLES = STREAM_ROLES;

export const STREAM_SCHEMAS = Object.freeze({
  nodes: 'notty.dev/graph/node/v1',
  observations: 'notty.dev/graph/observation/v1',
  coverage: 'notty.dev/graph/coverage/v1',
  findings: 'notty.dev/graph/finding/v1',
  proposals: 'notty.dev/graph/proposal/v1',
  diff: 'notty.dev/graph/diff/v1',
});

export const NODE_TYPES = Object.freeze([
  'project',
  'buildRun',
  'buildPass',
  'buildkitVertex',
  'collector',
  'evidenceSource',
  'sourceRecord',
  'process',
  'executable',
  'file',
  'syscall',
  'domain',
  'networkEndpoint',
  'cgroup',
  'image',
  'package',
  'httpRequest',
  'httpResponse',
  'workload',
  'policySet',
  'coverageSource',
]);

export const OBSERVATION_TYPES = Object.freeze([
  'contains',
  'executes',
  'exits',
  'accesses',
  'invokes',
  'queries',
  'resolvesTo',
  'connects',
  'communicatesWith',
  'accounts',
  'installs',
  'loads',
  'selects',
  'owns',
  'derivedFrom',
  'observedBy',
  'mayHaveOccurredDuring',
  'parentPidObserved',
  'correlatesWith',
  'requests',
  'respondsWith',
]);

export const COVERAGE_DOMAINS = Object.freeze([
  'buildkit-progress',
  'buildx-history',
  'cgroup-metrics',
  'process',
  'syscall',
  'network',
  'dns',
  'http-capture',
  'artifact-integrity',
  'file',
  'sbom-source',
  'sbom-image',
  'runtime-process',
  'runtime-file',
  'runtime-network',
  'hubble',
  'cpg',
]);

export const FINDING_TYPES = Object.freeze([
  'drift-new',
  'drift-broadened',
  'package-change',
  'provenance-change',
  'unresolved-evidence',
  'coverage-degraded',
  'denied-traffic',
  'unsupported-target',
  'policy-conflict',
]);

export const POLICY_DOMAINS = Object.freeze([
  'network',
  'http',
  'process',
  'filesystem',
  'syscall',
]);

export const POLICY_TARGET_KINDS = Object.freeze([
  'fqdn',
  'ipv4',
  'ipv4-cidr',
  'ipv6',
  'ipv6-cidr',
  'workload',
  'executable',
  'path',
  'syscall',
  'container',
  'http-resource',
]);

export const TARGET_PARITY = Object.freeze([
  'exact',
  'restrictive',
  'conditional',
  'permissive',
  'unsupported',
  'outsideScope',
]);

export const DEPLOYMENT_TARGETS = Object.freeze([
  'cilium',
  'guard-ebpf',
  'guard-nftables',
  'gateway-iptables',
  'gateway-pf',
  'gateway-ipfw',
  'gateway-ipfilter',
  'gateway-l7-proxy',
]);

export const HTTP_ASSURANCE_LEVELS = Object.freeze([
  'endpoint-only',
  'url-restricted',
  'native-integrity',
  'cas-replay',
  'live-digest-gate',
]);

export const HTTP_INTEGRITY_KINDS = Object.freeze([
  'none',
  'npm-sri',
  'apt-signed-metadata',
  'publisher-signature',
  'reviewed-digest',
  'cas-object',
  'live-response-digest',
]);

export const PRIVACY_CLASSES = Object.freeze([
  'portable',
  'portable-sensitive',
  'portable-hashed',
  'private',
  'never-store',
]);

export const RECORD_PRIVACY_CLASSES = Object.freeze([
  'portable',
  'portable-sensitive',
  'private',
]);

export const REVIEW_LIMITS = Object.freeze({
  maxStreamBytes: 128 * 1024 * 1024,
  maxLineBytes: 1024 * 1024,
  maxRecordsPerStream: 1_000_000,
  maxStringBytes: 16 * 1024,
  maxLabelBytes: 512,
  maxMessageBytes: 8 * 1024,
  maxJsonDepth: 10,
  maxObjectProperties: 128,
  maxArrayItems: 4096,
  maxEvidenceRefs: 256,
  maxRules: 100_000,
  maxViewNodes: 250_000,
  maxDeltaOperations: 100_000,
});

export const SHA256_PATTERN = /^sha256:[a-f0-9]{64}$/;
export const STABLE_ID_PATTERN = /^[a-z][a-z0-9-]{0,31}:[a-f0-9]{64}$/;
export const DECIMAL_PATTERN = /^(0|[1-9][0-9]*)$/;
export const SAFE_TOKEN_PATTERN = /^[A-Za-z0-9][A-Za-z0-9_.:/-]{0,255}$/;
