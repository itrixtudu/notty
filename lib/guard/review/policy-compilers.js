import crypto from 'node:crypto';
import net from 'node:net';

import {
  generateDnsmasqConfig,
  generateNftRules,
} from '../../guardd/egress-policy.js';
import {
  createHttpContentManifest,
  verifyHttpContentManifest,
} from '../../guardd/http-content-store.js';
import { validatePolicyIR } from './documents.js';
import { createStableId } from './ids.js';
import { jcsCanonicalize, sha256Digest } from './jcs.js';

const DNS_CAPABILITIES = Object.freeze([
  'connmarkAllowlist',
  'managedDnsExclusive',
  'strictSourceMarking',
]);

const EBPF_CAPABILITIES = Object.freeze([
  'atomicPolicyGeneration',
  'cgroupConnect',
  'cgroupSendmsg',
  'cgroupSkb',
  'dnsParser',
  'exactPlatformContainment',
  'ipv6',
  'ttlGrants',
]);

const DEFAULT_EBPF_RESOLVERS = Object.freeze([
  '1.1.1.1',
  '8.8.8.8',
]);

function plainObject(value, label) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    throw new TypeError(`${label} must be an object`);
  }
  return value;
}

function boundedString(value, label, maximum = 253) {
  if (
    typeof value !== 'string'
    || !value.trim()
    || value.length > maximum
    || /[\u0000-\u001f\u007f]/.test(value)
  ) {
    throw new TypeError(`${label} must be a bounded non-empty string`);
  }
  return value;
}

function exactObjectKeys(value, required, optional, label) {
  const selected = plainObject(value, label);
  const allowed = new Set([...required, ...optional]);
  for (const key of Object.keys(selected)) {
    if (!allowed.has(key)) throw new TypeError(`${label} contains unsupported field ${key}`);
  }
  for (const key of required) {
    if (!Object.hasOwn(selected, key)) throw new TypeError(`${label}.${key} is required`);
  }
  return selected;
}

function safeIdentifier(value, label, maximum = 63) {
  const selected = boundedString(value, label, maximum);
  if (!/^[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?$/.test(selected)) {
    throw new TypeError(`${label} contains unsupported characters`);
  }
  return selected;
}

function dnsLabel(value, label) {
  const selected = boundedString(value, label, 63);
  if (!/^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(selected)) {
    throw new TypeError(`${label} must be a lowercase DNS label`);
  }
  return selected;
}

function dnsSubdomain(value, label, maximum = 253) {
  const selected = boundedString(value, label, maximum);
  if (!selected.split('.').every((part) => {
    try {
      dnsLabel(part, label);
      return true;
    } catch {
      return false;
    }
  })) {
    throw new TypeError(`${label} must be a lowercase DNS subdomain`);
  }
  return selected;
}

function kubernetesLabelPart(value, label, allowEmpty = false) {
  if (allowEmpty && value === '') return '';
  const selected = boundedString(value, label, 63);
  if (!/^[A-Za-z0-9](?:[A-Za-z0-9_.-]{0,61}[A-Za-z0-9])?$/.test(selected)) {
    throw new TypeError(`${label} is not a Kubernetes label value`);
  }
  return selected;
}

function kubernetesLabelKey(value) {
  const selected = boundedString(value, 'workload label key', 253);
  const pieces = selected.split('/');
  if (pieces.length > 2) throw new TypeError('workload label key is invalid');
  const name = pieces.pop();
  kubernetesLabelPart(name, 'workload label name');
  if (pieces.length) {
    const prefix = pieces[0];
    if (
      prefix.length > 253
      || !prefix.split('.').every((part) => {
        try {
          dnsLabel(part, 'workload label prefix');
          return true;
        } catch {
          return false;
        }
      })
    ) {
      throw new TypeError('workload label key prefix is invalid');
    }
  }
  return selected;
}

function policyDomain(value) {
  const domain = boundedString(value, 'FQDN').toLowerCase().replace(/\.$/, '');
  const suffix = domain.startsWith('*.') ? domain.slice(2) : domain;
  if (
    (domain.includes('*') && !domain.startsWith('*.'))
    || !suffix.includes('.')
    || domain.length > 253
    || !suffix.split('.').every(
      (label) => /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(label),
    )
  ) {
    throw new TypeError(`policy v1 requires an exact or leading-wildcard FQDN: ${value}`);
  }
  return domain;
}

function ipv4Integer(address) {
  if (net.isIP(address) !== 4) {
    throw new TypeError(`policy v1 requires IPv4: ${address}`);
  }
  return address.split('.').reduce(
    (result, octet) => ((result << 8) | Number(octet)) >>> 0,
    0,
  );
}

function exactIpv4Cidr(value) {
  const selected = boundedString(value, 'IPv4 CIDR', 32);
  const pieces = selected.split('/');
  if (pieces.length > 2 || pieces.some((piece) => piece === '')) {
    throw new TypeError(`invalid IPv4 CIDR: ${value}`);
  }
  const address = pieces[0];
  const prefix = pieces.length === 1 ? 32 : Number(pieces[1]);
  if (!Number.isSafeInteger(prefix) || prefix < 0 || prefix > 32) {
    throw new TypeError(`invalid IPv4 CIDR prefix: ${value}`);
  }
  const integer = ipv4Integer(address);
  const mask = prefix === 0 ? 0 : (0xffffffff << (32 - prefix)) >>> 0;
  if ((integer & mask) >>> 0 !== integer) {
    throw new TypeError(`IPv4 CIDR must use its canonical network address: ${value}`);
  }
  return `${address}/${prefix}`;
}

function ipv6Integer(value) {
  if (net.isIP(value) !== 6) throw new TypeError(`policy v1 requires IPv6: ${value}`);
  let selected = value.toLowerCase();
  if (selected.includes('.')) {
    const separator = selected.lastIndexOf(':');
    const ipv4 = selected.slice(separator + 1);
    const integer = ipv4Integer(ipv4);
    selected = `${selected.slice(0, separator)}:${((integer >>> 16) & 0xffff).toString(16)}:${(integer & 0xffff).toString(16)}`;
  }
  const halves = selected.split('::');
  if (halves.length > 2) throw new TypeError(`invalid IPv6 address: ${value}`);
  const left = halves[0] ? halves[0].split(':') : [];
  const right = halves.length === 2 && halves[1] ? halves[1].split(':') : [];
  const missing = 8 - left.length - right.length;
  if (missing < 0 || (halves.length === 1 && missing !== 0)) {
    throw new TypeError(`invalid IPv6 address: ${value}`);
  }
  const words = [...left, ...Array(missing).fill('0'), ...right];
  if (words.length !== 8 || words.some((word) => !/^[a-f0-9]{1,4}$/.test(word))) {
    throw new TypeError(`invalid IPv6 address: ${value}`);
  }
  return words.reduce((result, word) => (result << 16n) | BigInt(`0x${word}`), 0n);
}

function canonicalIpv6(value) {
  const words = Array.from({ length: 8 }, (_, index) => (
    Number((value >> BigInt((7 - index) * 16)) & 0xffffn).toString(16)
  ));
  let bestStart = -1;
  let bestLength = 1;
  for (let index = 0; index < words.length;) {
    if (words[index] !== '0') {
      index += 1;
      continue;
    }
    let end = index + 1;
    while (end < words.length && words[end] === '0') end += 1;
    if (end - index > bestLength) {
      bestStart = index;
      bestLength = end - index;
    }
    index = end;
  }
  if (bestStart === -1) return words.join(':');
  const left = words.slice(0, bestStart).join(':');
  const right = words.slice(bestStart + bestLength).join(':');
  return `${left}::${right}`;
}

function exactIpv6Cidr(value) {
  const selected = boundedString(value, 'IPv6 CIDR', 64);
  const separator = selected.lastIndexOf('/');
  const address = separator === -1 ? selected : selected.slice(0, separator);
  const prefix = separator === -1 ? 128 : Number(selected.slice(separator + 1));
  if (!Number.isSafeInteger(prefix) || prefix < 0 || prefix > 128) {
    throw new TypeError(`invalid IPv6 CIDR prefix: ${value}`);
  }
  const integer = ipv6Integer(address);
  const mask = prefix === 0
    ? 0n
    : ((1n << BigInt(prefix)) - 1n) << BigInt(128 - prefix);
  const network = integer & mask;
  if (network !== integer) {
    throw new TypeError(`IPv6 CIDR must use its canonical network address: ${value}`);
  }
  return `${canonicalIpv6(network)}/${prefix}`;
}

function portsFor(rule, protocol) {
  if (protocol === 'icmp' || protocol === 'icmpv6') return [];
  const values = rule.transport?.ports;
  if (!Array.isArray(values) || values.length === 0) {
    throw new TypeError(`${protocol} rule ${rule.id} requires numeric ports`);
  }
  const ports = [...new Set(values.map(Number))].sort((left, right) => left - right);
  if (ports.some((port) => !Number.isSafeInteger(port) || port < 1 || port > 65535)) {
    throw new TypeError(`${protocol} rule ${rule.id} contains an invalid port`);
  }
  return ports;
}

function icmpValue(value, label) {
  if (value == null) return null;
  const selected = Number(value);
  if (!Number.isSafeInteger(selected) || selected < 0 || selected > 255) {
    throw new TypeError(`${label} must be from 0 to 255`);
  }
  return selected;
}

function normalizePeer(input) {
  const peer = plainObject(input, 'network rule peer');
  if (peer.kind === 'fqdn') {
    return { kind: 'fqdn', value: policyDomain(peer.value) };
  }
  if (peer.kind === 'ipv4-cidr') {
    return { kind: 'ipv4-cidr', value: exactIpv4Cidr(peer.value) };
  }
  if (peer.kind === 'ipv4') {
    const address = boundedString(peer.value, 'IPv4 address', 15);
    ipv4Integer(address);
    return { kind: 'ipv4-cidr', value: `${address}/32` };
  }
  if (peer.kind === 'ipv6-cidr') {
    return { kind: 'ipv6-cidr', value: exactIpv6Cidr(peer.value) };
  }
  if (peer.kind === 'ipv6') {
    return { kind: 'ipv6-cidr', value: exactIpv6Cidr(`${peer.value}/128`) };
  }
  if (peer.kind === 'workload') {
    const selector = plainObject(peer.selector, 'workload selector');
    const labels = Object.fromEntries(
      Object.entries(selector)
        .map(([key, value]) => [
          kubernetesLabelKey(key),
          kubernetesLabelPart(value, 'workload label value', true),
        ])
        .sort(([left], [right]) => left.localeCompare(right)),
    );
    if (!Object.keys(labels).length) {
      throw new TypeError('workload selector must not be empty');
    }
    return { kind: 'workload', selector: labels };
  }
  throw new TypeError(`unsupported policy v1 peer kind: ${peer.kind}`);
}

function normalizeNetworkRule(input) {
  const rule = plainObject(input, 'policy rule');
  const id = boundedString(rule.id, 'policy rule ID', 256);
  if (
    Object.hasOwn(rule, 'constraints')
    && (
      !rule.constraints
      || typeof rule.constraints !== 'object'
      || Array.isArray(rule.constraints)
      || Object.keys(rule.constraints).length > 0
    )
  ) {
    throw new TypeError(
      `network rule ${id} has constraints that the selected L3/L4 compiler cannot enforce`,
    );
  }
  if (rule.effect !== 'allow') {
    throw new TypeError(`policy v1 rule ${id} must be an allow rule`);
  }
  if (!['ingress', 'egress'].includes(rule.direction)) {
    throw new TypeError(`network rule ${id} requires ingress or egress direction`);
  }
  const protocol = String(rule.transport?.protocol || '').toLowerCase();
  if (!['tcp', 'udp', 'icmp', 'icmpv6'].includes(protocol)) {
    throw new TypeError(`network rule ${id} has an unsupported protocol`);
  }
  const normalized = {
    ...rule,
    id,
    domain: 'network',
    subjectId: boundedString(rule.subjectId, 'policy subject ID', 512),
    direction: rule.direction,
    effect: 'allow',
    peer: normalizePeer(rule.peer),
    transport: {
      protocol,
      ports: portsFor(rule, protocol),
      ...((protocol === 'icmp' || protocol === 'icmpv6')
        && Object.hasOwn(rule.transport, 'icmpType')
        ? {
            icmpType: icmpValue(rule.transport?.icmpType, 'ICMP type'),
          }
        : {}),
      ...((protocol === 'icmp' || protocol === 'icmpv6')
        && Object.hasOwn(rule.transport, 'icmpCode')
        ? {
            icmpCode: icmpValue(rule.transport?.icmpCode, 'ICMP code'),
          }
        : {}),
    },
    evidenceRefs: Array.isArray(rule.evidenceRefs)
      ? [...new Set(rule.evidenceRefs.map(String))].sort()
      : [],
    decisionRefs: Array.isArray(rule.decisionRefs)
      ? [...new Set(rule.decisionRefs.map(String))].sort()
      : [],
  };
  return normalized;
}

export function normalizePolicyIrForCompilation(input) {
  const policy = plainObject(input, 'PolicyIR');
  validatePolicyIR(policy);
  const defaults = plainObject(policy.defaults, 'PolicyIR defaults');
  if (defaults.ingress !== 'deny' || defaults.egress !== 'deny') {
    throw new TypeError('policy v1 requires explicit ingress and egress default deny');
  }
  if (!Array.isArray(policy.rules)) {
    throw new TypeError('PolicyIR rules must be an array');
  }
  const ids = new Set();
  const rules = policy.rules.map((rule) => {
    const domain = String(rule?.domain || '');
    const normalized = domain === 'network'
      ? normalizeNetworkRule(rule)
      : {
          ...plainObject(rule, 'PolicyIR rule'),
          id: boundedString(rule.id, 'policy rule ID', 256),
          domain: boundedString(domain, 'policy rule domain', 64),
        };
    if (ids.has(normalized.id)) {
      throw new TypeError(`duplicate PolicyIR rule ID: ${normalized.id}`);
    }
    ids.add(normalized.id);
    return normalized;
  });
  return {
    ...policy,
    rules,
  };
}

function capabilityResult(context, required) {
  const capabilities = plainObject(context.capabilities || {}, 'target capabilities');
  for (const [name, value] of Object.entries(capabilities)) {
    if (!/^[A-Za-z][A-Za-z0-9]*$/.test(name) || typeof value !== 'boolean') {
      throw new TypeError('target capabilities must be boolean capability tokens');
    }
  }
  const missing = required.filter((name) => capabilities[name] !== true);
  return { capabilities, missing };
}

function projection(rule, parity, details = {}) {
  return {
    ruleId: rule.id,
    domain: rule.domain,
    parity,
    targetIds: details.targetIds || [],
    preconditions: details.preconditions || [],
    reasons: details.reasons || [],
  };
}

function nonNetworkProjection(rule, target) {
  if (rule.domain === 'http') {
    return projection(rule, 'permissive', {
      reasons: [
        `${target} is an L3/L4 target and cannot enforce the reviewed HTTP request or response identity`,
      ],
    });
  }
  return projection(rule, 'outsideScope', {
    reasons: [`${target} does not compile this policy domain`],
  });
}

function artifactsDigest(artifacts) {
  return sha256Digest(jcsCanonicalize(Object.fromEntries(
    Object.entries(artifacts)
      .map(([name, content]) => [name, sha256Digest(content)])
      .sort(([left], [right]) => left.localeCompare(right)),
  )));
}

function compilerResult(target, policy, context, projections, artifacts, extra = {}) {
  const blocking = projections.some((entry) => [
    'permissive',
    'unsupported',
  ].includes(entry.parity));
  const conditional = projections.some((entry) => entry.parity === 'conditional');
  const activationEligible = extra.activationEligible !== false
    && !blocking
    && !conditional;
  return {
    apiVersion: 'notty.dev/v1alpha1',
    kind: 'NoshPolicyProjection',
    schemaVersion: 1,
    target,
    policyIrDigest: policy.contentDigest,
    targetContextDigest: sha256Digest(jcsCanonicalize(context)),
    capabilityDigest: sha256Digest(jcsCanonicalize(context.capabilities || {})),
    activationEligible,
    projections,
    artifacts,
    artifactsDigest: artifactsDigest(artifacts),
    limitations: extra.limitations || [],
  };
}

function k8sPortRules(rule) {
  if (rule.transport.protocol.startsWith('icmp')) return null;
  return [{
    ports: rule.transport.ports.map((port) => ({
      port: String(port),
      protocol: rule.transport.protocol.toUpperCase(),
    })),
  }];
}

function ciliumDirectionRule(rule) {
  const prefix = rule.direction === 'egress' ? 'to' : 'from';
  const result = {};
  if (rule.peer.kind === 'fqdn') {
    if (rule.direction !== 'egress') return null;
    result.toFQDNs = [rule.peer.value.startsWith('*.')
      ? { matchPattern: rule.peer.value }
      : { matchName: rule.peer.value }];
  } else if (['ipv4-cidr', 'ipv6-cidr'].includes(rule.peer.kind)) {
    result[`${prefix}CIDR`] = [rule.peer.value];
  } else {
    result[`${prefix}Endpoints`] = [{ matchLabels: rule.peer.selector }];
  }
  if (rule.transport.protocol.startsWith('icmp')) {
    result.icmps = [{
      fields: [{
        family: rule.transport.protocol === 'icmpv6' ? 'IPv6' : 'IPv4',
        ...(rule.transport.icmpType == null
          ? {}
          : { type: String(rule.transport.icmpType) }),
        ...(rule.transport.icmpCode == null
          ? {}
          : { code: String(rule.transport.icmpCode) }),
      }],
    }];
  } else {
    result[rule.direction === 'egress' ? 'toPorts' : 'toPorts'] = k8sPortRules(rule);
  }
  return result;
}

export function compileCiliumPolicy(policyInput, contextInput) {
  const policy = normalizePolicyIrForCompilation(policyInput);
  const context = plainObject(contextInput, 'Cilium target context');
  const namespace = dnsLabel(context.namespace, 'Cilium namespace');
  const name = dnsSubdomain(
    context.name || 'nosh-reviewed-policy',
    'Cilium policy name',
  );
  const endpointSelector = plainObject(
    context.endpointSelector,
    'Cilium endpoint selector',
  );
  if (!Object.keys(endpointSelector).length) {
    throw new TypeError('Cilium endpoint selector must not be empty');
  }
  const normalizedEndpointSelector = Object.fromEntries(
    Object.entries(endpointSelector)
      .map(([key, value]) => [
        kubernetesLabelKey(key),
        kubernetesLabelPart(value, 'Cilium endpoint label value', true),
      ])
      .sort(([left], [right]) => left.localeCompare(right)),
  );
  // A caller-supplied digest is not proof that the complete selecting-policy
  // inventory was collected or that its selector coverage was verified.
  // Version 1 can claim exact composition only for explicit exclusive
  // ownership; inventory-backed proof needs a separately verified artifact.
  const compositionProven = context.exclusiveOwnership === true;
  const projections = [];
  const ingress = [];
  const egress = [];
  for (const rule of policy.rules) {
    if (rule.domain !== 'network') {
      projections.push(nonNetworkProjection(rule, 'cilium'));
      continue;
    }
    const native = ciliumDirectionRule(rule);
    if (!native) {
      projections.push(projection(rule, 'unsupported', {
        reasons: ['Cilium FQDN peers are valid only for egress'],
      }));
      continue;
    }
    const targetId = `${namespace}/${name}#/spec/${rule.direction}/${
      rule.direction === 'egress' ? egress.length : ingress.length
    }`;
    (rule.direction === 'egress' ? egress : ingress).push(native);
    projections.push(projection(
      rule,
      compositionProven ? 'exact' : 'conditional',
      {
        targetIds: [targetId],
        preconditions: compositionProven
          ? []
          : ['prove exclusive ownership of every policy selecting this workload'],
      },
    ));
  }
  const cnp = {
    apiVersion: 'cilium.io/v2',
    kind: 'CiliumNetworkPolicy',
    metadata: {
      name,
      namespace,
      labels: {
        'app.kubernetes.io/managed-by': 'nosh-guard',
        'notty.dev/policy-ir': policy.contentDigest.slice(7, 23),
      },
    },
    spec: {
      endpointSelector: { matchLabels: normalizedEndpointSelector },
      ingress,
      egress,
    },
  };
  const inventory = {
    apiVersion: 'notty.dev/v1alpha1',
    kind: 'NoshCiliumOwnedObjectInventory',
    objects: [{
      apiVersion: cnp.apiVersion,
      kind: cnp.kind,
      namespace,
      name,
      contentDigest: sha256Digest(jcsCanonicalize(cnp)),
    }],
    selectingPolicyInventoryDigest: context.selectingPolicyInventoryDigest || null,
    exclusiveOwnership: context.exclusiveOwnership === true,
  };
  const artifacts = {
    'cilium-network-policy.yaml': `${JSON.stringify(cnp, null, 2)}\n`,
    'inventory.json': `${JSON.stringify(inventory, null, 2)}\n`,
  };
  return compilerResult(
    'cilium',
    policy,
    context,
    projections,
    artifacts,
    { activationEligible: compositionProven },
  );
}

function normalizeEbpfSubject(input, policy) {
  const subject = exactObjectKeys(
    input,
    ['workspaceKey', 'workspaceIdentity', 'imageDigest'],
    [],
    'eBPF subject binding',
  );
  const workspaceKey = boundedString(subject.workspaceKey, 'workspaceKey', 128);
  if (!/^(?:[a-f0-9]{64}|sha256:[a-f0-9]{64})$/.test(workspaceKey)) {
    throw new TypeError('workspaceKey must be a canonical workspace hash');
  }
  const workspaceIdentity = exactObjectKeys(
    subject.workspaceIdentity,
    ['dev', 'ino'],
    [],
    'workspaceIdentity',
  );
  const normalizedIdentity = {};
  for (const name of ['dev', 'ino']) {
    const value = String(workspaceIdentity[name]);
    if (!/^(0|[1-9][0-9]*)$/.test(value)) {
      throw new TypeError(`workspaceIdentity.${name} must be a decimal string`);
    }
    normalizedIdentity[name] = value;
  }
  const imageDigest = boundedString(subject.imageDigest, 'imageDigest', 71);
  if (!/^sha256:[a-f0-9]{64}$/.test(imageDigest)) {
    throw new TypeError('imageDigest must be an immutable SHA-256 digest');
  }
  const workspaceDigest = sha256Digest({ workspaceKey, workspaceIdentity: normalizedIdentity });
  if (
    policy.scope.class !== 'runtime'
    || policy.scope.imageDigest !== imageDigest
    || policy.scope.workspaceDigest !== workspaceDigest
  ) {
    throw new Error('eBPF target subject does not match the runtime review scope');
  }
  return {
    subjectId: policy.scope.subjectId,
    scopeDigest: policy.scope.scopeDigest,
    workspaceKey,
    workspaceIdentity: normalizedIdentity,
    workspaceDigest,
    imageDigest,
  };
}

function normalizeEbpfResolvers(input) {
  if (input != null && !Array.isArray(input)) {
    throw new TypeError('eBPF resolvers must be an array');
  }
  const values = input || DEFAULT_EBPF_RESOLVERS;
  const resolvers = [...new Set(values.map((entry) => {
    const value = boundedString(entry, 'eBPF resolver', 64).toLowerCase();
    const family = net.isIP(value);
    if (!family) throw new TypeError(`eBPF resolver must be an IP address: ${entry}`);
    return family === 6 ? canonicalIpv6(ipv6Integer(value)) : value;
  }))].sort((left, right) => {
    const family = net.isIP(left) - net.isIP(right);
    return family || left.localeCompare(right);
  });
  if (!resolvers.length || resolvers.length > 32) {
    throw new TypeError('eBPF resolvers must contain from 1 through 32 addresses');
  }
  return resolvers;
}

function normalizeEbpfContext(input, policy) {
  const supplied = plainObject(input, 'guard-ebpf target context');
  let contextInput = supplied;
  if (supplied.kind === 'NoshGuardEbpfTargetContext') {
    exactObjectKeys(
      supplied,
      [
        'apiVersion',
        'kind',
        'schemaVersion',
        'createdAt',
        'backendAbi',
        'objectDigest',
        'subject',
        'capabilities',
        'resolvers',
        'platformContainment',
        'contentHash',
      ],
      [],
      'guard-ebpf target context document',
    );
    if (
      supplied.apiVersion !== 'notty.dev/v1alpha1'
      || supplied.schemaVersion !== 2
      || supplied.backendAbi !== 'nosh-egress-v2'
      || !Number.isFinite(Date.parse(supplied.createdAt))
    ) {
      throw new TypeError('guard-ebpf target context document header is invalid');
    }
    const { contentHash, ...unsigned } = supplied;
    if (contentHash !== sha256Digest(jcsCanonicalize(unsigned))) {
      throw new Error('guard-ebpf target context content hash does not match');
    }
    contextInput = {
      backendAbi: supplied.backendAbi,
      objectDigest: supplied.objectDigest,
      subject: supplied.subject,
      capabilities: supplied.capabilities,
      resolvers: supplied.resolvers,
      platformContainment: supplied.platformContainment,
    };
  }
  const context = exactObjectKeys(
    contextInput,
    [
      'backendAbi',
      'objectDigest',
      'subject',
      'capabilities',
      'platformContainment',
    ],
    ['resolvers'],
    'guard-ebpf target context',
  );
  const backendAbi = boundedString(context.backendAbi, 'eBPF backend ABI', 64);
  if (backendAbi !== 'nosh-egress-v2') {
    throw new TypeError('guard-ebpf target context requires backend ABI nosh-egress-v2');
  }
  const objectDigest = boundedString(context.objectDigest, 'eBPF object digest', 71);
  if (!/^sha256:[a-f0-9]{64}$/.test(objectDigest)) {
    throw new TypeError('eBPF object digest must be an exact SHA-256 digest');
  }
  const subject = normalizeEbpfSubject(context.subject, policy);
  const capability = capabilityResult(context, EBPF_CAPABILITIES);
  const resolvers = normalizeEbpfResolvers(context.resolvers);
  const platformContainment = exactObjectKeys(
    plainObject(context.platformContainment, 'eBPF platform containment'),
    ['strategy', 'ipv4PrefixLength', 'ipv6PrefixLength'],
    [],
    'eBPF platform containment',
  );
  if (
    platformContainment.strategy !== 'per-run-docker-bridge-gateways'
    || platformContainment.ipv4PrefixLength !== 32
    || platformContainment.ipv6PrefixLength !== 128
  ) {
    throw new TypeError(
      'eBPF platform containment must use exact per-run Docker bridge gateway /32 and /128 identities',
    );
  }
  return {
    backendAbi,
    objectDigest,
    subject,
    capabilities: Object.fromEntries(
      Object.entries(capability.capabilities).sort(([left], [right]) => left.localeCompare(right)),
    ),
    missingCapabilities: capability.missing,
    resolvers,
    platformContainment: { ...platformContainment },
  };
}

function ebpfUnsupportedReason(rule) {
  if (rule.peer.kind === 'fqdn') {
    const wildcard = rule.peer.value.startsWith('*.');
    const domain = wildcard ? rule.peer.value.slice(2) : rule.peer.value;
    const labels = domain.split('.');
    if (domain.length >= 128) {
      return 'guard-ebpf v2 supports DNS names of at most 127 bytes';
    }
    if (labels.length > (wildcard ? 15 : 16)) {
      return wildcard
        ? 'guard-ebpf v2 wildcard suffixes support at most 15 labels'
        : 'guard-ebpf v2 exact DNS names support at most 16 labels';
    }
  }
  if (rule.transport.protocol === 'icmp' && rule.peer.kind !== 'ipv4-cidr') {
    return 'guard-ebpf v2 ICMP rules require an IPv4 peer';
  }
  if (rule.transport.protocol === 'icmpv6' && rule.peer.kind !== 'ipv6-cidr') {
    return 'guard-ebpf v2 ICMPv6 rules require an IPv6 peer';
  }
  return null;
}

function ebpfRuleMissingCapabilities(rule, context) {
  const missing = [...context.missingCapabilities];
  if (rule.peer.kind === 'fqdn' && context.capabilities.tcpDns !== true) {
    missing.push('tcpDns');
  }
  return [...new Set(missing)].sort();
}

export function assertEbpfRuleCapacity(rules) {
  const slots = new Map();
  const expandedMatches = new Map();
  let domainEntries = 0;
  let ipv4Entries = 0;
  let ipv6Entries = 0;
  for (const rule of rules) {
    const count = ['tcp', 'udp'].includes(rule.transport.protocol)
      ? rule.transport.ports.length
      : 1;
    const ports = ['tcp', 'udp'].includes(rule.transport.protocol)
      ? rule.transport.ports
      : [0];
    if (rule.peer.kind === 'fqdn') {
      const next = (slots.get(rule.peer.value) || 0) + count;
      if (next > 8) {
        throw new Error(
          `guard-ebpf domain ${rule.peer.value} exceeds the 8-rule slot limit`,
        );
      }
      slots.set(rule.peer.value, next);
      domainEntries += count;
      if (domainEntries > 8192) {
        throw new Error('guard-ebpf policy exceeds the 8192-domain-entry map limit');
      }
    } else if (rule.peer.kind === 'ipv4-cidr') {
      ipv4Entries += count;
      if (ipv4Entries > 16384) {
        throw new Error('guard-ebpf policy exceeds the 16384-IPv4-entry map limit');
      }
    } else if (rule.peer.kind === 'ipv6-cidr') {
      ipv6Entries += count;
      if (ipv6Entries > 16384) {
        throw new Error('guard-ebpf policy exceeds the 16384-IPv6-entry map limit');
      }
    }
    for (const port of ports) {
      const match = jcsCanonicalize({
        peer: rule.peer,
        protocol: rule.transport.protocol,
        port,
      });
      const prior = expandedMatches.get(match);
      if (prior && prior !== rule.id) {
        throw new Error(
          `guard-ebpf rules ${prior} and ${rule.id} have the same expanded match`,
        );
      }
      expandedMatches.set(match, rule.id);
    }
  }
  for (const [domain, exactSlots] of slots) {
    if (domain.startsWith('*.')) continue;
    const separator = domain.indexOf('.');
    if (separator < 1) continue;
    const wildcard = `*.${domain.slice(separator + 1)}`;
    if (exactSlots + (slots.get(wildcard) || 0) > 8) {
      throw new Error(
        `guard-ebpf domain union ${domain} plus ${wildcard} exceeds the 8-rule slot limit`,
      );
    }
  }
}

export function compileEbpfPolicy(policyInput, contextInput) {
  const policy = normalizePolicyIrForCompilation(policyInput);
  const context = normalizeEbpfContext(contextInput, policy);
  const deploymentContext = {
    backendAbi: context.backendAbi,
    objectDigest: context.objectDigest,
    subject: context.subject,
    capabilities: context.capabilities,
    resolvers: context.resolvers,
    platformContainment: context.platformContainment,
  };
  const targetContextDigest = sha256Digest(jcsCanonicalize(deploymentContext));
  const projections = [];
  const rules = [];
  for (const rule of policy.rules) {
    if (rule.scopeClass !== 'runtime') {
      projections.push(projection(rule, 'outsideScope', {
        reasons: ['build-time review evidence cannot authorize the runtime eBPF subject'],
      }));
      continue;
    }
    if (rule.domain !== 'network') {
      projections.push(nonNetworkProjection(rule, 'guard-ebpf'));
      continue;
    }
    if (rule.direction !== 'egress' || rule.peer.kind === 'workload') {
      projections.push(projection(rule, 'unsupported', {
        reasons: ['guard-ebpf egress v2 supports egress FQDN and IP/CIDR peers only'],
      }));
      continue;
    }
    if (
      rule.transport.protocol.startsWith('icmp')
      && (rule.transport.icmpType != null || rule.transport.icmpCode != null)
    ) {
      projections.push(projection(rule, 'unsupported', {
        reasons: [
          'the guard-ebpf v2 loader cannot enforce ICMP type/code selectors without weakening the reviewed rule',
        ],
      }));
      continue;
    }
    const unsupportedReason = ebpfUnsupportedReason(rule);
    if (unsupportedReason) {
      projections.push(projection(rule, 'unsupported', {
        reasons: [unsupportedReason],
      }));
      continue;
    }
    const missingCapabilities = ebpfRuleMissingCapabilities(rule, context);
    const nativeRule = {
      id: rule.id,
      effect: 'allow',
      direction: 'egress',
      peer: rule.peer,
      transport: {
        protocol: rule.transport.protocol,
        ports: rule.transport.ports,
        ...(rule.transport.icmpType == null
          ? {}
          : { icmpType: rule.transport.icmpType }),
        ...(rule.transport.icmpCode == null
          ? {}
          : { icmpCode: rule.transport.icmpCode }),
      },
      evidenceRefs: rule.evidenceRefs,
      decisionRefs: rule.decisionRefs,
    };
    if (!missingCapabilities.length) rules.push(nativeRule);
    projections.push(projection(
      rule,
      missingCapabilities.length
        ? 'unsupported'
        : 'exact',
      {
        targetIds: !missingCapabilities.length
          ? [`ebpf-policy.json#/rules/${rules.length - 1}`]
          : [],
        preconditions: missingCapabilities.map((name) => `missing capability ${name}`),
        reasons: [],
      },
    ));
  }
  assertEbpfRuleCapacity(rules);
  const nativePolicy = {
    apiVersion: 'notty.dev/v1alpha1',
    kind: 'NoshEbpfEgressPolicy',
    schemaVersion: 2,
    createdAt: policy.createdAt,
    backend: {
      target: 'guard-ebpf',
      abi: context.backendAbi,
      objectDigest: context.objectDigest,
    },
    subject: context.subject,
    bindings: {
      graphDigest: policy.graphDigest,
      decisionSetDigest: policy.decisionSetDigest,
      policyIrDigest: policy.contentDigest,
      targetContextDigest,
    },
    defaults: { egress: 'deny' },
    dns: {
      resolvers: context.resolvers,
      maximumGrantTtlSeconds: 300,
      exactNames: true,
      wildcardSuffixes: true,
      tcp: context.capabilities.tcpDns === true,
      udp: true,
    },
    platformContainment: context.platformContainment,
    rules,
  };
  const artifacts = {
    'ebpf-policy.json': `${jcsCanonicalize(nativePolicy)}\n`,
  };
  return compilerResult(
    'guard-ebpf',
    policy,
    deploymentContext,
    projections,
    artifacts,
    {
      activationEligible: context.missingCapabilities.length === 0,
      limitations: [
        'FQDN authorization is DNS-mediated and grants resolved addresses for at most 300 seconds',
        'FQDN rules require complete TCP DNS parsing; literal IP/CIDR rules do not',
        'DoH destinations require an independently approved IP/CIDR or FQDN rule',
        'the current per-run Docker bridge gateways remain platform-contained and cannot be authorized by reviewed policy',
      ],
    },
  );
}

function gatewayRule(rule) {
  if (rule.peer.kind === 'workload') return null;
  return {
    id: rule.id,
    destination: rule.peer.value,
    protocol: rule.transport.protocol,
    ports: rule.transport.ports,
    icmpType: rule.transport.icmpType,
    icmpCode: rule.transport.icmpCode,
  };
}

function gatewayContext(input, target) {
  const context = plainObject(input, `${target} target context`);
  if (net.isIP(context.sourceIpv4) !== 4 || net.isIP(context.gatewayIpv4) !== 4) {
    throw new TypeError(`${target} requires sourceIpv4 and gatewayIpv4`);
  }
  const networkName = safeIdentifier(context.networkName, `${target} network name`);
  const uplinkInterface = boundedString(
    context.uplinkInterface,
    `${target} uplink interface`,
    15,
  );
  if (!/^[A-Za-z0-9_.:-]+$/.test(uplinkInterface)) {
    throw new TypeError(`${target} uplink interface contains unsupported characters`);
  }
  if (context.internalInterfaces != null && !Array.isArray(context.internalInterfaces)) {
    throw new TypeError(`${target} internalInterfaces must be an array`);
  }
  const internalInterfaces = [...new Set((context.internalInterfaces || []).map((entry) => {
    const selected = boundedString(entry, `${target} internal interface`, 15);
    if (!/^[A-Za-z0-9_.:-]+$/.test(selected)) {
      throw new TypeError(`${target} internal interface contains unsupported characters`);
    }
    return selected;
  }))].sort();
  if (context.upstreamServers != null && !Array.isArray(context.upstreamServers)) {
    throw new TypeError(`${target} upstreamServers must be an array`);
  }
  const upstreamServers = [...new Set(
    (context.upstreamServers || ['1.1.1.1', '9.9.9.9']).map((server) => {
      if (net.isIP(server) !== 4) {
        throw new TypeError(`${target} upstream DNS servers must be IPv4 addresses`);
      }
      return server;
    }),
  )].sort();
  if (context.invariantBlockedCidrs != null && !Array.isArray(context.invariantBlockedCidrs)) {
    throw new TypeError(`${target} invariantBlockedCidrs must be an array`);
  }
  const invariantBlockedCidrs = [...new Set(
    (context.invariantBlockedCidrs || []).map(exactIpv4Cidr),
  )].sort();
  capabilityResult(context, []);
  return {
    ...context,
    networkName,
    uplinkInterface,
    internalInterfaces,
    upstreamServers,
    invariantBlockedCidrs,
    capabilities: Object.fromEntries(
      Object.entries(context.capabilities || {}).sort(([left], [right]) => (
        left.localeCompare(right)
      )),
    ),
  };
}

function gatewayPolicy(policy, context, rules) {
  return {
    runId: policy.scope?.subjectId || policy.graphDigest,
    mode: 'egress-enforce',
    profileRevision: policy.policyRevision || policy.decisionSetDigest,
    networkName: context.networkName,
    sourceIpv4: context.sourceIpv4,
    gatewayIpv4: context.gatewayIpv4,
    invariantBlockedCidrs: context.invariantBlockedCidrs || [],
    rules,
  };
}

export function compileNftGatewayPolicy(policyInput, contextInput) {
  const policy = normalizePolicyIrForCompilation(policyInput);
  const context = gatewayContext(contextInput, 'nft gateway');
  const capability = capabilityResult(context, [
    ...DNS_CAPABILITIES,
    'exclusiveFirewallOwnership',
    'nftset',
    'nftAtomic',
  ]);
  const projections = [];
  const rules = [];
  for (const rule of policy.rules) {
    if (rule.domain !== 'network') {
      projections.push(nonNetworkProjection(rule, 'guard-nftables'));
    } else if (rule.direction !== 'egress' || rule.peer.kind === 'workload') {
      projections.push(projection(rule, 'unsupported', {
        reasons: ['nft gateway v1 supports egress IPv4/FQDN peers only'],
      }));
    } else {
      rules.push(gatewayRule(rule));
      projections.push(projection(
        rule,
        capability.missing.length
          ? 'unsupported'
          : 'exact',
        {
          targetIds: [`nft:nosh_guard:${rule.id}`],
          preconditions: capability.missing.map((name) => `missing capability ${name}`),
          reasons: [],
        },
      ));
    }
  }
  const nativePolicy = gatewayPolicy(policy, context, rules);
  const nftables = generateNftRules([nativePolicy], [], {
    uplinkInterface: context.uplinkInterface,
  });
  const dnsmasq = generateDnsmasqConfig([nativePolicy], [], {
    internalInterfaces: context.internalInterfaces || [],
    listenAddresses: [context.gatewayIpv4],
    upstreamServers: context.upstreamServers,
    uplinkInterface: context.uplinkInterface,
    strictDomains: true,
  });
  const applyPlan = {
    schemaVersion: 1,
    backend: 'nftables-dnsmasq',
    phases: [
      'install-source-quarantine',
      'validate-dnsmasq-config',
      'load-nft-transaction',
      'restart-managed-dns',
      'purge-affected-conntrack',
      'verify-live-state',
      'remove-source-quarantine',
    ],
    failureState: 'retain-source-quarantine',
    requiresExclusiveFirewallOwnership: true,
  };
  const artifacts = {
    'gateway-policy.json': `${JSON.stringify(nativePolicy, null, 2)}\n`,
    'nftables.nft': nftables,
    'dnsmasq.conf': dnsmasq,
    'apply-plan.json': `${JSON.stringify(applyPlan, null, 2)}\n`,
  };
  return compilerResult(
    'guard-nftables',
    policy,
    context,
    projections,
    artifacts,
    { activationEligible: capability.missing.length === 0 },
  );
}

function shortHash(value, length = 12) {
  return crypto.createHash('sha256').update(String(value)).digest('hex').slice(0, length);
}

function iptablesFlowMark(policyDigest) {
  const value = (Number.parseInt(shortHash(policyDigest, 8), 16) | 0x100) >>> 0;
  return `0x${value.toString(16).padStart(8, '0')}`;
}

function iptablesSetName(policyDigest, ruleId) {
  return `ng_${policyDigest.slice(7, 15)}_${shortHash(ruleId, 12)}`.slice(0, 31);
}

function iptablesChainName(policyDigest) {
  return `NG_${policyDigest.slice(7, 23).toUpperCase()}`.slice(0, 28);
}

function iptablesMatches(rule, setName) {
  const parts = [`-m set --match-set ${setName} dst`];
  if (rule.transport.protocol === 'tcp' || rule.transport.protocol === 'udp') {
    parts.push(`-p ${rule.transport.protocol}`);
    return Array.from(
      { length: Math.ceil(rule.transport.ports.length / 15) },
      (_, index) => {
        const ports = rule.transport.ports.slice(index * 15, index * 15 + 15);
        return [...parts, ports.length === 1
          ? `--dport ${ports[0]}`
          : `-m multiport --dports ${ports.join(',')}`].join(' ');
      },
    );
  } else {
    parts.push('-p icmp');
    if (rule.transport.icmpType != null) {
      parts.push(`--icmp-type ${rule.transport.icmpType}${
        rule.transport.icmpCode == null ? '' : `/${rule.transport.icmpCode}`
      }`);
    }
  }
  return [parts.join(' ')];
}

function iptablesDnsConfig(domains, context) {
  return [
    'no-resolv',
    'no-hosts',
    'domain-needed',
    'bogus-priv',
    'stop-dns-rebind',
    'cache-size=4096',
    'min-cache-ttl=1',
    'max-cache-ttl=300',
    `listen-address=${context.gatewayIpv4}`,
    'bind-interfaces',
    `except-interface=${context.uplinkInterface}`,
    ...(context.upstreamServers || ['1.1.1.1', '9.9.9.9'])
      .map((server) => `server=${server}`),
    'connmark-allowlist-enable',
    ...(domains.length
      ? [`connmark-allowlist=1,${domains.map((entry) => entry.domain).join('/')}`]
      : []),
    ...domains.map((entry) => `ipset=/${entry.domain}/${entry.setName}`),
    '',
  ].join('\n');
}

export function compileIptablesGatewayPolicy(policyInput, contextInput) {
  const policy = normalizePolicyIrForCompilation(policyInput);
  const context = gatewayContext(contextInput, 'iptables gateway');
  const capability = capabilityResult(context, [
    ...DNS_CAPABILITIES,
    'conntrack',
    'dnsmasqIpSet',
    'exclusiveFirewallOwnership',
    'ipset',
    'iptablesRestore',
  ]);
  if (!['legacy', 'nft'].includes(context.iptablesVariant)) {
    throw new TypeError('iptablesVariant must bind legacy or nft');
  }
  const policyDigest = policy.contentDigest;
  const chain = iptablesChainName(policyDigest);
  const flowMark = iptablesFlowMark(policyDigest);
  const generationComment = `nosh-gateway:${policyDigest.slice(7, 19)}`;
  const infrastructureCommentPrefix = `nosh-gateway:${shortHash(
    `${context.sourceIpv4}|${context.gatewayIpv4}`,
    12,
  )}:infra`;
  const projections = [];
  const rules = [];
  for (const rule of policy.rules) {
    if (rule.domain !== 'network') {
      projections.push(nonNetworkProjection(rule, 'gateway-iptables'));
    } else if (rule.direction !== 'egress' || rule.peer.kind === 'workload') {
      projections.push(projection(rule, 'unsupported', {
        reasons: ['iptables gateway v1 supports egress IPv4/FQDN peers only'],
      }));
    } else if (
      rule.transport.protocol === 'icmp'
      && rule.transport.icmpCode != null
      && rule.transport.icmpType == null
    ) {
      projections.push(projection(rule, 'unsupported', {
        reasons: ['iptables cannot represent an ICMP code constraint without an ICMP type'],
      }));
    } else {
      const setName = iptablesSetName(policyDigest, rule.id);
      rules.push({ rule, setName });
      projections.push(projection(
        rule,
        capability.missing.length
          ? 'unsupported'
          : 'exact',
        {
          targetIds: [`iptables:${chain}:${rule.id}`, `ipset:${setName}`],
          preconditions: capability.missing.map((name) => `missing capability ${name}`),
          reasons: [],
        },
      ));
    }
  }
  const ipsetLines = [];
  const domainSets = [];
  for (const { rule, setName } of rules) {
    if (rule.peer.kind === 'fqdn') {
      ipsetLines.push(
        `create ${setName} hash:ip family inet timeout 300 maxelem 65536 -exist`,
        `flush ${setName}`,
      );
      domainSets.push({ domain: rule.peer.value, setName });
    } else {
      ipsetLines.push(
        `create ${setName} hash:net family inet maxelem 65536 -exist`,
        `flush ${setName}`,
        `add ${setName} ${rule.peer.value} -exist`,
      );
    }
  }
  const blocked = (context.invariantBlockedCidrs || [])
    .filter((cidr) => net.isIP(String(cidr).split('/')[0]) === 4);
  const forward = [
    `:${chain} - [0:0]`,
    `-A FORWARD -s ${context.sourceIpv4} -m comment --comment "${generationComment}:hook" -j ${chain}`,
    `-A FORWARD -d ${context.sourceIpv4} -m conntrack --ctstate ESTABLISHED,RELATED -m connmark --mark ${flowMark} -m comment --comment "${generationComment}:return" -j ACCEPT`,
    ...blocked.map((cidr) => `-A ${chain} -d ${cidr} -j DROP`),
  ];
  for (const { rule, setName } of rules) {
    for (const match of iptablesMatches(rule, setName)) {
      forward.push(
        `-A ${chain} ${match} -j CONNMARK --set-mark ${flowMark}`,
        `-A ${chain} ${match} -m connmark --mark ${flowMark} -j ACCEPT`,
      );
    }
  }
  forward.push(
    `-A ${chain} -m conntrack --ctstate ESTABLISHED,RELATED -m connmark --mark ${flowMark} -j ACCEPT`,
    `-A ${chain} -m limit --limit 20/second -j LOG --log-prefix "nosh ${chain} deny "`,
    `-A ${chain} -j DROP`,
  );
  const restore = [
    '*mangle',
    `-A PREROUTING -s ${context.sourceIpv4} -d ${context.gatewayIpv4} -p udp --dport 53 -m comment --comment "${infrastructureCommentPrefix}:dns-mark-udp" -j CONNMARK --set-mark 0x1`,
    `-A PREROUTING -s ${context.sourceIpv4} -d ${context.gatewayIpv4} -p tcp --dport 53 -m comment --comment "${infrastructureCommentPrefix}:dns-mark-tcp" -j CONNMARK --set-mark 0x1`,
    'COMMIT',
    '*filter',
    `-A INPUT -s ${context.sourceIpv4} -d ${context.gatewayIpv4} -p udp --dport 53 -m comment --comment "${infrastructureCommentPrefix}:dns-input-udp" -j ACCEPT`,
    `-A INPUT -s ${context.sourceIpv4} -d ${context.gatewayIpv4} -p tcp --dport 53 -m comment --comment "${infrastructureCommentPrefix}:dns-input-tcp" -j ACCEPT`,
    ...forward,
    'COMMIT',
    '*nat',
    `-A POSTROUTING -s ${context.sourceIpv4} -o ${context.uplinkInterface} -m comment --comment "${infrastructureCommentPrefix}:masquerade" -j MASQUERADE`,
    'COMMIT',
    '',
  ].join('\n');
  const applyPlan = {
    schemaVersion: 1,
    backend: `iptables-${context.iptablesVariant}-ipset-dnsmasq`,
    phases: [
      'install-high-priority-source-quarantine',
      'create-generation-ipsets',
      'validate-iptables-restore',
      'validate-dnsmasq-config',
      'restore-rules',
      'restart-managed-dns-with-empty-dynamic-sets',
      'purge-affected-conntrack',
      'verify-live-state',
      'remove-source-quarantine',
      'remove-unreferenced-old-generation-sets',
    ],
    failureState: 'retain-source-quarantine',
    globallyAtomic: false,
    requiresExclusiveFirewallOwnership: true,
  };
  const verifyPlan = {
    schemaVersion: 1,
    backend: applyPlan.backend,
    expectedChain: chain,
    expectedSets: rules.map((entry) => entry.setName).sort(),
    expectedSourceIpv4: context.sourceIpv4,
    expectedFlowMark: flowMark,
    expectedHookComment: `${generationComment}:hook`,
    infrastructureCommentPrefix,
    requireManagedDns: domainSets.length > 0,
  };
  const artifacts = {
    'ipset.restore': `${ipsetLines.join('\n')}\n`,
    'iptables-restore.v4': restore,
    'dnsmasq.conf': iptablesDnsConfig(domainSets, context),
    'apply-plan.json': `${JSON.stringify(applyPlan, null, 2)}\n`,
    'verify-plan.json': `${JSON.stringify(verifyPlan, null, 2)}\n`,
  };
  return compilerResult(
    'gateway-iptables',
    policy,
    context,
    projections,
    artifacts,
    {
      activationEligible: capability.missing.length === 0,
      limitations: [
        'iptables, ipset, dnsmasq, and conntrack do not share one transaction; apply retains quarantine on failure',
      ],
    },
  );
}

const PORTABLE_GATEWAY_BACKENDS = Object.freeze({
  'gateway-pf': Object.freeze({
    platform: 'openbsd',
    artifact: 'pf.anchor.conf',
  }),
  'gateway-ipfw': Object.freeze({
    platform: 'freebsd',
    artifact: 'ipfw.rules',
  }),
  'gateway-ipfilter': Object.freeze({
    platforms: Object.freeze(['illumos', 'netbsd']),
    artifact: 'ipf.conf',
  }),
});
const PORTABLE_GATEWAY_MAX_RULES = 4096;

function gatewayExportSetName(target, policyDigest, ruleId) {
  const prefix = {
    'gateway-pf': 'ngpf',
    'gateway-ipfw': 'ngfw',
    'gateway-ipfilter': 'ngipf',
  }[target];
  return `${prefix}_${policyDigest.slice(7, 15)}_${shortHash(ruleId, 8)}`;
}

function portableGatewayContext(input, target) {
  const selected = exactObjectKeys(
    input,
    [
      'capabilities',
      'gatewayIpv4',
      'networkName',
      'platform',
      'sourceIpv4',
      'target',
      'uplinkInterface',
    ],
    [],
    `${target} export target context`,
  );
  const context = gatewayContext(selected, `${target} export`);
  if (context.target !== target) {
    throw new TypeError(`${target} export target context must bind target ${target}`);
  }
  if (context.sourceIpv4 === context.gatewayIpv4) {
    throw new TypeError(`${target} sourceIpv4 and gatewayIpv4 must be distinct`);
  }
  const backend = PORTABLE_GATEWAY_BACKENDS[target];
  const platform = safeIdentifier(context.platform, `${target} platform`, 32);
  const accepted = backend.platform ? [backend.platform] : backend.platforms;
  if (!accepted.includes(platform)) {
    throw new TypeError(`${target} platform must be one of: ${accepted.join(', ')}`);
  }
  return { ...context, platform };
}

function portableGatewayRuleLine(rule, tableName, context, target) {
  const ports = rule.transport.ports;
  if (target === 'gateway-pf') {
    const port = ports.length === 1 ? String(ports[0]) : `{ ${ports.join(', ')} }`;
    return `pass out quick on $ext_if inet proto ${rule.transport.protocol} from $source_ipv4 to <${tableName}> port ${port} keep state label \"nosh:${shortHash(rule.id)}\"`;
  }
  if (target === 'gateway-ipfw') {
    const port = ports.join(',');
    return `allow ${rule.transport.protocol} from ${context.sourceIpv4} to table(${tableName}) ${port} out via ${context.uplinkInterface} keep-state`;
  }
  return ports.map((port) => (
    `pass out quick on ${context.uplinkInterface} proto ${rule.transport.protocol} from ${context.sourceIpv4} to pool/${tableName} port = ${port} keep state`
  )).join('\n');
}

function renderPortableGateway(target, policy, context, selectedRules) {
  const tables = selectedRules.map(({ rule, tableName }) => ({
    id: tableName,
    ruleId: rule.id,
    peer: rule.peer,
    addresses: rule.peer.kind === 'ipv4-cidr' ? [rule.peer.value] : [],
    dynamicDns: rule.peer.kind === 'fqdn',
  }));
  const header = [
    '# Generated by Nosh Policy Review. Render-only: validate on the named platform before activation.',
    `# policy-ir: ${policy.contentDigest}`,
    `# platform: ${context.platform}`,
  ];
  let artifacts;
  if (target === 'gateway-pf') {
    const lines = [
      ...header,
      `ext_if = \"${context.uplinkInterface}\"`,
      `source_ipv4 = \"${context.sourceIpv4}\"`,
      '',
      ...tables.map((table) => (
        table.dynamicDns
          ? `table <${table.id}> persist # managed DNS updater: ${table.peer.value}`
          : `table <${table.id}> persist { ${table.addresses.join(' ')} }`
      )),
      '',
      'match out on $ext_if inet from $source_ipv4 to any nat-to ($ext_if)',
      ...selectedRules.map(({ rule, tableName }) => (
        portableGatewayRuleLine(rule, tableName, context, target)
      )),
      'block drop out quick on $ext_if inet from $source_ipv4 to any label \"nosh:default-deny\"',
      '',
    ];
    artifacts = { 'pf.anchor.conf': lines.join('\n') };
  } else if (target === 'gateway-ipfw') {
    const lines = [
      ...header,
      '# Load these rules into a dedicated IPFW set. Rule numbers are intentionally omitted.',
      'check-state',
      ...tables.map((table) => (
        table.dynamicDns
          ? `table ${table.id} create type addr # managed DNS updater: ${table.peer.value}`
          : `table ${table.id} create type addr\ntable ${table.id} add ${table.addresses[0]}`
      )),
      ...selectedRules.map(({ rule, tableName }) => (
        portableGatewayRuleLine(rule, tableName, context, target)
      )),
      `deny log ip from ${context.sourceIpv4} to any out via ${context.uplinkInterface}`,
      '',
    ];
    artifacts = {
      'ipfw.rules': lines.join('\n'),
      'ipfw-nat.conf': [
        ...header,
        '# Integrate this NAT action after the dedicated reviewed filter set.',
        `nat 1 config if ${context.uplinkInterface}`,
        `nat 1 ip from ${context.sourceIpv4} to any out via ${context.uplinkInterface}`,
        '',
      ].join('\n'),
    };
  } else {
    const lines = [
      ...header,
      '# pool/<name> entries are populated from the separately hashed address-pool contract.',
      ...selectedRules.map(({ rule, tableName }) => (
        portableGatewayRuleLine(rule, tableName, context, target)
      )),
      `block out quick on ${context.uplinkInterface} from ${context.sourceIpv4} to any`,
      '',
    ];
    artifacts = {
      'ipf.conf': lines.join('\n'),
      'ippool.conf': [
        ...header,
        ...tables.map((table) => (
          `pool ipf/tree (name ${table.id};) { ${table.addresses.map((address) => `${address};`).join(' ')} };${table.dynamicDns ? ` # managed DNS updater: ${table.peer.value}` : ''}`
        )),
        '',
      ].join('\n'),
      'ipnat.conf': [
        ...header,
        `map ${context.uplinkInterface} ${context.sourceIpv4}/32 -> 0/32 portmap tcp/udp auto`,
        `map ${context.uplinkInterface} ${context.sourceIpv4}/32 -> 0/32`,
        '',
      ].join('\n'),
    };
  }
  const dnsTables = {
    schemaVersion: 1,
    policyIrDigest: policy.contentDigest,
    target,
    platform: context.platform,
    maximumTtlSeconds: 300,
    failureBehavior: 'empty-table-default-deny',
    tables: tables.filter((table) => table.dynamicDns).map((table) => ({
      id: table.id,
      ruleId: table.ruleId,
      fqdn: table.peer.value,
      addresses: [],
    })),
  };
  const applyPlan = {
    schemaVersion: 1,
    target,
    platform: context.platform,
    mode: 'render-only',
    forwardingRequired: true,
    sourceIpv4: context.sourceIpv4,
    gatewayIpv4: context.gatewayIpv4,
    uplinkInterface: context.uplinkInterface,
    phases: [
      'validate-native-syntax',
      'install-source-quarantine',
      'populate-reviewed-address-tables',
      'load-dedicated-ruleset',
      'enable-forwarding-and-nat',
      'verify-live-state',
      'remove-source-quarantine',
    ],
    failureState: 'retain-source-quarantine',
  };
  const gatewayExport = {
    apiVersion: 'notty.dev/v1alpha1',
    kind: 'NoshPortableGatewayPolicy',
    schemaVersion: 1,
    target,
    platform: context.platform,
    bindings: {
      graphDigest: policy.graphDigest,
      decisionSetDigest: policy.decisionSetDigest,
      policyIrDigest: policy.contentDigest,
    },
    subject: {
      sourceIpv4: context.sourceIpv4,
      gatewayIpv4: context.gatewayIpv4,
      uplinkInterface: context.uplinkInterface,
    },
    defaults: { forwarding: 'deny' },
    nat: { mode: 'uplink-interface-address' },
    rules: selectedRules.map(({ rule, tableName }) => ({
      id: rule.id,
      table: tableName,
      peer: rule.peer,
      transport: rule.transport,
    })),
  };
  const verifyPlan = {
    schemaVersion: 1,
    target,
    platform: context.platform,
    policyIrDigest: policy.contentDigest,
    expectedSourceIpv4: context.sourceIpv4,
    expectedGatewayIpv4: context.gatewayIpv4,
    expectedUplinkInterface: context.uplinkInterface,
    expectedDefault: 'deny',
    expectedTables: tables.map((table) => table.id).sort(),
    requireForwarding: true,
    requireNat: true,
    requireNoBypassRoute: true,
    verified: false,
  };
  return {
    ...artifacts,
    'gateway-policy.json': `${jcsCanonicalize(gatewayExport)}\n`,
    'dns-tables.json': `${JSON.stringify(dnsTables, null, 2)}\n`,
    'apply-plan.json': `${JSON.stringify(applyPlan, null, 2)}\n`,
    'verify-plan.json': `${JSON.stringify(verifyPlan, null, 2)}\n`,
  };
}

export function compilePortableGatewayPolicy(target, policyInput, contextInput) {
  if (!Object.hasOwn(PORTABLE_GATEWAY_BACKENDS, target)) {
    throw new TypeError(`unsupported portable gateway target: ${target}`);
  }
  const policy = normalizePolicyIrForCompilation(policyInput);
  const context = portableGatewayContext(contextInput, target);
  const projections = [];
  const selectedRules = [];
  for (const rule of policy.rules) {
    if (rule.domain !== 'network') {
      projections.push(nonNetworkProjection(rule, target));
      continue;
    }
    if (
      rule.direction !== 'egress'
      || !['ipv4-cidr', 'fqdn'].includes(rule.peer.kind)
      || !['tcp', 'udp'].includes(rule.transport.protocol)
    ) {
      projections.push(projection(rule, 'unsupported', {
        reasons: [`${target} render-only v1 supports egress IPv4/FQDN TCP/UDP rules`],
      }));
      continue;
    }
    if (selectedRules.length >= PORTABLE_GATEWAY_MAX_RULES) {
      throw new RangeError(
        `${target} render-only v1 supports at most ${PORTABLE_GATEWAY_MAX_RULES} rules`,
      );
    }
    const tableName = gatewayExportSetName(target, policy.contentDigest, rule.id);
    selectedRules.push({ rule, tableName });
    const dynamicDns = rule.peer.kind === 'fqdn';
    projections.push(projection(rule, dynamicDns ? 'conditional' : 'exact', {
      targetIds: [`${PORTABLE_GATEWAY_BACKENDS[target].artifact}:${tableName}`],
      preconditions: dynamicDns
        ? ['requires a fail-closed TTL-aware managed DNS table updater']
        : [],
      reasons: [],
    }));
  }
  const artifacts = renderPortableGateway(target, policy, context, selectedRules);
  return compilerResult(target, policy, context, projections, artifacts, {
    activationEligible: false,
    limitations: [
      'render-only projection; native syntax and live state have not been verified',
      'exact HTTP/HTTPS URL paths require a separately reviewed forced proxy policy',
      'FQDN tables require a fail-closed TTL-aware userspace updater',
    ],
  });
}

const L7_NETWORK_BACKENDS = Object.freeze([
  'guard-nftables',
  'gateway-iptables',
  'gateway-pf',
  'gateway-ipfw',
  'gateway-ipfilter',
]);

const L7_BASE_CAPABILITIES = Object.freeze([
  'completeCapture',
  'directWebDeny',
  'forcedRouting',
  'proxyPolicyAtomic',
  'quicDeny',
  'tlsInterception',
]);

function policyIrDigestPayload(document) {
  const { policyIrId, contentDigest, ...payload } = document;
  return payload;
}

function derivedPolicyIr(parent, rules) {
  const document = {
    ...parent,
    policyIrId: '',
    rules: [...rules].sort((left, right) => left.id.localeCompare(right.id)),
    contentDigest: '',
  };
  document.contentDigest = sha256Digest(policyIrDigestPayload(document));
  document.policyIrId = createStableId('policy-ir', document.contentDigest);
  validatePolicyIR(document);
  return document;
}

function derivedNetworkRule(policy, parentRule, intent) {
  const ruleBody = {
    proposalId: parentRule.proposalId,
    scopeClass: parentRule.scopeClass,
    ...intent,
    evidenceRefs: parentRule.evidenceRefs,
    decisionRefs: parentRule.decisionRefs,
  };
  return {
    id: createStableId('rule', {
      scopeDigest: policy.scope.scopeDigest,
      proposalId: parentRule.proposalId,
      scopeClass: parentRule.scopeClass,
      intent,
    }),
    ...ruleBody,
  };
}

function proxyEndpoint(input) {
  const selected = exactObjectKeys(
    input,
    ['ipv4', 'port'],
    [],
    'L7 proxy endpoint',
  );
  if (net.isIP(selected.ipv4) !== 4) {
    throw new TypeError('L7 proxy endpoint ipv4 must be an IPv4 address');
  }
  const port = Number(selected.port);
  if (!Number.isSafeInteger(port) || port < 1 || port > 65535) {
    throw new TypeError('L7 proxy endpoint port must be from 1 through 65535');
  }
  return { ipv4: selected.ipv4, port };
}

function exactDigest(value, label) {
  if (!/^sha256:[a-f0-9]{64}$/.test(String(value || ''))) {
    throw new TypeError(`${label} must be an exact SHA-256 digest`);
  }
  return value;
}

function normalizedL7NetworkContext(input, backend, role, endpoint) {
  const selected = plainObject(input, `${role} network context`);
  if (selected.target !== backend) {
    throw new TypeError(`${role} network context must bind ${backend}`);
  }
  if (role === 'proxy' && selected.sourceIpv4 !== endpoint.ipv4) {
    throw new TypeError('proxy network sourceIpv4 must equal the reviewed proxy endpoint');
  }
  return selected;
}

function normalizeL7Context(input) {
  const selected = exactObjectKeys(
    input,
    [
      'capabilities',
      'networkBackend',
      'provider',
      'proxyEndpoint',
      'proxyNetwork',
      'target',
      'workloadNetwork',
    ],
    ['contentManifest', 'contentManifestDigest'],
    'gateway-l7-proxy target context',
  );
  if (selected.target !== 'gateway-l7-proxy') {
    throw new TypeError('gateway-l7-proxy target context must bind its target');
  }
  if (!L7_NETWORK_BACKENDS.includes(selected.networkBackend)) {
    throw new TypeError(
      `gateway-l7-proxy networkBackend must be one of: ${L7_NETWORK_BACKENDS.join(', ')}`,
    );
  }
  if (selected.provider !== 'mitmproxy') {
    throw new TypeError(
      'managed gateway-l7-proxy enforcement currently supports only mitmproxy; Burp evidence remains review-only',
    );
  }
  const endpoint = proxyEndpoint(selected.proxyEndpoint);
  const capability = capabilityResult(selected, L7_BASE_CAPABILITIES);
  const workloadNetwork = normalizedL7NetworkContext(
    selected.workloadNetwork,
    selected.networkBackend,
    'workload',
    endpoint,
  );
  const proxyNetwork = normalizedL7NetworkContext(
    selected.proxyNetwork,
    selected.networkBackend,
    'proxy',
    endpoint,
  );
  if (workloadNetwork.sourceIpv4 === proxyNetwork.sourceIpv4) {
    throw new TypeError('workload and proxy network identities must be distinct');
  }
  let contentManifest = null;
  if (Object.hasOwn(selected, 'contentManifest')) {
    contentManifest = verifyHttpContentManifest(selected.contentManifest);
  }
  const contentManifestDigest = Object.hasOwn(selected, 'contentManifestDigest')
    ? exactDigest(selected.contentManifestDigest, 'contentManifestDigest')
    : contentManifest?.contentHash || null;
  if (
    contentManifest
    && contentManifestDigest !== contentManifest.contentHash
  ) {
    throw new TypeError('contentManifestDigest does not match the reviewed content manifest');
  }
  return {
    target: 'gateway-l7-proxy',
    networkBackend: selected.networkBackend,
    provider: selected.provider,
    proxyEndpoint: endpoint,
    workloadNetwork,
    proxyNetwork,
    capabilities: Object.fromEntries(
      Object.entries(capability.capabilities).sort(([left], [right]) => (
        left.localeCompare(right)
      )),
    ),
    ...(contentManifest ? { contentManifest } : {}),
    ...(contentManifestDigest ? { contentManifestDigest } : {}),
    missingBaseCapabilities: capability.missing,
  };
}

function directWebDenyPorts(policy) {
  const originPorts = policy.rules
    .filter((rule) => rule.domain === 'http')
    .map((rule) => rule.http.port);
  return {
    tcp: [...new Set([80, 443, ...originPorts])].sort((left, right) => left - right),
    udp: [...new Set([443, ...originPorts])].sort((left, right) => left - right),
  };
}

function directWebBypassRule(rule, denyPorts) {
  if (
    rule.domain !== 'network'
    || rule.effect !== 'allow'
    || rule.direction !== 'egress'
  ) return false;
  const ports = new Set(rule.transport?.ports || []);
  const denied = rule.transport?.protocol === 'tcp'
    ? denyPorts.tcp
    : rule.transport?.protocol === 'udp'
      ? denyPorts.udp
      : [];
  return denied.some((port) => ports.has(port));
}

function contentManifestEntryForRule(context, rule) {
  if (!context.contentManifest || rule.assurance?.level !== 'cas-replay') return null;
  const requestBodyDigest = rule.http.requestBodySha256 || null;
  const matches = context.contentManifest.entries.filter((entry) => (
    context.contentManifest.mode === 'offline-replay'
    && entry.request.method === rule.http.method
    && entry.request.scheme === rule.http.scheme
    && entry.request.hostname === rule.http.host.replace(/^\[|\]$/g, '')
    && entry.request.port === rule.http.port
    && entry.request.requestTargetDigest === rule.http.requestTargetSha256
    && entry.request.requestBodyDigest === requestBodyDigest
    && entry.request.representationHeadersDigest
      === rule.http.representationHeadersSha256
    && entry.response.bodyDigest === rule.assurance.contentDigest
    && (entry.response.locationDigest || null)
      === (rule.http.response?.redirectLocationSha256 || null)
    && (
      !rule.http.response?.status
      || entry.response.status === rule.http.response.status
    )
    && (
      !rule.http.response?.length
      || String(entry.response.bodyBytes) === rule.http.response.length
    )
    && context.contentManifest.contentHash === rule.assurance.proofDigest
  ));
  return matches.length === 1 ? matches[0] : null;
}

function deploymentContentManifest(context, httpRules) {
  if (!context.contentManifest) return null;
  const selected = new Map();
  for (const rule of httpRules) {
    if (rule.assurance?.level !== 'cas-replay') continue;
    const entry = contentManifestEntryForRule(context, rule);
    if (entry) selected.set(entry.requestKey, entry);
  }
  if (selected.size === 0) return null;
  return createHttpContentManifest({
    runId: context.contentManifest.runId,
    mode: 'offline-replay',
    generatedAt: context.contentManifest.generatedAt,
    entries: [...selected.values()],
  });
}

function compileL7NetworkBackend(target, policy, context) {
  if (target === 'guard-nftables') return compileNftGatewayPolicy(policy, context);
  if (target === 'gateway-iptables') return compileIptablesGatewayPolicy(policy, context);
  return compilePortableGatewayPolicy(target, policy, context);
}

function httpOriginPeer(http) {
  const unbracketed = http.host.startsWith('[') && http.host.endsWith(']')
    ? http.host.slice(1, -1)
    : http.host;
  const family = net.isIP(unbracketed);
  if (family === 4) return { kind: 'ipv4-cidr', value: `${unbracketed}/32` };
  if (family === 6) return { kind: 'ipv6-cidr', value: `${unbracketed}/128` };
  return { kind: 'fqdn', value: unbracketed };
}

function l7CapabilityRequirements(rule) {
  const level = rule.assurance?.level;
  if (level === 'native-integrity') return ['nativeIntegrity'];
  if (level === 'cas-replay') return ['offlineReplay'];
  if (level === 'live-digest-gate') return ['bufferBeforeRelease', 'liveDigestGate'];
  return [];
}

function prefixedArtifacts(prefix, artifacts) {
  return Object.fromEntries(Object.entries(artifacts).map(([name, content]) => [
    `${prefix}-${name}`,
    content,
  ]));
}

function projectionByRule(result) {
  return new Map(result.projections.map((entry) => [entry.ruleId, entry]));
}

function worseParity(left, right) {
  const order = new Map([
    ['exact', 0],
    ['restrictive', 1],
    ['conditional', 2],
    ['permissive', 3],
    ['unsupported', 4],
    ['outsideScope', 5],
  ]);
  return order.get(left) >= order.get(right) ? left : right;
}

/**
 * Compile a reviewed web authority as one digest-bound composite leaf.
 *
 * The workload and proxy are deliberately rendered as separate network
 * subjects.  The workload may reach only the fixed proxy endpoint for each
 * accepted HTTP rule; the proxy receives the independently reviewed origin
 * authority.  The provider policy then narrows that origin reachability to
 * the exact request and, when selected, response identity.
 */
export function compileL7ProxyGatewayPolicy(policyInput, contextInput) {
  const policy = normalizePolicyIrForCompilation(policyInput);
  const context = normalizeL7Context(contextInput);
  const workloadRules = [];
  const proxyRules = [];
  const derived = new Map();
  const httpRules = [];
  const bypassConflicts = new Set();
  const strictWebRouting = policy.rules.some((rule) => rule.domain === 'http');
  const deniedDirectWebPorts = directWebDenyPorts(policy);
  const bypassConflictReason = [
    'a forced-proxy projection cannot also authorize direct workload',
    `TCP ports ${deniedDirectWebPorts.tcp.join(', ')}`,
    `or UDP ports ${deniedDirectWebPorts.udp.join(', ')}`,
  ].join(' ');

  for (const rule of policy.rules) {
    if (rule.domain === 'network') {
      if (strictWebRouting && directWebBypassRule(rule, deniedDirectWebPorts)) {
        bypassConflicts.add(rule.id);
      } else {
        workloadRules.push(rule);
      }
      continue;
    }
    if (rule.domain !== 'http') continue;
    const clientRule = derivedNetworkRule(policy, rule, {
      domain: 'network',
      subjectId: rule.subjectId,
      effect: 'allow',
      direction: 'egress',
      peer: { kind: 'ipv4-cidr', value: `${context.proxyEndpoint.ipv4}/32` },
      transport: {
        protocol: 'tcp',
        ports: [context.proxyEndpoint.port],
      },
    });
    const originRule = derivedNetworkRule(policy, rule, {
      domain: 'network',
      subjectId: rule.subjectId,
      effect: 'allow',
      direction: 'egress',
      peer: httpOriginPeer(rule.http),
      transport: {
        protocol: 'tcp',
        ports: [rule.http.port],
      },
    });
    workloadRules.push(clientRule);
    proxyRules.push(originRule);
    derived.set(rule.id, { clientRule, originRule });
    httpRules.push(rule);
  }

  const workloadPolicy = derivedPolicyIr(policy, workloadRules);
  const proxyPolicy = derivedPolicyIr(policy, proxyRules);
  const workloadResult = compileL7NetworkBackend(
    context.networkBackend,
    workloadPolicy,
    context.workloadNetwork,
  );
  const proxyResult = compileL7NetworkBackend(
    context.networkBackend,
    proxyPolicy,
    context.proxyNetwork,
  );
  const workloadProjections = projectionByRule(workloadResult);
  const proxyProjections = projectionByRule(proxyResult);
  const projections = [];

  for (const rule of policy.rules) {
    if (rule.domain === 'network') {
      if (bypassConflicts.has(rule.id)) {
        projections.push(projection(rule, 'unsupported', {
          reasons: [bypassConflictReason],
        }));
        continue;
      }
      const network = workloadProjections.get(rule.id);
      if (!network) throw new Error(`workload compiler omitted network rule ${rule.id}`);
      projections.push(projection(rule, network.parity, {
        targetIds: (network.targetIds || []).map((id) => `workload:${id}`),
        preconditions: network.preconditions,
        reasons: network.reasons,
      }));
      continue;
    }
    if (rule.domain !== 'http') {
      projections.push(projection(rule, 'outsideScope', {
        reasons: ['gateway-l7-proxy does not compile this policy domain'],
      }));
      continue;
    }
    const pair = derived.get(rule.id);
    const client = workloadProjections.get(pair.clientRule.id);
    const origin = proxyProjections.get(pair.originRule.id);
    if (!client || !origin) throw new Error(`network compiler omitted HTTP legs for ${rule.id}`);
    const required = l7CapabilityRequirements(rule);
    const missing = [
      ...context.missingBaseCapabilities,
      ...required.filter((name) => context.capabilities[name] !== true),
      ...(rule.assurance?.level === 'cas-replay' && !context.contentManifestDigest
        ? ['contentManifestDigest']
        : []),
      ...(rule.assurance?.level === 'cas-replay'
        && !contentManifestEntryForRule(context, rule)
        ? ['reviewed CAS manifest membership']
        : []),
    ];
    let parity = worseParity(client.parity, origin.parity);
    if (missing.length) parity = 'unsupported';
    projections.push(projection(rule, parity, {
      targetIds: [
        ...(client.targetIds || []).map((id) => `workload:${id}`),
        ...(origin.targetIds || []).map((id) => `proxy:${id}`),
        `proxy-policy:${rule.id}`,
      ],
      preconditions: [
        ...(client.preconditions || []),
        ...(origin.preconditions || []),
        ...missing.map((name) => `missing capability or binding ${name}`),
      ],
      reasons: [
        ...(client.reasons || []),
        ...(origin.reasons || []),
      ],
    }));
  }

  const proxyPolicyArtifact = {
    apiVersion: 'notty.dev/v1alpha1',
    kind: 'NoshReviewedHttpProxyPolicy',
    schemaVersion: 1,
    provider: context.provider,
    bindings: {
      graphDigest: policy.graphDigest,
      decisionSetDigest: policy.decisionSetDigest,
      policyIrDigest: policy.contentDigest,
      workloadNetworkPolicyDigest: workloadPolicy.contentDigest,
      proxyNetworkPolicyDigest: proxyPolicy.contentDigest,
      ...(context.contentManifestDigest
        ? { reviewContentManifestDigest: context.contentManifestDigest }
        : {}),
    },
    defaults: {
      requests: 'deny',
      redirects: 'deny-each-unreviewed-hop',
      opaqueConnect: 'deny',
      streaming: 'deny-when-content-bound',
      directWeb: 'deny',
      quic: 'deny',
    },
    lifecycle: {
      learn: 'observe',
      audit: 'allow-and-report-would-deny',
      enforce: 'default-deny',
    },
    rules: httpRules.map((rule) => ({
      id: rule.id,
      authorityGroupId: rule.authorityGroupId,
      assurance: rule.assurance,
      request: rule.http,
    })),
  };
  const selectedContentManifest = deploymentContentManifest(context, httpRules);
  if (selectedContentManifest) {
    proxyPolicyArtifact.bindings.contentManifestDigest = selectedContentManifest.contentHash;
  }
  const topology = {
    schemaVersion: 1,
    provider: context.provider,
    networkBackend: context.networkBackend,
    workload: {
      sourceIpv4: context.workloadNetwork.sourceIpv4,
      allowedWebEndpoint: context.proxyEndpoint,
      deniedDirectTcpPorts: deniedDirectWebPorts.tcp,
      deniedDirectUdpPorts: deniedDirectWebPorts.udp,
    },
    proxy: {
      sourceIpv4: context.proxyNetwork.sourceIpv4,
      endpoint: context.proxyEndpoint,
      ownsOriginDns: true,
      unrestrictedConnect: false,
    },
  };
  const applyPlan = {
    schemaVersion: 1,
    target: 'gateway-l7-proxy',
    phases: [
      'install-workload-and-proxy-quarantine',
      'validate-content-and-proxy-policy',
      'load-workload-network-policy',
      'load-proxy-origin-network-policy',
      'start-policy-bound-proxy',
      'verify-direct-web-and-quic-bypass-denied',
      'verify-proxy-policy-and-content-gate',
      'remove-quarantine',
    ],
    failureState: 'retain-workload-and-proxy-quarantine',
    requireAllLayersVerified: true,
  };
  const verifyPlan = {
    schemaVersion: 1,
    target: 'gateway-l7-proxy',
    policyIrDigest: policy.contentDigest,
    expectedProvider: context.provider,
    expectedNetworkBackend: context.networkBackend,
    expectedProxyEndpoint: context.proxyEndpoint,
    requiredDirectTcpDenyPorts: deniedDirectWebPorts.tcp,
    requiredDirectUdpDenyPorts: deniedDirectWebPorts.udp,
    requireOpaqueConnectDeny: true,
    requireCompleteCapture: true,
    requirePolicyAndEvidenceCounters: true,
    verified: false,
  };
  const artifacts = {
    ...prefixedArtifacts('workload', workloadResult.artifacts),
    ...prefixedArtifacts('proxy', proxyResult.artifacts),
    'http-proxy-policy.json': `${jcsCanonicalize(proxyPolicyArtifact)}\n`,
    ...(selectedContentManifest ? {
      'http-content-manifest.json': `${jcsCanonicalize(selectedContentManifest)}\n`,
    } : {}),
    'proxy-topology.json': `${jcsCanonicalize(topology)}\n`,
    'composite-apply-plan.json': `${jcsCanonicalize(applyPlan)}\n`,
    'composite-verify-plan.json': `${jcsCanonicalize(verifyPlan)}\n`,
  };
  const {
    missingBaseCapabilities: ignoredMissingBaseCapabilities,
    ...deploymentContext
  } = context;
  return compilerResult(
    'gateway-l7-proxy',
    policy,
    deploymentContext,
    projections,
    artifacts,
    {
      activationEligible: false,
      limitations: [
        'gateway-l7-proxy v1 is a render-only composite export until a host actuator atomically applies and verifies both network legs and the proxy content gate',
        'HTTP capture evidence is not authoritative for network reachability; both network legs remain independently enforced',
        'a reviewed response digest binds bytes to the observation but does not establish that the observed bytes were safe',
        ...(Object.hasOwn(PORTABLE_GATEWAY_BACKENDS, context.networkBackend)
          ? ['selected native gateway output is render-only and cannot be activated until live validation succeeds']
          : []),
      ],
    },
  );
}

export function compilePolicyTarget(target, policy, context) {
  if (target === 'cilium') return compileCiliumPolicy(policy, context);
  if (target === 'guard-ebpf') return compileEbpfPolicy(policy, context);
  if (target === 'guard-nftables' || target === 'guard-nft') {
    return compileNftGatewayPolicy(policy, context);
  }
  if (target === 'gateway-iptables') {
    return compileIptablesGatewayPolicy(policy, context);
  }
  if (Object.hasOwn(PORTABLE_GATEWAY_BACKENDS, target)) {
    return compilePortableGatewayPolicy(target, policy, context);
  }
  if (target === 'gateway-l7-proxy') {
    return compileL7ProxyGatewayPolicy(policy, context);
  }
  throw new TypeError(`unsupported policy target: ${target}`);
}
