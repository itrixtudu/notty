import crypto from 'node:crypto';
import net from 'node:net';

import { SECURITY_MODES } from './constants.js';
import { isGrantActive } from './grants.js';

function identifier(value) {
  return crypto.createHash('sha256').update(String(value)).digest('hex').slice(0, 12);
}

function policyFlowMark(policy) {
  const digest = crypto
    .createHash('sha256')
    .update(JSON.stringify({
      runId: policy.runId,
      mode: policy.mode,
      profileRevision: policy.profileRevision,
      rules: policy.rules,
    }))
    .digest();
  const value = (digest.readUInt32BE(0) | 0x100) >>> 0;
  return `0x${value.toString(16).padStart(8, '0')}`;
}

export function egressPolicyFlowMark(inputPolicy, grants = []) {
  return policyFlowMark(normalizeEgressPolicy(inputPolicy, grants));
}

function validateIp(value, family, label) {
  if (net.isIP(value) !== family) {
    throw new TypeError(`${label} must be IPv${family}: ${value}`);
  }
  return value;
}

function normalizeProtocol(value) {
  const protocol = String(value || '').toLowerCase();
  if (!['tcp', 'udp', 'icmp', 'icmpv6'].includes(protocol)) {
    throw new TypeError(`unsupported egress protocol: ${value}`);
  }
  return protocol;
}

function normalizePorts(value, protocol) {
  if (protocol === 'icmp' || protocol === 'icmpv6') {
    return [];
  }
  const ports = (Array.isArray(value) ? value : [value])
    .flatMap((entry) => String(entry || '').split(','))
    .map((entry) => Number(entry));
  if (ports.some((port) => !Number.isSafeInteger(port) || port < 1 || port > 65535)) {
    throw new TypeError(`${protocol} egress rule requires valid ports`);
  }
  return [...new Set(ports)].sort((left, right) => left - right);
}

function validDomainName(domain) {
  return domain.length <= 253
    && domain.includes('.')
    && domain.split('.').every(
      (label) =>
        label.length >= 1
        && label.length <= 63
        && /^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/.test(label),
    );
}

function normalizeDestination(value) {
  const destination = String(value || '').toLowerCase().trim();
  if (!destination) {
    throw new TypeError('egress destination is required');
  }
  const destinationParts = destination.split('/');
  if (destinationParts.length > 2) {
    throw new TypeError(`invalid egress destination: ${destination}`);
  }
  const [address, prefix] = destinationParts;
  const family = net.isIP(address);
  if (family) {
    const maxPrefix = family === 4 ? 32 : 128;
    if (prefix === '') {
      throw new TypeError(`invalid CIDR prefix: ${destination}`);
    }
    const normalizedPrefix = prefix == null ? maxPrefix : Number(prefix);
    if (
      !Number.isSafeInteger(normalizedPrefix) ||
      normalizedPrefix < 0 ||
      normalizedPrefix > maxPrefix
    ) {
      throw new TypeError(`invalid CIDR prefix: ${destination}`);
    }
    return {
      kind: 'cidr',
      family,
      value: `${address}/${normalizedPrefix}`,
    };
  }
  const wildcard = destination.startsWith('*.');
  const domain = wildcard ? destination.slice(2) : destination;
  if (
    !validDomainName(domain)
  ) {
    throw new TypeError(`invalid FQDN destination: ${destination}`);
  }
  return {
    kind: 'fqdn',
    family: null,
    value: wildcard ? `*.${domain}` : domain,
  };
}

function normalizeIcmpField(value, label) {
  if (value == null || value === '') {
    return null;
  }
  const normalized = Number(value);
  if (
    !Number.isSafeInteger(normalized) ||
    normalized < 0 ||
    normalized > 255
  ) {
    throw new TypeError(`${label} must be an integer from 0 to 255`);
  }
  return normalized;
}

function normalizeRule(rule, source = 'profile') {
  const protocol = normalizeProtocol(rule.protocol);
  const destination = normalizeDestination(
    rule.destination || rule.fqdn || rule.cidr,
  );
  if (protocol === 'icmpv6' || destination.family === 6) {
    throw new TypeError(
      'IPv6 egress rules are unsupported by the IPv4-only runner network',
    );
  }
  return {
    id: identifier(
      `${source}:${destination.kind}:${destination.value}:${protocol}:${JSON.stringify(
        rule.ports || [],
      )}`,
    ),
    source,
    destination,
    protocol,
    ports: normalizePorts(rule.ports, protocol),
    icmpType: normalizeIcmpField(rule.icmpType, 'icmpType'),
    icmpCode: normalizeIcmpField(rule.icmpCode, 'icmpCode'),
  };
}

function grantRules(policy, grants) {
  return grants
    .filter(
      (grant) =>
        isGrantActive(grant) &&
        grant.runId === policy.runId,
    )
    .map((grant) => normalizeRule(grant, `grant:${grant.id}`));
}

export function egressModeBehavior(mode) {
  switch (mode) {
    case 'learn':
    case 'egress-learn':
      return 'record-allow';
    case 'audit':
    case 'egress-audit':
      return 'would-deny-allow';
    case 'enforce':
    case 'egress-enforce':
      return 'allowlist-drop';
    default:
      throw new TypeError(`unsupported egress mode: ${mode}`);
  }
}

export function requiresStrictManagedDns(mode) {
  return egressModeBehavior(mode) === 'allowlist-drop';
}

export function normalizeEgressPolicy(input, grants = []) {
  if (!input || typeof input !== 'object') {
    throw new TypeError('egress policy must be an object');
  }
  if (!SECURITY_MODES.includes(input.mode)) {
    throw new TypeError(`egress mode must be one of: ${SECURITY_MODES.join(', ')}`);
  }
  const policy = {
    runId: String(input.runId || ''),
    mode: input.mode,
    profileRevision: input.profileRevision || 'candidate',
    networkName: String(input.networkName || ''),
    sourceIpv4: validateIp(input.sourceIpv4, 4, 'sourceIpv4'),
    gatewayIpv4: validateIp(input.gatewayIpv4, 4, 'gatewayIpv4'),
    rules: (input.egress || input.rules || []).map((rule) =>
      normalizeRule(rule),
    ),
    invariantBlockedCidrs: input.invariantBlockedCidrs || [],
  };
  if (!policy.runId || !policy.networkName) {
    throw new TypeError('egress policy requires runId and networkName');
  }
  policy.rules.push(...grantRules(policy, grants));
  return policy;
}

function setName(policy, rule, family) {
  return `r_${identifier(policy.runId)}_${rule.id}_${family}`;
}

function nftSet(policy, rule, family) {
  const name = setName(policy, rule, family);
  const type = family === 4 ? 'ipv4_addr' : 'ipv6_addr';
  const cidr =
    rule.destination.kind === 'cidr' && rule.destination.family === family
      ? rule.destination.value
      : null;
  return [
    `  set ${name} {`,
    `    type ${type}`,
    cidr ? '    flags interval' : '    flags interval,timeout',
    // dnsmasq caps positive answers at five minutes below. nftset updates do
    // not carry the individual DNS TTL, so the set default must never outlive
    // that resolver cache ceiling.
    cidr ? '' : '    timeout 5m',
    cidr ? `    elements = { ${cidr} }` : '',
    '  }',
  ]
    .filter(Boolean)
    .join('\n');
}

function matchExpression(policy, rule, requestedFamily = null) {
  const family =
    requestedFamily ||
    (rule.protocol === 'icmpv6' ? 6 : rule.destination.family || 4);
  const addressKeyword = family === 4 ? 'ip daddr' : 'ip6 daddr';
  const destination = `${addressKeyword} @${setName(policy, rule, family)}`;
  if (rule.protocol === 'tcp' || rule.protocol === 'udp') {
    if (!rule.ports.length) {
      return `${destination} ${rule.protocol}`;
    }
    const ports =
      rule.ports.length === 1
        ? String(rule.ports[0])
        : `{ ${rule.ports.join(', ')} }`;
    return `${destination} ${rule.protocol} dport ${ports}`;
  }
  const protocol = rule.protocol === 'icmpv6' ? 'icmpv6' : 'icmp';
  const details = [];
  if (Number.isInteger(rule.icmpType)) {
    details.push(`${protocol} type ${rule.icmpType}`);
  }
  if (Number.isInteger(rule.icmpCode)) {
    details.push(`${protocol} code ${rule.icmpCode}`);
  }
  return details.length
    ? `${destination} ${details.join(' ')}`
    : `${destination} meta l4proto ${protocol}`;
}

function blockedSets(policies, family) {
  const type = family === 4 ? 'ipv4_addr' : 'ipv6_addr';
  const elements = [
    ...new Set(
      policies
        .flatMap((policy) => policy.invariantBlockedCidrs)
        .filter((cidr) => net.isIP(String(cidr).split('/')[0]) === family),
    ),
  ].sort();
  return [
    `  set invariant_blocked_v${family} {`,
    `    type ${type}`,
    '    flags interval',
    elements.length ? `    elements = { ${elements.join(', ')} }` : '',
    '  }',
  ]
    .filter(Boolean)
    .join('\n');
}

function policyRules(policy) {
  const source = `ip saddr ${policy.sourceIpv4}`;
  const runHash = identifier(policy.runId);
  const prefix = `nosh_guard ${runHash}`;
  const lines = [];
  const behavior = egressModeBehavior(policy.mode);
  const flowMark = policyFlowMark(policy);
  switch (behavior) {
    case 'record-allow':
      lines.push(
        `    ${source} limit rate 20/second log prefix "${prefix} ${policy.mode} allow "`,
        `    ${source} ct mark set ${flowMark} counter accept comment "nosh:${runHash}:${policy.mode}-observed"`,
      );
      return lines;
    case 'would-deny-allow':
    case 'allowlist-drop':
      break;
    default:
      throw new TypeError(`unsupported egress behavior: ${behavior}`);
  }
  for (const rule of policy.rules) {
    const families = [4];
    for (const family of families) {
      lines.push(
        `    ${source} ${matchExpression(
          policy,
          rule,
          family,
        )} ct mark set ${flowMark} counter accept comment "${rule.source}"`,
      );
    }
  }
  lines.push(
    `    ${source} ct state established,related ct mark ${flowMark} counter accept comment "nosh:${runHash}:${policy.mode}-established"`,
  );
  switch (behavior) {
    case 'would-deny-allow':
      lines.push(
        `    ${source} limit rate 20/second log prefix "${prefix} ${policy.mode} would-deny "`,
        `    ${source} ct mark set ${flowMark} counter accept comment "nosh:${runHash}:${policy.mode}-would-deny"`,
      );
      break;
    case 'allowlist-drop':
      lines.push(
        `    ${source} limit rate 20/second log prefix "${prefix} ${policy.mode} deny "`,
        `    ${source} counter drop comment "nosh:${runHash}:${policy.mode}-deny"`,
      );
      break;
    default:
      throw new TypeError(`unsupported egress behavior: ${behavior}`);
  }
  return lines;
}

function policyGuardrailRules(policy) {
  const source = `ip saddr ${policy.sourceIpv4}`;
  const runHash = identifier(policy.runId);
  const families = new Set(policy.invariantBlockedCidrs.map(
    (cidr) => net.isIP(String(cidr).split('/')[0]),
  ));
  return [
    ...(families.has(4)
      ? [`    ${source} ip daddr @invariant_blocked_v4 counter drop comment "nosh:${runHash}:invariant-deny"`]
      : []),
    ...(families.has(6)
      ? [`    ${source} ip6 daddr @invariant_blocked_v6 counter drop comment "nosh:${runHash}:invariant-deny"`]
      : []),
  ];
}

export function generateNftRules(inputPolicies, grants = [], options = {}) {
  const policies = inputPolicies.map((policy) =>
    normalizeEgressPolicy(policy, grants),
  );
  const uplinkInterface = options.uplinkInterface || 'eth0';
  if (!/^[A-Za-z0-9_.:-]+$/.test(uplinkInterface)) {
    throw new TypeError('invalid uplink interface');
  }
  const flowMarks = policies.map(policyFlowMark);
  if (new Set(flowMarks).size !== flowMarks.length) {
    throw new Error('managed egress policy flow-mark collision');
  }
  const sets = [
    blockedSets(policies, 4),
    blockedSets(policies, 6),
    ...policies.flatMap((policy) =>
      policy.rules.flatMap((rule) => {
        if (rule.destination.kind === 'cidr') {
          return [nftSet(policy, rule, rule.destination.family)];
        }
        return [nftSet(policy, rule, 4)];
      }),
    ),
  ];
  const inputDns = [...policies]
    .sort((left, right) => left.sourceIpv4.localeCompare(right.sourceIpv4))
    .flatMap((policy) => [
      `    ip saddr ${policy.sourceIpv4} ip daddr ${policy.gatewayIpv4} udp dport 53 ct mark set 1 counter accept`,
      `    ip saddr ${policy.sourceIpv4} ip daddr ${policy.gatewayIpv4} tcp dport 53 ct mark set 1 counter accept`,
    ]);
  const sources = [...new Set(policies.map((policy) => policy.sourceIpv4))];
  const blockedFamilies = new Set(policies.flatMap((policy) => (
    policy.invariantBlockedCidrs.map(
      (cidr) => net.isIP(String(cidr).split('/')[0]),
    )
  )));
  const natSources =
    sources.length === 1
      ? `ip saddr ${sources[0]}`
      : sources.length
        ? `ip saddr { ${sources.join(', ')} }`
        : 'ip saddr 0.0.0.0/32';

  return [
    'table inet nosh_guard {',
    ...sets,
    '  chain input {',
    '    type filter hook input priority filter; policy drop;',
    '    iifname "lo" accept',
    '    ct state established,related accept',
    ...inputDns,
    '  }',
    '  chain forward {',
    '    type filter hook forward priority filter; policy drop;',
    ...policies.flatMap(policyGuardrailRules),
    ...policies.flatMap(policyRules),
    // A source with no live policy must not inherit an old established flow.
    '    ip saddr 10.240.0.0/16 counter drop',
    // Current policy marks preserve long-lived approved flows across DNS-set
    // expiry, while a policy/grant revision changes the mark and revokes both
    // directions without depending on conntrack deletion.
    ...(flowMarks.length
      ? [`    ct state established,related ct mark { ${flowMarks.join(', ')} } accept`]
      : []),
    ...(blockedFamilies.has(4)
      ? ['    ip daddr @invariant_blocked_v4 counter drop']
      : []),
    ...(blockedFamilies.has(6)
      ? ['    ip6 daddr @invariant_blocked_v6 counter drop']
      : []),
    '  }',
    '  chain output {',
    '    type filter hook output priority filter; policy accept;',
    '  }',
    '  chain postrouting {',
    '    type nat hook postrouting priority srcnat; policy accept;',
    `    oifname "${uplinkInterface}" ${natSources} masquerade`,
    '  }',
    '}',
    '',
  ].join('\n');
}

export function generateDnsmasqConfig(inputPolicies, grants = [], options = {}) {
  const policies = inputPolicies.map((policy) =>
    normalizeEgressPolicy(policy, grants),
  );
  const interfaces = [...new Set(options.internalInterfaces || [])].sort();
  const listenAddresses = [
    ...new Set(
      [
        ...(options.listenAddresses || []),
        ...(options.listenAddress ? [options.listenAddress] : []),
      ].filter(Boolean),
    ),
  ].sort();
  for (const address of listenAddresses) {
    if (![4, 6].includes(net.isIP(address))) {
      throw new TypeError(`invalid DNS listen address: ${address}`);
    }
  }
  const upstreamServers = options.upstreamServers || ['1.1.1.1', '9.9.9.9'];
  for (const server of upstreamServers) {
    if (![4, 6].includes(net.isIP(server))) {
      throw new TypeError(`invalid upstream DNS server: ${server}`);
    }
  }
  const domainSets = new Map();
  for (const policy of policies) {
    for (const rule of policy.rules) {
      if (rule.destination.kind !== 'fqdn') {
        continue;
      }
      const entries = domainSets.get(rule.destination.value) || [];
      entries.push(`4#inet#nosh_guard#${setName(policy, rule, 4)}`);
      domainSets.set(rule.destination.value, entries);
    }
  }
  const strictDomains = options.strictDomains === true;
  const directiveDomain = (domain) => domain;
  if (
    options.pidFile &&
    (typeof options.pidFile !== 'string' ||
      !options.pidFile.startsWith('/') ||
      /[\r\n]/.test(options.pidFile))
  ) {
    throw new TypeError('dnsmasq pidFile must be a safe absolute path');
  }
  return [
    'no-resolv',
    'no-hosts',
    'domain-needed',
    'bogus-priv',
    'stop-dns-rebind',
    'log-queries=proto',
    'log-async=25',
    'cache-size=4096',
    'min-cache-ttl=1',
    'max-cache-ttl=300',
    'neg-ttl=30',
    ...(options.pidFile ? [`pid-file=${options.pidFile}`] : []),
    ...(listenAddresses.length
      ? ['bind-interfaces', ...listenAddresses.map((address) => `listen-address=${address}`)]
      : ['bind-dynamic']),
    'user=nobody',
    `except-interface=${options.uplinkInterface || 'eth0'}`,
    ...(!listenAddresses.length && interfaces.length
      ? interfaces.map((name) => `interface=${name}`)
      : !listenAddresses.length
        ? ['interface=lo']
        : []),
    ...upstreamServers.map((server) => `server=${server}`),
    ...(strictDomains
      ? [
          'connmark-allowlist-enable',
          ...(domainSets.size
            ? [
                `connmark-allowlist=1,${[...domainSets.keys()]
                  .sort()
                  .join('/')}`,
              ]
            : []),
        ]
      : []),
    ...[...domainSets.entries()]
      .sort(([left], [right]) => left.localeCompare(right))
      .map(
        ([domain, sets]) =>
          `nftset=/${directiveDomain(domain)}/${[...new Set(sets)].sort().join(',')}`,
      ),
    '',
  ].join('\n');
}

export function policySetNames(inputPolicy, grants = []) {
  const policy = normalizeEgressPolicy(inputPolicy, grants);
  return policy.rules.flatMap((rule) => {
    if (rule.destination.kind === 'cidr') {
      return [setName(policy, rule, rule.destination.family)];
    }
    return [setName(policy, rule, 4)];
  });
}
