import crypto from 'node:crypto';
import {
  closeSync,
  constants as fsConstants,
  fstatSync,
  lstatSync,
  openSync,
  readFileSync,
  realpathSync,
} from 'node:fs';
import fs from 'node:fs/promises';
import net from 'node:net';
import path from 'node:path';
import { spawnSync } from 'node:child_process';

import {
  DEFAULT_GUARD_CONFIG_DIR,
  DEFAULT_GUARD_STATE_DIR,
} from './constants.js';
import { stableStringify } from '../guard/stable.js';

export const EBPF_EGRESS_BACKEND = 'nosh-egress';
export const EBPF_EGRESS_MAP_ABI = 2;
export const EBPF_EGRESS_PROGRAM_ABI = 2;
export const EBPF_EGRESS_BACKEND_ABI = 'nosh-egress-v2';
export const EBPF_EGRESS_CAPABILITIES = Object.freeze({
  atomicPolicyGeneration: true,
  cgroupConnect: true,
  cgroupSendmsg: true,
  cgroupSkb: true,
  dnsParser: true,
  exactPlatformContainment: true,
  ipv6: true,
  tcpDns: false,
  ttlGrants: true,
});
export const EBPF_PLATFORM_CONTAINMENT = Object.freeze({
  strategy: 'per-run-docker-bridge-gateways',
  ipv4PrefixLength: 32,
  ipv6PrefixLength: 128,
});
export const DEFAULT_EBPF_EGRESS_LOADER =
  '/usr/local/libexec/nosh-guard/nosh-egress-loader';
export const DEFAULT_EBPF_EGRESS_RESOLVERS = Object.freeze([
  '1.1.1.1',
  '8.8.8.8',
]);

const EBPF_EGRESS_RESOLVER_MAX = 32;

const SAFE_RUN_ID = /^[A-Za-z0-9_.-]{1,128}$/;
const EXACT_DIGEST = /^sha256:[a-f0-9]{64}$/;
const WORKSPACE_KEY = /^[a-f0-9]{64}$/;
const DOMAIN = /^(?:\*\.)?[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?$/;
const MODES = new Map([
  ['egress-learn', 'learn'],
  ['egress-audit', 'audit'],
  ['egress-enforce', 'enforce'],
]);

const OBJECT_DIGEST = EXACT_DIGEST;

function configuredInstalledLoaderPath() {
  const versionsPath = path.join(DEFAULT_GUARD_CONFIG_DIR, 'versions.json');
  let stat;
  try {
    stat = lstatSync(versionsPath);
  } catch (error) {
    if (error.code === 'ENOENT') return DEFAULT_EBPF_EGRESS_LOADER;
    throw error;
  }
  if (
    !stat.isFile()
    || stat.isSymbolicLink()
    || stat.uid !== 0
    || (stat.mode & 0o022) !== 0
    || stat.size > 1024 * 1024
    || realpathSync(versionsPath) !== path.resolve(versionsPath)
  ) {
    throw new Error('installed Nosh Guard version contract is not trusted');
  }
  for (
    let directory = path.dirname(versionsPath);
    ;
    directory = path.dirname(directory)
  ) {
    const ancestor = lstatSync(directory);
    if (
      !ancestor.isDirectory()
      || ancestor.isSymbolicLink()
      || ancestor.uid !== 0
      || (ancestor.mode & 0o022) !== 0
    ) {
      throw new Error('installed Nosh Guard version contract ancestry is not trusted');
    }
    if (directory === path.parse(directory).root) break;
  }
  const fd = openSync(
    versionsPath,
    fsConstants.O_RDONLY | (fsConstants.O_NOFOLLOW || 0),
  );
  let raw;
  try {
    const opened = fstatSync(fd);
    if (
      !opened.isFile()
      || opened.dev !== stat.dev
      || opened.ino !== stat.ino
      || opened.size !== stat.size
    ) {
      throw new Error('installed Nosh Guard version contract changed while opening');
    }
    raw = readFileSync(fd, 'utf8');
  } finally {
    closeSync(fd);
  }
  const document = JSON.parse(raw);
  const loaderPath = document?.noshEgress?.loaderPath;
  if (
    typeof loaderPath !== 'string'
    || !path.isAbsolute(loaderPath)
    || loaderPath.includes('\0')
  ) {
    throw new Error('installed Nosh Guard version contract has no eBPF loader path');
  }
  return path.resolve(loaderPath);
}

function canonicalIpv4(value) {
  return [24n, 16n, 8n, 0n]
    .map((shift) => Number((value >> shift) & 0xffn))
    .join('.');
}

function canonicalIpv6(value) {
  const words = [];
  for (let shift = 112n; shift >= 0n; shift -= 16n) {
    words.push(Number((value >> shift) & 0xffffn));
  }
  let bestStart = -1;
  let bestLength = 0;
  for (let index = 0; index < words.length;) {
    if (words[index] !== 0) {
      index += 1;
      continue;
    }
    let end = index;
    while (end < words.length && words[end] === 0) end += 1;
    const length = end - index;
    if (length >= 2 && length > bestLength) {
      bestStart = index;
      bestLength = length;
    }
    index = end;
  }
  if (bestStart < 0) return words.map((word) => word.toString(16)).join(':');
  const left = words.slice(0, bestStart).map((word) => word.toString(16)).join(':');
  const right = words.slice(bestStart + bestLength)
    .map((word) => word.toString(16)).join(':');
  return `${left}::${right}`;
}

function addressValue(address, family) {
  if (family === 4) {
    const octets = address.split('.').map(Number);
    if (
      octets.length !== 4
      || octets.some((octet) => !Number.isInteger(octet) || octet < 0 || octet > 255)
    ) {
      throw new TypeError(`invalid IPv4 address: ${address}`);
    }
    return octets.reduce((value, octet) => (value << 8n) | BigInt(octet), 0n);
  }
  const pieces = address.split('::');
  if (pieces.length > 2) throw new TypeError(`invalid IPv6 address: ${address}`);
  const words = (part) => {
    if (!part) return [];
    return part.split(':').flatMap((word) => {
      if (word.includes('.')) {
        const ipv4 = word.split('.').map(Number);
        if (
          ipv4.length !== 4
          || ipv4.some((octet) => !Number.isInteger(octet) || octet < 0 || octet > 255)
        ) {
          throw new TypeError(`invalid embedded IPv4 address: ${address}`);
        }
        return [(ipv4[0] << 8) | ipv4[1], (ipv4[2] << 8) | ipv4[3]];
      }
      if (!/^[a-f0-9]{1,4}$/i.test(word)) {
        throw new TypeError(`invalid IPv6 word: ${address}`);
      }
      return [Number.parseInt(word, 16)];
    });
  };
  const left = words(pieces[0]);
  const right = words(pieces[1] || '');
  const missing = 8 - left.length - right.length;
  if (missing < 0 || (pieces.length === 1 && missing !== 0)) {
    throw new TypeError(`invalid IPv6 address: ${address}`);
  }
  const all = [...left, ...Array(missing).fill(0), ...right];
  return all.reduce((value, word) => (value << 16n) | BigInt(word), 0n);
}

function normalizeCidr(destination, family) {
  const [address, rawPrefix, ...rest] = destination.split('/');
  if (rest.length) throw new TypeError(`invalid CIDR: ${destination}`);
  const maximum = family === 4 ? 32 : 128;
  const prefix = rawPrefix == null ? maximum : Number(rawPrefix);
  if (
    rawPrefix === ''
    || !Number.isSafeInteger(prefix)
    || prefix < 0
    || prefix > maximum
  ) {
    throw new TypeError(`invalid CIDR prefix: ${destination}`);
  }
  const value = addressValue(address, family);
  const hostBits = BigInt(maximum - prefix);
  if (hostBits > 0n && (value & ((1n << hostBits) - 1n)) !== 0n) {
    throw new TypeError(`CIDR contains non-canonical host bits: ${destination}`);
  }
  return `${family === 4 ? canonicalIpv4(value) : canonicalIpv6(value)}/${prefix}`;
}

export function normalizeEbpfCidr(destination) {
  const address = String(destination || '').split('/', 1)[0];
  const family = net.isIP(address);
  if (!family) throw new TypeError(`invalid CIDR address: ${destination}`);
  return normalizeCidr(String(destination), family);
}

function validDomain(value) {
  const domain = value.startsWith('*.') ? value.slice(2) : value;
  const labels = domain.split('.');
  const maximumLabels = value.startsWith('*.') ? 15 : 16;
  return DOMAIN.test(value)
    // The loader/BPF ABI retains names in NOSH_EGRESS_DOMAIN_LEN=128,
    // including the terminating NUL. Reject longer reviewed names before
    // producing an otherwise valid-looking signed manifest.
    && domain.length < 128
    && domain.includes('.')
    // The v1 DNS decoder retains at most sixteen labels. A wildcard consumes
    // exactly one leading query label, so its reviewed suffix may contain at
    // most fifteen labels.
    && labels.length <= maximumLabels
    && labels.every(
      (label) => label.length >= 1
        && label.length <= 63
        && /^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/.test(label),
    );
}

function sha256(source) {
  return `sha256:${crypto.createHash('sha256').update(source).digest('hex')}`;
}

function requiredString(value, label, pattern = null) {
  if (typeof value !== 'string' || !value || (pattern && !pattern.test(value))) {
    throw new TypeError(`${label} is invalid`);
  }
  return value;
}

function requiredRunId(value) {
  const runId = requiredString(value, 'runId', SAFE_RUN_ID);
  if (runId === '.' || runId === '..') {
    throw new TypeError('runId is not a safe bpffs path segment');
  }
  return runId;
}

export function normalizeEbpfResolvers(values) {
  if (!Array.isArray(values) || !values.length) {
    throw new TypeError('eBPF egress resolvers must be a non-empty array');
  }
  const selected = [...new Set(values.map((entry) => {
    const value = String(entry).trim().toLowerCase();
    const family = net.isIP(value);
    if (!family) {
      throw new TypeError('eBPF egress resolvers must contain only IP addresses');
    }
    return family === 4
      ? canonicalIpv4(addressValue(value, family))
      : canonicalIpv6(addressValue(value, family));
  }))];
  if (selected.length > EBPF_EGRESS_RESOLVER_MAX) {
    throw new TypeError(
      `eBPF egress supports at most ${EBPF_EGRESS_RESOLVER_MAX} resolvers`,
    );
  }
  return selected.sort((left, right) => {
    const family = net.isIP(left) - net.isIP(right);
    return family || left.localeCompare(right);
  });
}

export function normalizePlatformContainmentCidrs(values) {
  if (!Array.isArray(values) || !values.length) {
    throw new TypeError(
      'eBPF egress platform containment must name at least one exact endpoint',
    );
  }
  const selected = [...new Set(values.map((entry) => {
    const value = String(entry || '').trim().toLowerCase();
    const [address, prefixText, ...extra] = value.split('/');
    const family = net.isIP(address);
    const exactPrefix = family === 4 ? 32 : family === 6 ? 128 : null;
    if (
      extra.length
      || exactPrefix == null
      || prefixText !== String(exactPrefix)
    ) {
      throw new TypeError(
        'eBPF egress platform containment accepts only exact /32 or /128 endpoints',
      );
    }
    return normalizeEbpfCidr(value);
  }))];
  if (selected.length > 8) {
    throw new TypeError('eBPF egress supports at most 8 platform endpoints');
  }
  return selected.sort((left, right) => {
    const leftFamily = net.isIP(left.split('/', 1)[0]);
    const rightFamily = net.isIP(right.split('/', 1)[0]);
    return leftFamily - rightFamily || left.localeCompare(right);
  });
}

function platformContainmentIdentity(values) {
  const cidrs = normalizePlatformContainmentCidrs(values);
  const source = cidrs.map((cidr) => {
    const address = cidr.split('/', 1)[0];
    return `platform-endpoint:${address}\t${cidr}\n`;
  }).join('');
  return {
    cidrs,
    digest: sha256(source),
    count: cidrs.length,
  };
}

function normalizeProtocol(value) {
  const protocol = String(value || '').toLowerCase();
  if (!['any', 'tcp', 'udp', 'icmp', 'icmpv6'].includes(protocol)) {
    throw new TypeError(`unsupported eBPF egress protocol: ${value}`);
  }
  return protocol;
}

function normalizedManifestRule(rule, index) {
  const peer = rule?.peer;
  const transport = rule?.transport;
  const reviewed = peer && transport
    ? {
        id: rule.id,
        destination: peer.value,
        protocol: transport.protocol,
        ports: transport.ports,
        icmpType: transport.icmpType,
        icmpCode: transport.icmpCode,
        effect: rule.effect,
        direction: rule.direction,
      }
    : rule;
  if (!reviewed || typeof reviewed !== 'object' || Array.isArray(reviewed)) {
    throw new TypeError('eBPF egress rules must be objects');
  }
  if (reviewed.effect != null && reviewed.effect !== 'allow') {
    throw new TypeError('eBPF egress manifest accepts only allow rules');
  }
  if (reviewed.direction != null && reviewed.direction !== 'egress') {
    throw new TypeError('eBPF egress manifest accepts only egress rules');
  }
  let destination = String(reviewed.destination || '').toLowerCase();
  const address = destination.split('/', 1)[0];
  const family = net.isIP(address);
  const kind = family ? 'cidr' : 'domain';
  if (family) {
    destination = normalizeEbpfCidr(destination);
  } else if (!validDomain(destination)) {
    throw new TypeError(`invalid eBPF egress destination: ${destination}`);
  }
  const protocol = normalizeProtocol(reviewed.protocol);
  if (
    kind === 'cidr'
    && (
      (protocol === 'icmp' && family !== 4)
      || (protocol === 'icmpv6' && family !== 6)
    )
  ) {
    throw new TypeError(
      `${protocol} does not match the address family for ${destination}`,
    );
  }
  if (reviewed.icmpType != null || reviewed.icmpCode != null) {
    throw new TypeError(
      'guard-ebpf v2 cannot enforce ICMP type/code selectors',
    );
  }
  const ports = protocol === 'tcp' || protocol === 'udp'
    ? reviewed.ports
    : [0];
  if (
    !Array.isArray(ports)
    || !ports.length
    || ports.some(
      (port) => !Number.isSafeInteger(port)
        || port < (protocol === 'tcp' || protocol === 'udp' ? 1 : 0)
        || port > (protocol === 'tcp' || protocol === 'udp' ? 65535 : 0),
    )
  ) {
    throw new TypeError(`invalid eBPF egress ports for ${destination}`);
  }
  if (kind === 'domain' && !['any', 'tcp', 'udp'].includes(protocol)) {
    throw new TypeError('domain egress rules support only any, tcp, and udp');
  }
  const identity = typeof reviewed.id === 'string' && reviewed.id
    ? reviewed.id
    : `legacy:${sha256(stableStringify({ destination, protocol, ports }))}`;
  if (identity.length > 256 || /[\0\r\n\t]/.test(identity)) {
    throw new TypeError(`invalid reviewed rule ID at index ${index}`);
  }
  return {
    identity,
    destination,
    kind,
    protocol,
    ports: [...new Set(ports)].sort((left, right) => left - right),
  };
}

function numericRuleId(identity) {
  const digest = crypto.createHash('sha256')
    .update('nosh-egress-rule-id-v1\0')
    .update(identity)
    .digest();
  for (let offset = 0; offset <= digest.length - 4; offset += 4) {
    const selected = digest.readUInt32BE(offset);
    if (selected !== 0) return selected;
  }
  throw new Error(`could not derive a nonzero eBPF rule ID for ${identity}`);
}

export function renderEbpfEgressManifest(
  rules,
  resolvers,
  platformContainmentCidrs,
) {
  if (!Array.isArray(rules)) {
    throw new TypeError('eBPF egress rules must be an array');
  }
  const lines = ['NOSH_EGRESS_POLICY_V2'];
  for (const resolver of normalizeEbpfResolvers(resolvers)) {
    lines.push(`resolver\t${resolver}`);
  }
  for (const endpoint of normalizePlatformContainmentCidrs(
    platformContainmentCidrs,
  )) {
    lines.push(`containment\t${endpoint}`);
  }
  const entries = [];
  const ids = new Map();
  const identities = new Map();
  const signatureOwners = new Map();
  const expandedMatchOwners = new Map();
  const domainSlots = new Map();
  let domainEntryCount = 0;
  let ipv4EntryCount = 0;
  let ipv6EntryCount = 0;
  for (const [index, candidate] of rules.entries()) {
    const rule = normalizedManifestRule(candidate, index);
    const numeric = numericRuleId(rule.identity);
    const collision = ids.get(numeric);
    if (collision && collision !== rule.identity) {
      throw new Error(
        `eBPF rule ID collision between ${collision} and ${rule.identity}`,
      );
    }
    const prior = identities.get(rule.identity);
    const signature = stableStringify({
      destination: rule.destination,
      protocol: rule.protocol,
      ports: rule.ports,
    });
    if (prior && prior !== signature) {
      throw new Error(`reviewed eBPF rule ID is reused: ${rule.identity}`);
    }
    const signatureOwner = signatureOwners.get(signature);
    if (signatureOwner && signatureOwner !== rule.identity) {
      throw new Error(
        `reviewed eBPF rules ${signatureOwner} and ${rule.identity} have the same match`,
      );
    }
    ids.set(numeric, rule.identity);
    identities.set(rule.identity, signature);
    signatureOwners.set(signature, rule.identity);
    if (rule.kind === 'domain') {
      const priorSlots = domainSlots.get(rule.destination) || 0;
      const nextSlots = priorSlots + rule.ports.length;
      if (nextSlots > 8) {
        throw new Error(
          `reviewed eBPF domain ${rule.destination} exceeds the 8-rule slot limit`,
        );
      }
      domainSlots.set(rule.destination, nextSlots);
      domainEntryCount += rule.ports.length;
      if (domainEntryCount > 8192) {
        throw new Error('reviewed eBPF policy exceeds the 8192-domain-entry map limit');
      }
    } else if (net.isIP(rule.destination.split('/', 1)[0]) === 4) {
      ipv4EntryCount += rule.ports.length;
      if (ipv4EntryCount > 16384) {
        throw new Error('reviewed eBPF policy exceeds the 16384-IPv4-entry map limit');
      }
    } else {
      ipv6EntryCount += rule.ports.length;
      if (ipv6EntryCount > 16384) {
        throw new Error('reviewed eBPF policy exceeds the 16384-IPv6-entry map limit');
      }
    }
    for (const port of rule.ports) {
      const expandedMatch = stableStringify({
        kind: rule.kind,
        destination: rule.destination,
        protocol: rule.protocol,
        port,
      });
      const expandedOwner = expandedMatchOwners.get(expandedMatch);
      if (expandedOwner && expandedOwner !== rule.identity) {
        throw new Error(
          `reviewed eBPF rules ${expandedOwner} and ${rule.identity} have the same expanded match`,
        );
      }
      expandedMatchOwners.set(expandedMatch, rule.identity);
      entries.push(
        `${rule.kind}\t${rule.destination}\t${rule.protocol}\t${port}\t${numeric}`,
      );
    }
  }
  for (const [destination, exactSlots] of domainSlots) {
    if (destination.startsWith('*.')) continue;
    const separator = destination.indexOf('.');
    if (separator < 1) continue;
    const wildcard = `*.${destination.slice(separator + 1)}`;
    const combinedSlots = exactSlots + (domainSlots.get(wildcard) || 0);
    if (combinedSlots > 8) {
      throw new Error(
        `reviewed eBPF domain union ${destination} plus ${wildcard} exceeds the 8-rule slot limit`,
      );
    }
  }
  lines.push(...[...new Set(entries)].sort());
  return {
    source: `${lines.join('\n')}\n`,
    ruleIdMap: Object.fromEntries(
      [...ids.entries()]
        .sort(([left], [right]) => left - right)
        .map(([numeric, identity]) => [String(numeric), identity]),
    ),
  };
}

function parseOutputRecords(result, operation) {
  if (result.status !== 0) {
    const error = new Error(
      `nosh-egress-loader ${operation} failed: ${
        result.error?.message || String(result.stderr || '').trim() ||
        `status ${result.status}`
      }`,
    );
    error.code = 'GUARD_EBPF_EGRESS_BACKEND_FAILED';
    throw error;
  }
  const records = String(result.stdout || '')
    .split(/\r?\n/)
    .filter(Boolean)
    .map((line) => JSON.parse(line));
  if (!records.length) {
    throw new Error(`nosh-egress-loader ${operation} returned no status`);
  }
  return records;
}

function parseStatusOutput(result, operation) {
  return parseOutputRecords(result, operation).at(-1);
}

async function pathIsAbsent(filePath) {
  try {
    await fs.lstat(filePath);
    return false;
  } catch (error) {
    if (error.code === 'ENOENT') return true;
    throw error;
  }
}

function validateDetachReceipt(record, run, pinRoot) {
  const fields = [
    'schemaVersion',
    'recordKind',
    'timestampUnixNs',
    'status',
    'cgroupId',
    'policyDigest',
    'containmentDigest',
    'containmentCount',
    'pinRoot',
    'message',
  ];
  if (
    !record
    || typeof record !== 'object'
    || Array.isArray(record)
    || Object.keys(record).sort().join(',') !== fields.sort().join(',')
    || record.schemaVersion !== 2
    || record.recordKind !== 'status'
    || record.status !== 'detached'
    || !/^(0|[1-9][0-9]*)$/.test(String(record.timestampUnixNs || ''))
    || !/^[1-9][0-9]*$/.test(String(record.cgroupId || ''))
    || String(record.cgroupId) !== String(run.cgroup?.id)
    || record.policyDigest !== run.egress?.policyDigest
    || record.containmentDigest !== run.egress?.containmentDigest
    || record.containmentCount !== run.egress?.containmentCount
    || record.pinRoot !== pinRoot
    || record.message !== 'pinned enforcement removed'
  ) {
    const error = new Error(
      'nosh-egress detach receipt does not match the guarded run',
    );
    error.code = 'GUARD_EBPF_EGRESS_DETACH_MISMATCH';
    throw error;
  }
  return structuredClone(record);
}

function validateIdArray(value, label, expectedLength) {
  if (
    !Array.isArray(value)
    || value.length !== expectedLength
    || new Set(value).size !== value.length
    || value.some((entry) => !Number.isSafeInteger(entry) || entry <= 0)
  ) {
    throw new Error(`nosh-egress ${label} attestation is invalid`);
  }
  return value;
}

function backendHealthRecord(record, exitStatus = 0) {
  const fields = [
    'schemaVersion',
    'recordKind',
    'timestampUnixNs',
    'status',
    'cgroupId',
    'attachedPrograms',
    'mapAbi',
    'programAbi',
    'objectDigest',
    'message',
    'checks',
  ];
  const checkFields = [
    'effectiveRoot',
    'kernelIdentity',
    'kernelBtf',
    'cgroupV2',
    'bpffs',
    'targetCgroup',
  ];
  if (
    !record
    || typeof record !== 'object'
    || Array.isArray(record)
    || Object.keys(record).sort().join(',') !== fields.sort().join(',')
    || exitStatus !== 0
    || record.schemaVersion !== 2
    || record?.recordKind !== 'status'
    || record?.status !== 'healthy'
    || !/^(0|[1-9][0-9]*)$/.test(String(record.timestampUnixNs || ''))
    || record.cgroupId !== null
    || record.attachedPrograms !== 0
    || record.mapAbi !== EBPF_EGRESS_MAP_ABI
    || record.programAbi !== EBPF_EGRESS_PROGRAM_ABI
    || !OBJECT_DIGEST.test(record.objectDigest || '')
    || record.message !== 'host prerequisites satisfied'
    || !record.checks
    || typeof record.checks !== 'object'
    || Array.isArray(record.checks)
    || Object.keys(record.checks).sort().join(',')
      !== checkFields.sort().join(',')
    || record.checks?.effectiveRoot !== true
    || record.checks?.kernelIdentity !== true
    || record.checks?.kernelBtf !== true
    || record.checks?.cgroupV2 !== true
    || record.checks?.bpffs !== true
    || record.checks?.targetCgroup !== true
  ) {
    const error = new Error('nosh-egress loader health attestation is incomplete');
    error.code = 'GUARD_EBPF_EGRESS_BACKEND_UNHEALTHY';
    error.health = record;
    throw error;
  }
  return structuredClone(record);
}

export function validateEbpfTargetContextDocument(document) {
  const expectedKeys = [
    'apiVersion',
    'backendAbi',
    'capabilities',
    'contentHash',
    'createdAt',
    'kind',
    'objectDigest',
    'platformContainment',
    'resolvers',
    'schemaVersion',
    'subject',
  ];
  if (
    !document
    || typeof document !== 'object'
    || Array.isArray(document)
    || Object.keys(document).sort().join(',') !== expectedKeys.sort().join(',')
  ) {
    throw new TypeError('guard-ebpf target context has an invalid field inventory');
  }
  const { contentHash, ...unsigned } = document;
  if (
    document.apiVersion !== 'notty.dev/v1alpha1'
    || document.kind !== 'NoshGuardEbpfTargetContext'
    || document.schemaVersion !== 2
    || !Number.isFinite(Date.parse(document.createdAt))
    || document.backendAbi !== EBPF_EGRESS_BACKEND_ABI
    || !OBJECT_DIGEST.test(document.objectDigest || '')
    || contentHash !== sha256(stableStringify(unsigned))
  ) {
    throw new TypeError('guard-ebpf target context header or digest is invalid');
  }
  const subject = document.subject;
  if (
    !subject
    || typeof subject !== 'object'
    || Array.isArray(subject)
    || Object.keys(subject).sort().join(',')
      !== 'imageDigest,workspaceIdentity,workspaceKey'
    || !EXACT_DIGEST.test(subject.imageDigest || '')
    || !WORKSPACE_KEY.test(subject.workspaceKey || '')
    || !subject.workspaceIdentity
    || Object.keys(subject.workspaceIdentity).sort().join(',') !== 'dev,ino'
    || !/^\d+$/.test(String(subject.workspaceIdentity.dev || ''))
    || !/^\d+$/.test(String(subject.workspaceIdentity.ino || ''))
  ) {
    throw new TypeError('guard-ebpf target context subject is invalid');
  }
  const capabilityKeys = Object.keys(EBPF_EGRESS_CAPABILITIES).sort();
  if (
    !document.capabilities
    || typeof document.capabilities !== 'object'
    || Array.isArray(document.capabilities)
    || Object.keys(document.capabilities).sort().join(',')
      !== capabilityKeys.join(',')
    || capabilityKeys.some((name) => (
      document.capabilities[name] !== EBPF_EGRESS_CAPABILITIES[name]
    ))
  ) {
    throw new TypeError('guard-ebpf target context capabilities are invalid');
  }
  const resolvers = normalizeEbpfResolvers(document.resolvers);
  if (stableStringify(resolvers) !== stableStringify(document.resolvers)) {
    throw new TypeError('guard-ebpf target context resolvers are not canonical');
  }
  if (
    stableStringify(document.platformContainment)
    !== stableStringify(EBPF_PLATFORM_CONTAINMENT)
  ) {
    throw new TypeError(
      'guard-ebpf target context platform containment changed',
    );
  }
  return {
    document: structuredClone(document),
    expected: {
      imageDigest: subject.imageDigest,
      workspaceKey: subject.workspaceKey,
      workspaceIdentity: {
        dev: String(subject.workspaceIdentity.dev),
        ino: String(subject.workspaceIdentity.ino),
      },
      backendAbi: document.backendAbi,
      objectDigest: document.objectDigest,
      capabilities: structuredClone(document.capabilities),
      resolvers: [...document.resolvers],
      platformContainment: { ...EBPF_PLATFORM_CONTAINMENT },
    },
  };
}

export function readInstalledEbpfBackendHealth(options = {}) {
  const loaderPath = options.loaderPath || configuredInstalledLoaderPath();
  const spawn = options.spawnSyncImpl || spawnSync;
  const result = spawn(loaderPath, ['health'], {
    encoding: 'utf8',
    timeout: 5_000,
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  let record = null;
  try {
    const records = String(result.stdout || '')
      .split(/\r?\n/)
      .filter(Boolean)
      .map((line) => JSON.parse(line));
    record = records.at(-1) || null;
  } catch {
    // The common parser below retains the executable/status diagnostics.
  }
  if (!record) {
    return backendHealthRecord(parseStatusOutput(result, 'health'), result.status);
  }
  return backendHealthRecord(record, result.status);
}

function targetContextDocument(input) {
  const unsigned = {
    apiVersion: 'notty.dev/v1alpha1',
    kind: 'NoshGuardEbpfTargetContext',
    schemaVersion: 2,
    createdAt: new Date().toISOString(),
    backendAbi: EBPF_EGRESS_BACKEND_ABI,
    objectDigest: input.objectDigest,
    subject: {
      workspaceKey: input.workspaceKey,
      workspaceIdentity: {
        dev: String(input.workspaceIdentity.dev),
        ino: String(input.workspaceIdentity.ino),
      },
      imageDigest: input.imageDigest,
    },
    capabilities: { ...EBPF_EGRESS_CAPABILITIES },
    resolvers: [...input.resolvers],
    platformContainment: { ...EBPF_PLATFORM_CONTAINMENT },
  };
  return validateEbpfTargetContextDocument({
    ...unsigned,
    contentHash: sha256(stableStringify(unsigned)),
  }).document;
}

export function validateEbpfEgressAttestation(attestation, expected) {
  if (!attestation || typeof attestation !== 'object') {
    throw new Error('nosh-egress readiness attestation is missing');
  }
  const expectedKeys = [
    'targetCgroupId',
    'policyDigest',
    'containmentDigest',
    'containmentCount',
    'mode',
    'objectDigest',
    'mapAbi',
    'programAbi',
    'policyGeneration',
    'runId',
    'imageDigest',
    'workspaceKey',
    'linkIds',
    'programIds',
    'mapIds',
  ];
  if (
    Array.isArray(attestation)
    || Object.keys(attestation).sort().join(',')
      !== expectedKeys.sort().join(',')
  ) {
    throw new Error('nosh-egress readiness attestation has an invalid field inventory');
  }
  const fields = {
    targetCgroupId: String(expected.cgroupId),
    policyDigest: expected.policyDigest,
    containmentDigest: expected.containmentDigest,
    containmentCount: expected.containmentCount,
    mode: expected.mode,
    runId: expected.runId,
    imageDigest: expected.imageDigest,
    workspaceKey: expected.workspaceKey,
    objectDigest: expected.objectDigest,
    mapAbi: EBPF_EGRESS_MAP_ABI,
    programAbi: EBPF_EGRESS_PROGRAM_ABI,
  };
  const mismatches = Object.entries(fields)
    .filter(([name, value]) => String(attestation[name]) !== String(value))
    .map(([name]) => name);
  if (mismatches.length) {
    const error = new Error(
      `nosh-egress attestation does not match the guarded run: ${mismatches.join(', ')}`,
    );
    error.code = 'GUARD_EBPF_EGRESS_ATTESTATION_MISMATCH';
    error.mismatches = mismatches;
    throw error;
  }
  if (!/^[1-9][0-9]*$/.test(String(attestation.policyGeneration || ''))) {
    throw new Error('nosh-egress policy generation attestation is invalid');
  }
  validateIdArray(attestation.programIds, 'program IDs', 6);
  validateIdArray(attestation.linkIds, 'link IDs', 6);
  validateIdArray(attestation.mapIds, 'map IDs', 12);
  return structuredClone(attestation);
}

function validateEbpfReadyStatus(status, expected) {
  const expectedKeys = [
    'schemaVersion',
    'recordKind',
    'timestampUnixNs',
    'status',
    'cgroupId',
    'attachedPrograms',
    'mode',
    'policyDigest',
    'containmentDigest',
    'containmentCount',
    'objectDigest',
    'mapAbi',
    'programAbi',
    'pinRoot',
    'message',
    'attestation',
  ];
  if (
    !status
    || typeof status !== 'object'
    || Array.isArray(status)
    || Object.keys(status).sort().join(',')
      !== expectedKeys.sort().join(',')
    || status.schemaVersion !== 2
    || status.recordKind !== 'status'
    || status.status !== 'ready'
    || !/^(0|[1-9][0-9]*)$/.test(String(status.timestampUnixNs || ''))
    || String(status.cgroupId) !== String(expected.cgroupId)
    || status.attachedPrograms !== 6
    || status.mode !== expected.mode
    || status.policyDigest !== expected.policyDigest
    || status.containmentDigest !== expected.containmentDigest
    || status.containmentCount !== expected.containmentCount
    || status.objectDigest !== expected.objectDigest
    || status.mapAbi !== EBPF_EGRESS_MAP_ABI
    || status.programAbi !== EBPF_EGRESS_PROGRAM_ABI
    || status.pinRoot !== expected.pinRoot
    || typeof status.message !== 'string'
    || !status.message
  ) {
    const error = new Error(
      'nosh-egress ready status does not match the exact pinned runtime',
    );
    error.code = 'GUARD_EBPF_EGRESS_ATTESTATION_MISMATCH';
    throw error;
  }
  return validateEbpfEgressAttestation(status.attestation, expected);
}

export class EbpfEgressBackend {
  constructor(options = {}) {
    if (!options.networkManager) {
      throw new TypeError('EbpfEgressBackend requires a network manager');
    }
    this.networkManager = options.networkManager;
    this.stateDir = path.resolve(options.stateDir || DEFAULT_GUARD_STATE_DIR);
    this.loaderPath = options.loaderPath || DEFAULT_EBPF_EGRESS_LOADER;
    this.pinRoot = path.resolve(options.pinRoot || '/sys/fs/bpf/nosh-guard');
    this.resolvers = normalizeEbpfResolvers(
      options.resolvers || DEFAULT_EBPF_EGRESS_RESOLVERS,
    );
    this.spawnSyncImpl = options.spawnSyncImpl || spawnSync;
    this.runsDir = path.join(this.stateDir, 'egress', 'ebpf', 'runs');
  }

  async initialize() {
    await fs.mkdir(this.runsDir, { recursive: true, mode: 0o700 });
    await fs.chmod(this.runsDir, 0o700);
  }

  configureLoaderPath(loaderPath) {
    if (
      typeof loaderPath !== 'string'
      || !path.isAbsolute(loaderPath)
      || loaderPath.includes('\0')
    ) {
      throw new TypeError('nosh-egress loader path must be absolute');
    }
    this.loaderPath = path.resolve(loaderPath);
  }

  preflight() {
    return readInstalledEbpfBackendHealth({
      loaderPath: this.loaderPath,
      spawnSyncImpl: this.spawnSyncImpl,
    });
  }

  async prepareNetwork(runId) {
    return this.networkManager.prepareDirectNetwork(runId);
  }

  resolversFor(values) {
    return normalizeEbpfResolvers(values || this.resolvers);
  }

  async prepareRun(input) {
    await this.initialize();
    const runId = requiredRunId(input.runId);
    const imageDigest = requiredString(
      input.imageDigest,
      'imageDigest',
      EXACT_DIGEST,
    );
    const workspaceKey = requiredString(
      input.workspaceKey,
      'workspaceKey',
      WORKSPACE_KEY,
    );
    const mode = MODES.get(input.mode);
    if (!mode) {
      throw new TypeError(`unsupported scoped egress mode: ${input.mode}`);
    }
    const runRoot = path.join(this.runsDir, runId);
    await fs.mkdir(runRoot, { mode: 0o700 });
    await fs.chmod(runRoot, 0o700);
    const objectDigest = requiredString(
      input.objectDigest,
      'objectDigest',
      OBJECT_DIGEST,
    );
    const workspaceIdentity = input.workspaceIdentity;
    if (
      !workspaceIdentity
      || !/^\d+$/.test(String(workspaceIdentity.dev || ''))
      || !/^\d+$/.test(String(workspaceIdentity.ino || ''))
    ) {
      throw new TypeError('workspaceIdentity is invalid');
    }
    const resolvers = this.resolversFor(input.resolvers);
    const platformContainmentCidrs = normalizePlatformContainmentCidrs(
      input.platformContainmentCidrs,
    );
    const platformContainment = platformContainmentIdentity(
      platformContainmentCidrs,
    );
    const rendered = renderEbpfEgressManifest(
      input.rules || [],
      resolvers,
      platformContainmentCidrs,
    );
    const policySource = rendered.source;
    const policyPath = path.join(runRoot, 'policy.manifest');
    const resolverConfigPath = path.join(runRoot, 'resolv.conf');
    const ruleIdMapPath = path.join(runRoot, 'rule-id-map.json');
    const targetContextPath = path.join(input.evidenceDir, 'guard-ebpf-target-context.json');
    const targetContext = targetContextDocument({
      objectDigest,
      workspaceKey,
      workspaceIdentity,
      imageDigest,
      resolvers,
    });
    await Promise.all([
      fs.writeFile(policyPath, policySource, { flag: 'wx', mode: 0o600 }),
      fs.writeFile(
        resolverConfigPath,
        `${resolvers.map((resolver) => `nameserver ${resolver}`).join('\n')}\noptions timeout:2 attempts:2 rotate\n`,
        { flag: 'wx', mode: 0o644 },
      ),
      fs.writeFile(
        ruleIdMapPath,
        `${stableStringify(rendered.ruleIdMap, 2)}\n`,
        { flag: 'wx', mode: 0o600 },
      ),
      fs.writeFile(
        targetContextPath,
        `${stableStringify(targetContext, 2)}\n`,
        { flag: 'wx', mode: 0o600 },
      ),
    ]);
    // writeFile's creation mode is filtered by the daemon umask. The runner
    // executes as an unprivileged UID, so make the read-only resolver bind
    // explicitly world-readable while retaining root ownership and no write
    // permission outside the owner.
    await fs.chmod(resolverConfigPath, 0o644);
    return {
      backend: EBPF_EGRESS_BACKEND,
      backendAbi: EBPF_EGRESS_BACKEND_ABI,
      backendMode: mode,
      policyPath,
      policyDigest: sha256(policySource),
      ruleIdMap: rendered.ruleIdMap,
      ruleIdMapPath,
      pinRoot: path.join(this.pinRoot, runId),
      resolverConfigPath,
      resolvers: [...resolvers],
      capabilities: { ...EBPF_EGRESS_CAPABILITIES },
      platformContainment: { ...EBPF_PLATFORM_CONTAINMENT },
      platformContainmentCidrs: [...platformContainmentCidrs],
      containmentDigest: platformContainment.digest,
      containmentCount: platformContainment.count,
      targetContext,
      targetContextPath,
      targetContextHash: targetContext.contentHash,
      imageDigest,
      workspaceKey,
      workspaceIdentity: {
        dev: String(workspaceIdentity.dev),
        ino: String(workspaceIdentity.ino),
      },
      objectDigest,
      mapAbi: EBPF_EGRESS_MAP_ABI,
      programAbi: EBPF_EGRESS_PROGRAM_ABI,
    };
  }

  async bindRun(run, inspected, allocation, preparation) {
    const endpoint = inspected?.NetworkSettings?.Networks
      ?.[allocation.networkName];
    const runnerAddress = endpoint?.IPAddress;
    const runnerIpv6 = endpoint?.GlobalIPv6Address;
    if (
      runnerAddress !== allocation.runnerIp
      || runnerIpv6 !== allocation.runnerIpv6
    ) {
      throw new Error(
        `runner address mismatch: expected ${allocation.runnerIp} and `
          + `${allocation.runnerIpv6}, got ${runnerAddress || 'none'} and `
          + `${runnerIpv6 || 'none'}`,
      );
    }
    return {
      ...preparation,
      networkName: allocation.networkName,
      sourceIpv4: allocation.runnerIp,
      sourceIpv6: allocation.runnerIpv6,
      gatewayIpv4: allocation.dockerGateway,
      gatewayContainerId: null,
      routeInstalled: false,
      dnsAuthority: EBPF_EGRESS_BACKEND,
    };
  }

  attestRun(run, adapters) {
    const adapter = (adapters || []).find((entry) => entry.name === EBPF_EGRESS_BACKEND);
    const readiness = adapter?.readiness;
    if (readiness?.status !== 'ready') {
      throw new Error('nosh-egress adapter did not retain a ready status');
    }
    const attestation = validateEbpfReadyStatus(readiness, {
      cgroupId: run.cgroup?.id,
      policyDigest: run.egress?.policyDigest,
      containmentDigest: run.egress?.containmentDigest,
      containmentCount: run.egress?.containmentCount,
      mode: run.egress?.backendMode,
      runId: run.runId,
      imageDigest: run.imageDigest,
      workspaceKey: run.workspaceKey,
      pinRoot: run.egress?.pinRoot,
      objectDigest: run.egress?.objectDigest,
    });
    return {
      apiVersion: 'notty.dev/v1alpha1',
      kind: 'NoshEbpfEgressRuntimeAttestation',
      generatedAt: new Date().toISOString(),
      runId: run.runId,
      containerId: run.containerId,
      imageDigest: run.imageDigest,
      workspaceKey: run.workspaceKey,
      policyDigest: run.egress.policyDigest,
      backend: EBPF_EGRESS_BACKEND,
      ...attestation,
      pinRoot: readiness.pinRoot,
    };
  }

  runtimeHealth(run) {
    try {
      const result = this.spawnSyncImpl(
        this.loaderPath,
        ['status', '--pin-root', run.egress?.pinRoot || ''],
        {
          encoding: 'utf8',
          timeout: 5_000,
          stdio: ['ignore', 'pipe', 'pipe'],
        },
      );
      const status = parseStatusOutput(result, 'status');
      const attestation = validateEbpfReadyStatus(
        status,
        {
          cgroupId: run.cgroup?.id,
          policyDigest: run.egress?.policyDigest,
          containmentDigest: run.egress?.containmentDigest,
          containmentCount: run.egress?.containmentCount,
          mode: run.egress?.backendMode,
          runId: run.runId,
          imageDigest: run.imageDigest,
          workspaceKey: run.workspaceKey,
          pinRoot: run.egress?.pinRoot,
          objectDigest: run.egress?.objectDigest,
        },
      );
      return {
        ok: status.status === 'ready',
        backend: EBPF_EGRESS_BACKEND,
        policyDigest: run.egress.policyDigest,
        policyGeneration: attestation.policyGeneration,
        pinRoot: status.pinRoot,
        attestation,
        error: status.status === 'ready' ? null : status.message || 'backend is not ready',
      };
    } catch (error) {
      return { ok: false, backend: EBPF_EGRESS_BACKEND, error: error.message };
    }
  }

  snapshotRun(run) {
    const result = this.spawnSyncImpl(
      this.loaderPath,
      ['snapshot', '--pin-root', run.egress?.pinRoot || ''],
      {
        encoding: 'utf8',
        timeout: 10_000,
        stdio: ['ignore', 'pipe', 'pipe'],
      },
    );
    const records = parseOutputRecords(result, 'snapshot');
    const header = records.find(
      (record) => record?.recordKind === 'snapshot-header',
    );
    const stats = records.findLast(
      (record) => record?.recordKind === 'stats' && record.final === true,
    );
    const headerFields = [
      'schemaVersion',
      'recordKind',
      'policyDigest',
      'objectDigest',
      'containmentDigest',
      'containmentCount',
      'pinRoot',
    ];
    if (
      !header
      || typeof header !== 'object'
      || Array.isArray(header)
      || Object.keys(header).sort().join(',')
        !== headerFields.sort().join(',')
      || header.schemaVersion !== 2
      || !stats
      || header.policyDigest !== run.egress?.policyDigest
      || header.objectDigest !== run.egress?.objectDigest
      || header.containmentDigest !== run.egress?.containmentDigest
      || header.containmentCount !== run.egress?.containmentCount
      || header.pinRoot !== run.egress?.pinRoot
      || String(stats.cgroupId) !== String(run.cgroup?.id)
      || String(stats.policyGeneration)
        !== String(run.egress?.attestation?.policyGeneration)
    ) {
      const error = new Error(
        'nosh-egress final snapshot does not match the guarded run',
      );
      error.code = 'GUARD_EBPF_EGRESS_SNAPSHOT_MISMATCH';
      throw error;
    }
    return { ...header, stats };
  }

  async detachRun(run) {
    const pinRoot = run.egress?.pinRoot;
    let detachment = null;
    if (pinRoot) {
      const result = this.spawnSyncImpl(
        this.loaderPath,
        ['detach', '--pin-root', pinRoot],
        {
          encoding: 'utf8',
          timeout: 10_000,
          stdio: ['ignore', 'pipe', 'pipe'],
        },
      );
      if (result.status === 0) {
        detachment = validateDetachReceipt(
          parseStatusOutput(result, 'detach'),
          run,
          pinRoot,
        );
      } else if (!(await pathIsAbsent(pinRoot))) {
        parseStatusOutput(result, 'detach');
      }
      if (!(await pathIsAbsent(pinRoot))) {
        const error = new Error(
          `nosh-egress pinned state remains after detach: ${pinRoot}`,
        );
        error.code = 'GUARD_EBPF_EGRESS_DETACH_INCOMPLETE';
        throw error;
      }
    }
    const network = await this.networkManager.detachDirectRun(run);
    const runRoot = path.join(this.runsDir, requiredRunId(run.runId));
    await fs.rm(runRoot, { recursive: true, force: true });
    return {
      ok: true,
      backend: EBPF_EGRESS_BACKEND,
      networkName: network.networkName,
      detachment,
    };
  }
}
