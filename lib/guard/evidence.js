import { API_VERSION, EVIDENCE_KIND, SCHEMA_VERSION } from './constants.js';
import {
  canonicalize,
  compareCanonical,
  isPlainObject,
  sanitizeDnsLabel,
  sha256,
  sortedUniqueStrings,
  stableStringify,
} from './stable.js';

const FILE_OPERATIONS = new Set([
  'create',
  'delete',
  'execute',
  'read',
  'rename',
  'write',
]);
const NETWORK_DIRECTIONS = new Set(['egress', 'ingress']);
const NETWORK_PROTOCOLS = new Set(['any', 'icmp', 'icmpv6', 'tcp', 'udp']);
const NETWORK_JOIN_MAX_CLOCK_SKEW_MS = 1000;
const RFC3339_TIMESTAMP =
  /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?(?:Z|[+-]\d{2}:\d{2})$/;

export function parseEvidenceInput(input) {
  if (typeof input !== 'string') {
    return input;
  }
  const source = input.trim();
  if (!source) {
    return [];
  }
  try {
    return JSON.parse(source);
  } catch {
    const advice = parseIgSeccompAdvice(source);
    if (advice.length) {
      return advice;
    }
    return source
      .split(/\r?\n/)
      .map((line) => line.trim())
      .filter(Boolean)
      .map((line, index) => {
        try {
          return JSON.parse(line);
        } catch (error) {
          throw new Error(`invalid evidence JSON on line ${index + 1}: ${error.message}`);
        }
      });
  }
}

function balancedJsonObjects(source) {
  const objects = [];
  let start = -1;
  let depth = 0;
  let inString = false;
  let escaped = false;
  for (let index = 0; index < source.length; index += 1) {
    const character = source[index];
    if (inString) {
      if (escaped) {
        escaped = false;
      } else if (character === '\\') {
        escaped = true;
      } else if (character === '"') {
        inString = false;
      }
      continue;
    }
    if (character === '"') {
      inString = true;
      continue;
    }
    if (character === '{') {
      if (depth === 0) {
        start = index;
      }
      depth += 1;
      continue;
    }
    if (character === '}' && depth > 0) {
      depth -= 1;
      if (depth === 0 && start >= 0) {
        objects.push(source.slice(start, index + 1));
        start = -1;
      }
    }
  }
  return objects;
}

function parseIgSeccompAdvice(source) {
  const documents = [];
  for (const candidate of balancedJsonObjects(source)) {
    let value;
    try {
      value = JSON.parse(candidate);
    } catch {
      continue;
    }
    if (
      !isPlainObject(value)
      || typeof value.defaultAction !== 'string'
      || !Array.isArray(value.syscalls)
    ) {
      continue;
    }
    documents.push({
      schemaVersion: 1,
      source: {
        kind: 'ig',
        name: 'advise_seccomp',
      },
      event: {
        type: 'recommendation',
        domain: 'seccomp',
        action: 'propose',
        generator: 'inspektor-gadget/advise_seccomp',
        value,
      },
    });
  }
  return documents;
}

function flattenRecords(input) {
  const parsed = parseEvidenceInput(input);
  if (Array.isArray(parsed)) {
    return parsed;
  }
  if (!isPlainObject(parsed)) {
    throw new TypeError('evidence must be an object, array, JSON document, or JSONL string');
  }
  if (parsed.kind === EVIDENCE_KIND && isPlainObject(parsed.observations)) {
    return recordsFromNormalizedEvidence(parsed);
  }
  const nested = Array.isArray(parsed.events)
    ? parsed.events
    : Array.isArray(parsed.records)
      ? parsed.records
      : null;
  if (!nested) {
    return [parsed];
  }
  return nested.map((record) => {
    if (!isPlainObject(record)) {
      return record;
    }
    return {
      ...record,
      source: record.source ?? parsed.source,
      runId: record.runId ?? parsed.runId,
      observedAt: record.observedAt ?? parsed.observedAt,
      container: record.container ?? parsed.container,
    };
  });
}

function recordsFromNormalizedEvidence(evidence) {
  const source = { kind: 'canonical', name: 'normalized-evidence' };
  const container = evidence.subject || {};
  const records = [];
  for (const executable of evidence.observations.executables || []) {
    const count = positiveInteger(executable.count, 1);
    for (let index = 0; index < count; index += 1) {
      records.push({
        source,
        container,
        event: {
          type: 'process.exec',
          executable: executable.path,
          parentExecutable: executable.parentPaths?.[0],
        },
      });
    }
  }
  for (const syscall of evidence.observations.syscalls || []) {
    const count = positiveInteger(syscall.count, 1);
    for (let index = 0; index < count; index += 1) {
      records.push({
        source,
        container,
        event: {
          type: 'syscall',
          name: syscall.name,
          architecture: syscall.architectures?.[0],
        },
      });
    }
  }
  for (const file of evidence.observations.files || []) {
    for (const operation of file.operations || []) {
      records.push({
        source,
        container,
        event: { type: 'file', path: file.path, operation },
      });
    }
  }
  for (const network of evidence.observations.network || []) {
    records.push({
      source,
      container,
      event: { type: 'network', ...network, count: undefined },
    });
  }
  for (const capability of evidence.observations.capabilities || []) {
    records.push({
      source,
      container,
      event: {
        type: 'capability',
        name: typeof capability === 'string' ? capability : capability.name,
      },
    });
  }
  for (const mount of evidence.observations.mounts || []) {
    records.push({
      source,
      container,
      event: { type: 'mount', ...mount, count: undefined },
    });
  }
  for (const advisory of evidence.advisoryEvidence || []) {
    records.push({
      source: advisory.source || { kind: 'advisory' },
      runId: advisory.runId,
      container,
      event: {
        type: 'recommendation',
        domain: advisory.domain,
        action: advisory.action,
        value: advisory.value,
        generator: advisory.generator,
      },
    });
  }
  return records;
}

function positiveInteger(value, fallback = 0) {
  return Number.isInteger(value) && value > 0 ? value : fallback;
}

function scalar(value) {
  if (typeof value === 'string' || typeof value === 'number' || typeof value === 'boolean') {
    return String(value).trim();
  }
  return '';
}

function normalizeSource(source, record) {
  const raw = isPlainObject(source)
    ? source
    : typeof source === 'string'
      ? { kind: source }
      : {};
  const tetragonEnvelope = Boolean(
    record.process_exec
    || record.process_exit
    || record.process_kprobe
    || record.process_lsm
    || record.process_tracepoint,
  );
  const kind = scalar(raw.kind || raw.type || (tetragonEnvelope ? 'tetragon' : 'unknown'))
    .toLowerCase();
  return canonicalize({
    kind: kind || 'unknown',
    ...(scalar(raw.name) ? { name: scalar(raw.name) } : {}),
    ...(scalar(raw.version) ? { version: scalar(raw.version) } : {}),
  });
}

function normalizeContainer(container) {
  if (!isPlainObject(container)) {
    return {};
  }
  const normalized = {
    ...(scalar(container.id || container.containerId)
      ? { id: scalar(container.id || container.containerId) }
      : {}),
    ...(scalar(container.name || container.containerName)
      ? { name: scalar(container.name || container.containerName) }
      : {}),
    ...(scalar(container.image) ? { image: scalar(container.image) } : {}),
    ...(scalar(container.imageDigest || container.digest)
      ? { imageDigest: scalar(container.imageDigest || container.digest) }
      : {}),
  };
  return canonicalize(normalized);
}

function containerIdentityKey(container) {
  if (container.id) {
    return `id:${container.id}`;
  }
  if (container.imageDigest && container.name) {
    return `digest-name:${container.imageDigest}:${container.name}`;
  }
  if (container.name) {
    return `name:${container.name}`;
  }
  return stableStringify(container);
}

function addContainer(map, container) {
  if (!Object.keys(container).length) {
    return;
  }
  const key = containerIdentityKey(container);
  const existing = map.get(key) || {};
  const merged = {};
  for (const field of ['id', 'name', 'image', 'imageDigest']) {
    const values = sortedUniqueStrings([existing[field], container[field]]);
    if (values.length) {
      merged[field] = values[0];
    }
  }
  map.set(key, canonicalize(merged));
}

function containerFromTetragon(payload) {
  const process = payload?.process || payload?.current || {};
  const docker = process.docker || payload?.docker || '';
  const pod = process.pod || payload?.pod || {};
  const container = pod.container || process.container || {};
  return normalizeContainer({
    id: docker || container.id,
    name: container.name,
    image: container.image?.name || container.image,
    imageDigest: container.image?.id || container.imageDigest,
  });
}

function normalizeSyscallName(value) {
  const name = scalar(value)
    .replace(/^__x64_sys_/, '')
    .replace(/^__ia32_sys_/, '')
    .replace(/^__arm64_sys_/, '')
    .replace(/^compat_sys_/, '')
    .replace(/^sys_/, '');
  return /^[a-zA-Z0-9_]+$/.test(name) ? name.toLowerCase() : '';
}

function inferArchitecture(value) {
  const name = scalar(value);
  if (name.startsWith('__x64_sys_')) {
    return 'SCMP_ARCH_X86_64';
  }
  if (name.startsWith('__ia32_sys_')) {
    return 'SCMP_ARCH_X86';
  }
  if (name.startsWith('__arm64_sys_')) {
    return 'SCMP_ARCH_AARCH64';
  }
  return '';
}

function argumentCount(value) {
  if (Array.isArray(value)) {
    return value.length;
  }
  if (typeof value === 'string' && value.trim()) {
    return value.trim().split(/\s+/).length;
  }
  return 0;
}

function nestedValues(value, key, results = []) {
  if (Array.isArray(value)) {
    for (const entry of value) {
      nestedValues(entry, key, results);
    }
    return results;
  }
  if (!isPlainObject(value)) {
    return results;
  }
  for (const [entryKey, entryValue] of Object.entries(value)) {
    if (entryKey === key) {
      results.push(entryValue);
    }
    nestedValues(entryValue, key, results);
  }
  return results;
}

function firstPathFromArguments(args) {
  const candidates = [
    ...nestedValues(args, 'path'),
    ...nestedValues(args, 'string_arg'),
  ];
  return candidates
    .map((candidate) => scalar(candidate))
    .find((candidate) => candidate.startsWith('/')) || '';
}

function firstSocketFromArguments(args) {
  const sockets = [
    ...nestedValues(args, 'sock_arg'),
    ...nestedValues(args, 'socket'),
  ].filter(isPlainObject);
  const socket = sockets[0];
  if (!socket) {
    return null;
  }
  const protocolValue = scalar(socket.protocol || socket.type).toLowerCase();
  const protocol = protocolValue.includes('udp') || protocolValue.includes('dgram')
    ? 'udp'
    : protocolValue.includes('icmp')
      ? 'icmp'
      : 'tcp';
  const port = Number(socket.port || socket.dport || socket.destination_port);
  return {
    protocol,
    ...(scalar(socket.address || socket.addr || socket.destination)
      ? { address: scalar(socket.address || socket.addr || socket.destination) }
      : {}),
    ...(Number.isInteger(port) && port >= 1 && port <= 65535 ? { port } : {}),
  };
}

function integerField(value, minimum, maximum) {
  const selected = Number(value);
  return Number.isSafeInteger(selected)
    && selected >= minimum
    && selected <= maximum
    ? selected
    : null;
}

function decimalField(value) {
  const selected = scalar(value);
  return /^(0|[1-9][0-9]*)$/.test(selected) ? selected : '';
}

function normalizeNetworkDecision(value) {
  if (!isPlainObject(value)) return null;
  const schemaVersion = integerField(value.schemaVersion, 1, 255);
  const verdict = scalar(value.verdict).toLowerCase();
  const reasonCode = integerField(value.reasonCode, 1, 255);
  const hook = integerField(value.hook, 1, 255);
  const ruleId = integerField(value.ruleId, 0, 0xffffffff);
  const family = integerField(value.family, 0, 255);
  const protocol = integerField(value.protocol, 0, 255);
  const sourcePort = integerField(value.sourcePort, 0, 65535);
  const destinationPort = integerField(value.destinationPort, 0, 65535);
  const packetBytes = integerField(value.packetBytes, 0, 0xffffffff);
  const transactionId = integerField(value.transactionId, 0, 0xffffffff);
  if (
    schemaVersion == null
    || scalar(value.recordKind) !== 'decision'
    || !['allow', 'would-deny', 'deny'].includes(verdict)
    || [reasonCode, hook, ruleId, family, sourcePort, destinationPort,
      protocol, packetBytes, transactionId].includes(null)
  ) {
    return null;
  }
  return canonicalize({
    schemaVersion,
    recordKind: 'decision',
    verdict,
    decisionClass: scalar(value.decisionClass).toLowerCase(),
    reason: scalar(value.reason).toLowerCase(),
    reasonCode,
    hook,
    ruleId,
    family,
    protocol,
    sourceAddress: scalar(value.sourceAddress),
    destinationAddress: scalar(value.destinationAddress),
    sourcePort,
    destinationPort,
    packetBytes,
    transactionId,
    domain: scalar(value.domain).toLowerCase().replace(/\.$/, ''),
    enforcementApplied: value.enforcementApplied === true,
    containmentId: scalar(value.containmentId),
    timestampMonotonicNs: decimalField(value.timestampMonotonicNs),
    cgroupId: decimalField(value.cgroupId),
    policyGeneration: decimalField(value.policyGeneration),
    expiresMonotonicNs: decimalField(value.expiresMonotonicNs),
  });
}

function normalizeDnsChain(value) {
  if (!Array.isArray(value)) return [];
  const unique = new Map();
  for (const entry of value) {
    if (!isPlainObject(entry)) continue;
    const dnsName = scalar(entry.dnsName).toLowerCase().replace(/\.$/, '');
    const address = scalar(entry.address);
    const protocol = scalar(entry.protocol).toLowerCase();
    const port = integerField(entry.port, 0, 65535);
    const transactionId = integerField(entry.transactionId, 0, 0xffffffff);
    const observedMonotonicNs = decimalField(entry.observedMonotonicNs);
    const expiresMonotonicNs = decimalField(entry.expiresMonotonicNs);
    const dnsRecordType = scalar(entry.dnsRecordType).toUpperCase();
    const schemaVersion = entry.schemaVersion == null
      ? null
      : integerField(entry.schemaVersion, 1, 255);
    const hook = entry.hook == null ? null : integerField(entry.hook, 1, 255);
    const transportFamily = entry.transportFamily == null
      ? null
      : integerField(entry.transportFamily, 0, 255);
    const timestampMonotonicNs = entry.timestampMonotonicNs == null
      ? ''
      : decimalField(entry.timestampMonotonicNs);
    const cgroupId = entry.cgroupId == null ? '' : decimalField(entry.cgroupId);
    const policyGeneration = entry.policyGeneration == null
      ? ''
      : decimalField(entry.policyGeneration);
    const transportProtocol = scalar(entry.transportProtocol).toLowerCase();
    const resolverPort = entry.resolverPort == null
      ? null
      : integerField(entry.resolverPort, 0, 65535);
    const clientPort = entry.clientPort == null
      ? null
      : integerField(entry.clientPort, 0, 65535);
    if (
      !dnsName
      || !address
      || !['any', 'tcp', 'udp'].includes(protocol)
      || port == null
      || transactionId == null
      || !observedMonotonicNs
      || !expiresMonotonicNs
      || (dnsRecordType && !['A', 'AAAA'].includes(dnsRecordType))
      || (entry.schemaVersion != null && schemaVersion == null)
      || (entry.recordKind != null && scalar(entry.recordKind) !== 'dns-answer')
      || (entry.hook != null && hook == null)
      || (entry.transportFamily != null && transportFamily == null)
      || (entry.timestampMonotonicNs != null && !timestampMonotonicNs)
      || (entry.cgroupId != null && !cgroupId)
      || (entry.policyGeneration != null && !policyGeneration)
      || (transportProtocol && !['tcp', 'udp'].includes(transportProtocol))
      || (entry.resolverPort != null && resolverPort == null)
      || (entry.clientPort != null && clientPort == null)
    ) {
      continue;
    }
    const normalized = canonicalize({
      dnsName,
      address,
      protocol,
      port,
      transactionId,
      observedMonotonicNs,
      expiresMonotonicNs,
      ...(dnsRecordType ? { dnsRecordType } : {}),
      ...(schemaVersion == null ? {} : {
        schemaVersion,
        recordKind: 'dns-answer',
      }),
      ...(hook == null ? {} : { hook }),
      ...(transportFamily == null ? {} : { transportFamily }),
      ...(timestampMonotonicNs ? { timestampMonotonicNs } : {}),
      ...(cgroupId ? { cgroupId } : {}),
      ...(policyGeneration ? { policyGeneration } : {}),
      ...(transportProtocol ? { transportProtocol } : {}),
      ...(scalar(entry.resolverAddress)
        ? { resolverAddress: scalar(entry.resolverAddress) }
        : {}),
      ...(resolverPort == null ? {} : { resolverPort }),
      ...(clientPort == null ? {} : { clientPort }),
      ...(scalar(entry.decisionClass)
        ? { decisionClass: scalar(entry.decisionClass).toLowerCase() }
        : {}),
      ...(scalar(entry.reason)
        ? { reason: scalar(entry.reason).toLowerCase() }
        : {}),
      ...(integerField(entry.reasonCode, 1, 255) == null
        ? {}
        : { reasonCode: integerField(entry.reasonCode, 1, 255) }),
      ...(typeof entry.enforcementApplied === 'boolean'
        ? { enforcementApplied: entry.enforcementApplied }
        : {}),
    });
    unique.set(stableStringify(normalized), normalized);
  }
  return [...unique.entries()]
    .sort(([left], [right]) => left.localeCompare(right))
    .map(([, entry]) => entry);
}

function normalizeDirectEvent(event) {
  if (!isPlainObject(event)) {
    return [];
  }
  const type = scalar(event.type).toLowerCase();
  if (type === 'process.exec' || type === 'exec' || type === 'process_exec') {
    const executable = scalar(event.executable || event.binary || event.path);
    if (!executable) {
      return [];
    }
    return [{
      type: 'process.exec',
      executable,
      ...(scalar(event.parentExecutable || event.parentBinary)
        ? { parentExecutable: scalar(event.parentExecutable || event.parentBinary) }
        : {}),
      argumentCount: argumentCount(event.arguments || event.argv),
    }];
  }
  if (type === 'syscall') {
    const name = normalizeSyscallName(event.name || event.syscall);
    if (!name) {
      return [];
    }
    return [{
      type,
      name,
      ...(scalar(event.architecture) ? { architecture: scalar(event.architecture) } : {}),
    }];
  }
  if (type === 'file') {
    const path = scalar(event.path);
    const operation = scalar(event.operation || event.action).toLowerCase();
    if (!path || !FILE_OPERATIONS.has(operation)) {
      return [];
    }
    return [{ type, path, operation }];
  }
  if (type === 'network') {
    const direction = scalar(event.direction).toLowerCase();
    const protocol = scalar(event.protocol || 'tcp').toLowerCase();
    const port = Number(event.port);
    if (!NETWORK_DIRECTIONS.has(direction) || !NETWORK_PROTOCOLS.has(protocol)) {
      return [];
    }
    const dnsNames = sortedUniqueStrings([
      ...(Array.isArray(event.dnsNames) ? event.dnsNames : []),
      scalar(event.dnsName),
    ].map((value) => scalar(value).toLowerCase().replace(/\.$/, '')));
    const decision = normalizeNetworkDecision(event.decision);
    const dnsChain = normalizeDnsChain(event.dnsChain);
    return [canonicalize({
      type,
      direction,
      protocol,
      ...(scalar(event.address) ? { address: scalar(event.address) } : {}),
      ...(scalar(event.cidr) ? { cidr: scalar(event.cidr) } : {}),
      ...(scalar(event.dnsName)
        ? { dnsName: scalar(event.dnsName).toLowerCase().replace(/\.$/, '') }
        : {}),
      ...(dnsNames.length ? { dnsNames } : {}),
      ...(dnsChain.length ? { dnsChain } : {}),
      ...(decision ? { decision } : {}),
      ...(Number.isInteger(port) && port >= 1 && port <= 65535 ? { port } : {}),
      ...(scalar(event.unresolvedReason)
        ? { unresolvedReason: scalar(event.unresolvedReason) }
        : {}),
    })];
  }
  if (type === 'capability') {
    const rawName = scalar(event.name)
      .toUpperCase()
      .replace(/^CAP_/, '');
    const name = rawName ? `CAP_${rawName}` : '';
    return name && /^CAP_[A-Z0-9_]+$/.test(name)
      ? [{ type, name }]
      : [];
  }
  if (type === 'mount') {
    const path = scalar(event.path || event.target);
    if (!path) {
      return [];
    }
    const operation = scalar(event.operation || 'read').toLowerCase();
    return [canonicalize({
      type,
      path,
      ...(FILE_OPERATIONS.has(operation) ? { operation } : {}),
      ...(scalar(event.source) ? { source: scalar(event.source) } : {}),
    })];
  }
  if (type === 'recommendation') {
    return [canonicalize({
      type,
      ...(scalar(event.domain) ? { domain: scalar(event.domain) } : {}),
      ...(scalar(event.action) ? { action: scalar(event.action) } : {}),
      ...(event.value !== undefined ? { value: canonicalize(event.value) } : {}),
      ...(scalar(event.generator) ? { generator: scalar(event.generator) } : {}),
    })];
  }
  return [];
}

function normalizeTetragonRecord(record) {
  const payload = record.process_exec
    || record.process_kprobe
    || record.process_lsm
    || record.process_tracepoint;
  if (!isPlainObject(payload)) {
    return [];
  }
  if (record.process_exec) {
    const process = payload.process || {};
    return normalizeDirectEvent({
      type: 'process.exec',
      executable: process.binary || process.executable,
      parentExecutable: process.parent_exec_id?.binary
        || payload.parent?.binary
        || process.parent?.binary,
      arguments: process.arguments || process.argv,
    });
  }

  const functionName = scalar(
    payload.function_name
    || payload.hook
    || payload.subsys
    || payload.event,
  );
  const events = [];
  const syscall = normalizeSyscallName(functionName);
  if (syscall && (
    functionName.includes('_sys_')
    || functionName.startsWith('sys_')
    || payload.syscall === true
  )) {
    events.push({
      type: 'syscall',
      name: syscall,
      ...(inferArchitecture(functionName)
        ? { architecture: inferArchitecture(functionName) }
        : {}),
    });
  }

  const lowerName = functionName.toLowerCase();
  const fileOperation = lowerName.includes('exec')
    ? 'execute'
    : lowerName.includes('unlink') || lowerName.includes('delete')
      ? 'delete'
      : lowerName.includes('rename')
        ? 'rename'
        : lowerName.includes('write') || lowerName.includes('create')
          ? 'write'
          : lowerName.includes('open') || lowerName.includes('read') || lowerName === 'file_open'
            ? 'read'
            : '';
  const path = firstPathFromArguments(payload.args);
  if (fileOperation && path) {
    events.push({ type: 'file', path, operation: fileOperation });
  }

  const direction = lowerName.includes('connect') || lowerName.includes('send')
    ? 'egress'
    : lowerName.includes('accept') || lowerName.includes('recv') || lowerName.includes('bind')
      ? 'ingress'
      : '';
  const socket = firstSocketFromArguments(payload.args);
  if (direction && socket) {
    events.push({ type: 'network', direction, ...socket });
  }
  return events;
}

function normalizeRecord(record) {
  if (!isPlainObject(record)) {
    return [];
  }
  if (isPlainObject(record.event)) {
    return normalizeDirectEvent(record.event);
  }
  if (scalar(record.type)) {
    return normalizeDirectEvent(record);
  }
  return normalizeTetragonRecord(record);
}

function provenanceKey(source, runId) {
  return stableStringify({ source, runId });
}

function updateRange(group, observedAt) {
  if (!observedAt) {
    return;
  }
  const milliseconds = Date.parse(observedAt);
  if (!Number.isFinite(milliseconds)) {
    return;
  }
  const timestamp = new Date(milliseconds).toISOString();
  if (!group.observedFrom || timestamp < group.observedFrom) {
    group.observedFrom = timestamp;
  }
  if (!group.observedTo || timestamp > group.observedTo) {
    group.observedTo = timestamp;
  }
}

function correlationTimestamp(value) {
  const timestamp = scalar(value);
  if (!RFC3339_TIMESTAMP.test(timestamp)) {
    return null;
  }
  const milliseconds = Date.parse(timestamp);
  if (!Number.isFinite(milliseconds)) {
    return null;
  }
  return {
    milliseconds,
    value: new Date(milliseconds).toISOString(),
  };
}

function correlationContainerIdentity(container) {
  if (!container.id || !container.imageDigest) {
    return '';
  }
  return `${container.id}\0${container.imageDigest}`;
}

function managedDnsJoinKey(entry) {
  if (
    !entry.runId
    || !entry.containerIdentity
    || !entry.event.address
  ) {
    return '';
  }
  return `${entry.runId}\0${entry.containerIdentity}\0${entry.event.address}`;
}

function increment(map, key, create) {
  let entry = map.get(key);
  if (!entry) {
    entry = create();
    map.set(key, entry);
  }
  entry.count += 1;
  return entry;
}

function normalizeSubject(subject) {
  if (!isPlainObject(subject)) {
    return {};
  }
  return canonicalize({
    ...(scalar(subject.id || subject.containerId)
      ? { containerId: scalar(subject.id || subject.containerId) }
      : {}),
    ...(scalar(subject.name) ? { name: scalar(subject.name) } : {}),
    ...(scalar(subject.image) ? { image: scalar(subject.image) } : {}),
    ...(scalar(subject.imageDigest || subject.digest)
      ? { imageDigest: scalar(subject.imageDigest || subject.digest) }
      : {}),
  });
}

export function isNormalizedEvidence(value) {
  return Boolean(
    isPlainObject(value)
    && value.apiVersion === API_VERSION
    && value.kind === EVIDENCE_KIND
    && isPlainObject(value.observations),
  );
}

export function normalizeEvidence(input, options = {}) {
  const records = flattenRecords(input);
  const provenance = new Map();
  const containers = new Map();
  const executables = new Map();
  const syscalls = new Map();
  const files = new Map();
  const network = new Map();
  const networkEvents = [];
  const capabilities = new Map();
  const mounts = new Map();
  const advisoryEvidence = [];
  const warnings = [];
  let ignoredRecords = 0;

  records.forEach((record, recordIndex) => {
    if (!isPlainObject(record)) {
      ignoredRecords += 1;
      warnings.push(`record ${recordIndex + 1} is not an object`);
      return;
    }
    const source = normalizeSource(record.source, record);
    const runId = scalar(record.runId || record.run_id);
    const payload = record.process_exec
      || record.process_kprobe
      || record.process_lsm
      || record.process_tracepoint;
    const container = normalizeContainer(record.container);
    const tetragonContainer = containerFromTetragon(payload);
    const effectiveContainer = canonicalize({
      ...tetragonContainer,
      ...container,
    });
    if (Object.keys(effectiveContainer).length) {
      addContainer(containers, effectiveContainer);
    }

    const key = provenanceKey(source, runId);
    let sourceGroup = provenance.get(key);
    if (!sourceGroup) {
      sourceGroup = {
        source,
        ...(runId ? { runId } : {}),
        recordCount: 0,
        eventHashes: [],
        containers: new Map(),
      };
      provenance.set(key, sourceGroup);
    }
    sourceGroup.recordCount += 1;
    if (Object.keys(effectiveContainer).length) {
      addContainer(sourceGroup.containers, effectiveContainer);
    }
    updateRange(sourceGroup, scalar(record.observedAt || record.time || record.timestamp));

    const events = normalizeRecord(record);
    if (!events.length) {
      ignoredRecords += 1;
      return;
    }
    sourceGroup.eventHashes.push(...events.map((event) => sha256(stableStringify(event))));

    const advisorySource = source.kind === 'ig'
      || source.kind.startsWith('ig-')
      || source.kind.startsWith('ig_')
      || source.kind.startsWith('inspektor-gadget')
      || source.kind === 'advisory';
    for (const event of events) {
      if (event.type === 'recommendation' || advisorySource) {
        advisoryEvidence.push(canonicalize({
          source,
          ...(runId ? { runId } : {}),
          domain: event.domain || event.type,
          ...(event.action ? { action: event.action } : {}),
          value: event.value !== undefined
            ? event.value
            : canonicalize(Object.fromEntries(
              Object.entries(event).filter(([field]) => field !== 'type'),
            )),
          ...(event.generator ? { generator: event.generator } : {}),
          policyUse: 'evidence-only',
        }));
        continue;
      }
      if (event.type === 'process.exec') {
        const entry = increment(executables, event.executable, () => ({
          path: event.executable,
          parentPaths: new Set(),
          count: 0,
        }));
        if (event.parentExecutable) {
          entry.parentPaths.add(event.parentExecutable);
        }
        continue;
      }
      if (event.type === 'syscall') {
        const entry = increment(syscalls, event.name, () => ({
          name: event.name,
          architectures: new Set(),
          count: 0,
        }));
        if (event.architecture) {
          entry.architectures.add(event.architecture);
        }
        continue;
      }
      if (event.type === 'file') {
        const entry = increment(files, event.path, () => ({
          path: event.path,
          operations: new Set(),
          count: 0,
        }));
        entry.operations.add(event.operation);
        continue;
      }
      if (event.type === 'network') {
        networkEvents.push({
          event,
          source,
          runId,
          containerIdentity: correlationContainerIdentity(effectiveContainer),
          observedAt: correlationTimestamp(
            record.observedAt || record.time || record.timestamp,
          ),
        });
        continue;
      }
      if (event.type === 'capability') {
        increment(capabilities, event.name, () => ({ name: event.name, count: 0 }));
        continue;
      }
      if (event.type === 'mount') {
        const normalized = canonicalize({
          path: event.path,
          ...(event.operation ? { operation: event.operation } : {}),
          ...(event.source ? { source: event.source } : {}),
        });
        increment(mounts, stableStringify(normalized), () => ({
          ...normalized,
          count: 0,
        }));
      }
    }
  });

  const managedDnsAnswers = new Map();
  for (const entry of networkEvents) {
    if (
      entry.source.kind !== 'managed_dns'
      || !entry.event.dnsName
      || !entry.observedAt
    ) {
      continue;
    }
    const key = managedDnsJoinKey(entry);
    if (!key) {
      continue;
    }
    const answers = managedDnsAnswers.get(key) || [];
    answers.push({
      dnsName: entry.event.dnsName,
      observedAt: entry.observedAt,
    });
    managedDnsAnswers.set(key, answers);
  }
  for (const entry of networkEvents) {
    if (entry.source.kind === 'managed_dns') {
      // Resolver answers are correlation evidence. A socket observation is
      // still required before they can become a destination/port rule.
      continue;
    }
    let event = entry.event;
    if (
      entry.source.kind === 'nosh_l4'
      && entry.runId
      && event.direction === 'egress'
      && ['tcp', 'udp'].includes(event.protocol)
      && event.address
      && !event.dnsName
    ) {
      const key = managedDnsJoinKey(entry);
      const candidates = key && entry.observedAt
        ? (managedDnsAnswers.get(key) || []).filter(
          (answer) =>
            Math.abs(
              answer.observedAt.milliseconds - entry.observedAt.milliseconds,
            ) <= NETWORK_JOIN_MAX_CLOCK_SKEW_MS,
        )
        : [];
      const names = new Set(candidates.map((answer) => answer.dnsName));
      if (names.size === 1) {
        const [dnsName] = names;
        event = canonicalize({
          ...event,
          address: undefined,
          dnsName,
        });
      } else if (names.size > 1) {
        const sortedNames = [...names].sort();
        event = canonicalize({
          ...event,
          unresolvedReason:
            `destination IP was shared by multiple DNS names: ${sortedNames.join(', ')}`,
        });
        warnings.push(
          `network destination ${event.address} was not promoted to DNS policy because ${names.size} names shared it`,
        );
      } else {
        event = canonicalize({
          ...event,
          unresolvedReason:
            `no managed DNS answer matched the run, container, destination IP, and ${NETWORK_JOIN_MAX_CLOCK_SKEW_MS}ms window`,
        });
        warnings.push(
          `network destination ${event.address} was not promoted because it had no trustworthy managed DNS correlation`,
        );
      }
    }
    const normalized = canonicalize({
      direction: event.direction,
      protocol: event.protocol,
      ...(event.address ? { address: event.address } : {}),
      ...(event.cidr ? { cidr: event.cidr } : {}),
      ...(event.dnsName ? { dnsName: event.dnsName } : {}),
      ...(event.dnsNames?.length ? { dnsNames: event.dnsNames } : {}),
      ...(event.dnsChain?.length ? { dnsChain: event.dnsChain } : {}),
      ...(event.decision ? { decision: event.decision } : {}),
      ...(event.port ? { port: event.port } : {}),
      ...(event.unresolvedReason
        ? { unresolvedReason: event.unresolvedReason }
        : {}),
    });
    increment(network, stableStringify(normalized), () => ({
      ...normalized,
      count: 0,
    }));
  }

  const containerList = Array.from(containers.values()).sort(compareCanonical);
  if (containerList.length > 1) {
    warnings.push(
      `evidence contains ${containerList.length} container identities; compile separate profiles before enforcement`,
    );
  }
  if (ignoredRecords) {
    warnings.push(`${ignoredRecords} evidence record(s) did not produce policy observations`);
  }

  const subject = normalizeSubject({
    ...(containerList[0] || {}),
    ...(isPlainObject(options.subject) ? options.subject : {}),
    ...(scalar(options.imageDigest) ? { imageDigest: scalar(options.imageDigest) } : {}),
  });
  const name = sanitizeDnsLabel(
    options.name || subject.name || records.find((record) => scalar(record?.runId))?.runId || 'nosh',
    'nosh',
  );
  const provenanceEntries = Array.from(provenance.values())
    .map((entry) => canonicalize({
      source: entry.source,
      ...(entry.runId ? { runId: entry.runId } : {}),
      recordCount: entry.recordCount,
      ...(entry.observedFrom ? { observedFrom: entry.observedFrom } : {}),
      ...(entry.observedTo ? { observedTo: entry.observedTo } : {}),
      containers: Array.from(entry.containers.values()).sort(compareCanonical),
      evidenceHash: sha256(stableStringify(entry.eventHashes.sort())),
      policyUse: entry.source.kind === 'ig'
        || entry.source.kind.startsWith('ig-')
        || entry.source.kind.startsWith('ig_')
        || entry.source.kind.startsWith('inspektor-gadget')
        || entry.source.kind === 'advisory'
        ? 'evidence-only'
        : 'candidate-input',
    }))
    .sort(compareCanonical);
  const explicitRuns = Array.isArray(options.runProvenance)
    ? options.runProvenance
    : [];
  const runProvenance = explicitRuns.length
    ? explicitRuns
      .map((run) => canonicalize(run))
      .sort((left, right) => (
        scalar(left?.runId).localeCompare(scalar(right?.runId))
        || compareCanonical(left, right)
      ))
    : sortedUniqueStrings(
      provenanceEntries.map((entry) => entry.runId).filter(Boolean),
    ).map((runId) => ({
      runId,
      mode: 'direct',
      manifestVerified: false,
      complete: false,
      promotionEligible: false,
      cleanAudit: false,
      gaps: ['direct evidence input has no completed run manifest'],
      lostEvents: null,
      wouldDenyCount: 0,
    }));
  const ingestion = canonicalize({
    mode: options.ingestion?.mode || 'direct',
    manifestCount: Number(options.ingestion?.manifestCount || 0),
    directInputCount: Number(
      options.ingestion?.directInputCount
      ?? (runProvenance.length || records.length ? 1 : 0),
    ),
    promotionInputEligible: options.ingestion?.promotionInputEligible === true,
    inputHashes: sortedUniqueStrings(options.ingestion?.inputHashes || []),
    ...(Number.isSafeInteger(options.ingestion?.inputCount)
      ? { inputCount: options.ingestion.inputCount }
      : {}),
    ...(Number.isSafeInteger(options.ingestion?.totalBytes)
      ? { totalBytes: options.ingestion.totalBytes }
      : {}),
  });

  return canonicalize({
    apiVersion: API_VERSION,
    kind: EVIDENCE_KIND,
    schemaVersion: SCHEMA_VERSION,
    metadata: { name },
    subject: {
      ...subject,
      identityUse: 'provenance-only',
    },
    provenance: provenanceEntries,
    runProvenance,
    ingestion,
    observations: {
      executables: Array.from(executables.values())
        .map((entry) => ({
          path: entry.path,
          parentPaths: Array.from(entry.parentPaths).sort(),
          count: entry.count,
        }))
        .sort(compareCanonical),
      syscalls: Array.from(syscalls.values())
        .map((entry) => ({
          name: entry.name,
          architectures: Array.from(entry.architectures).sort(),
          count: entry.count,
        }))
        .sort(compareCanonical),
      files: Array.from(files.values())
        .map((entry) => ({
          path: entry.path,
          operations: Array.from(entry.operations).sort(),
          count: entry.count,
        }))
        .sort(compareCanonical),
      network: Array.from(network.values()).sort(compareCanonical),
      capabilities: Array.from(capabilities.values()).sort(compareCanonical),
      mounts: Array.from(mounts.values()).sort(compareCanonical),
    },
    advisoryEvidence: advisoryEvidence.sort(compareCanonical),
    warnings: sortedUniqueStrings(warnings),
  });
}
