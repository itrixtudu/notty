import net from 'node:net';

const DECISION_FIELDS = [
  'schemaVersion', 'recordKind', 'timestampMonotonicNs', 'cgroupId',
  'policyGeneration', 'hook', 'family', 'protocol', 'sourceAddress',
  'destinationAddress', 'sourcePort', 'destinationPort', 'verdict',
  'decisionClass', 'reason', 'reasonCode', 'enforcementApplied',
  'containmentId', 'ruleId', 'packetBytes', 'transactionId', 'domain',
  'expiresMonotonicNs',
];

function unsignedInteger(value, maximum) {
  return Number.isSafeInteger(value) && value >= 0 && value <= maximum;
}

function decimal(value, positive = false) {
  return typeof value === 'string'
    && /^(0|[1-9][0-9]*)$/.test(value)
    && (!positive || value !== '0');
}

// This successful learning record describes a DNS question, not a connection
// to its answer. Keep it as evidence without inventing endpoint authority or
// a capture gap. Unknown or malformed records do not receive this exception.
export function isLearningDnsQueryEvidence(record) {
  return record != null && typeof record === 'object' && !Array.isArray(record)
    && Object.keys(record).length === DECISION_FIELDS.length
    && DECISION_FIELDS.every((field) => Object.hasOwn(record, field))
    && record.schemaVersion === 2 && record.recordKind === 'decision'
    && record.reasonCode === 17 && record.reason === 'dns-query-observed'
    && record.decisionClass === 'dns-observation' && record.verdict === 'allow'
    && record.enforcementApplied === false && record.containmentId === ''
    && record.ruleId === 0 && record.hook === 6
    && [4, 6].includes(record.family)
    && net.isIP(record.sourceAddress) === record.family
    && net.isIP(record.destinationAddress) === record.family
    && [6, 17].includes(record.protocol) && record.destinationPort === 53
    && unsignedInteger(record.sourcePort, 65535) && record.sourcePort > 0
    && unsignedInteger(record.packetBytes, 0xffffffff) && record.packetBytes > 0
    && unsignedInteger(record.transactionId, 65535)
    && decimal(record.timestampMonotonicNs)
    && decimal(record.cgroupId, true) && decimal(record.policyGeneration, true)
    && record.expiresMonotonicNs === '0'
    && typeof record.domain === 'string' && record.domain.length <= 253
    && record.domain.split('.').every((label) => label.length >= 1
      && label.length <= 63 && /^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/.test(label));
}

// Older immutable candidates put successful questions in unresolvedObservations.
// Recognize only that exact legacy representation; do not rewrite its hashes.
export function isLegacyLearningDnsQueryObservation(entry) {
  const observation = entry?.observation;
  const decision = observation?.decision;
  return isLearningDnsQueryEvidence(decision)
    && Object.keys(entry).length === 6
    && ['direction', 'protocol', 'destination', 'port', 'reason', 'observation']
      .every((field) => Object.hasOwn(entry, field))
    && Object.keys(observation).every((field) => ['address', 'decision', 'count'].includes(field))
    && (!Object.hasOwn(observation, 'count')
      || Number.isSafeInteger(observation.count) && observation.count > 0)
    && entry.reason === 'dns-observation evidence cannot become reviewed network authority'
    && entry.direction === 'egress'
    && entry.protocol === (decision.protocol === 17 ? 'udp' : 'tcp')
    && entry.port === 53 && entry.destination === decision.destinationAddress
    && observation.address === decision.destinationAddress;
}
