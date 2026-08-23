import net from 'node:net';

import { API_VERSION } from './constants.js';
import { asEvidence, profileName, validationResult } from './artifact-utils.js';
import {
  canonicalize,
  compareCanonical,
  isPlainObject,
} from './stable.js';

function destinationFromObservation(observation) {
  if (observation.cidr) {
    return observation.cidr;
  }
  if (observation.dnsName) {
    return observation.dnsName;
  }
  if (observation.address) {
    return observation.address;
  }
  return '';
}

function observationEvidence(observation) {
  if (!observation.decision && !observation.dnsChain?.length) {
    return null;
  }
  return canonicalize({
    ...(observation.address ? { address: observation.address } : {}),
    ...(observation.dnsName ? { dnsName: observation.dnsName } : {}),
    ...(observation.dnsNames?.length ? { dnsNames: observation.dnsNames } : {}),
    ...(observation.dnsChain?.length ? { dnsChain: observation.dnsChain } : {}),
    ...(observation.decision ? { decision: observation.decision } : {}),
    ...(Number.isSafeInteger(observation.count) && observation.count > 0
      ? { count: observation.count }
      : {}),
  });
}

const NON_AUTHORIZABLE_DECISION_CLASSES = new Set([
  'backend-deny',
  'containment-deny',
  'coverage-gap',
  'dns-observation',
  'infrastructure-allow',
]);

function ruleFromObservation(observation) {
  const destination = destinationFromObservation(observation);
  if (
    observation.unresolvedReason
    || NON_AUTHORIZABLE_DECISION_CLASSES.has(observation.decision?.decisionClass)
    || !destination
    || observation.protocol === 'any'
    || (['tcp', 'udp'].includes(observation.protocol) && !observation.port)
  ) {
    return null;
  }
  const evidence = observationEvidence(observation);
  return canonicalize({
    destination,
    protocol: observation.protocol,
    ...(['tcp', 'udp'].includes(observation.protocol)
      ? { ports: [observation.port] }
      : {}),
    ...(evidence ? { observations: [evidence] } : {}),
  });
}

function unresolvedObservationReason(observation) {
  if (observation.unresolvedReason) return observation.unresolvedReason;
  if (NON_AUTHORIZABLE_DECISION_CLASSES.has(
    observation.decision?.decisionClass,
  )) {
    return `${observation.decision.decisionClass} evidence cannot become reviewed network authority`;
  }
  if (observation.protocol === 'any') {
    return 'protocol any cannot be represented by the managed egress backend';
  }
  if (['tcp', 'udp'].includes(observation.protocol) && !observation.port) {
    return 'TCP and UDP rules require an observed destination port';
  }
  return 'missing peer address, CIDR, or DNS name';
}

export function compileNetworkArtifact(evidenceInput, options = {}) {
  const evidence = asEvidence(evidenceInput, options);
  const ingress = [];
  const egress = [];
  const unresolvedObservations = [];
  for (const observation of evidence.observations.network || []) {
    const rule = ruleFromObservation(observation);
    if (!rule) {
      const evidence = observationEvidence(observation);
      unresolvedObservations.push(canonicalize({
        direction: observation.direction,
        protocol: observation.protocol,
        ...(destinationFromObservation(observation)
          ? { destination: destinationFromObservation(observation) }
          : {}),
        ...(observation.port ? { port: observation.port } : {}),
        reason: unresolvedObservationReason(observation),
        ...(evidence ? { observation: evidence } : {}),
      }));
      continue;
    }
    if (observation.direction === 'ingress') {
      ingress.push(rule);
    } else if (observation.direction === 'egress') {
      egress.push(rule);
    }
  }
  ingress.sort(compareCanonical);
  egress.sort(compareCanonical);
  unresolvedObservations.sort(compareCanonical);
  return canonicalize({
    apiVersion: API_VERSION,
    kind: 'NoshNetworkPolicy',
    metadata: {
      name: profileName(evidence, options),
      annotations: {
        'notty.dev/candidate': 'true',
        'notty.dev/review-required': 'true',
      },
    },
    spec: {
      policyTypes: ['Ingress', 'Egress'],
      defaultDeny: {
        ingress: true,
        egress: true,
      },
      ingress,
      egress,
      unresolvedObservations,
    },
  });
}

function validateRule(rule, direction, errors, warnings) {
  if (!isPlainObject(rule)) {
    errors.push(`${direction} network rule must be an object`);
    return;
  }
  if (typeof rule.destination !== 'string' || !rule.destination) {
    errors.push(`${direction} network rule must have a destination`);
  } else {
    const destination = rule.destination.startsWith('*.')
      ? rule.destination.slice(2)
      : rule.destination;
    const [address, prefix] = destination.split('/');
    const family = net.isIP(address);
    const cidrValid = family && (
      prefix === undefined
      || (
        prefix !== ''
        && Number.isInteger(Number(prefix))
        && Number(prefix) >= 0
        && Number(prefix) <= (family === 4 ? 32 : 128)
      )
    );
    const dnsValid = !family
      && destination.includes('.')
      && destination.length <= 253
      && /^[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?$/.test(destination);
    if (!cidrValid && !dnsValid) {
      errors.push(`${direction} network rule destination must be an IP, CIDR, or FQDN`);
    }
  }
  if (
    rule.destination === '0.0.0.0'
    || rule.destination === '::'
    || rule.destination === '0.0.0.0/0'
    || rule.destination === '::/0'
    || rule.destination === '*'
  ) {
    warnings.push(`${direction} network rule contains a wildcard destination`);
  }
  if (rule.destination?.startsWith('*.')) {
    warnings.push(`${direction} network rule contains a wildcard DNS destination`);
  }
  if (!['icmp', 'icmpv6', 'tcp', 'udp'].includes(rule.protocol)) {
    errors.push(`${direction} network rule has an unsupported protocol`);
  }
  if (rule.ports !== undefined) {
    if (
      !Array.isArray(rule.ports)
      || !rule.ports.length
      || rule.ports.some((port) => !Number.isInteger(port) || port < 1 || port > 65535)
    ) {
      errors.push(`${direction} network rule ports must be integers from 1 to 65535`);
    }
  }
  if (
    ['tcp', 'udp'].includes(rule.protocol)
    && (!Array.isArray(rule.ports) || !rule.ports.length)
  ) {
    errors.push(`${direction} TCP and UDP network rules require ports`);
  }
  if (
    ['icmp', 'icmpv6'].includes(rule.protocol)
    && Array.isArray(rule.ports)
    && rule.ports.length
  ) {
    errors.push(`${direction} ICMP network rules must not contain ports`);
  }
}

export function validateNetworkArtifact(artifact) {
  const errors = [];
  const warnings = [];
  if (!isPlainObject(artifact)) {
    return validationResult(
      ['network artifact must be an object'],
      [],
      { enforceable: false, runtimeValidationRequired: true },
    );
  }
  if (artifact.apiVersion !== API_VERSION || artifact.kind !== 'NoshNetworkPolicy') {
    errors.push('network artifact must be a notty.dev/v1alpha1 NoshNetworkPolicy');
  }
  const spec = artifact.spec;
  if (spec?.defaultDeny?.ingress !== true || spec?.defaultDeny?.egress !== true) {
    errors.push('network candidate must default-deny both ingress and egress');
  }
  if (!Array.isArray(spec?.ingress) || !Array.isArray(spec?.egress)) {
    errors.push('network candidate ingress and egress rules must be arrays');
  }
  for (const rule of spec?.ingress || []) {
    validateRule(rule, 'ingress', errors, warnings);
  }
  for (const rule of spec?.egress || []) {
    validateRule(rule, 'egress', errors, warnings);
  }
  if (Array.isArray(spec?.unresolvedObservations) && spec.unresolvedObservations.length) {
    warnings.push(
      `${spec.unresolvedObservations.length} network observation(s) were not converted into allow rules`,
    );
  }
  if (!(spec?.ingress || []).length && !(spec?.egress || []).length) {
    warnings.push('network candidate denies all traffic; add reviewed rules required by the workload');
  }
  warnings.push('network policy requires an external manager that binds this intent to the target container');
  return validationResult(errors, warnings, {
    enforceable: errors.length === 0,
    runtimeValidationRequired: true,
  });
}
