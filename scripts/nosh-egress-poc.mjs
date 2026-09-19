#!/usr/bin/env node
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import net from 'node:net';
import path from 'node:path';
import { pathToFileURL } from 'node:url';
import {
  renderEbpfEgressManifest,
  validateEbpfEgressAttestation,
} from '../lib/guardd/enforcement-backend.js';

const phaseNames = ['allowA', 'allowB'];
const counterNames = [
  'allowed', 'wouldDeny', 'denied', 'ringbufDrops', 'parseErrors', 'fragments',
  'configInvalid', 'policyMisses', 'dnsQueries', 'dnsResponses',
  'dnsTransactionMisses', 'dnsGrantUpdates', 'dnsGrantFailures', 'dnsUnsupported',
  'unsupportedProtocol', 'coverageAllowed', 'coverageWouldDeny', 'coverageDenied',
  'containmentDenied', 'backendDenied', 'dnsAnswers',
];
const digestPattern = /^sha256:[a-f0-9]{64}$/;
const decisionFields = [
  'schemaVersion', 'recordKind', 'timestampMonotonicNs', 'cgroupId',
  'policyGeneration', 'hook', 'family', 'protocol', 'sourceAddress',
  'destinationAddress', 'sourcePort', 'destinationPort', 'verdict',
  'decisionClass', 'reason', 'reasonCode', 'enforcementApplied',
  'containmentId', 'ruleId', 'packetBytes', 'transactionId', 'domain',
  'expiresMonotonicNs',
];
const digest = (value) => `sha256:${crypto.createHash('sha256').update(value).digest('hex')}`;

function requireValue(condition, message) {
  if (!condition) throw new Error(message);
}

function decimal(value, label, nonzero = false) {
  requireValue(typeof value === 'string' && /^(0|[1-9][0-9]*)$/.test(value), `${label}: expected decimal string`);
  const parsed = BigInt(value);
  requireValue(parsed <= 0xffffffffffffffffn && (!nonzero || parsed > 0n), `${label}: invalid counter`);
  return parsed;
}

export function createPocPolicies(a, b, gateway, ruleCount = 1) {
  requireValue(Number.isSafeInteger(ruleCount) && ruleCount >= 1 && ruleCount <= 16384, 'POC rule count must be 1..16384');
  requireValue([a, b, gateway].every((address) => net.isIP(address) === 4), 'POC endpoints and gateway must be IPv4 addresses');
  requireValue(new Set([a, b, gateway]).size === 3, 'POC endpoints and gateway must be distinct');
  const phases = {};
  for (const [index, phase] of phaseNames.entries()) {
    const endpoint = index === 0 ? 'a' : 'b';
    const policy = {
      schemaVersion: 1,
      mode: 'enforce',
      rules: [{
        id: `poc-allow-${endpoint}`,
        effect: 'allow',
        direction: 'egress',
        destination: `${index === 0 ? a : b}/32`,
        protocol: 'tcp',
        ports: [8080],
      }],
      resolvers: [a],
      platformContainmentCidrs: [`${gateway}/32`],
    };
    for (let i = 0; i < ruleCount - 1; i++) policy.rules.push({
      id: `capacity-${i}`, effect: 'allow', direction: 'egress',
      destination: `198.18.${i >> 8}.${i & 255}/32`, protocol: 'tcp', ports: [443],
    });
    const rendered = renderEbpfEgressManifest(policy.rules, policy.resolvers, policy.platformContainmentCidrs);
    phases[phase] = { policy, manifest: rendered.source, policyDigest: digest(rendered.source) };
  }
  return { phases };
}

function readEvidence(root, relative) {
  const file = path.join(root, relative);
  const stat = fs.lstatSync(file);
  requireValue(stat.isFile() && stat.size <= 32 * 1024 * 1024, `${relative}: expected bounded regular evidence file`);
  return fs.readFileSync(file, 'utf8');
}

function readJson(root, relative) {
  try {
    return JSON.parse(readEvidence(root, relative));
  } catch (error) {
    throw new Error(`${relative}: ${error.message}`);
  }
}

function readJsonLines(root, relative) {
  const text = readEvidence(root, relative);
  requireValue(text.endsWith('\n'), `${relative}: missing complete final line`);
  return text.slice(0, -1).split('\n').map((line, index) => {
    try {
      const record = JSON.parse(line);
      requireValue(record && typeof record === 'object' && !Array.isArray(record), 'expected object');
      return record;
    } catch (error) {
      throw new Error(`${relative}:${index + 1}: ${error.message}`);
    }
  });
}

function validateStatus(record, expected, status, withAttestation) {
  requireValue(record?.schemaVersion === 2 && record.recordKind === 'status' && record.status === status, `${expected.phase}: missing ${status} status`);
  decimal(record.timestampUnixNs, 'status timestamp', true);
  for (const key of ['cgroupId', 'mode', 'policyDigest', 'objectDigest', 'containmentDigest', 'containmentCount', 'pinRoot']) {
    assert.deepEqual(record[key], expected[key], `${expected.phase}: status ${key} mismatch`);
  }
  requireValue(record.attachedPrograms === 6 && record.mapAbi === 2 && record.programAbi === 2, `${expected.phase}: incomplete attached backend`);
  if (withAttestation) {
    validateEbpfEgressAttestation(record.attestation, expected);
    requireValue(record.attestation.policyGeneration === expected.policyGeneration, `${expected.phase}: attested generation mismatch`);
  }
}

function validateStats(record, expected) {
  requireValue(record?.schemaVersion === 2 && record.recordKind === 'stats' && typeof record.final === 'boolean', `${expected.phase}: invalid stats record`);
  requireValue(record.cgroupId === expected.cgroupId && record.policyGeneration === expected.policyGeneration && record.mode === 'enforce', `${expected.phase}: stats identity mismatch`);
  decimal(record.timestampUnixNs, 'stats timestamp', true);
  decimal(record.eventsSeen, 'eventsSeen');
  requireValue(decimal(record.decoderErrors, 'decoderErrors') === 0n, `${expected.phase}: decoder errors`);
  assert.deepEqual(Object.keys(record.counters || {}).sort(), [...counterNames].sort(), `${expected.phase}: invalid counter inventory`);
  for (const name of counterNames) {
    const value = decimal(record.counters[name], name);
    if (!['allowed', 'denied', 'policyMisses'].includes(name)) {
      requireValue(value === 0n, `${expected.phase}: nonzero ${name}`);
    }
  }
}

function validatePhase(root, phase, endpoints, generated, index) {
  const meta = endpoints.phases?.[phase];
  requireValue(meta && typeof meta.runId === 'string' && /^[A-Za-z0-9_.-]+$/.test(meta.runId), `${phase}: missing run identity`);
  requireValue(typeof meta.pinRoot === 'string' && /^\/sys\/fs\/bpf\/nosh-guard\/[^/]+$/.test(meta.pinRoot), `${phase}: invalid pin root`);
  requireValue(meta.policyGeneration === String(index + 1), `${phase}: expected generation ${index + 1}`);
  const { policy, manifest, policyDigest } = generated.phases[phase];
  assert.deepEqual(readJson(root, `${phase}/policy.json`), policy, `${phase}: editable policy differs from intended endpoint`);
  assert.equal(readEvidence(root, `${phase}/policy.manifest`), manifest, `${phase}: manifest differs from rendered JSON policy`);
  const expected = {
    ...meta, phase, mode: 'enforce', cgroupId: endpoints.cgroupId,
    policyDigest, objectDigest: endpoints.objectDigest,
    imageDigest: endpoints.clientImage, workspaceKey: endpoints.workspaceKey,
    containmentCount: 1,
    containmentDigest: digest(`platform-endpoint:${endpoints.gateway}\t${endpoints.gateway}/32\n`),
  };
  const status = readJson(root, `${phase}/status.json`);
  validateStatus(status, expected, 'ready', true);
  const collectorStatus = readJsonLines(root, `${phase}/collector-status.jsonl`);
  requireValue(collectorStatus.length === 2, `${phase}: collector must report ready then stopped`);
  validateStatus(collectorStatus[0], expected, 'ready', true);
  validateStatus(collectorStatus[1], expected, 'stopped', false);
  assert.deepEqual(status.attestation, collectorStatus[0].attestation, `${phase}: active status differs from collector attachment`);

  const records = readJsonLines(root, `${phase}/events.jsonl`);
  requireValue(records.length >= 4 && records[0].recordKind === 'stats' && records[0].final === false, `${phase}: missing initial collector stats`);
  const finalStats = records.at(-1);
  requireValue(finalStats.recordKind === 'stats' && finalStats.final === true, `${phase}: missing final collector stats`);
  requireValue(records.filter((record) => record.recordKind === 'stats' && record.final === true).length === 1, `${phase}: duplicate final collector stats`);
  const { ruleIdMap } = renderEbpfEgressManifest(policy.rules, policy.resolvers, policy.platformContainmentCidrs);
  const allowedRuleIdentity = `poc-allow-${index === 0 ? 'a' : 'b'}`;
  const allowedRuleIds = Object.entries(ruleIdMap).filter(([, identity]) => identity === allowedRuleIdentity);
  requireValue(allowedRuleIds.length === 1, `${phase}: missing or ambiguous endpoint rule identity`);
  const allowedRuleId = Number(allowedRuleIds[0][0]);
  const allowedAddress = index === 0 ? endpoints.a : endpoints.b;
  const deniedAddress = index === 0 ? endpoints.b : endpoints.a;
  let seen = 0n;
  let allowed = 0n;
  let denied = 0n;
  let allowedConnect = false;
  let deniedConnect = false;
  let priorStats = null;
  for (const record of records) {
    if (record.recordKind === 'stats') {
      validateStats(record, expected);
      requireValue(BigInt(record.eventsSeen) === seen, `${phase}: eventsSeen mismatch`);
      if (priorStats) {
        for (const name of counterNames) {
          requireValue(BigInt(record.counters[name]) >= BigInt(priorStats.counters[name]), `${phase}: counters decreased`);
        }
      }
      priorStats = record;
      continue;
    }
    requireValue(record.schemaVersion === 2 && record.recordKind === 'decision', `${phase}: unexpected event kind`);
    assert.deepEqual(Object.keys(record).sort(), [...decisionFields].sort(), `${phase}: invalid decision fields`);
    requireValue(record.cgroupId === expected.cgroupId && record.policyGeneration === expected.policyGeneration, `${phase}: decision identity mismatch`);
    decimal(record.timestampMonotonicNs, 'decision timestamp', true);
    requireValue(net.isIP(record.sourceAddress) === 4 && net.isIP(record.destinationAddress) === 4, `${phase}: invalid decision addresses`);
    requireValue([record.sourcePort, record.destinationPort].every((port) => Number.isInteger(port) && port >= 0 && port <= 65535), `${phase}: invalid decision ports`);
    requireValue(Number.isInteger(record.packetBytes) && record.packetBytes >= 0 && record.packetBytes <= 0xffffffff && record.transactionId === 0 && record.expiresMonotonicNs === '0', `${phase}: invalid static decision metadata`);
    requireValue(record.family === 4 && record.protocol === 6 && [1, 5, 6].includes(record.hook), `${phase}: unexpected transport or hook`);
    requireValue(record.enforcementApplied === true && record.containmentId === '' && record.domain === '', `${phase}: missing enforcement or unexpected authority`);
    const remoteAddress = record.hook === 5 ? record.sourceAddress : record.destinationAddress;
    const remotePort = record.hook === 5 ? record.sourcePort : record.destinationPort;
    requireValue(remotePort === 8080, `${phase}: unexpected remote port`);
    if (record.verdict === 'allow') {
      requireValue(record.decisionClass === 'policy-allow' && record.reason === 'static-policy' && record.reasonCode === 1 && record.ruleId === allowedRuleId && remoteAddress === allowedAddress, `${phase}: invalid allowed decision`);
      allowed += 1n;
      allowedConnect ||= record.hook === 1;
    } else {
      requireValue(record.verdict === 'deny' && record.decisionClass === 'policy-deny' && record.reason === 'default-deny' && record.reasonCode === 5 && record.ruleId === 0 && remoteAddress === deniedAddress, `${phase}: invalid denied decision`);
      denied += 1n;
      deniedConnect ||= record.hook === 1;
    }
    seen += 1n;
  }
  requireValue(allowedConnect && deniedConnect, `${phase}: missing allowed or denied connect4 evidence`);
  requireValue(BigInt(finalStats.counters.allowed) === allowed && BigInt(finalStats.counters.denied) === denied && BigInt(finalStats.counters.policyMisses) === denied, `${phase}: decision counters mismatch`);
  const snapshot = readJsonLines(root, `${phase}/snapshot.jsonl`);
  requireValue(snapshot.length === 2 && snapshot[0].schemaVersion === 2 && snapshot[0].recordKind === 'snapshot-header', `${phase}: invalid final snapshot`);
  for (const key of ['policyDigest', 'objectDigest', 'containmentDigest', 'containmentCount', 'pinRoot']) {
    assert.deepEqual(snapshot[0][key], expected[key], `${phase}: snapshot ${key} mismatch`);
  }
  validateStats(snapshot[1], expected);
  requireValue(snapshot[1].final === true && snapshot[1].eventsSeen === '0', `${phase}: invalid snapshot stats`);
  assert.deepEqual(snapshot[1].counters, finalStats.counters, `${phase}: snapshot counters differ from collector final counters`);
  return { policyDigest, policyGeneration: expected.policyGeneration, allowedAddress, deniedAddress, allowedEvents: String(allowed), deniedEvents: String(denied), eventsSeen: String(seen) };
}

export function verifyPocEvidence(directory) {
  const root = path.resolve(directory);
  const endpoints = readJson(root, 'endpoints.json');
  const generated = createPocPolicies(endpoints.a, endpoints.b, endpoints.gateway, endpoints.capacityRuleCount || 1);
  requireValue(digestPattern.test(endpoints.clientImage) && /^[a-f0-9]{64}$/.test(endpoints.clientId), 'invalid client image/container identity');
  requireValue(digestPattern.test(endpoints.objectDigest) && /^[a-f0-9]{64}$/.test(endpoints.workspaceKey), 'invalid object/workspace identity');
  decimal(endpoints.cgroupId, 'client cgroup', true);
  const probes = readJsonLines(root, 'probes.jsonl');
  requireValue(probes.length === 6, 'expected exactly six probes');
  const combinations = new Set();
  for (const probe of probes) {
    requireValue(['baseline', ...phaseNames].includes(probe.phase) && ['a', 'b'].includes(probe.endpoint), 'invalid probe phase or endpoint');
    const key = `${probe.phase}/${probe.endpoint}`;
    requireValue(!combinations.has(key), `duplicate probe ${key}`);
    combinations.add(key);
    requireValue(probe.address === endpoints[probe.endpoint] && probe.port === 8080 && Number.isInteger(probe.exitCode) && typeof probe.httpCode === 'string' && typeof probe.body === 'string' && typeof probe.error === 'string', `${key}: invalid probe record`);
    const permitted = probe.phase === 'baseline' || probe.phase === `allow${probe.endpoint.toUpperCase()}`;
    if (permitted) {
      requireValue(probe.exitCode === 0 && probe.httpCode === '200' && probe.body.replace(/\r?\n$/, '') === probe.endpoint.toUpperCase() && !probe.error, `${key}: permitted HTTP request failed`);
    } else {
      requireValue(probe.exitCode > 0 && probe.exitCode <= 255 && probe.httpCode === '000' && probe.body === '' && probe.error.length > 0, `${key}: denied request was not a failed connection`);
    }
  }
  for (const endpoint of ['a', 'b']) {
    const server = readJsonLines(root, `server-${endpoint}.jsonl`);
    const requests = [];
    for (const record of server) {
      requireValue(record.endpoint === endpoint, `server ${endpoint}: wrong endpoint identity`);
      if (record.ready === true && record.path == null) continue;
      requireValue(typeof record.path === 'string' && record.ready == null, `server ${endpoint}: invalid request record`);
      requests.push(record.path);
    }
    assert.deepEqual(requests.sort(), [`/baseline/${endpoint}`, `/allow${endpoint.toUpperCase()}/${endpoint}`].sort(), `server ${endpoint}: request log contradicts policy`);
  }
  const phases = Object.fromEntries(phaseNames.map((phase, index) => [phase, validatePhase(root, phase, endpoints, generated, index)]));
  requireValue(endpoints.phases.allowA.pinRoot !== endpoints.phases.allowB.pinRoot && endpoints.phases.allowA.runId !== endpoints.phases.allowB.runId, 'phase attachment identities must differ');
  const cleanup = readJson(root, 'cleanup.json');
  for (const key of ['ok', 'containersRemoved', 'networkRemoved', 'pinRootsRemoved']) {
    requireValue(cleanup[key] === true, `cleanup incomplete: ${key}`);
  }
  return { schemaVersion: 1, status: 'passed', evidenceDir: root, cgroupId: endpoints.cgroupId, clientId: endpoints.clientId, baseline: { a: 'HTTP 200 A', b: 'HTTP 200 B' }, phases, cleanup };
}

if (process.argv[1] && import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href) {
  try {
    const [command, ...args] = process.argv.slice(2);
    let result;
    if (command === 'policies' && args.length === 3) result = createPocPolicies(...args, Number(process.env.NOSH_EGRESS_POC_RULE_COUNT || 1));
    else if (command === 'verify' && args.length === 1) result = verifyPocEvidence(args[0]);
    else throw new Error('usage: nosh-egress-poc.mjs policies A_IPV4 B_IPV4 GATEWAY_IPV4 | verify EVIDENCE_DIR');
    process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
  } catch (error) {
    process.stderr.write(`nosh-egress-poc: ${error.message}\n`);
    process.exitCode = 1;
  }
}
