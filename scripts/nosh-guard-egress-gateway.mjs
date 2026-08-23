#!/usr/bin/env node

import crypto from 'node:crypto';
import { constants as fsConstants } from 'node:fs';
import fs from 'node:fs/promises';
import http from 'node:http';
import net from 'node:net';
import path from 'node:path';
import { spawn, spawnSync } from 'node:child_process';
import { Transform, Writable } from 'node:stream';
import { finished } from 'node:stream/promises';

import {
  egressModeBehavior,
  egressPolicyFlowMark,
  generateDnsmasqConfig,
  generateNftRules,
  requiresStrictManagedDns,
} from '../lib/guardd/egress-policy.js';
import { MANAGED_GATEWAY_EVIDENCE_MAX_BYTES } from '../lib/guardd/constants.js';
import {
  MANAGED_DNS_EVIDENCE_MAX_BYTES,
  managedDnsEvidenceSnapshot,
  managedDnsEvidencePaths,
  managedDnsOverflowMarker,
  validateManagedDnsEvidenceSnapshot,
  validateManagedDnsOverflowMarker,
} from '../lib/guardd/managed-dns-evidence.js';
import {
  canonicalProxyHeaders,
  normalizeGatewayPublicOrigin,
  validatePublicRequestHeaders,
} from '../lib/guardd/proxy-contract.js';

const policyDir =
  process.env.NOSH_GUARD_POLICY_DIR || '/var/lib/nosh-guard/policies';
const grantsPath =
  process.env.NOSH_GUARD_GRANTS || '/var/lib/nosh-guard/grants/current.json';
const evidenceDir =
  process.env.NOSH_GUARD_EVIDENCE_DIR || '/var/lib/nosh-guard/evidence';
const controlSocketPath =
  process.env.NOSH_GUARD_CONTROL_SOCKET ||
  '/var/lib/nosh-guard/control/runner-proxy.sock';
const runtimeDir = '/run/nosh-guard';
const healthyPath = path.join(runtimeDir, 'healthy');
const gatewayEvidencePath = path.join(
  evidenceDir,
  'managed-gateway-counters.ndjson',
);
const gatewayEvidenceOverflowPath = path.join(
  evidenceDir,
  'managed-gateway-counters.overflow.json',
);
export { MANAGED_GATEWAY_EVIDENCE_MAX_BYTES };

let dnsmasq = new Map();
let proxyServer = null;
let activePolicies = new Map();
let activeFlowMarks = new Map();
let stopping = false;
let dirty = true;
let snapshotRequested = false;
let lastInputHash = null;
let counterEpoch = 0;
const counterSession = crypto.randomUUID();
let asynchronousFailure = null;

function timestampedDnsLog() {
  let buffered = '';
  return new Transform({
    transform(chunk, encoding, callback) {
      buffered += chunk.toString('utf8');
      const lines = buffered.split(/\r?\n/);
      buffered = lines.pop() || '';
      callback(
        null,
        lines
          .map(
            (line) =>
              `nosh-observed-at=${new Date().toISOString()} ${line}\n`,
          )
          .join(''),
      );
    },
    flush(callback) {
      callback(
        null,
        buffered
          ? `nosh-observed-at=${new Date().toISOString()} ${buffered}\n`
          : '',
      );
    },
  });
}

async function readOverflowMarker(overflowPath, runId, limitBytes) {
  let handle;
  try {
    handle = await fs.open(
      overflowPath,
      fsConstants.O_RDONLY | (fsConstants.O_NOFOLLOW || 0),
    );
    const stat = await handle.stat({ bigint: true });
    if (
      !stat.isFile()
      || stat.nlink !== 1n
      || (stat.mode & 0o7777n) !== 0o600n
      || stat.size > 64n * 1024n
    ) {
      throw new Error('marker is not a trusted 0600 file');
    }
    const document = JSON.parse(await handle.readFile('utf8'));
    return validateManagedDnsOverflowMarker(document, { runId, limitBytes });
  } catch (error) {
    if (error.code === 'ENOENT') {
      return null;
    }
    throw new Error(
      `managed DNS overflow marker is invalid for ${runId}: ${error.message}`,
      { cause: error },
    );
  } finally {
    await handle?.close().catch(() => {});
  }
}

async function writeOverflowMarker(overflowPath, marker) {
  const temporary = `${overflowPath}.${process.pid}.${crypto.randomUUID()}.tmp`;
  let handle;
  try {
    handle = await fs.open(
      temporary,
      fsConstants.O_WRONLY
        | fsConstants.O_CREAT
        | fsConstants.O_EXCL
        | (fsConstants.O_NOFOLLOW || 0),
      0o600,
    );
    await handle.writeFile(`${JSON.stringify(marker, null, 2)}\n`);
    await handle.sync();
    await handle.close();
    handle = null;
    await fs.rename(temporary, overflowPath);
    const directory = await fs.open(
      path.dirname(overflowPath),
      fsConstants.O_RDONLY
        | (fsConstants.O_DIRECTORY || 0)
        | (fsConstants.O_NOFOLLOW || 0),
    );
    try {
      await directory.sync();
    } finally {
      await directory.close();
    }
  } catch (error) {
    await handle?.close().catch(() => {});
    await fs.rm(temporary, { force: true }).catch(() => {});
    throw error;
  }
}

export async function appendManagedGatewayEvidence(content, options = {}) {
  const maximum = options.maxBytes ?? MANAGED_GATEWAY_EVIDENCE_MAX_BYTES;
  if (!Number.isSafeInteger(maximum) || maximum <= 0) {
    throw new TypeError('managed gateway evidence byte budget must be positive');
  }
  const targetPath = options.evidencePath || gatewayEvidencePath;
  const overflowPath = options.overflowPath || gatewayEvidenceOverflowPath;
  const buffer = Buffer.isBuffer(content) ? content : Buffer.from(String(content));
  try {
    await fs.lstat(overflowPath);
    const error = new Error(
      `managed gateway evidence is exhausted; remove ${overflowPath} only after archiving and clearing ${targetPath}`,
    );
    error.code = 'GUARD_GATEWAY_EVIDENCE_EXHAUSTED';
    throw error;
  } catch (error) {
    if (error.code !== 'ENOENT') {
      throw error;
    }
  }
  const handle = await fs.open(
    targetPath,
    fsConstants.O_WRONLY
      | fsConstants.O_APPEND
      | fsConstants.O_CREAT
      | (fsConstants.O_NOFOLLOW || 0),
    0o600,
  );
  try {
    const stat = await handle.stat();
    if (
      !stat.isFile()
      || stat.nlink !== 1
      || (stat.mode & 0o7777) !== 0o600
    ) {
      throw new Error('managed gateway evidence file is not a trusted 0600 file');
    }
    const requiredBytes = options.requireCapacity === true
      ? Math.max(1, buffer.length)
      : buffer.length;
    if (stat.size > maximum || requiredBytes > maximum - stat.size) {
      await writeOverflowMarker(overflowPath, {
        schemaVersion: 1,
        source: 'managed_gateway',
        type: 'evidence_overflow',
        observedAt: new Date().toISOString(),
        limitBytes: maximum,
        bytesWritten: stat.size,
        lostEvents: 1,
      });
      const error = new Error(
        `managed gateway evidence reached its ${maximum}-byte hard ceiling`,
      );
      error.code = 'GUARD_GATEWAY_EVIDENCE_EXHAUSTED';
      throw error;
    }
    if (buffer.length) {
      await handle.writeFile(buffer);
      await handle.sync();
    }
    return { bytesWritten: stat.size + buffer.length, maxBytes: maximum };
  } finally {
    await handle.close();
  }
}

export async function createManagedDnsEvidenceWriter(runId, options = {}) {
  const maximum = options.maxBytes ?? MANAGED_DNS_EVIDENCE_MAX_BYTES;
  if (!Number.isSafeInteger(maximum) || maximum <= 0) {
    throw new TypeError('managed DNS evidence byte budget must be positive');
  }
  const paths = managedDnsEvidencePaths(options.evidenceDir || evidenceDir, runId);
  const handle = await fs.open(
    paths.logPath,
    fsConstants.O_WRONLY
      | fsConstants.O_APPEND
      | (fsConstants.O_NOFOLLOW || 0),
  );
  let closePromise = null;
  let overflow = false;
  let overflowMarker = null;
  let bytesWritten = 0;
  try {
    const stat = await handle.stat();
    if (
      !stat.isFile()
      || stat.nlink !== 1
      || (stat.mode & 0o7777) !== 0o600
      || stat.size > maximum
    ) {
      throw new Error(`managed DNS evidence file is unsafe for ${runId}`);
    }
    bytesWritten = stat.size;
    const marker = await readOverflowMarker(paths.overflowPath, runId, maximum);
    if (marker) {
      if (marker.bytesWritten !== bytesWritten) {
        throw new Error(
          `managed DNS overflow marker byte count changed for ${runId}`,
        );
      }
      overflow = true;
      overflowMarker = marker;
    }
  } catch (error) {
    await handle.close();
    throw error;
  }

  const recordLoss = async (lossReason = 'byte_budget_exceeded') => {
    if (overflow) return;
    const marker = managedDnsOverflowMarker({
      runId,
      limitBytes: maximum,
      bytesWritten,
      lossReason,
    });
    await writeOverflowMarker(paths.overflowPath, marker);
    overflowMarker = marker;
    overflow = true;
  };
  const closeHandle = () => {
    if (!closePromise) {
      closePromise = (async () => {
        let syncError = null;
        try {
          await handle.sync();
        } catch (error) {
          syncError = error;
        }
        try {
          await handle.close();
        } catch (closeError) {
          if (!syncError) {
            throw closeError;
          }
        }
        if (syncError) {
          throw syncError;
        }
      })();
    }
    return closePromise;
  };
  const stream = new Writable({
    write(chunk, encoding, callback) {
      const buffer = Buffer.isBuffer(chunk)
        ? chunk
        : Buffer.from(chunk, encoding);
      (async () => {
        if (overflow || buffer.length === 0) return;
        const current = await handle.stat();
        if (!current.isFile() || current.size > maximum) {
          throw new Error(`managed DNS evidence file changed for ${runId}`);
        }
        bytesWritten = current.size;
        if (buffer.length > maximum - bytesWritten) {
          await recordLoss();
          return;
        }
        await handle.writeFile(buffer);
        bytesWritten += buffer.length;
      })().then(() => callback(), callback);
    },
    final(callback) {
      closeHandle().then(() => callback(), callback);
    },
    destroy(error, callback) {
      (async () => {
        let markerError = null;
        if (error && !overflow) {
          try {
            await recordLoss(
              error.code === 'MANAGED_DNS_FORCED_TERMINATION'
                ? 'forced_termination'
                : 'collector_failure',
            );
          } catch (lossError) {
            markerError = lossError;
          }
        }
        await closeHandle();
        if (markerError) {
          const fatal = new Error(
            `managed DNS evidence loss could not be persisted: ${markerError.message}`,
            { cause: markerError },
          );
          fatal.code = 'MANAGED_DNS_EVIDENCE_LOSS_UNRECORDED';
          throw fatal;
        }
      })().then(
        () => callback(error),
        (closeError) => callback(error || closeError),
      );
    },
  });
  return {
    stream,
    paths,
    maxBytes: maximum,
    get bytesWritten() {
      return bytesWritten;
    },
    get overflowed() {
      return overflow;
    },
    get overflowMarker() {
      return overflowMarker ? { ...overflowMarker } : null;
    },
  };
}

export function verifyPolicyDocumentHash(document) {
  if (
    !document ||
    typeof document !== 'object' ||
    Array.isArray(document) ||
    typeof document.policyHash !== 'string' ||
    !/^sha256:[a-f0-9]{64}$/.test(document.policyHash)
  ) {
    throw new Error('managed egress policy has no valid policyHash');
  }
  const unsigned = { ...document };
  const recordedHash = unsigned.policyHash;
  delete unsigned.policyHash;
  const computedHash = `sha256:${crypto
    .createHash('sha256')
    .update(JSON.stringify(unsigned))
    .digest('hex')}`;
  if (computedHash !== recordedHash) {
    throw new Error(
      `managed egress policy hash mismatch: expected ${recordedHash}, computed ${computedHash}`,
    );
  }
  return document;
}

function command(commandName, args, options = {}) {
  const result = spawnSync(commandName, args, {
    encoding: 'utf8',
    timeout: options.timeout || 10_000,
    input: options.input,
    stdio: ['pipe', 'pipe', 'pipe'],
  });
  if (result.status !== 0 && !options.allowFailure) {
    throw new Error(
      `${commandName} ${args.join(' ')} failed: ${
        result.error?.message || result.stderr || `status ${result.status}`
      }`,
    );
  }
  return result;
}

async function readPolicies() {
  const entries = await fs.readdir(policyDir);
  const policies = [];
  for (const entry of entries.sort()) {
    if (!entry.endsWith('.json')) {
      continue;
    }
    const document = JSON.parse(
      await fs.readFile(path.join(policyDir, entry), 'utf8'),
    );
    policies.push(verifyPolicyDocumentHash(document));
  }
  return policies;
}

async function readGrants() {
  try {
    const document = JSON.parse(await fs.readFile(grantsPath, 'utf8'));
    return Array.isArray(document.grants) ? document.grants : [];
  } catch (error) {
    if (error.code === 'ENOENT') {
      return [];
    }
    throw error;
  }
}

function networkLayout(policies) {
  const routes = JSON.parse(command('ip', ['-json', 'route', 'show', 'default']).stdout);
  const uplinkInterface = routes[0]?.dev;
  if (!uplinkInterface) {
    throw new Error('egress gateway has no default-route interface');
  }
  const addresses = JSON.parse(command('ip', ['-json', 'address', 'show']).stdout);
  const gatewayAddresses = new Set(policies.map((policy) => policy.gatewayIpv4));
  const interfaceByGateway = new Map();
  for (const entry of addresses) {
    for (const address of entry.addr_info || []) {
      if (entry.ifname && gatewayAddresses.has(address.local)) {
        interfaceByGateway.set(address.local, entry.ifname);
      }
    }
  }
  if (interfaceByGateway.size !== gatewayAddresses.size) {
    throw new Error('not every runner network is connected to the egress gateway');
  }
  return {
    uplinkInterface,
    internalInterfaces: [...new Set(interfaceByGateway.values())].sort(),
    interfaceByGateway,
  };
}

function applyNft(rules) {
  const exists =
    command('nft', ['list', 'table', 'inet', 'nosh_guard'], {
      allowFailure: true,
    }).status === 0;
  const transaction = exists
    ? `flush table inet nosh_guard\n${rules}`
    : rules;
  command('nft', ['--check', '-f', '-'], { input: transaction });
  command('nft', ['-f', '-'], { input: transaction });
}

async function enterFailClosedState(reason) {
  await fs.rm(healthyPath, { force: true });
  await fs.rm(path.join(evidenceDir, 'acks'), {
    recursive: true,
    force: true,
  });
  activePolicies = new Map();
  activeFlowMarks = new Map();
  const denyRules = [
    'table inet nosh_guard {',
    '  chain input {',
    '    type filter hook input priority filter; policy drop;',
    '    iifname "lo" accept',
    '  }',
    '  chain forward {',
    '    type filter hook forward priority filter; policy drop;',
    '  }',
    '  chain output {',
    '    type filter hook output priority filter; policy accept;',
    '  }',
    '}',
    '',
  ].join('\n');
  applyNft(denyRules);
  await stopDnsmasq();
  try {
    await appendManagedGatewayEvidence(
      `${JSON.stringify({
        schemaVersion: 1,
        source: 'managed_gateway',
        type: 'fail_closed',
        timestamp: new Date().toISOString(),
        error: reason,
      })}\n`,
    );
  } catch (error) {
    if (error.code !== 'GUARD_GATEWAY_EVIDENCE_EXHAUSTED') {
      throw error;
    }
    process.stderr.write(`${error.message}\n`);
  }
}

export function managedDnsSnapshotsForStoppedProcesses(processes) {
  return new Map(
    processes.map(({ runId, evidence }) => [
      runId,
      managedDnsEvidenceSnapshot({
        runId,
        limitBytes: evidence.maxBytes,
        bytesWritten: evidence.bytesWritten,
        overflowMarker: evidence.overflowMarker,
      }),
    ]),
  );
}

async function stopDnsmasqProcess({ child, evidence, loggingComplete }) {
  let killTimeout = null;
  let drainTimeout = null;
  const alreadyExited = child.exitCode != null || child.signalCode != null;
  const exited = alreadyExited
    ? Promise.resolve()
    : new Promise((resolve) => {
        child.once('exit', () => {
          clearTimeout(killTimeout);
          resolve();
        });
        killTimeout = setTimeout(() => {
          const error = new Error(
            'managed DNS required forced termination before evidence drain',
          );
          error.code = 'MANAGED_DNS_FORCED_TERMINATION';
          evidence.stream.destroy(error);
          child.kill('SIGKILL');
        }, 3_000);
        child.kill('SIGTERM');
      });
  const timedOut = new Promise((_resolve, reject) => {
    drainTimeout = setTimeout(() => {
      const error = new Error(
        'managed DNS did not stop before evidence drain timeout',
      );
      child.kill('SIGKILL');
      evidence.stream.destroy(error);
      reject(error);
    }, 5_000);
  });
  try {
    await Promise.race([
      Promise.all([exited, loggingComplete]),
      timedOut,
    ]);
  } catch (error) {
    child.kill('SIGKILL');
    evidence.stream.destroy(error);
    throw error;
  } finally {
    clearTimeout(killTimeout);
    clearTimeout(drainTimeout);
  }
}

async function stopDnsmasq() {
  if (!dnsmasq.size) {
    return new Map();
  }
  const processes = [...dnsmasq.entries()].map(
    ([runId, processState]) => ({ runId, ...processState }),
  );
  dnsmasq = new Map();
  await Promise.all(processes.map(stopDnsmasqProcess));
  return managedDnsSnapshotsForStoppedProcesses(processes);
}

function attachDnsEvidence(child, runId, evidence) {
  const stdoutLog = child.stdout.pipe(timestampedDnsLog());
  const stderrLog = child.stderr.pipe(timestampedDnsLog());
  stdoutLog.pipe(evidence.stream, { end: false });
  stderrLog.pipe(evidence.stream, { end: false });
  const sourcesComplete = Promise.all([
    finished(stdoutLog),
    finished(stderrLog),
  ]).then(
    () => {
      evidence.stream.end();
    },
    (error) => {
      evidence.stream.destroy(error);
      throw error;
    },
  );
  const loggingComplete = Promise.all([
    sourcesComplete,
    finished(evidence.stream),
  ]).catch((error) => {
    asynchronousFailure ||= new Error(
      `managed DNS evidence failed for ${runId}: ${error.message}`,
      { cause: error },
    );
    throw asynchronousFailure;
  });
  loggingComplete.catch(() => {});
  return loggingComplete;
}

async function startDnsmasq(policies, grants, layout) {
  await stopDnsmasq();
  for (const policy of policies) {
    const internalInterface = layout.interfaceByGateway.get(
      policy.gatewayIpv4,
    );
    if (!internalInterface) {
      throw new Error(
        `managed DNS has no interface for ${policy.gatewayIpv4}`,
      );
    }
    const configId = crypto
      .createHash('sha256')
      .update(policy.runId)
      .digest('hex')
      .slice(0, 16);
    const configPath = path.join(runtimeDir, `dnsmasq-${configId}.conf`);
    const pidFile = path.join(runtimeDir, `dnsmasq-${configId}.pid`);
    const configWithPid = generateDnsmasqConfig([policy], grants, {
      internalInterfaces: [internalInterface],
      listenAddress: policy.gatewayIpv4,
      pidFile,
      strictDomains: requiresStrictManagedDns(policy.mode),
      uplinkInterface: layout.uplinkInterface,
    });
    await fs.writeFile(configPath, configWithPid, { mode: 0o600 });
    command('dnsmasq', ['--test', `--conf-file=${configPath}`]);
    const evidence = await createManagedDnsEvidenceWriter(policy.runId);
    const child = spawn(
      'dnsmasq',
      ['--keep-in-foreground', `--conf-file=${configPath}`, '--log-facility=-'],
      {
        stdio: ['ignore', 'pipe', 'pipe'],
      },
    );
    const loggingComplete = attachDnsEvidence(child, policy.runId, evidence);
    dnsmasq.set(policy.runId, {
      runId: policy.runId,
      child,
      evidence,
      loggingComplete,
    });
    await new Promise((resolve, reject) => {
      child.once('spawn', resolve);
      child.once('error', reject);
    });
    await new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        child.off('exit', onStartupExit);
        resolve();
      }, 100);
      const onStartupExit = (status, signal) => {
        clearTimeout(timer);
        reject(
          new Error(
            `managed DNS for ${policy.runId} exited during startup: status=${status} signal=${signal}`,
          ),
        );
      };
      child.once('exit', onStartupExit);
    });
    if (child.exitCode != null || child.signalCode != null) {
      throw new Error(
        `managed DNS for ${policy.runId} was not live after startup`,
      );
    }
    child.once('exit', (status, signal) => {
      if (!stopping && dnsmasq.get(policy.runId)?.child === child) {
        process.stderr.write(
          `managed DNS for ${policy.runId} exited unexpectedly: status=${status} signal=${signal}\n`,
        );
        process.exitCode = 1;
        stopping = true;
      }
    });
  }
}

export function clearConnections(policies, execute = command) {
  for (const policy of policies) {
    execute('conntrack', ['-D', '-s', policy.sourceIpv4], {
      allowFailure: true,
    });
    execute('conntrack', ['-D', '-d', policy.sourceIpv4], {
      allowFailure: true,
    });
  }
}

async function inputHash() {
  const hash = crypto.createHash('sha256');
  for (const entry of (await fs.readdir(policyDir)).sort()) {
    if (entry.endsWith('.json')) {
      hash.update(entry);
      hash.update(await fs.readFile(path.join(policyDir, entry)));
    }
  }
  try {
    const grantsSource = await fs.readFile(grantsPath);
    hash.update(grantsSource);
    const document = JSON.parse(grantsSource.toString('utf8'));
    const activeGrantIds = (document.grants || [])
      .filter(
        (grant) =>
          !grant.revokedAt &&
          Number.isFinite(Date.parse(grant.expiresAt)) &&
          Date.parse(grant.expiresAt) > Date.now(),
      )
      .map((grant) => grant.id)
      .sort();
    hash.update(JSON.stringify(activeGrantIds));
  } catch (error) {
    if (error.code !== 'ENOENT') {
      throw error;
    }
  }
  return hash.digest('hex');
}

async function reload() {
  const policies = await readPolicies();
  const grants = await readGrants();
  const layout = networkLayout(policies);
  const nft = generateNftRules(policies, grants, layout);
  const nextFlowMarks = new Map(
    policies.map((policy) => [
      policy.runId,
      egressPolicyFlowMark(policy, grants),
    ]),
  );
  if (activePolicies.size) {
    await recordCounters([...activePolicies.values()]);
  }
  applyNft(nft);
  const nextPolicies = new Map(
    policies.map((policy) => [policy.runId, policy]),
  );
  const changedPolicies = new Map();
  for (const [runId, previous] of activePolicies) {
    const next = nextPolicies.get(runId);
    if (
      !next
      || next.sourceIpv4 !== previous.sourceIpv4
      || nextFlowMarks.get(runId) !== activeFlowMarks.get(runId)
    ) {
      changedPolicies.set(previous.sourceIpv4, previous);
      if (next) changedPolicies.set(next.sourceIpv4, next);
    }
  }
  for (const [runId, next] of nextPolicies) {
    if (!activePolicies.has(runId)) {
      changedPolicies.set(next.sourceIpv4, next);
    }
  }
  clearConnections([...changedPolicies.values()]);
  await startDnsmasq(policies, grants, layout);
  counterEpoch += 1;
  activePolicies = nextPolicies;
  activeFlowMarks = nextFlowMarks;
  const acknowledgementDir = path.join(evidenceDir, 'acks');
  await fs.mkdir(acknowledgementDir, { recursive: true, mode: 0o700 });
  for (const policy of policies) {
    const acknowledgement = {
      schemaVersion: 1,
      source: 'managed_gateway',
      type: 'policy_attestation',
      timestamp: new Date().toISOString(),
      runId: policy.runId,
      mode: policy.mode,
      profileRevision: policy.profileRevision,
      policyHash: policy.policyHash,
      approvalHash: policy.approvalHash || null,
      profilePolicyHash: policy.profilePolicyHash || null,
      imageDigest: policy.imageDigest || null,
      workspaceKey: policy.workspaceKey || null,
      networkName: policy.networkName,
      sourceIpv4: policy.sourceIpv4,
      gatewayIpv4: policy.gatewayIpv4,
    };
    const destination = path.join(
      acknowledgementDir,
      `${policy.runId}.json`,
    );
    const temporary = `${destination}.${process.pid}.tmp`;
    await fs.writeFile(
      temporary,
      `${JSON.stringify(acknowledgement, null, 2)}\n`,
      { mode: 0o600 },
    );
    await fs.rename(temporary, destination);
  }
  const activeAcknowledgements = new Set(
    policies.map((policy) => `${policy.runId}.json`),
  );
  for (const entry of await fs.readdir(acknowledgementDir)) {
    if (entry.endsWith('.json') && !activeAcknowledgements.has(entry)) {
      await fs.rm(path.join(acknowledgementDir, entry), { force: true });
    }
  }
  if (policies.length) {
    await appendManagedGatewayEvidence(
      policies
        .map((policy) =>
          JSON.stringify({
            schemaVersion: 1,
            source: 'managed_gateway',
            type: 'policy_reload',
            timestamp: new Date().toISOString(),
            runId: policy.runId,
            mode: policy.mode,
            profileRevision: policy.profileRevision,
            policyHash: policy.policyHash,
          }),
        )
        .join('\n') + '\n',
    );
  }
  await fs.writeFile(healthyPath, `${new Date().toISOString()}\n`, {
    mode: 0o600,
  });
}

function proxyPolicy(request) {
  const value = request.headers['x-nosh-guard-upstream-run'];
  const runId = value;
  if (
    typeof runId !== 'string' ||
    !/^[A-Za-z0-9_.-]+$/.test(runId) ||
    !activePolicies.has(runId)
  ) {
    return null;
  }
  return activePolicies.get(runId);
}

function proxyIdentityHeaders(headers) {
  const principal = headers['x-nosh-guard-principal'];
  const agent = headers['x-nosh-guard-agent'];
  if (
    typeof principal !== 'string' ||
    !/^[A-Za-z0-9_.-]+$/.test(principal) ||
    (agent != null && typeof agent !== 'string')
  ) {
    throw new TypeError('runner proxy identity headers are invalid');
  }
  return {
    'x-nosh-guard-principal': principal,
    'x-nosh-guard-agent': agent || '',
  };
}

function runnerProxyHeaders(headers, policy) {
  if (
    typeof headers['x-nosh-guard-upstream-run'] !== 'string' ||
    headers['x-nosh-guard-upstream-run'] !== policy.runId
  ) {
    throw new TypeError('runner proxy request is not bound to the selected run');
  }
  const publicOrigin = normalizeGatewayPublicOrigin(policy.publicOrigin);
  validatePublicRequestHeaders(headers, publicOrigin, {
    requireForwarded: true,
  });
  return canonicalProxyHeaders(
    headers,
    publicOrigin,
    proxyIdentityHeaders(headers),
  );
}

function proxyError(response, statusCode, message) {
  const body = Buffer.from(
    `${JSON.stringify({ error: { code: 'GUARD_RUNNER_PROXY', message } })}\n`,
  );
  response.writeHead(statusCode, {
    'content-type': 'application/json',
    'content-length': body.length,
    'cache-control': 'no-store',
  });
  response.end(body);
}

async function startRunnerProxy() {
  await fs.mkdir(path.dirname(controlSocketPath), {
    recursive: true,
    mode: 0o700,
  });
  try {
    const stat = await fs.lstat(controlSocketPath);
    if (!stat.isSocket()) {
      throw new Error(
        `refusing to replace non-socket runner proxy path: ${controlSocketPath}`,
      );
    }
    await fs.unlink(controlSocketPath);
  } catch (error) {
    if (error.code !== 'ENOENT') {
      throw error;
    }
  }
  proxyServer = http.createServer((request, response) => {
    try {
      const policy = proxyPolicy(request);
      if (!policy) {
        proxyError(response, 403, 'run is not active on the managed gateway');
        return;
      }
      const upstream = http.request(
        {
          host: policy.sourceIpv4,
          port: 3000,
          method: request.method,
          path: request.url,
          headers: runnerProxyHeaders(request.headers, policy),
        },
        (upstreamResponse) => {
          response.writeHead(
            upstreamResponse.statusCode || 502,
            upstreamResponse.headers,
          );
          upstreamResponse.pipe(response);
        },
      );
      upstream.on('error', (error) => proxyError(response, 502, error.message));
      request.pipe(upstream);
    } catch (error) {
      proxyError(response, 403, error.message);
    }
  });
  proxyServer.on('upgrade', (request, clientSocket, head) => {
    try {
      const policy = proxyPolicy(request);
      if (!policy) {
        throw new Error('run is not active on the managed gateway');
      }
      if (
        typeof request.headers.upgrade !== 'string' ||
        request.headers.upgrade.toLowerCase() !== 'websocket'
      ) {
        throw new Error('only WebSocket upgrades are allowed');
      }
      const headers = runnerProxyHeaders(request.headers, policy);
      const upstream = net.connect(3000, policy.sourceIpv4, () => {
        headers.connection = 'Upgrade';
        headers.upgrade = 'websocket';
        const headerLines = Object.entries(headers).flatMap(([name, value]) =>
          (Array.isArray(value) ? value : [value]).map(
            (entry) => `${name}: ${entry}`,
          ),
        );
        upstream.write(
          `${request.method} ${request.url} HTTP/${request.httpVersion}\r\n${headerLines.join(
            '\r\n',
          )}\r\n\r\n`,
        );
        if (head?.length) {
          upstream.write(head);
        }
        clientSocket.pipe(upstream).pipe(clientSocket);
      });
      upstream.on('error', () => clientSocket.destroy());
    } catch {
      clientSocket.end('HTTP/1.1 403 Forbidden\r\nConnection: close\r\n\r\n');
    }
  });
  await new Promise((resolve, reject) => {
    proxyServer.once('error', reject);
    proxyServer.listen(controlSocketPath, resolve);
  });
  await fs.chmod(controlSocketPath, 0o600);
}

function countersForPolicy(ruleset, policy) {
  const counters = [];
  for (const entry of ruleset?.nftables || []) {
    const rule = entry?.rule;
    if (!rule || !containsExactValue(rule.expr || [], policy.sourceIpv4)) {
      continue;
    }
    const counter = (rule.expr || []).find((expression) => expression?.counter)
      ?.counter;
    if (!counter) {
      continue;
    }
    counters.push({
      handle: rule.handle ?? null,
      comment: rule.comment || null,
      packets: nonnegativeNumber(counter.packets),
      bytes: nonnegativeNumber(counter.bytes),
    });
  }
  return counters;
}

function containsExactValue(value, expected) {
  if (Array.isArray(value)) {
    return value.some((entry) => containsExactValue(entry, expected));
  }
  if (value && typeof value === 'object') {
    return Object.values(value).some((entry) =>
      containsExactValue(entry, expected),
    );
  }
  return value === expected;
}

function nonnegativeNumber(value) {
  const parsed = Number(value ?? 0);
  return Number.isFinite(parsed) && parsed >= 0 ? parsed : 0;
}

function terminalCounterComment(policy) {
  const runHash = crypto
    .createHash('sha256')
    .update(String(policy.runId))
    .digest('hex')
    .slice(0, 12);
  let suffix;
  switch (egressModeBehavior(policy.mode)) {
    case 'record-allow':
      suffix = `${policy.mode}-observed`;
      break;
    case 'would-deny-allow':
      suffix = `${policy.mode}-would-deny`;
      break;
    case 'allowlist-drop':
      suffix = `${policy.mode}-deny`;
      break;
    default:
      throw new TypeError(`unsupported egress mode: ${policy.mode}`);
  }
  return `nosh:${runHash}:${suffix}`;
}

async function recordCounters(policyDocuments = null, options = {}) {
  const policies = policyDocuments || await readPolicies();
  const result = command('nft', ['-json', 'list', 'table', 'inet', 'nosh_guard'], {
    allowFailure: true,
  });
  if (!policies.length) {
    return;
  }
  let ruleset = null;
  let parseError = null;
  if (result.status === 0) {
    try {
      ruleset = JSON.parse(result.stdout);
    } catch (error) {
      parseError = error.message;
    }
  }
  const recordedAt = new Date().toISOString();
  const records = policies.map((policy) => {
    const counters = ruleset ? countersForPolicy(ruleset, policy) : [];
    const behavior = egressModeBehavior(policy.mode);
    const terminalComment = terminalCounterComment(policy);
    const terminalCounterPresent =
      terminalComment !== null &&
      counters.some((entry) => entry.comment === terminalComment);
    const complete =
      result.status === 0 &&
      !parseError &&
      terminalCounterPresent;
    const wouldDenyCount = counters
      .filter(
        (entry) =>
          behavior === 'would-deny-allow' &&
          entry.comment === terminalComment,
      )
      .reduce((total, entry) => total + entry.packets, 0);
    const deniedCount = counters
      .filter(
        (entry) =>
          entry.comment?.endsWith(':invariant-deny') ||
          entry.comment?.endsWith(':dns-bypass-deny') ||
          (behavior === 'allowlist-drop' &&
            entry.comment === terminalComment),
      )
      .reduce((total, entry) => total + entry.packets, 0);
    return {
      schemaVersion: 1,
      source: 'managed_gateway',
      type: 'counter_snapshot',
      timestamp: recordedAt,
      runId: policy.runId,
      mode: policy.mode,
      profileRevision: policy.profileRevision,
      policyHash: policy.policyHash,
      approvalHash: policy.approvalHash || null,
      profilePolicyHash: policy.profilePolicyHash || null,
      counterEpoch,
      counterSession,
      complete,
      decision:
        wouldDenyCount > 0
          ? 'would-deny'
          : deniedCount > 0
            ? 'denied'
            : 'observed',
      wouldDenyCount,
      deniedCount,
      counters,
      error:
        result.status === 0
          ? parseError ||
            (terminalCounterPresent
              ? null
              : `missing terminal counter ${terminalComment || 'for invalid mode'}`)
          : String(result.stderr || '').trim(),
    };
  });
  await appendManagedGatewayEvidence(
    records.map((record) => JSON.stringify(record)).join('\n') + '\n',
  );
  if (options.publishSnapshotAttestations !== true) {
    return records;
  }
  const requestDir = path.join(evidenceDir, 'snapshot-requests');
  const snapshotDir = path.join(evidenceDir, 'snapshots');
  await fs.mkdir(snapshotDir, { recursive: true, mode: 0o700 });
  for (const record of records) {
    let request;
    try {
      request = JSON.parse(
        await fs.readFile(path.join(requestDir, `${record.runId}.json`), 'utf8'),
      );
    } catch (error) {
      if (error.code === 'ENOENT' || error instanceof SyntaxError) {
        continue;
      }
      throw error;
    }
    if (
      request?.runId !== record.runId ||
      request?.policyHash !== record.policyHash ||
      typeof request?.nonce !== 'string' ||
      !/^[a-f0-9-]{16,64}$/.test(request.nonce)
    ) {
      continue;
    }
    let managedDnsEvidence = null;
    let managedDnsError = null;
    try {
      managedDnsEvidence = validateManagedDnsEvidenceSnapshot(
        options.managedDnsEvidenceSnapshots?.get(record.runId),
        {
          runId: record.runId,
          limitBytes: MANAGED_DNS_EVIDENCE_MAX_BYTES,
        },
      );
      if (managedDnsEvidence.overflowed) {
        managedDnsError = 'managed DNS evidence byte budget exceeded';
      }
    } catch (error) {
      managedDnsError = `managed DNS evidence snapshot failed: ${error.message}`;
    }
    const serializedRecord = JSON.stringify(record);
    const attestation = {
      schemaVersion: 1,
      source: 'managed_gateway',
      type: 'counter_snapshot_attestation',
      runId: record.runId,
      policyHash: record.policyHash,
      nonce: request.nonce,
      requestedAt: request.requestedAt,
      recordedAt,
      complete:
        record.complete
        && managedDnsEvidence !== null
        && !managedDnsEvidence.overflowed,
      evidenceRecordHash: `sha256:${crypto
        .createHash('sha256')
        .update(serializedRecord)
        .digest('hex')}`,
      managedDnsEvidence,
      error: record.error || managedDnsError,
    };
    const destination = path.join(snapshotDir, `${record.runId}.json`);
    const temporary = `${destination}.${process.pid}.tmp`;
    await fs.writeFile(
      temporary,
      `${JSON.stringify(attestation, null, 2)}\n`,
      { mode: 0o600 },
    );
    await fs.rename(temporary, destination);
  }
  return records;
}

export async function drainManagedDnsBeforeSnapshot(options = {}) {
  const policies = options.policies || await readPolicies();
  const grants = options.grants || await readGrants();
  const layout = options.layout || networkLayout(policies);
  const stopResolver = options.stopResolver || stopDnsmasq;
  const startResolver = options.startResolver || startDnsmasq;
  const captureCounters = options.captureCounters || recordCounters;
  const managedDnsEvidenceSnapshots = await stopResolver();
  await startResolver(policies, grants, layout);
  return captureCounters(policies, {
    publishSnapshotAttestations: true,
    managedDnsEvidenceSnapshots,
  });
}

async function main() {
  await Promise.all([
    fs.mkdir(policyDir, { recursive: true }),
    fs.mkdir(evidenceDir, { recursive: true }),
    fs.mkdir(runtimeDir, { recursive: true }),
  ]);
  await startRunnerProxy();
  process.on('SIGHUP', () => {
    dirty = true;
  });
  process.on('SIGUSR1', () => {
    snapshotRequested = true;
  });
  const shutdown = () => {
    stopping = true;
  };
  process.on('SIGINT', shutdown);
  process.on('SIGTERM', shutdown);

  let lastCounters = 0;
  while (!stopping) {
    try {
      if (asynchronousFailure) {
        const failure = asynchronousFailure;
        asynchronousFailure = null;
        throw failure;
      }
      if (lastInputHash === null) {
        await appendManagedGatewayEvidence('', { requireCapacity: true });
      }
      const currentHash = await inputHash();
      if (dirty || currentHash !== lastInputHash) {
        await reload();
        lastInputHash = currentHash;
        dirty = false;
      }
      if (snapshotRequested) {
        snapshotRequested = false;
        await drainManagedDnsBeforeSnapshot();
        lastCounters = Date.now();
      } else if (Date.now() - lastCounters >= 10_000) {
        await recordCounters();
        lastCounters = Date.now();
      }
    } catch (error) {
      process.stderr.write(`managed egress reload failed: ${error.message}\n`);
      try {
        await enterFailClosedState(error.message);
        if (
          error.code === 'GUARD_GATEWAY_EVIDENCE_EXHAUSTED'
          || error.code === 'MANAGED_DNS_EVIDENCE_LOSS_UNRECORDED'
        ) {
          stopping = true;
          process.exitCode = 1;
        } else {
          dirty = true;
          lastInputHash = null;
        }
      } catch (failClosedError) {
        process.stderr.write(
          `managed egress could not install deny-all state: ${failClosedError.message}\n`,
        );
        stopping = true;
        process.exitCode = 1;
      }
    }
    await new Promise((resolve) => setTimeout(resolve, 1_000));
  }
  await stopDnsmasq();
  if (proxyServer) {
    await new Promise((resolve) => proxyServer.close(resolve));
  }
  await fs.rm(controlSocketPath, { force: true });
}

if (import.meta.url === `file://${process.argv[1]}`) {
  main().catch((error) => {
    process.stderr.write(`nosh-guard-egress: ${error.stack || error.message}\n`);
    process.exitCode = 1;
  });
}

export { proxyIdentityHeaders, runnerProxyHeaders };
