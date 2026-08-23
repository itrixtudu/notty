#!/usr/bin/env node

import {
  appendFileSync,
  closeSync,
  existsSync,
  mkdirSync,
  openSync,
  readFileSync,
  readdirSync,
  renameSync,
  rmSync,
  unlinkSync,
  writeFileSync
} from 'node:fs';
import { createHash } from 'node:crypto';
import path from 'node:path';
import process from 'node:process';
import { fileURLToPath } from 'node:url';

const BLOCKED_EXIT_CODE = 3;
const DEFAULT_TIMEOUT_MS = 120_000;
const POLL_INTERVAL_MS = 100;

function usage() {
  process.stderr.write([
    'usage:',
    '  node durdraw-art-lock.mjs acquire <agent> <target>',
    '  node durdraw-art-lock.mjs verify <agent> <target>',
    '  node durdraw-art-lock.mjs release <agent> <target>',
    '  node durdraw-art-lock.mjs ready <agent>',
    '  node durdraw-art-lock.mjs begin-shared <agent> <target> [timeout-ms]',
    '  node durdraw-art-lock.mjs finish <agent>',
    '',
  ].join('\n'));
}

function fail(message, exitCode = 1) {
  process.stderr.write(`art-lock: ${message}\n`);
  process.exitCode = exitCode;
}

function workspaceRoot() {
  return path.resolve(process.env.ART_WORKSPACE || process.cwd());
}

function normalizeAgent(value) {
  const agent = String(value || '').trim();
  if (!/^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$/.test(agent)) {
    throw new Error(`invalid agent id: ${JSON.stringify(agent)}`);
  }
  return agent;
}

function normalizeTarget(value) {
  const raw = String(value || '').trim().replaceAll('\\', '/');
  const normalized = path.posix.normalize(raw);
  if (
    !normalized
    || normalized === '.'
    || normalized.startsWith('/')
    || normalized === '..'
    || normalized.startsWith('../')
    || normalized.includes('/../')
  ) {
    throw new Error(`target must be a safe relative path: ${JSON.stringify(raw)}`);
  }
  return normalized;
}

function positiveInteger(value, fallback) {
  const parsed = Number.parseInt(String(value || ''), 10);
  return Number.isSafeInteger(parsed) && parsed > 0 ? parsed : fallback;
}

function coordinationPath(...parts) {
  return path.join(workspaceRoot(), 'coordination', ...parts);
}

function lockPath(target) {
  return path.join(workspaceRoot(), 'agents', 'locks', ...target.split('/'));
}

function intentPath(agent) {
  return path.join(workspaceRoot(), 'agents', 'active', `${agent}.intent`);
}

function ensureLayout() {
  for (const directory of [
    path.join(workspaceRoot(), 'agents', 'active'),
    path.join(workspaceRoot(), 'agents', 'leases'),
    path.join(workspaceRoot(), 'agents', 'locks'),
    coordinationPath(),
    coordinationPath('ready'),
    coordinationPath('blocked')
  ]) {
    mkdirSync(directory, { recursive: true });
  }
}

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function readOwner(target) {
  try {
    return readFileSync(lockPath(target), 'utf8').split(/\r?\n/, 1)[0].trim();
  } catch {
    return '';
  }
}

function appendEvent(action, agent, target = '', extra = {}) {
  const event = {
    timestamp: new Date().toISOString(),
    action,
    agent,
    ...(target ? { target } : {}),
    ...extra
  };
  // One O_APPEND write keeps each short JSONL event intact across helpers
  // without a crash-prone secondary guard lock.
  appendFileSync(
    coordinationPath('lock-events.jsonl'),
    `${JSON.stringify(event)}\n`,
    { encoding: 'utf8', mode: 0o600 }
  );
}

function targetSnapshot(target) {
  const destination = path.join(workspaceRoot(), ...target.split('/'));
  if (!existsSync(destination)) {
    return { exists: false, bytes: 0, sha256: null };
  }
  const data = readFileSync(destination);
  return {
    exists: true,
    bytes: data.length,
    sha256: createHash('sha256').update(data).digest('hex')
  };
}

function leasePath(agent) {
  return path.join(workspaceRoot(), 'agents', 'leases', `${agent}.json`);
}

function writeLease(agent, target, before) {
  const destination = leasePath(agent);
  writeFileSync(
    destination,
    `${JSON.stringify({ agent, target, before })}\n`,
    { encoding: 'utf8', flag: 'wx', mode: 0o600 }
  );
}

function readLease(agent, target) {
  let lease;
  try {
    lease = JSON.parse(readFileSync(leasePath(agent), 'utf8'));
  } catch {
    throw new Error(`missing or invalid mutation lease for ${agent}`);
  }
  if (lease.agent !== agent || lease.target !== target || !lease.before) {
    throw new Error(`mutation lease mismatch for ${agent}: ${target}`);
  }
  return lease;
}

function snapshotChanged(before, after) {
  return before.exists !== after.exists
    || before.bytes !== after.bytes
    || before.sha256 !== after.sha256;
}

function writeIntent(agent, state, target = '', summary = '') {
  ensureLayout();
  const destination = intentPath(agent);
  const temporary = `${destination}.${process.pid}.tmp`;
  const lines = [
    `agent_id: ${agent}`,
    `state: ${state}`,
    `lock: ${target || '-'}`,
    'priority: normal',
    `requires_coordination: ${state === 'waiting_lock' ? 'true' : 'false'}`,
    'requires_human: false',
    `timestamp: ${new Date().toISOString()}`,
    `summary: ${summary || state}`,
    ''
  ];
  writeFileSync(temporary, lines.join('\n'), { encoding: 'utf8', mode: 0o600 });
  renameSync(temporary, destination);
}

function recordBlocked(agent, target, owner) {
  ensureLayout();
  const targetDirectory = coordinationPath(
    'blocked',
    Buffer.from(target).toString('base64url')
  );
  mkdirSync(targetDirectory, { recursive: true });
  writeIntent(agent, 'waiting_lock', target, `waiting for lock owned by ${owner || 'unknown'}`);
  appendEvent('blocked', agent, target, { owner: owner || null });
  // Publish the contention marker only after the corresponding audit event.
  writeFileSync(
    path.join(targetDirectory, agent),
    `${owner || 'unknown'}\n`,
    { encoding: 'utf8', mode: 0o600 }
  );
}

function tryAcquire(agent, target, options = {}) {
  ensureLayout();
  const destination = lockPath(target);
  mkdirSync(path.dirname(destination), { recursive: true });

  try {
    const descriptor = openSync(destination, 'wx', 0o600);
    try {
      writeFileSync(descriptor, `${agent}\n`, 'utf8');
    } finally {
      closeSync(descriptor);
    }
  } catch (error) {
    if (error?.code !== 'EEXIST') {
      throw error;
    }
    const owner = readOwner(target);
    if (options.recordBlocked !== false) {
      recordBlocked(agent, target, owner);
    }
    return { acquired: false, owner };
  }

  try {
    const owner = readOwner(target);
    if (owner !== agent) {
      throw new Error(`lock ownership verification failed after acquire: ${target}`);
    }
    const before = targetSnapshot(target);
    writeLease(agent, target, before);
    writeIntent(agent, 'working', target, `editing ${target}`);
    appendEvent('acquired', agent, target, {
      role: options.role || null,
      before
    });
    return { acquired: true, owner: agent };
  } catch (error) {
    if (readOwner(target) === agent) {
      rmSync(lockPath(target), { force: true });
    }
    rmSync(leasePath(agent), { force: true });
    throw error;
  }
}

function verify(agent, target) {
  const owner = readOwner(target);
  if (owner !== agent) {
    throw new Error(
      `lock verification failed for ${target}: expected ${agent}, found ${owner || 'unlocked'}`
    );
  }
  appendEvent('verified', agent, target);
}

function release(agent, target, options = {}) {
  verify(agent, target);
  const lease = readLease(agent, target);
  const after = targetSnapshot(target);
  if (!options.allowUnchanged && !snapshotChanged(lease.before, after)) {
    throw new Error(`refusing to release unchanged art target: ${target}`);
  }
  appendEvent('releasing', agent, target, {
    role: options.role || null,
    before: lease.before,
    after,
    changed: snapshotChanged(lease.before, after)
  });
  unlinkSync(lockPath(target));
  rmSync(leasePath(agent), { force: true });
  appendEvent(options.action || 'released', agent, target, {
    role: options.role || null,
    after
  });
  writeIntent(agent, 'idle', '', `released ${target}`);
}

function assertPersonalReady(agent) {
  const target = `${agent}.ans`;
  const snapshot = targetSnapshot(target);
  if (!snapshot.exists || snapshot.bytes === 0) {
    throw new Error(`personal art is missing or empty: ${target}`);
  }
  if (readOwner(target)) {
    throw new Error(`personal art lock is still held: ${target}`);
  }
  if (existsSync(leasePath(agent))) {
    throw new Error(`agent still has an active mutation lease: ${agent}`);
  }
  let events = [];
  try {
    events = readFileSync(coordinationPath('lock-events.jsonl'), 'utf8')
      .split(/\r?\n/)
      .filter(Boolean)
      .map((line) => JSON.parse(line));
  } catch {
    throw new Error(`cannot verify lock history for ${target}`);
  }
  const acquired = events.findIndex(
    (event) => event.action === 'acquired'
      && event.agent === agent
      && event.target === target
  );
  const released = events.findIndex(
    (event, index) => index > acquired
      && event.action === 'released'
      && event.agent === agent
      && event.target === target
  );
  if (acquired < 0 || released < 0) {
    throw new Error(`personal art has no completed lock lease: ${target}`);
  }
}

function blockedMarkerExists(target, excludingAgent) {
  const directory = coordinationPath(
    'blocked',
    Buffer.from(target).toString('base64url')
  );
  if (!existsSync(directory)) {
    return false;
  }
  return readdirSync(directory).some((name) => name !== excludingAgent);
}

async function waitFor(predicate, timeoutMs, description) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    if (predicate()) {
      return;
    }
    await sleep(POLL_INTERVAL_MS);
  }
  throw new Error(`timed out waiting for ${description}`);
}

async function beginShared(agent, target, timeoutMs) {
  ensureLayout();
  await waitFor(
    () => existsSync(coordinationPath('go')),
    timeoutMs,
    'the collaboration barrier'
  );

  const firstAttempt = tryAcquire(agent, target, {
    role: 'first',
    recordBlocked: true
  });

  if (firstAttempt.acquired) {
    try {
      await waitFor(
        () => blockedMarkerExists(target, agent),
        timeoutMs,
        'the peer to record lock contention'
      );
    } catch (error) {
      if (readOwner(target) === agent) {
        release(agent, target, {
          action: 'released_after_timeout',
          role: 'first',
          allowUnchanged: true
        });
      }
      throw error;
    }
    appendEvent('handoff_ready', agent, target, { role: 'first' });
    process.stdout.write(`${JSON.stringify({ role: 'first', owner: agent, target })}\n`);
    return;
  }

  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    await sleep(POLL_INTERVAL_MS + Math.floor(Math.random() * POLL_INTERVAL_MS));
    const retry = tryAcquire(agent, target, {
      role: 'second',
      recordBlocked: false
    });
    if (retry.acquired) {
      appendEvent('handoff_complete', agent, target, { role: 'second' });
      process.stdout.write(`${JSON.stringify({ role: 'second', owner: agent, target })}\n`);
      return;
    }
  }

  throw new Error(`timed out waiting to acquire shared lock: ${target}`);
}

async function main(argv = process.argv.slice(2)) {
  const [command, rawAgent, rawTarget, rawTimeout] = argv;
  if (!command || command === '-h' || command === '--help') {
    usage();
    return;
  }

  ensureLayout();
  const agent = normalizeAgent(rawAgent);

  switch (command) {
    case 'acquire': {
      const target = normalizeTarget(rawTarget);
      const result = tryAcquire(agent, target);
      if (!result.acquired) {
        fail(`lock busy: ${target} (owner=${result.owner || 'unknown'})`, BLOCKED_EXIT_CODE);
        return;
      }
      process.stdout.write(`${JSON.stringify({ acquired: true, agent, target })}\n`);
      return;
    }
    case 'verify': {
      const target = normalizeTarget(rawTarget);
      verify(agent, target);
      process.stdout.write(`${JSON.stringify({ verified: true, agent, target })}\n`);
      return;
    }
    case 'release': {
      const target = normalizeTarget(rawTarget);
      release(agent, target);
      process.stdout.write(`${JSON.stringify({ released: true, agent, target })}\n`);
      return;
    }
    case 'ready': {
      assertPersonalReady(agent);
      writeFileSync(
        coordinationPath('ready', agent),
        `${new Date().toISOString()}\n`,
        { encoding: 'utf8', flag: 'wx', mode: 0o600 }
      );
      writeIntent(agent, 'needs_coordination', '', 'ready for shared collaboration phase');
      appendEvent('ready', agent);
      process.stdout.write(`${JSON.stringify({ ready: true, agent })}\n`);
      return;
    }
    case 'begin-shared': {
      const target = normalizeTarget(rawTarget);
      await beginShared(
        agent,
        target,
        positiveInteger(rawTimeout, DEFAULT_TIMEOUT_MS)
      );
      return;
    }
    case 'finish': {
      if (existsSync(leasePath(agent))) {
        throw new Error(`cannot finish with an active mutation lease: ${agent}`);
      }
      const destination = intentPath(agent);
      if (existsSync(destination)) {
        rmSync(destination, { force: true });
      }
      appendEvent('finished', agent);
      process.stdout.write(`${JSON.stringify({ finished: true, agent })}\n`);
      return;
    }
    default:
      throw new Error(`unknown command: ${command}`);
  }
}

const isMain = process.argv[1]
  && path.resolve(process.argv[1]) === path.resolve(fileURLToPath(import.meta.url));

if (isMain) {
  main().catch((error) => {
    fail(error?.message || String(error));
  });
}

export {
  BLOCKED_EXIT_CODE,
  beginShared,
  lockPath,
  normalizeAgent,
  normalizeTarget,
  readOwner,
  release,
  tryAcquire,
  verify
};
