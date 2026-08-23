import crypto from 'node:crypto';
import fs from 'node:fs/promises';
import net from 'node:net';
import path from 'node:path';

import { DEFAULT_GUARD_STATE_DIR } from './constants.js';

const PROTOCOLS = Object.freeze(['tcp', 'udp', 'icmp']);
const MAX_TTL_SECONDS = 3600;
const LOCK_STALE_MS = 30_000;
const LOCK_TIMEOUT_MS = 35_000;
const mutationQueues = new Map();

function delay(milliseconds) {
  return new Promise((resolve) => setTimeout(resolve, milliseconds));
}

async function processStartIdentity(pid) {
  try {
    const source = await fs.readFile(`/proc/${pid}/stat`, 'utf8');
    const close = source.lastIndexOf(')');
    if (close < 0) return null;
    const fields = source.slice(close + 2).trim().split(/\s+/);
    return /^\d+$/.test(fields[19] || '') ? fields[19] : null;
  } catch (error) {
    if (error.code === 'ENOENT' || error.code === 'ESRCH') return null;
    throw error;
  }
}

async function lockOwnerActive(lockPath) {
  try {
    const owner = JSON.parse(
      await fs.readFile(path.join(lockPath, 'owner.json'), 'utf8'),
    );
    if (!Number.isSafeInteger(owner.pid) || owner.pid <= 0) return false;
    process.kill(owner.pid, 0);
    return !owner.processStartIdentity
      || await processStartIdentity(owner.pid) === owner.processStartIdentity;
  } catch (error) {
    return error.code === 'EPERM';
  }
}

async function acquireMutationLock(lockPath) {
  const deadline = Date.now() + LOCK_TIMEOUT_MS;
  for (;;) {
    const token = crypto.randomUUID();
    try {
      await fs.mkdir(lockPath, { mode: 0o700 });
      await fs.writeFile(
        path.join(lockPath, 'owner.json'),
        `${JSON.stringify({
          pid: process.pid,
          processStartIdentity: await processStartIdentity(process.pid),
          token,
        })}\n`,
        { flag: 'wx', mode: 0o600 },
      );
      return { lockPath, token };
    } catch (error) {
      if (error.code !== 'EEXIST') throw error;
    }
    const stat = await fs.stat(lockPath).catch((error) => {
      if (error.code === 'ENOENT') return null;
      throw error;
    });
    if (
      stat
      && Date.now() - stat.mtimeMs >= LOCK_STALE_MS
      && !await lockOwnerActive(lockPath)
    ) {
      const stale = `${lockPath}.stale.${process.pid}.${crypto.randomUUID()}`;
      try {
        await fs.rename(lockPath, stale);
        await fs.rm(stale, { recursive: true, force: true });
        continue;
      } catch (error) {
        if (error.code === 'ENOENT') continue;
        throw error;
      }
    }
    if (Date.now() >= deadline) {
      throw new Error('guard grant store is busy');
    }
    await delay(25);
  }
}

async function releaseMutationLock(lock) {
  const owner = JSON.parse(
    await fs.readFile(path.join(lock.lockPath, 'owner.json'), 'utf8'),
  );
  if (owner.pid !== process.pid || owner.token !== lock.token) {
    throw new Error('guard grant store lock identity changed');
  }
  await fs.rm(lock.lockPath, { recursive: true });
}

function queueMutation(filePath, operation) {
  const previous = mutationQueues.get(filePath) || Promise.resolve();
  const current = previous.then(operation, operation);
  mutationQueues.set(filePath, current.catch(() => {}));
  return current;
}

function requiredString(value, label) {
  if (typeof value !== 'string' || !value.trim()) {
    throw new TypeError(`${label} is required`);
  }
  return value.trim();
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
  const destination = requiredString(value, 'destination').toLowerCase();
  const destinationParts = destination.split('/');
  if (destinationParts.length > 2) {
    throw new TypeError('destination must be a valid FQDN wildcard or IPv4 CIDR');
  }
  const [address, prefixText] = destinationParts;
  const family = net.isIP(address);
  if (family) {
    if (family !== 4) {
      throw new TypeError(
        'IPv6 grants are unsupported by the IPv4-only runner network',
      );
    }
    if (prefixText === '') {
      throw new TypeError('grant destination has an invalid IPv4 CIDR prefix');
    }
    const prefix = prefixText == null ? 32 : Number(prefixText);
    if (!Number.isSafeInteger(prefix) || prefix < 0 || prefix > 32) {
      throw new TypeError('grant destination has an invalid IPv4 CIDR prefix');
    }
    return `${address}/${prefix}`;
  }
  const wildcard = destination.startsWith('*.');
  const domain = wildcard ? destination.slice(2) : destination;
  if (
    prefixText != null
    || !validDomainName(domain)
  ) {
    throw new TypeError('destination must be a valid FQDN wildcard or IPv4 CIDR');
  }
  return wildcard ? `*.${domain}` : domain;
}

function normalizePorts(value, protocol) {
  if (protocol === 'icmp' || protocol === 'icmpv6') {
    if (value != null && String(value).trim()) {
      throw new TypeError(`${protocol} grants use type/code, not ports`);
    }
    return [];
  }
  const source = Array.isArray(value) ? value : String(value || '').split(',');
  const ports = source
    .map((entry) => Number(String(entry).trim()));
  if (!ports.length || ports.some((port) => !Number.isSafeInteger(port) || port < 1 || port > 65535)) {
    throw new TypeError('tcp/udp grants require ports from 1 to 65535');
  }
  return [...new Set(ports)].sort((left, right) => left - right);
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

function active(grant, now = Date.now()) {
  return !grant.revokedAt && new Date(grant.expiresAt).getTime() > now;
}

export class GrantStore {
  constructor(options = {}) {
    const stateDir = options.stateDir || DEFAULT_GUARD_STATE_DIR;
    this.filePath =
      options.filePath ||
      path.join(stateDir, 'grants', 'current.json');
    this.legacyFilePath = options.filePath
      ? null
      : path.join(stateDir, 'grants.json');
    this.auditPath =
      options.auditPath ||
      path.join(stateDir, 'grant-audit.ndjson');
    this.lockPath = `${this.filePath}.lock`;
  }

  async initialize() {
    await fs.mkdir(path.dirname(this.filePath), { recursive: true, mode: 0o700 });
    return queueMutation(this.filePath, async () => {
      const lock = await acquireMutationLock(this.lockPath);
      try {
        try {
          await fs.access(this.filePath);
        } catch (error) {
          if (error.code !== 'ENOENT') {
            throw error;
          }
          if (this.legacyFilePath) {
            try {
              await fs.rename(this.legacyFilePath, this.filePath);
              return;
            } catch (migrationError) {
              if (migrationError.code !== 'ENOENT') {
                throw migrationError;
              }
            }
          }
          await this.write([]);
        }
      } finally {
        await releaseMutationLock(lock);
      }
    });
  }

  async read() {
    const document = JSON.parse(await fs.readFile(this.filePath, 'utf8'));
    if (document.schemaVersion !== 1 || !Array.isArray(document.grants)) {
      throw new TypeError('invalid guard grant store');
    }
    return document.grants;
  }

  async write(grants) {
    const temporary = `${this.filePath}.${process.pid}.tmp`;
    await fs.writeFile(
      temporary,
      `${JSON.stringify(
        {
          schemaVersion: 1,
          updatedAt: new Date().toISOString(),
          grants,
        },
        null,
        2,
      )}\n`,
      { mode: 0o600 },
    );
    await fs.rename(temporary, this.filePath);
  }

  async audit(action, grant) {
    await fs.appendFile(
      this.auditPath,
      `${JSON.stringify({
        schemaVersion: 1,
        timestamp: new Date().toISOString(),
        action,
        grant,
      })}\n`,
      { mode: 0o600 },
    );
  }

  async mutate(operation) {
    return queueMutation(this.filePath, async () => {
      const lock = await acquireMutationLock(this.lockPath);
      try {
        return await operation();
      } finally {
        await releaseMutationLock(lock);
      }
    });
  }

  async create(input) {
    const protocol = requiredString(input.protocol, 'protocol').toLowerCase();
    if (!PROTOCOLS.includes(protocol)) {
      throw new TypeError(`protocol must be one of: ${PROTOCOLS.join(', ')}`);
    }
    const runId = requiredString(input.runId, 'runId');
    const ttlSeconds = Number(input.ttlSeconds || MAX_TTL_SECONDS);
    if (
      !Number.isSafeInteger(ttlSeconds) ||
      ttlSeconds <= 0 ||
      ttlSeconds > MAX_TTL_SECONDS
    ) {
      throw new TypeError(`ttlSeconds must be from 1 to ${MAX_TTL_SECONDS}`);
    }
    const createdAt = new Date();
    const ports = normalizePorts(input.ports, protocol);
    const destination = normalizeDestination(input.destination);
    const grant = {
      id: input.id || crypto.randomUUID(),
      runId,
      destination,
      protocol,
      ports,
      icmpType: normalizeIcmpField(input.icmpType, 'icmpType'),
      icmpCode: normalizeIcmpField(input.icmpCode, 'icmpCode'),
      actor: requiredString(input.actor, 'actor'),
      reason: requiredString(input.reason, 'reason'),
      createdAt: createdAt.toISOString(),
      expiresAt: new Date(createdAt.getTime() + ttlSeconds * 1000).toISOString(),
      revokedAt: null,
    };
    return this.mutate(async () => {
      const grants = await this.read();
      grants.push(grant);
      await this.write(grants);
      try {
        await this.audit('create', grant);
      } catch (error) {
        error.code = 'GUARD_GRANT_AUDIT_FAILED_AFTER_COMMIT';
        error.mutationCommitted = true;
        error.grant = grant;
        throw error;
      }
      return grant;
    });
  }

  async list(options = {}) {
    const grants = await this.read();
    return options.includeExpired ? grants : grants.filter((grant) => active(grant));
  }

  async revoke(id, actor, reason) {
    return this.mutate(async () => {
      const grants = await this.read();
      const grant = grants.find((entry) => entry.id === id);
      if (!grant) {
        return null;
      }
      if (!grant.revokedAt) {
        grant.revokedAt = new Date().toISOString();
        grant.revokedBy = requiredString(actor, 'actor');
        grant.revokeReason = requiredString(reason, 'reason');
        await this.write(grants);
        try {
          await this.audit('revoke', grant);
        } catch (error) {
          error.code = 'GUARD_GRANT_AUDIT_FAILED_AFTER_COMMIT';
          error.mutationCommitted = true;
          error.grant = grant;
          throw error;
        }
      }
      return grant;
    });
  }
}

export { MAX_TTL_SECONDS, PROTOCOLS, active as isGrantActive };
