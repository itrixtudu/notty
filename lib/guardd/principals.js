import fs from 'node:fs/promises';
import path from 'node:path';

import { DEFAULT_GUARD_STATE_DIR } from './constants.js';

const DEFAULT_PREFIXES = Object.freeze([
  '/',
  '/collab',
  '/mcp',
  '/_next',
  '/credentialless-bootstrap.js',
  '/api/features',
  '/api/lockdown',
  '/api/ws',
  '/api/agents',
  '/api/collab',
  '/api/copilots',
  '/sse',
  '/message',
  '/api/mcp',
  '/api/spawn-otps',
  '/api/terminals',
  '/ws/terminals',
  '/health',
]);

function normalizeAllowedPrefixes(value) {
  const prefixes = value == null ? [...DEFAULT_PREFIXES] : value;
  if (!Array.isArray(prefixes)) {
    throw new TypeError('principal allowedPrefixes must be an array');
  }
  const normalized = [];
  const seen = new Set();
  for (const prefix of prefixes) {
    if (
      typeof prefix !== 'string' ||
      !prefix.startsWith('/') ||
      prefix.startsWith('//') ||
      /[?#%\\\u0000-\u0020\u007f]/.test(prefix) ||
      (prefix !== '/' && prefix.endsWith('/')) ||
      prefix.split('/').some((segment) => segment === '.' || segment === '..')
    ) {
      throw new TypeError(
        'principal allowedPrefixes must contain canonical absolute paths',
      );
    }
    if (
      !DEFAULT_PREFIXES.some(
        (allowed) =>
          prefix === allowed || prefix.startsWith(`${allowed}/`),
      )
    ) {
      throw new TypeError(
        `principal allowed prefix exceeds the gateway route ceiling: ${prefix}`,
      );
    }
    if (!seen.has(prefix)) {
      normalized.push(prefix);
      seen.add(prefix);
    }
  }
  return normalized;
}

function normalizeFingerprint(value) {
  if (typeof value !== 'string' || !value.trim()) {
    throw new TypeError('certificate fingerprint is required');
  }
  const normalized = value.replace(/:/g, '').toUpperCase();
  if (!/^[A-F0-9]{64}$/.test(normalized)) {
    throw new TypeError('certificate fingerprint must be a SHA-256 fingerprint');
  }
  return normalized;
}

function validatePrincipal(principal) {
  if (!principal?.id || !/^[A-Za-z0-9_.-]+$/.test(principal.id)) {
    throw new TypeError('principal id contains unsupported characters');
  }
  if (!principal.runId && !principal.agentId) {
    throw new TypeError('principal requires runId or agentId');
  }
  const expiresAt = new Date(principal.expiresAt);
  if (!Number.isFinite(expiresAt.getTime())) {
    throw new TypeError('principal expiresAt must be an ISO timestamp');
  }
  return {
    id: principal.id,
    certificateFingerprint: normalizeFingerprint(principal.certificateFingerprint),
    runId: principal.runId || null,
    agentId: principal.agentId || null,
    expiresAt: expiresAt.toISOString(),
    allowedPrefixes: normalizeAllowedPrefixes(principal.allowedPrefixes),
    createdAt: principal.createdAt || new Date().toISOString(),
  };
}

export class PrincipalStore {
  constructor(options = {}) {
    this.filePath =
      options.filePath ||
      path.join(options.stateDir || DEFAULT_GUARD_STATE_DIR, 'principals.json');
  }

  async initialize() {
    await fs.mkdir(path.dirname(this.filePath), { recursive: true, mode: 0o700 });
    try {
      await fs.access(this.filePath);
    } catch (error) {
      if (error.code !== 'ENOENT') {
        throw error;
      }
      await this.write([]);
    }
  }

  async read() {
    const document = JSON.parse(await fs.readFile(this.filePath, 'utf8'));
    if (document.schemaVersion !== 1 || !Array.isArray(document.principals)) {
      throw new TypeError('invalid guard principal store');
    }
    return document.principals.map((principal) => validatePrincipal(principal));
  }

  async write(principals) {
    const validated = principals.map((principal) =>
      validatePrincipal(principal),
    );
    const temporary = `${this.filePath}.${process.pid}.tmp`;
    const document = {
      schemaVersion: 1,
      updatedAt: new Date().toISOString(),
      principals: validated,
    };
    await fs.writeFile(temporary, `${JSON.stringify(document, null, 2)}\n`, {
      mode: 0o600,
    });
    await fs.rename(temporary, this.filePath);
  }

  async add(input) {
    const principal = validatePrincipal(input);
    const principals = (await this.read()).filter(
      (entry) =>
        entry.id !== principal.id &&
        normalizeFingerprint(entry.certificateFingerprint) !==
          principal.certificateFingerprint,
    );
    principals.push(principal);
    principals.sort((left, right) => left.id.localeCompare(right.id));
    await this.write(principals);
    return principal;
  }

  async revoke(id) {
    const principals = await this.read();
    const retained = principals.filter((entry) => entry.id !== id);
    if (retained.length === principals.length) {
      return false;
    }
    await this.write(retained);
    return true;
  }

  async findByFingerprint(fingerprint) {
    const normalized = normalizeFingerprint(fingerprint);
    const now = Date.now();
    return (
      (await this.read()).find(
        (entry) =>
          normalizeFingerprint(entry.certificateFingerprint) === normalized &&
          new Date(entry.expiresAt).getTime() > now,
      ) || null
    );
  }
}

export { DEFAULT_PREFIXES, normalizeAllowedPrefixes, normalizeFingerprint };
