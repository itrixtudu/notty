import { randomBytes, randomUUID } from 'node:crypto';
import { getAuthState, hashAuthSecret } from './authState.js';

const DEFAULT_SOURCE = 'ui';
const FALSE_VALUES = new Set(['0', 'false', 'no', 'off']);

const environmentOtpState = globalThis.__nottyEnvironmentOtpStateV2 || new WeakMap();
globalThis.__nottyEnvironmentOtpStateV2 = environmentOtpState;

function parsePositiveInteger(value) {
  const normalized = String(value ?? '').trim();
  if (!/^[1-9]\d*$/.test(normalized)) {
    return null;
  }
  const parsed = Number(normalized);
  return Number.isSafeInteger(parsed) ? parsed : null;
}

function normalizeOtpValue(value) {
  return typeof value === 'string' ? value.trim() : '';
}

function generateOtpValue() {
  return randomBytes(18).toString('base64url');
}

function expirationTimestamp(createdAt, ttlSeconds) {
  if (ttlSeconds === null) {
    return null;
  }
  const expiresAt = createdAt + ttlSeconds * 1000;
  if (!Number.isSafeInteger(expiresAt)) {
    throw new Error('TTL is too large.');
  }
  return expiresAt;
}

function getDefaultTtlSeconds() {
  const configured = process.env.NOTTY_MCP_SPAWN_OTP_TTL_SECONDS;
  if (configured === undefined || configured === null || String(configured).trim() === '') {
    return null;
  }
  const parsed = parsePositiveInteger(configured);
  if (parsed === null) {
    throw new Error('NOTTY_MCP_SPAWN_OTP_TTL_SECONDS must be a positive integer.');
  }
  return parsed;
}

function getOtpStatus(row, now = Date.now()) {
  if (row.revoked_at !== null) {
    return 'revoked';
  }
  if (row.consumed_at !== null) {
    return 'used';
  }
  if (row.expires_at !== null && now >= row.expires_at) {
    return 'expired';
  }
  return 'available';
}

function serializeRow(row, now = Date.now()) {
  const ttlSeconds = row.expires_at === null
    ? null
    : Math.max(1, Math.ceil((row.expires_at - row.created_at) / 1000));
  return {
    uuid: row.uuid,
    source: row.source,
    createdAt: row.created_at,
    usedAt: row.consumed_at,
    consumedAt: row.consumed_at,
    revokedAt: row.revoked_at,
    ttlSeconds,
    expiresAt: row.expires_at,
    remainingSeconds: row.expires_at === null
      ? null
      : Math.max(0, Math.ceil((row.expires_at - now) / 1000)),
    status: getOtpStatus(row, now)
  };
}

function selectRows(database) {
  return database.prepare(`
    SELECT uuid, source, created_at, expires_at, consumed_at, revoked_at
    FROM spawn_otps
    ORDER BY created_at DESC, uuid DESC
  `).all();
}

function summarizeRows(rows, now = Date.now()) {
  const counts = { available: 0, used: 0, expired: 0, revoked: 0 };
  for (const row of rows) {
    counts[getOtpStatus(row, now)] += 1;
  }
  return {
    enabled: true,
    totalCount: rows.length,
    availableCount: counts.available,
    usedCount: counts.used,
    expiredCount: counts.expired,
    revokedCount: counts.revoked,
    defaultTtlSeconds: getDefaultTtlSeconds()
  };
}

function environmentSignature(value, ttlSeconds) {
  return value ? `${hashAuthSecret(value)}:${ttlSeconds ?? ''}` : '';
}

function syncEnvironmentOtp() {
  const value = normalizeOtpValue(process.env.NOTTY_MCP_SPAWN_OTP);
  if (!value) {
    return;
  }

  const ttlSeconds = getDefaultTtlSeconds();
  const state = getAuthState();
  const signature = environmentSignature(value, ttlSeconds);
  if (environmentOtpState.get(state) === signature) {
    return;
  }

  const createdAt = Date.now();
  const expiresAt = expirationTimestamp(createdAt, ttlSeconds);
  state.transaction((database) => {
    database.prepare(`
      INSERT OR IGNORE INTO spawn_otps(
        uuid, token_hash, source, created_at, expires_at, consumed_at, revoked_at
      ) VALUES (?, ?, 'env', ?, ?, NULL, NULL)
    `).run(randomUUID(), hashAuthSecret(value), createdAt, expiresAt);
    database.prepare(`
      UPDATE spawn_otps
      SET revoked_at = ?
      WHERE source = 'env'
        AND token_hash <> ?
        AND consumed_at IS NULL
        AND revoked_at IS NULL
        AND (expires_at IS NULL OR expires_at > ?)
    `).run(createdAt, hashAuthSecret(value), createdAt);
  });
  environmentOtpState.set(state, signature);
}

function findRowByHash(database, tokenHash) {
  return database.prepare(`
    SELECT uuid, source, created_at, expires_at, consumed_at, revoked_at
    FROM spawn_otps
    WHERE token_hash = ?
  `).get(tokenHash);
}

export class SpawnOtpError extends Error {
  constructor(code, message, statusCode = 403, options = undefined) {
    super(message, options);
    this.name = 'SpawnOtpError';
    this.code = code;
    this.statusCode = statusCode;
  }
}

export function resolveSpawnOtp(args) {
  if (!args || typeof args !== 'object' || Array.isArray(args)) {
    return null;
  }
  const resolved = normalizeOtpValue(args.otp);
  return resolved || null;
}

export function isSpawnOtpProtected() {
  const configured = process.env.NOTTY_MCP_SPAWN_OTP_ENABLED;
  if (configured === undefined || configured === null || configured === '') {
    return true;
  }
  return !FALSE_VALUES.has(String(configured).trim().toLowerCase());
}

export function getSpawnOtpConfig() {
  const enabled = isSpawnOtpProtected();
  return {
    otp: enabled ? '__spawn_otp_registry__' : null,
    enabled,
    ttlSeconds: getDefaultTtlSeconds()
  };
}

export function getSpawnOtpSummary() {
  if (!isSpawnOtpProtected()) {
    return {
      enabled: false,
      totalCount: 0,
      availableCount: 0,
      usedCount: 0,
      expiredCount: 0,
      revokedCount: 0,
      defaultTtlSeconds: getDefaultTtlSeconds()
    };
  }

  syncEnvironmentOtp();
  const now = Date.now();
  const rows = selectRows(getAuthState().database);
  return summarizeRows(rows, now);
}

export function getSpawnOtpDashboard() {
  if (!isSpawnOtpProtected()) {
    return {
      serverTime: Date.now(),
      ...getSpawnOtpSummary(),
      otps: [],
      available: [],
      history: []
    };
  }

  syncEnvironmentOtp();
  const now = Date.now();
  const rows = selectRows(getAuthState().database);
  const otps = rows.map((row) => serializeRow(row, now));
  return {
    serverTime: now,
    ...summarizeRows(rows, now),
    otps,
    available: otps.filter((entry) => entry.status === 'available'),
    history: otps.filter((entry) => entry.status !== 'available')
  };
}

export function createSpawnOtp(options = {}) {
  if (!isSpawnOtpProtected()) {
    throw new SpawnOtpError(
      'spawn_terminal_otp_disabled',
      'Spawn OTP enforcement is disabled.'
    );
  }

  syncEnvironmentOtp();
  const suppliedValue = normalizeOtpValue(options.value);
  const value = suppliedValue || generateOtpValue();
  const ttlSeconds = options.ttlSeconds === undefined
    || options.ttlSeconds === null
    || options.ttlSeconds === ''
    ? getDefaultTtlSeconds()
    : parsePositiveInteger(options.ttlSeconds);

  if (
    options.ttlSeconds !== undefined
    && options.ttlSeconds !== null
    && options.ttlSeconds !== ''
    && ttlSeconds === null
  ) {
    throw new Error('TTL must be a positive integer number of seconds.');
  }

  const source = typeof options.source === 'string' && options.source.trim()
    ? options.source.trim().slice(0, 80)
    : DEFAULT_SOURCE;
  const createdAt = Date.now();
  const expiresAt = expirationTimestamp(createdAt, ttlSeconds);
  const uuid = randomUUID();
  const tokenHash = hashAuthSecret(value);
  const state = getAuthState();

  state.transaction((database) => {
    if (findRowByHash(database, tokenHash)) {
      throw new Error('Spawn OTP value already exists.');
    }
    database.prepare(`
      INSERT INTO spawn_otps(
        uuid, token_hash, source, created_at, expires_at, consumed_at, revoked_at
      ) VALUES (?, ?, ?, ?, ?, NULL, NULL)
    `).run(uuid, tokenHash, source, createdAt, expiresAt);
  });

  return {
    value,
    ...serializeRow({
      uuid,
      source,
      created_at: createdAt,
      expires_at: expiresAt,
      consumed_at: null,
      revoked_at: null
    })
  };
}

function consumeSpawnOtpInternal(args) {
  if (!isSpawnOtpProtected()) {
    return { enforced: false };
  }

  syncEnvironmentOtp();
  const providedOtp = resolveSpawnOtp(args);
  if (!providedOtp) {
    throw new SpawnOtpError('spawn_terminal_otp_required', 'Spawn OTP is required.');
  }

  const tokenHash = hashAuthSecret(providedOtp);
  const state = getAuthState();
  const now = Date.now();
  const consumed = state.transaction((database) => {
    const row = findRowByHash(database, tokenHash);
    if (!row) {
      throw new SpawnOtpError('spawn_terminal_otp_invalid', 'Spawn OTP is invalid.');
    }
    if (row.revoked_at !== null) {
      throw new SpawnOtpError('spawn_terminal_otp_revoked', 'Spawn OTP has been revoked.');
    }
    if (row.consumed_at !== null) {
      throw new SpawnOtpError('spawn_terminal_otp_used', 'Spawn OTP has already been used.');
    }
    if (row.expires_at !== null && now >= row.expires_at) {
      throw new SpawnOtpError('spawn_terminal_otp_expired', 'Spawn OTP has expired.');
    }

    const result = database.prepare(`
      UPDATE spawn_otps
      SET consumed_at = ?
      WHERE uuid = ?
        AND consumed_at IS NULL
        AND revoked_at IS NULL
        AND (expires_at IS NULL OR expires_at > ?)
    `).run(now, row.uuid, now);
    if (result.changes !== 1) {
      throw new SpawnOtpError('spawn_terminal_otp_used', 'Spawn OTP has already been used.');
    }

    return {
      enforced: true,
      otp: serializeRow({ ...row, consumed_at: now }, now)
    };
  });
  console.warn(`[spawn-otp] consumed uuid=${consumed.otp.uuid}`);
  return consumed;
}

export function consumeSpawnOtp(args) {
  try {
    return consumeSpawnOtpInternal(args);
  } catch (error) {
    if (error instanceof SpawnOtpError) {
      throw error;
    }
    throw new SpawnOtpError(
      'spawn_terminal_otp_state_unavailable',
      'Spawn OTP state is unavailable.',
      500,
      { cause: error }
    );
  }
}

// Compatibility for older callers. Consumption is intentionally atomic.
export function validateSpawnOtp(args) {
  try {
    return consumeSpawnOtp(args);
  } catch (error) {
    if (error instanceof SpawnOtpError) {
      return {
        enforced: true,
        error: { code: error.code, message: error.message }
      };
    }
    throw error;
  }
}
