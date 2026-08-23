import { randomBytes, randomUUID, timingSafeEqual } from 'node:crypto';

const globalSpawnOtpState = globalThis.__mcpSpawnOtpState || {
  entries: new Map(),
  envEntryUuid: null,
  envSignature: null
};

globalThis.__mcpSpawnOtpState = globalSpawnOtpState;

function parsePositiveInteger(value) {
  const parsed = Number.parseInt(value ?? '', 10);
  return Number.isFinite(parsed) && parsed > 0 ? parsed : null;
}

function normalizeOtpValue(value) {
  return typeof value === 'string' ? value.trim() : '';
}

function generateOtpValue() {
  return randomBytes(18).toString('base64url');
}

function createEntry({ value, ttlSeconds, source }) {
  const createdAt = Date.now();
  const normalizedTtl = parsePositiveInteger(ttlSeconds);

  return {
    uuid: randomUUID(),
    value,
    source,
    createdAt,
    ttlSeconds: normalizedTtl,
    expiresAt: normalizedTtl ? createdAt + normalizedTtl * 1000 : null,
    usedAt: null
  };
}

function getEntryStatus(entry, now = Date.now()) {
  if (entry.usedAt) {
    return 'used';
  }
  if (entry.expiresAt !== null && now >= entry.expiresAt) {
    return 'expired';
  }
  return 'available';
}

function serializeEntry(entry, now = Date.now()) {
  const status = getEntryStatus(entry, now);
  const remainingSeconds =
    entry.expiresAt === null ? null : Math.max(0, Math.ceil((entry.expiresAt - now) / 1000));

  return {
    uuid: entry.uuid,
    value: entry.value,
    source: entry.source,
    createdAt: entry.createdAt,
    usedAt: entry.usedAt,
    ttlSeconds: entry.ttlSeconds,
    expiresAt: entry.expiresAt,
    remainingSeconds,
    status
  };
}

function compareEntriesByCreatedAtDesc(left, right) {
  return right.createdAt - left.createdAt;
}

function listEntries() {
  syncEnvOtp();
  return Array.from(globalSpawnOtpState.entries.values()).sort(compareEntriesByCreatedAtDesc);
}

function removeEntryByUuid(uuid) {
  if (!uuid) {
    return;
  }
  globalSpawnOtpState.entries.delete(uuid);
}

function findEntryByValue(value) {
  const normalized = normalizeOtpValue(value);
  if (!normalized) {
    return null;
  }

  for (const entry of globalSpawnOtpState.entries.values()) {
    if (entry.value === normalized) {
      return entry;
    }
  }

  return null;
}

function tokensMatch(expected, provided) {
  if (typeof expected !== 'string' || typeof provided !== 'string') {
    return false;
  }

  const expectedBuffer = Buffer.from(expected);
  const providedBuffer = Buffer.from(provided);
  if (expectedBuffer.length !== providedBuffer.length) {
    return false;
  }

  try {
    return timingSafeEqual(expectedBuffer, providedBuffer);
  } catch {
    return false;
  }
}

function findEntryByProvidedOtp(value) {
  const normalized = normalizeOtpValue(value);
  if (!normalized) {
    return null;
  }

  for (const entry of globalSpawnOtpState.entries.values()) {
    if (tokensMatch(entry.value, normalized)) {
      return entry;
    }
  }

  return null;
}

function getDefaultTtlSeconds() {
  return parsePositiveInteger(process.env.NOTTY_MCP_SPAWN_OTP_TTL_SECONDS);
}

function syncEnvOtp() {
  const envOtp = normalizeOtpValue(process.env.NOTTY_MCP_SPAWN_OTP);
  const ttlSeconds = getDefaultTtlSeconds();
  const envSignature = envOtp ? `${envOtp}\n${ttlSeconds ?? ''}` : null;

  if (envSignature === globalSpawnOtpState.envSignature) {
    return;
  }

  removeEntryByUuid(globalSpawnOtpState.envEntryUuid);
  globalSpawnOtpState.envEntryUuid = null;
  globalSpawnOtpState.envSignature = envSignature;

  if (!envOtp) {
    return;
  }

  const duplicateEntry = findEntryByValue(envOtp);
  if (duplicateEntry) {
    removeEntryByUuid(duplicateEntry.uuid);
  }

  const envEntry = createEntry({
    value: envOtp,
    ttlSeconds,
    source: 'env'
  });

  globalSpawnOtpState.entries.set(envEntry.uuid, envEntry);
  globalSpawnOtpState.envEntryUuid = envEntry.uuid;
}

export function resolveSpawnOtp(args) {
  if (!args || typeof args !== 'object') {
    return null;
  }

  const resolved = normalizeOtpValue(args.otp);
  return resolved || null;
}

export function isSpawnOtpProtected() {
  return listEntries().length > 0;
}

export function getSpawnOtpConfig() {
  const summary = getSpawnOtpSummary();
  return {
    otp: summary.enabled ? '__spawn_otp_registry__' : null,
    ttlSeconds: summary.defaultTtlSeconds
  };
}

export function getSpawnOtpSummary() {
  const entries = listEntries();
  const now = Date.now();
  let availableCount = 0;
  let usedCount = 0;
  let expiredCount = 0;

  for (const entry of entries) {
    const status = getEntryStatus(entry, now);
    if (status === 'available') {
      availableCount += 1;
    } else if (status === 'used') {
      usedCount += 1;
    } else if (status === 'expired') {
      expiredCount += 1;
    }
  }

  return {
    enabled: entries.length > 0,
    totalCount: entries.length,
    availableCount,
    usedCount,
    expiredCount,
    defaultTtlSeconds: getDefaultTtlSeconds()
  };
}

export function getSpawnOtpDashboard() {
  const now = Date.now();
  const otps = listEntries().map((entry) => serializeEntry(entry, now));

  return {
    ...getSpawnOtpSummary(),
    otps,
    available: otps.filter((entry) => entry.status === 'available'),
    history: otps.filter((entry) => entry.status !== 'available')
  };
}

export function createSpawnOtp(options = {}) {
  syncEnvOtp();

  const suppliedValue = normalizeOtpValue(options.value);
  const value = suppliedValue || generateOtpValue();
  const ttlSeconds =
    options.ttlSeconds === undefined || options.ttlSeconds === null || options.ttlSeconds === ''
      ? getDefaultTtlSeconds()
      : parsePositiveInteger(options.ttlSeconds);

  if (!value) {
    throw new Error('Spawn OTP value is required.');
  }

  if (
    options.ttlSeconds !== undefined
    && options.ttlSeconds !== null
    && options.ttlSeconds !== ''
    && ttlSeconds === null
  ) {
    throw new Error('TTL must be a positive integer number of seconds.');
  }

  const duplicateEntry = findEntryByValue(value);
  if (duplicateEntry) {
    throw new Error('Spawn OTP value already exists.');
  }

  const entry = createEntry({
    value,
    ttlSeconds,
    source: 'ui'
  });

  globalSpawnOtpState.entries.set(entry.uuid, entry);
  return serializeEntry(entry);
}

export function validateSpawnOtp(args) {
  const entries = listEntries();
  if (entries.length === 0) {
    return { enforced: false };
  }

  const providedOtp = resolveSpawnOtp(args);
  if (!providedOtp) {
    return {
      enforced: true,
      error: { code: 'spawn_terminal_otp_required', message: 'Spawn OTP is required.' }
    };
  }

  const matchingEntry = findEntryByProvidedOtp(providedOtp);
  if (!matchingEntry) {
    return {
      enforced: true,
      error: { code: 'spawn_terminal_otp_invalid', message: 'Spawn OTP is invalid.' }
    };
  }

  if (matchingEntry.usedAt) {
    return {
      enforced: true,
      error: { code: 'spawn_terminal_otp_used', message: 'Spawn OTP has already been used.' }
    };
  }

  if (matchingEntry.expiresAt !== null && Date.now() >= matchingEntry.expiresAt) {
    return {
      enforced: true,
      error: { code: 'spawn_terminal_otp_expired', message: 'Spawn OTP has expired.' }
    };
  }

  matchingEntry.usedAt = Date.now();
  console.warn(
    `MCP SPAWN OTP USED: SENSITIVE TOKEN ACCEPTED FOR TERMINAL SPAWN. uuid=${matchingEntry.uuid}`
  );

  return {
    enforced: true,
    otp: serializeEntry(matchingEntry)
  };
}
