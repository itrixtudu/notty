import { randomBytes, randomUUID, timingSafeEqual } from 'node:crypto';

export const COPILOT_REMOTE_ACCESS_TTL_SECONDS = 3_600;
export const COPILOT_LOCAL_ACCESS_TTL_SECONDS = 28_800;

function positiveInteger(value, label) {
  const number = Number(value);
  if (!Number.isInteger(number) || number <= 0) {
    throw new Error(`${label} must be a positive integer`);
  }
  return number;
}

function requiredString(value, label) {
  if (typeof value !== 'string' || !value.trim()) {
    throw new Error(`${label} is required`);
  }
  return value.trim();
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

function publicOtp(entry, now) {
  let status = 'available';
  if (entry.revokedAt !== null) {
    status = 'revoked';
  } else if (entry.usedAt !== null) {
    status = 'used';
  } else if (now >= entry.expiresAt) {
    status = 'expired';
  }
  return {
    uuid: entry.uuid,
    bindingId: entry.bindingId,
    purpose: entry.purpose,
    runtime: entry.runtime,
    local: entry.local,
    createdAt: entry.createdAt,
    expiresAt: entry.expiresAt,
    ttlSeconds: entry.ttlSeconds,
    usedAt: entry.usedAt,
    revokedAt: entry.revokedAt,
    status,
    remainingSeconds: Math.max(0, Math.ceil((entry.expiresAt - now) / 1000))
  };
}

function publicLease(entry, now) {
  let status = 'active';
  if (entry.revokedAt !== null) {
    status = 'revoked';
  } else if (now >= entry.expiresAt) {
    status = 'expired';
  }
  return {
    id: entry.id,
    otpUuid: entry.otpUuid,
    bindingId: entry.bindingId,
    purpose: entry.purpose,
    runtime: entry.runtime,
    local: entry.local,
    createdAt: entry.createdAt,
    expiresAt: entry.expiresAt,
    ttlSeconds: entry.ttlSeconds,
    revokedAt: entry.revokedAt,
    status,
    remainingSeconds: Math.max(0, Math.ceil((entry.expiresAt - now) / 1000))
  };
}

function accessError(code, message) {
  return { ok: false, error: { code, message } };
}

export function getCopilotAccessTtlSeconds(runtimeOrOptions) {
  const options = typeof runtimeOrOptions === 'object' && runtimeOrOptions !== null
    ? runtimeOrOptions
    : { runtime: runtimeOrOptions };
  const runtime = String(options.runtime || '').trim().toLowerCase();
  return options.local === true || runtime === 'ollama'
    ? COPILOT_LOCAL_ACCESS_TTL_SECONDS
    : COPILOT_REMOTE_ACCESS_TTL_SECONDS;
}

export class PurposeScopedAccessRegistry {
  constructor(options = {}) {
    this.now = typeof options.now === 'function' ? options.now : Date.now;
    this.tokenFactory = typeof options.tokenFactory === 'function'
      ? options.tokenFactory
      : () => randomBytes(32).toString('base64url');
    this.idFactory = typeof options.idFactory === 'function' ? options.idFactory : randomUUID;
    this.otps = new Map();
    this.leases = new Map();
  }

  issue(options = {}) {
    const bindingId = requiredString(options.bindingId, 'bindingId');
    const purpose = requiredString(options.purpose, 'purpose');
    const runtime = typeof options.runtime === 'string' && options.runtime.trim()
      ? options.runtime.trim()
      : 'unknown';
    const local = options.local === true || runtime.toLowerCase() === 'ollama';
    const defaultTtl = getCopilotAccessTtlSeconds({ runtime, local });
    const ttlSeconds = positiveInteger(options.ttlSeconds ?? defaultTtl, 'ttlSeconds');
    const leaseTtlSeconds = positiveInteger(
      options.leaseTtlSeconds ?? ttlSeconds,
      'leaseTtlSeconds'
    );
    const createdAt = this.now();
    const token = requiredString(this.tokenFactory(), 'generated token');
    for (const entry of this.otps.values()) {
      if (tokensMatch(entry.token, token)) {
        throw new Error('Generated access OTP already exists');
      }
    }

    const entry = {
      uuid: this.idFactory(),
      token,
      bindingId,
      purpose,
      runtime,
      local,
      createdAt,
      expiresAt: createdAt + ttlSeconds * 1000,
      ttlSeconds,
      leaseTtlSeconds,
      usedAt: null,
      revokedAt: null
    };
    this.otps.set(entry.uuid, entry);
    return { token, otp: publicOtp(entry, createdAt) };
  }

  consume(token, constraints = {}) {
    const normalizedToken = typeof token === 'string' ? token.trim() : '';
    if (!normalizedToken) {
      return accessError('copilot_access_otp_required', 'Copilot access OTP is required.');
    }
    const entry = [...this.otps.values()].find((candidate) => (
      tokensMatch(candidate.token, normalizedToken)
    ));
    if (!entry) {
      return accessError('copilot_access_otp_invalid', 'Copilot access OTP is invalid.');
    }

    const now = this.now();
    if (entry.revokedAt !== null) {
      return accessError('copilot_access_otp_revoked', 'Copilot access OTP was revoked.');
    }
    if (entry.usedAt !== null) {
      return accessError('copilot_access_otp_used', 'Copilot access OTP was already used.');
    }
    if (now >= entry.expiresAt) {
      return accessError('copilot_access_otp_expired', 'Copilot access OTP has expired.');
    }
    if (constraints.bindingId !== undefined && constraints.bindingId !== entry.bindingId) {
      return accessError(
        'copilot_access_otp_wrong_binding',
        'Copilot access OTP does not belong to this terminal binding.'
      );
    }
    if (constraints.purpose !== undefined && constraints.purpose !== entry.purpose) {
      return accessError(
        'copilot_access_otp_wrong_purpose',
        'Copilot access OTP does not grant this purpose.'
      );
    }

    entry.usedAt = now;
    const lease = {
      id: this.idFactory(),
      otpUuid: entry.uuid,
      bindingId: entry.bindingId,
      purpose: entry.purpose,
      runtime: entry.runtime,
      local: entry.local,
      createdAt: now,
      expiresAt: now + entry.leaseTtlSeconds * 1000,
      ttlSeconds: entry.leaseTtlSeconds,
      revokedAt: null
    };
    this.leases.set(lease.id, lease);
    return {
      ok: true,
      otp: publicOtp(entry, now),
      lease: publicLease(lease, now)
    };
  }

  validateLease(leaseId, constraints = {}) {
    const entry = this.leases.get(leaseId);
    if (!entry) {
      return accessError('copilot_access_lease_invalid', 'Copilot access lease is invalid.');
    }
    const now = this.now();
    if (entry.revokedAt !== null) {
      return accessError('copilot_access_lease_revoked', 'Copilot access lease was revoked.');
    }
    if (now >= entry.expiresAt) {
      return accessError('copilot_access_lease_expired', 'Copilot access lease has expired.');
    }
    if (constraints.bindingId !== undefined && constraints.bindingId !== entry.bindingId) {
      return accessError(
        'copilot_access_lease_wrong_binding',
        'Copilot access lease does not belong to this terminal binding.'
      );
    }
    if (constraints.purpose !== undefined && constraints.purpose !== entry.purpose) {
      return accessError(
        'copilot_access_lease_wrong_purpose',
        'Copilot access lease does not grant this purpose.'
      );
    }
    return { ok: true, lease: publicLease(entry, now) };
  }

  revokeLease(leaseId) {
    const entry = this.leases.get(leaseId);
    if (!entry) {
      return false;
    }
    if (entry.revokedAt === null) {
      entry.revokedAt = this.now();
    }
    return true;
  }

  revokeBinding(bindingId) {
    const normalizedBindingId = requiredString(bindingId, 'bindingId');
    const now = this.now();
    let revoked = 0;
    for (const entry of this.otps.values()) {
      if (
        entry.bindingId === normalizedBindingId
        && entry.usedAt === null
        && entry.revokedAt === null
      ) {
        entry.revokedAt = now;
        revoked += 1;
      }
    }
    for (const entry of this.leases.values()) {
      if (entry.bindingId === normalizedBindingId && entry.revokedAt === null) {
        entry.revokedAt = now;
        revoked += 1;
      }
    }
    return revoked;
  }

  snapshot(options = {}) {
    const now = this.now();
    const bindingId = typeof options.bindingId === 'string' ? options.bindingId : null;
    const otps = [...this.otps.values()]
      .filter((entry) => !bindingId || entry.bindingId === bindingId)
      .map((entry) => publicOtp(entry, now));
    const leases = [...this.leases.values()]
      .filter((entry) => !bindingId || entry.bindingId === bindingId)
      .map((entry) => publicLease(entry, now));
    return { otps, leases };
  }
}

const globalRegistry = globalThis.__copilotAccessRegistry
  || new PurposeScopedAccessRegistry();
globalThis.__copilotAccessRegistry = globalRegistry;

export const copilotAccessRegistry = globalRegistry;

export function issueCopilotAccessOtp(options) {
  return copilotAccessRegistry.issue(options);
}

export function consumeCopilotAccessOtp(token, constraints) {
  return copilotAccessRegistry.consume(token, constraints);
}

export function validateCopilotAccessLease(leaseId, constraints) {
  return copilotAccessRegistry.validateLease(leaseId, constraints);
}

export function revokeCopilotAccessLease(leaseId) {
  return copilotAccessRegistry.revokeLease(leaseId);
}

export function revokeCopilotBindingAccess(bindingId) {
  return copilotAccessRegistry.revokeBinding(bindingId);
}

export function getCopilotAccessSnapshot(options) {
  return copilotAccessRegistry.snapshot(options);
}
