const LOCKDOWN_VALUE = process.env.NOTTY_LOCKDOWN;

function normalize(value) {
  if (typeof value === 'boolean') {
    return value;
  }

  if (value === undefined || value === null) {
    return false;
  }

  const normalized = String(value).trim().toLowerCase();
  if (!normalized) {
    return false;
  }

  return normalized === '1' || normalized === 'true' || normalized === 'yes' || normalized === 'on';
}

export function isTerminalLockdownEnabled(value = LOCKDOWN_VALUE) {
  return normalize(value);
}

export function sendTerminalLockdownResponse(res) {
  res.status(403).json({ error: 'Terminal HTTP API disabled in lockdown mode' });
}
