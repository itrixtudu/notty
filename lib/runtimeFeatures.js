const TRUE_VALUES = new Set(['1', 'true', 'yes', 'on']);
const FALSE_VALUES = new Set(['0', 'false', 'no', 'off']);

export function parseBooleanSwitch(value, label = 'boolean switch') {
  if (typeof value === 'boolean') {
    return value;
  }
  if (typeof value !== 'string') {
    throw new Error(`${label} must be true or false`);
  }
  const normalized = value.trim().toLowerCase();
  if (TRUE_VALUES.has(normalized)) {
    return true;
  }
  if (FALSE_VALUES.has(normalized)) {
    return false;
  }
  throw new Error(`${label} must be one of: true, false, 1, 0, yes, no, on, off`);
}

export function isCollabEnabled(env = process.env) {
  if (!Object.hasOwn(env, 'NOTTY_COLLAB_ENABLED')) {
    return false;
  }
  return parseBooleanSwitch(env.NOTTY_COLLAB_ENABLED, 'NOTTY_COLLAB_ENABLED');
}
