import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import process from 'node:process';

export const DEFAULT_NOSH_GUARD_PREFIX = '/usr/local';
export const NOSH_GUARD_LAYOUT_RECEIPT = '/etc/nosh-guard-install-layout.conf';

const USER_PATH_KEYS = new Set([
  'SCHEMA_VERSION',
  'BIN_DIR',
  'NOSH_BIN',
  'NOSH_GUARD_BIN',
  'NOSH_GUARD_PREFIX',
  'NOSH_GUARD_PRIVILEGED_BIN',
]);
const RECEIPT_KEYS = new Set([
  'SCHEMA_VERSION',
  'NOSH_GUARD_PREFIX',
  'MANIFEST_SHA256',
]);
const DISALLOWED_PREFIXES = new Set([
  '/',
  '/bin',
  '/boot',
  '/dev',
  '/etc',
  '/home',
  '/lib',
  '/lib64',
  '/media',
  '/mnt',
  '/opt',
  '/proc',
  '/root',
  '/run',
  '/sbin',
  '/srv',
  '/sys',
  '/tmp',
  '/usr',
  '/var',
]);

function parseAssignments(source, expectedKeys, label) {
  const lines = String(source).split('\n');
  if (lines.at(-1) === '') {
    lines.pop();
  }
  const values = {};
  for (const [index, line] of lines.entries()) {
    const match = /^([A-Z][A-Z0-9_]*)=([^\r\n]*)$/.exec(line);
    if (!match) {
      throw new Error(`${label} has malformed line ${index + 1}`);
    }
    const [, key, value] = match;
    if (!expectedKeys.has(key)) {
      throw new Error(`${label} contains unknown key ${key}`);
    }
    if (Object.hasOwn(values, key)) {
      throw new Error(`${label} contains duplicate key ${key}`);
    }
    values[key] = value;
  }
  for (const key of expectedKeys) {
    if (!Object.hasOwn(values, key)) {
      throw new Error(`${label} is missing ${key}`);
    }
  }
  if (values.SCHEMA_VERSION !== '1') {
    throw new Error(`${label} uses unsupported schema ${values.SCHEMA_VERSION || '<empty>'}`);
  }
  return values;
}

function readProtectedDataFile(filename, options) {
  const {
    expectedUid,
    expectedMode,
    expectedKeys,
    label,
    fsImpl = fs,
  } = options;
  let stat;
  try {
    stat = fsImpl.lstatSync(filename);
  } catch (error) {
    if (error?.code === 'ENOENT') {
      return null;
    }
    throw new Error(`${label} cannot be inspected: ${error.message}`, { cause: error });
  }
  if (
    !stat.isFile()
    || stat.isSymbolicLink()
    || stat.nlink !== 1
    || stat.uid !== expectedUid
    || (stat.mode & 0o7777) !== expectedMode
  ) {
    throw new Error(
      `${label} must be a singly linked regular file owned by uid ${expectedUid} with mode ${expectedMode.toString(8).padStart(4, '0')}`,
    );
  }
  let source;
  try {
    source = fsImpl.readFileSync(filename, 'utf8');
  } catch (error) {
    throw new Error(`${label} cannot be read: ${error.message}`, { cause: error });
  }
  return parseAssignments(source, expectedKeys, label);
}

export function validateGuardPrefix(value, label = 'Nosh Guard prefix') {
  const prefix = String(value || '');
  if (
    !prefix.startsWith('/')
    || prefix.length > 512
    || !/^\/[A-Za-z0-9][A-Za-z0-9._+-]*(?:\/[A-Za-z0-9][A-Za-z0-9._+-]*)*$/.test(prefix)
    || prefix.includes('//')
    || prefix.endsWith('/')
    || prefix.split('/').some((part) => part === '.' || part === '..')
    || path.posix.normalize(prefix) !== prefix
    || DISALLOWED_PREFIXES.has(prefix)
  ) {
    throw new Error(
      `${label} must be a normalized absolute software prefix such as /usr/local or /opt/notty`,
    );
  }
  return prefix;
}

function validateAbsolutePath(value, label) {
  const selected = String(value || '');
  if (
    !path.isAbsolute(selected)
    || path.normalize(selected) !== selected
    || selected.includes('//')
    || (selected !== '/' && selected.endsWith('/'))
    || selected.split('/').some((part) => part === '.' || part === '..')
    || /[\x00-\x1f\x7f]/.test(selected)
  ) {
    throw new Error(`${label} must be a normalized absolute path`);
  }
  return selected;
}

export function userPathsConfigPath(options = {}) {
  const env = options.env || process.env;
  const home = options.home || os.homedir();
  const configRoot = env.XDG_CONFIG_HOME || path.join(home, '.config');
  validateAbsolutePath(configRoot, 'XDG_CONFIG_HOME');
  return path.join(configRoot, 'nosh', 'paths.conf');
}

export function readUserPathsConfig(options = {}) {
  const uid = options.uid ?? (
    typeof process.getuid === 'function' ? process.getuid() : null
  );
  if (!Number.isInteger(uid) || uid < 0) {
    throw new Error('cannot validate Nosh user paths config without a numeric uid');
  }
  const filename = options.userConfigPath || userPathsConfigPath(options);
  const values = readProtectedDataFile(filename, {
    expectedUid: uid,
    expectedMode: 0o600,
    expectedKeys: USER_PATH_KEYS,
    label: `Nosh user paths config ${filename}`,
    fsImpl: options.fsImpl,
  });
  if (!values) {
    return null;
  }
  validateAbsolutePath(values.BIN_DIR, 'BIN_DIR');
  validateAbsolutePath(values.NOSH_BIN, 'NOSH_BIN');
  validateAbsolutePath(values.NOSH_GUARD_BIN, 'NOSH_GUARD_BIN');
  const prefix = validateGuardPrefix(values.NOSH_GUARD_PREFIX, 'NOSH_GUARD_PREFIX');
  const privileged = validateAbsolutePath(
    values.NOSH_GUARD_PRIVILEGED_BIN,
    'NOSH_GUARD_PRIVILEGED_BIN',
  );
  if (privileged !== path.join(prefix, 'bin', 'nosh-guard')) {
    throw new Error(
      `Nosh user paths config ${filename} has inconsistent privileged Guard paths`,
    );
  }
  return Object.freeze({ ...values, filename });
}

export function readGuardInstallReceipt(options = {}) {
  const filename = options.receiptPath || NOSH_GUARD_LAYOUT_RECEIPT;
  const values = readProtectedDataFile(filename, {
    expectedUid: 0,
    expectedMode: 0o644,
    expectedKeys: RECEIPT_KEYS,
    label: `Nosh Guard install receipt ${filename}`,
    fsImpl: options.fsImpl,
  });
  if (!values) {
    return null;
  }
  validateGuardPrefix(values.NOSH_GUARD_PREFIX, 'receipt NOSH_GUARD_PREFIX');
  if (!/^[a-f0-9]{64}$/.test(values.MANIFEST_SHA256)) {
    throw new Error(`Nosh Guard install receipt ${filename} has an invalid manifest digest`);
  }
  return Object.freeze({ ...values, filename });
}

export function resolvePrivilegedGuardPath(options = {}) {
  if (options.guardBin) {
    return validateAbsolutePath(options.guardBin, 'privileged nosh-guard helper path');
  }
  const env = options.env || process.env;
  if (env.NOSH_GUARD_PRIVILEGED_BIN) {
    return validateAbsolutePath(
      env.NOSH_GUARD_PRIVILEGED_BIN,
      'NOSH_GUARD_PRIVILEGED_BIN',
    );
  }
  if (env.NOSH_GUARD_PREFIX) {
    return path.join(
      validateGuardPrefix(env.NOSH_GUARD_PREFIX, 'NOSH_GUARD_PREFIX'),
      'bin',
      'nosh-guard',
    );
  }
  const userConfig = readUserPathsConfig(options);
  if (userConfig) {
    return userConfig.NOSH_GUARD_PRIVILEGED_BIN;
  }
  const receipt = readGuardInstallReceipt(options);
  if (receipt) {
    return path.join(receipt.NOSH_GUARD_PREFIX, 'bin', 'nosh-guard');
  }
  return path.join(DEFAULT_NOSH_GUARD_PREFIX, 'bin', 'nosh-guard');
}
