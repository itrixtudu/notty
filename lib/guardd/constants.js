import path from 'node:path';

export const GUARD_SCHEMA_VERSION = 1;
export const MANAGED_GATEWAY_EVIDENCE_MAX_BYTES = 256 * 1024 * 1024;
export const FULL_SECURITY_MODES = Object.freeze([
  'learn',
  'audit',
  'enforce',
]);
export const EGRESS_SECURITY_MODES = Object.freeze([
  'egress-learn',
  'egress-audit',
  'egress-enforce',
]);
export const SECURITY_MODES = Object.freeze([
  ...FULL_SECURITY_MODES,
  ...EGRESS_SECURITY_MODES,
]);
export const RUN_ACTIONS = Object.freeze(['start', 'attach', 'stop', 'rm', 'recreate']);

export const DEFAULT_GUARD_SOCKET =
  process.env.NOSH_GUARD_SOCKET || '/run/nosh-guardd.sock';
export const DEFAULT_GUARD_STATE_DIR =
  process.env.NOSH_GUARD_STATE_DIR || '/var/lib/nosh-guard';
export const DEFAULT_GUARD_PROFILE_DIR = path.join(
  DEFAULT_GUARD_STATE_DIR,
  'profiles',
);
export const DEFAULT_GUARD_CONFIG_DIR =
  process.env.NOSH_GUARD_CONFIG_DIR || '/etc/nosh-guard';
export const DEFAULT_DOCKER_SOCKET =
  process.env.NOSH_GUARD_DOCKER_SOCKET || '/var/run/docker.sock';

export const DEFAULT_ADAPTER_CONFIG = path.join(
  DEFAULT_GUARD_CONFIG_DIR,
  'adapters.json',
);
export const DEFAULT_BUILD_ADAPTER_CONFIG =
  process.env.NOSH_GUARD_BUILD_ADAPTER_CONFIG || path.join(
    DEFAULT_GUARD_CONFIG_DIR,
    'build-adapters.json',
  );

export const GUARD_LABEL_PREFIX = 'io.notty.guard';
export const RUNNER_IMAGE_ABI_LABEL = `${GUARD_LABEL_PREFIX}.runner-abi`;
export const RUNNER_IMAGE_ABI_VERSION = '1';
export const EGRESS_IMAGE_ABI_LABEL = `${GUARD_LABEL_PREFIX}.egress-abi`;
export const EGRESS_IMAGE_ABI_VERSION = '1';
export const RUNNER_RUNTIME_HOME = '/home/nosh-guard';

export const DEFAULT_RESOURCE_LIMITS = Object.freeze({
  memoryBytes: 4 * 1024 * 1024 * 1024,
  nanoCpus: 2_000_000_000,
  pids: 512,
  tmpBytes: 512 * 1024 * 1024,
});

export const INVARIANT_BLOCKED_CIDRS = Object.freeze([
  '0.0.0.0/8',
  '10.0.0.0/8',
  '100.64.0.0/10',
  '127.0.0.0/8',
  '169.254.0.0/16',
  '172.16.0.0/12',
  '192.168.0.0/16',
  '224.0.0.0/4',
  '::/128',
  '::1/128',
  'fc00::/7',
  'fe80::/10',
  'ff00::/8',
]);
