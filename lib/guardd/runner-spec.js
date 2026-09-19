import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';

import {
  GUARD_GATEWAY_PEER_IP_ENV,
  normalizeGuardGatewayPeerIp,
} from '../guardGatewayAuth.js';

import {
  DEFAULT_RESOURCE_LIMITS,
  GUARD_LABEL_PREFIX,
  RUNNER_IMAGE_ABI_LABEL,
  RUNNER_IMAGE_ABI_VERSION,
  RUNNER_RUNTIME_HOME,
  SECURITY_MODES,
} from './constants.js';
import { runnerPublicEnvironment } from './proxy-contract.js';

const SAFE_NAME = /[^A-Za-z0-9_.-]+/g;
const RUNNER_AUTH_STATE_DIR = '/var/lib/notty-auth';

function assertObject(value, label) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    throw new TypeError(`${label} must be an object`);
  }
}

function assertNonEmpty(value, label) {
  if (typeof value !== 'string' || !value.trim()) {
    throw new TypeError(`${label} must be a non-empty string`);
  }
}

function normalizeName(value) {
  assertNonEmpty(value, 'name');
  const normalized = value.replace(SAFE_NAME, '-').replace(/^[^A-Za-z0-9]+/, '');
  if (!normalized) {
    throw new TypeError('name does not contain a usable Docker name');
  }
  return normalized.slice(0, 128);
}

function normalizeWorkdir(value) {
  assertNonEmpty(value, 'workdir');
  const resolved = fs.realpathSync(value);
  if (/[:\r\n]/.test(resolved)) {
    throw new TypeError('workdir contains characters unsupported by Docker bind syntax');
  }
  const stat = fs.statSync(resolved);
  if (!stat.isDirectory()) {
    throw new TypeError(`workdir is not a directory: ${value}`);
  }
  return resolved;
}

function normalizeResolverConfig(value) {
  if (value == null) return null;
  assertNonEmpty(value, 'resolverConfigPath');
  const requested = path.resolve(value);
  const resolved = fs.realpathSync(value);
  if (requested !== resolved) {
    throw new TypeError('resolverConfigPath must not contain symbolic links');
  }
  if (/[:\r\n]/.test(resolved)) {
    throw new TypeError(
      'resolverConfigPath contains characters unsupported by Docker bind syntax',
    );
  }
  const stat = fs.lstatSync(resolved);
  if (!stat.isFile() || stat.isSymbolicLink()) {
    throw new TypeError('resolverConfigPath must be a regular non-symlink file');
  }
  if ((stat.mode & 0o7777) !== 0o644) {
    throw new Error('resolverConfigPath must be root-owned mode 0644');
  }
  if (
    typeof process.geteuid === 'function'
    && process.geteuid() === 0
    && stat.uid !== 0
  ) {
    throw new Error('resolverConfigPath must be root-owned mode 0644');
  }
  return resolved;
}

function currentIdentity(workdir) {
  const stat = fs.statSync(workdir);
  if (stat.uid === 0 || stat.gid === 0) {
    throw new Error(
      'guarded workdir must be owned by a non-root host user and group',
    );
  }
  return {
    uid: stat.uid,
    gid: stat.gid,
  };
}

function normalizeAuthStateDirectory(value, identity) {
  assertNonEmpty(value, 'authStateDir');
  const requested = path.resolve(value);
  const resolved = fs.realpathSync(requested);
  if (requested !== resolved || /[:\r\n]/.test(resolved)) {
    throw new TypeError('authStateDir must be a canonical path supported by Docker binds');
  }
  const stat = fs.lstatSync(resolved);
  if (stat.isSymbolicLink() || !stat.isDirectory()) {
    throw new TypeError('authStateDir must be a real directory');
  }
  if ((stat.mode & 0o7777) !== 0o700 || stat.uid !== identity.uid || stat.gid !== identity.gid) {
    throw new Error('authStateDir must be owned by the runner identity with mode 0700');
  }
  return resolved;
}

function normalizeStringArray(value, label) {
  if (value == null) {
    return [];
  }
  if (!Array.isArray(value) || value.some((item) => typeof item !== 'string')) {
    throw new TypeError(`${label} must be an array of strings`);
  }
  return [...value];
}

function normalizeEnvironment(value) {
  if (value == null) {
    return [];
  }
  assertObject(value, 'environment');
  const forbidden = new Set([
    'NOTTY_MCP_SPAWN_OTP',
    'NOTTY_MCP_SPAWN_OTP_TTL_SECONDS',
    'NOTTY_BASIC_AUTH_PASSWORD',
    'NOTTY_BASIC_AUTH_USERNAME',
    'NOTTY_MCP_AUTHORIZATION',
    'NOTTY_AUTH_STATE_DIR',
    'NOTTY_WORKSPACE_ID',
    'NOTTY_GUARD_GATEWAY_PEER_IP',
    'NOTTY_GUARD_GATEWAY_TOKEN',
    'NOTTY_NOAUTH',
    'NOTTY_NO_OAUTH',
    'NOTTY_NO_OTP_AUTH',
    'MCP_SPAWN_OTP',
    'COLLAB_AGENT_SPAWN_OTP',
    'AUTHORIZATION',
    'HTTP_AUTHORIZATION',
  ]);
  return Object.entries(value)
    .filter(([, entry]) => entry != null)
    .filter(([key]) => !forbidden.has(key) && !key.startsWith('NOTTY_OAUTH_'))
    .map(([key, entry]) => {
      if (!/^[A-Za-z_][A-Za-z0-9_]*$/.test(key)) {
        throw new TypeError(`invalid environment key: ${key}`);
      }
      return `${key}=${String(entry)}`;
    })
    .sort();
}

function runIdFor(input) {
  if (input.runId) {
    assertNonEmpty(input.runId, 'runId');
    return input.runId;
  }
  return crypto.randomUUID();
}

function buildGateCommand(command) {
  const encoded = Buffer.from(JSON.stringify(command), 'utf8').toString('base64url');
  return [
    'set -eu',
    'umask 077',
    "printf '%s\\n' 'nosh-guard: phase=gate-entered'",
    'mkdir -p "$XDG_CONFIG_HOME" "$XDG_CACHE_HOME" "$XDG_DATA_HOME" "$XDG_STATE_HOME" "$XDG_RUNTIME_DIR"',
    'chmod 0700 "$HOME" "$XDG_CONFIG_HOME" "$XDG_CACHE_HOME" "$XDG_DATA_HOME" "$XDG_STATE_HOME" "$XDG_RUNTIME_DIR"',
    "printf '%s\\n' 'nosh-guard: phase=gate-ready'",
    'while [ ! -e /run/nosh-guard/release ]; do sleep 0.05; done',
    `export NOSH_GUARD_COMMAND_B64=${encoded}`,
    'exec node -e \'const c=JSON.parse(Buffer.from(process.env.NOSH_GUARD_COMMAND_B64,"base64url"));require("node:child_process").spawn(c[0],c.slice(1),{stdio:"inherit"}).on("exit",(n,s)=>process.exitCode=n??(s?128:1))\'',
  ].join('; ');
}

function defaultRunnerCommand(startApp, appWorkdir) {
  if (startApp) {
    return ['/bin/bash', '-lc', `cd ${JSON.stringify(appWorkdir)} && exec npm run start:next:sse`];
  }
  return [
    '/bin/bash',
    '-lc',
    "trap 'exit 0' TERM INT; while sleep 3600; do :; done",
  ];
}

export function assertRunnerImageAbi(imageInfo) {
  const actual =
    imageInfo?.Config?.Labels?.[RUNNER_IMAGE_ABI_LABEL];
  if (actual !== RUNNER_IMAGE_ABI_VERSION) {
    const error = new Error(
      `guarded runner image ABI mismatch: expected ${
        RUNNER_IMAGE_ABI_LABEL
      }=${RUNNER_IMAGE_ABI_VERSION}, got ${actual == null ? 'missing' : actual}`,
    );
    error.code = 'GUARD_RUNNER_IMAGE_ABI_MISMATCH';
    error.label = RUNNER_IMAGE_ABI_LABEL;
    error.expected = RUNNER_IMAGE_ABI_VERSION;
    error.actual = actual ?? null;
    throw error;
  }
  return {
    label: RUNNER_IMAGE_ABI_LABEL,
    version: RUNNER_IMAGE_ABI_VERSION,
  };
}

export function buildRunnerSpec(input) {
  assertObject(input, 'runner request');
  if (!SECURITY_MODES.includes(input.mode)) {
    throw new TypeError(`mode must be one of: ${SECURITY_MODES.join(', ')}`);
  }
  assertNonEmpty(input.image, 'image');

  const workdir = normalizeWorkdir(input.workdir);
  const resolverConfigPath = normalizeResolverConfig(input.resolverConfigPath);
  const name = normalizeName(input.name);
  const runId = runIdFor(input);
  const agentId = input.agentId || name;
  const profileRevision = input.profileRevision || 'candidate';
  const identity = currentIdentity(workdir);
  const authStateDir = input.authStateDir
    ? normalizeAuthStateDirectory(input.authStateDir, identity)
    : null;
  const guardGatewayToken = input.guardGatewayToken == null
    ? null
    : String(input.guardGatewayToken);
  if (guardGatewayToken !== null && !/^[A-Za-z0-9_-]{43}$/.test(guardGatewayToken)) {
    throw new TypeError('guardGatewayToken must be a 256-bit base64url capability');
  }
  const configuredGuardGatewayPeerIp = input.guardGatewayPeerIp == null
    ? null
    : String(input.guardGatewayPeerIp);
  const guardGatewayPeerIp = normalizeGuardGatewayPeerIp(
    configuredGuardGatewayPeerIp,
  );
  if (
    configuredGuardGatewayPeerIp !== null
    && (
      guardGatewayPeerIp === null
      || configuredGuardGatewayPeerIp !== guardGatewayPeerIp
    )
  ) {
    throw new TypeError('guardGatewayPeerIp must be a canonical IP address');
  }
  if (Boolean(guardGatewayToken) !== Boolean(guardGatewayPeerIp)) {
    throw new TypeError(
      'guardGatewayToken and guardGatewayPeerIp must be configured together',
    );
  }
  const command = input.command
    ? normalizeStringArray(input.command, 'command')
    : defaultRunnerCommand(Boolean(input.startApp), input.appWorkdir || '/app');
  if (!command.length) {
    throw new TypeError('command must not be empty');
  }

  const limits = {
    ...DEFAULT_RESOURCE_LIMITS,
    ...(input.resources || {}),
  };
  const labels = {
    [`${GUARD_LABEL_PREFIX}.managed`]: 'true',
    [`${GUARD_LABEL_PREFIX}.component`]: 'runner',
    [`${GUARD_LABEL_PREFIX}.run-id`]: runId,
    [`${GUARD_LABEL_PREFIX}.agent-id`]: String(agentId),
    [`${GUARD_LABEL_PREFIX}.mode`]: input.mode,
    [`${GUARD_LABEL_PREFIX}.profile-revision`]: String(profileRevision),
  };
  if (input.imageDigest) {
    labels[`${GUARD_LABEL_PREFIX}.image-digest`] = String(input.imageDigest);
  }
  const environment = {
    NOTTY_SECURITY_MODE: input.mode,
    NOSH_GUARD_RUN_ID: runId,
    NOSH_GUARD_AGENT_ID: agentId,
    ...(input.mode === 'egress-enforce'
      ? { NOSH_GUARD_ENFORCEMENT_SCOPE: 'egress-only' }
      : {}),
    NOTTY_WORKDIR: workdir,
    NOTTY_APP_WORKDIR: input.appWorkdir || '/app',
    ...(input.environment || {}),
    NOTTY_BASIC_AUTH_ENABLED: 'false',
    NOTTY_GUARD_MTLS: 'true',
    NOTTY_MCP_SPAWN_OTP_ENABLED: 'true',
    HOME: RUNNER_RUNTIME_HOME,
    XDG_CACHE_HOME: `${RUNNER_RUNTIME_HOME}/.cache`,
    XDG_CONFIG_HOME: `${RUNNER_RUNTIME_HOME}/.config`,
    XDG_DATA_HOME: `${RUNNER_RUNTIME_HOME}/.local/share`,
    XDG_RUNTIME_DIR: `${RUNNER_RUNTIME_HOME}/.runtime`,
    XDG_STATE_HOME: `${RUNNER_RUNTIME_HOME}/.local/state`,
    ...(input.gatewayPublicOrigin
      ? runnerPublicEnvironment(input.gatewayPublicOrigin)
      : {}),
  };

  const securityOpt = ['no-new-privileges:true'];
  if (input.seccompDocument) {
    securityOpt.push(`seccomp=${JSON.stringify(input.seccompDocument)}`);
  }
  if (input.apparmorProfileName) {
    securityOpt.push(`apparmor=${input.apparmorProfileName}`);
  }

  const tmpfs = {
    '/run': `rw,nosuid,nodev,noexec,size=${64 * 1024 * 1024}`,
    '/tmp': `rw,nosuid,nodev,noexec,size=${limits.tmpBytes}`,
    [RUNNER_RUNTIME_HOME]:
      `rw,nosuid,nodev,noexec,size=${limits.tmpBytes},mode=0700,` +
      `uid=${identity.uid},gid=${identity.gid}`,
  };
  const networkMode = input.network || 'nosh-guard-internal';
  const networkDisabled = networkMode === 'none';

  const spec = {
    Image: input.image,
    Hostname: name,
    WorkingDir: workdir,
    User: `${identity.uid}:${identity.gid}`,
    Env: [
      ...normalizeEnvironment(environment),
      ...(authStateDir
        ? [`NOTTY_AUTH_STATE_DIR=${RUNNER_AUTH_STATE_DIR}`]
        : []),
      ...(guardGatewayToken
        ? [`NOTTY_GUARD_GATEWAY_TOKEN=${guardGatewayToken}`]
        : []),
      ...(guardGatewayPeerIp
        ? [`${GUARD_GATEWAY_PEER_IP_ENV}=${guardGatewayPeerIp}`]
        : []),
    ].sort(),
    Entrypoint: ['/bin/sh', '-c'],
    Cmd: [buildGateCommand(command)],
    Labels: labels,
    Healthcheck: {
      Test: ['CMD-SHELL', 'test -e /run/nosh-guard/release'],
      Interval: 10_000_000_000,
      Timeout: 2_000_000_000,
      Retries: 3,
      StartPeriod: 30_000_000_000,
    },
    HostConfig: {
      AutoRemove: false,
      Binds: [
        `${workdir}:${workdir}:rw`,
        ...(authStateDir ? [`${authStateDir}:${RUNNER_AUTH_STATE_DIR}:rw`] : []),
        ...(resolverConfigPath
          ? [`${resolverConfigPath}:/etc/resolv.conf:ro`]
          : []),
      ],
      CapDrop: ['ALL'],
      ...(input.cgroupParent ? { CgroupParent: input.cgroupParent } : {}),
      CgroupnsMode: 'private',
      CpuShares: 512,
      Devices: [],
      Dns: resolverConfigPath
        ? []
        : input.managedDns
          ? [input.managedDns]
          : [],
      Init: true,
      Memory: limits.memoryBytes,
      MemorySwap: limits.memoryBytes,
      NanoCpus: limits.nanoCpus,
      NetworkMode: networkMode,
      PidsLimit: limits.pids,
      PortBindings: {},
      Privileged: false,
      PublishAllPorts: false,
      ReadonlyRootfs: true,
      SecurityOpt: securityOpt,
      Tmpfs: tmpfs,
      Ulimits: [
        // RLIMIT_NPROC is cumulative for the real host UID, not scoped to
        // this container. HostConfig.PidsLimit supplies the cgroup-scoped
        // task limit without blocking a shared-UID runner before exec.
        { Name: 'nofile', Soft: 8192, Hard: 8192 },
      ],
    },
    NetworkingConfig: {
      EndpointsConfig: networkDisabled
        ? {}
        : {
          [networkMode]: input.runnerIp
            ? {
                IPAMConfig: {
                  IPv4Address: input.runnerIp,
                  ...(input.runnerIpv6
                    ? { IPv6Address: input.runnerIpv6 }
                    : {}),
                },
              }
            : {},
        },
    },
  };

  return {
    runId,
    name,
    workdir,
    mode: input.mode,
    agentId,
    profileRevision,
    command,
    spec,
  };
}

export function summarizeRunnerSpec(runner) {
  assertObject(runner, 'runner');
  return {
    runId: runner.runId,
    name: runner.name,
    mode: runner.mode,
    image: runner.spec.Image,
    user: runner.spec.User,
    workdir: runner.workdir,
    network: runner.spec.HostConfig.NetworkMode,
    readOnlyRoot: runner.spec.HostConfig.ReadonlyRootfs,
    capabilitiesDropped: runner.spec.HostConfig.CapDrop,
    securityOptions: runner.spec.HostConfig.SecurityOpt.map((entry) =>
      entry.startsWith('seccomp=') ? 'seccomp=<embedded-profile>' : entry,
    ),
    mounts: runner.spec.HostConfig.Binds,
    devices: runner.spec.HostConfig.Devices,
    publishedPorts: runner.spec.HostConfig.PortBindings,
    labels: runner.spec.Labels,
  };
}
