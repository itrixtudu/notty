import fs from 'node:fs';
import os from 'node:os';
import { spawnSync } from 'node:child_process';

import {
  DEFAULT_ADAPTER_CONFIG,
  DEFAULT_DOCKER_SOCKET,
  DEFAULT_GUARD_SOCKET,
} from './constants.js';

const REQUIRED_HEALTH_CHECKS_BY_MODE = Object.freeze({
  learn: Object.freeze(['linux', 'btf', 'cgroupV2', 'dockerSocket']),
  audit: Object.freeze([
    'linux',
    'btf',
    'cgroupV2',
    'dockerSocket',
    'tetra',
  ]),
  enforce: Object.freeze([
    'linux',
    'btf',
    'cgroupV2',
    'bpfLsm',
    'dockerSocket',
    'tetra',
    'apparmorParser',
    'standaloneIngress',
  ]),
  'egress-learn': Object.freeze([
    'linux',
    'btf',
    'cgroupV2',
    'dockerSocket',
  ]),
  'egress-audit': Object.freeze([
    'linux',
    'cgroupV2',
    'dockerSocket',
  ]),
  'egress-enforce': Object.freeze([
    'linux',
    'cgroupV2',
    'dockerSocket',
  ]),
});

export function guardModeGates(checks) {
  return Object.fromEntries(
    Object.entries(REQUIRED_HEALTH_CHECKS_BY_MODE).map(([mode, names]) => [
      mode,
      names.every((name) => checks?.[name]?.ok === true),
    ]),
  );
}

function commandCheck(command, args = ['--version']) {
  const result = spawnSync(command, args, {
    encoding: 'utf8',
    timeout: 5_000,
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  return {
    ok: result.status === 0,
    status: result.status,
    detail: String(result.stdout || result.stderr || '').trim().split('\n')[0] || null,
    error: result.error?.message || null,
  };
}

function fileCheck(filePath, mode = fs.constants.R_OK) {
  try {
    fs.accessSync(filePath, mode);
    return { ok: true, path: filePath };
  } catch (error) {
    return { ok: false, path: filePath, error: error.message };
  }
}

function readLsmList() {
  try {
    return fs.readFileSync('/sys/kernel/security/lsm', 'utf8').trim().split(',');
  } catch {
    return [];
  }
}

export function collectGuardHealth(options = {}) {
  const dockerSocket = options.dockerSocket || DEFAULT_DOCKER_SOCKET;
  const guardSocket = options.guardSocket || DEFAULT_GUARD_SOCKET;
  const adapterConfig = options.adapterConfig || DEFAULT_ADAPTER_CONFIG;
  const lsm = readLsmList();

  const checks = {
    linux: {
      ok: process.platform === 'linux',
      detail: `${process.platform}/${process.arch}`,
    },
    btf: fileCheck('/sys/kernel/btf/vmlinux'),
    cgroupV2: fileCheck('/sys/fs/cgroup/cgroup.controllers'),
    bpfLsm: {
      ok: lsm.includes('bpf'),
      detail: lsm.join(',') || null,
    },
    dockerSocket: fileCheck(dockerSocket, fs.constants.R_OK | fs.constants.W_OK),
    guardSocket: fileCheck(guardSocket, fs.constants.R_OK | fs.constants.W_OK),
    adapterConfig: fileCheck(adapterConfig),
    tetra: commandCheck('tetra', ['version']),
    inspektorGadget: commandCheck('ig', ['version']),
    nft: commandCheck('nft', ['--version']),
    apparmorParser: commandCheck('apparmor_parser', ['--version']),
    standaloneIngress: {
      ok: false,
      detail:
        'no standalone backend currently evaluates compiled ingress rules',
    },
  };

  return {
    generatedAt: new Date().toISOString(),
    kernel: os.release(),
    checks,
    gates: guardModeGates(checks),
  };
}

export function assertHealthForMode(health, mode, options = {}) {
  if (!health?.gates?.[mode] && !options.allowIncomplete) {
    const required = new Set(REQUIRED_HEALTH_CHECKS_BY_MODE[mode] || []);
    const failures = Object.entries(health?.checks || {})
      .filter(([name, check]) => required.has(name) && !check.ok)
      .map(([name]) => name);
    const error = new Error(
      `host is not qualified for ${mode} mode${
        failures.length ? `; failed checks: ${failures.join(', ')}` : ''
      }`,
    );
    error.code = 'GUARD_HOST_NOT_QUALIFIED';
    error.health = health;
    throw error;
  }
}
