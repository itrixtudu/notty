#!/usr/bin/env node

import { spawnSync } from 'node:child_process';
import process from 'node:process';
import { pathToFileURL } from 'node:url';

const MODE_NAMES = Object.freeze({
  enforce: 'TP_MODE_ENFORCE',
  monitor: 'TP_MODE_MONITOR',
  monitor_only: 'TP_MODE_MONITOR_ONLY',
});

function usage() {
  return `Usage: nosh-guard-tetragon-verify --policy-name NAME [options]

Verify that one exact Tetragon policy is loaded, enabled, and in the expected
mode. The command prints a JSON attestation on success and changes no state.

Options:
  --policy-name NAME       exact runtime tracing-policy name (required)
  --server-address URI     Tetragon gRPC address
  --expected-mode MODE     enforce, monitor, or monitor_only (default: enforce)
  --timeout-ms NUMBER      bounded verification window (default: 5000)
  --tetra PATH             tetra executable (default: tetra)
  -h, --help               show this help
`;
}

function requireValue(argv, index, option) {
  const value = argv[index + 1];
  if (!value || value.startsWith('--')) {
    throw new TypeError(`${option} requires a value`);
  }
  return value;
}

export function parseArguments(argv) {
  const options = {
    expectedMode: 'enforce',
    serverAddress:
      process.env.NOSH_GUARD_TETRAGON_ADDRESS ||
      'unix:///run/nosh-guard/tetragon/tetragon.sock',
    tetra: process.env.NOSH_GUARD_TETRA_BIN || 'tetra',
    timeoutMs: 5_000,
  };
  for (let index = 0; index < argv.length; index += 1) {
    const argument = argv[index];
    if (argument === '-h' || argument === '--help') {
      options.help = true;
      continue;
    }
    if (argument === '--policy-name') {
      options.policyName = requireValue(argv, index, argument);
      index += 1;
      continue;
    }
    if (argument === '--server-address') {
      options.serverAddress = requireValue(argv, index, argument);
      index += 1;
      continue;
    }
    if (argument === '--expected-mode') {
      options.expectedMode = requireValue(argv, index, argument);
      index += 1;
      continue;
    }
    if (argument === '--timeout-ms') {
      options.timeoutMs = Number(requireValue(argv, index, argument));
      index += 1;
      continue;
    }
    if (argument === '--tetra') {
      options.tetra = requireValue(argv, index, argument);
      index += 1;
      continue;
    }
    throw new TypeError(`unknown option: ${argument}`);
  }
  if (options.help) {
    return options;
  }
  if (!options.policyName) {
    throw new TypeError('--policy-name is required');
  }
  if (!MODE_NAMES[options.expectedMode]) {
    throw new TypeError(
      '--expected-mode must be enforce, monitor, or monitor_only',
    );
  }
  if (
    !Number.isSafeInteger(options.timeoutMs) ||
    options.timeoutMs < 1 ||
    options.timeoutMs > 30_000
  ) {
    throw new TypeError('--timeout-ms must be an integer from 1 to 30000');
  }
  return options;
}

function readPolicyList(options, spawnSyncImpl) {
  const result = spawnSyncImpl(
    options.tetra,
    [
      '--server-address',
      options.serverAddress,
      'tracingpolicy',
      'list',
      '--output',
      'json',
    ],
    {
      encoding: 'utf8',
      timeout: Math.min(options.timeoutMs, 5_000),
      stdio: ['ignore', 'pipe', 'pipe'],
    },
  );
  if (result.status !== 0) {
    throw new Error(
      `tetra tracingpolicy list failed: ${
        result.error?.message ||
        String(result.stderr || '').trim() ||
        `status ${result.status}`
      }`,
    );
  }
  let document;
  try {
    document = JSON.parse(String(result.stdout || '').trim());
  } catch (error) {
    throw new Error(`tetra returned invalid policy JSON: ${error.message}`);
  }
  if (!Array.isArray(document.policies)) {
    throw new Error('tetra policy JSON has no policies array');
  }
  return document.policies;
}

function terminalPolicyError(policy, expectedMode) {
  if (policy.error) {
    return `policy reports an error: ${policy.error}`;
  }
  if (policy.enabled !== true && policy.state !== 'TP_STATE_LOADING') {
    return 'policy enabled flag is not true';
  }
  if (
    ['TP_STATE_LOAD_ERROR', 'TP_STATE_ERROR', 'TP_STATE_DISABLED', 'TP_STATE_SKIPPED']
      .includes(policy.state)
  ) {
    return `policy is not enabled: ${policy.state}`;
  }
  if (
    policy.mode &&
    policy.mode !== expectedMode &&
    policy.state !== 'TP_STATE_LOADING'
  ) {
    return `policy mode is ${policy.mode}, expected ${expectedMode}`;
  }
  return null;
}

export async function verifyTetragonPolicy(options, dependencies = {}) {
  const spawnSyncImpl = dependencies.spawnSyncImpl || spawnSync;
  const wait =
    dependencies.wait ||
    ((milliseconds) =>
      new Promise((resolve) => {
        setTimeout(resolve, milliseconds);
      }));
  const now = dependencies.now || Date.now;
  const expectedMode = MODE_NAMES[options.expectedMode];
  const deadline = now() + options.timeoutMs;
  let lastDetail = 'policy was not returned by Tetragon';

  while (now() <= deadline) {
    let policies;
    try {
      policies = readPolicyList(options, spawnSyncImpl);
    } catch (error) {
      lastDetail = error.message;
      policies = [];
    }
    const matches = policies.filter(
      (policy) => policy?.name === options.policyName,
    );
    if (matches.length > 1) {
      throw new Error(
        `Tetragon returned ${matches.length} policies named ${options.policyName}`,
      );
    }
    if (matches.length === 1) {
      const policy = matches[0];
      const terminalError = terminalPolicyError(policy, expectedMode);
      if (terminalError) {
        throw new Error(`${options.policyName}: ${terminalError}`);
      }
      if (
        policy.enabled === true &&
        policy.state === 'TP_STATE_ENABLED' &&
        policy.mode === expectedMode
      ) {
        return {
          schemaVersion: 1,
          source: 'tetragon-enforce-policy',
          verifiedAt: new Date(now()).toISOString(),
          serverAddress: options.serverAddress,
          policy: {
            id: String(policy.id || ''),
            name: policy.name,
            namespace: policy.namespace || '',
            domain: policy.domain || '',
            state: policy.state,
            mode: policy.mode,
            enabled: policy.enabled === true,
            kernelMemoryBytes: String(policy.kernel_memory_bytes || '0'),
          },
        };
      }
      lastDetail = `state=${policy.state || 'unknown'} mode=${
        policy.mode || 'unknown'
      }`;
    }
    if (now() >= deadline) {
      break;
    }
    await wait(Math.min(250, Math.max(1, deadline - now())));
  }
  throw new Error(
    `policy ${options.policyName} was not enabled in ${expectedMode}: ${lastDetail}`,
  );
}

export async function main(argv = process.argv.slice(2)) {
  let options;
  try {
    options = parseArguments(argv);
  } catch (error) {
    process.stderr.write(`nosh-guard-tetragon-verify: ${error.message}\n`);
    process.stderr.write(usage());
    return 2;
  }
  if (options.help) {
    process.stdout.write(usage());
    return 0;
  }
  try {
    const attestation = await verifyTetragonPolicy(options);
    process.stdout.write(`${JSON.stringify(attestation)}\n`);
    return 0;
  } catch (error) {
    process.stderr.write(`nosh-guard-tetragon-verify: ${error.message}\n`);
    return 1;
  }
}

const invokedPath = process.argv[1]
  ? pathToFileURL(process.argv[1]).href
  : null;
if (invokedPath === import.meta.url) {
  process.exitCode = await main();
}
