#!/usr/bin/env node

import {
  applyGatewayActivation,
  createCommandRunner,
  createGatewayDiff,
  DEFAULT_GATEWAY_TRUST_PATH,
  gatewayStatus,
  loadGatewayActivation,
} from '../lib/guard/review/gateway-host.js';

export const HELP = `Usage: nosh-gateway <verify|diff|apply|status> [options]

Root-owned external gateway policy activation.

Commands:
  verify   Verify policy leaf, review approval, deployment grant, and trust bindings
  diff     Verify, validate backend syntax, and compare desired/configured/live state
  apply    Verify and apply with a source quarantine; requires root and --yes
  status   Show the active grant-set digest and fail-closed state

Activation options:
  --policy PATH       Root-owned NoshPolicyLeafBundle directory
  --approval PATH     Root-owned review-approval DSSE envelope
  --grant PATH        Root-owned short-lived gateway-grant DSSE envelope
  --trust PATH        Root-owned mode-0600 trust config
                      (default: ${DEFAULT_GATEWAY_TRUST_PATH})

Apply option:
  --yes               Confirm the fail-closed host mutation
`;

function parseArguments(command, argv) {
  const allowed = command === 'status'
    ? new Set(['trust'])
    : new Set(['approval', 'grant', 'policy', 'trust']);
  const result = {};
  for (let index = 0; index < argv.length; index += 1) {
    const argument = argv[index];
    if (argument === '--help' || argument === '-h') return { help: true };
    if (argument === '--yes') {
      if (command !== 'apply') throw new TypeError('--yes is accepted only by apply');
      if (result.yes) throw new TypeError('--yes may be supplied only once');
      result.yes = true;
      continue;
    }
    if (!argument.startsWith('--')) {
      throw new TypeError(`unexpected positional argument: ${argument}`);
    }
    const separator = argument.indexOf('=');
    const name = separator < 0 ? argument.slice(2) : argument.slice(2, separator);
    if (!allowed.has(name)) throw new TypeError(`${command} does not accept --${name}`);
    const value = separator < 0 ? argv[++index] : argument.slice(separator + 1);
    if (!value || value.startsWith('--')) throw new TypeError(`--${name} requires a value`);
    if (Object.hasOwn(result, name)) throw new TypeError(`--${name} may be supplied only once`);
    result[name] = value;
  }
  return result;
}

function required(options, name) {
  if (!options[name]) throw new TypeError(`--${name} is required`);
  return options[name];
}

function activationInput(options) {
  return {
    policy: required(options, 'policy'),
    approval: required(options, 'approval'),
    grant: required(options, 'grant'),
    trust: options.trust || DEFAULT_GATEWAY_TRUST_PATH,
  };
}

function verificationSummary(activation) {
  return {
    verified: true,
    audience: activation.trust.audience,
    target: activation.trust.target,
    leafBundleDigest: activation.policy.leaf.bundleDigest,
    graphDigest: activation.policy.policyIR.graphDigest,
    policyIrDigest: activation.policy.policyIR.contentDigest,
    targetReviewSetDigest: activation.policy.targetReviewSet.contentDigest,
    approvalEnvelopeDigest: activation.approval.envelopeDigest,
    grantEnvelopeDigest: activation.grant.envelopeDigest,
    grantExpiresAt: activation.grant.statement.expiresAt,
    activeGrantSetDigest: activation.state.activeGrantSetDigest,
  };
}

export async function main(argv = process.argv.slice(2), dependencies = {}) {
  const [command, ...rest] = argv;
  if (!command || ['help', '--help', '-h'].includes(command)) {
    process.stdout.write(HELP);
    return 0;
  }
  if (!['verify', 'diff', 'apply', 'status'].includes(command)) {
    throw new TypeError(`unknown nosh-gateway command: ${command}`);
  }
  const options = parseArguments(command, rest);
  if (options.help) {
    process.stdout.write(HELP);
    return 0;
  }
  if (command === 'status') {
    const result = await gatewayStatus({
      trust: options.trust || DEFAULT_GATEWAY_TRUST_PATH,
    }, dependencies);
    process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
    return result.status === 'quarantine-retained'
      || result.live.untrackedQuarantines.length > 0
      || result.live.trackedQuarantineMissing
      || (result.status === 'active' && result.live.matchesExpected !== true)
      ? 2
      : 0;
  }
  const activation = await loadGatewayActivation(activationInput(options), dependencies);
  if (command === 'verify') {
    process.stdout.write(`${JSON.stringify(verificationSummary(activation), null, 2)}\n`);
    return 0;
  }
  const runner = dependencies.runner || createCommandRunner();
  if (command === 'diff') {
    const result = await createGatewayDiff(activation, {
      ...dependencies,
      runner,
    });
    process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
    return result.changed ? 2 : 0;
  }
  if (options.yes !== true) throw new Error('apply requires --yes');
  const result = await applyGatewayActivation(activation, {
    ...dependencies,
    runner,
    confirmed: true,
  });
  process.stdout.write(`${JSON.stringify({
    applied: true,
    target: activation.trust.target,
    leafBundleDigest: result.state.currentLeafBundleDigest,
    grantEnvelopeDigest: result.state.currentGrantEnvelopeDigest,
    activeGrantSetDigest: result.state.activeGrantSetDigest,
    stateDigest: result.state.stateDigest,
    receipt: result.file,
  }, null, 2)}\n`);
  return 0;
}

if (import.meta.url === `file://${process.argv[1]}`) {
  main()
    .then((status) => {
      process.exitCode = status;
    })
    .catch((error) => {
      process.stderr.write(`nosh-gateway: ${error.message}\n`);
      if (process.env.NOSH_GATEWAY_DEBUG === '1') {
        process.stderr.write(`${error.stack}\n`);
      }
      process.exitCode = 1;
    });
}
