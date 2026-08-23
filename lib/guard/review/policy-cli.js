import path from 'node:path';

import { readTrustedJson } from './io.js';
import { jcsCanonicalize, sha256Digest } from './jcs.js';
import {
  createPolicyProjectionArtifact,
  writePolicyProjectionArtifact,
} from './projection-service.js';

export const POLICY_HELP = `Usage: nosh-guard policy project [options]

Options:
  --bundle PATH       Frozen Nosh review bundle (required)
  --decisions PATH    NoshPolicyDecisionSet exported by the reviewer (required)
  --target TARGET     guard-ebpf, cilium, guard-nftables, gateway-iptables,
                      gateway-pf, gateway-ipfw, gateway-ipfilter, or
                      gateway-l7-proxy (required)
  --context PATH      Target capability/identity context JSON (required)
  --output PATH       New private target-review directory (required)
`;

function parseOptions(argv) {
  const options = {};
  for (let index = 0; index < argv.length; index += 1) {
    const argument = argv[index];
    if (argument === '--help' || argument === '-h') {
      options.help = true;
      continue;
    }
    if (!argument.startsWith('--')) throw new TypeError(`unexpected positional argument: ${argument}`);
    const separator = argument.indexOf('=');
    const name = separator === -1 ? argument.slice(2) : argument.slice(2, separator);
    if (!['bundle', 'decisions', 'target', 'context', 'output'].includes(name)) {
      throw new TypeError(`policy project does not accept --${name}`);
    }
    const value = separator === -1 ? argv[++index] : argument.slice(separator + 1);
    if (!value || value.startsWith('--')) throw new TypeError(`--${name} requires a value`);
    if (Object.hasOwn(options, name)) throw new TypeError(`--${name} may be supplied only once`);
    options[name] = value;
  }
  return options;
}

function required(options, name) {
  if (typeof options[name] !== 'string' || !options[name]) {
    throw new TypeError(`--${name} is required`);
  }
  return options[name];
}

export async function commandPolicy(argv) {
  const [command, ...rest] = argv;
  if (!command || ['help', '--help', '-h'].includes(command)) {
    process.stdout.write(POLICY_HELP);
    return 0;
  }
  if (command !== 'project') throw new TypeError(`unknown policy command: ${command}`);
  const options = parseOptions(rest);
  if (options.help) {
    process.stdout.write(POLICY_HELP);
    return 0;
  }
  const loadedContext = await readTrustedJson(path.resolve(required(options, 'context')), {
    maximumBytes: 4 * 1024 * 1024,
    allowGroupRead: true,
  });
  const target = required(options, 'target') === 'guard-nft'
    ? 'guard-nftables'
    : options.target;
  const artifact = await createPolicyProjectionArtifact({
    bundle: required(options, 'bundle'),
    decisions: required(options, 'decisions'),
    target,
    context: loadedContext.document,
  });
  const written = await writePolicyProjectionArtifact(
    required(options, 'output'),
    artifact,
  );
  const projection = artifact.targetReviewSet.projections[0];
  const renderOnly = [
    'gateway-pf',
    'gateway-ipfw',
    'gateway-ipfilter',
  ].includes(projection.target) || projection.target === 'gateway-l7-proxy';
  let ebpfBinding = {};
  if (projection.target === 'guard-ebpf') {
    const nativePolicy = JSON.parse(artifact.compilerResult.artifacts['ebpf-policy.json']);
    ebpfBinding = {
      backendAbi: nativePolicy.backend.abi,
      objectDigest: nativePolicy.backend.objectDigest,
      subjectBindingDigest: sha256Digest(jcsCanonicalize(nativePolicy.subject)),
      targetBindingDigest: sha256Digest(jcsCanonicalize({
        backend: nativePolicy.backend,
        subject: nativePolicy.subject,
      })),
    };
  }
  process.stdout.write(`${JSON.stringify({
    directory: written.directory,
    target: projection.target,
    status: projection.status,
    activationEligible: projection.activationEligible,
    renderOnly,
    requiresAcknowledgement: projection.requiresAcknowledgement,
    policyIrDigest: artifact.policyIR.contentDigest,
    targetReviewSetDigest: artifact.targetReviewSet.contentDigest,
    leafBundleDigest: artifact.leaf.bundleDigest,
    ...ebpfBinding,
  }, null, 2)}\n`);
  return projection.activationEligible || renderOnly ? 0 : 2;
}
