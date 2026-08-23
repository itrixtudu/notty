import {
  createGatewayGrantArtifact,
  writeGatewayGrantArtifact,
} from './grant-service.js';

export const GATEWAY_HELP = `Usage: nosh-guard gateway grant [options]

Options:
  --policy PATH                    Verified target-review directory (required)
  --approval PATH                  Review approval DSSE envelope (required)
  --review-key PATH                Trusted review public key PEM (required)
  --review-audience NAME           Review-key audience (required for guard-ebpf)
  --deployment-key PATH            Deployment-grant private key PEM (required)
  --audience NAME                  Exact destination backend audience (required)
  --target-binding-digest SHA256   Exact backend/subject digest (required)
  --active-grant-set-digest SHA256 Current deployment grant-set digest (required)
  --ttl-seconds NUMBER             1..86400, default 3600
  --output PATH                    New private grant directory (required)
`;

function options(argv) {
  const result = {};
  const allowed = new Set([
    'policy',
    'approval',
    'review-key',
    'review-audience',
    'deployment-key',
    'audience',
    'target-binding-digest',
    'active-grant-set-digest',
    'ttl-seconds',
    'output',
  ]);
  for (let index = 0; index < argv.length; index += 1) {
    const argument = argv[index];
    if (argument === '--help' || argument === '-h') return { help: true };
    if (!argument.startsWith('--')) throw new TypeError(`unexpected positional argument: ${argument}`);
    const separator = argument.indexOf('=');
    const name = separator < 0 ? argument.slice(2) : argument.slice(2, separator);
    if (!allowed.has(name)) throw new TypeError(`gateway grant does not accept --${name}`);
    const value = separator < 0 ? argv[++index] : argument.slice(separator + 1);
    if (!value || value.startsWith('--')) throw new TypeError(`--${name} requires a value`);
    if (Object.hasOwn(result, name)) throw new TypeError(`--${name} may be supplied only once`);
    result[name] = value;
  }
  return result;
}

function required(input, name) {
  if (!input[name]) throw new TypeError(`--${name} is required`);
  return input[name];
}

export async function commandGateway(argv) {
  const [command, ...rest] = argv;
  if (!command || ['help', '--help', '-h'].includes(command)) {
    process.stdout.write(GATEWAY_HELP);
    return 0;
  }
  if (command !== 'grant') throw new TypeError(`unknown gateway command: ${command}`);
  const input = options(rest);
  if (input.help) {
    process.stdout.write(GATEWAY_HELP);
    return 0;
  }
  const artifact = await createGatewayGrantArtifact({
    policy: required(input, 'policy'),
    approval: required(input, 'approval'),
    reviewPublicKey: required(input, 'review-key'),
    reviewAudience: input['review-audience'],
    deploymentPrivateKey: required(input, 'deployment-key'),
    audience: required(input, 'audience'),
    targetBindingDigest: required(input, 'target-binding-digest'),
    activeGrantSetDigest: required(input, 'active-grant-set-digest'),
    ttlSeconds: input['ttl-seconds'],
  });
  const written = await writeGatewayGrantArtifact(required(input, 'output'), artifact);
  process.stdout.write(`${JSON.stringify({
    directory: written.directory,
    target: artifact.statement.target,
    audience: artifact.statement.audience,
    expiresAt: artifact.statement.expiresAt,
    keyId: artifact.receipt.keyId,
    grantEnvelopeDigest: artifact.receipt.grantEnvelopeDigest,
    leafBundleDigest: artifact.statement.leafBundleDigest,
  }, null, 2)}\n`);
  return 0;
}
