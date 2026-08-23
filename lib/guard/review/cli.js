import crypto from 'node:crypto';
import http from 'node:http';
import net from 'node:net';
import os from 'node:os';
import fs from 'node:fs/promises';
import path from 'node:path';

import {
  readReviewBundleArtifact,
  REVIEW_VIEW_LIMITS,
} from './bundle-store.js';
import { buildAndWriteReviewBundle } from './review-service.js';
import { generateEd25519KeyPair } from './signing.js';
import { writeEd25519KeyPair } from './io.js';
import {
  createReviewApprovalArtifact,
  nonApprovableSbomDomains,
  writeReviewApprovalArtifact,
} from './approval-service.js';
import { generateBuildSboms } from './sbom.js';

export const REVIEW_HELP = `Usage: nosh-guard review <command> [options]

Commands:
  bundle   Convert a verified build profile and SBOMs into a review bundle
  inspect  Verify and summarize a review bundle
  serve    Serve one frozen semantic graph on loopback for the review UI
  keygen   Create an Ed25519 review/deployment key pair
  approve  Sign a complete decision set and activation-eligible target review
  sbom     Generate offline pinned source/final-image SPDX SBOMs

Bundle options:
  --profile PATH             Verified Nosh build profile directory (required)
  --runtime-candidate PATH   Verified image/workspace-bound egress candidate
  --output PATH              New private review bundle directory (required)
  --baseline PATH            Previously verified Nosh review bundle
  --base-policy PATH         Verified policy leaf produced from that baseline
  --baseline-override-reason TEXT
  --sbom-source PATH         SPDX or CycloneDX source SBOM
  --sbom-image PATH          SPDX or CycloneDX final-image SBOM
  --allow-missing-sbom       Preserve a review-only graph; signing remains blocked

Inspect options:
  --bundle PATH              Review bundle directory (required)
  --json                     Emit the complete materialized graph

Serve options:
  --bundle PATH              Review bundle directory (required)
  --port NUMBER              Loopback port, or 0 for an ephemeral port (default: 8765)
  --origin ORIGIN            Exact browser origin allowed by CORS
  --host HOST                Bind to loopback, 0.0.0.0, or Docker bridge IPv4
  --advertise-host HOST      URL host, or auto for one Docker bridge IPv4

Keygen options:
  --output PATH              New private key directory (required)

Approve options:
  --bundle PATH              Frozen review bundle (required)
  --decisions PATH           Complete NoshPolicyDecisionSet (required)
  --policy PATH              Verified target-review directory (required)
  --reviewer ID              Must equal the decision-set reviewer (required)
  --audience NAME            Signed review trust audience (required)
  --key PATH                 Ed25519 private key PEM (required)
  --confirmation DIGEST      Exact target-review-set digest (required)
  --output PATH              New private approval directory (required)

SBOM options:
  --context PATH             Source tree to scan (required)
  --image IMAGE              Optional locally available final image reference
  --output PATH              New private SBOM directory (required)
`;

const BOOLEAN_OPTIONS = new Set(['allow-missing-sbom', 'help', 'json']);
const REPEAT_OPTIONS = new Set();

function parseOptions(argv) {
  const options = {};
  const positionals = [];
  for (let index = 0; index < argv.length; index += 1) {
    const argument = argv[index];
    if (!argument.startsWith('--')) {
      positionals.push(argument);
      continue;
    }
    const separator = argument.indexOf('=');
    const name = (separator === -1 ? argument.slice(2) : argument.slice(2, separator));
    if (!/^[a-z][a-z0-9-]*$/.test(name)) {
      throw new TypeError(`invalid review option: ${argument}`);
    }
    if (BOOLEAN_OPTIONS.has(name)) {
      if (separator !== -1) throw new TypeError(`--${name} does not take a value`);
      if (Object.hasOwn(options, name)) {
        throw new TypeError(`--${name} may be supplied only once`);
      }
      options[name] = true;
      continue;
    }
    const value = separator === -1 ? argv[++index] : argument.slice(separator + 1);
    if (value == null || value === '' || value.startsWith('--')) {
      throw new TypeError(`--${name} requires a value`);
    }
    if (REPEAT_OPTIONS.has(name)) {
      options[name] = [...(options[name] || []), value];
    } else if (Object.hasOwn(options, name)) {
      throw new TypeError(`--${name} may be supplied only once`);
    } else {
      options[name] = value;
    }
  }
  return { options, positionals };
}

function assertAllowed(options, allowed, command) {
  for (const name of Object.keys(options)) {
    if (!allowed.has(name)) throw new TypeError(`${command} does not accept --${name}`);
  }
}

function required(options, name) {
  if (typeof options[name] !== 'string' || !options[name]) {
    throw new TypeError(`--${name} is required`);
  }
  return options[name];
}

function summary(loaded) {
  const blockingCoverage = loaded.graph.coverage.filter(
    (entry) => entry.blocking && entry.status !== 'complete',
  );
  const missingSbomCoverage = nonApprovableSbomDomains(loaded.graph);
  const blockingFindings = loaded.graph.findings.filter((entry) => entry.blocking);
  return {
    directory: loaded.directory,
    bundleId: loaded.bundle.bundleId,
    bundleDigest: loaded.bundle.bundleDigest,
    graphDigest: loaded.bundle.graphDigest,
    graphContentDigest: loaded.graph.contentDigest,
    proposalSetDigest: loaded.bundle.proposalSetDigest,
    basePolicyDigest: loaded.bundle.basePolicyDigest,
    scope: loaded.bundle.scope,
    records: Object.fromEntries(
      ['nodes', 'observations', 'coverage', 'findings', 'proposals', 'diff']
        .map((role) => [role, loaded.graph[role].length]),
    ),
    blockingCoverage: blockingCoverage.length,
    missingSbomCoverage: missingSbomCoverage.length,
    blockingFindings: blockingFindings.length,
    approvalEligible: (
      blockingCoverage.length === 0
      && missingSbomCoverage.length === 0
      && blockingFindings.length === 0
    ),
  };
}

function normalizeOrigin(value) {
  if (value == null) return null;
  let parsed;
  try {
    parsed = new URL(value);
  } catch {
    throw new TypeError('--origin must be an exact HTTP(S) origin');
  }
  if (
    !['http:', 'https:'].includes(parsed.protocol)
    || parsed.username
    || parsed.password
    || parsed.pathname !== '/'
    || parsed.search
    || parsed.hash
  ) {
    throw new TypeError('--origin must be an exact HTTP(S) origin');
  }
  return parsed.origin;
}

function tokenMatches(actual, expected) {
  const left = Buffer.from(String(actual || ''), 'utf8');
  const right = Buffer.from(expected, 'utf8');
  return left.length === right.length && crypto.timingSafeEqual(left, right);
}

function isDockerBridgeIpv4(value) {
  return net.isIP(value) === 4
    && /^172\.(1[6-9]|2[0-9]|3[0-1])\./.test(value);
}

export function resolveReviewGraphHosts(input = {}, dependencies = {}) {
  const listenHost = input.host || '127.0.0.1';
  const requestedAdvertiseHost = input.advertiseHost || listenHost;
  if (net.isIP(listenHost) !== 4) {
    throw new TypeError('review graph host must be an IPv4 address');
  }
  if (![
    '0.0.0.0',
    '127.0.0.1',
  ].includes(listenHost) && !isDockerBridgeIpv4(listenHost)) {
    throw new TypeError(
      'review graph host must be loopback, wildcard, or a Docker bridge address',
    );
  }

  let advertiseHost = requestedAdvertiseHost;
  if (requestedAdvertiseHost === 'auto') {
    if (listenHost !== '0.0.0.0') {
      throw new TypeError(
        'review graph advertised host auto requires the wildcard bind host',
      );
    }
    const networkInterfaces = dependencies.networkInterfaces || os.networkInterfaces;
    if (typeof networkInterfaces !== 'function') {
      throw new TypeError('review graph network interface resolver is unavailable');
    }
    const candidates = new Set();
    for (const addresses of Object.values(networkInterfaces() || {})) {
      if (!Array.isArray(addresses)) continue;
      for (const address of addresses) {
        if (
          address
          && (address.family === 'IPv4' || address.family === 4)
          && address.internal !== true
          && typeof address.address === 'string'
          && isDockerBridgeIpv4(address.address)
        ) {
          candidates.add(address.address);
        }
      }
    }
    if (candidates.size !== 1) {
      throw new TypeError(
        `review graph advertised host auto requires exactly one Docker bridge address; found ${candidates.size}`,
      );
    }
    [advertiseHost] = candidates;
  } else if (listenHost === '0.0.0.0') {
    throw new TypeError(
      'review graph wildcard bind requires automatic Docker bridge advertisement',
    );
  }

  if (!(advertiseHost === '127.0.0.1' || isDockerBridgeIpv4(advertiseHost))) {
    throw new TypeError('review graph advertised host must be loopback or a Docker bridge address');
  }
  if (listenHost !== '0.0.0.0' && advertiseHost !== listenHost) {
    throw new TypeError('review graph advertised host must match its bind host');
  }
  return { listenHost, advertiseHost };
}

export async function listenReviewGraph(input, dependencies = {}) {
  const { listenHost, advertiseHost } = resolveReviewGraphHosts(input, dependencies);
  const token = input.token || crypto.randomBytes(32).toString('hex');
  if (!/^[a-f0-9]{64}$/.test(token)) throw new TypeError('review server token is invalid');
  const origin = normalizeOrigin(input.origin);
  const port = input.port ?? 8765;
  if (!Number.isSafeInteger(port) || port < 0 || port > 65535) {
    throw new TypeError('review server port must be from 0 through 65535');
  }
  const loaded = await readReviewBundleArtifact(input.bundle);
  const graphBytes = Buffer.from(`${JSON.stringify(loaded.graph)}\n`, 'utf8');
  if (graphBytes.length > REVIEW_VIEW_LIMITS.bytes) {
    throw new Error('materialized graph exceeds the browser-serving byte limit');
  }
  const server = http.createServer((request, response) => {
    response.setHeader('Cache-Control', 'no-store');
    response.setHeader('X-Content-Type-Options', 'nosniff');
    response.setHeader('Content-Security-Policy', "default-src 'none'; frame-ancestors 'none'");
    const requestOrigin = request.headers.origin || null;
    if (requestOrigin && requestOrigin !== origin) {
      response.writeHead(403, { 'Content-Type': 'application/json' });
      response.end('{"error":"origin not allowed"}\n');
      return;
    }
    if (origin) {
      response.setHeader('Access-Control-Allow-Origin', origin);
      response.setHeader('Vary', 'Origin');
    }
    if (request.method === 'OPTIONS' && origin) {
      response.writeHead(204, {
        'Access-Control-Allow-Methods': 'GET',
        'Access-Control-Allow-Headers': 'Content-Type',
      });
      response.end();
      return;
    }
    const url = new URL(request.url || '/', 'http://127.0.0.1');
    const match = url.search
      ? null
      : /^\/v1\/graph\/([a-f0-9]{64})$/.exec(url.pathname);
    if (request.method !== 'GET' || !match || !tokenMatches(match[1], token)) {
      response.writeHead(404, { 'Content-Type': 'application/json' });
      response.end('{"error":"not found"}\n');
      return;
    }
    response.writeHead(200, {
      'Content-Type': 'application/json; charset=utf-8',
      'Content-Length': String(graphBytes.length),
    });
    response.end(graphBytes);
  });
  await new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(port, listenHost, resolve);
  });
  const address = server.address();
  return {
    server,
    loaded,
    url: `http://${advertiseHost}:${address.port}/v1/graph/${token}`,
  };
}

async function waitForServer(server) {
  await new Promise((resolve, reject) => {
    const stop = () => server.close((error) => (error ? reject(error) : resolve()));
    process.once('SIGINT', stop);
    process.once('SIGTERM', stop);
  });
}

async function commandBundle(options) {
  assertAllowed(options, new Set([
    'profile',
    'runtime-candidate',
    'output',
    'baseline',
    'base-policy',
    'baseline-override-reason',
    'sbom-source',
    'sbom-image',
    'allow-missing-sbom',
  ]), 'review bundle');
  if (options['baseline-override-reason'] && !options.baseline) {
    throw new TypeError('--baseline-override-reason requires --baseline');
  }
  const sboms = [];
  if (options['sbom-source']) sboms.push({ role: 'source', file: options['sbom-source'] });
  if (options['sbom-image']) sboms.push({ role: 'image', file: options['sbom-image'] });
  const result = await buildAndWriteReviewBundle({
    profile: required(options, 'profile'),
    runtimeCandidate: options['runtime-candidate'],
    output: required(options, 'output'),
    baseline: options.baseline,
    basePolicy: options['base-policy'],
    baselineOverrideReason: options['baseline-override-reason'],
    sboms,
    requireSbom: options['allow-missing-sbom'] !== true,
  });
  process.stdout.write(`${JSON.stringify(summary(result.written), null, 2)}\n`);
  return summary(result.written).approvalEligible ? 0 : 2;
}

async function commandInspect(options) {
  assertAllowed(options, new Set(['bundle', 'json']), 'review inspect');
  const loaded = await readReviewBundleArtifact(required(options, 'bundle'));
  process.stdout.write(`${JSON.stringify(options.json ? loaded.graph : summary(loaded), null, 2)}\n`);
  return summary(loaded).approvalEligible ? 0 : 2;
}

async function commandServe(options) {
  assertAllowed(options, new Set(['bundle', 'port', 'origin', 'host', 'advertise-host']), 'review serve');
  if (options.port != null && !/^(0|[1-9][0-9]{0,4})$/.test(options.port)) {
    throw new TypeError('--port must be a canonical decimal port');
  }
  const port = options.port == null ? 8765 : Number(options.port);
  const running = await listenReviewGraph({
    bundle: required(options, 'bundle'),
    port,
    origin: options.origin,
    host: options.host,
    advertiseHost: options['advertise-host'],
  });
  process.stdout.write(`Nosh policy review graph: ${running.url}\n`);
  await waitForServer(running.server);
  return 0;
}

async function commandKeygen(options) {
  assertAllowed(options, new Set(['output']), 'review keygen');
  const output = path.resolve(required(options, 'output'));
  await fs.lstat(path.dirname(output));
  const written = await writeEd25519KeyPair(output, generateEd25519KeyPair());
  process.stdout.write(`${JSON.stringify({ directory: written.directory, keyId: written.keyId }, null, 2)}\n`);
  return 0;
}

async function commandApprove(options) {
  assertAllowed(options, new Set([
    'bundle',
    'decisions',
    'policy',
    'reviewer',
    'audience',
    'key',
    'confirmation',
    'output',
  ]), 'review approve');
  const artifact = await createReviewApprovalArtifact({
    bundle: required(options, 'bundle'),
    decisions: required(options, 'decisions'),
    policy: required(options, 'policy'),
    reviewer: required(options, 'reviewer'),
    audience: required(options, 'audience'),
    privateKey: required(options, 'key'),
    confirmation: required(options, 'confirmation'),
  });
  const written = await writeReviewApprovalArtifact(
    required(options, 'output'),
    artifact,
  );
  process.stdout.write(`${JSON.stringify({
    directory: written.directory,
    reviewer: artifact.statement.reviewer,
    audience: artifact.statement.audience,
    keyId: artifact.receipt.keyId,
    approvalEnvelopeDigest: artifact.receipt.approvalEnvelopeDigest,
    targetReviewSetDigest: artifact.statement.targetReviewSetDigest,
    leafBundleDigest: artifact.receipt.leafBundleDigest,
  }, null, 2)}\n`);
  return 0;
}

async function commandSbom(options) {
  assertAllowed(options, new Set(['context', 'image', 'output']), 'review sbom');
  const generated = await generateBuildSboms({
    context: required(options, 'context'),
    imageReference: options.image,
    output: required(options, 'output'),
  });
  process.stdout.write(`${JSON.stringify(generated, null, 2)}\n`);
  return 0;
}

export async function commandReview(argv) {
  const [command, ...rest] = argv;
  if (!command) {
    process.stdout.write(REVIEW_HELP);
    return 0;
  }
  if (['help', '--help', '-h'].includes(command)) {
    if (rest.length) {
      throw new TypeError(`review ${command} does not accept other arguments`);
    }
    process.stdout.write(REVIEW_HELP);
    return 0;
  }
  const commands = new Set([
    'bundle',
    'inspect',
    'serve',
    'keygen',
    'approve',
    'sbom',
  ]);
  if (!commands.has(command)) {
    throw new TypeError(`unknown review command: ${command}`);
  }
  const { options, positionals } = parseOptions(rest);
  if (options.help) {
    if (Object.keys(options).length !== 1 || positionals.length) {
      throw new TypeError(`review ${command} --help does not accept other arguments`);
    }
    process.stdout.write(REVIEW_HELP);
    return 0;
  }
  if (positionals.length) throw new TypeError(`review ${command} does not accept positional arguments`);
  if (command === 'bundle') return commandBundle(options);
  if (command === 'inspect') return commandInspect(options);
  if (command === 'serve') return commandServe(options);
  if (command === 'keygen') return commandKeygen(options);
  if (command === 'approve') return commandApprove(options);
  if (command === 'sbom') return commandSbom(options);
  throw new TypeError(`unknown review command: ${command}`);
}
