import { spawnSync } from 'node:child_process';
import fsSync from 'node:fs';
import fs from 'node:fs/promises';
import net from 'node:net';
import path from 'node:path';

import { sha256 } from '../guard/stable.js';
import {
  createBuildHttpObservations,
  createHttpEvidenceSourceDescriptor,
  httpDownstreamCorrelationHint,
  httpRequestIdentityKey,
  parseHttpEvidenceNdjson,
} from './http-evidence.js';
import { HttpContentStore, verifyHttpContentManifest } from './http-content-store.js';

export const MANAGED_MITMPROXY_IMAGE =
  'mitmproxy/mitmproxy:12.2.3@sha256:00b77b5d8804c8ad18cb6caefbf9d5849e895e8986c5ce011f4ae30f4385962f';
export const HTTP_CAPTURE_DOCKERFILE_MARKER = 'nosh-http-capture-ca-secret=v1';
export const HTTP_CAPTURE_PROXY_ALIAS = 'nosh-http-proxy';
export const HTTP_CAPTURE_PROXY_PORT = 8080;

const MAX_HTTP_EVIDENCE_BYTES = 128 * 1024 * 1024;
const STARTUP_ATTEMPTS = 100;
const STARTUP_INTERVAL_MS = 100;

function safeName(prefix, value) {
  return `${prefix}-${sha256(String(value)).slice('sha256:'.length, 'sha256:'.length + 20)}`;
}

function commandError(args, result) {
  const detail = String(result.stderr || result.stdout || '')
    .replace(/[\x00-\x1f\x7f]+/g, ' ')
    .replace(/\s+/g, ' ')
    .trim()
    .slice(0, 512);
  const error = new Error(
    `docker ${args.join(' ')} failed with status ${result.status}${
      detail ? `: ${detail}` : ''
    }`,
  );
  error.status = result.status;
  return error;
}

function managedCaptureError(primary, cleanupFailures, resources, message) {
  const selectedPrimary = primary instanceof Error
    ? primary
    : new Error(String(primary));
  const selected = cleanupFailures.length > 0
    ? new AggregateError([selectedPrimary, ...cleanupFailures], message)
    : selectedPrimary;
  selected.managedHttpResources = Object.freeze({ ...resources });
  return selected;
}

function cleanupDocker(args, dependencies, options = {}) {
  try {
    const result = docker(args, dependencies, { allowFailure: true });
    if (
      result.status === 0
      || (
        options.missingContainerIsClean === true
        && /no such container/i.test(String(result.stderr || result.stdout || ''))
      )
    ) return null;
    return commandError(args, result);
  } catch (error) {
    return error instanceof Error ? error : new Error(String(error));
  }
}

function docker(args, dependencies = {}, { allowFailure = false } = {}) {
  const result = (dependencies.spawnSyncImpl || spawnSync)('docker', args, {
    encoding: 'utf8',
    maxBuffer: 4 * 1024 * 1024,
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  if (result.error) throw result.error;
  if (result.status !== 0 && !allowFailure) throw commandError(args, result);
  return result;
}

function delay(milliseconds) {
  return new Promise((resolve) => setTimeout(resolve, milliseconds));
}

async function secureDirectory(directory) {
  await fs.mkdir(directory, { recursive: true, mode: 0o700 });
  const resolved = path.resolve(directory);
  const canonical = await fs.realpath(resolved);
  const details = await fs.lstat(resolved);
  const expectedUid = typeof process.getuid === 'function' ? process.getuid() : details.uid;
  if (
    canonical !== resolved
    || !details.isDirectory()
    || details.isSymbolicLink()
    || details.uid !== expectedUid
  ) {
    throw new Error(`managed HTTP capture directory is not trusted: ${resolved}`);
  }
  await fs.chmod(resolved, 0o700);
  return resolved;
}

async function assertCaptureDockerfile(dockerfile) {
  const handle = await fs.open(
    dockerfile,
    fsSync.constants.O_RDONLY | (fsSync.constants.O_NOFOLLOW || 0),
  );
  try {
    const details = await handle.stat();
    if (!details.isFile() || details.size > 16 * 1024 * 1024) {
      throw new Error('HTTP capture Dockerfile is not a bounded regular file');
    }
    const content = await handle.readFile('utf8');
    if (!content.split(/\r?\n/).some((line) => (
      line.trim() === `# ${HTTP_CAPTURE_DOCKERFILE_MARKER}`
    ))) {
      throw new Error(
        `managed HTTP capture requires Dockerfile opt-in marker: # ${HTTP_CAPTURE_DOCKERFILE_MARKER}`,
      );
    }
  } finally {
    await handle.close();
  }
}

async function trustedPublicCa(file) {
  const handle = await fs.open(
    file,
    fsSync.constants.O_RDONLY | (fsSync.constants.O_NOFOLLOW || 0),
  );
  try {
    const details = await handle.stat();
    const expectedUid = typeof process.getuid === 'function' ? process.getuid() : details.uid;
    if (
      !details.isFile()
      || details.isSymbolicLink?.()
      || details.nlink !== 1
      || details.uid !== expectedUid
      || details.size < 256
      || details.size > 1024 * 1024
    ) {
      throw new Error('managed HTTP capture public CA is not a trusted regular file');
    }
    const content = await handle.readFile();
    if (!content.includes(Buffer.from('BEGIN CERTIFICATE'))) {
      throw new Error('managed HTTP capture public CA is not PEM encoded');
    }
    return { content, digest: sha256(content) };
  } finally {
    await handle.close();
  }
}

async function waitForReady(session, dependencies) {
  let lastError = null;
  for (let attempt = 0; attempt < STARTUP_ATTEMPTS; attempt += 1) {
    const inspected = docker([
      'inspect',
      '--format', '{{json .State.Running}}',
      session.containerName,
    ], dependencies, { allowFailure: true });
    if (inspected.status !== 0 || String(inspected.stdout).trim() !== 'true') {
      throw new Error('managed HTTP capture container exited before readiness');
    }
    try {
      const ca = await trustedPublicCa(session.caPath);
      const socket = docker([
        'exec', session.containerName,
        'python3', '-c',
        `import socket;s=socket.create_connection(('127.0.0.1',${HTTP_CAPTURE_PROXY_PORT}),1);s.close()`,
      ], dependencies, { allowFailure: true });
      if (socket.status === 0) return ca;
      lastError = new Error('managed HTTP proxy socket is not accepting connections');
    } catch (error) {
      if (error.code !== 'ENOENT') lastError = error;
    }
    await delay(STARTUP_INTERVAL_MS);
  }
  throw new Error(
    `managed HTTP capture did not become ready${lastError ? `: ${lastError.message}` : ''}`,
  );
}

function repositoryScripts(input) {
  const scriptsDirectory = path.resolve(input.scriptsDirectory);
  const wrapper = path.join(scriptsDirectory, 'nosh-mitmproxy-capture.sh');
  const addon = path.join(scriptsDirectory, 'nosh-mitmproxy-addon.py');
  for (const file of [wrapper, addon]) {
    const details = fsSync.lstatSync(file);
    if (!details.isFile() || details.isSymbolicLink()) {
      throw new Error(`managed HTTP capture component is unsafe: ${file}`);
    }
  }
  return {
    wrapper,
    addon,
    collectorWrapperDigest: sha256(fsSync.readFileSync(wrapper)),
    collectorAddonDigest: sha256(fsSync.readFileSync(addon)),
  };
}

export async function startManagedHttpCapture(input, dependencies = {}) {
  if (!input || typeof input !== 'object' || Array.isArray(input)) {
    throw new TypeError('managed HTTP capture input is required');
  }
  if (!/^[A-Za-z0-9_.-]{1,128}$/.test(input.runId || '')) {
    throw new TypeError('managed HTTP capture runId is invalid');
  }
  await assertCaptureDockerfile(path.resolve(input.dockerfile));
  const root = await secureDirectory(path.join(path.resolve(input.bundleDir), 'http-capture'));
  const casRoot = await secureDirectory(path.join(root, 'cas'));
  const confdir = await secureDirectory(path.join(root, 'conf'));
  const evidencePath = path.join(root, 'http.ndjson');
  const caPath = path.join(confdir, 'mitmproxy-ca-cert.pem');
  const networkName = safeName('nosh-http-net', input.runId);
  const containerName = safeName('nosh-http-proxy', input.runId);
  const scripts = repositoryScripts(input);
  const image = input.image || MANAGED_MITMPROXY_IMAGE;
  if (image !== MANAGED_MITMPROXY_IMAGE) {
    throw new TypeError('managed HTTP capture image must match the exact pinned image');
  }
  const collectorIdentity = {
    collectorImageDigest: MANAGED_MITMPROXY_IMAGE.split('@')[1],
    collectorAddonDigest: scripts.collectorAddonDigest,
    collectorWrapperDigest: scripts.collectorWrapperDigest,
  };
  const uid = typeof process.getuid === 'function' ? process.getuid() : 0;
  const gid = typeof process.getgid === 'function' ? process.getgid() : 0;
  let networkCreated = false;
  let containerStarted = false;
  let runAttempted = false;
  try {
    const imageInspection = docker(
      ['image', 'inspect', MANAGED_MITMPROXY_IMAGE],
      dependencies,
      { allowFailure: true },
    );
    if (imageInspection.status !== 0) {
      throw new Error(
        `managed HTTP capture image is not locally available: ${MANAGED_MITMPROXY_IMAGE}`,
      );
    }
    docker([
      'network', 'create',
      '--driver', 'bridge',
      '--label', `io.notty.guard.http-run=${input.runId}`,
      networkName,
    ], dependencies);
    networkCreated = true;
    runAttempted = true;
    docker([
      'run', '--detach', '--rm',
      '--pull=never',
      '--name', containerName,
      '--network', networkName,
      '--network-alias', HTTP_CAPTURE_PROXY_ALIAS,
      '--user', `${uid}:${gid}`,
      '--read-only',
      '--cap-drop', 'ALL',
      '--security-opt', 'no-new-privileges=true',
      '--tmpfs', '/tmp:rw,nosuid,nodev,noexec,size=64m,mode=1777',
      '--mount', `type=bind,src=${root},dst=/private`,
      '--mount', `type=bind,src=${scripts.wrapper},dst=/usr/local/libexec/nosh-mitmproxy-capture,readonly`,
      '--mount', `type=bind,src=${scripts.addon},dst=/usr/local/libexec/nosh-mitmproxy-addon.py,readonly`,
      '--entrypoint', '/usr/local/libexec/nosh-mitmproxy-capture',
      image,
      '--run-id', input.runId,
      '--run-root', '/private',
      '--evidence', '/private/http.ndjson',
      '--cas-root', '/private/cas',
      '--confdir', '/private/conf',
      '--mode', 'observe',
      '--listen-host', '0.0.0.0',
      '--listen-port', String(HTTP_CAPTURE_PROXY_PORT),
      '--addon', '/usr/local/libexec/nosh-mitmproxy-addon.py',
      '--image-digest', collectorIdentity.collectorImageDigest,
      '--addon-digest', collectorIdentity.collectorAddonDigest,
      '--wrapper-digest', collectorIdentity.collectorWrapperDigest,
    ], dependencies);
    containerStarted = true;
    const ca = await waitForReady({ containerName, caPath }, dependencies);
    const addressResult = docker([
      'inspect',
      '--format', `{{with index .NetworkSettings.Networks "${networkName}"}}{{.IPAddress}}{{end}}`,
      containerName,
    ], dependencies);
    const proxyIpv4 = String(addressResult.stdout || '').trim();
    if (net.isIP(proxyIpv4) !== 4) {
      throw new Error('managed HTTP capture did not receive an exact bridge IPv4 address');
    }
    return {
      runId: input.runId,
      root,
      casRoot,
      confdir,
      evidencePath,
      caPath,
      caDigest: ca.digest,
      networkName,
      containerName,
      proxyAlias: HTTP_CAPTURE_PROXY_ALIAS,
      proxyIpv4,
      proxyPort: HTTP_CAPTURE_PROXY_PORT,
      collectorIdentity,
      stopped: false,
      networkCreated,
      containerStarted,
    };
  } catch (error) {
    const cleanupFailures = [];
    if (runAttempted) {
      const cleanupError = cleanupDocker(
        ['rm', '--force', containerName],
        dependencies,
        { missingContainerIsClean: true },
      );
      if (cleanupError) cleanupFailures.push(cleanupError);
      else {
        containerStarted = false;
        runAttempted = false;
      }
    }
    if (networkCreated) {
      const cleanupError = cleanupDocker(['network', 'rm', networkName], dependencies);
      if (cleanupError) cleanupFailures.push(cleanupError);
      else networkCreated = false;
    }
    throw managedCaptureError(error, cleanupFailures, {
      containerName,
      containerMayExist: runAttempted || containerStarted,
      networkName,
      networkMayExist: networkCreated,
    }, 'managed HTTP capture startup and cleanup failed');
  }
}

export function managedHttpBuildOptions(session) {
  if (!session || session.stopped) {
    throw new TypeError('active managed HTTP capture session is required');
  }
  const proxyUrl = `http://${session.proxyAlias}:${session.proxyPort}`;
  return {
    networkName: session.networkName,
    secret: { id: 'nosh-http-ca', source: session.caPath },
    buildArgs: [
      `HTTP_PROXY=${proxyUrl}`,
      `HTTPS_PROXY=${proxyUrl}`,
      `FTP_PROXY=${proxyUrl}`,
      `ALL_PROXY=${proxyUrl}`,
      'NO_PROXY=',
      `http_proxy=${proxyUrl}`,
      `https_proxy=${proxyUrl}`,
      `ftp_proxy=${proxyUrl}`,
      `all_proxy=${proxyUrl}`,
      'no_proxy=',
      'NOSH_HTTP_CAPTURE=1',
      'NOSH_HTTP_CAPTURE_CA_FILE=/usr/local/share/ca-certificates/nosh-http-capture.crt',
    ],
  };
}

export async function stopManagedHttpCapture(session, dependencies = {}) {
  if (!session || session.stopped) {
    throw new TypeError('active managed HTTP capture session is required');
  }
  const stopped = docker(
    ['stop', '--time', '15', session.containerName],
    dependencies,
    { allowFailure: true },
  );
  if (stopped.status !== 0) {
    const primary = commandError(['stop', session.containerName], stopped);
    const cleanupError = cleanupDocker(
      ['rm', '--force', session.containerName],
      dependencies,
    );
    if (!cleanupError) {
      session.stopped = true;
      session.containerStarted = false;
    }
    throw managedCaptureError(primary, cleanupError ? [cleanupError] : [], {
      containerName: session.containerName,
      containerMayExist: session.containerStarted === true,
      networkName: session.networkName,
      networkMayExist: session.networkCreated === true,
    }, 'managed HTTP capture stop and containment failed');
  }
  session.stopped = true;
  session.containerStarted = false;
  const handle = await fs.open(
    session.evidencePath,
    fsSync.constants.O_RDONLY | (fsSync.constants.O_NOFOLLOW || 0),
  );
  let content;
  try {
    const details = await handle.stat();
    if (!details.isFile() || details.nlink !== 1 || details.size > MAX_HTTP_EVIDENCE_BYTES) {
      throw new Error('managed HTTP evidence is not a bounded regular file');
    }
    content = await handle.readFile();
  } finally {
    await handle.close();
  }
  const records = parseHttpEvidenceNdjson(content);
  const source = createHttpEvidenceSourceDescriptor({
    file: 'raw/http.ndjson',
    content,
    records,
    required: true,
    expectedCollectorIdentity: session.collectorIdentity,
  });
  const stats = records.at(-1);
  let contentManifest = null;
  let contentManifestPath = null;
  if (stats.contentManifestDigest) {
    const store = new HttpContentStore({
      root: session.casRoot,
      containmentRoot: session.root,
    });
    contentManifest = await store.readManifest(stats.contentManifestDigest);
    if (
      contentManifest.runId !== session.runId
      || contentManifest.mode !== 'offline-replay'
    ) {
      throw new Error('managed HTTP capture manifest identity is invalid');
    }
    const casByExchangeId = captureManifestCas(records, contentManifest);
    for (const entry of contentManifest.entries) {
      await store.verify(entry.response.bodyDigest, {
        expectedBytes: entry.response.bodyBytes,
      });
    }
    if (casByExchangeId.size !== contentManifest.entries.length) {
      throw new Error('managed HTTP capture manifest contains ambiguous entries');
    }
    contentManifestPath = store.manifestPath(contentManifest.contentHash);
  } else if (
    stats.responses > 0
    && stats.contentAssuranceGaps.length === 0
  ) {
    throw new Error('managed HTTP capture omitted its replay manifest without a gap');
  }
  await fs.rm(session.confdir, { recursive: true, force: true });
  await fs.rm(session.evidencePath, { force: true });
  return {
    records,
    source,
    contentManifest,
    contentManifestPath,
  };
}

function captureManifestCas(records, input) {
  if (!input) return new Map();
  const manifest = verifyHttpContentManifest(input);
  const requests = new Map(records
    .filter((record) => record.recordKind === 'http-request')
    .map((record) => [record.exchangeId, record]));
  const responses = new Map(records
    .filter((record) => record.recordKind === 'http-response')
    .map((record) => [record.exchangeId, record]));
  const redirects = new Map(records
    .filter((record) => record.recordKind === 'http-redirect')
    .map((record) => [record.exchangeId, record]));
  const result = new Map();
  for (const entry of manifest.entries) {
    const request = requests.get(entry.sourceExchangeId);
    const response = responses.get(entry.sourceExchangeId);
    const redirect = redirects.get(entry.sourceExchangeId) || null;
    if (
      !request
      || request.credentialed
      || !response?.bodyComplete
      || response.rangeResponse
      || httpRequestIdentityKey(request) !== entry.requestKey
      || response.status !== entry.response.status
      || response.bodyDigest !== entry.response.bodyDigest
      || response.bodyBytes !== entry.response.bodyBytes
      || response.contentType !== entry.response.contentType
      || response.contentEncoding !== entry.response.contentEncoding
      || (entry.response.locationDigest === null) !== (redirect === null)
      || (redirect && redirect.status !== response.status)
      || (redirect && redirect.locationDigest !== entry.response.locationDigest)
      || result.has(entry.sourceExchangeId)
    ) {
      throw new Error('managed HTTP CAS manifest does not match normalized evidence');
    }
    result.set(entry.sourceExchangeId, {
      objectSha256: entry.response.bodyDigest,
      manifestSha256: manifest.contentHash,
      available: true,
    });
  }
  return result;
}

export function correlateManagedHttpEvidence(records, input = {}) {
  const attempts = Array.isArray(input.networkAttempts) ? input.networkAttempts : [];
  // This collector is scoped to the build cgroup, so this exact join attests
  // only the workload-to-proxy leg. Review keeps that role non-authoritative
  // until a separately scoped proxy-leg collector can attest origin reachability.
  const proxyByExchange = new Map();
  const passByExchange = new Map();
  const roleByExchange = new Map();
  const casByExchange = captureManifestCas(records, input.contentManifest || null);
  for (const record of records) {
    if (record.recordKind !== 'http-request') continue;
    const candidates = attempts.filter((attempt) => {
      if (
        attempt.protocol !== 'tcp'
        || attempt.ip !== input.proxyIpv4
        || attempt.port !== input.proxyPort
      ) return false;
      const firstTimestampNs = attempt.firstTimestampNs
        ?? attempt.firstObservedNs
        ?? attempt.timestampNs;
      const lastTimestampNs = attempt.lastTimestampNs
        ?? attempt.lastObservedNs
        ?? attempt.timestampNs;
      if (
        typeof firstTimestampNs !== 'string'
        || typeof lastTimestampNs !== 'string'
        || !/^(0|[1-9][0-9]*)$/.test(firstTimestampNs)
        || !/^(0|[1-9][0-9]*)$/.test(lastTimestampNs)
      ) return false;
      const hint = httpDownstreamCorrelationHint(record, { pass: attempt.pass });
      if (
        !hint
        || hint.source.address !== attempt.sourceAddress
        || hint.source.port !== attempt.sourcePort
        || hint.destination.ip !== attempt.ip
        || hint.destination.port !== attempt.port
      ) return false;
      const firstTimestamp = BigInt(firstTimestampNs);
      const lastTimestamp = BigInt(lastTimestampNs);
      const requestTimestamp = BigInt(hint.timestampUnixNs);
      return firstTimestamp <= lastTimestamp
        && firstTimestamp <= requestTimestamp
        && requestTimestamp <= lastTimestamp + 30_000_000_000n;
    });
    const identities = new Map();
    for (const candidate of candidates) {
      const identity = JSON.stringify([
        candidate.pass,
        candidate.socketCookie,
        candidate.sourceAddress,
        candidate.sourcePort,
        candidate.ip,
        candidate.port,
      ]);
      const current = identities.get(identity);
      if (
        !current
        || BigInt(
          candidate.lastTimestampNs
          ?? candidate.lastObservedNs
          ?? candidate.timestampNs,
        ) > BigInt(
          current.lastTimestampNs
          ?? current.lastObservedNs
          ?? current.timestampNs,
        )
      ) {
        identities.set(identity, candidate);
      }
    }
    if (identities.size !== 1) continue;
    const matched = [...identities.values()][0];
    proxyByExchange.set(record.exchangeId, {
      ip: matched.ip,
      protocol: 'tcp',
      port: matched.port,
    });
    passByExchange.set(record.exchangeId, matched.pass);
    roleByExchange.set(record.exchangeId, 'workload-to-proxy');
  }
  const observations = createBuildHttpObservations(records, {
    passByExchangeId: passByExchange,
    destinationByExchangeId: proxyByExchange,
    destinationRoleByExchangeId: roleByExchange,
    casByExchangeId: casByExchange,
    required: true,
  });
  const gaps = new Set(observations.gaps);
  const managedRequests = records.filter((record) => record.recordKind === 'http-request');
  if (managedRequests.some((record) => !proxyByExchange.has(record.exchangeId))) {
    gaps.add('managed HTTP request has no exact scoped L4 proxy correlation');
  }
  if (managedRequests.length > 0) {
    gaps.add('managed HTTP origin route lacks independent proxy-leg L4 provenance');
  }
  const managedOriginPorts = new Set(managedRequests.map((record) => record.port));
  const managedHttpsPorts = new Set(managedRequests
    .filter((record) => record.scheme === 'https')
    .map((record) => record.port));
  const directWebBypass = attempts.some((attempt) => {
    const standardWeb = (
      attempt.protocol === 'tcp'
      && (
        attempt.port === 80
        || attempt.port === 443
        || managedOriginPorts.has(attempt.port)
      )
    ) || (
      attempt.protocol === 'udp'
      && (attempt.port === 443 || managedHttpsPorts.has(attempt.port))
    );
    const exactProxy = attempt.protocol === 'tcp'
      && attempt.ip === input.proxyIpv4
      && attempt.port === input.proxyPort;
    return standardWeb && !exactProxy;
  });
  if (directWebBypass) {
    gaps.add('scoped L4 evidence observed direct HTTP(S)/QUIC proxy bypass');
  }
  const selectedGaps = [...gaps].sort();
  return {
    ...observations,
    complete: observations.complete && selectedGaps.length === 0,
    gaps: selectedGaps,
  };
}

export function cleanupManagedHttpCaptureNetwork(session, dependencies = {}) {
  if (!session?.networkCreated) return;
  const result = docker(
    ['network', 'rm', session.networkName],
    dependencies,
    { allowFailure: true },
  );
  if (result.status !== 0) throw commandError(['network', 'rm', session.networkName], result);
  session.networkCreated = false;
}
