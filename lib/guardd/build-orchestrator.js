import crypto from 'node:crypto';
import { spawn, spawnSync } from 'node:child_process';
import fsSync, { createWriteStream } from 'node:fs';
import fs from 'node:fs/promises';
import net from 'node:net';
import os from 'node:os';
import path from 'node:path';
import process from 'node:process';
import { Transform } from 'node:stream';
import { fileURLToPath } from 'node:url';

import { finalizeBuildPassManifests } from './build-profile-store.js';
import {
  cleanupManagedHttpCaptureNetwork,
  correlateManagedHttpEvidence,
  managedHttpBuildOptions,
  startManagedHttpCapture,
  stopManagedHttpCapture,
} from './http-capture-manager.js';
import { resolvePrivilegedGuardPath } from './install-layout.js';

const DEFAULT_BUILDKIT_IMAGE =
  'moby/buildkit:v0.30.0@sha256:0168606be2315b7c807a03b3d8aa79beefdb31c98740cebdffdfeebf31190c9f';
const MAX_BUILDKIT_PROGRESS_BYTES = 128 * 1024 * 1024;
const DEFAULT_BUILDKIT_PROGRESS_HEARTBEAT_MS = 30_000;
const MAX_BUILDKIT_HEARTBEAT_VERTICES = 8;
const MAX_BUILDKIT_PROGRESS_NAME_CHARS = 140;
const SLOW_BUILDKIT_VERTEX_MS = 2_000;
const MAX_BUILDX_HISTORY_EXPORT_BYTES = 64 * 1024 * 1024;
const MAX_BUILDX_HISTORY_REASON_CHARS = 512;
const IMMUTABLE_IMAGE_PATTERN = /@sha256:[a-f0-9]{64}$/i;
const BUILDKIT_HISTORY_ID_PATTERN = /^[a-z0-9]{1,128}$/;
const RESERVED_BUILDX_OPTIONS = new Set([
  '--',
  '--builder',
  '--call',
  '--cgroup-parent',
  '--check',
  '--file',
  '-f',
  '--metadata-file',
  '--no-cache',
  '--output',
  '-o',
  '--platform',
  '--progress',
  '--pull',
  '--push',
  '--load',
  '--target',
  '--tag',
  '-t',
]);
const MANAGED_HTTP_BUILD_ARG_NAMES = new Set([
  'HTTP_PROXY',
  'HTTPS_PROXY',
  'FTP_PROXY',
  'ALL_PROXY',
  'NO_PROXY',
  'http_proxy',
  'https_proxy',
  'ftp_proxy',
  'all_proxy',
  'no_proxy',
  'NOSH_HTTP_CAPTURE',
  'NOSH_HTTP_CAPTURE_CA_FILE',
]);
const MANAGED_HTTP_CA_SECRET_ID = 'nosh-http-ca';
const VALUE_OPTIONS = new Set([
  '--builder',
  '--cgroup-parent',
  '--file',
  '-f',
  '--metadata-file',
  '--output',
  '-o',
  '--platform',
  '--progress',
  '--target',
  '--tag',
  '-t',
]);

function commandError(command, args, result) {
  const detail = String(result.stderr || result.stdout || '').trim();
  const error = new Error(
    `${command} ${args.join(' ')} failed${
      Number.isInteger(result.status) ? ` with status ${result.status}` : ''
    }${detail ? `: ${detail.split(/\r?\n/)[0]}` : ''}`,
  );
  error.status = result.status;
  error.signal = result.signal;
  error.stdout = result.stdout;
  error.stderr = result.stderr;
  return error;
}

function runSync(command, args, options = {}) {
  const result = (options.spawnSyncImpl || spawnSync)(command, args, {
    encoding: 'utf8',
    maxBuffer: 32 * 1024 * 1024,
    stdio: ['ignore', 'pipe', 'pipe'],
    ...options.spawnOptions,
  });
  if (result.error) {
    throw result.error;
  }
  if (result.status !== 0 && !options.allowFailure) {
    throw commandError(command, args, result);
  }
  return result;
}

function defaultReportProgress(message) {
  process.stderr.write(`${message}\n`);
}

function progressReporter(options = {}) {
  const reportProgress = options.reportProgress || defaultReportProgress;
  if (typeof reportProgress !== 'function') {
    throw new TypeError('reportProgress must be a function');
  }
  return reportProgress;
}

function formatProgressElapsed(milliseconds) {
  const bounded = Math.max(0, Number(milliseconds) || 0);
  if (bounded < 60_000) {
    return `${(bounded / 1000).toFixed(1)}s`;
  }
  const totalSeconds = Math.floor(bounded / 1000);
  const minutes = Math.floor(totalSeconds / 60);
  const seconds = String(totalSeconds % 60).padStart(2, '0');
  return `${minutes}m ${seconds}s`;
}

function vertexElapsedMs(vertex, finishedAt) {
  const startedAt = Date.parse(vertex?.started || '');
  const endedAt = vertex?.completed
    ? Date.parse(vertex.completed)
    : Number(finishedAt);
  if (!Number.isFinite(startedAt) || !Number.isFinite(endedAt)) {
    return null;
  }
  return Math.max(0, endedAt - startedAt);
}

function normalizedBuildkitVertexName(vertex) {
  const name = String(vertex?.name || '')
    .replace(/\s+/g, ' ')
    .trim();
  return name || '(unnamed BuildKit vertex)';
}

function compactBuildkitVertexName(vertex) {
  const name = normalizedBuildkitVertexName(vertex);
  if (name.length <= MAX_BUILDKIT_PROGRESS_NAME_CHARS) {
    return name;
  }
  const separator = ' ... ';
  const tailLength = 42;
  const headLength = MAX_BUILDKIT_PROGRESS_NAME_CHARS
    - separator.length
    - tailLength;
  return `${name.slice(0, headLength)}${separator}${name.slice(-tailLength)}`;
}

function isBuildkitRunVertex(vertex) {
  return /(?:^|\]\s+)RUN(?:\s|$)/i.test(normalizedBuildkitVertexName(vertex));
}

function createBuildkitProgressTracker(reportProgress, options = {}) {
  const now = options.now || Date.now;
  if (typeof reportProgress !== 'function') {
    throw new TypeError('reportProgress must be a function');
  }
  if (typeof now !== 'function') {
    throw new TypeError('progress clock must be a function');
  }
  const vertices = new Map();
  const reportedSlowSemantics = new Set();

  function vertexName(vertex) {
    return compactBuildkitVertexName(vertex);
  }

  function semanticKey(vertex) {
    return normalizedBuildkitVertexName(vertex);
  }

  function update(vertex) {
    if (!vertex?.digest) {
      return;
    }
    const previous = vertices.get(vertex.digest) || {};
    const restarted = Boolean(
      previous.started
      && vertex.started
      && previous.started !== vertex.started,
    );
    const base = restarted
      ? {
          digest: previous.digest,
          name: previous.name,
          progressGroup: previous.progressGroup,
        }
      : previous;
    const merged = { ...base, ...vertex };
    vertices.set(vertex.digest, merged);

    const started = !base.started && Boolean(merged.started);
    const completed = !base.completed && Boolean(merged.completed);
    const runVertex = isBuildkitRunVertex(merged);
    if (started && !merged.completed && runVertex) {
      reportProgress(`[build] STARTED ${vertexName(merged)}`);
    }
    if (!completed) {
      return;
    }

    const elapsed = vertexElapsedMs(merged, Date.parse(merged.completed));
    const timing = elapsed == null ? '' : ` ${formatProgressElapsed(elapsed)}`;
    const state = merged.error
      ? 'FAILED'
      : merged.cached === true
        ? 'CACHED'
        : 'DONE';
    const slow = elapsed != null && elapsed >= SLOW_BUILDKIT_VERTEX_MS;
    const key = semanticKey(merged);
    if (!merged.error && !runVertex) {
      if (!slow || reportedSlowSemantics.has(key)) {
        return;
      }
      reportedSlowSemantics.add(key);
    }
    reportProgress(`[build] ${state}${timing} ${vertexName(merged)}`);
  }

  function heartbeat() {
    const currentTime = Number(now());
    if (!Number.isFinite(currentTime)) {
      return;
    }
    const activeBySemantic = new Map();
    for (const vertex of vertices.values()) {
      if (!vertex.started || vertex.completed) {
        continue;
      }
      const key = semanticKey(vertex);
      const previous = activeBySemantic.get(key);
      const startedAt = Date.parse(vertex.started);
      const previousStartedAt = Date.parse(previous?.started || '');
      if (
        !previous
        || (Number.isFinite(startedAt)
          && (!Number.isFinite(previousStartedAt) || startedAt > previousStartedAt))
      ) {
        activeBySemantic.set(key, vertex);
      }
    }
    const active = [...activeBySemantic.values()]
      .sort((left, right) => {
        const runOrder = Number(isBuildkitRunVertex(right))
          - Number(isBuildkitRunVertex(left));
        if (runOrder !== 0) return runOrder;
        const leftStarted = Date.parse(left.started);
        const rightStarted = Date.parse(right.started);
        if (Number.isFinite(leftStarted) && Number.isFinite(rightStarted)) {
          const timestampOrder = rightStarted - leftStarted;
          if (timestampOrder !== 0) return timestampOrder;
        } else if (Number.isFinite(leftStarted)) {
          return -1;
        } else if (Number.isFinite(rightStarted)) {
          return 1;
        }
        const nameOrder = vertexName(left).localeCompare(vertexName(right));
        return nameOrder || String(left.digest).localeCompare(String(right.digest));
      });
    for (const vertex of active.slice(0, MAX_BUILDKIT_HEARTBEAT_VERTICES)) {
      const elapsed = vertexElapsedMs(vertex, currentTime);
      const timing = elapsed == null ? '' : ` ${formatProgressElapsed(elapsed)}`;
      reportProgress(`[build] RUNNING${timing} ${vertexName(vertex)}`);
    }
    if (active.length > MAX_BUILDKIT_HEARTBEAT_VERTICES) {
      reportProgress(
        `[build] RUNNING ${active.length - MAX_BUILDKIT_HEARTBEAT_VERTICES} additional BuildKit vertices`,
      );
    }
  }

  return Object.freeze({ heartbeat, update });
}

function slug(value) {
  return String(value || 'project')
    .toLowerCase()
    .replace(/[^a-z0-9_.-]+/g, '-')
    .replace(/^-+|-+$/g, '')
    .slice(0, 40) || 'project';
}

function sha256(value) {
  return crypto.createHash('sha256').update(value).digest('hex');
}

function safeName(prefix, seed, suffix = '') {
  return `${prefix}-${sha256(seed).slice(0, 20)}${suffix}`.slice(0, 48);
}

function architecturePlatform(architecture = process.arch) {
  const mapped = {
    arm64: 'arm64',
    x64: 'amd64',
  }[architecture];
  if (!mapped) {
    throw new Error(`--platform is required on unsupported host architecture ${architecture}`);
  }
  return `linux/${mapped}`;
}

function buildArgName(value) {
  const separator = String(value).indexOf('=');
  return separator === -1 ? String(value) : String(value).slice(0, separator);
}

function sanitizedPassthrough(argv) {
  const result = [];
  for (let index = 0; index < argv.length; index += 1) {
    const value = argv[index];
    if (value === '--secret' || value.startsWith('--secret=')) {
      const source = value === '--secret' ? argv[++index] : value.slice('--secret='.length);
      const id = String(source || '').match(/(?:^|,)id=([^,]+)/)?.[1] || 'unnamed';
      result.push(`--secret=id=${id},<redacted>`);
      continue;
    }
    if (value === '--ssh' || value.startsWith('--ssh=')) {
      if (value === '--ssh') {
        index += 1;
      }
      result.push('--ssh=<redacted>');
      continue;
    }
    if (value === '--build-arg' || value.startsWith('--build-arg=')) {
      const source = value === '--build-arg'
        ? argv[++index]
        : value.slice('--build-arg='.length);
      result.push(`--build-arg=${buildArgName(source)}=<redacted>`);
      continue;
    }
    result.push(value);
  }
  return result;
}

function validatePassthrough(argv, options = {}) {
  const hasOutput = Boolean(
    options.push
    || (Array.isArray(options.output) ? options.output.length : options.output),
  );
  for (let index = 0; index < argv.length; index += 1) {
    const value = argv[index];
    if (typeof value !== 'string' || /[\r\n\0]/.test(value)) {
      throw new TypeError('Buildx arguments must be newline-free strings');
    }
    const option = value.includes('=') ? value.slice(0, value.indexOf('=')) : value;
    const unsupportedShortSyntax = value.startsWith('-')
      && !value.startsWith('--')
      && value !== '-q';
    if (RESERVED_BUILDX_OPTIONS.has(option) || unsupportedShortSyntax) {
      throw new TypeError(`${option} is owned by nosh build; use its structured option`);
    }
    if (
      value === '--allow'
      || value.startsWith('--allow=')
      || value === '--network=host'
      || (value === '--network' && argv[index + 1] === 'host')
    ) {
      throw new TypeError('host networking and insecure BuildKit entitlements are unsupported');
    }
    if (
      options.forceClean
      && (value === '--cache-from' || value.startsWith('--cache-from='))
    ) {
      throw new TypeError('build network learning rejects cache imports');
    }
    if (VALUE_OPTIONS.has(option) && !value.includes('=')) {
      index += 1;
    }
  }
  return { hasOutput };
}

function assertManagedHttpBuildInputsAvailable(invocation) {
  for (const value of invocation.buildArgs) {
    const name = buildArgName(value);
    if (MANAGED_HTTP_BUILD_ARG_NAMES.has(name)) {
      throw new TypeError(
        `managed HTTP capture owns the ${name} build argument`,
      );
    }
  }
  const passthrough = invocation.passthrough;
  for (let index = 0; index < passthrough.length; index += 1) {
    const value = passthrough[index];
    if (value === '--network' || value.startsWith('--network=')) {
      throw new TypeError('managed HTTP capture owns the BuildKit network');
    }
    if (value === '--build-arg' || value.startsWith('--build-arg=')) {
      const source = value === '--build-arg'
        ? passthrough[++index]
        : value.slice('--build-arg='.length);
      const name = buildArgName(source || '');
      if (MANAGED_HTTP_BUILD_ARG_NAMES.has(name)) {
        throw new TypeError(
          `managed HTTP capture owns the ${name} build argument`,
        );
      }
      continue;
    }
    if (value === '--secret' || value.startsWith('--secret=')) {
      const source = value === '--secret'
        ? passthrough[++index]
        : value.slice('--secret='.length);
      const id = String(source || '').match(/(?:^|,)id=([^,]+)/)?.[1] || '';
      if (id === MANAGED_HTTP_CA_SECRET_ID) {
        throw new TypeError(
          `managed HTTP capture owns the ${MANAGED_HTTP_CA_SECRET_ID} BuildKit secret`,
        );
      }
    }
  }
}

async function secureUserDirectory(directory) {
  const resolved = path.resolve(directory);
  const parsed = path.parse(resolved);
  const parts = resolved.slice(parsed.root.length).split(path.sep).filter(Boolean);
  let current = parsed.root;
  for (const part of parts) {
    current = path.join(current, part);
    try {
      const stat = await fs.lstat(current);
      if (!stat.isDirectory() || stat.isSymbolicLink()) {
        throw new Error(`build bundle path is not a real directory: ${current}`);
      }
    } catch (error) {
      if (error.code !== 'ENOENT') {
        throw error;
      }
      await fs.mkdir(current, { mode: 0o700 });
    }
  }
  await fs.chmod(resolved, 0o700);
  return resolved;
}

async function copyPrivateTree(source, destination, expectedUid) {
  const sourceStat = await fs.lstat(source);
  if (
    sourceStat.isSymbolicLink()
    || sourceStat.uid !== expectedUid
    || (sourceStat.mode & 0o022) !== 0
  ) {
    throw new Error(`private build artifact has an unsafe owner or mode: ${source}`);
  }
  if (sourceStat.isDirectory()) {
    await fs.mkdir(destination, { mode: 0o700 });
    for (const entry of (await fs.readdir(source)).sort()) {
      await copyPrivateTree(
        path.join(source, entry),
        path.join(destination, entry),
        expectedUid,
      );
    }
    return;
  }
  if (!sourceStat.isFile() || sourceStat.nlink !== 1) {
    throw new Error(`private build artifact is not a regular file: ${source}`);
  }
  await fs.copyFile(source, destination, fsSync.constants.COPYFILE_EXCL);
  // Content-addressed HTTP objects and manifests are immutable mode-0400
  // inputs to the replay gate. Preserve that exact mode while normalizing all
  // other private files to mode 0600.
  await fs.chmod(destination, (sourceStat.mode & 0o7777) === 0o400 ? 0o400 : 0o600);
}

async function syncPrivateTree(selected) {
  const stat = await fs.lstat(selected);
  if (stat.isSymbolicLink()) {
    throw new Error(`cannot sync a symbolic link in private build evidence: ${selected}`);
  }
  if (stat.isDirectory()) {
    for (const entry of await fs.readdir(selected)) {
      await syncPrivateTree(path.join(selected, entry));
    }
  } else if (!stat.isFile()) {
    throw new Error(`cannot sync an unsupported private build artifact: ${selected}`);
  }
  const handle = await fs.open(
    selected,
    fsSync.constants.O_RDONLY
      | (fsSync.constants.O_NOFOLLOW || 0)
      | (stat.isDirectory() ? (fsSync.constants.O_DIRECTORY || 0) : 0),
  );
  try {
    await handle.sync();
  } finally {
    await handle.close();
  }
}

async function adoptBuildEvidence(manifestPath, passDir) {
  if (typeof manifestPath !== 'string' || !manifestPath) {
    throw new Error('privileged build session did not export its evidence');
  }
  const resolvedManifest = await fs.realpath(path.resolve(manifestPath));
  if (path.basename(resolvedManifest) !== 'build-evidence-manifest.json') {
    throw new Error('privileged build evidence returned an unexpected manifest');
  }
  const source = path.dirname(resolvedManifest);
  const destination = path.join(passDir, 'kernel-evidence');
  if (source === destination) {
    return resolvedManifest;
  }
  if (
    path.dirname(source) !== '/tmp'
    || !path.basename(source).startsWith('nosh-build-evidence-')
  ) {
    throw new Error('privileged build evidence returned an unexpected staging path');
  }
  const expectedUid = typeof process.getuid === 'function' ? process.getuid() : 0;
  const sourceStat = await fs.lstat(source);
  if (
    !sourceStat.isDirectory()
    || sourceStat.isSymbolicLink()
    || sourceStat.uid !== expectedUid
    || (sourceStat.mode & 0o7777) !== 0o700
  ) {
    throw new Error('privileged build evidence staging directory is not trusted');
  }
  try {
    await fs.rename(source, destination);
  } catch (error) {
    if (error.code !== 'EXDEV') {
      throw error;
    }
    await copyPrivateTree(source, destination, expectedUid);
    await fs.rm(source, { recursive: true, force: true });
  }
  return path.join(destination, 'build-evidence-manifest.json');
}

async function resolveDockerfile(context, options = {}) {
  if (options.file && options.variant) {
    throw new TypeError('--file and --variant are mutually exclusive');
  }
  let selected;
  if (options.variant) {
    if (!/^[A-Za-z0-9][A-Za-z0-9_.-]*$/.test(options.variant)) {
      throw new TypeError('--variant contains unsupported characters');
    }
    selected = path.join(context, `Dockerfile.${options.variant}`);
  } else if (options.file) {
    selected = path.resolve(options.cwd || process.cwd(), options.file);
  } else {
    selected = path.join(context, 'Dockerfile');
  }
  const real = await fs.realpath(selected);
  const handle = await fs.open(
    real,
    fsSync.constants.O_RDONLY | (fsSync.constants.O_NOFOLLOW || 0),
  );
  try {
    const stat = await handle.stat({ bigint: true });
    if (!stat.isFile()) {
      throw new Error(`Dockerfile must be a regular non-symlink file: ${selected}`);
    }
    return {
      path: real,
      sha256: `sha256:${sha256(await handle.readFile())}`,
      dev: String(stat.dev),
      ino: String(stat.ino),
      size: String(stat.size),
    };
  } finally {
    await handle.close();
  }
}

async function assertDockerfileStable(dockerfile) {
  const current = await fs.realpath(dockerfile.path);
  if (current !== dockerfile.path) {
    throw new Error('Dockerfile identity changed during build profiling');
  }
  const handle = await fs.open(
    current,
    fsSync.constants.O_RDONLY | (fsSync.constants.O_NOFOLLOW || 0),
  );
  try {
    const stat = await handle.stat({ bigint: true });
    const digest = `sha256:${sha256(await handle.readFile())}`;
    if (
      !stat.isFile()
      || String(stat.dev) !== dockerfile.dev
      || String(stat.ino) !== dockerfile.ino
      || String(stat.size) !== dockerfile.size
      || digest !== dockerfile.sha256
    ) {
      throw new Error('Dockerfile changed during build profiling');
    }
  } finally {
    await handle.close();
  }
}

export async function resolveBuildInvocation(options = {}) {
  const context = await fs.realpath(path.resolve(options.context || '.'));
  const contextStat = await fs.stat(context, { bigint: true });
  if (!contextStat.isDirectory()) {
    throw new Error(`build context is not a directory: ${context}`);
  }
  const dockerfile = await resolveDockerfile(context, options);
  const platform = options.platform || architecturePlatform(options.architecture);
  if (platform.includes(',')) {
    throw new TypeError('nosh build profiles exactly one platform per invocation');
  }
  const passthrough = options.passthrough || [];
  const checked = validatePassthrough(passthrough, options);
  const buildArgs = Array.isArray(options.buildArg)
    ? options.buildArg
    : options.buildArg
      ? [options.buildArg]
      : [];
  const tags = Array.isArray(options.tag)
    ? options.tag
    : options.tag
      ? [options.tag]
      : [];
  const outputs = Array.isArray(options.output)
    ? options.output
    : options.output
      ? [options.output]
      : [];
  if (options.push && outputs.length) {
    throw new TypeError('--push and --output are mutually exclusive');
  }
  return {
    context,
    contextIdentity: {
      dev: String(contextStat.dev),
      ino: String(contextStat.ino),
    },
    dockerfile,
    variant: options.variant || null,
    tags,
    target: options.target || null,
    platform,
    push: Boolean(options.push),
    outputs,
    noLoad: Boolean(options.noLoad),
    passthrough,
    hasOutput: checked.hasOutput,
    buildArgs,
    sanitized: {
      context,
      dockerfile,
      variant: options.variant || null,
      tags,
      target: options.target || null,
      platform,
      buildArgNames: buildArgs.map(buildArgName),
      outputs,
      passthrough: sanitizedPassthrough(passthrough),
    },
  };
}

function parseJsonOutput(result, label) {
  try {
    return JSON.parse(String(result.stdout || ''));
  } catch (error) {
    throw new Error(`${label} did not return JSON: ${error.message}`);
  }
}

function procStartTime(pid = process.pid) {
  const source = fsSync.readFileSync(`/proc/${pid}/stat`, 'utf8');
  const close = source.lastIndexOf(')');
  const fields = source.slice(close + 2).trim().split(/\s+/);
  if (!/^\d+$/.test(fields[19] || '')) {
    throw new Error('build client process start time is unavailable');
  }
  return fields[19];
}

function trustedPrivilegedHelper(requested) {
  if (!path.isAbsolute(requested)) {
    throw new Error('privileged nosh-guard helper path must be absolute');
  }
  let resolved;
  try {
    resolved = fsSync.realpathSync(requested);
  } catch (error) {
    if (error?.code === 'ENOENT' || error?.code === 'ENOTDIR') {
      throw new Error(
        `privileged nosh-guard helper is not installed at ${requested}; `
        + 'run the checkout\'s ./scripts/setup-nosh.sh for the reviewed host-bundle install command, '
        + 'or set NOSH_GUARD_PREFIX/NOSH_GUARD_PRIVILEGED_BIN to an installed root-owned helper',
        { cause: error },
      );
    }
    throw new Error(
      `privileged nosh-guard helper cannot be inspected at ${requested}: ${error.message}`,
      { cause: error },
    );
  }
  const stat = fsSync.statSync(resolved);
  if (
    !stat.isFile()
    || stat.uid !== 0
    || stat.nlink !== 1
    || (stat.mode & 0o022) !== 0
    || (stat.mode & 0o111) === 0
  ) {
    throw new Error(
      `privileged nosh-guard helper must be a singly linked, root-owned, executable, non-writable file: ${resolved}`,
    );
  }
  let cursor = path.dirname(resolved);
  while (true) {
    const ancestor = fsSync.statSync(cursor);
    if (!ancestor.isDirectory() || ancestor.uid !== 0 || (ancestor.mode & 0o022) !== 0) {
      throw new Error(`privileged helper has an untrusted path ancestor: ${cursor}`);
    }
    const parent = path.dirname(cursor);
    if (parent === cursor) {
      break;
    }
    cursor = parent;
  }
  return resolved;
}

export function defaultPrivilegedInvoker(action, payload, options = {}) {
  const direct = typeof process.geteuid === 'function' && process.geteuid() === 0;
  const guardBin = direct
    ? options.guardBin || process.env.NOSH_GUARD_BIN || fileURLToPath(
        new URL('../../bin/nosh-guard', import.meta.url),
      )
    : trustedPrivilegedHelper(resolvePrivilegedGuardPath(options));
  const command = direct ? guardBin : (options.sudoBin || 'sudo');
  const args = direct
    ? ['build-session', action]
    : ['--', guardBin, 'build-session', action];
  if (!direct && process.env.NOSH_BUILD_NONINTERACTIVE === '1') args.unshift('-n');
  const result = runSync(command, args, {
    spawnSyncImpl: options.spawnSyncImpl,
    spawnOptions: {
      input: `${JSON.stringify(payload)}\n`,
      stdio: ['pipe', 'pipe', 'inherit'],
    },
  });
  return parseJsonOutput(result, `privileged build-session ${action}`);
}

function dockerInfo(options = {}) {
  const contextResult = runSync('docker', ['context', 'inspect', '--format', '{{json .Endpoints.docker.Host}}'], options);
  const endpoint = parseJsonOutput(contextResult, 'docker context inspect');
  if (typeof endpoint !== 'string' || !endpoint.startsWith('unix://')) {
    throw new Error('nosh build profiling requires a local Unix-socket Docker context');
  }
  const infoResult = runSync('docker', ['info', '--format', '{{json .}}'], options);
  const info = parseJsonOutput(infoResult, 'docker info');
  if (info.OSType !== 'linux' || String(info.CgroupVersion) !== '2') {
    throw new Error('nosh build profiling requires Linux Docker with cgroup v2');
  }
  if ((info.SecurityOptions || []).some((entry) => String(entry).includes('rootless'))) {
    throw new Error('rootless Docker is not supported by build profiling v1');
  }
  const privateCgroupNamespaces = (info.SecurityOptions || []).some((entry) => (
    String(entry).split(',').includes('name=cgroupns')
  ));
  if (!privateCgroupNamespaces) {
    throw new Error(
      'nosh build profiling requires Docker with private cgroup namespaces enabled by default',
    );
  }
  runSync('docker', ['buildx', 'version'], options);
  runSync('docker', ['buildx', 'history', '--help'], options);
  return { endpoint, info };
}

function builderNames(invocation, profileId, cacheMode, endpoint, uid) {
  const stableSeed = [uid, invocation.context, invocation.platform, endpoint].join('\0');
  const uniqueSeed = `${stableSeed}\0${profileId}`;
  const builderName = cacheMode === 'warm'
    ? safeName('nosh-build', stableSeed)
    : safeName('nosh-build', uniqueSeed);
  return { builderName, builderNode: `${builderName}0` };
}

function assertSingleBuilderNode(output, names) {
  const source = String(output || '');
  if (!/^Driver:\s+docker-container\s*$/m.test(source)) {
    throw new Error(`builder ${names.builderName} is not docker-container`);
  }
  const nodes = source.match(/^Nodes:\s*$([\s\S]*)/m)?.[1] || '';
  const nodeNames = [...nodes.matchAll(/^Name:\s+(\S+)\s*$/gm)]
    .map((match) => match[1]);
  if (nodeNames.length !== 1 || nodeNames[0] !== names.builderNode) {
    throw new Error(
      `builder ${names.builderName} must contain exactly the profiled node ${names.builderNode}`,
    );
  }
}

async function acquireBuilderLock(home, builderName, dependencies = {}) {
  const directory = await secureUserDirectory(path.join(home, '.nosh', 'build-locks'));
  const lockPath = path.join(directory, `${builderName}.lock`);
  const fd = fsSync.openSync(
    lockPath,
    fsSync.constants.O_RDWR
      | fsSync.constants.O_CREAT
      | (fsSync.constants.O_NOFOLLOW || 0),
    0o600,
  );
  try {
    fsSync.fchmodSync(fd, 0o600);
    const flockBinary = ['/usr/bin/flock', '/bin/flock'].find(fsSync.existsSync);
    if (!flockBinary) {
      throw new Error('build profiling requires /usr/bin/flock or /bin/flock');
    }
    const result = (dependencies.spawnSyncImpl || spawnSync)(
      flockBinary,
      ['--exclusive', '--nonblock', '--conflict-exit-code', '73', '3'],
      {
        encoding: 'utf8',
        stdio: ['ignore', 'pipe', 'pipe', fd],
      },
    );
    if (result.error) {
      throw result.error;
    }
    if (result.status === 73) {
      const error = new Error(`BuildKit builder ${builderName} is already being profiled`);
      error.code = 'NOSH_BUILD_LEASE_CONFLICT';
      throw error;
    }
    if (result.status !== 0) {
      throw commandError(flockBinary, ['3'], result);
    }
  } catch (error) {
    fsSync.closeSync(fd);
    throw error;
  }
  return {
    lockPath,
    release() {
      fsSync.closeSync(fd);
    },
  };
}

function ensureBuilder(names, image, cacheMode, dependencies = {}, options = {}) {
  const networkName = options.networkName || null;
  if (
    networkName != null
    && !/^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$/.test(networkName)
  ) {
    throw new TypeError('BuildKit builder network name is invalid');
  }
  const existing = runSync('docker', ['buildx', 'inspect', names.builderName], {
    ...dependencies,
    allowFailure: true,
  });
  if (existing.status === 0) {
    if (cacheMode !== 'warm') {
      throw new Error(`unexpected existing ephemeral builder ${names.builderName}`);
    }
    if (!/Driver:\s+docker-container/.test(String(existing.stdout || ''))) {
      throw new Error(`existing builder ${names.builderName} is not docker-container`);
    }
  } else {
    const createArgs = [
      'buildx',
      'create',
      '--name', names.builderName,
      '--node', names.builderNode,
      '--driver', 'docker-container',
      '--driver-opt', `image=${image}`,
    ];
    if (networkName) createArgs.push('--driver-opt', `network=${networkName}`);
    runSync('docker', createArgs, dependencies);
  }
  const created = existing.status !== 0;
  try {
    const bootstrapped = runSync(
      'docker',
      ['buildx', 'inspect', '--bootstrap', names.builderName],
      dependencies,
    );
    assertSingleBuilderNode(bootstrapped.stdout, names);
    const containerName = `buildx_buildkit_${names.builderNode}`;
    const inspect = runSync('docker', [
      'inspect',
      '--format', '{{json .}}',
      containerName,
    ], dependencies);
    const inspected = parseJsonOutput(inspect, 'docker inspect builder');
    const containerId = inspected?.Id;
    if (!/^[a-f0-9]{64}$/i.test(containerId)) {
      throw new Error('Docker did not return an exact BuildKit container ID');
    }
    if (inspected?.HostConfig?.CgroupnsMode !== 'private') {
      throw new Error('BuildKit builder must use a private cgroup namespace');
    }
    if (
      networkName
      && !Object.hasOwn(inspected?.NetworkSettings?.Networks || {}, networkName)
    ) {
      throw new Error(
        `BuildKit builder is not attached to managed HTTP capture network ${networkName}`,
      );
    }
    const expectedDigest = String(image).match(/@((?:sha256:)[a-f0-9]{64})$/i)?.[1];
    const configuredDigest = String(inspected?.Config?.Image || '')
      .match(/@((?:sha256:)[a-f0-9]{64})$/i)?.[1];
    if (!expectedDigest || expectedDigest.toLowerCase() !== configuredDigest?.toLowerCase()) {
      throw new Error(
        `builder ${names.builderName} uses a different BuildKit image; reset it explicitly`,
      );
    }
    return {
      ...names,
      containerName,
      containerId,
      created,
    };
  } catch (error) {
    if (created) {
      const cleanup = runSync('docker', ['buildx', 'rm', names.builderName], {
        ...dependencies,
        allowFailure: true,
      });
      if (cleanup.status !== 0) {
        throw new AggregateError(
          [error, commandError('docker', ['buildx', 'rm', names.builderName], cleanup)],
          'builder bootstrap and cleanup failed',
        );
      }
    }
    throw error;
  }
}

function buildCommand(invocation, builder, pass, options = {}) {
  const metadataPath = path.join(options.passDir, 'buildx-metadata.json');
  const args = [
    'buildx', 'build',
    '--builder', builder.builderName,
    '--progress', 'rawjson',
    '--metadata-file', metadataPath,
    '--platform', invocation.platform,
    '--file', invocation.dockerfile.path,
  ];
  for (const tag of invocation.tags) {
    args.push('--tag', tag);
  }
  if (invocation.target) {
    args.push('--target', invocation.target);
  }
  for (const value of invocation.buildArgs) {
    args.push('--build-arg', value);
  }
  if (options.httpBuild) {
    const httpBuild = options.httpBuild;
    if (
      !Array.isArray(httpBuild.buildArgs)
      || !httpBuild.secret
      || httpBuild.secret.id !== MANAGED_HTTP_CA_SECRET_ID
      || typeof httpBuild.secret.source !== 'string'
      || !path.isAbsolute(httpBuild.secret.source)
    ) {
      throw new TypeError('managed HTTP build inputs are invalid');
    }
    for (const value of httpBuild.buildArgs) {
      if (
        typeof value !== 'string'
        || /[\r\n\0]/.test(value)
        || !MANAGED_HTTP_BUILD_ARG_NAMES.has(buildArgName(value))
      ) {
        throw new TypeError('managed HTTP build argument is invalid');
      }
      args.push('--build-arg', value);
    }
    args.push(
      '--secret',
      `id=${httpBuild.secret.id},src=${httpBuild.secret.source}`,
    );
  }
  if (options.forceClean) {
    args.push('--pull', '--no-cache');
  }
  if (pass === 'cold' && options.compare) {
    args.push('--output', 'type=cacheonly');
  } else if (invocation.push) {
    args.push('--push');
  } else if (invocation.outputs.length) {
    for (const output of invocation.outputs) {
      args.push('--output', output);
    }
  } else if (!invocation.hasOutput && !invocation.noLoad) {
    args.push('--load');
  }
  args.push(...invocation.passthrough, invocation.context);
  return { args, metadataPath };
}

async function runStreamingBuild(args, progressPath, options = {}) {
  const reportProgress = progressReporter(options);
  const progressTracker = createBuildkitProgressTracker(reportProgress, {
    now: options.now,
  });
  const progressMaxBytes = options.progressMaxBytes == null
    ? MAX_BUILDKIT_PROGRESS_BYTES
    : Number(options.progressMaxBytes);
  const progressHeartbeatMs = options.progressHeartbeatMs == null
    ? DEFAULT_BUILDKIT_PROGRESS_HEARTBEAT_MS
    : Number(options.progressHeartbeatMs);
  if (
    !Number.isSafeInteger(progressMaxBytes)
    || progressMaxBytes < 1
    || progressMaxBytes > MAX_BUILDKIT_PROGRESS_BYTES
  ) {
    throw new TypeError(
      `BuildKit progress byte limit must be from 1 to ${MAX_BUILDKIT_PROGRESS_BYTES}`,
    );
  }
  if (!Number.isSafeInteger(progressHeartbeatMs) || progressHeartbeatMs < 0) {
    throw new TypeError('BuildKit progress heartbeat must be a non-negative integer');
  }
  const output = createWriteStream(progressPath, { flags: 'wx', mode: 0o600 });
  let outputFailure = null;
  let captureFailure = null;
  let child = null;
  let terminationTimer = null;
  let progressHeartbeatTimer = null;
  const terminateForCaptureFailure = (error) => {
    if (captureFailure) return;
    captureFailure = error;
    if (!child?.pid) return;
    child.kill('SIGTERM');
    if (!terminationTimer) {
      terminationTimer = setTimeout(() => child.kill('SIGKILL'), 2_000);
      terminationTimer.unref();
    }
  };
  let completeOutput;
  const outputComplete = new Promise((resolve) => {
    completeOutput = resolve;
  });
  output.on('error', (error) => {
    outputFailure ||= error;
    terminateForCaptureFailure(error);
    completeOutput();
  });
  output.once('finish', completeOutput);
  let progressBytes = 0;
  const progressLimiter = new Transform({
    transform(chunk, encoding, callback) {
      const buffer = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk, encoding);
      if (progressBytes + buffer.length > progressMaxBytes) {
        callback(new Error(`BuildKit progress exceeded ${progressMaxBytes} bytes`));
        return;
      }
      progressBytes += buffer.length;
      callback(null, buffer);
    },
  });
  progressLimiter.once('error', (error) => {
    terminateForCaptureFailure(error);
    output.destroy(error);
  });
  child = (options.spawnImpl || spawn)('docker', args, {
    env: process.env,
    stdio: ['inherit', 'inherit', 'pipe'],
  });
  if (progressHeartbeatMs > 0) {
    progressHeartbeatTimer = setInterval(
      () => progressTracker.heartbeat(),
      progressHeartbeatMs,
    );
    progressHeartbeatTimer.unref();
  }
  let buffered = '';
  let droppingOversizedLine = false;
  const processProgressLine = (line) => {
    if (!line) {
      return;
    }
    if (line.length > 1024 * 1024) {
      reportProgress('[build] oversized progress line elided');
      return;
    }
    try {
      const record = JSON.parse(line);
      for (const vertex of record.vertexes || []) {
        progressTracker.update(vertex);
      }
    } catch {
      reportProgress(line);
    }
  };
  let interruptedSignal = null;
  const onSignal = (signal) => {
    interruptedSignal ||= signal;
    child.kill(signal);
    if (!terminationTimer) {
      terminationTimer = setTimeout(() => child.kill('SIGKILL'), 10_000);
      terminationTimer.unref();
    }
  };
  const onSigint = () => onSignal('SIGINT');
  const onSigterm = () => onSignal('SIGTERM');
  process.on('SIGINT', onSigint);
  process.on('SIGTERM', onSigterm);
  child.stderr.once('error', (error) => progressLimiter.destroy(error));
  child.stderr.pipe(progressLimiter).pipe(output);
  child.stderr.on('data', (chunk) => {
    let text = chunk.toString('utf8');
    if (droppingOversizedLine) {
      const newline = text.indexOf('\n');
      if (newline === -1) return;
      text = text.slice(newline + 1);
      droppingOversizedLine = false;
    }
    buffered += text;
    if (buffered.length > 1024 * 1024 && !buffered.includes('\n')) {
      buffered = '';
      droppingOversizedLine = true;
      reportProgress('[build] oversized progress line elided');
      return;
    }
    const lines = buffered.split(/\r?\n/);
    buffered = lines.pop() || '';
    for (const line of lines) {
      processProgressLine(line);
    }
  });
  child.stderr.on('end', () => {
    if (!droppingOversizedLine && buffered) {
      processProgressLine(buffered);
      buffered = '';
    }
  });
  let result;
  let executionFailure = null;
  try {
    result = await new Promise((resolve, reject) => {
      let spawnFailure = null;
      child.once('error', (error) => {
        spawnFailure = error;
      });
      child.once('close', (code, signal) => {
        if (spawnFailure) reject(spawnFailure);
        else resolve({ code, signal });
      });
    });
  } catch (error) {
    executionFailure = error;
  } finally {
    process.removeListener('SIGINT', onSigint);
    process.removeListener('SIGTERM', onSigterm);
    if (terminationTimer) clearTimeout(terminationTimer);
    if (progressHeartbeatTimer) clearInterval(progressHeartbeatTimer);
    await outputComplete;
  }
  if (executionFailure) {
    throw executionFailure;
  }
  if (captureFailure) {
    throw captureFailure;
  }
  if (outputFailure) {
    throw outputFailure;
  }
  if (interruptedSignal) {
    const number = os.constants.signals[interruptedSignal] || 1;
    return { status: 128 + number, signal: interruptedSignal };
  }
  return {
    status: Number.isInteger(result.code) ? result.code : 1,
    signal: result.signal || null,
  };
}

async function readOptionalJson(filePath) {
  try {
    return JSON.parse(await fs.readFile(filePath, 'utf8'));
  } catch (error) {
    if (error.code === 'ENOENT') {
      return null;
    }
    throw error;
  }
}

function resultMetadata(metadata) {
  if (!metadata || typeof metadata !== 'object') {
    return {};
  }
  return {
    buildRef: metadata['buildx.build.ref'] || null,
    imageDigest: metadata['containerimage.digest'] || null,
    configDigest: metadata['containerimage.config.digest'] || null,
    descriptor: metadata['containerimage.descriptor'] || null,
  };
}

function buildHistoryId(builder, metadata) {
  const buildRef = metadata?.['buildx.build.ref'];
  if (typeof buildRef !== 'string' || !buildRef) {
    return null;
  }
  const expectedPrefix = `${builder.builderName}/${builder.builderNode}/`;
  if (!buildRef.startsWith(expectedPrefix)) {
    throw new Error('build metadata reference does not match the selected builder node');
  }
  const buildId = buildRef.slice(expectedPrefix.length);
  if (!BUILDKIT_HISTORY_ID_PATTERN.test(buildId)) {
    throw new Error('build metadata reference contains an invalid BuildKit history ID');
  }
  return buildId;
}

function buildHistoryFailureReason(value, fallback = 'Buildx history command failed') {
  const source = String(value || '')
    .replace(/\x1b\[[0-?]*[ -/]*[@-~]/g, '')
    .replace(/[\x00-\x1f\x7f-\x9f]+/g, ' ')
    .replace(/\s+/g, ' ')
    .trim();
  const selected = source || fallback;
  return selected.length <= MAX_BUILDX_HISTORY_REASON_CHARS
    ? selected
    : `${selected.slice(0, MAX_BUILDX_HISTORY_REASON_CHARS - 3)}...`;
}

function assertBuildL4FlowSummaryContract(session) {
  const adapters = Array.isArray(session?.adapters) ? session.adapters : [];
  const matches = adapters.filter((adapter) => adapter?.name === 'nosh-l4');
  const adapter = matches.length === 1 ? matches[0] : null;
  const command = Array.isArray(adapter?.command) ? adapter.command : [];
  const outputModeIndexes = [];
  for (let index = 0; index < command.length; index += 1) {
    if (command[index] === '--output-mode') outputModeIndexes.push(index);
  }
  const commandMatches = outputModeIndexes.length === 1
    && command[outputModeIndexes[0] + 1] === 'flow-summary';
  const readinessMatches = adapter?.readiness?.recordKind === 'status'
    && adapter.readiness.status === 'ready'
    && adapter.readiness.outputMode === 'flow-summary';
  const completionMatches =
    adapter?.completion?.match?.recordKind === 'stats'
    && adapter.completion.match.final === true
    && adapter.completion.match.outputMode === 'flow-summary';

  if (
    !adapter
    || adapter.required !== true
    || adapter.longRunning !== true
    || !commandMatches
    || !readinessMatches
    || !completionMatches
  ) {
    throw new Error(
      'privileged build session uses an incompatible nosh-l4 collector contract; '
      + 'refresh the host bundle from the reviewed checkout with '
      + './scripts/reset-nosh-guard.sh --replace-config before profiling '
      + '(required command, readiness, and completion outputMode: flow-summary)',
    );
  }
}

async function collectBuildHistory(builder, metadata, passDir, dependencies = {}) {
  const buildId = buildHistoryId(builder, metadata);
  if (!buildId) {
    return { available: false, reason: 'build metadata did not include a build reference' };
  }
  const inspect = runSync('docker', [
    'buildx', 'history', 'inspect',
    '--builder', builder.builderName,
    '--format', 'json',
    buildId,
  ], {
    ...dependencies,
    allowFailure: true,
    spawnOptions: {
      ...dependencies.spawnOptions,
      timeout: 60_000,
    },
  });
  if (inspect.status !== 0) {
    return {
      available: false,
      reason: buildHistoryFailureReason(
        inspect.stderr || inspect.stdout,
        `Buildx history inspect failed with status ${inspect.status}`,
      ),
    };
  }
  const historyPath = path.join(passDir, 'buildx-history.json');
  await fs.writeFile(historyPath, inspect.stdout, { flag: 'wx', mode: 0o600 });
  const recordPath = path.join(passDir, 'buildx-record.dockerbuild');
  const exportArgs = [
    'buildx', 'history', 'export',
    '--builder', builder.builderName,
    '--finalize',
    buildId,
  ];
  const exported = (dependencies.spawnSyncImpl || spawnSync)(
    'docker',
    exportArgs,
    {
      encoding: null,
      maxBuffer: MAX_BUILDX_HISTORY_EXPORT_BYTES,
      stdio: ['ignore', 'pipe', 'pipe'],
      timeout: 60_000,
    },
  );
  const exportError = exported.error?.message
    ? buildHistoryFailureReason(exported.error.message)
    : exported.status === 0
      ? null
      : buildHistoryFailureReason(
          Buffer.from(exported.stderr || '').toString('utf8'),
          `Buildx history export failed with status ${exported.status}`,
        );
  if (!exportError) {
    const record = Buffer.isBuffer(exported.stdout)
      ? exported.stdout
      : Buffer.from(exported.stdout || '', 'utf8');
    if (record.length > MAX_BUILDX_HISTORY_EXPORT_BYTES) {
      throw new Error('Buildx history export exceeded its byte limit');
    }
    await fs.writeFile(recordPath, record, { flag: 'wx', mode: 0o600 });
  }
  return {
    available: true,
    historyPath,
    recordPath: exportError ? null : recordPath,
    exportError,
  };
}

async function runPass(profile, invocation, builder, pass, options, dependencies) {
  const reportProgress = progressReporter(dependencies);
  const passDir = await secureUserDirectory(path.join(profile.bundleDir, pass));
  const runId = `${profile.profileId}-${pass}`;
  const clientPid = process.pid;
  const beginPayload = {
    runId,
    mode: profile.mode,
    pass,
    depth: profile.depth,
    workdir: invocation.context,
    workspaceDev: invocation.contextIdentity.dev,
    workspaceIno: invocation.contextIdentity.ino,
    builderContainerId: builder.containerId,
    builderName: builder.builderName,
    builderNode: builder.builderNode,
    builderImage: profile.builderImage,
    clientPid,
    clientStartTime: procStartTime(clientPid),
    clientUid: typeof process.getuid === 'function' ? process.getuid() : 0,
    clientGid: typeof process.getgid === 'function' ? process.getgid() : 0,
  };
  const privileged = dependencies.privilegedInvoker || defaultPrivilegedInvoker;
  reportProgress(`[build] preparing ${pass} sensors`);
  const session = privileged('begin', beginPayload, dependencies);
  const build = buildCommand(invocation, builder, pass, {
    passDir,
    compare: options.cacheMode === 'compare',
    forceClean: options.forceClean,
    httpBuild: profile.httpBuild || null,
  });
  const progressPath = path.join(passDir, 'buildx-progress.raw.jsonl');
  const buildStartedAt = new Date().toISOString();
  let execution;
  let metadata = null;
  let history = null;
  let finish;
  try {
    assertBuildL4FlowSummaryContract(session);
    reportProgress(`[build] starting ${pass} pass`);
    execution = await runStreamingBuild(build.args, progressPath, dependencies);
    const buildFinishedAt = new Date().toISOString();
    metadata = await readOptionalJson(build.metadataPath);
    finish = privileged('finish', {
      runId: session.runId,
      exportEvidence: true,
      result: {
        buildExitCode: execution.status,
        buildStartedAt,
        buildFinishedAt,
        metadata: resultMetadata(metadata),
        limitations: [],
      },
    }, dependencies);
    finish.userEvidenceManifest = await adoptBuildEvidence(
      finish.userEvidenceManifest,
      passDir,
    );
    try {
      history = await collectBuildHistory(builder, metadata, passDir, dependencies);
    } catch (error) {
      history = {
        available: false,
        reason: buildHistoryFailureReason(error.message),
      };
    }
  } catch (error) {
    try {
      const aborted = privileged('abort', {
        runId: session.runId,
        exportEvidence: true,
        reason: error.message,
      }, dependencies);
      if (aborted.userEvidenceManifest) {
        await adoptBuildEvidence(aborted.userEvidenceManifest, passDir);
      }
    } catch (cleanupError) {
      throw new AggregateError(
        [error, cleanupError],
        'profiled build failed and collector cleanup was incomplete',
      );
    }
    throw error;
  }
  return {
    pass,
    runId: session.runId,
    passDir,
    progressPath,
    metadataPath: build.metadataPath,
    status: execution.status,
    signal: execution.signal,
    metadata: resultMetadata(metadata),
    history,
    evidenceComplete: finish.evidenceComplete === true,
    buildSucceeded: finish.buildSucceeded === true,
    evidenceManifest: finish.userEvidenceManifest || finish.evidenceManifest || null,
    evidenceDir: finish.userEvidenceManifest
      ? path.dirname(finish.userEvidenceManifest)
      : finish.evidenceDir || null,
    manifest: finish.manifest || null,
  };
}

function cleanupBuilder(builderName, cacheMode, dependencies = {}) {
  const args = ['buildx', 'rm'];
  if (cacheMode === 'warm') {
    args.push('--keep-state');
  }
  args.push(builderName);
  return runSync('docker', args, { ...dependencies, allowFailure: true });
}

async function writeInitialBundle(profile, invocation, docker, options) {
  await fs.writeFile(
    path.join(profile.bundleDir, 'invocation.json'),
    `${JSON.stringify({
      apiVersion: 'notty.dev/v1alpha1',
      kind: 'NoshBuildInvocation',
      profileId: profile.profileId,
      mode: profile.mode,
      cacheMode: options.cacheMode,
      depth: options.depth,
      httpCapture: options.httpCapture || 'none',
      builderImage: profile.builderImage,
      dockerEndpoint: docker.endpoint,
      invocation: invocation.sanitized,
      startedAt: profile.startedAt,
    }, null, 2)}\n`,
    { flag: 'wx', mode: 0o600 },
  );
}

async function writeFallbackSummary(profile, invocation, passes, options) {
  const complete = passes.every((entry) => entry.evidenceComplete);
  const succeeded = passes.every((entry) => entry.buildSucceeded);
  const cold = passes.find((entry) => entry.pass === 'cold' || entry.pass === 'single');
  const document = {
    apiVersion: 'notty.dev/v1alpha1',
    kind: options.mode === 'build-net-learn'
      ? 'NoshBuildNetworkCandidate'
      : 'NoshBuildProfileCandidate',
    schemaVersion: 1,
    profileId: profile.profileId,
    createdAt: new Date().toISOString(),
    status: complete && succeeded ? 'candidate' : 'diagnostic-only',
    complete,
    buildSucceeded: succeeded,
    promotion: {
      eligible: false,
      reasons: [
        'build profile approval and enforcement are not implemented',
        ...(!complete ? ['one or more evidence passes are incomplete'] : []),
        ...(!succeeded ? ['one or more build passes failed'] : []),
      ],
    },
    subject: {
      context: invocation.context,
      dockerfile: invocation.dockerfile,
      target: invocation.target,
      platform: invocation.platform,
    },
    output: cold?.metadata || {},
    passes,
    independentFromRuntimeProfiles: true,
  };
  await fs.writeFile(
    path.join(profile.bundleDir, 'candidate.json'),
    `${JSON.stringify(document, null, 2)}\n`,
    { flag: 'wx', mode: 0o600 },
  );
  return document;
}

function sourcePathForPass(entry, name) {
  const source = entry.manifest?.sources?.find((candidate) => candidate.name === name);
  const selected = source?.file?.path || source?.file || null;
  if (!selected || !entry.evidenceDir) {
    return null;
  }
  const resolved = path.isAbsolute(selected)
    ? selected
    : path.resolve(entry.evidenceDir, selected);
  const relative = path.relative(path.resolve(entry.evidenceDir), resolved);
  if (!relative || relative.startsWith('..') || path.isAbsolute(relative)) {
    throw new Error(`build evidence source escaped its pass bundle: ${name}`);
  }
  return resolved;
}

async function readJsonLines(filePath, maximumBytes = 128 * 1024 * 1024) {
  if (!filePath) {
    return { records: [], parseFailures: 1 };
  }
  const stat = await fs.stat(filePath);
  if (!stat.isFile() || stat.size > maximumBytes) {
    throw new Error(`profile source is not a supported regular file: ${filePath}`);
  }
  const records = [];
  let parseFailures = 0;
  for (const line of (await fs.readFile(filePath, 'utf8')).split(/\r?\n/)) {
    if (!line) {
      continue;
    }
    try {
      records.push(JSON.parse(line));
    } catch {
      parseFailures += 1;
    }
  }
  return { records, parseFailures };
}

function increment(map, key, amount = 1) {
  map.set(key, (map.get(key) || 0) + amount);
}

function bigIntValue(value) {
  try {
    return BigInt(value || 0);
  } catch {
    return 0n;
  }
}

function decimalCounter(value) {
  const normalized = String(value ?? '').trim();
  return /^(0|[1-9][0-9]*)$/.test(normalized) ? normalized : null;
}

function sumDecimalCounters(records, field) {
  let total = 0n;
  for (const record of records) {
    if (record[field] == null) return null;
    total += BigInt(record[field]);
  }
  return total.toString();
}

function isPrivateAddress(address) {
  const value = String(address || '').toLowerCase();
  if (
    value === '::1'
    || value.startsWith('fc')
    || value.startsWith('fd')
    || value.startsWith('fe8')
    || value.startsWith('fe9')
    || value.startsWith('fea')
    || value.startsWith('feb')
  ) {
    return true;
  }
  const octets = value.split('.').map(Number);
  return octets.length === 4 && (
    octets[0] === 10
    || octets[0] === 127
    || (octets[0] === 169 && octets[1] === 254)
    || (octets[0] === 172 && octets[1] >= 16 && octets[1] <= 31)
    || (octets[0] === 192 && octets[1] === 168)
  );
}

function normalizeObservedDnsName(value) {
  const normalized = String(value || '').trim().toLowerCase();
  if (!normalized) return null;
  return normalized === '.' ? '.' : normalized.replace(/\.$/, '');
}

function dnsObservationId(pass, record, timestampNs) {
  const correlationId = String(record?.dns?.correlation?.id || '').trim();
  const kind = String(record?.eventKind || '').trim();
  if (!correlationId || !kind || timestampNs == null) return null;
  return `${pass}:${correlationId}:${kind}:${timestampNs}`;
}

function validDnsObservation(query, correlation) {
  const expectedCorrelationId = [
    'udp53',
    query.socketCookie,
    query.transactionId,
    query.clientPort,
    query.resolver.address,
    query.resolver.port,
  ].join(':');
  return correlation.keyVersion === 1
    && Number.isSafeInteger(query.queryType)
    && query.queryType >= 0
    && query.queryType <= 65_535
    && Number.isSafeInteger(query.queryClass)
    && query.queryClass >= 0
    && query.queryClass <= 65_535
    && Number.isSafeInteger(query.transactionId)
    && query.transactionId >= 0
    && query.transactionId <= 65_535
    && Number.isSafeInteger(query.clientPort)
    && query.clientPort >= 1
    && query.clientPort <= 65_535
    && query.resolver.port === 53
    && net.isIP(query.resolver.address) !== 0
    && decimalString(query.socketCookie) != null
    && correlation.complete === (query.socketCookie !== '0')
    && Number(correlation.clientPort) === query.clientPort
    && Number(correlation.serverPort) === query.resolver.port
    && String(correlation.serverAddress || '').toLowerCase()
      === query.resolver.address
    && String(correlation.id || '') === expectedCorrelationId;
}

function dnsTransactionKey(query) {
  return JSON.stringify([
    query.pass,
    query.socketCookie,
    query.transactionId,
    query.clientPort,
    query.resolver.address,
    query.resolver.port,
    query.qname,
    query.queryType,
    query.queryClass,
  ]);
}

function dnsAddressFamily(kind) {
  if (kind === 'ipv4') return 'ipv4';
  if (kind === 'ipv6') return 'ipv6';
  return null;
}

function decimalString(value, { nonzero = false } = {}) {
  const normalized = String(value ?? '').trim();
  const pattern = nonzero ? /^[1-9][0-9]*$/ : /^(0|[1-9][0-9]*)$/;
  return pattern.test(normalized) ? normalized : null;
}

function normalizeUrlObservation(pass, record, expectedTargetCgroupId) {
  if (!record || typeof record !== 'object' || Array.isArray(record)) return null;
  const scheme = String(record.scheme || '').trim().toLowerCase();
  const host = normalizeUrlHost(record.host);
  const resourcePath = String(record.path || '');
  const processName = String(record.process || '');
  const port = Number(record.port);
  const pid = Number(record.pid);
  const tid = Number(record.tid);
  if (
    record.schemaVersion !== 1
    || record.recordKind !== 'url-observation'
    || record.observationOnly !== true
    || record.provider !== 'libcurl'
    || record.source !== 'libcurl:CURLOPT_URL'
    || !/^[a-z][a-z0-9+.-]{0,31}$/.test(scheme)
    || host == null
    || !Number.isSafeInteger(port)
    || port < 1
    || port > 65_535
    || !resourcePath.startsWith('/')
    || resourcePath.length > 512
    || /[\x00-\x1f\x7f?#]/.test(resourcePath)
    || !processName
    || processName.length > 15
    || !Number.isSafeInteger(pid)
    || pid < 1
    || !Number.isSafeInteger(tid)
    || tid < 1
    || decimalString(record.timestampUnixNs) == null
    || decimalString(record.timestampMonotonicNs) == null
    || decimalString(record.targetCgroupId, { nonzero: true }) == null
    || decimalString(record.cgroupId, { nonzero: true }) == null
    || record.targetCgroupId !== expectedTargetCgroupId
    || typeof record.pathTruncated !== 'boolean'
  ) {
    return null;
  }
  const identity = JSON.stringify([
    pass,
    record.timestampMonotonicNs,
    record.targetCgroupId,
    record.cgroupId,
    pid,
    tid,
    scheme,
    host,
    port,
  ]);
  return {
    // Keep the producer identity byte-for-byte aligned with the artifact
    // validator's stable sha256 digest representation. The path remains
    // deliberately absent from this identity.
    id: `url:sha256:${sha256(identity)}`,
    provider: 'libcurl',
    scheme,
    host,
    port,
    path: resourcePath,
    pathTruncated: record.pathTruncated,
    process: processName,
    pid,
    tid,
    timestampUnixNs: String(record.timestampUnixNs),
    timestampMonotonicNs: String(record.timestampMonotonicNs),
    targetCgroupId: String(record.targetCgroupId),
    cgroupId: String(record.cgroupId),
    pass,
    source: 'nosh-url',
  };
}

const URL_STAT_COUNTERS = Object.freeze([
  'ringbufDrops',
  'configMissing',
  'cgroupFilterErrors',
  'readErrors',
  'optionCalls',
  'rawObservations',
  'discoveryScans',
  'processesInspected',
  'libraryMappingsSeen',
  'attachments',
  'discoveryMisses',
  'sanitizerRejects',
  'pathTruncations',
  'decoderErrors',
  'observations',
  'outputLimitReached',
]);

const URL_CORRELATION_WINDOW_NS = 30_000_000_000n;
const DNS_ADDRESS_BINDING_MAX_TTL_SECONDS = 300;
const DNS_TRANSACTION_WINDOW_NS = 30_000_000_000n;
const DNS_QUERY_ATTEMPT_WINDOW_NS = 30_000_000_000n;

function boundedTemporalJoin(earlier, later) {
  const start = decimalBigInt(earlier);
  const end = decimalBigInt(later);
  return start != null
    && end != null
    && end >= start
    && end - start <= URL_CORRELATION_WINDOW_NS;
}

function nearestUniqueUrlResource(candidates) {
  let newest = null;
  let selected = null;
  let tied = false;
  for (const candidate of candidates) {
    const timestamp = decimalBigInt(candidate.timestampUnixNs);
    if (timestamp == null) continue;
    if (newest == null || timestamp > newest) {
      newest = timestamp;
      selected = candidate;
      tied = false;
    } else if (timestamp === newest) {
      tied = true;
    }
  }
  return tied ? null : selected;
}

function urlLiteralAddress(host) {
  const value = String(host || '');
  const unwrapped = value.startsWith('[') && value.endsWith(']')
    ? value.slice(1, -1)
    : value;
  return net.isIP(unwrapped) ? unwrapped.toLowerCase() : null;
}

function normalizeUrlHost(value) {
  const host = String(value || '').trim().toLowerCase().replace(/\.$/, '');
  if (
    !host
    || host.length > 253
    || /[\s\x00-\x1f\x7f\/@?#\\%]/.test(host)
    || host.includes('..')
  ) {
    return null;
  }
  if (host.includes('[') || host.includes(']') || host.includes(':')) {
    if (
      !host.startsWith('[')
      || !host.endsWith(']')
      || net.isIP(host.slice(1, -1)) !== 6
    ) {
      return null;
    }
    try {
      return new URL(`http://${host}/`).hostname;
    } catch {
      return null;
    }
  }
  return host;
}

function normalizeUrlFinalStats(pass, record, expectedTargetCgroupId) {
  if (
    !record
    || typeof record !== 'object'
    || Array.isArray(record)
    || record.schemaVersion !== 1
    || record.recordKind !== 'stats'
    || record.final !== true
    || record.provider !== 'libcurl'
    || record.observationOnly !== true
    || record.coverageComplete !== false
    || typeof record.coverageLimitation !== 'string'
    || !record.coverageLimitation.trim()
    || decimalString(record.timestampUnixNs) == null
    || decimalString(record.cgroupId, { nonzero: true }) == null
    || record.cgroupId !== expectedTargetCgroupId
    || !Array.isArray(record.providersAttached)
    || record.providersAttached.some((provider) => provider !== 'libcurl')
    || !record.counters
    || typeof record.counters !== 'object'
    || Array.isArray(record.counters)
  ) {
    return null;
  }
  const counters = {};
  for (const name of URL_STAT_COUNTERS) {
    const normalized = decimalString(record.counters[name]);
    if (normalized == null) return null;
    counters[name] = normalized;
  }
  return {
    pass,
    timestampUnixNs: String(record.timestampUnixNs),
    cgroupId: String(record.cgroupId),
    providersAttached: [...new Set(record.providersAttached)].sort(),
    coverageLimitation: record.coverageLimitation.trim(),
    counters,
  };
}

function decimalBigInt(value) {
  const normalized = String(value ?? '').trim();
  return /^(0|[1-9][0-9]*)$/.test(normalized) ? BigInt(normalized) : null;
}

function keyValueCounters(source) {
  const result = {};
  for (const line of String(source || '').split(/\r?\n/).filter(Boolean)) {
    const [key, value] = line.trim().split(/\s+/, 2);
    const parsed = decimalBigInt(value);
    if (key && parsed != null) result[key] = parsed;
  }
  return result;
}

function counterDelta(before, after, key) {
  const left = before[key];
  const right = after[key];
  return left != null && right != null && right >= left
    ? (right - left).toString()
    : null;
}

function signedGaugeDelta(before, after) {
  const left = decimalBigInt(before);
  const right = decimalBigInt(after);
  return left != null && right != null ? (right - left).toString() : null;
}

function aggregateIo(source) {
  const totals = {};
  for (const line of String(source || '').split(/\r?\n/).filter(Boolean)) {
    const [, ...fields] = line.trim().split(/\s+/);
    for (const field of fields) {
      const [key, value] = field.split('=', 2);
      const parsed = decimalBigInt(value);
      if (key && parsed != null) totals[key] = (totals[key] || 0n) + parsed;
    }
  }
  return totals;
}

function pressureTotals(source) {
  const result = {};
  for (const line of String(source || '').split(/\r?\n/).filter(Boolean)) {
    const [scope, ...fields] = line.trim().split(/\s+/);
    const total = fields.find((field) => field.startsWith('total='));
    const parsed = decimalBigInt(total?.slice('total='.length));
    if (scope && parsed != null) result[scope] = parsed;
  }
  return result;
}

function cgroupPassMetrics(pass, before, after) {
  const required = [
    'cpu.stat',
    'cpu.pressure',
    'io.stat',
    'io.pressure',
    'memory.current',
    'memory.events',
    'memory.pressure',
    'pids.current',
  ];
  const missing = required.filter((name) => (
    typeof before?.[name] !== 'string'
    || typeof after?.[name] !== 'string'
    || (name !== 'io.stat' && (!before[name].trim() || !after[name].trim()))
  ));
  if (missing.length) {
    throw new Error(`required cgroup metrics are missing: ${missing.join(', ')}`);
  }
  const cpuBefore = keyValueCounters(before['cpu.stat']);
  const cpuAfter = keyValueCounters(after['cpu.stat']);
  const memoryBefore = keyValueCounters(before['memory.events']);
  const memoryAfter = keyValueCounters(after['memory.events']);
  const pidsBefore = keyValueCounters(before['pids.events']);
  const pidsAfter = keyValueCounters(after['pids.events']);
  const ioBefore = aggregateIo(before['io.stat']);
  const ioAfter = aggregateIo(after['io.stat']);
  const pressure = {};
  for (const controller of ['cpu', 'io', 'memory']) {
    const pressureBefore = pressureTotals(before[`${controller}.pressure`]);
    const pressureAfter = pressureTotals(after[`${controller}.pressure`]);
    pressure[controller] = {
      someTotalUsec: counterDelta(pressureBefore, pressureAfter, 'some'),
      fullTotalUsec: counterDelta(pressureBefore, pressureAfter, 'full'),
    };
  }
  return {
    pass,
    cpu: Object.fromEntries([
      'usage_usec',
      'user_usec',
      'system_usec',
      'nr_periods',
      'nr_throttled',
      'throttled_usec',
    ].map((key) => [key, counterDelta(cpuBefore, cpuAfter, key)])),
    memory: {
      currentBeforeBytes: decimalCounter(before['memory.current']),
      currentAfterBytes: decimalCounter(after['memory.current']),
      currentDeltaBytes: signedGaugeDelta(
        before['memory.current'],
        after['memory.current'],
      ),
      peakAfterBytes: decimalCounter(after['memory.peak']),
      events: Object.fromEntries(
        [...new Set([...Object.keys(memoryBefore), ...Object.keys(memoryAfter)])]
          .sort()
          .map((key) => [key, counterDelta(memoryBefore, memoryAfter, key)]),
      ),
    },
    io: Object.fromEntries(
      [...new Set([...Object.keys(ioBefore), ...Object.keys(ioAfter)])]
        .sort()
        .map((key) => [key, counterDelta(ioBefore, ioAfter, key)]),
    ),
    pressure,
    pids: {
      currentBefore: decimalCounter(before['pids.current']),
      currentAfter: decimalCounter(after['pids.current']),
      events: Object.fromEntries(
        [...new Set([...Object.keys(pidsBefore), ...Object.keys(pidsAfter)])]
          .sort()
          .map((key) => [key, counterDelta(pidsBefore, pidsAfter, key)]),
      ),
    },
  };
}

function buildkitPassSummary(pass, records) {
  const vertices = new Map();
  for (const record of records) {
    for (const vertex of record.vertexes || []) {
      if (!vertex?.digest) {
        continue;
      }
      vertices.set(vertex.digest, { ...vertices.get(vertex.digest), ...vertex });
    }
  }
  const summarized = [...vertices.values()].map((vertex) => {
    const started = vertex.started ? Date.parse(vertex.started) : NaN;
    const completed = vertex.completed ? Date.parse(vertex.completed) : NaN;
    return {
      id: `sha256:${sha256(String(vertex.digest))}`,
      nameHash: `sha256:${sha256(String(vertex.name || ''))}`,
      cached: vertex.cached === true,
      durationMs: Number.isFinite(started) && Number.isFinite(completed)
        ? Math.max(0, completed - started)
        : null,
      error: vertex.error ? true : false,
    };
  });
  return {
    pass,
    vertexCount: summarized.length,
    cachedVertices: summarized.filter((entry) => entry.cached).length,
    failedVertices: summarized.filter((entry) => entry.error).length,
    longest: summarized
      .filter((entry) => entry.durationMs != null)
      .sort((left, right) => right.durationMs - left.durationMs)
      .slice(0, 10),
  };
}

async function summarizeBuildPasses(passes) {
  const commandCounts = new Map();
  const syscallTotals = new Map();
  const destinations = new Map();
  const qnames = new Set();
  const dnsQueries = new Map();
  const dnsAnswers = new Map();
  const dnsSnapshots = new Map();
  const dnsAddressBindings = new Map();
  const dnsTransactionQueries = new Map();
  const correlations = new Map();
  const resources = new Map();
  const networkAttempts = [];
  const buildkit = [];
  const cgroup = [];
  const metricFailures = [];
  const collectorFinalStats = [];
  const urlFinalStats = [];
  const urlCoverageLimitations = new Set();
  const urlProviders = new Set();
  let execEvents = 0;
  let exitEvents = 0;
  let parseFailures = 0;
  let urlSourcePasses = 0;
  let urlParseFailures = 0;
  for (const entry of passes) {
    const progress = await readJsonLines(entry.progressPath);
    parseFailures += progress.parseFailures;
    buildkit.push(buildkitPassSummary(entry.pass, progress.records));
    try {
      const before = await readOptionalJson(sourcePathForPass(entry, 'cgroup-before.json'));
      const after = await readOptionalJson(sourcePathForPass(entry, 'cgroup-after.json'));
      if (!before || !after) throw new Error('cgroup snapshots are missing');
      cgroup.push(cgroupPassMetrics(entry.pass, before, after));
    } catch (error) {
      metricFailures.push(`${entry.pass} cgroup metrics unavailable: ${error.message}`);
    }
    const behavior = await readJsonLines(sourcePathForPass(entry, 'nosh-build'));
    parseFailures += behavior.parseFailures;
    for (const record of behavior.records) {
      if (record.eventKind === 'process-exec') {
        execEvents += 1;
        increment(commandCounts, String(record.process?.comm || 'unknown'));
      } else if (record.eventKind === 'process-exit') {
        exitEvents += 1;
      } else if (
        ['dns-query', 'dns-response'].includes(record.eventKind)
        && record.dns?.qname
      ) {
        const qname = normalizeObservedDnsName(record.dns.qname);
        const correlation = record.dns.correlation || {};
        const resolverAddress = String(record.network?.serverAddress || '').toLowerCase();
        const timestampNs = decimalCounter(record.timestampNs);
        const observationId = dnsObservationId(entry.pass, record, timestampNs);
        const expectedDirection = record.eventKind === 'dns-query'
          ? 'query'
          : 'response';
        if (
          record.schemaVersion !== 2
          || record.recordKind !== 'event'
          || record.metadataOnly !== true
          || record.dns.transport !== 'udp'
          || record.network?.protocol !== 'udp'
          || record.network?.direction !== expectedDirection
          || !qname
          || !observationId
          || !resolverAddress
          || timestampNs == null
        ) {
          parseFailures += 1;
          continue;
        }
        qnames.add(qname);
        const query = {
          id: observationId,
          pass: entry.pass,
          timestampNs,
          transport: 'udp',
          qname,
          queryType: Number(record.dns.queryType),
          queryClass: Number(record.dns.queryClass),
          resolver: {
            address: resolverAddress,
            port: Number(record.network.serverPort),
          },
          clientPort: Number(record.network.clientPort),
          socketCookie: String(correlation.socketCookie || '0'),
          transactionId: Number(correlation.transactionId),
          correlationComplete: correlation.complete === true,
        };
        if (!validDnsObservation(query, correlation)) {
          parseFailures += 1;
          continue;
        }
        if (record.eventKind === 'dns-query') {
          dnsQueries.set(JSON.stringify(query), query);
          if (query.socketCookie !== '0' && query.correlationComplete) {
            const transactionKey = dnsTransactionKey(query);
            const current = dnsTransactionQueries.get(transactionKey) || [];
            if (!current.some((candidate) => JSON.stringify(candidate) === JSON.stringify(query))) {
              current.push(query);
            }
            dnsTransactionQueries.set(transactionKey, current);
          }
        } else {
          const responseTimestamp = BigInt(timestampNs);
          const matchingQueries = (dnsTransactionQueries.get(
            dnsTransactionKey(query),
          ) || []).filter((candidate) => {
            const queryTimestamp = BigInt(candidate.timestampNs);
            return queryTimestamp <= responseTimestamp
              && responseTimestamp - queryTimestamp <= DNS_TRANSACTION_WINDOW_NS;
          });
          const latestQueryTimestamp = matchingQueries.reduce(
            (latest, candidate) => {
              const timestamp = BigInt(candidate.timestampNs);
              return latest == null || timestamp > latest ? timestamp : latest;
            },
            null,
          );
          const latestQueries = latestQueryTimestamp == null
            ? []
            : matchingQueries.filter(
              (candidate) => BigInt(candidate.timestampNs) === latestQueryTimestamp,
            );
          const matchedQuery = latestQueries.length === 1
            ? latestQueries[0]
            : null;
          const responseId = observationId;
          const responseQueryId = matchedQuery?.id ?? null;
          const response = record.dns.response || {};
          const cnameEdges = new Map();
          let cnameEdgesAmbiguous = false;
          const responseAnswers = [];
          for (const answer of response.answers || []) {
            const ownerName = normalizeObservedDnsName(answer.ownerName);
            const valueKind = String(answer.data?.kind || '');
            const value = valueKind === 'cname'
              ? normalizeObservedDnsName(answer.data?.name)
              : String(answer.data?.address || '').toLowerCase();
            if (!ownerName || !value) {
              parseFailures += 1;
              continue;
            }
            const normalized = {
              snapshotId: responseId,
              queryId: responseQueryId,
              pass: entry.pass,
              index: Number(answer.index),
              ownerName,
              type: Number(answer.type),
              class: Number(answer.class),
              ttl: Number(answer.ttl),
              valueKind,
              value,
            };
            dnsAnswers.set(JSON.stringify(normalized), normalized);
            responseAnswers.push(normalized);
            if (valueKind === 'cname') {
              if (cnameEdges.has(ownerName)) {
                cnameEdgesAmbiguous = true;
              } else {
                cnameEdges.set(ownerName, { name: value, ttl: normalized.ttl });
              }
            }
          }
          const namesInChain = new Set([qname]);
          const cnameTtlCaps = new Map([[qname, null]]);
          let currentName = qname;
          let cnameChainComplete = true;
          for (let depth = 0; depth < 16; depth += 1) {
            const edge = cnameEdges.get(currentName);
            if (!edge) break;
            if (
              !Number.isSafeInteger(edge.ttl)
              || edge.ttl < 0
              || namesInChain.has(edge.name)
            ) {
              cnameChainComplete = false;
              break;
            }
            const priorTtl = cnameTtlCaps.get(currentName);
            const nextTtl = priorTtl == null
              ? edge.ttl
              : Math.min(priorTtl, edge.ttl);
            const nextName = edge.name;
            namesInChain.add(nextName);
            cnameTtlCaps.set(nextName, nextTtl);
            currentName = nextName;
          }
          if (cnameEdges.has(currentName)) cnameChainComplete = false;
          const addressCandidates = responseAnswers
            .filter((answer) => dnsAddressFamily(answer.valueKind))
            .map((answer) => ({
              address: answer.value,
              family: dnsAddressFamily(answer.valueKind),
              ownerName: answer.ownerName,
              ttl: answer.ttl,
              effectiveTtl: cnameTtlCaps.get(answer.ownerName) == null
                ? answer.ttl
                : Math.min(cnameTtlCaps.get(answer.ownerName), answer.ttl),
            }));
          const addresses = addressCandidates.map((address) => ({
            address: address.address,
            family: address.family,
            ownerName: address.ownerName,
            ttl: address.ttl,
          }));
          const snapshot = {
            id: responseId,
            queryId: responseQueryId,
            pass: entry.pass,
            timestampNs,
            qname,
            queryType: Number(record.dns.queryType),
            queryClass: Number(record.dns.queryClass),
            resolver: {
              address: resolverAddress,
              port: Number(record.network.serverPort),
            },
            socketCookie: query.socketCookie,
            transactionId: query.transactionId,
            clientPort: query.clientPort,
            queryTimestampNs: matchedQuery?.timestampNs ?? null,
            correlationComplete: query.correlationComplete && matchedQuery != null,
            responseCode: Number(response.responseCode),
            truncated: response.truncated === true,
            parseComplete: response.parseComplete === true,
            answerLimitReached: response.answerLimitReached === true,
            answersDeclared: Number(response.answersDeclared),
            answersCaptured: Number(response.answersCaptured),
            cnameChain: [...namesInChain],
            addresses,
          };
          dnsSnapshots.set(JSON.stringify(snapshot), snapshot);
          const responseComplete = snapshot.correlationComplete
            && snapshot.responseCode === 0
            && snapshot.truncated === false
            && snapshot.parseComplete === true
            && snapshot.answerLimitReached === false
            && cnameChainComplete
            && cnameEdgesAmbiguous === false
            && Number.isSafeInteger(snapshot.answersDeclared)
            && snapshot.answersDeclared === snapshot.answersCaptured;
          for (const address of addressCandidates) {
            if (
              !responseComplete
              || address.ownerName !== currentName
              || query.queryClass !== 1
              || (address.family === 'ipv4' && query.queryType !== 1)
              || (address.family === 'ipv6' && query.queryType !== 28)
              || !Number.isSafeInteger(address.effectiveTtl)
              || address.effectiveTtl < 1
            ) {
              continue;
            }
            const boundedTtl = Math.min(
              address.effectiveTtl,
              DNS_ADDRESS_BINDING_MAX_TTL_SECONDS,
            );
            const expiresTimestampNs = (
              BigInt(timestampNs) + BigInt(boundedTtl) * 1_000_000_000n
            ).toString();
            const current = dnsAddressBindings.get(address.address) || [];
            current.push({
              snapshotId: responseId,
              queryId: responseQueryId,
              pass: entry.pass,
              qname,
              ownerName: address.ownerName,
              address: address.address,
              family: address.family,
              ttl: address.ttl,
              responseTimestampNs: timestampNs,
              expiresTimestampNs,
              correlationComplete: true,
              responseComplete: true,
            });
            dnsAddressBindings.set(address.address, current);
          }
        }
      } else if (record.recordKind === 'syscall-summary') {
        const number = String(record.syscallNumber);
        const current = syscallTotals.get(number) || {
          syscallNumber: Number(record.syscallNumber),
          calls: 0n,
          completions: 0n,
          errors: 0n,
          totalDurationNs: 0n,
          maxDurationNs: 0n,
        };
        current.calls += bigIntValue(record.calls);
        current.completions += bigIntValue(record.completions);
        current.errors += bigIntValue(record.errors);
        current.totalDurationNs += bigIntValue(record.totalDurationNs);
        current.maxDurationNs = current.maxDurationNs > bigIntValue(record.maxDurationNs)
          ? current.maxDurationNs
          : bigIntValue(record.maxDurationNs);
        syscallTotals.set(number, current);
      } else if (record.recordKind === 'stats' && record.final === true) {
        collectorFinalStats.push({
          pass: entry.pass,
          finalTimestampUnixNs: decimalCounter(record.timestampUnixNs),
          inflightSyscalls: decimalCounter(record.inflightSyscalls),
          dnsParseErrors: decimalCounter(record.counters?.dnsParseErrors),
          dnsCompressedNames: decimalCounter(record.counters?.dnsCompressedNames),
          dnsTruncatedNames: decimalCounter(record.counters?.dnsTruncatedNames),
          dnsTruncatedResponses: decimalCounter(record.counters?.dnsTruncatedResponses),
          dnsAnswerLimitReached: decimalCounter(record.counters?.dnsAnswerLimitReached),
          dnsUnsupportedAnswers: decimalCounter(record.counters?.dnsUnsupportedAnswers),
          dnsCorrelationMissing: decimalCounter(record.counters?.dnsCorrelationMissing),
          dnsQueryObservations: decimalCounter(record.counters?.dnsQueryObservations),
          dnsResponseObservations: decimalCounter(record.counters?.dnsResponseObservations),
          dnsNamePointers: decimalCounter(record.counters?.dnsNamePointers),
          fileMapFull: decimalCounter(record.counters?.fileMapFull),
          filePathErrors: decimalCounter(record.counters?.filePathErrors),
          fileOpenObservations: decimalCounter(record.counters?.fileOpenObservations),
          fileSummaryRecords: decimalCounter(record.fileSummaryRecords),
        });
      }
    }
    const network = await readJsonLines(sourcePathForPass(entry, 'nosh-l4'));
    parseFailures += network.parseFailures;
    for (const record of network.records) {
      const observed = record.network;
      const destinationPort = Number(observed?.destinationPort);
      if (
        record.eventKind !== 'attempt'
          && record.recordKind !== 'flow-summary'
      ) {
        continue;
      }
      if (
        observed?.direction !== 'egress'
        || !['tcp', 'udp'].includes(observed?.protocol)
        || !observed.destinationAddress
        || !Number.isSafeInteger(destinationPort)
        || destinationPort < 1
        || destinationPort > 65_535
      ) {
        continue;
      }
      const attemptTimestampNs = decimalCounter(
        record.recordKind === 'flow-summary'
          ? record.firstObservedNs
          : (record.timestampNs ?? record.timestampUnixNs),
      );
      const lastAttemptTimestampNs = decimalCounter(
        record.recordKind === 'flow-summary'
          ? record.lastObservedNs
          : (record.timestampNs ?? record.timestampUnixNs),
      );
      const attemptTimestamp = decimalBigInt(attemptTimestampNs);
      const sourcePort = observed.sourcePort == null
        ? null
        : Number(observed.sourcePort);
      const addressBindings = (dnsAddressBindings.get(
        String(observed.destinationAddress).toLowerCase(),
      ) || []).filter((binding) => (
        binding.pass === entry.pass
        && binding.correlationComplete === true
        && binding.responseComplete === true
        && attemptTimestamp != null
        && attemptTimestamp >= BigInt(binding.responseTimestampNs)
        && attemptTimestamp <= BigInt(binding.expiresTimestampNs)
      ));
      const boundNames = [...new Set(
        addressBindings.map((binding) => binding.qname),
      )].sort();
      const destination = {
        fqdn: boundNames.length === 1 ? boundNames[0] : null,
        ip: String(observed.destinationAddress).toLowerCase(),
        protocol: observed.protocol,
        port: destinationPort,
        source: boundNames.length === 1
          ? 'nosh-build-dns+nosh-l4'
          : 'nosh-l4',
      };
      const destinationKey = JSON.stringify(destination);
      destinations.set(destinationKey, destination);
      const detail = {
        pass: entry.pass,
        destinationKey,
        timestampNs: attemptTimestampNs,
        firstTimestampNs: attemptTimestampNs,
        lastTimestampNs: lastAttemptTimestampNs,
        socketCookie: String(record.socketCookie || '0'),
        sourceAddress: net.isIP(String(observed.sourceAddress || '').toLowerCase())
          ? String(observed.sourceAddress).toLowerCase()
          : null,
        sourcePort: Number.isSafeInteger(sourcePort)
          && sourcePort >= 1
          && sourcePort <= 65_535
          ? sourcePort
          : null,
        process: record.process == null
          ? null
          : {
              pid: Number(record.process.pid),
              comm: String(record.process.comm || ''),
            },
      };
      networkAttempts.push({
        ...detail,
        ip: destination.ip,
        protocol: destination.protocol,
        port: destination.port,
      });
      for (const binding of addressBindings) {
        const correlated = {
          kind: 'dns-destination',
          pass: entry.pass,
          snapshotId: binding.snapshotId,
          queryId: binding.queryId,
          qname: binding.qname,
          ownerName: binding.ownerName,
          address: binding.address,
          protocol: destination.protocol,
          port: destination.port,
          destinationKey,
          process: detail.process,
          timestampNs: detail.timestampNs,
        };
        correlations.set(JSON.stringify(correlated), correlated);
      }
    }
    const urlSource = entry.manifest?.sources?.find((source) =>
      source.name === 'nosh-url');
    if (urlSource) {
      urlSourcePasses += 1;
      const expectedTargetCgroupId = decimalString(
        entry.manifest?.builder?.cgroup?.id,
        { nonzero: true },
      );
      const urlPath = sourcePathForPass(entry, 'nosh-url');
      if (!expectedTargetCgroupId) {
        urlCoverageLimitations.add(
          `${entry.pass} optional nosh-url evidence is not bound to an exact builder cgroup ID.`,
        );
      } else if (!urlPath) {
        urlCoverageLimitations.add(
          `${entry.pass} optional nosh-url evidence has no bounded source file.`,
        );
      } else {
        try {
          const urlEvidence = await readJsonLines(urlPath);
          let passParseFailures = urlEvidence.parseFailures;
          const passResources = [];
          const passFinalStats = [];
          for (const record of urlEvidence.records) {
            if (record?.recordKind === 'url-observation') {
              const resource = normalizeUrlObservation(
                entry.pass,
                record,
                expectedTargetCgroupId,
              );
              if (!resource) {
                passParseFailures += 1;
                continue;
              }
              passResources.push(resource);
            } else if (record?.recordKind === 'stats' && record.final === true) {
              const stats = normalizeUrlFinalStats(
                entry.pass,
                record,
                expectedTargetCgroupId,
              );
              if (!stats) {
                passParseFailures += 1;
                continue;
              }
              passFinalStats.push(stats);
            } else if (record?.recordKind !== 'stats') {
              passParseFailures += 1;
            }
          }
          const stats = passFinalStats.length === 1 ? passFinalStats[0] : null;
          const declaredObservations = stats == null
            ? null
            : BigInt(stats.counters.observations);
          const rawObservations = stats == null
            ? null
            : BigInt(stats.counters.rawObservations);
          const optionCalls = stats == null
            ? null
            : BigInt(stats.counters.optionCalls);
          const readErrors = stats == null
            ? null
            : BigInt(stats.counters.readErrors);
          const ringbufDrops = stats == null
            ? null
            : BigInt(stats.counters.ringbufDrops);
          const sanitizerRejects = stats == null
            ? null
            : BigInt(stats.counters.sanitizerRejects);
          const decoderErrors = stats == null
            ? null
            : BigInt(stats.counters.decoderErrors);
          const outputLimitReached = stats == null
            ? null
            : BigInt(stats.counters.outputLimitReached);
          const pathTruncations = stats == null
            ? null
            : BigInt(stats.counters.pathTruncations);
          const attachments = stats == null
            ? null
            : BigInt(stats.counters.attachments);
          const providerAttached = stats?.providersAttached.includes('libcurl') === true;
          const consistencyFailures = [];
          if (passFinalStats.length !== 1) {
            consistencyFailures.push(
              `expected one final stats record, observed ${passFinalStats.length}`,
            );
          }
          if (
            declaredObservations != null
            && declaredObservations !== BigInt(passResources.length)
          ) {
            consistencyFailures.push(
              `declares ${declaredObservations} emitted observations but contains ${passResources.length}`,
            );
          }
          if (
            rawObservations != null
            && declaredObservations != null
            && sanitizerRejects != null
            && decoderErrors != null
            && outputLimitReached != null
            && rawObservations !== declaredObservations
              + sanitizerRejects + decoderErrors + outputLimitReached
          ) {
            consistencyFailures.push(
              'does not conserve raw observations across emitted, rejected, decoder-error, and output-limit outcomes',
            );
          }
          if (
            optionCalls != null
            && rawObservations != null
            && readErrors != null
            && ringbufDrops != null
            && optionCalls !== rawObservations + readErrors + ringbufDrops
          ) {
            consistencyFailures.push(
              'does not conserve CURLOPT_URL calls across observations, read errors, and ring-buffer drops',
            );
          }
          if (
            pathTruncations != null
            && declaredObservations != null
            && pathTruncations > declaredObservations
          ) {
            consistencyFailures.push(
              'declares more path truncations than emitted observations',
            );
          }
          if (
            attachments != null
            && ((attachments > 0n) !== providerAttached
              || (declaredObservations > 0n && attachments === 0n))
          ) {
            consistencyFailures.push(
              'has inconsistent libcurl provider and attachment counters',
            );
          }
          urlParseFailures += passParseFailures;
          if (passParseFailures > 0 || consistencyFailures.length > 0) {
            if (consistencyFailures.length > 0) {
              urlCoverageLimitations.add(
                `${entry.pass} optional nosh-url evidence is internally inconsistent: ${consistencyFailures.join('; ')}.`,
              );
            }
          } else {
            for (const resource of passResources) {
              resources.set(JSON.stringify(resource), resource);
              urlProviders.add(resource.provider);
            }
            urlFinalStats.push(stats);
            stats.providersAttached.forEach((provider) => urlProviders.add(provider));
            urlCoverageLimitations.add(stats.coverageLimitation);
          }
        } catch (error) {
          urlCoverageLimitations.add(
            `${entry.pass} optional nosh-url evidence could not be read from its bounded source file.`,
          );
        }
      }
      if (urlSource.complete !== true) {
        urlCoverageLimitations.add(
          `${entry.pass} optional nosh-url collector did not complete cleanly.`,
        );
      }
    }
  }
  for (const query of dnsQueries.values()) {
    if (!query.correlationComplete || query.socketCookie === '0') continue;
    const queryTimestamp = BigInt(query.timestampNs);
    const candidates = networkAttempts.filter((attempt) => {
      const attemptTimestamp = decimalBigInt(attempt.timestampNs);
      return attempt.pass === query.pass
        && attempt.socketCookie === query.socketCookie
        && attempt.protocol === 'udp'
        && attempt.ip === query.resolver.address
        && attempt.port === query.resolver.port
        && (attempt.sourcePort == null || attempt.sourcePort === query.clientPort)
        && attemptTimestamp != null
        && attemptTimestamp <= queryTimestamp
        && queryTimestamp - attemptTimestamp <= DNS_QUERY_ATTEMPT_WINDOW_NS;
    });
    const latestTimestamp = candidates.reduce((latest, attempt) => {
      const timestamp = BigInt(attempt.timestampNs);
      return latest == null || timestamp > latest ? timestamp : latest;
    }, null);
    const latest = latestTimestamp == null
      ? []
      : candidates.filter(
        (attempt) => BigInt(attempt.timestampNs) === latestTimestamp,
      );
    if (latest.length !== 1) continue;
    const attempt = latest[0];
    const correlated = {
      kind: 'dns-query-process',
      correlationConfidence: 'heuristic-socket-resolver-bounded-time',
      pass: query.pass,
      queryId: query.id,
      socketCookie: query.socketCookie,
      qname: query.qname,
      resolver: query.resolver,
      clientPort: query.clientPort,
      process: attempt.process,
      attemptTimestampNs: attempt.timestampNs,
      timestampNs: query.timestampNs,
    };
    correlations.set(JSON.stringify(correlated), correlated);
  }
  const urlResources = [...resources.values()].sort((left, right) =>
    JSON.stringify(left).localeCompare(JSON.stringify(right)));
  const existingCorrelations = [...correlations.values()];
  const resourceDestinationMatches = new Set();
  for (const query of dnsQueries.values()) {
    const processMatches = existingCorrelations.filter((entry) =>
      entry.kind === 'dns-query-process'
      && entry.queryId === query.id
      && Number.isSafeInteger(entry.process?.pid));
    const resource = nearestUniqueUrlResource(urlResources.filter((entry) =>
      entry.pass === query.pass
      && entry.host === query.qname
      && boundedTemporalJoin(entry.timestampUnixNs, query.timestampNs)
      && processMatches.some((match) => match.process.pid === entry.pid)));
    if (!resource) continue;
    const dnsProcess = processMatches.find((match) =>
      match.process.pid === resource.pid)?.process;
    const correlated = {
      kind: 'resource-dns-query',
      correlationConfidence: 'heuristic-same-pid-host-bounded-time',
      pass: resource.pass,
      resourceId: resource.id,
      provider: resource.provider,
      host: resource.host,
      queryId: query.id,
      qname: query.qname,
      resolver: query.resolver,
      resourceTimestampUnixNs: resource.timestampUnixNs,
      queryTimestampNs: query.timestampNs,
      resourceProcess: {
        pid: resource.pid,
        comm: resource.process,
      },
      dnsProcess,
    };
    correlations.set(JSON.stringify(correlated), correlated);
  }
  for (const destination of existingCorrelations) {
    if (
      destination.kind !== 'dns-destination'
      || !Number.isSafeInteger(destination.process?.pid)
      || decimalBigInt(destination.timestampNs) == null
    ) {
      continue;
    }
    const resource = nearestUniqueUrlResource(urlResources.filter((entry) =>
      entry.pass === destination.pass
      && entry.host === destination.qname
      && entry.port === destination.port
      && entry.pid === destination.process.pid
      && boundedTemporalJoin(entry.timestampUnixNs, destination.timestampNs)));
    if (!resource) continue;
    const correlated = {
      kind: 'resource-destination',
      correlationConfidence: 'heuristic-same-pid-host-port-bounded-time',
      pass: resource.pass,
      resourceId: resource.id,
      provider: resource.provider,
      host: resource.host,
      snapshotId: destination.snapshotId,
      queryId: destination.queryId,
      qname: destination.qname,
      ownerName: destination.ownerName,
      address: destination.address,
      protocol: destination.protocol,
      port: destination.port,
      destinationKey: destination.destinationKey,
      resourceTimestampUnixNs: resource.timestampUnixNs,
      destinationTimestampNs: destination.timestampNs,
      resourceProcess: {
        pid: resource.pid,
        comm: resource.process,
      },
      networkProcess: destination.process,
    };
    correlations.set(JSON.stringify(correlated), correlated);
    resourceDestinationMatches.add(resource.id);
  }
  for (const destination of networkAttempts) {
    if (
      !Number.isSafeInteger(destination.process?.pid)
      || decimalBigInt(destination.timestampNs) == null
    ) {
      continue;
    }
    const resource = nearestUniqueUrlResource(urlResources.filter((entry) =>
      entry.pass === destination.pass
      && urlLiteralAddress(entry.host) === destination.ip
      && entry.port === destination.port
      && entry.pid === destination.process.pid
      && boundedTemporalJoin(entry.timestampUnixNs, destination.timestampNs)));
    if (!resource) continue;
    const correlated = {
      kind: 'resource-direct-destination',
      correlationConfidence: 'heuristic-direct-ip-same-pid-port-bounded-time',
      pass: resource.pass,
      resourceId: resource.id,
      provider: resource.provider,
      host: resource.host,
      address: destination.ip,
      protocol: destination.protocol,
      port: destination.port,
      destinationKey: destination.destinationKey,
      resourceTimestampUnixNs: resource.timestampUnixNs,
      destinationTimestampNs: destination.timestampNs,
      resourceProcess: {
        pid: resource.pid,
        comm: resource.process,
      },
      networkProcess: destination.process,
    };
    correlations.set(JSON.stringify(correlated), correlated);
    resourceDestinationMatches.add(resource.id);
  }
  if (urlResources.length > resourceDestinationMatches.size) {
    urlCoverageLimitations.add(
      `${urlResources.length - resourceDestinationMatches.size} URL observations lacked a unique same-PID, host, port, and bounded-time L4 correlation.`,
    );
  }
  const networkDestinations = [...destinations.values()].sort((left, right) =>
    JSON.stringify(left).localeCompare(JSON.stringify(right)));
  const syscalls = [...syscallTotals.values()]
    .sort((left, right) => (
      left.totalDurationNs === right.totalDurationNs
        ? right.calls > left.calls ? 1 : -1
        : right.totalDurationNs > left.totalDurationNs ? 1 : -1
    ))
    .map((entry) => Object.fromEntries(
      Object.entries(entry).map(([key, value]) => [
        key,
        typeof value === 'bigint' ? value.toString() : value,
      ]),
    ));
  const collectorTotals = {
    inflightSyscalls: sumDecimalCounters(collectorFinalStats, 'inflightSyscalls'),
    dnsParseErrors: sumDecimalCounters(collectorFinalStats, 'dnsParseErrors'),
    dnsCompressedNames: sumDecimalCounters(collectorFinalStats, 'dnsCompressedNames'),
    dnsTruncatedNames: sumDecimalCounters(collectorFinalStats, 'dnsTruncatedNames'),
    dnsTruncatedResponses: sumDecimalCounters(collectorFinalStats, 'dnsTruncatedResponses'),
    dnsAnswerLimitReached: sumDecimalCounters(collectorFinalStats, 'dnsAnswerLimitReached'),
    dnsUnsupportedAnswers: sumDecimalCounters(collectorFinalStats, 'dnsUnsupportedAnswers'),
    dnsCorrelationMissing: sumDecimalCounters(collectorFinalStats, 'dnsCorrelationMissing'),
    dnsQueryObservations: sumDecimalCounters(collectorFinalStats, 'dnsQueryObservations'),
    dnsResponseObservations: sumDecimalCounters(collectorFinalStats, 'dnsResponseObservations'),
    dnsNamePointers: sumDecimalCounters(collectorFinalStats, 'dnsNamePointers'),
    fileMapFull: sumDecimalCounters(collectorFinalStats, 'fileMapFull'),
    filePathErrors: sumDecimalCounters(collectorFinalStats, 'filePathErrors'),
    fileOpenObservations: sumDecimalCounters(collectorFinalStats, 'fileOpenObservations'),
    fileSummaryRecords: sumDecimalCounters(collectorFinalStats, 'fileSummaryRecords'),
  };
  const urlTotals = Object.fromEntries(URL_STAT_COUNTERS.map((name) => {
    let total = 0n;
    for (const stats of urlFinalStats) total += BigInt(stats.counters[name]);
    return [name, total.toString()];
  }));
  if (urlSourcePasses > 0 && urlFinalStats.length !== urlSourcePasses) {
    urlCoverageLimitations.add(
      'Optional userspace URL observation is missing a final stats record for one or more build passes.',
    );
  }
  if (urlParseFailures > 0) {
    urlCoverageLimitations.add(
      `Optional userspace URL observation had ${urlParseFailures} local parse or contract failures.`,
    );
  }
  const urlGapCounters = [
    ['ringbufDrops', 'ring-buffer drops'],
    ['configMissing', 'missing collector configuration'],
    ['cgroupFilterErrors', 'cgroup filter errors'],
    ['readErrors', 'userspace string read errors'],
    ['discoveryMisses', 'dynamic attachment discovery misses'],
    ['sanitizerRejects', 'rejected or unsupported URL values'],
    ['pathTruncations', 'truncated resource paths'],
    ['decoderErrors', 'event decoder errors'],
    ['outputLimitReached', 'evidence output limit events'],
  ];
  for (const [name, label] of urlGapCounters) {
    if (urlTotals[name] !== '0') {
      urlCoverageLimitations.add(`${urlTotals[name]} ${label}.`);
    }
  }
  const urlCoverage = urlSourcePasses > 0
    ? {
        enabled: true,
        providers: [...urlProviders].sort(),
        observations: urlResources.length,
        discoveryMisses: Number(urlTotals.discoveryMisses),
        readErrors: Number(urlTotals.readErrors),
        complete: false,
        limitations: [...urlCoverageLimitations].sort(),
      }
    : {
        enabled: false,
        providers: [],
        observations: 0,
        discoveryMisses: 0,
        readErrors: 0,
        complete: false,
        limitations: [
          'Optional userspace URL observation was not enabled for this build profile.',
        ],
      };
  const allCollectorFinalStatsPresent = collectorFinalStats.length === passes.length
    && collectorFinalStats.every((record) => record.finalTimestampUnixNs != null);
  const syscallDurationTotalsComplete = allCollectorFinalStatsPresent
    && collectorTotals.inflightSyscalls === '0';
  const dnsNameCoverageComplete = allCollectorFinalStatsPresent
    && collectorTotals.dnsParseErrors === '0'
    && collectorTotals.dnsCompressedNames === '0'
    && collectorTotals.dnsTruncatedNames === '0'
    && collectorTotals.dnsTruncatedResponses === '0'
    && collectorTotals.dnsAnswerLimitReached === '0'
    && collectorTotals.dnsUnsupportedAnswers === '0'
    && collectorTotals.dnsCorrelationMissing === '0';
  const diagnosticLimitations = [];
  if (collectorTotals.inflightSyscalls != null && collectorTotals.inflightSyscalls !== '0') {
    diagnosticLimitations.push(
      `${collectorTotals.inflightSyscalls} syscalls were still active at collector shutdown; syscall duration totals are incomplete.`,
    );
  }
  if (!dnsNameCoverageComplete && allCollectorFinalStatsPresent) {
    diagnosticLimitations.push(
      'Build DNS query/answer coverage has parse, truncation, bounded-answer, unsupported-answer, or transaction-correlation gaps; L4 destinations remain available.',
    );
  }
  if (
    allCollectorFinalStatsPresent
    && (collectorTotals.fileMapFull !== '0' || collectorTotals.filePathErrors !== '0')
  ) {
    diagnosticLimitations.push(
      'Build file-open coverage has path-resolution or bounded-map loss and is incomplete.',
    );
  }
  return {
    privateNetworkAttempts: networkAttempts,
    metrics: {
      buildkit,
      cgroup: { passes: cgroup },
      process: {
        execEvents,
        exitEvents,
        commands: [...commandCounts.entries()]
          .map(([command, count]) => ({ command, count }))
          .sort((left, right) => right.count - left.count || left.command.localeCompare(right.command)),
      },
      syscalls: {
        unique: syscalls.length,
        hottest: syscalls.slice(0, 32),
        durationTotalsComplete: syscallDurationTotalsComplete,
        inflightAtStop: collectorTotals.inflightSyscalls,
      },
      network: {
        destinations: networkDestinations.length,
        dnsQueries: dnsQueries.size,
        dnsResponses: dnsSnapshots.size,
        dnsAnswers: dnsAnswers.size,
        dnsCorrelations: [...correlations.values()].filter((entry) =>
          entry.kind.startsWith('dns-')).length,
        urlObservations: urlResources.length,
        urlCorrelations: [...correlations.values()].filter((entry) =>
          entry.kind.startsWith('resource-')).length,
        urlCoverageComplete: false,
        dnsNameCoverageComplete,
        dnsDiagnostics: {
          parseErrors: collectorTotals.dnsParseErrors,
          compressedNames: collectorTotals.dnsCompressedNames,
          truncatedNames: collectorTotals.dnsTruncatedNames,
          truncatedResponses: collectorTotals.dnsTruncatedResponses,
          answerLimitReached: collectorTotals.dnsAnswerLimitReached,
          unsupportedAnswers: collectorTotals.dnsUnsupportedAnswers,
          transactionMisses: collectorTotals.dnsCorrelationMissing,
          queryObservations: collectorTotals.dnsQueryObservations,
          responseObservations: collectorTotals.dnsResponseObservations,
          namePointers: collectorTotals.dnsNamePointers,
        },
      },
      file: {
        openObservations: collectorTotals.fileOpenObservations,
        summaryRecords: collectorTotals.fileSummaryRecords,
        mapFull: collectorTotals.fileMapFull,
        pathErrors: collectorTotals.filePathErrors,
      },
      collectorDiagnostics: {
        noshBuild: {
          passes: collectorFinalStats,
          totals: collectorTotals,
          allFinalStatsPresent: allCollectorFinalStatsPresent,
          syscallDurationTotalsComplete,
          dnsNameCoverageComplete,
        },
        noshUrl: {
          enabled: urlSourcePasses > 0,
          passes: urlFinalStats,
          totals: urlTotals,
          finalStatsPresent: urlFinalStats.length === urlSourcePasses,
          parseFailures: urlParseFailures,
          coverageComplete: false,
          limitations: urlCoverage.limitations,
        },
      },
      parseFailures,
    },
    observations: {
      process: {
        commands: [...commandCounts.keys()].sort(),
      },
      syscalls: syscalls.map((entry) => entry.syscallNumber).sort((a, b) => a - b),
      network: {
        destinations: networkDestinations,
        dns: {
          queries: [...dnsQueries.values()],
          answers: [...dnsAnswers.values()],
          snapshots: [...dnsSnapshots.values()],
        },
        resources: urlResources,
        correlations: [...correlations.values()],
        coverage: {
          dns: {
            queries: dnsQueries.size,
            responses: dnsSnapshots.size,
            answers: dnsAnswers.size,
            transactionMisses: Number(collectorTotals.dnsCorrelationMissing || 0),
            parseFailures: Number(
              bigIntValue(collectorTotals.dnsParseErrors)
              + bigIntValue(collectorTotals.dnsTruncatedNames)
              + bigIntValue(collectorTotals.dnsTruncatedResponses)
              + bigIntValue(collectorTotals.dnsAnswerLimitReached),
            ),
            complete: dnsNameCoverageComplete,
          },
          url: urlCoverage,
        },
        directIp: networkDestinations,
        encryptedDns: networkDestinations.filter((entry) => entry.port === 853),
        privateDestinations: networkDestinations.filter((entry) => isPrivateAddress(entry.ip)),
        parseFailures: parseFailures ? [`${parseFailures} local summary parse failures`] : [],
        unresolved: [...qnames]
          .filter((qname) => ![...dnsSnapshots.values()].some(
            (snapshot) => snapshot.qname === qname && snapshot.addresses.length > 0,
          ))
          .sort(),
      },
    },
    incompleteReasons: [
      ...(parseFailures
        ? [`local build evidence summary had ${parseFailures} parse failures`]
        : []),
      ...metricFailures,
    ],
    limitations: diagnosticLimitations,
  };
}

export async function executeBuildProfile(input = {}, dependencies = {}) {
  const mode = input.mode === 'build-net-learn'
    ? 'build-net-learn'
    : 'build-profile';
  const cacheMode = mode === 'build-net-learn'
    ? 'cold'
    : input.cacheMode || 'compare';
  const httpCapture = input.httpCapture || 'none';
  const httpCaptureSpecified = Object.hasOwn(input, 'httpCapture')
    && input.httpCapture != null;
  if (!['none', 'mitmproxy'].includes(httpCapture)) {
    throw new TypeError('--http-capture must be none or mitmproxy');
  }
  if (mode !== 'build-net-learn' && httpCaptureSpecified) {
    throw new TypeError('--http-capture is supported only by build net learn');
  }
  if (!['compare', 'cold', 'warm'].includes(cacheMode)) {
    throw new TypeError('--cache-mode must be compare, cold, or warm');
  }
  const depth = input.depth || 'balanced';
  if (!['balanced', 'policy', 'deep'].includes(depth)) {
    throw new TypeError('--depth must be balanced, policy, or deep');
  }
  if (depth === 'deep') {
    throw new Error('deep build collectors are not installed; use --depth balanced or policy');
  }
  if (
    !input.dryRun
    && typeof process.geteuid === 'function'
    && process.geteuid() === 0
    && process.env.SUDO_UID != null
  ) {
    throw new Error(
      'run nosh build as the Docker-authorized user without sudo; only sensor sessions elevate',
    );
  }
  const reportProgress = progressReporter(dependencies);
  const workflowLabel = mode === 'build-net-learn'
    ? 'build network learning'
    : 'build profile';
  if (!input.dryRun) {
    reportProgress(`[build] starting ${workflowLabel}`);
  }
  const invocation = await resolveBuildInvocation({
    ...input,
    forceClean:
      mode === 'build-net-learn'
      || cacheMode === 'cold'
      || cacheMode === 'compare',
  });
  if (httpCapture === 'mitmproxy') {
    assertManagedHttpBuildInputsAvailable(invocation);
  }
  if (input.dryRun) {
    return {
      dryRun: true,
      mode,
      cacheMode,
      depth,
      httpCapture,
      invocation: invocation.sanitized,
    };
  }
  let profileDependencies = dependencies;
  const direct = typeof process.geteuid === 'function' && process.geteuid() === 0;
  if (!direct && !dependencies.privilegedInvoker) {
    const guardBin = trustedPrivilegedHelper(resolvePrivilegedGuardPath(dependencies));
    profileDependencies = { ...dependencies, guardBin };
  }
  const docker = (profileDependencies.dockerInfo || dockerInfo)(profileDependencies);
  reportProgress('[build] Docker preflight complete');
  const profileId = crypto.randomUUID();
  const projectKey = sha256(invocation.context);
  const bundleRoot = mode === 'build-net-learn'
    ? 'build-net-profiles'
    : 'build-profiles';
  const selectedHome = input.home || os.homedir();
  const projectDirectory = await secureUserDirectory(path.join(
    selectedHome,
    '.nosh',
    bundleRoot,
    projectKey,
  ));
  const stagingRoot = await secureUserDirectory(path.join(
    projectDirectory,
    '.staging',
  ));
  const bundleDir = await secureUserDirectory(path.join(
    stagingRoot,
    profileId,
  ));
  const builderImage = input.builderImage
    || process.env.NOSH_BUILDKIT_IMAGE
    || DEFAULT_BUILDKIT_IMAGE;
  if (!IMMUTABLE_IMAGE_PATTERN.test(builderImage)) {
    throw new Error(
      'live build profiling requires NOSH_BUILDKIT_IMAGE to use an immutable @sha256 digest',
    );
  }
  const profile = {
    profileId,
    mode,
    cacheMode,
    depth,
    httpCapture,
    bundleDir,
    builderImage,
    startedAt: new Date().toISOString(),
  };
  await writeInitialBundle(profile, invocation, docker, {
    cacheMode,
    depth,
    httpCapture,
  });
  const names = builderNames(
    invocation,
    profileId,
    cacheMode,
    docker.endpoint,
    typeof process.getuid === 'function' ? process.getuid() : 0,
  );
  let builder = null;
  let builderLock = null;
  let httpSession = null;
  let httpEvidence = null;
  const passes = [];
  let primaryError = null;
  let builderCleanupComplete = false;
  let httpCaptureCleanupComplete = httpCapture === 'none';
  try {
    builderLock = await acquireBuilderLock(
      selectedHome,
      names.builderName,
      profileDependencies,
    );
    if (httpCapture === 'mitmproxy') {
      reportProgress('[build] preparing managed HTTP observation proxy');
      const startHttpCapture = profileDependencies.startManagedHttpCapture
        || startManagedHttpCapture;
      httpSession = await startHttpCapture({
        runId: profileId,
        bundleDir,
        dockerfile: invocation.dockerfile.path,
        scriptsDirectory: path.resolve(
          path.dirname(fileURLToPath(import.meta.url)),
          '../../scripts',
        ),
      }, profileDependencies);
      const buildOptions = profileDependencies.managedHttpBuildOptions
        || managedHttpBuildOptions;
      profile.httpBuild = buildOptions(httpSession);
      reportProgress('[build] managed HTTP observation proxy ready');
    }
    reportProgress('[build] preparing BuildKit builder');
    builder = ensureBuilder(
      names,
      builderImage,
      cacheMode,
      profileDependencies,
      { networkName: httpSession?.networkName || null },
    );
    reportProgress('[build] BuildKit builder ready');
    const selectedPasses = cacheMode === 'compare'
      ? ['cold', 'warm']
      : [cacheMode];
    for (const pass of selectedPasses) {
      await assertDockerfileStable(invocation.dockerfile);
      const result = await runPass(
        profile,
        invocation,
        builder,
        pass,
        {
          cacheMode,
          forceClean: mode === 'build-net-learn' || pass === 'cold',
        },
        profileDependencies,
      );
      await assertDockerfileStable(invocation.dockerfile);
      passes.push(result);
      if (result.status !== 0) {
        break;
      }
    }
  } catch (error) {
    primaryError = error;
  } finally {
    try {
      if (httpSession && !httpSession.stopped) {
        reportProgress('[build] stopping managed HTTP observation proxy');
        const stopHttpCapture = profileDependencies.stopManagedHttpCapture
          || stopManagedHttpCapture;
        httpEvidence = await stopHttpCapture(httpSession, profileDependencies);
      }
    } catch (error) {
      primaryError = primaryError
        ? new AggregateError(
            [primaryError, error],
            'build profiling and managed HTTP capture shutdown failed',
          )
        : error;
    }
    try {
      if (builder) {
        reportProgress('[build] cleaning up BuildKit builder');
        const cleanup = cleanupBuilder(builder.builderName, cacheMode, profileDependencies);
        builderCleanupComplete = cleanup.status === 0;
        if (cleanup.status !== 0) {
          const cleanupError = commandError('docker', ['buildx', 'rm', builder.builderName], cleanup);
          primaryError = primaryError
            ? new AggregateError([primaryError, cleanupError], 'build profiling and builder cleanup failed')
            : cleanupError;
        }
      }
    } catch (error) {
      primaryError = primaryError
        ? new AggregateError([primaryError, error], 'build profiling and builder cleanup failed')
        : error;
    }
    try {
      if (httpSession?.networkCreated) {
        const cleanupHttpNetwork = profileDependencies.cleanupManagedHttpCaptureNetwork
          || cleanupManagedHttpCaptureNetwork;
        cleanupHttpNetwork(httpSession, profileDependencies);
      }
      httpCaptureCleanupComplete = httpCapture === 'none'
        || (httpSession?.stopped === true && httpSession?.networkCreated === false);
    } catch (error) {
      primaryError = primaryError
        ? new AggregateError(
            [primaryError, error],
            'build profiling and managed HTTP network cleanup failed',
          )
        : error;
    } finally {
      builderLock?.release();
    }
  }
  let finalized = null;
  if (passes.length) {
    reportProgress('[build] finalizing build evidence');
    let summary;
    try {
      summary = await summarizeBuildPasses(passes);
      if (httpEvidence) {
        const correlateHttpEvidence = profileDependencies.correlateManagedHttpEvidence
          || correlateManagedHttpEvidence;
        const http = correlateHttpEvidence(httpEvidence.records, {
          networkAttempts: summary.privateNetworkAttempts,
          proxyIpv4: httpSession.proxyIpv4,
          proxyPort: httpSession.proxyPort,
          contentManifest: httpEvidence.contentManifest,
        });
        const uncorrelated = http.exchanges.filter(
          (exchange) => exchange.destination == null,
        ).length;
        if (uncorrelated > 0) {
          http.complete = false;
          http.gaps = [...new Set([
            ...http.gaps,
            `${uncorrelated} managed HTTP exchanges have no exact scoped eBPF L4 correlation`,
          ])].sort();
        }
        summary.observations.http = http;
        if (!http.complete) {
          summary.incompleteReasons = [...new Set([
            ...(summary.incompleteReasons || []),
            'managed HTTP capture has unresolved routing or network-provenance gaps',
          ])].sort();
        }
      }
    } catch (error) {
      summary = {
        metrics: {},
        observations: { network: {} },
        incompleteReasons: [`build evidence summary failed: ${error.message}`],
      };
      if (httpCapture === 'mitmproxy') {
        primaryError = primaryError
          ? new AggregateError(
              [primaryError, error],
              'managed HTTP evidence correlation failed',
            )
          : error;
      }
    }
    try {
      finalized = await finalizeBuildPassManifests({
        context: invocation.context,
        runId: profileId,
        profileId,
        mode,
        cacheMode,
        depth,
        httpCapture,
        httpEvidenceSource: httpEvidence?.source || null,
        passes: passes.map((entry) => ({
          ...entry,
          metrics: {
            buildkit: summary.metrics?.buildkit?.find(
              (candidate) => candidate.pass === entry.pass,
            ) || null,
            cgroup: summary.metrics?.cgroup?.passes?.find(
              (candidate) => candidate.pass === entry.pass,
            ) || null,
          },
        })),
        platform: invocation.platform,
        target: invocation.target,
        builderImage,
        dockerEndpoint: docker.endpoint,
        builderCleanupComplete,
        exclusiveBuilderLease: true,
        parentObserved: passes.some((entry) => (
          entry.manifest?.sources?.find((source) => source.name === 'nosh-build')
            ?.completion?.descendantObserved === true
        )),
        freshBuilder: builder?.created === true,
        forcedSourcePulls: mode === 'build-net-learn',
        cacheImportsDisabled: mode === 'build-net-learn',
        allReachableStepsExecuted:
          mode === 'build-net-learn' && passes.every((entry) => entry.status === 0),
        metrics: summary.metrics,
        observations: {
          ...summary.observations,
          provenance: {
            dockerfileDigest: invocation.dockerfile.sha256,
            invocationHash: `sha256:${sha256(JSON.stringify(invocation.sanitized))}`,
          },
        },
        incompleteReasons: summary.incompleteReasons,
        limitations: [
          ...(summary.limitations || []),
          ...(httpCapture === 'mitmproxy'
            ? [
                'Managed HTTP capture during LEARN is observational; eBPF L4 evidence remains the reachability authority and unmatched streams remain coverage gaps.',
                'BuildKit daemon image, registry, and context acquisition may occur outside Dockerfile RUN proxy settings and remains visible only through independent network evidence.',
              ]
            : []),
          ...(!httpCaptureCleanupComplete
            ? ['Managed HTTP capture cleanup was not proven complete.']
            : []),
          ...passes
            .filter((entry) => entry.history?.exportError)
            .map((entry) => (
              `Optional Buildx build-record archive was omitted for the ${entry.pass} pass because its bounded export failed.`
            )),
          'BuildKit step records and cgroup events are correlated by pass window, not by a kernel-level Dockerfile-step identifier.',
        ],
      }, { home: selectedHome });
    } catch (error) {
      primaryError = primaryError
        ? new AggregateError([primaryError, error], 'build profiling and evidence finalization failed')
        : error;
    }
  }
  let portableDurable = false;
  if (finalized) {
    reportProgress('[build] preserving build evidence');
    try {
      await copyPrivateTree(
        bundleDir,
        path.join(finalized.directory, 'private'),
        typeof process.getuid === 'function' ? process.getuid() : 0,
      );
      await syncPrivateTree(path.join(finalized.directory, 'private'));
      await syncPrivateTree(finalized.directory);
      await fs.rm(bundleDir, { recursive: true, force: true });
      portableDurable = true;
    } catch (error) {
      primaryError = primaryError
        ? new AggregateError([primaryError, error], 'build profiling and private evidence preservation failed')
        : error;
    }
  }
  if (portableDurable) {
    const privileged = profileDependencies.privilegedInvoker || defaultPrivilegedInvoker;
    try {
      for (const pass of passes) {
        privileged('exported', {
          runId: pass.runId,
          portableBundleHash: finalized.portableBundle.contentHash,
        }, profileDependencies);
      }
    } catch (error) {
      primaryError = primaryError
        ? new AggregateError(
            [primaryError, error],
            'build profiling failed and root evidence retention acknowledgement also failed',
          )
        : new AggregateError(
            [error],
            'build profile was preserved but root evidence retention acknowledgement failed',
          );
    }
  }
  if (primaryError) {
    primaryError.bundleDir = finalized?.directory || bundleDir;
    throw primaryError;
  }
  if (!finalized) {
    throw new Error('build profiling ended without a final evidence bundle');
  }
  const buildStatus = passes.find((entry) => entry.status !== 0)?.status || 0;
  const httpContentManifestDigest = httpEvidence?.contentManifest?.contentHash || null;
  const httpContentManifestPath = httpContentManifestDigest
    ? path.join(
        finalized.directory,
        'private',
        'http-capture',
        'cas',
        'manifests',
        `${httpContentManifestDigest.slice('sha256:'.length)}.json`,
      )
    : null;
  reportProgress(`[build] ${workflowLabel} complete`);
  return {
    profileId,
    mode,
    cacheMode,
    depth,
    bundleDir: finalized.directory,
    portableBundleDir: finalized.portableDirectory,
    candidate: finalized.candidate,
    policyDraft: finalized.policyDraft,
    manifest: finalized.manifest,
    httpContentManifestDigest,
    httpContentManifestPath,
    passes: passes.map((entry) => ({
      pass: entry.pass,
      runId: entry.runId,
      status: entry.status,
      signal: entry.signal,
      evidenceComplete: entry.evidenceComplete,
      buildSucceeded: entry.buildSucceeded,
      metadata: entry.metadata,
    })),
    status: buildStatus || (finalized.manifest.complete ? 0 : 1),
  };
}

export const buildOrchestratorInternals = Object.freeze({
  architecturePlatform,
  assertManagedHttpBuildInputsAvailable,
  assertBuildL4FlowSummaryContract,
  assertSingleBuilderNode,
  buildHistoryFailureReason,
  buildHistoryId,
  buildCommand,
  builderNames,
  createBuildkitProgressTracker,
  defaultPrivilegedInvoker,
  dockerInfo,
  ensureBuilder,
  procStartTime,
  resolvePrivilegedGuardPath,
  runPass,
  runStreamingBuild,
  sanitizedPassthrough,
  summarizeBuildPasses,
  trustedPrivilegedHelper,
  validatePassthrough,
});
