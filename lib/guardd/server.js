import { spawnSync } from 'node:child_process';
import {
  closeSync,
  constants as fsConstants,
  existsSync,
  fchmodSync,
  fstatSync,
  fsyncSync,
  ftruncateSync,
  lstatSync,
  openSync,
  writeSync,
} from 'node:fs';
import fs from 'node:fs/promises';
import http from 'node:http';
import net from 'node:net';
import path from 'node:path';

import {
  DEFAULT_GUARD_SOCKET,
  DEFAULT_GUARD_STATE_DIR,
} from './constants.js';
import { BuildSessionService } from './build-session-service.js';
import { sanitizeDockerRuntimeLogTail } from './docker-client.js';
import {
  GuardService,
  sanitizeStoppedRuntimeState,
} from './service.js';

const MAX_BODY_BYTES = 1024 * 1024;
const DEFAULT_SOCKET_PROBE_TIMEOUT_MS = 500;
const DAEMON_LOCK_NAME = 'guardd.lock';
const FLOCK_CONFLICT_STATUS = 73;
const FLOCK_BINARY = ['/usr/bin/flock', '/bin/flock'].find(existsSync) || null;

function requiredDaemonUid() {
  const uid =
    typeof process.geteuid === 'function'
      ? process.geteuid()
      : typeof process.getuid === 'function'
        ? process.getuid()
        : null;
  if (!Number.isSafeInteger(uid) || uid < 0) {
    throw new Error('nosh-guard requires a Unix effective user identity');
  }
  return uid;
}

function trustedDirectoryOwner(uid, daemonUid) {
  return uid === 0 || uid === daemonUid;
}

async function assertTrustedDirectory(directoryPath, daemonUid) {
  const stat = await fs.lstat(directoryPath);
  if (!stat.isDirectory() || stat.isSymbolicLink()) {
    throw new Error(
      `guard daemon path ancestor must be a real directory: ${directoryPath}`,
    );
  }
  if (!trustedDirectoryOwner(stat.uid, daemonUid)) {
    throw new Error(
      `guard daemon path ancestor must be owned by root or uid ${daemonUid}: ${directoryPath}`,
    );
  }
  if ((stat.mode & 0o022) !== 0) {
    throw new Error(
      `guard daemon path ancestor must not be group- or other-writable: ${directoryPath}`,
    );
  }
  return stat;
}

async function ensureTrustedDirectoryPath(
  directoryPath,
  daemonUid,
  options = {},
) {
  const resolved = path.resolve(directoryPath);
  const parsed = path.parse(resolved);
  const segments = resolved
    .slice(parsed.root.length)
    .split(path.sep)
    .filter(Boolean);
  let current = parsed.root;
  await assertTrustedDirectory(current, daemonUid);
  for (const segment of segments) {
    current = path.join(current, segment);
    let created = false;
    try {
      await fs.mkdir(current, {
        mode: options.createMode || 0o700,
      });
      created = true;
    } catch (error) {
      if (error.code !== 'EEXIST') {
        throw error;
      }
    }
    const stat = await assertTrustedDirectory(current, daemonUid);
    if (
      current === resolved &&
      options.requiredMode != null &&
      (stat.mode & 0o7777) !== options.requiredMode
    ) {
      throw new Error(
        `guard daemon directory mode must be ${options.requiredMode.toString(
          8,
        )}: ${resolved}`,
      );
    }
    if (
      created &&
      options.createMode != null &&
      (stat.mode & 0o7777) !== options.createMode
    ) {
      throw new Error(
        `new guard daemon directory mode must be ${options.createMode.toString(
          8,
        )}: ${current}`,
      );
    }
  }
  return resolved;
}

function daemonAlreadyOwnsState(stateDir) {
  const error = new Error(
    `nosh-guard state directory is already owned by a live daemon: ${stateDir}`,
  );
  error.code = 'GUARD_ALREADY_RUNNING';
  return error;
}

function acquireDaemonStateLock(stateDir, socketPath, daemonUid) {
  if (!FLOCK_BINARY) {
    const error = new Error(
      'nosh-guard requires /usr/bin/flock or /bin/flock for daemon exclusion',
    );
    error.code = 'GUARD_FLOCK_UNAVAILABLE';
    throw error;
  }
  const lockPath = path.join(stateDir, DAEMON_LOCK_NAME);
  let fd = -1;
  try {
    fd = openSync(
      lockPath,
      fsConstants.O_RDWR |
        fsConstants.O_CREAT |
        (fsConstants.O_NOFOLLOW || 0),
      0o600,
    );
    let stat = fstatSync(fd);
    if (
      !stat.isFile() ||
      stat.nlink !== 1 ||
      stat.uid !== daemonUid
    ) {
      throw new Error(
        `guard daemon lock must be a singly-linked file owned by uid ${daemonUid}: ${lockPath}`,
      );
    }
    fchmodSync(fd, 0o600);
    stat = fstatSync(fd);
    const current = lstatSync(lockPath);
    if (
      !current.isFile() ||
      current.isSymbolicLink() ||
      current.dev !== stat.dev ||
      current.ino !== stat.ino ||
      (stat.mode & 0o7777) !== 0o600
    ) {
      throw new Error(
        `guard daemon lock changed during validation: ${lockPath}`,
      );
    }
    // fd 3 is a duplicate of the parent's open-file description. The helper
    // exits immediately after applying flock(2); the lock then lives only as
    // long as the parent keeps its descriptor open. Keep the anchor inode
    // persistent so stale recovery never has to unlink a contested lock path.
    const result = spawnSync(
      FLOCK_BINARY,
      [
        '--exclusive',
        '--nonblock',
        '--conflict-exit-code',
        String(FLOCK_CONFLICT_STATUS),
        '3',
      ],
      {
        encoding: 'utf8',
        stdio: ['ignore', 'pipe', 'pipe', fd],
      },
    );
    if (result.error) {
      throw result.error;
    }
    if (result.status === FLOCK_CONFLICT_STATUS) {
      throw daemonAlreadyOwnsState(stateDir);
    }
    if (result.status !== 0) {
      const detail = String(result.stderr || '').trim();
      const error = new Error(
        `failed to acquire guard daemon lock${detail ? `: ${detail}` : ''}`,
      );
      error.code = 'GUARD_FLOCK_FAILED';
      throw error;
    }
    const locked = fstatSync(fd);
    const lockedPath = lstatSync(lockPath);
    if (
      locked.dev !== lockedPath.dev ||
      locked.ino !== lockedPath.ino
    ) {
      throw new Error(
        `guard daemon lock path changed during acquisition: ${lockPath}`,
      );
    }
    const metadata = Buffer.from(
      `${JSON.stringify(
        {
          schemaVersion: 1,
          pid: process.pid,
          stateDir,
          socketPath,
          acquiredAt: new Date().toISOString(),
        },
        null,
        2,
      )}\n`,
      'utf8',
    );
    ftruncateSync(fd, 0);
    if (writeSync(fd, metadata, 0, metadata.length, 0) !== metadata.length) {
      throw new Error(`failed to write guard daemon lock metadata: ${lockPath}`);
    }
    fsyncSync(fd);
    let released = false;
    return {
      fd,
      lockPath,
      release() {
        if (released) {
          return;
        }
        released = true;
        closeSync(fd);
      },
    };
  } catch (error) {
    if (fd >= 0) {
      closeSync(fd);
    }
    throw error;
  }
}

async function readJson(request) {
  const chunks = [];
  let size = 0;
  for await (const chunk of request) {
    size += chunk.length;
    if (size > MAX_BODY_BYTES) {
      const error = new Error('request body exceeds 1 MiB');
      error.statusCode = 413;
      throw error;
    }
    chunks.push(chunk);
  }
  if (!chunks.length) {
    return {};
  }
  return JSON.parse(Buffer.concat(chunks).toString('utf8'));
}

function sendJson(response, statusCode, body) {
  const encoded = Buffer.from(`${JSON.stringify(body, null, 2)}\n`, 'utf8');
  response.writeHead(statusCode, {
    'content-type': 'application/json; charset=utf-8',
    'content-length': encoded.length,
    'cache-control': 'no-store',
  });
  response.end(encoded);
}

function safeRunId(value) {
  return typeof value === 'string'
    && /^[A-Za-z0-9_.-]{1,255}$/.test(value)
    ? value
    : undefined;
}

function safeContainerId(value) {
  return typeof value === 'string' && /^[a-f0-9]{64}$/i.test(value)
    ? value
    : undefined;
}

function errorDocument(error) {
  const runtimeState = error.runtimeState
    ? sanitizeStoppedRuntimeState(error.runtimeState)
    : undefined;
  const runtimeLogTail = error.runtimeLogTail
    ? sanitizeDockerRuntimeLogTail(error.runtimeLogTail)
    : undefined;
  return {
    error: {
      code: error.code || 'GUARD_REQUEST_FAILED',
      message: error.message,
      health: error.health || undefined,
      verification: error.verification || undefined,
      runId: safeRunId(error.runId),
      containerId: safeContainerId(error.containerId),
      runtimeState: runtimeState || undefined,
      runtimeLogTail: runtimeLogTail || undefined,
      containerRemoved:
        typeof error.containerRemoved === 'boolean'
          ? error.containerRemoved
          : undefined,
    },
  };
}

function guardAlreadyRunning(socketPath) {
  const error = new Error(
    `nosh-guard is already listening on ${socketPath}; refusing to replace its live socket`,
  );
  error.code = 'GUARD_ALREADY_RUNNING';
  return error;
}

function probeUnixSocket(socketPath, timeoutMs) {
  return new Promise((resolve, reject) => {
    let settled = false;
    const socket = net.createConnection({ path: socketPath });
    const timer = setTimeout(() => {
      if (settled) {
        return;
      }
      settled = true;
      socket.destroy();
      const error = new Error(
        `timed out probing existing guard socket ${socketPath}`,
      );
      error.code = 'GUARD_SOCKET_PROBE_TIMEOUT';
      reject(error);
    }, timeoutMs);
    const finish = (callback, value) => {
      if (settled) {
        return;
      }
      settled = true;
      clearTimeout(timer);
      socket.destroy();
      callback(value);
    };
    socket.once('connect', () => finish(resolve, true));
    socket.once('error', (error) => {
      if (error.code === 'ECONNREFUSED' || error.code === 'ENOENT') {
        finish(resolve, false);
        return;
      }
      finish(reject, error);
    });
  });
}

async function removeStaleSocket(
  socketPath,
  daemonUid,
  probeTimeoutMs = DEFAULT_SOCKET_PROBE_TIMEOUT_MS,
) {
  try {
    const stat = await fs.lstat(socketPath);
    if (!stat.isSocket()) {
      throw new Error(`refusing to replace non-socket guard path: ${socketPath}`);
    }
    if (stat.uid !== daemonUid) {
      throw new Error(
        `refusing to replace guard socket not owned by uid ${daemonUid}: ${socketPath}`,
      );
    }
    if (await probeUnixSocket(socketPath, probeTimeoutMs)) {
      throw guardAlreadyRunning(socketPath);
    }
    const current = await fs.lstat(socketPath);
    if (
      !current.isSocket() ||
      current.uid !== daemonUid ||
      current.dev !== stat.dev ||
      current.ino !== stat.ino
    ) {
      throw new Error(
        `guard socket changed while checking whether it was stale: ${socketPath}`,
      );
    }
    await fs.unlink(socketPath);
  } catch (error) {
    if (error.code !== 'ENOENT') {
      throw error;
    }
  }
}

async function removeOwnedSocket(socketPath, identity) {
  try {
    const current = await fs.lstat(socketPath);
    if (
      current.isSocket() &&
      current.dev === identity.dev &&
      current.ino === identity.ino
    ) {
      await fs.unlink(socketPath);
    }
  } catch (error) {
    if (error.code !== 'ENOENT') {
      throw error;
    }
  }
}

export async function createGuardServer(options = {}) {
  const service = options.service || new GuardService(options);
  const buildService = options.buildService || new BuildSessionService(options);
  await Promise.all([service.initialize(), buildService.initialize()]);
  const server = http.createServer(async (request, response) => {
    try {
      const url = new URL(request.url || '/', 'http://nosh-guard.local');
      if (request.method === 'GET' && url.pathname === '/v1/health') {
        sendJson(response, 200, service.health());
        return;
      }
      if (request.method === 'GET' && url.pathname === '/v1/runs') {
        sendJson(response, 200, { runs: await service.listRuns() });
        return;
      }
      if (request.method === 'POST' && url.pathname === '/v1/runs') {
        sendJson(response, 201, await service.startRun(await readJson(request)));
        return;
      }
      if (request.method === 'GET' && url.pathname === '/v1/build-runs') {
        sendJson(response, 200, { runs: await buildService.listRuns() });
        return;
      }
      if (request.method === 'POST' && url.pathname === '/v1/build-runs') {
        sendJson(response, 201, await buildService.begin(await readJson(request)));
        return;
      }
      const buildActionMatch = url.pathname.match(
        /^\/v1\/build-runs\/([^/]+)\/(finish|abort)$/,
      );
      if (request.method === 'POST' && buildActionMatch) {
        const [, runId, action] = buildActionMatch;
        const input = await readJson(request);
        sendJson(
          response,
          200,
          action === 'finish'
            ? await buildService.finish(decodeURIComponent(runId), input)
            : await buildService.abort(decodeURIComponent(runId), input),
        );
        return;
      }
      const buildExportMatch = url.pathname.match(
        /^\/v1\/build-runs\/([^/]+)\/exported$/,
      );
      if (request.method === 'POST' && buildExportMatch) {
        const [, runId] = buildExportMatch;
        sendJson(
          response,
          200,
          await buildService.acknowledgeExport(
            decodeURIComponent(runId),
            await readJson(request),
          ),
        );
        return;
      }
      const actionMatch = url.pathname.match(
        /^\/v1\/runs\/([^/]+)\/(attach|stop|rm)$/,
      );
      if (request.method === 'POST' && actionMatch) {
        const [, identifier, action] = actionMatch;
        sendJson(
          response,
          200,
          await service.runAction(decodeURIComponent(identifier), action, await readJson(request)),
        );
        return;
      }
      sendJson(response, 404, {
        error: { code: 'GUARD_NOT_FOUND', message: 'route not found' },
      });
    } catch (error) {
      sendJson(response, error.statusCode || 400, errorDocument(error));
    }
  });
  const watchdogIntervalMs = options.watchdogIntervalMs ?? 5_000;
  let watchdog = null;
  if (watchdogIntervalMs > 0) {
    watchdog = setInterval(() => {
      Promise.all([service.watchdogTick(), buildService.watchdogTick()])
        .catch((error) => {
          process.stderr.write(`nosh-guard watchdog failed: ${error.message}\n`);
        });
    }, watchdogIntervalMs);
    watchdog.unref();
    server.once('close', () => clearInterval(watchdog));
  }
  return { server, service, buildService, watchdog };
}

function resolveDaemonStateDir(options, service) {
  const configured = path.resolve(
    options.stateDir || service?.store?.root || DEFAULT_GUARD_STATE_DIR,
  );
  if (
    options.stateDir &&
    service?.store?.root &&
    path.resolve(service.store.root) !== configured
  ) {
    throw new Error(
      `guard service state root does not match daemon state directory: ${configured}`,
    );
  }
  if (configured === path.parse(configured).root) {
    throw new Error('guard daemon state directory must not be a filesystem root');
  }
  return configured;
}

function secureSocketMode(value) {
  const mode = value ?? 0o600;
  if (mode !== 0o600) {
    throw new TypeError('guard management socket mode must be 600');
  }
  return mode;
}

async function listenWithRestrictiveUmask(server, socketPath, socketMode) {
  await new Promise((resolve, reject) => {
    const onError = (error) => {
      server.off('listening', onListening);
      reject(error);
    };
    const onListening = () => {
      server.off('error', onError);
      resolve();
    };
    server.once('error', onError);
    server.once('listening', onListening);
    const previousUmask = process.umask(0o777 & ~socketMode);
    try {
      server.listen(socketPath);
    } catch (error) {
      server.off('error', onError);
      server.off('listening', onListening);
      reject(error);
    } finally {
      process.umask(previousUmask);
    }
  });
}

export async function listenGuardServer(options = {}) {
  const socketPath = path.resolve(options.socketPath || DEFAULT_GUARD_SOCKET);
  const socketMode = secureSocketMode(options.socketMode);
  const daemonUid = requiredDaemonUid();
  const service = options.service || new GuardService(options);
  const buildService = options.buildService || new BuildSessionService(options);
  const stateDir = resolveDaemonStateDir(options, service);
  await ensureTrustedDirectoryPath(stateDir, daemonUid, {
    createMode: 0o700,
    requiredMode: 0o700,
  });
  const daemonLock = acquireDaemonStateLock(
    stateDir,
    socketPath,
    daemonUid,
  );
  let server = null;
  let watchdog = null;
  let socketIdentity = null;
  try {
    await ensureTrustedDirectoryPath(path.dirname(socketPath), daemonUid, {
      createMode: 0o700,
    });
    await removeStaleSocket(
      socketPath,
      daemonUid,
      options.socketProbeTimeoutMs,
    );
    ({ server, watchdog } = await createGuardServer({
      ...options,
      service,
      buildService,
    }));
    await listenWithRestrictiveUmask(server, socketPath, socketMode);
    socketIdentity = await fs.lstat(socketPath);
    if (
      !socketIdentity.isSocket() ||
      socketIdentity.uid !== daemonUid ||
      (socketIdentity.mode & 0o7777) !== socketMode
    ) {
      throw new Error(
        `guard management socket was not created securely: ${socketPath}`,
      );
    }
  } catch (error) {
    if (watchdog) {
      clearInterval(watchdog);
    }
    if (server?.listening) {
      await new Promise((resolve) => server.close(resolve));
    }
    if (socketIdentity) {
      await removeOwnedSocket(socketPath, socketIdentity).catch(() => {});
    }
    daemonLock.release();
    if (error.code === 'EADDRINUSE') {
      throw guardAlreadyRunning(socketPath);
    }
    throw error;
  }
  // Node does not expose Linux SO_PEERCRED for HTTP-over-Unix sockets. Keep
  // lifecycle control root-only until a credential-aware broker is installed.
  server.on('close', () => {
    daemonLock.release();
    removeOwnedSocket(socketPath, socketIdentity).catch(() => {});
  });
  return {
    server,
    service,
    buildService,
    socketPath,
    stateDir,
    daemonLockPath: daemonLock.lockPath,
    watchdog,
  };
}
