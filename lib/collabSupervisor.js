import { spawn } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';

const DEFAULT_BASE_URL = 'http://127.0.0.1:1337';
const DAEMON_MARKER = 'notty-collab-daemon';
const API_VERSION = 'v1';

function canonicalPath(value) {
  const resolved = path.resolve(String(value || '.'));
  try {
    return fs.realpathSync.native(resolved);
  } catch {
    return resolved;
  }
}

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function normalizeBaseUrl(value) {
  const url = new URL(value || DEFAULT_BASE_URL);
  if (url.protocol !== 'http:') {
    throw new Error('Collab daemon URL must use http');
  }
  if (!['127.0.0.1', 'localhost', '[::1]'].includes(url.hostname)) {
    throw new Error('Collab daemon URL must be loopback-only');
  }
  url.pathname = '/';
  url.search = '';
  url.hash = '';
  return url;
}

function isConnectionRefused(error) {
  const code = error?.cause?.code || error?.code;
  return code === 'ECONNREFUSED' || code === 'ECONNRESET' || code === 'EPIPE';
}

function bootstrapWorkspace(bootstrap) {
  return bootstrap?.workspaceRoot || bootstrap?.paths?.workspaceRoot || null;
}

export class CollabSupervisorError extends Error {
  constructor(message, options = {}) {
    super(message, options);
    this.name = 'CollabSupervisorError';
    this.code = options.code || 'COLLAB_UNAVAILABLE';
    this.statusCode = options.statusCode || 503;
    this.details = options.details;
  }
}

export class CollabSupervisor {
  constructor(options = {}) {
    this.appRoot = canonicalPath(options.appRoot || process.cwd());
    this.workspaceRoot = canonicalPath(options.workspaceRoot || this.appRoot);
    this.baseUrl = normalizeBaseUrl(options.baseUrl || process.env.NOTTY_COLLAB_URL);
    this.startupTimeoutMs = options.startupTimeoutMs || 10_000;
    this.probeTimeoutMs = options.probeTimeoutMs || 1_500;
    this.maxRestartAttempts = options.maxRestartAttempts ?? 6;
    this.restartBaseDelayMs = options.restartBaseDelayMs || 250;
    this.restartMaxDelayMs = options.restartMaxDelayMs || 5_000;
    this.spawnImpl = options.spawnImpl || spawn;
    this.fetchImpl = options.fetchImpl || globalThis.fetch;

    if (typeof this.fetchImpl !== 'function') {
      throw new Error('Collab supervision requires fetch support');
    }

    this.child = null;
    this.ensurePromise = null;
    this.restartTimer = null;
    this.restartAttempts = 0;
    this.lastReadyAt = 0;
    this.lastBootstrap = null;
    this.stopping = false;
    this.stderrTail = '';
    this.handleProcessExit = () => this.stop({ removeExitHandler: false });
    process.once('exit', this.handleProcessExit);
  }

  get daemonUrl() {
    return this.baseUrl.origin;
  }

  resolveUrl(pathname, search = '') {
    const url = new URL(pathname, this.baseUrl);
    url.search = search || '';
    return url;
  }

  getState() {
    return {
      baseUrl: this.daemonUrl,
      workspaceRoot: this.workspaceRoot,
      owned: Boolean(this.child),
      pid: this.child?.pid || this.lastBootstrap?.daemon?.pid || null,
      ready: Boolean(this.lastBootstrap),
      restartAttempts: this.restartAttempts
    };
  }

  async start() {
    return this.ensureReady();
  }

  async ensureReady() {
    if (this.stopping) {
      throw new CollabSupervisorError('Collab supervisor is stopping');
    }
    if (this.ensurePromise) {
      return this.ensurePromise;
    }

    this.ensurePromise = this.#ensureReady().finally(() => {
      this.ensurePromise = null;
    });
    return this.ensurePromise;
  }

  async request(pathname, options = {}) {
    await this.ensureReady();
    const response = await this.fetchImpl(this.resolveUrl(pathname, options.search), {
      method: options.method || 'GET',
      headers: options.headers,
      body: options.body,
      signal: options.signal,
      redirect: 'manual'
    });
    return response;
  }

  async requestJson(pathname, options = {}) {
    const response = await this.request(pathname, options);
    const text = await response.text();
    let body = null;
    if (text) {
      try {
        body = JSON.parse(text);
      } catch {
        throw new CollabSupervisorError('Collab daemon returned invalid JSON', {
          code: 'COLLAB_INVALID_RESPONSE',
          statusCode: 502,
          details: { upstreamStatus: response.status }
        });
      }
    }
    if (!response.ok) {
      const error = new CollabSupervisorError(
        body?.error?.message || body?.error || `Collab daemon request failed (${response.status})`,
        {
          code: body?.error?.code || 'COLLAB_UPSTREAM_ERROR',
          statusCode: response.status,
          details: body
        }
      );
      throw error;
    }
    return body;
  }

  stop(options = {}) {
    this.stopping = true;
    if (this.restartTimer) {
      clearTimeout(this.restartTimer);
      this.restartTimer = null;
    }
    const child = this.child;
    this.child = null;
    this.lastBootstrap = null;
    if (child && child.exitCode === null && !child.killed) {
      try {
        child.kill('SIGTERM');
      } catch {
        // The child may exit between the state check and signal delivery.
      }
    }
    if (options.removeExitHandler !== false) {
      process.off('exit', this.handleProcessExit);
    }
  }

  async #ensureReady() {
    let probe = await this.#probe();
    if (probe.kind === 'ready') {
      this.#markReady(probe.bootstrap);
      return probe.bootstrap;
    }
    if (probe.kind !== 'unavailable') {
      throw probe.error;
    }

    if (!this.child) {
      this.#spawnDaemon();
    }

    const deadline = Date.now() + this.startupTimeoutMs;
    while (Date.now() < deadline) {
      await sleep(125);
      probe = await this.#probe();
      if (probe.kind === 'ready') {
        this.#markReady(probe.bootstrap);
        return probe.bootstrap;
      }
      if (probe.kind !== 'unavailable') {
        throw probe.error;
      }
      if (!this.child && !this.restartTimer) {
        break;
      }
    }

    const detail = this.stderrTail.trim();
    throw new CollabSupervisorError(
      detail ? `Collab daemon failed to become ready: ${detail}` : 'Collab daemon failed to become ready',
      { code: 'COLLAB_START_FAILED', statusCode: 503 }
    );
  }

  async #probe() {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), this.probeTimeoutMs);
    timeout.unref?.();
    let response;
    try {
      response = await this.fetchImpl(this.resolveUrl('/admin/v1/bootstrap'), {
        method: 'GET',
        headers: { Accept: 'application/json' },
        signal: controller.signal,
        redirect: 'manual'
      });
    } catch (error) {
      if (isConnectionRefused(error)) {
        return { kind: 'unavailable', error };
      }
      return {
        kind: 'occupied',
        error: new CollabSupervisorError('The collab daemon port is occupied but did not respond', {
          code: 'COLLAB_PORT_OCCUPIED',
          statusCode: 409,
          details: { baseUrl: this.daemonUrl, cause: error.message }
        })
      };
    } finally {
      clearTimeout(timeout);
    }

    if (!response.ok) {
      return {
        kind: 'occupied',
        error: new CollabSupervisorError(
          `The collab daemon port is serving an incompatible endpoint (${response.status})`,
          {
            code: 'COLLAB_INCOMPATIBLE_DAEMON',
            statusCode: 409,
            details: { baseUrl: this.daemonUrl, upstreamStatus: response.status }
          }
        )
      };
    }

    let bootstrap;
    try {
      bootstrap = await response.json();
    } catch (error) {
      return {
        kind: 'occupied',
        error: new CollabSupervisorError('The collab daemon bootstrap response is invalid', {
          code: 'COLLAB_INCOMPATIBLE_DAEMON',
          statusCode: 409,
          details: { baseUrl: this.daemonUrl, cause: error.message }
        })
      };
    }

    if (
      bootstrap?.apiVersion !== API_VERSION
      || bootstrap?.daemon?.marker !== DAEMON_MARKER
      || bootstrap?.daemon?.version !== 1
    ) {
      return {
        kind: 'occupied',
        error: new CollabSupervisorError('The process on the collab daemon port is not compatible', {
          code: 'COLLAB_INCOMPATIBLE_DAEMON',
          statusCode: 409,
          details: {
            baseUrl: this.daemonUrl,
            apiVersion: bootstrap?.apiVersion || null,
            marker: bootstrap?.daemon?.marker || null,
            daemonVersion: bootstrap?.daemon?.version || null
          }
        })
      };
    }

    const reportedWorkspace = bootstrapWorkspace(bootstrap);
    if (!reportedWorkspace || canonicalPath(reportedWorkspace) !== this.workspaceRoot) {
      return {
        kind: 'mismatch',
        error: new CollabSupervisorError('Collab daemon is attached to a different workspace', {
          code: 'COLLAB_WORKSPACE_MISMATCH',
          statusCode: 409,
          details: {
            expectedWorkspace: this.workspaceRoot,
            actualWorkspace: reportedWorkspace ? canonicalPath(reportedWorkspace) : null
          }
        })
      };
    }

    return { kind: 'ready', bootstrap };
  }

  #spawnDaemon() {
    if (this.child || this.stopping) {
      return;
    }

    const collabPath = path.join(this.appRoot, 'collab.cjs');
    const host = this.baseUrl.hostname === '[::1]' ? '::1' : this.baseUrl.hostname;
    const port = this.baseUrl.port || '80';
    const args = [
      collabPath,
      'daemon',
      '--ip',
      host,
      '--port',
      port,
      '--workdir',
      this.workspaceRoot
    ];

    this.stderrTail = '';
    const child = this.spawnImpl(process.execPath, args, {
      cwd: this.appRoot,
      env: {
        ...process.env,
        NOTTY_APP_WORKDIR: this.appRoot,
        NOTTY_WORKDIR: this.workspaceRoot
      },
      stdio: ['ignore', 'ignore', 'pipe']
    });
    this.child = child;

    child.stderr?.on('data', (chunk) => {
      this.stderrTail = `${this.stderrTail}${chunk.toString('utf8')}`.slice(-8192);
    });
    child.once('error', (error) => {
      this.stderrTail = `${this.stderrTail}\n${error.message}`.slice(-8192);
    });
    child.once('exit', (code, signal) => {
      if (this.child !== child) {
        return;
      }
      this.child = null;
      this.lastBootstrap = null;
      if (this.stopping) {
        return;
      }
      if (this.lastReadyAt && Date.now() - this.lastReadyAt > 30_000) {
        this.restartAttempts = 0;
      }
      console.error(
        `[collab-supervisor] daemon exited (${signal ? `signal=${signal}` : `code=${code}`})`
      );
      this.#scheduleRestart();
    });
  }

  #markReady(bootstrap) {
    this.lastBootstrap = bootstrap;
    this.lastReadyAt = Date.now();
  }

  #scheduleRestart() {
    if (this.restartTimer || this.stopping) {
      return;
    }
    if (this.restartAttempts >= this.maxRestartAttempts) {
      console.error('[collab-supervisor] restart limit reached; waiting for the next API request');
      return;
    }

    const delay = Math.min(
      this.restartBaseDelayMs * (2 ** this.restartAttempts),
      this.restartMaxDelayMs
    );
    this.restartAttempts += 1;
    this.restartTimer = setTimeout(() => {
      this.restartTimer = null;
      this.ensureReady().catch((error) => {
        console.error(`[collab-supervisor] restart failed: ${error.message}`);
        this.#scheduleRestart();
      });
    }, delay);
    this.restartTimer.unref?.();
  }
}

export function createCollabSupervisor(options = {}) {
  return new CollabSupervisor(options);
}
