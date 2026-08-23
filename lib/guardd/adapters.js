import fs from 'node:fs/promises';
import { constants as fsConstants } from 'node:fs';
import path from 'node:path';
import { spawn, spawnSync } from 'node:child_process';
import { Writable } from 'node:stream';
import { finished } from 'node:stream/promises';

import { DEFAULT_ADAPTER_CONFIG, GUARD_SCHEMA_VERSION } from './constants.js';

const DEFAULT_OUTPUT_MAX_BYTES = 128 * 1024 * 1024;
const DEFAULT_DIAGNOSTICS_MAX_BYTES = 16 * 1024 * 1024;
const DEFAULT_LIMIT_KILL_GRACE_MS = 2_000;
const STARTUP_DIAGNOSTICS_TAIL_BYTES = 64 * 1024;
const STARTUP_DIAGNOSTICS_DRAIN_MS = 1_000;
const STARTUP_DIAGNOSTIC_TEXT_LENGTH = 2_048;

function positiveByteLimit(value, fallback, label) {
  const selected = value == null ? fallback : Number(value);
  if (!Number.isSafeInteger(selected) || selected < 1 || selected > fallback) {
    throw new TypeError(`${label} must be an integer from 1 to ${fallback}`);
  }
  return selected;
}

function boundedFileWriter(handle, maximumBytes, onOverflow) {
  let bytes = 0;
  let overflow = null;
  const writer = new Writable({
    write(chunk, encoding, callback) {
      const buffer = Buffer.isBuffer(chunk)
        ? chunk
        : Buffer.from(chunk, encoding);
      const remaining = Math.max(0, maximumBytes - bytes);
      const accepted = buffer.subarray(0, remaining);
      const finishWrite = () => {
        if (!overflow && accepted.length < buffer.length) {
          overflow = {
            maximumBytes,
            bytesRetained: bytes,
            bytesDiscardedAtDetection: buffer.length - accepted.length,
            detectedAt: new Date().toISOString(),
          };
          onOverflow(overflow);
        }
        callback();
      };
      if (!accepted.length) {
        finishWrite();
        return;
      }
      handle.write(accepted).then(({ bytesWritten }) => {
        if (bytesWritten !== accepted.length) {
          callback(new Error('short write while retaining adapter evidence'));
          return;
        }
        bytes += bytesWritten;
        finishWrite();
      }, callback);
    },
  });
  const done = finished(writer)
    .finally(() => handle.close())
    .catch((error) => ({ error }));
  return {
    writer,
    done,
    get bytes() {
      return bytes;
    },
    get overflow() {
      return overflow;
    },
  };
}

function substitute(value, context) {
  if (typeof value !== 'string') {
    throw new TypeError('adapter command arguments must be strings');
  }
  return value.replace(/\{([A-Za-z][A-Za-z0-9]*)\}/g, (match, key) => {
    if (context[key] == null) {
      throw new Error(`adapter placeholder has no value: ${match}`);
    }
    return String(context[key]);
  });
}

function commandSpec(spec, context) {
  if (!spec?.command || typeof spec.command !== 'string') {
    throw new TypeError('adapter command requires command');
  }
  if (spec.args != null && !Array.isArray(spec.args)) {
    throw new TypeError('adapter command args must be an array');
  }
  return {
    command: substitute(spec.command, context),
    args: (spec.args || []).map((arg) => substitute(arg, context)),
    environment: Object.fromEntries(
      Object.entries(spec.environment || {}).map(([key, value]) => [
        key,
        substitute(String(value), context),
      ]),
    ),
  };
}

function storedCommandSpec(spec) {
  if (
    !spec ||
    typeof spec.command !== 'string' ||
    !Array.isArray(spec.args) ||
    spec.args.some((argument) => typeof argument !== 'string') ||
    !spec.environment ||
    typeof spec.environment !== 'object' ||
    Array.isArray(spec.environment) ||
    Object.values(spec.environment).some((value) => typeof value !== 'string')
  ) {
    throw new TypeError('stored adapter detach command is invalid');
  }
  return {
    command: spec.command,
    args: [...spec.args],
    environment: { ...spec.environment },
  };
}

async function waitForSpawn(child) {
  await new Promise((resolve, reject) => {
    child.once('spawn', resolve);
    child.once('error', reject);
  });
}

async function assertProcessStayedRunning(child, adapter) {
  const startupGraceMs = adapter.startupGraceMs ?? 250;
  if (startupGraceMs <= 0) {
    return;
  }
  const exited = child.exitCode != null || child.signalCode != null
    ? { code: child.exitCode, signal: child.signalCode }
    : await new Promise((resolve) => {
      const timer = setTimeout(() => {
        child.removeListener('exit', onExit);
        resolve(null);
      }, startupGraceMs);
      function onExit(code, signal) {
        clearTimeout(timer);
        resolve({ code, signal });
      }
      child.once('exit', onExit);
    });
  if (exited) {
    throw new Error(
      `long-running adapter ${adapter.name} exited during startup: ${
        exited.signal || `status ${exited.code}`
      }`,
    );
  }
}

function safeStartupDiagnosticText(
  value,
  maximumLength = STARTUP_DIAGNOSTIC_TEXT_LENGTH,
) {
  if (typeof value !== 'string') return null;
  const selected = value
    .trim()
    .replace(/[\r\n\t]+/g, ' ')
    .replace(/ {2,}/g, ' ');
  if (!selected || /[\x00-\x1f\x7f-\x9f]/.test(selected)) {
    return null;
  }
  return selected.length > maximumLength
    ? `${selected.slice(0, maximumLength - 3)}...`
    : selected;
}

async function readDiagnosticsTail(filePath) {
  const handle = await fs.open(
    filePath,
    fsConstants.O_RDONLY | (fsConstants.O_NOFOLLOW || 0),
  );
  try {
    const stat = await handle.stat();
    if (!stat.isFile() || stat.size < 1) return '';
    const boundaryByte = stat.size > STARTUP_DIAGNOSTICS_TAIL_BYTES ? 1 : 0;
    const length = Math.min(
      stat.size,
      STARTUP_DIAGNOSTICS_TAIL_BYTES + boundaryByte,
    );
    const start = stat.size - length;
    const buffer = Buffer.alloc(length);
    let bytesRead = 0;
    while (bytesRead < length) {
      const result = await handle.read(
        buffer,
        bytesRead,
        length - bytesRead,
        start + bytesRead,
      );
      if (!result.bytesRead) break;
      bytesRead += result.bytesRead;
    }
    let source = buffer.subarray(0, bytesRead).toString('utf8');
    if (start > 0) {
      const firstNewline = source.indexOf('\n');
      source = firstNewline < 0 ? '' : source.slice(firstNewline + 1);
    }
    return source;
  } finally {
    await handle.close();
  }
}

function startupDiagnosticSegments(source) {
  let statusMessage = null;
  let diagnosticMessage = null;
  let diagnosticComponent = null;
  for (const line of source.split(/\r?\n/).filter(Boolean)) {
    let record;
    try {
      record = JSON.parse(line);
    } catch {
      continue;
    }
    if (record?.recordKind === 'status' && record.status === 'error') {
      const message = safeStartupDiagnosticText(record.message);
      if (message) statusMessage = message;
    } else if (
      record?.recordKind === 'diagnostic'
      && ['error', 'warning'].includes(record.level)
    ) {
      const message = safeStartupDiagnosticText(record.message);
      if (
        message
        && (
          !diagnosticMessage
          || message.includes('-- BEGIN PROG LOAD LOG --')
          || !diagnosticMessage.includes('-- BEGIN PROG LOAD LOG --')
        )
      ) {
        diagnosticMessage = message;
        diagnosticComponent = safeStartupDiagnosticText(record.component, 128);
      }
    }
  }
  return [
    statusMessage ? `status error: ${statusMessage}` : null,
    diagnosticMessage && diagnosticMessage !== statusMessage
      ? `${diagnosticComponent ? `${diagnosticComponent} ` : ''}diagnostic: ${diagnosticMessage}`
      : null,
  ].filter(Boolean);
}

function containsErrorSegment(message, segment) {
  return message === segment
    || message.startsWith(`${segment}; `)
    || message.endsWith(`; ${segment}`)
    || message.includes(`; ${segment}; `);
}

async function appendStartupDiagnostics(
  error,
  lifecycle,
  diagnosticsPath,
  waitForDrain,
) {
  try {
    const drained = !waitForDrain || await waitForPromise(
      lifecycle.diagnosticsClosed || lifecycle.closed,
      STARTUP_DIAGNOSTICS_DRAIN_MS,
    );
    const segments = startupDiagnosticSegments(
      await readDiagnosticsTail(diagnosticsPath),
    ).filter((segment) => !containsErrorSegment(error.message, segment));
    if (waitForDrain && !drained) {
      segments.push(
        `startup diagnostics did not drain within ${STARTUP_DIAGNOSTICS_DRAIN_MS}ms`,
      );
    }
    if (segments.length) {
      error.message = `${error.message}; ${segments.join('; ')}`;
    }
  } catch {
    // Diagnostic enrichment must never replace the collector startup failure.
  }
}

async function waitForJsonReadiness(child, adapter, streams) {
  if (!adapter.readiness) {
    return null;
  }
  const match = adapter.readiness.match;
  if (
    !match ||
    typeof match !== 'object' ||
    Array.isArray(match) ||
    !Object.keys(match).length
  ) {
    throw new TypeError(`adapter readiness requires a non-empty match object`);
  }
  const stream = adapter.readiness.stream || 'stderr';
  if (!['stdout', 'stderr'].includes(stream)) {
    throw new TypeError('adapter readiness stream must be stdout or stderr');
  }
  const filePath = stream === 'stdout' ? streams.stdout : streams.stderr;
  const timeoutMs = adapter.readiness.timeoutMs || 10_000;
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    if (child.exitCode != null || child.signalCode != null) {
      throw new Error(
        `adapter ${adapter.name} exited before reporting readiness`,
      );
    }
    let source = '';
    try {
      source = await fs.readFile(filePath, 'utf8');
    } catch (error) {
      if (error.code !== 'ENOENT') {
        throw error;
      }
    }
    let readiness = null;
    for (const line of source.split(/\r?\n/).filter(Boolean)) {
      let record;
      try {
        record = JSON.parse(line);
      } catch {
        // A writer may have an incomplete final line while being polled.
        continue;
      }
      if (record?.recordKind === 'status' && record.status === 'error') {
        const message = safeStartupDiagnosticText(record.message);
        throw new Error(
          `adapter ${adapter.name} reported a startup status error${
            message ? `; status error: ${message}` : ''
          }`,
        );
      }
      if (
        Object.entries(match).every(
          ([key, expected]) => record?.[key] === expected,
        )
      ) {
        readiness = record;
      }
    }
    if (readiness) {
      if (child.exitCode != null || child.signalCode != null) {
        throw new Error(
          `adapter ${adapter.name} exited while reporting readiness`,
        );
      }
      return readiness;
    }
    await new Promise((resolve) => setTimeout(resolve, 50));
  }
  throw new Error(
    `adapter ${adapter.name} did not report readiness within ${timeoutMs}ms`,
  );
}

async function waitForProcessExit(pid, timeoutMs) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    try {
      process.kill(pid, 0);
    } catch (error) {
      if (error.code === 'ESRCH') {
        return true;
      }
      throw error;
    }
    await new Promise((resolve) => setTimeout(resolve, 50));
  }
  return false;
}

async function waitForPromise(promise, timeoutMs) {
  let timer;
  try {
    return await Promise.race([
      promise.then(() => true),
      new Promise((resolve) => {
        timer = setTimeout(() => resolve(false), timeoutMs);
      }),
    ]);
  } finally {
    clearTimeout(timer);
  }
}

async function waitForChildClose(lifecycle, timeoutMs) {
  if (lifecycle.exited) return true;
  return waitForPromise(lifecycle.closed, timeoutMs);
}

async function cleanupFailedStartupProcess({
  child,
  lifecycle,
  pidStartTime,
  termTimeoutMs,
  killTimeoutMs,
  processStartTimeProvider,
  signalProcessImpl,
}) {
  const result = {
    cleanupOk: false,
    forced: false,
    identityLost: false,
    signal: null,
    error: null,
  };
  lifecycle.expectedStop = true;
  if (
    lifecycle.exited
    || lifecycle.processExited
    || child.exitCode != null
    || child.signalCode != null
  ) {
    result.cleanupOk = true;
    return result;
  }
  if (!Number.isSafeInteger(child.pid)) {
    result.error = 'adapter PID is unavailable for supervised startup cleanup';
    return result;
  }

  if (pidStartTime) {
    try {
      const currentStartTime = await processStartTimeProvider(child.pid);
      if (currentStartTime !== pidStartTime) {
        result.cleanupOk = true;
        result.identityLost = true;
        return result;
      }
    } catch (error) {
      if (error.code === 'ESRCH' || error.code === 'ENOENT') {
        result.cleanupOk = true;
        return result;
      }
      result.error = error.message;
      return result;
    }
  }

  try {
    signalProcessImpl(child.pid, 'SIGTERM');
    result.signal = 'SIGTERM';
  } catch (error) {
    if (error.code === 'ESRCH' || error.code === 'ENOENT') {
      result.cleanupOk = true;
      return result;
    }
    result.error = error.message;
    return result;
  }
  let exited = await waitForChildClose(lifecycle, termTimeoutMs);
  if (
    exited
    || lifecycle.processExited
    || child.exitCode != null
    || child.signalCode != null
  ) {
    result.cleanupOk = true;
    return result;
  }
  if (!pidStartTime) {
    result.error =
      'adapter process identity is unavailable for safe SIGKILL escalation';
    return result;
  }

  try {
    const currentStartTime = await processStartTimeProvider(child.pid);
    if (currentStartTime !== pidStartTime) {
      result.cleanupOk = true;
      result.identityLost = true;
      return result;
    }
  } catch (error) {
    if (error.code === 'ESRCH' || error.code === 'ENOENT') {
      result.cleanupOk = true;
      return result;
    }
    result.error = error.message;
    return result;
  }

  result.forced = true;
  result.signal = 'SIGKILL';
  try {
    signalProcessImpl(-child.pid, 'SIGKILL');
  } catch (error) {
    if (error.code !== 'ESRCH') {
      result.error = error.message;
      return result;
    }
    try {
      const currentStartTime = await processStartTimeProvider(child.pid);
      if (currentStartTime !== pidStartTime) {
        result.cleanupOk = true;
        result.identityLost = true;
        return result;
      }
      signalProcessImpl(child.pid, 'SIGKILL');
    } catch (fallbackError) {
      if (
        fallbackError.code === 'ESRCH'
        || fallbackError.code === 'ENOENT'
      ) {
        result.cleanupOk = true;
        return result;
      }
      result.error = fallbackError.message;
      return result;
    }
  }
  exited = await waitForChildClose(lifecycle, killTimeoutMs);
  if (
    exited
    || lifecycle.processExited
    || child.exitCode != null
    || child.signalCode != null
  ) {
    result.cleanupOk = true;
    return result;
  }
  try {
    const currentStartTime = await processStartTimeProvider(child.pid);
    if (currentStartTime !== pidStartTime) {
      result.cleanupOk = true;
      result.identityLost = true;
      return result;
    }
  } catch (error) {
    if (error.code === 'ESRCH' || error.code === 'ENOENT') {
      result.cleanupOk = true;
      return result;
    }
    result.error = error.message;
    return result;
  }
  result.error = 'adapter did not exit after SIGTERM and SIGKILL';
  return result;
}

async function processStartTime(pid) {
  const stat = await fs.readFile(`/proc/${pid}/stat`, 'utf8');
  const close = stat.lastIndexOf(')');
  if (close < 0) {
    throw new Error(`cannot parse process identity for PID ${pid}`);
  }
  const fields = stat.slice(close + 2).trim().split(/\s+/);
  const startTime = fields[19];
  if (!/^\d+$/.test(startTime || '')) {
    throw new Error(`process start time is unavailable for PID ${pid}`);
  }
  return startTime;
}

function modeRequired(adapter, mode) {
  return (adapter.requiredModes || []).includes(mode);
}

function modeActive(adapter, mode) {
  return (adapter.requiredModes || []).includes(mode)
    || (adapter.modes || []).includes(mode);
}

function outputPath(adapter, context) {
  const configured = substitute(
    adapter.outputFile || `${adapter.name}.log`,
    context,
  );
  const evidenceRoot = path.resolve(context.evidenceDir);
  const resolved = path.resolve(
    path.isAbsolute(configured)
      ? configured
      : path.join(evidenceRoot, configured),
  );
  const relative = path.relative(evidenceRoot, resolved);
  if (relative.startsWith('..') || path.isAbsolute(relative)) {
    throw new Error(
      `adapter output must stay inside the run evidence directory: ${adapter.name}`,
    );
  }
  return resolved;
}

function stderrPath(adapter, context) {
  const configured = substitute(
    adapter.stderrFile || `${adapter.name}.stderr.log`,
    context,
  );
  const evidenceRoot = path.resolve(context.evidenceDir);
  const resolved = path.resolve(
    path.isAbsolute(configured)
      ? configured
      : path.join(evidenceRoot, configured),
  );
  const relative = path.relative(evidenceRoot, resolved);
  if (relative.startsWith('..') || path.isAbsolute(relative)) {
    throw new Error(
      `adapter diagnostics must stay inside the run evidence directory: ${adapter.name}`,
    );
  }
  return resolved;
}

export class AdapterController {
  constructor(options = {}) {
    this.configPath = options.configPath || DEFAULT_ADAPTER_CONFIG;
    this.spawnImpl = options.spawnImpl || spawn;
    this.spawnSyncImpl = options.spawnSyncImpl || spawnSync;
    this.trustedConfigUid =
      options.trustedConfigUid ??
      (typeof process.geteuid === 'function' && process.geteuid() === 0
        ? 0
        : null);
    this.trustedConfigRoot = path.resolve(options.trustedConfigRoot || '/');
    this.outputMaxBytes = positiveByteLimit(
      options.outputMaxBytes,
      DEFAULT_OUTPUT_MAX_BYTES,
      'adapter output byte limit',
    );
    this.diagnosticsMaxBytes = positiveByteLimit(
      options.diagnosticsMaxBytes,
      DEFAULT_DIAGNOSTICS_MAX_BYTES,
      'adapter diagnostics byte limit',
    );
    this.limitKillGraceMs = Number.isSafeInteger(options.limitKillGraceMs)
      && options.limitKillGraceMs >= 0
      ? options.limitKillGraceMs
      : DEFAULT_LIMIT_KILL_GRACE_MS;
    this.processStartTimeProvider = options.processStartTimeProvider
      || processStartTime;
    this.signalProcessImpl = options.signalProcessImpl || process.kill;
    this.longRunningChildren = new Map();
  }

  async loadConfig() {
    const resolved = path.resolve(this.configPath);
    const realPath = await fs.realpath(resolved);
    if (realPath !== resolved) {
      throw new Error('adapter configuration path must not contain symbolic links');
    }
    const lstat = await fs.lstat(resolved);
    if (!lstat.isFile() || lstat.isSymbolicLink()) {
      throw new Error('adapter configuration must be a regular non-symlink file');
    }
    if (this.trustedConfigUid != null) {
      const relative = path.relative(this.trustedConfigRoot, resolved);
      if (relative.startsWith('..') || path.isAbsolute(relative)) {
        throw new Error('adapter configuration escapes its trusted root');
      }
      let cursor = path.dirname(resolved);
      while (true) {
        const stat = await fs.stat(cursor);
        if (
          !stat.isDirectory()
          || stat.uid !== this.trustedConfigUid
          || (stat.mode & 0o022) !== 0
        ) {
          throw new Error(
            `adapter configuration directory is not trusted: ${cursor}`,
          );
        }
        if (cursor === this.trustedConfigRoot) {
          break;
        }
        const parent = path.dirname(cursor);
        if (parent === cursor) {
          throw new Error('adapter configuration trusted root is unreachable');
        }
        cursor = parent;
      }
      if (
        lstat.uid !== this.trustedConfigUid
        || (lstat.mode & 0o022) !== 0
      ) {
        throw new Error('adapter configuration is not owned or writable safely');
      }
    }
    const handle = await fs.open(
      resolved,
      fsConstants.O_RDONLY | (fsConstants.O_NOFOLLOW || 0),
    );
    let raw;
    try {
      const stat = await handle.stat();
      if (
        !stat.isFile()
        || stat.dev !== lstat.dev
        || stat.ino !== lstat.ino
        || stat.size > 1024 * 1024
      ) {
        throw new Error('adapter configuration changed or is too large');
      }
      raw = await handle.readFile('utf8');
    } finally {
      await handle.close();
    }
    const document = JSON.parse(raw);
    if (
      document.schemaVersion !== GUARD_SCHEMA_VERSION ||
      !Array.isArray(document.adapters)
    ) {
      throw new TypeError('invalid guard adapter configuration');
    }
    return document;
  }

  async configuredExecutable(adapterName, operation) {
    const config = await this.loadConfig();
    const matches = config.adapters.filter((entry) => entry?.name === adapterName);
    if (matches.length !== 1) {
      throw new Error(
        `adapter configuration must contain exactly one ${adapterName} adapter`,
      );
    }
    const executable = matches[0]?.[operation]?.command;
    if (
      typeof executable !== 'string'
      || !path.isAbsolute(executable)
      || executable.includes('\0')
    ) {
      throw new Error(
        `adapter ${adapterName} ${operation} executable must be an absolute path`,
      );
    }
    return path.resolve(executable);
  }

  async health(mode, context = {}) {
    const config = await this.loadConfig();
    const results = [];
    for (const adapter of config.adapters) {
      if (!modeActive(adapter, mode)) {
        continue;
      }
      if (!adapter.health) {
        results.push({
          name: adapter.name,
          required: modeRequired(adapter, mode),
          ok: !modeRequired(adapter, mode),
          detail: 'no health command configured',
        });
        continue;
      }
      const command = commandSpec(adapter.health, context);
      const result = this.spawnSyncImpl(command.command, command.args, {
        encoding: 'utf8',
        timeout: adapter.health.timeoutMs || 5_000,
        env: { ...process.env, ...command.environment },
        stdio: ['ignore', 'pipe', 'pipe'],
      });
      results.push({
        name: adapter.name,
        required: modeRequired(adapter, mode),
        ok: result.status === 0,
        status: result.status,
        detail: String(result.stdout || result.stderr || '').trim().split('\n')[0],
        error: result.error?.message || null,
      });
    }
    return results;
  }

  async attach(mode, context, options = {}) {
    const config = await this.loadConfig();
    await fs.mkdir(context.evidenceDir, { recursive: true, mode: 0o700 });
    const attached = [];
    const persistAttached = async () => {
      if (typeof options.onAttached !== 'function') return;
      try {
        await options.onAttached([...attached]);
      } catch (error) {
        error.attachedAdapters = [...attached];
        throw error;
      }
    };
    for (const adapter of config.adapters) {
      if (!modeActive(adapter, mode)) {
        continue;
      }
      if (!adapter.attach) {
        if (modeRequired(adapter, mode)) {
          throw new Error(`required adapter has no attach command: ${adapter.name}`);
        }
        continue;
      }
      const command = commandSpec(adapter.attach, context);
      const detachCommand = adapter.detach
        ? commandSpec(adapter.detach, context)
        : null;
      const logPath = outputPath(adapter, context);
      const diagnosticsPath = stderrPath(adapter, context);
      await Promise.all([
        fs.mkdir(path.dirname(logPath), { recursive: true, mode: 0o700 }),
        fs.mkdir(path.dirname(diagnosticsPath), {
          recursive: true,
          mode: 0o700,
        }),
      ]);
      let entry;
      if (adapter.longRunning) {
        const outputMaxBytes = positiveByteLimit(
          adapter.maxOutputBytes,
          this.outputMaxBytes,
          `${adapter.name} output byte limit`,
        );
        const diagnosticsMaxBytes = positiveByteLimit(
          adapter.maxDiagnosticsBytes,
          this.diagnosticsMaxBytes,
          `${adapter.name} diagnostics byte limit`,
        );
        let logHandle;
        let diagnosticsHandle;
        let child;
        try {
          logHandle = await fs.open(logPath, 'wx', 0o600);
          diagnosticsHandle = await fs.open(diagnosticsPath, 'wx', 0o600);
          child = this.spawnImpl(command.command, command.args, {
            detached: true,
            env: { ...process.env, ...command.environment },
            stdio: ['ignore', 'pipe', 'pipe'],
          });
          if (!child || typeof child.once !== 'function') {
            throw new Error('adapter spawn did not return a child process');
          }
        } catch (error) {
          await Promise.all([
            logHandle?.close().catch(() => {}),
            diagnosticsHandle?.close().catch(() => {}),
          ]);
          if (modeRequired(adapter, mode)) throw error;
          entry = {
            name: adapter.name,
            required: false,
            evidence: adapter.evidence !== false,
            evidenceRequired: adapter.evidenceRequired === true,
            cleanupCritical: adapter.cleanupCritical === true,
            longRunning: true,
            logPath,
            diagnosticsPath,
            completion: adapter.completion || null,
            requireCleanExit: adapter.requireCleanExit === true
              || Boolean(adapter.completion),
            outputLimits: {
              stdout: outputMaxBytes,
              stderr: diagnosticsMaxBytes,
            },
            command: [command.command, ...command.args],
            detachCommand,
            detachCommandTimeoutMs: adapter.detach?.timeoutMs || 30_000,
            detachTimeoutMs: adapter.detachTimeoutMs || 5_000,
            startupCleanupOk: true,
            error: `optional adapter setup failed: ${error.message}`,
          };
          attached.push(entry);
          await persistAttached();
          continue;
        }
        const lifecycle = {
          child,
          exited: false,
          exitCode: null,
          signal: null,
          closed: null,
          evidenceFailures: [],
          persistenceError: null,
          limitKillTimer: null,
          processExited: false,
          diagnosticsClosed: null,
          expectedStop: false,
        };
        child.once('exit', (code, signal) => {
          lifecycle.processExited = true;
          lifecycle.processExitCode = Number.isInteger(code) ? code : null;
          lifecycle.processExitSignal = signal || null;
        });
        const applyLifecycle = () => {
          if (!entry) return;
          entry.exitStatusKnown = lifecycle.exited;
          entry.exitCode = lifecycle.exitCode;
          entry.exitSignal = lifecycle.signal;
          if (lifecycle.exitedAt) entry.exitedAt = lifecycle.exitedAt;
          if (lifecycle.evidenceFailures.length) {
            entry.evidenceFailures = [...lifecycle.evidenceFailures];
            entry.error ||= lifecycle.evidenceFailures[0].error;
          }
        };
        const persistLifecycle = () => {
          applyLifecycle();
          void persistAttached().catch((error) => {
            lifecycle.persistenceError = error.message;
            if (entry) entry.lifecyclePersistenceError = error.message;
          });
        };
        const stopForEvidenceFailure = (failure) => {
          if (lifecycle.evidenceFailures.some(
            (current) => current.stream === failure.stream,
          )) {
            return;
          }
          lifecycle.evidenceFailures.push(failure);
          persistLifecycle();
          if (lifecycle.exited || !Number.isSafeInteger(child.pid)) return;
          child.kill?.('SIGTERM');
          lifecycle.limitKillTimer = setTimeout(() => {
            if (!lifecycle.exited) child.kill('SIGKILL');
          }, this.limitKillGraceMs);
          lifecycle.limitKillTimer.unref?.();
        };
        const logSink = boundedFileWriter(
          logHandle,
          outputMaxBytes,
          (overflow) => stopForEvidenceFailure({
            stream: 'stdout',
            ...overflow,
            error: `adapter output exceeded ${outputMaxBytes} bytes`,
          }),
        );
        const diagnosticsSink = boundedFileWriter(
          diagnosticsHandle,
          diagnosticsMaxBytes,
          (overflow) => stopForEvidenceFailure({
            stream: 'stderr',
            ...overflow,
            error: `adapter diagnostics exceeded ${diagnosticsMaxBytes} bytes`,
          }),
        );
        lifecycle.diagnosticsClosed = diagnosticsSink.done;
        logSink.writer.once('error', (error) => stopForEvidenceFailure({
          stream: 'stdout',
          error: `adapter output could not be retained: ${error.message}`,
          detectedAt: new Date().toISOString(),
        }));
        diagnosticsSink.writer.once('error', (error) => stopForEvidenceFailure({
          stream: 'stderr',
          error: `adapter diagnostics could not be retained: ${error.message}`,
          detectedAt: new Date().toISOString(),
        }));
        if (!child.stdout || !child.stderr) {
          logSink.writer.end();
          diagnosticsSink.writer.end();
          child.kill?.('SIGTERM');
          throw new Error(`long-running adapter ${adapter.name} has no output pipes`);
        }
        child.stdout.pipe(logSink.writer);
        child.stderr.pipe(diagnosticsSink.writer);
        lifecycle.closed = new Promise((resolve) => {
          child.once('close', (code, signal) => {
            clearTimeout(lifecycle.limitKillTimer);
            void Promise.all([logSink.done, diagnosticsSink.done]).then(
              ([outputResult, diagnosticsResult]) => {
                lifecycle.exited = true;
                lifecycle.exitCode = Number.isInteger(code) ? code : null;
                lifecycle.signal = signal || null;
                lifecycle.exitedAt = new Date().toISOString();
                for (const [stream, result] of [
                  ['stdout', outputResult],
                  ['stderr', diagnosticsResult],
                ]) {
                  if (result?.error) {
                    stopForEvidenceFailure({
                      stream,
                      error: `adapter ${stream} persistence failed: ${result.error.message}`,
                      detectedAt: lifecycle.exitedAt,
                    });
                  }
                }
                applyLifecycle();
                return persistAttached().catch((error) => {
                  lifecycle.persistenceError = error.message;
                  if (entry) entry.lifecyclePersistenceError = error.message;
                }).finally(() => {
                  if (
                    entry
                    && entry.required === true
                    && lifecycle.expectedStop !== true
                    && typeof options.onRequiredAdapterExit === 'function'
                  ) {
                    const failure = {
                      name: entry.name,
                      required: true,
                      ok: false,
                      error: lifecycle.evidenceFailures[0]?.error
                        || `required adapter exited unexpectedly: ${
                          lifecycle.signal || `status ${lifecycle.exitCode}`
                        }`,
                      exitCode: lifecycle.exitCode,
                      exitSignal: lifecycle.signal,
                      evidenceFailures: [...lifecycle.evidenceFailures],
                      exitedAt: lifecycle.exitedAt,
                    };
                    void Promise.resolve(
                      options.onRequiredAdapterExit(failure),
                    ).catch((error) => {
                      lifecycle.containmentCallbackError = error.message;
                      if (entry) {
                        entry.containmentCallbackError = error.message;
                      }
                    });
                  }
                });
              },
            ).finally(resolve);
          });
        });
        let readiness = null;
        let pidStartTime = null;
        try {
          await waitForSpawn(child);
          pidStartTime = await this.processStartTimeProvider(child.pid);
          this.longRunningChildren.set(`${child.pid}:${pidStartTime}`, lifecycle);
          entry = {
            name: adapter.name,
            required: modeRequired(adapter, mode),
            evidence: adapter.evidence !== false,
            evidenceRequired: adapter.evidenceRequired == null
              ? modeRequired(adapter, mode)
              : adapter.evidenceRequired === true,
            cleanupCritical: adapter.cleanupCritical === true,
            pid: child.pid,
            pidStartTime,
            longRunning: true,
            logPath,
            diagnosticsPath,
            readiness: null,
            completion: adapter.completion || null,
            requireCleanExit: adapter.requireCleanExit === true
              || Boolean(adapter.completion),
            outputLimits: {
              stdout: outputMaxBytes,
              stderr: diagnosticsMaxBytes,
            },
            command: [command.command, ...command.args],
            detachCommand,
            detachCommandTimeoutMs: adapter.detach?.timeoutMs || 30_000,
            detachTimeoutMs: adapter.detachTimeoutMs || 5_000,
          };
          attached.push(entry);
          await persistAttached();
          await assertProcessStayedRunning(child, adapter);
          readiness = await waitForJsonReadiness(child, adapter, {
            stdout: logPath,
            stderr: diagnosticsPath,
          });
          entry.readiness = readiness;
        } catch (error) {
          const processExited = (
            lifecycle.processExited
            || child.exitCode != null
            || child.signalCode != null
          );
          await appendStartupDiagnostics(
            error,
            lifecycle,
            diagnosticsPath,
            processExited,
          );
          if (modeRequired(adapter, mode)) {
            error.attachedAdapters = entry
              ? [...attached]
              : [...attached, {
                  name: adapter.name,
                  required: true,
                  evidence: adapter.evidence !== false,
                  evidenceRequired: adapter.evidenceRequired !== false,
                  cleanupCritical: adapter.cleanupCritical === true,
                  pid: child.pid,
                  pidStartTime,
                  longRunning: true,
                  logPath,
                  diagnosticsPath,
                  outputLimits: {
                    stdout: outputMaxBytes,
                    stderr: diagnosticsMaxBytes,
                  },
                  requireCleanExit: adapter.requireCleanExit === true
                    || Boolean(adapter.completion),
                  detachCommand,
                  detachCommandTimeoutMs: adapter.detach?.timeoutMs || 30_000,
                  detachTimeoutMs: adapter.detachTimeoutMs || 5_000,
                }];
            throw error;
          }
          if (!entry) {
            entry = {
              name: adapter.name,
              required: false,
              evidence: adapter.evidence !== false,
              evidenceRequired: adapter.evidenceRequired === true,
              cleanupCritical: adapter.cleanupCritical === true,
              pid: child.pid,
              pidStartTime,
              longRunning: true,
              logPath,
              diagnosticsPath,
              outputLimits: {
                stdout: outputMaxBytes,
                stderr: diagnosticsMaxBytes,
              },
              requireCleanExit: adapter.requireCleanExit === true
                || Boolean(adapter.completion),
              detachCommand,
              detachCommandTimeoutMs: adapter.detach?.timeoutMs || 30_000,
              detachTimeoutMs: adapter.detachTimeoutMs || 5_000,
            };
            attached.push(entry);
          }
          const startupCleanup = await cleanupFailedStartupProcess({
            child,
            lifecycle,
            pidStartTime,
            termTimeoutMs: adapter.detachTimeoutMs || 5_000,
            killTimeoutMs: this.limitKillGraceMs,
            processStartTimeProvider: this.processStartTimeProvider,
            signalProcessImpl: this.signalProcessImpl,
          });
          entry.error = error.message;
          entry.startupCleanupOk = startupCleanup.cleanupOk;
          entry.startupCleanupForced = startupCleanup.forced;
          entry.startupCleanupIdentityLost = startupCleanup.identityLost;
          entry.startupCleanupSignal = startupCleanup.signal;
          if (startupCleanup.error) {
            entry.startupCleanupError = startupCleanup.error;
          }
          await persistAttached();
          if (startupCleanup.cleanupOk && pidStartTime) {
            this.longRunningChildren.delete(`${child.pid}:${pidStartTime}`);
          }
          if (
            adapter.cleanupCritical === true
            && startupCleanup.cleanupOk !== true
          ) {
            const cleanupError = new Error(
              `optional cleanup-critical adapter ${adapter.name} startup failed and could not be proven stopped: ${
                startupCleanup.error || error.message
              }`,
            );
            cleanupError.cause = error;
            cleanupError.attachedAdapters = [...attached];
            throw cleanupError;
          }
          continue;
        }
        child.unref();
      } else {
        const result = this.spawnSyncImpl(command.command, command.args, {
          encoding: 'utf8',
          timeout: adapter.attach.timeoutMs || 30_000,
          env: { ...process.env, ...command.environment },
          stdio: ['ignore', 'pipe', 'pipe'],
        });
        await Promise.all([
          fs.writeFile(logPath, String(result.stdout || ''), { mode: 0o600 }),
          fs.writeFile(diagnosticsPath, String(result.stderr || ''), {
            mode: 0o600,
          }),
        ]);
        if (result.status !== 0) {
          if (modeRequired(adapter, mode)) {
            const current = {
              name: adapter.name,
              required: true,
              evidence: adapter.evidence !== false,
              evidenceRequired: adapter.evidenceRequired !== false,
              cleanupCritical: adapter.cleanupCritical === true,
              longRunning: false,
              logPath,
              diagnosticsPath,
              command: [command.command, ...command.args],
              detachCommand,
              detachCommandTimeoutMs: adapter.detach?.timeoutMs || 30_000,
              detachTimeoutMs: adapter.detachTimeoutMs || 5_000,
              attachStatus: result.status,
              attachError:
                result.error?.message || String(result.stderr || '').trim(),
            };
            const error = new Error(
              `required adapter ${adapter.name} failed to attach: ${
                result.error?.message || result.stderr || `status ${result.status}`
              }`,
            );
            error.attachedAdapters = [...attached, current];
            throw error;
          }
          attached.push({
            name: adapter.name,
            error: result.error?.message || String(result.stderr || ''),
            status: result.status,
            required: false,
            evidence: adapter.evidence !== false,
            evidenceRequired: adapter.evidenceRequired === true,
            cleanupCritical: adapter.cleanupCritical === true,
            logPath,
            diagnosticsPath,
            detachCommand,
            detachCommandTimeoutMs: adapter.detach?.timeoutMs || 30_000,
            detachTimeoutMs: adapter.detachTimeoutMs || 5_000,
          });
          await persistAttached();
          continue;
        }
        entry = {
          name: adapter.name,
          required: modeRequired(adapter, mode),
          evidence: adapter.evidence !== false,
          evidenceRequired: adapter.evidenceRequired == null
            ? modeRequired(adapter, mode)
            : adapter.evidenceRequired === true,
          cleanupCritical: adapter.cleanupCritical === true,
          longRunning: false,
          logPath,
          diagnosticsPath,
          command: [command.command, ...command.args],
          completion: adapter.completion || null,
          detachCommand,
          detachCommandTimeoutMs: adapter.detach?.timeoutMs || 30_000,
          detachTimeoutMs: adapter.detachTimeoutMs || 5_000,
        };
      }
      if (!attached.includes(entry)) attached.push(entry);
      await persistAttached();
      if (adapter.verify) {
        const verification = commandSpec(adapter.verify, context);
        const result = this.spawnSyncImpl(
          verification.command,
          verification.args,
          {
            encoding: 'utf8',
            timeout: adapter.verify.timeoutMs || 10_000,
            env: { ...process.env, ...verification.environment },
            stdio: ['ignore', 'pipe', 'pipe'],
          },
        );
        const verificationPath = path.join(
          context.evidenceDir,
          `${adapter.name}.verify.log`,
        );
        await fs.writeFile(
          verificationPath,
          `${String(result.stdout || '')}${String(result.stderr || '')}`,
          { mode: 0o600 },
        );
        entry.verification = {
          ok: result.status === 0,
          status: result.status,
          logPath: verificationPath,
          command: [verification.command, ...verification.args],
          error:
            result.error?.message || String(result.stderr || '').trim() || null,
        };
        if (result.status !== 0) {
          if (modeRequired(adapter, mode)) {
            const error = new Error(
              `required adapter ${adapter.name} failed post-attach verification: ${
                entry.verification.error || `status ${result.status}`
              }`,
            );
            error.attachedAdapters = [...attached];
            throw error;
          }
          await this.detach({ adapters: [entry] }, context);
          entry.detached = true;
          entry.error =
            entry.verification.error ||
            `post-attach verification exited ${result.status}`;
        }
        await persistAttached();
      }
    }
    return attached;
  }

  async detach(run, context) {
    let configError = null;
    let byName = new Map();
    try {
      const config = await this.loadConfig();
      byName = new Map(
        config.adapters.map((adapter) => [adapter.name, adapter]),
      );
    } catch (error) {
      configError = error;
    }
    const results = [];
    for (const attached of run.adapters || []) {
      const adapter = byName.get(attached.name);
      let detachCommand = null;
      let detachCommandError = null;
      try {
        detachCommand = attached.detachCommand
          ? storedCommandSpec(attached.detachCommand)
          : adapter?.detach
            ? commandSpec(adapter.detach, context)
            : null;
      } catch (error) {
        detachCommandError = error;
      }
      if (detachCommand) {
        let result;
        try {
          result = this.spawnSyncImpl(
            detachCommand.command,
            detachCommand.args,
            {
              encoding: 'utf8',
              timeout:
                attached.detachCommandTimeoutMs ||
                adapter?.detach?.timeoutMs ||
                30_000,
              env: { ...process.env, ...detachCommand.environment },
              stdio: ['ignore', 'pipe', 'pipe'],
            },
          );
        } catch (error) {
          result = { status: null, error, stderr: '' };
        }
        results.push({
          name: attached.name,
          ok: result.status === 0,
          cleanupCritical: attached.cleanupCritical === true,
          cleanupOk: result.status === 0,
          status: result.status,
          error: result.error?.message || String(result.stderr || '').trim() || null,
        });
      } else if (attached.cleanupCritical === true) {
        results.push({
          name: attached.name,
          ok: false,
          cleanupCritical: true,
          cleanupOk: false,
          error:
            detachCommandError?.message ||
            (configError
              ? `no pinned detach command and adapter configuration is unavailable: ${configError.message}`
              : 'adapter has no detach command'),
        });
      }
      if (attached.longRunning && Number.isSafeInteger(attached.pid)) {
        const lifecycleKey = `${attached.pid}:${attached.pidStartTime || ''}`;
        const lifecycle = this.longRunningChildren.get(lifecycleKey) || null;
        if (lifecycle) {
          lifecycle.expectedStop = true;
        }
        const persistedExitStatusKnown = attached.exitStatusKnown === true;
        const observedExitStatusKnown = Boolean(lifecycle?.exited)
          || persistedExitStatusKnown;
        const observedExitCode = lifecycle?.exited
          ? lifecycle.exitCode
          : persistedExitStatusKnown
            ? attached.exitCode ?? null
            : null;
        const observedExitSignal = lifecycle?.exited
          ? lifecycle.signal
          : persistedExitStatusKnown
            ? attached.exitSignal ?? null
            : null;
        const evidenceFailures = Array.isArray(lifecycle?.evidenceFailures)
          ? lifecycle.evidenceFailures
          : Array.isArray(attached.evidenceFailures)
            ? attached.evidenceFailures
            : [];
        const requireCleanExit = attached.requireCleanExit === true
          || Boolean(adapter?.completion);
        try {
          if (observedExitStatusKnown) {
            const evidenceOk = evidenceFailures.length === 0;
            const exitStatusOk = observedExitCode === 0
              && observedExitSignal == null;
            results.push({
              name: attached.name,
              ok: exitStatusOk && evidenceOk,
              cleanupCritical: attached.cleanupCritical === true,
              cleanupOk: true,
              evidenceOk,
              evidenceFailures,
              signal: null,
              exitCode: observedExitCode,
              exitSignal: observedExitSignal,
              exitStatusKnown: true,
              error: !exitStatusOk
                ? `adapter exited unsuccessfully: ${
                  observedExitSignal || `status ${observedExitCode}`
                }`
                : evidenceFailures[0]?.error || null,
            });
            continue;
          }
          const currentStartTime = await this.processStartTimeProvider(attached.pid);
          if (
            !attached.pidStartTime ||
            currentStartTime !== attached.pidStartTime
          ) {
            results.push({
              name: attached.name,
              ok: false,
              cleanupCritical: attached.cleanupCritical === true,
              cleanupOk: false,
              error: 'refusing to signal an adapter PID with a different process identity',
            });
            continue;
          }
          this.signalProcessImpl(attached.pid, 'SIGTERM');
          const detachTimeoutMs =
            attached.detachTimeoutMs || adapter?.detachTimeoutMs || 5_000;
          let exited = lifecycle
            ? await waitForChildClose(lifecycle, detachTimeoutMs)
            : await waitForProcessExit(attached.pid, detachTimeoutMs);
          let forced = false;
          let identityLost = false;
          if (!exited) {
            try {
              identityLost = await this.processStartTimeProvider(attached.pid)
                !== attached.pidStartTime;
            } catch (error) {
              if (error.code !== 'ESRCH' && error.code !== 'ENOENT') throw error;
              identityLost = true;
            }
            if (identityLost) {
              exited = true;
            } else {
              forced = true;
              try {
                this.signalProcessImpl(-attached.pid, 'SIGKILL');
              } catch (error) {
                if (error.code !== 'ESRCH') throw error;
                const currentStartTime = await this.processStartTimeProvider(
                  attached.pid,
                );
                if (currentStartTime !== attached.pidStartTime) {
                  identityLost = true;
                } else {
                  this.signalProcessImpl(attached.pid, 'SIGKILL');
                }
              }
              exited = identityLost || (lifecycle
                ? await waitForChildClose(lifecycle, this.limitKillGraceMs)
                : await waitForProcessExit(attached.pid, this.limitKillGraceMs));
            }
          }
          const exitStatusKnown = Boolean(
            lifecycle?.exited || lifecycle?.processExited,
          );
          const exitCode = lifecycle?.exited
            ? lifecycle.exitCode
            : lifecycle?.processExitCode ?? null;
          const exitSignal = lifecycle?.exited
            ? lifecycle.signal
            : lifecycle?.processExitSignal ?? null;
          const exitStatusOk = exitStatusKnown
            && exitCode === 0
            && exitSignal == null;
          const exitStatusAccepted = exitStatusOk || (
            exitStatusKnown
            && !forced
            && !requireCleanExit
            && exitSignal === 'SIGTERM'
          );
          const evidenceOk = evidenceFailures.length === 0 && !identityLost;
          results.push({
            name: attached.name,
            ok: exited && exitStatusAccepted && evidenceOk,
            cleanupCritical: attached.cleanupCritical === true,
            cleanupOk: exited,
            evidenceOk,
            evidenceFailures,
            signal: forced ? 'SIGKILL' : 'SIGTERM',
            forced,
            identityLost,
            exitCode: exitStatusKnown ? exitCode : null,
            exitSignal: exitStatusKnown ? exitSignal : null,
            exitStatusKnown,
            requireCleanExit,
            error: identityLost
              ? 'adapter process identity disappeared during shutdown; evidence is incomplete'
              : !exited
              ? `adapter did not exit after SIGTERM and SIGKILL; evidence may be incomplete`
              : !exitStatusKnown
                ? 'adapter exit status is unavailable after supervisor restart'
                : !exitStatusAccepted
                  ? `adapter exited unsuccessfully: ${exitSignal || `status ${exitCode}`}`
                  : evidenceFailures[0]?.error || null,
          });
        } catch (error) {
          const processGone = error.code === 'ESRCH' || error.code === 'ENOENT';
          results.push({
            name: attached.name,
            ok: false,
            cleanupCritical: attached.cleanupCritical === true,
            cleanupOk: processGone,
            evidenceOk: false,
            evidenceFailures,
            exitCode: lifecycle?.exitCode ?? null,
            exitSignal: lifecycle?.signal ?? null,
            exitStatusKnown: Boolean(lifecycle?.exited) || persistedExitStatusKnown,
            error: processGone
              ? 'long-running adapter exited before supervised shutdown; exit status is unavailable'
              : error.message,
          });
        } finally {
          if (!lifecycle || lifecycle.exited || lifecycle.processExited) {
            this.longRunningChildren.delete(lifecycleKey);
          }
        }
      }
    }
    return results;
  }

  async runtimeHealth(run, context) {
    const config = await this.loadConfig();
    const byName = new Map(config.adapters.map((adapter) => [adapter.name, adapter]));
    const results = [];
    for (const attached of run.adapters || []) {
      const adapter = byName.get(attached.name);
      if (!adapter || !modeActive(adapter, run.mode)) {
        const required = attached.required !== false;
        results.push({
          name: attached.name,
          required,
          ok: !required,
          processOk: false,
          verification: null,
          error: adapter
            ? 'attached adapter is no longer active in this run mode'
            : 'attached adapter is missing from the trusted configuration',
        });
        continue;
      }
      let processOk = true;
      let processError = null;
      if (attached.longRunning) {
        const lifecycle = this.longRunningChildren.get(
          `${attached.pid}:${attached.pidStartTime || ''}`,
        ) || null;
        const exitStatusKnown = Boolean(lifecycle?.exited)
          || attached.exitStatusKnown === true;
        const exitCode = lifecycle?.exited
          ? lifecycle.exitCode
          : attached.exitCode ?? null;
        const exitSignal = lifecycle?.exited
          ? lifecycle.signal
          : attached.exitSignal ?? null;
        const evidenceFailures = lifecycle?.evidenceFailures?.length
          ? lifecycle.evidenceFailures
          : attached.evidenceFailures;
        if (Array.isArray(evidenceFailures) && evidenceFailures.length) {
          processOk = false;
          processError = evidenceFailures[0].error
            || 'collector evidence limit was exceeded';
        } else if (exitStatusKnown) {
          processOk = false;
          processError = `collector exited before finalization: ${
            exitSignal || `status ${exitCode}`
          }`;
        } else {
          try {
            processOk =
              Number.isSafeInteger(attached.pid) &&
              Boolean(attached.pidStartTime) &&
              (await this.processStartTimeProvider(attached.pid))
                === attached.pidStartTime;
            if (!processOk) {
              processError = 'collector process identity changed';
            }
          } catch (error) {
            processOk = false;
            processError = error.message;
          }
        }
      }
      let verification = null;
      if (processOk && adapter.verify) {
        const command = commandSpec(adapter.verify, context);
        const result = this.spawnSyncImpl(command.command, command.args, {
          encoding: 'utf8',
          timeout: adapter.verify.timeoutMs || 10_000,
          env: { ...process.env, ...command.environment },
          stdio: ['ignore', 'pipe', 'pipe'],
        });
        verification = {
          ok: result.status === 0,
          status: result.status,
          error:
            result.error?.message || String(result.stderr || '').trim() || null,
        };
      }
      results.push({
        name: attached.name,
        required: attached.required !== false,
        ok: processOk && verification?.ok !== false,
        processOk,
        verification,
        error: processError || verification?.error || null,
      });
    }
    return results;
  }
}
