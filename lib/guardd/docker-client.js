import http from 'node:http';

import { DEFAULT_DOCKER_SOCKET } from './constants.js';

const DEFAULT_REQUEST_TIMEOUT_MS = 30_000;
const DEFAULT_EXEC_WAIT_TIMEOUT_MS = 10_000;
const DEFAULT_EXEC_POLL_INTERVAL_MS = 50;
const MAX_TIMEOUT_MS = 300_000;
const DEFAULT_LOG_TAIL_LINES = 40;
const DEFAULT_LOG_MAX_WIRE_BYTES = 32 * 1024;
const DEFAULT_LOG_MAX_TEXT_BYTES = 8 * 1024;
const MAX_LOG_TAIL_LINES = 200;
const MAX_LOG_WIRE_BYTES = 256 * 1024;
const MAX_LOG_TEXT_BYTES = 32 * 1024;

function collectResponse(response) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    response.on('data', (chunk) => chunks.push(chunk));
    response.on('error', reject);
    response.on('end', () => {
      const raw = Buffer.concat(chunks).toString('utf8');
      let body = null;
      if (raw) {
        try {
          body = JSON.parse(raw);
        } catch {
          body = raw;
        }
      }
      resolve({ statusCode: response.statusCode || 0, headers: response.headers, body });
    });
  });
}

function collectBoundedResponse(response, maxBytes) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let length = 0;
    let settled = false;
    const result = (truncated) => ({
      statusCode: response.statusCode || 0,
      headers: response.headers,
      body: Buffer.concat(chunks, length),
      truncated,
    });
    const finish = (callback, value) => {
      if (settled) {
        return;
      }
      settled = true;
      callback(value);
    };
    response.on('data', (chunk) => {
      if (settled) {
        return;
      }
      const buffer = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
      const remaining = maxBytes - length;
      if (remaining > 0) {
        const retained = buffer.length > remaining
          ? buffer.subarray(0, remaining)
          : buffer;
        chunks.push(retained);
        length += retained.length;
      }
      if (buffer.length > remaining) {
        response.pause?.();
        finish(resolve, result(true));
      }
    });
    response.on('error', (error) => finish(reject, error));
    response.on('end', () => finish(resolve, result(false)));
  });
}

function dockerError(method, requestPath, response) {
  const detail =
    response.body && typeof response.body === 'object'
      ? response.body.message
      : response.body;
  const error = new Error(
    `Docker ${method} ${requestPath} failed (${response.statusCode})${
      detail ? `: ${detail}` : ''
    }`,
  );
  error.statusCode = response.statusCode;
  error.dockerResponse = response.body;
  return error;
}

function timeoutValue(value, fallback, name) {
  const timeout = value ?? fallback;
  if (
    !Number.isSafeInteger(timeout) ||
    timeout <= 0 ||
    timeout > MAX_TIMEOUT_MS
  ) {
    throw new TypeError(
      `${name} must be an integer between 1 and ${MAX_TIMEOUT_MS} milliseconds`,
    );
  }
  return timeout;
}

function boundedInteger(value, fallback, name, maximum) {
  const selected = value ?? fallback;
  if (
    !Number.isSafeInteger(selected)
    || selected <= 0
    || selected > maximum
  ) {
    throw new TypeError(
      `${name} must be an integer between 1 and ${maximum}`,
    );
  }
  return selected;
}

function timeoutError(method, requestPath, timeoutMs) {
  const error = new Error(
    `Docker ${method} ${requestPath} timed out after ${timeoutMs}ms`,
  );
  error.code = 'DOCKER_REQUEST_TIMEOUT';
  error.timeoutMs = timeoutMs;
  return error;
}

function execError(execId, exitCode) {
  const error = new Error(
    `Docker exec ${execId} failed with exit code ${exitCode}`,
  );
  error.code = 'DOCKER_EXEC_FAILED';
  error.execId = execId;
  error.exitCode = exitCode;
  return error;
}

function execTimeoutError(execId, timeoutMs) {
  const error = new Error(
    `Docker exec ${execId} did not complete within ${timeoutMs}ms`,
  );
  error.code = 'DOCKER_EXEC_TIMEOUT';
  error.execId = execId;
  error.timeoutMs = timeoutMs;
  return error;
}

function delay(milliseconds) {
  return new Promise((resolve) => setTimeout(resolve, milliseconds));
}

function dockerLogFrameHeader(buffer, offset) {
  if (buffer.length - offset < 8) {
    return null;
  }
  const stream = buffer[offset];
  if (
    ![1, 2].includes(stream)
    || buffer[offset + 1] !== 0
    || buffer[offset + 2] !== 0
    || buffer[offset + 3] !== 0
  ) {
    return false;
  }
  return {
    stream,
    length: buffer.readUInt32BE(offset + 4),
  };
}

export function decodeDockerLogStream(value) {
  const buffer = Buffer.isBuffer(value) ? value : Buffer.from(value || '');
  const firstHeader = dockerLogFrameHeader(buffer, 0);
  if (!firstHeader) {
    return {
      buffer,
      multiplexed: false,
      incomplete: false,
    };
  }
  const payloads = [];
  let payloadLength = 0;
  let offset = 0;
  let incomplete = false;
  while (offset < buffer.length) {
    const header = dockerLogFrameHeader(buffer, offset);
    if (!header) {
      incomplete = true;
      break;
    }
    const payloadOffset = offset + 8;
    const available = Math.min(
      header.length,
      Math.max(0, buffer.length - payloadOffset),
    );
    if (available > 0) {
      payloads.push(buffer.subarray(payloadOffset, payloadOffset + available));
      payloadLength += available;
    }
    if (available !== header.length) {
      incomplete = true;
      break;
    }
    offset = payloadOffset + header.length;
  }
  return {
    buffer: Buffer.concat(payloads, payloadLength),
    multiplexed: true,
    incomplete,
  };
}

const SENSITIVE_RUNTIME_LOG_KEY =
  /api[_-]?key|access[_-]?key|authorization|client[_-]?secret|cookie|nosh_guard_command_b64|pass(?:word|wd)?|private[_-]?key|secret|set-cookie|token/iu;

function redactSensitiveLogAssignments(value) {
  return value
    .split('\n')
    .map((line) => {
      const assignments = /(^|[^A-Za-z0-9])([A-Za-z_][A-Za-z0-9_-]*)\s*[:=]\s*/gu;
      let match;
      while ((match = assignments.exec(line)) !== null) {
        if (SENSITIVE_RUNTIME_LOG_KEY.test(match[2])) {
          return `${line.slice(0, match.index + match[0].length)}[redacted]`;
        }
      }
      return line;
    })
    .join('\n');
}

function redactRuntimeLogSecrets(value) {
  return redactSensitiveLogAssignments(value)
    .replace(/\bBearer\s+[^\s]+/giu, 'Bearer [redacted]')
    .replace(
      /\b([a-z][a-z0-9+.-]*:\/\/)[^\s/@:]+:[^\s/@]+@/giu,
      '$1[redacted]@',
    );
}

function controlSanitizedLogText(value) {
  return value
    .replace(/\r\n?/gu, '\n')
    .split('\n')
    .map((line) => line.replace(/[\p{Cc}\p{Cf}\p{Zl}\p{Zp}]/gu, '\ufffd'))
    .join('\n');
}

function utf8Tail(value, maxBytes) {
  if (Buffer.byteLength(value, 'utf8') <= maxBytes) {
    return { text: value, truncated: false };
  }
  const characters = Array.from(value);
  let bytes = 0;
  let start = characters.length;
  while (start > 0) {
    const next = Buffer.byteLength(characters[start - 1], 'utf8');
    if (bytes + next > maxBytes) {
      break;
    }
    bytes += next;
    start -= 1;
  }
  return {
    text: characters.slice(start).join(''),
    truncated: true,
  };
}

export function sanitizeDockerRuntimeLogTail(value, options = {}) {
  const maxLines = boundedInteger(
    options.maxLines,
    DEFAULT_LOG_TAIL_LINES,
    'maxLines',
    MAX_LOG_TAIL_LINES,
  );
  const maxBytes = boundedInteger(
    options.maxBytes,
    DEFAULT_LOG_MAX_TEXT_BYTES,
    'maxBytes',
    MAX_LOG_TEXT_BYTES,
  );
  const rawText = typeof value === 'string'
    ? value
    : typeof value?.text === 'string'
      ? value.text
      : '';
  let text = redactRuntimeLogSecrets(controlSanitizedLogText(rawText));
  text = text.replace(/\n+$/u, '');
  if (!text) {
    return value && typeof value === 'object'
      ? { text: '', truncated: value.truncated === true }
      : null;
  }
  const lines = text.split('\n');
  const lineTruncated = lines.length > maxLines;
  if (lineTruncated) {
    text = lines.slice(-maxLines).join('\n');
  }
  const byteTail = utf8Tail(text, maxBytes);
  return {
    text: byteTail.text,
    truncated:
      value?.truncated === true
      || lineTruncated
      || byteTail.truncated,
  };
}

export class DockerClient {
  constructor(options = {}) {
    this.socketPath = options.socketPath || DEFAULT_DOCKER_SOCKET;
    this.apiVersion = options.apiVersion || 'v1.44';
    this.requestImpl = options.requestImpl || http.request;
    this.requestTimeoutMs = timeoutValue(
      options.requestTimeoutMs,
      DEFAULT_REQUEST_TIMEOUT_MS,
      'requestTimeoutMs',
    );
    this.execWaitTimeoutMs = timeoutValue(
      options.execWaitTimeoutMs,
      DEFAULT_EXEC_WAIT_TIMEOUT_MS,
      'execWaitTimeoutMs',
    );
    this.execPollIntervalMs = timeoutValue(
      options.execPollIntervalMs,
      DEFAULT_EXEC_POLL_INTERVAL_MS,
      'execPollIntervalMs',
    );
  }

  async request(method, endpoint, body = undefined, options = {}) {
    const encoded = body == null ? null : Buffer.from(JSON.stringify(body), 'utf8');
    const requestPath = `/${this.apiVersion}${endpoint}`;
    const requestTimeoutMs = timeoutValue(
      options.timeoutMs,
      this.requestTimeoutMs,
      'timeoutMs',
    );
    const result = await new Promise((resolve, reject) => {
      let request;
      let response;
      let timer = null;
      let settled = false;
      const finish = (callback, value) => {
        if (settled) {
          return;
        }
        settled = true;
        if (timer) {
          clearTimeout(timer);
        }
        callback(value);
      };
      request = this.requestImpl(
        {
          socketPath: this.socketPath,
          method,
          path: requestPath,
          headers: encoded
            ? {
                'content-type': 'application/json',
                'content-length': String(encoded.length),
              }
            : {},
        },
        (incoming) => {
          response = incoming;
          collectResponse(incoming).then(
            (collected) => finish(resolve, collected),
            (error) => finish(reject, error),
          );
        },
      );
      request.on('error', (error) => finish(reject, error));
      if (!settled) {
        timer = setTimeout(() => {
          const error = timeoutError(method, requestPath, requestTimeoutMs);
          finish(reject, error);
          request.destroy?.();
          response?.destroy?.();
        }, requestTimeoutMs);
      }
      if (encoded) {
        request.write(encoded);
      }
      request.end();
    });
    const accepted = options.accept || [200, 201, 204];
    if (!accepted.includes(result.statusCode)) {
      throw dockerError(method, requestPath, result);
    }
    return result.body;
  }

  async requestBoundedBuffer(method, endpoint, options = {}) {
    const requestPath = `/${this.apiVersion}${endpoint}`;
    const requestTimeoutMs = timeoutValue(
      options.timeoutMs,
      this.requestTimeoutMs,
      'timeoutMs',
    );
    const maxBytes = boundedInteger(
      options.maxBytes,
      DEFAULT_LOG_MAX_WIRE_BYTES,
      'maxBytes',
      MAX_LOG_WIRE_BYTES,
    );
    return new Promise((resolve, reject) => {
      let request;
      let response;
      let timer = null;
      let settled = false;
      const finish = (callback, value) => {
        if (settled) {
          return;
        }
        settled = true;
        if (timer) {
          clearTimeout(timer);
        }
        callback(value);
      };
      request = this.requestImpl(
        {
          socketPath: this.socketPath,
          method,
          path: requestPath,
          headers: {
            accept: 'application/vnd.docker.raw-stream',
          },
        },
        (incoming) => {
          response = incoming;
          collectBoundedResponse(incoming, maxBytes).then(
            (collected) => {
              finish(resolve, { ...collected, requestPath });
              if (collected.truncated) {
                request.destroy?.();
                incoming.destroy?.();
              }
            },
            (error) => finish(reject, error),
          );
        },
      );
      request.on('error', (error) => finish(reject, error));
      if (!settled) {
        timer = setTimeout(() => {
          const error = timeoutError(method, requestPath, requestTimeoutMs);
          finish(reject, error);
          request.destroy?.();
          response?.destroy?.();
        }, requestTimeoutMs);
      }
      request.end();
    });
  }

  ping() {
    return this.request('GET', '/_ping', undefined, { accept: [200] });
  }

  createContainer(name, spec) {
    const query = new URLSearchParams({ name }).toString();
    return this.request('POST', `/containers/create?${query}`, spec, {
      accept: [201],
    });
  }

  startContainer(containerId) {
    return this.request('POST', `/containers/${encodeURIComponent(containerId)}/start`);
  }

  inspectContainer(containerId) {
    return this.request('GET', `/containers/${encodeURIComponent(containerId)}/json`);
  }

  async containerLogs(containerId, options = {}) {
    const tailLines = boundedInteger(
      options.tailLines,
      DEFAULT_LOG_TAIL_LINES,
      'tailLines',
      MAX_LOG_TAIL_LINES,
    );
    const maxTextBytes = boundedInteger(
      options.maxTextBytes,
      DEFAULT_LOG_MAX_TEXT_BYTES,
      'maxTextBytes',
      MAX_LOG_TEXT_BYTES,
    );
    const query = new URLSearchParams({
      follow: 'false',
      stderr: 'true',
      stdout: 'true',
      tail: String(tailLines),
      timestamps: 'false',
    });
    const result = await this.requestBoundedBuffer(
      'GET',
      `/containers/${encodeURIComponent(containerId)}/logs?${query}`,
      {
        maxBytes: options.maxWireBytes,
        timeoutMs: options.timeoutMs,
      },
    );
    if (result.statusCode !== 200) {
      const raw = result.body.toString('utf8');
      let body = raw;
      if (raw) {
        try {
          body = JSON.parse(raw);
        } catch {
          // Keep the already bounded response text for Docker's error detail.
        }
      }
      throw dockerError('GET', result.requestPath, {
        ...result,
        body,
      });
    }
    // Docker selects the final lines server-side. If that selected response
    // exceeds the wire cap, retain only the bounded segment and report it as
    // truncated rather than buffering an arbitrarily large line.
    const decoded = decodeDockerLogStream(result.body);
    return sanitizeDockerRuntimeLogTail(
      {
        text: decoded.buffer.toString('utf8'),
        truncated: result.truncated || decoded.incomplete,
      },
      {
        maxLines: tailLines,
        maxBytes: maxTextBytes,
      },
    );
  }

  listContainers(options = {}) {
    const query = new URLSearchParams({
      all: String(options.all !== false),
    });
    if (options.filters) {
      query.set('filters', JSON.stringify(options.filters));
    }
    return this.request('GET', `/containers/json?${query.toString()}`);
  }

  inspectImage(image) {
    return this.request('GET', `/images/${encodeURIComponent(image)}/json`);
  }

  inspectNetwork(network) {
    return this.request('GET', `/networks/${encodeURIComponent(network)}`, undefined, {
      accept: [200],
    });
  }

  createNetwork(name, options = {}) {
    return this.request(
      'POST',
      '/networks/create',
      {
        Name: name,
        Driver: options.driver || 'bridge',
        Internal: options.internal !== false,
        Attachable: false,
        Ingress: false,
        CheckDuplicate: true,
        EnableIPv6: Boolean(options.enableIPv6),
        Labels: options.labels || {},
        Options: options.options || {},
        IPAM: options.ipam
          ? {
              Driver: options.ipam.driver || 'default',
              Config: (options.ipam.config || [options.ipam]).map((entry) => ({
                Subnet: entry.subnet,
                Gateway: entry.gateway,
                IPRange: entry.ipRange || '',
                AuxAddress: entry.auxAddress || {},
              })),
              Options: options.ipam.options || {},
            }
          : undefined,
      },
      { accept: [201] },
    );
  }

  connectNetwork(network, containerId, options = {}) {
    return this.request(
      'POST',
      `/networks/${encodeURIComponent(network)}/connect`,
      {
        Container: containerId,
        EndpointConfig: {
          IPAMConfig: {
            IPv4Address: options.ipv4Address || '',
            IPv6Address: options.ipv6Address || '',
            LinkLocalIPs: options.linkLocalIps || [],
          },
          Aliases: options.aliases || [],
        },
      },
    );
  }

  disconnectNetwork(network, containerId, force = false) {
    return this.request(
      'POST',
      `/networks/${encodeURIComponent(network)}/disconnect`,
      { Container: containerId, Force: Boolean(force) },
    );
  }

  removeNetwork(network) {
    return this.request('DELETE', `/networks/${encodeURIComponent(network)}`);
  }

  async ensureInternalNetwork(name, options = {}) {
    let network;
    try {
      network = await this.inspectNetwork(name);
    } catch (error) {
      if (error.statusCode !== 404) {
        throw error;
      }
      await this.createNetwork(name, { ...options, internal: true });
      network = await this.inspectNetwork(name);
    }
    if (!network?.Internal) {
      throw new Error(`guard network must be Docker-internal: ${name}`);
    }
    return network;
  }

  stopContainer(containerId, timeoutSeconds = 10) {
    const query = new URLSearchParams({ t: String(timeoutSeconds) }).toString();
    return this.request(
      'POST',
      `/containers/${encodeURIComponent(containerId)}/stop?${query}`,
      undefined,
      { accept: [204, 304] },
    );
  }

  removeContainer(containerId, force = false) {
    const query = new URLSearchParams({ force: String(Boolean(force)) }).toString();
    return this.request(
      'DELETE',
      `/containers/${encodeURIComponent(containerId)}?${query}`,
    );
  }

  async exec(containerId, command, options = {}) {
    const created = await this.request(
      'POST',
      `/containers/${encodeURIComponent(containerId)}/exec`,
      {
        AttachStderr: false,
        AttachStdout: false,
        Cmd: command,
        Env: options.environment || [],
        Privileged: false,
        Tty: false,
        User: options.user || '0',
        WorkingDir: options.workdir || '/',
      },
      { accept: [201] },
    );
    if (!created?.Id) {
      throw new Error('Docker did not return an exec ID');
    }
    await this.request(
      'POST',
      `/exec/${encodeURIComponent(created.Id)}/start`,
      { Detach: true, Tty: false },
    );
    return created.Id;
  }

  inspectExec(execId, options = {}) {
    return this.request(
      'GET',
      `/exec/${encodeURIComponent(execId)}/json`,
      undefined,
      options,
    );
  }

  async waitForExec(execId, options = {}) {
    const timeoutMs = timeoutValue(
      options.timeoutMs,
      this.execWaitTimeoutMs,
      'timeoutMs',
    );
    const pollIntervalMs = timeoutValue(
      options.pollIntervalMs,
      this.execPollIntervalMs,
      'pollIntervalMs',
    );
    const deadline = Date.now() + timeoutMs;
    while (true) {
      const remainingMs = deadline - Date.now();
      if (remainingMs <= 0) {
        throw execTimeoutError(execId, timeoutMs);
      }
      const inspection = await this.inspectExec(execId, {
        timeoutMs: Math.max(1, Math.min(this.requestTimeoutMs, remainingMs)),
      });
      if (inspection?.Running === false) {
        if (!Number.isInteger(inspection.ExitCode)) {
          throw new Error(`Docker exec ${execId} returned no exit code`);
        }
        if (inspection.ExitCode !== 0) {
          throw execError(execId, inspection.ExitCode);
        }
        return inspection;
      }
      if (inspection?.Running !== true) {
        throw new Error(`Docker exec ${execId} returned an invalid running state`);
      }
      const sleepMs = Math.min(pollIntervalMs, deadline - Date.now());
      if (sleepMs <= 0) {
        throw execTimeoutError(execId, timeoutMs);
      }
      await delay(sleepMs);
    }
  }

  async releaseGate(containerId, options = {}) {
    const execId = await this.exec(
      containerId,
      ['/bin/sh', '-c', 'mkdir -p /run/nosh-guard && : > /run/nosh-guard/release'],
      { user: '0' },
    );
    await this.waitForExec(execId, options);
    return execId;
  }

  pauseContainer(containerId) {
    return this.request('POST', `/containers/${encodeURIComponent(containerId)}/pause`);
  }

  unpauseContainer(containerId) {
    return this.request('POST', `/containers/${encodeURIComponent(containerId)}/unpause`);
  }
}
