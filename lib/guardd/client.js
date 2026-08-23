import http from 'node:http';

import { DEFAULT_GUARD_SOCKET } from './constants.js';

const DEFAULT_REQUEST_TIMEOUT_MS = 120_000;
const MAX_REQUEST_TIMEOUT_MS = 600_000;

function requestTimeout(value) {
  const selected = value ?? DEFAULT_REQUEST_TIMEOUT_MS;
  if (
    !Number.isSafeInteger(selected)
    || selected < 1
    || selected > MAX_REQUEST_TIMEOUT_MS
  ) {
    throw new TypeError(
      `requestTimeoutMs must be an integer between 1 and ${MAX_REQUEST_TIMEOUT_MS} milliseconds`,
    );
  }
  return selected;
}

function timeoutError(method, requestPath, timeoutMs) {
  const error = new Error(
    `Nosh Guard ${method} ${requestPath} timed out after ${timeoutMs}ms`,
  );
  error.code = 'GUARD_REQUEST_TIMEOUT';
  error.timeoutMs = timeoutMs;
  return error;
}

function collect(response) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    response.on('data', (chunk) => chunks.push(chunk));
    response.on('error', reject);
    response.on('end', () => {
      const raw = Buffer.concat(chunks).toString('utf8');
      const body = raw ? JSON.parse(raw) : null;
      if ((response.statusCode || 500) >= 400) {
        const error = new Error(body?.error?.message || 'guard request failed');
        error.code = body?.error?.code;
        error.statusCode = response.statusCode;
        for (const field of [
          'runId',
          'containerId',
          'runtimeState',
          'runtimeLogTail',
          'containerRemoved',
        ]) {
          if (body?.error?.[field] !== undefined) {
            error[field] = body.error[field];
          }
        }
        error.document = body;
        reject(error);
        return;
      }
      resolve(body);
    });
  });
}

export class GuardClient {
  constructor(options = {}) {
    this.socketPath = options.socketPath || DEFAULT_GUARD_SOCKET;
    this.requestImpl = options.requestImpl || http.request;
    this.requestTimeoutMs = requestTimeout(options.requestTimeoutMs);
  }

  request(method, requestPath, body = undefined) {
    const encoded = body == null ? null : Buffer.from(JSON.stringify(body), 'utf8');
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
        if (timer !== null) {
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
                'content-length': encoded.length,
              }
            : {},
        },
        (incoming) => {
          response = incoming;
          collect(incoming).then(
            (result) => finish(resolve, result),
            (error) => finish(reject, error),
          );
        },
      );
      request.on('error', (error) => finish(reject, error));
      if (!settled) {
        timer = setTimeout(() => {
          const error = timeoutError(method, requestPath, this.requestTimeoutMs);
          finish(reject, error);
          request.destroy?.();
          response?.destroy?.();
        }, this.requestTimeoutMs);
      }
      try {
        if (encoded) {
          request.write(encoded);
        }
        request.end();
      } catch (error) {
        finish(reject, error);
        request.destroy?.();
      }
    });
  }

  health() {
    return this.request('GET', '/v1/health');
  }

  listRuns() {
    return this.request('GET', '/v1/runs');
  }

  startRun(input) {
    return this.request('POST', '/v1/runs', input);
  }

  listBuildRuns() {
    return this.request('GET', '/v1/build-runs');
  }

  startBuildRun(input) {
    return this.request('POST', '/v1/build-runs', input);
  }

  finishBuildRun(runId, input = {}) {
    return this.request(
      'POST',
      `/v1/build-runs/${encodeURIComponent(runId)}/finish`,
      input,
    );
  }

  abortBuildRun(runId, input = {}) {
    return this.request(
      'POST',
      `/v1/build-runs/${encodeURIComponent(runId)}/abort`,
      input,
    );
  }

  acknowledgeBuildExport(runId, input = {}) {
    return this.request(
      'POST',
      `/v1/build-runs/${encodeURIComponent(runId)}/exported`,
      input,
    );
  }

  action(identifier, action, options = {}) {
    return this.request(
      'POST',
      `/v1/runs/${encodeURIComponent(identifier)}/${encodeURIComponent(action)}`,
      options,
    );
  }
}
