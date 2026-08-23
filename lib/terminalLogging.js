import { AsyncLocalStorage } from 'node:async_hooks';
import fs from 'node:fs';

const globalState = globalThis.__nottyLogState || {
  context: new AsyncLocalStorage(),
  stream: null,
  streamPath: null,
  config: null,
  logFileError: false
};

globalThis.__nottyLogState = globalState;

function parseBoolean(value) {
  if (value === undefined || value === null) {
    return null;
  }

  const normalized = String(value).trim().toLowerCase();
  if (['1', 'true', 'yes', 'on'].includes(normalized)) {
    return true;
  }
  if (['0', 'false', 'no', 'off'].includes(normalized)) {
    return false;
  }

  return null;
}

function resolveEnabled() {
  const disabled = parseBoolean(process.env.NOTTY_LOG_DISABLED);
  if (disabled === true) {
    return false;
  }

  const enabled = parseBoolean(process.env.NOTTY_LOG_ENABLED);
  if (enabled !== null) {
    return enabled;
  }

  return true;
}

function loadConfig() {
  if (globalState.config) {
    return globalState.config;
  }

  const config = {
    enabled: resolveEnabled(),
    logReads: parseBoolean(process.env.NOTTY_LOG_READS) === true,
    logFile:
      typeof process.env.NOTTY_LOG_FILE === 'string' && process.env.NOTTY_LOG_FILE.trim()
        ? process.env.NOTTY_LOG_FILE.trim()
        : null
  };

  globalState.config = config;
  return config;
}

function getLogStream() {
  const config = loadConfig();
  if (!config.enabled) {
    return null;
  }

  if (!config.logFile) {
    return process.stderr;
  }

  if (globalState.stream && globalState.streamPath === config.logFile) {
    return globalState.stream;
  }

  try {
    const stream = fs.createWriteStream(config.logFile, { flags: 'a' });
    globalState.stream = stream;
    globalState.streamPath = config.logFile;
    stream.on('error', (err) => {
      globalState.stream = process.stderr;
      globalState.streamPath = null;
      if (!globalState.logFileError) {
        globalState.logFileError = true;
        process.stderr.write(`[notty] log file error: ${err.message}\n`);
      }
    });
    return stream;
  } catch (err) {
    globalState.stream = process.stderr;
    globalState.streamPath = null;
    if (!globalState.logFileError) {
      globalState.logFileError = true;
      process.stderr.write(`[notty] log file error: ${err.message}\n`);
    }
    return process.stderr;
  }
}

export function isLoggingEnabled() {
  return loadConfig().enabled;
}

export function shouldLogReads() {
  return loadConfig().logReads;
}

export function getLogContext() {
  return globalState.context.getStore() || {};
}

export function withLogContext(context, fn) {
  const current = getLogContext();
  const merged = { ...current, ...context };
  return globalState.context.run(merged, fn);
}

export function withLogContextDefaults(context, fn) {
  const current = getLogContext();
  const merged = { ...context, ...current };
  return globalState.context.run(merged, fn);
}

export function logTerminalEvent(event) {
  const config = loadConfig();
  if (!config.enabled) {
    return;
  }

  const context = getLogContext();
  const record = {
    ts: new Date().toISOString(),
    ...context,
    ...event
  };

  if (!record.protocol) {
    record.protocol = 'local';
  }
  if (!record.transport) {
    record.transport = 'local';
  }

  const stream = getLogStream();
  if (!stream) {
    return;
  }

  try {
    stream.write(`${JSON.stringify(record)}\n`);
  } catch {
    // ignore logging errors
  }
}

export function getHttpProtocol(req) {
  const headerValue = req?.headers?.['x-forwarded-proto'];
  const forwarded = Array.isArray(headerValue) ? headerValue[0] : headerValue;
  if (typeof forwarded === 'string' && forwarded.length) {
    const normalized = forwarded.split(',')[0].trim().toLowerCase();
    if (normalized === 'https' || normalized === 'http') {
      return normalized;
    }
  }

  if (typeof req?.protocol === 'string' && req.protocol.length) {
    return req.protocol;
  }

  if (req?.socket?.encrypted) {
    return 'https';
  }

  return 'http';
}

export function getWsProtocol(req) {
  const headerValue = req?.headers?.['x-forwarded-proto'];
  const forwarded = Array.isArray(headerValue) ? headerValue[0] : headerValue;
  if (typeof forwarded === 'string' && forwarded.length) {
    const normalized = forwarded.split(',')[0].trim().toLowerCase();
    if (normalized === 'wss' || normalized === 'ws') {
      return normalized;
    }
    if (normalized === 'https') {
      return 'wss';
    }
    if (normalized === 'http') {
      return 'ws';
    }
  }

  if (req?.socket?.encrypted) {
    return 'wss';
  }

  return 'ws';
}

export function getRequestIpInfo(req) {
  const headerValue = req?.headers?.['x-forwarded-for'];
  let forwardedFor = null;
  if (Array.isArray(headerValue)) {
    forwardedFor = headerValue.join(', ');
  } else if (typeof headerValue === 'string' && headerValue.trim()) {
    forwardedFor = headerValue.trim();
  }

  const sourceIp =
    req?.socket?.remoteAddress
    || req?.connection?.remoteAddress
    || (typeof req?.ip === 'string' ? req.ip : null)
    || null;

  return { sourceIp, forwardedFor };
}
