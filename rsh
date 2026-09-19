#!/usr/bin/env node

const DEFAULT_LIST_TIMEOUT_MS = 800;
const DEFAULT_SESSION_TIMEOUT_MS = 1000;
const DEFAULT_SESSION_ID = 1;

(async () => {
  const args = process.argv.slice(2);
  let command = 'attach';
  if (args.length && typeof args[0] === 'string') {
    const head = args[0].toLowerCase();
    if (head === 'list') {
      command = 'list';
      args.shift();
    } else if (head === 'inspect') {
      command = 'inspect';
      args.shift();
    }
  }
  const listCommand = command === 'list';
  const inspectCommand = command === 'inspect';
  let inspectLocalCommand = false;
  if (inspectCommand && args.length && typeof args[0] === 'string' && args[0].toLowerCase() === 'local') {
    inspectLocalCommand = true;
    args.shift();
  }

  let sessionId;
  let sessionProvided = false;
  let includeHistory = false;
  let showList = listCommand;
  let httpOverride;
  let wsOverride;
  let forceLocal = false;
  let debugFlag = false;
  let positionalSessionId = null;

  const usage = () => {
    console.error('Usage:');
    console.error('  rsh [sessionId] [options]');
    console.error('  rsh list [options]');
    console.error('  rsh inspect [sessionId] [options]');
    console.error('  rsh inspect local [sessionId] [options]');
    console.error('Options:');
    console.error('  -s, --session <id>   Attach to the specified terminal session (defaults to 1)');
    console.error('      --from-start      Replay buffered output before attaching');
    console.error('      --list           List active sessions (legacy flag, prefer `rsh list`)');
    console.error('      --http <url>     Prefer remote REST endpoint (base or /api/terminals URL)');
    console.error('      --ws <url>       Explicit WebSocket endpoint (falls back to discovery/env)');
    console.error('      --local          Skip remote discovery and use in-process sessions only');
    console.error('      --debug          Enable verbose logging');
    console.error('  -h, --help           Show this help message');
    console.error('A one-time spawn OTP is prompted for without echo when session creation requires it.');
    console.error('Detach with Ctrl+] (ASCII 29). Ctrl+C is forwarded to the session.');
  };

  const expectValue = (flag, index) => {
    const value = args[index + 1];
    if (!value) {
      console.error(`Missing value for ${flag}`);
      usage();
      process.exit(1);
    }
    return value;
  };

  for (let i = 0; i < args.length; i += 1) {
    const arg = args[i];
    if (arg === '-s' || arg === '--session') {
      sessionProvided = true;
      const value = expectValue(arg, i);
      i += 1;
      const parsed = Number.parseInt(value, 10);
      if (Number.isNaN(parsed)) {
        console.error(`Invalid session id: ${value}`);
        process.exit(1);
      }
      sessionId = parsed;
    } else if (arg === '--from-start' || arg === '--history') {
      includeHistory = true;
    } else if (arg === '--list') {
      showList = true;
    } else if (arg === '--http') {
      httpOverride = expectValue(arg, i);
      i += 1;
    } else if (arg === '--ws') {
      wsOverride = expectValue(arg, i);
      i += 1;
    } else if (arg === '--local') {
      forceLocal = true;
    } else if (arg === '--debug') {
      debugFlag = true;
    } else if (arg === '-h' || arg === '--help') {
      usage();
      process.exit(0);
    } else if (/^\d+$/.test(arg) && positionalSessionId === null) {
      positionalSessionId = Number.parseInt(arg, 10);
    } else {
      console.error(`Unknown option: ${arg}`);
      usage();
      process.exit(1);
    }
  }

  if (!sessionProvided) {
    if (positionalSessionId !== null) {
      sessionId = positionalSessionId;
      sessionProvided = true;
    }
  }

  if (!sessionProvided) {
    sessionId = DEFAULT_SESSION_ID;
  }
  const allowDefaultSessionCreation = sessionId === DEFAULT_SESSION_ID;

  const DEBUG = debugFlag || process.env.DEBUG === '1';
  const logDebug = (...parts) => {
    if (DEBUG) {
      console.error('[rsh]', ...parts);
    }
  };

  let remoteListResult = null;
  if (showList && !forceLocal) {
    remoteListResult = await tryListRemote({
      httpOverride,
      wsOverride,
      logDebug
    });
  }

  if (showList) {
    if (remoteListResult) {
      const base = remoteListResult.httpBase ?? remoteListResult.listUrl;
      console.error(`[rsh] Remote endpoint: ${base}`);
      printSessionList(remoteListResult.sessions);
    } else {
      await listLocalSessions();
    }

    if (!sessionProvided || listCommand) {
      return;
    }
  }

  if (inspectCommand) {
    const inspectLocalOnly = forceLocal || inspectLocalCommand;
    if (inspectLocalOnly) {
      await inspectLocalSession(sessionId);
      return;
    }

    let remoteInspection = null;
    if (!inspectLocalOnly) {
      remoteInspection = await tryFetchRemoteInspection(sessionId, {
        httpOverride,
        logDebug
      });
    }

    if (remoteInspection) {
      printInspectionDetails(remoteInspection.inspection, {
        source: 'remote',
        endpoint: remoteInspection.inspectUrl
      });
      return;
    }

    console.error(
      `[rsh] Remote inspection unavailable for session ${sessionId}. ` +
        'Use "rsh inspect local <id>" for in-process sessions.'
    );
    process.exit(1);
  }

  if (!forceLocal) {
    let remoteContext = null;
    if (remoteListResult) {
      remoteContext = await sessionFromList(remoteListResult, sessionId, wsOverride, logDebug);
    }
    if (!remoteContext) {
      remoteContext = await tryFetchRemoteSession(sessionId, {
        httpOverride,
        wsOverride,
        logDebug
      });
    }

    if (!remoteContext && allowDefaultSessionCreation) {
      console.error('[rsh] Session 1 not found remotely. Creating new default session...');
      try {
        remoteContext = await tryCreateRemoteSession({
          httpOverride,
          wsOverride,
          logDebug
        });
      } catch (error) {
        console.error(`[rsh] ${error.message || error}`);
        process.exitCode = Number.isInteger(error?.exitCode) ? error.exitCode : 1;
        return;
      }
      if (remoteContext) {
        sessionId = remoteContext.session.id;
        if (sessionId !== DEFAULT_SESSION_ID) {
          console.error(
            `[rsh] Created remote session ${sessionId} (expected ${DEFAULT_SESSION_ID}). Attaching anyway.`
          );
        }
      }
    }

    if (remoteContext) {
      try {
        await attachRemote(sessionId, includeHistory, remoteContext, logDebug);
        return;
      } catch (err) {
        console.error(`[rsh] Remote attach failed: ${err.message || err}`);
      }
    }
  }

  await attachLocal(sessionId, includeHistory, logDebug, {
    allowCreateDefault: allowDefaultSessionCreation,
    defaultSessionId: DEFAULT_SESSION_ID
  });
})();

function buildHttpCandidates(httpOverride) {
  const configuredPort = process.env.PORT;
  const portCandidates = configuredPort
    ? [
        `http://localhost:${configuredPort}`,
        `http://127.0.0.1:${configuredPort}`
      ]
    : [];
  const candidates = [
    httpOverride,
    ...portCandidates,
    process.env.TERMINAL_HTTP_URL,
    process.env.TERMINAL_API_BASE,
    'http://127.0.0.1:4000',
    'http://localhost:4000',
    'http://127.0.0.1:3000',
    'http://localhost:3000'
  ].filter(Boolean);

  return Array.from(new Set(candidates));
}

function resolveCandidateBase(candidate) {
  try {
    const parsed = new URL(candidate);
    const trimmedPath = parsed.pathname.replace(/\/+$/, '');

    if (trimmedPath.endsWith('/api/terminals')) {
      const listUrl = new URL(parsed.toString());
      listUrl.pathname = trimmedPath;
      listUrl.search = '';
      listUrl.hash = '';
      const httpBase = deriveHttpBaseFromListUrl(listUrl.toString());
      return {
        listUrl: listUrl.toString(),
        httpBase
      };
    }

    const normalized = new URL(parsed.toString());
    if (!normalized.pathname.endsWith('/')) {
      normalized.pathname += '/';
    }
    const listUrl = new URL('api/terminals', normalized);
    listUrl.search = '';
    listUrl.hash = '';
    const httpBase = deriveHttpBaseFromListUrl(listUrl.toString());

    return {
      listUrl: listUrl.toString(),
      httpBase
    };
  } catch {
    return null;
  }
}

function deriveHttpBaseFromListUrl(listUrl) {
  const parsed = new URL(listUrl);
  let path = parsed.pathname;

  if (path.endsWith('/')) {
    path = path.slice(0, -1);
  }

  const suffix = '/api/terminals';
  if (path.endsWith(suffix)) {
    path = path.slice(0, -suffix.length);
  } else {
    const parts = path.split('/');
    parts.pop();
    path = parts.join('/');
  }

  if (!path) {
    parsed.pathname = '/';
  } else if (!path.endsWith('/')) {
    parsed.pathname = `${path}/`;
  } else {
    parsed.pathname = path;
  }

  parsed.search = '';
  parsed.hash = '';
  return parsed.toString();
}

function buildSessionUrlFromListUrl(listUrl, sessionId) {
  const parsed = new URL(listUrl);
  let path = parsed.pathname;

  if (!path.endsWith('/')) {
    path += '/';
  }

  parsed.pathname = `${path}${sessionId}`;
  parsed.search = '';
  parsed.hash = '';
  return parsed.toString();
}

function buildSessionInspectUrlFromListUrl(listUrl, sessionId) {
  const base = buildSessionUrlFromListUrl(listUrl, sessionId);
  try {
    const parsed = new URL(base);
    if (!parsed.pathname.endsWith('/inspect')) {
      parsed.pathname = `${parsed.pathname.replace(/\/+$/, '')}/inspect`;
    }
    return parsed.toString();
  } catch {
    return `${base.replace(/\/+$/, '')}/inspect`;
  }
}

async function tryListRemote(options) {
  const httpCandidates = buildHttpCandidates(options.httpOverride);
  const seen = new Set();

  for (const candidate of httpCandidates) {
    const baseInfo = resolveCandidateBase(candidate);
    if (!baseInfo) {
      continue;
    }
    if (seen.has(baseInfo.listUrl)) {
      continue;
    }
    seen.add(baseInfo.listUrl);

    options.logDebug('Trying remote list', baseInfo.listUrl);

    try {
      const res = await fetchWithTimeout(baseInfo.listUrl, DEFAULT_LIST_TIMEOUT_MS, {
        headers: { Accept: 'application/json' }
      });
      if (!res.ok) {
        options.logDebug('Remote list returned status', res.status, 'for', baseInfo.listUrl);
        continue;
      }

      const body = await safeJson(res);
      if (!body || !Array.isArray(body.sessions)) {
        options.logDebug('Remote list missing sessions array at', baseInfo.listUrl);
        continue;
      }

      const wsUrl = await resolveWsUrl({
        httpBase: baseInfo.httpBase,
        wsOverride: options.wsOverride,
        logDebug: options.logDebug
      });

      return {
        sessions: body.sessions,
        listUrl: baseInfo.listUrl,
        httpBase: baseInfo.httpBase,
        wsUrl
      };
    } catch (err) {
      options.logDebug('Remote list failed for', baseInfo.listUrl, err.message || err);
    }
  }

  return null;
}

async function sessionFromList(listResult, sessionId, wsOverride, logDebug) {
  if (!listResult.sessions || !listResult.sessions.length) {
    return null;
  }

  const match = listResult.sessions.find((sess) => Number(sess.id) === sessionId);
  let session = match;

  if (!session) {
    try {
      const url = buildSessionUrlFromListUrl(listResult.listUrl, sessionId);
      logDebug('Fetching session summary from list source', url);
      const res = await fetchWithTimeout(url, DEFAULT_SESSION_TIMEOUT_MS, {
        headers: { Accept: 'application/json' }
      });
      if (res.ok) {
        const body = await safeJson(res);
        if (body?.session) {
          session = body.session;
        }
      }
    } catch (err) {
      logDebug('Failed to resolve session via list source', err.message || err);
    }
  }

  if (!session) {
    return null;
  }

  let wsUrl = listResult.wsUrl;
  if (!wsUrl) {
    wsUrl = await resolveWsUrl({
      httpBase: listResult.httpBase,
      wsOverride,
      logDebug
    });
  }

  return {
    session,
    httpBase: listResult.httpBase,
    wsUrl
  };
}

async function tryFetchRemoteSession(sessionId, options) {
  const httpCandidates = buildHttpCandidates(options.httpOverride);
  const seen = new Set();

  for (const candidate of httpCandidates) {
    const baseInfo = resolveCandidateBase(candidate);
    if (!baseInfo) {
      continue;
    }

    const sessionUrl = buildSessionUrlFromListUrl(baseInfo.listUrl, sessionId);
    if (seen.has(sessionUrl)) {
      continue;
    }
    seen.add(sessionUrl);

    options.logDebug('Attempting remote session fetch', sessionUrl);

    try {
      const res = await fetchWithTimeout(sessionUrl, DEFAULT_SESSION_TIMEOUT_MS, {
        headers: { Accept: 'application/json' }
      });

      if (!res.ok) {
        options.logDebug('Remote session fetch status', res.status, 'for', sessionUrl);
        continue;
      }

      const body = await safeJson(res);
      if (!body?.session) {
        options.logDebug('Remote session response missing session payload at', sessionUrl);
        continue;
      }

      const wsUrl = await resolveWsUrl({
        httpBase: baseInfo.httpBase,
        wsOverride: options.wsOverride,
        logDebug: options.logDebug
      });

      return {
        session: body.session,
        httpBase: baseInfo.httpBase,
        wsUrl
      };
    } catch (err) {
      options.logDebug('Remote session fetch error for', sessionUrl, err.message || err);
    }
  }

  return null;
}

async function tryFetchRemoteInspection(sessionId, options) {
  const httpCandidates = buildHttpCandidates(options.httpOverride);
  const seen = new Set();

  for (const candidate of httpCandidates) {
    const baseInfo = resolveCandidateBase(candidate);
    if (!baseInfo) {
      continue;
    }

    const inspectUrl = buildSessionInspectUrlFromListUrl(baseInfo.listUrl, sessionId);
    if (seen.has(inspectUrl)) {
      continue;
    }
    seen.add(inspectUrl);

    options.logDebug('Attempting remote inspection fetch', inspectUrl);

    try {
      const res = await fetchWithTimeout(inspectUrl, DEFAULT_SESSION_TIMEOUT_MS, {
        headers: { Accept: 'application/json' }
      });

      if (!res.ok) {
        options.logDebug('Remote inspection fetch status', res.status, 'for', inspectUrl);
        continue;
      }

      const body = await safeJson(res);
      if (!body?.inspection) {
        options.logDebug('Remote inspection response missing inspection payload at', inspectUrl);
        continue;
      }

      return {
        inspection: body.inspection,
        inspectUrl,
        httpBase: baseInfo.httpBase
      };
    } catch (err) {
      options.logDebug('Remote inspection fetch error for', inspectUrl, err.message || err);
    }
  }

  return null;
}

async function tryCreateRemoteSession(options) {
  const httpCandidates = buildHttpCandidates(options.httpOverride);
  const seen = new Set();

  for (const candidate of httpCandidates) {
    const baseInfo = resolveCandidateBase(candidate);
    if (!baseInfo) {
      continue;
    }
    if (seen.has(baseInfo.listUrl)) {
      continue;
    }
    seen.add(baseInfo.listUrl);

    options.logDebug('Attempting remote session creation via', baseInfo.listUrl);
    let spawnOtpAttempted = false;

    try {
      let attempt = await postRemoteSession(baseInfo.listUrl);

      if (!attempt.response.ok && getSpawnOtpErrorCode(attempt.body) === 'spawn_terminal_otp_required') {
        let otp = await promptSpawnOtp();
        spawnOtpAttempted = true;
        try {
          attempt = await postRemoteSession(baseInfo.listUrl, otp);
        } finally {
          otp = '';
        }
      }

      if (!attempt.response.ok) {
        if (spawnOtpAttempted) {
          const message = attempt.body?.error?.message || 'Terminal creation rejected the spawn OTP.';
          throw createSpawnOtpPromptError(message);
        }
        options.logDebug(
          'Remote session create status',
          attempt.response.status,
          'for',
          baseInfo.listUrl
        );
        continue;
      }

      const body = attempt.body;
      if (!body?.session) {
        options.logDebug('Remote session create response missing session payload at', baseInfo.listUrl);
        continue;
      }

      const wsUrl = await resolveWsUrl({
        httpBase: baseInfo.httpBase,
        wsOverride: options.wsOverride,
        logDebug: options.logDebug
      });

      return {
        session: body.session,
        httpBase: baseInfo.httpBase,
        wsUrl
      };
    } catch (err) {
      if (isSpawnOtpPromptError(err)) {
        throw err;
      }
      if (spawnOtpAttempted) {
        throw createSpawnOtpPromptError('Terminal creation failed after the spawn OTP was submitted.');
      }
      options.logDebug('Remote session create error for', baseInfo.listUrl, err.message || err);
    }
  }

  return null;
}

async function postRemoteSession(url, otp = '') {
  const value = typeof otp === 'string' ? otp.trim() : '';
  const response = await fetchWithTimeout(url, DEFAULT_SESSION_TIMEOUT_MS, {
    method: 'POST',
    headers: {
      Accept: 'application/json',
      'Content-Type': 'application/json'
    },
    body: JSON.stringify(value ? { otp: value } : {})
  });
  return {
    response,
    body: await safeJson(response)
  };
}

function getSpawnOtpErrorCode(body) {
  return typeof body?.error?.code === 'string' ? body.error.code : '';
}

async function resolveWsUrl({ httpBase, wsOverride, logDebug }) {
  const candidates = [
    wsOverride,
    process.env.TERMINAL_WS_URL
  ];

  const discoveryUrl = buildApiUrl(httpBase, 'api/ws');
  const discovered = await discoverWsUrl(discoveryUrl, logDebug);
  if (discovered) {
    candidates.push(discovered);
  }

  candidates.push(deriveWsFromHttp(httpBase));

  for (const candidate of candidates) {
    if (!candidate) {
      continue;
    }
    try {
      const url = new URL(candidate);
      return url.toString();
    } catch (err) {
      logDebug('Invalid WebSocket candidate', candidate, err.message || err);
    }
  }

  return null;
}

async function discoverWsUrl(url, logDebug) {
  try {
    const res = await fetchWithTimeout(url, DEFAULT_LIST_TIMEOUT_MS, {
      headers: { Accept: 'application/json' }
    });

    if (!res.ok) {
      logDebug('WS discovery status', res.status, 'for', url);
      return null;
    }

    const body = await safeJson(res);
    if (!body) {
      return null;
    }

    if (typeof body.url === 'string' && body.url.length) {
      return body.url;
    }

    if (body.host && body.path) {
      const protocol = url.startsWith('https:') ? 'wss:' : 'ws:';
      const port = body.port ? `:${body.port}` : '';
      const path = body.path.startsWith('/') ? body.path : `/${body.path}`;
      return `${protocol}//${body.host}${port}${path}`;
    }
  } catch (err) {
    logDebug('WS discovery failed for', url, err.message || err);
  }

  return null;
}

function deriveWsFromHttp(httpBase) {
  try {
    const parsed = new URL(httpBase);
    const protocol = parsed.protocol === 'https:' ? 'wss:' : 'ws:';
    const host = parsed.hostname;
    const port = process.env.PORT || parsed.port;
    const normalizedPath = '/ws/terminals';
    const portSegment = port ? `:${port}` : '';
    return `${protocol}//${host}${portSegment}${normalizedPath}`;
  } catch {
    return null;
  }
}

function buildApiUrl(httpBase, suffix) {
  try {
    const parsed = new URL(httpBase);
    let path = parsed.pathname;
    if (!path.endsWith('/')) {
      path += '/';
    }
    parsed.pathname = `${path}${suffix.replace(/^\//, '')}`;
    parsed.search = '';
    parsed.hash = '';
    return parsed.toString();
  } catch {
    return httpBase;
  }
}

async function fetchWithTimeout(url, timeoutMs, init = {}) {
  const controller = new AbortController();
  const timer = timeoutMs ? setTimeout(() => controller.abort(), timeoutMs) : null;
  try {
    return await fetch(url, { ...init, signal: controller.signal });
  } finally {
    if (timer) {
      clearTimeout(timer);
    }
  }
}

async function safeJson(res) {
  try {
    return await res.json();
  } catch {
    return null;
  }
}

function createSpawnOtpPromptError(message, exitCode = 1) {
  const error = new Error(message);
  error.code = 'rsh_spawn_otp_prompt_error';
  error.exitCode = exitCode;
  return error;
}

function isSpawnOtpPromptError(error) {
  return error?.code === 'rsh_spawn_otp_prompt_error';
}

function requireSpawnOtp(value) {
  const otp = typeof value === 'string' ? value.trim() : '';
  if (!otp) {
    throw createSpawnOtpPromptError('A non-empty spawn OTP is required.');
  }
  return otp;
}

async function promptSpawnOtp() {
  const input = process.stdin;
  const output = process.stderr;
  const prompt = '[rsh] Spawn OTP: ';

  if (input.isTTY && typeof input.setRawMode !== 'function') {
    throw createSpawnOtpPromptError('This terminal cannot securely read a hidden spawn OTP.');
  }

  if (!input.isTTY) {
    const { createInterface } = await import('node:readline/promises');
    const reader = createInterface({ input, output, terminal: false });
    try {
      return requireSpawnOtp(await reader.question(prompt));
    } catch (error) {
      if (isSpawnOtpPromptError(error)) {
        throw error;
      }
      throw createSpawnOtpPromptError('Unable to read a spawn OTP from stdin.');
    } finally {
      reader.close();
    }
  }

  const wasRaw = Boolean(input.isRaw);
  const wasPaused = input.isPaused();
  output.write(prompt);

  return new Promise((resolve, reject) => {
    let value = '';
    let settled = false;

    const cleanup = () => {
      input.off('data', onData);
      if (!wasRaw) {
        try {
          input.setRawMode(false);
        } catch {
          // Best-effort restoration after an input failure.
        }
      }
      if (wasPaused) {
        input.pause();
      }
    };

    const finish = (error = null) => {
      if (settled) {
        return;
      }
      settled = true;
      cleanup();
      output.write('\n');
      if (error) {
        reject(error);
        return;
      }
      try {
        resolve(requireSpawnOtp(value));
      } catch (validationError) {
        reject(validationError);
      }
    };

    const onData = (chunk) => {
      for (const character of String(chunk)) {
        if (character === '\r' || character === '\n') {
          finish();
          return;
        }
        if (character === '\u0003') {
          finish(createSpawnOtpPromptError('Spawn OTP entry cancelled.', 130));
          return;
        }
        if (character === '\u007f' || character === '\b') {
          value = Array.from(value).slice(0, -1).join('');
          continue;
        }
        if (character >= ' ' && character !== '\u007f') {
          value += character;
        }
      }
    };

    try {
      input.setRawMode(true);
      input.resume();
      input.on('data', onData);
    } catch {
      finish(createSpawnOtpPromptError('Unable to read a spawn OTP from the terminal.'));
    }
  });
}

function printSessionList(sessions) {
  if (!sessions || sessions.length === 0) {
    console.error('No active sessions.');
    return;
  }

  for (const sess of sessions) {
    const cols = sess.cols ?? '?';
    const rows = sess.rows ?? '?';
    console.error(
      `Session ${sess.id}: shell=${sess.shell ?? '?'} cwd=${sess.cwd ?? '?'} ` +
        `size=${cols}x${rows} alive=${sess.alive ?? '?'}`
    );
  }
}

async function listLocalSessions() {
  try {
    const module = await import('./lib/terminalManager.js');
    const sessions = module.listTerminals();
    printSessionList(sessions);
    return sessions;
  } catch (err) {
    console.error(`[rsh] Failed to load terminal manager: ${err.message || err}`);
    return [];
  }
}

async function inspectLocalSession(sessionId) {
  try {
    const module = await import('./lib/terminalManager.js');
    if (typeof module.inspectTerminal !== 'function') {
      throw new Error('Local inspection not supported by terminal manager');
    }
    const inspection = module.inspectTerminal(sessionId);
    printInspectionDetails(inspection, { source: 'local' });
    return inspection;
  } catch (err) {
    console.error(`[rsh] Local inspection failed: ${err.message || err}`);
    process.exit(1);
  }
}

function printInspectionDetails(inspection, context = {}) {
  if (!inspection) {
    console.error('[rsh] No inspection data available.');
    return;
  }
  const percent = formatPercent(inspection.bufferBytesUsed, inspection.maxBufferBytes);
  const usage = `${formatBytes(inspection.bufferBytesUsed)} / ${formatBytes(inspection.maxBufferBytes)} (${percent})`;
  const prefix = context.source === 'remote'
    ? '[rsh] Remote inspection'
    : '[rsh] Local inspection';
  const endpointNote = context.endpoint ? ` via ${context.endpoint}` : '';
  console.error(
    `${prefix}${endpointNote}: session ${inspection.id} terminal=${inspection.terminalType ?? '?'} buffer=${usage}`
  );
  if (inspection.shell || inspection.cwd) {
    console.error(`  shell=${inspection.shell ?? '?'} cwd=${inspection.cwd ?? '?'}`);
  }
}

function formatBytes(value) {
  if (!Number.isFinite(value)) {
    return 'n/a';
  }
  const units = ['B', 'KB', 'MB', 'GB', 'TB'];
  let index = 0;
  let current = value;
  while (current >= 1024 && index < units.length - 1) {
    current /= 1024;
    index += 1;
  }
  const precision = index === 0 ? 0 : current < 10 ? 1 : 0;
  return `${current.toFixed(precision)} ${units[index]}`;
}

function formatPercent(value, total) {
  if (!Number.isFinite(value) || !Number.isFinite(total) || total <= 0) {
    return 'n/a';
  }
  const pct = Math.min(100, (value / total) * 100);
  return `${pct.toFixed(pct < 10 ? 2 : 1)}%`;
}

async function attachLocal(sessionId, includeHistory, logDebug, options = {}) {
  const allowCreateDefault = options.allowCreateDefault ?? false;
  const defaultSessionId = options.defaultSessionId ?? DEFAULT_SESSION_ID;
  let module;
  try {
    module = await import('./lib/terminalManager.js');
  } catch (err) {
    console.error(`[rsh] Failed to load terminal manager: ${err.message || err}`);
    process.exit(1);
  }

  const {
    listTerminals,
    getTerminalSummary,
    createTerminalReader,
    subscribeToTerminal,
    onTerminalExit,
    writeToTerminal,
    spawnTerminal
  } = module;

  logDebug('Available local sessions:', listTerminals().map((sess) => sess.id));

  let targetSessionId = sessionId;
  let session;
  try {
    session = getTerminalSummary(targetSessionId);
  } catch (err) {
    if (allowCreateDefault && targetSessionId === defaultSessionId) {
      console.error(
        `[rsh] Session ${defaultSessionId} not found locally. Creating new default session...`
      );
      try {
        try {
          session = spawnTerminal({});
        } catch (spawnError) {
          if (spawnError?.code !== 'spawn_terminal_otp_required') {
            throw spawnError;
          }
          let otp = await promptSpawnOtp();
          try {
            session = spawnTerminal({ otp });
          } finally {
            otp = '';
          }
        }
        targetSessionId = session.id;
        if (targetSessionId !== defaultSessionId) {
          console.error(
            `[rsh] Created local session ${targetSessionId} (expected ${defaultSessionId}). Attaching anyway.`
          );
        }
      } catch (spawnErr) {
        console.error(`[rsh] Failed to create default session: ${spawnErr.message || spawnErr}`);
        process.exit(1);
      }
    } else {
      console.error(err.message || 'Failed to load session');
      process.exit(1);
    }
  }

  console.error(
    `[rsh] Connecting to session ${session.id} (${session.shell}) in ${session.cwd}.` +
      (includeHistory ? ' Replaying history...' : '')
  );

  const reader = createTerminalReader(targetSessionId, { includeHistory });

  const flush = () => {
    const data = reader.read();
    if (data) {
      process.stdout.write(data);
    }
  };

  let cleanedUp = false;

  let handleInput;
  let sigintHandler;
  let sigtermHandler;

  const cleanup = (code = 0) => {
    if (cleanedUp) {
      return;
    }
    cleanedUp = true;
    try {
      flush();
    } catch {
      // ignore
    }
    if (typeof unsubData === 'function') {
      unsubData();
    }
    if (typeof unsubExit === 'function') {
      unsubExit();
    }
    reader.dispose();
    if (process.stdin.isTTY) {
      try {
        process.stdin.setRawMode(false);
      } catch {
        // ignore
      }
    }
    if (typeof handleInput === 'function') {
      process.stdin.off('data', handleInput);
    }
    process.stdin.pause();
    if (sigintHandler) {
      process.removeListener('SIGINT', sigintHandler);
    }
    if (sigtermHandler) {
      process.removeListener('SIGTERM', sigtermHandler);
    }
    process.exit(code);
  };

  const unsubData = subscribeToTerminal(targetSessionId, () => {
    flush();
  });

  const unsubExit = onTerminalExit(targetSessionId, (info) => {
    flush();
    const parts = [];
    if (typeof info.exitCode === 'number') {
      parts.push(`code ${info.exitCode}`);
    }
    if (info.signal) {
      parts.push(`signal ${info.signal}`);
    }
    console.error(
      `[rsh] Session ${targetSessionId} exited${parts.length ? ` (${parts.join(', ')})` : ''}.`
    );
    cleanup(0);
  });

  handleInput = (chunk) => {
    if (chunk.length === 1 && chunk[0] === 0x1d) {
      console.error('\n[rsh] Detaching.');
      cleanup(0);
      return;
    }
    try {
      writeToTerminal(targetSessionId, chunk.toString('utf8'), { actor: 'human' });
    } catch (err) {
      console.error(`\n[rsh] Failed to write to terminal: ${err.message}`);
      cleanup(1);
    }
  };

  if (process.stdin.isTTY) {
    try {
      process.stdin.setRawMode(true);
    } catch (err) {
      console.error(`[rsh] Failed to enable raw mode: ${err.message}`);
    }
  }

  process.stdin.resume();
  process.stdin.on('data', handleInput);

  flush();

  sigintHandler = () => {
    try {
      writeToTerminal(targetSessionId, '\u0003', { actor: 'human' });
    } catch {
      cleanup(0);
    }
  };

  sigtermHandler = () => {
    console.error('\n[rsh] Received SIGTERM, detaching.');
    cleanup(0);
  };

  process.on('SIGINT', sigintHandler);
  process.on('SIGTERM', sigtermHandler);
}

async function attachRemote(sessionId, includeHistory, context, logDebug) {
  if (!context.session) {
    throw new Error('Missing remote session summary');
  }
  if (!context.wsUrl) {
    throw new Error('Unable to determine WebSocket endpoint for remote terminal');
  }

  console.error(
    `[rsh] Connecting to remote session ${context.session.id} (${context.session.shell}) ` +
      `via ${context.httpBase || 'remote service'}.` +
      (includeHistory ? ' Replaying server-sent history...' : '')
  );

  const wsModule = await import('ws');
  const WebSocketCtor = wsModule.WebSocket || wsModule.default;
  if (!WebSocketCtor) {
    throw new Error('ws module does not export a WebSocket constructor');
  }

  const wsUrl = appendSessionId(context.wsUrl, sessionId);
  logDebug('Connecting WebSocket', wsUrl);

  const ws = new WebSocketCtor(wsUrl);
  let cleanedUp = false;
  let socketOpen = false;
  let suppressHistory = !includeHistory;

  let handleInput;
  let sigintHandler;
  let sigtermHandler;

  const cleanup = (code = 0) => {
    if (cleanedUp) {
      return;
    }
    cleanedUp = true;

    try {
      ws.removeAllListeners();
      if (ws.readyState === WebSocketCtor.OPEN || ws.readyState === WebSocketCtor.CONNECTING) {
        ws.close(1000, 'client detach');
      }
    } catch {
      // ignore close errors
    }

    if (process.stdin.isTTY) {
      try {
        process.stdin.setRawMode(false);
      } catch {
        // ignore
      }
    }

    if (handleInput) {
      process.stdin.off('data', handleInput);
    }
    process.stdin.pause();

    if (sigintHandler) {
      process.removeListener('SIGINT', sigintHandler);
    }
    if (sigtermHandler) {
      process.removeListener('SIGTERM', sigtermHandler);
    }

    process.exit(code);
  };

  ws.on('open', () => {
    socketOpen = true;
  });

  ws.on('message', (raw) => {
    let message;
    try {
      message = JSON.parse(raw.toString());
    } catch (err) {
      console.error('[rsh] Failed to parse message:', err.message);
      return;
    }

    if (!message || typeof message !== 'object') {
      return;
    }

    if (message.type === 'session' && message.session) {
      context.session = message.session;
      return;
    }

    if (message.type === 'output') {
      if (typeof message.data === 'string') {
        if (suppressHistory) {
          suppressHistory = false;
          return;
        }
        process.stdout.write(message.data);
      }
      return;
    }

    if (message.type === 'exit') {
      const parts = [];
      if (typeof message.info?.exitCode === 'number') {
        parts.push(`code ${message.info.exitCode}`);
      }
      if (message.info?.signal) {
        parts.push(`signal ${message.info.signal}`);
      }
      console.error(
        `[rsh] Remote session ${sessionId} exited${parts.length ? ` (${parts.join(', ')})` : ''}.`
      );
      cleanup(0);
      return;
    }

    if (message.type === 'error' && message.error) {
      console.error(`[rsh] Remote error: ${message.error}`);
      return;
    }
  });

  ws.on('close', (code, reason) => {
    if (!cleanedUp) {
      const text = reason ? reason.toString() : '';
      console.error(
        `[rsh] Remote connection closed (${code}${
          text ? `: ${text}` : ''
        }).`
      );
      cleanup(code === 1000 ? 0 : 1);
    }
  });

  ws.on('error', (err) => {
    if (!cleanedUp) {
      console.error(`[rsh] WebSocket error: ${err.message || err}`);
      cleanup(1);
    }
  });

  handleInput = (chunk) => {
    if (chunk.length === 1 && chunk[0] === 0x1d) {
      console.error('\n[rsh] Detaching.');
      cleanup(0);
      return;
    }

    if (!socketOpen) {
      return;
    }

    try {
      ws.send(
        JSON.stringify({
          type: 'input',
          data: chunk.toString('utf8')
        })
      );
    } catch (err) {
      console.error(`\n[rsh] Failed to send remote input: ${err.message}`);
      cleanup(1);
    }
  };

  if (process.stdin.isTTY) {
    try {
      process.stdin.setRawMode(true);
    } catch (err) {
      console.error(`[rsh] Failed to enable raw mode: ${err.message}`);
    }
  }

  process.stdin.resume();
  process.stdin.on('data', handleInput);

  sigintHandler = () => {
    if (!socketOpen) {
      return;
    }
    try {
      ws.send(JSON.stringify({ type: 'input', data: '\u0003' }));
    } catch {
      cleanup(0);
    }
  };

  sigtermHandler = () => {
    console.error('\n[rsh] Received SIGTERM, detaching.');
    cleanup(0);
  };

  process.on('SIGINT', sigintHandler);
  process.on('SIGTERM', sigtermHandler);
}

function appendSessionId(baseWsUrl, sessionId) {
  const url = new URL(baseWsUrl);
  url.searchParams.set('id', String(sessionId));
  return url.toString();
}
