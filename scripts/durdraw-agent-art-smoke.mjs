#!/usr/bin/env node

import { spawn } from 'node:child_process';
import { createHash, randomBytes } from 'node:crypto';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StreamableHTTPClientTransport } from '@modelcontextprotocol/sdk/client/streamableHttp.js';
import {
  access,
  chmod,
  copyFile,
  mkdir,
  mkdtemp,
  readFile,
  readdir,
  rm,
  writeFile
} from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import process from 'node:process';
import { fileURLToPath } from 'node:url';

const SCRIPT_DIR = path.dirname(fileURLToPath(import.meta.url));
const APP_ROOT = path.resolve(SCRIPT_DIR, '..');
const DEFAULT_NOTTY_MCP_URL = 'http://127.0.0.1:3000/mcp';
const DEFAULT_COLLAB_MCP_URL = 'http://127.0.0.1:1337/mcp';
const DEFAULT_TIMEOUT_MS = 15 * 60_000;
const DEFAULT_OTP_TTL_SECONDS = 5 * 60;
const HTTP_TIMEOUT_MS = 15_000;
const POLL_INTERVAL_MS = 200;
const AUTH_ENV_NAME = 'NOTTY_ART_AUTHORIZATION';
const CHILD_SECRET_ENV_KEYS = [
  'SPAWN_OTP',
  'MCP_SPAWN_OTP',
  'NOTTY_MCP_SPAWN_OTP',
  'COLLAB_AGENT_SPAWN_OTP',
  'NOTTY_MCP_AUTHORIZATION',
  'NOTTY_MCP_BEARER_TOKEN',
  'NOTTY_BASIC_AUTH_USERNAME',
  'NOTTY_BASIC_AUTH_PASSWORD'
];
const AGENT_IDS = ['artist-a', 'artist-b'];
const REQUIRED_DURDRAW_TOOLS = [
  'spawn_durdraw',
  'durdraw_action',
  'durdraw_text',
  'read_terminal'
];
const log = (...parts) => process.stderr.write(`[durdraw-agent-art] ${parts.join(' ')}\n`);

function usage() {
  process.stdout.write(`
Usage: node scripts/durdraw-agent-art-smoke.mjs [options]

Launch two Codex artists against Notty's Durdraw MCP toolset, give each one
single-use OTP-backed terminal, and test a contended collaboration handoff.

Options:
  --notty-url URL       Notty Streamable HTTP MCP URL
                        (default: ${DEFAULT_NOTTY_MCP_URL})
  --collab-url URL      Collab Streamable HTTP MCP URL
                        (default: ${DEFAULT_COLLAB_MCP_URL})
  --codex-bin PATH      Codex executable (default: codex)
  --model MODEL         Codex model for both artists
  --think LEVEL         minimal, low, medium, high, or xhigh (default: medium)
  --sandbox MODE        Codex shell sandbox: workspace-write or danger-full-access
                        (default: workspace-write)
  --timeout-ms N        Per-agent and barrier timeout (default: ${DEFAULT_TIMEOUT_MS})
  --otp-ttl-seconds N   Lifetime of each spawn OTP (default: ${DEFAULT_OTP_TTL_SECONDS})
  --output-dir PATH     Create the art workspace at PATH instead of
                        <repo>/.notty-art-runs/run-*
  -h, --help            Show this help

Authentication is read only from the environment. Use either:
  NOTTY_MCP_AUTHORIZATION='Basic ...' (or 'Bearer ...')
  NOTTY_MCP_BEARER_TOKEN=...
  NOTTY_BASIC_AUTH_USERNAME=... and NOTTY_BASIC_AUTH_PASSWORD=...

The script never passes an OTP to an artist. It consumes each OTP once while
pre-spawning that artist's assigned Durdraw terminal.
`.trimStart());
}

function positiveInteger(value, label) {
  const raw = String(value);
  if (!/^[1-9][0-9]*$/.test(raw)) {
    throw new Error(`${label} must be a positive integer`);
  }
  const parsed = Number(raw);
  if (!Number.isSafeInteger(parsed) || parsed <= 0) {
    throw new Error(`${label} must be a positive integer`);
  }
  return parsed;
}

function parseArgs(argv = process.argv.slice(2)) {
  const options = {
    nottyUrl: process.env.NOTTY_MCP_URL || DEFAULT_NOTTY_MCP_URL,
    collabUrl: process.env.COLLAB_MCP_URL || DEFAULT_COLLAB_MCP_URL,
    codexBin: process.env.DURDRAW_AGENT_CODEX_BIN || 'codex',
    model: process.env.DURDRAW_AGENT_MODEL || '',
    think: process.env.DURDRAW_AGENT_THINK || 'medium',
    sandbox: process.env.DURDRAW_AGENT_SANDBOX || 'workspace-write',
    timeoutMs: positiveInteger(
      process.env.DURDRAW_AGENT_TIMEOUT_MS || DEFAULT_TIMEOUT_MS,
      'DURDRAW_AGENT_TIMEOUT_MS'
    ),
    otpTtlSeconds: positiveInteger(
      process.env.DURDRAW_AGENT_OTP_TTL_SECONDS || DEFAULT_OTP_TTL_SECONDS,
      'DURDRAW_AGENT_OTP_TTL_SECONDS'
    ),
    outputDir: '',
    help: false
  };

  const takeValue = (index, option) => {
    const value = argv[index + 1];
    if (!value || value.startsWith('--')) {
      throw new Error(`${option} requires a value`);
    }
    return value;
  };

  for (let index = 0; index < argv.length; index += 1) {
    const argument = argv[index];
    switch (argument) {
      case '-h':
      case '--help':
        options.help = true;
        break;
      case '--notty-url':
        options.nottyUrl = takeValue(index, argument);
        index += 1;
        break;
      case '--collab-url':
        options.collabUrl = takeValue(index, argument);
        index += 1;
        break;
      case '--codex-bin':
        options.codexBin = takeValue(index, argument);
        index += 1;
        break;
      case '--model':
        options.model = takeValue(index, argument);
        index += 1;
        break;
      case '--think':
        options.think = takeValue(index, argument).toLowerCase();
        index += 1;
        break;
      case '--sandbox':
        options.sandbox = takeValue(index, argument).toLowerCase();
        index += 1;
        break;
      case '--timeout-ms':
        options.timeoutMs = positiveInteger(takeValue(index, argument), argument);
        index += 1;
        break;
      case '--otp-ttl-seconds':
        options.otpTtlSeconds = positiveInteger(takeValue(index, argument), argument);
        index += 1;
        break;
      case '--output-dir':
        options.outputDir = path.resolve(takeValue(index, argument));
        index += 1;
        break;
      default:
        throw new Error(`unknown option: ${argument}`);
    }
  }

  if (!['minimal', 'low', 'medium', 'high', 'xhigh'].includes(options.think)) {
    throw new Error('--think must be one of: minimal, low, medium, high, xhigh');
  }
  if (!['workspace-write', 'danger-full-access'].includes(options.sandbox)) {
    throw new Error('--sandbox must be workspace-write or danger-full-access');
  }
  options.nottyUrl = normalizeMcpUrl(options.nottyUrl, '--notty-url');
  options.collabUrl = normalizeMcpUrl(options.collabUrl, '--collab-url');
  return options;
}

function normalizeMcpUrl(value, label) {
  let parsed;
  try {
    parsed = new URL(value);
  } catch {
    throw new Error(`${label} must be a valid URL`);
  }
  if (!['http:', 'https:'].includes(parsed.protocol)) {
    throw new Error(`${label} must use http or https`);
  }
  if (parsed.username || parsed.password) {
    throw new Error(`${label} must not contain credentials; use authentication environment variables`);
  }
  if (parsed.search) {
    throw new Error(`${label} must not contain query credentials or parameters`);
  }
  parsed.hash = '';
  parsed.pathname = parsed.pathname.replace(/\/+$/, '');
  if (!parsed.pathname.endsWith('/mcp')) {
    throw new Error(`${label} must end in /mcp`);
  }
  return parsed.toString().replace(/\/$/, '');
}

function siblingUrl(mcpUrl, suffix) {
  const parsed = new URL(mcpUrl);
  parsed.pathname = `${parsed.pathname.replace(/\/mcp$/, '')}${suffix}`;
  parsed.search = '';
  parsed.hash = '';
  return parsed.toString();
}

function mcpRouteUrl(mcpUrl, suffix) {
  const parsed = new URL(mcpUrl);
  parsed.pathname = `${parsed.pathname}${suffix}`;
  parsed.search = '';
  parsed.hash = '';
  return parsed.toString();
}

function resolveNottyAuth(environment = process.env) {
  const raw = String(environment.NOTTY_MCP_AUTHORIZATION || '').trim();
  const bearer = String(environment.NOTTY_MCP_BEARER_TOKEN || '').trim();
  const basicPassword = String(environment.NOTTY_BASIC_AUTH_PASSWORD || '');
  const basicUsername = String(environment.NOTTY_BASIC_AUTH_USERNAME || 'notty');
  const modes = [
    raw ? 'NOTTY_MCP_AUTHORIZATION' : '',
    bearer ? 'NOTTY_MCP_BEARER_TOKEN' : '',
    basicPassword ? 'NOTTY_BASIC_AUTH_PASSWORD' : ''
  ].filter(Boolean);

  if (modes.length > 1) {
    throw new Error(
      `configure only one Notty Authorization mode; found ${modes.join(', ')}`
    );
  }
  if (raw && !/^(Basic|Bearer)\s+\S+$/i.test(raw)) {
    throw new Error('NOTTY_MCP_AUTHORIZATION must be a Basic or Bearer Authorization value');
  }
  if (raw) {
    return { header: raw, secrets: [raw] };
  }
  if (bearer) {
    return { header: `Bearer ${bearer}`, secrets: [bearer, `Bearer ${bearer}`] };
  }
  if (basicPassword) {
    const encoded = Buffer.from(`${basicUsername}:${basicPassword}`).toString('base64');
    return {
      header: `Basic ${encoded}`,
      secrets: [basicPassword, encoded, `Basic ${encoded}`]
    };
  }
  return { header: '', secrets: [] };
}

function authHeaders(auth) {
  return auth.header ? { Authorization: auth.header } : {};
}

function scrubbedCodexEnvironment(environment = process.env) {
  const output = { ...environment };
  for (const key of CHILD_SECRET_ENV_KEYS) {
    delete output[key];
  }
  return output;
}

function redact(value, secrets) {
  let output = String(value || '');
  for (const secret of secrets.filter(Boolean).sort((a, b) => b.length - a.length)) {
    output = output.split(secret).join('[REDACTED]');
  }
  return output;
}

async function withTimeout(promise, timeoutMs, label) {
  let timer;
  try {
    return await Promise.race([
      promise,
      new Promise((_, reject) => {
        timer = setTimeout(() => reject(new Error(`${label} timed out`)), timeoutMs);
        timer.unref?.();
      })
    ]);
  } finally {
    clearTimeout(timer);
  }
}

async function listMcpToolNames(url, authorization, label) {
  let client;
  let transport;
  try {
    transport = new StreamableHTTPClientTransport(new URL(url), {
      requestInit: authorization
        ? { headers: { Authorization: authorization } }
        : undefined
    });
    client = new Client(
      { name: 'notty-durdraw-agent-preflight', version: '1.0.0' },
      { capabilities: { tools: {} } }
    );
    await withTimeout(client.connect(transport), HTTP_TIMEOUT_MS, `${label} connection`);
    const response = await withTimeout(client.listTools(), HTTP_TIMEOUT_MS, `${label} listTools`);
    return new Set(
      (Array.isArray(response?.tools) ? response.tools : []).map((tool) => tool?.name)
    );
  } catch (error) {
    throw new Error(`${label} Streamable HTTP MCP failed: ${error.message}`);
  } finally {
    await Promise.allSettled([
      typeof client?.close === 'function' ? client.close() : Promise.resolve(),
      typeof transport?.close === 'function' ? transport.close() : Promise.resolve()
    ]);
  }
}

async function requestJson(url, options = {}) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), options.timeoutMs || HTTP_TIMEOUT_MS);
  timer.unref?.();
  let response;
  try {
    response = await fetch(url, {
      method: options.method || 'GET',
      headers: {
        Accept: 'application/json',
        ...(options.body === undefined ? {} : { 'Content-Type': 'application/json' }),
        ...(options.headers || {})
      },
      body: options.body === undefined ? undefined : JSON.stringify(options.body),
      signal: controller.signal
    });
  } catch (error) {
    if (error?.name === 'AbortError') {
      throw new Error(`${options.label || url} timed out`);
    }
    throw new Error(`${options.label || url} is unreachable: ${error.message}`);
  } finally {
    clearTimeout(timer);
  }

  const text = await response.text();
  let payload = null;
  if (text) {
    try {
      payload = JSON.parse(text);
    } catch {
      payload = { text };
    }
  }
  const expected = options.expectedStatuses || [200];
  if (!expected.includes(response.status)) {
    const detail = payload?.error?.message
      || payload?.error
      || payload?.text
      || response.statusText;
    throw new Error(
      `${options.label || url} returned HTTP ${response.status}: ${String(detail).slice(0, 500)}`
    );
  }
  return { status: response.status, payload };
}

function parseMcpText(result, toolName) {
  const text = result?.content?.find((entry) => entry?.type === 'text')?.text;
  if (typeof text !== 'string') {
    throw new Error(`${toolName} returned no text content`);
  }
  try {
    return JSON.parse(text);
  } catch {
    throw new Error(`${toolName} returned invalid JSON content`);
  }
}

async function preflightNotty(options, auth) {
  const names = await listMcpToolNames(
    options.nottyUrl,
    auth.header,
    'Notty Durdraw'
  );
  const missing = REQUIRED_DURDRAW_TOOLS.filter((name) => !names.has(name));
  if (missing.length > 0) {
    throw new Error(
      `Notty is not running the Durdraw MCP toolset (missing: ${missing.join(', ')}). ` +
      'Start Nosh with: ./scripts/nosh.sh start -p durdraw'
    );
  }
  log(`Notty MCP ready (${REQUIRED_DURDRAW_TOOLS.join(', ')})`);
}

async function preflightCollab(options) {
  const names = await listMcpToolNames(options.collabUrl, '', 'Collab');
  const missing = ['set_nickname', 'set_status', 'send_message']
    .filter((name) => !names.has(name));
  if (missing.length > 0) {
    throw new Error(`Collab MCP is missing required tools: ${missing.join(', ')}`);
  }
  const { payload } = await requestJson(siblingUrl(options.collabUrl, '/admin/v1/bootstrap'), {
    label: 'Collab admin preflight'
  });
  if (payload?.service?.status !== 'ready') {
    throw new Error('Collab admin API did not report service.status=ready');
  }
  log(`Collab MCP ready (${options.collabUrl})`);
}

async function issueOtp(options, auth, requestedValue) {
  const { payload } = await requestJson(siblingUrl(options.nottyUrl, '/api/spawn-otps'), {
    method: 'POST',
    headers: authHeaders(auth),
    body: { value: requestedValue, ttlSeconds: options.otpTtlSeconds },
    expectedStatuses: [201],
    label: 'Notty OTP issuance'
  });
  const otp = payload?.otp;
  if (
    !otp
    || typeof otp.value !== 'string'
    || !otp.value
    || typeof otp.uuid !== 'string'
    || !otp.uuid
    || otp.value !== requestedValue
  ) {
    throw new Error('Notty OTP issuance returned an invalid OTP record');
  }
  return { value: otp.value, uuid: otp.uuid };
}

async function callNottyTool(options, auth, name, args) {
  const { payload } = await requestJson(mcpRouteUrl(options.nottyUrl, '/call'), {
    method: 'POST',
    headers: authHeaders(auth),
    body: { name, arguments: args },
    label: `Notty ${name}`
  });
  return parseMcpText(payload, name);
}

async function spawnAssignedTerminal(options, auth, otp, workspace) {
  const result = await callNottyTool(options, auth, 'spawn_durdraw', {
    otp: otp.value,
    cwd: workspace,
    cols: 80,
    rows: 30,
    width: 80,
    height: 25,
    colorMode: '16',
    blackBg: true,
    noMouse: true,
    cursor: 'pipe',
    cp437: true
  });
  if (
    typeof result.terminal_uuid !== 'string'
    || !/^[0-9a-f-]{36}$/i.test(result.terminal_uuid)
  ) {
    throw new Error('spawn_durdraw did not return a terminal UUID');
  }
  return result.terminal_uuid;
}

async function assertOtpReplayRejected(options, auth, otp, workspace) {
  const { payload } = await requestJson(mcpRouteUrl(options.nottyUrl, '/call'), {
    method: 'POST',
    headers: authHeaders(auth),
    body: {
      name: 'spawn_durdraw',
      arguments: { otp: otp.value, cwd: workspace }
    },
    expectedStatuses: [400],
    label: 'Notty OTP replay check'
  });
  const message = payload?.content?.find((entry) => entry?.type === 'text')?.text || '';
  if (payload?.isError !== true || !/already been used/i.test(message)) {
    throw new Error('Notty did not reject a replay of the consumed spawn OTP');
  }
}

async function waitForDurdraw(options, auth, terminalUuid, workspace) {
  const terminalUrl = siblingUrl(
    options.nottyUrl,
    `/api/terminals/${encodeURIComponent(terminalUuid)}`
  );
  const readUrl = siblingUrl(
    options.nottyUrl,
    `/api/terminals/${encodeURIComponent(terminalUuid)}/read`
  );
  const initialSummary = await requestJson(terminalUrl, {
    headers: authHeaders(auth),
    label: 'Durdraw terminal summary'
  });
  const session = initialSummary.payload?.session;
  if (!session?.alive) {
    throw new Error('the assigned Durdraw terminal is not alive');
  }
  if (path.resolve(String(session.cwd || '')) !== path.resolve(workspace)) {
    throw new Error(
      `Notty opened the terminal in ${session.cwd || 'an unknown directory'}, ` +
      `not the shared art workspace ${workspace}. Ensure that exact path ` +
      'is mounted into the Nosh container, or pass --output-dir under NOTTY_WORKDIR.'
    );
  }
  const deadline = Date.now() + Math.min(options.timeoutMs, 15_000);
  let output = '';

  while (Date.now() < deadline) {
    const { payload } = await requestJson(readUrl, {
      method: 'POST',
      headers: authHeaders(auth),
      body: {},
      label: 'Durdraw terminal readiness'
    });
    output = String(payload?.data || '');
    if (/command not found|ModuleNotFoundError|Traceback \(most recent call last\)/i.test(output)) {
      throw new Error('the assigned terminal could not launch Durdraw; inspect the Notty image/PATH');
    }
    if (output.includes('FPS') && output.includes('[80x25]')) {
      await sleep(300);
      const settled = await requestJson(terminalUrl, {
        headers: authHeaders(auth),
        label: 'settled Durdraw terminal summary'
      });
      if (!settled.payload?.session?.alive) {
        throw new Error('Durdraw exited during startup');
      }
      return;
    }
    await sleep(POLL_INTERVAL_MS);
  }
  throw new Error('Durdraw did not produce terminal output before the readiness timeout');
}

async function readOtpDashboard(options, auth) {
  const { payload } = await requestJson(siblingUrl(options.nottyUrl, '/api/spawn-otps'), {
    headers: authHeaders(auth),
    label: 'Notty OTP dashboard'
  });
  return payload;
}

function assertOtpsUsed(dashboard, assignments) {
  const rows = Array.isArray(dashboard?.otps) ? dashboard.otps : [];
  for (const assignment of assignments) {
    const row = rows.find((entry) => entry?.uuid === assignment.otp.uuid);
    if (!row || row.status !== 'used' || !row.usedAt) {
      throw new Error(`${assignment.id} OTP was not recorded as single-use/used`);
    }
  }
}

async function createExclusiveDirectory(destination) {
  await mkdir(path.dirname(destination), { recursive: true });
  await mkdir(destination, { recursive: false });
}

async function createWorkspace(options) {
  const defaultOutputRoot = path.resolve(
    process.env.DURDRAW_AGENT_OUTPUT_ROOT
      || path.join(APP_ROOT, '.notty-art-runs')
  );
  if (!options.outputDir) {
    await mkdir(defaultOutputRoot, { recursive: true, mode: 0o700 });
  }
  const workspace = options.outputDir
    ? options.outputDir
    : await mkdtemp(path.join(defaultOutputRoot, 'run-'));
  if (options.outputDir) {
    await createExclusiveDirectory(workspace);
  }

  for (const directory of [
    '.notty-art',
    'agents/active',
    'agents/locks',
    'coordination/ready',
    'coordination/blocked',
    'logs'
  ]) {
    await mkdir(path.join(workspace, directory), { recursive: true });
  }
  await copyFile(
    path.join(SCRIPT_DIR, 'durdraw-art-lock.mjs'),
    path.join(workspace, '.notty-art', 'art-lock.mjs')
  );
  await chmod(path.join(workspace, '.notty-art', 'art-lock.mjs'), 0o755);
  await writeFile(
    path.join(workspace, 'collaboration.ans'),
    Buffer.from('\u001b[0mCOLLABORATION CANVAS\r\n', 'utf8'),
    { mode: 0o600 }
  );
  await writeFile(path.join(workspace, 'AGENTS.md'), workspaceInstructions(), {
    encoding: 'utf8',
    mode: 0o600
  });
  return workspace;
}

function workspaceInstructions() {
  return `# Durdraw art smoke workspace

This workspace is controlled by the two-agent Durdraw smoke test.

## File authority and locking

- You may edit only your personal ANSI file and \`collaboration.ans\`.
- Every target must be locked before the first editing tool call.
- The lock is authoritative at \`agents/locks/<target>\`; its first line is the owner.
- Never edit a target when acquisition reports busy or verification fails.
- Hold only one lock at a time. Release it as soon as that save is complete.
- Do not delete, replace, or take over another agent's lock.
- Use only \`.notty-art/art-lock.mjs\` for acquisition, verification, barriers, and release.
- Use Durdraw MCP tools for art edits. Never create or modify an \`.ans\` file with shell,
  JavaScript, Python, redirection, apply_patch, base64, or another filesystem tool.
- The only shell writes permitted are those performed by the lock helper.

The parent creates \`coordination/go\` only after both personal pieces are saved and
both artists have recorded readiness. The shared lock race intentionally requires
one denied acquisition before a verified handoff.
`;
}

function artBrief(agentId) {
  if (agentId === 'artist-a') {
    return {
      title: 'NEON RELAY',
      palette: 'black/dark blue/cyan/white with one yellow signal accent',
      scene: 'a compact technical relay tower, packet traces, and a crisp status strip'
    };
  }
  return {
    title: 'GHOST SIGNAL',
    palette: 'black/red/magenta/gray/white',
    scene: 'a haunted receiver, spectral radio waves, and a broken-carrier status strip'
  };
}

function agentPrompt(assignment, context) {
  const brief = artBrief(assignment.id);
  const personalFile = `${assignment.id}.ans`;
  const helper = 'node .notty-art/art-lock.mjs';
  return `You are ${assignment.id}, one of two ANSI artists in an integration smoke test.

Your assigned Notty Durdraw terminal UUID is:
${assignment.terminalUuid}

Use MCP servers \`notty_durdraw\` and \`collab_art\`. Never call
\`spawn_durdraw\`: the parent already consumed your one and only OTP to create
the terminal above. Never expose or search for credentials.

First register with Collab:
1. Call \`set_nickname\` with nickname \`${assignment.id}\`.
2. Call \`set_status\` with \`busy\`.
3. Send a message to channel \`${context.channel}\` saying that your assigned
   Durdraw session is ready. Use agent \`${assignment.id}\` when the tool accepts it.

All art changes must be made interactively through \`durdraw_action\` and
\`durdraw_text\` using terminal_uuid \`${assignment.terminalUuid}\`. Use
\`read_terminal\` often to verify which prompt or canvas is active. You may use
the shell only to run the lock helper commands shown below. Do not write ANSI
files by any other means.

PHASE 1 — personal art

1. Run:
   ${helper} acquire ${assignment.id} ${personalFile}
2. Verify the helper succeeded before touching the canvas.
3. Create an original 80-column, roughly 10–16-line ANSI scene titled
   "${brief.title}". Theme: ${brief.scene}. Use a restrained 16-color palette:
   ${brief.palette}. Keep a clear hierarchy (title, scene, status, signature),
   intentional negative space, and CP437-style \`░▒▓█\` or box-drawing texture.
   Include the literal ASCII signature \`[${assignment.id}]\`.
4. You must make at least one \`durdraw_text\` call and at least one
   \`durdraw_action\` call that changes foreground color (for example
   \`nextfgcolor\`). Keep every visible row at or under 80 columns.
5. Save from Durdraw, checking terminal output between steps:
   - call action \`save\`
   - type \`a\` for ANSI
   - type \`c\` for CP437
   - type \`${personalFile}\` with append_enter=true
   - if prompted to overwrite, type \`y\`
   - press \`space\` once to dismiss the saved notice
6. Run:
   ${helper} verify ${assignment.id} ${personalFile}
   ${helper} release ${assignment.id} ${personalFile}
7. Tell channel \`${context.channel}\` the personal file is saved, then run:
   ${helper} ready ${assignment.id}

PHASE 2 — intentional shared-lock race and handoff

1. Run this command and wait for it to return:
   ${helper} begin-shared ${assignment.id} collaboration.ans ${context.timeoutMs}
   It waits for the parent barrier, races the peer, and prints JSON with role
   \`first\` or \`second\`. A busy lock is expected for one artist; never bypass it.
2. Tell the peer your returned role in channel \`${context.channel}\`.
3. Open the shared file through Durdraw:
   - call action \`open\`
   - inspect the terminal; if an unsaved-changes Y/N prompt unexpectedly appears,
     answer only after confirming the personal save completed
   - the shortcut opens the file picker directly, so type
     \`collaboration.ans\` with append_enter=true (do not type a format letter)
   - inspect and confirm that the shared canvas loaded before editing
4. If role is \`first\`, replace the seed with a compact title/frame and upper
   half of a shared "SIGNAL BRIDGE" composition in rows 1–10, ending with the
   literal ASCII signature \`[${assignment.id}]\`. Leave rows 13–22 open.
   If role is \`second\`, preserve the first artist's work: move down at least
   13 rows (newline/Enter navigation is fine), add the lower half, harmonize the
   scene, and include the literal ASCII signature \`[${assignment.id}]\`.
5. Again use both \`durdraw_text\` and a foreground-color \`durdraw_action\`.
6. Save as ANSI/CP437 to \`collaboration.ans\` using the same save sequence.
   This file exists, so answer \`y\` to the overwrite prompt and dismiss the
   saved notice.
7. Run:
   ${helper} verify ${assignment.id} collaboration.ans
   ${helper} release ${assignment.id} collaboration.ans
   ${helper} finish ${assignment.id}
8. Tell channel \`${context.channel}\` that your shared handoff is complete,
   call \`set_status\` with \`idle\`, and finish with a short summary.

Do not stop after phase 1. If the interface is unclear, inspect it with
\`read_terminal\`; do not substitute shell-generated art.
`;
}

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function appendCapture(current, chunk, limit = 96 * 1024) {
  const combined = current + chunk;
  return combined.length > limit ? combined.slice(-limit) : combined;
}

function signalProcess(child, signal) {
  if (!child?.pid) {
    return;
  }
  try {
    if (process.platform === 'win32') {
      child.kill(signal);
    } else {
      process.kill(-child.pid, signal);
    }
  } catch {
    // The process may already have exited.
  }
}

function runCommand(command, args, options = {}) {
  return new Promise((resolve, reject) => {
    let stdout = '';
    let stderr = '';
    let timedOut = false;
    let settled = false;
    let forceKillTimer;
    const child = spawn(command, args, {
      cwd: options.cwd,
      env: options.env,
      detached: process.platform !== 'win32',
      stdio: [options.input === undefined ? 'ignore' : 'pipe', 'pipe', 'pipe']
    });

    child.stdout.setEncoding('utf8');
    child.stderr.setEncoding('utf8');
    child.stdout.on('data', (chunk) => {
      stdout = appendCapture(stdout, chunk);
    });
    child.stderr.on('data', (chunk) => {
      stderr = appendCapture(stderr, chunk);
    });
    if (options.input !== undefined) {
      child.stdin.end(options.input);
    }

    const timeoutMs = options.timeoutMs || 60_000;
    const timer = setTimeout(() => {
      timedOut = true;
      signalProcess(child, 'SIGTERM');
      forceKillTimer = setTimeout(() => signalProcess(child, 'SIGKILL'), 2_000);
      forceKillTimer.unref?.();
    }, timeoutMs);
    timer.unref?.();

    const finish = (callback) => {
      if (settled) {
        return;
      }
      settled = true;
      clearTimeout(timer);
      clearTimeout(forceKillTimer);
      callback();
    };
    child.once('error', (error) => {
      finish(() => reject(new Error(`could not start ${command}: ${error.message}`)));
    });
    child.once('close', (code, signal) => {
      finish(() => resolve({ code, signal, stdout, stderr, timedOut }));
    });
  });
}

function commandFailure(label, result, secrets = []) {
  const output = [
    result?.stdout ? `stdout:\n${result.stdout}` : '',
    result?.stderr ? `stderr:\n${result.stderr}` : ''
  ].filter(Boolean).join('\n');
  const reason = result?.timedOut
    ? 'timed out'
    : `exited with ${result?.code ?? 'no status'}${result?.signal ? ` (${result.signal})` : ''}`;
  return new Error(`${label} ${reason}${output ? `\n${redact(output, secrets)}` : ''}`);
}

async function preflightCodexSandbox(options) {
  const version = await runCommand(options.codexBin, ['--version'], {
    cwd: APP_ROOT,
    env: scrubbedCodexEnvironment(),
    timeoutMs: 30_000
  });
  if (version.code !== 0) {
    throw commandFailure('Codex CLI preflight', version);
  }
  if (process.platform !== 'linux' || options.sandbox !== 'workspace-write') {
    return;
  }

  let probe;
  try {
    probe = await runCommand(
      'bwrap',
      ['--ro-bind', '/', '/', '--proc', '/proc', '--dev', '/dev', 'true'],
      {
        cwd: APP_ROOT,
        env: scrubbedCodexEnvironment(),
        timeoutMs: 5_000
      }
    );
  } catch (error) {
    if (/could not start bwrap/i.test(error.message)) {
      return;
    }
    throw error;
  }
  if (
    probe.code !== 0
    && /permissions to create new namespace|operation not permitted/i.test(
      `${probe.stdout}\n${probe.stderr}`
    )
  ) {
    throw new Error(
      'this host cannot create the Codex workspace sandbox. If the script is ' +
      'already running inside an isolated Nosh container, rerun with ' +
      '--sandbox danger-full-access'
    );
  }
}

async function configureCodexHome(options, home, auth, originalCodexHome) {
  await mkdir(home, { recursive: true, mode: 0o700 });
  const sourceAuth = path.join(originalCodexHome, 'auth.json');
  try {
    await access(sourceAuth);
    await copyFile(sourceAuth, path.join(home, 'auth.json'));
    await chmod(path.join(home, 'auth.json'), 0o600);
  } catch {
    // Codex can also authenticate from its normal API-key environment variables.
  }

  const environment = {
    ...scrubbedCodexEnvironment(),
    CODEX_HOME: home,
    ...(auth.header ? { [AUTH_ENV_NAME]: auth.header } : {})
  };
  for (const server of [
    { name: 'notty_durdraw', url: options.nottyUrl },
    { name: 'collab_art', url: options.collabUrl }
  ]) {
    const before = await runCommand(options.codexBin, ['mcp', 'list', '--json'], {
      cwd: APP_ROOT,
      env: environment,
      timeoutMs: 30_000
    });
    if (before.code !== 0) {
      throw commandFailure('codex mcp list', before, auth.secrets);
    }
    let entries;
    try {
      entries = JSON.parse(before.stdout);
    } catch {
      throw new Error('codex mcp list returned invalid JSON');
    }
    const existing = Array.isArray(entries)
      ? entries.find((entry) => entry?.name === server.name)
      : null;
    if (!existing) {
      const added = await runCommand(
        options.codexBin,
        ['mcp', 'add', server.name, '--url', server.url],
        {
          cwd: APP_ROOT,
          env: environment,
          timeoutMs: 30_000
        }
      );
      if (added.code !== 0) {
        throw commandFailure(`codex mcp add ${server.name}`, added, auth.secrets);
      }
    } else if (existing?.transport?.url !== server.url) {
      throw new Error(
        `temporary Codex home has ${server.name} at ${existing.transport?.url}, expected ${server.url}`
      );
    }
  }

  const overrideArgs = auth.header
    ? ['-c', `mcp_servers.notty_durdraw.env_http_headers={ Authorization = "${AUTH_ENV_NAME}" }`]
    : [];
  const after = await runCommand(
    options.codexBin,
    [...overrideArgs, 'mcp', 'list', '--json'],
    { cwd: APP_ROOT, env: environment, timeoutMs: 30_000 }
  );
  if (after.code !== 0) {
    throw commandFailure('codex mcp verification', after, auth.secrets);
  }
  const configured = JSON.parse(after.stdout);
  for (const expected of ['notty_durdraw', 'collab_art']) {
    if (!configured.some((entry) => entry?.name === expected && entry.enabled)) {
      throw new Error(`Codex MCP verification did not find enabled server ${expected}`);
    }
  }
  return environment;
}

function startCodexAgent(options, assignment, context, environment, runtimeDir) {
  const stdoutPath = path.join(runtimeDir, `${assignment.id}.codex.jsonl`);
  const stderrPath = path.join(runtimeDir, `${assignment.id}.stderr.log`);
  const finalPath = path.join(runtimeDir, `${assignment.id}.final.txt`);
  const args = [
    '--ask-for-approval', 'never',
    '-c', `model_reasoning_effort="${options.think}"`,
    '-c', 'mcp_servers.notty_durdraw.required=true',
    '-c', 'mcp_servers.collab_art.required=true',
    '-c', 'mcp_servers.notty_durdraw.default_tools_approval_mode="approve"',
    '-c', 'mcp_servers.collab_art.default_tools_approval_mode="approve"',
    '-c', 'mcp_servers.notty_durdraw.tool_timeout_sec=90',
    '-c', 'mcp_servers.collab_art.tool_timeout_sec=90',
    '-c', 'shell_environment_policy.exclude=["SPAWN_OTP","MCP_SPAWN_OTP","NOTTY_MCP_SPAWN_OTP","COLLAB_AGENT_SPAWN_OTP","NOTTY_ART_AUTHORIZATION","NOTTY_BASIC_AUTH_USERNAME","NOTTY_BASIC_AUTH_PASSWORD","NOTTY_MCP_BEARER_TOKEN","NOTTY_MCP_AUTHORIZATION","OPENAI_API_KEY"]'
  ];
  if (context.auth.header) {
    args.push(
      '-c',
      `mcp_servers.notty_durdraw.env_http_headers={ Authorization = "${AUTH_ENV_NAME}" }`
    );
  }
  args.push(
    'exec',
    '--ephemeral',
    '--skip-git-repo-check',
    '--sandbox', options.sandbox,
    '--color', 'never',
    '--json',
    '--output-last-message', finalPath,
    '-C', context.workspace
  );
  if (options.model) {
    args.push('--model', options.model);
  }
  args.push('-');

  let stdout = '';
  let stderr = '';
  let timedOut = false;
  let settled = false;
  let completedResult = null;
  let forceKillTimer;
  const child = spawn(options.codexBin, args, {
    cwd: context.workspace,
    env: {
      ...environment,
      ART_WORKSPACE: context.workspace
    },
    detached: process.platform !== 'win32',
    stdio: ['pipe', 'pipe', 'pipe']
  });
  child.stdout.setEncoding('utf8');
  child.stderr.setEncoding('utf8');
  child.stdout.on('data', (chunk) => {
    stdout += chunk;
  });
  child.stderr.on('data', (chunk) => {
    stderr += chunk;
  });
  child.stdin.end(agentPrompt(assignment, context));

  const completion = new Promise((resolve) => {
    const timer = setTimeout(() => {
      timedOut = true;
      signalProcess(child, 'SIGTERM');
      forceKillTimer = setTimeout(() => signalProcess(child, 'SIGKILL'), 2_000);
      forceKillTimer.unref?.();
    }, options.timeoutMs);
    timer.unref?.();

    const finish = async (result) => {
      if (settled) {
        return;
      }
      settled = true;
      clearTimeout(timer);
      clearTimeout(forceKillTimer);
      let logWriteError = null;
      try {
        await writeFile(stdoutPath, stdout, { encoding: 'utf8', mode: 0o600 });
        await writeFile(stderrPath, stderr, { encoding: 'utf8', mode: 0o600 });
      } catch (error) {
        logWriteError = error;
      } finally {
        completedResult = {
          ...result,
          stdout,
          stderr,
          stdoutPath,
          stderrPath,
          finalPath,
          logWriteError
        };
        resolve(completedResult);
      }
    };
    child.once('error', (error) => {
      void finish({ code: null, signal: null, timedOut, startError: error });
    });
    child.once('close', (code, signal) => {
      void finish({ code, signal, timedOut });
    });
  });

  return {
    id: assignment.id,
    child,
    completion,
    get settled() {
      return settled;
    },
    get result() {
      return completedResult;
    }
  };
}

async function stopAgentHandles(handles) {
  for (const handle of handles) {
    if (!handle.settled) {
      signalProcess(handle.child, 'SIGTERM');
    }
  }
  const completions = Promise.allSettled(handles.map((handle) => handle.completion));
  await Promise.race([completions, sleep(2_000)]);
  for (const handle of handles) {
    if (!handle.settled) {
      signalProcess(handle.child, 'SIGKILL');
    }
  }
  await Promise.race([completions, sleep(5_000)]);
}

async function waitForAgentCompletion(handles, secrets) {
  const watched = handles.map(async (handle) => ({
    id: handle.id,
    ...await handle.completion
  }));
  const failure = Promise.race(
    watched.map(async (promise) => {
      const result = await promise;
      if (result.startError || result.timedOut || result.code !== 0) {
        return result;
      }
      return new Promise(() => {});
    })
  );
  const all = Promise.all(watched);
  const outcome = await Promise.race([
    all.then((results) => ({ type: 'all', results })),
    failure.then((result) => ({ type: 'failure', result }))
  ]);
  if (outcome.type === 'all') {
    return outcome.results;
  }
  await stopAgentHandles(handles);
  const results = handles
    .filter((handle) => handle.result)
    .map((handle) => ({ id: handle.id, ...handle.result }));
  const error = outcome.result.startError
    ? new Error(`could not start ${outcome.result.id}: ${outcome.result.startError.message}`)
    : commandFailure(outcome.result.id, outcome.result, secrets);
  error.agentResults = results;
  throw error;
}

async function pathExists(target) {
  try {
    await access(target);
    return true;
  } catch {
    return false;
  }
}

async function waitForReady(handles, workspace, timeoutMs, secrets) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    const readiness = await Promise.all(
      AGENT_IDS.map((id) => pathExists(path.join(workspace, 'coordination', 'ready', id)))
    );
    if (readiness.every(Boolean)) {
      return;
    }
    const early = handles.find((handle) => handle.settled);
    if (early) {
      const result = { id: early.id, ...await early.completion };
      if (result.startError) {
        throw new Error(`could not start ${early.id}: ${result.startError.message}`);
      }
      throw commandFailure(
        `${early.id} exited before both artists reached the collaboration barrier and`,
        result,
        secrets
      );
    }
    await sleep(POLL_INTERVAL_MS);
  }
  throw new Error('timed out waiting for both artists to finish their personal files');
}

async function persistAgentLogs(results, workspace, secrets) {
  for (const result of results) {
    if (result.logWriteError) {
      throw new Error(`${result.id} could not write its temporary runtime log: ${result.logWriteError.message}`);
    }
    const stdout = redact(result.stdout, secrets);
    const stderr = redact(result.stderr, secrets);
    await writeFile(
      path.join(workspace, 'logs', `${result.id}.codex.jsonl`),
      stdout,
      { encoding: 'utf8', mode: 0o600 }
    );
    await writeFile(
      path.join(workspace, 'logs', `${result.id}.stderr.log`),
      stderr,
      { encoding: 'utf8', mode: 0o600 }
    );
    if (await pathExists(result.finalPath)) {
      await writeFile(
        path.join(workspace, 'logs', `${result.id}.final.txt`),
        redact(await readFile(result.finalPath, 'utf8'), secrets),
        { encoding: 'utf8', mode: 0o600 }
      );
    }
  }
}

function assertAgentResults(results, secrets) {
  for (const result of results) {
    if (result.startError) {
      throw new Error(`could not start ${result.id}: ${result.startError.message}`);
    }
    if (result.timedOut || result.code !== 0) {
      throw commandFailure(result.id, result, secrets);
    }
  }
}

function completedMcpCalls(trace, agentId) {
  const calls = [];
  for (const [index, line] of String(trace || '').split(/\r?\n/).entries()) {
    if (!line) {
      continue;
    }
    let event;
    try {
      event = JSON.parse(line);
    } catch {
      throw new Error(`${agentId} emitted invalid Codex JSONL at line ${index + 1}`);
    }
    const item = event?.item;
    if (
      event.type === 'item.completed'
      && item?.type === 'mcp_tool_call'
      && item?.status === 'completed'
      && !item?.error
    ) {
      calls.push({ server: item.server, tool: item.tool });
    }
  }
  return calls;
}

function assertAgentToolEvidence(results) {
  for (const result of results) {
    const calls = completedMcpCalls(result.stdout, result.id);
    const allItems = String(result.stdout || '')
      .split(/\r?\n/)
      .filter(Boolean)
      .map((line) => JSON.parse(line)?.item)
      .filter((item) => item?.type === 'mcp_tool_call');
    const expected = [
      ['Durdraw text', 'notty_durdraw', 'durdraw_text'],
      ['Durdraw action', 'notty_durdraw', 'durdraw_action'],
      ['Collab message', 'collab_art', 'send_message']
    ];
    for (const [label, server, tool] of expected) {
      if (!calls.some((call) => call.server === server && call.tool === tool)) {
        throw new Error(`${result.id} trace has no ${label} MCP call evidence`);
      }
    }
    if (allItems.some(
      (item) => item.server === 'notty_durdraw' && item.tool === 'spawn_durdraw'
    )) {
      throw new Error(`${result.id} attempted spawn_durdraw instead of reusing its assigned OTP session`);
    }
  }
}

function parseLockEvents(text) {
  return text
    .split(/\r?\n/)
    .filter(Boolean)
    .map((line, index) => {
      try {
        return JSON.parse(line);
      } catch {
        throw new Error(`invalid lock event JSON at line ${index + 1}`);
      }
    });
}

async function listFilesRecursive(root) {
  if (!await pathExists(root)) {
    return [];
  }
  const output = [];
  const visit = async (directory) => {
    for (const entry of await readdir(directory, { withFileTypes: true })) {
      const target = path.join(directory, entry.name);
      if (entry.isDirectory()) {
        await visit(target);
      } else {
        output.push(target);
      }
    }
  };
  await visit(root);
  return output;
}

function findEventIndex(events, predicate, start = 0) {
  for (let index = start; index < events.length; index += 1) {
    if (predicate(events[index])) {
      return index;
    }
  }
  return -1;
}

async function validateLocks(workspace) {
  const text = await readFile(path.join(workspace, 'coordination', 'lock-events.jsonl'), 'utf8');
  const events = parseLockEvents(text);

  for (const id of AGENT_IDS) {
    const target = `${id}.ans`;
    const acquired = findEventIndex(
      events,
      (event) => event.action === 'acquired' && event.agent === id && event.target === target
    );
    const released = findEventIndex(
      events,
      (event) => event.action === 'released' && event.agent === id && event.target === target,
      acquired + 1
    );
    const mutation = findEventIndex(
      events,
      (event) => event.action === 'releasing'
        && event.agent === id
        && event.target === target
        && event.changed === true,
      acquired + 1
    );
    if (acquired < 0 || mutation < 0 || released < 0) {
      throw new Error(`${id} did not mutate, verify, and release its personal file lock`);
    }
  }

  const first = findEventIndex(
    events,
    (event) => event.action === 'acquired'
      && event.target === 'collaboration.ans'
      && event.role === 'first'
  );
  const blocked = findEventIndex(
    events,
    (event) => event.action === 'blocked' && event.target === 'collaboration.ans',
    first + 1
  );
  const firstReleasing = findEventIndex(
    events,
    (event) => event.action === 'releasing'
      && event.target === 'collaboration.ans'
      && event.agent === events[first]?.agent
      && event.changed === true,
    blocked + 1
  );
  const second = findEventIndex(
    events,
    (event) => event.action === 'acquired'
      && event.target === 'collaboration.ans'
      && event.role === 'second',
    firstReleasing + 1
  );
  const firstRelease = findEventIndex(
    events,
    (event) => event.action === 'released'
      && event.target === 'collaboration.ans'
      && event.agent === events[first]?.agent,
    firstReleasing + 1
  );
  const secondReleasing = findEventIndex(
    events,
    (event) => event.action === 'releasing'
      && event.target === 'collaboration.ans'
      && event.agent === events[second]?.agent
      && event.changed === true,
    second + 1
  );
  const secondRelease = findEventIndex(
    events,
    (event) => event.action === 'released'
      && event.target === 'collaboration.ans'
      && event.agent === events[second]?.agent,
    secondReleasing + 1
  );
  if (
    [first, blocked, firstReleasing, firstRelease, second, secondReleasing, secondRelease]
      .some((index) => index < 0)
  ) {
    throw new Error('shared lock evidence is incomplete (first, blocked, handoff, second, release)');
  }
  if (events.some((event) => event.action === 'released_after_timeout')) {
    throw new Error('a shared lock timed out instead of completing the collaboration');
  }
  if (events[first].agent === events[second].agent) {
    throw new Error('the shared lock was not handed to the peer');
  }
  if (events[blocked].agent !== events[second].agent) {
    throw new Error('the blocked artist was not the artist that acquired second');
  }
  const leftovers = await listFilesRecursive(path.join(workspace, 'agents', 'locks'));
  if (leftovers.length > 0) {
    throw new Error(`lock files remain after completion: ${leftovers.join(', ')}`);
  }
  return {
    eventCount: events.length,
    first: events[first].agent,
    second: events[second].agent,
    blocked: events[blocked].agent
  };
}

function containsAscii(buffer, value) {
  const visible = buffer.toString('latin1')
    .replace(/\u001b\][^\u0007]*(?:\u0007|\u001b\\)/g, '')
    .replace(/\u001b\[[0-?]*[ -/]*[@-~]/g, '')
    .replace(/[\u000e\u000f]/g, '');
  return visible.includes(value);
}

async function validateArt(workspace) {
  const files = {};
  for (const file of ['artist-a.ans', 'artist-b.ans', 'collaboration.ans']) {
    const target = path.join(workspace, file);
    const data = await readFile(target);
    if (data.length < 80) {
      throw new Error(`${file} is too small to be a completed ANSI smoke artifact`);
    }
    if (!data.includes(0x1b)) {
      throw new Error(`${file} contains no ANSI escape sequences`);
    }
    files[file] = {
      bytes: data.length,
      sha256: createHash('sha256').update(data).digest('hex')
    };
  }
  if (!containsAscii(await readFile(path.join(workspace, 'artist-a.ans')), '[artist-a]')) {
    throw new Error('artist-a.ans is missing its literal signature');
  }
  if (!containsAscii(await readFile(path.join(workspace, 'artist-b.ans')), '[artist-b]')) {
    throw new Error('artist-b.ans is missing its literal signature');
  }
  const shared = await readFile(path.join(workspace, 'collaboration.ans'));
  for (const id of AGENT_IDS) {
    if (!containsAscii(shared, `[${id}]`)) {
      throw new Error(`collaboration.ans is missing [${id}] after the handoff`);
    }
  }
  if (files['artist-a.ans'].sha256 === files['artist-b.ans'].sha256) {
    throw new Error('the two personal ANSI files are unexpectedly identical');
  }
  return files;
}

async function validateCollab(options, channel) {
  const { payload } = await requestJson(
    siblingUrl(options.collabUrl, '/admin/v1/commands/who'),
    {
      method: 'POST',
      body: { channel },
      label: 'Collab participant verification'
    }
  );
  const participants = Array.isArray(payload?.result?.participants)
    ? payload.result.participants
    : [];
  const names = new Set(participants.map((entry) => entry?.agent));
  for (const id of AGENT_IDS) {
    if (!names.has(id)) {
      throw new Error(`Collab channel ${channel} has no message evidence from ${id}`);
    }
  }
  const messagesUrl = new URL(
    siblingUrl(
      options.collabUrl,
      `/admin/v1/channels/${encodeURIComponent(channel)}/messages`
    )
  );
  messagesUrl.searchParams.set('limit', '500');
  const { payload: messagePayload } = await requestJson(messagesUrl.toString(), {
    label: 'Collab message verification'
  });
  const messages = Array.isArray(messagePayload?.messages)
    ? messagePayload.messages
    : [];
  for (const id of AGENT_IDS) {
    const bodies = messages
      .filter((message) => message?.agent_id === id)
      .map((message) => String(message.body || ''));
    if (!bodies.some((body) => /personal[\s\S]{0,80}sav|sav[\s\S]{0,80}personal/i.test(body))) {
      throw new Error(`Collab channel has no personal-save message from ${id}`);
    }
    if (!bodies.some((body) => /\brole\b[\s\S]{0,60}\b(first|second)\b/i.test(body))) {
      throw new Error(`Collab channel has no shared-lock role message from ${id}`);
    }
    if (!bodies.some((body) => /shared[\s\S]{0,100}(complete|done)|handoff[\s\S]{0,100}complete/i.test(body))) {
      throw new Error(`Collab channel has no shared-handoff completion from ${id}`);
    }
  }
  return { participants, messages };
}

async function assertNoSecrets(workspace, secrets) {
  const meaningful = secrets.filter((secret) => typeof secret === 'string' && secret.length >= 6);
  if (meaningful.length === 0) {
    return;
  }
  for (const file of await listFilesRecursive(workspace)) {
    const data = await readFile(file);
    for (const secret of meaningful) {
      if (data.indexOf(Buffer.from(secret)) >= 0) {
        throw new Error(`secret material leaked into retained workspace file ${file}`);
      }
    }
  }
}

async function recoverExpectedLocks(workspace) {
  const lockRoot = path.join(workspace, 'agents', 'locks');
  const recovered = [];
  for (const lockFile of await listFilesRecursive(lockRoot)) {
    let owner = '';
    try {
      owner = (await readFile(lockFile, 'utf8')).split(/\r?\n/, 1)[0].trim();
    } catch {
      continue;
    }
    if (!AGENT_IDS.includes(owner)) {
      continue;
    }
    const target = path.relative(lockRoot, lockFile).split(path.sep).join('/');
    await rm(lockFile, { force: true });
    await rm(path.join(workspace, 'agents', 'leases', `${owner}.json`), { force: true });
    await writeFile(
      path.join(workspace, 'coordination', 'lock-events.jsonl'),
      `${JSON.stringify({
        timestamp: new Date().toISOString(),
        action: 'parent_recovered',
        agent: owner,
        target
      })}\n`,
      { encoding: 'utf8', flag: 'a', mode: 0o600 }
    );
    recovered.push({ owner, target });
  }
  return recovered;
}

async function cleanupTerminal(options, auth, terminalUuid) {
  try {
    await requestJson(
      siblingUrl(options.nottyUrl, `/api/terminals/${encodeURIComponent(terminalUuid)}`),
      {
        method: 'DELETE',
        headers: authHeaders(auth),
        expectedStatuses: [204, 404],
        label: `terminal cleanup ${terminalUuid}`
      }
    );
  } catch (error) {
    log(`warning: ${error.message}`);
  }
}

async function consumeAvailableOtps(options, auth, otpValues, workspace) {
  if (otpValues.length === 0) {
    return;
  }
  try {
    const dashboard = await readOtpDashboard(options, auth);
    const rows = Array.isArray(dashboard?.otps) ? dashboard.otps : [];
    for (const value of otpValues) {
      const row = rows.find((entry) => entry?.value === value);
      if (row?.status !== 'available') {
        continue;
      }
      try {
        const terminal = await callNottyTool(options, auth, 'spawn_durdraw', {
          otp: value,
          cwd: workspace,
          command: 'exit'
        });
        if (terminal?.terminal_uuid) {
          await cleanupTerminal(options, auth, terminal.terminal_uuid);
        }
      } catch {
        log(`warning: could not invalidate unused OTP metadata ${row.uuid}`);
      }
    }
  } catch (error) {
    log(`warning: could not audit unused OTP cleanup: ${error.message}`);
  }
}

async function run(options) {
  const auth = resolveNottyAuth();
  const workspace = await createWorkspace(options);
  const runtimeDir = await mkdtemp(path.join(os.tmpdir(), 'notty-durdraw-runtime-'));
  const originalCodexHome = path.resolve(
    process.env.CODEX_HOME || path.join(os.homedir(), '.codex')
  );
  const channel = `durdraw-${Date.now().toString(36)}-${randomBytes(4).toString('hex')}`;
  const assignments = [];
  const handles = [];
  const environments = [];
  const otpValues = AGENT_IDS.map(() => randomBytes(18).toString('base64url'));
  let results = [];
  let interruptedSignal = '';
  const onSignal = (signal) => {
    interruptedSignal ||= signal;
    void stopAgentHandles(handles);
  };
  const onSigint = () => onSignal('SIGINT');
  const onSigterm = () => onSignal('SIGTERM');
  const throwIfInterrupted = () => {
    if (interruptedSignal) {
      throw new Error(`interrupted by ${interruptedSignal}`);
    }
  };
  process.once('SIGINT', onSigint);
  process.once('SIGTERM', onSigterm);

  log(`art workspace: ${workspace}`);
  try {
    await Promise.all([
      preflightNotty(options, auth),
      preflightCollab(options)
    ]);
    throwIfInterrupted();
    await preflightCodexSandbox(options);
    throwIfInterrupted();

    for (const id of AGENT_IDS) {
      throwIfInterrupted();
      const home = path.join(runtimeDir, `${id}-codex-home`);
      environments.push(
        await configureCodexHome(options, home, auth, originalCodexHome)
      );
    }
    log('temporary Codex MCP homes verified');

    log('issuing two distinct one-time spawn tokens');
    auth.secrets.push(...otpValues);
    const otps = [];
    for (const value of otpValues) {
      throwIfInterrupted();
      otps.push(await issueOtp(options, auth, value));
    }
    if (new Set(otps.map((otp) => otp.value)).size !== AGENT_IDS.length) {
      throw new Error('Notty issued duplicate OTP values');
    }
    if (new Set(otps.map((otp) => otp.uuid)).size !== AGENT_IDS.length) {
      throw new Error('Notty issued duplicate OTP UUIDs');
    }
    for (let index = 0; index < AGENT_IDS.length; index += 1) {
      throwIfInterrupted();
      const id = AGENT_IDS[index];
      const terminalUuid = await spawnAssignedTerminal(
        options,
        auth,
        otps[index],
        workspace
      );
      const assignment = { id, otp: otps[index], terminalUuid };
      assignments.push(assignment);
      await assertOtpReplayRejected(options, auth, otps[index], workspace);
      await waitForDurdraw(options, auth, terminalUuid, workspace);
      log(`${id}: OTP consumed, Durdraw terminal ${terminalUuid} ready`);
    }
    if (new Set(assignments.map((entry) => entry.terminalUuid)).size !== AGENT_IDS.length) {
      throw new Error('the two OTPs did not produce distinct terminal UUIDs');
    }
    assertOtpsUsed(await readOtpDashboard(options, auth), assignments);

    log('launching both artists');

    const context = {
      auth,
      channel,
      timeoutMs: options.timeoutMs,
      workspace
    };
    for (let index = 0; index < assignments.length; index += 1) {
      throwIfInterrupted();
      handles.push(
        startCodexAgent(
          options,
          assignments[index],
          context,
          environments[index],
          runtimeDir
        )
      );
    }
    await waitForReady(handles, workspace, options.timeoutMs, auth.secrets);
    throwIfInterrupted();
    await writeFile(
      path.join(workspace, 'coordination', 'go'),
      `${new Date().toISOString()}\n`,
      { encoding: 'utf8', flag: 'wx', mode: 0o600 }
    );
    log('both personal pieces are ready; released the shared-lock race barrier');

    results = await waitForAgentCompletion(handles, auth.secrets);
    throwIfInterrupted();
    await persistAgentLogs(results, workspace, auth.secrets);
    assertAgentResults(results, auth.secrets);
    assertAgentToolEvidence(results);

    const [art, locks, collabEvidence, dashboard] = await Promise.all([
      validateArt(workspace),
      validateLocks(workspace),
      validateCollab(options, channel),
      readOtpDashboard(options, auth)
    ]);
    assertOtpsUsed(dashboard, assignments);
    await assertNoSecrets(workspace, auth.secrets);

    const report = {
      ok: true,
      completedAt: new Date().toISOString(),
      workspace,
      channel,
      nottyMcpUrl: options.nottyUrl,
      collabMcpUrl: options.collabUrl,
      model: options.model || 'codex default',
      think: options.think,
      agents: assignments.map((assignment) => ({
        id: assignment.id,
        otpId: assignment.otp.uuid,
        otpStatus: 'used',
        terminalUuid: assignment.terminalUuid
      })),
      art,
      locks,
      collabParticipants: collabEvidence.participants.map((entry) => entry.agent),
      collabMessageCount: collabEvidence.messages.length
    };
    await writeFile(
      path.join(workspace, 'smoke-report.json'),
      `${JSON.stringify(report, null, 2)}\n`,
      { encoding: 'utf8', mode: 0o600 }
    );
    log(`PASS: two personal ANSI files and one locked collaboration are in ${workspace}`);
    process.stdout.write(`${JSON.stringify(report, null, 2)}\n`);
    return report;
  } catch (error) {
    await stopAgentHandles(handles);
    if (handles.length > 0) {
      results = Array.isArray(error?.agentResults)
        ? error.agentResults
        : handles
          .filter((handle) => handle.result)
          .map((handle) => ({ id: handle.id, ...handle.result }));
      await persistAgentLogs(results, workspace, auth.secrets).catch(() => {});
    }
    await recoverExpectedLocks(workspace).catch(() => {});
    const baseMessage = redact(error?.message || String(error), auth.secrets);
    const sandboxHint = options.sandbox === 'workspace-write'
      && /bwrap|namespace|sandbox/i.test(baseMessage)
      && !baseMessage.includes('--sandbox danger-full-access')
      ? '\nThis host cannot create the Codex workspace sandbox. If this script is already ' +
        'running inside an isolated Nosh container, rerun with --sandbox danger-full-access.'
      : '';
    throw new Error(`${baseMessage}${sandboxHint}\nart workspace: ${workspace}`);
  } finally {
    process.removeListener('SIGINT', onSigint);
    process.removeListener('SIGTERM', onSigterm);
    await Promise.all(
      assignments.map((assignment) =>
        cleanupTerminal(options, auth, assignment.terminalUuid)
      )
    );
    await consumeAvailableOtps(options, auth, otpValues, workspace);
    await rm(runtimeDir, { recursive: true, force: true });
  }
}

async function main() {
  try {
    const options = parseArgs();
    if (options.help) {
      usage();
      return;
    }
    await run(options);
  } catch (error) {
    process.stderr.write(`[durdraw-agent-art] ERROR: ${error?.message || String(error)}\n`);
    process.exitCode = 1;
  }
}

const isMain = process.argv[1]
  && path.resolve(process.argv[1]) === path.resolve(fileURLToPath(import.meta.url));

if (isMain) {
  await main();
}

export {
  AGENT_IDS,
  agentPrompt,
  assertAgentToolEvidence,
  assertOtpsUsed,
  completedMcpCalls,
  normalizeMcpUrl,
  parseArgs,
  parseLockEvents,
  resolveNottyAuth,
  run,
  scrubbedCodexEnvironment,
  siblingUrl,
  validateArt,
  validateCollab,
  validateLocks,
  workspaceInstructions
};
