#!/usr/bin/env node

import { spawn } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import http from 'node:http';
import os from 'node:os';
import path from 'node:path';
import process from 'node:process';
import { createRequire } from 'node:module';
import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { StreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/streamableHttp.js';
import {
  CallToolRequestSchema,
  ListToolsRequestSchema
} from '@modelcontextprotocol/sdk/types.js';

const require = createRequire(import.meta.url);
const {
  prepareOllamaCodexProvider,
  removeOllamaModelCatalog
} = require('../lib/collab/ollama.cjs');
const { buildOllamaCodexRelayCommand } = require('../lib/collab/ollama-codex-relay.cjs');

const ENABLE_ENV = 'NOTTY_COLLAB_REAL_RUNTIME_SMOKE';
const DEFAULT_TIMEOUT_MS = 300_000;
const MAX_CAPTURE_CHARS = 64 * 1024;
const EXPECTED_RESPONSE = 'hello';

const log = (...parts) => console.error('[collab-real-runtime-smoke]', ...parts);

function positiveInteger(value, fallback) {
  const parsed = Number.parseInt(String(value || ''), 10);
  return Number.isSafeInteger(parsed) && parsed > 0 ? parsed : fallback;
}

function scrubbedChildEnv() {
  const env = { ...process.env };
  delete env.NOTTY_MCP_SPAWN_OTP;
  delete env.MCP_SPAWN_OTP;
  delete env.COLLAB_AGENT_SPAWN_OTP;
  return env;
}

function runtimeEnv() {
  return {
    ...scrubbedChildEnv(),
    // A Notty server OTP is not an agent credential. Give each runtime only
    // its explicitly generated, single-use MCP_SPAWN_OTP.
    MCP_SPAWN_OTP: randomBytes(32).toString('base64url')
  };
}

function appendCapture(current, chunk) {
  const combined = current + chunk;
  return combined.length > MAX_CAPTURE_CHARS
    ? combined.slice(-MAX_CAPTURE_CHARS)
    : combined;
}

function signalProcess(child, signal) {
  if (!child?.pid) {
    return;
  }

  try {
    if (process.platform !== 'win32') {
      process.kill(-child.pid, signal);
    } else {
      child.kill(signal);
    }
  } catch {
    // The process may have exited between the timeout and this signal.
  }
}

function runCommand(command, args, options = {}) {
  const timeoutMs = positiveInteger(options.timeoutMs, DEFAULT_TIMEOUT_MS);

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
      stdio: ['ignore', 'pipe', 'pipe']
    });

    child.stdout.setEncoding('utf8');
    child.stderr.setEncoding('utf8');
    child.stdout.on('data', chunk => {
      stdout = appendCapture(stdout, chunk);
    });
    child.stderr.on('data', chunk => {
      stderr = appendCapture(stderr, chunk);
    });

    const timer = setTimeout(() => {
      timedOut = true;
      signalProcess(child, 'SIGTERM');
      forceKillTimer = setTimeout(() => signalProcess(child, 'SIGKILL'), 2_000);
      forceKillTimer.unref?.();
    }, timeoutMs);
    timer.unref?.();

    const finish = callback => {
      if (settled) {
        return;
      }
      settled = true;
      clearTimeout(timer);
      clearTimeout(forceKillTimer);
      callback();
    };

    child.once('error', error => {
      finish(() => reject(new Error(`could not start ${command}: ${error.message}`)));
    });

    child.once('close', (code, signal) => {
      finish(() => {
        if (timedOut) {
          reject(commandError(
            `${command} timed out after ${timeoutMs}ms`,
            { stdout, stderr, code, signal }
          ));
          return;
        }
        resolve({ stdout, stderr, code, signal });
      });
    });
  });
}

function diagnosticText(result) {
  const sections = [];
  const stdout = String(result?.stdout || '').trim();
  const stderr = String(result?.stderr || '').trim();
  if (stdout) {
    sections.push(`stdout:\n${stdout}`);
  }
  if (stderr) {
    sections.push(`stderr:\n${stderr}`);
  }
  return sections.length > 0 ? `\n${sections.join('\n')}` : '';
}

function commandError(message, result) {
  return new Error(`${message}${diagnosticText(result)}`);
}

function requireSuccessfulCommand(label, result) {
  if (result.code !== 0) {
    throw commandError(
      `${label} exited with code ${result.code ?? 'null'}${result.signal ? ` (${result.signal})` : ''}`,
      result
    );
  }
}

function normalizeResponse(value) {
  return String(value || '')
    .replace(/\u001B\][^\u0007]*(?:\u0007|\u001B\\)/g, '')
    .replace(/\u001B\[[0-?]*[ -/]*[@-~]/g, '')
    .replace(/\r\n?/g, '\n')
    .trim();
}

function requireHello(runtime, response, result) {
  const normalized = normalizeResponse(response);
  if (normalized !== EXPECTED_RESPONSE) {
    throw commandError(
      `${runtime} response mismatch: expected ${JSON.stringify(EXPECTED_RESPONSE)}, received ${JSON.stringify(normalized)}`,
      result
    );
  }
}

function helloPrompt() {
  return 'just respond with hello';
}

function ollamaMcpPrompt() {
  return [
    'Call the return_hello tool from notty_relay_smoke exactly once with an empty object.',
    'Then respond with only the tool result.'
  ].join(' ');
}

async function readJsonRequest(request) {
  const chunks = [];
  for await (const chunk of request) chunks.push(chunk);
  return JSON.parse(Buffer.concat(chunks).toString('utf8'));
}

async function startOllamaMcpFixture() {
  let toolCalls = 0;
  const httpServer = http.createServer(async (request, response) => {
    const requestUrl = new URL(request.url || '/', 'http://127.0.0.1');
    if (requestUrl.pathname !== '/mcp' || request.method !== 'POST') {
      response.writeHead(405, { 'content-type': 'application/json' });
      response.end(JSON.stringify({
        jsonrpc: '2.0',
        error: { code: -32000, message: 'Method not allowed.' },
        id: null
      }));
      return;
    }

    let mcpServer;
    let transport;
    try {
      const body = await readJsonRequest(request);
      mcpServer = new Server(
        { name: 'notty-ollama-relay-smoke', version: '1.0.0' },
        { capabilities: { tools: {} } }
      );
      mcpServer.setRequestHandler(ListToolsRequestSchema, async () => ({
        tools: [{
          name: 'return_hello',
          description: 'Return the exact word hello for the Ollama relay smoke test.',
          inputSchema: {
            type: 'object',
            properties: {},
            additionalProperties: false
          }
        }]
      }));
      mcpServer.setRequestHandler(CallToolRequestSchema, async requestValue => {
        if (requestValue.params.name !== 'return_hello') {
          throw new Error(`unexpected smoke tool: ${requestValue.params.name}`);
        }
        toolCalls += 1;
        return { content: [{ type: 'text', text: EXPECTED_RESPONSE }] };
      });
      transport = new StreamableHTTPServerTransport({ sessionIdGenerator: undefined });
      await mcpServer.connect(transport);
      await transport.handleRequest(request, response, body);
    } catch (error) {
      if (!response.headersSent) {
        response.writeHead(500, { 'content-type': 'application/json' });
        response.end(JSON.stringify({
          jsonrpc: '2.0',
          error: { code: -32603, message: error.message || String(error) },
          id: null
        }));
      } else {
        response.destroy(error);
      }
    } finally {
      try {
        await transport?.close();
      } catch {
        // The request response may already have closed the stateless transport.
      }
      try {
        await mcpServer?.close();
      } catch {
        // Preserve the original fixture request result.
      }
    }
  });
  await new Promise((resolve, reject) => {
    httpServer.once('error', reject);
    httpServer.listen(0, '127.0.0.1', () => {
      httpServer.off('error', reject);
      resolve();
    });
  });
  const address = httpServer.address();
  if (!address || typeof address === 'string') {
    httpServer.close();
    throw new Error('unable to resolve Ollama MCP smoke fixture address');
  }
  return {
    url: `http://127.0.0.1:${address.port}/mcp`,
    get toolCalls() { return toolCalls; },
    close: () => new Promise(resolve => {
      httpServer.close(() => resolve());
      httpServer.closeAllConnections?.();
    })
  };
}

async function readLastMessage(runtime, outputPath, result) {
  try {
    return await readFile(outputPath, 'utf8');
  } catch (error) {
    throw commandError(
      `${runtime} did not write its final response to ${outputPath}: ${error.message}`,
      result
    );
  }
}

async function checkCodex(options) {
  const outputPath = path.join(options.tempDir, 'codex-response.txt');
  const args = [
    'exec',
    '--ephemeral',
    '--skip-git-repo-check',
    '--sandbox', 'read-only',
    '--color', 'never',
    '--output-last-message', outputPath
  ];
  if (options.codexModel) {
    args.push('--model', options.codexModel);
  }
  args.push(helloPrompt());

  const result = await runCommand(options.codexBin, args, {
    cwd: options.tempDir,
    env: runtimeEnv(),
    timeoutMs: options.timeoutMs
  });
  requireSuccessfulCommand('Codex', result);
  requireHello('Codex', await readLastMessage('Codex', outputPath, result), result);
}

async function checkAgy(options) {
  const args = [
    '--print-timeout', `${options.timeoutMs}ms`,
    '--mode', 'plan',
    '--sandbox'
  ];
  if (options.agyModel) {
    args.push('--model', options.agyModel);
  }
  args.push('--print', helloPrompt());

  const result = await runCommand(options.agyBin, args, {
    cwd: options.tempDir,
    env: runtimeEnv(),
    timeoutMs: options.timeoutMs
  });
  requireSuccessfulCommand('Agy', result);
  requireHello('Agy', result.stdout, result);
}

async function checkOllama(options) {
  const mcpFixture = await startOllamaMcpFixture();
  let prepared;
  let result;
  try {
    prepared = prepareOllamaCodexProvider({
      endpoint: options.ollamaEndpoint,
      model: options.ollamaModel,
      runtimeDir: options.tempDir,
      isolationKey: 'collab-real-runtime-smoke',
      curlBin: options.curlBin,
      timeoutMs: Math.min(options.timeoutMs, 30_000),
      environment: scrubbedChildEnv()
    });

    const outputPath = path.join(options.tempDir, 'ollama-response.txt');
    const args = [
      ...prepared.args,
      '-c', `mcp_servers.notty_relay_smoke.url=${JSON.stringify(mcpFixture.url)}`,
      '-c', 'mcp_servers.notty_relay_smoke.required=true',
      '-c', 'mcp_servers.notty_relay_smoke.enabled_tools=["return_hello"]',
      '-c', 'features.multi_agent=false',
      '-c', 'features.plugins=false',
      '-c', 'features.remote_plugin=false',
      '-c', 'model_reasoning_effort="low"',
      'exec',
      '--ephemeral',
      '--skip-git-repo-check',
      '--sandbox', 'read-only',
      '--color', 'never',
      '--output-last-message', outputPath,
      ollamaMcpPrompt()
    ];
    const command = buildOllamaCodexRelayCommand([options.codexBin, ...args]);
    result = await runCommand(command[0], command.slice(1), {
      cwd: options.tempDir,
      env: runtimeEnv(),
      timeoutMs: options.timeoutMs
    });
    requireSuccessfulCommand(`Ollama (${options.ollamaModel})`, result);
    requireHello(
      `Ollama (${options.ollamaModel})`,
      await readLastMessage('Ollama', outputPath, result),
      result
    );
    if (mcpFixture.toolCalls !== 1) {
      throw commandError(
        `Ollama relay MCP call mismatch: expected 1 call, received ${mcpFixture.toolCalls}`,
        result
      );
    }
  } finally {
    try {
      await mcpFixture.close();
    } finally {
      if (prepared?.catalogPath) {
        removeOllamaModelCatalog(prepared.catalogPath, {
          runtimeDir: options.tempDir,
          environment: scrubbedChildEnv()
        });
      }
    }
  }
}

async function runCheck(label, check, failures) {
  log(`RUN ${label}`);
  try {
    await check();
    log(`PASS ${label}`);
  } catch (error) {
    const message = error?.stack || error?.message || String(error);
    failures.push(`${label}: ${message}`);
    log(`FAIL ${label}\n${message}`);
  }
}

async function main() {
  if (process.env[ENABLE_ENV] !== '1') {
    log(`SKIP: set ${ENABLE_ENV}=1 to run authenticated provider checks.`);
    return;
  }

  const tempDir = await mkdtemp(path.join(os.tmpdir(), 'notty-collab-runtime-smoke-'));
  const options = {
    tempDir,
    timeoutMs: positiveInteger(process.env.COLLAB_SMOKE_TIMEOUT_MS, DEFAULT_TIMEOUT_MS),
    codexBin: String(process.env.CODEX_BIN || 'codex'),
    codexModel: String(process.env.COLLAB_SMOKE_CODEX_MODEL || '').trim(),
    agyBin: String(process.env.AGY_BIN || 'agy'),
    agyModel: String(process.env.COLLAB_SMOKE_AGY_MODEL || '').trim(),
    curlBin: String(process.env.CURL_BIN || 'curl'),
    ollamaEndpoint: String(process.env.OLLAMA_HOST || '').trim(),
    ollamaModel: String(process.env.COLLAB_SMOKE_OLLAMA_MODEL || 'ornith:9b').trim()
  };
  const failures = [];

  try {
    if (!options.ollamaModel) {
      throw new Error('COLLAB_SMOKE_OLLAMA_MODEL must not be empty.');
    }

    await runCheck('Codex', () => checkCodex(options), failures);
    await runCheck('Agy', () => checkAgy(options), failures);
    await runCheck(
      `Ollama via Codex (${options.ollamaModel})`,
      () => checkOllama(options),
      failures
    );
  } finally {
    await rm(tempDir, { recursive: true, force: true });
  }

  if (failures.length > 0) {
    throw new Error(`${failures.length} real-runtime smoke check(s) failed.`);
  }

  log('PASS all real-runtime checks returned exactly "hello".');
}

main().catch(error => {
  log(`FAILED: ${error?.stack || error?.message || error}`);
  process.exitCode = 1;
});
