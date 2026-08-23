#!/usr/bin/env node

// mcp-sse-smoke.js
// Smoke test MCP over HTTP (streamable) and SSE using scripts/call-tool.js.

import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { setTimeout as delay } from 'node:timers/promises';
import path from 'node:path';
import process from 'node:process';

const DEFAULT_TARGETS = ['http://localhost:3000/mcp', 'http://localhost:3000/sse'];
const SCRIPT_DIR = path.dirname(fileURLToPath(import.meta.url));
const CALL_TOOL = path.join(SCRIPT_DIR, 'call-tool.js');

function usage() {
  console.error('Usage: node scripts/mcp-sse-smoke.js [--targets url1,url2] [--otp TOKEN] [--keep]');
  console.error('Defaults:');
  console.error(`  --targets ${DEFAULT_TARGETS.join(',')}`);
  console.error('  --otp (from MCP_SPAWN_OTP or NOTTY_MCP_SPAWN_OTP env)');
  console.error('Examples:');
  console.error('  node scripts/mcp-sse-smoke.js --otp "$NOTTY_MCP_SPAWN_OTP"');
  console.error('  node scripts/mcp-sse-smoke.js --targets http://localhost:3000/mcp,http://localhost:3000/mcp/sse');
}

function parseArgs(argv) {
  let targets = null;
  let otp = null;
  let keep = false;
  let help = false;

  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    if (arg === '--help' || arg === '-h') {
      help = true;
      continue;
    }
    if (arg === '--targets') {
      targets = argv[i + 1];
      i += 1;
      continue;
    }
    if (arg.startsWith('--targets=')) {
      targets = arg.slice('--targets='.length);
      continue;
    }
    if (arg === '--otp') {
      otp = argv[i + 1];
      i += 1;
      continue;
    }
    if (arg.startsWith('--otp=')) {
      otp = arg.slice('--otp='.length);
      continue;
    }
    if (arg === '--keep') {
      keep = true;
      continue;
    }
  }

  if (!otp) {
    otp = process.env.MCP_SPAWN_OTP || process.env.NOTTY_MCP_SPAWN_OTP || '';
  }

  const targetList = targets
    ? targets.split(',').map((entry) => entry.trim()).filter(Boolean)
    : DEFAULT_TARGETS.slice();

  return {
    targets: targetList,
    otp,
    keep,
    help
  };
}

function callTool(target, toolName, toolArgs) {
  const args = [target, toolName];
  if (toolArgs) {
    args.push(JSON.stringify(toolArgs));
  }
  args.push('--json');

  try {
    const stdout = execFileSync(CALL_TOOL, args, { encoding: 'utf8' });
    return JSON.parse(stdout);
  } catch (err) {
    const stderr = err?.stderr ? err.stderr.toString() : '';
    const message = stderr.trim() || err.message || 'Unknown error';
    throw new Error(`[mcp-smoke] call-tool failed for ${toolName} on ${target}: ${message}`);
  }
}

function parseToolPayload(response) {
  const text = response?.content?.[0]?.text ?? '';
  if (!text) {
    return { text: '', parsed: null };
  }

  try {
    return { text, parsed: JSON.parse(text) };
  } catch {
    return { text, parsed: null };
  }
}

function formatTargetLabel(target) {
  return target
    .replace(/^https?:\/\//i, '')
    .replace(/[^a-z0-9]+/gi, '-')
    .replace(/^-+|-+$/g, '')
    .slice(0, 48);
}

async function main() {
  const { targets, otp, keep, help } = parseArgs(process.argv.slice(2));
  if (help) {
    usage();
    process.exit(0);
  }

  if (targets.length === 0) {
    console.error('[mcp-smoke] No targets specified.');
    usage();
    process.exit(1);
  }

  console.error(`[mcp-smoke] Targets: ${targets.join(', ')}`);

  const spawnArgs = { cols: 80, rows: 30 };
  if (otp) {
    spawnArgs.otp = otp;
  }

  const spawnResponse = callTool(targets[0], 'spawn_terminal', spawnArgs);
  const spawnPayload = parseToolPayload(spawnResponse);

  if (spawnResponse.isError) {
    const code = spawnPayload.parsed?.error?.code;
    if (code === 'spawn_terminal_otp_required') {
      console.error('[mcp-smoke] Spawn OTP required. Pass --otp <token> or set MCP_SPAWN_OTP.');
    }
    console.error(`[mcp-smoke] spawn_terminal failed: ${spawnPayload.text || 'unknown error'}`);
    process.exit(1);
  }

  const terminalUuid = spawnPayload.parsed?.terminal_uuid;
  if (!terminalUuid) {
    console.error('[mcp-smoke] spawn_terminal response missing terminal_uuid.');
    process.exit(1);
  }

  console.error(`[mcp-smoke] Spawned terminal ${terminalUuid} via ${targets[0]}`);

  for (const target of targets) {
    const label = formatTargetLabel(target);
    callTool(target, 'write_terminal', {
      terminal_uuid: terminalUuid,
      data: `echo mcp-smoke-${label}\\r`
    });

    await delay(150);

    const readResponse = callTool(target, 'read_terminal', { terminal_uuid: terminalUuid });
    const readPayload = parseToolPayload(readResponse);
    if (readResponse.isError) {
      console.error(`[mcp-smoke] read_terminal failed on ${target}: ${readPayload.text}`);
      process.exitCode = 1;
    } else {
      const output = readPayload.parsed?.output ?? '';
      const bytes = typeof output === 'string' ? output.length : 0;
      const hasOutput =
        typeof readPayload.parsed?.has_output === 'boolean'
          ? readPayload.parsed.has_output
          : bytes > 0;
      console.error(
        `[mcp-smoke] ${target} read_terminal ${hasOutput ? 'ok' : 'empty'} (${bytes} bytes)`
      );
    }
  }

  if (keep) {
    console.error(`[mcp-smoke] --keep set; leaving terminal ${terminalUuid} running.`);
    return;
  }

  const killResponse = callTool(targets[0], 'kill_terminal', { terminal_uuid: terminalUuid });
  const killPayload = parseToolPayload(killResponse);
  if (killResponse.isError) {
    console.error(`[mcp-smoke] kill_terminal failed: ${killPayload.text}`);
    process.exitCode = 1;
  } else {
    console.error(`[mcp-smoke] kill_terminal ok for ${terminalUuid}`);
  }
}

main().catch((err) => {
  console.error(err?.message || err);
  process.exit(1);
});
