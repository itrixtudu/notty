#!/usr/bin/env node

import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { buildWsUrl, resolveServerAddress } from '../lib/serverAddress.js';

const { port, bindHost, publicHost } = resolveServerAddress();
const path = '/ws/terminals';
const explicitUrl = process.env.NOTTY_PUBLIC_WS_URL;
const fallbackUrl = buildWsUrl({ host: publicHost, port, path });
const url = explicitUrl || fallbackUrl;

const banner = [
  '[terminal-ui]',
  'WebSocket bridge',
  `-> ${url}`,
  explicitUrl ? '(NOTTY_PUBLIC_WS_URL in effect)' : `(PORT ${port}, host ${publicHost})`
].join(' ');

console.log(banner);

const serverPath = fileURLToPath(new URL('../server.js', import.meta.url));

const child = spawn(process.execPath, [serverPath, ...process.argv.slice(2)], {
  stdio: 'inherit',
  env: {
    ...process.env,
    NODE_ENV: 'development',
    NOTTY_MODE: 'next'
  }
});

child.on('exit', (code, signal) => {
  if (signal) {
    process.kill(process.pid, signal);
    return;
  }
  process.exit(code ?? 0);
});
