'use strict';

const assert = require('node:assert/strict');
const childProcess = require('node:child_process');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');

const appRoot = path.resolve(__dirname, '..');
const screenPath = path.join(appRoot, 'scripts', 'notty-lockdown-screen.sh');

function waitForOutput(stream, pattern, timeoutMs = 2000) {
  return new Promise((resolve, reject) => {
    let output = '';
    const timeout = setTimeout(() => reject(new Error(`timed out waiting for ${pattern}`)), timeoutMs);
    stream.on('data', (chunk) => {
      output += chunk.toString('utf8');
      if (pattern.test(output)) {
        clearTimeout(timeout);
        resolve(output);
      }
    });
  });
}

function waitForExit(child, timeoutMs = 2000) {
  return new Promise((resolve, reject) => {
    const timeout = setTimeout(() => {
      child.kill('SIGKILL');
      reject(new Error('lockdown screen did not exit after SIGTERM'));
    }, timeoutMs);
    child.once('exit', (code, signal) => {
      clearTimeout(timeout);
      resolve({ code, signal });
    });
  });
}

test('server lockdown uses the project-owned status screen', () => {
  const server = fs.readFileSync(path.join(appRoot, 'server.js'), 'utf8');
  assert.match(server, /scripts\/notty-lockdown-screen\.sh/);
  assert.doesNotMatch(server, /art\/acid\/klock/);
  assert.ok((fs.statSync(screenPath).mode & 0o111) !== 0, 'status screen must be executable');
});

test('lockdown status screen consumes input without treating it as a password', async (t) => {
  const child = childProcess.spawn(screenPath, [], {
    cwd: appRoot,
    stdio: ['pipe', 'pipe', 'pipe'],
  });
  t.after(() => {
    if (!child.killed) child.kill('SIGKILL');
  });

  const initialOutput = await waitForOutput(child.stdout, /NOTTY LOCKDOWN VIEW ACTIVE/);
  assert.match(initialOutput, /does not disable MCP or terminal WebSocket control/);
  assert.match(initialOutput, /does not accept a password or change service policy/);

  let laterOutput = '';
  child.stdout.on('data', (chunk) => {
    laterOutput += chunk.toString('utf8');
  });
  child.stdin.write('must-not-echo\n');
  await new Promise((resolve) => setTimeout(resolve, 50));
  assert.doesNotMatch(laterOutput, /must-not-echo/);

  const exitPromise = waitForExit(child);
  child.kill('SIGTERM');
  const result = await exitPromise;
  assert.ok(result.code === 0 || result.signal === 'SIGTERM');
});

test('lockdown status screen contains no network or filesystem writer', () => {
  const source = fs.readFileSync(screenPath, 'utf8');
  assert.doesNotMatch(source, /\b(?:curl|wget|nc|ncat|npm|node)\b/);
  assert.doesNotMatch(source, /(?:^|\s)(?:>|>>|tee)(?:\s|$)/m);
});
