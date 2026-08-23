'use strict';

const assert = require('node:assert/strict');
const { spawn } = require('node:child_process');
const fs = require('node:fs');
const http = require('node:http');
const net = require('node:net');
const path = require('node:path');
const test = require('node:test');

const project = path.resolve(__dirname, '..');
const packageManifest = require('../package.json');

const DEV_FIXTURE_PATHS = [
  'components',
  'modules',
  'pages',
  'styles',
  'next.config.js',
  'package.json',
];

function copyDevFixture(target) {
  const moduleTests = path.join(project, 'modules', '__tests__');
  for (const relativePath of DEV_FIXTURE_PATHS) {
    fs.cpSync(
      path.join(project, relativePath),
      path.join(target, relativePath),
      {
        recursive: true,
        filter: source => (
          source !== moduleTests
          && !source.startsWith(`${moduleTests}${path.sep}`)
        ),
      },
    );
  }

  const configPath = path.join(target, 'next.config.js');
  const config = fs.readFileSync(configPath, 'utf8');
  const isolatedConfig = config.replace(
    'root: __dirname',
    `root: ${JSON.stringify(project)}`,
  );
  assert.notEqual(isolatedConfig, config, 'fixture must override its Turbopack resolution root');
  fs.writeFileSync(configPath, isolatedConfig);
}

function reserveLoopbackPort() {
  return new Promise((resolve, reject) => {
    const server = net.createServer();
    server.once('error', reject);
    server.listen(0, '127.0.0.1', () => {
      const address = server.address();
      server.close(error => {
        if (error) {
          reject(error);
          return;
        }
        resolve(address.port);
      });
    });
  });
}

function requestStatus(port, pathname) {
  return new Promise((resolve, reject) => {
    const request = http.get({
      host: '127.0.0.1',
      port,
      path: pathname,
      timeout: 1_000,
    }, response => {
      response.resume();
      response.once('end', () => resolve(response.statusCode));
    });
    request.once('timeout', () => request.destroy(new Error('request timed out')));
    request.once('error', reject);
  });
}

async function waitForPage(child, output, port, pathname) {
  const deadline = Date.now() + 30_000;
  let lastError;

  while (Date.now() < deadline) {
    if (child.exitCode !== null) {
      throw new Error(`development server exited with ${child.exitCode}\n${output.value}`);
    }

    try {
      const status = await requestStatus(port, pathname);
      if (status === 200) {
        return;
      }
      if (status >= 500) {
        throw new Error(`${pathname} returned HTTP ${status}\n${output.value}`);
      }
      lastError = new Error(`${pathname} returned HTTP ${status}`);
    } catch (error) {
      if (/returned HTTP 5\d\d/.test(error.message)) {
        throw error;
      }
      lastError = error;
    }

    await new Promise(resolve => setTimeout(resolve, 100));
  }

  throw new Error(`development server did not serve ${pathname}: ${lastError}\n${output.value}`);
}

async function stopProcessGroup(child) {
  if (child.exitCode !== null) {
    return;
  }

  const exited = new Promise(resolve => child.once('exit', resolve));
  try {
    process.kill(-child.pid, 'SIGTERM');
  } catch (error) {
    if (error.code !== 'ESRCH') {
      throw error;
    }
  }

  let forceKillTimeout;
  const stopped = await Promise.race([
    exited.then(() => true),
    new Promise(resolve => {
      forceKillTimeout = setTimeout(() => resolve(false), 5_000);
    }),
  ]);
  clearTimeout(forceKillTimeout);
  if (!stopped) {
    try {
      process.kill(-child.pid, 'SIGKILL');
    } catch (error) {
      if (error.code !== 'ESRCH') {
        throw error;
      }
    }
    await exited;
  }
}

test('lifecycle scripts pin the intended NODE_ENV', () => {
  assert.equal(packageManifest.scripts.dev, 'NODE_ENV=development next dev');
  assert.equal(packageManifest.scripts.build, 'NODE_ENV=production next build');
  assert.equal(packageManifest.scripts.start, 'NODE_ENV=production next start');
});

test('dev server renders both routes when its parent NODE_ENV is production', {
  timeout: 45_000,
}, async () => {
  const fixture = fs.mkdtempSync(path.join(project, '.dev-runtime-'));
  const port = await reserveLoopbackPort();
  const output = { value: '' };
  let child;

  try {
    copyDevFixture(fixture);
    child = spawn('npm', [
      'run',
      'dev',
      '--',
      '--hostname',
      '127.0.0.1',
      '--port',
      String(port),
    ], {
      cwd: fixture,
      detached: true,
      env: { ...process.env, NODE_ENV: 'production' },
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    child.stdout.on('data', chunk => {
      output.value += chunk;
    });
    child.stderr.on('data', chunk => {
      output.value += chunk;
    });

    await waitForPage(child, output, port, '/');
    await waitForPage(child, output, port, '/policy-review');

    assert.doesNotMatch(output.value, /non-standard ["']NODE_ENV["'] value/i);
    assert.doesNotMatch(output.value, /jsxDEV.*is not a function/i);
  } finally {
    if (child) {
      await stopProcessGroup(child);
    }
    fs.rmSync(fixture, { recursive: true, force: true });
  }
});
