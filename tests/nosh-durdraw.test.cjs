'use strict';

const assert = require('node:assert/strict');
const childProcess = require('node:child_process');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const test = require('node:test');

const appRoot = path.resolve(__dirname, '..');
const noshPath = path.join(appRoot, 'scripts/nosh.sh');

function createFixture(t) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'notty-nosh-durdraw-'));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const home = path.join(root, 'home');
  const workspace = path.join(root, 'workspace');
  fs.mkdirSync(home, { recursive: true });
  fs.mkdirSync(workspace, { recursive: true });
  return { home, workspace };
}

function runNosh(fixture, profiles = []) {
  const result = childProcess.spawnSync('bash', [
    noshPath,
    'start',
    '--dry-run',
    '--noauth',
    '--otp',
    'fixed-test-otp',
    '--no-start-app',
    '--workdir',
    fixture.workspace,
    ...profiles.flatMap((profile) => ['-p', profile]),
  ], {
    cwd: fixture.workspace,
    encoding: 'utf8',
    env: {
      PATH: process.env.PATH,
      HOME: fixture.home,
      XDG_CONFIG_HOME: path.join(fixture.home, '.config'),
    },
  });
  const output = `${result.stdout || ''}${result.stderr || ''}`;
  const dockerRun = String(result.stdout || '')
    .split(/\r?\n/)
    .find((line) => line.startsWith('docker run ')) || '';
  return { ...result, output, dockerRun };
}

function runNoshWithArgs(fixture, args = []) {
  return childProcess.spawnSync('bash', [
    noshPath,
    'start',
    '--dry-run',
    '--noauth',
    '--otp',
    'fixed-test-otp',
    '--no-start-app',
    '--workdir',
    fixture.workspace,
    ...args,
  ], {
    cwd: fixture.workspace,
    encoding: 'utf8',
    env: {
      PATH: process.env.PATH,
      HOME: fixture.home,
      XDG_CONFIG_HOME: path.join(fixture.home, '.config'),
    },
  });
}

test('Nosh durdraw profile enables the toolset and persists user configuration', (t) => {
  const fixture = createFixture(t);
  const result = runNosh(fixture, ['durdraw']);
  const configPath = path.join(fixture.home, '.durdraw');

  assert.equal(result.status, 0, result.output);
  assert.deepEqual(
    result.dockerRun.match(/NOTTY_NOSH_PROFILES=[^ ]+/g),
    ['NOTTY_NOSH_PROFILES=durdraw'],
  );
  assert.deepEqual(
    result.dockerRun.match(/NOTTY_MCP_TOOLSET=[^ ]+/g),
    ['NOTTY_MCP_TOOLSET=durdraw'],
  );
  assert.match(
    result.dockerRun,
    new RegExp(`${configPath.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}:${configPath.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}:rw`),
  );
});

test('Nosh keeps the full MCP toolset when the durdraw profile is not selected', (t) => {
  const fixture = createFixture(t);
  const result = runNosh(fixture);

  assert.equal(result.status, 0, result.output);
  assert.doesNotMatch(result.dockerRun, /NOTTY_MCP_TOOLSET=/);
  assert.doesNotMatch(result.dockerRun, /NOTTY_NOSH_PROFILES=durdraw/);
});

test('Nosh MCP enforcement is opt-in and forwards a repeated allowlist', (t) => {
  const fixture = createFixture(t);
  const unfiltered = runNoshWithArgs(fixture);
  assert.equal(unfiltered.status, 0, unfiltered.stderr);
  assert.doesNotMatch(unfiltered.stdout, /NOTTY_MCP_ALLOWED_TOOLS=/);

  const filtered = runNoshWithArgs(fixture, [
    '--allow-mcp-tool', 'read_terminal',
    '--allow-mcp-tool=list_terminals',
  ]);
  assert.equal(filtered.status, 0, filtered.stderr);
  assert.match(filtered.stdout, /NOTTY_MCP_ALLOWED_TOOLS=read_terminal,list_terminals/);
  assert.match(filtered.stderr, /MCP tool filter active: read_terminal,list_terminals/);
});

test('Nosh help advertises the durdraw profile', () => {
  const result = childProcess.spawnSync('bash', [noshPath, '--help'], {
    encoding: 'utf8',
    env: { PATH: process.env.PATH, HOME: process.env.HOME },
  });

  assert.equal(result.status, 0, result.stderr);
  assert.match(result.stdout, /codex,durdraw,zig,arduino/);
});

test('the common Nosh image bundles PATH-visible vendored Durdraw commands', () => {
  const dockerfile = fs.readFileSync(path.join(appRoot, 'Dockerfile.nosh'), 'utf8');

  assert.match(dockerfile, /COPY ansi\/dd \/opt\/durdraw\//);
  assert.match(
    dockerfile,
    /ln -s \/opt\/durdraw\/start-durdraw \/usr\/local\/bin\/durdraw/,
  );
  assert.match(
    dockerfile,
    /ln -s \/opt\/durdraw\/durview \/usr\/local\/bin\/durview/,
  );
  assert.match(dockerfile, /test "\$\(durdraw --version\)" = "0\.29\.0"/);
  assert.match(dockerfile, /test "\$\(durview --version\)" = "0\.29\.0"/);
  assert.match(
    dockerfile,
    /test "\$\(durview --version\)" = "0\.29\.0"\n\nRUN echo/,
    'the /tmp Durdraw smoke check must end before the /app Next.js build layer',
  );
});

test('Durdraw MCP launches the image command instead of a workspace-relative script', async () => {
  const { buildDurdrawCommand } = await import('../lib/mcpDurdraw.js');

  assert.deepEqual(buildDurdrawCommand({}), { command: 'durdraw' });
  assert.deepEqual(
    buildDurdrawCommand({
      filename: 'art packs/demo.ans',
      colorMode: '256',
      noMouse: true,
    }),
    {
      command: "durdraw --256color --nomouse 'art packs/demo.ans'",
    },
  );
});
