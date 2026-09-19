'use strict';

const assert = require('node:assert/strict');
const childProcess = require('node:child_process');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const test = require('node:test');
const { pathToFileURL } = require('node:url');

const repository = path.resolve(__dirname, '..');

function temporaryDirectory(t, prefix) {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), prefix));
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  return directory;
}

async function importModule(relativePath) {
  return import(pathToFileURL(path.join(repository, relativePath)).href);
}

test('Guard auth reset worker refuses a root workspace identity', async () => {
  const { executeAuthResetWorker } = await importModule(
    'lib/guardd/auth-reset-worker.js',
  );
  assert.throws(
    () => executeAuthResetWorker(['/tmp/state', '/tmp/workspace', 'workspace-id', '0', '0']),
    /non-root workspace owner and group/,
  );
});

test('Guard auth reset derives daemon state and resets it transactionally', async (t) => {
  const fixture = temporaryDirectory(t, 'nosh-guard-auth-reset-');
  const stateRoot = path.join(fixture, 'guard-state');
  const workspace = path.join(fixture, 'workspace');
  fs.mkdirSync(stateRoot, { mode: 0o700 });
  fs.mkdirSync(workspace, { mode: 0o700 });

  const { AuthStateDatabase, workspaceAuthId } = await importModule('lib/authState.js');
  const { prepareRunnerAuthState } = await importModule('lib/guardd/service.js');
  const { resetGuardWorkspaceAuthState } = await importModule('lib/guardd/auth-state.js');
  const authStateDir = await prepareRunnerAuthState(stateRoot, workspace);
  let state = new AuthStateDatabase({
    stateDirectory: authStateDir,
    workspaceRoot: workspace,
    workspaceId: workspaceAuthId(workspace),
  });
  state.database.prepare(`
    INSERT INTO oauth_clients(
      client_id, client_name, redirect_uris_json, grant_types_json,
      response_types_json, token_endpoint_auth_method, created_at, revoked_at
    ) VALUES (?, ?, ?, ?, ?, ?, ?, NULL)
  `).run(
    'guard-client',
    'Guard test',
    '["http://127.0.0.1/callback"]',
    '["authorization_code"]',
    '["code"]',
    'none',
    Date.now(),
  );
  state.database.prepare(`
    INSERT INTO spawn_otps(
      uuid, token_hash, source, created_at, expires_at, consumed_at, revoked_at
    ) VALUES (?, ?, ?, ?, NULL, NULL, NULL)
  `).run('guard-otp', 'a'.repeat(64), 'operator-cli', Date.now());
  state.close();

  const reset = await resetGuardWorkspaceAuthState(stateRoot, workspace);
  assert.equal(reset.workspaceId, workspaceAuthId(workspace));
  assert.equal(reset.workspace, fs.realpathSync(workspace));
  assert.equal(reset.authStateDir, authStateDir);

  state = new AuthStateDatabase({
    stateDirectory: authStateDir,
    workspaceRoot: workspace,
    workspaceId: workspaceAuthId(workspace),
  });
  assert.equal(state.database.prepare('SELECT COUNT(*) AS count FROM oauth_clients').get().count, 0);
  assert.equal(
    typeof state.database.prepare('SELECT revoked_at FROM spawn_otps').get().revoked_at,
    'number',
  );
  assert.equal(
    state.database.prepare(`
      SELECT reason FROM auth_revocations ORDER BY revocation_id DESC LIMIT 1
    `).get().reason,
    'operator_reset',
  );
  state.close();
});

test('Guard auth reset relocates for the dropped worker and restores on failure', async (t) => {
  const fixture = temporaryDirectory(t, 'nosh-guard-auth-relocation-');
  const stateRoot = path.join(fixture, 'guard-state');
  const workspace = path.join(fixture, 'workspace');
  fs.mkdirSync(stateRoot, { mode: 0o700 });
  fs.mkdirSync(workspace, { mode: 0o700 });

  const { workspaceAuthId } = await importModule('lib/authState.js');
  const { prepareRunnerAuthState } = await importModule('lib/guardd/service.js');
  const { resetGuardWorkspaceAuthState } = await importModule('lib/guardd/auth-state.js');
  const authStateDir = await prepareRunnerAuthState(stateRoot, workspace);
  const original = fs.lstatSync(authStateDir);
  let workerStateDir = null;

  await assert.rejects(
    resetGuardWorkspaceAuthState(stateRoot, workspace, {
      async executeWorker(input) {
        workerStateDir = input.authStateDir;
        assert.ok(path.basename(workerStateDir).startsWith(
          `.nosh-guard-auth-reset-${workspaceAuthId(workspace)}-`,
        ));
        assert.ok(path.relative(stateRoot, workerStateDir).startsWith(`..${path.sep}`));
        const relocated = fs.lstatSync(workerStateDir);
        assert.equal(relocated.ino, original.ino);
        assert.equal(relocated.uid, original.uid);
        assert.equal(relocated.mode & 0o7777, 0o700);

        const placeholder = fs.lstatSync(authStateDir);
        assert.notEqual(placeholder.ino, original.ino);
        assert.equal(placeholder.mode & 0o7777, 0o700);
        assert.deepEqual(fs.readdirSync(authStateDir), []);
        throw new Error('injected worker failure');
      },
    }),
    /injected worker failure/,
  );

  assert.ok(workerStateDir);
  assert.equal(fs.existsSync(workerStateDir), false);
  const restored = fs.lstatSync(authStateDir);
  assert.equal(restored.ino, original.ino);
  assert.equal(restored.uid, original.uid);
  assert.equal(restored.gid, original.gid);
  assert.equal(restored.mode & 0o7777, 0o700);
});

test('Guard auth reset is exposed only through the management client contract', async (t) => {
  const fixture = temporaryDirectory(t, 'nosh-guard-auth-rpc-');
  const socketPath = path.join(fixture, 'guard.sock');
  const stateRoot = path.join(fixture, 'state');
  const workspace = path.join(fixture, 'workspace');
  fs.mkdirSync(stateRoot, { mode: 0o700 });
  fs.mkdirSync(workspace, { mode: 0o700 });

  const { GuardClient } = await importModule('lib/guardd/client.js');
  const { createGuardServer } = await importModule('lib/guardd/server.js');
  const requests = [];
  const service = {
    store: { root: stateRoot },
    async initialize() {},
    health() { return { ok: true }; },
  };
  const buildService = { async initialize() {} };
  const { server } = await createGuardServer({
    service,
    buildService,
    watchdogIntervalMs: 0,
    async resetAuthState(receivedRoot, receivedWorkspace) {
      requests.push([receivedRoot, receivedWorkspace]);
      return { workspaceId: 'workspace-test', resetAt: 1234 };
    },
  });
  await new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(socketPath, resolve);
  });
  t.after(() => new Promise((resolve) => server.close(resolve)));

  const client = new GuardClient({ socketPath });
  assert.deepEqual(await client.resetAuth(workspace), {
    workspaceId: 'workspace-test',
    resetAt: 1234,
  });
  assert.deepEqual(requests, [[stateRoot, workspace]]);
});

test('Guard auth CLI requires root for live reset but not dry-run', async () => {
  const { commandAuth } = await importModule('scripts/nosh-guard.mjs');
  const workdir = '/workspace/project';

  await assert.rejects(
    commandAuth(['reset', '--workdir', workdir], {
      geteuid: () => 1000,
      client: { async resetAuth() { throw new Error('must not contact daemon'); } },
      print() {},
    }),
    (error) => error.code === 'GUARD_ROOT_REQUIRED',
  );

  const dryRuns = [];
  assert.equal(await commandAuth([
    'reset',
    '--workdir', workdir,
    '--socket', '/run/test-guard.sock',
    '--dry-run',
  ], {
    geteuid: () => 1000,
    print(value) { dryRuns.push(value); },
  }), 0);
  assert.deepEqual(dryRuns, [{
    dryRun: true,
    command: 'auth reset',
    workdir,
    socket: '/run/test-guard.sock',
  }]);

  const calls = [];
  const receipts = [];
  assert.equal(await commandAuth(['reset', '--workdir', workdir], {
    geteuid: () => 0,
    client: {
      async resetAuth(value) {
        calls.push(value);
        return { workspaceId: 'root-reset', resetAt: 5678 };
      },
    },
    print(value) { receipts.push(value); },
  }), 0);
  assert.deepEqual(calls, [workdir]);
  assert.deepEqual(receipts, [{ workspaceId: 'root-reset', resetAt: 5678 }]);
});

test('Nosh secure reset delegates without mutating legacy XDG state', (t) => {
  const fixture = temporaryDirectory(t, 'nosh-auth-reset-launcher-');
  const workspace = path.join(fixture, 'workspace');
  const home = path.join(fixture, 'home');
  const stateHome = path.join(fixture, 'xdg-state');
  fs.mkdirSync(workspace, { mode: 0o700 });
  fs.mkdirSync(home, { mode: 0o700 });
  const environment = {
    PATH: process.env.PATH,
    HOME: home,
    XDG_STATE_HOME: stateHome,
  };

  const secure = childProcess.spawnSync('bash', [
    path.join(repository, 'nosh.sh'),
    'auth',
    'reset',
    '--secure',
    '--workdir', workspace,
    '--dry-run',
  ], { cwd: workspace, encoding: 'utf8', env: environment });
  assert.equal(secure.status, 0, `${secure.stdout}${secure.stderr}`);
  assert.match(
    secure.stdout,
    /nosh-guard auth reset --workdir .*workspace --dry-run$/m,
  );
  assert.doesNotMatch(secure.stdout, /^docker run /m);
  assert.equal(fs.existsSync(stateHome), false);

  const legacy = childProcess.spawnSync('bash', [
    path.join(repository, 'nosh.sh'),
    'auth',
    'reset',
    '--workdir', workspace,
    '--dry-run',
  ], { cwd: workspace, encoding: 'utf8', env: environment });
  assert.equal(legacy.status, 0, `${legacy.stdout}${legacy.stderr}`);
  assert.match(legacy.stdout, /^docker run .*auth-state-cli\.mjs reset$/m);
  assert.equal(fs.existsSync(stateHome), false);

  const otp = childProcess.spawnSync('bash', [
    path.join(repository, 'nosh.sh'),
    'auth',
    'otp',
    '--secure',
    '--workdir', workspace,
    '--dry-run',
  ], { cwd: workspace, encoding: 'utf8', env: environment });
  assert.notEqual(otp.status, 0);
  assert.match(otp.stderr, /Guard OTPs are minted through the mTLS gateway/);
});

test('Guard host bundle carries top-level auth dependencies', () => {
  const builder = fs.readFileSync(
    path.join(repository, 'scripts/build-nosh-guard-host-bundle-container.sh'),
    'utf8',
  );
  const installer = fs.readFileSync(
    path.join(repository, 'scripts/install-nosh-guard-host-bundle.sh'),
    'utf8',
  );
  for (const dependency of ['authState.js', 'guardGatewayAuth.js']) {
    assert.ok(builder.includes(`lib/${dependency}`));
    assert.ok(installer.includes(`payload/lib/${dependency}`));
  }
});
