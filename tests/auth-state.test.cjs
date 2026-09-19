'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const test = require('node:test');

function temporaryRoot(t) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'notty-auth-state-'));
  fs.chmodSync(root, 0o700);
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  return root;
}

test('auth state creates a private per-workspace SQLite database', async (t) => {
  const root = temporaryRoot(t);
  const {
    AUTH_STATE_SCHEMA_VERSION,
    AuthStateDatabase
  } = await import('../lib/authState.js');
  const state = new AuthStateDatabase({
    env: {
      HOME: root,
      XDG_STATE_HOME: path.join(root, 'state'),
      NOTTY_WORKDIR: path.join(root, 'workspace')
    }
  });
  t.after(() => state.close());

  assert.match(state.location.workspaceId, /^[0-9a-f]{32}$/);
  assert.equal(fs.statSync(state.location.stateDirectory).mode & 0o777, 0o700);
  assert.equal(fs.statSync(state.location.databasePath).mode & 0o777, 0o600);
  assert.equal(
    state.database.prepare('PRAGMA quick_check').get().quick_check,
    'ok'
  );
  assert.equal(
    state.database.prepare('PRAGMA user_version').get().user_version,
    AUTH_STATE_SCHEMA_VERSION
  );
  assert.ok(
    state.database.prepare('PRAGMA table_info(oauth_refresh_families)').all()
      .some((column) => column.name === 'grant_id')
  );
  assert.equal(
    state.database.prepare(`
      SELECT COUNT(*) AS count
      FROM sqlite_schema
      WHERE type = 'index' AND name = 'oauth_refresh_grant_idx'
    `).get().count,
    1
  );
});

test('auth state migrates v1 families without guessing grant ownership', async (t) => {
  const root = temporaryRoot(t);
  const stateDirectory = path.join(root, 'state');
  const databasePath = path.join(stateDirectory, 'auth.sqlite3');
  fs.mkdirSync(stateDirectory, { mode: 0o700 });
  const { DatabaseSync } = require('node:sqlite');
  const legacy = new DatabaseSync(databasePath);
  // Preserve the historical DDL text exactly because schema validation also
  // detects weakened constraints by comparing SQLite's stored schema SQL.
  legacy.exec(`
  PRAGMA foreign_keys = ON;
  CREATE TABLE IF NOT EXISTS oauth_clients (
    client_id TEXT PRIMARY KEY,
    client_name TEXT NOT NULL,
    redirect_uris_json TEXT NOT NULL,
    grant_types_json TEXT NOT NULL,
    response_types_json TEXT NOT NULL,
    token_endpoint_auth_method TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    revoked_at INTEGER
  ) STRICT;

  CREATE TABLE IF NOT EXISTS oauth_grants (
    grant_id TEXT PRIMARY KEY,
    client_id TEXT NOT NULL REFERENCES oauth_clients(client_id),
    subject TEXT NOT NULL,
    scope TEXT NOT NULL,
    resource TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    revoked_at INTEGER
  ) STRICT;

  CREATE TABLE IF NOT EXISTS oauth_authorization_codes (
    code_hash TEXT PRIMARY KEY,
    grant_id TEXT NOT NULL REFERENCES oauth_grants(grant_id),
    client_id TEXT NOT NULL REFERENCES oauth_clients(client_id),
    subject TEXT NOT NULL,
    scope TEXT NOT NULL,
    resource TEXT NOT NULL,
    redirect_uri TEXT NOT NULL,
    code_challenge TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    consumed_at INTEGER
  ) STRICT;

  CREATE TABLE IF NOT EXISTS oauth_refresh_families (
    family_id TEXT PRIMARY KEY,
    client_id TEXT NOT NULL REFERENCES oauth_clients(client_id),
    subject TEXT NOT NULL,
    scope TEXT NOT NULL,
    resource TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    revoked_at INTEGER,
    replayed_at INTEGER
  ) STRICT;

  CREATE TABLE IF NOT EXISTS oauth_refresh_tokens (
    token_hash TEXT PRIMARY KEY,
    family_id TEXT NOT NULL REFERENCES oauth_refresh_families(family_id),
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    consumed_at INTEGER,
    revoked_at INTEGER,
    replaced_by_hash TEXT
  ) STRICT;

  CREATE TABLE IF NOT EXISTS oauth_access_tokens (
    token_hash TEXT PRIMARY KEY,
    family_id TEXT REFERENCES oauth_refresh_families(family_id),
    client_id TEXT NOT NULL REFERENCES oauth_clients(client_id),
    subject TEXT NOT NULL,
    scope TEXT NOT NULL,
    resource TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    revoked_at INTEGER
  ) STRICT;

  CREATE TABLE IF NOT EXISTS spawn_otps (
    uuid TEXT PRIMARY KEY,
    token_hash TEXT NOT NULL UNIQUE,
    source TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    expires_at INTEGER,
    consumed_at INTEGER,
    revoked_at INTEGER
  ) STRICT;

  CREATE TABLE IF NOT EXISTS auth_revocations (
    revocation_id INTEGER PRIMARY KEY AUTOINCREMENT,
    kind TEXT NOT NULL,
    target_id TEXT NOT NULL,
    reason TEXT NOT NULL,
    created_at INTEGER NOT NULL
  ) STRICT;

  CREATE INDEX IF NOT EXISTS oauth_codes_client_idx
    ON oauth_authorization_codes(client_id, expires_at);
  CREATE INDEX IF NOT EXISTS oauth_access_client_idx
    ON oauth_access_tokens(client_id, expires_at);
  CREATE INDEX IF NOT EXISTS oauth_access_family_idx
    ON oauth_access_tokens(family_id);
  CREATE INDEX IF NOT EXISTS oauth_refresh_family_idx
    ON oauth_refresh_tokens(family_id);
  CREATE INDEX IF NOT EXISTS spawn_otps_created_idx
    ON spawn_otps(created_at DESC);
  PRAGMA user_version = 1;
  `);
  const now = Date.now();
  legacy.prepare(`
    INSERT INTO oauth_clients(
      client_id, client_name, redirect_uris_json, grant_types_json,
      response_types_json, token_endpoint_auth_method, created_at
    ) VALUES (?, ?, ?, ?, ?, ?, ?)
  `).run(
    'legacy-client',
    'Legacy client',
    '["https://client.example/callback"]',
    '["authorization_code","refresh_token"]',
    '["code"]',
    'none',
    now
  );
  legacy.prepare(`
    INSERT INTO oauth_grants(
      grant_id, client_id, subject, scope, resource, created_at
    ) VALUES (?, ?, ?, ?, ?, ?)
  `).run('legacy-grant', 'legacy-client', 'alice', 'mcp:tools', 'https://notty.example/mcp', now);
  legacy.prepare(`
    INSERT INTO oauth_authorization_codes(
      code_hash, grant_id, client_id, subject, scope, resource,
      redirect_uri, code_challenge, created_at, expires_at, consumed_at
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `).run(
    'a'.repeat(64),
    'legacy-grant',
    'legacy-client',
    'alice',
    'mcp:tools',
    'https://notty.example/mcp',
    'https://client.example/callback',
    'b'.repeat(43),
    now,
    now + 300_000,
    now
  );
  legacy.prepare(`
    INSERT INTO oauth_refresh_families(
      family_id, client_id, subject, scope, resource, created_at, expires_at
    ) VALUES (?, ?, ?, ?, ?, ?, ?)
  `).run(
    'legacy-family',
    'legacy-client',
    'alice',
    'mcp:tools',
    'https://notty.example/mcp',
    now,
    now + 86_400_000
  );
  legacy.prepare(`
    INSERT INTO oauth_refresh_tokens(token_hash, family_id, created_at, expires_at)
    VALUES (?, ?, ?, ?)
  `).run('c'.repeat(64), 'legacy-family', now, now + 86_400_000);
  legacy.prepare(`
    INSERT INTO oauth_access_tokens(
      token_hash, family_id, client_id, subject, scope, resource, created_at, expires_at
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
  `).run(
    'd'.repeat(64),
    'legacy-family',
    'legacy-client',
    'alice',
    'mcp:tools',
    'https://notty.example/mcp',
    now,
    now + 3_600_000
  );
  legacy.close();
  fs.chmodSync(databasePath, 0o600);

  const {
    AUTH_STATE_SCHEMA_VERSION,
    AuthStateDatabase
  } = await import('../lib/authState.js');
  const migrated = new AuthStateDatabase({ stateDirectory });
  t.after(() => migrated.close());

  assert.equal(
    migrated.database.prepare('PRAGMA user_version').get().user_version,
    AUTH_STATE_SCHEMA_VERSION
  );
  const family = migrated.database.prepare(`
    SELECT grant_id, revoked_at, replayed_at
    FROM oauth_refresh_families
    WHERE family_id = 'legacy-family'
  `).get();
  assert.equal(family.grant_id, null);
  assert.equal(typeof family.revoked_at, 'number');
  assert.equal(family.replayed_at, null);
  assert.equal(
    typeof migrated.database.prepare(`
      SELECT revoked_at FROM oauth_refresh_tokens WHERE family_id = 'legacy-family'
    `).get().revoked_at,
    'number'
  );
  assert.equal(
    typeof migrated.database.prepare(`
      SELECT revoked_at FROM oauth_access_tokens WHERE family_id = 'legacy-family'
    `).get().revoked_at,
    'number'
  );
  assert.equal(
    typeof migrated.database.prepare(`
      SELECT revoked_at FROM oauth_grants WHERE grant_id = 'legacy-grant'
    `).get().revoked_at,
    'number'
  );
  assert.equal(
    migrated.database.prepare(`
      SELECT COUNT(*) AS count
      FROM auth_revocations
      WHERE kind = 'refresh_family'
        AND target_id = 'legacy-family'
        AND reason = 'schema_v2_unlinked_grant'
    `).get().count,
    1
  );
});

test('auth state rejects insecure directories and symbolic links', async (t) => {
  const root = temporaryRoot(t);
  const { AuthStateDatabase } = await import('../lib/authState.js');
  const insecure = path.join(root, 'insecure');
  fs.mkdirSync(insecure, { mode: 0o755 });
  fs.chmodSync(insecure, 0o755);
  assert.throws(
    () => new AuthStateDatabase({ stateDirectory: insecure }),
    /mode 0700/
  );

  const sticky = path.join(root, 'sticky');
  fs.mkdirSync(sticky, { mode: 0o700 });
  fs.chmodSync(sticky, 0o1700);
  assert.throws(
    () => new AuthStateDatabase({ stateDirectory: sticky }),
    /mode 0700/
  );

  const real = path.join(root, 'real');
  const linked = path.join(root, 'linked');
  fs.mkdirSync(real, { mode: 0o700 });
  fs.symlinkSync(real, linked, 'dir');
  assert.throws(
    () => new AuthStateDatabase({ stateDirectory: linked }),
    /symlinks|real directory/
  );

  const realParent = path.join(root, 'real-parent');
  const linkedParent = path.join(root, 'linked-parent');
  fs.mkdirSync(realParent, { mode: 0o700 });
  fs.mkdirSync(path.join(realParent, 'leaf'), { mode: 0o700 });
  fs.symlinkSync(realParent, linkedParent, 'dir');
  assert.throws(
    () => new AuthStateDatabase({ stateDirectory: path.join(linkedParent, 'leaf') }),
    /must not contain symlinks/
  );
});

test('auth state rejects database mode drift, hard links, and wrong ownership', async (t) => {
  const root = temporaryRoot(t);
  const { AuthStateDatabase } = await import('../lib/authState.js');

  const modeDirectory = path.join(root, 'mode-state');
  fs.mkdirSync(modeDirectory, { mode: 0o700 });
  const modeDatabase = path.join(modeDirectory, 'auth.sqlite3');
  fs.writeFileSync(modeDatabase, '', { mode: 0o644 });
  fs.chmodSync(modeDatabase, 0o644);
  assert.throws(
    () => new AuthStateDatabase({ stateDirectory: modeDirectory }),
    /mode 0600/
  );

  const specialModeDirectory = path.join(root, 'special-mode-state');
  fs.mkdirSync(specialModeDirectory, { mode: 0o700 });
  const specialModeDatabase = path.join(specialModeDirectory, 'auth.sqlite3');
  fs.writeFileSync(specialModeDatabase, '', { mode: 0o600 });
  fs.chmodSync(specialModeDatabase, 0o4600);
  assert.throws(
    () => new AuthStateDatabase({ stateDirectory: specialModeDirectory }),
    /mode 0600/
  );

  const hardlinkDirectory = path.join(root, 'hardlink-state');
  fs.mkdirSync(hardlinkDirectory, { mode: 0o700 });
  const databasePath = path.join(hardlinkDirectory, 'auth.sqlite3');
  fs.writeFileSync(databasePath, '', { mode: 0o600 });
  fs.linkSync(databasePath, path.join(root, 'auth-database-link'));
  assert.throws(
    () => new AuthStateDatabase({ stateDirectory: hardlinkDirectory }),
    /multiple hard links/
  );

  if (typeof process.geteuid === 'function' && process.geteuid() === 0) {
    const ownerDirectory = path.join(root, 'owner-state');
    fs.mkdirSync(ownerDirectory, { mode: 0o700 });
    fs.chownSync(ownerDirectory, 1, 1);
    assert.throws(
      () => new AuthStateDatabase({ stateDirectory: ownerDirectory }),
      /not owned by the current user/
    );
  }
});

test('auth reset removes OAuth authority and revokes OTPs transactionally', async (t) => {
  const root = temporaryRoot(t);
  const { AuthStateDatabase } = await import('../lib/authState.js');
  const state = new AuthStateDatabase({ stateDirectory: path.join(root, 'state') });
  t.after(() => state.close());
  const now = Date.now();
  state.database.prepare(`
    INSERT INTO oauth_clients(
      client_id, client_name, redirect_uris_json, grant_types_json,
      response_types_json, token_endpoint_auth_method, created_at
    ) VALUES (?, ?, ?, ?, ?, ?, ?)
  `).run('client', 'Client', '["http://127.0.0.1/callback"]', '["authorization_code"]', '["code"]', 'none', now);
  state.database.prepare(`
    INSERT INTO spawn_otps(uuid, token_hash, source, created_at)
    VALUES (?, ?, ?, ?)
  `).run('otp-id', 'a'.repeat(64), 'operator', now);

  const result = state.reset();
  assert.equal(result.workspaceId, state.location.workspaceId);
  assert.equal(state.database.prepare('SELECT count(*) AS count FROM oauth_clients').get().count, 0);
  const resetOtp = state.database.prepare('SELECT revoked_at FROM spawn_otps').get();
  assert.equal(typeof resetOtp.revoked_at, 'number');
  assert.equal(
    state.database.prepare('SELECT reason FROM auth_revocations ORDER BY revocation_id DESC').get().reason,
    'operator_reset'
  );
});

test('auth state fails closed on a corrupt database', async (t) => {
  const root = temporaryRoot(t);
  const stateDirectory = path.join(root, 'state');
  fs.mkdirSync(stateDirectory, { mode: 0o700 });
  const databasePath = path.join(stateDirectory, 'auth.sqlite3');
  fs.writeFileSync(databasePath, 'not a sqlite database', { mode: 0o600 });
  const { AuthStateDatabase } = await import('../lib/authState.js');
  assert.throws(
    () => new AuthStateDatabase({ stateDirectory }),
    /Unable to open Notty auth state/
  );
});

test('auth state rejects a structurally incomplete current-version database', async (t) => {
  const root = temporaryRoot(t);
  const stateDirectory = path.join(root, 'state');
  const { AuthStateDatabase } = await import('../lib/authState.js');
  const state = new AuthStateDatabase({ stateDirectory });
  state.close();

  const { DatabaseSync } = require('node:sqlite');
  const database = new DatabaseSync(path.join(stateDirectory, 'auth.sqlite3'));
  database.exec('DROP TABLE auth_revocations');
  database.close();

  assert.throws(
    () => new AuthStateDatabase({ stateDirectory }),
    /schema is missing or corrupt/
  );
});

test('auth state rejects a same-column schema with weakened constraints', async (t) => {
  const root = temporaryRoot(t);
  const stateDirectory = path.join(root, 'state');
  const { AuthStateDatabase } = await import('../lib/authState.js');
  const state = new AuthStateDatabase({ stateDirectory });
  state.close();

  const { DatabaseSync } = require('node:sqlite');
  const database = new DatabaseSync(path.join(stateDirectory, 'auth.sqlite3'));
  database.exec(`
    PRAGMA foreign_keys = OFF;
    PRAGMA legacy_alter_table = ON;
    BEGIN IMMEDIATE;
    ALTER TABLE oauth_clients RENAME TO oauth_clients_original;
    CREATE TABLE oauth_clients (
      client_id TEXT PRIMARY KEY,
      client_name TEXT,
      redirect_uris_json TEXT NOT NULL,
      grant_types_json TEXT NOT NULL,
      response_types_json TEXT NOT NULL,
      token_endpoint_auth_method TEXT NOT NULL,
      created_at INTEGER NOT NULL,
      revoked_at INTEGER
    ) STRICT;
    DROP TABLE oauth_clients_original;
    COMMIT;
  `);
  assert.deepEqual(
    database.prepare('PRAGMA table_info("oauth_clients")').all().map((row) => row.name),
    [
      'client_id',
      'client_name',
      'redirect_uris_json',
      'grant_types_json',
      'response_types_json',
      'token_endpoint_auth_method',
      'created_at',
      'revoked_at'
    ]
  );
  assert.equal(
    database.prepare('PRAGMA table_info("oauth_clients")').all()
      .find((row) => row.name === 'client_name').notnull,
    0
  );
  database.close();

  assert.throws(
    () => new AuthStateDatabase({ stateDirectory }),
    /schema is missing or corrupt table oauth_clients/
  );
});
