import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { createHash } from 'node:crypto';
import { DatabaseSync } from 'node:sqlite';

const AUTH_STATE_SCHEMA_VERSION = 2;
const WORKSPACE_ID_PATTERN = /^[a-zA-Z0-9_-]{16,128}$/;
const REQUIRED_TABLE_COLUMNS = Object.freeze({
  oauth_clients: ['client_id', 'client_name', 'redirect_uris_json', 'grant_types_json', 'response_types_json', 'token_endpoint_auth_method', 'created_at', 'revoked_at'],
  oauth_grants: ['grant_id', 'client_id', 'subject', 'scope', 'resource', 'created_at', 'revoked_at'],
  oauth_authorization_codes: ['code_hash', 'grant_id', 'client_id', 'subject', 'scope', 'resource', 'redirect_uri', 'code_challenge', 'created_at', 'expires_at', 'consumed_at'],
  oauth_refresh_families: ['family_id', 'client_id', 'subject', 'scope', 'resource', 'created_at', 'expires_at', 'revoked_at', 'replayed_at', 'grant_id'],
  oauth_refresh_tokens: ['token_hash', 'family_id', 'created_at', 'expires_at', 'consumed_at', 'revoked_at', 'replaced_by_hash'],
  oauth_access_tokens: ['token_hash', 'family_id', 'client_id', 'subject', 'scope', 'resource', 'created_at', 'expires_at', 'revoked_at'],
  spawn_otps: ['uuid', 'token_hash', 'source', 'created_at', 'expires_at', 'consumed_at', 'revoked_at'],
  auth_revocations: ['revocation_id', 'kind', 'target_id', 'reason', 'created_at']
});

const schemaV1 = `
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
`;

const SCHEMA_V2_UPGRADE_DDL = `
  ALTER TABLE oauth_refresh_families
  ADD COLUMN grant_id TEXT REFERENCES oauth_grants(grant_id);
  CREATE UNIQUE INDEX oauth_refresh_grant_idx
    ON oauth_refresh_families(grant_id)
    WHERE grant_id IS NOT NULL;
`;

const expectedSchemaManifests = new Map();

function pragmaArgument(value) {
  return `'${String(value).replaceAll("'", "''")}'`;
}

function comparableSchemaValue(value) {
  return value === null || value === undefined ? null : value;
}

function collectSchemaManifest(database) {
  const tableListings = database.prepare('PRAGMA table_list').all();
  const schemaObjects = database.prepare(`
    SELECT type, name, tbl_name, sql
    FROM sqlite_schema
    ORDER BY type, name, tbl_name
  `).all().map((row) => ({
    type: row.type,
    name: row.name,
    table: row.tbl_name,
    sql: comparableSchemaValue(row.sql)
  }));
  const tables = {};

  for (const table of Object.keys(REQUIRED_TABLE_COLUMNS).sort()) {
    const listing = tableListings.find((row) => row.schema === 'main' && row.name === table);
    const columns = database.prepare(
      `PRAGMA table_xinfo(${pragmaArgument(table)})`
    ).all().map((row) => ({
      cid: row.cid,
      name: row.name,
      type: row.type,
      notNull: row.notnull,
      defaultValue: comparableSchemaValue(row.dflt_value),
      primaryKeyPosition: row.pk,
      hidden: row.hidden
    }));
    const foreignKeys = database.prepare(
      `PRAGMA foreign_key_list(${pragmaArgument(table)})`
    ).all().map((row) => ({
      sequence: row.seq,
      table: row.table,
      from: row.from,
      to: row.to,
      onUpdate: row.on_update,
      onDelete: row.on_delete,
      match: row.match
    })).sort((left, right) => JSON.stringify(left).localeCompare(JSON.stringify(right)));
    const indexes = database.prepare(
      `PRAGMA index_list(${pragmaArgument(table)})`
    ).all().map((row) => ({
      name: row.name,
      unique: row.unique,
      origin: row.origin,
      partial: row.partial,
      columns: database.prepare(
        `PRAGMA index_xinfo(${pragmaArgument(row.name)})`
      ).all().map((column) => ({
        sequence: column.seqno,
        cid: column.cid,
        name: comparableSchemaValue(column.name),
        descending: column.desc,
        collation: comparableSchemaValue(column.coll),
        key: column.key
      }))
    })).sort((left, right) => left.name.localeCompare(right.name));

    tables[table] = {
      listing: listing
        ? {
            type: listing.type,
            columnCount: listing.ncol,
            withoutRowId: listing.wr,
            strict: listing.strict
          }
        : null,
      columns,
      foreignKeys,
      indexes
    };
  }

  return { schemaObjects, tables };
}

function getExpectedSchemaManifest(version = AUTH_STATE_SCHEMA_VERSION) {
  if (![1, AUTH_STATE_SCHEMA_VERSION].includes(version)) {
    throw new Error(`Unsupported Notty auth schema manifest version ${version}`);
  }
  const cached = expectedSchemaManifests.get(version);
  if (cached) {
    return cached;
  }

  const database = new DatabaseSync(':memory:');
  try {
    database.exec('PRAGMA foreign_keys = ON;');
    database.exec(schemaV1);
    if (version >= 2) {
      database.exec(SCHEMA_V2_UPGRADE_DDL);
    }
    const manifest = collectSchemaManifest(database);
    expectedSchemaManifests.set(version, manifest);
    return manifest;
  } finally {
    database.close();
  }
}

function modeBits(stat) {
  return stat.mode & 0o7777;
}

function currentUid() {
  return typeof process.geteuid === 'function' ? process.geteuid() : null;
}

function assertOwned(stat, target) {
  const uid = currentUid();
  if (uid !== null && stat.uid !== uid) {
    throw new Error(`Notty auth state is not owned by the current user: ${target}`);
  }
}

function assertNoSymlinkComponents(target) {
  const absolute = path.resolve(target);
  const parsed = path.parse(absolute);
  let cursor = parsed.root;
  for (const part of absolute.slice(parsed.root.length).split(path.sep).filter(Boolean)) {
    cursor = path.join(cursor, part);
    let stat;
    try {
      stat = fs.lstatSync(cursor);
    } catch (error) {
      if (error.code === 'ENOENT') {
        break;
      }
      throw error;
    }
    if (stat.isSymbolicLink()) {
      throw new Error(`Notty auth state path must not contain symlinks: ${cursor}`);
    }
  }
}

function assertSecureDirectory(target, { create = true, exactMode = true } = {}) {
  let stat;
  try {
    stat = fs.lstatSync(target);
  } catch (error) {
    if (error.code !== 'ENOENT' || !create) {
      throw error;
    }
    fs.mkdirSync(target, { mode: 0o700 });
    stat = fs.lstatSync(target);
  }

  if (stat.isSymbolicLink() || !stat.isDirectory()) {
    throw new Error(`Notty auth state directory must be a real directory: ${target}`);
  }
  assertOwned(stat, target);
  if (exactMode && modeBits(stat) !== 0o700) {
    throw new Error(`Notty auth state directory must have mode 0700: ${target}`);
  }
}

function ensureSecureStateTree(stateHome, stateDirectory, explicitDirectory) {
  if (!path.isAbsolute(stateHome) || !path.isAbsolute(stateDirectory)) {
    throw new Error('Notty auth state paths must be absolute');
  }

  assertNoSymlinkComponents(stateHome);
  if (!fs.existsSync(stateHome)) {
    fs.mkdirSync(stateHome, { recursive: true, mode: 0o700 });
  }
  assertNoSymlinkComponents(stateHome);
  assertSecureDirectory(stateHome, { create: false, exactMode: false });

  if (explicitDirectory) {
    const relative = path.relative(stateHome, stateDirectory);
    if (relative.startsWith('..') || path.isAbsolute(relative)) {
      throw new Error('NOTTY_AUTH_STATE_DIR must resolve beneath its state root');
    }
  }

  let cursor = stateHome;
  const relativeParts = path.relative(stateHome, stateDirectory).split(path.sep).filter(Boolean);
  for (const part of relativeParts) {
    cursor = path.join(cursor, part);
    assertSecureDirectory(cursor);
    assertNoSymlinkComponents(cursor);
  }

  if (relativeParts.length === 0) {
    assertSecureDirectory(stateDirectory);
  }
}

function assertSecureDatabaseFile(databasePath) {
  let stat;
  try {
    stat = fs.lstatSync(databasePath);
  } catch (error) {
    if (error.code !== 'ENOENT') {
      throw error;
    }
    const descriptor = fs.openSync(
      databasePath,
      fs.constants.O_CREAT | fs.constants.O_EXCL | fs.constants.O_RDWR,
      0o600
    );
    fs.closeSync(descriptor);
    stat = fs.lstatSync(databasePath);
  }

  if (stat.isSymbolicLink() || !stat.isFile()) {
    throw new Error(`Notty auth database must be a real file: ${databasePath}`);
  }
  assertOwned(stat, databasePath);
  if (stat.nlink !== 1) {
    throw new Error(`Notty auth database must not have multiple hard links: ${databasePath}`);
  }
  if (modeBits(stat) !== 0o600) {
    throw new Error(`Notty auth database must have mode 0600: ${databasePath}`);
  }
  return stat;
}

function canonicalWorkspace(workspaceRoot) {
  const resolved = path.resolve(workspaceRoot || process.cwd());
  try {
    return fs.realpathSync(resolved);
  } catch {
    return resolved;
  }
}

export function workspaceAuthId(workspaceRoot = process.env.NOTTY_WORKDIR || process.cwd()) {
  return createHash('sha256').update(canonicalWorkspace(workspaceRoot)).digest('hex').slice(0, 32);
}

export function hashAuthSecret(value) {
  if (typeof value !== 'string' || value.length === 0) {
    throw new Error('Auth secret must be a non-empty string');
  }
  return createHash('sha256').update(value, 'utf8').digest('hex');
}

export function resolveAuthStateLocation(options = {}) {
  const env = options.env || process.env;
  const workspaceRoot = options.workspaceRoot || env.NOTTY_WORKDIR || process.cwd();
  const configuredWorkspaceId = String(options.workspaceId || env.NOTTY_WORKSPACE_ID || '').trim();
  if (configuredWorkspaceId && !WORKSPACE_ID_PATTERN.test(configuredWorkspaceId)) {
    throw new Error('NOTTY_WORKSPACE_ID must contain 16-128 letters, digits, underscores, or dashes');
  }
  const workspaceId = configuredWorkspaceId || workspaceAuthId(workspaceRoot);
  const stateHome = path.resolve(
    options.stateHome
      || env.XDG_STATE_HOME
      || path.join(env.HOME || os.homedir(), '.local', 'state')
  );
  const explicitDirectoryValue = options.stateDirectory || env.NOTTY_AUTH_STATE_DIR || '';
  const stateDirectory = explicitDirectoryValue
    ? path.resolve(explicitDirectoryValue)
    : path.join(stateHome, 'notty', 'auth', workspaceId);
  return {
    workspaceId,
    workspaceRoot: canonicalWorkspace(workspaceRoot),
    // An explicitly mounted state directory is the trust root. Its container
    // parent (for example /var/lib) is normally root-owned and must not be
    // treated as runner-owned auth state.
    stateHome: explicitDirectoryValue ? stateDirectory : stateHome,
    stateDirectory,
    databasePath: path.join(stateDirectory, 'auth.sqlite3'),
    explicitDirectory: Boolean(explicitDirectoryValue)
  };
}

function quickCheck(database) {
  const rows = database.prepare('PRAGMA quick_check').all();
  if (rows.length !== 1 || Object.values(rows[0])[0] !== 'ok') {
    throw new Error('Notty auth database failed SQLite integrity checking');
  }
}

function validateSchema(database, version = AUTH_STATE_SCHEMA_VERSION) {
  const expected = getExpectedSchemaManifest(version);
  const actual = collectSchemaManifest(database);

  for (const table of Object.keys(REQUIRED_TABLE_COLUMNS)) {
    if (JSON.stringify(actual.tables[table]) !== JSON.stringify(expected.tables[table])) {
      throw new Error(`Notty auth database schema is missing or corrupt table ${table}`);
    }
  }
  if (JSON.stringify(actual.schemaObjects) !== JSON.stringify(expected.schemaObjects)) {
    throw new Error('Notty auth database schema is missing or corrupt');
  }
  const foreignKeyFailures = database.prepare('PRAGMA foreign_key_check').all();
  if (foreignKeyFailures.length > 0) {
    throw new Error('Notty auth database contains invalid foreign-key references');
  }
}

function migrateSchemaV1ToV2(database) {
  // Version 1 did not persist a family-to-grant link. Several grants can
  // legitimately have the same client, subject, scope, resource, and
  // timestamp, so attempting to infer that link could revoke the wrong
  // family on a later authorization-code replay. Revoke legacy families
  // once during migration and require reauthorization instead.
  validateSchema(database, 1);
  const migratedAt = Date.now();
  database.exec('BEGIN IMMEDIATE');
  try {
    database.exec(SCHEMA_V2_UPGRADE_DDL);
    database.prepare(`
      INSERT INTO auth_revocations(kind, target_id, reason, created_at)
      SELECT 'refresh_family', family_id, 'schema_v2_unlinked_grant', ?
      FROM oauth_refresh_families
      WHERE revoked_at IS NULL
    `).run(migratedAt);
    database.prepare(`
      UPDATE oauth_refresh_tokens
      SET revoked_at = COALESCE(revoked_at, ?)
      WHERE family_id IN (SELECT family_id FROM oauth_refresh_families)
    `).run(migratedAt);
    database.prepare(`
      UPDATE oauth_access_tokens
      SET revoked_at = COALESCE(revoked_at, ?)
      WHERE family_id IN (SELECT family_id FROM oauth_refresh_families)
    `).run(migratedAt);
    database.prepare(`
      UPDATE oauth_refresh_families
      SET revoked_at = COALESCE(revoked_at, ?)
    `).run(migratedAt);
    database.prepare(`
      UPDATE oauth_grants
      SET revoked_at = COALESCE(revoked_at, ?)
      WHERE grant_id IN (
        SELECT grant_id
        FROM oauth_authorization_codes
        WHERE consumed_at IS NOT NULL
      )
    `).run(migratedAt);
    database.exec(`PRAGMA user_version = ${AUTH_STATE_SCHEMA_VERSION}`);
    database.exec('COMMIT');
  } catch (error) {
    database.exec('ROLLBACK');
    throw error;
  }
}

export class AuthStateDatabase {
  constructor(options = {}) {
    this.location = resolveAuthStateLocation(options);
    ensureSecureStateTree(
      this.location.stateHome,
      this.location.stateDirectory,
      this.location.explicitDirectory
    );
    const checkedDatabaseStat = assertSecureDatabaseFile(this.location.databasePath);

    try {
      this.database = new DatabaseSync(this.location.databasePath);
      const openedDatabaseStat = assertSecureDatabaseFile(this.location.databasePath);
      if (
        openedDatabaseStat.dev !== checkedDatabaseStat.dev
        || openedDatabaseStat.ino !== checkedDatabaseStat.ino
      ) {
        throw new Error('Notty auth database changed while it was being opened');
      }
      this.database.exec('PRAGMA foreign_keys = ON; PRAGMA busy_timeout = 5000;');
      quickCheck(this.database);
      const versionRow = this.database.prepare('PRAGMA user_version').get();
      let version = Number(Object.values(versionRow || {})[0] || 0);
      if (![0, 1, AUTH_STATE_SCHEMA_VERSION].includes(version)) {
        throw new Error(
          `Unsupported Notty auth database schema ${version}; expected ${AUTH_STATE_SCHEMA_VERSION}`
        );
      }
      if (version === 0) {
        this.database.exec('BEGIN IMMEDIATE');
        try {
          this.database.exec(schemaV1);
          this.database.exec('PRAGMA user_version = 1');
          this.database.exec('COMMIT');
          version = 1;
        } catch (error) {
          this.database.exec('ROLLBACK');
          throw error;
        }
      }
      if (version === 1) {
        migrateSchemaV1ToV2(this.database);
        version = AUTH_STATE_SCHEMA_VERSION;
      }
      validateSchema(this.database, version);
      quickCheck(this.database);
    } catch (error) {
      try {
        this.database?.close();
      } catch {
        // Preserve the initialization error.
      }
      throw new Error(`Unable to open Notty auth state: ${error.message}`, { cause: error });
    }
  }

  transaction(operation) {
    this.database.exec('BEGIN IMMEDIATE');
    try {
      const result = operation(this.database);
      this.database.exec('COMMIT');
      return result;
    } catch (error) {
      this.database.exec('ROLLBACK');
      throw error;
    }
  }

  reset() {
    const now = Date.now();
    return this.transaction((database) => {
      database.prepare(`
        INSERT INTO auth_revocations(kind, target_id, reason, created_at)
        VALUES ('workspace', ?, 'operator_reset', ?)
      `).run(this.location.workspaceId, now);
      database.exec(`
        DELETE FROM oauth_authorization_codes;
        DELETE FROM oauth_access_tokens;
        DELETE FROM oauth_refresh_tokens;
        DELETE FROM oauth_refresh_families;
        DELETE FROM oauth_grants;
        DELETE FROM oauth_clients;
      `);
      database.prepare(`
        UPDATE spawn_otps
        SET revoked_at = ?
        WHERE revoked_at IS NULL AND consumed_at IS NULL
      `).run(now);
      return { workspaceId: this.location.workspaceId, resetAt: now };
    });
  }

  close() {
    this.database.close();
  }
}

const stateCache = globalThis.__nottyAuthStateCache || new Map();
globalThis.__nottyAuthStateCache = stateCache;

export function getAuthState(options = {}) {
  const location = resolveAuthStateLocation(options);
  const key = location.databasePath;
  let state = stateCache.get(key);
  if (!state) {
    state = new AuthStateDatabase(options);
    stateCache.set(key, state);
  }
  return state;
}

export function closeAuthState(options = {}) {
  const location = resolveAuthStateLocation(options);
  const state = stateCache.get(location.databasePath);
  if (!state) {
    return false;
  }
  state.close();
  stateCache.delete(location.databasePath);
  return true;
}

export { AUTH_STATE_SCHEMA_VERSION };
