import fs from 'node:fs/promises';
import path from 'node:path';
import crypto from 'node:crypto';
import { readPrivateJson } from '../policy-review/sessionStorage.js';
import { validateProfile } from './model.js';

const MAX_BYTES = 1024 * 1024;
function directory(variable) {
  const value = process.env[variable];
  if (!value || !path.isAbsolute(value)) throw new Error('Open setup with nosh config.');
  return value;
}
export async function readSession() {
  const filename = process.env.NOTTY_SETUP_SESSION_FILE;
  if (!filename) throw new Error('Open setup with nosh config.');
  const session = await readPrivateJson(filename, MAX_BYTES);
  if (session.kind !== 'NoshSetupSession' || session.schemaVersion !== 1
    || !/^[a-f0-9]{64}$/.test(session.token) || !/^http:\/\/127\.0\.0\.1:\d+$/.test(session.origin)) throw new Error('Invalid setup session.');
  return session;
}
async function readProfile() {
  const document = await readPrivateJson(path.join(directory('NOTTY_SETUP_PROFILE_DIR'), 'profile.json'), MAX_BYTES);
  if (document.kind !== 'NoshRepositoryProfile' || document.schemaVersion !== 1 || !Number.isSafeInteger(document.revision) || document.revision < 1) throw new Error('Unsupported repository profile.');
  validateProfile(document.profile);
  return document;
}
export async function load() {
  const state = directory('NOTTY_SETUP_STATE_DIR');
  const binding = await readPrivateJson(path.join(state, 'binding.json'), MAX_BYTES);
  if (!binding.workspace || ![binding.workspace.path, binding.launcher, binding.scripts].every(value => typeof value === 'string' && path.isAbsolute(value))) throw new Error('Invalid host workspace binding.');
  let snapshot = null;
  try { snapshot = await readPrivateJson(path.join(state, 'snapshot.json'), MAX_BYTES); }
  catch (error) { if (error.code !== 'ENOENT') throw error; }
  return { document: await readProfile(), binding, snapshot };
}
export async function save(request) {
  if (!request || Object.keys(request).sort().join(',') !== 'profile,revision' || !Number.isSafeInteger(request.revision)) throw new Error('Invalid save request.');
  validateProfile(request.profile);
  const root = directory('NOTTY_SETUP_PROFILE_DIR');
  const info = await fs.lstat(root);
  if (!info.isDirectory() || info.isSymbolicLink() || info.uid !== process.geteuid() || (info.mode & 0o077)) throw new Error('Profile directory must be private and owned.');
  const lock = path.join(root, '.write-lock');
  try { await fs.mkdir(lock, { mode: 0o700 }); }
  catch (error) {
    if (error.code === 'EEXIST') throw Object.assign(new Error('Another save is in progress. Retry.'), { status: 409 });
    throw error;
  }
  const temporary = path.join(root, `.save-${crypto.randomUUID()}`);
  try {
    const current = await readProfile();
    if (current.revision !== request.revision) throw Object.assign(new Error('This profile changed in another session. Reload before saving.'), { status: 409 });
    const document = { ...current, revision: current.revision + 1, profile: request.profile };
    const encoded = JSON.stringify(document, null, 2) + '\n';
    if (Buffer.byteLength(encoded) > MAX_BYTES) throw new Error('Profile exceeds 1 MiB.');
    const file = await fs.open(temporary, 'wx', 0o600);
    try { await file.writeFile(encoded); await file.sync(); } finally { await file.close(); }
    await fs.rename(temporary, path.join(root, 'profile.json'));
    return document;
  } finally {
    await fs.rm(temporary, { force: true });
    await fs.rmdir(lock);
  }
}
