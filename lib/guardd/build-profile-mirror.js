import crypto from 'node:crypto';
import fs from 'node:fs/promises';
import { constants as fsConstants } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import process from 'node:process';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

import {
  buildProjectKey,
  normalizeBuildMode,
  safeBuildSegment,
  validateBuildEvidenceManifest,
  verifyBuildCandidate,
} from './build-profile-artifacts.js';
import {
  BUILD_PROFILE_FILES,
  defaultBuildProfileRoots,
  writePortableBuildBundle,
} from './build-profile-store.js';

const RECEIPT_KIND = 'NoshBuildProfileReceipt';

function numericId(value, label) {
  if (!/^\d+$/.test(String(value || ''))) {
    throw new Error(`${label} must be a numeric ID`);
  }
  const parsed = Number(value);
  if (!Number.isSafeInteger(parsed) || parsed < 0) {
    throw new Error(`${label} is outside the supported range`);
  }
  return parsed;
}

function passwdRecord(raw, expectedUid, expectedGid) {
  const fields = String(raw || '').trim().split(':');
  if (fields.length < 7) throw new Error(`cannot resolve invoking uid ${expectedUid}`);
  const uid = numericId(fields[2], 'passwd uid');
  const gid = numericId(fields[3], 'passwd gid');
  if (!path.isAbsolute(fields[5] || '')) {
    throw new Error('invoking user home from passwd must be absolute');
  }
  if (uid !== expectedUid || gid !== expectedGid) {
    throw new Error('invoking user identity does not match passwd data');
  }
  return { username: fields[0], uid, gid, home: path.resolve(fields[5]) };
}

export function resolveBuildInvokingUser(options = {}) {
  const env = options.env || process.env;
  const getuid = options.getuid || process.getuid;
  const getgid = options.getgid || process.getgid;
  const currentUid = typeof getuid === 'function' ? getuid() : 0;
  const currentGid = typeof getgid === 'function' ? getgid() : 0;
  if (currentUid === 0 && ((env.SUDO_UID == null) !== (env.SUDO_GID == null))) {
    throw new Error('SUDO_UID and SUDO_GID must be supplied together');
  }
  if (currentUid === 0 && env.SUDO_UID != null) {
    const uid = numericId(env.SUDO_UID, 'SUDO_UID');
    const gid = numericId(env.SUDO_GID, 'SUDO_GID');
    const lookup = options.passwdLookup || ((selectedUid) => {
      const result = spawnSync('getent', ['passwd', String(selectedUid)], {
        encoding: 'utf8',
        timeout: 5_000,
        stdio: ['ignore', 'pipe', 'pipe'],
      });
      if (result.status !== 0) {
        throw new Error(
          `getent passwd ${selectedUid} failed: ${result.error?.message || result.stderr || `status ${result.status}`}`,
        );
      }
      return result.stdout;
    });
    return passwdRecord(lookup(uid), uid, gid);
  }
  const selected = options.userInfo ? options.userInfo() : os.userInfo();
  return {
    username: selected.username,
    uid: Number.isSafeInteger(selected.uid) ? selected.uid : currentUid,
    gid: Number.isSafeInteger(selected.gid) ? selected.gid : currentGid,
    home: path.resolve(selected.homedir),
  };
}

export function buildProfileMirrorDirectory(workdir, home, mode, runId) {
  const canonical = path.resolve(workdir);
  const selectedMode = normalizeBuildMode(mode);
  const roots = defaultBuildProfileRoots(home);
  const root = selectedMode === 'build-net-learn' ? roots.network : roots.profile;
  return path.join(
    root,
    buildProjectKey(canonical),
    safeBuildSegment(runId, 'runId'),
    BUILD_PROFILE_FILES.portableDirectory,
  );
}

async function secureDirectory(directory) {
  await fs.mkdir(directory, { recursive: true, mode: 0o700 });
  const stat = await fs.lstat(directory);
  if (!stat.isDirectory() || stat.isSymbolicLink()) {
    throw new Error(`build profile mirror path is not a directory: ${directory}`);
  }
  await fs.chmod(directory, 0o700);
}

async function atomicWrite(destination, content) {
  const temporary = `${destination}.${process.pid}.${crypto.randomUUID()}.tmp`;
  let handle;
  try {
    handle = await fs.open(
      temporary,
      fsConstants.O_WRONLY
        | fsConstants.O_CREAT
        | fsConstants.O_EXCL
        | (fsConstants.O_NOFOLLOW || 0),
      0o600,
    );
    await handle.writeFile(content);
    await handle.sync();
    await handle.close();
    handle = null;
    await fs.rename(temporary, destination);
  } catch (error) {
    await handle?.close().catch(() => {});
    await fs.unlink(temporary).catch(() => {});
    throw error;
  }
}

function assertBelowHome(directory, home) {
  const relative = path.relative(path.resolve(home), path.resolve(directory));
  if (!relative || relative === '..' || relative.startsWith(`..${path.sep}`) || path.isAbsolute(relative)) {
    throw new Error('build profile mirror escaped the invoking user home');
  }
}

export async function writeBuildProfileMirrorPayload(payload) {
  if (!payload || typeof payload !== 'object' || Array.isArray(payload)) {
    throw new TypeError('build profile mirror payload is required');
  }
  const manifest = validateBuildEvidenceManifest(payload.manifest);
  const candidate = payload.candidate || null;
  if (candidate) verifyBuildCandidate(candidate, manifest);
  const workdir = await fs.realpath(path.resolve(payload.workdir));
  if (
    manifest.project.canonicalPath !== workdir
    || manifest.project.key !== buildProjectKey(workdir)
  ) {
    throw new Error('build profile mirror project does not match its evidence');
  }
  const home = path.resolve(payload.home);
  const directory = buildProfileMirrorDirectory(
    workdir,
    home,
    manifest.mode,
    manifest.runId,
  );
  assertBelowHome(directory, home);
  for (const selected of [
    path.join(home, '.nosh'),
    path.dirname(path.dirname(path.dirname(directory))),
    path.dirname(path.dirname(directory)),
    path.dirname(directory),
  ]) {
    await secureDirectory(selected);
  }
  const portable = await writePortableBuildBundle({
    directory,
    manifest,
    candidate,
  });
  const projectDirectory = path.dirname(path.dirname(directory));
  const receipt = {
    apiVersion: 'notty.dev/v1alpha1',
    kind: RECEIPT_KIND,
    authoritative: false,
    attested: false,
    updatedAt: new Date().toISOString(),
    runId: manifest.runId,
    mode: manifest.mode,
    project: { key: manifest.project.key },
    portableBundleHash: portable.bundle.contentHash,
  };
  await atomicWrite(
    path.join(projectDirectory, 'current.json'),
    `${JSON.stringify(receipt, null, 2)}\n`,
  );
  return { directory, receipt, bundle: portable.bundle };
}

export function writeInvokingUserBuildProfileMirror(payload, options = {}) {
  const invokingUser = options.invokingUser || resolveBuildInvokingUser(options);
  const helperPath = fileURLToPath(import.meta.url);
  const result = (options.spawnSyncImpl || spawnSync)(
    process.execPath,
    [helperPath, '--write-payload'],
    {
      encoding: 'utf8',
      input: JSON.stringify({ ...payload, home: invokingUser.home }),
      timeout: 30_000,
      uid: invokingUser.uid,
      gid: invokingUser.gid,
      env: {
        HOME: invokingUser.home,
        PATH: process.env.PATH || '/usr/bin:/bin',
      },
      stdio: ['pipe', 'pipe', 'pipe'],
    },
  );
  if (result.status !== 0) {
    throw new Error(
      `build profile mirror update failed: ${result.error?.message || result.stderr || `status ${result.status}`}`,
    );
  }
  return JSON.parse(String(result.stdout || '').trim());
}

export async function readCurrentBuildProfileMirror(workdir, options = {}) {
  const canonical = await fs.realpath(path.resolve(workdir));
  const selected = options.user || resolveBuildInvokingUser(options);
  const mode = normalizeBuildMode(options.mode || 'build-profile');
  const roots = defaultBuildProfileRoots(selected.home);
  const root = mode === 'build-net-learn' ? roots.network : roots.profile;
  const projectDirectory = path.join(root, buildProjectKey(canonical));
  const receipt = JSON.parse(
    await fs.readFile(path.join(projectDirectory, 'current.json'), 'utf8'),
  );
  if (
    receipt?.kind !== RECEIPT_KIND
    || receipt?.authoritative !== false
    || receipt?.attested !== false
    || receipt?.mode !== mode
    || receipt?.project?.key !== buildProjectKey(canonical)
  ) {
    throw new Error('build profile mirror does not match this project');
  }
  return {
    directory: path.join(projectDirectory, receipt.runId, BUILD_PROFILE_FILES.portableDirectory),
    receipt,
  };
}

async function readStdin() {
  const chunks = [];
  for await (const chunk of process.stdin) chunks.push(chunk);
  return Buffer.concat(chunks).toString('utf8');
}

if (
  process.argv[1]
  && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)
  && process.argv[2] === '--write-payload'
) {
  readStdin()
    .then((source) => writeBuildProfileMirrorPayload(JSON.parse(source)))
    .then((result) => process.stdout.write(`${JSON.stringify(result)}\n`))
    .catch((error) => {
      process.stderr.write(`${error.stack || error.message}\n`);
      process.exitCode = 1;
    });
}

