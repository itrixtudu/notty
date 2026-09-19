import { spawn } from 'node:child_process';
import { randomUUID } from 'node:crypto';
import { constants as fsConstants } from 'node:fs';
import {
  lstatSync,
  mkdirSync,
  readdirSync,
  renameSync,
  rmdirSync,
} from 'node:fs';
import fs from 'node:fs/promises';
import path from 'node:path';
import process from 'node:process';
import { fileURLToPath } from 'node:url';

import { workspaceAuthId } from '../authState.js';
import { prepareRunnerAuthState } from './service.js';

const AUTH_RESET_WORKER = fileURLToPath(
  new URL('./auth-reset-worker.js', import.meta.url),
);
const WORKER_TIMEOUT_MS = 30_000;
const WORKER_MAX_OUTPUT_BYTES = 64 * 1024;
const pendingWorkspaceResets = new Set();

function requireAbsoluteWorkspace(workdir) {
  if (typeof workdir !== 'string' || !path.isAbsolute(workdir)) {
    throw new TypeError('Guard auth reset requires an absolute workspace path');
  }
  return path.resolve(workdir);
}

async function validateAuthStateDirectory(input) {
  const handle = await fs.open(
    input.authStateDir,
    fsConstants.O_RDONLY
      | (fsConstants.O_DIRECTORY || 0)
      | (fsConstants.O_NOFOLLOW || 0),
  );
  try {
    const descriptorStat = await handle.stat();
    const currentStat = await fs.lstat(input.authStateDir);
    if (
      !descriptorStat.isDirectory()
      || currentStat.isSymbolicLink()
      || !currentStat.isDirectory()
      || descriptorStat.dev !== currentStat.dev
      || descriptorStat.ino !== currentStat.ino
      || descriptorStat.uid !== input.uid
      || descriptorStat.gid !== input.gid
      || (descriptorStat.mode & 0o7777) !== 0o700
    ) {
      throw new Error('Guard workspace auth state changed before reset');
    }
  } finally {
    await handle.close().catch(() => {});
  }
}

function canTraverse(stat, identity) {
  if (identity.uid === 0) return true;
  if (stat.uid === identity.uid) return (stat.mode & 0o100) !== 0;
  if (stat.gid === identity.gid) return (stat.mode & 0o010) !== 0;
  return (stat.mode & 0o001) !== 0;
}

async function relocationParent(stateRoot, identity, device) {
  const daemonUid = process.geteuid?.();
  if (!Number.isSafeInteger(daemonUid)) {
    throw new Error('Guard auth reset requires a Unix daemon identity');
  }
  let candidate = path.dirname(path.resolve(stateRoot));
  const filesystemRoot = path.parse(candidate).root;

  while (candidate !== filesystemRoot) {
    const candidateStat = await fs.lstat(candidate);
    if (
      candidateStat.isDirectory()
      && !candidateStat.isSymbolicLink()
      && candidateStat.dev === device
      && candidateStat.uid === daemonUid
      && (candidateStat.mode & 0o022) === 0
    ) {
      const relative = path.relative(filesystemRoot, candidate);
      let current = filesystemRoot;
      let traversable = true;
      for (const segment of relative.split(path.sep).filter(Boolean)) {
        current = path.join(current, segment);
        const stat = await fs.lstat(current);
        if (
          !stat.isDirectory()
          || stat.isSymbolicLink()
          || !canTraverse(stat, identity)
        ) {
          traversable = false;
          break;
        }
      }
      if (traversable) return candidate;
    }
    candidate = path.dirname(candidate);
  }
  throw new Error(
    'Guard auth reset cannot find a trusted same-filesystem path traversable by the workspace owner',
  );
}

function relocateAuthState(input, parent) {
  const daemonUid = process.geteuid?.();
  const daemonGid = process.getegid?.();
  if (!Number.isSafeInteger(daemonUid) || !Number.isSafeInteger(daemonGid)) {
    throw new Error('Guard auth reset requires a Unix daemon identity');
  }
  const original = lstatSync(input.authStateDir);
  const relocated = path.join(
    parent,
    `.nosh-guard-auth-reset-${input.workspaceId}-${randomUUID()}`,
  );
  renameSync(input.authStateDir, relocated);
  let placeholder = null;
  try {
    mkdirSync(input.authStateDir, { mode: 0o700 });
    placeholder = lstatSync(input.authStateDir);
    const current = lstatSync(relocated);
    if (
      current.isSymbolicLink()
      || !current.isDirectory()
      || current.dev !== original.dev
      || current.ino !== original.ino
      || current.uid !== input.uid
      || current.gid !== input.gid
      || (current.mode & 0o7777) !== 0o700
      || !placeholder.isDirectory()
      || placeholder.isSymbolicLink()
      || placeholder.uid !== daemonUid
      || placeholder.gid !== daemonGid
      || (placeholder.mode & 0o7777) !== 0o700
    ) {
      throw new Error('Guard auth reset relocation changed identity or permissions');
    }
    return { relocated, placeholder, original };
  } catch (error) {
    if (placeholder) {
      rmdirSync(input.authStateDir);
    }
    renameSync(relocated, input.authStateDir);
    throw error;
  }
}

function restoreAuthState(input, relocation) {
  const placeholder = lstatSync(input.authStateDir);
  const relocated = lstatSync(relocation.relocated);
  if (
    !placeholder.isDirectory()
    || placeholder.isSymbolicLink()
    || placeholder.dev !== relocation.placeholder.dev
    || placeholder.ino !== relocation.placeholder.ino
    || placeholder.uid !== relocation.placeholder.uid
    || placeholder.gid !== relocation.placeholder.gid
    || (placeholder.mode & 0o7777) !== 0o700
    || readdirSync(input.authStateDir).length !== 0
    || !relocated.isDirectory()
    || relocated.isSymbolicLink()
    || relocated.dev !== relocation.original.dev
    || relocated.ino !== relocation.original.ino
    || relocated.uid !== input.uid
    || relocated.gid !== input.gid
    || (relocated.mode & 0o7777) !== 0o700
  ) {
    throw new Error('Guard auth reset state changed before restoration');
  }
  rmdirSync(input.authStateDir);
  renameSync(relocation.relocated, input.authStateDir);
}

async function runResetWorker(input) {
  return new Promise((resolve, reject) => {
    const child = spawn(
      process.execPath,
      [
        AUTH_RESET_WORKER,
        input.authStateDir,
        input.workspacePath,
        input.workspaceId,
        String(input.uid),
        String(input.gid),
      ],
      {
        cwd: input.authStateDir,
        env: {
          HOME: '/nonexistent',
          LANG: 'C',
          LC_ALL: 'C',
          PATH: '/usr/bin:/bin',
          TMPDIR: '/tmp',
        },
        stdio: ['ignore', 'pipe', 'pipe'],
      },
    );
    const stdout = [];
    const stderr = [];
    let outputBytes = 0;
    let outputOverflow = false;
    let spawnError = null;
    const timer = setTimeout(() => {
      spawnError = new Error(
        `Guard auth reset worker timed out after ${WORKER_TIMEOUT_MS}ms`,
      );
      child.kill('SIGKILL');
    }, WORKER_TIMEOUT_MS);

    const collect = (chunks) => (chunk) => {
      outputBytes += chunk.length;
      if (outputBytes > WORKER_MAX_OUTPUT_BYTES) {
        outputOverflow = true;
        child.kill('SIGKILL');
        return;
      }
      chunks.push(chunk);
    };
    child.stdout.on('data', collect(stdout));
    child.stderr.on('data', collect(stderr));
    child.once('error', (error) => {
      spawnError = error;
    });
    child.once('close', (code, signal) => {
      clearTimeout(timer);
      const errorOutput = Buffer.concat(stderr).toString('utf8').trim();
      if (outputOverflow) {
        reject(new Error('Guard auth reset worker exceeded its output limit'));
        return;
      }
      if (spawnError || code !== 0) {
        const status = signal ? `signal ${signal}` : `status ${code}`;
        reject(new Error(
          `Guard auth reset transaction failed (${status})${
            errorOutput ? `: ${errorOutput}` : ''
          }`,
          spawnError ? { cause: spawnError } : undefined,
        ));
        return;
      }
      const output = Buffer.concat(stdout).toString('utf8');
      try {
        resolve(JSON.parse(output));
      } catch (parseError) {
        reject(new Error('Guard auth reset worker returned an invalid receipt', {
          cause: parseError,
        }));
      }
    });
  });
}

export async function resetGuardWorkspaceAuthState(
  stateRoot,
  workdir,
  options = {},
) {
  if (typeof stateRoot !== 'string' || !path.isAbsolute(stateRoot)) {
    throw new TypeError('Guard auth reset requires an absolute daemon state root');
  }

  const requestedWorkspace = requireAbsoluteWorkspace(workdir);
  const workspacePath = await fs.realpath(requestedWorkspace);
  const identity = await fs.stat(workspacePath);
  if (!identity.isDirectory()) {
    throw new TypeError(`Guard auth reset workspace is not a directory: ${workspacePath}`);
  }
  if (identity.uid === 0 || identity.gid === 0) {
    throw new Error('Guard auth reset requires a non-root workspace owner and group');
  }

  const workspaceId = workspaceAuthId(workspacePath);
  if (pendingWorkspaceResets.has(workspaceId)) {
    const error = new Error('Guard auth reset is already running for this workspace');
    error.code = 'GUARD_AUTH_RESET_BUSY';
    error.statusCode = 409;
    throw error;
  }
  pendingWorkspaceResets.add(workspaceId);

  try {
    const resolvedStateRoot = path.resolve(stateRoot);
    const prepareAuthState = options.prepareAuthState || prepareRunnerAuthState;
    const authStateDir = await prepareAuthState(resolvedStateRoot, workspacePath);
    const expectedAuthStateDir = path.join(
      resolvedStateRoot,
      'auth',
      workspaceId,
    );
    if (path.resolve(authStateDir) !== expectedAuthStateDir) {
      throw new Error('Guard auth reset resolved an unexpected workspace state directory');
    }

    const workerInput = {
      authStateDir,
      workspacePath,
      workspaceId,
      uid: identity.uid,
      gid: identity.gid,
    };
    await validateAuthStateDirectory(workerInput);
    const authStateStat = await fs.lstat(authStateDir);
    const parent = await relocationParent(
      resolvedStateRoot,
      identity,
      authStateStat.dev,
    );
    const relocation = relocateAuthState(workerInput, parent);
    const executeWorker = options.executeWorker || runResetWorker;
    let result;
    try {
      result = await executeWorker({
        ...workerInput,
        authStateDir: relocation.relocated,
      });
    } finally {
      restoreAuthState(workerInput, relocation);
    }
    if (
      result?.workspaceId !== workspaceId
      || !Number.isSafeInteger(result?.resetAt)
      || result.resetAt < 0
    ) {
      throw new Error('Guard auth reset worker returned a mismatched receipt');
    }
    return {
      ...result,
      authStateDir,
      workspace: workspacePath,
    };
  } finally {
    pendingWorkspaceResets.delete(workspaceId);
  }
}
