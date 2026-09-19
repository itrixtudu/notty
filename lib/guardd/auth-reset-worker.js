import process from 'node:process';
import { pathToFileURL } from 'node:url';

import { AuthStateDatabase } from '../authState.js';

function numericIdentity(value, label) {
  if (typeof value !== 'string' || !/^(?:0|[1-9][0-9]*)$/.test(value)) {
    throw new TypeError(`${label} must be a non-negative integer`);
  }
  const selected = Number(value);
  if (!Number.isSafeInteger(selected)) {
    throw new TypeError(`${label} must be a safe integer`);
  }
  return selected;
}

function dropWorkerPrivileges(uid, gid) {
  const currentUid = process.geteuid?.();
  const currentGid = process.getegid?.();
  if (!Number.isSafeInteger(currentUid) || !Number.isSafeInteger(currentGid)) {
    throw new Error('Guard auth reset worker requires Unix process identities');
  }

  if (currentUid === 0) {
    process.setgroups([]);
    process.setgid(gid);
    process.setuid(uid);
  } else if (currentUid !== uid || currentGid !== gid) {
    throw new Error('Guard auth reset worker identity does not match the workspace owner');
  }

  if (process.geteuid?.() !== uid || process.getegid?.() !== gid) {
    throw new Error('Guard auth reset worker failed to drop privileges');
  }
  const remainingGroups = process.getgroups?.() || [];
  if (remainingGroups.some((group) => group !== gid)) {
    throw new Error('Guard auth reset worker retained supplementary groups');
  }
}

export function executeAuthResetWorker(argv = process.argv.slice(2)) {
  const [stateDirectory, workspaceRoot, workspaceId, uidValue, gidValue, ...extra] = argv;
  if (
    extra.length
    || !stateDirectory
    || !workspaceRoot
    || !workspaceId
  ) {
    throw new TypeError(
      'Guard auth reset worker requires state directory, workspace, workspace id, uid, and gid',
    );
  }

  const uid = numericIdentity(uidValue, 'workspace uid');
  const gid = numericIdentity(gidValue, 'workspace gid');
  if (uid === 0 || gid === 0) {
    throw new Error('Guard auth reset worker requires a non-root workspace owner and group');
  }
  dropWorkerPrivileges(uid, gid);

  const state = new AuthStateDatabase({
    stateDirectory,
    workspaceRoot,
    workspaceId,
  });
  try {
    return state.reset();
  } finally {
    state.close();
  }
}

if (import.meta.url === pathToFileURL(process.argv[1] || '').href) {
  try {
    process.stdout.write(`${JSON.stringify(executeAuthResetWorker())}\n`);
  } catch (error) {
    process.stderr.write(`Guard auth reset worker failed: ${error.message}\n`);
    process.exitCode = 1;
  }
}
