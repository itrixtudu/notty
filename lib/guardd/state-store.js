import crypto from 'node:crypto';
import fs from 'node:fs/promises';
import { constants as fsConstants } from 'node:fs';
import path from 'node:path';

import { DEFAULT_GUARD_STATE_DIR, GUARD_SCHEMA_VERSION } from './constants.js';

const MAX_RUN_STATE_BYTES = 16 * 1024 * 1024;

function safeSegment(value, label) {
  if (typeof value !== 'string' || !/^[A-Za-z0-9_.-]+$/.test(value)) {
    throw new TypeError(`${label} contains unsupported characters`);
  }
  return value;
}

function requiredStateUid() {
  return typeof process.geteuid === 'function' ? process.geteuid() : null;
}

async function secureDirectory(directoryPath, mode = 0o700) {
  const resolved = path.resolve(directoryPath);
  await fs.mkdir(resolved, { recursive: true, mode });
  if ((await fs.realpath(resolved)) !== resolved) {
    throw new Error(
      `guard state directory path must not contain symbolic links: ${resolved}`,
    );
  }
  const handle = await fs.open(
    resolved,
    fsConstants.O_RDONLY |
      (fsConstants.O_DIRECTORY || 0) |
      (fsConstants.O_NOFOLLOW || 0),
  );
  try {
    const before = await handle.stat();
    const expectedUid = requiredStateUid();
    if (!before.isDirectory()) {
      throw new Error(`guard state path is not a directory: ${resolved}`);
    }
    if (expectedUid != null && before.uid !== expectedUid) {
      throw new Error(
        `guard state directory must be owned by uid ${expectedUid}: ${resolved}`,
      );
    }
    await handle.chmod(mode);
    const after = await handle.stat();
    const current = await fs.lstat(resolved);
    if (
      !current.isDirectory()
      || current.isSymbolicLink()
      || current.dev !== after.dev
      || current.ino !== after.ino
    ) {
      throw new Error(`guard state directory changed during validation: ${resolved}`);
    }
    if ((after.mode & 0o7777) !== mode) {
      throw new Error(
        `guard state directory mode must be ${mode.toString(8)}: ${resolved}`,
      );
    }
  } finally {
    await handle.close();
  }
}

async function readTrustedRunFile(filePath) {
  const handle = await fs.open(
    filePath,
    fsConstants.O_RDONLY | (fsConstants.O_NOFOLLOW || 0),
  );
  try {
    const stat = await handle.stat();
    const expectedUid = requiredStateUid();
    if (!stat.isFile() || stat.nlink !== 1) {
      throw new Error(`guard run state must be a singly-linked regular file: ${filePath}`);
    }
    if (expectedUid != null && stat.uid !== expectedUid) {
      throw new Error(
        `guard run state must be owned by uid ${expectedUid}: ${filePath}`,
      );
    }
    if ((stat.mode & 0o7777) !== 0o600) {
      throw new Error(`guard run state mode must be 600: ${filePath}`);
    }
    if (stat.size > MAX_RUN_STATE_BYTES) {
      throw new Error(
        `guard run state exceeds ${MAX_RUN_STATE_BYTES} bytes: ${filePath}`,
      );
    }
    return JSON.parse(await handle.readFile('utf8'));
  } finally {
    await handle.close();
  }
}

export class GuardStateStore {
  constructor(root = DEFAULT_GUARD_STATE_DIR) {
    this.root = path.resolve(root);
    this.runsDir = path.join(this.root, 'runs');
    this.profilesDir = path.join(this.root, 'profiles');
    this.evidenceDir = path.join(this.root, 'evidence');
  }

  async initialize() {
    await secureDirectory(this.root);
    await secureDirectory(this.runsDir);
    await secureDirectory(this.profilesDir);
    await secureDirectory(this.evidenceDir);
  }

  runPath(runId) {
    return path.join(this.runsDir, `${safeSegment(runId, 'runId')}.json`);
  }

  evidencePath(runId) {
    return path.join(this.evidenceDir, safeSegment(runId, 'runId'));
  }

  async writeRun(run) {
    const runId = safeSegment(run?.runId, 'runId');
    const now = new Date().toISOString();
    const document = {
      schemaVersion: GUARD_SCHEMA_VERSION,
      createdAt: run.createdAt || now,
      ...run,
      runId,
      updatedAt: now,
    };
    const destination = this.runPath(runId);
    const temporary = `${destination}.${process.pid}.${crypto.randomUUID()}.tmp`;
    let handle;
    try {
      handle = await fs.open(
        temporary,
        fsConstants.O_WRONLY |
          fsConstants.O_CREAT |
          fsConstants.O_EXCL |
          (fsConstants.O_NOFOLLOW || 0),
        0o600,
      );
      await handle.writeFile(`${JSON.stringify(document, null, 2)}\n`, 'utf8');
      await handle.sync();
      await handle.close();
      handle = null;
      await fs.rename(temporary, destination);
    } catch (error) {
      await handle?.close().catch(() => {});
      await fs.unlink(temporary).catch(() => {});
      throw error;
    }
    return document;
  }

  async readRun(runId) {
    const expectedRunId = safeSegment(runId, 'runId');
    const document = await readTrustedRunFile(this.runPath(expectedRunId));
    if (document?.runId !== expectedRunId) {
      throw new Error(
        `guard run state identity does not match ${expectedRunId}`,
      );
    }
    return document;
  }

  async findRun(identifier) {
    try {
      return await this.readRun(identifier);
    } catch (error) {
      if (error?.code !== 'ENOENT') {
        throw error;
      }
    }
    const entries = await fs.readdir(this.runsDir);
    for (const entry of entries) {
      if (!entry.endsWith('.json')) {
        continue;
      }
      const run = await this.readRun(entry.slice(0, -'.json'.length));
      if (run.name === identifier || run.containerId === identifier) {
        return run;
      }
    }
    return null;
  }

  async listRuns() {
    const entries = await fs.readdir(this.runsDir);
    const runs = [];
    for (const entry of entries.sort()) {
      if (!entry.endsWith('.json')) {
        continue;
      }
      runs.push(await this.readRun(entry.slice(0, -'.json'.length)));
    }
    return runs;
  }

  async removeRun(runId) {
    await fs.rm(this.runPath(runId), { force: true });
  }
}
