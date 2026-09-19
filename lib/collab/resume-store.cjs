'use strict';

const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const MAX_BYTES = 1024 * 1024;
const fail = (message) => { throw new Error(`Collab resume index: ${message}`); };
function fields(value, keys) {
  if (!value || typeof value !== 'object' || Array.isArray(value)
    || Object.keys(value).some((key) => !keys.includes(key))) fail('invalid fields');
}
function text(value, limit = 4096) {
  if (typeof value !== 'string' || value.length > limit) fail('invalid text');
}
function validate(document, project) {
  fields(document, ['version', 'project', 'lastTaskId', 'autoResume', 'tasks']);
  if (document.version !== 1 || document.project !== project || typeof document.autoResume !== 'boolean'
    || !Array.isArray(document.tasks) || document.tasks.length > 100) fail('invalid project or schema');
  const ids = new Set();
  for (const task of document.tasks) {
    fields(task, ['id', 'name', 'createdAt', 'updatedAt', 'manualResumes', 'launch', 'roles']);
    if (!UUID.test(task.id) || ids.has(task.id)) fail('invalid task identity');
    ids.add(task.id);
    text(task.name, 120);
    if (!task.name.trim() || !Number.isSafeInteger(task.manualResumes) || task.manualResumes < 0) fail('invalid task');
    text(task.createdAt, 40); text(task.updatedAt, 40);
    if (task.launch !== null) {
      fields(task.launch, ['templateId', 'coordinatorMode', 'channel', 'agentChoices']);
      text(task.launch.templateId, 128); text(task.launch.channel, 128);
      if (!['human', 'agent'].includes(task.launch.coordinatorMode) || !Array.isArray(task.launch.agentChoices)
        || task.launch.agentChoices.length > 100) fail('invalid launch settings');
      for (const choice of task.launch.agentChoices) {
        fields(choice, ['harness', 'backend', 'model', 'think', 'timeoutSeconds', 'terminateOnExpire']);
        require('./timeout.cjs').timeoutPolicy(choice);
        for (const key of ['harness', 'backend', 'model', 'think']) text(choice[key], 256);
      }
    }
    if (!Array.isArray(task.roles) || task.roles.length > 200) fail('invalid roles');
    const roles = new Set();
    for (const role of task.roles) {
      fields(role, ['identity', 'backend', 'marker', 'threadId', 'model', 'think', 'status', 'updatedAt']);
      text(role.identity, 128); text(role.model, 256); text(role.think, 40); text(role.updatedAt, 40);
      if (!['default', 'ollama'].includes(role.backend) || !UUID.test(role.marker)
        || (role.threadId !== '' && !UUID.test(role.threadId))
        || !['capturing', 'saved', 'failed'].includes(role.status)
        || (role.status === 'saved' && !role.threadId) || !role.identity) fail('invalid role metadata');
      const key = `${role.identity}:${role.backend}`;
      if (roles.has(key)) fail('duplicate role');
      roles.add(key);
    }
  }
  if (document.lastTaskId !== null && !ids.has(document.lastTaskId)) fail('unknown selected task');
  return document;
}

function createResumeStore(workspaceRoot) {
  const project = fs.realpathSync(workspaceRoot);
  const directory = path.join(project, '.notty');
  const filename = path.join(directory, 'collab-resume.json');
  function check(target, directoryExpected = false) {
    const stat = fs.lstatSync(target);
    if (stat.isSymbolicLink() || (directoryExpected ? !stat.isDirectory() : !stat.isFile())
      || stat.uid !== process.getuid() || (stat.mode & (directoryExpected ? 0o022 : 0o077))
      || (!directoryExpected && (stat.nlink !== 1 || stat.size > MAX_BYTES))) fail('unsafe state path');
    return stat;
  }
  function prepare() {
    try { fs.mkdirSync(directory, { mode: 0o700 }); } catch (error) { if (error.code !== 'EEXIST') throw error; }
    check(directory, true);
  }
  function read() {
    try { check(directory, true); } catch (error) {
      if (error.code === 'ENOENT') return { version: 1, project, lastTaskId: null, autoResume: false, tasks: [] };
      throw error;
    }
    let fd;
    try {
      check(filename);
      fd = fs.openSync(filename, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW);
      const stat = fs.fstatSync(fd);
      if (!stat.isFile() || stat.size > MAX_BYTES || stat.nlink !== 1 || stat.uid !== process.getuid() || (stat.mode & 0o077)) fail('unsafe index');
      const buffer = Buffer.alloc(MAX_BYTES + 1);
      let length = 0;
      while (length < buffer.length) {
        const count = fs.readSync(fd, buffer, length, buffer.length - length, length);
        if (!count) break;
        length += count;
      }
      if (length > MAX_BYTES) fail('index capacity exceeded');
      return validate(JSON.parse(buffer.subarray(0, length).toString('utf8')), project);
    } catch (error) {
      if (error.code === 'ENOENT') return { version: 1, project, lastTaskId: null, autoResume: false, tasks: [] };
      throw error;
    } finally { if (fd !== undefined) fs.closeSync(fd); }
  }
  function update(change) {
    prepare();
    const lock = `${filename}.lock`;
    const fd = fs.openSync(lock, 'wx', 0o600);
    let temporary;
    try {
      const document = read();
      change(document);
      validate(document, project);
      const data = `${JSON.stringify(document, null, 2)}\n`;
      if (Buffer.byteLength(data) > MAX_BYTES) fail('index capacity exceeded');
      temporary = `${filename}.${crypto.randomUUID()}.tmp`;
      const output = fs.openSync(temporary, 'wx', 0o600);
      try { fs.writeFileSync(output, data); fs.fsyncSync(output); } finally { fs.closeSync(output); }
      fs.renameSync(temporary, filename);
      temporary = null;
      const directoryFd = fs.openSync(directory, fs.constants.O_RDONLY | fs.constants.O_DIRECTORY | fs.constants.O_NOFOLLOW);
      try { fs.fsyncSync(directoryFd); } finally { fs.closeSync(directoryFd); }
      return document;
    } finally {
      if (temporary) fs.unlinkSync(temporary);
      fs.closeSync(fd);
      fs.unlinkSync(lock);
    }
  }
  function createTask(name) {
    text(name, 120);
    if (!name.trim()) fail('task name is required');
    const id = crypto.randomUUID();
    return update((document) => {
      const now = new Date().toISOString();
      document.tasks.push({ id, name: name.trim(), createdAt: now, updatedAt: now, manualResumes: 0, launch: null, roles: [] });
      document.lastTaskId = id;
      document.autoResume = false;
    });
  }
  return { read, update, createTask, filename };
}

module.exports = { createResumeStore, validate };
