import fs from 'node:fs';
import path from 'node:path';
import { spawn, spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { RUNNER_RUNTIME_HOME } from './constants.js';

export const AGENTS = Object.freeze(['codex', 'claude', 'gemini']);
export const codexStateHelper = fileURLToPath(new URL('../../scripts/codex-state.py', import.meta.url));

export async function reserveCodexProfile(mounts = []) {
  const mount = mounts.find((entry) => entry.agent === 'codex');
  if (!mount) return null;
  const child = spawn('python3', [codexStateHelper, 'lease', '--codex-home', mount.source,
    '--uid', String(mount.uid)], { detached: true, stdio: ['pipe', 'pipe', 'pipe'] });
  await new Promise((resolve, reject) => {
    let errors = '';
    child.stderr.on('data', (data) => { errors += data; });
    child.once('error', reject);
    child.once('exit', () => reject(new Error(errors.trim() || 'Codex profile lease failed')));
    child.stdout.once('data', (data) => {
      if (String(data).trim() === 'locked') resolve();
      else reject(new Error('invalid Codex lease handshake'));
    });
  });
  return {
    bind(containerId) {
      child.stdin.end(`${containerId}\n`);
      child.stdout.destroy();
      child.stderr.destroy();
      child.unref();
    },
    cancel() { child.stdin.end(); },
  };
}

export function resourceModes(options) {
  if (!['skills', 'settings', 'plugins'].some((key) => options[`agent-${key}`] !== undefined)) return undefined;
  return Object.fromEntries(['skills', 'settings', 'plugins'].map((key) => {
    const value = options[`agent-${key}`] || 'ro';
    if (!['ro', 'rw'].includes(value)) throw new Error(`--agent-${key} must be ro or rw`);
    return [key, value];
  }));
}

function codexPolicy(user, codex, workspace, modes, prepare = false) {
  if (!workspace) throw new Error('Codex resource policy requires a workspace');
  const args = [codexStateHelper, 'policy', '--home', user.home, '--codex-home', codex,
    '--workspace', workspace, '--target-home', RUNNER_RUNTIME_HOME, '--uid', String(user.uid)];
  for (const key of ['skills', 'settings', 'plugins']) args.push(`--${key}`, modes[key] || 'ro');
  if (prepare) args.push('--prepare');
  const result = spawnSync('python3', args, { encoding: 'utf8',
    ...(process.getuid() === 0 ? { uid: user.uid, gid: user.gid ?? user.uid } : {}) });
  if (result.status !== 0) throw new Error(result.stderr?.trim() || result.error?.message || 'Codex resource validation failed');
  const policy = JSON.parse(result.stdout);
  policy.resources = policy.resources.map((resource) => ({
    ...checkedMount(resource.source, resource.target, user, resource.kind, 'codex'),
    mode: resource.mode, category: resource.category,
  }));
  return policy;
}

export function flattenedAgentMounts(mounts = []) {
  return mounts.flatMap((mount) => [mount, ...(mount.policy?.resources || [])]);
}

export function validateCodexAliases(mounts, extraSources = []) {
  const codex = mounts.find((mount) => mount.policy);
  if (!codex) return;
  const protectedPaths = [codex.source, ...codex.policy.resources.map((entry) => entry.source)];
  for (const source of [...mounts.filter((mount) => mount !== codex).map((mount) => mount.source), ...extraSources]) {
    if (!source) continue;
    if (protectedPaths.some((protectedPath) => source === protectedPath
      || source.startsWith(`${protectedPath}/`) || protectedPath.startsWith(`${source}/`))) {
      throw new Error('additional mount exposes a protected Codex resource');
    }
  }
}

export function workloadName(value = 'dev') {
  if (!['dev', 'run'].includes(value)) {
    throw new TypeError('workload must be dev or run');
  }
  return value;
}

export function selectedAgents(value = 'auto', workload = 'dev') {
  workloadName(workload);
  if (workload !== 'dev') {
    if (value !== 'none' && value !== 'auto') throw new Error('agent homes require the dev workload');
    return [];
  }
  if (value === 'none') return [];
  if (value === 'auto') return [...AGENTS];
  const names = [...new Set(String(value).split(','))];
  if (!names.length || names.some((name) => !AGENTS.includes(name))) {
    throw new TypeError('agents must be auto, none, or comma-separated codex,claude,gemini');
  }
  return names.sort();
}

function checkedMount(source, target, user, kind, agent) {
  const resolved = fs.realpathSync(source);
  if (resolved !== path.resolve(source) || /[:,\r\n\0]/.test(resolved)) {
    throw new Error(`agent home must be a canonical bind-safe path: ${source}`);
  }
  const stat = fs.statSync(resolved);
  if (stat.uid !== user.uid || (kind === 'directory' ? !stat.isDirectory() : !stat.isFile())) {
    throw new Error(`agent state must be a ${kind} owned by the invoking user: ${source}`);
  }
  if (stat.mode & 0o002) throw new Error(`agent state must not be world writable: ${source}`);
  return { agent, source: resolved, target, kind, mode: 'rw', uid: user.uid,
    dev: String(stat.dev), ino: String(stat.ino) };
}

export function resolveAgentHomes({ workload = 'dev', agents = 'auto', user, codexHome, workspace, modes, prepare = true } = {}) {
  const mounts = [];
  for (const agent of selectedAgents(agents, workload)) {
    const source = agent === 'codex' && codexHome ? codexHome : path.join(user.home, `.${agent}`);
    if (!fs.existsSync(source)) {
      if (agents !== 'auto') throw new Error(`missing ${agent} home: ${source}; initialize it on the host or omit this agent`);
      continue;
    }
    mounts.push(checkedMount(source, `${RUNNER_RUNTIME_HOME}/.${agent}`, user, 'directory', agent));
    if (agent === 'codex' && modes) mounts.at(-1).policy = codexPolicy(user, source, workspace, modes, prepare);
    if (agent === 'claude' && fs.existsSync(path.join(user.home, '.claude.json'))) {
      mounts.push(checkedMount(path.join(user.home, '.claude.json'), `${RUNNER_RUNTIME_HOME}/.claude.json`, user, 'file', agent));
    }
  }
  if (modes && !mounts.some((mount) => mount.agent === 'codex')) throw new Error('resource controls require a Codex dev home');
  return { agents: [...new Set(mounts.map((entry) => entry.agent))].sort(), mounts };
}

export function validateAgentMounts(mounts = [], identity, workload = 'dev', workspace) {
  workloadName(workload);
  if (!Array.isArray(mounts) || (workload !== 'dev' && mounts.length)) {
    throw new Error('agent mounts require the dev workload');
  }
  validateCodexAliases(mounts);
  const destinations = new Set();
  return mounts.map((mount) => {
    const expectedTarget = `${RUNNER_RUNTIME_HOME}/.${mount.agent}${mount.kind === 'file' ? '.json' : ''}`;
    if (!AGENTS.includes(mount.agent) || mount.target !== expectedTarget
      || !['directory', 'file'].includes(mount.kind)
      || (mount.kind === 'file' && mount.agent !== 'claude')
      || mount.mode !== 'rw' || destinations.has(mount.target)) {
      throw new Error('invalid or duplicate agent mount destination');
    }
    destinations.add(mount.target);
    const current = checkedMount(mount.source, mount.target, identity, mount.kind, mount.agent);
    if (mount.policy) {
      if (mount.agent !== 'codex' || (workspace && mount.policy.workspace !== workspace)) throw new Error('invalid Codex resource workspace');
      current.policy = codexPolicy({ ...identity, home: mount.policy.home }, mount.source,
        mount.policy.workspace, mount.policy.modes);
      if (!sameAgentMounts(current.policy.resources, mount.policy.resources)) throw new Error('Codex resources changed; learn again');
    }
    // Files may be atomically replaced by credential refresh. Directory identity
    // is stable; record and check it rather than hashing any credential contents.
    if (mount.uid !== current.uid || (mount.kind === 'directory'
      && (mount.dev !== current.dev || mount.ino !== current.ino))) {
      throw new Error('agent home identity changed; learn the dev workload again');
    }
    return current;
  });
}

export function sameAgentMounts(left = [], right = []) {
  const bindings = (mounts) => mounts.map((mount) => ({
    agent: mount.agent, source: mount.source, target: mount.target,
    kind: mount.kind, mode: mount.mode, uid: mount.uid,
    ...(mount.kind === 'directory' ? { dev: mount.dev, ino: mount.ino } : {}),
    ...(mount.policy ? { policy: { ...mount.policy, resources: bindings(mount.policy.resources) } } : {}),
  })).sort((a, b) => a.target.localeCompare(b.target));
  return JSON.stringify(bindings(left)) === JSON.stringify(bindings(right));
}

export function verifyLiveAgentMounts(inspected, mounts = [], initPid, { forceReadOnly = false } = {}) {
  for (const mount of flattenedAgentMounts(mounts)) {
    const actual = inspected.Mounts?.find((entry) => entry.Destination === mount.target);
    if (!actual || actual.Type !== 'bind' || actual.Source !== mount.source || actual.RW !== (!forceReadOnly && mount.mode === 'rw')) {
      throw new Error(`runner agent mount does not match its launch description: ${mount.agent}`);
    }
    if (!Number.isSafeInteger(initPid) || initPid <= 0) throw new Error('agent mount verification requires the live runner PID');
    const live = fs.statSync(`/proc/${initPid}/root${mount.target}`);
    const host = fs.statSync(mount.source);
    if (live.dev !== host.dev || live.ino !== host.ino) throw new Error('live agent mount identity changed');
  }
}
