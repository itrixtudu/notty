#!/usr/bin/env node
// Host-only kernel acceptance probe. Changes only temporary profiles/containers.
// It never writes an activation receipt or changes active NOSH policy.
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import crypto from 'node:crypto';
import { spawnSync } from 'node:child_process';
import { candidateWorkerSpec } from '../lib/command-policy/runner-spec.js';
import { emptyRules } from '../policy-review/modules/command-policy/model.js';

function run(command, args, options = {}) {
  return spawnSync(command, args, { encoding: 'utf8', timeout: 30000, maxBuffer: 1024 * 1024, ...options });
}
const image = process.argv[2];
if (!/^sha256:[a-f0-9]{64}$/.test(image || '') || process.getuid() !== 0) {
  console.error('Run on the Linux Docker/AppArmor host as root: node scripts/command-runner-host-probe.mjs sha256:EXACT_PROBE_IMAGE_ID');
  process.exit(2);
}
const endpoint = process.env.DOCKER_HOST || run('docker', ['context', 'inspect', '--format', '{{.Endpoints.docker.Host}}']).stdout?.trim();
if (!endpoint?.startsWith('unix://')) throw new Error('Probe requires a local Unix-socket Docker daemon');
const security = run('docker', ['info', '--format', '{{json .SecurityOptions}}']);
if (security.status !== 0 || !JSON.parse(security.stdout).some(value => value.includes('apparmor'))) throw new Error('Docker AppArmor is required');
const identity = run('docker', ['image', 'inspect', '--format', '{{.Id}}', image]);
if (identity.status !== 0 || identity.stdout.trim() !== image) throw new Error('Exact local probe image is required');

const directory = await fs.mkdtemp(path.join(os.tmpdir(), 'nosh-command-probe-'));
const workspace = path.join(directory, 'workspace');
await fs.mkdir(workspace);
await fs.chown(workspace, 65534, 65534);
const name = 'nosh-command-probe-' + crypto.randomBytes(8).toString('hex');
const rules = { ...emptyRules('sha256:' + '0'.repeat(64)), rules: [{ id: 'probe', command: 'sed', mode: 'read-only',
  anySwitches: false, allowedSwitches: ['-e', '-n'], requiredSwitches: ['--sandbox'], optionValues: {} }] };
const spec = candidateWorkerSpec({ image, workspace, uid: 65534, gid: 65534, name,
  argv: ['sed', '--sandbox', 's/a/b/'], rules });
const profile = path.join(directory, 'profile');
await fs.writeFile(profile, spec.profile, { mode: 0o600 });
let loaded = false;
try {
  const installed = run('apparmor_parser', ['--replace', profile]);
  if (installed.status !== 0) throw new Error('Profile installation failed: ' + installed.stderr);
  loaded = true;
  const transformed = run('docker', spec.args, { input: 'a\n' });
  if (transformed.status !== 0 || transformed.stdout !== 'b\n') throw new Error('Confined sed stream failed: ' + transformed.stderr);
  // Deliberately bypass the matcher to test kernel denial, not merely validation.
  const prefix = spec.args.slice(0, spec.args.indexOf(image) + 1);
  const escaped = run('docker', [...prefix, '/usr/bin/sed', 'e touch /workspace/escaped'], { input: 'a\n' });
  if (!escaped.stderr?.includes('Permission denied')) throw new Error('No kernel execution-denial evidence: ' + escaped.stderr);
  try { await fs.stat(path.join(workspace, 'escaped')); throw new Error('Worker subprocess escaped'); }
  catch (error) { if (error.code !== 'ENOENT') throw error; }
  await fs.writeFile(path.join(workspace, 'original'), 'a\n');
  await fs.chown(path.join(workspace, 'original'), 65534, 65534);
  const edited = run('docker', [...prefix, '/usr/bin/sed', '--sandbox', '-i', 's/a/b/', '/workspace/original']);
  if (edited.status === 0 || await fs.readFile(path.join(workspace, 'original'), 'utf8') !== 'a\n') throw new Error('Read-only workspace bypass');
  console.log(JSON.stringify({ workerProbePassed: true, enforcementReady: false,
    remaining: ['strict Codex process confinement', 'MCP broker integration', 'alternate-loader/execveat/process-control bypass suite', 'full pipeline and lifecycle tests'] }, null, 2));
} finally {
  const inspected = run('docker', ['inspect', '--format', '{{.Config.Image}}', name]);
  if (inspected.status === 0 && inspected.stdout.trim() === image) run('docker', ['rm', '-f', name]);
  if (loaded) {
    const removed = run('apparmor_parser', ['--remove', profile]);
    if (removed.status !== 0) { console.error('Profile cleanup failed; retained ' + profile); process.exitCode = 1; }
  }
  if (!process.exitCode) await fs.rm(directory, { recursive: true, force: true });
}
