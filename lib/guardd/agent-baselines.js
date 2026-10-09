import crypto from 'node:crypto';
import fs from 'node:fs/promises';
import { constants } from 'node:fs';
import { AGENTS } from './workload.js';
import { normalizeEgressRules } from './net-profile-store.js';

// Baselines are review inputs, never activation authority. Pin the exact bytes
// on the command line so a changed file cannot silently widen a future learn.
export async function readAgentBaselines(selections = [], { workload, agents, uid } = {}) {
  if (selections.length && workload !== 'dev') throw new Error('agent baselines require the dev workload');
  const baselines = [];
  for (const selection of selections) {
    const match = /^(.*)@(sha256:[a-f0-9]{64})$/.exec(selection);
    if (!match) throw new Error('agent baseline must be FILE@sha256:DIGEST');
    const handle = await fs.open(match[1], constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
    let source;
    try {
      const stat = await handle.stat();
      if (!stat.isFile() || stat.size > 1024 * 1024 || stat.uid !== uid || (stat.mode & 0o022)) {
        throw new Error('agent baseline must be a caller-owned regular file, at most 1 MiB, without group/world write access');
      }
      source = await handle.readFile();
    } finally { await handle.close(); }
    const digest = `sha256:${crypto.createHash('sha256').update(source).digest('hex')}`;
    if (digest !== match[2]) throw new Error('agent baseline digest changed');
    const doc = JSON.parse(source);
    const keys = ['schemaVersion', 'agent', 'revision', 'imageDigest', 'toolVersion', 'rules'];
    if (Object.keys(doc).some((key) => !keys.includes(key)) || doc.schemaVersion !== 1
      || !AGENTS.includes(doc.agent) || !agents.includes(doc.agent)
      || !/^[A-Za-z0-9_.-]{1,128}$/.test(doc.revision || '')
      || !/^sha256:[a-f0-9]{64}$/.test(doc.imageDigest || '')
      || typeof doc.toolVersion !== 'string' || !/^[A-Za-z0-9_.+ -]{1,128}$/.test(doc.toolVersion)) {
      throw new Error('invalid or unselected agent baseline; expected schemaVersion, agent, revision, imageDigest, toolVersion, rules');
    }
    if (!Array.isArray(doc.rules) || doc.rules.some((rule) => !rule || Object.keys(rule).some(
      (key) => !['destination', 'protocol', 'ports', 'icmpType', 'icmpCode'].includes(key),
    ))) throw new Error('baseline rules may contain only destination/protocol/ports/ICMP fields');
    if (baselines.some((entry) => entry.agent === doc.agent)) throw new Error('select only one baseline revision per agent');
    baselines.push({ ...doc, digest, rules: normalizeEgressRules(doc.rules) });
  }
  return baselines;
}

export function composeAgentBaselines(rules, baselines, imageDigest) {
  for (const baseline of baselines) {
    if (baseline.imageDigest !== imageDigest) throw new Error(`baseline for ${baseline.agent} targets another image; relearn or review a compatible baseline`);
  }
  return normalizeEgressRules([...rules, ...baselines.flatMap((baseline) => baseline.rules.map((rule) => ({
    ...rule,
    observations: [{ source: 'agent-baseline', agent: baseline.agent, revision: baseline.revision,
      digest: baseline.digest, toolVersion: baseline.toolVersion }],
  })))]);
}
