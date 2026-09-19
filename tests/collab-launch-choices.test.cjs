'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');
const { resolveLaunchChoices } = require('../lib/collab/session.cjs');

const prompts = {
  coder: { role: 'coder', identity: 'coder' },
  lead: { role: 'lead', identity: 'lead', coordinatorCapable: true },
};
const template = {
  agents: ['coder_codex_original', 'coder_codex_original'],
  coordinatorSpec: 'lead_codex_original',
};
const choice = { harness: 'codex', backend: 'ollama', model: 'qwen3:4b', think: 'high' };

test('per-launch choices preserve duplicate roles and do not mutate the template', () => {
  const before = structuredClone(template);
  const roster = resolveLaunchChoices(template, prompts, 'human', [choice, { ...choice, model: 'second' }]);
  assert.deepEqual(roster.agents.map((agent) => agent.model), ['qwen3:4b', 'second']);
  assert.deepEqual(roster.agents.map((agent) => agent.prompt), ['coder', 'coder']);
  assert.equal(roster.agents[0].think, 'high');
  assert.deepEqual(template, before);
});

test('launch choices include the coordinator fallback only in agent mode', () => {
  const roster = resolveLaunchChoices(template, prompts, 'agent', [choice, choice, choice]);
  assert.deepEqual(roster.agents.map((agent) => agent.prompt), ['lead', 'coder', 'coder']);
  assert.equal(roster.agents.filter((agent) => agent.coordinatorCapable).length, 1);
  assert.equal(resolveLaunchChoices(template, prompts, 'human').agents[0].model, 'original');
});

test('launch choices cannot add roles, change roster size, or use incompatible targets', () => {
  for (const choices of [null, [], [choice], [{ ...choice, prompt: 'lead' }, choice], [{ ...choice, model: '' }, choice]]) {
    assert.throws(() => resolveLaunchChoices(template, prompts, 'human', choices), { statusCode: 422 });
  }
  assert.throws(() => resolveLaunchChoices(template, prompts, 'human', [{ ...choice, harness: 'agy' }, choice]), /requires the codex/);
});
