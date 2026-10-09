'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const modules = Promise.all([import('../modules/command-policy/model.js'), import('../modules/command-policy/analyze.js')]);
const digest = 'sha256:' + 'a'.repeat(64);

async function rule(changes = {}) {
  const [model] = await modules;
  return model.validateRules({ ...model.emptyRules(digest), rules: [{ id: 'sed', command: 'sed', mode: 'read-only',
    anySwitches: false, allowedSwitches: ['-n', '-e', '-E'], requiredSwitches: ['--sandbox'], optionValues: {}, ...changes }] }, digest).rules[0];
}

test('switch matching handles aliases, combinations, attached values, repeated values and --', async () => {
  const [model] = await modules;
  const allowed = await rule({ optionValues: { '-e': ['*p'] } });
  for (const argv of [
    ['sed', '--sandbox', '-ne1p'], ['sed', '--sandbox', '--quiet', '--expression=1p'],
    ['sed', '--sandbox', '-n', '-e', '1p', '-e', '2p', '--', '-filename'],
  ]) assert.equal(model.matchRule(allowed, model.parseInvocation(argv)).matches, true);
  assert.equal(model.matchRule(allowed, model.parseInvocation(['sed', '--sandbox', '-e', '1p', '-e', 'w out'])).matches, false);
  assert.deepEqual(model.parseInvocation(['sed', '--sandbox', '-n', '1p', '--', '-n']).files, ['-n']);
});

test('wildcards are anchored literal token patterns, not regex or shell evaluation', async () => {
  const [model] = await modules;
  assert.equal(model.globMatch('--col*', '--color'), true);
  assert.equal(model.globMatch('--col*', '--not-color'), false);
  assert.equal(model.globMatch('a?c', 'abc'), true);
  assert.equal(model.globMatch('a.b', 'axb'), false);
  assert.equal(model.globMatch('$(id)', '$(id)'), true);
  assert.equal(model.globMatch('*a*b', 'x'.repeat(10000)), false);
});

test('any switches retains required switches, value conditions, workspace restrictions and xargs denial', async () => {
  const [model] = await modules;
  const allowed = await rule({ anySwitches: true, optionValues: { '-e': ['*p'] } });
  assert.equal(model.matchRule(allowed, model.parseInvocation(['sed', '--sandbox', '-z', '-e', '1p'])).matches, true);
  assert.equal(model.matchRule(allowed, model.parseInvocation(['sed', '-z', '-e', '1p'])).matches, false);
  assert.equal(model.matchRule(allowed, model.parseInvocation(['sed', '--sandbox', '-e', 'w out'])).matches, false);
  assert.equal(model.matchRule(allowed, model.parseInvocation(['sed', '--sandbox', '-i', '1p', 'file']), 'implementation').matches, false);
  const writer = await rule({ anySwitches: true, mode: 'implementation' });
  assert.equal(model.matchRule(writer, model.parseInvocation(['sed', '--sandbox', '-i.bak', 's/a/b/', 'file']), 'implementation').matches, true);
  assert.equal(model.parseInvocation(['xargs', '-0', 'sed']).supported, false);
  assert.equal(model.parseInvocation(['/tmp/sed', '--sandbox', '1p']).supported, false);
});

test('pipeline validation rejects an unauthorized stage before execution and never marks drafts active', async () => {
  const [model] = await modules;
  const document = { ...model.emptyRules(digest), rules: [await rule()] };
  assert.equal(model.authorizePipeline(document, [['sed', '--sandbox', '-n', '1p']]).allowed, true);
  assert.equal(model.authorizePipeline(document, [['sed', '--sandbox', '-n', '1p'], ['xargs', 'sh']]).allowed, false);
  assert.equal(model.authorizePipeline(document, [['sed', '--sandbox', '1p']], 'invalid').allowed, false);
  assert.equal(model.ENFORCEMENT.ready, false);
  assert.throws(() => model.validateRules({ ...document, enforcing: true }, digest));
});

test('literal analysis separates pipeline stages while preserving quoting and declining expansions', async () => {
  const [, analysis] = await modules;
  assert.deepEqual(analysis.literalPipeline("cat 'file name' | sed --sandbox -e 's/a|b/c/'"),
    [['cat', 'file name'], ['sed', '--sandbox', '-e', 's/a|b/c/']]);
  for (const source of ['cat $FILE', 'cat a > b', 'cat a && sed x', 'cat a || sed x', 'cat `id`', 'cat *.txt', 'cat a\nsed x']) {
    assert.equal(analysis.literalPipeline(source), null, source);
  }
  const result = analysis.analyzeRequest('exec_command', { cmd: "cat file | sed --sandbox -n '1p'" });
  assert.equal(result.commands[1].input, 'stdin');
});

test('orchestration analysis extracts only static arguments without evaluating recorded code', async () => {
  const [, analysis] = await modules;
  globalThis.commandPolicyMustNotRun = false;
  const result = analysis.analyzeRequest('exec', 'globalThis.commandPolicyMustNotRun = true; await tools.exec_command({cmd:"sed --sandbox -n 1p file"}); await tools.exec_command(dynamic);');
  assert.equal(globalThis.commandPolicyMustNotRun, false);
  assert.equal(result.commands[0].command, 'sed');
  assert.equal(result.commands[0].nested, true);
  assert.equal(result.unresolved, true);
  delete globalThis.commandPolicyMustNotRun;
});
