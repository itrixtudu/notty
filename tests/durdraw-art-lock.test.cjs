'use strict';

const assert = require('node:assert/strict');
const childProcess = require('node:child_process');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const test = require('node:test');

const appRoot = path.resolve(__dirname, '..');
const helperPath = path.join(appRoot, 'scripts', 'durdraw-art-lock.mjs');

function createFixture(t) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'notty-durdraw-art-lock-'));
  const children = new Set();

  t.after(async () => {
    for (const processHandle of children) {
      if (processHandle.child.exitCode === null && processHandle.child.signalCode === null) {
        processHandle.child.kill('SIGKILL');
      }
    }
    await Promise.allSettled([...children].map(({ completion }) => completion));
    fs.rmSync(root, { recursive: true, force: true });
  });

  return { root, children };
}

function helperEnvironment(root) {
  return {
    ...process.env,
    ART_WORKSPACE: root,
  };
}

function runHelper(root, args) {
  const result = childProcess.spawnSync(process.execPath, [helperPath, ...args], {
    cwd: root,
    encoding: 'utf8',
    env: helperEnvironment(root),
  });
  return {
    ...result,
    output: `${result.stdout || ''}${result.stderr || ''}`,
  };
}

function spawnHelper(fixture, args) {
  const child = childProcess.spawn(process.execPath, [helperPath, ...args], {
    cwd: fixture.root,
    env: helperEnvironment(fixture.root),
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  let stdout = '';
  let stderr = '';
  let settled = false;

  child.stdout.setEncoding('utf8');
  child.stderr.setEncoding('utf8');
  child.stdout.on('data', (chunk) => {
    stdout += chunk;
  });
  child.stderr.on('data', (chunk) => {
    stderr += chunk;
  });

  const processHandle = {
    child,
    get settled() {
      return settled;
    },
  };
  processHandle.completion = new Promise((resolve, reject) => {
    child.once('error', reject);
    child.once('close', (status, signal) => {
      settled = true;
      resolve({
        status,
        signal,
        stdout,
        stderr,
        output: `${stdout}${stderr}`,
      });
    });
  });
  fixture.children.add(processHandle);

  return processHandle;
}

function parseJsonOutput(result) {
  assert.equal(result.status, 0, result.output);
  assert.equal(result.signal, null, result.output);
  return JSON.parse(result.stdout.trim());
}

function readEvents(root) {
  const eventPath = path.join(root, 'coordination', 'lock-events.jsonl');
  return fs.readFileSync(eventPath, 'utf8')
    .split(/\r?\n/)
    .filter(Boolean)
    .map((line) => JSON.parse(line));
}

async function waitFor(predicate, timeoutMs = 2_000) {
  const deadline = Date.now() + timeoutMs;
  while (!predicate()) {
    if (Date.now() >= deadline) {
      return false;
    }
    await new Promise((resolve) => setTimeout(resolve, 20));
  }
  return true;
}

test('Durdraw art lock accepts normalized relative targets and rejects escapes', async (t) => {
  const fixture = createFixture(t);
  const { normalizeTarget } = await import('../scripts/durdraw-art-lock.mjs');
  const escapedDirectory = path.resolve(
    fixture.root,
    '..',
    `outside-${path.basename(fixture.root)}`,
  );
  t.after(() => fs.rmSync(escapedDirectory, { recursive: true, force: true }));

  assert.equal(normalizeTarget('art/./shared/banner.dur'), 'art/shared/banner.dur');
  assert.equal(normalizeTarget('art/drafts/../banner.dur'), 'art/banner.dur');

  for (const unsafeTarget of [
    '',
    '.',
    '/tmp/banner.dur',
    '../banner.dur',
    '../../outside/banner.dur',
    '..\\..\\outside\\banner.dur',
  ]) {
    assert.throws(
      () => normalizeTarget(unsafeTarget),
      /target must be a safe relative path/,
      unsafeTarget,
    );
  }

  const invalid = runHelper(fixture.root, [
    'acquire',
    'unsafe-agent',
    `../../../${path.basename(escapedDirectory)}/banner.dur`,
  ]);
  assert.notEqual(invalid.status, 0);
  assert.match(invalid.stderr, /target must be a safe relative path/);
  assert.equal(
    fs.existsSync(path.join(escapedDirectory, 'banner.dur')),
    false,
  );
});

test('Durdraw art lock refuses unchanged releases and premature readiness', (t) => {
  const fixture = createFixture(t);
  const target = 'artist-a.ans';
  const targetFile = path.join(fixture.root, target);
  const lockFile = path.join(fixture.root, 'agents', 'locks', target);

  const earlyReady = runHelper(fixture.root, ['ready', 'artist-a']);
  assert.notEqual(earlyReady.status, 0);
  assert.match(earlyReady.stderr, /personal art is missing or empty/);

  assert.equal(runHelper(fixture.root, ['acquire', 'artist-a', target]).status, 0);
  const unchanged = runHelper(fixture.root, ['release', 'artist-a', target]);
  assert.notEqual(unchanged.status, 0);
  assert.match(unchanged.stderr, /refusing to release unchanged art target/);
  assert.equal(fs.readFileSync(lockFile, 'utf8').trim(), 'artist-a');

  fs.writeFileSync(targetFile, '\u001b[31m[artist-a]\u001b[0m\r\n');
  assert.equal(runHelper(fixture.root, ['release', 'artist-a', target]).status, 0);
  const ready = runHelper(fixture.root, ['ready', 'artist-a']);
  assert.deepEqual(parseJsonOutput(ready), { ready: true, agent: 'artist-a' });
});

test('Durdraw art lock serializes two barrier participants and hands off atomically', {
  timeout: 15_000,
}, async (t) => {
  const fixture = createFixture(t);
  const target = 'art/shared/banner.dur';
  const agents = ['alice', 'bob'];
  const lockFile = path.join(fixture.root, 'agents', 'locks', ...target.split('/'));
  const targetFile = path.join(fixture.root, ...target.split('/'));
  const barrierFile = path.join(fixture.root, 'coordination', 'go');
  fs.mkdirSync(path.dirname(targetFile), { recursive: true });
  fs.writeFileSync(targetFile, 'seed\n');

  const participants = agents.map((agent) => ({
    agent,
    processHandle: spawnHelper(fixture, [
      'begin-shared',
      agent,
      target,
      '8000',
    ]),
  }));

  assert.equal(
    await waitFor(() => fs.existsSync(path.dirname(barrierFile))),
    true,
    'participants should initialize the coordination directory',
  );
  await new Promise((resolve) => setTimeout(resolve, 100));
  assert.equal(fs.existsSync(lockFile), false, 'no lock may be taken before the barrier');
  assert.ok(
    participants.every(({ processHandle }) => !processHandle.settled),
    'both participants should wait at the barrier',
  );

  fs.writeFileSync(barrierFile, 'go\n', { encoding: 'utf8', flag: 'wx' });

  const firstCompletion = await Promise.race(
    participants.map(async (participant) => ({
      participant,
      result: await participant.processHandle.completion,
    })),
  );
  const firstPayload = parseJsonOutput(firstCompletion.result);
  assert.equal(firstPayload.role, 'first');
  assert.equal(firstPayload.owner, firstCompletion.participant.agent);
  assert.equal(firstPayload.target, target);
  assert.equal(fs.readFileSync(lockFile, 'utf8').trim(), firstPayload.owner);
  fs.appendFileSync(targetFile, `${firstPayload.owner} first\n`);

  const secondParticipant = participants.find(
    ({ agent }) => agent !== firstPayload.owner,
  );
  assert.ok(secondParticipant);
  assert.equal(
    secondParticipant.processHandle.settled,
    false,
    'the contending participant must remain blocked while the first owns the lock',
  );

  const releaseFirst = runHelper(fixture.root, [
    'release',
    firstPayload.owner,
    target,
  ]);
  assert.deepEqual(parseJsonOutput(releaseFirst), {
    released: true,
    agent: firstPayload.owner,
    target,
  });

  const secondResult = await secondParticipant.processHandle.completion;
  const secondPayload = parseJsonOutput(secondResult);
  assert.equal(secondPayload.role, 'second');
  assert.equal(secondPayload.owner, secondParticipant.agent);
  assert.equal(secondPayload.target, target);
  assert.equal(fs.readFileSync(lockFile, 'utf8').trim(), secondPayload.owner);
  fs.appendFileSync(targetFile, `${secondPayload.owner} second\n`);

  const releaseSecond = runHelper(fixture.root, [
    'release',
    secondPayload.owner,
    target,
  ]);
  assert.deepEqual(parseJsonOutput(releaseSecond), {
    released: true,
    agent: secondPayload.owner,
    target,
  });

  assert.equal(fs.existsSync(lockFile), false, 'the shared lock must be released');
  assert.equal(
    fs.existsSync(path.join(fixture.root, 'coordination', '.lock-events.guard')),
    false,
    'the event writer guard must not be left behind',
  );

  const events = readEvents(fixture.root);
  const targetEvents = events.filter((event) => event.target === target);
  const blockedEvents = targetEvents.filter((event) => event.action === 'blocked');
  assert.deepEqual(
    targetEvents
      .filter((event) => event.action === 'acquired')
      .map((event) => event.role)
      .sort(),
    ['first', 'second'],
  );
  assert.equal(
    targetEvents.filter((event) => event.action === 'released').length,
    2,
  );
  assert.equal(
    targetEvents.filter((event) => event.action === 'releasing' && event.changed).length,
    2,
  );
  assert.ok(blockedEvents.length >= 1, 'contention should emit at least one blocked event');
  assert.ok(
    blockedEvents.some(
      (event) => event.agent === secondPayload.owner && event.owner === firstPayload.owner,
    ),
    'the blocked event should identify the waiter and current owner',
  );

  const firstAcquiredIndex = targetEvents.findIndex(
    (event) => event.action === 'acquired'
      && event.agent === firstPayload.owner
      && event.role === 'first',
  );
  const firstReleasedIndex = targetEvents.findIndex(
    (event) => event.action === 'released' && event.agent === firstPayload.owner,
  );
  const firstVerifiedIndex = targetEvents.findIndex(
    (event) => event.action === 'verified' && event.agent === firstPayload.owner,
  );
  const secondAcquiredIndex = targetEvents.findIndex(
    (event) => event.action === 'acquired'
      && event.agent === secondPayload.owner
      && event.role === 'second',
  );
  const secondReleasedIndex = targetEvents.findIndex(
    (event) => event.action === 'released' && event.agent === secondPayload.owner,
  );

  assert.ok(firstAcquiredIndex >= 0, 'the first role should be recorded');
  assert.ok(
    firstVerifiedIndex > firstAcquiredIndex,
    'the first owner should verify ownership before releasing',
  );
  assert.ok(firstReleasedIndex > firstAcquiredIndex, 'the first owner should release');
  assert.ok(
    secondAcquiredIndex > firstVerifiedIndex,
    'the second role may acquire only after the first release begins',
  );
  assert.ok(secondReleasedIndex > secondAcquiredIndex, 'the second owner should release');
  assert.equal(
    targetEvents.filter((event) => event.action === 'handoff_ready').length,
    1,
  );
  assert.equal(
    targetEvents.filter((event) => event.action === 'handoff_complete').length,
    1,
  );
});
