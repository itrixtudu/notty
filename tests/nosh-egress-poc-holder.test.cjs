'use strict';

// Root-free supervision tests with mocked boundaries; these do not prove kernel enforcement.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawn, spawnSync } = require('node:child_process');
const test = require('node:test');

const source = fs.readFileSync(path.join(__dirname, '../scripts/nosh-egress-poc.sh'), 'utf8');
const prerequisites = spawnSync('/bin/bash', ['-c', 'command -v jq >/dev/null'], { encoding: 'utf8' });
const bashJqOptions = {
  skip: prerequisites.error || prerequisites.status !== 0
    ? 'requires Bash and jq; run the offline holder tests in the cached base image'
    : false,
};

function shellFunction(name) {
  const matches = [...source.matchAll(new RegExp(`^${name}\\(\\) \\{\\n[\\s\\S]*?^\\}`, 'gm'))];
  assert.equal(matches.length, 1, `expected one anchored ${name} definition`);
  return matches[0][0];
}

function fixture(t) {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'nosh-holder-test-'));
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  const phase = path.join(directory, 'allowA');
  fs.mkdirSync(phase);
  const status = {
    schemaVersion: 2, recordKind: 'status', status: 'ready', timestampUnixNs: '100',
    cgroupId: '123', mode: 'enforce', policyDigest: `sha256:${'a'.repeat(64)}`,
    attestation: { targetCgroupId: '123', policyGeneration: '1', linkIds: [1, 2, 3, 4, 5, 6] },
  };
  fs.writeFileSync(path.join(phase, 'status.json'), JSON.stringify(status));
  fs.writeFileSync(path.join(directory, 'loader-status.json'), JSON.stringify({ ...status, timestampUnixNs: '200' }));
  const decisions = ['a', 'b'].map((endpoint) => ({
    recordKind: 'decision', cgroupId: '123', policyGeneration: '1', hook: 1,
    family: 4, protocol: 6, destinationPort: 8080, enforcementApplied: true,
    destinationAddress: endpoint === 'a' ? '172.30.1.2' : '172.30.1.3',
    verdict: endpoint === 'a' ? 'allow' : 'deny',
    decisionClass: endpoint === 'a' ? 'policy-allow' : 'policy-deny',
    reason: endpoint === 'a' ? 'static-policy' : 'default-deny',
  }));
  fs.writeFileSync(path.join(phase, 'events.jsonl'), decisions.map(JSON.stringify).join('\n') + '\n');
  for (const name of ['collector-status.jsonl', 'diagnostics.log', 'monitor.log']) {
    fs.writeFileSync(path.join(phase, name), '');
  }
  fs.writeFileSync(path.join(directory, 'probes.jsonl'), [
    { phase: 'allowA', endpoint: 'a', exitCode: 0, httpCode: '200', body: 'A' },
    { phase: 'allowA', endpoint: 'b', exitCode: 7, httpCode: '000', body: '' },
  ].map(JSON.stringify).join('\n') + '\n');
  const loader = path.join(directory, 'mock-loader');
  fs.writeFileSync(loader, '#!/bin/sh\n[ "$1" = status ] || exit 2\n[ "${POC_TEST_LOADER_FAIL:-false}" = false ] || exit 3\ncat "$POC_TEST_LOADER_STATUS"\n', { mode: 0o700 });
  const environment = {
    ...process.env,
    POC_STAGE: directory,
    POC_PHASE: 'allowA', POC_HOLD_PHASE: 'allowA', POC_GENERATION: '1',
    POC_CGROUP_ID: '123', POC_CLIENT: 'b'.repeat(64), POC_PIN_ROOT: '/mock/pins',
    POC_A: '172.30.1.2', POC_B: '172.30.1.3', POC_LOADER: loader,
    POC_HOLD_STARTED: 'false', POC_HOLD_STOP: 'false', POC_HOLD_STOP_REASON: '',
    POC_ALLOWED_URL: '', POC_DENIED_URL: '',
    POC_TEST_LOADER_STATUS: path.join(directory, 'loader-status.json'),
    POC_TEST_OPERATIONS: path.join(directory, 'operations'),
  };
  const setup = `set -euo pipefail
${shellFunction('poc_start_time')}
POC_COLLECTOR=$$
POC_COLLECTOR_START=$(poc_start_time "$POC_COLLECTOR")
poc_validate_client() { [[ \${POC_TEST_CLIENT_INVALID:-false} == false ]]; }
poc_docker() { printf 'docker:%s:%s\\n' "$1" "\${2:-}" >> "$POC_TEST_OPERATIONS"; }
poc_die() { printf 'stop:%s\\n' "$*" >> "$POC_TEST_OPERATIONS"; exit 1; }
poc_session_receipt() { printf 'receipt:%s\\n' "$1" >> "$POC_TEST_OPERATIONS"; }
sleep() { command sleep 0.02; }
`;
  const operations = () => fs.existsSync(environment.POC_TEST_OPERATIONS)
    ? fs.readFileSync(environment.POC_TEST_OPERATIONS, 'utf8').trim().split('\n') : [];
  return { directory, phase, status, environment, setup, operations };
}

function runScript(script, environment) {
  return spawnSync('/bin/bash', ['-c', script], { env: environment, encoding: 'utf8', timeout: 3000 });
}

function runWithSignals(script, environment, marker, signals) {
  return new Promise((resolve, reject) => {
    const child = spawn('/bin/bash', ['-c', script], { env: environment });
    let stdout = '';
    let stderr = '';
    let sent = false;
    const timer = setTimeout(() => {
      child.kill('SIGKILL');
      reject(new Error(`holder timed out: ${stdout}\n${stderr}`));
    }, 3000);
    child.stdout.on('data', (data) => {
      stdout += data;
      if (!sent && stdout.includes(marker)) {
        sent = true;
        for (const signal of signals) child.kill(signal);
      }
    });
    child.stderr.on('data', (data) => { stderr += data; });
    child.on('error', (error) => { clearTimeout(timer); reject(error); });
    child.on('close', (code, signal) => {
      clearTimeout(timer);
      resolve({ code, signal, stdout, stderr, sent });
    });
  });
}

test('holder monitor accepts timestamp changes and rejects identity or evidence drift', bashJqOptions, async (t) => {
  const cases = [
    ['timestamp only', () => {}, '', 0],
    ['changed attachment', (f) => {
      f.status.attestation.linkIds[0] = 99;
      fs.writeFileSync(f.environment.POC_TEST_LOADER_STATUS, JSON.stringify(f.status));
    }, '', 1],
    ['changed client', (f) => { f.environment.POC_TEST_CLIENT_INVALID = 'true'; }, '', 1],
    ['dead collector', () => {}, 'POC_COLLECTOR=2147483647\n', 1],
    ['reused collector PID', () => {}, 'POC_COLLECTOR_START=0\n', 1],
    ['loader status failure', (f) => { f.environment.POC_TEST_LOADER_FAIL = 'true'; }, '', 1],
    ['exact evidence limit', (f) => fs.truncateSync(path.join(f.phase, 'events.jsonl'), 64 * 1024 * 1024), '', 0],
    ['oversized evidence', (f) => fs.truncateSync(path.join(f.phase, 'events.jsonl'), 64 * 1024 * 1024 + 1), '', 1],
  ];
  for (const [name, arrange, before, expected] of cases) {
    await t.test(name, (t) => {
      const f = fixture(t);
      arrange(f);
      const result = runScript(`${f.setup}${shellFunction('poc_monitor_hold')}\n${before}
result=0
poc_monitor_hold || result=$?
printf 'reason:%s\\n' "$POC_HOLD_STOP_REASON"
exit "$result"
`, f.environment);
      assert.equal(result.status, expected, result.stderr);
      if (name === 'oversized evidence') assert.match(result.stdout, /reason:evidence-size-limit/);
    });
  }
});

function heldScript(f) {
  const monitor = shellFunction('poc_monitor_hold').replace(/^poc_monitor_hold\(\)/, 'poc_checked_monitor_hold()');
  return `${f.setup}${monitor}
poc_monitor_hold() {
  poc_checked_monitor_hold || return 1
  if [[ $POC_HOLD_STARTED == true ]]; then
    printf 'HELD_LOOP_READY\\n'
    [[ \${POC_TEST_MONITOR_FAIL:-false} == false ]] || return 1
  fi
}
${shellFunction('poc_hold')}
poc_hold
printf 'HOLD_RETURNED:%s\\n' "$POC_HOLD_STOP_REASON"
`;
}

test('holder returns cleanly to teardown on INT, TERM, and HUP', bashJqOptions, async (t) => {
  for (const signal of ['SIGINT', 'SIGTERM', 'SIGHUP']) {
    await t.test(signal, async (t) => {
      const f = fixture(t);
      const result = await runWithSignals(heldScript(f), f.environment, 'HELD_LOOP_READY', [signal]);
      assert.equal(result.sent, true);
      assert.equal(result.code, 0, result.stderr);
      assert.equal(result.signal, null);
      assert.match(result.stdout, new RegExp(`HOLD_RETURNED:${signal}`));
      assert.match(result.stdout, /ALLOW_URL=http:\/\/172\.30\.1\.2:8080\/manual\/a/);
      assert.match(result.stdout, /DENY_URL=http:\/\/172\.30\.1\.3:8080\/manual\/b/);
      assert.ok(result.stdout.includes(f.environment.POC_CLIENT));
      assert.equal(f.operations().some((entry) => entry.startsWith('stop:')), false);
    });
  }
});

test('holder pauses its client before stopping when supervision fails', bashJqOptions, (t) => {
  const f = fixture(t);
  f.environment.POC_TEST_MONITOR_FAIL = 'true';
  const result = runScript(heldScript(f), f.environment);
  assert.equal(result.status, 1, result.stderr);
  const operations = f.operations();
  assert.equal(operations[0], 'receipt:active');
  assert.equal(operations[1], `docker:pause:${f.environment.POC_CLIENT}`);
  assert.match(operations[2], /^stop:held client, collector, or policy changed/);
  assert.doesNotMatch(result.stdout, /HOLD_RETURNED/);
});

test('holder final cleanup ignores repeated termination signals until receipt and export finish', bashJqOptions, async (t) => {
  const f = fixture(t);
  Object.assign(f.environment, { POC_CLEANED: 'false', POC_HOLD_STARTED: 'true', POC_SUCCESS: 'HELD SESSION CLOSED' });
  const script = `${f.setup}
poc_cleanup() {
  printf 'cleanup:begin\\n' >> "$POC_TEST_OPERATIONS"
  printf 'CLEANUP_READY\\n'
  command sleep 0.15
  printf 'cleanup:end\\n' >> "$POC_TEST_OPERATIONS"
  POC_CLEANED=true
}
poc_cleanup_tools() { printf 'cleanup:tools\\n' >> "$POC_TEST_OPERATIONS"; }
poc_export() { printf 'export\\n' >> "$POC_TEST_OPERATIONS"; }
${shellFunction('poc_finish')}
true
poc_finish
`;
  const result = await runWithSignals(script, f.environment, 'CLEANUP_READY', ['SIGINT', 'SIGTERM', 'SIGHUP', 'SIGINT']);
  assert.equal(result.sent, true);
  assert.equal(result.code, 0, result.stderr);
  assert.equal(result.signal, null);
  assert.deepEqual(f.operations(), ['cleanup:begin', 'cleanup:end', 'cleanup:tools', 'receipt:closed', 'export']);
  assert.match(result.stdout, /HELD SESSION CLOSED/);
});
