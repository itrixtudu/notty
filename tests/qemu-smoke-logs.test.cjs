'use strict';

const assert = require('node:assert/strict');
const { spawnSync } = require('node:child_process');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const test = require('node:test');

const guest = fs.readFileSync(path.join(__dirname, '../scripts/qemu/guest.sh'), 'utf8');
const finish = guest.slice(guest.indexOf('finish() {'), guest.indexOf('\ntrap finish EXIT'));
const containerId = 'a'.repeat(64);

function runFinish(t, { status = 23, logStatus = 0, removeStatus = 0, receipt = false } = {}) {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'notty-qemu-smoke-logs-'));
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  const state = path.join(directory, 'state');
  const output = path.join(directory, 'output');
  fs.mkdirSync(state);
  fs.mkdirSync(output);
  fs.writeFileSync(path.join(state, 'smoke.cid'), containerId + '\n');
  const script = `set -Eeuo pipefail
LEARN_PID=''
FIXTURE_PID=''
INTERFACE_OWNED=false
RUN_IDS=()
ACTION=smoke
docker() {
  printf '%s\\n' "$*" >>"$EVENT_LOG"
  case "$1" in
    logs) printf 'captured service startup\\n'; return "$LOG_STATUS" ;;
    rm) return "$REMOVE_STATUS" ;;
    *) return 99 ;;
  esac
}
sudo() { return 0; }
record() { printf '%s\\n' "$*" >>"$EVENT_LOG"; }
${finish}
trap finish EXIT
exit "$TEST_STATUS"
`;
  const eventLog = path.join(directory, 'events.log');
  const result = spawnSync('bash', ['-c', script], {
    encoding: 'utf8',
    timeout: 5000,
    env: {
      ...process.env,
      STATE: state,
      OUT: output,
      EVENT_LOG: eventLog,
      SMOKE_ID: receipt ? '' : containerId,
      TEST_STATUS: String(status),
      LOG_STATUS: String(logStatus),
      REMOVE_STATUS: String(removeStatus),
    },
  });
  assert.equal(result.error, undefined, result.error?.message);
  return { result, output, state, events: fs.readFileSync(eventLog, 'utf8').trim().split('\n') };
}

test('smoke failure captures server logs before removing the container and preserves status', (t) => {
  for (const receipt of [false, true]) {
    const { result, output, state, events } = runFinish(t, { receipt });
    assert.equal(result.status, 23, result.stdout + result.stderr);
    assert.equal(fs.readFileSync(path.join(output, 'server.log'), 'utf8'), 'captured service startup\n');
    assert.deepEqual(events, [`logs ${containerId}`, `rm -f ${containerId}`, 'smoke failed exit 23']);
    assert.equal(fs.existsSync(path.join(state, 'smoke.cid')), false);
  }
});

test('failed log collection still removes the container without masking the smoke result', (t) => {
  for (const status of [0, 23, 130]) {
    const { result, events } = runFinish(t, { status, logStatus: 1 });
    assert.equal(result.status, status, result.stdout + result.stderr);
    assert.deepEqual(events.slice(0, 2), [`logs ${containerId}`, `rm -f ${containerId}`]);
  }
});

test('container removal failure fails a successful run and preserves an existing failure', (t) => {
  for (const status of [0, 2, 23, 143]) {
    const { result, events } = runFinish(t, { status, removeStatus: 1 });
    assert.equal(result.status, status || 1, result.stdout + result.stderr);
    assert.deepEqual(events.slice(0, 2), [`logs ${containerId}`, `rm -f ${containerId}`]);
  }
});
