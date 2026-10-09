'use strict';

const assert = require('node:assert/strict');
const { spawnSync } = require('node:child_process');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const test = require('node:test');

const guestSource = fs.readFileSync(path.join(__dirname, '../scripts/qemu/guest.sh'), 'utf8');
const cleanupFunction = guestSource.match(/^cleanup_guest\(\) \{[\s\S]*?^\}/m)?.[0];
assert.ok(cleanupFunction, 'guest cleanup function must be available');

function cleanupFixture(t, behavior) {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'notty-qemu-cleanup-'));
  const configDirectory = path.join(directory, 'etc/nosh-guard');
  fs.mkdirSync(configDirectory, { recursive: true });
  if (behavior !== 'missing-before') {
    fs.writeFileSync(path.join(configDirectory, 'adapters.json'), '{}\n', { mode: 0o640 });
  }
  t.after(() => {
    fs.chmodSync(configDirectory, 0o700);
    fs.rmSync(directory, { recursive: true, force: true });
  });

  // The assertion must run without permission to search the config directory,
  // including when the container's test runner itself happens to be root.
  const identity = process.getuid() === 0 ? { uid: 65534, gid: 65534 } : {};
  if (identity.uid !== undefined) {
    const changeOwner = (filename) => {
      if (fs.statSync(filename).isDirectory()) {
        for (const name of fs.readdirSync(filename)) changeOwner(path.join(filename, name));
      }
      fs.chownSync(filename, identity.uid, identity.gid);
    };
    changeOwner(directory);
  }
  fs.chmodSync(configDirectory, 0o000);

  let cleanup = cleanupFunction;
  for (const systemPath of [
    '/etc/nosh-guard', '/var/lib/nosh-guard', '/usr/local/bin/nosh-guard',
    '/run/nosh-guardd.sock', '/sys/fs/bpf/nosh-guard',
  ]) {
    cleanup = cleanup.replaceAll(systemPath, `${directory}${systemPath}`);
  }

  const script = String.raw`
set -Eeuo pipefail
REV=fixture-revision
CONFIG="$FIXTURE_ROOT/etc/nosh-guard"
STATE="$FIXTURE_ROOT/var/lib/nosh-guard"
[[ ! -f "$CONFIG/adapters.json" ]] || { echo 'fixture has unexpected directory access' >&2; exit 90; }
fail() { printf 'FAILED: %s\n' "$*" >&2; exit 1; }
record() { printf 'record %s %s\n' "$1" "$2"; }
docker() {
  case "$*" in
    'ps -aq --filter label=io.notty.guard.managed=true'|'network ls -q --filter label=io.notty.guard.managed=true') ;;
    *) fail 'unexpected fixture Docker command' ;;
  esac
}
sudo() {
  [[ $1 == -n ]] || fail 'fixture requires noninteractive sudo'
  shift
  local argument result
  for argument in "$@"; do
    [[ $argument != /* || $argument == "$FIXTURE_ROOT/"* ]] || fail 'fixture command escaped temporary directory'
  done
  case "$1" in
    systemctl)
      [[ $* == 'systemctl is-active --quiet nosh-guardd.service' ]] || fail 'unexpected fixture service command'
      return 3 ;;
    python3)
      # The BPF check is unrelated to the config permission regression.
      cat >/dev/null
      return 0 ;;
    test|cat|tee|install) ;;
    *) fail 'unexpected fixture sudo command' ;;
  esac
  # Simulate privileged traversal only while the requested probe runs.
  chmod 0700 "$CONFIG"
  if command "$@"; then result=0; else result=$?; fi
  chmod 0000 "$CONFIG"
  return "$result"
}
installer() {
  chmod 0700 "$CONFIG"
  case "$*" in
    uninstall)
      if [[ $FIXTURE_BEHAVIOR == remove-preserved ]]; then rm "$CONFIG/adapters.json"; fi ;;
    'install --enable-now --deep-verify')
      printf '{}\n' >"$CONFIG/adapters.json" ;;
    'uninstall --purge-config --purge-state')
      if [[ $FIXTURE_BEHAVIOR != leave-purged ]]; then rm "$CONFIG/adapters.json"; fi
      rm -rf -- "$STATE" ;;
    *) fail 'unexpected fixture installer command' ;;
  esac
  chmod 0000 "$CONFIG"
}
`;
  const result = spawnSync('bash', ['-s'], {
    ...identity,
    cwd: directory,
    input: `${script}\n${cleanup}\ncleanup_guest\n`,
    encoding: 'utf8',
    env: { ...process.env, FIXTURE_ROOT: directory, FIXTURE_BEHAVIOR: behavior },
    timeout: 5000,
  });
  assert.equal(result.error, undefined, result.error?.message);
  return result;
}

test('QEMU cleanup accepts preserved and purged config behind a protected directory', (t) => {
  const result = cleanupFixture(t, 'normal');
  assert.equal(result.status, 0, result.stdout + result.stderr);
  assert.match(result.stdout, /record uninstall-preserves-state passed/);
  assert.match(result.stdout, /record explicit-purge passed/);
});

test('QEMU cleanup rejects config removed by ordinary uninstall', (t) => {
  const result = cleanupFixture(t, 'remove-preserved');
  assert.equal(result.status, 1, result.stdout + result.stderr);
  assert.match(result.stderr, /uninstall removed preserved configuration/);
  assert.doesNotMatch(result.stdout, /uninstall-preserves-state passed/);
});

test('QEMU cleanup detects config left behind by explicit purge', (t) => {
  const result = cleanupFixture(t, 'leave-purged');
  assert.equal(result.status, 1, result.stdout + result.stderr);
  assert.match(result.stderr, /explicit purge left installed configuration/);
  assert.match(result.stdout, /record uninstall-preserves-state passed/);
  assert.doesNotMatch(result.stdout, /explicit-purge passed/);
});

test('QEMU cleanup requires installed config before checking preservation', (t) => {
  const result = cleanupFixture(t, 'missing-before');
  assert.equal(result.status, 1, result.stdout + result.stderr);
  assert.match(result.stderr, /cleanup requires installed configuration/);
  assert.doesNotMatch(result.stdout, /uninstall-preserves-state passed/);
});
