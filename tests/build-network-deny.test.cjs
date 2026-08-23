'use strict';

const assert = require('node:assert/strict');
const childProcess = require('node:child_process');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const test = require('node:test');

function dockerAvailable() {
  const result = childProcess.spawnSync('docker', ['info', '--format', '{{.ServerVersion}}'], {
    encoding: 'utf8',
    stdio: ['ignore', 'pipe', 'ignore'],
    timeout: 5_000,
  });
  return result.status === 0;
}

test('a build step cannot reach example.org or a direct public IP', (t) => {
  if (!dockerAvailable()) {
    t.skip('Docker daemon is unavailable');
    return;
  }

  const image = 'busybox:1.36';
  const imageCheck = childProcess.spawnSync('docker', ['image', 'inspect', image], {
    encoding: 'utf8',
    stdio: 'ignore',
    timeout: 5_000,
  });
  if (imageCheck.status !== 0) {
    t.skip(`local fixture image ${image} is unavailable (the test never pulls images)`);
    return;
  }

  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'nosh-build-network-deny-'));
  const tag = `nosh-build-network-deny:${process.pid}-${Date.now()}`;
  t.after(() => {
    fs.rmSync(directory, { recursive: true, force: true });
    childProcess.spawnSync('docker', ['image', 'rm', '--force', tag], {
      stdio: 'ignore',
      timeout: 5_000,
    });
  });

  fs.writeFileSync(path.join(directory, 'Dockerfile'), [
    `FROM ${image}`,
    'RUN set -eu; \\',
    '    if wget -T 2 -q -O /dev/null http://example.org/; then \\',
    '      echo "UNEXPECTED_ESCAPE example.org" >&2; exit 41; \\',
    '    fi; \\',
    '    echo "BLOCKED example.org"; \\',
    '    if wget -T 2 -q -O /dev/null http://1.1.1.1/; then \\',
    '      echo "UNEXPECTED_ESCAPE 1.1.1.1" >&2; exit 42; \\',
    '    fi; \\',
    '    echo "BLOCKED 1.1.1.1"',
    '',
  ].join('\n'));

  const result = childProcess.spawnSync('docker', [
    'build', '--pull=false', '--no-cache', '--progress=plain', '--network=none',
    '--tag', tag, directory,
  ], { encoding: 'utf8', timeout: 30_000 });
  assert.equal(result.status, 0, `${result.stdout}\n${result.stderr}`);
  const output = `${result.stdout}\n${result.stderr}`;
  assert.match(output, /BLOCKED example\.org/);
  assert.match(output, /BLOCKED 1\.1\.1\.1/);
  assert.doesNotMatch(output, /UNEXPECTED_ESCAPE/);
});
