'use strict';

const assert = require('node:assert/strict');
const { spawnSync } = require('node:child_process');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const test = require('node:test');

const source = fs.readFileSync(path.join(__dirname, '../scripts/nosh.sh'), 'utf8');
const helper = source.match(/^ensure_local_image\(\) \{\n.*?^\}/ms)[0];

function fixture(t) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'nosh-image-build-'));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const workspace = path.join(root, 'workspace');
  const checkout = path.join(root, 'checkout');
  fs.mkdirSync(workspace);
  fs.mkdirSync(checkout);
  return {
    workspace, checkout,
    run(image, options = {}) {
      // Exercise the launcher's actual helper with a stateful Docker stand-in.
      const mock = `
docker() {
  if [[ "$1 $2" == 'image inspect' ]]; then
    if [[ "$3" == --format ]]; then printf '%s\\n' baseowner; return; fi
    [[ ",${options.images || ''}," == *",$3,"* || ",$built," == *",$3,"* ]]
    return
  fi
  printf '%s\\n' "$*"
  [[ "$build_status" == 0 ]] || return "$build_status"
  local previous='' value
  for value in "$@"; do
    if [[ "$previous" == --tag ]]; then built="$built,$value"; fi
    previous="$value"
  done
}
docker_cmd() {
  if [[ "$DRY_RUN" == true ]]; then printf 'PREVIEW %s\\n' "$*"; else docker "$@"; fi
}
built=''
${helper}
ensure_local_image "$SELECTED_IMAGE"
`;
      return spawnSync('bash', ['-euc', mock], {
        encoding: 'utf8',
        env: { ...process.env, WORKDIR: workspace, REPO_ROOT: checkout,
          USERNAME: 'builder', USER_UID: '1234', USER_GID: '1234',
          SELECTED_IMAGE: image, DRY_RUN: String(options.dryRun || false),
          build_status: String(options.buildStatus || 0) },
      });
    },
  };
}

test('missing tagged image builds the project Dockerfile before the checkout copy', t => {
  const f = fixture(t);
  for (const dir of [f.workspace, f.checkout]) {
    fs.writeFileSync(path.join(dir, 'Dockerfile.nosh-custom'), 'FROM debian:bookworm\n');
  }
  const result = f.run('nosh-custom:dev');
  assert.equal(result.status, 0, result.stderr);
  assert.match(result.stdout, /--tag nosh-custom:dev/);
  assert.ok(result.stdout.includes(`${f.workspace}/Dockerfile.nosh-custom`));
  assert.ok(!result.stdout.includes(f.checkout));
});

test('existing images, absent Dockerfiles and registry references skip building', t => {
  const f = fixture(t);
  fs.writeFileSync(path.join(f.workspace, 'Dockerfile.nosh-custom'), 'FROM debian:bookworm\n');
  for (const [image, options] of [
    ['nosh-custom', { images: 'nosh-custom' }], ['missing', {}],
    ['registry.example/nosh-custom:dev', {}], ['nosh-custom@sha256:abc', {}],
  ]) {
    const result = f.run(image, options);
    assert.equal(result.status, 0, result.stderr);
    assert.equal(result.stdout, '');
  }
});

test('derived image builds the checkout base first and uses its container user', t => {
  const f = fixture(t);
  fs.writeFileSync(path.join(f.checkout, 'Dockerfile.nosh'), 'FROM debian:bookworm AS local\n');
  fs.writeFileSync(path.join(f.checkout, 'Dockerfile.nosh-zig'),
    'ARG NOSH_IMAGE=nosh:latest\nFROM ${NOSH_IMAGE}\n');
  const result = f.run('nosh-zig');
  assert.equal(result.status, 0, result.stderr);
  const builds = result.stdout.trim().split('\n');
  assert.equal(builds.length, 2);
  assert.match(builds[0], /--tag nosh .*--target local/);
  assert.match(builds[1], /--tag nosh-zig .*USERNAME=baseowner/);
});

test('base build failure prevents the derived build', t => {
  const f = fixture(t);
  fs.writeFileSync(path.join(f.checkout, 'Dockerfile.nosh'), 'FROM debian:bookworm\n');
  fs.writeFileSync(path.join(f.checkout, 'Dockerfile.nosh-zig'), 'FROM nosh\n');
  const result = f.run('nosh-zig', { buildStatus: 19 });
  assert.equal(result.status, 19);
  assert.equal(result.stdout.trim().split('\n').length, 1);
  assert.ok(!result.stdout.includes('--tag nosh-zig'));
});

test('dry run previews the build without executing it', t => {
  const f = fixture(t);
  fs.writeFileSync(path.join(f.workspace, 'Dockerfile.nosh-custom'), 'FROM debian:bookworm\n');
  const result = f.run('nosh-custom', { dryRun: true, buildStatus: 19 });
  assert.equal(result.status, 0, result.stderr);
  assert.match(result.stdout, /^PREVIEW build /);
});

test('interactive existing images offer reuse or rebuild, with reuse as the default', t => {
  const f = fixture(t);
  fs.writeFileSync(path.join(f.workspace, 'Dockerfile.nosh-custom'), 'FROM debian:bookworm\n');
  const shell = `
docker() { return 0; }
docker_cmd() { printf 'BUILD_REQUESTED\\n'; }
${helper}
ensure_local_image nosh-custom
ensure_local_image nosh-custom
`;
  const script = `
import os, pty, select, signal, time
for answer, should_build in [('', False), ('u', False), ('r', True)]:
    pid, master = pty.fork()
    if pid == 0:
        env = dict(os.environ, WORKDIR=${JSON.stringify(f.workspace)},
                   REPO_ROOT=${JSON.stringify(f.checkout)}, DRY_RUN='false',
                   USERNAME='builder', USER_UID='1234', USER_GID='1234')
        os.execve('/bin/bash', ['bash', '-euc', ${JSON.stringify(shell)}], env)
    output = b''
    replied = False
    try:
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            if not select.select([master], [], [], .1)[0]:
                continue
            try:
                data = os.read(master, 65536)
            except OSError:
                break
            if not data:
                break
            output += data
            if b'or rebuild [r]?' in output and not replied:
                os.write(master, (answer + '\\n').encode())
                replied = True
        assert replied, output
        assert output.count(b'or rebuild [r]?') == 1, output
        assert output.count(b'BUILD_REQUESTED') == int(should_build), output
    finally:
        os.close(master)
        try:
            os.kill(pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        os.waitpid(pid, 0)
`;
  const result = spawnSync('python3', ['-I', '-S', '-c', script], {
    encoding: 'utf8', timeout: 20000,
  });
  assert.equal(result.status, 0, result.stdout + result.stderr);
});
