'use strict';

const assert = require('node:assert/strict');
const { spawnSync } = require('node:child_process');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const test = require('node:test');

const repo = path.resolve(__dirname, '..');
const launcher = path.join(repo, 'scripts/nosh.sh');

test('ordinary Docker startup follows the workspace and explicit overrides', t => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'notty-app-start-'));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const workspace = path.join(root, 'workspace');
  fs.mkdirSync(workspace);
  const checkoutLink = path.join(root, 'checkout-link');
  fs.symlinkSync(repo, checkoutLink);
  const cases = [
    [workspace, [], true],
    [repo, [], false],
    [checkoutLink, [], false],
    [workspace, ['--no-start-app'], false],
    [repo, ['--start-app'], true],
    [repo, ['--workload', 'run'], true],
  ];
  for (const [cwd, args, started] of cases) {
    const result = spawnSync('bash', [launcher, '--dry-run', '--security-mode', 'legacy',
      '--agents', 'none', '--no-collab', ...args], {
      cwd, encoding: 'utf8', env: {
        PATH: process.env.PATH, HOME: root, XDG_CONFIG_HOME: path.join(root, '.config'),
        XDG_STATE_HOME: path.join(root, '.state'),
      },
    });
    assert.equal(result.status, 0, result.stdout + result.stderr);
    assert.equal(result.stdout.includes('exec npm run start:next:sse'), started, result.stdout);
    assert.equal(result.stdout.includes('app service not started'), !started, result.stdout);
  }
});

test('interactive checkout startup prompts and honors the answer', () => {
  // Run the actual resolver with a controlling terminal without launching
  // containers or requiring authentication state.
  const script = `
import os, pathlib, pty, re, select, signal, time
source = pathlib.Path(${JSON.stringify(launcher)}).read_text()
names = ['trim', 'normalize_bool_mode', 'resolve_start_app_mode']
functions = '\\n'.join(re.search(r'^' + name + r'\\(\\) \\{\\n.*?^\\}', source, re.M | re.S)[0] for name in names)
for answer, expected in [('y', 'true'), ('', 'false'), ('n', 'false')]:
    pid, master = pty.fork()
    if pid == 0:
        command = functions + '\\nresolve_start_app_mode\\nprintf "RESULT=%s\\\\n" "$START_APP"'
        env = dict(os.environ, START_APP='auto', WORKLOAD='dev', SECURITY_MODE='legacy',
                   NET_WORKFLOW='false', DRY_RUN='false', WORKDIR=${JSON.stringify(repo)},
                   REPO_ROOT=${JSON.stringify(repo)})
        os.execve('/bin/bash', ['bash', '-euc', command], env)
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
            if b'Start bundled /app service? [y/N]' in output and not replied:
                os.write(master, (answer + '\\n').encode())
                replied = True
        assert replied, output
        assert ('RESULT=' + expected).encode() in output, output
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
