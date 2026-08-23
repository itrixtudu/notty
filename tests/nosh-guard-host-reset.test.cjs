'use strict';

const assert = require('node:assert/strict');
const childProcess = require('node:child_process');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const test = require('node:test');

const repository = path.resolve(__dirname, '..');
const resetPath = path.join(repository, 'reset-nosh-guard.sh');

function run(command, args, options = {}) {
  return childProcess.spawnSync(command, args, {
    cwd: repository,
    encoding: 'utf8',
    ...options,
  });
}

test('host Guard reset is a safe in-place refresh wrapper', () => {
  const source = fs.readFileSync(resetPath, 'utf8');
  const mode = fs.statSync(resetPath).mode & 0o7777;

  assert.notEqual(mode & 0o100, 0, 'reset wrapper must be owner-executable');
  assert.equal(mode & 0o022, 0, 'reset wrapper must not be group/world-writable');
  assert.equal(run('/bin/bash', ['-n', resetPath]).status, 0);
  assert.match(source, /^set -euo pipefail$/m);
  assert.match(source, /^umask 077$/m);
  assert.match(source, /build-nosh-guard-host-bundle\.sh/);
  assert.match(source, /sha256sum --check --strict/);
  assert.match(source, /sudo -- "\$installer" install/);
  assert.match(source, /--enable-now/);
  assert.match(source, /--deep-verify/);
  assert.doesNotMatch(source, /--use-existing-loaders/);
  assert.doesNotMatch(source, /--purge-(?:config|state)/);
  assert.doesNotMatch(source, /"\$installer" uninstall/);
  assert.ok(
    source.indexOf('build-nosh-guard-host-bundle.sh')
      < source.indexOf('sudo -- "$installer" install'),
  );

  const help = run(resetPath, ['--help']);
  assert.equal(help.status, 0, help.stderr);
  assert.match(help.stdout, /purge configuration/i);
  assert.match(help.stdout, /Guard evidence/i);
  assert.match(help.stdout, /validated installed layout receipt/);
  assert.match(help.stdout, /fails closed/i);
  assert.match(help.stdout, /bundle-authoritative/i);
  assert.match(help.stdout, /operator-managed network contract/i);
  assert.match(help.stdout, /installs the reviewed first-party eBPF loaders/i);
  assert.match(help.stdout, /do not use a separate managed\s+dnsmasq\/nftables gateway/i);
  assert.match(help.stdout, /legacy full-profile gateway artifact[\s\S]*preserved/i);
  assert.doesNotMatch(source, /\bdocker\s+(?:build|pull|stop|rm|remove|create|run)\b/);

  const unknown = run(resetPath, ['--unknown-reset-option']);
  assert.equal(unknown.status, 2);
  assert.match(unknown.stderr, /unknown option/);

  const broad = run(resetPath, ['--prefix', '/']);
  assert.equal(broad.status, 1);
  assert.match(broad.stderr, /absolute path other than/);
  assert.doesNotMatch(broad.stderr, /Building digest-pinned/);
});

test('host Guard reset verifies a fresh bundle before the only sudo step', (t) => {
  const fixture = fs.mkdtempSync(path.join(os.tmpdir(), 'nosh-guard-reset-'));
  const scripts = path.join(fixture, 'scripts');
  const fakeBin = path.join(fixture, 'bin');
  const installArgs = path.join(fixture, 'install-args.txt');
  const builderOutput = path.join(fixture, 'builder-output.txt');
  const sudoLog = path.join(fixture, 'sudo.log');
  const receiptPath = path.join(fixture, 'layout-receipt.conf');
  const fixtureResetPath = path.join(fixture, 'reset-nosh-guard.sh');
  fs.mkdirSync(scripts, { mode: 0o700 });
  fs.mkdirSync(fakeBin, { mode: 0o700 });
  const resetSource = fs.readFileSync(resetPath, 'utf8');
  const fixtureResetSource = resetSource.replace(
    'RECEIPT_PATH="/etc/nosh-guard-install-layout.conf"',
    `RECEIPT_PATH=${JSON.stringify(receiptPath)}`,
  );
  assert.notEqual(fixtureResetSource, resetSource);
  fs.writeFileSync(fixtureResetPath, fixtureResetSource, { mode: 0o755 });
  t.after(() => fs.rmSync(fixture, { recursive: true, force: true }));

  const fakeBuilder = `#!/usr/bin/env bash
set -euo pipefail
[[ "$#" == 2 && "$1" == --output-dir ]]
output_dir="$2"
printf '%s\n' "$output_dir" >"\${RESET_BUILDER_OUTPUT_FILE:?}"
if [[ "\${RESET_FAKE_MODE:-success}" == builder-failure ]]; then
  exit 42
fi
source_dir="$(mktemp -d)"
trap 'rm -rf -- "$source_dir"' EXIT
mkdir -p "$source_dir/notty-nosh-guard-test"
cat >"$source_dir/notty-nosh-guard-test/install.sh" <<'INSTALLER'
#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "$@" >"\${RESET_INSTALL_ARGS_FILE:?}"
INSTALLER
chmod 0755 "$source_dir/notty-nosh-guard-test/install.sh"
archive="$output_dir/notty-nosh-guard-test.tar.gz"
tar -czf "$archive" -C "$source_dir" notty-nosh-guard-test
chmod 0644 "$archive"
(
  cd "$output_dir"
  if [[ "\${RESET_FAKE_MODE:-success}" == wrong-checksum-target ]]; then
    printf 'not the selected archive\n' > unrelated.txt
    sha256sum unrelated.txt >"$(basename "$archive").sha256"
  else
    sha256sum "$(basename "$archive")" >"$(basename "$archive").sha256"
  fi
)
chmod 0644 "$archive.sha256"
`;
  fs.writeFileSync(
    path.join(scripts, 'build-nosh-guard-host-bundle.sh'),
    fakeBuilder,
    { mode: 0o755 },
  );
  fs.writeFileSync(
    path.join(fakeBin, 'sudo'),
    `#!/usr/bin/env bash
set -euo pipefail
[[ "\${1:-}" == -- ]]
shift
printf '%s\n' "$*" >>"\${RESET_SUDO_LOG_FILE:?}"
exec "$@"
`,
    { mode: 0o755 },
  );
  fs.writeFileSync(
    path.join(fakeBin, 'stat'),
    `#!/usr/bin/env bash
set -euo pipefail
if [[ "\${@: -1}" == ${JSON.stringify(receiptPath)} ]]; then
  printf '0 644 1\n'
  exit 0
fi
exec /usr/bin/stat "$@"
`,
    { mode: 0o755 },
  );

  const runReset = (mode, args = []) => {
    for (const output of [builderOutput, installArgs, sudoLog]) {
      fs.rmSync(output, { force: true });
    }
    return run(fixtureResetPath, args, {
      cwd: fixture,
      env: {
        ...process.env,
        PATH: `${fakeBin}:${process.env.PATH}`,
        NOSH_GUARD_PREFIX: '',
        RESET_BUILDER_OUTPUT_FILE: builderOutput,
        RESET_FAKE_MODE: mode,
        RESET_INSTALL_ARGS_FILE: installArgs,
        RESET_SUDO_LOG_FILE: sudoLog,
      },
    });
  };

  const noSelection = runReset('success', []);
  assert.equal(noSelection.status, 1);
  assert.match(noSelection.stderr, /no installed Guard prefix/);
  assert.equal(fs.existsSync(builderOutput), false);
  assert.equal(fs.existsSync(sudoLog), false);

  fs.writeFileSync(
    receiptPath,
    [
      'SCHEMA_VERSION=1',
      'NOSH_GUARD_PREFIX=/opt/notty',
      `MANIFEST_SHA256=${'a'.repeat(64)}`,
      '',
    ].join('\n'),
    { mode: 0o644 },
  );
  const mismatchedPrefix = runReset('success', ['--prefix', '/usr/local']);
  assert.equal(mismatchedPrefix.status, 1);
  assert.match(mismatchedPrefix.stderr, /does not match installed prefix/);
  assert.equal(fs.existsSync(builderOutput), false);
  assert.equal(fs.existsSync(sudoLog), false);

  const result = runReset('success');
  assert.equal(result.status, 0, result.stderr);
  assert.deepEqual(
    fs.readFileSync(installArgs, 'utf8').trim().split('\n'),
    ['install', '--prefix', '/opt/notty', '--enable-now', '--deep-verify'],
  );
  const sudoCalls = fs.readFileSync(sudoLog, 'utf8').trim().split('\n');
  assert.equal(sudoCalls.length, 1);
  assert.match(
    sudoCalls[0],
    /install\.sh install --prefix \/opt\/notty --enable-now --deep-verify$/,
  );
  assert.match(result.stdout, /configuration and evidence were preserved/);
  assert.match(
    result.stdout,
    /installed host bundle includes the first-party eBPF enforcement backend/,
  );
  assert.match(result.stdout, /scoped egress uses no separate gateway image/);
  let temporaryOutput = fs.readFileSync(builderOutput, 'utf8').trim();
  assert.equal(fs.existsSync(path.dirname(temporaryOutput)), false);

  const replacement = runReset('success', ['--replace-config']);
  assert.equal(replacement.status, 0, replacement.stderr);
  assert.match(
    replacement.stderr,
    /bundle-authoritative configuration replacement enabled/,
  );
  assert.deepEqual(
    fs.readFileSync(installArgs, 'utf8').trim().split('\n'),
    [
      'install',
      '--prefix',
      '/opt/notty',
      '--replace-config',
      '--enable-now',
      '--deep-verify',
    ],
  );
  const replacementSudoCalls = fs.readFileSync(sudoLog, 'utf8')
    .trim()
    .split('\n');
  assert.equal(replacementSudoCalls.length, 1);
  assert.match(
    replacementSudoCalls[0],
    /install\.sh install --prefix \/opt\/notty --replace-config --enable-now --deep-verify$/,
  );
  assert.match(
    replacement.stdout,
    /adapter\/version configuration was replaced/,
  );
  assert.match(
    replacement.stdout,
    /operator network contract, state, and evidence were preserved/,
  );
  assert.match(
    replacement.stdout,
    /installed host bundle includes the first-party eBPF enforcement backend/,
  );
  assert.match(replacement.stdout, /scoped egress uses no separate gateway image/);
  temporaryOutput = fs.readFileSync(builderOutput, 'utf8').trim();
  assert.equal(fs.existsSync(path.dirname(temporaryOutput)), false);

  const wrongTarget = runReset('wrong-checksum-target');
  assert.equal(wrongTarget.status, 1);
  assert.match(wrongTarget.stderr, /checksum record does not name/);
  assert.equal(fs.existsSync(installArgs), false);
  assert.equal(fs.existsSync(sudoLog), false);
  temporaryOutput = fs.readFileSync(builderOutput, 'utf8').trim();
  assert.equal(fs.existsSync(path.dirname(temporaryOutput)), false);

  const builderFailure = runReset('builder-failure');
  assert.notEqual(builderFailure.status, 0);
  assert.equal(fs.existsSync(installArgs), false);
  assert.equal(fs.existsSync(sudoLog), false);
  temporaryOutput = fs.readFileSync(builderOutput, 'utf8').trim();
  assert.equal(fs.existsSync(path.dirname(temporaryOutput)), false);
});
