const assert = require('node:assert/strict');
const childProcess = require('node:child_process');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const test = require('node:test');

const root = path.resolve(__dirname, '..');
const hostScript = path.join(root, 'release-audit.sh');
const containerScript = path.join(root, 'scripts', 'release-audit-container.sh');
const ciHostScript = path.join(root, 'scripts', 'ci-release-audit.sh');
const pretagChecker = path.join(root, 'scripts', 'check-pretag-audit-report.py');
const auditDockerfile = path.join(root, 'Dockerfile.release-audit');
const auditWorkflow = path.join(root, '.github', 'workflows', 'release-audit.yml');

function run(command, args, options = {}) {
  return childProcess.spawnSync(command, args, {
    cwd: root,
    encoding: 'utf8',
    ...options,
  });
}

function escapeRegExp(value) {
  return value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

function waitForPath(filePath, timeoutMs = 10000) {
  return new Promise((resolve, reject) => {
    const startedAt = Date.now();
    const poll = () => {
      if (fs.existsSync(filePath)) {
        resolve();
      } else if (Date.now() - startedAt >= timeoutMs) {
        reject(new Error(`timed out waiting for ${filePath}`));
      } else {
        setTimeout(poll, 10);
      }
    };
    poll();
  });
}

function waitForChildClose(child, timeoutMs = 10000) {
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => {
      reject(new Error(`timed out waiting for child ${child.pid}`));
    }, timeoutMs);
    child.once('error', (error) => {
      clearTimeout(timer);
      reject(error);
    });
    child.once('close', (code, signal) => {
      clearTimeout(timer);
      resolve({ code, signal });
    });
  });
}

test('release audit shell entrypoints are executable and syntactically valid', () => {
  for (const script of [hostScript, containerScript, ciHostScript]) {
    assert.notEqual(fs.statSync(script).mode & 0o111, 0, `${script} must be executable`);
    const result = run('bash', ['-n', script]);
    assert.equal(result.status, 0, result.stderr);
  }
});

test('production advisory success is qualified as zero known vulnerabilities', () => {
  const source = fs.readFileSync(containerScript, 'utf8');

  assert.match(source, /npm audit reports zero known production vulnerabilities/);
  assert.doesNotMatch(source, /npm audit reports zero production vulnerabilities/);
});

test('release audit packages and compiles the optional URL evidence collector', () => {
  const source = fs.readFileSync(containerScript, 'utf8');

  for (const required of [
    'bpf/nosh_url/Makefile',
    'bpf/nosh_url/nosh_url.bpf.c',
    'bpf/nosh_url/loader/nosh_url_loader.c',
    'bpf/nosh_url/loader/url_sanitizer.c',
    'bpf/nosh_url/tests/include/bpf/libbpf.h',
    'bpf/nosh_url/tests/loader_stubs.c',
    'bpf/nosh_url/tests/static.sh',
  ]) {
    assert.match(source, new RegExp(escapeRegExp(required)));
  }
  assert.match(
    source,
    /Optional URL eBPF collector static contract \(offline\)/,
  );
  assert.match(
    source,
    /Optional URL eBPF collector CO-RE compile \(offline\)/,
  );
  assert.match(source, /compile_collector_loader bpf\/nosh_url/);
});

test('CI uses host Git checkout and runs package work only in the Docker audit', () => {
  const workflow = fs.readFileSync(auditWorkflow, 'utf8');
  const ciSource = fs.readFileSync(ciHostScript, 'utf8');

  assert.doesNotMatch(workflow, /^\s*uses:/m);
  assert.match(workflow, /git fetch --force --prune --tags origin "\$CHECKOUT_REF"/);
  assert.match(workflow, /GIT_CONFIG_VALUE_0="AUTHORIZATION: basic \$checkout_auth"/);
  assert.match(workflow, /git config --local --get-all/);
  assert.match(workflow, /unset CHECKOUT_TOKEN checkout_auth/);
  assert.match(workflow, /permissions:\s*\n\s+contents: read/);
  assert.match(workflow, /git rev-list --parents -n 1 HEAD/);
  assert.match(workflow, /run: \.\/release-audit\.sh/);
  assert.match(workflow, /run: \.\/scripts\/ci-release-audit\.sh/);
  assert.doesNotMatch(workflow, /pull_request_target|actions\/setup-node/);
  assert.doesNotMatch(workflow, /^\s*run:\s*(?:npm|npx|node)\b/m);
  assert.doesNotMatch(workflow, /^\s+(?:npm|npx|node)(?:\s|$)/m);
  assert.match(ciSource, /readonly -f npm npx node/);
  assert.match(ciSource, /\.release-audit\/ci-\$\{GITHUB_RUN_ID:-local\}/);
  assert.match(ciSource, /refusing pre-existing report path/);
  assert.match(ciSource, /did not publish a fresh regular report/);
  assert.doesNotMatch(ciSource, /^\s*(?:command\s+)?(?:npm|npx|node)\b/m);
});

test('pre-tag CI accepts only a sole missing release-tag gate', (t) => {
  const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'notty-pretag-report-'));
  t.after(() => fs.rmSync(tempRoot, { recursive: true, force: true }));
  const reportPath = path.join(tempRoot, 'audit.md');
  const gateLabels = [
    'Required host tools',
    'Docker daemon availability',
    'Git whitespace checks',
    'Clean Git worktree',
    'RELEASE.md version and exact release tag',
    'Digest-pinned audit image',
    'Ephemeral audit volume and network',
    'Captured-commit source archive and SHA-256',
    'Networked phases bound to captured manifests',
    'Manifest-only dependency acquisition',
    'Production dependency advisory audit',
    'Offline metadata, release files, rebuild, tests, build, and package verification',
    'Offline full-checkout package leak inventory',
    'Repository and audit inputs stable for the run',
    'Ephemeral audit object cleanup',
  ];
  const gateRows = gateLabels.map((label) => {
    const passed = label !== 'RELEASE.md version and exact release tag';
    return `- [${passed ? 'x' : ' '}] \`${passed ? 'PASS' : 'FAIL'}\` - ${label}`;
  }).join('\n');
  const goodReport = `# Notty Release Audit Report

> Outcome: **FAIL** (exit status \`1\`)

## Run identity

- Release candidate at captured commit: \` 1.0.0 \`
- Package version at captured commit: \` 1.0.0 \`

## Repository worktree

Clean, including untracked files.

## Automated gates

${gateRows}

### Passed

- [x] \` repository checks passed \`

### Failed or incomplete

- [ ] \` captured commit lacks release tag 1.0.0 or v1.0.0 \`

### Warnings

- None recorded.

## Manual gates (not evaluated)

- [ ] A manual gate.
`;
  fs.writeFileSync(reportPath, goodReport);

  const accepted = run('python3', [pretagChecker, reportPath]);
  assert.equal(accepted.status, 0, accepted.stdout + accepted.stderr);
  assert.match(accepted.stdout, /every automated gate passed except/);

  fs.writeFileSync(
    reportPath,
    goodReport.replace(
      '- [x] `PASS` - Production dependency advisory audit',
      '- [ ] `FAIL` - Production dependency advisory audit',
    ),
  );
  const extraFailure = run('python3', [pretagChecker, reportPath]);
  assert.equal(extraFailure.status, 1, extraFailure.stdout + extraFailure.stderr);
  assert.match(extraFailure.stderr, /non-tag automated gates are incomplete/);

  fs.writeFileSync(
    reportPath,
    goodReport.replace(
      'Package version at captured commit: ` 1.0.0 `',
      'Package version at captured commit: ` 1.0.1 `',
    ),
  );
  const mismatchedVersion = run('python3', [pretagChecker, reportPath]);
  assert.equal(mismatchedVersion.status, 1, mismatchedVersion.stdout + mismatchedVersion.stderr);
  assert.match(mismatchedVersion.stderr, /does not equal candidate/);

  fs.writeFileSync(
    reportPath,
    goodReport.replace(
      '- [x] `PASS` - Required host tools',
      '- [x] `BROKEN` - Required host tools',
    ),
  );
  const malformedGate = run('python3', [pretagChecker, reportPath]);
  assert.equal(malformedGate.status, 1, malformedGate.stdout + malformedGate.stderr);
  assert.match(malformedGate.stderr, /malformed automated-gate row/);

  fs.writeFileSync(
    reportPath,
    goodReport.replace(
      '### Warnings',
      '- [ ] ` an unmapped internal failure `\n\n### Warnings',
    ),
  );
  const unmappedFailure = run('python3', [pretagChecker, reportPath]);
  assert.equal(unmappedFailure.status, 1, unmappedFailure.stdout + unmappedFailure.stderr);
  assert.match(unmappedFailure.stderr, /not exactly the absent-tag failure/);

  fs.writeFileSync(
    reportPath,
    goodReport.replace(
      '> Outcome: **FAIL** (exit status `1`)',
      '> Outcome: **PASS** (exit status `0`)\n\n> Outcome: **FAIL** (exit status `1`)',
    ),
  );
  const forgedOutcome = run('python3', [pretagChecker, reportPath]);
  assert.equal(forgedOutcome.status, 1, forgedOutcome.stdout + forgedOutcome.stderr);
  assert.match(forgedOutcome.stderr, /outcome is missing, misplaced, or duplicated/);

  fs.writeFileSync(
    reportPath,
    goodReport.replace(
      '- Package version at captured commit: ` 1.0.0 `',
      '- Package version at captured commit: ` 1.0.0 `\n' +
      '- Package version at captured commit: ` 1.0.0 `',
    ),
  );
  const duplicateIdentity = run('python3', [pretagChecker, reportPath]);
  assert.equal(duplicateIdentity.status, 1, duplicateIdentity.stdout + duplicateIdentity.stderr);
  assert.match(duplicateIdentity.stderr, /package version is missing or duplicated/);

  fs.writeFileSync(reportPath, goodReport);
  const reportLink = path.join(tempRoot, 'audit-link.md');
  fs.symlinkSync(reportPath, reportLink);
  const symlinkReport = run('python3', [pretagChecker, reportLink]);
  assert.equal(symlinkReport.status, 1, symlinkReport.stdout + symlinkReport.stderr);
  assert.match(symlinkReport.stderr, /could not read/);
});

test('host help states the no-host-npm boundary and invalid options return 2', () => {
  const help = run('bash', [hostScript, '--help']);
  assert.equal(help.status, 0, help.stderr);
  assert.match(help.stdout, /never runs npm, npx, or node on the host/i);
  assert.match(help.stdout, /Docker is mandatory/i);
  assert.match(help.stdout, /rebuild, tests, build, pack: --network none/);
  assert.match(help.stdout, /full-checkout inventory:\s+--network none, ephemeral copy/);
  assert.match(help.stdout, /remain explicit manual gates/);
  assert.match(help.stdout, /limited to 30\s+minutes/);
  assert.match(help.stdout, /release candidate\s+declared in the captured `RELEASE\.md`/i);
  assert.match(help.stdout, /\.release-audit\/latest\.md/);
  assert.match(help.stdout, /--report PATH/);
  assert.match(help.stdout, /inside the checkout must stay below\s+`?\.release-audit/i);
  assert.match(help.stdout, /never edits or\s+checks boxes in RELEASE\.md/);

  const invalid = run('bash', [hostScript, '--not-an-option']);
  assert.equal(invalid.status, 2);

  const missingReportPath = run('bash', [hostScript, '--report']);
  assert.equal(missingReportPath.status, 2);
  assert.match(missingReportPath.stderr, /--report requires a non-empty path/);
});

test('host wrapper has no direct package-manager invocation', () => {
  const source = fs.readFileSync(hostScript, 'utf8');

  assert.doesNotMatch(source, /^\s*(?:command\s+)?(?:npm|npx|node)\b/m);
  assert.doesNotMatch(source, /\$\(\s*(?:npm|npx|node)\b/);
  assert.match(source, /readonly -f npm npx node/);
  assert.match(source, /Docker daemon is unavailable; refusing to fall back to host npm/);
});

test('missing Docker never falls back to a host npm executable', (t) => {
  const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'notty-release-audit-test-'));
  t.after(() => fs.rmSync(tempRoot, { recursive: true, force: true }));

  const fakeBin = path.join(tempRoot, 'bin');
  const npmMarker = path.join(tempRoot, 'host-npm-was-called');
  const reportPath = path.join(tempRoot, 'reports with spaces', 'audit.md');
  const releasePath = path.join(root, 'RELEASE.md');
  const releaseBefore = fs.readFileSync(releasePath, 'utf8');
  fs.mkdirSync(fakeBin);
  fs.writeFileSync(
    path.join(fakeBin, 'docker'),
    '#!/bin/sh\n[ "$1" = info ] && exit 1\nexit 99\n',
    { mode: 0o755 },
  );
  fs.writeFileSync(
    path.join(fakeBin, 'npm'),
    `#!/bin/sh\ntouch ${JSON.stringify(npmMarker)}\nexit 99\n`,
    { mode: 0o755 },
  );

  const result = run('/bin/bash', [hostScript, '--report', reportPath], {
    env: {
      PATH: `${fakeBin}:/usr/bin:/bin`,
      TMPDIR: tempRoot,
    },
  });

  assert.equal(result.status, 1, result.stdout + result.stderr);
  assert.match(result.stdout + result.stderr, /refusing to fall back to host npm/i);
  assert.equal(fs.existsSync(npmMarker), false, 'host npm must never be called');
  assert.equal(fs.existsSync(reportPath), true, 'early failure must still write a report');
  assert.equal(fs.statSync(reportPath).mode & 0o777, 0o600);
  assert.equal(fs.readFileSync(releasePath, 'utf8'), releaseBefore);

  const report = fs.readFileSync(reportPath, 'utf8');
  assert.match(report, /Outcome: \*\*INCOMPLETE\*\*/);
  assert.match(report, /Docker daemon is unavailable; refusing to fall back to host npm/);
  assert.match(report, /- \[x\] `PASS` - Required host tools/);
  assert.match(report, /- \[ \] `FAIL` - Docker daemon availability/);
  assert.match(report, /- \[ \] `NOT RUN` - Git whitespace checks/);
  assert.match(report, /- \[ \] `NOT RUN` - Offline metadata, release files, rebuild, tests, build, and package verification/);
  assert.match(report, /- \[ \] `NOT RUN` - Ephemeral audit object cleanup/);
  assert.match(report, /- \[x\] ` host command available: docker `/);
  assert.match(report, /## Manual gates \(not evaluated\)/);
  assert.match(report, /does not modify\n`RELEASE\.md`/);
  assert.match(result.stdout, new RegExp(`report=${escapeRegExp(reportPath)}`));
});

test('an interrupted audit publishes an INTERRUPTED report', async (t) => {
  const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'notty-release-audit-signal-'));
  const fakeBin = path.join(tempRoot, 'bin');
  const dockerMarker = path.join(tempRoot, 'docker-info-started');
  const reportPath = path.join(tempRoot, 'interrupted.md');
  let child;

  t.after(() => {
    if (child && child.exitCode === null && child.signalCode === null) {
      try {
        process.kill(-child.pid, 'SIGKILL');
      } catch {
        // The detached process group already exited.
      }
    }
    fs.rmSync(tempRoot, { recursive: true, force: true });
  });

  fs.mkdirSync(fakeBin);
  fs.writeFileSync(
    path.join(fakeBin, 'docker'),
    `#!/bin/sh\nif [ "$1" = info ]; then\n  touch ${JSON.stringify(dockerMarker)}\n  exec sleep 30\nfi\nexit 99\n`,
    { mode: 0o755 },
  );

  child = childProcess.spawn('/bin/bash', [hostScript, '--report', reportPath], {
    cwd: root,
    detached: true,
    env: {
      PATH: `${fakeBin}:/usr/bin:/bin`,
      TMPDIR: tempRoot,
    },
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  child.stdout.setEncoding('utf8');
  child.stderr.setEncoding('utf8');
  let output = '';
  child.stdout.on('data', (chunk) => {
    output += chunk;
  });
  child.stderr.on('data', (chunk) => {
    output += chunk;
  });
  const closePromise = waitForChildClose(child);

  await waitForPath(dockerMarker);
  process.kill(-child.pid, 'SIGTERM');
  const { code, signal } = await closePromise;

  assert.equal(signal, null, output);
  assert.equal(code, 143, output);
  assert.equal(fs.existsSync(reportPath), true, output);
  const report = fs.readFileSync(reportPath, 'utf8');
  assert.match(report, /Outcome: \*\*INTERRUPTED\*\* \(exit status `143`\)/);
  assert.match(report, /release audit interrupted by TERM/);
  assert.match(report, /- \[ \] `NOT RUN` - Docker daemon availability/);
  assert.match(report, /The audit was interrupted by ` TERM `/);
});

test('report publication refuses a symlink target', (t) => {
  const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'notty-release-audit-symlink-'));
  t.after(() => fs.rmSync(tempRoot, { recursive: true, force: true }));

  const fakeBin = path.join(tempRoot, 'bin');
  const dockerMarker = path.join(tempRoot, 'docker-was-called');
  const sentinel = path.join(tempRoot, 'sentinel.md');
  const reportLink = path.join(tempRoot, 'report.md');
  fs.mkdirSync(fakeBin);
  fs.writeFileSync(
    path.join(fakeBin, 'docker'),
    `#!/bin/sh\ntouch ${JSON.stringify(dockerMarker)}\nexit 99\n`,
    { mode: 0o755 },
  );
  fs.writeFileSync(sentinel, 'do not overwrite\n');
  fs.symlinkSync(sentinel, reportLink);

  const result = run('/bin/bash', [hostScript, `--report=${reportLink}`], {
    env: {
      PATH: `${fakeBin}:/usr/bin:/bin`,
      TMPDIR: tempRoot,
    },
  });

  assert.equal(result.status, 1, result.stdout + result.stderr);
  assert.match(result.stdout + result.stderr, /refusing symlink report target/);
  assert.equal(fs.existsSync(dockerMarker), false, 'invalid report must fail before Docker');
  assert.equal(fs.readFileSync(sentinel, 'utf8'), 'do not overwrite\n');
  assert.equal(fs.lstatSync(reportLink).isSymbolicLink(), true);

  const existingTargetResult = run('/bin/bash', [hostScript, '--report', sentinel], {
    env: {
      PATH: `${fakeBin}:/usr/bin:/bin`,
      TMPDIR: tempRoot,
    },
  });
  assert.equal(existingTargetResult.status, 1);
  assert.match(existingTargetResult.stdout + existingTargetResult.stderr, /not a Notty audit report/);
  assert.equal(fs.existsSync(dockerMarker), false, 'existing non-report must fail before Docker');
  assert.equal(fs.readFileSync(sentinel, 'utf8'), 'do not overwrite\n');

  const releasePath = path.join(root, 'RELEASE.md');
  const releaseBefore = fs.readFileSync(releasePath, 'utf8');
  const releaseTargetResult = run('/bin/bash', [hostScript, '--report', releasePath], {
    env: {
      PATH: `${fakeBin}:/usr/bin:/bin`,
      TMPDIR: tempRoot,
    },
  });
  assert.equal(releaseTargetResult.status, 1);
  assert.match(releaseTargetResult.stdout + releaseTargetResult.stderr, /refusing to use RELEASE\.md/);
  assert.equal(fs.existsSync(dockerMarker), false, 'RELEASE target must fail before Docker');
  assert.equal(fs.readFileSync(releasePath, 'utf8'), releaseBefore);
});

test('custom reports inside the checkout are confined to .release-audit', (t) => {
  const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'notty-release-audit-scope-'));
  t.after(() => fs.rmSync(tempRoot, { recursive: true, force: true }));

  const fakeBin = path.join(tempRoot, 'bin');
  const dockerMarker = path.join(tempRoot, 'docker-was-called');
  const forbiddenReport = path.join(root, `.audit-report-${process.pid}.md`);
  const localReportDir = path.join(root, '.release-audit');
  const outsideDir = path.join(tempRoot, 'outside');
  const escapeLink = path.join(localReportDir, `escape-${process.pid}`);
  t.after(() => fs.rmSync(forbiddenReport, { force: true }));
  t.after(() => {
    fs.rmSync(escapeLink, { force: true });
    try {
      fs.rmdirSync(localReportDir);
    } catch {
      // Preserve a pre-existing or non-empty local report directory.
    }
  });
  fs.mkdirSync(fakeBin);
  fs.mkdirSync(localReportDir, { recursive: true });
  fs.mkdirSync(outsideDir);
  fs.symlinkSync(outsideDir, escapeLink);
  fs.writeFileSync(
    path.join(fakeBin, 'docker'),
    `#!/bin/sh\ntouch ${JSON.stringify(dockerMarker)}\nexit 99\n`,
    { mode: 0o755 },
  );

  const result = run('/bin/bash', [hostScript, '--report', forbiddenReport], {
    env: {
      PATH: `${fakeBin}:/usr/bin:/bin`,
      TMPDIR: tempRoot,
    },
  });

  assert.equal(result.status, 1, result.stdout + result.stderr);
  assert.match(result.stdout + result.stderr, /in-repository reports must stay under/);
  assert.equal(fs.existsSync(forbiddenReport), false);
  assert.equal(fs.existsSync(dockerMarker), false, 'report scope must be checked before Docker');

  const escapedReport = path.join(escapeLink, 'created', 'report.md');
  const escapeResult = run('/bin/bash', [hostScript, '--report', escapedReport], {
    env: {
      PATH: `${fakeBin}:/usr/bin:/bin`,
      TMPDIR: tempRoot,
    },
  });

  assert.equal(escapeResult.status, 1, escapeResult.stdout + escapeResult.stderr);
  assert.match(escapeResult.stdout + escapeResult.stderr, /resolved outside/);
  assert.equal(fs.existsSync(path.join(outsideDir, 'created')), false);
  assert.equal(fs.existsSync(dockerMarker), false, 'symlink escape must fail before Docker');
});

test('release tag must match the captured RELEASE candidate', (t) => {
  const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'notty-release-audit-tag-'));
  t.after(() => fs.rmSync(tempRoot, { recursive: true, force: true }));

  const fixture = path.join(tempRoot, 'checkout');
  const fakeBin = path.join(tempRoot, 'bin');
  const reportPath = path.join(tempRoot, 'tag-report.md');
  const gitEnv = {
    ...process.env,
    GIT_CONFIG_GLOBAL: '/dev/null',
    GIT_CONFIG_NOSYSTEM: '1',
    GIT_CONFIG_COUNT: '2',
    GIT_CONFIG_KEY_0: 'commit.gpgSign',
    GIT_CONFIG_VALUE_0: 'false',
    GIT_CONFIG_KEY_1: 'tag.gpgSign',
    GIT_CONFIG_VALUE_1: 'false',
  };
  const releaseCandidateMatch = fs.readFileSync(path.join(root, 'RELEASE.md'), 'utf8')
    .match(/^\*\*Release candidate:\*\* `([^`]+)`$/m);
  assert.ok(releaseCandidateMatch, 'RELEASE.md must declare one release candidate');
  const expectedReleaseVersion = releaseCandidateMatch[1];
  fs.mkdirSync(path.join(fixture, 'scripts'), { recursive: true });
  fs.mkdirSync(fakeBin);
  for (const [source, destination] of [
    [hostScript, path.join(fixture, 'release-audit.sh')],
    [containerScript, path.join(fixture, 'scripts', 'release-audit-container.sh')],
    [auditDockerfile, path.join(fixture, 'Dockerfile.release-audit')],
    [path.join(root, 'RELEASE.md'), path.join(fixture, 'RELEASE.md')],
    [path.join(root, 'package.json'), path.join(fixture, 'package.json')],
    [path.join(root, 'package-lock.json'), path.join(fixture, 'package-lock.json')],
  ]) {
    fs.copyFileSync(source, destination);
  }
  const fixturePackagePath = path.join(fixture, 'package.json');
  const fixtureLockPath = path.join(fixture, 'package-lock.json');
  const fixturePackage = JSON.parse(fs.readFileSync(fixturePackagePath, 'utf8'));
  const fixtureLock = JSON.parse(fs.readFileSync(fixtureLockPath, 'utf8'));
  fixturePackage.version = expectedReleaseVersion;
  fixtureLock.version = expectedReleaseVersion;
  fixtureLock.packages[''].version = expectedReleaseVersion;
  fs.writeFileSync(fixturePackagePath, `${JSON.stringify(fixturePackage, null, 2)}\n`);
  fs.writeFileSync(fixtureLockPath, `${JSON.stringify(fixtureLock, null, 2)}\n`);
  fs.chmodSync(path.join(fixture, 'release-audit.sh'), 0o755);
  fs.writeFileSync(
    path.join(fakeBin, 'docker'),
    '#!/bin/sh\n[ "$1" = info ] && exit 0\nexit 99\n',
    { mode: 0o755 },
  );

  for (const args of [
    ['init', '-q'],
    ['config', 'user.name', 'Release Audit Test'],
    ['config', 'user.email', 'release-audit@example.invalid'],
    ['add', '.'],
    ['commit', '-qm', 'fixture'],
    ['tag', 'backup/test'],
  ]) {
    const gitResult = run('git', args, { cwd: fixture, env: gitEnv });
    assert.equal(gitResult.status, 0, gitResult.stderr);
  }

  const result = run('/bin/bash', [path.join(fixture, 'release-audit.sh'), '--report', reportPath], {
    cwd: fixture,
    env: {
      PATH: `${fakeBin}:/usr/bin:/bin`,
      TMPDIR: tempRoot,
    },
  });

  assert.equal(result.status, 1, result.stdout + result.stderr);
  const report = fs.readFileSync(reportPath, 'utf8');
  assert.ok(
    report.includes(
      'Release candidate at captured commit: ` ' + expectedReleaseVersion + ' `',
    ),
  );
  assert.ok(
    report.includes(
      'Package version at captured commit: ` ' + expectedReleaseVersion + ' `',
    ),
  );
  assert.match(report, /Exact tags at captured commit: ` backup\/test `/);
  assert.match(report, /- \[ \] `FAIL` - RELEASE\.md version and exact release tag/);
  assert.ok(
    report.includes(
      `captured commit lacks release tag ${expectedReleaseVersion} or ` +
      `v${expectedReleaseVersion}`,
    ),
  );
});

test('container helper refuses to execute outside the audit container', () => {
  const result = run('/bin/bash', [containerScript, 'acquire'], {
    env: {
      PATH: '/usr/bin:/bin',
      DOCKER_CONTAINER: '0',
      HOME: '/audit/runtime/home',
      NPM_CONFIG_USERCONFIG: '/dev/null',
    },
  });

  assert.equal(result.status, 2);
  assert.match(result.stderr, /refusing to run npm/);
});

test('audit image and Docker phases keep the intended isolation controls', () => {
  const dockerfile = fs.readFileSync(auditDockerfile, 'utf8');
  const hostSource = fs.readFileSync(hostScript, 'utf8');

  assert.match(
    dockerfile,
    /node:24\.18\.0-bookworm-slim@sha256:[a-f0-9]{64}/,
  );
  assert.match(dockerfile, /^USER node$/m);
  assert.match(hostSource, /--read-only/);
  assert.match(hostSource, /--cap-drop ALL/);
  assert.match(hostSource, /--security-opt=no-new-privileges=true/);
  assert.match(hostSource, /common_container_args "\$verify_name" none/);
  assert.match(hostSource, /common_container_args "\$inventory_name" none|inventory_name[\s\S]*?none/);
  assert.equal(
    (hostSource.match(/\/audit\/exec-tmp:rw,nosuid,nodev,exec/g) || []).length,
    1,
  );
  assert.match(hostSource, /\/audit\/exec-tmp:rw,nosuid,nodev,exec,size=512m/);
  assert.match(hostSource, /--env TMPDIR=\/audit\/exec-tmp/);
  assert.match(hostSource, /\/tmp:rw,nosuid,nodev,noexec/);
  assert.match(hostSource, /\/audit\/runtime:rw,nosuid,nodev,noexec/);
  assert.match(hostSource, /captured commit contains a tracked node_modules path/);
  assert.match(hostSource, /import tarfile/);
  assert.doesNotMatch(hostSource, /dst=\/source/);
  assert.doesNotMatch(hostSource, /docker\.sock|--privileged|--network host/);
  const containerSource = fs.readFileSync(containerScript, 'utf8');
  assert.match(containerSource, /WORK_ROOT="\$DEPS_ROOT"/);
  assert.doesNotMatch(containerSource, /ln -s "\$DEPS_ROOT\/node_modules"/);
  assert.match(containerSource, /Offline executable test scratch/);
  assert.match(containerSource, /dependency volume contains unexpected top-level entries/);
  assert.doesNotMatch(containerSource, /--exclude=.*node_modules/);
});

test('generated reports are excluded from Git, Docker, package, and inventory inputs', () => {
  const gitignore = fs.readFileSync(path.join(root, '.gitignore'), 'utf8');
  const dockerignore = fs.readFileSync(path.join(root, '.dockerignore'), 'utf8');
  const npmignore = fs.readFileSync(path.join(root, '.npmignore'), 'utf8');
  const hostSource = fs.readFileSync(hostScript, 'utf8');
  const containerSource = fs.readFileSync(containerScript, 'utf8');

  assert.match(gitignore, /^\/\.release-audit\/$/m);
  assert.match(dockerignore, /^\.release-audit$/m);
  assert.match(npmignore, /^\.release-audit\/$/m);
  assert.match(hostSource, /--exclude='\.\/\.release-audit'/);
  assert.match(hostSource, /chmod 0700 "\$REPO_ROOT\/\.release-audit"/);
  assert.match(hostSource, /chmod 0600 "\$REPORT_TMP"/);
  assert.match(hostSource, /mv -T -- "\$REPORT_TMP" "\$REPORT_PATH"/);
  assert.match(containerSource, /\^\\\.release-audit\\\//);
});
