'use strict';

const assert = require('node:assert/strict');
const childProcess = require('node:child_process');
const crypto = require('node:crypto');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const test = require('node:test');

const appRoot = path.resolve(__dirname, '..');
const workflowPath = path.join(appRoot, 'scripts/profile-build-and-run.sh');

function writeExecutable(filePath, lines) {
  fs.writeFileSync(filePath, `${lines.join('\n')}\n`, { mode: 0o755 });
}

function createFixture(t, {
  buildExit = 0,
  buildEligible = true,
  runtimeDuration = 3,
} = {}) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'notty combined profile '));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));

  const bin = path.join(root, 'fake commands');
  const home = path.join(root, 'profile home');
  const workspace = path.join(root, 'runtime workspace');
  const buildBundle = path.join(root, 'build profile bundle');
  const buildPortable = path.join(buildBundle, 'portable');
  const runtimeAuthority = path.join(root, 'authoritative runtime bundle');
  const runtimeMirror = path.join(root, 'returned runtime mirror');
  const stateDirectory = path.join(root, 'fixture state');
  for (const directory of [
    bin,
    home,
    workspace,
    buildPortable,
    runtimeAuthority,
    runtimeMirror,
    stateDirectory,
  ]) {
    fs.mkdirSync(directory, { recursive: true });
  }

  const eventLog = path.join(stateDirectory, 'events.log');
  const dockerLog = path.join(stateDirectory, 'docker.log');
  const buildEnvironmentLog = path.join(stateDirectory, 'build-environment.log');
  const buildReady = path.join(stateDirectory, 'build-ready');
  const buildChildPid = path.join(stateDirectory, 'build-child.pid');
  const staleEvidence = path.join(stateDirectory, 'stale-evidence-manifest.json');
  const buildState = path.join(stateDirectory, 'build-state.json');
  const buildAfter = path.join(stateDirectory, 'build-after.json');
  const buildResult = path.join(stateDirectory, 'build-result.json');
  const buildSelected = path.join(stateDirectory, 'build-selected.json');
  const runtimeLearn = path.join(stateDirectory, 'runtime-learn.json');
  const runtimeStatus = path.join(stateDirectory, 'runtime-status.json');
  const buildRunId = 'build-run-with-spaces';
  const runtimeGuardName = `nosh-profile-${crypto
    .createHash('sha256')
    .update(buildRunId, 'utf8')
    .digest('hex')
    .slice(0, 24)}`;
  const runtimeRevision = 'runtime-revision-with-spaces';
  const buildOutputImageDigest = `sha256:${'d'.repeat(64)}`;
  const buildConfigDigest = `sha256:${'e'.repeat(64)}`;
  const policyToolingImage = `sha256:${'9'.repeat(64)}`;
  const buildCandidateBytes = Buffer.from(
    '{"kind":"build-profile","marker":"displayed build artifact"}\n',
  );
  const buildCandidateHash = `sha256:${crypto
    .createHash('sha256')
    .update(buildCandidateBytes)
    .digest('hex')}`;
  const buildProfile = path.join(buildPortable, 'candidate.json');

  fs.writeFileSync(staleEvidence, '{"historical":"invalid but preserved"}\n');
  fs.writeFileSync(buildState, '{"runs":[]}\n');
  fs.writeFileSync(buildAfter, `${JSON.stringify({
    runs: [{
      runId: buildRunId,
      directory: buildBundle,
      complete: buildEligible,
      candidateEligible: buildEligible,
    }],
  })}\n`);
  fs.writeFileSync(buildSelected, `${JSON.stringify({
    directory: buildBundle,
    portableDirectory: buildPortable,
    manifest: {
      schemaVersion: 1,
      apiVersion: 'notty.dev/v1alpha1',
      kind: 'NoshBuildEvidenceManifest',
      runId: buildRunId,
      mode: 'build-profile',
      complete: buildEligible,
      candidateEligible: buildEligible,
      build: {
        success: buildEligible,
        exitCode: buildEligible ? 0 : 37,
        outputImageDigest: buildOutputImageDigest,
        configDigest: buildConfigDigest,
      },
    },
    candidate: buildEligible
      ? { spec: { outputImageDigest: buildOutputImageDigest } }
      : null,
    report: {
      build: { outputImageDigest: buildOutputImageDigest },
    },
    portableBundle: {
      schemaVersion: 1,
      apiVersion: 'notty.dev/v1alpha1',
      kind: 'NoshBuildPortableBundle',
      runId: buildRunId,
      mode: 'build-profile',
      projectKey: 'f'.repeat(64),
      authoritative: false,
      attested: false,
      integrityOnly: true,
      redacted: true,
      files: {
        'candidate.json': {
          hash: buildCandidateHash,
          bytes: buildCandidateBytes.length,
          mediaType: 'application/json',
        },
      },
      contentHash: `sha256:${'a'.repeat(64)}`,
    },
  })}\n`);
  const selectedBuild = JSON.parse(fs.readFileSync(buildSelected, 'utf8'));
  fs.writeFileSync(buildResult, `${JSON.stringify({
    profileId: buildRunId,
    mode: 'build-profile',
    cacheMode: 'compare',
    depth: 'balanced',
    bundleDir: buildBundle,
    portableBundleDir: buildPortable,
    candidate: selectedBuild.candidate,
    manifest: selectedBuild.manifest,
    passes: [],
    status: buildEligible ? 0 : 37,
  })}\n`);
  const runtimePolicyBytes = Buffer.from(
    '{"kind":"runtime-egress-policy","marker":"displayed runtime artifact"}\n',
  );
  const policyHash = `sha256:${crypto
    .createHash('sha256')
    .update(runtimePolicyBytes)
    .digest('hex')}`;
  const profileHash = `sha256:${'b'.repeat(64)}`;
  const manifestHash = `sha256:${'c'.repeat(64)}`;
  const authoritativePolicy = path.join(runtimeAuthority, 'egress-policy.json');
  const runtimeProfile = path.join(runtimeMirror, 'candidate-egress-policy.json');
  const evidenceManifest = path.join(runtimeAuthority, 'evidence-manifest.json');
  const runtimeReviewCandidate = path.join(
    runtimeMirror,
    'review-candidates',
    'a'.repeat(64),
    runtimeRevision,
  );
  const runtimeReviewTargetContext = path.join(
    runtimeReviewCandidate,
    'guard-ebpf-target-context.json',
  );
  fs.mkdirSync(runtimeReviewCandidate, { recursive: true, mode: 0o700 });
  fs.writeFileSync(authoritativePolicy, runtimePolicyBytes);
  fs.writeFileSync(runtimeProfile, runtimePolicyBytes);
  fs.writeFileSync(evidenceManifest, '{"complete":true}\n');
  fs.writeFileSync(runtimeReviewTargetContext, '{"kind":"NoshGuardEbpfTargetContext"}\n', {
    mode: 0o600,
  });

  fs.writeFileSync(runtimeLearn, `${JSON.stringify({
    apiVersion: 'notty.dev/v1alpha1',
    kind: 'NoshEgressLearnResult',
    runId: runtimeRevision,
    revision: runtimeRevision,
    profileDirectory: runtimeAuthority,
    mirrorDirectory: runtimeMirror,
    authoritativePolicy,
    mirrorPolicy: runtimeProfile,
    candidatePolicy: runtimeProfile,
    reviewCandidateDirectory: runtimeReviewCandidate,
    reviewTargetContext: runtimeReviewTargetContext,
    evidenceManifest,
    imageDigest: buildConfigDigest,
    imageReference: buildConfigDigest,
    policyHash,
    profileHash,
    manifestHash,
    durationSeconds: runtimeDuration,
    requestedDurationSeconds: runtimeDuration,
    observedDurationMilliseconds: runtimeDuration * 1000 + 25,
    observationComplete: true,
  })}\n`);
  fs.writeFileSync(runtimeStatus, `${JSON.stringify({
    apiVersion: 'notty.dev/v1alpha1',
    kind: 'NoshEgressProfileReceipt',
    workspace: { path: fs.realpathSync(workspace) },
    integrity: {
      ok: true,
      checks: {
        candidate: {
          present: true,
          ok: true,
          revision: runtimeRevision,
        },
      },
    },
    latestCandidate: {
      runId: runtimeRevision,
      revision: runtimeRevision,
      directory: runtimeAuthority,
      imageDigest: buildConfigDigest,
      evidenceManifest,
      policyHash,
      profileHash,
      manifestHash,
      launchConfig: {
        image: buildConfigDigest,
        imageDigest: buildConfigDigest,
        name: runtimeGuardName,
        observationDurationSeconds: runtimeDuration,
      },
    },
    lastLaunch: {
      mode: 'egress-learn',
      runId: runtimeRevision,
      revision: runtimeRevision,
      profileDirectory: runtimeAuthority,
    },
  })}\n`);

  fs.writeFileSync(buildProfile, buildCandidateBytes);
  fs.writeFileSync(
    path.join(buildPortable, 'report.txt'),
    'portable build report from fixture\n',
  );

  const buildBin = path.join(bin, 'fake build launcher');
  const dockerBin = path.join(bin, 'docker');
  const noshBin = path.join(bin, 'fake nosh launcher');
  const sudoBin = path.join(bin, 'fake sudo launcher');
  const privilegedGuard = fs.realpathSync('/bin/true');

  writeExecutable(buildBin, [
    '#!/usr/bin/env bash',
    'set -euo pipefail',
    '{',
    "  printf 'build'",
    '  for argument in "$@"; do printf "\\t%s" "$argument"; done',
    "  printf '\\n'",
    '} >>"$NOSH_TEST_EVENT_LOG"',
    'printf "IMAGE_NAME=%s\\nTARGET=%s\\n" "${IMAGE_NAME-}" "${TARGET-}" >"$NOSH_TEST_BUILD_ENV_LOG"',
    'for argument in "$@"; do',
    '  if [[ "$argument" == "--dry-run" ]]; then',
    "    printf 'fake build dry run\\n'",
    '    exit 0',
    '  fi',
    'done',
    'if [[ -n "${NOSH_TEST_BUILD_ERROR-}" ]]; then',
    '  printf "%s\\n" "$NOSH_TEST_BUILD_ERROR" >&2',
    'fi',
    'if [[ "$NOSH_TEST_BLOCK_BUILD" == "true" ]]; then',
    "  trap 'printf \"build-signal\\tINT\\n\" >>\"$NOSH_TEST_EVENT_LOG\"; exit 130' INT",
    "  trap 'printf \"build-signal\\tTERM\\n\" >>\"$NOSH_TEST_EVENT_LOG\"; exit 143' TERM",
    '  printf "%s\\n" "$$" >"$NOSH_TEST_BUILD_CHILD_PID"',
    '  : >"$NOSH_TEST_BUILD_READY"',
    '  while :; do',
    '    read -r -t 60 _ || true',
    '  done',
    'fi',
    'cp -- "$NOSH_TEST_BUILD_AFTER" "$NOSH_TEST_BUILD_STATE"',
    'if [[ " ${*} " == *" --private-json "* ]]; then',
    '  command cat -- "$NOSH_TEST_BUILD_RESULT"',
    'else',
    "  printf 'fake profiled build\\n'",
    'fi',
    'exit "$NOSH_TEST_BUILD_EXIT"',
  ]);

  writeExecutable(dockerBin, [
    '#!/usr/bin/env bash',
    'set -euo pipefail',
    'if [[ "${1-}" == "image" && "${2-}" == "inspect" ]]; then',
    '  [[ "${NOSH_TEST_POLICY_TOOLING_INSPECT_FAIL:-false}" != "true" ]] || exit 1',
    '  requested="${*: -1}"',
    '  [[ "$requested" == "$NOSH_TEST_POLICY_TOOLING_IMAGE" ]] || exit 98',
    '  printf "%s|%s\\n" "${NOSH_TEST_POLICY_TOOLING_RESOLVED_ID:-$requested}" "${NOSH_TEST_POLICY_TOOLING_ABI:-1}"',
    '  exit 0',
    'fi',
    'if [[ "${1-}" == "run" ]]; then',
    '  interactive=false',
    '  shift',
    '  while (($#)); do',
    '    case "$1" in',
    '      --rm|--read-only) shift ;;',
    '      -i|--interactive) interactive=true; shift ;;',
    '      --pull|--network|--user|--cap-drop|--security-opt|--pids-limit|--memory|--memory-swap|--tmpfs|--env|--mount|--entrypoint) shift 2 ;;',
    '      --*) printf "unexpected fake docker run option: %s\\n" "$1" >&2; exit 96 ;;',
    '      *) break ;;',
    '    esac',
    '  done',
    '  image="${1-}"',
    '  [[ -n "$image" ]] || exit 95',
    '  shift',
    '  printf "run\\t%s" "$image" >>"$NOSH_TEST_DOCKER_LOG"',
    '  for argument in "$@"; do printf "\\t%s" "$argument" >>"$NOSH_TEST_DOCKER_LOG"; done',
    '  printf "\\n" >>"$NOSH_TEST_DOCKER_LOG"',
    // Docker closes container stdin unless --interactive is supplied.
    '  if [[ "$interactive" != true ]]; then exec </dev/null; fi',
    '  exec "$NOSH_TEST_NODE_BIN" "$@"',
    'fi',
    'printf "unexpected docker invocation\\n" >&2',
    'exit 97',
  ]);

  writeExecutable(noshBin, [
    '#!/usr/bin/env bash',
    'set -euo pipefail',
    '{',
    "  printf 'nosh'",
    '  for argument in "$@"; do printf "\\t%s" "$argument"; done',
    "  printf '\\n'",
    '} >>"$NOSH_TEST_EVENT_LOG"',
    'if [[ "${1-}" == "build" && "${2-}" == "status" ]]; then',
    '  if [[ " ${*} " != *" --run "* && "$NOSH_TEST_FAIL_BROAD_STATUS" == "true" ]]; then',
    "    printf 'stale historical build profile is invalid\\n' >&2",
    '    exit 88',
    '  fi',
    '  if [[ " ${*} " == *" --run "* && " ${*} " == *" --json "* && "$NOSH_TEST_FAIL_EXACT_JSON" == "true" ]]; then',
    "    printf 'exact build profile is invalid\\n' >&2",
    '    exit 89',
    '  fi',
    '  if [[ " ${*} " == *" --run "* && " ${*} " == *" --json "* ]]; then',
    '    command cat -- "$NOSH_TEST_BUILD_SELECTED"',
    '  elif [[ " ${*} " == *" --json "* ]]; then',
    '    command cat -- "$NOSH_TEST_BUILD_STATE"',
    '  else',
    "    printf 'fixture build profile report\\n'",
    '  fi',
    '  exit 0',
    'fi',
    'if [[ "${1-}" == "net" && "${2-}" == "learn" ]]; then',
    '  if [[ -n "$NOSH_TEST_MUTATE_BUILD_CANDIDATE" ]]; then',
    '    printf "{\\\"marker\\\":\\\"mutated after snapshot\\\"}\\n" >"$NOSH_TEST_MUTATE_BUILD_CANDIDATE"',
    '  fi',
    '  if [[ "${NOSH_TEST_RUNTIME_LEARN_EXIT:-0}" != "0" ]]; then',
    '    printf "%s\\n" "${NOSH_TEST_RUNTIME_LEARN_ERROR:-runtime learn failed}" >&2',
    '    if [[ -n "${NOSH_TEST_RUNTIME_LEARN_PARTIAL:-}" ]]; then',
    '      printf "%s\\n" "$NOSH_TEST_RUNTIME_LEARN_PARTIAL"',
    '    fi',
    '    exit "$NOSH_TEST_RUNTIME_LEARN_EXIT"',
    '  fi',
    '  if [[ " ${*} " == *" --dry-run "* ]]; then',
    "    printf '{\"dryRun\":true}\\n'",
    '  elif [[ " ${*} " == *" --json "* ]]; then',
    '    command cat -- "$NOSH_TEST_RUNTIME_LEARN"',
    '  else',
    "    printf 'fixture runtime learning report\\n'",
    '  fi',
    '  exit 0',
    'fi',
    'if [[ "${1-}" == "net" && "${2-}" == "status" ]]; then',
    '  if [[ " ${*} " == *" --json "* ]]; then',
    '    command cat -- "$NOSH_TEST_RUNTIME_STATUS"',
    '  else',
    "    printf 'fixture runtime profile report\\n'",
    '  fi',
    '  exit 0',
    'fi',
    "printf 'unexpected fake nosh invocation\\n' >&2",
    'exit 97',
  ]);

  writeExecutable(sudoBin, [
    '#!/usr/bin/env bash',
    'set -euo pipefail',
    '{',
    "  printf 'sudo'",
    '  for argument in "$@"; do printf "\\t%s" "$argument"; done',
    "  printf '\\n'",
    '} >>"$NOSH_TEST_EVENT_LOG"',
    '[[ "${1-}" == "--" ]] || exit 96',
    'shift',
    'if [[ "${1-}" == "$NOSH_TEST_PRIVILEGED_GUARD" ]]; then',
    '  shift',
    '  set -- "$NOSH_TEST_NOSH_BIN" "$@"',
    'fi',
    'exec "$@"',
  ]);

  return {
    root,
    home,
    workspace,
    buildBundle,
    buildPortable,
    buildProfile,
    buildCandidateBytes,
    buildCandidateHash,
    runtimeAuthority,
    authoritativePolicy,
    runtimeMirror,
    runtimeProfile,
    runtimeReviewCandidate,
    runtimeReviewTargetContext,
    evidenceManifest,
    policyHash,
    profileHash,
    manifestHash,
    buildOutputImageDigest,
    buildConfigDigest,
    policyToolingImage,
    buildRunId,
    runtimeGuardName,
    runtimeRevision,
    eventLog,
    dockerLog,
    buildEnvironmentLog,
    buildReady,
    buildChildPid,
    staleEvidence,
    buildBin,
    dockerBin,
    noshBin,
    sudoBin,
    privilegedGuard,
    env: {
      HOME: home,
      PATH: `${bin}:${process.env.PATH}`,
      NOSH_PROFILE_BUILD_BIN: buildBin,
      NOSH_PROFILE_NOSH_BIN: noshBin,
      NOSH_PROFILE_SUDO_BIN: sudoBin,
      NOSH_GUARD_PRIVILEGED_BIN: privilegedGuard,
      NOSH_PROFILE_DOCKER_BIN: dockerBin,
      NOSH_POLICY_TOOLING_IMAGE: policyToolingImage,
      NOSH_TEST_POLICY_TOOLING_IMAGE: policyToolingImage,
      NOSH_TEST_POLICY_TOOLING_ABI: '1',
      NOSH_TEST_NODE_BIN: process.execPath,
      NOSH_TEST_EVENT_LOG: eventLog,
      NOSH_TEST_DOCKER_LOG: dockerLog,
      NOSH_TEST_BUILD_ENV_LOG: buildEnvironmentLog,
      NOSH_TEST_BUILD_READY: buildReady,
      NOSH_TEST_BUILD_CHILD_PID: buildChildPid,
      NOSH_TEST_BLOCK_BUILD: 'false',
      NOSH_TEST_BUILD_STATE: buildState,
      NOSH_TEST_BUILD_AFTER: buildAfter,
      NOSH_TEST_BUILD_RESULT: buildResult,
      NOSH_TEST_BUILD_SELECTED: buildSelected,
      NOSH_TEST_BUILD_EXIT: String(buildExit),
      NOSH_TEST_BUILD_ERROR: '',
      NOSH_TEST_RUNTIME_LEARN: runtimeLearn,
      NOSH_TEST_RUNTIME_STATUS: runtimeStatus,
      NOSH_TEST_MUTATE_BUILD_CANDIDATE: '',
      NOSH_TEST_FAIL_BROAD_STATUS: 'false',
      NOSH_TEST_FAIL_EXACT_JSON: 'false',
      NOSH_TEST_PRIVILEGED_GUARD: privilegedGuard,
      NOSH_TEST_NOSH_BIN: noshBin,
    },
    runtimeLearn,
    runtimeStatus,
    buildResult,
  };
}

function runWorkflow(fixture, args, env = {}) {
  return childProcess.spawnSync('bash', [workflowPath, ...args], {
    cwd: fixture.workspace,
    encoding: 'utf8',
    env: {
      ...fixture.env,
      ...env,
    },
  });
}

function output(result) {
  return `${result.stdout || ''}${result.stderr || ''}`;
}

function events(fixture) {
  if (!fs.existsSync(fixture.eventLog)) return [];
  return fs.readFileSync(fixture.eventLog, 'utf8').trim().split('\n');
}

function dockerEvents(fixture) {
  if (!fs.existsSync(fixture.dockerLog)) return [];
  return fs.readFileSync(fixture.dockerLog, 'utf8').trim().split('\n');
}

function findLine(text, fragment) {
  return text.split(/\r?\n/).find((line) => line.includes(fragment));
}

function waitForPath(filePath, timeoutMilliseconds = 5_000) {
  if (fs.existsSync(filePath)) return Promise.resolve();
  return new Promise((resolve, reject) => {
    let settled = false;
    const watcher = fs.watch(path.dirname(filePath), () => {
      if (fs.existsSync(filePath)) finish();
    });
    const timer = setTimeout(() => {
      finish(new Error(`timed out waiting for ${filePath}`));
    }, timeoutMilliseconds);
    function finish(error = null) {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      watcher.close();
      if (error) reject(error);
      else resolve();
    }
    if (fs.existsSync(filePath)) finish();
  });
}

test('workflow re-execs a private control snapshot before candidate execution', () => {
  const source = fs.readFileSync(workflowPath, 'utf8');
  assert.match(source, /nosh-profile-run-control\.XXXXXX/);
  assert.match(source, /NOSH_PROFILE_RUN_ORIGINAL_SCRIPT_DIR/);
  assert.match(source, /install -m 0500/);
});

test('dry run uses the default 180 second runtime profile without sudo', (t) => {
  const fixture = createFixture(t);
  const result = runWorkflow(fixture, ['--dry-run']);

  assert.equal(result.status, 0, output(result));
  assert.match(result.stdout, /== Build profile \(dry run\) ==/);
  assert.match(result.stdout, /== Runtime egress profile \(dry run\) ==/);
  assert.match(result.stdout, /--duration 180(?: |$)/m);
  assert.match(result.stdout, /No files or policies were created/);

  const recorded = events(fixture);
  assert.equal(recorded.length, 2, recorded.join('\n'));
  assert.equal(recorded[0], 'build\tprofile\t--cache-mode\tcompare\t--dry-run');
  assert.equal(
    recorded[1],
    [
      'nosh',
      'net',
      'learn',
      '--duration',
      '180',
      '--image',
      'nosh',
      '--workdir',
      fixture.workspace,
      '--no-collab',
      '--start-app',
      '--json',
      '--dry-run',
    ].join('\t'),
  );
  assert.ok(recorded.every((line) => !line.startsWith('sudo\t')));
  assert.deepEqual(dockerEvents(fixture), []);
});

test('runtime profiling has no legacy gateway-image prerequisite', (t) => {
  const fixture = createFixture(t);
  const result = runWorkflow(fixture, ['--duration', '3'], {
    NOSH_GUARD_EGRESS_IMAGE: `registry.example/obsolete@sha256:${'9'.repeat(64)}`,
  });

  assert.equal(result.status, 0, output(result));
  assert.equal(dockerEvents(fixture).length, 4);
  assert.ok(dockerEvents(fixture).every(
    (line) => line.startsWith(`run\t${fixture.policyToolingImage}\t`),
  ));
  assert.ok(events(fixture)[0].startsWith('build\tprofile\t'));
});

test('all JSON validation is delegated to isolated Docker runs, never host Node', (t) => {
  const fixture = createFixture(t);
  const forbiddenNode = path.join(fixture.root, 'forbidden host node');
  writeExecutable(forbiddenNode, [
    '#!/usr/bin/env bash',
    'printf "host Node was invoked\\n" >&2',
    'exit 94',
  ]);
  const result = runWorkflow(fixture, ['--duration', '3'], {
    NOSH_PROFILE_NODE_BIN: forbiddenNode,
  });

  assert.equal(result.status, 0, output(result));
  assert.doesNotMatch(output(result), /host Node was invoked/);
  const dockerRuns = dockerEvents(fixture);
  assert.equal(dockerRuns.length, 4, dockerRuns.join('\n'));
  assert.ok(dockerRuns.every((line) => line.includes('\t-\t')));
  assert.ok(dockerRuns.every(
    (line) => line.startsWith(`run\t${fixture.policyToolingImage}\t`),
  ));
});

test('workflow rejects missing, drifted, or ABI-incompatible policy tooling before build', (t) => {
  const fixture = createFixture(t);
  for (const override of [
    { NOSH_POLICY_TOOLING_IMAGE: '' },
    { NOSH_TEST_POLICY_TOOLING_RESOLVED_ID: `sha256:${'8'.repeat(64)}` },
    { NOSH_TEST_POLICY_TOOLING_ABI: '2' },
  ]) {
    const result = runWorkflow(fixture, ['--duration', '3'], override);
    assert.notEqual(result.status, 0);
    assert.match(output(result), /policy-tooling|NOSH_POLICY_TOOLING_IMAGE/);
    assert.ok(result.stderr.includes("export NOSH_POLICY_TOOLING_IMAGE=\"$(docker image inspect --format '{{.Id}}' nosh)\""));
    assert.match(result.stderr, /same shell/);
    assert.match(result.stderr, /\.\/scripts\/build-nosh\.sh/);
  }
  assert.deepEqual(events(fixture), []);
  assert.deepEqual(dockerEvents(fixture), []);
});

test('successful workflow orders both profiles, displays artifacts, and prints exact apply revisions', (t) => {
  const fixture = createFixture(t);
  const image = 'example/notty:profiled';
  const result = runWorkflow(fixture, [
    '--duration',
    '3',
    '--image',
    image,
    '--target',
    'cdev',
    '--cache-mode',
    'cold',
    '--workdir',
    fixture.workspace,
    '--no-start-app',
    '--',
    '--platform',
    'linux/amd64',
  ]);

  assert.equal(result.status, 0, output(result));
  assert.equal(
    fs.readFileSync(fixture.buildEnvironmentLog, 'utf8'),
    `IMAGE_NAME=${image}\nTARGET=cdev\n`,
  );

  const recorded = events(fixture);
  assert.deepEqual(recorded, [
    [
      'build', 'profile', '--cache-mode', 'cold', '--private-json',
      '--platform', 'linux/amd64',
    ].join('\t'),
    ['nosh', 'build', 'status', '--run', fixture.buildRunId, appRoot].join('\t'),
    [
      'nosh', 'build', 'status', '--run', fixture.buildRunId, '--json', appRoot,
    ].join('\t'),
    [
      'sudo', '--', fixture.privilegedGuard, 'net', 'learn', '--duration', '3',
      '--image', fixture.buildConfigDigest, '--name', fixture.runtimeGuardName,
      '--workdir', fixture.workspace, '--no-collab', '--no-start-app', '--json',
    ].join('\t'),
    [
      'nosh', 'net', 'learn', '--duration', '3', '--image', fixture.buildConfigDigest,
      '--name', fixture.runtimeGuardName, '--workdir', fixture.workspace,
      '--no-collab', '--no-start-app', '--json',
    ].join('\t'),
    [
      'sudo', '--', fixture.privilegedGuard, 'net', 'status', '--workdir',
      fixture.workspace, '--repair', '--json',
    ].join('\t'),
    [
      'nosh', 'net', 'status', '--workdir', fixture.workspace, '--repair',
      '--json',
    ].join('\t'),
  ]);

  const sectionNames = [
    '== Build profile ==',
    '== Build profile result ==',
    '== Runtime egress profile (3s) ==',
    '== Runtime profile result ==',
    '== Profile files ==',
    '== How to use them ==',
  ];
  let previousIndex = -1;
  for (const sectionName of sectionNames) {
    const currentIndex = result.stdout.indexOf(sectionName);
    assert.ok(currentIndex > previousIndex, `missing or out-of-order ${sectionName}`);
    previousIndex = currentIndex;
  }

  assert.match(result.stdout, /displayed build artifact/);
  assert.match(result.stdout, /displayed runtime artifact/);
  assert.match(result.stdout, /Version 1 build profiles are observational/);
  assert.ok(result.stdout.includes(`Build profile file: ${path.join(fixture.buildPortable, 'candidate.json')}`));
  assert.ok(result.stdout.includes(`Portable CI bundle: ${fixture.buildPortable}`));
  assert.ok(result.stdout.includes(`Authoritative runtime bundle: ${fixture.runtimeAuthority}`));
  assert.ok(result.stdout.includes(`Runtime egress policy (non-authoritative user mirror): ${fixture.runtimeProfile}`));
  assert.ok(result.stdout.includes(`Authoritative runtime policy: ${fixture.authoritativePolicy}`));
  assert.ok(result.stdout.includes(`Requested image tag: ${image}`));
  assert.ok(result.stdout.includes(`Build output digest: ${fixture.buildOutputImageDigest}`));
  assert.ok(result.stdout.includes(`Immutable local runtime image ID: ${fixture.buildConfigDigest}`));
  assert.ok(result.stdout.includes(`Unique runtime Guard name: ${fixture.runtimeGuardName}`));
  assert.ok(result.stdout.includes(`Runtime review candidate: ${fixture.runtimeReviewCandidate}`));
  assert.ok(result.stdout.includes(`Guard eBPF target context: ${fixture.runtimeReviewTargetContext}`));
  assert.match(result.stdout, /Authoritative integrity: verified/);
  assert.match(result.stdout, /Observed duration: 3025ms/);

  const auditLine = findLine(result.stdout, ' net audit ');
  const enforceLine = findLine(result.stdout, ' net enforce ');
  for (const line of [auditLine, enforceLine]) {
    assert.ok(line, output(result));
    assert.match(line, /\\ /, `path with spaces was not shell-escaped: ${line}`);
    assert.match(line, /--workdir /);
    assert.ok(line.includes(fixture.privilegedGuard));
  }
  assert.equal(
    findLine(result.stdout, `${fixture.privilegedGuard} net approve `),
    undefined,
  );
  assert.doesNotMatch(enforceLine, /--revision /);
});

test('invalid historical status cannot block or replace the direct new-build result', (t) => {
  const fixture = createFixture(t);
  const preserved = fs.readFileSync(fixture.staleEvidence);
  const result = runWorkflow(fixture, ['--duration', '3'], {
    NOSH_TEST_FAIL_BROAD_STATUS: 'true',
  });

  assert.equal(result.status, 0, output(result));
  const recorded = events(fixture);
  assert.ok(recorded.some((line) => line === [
    'build', 'profile', '--cache-mode', 'compare', '--private-json',
  ].join('\t')));
  assert.ok(recorded.some((line) => line === [
    'nosh', 'build', 'status', '--run', fixture.buildRunId, '--json', appRoot,
  ].join('\t')));
  assert.ok(recorded.every((line) =>
    !line.startsWith('nosh\tbuild\tstatus\t--json\t')));
  assert.equal(fs.readFileSync(fixture.staleEvidence).equals(preserved), true);
});

test('a failed build without private JSON preserves its error without parser noise', (t) => {
  const fixture = createFixture(t, { buildExit: 37, buildEligible: false });
  const primaryError =
    'nosh-guard: privileged build session uses an incompatible collector contract';
  fs.writeFileSync(fixture.buildResult, '');

  const result = runWorkflow(fixture, [], {
    NOSH_TEST_BUILD_ERROR: primaryError,
  });

  assert.notEqual(result.status, 0);
  assert.equal(
    result.stderr,
    `${primaryError}\n` +
      'profile-build-and-run: build profile command failed with status 37 ' +
      'before producing private JSON\n',
  );
  assert.doesNotMatch(result.stderr, /JSON\.parse|SyntaxError|node:internal/);
  assert.deepEqual(events(fixture), [
    'build\tprofile\t--cache-mode\tcompare\t--private-json',
  ]);
});

test('mismatched or non-absolute private build results fail before runtime elevation', (t) => {
  const cases = [
    {
      label: 'mismatched run identity',
      mutate(result) {
        result.manifest.runId = 'different-run';
      },
    },
    {
      label: 'relative bundle paths',
      mutate(result) {
        result.bundleDir = 'relative/build-bundle';
        result.portableBundleDir = 'relative/build-bundle/portable';
      },
    },
  ];

  for (const current of cases) {
    const fixture = createFixture(t);
    const privateResult = JSON.parse(fs.readFileSync(fixture.buildResult, 'utf8'));
    current.mutate(privateResult);
    fs.writeFileSync(fixture.buildResult, `${JSON.stringify(privateResult)}\n`);

    const result = runWorkflow(fixture, ['--duration', '3']);
    assert.notEqual(result.status, 0, current.label);
    assert.match(result.stderr, /private result for the new build profile is invalid/);
    assert.match(result.stderr, /could not validate the new build profile result/);
    const recorded = events(fixture);
    assert.equal(recorded.length, 1, `${current.label}: ${recorded.join('\n')}`);
    assert.ok(recorded[0].startsWith('build\tprofile\t'));
    assert.ok(recorded.every((line) => !line.startsWith('sudo\t')));
    assert.ok(recorded.every((line) => !line.startsWith('nosh\tnet\t')));
  }
});

test('failure to verify the exact new build JSON blocks privileged runtime learning', (t) => {
  const fixture = createFixture(t);
  const result = runWorkflow(fixture, ['--duration', '3'], {
    NOSH_TEST_FAIL_EXACT_JSON: 'true',
  });

  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /exact build profile is invalid/);
  assert.match(result.stderr, /could not read the exact successful build profile/);
  const recorded = events(fixture);
  assert.ok(recorded.includes([
    'nosh', 'build', 'status', '--run', fixture.buildRunId, '--json', appRoot,
  ].join('\t')));
  assert.ok(recorded.every((line) => !line.startsWith('sudo\t')));
  assert.ok(recorded.every((line) => !line.startsWith('nosh\tnet\t')));
});

test('runtime learning uses the build config digest instead of the mutable image tag', (t) => {
  const fixture = createFixture(t);
  const mutableTag = 'example/notty:tag-that-may-be-retargeted';
  const result = runWorkflow(fixture, [
    '--duration', '3', '--image', mutableTag,
  ]);

  assert.equal(result.status, 0, output(result));
  assert.equal(
    fs.readFileSync(fixture.buildEnvironmentLog, 'utf8'),
    `IMAGE_NAME=${mutableTag}\nTARGET=local\n`,
  );
  const runtimeLearn = events(fixture).find((line) =>
    line.startsWith(`sudo\t--\t${fixture.privilegedGuard}\tnet\tlearn\t`),
  );
  assert.ok(runtimeLearn, output(result));
  assert.match(runtimeLearn, new RegExp(`\\t--image\\t${fixture.buildConfigDigest}\\t`));
  assert.ok(!runtimeLearn.includes(mutableTag));
  assert.ok(result.stdout.includes(`Requested image tag: ${mutableTag}`));
  assert.ok(result.stdout.includes(
    `Immutable local runtime image ID: ${fixture.buildConfigDigest}`,
  ));
});

test('runtime learning failure preserves concise diagnostics without dumping the build candidate', (t) => {
  const fixture = createFixture(t);
  const primaryError =
    'nosh-guard: guard run identity is already reserved by another run';
  const partialOutput = '{"kind":"unvalidated-runtime-receipt"}';
  const result = runWorkflow(fixture, ['--duration', '3'], {
    NOSH_TEST_RUNTIME_LEARN_EXIT: '73',
    NOSH_TEST_RUNTIME_LEARN_ERROR: primaryError,
    NOSH_TEST_RUNTIME_LEARN_PARTIAL: partialOutput,
  });

  assert.notEqual(result.status, 0);
  assert.match(result.stderr, new RegExp(primaryError));
  assert.match(
    result.stderr,
    /profile-build-and-run: timed runtime profiling failed with status 73/,
  );
  assert.ok(result.stdout.includes(
    'Runtime profile: not created (command status 73)',
  ));
  assert.ok(result.stdout.includes(
    `Build profile preserved: ${fixture.buildProfile}`,
  ));
  assert.ok(result.stdout.includes(
    `Portable build evidence preserved: ${fixture.buildPortable}`,
  ));
  assert.ok(result.stdout.includes(
    `Immutable runtime image ID: ${fixture.buildConfigDigest}`,
  ));
  assert.match(
    result.stdout,
    /Unvalidated runtime command output: 39 bytes \(not displayed\)/,
  );
  assert.ok(result.stdout.includes(
    'Inspect the retained Guard failure (read-only):',
  ));
  assert.ok(result.stdout.includes(
    'Retry only the runtime phase with the loaded immutable image (no rebuild):',
  ));
  assert.ok(result.stdout.includes(
    `--image ${fixture.buildConfigDigest} --name ${fixture.runtimeGuardName}-retry`,
  ));
  assert.match(result.stdout, /--no-collab --start-app --json/);
  assert.doesNotMatch(result.stdout, /displayed build artifact/);
  assert.doesNotMatch(result.stdout, /unvalidated-runtime-receipt/);
  const recorded = events(fixture);
  assert.ok(recorded.includes([
    'sudo', '--', fixture.privilegedGuard, 'net', 'learn', '--duration', '3',
    '--image', fixture.buildConfigDigest, '--name', fixture.runtimeGuardName,
    '--workdir', fixture.workspace, '--no-collab', '--start-app', '--json',
  ].join('\t')));
  assert.ok(recorded.every((line) => !line.startsWith('nosh\tnet\tstatus\t')));
});

test('an invalid selected build image identity prevents privileged runtime learning', (t) => {
  const fixture = createFixture(t);
  const selectedPath = fixture.env.NOSH_TEST_BUILD_SELECTED;
  const selected = JSON.parse(fs.readFileSync(selectedPath, 'utf8'));
  selected.manifest.build.configDigest = 'sha256:not-an-image-id';
  fs.writeFileSync(selectedPath, `${JSON.stringify(selected)}\n`);

  const result = runWorkflow(fixture, [
    '--duration', '3', '--image', 'example/notty:mutable',
  ]);

  assert.notEqual(result.status, 0);
  assert.match(
    result.stderr,
    /could not bind runtime profiling to the exact build image and portable candidate/,
  );
  assert.ok(events(fixture).every((line) => !line.startsWith('sudo\t')));
});

test('displayed build profile is the descriptor-bound snapshot taken before runtime', (t) => {
  const fixture = createFixture(t);
  const result = runWorkflow(fixture, [
    '--duration', '3', '--image', 'example/notty:snapshot',
  ], {
    NOSH_TEST_MUTATE_BUILD_CANDIDATE: fixture.buildProfile,
  });

  assert.equal(result.status, 0, output(result));
  assert.match(result.stdout, /displayed build artifact/);
  assert.doesNotMatch(result.stdout, /mutated after snapshot/);
  assert.match(fs.readFileSync(fixture.buildProfile, 'utf8'), /mutated after snapshot/);
});

test('portable build candidate rejects symlinks and descriptor hash drift before runtime', (t) => {
  const symlinkFixture = createFixture(t);
  const symlinkTarget = path.join(symlinkFixture.root, 'build candidate target.json');
  fs.writeFileSync(symlinkTarget, symlinkFixture.buildCandidateBytes);
  fs.rmSync(symlinkFixture.buildProfile);
  fs.symlinkSync(symlinkTarget, symlinkFixture.buildProfile);

  const symlinkResult = runWorkflow(symlinkFixture, [
    '--duration', '3', '--image', 'example/notty:symlink',
  ]);
  assert.notEqual(symlinkResult.status, 0);
  assert.match(symlinkResult.stderr, /regular non-symlink file/);
  assert.ok(events(symlinkFixture).every((line) => !line.startsWith('sudo\t')));

  const hashFixture = createFixture(t);
  const changed = Buffer.from(hashFixture.buildCandidateBytes);
  changed[0] ^= 1;
  fs.writeFileSync(hashFixture.buildProfile, changed);

  const hashResult = runWorkflow(hashFixture, [
    '--duration', '3', '--image', 'example/notty:hash-drift',
  ]);
  assert.notEqual(hashResult.status, 0);
  assert.match(hashResult.stderr, /does not match its descriptor hash/);
  assert.ok(events(hashFixture).every((line) => !line.startsWith('sudo\t')));
});

test('TERM sent only to the wrapper is forwarded and the active build is reaped', async (t) => {
  const fixture = createFixture(t);
  const child = childProcess.spawn('bash', [workflowPath], {
    cwd: fixture.workspace,
    env: {
      ...fixture.env,
      NOSH_TEST_BLOCK_BUILD: 'true',
    },
    stdio: ['pipe', 'pipe', 'pipe'],
  });
  const stdout = [];
  const stderr = [];
  child.stdout.setEncoding('utf8');
  child.stderr.setEncoding('utf8');
  child.stdout.on('data', (chunk) => stdout.push(chunk));
  child.stderr.on('data', (chunk) => stderr.push(chunk));
  t.after(() => {
    child.stdin.destroy();
    if (child.exitCode === null && child.signalCode === null) {
      child.kill('SIGKILL');
    }
  });

  await waitForPath(fixture.buildReady);
  const activePid = Number(fs.readFileSync(fixture.buildChildPid, 'utf8').trim());
  assert.ok(Number.isSafeInteger(activePid) && activePid > 1);
  const closed = new Promise((resolve) => {
    child.once('close', (code, signal) => resolve({ code, signal }));
  });
  assert.equal(child.kill('SIGTERM'), true);
  const result = await closed;

  assert.deepEqual(result, { code: 143, signal: null }, [
    stdout.join(''),
    stderr.join(''),
  ].join('\n'));
  assert.ok(events(fixture).includes('build-signal\tTERM'));
  assert.throws(
    () => process.kill(activePid, 0),
    (error) => error?.code === 'ESRCH',
  );
  assert.ok(events(fixture).every((line) => !line.startsWith('sudo\t')));
});

test('a failed build displays its report and never enters the sudo runtime phase', (t) => {
  const fixture = createFixture(t, { buildExit: 37, buildEligible: false });
  const result = runWorkflow(fixture, []);

  assert.notEqual(result.status, 0);
  assert.match(result.stdout, /portable build report from fixture/);
  assert.match(
    result.stderr,
    /build profile is incomplete or the build failed; runtime profiling was not started/,
  );
  const recorded = events(fixture);
  assert.ok(recorded.some((line) => line.startsWith('build\tprofile\t')));
  assert.ok(recorded.every((line) => !line.startsWith('sudo\t')));
  assert.ok(recorded.every((line) => !line.startsWith('nosh\tnet\tlearn\t')));
});

test('authoritative status must retain the exact learned revision, directory, and launch identity', (t) => {
  const fixture = createFixture(t);
  const status = JSON.parse(fs.readFileSync(fixture.runtimeStatus, 'utf8'));
  status.latestCandidate = {
    ...status.latestCandidate,
    runId: 'concurrent-run',
    revision: 'concurrent-run',
  };
  status.lastLaunch = {
    ...status.lastLaunch,
    runId: 'concurrent-run',
    revision: 'concurrent-run',
  };
  fs.writeFileSync(fixture.runtimeStatus, `${JSON.stringify(status)}\n`);

  const result = runWorkflow(fixture, [
    '--duration', '3', '--image', 'example/notty:profiled',
  ]);

  assert.notEqual(result.status, 0);
  assert.match(
    result.stderr,
    /authoritative runtime status does not match the exact learn receipt/,
  );
  assert.match(
    result.stderr,
    /runtime profile identity changed or failed authoritative verification/,
  );
  assert.doesNotMatch(result.stdout, /displayed runtime artifact/);
});

test('the returned mirror policy must remain a regular non-symlink with the learned digest', (t) => {
  const symlinkFixture = createFixture(t);
  const symlinkTarget = path.join(symlinkFixture.root, 'replacement policy.json');
  fs.writeFileSync(
    symlinkTarget,
    '{"kind":"runtime-egress-policy","marker":"displayed runtime artifact"}\n',
  );
  fs.rmSync(symlinkFixture.runtimeProfile);
  fs.symlinkSync(symlinkTarget, symlinkFixture.runtimeProfile);

  const symlinkResult = runWorkflow(symlinkFixture, [
    '--duration', '3', '--image', 'example/notty:profiled',
  ]);
  assert.notEqual(symlinkResult.status, 0);
  assert.match(symlinkResult.stderr, /regular non-symlink file/);
  assert.doesNotMatch(symlinkResult.stdout, /displayed runtime artifact/);

  const digestFixture = createFixture(t);
  fs.writeFileSync(
    digestFixture.runtimeProfile,
    '{"kind":"runtime-egress-policy","marker":"replaced after learning"}\n',
  );
  const digestResult = runWorkflow(digestFixture, [
    '--duration', '3', '--image', 'example/notty:profiled',
  ]);
  assert.notEqual(digestResult.status, 0);
  assert.match(digestResult.stderr, /does not match policyHash/);
  assert.doesNotMatch(digestResult.stdout, /replaced after learning/);
});

test('invalid workflow and reserved build options fail before delegation', (t) => {
  const fixture = createFixture(t);
  const cases = [
    [['--duration', '0'], /--duration must be an integer from 1 to 86400/],
    [['--duration=86401'], /--duration must be an integer from 1 to 86400/],
    [['--duration', '1', '--duration=2'], /--duration may be specified only once/],
    [['--cache-mode', 'sometimes'], /--cache-mode must be compare, cold, or warm/],
    [['--workdir', path.join(fixture.root, 'missing workdir')], /runtime workdir is not a directory/],
    [['--unknown'], /unknown option: --unknown/],
    [['--', '--push'], /--push is controlled by the combined profiling workflow/],
    [['--', '--output=type=local,dest=out'], /--output=type=local,dest=out is controlled/],
    [['--', '-olocal'], /-olocal is controlled/],
    [['--', '--load'], /--load is controlled/],
    [['--', '--private-json'], /--private-json is controlled/],
    [['--', '--cache-mode=warm'], /--cache-mode=warm is controlled/],
  ];

  for (const [args, expected] of cases) {
    fs.rmSync(fixture.eventLog, { force: true });
    const result = runWorkflow(fixture, args);
    assert.notEqual(result.status, 0, `${args.join(' ')} unexpectedly succeeded`);
    assert.match(output(result), expected);
    assert.deepEqual(events(fixture), [], `delegated invalid case: ${args.join(' ')}`);
  }
});
