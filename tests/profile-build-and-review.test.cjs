'use strict';

const assert = require('node:assert/strict');
const childProcess = require('node:child_process');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const test = require('node:test');

const appRoot = path.resolve(__dirname, '..');
const wrapper = path.join(appRoot, 'profile-build-and-review.sh');

const uiContainerId = '1'.repeat(64);
const graphContainerId = '2'.repeat(64);
const graphDigest = `sha256:${'3'.repeat(64)}`;
const graphContentDigest = `sha256:${'4'.repeat(64)}`;
const networkId = '5'.repeat(64);
const foreignContainerId = '6'.repeat(64);
const graphToken = '8'.repeat(64);
const uiAddress = '172.29.7.11';
const graphAddress = '172.29.7.23';
const graphPort = '8765';

function executable(file, source) {
  fs.writeFileSync(file, `${source}\n`, { mode: 0o755 });
}

function fixture(t) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'notty profile review '));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const bin = path.join(root, 'bin');
  const workdir = path.join(root, 'workspace');
  const buildRoot = path.join(root, 'build-store');
  const buildProfile = path.join(buildRoot, 'project', 'profile-1');
  const runtimeRoot = path.join(root, 'runtime-store');
  const runtimeCandidate = path.join(runtimeRoot, 'workspace-key', 'revision-1');
  const targetContext = path.join(runtimeCandidate, 'guard-ebpf-target-context.json');
  const reviewRoot = path.join(root, 'review-state');
  const dockerState = path.join(root, 'fake-docker-state');
  const log = path.join(root, 'events.log');
  const policyToolingImage = `sha256:${'9'.repeat(64)}`;
  const policyReviewUiImage = `sha256:${'7'.repeat(64)}`;
  for (const directory of [
    bin,
    workdir,
    buildProfile,
    runtimeCandidate,
    reviewRoot,
    dockerState,
  ]) {
    fs.mkdirSync(directory, { recursive: true, mode: 0o700 });
    fs.chmodSync(directory, 0o700);
  }
  fs.writeFileSync(
    path.join(buildProfile, 'evidence-manifest.json'),
    '{"kind":"NoshBuildProfileEvidence","complete":false}\n',
    { mode: 0o600 },
  );
  fs.writeFileSync(targetContext, '{"kind":"NoshGuardEbpfTargetContext"}\n', {
    mode: 0o600,
  });
  for (const [name, contents] of [
    ['egress-profile.json', '{"kind":"NoshRuntimeEgressProfile"}\n'],
    ['egress-policy.json', '{"kind":"NoshRuntimeEgressPolicy"}\n'],
    ['manifest.json', '{"kind":"NoshRuntimeReviewManifest"}\n'],
  ]) {
    fs.writeFileSync(path.join(runtimeCandidate, name), contents, { mode: 0o600 });
  }

  const profile = path.join(bin, 'profile');
  executable(profile, [
    '#!/usr/bin/env bash',
    'set -euo pipefail',
    'printf "profile\\t" >>"$TEST_LOG"',
    'printf "%q " "$@" >>"$TEST_LOG"',
    'printf "\\n" >>"$TEST_LOG"',
    'printf "%s\\n" \\',
    '  "Nosh build profile: profile-1" \\',
    '  "Private bundle: $TEST_BUILD_PROFILE" \\',
    '  "Immutable local runtime image ID: sha256:${TEST_IMAGE_HEX}" \\',
    '  "Runtime review candidate: $TEST_RUNTIME_CANDIDATE" \\',
    '  "Guard eBPF target context: $TEST_TARGET_CONTEXT"',
    'exit "${TEST_PROFILE_STATUS:-0}"',
  ].join('\n'));

  const docker = path.join(bin, 'docker');
  executable(docker, [
    '#!/usr/bin/env node',
    "'use strict';",
    "const fs = require('node:fs');",
    "const path = require('node:path');",
    'const args = process.argv.slice(2);',
    'const env = process.env;',
    "const stateFile = path.join(env.TEST_DOCKER_STATE, 'state.json');",
    'let state = { network: null, ui: null, graph: null };',
    'if (fs.existsSync(stateFile)) {',
    "  state = JSON.parse(fs.readFileSync(stateFile, 'utf8'));",
    '}',
    'function save() {',
    "  fs.writeFileSync(stateFile, `${JSON.stringify(state)}\\n`, { mode: 0o600 });",
    '  fs.chmodSync(stateFile, 0o600);',
    '}',
    'function write(value) {',
    "  process.stdout.write(`${value}\\n`);",
    '}',
    'function fail(status = 1) {',
    '  process.exit(status);',
    '}',
    'function has(value) {',
    '  return args.includes(value);',
    '}',
    'function after(value) {',
    '  const index = args.indexOf(value);',
    "  return index >= 0 ? (args[index + 1] || '') : '';",
    '}',
    'function labels() {',
    '  const result = {};',
    '  for (let index = 0; index < args.length - 1; index += 1) {',
    "    if (args[index] !== '--label') continue;",
    "    const [key, ...rest] = args[index + 1].split('=');",
    "    result[key] = rest.join('=');",
    '  }',
    '  return result;',
    '}',
    'function record() {',
    "  fs.appendFileSync(env.TEST_LOG, `docker\\t${args.join('\\t')}\\n`);",
    '}',
    'function exactImage(requested, failName, resolvedName, abiName) {',
    "  if (env[failName] === 'true') fail();",
    "  write(`${env[resolvedName] || requested}|${env[abiName] || '1'}`);",
    '}',
    "if (args[0] === 'image' && args[1] === 'inspect') {",
    '  const requested = args.at(-1);',
    '  if (requested === env.TEST_TOOLING_IMAGE) {',
    "    exactImage(requested, 'TEST_TOOLING_INSPECT_FAIL', 'TEST_TOOLING_RESOLVED_ID', 'TEST_TOOLING_ABI');",
    '  } else if (requested === env.TEST_UI_IMAGE) {',
    "    exactImage(requested, 'TEST_UI_INSPECT_FAIL', 'TEST_UI_RESOLVED_ID', 'TEST_UI_ABI');",
    '  } else {',
    '    fail(98);',
    '  }',
    '  process.exit(0);',
    '}',
    'record();',
    "if (args[0] === 'run') {",
    "  if (!has('--detach')) {",
    "    if (has('/app/scripts/nosh-policy-session.mjs')) {",
    "      const directory = path.join(after('--session'), 'runtime');",
    "      fs.writeFileSync(path.join(directory, 'review-session.json'), '{}', { mode: 0o600 });",
    "      fs.writeFileSync(path.join(directory, 'review.graph.json'), '{}', { mode: 0o600 });",
    "      write('{}'); process.exit(0);",
    '    }',
    "    if (!has('review') || (!has('bundle') && !has('inspect'))) fail(97);",
    "    const output = after('--output');",
    '    if (output) {',
    '      fs.mkdirSync(output, { recursive: true, mode: 0o700 });',
    '      fs.chmodSync(output, 0o700);',
    "      fs.writeFileSync(path.join(output, 'graph.marker'), 'frozen\\n', { mode: 0o600 });",
    '    }',
    "    write('{');",
    "    write(`  \\\"graphDigest\\\": \\\"${env.TEST_GRAPH_DIGEST}\\\",`);",
    "    write(`  \\\"graphContentDigest\\\": \\\"${env.TEST_GRAPH_CONTENT_DIGEST}\\\"`);",
    "    write('}');",
    "    process.exit(Number(env.TEST_REVIEW_STATUS || '0'));",
    '  }',
    '  const selectedLabels = labels();',
    "  const component = selectedLabels['io.notty.policy-review.component'];",
    "  if (component === 'ui' && env.TEST_UI_CREATE_FAIL === 'true') fail(75);",
    "  if (component === 'graph' && env.TEST_GRAPH_CREATE_FAIL === 'true') fail(76);",
    "  if (component !== 'ui' && component !== 'graph') fail(97);",
    '  const selected = {',
    "    id: component === 'ui' ? env.TEST_UI_ID : env.TEST_GRAPH_ID,",
    "    name: after('--name'),",
    "    network: after('--network'),",
    "    image: component === 'ui' ? env.TEST_UI_IMAGE : env.TEST_TOOLING_IMAGE,",
    '    labels: selectedLabels,',
    "    ip: component === 'ui' ? env.TEST_UI_IP : env.TEST_GRAPH_IP,",
    '  };',
    '  state[component] = selected;',
    '  save();',
    '  write(selected.id);',
    '  process.exit(0);',
    '}',
    "if (args[0] === 'network') {",
    "  if (args[1] === 'create') {",
    '    const selectedLabels = labels();',
    '    state.network = {',
    '      id: env.TEST_NETWORK_ID,',
    '      name: args.at(-1),',
    "      driver: after('--driver'),",
    "      internal: has('--internal'),",
    '      labels: selectedLabels,',
    '    };',
    '    save();',
    '    write(state.network.id);',
    '    process.exit(0);',
    '  }',
    "  if (args[1] !== 'inspect' || !state.network) fail(94);",
    '  const target = args.at(-1);',
    '  if (target !== state.network.name && target !== state.network.id) fail(94);',
    "  const format = after('--format');",
    "  if (format === '{{.Id}}') {",
    '    write(env.TEST_FOUND_NETWORK_ID || state.network.id);',
    '    process.exit(0);',
    '  }',
    '  const selectedLabels = state.network.labels;',
    '  write([',
    '    env.TEST_NETWORK_ATTESTED_ID || state.network.id,',
    '    state.network.name,',
    "    env.TEST_NETWORK_DRIVER_ATTESTATION || state.network.driver || 'bridge',",
    "    env.TEST_NETWORK_INTERNAL_ATTESTATION || String(state.network.internal),",
    "    env.TEST_NETWORK_MANAGED_ATTESTATION || selectedLabels['io.notty.policy-review.managed'],",
    "    env.TEST_NETWORK_COMPONENT_ATTESTATION || selectedLabels['io.notty.policy-review.component'],",
    "    env.TEST_NETWORK_PROFILE_ATTESTATION || selectedLabels['io.notty.policy-review.profile'],",
    "    env.TEST_NETWORK_EVIDENCE_ATTESTATION || selectedLabels['io.notty.policy-review.profile-evidence-digest'],",
    "    env.TEST_NETWORK_GRAPH_ATTESTATION || selectedLabels['io.notty.policy-review.graph-digest'],",
    "    env.TEST_NETWORK_CONTENT_ATTESTATION || selectedLabels['io.notty.policy-review.graph-content-digest'],",
    "  ].join('|'));",
    '  process.exit(0);',
    '}',
    "if (args[0] === 'inspect') {",
    "  const format = after('--format');",
    '  const target = args.at(-1);',
    "  if (format === '{{.Id}}') {",
    '    if (state.ui && target === state.ui.name) write(env.TEST_FOUND_UI_ID || state.ui.id);',
    '    else if (state.graph && target === state.graph.name) write(env.TEST_FOUND_GRAPH_ID || state.graph.id);',
    '    else fail(96);',
    '    process.exit(0);',
    '  }',
    '  let selected = null;',
    "  let component = '';",
    '  if (state.ui && (target === state.ui.id || target === state.ui.name)) {',
    '    selected = state.ui;',
    "    component = 'ui';",
    '  } else if (state.graph && (target === state.graph.id || target === state.graph.name)) {',
    '    selected = state.graph;',
    "    component = 'graph';",
    '  } else {',
    '    fail(96);',
    '  }',
    "  const prefix = component === 'ui' ? 'TEST_UI_' : 'TEST_GRAPH_';",
    "  if (format.includes('io.notty.policy-review.ui-origin')) {",
    "    write(env.TEST_GRAPH_ORIGIN_ATTESTATION || selected.labels['io.notty.policy-review.ui-origin'] || '');",
    '    process.exit(0);',
    '  }',
    "  if (format.includes('io.notty.policy-review.profile-evidence-digest')) {",
    '    write([',
    "      env[`${prefix}CONTAINER_ID_ATTESTATION`] || selected.id,",
    "      env[`${prefix}IMAGE_ATTESTATION`] || selected.image,",
    "      env[`${prefix}MANAGED_ATTESTATION`] || selected.labels['io.notty.policy-review.managed'],",
    "      env[`${prefix}COMPONENT_ATTESTATION`] || selected.labels['io.notty.policy-review.component'],",
    "      env[`${prefix}PROFILE_ATTESTATION`] || selected.labels['io.notty.policy-review.profile'],",
    "      env[`${prefix}EVIDENCE_ATTESTATION`] || selected.labels['io.notty.policy-review.profile-evidence-digest'],",
    "      env[`${prefix}GRAPH_ATTESTATION`] || selected.labels['io.notty.policy-review.graph-digest'],",
    "      env[`${prefix}CONTENT_ATTESTATION`] || selected.labels['io.notty.policy-review.graph-content-digest'],",
    "      `/${selected.name}`,",
    "      env[`${prefix}RUNNING_ATTESTATION`] || 'true',",
    "    ].join('|'));",
    '    process.exit(0);',
    '  }',
    "  if (format.includes('NetworkSettings.Networks')) {",
    '    const attachedNetwork = state.network;',
    "    if (!attachedNetwork || selected.network !== attachedNetwork.name) fail(95);",
    "    write(`1|${env[`${prefix}NETWORK_ID_ATTESTATION`] || attachedNetwork.id}|${env[`${prefix}IP_ATTESTATION`] || selected.ip}`);",
    '    process.exit(0);',
    '  }',
    "  if (format.includes('.State.Health')) {",
    "    write(env.TEST_UI_HEALTH || 'healthy');",
    '    process.exit(0);',
    '  }',
    "  if (format.includes('.State.Running')) {",
    "    write(env[`${prefix}STATE_RUNNING`] || 'true');",
    '    process.exit(0);',
    '  }',
    '  fail(95);',
    '}',
    "if (args[0] === 'logs') {",
    '  const target = args.at(-1);',
    '  if (state.graph && (target === state.graph.id || target === state.graph.name)) {',
    "    write(`Nosh policy review graph: http://${env.TEST_GRAPH_LOG_IP || state.graph.ip}:${env.TEST_GRAPH_PORT}/v1/graph/${env.TEST_GRAPH_TOKEN}`);",
    '  } else if (state.ui && (target === state.ui.id || target === state.ui.name)) {',
    "    write('Policy Review UI log');",
    '  } else {',
    '    fail(95);',
    '  }',
    '  process.exit(0);',
    '}',
    "if (args[0] === 'stop') {",
    '  process.exit(0);',
    '}',
    "process.stderr.write(`unexpected fake Docker command: ${args.join(' ')}\\n`);",
    'fail(97);',
  ].join('\n'));

  const xdg = path.join(bin, 'xdg-open');
  executable(xdg, [
    '#!/usr/bin/env bash',
    'set -euo pipefail',
    'printf "xdg\\t%s\\n" "$1" >>"$TEST_LOG"',
    'exit "${TEST_XDG_STATUS:-0}"',
  ].join('\n'));

  return {
    root,
    workdir,
    buildProfile,
    runtimeCandidate,
    targetContext,
    reviewRoot,
    dockerState,
    log,
    profile,
    docker,
    xdg,
    policyToolingImage,
    policyReviewUiImage,
    env: {
      ...process.env,
      HOME: root,
      PATH: `${bin}:${process.env.PATH}`,
      TEST_LOG: log,
      TEST_DOCKER_STATE: dockerState,
      TEST_BUILD_PROFILE: buildProfile,
      TEST_RUNTIME_CANDIDATE: runtimeCandidate,
      TEST_TARGET_CONTEXT: targetContext,
      TEST_IMAGE_HEX: 'a'.repeat(64),
      TEST_TOOLING_IMAGE: policyToolingImage,
      TEST_TOOLING_ABI: '1',
      TEST_UI_IMAGE: policyReviewUiImage,
      TEST_UI_ABI: '1',
      TEST_UI_ID: uiContainerId,
      TEST_GRAPH_ID: graphContainerId,
      TEST_NETWORK_ID: networkId,
      TEST_GRAPH_DIGEST: graphDigest,
      TEST_GRAPH_CONTENT_DIGEST: graphContentDigest,
      TEST_GRAPH_TOKEN: graphToken,
      TEST_UI_IP: uiAddress,
      TEST_GRAPH_IP: graphAddress,
      TEST_GRAPH_PORT: graphPort,
      NOSH_POLICY_TOOLING_IMAGE: policyToolingImage,
      NOSH_POLICY_REVIEW_UI_IMAGE: policyReviewUiImage,
      NOSH_PROFILE_REVIEW_PROFILE_BIN: profile,
      NOSH_PROFILE_REVIEW_DOCKER_BIN: docker,
      NOSH_PROFILE_REVIEW_XDG_OPEN_BIN: xdg,
      NOSH_PROFILE_REVIEW_WORKDIR: workdir,
      NOSH_PROFILE_REVIEW_STATE_ROOT: reviewRoot,
    },
  };
}

function launch(selected, args = [], overrides = {}) {
  return childProcess.spawnSync('bash', [wrapper, ...args], {
    cwd: selected.workdir,
    encoding: 'utf8',
    env: { ...selected.env, ...overrides },
  });
}

function outputOf(result) {
  return `${result.stdout || ''}${result.stderr || ''}`;
}

function eventsOf(selected) {
  if (!fs.existsSync(selected.log)) return [];
  return fs.readFileSync(selected.log, 'utf8').trim().split('\n').filter(Boolean);
}

function escaped(value) {
  return value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

function expectedGraphUrl() {
  return `http://${graphAddress}:${graphPort}/v1/graph/${graphToken}`;
}

function expectedOpenUrl() {
  const encoded = expectedGraphUrl()
    .replaceAll('%', '%25')
    .replaceAll(':', '%3A')
    .replaceAll('/', '%2F');
  return `http://${uiAddress}:3000/policy-review?graph=${encoded}`;
}

function onlySession(selected) {
  const entries = fs.readdirSync(selected.reviewRoot, { withFileTypes: true })
    .filter((entry) => entry.isDirectory());
  assert.equal(entries.length, 1, entries.map((entry) => entry.name).join('\n'));
  return path.join(selected.reviewRoot, entries[0].name);
}

function fileMode(file) {
  return fs.statSync(file).mode & 0o777;
}

test('review orchestrator re-execs a private, syntax-valid control snapshot', () => {
  const source = fs.readFileSync(wrapper, 'utf8');
  assert.match(source, /nosh-profile-review-control\.XXXXXX/);
  assert.match(source, /NOSH_PROFILE_REVIEW_ORIGINAL_SCRIPT_DIR/);
  assert.match(source, /install -m 0500/);
  const syntax = childProcess.spawnSync('bash', ['-n', wrapper], { encoding: 'utf8' });
  assert.equal(syntax.status, 0, outputOf(syntax));
});

test('materializes and serves a review on distinct discovered bridge addresses', (t) => {
  const selected = fixture(t);
  const result = launch(selected, ['--cache-mode', 'cold']);
  const output = outputOf(result);
  assert.equal(result.status, 0, output);

  const events = eventsOf(selected);
  assert.match(events[0], /^profile\t/);
  const dockerRuns = events.filter((line) => line.startsWith('docker\trun\t'));
  assert.equal(dockerRuns.length, 4, events.join('\n'));
  const bundleRun = dockerRuns.find((line) => /\treview\tbundle\t/.test(line));
  assert.ok(bundleRun.includes(`type=bind,src=${selected.workdir},dst=${selected.workdir},readonly`));
  const uiRun = dockerRuns.find((line) => line.includes('\tio.notty.policy-review.component=ui\t'));
  const graphRun = dockerRuns.find((line) => line.includes('\tio.notty.policy-review.component=graph\t'));
  assert.ok(bundleRun);
  assert.ok(uiRun);
  assert.ok(graphRun);
  assert.match(bundleRun, /\t--entrypoint\t\/usr\/local\/bin\/node\t/);
  assert.match(bundleRun, /\t--network\tnone\t/);
  assert.match(bundleRun, new RegExp(`\\t${escaped(selected.policyToolingImage)}\\t`));
  assert.match(bundleRun, /\t--runtime-candidate\t/);
  assert.doesNotMatch(bundleRun, /--allow-missing-sbom/);
  assert.match(uiRun, /\t--detach\t/);
  assert.match(uiRun, new RegExp('\\t--network\\tnosh-review-[^\\t]+'));
  assert.match(uiRun, new RegExp(`\\t${escaped(selected.policyReviewUiImage)}$`));
  assert.doesNotMatch(uiRun, /\t--publish\t/);
  assert.match(graphRun, /\t--detach\t/);
  assert.match(graphRun, new RegExp(`\\t${escaped(selected.policyToolingImage)}\\t`));
  assert.match(graphRun, /\treview\tserve\t/);
  assert.match(
    graphRun,
    new RegExp(`\\t--label\\tio\\.notty\\.policy-review\\.ui-origin=http://${escaped(uiAddress)}:3000\\t`),
  );
  assert.match(graphRun, new RegExp(`\\t--origin\\thttp://${escaped(uiAddress)}:3000$`));
  assert.ok(dockerRuns.every((line) => !line.includes(`sha256:${'a'.repeat(64)}`)));

  const networkCreate = events.find((line) => line.startsWith('docker\tnetwork\tcreate\t'));
  assert.ok(networkCreate);
  assert.match(networkCreate, /\t--driver\tbridge\t--internal\t/);
  assert.match(networkCreate, /\tio\.notty\.policy-review\.component=network\t/);
  assert.ok(events.some((line) => line.startsWith('docker\tnetwork\tinspect\t')));

  const openUrl = expectedOpenUrl();
  assert.ok(output.includes(`\x1b]8;;${openUrl}\x1b\\Open Policy Review\x1b]8;;\x1b\\`));
  assert.match(output, new RegExp(`Policy Review: ${escaped(openUrl)}`));
  assert.match(output, new RegExp(`Graph URL: ${escaped(expectedGraphUrl())}`));
  assert.doesNotMatch(output, /127\.0\.0\.1/);
  assert.doesNotMatch(events.join('\n'), /127\.0\.0\.1/);
  assert.equal(events.find((line) => line.startsWith('xdg\t')), `xdg\t${openUrl}`);

  const session = onlySession(selected);
  const attestation = JSON.parse(fs.readFileSync(
    path.join(session, 'runtime', 'policy-review-attestation.json'),
    'utf8',
  ));
  assert.deepEqual(attestation, {
    schemaVersion: 1,
    uiOrigin: `http://${uiAddress}:3000`,
    graphOrigin: `http://${graphAddress}:${graphPort}`,
  });
  assert.match(output, new RegExp(escaped(graphDigest)));
  assert.match(output, /Review every proposal and coverage finding/);
});

test('loads approved service image IDs from the private setup configuration', (t) => {
  const selected = fixture(t);
  const imageConfig = path.join(selected.root, 'policy-review-images.conf');
  fs.writeFileSync(imageConfig, [
    'SCHEMA_VERSION=1',
    `NOSH_POLICY_TOOLING_IMAGE=${selected.policyToolingImage}`,
    `NOSH_POLICY_REVIEW_UI_IMAGE=${selected.policyReviewUiImage}`,
    '',
  ].join('\n'), { mode: 0o600 });
  const result = launch(selected, ['--cache-mode', 'cold'], {
    NOSH_POLICY_TOOLING_IMAGE: '',
    NOSH_POLICY_REVIEW_UI_IMAGE: '',
    NOSH_PROFILE_REVIEW_IMAGE_CONFIG: imageConfig,
  });
  assert.equal(result.status, 0, outputOf(result));
  assert.match(outputOf(result), /Policy Review: http:\/\/172\.29\.7\.11:3000/);
});

test('an existing incomplete profile remains reviewable when bundle exits 2', (t) => {
  const selected = fixture(t);
  const result = launch(
    selected,
    ['--build-profile', selected.buildProfile],
    { TEST_REVIEW_STATUS: '2' },
  );
  const output = outputOf(result);
  assert.equal(result.status, 0, output);
  const events = eventsOf(selected);
  assert.ok(events.every((line) => !line.startsWith('profile\t')));
  const bundleRun = events.find((line) => /\treview\tbundle\t/.test(line));
  assert.ok(bundleRun);
  assert.match(bundleRun, /\t--allow-missing-sbom(?:\t|$)/);
  assert.doesNotMatch(bundleRun, /\t--runtime-candidate\t/);
  assert.match(output, /blocking coverage\/findings; it is reviewable but cannot yet be activated/);
  assert.match(output, new RegExp(`Policy Review: ${escaped(expectedOpenUrl())}`));
  assert.ok(events.some((line) => line === `xdg\t${expectedOpenUrl()}`));
});

test('browser launch success, failure, and absence never invalidate review evidence', (t) => {
  const succeeded = fixture(t);
  const successResult = launch(succeeded);
  assert.equal(successResult.status, 0, outputOf(successResult));
  assert.ok(eventsOf(succeeded).includes(`xdg\t${expectedOpenUrl()}`));

  const failed = fixture(t);
  const failedResult = launch(failed, [], { TEST_XDG_STATUS: '9' });
  assert.equal(failedResult.status, 0, outputOf(failedResult));
  assert.match(outputOf(failedResult), /xdg-open could not launch the browser/);
  assert.ok(eventsOf(failed).includes(`xdg\t${expectedOpenUrl()}`));

  const missing = fixture(t);
  const missingResult = launch(missing, [], {
    NOSH_PROFILE_REVIEW_XDG_OPEN_BIN: path.join(missing.root, 'missing-xdg-open'),
  });
  assert.equal(missingResult.status, 0, outputOf(missingResult));
  assert.match(outputOf(missingResult), /xdg-open is unavailable/);
  assert.ok(eventsOf(missing).every((line) => !line.startsWith('xdg\t')));
  assert.ok(fs.existsSync(path.join(onlySession(missing), 'services.state')));
});

test('persists review directories as 0700 and private identity files as 0600', (t) => {
  const selected = fixture(t);
  const result = launch(selected);
  assert.equal(result.status, 0, outputOf(result));
  const session = onlySession(selected);
  for (const directory of [
    selected.reviewRoot,
    session,
    path.join(session, 'runtime'),
    path.join(session, 'bundle'),
  ]) {
    assert.equal(fileMode(directory), 0o700, directory);
  }
  for (const file of [
    path.join(session, 'profile.state'),
    path.join(session, 'services.state'),
    path.join(session, 'runtime', 'policy-review-attestation.json'),
    path.join(session, 'bundle', 'graph.marker'),
  ]) {
    assert.equal(fileMode(file), 0o600, file);
  }
});

test('reuses only the attested network, containers, graph, and token', (t) => {
  const selected = fixture(t);
  const first = launch(selected, ['--cache-mode', 'cold']);
  assert.equal(first.status, 0, outputOf(first));
  const firstEvents = eventsOf(selected);
  assert.equal(firstEvents.filter((line) => line.startsWith('docker\trun\t--detach\t')).length, 2);
  assert.equal(firstEvents.filter((line) => line.startsWith('docker\tnetwork\tcreate\t')).length, 1);

  const second = launch(selected, ['--cache-mode', 'cold']);
  const output = outputOf(second);
  assert.equal(second.status, 0, output);
  const allEvents = eventsOf(selected);
  assert.equal(allEvents.filter((line) => line.startsWith('docker\trun\t--detach\t')).length, 2);
  assert.equal(allEvents.filter((line) => line.startsWith('docker\tnetwork\tcreate\t')).length, 1);
  assert.equal(allEvents.filter((line) => /\treview\tbundle\t/.test(line)).length, 1);
  assert.equal(allEvents.filter((line) => /\treview\tinspect\t/.test(line)).length, 1);
  assert.equal(allEvents.filter((line) => line === `xdg\t${expectedOpenUrl()}`).length, 2);
  assert.match(output, /Verifying persisted frozen review bundle/);
  assert.match(output, /Reusing attested Policy Review UI/);
  assert.match(output, /Reusing attested tokenized review graph server/);
  assert.match(output, new RegExp(`Policy Review: ${escaped(expectedOpenUrl())}`));
});

test('rejects stale or foreign named containers without stopping them', (t) => {
  const stale = fixture(t);
  const staleFirst = launch(stale);
  assert.equal(staleFirst.status, 0, outputOf(staleFirst));
  const staleResult = launch(stale, [], { TEST_UI_PROFILE_ATTESTATION: 'other-profile' });
  assert.notEqual(staleResult.status, 0);
  assert.match(
    outputOf(staleResult),
    /running Policy Review UI failed profile, graph, image, network, or identity attestation/,
  );
  assert.ok(eventsOf(stale).every((line) => !line.startsWith('docker\tstop\t')));

  const foreign = fixture(t);
  const foreignFirst = launch(foreign);
  assert.equal(foreignFirst.status, 0, outputOf(foreignFirst));
  const foreignResult = launch(foreign, [], { TEST_FOUND_GRAPH_ID: foreignContainerId });
  assert.notEqual(foreignResult.status, 0);
  assert.match(outputOf(foreignResult), /review graph container identity changed; refusing foreign or stale reuse/);
  const foreignEvents = eventsOf(foreign);
  assert.ok(foreignEvents.every((line) => !line.startsWith('docker\tstop\t')));
  assert.ok(fs.existsSync(path.join(foreign.dockerState, 'state.json')));
});

test('missing-SBOM coverage downgrade is explicit and forwarded only to bundle', (t) => {
  const selected = fixture(t);
  const result = launch(selected, ['--allow-missing-sbom', '--cache-mode', 'cold']);
  const output = outputOf(result);
  assert.equal(result.status, 0, output);
  assert.match(output, /explicit missing-SBOM coverage downgrade requested/);
  const events = eventsOf(selected);
  assert.doesNotMatch(events[0], /allow-missing-sbom/);
  const dockerRuns = events.filter((line) => line.startsWith('docker\trun\t'));
  assert.match(dockerRuns[0], /\t--allow-missing-sbom(?:\t|$)/);
  assert.doesNotMatch(dockerRuns[1], /allow-missing-sbom/);
  assert.doesNotMatch(dockerRuns[2], /allow-missing-sbom/);
});

test('reviewed source and image SBOMs are mounted read-only and never passed to profiling', (t) => {
  const selected = fixture(t);
  const sourceSbom = path.join(selected.root, 'source.spdx.json');
  const imageSbom = path.join(selected.root, 'image.spdx.json');
  fs.writeFileSync(sourceSbom, '{"spdxVersion":"SPDX-2.3"}\n');
  fs.writeFileSync(imageSbom, '{"spdxVersion":"SPDX-2.3"}\n');
  const result = launch(selected, [
    '--sbom-source', sourceSbom,
    `--sbom-image=${imageSbom}`,
    '--cache-mode', 'cold',
  ]);
  const output = outputOf(result);
  assert.equal(result.status, 0, output);
  const events = eventsOf(selected);
  assert.doesNotMatch(events[0], /sbom-(?:source|image)/);
  const bundleRun = events.find((line) => /\treview\tbundle\t/.test(line));
  assert.doesNotMatch(bundleRun, new RegExp(escaped(sourceSbom)));
  assert.match(bundleRun, /src=\/tmp\/nosh-profile-review\.[^,]+\/source\.spdx\.json,dst=\/tmp\/nosh-profile-review\.[^,]+\/source\.spdx\.json,readonly/);
  assert.match(bundleRun, /src=\/tmp\/nosh-profile-review\.[^,]+\/image\.spdx\.json,dst=\/tmp\/nosh-profile-review\.[^,]+\/image\.spdx\.json,readonly/);
  assert.match(bundleRun, /\t--sbom-source\t/);
  assert.match(bundleRun, /\t--sbom-image\t/);
});

test('rejects mutable or ABI-incompatible policy tooling before profiling', (t) => {
  const selected = fixture(t);
  for (const override of [
    { NOSH_POLICY_TOOLING_IMAGE: 'nosh:latest' },
    { TEST_TOOLING_RESOLVED_ID: `sha256:${'8'.repeat(64)}` },
    { TEST_TOOLING_ABI: '2' },
  ]) {
    const result = launch(selected, [], override);
    assert.notEqual(result.status, 0);
    assert.match(outputOf(result), /policy-tooling|NOSH_POLICY_TOOLING_IMAGE/);
  }
  assert.equal(fs.existsSync(selected.log), false);
});

test('rejects mutable or ABI-incompatible Policy Review UI before profiling', (t) => {
  const selected = fixture(t);
  for (const override of [
    { NOSH_POLICY_REVIEW_UI_IMAGE: 'policy-review:latest' },
    { TEST_UI_RESOLVED_ID: `sha256:${'6'.repeat(64)}` },
    { TEST_UI_ABI: '2' },
  ]) {
    const result = launch(selected, [], override);
    assert.notEqual(result.status, 0);
    assert.match(outputOf(result), /Policy Review UI|NOSH_POLICY_REVIEW_UI_IMAGE/);
  }
  assert.equal(fs.existsSync(selected.log), false);
});

test('rejects warm-only evidence before invoking the profile workflow', (t) => {
  const selected = fixture(t);
  const result = launch(selected, ['--cache-mode=warm']);
  assert.equal(result.status, 1);
  assert.match(result.stderr, /warm-only evidence cannot generate/);
  assert.equal(fs.existsSync(selected.log), false);
});

test('does not stop an existing container when reviewed UI creation fails', (t) => {
  const selected = fixture(t);
  const result = launch(selected, ['--cache-mode', 'cold'], { TEST_UI_CREATE_FAIL: 'true' });
  assert.notEqual(result.status, 0);
  const events = eventsOf(selected);
  assert.ok(events.some((line) => line.startsWith('docker\trun\t')));
  assert.ok(events.every((line) => !line.startsWith('docker\tstop\t')));
});

test('ignores a TMPDIR inside the workspace and rejects overlapping review state', (t) => {
  const selected = fixture(t);
  const safeResult = launch(selected, ['--cache-mode', 'cold'], { TMPDIR: selected.workdir });
  assert.equal(safeResult.status, 0, outputOf(safeResult));
  const bundleRun = eventsOf(selected).find((line) => /\treview\tbundle\t/.test(line));
  assert.ok(bundleRun);
  assert.doesNotMatch(bundleRun, new RegExp(`${escaped(selected.workdir)}/nosh-profile-review`));

  const overlapping = fixture(t);
  const overlappingState = path.join(overlapping.workdir, 'review-state');
  const rejected = launch(overlapping, ['--cache-mode', 'cold'], {
    NOSH_PROFILE_REVIEW_STATE_ROOT: overlappingState,
  });
  assert.notEqual(rejected.status, 0);
  assert.match(rejected.stderr, /review state root overlaps profile workdir/);
});
