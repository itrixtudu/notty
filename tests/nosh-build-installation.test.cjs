const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');

const repository = path.resolve(__dirname, '..');

function read(relative) {
  return fs.readFileSync(path.join(repository, relative), 'utf8');
}

test('build collector configuration matches the daemon mode and install contract', () => {
  const adapters = JSON.parse(read('config/nosh-build/adapters.json'));
  const byName = new Map(adapters.adapters.map((entry) => [entry.name, entry]));
  const expectedModes = ['build-profile', 'build-net-learn'];

  assert.deepEqual(byName.get('nosh-build').requiredModes, expectedModes);
  assert.deepEqual(byName.get('nosh-l4').requiredModes, expectedModes);
  assert.equal(
    byName.get('nosh-build').health.command,
    '/usr/local/libexec/nosh-build/nosh-build-loader',
  );
  assert.equal(
    byName.get('nosh-l4').health.command,
    '/usr/local/libexec/nosh-guard/nosh-l4-loader',
  );
  assert.equal(
    byName.get('nosh-url').health.command,
    '/usr/local/libexec/nosh-build/nosh-url-loader',
  );
  assert.deepEqual(byName.get('nosh-url').requiredModes, []);
  assert.deepEqual(byName.get('nosh-url').modes, []);
  assert.equal(byName.get('nosh-url').evidenceRequired, false);
  assert.deepEqual(
    byName.get('nosh-build').health.args,
    [
      'health',
      '--cgroup',
      '{cgroupPath}',
      '--cgroup-id',
      '{cgroupId}',
      '--depth',
      '{depth}',
    ],
  );
  assert.deepEqual(
    byName.get('nosh-l4').health.args,
    [
      'health',
      '--cgroup',
      '{cgroupPath}',
      '--cgroup-id',
      '{cgroupId}',
      '--output-mode',
      'flow-summary',
    ],
  );
  assert.deepEqual(byName.get('nosh-build').supportedDepths, [
    'balanced',
    'policy',
  ]);
  assert.ok(
    byName.get('nosh-build').completion.requireZero
      .includes('counters.fileMapFull'),
  );
  assert.deepEqual(byName.get('nosh-l4').attach.args.slice(-2), [
    '--output-mode',
    'flow-summary',
  ]);
  assert.equal(
    byName.get('nosh-l4').readiness.match.outputMode,
    'flow-summary',
  );
  assert.equal(
    byName.get('nosh-l4').completion.match.outputMode,
    'flow-summary',
  );

  const versions = JSON.parse(read('config/nosh-build/versions.json'));
  assert.equal(versions.buildkit.version, 'v0.30.0');
  assert.equal(
    versions.noshBuild.loaderPath,
    byName.get('nosh-build').health.command,
  );
  assert.equal(
    versions.noshL4.loaderPath,
    byName.get('nosh-l4').health.command,
  );
  assert.equal(
    versions.noshUrl.loaderPath,
    byName.get('nosh-url').health.command,
  );
  assert.equal(versions.noshUrl.optional, true);
  assert.equal(versions.noshUrl.observationOnly, true);
  assert.match(
    read('bpf/nosh_url/Makefile'),
    /LOADER_INSTALL_DIR \?= \$\(PREFIX\)\/libexec\/nosh-build/,
  );
});

test('host installation documentation uses the supported bundle and adapter path', () => {
  const detailed = read('docs/nosh-build-profiling.md');
  const guard = read('docs/nosh-guard.md');

  for (const source of [detailed, guard]) {
    assert.match(source, /build-nosh-guard-host-bundle\.sh/);
    assert.match(source, /install\.sh install/);
    assert.match(source, /setup-nosh\.sh/);
    assert.match(source, /--prefix/);
    assert.match(source, /nosh-guard-host-verify/);
    assert.match(source, /install\.sh uninstall/);
  }
  assert.doesNotMatch(detailed, /\/etc\/nosh-build\/adapters\.json/);
  assert.doesNotMatch(guard, /\/etc\/nosh-build\/adapters\.json/);
});

test('release package audit requires the build profiling host assets', () => {
  const audit = read('scripts/release-audit-container.sh');
  for (const required of [
    'build-nosh.sh',
    'Dockerfile.guard',
    'Dockerfile.nosh-guard-host-bundle',
    'bpf/nosh_build/Makefile',
    'bpf/nosh_build/nosh_build.bpf.c',
    'bpf/nosh_build/tests/nosh-build-static.test.cjs',
    'bpf/nosh_url/Makefile',
    'bpf/nosh_url/nosh_url.bpf.c',
    'bpf/nosh_url/loader/nosh_url_loader.c',
    'bpf/nosh_url/loader/url_sanitizer.c',
    'bpf/nosh_url/tests/include/bpf/libbpf.h',
    'bpf/nosh_url/tests/loader_stubs.c',
    'bpf/nosh_url/tests/static.sh',
    'bin/nosh-gateway',
    'config/nosh-build/adapters.json',
    'config/nosh-build/versions.json',
    'config/nosh-gateway/trust.schema.json',
    'deploy/host/nosh-gateway',
    'deploy/host/nosh-guard',
    'deploy/systemd/nosh-guardd.service',
    'docs/nosh-build-profiling.md',
    'docs/nosh-gateway.md',
    'docs/nosh-http-capture-contract.md',
    'lib/guard/review/gateway-host.js',
    'lib/guard/review/cli.js',
    'lib/guardd/build-orchestrator.js',
    'lib/guardd/http-capture-manager.js',
    'lib/guardd/http-content-store.js',
    'lib/guardd/http-evidence.js',
    'lib/guardd/install-layout.js',
    'lib/guardd/build-session-service.js',
    'profile-build-and-review.sh',
    'reset-nosh-guard.sh',
    'setup-nosh.sh',
    'scripts/build-nosh-guard-host-bundle.sh',
    'scripts/build-nosh-guard-host-bundle-container.sh',
    'scripts/install-nosh-guard-host-bundle.sh',
    'scripts/nosh-egress-containment-probe.mjs',
    'scripts/nosh-guard-doctor.sh',
    'scripts/nosh-gateway.mjs',
    'scripts/nosh-mitmproxy-addon.py',
    'scripts/nosh-mitmproxy-capture.sh',
    'scripts/render-nosh-guard-install.mjs',
    'scripts/run-nosh-guard-host-bundle-container.sh',
    'scripts/verify-nosh-guard-host-install.sh',
    'tests/nosh-build-installation.test.cjs',
    'tests/build-nosh-launcher.test.cjs',
    'tests/nosh-review-graph-server.test.cjs',
    'policy-review/modules/policy-review/runtimeAttestation.js',
    'policy-review/pages/api/policy-review-attestation.js',
    'policy-review/pages/api/policy-review-decision-set.js',
    'policy-review/tests/runtime-attestation-api.test.cjs',
    'policy-review/tests/decision-set-api.test.cjs',
    'tests/nosh-gateway-host.test.cjs',
    'tests/nosh-guard-host-reset.test.cjs',
    'tests/nosh-guard-host-bundle.test.cjs',
    'tests/nosh-guard-install-layout.test.cjs',
    'tests/nosh-guard-install-renderer.test.cjs',
    'tests/nosh-egress-containment-probe.test.cjs',
    'tests/build-network-deny.test.cjs',
    'tests/reviewed-policy-enforcement.test.cjs',
    'tests/nosh-setup.test.cjs',
  ]) {
    assert.match(audit, new RegExp(required.replaceAll('/', '\\/').replaceAll('.', '\\.')));
  }
});
