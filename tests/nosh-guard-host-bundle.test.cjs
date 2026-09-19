const assert = require('node:assert/strict');
const childProcess = require('node:child_process');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const test = require('node:test');

const repository = path.resolve(__dirname, '..');
const hostBuilderPath = path.join(
  repository,
  'scripts',
  'build-nosh-guard-host-bundle.sh',
);
const containerBuilderPath = path.join(
  repository,
  'scripts',
  'build-nosh-guard-host-bundle-container.sh',
);
const containerEntrypointPath = path.join(
  repository,
  'scripts',
  'run-nosh-guard-host-bundle-container.sh',
);

function read(relative) {
  return fs.readFileSync(path.join(repository, relative), 'utf8');
}

function walkJavaScript(relative) {
  const root = path.join(repository, relative);
  return fs.readdirSync(root, { withFileTypes: true }).flatMap((entry) => {
    const child = path.join(root, entry.name);
    if (entry.isDirectory()) {
      return walkJavaScript(path.relative(repository, child));
    }
    return entry.isFile() && /\.(?:js|mjs)$/.test(entry.name) ? [child] : [];
  });
}

test('host bundle has a closed local JavaScript dependency graph', () => {
  const files = [
    path.join(repository, 'scripts/nosh-gateway.mjs'),
    path.join(repository, 'scripts/nosh-guard.mjs'),
    path.join(repository, 'scripts/nosh-guard-fail-closed.mjs'),
    path.join(repository, 'scripts/nosh-guard-tetragon-verify.mjs'),
    path.join(repository, 'scripts/render-nosh-guard-install.mjs'),
    ...walkJavaScript('lib/guard'),
    ...walkJavaScript('lib/guardd'),
  ];
  const importPattern = /(?:from\s+|import\s*\()(['"])([^'"]+)\1/g;

  for (const file of files) {
    const source = fs.readFileSync(file, 'utf8');
    for (const match of source.matchAll(importPattern)) {
      const specifier = match[2];
      assert.ok(
        specifier.startsWith('node:') || specifier.startsWith('.'),
        `${path.relative(repository, file)} imports external package ${specifier}`,
      );
      if (specifier.startsWith('.')) {
        const resolved = path.resolve(path.dirname(file), specifier);
        assert.ok(
          fs.existsSync(resolved),
          `${path.relative(repository, file)} has missing import ${specifier}`,
        );
      }
    }
  }
});

test('Guard toolchain image is pinned, non-root, and build-only', () => {
  const image = read('Dockerfile.guard');
  const bundleImage = read('Dockerfile.nosh-guard-host-bundle');
  const imagePattern = /^ARG NODE_IMAGE=(node:24\.18\.0-bookworm-slim@sha256:[a-f0-9]{64})$/m;

  assert.match(image, imagePattern);
  assert.equal(image.match(imagePattern)[1], bundleImage.match(imagePattern)[1]);
  assert.match(image, /io\.notty\.nosh-guard-toolchain="1"/);
  assert.match(image, /^USER node$/m);
  assert.match(image, /^WORKDIR \/workspace$/m);
  assert.match(image, /^CMD \["\/bin\/bash"\]$/m);
  assert.match(image, /CLANG=clang-14/);
  assert.match(image, /BPFTOOL=bpftool/);
  for (const toolchainPackage of [
    'bpftool',
    'clang-14',
    'coreutils',
    'gcc',
    'grep',
    'libbpf-dev',
    'libelf-dev',
    'make',
    'mawk',
    'pkg-config',
    'ripgrep',
    'zlib1g-dev',
  ]) {
    assert.match(image, new RegExp(`\\b${toolchainPackage}\\b`));
  }
  assert.match(image, /--network none/);
  assert.match(image, /--read-only/);
  assert.match(image, /--cap-drop ALL/);
  assert.match(image, /--security-opt no-new-privileges=true/);
  assert.match(image, /--tmpfs \/tmp:rw,nosuid,nodev,exec/);
  assert.match(image, /\/sys\/kernel\/btf\/vmlinux/);
  assert.doesNotMatch(image, /^(?:ADD|COPY|ENTRYPOINT|VOLUME)\b/m);

  const userOffset = image.indexOf('\nUSER node');
  assert.ok(userOffset > image.lastIndexOf('\nRUN '));
});

test('containerized host bundle builder and installer preserve the privilege boundary', () => {
  const hostBuilder = read('scripts/build-nosh-guard-host-bundle.sh');
  const containerBuilder = read('scripts/build-nosh-guard-host-bundle-container.sh');
  const containerEntrypoint = read('scripts/run-nosh-guard-host-bundle-container.sh');
  const bundleImage = read('Dockerfile.nosh-guard-host-bundle');
  const auditImage = read('Dockerfile.release-audit');
  const installer = read('scripts/install-nosh-guard-host-bundle.sh');
  const verifier = read('scripts/verify-nosh-guard-host-install.sh');
  const cli = read('scripts/nosh-guard.mjs');
  const client = read('lib/guardd/client.js');
  const server = read('lib/guardd/server.js');
  const unit = read('deploy/systemd/nosh-guardd.service');
  const runnerImage = read('Dockerfile.nosh');
  const dockerIgnore = read('.dockerignore');
  const npmIgnore = read('.npmignore');

  const enableNowOffset = installer.indexOf(
    'systemctl enable --now nosh-guardd.service',
  );
  const enableReadinessOffset = installer.indexOf(
    'wait_for_guard_service_ready /run/nosh-guardd.sock',
    enableNowOffset,
  );
  const restartOffset = installer.indexOf(
    'systemctl start nosh-guardd.service',
    enableReadinessOffset,
  );
  const restartReadinessOffset = installer.indexOf(
    'wait_for_guard_service_ready /run/nosh-guardd.sock',
    restartOffset,
  );
  const installSuccessOffset = installer.indexOf(
    "printf 'install.sh: installed Nosh Guard %s\\n'",
    restartReadinessOffset,
  );
  assert.ok(enableNowOffset >= 0);
  assert.ok(enableReadinessOffset > enableNowOffset);
  assert.ok(restartOffset > enableReadinessOffset);
  assert.ok(restartReadinessOffset > restartOffset);
  assert.ok(installSuccessOffset > restartReadinessOffset);
  assert.match(installer, /attempt <= 10/);
  assert.match(installer, /consecutive_ready >= 2/);
  assert.match(installer, /stat -Lc '%u %a %h'.*'0 600 1'/);
  assert.match(installer, /timeout --signal=KILL 2s/);
  assert.match(installer, /nosh-guard" runs --socket/);
  for (const installedReviewDocument of [
    'nosh-gateway.md',
    'nosh-policy-review.md',
  ]) {
    assert.match(installer, new RegExp(`payload/docs/${installedReviewDocument}`));
    assert.match(verifier, new RegExp(`payload/docs/${installedReviewDocument}`));
  }
  for (const safeHelpLauncher of [
    'nosh-gateway',
    'nosh-guard',
    'nosh-guardd',
    'nosh-guard-tetragon-verify',
  ]) {
    assert.match(
      verifier,
      new RegExp(`"\\$PREFIX/bin/${safeHelpLauncher}"`),
    );
  }
  assert.doesNotMatch(
    verifier,
    /check_launcher_help "\$PREFIX\/bin\/nosh-guard-fail-closed"/,
  );
  const buildHealthOffset = verifier.indexOf(
    'nosh-build-loader" health --depth balanced',
  );
  const buildVerifyOffset = verifier.indexOf(
    'nosh-build-loader" verify --depth balanced',
  );
  assert.ok(buildHealthOffset >= 0);
  assert.ok(buildVerifyOffset > buildHealthOffset);
  assert.match(verifier, /Usage: nosh-guard <command> \[options\]/);
  assert.match(
    verifier,
    /Usage: nosh-gateway <verify\|diff\|apply\|status> \[options\]/,
  );
  assert.match(
    verifier,
    /Usage: nosh-guard-tetragon-verify --policy-name NAME \[options\]/,
  );
  assert.match(verifier, /NOSH_GUARD_ALLOW_INCOMPLETE=1/);
  assert.match(verifier, /timeout --signal=KILL 2s "\$launcher" --help/);
  assert.match(
    verifier,
    /launcher did not execute its entrypoint/,
  );

  assert.doesNotMatch(
    hostBuilder,
    /^\s*(?:command\s+)?(?:npm|npx|node|make|clang|bpftool)(?:\s|$)/m,
  );
  assert.doesNotMatch(
    hostBuilder,
    /\$\(\s*(?:npm|npx|node|make|clang|bpftool)(?:\s|\))/m,
  );
  assert.doesNotMatch(hostBuilder, /NODE_BINARY|NOSH_GUARD_NODE_BINARY/);
  assert.match(hostBuilder, /host Node overrides are not supported/);
  assert.match(hostBuilder, /bpf\/nosh_url\/build\/nosh-url-loader/);
  assert.match(hostBuilder, /Docker is mandatory/i);
  assert.match(hostBuilder, /docker build/);
  assert.match(hostBuilder, /docker run/);
  assert.match(hostBuilder, /docker context inspect/);
  assert.match(hostBuilder, /docker_endpoint.*unix:\/\//);
  assert.match(hostBuilder, /docker_os.*linux/);
  assert.match(hostBuilder, /rootless or userns-remapped Docker is not supported/);
  assert.match(hostBuilder, /image_id.*\^sha256:\[0-9a-f\]\{64\}/);
  assert.match(hostBuilder, /io\.notty\.nosh-guard-host-bundle/);
  assert.match(
    hostBuilder,
    /docker run "\$\{run_args\[@\]\}" "\$image_id" "\$\{packager_args\[@\]\}"/,
  );
  assert.match(hostBuilder, /packager_args\+=\(--use-existing-loaders\)/);
  for (const pattern of [
    /--read-only/,
    /--user "\$\(id -u\):\$\(id -g\)"/,
    /--network none/,
    /--cap-drop ALL/,
    /no-new-privileges=true/,
    /type=bind,src=.*dst=\/input,readonly/,
    /type=bind,src=.*dst=\/output/,
    /dst=\/sys\/kernel\/btf\/vmlinux,readonly/,
    /--tmpfs ["']?\/bundle-work:.*exec/,
    /NOSH_GUARD_HOST_BUNDLE_CONTAINER=1/,
  ]) {
    assert.match(hostBuilder, pattern);
  }

  assert.match(
    containerBuilder,
    /NOSH_GUARD_HOST_BUNDLE_CONTAINER.*1/,
  );
  for (const pattern of [
    /-f \/\.dockerenv/,
    /id -u.*!= 0/,
    /CapEff:/,
    /NOSH_GUARD_HOST_BUNDLE_NETWORK_MODE.*none/,
    /TMPDIR.*\/bundle-work\/tmp/,
    /\/proc\/self\/mountinfo/,
    /mount_has_option \/input ro/,
    /mount_has_option \/output rw/,
    /network_interface in \/sys\/class\/net\/\*/,
    /NODE_REQUESTED="\/usr\/local\/bin\/node"/,
    /! -e \/var\/run\/docker\.sock/,
  ]) {
    assert.match(containerBuilder, pattern);
  }
  assert.match(containerEntrypoint, /NOSH_GUARD_HOST_BUNDLE_CONTAINER.*1/);
  assert.match(containerEntrypoint, /\/input/);
  assert.match(containerEntrypoint, /\/bundle-work/);
  assert.match(containerEntrypoint, /build-nosh-guard-host-bundle-container\.sh/);

  const imagePattern = /^ARG NODE_IMAGE=(node:24\.18\.0-bookworm-slim@sha256:[a-f0-9]{64})$/m;
  assert.match(bundleImage, imagePattern);
  assert.match(auditImage, imagePattern);
  assert.equal(bundleImage.match(imagePattern)[1], auditImage.match(imagePattern)[1]);
  assert.match(bundleImage, /NOSH_GUARD_HOST_BUNDLE_CONTAINER=1/);
  assert.match(bundleImage, /io\.notty\.nosh-guard-host-bundle="1"/);
  assert.match(bundleImage, /run-nosh-guard-host-bundle-container\.sh/);
  const bundleNonRootUser = bundleImage.indexOf('\nUSER node');
  const bundleLastRootRun = bundleImage.lastIndexOf('\nRUN ', bundleNonRootUser);
  assert.ok(bundleNonRootUser >= 0);
  assert.ok(bundleLastRootRun >= 0);
  for (const runtimeSetting of [
    'TMPDIR=/bundle-work/tmp',
    'HOME=/bundle-work/home',
  ]) {
    const settingOffset = bundleImage.indexOf(runtimeSetting);
    assert.ok(
      settingOffset > bundleLastRootRun && settingOffset < bundleNonRootUser,
      `${runtimeSetting} must follow build-time root RUN layers and precede USER node`,
    );
  }
  assert.match(
    containerEntrypoint,
    /install -d -m 0700 "\$TMPDIR" "\$HOME"/,
  );
  assert.match(bundleImage, /^USER node$/m);
  assert.match(bundleImage, /ENTRYPOINT/);
  for (const toolchainPackage of [
    'bpftool',
    'clang-14',
    'gcc',
    'libbpf-dev',
    'libelf-dev',
    'make',
    'pkg-config',
    'ripgrep',
    'zlib1g-dev',
  ]) {
    assert.match(bundleImage, new RegExp(`\\b${toolchainPackage}\\b`));
  }

  assert.doesNotMatch(containerBuilder, /^[\t ]*(?:npm|npx)(?:[\t ]|$)/m);
  assert.match(
    containerBuilder,
    /"\$NODE_REQUESTED" --test "\$REPOSITORY_ROOT\/bpf\/nosh_build\/tests\/"\*\.test\.cjs/,
  );
  assert.match(
    containerBuilder,
    /make -C "\$LOADER_BUILD_ROOT\/nosh_url" test/,
  );
  assert.match(
    containerBuilder,
    /make -C "\$LOADER_BUILD_ROOT\/nosh_l4" test/,
  );
  assert.match(
    containerBuilder,
    /make -C "\$LOADER_BUILD_ROOT\/nosh_egress" test/,
  );
  assert.match(
    containerBuilder,
    /make -C "\$LOADER_BUILD_ROOT\/nosh_build" CLANG=clang-14 loader test-dns/,
  );
  assert.match(
    containerBuilder,
    /make -C "\$LOADER_BUILD_ROOT\/nosh_url" CLANG=clang-14 loader/,
  );
  assert.match(
    containerBuilder,
    /make -C "\$LOADER_BUILD_ROOT\/nosh_l4" CLANG=clang-14 loader/,
  );
  assert.match(containerBuilder, /make -C "\$LOADER_BUILD_ROOT\/nosh_build" clean/);
  assert.match(containerBuilder, /make -C "\$LOADER_BUILD_ROOT\/nosh_url" clean/);
  assert.match(containerBuilder, /make -C "\$LOADER_BUILD_ROOT\/nosh_l4" clean/);
  assert.doesNotMatch(containerBuilder, /make -C "\$REPOSITORY_ROOT\/bpf\//);
  assert.match(
    containerBuilder,
    /LOADER_BUILD_ROOT="\$TMPDIR\/loader-source"/,
  );
  assert.match(containerBuilder, /manifest\.sha256/);
  assert.match(containerBuilder, /NODE_VERSION="\$\(\$NODE_BINARY --version\)"/);
  assert.match(containerBuilder, /NODE_VERSION" == v24\.18\.0/);
  assert.match(containerBuilder, /NODE_SHA256/);
  assert.match(containerBuilder, /copied Node runtime is not relocatable/);
  assert.match(containerBuilder, /scripts\/nosh-guard-doctor\.sh/);
  assert.match(containerBuilder, /render-nosh-guard-install\.mjs/);
  assert.match(
    containerBuilder,
    /\$PAYLOAD_ROOT\/libexec\/nosh-build\/nosh-url-loader/,
  );
  assert.match(containerBuilder, /templates\/deploy\/host/);
  assert.match(containerBuilder, /templates\/libexec\/nosh-guard/);
  assert.match(containerBuilder, /'BUNDLE_FORMAT=2'/);
  assert.match(
    containerBuilder,
    /"\$PAYLOAD_ROOT\/runtime\/node"[\s\\]+"\$PAYLOAD_ROOT\/scripts\/render-nosh-guard-install\.mjs"/,
  );

  assert.match(installer, /sha256sum --check --strict --quiet manifest\.sha256/);
  const manifestCapture = installer.indexOf(
    'manifest_digest="$(sha256sum "$BUNDLE_ROOT/manifest.sha256"',
  );
  const sourceVerification = installer.indexOf('verify_bundle', manifestCapture);
  const unchangedCheck = installer.indexOf(
    'bundle manifest changed during verification',
    sourceVerification,
  );
  assert.ok(manifestCapture >= 0);
  assert.ok(sourceVerification > manifestCapture);
  assert.ok(unchangedCheck > sourceVerification);
  assert.match(installer, /verify_manifest_tree "\$INSTALL_STAGING" 'root-owned staging'/);
  assert.match(installer, /bundle changed while creating root-owned staging/);
  assert.match(installer, /-type f -links \+1/);
  assert.match(installer, /PREFIX="\/usr\/local"/);
  assert.match(installer, /INSTALL_BASE="\$PREFIX\/lib\/notty\/nosh-guard"/);
  assert.match(installer, /--prefix ABS/);
  assert.match(installer, /--prefix must be an absolute path other than/);
  assert.match(installer, /--prefix is a broad system root/);
  assert.match(installer, /refusing cross-prefix/);
  assert.match(installer, /BUNDLE_FORMAT\)" == 2/);
  assert.match(installer, /render-nosh-guard-install\.mjs/);
  assert.match(installer, /--source-root "\$release_root"/);
  assert.match(installer, /--output-dir "\$RENDER_STAGING"/);
  assert.match(installer, /\/etc\/nosh-guard-install-layout\.conf/);
  assert.match(installer, /'SCHEMA_VERSION=1'/);
  assert.match(installer, /"NOSH_GUARD_PREFIX=\$PREFIX"/);
  assert.match(installer, /"MANIFEST_SHA256=\$manifest_digest"/);
  assert.match(installer, /'0 644 1'/);
  assert.match(installer, /--sudoers-group/);
  assert.match(installer, /nosh-guard build-session begin/);
  assert.match(installer, /nosh-guard build-session exported/);
  assert.match(installer, /--replace-sudoers/);
  assert.match(installer, /sudoers target must have one link/);
  assert.match(installer, /existing Nosh sudoers policy requires --sudoers-group validation/);
  assert.match(installer, /sudoers policy is not bundle-managed/);
  assert.match(installer, /line_count="\$\(sed -n '\$=' "\$destination"\)"/);
  assert.match(installer, /operator configuration has unsafe owner\/mode\/links/);
  assert.match(installer, /preserved \/etc\/nosh-guard configuration/);
  assert.match(installer, /preserved \/var\/lib\/nosh-guard evidence and state/);
  assert.match(installer, /--purge-config/);
  assert.match(installer, /--purge-state/);
  assert.match(verifier, /payload\/runtime\/node/);
  assert.match(verifier, /NODE_VERSION/);
  assert.match(verifier, /NODE_SHA256/);
  assert.match(verifier, /verify_manifest_inventory "\$CURRENT_ROOT"/);
  assert.match(verifier, /release contains a multiply linked file/);
  assert.match(verifier, /optional sudoers policy drifted/);
  assert.match(verifier, /sudoers\/nosh-build-session\.alias/);
  assert.match(verifier, /^PREFIX='@@NOSH_GUARD_PREFIX@@'$/m);
  assert.match(verifier, /\/etc\/nosh-guard-install-layout\.conf/);
  assert.match(verifier, /receipt prefix .* does not match requested/);
  assert.match(verifier, /receipt does not identify the current release/);
  assert.match(verifier, /render-nosh-guard-install\.mjs/);
  assert.match(installer, /payload\/libexec\/nosh-build\/nosh-url-loader/);
  assert.match(installer, /payload\/scripts\/nosh-mitmproxy-capture\.sh/);
  assert.match(installer, /payload\/scripts\/nosh-mitmproxy-addon\.py/);
  assert.match(containerBuilder, /nosh-mitmproxy-capture\.sh/);
  assert.match(containerBuilder, /nosh-mitmproxy-addon\.py/);
  assert.match(containerBuilder, /docs\/nosh-http-capture-contract\.md/);
  assert.match(verifier, /payload\/libexec\/nosh-build\/nosh-url-loader/);
  assert.doesNotMatch(
    verifier,
    /nosh-url-loader" health/,
  );
  assert.match(verifier, /--source-root "\$CURRENT_ROOT"/);
  assert.match(verifier, /compare_deployed[\s\S]*\$RENDER_STAGING\/deploy\/host/);
  assert.doesNotMatch(verifier, /\/usr\/local/);
  assert.match(
    unit,
    /ExecStartPre=@@NOSH_GUARD_PREFIX@@\/libexec\/nosh-guard\/nosh-guard-host-verify --service/,
  );
  assert.match(dockerIgnore, /^\.nosh-guard-host-bundles\/?$/m);
  assert.match(npmIgnore, /^\.nosh-guard-host-bundles\/$/m);

  assert.doesNotMatch(runnerImage, /nosh-build-loader/);
  assert.doesNotMatch(runnerImage, /nosh-url-loader/);
  assert.doesNotMatch(runnerImage, /nosh-l4-loader/);
  assert.doesNotMatch(runnerImage, /nosh-guardd\.service/);
  assert.match(cli, /'begin', 'finish', 'abort', 'exported'/);
  assert.match(client, /acknowledgeBuildExport/);
  assert.match(server, /\\\/exported/);
});

test('host bundle scripts are executable, syntactically valid, and container-bound', () => {
  for (const script of [
    hostBuilderPath,
    containerBuilderPath,
    containerEntrypointPath,
  ]) {
    assert.notEqual(fs.statSync(script).mode & 0o111, 0, `${script} must be executable`);
    const syntax = childProcess.spawnSync('/bin/bash', ['-n', script], {
      cwd: repository,
      encoding: 'utf8',
    });
    assert.equal(syntax.status, 0, syntax.stderr);
  }

  const help = childProcess.spawnSync('/bin/bash', [hostBuilderPath, '--help'], {
    cwd: repository,
    encoding: 'utf8',
  });
  assert.equal(help.status, 0, help.stderr);
  assert.match(help.stdout, /Docker/i);
  assert.match(help.stdout, /never runs .*node.*host/is);
  assert.doesNotMatch(help.stdout, /--node(?:-license)?(?:\s|=)/);

  const invalid = childProcess.spawnSync(
    '/bin/bash',
    [hostBuilderPath, '--invalid'],
    { cwd: repository, encoding: 'utf8' },
  );
  assert.equal(invalid.status, 2);

  const hostNodeOverride = childProcess.spawnSync(
    '/bin/bash',
    [hostBuilderPath, '--node', '/usr/bin/node'],
    { cwd: repository, encoding: 'utf8' },
  );
  assert.equal(hostNodeOverride.status, 2);
  assert.match(hostNodeOverride.stderr, /host Node overrides are not supported/i);

  for (const script of [containerBuilderPath, containerEntrypointPath]) {
    const outsideContainer = childProcess.spawnSync('/bin/bash', [script], {
      cwd: repository,
      encoding: 'utf8',
      env: {
        ...process.env,
        NOSH_GUARD_HOST_BUNDLE_CONTAINER: '0',
      },
    });
    assert.equal(outsideContainer.status, 2, outsideContainer.stdout + outsideContainer.stderr);
    assert.match(outsideContainer.stderr, /refus|container/i);
  }
});

test('container mount-option probe is portable and matches exact option tokens', () => {
  const containerBuilder = fs.readFileSync(containerBuilderPath, 'utf8');
  const probeMatch = containerBuilder.match(
    /awk -v target="\$mount_target" -v required="\$required_option" '([\s\S]*?)'\s+\/proc\/self\/mountinfo/,
  );
  assert.ok(probeMatch, 'mount-option awk probe must be discoverable');

  const mountinfo = [
    '36 25 0:32 / / rw,relatime - overlay overlay rw',
    '50 36 8:1 /source /input ro,nosuid,nodev - ext4 /dev/sda1 rw',
    '',
  ].join('\n');
  const present = childProcess.spawnSync(
    'awk',
    ['-v', 'target=/input', '-v', 'required=ro', probeMatch[1]],
    { encoding: 'utf8', input: mountinfo },
  );
  assert.equal(present.status, 0, present.stderr);

  for (const absentOption of ['rw', 'o']) {
    const absent = childProcess.spawnSync(
      'awk',
      ['-v', 'target=/input', '-v', `required=${absentOption}`, probeMatch[1]],
      { encoding: 'utf8', input: mountinfo },
    );
    assert.equal(absent.status, 1, absent.stderr);
  }
});

test('host bundle wrapper invokes only an isolated Docker build and run', (t) => {
  const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'notty-guard-bundle-docker-'));
  t.after(() => fs.rmSync(tempRoot, { recursive: true, force: true }));
  const fakeBin = path.join(tempRoot, 'bin');
  const outputDir = path.join(tempRoot, 'output');
  const dockerLog = path.join(tempRoot, 'docker.log');
  const hostToolMarker = path.join(tempRoot, 'host-tool-called');
  fs.mkdirSync(fakeBin);
  fs.writeFileSync(
    path.join(fakeBin, 'docker'),
    `#!/bin/sh
set -eu
{
  printf '%s\n' CALL
  for argument in "$@"; do
    printf 'arg=%s\n' "$argument"
  done
} >>"$FAKE_DOCKER_LOG"
case "$*" in
  *Endpoints.docker.Host*) printf '%s\n' unix:///var/run/docker.sock ;;
  *OSType*) printf '%s\n' linux ;;
  *io.notty.nosh-guard-host-bundle*) printf '%s\n' 1 ;;
  *'{{.Id}}'*) printf 'sha256:%064d\n' 1 ;;
esac
if [ "\${1:-}" = run ]; then
  output_dir=
  result_name=
  for argument in "$@"; do
    case "$argument" in
      type=bind,src=*,dst=/output)
        output_dir=\${argument#type=bind,src=}
        output_dir=\${output_dir%,dst=/output}
        ;;
      NOSH_GUARD_HOST_BUNDLE_RESULT=/output/*)
        result_name=\${argument#NOSH_GUARD_HOST_BUNDLE_RESULT=/output/}
        ;;
    esac
  done
  [ -n "$output_dir" ]
  [ -n "$result_name" ]
  version=$(sed -n 's/.*"version":[[:space:]]*"\\([^"]*\\)".*/\\1/p' package.json)
  archive=notty-nosh-guard-$version-$(uname -m)-$(uname -r).tar.gz
  printf '%s\n' 'fake bundle' >"$output_dir/$archive"
  chmod 0644 "$output_dir/$archive"
  digest=$(command sha256sum "$output_dir/$archive")
  digest=\${digest%% *}
  printf '%s  %s\n' "$digest" "$archive" >"$output_dir/$archive.sha256"
  chmod 0644 "$output_dir/$archive.sha256"
  printf 'ARCHIVE=%s\nCHECKSUM=%s\n' \
    "$archive" "$archive.sha256" >"$output_dir/$result_name"
  chmod 0600 "$output_dir/$result_name"
fi
exit 0
`,
    { mode: 0o755 },
  );
  for (const command of ['npm', 'npx', 'node', 'make', 'clang', 'bpftool']) {
    fs.writeFileSync(
      path.join(fakeBin, command),
      `#!/bin/sh\nprintf '%s\\n' ${JSON.stringify(command)} >>"$HOST_TOOL_MARKER"\nexit 99\n`,
      { mode: 0o755 },
    );
  }

  const result = childProcess.spawnSync(
    '/bin/bash',
    [hostBuilderPath, '--output-dir', outputDir],
    {
      cwd: repository,
      encoding: 'utf8',
      env: {
        PATH: `${fakeBin}:/usr/bin:/bin`,
        FAKE_DOCKER_LOG: dockerLog,
        HOST_TOOL_MARKER: hostToolMarker,
      },
    },
  );

  assert.equal(result.status, 0, result.stdout + result.stderr);
  assert.equal(fs.existsSync(hostToolMarker), false);
  assert.ok(result.stdout.includes(`host bundle: ${outputDir}/`));
  assert.ok(result.stdout.includes(`checksum:    ${outputDir}/`));
  assert.doesNotMatch(result.stdout, /host bundle: \/output\//);
  const invocation = fs.readFileSync(dockerLog, 'utf8');
  assert.match(invocation, /^arg=build$/m);
  assert.match(invocation, /^arg=--pull$/m);
  assert.match(invocation, /^arg=notty-nosh-guard-host-bundle:node24\.18\.0$/m);
  assert.match(invocation, /^arg=run$/m);
  assert.match(invocation, /^arg=--read-only$/m);
  assert.match(invocation, /^arg=--network$/m);
  assert.match(invocation, /^arg=none$/m);
  assert.match(invocation, /^arg=--cap-drop$/m);
  assert.match(invocation, /^arg=ALL$/m);
  assert.match(invocation, /^arg=--security-opt$/m);
  assert.match(invocation, /^arg=no-new-privileges=true$/m);
  assert.match(invocation, /^arg=NOSH_GUARD_HOST_BUNDLE_CONTAINER=1$/m);
  assert.match(invocation, /^arg=type=bind,src=.*dst=\/input,readonly(?:,.*)?$/m);
  assert.match(invocation, /^arg=type=bind,src=.*dst=\/output(?:,.*)?$/m);
  assert.match(
    invocation,
    /^arg=type=bind,src=\/sys\/kernel\/btf\/vmlinux,dst=\/sys\/kernel\/btf\/vmlinux,readonly(?:,.*)?$/m,
  );
  assert.match(invocation, /^arg=\/bundle-work:.*exec.*$/m);
  assert.match(invocation, /^arg=sha256:0{63}1$/m);
});

test('unavailable Docker never falls back to host Node or build tools', (t) => {
  const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'notty-guard-bundle-no-docker-'));
  t.after(() => fs.rmSync(tempRoot, { recursive: true, force: true }));
  const fakeBin = path.join(tempRoot, 'bin');
  const hostToolMarker = path.join(tempRoot, 'host-tool-called');
  fs.mkdirSync(fakeBin);
  fs.writeFileSync(
    path.join(fakeBin, 'docker'),
    '#!/bin/sh\nexit 1\n',
    { mode: 0o755 },
  );
  for (const command of ['npm', 'npx', 'node', 'make', 'clang', 'bpftool']) {
    fs.writeFileSync(
      path.join(fakeBin, command),
      `#!/bin/sh\nprintf '%s\\n' ${JSON.stringify(command)} >>"$HOST_TOOL_MARKER"\nexit 99\n`,
      { mode: 0o755 },
    );
  }

  const outputDir = path.join(tempRoot, 'output');
  const result = childProcess.spawnSync(
    '/bin/bash',
    [hostBuilderPath, '--output-dir', outputDir],
    {
      cwd: repository,
      encoding: 'utf8',
      env: {
        PATH: `${fakeBin}:/usr/bin:/bin`,
        HOST_TOOL_MARKER: hostToolMarker,
      },
    },
  );

  assert.equal(result.status, 1, result.stdout + result.stderr);
  assert.match(result.stdout + result.stderr, /Docker.*(?:mandatory|required|unavailable)/i);
  assert.equal(fs.existsSync(hostToolMarker), false);
});

test('host launcher templates defer all software paths to the renderer', () => {
  for (const launcher of [
    'nosh-gateway',
    'nosh-guard',
    'nosh-guardd',
    'nosh-guard-fail-closed',
    'nosh-guard-tetragon-verify',
  ]) {
    const source = read(`deploy/host/${launcher}`);
    assert.match(
      source,
      /exec @@NOSH_GUARD_PREFIX@@\/lib\/notty\/nosh-guard\/current\/payload\/runtime\/node/,
    );
    assert.match(
      source,
      new RegExp(
        `@@NOSH_GUARD_PREFIX@@/lib/notty/nosh-guard/current/payload/bin/${launcher}`,
      ),
    );
    assert.doesNotMatch(source, /current\/payload\/scripts\//);
    assert.doesNotMatch(
      source,
      /\/usr\/local\/(?:lib\/notty\/nosh-guard|libexec\/nosh-|bin\/nosh-guard)/,
    );
    assert.doesNotMatch(source, /\$\{PATH/);
    assert.ok(fs.statSync(path.join(repository, 'deploy/host', launcher)).mode & 0o111);
  }
});

test('installer and verifier reject unsafe prefixes before privileged work', () => {
  const installer = path.join(
    repository,
    'scripts',
    'install-nosh-guard-host-bundle.sh',
  );
  const verifier = path.join(
    repository,
    'scripts',
    'verify-nosh-guard-host-install.sh',
  );

  for (const prefix of [
    'usr/local',
    '/',
    '/usr',
    '/opt/',
    '/opt/../usr/local',
    '/opt/not ty',
    '/opt/$notty',
  ]) {
    const installed = childProcess.spawnSync(
      'bash',
      [installer, 'install', '--prefix', prefix],
      { encoding: 'utf8' },
    );
    assert.equal(installed.status, 2, `${prefix}: ${installed.stderr}`);
    assert.match(installed.stderr, /--prefix/);

    const renderedVerifier = fs.readFileSync(verifier, 'utf8')
      .replaceAll('@@NOSH_GUARD_PREFIX@@', '/usr/local');
    const checked = childProcess.spawnSync(
      'bash',
      ['-s', '--', '--prefix', prefix],
      { encoding: 'utf8', input: renderedVerifier },
    );
    assert.equal(checked.status, 2, `${prefix}: ${checked.stderr}`);
    assert.match(checked.stderr, /--prefix/);
  }
});

test('bpffs preparation creates a private child on an existing mount and preserves pins', (t) => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'nosh-bpffs-'));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const bpffs = path.join(root, 'bpf');
  const commands = path.join(root, 'bin');
  fs.mkdirSync(bpffs);
  fs.mkdirSync(commands);
  // Simulate filesystem magic and root identity; mkdir, modes, and symlink
  // handling operate on real temporary files, without mounting host bpffs.
  fs.writeFileSync(path.join(commands, 'id'), '#!/bin/sh\necho 0\n', { mode: 0o700 });
  fs.writeFileSync(path.join(commands, 'stat'), `#!/bin/sh
if [ "$1" = -f ]; then echo cafe4a11
elif [ "$2" = %u ]; then echo "\${TEST_PIN_OWNER:-0}"
else exec /usr/bin/stat "$@"
fi
`, { mode: 0o700 });
  fs.writeFileSync(path.join(commands, 'mount'), '#!/bin/sh\nexit 99\n', { mode: 0o700 });
  const script = path.join(root, 'prepare.sh');
  fs.writeFileSync(script, read('scripts/ensure-nosh-guard-bpffs.sh')
    .replace('BPFFS_PATH=/sys/fs/bpf', `BPFFS_PATH='${bpffs}'`));
  const run = (extra = {}) => childProcess.spawnSync('bash', [script], {
    encoding: 'utf8', env: { ...process.env, PATH: `${commands}:${process.env.PATH}`, ...extra },
  });
  const created = run();
  assert.equal(created.status, 0, created.stderr);
  const base = path.join(bpffs, 'nosh-guard');
  assert.equal(fs.statSync(base).mode & 0o777, 0o700);
  const pin = path.join(base, 'existing-pin');
  fs.writeFileSync(pin, 'preserve');
  assert.equal(run().status, 0);
  assert.equal(fs.readFileSync(pin, 'utf8'), 'preserve');
  assert.notEqual(run({ TEST_PIN_OWNER: '1000' }).status, 0);
  fs.chmodSync(base, 0o777);
  assert.match(run().stderr, /group\/other writable/);
  assert.equal(fs.statSync(base).mode & 0o777, 0o777);
  fs.chmodSync(base, 0o700);
  fs.renameSync(base, `${base}-original`);
  fs.symlinkSync(`${base}-original`, base);
  assert.match(run().stderr, /unsafe pin base/);
  assert.equal(fs.readFileSync(path.join(`${base}-original`, 'existing-pin'), 'utf8'), 'preserve');
});
